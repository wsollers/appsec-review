from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
from pathlib import Path

import pytest

from appsec_review.jobs.job_dependency_intelligence.curation import curate_native_components
from appsec_review.jobs.job_dependency_intelligence.discovery import discover_native_dependencies
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import (
    CURATION_SCHEMA, INFERENCE_COUNTERS, NativeInferenceBounds, NativeInferenceError,
)
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
    GAP_KINDS, NativeBounds, NativeInputIntegrityError, evidence_identity,
)
from appsec_review.storage import canonical_json


BOUNDS = NativeInferenceBounds()
DISCOVERY_BOUNDS = NativeBounds(
    candidate_limit=100, command_token_limit=100, file_limit=100, bytes_per_file=10000,
    source_bytes_limit=100000, root_limit=100, evidence_limit=1000, evidence_per_candidate=100,
    field_bytes=4096, path_chars=512,
)
REF = {"path": "data/catalog.json", "sha256": "a" * 64, "size_bytes": 100}


def discover(contents, *, domain="target", root_id="target"):
    data = {path: value.encode() for path, value in contents.items()}
    files = [
        {"domain": domain, "root_id": root_id, "path": path,
         "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value),
         "upstream": dict(REF), "backing": None if domain == "target" else {
             "path": "data/backings/" + hashlib.sha256(value).hexdigest(),
             "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}}
        for path, value in data.items()
    ]
    result = discover_native_dependencies(
        source_fingerprint="snapshot-1", files=files, invocations=[], artifacts=[],
        read_file=lambda file, limit: data[file["path"]][:limit], bounds=DISCOVERY_BOUNDS,
    )
    return result, files


def merge_inputs(*inputs):
    discovery = deepcopy(inputs[0][0])
    discovery["candidates"] = [row for result, _ in inputs for row in result["candidates"]]
    discovery["evidence"] = [row for result, _ in inputs for row in result["evidence"]]
    discovery["gaps"] = [row for result, _ in inputs for row in result["gaps"]]
    return discovery, [file for _, files in inputs for file in files]


def library(name, ids, paths, *, kind="library"):
    return {"name": name, "kind": kind, "candidate_ids": sorted(ids),
            "supporting_paths": sorted(paths), "basis": "Specific authenticated header paths"}


def proposal(payload, libraries=(), groups=(), *, rejected=(), uncertain=()):
    return {"schema": CURATION_SCHEMA, "input_records": payload["input_records"],
            "libraries": sorted(libraries, key=lambda row: row["name"].casefold().replace("_", "-")),
            "sdk_groups": sorted(groups, key=lambda row: row["name"]),
            "rejected_candidate_ids": sorted(rejected), "uncertain_candidate_ids": sorted(uncertain)}


def retain(stage, payload):
    assert stage == "curate"
    return proposal(payload, [
        library(row["native_name"], [row["candidate_id"]], row["context_paths"])
        for row in payload["candidates"]
    ])


def run(inputs, propose=retain, *, bounds=BOUNDS):
    original = deepcopy(inputs)
    result = curate_native_components(*inputs, propose=propose, bounds=bounds)
    assert inputs == original
    assert set(result["metrics"]) <= set(INFERENCE_COUNTERS)
    assert not set(result["metrics"]) & {"model_calls", "model_failures", "input_tokens",
                                       "output_tokens", "cache_tokens", "unknown_usage_calls"}
    assert all(type(count) is int and count >= 0 for count in result["metrics"].values())
    assert all(gap["kind"] in GAP_KINDS for gap in result["gaps"])
    evidence = {row["evidence_id"]: row for row in result["discovery"]["evidence"]}
    assert all(evidence_identity(row) == key for key, row in evidence.items())
    effective = {row["candidate_id"] for row in result["discovery"]["candidates"]}
    for candidate in result["discovery"]["candidates"]:
        assert set(candidate["evidence_ids"]) <= evidence.keys()
        for field in ("identity", "release", "upstream"):
            assert set(candidate[field]["evidence_ids"]) <= evidence.keys()
    for component in result["components"]:
        assert set(component["candidate_ids"]) <= effective
        assert set(component["source_candidate_ids"]) <= {
            row["candidate_id"] for row in inputs[0]["candidates"]}
    return result


def component(result, name):
    return next(row for row in result["components"] if row["name"] == name)


def reasons(result):
    return " ".join(row["detail"] for row in result["gaps"])


def test_generic_headers_split_into_unfamiliar_named_frameworks_without_io(monkeypatch):
    inputs = discover({
        "include/AsterFramework.h": "// interface\n",
        "include/CometFramework.hpp": "// interface\n",
    })
    source_id = inputs[0]["candidates"][0]["candidate_id"]

    def propose(stage, payload):
        assert stage == "curate"
        row, = payload["candidates"]
        assert row["candidate_id"] == source_id
        assert row["package_root"] == "include"
        assert row["evidence"] and row["files"]
        assert row["context_paths"] == ["include/AsterFramework.h", "include/CometFramework.hpp"]
        return proposal(payload, [
            library("asterframework", [source_id], ["include/AsterFramework.h"]),
            library("cometframework", [source_id], ["include/CometFramework.hpp"]),
        ])

    def no_io(*args, **kwargs):
        raise AssertionError("curation attempted host I/O")

    monkeypatch.setattr(Path, "read_bytes", no_io)
    monkeypatch.setattr(Path, "read_text", no_io)
    monkeypatch.setattr(Path, "glob", no_io)
    monkeypatch.setattr(Path, "rglob", no_io)
    result = run(inputs, propose)
    assert [row["name"] for row in result["components"]] == ["asterframework", "cometframework"]
    assert result["metrics"]["uncertain_candidates"] == 0
    for candidate in result["discovery"]["candidates"]:
        assert candidate["identity"]["status"] == "inferred"
        assert candidate["release"]["status"] == "unknown"
        assert candidate["metadata"]["curation"]["source_candidate_ids"] == [source_id]


def family(payload, *, prefix="qx"):
    row, = payload["candidates"]
    identifier = row["candidate_id"]
    names = [prefix + "core", prefix + "paint"]
    libraries = [library(name, [identifier], [
        path for path in row["context_paths"] if Path(path).stem.casefold() == name
    ], kind="sdk-component") for name in names]
    groups = [{"name": prefix + "-sdk", "component_names": names, "candidate_ids": [identifier],
               "supporting_paths": row["context_paths"],
               "basis": "Shared namespace and authenticated SDK include subtree"}]
    return proposal(payload, libraries, groups)


def test_prefix_family_retains_components_and_inferred_group_not_package_boundary():
    inputs = discover({"QXSDK/include/QXCore.h": "// core", "QXSDK/include/QXPaint.h": "// paint"})
    result = run(inputs, lambda stage, payload: family(payload))
    assert {"qxcore", "qxpaint"} == {row["name"] for row in result["components"]}
    group, = result["sdk_groups"]
    assert group["component_ids"] == sorted(component(result, name)["component_id"]
                                             for name in ("qxcore", "qxpaint"))
    assert result["discovery"]["coverage"]["curation"]["grouping_status"] == "inferred"
    assert all(row["identity"]["status"] != "corroborated"
               for row in result["discovery"]["candidates"])


def test_prefix_collision_does_not_authorize_merging_independent_libraries():
    inputs = discover({"vendor/QXCore/QXCore.h": "// core", "vendor/QXPaint/QXPaint.h": "// paint"})

    def propose(stage, payload):
        return proposal(payload, [library("qx", [
            row["candidate_id"] for row in payload["candidates"]
        ], [path for row in payload["candidates"] for path in row["context_paths"]])])

    result = run(inputs, propose)
    assert {row["name"] for row in result["components"]} == {"qxcore", "qxpaint"}
    assert result["metrics"]["uncertain_candidates"] == 2
    assert "name-specific path" in reasons(result)


def test_prefix_collision_does_not_authorize_group_without_packaging_context():
    inputs = discover({"vendor/QXCore/QXCore.h": "// core", "vendor/QXPaint/QXPaint.h": "// paint"})

    def propose(stage, payload):
        libraries = [library(row["native_name"], [row["candidate_id"]], row["context_paths"],
                             kind="sdk-component") for row in payload["candidates"]]
        return proposal(payload, libraries, [{
            "name": "qx-sdk", "component_names": sorted(row["name"] for row in libraries),
            "candidate_ids": sorted(row["candidate_id"] for row in payload["candidates"]),
            "supporting_paths": sorted(path for row in libraries for path in row["supporting_paths"]),
            "basis": "Names have same prefix",
        }])

    result = run(inputs, propose)
    assert not result["sdk_groups"]
    assert {row["name"] for row in result["components"]} == {"qxcore", "qxpaint"}
    assert "coherent SDK packaging" in reasons(result)


def test_duplicate_copies_retain_roots_and_never_exchange_versions():
    inputs = merge_inputs(
        discover({"vendor/flux/flux.h": '#define FLUX_VERSION "1.2.3"\n'}),
        discover({"prefix/flux/flux.h": '#define FLUX_VERSION "4.5.6"\n'},
                 domain="workspace", root_id="build-root"),
    )

    def propose(stage, payload):
        return proposal(payload, [library("flux", [
            row["candidate_id"] for row in payload["candidates"]
        ], [path for row in payload["candidates"] for path in row["context_paths"]])])

    result = run(inputs, propose)
    curated, = result["components"]
    assert len(curated["candidate_ids"]) == 2
    copies = result["discovery"]["candidates"]
    assert {(row["root_id"], row["package_root"], row["release"]["value"]) for row in copies} == {
        ("target", "vendor/flux", "1.2.3"), ("build-root", "prefix/flux", "4.5.6")}
    assert {row["metadata"]["curation"]["domain"] for row in copies} == {"target", "workspace"}


def test_identical_root_strings_in_different_domains_cannot_alias_effective_ids():
    left = discover({"include/flux.h": '#define FLUX_VERSION "1.2.3"\n'})
    right = discover({"include/flux.h": '#define FLUX_VERSION "4.5.6"\n'},
                     domain="workspace", root_id="target")
    # Discovery's legacy candidate helper omits domain; accepted source IDs must still be unique.
    right[0]["candidates"][0]["candidate_id"] += "-workspace"
    inputs = merge_inputs(left, right)

    def propose(stage, payload):
        return proposal(payload, [library("flux", [row["candidate_id"] for row in payload["candidates"]],
                                         ["include/flux.h"])])

    result = run(inputs, propose)
    assert len(component(result, "flux")["candidate_ids"]) == 2
    assert {row["release"]["value"] for row in result["discovery"]["candidates"]} == {"1.2.3", "4.5.6"}


@pytest.mark.parametrize("disposition", ["rename", "reject", "uncertain"])
def test_corroborated_identity_release_upstream_and_metadata_are_preserved(disposition):
    inputs = discover({
        "vendor/zlib/zlib.h": '#define ZLIB_VERSION "1.3.1"\n',
        "vendor/zlib/README": "Package: zlib\nVersion: 1.3.1\nRepository: https://github.com/acme/zlib\n",
        "vendor/zlib/zlib.pc": "Name: zlib\nVersion: 1.3.1\nURL: https://github.com/acme/zlib\n",
        "vendor/zlib/Other.h": "// not zlib metadata\n",
    })
    original, = inputs[0]["candidates"]
    assert all(original[field]["status"] == "corroborated"
               for field in ("identity", "release", "upstream"))

    def propose(stage, payload):
        identifier = original["candidate_id"]
        if disposition == "rename":
            return proposal(payload, [library("other", [identifier], ["vendor/zlib/Other.h"])])
        return proposal(payload, **{disposition if disposition == "uncertain" else "rejected":
                                    [identifier]})

    result = run(inputs, propose)
    retained = next(row for row in result["discovery"]["candidates"] if row["native_name"] == "zlib")
    for field in ("identity", "release", "upstream", "repository", "observations", "evidence_ids"):
        assert retained[field] == original[field]
    assert retained["metadata"]["version"] == "1.3.1"
    assert result["metrics"]["uncertain_candidates"] == 1
    assert result["metrics"]["excluded_candidates"] == 0
    if disposition == "rename":
        renamed = next(row for row in result["discovery"]["candidates"] if row["native_name"] == "other")
        assert renamed["release"]["status"] == "unknown"
        assert renamed["upstream"]["status"] == "unknown"
        assert "version" not in renamed["metadata"]


def test_rejected_uncertain_and_unaccounted_have_distinct_explicit_accounting():
    inputs = discover({f"include/{name}/{name}.h": "// header\n" for name in ("first", "next", "last")})
    ids = sorted(row["candidate_id"] for row in inputs[0]["candidates"])
    result = run(inputs, lambda stage, payload: proposal(payload, rejected=[ids[0]], uncertain=[ids[1]]))
    assert result["metrics"]["excluded_candidates"] == 1
    assert result["metrics"]["uncertain_candidates"] == 2
    assert {row["candidate_id"]: row["decision"] for row in result["decisions"]} == {
        ids[0]: "rejected", ids[1]: "uncertain", ids[2]: "uncertain"}
    assert len(result["discovery"]["candidates"]) == 2
    assert "unaccounted" in reasons(result)


@pytest.mark.parametrize("mutation", [
    "schema", "count", "count-bool", "extra", "unknown-id", "unknown-path", "wrong-owner",
    "overlap", "selected-rejected", "duplicate-ids", "bad-kind", "unsorted",
    "oversized-name", "oversized-basis", "empty-basis", "no-paths", "status", "none", "kind-list",
])
def test_malformed_proposals_preserve_all_originals_with_named_gap(mutation):
    inputs = discover({"vendor/alpha/alpha.h": "// alpha", "vendor/beta/beta.h": "// beta"})

    def propose(stage, payload):
        result = retain(stage, payload)
        first, second = result["libraries"]
        if mutation == "schema":
            result["schema"] = "wrong"
        elif mutation == "count":
            result["input_records"] += 1
        elif mutation == "count-bool":
            result["input_records"] = True
        elif mutation == "extra":
            result["confidence"] = 1
        elif mutation == "unknown-id":
            first["candidate_ids"] = ["unowned"]
        elif mutation == "unknown-path":
            first["supporting_paths"] = ["include/not-accepted.h"]
        elif mutation == "wrong-owner":
            first["supporting_paths"] = second["supporting_paths"]
        elif mutation == "overlap":
            result.update(libraries=[], rejected_candidate_ids=first["candidate_ids"],
                          uncertain_candidate_ids=first["candidate_ids"])
        elif mutation == "selected-rejected":
            result["rejected_candidate_ids"] = first["candidate_ids"]
        elif mutation == "duplicate-ids":
            first["candidate_ids"] *= 2
        elif mutation == "bad-kind":
            first["kind"] = "corroborated-package"
        elif mutation == "kind-list":
            first["kind"] = []
        elif mutation == "unsorted":
            result["libraries"].reverse()
        elif mutation == "oversized-name":
            first["name"] = "a" * 257
        elif mutation == "oversized-basis":
            first["basis"] = "a" * (BOUNDS.field_bytes + 1)
        elif mutation == "empty-basis":
            first["basis"] = ""
        elif mutation == "no-paths":
            first["supporting_paths"] = []
        elif mutation == "status":
            first["status"] = "corroborated"
        elif mutation == "none":
            return None
        return result

    result = run(inputs, propose)
    assert {row["name"] for row in result["components"]} == {"alpha", "beta"}
    assert result["metrics"]["uncertain_candidates"] == 2
    assert "invalid proposal" in reasons(result)


@pytest.mark.parametrize("mutation", ["ids", "paths", "member", "kind", "duplicates", "name"])
def test_invalid_sdk_member_unions_and_references_are_not_published(mutation):
    inputs = discover({"QXSDK/include/QXCore.h": "// core", "QXSDK/include/QXPaint.h": "// paint"})

    def propose(stage, payload):
        result = family(payload)
        group, = result["sdk_groups"]
        if mutation == "ids":
            group["candidate_ids"] = ["unowned"]
        elif mutation == "paths":
            group["supporting_paths"] = group["supporting_paths"][:1]
        elif mutation == "member":
            group["component_names"] = ["not-selected", "qxcore"]
        elif mutation == "kind":
            result["libraries"][0]["kind"] = "library"
        elif mutation == "duplicates":
            group["component_names"] = ["qxcore", "qxcore"]
        elif mutation == "name":
            group["name"] = "../qx"
        return result

    result = run(inputs, propose)
    assert not result["sdk_groups"]
    assert result["metrics"]["uncertain_candidates"] == 1
    assert "invalid proposal" in reasons(result)


def test_batches_and_max_calls_retain_omitted_originals():
    inputs = discover({f"vendor/pkg{index}/pkg{index}.h": "// header" for index in range(5)})
    calls = []

    def propose(stage, payload):
        calls.append(payload)
        assert len(payload["candidates"]) <= 2
        return retain(stage, payload)

    result = run(inputs, propose, bounds=replace(BOUNDS, batch_candidates=2, max_calls=1))
    assert len(calls) == 1
    assert result["metrics"]["input_candidates"] == len(result["components"]) == 5
    assert result["metrics"]["omitted_candidates"] == 3
    assert result["metrics"]["uncertain_candidates"] == 3
    assert "max_calls" in reasons(result)


def test_payload_bytes_partition_batches_and_preserve_single_oversize_context():
    inputs = discover({f"vendor/pkg{index}/pkg{index}.h": "// header" for index in range(3)})
    payload_sizes = []
    run(inputs, lambda stage, payload: (payload_sizes.append(len(canonical_json(payload)))
                                       or retain(stage, payload)),
        bounds=replace(BOUNDS, batch_candidates=1))
    limit = max(payload_sizes)
    calls = []

    def propose(stage, payload):
        assert len(canonical_json(payload)) <= limit
        calls.append(payload["input_records"])
        return retain(stage, payload)

    result = run(inputs, propose, bounds=replace(BOUNDS, max_payload_bytes=limit))
    assert calls == [1, 1, 1]
    assert not result["gaps"]
    bounded = run(inputs, lambda *_: pytest.fail("oversized payload reached callback"),
                  bounds=replace(BOUNDS, max_payload_bytes=10))
    assert bounded["metrics"]["omitted_candidates"] == 3
    assert bounded["metrics"]["uncertain_candidates"] == 3
    assert "max_payload_bytes" in reasons(bounded)


def test_oversized_response_preserves_originals():
    inputs = discover({"include/alpha.h": "// header"})

    def propose(stage, payload):
        result = retain(stage, payload)
        result["libraries"][0]["basis"] = "x" * BOUNDS.max_payload_bytes
        return result

    result = run(inputs, propose)
    assert result["metrics"]["uncertain_candidates"] == 1
    assert "proposal exceeds max_payload_bytes" in reasons(result)


def test_component_limit_caps_inference_but_not_conservative_originals():
    inputs = discover({"include/Aster.h": "// header", "include/Comet.h": "// header"})

    def propose(stage, payload):
        identifier = payload["candidates"][0]["candidate_id"]
        return proposal(payload, [
            library("aster", [identifier], ["include/Aster.h"]),
            library("comet", [identifier], ["include/Comet.h"]),
        ])

    result = run(inputs, propose, bounds=replace(BOUNDS, component_limit=1))
    assert {row["name"] for row in result["components"]} == {"aster", "include"}
    assert result["metrics"]["omitted_candidates"] == 1
    assert result["metrics"]["uncertain_candidates"] == 1
    assert "component_limit" in reasons(result)


def test_group_limit_omits_groups_without_dropping_components():
    inputs = discover({
        f"SDK/include/{name}.h": "// header"
        for name in ("QXCore", "QXPaint", "RYCore", "RYPaint")
    })

    def propose(stage, payload):
        identifier = payload["candidates"][0]["candidate_id"]
        libraries = [library(Path(path).stem.casefold(), [identifier], [path], kind="sdk-component")
                     for path in payload["candidates"][0]["context_paths"]]
        groups = [{
            "name": prefix + "-sdk", "component_names": [prefix + "core", prefix + "paint"],
            "candidate_ids": [identifier], "supporting_paths": sorted(
                path for row in libraries if row["name"].startswith(prefix)
                for path in row["supporting_paths"]),
            "basis": "Shared namespace and SDK packaging",
        } for prefix in ("qx", "ry")]
        return proposal(payload, libraries, groups)

    result = run(inputs, propose, bounds=replace(BOUNDS, group_limit=1))
    assert len(result["sdk_groups"]) == 1
    assert {"qxcore", "qxpaint", "rycore", "rypaint"} <= {
        row["name"] for row in result["components"]}
    assert "group_limit" in reasons(result)


def test_context_file_bound_reports_omitted_catalog_paths_without_losing_evidence():
    inputs = discover({"include/alpha.h": "// header"})
    for index in range(5):
        inputs[1].append({**deepcopy(inputs[1][0]), "path": f"include/extra{index}.h"})
    calls = []

    def propose(stage, payload):
        row, = payload["candidates"]
        assert len(row["files"]) == 2
        assert "include/alpha.h" in row["context_paths"]
        calls.append(payload)
        return retain(stage, payload)

    result = run(inputs, propose, bounds=replace(BOUNDS, files_per_root=2))
    assert len(calls) == 1
    assert result["metrics"]["omitted_files"] == 4
    assert "files_per_root" in reasons(result)
    assert all(row in result["discovery"]["evidence"] for row in inputs[0]["evidence"])


@pytest.mark.parametrize("failure", ["missing", "transport"])
def test_missing_or_failed_model_retains_originals_with_accounting(failure):
    inputs = discover({"include/alpha.h": "// header"})

    def fail(stage, payload):
        raise NativeInferenceError("deadline", "proposal timed out")

    result = run(inputs, None if failure == "missing" else fail)
    assert len(result["components"]) == 1
    assert result["metrics"]["uncertain_candidates"] == 1
    assert ("proposer unavailable" if failure == "missing" else "deadline") in reasons(result)


def test_callback_integrity_errors_are_not_masked():
    inputs = discover({"include/alpha.h": "// header"})

    def fail(stage, payload):
        raise NativeInputIntegrityError("accepted evidence changed")

    with pytest.raises(NativeInputIntegrityError, match="accepted evidence changed"):
        run(inputs, fail)


@pytest.mark.parametrize("damage", ["evidence", "reference", "catalog", "backing", "duplicate"])
def test_input_integrity_failure_occurs_before_model_call(damage):
    inputs = discover({"include/alpha.h": "// header"})
    if damage == "evidence":
        inputs[0]["evidence"][0]["value"] = "tampered"
    elif damage == "reference":
        inputs[0]["candidates"][0]["release"]["evidence_ids"].append("missing")
    elif damage == "catalog":
        inputs[1][0]["sha256"] = "b" * 64
    elif damage == "backing":
        inputs[1][0]["backing"] = {"path": "data/changed", "sha256": "b" * 64, "size_bytes": 0}
    elif damage == "duplicate":
        inputs[0]["candidates"].append({**inputs[0]["candidates"][0], "native_name": "other"})
    with pytest.raises(NativeInputIntegrityError):
        run(inputs, lambda *_: pytest.fail("invalid inputs reached model"))


def test_callback_payload_mutation_does_not_mutate_input_or_accepted_context():
    inputs = discover({"include/alpha.h": "// header"})

    def propose(stage, payload):
        result = retain(stage, payload)
        payload["candidates"][0]["metadata"]["injected"] = True
        payload["candidates"][0]["evidence"][0]["value"] = "not accepted"
        payload["candidates"][0]["context_paths"].append("fabricated/path.h")
        result["libraries"][0]["supporting_paths"] = ["fabricated/path.h"]
        return result

    result = run(inputs, propose)
    assert result["metrics"]["uncertain_candidates"] == 1
    assert all("injected" not in row["metadata"] for row in result["discovery"]["candidates"])


def test_results_are_deterministic_under_input_reordering_and_repeated_calls():
    inputs = discover({"vendor/alpha/alpha.h": "// alpha", "vendor/beta/beta.h": "// beta"})
    expected = run(inputs)
    reversed_inputs = deepcopy(inputs)
    for field in ("candidates", "evidence", "gaps"):
        reversed_inputs[0][field].reverse()
    reversed_inputs[1].reverse()
    assert run(reversed_inputs) == expected
    assert run(inputs) == expected


def test_catalog_only_support_is_bound_as_resolving_path_evidence():
    inputs = discover({"include/alpha.h": "// header"})
    inputs[1].append({**deepcopy(inputs[1][0]), "path": "include/Unfamiliar.hpp"})

    def propose(stage, payload):
        return proposal(payload, [library("unfamiliar", [payload["candidates"][0]["candidate_id"]],
                                         ["include/Unfamiliar.hpp"])])

    result = run(inputs, propose)
    path_evidence, = [row for row in result["discovery"]["evidence"] if row["kind"] == "catalog_path"]
    assert path_evidence["path"] == path_evidence["selector"]["catalog_path"] == "include/Unfamiliar.hpp"
    assert path_evidence["sha256"] == inputs[1][1]["sha256"]
    assert path_evidence["evidence_id"] in result["discovery"]["candidates"][0]["identity"]["evidence_ids"]


def test_empty_discovery_does_not_call_model_or_invent_gaps():
    result = run(discover({}), lambda *_: pytest.fail("empty input reached model"))
    assert not result["components"] and not result["sdk_groups"] and not result["gaps"]
    assert all(value == 0 for value in result["metrics"].values())


def test_renamed_library_must_have_specific_paths_for_every_source_copy():
    inputs = merge_inputs(
        discover({"include/Specific.h": "// interface"}),
        discover({"other/include/Unrelated.h": "// interface"},
                 domain="workspace", root_id="build-root"),
    )

    def propose(stage, payload):
        return proposal(payload, [library("specific", [
            row["candidate_id"] for row in payload["candidates"]
        ], [path for row in payload["candidates"] for path in row["context_paths"]])])

    result = run(inputs, propose)
    assert result["metrics"]["uncertain_candidates"] == 2
    assert not any(row["name"] == "specific" for row in result["components"])
    assert "name-specific path evidence" in reasons(result)


def test_independently_named_inferred_original_is_retained_when_input_is_split():
    inputs = discover({
        "vendor/flux/flux.h": '#define FLUX_VERSION "1.2.3"\n',
        "vendor/flux/Companion.h": "// interface",
    })
    original, = inputs[0]["candidates"]
    assert original["identity"]["status"] == "inferred"

    def propose(stage, payload):
        return proposal(payload, [library("companion", [original["candidate_id"]],
                                         ["vendor/flux/Companion.h"])])

    result = run(inputs, propose)
    assert {row["name"] for row in result["components"]} == {"companion", "flux"}
    retained = next(row for row in result["discovery"]["candidates"] if row["native_name"] == "flux")
    assert retained["release"] == original["release"]
    assert "independently named" in reasons(result)


def test_repeated_sdk_group_across_batches_unions_paths_and_keeps_copies():
    inputs = discover({
        f"{root}/include/{name}.h": "// interface"
        for root in ("pack-one", "pack-two") for name in ("QXCore", "QXPaint")
    })
    result = run(inputs, lambda stage, payload: family(payload),
                 bounds=replace(BOUNDS, batch_candidates=1))
    assert result["metrics"]["uncertain_candidates"] == 0
    assert len(result["sdk_groups"]) == 1
    assert result["sdk_groups"][0]["supporting_paths"] == sorted(file["path"] for file in inputs[1])
    assert all(len(component(result, name)["candidate_ids"]) == 2 for name in ("qxcore", "qxpaint"))
    assert all(len(component(result, name)["source_candidate_ids"]) == 2
               for name in ("qxcore", "qxpaint"))


def test_oversized_input_field_retains_original_without_sending_partial_context():
    inputs = discover({"include/alpha.h": "// header"})
    inputs[0]["candidates"][0]["metadata"]["large_note"] = "x" * (BOUNDS.field_bytes + 1)
    result = run(inputs, lambda *_: pytest.fail("oversized field reached callback"))
    assert result["metrics"]["uncertain_candidates"] == result["metrics"]["omitted_candidates"] == 1
    assert result["discovery"]["candidates"][0]["metadata"]["large_note"] == "x" * (BOUNDS.field_bytes + 1)
    assert "field_bytes" in reasons(result)


def test_mandatory_oversized_fallback_does_not_consume_inferred_component_budget():
    inputs = discover({"vendor/alpha/alpha.h": "// interface", "vendor/beta/beta.h": "// interface"})
    first, second = sorted(inputs[0]["candidates"], key=lambda row: row["candidate_id"])
    first["metadata"]["large_note"] = "x" * (BOUNDS.field_bytes + 1)
    result = run(inputs, bounds=replace(BOUNDS, component_limit=1))
    selected = [row for row in result["decisions"] if row["decision"] == "selected"]
    assert [row["candidate_id"] for row in selected] == [second["candidate_id"]]
    assert len(result["components"]) == 2
    assert result["metrics"]["omitted_candidates"] == 1


def test_merging_same_local_component_with_conflicting_claims_retains_conflict_not_version():
    inputs = discover({
        "vendor/flux/flux.h": '#define FLUX_VERSION "1.2.3"\n',
        "vendor/flux/README": "Package: flux\nVersion: 1.2.3\n",
    })
    original = inputs[0]["candidates"][0]
    duplicate = deepcopy(original)
    duplicate["candidate_id"] += "-second-record"
    duplicate["release"]["value"] = "4.5.6"
    duplicate["metadata"]["version"] = "4.5.6"
    inputs[0]["candidates"].append(duplicate)

    def propose(stage, payload):
        return proposal(payload, [library("flux", [
            row["candidate_id"] for row in payload["candidates"]
        ], ["vendor/flux/flux.h"])])

    result = run(inputs, propose)
    merged, = result["discovery"]["candidates"]
    assert merged["release"]["status"] == "conflicted"
    assert merged["release"]["value"] is None
    assert merged["release"]["alternatives"] == ["1.2.3", "4.5.6"]
    assert "version" not in merged["metadata"]
    assert any(gap["kind"] == "version_conflict" for gap in result["gaps"])


def test_rejection_cannot_suppress_a_deterministic_conflicted_claim():
    inputs = discover({"vendor/flux/flux.h":
                       '#define FLUX_VERSION "1.2.3"\n#define FLUX_VERSION "4.5.6"\n'})
    original, = inputs[0]["candidates"]
    assert original["release"]["status"] == "conflicted"
    result = run(inputs, lambda stage, payload: proposal(
        payload, rejected=[original["candidate_id"]]))
    retained, = result["discovery"]["candidates"]
    assert retained["release"] == original["release"]
    assert result["metrics"]["excluded_candidates"] == 0
    assert result["metrics"]["uncertain_candidates"] == 1
    assert "cannot reject corroborated or conflicted" in reasons(result)


def test_shared_company_namespace_is_not_itself_coherent_sdk_packaging():
    inputs = discover({"company/QXCore/QXCore.h": "// core",
                       "company/QXPaint/QXPaint.h": "// paint"})

    def propose(stage, payload):
        libraries = [library(row["native_name"], [row["candidate_id"]], row["context_paths"],
                             kind="sdk-component") for row in payload["candidates"]]
        return proposal(payload, libraries, [{
            "name": "qx-sdk", "component_names": sorted(row["name"] for row in libraries),
            "candidate_ids": sorted(row["candidate_id"] for row in payload["candidates"]),
            "supporting_paths": sorted(path for row in libraries for path in row["supporting_paths"]),
            "basis": "Vendor namespace has shared name prefix",
        }])

    result = run(inputs, propose)
    assert not result["sdk_groups"]
    assert result["metrics"]["uncertain_candidates"] == 2
    assert "coherent SDK packaging" in reasons(result)
