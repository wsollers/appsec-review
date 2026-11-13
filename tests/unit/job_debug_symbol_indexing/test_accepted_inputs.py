"""``_accepted_inputs`` reads the accepted artifact catalog (and, when supplied, the language-build
receipts) into the bounded artifact list the decision freezes. The accepted-handoff readers are
faked at the module boundary; the catalog shard and manifest are real."""
from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_debug_symbol_indexing import job as job_module
from appsec_review.jobs.job_debug_symbol_indexing.job import FrameworkIntegrityError, _accepted_inputs
from appsec_review.runtime import consume
from appsec_review.storage import file_sha256
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, MSF, RUN_ID, SNAPSHOT, artifact, catalog_shard, job_context, manifest, source_shard, unit,
)

IMAGE = {"image_id": "sha256:" + "d" * 64, "image_tag": "accepted/compiler:receipt", "user": "10001:10001"}
SETTINGS = {"max_artifacts": 128}


@pytest.fixture
def upstream(tmp_path: Path, monkeypatch):
    """Fake the accepted artifact-index and language-build readers; the catalog shard is real."""
    context = job_context(tmp_path)
    state = type("State", (), {})()
    state.context = context
    state.accepted = None
    state.language = None
    state.calls = []
    monkeypatch.setattr(job_module, "load_accepted_artifact_index",
                        lambda root: state.calls.append(("artifacts", root)) or state.accepted)
    monkeypatch.setattr(consume, "has_accepted_upstream",
                        lambda root, job_id: state.calls.append(("has", job_id)) or state.language is not None)
    monkeypatch.setattr(job_module, "load_accepted_language_build",
                        lambda root: state.calls.append(("language", root)) or state.language)
    return state


def _accepted(run_root, artifacts, *, snapshot=SNAPSHOT, run_id=RUN_ID, target_artifacts=None, language_sha=None,
              gaps=(), shards=None):
    indexes = [catalog_shard(run_root, artifacts, snapshot=snapshot)] if shards is None else shards
    reference = manifest(run_root, indexes, snapshot=snapshot, run_id=run_id)
    return {"schema": "appsec-review/artifact-indexing/1", "source_fingerprint": snapshot,
            "target_artifacts": [item["reference"] for item in artifacts] if target_artifacts is None else target_artifacts,
            "gaps": list(gaps), "language_build_handoff_sha256": language_sha,
            "index_manifest": reference, "handoff_sha256": "7" * 64}


def test_catalog_entries_become_bounded_artifacts_with_their_intake_references(upstream) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, "bin/program", ELF), artifact(run_root, "symbols/program.pdb", MSF, "debug-information"),
             artifact(run_root, "lib/libx.a", b"!<arch>", "library")]
    upstream.accepted = _accepted(run_root, items, gaps=["catalog gap"])
    result = _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)
    assert [kind for kind, _ in upstream.calls] == ["artifacts", "has"]
    assert result["artifact_handoff_sha256"] == "7" * 64 and result["language_build_handoff_sha256"] is None
    assert result["upstream_manifest"] == upstream.accepted["index_manifest"]
    assert result["gaps"] == ["catalog gap"]
    expected = sorted(items, key=lambda item: item["artifact_identity"])
    assert result["artifacts"] == [{"artifact_identity": item["artifact_identity"], "kind": item["kind"],
                                    "reference": item["reference"], "build_image": None} for item in expected]


def test_catalog_entries_without_an_intake_reference_use_their_own_payload(upstream) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, "bin/program", ELF)]
    upstream.accepted = _accepted(run_root, items, target_artifacts=[])
    (entry,) = _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)["artifacts"]
    assert entry["reference"] == items[0]["reference"] and entry["build_image"] is None


def test_language_build_receipts_bind_produced_artifacts_to_their_build_image(upstream) -> None:
    run_root = upstream.context.run_root
    produced = artifact(run_root, "build/app", ELF)
    produced["artifact_identity"] = canonical_artifact_identity(SNAPSHOT, "build-unit-1", produced["reference"]).value
    produced["reference"]["canonical_identity"] = produced["artifact_identity"]
    upstream.accepted = _accepted(run_root, [produced], target_artifacts=[], language_sha="f" * 64)
    upstream.language = {"source_fingerprint": SNAPSHOT, "language_build_handoff_sha256": "f" * 64, "receipts": [
        {"build_unit_id": "build-unit-1", "terminal_status": "SUCCEEDED", "image": IMAGE,
         "artifacts": [produced["reference"]]},
        {"build_unit_id": "build-unit-2", "terminal_status": "FAILED", "image": {}, "artifacts": [produced["reference"]]},
        "not a receipt"]}
    result = _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)
    assert [kind for kind, _ in upstream.calls] == ["artifacts", "has", "language"]
    (entry,) = result["artifacts"]
    assert entry["build_image"] == {"image_id": IMAGE["image_id"], "user": "10001:10001"}
    assert entry["reference"] == produced["reference"] and result["language_build_handoff_sha256"] == "f" * 64


def test_language_build_metadata_must_agree_with_the_accepted_catalog(upstream) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, "bin/program", ELF)]
    upstream.accepted = _accepted(run_root, items, language_sha="f" * 64)
    upstream.language = {"source_fingerprint": SNAPSHOT, "language_build_handoff_sha256": "e" * 64, "receipts": []}
    with pytest.raises(ValueError, match="language-build metadata differ"):
        _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)
    upstream.language = {"source_fingerprint": "b" * 64, "language_build_handoff_sha256": "f" * 64, "receipts": []}
    with pytest.raises(ValueError, match="language-build metadata differ"):
        _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)


def test_conflicting_build_images_for_one_artifact_are_an_integrity_failure(upstream) -> None:
    run_root = upstream.context.run_root
    produced = artifact(run_root, "build/app", ELF)
    upstream.accepted = _accepted(run_root, [produced], target_artifacts=[], language_sha="f" * 64)
    other = {**IMAGE, "image_id": "sha256:" + "e" * 64}
    upstream.language = {"source_fingerprint": SNAPSHOT, "language_build_handoff_sha256": "f" * 64, "receipts": [
        {"build_unit_id": "u", "terminal_status": "SUCCEEDED", "image": IMAGE, "artifacts": [produced["reference"]]},
        {"build_unit_id": "u", "terminal_status": "SUCCEEDED", "image": other, "artifacts": [produced["reference"]]}]}
    with pytest.raises(FrameworkIntegrityError, match="conflicting build image"):
        _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)


def test_an_unpinned_receipt_image_is_refused(upstream) -> None:
    run_root = upstream.context.run_root
    produced = artifact(run_root, "build/app", ELF)
    upstream.accepted = _accepted(run_root, [produced], target_artifacts=[], language_sha="f" * 64)
    upstream.language = {"source_fingerprint": SNAPSHOT, "language_build_handoff_sha256": "f" * 64, "receipts": [
        {"build_unit_id": "u", "terminal_status": "SUCCEEDED", "image": {"image_id": "latest"},
         "artifacts": [produced["reference"]]}]}
    with pytest.raises(ValueError, match="image identity is invalid"):
        _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)


@pytest.mark.parametrize("defect,message", [
    ("snapshot", "another target snapshot"), ("no-manifest", "no index manifest"),
    ("manifest-run", "another run or target"), ("manifest-bytes", "accepted artifact manifest integrity"),
])
def test_accepted_catalog_must_belong_to_this_run_and_snapshot(upstream, defect, message) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, "bin/program", ELF)]
    if defect == "snapshot":
        upstream.accepted = {**_accepted(run_root, items), "source_fingerprint": "b" * 64}
    elif defect == "no-manifest":
        upstream.accepted = {**_accepted(run_root, items), "index_manifest": None}
    elif defect == "manifest-run":
        upstream.accepted = _accepted(run_root, items, run_id="other-run")
    else:
        upstream.accepted = _accepted(run_root, items)
        (run_root / upstream.accepted["index_manifest"]["path"]).write_text("{}")
    with pytest.raises(ValueError, match=message):
        _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)


def test_an_intake_reference_that_disagrees_with_the_catalog_identity_is_refused(upstream) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, "bin/program", ELF)]
    upstream.accepted = _accepted(run_root, items, target_artifacts=[{**items[0]["reference"], "sha256": "0" * 64}])
    with pytest.raises(ValueError, match="does not match catalog identity"):
        _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)


def test_the_artifact_limit_is_a_named_gap_and_entries_are_sorted_and_unique(upstream) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, f"bin/program-{index}", ELF + bytes([index])) for index in range(3)]
    upstream.accepted = _accepted(run_root, items)
    result = _accepted_inputs(unit(upstream.context, "decide.target"), {"max_artifacts": 2})
    assert len(result["artifacts"]) == 2
    assert result["gaps"] == ["max_artifacts: accepted artifact catalog exceeded configured limit"]
    assert [item["artifact_identity"] for item in result["artifacts"]] == sorted(
        item["artifact_identity"] for item in items)[:2]
    full = _accepted_inputs(unit(upstream.context, "decide.target"), {"max_artifacts": 3})
    assert len(full["artifacts"]) == 3 and full["gaps"] == []


def test_only_catalog_shards_of_the_artifacts_index_are_read(upstream) -> None:
    run_root = upstream.context.run_root
    items = [artifact(run_root, "bin/program", ELF)]
    other = catalog_shard(run_root, [artifact(run_root, "bin/other", ELF + b"o")], shard_id="members-x")
    source = source_shard(run_root, b"int main;\n")
    upstream.accepted = _accepted(run_root, items, shards=[catalog_shard(run_root, items), other, source])
    result = _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)
    assert [item["artifact_identity"] for item in result["artifacts"]] == [items[0]["artifact_identity"]]


def test_a_catalog_without_native_artifacts_is_a_named_gap(upstream) -> None:
    run_root = upstream.context.run_root
    wheel = artifact(run_root, "dist/x.whl", b"PK", "wheel")
    upstream.accepted = _accepted(run_root, [wheel], gaps=["b", "a", "a"])
    result = _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)
    assert result["artifacts"] == []
    assert result["gaps"] == ["a", "accepted_artifacts_unavailable: no native artifact catalog entries", "b"]


def test_the_real_catalog_loader_is_called_with_the_run_root(upstream) -> None:
    run_root = upstream.context.run_root
    upstream.accepted = _accepted(run_root, [artifact(run_root, "bin/program", ELF)])
    _accepted_inputs(unit(upstream.context, "decide.target"), SETTINGS)
    assert upstream.calls[0] == ("artifacts", run_root)
    assert file_sha256(run_root / upstream.accepted["index_manifest"]["path"]) == upstream.accepted["index_manifest"]["sha256"]
