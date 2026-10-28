from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config.owasp import AssessmentMode, OwaspSettings
from appsec_review.owasp_workbench.evidence import EvidenceResolver, accepted_inputs, redact
from appsec_review.owasp_workbench.standards import digest
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.retrieval.core import RetrievalCore, RetrievalLimits
from appsec_review.retrieval.model import canonical_json
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.builder import (
    FILES, FIXTURE_SECRET, SECRET_FILE, build_accepted_index_set,
)


PATH = "svc/api/handler.py"
COMPONENT = "component:0001"
NATIVE = "component:0002"


@pytest.fixture(scope="module")
def seed_publication(tmp_path_factory):
    return build_accepted_index_set(tmp_path_factory.mktemp("seed"), secrets=True)


@pytest.fixture
def publication(seed_publication, tmp_path_factory):
    base = tmp_path_factory.mktemp("pub")
    shutil.copytree(seed_publication.target.parent, base, dirs_exist_ok=True)
    fixture = replace(seed_publication, runs_dir=base / "runs",
                      run_root=base / "runs" / seed_publication.run_id, target=base / "target")
    manifest_path = fixture.run_root / "data" / "indices" / "manifests" / "fixture.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    write_manifest(
        manifest_path, run_id=fixture.run_id, target_snapshot=fixture.snapshot, target_root=fixture.target,
        indexes=[IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in manifest["indexes"]],
    )
    repin(fixture, manifest_path)
    return fixture


def repin(publication, manifest_path):
    pointer_path = publication.run_root / "data" / "indices" / "accepted.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    pointer["manifest_path"] = manifest_path.relative_to(publication.run_root).as_posix()
    handoff_path = publication.run_root / pointer["handoff_path"]
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["artifacts"] = [{"path": pointer["manifest_path"], "sha256": file_sha256(manifest_path)}]
    atomic_json(handoff_path, handoff)
    pointer.update(manifest_sha256=file_sha256(manifest_path), handoff_sha256=file_sha256(handoff_path))
    atomic_json(pointer_path, pointer)


def resolver(publication, **kwargs):
    return EvidenceResolver(
        RetrievalCore(publication.runs_dir, publication.run_id),
        accept_manifest(publication.run_root), **kwargs,
    )


def location(publication, path=PATH, *, start_line=1, end_line=None, **changes):
    data = (publication.target / path).read_bytes()
    value = SourceLocation(
        publication.snapshot, path, file_sha256(publication.target / path), 0, len(data),
        start_line, end_line or start_line, 1, 1, {}, "fixture-exact", 1.0,
    )
    return replace(value, **changes)


def record(publication, kind, key, payload, loc=None):
    identity = LogicalIdentity.derive(kind, publication.snapshot, {"binding-test": key})
    return EntityRecord(identity, key, key, key, payload, loc)


def publish(publication, name, shard_id, entities, *, job="job_evidence_collection", replacing=False):
    """Republish through the real index/manifest and accepted-handoff contracts."""
    manifest_path = publication.run_root / "data" / "indices" / "manifests" / "fixture.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fingerprint = digest([name, shard_id, job, [asdict(item) for item in entities]])
    path = publication.run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint=fingerprint,
                           target_snapshot=publication.snapshot, shard_id=shard_id)
    for item in entities:
        builder.add_entity(item)
    builder.add_coverage("evidence-binding", "complete", None)
    identity = IndexIdentity(
        name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
        path.relative_to(publication.run_root).as_posix(), {"job": job}, (), shard_id,
    )
    previous = [
        IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
        for item in manifest["indexes"]
        if not (replacing and item["name"] == name and item["shard_id"] == shard_id)
    ]
    write_manifest(
        manifest_path, run_id=publication.run_id, target_snapshot=publication.snapshot,
        target_root=publication.target, indexes=[*previous, identity],
    )
    repin(publication, manifest_path)
    return entities[0].identity.value


def source(publication, *, path=PATH, text=None, loc=None):
    if text is not None:
        (publication.target / path).write_text(text, encoding="utf-8")
    item = EntityRecord(LogicalIdentity.parse(publication.ids[path]), path, path, path,
                        {"path": path, "language": "Python"}, loc or location(publication, path))
    remaining = [
        EntityRecord(LogicalIdentity.parse(publication.ids[other]), other, other, other,
                     {"path": other, "language": language}, location(publication, other))
        for other, (language, _text) in {**FILES, SECRET_FILE: ("C++", "")}.items() if other != path
    ]
    publish(publication, "source", "default", [item, *remaining], job="job_target_catalog", replacing=True)
    return item


def settings(**changes):
    return replace(OwaspSettings(True, AssessmentMode.QUALIFICATION, "reviewer", 50, 120, 10, 10, 2, 10),
                   **changes)


def inputs(publication, **changes):
    core = RetrievalCore(publication.runs_dir, publication.run_id)
    scope = accept_manifest(publication.run_root)
    return accepted_inputs(core, settings(**changes), manifest_path=scope.manifest_path)


def test_original_source_and_scanner_references_reresolve(publication):
    bound = resolver(publication)
    source_value = bound.materialize(publication.ids[PATH], component_id=COMPONENT)
    assert source_value["category"] == "source"
    assert "return db.raw(q)" in source_value["excerpt"]
    assert source_value["reference"]["build_unit_id"] == "py-svc"
    assert source_value["reference"]["environment"] == "unestablished"
    assert source_value["reference"]["locator"]["lines"] == [1, 4]
    assert bound.resolve(source_value["reference"], component_id=COMPONENT) == source_value
    scanner = bound.materialize(publication.ids["sast_high"], component_id=COMPONENT)
    assert scanner["category"] == "scanner_observation"
    assert scanner["reference"]["locator"]["lines"] == [3, 3]
    assert bound.resolve(scanner["reference"], component_id=COMPONENT) == scanner


@pytest.mark.parametrize("field,value", [
    ("run_id", "2026-10-12-0002"), ("target_snapshot", "target-sha256:" + "8" * 64),
    ("manifest_sha256", "0" * 64),
])
def test_resolver_rejects_mismatched_run_target_or_manifest_scope(publication, field, value):
    core = RetrievalCore(publication.runs_dir, publication.run_id)
    scope = replace(accept_manifest(publication.run_root), **{field: value})
    with pytest.raises(ValueError, match="isolation mismatch"):
        EvidenceResolver(core, scope)


@pytest.mark.parametrize("field,value", [
    ("run_id", "2026-10-12-0002"), ("target_snapshot", "target-sha256:" + "8" * 64),
    ("component_id", NATIVE), ("build_unit_id", "native-main"), ("environment", "production"),
    ("content_sha256", "0" * 64), ("entity_kind", "symbol"),
    ("publication.sha256", "0" * 64), ("publication.manifest_sha256", "0" * 64),
    ("publication.shard_id", "other"), ("locator.file_sha256", "0" * 64),
    ("locator.source_custody", {"source_domain": "generated"}),
    ("locator.path", "svc/api/util.py"), ("locator.lines", [1, 99]),
    ("locator.lines", [True, 1]), ("locator.extra", "invented"),
])
def test_reference_identity_scope_custody_and_span_tampering_is_denied(publication, field, value):
    bound = resolver(publication)
    citation = deepcopy(bound.materialize(publication.ids[PATH], component_id=COMPONENT)["reference"])
    keys = field.split(".")
    parent = citation
    for key in keys[:-1]:
        parent = parent[key]
    parent[keys[-1]] = value
    with pytest.raises(ValueError):
        bound.resolve(citation, component_id=COMPONENT)
    assert bound.metrics["denials"] == 1


def test_wrong_component_and_span_escaping_accepted_subject_are_denied(publication):
    bound = resolver(publication)
    with pytest.raises(ValueError, match="different or unresolved component"):
        bound.materialize(publication.ids[PATH], component_id=NATIVE)
    citation = bound.materialize(publication.ids["sast_high"], component_id=COMPONENT)["reference"]
    citation["locator"]["lines"] = [2, 3]
    with pytest.raises(ValueError, match="escapes its accepted subject"):
        bound.resolve(citation, component_id=COMPONENT)


@pytest.mark.parametrize("changed", ["stale", "missing"])
def test_verified_source_is_not_replaced_by_stale_or_missing_target(publication, changed):
    bound = resolver(publication)
    citation = bound.materialize(publication.ids[PATH], component_id=COMPONENT)["reference"]
    path = publication.target / PATH
    if changed == "stale":
        path.write_text("changed source\n", encoding="utf-8")
    else:
        path.unlink()
    with pytest.raises(ValueError, match="changed after indexing|unavailable"):
        bound.resolve(citation, component_id=COMPONENT)


@pytest.mark.parametrize("change", [{"end_line": 99}, {"end_byte": 100000}, {"start_byte": 100000, "end_byte": 100001}])
def test_accepted_location_must_fit_verified_bytes_and_lines(publication, change):
    source(publication, loc=location(publication, **change))
    with pytest.raises(ValueError, match="outside verified content"):
        resolver(publication).materialize(publication.ids[PATH], component_id=COMPONENT)


def test_configured_500_line_cap_round_trips_and_default_120_is_truthful(publication):
    source(publication, text="".join(f"line_{number}\n" for number in range(200)))
    bound = resolver(publication, max_source_lines=500)
    value = bound.materialize(publication.ids[PATH], component_id=COMPONENT)
    assert value["reference"]["locator"]["lines"] == [1, 200]
    assert not value["truncated"]
    assert bound.resolve(value["reference"], component_id=COMPONENT) == value
    default = resolver(publication)
    short = default.materialize(publication.ids[PATH], component_id=COMPONENT)
    assert short["reference"]["locator"]["lines"] == [1, 120]
    assert short["truncated"]
    assert "80 accepted subject lines omitted" in " ".join(short["limitations"])
    with pytest.raises(ValueError, match="span is invalid"):
        default.resolve(value["reference"], component_id=COMPONENT)
    with pytest.raises(ValueError, match="configured cap"):
        default.materialize(publication.ids[PATH], component_id=COMPONENT, max_lines=500)


def test_bounded_subspans_and_character_clipping_report_truncation(publication):
    source(publication, text="a" * 17000 + "\n")
    bound = resolver(publication)
    value = bound.materialize(publication.ids[PATH], component_id=COMPONENT)
    assert len(value["excerpt"]) == 16000
    assert value["truncated"]
    assert "1000 redacted characters omitted" in " ".join(value["limitations"])
    assert bound.metrics["truncations"] == 1
    source(publication, text="one\ntwo\nthree\nfour\n")
    bound = resolver(publication)
    value = bound.materialize(publication.ids[PATH], component_id=COMPONENT)
    locator = {**value["reference"]["locator"], "lines": [2, 3]}
    selected = bound.materialize(publication.ids[PATH], component_id=COMPONENT, locator=locator)
    assert selected["truncated"]
    assert "2 accepted subject lines omitted" in " ".join(selected["limitations"])
    assert bound.resolve(selected["reference"], component_id=COMPONENT) == selected


@pytest.mark.parametrize("index", ["analysis", "source"])
def test_duplicate_identity_uses_original_catalog_despite_other_index_copy(publication, index):
    item = EntityRecord(LogicalIdentity.parse(publication.ids[PATH]), PATH, PATH, PATH,
                        {"component_id": COMPONENT, "result": {"derived": "not original"}}, location(publication))
    publish(publication, index, "duplicate", [item], job="job_tree_sitter_ast")
    bound = resolver(publication)
    value = bound.materialize(publication.ids[PATH], component_id=COMPONENT)
    assert value["reference"]["publication"]["index"] == "source"
    assert bound.resolve(value["reference"], component_id=COMPONENT) == value


@pytest.mark.parametrize("conflict", [False, True])
def test_duplicate_original_records_must_be_equivalent_even_with_pagination(publication, conflict):
    original = source(publication)
    item = replace(original, payload={"language": "C"} if conflict else original.payload)
    publish(publication, "source", "second-original", [item], job="job_target_catalog")
    core = RetrievalCore(publication.runs_dir, publication.run_id, limits=RetrievalLimits(max_results=1))
    bound = EvidenceResolver(core, accept_manifest(publication.run_root))
    if conflict:
        with pytest.raises(ValueError, match="conflicting accepted original"):
            bound.materialize(publication.ids[PATH], component_id=COMPONENT)
    else:
        value = bound.materialize(publication.ids[PATH], component_id=COMPONENT)
        assert value["reference"]["publication"]["shard_id"] == "default"
        assert bound.resolve(value["reference"], component_id=COMPONENT) == value
        assert bound.metrics["truncations"] > 0  # Lookup pagination is accounted for, not denied.


@pytest.mark.parametrize("flavor", ["owasp", "precomputed", "worker"])
def test_downstream_precomputed_and_worker_conclusions_are_not_original_evidence(publication, flavor):
    if flavor == "precomputed":
        identity = publication.ids["advisory_fact"]
    else:
        item = record(publication, EntityKind.TOOL_OBSERVATION, flavor,
                      {"component_id": COMPONENT, "result": {"verified": True},
                       **({"producer": "bounded_inference"} if flavor == "worker" else {})},
                      location(publication))
        identity = publish(publication, "observations", flavor, [item],
                           job="job_owasp_control_assessment" if flavor == "owasp" else "job_post_build_security_assessment")
    with pytest.raises(ValueError, match="outside accepted upstream"):
        resolver(publication).materialize(identity, component_id=COMPONENT)


@pytest.mark.parametrize("payload", [
    {"component_id": COMPONENT}, {"component_id": COMPONENT, "language": "Python"},
    {"component_id": COMPONENT, "sha256": "a" * 64},
    {"component_id": COMPONENT, "result": {}},
    {"component_id": COMPONENT, "result": {"component_id": COMPONENT}},
])
def test_identity_and_empty_metadata_are_not_meaningful_structured_evidence(publication, payload):
    item = record(publication, EntityKind.EVIDENCE_ARTIFACT, "metadata", payload)
    identity = publish(publication, "evidence", "metadata", [item])
    with pytest.raises(ValueError, match="meaningful structured locator"):
        resolver(publication).materialize(identity, component_id=COMPONENT)


def test_structured_check_resolves_original_accepted_record_and_pointer(publication):
    item = record(publication, EntityKind.EVIDENCE_ARTIFACT, "check",
                  {"component_id": COMPONENT, "build_unit_id": "py-svc",
                   "checks": [{"check_id": "stack-protector", "status": "PASS"}]})
    identity = publish(publication, "evidence", "check", [item])
    bound = resolver(publication)
    value = bound.materialize(identity, component_id=COMPONENT)
    assert value["category"] == "static_fact"
    assert value["reference"]["locator"]["pointer"] == "/payload/checks"
    assert "stack-protector" in value["excerpt"]
    assert bound.resolve(value["reference"], component_id=COMPONENT) == value
    citation = deepcopy(value["reference"])
    citation["locator"]["pointer"] = "/payload/component_id"
    with pytest.raises(ValueError, match="locator differs"):
        bound.resolve(citation, component_id=COMPONENT)


@pytest.mark.parametrize("flavor", [
    "component", "build", "mapping", "shared", "declared-build", "declared-shared",
    "unknown-build", "unknown-component",
])
def test_ambiguous_shared_and_conflicting_ownership_fails_closed(publication, flavor):
    if flavor in {"declared-build", "declared-shared", "unknown-build", "unknown-component"}:
        payload = {
            "declared-build": {"component_id": COMPONENT, "build_unit_id": "native-main"},
            "declared-shared": {"subject": {"component_ownership": "shared", "component_id": COMPONENT}},
            "unknown-build": {"build_unit_id": "unknown"},
            "unknown-component": {"component_id": "unknown"},
        }[flavor]
        item = record(publication, EntityKind.SYMBOL, flavor,
                      payload, location(publication))
        identity = publish(publication, "analysis", flavor, [item], job="job_tree_sitter_ast")
        bound = resolver(publication)
    else:
        bound = resolver(publication)
        identity = publication.ids[PATH]
        if flavor == "component":
            bound.scope = replace(bound.scope, components=(*bound.scope.components,
                replace(bound.scope.components[0], component_id="component:other", root="svc")))
        elif flavor == "build":
            bound.scope = replace(bound.scope, build_units=(*bound.scope.build_units,
                replace(next(item for item in bound.scope.build_units if item.root == "svc"),
                        build_unit_id="another-unit")))
        elif flavor == "mapping":
            source(publication, loc=location(publication, ambiguous=True))
            bound = resolver(publication)
        else:
            identity = publication.ids[".github/workflows/ci.yml"]
    with pytest.raises(ValueError, match="ambiguous|no component ownership|disagrees|unknown"):
        bound.materialize(identity, component_id=COMPONENT)


def test_authentic_unrelated_same_component_reference_resolves_but_does_not_prove_entailment(publication):
    bound = resolver(publication)
    unrelated = bound.materialize(publication.ids["svc/api/util.py"], component_id=COMPONENT)
    assert unrelated["excerpt"] == "assert True"
    assert bound.resolve(unrelated["reference"], component_id=COMPONENT) == unrelated
    assert "outcome" not in unrelated


def test_tag_cloud_priorities_and_graph_are_bounded_routing_not_proof(publication):
    graph = record(publication, EntityKind.SYMBOL, "graph-symbol",
                   {"scope": {"component_id": COMPONENT, "build_unit_id": "py-svc"},
                    "classification": "entry_point", "result": {"source_class": "network"}}, location(publication))
    identity = publish(publication, "graph", "routing", [graph], job="job_code_graph_index")
    bound = resolver(publication)
    for key in ("tag:0", "priority:handler"):
        value = bound.materialize(publication.ids[key], component_id=COMPONENT)
        assert value["category"] == "declaration"
        assert "routing/context only" in " ".join(value["limitations"])
    assert bound.materialize(identity, component_id=COMPONENT)["category"] == "declaration"
    result = inputs(publication)
    component = next(item for item in result["components"] if item["component_id"] == COMPONENT)
    assert component["tag_cloud"] == {
        "usage": "routing_only", "counts": {"asvs:v5-input": 1, "cwe:89": 1}, "counts_are_lower_bounds": True,
        "count_metric": "distinct_subjects", "reading_rule": "Absent tags are unknown, never proof of absence.",
    }
    assert {row["index"] for row in component["routing_context"]} == {"tags", "priority", "graph"}
    assert all(row["usage"] == "routing_only" for row in component["routing_context"])
    assert any(row["identity"] == identity for row in component["routing_context"])
    limited = inputs(publication, max_evidence_per_component=1)
    assert all(len(item["routing_context"]) <= 1 for item in limited["components"])
    assert all(sum(item["component_id"] == component["component_id"] for item in limited["evidence"]) <= 1
               for component in limited["components"])
    assert "at least" in " ".join(limited["limitations"])
    assert "omitted" in " ".join(limited["limitations"])
    exact_source_cap = inputs(publication, max_evidence_per_component=2)
    assert any(line.startswith(COMPONENT + ": evidence cap reached; at least ")
               for line in exact_source_cap["limitations"])


def test_unlocated_graph_scope_is_routing_context_and_not_static_proof(publication):
    graph = record(publication, EntityKind.ENTRY_POINT, "entry",
                   {"scope": {"component_id": COMPONENT, "build_unit_id": "py-svc"},
                    "family": "entry_point", "result": {"source_class": "network"}})
    identity = publish(publication, "graph", "entry", [graph], job="job_code_graph_index")
    bound = resolver(publication)
    value = bound.materialize(identity, component_id=COMPONENT)
    assert value["category"] == "declaration"
    component = next(item for item in inputs(publication)["components"] if item["component_id"] == COMPONENT)
    assert any(row["identity"] == identity and row["context"]["result"]["source_class"] == "network"
               for row in component["routing_context"])


def test_source_and_input_excerpts_redact_values_without_losing_names(publication):
    bound = resolver(publication)
    value = bound.materialize(publication.ids[SECRET_FILE], component_id=NATIVE)
    assert "kApiKey" in value["excerpt"] and "send_key" in value["excerpt"]
    assert FIXTURE_SECRET not in json.dumps(value)
    assert value["redaction"]["applied"]
    assert bound.resolve(value["reference"], component_id=NATIVE) == value
    assert FIXTURE_SECRET not in json.dumps(inputs(publication))


def fingerprints(value):
    return {item["component_id"]: item["evidence_fingerprint"] for item in value["components"]}


def test_component_evidence_fingerprint_survives_unrelated_manifest_repin(publication):
    before = inputs(publication)
    original = publication.run_root / "data" / "indices" / "manifests" / "fixture.json"
    manifest = json.loads(original.read_text(encoding="utf-8"))
    manifest.pop("content_sha256")
    manifest["unrelated_root_metadata_note"] = "republished unchanged accepted component shards"
    manifest["content_sha256"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    republished = original.with_name("fixture-repin.json")
    atomic_json(republished, manifest)
    repin(publication, republished)
    after = inputs(publication)
    assert before["retrieval_manifest"] != after["retrieval_manifest"]
    assert before["evidence"][0]["reference"]["publication"] != after["evidence"][0]["reference"]["publication"]
    assert before["evidence"][0]["evidence_id"] != after["evidence"][0]["evidence_id"]
    assert fingerprints(before) == fingerprints(after)
    assert all(item["reference"]["publication"]["manifest_sha256"] == after["retrieval_manifest"]["sha256"]
               for item in after["evidence"])


def test_source_change_only_invalidates_affected_component_despite_shared_shard_repin(publication):
    before = inputs(publication)
    source(publication, path="native/src/parse.c", text="int changed_parse(void) { return 1; }\n" * 6)
    after = inputs(publication)
    assert before["retrieval_manifest"] != after["retrieval_manifest"]
    assert fingerprints(before)[COMPONENT] == fingerprints(after)[COMPONENT]
    assert fingerprints(before)[NATIVE] != fingerprints(after)[NATIVE]


def test_routing_change_invalidates_component_even_when_outside_evidence_cap(publication):
    before = inputs(publication, max_evidence_per_component=3)
    tags = []
    for number, (path, tag) in enumerate(((PATH, "func:auth:authentication"), (PATH, "cwe:89"),
                                         ("native/src/parse.c", "cwe:120"))):
        tags.append(EntityRecord(
            LogicalIdentity.parse(publication.ids[f"tag:{number}"]), f"tag-{number}", tag, f"{tag} {path}",
            {"tag": tag, "subject": {"kind": "file", "path": path, "logical_id": publication.ids[path]}},
            location(publication, path),
        ))
    publish(publication, "tags", "security-domain", tags, job="job_security_tagging", replacing=True)
    after = inputs(publication, max_evidence_per_component=3)
    assert all(item["reference"]["source_identity"] != publication.ids["tag:0"] for item in before["evidence"])
    assert fingerprints(before)[COMPONENT] != fingerprints(after)[COMPONENT]
    assert fingerprints(before)[NATIVE] == fingerprints(after)[NATIVE]


def test_private_key_body_cannot_leak_when_requested_span_omits_header(publication):
    source(publication, text="-----BEGIN PRIVATE KEY-----\nplain-key-body\n-----END PRIVATE KEY-----\n")
    item = record(publication, EntityKind.SYMBOL, "key-body", {},
                  location(publication, start_line=2))
    identity = publish(publication, "analysis", "key-body", [item], job="job_tree_sitter_ast")
    bound = resolver(publication)
    value = bound.materialize(identity, component_id=COMPONENT)
    assert "plain-key-body" not in value["excerpt"]
    assert value["redaction"]["applied"]
    assert bound.resolve(value["reference"], component_id=COMPONENT) == value


@pytest.mark.parametrize("text,secret,name", [
    ('const char *password = "short";', "short", "password"),
    ('{"password": "short", "logical_id": "asr:symbol:' + "1" * 64 + '"}', "short", "logical_id"),
    ('API_KEY=opaqueCredential', "opaqueCredential", "API_KEY"),
    ('Authorization: Bearer abc123456', "abc123456", "Authorization"),
    ('endpoint = "https://service:opaqueCredential@example.test"', "opaqueCredential", "endpoint"),
    ('// ghp_1234567890abcdefghijklmnopqrstuvwxyz', "ghp_1234567890abcdefghijklmnopqrstuvwxyz", "//"),
    ('-----BEGIN PRIVATE KEY-----\nplain-key-body\n-----END PRIVATE KEY-----', "plain-key-body", "<redacted:"),
])
def test_redaction_handles_credentials_and_keeps_canonical_names(text, secret, name):
    safe, changed = redact(text)
    assert changed and secret not in safe
    assert name in safe
