from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import ast
import hashlib
import json
from pathlib import Path
import shutil

from jsonschema import Draft202012Validator
import pytest
from referencing.exceptions import NoSuchResource

from appsec_review.jobs.job_openvex_export import contracts as c
from appsec_review.jobs.accepted_review import HANDOFF_SCHEMA as REVIEW_HANDOFF_SCHEMA
from appsec_review.review.models import IntegrityError
from tests.openvex_support import (
    SCHEMAS, enabled_settings, example_bundle, make_verified_inputs, schema_registry, schema_validator,
)


def test_contract_imports_no_unimplemented_job_modules() -> None:
    forbidden = {"job", "inputs", "projection", "validation", "metrics", "reporting", "datasets"}
    package_root = Path(c.__file__).parent
    for filename in ("contracts.py", "settings.py"):
        for node in ast.walk(ast.parse((package_root / filename).read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    assert module.split(".")[0] not in forbidden
                elif module.startswith("appsec_review.jobs.job_openvex_export."):
                    assert module.rsplit(".", 1)[-1] not in forbidden


def test_upstream_pin_license_and_schema_resource_identity() -> None:
    lock_bytes = (SCHEMAS / "upstream" / "upstream.lock.json").read_bytes()
    assert hashlib.sha256(lock_bytes).hexdigest() == c.UPSTREAM_LOCK_SHA256
    lock = json.loads(lock_bytes)
    assert lock["commit"] == c.UPSTREAM_COMMIT and lock["version"] == "0.2.0"
    assert lock["license"] == "CC0-1.0" and "OpenVEX" in lock["attribution"]
    for name in ("schema_source", "license_source"):
        source = lock[name]
        payload = (SCHEMAS / "upstream" / source["path"]).read_bytes()
        assert len(payload) == source["size_bytes"]
        assert hashlib.sha256(payload).hexdigest() == source["sha256"]
        assert b"\r" not in payload
    assert lock["schema_source"]["sha256"] == c.UPSTREAM_SCHEMA_SHA256
    assert lock["license_source"]["sha256"] == c.UPSTREAM_LICENSE_SHA256
    assert b"CC0 1.0 Universal" in (SCHEMAS / "upstream" / "LICENSE").read_bytes()
    for relative, expected in c.SCHEMA_SHA256.items():
        payload = (SCHEMAS / relative).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected
        Draft202012Validator.check_schema(json.loads(payload))
    assert c.VALIDATION_PROFILE_SHA256 != c.UPSTREAM_SCHEMA_SHA256
    gate_schema = json.loads((SCHEMAS.parent / "final-report" / "final-publication-gate.schema.json").read_bytes())
    report_schema = json.loads((SCHEMAS.parent / "final-report" / "final-report.schema.json").read_bytes())
    review_schema = json.loads((SCHEMAS.parent / "inference-security-review" / "handoff.schema.json").read_bytes())
    assert gate_schema["properties"]["schema"]["const"] == c.FINAL_PUBLICATION_GATE_SCHEMA == (
        "appsec-review/final-publication-gate/2")
    assert report_schema["properties"]["schema"]["const"] == "appsec-review/final-report/2"
    assert review_schema["properties"]["schema"]["const"] == REVIEW_HANDOFF_SCHEMA == (
        "appsec-review/inference-review-handoff/3")


def test_offline_registry_resolves_installed_layout_without_remote_retrieval(tmp_path: Path) -> None:
    installed = tmp_path / "share" / "appsec-review" / "schemas" / "openvex-export"
    for relative in c.SCHEMA_SHA256:
        destination = installed / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCHEMAS / relative, destination)
    for inputs in (make_verified_inputs(), make_verified_inputs(
            ("publishable", "publishable", "verification_backlog"), completion_attachments=True)):
        bundle = example_bundle(inputs)
        schema_validator("manifest.schema.json", installed).validate(c.json_body(bundle.manifest))
        schema_validator("result.schema.json", installed).validate(c.json_body(bundle.result))
        schema_validator("upstream/openvex-v0.2.0.schema.json", installed).validate(c.json_body(bundle.document))
    with pytest.raises(NoSuchResource):
        schema_registry(installed).get_or_retrieve("https://example.invalid/never-fetch.json")


@pytest.mark.parametrize("buckets", [(), ("publishable",), ("verification_backlog",), ("withheld",),
                                    ("publishable", "verification_backlog", "withheld")])
def test_synthetic_verified_inputs_and_complete_example_shapes(buckets: tuple[str, ...]) -> None:
    inputs = make_verified_inputs(buckets)
    schema_validator("../final-report/final-publication-gate.schema.json").validate(c.json_body(inputs.gate))
    assert c.VerifiedInputs.from_mapping(inputs.to_json()) == inputs
    bundle = example_bundle(inputs)
    schema_validator("manifest.schema.json").validate(c.json_body(bundle.manifest))
    schema_validator("result.schema.json").validate(c.json_body(bundle.result))
    eligible = buckets.count("publishable")
    assert bundle.result["statement_count"] == bundle.result["included_findings"] == eligible
    assert bundle.result["excluded_findings"] == len(buckets) - eligible
    assert len(bundle.manifest["packages"]) == len(buckets)
    if eligible:
        schema_validator("upstream/openvex-v0.2.0.schema.json").validate(c.json_body(bundle.document))
        assert len(bundle.document["statements"]) == eligible
        assert {statement["status"] for statement in bundle.document["statements"]} == {"affected"}
    else:
        assert bundle.document is bundle.document_bytes is bundle.document_ref is None
        assert bundle.result["outcome"] == "no_statements" and c.NO_STATEMENTS_GAP in bundle.result["gaps"]


def test_gate_v2_completion_context_is_exact_immutable_and_does_not_change_eligibility() -> None:
    inputs = make_verified_inputs(("publishable", "publishable", "verification_backlog"), completion_attachments=True)
    assert inputs.gate["schema"] == c.FINAL_PUBLICATION_GATE_SCHEMA
    assert "unavailable_inputs" not in inputs.gate
    assert c.VerifiedInputs.from_mapping(inputs.to_json()) == inputs
    schema_validator("../final-report/final-publication-gate.schema.json").validate(c.json_body(inputs.gate))
    bundle = example_bundle(inputs)
    schema_validator("manifest.schema.json").validate(c.json_body(bundle.manifest))
    schema_validator("result.schema.json").validate(c.json_body(bundle.result))
    context = bundle.manifest["review_context"]
    for name in ("capabilities", "attachments", "limitations"):
        assert c.canonical_bytes(context[name]) == c.canonical_bytes(inputs.gate[name])
    assert inputs.gate["attachments"]["poc_generation"][0]["status"] == "compile_failed"
    assert inputs.gate["attachments"]["attack_chains"][0]["status"] == "qualified_supported"
    assert len(inputs.gate["attachments"]["remediation_planning"]) == 2
    assert len(inputs.gate["attachments"]["remediation_validation"]) == 2
    assert len(inputs.gate["attachments"]["dossiers"]) == 3
    assert bundle.result["outcome"] == "exported_with_gaps"
    assert bundle.result["included_findings"] == bundle.result["statement_count"] == 2
    assert bundle.result["excluded_findings"] == 1
    assert {statement["status"] for statement in bundle.document["statements"]} == {"affected"}
    notice = next(item for item in context["limitations"] if item["limitation_id"] == "compile_only_nonexecution")
    assert notice["kind"] == "notice" and notice["limitation_id"] not in bundle.result["gaps"]
    with pytest.raises(TypeError):
        context["attachments"]["poc_generation"][0]["files"]["source"]["sha256"] = "0" * 64
    changed = c.json_body(bundle.manifest)
    changed["review_context"]["unavailable_inputs"] = {}
    assert list(schema_validator("manifest.schema.json").iter_errors(changed))


def _rebind_gate(inputs: c.VerifiedInputs, gate: dict) -> c.VerifiedInputs:
    payload = c.canonical_bytes(gate)
    reference = c.ArtifactRef(inputs.provenance.gate.path, hashlib.sha256(payload).hexdigest())
    inventory = tuple(c.SizedArtifactRef(reference.path, reference.sha256, len(payload))
                      if item.path == reference.path else item for item in inputs.input_inventory)
    return replace(inputs, gate=gate, provenance=replace(inputs.provenance, gate=reference), input_inventory=inventory)


@pytest.mark.parametrize("section,path", [
    ("inputs", ("review_handoff",)),
    ("capabilities", ("attack_chains", "summary")),
    ("capabilities", ("poc_generation", "handoff")),
    ("attachments", ("attack_chains", 0, "artifact")),
    ("attachments", ("poc_generation", 0, "files", "source")),
    ("attachments", ("remediation_planning", 0, "plan")),
    ("attachments", ("remediation_validation", 0, "validation")),
    ("attachments", ("dossiers", 0, "files", "receipt")),
])
def test_gate_v2_context_references_require_certification_and_measured_inventory(section, path) -> None:
    inputs = make_verified_inputs(("publishable", "publishable"), completion_attachments=True)
    gate = c.json_body(inputs.gate)
    reference = gate[section]
    for part in path:
        reference = reference[part]
    assert reference in gate["bindings"]
    gate["bindings"].remove(reference)
    with pytest.raises(ValueError, match="certified bindings"):
        _rebind_gate(inputs, gate)
    with pytest.raises(ValueError, match="omits"):
        replace(inputs, input_inventory=tuple(
            item for item in inputs.input_inventory if item.reference.to_json() != reference))


def test_legacy_gate_and_missing_v2_context_are_not_accepted_under_a_new_hash() -> None:
    inputs = make_verified_inputs()
    gate = c.json_body(inputs.gate)
    gate["schema"] = "appsec-review/final-publication-gate/1"
    with pytest.raises(ValueError, match="schema"):
        _rebind_gate(inputs, gate)
    gate = c.json_body(inputs.gate)
    del gate["capabilities"]
    del gate["attachments"]
    gate["unavailable_inputs"] = {}
    with pytest.raises(ValueError, match="strict capability"):
        _rebind_gate(inputs, gate)


def test_empty_review_has_a_bound_chain_manifest_and_notice_is_not_a_coverage_gap() -> None:
    inputs = make_verified_inputs(())
    chains = inputs.gate["capabilities"]["attack_chains"]
    assert chains["enabled"] is True and chains["disposition"] == "SKIPPED_NA"
    assert chains["summary"] in inputs.gate["bindings"]
    assert chains["summary"] in [item.reference.to_json() for item in inputs.input_inventory]
    clean = example_bundle(make_verified_inputs())
    assert clean.result["outcome"] == "exported"
    assert "compile_only_nonexecution" not in clean.result["gaps"]
    assert len([item for item in clean.manifest["review_context"]["limitations"] if item["kind"] == "notice"]) == 1
    assert example_bundle(inputs).result["outcome"] == "no_statements"


def test_local_schema_objects_are_closed_and_arrays_bounded() -> None:
    def check(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            if value.get("type") == "array":
                assert type(value.get("maxItems")) is int
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    for name in ("common.schema.json", "manifest.schema.json", "result.schema.json"):
        check(json.loads((SCHEMAS / name).read_bytes()))


def test_local_schemas_reject_unknown_fields_counts_and_empty_success() -> None:
    bundle = example_bundle()
    for name, body in (("manifest", bundle.manifest), ("result", bundle.result)):
        changed = c.json_body(body)
        changed["extra"] = "not accepted"
        assert list(schema_validator(f"{name}.schema.json").iter_errors(changed))
    result = c.json_body(bundle.result)
    result["statement_count"] = 10001
    assert list(schema_validator("result.schema.json").iter_errors(result))
    result["statement_count"] = 0
    assert list(schema_validator("result.schema.json").iter_errors(result))
    empty = c.json_body(example_bundle(make_verified_inputs(())).result)
    empty["gaps"] = []
    assert list(schema_validator("result.schema.json").iter_errors(empty))
    manifest = c.json_body(bundle.manifest)
    manifest["packages"][0]["finding"]["unsafe_extra"] = "no"
    assert list(schema_validator("manifest.schema.json").iter_errors(manifest))
    for field, maximum in (("document", c.MAX_DOCUMENT_BYTES), ("manifest", c.MAX_MANIFEST_BYTES)):
        result = c.json_body(bundle.result)
        result[field]["size_bytes"] = maximum
        assert not list(schema_validator("result.schema.json").iter_errors(result))
        result[field]["size_bytes"] += 1
        assert list(schema_validator("result.schema.json").iter_errors(result))


@pytest.mark.parametrize("field", ["@context", "@id", "author", "timestamp", "version", "statements"])
def test_upstream_required_document_fields(field: str) -> None:
    body = c.json_body(example_bundle().document)
    del body[field]
    assert list(schema_validator("upstream/openvex-v0.2.0.schema.json").iter_errors(body))


def test_upstream_affected_requires_action_nonempty_statements_and_closed_objects() -> None:
    validator = schema_validator("upstream/openvex-v0.2.0.schema.json")
    document = c.json_body(example_bundle().document)
    del document["statements"][0]["action_statement"]
    assert list(validator.iter_errors(document))
    document = c.json_body(example_bundle().document)
    document["statements"] = []
    assert list(validator.iter_errors(document))
    for where in ("document", "statement", "vulnerability", "product"):
        document = c.json_body(example_bundle().document)
        objects = {"document": document, "statement": document["statements"][0],
                   "vulnerability": document["statements"][0]["vulnerability"],
                   "product": document["statements"][0]["products"][0]}
        objects[where]["schema"] = "local-fields-are-not-openvex"
        assert list(validator.iter_errors(document))


def test_upstream_schema_is_not_the_local_semantic_validator() -> None:
    # These are deliberate upstream gaps. Wave 1 must reject them semantically, not edit the pin.
    document = c.json_body(example_bundle().document)
    document["@context"] = "https://example.test/not-openvex"
    document["author"] = "bot"
    document["timestamp"] = "not-a-date"
    document["statements"][0]["products"] = []
    document["statements"][0]["action_statement"] = ""
    schema_validator("upstream/openvex-v0.2.0.schema.json").validate(document)


def test_identity_formulas_domains_and_no_self_hash_cycle() -> None:
    inputs, settings = make_verified_inputs(), enabled_settings()
    repository, snapshot, config = inputs.source.repository_iri, inputs.source.target_snapshot, inputs.provenance.resolved_config_sha256
    assert c.source_product_id(repository, snapshot, config) == (
        f"urn:appsec-review:source-snapshot:{c.json_sha256(repository)}:{snapshot}:{config}")
    claim = inputs.findings[0].claim_id
    assert c.vulnerability_id(repository, snapshot, claim).endswith(
        c.json_sha256(["openvex-vulnerability/1", repository, snapshot, claim]))
    body = {"status": "affected"}
    assert c.statement_id(settings.author, body).endswith(c.json_sha256(["openvex-statement/1", settings.author, body]))
    assert c.document_id(body).endswith(c.json_sha256(["openvex-document/1", body]))
    assert c.document_id(body) != c.statement_id(settings.author, body)
    for function in (c.document_id, lambda value: c.statement_id(settings.author, value)):
        with pytest.raises(ValueError, match="own @id"):
            function({"@id": "self"})
    assert c.vulnerability_id(repository, snapshot, claim) != c.vulnerability_id("urn:example:other", snapshot, claim)


def test_prefix_is_explicit_and_does_not_enter_document_identity() -> None:
    first = example_bundle(output_prefix="data/exports/one")
    second = example_bundle(output_prefix="data/exports/two")
    assert first.document_bytes == second.document_bytes
    assert first.manifest_bytes != second.manifest_bytes and first.result_bytes != second.result_bytes
    assert first.document_ref.path == "data/exports/one/openvex.json"
    for prefix in ("", ".", "../other", "/absolute", "data\\export", "data//export", "C:/export"):
        with pytest.raises(ValueError):
            c.output_reference(prefix, c.DOCUMENT_NAME, b"{}\n")
    with pytest.raises(ValueError):
        c.output_reference("data/export", "../file", b"{}\n")
    payload = b"x" * c.MAX_RESULT_BYTES
    assert c.output_reference("data/export", c.RESULT_NAME, payload).size_bytes == len(payload)
    with pytest.raises(ValueError, match="byte bound"):
        c.output_reference("data/export", c.RESULT_NAME, payload + b"x")


@pytest.mark.parametrize("timestamp", ["2026-10-28T14:00:00Z", "2026-10-28T10:00:00-04:00",
                                      "2026-10-28T15:00:00.000000+01:00"])
def test_gate_acceptance_timestamp_normalizes_without_a_clock(timestamp: str) -> None:
    assert c.normalize_timestamp(timestamp) == "2026-10-28T14:00:00.000000Z"


@pytest.mark.parametrize("timestamp", ["2026-10-28", "2026-10-28T10:00:00", "2026-02-30T00:00:00Z",
                                      "2026-10-28T00:00:00-00:00", "2026-10-28T00:00:00.1234567Z", "now"])
def test_invalid_or_lossy_time_is_rejected(timestamp: str) -> None:
    with pytest.raises(ValueError):
        c.normalize_timestamp(timestamp)


def test_frozen_records_do_not_expose_mutable_authority() -> None:
    inputs = make_verified_inputs()
    with pytest.raises(FrozenInstanceError):
        inputs.run_id = "changed"
    with pytest.raises(TypeError):
        inputs.gate["review"]["status"] = "EMPTY"
    with pytest.raises(TypeError):
        inputs.findings[0].projection["scores"][0]["native"]["score"] = 0
    detached = inputs.to_json()
    detached["gate"]["review"]["status"] = "EMPTY"
    assert inputs.gate["review"]["status"] == "COMPLETE"
    projection = c.json_body(inputs.findings[0].projection)
    finding = c.VerifiedFinding(projection, (), ())
    projection["title"] = "mutated original"
    assert finding.projection["title"] == "Synthetic finding 0"
    bundle = example_bundle(inputs)
    with pytest.raises(TypeError):
        bundle.result["statement_count"] = 0
    with pytest.raises(ValueError, match="disagree"):
        replace(bundle, document_bytes=b"{}\n")
    with pytest.raises(ValueError, match="no_statements"):
        replace(bundle, document=None, document_bytes=None, document_ref=None)
    empty = example_bundle(make_verified_inputs(()))
    changed = c.json_body(empty.manifest)
    changed["accounting"]["gate_publishable"] = 1
    payload = c.canonical_bytes(changed)
    reference = c.SizedArtifactRef(empty.manifest_ref.path, hashlib.sha256(payload).hexdigest(), len(payload))
    with pytest.raises(ValueError, match="genuine zero"):
        replace(empty, manifest=changed, manifest_bytes=payload, manifest_ref=reference)


def test_verified_records_require_exact_gate_coverage_and_inventory() -> None:
    inputs = make_verified_inputs(("publishable", "verification_backlog", "withheld"))
    with pytest.raises(ValueError, match="exactly cover"):
        replace(inputs, findings=inputs.findings[:1])
    with pytest.raises(ValueError, match="repeat"):
        replace(inputs, findings=(*inputs.findings, inputs.findings[0]))
    with pytest.raises(ValueError, match="omits"):
        replace(inputs, input_inventory=inputs.input_inventory[1:])
    with pytest.raises(ValueError, match="repeats"):
        replace(inputs, input_inventory=(*inputs.input_inventory, inputs.input_inventory[0]))
    gate = c.json_body(inputs.gate)
    gate["review"]["status"] = "EMPTY"
    with pytest.raises(ValueError, match="artifact hash"):
        replace(inputs, gate=gate)
    row = c.json_body(inputs.findings[0].projection)
    row.update(bucket="publishable", state="supported")
    with pytest.raises(ValueError, match="contradicts"):
        c.VerifiedFinding(row, (), ())
    with pytest.raises(ValueError, match="exactly"):
        c.VerifiedInputs.from_mapping({**inputs.to_json(), "extra": 1})


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}',
                                    b'{"x":"\\ud800"}', b'[]', b'\xff', b'{"x":1} trailing'])
def test_new_local_json_is_strict_and_bounded(payload: bytes) -> None:
    with pytest.raises(ValueError):
        c.parse_json_bytes(payload, max_bytes=1024)


def test_json_size_depth_utf8_and_finite_canonical_bytes() -> None:
    payload = '{"text":"é"}\n'.encode("utf-8")
    assert c.parse_json_bytes(payload, max_bytes=len(payload)) == {"text": "é"}
    with pytest.raises(ValueError):
        c.parse_json_bytes(payload, max_bytes=len(payload) - 1)
    assert c.canonical_bytes({"b": 1, "a": "é"}) == '{"a":"é","b":1}\n'.encode("utf-8")
    at_limit = b'{"x":' + b"[" * 31 + b"0" + b"]" * 31 + b"}"
    c.parse_json_bytes(at_limit, max_bytes=1024)
    with pytest.raises(ValueError, match="depth"):
        c.parse_json_bytes(b'{"x":' + b"[" * 32 + b"0" + b"]" * 32 + b"}", max_bytes=1024)
    assert c.parse_json_bytes(b'{"x":"[{{{\\\\\\""}', max_bytes=1024)
    for value in (float("nan"), float("inf"), {1: "not-string-key"}, object()):
        with pytest.raises(ValueError):
            c.canonical_bytes({"value": value})


def test_error_and_metric_vocabulary_is_closed_and_fail_closed() -> None:
    error = c.ExportError("protected diagnostic", reason=c.ExportFailureReason.INPUT_TAMPERED, phase=c.ExportPhase.LOAD)
    assert isinstance(error, IntegrityError) and str(error) == "protected diagnostic"
    assert error.reason.value == "input_tampered" and error.phase.value == "load"
    with pytest.raises(ValueError):
        c.ExportError("bad", reason="raw-secret-string", phase="load")
    with pytest.raises(ValueError):
        c.VexStatus("not_affected")
    assert len(c.ExportFailureReason) == 11 and {phase.value for phase in c.ExportPhase} == {
        "load", "assemble", "validate", "accept"}
    assert c.DURATION_BUCKETS[-1] == 120 and c.SIZE_BUCKETS[-1] == c.MAX_DOCUMENT_BYTES


def test_report_states_cannot_link_stale_output_or_invent_accepted_zeroes() -> None:
    missing = c.ExportReportView(c.ExportReportState.NOT_RUN, None, None, None, None, None,
                                 None, None, None, ("openvex_not_run",))
    with pytest.raises(ValueError, match="must not expose"):
        replace(missing, statement_count=0)
    bundle, inputs = example_bundle(), make_verified_inputs()
    available = c.ExportReportView(c.ExportReportState.AVAILABLE, c.ExportOutcome.EXPORTED,
                                   inputs.provenance.gate_handoff, bundle.result_ref, bundle.manifest_ref,
                                   bundle.document_ref, 1, 1, 0, ())
    with pytest.raises(ValueError, match="must not expose"):
        replace(available, state=c.ExportReportState.STALE)
