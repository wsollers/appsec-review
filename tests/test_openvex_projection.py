from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
from typing import Any
import urllib.request

from jsonschema.exceptions import ValidationError
import pytest
from referencing.exceptions import NoSuchResource, Unresolvable

from appsec_review.jobs.job_openvex_export import contracts as c
from appsec_review.jobs.job_openvex_export import validation as v
from appsec_review.jobs.job_openvex_export.projection import assemble_export
from tests.openvex_support import (
    OUTPUT_PREFIX, RELEASE, ROOT, SCHEMAS, enabled_settings, make_verified_inputs, schema_validator,
)


def assemble(inputs: c.VerifiedInputs | None = None, settings: Any = None, **kwargs: Any) -> c.ExportBundle:
    settings = settings or enabled_settings()
    return assemble_export(inputs or make_verified_inputs(settings=settings), settings, RELEASE,
                           output_prefix=OUTPUT_PREFIX, **kwargs)


def rewrite(
    bundle: c.ExportBundle, change: Callable[[Any, dict, dict], None], *, reidentify: bool = False,
) -> c.ExportBundle:
    """Rehash all output bindings: semantic negatives must not depend on stale byte hashes."""
    document, manifest, result = (c.json_body(getattr(bundle, name)) for name in ("document", "manifest", "result"))
    change(document, manifest, result)
    if reidentify and document is not None:
        for statement in document["statements"]:
            statement.pop("@id", None)
            statement["@id"] = c.statement_id(document["author"], statement)
        document.pop("@id", None)
        document["@id"] = c.document_id(document)
    document_bytes = None if document is None else c.canonical_bytes(document)
    prefix = bundle.result_ref.path.rsplit("/", 1)[0]
    document_ref = None if document_bytes is None else c.output_reference(prefix, c.DOCUMENT_NAME, document_bytes)
    manifest["document"] = result["document"] = None if document_ref is None else document_ref.to_json()
    manifest_bytes = c.canonical_bytes(manifest)
    manifest_ref = c.output_reference(prefix, c.MANIFEST_NAME, manifest_bytes)
    result["manifest"] = manifest_ref.to_json()
    result_bytes = c.canonical_bytes(result)
    return c.ExportBundle(document, manifest, result, document_bytes, manifest_bytes, result_bytes,
                          document_ref, manifest_ref, c.output_reference(prefix, c.RESULT_NAME, result_bytes))


def with_gate(inputs: c.VerifiedInputs, gate: dict) -> c.VerifiedInputs:
    ref = c.ArtifactRef(inputs.provenance.gate.path, c.json_sha256(gate))
    inventory = tuple(c.SizedArtifactRef(ref.path, ref.sha256, len(c.canonical_bytes(gate)))
                      if item.path == ref.path else item for item in inputs.input_inventory)
    findings = tuple(c.VerifiedFinding(row, finding.score_refs, finding.evidence_refs)
                     for row in gate["packages"]
                     for finding in inputs.findings if finding.finding_package_id == row["finding_package_id"])
    return replace(inputs, gate=gate, findings=findings, input_inventory=inventory,
                   provenance=replace(inputs.provenance, gate=ref))


@pytest.mark.parametrize("buckets", [
    (), ("publishable",), ("verification_backlog",), ("withheld",),
    ("publishable", "verification_backlog", "withheld", "publishable", "withheld"),
])
def test_exact_selection_sets_counts_and_empty_nonclean_outcomes(buckets: tuple[str, ...]) -> None:
    inputs, settings = make_verified_inputs(buckets), enabled_settings()
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, settings)
    manifest, result = bundle.manifest, bundle.result
    expected = {finding.finding_package_id for finding in inputs.findings if finding.bucket == "publishable"}
    rows = manifest["packages"]
    included = {row["finding"]["finding_package_id"] for row in rows if row["disposition"] == "included"}
    assert included == expected
    assert len(rows) == len({row["finding"]["finding_package_id"] for row in rows}) == len(buckets)
    assert [row["finding"]["finding_package_id"] for row in rows] == sorted(
        finding.finding_package_id for finding in inputs.findings)
    counts = manifest["accounting"]
    assert counts["gate_total"] == len(buckets) == counts["included_findings"] + counts["excluded_findings"]
    assert counts["gate_total"] == counts["gate_publishable"] + counts["gate_verification_backlog"] + counts["gate_withheld"]
    assert counts["included_findings"] == counts["gate_publishable"] == counts["statement_count"] == len(expected)
    assert counts["excluded_findings"] == sum(counts["exclusion_counts"].values()) == len(buckets) - len(expected)
    assert counts["exclusion_counts"] == {
        "gate_verification_backlog": buckets.count("verification_backlog"), "gate_withheld": buckets.count("withheld"),
    }
    for row in rows:
        bucket = row["finding"]["bucket"]
        assert row["reason"] == ("included" if bucket == "publishable" else f"gate_{bucket}")
        assert (row["statement_id"] is not None) == (bucket == "publishable")
    mappings = manifest["statement_mappings"]
    assert {row["finding_package_id"] for row in mappings} == expected
    assert [row["statement_index"] for row in mappings] == list(range(len(expected)))
    assert len({row["statement_id"] for row in mappings}) == len(expected)
    if not expected:
        assert bundle.document is bundle.document_bytes is bundle.document_ref is None
        assert result["document"] is manifest["document"] is None
        assert result["outcome"] == "no_statements" and c.NO_STATEMENTS_GAP in result["gaps"]
        assert not mappings
    else:
        assert result["outcome"] == ("exported_with_gaps" if "withheld" in buckets else "exported")
        statements = bundle.document["statements"]
        assert {statement["@id"] for statement in statements} == {row["statement_id"] for row in mappings}
        assert {statement["status"] for statement in statements} == {"affected"}
        assert all(len(statement["products"]) == 1 for statement in statements)
        assert all(statement["action_statement"] == settings.action_statement for statement in statements)


def test_review_dimensions_and_resolving_evidence_remain_verbatim() -> None:
    inputs = make_verified_inputs(("publishable", "verification_backlog", "withheld"), review_gap=True)
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, enabled_settings())
    assert bundle.result["outcome"] == "exported_with_gaps"
    assert bundle.result["gaps"] == tuple(sorted(
        item["limitation_id"] for item in inputs.gate["limitations"] if item["kind"] == "gap"))
    assert {item["kind"] for item in bundle.manifest["review_context"]["limitations"]} == {"gap", "not_run", "notice"}
    for key, value in bundle.manifest["review_context"].items():
        assert c.canonical_bytes(value) == c.canonical_bytes(inputs.gate[key])
    for row, finding in zip(bundle.manifest["packages"], inputs.findings, strict=True):
        assert row["finding"] == finding.projection
        assert c.json_body(row["score_refs"]) == [ref.to_json() for ref in finding.score_refs]
        assert c.json_body(row["evidence_refs"]) == [ref.to_json() for ref in finding.evidence_refs]
        assert row["finding"]["scores"][0]["environmental_business_impact"] is None
        assert row["finding"]["scores"][0]["exploitability_confidence"] is None
    for mapping in bundle.manifest["statement_mappings"]:
        finding = next(f for f in inputs.findings if f.finding_package_id == mapping["finding_package_id"])
        assert c.json_body(mapping["finding_package"]) == finding.reference.to_json()
        assert mapping["claim_id"] == finding.claim_id
        assert mapping["claim_ledger"] == inputs.gate["inputs"]["claim_ledger"]
        assert mapping["projection"] == inputs.gate["inputs"]["projection"]
        assert mapping["settings_sha256"] == inputs.settings_sha256
    assert c.json_body(bundle.manifest["bindings"]) == [ref.reference.to_json() for ref in inputs.input_inventory]


def test_unrated_pending_independence_or_incomplete_review_never_filters_publishable() -> None:
    inputs = make_verified_inputs(review_gap=True)
    gate = c.json_body(inputs.gate)
    finding = gate["packages"][0]
    finding["scores"] = []
    finding["ship_block"].update(status="ship_blocking_pending_distinct_verification",
                                 reasons=["technical_severity_unrated"], technical_severity="unrated",
                                 technical_severity_score_id=None, technical_severity_floor=None,
                                 technical_severity_ceiling=None, verifier_model_distinct=False)
    finding["independence"].update(independent=False, verifier_model_distinct=False)
    finding["missing_predicates"] = ["source_to_sink_reachability"]
    gate["verification"].update(distinct=False, warning="Synthetic distinct-verification warning")
    inputs = with_gate(inputs, gate)
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, enabled_settings())
    assert bundle.result["statement_count"] == 1
    assert bundle.manifest["packages"][0]["finding"] == inputs.findings[0].projection
    assert bundle.manifest["review_context"]["verification"]["distinct"] is False


def test_deterministic_order_independent_replay_and_output_prefix() -> None:
    inputs = make_verified_inputs(("publishable", "publishable", "verification_backlog"))
    first = assemble(inputs)
    permuted = replace(inputs, findings=tuple(reversed(inputs.findings)),
                       input_inventory=tuple(reversed(inputs.input_inventory)))
    assert assemble(permuted) == first
    gate = c.json_body(inputs.gate)
    gate["packages"].reverse()
    gate["bindings"].reverse()
    for bucket in gate["buckets"].values():
        bucket.reverse()
    changed = assemble(with_gate(inputs, gate))
    assert changed.document_bytes == first.document_bytes
    assert changed.manifest_bytes != first.manifest_bytes
    relocated = assemble_export(inputs, enabled_settings(), RELEASE, output_prefix="data/exports/other")
    assert relocated.document_bytes == first.document_bytes
    assert relocated.manifest_bytes != first.manifest_bytes and relocated.result_bytes != first.result_bytes
    assert first.document_bytes.endswith(b"\n") and not first.document_bytes.endswith(b"\n\n")


@pytest.mark.parametrize("timestamp", [
    "2026-10-28T14:00:00Z", "2026-10-28T10:00:00-04:00", "2026-10-28T15:00:00.000000+01:00",
])
def test_only_accepted_timestamp_is_used_normalized_to_utc(timestamp: str) -> None:
    inputs = make_verified_inputs(gate_completed_at=timestamp)
    bundle = assemble(inputs)
    assert bundle.document["timestamp"] == bundle.document["statements"][0]["timestamp"] == "2026-10-28T14:00:00.000000Z"
    assert bundle.manifest["provenance"]["gate_completed_at"] == "2026-10-28T14:00:00.000000Z"
    assert bundle.manifest["provenance"]["timestamp_source"] == c.TIMESTAMP_SOURCE
    assert "action_statement_timestamp" not in bundle.document["statements"][0]
    assert bundle.document_bytes == assemble(make_verified_inputs()).document_bytes


def test_source_full_configuration_and_claim_identities_are_not_release_or_cwe_ids() -> None:
    inputs = make_verified_inputs()
    first = assemble(inputs)
    product = first.document["statements"][0]["products"][0]
    assert set(product) == {"@id"}
    assert product["@id"] == c.source_product_id(inputs.source.repository_iri, inputs.source.target_snapshot,
                                                inputs.provenance.resolved_config_sha256)
    vulnerability = first.document["statements"][0]["vulnerability"]
    assert vulnerability["@id"] == vulnerability["name"] == c.vulnerability_id(
        inputs.source.repository_iri, inputs.source.target_snapshot, inputs.findings[0].claim_id)
    assert set(vulnerability) == {"@id", "name"} and "CVE-" not in vulnerability["name"] and "CWE-" not in vulnerability["name"]
    snapshot = replace(inputs, source=replace(inputs.source, target_snapshot=c.json_sha256("other-snapshot")))
    snapshot_bundle = assemble(snapshot)
    assert snapshot_bundle.document_bytes != first.document_bytes
    assert snapshot_bundle.document["statements"][0]["vulnerability"] != vulnerability
    new_config = c.ArtifactRef(inputs.provenance.resolved_configuration.path, c.json_sha256("other-full-config"))
    gate = c.json_body(inputs.gate)
    for ref in gate["bindings"]:
        if ref["path"] == new_config.path:
            ref["sha256"] = new_config.sha256
    gate_ref = c.ArtifactRef(inputs.provenance.gate.path, c.json_sha256(gate))
    changed_refs = {new_config.path: new_config, gate_ref.path: gate_ref}
    inventory = tuple(c.SizedArtifactRef(item.path, changed_refs[item.path].sha256,
                                       len(c.canonical_bytes(gate)) if item.path == gate_ref.path else item.size_bytes)
                      if item.path in changed_refs else item for item in inputs.input_inventory)
    config = replace(inputs, gate=gate, provenance=replace(inputs.provenance, gate=gate_ref,
                                                          resolved_configuration=new_config), input_inventory=inventory)
    config_bundle = assemble(config)
    assert config_bundle.document["statements"][0]["products"][0] != product
    assert config_bundle.document["statements"][0]["vulnerability"] == vulnerability
    assert config.provenance.review_settings_sha256 == inputs.provenance.review_settings_sha256


@pytest.mark.parametrize("override", [
    {"author": "Another Security Team"}, {"action_statement": "Disable the synthetic service."},
    {"repository_iri": "urn:example:different-system"}, {"role": "Security reviewer"},
])
def test_changed_exact_issuer_action_or_repository_changes_document_identity(override: dict) -> None:
    settings = enabled_settings(**override)
    changed = assemble(make_verified_inputs(settings=settings), settings)
    first = assemble()
    assert changed.document["@id"] != first.document["@id"] and changed.document_bytes != first.document_bytes
    assert changed.document["version"] == 1
    v.validate_export(changed, make_verified_inputs(settings=settings), settings)


def test_changed_release_or_timestamp_changes_identity_and_no_runtime_fields_exist() -> None:
    inputs, settings = make_verified_inputs(), enabled_settings()
    first = assemble(inputs)
    changed = assemble_export(inputs, settings, "another-release/1", output_prefix=OUTPUT_PREFIX)
    timestamp = assemble(replace(inputs, gate_completed_at="2026-10-28T14:00:01Z"))
    assert len({item.document["@id"] for item in (first, changed, timestamp)}) == 3
    for payload in (first.document_bytes, first.manifest_bytes, first.result_bytes):
        assert all(key not in json.loads(payload) for key in ("duration_seconds", "resources", "pid", "created_at"))
    assert "role" not in first.document and "last_updated" not in first.document


def test_accepted_acquisition_and_observed_build_qualifications_are_preserved() -> None:
    inputs = make_verified_inputs()
    acquisition = c.ArtifactRef("data/fixtures/acquisition.json", c.json_sha256("acquisition"))
    inputs = replace(inputs, source=replace(inputs.source, acquisition=acquisition,
                                           repository_identity_basis=c.RepositoryIdentityBasis.ACCEPTED_ACQUISITION,
                                           qualifications=("Observed debug configuration", "Build unavailable")),
                     input_inventory=(*inputs.input_inventory,
                                      c.SizedArtifactRef(acquisition.path, acquisition.sha256, 20)))
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, enabled_settings())
    product = bundle.manifest["products"][0]
    assert product["repository_identity_basis"] == "accepted_acquisition"
    assert c.json_body(product["acquisition"]) == acquisition.to_json()
    assert product["qualifications"] == inputs.source.qualifications
    assert product["scope_statement"] == c.STATUS_NOTES
    conflicting = replace(inputs, source=replace(inputs.source, repository_iri="urn:example:conflict"))
    with pytest.raises(c.ExportError) as error:
        assemble(conflicting)
    assert error.value.reason == c.ExportFailureReason.IDENTITY_CONFLICT


@pytest.mark.parametrize("prefix", ["", ".", "../other", "/absolute", "data\\export", "data//export", "C:/export"])
def test_output_prefix_is_mandatory_safe_and_exact(prefix: str) -> None:
    with pytest.raises(c.ExportError) as error:
        assemble_export(make_verified_inputs(), enabled_settings(), RELEASE, output_prefix=prefix)
    assert error.value.reason == c.ExportFailureReason.CONFIGURATION_INVALID
    with pytest.raises(TypeError):
        assemble_export(make_verified_inputs(), enabled_settings(), RELEASE)


def test_output_cannot_overwrite_an_input() -> None:
    inputs = make_verified_inputs()
    extra = c.SizedArtifactRef(f"{OUTPUT_PREFIX}/{c.DOCUMENT_NAME}", c.json_sha256("old"), 6)
    inputs = replace(inputs, input_inventory=(*inputs.input_inventory, extra))
    with pytest.raises(c.ExportError, match="overwrite"):
        assemble(inputs)


@pytest.mark.parametrize("buckets", [(), ("publishable",)])
def test_disabled_and_stale_settings_are_never_empty_success(buckets: tuple[str, ...]) -> None:
    inputs = make_verified_inputs(buckets)
    with pytest.raises(c.ExportError) as error:
        assemble(inputs, replace(enabled_settings(), enabled=False))
    assert error.value.reason == c.ExportFailureReason.CONFIGURATION_INVALID
    with pytest.raises(c.ExportError) as error:
        assemble(inputs, enabled_settings(action_statement="Different operator-reviewed action."))
    assert error.value.reason == c.ExportFailureReason.INPUT_STALE


@pytest.mark.parametrize("change", ["counts", "bucket_set", "duplicate_bucket", "provenance"])
def test_inconsistent_gate_accounting_membership_or_provenance_fails_closed(change: str) -> None:
    inputs = make_verified_inputs(("publishable", "publishable"))
    gate = c.json_body(inputs.gate)
    if change == "counts":
        gate["package_counts"]["publishable"] -= 1
    elif change == "bucket_set":
        gate["buckets"]["publishable"][0] = gate["buckets"]["publishable"][1]
    elif change == "duplicate_bucket":
        gate["buckets"]["publishable"].append(gate["buckets"]["publishable"][0])
    else:
        gate["review"]["lead_package_manifest_sha256"] = c.json_sha256("wrong-lead")
    with pytest.raises(c.ExportError):
        assemble(with_gate(inputs, gate))


@pytest.mark.parametrize("field", ["max_document_bytes", "max_manifest_bytes"])
def test_exact_output_byte_limits_and_one_below(field: str) -> None:
    inputs = make_verified_inputs()
    first = assemble(inputs)
    size = len(first.document_bytes if field == "max_document_bytes" else first.manifest_bytes)
    settings = replace(enabled_settings(), **{field: size})
    bounded = replace(inputs, settings_sha256=settings.settings_sha256())
    bundle = assemble(bounded, settings)
    v.validate_export(bundle, bounded, settings)
    assert len(bundle.document_bytes if field == "max_document_bytes" else bundle.manifest_bytes) == size
    smaller = replace(settings, **{field: size - 1})
    with pytest.raises(c.ExportError) as error:
        assemble(replace(inputs, settings_sha256=smaller.settings_sha256()), smaller)
    assert error.value.reason == c.ExportFailureReason.BOUND_EXCEEDED


@pytest.mark.parametrize("field", ["max_packages", "max_bindings", "max_artifact_bytes", "max_total_input_bytes"])
def test_lower_input_bounds_are_checked_without_skipping_rows(field: str) -> None:
    inputs = make_verified_inputs(("publishable", "publishable"))
    maximum = max(ref.size_bytes for ref in inputs.input_inventory)
    limits = {"max_packages": len(inputs.findings), "max_bindings": len(inputs.input_inventory),
              "max_artifact_bytes": maximum, "max_total_input_bytes": inputs.total_input_bytes}
    settings = replace(enabled_settings(), **limits)
    bounded = replace(inputs, settings_sha256=settings.settings_sha256())
    v.validate_export(assemble(bounded, settings), bounded, settings)
    smaller = replace(settings, **{field: limits[field] - 1})
    with pytest.raises(c.ExportError) as error:
        assemble(replace(inputs, settings_sha256=smaller.settings_sha256()), smaller)
    assert error.value.reason == c.ExportFailureReason.BOUND_EXCEEDED


def test_utf8_advice_preserved_exactly_with_byte_not_character_sizes() -> None:
    settings = enabled_settings(action_statement="Disable the caf\u00e9 endpoint.\nRestrict access.")
    inputs = make_verified_inputs(settings=settings)
    bundle = assemble(inputs, settings)
    v.validate_export(bundle, inputs, settings)
    assert b"caf\xc3\xa9" in bundle.document_bytes and b"\\u00e9" not in bundle.document_bytes
    assert bundle.document["statements"][0]["action_statement"] == settings.action_statement
    assert bundle.document_ref.size_bytes == len(bundle.document_bytes)


@pytest.mark.parametrize("field,value", [
    ("@context", "https://example.test/not-openvex"), ("author", ""), ("author", "bot"),
    ("timestamp", "2026-10-28T14:00:01.000000Z"), ("version", 2),
])
def test_schema_valid_document_semantic_tamper_rejected_even_after_all_rehashes(field: str, value: Any) -> None:
    inputs, settings = make_verified_inputs(), enabled_settings()
    changed = rewrite(assemble(inputs), lambda document, manifest, result: document.update({field: value}))
    schema_validator("upstream/openvex-v0.2.0.schema.json").validate(c.json_body(changed.document))
    with pytest.raises(c.ExportError):
        v.validate_export(changed, inputs, settings)


@pytest.mark.parametrize("field,value", [
    ("action_statement", ""), ("action_statement", " \t\n"), ("action_statement", "Different nonblank advice."),
    ("products", []), ("products", [{"@id": "urn:example:wrong-source"}]),
    ("vulnerability", {"name": "CWE-79"}), ("vulnerability", {"name": "CVE-2026-0001"}),
    ("status_notes", "Wrong qualification."), ("timestamp", "2026-10-28T14:00:01.000000Z"),
    ("version", 2), ("status", "fixed"),
])
def test_schema_valid_statement_semantic_tamper_rejected_after_identity_and_reference_rehash(
    field: str, value: Any,
) -> None:
    inputs, settings = make_verified_inputs(), enabled_settings()
    changed = rewrite(assemble(inputs),
                      lambda document, manifest, result: document["statements"][0].update({field: value}),
                      reidentify=True)
    schema_validator("upstream/openvex-v0.2.0.schema.json").validate(c.json_body(changed.document))
    with pytest.raises(c.ExportError):
        v.validate_export(changed, inputs, settings)


@pytest.mark.parametrize("status", ["not_affected", "fixed", "under_investigation"])
def test_other_openvex_statuses_are_never_inferred(status: str) -> None:
    inputs = make_verified_inputs()

    def change(document: dict, manifest: dict, result: dict) -> None:
        document["statements"][0]["status"] = status
        if status == "not_affected":
            document["statements"][0]["justification"] = "component_not_present"

    changed = rewrite(assemble(inputs), change, reidentify=True)
    schema_validator("upstream/openvex-v0.2.0.schema.json").validate(c.json_body(changed.document))
    with pytest.raises(c.ExportError):
        v.validate_export(changed, inputs, enabled_settings())


@pytest.mark.parametrize("change", [
    lambda d, m, r: m["accounting"]["exclusion_counts"].update(gate_withheld=1),
    lambda d, m, r: m["packages"][0].update(reason="gate_withheld", disposition="excluded", statement_id=None),
    lambda d, m, r: m["packages"][0]["finding"]["independence"].update(independent=False),
    lambda d, m, r: m["packages"][0]["finding"]["scores"][0]["technical_severity"].update(value=1),
    lambda d, m, r: m["statement_mappings"][0].update(claim_id="claim-" + "0" * 64),
    lambda d, m, r: m["statement_mappings"][0].update(evidence_refs=[]),
    lambda d, m, r: m["statement_mappings"][0].update(settings_sha256="0" * 64),
    lambda d, m, r: m["products"][0].update(scope_statement="All releases."),
    lambda d, m, r: m["review_context"]["coverage"]["summary"].update(reviewed=0),
    lambda d, m, r: m["bindings"].pop(),
    lambda d, m, r: r.update(gaps=["invented_gap"]),
    lambda d, m, r: r["gate"].update(sha256="0" * 64),
])
def test_closed_schema_valid_companion_and_result_tamper_is_not_accepted(change: Callable) -> None:
    inputs = make_verified_inputs()
    changed = rewrite(assemble(inputs), change)
    schema_validator("manifest.schema.json").validate(c.json_body(changed.manifest))
    schema_validator("result.schema.json").validate(c.json_body(changed.result))
    with pytest.raises(c.ExportError, match="exactly project"):
        v.validate_export(changed, inputs, enabled_settings())


def test_count_preserving_duplicate_mapping_and_statement_fail() -> None:
    inputs = make_verified_inputs(("publishable", "publishable"))
    for change in (
        lambda d, m, r: m["statement_mappings"][1].update(
            finding_package_id=m["statement_mappings"][0]["finding_package_id"]),
        lambda d, m, r: d["statements"].__setitem__(1, dict(d["statements"][0])),
    ):
        changed = rewrite(assemble(inputs), change)
        with pytest.raises(c.ExportError):
            v.validate_export(changed, inputs, enabled_settings())


def test_empty_result_named_gap_cannot_be_removed_or_reinterpreted_as_clean() -> None:
    inputs = make_verified_inputs(())
    bundle = assemble(inputs)
    changed = rewrite(bundle, lambda d, m, r: r.update(gaps=["some_other_gap"]))
    with pytest.raises(c.ExportError):
        v.validate_export(changed, inputs, enabled_settings())
    with pytest.raises(ValueError):
        rewrite(bundle, lambda d, m, r: r.update(outcome="exported"))


def test_output_bindings_recomputed_and_exact_filenames_enforced() -> None:
    inputs = make_verified_inputs()
    bundle = assemble(inputs)
    for name in ("document", "manifest", "result"):
        ref = getattr(bundle, f"{name}_ref")
        payload = getattr(bundle, f"{name}_bytes")
        assert ref.sha256 == hashlib.sha256(payload).hexdigest() and ref.size_bytes == len(payload)
        wrong_name = replace(ref, path=f"{OUTPUT_PREFIX}/wrong-name.json")
        with pytest.raises(c.ExportError):
            v.validate_export(replace(bundle, **{f"{name}_ref": wrong_name}), inputs, enabled_settings())
    assert bundle.manifest["document"] == bundle.result["document"]
    assert c.json_body(bundle.result["manifest"]) == bundle.manifest_ref.to_json()
    assert "result" not in bundle.result and "manifest" not in bundle.manifest


def test_validator_enforces_lower_output_bounds_independently() -> None:
    inputs, bundle = make_verified_inputs(), assemble()
    settings = enabled_settings(max_document_bytes=len(bundle.document_bytes) - 1)
    with pytest.raises(c.ExportError) as error:
        v.validate_export(bundle, inputs, settings)
    assert error.value.reason == c.ExportFailureReason.BOUND_EXCEEDED


@pytest.mark.parametrize("field,value", [
    ("timestamp", "not-a-date"), ("timestamp", "2026-02-30T00:00:00Z"),
    ("timestamp", "2026-10-28T14:00:00+01:60"), ("@id", "not an iri"),
    ("@id", "https://user:password@example.test/repository"), ("@id", "urn:example:bad%00id"),
    ("@context", "https://example.test/%not-an-escape"),
])
def test_offline_formats_are_checked_without_optional_format_dependencies(field: str, value: str) -> None:
    document = c.json_body(assemble().document)
    document[field] = value
    schema_validator("upstream/openvex-v0.2.0.schema.json").validate(document)
    with pytest.raises(ValidationError):
        v.schema_validator("upstream/openvex-v0.2.0.schema.json").validate(document)


def installed_resources(tmp_path: Path) -> Path:
    root = tmp_path / "share" / "appsec-review" / "schemas" / "openvex-export"
    for relative in (*c.SCHEMA_SHA256, "upstream/upstream.lock.json", "upstream/LICENSE"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCHEMAS / relative, destination)
    return root


def test_public_offline_resources_source_precedence_and_installed_fallback(tmp_path: Path, monkeypatch: Any) -> None:
    installed = installed_resources(tmp_path)
    monkeypatch.setattr(v.sys, "prefix", str(tmp_path))
    assert v.schema_resource_root(ROOT) == SCHEMAS
    missing_repository = tmp_path / "no-source-checkout"
    assert v.schema_resource_root(missing_repository) == installed
    bundle = assemble()
    for name, body in (("manifest.schema.json", bundle.manifest), ("result.schema.json", bundle.result),
                       ("upstream/openvex-v0.2.0.schema.json", bundle.document)):
        v.schema_validator(name, repository_root=missing_repository).validate(c.json_body(body))
    assert v.schema_registry(repository_root=missing_repository).get_or_retrieve(c.UPSTREAM_SCHEMA_ID)
    assert set(v.schema_registry(repository_root=missing_repository)) == {
        json.loads((SCHEMAS / relative).read_bytes())["$id"] for relative in c.SCHEMA_SHA256
    }


def test_resource_reader_opens_only_the_seven_schema_pins_lock_and_license(monkeypatch: Any) -> None:
    opened = []
    original = Path.open

    def tracked(path: Path, *args: Any, **kwargs: Any) -> Any:
        opened.append(path.resolve())
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked)
    v.schema_registry(repository_root=ROOT)
    assert len(opened) == 9
    assert set(opened) == {(SCHEMAS / relative).resolve() for relative in (
        *c.SCHEMA_SHA256, "upstream/upstream.lock.json", "upstream/LICENSE",
    )}


@pytest.mark.parametrize("relative", [
    *c.SCHEMA_SHA256, "upstream/upstream.lock.json", "upstream/LICENSE",
])
def test_every_resource_pin_is_checked_without_newline_normalization(relative: str, tmp_path: Path,
                                                                    monkeypatch: Any) -> None:
    installed = installed_resources(tmp_path)
    monkeypatch.setattr(v.sys, "prefix", str(tmp_path))
    path = installed / relative
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    with pytest.raises(c.ExportError) as error:
        v.schema_registry(repository_root=tmp_path / "missing")
    assert error.value.reason == c.ExportFailureReason.INPUT_TAMPERED


def test_partial_source_does_not_fall_back_to_healthy_installed_resources(tmp_path: Path, monkeypatch: Any) -> None:
    installed_resources(tmp_path)
    monkeypatch.setattr(v.sys, "prefix", str(tmp_path))
    source = tmp_path / "source" / "docs" / "schemas" / "openvex-export"
    source.mkdir(parents=True)
    with pytest.raises(c.ExportError) as error:
        v.schema_registry(repository_root=tmp_path / "source")
    assert error.value.reason == c.ExportFailureReason.INPUT_MISSING
    monkeypatch.setattr(v.sys, "prefix", str(tmp_path / "absent"))
    with pytest.raises(c.ExportError) as error:
        v.schema_resource_root(tmp_path / "absent")
    assert error.value.reason == c.ExportFailureReason.INPUT_MISSING


def test_resource_io_and_type_errors_do_not_fall_back(tmp_path: Path, monkeypatch: Any) -> None:
    installed_resources(tmp_path)
    monkeypatch.setattr(v.sys, "prefix", str(tmp_path))
    source = tmp_path / "source" / "docs" / "schemas" / "openvex-export"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"not-a-directory")
    with pytest.raises(c.ExportError) as error:
        v.schema_resource_root(tmp_path / "source")
    assert error.value.reason == c.ExportFailureReason.INPUT_TAMPERED

    def denied(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("synthetic custody failure")

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(c.ExportError) as error:
        v.schema_registry(repository_root=tmp_path / "missing")
    assert error.value.reason == c.ExportFailureReason.IO_ERROR
    assert isinstance(error.value.__cause__, PermissionError)


def test_no_network_context_or_unknown_schema_retrieval(monkeypatch: Any) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("projection/validation attempted network, subprocess or source traversal")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    inputs, settings = make_verified_inputs(), enabled_settings()
    v.validate_export(assemble(inputs), inputs, settings)
    registry = v.schema_registry()
    with pytest.raises(NoSuchResource):
        registry.get_or_retrieve("https://example.invalid/never-fetch")
    validator = v.schema_validator("result.schema.json").evolve(
        schema={"$ref": "https://example.invalid/unknown.json"})
    with pytest.raises(Unresolvable):
        validator.validate({})
    with pytest.raises(c.ExportError):
        v.schema_validator("../unknown.schema.json")


@pytest.mark.parametrize("review_gap", [False, True])
def test_gate2_completion_certificate_is_retained_without_changing_eligibility(review_gap: bool) -> None:
    inputs = make_verified_inputs(("publishable", "publishable", "verification_backlog", "withheld"),
                                  completion_attachments=True, review_gap=review_gap)
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, enabled_settings())
    context = bundle.manifest["review_context"]
    assert "unavailable_inputs" not in context
    assert set(context) == {"review", "accounting", "ship_block", "verification", "coverage",
                            "limitations", "gap_ids", "capabilities", "attachments", "status"}
    for key, value in context.items():
        assert c.canonical_bytes(value) == c.canonical_bytes(inputs.gate[key])
    assert bundle.result["statement_count"] == bundle.result["included_findings"] == 2
    assert bundle.result["excluded_findings"] == 2
    assert bundle.manifest["accounting"]["exclusion_counts"] == {
        "gate_verification_backlog": 1, "gate_withheld": 1,
    }
    assert bundle.result["outcome"] == "exported_with_gaps"
    assert set(context["capabilities"]) == {
        "poc_generation", "attack_chains", "remediation_planning", "remediation_validation", "dossiers",
    }
    assert all(record["enabled"] for record in context["capabilities"].values())
    attachments = context["attachments"]
    assert attachments["attack_chains"][0]["status"] == "qualified_supported"
    assert attachments["poc_generation"][0]["status"] == "compile_failed"
    assert {row["status"] for row in attachments["remediation_planning"]} == {"manual_design_required"}
    assert {row["status"] for row in attachments["remediation_validation"]} == {"manual_validation_required"}
    assert {row["kind"] for row in attachments["dossiers"]} == {"confirmed_finding", "poc"}
    for section in ("poc_generation", "remediation_planning", "remediation_validation"):
        for row in attachments[section]:
            assert row["execution"] == "not_performed_by_policy"
            assert row["runtime_verified"] is False and row["result_id"] is None
    notice = next(row for row in context["limitations"] if row["limitation_id"] == "compile_only_nonexecution")
    assert notice["kind"] == "notice" and notice["limitation_id"] not in bundle.result["gaps"]
    assert {row["finding"]["finding_package_id"] for row in bundle.manifest["packages"]
            if row["disposition"] == "included"} == {
                row.finding_package_id for row in inputs.findings if row.bucket == "publishable"}
    for statement in bundle.document["statements"]:
        assert statement["status"] == "affected"
        assert set(statement["products"][0]) == {"@id"}
        assert "compile" not in statement["action_statement"]
    assert bundle.manifest["provenance"]["validation_profile_sha256"] == c.VALIDATION_PROFILE_SHA256


def test_gate2_completion_notices_are_not_invented_review_gaps() -> None:
    inputs = make_verified_inputs()
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, enabled_settings())
    assert {row["kind"] for row in inputs.gate["limitations"]} == {"notice", "not_run"}
    assert bundle.result["outcome"] == "exported" and bundle.result["gaps"] == ()
    assert bundle.manifest["review_context"]["limitations"] == inputs.gate["limitations"]
    assert inputs.gate["capabilities"]["attack_chains"]["disposition"] == "SKIPPED_NA"
    assert not any(inputs.gate["attachments"].values())


@pytest.mark.parametrize("buckets", [(), ("verification_backlog",), ("withheld",)])
def test_gate2_empty_eligibility_keeps_completion_context_and_nonclean_gap(buckets: tuple[str, ...]) -> None:
    inputs = make_verified_inputs(buckets)
    bundle = assemble(inputs)
    v.validate_export(bundle, inputs, enabled_settings())
    assert bundle.document is bundle.document_bytes is bundle.document_ref is None
    assert bundle.result["outcome"] == "no_statements"
    assert c.NO_STATEMENTS_GAP in bundle.result["gaps"]
    assert "compile_only_nonexecution" not in bundle.result["gaps"]
    assert bundle.manifest["review_context"]["capabilities"] == inputs.gate["capabilities"]
    assert bundle.manifest["review_context"]["attachments"] == inputs.gate["attachments"]


@pytest.mark.parametrize("change", [
    lambda context: context["capabilities"]["attack_chains"].update(gap_count=0),
    lambda context: context["capabilities"]["dossiers"].update(item_count=0),
    lambda context: context["capabilities"]["poc_generation"].update(disposition="SUCCEEDED"),
    lambda context: context["capabilities"]["dossiers"].update(reason="Rewritten certificate."),
    lambda context: context["capabilities"]["remediation_planning"].update(summary=None),
    lambda context: context["capabilities"]["remediation_validation"]["handoff"].update(sha256="0" * 64),
    lambda context: context["attachments"]["poc_generation"][0].update(status="compile_verified"),
    lambda context: context["attachments"]["poc_generation"][0]["files"]["compile"].update(sha256="0" * 64),
    lambda context: context["attachments"]["attack_chains"][0].update(status="confirmed"),
    lambda context: context["attachments"]["attack_chains"][0]["component_claim_ids"].__setitem__(
        0, "claim-" + "0" * 64),
    lambda context: context["attachments"]["remediation_planning"][0].update(status="proposal_generated"),
    lambda context: context["attachments"]["remediation_validation"][0].update(status="build_checked"),
    lambda context: context["attachments"]["dossiers"][0]["files"]["receipt"].update(sha256="0" * 64),
    lambda context: context["attachments"]["dossiers"].pop(),
    lambda context: context["limitations"][-1].update(kind="gap"),
])
def test_gate2_schema_valid_certificate_tamper_fails_after_all_output_rehashes(change: Callable) -> None:
    inputs = make_verified_inputs(("publishable", "publishable"), completion_attachments=True)
    changed = rewrite(assemble(inputs), lambda d, m, r: change(m["review_context"]), reidentify=True)
    schema_validator("manifest.schema.json").validate(c.json_body(changed.manifest))
    schema_validator("result.schema.json").validate(c.json_body(changed.result))
    with pytest.raises(c.ExportError, match="exactly project") as error:
        v.validate_export(changed, inputs, enabled_settings())
    assert error.value.reason == c.ExportFailureReason.SEMANTIC_INVALID
    assert error.value.phase == c.ExportPhase.VALIDATE


@pytest.mark.parametrize("section", ["poc_generation", "remediation_planning", "remediation_validation"])
def test_gate2_completion_cannot_be_promoted_to_runtime_execution(section: str) -> None:
    inputs = make_verified_inputs(("publishable", "publishable"), completion_attachments=True)
    changed = rewrite(assemble(inputs), lambda d, m, r:
                      m["review_context"]["attachments"][section][0].update(runtime_verified=True))
    with pytest.raises(c.ExportError) as error:
        v.validate_export(changed, inputs, enabled_settings())
    assert error.value.reason == c.ExportFailureReason.SCHEMA_INVALID


def test_gate2_completion_changes_only_the_companion_not_openvex_assertions() -> None:
    inputs = make_verified_inputs(("publishable", "publishable"), completion_attachments=True)
    bundle = assemble(inputs)
    plain = assemble(make_verified_inputs(("publishable", "publishable")))
    assert bundle.document_bytes == plain.document_bytes
    assert bundle.manifest_bytes != plain.manifest_bytes and bundle.result_bytes != plain.result_bytes
    gate = c.json_body(inputs.gate)
    for rows in gate["attachments"].values():
        rows.reverse()
    gate["bindings"].reverse()
    permuted = with_gate(inputs, gate)
    replay = assemble(permuted)
    v.validate_export(replay, permuted, enabled_settings())
    assert replay.document_bytes == bundle.document_bytes
    assert replay.manifest_bytes != bundle.manifest_bytes
    assert replay.manifest["review_context"]["attachments"] == permuted.gate["attachments"]


def test_gate2_nested_completion_bindings_cover_gate_certificate_and_measured_inventory() -> None:
    inputs = make_verified_inputs(("publishable", "publishable"), completion_attachments=True)
    gate_refs = {c.ArtifactRef.from_mapping(ref) for ref in inputs.gate["bindings"]}
    inventory = {ref.reference for ref in inputs.input_inventory}
    bundle = assemble(inputs)
    companion_refs = {c.ArtifactRef.from_mapping(ref) for ref in bundle.manifest["bindings"]}
    references = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            if {"path", "sha256"} <= value.keys():
                references.append(c.ArtifactRef.from_mapping(value))
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(c.json_body(inputs.gate["capabilities"]))
    collect(c.json_body(inputs.gate["attachments"]))
    assert len(references) > 20
    assert set(references) <= gate_refs <= inventory == companion_refs
    for reference in set(references):
        gate = c.json_body(inputs.gate)
        gate["bindings"] = [ref for ref in gate["bindings"] if ref["path"] != reference.path]
        with pytest.raises(ValueError, match="certified bindings"):
            with_gate(inputs, gate)
        with pytest.raises(ValueError, match="required input reference"):
            replace(inputs, input_inventory=tuple(ref for ref in inputs.input_inventory if ref.path != reference.path))


def test_gate2_full_completion_context_validates_from_offline_installed_schema_closure(
    tmp_path: Path, monkeypatch: Any,
) -> None:
    installed = installed_resources(tmp_path)
    monkeypatch.setattr(v.sys, "prefix", str(tmp_path))
    inputs = make_verified_inputs(("publishable", "publishable"), completion_attachments=True)
    bundle = assemble(inputs)
    validator = v.schema_validator("manifest.schema.json", repository_root=tmp_path / "no-checkout")
    validator.validate(c.json_body(bundle.manifest))
    report_schema_id = json.loads((installed / "../final-report/final-report.schema.json").read_bytes())["$id"]
    registry = v.schema_registry(repository_root=tmp_path / "no-checkout")
    assert len(c.SCHEMA_SHA256) == len(registry) == 7
    assert registry.get_or_retrieve(report_schema_id)
    (installed / "../final-report/final-report.schema.json").unlink()
    with pytest.raises(c.ExportError) as error:
        v.schema_validator("manifest.schema.json", repository_root=tmp_path / "no-checkout")
    assert error.value.reason == c.ExportFailureReason.INPUT_MISSING
