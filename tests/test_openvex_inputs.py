"""Unit coverage of the accepted-input boundary, not the live review/export chain."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import urllib.request
from unittest.mock import Mock

import pytest

from appsec_review.jobs.job_openvex_export import contracts as c, inputs
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.review.models import IntegrityError

from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT, enabled_settings


def assert_failure(call, reason: c.ExportFailureReason, phase: c.ExportPhase = c.ExportPhase.LOAD) -> c.ExportError:
    with pytest.raises(c.ExportError) as caught:
        call()
    assert caught.value.reason == reason
    assert caught.value.phase == phase
    return caught.value


@pytest.mark.parametrize("buckets", [(), ("publishable",), ("verification_backlog",), ("withheld",),
                                   ("publishable", "verification_backlog", "withheld")])
def test_real_hash_bound_disk_and_exact_classifier_projection(tmp_path, monkeypatch, buckets):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=buckets)
    verified = disk.verify()
    assert disk.calls == ["load_accepted_review"]
    assert c.json_body(verified.gate) == disk.gate
    assert [finding.bucket.value for finding in verified.findings] == [
        row["bucket"] for row in sorted(disk.gate["packages"], key=lambda row: row["finding_package_id"])]
    assert verified.gate_completed_at == "2026-10-28T14:00:00.000000Z"
    assert verified.provenance.resolved_config_sha256 == disk.config_ref["sha256"]
    assert verified.provenance.review_settings_sha256 != verified.provenance.resolved_config_sha256
    assert verified.source.target_snapshot == disk.snapshot
    assert verified.source.repository_identity_basis == c.RepositoryIdentityBasis.OPERATOR_DECLARED
    assert verified.source.acquisition is None
    assert {item.path for item in verified.input_inventory} >= {
        disk.scope_ref["path"], disk.manifest_ref["path"], disk.config_ref["path"],
        *(ref["path"] for ref in disk.lane_manifest_refs.values()),
    }
    assert verified.total_input_bytes == sum((disk.root / item.path).stat().st_size
                                             for item in verified.input_inventory)
    assert len(verified.input_inventory) == len({item.path for item in verified.input_inventory})
    for finding in verified.findings:
        assert c.json_body(finding.projection) in disk.gate["packages"]
        assert {ref.path for ref in finding.evidence_refs} == {disk.projection_ref["path"], disk.ledger_ref["path"]}
        assert all((disk.root / ref.path).is_file() for ref in finding.score_refs)
    assert c.VerifiedInputs.from_mapping(verified.to_json()) == verified
    inputs.reprove_inputs(disk.root, verified, disk.settings, ROOT)


@pytest.mark.parametrize("field", ["status", "bucket", "score", "binding", "count", "limitation", "lead", "hunt"])
def test_recomputed_gate_digest_does_not_authorize_semantic_changes(tmp_path, monkeypatch, field):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    gate = deepcopy(disk.gate)
    if field == "status":
        gate["packages"][0]["state"] = "supported"
    elif field == "bucket":
        gate["packages"][0]["bucket"] = "withheld"
    elif field == "score":
        gate["packages"][0]["scores"][0]["technical_severity"]["rating"] = "low"
    elif field == "binding":
        gate["bindings"].pop()
    elif field == "count":
        gate["package_counts"]["total"] += 1
    elif field == "limitation":
        gate["limitations"][0]["statement"] = "A rewritten accepted limitation"
    else:
        gate["review"]["lead_package_manifest_sha256" if field == "lead"
                       else "package_manifest_sha256"] = c.json_sha256("different package manifest")
    disk.publish_gate(gate)
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_STALE)


@pytest.mark.parametrize("reference", [
    "gate_ref", "review_ref", "scope_ref", "manifest_ref", "projection_ref", "ledger_ref",
    "receipt_ref", "coverage_ref", "config_ref", "review_job_ref", "gate_job_ref",
])
def test_each_consumed_reference_is_verified_from_bytes(tmp_path, monkeypatch, reference):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    ref = getattr(disk, reference)
    with (disk.root / ref["path"]).open("ab") as stream:
        stream.write(b" ")
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


@pytest.mark.parametrize("lane", ["lead", "hunt"])
def test_both_lane_manifest_bytes_are_checked_before_review_authority(tmp_path, monkeypatch, lane):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    (disk.root / disk.lane_manifest_refs[lane]["path"]).write_bytes(b"{}")
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)
    assert not disk.calls


@pytest.mark.parametrize("job", [inputs.GATE_JOB, inputs.REVIEW_JOB])
def test_absent_required_pointer_is_failure_not_empty_success(tmp_path, monkeypatch, job):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=())
    (disk.root / f"data/jobs/{job}/latest.json").unlink()
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_MISSING)


@pytest.mark.parametrize("job", [inputs.GATE_JOB, inputs.REVIEW_JOB, inputs.INTAKE_JOB])
def test_symlink_pointer_is_never_treated_as_not_run_using_safe_double(tmp_path, monkeypatch, job):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    pointer = disk.root / f"data/jobs/{job}/latest.json"
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == pointer or original(path))
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


@pytest.mark.parametrize("name", ["data/gate/gate.json", "data/review", "data/jobs/job_final_publication_gate"])
def test_symlink_artifact_and_parent_custody_using_safe_double(tmp_path, monkeypatch, name):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    linked = disk.root / name
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == linked or original(path))
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


@pytest.mark.parametrize("path", ["../outside.json", "/outside.json", "data\\gate\\gate.json",
                                 "C:/outside.json", "data/jobs/job_other/attempts/a/handoff.json"])
def test_unsafe_or_cross_job_pointer(tmp_path, monkeypatch, path):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.put(f"data/jobs/{inputs.GATE_JOB}/latest.json",
             {"handoff_path": path, "handoff_sha256": disk.gate_job_ref["sha256"]})
    error = assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID
                           if path != "data/jobs/job_other/attempts/a/handoff.json"
                           else c.ExportFailureReason.IDENTITY_CONFLICT)
    if path != "data/jobs/job_other/attempts/a/handoff.json":
        assert error.__cause__ is not None


def test_new_review_pointer_makes_gate_stale_even_when_review_bytes_unchanged(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    handoff = deepcopy(disk.review_handoff)
    handoff["completed_at"] = "2026-10-28T15:00:00Z"
    disk.publish(inputs.REVIEW_JOB, handoff)
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_STALE)


def test_review_helper_failure_is_not_swallowed_and_preserves_cause(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    cause = IntegrityError("authoritative ledger reproof rejected changed chain")
    spy = Mock(side_effect=cause)
    monkeypatch.setattr(inputs, "load_accepted_review", spy)
    error = assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID)
    assert error.__cause__ is cause
    assert spy.call_count == 1


@pytest.mark.parametrize("field", ["manifest_sha256", "target_snapshot", "run_id", "schema", "shards"])
def test_rehashed_accepted_scope_cannot_swap_identity(tmp_path, monkeypatch, field):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    scope = deepcopy(disk.scope)
    if field == "shards":
        scope[field] = [{"name": "source", "shard_id": "fake", "sha256": c.json_sha256("fake")}]
    else:
        scope[field] = c.json_sha256("different") if field in {"target_snapshot", "manifest_sha256"} else "wrong"
    reference = disk.put(disk.scope_ref["path"], scope)
    disk.review_handoff["outputs"]["scope.accept_manifest"]["artifact"] = reference
    disk.review_job_ref = disk.publish(inputs.REVIEW_JOB, disk.review_handoff)
    disk.authority["inputs"]["job_handoff"] = disk.review_job_ref
    disk.authority["bindings"] = [disk.review_job_ref if row["path"] == disk.review_job_ref["path"] else row
                                  for row in disk.authority["bindings"]]
    disk.publish_gate()
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


def test_input_limits_enforced_before_authoritative_review(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=("publishable", "withheld"),
                             settings=enabled_settings(max_packages=1))
    assert_failure(disk.verify, c.ExportFailureReason.BOUND_EXCEEDED)
    assert not disk.calls


@pytest.mark.parametrize("kind", ["artifact", "aggregate", "bindings"])
def test_reader_exact_lowered_thresholds_and_unique_accounting(tmp_path, kind):
    root = tmp_path / "run"
    root.mkdir()
    payload = b"x" * 17
    (root / "a").write_bytes(payload)
    (root / "b").write_bytes(payload)
    ref = c.ArtifactRef("a", hashlib.sha256(payload).hexdigest())
    settings = enabled_settings(max_artifact_bytes=17, max_total_input_bytes=34, max_bindings=2)
    reader = inputs.BoundedInputReader(root, settings)
    assert reader.read(ref) == payload
    assert reader.read(ref) == payload
    reader.read(c.ArtifactRef("b", ref.sha256))
    assert sum(item.size_bytes for item in reader.inventory) == 34
    if kind == "artifact":
        bad_settings = replace(settings, max_artifact_bytes=16)
        bad_ref = ref
    elif kind == "aggregate":
        bad_settings = replace(settings, max_total_input_bytes=33)
        bad_ref = c.ArtifactRef("b", ref.sha256)
    else:
        bad_settings = replace(settings, max_bindings=1)
        bad_ref = c.ArtifactRef("b", ref.sha256)
    reader = inputs.BoundedInputReader(root, bad_settings)
    if kind != "artifact":
        reader.read(ref)
    assert_failure(lambda: reader.read(bad_ref), c.ExportFailureReason.BOUND_EXCEEDED)


def test_bound_inventory_cannot_be_substituted_for_filesystem_reproof(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    verified = disk.verify()
    (disk.root / disk.ledger_ref["path"]).write_bytes(b"changed")
    assert_failure(lambda: inputs.reprove_inputs(disk.root, verified, disk.settings, ROOT),
                   c.ExportFailureReason.INPUT_TAMPERED, c.ExportPhase.ACCEPT)


@pytest.mark.parametrize("job", [inputs.GATE_JOB, inputs.REVIEW_JOB, inputs.INTAKE_JOB])
def test_pointer_changed_during_verification_fails_without_mutating_old_handoff(tmp_path, monkeypatch, job):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, acquisition=enabled_settings().repository_iri)
    original = inputs._findings

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        handoff = deepcopy({inputs.GATE_JOB: disk.gate_handoff, inputs.REVIEW_JOB: disk.review_handoff,
                            inputs.INTAKE_JOB: disk.intake_handoff}[job])
        handoff["completed_at"] = "2026-10-29T10:00:00Z"
        reference = disk.put(f"data/jobs/{job}/attempts/two/handoff.json", handoff)
        disk.put(f"data/jobs/{job}/latest.json",
                 {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
        return result

    monkeypatch.setattr(inputs, "_findings", changed)
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


@pytest.mark.parametrize("operation", ["start", "upstream"])
def test_deadline_is_checked_at_start_and_after_upstream_verifier(tmp_path, monkeypatch, operation):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    now = [0.0]
    monkeypatch.setattr(inputs.time, "monotonic", lambda: now[0])
    if operation == "start":
        reader = inputs.BoundedInputReader(disk.root, disk.settings, deadline=0.0)
        assert_failure(lambda: reader.read(c.ArtifactRef(**disk.gate_ref)), c.ExportFailureReason.TIMED_OUT)
    else:
        original = inputs.load_accepted_review

        def expire(*args, **kwargs):
            now[0] = 121.0
            return original(*args, **kwargs)

        monkeypatch.setattr(inputs, "load_accepted_review", expire)
        assert_failure(disk.verify, c.ExportFailureReason.TIMED_OUT)


def test_matching_acquisition_qualifies_identity_without_guessing_product_hash(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, acquisition=enabled_settings().repository_iri)
    verified = disk.verify()
    assert verified.source.acquisition == c.ArtifactRef(**disk.acquisition_ref)
    assert verified.source.repository_identity_basis == c.RepositoryIdentityBasis.ACCEPTED_ACQUISITION
    assert verified.source.repository_iri == disk.settings.repository_iri
    assert verified.source.target_snapshot == disk.snapshot
    assert "b" * 40 not in verified.source.target_snapshot
    assert "DO-NOT-ACCESS-TARGET" not in repr(verified.source)


def test_acquisition_repository_swap_is_not_overridden_by_operator_setting(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, acquisition="https://example.test/another-repository")
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


def test_changed_since_acquisition_is_preserved_as_qualification_not_commit_identity(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.add_acquisition(disk.settings.repository_iri, tree_matches=False)
    verified = disk.verify()
    assert verified.source.target_snapshot == disk.snapshot
    assert any("differs" in value for value in verified.source.qualifications)


def test_settings_are_immutable_even_with_no_findings(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=())
    assert_failure(lambda: inputs.verify_inputs(disk.root, replace(disk.settings, author="Another Organization"), ROOT),
                   c.ExportFailureReason.CONFIGURATION_INVALID)
    assert_failure(lambda: inputs.verify_inputs(disk.root, OpenVexExportSettings(), ROOT),
                   c.ExportFailureReason.CONFIGURATION_INVALID)


def test_manifest_verifier_is_authority_and_failure_is_preserved(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    cause = ValueError("manifest semantic identity mismatch despite recomputed file digest")
    spy = Mock(side_effect=cause)
    monkeypatch.setattr(inputs, "load_verified_manifest", spy)
    error = assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID)
    assert error.__cause__ is cause
    assert spy.call_count == 1


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":' + b"[" * 33 + b"]" * 33 + b"}",
                                   b"\xff", b"[]"])
def test_bounded_json_rejects_ambiguous_documents(tmp_path, payload):
    (tmp_path / "input").write_bytes(payload)
    reader = inputs.BoundedInputReader(tmp_path, enabled_settings())
    reference = reader.pin("input").reference
    error = assert_failure(lambda: reader.json(reference), c.ExportFailureReason.SCHEMA_INVALID)
    assert error.__cause__ is not None


def test_conflicting_path_hashes_rejected_independently_of_byte_count(tmp_path):
    (tmp_path / "input").write_bytes(b"test")
    reader = inputs.BoundedInputReader(tmp_path, enabled_settings())
    reference = reader.pin("input").reference
    assert_failure(lambda: reader.read(c.ArtifactRef(reference.path, c.json_sha256("different"))),
                   c.ExportFailureReason.IDENTITY_CONFLICT)


@pytest.mark.parametrize("overrides", [{"max_artifact_bytes": 1}, {"max_bindings": 1},
                                     {"max_artifact_bytes": 1, "max_total_input_bytes": 1}])
def test_configured_lower_input_limits_apply_to_real_verification(tmp_path, monkeypatch, overrides):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, settings=enabled_settings(**overrides))
    assert_failure(disk.verify, c.ExportFailureReason.BOUND_EXCEEDED)
    assert disk.calls == []


def test_configuration_manifest_cannot_repoint_frozen_resolved_bytes(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.put(disk.config_manifest_ref["path"], {"resolved_sha256": c.json_sha256("different configuration")})
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


def test_rehashed_configuration_is_still_pinned_by_accepted_job_handoffs(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.resolved["configuration_profile"]["name"] = "changed profile"
    reference = disk.put(disk.config_ref["path"], disk.resolved)
    disk.put(disk.config_manifest_ref["path"], {"resolved_sha256": reference["sha256"]})
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_STALE)


def test_rehashed_review_settings_cannot_disagree_with_semantic_review_hash(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.resolved["jobs"][inputs.REVIEW_JOB]["settings"]["rounds"]["stable_rounds_required"] += 1
    reference = disk.put(disk.config_ref["path"], disk.resolved)
    disk.put(disk.config_manifest_ref["path"], {"resolved_sha256": reference["sha256"]})
    disk.review_handoff["resolved_config_sha256"] = reference["sha256"]
    disk.gate_handoff["resolved_config_sha256"] = reference["sha256"]
    disk.review_job_ref = disk.publish(inputs.REVIEW_JOB, disk.review_handoff)
    disk.authority["inputs"]["job_handoff"] = disk.review_job_ref
    disk.authority["bindings"] = [disk.review_job_ref if ref["path"] == disk.review_job_ref["path"] else ref
                                 for ref in disk.authority["bindings"]]
    disk.config_ref = reference
    disk.publish_gate()
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


def test_rehashed_score_package_cannot_swap_claim_identity(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    row = disk.authority["packages"][0]
    score = row["scores"][0]
    path = f"data/review/scoring/scores/{score['score_id']}.json"
    body = json.loads((disk.root / path).read_bytes())
    body["claim_id"] = "claim-" + c.json_sha256("another claim")
    reference = disk.put(path, body)
    score["sha256"] = reference["sha256"]
    disk.review["score_packages"][0]["sha256"] = reference["sha256"]
    disk.authority["bindings"] = [reference if ref["path"] == path else ref for ref in disk.authority["bindings"]]
    disk.refresh_review()
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


def test_rehashed_evidence_projection_cannot_swap_relation_claim(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    row = disk.authority["packages"][0]
    disk.projection["relations"][row["claim_id"]][0]["claim_id"] = "claim-" + c.json_sha256("another claim")
    reference = disk.put(disk.projection_ref["path"], disk.projection)
    disk.authority["inputs"]["projection"] = reference
    disk.authority["review"]["projection_sha256"] = reference["sha256"]
    receipt = json.loads((disk.root / disk.receipt_ref["path"]).read_bytes())
    receipt.update({"projection_sha256": reference["sha256"], "projection_file_sha256": reference["sha256"]})
    receipt_ref = disk.put(disk.receipt_ref["path"], receipt)
    disk.review_handoff["outputs"]["publication.publish_claim_ledger"]["artifact"] = receipt_ref
    updates = {ref["path"]: ref for ref in (reference, receipt_ref)}
    disk.authority["bindings"] = [updates.get(ref["path"], ref) for ref in disk.authority["bindings"]]
    disk.refresh_review()
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


def test_published_gate_count_is_verified_separately_from_gate_document(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.gate_handoff["outputs"]["acceptance.publish_handoff"]["item_count"] = 0
    disk.publish(inputs.GATE_JOB, disk.gate_handoff)
    assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID)


@pytest.mark.parametrize("kind", ["cross_run", "nonaccepted", "wrong_job"])
def test_accepted_handoff_identity_is_not_inferred_from_its_filename(tmp_path, monkeypatch, kind):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    field, value = {"cross_run": ("run_id", "another-run"), "nonaccepted": ("status", "FAILED"),
                    "wrong_job": ("job_id", inputs.REVIEW_JOB)}[kind]
    disk.gate_handoff[field] = value
    disk.publish(inputs.GATE_JOB, disk.gate_handoff)
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


def test_network_process_and_target_access_are_not_part_of_verification(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    forbidden = Mock(side_effect=AssertionError("network/process/target access forbidden"))
    for owner, name in ((socket, "create_connection"), (subprocess, "Popen"), (urllib.request, "urlopen")):
        monkeypatch.setattr(owner, name, forbidden)
    original_open = Path.open
    original_glob = Path.glob

    def guarded_open(path, *args, **kwargs):
        assert "DO-NOT-ACCESS-TARGET" not in str(path)
        return original_open(path, *args, **kwargs)

    def guarded_glob(path, *args, **kwargs):
        assert path.is_relative_to(ROOT / "docs" / "schemas")
        return original_glob(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(Path, "glob", guarded_glob)
    monkeypatch.setattr(Path, "rglob", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    assert disk.verify().source.target_snapshot == disk.snapshot
    forbidden.assert_not_called()


@pytest.mark.parametrize("cause,reason", [(PermissionError("denied"), c.ExportFailureReason.IO_ERROR),
                                       (RuntimeError("unexpected verifier error"), c.ExportFailureReason.INTERNAL_ERROR)])
def test_upstream_errors_are_explicit_closed_failures_with_causes(tmp_path, monkeypatch, cause, reason):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    monkeypatch.setattr(inputs, "load_accepted_review", Mock(side_effect=cause))
    assert assert_failure(disk.verify, reason).__cause__ is cause


def test_sized_reference_size_is_measured_not_trusted(tmp_path):
    (tmp_path / "input").write_bytes(b"test")
    reader = inputs.BoundedInputReader(tmp_path, enabled_settings(), phase=c.ExportPhase.ACCEPT)
    reference = reader.pin("input")
    assert_failure(lambda: reader.read(replace(reference, size_bytes=3)), c.ExportFailureReason.INPUT_TAMPERED,
                   c.ExportPhase.ACCEPT)


def test_directories_are_not_input_files(tmp_path):
    (tmp_path / "directory").mkdir()
    reader = inputs.BoundedInputReader(tmp_path, enabled_settings())
    assert_failure(lambda: reader.pin("directory"), c.ExportFailureReason.INPUT_TAMPERED)


@pytest.mark.parametrize("field", ["source_fingerprint", "evidence_target_snapshot"])
def test_rehashed_job_snapshot_qualification_cannot_swap_scope(tmp_path, monkeypatch, field):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.gate_handoff[field] = c.json_sha256("another snapshot")
    disk.publish(inputs.GATE_JOB, disk.gate_handoff)
    assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)


@pytest.mark.parametrize("kind", ["perforce", "system", "revision_swap"])
def test_acquisition_without_single_repository_preserves_operator_qualification(tmp_path, monkeypatch, kind):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, acquisition=enabled_settings().repository_iri)
    acquisition = json.loads((disk.root / disk.acquisition_ref["path"]).read_bytes())
    if kind == "perforce":
        acquisition.update({"spec": {"kind": "perforce"},
                            "identity": {"kind": "perforce", "changelist": 123}})
    elif kind == "system":
        acquisition.update({"schema": "appsec-review/target-system-acquisition/1",
                            "spec": {"system": "example", "components": {"component": {"kind": "git"}}},
                            "identity": {"component": {"identity": acquisition["identity"]}}})
    else:
        acquisition["spec"]["commit"] = "d" * 40
    acquisition["identity_sha256"] = c.json_sha256(acquisition["identity"])
    reference = disk.put(disk.acquisition_ref["path"], acquisition)
    intake = json.loads((disk.root / disk.intake_ref["path"]).read_bytes())
    record = intake["fingerprint"]["acquisition"]
    record.update({key: acquisition[key] for key in ("schema", "identity", "identity_sha256")})
    record["manifest_sha256"] = reference["sha256"]
    intake_reference = disk.put(disk.intake_ref["path"], intake)
    disk.intake_handoff["outputs"]["publish_intake.publish_handoff"]["artifact"] = intake_reference
    disk.publish(inputs.INTAKE_JOB, disk.intake_handoff)
    if kind == "revision_swap":
        assert_failure(disk.verify, c.ExportFailureReason.IDENTITY_CONFLICT)
    else:
        source = disk.verify().source
        assert source.repository_iri == disk.settings.repository_iri
        assert source.repository_identity_basis == c.RepositoryIdentityBasis.ACCEPTED_ACQUISITION
        assert source.acquisition == c.ArtifactRef(**reference)
        assert any("no single repository IRI" in value for value in source.qualifications)


def test_admission_pointers_are_measured_but_not_durable_bindings(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, acquisition=enabled_settings().repository_iri)
    reader_type = inputs.BoundedInputReader
    readers = []

    def tracking_reader(*args, **kwargs):
        reader = reader_type(*args, **kwargs)
        readers.append(reader)
        return reader

    monkeypatch.setattr(inputs, "BoundedInputReader", tracking_reader)
    verified = disk.verify()
    operational = {f"data/jobs/{job}/latest.json" for job in (
        inputs.GATE_JOB, inputs.REVIEW_JOB, inputs.INTAKE_JOB)}
    full_inventory = readers[0].inventory
    assert operational <= {reference.path for reference in full_inventory}
    assert not operational & {reference.path for reference in verified.input_inventory}
    assert set(verified.input_inventory) == {reference for reference in full_inventory
                                           if reference.path not in operational}
    pointer_bytes = sum(reference.size_bytes for reference in full_inventory if reference.path in operational)
    assert sum(reference.size_bytes for reference in full_inventory) == verified.total_input_bytes + pointer_bytes
    assert set(verified.provenance.references) <= {reference.reference for reference in verified.input_inventory}


def test_durable_inventory_survives_new_gate_pointer_but_current_reproof_is_stale(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    verified = disk.verify()
    original_handoff = (disk.root / disk.gate_job_ref["path"]).read_bytes()
    handoff = deepcopy(disk.gate_handoff)
    handoff["completed_at"] = "2026-10-29T10:00:00Z"
    reference = disk.put(f"data/jobs/{inputs.GATE_JOB}/attempts/two/handoff.json", handoff)
    disk.put(f"data/jobs/{inputs.GATE_JOB}/latest.json",
             {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
    reader = inputs.BoundedInputReader(disk.root, disk.settings, phase=c.ExportPhase.ACCEPT)
    for bound in verified.input_inventory:
        reader.read(bound)
    assert (disk.root / disk.gate_job_ref["path"]).read_bytes() == original_handoff
    assert reader.read(verified.provenance.gate_handoff) == original_handoff
    assert disk.verify().provenance.gate_handoff == c.ArtifactRef(**reference)
    assert_failure(lambda: inputs.reprove_inputs(disk.root, verified, disk.settings, ROOT),
                   c.ExportFailureReason.INPUT_STALE, c.ExportPhase.ACCEPT)


@pytest.mark.parametrize("pointer", ["data/jobs/job_example/latest.json", "data/indices/accepted.json"])
@pytest.mark.parametrize("bound", ["bindings", "bytes"])
def test_operational_pointer_bytes_and_references_still_count_toward_bounds(tmp_path, pointer, bound):
    path = tmp_path / pointer
    path.parent.mkdir(parents=True)
    path.write_bytes(b"pointer")
    (tmp_path / "immutable.json").write_bytes(b"immutable")
    settings = enabled_settings(max_bindings=1 if bound == "bindings" else 2,
                                max_artifact_bytes=9, max_total_input_bytes=16 if bound == "bindings" else 15)
    reader = inputs.BoundedInputReader(tmp_path, settings)
    reader.pin(pointer)
    assert inputs._durable_inventory(reader.inventory) == ()
    assert_failure(lambda: reader.pin("immutable.json"), c.ExportFailureReason.BOUND_EXCEEDED)


def test_only_exact_operational_pointer_families_are_omitted(tmp_path):
    names = ("data/jobs/job_example/latest.json", "data/indices/accepted.json",
             "data/jobs/job_example/attempts/one/latest.json", "data/indices/original-manifest.json")
    reader = inputs.BoundedInputReader(tmp_path, enabled_settings())
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}")
        reader.pin(name)
    assert {reference.path for reference in inputs._durable_inventory(reader.inventory)} == set(names[2:])
    (tmp_path / names[1]).write_bytes(b'{"changed":true}')
    assert_failure(reader.reprove, c.ExportFailureReason.INPUT_TAMPERED)
