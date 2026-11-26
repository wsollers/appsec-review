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
from appsec_review.interchange import HANDOFF_SCHEMA, decode_handoff
from appsec_review.review.models import IntegrityError

from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT, enabled_settings


def assert_failure(call, reason: c.ExportFailureReason, phase: c.ExportPhase = c.ExportPhase.LOAD) -> c.ExportError:
    with pytest.raises(c.ExportError) as caught:
        call()
    assert caught.value.reason == reason
    assert caught.value.phase == phase
    return caught.value


def repin_gate_handoff(disk, handoff):
    reference = disk.put(disk.gate_job_ref["path"], handoff)
    disk.put(f"data/jobs/{inputs.GATE_JOB}/latest.json",
             {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})


def test_dependency_sca_is_read_through_the_bound_domain_artifact(tmp_path, monkeypatch):
    from appsec_review.jobs.job_openvex_export.dependencies import DEPENDENCY_JOB, read_dependency_inputs

    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    document = {
        "schema": "appsec-review/sca-reachability/1", "source_fingerprint": disk.snapshot,
        "configured_osv_mode": "disabled", "osv_matching_mode": "disabled",
        "advisories": [], "coverage": "partial", "gaps": ["no dependency analysis"],
        "telemetry": {"advisories_matched": 0, "osv_matching_mode": "disabled",
                      "symbol_reachable_count": 0, "ffi_boundary_matches": 0},
    }
    sca = disk.put("data/dependency/sca.json", document)
    domain = disk.put("data/dependency/handoff.json", {
        "schema": "appsec-review/dependency-intelligence-handoff/1",
        "source_fingerprint": disk.snapshot, "sca_reachability": sca,
    })
    handoff = disk.handoff(DEPENDENCY_JOB, {"acceptance.publish_handoff": {"artifact": domain}})
    handoff["artifacts"] = [sca]
    disk.publish(DEPENDENCY_JOB, handoff)
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    _accepted, reference, loaded = read_dependency_inputs(
        reader, ROOT, resolved_config_sha256=disk.config_ref["sha256"], target_snapshot=disk.snapshot)
    assert reference == c.ArtifactRef.from_mapping(sca)
    assert loaded == document
    assert domain["path"] in {item.path for item in reader.inventory}
    (disk.root / domain["path"]).write_bytes(b"{}")
    with pytest.raises(c.ExportError):
        read_dependency_inputs(inputs.BoundedInputReader(disk.root, disk.settings), ROOT,
                               resolved_config_sha256=disk.config_ref["sha256"], target_snapshot=disk.snapshot)


def test_common_envelopes_use_the_real_shared_reader_and_bind_accounting_before_authority(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    original = inputs.accepted_handoff
    seen = []

    def accepted(root, job):
        admitted = {ref.path: ref for ref in reader.inventory}
        handoff = disk.gate_handoff
        assert handoff["schema"] == HANDOFF_SCHEMA
        assert decode_handoff(handoff, run_id=root.name, job_id=job) == handoff
        for raw in handoff["artifacts"]:
            assert admitted[raw["path"]] == c.SizedArtifactRef.from_mapping(raw)
        seen.append(job)
        return original(root, job)

    monkeypatch.setattr(inputs, "accepted_handoff", accepted)
    accepted = inputs._accepted(reader, inputs.GATE_JOB)
    assert accepted.handoff == disk.gate_handoff
    assert seen == [inputs.GATE_JOB]
    paths = {ref.path for ref in reader.inventory}
    attempt = disk.gate_handoff["resolving_paths"]["attempt"]
    assert {attempt + "/claim.json", attempt + "/result.json", attempt + "/outcomes.json",
            attempt + "/steps/acceptance/tasks/publish_handoff/status.json",
            attempt + "/steps/acceptance/tasks/publish_handoff/result.json"} <= paths


def test_disk_publisher_retains_explicit_artifacts_attempt_and_raw_completion_time(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    artifact = disk.put("data/extra/runtime.bin", b"opaque retained data, not a JSON control document")
    handoff = disk.handoff(inputs.GATE_JOB, disk.gate_handoff["outputs"])
    handoff.update({"attempt_id": "explicit", "artifacts": [artifact],
                    "completed_at": "2026-10-28T15:00:00+01:30"})
    reference = disk.publish(inputs.GATE_JOB, handoff)
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    accepted = inputs._accepted(reader, inputs.GATE_JOB)
    assert reference["path"] == f"data/jobs/{inputs.GATE_JOB}/attempts/explicit/handoff.json"
    assert accepted.handoff == handoff
    assert handoff["completed_at"] == "2026-10-28T15:00:00+01:30"
    assert c.ArtifactRef(**artifact) in {ref.reference for ref in reader.inventory}


def test_common_accounting_source_inventory_is_not_permission_to_open_target_paths(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    target = tmp_path / "DO-NOT-ACCESS-TARGET" / "source.c"
    disk.gate_handoff["outputs"]["acceptance.publish_handoff"]["source_files"] = [
        {"path": str(target), "sha256": c.json_sha256("source inventory identity, not run evidence")}]
    disk.publish(inputs.GATE_JOB, disk.gate_handoff)
    original = Path.open

    def no_target(path, *args, **kwargs):
        assert path != target
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_target)
    inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), inputs.GATE_JOB)


@pytest.mark.parametrize("mutation", ["legacy", "incomplete", "duplicate_artifact", "input_hash"])
def test_legacy_or_structurally_invalid_common_envelopes_fail_before_shared_authority(tmp_path, monkeypatch, mutation):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    handoff = deepcopy(disk.gate_handoff)
    if mutation == "legacy":
        handoff["schema"] = "appsec-review/job-handoff/1"
    elif mutation == "incomplete":
        handoff.pop("outcomes")
    elif mutation == "duplicate_artifact":
        handoff["artifacts"].append(deepcopy(handoff["artifacts"][0]))
    else:
        handoff["input_set_sha256"] = c.json_sha256("recomputed outer handoff, invalid inner identity")
    repin_gate_handoff(disk, handoff)
    spy = Mock(side_effect=AssertionError("shared authority must not read malformed envelope"))
    monkeypatch.setattr(inputs, "accepted_handoff", spy)
    assert_failure(lambda: inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), inputs.GATE_JOB),
                   c.ExportFailureReason.SCHEMA_INVALID)
    spy.assert_not_called()


@pytest.mark.parametrize("suffix", [
    "/claim.json", "/result.json", "/outcomes.json",
    "/steps/acceptance/tasks/publish_handoff/status.json",
    "/steps/acceptance/tasks/publish_handoff/result.json",
])
def test_every_common_accounting_file_is_bounded_before_shared_authority(tmp_path, monkeypatch, suffix):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    attempt = disk.gate_handoff["resolving_paths"]["attempt"]
    (disk.root / (attempt + suffix)).write_bytes(b"tampered accounting")
    spy = Mock(side_effect=AssertionError("shared authority must not read corrupt accounting"))
    monkeypatch.setattr(inputs, "accepted_handoff", spy)
    assert_failure(lambda: inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), inputs.GATE_JOB),
                   c.ExportFailureReason.INPUT_TAMPERED)
    spy.assert_not_called()


def test_declared_common_artifact_size_is_not_trusted(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    handoff = deepcopy(disk.gate_handoff)
    handoff["artifacts"][0]["size_bytes"] += 1
    repin_gate_handoff(disk, handoff)
    spy = Mock(side_effect=AssertionError("sized declarations must be measured first"))
    monkeypatch.setattr(inputs, "accepted_handoff", spy)
    assert_failure(lambda: inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), inputs.GATE_JOB),
                   c.ExportFailureReason.INPUT_TAMPERED)
    spy.assert_not_called()


@pytest.mark.parametrize("surface", ["result_run_path", "shared_receipt"])
def test_large_common_accounting_references_are_reproved_before_authority(tmp_path, monkeypatch, surface):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    handoff = deepcopy(disk.gate_handoff)
    large = disk.put("retained.bin", b"x" * 100000)
    if surface == "result_run_path":
        name = handoff["resolving_paths"]["result"]
        document = json.loads((disk.root / name).read_bytes())
        document["retained_artifact"] = {"run_path": large["path"], "sha256": large["sha256"]}
    else:
        name = handoff["resolving_paths"]["attempt"] + "/shared/synthetic/" + "a" * 64 + ".json"
        document = {"object": {"run_path": large["path"], "sha256": large["sha256"]}}
    reference = disk.put(name, document)
    reference["size_bytes"] = (disk.root / name).stat().st_size
    handoff["artifacts"] = [raw for raw in handoff["artifacts"] if raw["path"] != name] + [reference]
    repin_gate_handoff(disk, handoff)
    (disk.root / large["path"]).write_bytes(b"y" * 100000)
    spy = Mock(side_effect=AssertionError("transitive accounting must be verified before shared authority"))
    monkeypatch.setattr(inputs, "accepted_handoff", spy)
    settings = disk.settings
    assert_failure(lambda: inputs._accepted(inputs.BoundedInputReader(disk.root, settings), inputs.GATE_JOB),
                   c.ExportFailureReason.INPUT_TAMPERED)
    spy.assert_not_called()


@pytest.mark.parametrize("kind", ["bindings", "bytes"])
def test_common_envelope_accounting_counts_once_and_obeys_lowered_limits(tmp_path, monkeypatch, kind):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    inputs._accepted(reader, inputs.GATE_JOB)
    inventory = reader.inventory
    settings = replace(disk.settings, max_bindings=len(inventory))
    exact = inputs.BoundedInputReader(disk.root, settings)
    inputs._accepted(exact, inputs.GATE_JOB)
    inputs._accepted(exact, inputs.GATE_JOB)
    assert exact.inventory == inventory
    settings = replace(settings, **({"max_bindings": len(inventory) - 1} if kind == "bindings" else
                                   {"max_document_bytes": 1024}))
    if kind == "bytes":
        reader = inputs.BoundedInputReader(disk.root, settings)
        inputs._accepted(reader, inputs.GATE_JOB)
        assert reader.inventory == inventory
        return
    spy = Mock(side_effect=AssertionError("lowered envelope bound must fail before authority"))
    monkeypatch.setattr(inputs, "accepted_handoff", spy)
    assert_failure(lambda: inputs._accepted(inputs.BoundedInputReader(disk.root, settings), inputs.GATE_JOB),
                   c.ExportFailureReason.BOUND_EXCEEDED)
    spy.assert_not_called()


def test_rehashed_common_outcomes_still_need_authoritative_task_accounting(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    handoff = deepcopy(disk.gate_handoff)
    document = json.loads((disk.root / handoff["outcomes"]["path"]).read_bytes())
    document["coverage"]["gap_count"] += 1
    reference = disk.put(handoff["outcomes"]["path"], document)
    reference["size_bytes"] = (disk.root / reference["path"]).stat().st_size
    handoff["outcomes"] = reference
    handoff["artifacts"] = [reference if raw["path"] == reference["path"] else raw for raw in handoff["artifacts"]]
    repin_gate_handoff(disk, handoff)
    error = assert_failure(
        lambda: inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), inputs.GATE_JOB),
        c.ExportFailureReason.INPUT_TAMPERED)
    assert "outcomes differ" in str(error.__cause__)


def test_common_accounting_bytes_are_reproved_after_shared_authority(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    original = inputs.accepted_handoff

    def accepted(root, job):
        result = original(root, job)
        (root / result.handoff["resolving_paths"]["result"]).write_bytes(b"changed after authority")
        return result

    monkeypatch.setattr(inputs, "accepted_handoff", accepted)
    inputs._accepted(reader, inputs.GATE_JOB)
    assert_failure(reader.reprove, c.ExportFailureReason.INPUT_TAMPERED)


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
        disk.chain_manifest_ref["path"], *(ref["path"] for ref in disk.lane_refs.values()),
        *(ref["path"] for ref in disk.lane_manifest_refs.values()),
        *(ref["path"] for ref in disk.lane_package_refs.values()),
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
    "receipt_ref", "coverage_ref", "config_ref", "review_job_ref", "gate_job_ref", "chain_manifest_ref",
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


@pytest.mark.parametrize("lane", ["lead", "hunt"])
@pytest.mark.parametrize("reference", ["lane_refs", "lane_package_refs"])
def test_authenticated_lane_sets_and_package_bytes_are_bounded_before_authority(tmp_path, monkeypatch, lane, reference):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    (disk.root / getattr(disk, reference)[lane]["path"]).write_bytes(b"{}")
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)
    assert not disk.calls


@pytest.mark.parametrize("schema", ["appsec-review/inference-review-handoff/2", "unknown"])
def test_review_preflight_has_no_legacy_adapter(tmp_path, monkeypatch, schema):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.review["schema"] = schema
    disk.refresh_review()
    assert_failure(disk.verify, c.ExportFailureReason.SCHEMA_INVALID)
    assert not disk.calls


def test_chain_preflight_bounds_proposals_decisions_and_original_actor_receipts(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    artifact = disk.put("data/review/chains/chain.json", {"synthetic": "chain"})
    proposal = disk.put("data/review/chains/proposal.json", {"synthetic": "proposal"})
    challenge = disk.put("data/review/chains/challenge-receipt.json", {"synthetic": "challenge"})
    cell_id = "cell-synthetic-composer"
    composer = disk.put(f"data/jobs/{inputs.REVIEW_JOB}/cells/{cell_id}/attempt-1.json",
                        {"synthetic": "composer"})
    disk.chain_manifest["items"] = [{"artifact": artifact}]
    disk.review["attack_chain_manifest"] = disk.put(disk.chain_manifest_ref["path"], disk.chain_manifest)
    # Derived continuity cites accepted build products: the link database is a JSON array, the compile
    # database an object outside the review job. Both are hash-bound, neither is parsed as review JSON.
    link_database = disk.put("data/build/probes/units/build-unit-1/attempts/attempt_0001/link-commands.json",
                             [{"output_path": "build/app", "input_paths": ["build/a.o"]}])
    compile_database = disk.put("data/build/probes/units/build-unit-1/attempts/attempt_0001/compile-database.json",
                                {"schema": "synthetic", "rows": []})
    disk.projection["attack_chains"] = {"synthetic": {
        "proposal": {"composer": {"conversation_id": cell_id},
                     "edges": [{"obligations": [{"evidence": [{"derivation": {"bound_files": {
                         "link_database": link_database, "compile_database": compile_database}}}]}]}]},
        "proposal_artifact": proposal,
        "challenges": [{"actor": {"conversation_id": "cell-synthetic-challenge"}, "receipt": challenge}],
        "decision": {"artifact": artifact},
    }}
    disk.projection["cells"] = {cell_id: [{"task": "chain_composer", "attempts": 1,
                                          "receipt_sha256": composer["sha256"]}],
                                "unused-composer": [{"task": "chain_composer", "attempts": 1,
                                                     "receipt_sha256": c.json_sha256("not an admitted actor")}]}
    projection_ref = disk.put(disk.projection_ref["path"], disk.projection)
    receipt = json.loads((disk.root / disk.receipt_ref["path"]).read_bytes())
    receipt["projection_file_sha256"] = projection_ref["sha256"]
    disk.review_handoff["outputs"]["publication.publish_claim_ledger"]["artifact"] = disk.put(
        disk.receipt_ref["path"], receipt)
    disk.review_handoff["outputs"]["publication.publish_handoff"]["artifact"] = disk.put(
        disk.review_ref["path"], disk.review)
    reader = inputs.BoundedInputReader(disk.root, disk.settings)
    inputs._preflight_review(reader, disk.review_handoff)
    assert {ref["path"] for ref in (artifact, proposal, challenge, composer, link_database, compile_database)} <= {
        ref.path for ref in reader.inventory}
    assert not disk.calls  # Synthetic chain references exercise preflight only, not ledger authority.
    (disk.root / composer["path"]).write_bytes(b"changed")
    assert_failure(reader.reprove, c.ExportFailureReason.INPUT_TAMPERED)


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
                           else c.ExportFailureReason.INPUT_TAMPERED)
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


def test_shared_snapshot_authority_is_used_with_the_admitted_gate_identity(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    original = inputs.load_accepted_gate
    calls = []

    def load(root, schemas, *, expected_handoff_sha256):
        calls.append((root, schemas.directory, expected_handoff_sha256))
        return original(root, schemas, expected_handoff_sha256=expected_handoff_sha256)

    monkeypatch.setattr(inputs, "load_accepted_gate", load)
    disk.verify()
    assert calls == [(disk.root, ROOT / "docs" / "schemas" / "final-report", disk.gate_job_ref["sha256"])]


def test_snapshot_authority_failure_is_closed_and_preserves_cause(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    cause = IntegrityError("certified snapshot rejected despite a fresh handoff digest")
    spy = Mock(side_effect=cause)
    monkeypatch.setattr(inputs, "load_accepted_gate", spy)
    assert assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID).__cause__ is cause
    assert spy.call_count == 1


@pytest.mark.parametrize("timestamp", ["2026-10-28T10:00:00+01:60", "2026-10-28T10:00:00+24:00"])
def test_original_gate_completion_timestamp_is_not_normalized_before_strict_boundary(tmp_path, monkeypatch, timestamp):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.gate_handoff["completed_at"] = timestamp
    disk.publish(inputs.GATE_JOB, disk.gate_handoff)
    error = assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID)
    assert isinstance(error.__cause__, ValueError)
    assert "RFC3339" in str(error.__cause__)


@pytest.mark.parametrize("swapped", ["handoff", "gate"])
def test_snapshot_authority_result_cannot_swap_the_bounded_admission(tmp_path, monkeypatch, swapped):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    original = inputs.load_accepted_gate

    def load(*args, **kwargs):
        accepted, gate = original(*args, **kwargs)
        if swapped == "handoff":
            accepted = replace(accepted, path=f"data/jobs/{inputs.GATE_JOB}/attempts/other/handoff.json")
        else:
            gate["status"] = "COMPLETE"
        return accepted, gate

    monkeypatch.setattr(inputs, "load_accepted_gate", load)
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_STALE)


def test_certified_chain_is_measured_durably_and_producer_heads_are_not_reinterpreted(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=("publishable", "publishable"))
    chain_ref = disk.add_certified_chain()
    verified = disk.verify()
    optional_jobs = ("job_poc_generation", "job_remediation_planning", "job_remediation_validation",
                     "job_dossier_publication", "job_attack_chain_composition")
    pointers = {f"data/jobs/{job}/latest.json" for job in optional_jobs}
    for path in pointers:
        disk.put(path, b"not valid JSON")
    original = Path.open

    def no_optional_heads(path, *args, **kwargs):
        assert path not in {disk.root / name for name in pointers}
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_optional_heads)
    current = disk.verify()
    assert current == verified
    inputs.reprove_inputs(disk.root, verified, disk.settings, ROOT)
    references = {ref.reference for ref in verified.input_inventory}
    assert {c.ArtifactRef(**chain_ref), c.ArtifactRef(**disk.chain_manifest_ref)} <= references
    assert not pointers & {ref.path for ref in verified.input_inventory}
    for name in ("inputs", "capabilities", "attachments"):
        assert set(inputs._references(c.json_body(verified.gate[name]))) <= references


@pytest.mark.parametrize("surface", ["capabilities", "attachments"])
def test_nested_completion_reference_must_be_certified_not_merely_readable(tmp_path, monkeypatch, surface):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reference = disk.put("data/unbound/certificate.json", {"synthetic": "not certified"})
    if surface == "capabilities":
        disk.authority[surface]["dossiers"]["handoff"] = reference
    else:
        disk.authority[surface]["attack_chains"] = [{
            "chain_id": "chain-" + c.json_sha256("unbound chain"), "status": "qualified_supported",
            "component_claim_ids": ["claim-" + c.json_sha256(str(index)) for index in range(2)],
            "artifact": reference, "gap_count": 1, "disposition": "assessed",
        }]
    disk.publish_gate()
    error = assert_failure(disk.verify, c.ExportFailureReason.SEMANTIC_INVALID)
    assert isinstance(error.__cause__, IntegrityError)
    assert "certified bindings" in str(error.__cause__)


@pytest.mark.parametrize("reference", ["chain", "manifest"])
def test_certified_chain_bytes_are_rehashed_after_snapshot_authority(tmp_path, monkeypatch, reference):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=("publishable", "publishable"))
    chain_ref = disk.add_certified_chain()
    target = chain_ref if reference == "chain" else disk.chain_manifest_ref
    original = inputs.load_accepted_gate

    def load(*args, **kwargs):
        result = original(*args, **kwargs)
        (disk.root / target["path"]).write_bytes(b"changed after authority")
        return result

    monkeypatch.setattr(inputs, "load_accepted_gate", load)
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


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
    updates = {ref["path"]: ref for ref in (reference, disk.review_job_ref)}
    disk.authority["bindings"] = [updates.get(row["path"], row) for row in disk.authority["bindings"]]
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
    settings = enabled_settings(max_bindings=2)
    reader = inputs.BoundedInputReader(root, settings)
    assert reader.read(ref) == payload
    assert reader.read(ref) == payload
    reader.read(c.ArtifactRef("b", ref.sha256))
    assert sum(item.size_bytes for item in reader.inventory) == 34
    if kind == "artifact":
        bad_settings = settings
        bad_ref = ref
    elif kind == "aggregate":
        bad_settings = settings
        bad_ref = c.ArtifactRef("b", ref.sha256)
    else:
        bad_settings = replace(settings, max_bindings=1)
        bad_ref = c.ArtifactRef("b", ref.sha256)
    reader = inputs.BoundedInputReader(root, bad_settings)
    if kind != "artifact":
        reader.read(ref)
    if kind == "bindings":
        assert_failure(lambda: reader.read(bad_ref), c.ExportFailureReason.BOUND_EXCEEDED)
    else:
        assert reader.read(bad_ref) == payload
        reader.reprove()
        assert sum(item.size_bytes for item in reader.inventory) == (17 if kind == "artifact" else 34)


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


@pytest.mark.parametrize("operation", ["start", "review", "gate"])
def test_deadline_is_checked_at_start_and_after_upstream_verifier(tmp_path, monkeypatch, operation):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    now = [0.0]
    monkeypatch.setattr(inputs.time, "monotonic", lambda: now[0])
    if operation == "start":
        reader = inputs.BoundedInputReader(disk.root, disk.settings, deadline=0.0)
        assert_failure(lambda: reader.read(c.ArtifactRef(**disk.gate_ref)), c.ExportFailureReason.TIMED_OUT)
    else:
        name = "load_accepted_review" if operation == "review" else "load_accepted_gate"
        original = getattr(inputs, name)

        def expire(*args, **kwargs):
            now[0] = disk.settings.timeout_seconds + 1.0
            return original(*args, **kwargs)

        monkeypatch.setattr(inputs, name, expire)
        assert_failure(disk.verify, c.ExportFailureReason.TIMED_OUT)


@pytest.mark.parametrize("acquisition", [None, "https://example.test/repository", "git@example.test:private/repository"])
def test_automatic_identity_needs_no_repository_setup_or_publication_claim(tmp_path, monkeypatch, acquisition):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, settings=OpenVexExportSettings(), acquisition=acquisition)
    verified = disk.verify()
    assert verified.source.repository_iri == c.snapshot_repository_iri(disk.snapshot)
    assert verified.source.repository_identity_basis == c.RepositoryIdentityBasis.SOURCE_SNAPSHOT
    assert verified.source.target_snapshot == disk.snapshot
    assert (verified.source.acquisition is not None) is (acquisition is not None)
    assert any("no repository publisher" in value for value in verified.source.qualifications)
    assert "private/repository" not in repr(verified.source)
    inputs.reprove_inputs(disk.root, verified, disk.settings, ROOT)


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


@pytest.mark.parametrize("overrides", [{"max_document_bytes": 1}, {"max_bindings": 1}])
def test_real_verification_preserves_binding_limits_without_input_byte_rejection(tmp_path, monkeypatch, overrides):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, settings=enabled_settings(**overrides))
    if "max_bindings" in overrides:
        assert_failure(disk.verify, c.ExportFailureReason.BOUND_EXCEEDED)
        assert disk.calls == []
    else:
        verified = disk.verify()
        assert verified.total_input_bytes > disk.settings.max_document_bytes
        assert len(verified.findings) == 1
        assert disk.calls


def test_configuration_manifest_cannot_repoint_frozen_resolved_bytes(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.put(disk.config_manifest_ref["path"], {"resolved_sha256": c.json_sha256("different configuration")})
    assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)


def test_rehashed_configuration_is_still_pinned_by_accepted_job_handoffs(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.resolved["configuration_profile"]["name"] = "changed profile"
    reference = disk.put(disk.config_ref["path"], disk.resolved)
    disk.put(disk.config_manifest_ref["path"], {"resolved_sha256": reference["sha256"]})
    error = assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)
    assert isinstance(error.__cause__, ValueError)


def test_rehashed_review_settings_cannot_disagree_with_semantic_review_hash(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    disk.resolved["jobs"][inputs.REVIEW_JOB]["settings"]["rounds"]["stable_rounds_required"] += 1
    disk.resolved["jobs"][inputs.REVIEW_JOB]["settings"]["rounds"]["max_rounds"] += 1
    reference = disk.put(disk.config_ref["path"], disk.resolved)
    disk.put(disk.config_manifest_ref["path"], {"resolved_sha256": reference["sha256"]})
    disk.review_handoff["resolved_config_sha256"] = reference["sha256"]
    disk.gate_handoff["resolved_config_sha256"] = reference["sha256"]
    disk.review_job_ref = disk.publish(inputs.REVIEW_JOB, disk.review_handoff)
    disk.authority["inputs"]["job_handoff"] = disk.review_job_ref
    updates = {ref["path"]: ref for ref in (reference, disk.review_job_ref)}
    disk.authority["bindings"] = [updates.get(ref["path"], ref) for ref in disk.authority["bindings"]]
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
    reference = disk.put(disk.gate_job_ref["path"], disk.gate_handoff)
    disk.put(f"data/jobs/{inputs.GATE_JOB}/latest.json",
             {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
    assert_failure(disk.verify, c.ExportFailureReason.SCHEMA_INVALID)


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
    if field == "source_fingerprint":
        disk.publish(inputs.GATE_JOB, disk.gate_handoff)
        error = assert_failure(disk.verify, c.ExportFailureReason.INPUT_TAMPERED)
        assert "evidence identity" in str(error.__cause__)
    else:
        reference = disk.put(disk.gate_job_ref["path"], disk.gate_handoff)
        disk.put(f"data/jobs/{inputs.GATE_JOB}/latest.json",
                 {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
        error = assert_failure(disk.verify, c.ExportFailureReason.SCHEMA_INVALID)
        assert "contradictory handoff target identities" in str(error.__cause__.__cause__)


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


def test_admission_pointers_are_resolved_by_shared_reader_not_read_as_evidence(tmp_path, monkeypatch):
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
    assert not operational & {reference.path for reference in full_inventory}
    assert not operational & {reference.path for reference in verified.input_inventory}
    assert set(verified.input_inventory) == {reference for reference in full_inventory
                                           if reference.path not in operational}
    assert sum(reference.size_bytes for reference in full_inventory) == verified.total_input_bytes
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
def test_operational_pointer_bytes_remain_measured_and_binding_count_stays_bounded(tmp_path, pointer, bound):
    path = tmp_path / pointer
    path.parent.mkdir(parents=True)
    path.write_bytes(b"pointer")
    (tmp_path / "immutable.json").write_bytes(b"immutable")
    settings = enabled_settings(max_bindings=1 if bound == "bindings" else 2)
    reader = inputs.BoundedInputReader(tmp_path, settings)
    reader.pin(pointer)
    assert inputs._durable_inventory(reader.inventory) == ()
    if bound == "bindings":
        assert_failure(lambda: reader.pin("immutable.json"), c.ExportFailureReason.BOUND_EXCEEDED)
    else:
        reference = reader.pin("immutable.json")
        assert sum(item.size_bytes for item in reader.inventory) == 16
        assert inputs._durable_inventory(reader.inventory) == (reference,)


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



def _install_base_configuration_snapshot(run_root: Path, resolved: dict) -> dict[str, str]:
    source_bytes = b"# synthetic frozen configuration source\n"
    source_sha = hashlib.sha256(source_bytes).hexdigest()
    (run_root / "data/configuration/appsec-review.toml").write_bytes(source_bytes)
    resolved_bytes = c.canonical_bytes(resolved)
    resolved_sha = hashlib.sha256(resolved_bytes).hexdigest()
    (run_root / "data/configuration/resolved.json").write_bytes(resolved_bytes)
    manifest = {
        "schema": "appsec-review/run-configuration/2",
        "resolved_sha256": resolved_sha,
        "source_sha256": source_sha,
        "source_layers": [],
        "sources": [],
    }
    manifest_bytes = c.canonical_bytes(manifest)
    (run_root / "data/configuration/manifest.json").write_bytes(manifest_bytes)
    return {"path": "data/configuration/resolved.json", "sha256": resolved_sha}


def _install_operational_revision(
    run_root: Path,
    base_cfg: dict[str, Any],
    mutator: Any,
) -> dict[str, str]:
    """Ensure base configuration has a complete CONFIGURATION_SCHEMA snapshot and write a REVISION_SCHEMA snapshot."""
    from appsec_review.config.operational import operational_changes
    from appsec_review.runtime.configuration import (
        CONFIGURATION_SCHEMA,
        REVISION_SCHEMA,
        configuration_snapshot,
        configurations_compatible,
    )

    source_toml = b"[project]\nname = 'synthetic-test'\n"
    source_sha = hashlib.sha256(source_toml).hexdigest()
    base_bytes = (run_root / "data/configuration/resolved.json").read_bytes()
    base_sha = hashlib.sha256(base_bytes).hexdigest()
    base_dir = run_root / "data" / "configuration"
    if not (base_dir / "appsec-review.toml").is_file():
        (base_dir / "appsec-review.toml").write_bytes(source_toml)
    base_manifest = json.loads((base_dir / "manifest.json").read_bytes())
    if base_manifest.get("schema") != CONFIGURATION_SCHEMA or base_manifest.get("source_sha256") != source_sha:
        base_manifest.update(
            {
                "schema": CONFIGURATION_SCHEMA,
                "resolved_sha256": base_sha,
                "source_sha256": source_sha,
                "sources": base_manifest.get("sources", []),
                "source_layers": [],
            }
        )
        (base_dir / "manifest.json").write_bytes(c.canonical_bytes(base_manifest))

    rev_cfg = deepcopy(base_cfg)
    mutator(rev_cfg)
    rev_bytes = c.canonical_bytes(rev_cfg)
    rev_sha = hashlib.sha256(rev_bytes).hexdigest()
    assert rev_sha != base_sha

    changes = operational_changes(base_cfg, rev_cfg)
    assert changes, "expected at least one operational setting change"

    rev_dir = base_dir / "revisions" / rev_sha
    rev_dir.mkdir(parents=True, exist_ok=True)
    (rev_dir / "appsec-review.toml").write_bytes(source_toml)
    (rev_dir / "resolved.json").write_bytes(rev_bytes)
    rev_manifest = {
        "schema": REVISION_SCHEMA,
        "base_resolved_sha256": base_sha,
        "source_sha256": source_sha,
        "resolved_sha256": rev_sha,
        "resolved": {"path": "resolved.json", "sha256": rev_sha},
        "sources": [],
        "source_layers": [],
        "operational_changes": changes,
    }
    (rev_dir / "manifest.json").write_bytes(c.canonical_bytes(rev_manifest))
    snap = configuration_snapshot(run_root, rev_sha)
    assert snap.sha256 == rev_sha
    assert configurations_compatible(run_root, base_sha, rev_sha)
    return {
        "path": f"data/configuration/revisions/{rev_sha}/resolved.json",
        "sha256": rev_sha,
    }


def test_hash_only_artifacts_stream_through_verify_without_retaining_bytes_and_json_enforces_byte_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hash-only artifacts must stream through BoundedInputReader.verify() without calling read()."""
    from appsec_review.jobs.job_openvex_export import reporting as openvex_reporting
    from appsec_review.retrieval.index import INDEX_SCHEMA, IndexBuilder, IndexIdentity, write_manifest
    from tests.handoff_fixture import write_fixture_handoff
    from tests.test_openvex_job_units import ExportUnits
    from tests.unit.job_openvex_export.test_dependency_publication import admitted, dependency, publish_export

    stream_dir = tmp_path / "run-stream-verify"
    stream_dir.mkdir()
    disk = AcceptedInputDisk(stream_dir, monkeypatch, acquisition="https://example.invalid/repo.git")
    shard_rel = "data/indices/source-default.sqlite"
    fingerprint = c.json_sha256("source-shard-fingerprint")
    builder = IndexBuilder(
        disk.root / shard_rel,
        name="source",
        fingerprint=fingerprint,
        target_snapshot=disk.snapshot,
        shard_id="default",
    )
    shard_sha = builder.build()
    shard_ref = {"path": shard_rel, "sha256": shard_sha}
    manifest_path = disk.root / "data/indices/source-manifest.json"
    write_manifest(
        manifest_path,
        run_id=disk.root.name,
        target_snapshot=disk.snapshot,
        target_root=disk.root,
        indexes=[
            IndexIdentity(
                name="source",
                schema=INDEX_SCHEMA,
                sha256=shard_sha,
                fingerprint=fingerprint,
                relative_path=shard_rel,
                producer={"job": "job_source_indexing"},
                shard_id="default",
            )
        ],
    )
    old_manifest_path = disk.manifest_ref["path"]
    disk.manifest_ref = {
        "path": "data/indices/source-manifest.json",
        "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    }
    review_shard_ref = disk.put("data/review/shards/ledger-0001.bin", b"R" * 4096)
    disk.scope["manifest_path"] = disk.manifest_ref["path"]
    disk.scope["manifest_sha256"] = disk.manifest_ref["sha256"]
    disk.scope["shards"] = [
        {"name": "source", "shard_id": "default", "path": shard_ref["path"], "sha256": shard_ref["sha256"]}
    ]
    disk.scope_ref = disk.put("data/review/scope.json", disk.scope)
    disk.review_handoff["outputs"]["scope.accept_manifest"]["artifact"] = disk.scope_ref
    disk.review["accepted_manifest_sha256"] = disk.manifest_ref["sha256"]
    disk.review["shards"] = [review_shard_ref]
    disk.authority["review"]["accepted_manifest_sha256"] = disk.manifest_ref["sha256"]
    disk.authority["bindings"] = [
        disk.scope_ref if ref["path"] == disk.scope_ref["path"]
        else (disk.manifest_ref if ref["path"] == old_manifest_path else ref)
        for ref in disk.authority["bindings"]
    ] + [review_shard_ref, shard_ref]
    disk.refresh_review()
    _, dep_accepted = dependency(disk)

    read_paths: list[str] = []
    verify_paths: list[str] = []
    orig_read = inputs.BoundedInputReader.read
    orig_verify = inputs.BoundedInputReader.verify

    def spy_read(self: inputs.BoundedInputReader, raw_path: Any, *args: Any, **kwargs: Any) -> bytes:
        read_paths.append(raw_path.path if hasattr(raw_path, "path") else str(raw_path))
        return orig_read(self, raw_path, *args, **kwargs)

    def spy_verify(self: inputs.BoundedInputReader, raw_path: Any, *args: Any, **kwargs: Any) -> Path:
        verify_paths.append(raw_path.path if hasattr(raw_path, "path") else str(raw_path))
        return orig_verify(self, raw_path, *args, **kwargs)

    monkeypatch.setattr(inputs.BoundedInputReader, "read", spy_read)
    monkeypatch.setattr(inputs.BoundedInputReader, "verify", spy_verify)

    units = ExportUnits(disk)
    with admitted(disk, dep_accepted):
        units.assemble()
        units.execute("acceptance.publish_handoff")
    publish_export(disk, units, accepted=dep_accepted)

    report_view = openvex_reporting.load_export(disk.root, disk.settings, ROOT, exporter_release=units.release)
    assert report_view.state == c.ExportReportState.AVAILABLE

    hash_only_targets = {
        shard_ref["path"],
        review_shard_ref["path"],
        disk.ledger_ref["path"],
        *(ref["path"] for ref in disk.lane_package_refs.values()),
        *(row["path"] for row in disk.authority["packages"]),
        *(f"data/review/scoring/scores/{s['score_id']}.json" for row in disk.authority["packages"] for s in row["scores"]),
        "data/jobs/job_openvex_export/latest.json",
    }
    assert hash_only_targets <= set(verify_paths)
    assert hash_only_targets.isdisjoint(set(read_paths))

    oversized_ref = c.ArtifactRef.from_mapping(
        disk.put("data/review/oversized.json", b"[" + (b"1," * 2048) + b"1]")
    )
    small_settings = replace(disk.settings, max_manifest_bytes=1024, max_document_bytes=1024)
    small_reader = inputs.BoundedInputReader(disk.root, small_settings)
    monkeypatch.setattr(inputs, "_MIN_JSON_INPUT_BYTES", 1024)
    with pytest.raises(c.ExportError) as exc_info:
        small_reader.json(oversized_ref)
    assert exc_info.value.reason == c.ExportFailureReason.BOUND_EXCEEDED


def test_decision_audit_accepts_operational_configuration_revision_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    """decision_audit must verify operational configuration revisions and reject tampered revision manifests."""
    from appsec_review.review.models import IntegrityError
    from appsec_review.storage import atomic_json, file_sha256
    from tests.handoff_fixture import write_fixture_handoff
    from tests.unit.review_decision_audit_consumers.helpers import Fixture as AuditFixture

    audit_dir = tmp_path / "audit-rev"
    audit_dir.mkdir()
    audit_fx = AuditFixture(audit_dir)
    audit_fx.config["jobs"]["job_inference_security_review"]["settings"]["attack_chains"] = {"max_links": 4}
    base_audit_ref = audit_fx.write("data/configuration/resolved.json", audit_fx.config, pin=False)
    audit_fx.write("data/configuration/manifest.json", {"resolved_sha256": base_audit_ref["sha256"]}, pin=False)
    rev_audit = _install_operational_revision(
        audit_fx.root,
        audit_fx.config,
        lambda cfg: cfg["jobs"]["job_inference_security_review"]["settings"]["attack_chains"].update({"max_links": 8}),
    )
    audit_fx.origin = replace(audit_fx.origin, configuration_sha256=rev_audit["sha256"])
    audit_fx.publish(products=())
    review_handoff_path = audit_fx.root / audit_fx.attempt / "handoff.json"
    (review_handoff_path.parent / "result.json").unlink(missing_ok=True)
    write_fixture_handoff(
        audit_fx.root,
        review_handoff_path,
        {
            "job_id": inputs.REVIEW_JOB,
            "target_snapshot": "target-1",
            "outputs": audit_fx.outputs,
            "artifacts": list(audit_fx.artifacts.values()),
            "resolved_config_sha256": rev_audit["sha256"],
        },
        target_snapshot="target-1",
        configuration_sha256=rev_audit["sha256"],
    )
    atomic_json(
        review_handoff_path.parent.parent.parent / "latest.json",
        {
            "handoff_path": review_handoff_path.relative_to(audit_fx.root).as_posix(),
            "handoff_sha256": file_sha256(review_handoff_path),
        },
    )
    accepted_audit = audit_fx.load()
    assert accepted_audit.manifest is not None and accepted_audit.unavailable_reason is None

    from appsec_review.indexing.store import accepted_handoff
    from appsec_review.review.decision_audit.reader import verify_decision_audit

    prior_accepted = accepted_handoff(audit_fx.root, inputs.REVIEW_JOB)
    published = prior_accepted.handoff["outputs"]["publication.publish_handoff"]
    rev_manifest_path = audit_fx.root / f"data/configuration/revisions/{rev_audit['sha256']}/manifest.json"
    tampered_manifest = json.loads(rev_manifest_path.read_bytes())
    tampered_manifest["operational_changes"] = []
    rev_manifest_path.write_bytes(c.canonical_bytes(tampered_manifest))
    with pytest.raises(IntegrityError, match="configuration snapshot failed verification"):
        verify_decision_audit(
            audit_fx.root,
            accepted=prior_accepted,
            published=published,
            review=json.loads((audit_fx.root / published["artifact"]["path"]).read_bytes()),
            scope=json.loads((audit_fx.root / prior_accepted.handoff["outputs"]["scope.accept_manifest"]["artifact"]["path"]).read_bytes()),
            projection=audit_fx.projection,
            projection_ref=audit_fx.projection_ref,
            findings=((audit_fx.finding_ref, audit_fx.finding),),
        )



def test_openvex_chain_accepts_compatible_operational_configuration_revisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Compatible operational configuration revisions across review -> gate -> dependencies -> openvex must succeed."""
    from appsec_review.jobs.job_openvex_export import metrics as openvex_metrics
    from appsec_review.jobs.job_openvex_export import reporting as openvex_reporting
    from tests.handoff_fixture import write_fixture_handoff
    from tests.test_openvex_job_units import ExportUnits
    from tests.unit.job_openvex_export.test_dependency_publication import admitted, dependency

    openvex_dir = tmp_path / "openvex-rev"
    openvex_dir.mkdir()
    disk = AcceptedInputDisk(openvex_dir, monkeypatch, acquisition="https://example.invalid/repo.git")
    units = ExportUnits(disk)
    base_cfg = json.loads((disk.root / "data/configuration/resolved.json").read_bytes())
    rev_review = _install_operational_revision(
        disk.root,
        base_cfg,
        lambda cfg: cfg["jobs"]["job_inference_security_review"]["settings"]["attack_chains"].update(
            {"max_links": int(cfg["jobs"]["job_inference_security_review"]["settings"]["attack_chains"]["max_links"]) + 2}
        ),
    )
    rev_gate = _install_operational_revision(
        disk.root,
        base_cfg,
        lambda cfg: cfg["jobs"]["job_final_publication_gate"]["settings"].update(
            {"max_packages": int(cfg["jobs"]["job_final_publication_gate"]["settings"]["max_packages"]) + 50}
        ),
    )
    rev_deps = _install_operational_revision(
        disk.root,
        base_cfg,
        lambda cfg: cfg["jobs"]["job_dependency_intelligence"]["settings"].update(
            {"max_advisories": int(cfg["jobs"]["job_dependency_intelligence"]["settings"]["max_advisories"]) + 25}
        ),
    )
    rev_openvex = _install_operational_revision(
        disk.root,
        base_cfg,
        lambda cfg: cfg["jobs"]["job_openvex_export"]["settings"].update(
            {"timeout_seconds": int(cfg["jobs"]["job_openvex_export"]["settings"]["timeout_seconds"]) + 45}
        ),
    )

    from appsec_review.config.inference_review import parse_inference_review_settings, semantic_settings_sha256

    rev_review_doc = json.loads((disk.root / rev_review["path"]).read_bytes())
    disk.authority["review"]["configuration_sha256"] = semantic_settings_sha256(
        parse_inference_review_settings(rev_review_doc["jobs"][inputs.REVIEW_JOB]["settings"])
    )
    disk.review_handoff["resolved_config_sha256"] = rev_review["sha256"]
    disk.review_job_ref = disk.publish(
        inputs.REVIEW_JOB,
        disk.review_handoff,
        configuration_sha256=rev_review["sha256"],
    )
    disk.authority["inputs"]["job_handoff"] = disk.review_job_ref
    disk.authority["bindings"] = [
        disk.review_job_ref if ref["path"] == disk.review_job_ref["path"]
        else (rev_gate if ref["path"] == disk.config_ref["path"] else ref)
        for ref in disk.authority["bindings"]
    ]
    disk.publish_gate()
    disk.gate_handoff["resolved_config_sha256"] = rev_gate["sha256"]
    disk.gate_job_ref = disk.publish(inputs.GATE_JOB, disk.gate_handoff, configuration_sha256=rev_gate["sha256"])

    _, dep_accepted = dependency(disk)
    dep_handoff_path = disk.root / dep_accepted["path"]
    dep_handoff = json.loads(dep_handoff_path.read_bytes())
    dep_handoff["resolved_config_sha256"] = rev_deps["sha256"]
    write_fixture_handoff(
        disk.root,
        dep_handoff_path,
        dep_handoff,
        target_snapshot=disk.snapshot,
        configuration_sha256=rev_deps["sha256"],
    )
    dep_accepted = {
        "path": dep_accepted["path"],
        "sha256": hashlib.sha256(dep_handoff_path.read_bytes()).hexdigest(),
    }
    disk.put(
        f"data/jobs/{dep_handoff['job_id']}/latest.json",
        {"handoff_path": dep_accepted["path"], "handoff_sha256": dep_accepted["sha256"]},
    )

    rev_openvex_settings = replace(disk.settings, timeout_seconds=disk.settings.timeout_seconds + 45)
    units.context = replace(
        units.context,
        resolved_config_sha256=rev_openvex["sha256"],
        config=replace(units.context.config, settings=rev_openvex_settings.to_mapping(), typed_settings=rev_openvex_settings),
    )
    with admitted(disk, dep_accepted):
        units.assemble()
        units.execute("acceptance.publish_handoff")
    export_handoff = disk.handoff(c.JOB_ID, deepcopy(units.outputs))
    export_handoff.update(
        {
            "attempt_id": units.context.attempt_id,
            "completion_status": units.outputs["acceptance.publish_handoff"]["terminal_status"],
            "schema_identity": c.OPENVEX_EXPORT_HANDOFF_SCHEMA,
            "implementation_identity": units.implementation_identity,
            "resolved_config_sha256": rev_openvex["sha256"],
            "upstream_handoff_sha256": {
                inputs.GATE_JOB: disk.gate_job_ref["sha256"],
                inputs.REVIEW_JOB: disk.review_job_ref["sha256"],
                dep_handoff["job_id"]: dep_accepted["sha256"],
            },
        }
    )
    export_ref = c.ArtifactRef.from_mapping(
        disk.publish(c.JOB_ID, export_handoff, configuration_sha256=rev_openvex["sha256"])
    )
    published_handoff = json.loads((disk.root / export_ref.path).read_bytes())
    assert published_handoff["resolved_config_sha256"] == rev_openvex["sha256"]

    report_view = openvex_reporting.load_export(disk.root, disk.settings, ROOT, exporter_release=units.release)
    assert report_view.state == c.ExportReportState.AVAILABLE

    cfg_settings, cfg_release = openvex_metrics._configuration(disk.root, expected_sha256=rev_openvex["sha256"])
    assert cfg_settings.timeout_seconds == rev_openvex_settings.timeout_seconds
    assert isinstance(cfg_release, str)


def test_final_report_schema_sha256_pins_stay_in_sync_across_report_and_openvex_contracts() -> None:
    """Both job_final_report_publication and job_openvex_export must pin identical SHA-256 digests for final-report schemas."""
    from appsec_review.jobs.job_final_report_publication.contracts import FINAL_REPORT_SCHEMA_SHA256
    from appsec_review.jobs.job_openvex_export.contracts import SCHEMA_SHA256

    schema_dir = ROOT / "docs" / "schemas" / "final-report"
    on_disk = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(schema_dir.glob("*.json"))}
    assert dict(FINAL_REPORT_SCHEMA_SHA256) == on_disk
    assert SCHEMA_SHA256["../final-report/final-report.schema.json"] == FINAL_REPORT_SCHEMA_SHA256["final-report.schema.json"]
    assert SCHEMA_SHA256["../final-report/final-report.schema.json"] == on_disk["final-report.schema.json"]
