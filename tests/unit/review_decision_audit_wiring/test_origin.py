from copy import deepcopy
from dataclasses import replace
import json
import os

import pytest

from appsec_review.jobs.job_inference_security_review.audit import trusted_origin
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.metadata import policy_document
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.release import MAX_MANIFEST_BYTES

from .helpers import ATTEMPT, HASH, change_json, context_fixture, put


@pytest.mark.parametrize("mode", ["enabled", "disabled", "absent"])
def test_origin_uses_full_frozen_configuration_and_independent_attempt(mode, tmp_path):
    f = context_fixture(tmp_path, enabled=mode == "enabled", absent=mode == "absent")
    origin, reference = trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)
    assert reference == f.config_ref
    assert origin.configuration_sha256 == f.claim["resolved_config_sha256"]
    assert origin.configuration_sha256 != f.handoff["configuration_sha256"]
    assert origin.review_handoff_sha256 == f.handoff_ref["sha256"]
    assert origin.review_attempt_id == f.unit.job.attempt_id
    assert origin.target_snapshot == f.scope.target_snapshot
    assert origin.projection_sha256 == f.outputs["publication.publish_claim_ledger"]["projection"]["sha256"]
    assert origin.ledger_head_sha256 == f.handoff["ledger_head_sha256"]
    assert origin.guidance_sha256 == origin.implementation_sha256 == c.HashLink(None, c.AbsenceReason.NOT_PRODUCED)
    assert origin.projection_policy_sha256 == policy_document(f.settings)["sha256"]
    assert f.settings.enabled is (mode == "enabled")


@pytest.mark.parametrize("field,value", [
    ("schema", "foreign/1"), ("run_id", "foreign"), ("job_id", "job_foreign"),
    ("attempt_id", "attempt_0002"), ("attempt_path", "foreign"), ("repository_root", "foreign"),
    ("source_fingerprint", "foreign"), ("upstream_handoffs", {"foreign": HASH}),
    ("evidence_target_snapshot", "foreign"), ("input_manifest_path", "foreign"),
    ("input_manifest_sha256", "0" * 64), ("resolved_config_sha256", "0" * 64),
])
def test_claim_cannot_override_trusted_context(tmp_path, field, value):
    f = context_fixture(tmp_path)
    put(f.root, ATTEMPT + "/claim.json", {**f.claim, field: value})
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("field,value", [
    ("run_id", "foreign"), ("attempt_id", "attempt_0002"), ("source_fingerprint", "foreign"),
    ("evidence_target_snapshot", "foreign"), ("input_manifest_sha256", "0" * 64),
    ("input_manifest_path", None),
])
def test_live_context_cannot_disagree_with_the_claim(tmp_path, field, value):
    f = context_fixture(tmp_path)
    unit = replace(f.unit, job=replace(f.unit.job, **{field: value}))
    with pytest.raises(IntegrityError):
        trusted_origin(unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("change", ["run-root", "attempt-root", "job-id", "scope-run", "scope-target",
                                   "scope-root", "scope-manifest", "linked-root", "linked-claim-parent"])
def test_foreign_context_and_path_custody(tmp_path, change):
    f = context_fixture(tmp_path)
    if change == "run-root":
        f.unit = replace(f.unit, job=replace(f.unit.job, run_root=tmp_path))
    elif change == "attempt-root":
        f.unit = replace(f.unit, job=replace(f.unit.job, attempt_root=f.root / "other"))
    elif change == "job-id":
        f.unit = replace(f.unit, job=replace(f.unit.job, config=replace(f.unit.job.config, job_id="job_other")))
    elif change == "linked-root":
        linked = tmp_path / "linked"
        linked.symlink_to(f.root, target_is_directory=True)
        f.unit = replace(f.unit, job=replace(f.unit.job, run_root=linked))
    elif change == "linked-claim-parent":
        attempt = f.unit.job.attempt_root
        moved = attempt.with_name("moved")
        attempt.rename(moved)
        attempt.symlink_to(moved, target_is_directory=True)
    else:
        changes = {
            "scope-run": {"run_id": "foreign"}, "scope-target": {"target_snapshot": "foreign"},
            "scope-root": {"run_root": tmp_path}, "scope-manifest": {"manifest_sha256": "0" * 64},
        }[change]
        f.scope = replace(f.scope, **changes)
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("change", ["resolved-bytes", "manifest-bytes", "frozen-settings",
                                   "frozen-policy", "typed-policy", "invalid-policy", "missing-jobs"])
def test_configuration_and_policy_are_not_self_attested(tmp_path, change):
    f = context_fixture(tmp_path)
    if change == "resolved-bytes":
        (f.root / f.config_ref["path"]).write_bytes(b"{}")
    elif change == "manifest-bytes":
        put(f.root, "data/configuration/manifest.json", {"resolved_sha256": "0" * 64})
    elif change == "typed-policy":
        f.settings = replace(f.settings, max_records=1)
    else:
        frozen = deepcopy(f.frozen)
        table = frozen["jobs"][f.unit.job.config.job_id]["settings"]
        if change == "missing-jobs":
            frozen.pop("jobs")
        elif change == "frozen-settings":
            table["lanes"]["incomplete_gap_ratio"] = .9
        else:
            table["decision_audit"]["max_records"] = True if change == "invalid-policy" else 1
            # The raw table may agree with its config object; the typed policy still must agree.
            f.unit = replace(f.unit, job=replace(f.unit.job, config=replace(f.unit.job.config, settings=table)))
        config_ref = put(f.root, f.config_ref["path"], frozen)
        put(f.root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
        put(f.root, ATTEMPT + "/claim.json", {**f.claim, "resolved_config_sha256": config_ref["sha256"]})
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("field,value", [
    ("schema", "wrong/1"), ("run_id", "foreign"), ("target_snapshot", "foreign"),
    ("manifest_sha256", "0" * 64), ("manifest_path", "foreign"),
])
def test_scope_control_artifact_must_match_the_actual_accepted_scope(tmp_path, field, value):
    f = context_fixture(tmp_path)
    f.outputs["scope.accept_manifest"]["artifact"] = change_json(
        f.root, f.outputs["scope.accept_manifest"]["artifact"], **{field: value})
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("field,value", [
    ("schema", "wrong/1"), ("run_id", "foreign"), ("accepted_manifest_sha256", "0" * 64),
    ("configuration_sha256", "0" * 64), ("ledger_head_sha256", "0" * 64), ("projection_sha256", "0" * 64),
    ("package_manifest_sha256", "0" * 64), ("lead_package_manifest_sha256", "0" * 64),
])
def test_original_handoff_cannot_rebind_original_anchors(tmp_path, field, value):
    f = context_fixture(tmp_path)
    ref = change_json(f.root, f.handoff_ref, **{field: value})
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, ref, f.settings)


@pytest.mark.parametrize("anchor", ["scope", "handoff", "lead-packages", "hunt-packages"])
@pytest.mark.parametrize("change", ["tamper", "foreign-attempt", "symlink"])
def test_anchor_hashes_and_custody_are_checked(tmp_path, anchor, change):
    f = context_fixture(tmp_path)
    ref = (f.outputs["scope.accept_manifest"]["artifact"] if anchor == "scope" else
           f.handoff_ref if anchor == "handoff" else
           f.outputs[f"packages.assemble_{anchor.split('-')[0]}_packages"]["artifact"])
    path = f.root / ref["path"]
    if change == "tamper":
        path.write_bytes(b"{}")
    elif change == "symlink":
        other = path.with_name("other.json")
        path.rename(other)
        path.symlink_to(other)
    else:
        new_ref = put(f.root, "data/foreign/anchor.json", path.read_bytes())
        ref.update(new_ref)
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("change", ["missing", "malformed", "nonobject", "oversize", "duplicate-configuration"])
def test_control_inputs_fail_closed_not_as_successful_unavailable(tmp_path, change):
    f = context_fixture(tmp_path)
    path = f.unit.job.attempt_root / "claim.json"
    if change == "missing":
        path.unlink()
    elif change == "malformed":
        path.write_bytes(b"{")
    elif change == "nonobject":
        path.write_bytes(b"[]")
    elif change == "oversize":
        path.write_bytes(b" " * (MAX_MANIFEST_BYTES + 1))
    else:
        payload = b'{"jobs":{},"jobs":{}}'
        config_ref = put(f.root, f.config_ref["path"], payload)
        put(f.root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
        put(f.root, ATTEMPT + "/claim.json", {**f.claim, "resolved_config_sha256": config_ref["sha256"]})
    with pytest.raises(IntegrityError):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


def test_legacy_target_anchor_uses_actual_source_fingerprint(tmp_path):
    f = context_fixture(tmp_path)
    f.claim.pop("evidence_target_snapshot")
    put(f.root, ATTEMPT + "/claim.json", f.claim)
    unit = replace(f.unit, job=replace(f.unit.job, evidence_target_snapshot=None))
    origin, _ = trusted_origin(unit, f.scope, f.handoff_ref, f.settings)
    assert origin.target_snapshot == f.unit.job.source_fingerprint
    assert json.loads((f.root / f.handoff_ref["path"]).read_bytes()) == f.handoff


@pytest.mark.parametrize("lane", ["lead", "hunt"])
@pytest.mark.parametrize("field,value", [
    ("schema", "foreign/1"), ("lane", "other"), ("package_manifest_content_sha256", "0" * 64)])
def test_original_package_set_identity_is_reverified(tmp_path, lane, field, value):
    f = context_fixture(tmp_path)
    output = f.outputs[f"packages.assemble_{lane}_packages"]
    output["artifact"] = change_json(f.root, output["artifact"], **{field: value})
    with pytest.raises(IntegrityError, match="package set"):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)


@pytest.mark.parametrize("anchor", ["claim", "configuration"])
def test_control_anchor_cannot_be_a_fifo(tmp_path, anchor):
    f = context_fixture(tmp_path)
    path = f.root / (ATTEMPT + "/claim.json" if anchor == "claim" else "data/configuration/manifest.json")
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(IntegrityError, match="regular file"):
        trusted_origin(f.unit, f.scope, f.handoff_ref, f.settings)
