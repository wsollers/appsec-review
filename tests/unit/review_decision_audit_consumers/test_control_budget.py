from pathlib import Path
import os

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.review.decision_audit.reader import AuditBoundExceeded, REVIEW_JOB, verify_decision_audit
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.contracts import InputRequirement, JobContract
from appsec_review.runtime.inputs import input_read_scope
from types import SimpleNamespace

from .helpers import Fixture


def fixture_with_small_payload_budget(tmp_path, reason="capacity_exceeded"):
    settings = DecisionAuditSettings(enabled=reason != "disabled", max_input_bytes=4096, shard_bytes=4096,
                                      page_size=2, max_page_size=3)
    fixture = Fixture(tmp_path, settings=settings, config_padding_bytes=5000)
    fixture.publish(reason=reason)
    return fixture


def verified_inputs(fixture):
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    published = accepted.handoff["outputs"]["publication.publish_handoff"]
    return {
        "accepted": accepted, "published": published,
        "review": read_bound_json(fixture.root, published["artifact"]),
        "scope": read_bound_json(fixture.root, accepted.handoff["outputs"]["scope.accept_manifest"]["artifact"]),
        "projection": read_bound_json(fixture.root, fixture.projection_ref), "projection_ref": fixture.projection_ref,
        "findings": ((fixture.finding_ref, read_bound_json(fixture.root, fixture.finding_ref)),),
    }


def forbid_payload_opens(monkeypatch):
    """Observe the real reader's filesystem boundary, after common acceptance verification."""
    opened = []
    original = os.open

    def checked(path, *args, **kwargs):
        name = Path(path).name
        assert name != "manifest.json" and not name.endswith(".jsonl"), "unavailable audit opened a payload"
        opened.append(name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked)
    return opened


@pytest.mark.parametrize("reason", ["disabled", "capacity_exceeded", "input_unavailable"])
def test_unavailable_small_payload_budget_verifies_control_and_never_opens_payload(tmp_path, monkeypatch, reason):
    fixture = fixture_with_small_payload_budget(tmp_path, reason)
    arguments = verified_inputs(fixture)
    opened = forbid_payload_opens(monkeypatch)
    audit = verify_decision_audit(fixture.root, **arguments)
    assert not audit.available and audit.unavailable_reason == reason
    assert audit.settings == fixture.settings
    assert audit.settings.max_input_bytes == 4096 and audit.settings.max_page_size == 3
    assert audit.records == audit.continuations == ()
    assert audit.manifest is audit.reference is None
    assert sum(row.byte_count for row in audit.reads) > audit.settings.max_input_bytes
    expected = {fixture.audit_root + "/publication.json", "data/configuration/resolved.json",
                fixture.review_ref["path"], fixture.projection_ref["path"], fixture.scope_ref["path"]}
    assert {row.path for row in audit.reads} == expected
    assert {"publication.json", "resolved.json", "review.json", "projection.json", "scope.json"} <= set(opened)


def test_available_same_small_budget_still_charges_bootstrap_before_payload(tmp_path, monkeypatch):
    fixture = fixture_with_small_payload_budget(tmp_path, None)
    arguments = verified_inputs(fixture)
    opened = forbid_payload_opens(monkeypatch)
    with pytest.raises(AuditBoundExceeded, match="control bootstrap"):
        verify_decision_audit(fixture.root, **arguments)
    assert "scope.json" in opened


def test_available_budget_includes_original_anchors_not_just_metadata_and_configuration(tmp_path, monkeypatch):
    probe = Fixture(tmp_path / "sizing", settings=DecisionAuditSettings(enabled=True, shard_bytes=4096))
    control_names = (probe.audit_root + "/publication.json", "data/configuration/resolved.json")
    budget = max(4096, sum((probe.root / name).stat().st_size for name in control_names) + 256)
    fixture = Fixture(tmp_path / "bounded", settings=DecisionAuditSettings(
        enabled=True, max_input_bytes=budget, shard_bytes=4096))
    sizes = {name: (fixture.root / name).stat().st_size for name in (
        fixture.audit_root + "/publication.json", "data/configuration/resolved.json",
        fixture.review_ref["path"], fixture.projection_ref["path"], fixture.scope_ref["path"])}
    assert sizes[fixture.audit_root + "/publication.json"] + sizes["data/configuration/resolved.json"] <= budget
    assert sum(sizes.values()) > budget
    arguments = verified_inputs(fixture)
    forbid_payload_opens(monkeypatch)
    with pytest.raises(AuditBoundExceeded, match="control bootstrap"):
        verify_decision_audit(fixture.root, **arguments)


@pytest.mark.parametrize("mutation", [
    "schema", "extra-field", "status", "reason", "manifest", "policy",
    "foreign-run", "foreign-attempt", "foreign-target", "foreign-configuration",
])
def test_unavailable_is_strictly_validated_even_when_controls_exceed_payload_budget(tmp_path, mutation):
    fixture = fixture_with_small_payload_budget(tmp_path)

    def change(document):
        if mutation == "schema":
            document["schema"] = "unknown"
        elif mutation == "extra-field":
            document["unexpected"] = True
        elif mutation == "status":
            document["status"] = "unknown"
        elif mutation == "reason":
            document["unavailable_reason"] = "legacy_unrecorded"
        elif mutation == "manifest":
            document["manifest"] = fixture.reference.to_dict()
        elif mutation == "policy":
            document["policy"]["sha256"] = "a" * 64
        else:
            field, value = {
                "foreign-run": ("run_id", "foreign-run"),
                "foreign-attempt": ("review_attempt_id", "attempt_9999"),
                "foreign-target": ("target_snapshot", "foreign-target"),
                "foreign-configuration": ("configuration_sha256", "a" * 64),
            }[mutation]
            document["origin"][field] = value

    fixture.publish(reason="capacity_exceeded", mutate_metadata=change)
    with pytest.raises(IntegrityError, match="publication|origin|policy") as caught:
        fixture.load()
    assert not isinstance(caught.value, AuditBoundExceeded)


@pytest.mark.parametrize("artifact", ["metadata", "review", "projection", "scope", "configuration"])
def test_unavailable_does_not_bypass_tampered_control_or_original_anchor_pins(tmp_path, monkeypatch, artifact):
    fixture = fixture_with_small_payload_budget(tmp_path)
    arguments = verified_inputs(fixture)
    name = {
        "metadata": fixture.audit_root + "/publication.json", "review": fixture.review_ref["path"],
        "projection": fixture.projection_ref["path"], "scope": fixture.scope_ref["path"],
        "configuration": "data/configuration/resolved.json",
    }[artifact]
    target = fixture.root / name
    target.write_bytes(target.read_bytes() + b" ")
    forbid_payload_opens(monkeypatch)
    with pytest.raises(IntegrityError, match="hash changed") as caught:
        verify_decision_audit(fixture.root, **arguments)
    assert not isinstance(caught.value, AuditBoundExceeded)


def test_unavailable_control_retains_symlink_custody_and_runtime_permissions(tmp_path, monkeypatch):
    fixture = fixture_with_small_payload_budget(tmp_path)
    arguments = verified_inputs(fixture)
    context = SimpleNamespace(run_root=fixture.root, config=SimpleNamespace(job_id="job_poc_generation"),
        upstream_handoffs={REVIEW_JOB: arguments["accepted"].sha256},
        contract=JobContract(inputs=(InputRequirement(REVIEW_JOB, "handoff", "appsec-review/job-handoff/2"),)))
    with pytest.raises(ValueError, match="undeclared consumption.*review_audit_metadata"):
        with input_read_scope(context):
            verify_decision_audit(fixture.root, **arguments)
    metadata = fixture.root / fixture.audit_root / "publication.json"
    copied = metadata.with_name("descriptor-copy.json")
    copied.write_bytes(metadata.read_bytes())
    metadata.unlink()
    metadata.symlink_to(copied)
    forbid_payload_opens(monkeypatch)
    with pytest.raises(IntegrityError, match="custody"):
        verify_decision_audit(fixture.root, **arguments)


def test_unavailable_bootstrap_keeps_the_fixed_default_hard_limit(tmp_path, monkeypatch):
    hard_limit = DecisionAuditSettings().max_input_bytes
    assert hard_limit == 64 * 1024 * 1024
    fixture = Fixture(tmp_path, settings=DecisionAuditSettings(
        enabled=True, max_input_bytes=4096, shard_bytes=4096), config_padding_bytes=hard_limit)
    fixture.publish(reason="capacity_exceeded")
    arguments = verified_inputs(fixture)
    assert (fixture.root / "data/configuration/resolved.json").stat().st_size > hard_limit
    opened = forbid_payload_opens(monkeypatch)
    with pytest.raises(AuditBoundExceeded, match="max_input_bytes"):
        verify_decision_audit(fixture.root, **arguments)
    assert "resolved.json" in opened and "review.json" not in opened
