"""T-5008 stage 4: the optional, recorded collation model pass with a scripted transport.

Off by default; one bounded call per first-party component; every claim cites a supplied line or a
deterministic assignment. Local rejection/failure cases leave deterministic facets untouched;
the active-admission regressions in test_audit_semantics verify that global stops still propagate.
"""
from __future__ import annotations

import json

import pytest

from appsec_review.config.collation import CollationSettings, ModelPassSettings
from appsec_review.guidance import load_registry
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.guidance.workers import SPECIALIZED_WORKERS, worker_bundle
from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.job_security_tagging import job
from appsec_review.jobs.job_security_tagging.model_pass import PROPOSAL_SCHEMA, PURPOSES_SCHEMA, WORKER_ID
from appsec_review.review.dispositions import SourceDispositions

from .helpers import ROOT, CannedIndexes, scope, shard, unit_context
from .test_collation import HTTP_LOGIN, canned, settings as plain_settings

MODEL = {"enabled": True, "provider": "offline", "model": "fixture", "reasoning": "high", "max_input_tokens": 32768,
         "max_output_tokens": 4096, "timeout_seconds": 60, "retries": 0}


def settings(enabled: bool = True) -> CollationSettings:
    return CollationSettings(source_dispositions=SourceDispositions(vendored=("**/third_party/**",)),
                             model_pass=ModelPassSettings(enabled=enabled, max_excerpt_lines=40, model=MODEL))


class Scripted:
    """A transport double: it returns what the test scripts and records every request."""

    def __init__(self, proposal=None, *, error=None):
        self.proposal, self.error, self.calls = proposal, error, []

    def __call__(self, request, *, timeout_seconds):
        assert isinstance(request, ModelRequest) and timeout_seconds == 60
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        proposal = self.proposal(request) if callable(self.proposal) else self.proposal
        return ModelResult(proposal, input_tokens=10, output_tokens=5, served_model="fixture", served_provider="offline")


def handler(name, infer=None):
    return next(unit.handler for unit in job.build_job(infer=infer).units if unit.unit_id == name)


def run_pass(tmp_path, monkeypatch, infer, *, enabled=True, indexes=None):
    indexes = indexes or canned(("app/login.py", HTTP_LOGIN, "Python"))
    monkeypatch.setattr(job, "_indexes", lambda unit: indexes)
    monkeypatch.setattr(job, "_scope", lambda unit: scope())
    monkeypatch.setattr(job, "_collation_settings", lambda value: settings(enabled))
    loaded = handler("taxonomy.load_taxonomy")(unit_context(tmp_path, "taxonomy.load_taxonomy"))
    source_unit = unit_context(tmp_path, "collection.source_facts", {"taxonomy.load_taxonomy": loaded})
    source_result = handler("collection.source_facts")(source_unit)
    empty = {"artifact": job._write(source_unit, "empty.json", {"schema": "appsec-review/tag-assignment-set/1",
                                                                 "collector": "fixture", "assignments": [], "gaps": []})}
    outputs = {"taxonomy.load_taxonomy": loaded, "collection.source_facts": source_result,
               "collection.observation_facts": empty, "collection.coverage_gaps": empty}
    collate_unit = unit_context(tmp_path, job.COLLATION, outputs)
    outputs[job.COLLATION] = handler(job.COLLATION)(collate_unit)
    unit = unit_context(tmp_path, job.MODEL_PASS, outputs)
    result = handler(job.MODEL_PASS, infer)(unit)
    return unit, outputs, result


def valid_proposal(request):
    summary = request.summary
    cited = next(row for row in summary["excerpts"] if "verify_password" in row["text"])
    deterministic = next(item for item in summary["deterministic_facets"] if item["tag"] == "role:session")
    return {"schema": PROPOSAL_SCHEMA, "component_id": summary["component_id"], "role": ["role:auth", "role:session"],
            "asset": ["asset:credentials"], "purpose": "A login route that checks a password and keeps a session.",
            "claims": [{"tag": "role:auth", "citations": [{"path": cited["path"], "line": cited["line"]}]},
                       {"tag": "asset:credentials", "citations": [{"path": cited["path"], "line": cited["line"]}]},
                       {"tag": "role:session", "citations": [{"assignment_id": deterministic["assignment_id"]}]}],
            "unknown": []}


def test_disabled_pass_calls_no_model_and_publishes_a_disabled_record(tmp_path, monkeypatch) -> None:
    transport = Scripted(valid_proposal)
    unit, _outputs, result = run_pass(tmp_path, monkeypatch, transport, enabled=False)
    assert transport.calls == [] and result["item_count"] == 0 and result["gaps"] == []
    assert result["terminal_status"] == "SUCCEEDED" and result["mode"] == "disabled"
    document = job._read(unit, result["purposes"])
    assert document["schema"] == PURPOSES_SCHEMA and document["components"] == []
    assert job.TOPOLOGY["collation"] == ("collate_facets", "model_pass")


def test_accepted_proposal_adds_reported_facets_with_cited_evidence_and_records_the_purpose(tmp_path, monkeypatch) -> None:
    transport = Scripted(valid_proposal)
    unit, outputs, result = run_pass(tmp_path, monkeypatch, transport)
    assert len(transport.calls) == 1
    request = transport.calls[0]
    assert request.schema == PROPOSAL_SCHEMA and request.role == "unit_purpose_collator"
    assert request.allowed_components == ("component:app",) and request.allowed_paths == ("app/login.py",)
    assert len(request.summary["excerpts"]) <= 40
    assert all(set(row) == {"path", "line", "text"} and len(row["text"]) <= 200 for row in request.summary["excerpts"])
    assert set(request.summary["allowed_values"]) == {"role", "asset"}
    assert "unit-purpose-collation" in request.guidance and "cited_line" in request.guidance
    records = job._read(unit, result["artifact"])["assignments"]
    assert {record["tag"] for record in records} == {"role:auth", "role:session", "asset:credentials"}
    assert all(record["basis"] == "reported" and record["producer"]["name"] == "collation-model-pass"
               and record["confidence"] == "medium" and record["subject"]["kind"] == "component" for record in records)
    auth = next(record for record in records if record["tag"] == "role:auth")
    assert auth["evidence"][0]["cited_line"] is True and auth["evidence"][0]["path"] == "app/login.py"
    assert auth["evidence"][0]["span"]["start_line"] == auth["evidence"][0]["location"]["start_line"]
    session = next(record for record in records if record["tag"] == "role:session")
    assert session["evidence"][0]["cited_assignment"] is True
    deterministic_ids = {item["assignment_id"] for item in job._read(unit, outputs[job.COLLATION]["artifact"])["assignments"]}
    assert session["evidence"][0]["ref"] in deterministic_ids
    document = job._read(unit, result["purposes"])
    [entry] = document["components"]
    assert entry["status"] == "accepted" and entry["purpose"].startswith("A login route")
    assert entry["guidance_bundle_sha256"] == document["guidance_bundle_sha256"] and len(entry["proposal_sha256"]) == 64
    assert result["terminal_status"] == "SUCCEEDED" and result["component_status"] == {"component:app": "accepted"}
    # The deterministic set is a different artifact and is untouched.
    assert {record["tag"] for record in job._read(unit, outputs[job.COLLATION]["artifact"])["assignments"]} >= {
        "role:auth", "mechanism:http"}


@pytest.mark.parametrize("damage", ["unknown-key", "foreign-value", "uncited", "unsupplied-line", "foreign-assignment",
                                    "long-purpose", "other-component", "bad-unknown"])
def test_rejected_proposals_leave_the_deterministic_facets_and_record_a_gap(tmp_path, monkeypatch, damage) -> None:
    def proposal(request):
        value = valid_proposal(request)
        if damage == "unknown-key":
            value["severity"] = "high"
        elif damage == "foreign-value":
            value["role"] = ["role:telepathy"]
        elif damage == "uncited":
            value["asset"] = ["asset:credentials", "asset:keys"]
        elif damage == "unsupplied-line":
            value["claims"][0]["citations"] = [{"path": "app/login.py", "line": 9999}]
        elif damage == "foreign-assignment":
            value["claims"][2]["citations"] = [{"assignment_id": "tag:" + "0" * 64}]
        elif damage == "long-purpose":
            value["purpose"] = "x" * 601
        elif damage == "other-component":
            value["component_id"] = "component:other"
        else:
            value["unknown"] = ["weakness"]
        return value

    unit, _outputs, result = run_pass(tmp_path, monkeypatch, Scripted(proposal))
    assert result["item_count"] == 0 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert len(result["gaps"]) == 1 and result["gaps"][0].startswith("collation:model_pass_rejected:component:app:")
    document = job._read(unit, result["purposes"])
    assert document["components"][0]["status"] == "rejected" and "purpose" not in document["components"][0]


def test_provider_failure_is_a_named_gap_not_a_result(tmp_path, monkeypatch) -> None:
    unit, _outputs, result = run_pass(tmp_path, monkeypatch, Scripted(error=ProviderError("scripted outage", code="down")))
    assert result["item_count"] == 0
    assert result["gaps"] == ["collation:model_pass_failed:component:app: ProviderError"]
    assert job._read(unit, result["purposes"])["components"][0]["status"] == "failed"


def test_enabled_pass_without_a_transport_is_a_named_gap(tmp_path, monkeypatch) -> None:
    _unit, _outputs, result = run_pass(tmp_path, monkeypatch, None)
    assert result["item_count"] == 0 and result["gaps"][0].startswith("collation:model_pass_unavailable")


def test_the_worker_is_registered_bounded_and_its_skill_is_runtime_only() -> None:
    worker = SPECIALIZED_WORKERS[WORKER_ID]
    assert (worker.job, worker.role, worker.skill) == ("job_security_tagging", "unit_purpose_collator", "unit-purpose-collation")
    registry = load_registry(ROOT)
    assert registry["runtime_skills"]["unit-purpose-collation"]["jobs"] == ["job_security_tagging"]
    assert registry["roles"]["unit_purpose_collator"]["responsibility"]
    skill = load_runtime_skill(ROOT, "unit-purpose-collation", job_id="job_security_tagging", fallback_to_package=False)
    assert "citation" in skill.body.lower() and "weakness" in skill.body
    with pytest.raises(Exception):
        load_runtime_skill(ROOT, "unit-purpose-collation", job_id="job_inference_security_review", fallback_to_package=False)
    bundle = worker_bundle(ROOT, WORKER_ID, model=MODEL)
    assert [item["name"] for item in bundle["sections"]][-1] == "procedures"
    assert bundle["role_id"] == "unit_purpose_collator"


def test_model_pass_settings_require_an_enabled_model_profile() -> None:
    with pytest.raises(ValueError, match="enabled model profile"):
        ModelPassSettings(enabled=True, model={**MODEL, "enabled": False})
    with pytest.raises(ValueError, match="complete model profile"):
        ModelPassSettings(enabled=True, model={"provider": "x"})
    assert ModelPassSettings().enabled is False and plain_settings().model_pass.model is None
    with pytest.raises(ValueError, match="max_excerpt_lines"):
        ModelPassSettings(max_excerpt_lines=0)
