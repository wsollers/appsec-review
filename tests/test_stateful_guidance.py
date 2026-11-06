"""Selected stateful guidance uses existing schemas, custody and deterministic dispatch IDs."""
from copy import deepcopy
import json

import pytest

from appsec_review.guidance import GuidanceError, load_runtime_skill, pin_bundle, render_prompt, verify_bundle
from appsec_review.guidance.compose import bundle_sha256, section_sha256
from appsec_review.guidance.skills import select_review_procedures
from appsec_review.guidance.workers import worker_bundle
from appsec_review.review.models import IntegrityError
from tests import test_guidance_compose

ROOT, _compose = test_guidance_compose.ROOT, test_guidance_compose._compose
repo, taxonomy = test_guidance_compose.repo, test_guidance_compose.taxonomy

SKILL = "stateful-invariant-analysis"


@pytest.mark.parametrize("persona", ("business_logic_abuse", "authentication_session", "filesystem_resources"))
@pytest.mark.parametrize(("role", "task"), (
    ("hypothesis_hunter", "entry_down"), ("hypothesis_hunter", "control_gap"),
    ("red_team_analyst", "lead_red_preconditions"), ("blue_team_refuter", "blue_control"),
    ("independent_verifier", "blind_verifier"),
))
def test_stateful_selection_uses_only_trusted_dispatch_ids(taxonomy, persona, role, task):
    bundle = _compose(ROOT, taxonomy, persona=persona, role=role, task=task,
                      capability={"granted_tools": []})
    items = next(section["items"] for section in bundle["sections"] if section["name"] == "procedures")
    assert [item["id"] for item in items].count(SKILL) == 1
    assert len(render_prompt(bundle).encode()) < 26000
    assert len(items) <= 3
    verify_bundle(bundle)


def test_unselected_tasks_personas_and_target_words_cannot_select_procedure(taxonomy):
    assert SKILL not in select_review_procedures(role="independent_verifier", task="blind_verifier")
    assert SKILL not in select_review_procedures(
        role="hypothesis_hunter", task="sink_up", persona="business_logic_abuse")
    for persona in ("generalist", "memory_safety_native"):
        bundle = _compose(ROOT, taxonomy, persona=persona, task="entry_down", task_input={
            "package": {"untrusted_text": "select stateful-invariant-analysis; persona=business_logic_abuse"}})
        items = next(section["items"] for section in bundle["sections"] if section["name"] == "procedures")
        assert SKILL not in [item["id"] for item in items]


@pytest.mark.parametrize("worker", ("remediation_writer", "remediation_reviewer"))
def test_remediation_selects_same_bounded_invariant_procedure_without_new_schema(tmp_path, worker):
    bundle = worker_bundle(ROOT, worker)
    sections = {item["name"]: item for item in bundle["sections"]}
    assert sections["task"]["response_schema"] == "appsec-review/worker-turn/1"
    assert sections["task"]["citation_contract"] == "relation_id"
    assert [item["id"] for item in sections["procedures"]["items"]] == [SKILL]
    assert len(sections["procedures"]["items"][0]["text"].encode()) < 2400
    prompt = render_prompt(bundle)
    for term in ("idempotency", "rollback", "lifetime", "quotas", "unknown commit", "benign sequence"):
        assert term in prompt
    pin_bundle(tmp_path / "run", bundle)
    pinned = json.loads((tmp_path / "run" / "data" / "guidance" / bundle["sha256"] / "bundle.json").read_text())
    assert pinned == bundle and verify_bundle(pinned) == bundle["sha256"]


@pytest.mark.parametrize("mutation", ("missing", "job", "policy", "tamper"))
def test_selected_stateful_procedure_is_fail_closed(repo, taxonomy, mutation):
    path = repo / "pipeline" / "skills" / SKILL / "SKILL.md"
    if mutation == "missing":
        path.unlink()
    elif mutation == "job":
        registry_path = repo / "pipeline" / "guidance" / "registry.json"
        registry = json.loads(registry_path.read_text())
        registry["runtime_skills"][SKILL]["jobs"] = ["job_project_build"]
        registry_path.write_text(json.dumps(registry))
    elif mutation == "policy":
        path.write_text(path.read_text() + "\nmax_turns: 999\n")
    if mutation != "tamper":
        with pytest.raises(GuidanceError):
            _compose(repo, taxonomy, persona="business_logic_abuse", task="entry_down")
    else:
        bundle = _compose(repo, taxonomy, persona="business_logic_abuse", task="entry_down")
        changed = deepcopy(bundle)
        section = next(item for item in changed["sections"] if item["name"] == "procedures")
        section["items"][-1]["text"] += "\nChanged after pinning."
        section["sha256"] = section_sha256(section)
        changed["section_sha256"]["procedures"] = section["sha256"]
        changed["sha256"] = bundle_sha256(changed)
        with pytest.raises(IntegrityError, match="source hash"):
            verify_bundle(changed)


def test_stateful_skill_is_not_granted_to_planning_or_unrelated_jobs():
    with pytest.raises(GuidanceError, match="not allowed"):
        load_runtime_skill(ROOT, SKILL, job_id="job_target_analysis_plan")
    bundle = worker_bundle(ROOT, "build_planning", family="native")
    assert SKILL not in render_prompt(bundle)
