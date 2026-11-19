"""Selected stateful guidance uses existing schemas, custody and deterministic dispatch IDs."""
from copy import deepcopy
import json
import re

import pytest

from appsec_review.guidance import (
    GuidanceError, load_registry, load_runtime_skill, pin_bundle, render_prompt, verify_bundle,
)
from appsec_review.guidance.compose import bundle_sha256, section_sha256
from appsec_review.guidance.skills import select_review_procedures
from appsec_review.guidance.workers import worker_bundle
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError
from appsec_review.storage import file_sha256
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


@pytest.mark.parametrize("persona", ("authentication_session", "business_logic_abuse", "filesystem_resources"))
def test_stateful_control_gap_retains_complete_pinned_sources(taxonomy, tmp_path, persona):
    bundle = _compose(ROOT, taxonomy, persona=persona, task="control_gap", capability={"granted_tools": []})
    assert _compose(ROOT, taxonomy, persona=persona, task="control_gap",
                    capability={"granted_tools": []}) == bundle
    sections = {section["name"]: section for section in bundle["sections"]}
    prompt = render_prompt(bundle)
    registry = load_registry(ROOT)
    role_path = ROOT / registry["roles"]["hypothesis_hunter"]["path"]
    assert sections["role"]["text"] == role_path.read_text(encoding="utf-8")
    for name in ("governing_rules", "role", "task"):
        assert sections[name]["text"].strip() in prompt
    for name, record in (
        ("persona", registry["personas"][persona]),
        ("stack", registry["stacks"]["cpp_rpc_service"]),
        ("task", registry["tasks"]["inference-security-review"]["control_gap"]),
    ):
        assert sections[name]["source_sha256"] == file_sha256(ROOT / record["path"])
        for part in sections[name].get("sections", ()):
            assert f"## {part['heading']}\n{part['text']}".strip() in prompt
    items = sections["procedures"]["items"]
    assert [item["id"] for item in items] == [
        "generative-investigation", "effective-control-verification", SKILL,
    ]
    for item in items:
        skill = load_runtime_skill(ROOT, item["id"], job_id="job_inference_security_review",
                                   fallback_to_package=False)
        assert item == {"id": skill.name, "path": skill.path, "text": skill.text,
                        "source_sha256": file_sha256(ROOT / skill.path)}
        assert skill.text.strip() in prompt
    assert sections["receipt"]["capability"] == {"granted_tools": []}
    run_root = tmp_path / "run"
    pin = pin_bundle(run_root, bundle)
    assert pin_bundle(run_root, bundle) == pin
    pinned_path = run_root / pin["path"]
    pinned = json.loads(pinned_path.read_text(encoding="utf-8"))
    assert pinned == bundle
    assert verify_bundle(pinned) == bundle["sha256"]
    assert pinned_path.with_name("prompt.md").read_bytes() == prompt.encode("utf-8")


def test_compact_hunter_keeps_evidence_questions_and_uncertainty(taxonomy):
    bundle = _compose(ROOT, taxonomy, persona="authentication_session", task="control_gap",
                      capability={"granted_tools": []})
    prompt = render_prompt(bundle)
    role = prompt.split("<<<role ", 1)[1].split("<<<end role>>>", 1)[0]
    prose = " ".join(role.split())
    for rule in (
        "Account for each package-menu lead exactly once",
        "do not re-report known unit claims",
        "caller/callee source lines before marking an edge observed",
        "material-gap labels (X1), never prose",
        "Claim-local `evidence_requests`",
        "Does not rate severity, set or change any claim state, accept or refute a claim",
        "read another cell's output, widen the unit scope, request an unlisted tool",
        "read target guidance, or run code",
        "Works alone; receives known unit claim identities and statements, never their reasoning",
        "compile-only proof-of-trigger; confirmed claims without a basis get none",
        "not claims; without seeds no chain is composed",
        "unproven link stays a question, not accepted dataflow",
        "Obligation citations identify investigation, not discharge",
        "Specialist requests name missing knowledge, not worker invocation",
        "Put counter-evidence in `counter`",
    ):
        assert rule in prose
    good = role.split("Do not do this", 1)[0]
    decoder = json.JSONDecoder()
    finals = []
    for block in re.findall(r"```json\n(.*?)\n```", good, re.S):
        remaining = block.strip()
        while remaining:
            example, end = decoder.raw_decode(remaining)
            remaining = remaining[end:].lstrip()
            if example["action"] == "final":
                finals.append(example["result"])
    schemas = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
    for result in finals:
        schemas.validate("red-compact", result)
    claims = [claim for result in finals for claim in result["claims"]]
    overflow = next(claim for claim in claims if claim["security_predicate"] == "memory_corruption")
    assert overflow["missing"] == overflow["poc_basis"]["unknowns"] == ["X1"]
    assert overflow["support"]["missing_or_ineffective_guard"] == ["G2", "S1", "S2"]
    seed = next(result["chain_seeds"][0] for result in finals if "chain_seeds" in result)
    assert seed["steps"][1]["claim"] is None
    assert seed["links"][0]["questions"] == [
        "Does the same connection stay open between the two requests?",
    ]
    queued = next(claim for claim in claims if claim["security_predicate"] == "authz_bypass")
    assert queued["obligations"] == [{
        "predicate": "missing_or_ineffective_guard",
        "question": "Does the consumer bind actor, action, document and tenant at use?",
        "cites": ["K1"],
    }]
    edge = queued["taint_paths"][0]["edges"][0]
    assert edge["basis"] == "analyst_hypothesis" and edge["cites"] == []
    assert edge["question"] == "Which serialized actor and document fields reach this consumer?"
    assert queued["evidence_requests"] == [{
        "predicate": "source_to_sink_reachability", "requested_kind": "dataflow", "anchors": ["E1", "K1"],
        "question": "Resolve producer-to-consumer field flow and checks after dequeue.",
        "specialist": "authorization_access_control",
    }]


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
