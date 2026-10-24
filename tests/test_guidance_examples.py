"""The worked examples in the role guidance use the real compact shapes and the real tool request shape."""
from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from appsec_review.guidance import load_registry
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.capability import AuthorityDenied, Authorized, CellCapability

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
ROLES = {"red_team_analyst": "red-compact", "hypothesis_hunter": "red-compact", "blue_team_refuter": "blue-compact",
         "independent_verifier": "verifier-compact", "adjudication_judge": "judge-result-compact"}
SINK = "asr:sink_site:" + "1" * 64
GUARD = "asr:guard_fact:" + "2" * 64


def blocks(role: str) -> tuple[list[dict], list[dict]]:
    """(examples, non-examples): the JSON objects in the role\'s Examples section, split at "Do not do this"."""
    text = (ROOT / "pipeline" / "prompt-fragments" / "roles" / f"{role}.md").read_text(encoding="utf-8")
    examples = text.split("## Examples", 1)[1]
    good, _, bad = examples.partition("Do not do this")
    parse = lambda part: [json.loads(line) for block in re.findall(r"```json\n(.*?)```", part, re.S)  # noqa: E731
                          for line in block.strip().split("\n{") for line in [line if line.startswith("{") else "{" + line]]
    return parse(good), parse(bad)


def capability(role: str) -> CellCapability:
    registry = load_registry(ROOT)["roles"][role]
    tools = sorted((set(registry["tools"]) & {"find", "query_observations", "query_codeql", "read_excerpt"}) | {"expand"})
    return CellCapability.issue(
        run_id="2026-10-12-0001", manifest_sha256="1" * 64, package_id="p", package_sha256="2" * 64, role=role, round=0,
        tools=tools, indexes=("source", "observations", "precomputed"), entities=(SINK, GUARD), max_queries=8,
        max_turns=4, page_size=10, max_depth=3, max_result_bytes=16384)


@pytest.mark.parametrize("role", sorted(ROLES))
def test_every_role_has_examples_with_a_non_example(role: str) -> None:
    good, bad = blocks(role)
    assert good and bad
    actions = {item["action"] for item in good}
    assert actions == {"final", "retrieve"} or role == "hypothesis_hunter" or "final" in actions


@pytest.mark.parametrize("role", sorted(ROLES))
def test_final_examples_validate_against_the_roles_compact_schema_and_non_examples_do_not(role: str) -> None:
    good, bad = blocks(role)
    schema = ROLES[role]
    finals = [item["result"] for item in good if item["action"] == "final"]
    assert finals
    for result in finals:
        assert SCHEMAS.errors(schema, result) == [], (role, result)
    # A non-example breaks the contract of its schema or its tool catalog.
    broken = 0
    for item in bad:
        if item["action"] == "final":
            labels = json.dumps(item["result"])
            broken += bool(SCHEMAS.errors(schema, item["result"])) or "the " in labels or "obviously" in labels
        else:
            broken += all(isinstance(_decide(role, request), AuthorityDenied) for request in item["requests"])
    assert broken == len(bad)


def _decide(role: str, request: dict):
    return capability(role).authorize(request, labels={"G2": GUARD, "K1": SINK, "J1": GUARD}, locator_paths={"src/packet.cpp"})


@pytest.mark.parametrize("role", sorted(ROLES))
def test_retrieve_examples_are_accepted_by_the_capability_and_path_requests_are_not(role: str) -> None:
    good, bad = blocks(role)
    requests = [request for item in good if item["action"] == "retrieve" for request in item["requests"]]
    for request in requests:
        decision = _decide(role, request)
        assert isinstance(decision, Authorized), (role, request, decision)
    path_requests = [request for item in bad if item["action"] == "retrieve" for request in item["requests"]]
    assert all(_decide(role, request).code == "forbidden_parameter" for request in path_requests)


def test_the_judge_guidance_shows_every_verdict_and_names_neither_side() -> None:
    good, bad = blocks("adjudication_judge")
    verdicts = {item["result"]["verdict"] for item in good if item["action"] == "final"}
    assert verdicts == {"A", "B", "both", "neither", "unresolved"}
    text = (ROOT / "pipeline" / "prompt-fragments" / "roles" / "adjudication_judge.md").read_text(encoding="utf-8")
    assert not re.search(r"\b(?:red|blue)\b|red_team|blue_team|hypothesis_hunter", text, re.IGNORECASE)
    # The non-examples: a side with no resolvable citation, a role named as the verdict, and a path lookup.
    finals = [item["result"] for item in bad if item["action"] == "final"]
    assert any(item["verdict"] not in {"A", "B", "both", "neither", "unresolved"} for item in finals)
    assert any(entry["cites"] and not re.fullmatch(r"[A-Z][0-9]+", entry["cites"][0])
               for item in finals for entry in item["per_predicate"].values())


def test_blue_examples_never_support_and_fixed_guard_cites_capacity_and_dominance() -> None:
    good, _ = blocks("blue_team_refuter")
    finals = [item["result"] for item in good if item["action"] == "final"]
    assert {item["stance"] for item in finals} == {"contradicts", "qualifies", "unresolved"}
    contradictions = [item for item in finals if item["stance"] == "contradicts"]
    assert contradictions and all(set(item["cites"]) >= {"G2", "S1", "S2"} for item in contradictions)
    for role in ("blue_team_refuter", "independent_verifier"):
        text = (ROOT / "pipeline" / "prompt-fragments" / "roles" / f"{role}.md").read_text(encoding="utf-8")
        assert "24-byte source with length 20" in text
        assert "n > sizeof out.name || n > size - 4" in text
        assert "mutation" in text and "array, not a pointer" in text


def test_small_examples_cover_async_authorization_configuration_and_invariants() -> None:
    hunters, _ = blocks("hypothesis_hunter")
    claims = [claim for item in hunters if item["action"] == "final" for claim in item["result"]["claims"]]
    authz = next(claim for claim in claims if claim["security_predicate"] == "authz_bypass")
    assert authz["obligations"] and authz["evidence_requests"]
    assert authz["taint_paths"][0]["edges"][0]["basis"] == "analyst_hypothesis"
    assert authz["taint_paths"][0]["edges"][0]["cites"] == []
    blue, _ = blocks("blue_team_refuter")
    verifier, _ = blocks("independent_verifier")
    for answers, specialist in [(blue, "ci_cd_pipeline"), (verifier, "business_logic_abuse")]:
        requests = [request for item in answers if item["action"] == "final"
                    for request in item["result"].get("evidence_requests", [])]
        assert any(request["specialist"] == specialist for request in requests)
