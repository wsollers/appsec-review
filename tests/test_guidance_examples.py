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
         "independent_verifier": "verifier-compact"}
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
    return capability(role).authorize(request, labels={"G2": GUARD, "K1": SINK}, locator_paths={"src/packet.cpp"})


@pytest.mark.parametrize("role", sorted(ROLES))
def test_retrieve_examples_are_accepted_by_the_capability_and_path_requests_are_not(role: str) -> None:
    good, bad = blocks(role)
    requests = [request for item in good if item["action"] == "retrieve" for request in item["requests"]]
    for request in requests:
        decision = _decide(role, request)
        assert isinstance(decision, Authorized), (role, request, decision)
    path_requests = [request for item in bad if item["action"] == "retrieve" for request in item["requests"]]
    assert all(_decide(role, request).code == "forbidden_parameter" for request in path_requests)
