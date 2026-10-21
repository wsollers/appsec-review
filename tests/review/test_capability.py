from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.review.capability import (
    AuthorityDenied, Authorized, CellCapability, IN_PROCESS_TOOLS,
)
from appsec_review.review.models import IntegrityError, Role

IN_SCOPE = "asr:source_span:" + "a" * 64
OTHER = "asr:source_span:" + "b" * 64
OBSERVATION = "asr:tool_observation:" + "c" * 64


def _capability(**overrides) -> CellCapability:
    values = dict(run_id="2026-10-12-0001", manifest_sha256="m" * 64, package_id="package-1",
                  package_sha256="p" * 64, role=Role.RED_TEAM_ANALYST, round=0,
                  tools=("search", "find", "read_excerpt", "trace", "query_codeql"),
                  indexes=("source", "observations"), entities=(IN_SCOPE,),
                  entity_prefixes=("asr:tool_observation:",), max_queries=3, max_turns=4,
                  page_size=10, max_depth=3, max_result_bytes=8192)
    values.update(overrides)
    return CellCapability.issue(**values)


def test_catalog_is_the_published_tool_schema_minus_the_owasp_store() -> None:
    catalog = json.loads((Path(__file__).resolve().parents[2] / "docs" / "schemas" /
                          "retrieval-mcp-tools.json").read_text(encoding="utf-8"))
    assert IN_PROCESS_TOOLS == {tool["name"] for tool in catalog["tools"]} - {"query_owasp_workbench"}


@pytest.mark.parametrize("request_value", [
    {"tool": "read_excerpt", "arguments": {"identity": IN_SCOPE}},
    {"tool": "read_excerpt", "args": {"identity": IN_SCOPE}},
    {"tool": "read_excerpt", "identity": IN_SCOPE},
    {"tool": "read_excerpt", "parameters": {"identity": IN_SCOPE, "purpose": "read the span"}},
    {"tool": "read_excerpt", "arguments": {"identity": IN_SCOPE}, "purpose": "read the span"},
])
def test_common_spellings_of_a_request_are_accepted_and_still_fully_checked(request_value) -> None:
    decision = _capability().authorize(request_value)
    assert isinstance(decision, Authorized) and decision.parameters == {"identity": IN_SCOPE}


def test_a_normalized_request_gets_no_extra_authority() -> None:
    capability = _capability()
    assert capability.authorize({"tool": "read_excerpt", "arguments": {"identity": OTHER}}).code == "entity_out_of_scope"
    assert capability.authorize({"tool": "search", "args": {"query": "x", "sql": "select 1"}}).code == "forbidden_parameter"
    assert capability.authorize({"tool": "coverage", "args": {}}).code == "tool_not_granted"
    # An alias next to a second key, and a key next to explicit parameters, stay malformed.
    assert capability.authorize({"tool": "search", "arguments": {"query": "x"}, "extra": 1}).code == "malformed_request"
    assert capability.authorize({"tool": "search", "parameters": {"query": "x"}, "extra": 1}).code == "malformed_request"


def test_a_cell_is_told_the_exact_tool_catalog_and_request_shape() -> None:
    from appsec_review.review.cells import _request_example, _tool_catalog

    capability = _capability()
    catalog = _tool_catalog(capability)
    assert [tool["name"] for tool in catalog] == sorted(capability.tools)
    assert all(tool["parameters"].get("type") == "object" for tool in catalog)
    example = _request_example(capability)
    assert example["tool"] == catalog[0]["name"] and set(example) == {"tool", "parameters"}


def test_authorized_request_is_normalized_to_granted_indexes_and_page_size() -> None:
    decision = _capability().authorize({"tool": "search", "parameters": {"query": "memcpy length"}})
    assert isinstance(decision, Authorized)
    assert decision.parameters == {"query": "memcpy length", "indexes": ["observations", "source"],
                                   "limit": 10}
    assert len(decision.filter_sha256) == 64
    assert isinstance(_capability().authorize(
        {"tool": "read_excerpt", "parameters": {"identity": IN_SCOPE}}), Authorized)
    assert isinstance(_capability().authorize(
        {"tool": "trace", "parameters": {"identity": OBSERVATION, "depth": 3}}), Authorized)


@pytest.mark.parametrize(("request_value", "code"), [
    ("not an object", "malformed_request"),
    ({"tool": "search", "parameters": {"query": "x"}, "extra": 1}, "malformed_request"),
    ({"tool": "shell", "parameters": {"cmd": "id"}}, "unknown_tool"),
    ({"tool": "query_owasp_workbench", "parameters": {}}, "unknown_tool"),
    ({"tool": "coverage", "parameters": {}}, "tool_not_granted"),
    ({"tool": "search", "parameters": {"query": "x", "sql": "select 1"}}, "forbidden_parameter"),
    ({"tool": "find", "parameters": {"path": "src/main.c"}}, "forbidden_parameter"),
    ({"tool": "search", "parameters": {"query": "x", "limit": "ten"}}, "schema_violation"),
    ({"tool": "search", "parameters": {"query": "x", "bogus": 1}}, "schema_violation"),
    ({"tool": "search", "parameters": {}}, "schema_violation"),
    ({"tool": "read_excerpt", "parameters": {"identity": "../../etc/passwd"}}, "schema_violation"),
    ({"tool": "search", "parameters": {"query": "../../appsec-multi-vuln-guide"}}, "path_like_value"),
    ({"tool": "search", "parameters": {"query": "/etc/shadow"}}, "path_like_value"),
    ({"tool": "search", "parameters": {"query": "strcpy.*buf"}}, "regex_like_value"),
    ({"tool": "search", "parameters": {"query": "a|b"}}, "regex_like_value"),
    ({"tool": "search", "parameters": {"query": "x; drop table entities"}}, "sql_like_value"),
    ({"tool": "search", "parameters": {"query": "1 union select payload_json"}}, "sql_like_value"),
    ({"tool": "read_excerpt", "parameters": {"identity": OTHER}}, "entity_out_of_scope"),
    ({"tool": "search", "parameters": {"query": "x", "indexes": ["history"]}}, "index_not_granted"),
    ({"tool": "search", "parameters": {"query": "x", "limit": 50}}, "page_cap_exceeded"),
    ({"tool": "trace", "parameters": {"identity": IN_SCOPE, "depth": 8}}, "depth_cap_exceeded"),
])
def test_model_requests_outside_the_capability_are_denied_without_raising(request_value, code) -> None:
    decision = _capability().authorize(request_value)
    assert isinstance(decision, AuthorityDenied)
    assert decision.code == code


def test_tool_reading_ungranted_indexes_and_exhausted_query_budget_are_denied() -> None:
    capability = _capability(tools=("search", "query_hotspots"))
    assert capability.authorize({"tool": "query_hotspots", "parameters": {}}).code == "index_not_granted"
    assert capability.authorize({"tool": "search", "parameters": {"query": "x"}},
                                queries_used=3).code == "query_cap_exceeded"


def test_sql_words_in_code_search_are_not_statement_syntax() -> None:
    assert isinstance(_capability().authorize(
        {"tool": "search", "parameters": {"query": "executeQuery select from users where"}}), Authorized)


def test_capability_is_hash_bound_and_tampering_is_an_integrity_error() -> None:
    capability = _capability()
    capability.verify()
    assert capability.capability_sha256 != _capability(round=1).capability_sha256
    object.__setattr__(capability, "tools", capability.tools + ("coverage",))
    with pytest.raises(IntegrityError):
        capability.authorize({"tool": "coverage", "parameters": {}})


@pytest.mark.parametrize("overrides", [
    {"tools": ("query_owasp_workbench",)}, {"tools": ("shell",)}, {"indexes": ("ground_truth",)},
    {"entities": ("src/main.c",)}, {"entity_prefixes": ("",)}, {"entity_prefixes": ("/home",)},
    {"max_queries": 0}, {"page_size": 101}, {"max_depth": 9},
])
def test_the_application_cannot_issue_an_unbounded_or_unknown_capability(overrides) -> None:
    with pytest.raises(ValueError):
        _capability(**overrides)
