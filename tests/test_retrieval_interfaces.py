from __future__ import annotations

import pytest

from appsec_review.retrieval import ArtifactQueryRequest, SearchHit, SearchRequest


def test_search_request_enforces_a_bounded_page() -> None:
    with pytest.raises(ValueError, match="between 1 and 100"):
        SearchRequest(run_id="run-1", index="code", query="authenticate", limit=101)


def test_search_hit_requires_resolving_lines() -> None:
    with pytest.raises(ValueError, match="line range"):
        SearchHit(
            source_id="sha256:abc",
            path="src/auth.py",
            start_line=20,
            end_line=10,
            excerpt="def authenticate(...):",
        )


def test_artifact_query_contract_is_bounded_and_transport_neutral() -> None:
    request = ArtifactQueryRequest(language="rust", architecture="wasm32", limit=7)
    assert request.filters == {"language": "rust", "architecture": "wasm32"}
    with pytest.raises(ValueError, match="invalid artifact query filter"):
        ArtifactQueryRequest(shard="bad/shard")
    with pytest.raises(ValueError, match="between 1 and 100"):
        ArtifactQueryRequest(limit=101)


def test_published_mcp_tool_catalog_matches_the_server_tools() -> None:
    import json
    from pathlib import Path

    from appsec_review.mcp.schema import TOOLS

    catalog = json.loads((Path(__file__).resolve().parents[1] / "docs" / "schemas" /
                          "retrieval-mcp-tools.json").read_text(encoding="utf-8"))
    assert catalog["schema"] == "appsec-review/mcp-tool-catalog/1"
    assert catalog["tools"] == [
        {"name": tool["name"], "required": list(tool["inputSchema"].get("required", [])),
         "properties": list(tool["inputSchema"]["properties"])}
        for tool in TOOLS
    ]
