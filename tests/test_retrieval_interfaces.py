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

def test_graph_hop_and_depth_caps_align_across_runtime_mcp_and_worker_turn(tmp_path: Path) -> None:
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator

    from appsec_review.mcp.schema import TOOLS
    from appsec_review.retrieval import RetrievalCore
    from tests.test_retrieval_core import RUN_ID, _fixture

    by_name = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
    assert by_name["query_cpg_slice"]["properties"]["max_depth"]["maximum"] == 16
    assert by_name["query_call_paths"]["properties"]["max_hops"]["maximum"] == 16

    root = Path(__file__).resolve().parents[1]
    worker_turn = json.loads(
        (root / "docs" / "schemas" / "inference-security-review" / "worker-turn.schema.json").read_text(encoding="utf-8")
    )
    branches = {
        row["properties"]["tool"]["const"]: row["properties"]["parameters"]["properties"]
        for row in worker_turn["$defs"]["request"]["oneOf"]
    }
    assert branches["query_cpg_slice"]["max_depth"]["maximum"] == 16
    assert branches["query_call_paths"]["max_hops"]["maximum"] == 16

    cpg_validator = Draft202012Validator(by_name["query_cpg_slice"])
    assert cpg_validator.is_valid({"function_name": "fn", "max_depth": 16})
    assert not cpg_validator.is_valid({"function_name": "fn", "max_depth": 17})

    paths_validator = Draft202012Validator(by_name["query_call_paths"])
    assert paths_validator.is_valid({"source": "a", "sink": "b", "max_hops": 16})
    assert not paths_validator.is_valid({"source": "a", "sink": "b", "max_hops": 17})

    runs, _ = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    assert core.query_cpg_slice(function_name="authenticate", max_depth=16)["status"] in {"ok", "unavailable", "empty"}
    assert core.query_call_paths(source="a", sink="b", max_hops=16)["status"] in {"ok", "unavailable", "empty"}
    with pytest.raises(ValueError, match="max_depth must be an integer between 1 and 16"):
        core.query_cpg_slice(function_name="authenticate", max_depth=17)
    with pytest.raises(ValueError, match="max_hops must be an integer between 1 and 16"):
        core.query_call_paths(source="a", sink="b", max_hops=17)
