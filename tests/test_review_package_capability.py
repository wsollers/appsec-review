from __future__ import annotations

import time

import pytest

from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability


SECRET = b"s" * 32


class Core:
    run_id = "2026-10-10-0001"
    manifest_sha256 = "a" * 64


class Adapter:
    core = Core()

    def call(self, name, arguments):
        if name == "query_precomputed":
            return {"results": [{"identity": arguments["subject"]}],
                    "pagination": {"next_cursor": "core-cursor"}}
        return {"results": [{"identity": arguments["identity"]}],
                "pagination": {"next_cursor": None}}


def _package(name: str, entity: str) -> dict:
    return {"run_id": Core.run_id, "manifest_sha256": Core.manifest_sha256,
            "package_id": name, "retrieval": {"indexes": ["precomputed"],
                "query_sets": ["scanner_correlation"], "entity_ids": [entity],
                "max_page_size": 2, "max_pages": 2, "max_depth": 2,
                "max_response_bytes": 131072}}


def _scope(package: dict, *, role: str = "red") -> ScopedRetrievalMcpAdapter:
    token = issue_capability(package, role=role, round_id="1", secret=SECRET,
                             expires_at=int(time.time()) + 300)
    return ScopedRetrievalMcpAdapter(Adapter(), package, capability=token, secret=SECRET,
                                     role=role, round_id="1")


def test_capability_denies_cross_package_identity_and_unbounded_tools() -> None:
    scope = _scope(_package("first", "asr:precomputed_fact:" + "1" * 64))
    assert scope.call("find", {"identity": "asr:precomputed_fact:" + "1" * 64})["results"]
    with pytest.raises(ValueError, match="outside review package"):
        scope.call("find", {"identity": "asr:precomputed_fact:" + "2" * 64})
    with pytest.raises(ValueError, match="outside review capability"):
        scope.call("search", {"query": "password"})
    with pytest.raises(ValueError, match="outside review package"):
        scope.call("query_precomputed", {"query_set": "scanner_correlation",
                                         "subject": "asr:precomputed_fact:" + "2" * 64})


def test_cursor_is_bound_to_package_role_and_query() -> None:
    entity = "asr:precomputed_fact:" + "1" * 64
    first = _scope(_package("first", entity))
    query = {"query_set": "scanner_correlation", "subject": entity, "limit": 1}
    cursor = first.call("query_precomputed", query)["pagination"]["next_cursor"]
    assert first.call("query_precomputed", {**query, "cursor": cursor})["results"]
    other = _scope(_package("other", entity))
    with pytest.raises(ValueError, match="cursor binding"):
        other.call("query_precomputed", {**query, "cursor": cursor})
    with pytest.raises(ValueError, match="cursor binding"):
        first.call("query_precomputed", {**query, "limit": 2, "cursor": cursor})
    verifier = _scope(_package("first", entity), role="verifier")
    with pytest.raises(ValueError, match="cursor binding"):
        verifier.call("query_precomputed", {**query, "cursor": cursor})


def test_capability_rejects_modified_package_and_expiry() -> None:
    package = _package("first", "asr:precomputed_fact:" + "1" * 64)
    token = issue_capability(package, role="red", round_id="1", secret=SECRET,
                             expires_at=int(time.time()) + 300)
    altered = {**package, "package_id": "other"}
    scope = ScopedRetrievalMcpAdapter(Adapter(), altered, capability=token, secret=SECRET,
                                      role="red", round_id="1")
    with pytest.raises(ValueError, match="binding"):
        scope.call("find", {"identity": package["retrieval"]["entity_ids"][0]})
    expired = issue_capability(package, role="red", round_id="1", secret=SECRET,
                               expires_at=int(time.time()) - 1)
    scope = ScopedRetrievalMcpAdapter(Adapter(), package, capability=expired, secret=SECRET,
                                      role="red", round_id="1")
    with pytest.raises(ValueError, match="binding"):
        scope.call("find", {"identity": package["retrieval"]["entity_ids"][0]})


def test_cell_capability_authorizes_and_scopes_exploration_tools() -> None:
    from appsec_review.review.capability import AuthorityDenied, Authorized, CellCapability
    from appsec_review.review.cells import _bound, _covers_line, _label_rows
    from appsec_review.review.labels import LabelTable

    src_in = "asr:source_file:" + "a" * 64
    ast_in = "asr:ast_node:" + "b" * 64
    ast_out = "asr:ast_node:" + "c" * 64
    tb_in = "asr:precomputed_fact:" + "d" * 64
    tb_out = "asr:precomputed_fact:" + "e" * 64
    sca_id = "asr:component_fact:" + "f" * 64

    cap = CellCapability.issue(
        run_id="2026-11-18-0001",
        package_id="pkg-1",
        package_sha256="2" * 64,
        role="hypothesis_hunter",
        round=0,
        manifest_sha256="1" * 64,
        tools=(
            "query_cfg_function",
            "query_guard_dominators",
            "query_cpg_slice",
            "query_call_paths",
            "query_threat_boundaries",
            "query_owasp_gaps",
            "query_doc_drift",
            "query_engineering_signals",
            "query_sca_reachability",
            "query_sanitizer_readiness",
        ),
        indexes=("analysis", "graph", "precomputed", "observations", "components", "inventory"),
        entities=(src_in,),
        graph_scopes=("scope-cpp",),
        max_queries=12,
        max_turns=4,
        page_size=20,
        max_depth=3,
        max_result_bytes=32768,
    )
    locator_paths = frozenset({"src/parser.cpp"})

    # Raw path is forbidden; locator inside package scope resolves cleanly
    denied_raw = cap.authorize(
        {"tool": "query_cpg_slice", "parameters": {"path": "src/parser.cpp", "line": 42}},
        locator_paths=locator_paths,
    )
    assert isinstance(denied_raw, AuthorityDenied)
    assert denied_raw.code == "forbidden_parameter"

    denied_loc = cap.authorize(
        {"tool": "query_cpg_slice", "parameters": {"locator": {"path": "src/other.cpp", "line": 42}}},
        locator_paths=locator_paths,
    )
    assert isinstance(denied_loc, AuthorityDenied)
    assert denied_loc.code == "entity_out_of_scope"

    auth_slice = cap.authorize(
        {"tool": "query_cpg_slice", "parameters": {"locator": {"path": "src/parser.cpp", "line": 42}, "direction": "backward"}},
        locator_paths=locator_paths,
    )
    assert isinstance(auth_slice, Authorized)
    assert auth_slice.parameters["path"] == "src/parser.cpp"
    assert auth_slice.parameters["line"] == 42
    assert auth_slice.line is None  # slice rows on upstream lines are retained

    # query_cfg_function sets decision.line and _covers_line supports top-level start_line/end_line
    auth_cfg = cap.authorize(
        {"tool": "query_cfg_function", "parameters": {"locator": {"path": "src/parser.cpp", "line": 25}}},
        locator_paths=locator_paths,
    )
    assert isinstance(auth_cfg, Authorized)
    assert auth_cfg.line == 25
    assert _covers_line({"path": "src/parser.cpp", "start_line": 10, "end_line": 40}, 25) is True
    assert _covers_line({"path": "src/parser.cpp", "start_line": 10, "end_line": 20}, 25) is False

    # query_call_paths accepts plain function name in `source` without failing IDENTITY_PARAMETERS
    auth_paths = cap.authorize(
        {"tool": "query_call_paths", "parameters": {"source": "handle_packet", "sink_class": "memory_copy", "entrypoint_only": True}},
        locator_paths=locator_paths,
    )
    assert isinstance(auth_paths, Authorized)
    assert auth_paths.parameters["source"] == "handle_packet"

    # _bound + _label_rows scopes CFG/guard rows to package files and grants citable Q labels
    granted: set[str] = set()
    cfg_resp = {
        "results": [
            {"function_name": "parse_packet", "path": "src/parser.cpp", "start_line": 10, "end_line": 40, "ast_identity": ast_in, "source_identity": src_in},
            {"function_name": "other_fn", "path": "src/other.cpp", "start_line": 1, "end_line": 15, "ast_identity": ast_out},
        ]
    }
    bounded_cfg, withheld_cfg = _bound("query_cfg_function", cfg_resp, cap, granted=granted, locator_paths=locator_paths)
    assert withheld_cfg == 1
    assert len(bounded_cfg["results"]) == 1
    assert ast_in in granted and ast_out not in granted

    labels = LabelTable({})
    labels.know(granted)
    _label_rows(bounded_cfg["results"], labels)
    assert bounded_cfg["results"][0]["label"].startswith("Q")

    # _bound scopes threat boundaries by locator_paths and grants SCA reachability identities
    tb_resp = {
        "results": [
            {"identity": tb_in, "location": {"path": "src/parser.cpp", "start_line": 12}, "payload": {"boundary_id": "net-edge"}},
            {"identity": tb_out, "location": {"path": "src/other.cpp", "start_line": 5}, "payload": {"boundary_id": "admin-only"}},
        ]
    }
    granted_tb: set[str] = set()
    bounded_tb, withheld_tb = _bound("query_threat_boundaries", tb_resp, cap, granted=granted_tb, locator_paths=locator_paths)
    assert withheld_tb == 1
    assert [r["identity"] for r in bounded_tb["results"]] == [tb_in]

    granted_sca: set[str] = set()
    bounded_sca, withheld_sca = _bound(
        "query_sca_reachability",
        {"results": [{"identity": sca_id, "location": {"path": "CMakeLists.txt", "start_line": 8}, "payload": {"package": "zlib"}}]},
        cap,
        granted=granted_sca,
        locator_paths=locator_paths,
    )
    assert withheld_sca == 0
    assert sca_id in granted_sca
    assert len(bounded_sca["results"]) == 1
