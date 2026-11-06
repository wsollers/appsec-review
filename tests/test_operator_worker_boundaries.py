import time

import pytest

from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.mcp.operator_schema import OPERATOR_TOOLS
from appsec_review.retrieval import RetrievalCore
from tests.test_retrieval_core import RUN_ID, _fixture


def scoped(tmp_path, role):
    runs, ids = _fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    package = {
        "run_id": RUN_ID, "manifest_sha256": core.manifest_sha256, "package_id": "accepted-fixture-scope",
        "retrieval": {"indexes": ["source", "analysis", "history", "precomputed"],
                      "query_sets": ["symbol_links", "history_context", "dependency_advisories"],
                      "entity_ids": [ids["symbol"], ids["precomputed"]],
                      "max_page_size": 20, "max_pages": 2, "max_depth": 2, "max_response_bytes": 131072},
    }
    secret = b"offline-unit-capability-secret-32"
    capability = issue_capability(package, role=role, round_id="offline-unit", secret=secret,
                                  expires_at=int(time.time()) + 300)
    adapter = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=capability,
                                        secret=secret, role=role, round_id="offline-unit")
    return adapter, ids


@pytest.mark.parametrize("role", ["hypothesis_hunter", "red_team_analyst", "blue_team_refuter",
                                  "independent_verifier", "adjudication_judge", "red", "blue", "verifier"])
def test_operator_tools_and_broad_history_remain_denied_to_real_capabilities(tmp_path, role):
    adapter, ids = scoped(tmp_path, role)
    for name in [tool["name"] for tool in OPERATOR_TOOLS] + ["query_change_context", "query_artifacts",
                                                          "query_owasp_workbench", "search"]:
        with pytest.raises(ValueError, match="outside review capability"):
            adapter.call(name, {})
    assert adapter.call("find", {"identity": ids["symbol"]})["results"][0]["identity"] == ids["symbol"]
    with pytest.raises(ValueError, match="outside review package"):
        adapter.call("find", {"identity": ids["file"]})


def test_existing_context_adapter_preserves_exact_subject_and_missing_producer_gaps(tmp_path):
    adapter, ids = scoped(tmp_path, "hypothesis_hunter")
    result = adapter.call("query_precomputed", {"query_set": "symbol_links", "subject": ids["symbol"]})
    assert result["results"][0]["identity"] == ids["precomputed"]
    assert result["results"][0]["payload"]["subject_identity"] == ids["symbol"]
    for query_set in ("history_context", "dependency_advisories"):
        result = adapter.call("query_precomputed", {"query_set": query_set, "subject": ids["symbol"]})
        assert result["results"] == [] and result["coverage_gaps"]
        with pytest.raises(ValueError, match="outside review package"):
            adapter.call("query_precomputed", {"query_set": query_set, "subject": ids["file"]})
        with pytest.raises(ValueError, match="outside review package"):
            adapter.call("query_precomputed", {"query_set": query_set, "path": "src/auth.c"})
