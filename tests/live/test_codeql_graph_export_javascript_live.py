"""Live tier for the JavaScript/TypeScript code-graph export pack (skipped without the pinned CodeQL image).

It extracts tests/fixtures/graph/codeql_export/javascript-synthetic/source in source mode (no build),
runs the hash-pinned ``appsec-review/graph-export-javascript`` pack through the runner ``export``
action, and requires the live rows to satisfy every semantic expectation in that fixture's
expected-facts.json. The recording beside it is hand-authored and is never refreshed from this test.
"""
from __future__ import annotations

from pathlib import Path
import shutil

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import load_expectations, unmet
from tests.live.test_codeql_graph_export_live import _export
from tests.test_live_codeql_toolchains import LIVE_SCOPES, live_codeql_runtime  # noqa: F401

FIXTURE = Path(__file__).parents[2] / "tests" / "fixtures" / "graph" / "codeql_export" / "javascript-synthetic"


def test_live_javascript_graph_export_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, mode, _subroot, commands = next(item for item in LIVE_SCOPES if item[0] == "javascript")
    workspace = run_root / "javascript-synthetic-workspace"
    shutil.copytree(FIXTURE / "source", workspace / "src")
    scratch = _export(settings, run_root, image_for, "javascript-synthetic", workspace, profile, mode, "src",
                      commands, language="javascript")
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations(FIXTURE))
    assert not failures, "\n".join(failures)
