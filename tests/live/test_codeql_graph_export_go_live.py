"""Live tier for the Go code-graph export pack (skipped without the pinned CodeQL image).

It builds a real Go database for tests/fixtures/graph/codeql_export/go-synthetic/source with
``go build`` under the CodeQL tracer in the ``go`` build profile, runs the hash-pinned
appsec-review/graph-export-go pack through the runner ``export`` action, and requires the live export
to satisfy every semantic expectation in that fixture's expected-facts.json (cross-function SQL flow,
argv and environment sources, sanitized path, SSRF and deserialization sinks, the dominating and
non-dominating guard, the guard-bounded range, the narrowing conversion, interface dispatch and the
unresolved and reflective calls). The recording is hand-authored and not refreshable; a failure here
means the pack or the recording must change in the same commit.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import load_expectations, unmet
from tests.live.test_codeql_graph_export_live import _export
from tests.test_live_codeql_toolchains import LIVE_SCOPES, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
GO_SYNTHETIC = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "go-synthetic"


def test_live_go_graph_export_pack_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, mode, _subroot, scope_commands = next(item for item in LIVE_SCOPES if item[0] == "go")
    environment = {**scope_commands[0][2], "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"}
    commands = (("gosynthetic", ("go", "build", "-o", "codeql-app", "."), environment),)
    workspace = run_root / "go-synthetic-workspace"
    shutil.copytree(GO_SYNTHETIC / "source", workspace / "gosynthetic")
    scratch = _export(settings, run_root, image_for, "go-synthetic", workspace, profile, mode, "gosynthetic",
                      commands, language="go")
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations(GO_SYNTHETIC))
    assert not failures, "\n".join(failures)
