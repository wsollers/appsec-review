"""Live tier for the Java/Kotlin code-graph export pack (skipped without the pinned CodeQL image).

It compiles tests/fixtures/graph/codeql_export/java-synthetic/source with ``javac`` in the ``java``
build profile, runs the hash-pinned ``appsec-review/graph-export-java`` pack through the runner
``export`` action, and requires the live export to satisfy every semantic expectation in that
fixture's expected-facts.json (sources, sinks, paths, sanitizers, guards, summaries, dispatch). The
recording is hand-authored and is not compared row for row.
"""
from __future__ import annotations

from pathlib import Path
import shutil

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import load_expectations, unmet
from tests.live.test_codeql_graph_export_live import _export
from tests.test_live_codeql_toolchains import LIVE_SCOPES, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "java-synthetic"


def test_live_java_graph_export_pack_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, mode, _subroot, _commands = next(item for item in LIVE_SCOPES if item[0] == "java")
    files = tuple(f"app/{path.name}" for path in sorted((FIXTURE / "source" / "app").glob("*.java")))
    commands = (("java-synthetic", ("javac", "-d", "classes", *files), {}),)
    workspace = run_root / "java-synthetic-workspace"
    shutil.copytree(FIXTURE / "source", workspace / "java-synthetic")
    scratch = _export(settings, run_root, image_for, "java-synthetic", workspace, profile, mode, "java-synthetic",
                      commands, language="java")
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations(FIXTURE))
    assert not failures, "\n".join(failures)
