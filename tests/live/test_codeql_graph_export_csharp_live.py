"""Live tier for the C# code-graph export pack (skipped without the pinned CodeQL image).

It builds a C# database for tests/fixtures/graph/codeql_export/csharp-synthetic/source with the
``dotnet`` build profile (an offline ``dotnet restore``: the project has no PackageReference, so the
SDK's bundled ASP.NET Core targeting pack is enough), runs the hash-pinned
``appsec-review/graph-export-csharp`` pack through the runner ``export`` action, and requires the
export to satisfy every semantic expectation in that fixture's expected-facts.json (paths, guards,
ranges, conversions, dispatch, sanitizers). The recording itself is hand-authored and not refreshable.
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
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "csharp-synthetic"


def test_live_csharp_graph_export_pack_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, mode, _subroot, scope_commands = next(item for item in LIVE_SCOPES if item[0] == "csharp")
    environment = scope_commands[0][2]
    commands = (
        ("synthetic", ("dotnet", "restore", "Synthetic.csproj"), environment),
        ("synthetic", ("dotnet", "build", "Synthetic.csproj", "--no-restore"), environment),
    )
    workspace = run_root / "csharp-synthetic-workspace"
    shutil.copytree(FIXTURE / "source", workspace / "synthetic")
    scratch = _export(settings, run_root, image_for, "csharp-synthetic", workspace, profile, mode, "synthetic",
                      commands, language="csharp")
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations(FIXTURE))
    assert not failures, "\n".join(failures)
