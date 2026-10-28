"""Live tier for the Rust code-graph export pack (skipped without the pinned CodeQL image).

It builds a source-mode (``none``) Rust database for
tests/fixtures/graph/codeql_export/rust-synthetic/source, a zero-network Cargo workspace whose
reqwest, rusqlite and serde_json dependencies are offline path stand-ins pinned by Cargo.lock. It
then runs the hash-pinned appsec-review/graph-export-rust pack through the runner ``export`` action
and requires the live rows to satisfy every semantic expectation in that fixture's
expected-facts.json. The recording is hand-authored and not refreshable; this is the tier that
proves the Rust dataflow families and settles the pack's LIVE-UNVERIFIED canonical names.
"""
from __future__ import annotations

from pathlib import Path
import shutil

from appsec_review.codeql.runtime import load_asset_lock, load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import load_expectations, unmet
from tests.live.test_codeql_graph_export_live import _export
from tests.test_live_codeql_toolchains import LIVE_SCOPES, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "rust-synthetic"


def test_live_rust_graph_export_pack_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    assert "rust" in load_asset_lock(ROOT)["export_query_packs"], (
        "lock export_query_packs.rust in containers/tools/codeql/assets.lock.json before the live tier")
    _language, profile, mode, _subroot, commands = next(item for item in LIVE_SCOPES if item[0] == "rust")
    workspace = run_root / "rust-synthetic-workspace"
    shutil.copytree(FIXTURE / "source", workspace / "rust-synthetic")
    scratch = _export(settings, run_root, image_for, "rust-synthetic", workspace, profile, mode,
                      "rust-synthetic", commands, language="rust")
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations(FIXTURE))
    assert not failures, "\n".join(failures)
