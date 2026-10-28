"""Live tier for the Swift code-graph export pack (skipped until a macOS CodeQL executor exists).

CodeQL 2.27.0 extracts Swift only on macOS ("Support for the analysis of Swift requires macOS"), and the
pinned image ``audit-codeql:custom-2.27.0`` is Linux, so Swift has no entry in ``LIVE_SCOPES`` and no
build profile. That is a named coverage gap, not a clean result. When a macOS executor and a ``swift``
LIVE_SCOPES entry exist, this test compiles tests/fixtures/graph/codeql_export/swift-synthetic/source,
runs the hash-pinned export pack, and requires every expectation in that fixture's
expected-facts.json to hold (the recording itself is hand-authored and not refreshable).
"""
from __future__ import annotations

import shutil

import pytest

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import load_expectations, unmet
from tests.live.test_codeql_graph_export_live import ROOT, _export
from tests.test_live_codeql_toolchains import LIVE_SCOPES, live_codeql_runtime  # noqa: F401

FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "swift-synthetic"
MACOS_GAP = ("swift extraction requires a macOS CodeQL executor; the pinned audit-codeql:custom-2.27.0 "
             "image is Linux and LIVE_SCOPES has no swift entry")


def test_live_swift_graph_export_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    scopes = [item for item in LIVE_SCOPES if item[0] == "swift"]
    if not scopes:
        pytest.skip(MACOS_GAP)
    settings, run_root, image_for = live_codeql_runtime
    [(_language, profile, mode, _subroot, _commands)] = scopes
    commands = (("swift-synthetic", ("swiftc", "-c", "Synthetic.swift", "-o", "Synthetic.o"), {}),)
    workspace = run_root / "swift-synthetic-workspace"
    shutil.copytree(FIXTURE / "source", workspace / "swift-synthetic")
    scratch = _export(settings, run_root, image_for, "swift-synthetic", workspace, profile, mode,
                      "swift-synthetic", commands, language="swift")
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations(FIXTURE))
    assert not failures, "\n".join(failures)
