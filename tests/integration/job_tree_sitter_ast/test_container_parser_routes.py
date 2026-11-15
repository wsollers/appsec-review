"""Integration tests for container parser grammar routing and cross-job Tree-sitter metrics."""

from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
import runpy

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import ContainerExecutor, load_catalog
from appsec_review.jobs.job_tree_sitter_ast import Scope
from appsec_review.jobs.job_tree_sitter_ast.job import _grammar_locks
from appsec_review.jobs.job_tree_sitter_ast.model import SUPPORTED_LANGUAGES
from appsec_review.jobs.job_tree_sitter_ast.scope_execution import parse_scope
from appsec_review.observability import aggregate_run_metrics
from appsec_review.storage import file_sha256

ROOT = Path(__file__).resolve().parents[3]


def test_container_parser_and_acquisition_route_every_supported_language() -> None:
    pytest.importorskip(
        "tree_sitter_language_pack",
        reason="tree-sitter packages are installed only in the tool-tree-sitter image",
    )
    parser = runpy.run_path(str(ROOT / "containers" / "tools" / "tree-sitter" / "parser.py"))
    acquisition = runpy.run_path(str(ROOT / "containers" / "tools" / "tree-sitter" / "acquire_assets.py"))
    assert set(parser["LANGUAGES"]) == SUPPORTED_LANGUAGES
    assert set(parser["LANGUAGES"].values()) == set(acquisition["LANGUAGES"])
    lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text(encoding="utf-8"))
    for item in lock["grammars"]:
        assert parser["LANGUAGES"][item["language"]] == item["grammar"]


def test_both_callers_share_metrics_and_ast_reuse_is_not_an_invocation(tmp_path: Path) -> None:
    from tests.integration.job_source_history_analysis.test_analysis import LocalDocker, invoke_symbols, symbol_unit

    unit = symbol_unit(tmp_path, {"python/app.py": ("Python", "def check():\n    return 1\n")})
    docker = LocalDocker()
    invoke_symbols(unit, docker)
    locks, assets = _grammar_locks(ROOT)
    tool = load_catalog(ROOT).tool("tool-tree-sitter")
    config = load_config(ROOT / "appsec-review.toml").job("job_tree_sitter_ast")
    ast_unit = replace(
        unit,
        job=replace(unit.job, config=config),
        unit_id="parse.scope",
        step_id="parse",
        task_id="scope",
        outputs={
            "load.accepted_inputs": {
                "grammar_locks": {key: asdict(value) for key, value in locks.items()},
                "asset_lock": assets,
                "image_id": tool.expected_image_id,
            }
        },
    )
    digest = file_sha256(unit.job.target_root / "python/app.py")
    size = (unit.job.target_root / "python/app.py").stat().st_size
    scope = Scope(
        "scope-python",
        "component:0001",
        "python",
        "source:component:0001",
        "python",
        "Python",
        ({"path": "python/app.py", "sha256": digest, "size_bytes": size, "language": "Python"},),
    )
    factory = lambda context: ContainerExecutor(load_catalog(ROOT), context.job.run_root, runner=docker)
    first = parse_scope(ast_unit, asdict(scope), factory)
    second = parse_scope(ast_unit, asdict(scope), factory)
    assert not first["index_reused"] and second["index_reused"]
    assert first["tree_sitter_invocation_id"] == second["tree_sitter_invocation_id"]
    summary = aggregate_run_metrics(unit.job.run_root)["tree_sitter"]
    assert summary["invocation_count"] == 2 and summary["reused_scope_count"] == 1
    assert len({row["invocation_id"] for row in summary["invocations"]}) == 2
    assert {row["job_id"] for row in summary["by_job_attempt"]} == {
        "job_source_history_analysis",
        "job_tree_sitter_ast",
    }
    assert summary["counts"]["files_parsed"] == {"value": 2, "complete": True}
    assert summary["measurements"]["memory_peak_bytes"]["value"] is None
    assert summary["incomplete_accounting"], "mocked counters must not be reported as measured zeros"
