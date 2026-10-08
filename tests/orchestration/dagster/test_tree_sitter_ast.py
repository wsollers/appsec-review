from __future__ import annotations

from pathlib import Path

from appsec_review.config import load_config
from appsec_review.jobs.job_tree_sitter_ast.dagster import build_dagster_job
from appsec_review.runtime import JobRunner


ROOT = Path(__file__).resolve().parents[3]


def test_tree_sitter_dagster_job_uses_real_dynamic_scope_mapping() -> None:
    job = build_dagster_job(load_config(ROOT / "appsec-review.toml"), JobRunner)
    nodes = {node.name: node for node in job.graph.node_defs}
    assert job.name == "tree_sitter_ast"
    assert {
        "standalone__tree_sitter_ast__plan__route_scopes",
        "standalone__tree_sitter_ast__parse__scope",
        "standalone__tree_sitter_ast__parse__dynamic_scopes",
    } <= set(nodes)
    route = nodes["standalone__tree_sitter_ast__plan__route_scopes"]
    assert route.output_defs[0].is_dynamic
    assert nodes["standalone__tree_sitter_ast__parse__scope"].pool == "index"
