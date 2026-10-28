from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.cli import GRAPH_JOB_IDS
from appsec_review.config import load_config
from appsec_review.debug_symbols.contract import INDEX_NAME, JOB_ID, QUERY_TOOL
from appsec_review.mcp.schema import TOOLS
from appsec_review.orchestration.topology import upstream_closure, wave1_dependencies
from appsec_review.retrieval.index import INDEX_NAMES
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime import active_job_ids, job_is_enabled


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("target", ("clang", "msvc"))
def test_each_target_has_a_registered_decision_and_both_extraction_lanes(target, monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    config = load_config(ROOT / "appsec-review.toml", profile="dev", compiler_target=target)
    job = builtin_registry().build(JOB_ID)
    assert job.name == config.job(JOB_ID).name
    assert config.job(JOB_ID).settings["compiler_target"] == target
    assert config.job(JOB_ID).settings["enabled"] is True
    assert job_is_enabled(config, JOB_ID)
    assert JOB_ID in active_job_ids(config, GRAPH_JOB_IDS)
    units = {unit.unit_id: unit for unit in job.units}
    assert "decide.target" in units
    for lane in ("extract.clang_dwarf", "extract.msvc_pdb"):
        assert lane in units
        assert "decide.target" in units[lane].dependencies
    assert job.propagate_handoff
    assert job.datasets


def test_symbol_shard_and_query_are_part_of_the_public_contract() -> None:
    assert INDEX_NAME in INDEX_NAMES
    tools = {tool["name"]: tool for tool in TOOLS}
    assert QUERY_TOOL in tools
    assert tools[QUERY_TOOL]["inputSchema"]["additionalProperties"] is False
    assert JOB_ID in GRAPH_JOB_IDS
    assert GRAPH_JOB_IDS.index("job_artifact_indexing") < GRAPH_JOB_IDS.index(JOB_ID)
    assert GRAPH_JOB_IDS.index(JOB_ID) < GRAPH_JOB_IDS.index("job_review_data_indexing")


def test_topology_propagates_symbols_to_downstream_inventory_and_review() -> None:
    registered = set(GRAPH_JOB_IDS) | {"job_security_tagging"}
    dependencies = wave1_dependencies(registered)
    assert dependencies is not None
    assert dependencies[JOB_ID] == ("job_artifact_indexing",)
    assert JOB_ID in upstream_closure("job_review_data_indexing", dependencies, registered)
    assert JOB_ID in upstream_closure("job_codeql_analysis", dependencies, registered)
    without_symbols = wave1_dependencies(registered - {JOB_ID})
    assert without_symbols is not None
    assert JOB_ID not in without_symbols
    assert all(JOB_ID not in upstream for upstream in without_symbols.values())
