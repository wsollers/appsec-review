from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

import pytest

pytest.importorskip("dagster")

from appsec_review.orchestration.dagster.adapter import build_definitions
from appsec_review.storage import RunStore


ROOT = Path(__file__).resolve().parents[3]


def _citation(name: str) -> dict:
    return {"source_identity": name, "artifact_sha256": hashlib.sha256(name.encode()).hexdigest(),
            "lines": [1, 1]}


def test_owasp_dag_has_parallel_cells_join_and_publication() -> None:
    graph = build_definitions(ROOT / "appsec-review.toml").get_job_def(
        "owasp_control_assessment").graph
    names = {node.name for node in graph.node_defs}
    cells = {f"standalone__owasp_control_assessment__validation__cell_0{index}" for index in range(1, 5)}
    assert cells <= names
    join = "standalone__owasp_control_assessment__join__deterministic_join"
    verify = "standalone__owasp_control_assessment__verification__independent_review"
    publication = "standalone__owasp_control_assessment__publication__publish_indexes"

    def upstream(node: str) -> set[str]:
        mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
        return {output.node_name for outputs in mapping.values() for output in outputs}

    assert cells <= upstream(verify)
    assert verify in upstream(join)
    assert join in upstream(publication)


def test_dagster_fixture_acceptance_publishes_exact_join(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    store = RunStore(ROOT / "runs")
    run_id, run_root = store.create(datetime.now(timezone.utc))
    try:
        payload = {
            "schema": "appsec-review/owasp-workbench-input/1",
            "components": [{"target_id": "fixture", "project_id": "fixture-project",
                "component_id": "fixture-api", "paths": ["main.py"], "languages": ["Python"],
                "frameworks": ["FastAPI"], "tags": ["api", "server"],
                "evidence": [_citation("fixture-component")]}],
            "evidence": [], "retrieval_manifest": {"fixture_sha256": "a" * 64},
        }
        input_path = run_root / "data" / "inputs" / "owasp-workbench.json"
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text(json.dumps(payload), encoding="utf-8")
        result = build_definitions(ROOT / "appsec-review.toml").get_job_def(
            "owasp_control_assessment").execute_in_process(
                tags={"appsec/application_run_id": run_id})
        assert result.success
        pointer = json.loads((run_root / "data" / "indexes" / "owasp" / "accepted.json").read_text())
        assert pointer["run_id"] == run_id
        attempts = run_root / "data" / "jobs" / "job_owasp_control_assessment" / "attempts"
        latest = sorted(attempts.iterdir())[-1]
        joined = json.loads((latest / "artifacts" / "owasp-workbench" / "control-results.json").read_text())
        assert joined["accounting"]["exactly_once"] is True
        assert joined["accounting"]["selected"] == joined["accounting"]["joined"]
    finally:
        shutil.rmtree(run_root, ignore_errors=True)
