"""Integration test for Dagster execution of job_owasp_control_assessment."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from appsec_review.orchestration.dagster.adapter import build_definitions
from appsec_review.storage import RunStore

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]


def _citation(name: str) -> dict:
    return {"source_identity": name, "artifact_sha256": hashlib.sha256(name.encode()).hexdigest(),
            "lines": [1, 1]}


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


@pytest.mark.parametrize("satisfied", [False, True], ids=["adverse", "benign-context"])
def test_owasp_job_publication_delivers_control_context_to_review_roles(tmp_path: Path, satisfied: bool) -> None:
    from tests.test_owasp_assessment_job import (
        ScriptedAssessment,
        accepted_fixture,
        assert_adverse_downstream,
        assert_roles_receive_control_context,
        execute,
        sql_row,
    )
    from tests.test_owasp_downstream import project_and_assemble

    if satisfied:
        fixture = accepted_fixture(tmp_path, source=(
            "def get(q):\n    import db\n"
            "    result = db.execute('SELECT name FROM users WHERE id = ?', (q,))\n    return result\n"))
        outputs = execute(fixture, ScriptedAssessment(outcome="satisfied"), publish_handoff=True)
        row = sql_row(outputs)
        downstream = project_and_assemble(fixture)
        package = next(package for package in downstream.assembly.packages
                       if fixture.ids["sast_high"] in package.lead_ids and package.kind == "finding_lead")
        assert_roles_receive_control_context(fixture, downstream, package.package_id, row["control_identity"])
    else:
        fixture = accepted_fixture(tmp_path, secrets=True)
        outputs = execute(fixture, ScriptedAssessment(retrieve=True), publish_handoff=True)
        row = sql_row(outputs)
        assert_adverse_downstream(fixture, row, check_roles=True)
