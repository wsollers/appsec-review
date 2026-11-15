"""The iteration's mandatory project-build input must be refused at admission."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.build_iterations import REQUEST_SCHEMA, retain
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_iteration.job import build_job, iteration_inputs
from appsec_review.runtime.consume import UpstreamIntegrityError
from appsec_review.runtime.inputs import admit_inputs, input_read_scope
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext

ROOT = Path(__file__).resolve().parents[3]


def test_missing_project_build_is_rejected_before_the_iteration_unit(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    target = tmp_path / "source"
    target.mkdir()
    (target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    run_root = tmp_path / "2026-11-13-0001"
    configuration = run_root / "data/configuration"
    configuration.mkdir(parents=True)
    (configuration / "manifest.json").write_text(json.dumps({
        "resolved_sha256": config.resolved_sha256,
        "sources": [{"path": str(ROOT / "appsec-review.toml")}],
        "selection": {"profile": config.profile, "compiler_target": config.compiler_target.value},
    }), encoding="utf-8")
    source_identity = source_fingerprint(target)
    reference = {
        **retain(run_root, "requests", {
            "schema": REQUEST_SCHEMA, "run_id": run_root.name,
            "node_id": "build-unit-" + "a" * 20,
            "target": str(target), "binding": {"source_identity": source_identity},
        }),
        "run_id": run_root.name,
    }
    pending = run_root / "data/build/iterations/pending.json"
    pending.parent.mkdir(parents=True)
    pending.write_text(json.dumps({"request": reference}), encoding="utf-8")
    inputs = iteration_inputs(run_root, reference)
    assert inputs.upstream_handoffs == {}
    job = build_job()
    context = JobContext(
        run_id=run_root.name, attempt_id="attempt_0001", trigger="dagster",
        repository_root=ROOT, run_root=run_root,
        attempt_root=run_root / "data/jobs/job_build_iteration/attempts/attempt_0001",
        metadata_root=tmp_path / "metadata",
        orchestration={"run_id": "fixture-dagster-run", "iteration_request": json.dumps(reference)},
        config=config.job(job.job_id), events=None, target_root=target,
        source_fingerprint=source_identity, contract=job.contract,
        upstream_handoffs=inputs.upstream_handoffs,
    )
    unit = UnitContext(
        job=context, unit_id="execute.node", step_id="execute", task_id="node",
        unit_root=context.attempt_root / "steps/execute/tasks/node", outputs={},
    )

    # The real handler, controller and accepted reader prove this is a hard input.
    with pytest.raises(UpstreamIntegrityError, match=r"^accepted job_project_build handoff is required$"):
        with input_read_scope(context):
            job.units[0].handler(unit)

    # The same absence must be rejected before the runtime admits that unit.
    with pytest.raises(ValueError, match=r"^required input unavailable: job_project_build/handoff$"):
        admit_inputs(context, enabled=set(job.consumes))
