"""Code-level unit handler, topology validator, and failure-seam tests for job_build_environment_analysis."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_build_environment_analysis import job as env_job
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID,
    SCHEMA,
    BuildEnvironmentAnalysisFailed,
    build_job,
)
from appsec_review.jobs.job_target_analysis_plan import job as plan_job

ROOT = Path(__file__).resolve().parents[3]
ANALYZE = "environment_analysis.analyze_scripts"
PUBLISH = "environment_analysis.publish_handoff"


def test_validate_config_accepts_shipped_topology_and_rejects_mismatches():
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    job_cfg = config.jobs[JOB_ID]
    job = build_job()
    (validator,) = job.input_validators
    validator(SimpleNamespace(config=job_cfg), {})

    bad_steps = SimpleNamespace(steps={"wrong_step": None}, settings={})
    with pytest.raises(ValueError, match="topology does not match"):
        validator(SimpleNamespace(config=bad_steps), {})

    bad_tasks = SimpleNamespace(
        steps=("environment_analysis",),
        step=lambda _s: SimpleNamespace(tasks=("analyze_scripts",)),
        settings={},
    )
    with pytest.raises(ValueError, match="topology does not match"):
        validator(SimpleNamespace(config=bad_tasks), {})

    bad_settings = SimpleNamespace(
        steps=("environment_analysis",),
        step=lambda _s: SimpleNamespace(tasks=("analyze_scripts", "publish_handoff")),
        settings={"max_scripts": 99},
    )
    with pytest.raises(ValueError, match="max_scripts"):
        validator(SimpleNamespace(config=bad_settings), {})


def _unit_ctx(
    run_root: Path,
    target_root: Path | None,
    *,
    source_fingerprint: str = "fp-1",
    settings: dict | None = None,
    events: list | None = None,
    unit_id: str = ANALYZE,
    upstream_outputs: dict | None = None,
):
    recorded = events if events is not None else []
    step, task = unit_id.split(".")
    unit_root = run_root / "data/jobs" / JOB_ID / "attempts/attempt_0001/steps" / step / "tasks" / task
    unit_root.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        unit_id=unit_id,
        unit_root=unit_root,
        output=lambda uid: (upstream_outputs or {})[uid],
        job=SimpleNamespace(
            run_root=run_root,
            target_root=target_root,
            source_fingerprint=source_fingerprint,
            config=SimpleNamespace(settings=settings or {}),
            events=SimpleNamespace(write=lambda name, **kw: recorded.append((name, kw))),
        ),
    )


def test_analyze_and_publish_handlers_succeed_and_translate_failures(tmp_path, monkeypatch):
    run_root = tmp_path / "run"
    target = tmp_path / "target"
    target.mkdir()
    script_bytes = b"SDK_ROOT=tools/sdk\n"
    (target / "setup.sh").write_bytes(script_bytes)
    (target / "README.md").write_bytes(b"docs\n")

    catalog_doc = {
        "source_fingerprint": "fp-1",
        "catalog_handoff_sha256": "c" * 64,
        "files": [
            {
                "path": "setup.sh",
                "sha256": hashlib.sha256(script_bytes).hexdigest(),
                "size_bytes": len(script_bytes),
            },
            {
                "path": "README.md",
                "sha256": hashlib.sha256(b"docs\n").hexdigest(),
                "size_bytes": 5,
            },
        ],
    }
    monkeypatch.setattr(plan_job, "_accepted_catalog", lambda _root: catalog_doc)

    # 1. Catalog source mismatch
    with pytest.raises(BuildEnvironmentAnalysisFailed, match="catalog source mismatch"):
        build_job().units[0].handler(_unit_ctx(run_root, target, source_fingerprint="wrong-fp"))

    # 2. Missing target custody
    with pytest.raises(BuildEnvironmentAnalysisFailed, match="source custody is missing"):
        build_job().units[0].handler(_unit_ctx(run_root, None))

    # 3. Clean analyze -> publish without before_reading
    events: list[tuple[str, dict]] = []
    analyzed = build_job().units[0].handler(_unit_ctx(run_root, target, events=events))
    assert analyzed["schema"] == SCHEMA
    assert analyzed["environment"]["coverage"] == "complete"
    assert [name for name, _ in events] == [
        "BUILD_ENVIRONMENT_ANALYSIS_STARTED",
        "BUILD_ENVIRONMENT_ANALYZED",
    ]
    assert events[0][1]["selected_scripts"] == 1 and events[0][1]["inventory_files"] == 2

    pub_events: list[tuple[str, dict]] = []
    published = build_job().units[1].handler(
        _unit_ctx(
            run_root,
            target,
            unit_id=PUBLISH,
            events=pub_events,
            upstream_outputs={ANALYZE: analyzed},
        )
    )
    assert published["terminal_status"] == "SUCCEEDED" and published["gaps"] == []
    assert json.loads((run_root / published["artifact"]["path"]).read_bytes()) == analyzed["environment"]

    # 4. Gapped publish -> COMPLETED_WITH_GAPS
    gapped_env = {
        **analyzed["environment"],
        "coverage": "partial",
        "gaps": ["setup.sh: unresolved_sourcing"],
    }
    gapped_pub = build_job().units[1].handler(
        _unit_ctx(
            run_root,
            target,
            unit_id=PUBLISH,
            upstream_outputs={ANALYZE: {"environment": gapped_env}},
        )
    )
    assert gapped_pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert gapped_pub["gaps"][0]["scope_id"] == "setup.sh"

    # 5. before_reading mutates bytes -> BuildEnvironmentAnalysisFailed
    seam_job = build_job(before_reading=lambda _u: (target / "setup.sh").write_bytes(b"SDK_ROOT=tampered\n"))
    with pytest.raises(BuildEnvironmentAnalysisFailed, match="source bytes changed"):
        seam_job.units[0].handler(_unit_ctx(run_root, target))

    # 6. before_reading unlinks script -> BuildEnvironmentAnalysisFailed
    missing_job = build_job(before_reading=lambda _u: (target / "setup.sh").unlink())
    with pytest.raises(BuildEnvironmentAnalysisFailed, match="accepted environment script is missing: setup.sh"):
        missing_job.units[0].handler(_unit_ctx(run_root, target))

    # 7. Oversized publication payload -> BuildEnvironmentAnalysisFailed
    monkeypatch.setattr(env_job, "canonical_json", lambda _value: b"x" * (16 * 1024 * 1024 + 1))
    with pytest.raises(BuildEnvironmentAnalysisFailed, match="exceeds its accepted reader bound"):
        build_job().units[1].handler(
            _unit_ctx(run_root, target, unit_id=PUBLISH, upstream_outputs={ANALYZE: analyzed})
        )
