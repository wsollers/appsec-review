from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.config.development import OVERRIDE_DIRECTORY, parse_job_development, reject_development
from appsec_review.config.operational import MaterialConfigurationChange, operational_changes
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.runtime.contracts import (
    Availability,
    InputRequirement,
    JobContract,
    MissingPolicy,
    accepted_inputs,
)
from appsec_review.runtime.datasets import artifact_only
from appsec_review.runtime.development import check_lookup, lookup_function
from appsec_review.runtime import GraphRunner, Job, JobRunner, Unit
from appsec_review.runtime.inputs import input_file
from appsec_review.runtime.units import UnitExecutor
from appsec_review.runtime.registry import JobRegistry
from appsec_review.runtime.repair import admit_repair, plan_repair
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import RECEIPT_SCHEMA, SharedArtifacts, put_bytes, reference
from tests.test_job_runtime import write_config
from tests.test_repair_admission import write_release

ROOT = Path(__file__).resolve().parents[1]


def _write_pipeline_configs(
    root: Path,
    job_ids: tuple[str, ...],
    *,
    dev_overrides_toml: str = "",
    extra_base_toml: str = "",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "profiles").mkdir(parents=True, exist_ok=True)
    config_path = write_config(root)
    extra_lines = [
        "",
        "[jobs.job_target_analysis_plan]",
        'name = "target_analysis_plan"',
        "workers = 1",
        "",
        "[jobs.job_target_analysis_plan.settings.model]",
        'provider = "copilot-sdk"',
        'model = "claude-haiku-5.5"',
        "",
    ]
    for job_id in job_ids:
        if job_id != "job_fixture":
            extra_lines.extend([
                f"[jobs.{job_id}]",
                f'name = "{job_id}"',
                "workers = 1",
                "",
            ])
    if extra_base_toml:
        extra_lines.append(extra_base_toml)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write("\n".join(extra_lines) + "\n")

    profile_body = (
        '[jobs.job_target_analysis_plan.settings.model]\n'
        'provider = "copilot-sdk"\n'
        'model = "claude-haiku-5.5"\n'
    )
    if dev_overrides_toml:
        profile_body += "\n" + dev_overrides_toml.strip() + "\n"
    (root / "profiles" / "copilot-dev.toml").write_text(profile_body, encoding="utf-8")

    prod_body = (
        '[jobs.job_target_analysis_plan.settings.model]\n'
        'provider = "copilot-sdk"\n'
        'model = "claude-haiku-5.5"\n'
    )
    if dev_overrides_toml:
        prod_body += "\n" + dev_overrides_toml.strip() + "\n"
    (root / "profiles" / "prod.toml").write_text(prod_body, encoding="utf-8")

    write_release(root, ("job_fixture", "job_target_analysis_plan", *job_ids))
    return config_path


def _three_stage_jobs(phase_log: dict[str, list[str]] | None = None) -> tuple[tuple[Job, Job, Job], dict[str, tuple[str, ...]]]:
    stage1_decl = artifact_only(
        "stage1_payload",
        "work",
        "inventory",
        "appsec-review/stage1-payload/1",
        "Stage 1 payload",
        artifacts=("data/jobs/job_stage1/attempts/*/steps/work/tasks/only/payload.json",),
        reason="unit regression fixture",
    )
    stage2_decl = artifact_only(
        "stage2_payload",
        "work",
        "inventory",
        "appsec-review/stage2-payload/1",
        "Stage 2 payload",
        artifacts=("data/jobs/job_stage2/attempts/*/steps/work/tasks/only/payload.json",),
        reason="unit regression fixture",
    )
    stage3_decl = artifact_only(
        "stage3_payload",
        "work",
        "inventory",
        "appsec-review/stage3-payload/1",
        "Stage 3 payload",
        artifacts=("data/jobs/job_stage3/attempts/*/steps/work/tasks/only/payload.json",),
        reason="unit regression fixture",
    )

    def run_stage1(unit):
        out = unit.unit_root / "payload.json"
        atomic_json(out, {"schema": "appsec-review/stage1-payload/1", "message": "original-from-stage1"})
        return {"artifact": reference(unit.job.run_root, out), "terminal_status": "SUCCEEDED"}

    def _read_stage1_message(run_root: Path) -> str:
        up = accepted_upstream(run_root, "job_stage1")
        ref = up.handoff["outputs"]["work.only"]["artifact"]
        src = input_file(run_root, "job_stage1", "stage1_payload", ref)
        return json.loads(src.path.read_bytes())["message"]

    def stage2_input_validator(context, _payload=None):
        msg = _read_stage1_message(context.run_root)
        if phase_log is not None:
            phase_log.setdefault("input_validator", []).append(msg)

    def run_stage2(unit):
        msg = _read_stage1_message(unit.job.run_root)
        if phase_log is not None:
            phase_log.setdefault("unit", []).append(msg)
        out = unit.unit_root / "payload.json"
        atomic_json(out, {"schema": "appsec-review/stage2-payload/1", "derived": f"stage2:{msg}"})
        return {"artifact": reference(unit.job.run_root, out), "terminal_status": "SUCCEEDED"}

    def stage2_finalize(context, result):
        msg = _read_stage1_message(context.run_root)
        if phase_log is not None:
            phase_log.setdefault("finalize_result", []).append(msg)
        return result

    def stage2_output_validator(context, result):
        msg = _read_stage1_message(context.run_root)
        if phase_log is not None:
            phase_log.setdefault("output_validator", []).append(msg)

    def run_stage3(unit):
        up = accepted_upstream(unit.job.run_root, "job_stage2")
        ref = up.handoff["outputs"]["work.only"]["artifact"]
        src = input_file(unit.job.run_root, "job_stage2", "stage2_payload", ref)
        derived = json.loads(src.path.read_bytes())["derived"]
        out = unit.unit_root / "payload.json"
        atomic_json(out, {"schema": "appsec-review/stage3-payload/1", "final": f"stage3<-{derived}"})
        return {"artifact": reference(unit.job.run_root, out), "terminal_status": "SUCCEEDED"}

    u1 = (Unit("work.only", run_stage1),)
    job1 = Job(
        job_id="job_stage1",
        name="job_stage1",
        handler=UnitExecutor(u1).execute,
        units=u1,
        datasets=(stage1_decl,),
        contract=JobContract(),
        strict_gaps=True,
    )

    u2 = (Unit("work.only", run_stage2),)
    job2 = Job(
        job_id="job_stage2",
        name="job_stage2",
        handler=UnitExecutor(u2).execute,
        units=u2,
        datasets=(stage2_decl,),
        consumes=("job_stage1",),
        contract=JobContract(
            inputs=accepted_inputs(
                "job_stage1",
                (stage1_decl,),
                availability=Availability.REQUIRED,
                missing=MissingPolicy.REJECT,
            ),
        ),
        input_validators=(stage2_input_validator,),
        result_transform=stage2_finalize,
        output_validators=(stage2_output_validator,),
        strict_gaps=True,
    )

    u3 = (Unit("work.only", run_stage3),)
    job3 = Job(
        job_id="job_stage3",
        name="job_stage3",
        handler=UnitExecutor(u3).execute,
        units=u3,
        datasets=(stage3_decl,),
        consumes=("job_stage2",),
        contract=JobContract(
            inputs=accepted_inputs(
                "job_stage2",
                (stage2_decl,),
                availability=Availability.REQUIRED,
                missing=MissingPolicy.REJECT,
            ),
        ),
        strict_gaps=True,
    )

    dependencies = {
        "job_stage1": (),
        "job_stage2": ("job_stage1",),
        "job_stage3": ("job_stage2",),
    }
    return (job1, job2, job3), dependencies


def _accepted_handoff(run_root: Path, job_id: str) -> dict:
    pointer = json.loads((run_root / "data/jobs" / job_id / "latest.json").read_bytes())
    return json.loads((run_root / pointer["handoff_path"]).read_bytes())


def sample_stage2_lookup(run_root: Path) -> dict[str, str]:
    up = accepted_upstream(run_root, "job_stage1")
    ref = up.handoff["outputs"]["work.only"]["artifact"]
    src = input_file(run_root, "job_stage1", "stage1_payload", ref)
    return json.loads(src.path.read_bytes())


def test_checked_in_recipe_has_no_development_blocks_and_layer_guards_reject_misuse(tmp_path: Path) -> None:
    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    for job_id, body in raw.get("jobs", {}).items():
        assert "development" not in body, f"checked-in appsec-review.toml must not define jobs.{job_id}.development"

    override_block = (
        "[[jobs.job_stage2.development.input_overrides]]\n"
        'producer = "job_stage1"\n'
        'output_kind = "stage1_payload"\n'
        'artifact = "data/jobs/job_stage1/attempts/attempt_0001/steps/work/tasks/only/payload.json"\n'
        f'replacement = "{OVERRIDE_DIRECTORY}/job_stage2/payload.json"\n'
    )

    # Base recipe rejects development blocks
    base_cfg = _write_pipeline_configs(
        tmp_path / "base_reject",
        ("job_stage1", "job_stage2"),
        extra_base_toml=override_block,
    )
    with pytest.raises(ValueError, match="not allowed in the base configuration"):
        load_config(base_cfg)

    # Non-development profile rejects development blocks
    prod_cfg = _write_pipeline_configs(
        tmp_path / "prod_reject",
        ("job_stage1", "job_stage2"),
        dev_overrides_toml=override_block,
    )
    with pytest.raises(ValueError, match="not allowed in the non-development profile prod"):
        load_config(prod_cfg, profile="prod")

    # Capacity overlay rejects development blocks at load time and in operational_changes
    overlay_dir = tmp_path / "overlay_reject"
    clean_cfg = _write_pipeline_configs(overlay_dir, ("job_stage1", "job_stage2"))
    overlay_file = overlay_dir / "overlay.toml"
    overlay_file.write_text(override_block, encoding="utf-8")
    with pytest.raises(ValueError, match="not allowed in the capacity overlay"):
        load_config(clean_cfg, profile="copilot-dev", overlay=overlay_file)

    loaded_clean = load_config(clean_cfg, profile="copilot-dev")
    before_doc = json.loads(loaded_clean.resolved_json)
    after_overlay_doc = deepcopy(before_doc)
    after_overlay_doc["configuration_overlay"] = {
        "layer": "capacity_overlay",
        "path": str(overlay_file),
        "sha256": "a" * 64,
        "keys": ["jobs.job_stage2.development.input_overrides"],
        "document": tomllib.loads(override_block),
    }
    with pytest.raises(MaterialConfigurationChange, match="development"):
        operational_changes(before_doc, after_overlay_doc)

    # operational_changes rejects malformed development blocks and non-dev profile injection
    after_non_dev = deepcopy(before_doc)
    after_non_dev["configuration_profile"]["name"] = "prod"
    after_non_dev["jobs"]["job_stage2"]["development"] = tomllib.loads(override_block)["jobs"]["job_stage2"]["development"]
    with pytest.raises(MaterialConfigurationChange, match="development profile"):
        operational_changes(before_doc, after_non_dev)


def test_parse_and_resolve_development_inputs_reject_unsafe_paths_symlinks_and_missing_files(tmp_path: Path) -> None:
    valid = {
        "input_overrides": [{
            "producer": "job_stage1",
            "output_kind": "stage1_payload",
            "artifact": "data/jobs/job_stage1/attempts/attempt_0001/steps/work/tasks/only/payload.json",
            "replacement": f"{OVERRIDE_DIRECTORY}/job_stage2/payload.json",
        }],
    }
    parsed = parse_job_development("job_stage2", valid)
    assert len(parsed.input_overrides) == 1

    for bad_override, match in [
        ({**valid["input_overrides"][0], "artifact": "data/jobs/job_stage1/attempts/attempt_0001/handoff.json"}, "control or signing"),
        ({**valid["input_overrides"][0], "replacement": f"{OVERRIDE_DIRECTORY}/job_stage2/evil.py"}, "executable code"),
        ({**valid["input_overrides"][0], "replacement": f"{OVERRIDE_DIRECTORY}/job_stage2/../escape.json"}, "canonical relative path"),
        ({**valid["input_overrides"][0], "replacement": "outside/job_stage2/payload.json"}, OVERRIDE_DIRECTORY),
        ({**valid["input_overrides"][0], "producer": "job_stage2"}, "another job"),
        ({**valid["input_overrides"][0], "output_kind": "handoff"}, "handoff envelope"),
    ]:
        with pytest.raises(ValueError, match=match):
            parse_job_development("job_stage2", {"input_overrides": [bad_override]})

    # Missing replacement and symlink replacement fail closed during Job.resolve_development_inputs
    (job1, job2, _), _ = _three_stage_jobs()
    cfg_path = _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2"))
    base_cfg = load_config(cfg_path, profile="copilot-dev")
    r1 = JobRunner(base_cfg).run(job1, target_root=tmp_path, source_fingerprint="none")
    run_id = r1["status"]["run_id"]
    run_root = base_cfg.runtime.runs_dir / run_id
    artifact_path = _accepted_handoff(run_root, "job_stage1")["outputs"]["work.only"]["artifact"]["path"]

    override_toml = (
        "[[jobs.job_stage2.development.input_overrides]]\n"
        'producer = "job_stage1"\n'
        'output_kind = "stage1_payload"\n'
        f'artifact = "{artifact_path}"\n'
        f'replacement = "{OVERRIDE_DIRECTORY}/job_stage2/edited.json"\n'
    )
    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2"), dev_overrides_toml=override_toml)
    dev_cfg = load_config(cfg_path, profile="copilot-dev")
    plan = plan_repair(dev_cfg, run_root, (job1, job2), "none")
    admit_repair(dev_cfg, run_root, (job1, job2), plan)

    # Missing replacement file
    with pytest.raises(ValueError, match="development replacement is missing"):
        JobRunner(dev_cfg).run(
            job2,
            run_id=run_id,
            target_root=tmp_path,
            source_fingerprint="none",
            upstream_handoffs={"job_stage1": r1["handoff_sha256"]},
        )

    # Symlink replacement escaping outside override directory
    outside = tmp_path / "outside-secret.json"
    outside.write_text('{"schema": "appsec-review/stage1-payload/1", "message": "secret"}', encoding="utf-8")
    replacement_file = tmp_path / OVERRIDE_DIRECTORY / "job_stage2" / "edited.json"
    replacement_file.parent.mkdir(parents=True, exist_ok=True)
    replacement_file.symlink_to(outside)
    with pytest.raises(ValueError, match="escapes|symlink"):
        JobRunner(dev_cfg).run(
            job2,
            run_id=run_id,
            target_root=tmp_path,
            source_fingerprint="none",
            upstream_handoffs={"job_stage1": r1["handoff_sha256"]},
        )


def test_check_lookup_and_attempt_wide_input_file_consistency(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="appsec_review"):
        lookup_function("os.path:join")
    with pytest.raises(ValueError, match="appsec_review"):
        lookup_function("appsec_review.runtime.development")
    resolved_fn = lookup_function("appsec_review.runtime.development:lookup_function")
    assert resolved_fn is lookup_function

    phase_log: dict[str, list[str]] = {}
    (job1, job2, job3), dependencies = _three_stage_jobs(phase_log)
    cfg_path = _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"))
    base_cfg = load_config(cfg_path, profile="copilot-dev")
    first = GraphRunner(base_cfg, (job1, job2, job3), dependencies=dependencies).run(
        target_root=tmp_path, source_fingerprint="none",
    )
    run_id = first["run_id"]
    run_root = base_cfg.runtime.runs_dir / run_id
    artifact_path = _accepted_handoff(run_root, "job_stage1")["outputs"]["work.only"]["artifact"]["path"]

    replacement_file = tmp_path / OVERRIDE_DIRECTORY / "job_stage2" / "edited.json"
    replacement_file.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(replacement_file, {"schema": "appsec-review/stage1-payload/1", "message": "overridden-in-dev"})

    override_toml = (
        "[[jobs.job_stage2.development.input_overrides]]\n"
        'producer = "job_stage1"\n'
        'output_kind = "stage1_payload"\n'
        f'artifact = "{artifact_path}"\n'
        f'replacement = "{OVERRIDE_DIRECTORY}/job_stage2/edited.json"\n'
    )
    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"), dev_overrides_toml=override_toml)
    dev_cfg = load_config(cfg_path, profile="copilot-dev")

    registry = JobRegistry()
    for item in (job1, job2, job3):
        registry.register(item.job_id, lambda item=item: item)

    before_attempts = sorted((run_root / "data/jobs/job_stage2/attempts").glob("attempt_*"))
    dev_lookup = check_lookup(dev_cfg, run_root, "job_stage2", sample_stage2_lookup, original=False, registry=registry)
    orig_lookup = check_lookup(dev_cfg, run_root, "job_stage2", sample_stage2_lookup, original=True, registry=registry)
    after_attempts = sorted((run_root / "data/jobs/job_stage2/attempts").glob("attempt_*"))
    assert before_attempts == after_attempts
    assert dev_lookup["status"] == "returned"
    assert dev_lookup["result"] == {"schema": "appsec-review/stage1-payload/1", "message": "overridden-in-dev"}
    dev_payload_read = next(r for r in dev_lookup["reads"] if r["output_kind"] == "stage1_payload")
    orig_payload_read = next(r for r in orig_lookup["reads"] if r["output_kind"] == "stage1_payload")
    assert any("development_replacement" in str(v) or k == "development_replacement" for k, v in dev_payload_read.items())
    assert orig_lookup["status"] == "returned"
    assert orig_lookup["result"] == {"schema": "appsec-review/stage1-payload/1", "message": "original-from-stage1"}
    assert not any("development_replacement" in str(v) or k == "development_replacement" for k, v in orig_payload_read.items())

    # Now execute job_stage2 and verify input_validators, unit, finalize_result, and output_validators ALL see override!
    phase_log.clear()
    plan = plan_repair(dev_cfg, run_root, (job1, job2, job3), "none", dependencies=dependencies)
    assert plan["admissible"], plan["refusals"]
    admit_repair(dev_cfg, run_root, (job1, job2, job3), plan, dependencies=dependencies)
    GraphRunner(dev_cfg, (job1, job2, job3), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none",
    )
    assert phase_log == {
        "input_validator": ["overridden-in-dev"],
        "unit": ["overridden-in-dev"],
        "finalize_result": ["overridden-in-dev"],
        "output_validator": ["overridden-in-dev"],
    }


def test_end_to_end_development_taint_inheritance_non_dev_refusal_and_full_clearing_on_restart(tmp_path: Path) -> None:
    (job1, job2, job3), dependencies = _three_stage_jobs()
    cfg_path = _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"))
    clean_dev_cfg = load_config(cfg_path, profile="copilot-dev")

    # 1. Clean initial run: zero development_tainted flags anywhere
    first = GraphRunner(clean_dev_cfg, (job1, job2, job3), dependencies=dependencies).run(
        target_root=tmp_path, source_fingerprint="none",
    )
    run_id = first["run_id"]
    run_root = clean_dev_cfg.runtime.runs_dir / run_id
    for jid in ("job_stage1", "job_stage2", "job_stage3"):
        assert "development_tainted" not in _accepted_handoff(run_root, jid)

    artifact_path = _accepted_handoff(run_root, "job_stage1")["outputs"]["work.only"]["artifact"]["path"]
    replacement_file = tmp_path / OVERRIDE_DIRECTORY / "job_stage2" / "edited.json"
    replacement_file.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(replacement_file, {"schema": "appsec-review/stage1-payload/1", "message": "delta-check"})

    # 2. Delta job_stage2 input and rerun in copilot-dev:
    #    - job_stage1 is REUSED (untainted)
    #    - job_stage2 RUNS and gets development_tainted = True
    #    - job_stage3 (no overrides of its own) PROCEEDS FINE and temporarily INHERITS development_tainted = True!
    override_toml = (
        "[[jobs.job_stage2.development.input_overrides]]\n"
        'producer = "job_stage1"\n'
        'output_kind = "stage1_payload"\n'
        f'artifact = "{artifact_path}"\n'
        f'replacement = "{OVERRIDE_DIRECTORY}/job_stage2/edited.json"\n'
    )
    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"), dev_overrides_toml=override_toml)
    override_cfg = load_config(cfg_path, profile="copilot-dev")
    plan2 = plan_repair(override_cfg, run_root, (job1, job2, job3), "none", dependencies=dependencies)
    assert plan2["admissible"], plan2["refusals"]
    assert {row["job_id"]: row["action"] for row in plan2["decisions"]} == {
        "job_stage1": "REUSE",
        "job_stage2": "RUN",
        "job_stage3": "INVALIDATE",
    }
    admit_repair(override_cfg, run_root, (job1, job2, job3), plan2, dependencies=dependencies)
    second = GraphRunner(override_cfg, (job1, job2, job3), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none",
    )
    assert second["jobs"]["job_stage1"]["decision"]["action"] == "REUSE"
    assert second["jobs"]["job_stage2"]["decision"]["action"] == "RUN"
    assert second["jobs"]["job_stage3"]["decision"]["action"] == "INVALIDATE"
    assert _accepted_handoff(run_root, "job_stage1")["attempt_id"] == "attempt_0001"
    assert _accepted_handoff(run_root, "job_stage2")["attempt_id"] == "attempt_0002"
    assert _accepted_handoff(run_root, "job_stage3")["attempt_id"] == "attempt_0002"

    h1_tainted = _accepted_handoff(run_root, "job_stage1")
    h2_tainted = _accepted_handoff(run_root, "job_stage2")
    h3_tainted = _accepted_handoff(run_root, "job_stage3")
    assert "development_tainted" not in h1_tainted
    assert h2_tainted.get("development_tainted") is True
    assert h3_tainted.get("development_tainted") is True
    stage3_out = run_root / h3_tainted["outputs"]["work.only"]["artifact"]["path"]
    assert json.loads(stage3_out.read_bytes())["final"] == "stage3<-stage2:delta-check"

    # 3. Non-dev profile refuses reusing or consuming development_tainted handoffs
    from dataclasses import replace as dc_replace
    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"), dev_overrides_toml="")
    cleared_cfg = load_config(cfg_path, profile="copilot-dev")
    non_dev_cfg = dc_replace(cleared_cfg, profile="copilot")
    non_dev_decisions = {
        d.job_id: d
        for d in ResumePlanner(
            non_dev_cfg, run_root, (job1, job2, job3), "none", dependencies=dependencies
        ).plan()
    }
    assert non_dev_decisions["job_stage1"].action == "REUSE"
    assert non_dev_decisions["job_stage2"].action == "RUN"
    assert any("development-tainted" in r for r in non_dev_decisions["job_stage2"].reasons)
    assert non_dev_decisions["job_stage3"].action == "INVALIDATE"
    stage2_digest = json.loads((run_root / "data/jobs/job_stage2/latest.json").read_bytes())["handoff_sha256"]
    plan_non_dev = plan_repair(cleared_cfg, run_root, (job1, job2, job3), "none", dependencies=dependencies)
    admit_repair(cleared_cfg, run_root, (job1, job2, job3), plan_non_dev, dependencies=dependencies)
    with pytest.raises(ValueError, match="development-tainted"):
        JobRunner(non_dev_cfg).begin_attempt(
            job3,
            run_id=run_id,
            target_root=tmp_path,
            source_fingerprint="none",
            upstream_handoffs={"job_stage2": stage2_digest},
        )

    # 4. Clear override and rerun in copilot-dev: job_stage2 and job_stage3 both re-run cleanly and ALL dev flags clear!
    plan3 = plan_repair(cleared_cfg, run_root, (job1, job2, job3), "none", dependencies=dependencies)
    assert plan3["admissible"], plan3["refusals"]
    assert {row["job_id"]: row["action"] for row in plan3["decisions"]} == {
        "job_stage1": "REUSE",
        "job_stage2": "RUN",
        "job_stage3": "INVALIDATE",
    }
    admit_repair(cleared_cfg, run_root, (job1, job2, job3), plan3, dependencies=dependencies)
    third = GraphRunner(cleared_cfg, (job1, job2, job3), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none",
    )
    assert third["jobs"]["job_stage1"]["decision"]["action"] == "REUSE"
    assert third["jobs"]["job_stage2"]["decision"]["action"] == "RUN"
    assert third["jobs"]["job_stage3"]["decision"]["action"] == "INVALIDATE"
    assert _accepted_handoff(run_root, "job_stage1")["attempt_id"] == "attempt_0001"
    assert _accepted_handoff(run_root, "job_stage2")["attempt_id"] == "attempt_0003"
    assert _accepted_handoff(run_root, "job_stage3")["attempt_id"] == "attempt_0004"
    for jid in ("job_stage1", "job_stage2", "job_stage3"):
        clean_handoff = _accepted_handoff(run_root, jid)
        assert "development_tainted" not in clean_handoff, f"{jid} retained development_tainted after clearing override"
    stage3_clean_out = run_root / _accepted_handoff(run_root, "job_stage3")["outputs"]["work.only"]["artifact"]["path"]
    assert json.loads(stage3_clean_out.read_bytes())["final"] == "stage3<-stage2:original-from-stage1"

def test_restart_from_top_clears_all_development_tainted_flags(tmp_path: Path) -> None:
    (job1, job2, job3), dependencies = _three_stage_jobs()
    cfg_path = _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"))
    clean_dev_cfg = load_config(cfg_path, profile="copilot-dev")
    first = GraphRunner(clean_dev_cfg, (job1, job2, job3), dependencies=dependencies).run(
        target_root=tmp_path, source_fingerprint="none",
    )
    run_id = first["run_id"]
    run_root = clean_dev_cfg.runtime.runs_dir / run_id
    artifact_path = _accepted_handoff(run_root, "job_stage1")["outputs"]["work.only"]["artifact"]["path"]

    replacement_file = tmp_path / OVERRIDE_DIRECTORY / "job_stage2" / "edited.json"
    replacement_file.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(replacement_file, {"schema": "appsec-review/stage1-payload/1", "message": "delta-check"})
    override_toml = (
        "[[jobs.job_stage2.development.input_overrides]]\n"
        'producer = "job_stage1"\n'
        'output_kind = "stage1_payload"\n'
        f'artifact = "{artifact_path}"\n'
        f'replacement = "{OVERRIDE_DIRECTORY}/job_stage2/edited.json"\n'
    )
    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"), dev_overrides_toml=override_toml)
    tainted_cfg = load_config(cfg_path, profile="copilot-dev")
    plan_taint = plan_repair(tainted_cfg, run_root, (job1, job2, job3), "none", dependencies=dependencies)
    admit_repair(tainted_cfg, run_root, (job1, job2, job3), plan_taint, dependencies=dependencies)
    GraphRunner(tainted_cfg, (job1, job2, job3), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none",
    )
    assert _accepted_handoff(run_root, "job_stage2").get("development_tainted") is True
    assert _accepted_handoff(run_root, "job_stage3").get("development_tainted") is True

    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2", "job_stage3"), dev_overrides_toml="")
    restart_cfg = load_config(cfg_path, profile="copilot-dev")
    plan_restart = plan_repair(
        restart_cfg, run_root, (job1, job2, job3), "none",
        dependencies=dependencies, force_from="job_stage1",
    )
    assert plan_restart["admissible"], plan_restart["refusals"]
    assert {row["job_id"]: row["action"] for row in plan_restart["decisions"]} == {
        "job_stage1": "RUN",
        "job_stage2": "INVALIDATE",
        "job_stage3": "INVALIDATE",
    }
    admit_repair(restart_cfg, run_root, (job1, job2, job3), plan_restart, dependencies=dependencies)
    restarted = GraphRunner(restart_cfg, (job1, job2, job3), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none", force_from="job_stage1",
    )
    assert restarted["jobs"]["job_stage1"]["decision"]["action"] == "RUN"
    assert restarted["jobs"]["job_stage2"]["decision"]["action"] == "INVALIDATE"
    assert restarted["jobs"]["job_stage3"]["decision"]["action"] == "INVALIDATE"
    for jid in ("job_stage1", "job_stage2", "job_stage3"):
        assert "development_tainted" not in _accepted_handoff(run_root, jid)
    assert _accepted_handoff(run_root, "job_stage1")["attempt_id"] == "attempt_0002"
    assert _accepted_handoff(run_root, "job_stage2")["attempt_id"] == "attempt_0003"
    assert _accepted_handoff(run_root, "job_stage3")["attempt_id"] == "attempt_0003"


def test_shared_artifacts_never_reuse_development_tainted_computation_after_clean_restart(tmp_path: Path) -> None:
    (job1, _, _), _ = _three_stage_jobs()
    shared_decl = artifact_only(
        "cache",
        "work",
        "inventory",
        RECEIPT_SCHEMA,
        "Shared fixture receipt",
        artifacts=("data/jobs/job_stage2/attempts/*/shared/fixture/*.json",),
        reason="unit regression fixture",
    )
    executions: list[str] = []

    def run_shared_stage2(unit):
        up = accepted_upstream(unit.job.run_root, "job_stage1")
        ref = up.handoff["outputs"]["work.only"]["artifact"]
        src = input_file(unit.job.run_root, "job_stage1", "stage1_payload", ref)
        msg = json.loads(src.path.read_bytes())["message"]
        owner = SharedArtifacts.for_job(unit.job)
        key = "f" * 64
        hit = owner.lookup("fixture", key)
        if hit is None:
            executions.append(f"{unit.job.attempt_id}:{msg}")
            computed_ref = owner.computed(
                "fixture", key, put_bytes(unit.job.run_root, msg.encode("utf-8")),
                computation={"constant": "key"},
            )
        else:
            _, computed_ref = hit
        return {"artifact": computed_ref, "terminal_status": "SUCCEEDED"}

    u2 = (Unit("work.only", run_shared_stage2),)
    job2 = Job(
        job_id="job_stage2",
        name="job_stage2",
        handler=UnitExecutor(u2).execute,
        units=u2,
        datasets=(shared_decl,),
        consumes=("job_stage1",),
        contract=JobContract(
            inputs=accepted_inputs(
                "job_stage1",
                job1.datasets,
                availability=Availability.REQUIRED,
                missing=MissingPolicy.REJECT,
            ),
        ),
        strict_gaps=True,
    )
    dependencies = {"job_stage1": (), "job_stage2": ("job_stage1",)}
    cfg_path = _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2"))
    base_cfg = load_config(cfg_path, profile="copilot-dev")
    r1 = JobRunner(base_cfg).run(job1, target_root=tmp_path, source_fingerprint="none")
    run_id = r1["status"]["run_id"]
    run_root = base_cfg.runtime.runs_dir / run_id
    artifact_path = _accepted_handoff(run_root, "job_stage1")["outputs"]["work.only"]["artifact"]["path"]

    replacement_file = tmp_path / OVERRIDE_DIRECTORY / "job_stage2" / "edited.json"
    replacement_file.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(replacement_file, {"schema": "appsec-review/stage1-payload/1", "message": "tainted-bytes"})
    override_toml = (
        "[[jobs.job_stage2.development.input_overrides]]\n"
        'producer = "job_stage1"\n'
        'output_kind = "stage1_payload"\n'
        f'artifact = "{artifact_path}"\n'
        f'replacement = "{OVERRIDE_DIRECTORY}/job_stage2/edited.json"\n'
    )
    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2"), dev_overrides_toml=override_toml)
    tainted_cfg = load_config(cfg_path, profile="copilot-dev")
    plan1 = plan_repair(tainted_cfg, run_root, (job1, job2), "none", dependencies=dependencies)
    admit_repair(tainted_cfg, run_root, (job1, job2), plan1, dependencies=dependencies)
    GraphRunner(tainted_cfg, (job1, job2), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none",
    )

    _write_pipeline_configs(tmp_path, ("job_stage1", "job_stage2"), dev_overrides_toml="")
    clean_cfg = load_config(cfg_path, profile="copilot-dev")
    plan2 = plan_repair(clean_cfg, run_root, (job1, job2), "none", dependencies=dependencies)
    admit_repair(clean_cfg, run_root, (job1, job2), plan2, dependencies=dependencies)
    GraphRunner(clean_cfg, (job1, job2), dependencies=dependencies).run(
        run_id=run_id, target_root=tmp_path, source_fingerprint="none",
    )
    assert executions == ["attempt_0001:tainted-bytes", "attempt_0002:original-from-stage1"]
