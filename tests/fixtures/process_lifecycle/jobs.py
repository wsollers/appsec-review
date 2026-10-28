from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
import time

from appsec_review.config import load_config
from appsec_review.config.run_selection import RunConfigurations
from appsec_review.inference import ModelOutputError, ModelRequest, ModelResult
from appsec_review.inference.recording import recorded
from appsec_review.observability.spans import operation_span
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime import execution_safety as safety
from appsec_review.runtime.resources import ResourceAdmission, Reservation, process_identity
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json

from .support import MODULE, read, wait_for


def root():
    return Path(os.environ["APPSEC_PROCESS_ROOT"])


def config():
    return load_config(root() / "appsec-review.toml", profile="dev", overlay="")


def marker(name, **details):
    atomic_json(root() / f"{name}.json", {
        "pid": os.getpid(), "generation": process_identity(os.getpid()),
        "monotonic_ns": time.monotonic_ns(), "observed_ns": time.time_ns(), **details})


def fixture_job(handlers):
    units = tuple(Unit(f"work.{name}", handler) for name, handler in handlers)
    return Job("job_fixture", "fixture", UnitExecutor(units).execute, units=units)


def propagation(context):
    selected = RunConfigurations(config()).for_tags({
        "appsec/profile": "prod",
        "appsec/overlay": str(root() / "test" / "acceptance" / "capacity.toml"),
    })
    # The runner-created immutable claim is the observed worker input, not a parent assertion.
    claim = read(context.job.attempt_root / "claim.json")
    begin = time.monotonic_ns()
    if context.task_id == "first":
        marker("first-ready")
        wait_for(lambda: (root() / "release-first").exists(), timeout=20)
    end = time.monotonic_ns()
    return {"pid": os.getpid(), "begin": begin, "end": end,
            "claim_sha256": claim["resolved_config_sha256"],
            "profile": selected.profile, "layers": [dict(layer) for layer in selected.layers],
            "model": selected.job("job_target_analysis_plan").settings["model"]["model"],
            "resolved_sha256": selected.resolved_sha256}


def define_propagation():
    from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
    return _build_dagster_graph("propagation", (fixture_job((
        ("first", propagation), ("second", propagation))),), config(), JobRunner)


def model_unit(context):
    calls = 0

    def transport(request, *, timeout_seconds):
        nonlocal calls
        calls += 1
        if os.environ.get("APPSEC_REVIEW_MODEL_RECORDING") != "record":
            # A replay transport violation terminates the real worker, not a catchable fallback.
            os._exit(91)
        if calls == 1:
            raise ModelOutputError("fixture malformed first response")
        return ModelResult({"value": calls}, input_tokens=3, output_tokens=2, raw_response="{}")

    infer = recorded(transport)
    request = ModelRequest(
        schema="fixture/model/1", persona="fixture", role="fixture", guidance="fixture",
        summary={"target": str((context.job.target_root or context.job.repository_root / "target") / "main.py"),
                 "repository": str(context.job.repository_root), "run": str(context.job.run_root)},
        allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
        allowed_paths=("main.py",), allowed_build_units=(), provider="claude-cli",
        model="fixture-no-network", reasoning="low", max_input_tokens=20, max_output_tokens=20)
    if os.environ.get("APPSEC_PROCESS_REPLAY_MISS") == "1":
        request = replace(request, guidance="unrecorded")
    with operation_span(context.job.events, "fixture.model_sequence"):
        try:
            infer(request, timeout_seconds=2)
        except ModelOutputError as error:
            failure = {"type": type(error).__name__, "message": str(error)}
        else:
            raise AssertionError("recorded first failure was not preserved")
        results = [infer(request, timeout_seconds=2), infer(request, timeout_seconds=2)]
        if os.environ.get("APPSEC_PROCESS_REPLAY_EXHAUST") == "1":
            infer(request, timeout_seconds=2)
    return {"failure": failure, "proposals": [value.proposal for value in results],
            "tokens": [value.input_tokens for value in results]}


def define_recording():
    from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
    return _build_dagster_graph(
        "recording", (fixture_job((("first", model_unit),)),), config(), JobRunner)


def recovery_job(block):
    from appsec_review.jobs.job_target_catalog import build_job

    job = build_job()
    original = job.units[0]

    def interrupted(context):
        with ResourceAdmission(context.job.metadata_root, config().review_policy.resources).reserve(
                Reservation(1, 16), events=context.job.events,
                action="fixture.interrupted-worker", timeout_seconds=2) as lease:
            marker("worker-ready", lease=lease, run_id=context.job.run_id,
                   attempt=str(context.job.attempt_root))
            wait_for(lambda: (root() / "release-worker").exists(), timeout=40)
            return original.handler(context)

    return replace(job, units=(replace(original, handler=interrupted), *job.units[1:])) if block else job


def define_fail_fast():
    from dagster import RetryPolicy, job, op
    from appsec_review.orchestration.dagster.fail_fast import execution_definition, guarded_op

    selected = load_config(root() / "appsec-review.toml", profile="dev",
                           overlay=str(root() / "test" / "acceptance" / "capacity.toml"))

    @op
    @guarded_op(selected)
    def a_active(context):
        from appsec_review.observability.events import EventLog, PipelineLog
        events = EventLog(root() / "active-events.jsonl", PipelineLog(root() / "safety-run"), {
            "run_id": "fixture", "job_id": "job_fixture", "attempt_id": "attempt_0001"})
        with ResourceAdmission(selected.runtime.metadata_dir, selected.review_policy.resources).reserve(
                Reservation(1, 16), events=events, action="fixture.active", timeout_seconds=2):
            result = safety.run_process([sys.executable, "-m", MODULE, "tree"], timeout=25)
            deaths = {}
            for name in ("child-ready", "grandchild-ready"):
                identity = read(root() / f"{name}.json")
                stat = Path(f"/proc/{identity['pid']}/stat")
                deaths[name] = (not stat.exists() or
                                stat.read_text().split(") ", 1)[1].split()[0] in {"Z", "X"})
            if not all(deaths.values()):
                from appsec_review.runtime.resources import quarantine_resources
                quarantine_resources("fixture_owned_descendant_death_unconfirmed")
                raise RuntimeError("actual owned descendant death unconfirmed")
            marker("tree-returned", timed_out=result[3], deaths=deaths)

    @op(retry_policy=RetryPolicy(max_retries=2))
    @guarded_op(selected)
    def b_failure(context):
        wait_for(lambda: (root() / "grandchild-ready.json").exists(), timeout=20)
        safety.fail("fixture original failure", action="fixture.first")

    @op
    @guarded_op(selected)
    def z_queued(context):
        marker("incorrectly-admitted")

    @job(name="fail_fast", executor_def=execution_definition(selected))
    def dag():
        a_active()
        b_failure()
        z_queued()

    return dag


def define_sensor():
    from dagster import job, op
    from appsec_review.orchestration.dagster.fail_fast import execution_definition

    @op
    def a_blocked():
        marker("sensor-active")
        wait_for(lambda: (root() / "release-sensor").exists(), timeout=25)

    @op
    def b_failure():
        wait_for(lambda: (root() / "sensor-active.json").exists(), timeout=20)
        raise RuntimeError("fixture failure while sibling active")

    @job(name="wave1_review", executor_def=execution_definition(config()))
    def dag():
        a_blocked()
        b_failure()

    return dag
