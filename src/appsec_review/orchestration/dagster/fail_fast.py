"""Dagster's public executor extension, with an opt-in immutable safety envelope."""
from __future__ import annotations

from functools import wraps
import json
import threading

from dagster import (
    Executor, Field, InitExecutorContext, Permissive, executor,
    multiprocess_executor, multiple_process_executor_requirements,
)

from appsec_review.config.run_selection import configurations
from appsec_review.runtime import execution_safety as safety


def _config_for(config, run):
    """The run's configuration: launch tags may select another profile or overlay (``run_selection``)."""
    return config.for_run(run) if hasattr(config, "for_run") else config


def _executor_settings(config) -> dict:
    return {
        "max_concurrent": config.dagster.max_concurrent,
        "retries": {"enabled": {}},
        "tag_concurrency_limits": [
            {"key": "appsec/pool", "value": pool, "limit": limit}
            for pool, limit in sorted(config.dagster.pool_limits.items())
        ],
    }


def _envelope(run, config):
    config = _config_for(config, run)
    value = run.run_config.get("execution", {}).get("config", {}).get("safety")
    if value is None:
        return None
    from appsec_review.config.native_dagster import native_execution_requested
    if native_execution_requested():
        raise ValueError("first-error execution requires commissioned native broker cancellation")
    envelope = safety.validate(value)
    if envelope["dagster_run_id"] != run.run_id:
        raise ValueError("execution safety UUID differs from this Dagster run")
    if run.tags.get("dagster/max_retries") != "0":
        raise ValueError("execution safety requires Dagster run retries disabled")
    if run.tags.get("appsec/safety_identity") != safety.identity(envelope):
        raise ValueError("execution safety correlation identity mismatch")
    expected = envelope["submission"]["configuration"]
    resolved = json.loads(config.resolved_json)
    profile = resolved["configuration_profile"]
    overlay = resolved.get("configuration_overlay", {})
    if (expected.get("base_sha256") != config.source_sha256
            or expected.get("profile") != profile["name"]
            or expected.get("profile_sha256") != profile.get("sha256")
            or expected.get("overlay_sha256") != overlay.get("sha256")
            or expected.get("compiler_target", "clang") != resolved.get("compiler_target", "clang")):
        raise ValueError("deployed configuration differs from the frozen safety envelope")
    return envelope


def guarded_op(config):
    def decorate(function):
        @wraps(function)
        def guarded(context, *args, **kwargs):
            envelope = _envelope(context.dagster_run, config)
            try:
                with safety.safety_scope(envelope), safety.operation(f"dagster.{context.op.name}"):
                    return function(context, *args, **kwargs)
            except safety.ReviewStopped as exc:
                # Cancellation must escape producer catches, then become a normal Dagster failure.
                raise RuntimeError(f"review stopped: {exc}") from exc
        return guarded
    return decorate


class SafetyExecutor(Executor):
    def __init__(self, delegate, config, rebuild=None):
        self.delegate = delegate
        self.config = config
        self.rebuild = rebuild

    @property
    def retries(self):
        return self.delegate.retries

    @property
    def step_dependency_config(self):
        return self.delegate.step_dependency_config

    def _delegate_for(self, config):
        """Pool limits are per-run executor limits, so a run's own overlay pools apply to it alone."""
        base = getattr(self.config, "base", self.config)
        if self.rebuild is None or _executor_settings(config) == _executor_settings(base):
            return self.delegate
        return self.rebuild(config)

    def execute(self, plan_context, execution_plan):
        config = _config_for(self.config, plan_context.dagster_run)
        delegate = self._delegate_for(config)
        envelope = _envelope(plan_context.dagster_run, config)
        if envelope is None:
            yield from delegate.execute(plan_context, execution_plan)
            return
        with safety.AdmissionGuardian(
                envelope, config.runtime.metadata_dir,
                resolved_config_sha256=config.resolved_sha256) as guardian:
            cancellation_requested = False
            cancellation_lock = threading.Lock()

            def cancel_once():
                nonlocal cancellation_requested
                with cancellation_lock:
                    if cancellation_requested:
                        return
                    cancellation_requested = True
                try:
                    guardian.cancellation("REQUESTED")
                    confirmed = plan_context.instance.run_launcher.terminate(plan_context.run_id)
                    guardian.cancellation("REQUEST_ACCEPTED" if confirmed else "UNCERTAIN")
                except Exception as exc:
                    guardian.state["cancellation"] = "UNCERTAIN"
                    guardian.fail(f"cancellation unconfirmed: {type(exc).__name__}")

            guardian.on_stop = cancel_once
            try:
                for event in delegate.execute(plan_context, execution_plan):
                    if (event.is_step_failure or event.is_resource_init_failure
                            or (event.is_engine_event and event.engine_event_data.error is not None)):
                        guardian.fail(f"Dagster {event.event_type_value}",
                                      action=event.step_key or "dagster")
                    if guardian.stopped.is_set() and not cancellation_requested:
                        cancel_once()
                    yield event
                if guardian.stopped.is_set():
                    raise RuntimeError("review stopped; retained leases require cleanup verification")
            except BaseException as exc:
                guardian.fail(f"{type(exc).__name__}: {exc}")
                cancel_once()
                raise


def execution_definition(config):
    configs = configurations(config)

    @executor(name="multiprocess", config_schema={"safety": Field(Permissive(), is_required=False)},
              requirements=multiple_process_executor_requirements())
    def create(context):
        guarded = context.executor_config.get("safety") is not None
        if guarded:
            safety.validate(context.executor_config["safety"])

        def build(selected):
            settings = _executor_settings(selected)
            if guarded:
                settings["retries"] = {"disabled": {}}
            return multiprocess_executor.executor_creation_fn(InitExecutorContext(
                context.job, multiprocess_executor, settings, context.instance))

        return SafetyExecutor(build(configs.base), configs, rebuild=build)

    return create
