"""Dagster ``op`` that binds the pipeline log context for every step, so no worker has to.

    from pipeline_log_dagster import op      # in place of dagster's op

Each wrapped op, when it starts, sets the log context (run from the ``engagement_run_id`` run tag, job =
op name, step key, attempt = Dagster run id), writes a session banner once per Dagster run (reason
``intake`` for the phase1_intake job, ``resume`` otherwise), logs ``step start`` and ``step finished`` /
``step failed`` with the elapsed time, and clears the context on exit. Anything the step's process or
its children log afterwards (through ``pipeline_log``) carries that context; children inherit it through
the environment. Binding never raises and never changes the op's result or exceptions.
"""
from __future__ import annotations

import functools
import inspect
import time
from typing import Any

from dagster import op as _dagster_op

import pipeline_log

INTAKE_JOBS = frozenset({"phase1_intake"})


def _tag(context: Any, name: str) -> str | None:
    try:
        return context.dagster_run.tags.get(name)
    except Exception:
        return None


def _get(context: Any, *names: str) -> Any:
    """Attribute chain that tolerates a directly-invoked op (Dagster raises non-AttributeError there)."""
    value = context
    try:
        for name in names:
            value = getattr(value, name)
    except Exception:
        return None
    return value


def bind(context: Any) -> tuple[str | None, str, str]:
    """Set the pipeline-log context for this step; returns (run, job, attempt)."""
    run = _tag(context, "engagement_run_id")
    job = str(_get(context, "op", "name") or "step")
    attempt = str(_get(context, "run_id") or "")
    step = str(_get(context, "step_key") or job)
    try:
        pipeline_log.set_context(run=run, job=job, step=step, attempt=attempt, who=None)
        if run and attempt:
            job_name = _get(context, "job_name")
            reason = "intake" if job_name in INTAKE_JOBS else "resume"
            pipeline_log.banner_once(run, attempt, reason, dagster_job=job_name, dagster_run=attempt)
    except Exception:
        pass
    return run, job, attempt


def _wrap(fn):
    params = list(inspect.signature(fn).parameters)
    if not params or params[0] != "context":
        return fn                                   # nothing to bind from

    @functools.wraps(fn)
    def bound(context, *args, **kwargs):
        bind(context)
        started = time.time()
        pipeline_log.log("step start")
        try:
            result = fn(context, *args, **kwargs)
        except BaseException as exc:
            pipeline_log.log(f"step failed after {int(time.time() - started)}s: {type(exc).__name__}: {str(exc)[:300]}",
                             level="error")
            pipeline_log.flush()
            raise
        else:
            pipeline_log.log(f"step finished after {int(time.time() - started)}s")
            return result
        finally:
            pipeline_log.set_context(run=None, job=None, step=None, attempt=None, who=None)
    return bound


def op(*args: Any, **kwargs: Any):
    """Drop-in for ``dagster.op`` (bare or with arguments)."""
    if len(args) == 1 and callable(args[0]) and not kwargs:
        return _dagster_op(_wrap(args[0]))
    decorator = _dagster_op(*args, **kwargs)
    return lambda fn: decorator(_wrap(fn))
