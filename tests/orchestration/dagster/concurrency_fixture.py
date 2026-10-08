from __future__ import annotations

import os
from pathlib import Path
import time

from appsec_review.config import load_config
from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime.runner import JobRunner


def _root() -> Path:
    return Path(os.environ["APPSEC_TEST_ROOT"])


def _touch(name: str) -> None:
    (_root() / name).write_text(str(time.time_ns()), encoding="utf-8")


def define_job():
    config = load_config(_root() / "appsec-review.toml")

    def slow_scan(context):
        _touch("slow-started")
        deadline = time.monotonic() + 90
        while not (_root() / "release-slow").exists():
            if time.monotonic() > deadline:
                raise RuntimeError("slow producer gate timed out")
            time.sleep(0.02)
        _touch("slow-completed")
        return {"tool_id": "tool-codeql-like", "terminal_status": "SUCCEEDED", "record_count": 1}

    def fast_scan(context):
        _touch("fast-scanned")
        return {"tool_id": "tool-gitleaks-like", "terminal_status": "SUCCEEDED", "record_count": 1}

    def passthrough(source: str):
        return lambda context: dict(context.output(source))

    def fast_index(context):
        _touch("fast-indexed")
        return {**context.output("fast.normalize"), "index_identity": {"shard_id": "fast"}}

    def slow_index(context):
        _touch("slow-indexed")
        return {**context.output("slow.normalize"), "index_identity": {"shard_id": "slow"}}

    def assemble(context):
        assert (_root() / "slow-completed").exists()
        assert (_root() / "fast-indexed").exists()
        _touch("manifest-assembled")
        return {"dispositions": [context.output("fast.index"), context.output("slow.index")]}

    def publish(context):
        _touch("handoff-published")
        return {"schema": "fixture/handoff/1", "dispositions": context.output("publication.assemble")["dispositions"]}

    units = (
        Unit("slow.scan", slow_scan),
        Unit("slow.normalize", passthrough("slow.scan"), ("slow.scan",)),
        Unit("slow.index", slow_index, ("slow.normalize",)),
        Unit("fast.scan", fast_scan),
        Unit("fast.normalize", passthrough("fast.scan"), ("fast.scan",)),
        Unit("fast.index", fast_index, ("fast.normalize",)),
        Unit("publication.assemble", assemble, ("slow.index", "fast.index")),
        Unit("publication.publish", publish, ("publication.assemble",)),
    )
    job = Job("job_fixture", "fixture", UnitExecutor(units).execute, units=units)
    return _build_dagster_graph("fixture", (job,), config, JobRunner)
