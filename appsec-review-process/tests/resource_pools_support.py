"""Dagster jobs for the B15 resource-pool service tests. Imported only where Dagster exists.

The jobs are module-level so the multiprocess executor can reconstruct them in step processes.
Every pool id and limit comes from resource_pools; an op records its start and end in the file
named by POOL_TEST_LOG so the tests can measure real overlap across processes and runs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import time

from dagster import DagsterInstance, Failure, execute_job, job, multiprocess_executor, op, reconstructable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import resource_pools as rp  # noqa: E402

LOG_ENV = "POOL_TEST_LOG"
HOLD_SECONDS = 3.0
COORDINATION = rp.unassigned("coordination_only")


def mark(context, what):
    record = {"time": time.time(), "run_id": context.run_id, "op": context.op.name, "what": what,
              "pid": os.getpid()}
    with open(os.environ[LOG_ENV], "a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")


def holding_op(name, pool, seconds=HOLD_SECONDS, after=False):
    if after:
        @op(name=name, pool=pool)
        def held_after(context, previous):
            mark(context, "start"); time.sleep(seconds); mark(context, "end")
            return name
        return held_after

    @op(name=name, pool=pool)
    def held(context):
        mark(context, "start"); time.sleep(seconds); mark(context, "end")
        return name
    return held


# One more contender than each pool holds, all ready at once, executor cap out of the way.
CONTENDERS = {pool.pool_id: [holding_op(f"{pool.pool_id}_{index}", pool.pool_id) for index in range(pool.limit + 1)]
              for pool in rp.POOLS}


@job(executor_def=multiprocess_executor.configured({"max_concurrent": sum(rp.LIMITS.values()) + len(rp.POOLS)}))
def contention():
    for ops in CONTENDERS.values():
        for contender in ops:
            contender()


docker_queue = [holding_op(f"docker_queue_{index}", rp.DOCKER) for index in range(3)]
network_quick = holding_op("network_quick", rp.NETWORK, seconds=0.5)


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 4}))
def two_pools():
    for queued in docker_queue:
        queued()
    network_quick()


cpu_trio = [holding_op(f"cpu_capped_{index}", rp.CPU) for index in range(3)]


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 2}))
def executor_cap():
    # The pool would admit three; the executor cap of two is the outer limit and must still hold.
    for capped in cpu_trio:
        capped()


chain_first = holding_op("chain_first", rp.MEMORY)
chain_second = holding_op("chain_second", rp.MEMORY, after=True)


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 3}))
def engagement_chain():
    chain_second(chain_first())


@op(pool=rp.DOCKER)
def failing_step(context):
    mark(context, "start")
    raise Failure("injected failure while holding a docker slot")


@op(pool=rp.DOCKER)
def crashing_step(context):
    mark(context, "start")
    os.kill(os.getpid(), signal.SIGKILL)


long_hold = holding_op("long_hold", rp.DOCKER, seconds=120)


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 2}))
def failing():
    failing_step()


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 2}))
def crashing():
    crashing_step()


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 2}))
def long_running():
    long_hold()


docker_after = holding_op("docker_after", rp.DOCKER, seconds=0.2)


@job(executor_def=multiprocess_executor.configured({"max_concurrent": 2}))
def next_in_line():
    docker_after()


@op
def silent_default(context):
    return 1


@op(pool="gpu")
def unknown_pool(context):
    return 1


@op(pool=rp.CPU, tags=COORDINATION)
def pooled_and_unassigned(context):
    return 1


@op(tags={rp.TAG_POOL: rp.UNASSIGNED, rp.TAG_REASON: "because"})
def bad_reason(context):
    return 1


@op(tags={rp.TAG_REASON: "coordination_only"})
def reason_without_state(context):
    return 1


@op(tags=COORDINATION)
def recorded_unassigned(context):
    return 1


@job
def undeclared():
    silent_default(); unknown_pool(); pooled_and_unassigned(); bad_reason(); reason_without_state()
    recorded_unassigned()


JOBS = {item.name: item for item in (contention, two_pools, executor_cap, engagement_chain, failing, crashing,
                                     long_running, next_in_line)}


def run(job_name, instance, tags=None):
    return execute_job(reconstructable(JOBS[job_name]), instance=instance, raise_on_error=False, tags=tags or {})


def read_log(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]


def worker_main(home, job_name):
    """Run-worker stand-in for the tests that interrupt or kill a whole run."""
    with DagsterInstance.from_config(home) as instance:
        result = run(job_name, instance)
        print(result.run_id, result.success, flush=True)
