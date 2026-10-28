"""Shared support for the final publication gate and final report tests.

``run_review_chain`` drives the real inference review with its scripted ``Infer`` double (no model),
then the gate, then the report, each through the application runner exactly as a graph run does. The
repository configuration's own ``[jobs.job_final_*]`` tables are used unchanged. Each chain carries the
environment it was built with, so several chains can live in one test module without interfering.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import gc
import json
import os
from pathlib import Path
import shutil
from typing import Any, Iterator, Mapping

from appsec_review.config import load_config
from appsec_review.runtime.runner import JobRunner
from tests.fixtures.inference_review.acceptance import JOB, ROOT, write_config, write_overlay, write_scenario
from tests.fixtures.inference_review.builder import FixtureRun, build_accepted_index_set

GATE = "job_final_publication_gate"
REPORT = "job_final_report_publication"


def job_tables(job_id: str) -> str:
    """The repository configuration's tables for one job, verbatim."""
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = text.index(f"[jobs.{job_id}]\n")
    lines: list[str] = []
    for line in text[start:].splitlines():
        if line.startswith("[") and job_id not in line:
            break
        if line.startswith("#") and lines and not lines[-1].strip():
            break
        lines.append(line)
    return "\n".join(lines) + "\n"


def write_chain_config(base: Path, runs_dir: Path) -> Path:
    return write_config(base, runs_dir, extra=job_tables(GATE) + job_tables(REPORT))


@contextmanager
def environment(values: Mapping[str, str]) -> Iterator[None]:
    saved = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_job(config: Path, job: Any, run_id: str, upstream: Mapping[str, str] | None = None,
            env: Mapping[str, str] | None = None) -> Mapping[str, Any]:
    with environment(env or {}):
        runner = JobRunner(load_config(config))
        claim = runner.begin_attempt(job, run_id=run_id, upstream_handoffs=dict(upstream or {}))
        for unit in job.units:
            runner.execute_or_reuse_unit(job, claim, unit.unit_id)
        return runner.finalize_attempt(job, claim)


def gate_job():
    from appsec_review.jobs.job_final_publication_gate import build_job
    return build_job(repository_root=ROOT)


def report_job():
    from appsec_review.jobs.job_final_report_publication import build_job
    return build_job(repository_root=ROOT)


def review_job():
    from tests.fixtures.inference_review.acceptance import build_registry
    return build_registry().build(JOB)


@dataclass
class Chain:
    base: Path
    fixture: FixtureRun
    config: Path
    env: Mapping[str, str]
    snapshot: Path | None = None
    review: Mapping[str, Any] = field(default_factory=dict)

    @property
    def run_root(self) -> Path:
        return self.fixture.run_root

    def unit_file(self, job_id: str, unit: str, name: str) -> Path:
        attempts = self.run_root / "data" / "jobs" / job_id / "attempts"
        step, task = unit.split(".")
        return sorted(attempts.iterdir())[-1] / "steps" / step / "tasks" / task / name

    def read(self, job_id: str, unit: str, name: str) -> Any:
        return json.loads(self.unit_file(job_id, unit, name).read_text(encoding="utf-8"))

    def handoff(self, job_id: str) -> dict[str, Any]:
        pointer = json.loads((self.run_root / "data" / "jobs" / job_id / "latest.json").read_text(encoding="utf-8"))
        return json.loads((self.run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))

    def pointer_sha(self, job_id: str) -> str:
        return json.loads((self.run_root / "data" / "jobs" / job_id / "latest.json").read_text(
            encoding="utf-8"))["handoff_sha256"]

    def upstream(self, job_id: str) -> dict[str, str]:
        """The upstream binding a graph run would pass; empty when the upstream has no accepted handoff."""
        return {job_id: self.pointer_sha(job_id)} if (self.run_root / "data" / "jobs" / job_id / "latest.json").exists() else {}

    def run_gate(self) -> Mapping[str, Any]:
        return run_job(self.config, gate_job(), self.fixture.run_id, self.upstream(JOB), self.env)

    def run_report(self) -> Mapping[str, Any]:
        return run_job(self.config, report_job(), self.fixture.run_id, self.upstream(GATE), self.env)

    def restore(self) -> None:
        """Put the run tree back exactly as it was when the chain finished (after a tamper test)."""
        assert self.snapshot is not None
        gc.collect()
        shutil.rmtree(self.base)
        shutil.copytree(self.snapshot, self.base)


def run_review_chain(base: Path, logs: Path, *, scenario: Mapping[str, Any] | None = None, teams: int = 1) -> Chain:
    """Inference review (scripted), then the gate and the report, with a snapshot for tamper tests."""
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True)
    logs.mkdir(parents=True, exist_ok=True)
    fixture = build_accepted_index_set(base)
    config = write_chain_config(base, fixture.runs_dir)
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(base, teams)),
           "APPSEC_C7_CONFIG": str(config),
           "APPSEC_C7_SCENARIO": str(write_scenario(
               logs, fixture.ids, calls=str(logs / "calls.jsonl"), captures=str(logs / "captures"),
               **dict(scenario or {})))}
    chain = Chain(base, fixture, config, env)
    chain.review = run_job(config, review_job(), fixture.run_id, env=env)
    chain.run_gate()
    chain.run_report()
    chain.snapshot = base.parent / f"{base.name}-snapshot"
    shutil.copytree(base, chain.snapshot)
    return chain
