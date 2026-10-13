"""Acceptance helpers: a runnable configuration and scenario for ``job_inference_security_review``.

``write_config`` copies the repository's own ``[jobs.job_inference_security_review]`` tables and
applies the slice 1 acceptance overrides (two hunted units, a team-package budget that leaves one
lane B package unlaunched, caps that exercise lane B triage). ``define_job`` is the reconstructable
Dagster entry point used by multiprocess acceptance runs; the injected ``Infer`` double is the
scripted :mod:`tests.fixtures.inference_review.fake_infer`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from tests.capture_fakes import build_capture_toml

ROOT = Path(__file__).resolve().parents[3]
JOB = "job_inference_security_review"
OVERRIDES = {
    "review_teams": 1, "hunt_max_units": 2, "hunt_max_claims_per_package": 2, "lead_budget_share": 0.9,
    "budget_team_packages": 10, "incomplete_gap_ratio": 0.4,
}


def job_tables(overrides: Mapping[str, Any] | None = None) -> str:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = text.index(f"[jobs.{JOB}]\n")
    lines = []
    for line in text[start:].splitlines():
        if line.startswith("[") and JOB not in line:
            break
        lines.append(line)
    body = "\n".join(lines) + "\n"
    for key, value in {**OVERRIDES, **dict(overrides or {})}.items():
        body, count = re.subn(rf"(?m)^{key} = .*$", f"{key} = {json.dumps(value)}", body)
        if count != 1:
            raise KeyError(f"override did not match exactly one setting: {key}")
    return body


def write_config(directory: Path, runs_dir: Path, *, overrides: Mapping[str, Any] | None = None,
                 extra: str = "") -> Path:
    """``extra`` is appended TOML (for example an additional model profile table)."""
    path = Path(directory) / "appsec-review.toml"
    path.write_text(f"""[runtime]
runs_dir = "{Path(runs_dir).as_posix()}"
data_dir = "data"
metadata_dir = "{(Path(runs_dir) / 'metadata').as_posix()}"

[orchestration.dagster]
executor = "multiprocess"
max_concurrent = 8

[orchestration.dagster.pools]
lifecycle = 1
application = 4
inference_teams = 2
inference_score = 1

{job_tables(overrides)}
{extra}
{build_capture_toml()}""", encoding="utf-8")
    return path


def write_overlay(directory: Path, review_teams: int) -> Path:
    path = Path(directory) / "capacity-overlay.toml"
    path.write_text(f"[jobs.{JOB}.settings.teams]\nreview_teams = {review_teams}\n", encoding="utf-8")
    return path


def write_scenario(directory: Path, ids: Mapping[str, str], **values: Any) -> Path:
    path = Path(directory) / "scenario.json"
    path.write_text(json.dumps({"ids": dict(ids), **values}, sort_keys=True), encoding="utf-8")
    return path


def build_registry():
    from appsec_review.jobs.job_inference_security_review import build_job
    from appsec_review.runtime.registry import JobRegistry
    from tests.fixtures.inference_review.fake_infer import ScriptedInfer

    registry = JobRegistry()
    registry.register(JOB, lambda: build_job(infer=ScriptedInfer.from_env(), repository_root=ROOT))
    return registry


def define_job():
    """Reconstructable entry point: configuration path and scenario come from the environment."""
    from appsec_review.orchestration.dagster import build_definitions

    return build_definitions(os.environ["APPSEC_C7_CONFIG"], registry=build_registry()).get_job_def(
        "inference_security_review")
