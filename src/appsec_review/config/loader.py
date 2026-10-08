from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import tomllib
from types import MappingProxyType
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from urllib.parse import unquote, urlparse


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    repository_root: Path
    runs_dir: Path
    data_dir: Path
    metadata_dir: Path


@dataclass(frozen=True, slots=True)
class ScheduleConfig:
    enabled: bool
    cron: str
    timezone: str

    def __post_init__(self) -> None:
        if len(self.cron.split()) != 5:
            raise ValueError("schedule cron must have five fields")
        if self.timezone == "UTC":
            return
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown schedule timezone: {self.timezone}") from exc


@dataclass(frozen=True, slots=True)
class TaskConfig:
    task_id: str
    workers: int
    settings: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.task_id):
            raise ValueError(f"invalid task id: {self.task_id}")
        if self.workers < 1:
            raise ValueError("task workers must be positive")


@dataclass(frozen=True, slots=True)
class StepConfig:
    step_id: str
    workers: int
    settings: Mapping[str, Any]
    tasks: Mapping[str, TaskConfig]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.step_id):
            raise ValueError(f"invalid step id: {self.step_id}")
        if self.workers < 1:
            raise ValueError("step workers must be positive")

    def task(self, task_id: str) -> TaskConfig:
        try:
            return self.tasks[task_id]
        except KeyError as exc:
            raise KeyError(f"task is not configured: {self.step_id}.{task_id}") from exc


@dataclass(frozen=True, slots=True)
class JobConfig:
    job_id: str
    name: str
    workers: int
    schedule: ScheduleConfig | None
    settings: Mapping[str, Any]
    steps: Mapping[str, StepConfig]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"job_[a-z][a-z0-9_]*", self.job_id):
            raise ValueError(f"invalid job id: {self.job_id}")
        if not self.name.strip():
            raise ValueError("job name is required")
        if self.workers < 1:
            raise ValueError("workers must be positive")

    def step(self, step_id: str) -> StepConfig:
        try:
            return self.steps[step_id]
        except KeyError as exc:
            raise KeyError(f"step is not configured: {self.job_id}.{step_id}") from exc


@dataclass(frozen=True, slots=True)
class AppConfig:
    source_path: Path
    source_sha256: str
    runtime: RuntimeConfig
    jobs: Mapping[str, JobConfig]

    def job(self, job_id: str) -> JobConfig:
        try:
            return self.jobs[job_id]
        except KeyError as exc:
            raise KeyError(f"job is not configured: {job_id}") from exc


def _path(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty path")
    candidate = Path(value)
    return (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()


def load_config(path: str | Path = "appsec-review.toml") -> AppConfig:
    raw = str(path)
    parsed = urlparse(raw)
    windows_path = bool(re.match(r"^[A-Za-z]:[\\/]", raw))
    if parsed.scheme and parsed.scheme != "file" and not windows_path:
        raise ValueError(f"unsupported configuration URI scheme: {parsed.scheme}")
    if parsed.scheme == "file" and not windows_path:
        file_path = unquote(parsed.path)
        if parsed.netloc:
            file_path = f"//{parsed.netloc}{file_path}"
        if len(file_path) >= 3 and file_path[0] == "/" and file_path[2] == ":":
            file_path = file_path[1:]
        source = Path(file_path).resolve(strict=True)
    else:
        source = Path(path).resolve(strict=True)
    repository_root = source.parent
    source_bytes = source.read_bytes()
    document = tomllib.loads(source_bytes.decode("utf-8"))

    runtime_value = document.get("runtime")
    if not isinstance(runtime_value, dict):
        raise ValueError("[runtime] is required")
    runtime = RuntimeConfig(
        repository_root=repository_root,
        runs_dir=_path(repository_root, runtime_value.get("runs_dir"), "runtime.runs_dir"),
        data_dir=_path(repository_root, runtime_value.get("data_dir"), "runtime.data_dir"),
        metadata_dir=_path(
            repository_root,
            runtime_value.get("metadata_dir", "runs/metadata"),
            "runtime.metadata_dir",
        ),
    )
    if runtime.metadata_dir != runtime.runs_dir / "metadata":
        raise ValueError("runtime.metadata_dir must be the runs/metadata host metadata area")

    jobs_value = document.get("jobs")
    if not isinstance(jobs_value, dict) or not jobs_value:
        raise ValueError("[jobs] must contain at least one job")
    jobs: dict[str, JobConfig] = {}
    for job_id, value in jobs_value.items():
        if not isinstance(value, dict):
            raise ValueError(f"jobs.{job_id} must be a table")
        schedule_value = value.get("schedule")
        schedule = None
        if schedule_value is not None:
            if not isinstance(schedule_value, dict):
                raise ValueError(f"jobs.{job_id}.schedule must be a table")
            schedule = ScheduleConfig(
                enabled=bool(schedule_value.get("enabled", False)),
                cron=str(schedule_value.get("cron", "")),
                timezone=str(schedule_value.get("timezone", "")),
            )
        settings = value.get("settings", {})
        if not isinstance(settings, dict):
            raise ValueError(f"jobs.{job_id}.settings must be a table")
        steps_value = value.get("steps", {})
        if not isinstance(steps_value, dict):
            raise ValueError(f"jobs.{job_id}.steps must be a table")
        steps: dict[str, StepConfig] = {}
        for step_id, step_value in steps_value.items():
            if not isinstance(step_value, dict):
                raise ValueError(f"jobs.{job_id}.steps.{step_id} must be a table")
            step_settings = step_value.get("settings", {})
            tasks_value = step_value.get("tasks", {})
            if not isinstance(step_settings, dict) or not isinstance(tasks_value, dict):
                raise ValueError(f"jobs.{job_id}.steps.{step_id} settings/tasks must be tables")
            tasks: dict[str, TaskConfig] = {}
            for task_id, task_value in tasks_value.items():
                if not isinstance(task_value, dict):
                    raise ValueError(f"jobs.{job_id}.steps.{step_id}.tasks.{task_id} must be a table")
                task_settings = task_value.get("settings", {})
                if not isinstance(task_settings, dict):
                    raise ValueError(
                        f"jobs.{job_id}.steps.{step_id}.tasks.{task_id}.settings must be a table"
                    )
                tasks[task_id] = TaskConfig(
                    task_id=task_id,
                    workers=int(task_value.get("workers", 1)),
                    settings=MappingProxyType(dict(task_settings)),
                )
            steps[step_id] = StepConfig(
                step_id=step_id,
                workers=int(step_value.get("workers", 1)),
                settings=MappingProxyType(dict(step_settings)),
                tasks=MappingProxyType(tasks),
            )
        jobs[job_id] = JobConfig(
            job_id=job_id,
            name=str(value.get("name", "")),
            workers=int(value.get("workers", 1)),
            schedule=schedule,
            settings=MappingProxyType(dict(settings)),
            steps=MappingProxyType(steps),
        )
    return AppConfig(
        source_path=source,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        runtime=runtime,
        jobs=MappingProxyType(jobs),
    )
