"""Narrow worker adapter protocol for the first Workstream B runtime slice.

Only deterministic Python and supplied-human-decision adapters are executable here. Container,
persona, pool and controller adapters remain explicit future kinds and raise before work.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from execution_state import beneath


@dataclass(frozen=True)
class WorkerRequest:
    run_id: str
    job_id: str
    attempt_id: str
    attempt_root: Path
    inputs: Mapping[str, Any]


@runtime_checkable
class WorkerAdapter(Protocol):
    kind: str

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]: ...


class DeterministicPythonAdapter:
    kind = "deterministic_python"

    def __init__(self, worker: Callable[[WorkerRequest], Mapping[str, Any]]) -> None:
        if not callable(worker):
            raise TypeError("deterministic Python worker must be callable")
        self.worker = worker

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]:
        result = self.worker(request)
        if not isinstance(result, Mapping):
            raise TypeError("deterministic Python worker must return a mapping")
        return result


class SuppliedHumanDecisionAdapter:
    kind = "supplied_human_decision"

    def __init__(self, relative_path: str = "supplied/result.json") -> None:
        candidate = Path(relative_path)
        if (candidate.is_absolute() or re.match(r"^[A-Za-z]:", relative_path) or
                ".." in candidate.parts or "\\" in relative_path):
            raise ValueError("supplied result path must be a normalized relative path")
        self.relative_path = candidate

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]:
        path = beneath(request.attempt_root, request.attempt_root / self.relative_path)
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not value:
            raise ValueError("supplied human decision must be a non-empty JSON object")
        return value


class UnsupportedWorkerAdapter:
    def __init__(self, kind: str) -> None:
        self.kind = kind

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]:
        raise NotImplementedError(f"{self.kind} adapter is specified but not implemented")
