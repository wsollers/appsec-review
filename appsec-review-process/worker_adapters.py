"""Narrow worker adapter protocol for the first Workstream B runtime slice.

Deterministic Python, supplied-human-decision, (B13) pinned-container and (B14) persona-invocation
adapters are executable here. Pool and controller adapters remain explicit future kinds and raise
before work.
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


class PinnedContainerAdapter:
    """B13 ``appsec-review/pinned-container-adapter/1.0``; see docs/pinned-container-adapter.md.

    ``runtime`` is the trusted, integrator-built ``container_execution.ContainerRuntime``; the
    container request is ``request.inputs["container_request"]``. No lifecycle worker uses it yet.
    """
    kind = "pinned_container"

    def __init__(self, runtime: Any) -> None:
        import container_execution
        container_execution.validate_runtime(runtime)
        self.runtime = runtime

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]:
        import container_execution
        if not isinstance(request.inputs, Mapping) or "container_request" not in request.inputs:
            raise container_execution.ContainerRequestError(
                "worker request inputs must carry 'container_request'")
        return container_execution.run_container(
            self.runtime, run_id=request.run_id, job_id=request.job_id,
            attempt_id=request.attempt_id, attempt_root=request.attempt_root,
            request=request.inputs["container_request"])


class PersonaInvocationAdapter:
    """B14 ``appsec-review/persona-invocation-adapter/1.0``; see docs/persona-invocation-adapter.md.

    ``runtime`` is the trusted, integrator-built ``persona_invocation.PersonaRuntime`` (it carries
    the invoker); the invocation request is ``request.inputs["persona_request"]``. Dispatch
    protocol only: no lifecycle persona job uses it yet.
    """
    kind = "persona"

    def __init__(self, runtime: Any) -> None:
        import persona_invocation
        persona_invocation.validate_runtime(runtime)
        self.runtime = runtime

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]:
        import persona_invocation
        if not isinstance(request.inputs, Mapping) or "persona_request" not in request.inputs:
            raise persona_invocation.PersonaRequestError(
                "worker request inputs must carry 'persona_request'")
        return persona_invocation.run_invocation(
            self.runtime, run_id=request.run_id, job_id=request.job_id,
            attempt_id=request.attempt_id, attempt_root=request.attempt_root,
            request=request.inputs["persona_request"])


class UnsupportedWorkerAdapter:
    def __init__(self, kind: str) -> None:
        self.kind = kind

    def execute(self, request: WorkerRequest) -> Mapping[str, Any]:
        raise NotImplementedError(f"{self.kind} adapter is specified but not implemented")
