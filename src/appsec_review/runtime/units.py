from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import traceback
from types import MappingProxyType
from typing import Any, Callable, Protocol

from appsec_review.runtime.job import JobContext
from appsec_review.storage import atomic_json
from appsec_review.observability import EventLog


@dataclass(frozen=True, slots=True)
class UnitContext:
    job: JobContext
    unit_id: str
    step_id: str
    task_id: str
    unit_root: Path
    outputs: Mapping[str, Mapping[str, Any]]

    def output(self, unit_id: str) -> Mapping[str, Any]:
        try:
            return self.outputs[unit_id]
        except KeyError as exc:
            raise KeyError(f"unit output is unavailable: {unit_id}") from exc


class UnitHandler(Protocol):
    def __call__(self, context: UnitContext) -> Mapping[str, Any]: ...


class UnitValidator(Protocol):
    def __call__(self, context: UnitContext, result: Mapping[str, Any] | None) -> None: ...


@dataclass(frozen=True, slots=True)
class Unit:
    unit_id: str
    handler: UnitHandler
    dependencies: tuple[str, ...] = ()
    input_validators: tuple[UnitValidator, ...] = ()
    output_validators: tuple[UnitValidator, ...] = ()

    def __post_init__(self) -> None:
        parts = self.unit_id.split(".")
        if len(parts) != 2 or not all(part and part.replace("_", "a").isalnum() for part in parts):
            raise ValueError(f"unit id must be <step>.<task>: {self.unit_id}")
        if self.unit_id in self.dependencies:
            raise ValueError(f"unit cannot depend on itself: {self.unit_id}")


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class UnitExecutor:
    """Execute a small task DAG while preserving independent branches and receipts."""

    def __init__(self, units: tuple[Unit, ...]):
        if not units:
            raise ValueError("a job must contain at least one unit")
        self.units = units
        ids = [unit.unit_id for unit in units]
        if len(ids) != len(set(ids)):
            raise ValueError("unit ids must be unique")
        unknown = sorted({dep for unit in units for dep in unit.dependencies} - set(ids))
        if unknown:
            raise ValueError(f"unknown unit dependencies: {unknown}")
        pending = set(ids)
        resolved: set[str] = set()
        while pending:
            ready = {unit.unit_id for unit in units if unit.unit_id in pending and set(unit.dependencies) <= resolved}
            if not ready:
                raise ValueError(f"unit dependency cycle: {sorted(pending)}")
            pending -= ready
            resolved |= ready

    def execute(self, context: JobContext) -> dict[str, Any]:
        outputs: dict[str, Mapping[str, Any]] = {}
        receipts: dict[str, dict[str, Any]] = {}
        step_started: dict[str, datetime] = {}
        remaining = {step: sum(1 for unit in self.units if unit.unit_id.startswith(step + "."))
                     for step in {unit.unit_id.split(".")[0] for unit in self.units}}
        for unit in self.units:
            step_id, task_id = unit.unit_id.split(".")
            if step_id not in step_started:
                step_started[step_id] = datetime.now(timezone.utc)
                context.events.write("STEP_STARTED", unit_id=f"{step_id}.-")
            unit_root = context.attempt_root / "steps" / step_id / "tasks" / task_id
            unit_root.mkdir(parents=True, exist_ok=True)
            unit_events = EventLog(unit_root / "logs" / "events.jsonl")
            blocked_by = [dep for dep in unit.dependencies if receipts[dep]["status"] != "SUCCEEDED"]
            started = _stamp()
            if blocked_by:
                receipt = {
                    "unit_id": unit.unit_id,
                    "step_id": step_id,
                    "task_id": task_id,
                    "status": "SKIPPED",
                    "started_at": started,
                    "completed_at": _stamp(),
                    "dependencies": list(unit.dependencies),
                    "blocked_by": blocked_by,
                }
                atomic_json(unit_root / "status.json", receipt)
                receipts[unit.unit_id] = receipt
                context.events.write("TASK_SKIPPED", unit_id=unit.unit_id, blocked_by=blocked_by)
                unit_events.write("TASK_SKIPPED", unit_id=unit.unit_id, blocked_by=blocked_by)
                remaining[step_id] -= 1
                if remaining[step_id] == 0:
                    duration = max(0, int((datetime.now(timezone.utc) - step_started[step_id]).total_seconds() * 1000))
                    context.events.write("STEP_FAILED", unit_id=f"{step_id}.-",
                                         completion_status="FAILED", duration_ms=duration)
                continue
            unit_context = UnitContext(
                job=context,
                unit_id=unit.unit_id,
                step_id=step_id,
                task_id=task_id,
                unit_root=unit_root,
                outputs=MappingProxyType(outputs),
            )
            running = {
                "unit_id": unit.unit_id,
                "step_id": step_id,
                "task_id": task_id,
                "status": "RUNNING",
                "started_at": started,
                "dependencies": list(unit.dependencies),
            }
            atomic_json(unit_root / "status.json", running)
            context.events.write("TASK_STARTED", unit_id=unit.unit_id)
            unit_events.write("TASK_STARTED", unit_id=unit.unit_id)
            try:
                for validator in unit.input_validators:
                    validator(unit_context, None)
                result = dict(unit.handler(unit_context))
                for validator in unit.output_validators:
                    validator(unit_context, result)
                atomic_json(unit_root / "result.json", result)
                outputs[unit.unit_id] = result
                receipt = {**running, "status": "SUCCEEDED", "completed_at": _stamp()}
                atomic_json(unit_root / "status.json", receipt)
                receipts[unit.unit_id] = receipt
                disposition = result.get("terminal_status")
                terminal_event = ("TASK_COMPLETED_WITH_GAPS"
                                  if disposition not in {None, "SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}
                                  else "TASK_SUCCEEDED")
                context.events.write(terminal_event, unit_id=unit.unit_id,
                                     disposition=disposition)
                unit_events.write(terminal_event, unit_id=unit.unit_id,
                                  disposition=disposition)
            except Exception as exc:
                (unit_root / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
                receipt = {
                    **running,
                    "status": "FAILED",
                    "completed_at": _stamp(),
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                }
                atomic_json(unit_root / "status.json", receipt)
                receipts[unit.unit_id] = receipt
                context.events.write("TASK_FAILED", unit_id=unit.unit_id, error_type=type(exc).__name__)
                unit_events.write("TASK_FAILED", unit_id=unit.unit_id, error_type=type(exc).__name__)
            remaining[step_id] -= 1
            if remaining[step_id] == 0:
                states = [receipts[item.unit_id]["status"] for item in self.units
                          if item.unit_id.startswith(step_id + ".")]
                dispositions = [str(outputs[item.unit_id].get("terminal_status")) for item in self.units
                                if item.unit_id.startswith(step_id + ".") and item.unit_id in outputs and
                                outputs[item.unit_id].get("terminal_status") is not None]
                if "FAILED" in states or "SKIPPED" in states:
                    terminal = "FAILED"
                elif any(value not in {"SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"} for value in dispositions):
                    terminal = "COMPLETED_WITH_GAPS"
                else:
                    terminal = "SUCCEEDED"
                duration = max(0, int((datetime.now(timezone.utc) - step_started[step_id]).total_seconds() * 1000))
                context.events.write(f"STEP_{terminal}", unit_id=f"{step_id}.-",
                                     completion_status=terminal, duration_ms=duration,
                                     dispositions=dispositions)

        failed = [unit_id for unit_id, receipt in receipts.items() if receipt["status"] == "FAILED"]
        skipped = [unit_id for unit_id, receipt in receipts.items() if receipt["status"] == "SKIPPED"]
        steps: dict[str, str] = {}
        for unit in self.units:
            step_id = unit.unit_id.split(".")[0]
            states = [receipts[item.unit_id]["status"] for item in self.units if item.unit_id.startswith(step_id + ".")]
            steps[step_id] = "FAILED" if "FAILED" in states or "SKIPPED" in states else "SUCCEEDED"
        completion = "FAILED" if failed or skipped else "SUCCEEDED"
        dispositions = [str(output.get("terminal_status")) for output in outputs.values()
                        if output.get("terminal_status") is not None]
        if completion == "SUCCEEDED" and any(value not in {"SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}
                                               for value in dispositions):
            completion = "COMPLETED_WITH_GAPS"
        return {
            "schema": "appsec-review/unit-execution/1",
            "status": completion,
            "steps": steps,
            "units": receipts,
            "outputs": outputs,
            "failed_units": failed,
            "skipped_units": skipped,
        }

    @staticmethod
    def summarize(units: tuple[Unit, ...], receipts: Mapping[str, Mapping[str, Any]],
                  outputs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        failed = [unit_id for unit_id, receipt in receipts.items() if receipt["status"] == "FAILED"]
        skipped = [unit_id for unit_id, receipt in receipts.items() if receipt["status"] == "SKIPPED"]
        steps: dict[str, str] = {}
        for unit in units:
            step_id = unit.unit_id.split(".")[0]
            states = [receipts[item.unit_id]["status"] for item in units
                      if item.unit_id.startswith(step_id + ".")]
            steps[step_id] = "FAILED" if "FAILED" in states or "SKIPPED" in states else "SUCCEEDED"
        completion = "FAILED" if failed or skipped else "SUCCEEDED"
        dispositions = [str(output.get("terminal_status")) for output in outputs.values()
                        if output.get("terminal_status") is not None]
        if completion == "SUCCEEDED" and any(value not in {"SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}
                                               for value in dispositions):
            completion = "COMPLETED_WITH_GAPS"
        return {
            "schema": "appsec-review/unit-execution/2",
            "status": completion,
            "steps": steps,
            "units": dict(receipts),
            "outputs": dict(outputs),
            "failed_units": failed,
            "skipped_units": skipped,
        }
