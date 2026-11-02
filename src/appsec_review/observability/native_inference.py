"""Receipt-backed native SBOM inference accounting, separate from inventories."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any

from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import INFERENCE_COUNTERS
from appsec_review.jobs.job_dependency_intelligence.native_inference_integration import (
    INFERENCE_UNITS, validate_inference_receipt,
)
from appsec_review.storage.shared import safe_path


def aggregate_native_inference(run_root: Path, records: list[Mapping[str, Any]], *,
                               accepted: Mapping[str, Any] | None = None) -> dict[str, Any]:
    sources: dict[tuple[str, str], Mapping[str, Any]] = {}
    reused: set[tuple[str, str]] = set()
    failed: set[tuple[str, str]] = set()
    invalid: set[tuple[str, str]] = set()
    reuse_handoffs: dict[str, set[str]] = {}
    historical: dict[str, Mapping[str, Any]] = {}
    gaps: list[str] = []
    inventory: dict[str, Mapping[str, Any]] = {}
    if accepted is not None and accepted.get("inference_metrics") is not None:
        try:
            references = accepted["inference_metrics"]
            if not isinstance(references, list) or len(references) != len(INFERENCE_UNITS):
                raise ValueError("accepted native inference metrics are incomplete")
            for unit_id, identity in zip(INFERENCE_UNITS, references, strict=True):
                inventory[unit_id] = validate_inference_receipt(
                    run_root, identity, source_fingerprint=accepted["source_fingerprint"],
                    attempt_id=accepted["attempt_id"], unit_id=unit_id)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            inventory.clear()
            gaps.append(f"native inference accepted receipts: {exc}")
    for event in records:
        if event.get("job_id") != "job_dependency_intelligence":
            continue
        details = event.get("details", {})
        unit = details.get("unit_id") or ".".join(
            str(event.get(field) or "") for field in ("step_id", "task_id"))
        attempt = str(event.get("attempt_id", ""))
        kind = event.get("event_type")
        if kind in {"NATIVE_INFERENCE_RESULT", "JOB_REUSED", "TASK_REUSED"} and (
                unit in INFERENCE_UNITS or kind != "TASK_REUSED"):
            if event.get("run_id") != run_root.name:
                gaps.append("native inference event run binding changed")
                if unit in INFERENCE_UNITS:
                    invalid.add((attempt, unit))
                else:
                    invalid.update((attempt, name) for name in INFERENCE_UNITS)
        if kind == "JOB_REUSED":
            reused.update((attempt, name) for name in INFERENCE_UNITS)
            digest = details.get("handoff_sha256")
            if not isinstance(digest, str):
                invalid.update((attempt, name) for name in INFERENCE_UNITS)
                gaps.append("native inference job reuse lacks a handoff binding")
            else:
                reuse_handoffs.setdefault(attempt, set()).add(digest)
            continue
        if unit not in INFERENCE_UNITS:
            if kind == "NATIVE_INFERENCE_RESULT":
                gaps.append("native inference result has an unexpected unit")
            continue
        key = (attempt, unit)
        if kind == "TASK_REUSED":
            reused.add(key)
        elif kind in {"TASK_FAILED", "STEP_FAILED"} or (
                kind == "OPERATION_COMPLETED" and details.get("terminal_status") == "FAILED"):
            failed.add(key)
        elif kind == "NATIVE_INFERENCE_RESULT":
            binding = {"metrics_receipt": details.get("metrics_receipt"),
                       "input_fingerprint": details.get("input_fingerprint")}
            if key in sources and sources[key] != binding:
                invalid.add(key)
                gaps.append("native inference has conflicting duplicate result receipts")
            if event.get("run_id") != run_root.name:
                invalid.add(key)
                gaps.append("native inference result run binding changed")
            sources[key] = binding
    rows = []
    for key in sorted(set(sources) | reused | failed | invalid):
        attempt, unit = key
        receipt = None
        if key not in invalid:
            try:
                prior = None
                if attempt in reuse_handoffs:
                    hashes = reuse_handoffs[attempt]
                    if len(hashes) != 1:
                        raise ValueError("native inference reuse has conflicting handoffs")
                    digest = next(iter(hashes))
                    if (accepted is not None and accepted.get("attempt_id") == attempt
                            and accepted.get("handoff_sha256") == digest):
                        if accepted.get("inference_metrics") is None:
                            if key not in sources and key not in failed:
                                continue
                            raise ValueError("native inference result is absent from reused publication")
                        prior = inventory
                    else:
                        if attempt not in historical:
                            from .telemetry import _native_sbom_accepted
                            publication = _native_sbom_accepted(run_root, historical=(attempt, digest))
                            if publication is None or publication.get("inference_metrics") is None:
                                if publication is not None and key not in sources and key not in failed:
                                    continue
                                raise ValueError("native inference reused publication is unavailable")
                            historical[attempt] = {
                                name: validate_inference_receipt(
                                    run_root, identity, unit_id=name, attempt_id=attempt,
                                    source_fingerprint=publication["source_fingerprint"])
                                for name, identity in zip(
                                    INFERENCE_UNITS, publication["inference_metrics"], strict=True)
                            }
                        prior = historical[attempt]
                if key in sources:
                    claim_path = safe_path(
                        run_root, f"data/jobs/job_dependency_intelligence/attempts/{attempt}/claim.json")
                    claim = json.loads(claim_path.read_bytes())
                    if (claim.get("schema") != "appsec-review/attempt-claim/1"
                            or claim.get("run_id") != run_root.name
                            or claim.get("job_id") != "job_dependency_intelligence"
                            or claim.get("attempt_id") != attempt):
                        raise ValueError("native inference attempt binding changed")
                    receipt = validate_inference_receipt(
                        run_root, sources[key]["metrics_receipt"], unit_id=unit,
                        attempt_id=attempt, source_fingerprint=claim["source_fingerprint"])
                    if receipt["input_fingerprint"] != sources[key]["input_fingerprint"]:
                        raise ValueError("native inference event fingerprint changed")
                elif unit in inventory and inventory[unit]["attempt_id"] == attempt:
                    receipt = inventory[unit]
                elif prior is not None and unit in prior:
                    receipt = prior[unit]
                else:
                    raise ValueError("native inference attempt has no verified receipt")
                if (unit in inventory and inventory[unit]["attempt_id"] == attempt
                        and receipt != inventory[unit]):
                    raise ValueError("native inference event conflicts with accepted inventory")
                if prior is not None and receipt != prior.get(unit):
                    raise ValueError("native inference event conflicts with reused publication")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                invalid.add(key)
                gaps.append(f"native inference receipt: {exc}")
        if key in invalid:
            receipt = None
        rows.append({
            "attempt_id": attempt, "unit_id": unit, "reused": key in reused,
            "fresh_work": key in sources or key in failed,
            "status": "INTEGRITY_ERROR" if key in invalid else "FAILED" if key in failed else
                      receipt["status"] if receipt is not None else "INCOMPLETE",
            "counters": receipt["counters"] if receipt is not None else None,
            "duration_ms": (receipt["duration_ms"] if receipt is not None
                            and (key in sources or key in failed) else None),
            "usage_complete": receipt["usage_complete"] if receipt is not None else False,
            "accounting_complete": receipt is not None,
        })
    if sources and not inventory:
        gaps.append("native inference has no accepted current inventory")
    return {
        "availability": "partial" if gaps else "available" if rows or inventory else "not_available",
        "accounting_complete": bool(rows or inventory) and not gaps,
        "attempts": rows, "current_inventory": {
            unit: {"attempt_id": receipt["attempt_id"], "status": receipt["status"],
                   "counters": receipt["counters"], "duration_ms": receipt["duration_ms"],
                   "usage_complete": receipt["usage_complete"]}
            for unit, receipt in inventory.items()
        },
        "fresh_work": sum(row["fresh_work"] for row in rows),
        "reused_stage_count": sum(row["reused"] for row in rows),
        "work_counters": {
            name: sum(row["counters"][name] for row in rows
                      if row["fresh_work"] and row["counters"] is not None)
            if all(row["accounting_complete"] for row in rows if row["fresh_work"]) else None
            for name in INFERENCE_COUNTERS
        } if rows else None,
        "gaps": sorted(set(gaps)),
    }
