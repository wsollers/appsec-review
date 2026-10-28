"""Publish structurally complete synthetic handoffs without weakening production admission."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.interchange import (
    ArtifactReference, CoverageSummary, HANDOFF_SCHEMA, OUTCOMES_SCHEMA, UnitOutcome,
    decode_handoff, handoff_input_projection, input_set_sha256,
)
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256


def write_fixture_handoff(run_root: Path, path: Path, value: Mapping[str, Any], *,
                          target_snapshot: str | None = None) -> Path:
    """Create real, hash-bound accounting bytes for a deliberately synthetic test producer."""
    relative = path.relative_to(run_root).parts
    job_id = value.get("job_id")
    if job_id is None:
        job_id = relative[relative.index("jobs") + 1]
    attempt_id = value.get("attempt_id", path.parent.name if "attempts" in relative else "fixture")
    attempt = (path.parent if "attempts" in relative else
               run_root / "data" / "jobs" / job_id / "attempts" / attempt_id)
    outputs = dict(value.get("outputs", {}))
    artifacts: dict[str, dict[str, Any]] = {}
    snapshots = set()

    def retain(reference):
        source = run_root / reference["path"]
        actual = {"path": reference["path"], "sha256": file_sha256(source),
                  "size_bytes": source.stat().st_size}
        if actual["sha256"] != reference["sha256"]:
            raise ValueError("synthetic handoff artifact changed")
        artifacts[actual["path"]] = actual
        if source.suffix == ".json":
            document = json.loads(source.read_text(encoding="utf-8"))
            if isinstance(document, dict):
                snapshot = document.get("target_snapshot", document.get("source_fingerprint"))
                if isinstance(snapshot, str):
                    snapshots.add(snapshot)
        return ArtifactReference(**actual)

    for reference in value.get("artifacts", ()):
        retain(reference)
    for output in outputs.values():
        if isinstance(output, Mapping):
            for key in ("artifact", "index_manifest"):
                reference = output.get(key)
                if isinstance(reference, Mapping) and "path" in reference and "sha256" in reference:
                    retain(reference)
    snapshot = target_snapshot or value.get("target_snapshot") or value.get("source_fingerprint")
    if snapshot is None:
        if len(snapshots) > 1:
            raise ValueError("synthetic handoff target snapshots disagree")
        snapshot = next(iter(snapshots), "fixture-snapshot")
    completion = value.get("completion_status", "SUCCEEDED")
    disposition = "partial" if completion == "COMPLETED_WITH_GAPS" else "complete"
    coverage = CoverageSummary(disposition, 0, False).as_dict()
    units = []
    for unit_id, output in outputs.items():
        step_id, task_id = unit_id.split(".", 1) if "." in unit_id else ("fixture", unit_id)
        outcome_unit_id = f"{step_id}.{task_id}"
        unit_path = attempt / "steps" / step_id / "tasks" / task_id
        result_path, status_path = unit_path / "result.json", unit_path / "status.json"
        atomic_json(result_path, output)
        result_reference = retain({"path": result_path.relative_to(run_root).as_posix(),
                                   "sha256": file_sha256(result_path)})
        atomic_json(status_path, {"unit_id": outcome_unit_id, "step_id": step_id, "task_id": task_id,
                                  "status": "SUCCEEDED",
                                  "result_sha256": result_reference.sha256})
        status_reference = retain({"path": status_path.relative_to(run_root).as_posix(),
                                   "sha256": file_sha256(status_path)})
        units.append(UnitOutcome(outcome_unit_id, "SUCCEEDED", None, disposition,
                                 result_reference, status_reference).as_dict())
    outcomes_path = attempt / "outcomes.json"
    atomic_json(outcomes_path, {
        "schema": OUTCOMES_SCHEMA, "run_id": run_root.name, "job_id": job_id,
        "attempt_id": attempt_id, "target_snapshot": snapshot, "units": units, "gaps": [], "coverage": coverage,
    })
    outcomes = retain({"path": outcomes_path.relative_to(run_root).as_posix(),
                       "sha256": file_sha256(outcomes_path)}).as_dict()
    claim_path = attempt / "claim.json"
    prior_claim = json.loads(claim_path.read_text(encoding="utf-8")) if claim_path.is_file() else {}
    contract = prior_claim.get("dataset_contract", dataset_contract(
        job_id, sorted({unit["unit_id"].split(".")[0] for unit in units}), ()))
    resolved_config_sha256 = value.get("resolved_config_sha256", "a" * 64)
    atomic_json(claim_path, {
        **prior_claim, "run_id": run_root.name, "job_id": job_id, "attempt_id": attempt_id,
        "attempt_path": attempt.relative_to(run_root).as_posix(),
        "source_fingerprint": value.get("source_fingerprint", snapshot),
        "resolved_config_sha256": resolved_config_sha256, "input_identity": None,
        "dataset_contract": contract, "upstream_handoffs": dict(value.get("upstream_handoff_sha256", {})),
    })
    retain({"path": claim_path.relative_to(run_root).as_posix(), "sha256": file_sha256(claim_path)})
    handoff = {
        **dict(value), "schema": HANDOFF_SCHEMA, "run_id": run_root.name, "job_id": job_id,
        "attempt_id": attempt_id, "status": "ACCEPTED", "execution_status": "SUCCEEDED",
        "completion_status": completion, "outputs": outputs, "artifacts": list(artifacts.values()),
        "upstream_handoff_sha256": dict(value.get("upstream_handoff_sha256", {})),
        "resolved_config_sha256": resolved_config_sha256,
        "job_config_sha256": value.get("job_config_sha256", "b" * 64),
        "source_fingerprint": value.get("source_fingerprint", snapshot), "target_snapshot": snapshot,
        "implementation_identity": value.get("implementation_identity", "fixture-implementation/1"),
        "schema_identity": value.get("schema_identity", "fixture-schema/1"),
        "validation_identity": value.get("validation_identity", "fixture-validator/1"),
        "tool_identity": value.get("tool_identity", {"fixture": "1"}), "input_identity": None,
        "input_manifest": None, "dataset_contract_sha256": contract["sha256"],
        "coverage": coverage, "outcomes": outcomes,
        "resolving_paths": dict(value.get("resolving_paths", {"attempt": attempt.relative_to(run_root).as_posix()})),
        "started_at": "2026-10-28T00:00:00+00:00", "completed_at": "2026-10-28T00:00:01+00:00",
    }
    handoff["input_set_sha256"] = input_set_sha256(handoff_input_projection(handoff))
    atomic_json(path, decode_handoff(handoff))
    return path
