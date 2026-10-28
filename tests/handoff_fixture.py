"""Publish structurally complete synthetic handoffs without weakening production admission."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.interchange import (
    ArtifactReference, HANDOFF_SCHEMA,
    decode_handoff, handoff_input_projection, input_set_sha256,
)
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.handoff import (
    build_outcomes, collect_artifacts, execution_status, frozen_job_config_sha256,
)
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256


def _freeze_configuration(run_root: Path, job_id: str) -> tuple[str, str]:
    from appsec_review.config import load_config
    from appsec_review.runtime.runner import JobRunner

    directory = run_root / "data" / "configuration"
    resolved_path = directory / "resolved.json"
    if not resolved_path.is_file():
        candidates = [parent / "appsec-review.toml" for parent in
                      (run_root, run_root.parent, run_root.parent.parent)]
        source = next((path for path in candidates if path.is_file()), None)
        if source is not None:
            JobRunner(load_config(source))._bind_configuration(run_root)
        else:
            config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
            document = json.loads(config.resolved_json)
            for name in ("fixture", "post", "live", "job_fixture", "branch_a", "branch_b",
                         "retrieval_producer", "specialized_producer", "consumer", job_id):
                document["jobs"].setdefault(name, {"name": name, "workers": 1, "settings": {}, "steps": {}})
            atomic_bytes(directory / "appsec-review.toml", config.source_path.read_bytes())
            atomic_bytes(resolved_path, canonical_json(document))
            atomic_json(directory / "manifest.json", {
                "schema": "appsec-review/run-configuration/2",
                "source_sha256": file_sha256(directory / "appsec-review.toml"),
                "resolved_sha256": file_sha256(resolved_path),
                "resolved": {"path": "resolved.json", "sha256": file_sha256(resolved_path)},
            })
    document = json.loads(resolved_path.read_text(encoding="utf-8"))
    return file_sha256(resolved_path), frozen_job_config_sha256(document, job_id)


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
    unit_ids = []
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
        retain({"path": status_path.relative_to(run_root).as_posix(), "sha256": file_sha256(status_path)})
        unit_ids.append(outcome_unit_id)
    document = build_outcomes(run_root, run_id=run_root.name, job_id=job_id, attempt_id=attempt_id,
                              target_snapshot=snapshot, unit_ids=unit_ids)
    coverage = document["coverage"]
    outcomes_path = attempt / "outcomes.json"
    atomic_json(outcomes_path, document)
    outcomes = retain({"path": outcomes_path.relative_to(run_root).as_posix(),
                       "sha256": file_sha256(outcomes_path)}).as_dict()
    claim_path = attempt / "claim.json"
    prior_claim = json.loads(claim_path.read_text(encoding="utf-8")) if claim_path.is_file() else {}
    contract = prior_claim.get("dataset_contract", dataset_contract(
        job_id, sorted({unit_id.split(".")[0] for unit_id in unit_ids}), ()))
    resolved_config_sha256, job_config_sha256 = _freeze_configuration(run_root, job_id)
    atomic_json(claim_path, {
        **prior_claim, "run_id": run_root.name, "job_id": job_id, "attempt_id": attempt_id,
        "attempt_path": attempt.relative_to(run_root).as_posix(),
        "source_fingerprint": value.get("source_fingerprint", snapshot),
        "resolved_config_sha256": resolved_config_sha256, "input_identity": None,
        "dataset_contract": contract, "upstream_handoffs": dict(value.get("upstream_handoff_sha256", {})),
    })
    retain({"path": claim_path.relative_to(run_root).as_posix(), "sha256": file_sha256(claim_path)})
    result_path = attempt / "result.json"
    if not result_path.is_file():
        atomic_json(result_path, {"status": completion, "outputs": outputs})
    result = json.loads(result_path.read_text(encoding="utf-8"))
    for reference in collect_artifacts(run_root, result):
        retain(reference)
    retain({"path": result_path.relative_to(run_root).as_posix(), "sha256": file_sha256(result_path)})
    resolving_paths = {**value.get("resolving_paths", {}),
                       "attempt": attempt.relative_to(run_root).as_posix(),
                       "result": result_path.relative_to(run_root).as_posix()}
    handoff = {
        **dict(value), "schema": HANDOFF_SCHEMA, "run_id": run_root.name, "job_id": job_id,
        "attempt_id": attempt_id, "status": "ACCEPTED", "execution_status": execution_status(document),
        "completion_status": completion, "outputs": outputs, "artifacts": list(artifacts.values()),
        "upstream_handoff_sha256": dict(value.get("upstream_handoff_sha256", {})),
        "resolved_config_sha256": resolved_config_sha256,
        "job_config_sha256": job_config_sha256,
        "source_fingerprint": value.get("source_fingerprint", snapshot), "target_snapshot": snapshot,
        "implementation_identity": value.get("implementation_identity", "fixture-implementation/1"),
        "schema_identity": value.get("schema_identity", "fixture-schema/1"),
        "validation_identity": value.get("validation_identity", "fixture-validator/1"),
        "tool_identity": value.get("tool_identity", {"fixture": "1"}), "input_identity": None,
        "input_manifest": None, "dataset_contract_sha256": contract["sha256"],
        "coverage": coverage, "outcomes": outcomes,
        "resolving_paths": resolving_paths,
        "started_at": "2026-10-28T00:00:00+00:00", "completed_at": "2026-10-28T00:00:01+00:00",
    }
    handoff["input_set_sha256"] = input_set_sha256(handoff_input_projection(handoff))
    atomic_json(path, decode_handoff(handoff))
    return path
