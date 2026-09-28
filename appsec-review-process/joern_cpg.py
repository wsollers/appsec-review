"""Accepted offline Joern CPG producer using the pinned B13 container boundary."""
from __future__ import annotations

import tunables
import json

from datetime import datetime, timezone
from pathlib import Path
import threading
from typing import Any

import code_graph_evidence as core
import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import intake
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

JOB = "02-code-property-graph"
CONTRACT = "code-property-graph"
RESULT = "code-property-graph.json"
RECORDS = "code-property-graph.records.jsonl"   # one record per line; RESULT carries count and hash
RECEIPT = "b13-receipt.json"
SUMMARY = "code-property-graph-summary.md"
IMAGE_ID = "audit-native"
EXPORTER = ROOT.parent / "pipeline" / "joern_export_records.sc"
PERMISSIONS = ["read-source", "write-run-data"]


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _target(run_id: str) -> tuple[Path, str, str]:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked(f"{JOB}: staged artifact manifest is required")
    value = read_json(manifest).get("target", {}).get("repo_path")
    target = Path(value) if isinstance(value, str) else Path()
    if not value or not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise Blocked(f"{JOB}: target must be an absolute real checkout")
    identity = intake.source_identity(str(target.resolve()))
    return target.resolve(), "sha256:" + file_hash(manifest), identity.get("revision") or "unversioned"


def _code() -> dict[str, str]:
    paths = ("joern_cpg.py", "code_graph_evidence.py", "container_execution.py",
             "publish_job_output.py", "registry/job-templates/02-code-property-graph.json",
             "registry/output-contracts/code-property-graph.json")
    values = {name: file_hash(ROOT / name) for name in paths}
    values["pipeline/joern_export_records.sc"] = file_hash(EXPORTER)
    for name in ("code-property-graph.schema.json", "code-property-graph-record.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _permission(run_id: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": JOB,
                   "capabilities": []}
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def current_inputs(run_id: str) -> dict[str, Any]:
    target, source, revision = _target(run_id)
    if not EXPORTER.is_file():
        raise Blocked(f"{JOB}: Joern exporter is missing")
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    image = registry.get(IMAGE_ID)
    if image is None:
        raise Blocked(f"{JOB}: {IMAGE_ID} has no current B16 record")
    tree = core.source_tree_sha256(target)
    exporter = "sha256:" + file_hash(EXPORTER)
    build = "sha256:" + digest({"source_tree_sha256": tree, "image_digest": image["digest"],
                                 "exporter_sha256": exporter})
    return {"run_id": run_id, "job": JOB, "target_path": str(target),
            "source_snapshot_sha256": source, "source_revision": revision,
            "source_tree_sha256": tree, "image": image, "exporter_sha256": exporter,
            "build_identity_sha256": build, "boundary_sha256": ce.boundary_sha256(), "code": _code()}


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=[], clock=_utc, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _request(run_id: str, attempt_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
    image = inputs["image"]
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
        "image": {"image_id": IMAGE_ID, "digest": image["digest"]},
        "argv": ["/opt/joern-cli/joern", "--script", "/inputs/joern/joern_export_records.sc",
                 "--param", "inputPath=/workspace", "--param", "outputPath=/scratch/records.jsonl",
                 "--param", "maxRecords=2147483647"],  # uncapped (ADR-0013); counts go to size_log
        "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                        {"name": "NO_COLOR", "value": "1"}],
        "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"},
                          {"host_path": str(EXPORTER.parent), "container_path": "/inputs/joern"}],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, inputs["source_snapshot_sha256"], _utc()),
        "limits": tunables.container_limits(JOB)}


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": run_id,
                  "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
                  "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": run_id,
               "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
               "build_lineage_sha256": inputs["build_identity_sha256"]}
    return permission, lineage


def _split(result: dict[str, Any], destination: Path | None) -> dict[str, Any]:
    """Move records out of the result into JSONL (freeciv21: 593K records, 580 MB as one JSON
    document; doom3-bfg over 1M). Returns the summary; writes the file when destination is set."""
    import hashlib
    records = result.pop("records")
    digest_ = hashlib.sha256()
    stream = destination.open("wb") if destination is not None else None
    try:
        for record in records:
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
            digest_.update(line)
            if stream is not None:
                stream.write(line)
    finally:
        if stream is not None:
            stream.close()
    result["records_file"] = {"path": RECORDS, "sha256": "sha256:" + digest_.hexdigest(), "count": len(records)}
    return result


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or current_inputs(run_id) != inputs:
        raise Blocked(f"{JOB}: inputs or source generation changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, "code-property-graph.schema.json"):
        raise Blocked(f"{JOB}: result fails schema validation")
    common = {"run_id": run_id, "source_revision": inputs["source_revision"],
              "source_snapshot_sha256": inputs["source_snapshot_sha256"],
              "source_tree_sha256": inputs["source_tree_sha256"],
              "build_identity_sha256": inputs["build_identity_sha256"], "image_id": IMAGE_ID,
              "image_digest": inputs["image"]["digest"], "exporter_sha256": inputs["exporter_sha256"]}
    if any(result.get(key) != value for key, value in common.items()):
        raise Blocked(f"{JOB}: published generation binding differs from immutable inputs")
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: producer permission or lineage receipt changed")
    receipt = read_json(attempt / RECEIPT)
    trial = attempt / receipt.get("trial_path", "")
    request = read_json(trial / "logs" / "container" / ce.REQUEST_FILE)
    runtime = _runtime(inputs["source_snapshot_sha256"])
    ce.load_verified_result(trial, run_id=run_id, job_id=JOB,
        attempt_id=receipt.get("adapter_attempt_id", ""), request=request, images_dir=runtime.images_dir,
        expected_result_sha256=receipt.get("expected_result_sha256", ""), **_host(runtime))
    raw = trial / "scratch" / "records.jsonl"
    if not raw.is_file() or raw.is_symlink() or "sha256:" + file_hash(raw) != receipt.get("raw_sha256"):
        raise Blocked(f"{JOB}: raw Joern projection changed")
    expected = core.normalize_jsonl(raw, target=Path(inputs["target_path"]), run_id=run_id,
        source_snapshot_sha256=inputs["source_snapshot_sha256"], source_revision=inputs["source_revision"],
        image_id=IMAGE_ID, image_digest=inputs["image"]["digest"],
        exporter_sha256=inputs["exporter_sha256"], build_identity_sha256=inputs["build_identity_sha256"])
    if result != _split(expected, None):
        raise Blocked(f"{JOB}: normalized CPG differs from its immutable Joern output")
    if "sha256:" + file_hash(attempt / RECORDS) != result["records_file"]["sha256"]:
        raise Blocked(f"{JOB}: published CPG records file changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if current_inputs(run_id) != inputs:
            raise Blocked(f"{JOB}: source or implementation changed before execution")
        attempt = allocation["attempt"]
        trial = attempt / "tool"; trial.mkdir(parents=True)
        adapter_id = "joern-" + allocation["attempt_id"][:12]
        runtime = _runtime(inputs["source_snapshot_sha256"]); request = _request(run_id, adapter_id, inputs)
        terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                    attempt_root=trial, request=request)
        expected_sha = terminal["result_sha256"]
        ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
            request=request, images_dir=runtime.images_dir, expected_result_sha256=expected_sha, **_host(runtime))
        if terminal["execution_status"] != "OK":
            raise RuntimeError(f"{JOB}: Joern ended {terminal['execution_status']}")
        raw = trial / "scratch" / "records.jsonl"
        result = core.normalize_jsonl(raw, target=Path(inputs["target_path"]), run_id=run_id,
            source_snapshot_sha256=inputs["source_snapshot_sha256"], source_revision=inputs["source_revision"],
            image_id=IMAGE_ID, image_digest=inputs["image"]["digest"],
            exporter_sha256=inputs["exporter_sha256"], build_identity_sha256=inputs["build_identity_sha256"])
        result = _split(result, attempt / RECORDS)
        atomic_json(attempt / RESULT, result)
        atomic_json(attempt / RECEIPT, {"adapter_attempt_id": adapter_id, "trial_path": "tool",
            "expected_result_sha256": expected_sha, "raw_sha256": "sha256:" + file_hash(raw)})
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        (attempt / SUMMARY).write_text("# Code property graph\n\n"
            f"- Source-bound records: {result['record_count']}.\n"
            f"- Coverage gaps: {len(result['coverage_gaps'])}.\n"
            "- Query hits are locators and require source dereference.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id,
                  "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
                  "records": result["record_count"], "coverage_gaps": len(result["coverage_gaps"]),
                  "network": "none", "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_id, worker_kind="pinned_container", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=result["status"], summary=f"Joern published {result['record_count']} locator records.",
            status_record=status, artifact_paths=[RESULT, RECORDS, RECEIPT, SUMMARY, "status.json", "permission.json", "lineage.json"],
            gaps=[gap["reason"] for gap in result["coverage_gaps"]],
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/joern_cpg.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="Joern CPG preflight did not complete.",
        failed_summary="Joern CPG did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("run_id"); parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true"); args = parser.parse_args()
    print(run(args.run_id, args.dagster_id, args.force))
