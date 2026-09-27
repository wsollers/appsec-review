"""Deterministic happy-path worker for ``02-source-sast``.

This first D09 slice runs the pinned Semgrep image offline through B13 with a repository-owned,
hash-bound ruleset.  It publishes only normalized static-analysis leads: rule id, closed category,
and a fresh source citation.  Raw Semgrep messages and snippets remain inside the immutable B13
attempt and are never promoted to findings or runtime claims.

The worker deliberately uses the common immutable-attempt lifecycle.  Full failure injection and
live Dagster qualification remain integration work; until then its readiness is
``implemented_not_qualified``.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
from typing import Any

import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import permission_capabilities as pc
import source_sast_language_adapters as language_adapters
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

JOB = "02-source-sast"
DAGSTER_JOB = "source_sast"
CONTRACT = "source-sast"
RESULT = "source-sast.json"
RECEIPTS = "b13-receipts.json"
SUMMARY = "source-sast-summary.md"
IMAGE_ID = "tool-semgrep"
TOOL_ID = "semgrep-repository-rules-v1"
RULES = ROOT.parent / "data" / "source-sast" / "rules-v1.yml"
SCHEMA = "appsec-review/source-sast/1"
RULE_CATEGORIES = {
    "appsec.c.strcpy": "unsafe-copy",
    "appsec.c.printf-nonliteral": "format-string",
    "appsec.c.memcpy": "memory-copy",
    "appsec.c.system": "command-execution",
}
SEMGREP_RULE_PREFIX = "inputs.source-sast-rules."
CODE_FILES = (
    "source_sast.py", "container_execution.py", "permission_capabilities.py",
    "publish_job_output.py", "validate_job_output.py", "source_sast_language_adapters.py",
    "registry/output-contracts/source-sast.json",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _source_snapshot(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    return "sha256:" + file_hash(path)


def _target(run_id: str) -> Path:
    manifest = read_json(run_path(run_id) / "inputs" / "artifact-manifest.json")
    value = manifest.get("target", {}).get("repo_path")
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    return path.resolve()


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values["data/source-sast/rules-v1.yml"] = file_hash(RULES)
    values["schemas/source-sast.schema.json"] = file_hash(ROOT.parent / "schemas" / "source-sast.schema.json")
    return values


def _permission(run_id: str, source: str, at: str) -> dict[str, Any]:
    requirement = {
        "schema": "appsec-review/permission-requirement/1.0",
        "job_id": JOB,
        "capabilities": [],
    }
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def current_inputs(run_id: str) -> dict[str, Any]:
    source = _source_snapshot(run_id)
    target = _target(run_id)
    if not RULES.is_file():
        raise Blocked(f"{JOB}: repository-owned ruleset is missing")
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    if IMAGE_ID not in registry:
        raise Blocked(f"{JOB}: {IMAGE_ID} has no current B16 record")
    record = registry[IMAGE_ID]
    paths = [path.relative_to(target).as_posix() for path in target.rglob("*")
             if path.is_file() and not path.is_symlink()]
    language_plan = language_adapters.build_plan(language_adapters.detected_languages(paths), registry)
    return {
        "job": JOB,
        "run_id": run_id,
        "source_snapshot_sha256": source,
        "target_path": str(target),
        "image": record,
        "rules": {"path": str(RULES), "sha256": "sha256:" + file_hash(RULES),
                  "ids": sorted(RULE_CATEGORIES)},
        "permission_fingerprint_sha256": pc.input_fingerprint_component(
            _permission(run_id, source, _utc_now())["decision"]),
        "boundary_sha256": ce.boundary_sha256(),
        "language_tool_plan": language_plan,
        "code": _code_hashes(),
    }


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable")
    return ce.ContainerRuntime(
        docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=[], clock=_utc_now, cancel=threading.Event(),
    )


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _request(run_id: str, adapter_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
    image = inputs["image"]
    return {
        "schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": adapter_id,
        "image": {"image_id": image["image_id"], "digest": image["digest"]},
        "argv": [
            "/opt/tool/bin/semgrep", "scan", "--metrics=off", "--disable-version-check",
            "--oss-only", "--config", "/inputs/source-sast-rules/rules-v1.yml", "--json",
            "--output", "/scratch/semgrep.json", "/workspace",
        ],
        "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                        {"name": "NO_COLOR", "value": "1"}],
        "target_mounts": [
            {"host_path": inputs["target_path"], "container_path": "/workspace"},
            {"host_path": str(RULES.parent), "container_path": "/inputs/source-sast-rules"},
        ],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, inputs["source_snapshot_sha256"], _utc_now()),
        "limits": {"timeout_seconds": 900, "memory_bytes": 2 * 1024 * 1024 * 1024,
                   "cpu_millis": 2000, "pids": 256, "tmpfs_bytes": 256 * 1024 * 1024,
                   "stdout_limit_bytes": 1024 * 1024, "stderr_limit_bytes": 1024 * 1024},
    }


def _relative_source(raw_path: Any, target: Path) -> tuple[str, Path]:
    if not isinstance(raw_path, str) or not raw_path:
        raise RuntimeError(f"{JOB}: Semgrep result has no source path")
    normalized = raw_path.replace("\\", "/")
    for prefix in ("/workspace/", "workspace/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    if normalized.startswith("/") or any(part in ("", ".", "..") for part in normalized.split("/")):
        raise RuntimeError(f"{JOB}: Semgrep result path is not normalized beneath the target")
    resolved = (target / normalized).resolve()
    try:
        resolved.relative_to(target)
    except ValueError as exc:
        raise RuntimeError(f"{JOB}: Semgrep result leaves the target") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise RuntimeError(f"{JOB}: Semgrep result does not cite a regular target file")
    return normalized, resolved


def normalize_semgrep(raw: dict[str, Any], *, target: Path, run_id: str, attempt_id: str,
                      source_snapshot_sha256: str, image: dict[str, Any],
                      language_tool_plan: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
        raise RuntimeError(f"{JOB}: Semgrep JSON has no results array")
    findings = []
    for item in raw["results"]:
        raw_rule_id = item.get("check_id") if isinstance(item, dict) else None
        rule_id = (raw_rule_id[len(SEMGREP_RULE_PREFIX):]
                   if isinstance(raw_rule_id, str) and raw_rule_id.startswith(SEMGREP_RULE_PREFIX)
                   else raw_rule_id)
        if rule_id not in RULE_CATEGORIES:
            raise RuntimeError(f"{JOB}: Semgrep returned an undeclared rule id")
        path, source = _relative_source(item.get("path"), target)
        start = item.get("start", {}).get("line") if isinstance(item.get("start"), dict) else None
        end = item.get("end", {}).get("line") if isinstance(item.get("end"), dict) else None
        if not isinstance(start, int) or isinstance(start, bool) or start < 1:
            raise RuntimeError(f"{JOB}: Semgrep result has an invalid start line")
        if not isinstance(end, int) or isinstance(end, bool) or end < start:
            raise RuntimeError(f"{JOB}: Semgrep result has an invalid end line")
        key = {"tool_id": TOOL_ID, "rule_id": rule_id, "path": path,
               "start_line": start, "end_line": end, "source_sha256": "sha256:" + file_hash(source)}
        findings.append({"lead_id": "lead_" + digest(key)[:16], **key,
                         "category": RULE_CATEGORIES[rule_id]})
    findings.sort(key=lambda value: (value["path"], value["start_line"], value["rule_id"]))
    return {
        "schema": SCHEMA, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
        "source_snapshot_sha256": source_snapshot_sha256, "status": "OK_WITH_GAPS",
        "tools": [{"tool_id": TOOL_ID, "tool": "semgrep", "version": "1.178.0",
                   "image_id": image["image_id"], "image_digest": image["digest"],
                   "ruleset_sha256": "sha256:" + file_hash(RULES), "records": len(findings)}],
        "leads": findings,
        "coverage_gaps": (["Repository-owned C/C++ Semgrep rules do not cover every source-analysis family."] +
                          language_adapters.execution_gaps(language_tool_plan or [])),
    }


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, "source-sast.schema.json"):
        raise Blocked(f"{JOB}: result schema validation failed")
    receipt = read_json(attempt / RECEIPTS)
    trial = attempt / receipt["trial_path"]
    request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
    runtime = _runtime(inputs["source_snapshot_sha256"])
    errors = ce.verify_container_result(
        trial, run_id=run_id, job_id=JOB, attempt_id=receipt["adapter_attempt_id"],
        request=request, images_dir=runtime.images_dir,
        expected_result_sha256=receipt["expected_result_sha256"], **_host(runtime),
    )
    if errors:
        raise Blocked(f"{JOB}: B13 evidence failed re-verification ({len(errors)} errors)")
    expected = normalize_semgrep(
        read_json(trial / "scratch" / "semgrep.json"), target=Path(inputs["target_path"]),
        run_id=run_id, attempt_id=attempt.name,
        source_snapshot_sha256=inputs["source_snapshot_sha256"], image=inputs["image"],
        language_tool_plan=inputs.get("language_tool_plan", []),
    )
    if result != expected:
        raise Blocked(f"{JOB}: normalized result no longer matches immutable Semgrep evidence")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {DAGSTER_JOB} --wait"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        runtime = _runtime(inputs["source_snapshot_sha256"])
        adapter_id = "semgrep-" + allocation["attempt_id"][:12]
        request = _request(run_id, adapter_id, inputs)
        trial = attempt / "tools" / TOOL_ID
        trial.mkdir(parents=True)
        terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                    attempt_root=trial, request=request)
        expected_sha = terminal["result_sha256"]
        ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                request=request, images_dir=runtime.images_dir,
                                expected_result_sha256=expected_sha, **_host(runtime))
        if terminal["execution_status"] != "OK":
            raise RuntimeError(f"{JOB}: Semgrep ended {terminal['execution_status']}")
        result = normalize_semgrep(
            read_json(trial / "scratch" / "semgrep.json"), target=Path(inputs["target_path"]),
            run_id=run_id, attempt_id=allocation["attempt_id"],
            source_snapshot_sha256=inputs["source_snapshot_sha256"], image=inputs["image"],
            language_tool_plan=inputs.get("language_tool_plan", []),
        )
        atomic_json(attempt / RESULT, result)
        receipt = {"tool_id": TOOL_ID, "adapter_attempt_id": adapter_id,
                   "trial_path": trial.relative_to(attempt).as_posix(),
                   "expected_result_sha256": expected_sha,
                   "raw_result_sha256": "sha256:" + file_hash(trial / "scratch" / "semgrep.json")}
        atomic_json(attempt / RECEIPTS, receipt)
        (attempt / SUMMARY).write_text(
            "# Source SAST\n\n"
            f"- Semgrep repository rules: {len(result['leads'])} static-analysis lead(s).\n"
            "- Coverage: C/C++ happy-path rules only; remaining declared language tools are a gap.\n",
            encoding="utf-8",
        )
        status = {"process": JOB, "status": "OK_WITH_GAPS", "run_id": run_id,
                  "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
                  "tools_run": 1, "leads": len(result["leads"]), "network": "none",
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="pinned_container", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"], execution_status="OK_WITH_GAPS",
            summary=f"Semgrep produced {len(result['leads'])} normalized static-analysis lead(s).",
            status_record=status, artifact_paths=[RESULT, RECEIPTS, SUMMARY, "status.json"],
            gaps=result["coverage_gaps"],
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs),
        )

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="Source SAST preflight did not complete.",
        failed_summary="Source SAST did not publish; no older success may be used.",
    )


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    args = parser.parse_args()
    print(validate(args.run_id))
