"""Config-driven orchestration for dependency evidence and CVE reachability jobs.

The adapter owns no scanner logic.  It binds explicit run-owned inputs to the public B13
adapters, supplies only verified offline database snapshots, and then calls the dependency
worker's immutable publication seam.  Snapshot synchronization deliberately lives elsewhere.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import dependency_b13_adapters as b13
import dependency_workers as workers
from execution_state import Blocked, atomic_json, beneath, data_path, file_hash, identifier, run_path

REQUEST_SCHEMA = "appsec-review/dependency-orchestration-request/1.0"
JOBS = {
    "02-sbom-inventory": "sbom",
    "02-sca-vulnerability-match": "sca",
    "02-license-scan": "license",
    "02-dependency-lifecycle": "lifecycle",
    "06-cve-reachability": "reachability",
}
_REQUEST_KEYS = {"schema", "run_id", "job_id", "source_generation", "generated_at", "payload", "tool"}
_PAYLOAD_KEYS = {
    "sbom": {"source_files"},
    "sca": {"sbom"},
    "license": {"sbom", "source_files"},
    "lifecycle": {"sbom", "license", "reference_table", "reference_table_sha256", "max_reference_age_days"},
    "reachability": {"sca", "reachability_evidence", "reachability_evidence_sha256"},
}
_TOOL_KEYS = {
    "sbom": {"target_path"},
    "sca": {"sbom_root", "snapshot_registry", "max_database_age_seconds"},
    "license": {"target_path"},
    "lifecycle": set(),
    "reachability": set(),
}


def _owned(value: Any, owner: Path, label: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not value:
        raise Blocked(f"dependency orchestration: {label} path is required")
    path = Path(value).absolute()
    try:
        path = beneath(owner, path)
    except ValueError as exc:
        raise Blocked(f"dependency orchestration: {label} path is not run-owned") from exc
    present = path.is_dir() if directory else path.is_file()
    if not present or path.is_symlink():
        raise Blocked(f"dependency orchestration: {label} is absent or linked")
    return path


def _offline_registry(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise Blocked("dependency orchestration: offline snapshot registry is required")
    configured = Path(value)
    if not configured.is_absolute() or not configured.is_dir() or configured.is_symlink():
        raise Blocked("dependency orchestration: offline snapshot registry is absent or linked")
    return configured.resolve()


def _binding_paths(payload: dict[str, Any], owner: Path, kind: str) -> None:
    for key in ("sbom", "license", "sca"):
        if key not in payload:
            continue
        binding = payload[key]
        if not isinstance(binding, dict):
            raise Blocked(f"dependency orchestration: {key} binding is invalid")
        _owned(binding.get("path"), owner, key)
        _owned(binding.get("accepted_path"), owner, key + " accepted pointer")
    if kind == "lifecycle":
        _owned(payload.get("reference_table"), owner, "reference table")
    if kind == "reachability":
        _owned(payload.get("reachability_evidence"), owner, "reachability evidence")


def _canonical_attempt(value: str, owner: Path, job_id: str) -> Path:
    path = Path(value).absolute()
    expected_parent = data_path(owner.name, "jobs", job_id, "orchestration-attempts").absolute()
    if path.parent != expected_parent:
        raise Blocked("dependency orchestration: attempt root is not the canonical run-owned path")
    identifier(path.name)
    try:
        beneath(owner, path.parent)
    except ValueError as exc:
        raise Blocked("dependency orchestration: attempt root is not run-owned") from exc
    return path


def _reuse_or_prepare(attempt: Path, request_path: Path) -> Path | None:
    resolved = attempt / "worker-request.json"
    metadata = attempt / "orchestration-input.json"
    if not attempt.exists():
        attempt.mkdir(parents=True)
        atomic_json(metadata, {"input_path": str(request_path), "input_sha256": "sha256:" + file_hash(request_path)})
        return None
    if attempt.is_symlink() or not attempt.is_dir() or not resolved.is_file() or resolved.is_symlink():
        raise Blocked("dependency orchestration: incomplete prior orchestration attempt")
    try:
        recorded = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Blocked("dependency orchestration: prior input identity is unreadable") from None
    if recorded != {"input_path": str(request_path), "input_sha256": "sha256:" + file_hash(request_path)}:
        raise Blocked("dependency orchestration: orchestration attempt input changed")
    return resolved


def execute(*, job_id: str, run_id: str, input_path: str, output_root: str,
            attempt_root: str) -> dict[str, Any]:
    """Run one dependency job from closed config and explicit paths."""
    if job_id not in JOBS:
        raise Blocked("dependency orchestration: unknown lifecycle job")
    run_id = identifier(run_id)
    owner = run_path(run_id).absolute()
    request_path = _owned(input_path, owner, "input request")
    expected_output = data_path(run_id, "jobs").absolute()
    selected_output = Path(output_root).absolute()
    try:
        selected_output = beneath(owner, selected_output)
    except ValueError as exc:
        raise Blocked("dependency orchestration: output root is not run-owned") from exc
    if selected_output != expected_output:
        raise Blocked("dependency orchestration: output root is not the canonical jobs root")
    attempt = _canonical_attempt(attempt_root, owner, job_id)

    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise Blocked("dependency orchestration: input request is unreadable") from None
    if not isinstance(request, dict) or set(request) != _REQUEST_KEYS:
        raise Blocked("dependency orchestration: request shape is not closed")
    if (request.get("schema") != REQUEST_SCHEMA or request.get("run_id") != run_id or
            request.get("job_id") != job_id):
        raise Blocked("dependency orchestration: request identity is invalid")
    manifest = owner / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked("dependency orchestration: run artifact manifest is unavailable")
    generation = "sha256:" + file_hash(manifest)
    if request.get("source_generation") != generation:
        raise Blocked("dependency orchestration: request source generation is stale")

    kind = JOBS[job_id]
    payload, tool = request.get("payload"), request.get("tool")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS[kind]:
        raise Blocked("dependency orchestration: worker payload shape is not closed")
    if not isinstance(tool, dict) or set(tool) != _TOOL_KEYS[kind]:
        raise Blocked("dependency orchestration: tool config shape is not closed")
    _binding_paths(payload, owner, kind)

    resolved = _reuse_or_prepare(attempt, request_path)
    if resolved is not None:
        return workers.run(kind, resolved)

    worker_request = {"run_id": run_id, "source_snapshot_sha256": generation,
                      "generated_at": request["generated_at"], "output_root": str(selected_output), **payload}
    try:
        if kind in {"sbom", "license"}:
            target = _owned(tool["target_path"], owner, "target", directory=True)
            adapter_kind = "syft" if kind == "sbom" else "scancode"
            b13_root = attempt / "b13" / adapter_kind
            b13_root.mkdir(parents=True)
            result = b13.execute(adapter_kind, run_id=run_id,
                adapter_attempt_id=attempt.name + "-" + adapter_kind,
                source_snapshot_sha256=generation, attempt_root=b13_root, target=target)
            worker_request["b13_attempt"] = result["b13_attempt"]
        elif kind == "sca":
            sbom_root = _owned(tool["sbom_root"], owner, "SBOM root", directory=True)
            if Path(payload["sbom"]["path"]).parent.resolve() != sbom_root.resolve():
                raise Blocked("dependency orchestration: SBOM root differs from the accepted SBOM binding")
            registry = _offline_registry(tool["snapshot_registry"])
            max_age = tool["max_database_age_seconds"]
            if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
                raise Blocked("dependency orchestration: explicit non-negative database age ceiling is required")
            identities = []
            for adapter_kind in ("grype", "osv"):
                b13_root = attempt / "b13" / adapter_kind
                b13_root.mkdir(parents=True)
                result = b13.execute_registered(adapter_kind, snapshot_registry=registry,
                    max_age_seconds=max_age, run_id=run_id,
                    adapter_attempt_id=attempt.name + "-" + adapter_kind,
                    source_snapshot_sha256=generation, attempt_root=b13_root, sbom_root=sbom_root)
                worker_request[("osv_" if adapter_kind == "osv" else "") + "b13_attempt"] = result["b13_attempt"]
                identities.append(result["database"])
            worker_request.update(databases=identities, max_database_age_seconds=max_age)
        resolved = attempt / "worker-request.json"
        atomic_json(resolved, worker_request)
        return workers.run(kind, resolved)
    except (b13.AdapterBlocked, workers.WorkerBlocked) as exc:
        raise Blocked(str(exc)) from exc
