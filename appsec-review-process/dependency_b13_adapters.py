#!/usr/bin/env python3
"""B13 execution adapters for the dependency evidence workers.

All argv, mounts, limits and environment values are fixed here.  The caller retains the B13
``result_sha256`` outside the adapter attempt, and this module re-verifies it before exposing a
tool output or minting the small receipt consumed by :mod:`dependency_workers`.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
from typing import Any

import container_execution as ce
from execution_state import atomic_bytes
import permission_capabilities as pc
import dependency_snapshot_registry as snapshots

PINNED_RECEIPT_SCHEMA = "appsec-review/pinned-tool-evidence/1.0"
SPECS = {
    "syft": {"job": "02-sbom-inventory", "image": "tool-syft", "tool": "syft-directory",
             "output": "sbom.cdx.json", "argv": ["/opt/tool/bin/syft", "scan", "dir:/workspace",
                 "--select-catalogers", "+file-metadata-cataloger", "-o", "cyclonedx-json@1.5=/scratch/sbom.cdx.json"]},
    "grype": {"job": "02-sca-vulnerability-match", "image": "tool-grype", "tool": "grype",
              "output": "grype.json", "argv": ["/opt/tool/bin/grype", "sbom:/inputs/sbom/sbom.cdx.json",
                  "--output", "json", "--file", "/scratch/grype.json"]},
    "osv": {"job": "02-sca-vulnerability-match", "image": "tool-osv-scanner", "tool": "osv-scanner",
            "output": "osv.json", "argv": ["/opt/tool/bin/osv-scanner", "scan", "--experimental-offline-vulnerabilities", "--format", "json",
                "--output", "/scratch/osv.json", "--sbom", "/inputs/sbom/sbom.cdx.json"]},
    "scancode": {"job": "02-license-scan", "image": "scancode-toolkit", "tool": "scancode-toolkit",
                 # The separately built image declares WORKDIR /scancode-toolkit and ENTRYPOINT
                 # ./scancode.  B13 deliberately overrides entrypoints with argv[0], so spell the
                 # same executable as one normalized absolute path.
                 "output": "scancode.json", "argv": ["/scancode-toolkit/scancode", "-clip",
                     "--json-pp", "/scratch/scancode.json", "/workspace"]},
}
LIMITS = {"timeout_seconds": 900, "memory_bytes": 4 * 1024 * 1024 * 1024,
          "cpu_millis": 2000, "pids": 256, "tmpfs_bytes": 1024 * 1024 * 1024,
          "stdout_limit_bytes": 1024 * 1024, "stderr_limit_bytes": 1024 * 1024}


class AdapterBlocked(RuntimeError):
    pass


def _clock() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _permission(run_id: str, job: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job, "capabilities": []}
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def runtime(source_snapshot_sha256: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise AdapterBlocked("dependency tool execution requires Docker")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"], container_user=defaults["container_user"],
        source_snapshot_sha256=source_snapshot_sha256, registry_ceiling=[], clock=_clock,
        cancel=threading.Event())


def _real_dir(value: Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise AdapterBlocked(f"{label} must be an absolute real directory")
    return path.resolve()


def request(kind: str, *, run_id: str, adapter_attempt_id: str, source_snapshot_sha256: str,
            image: dict[str, Any], target: Path | None = None, sbom_root: Path | None = None,
            database_root: Path | None = None, at: str | None = None) -> dict[str, Any]:
    if kind not in SPECS: raise AdapterBlocked("unknown dependency tool adapter")
    spec = SPECS[kind]
    mounts = []
    if kind in {"syft", "scancode"}:
        mounts.append({"host_path": str(_real_dir(Path(target or ""), "target")), "container_path": "/workspace"})
    else:
        mounts.append({"host_path": str(_real_dir(Path(sbom_root or ""), "sbom_root")),
                       "container_path": "/inputs/sbom"})
        mounts.append({"host_path": str(_real_dir(Path(database_root or ""), "database_root")),
                       "container_path": "/inputs/" + ("grype-db" if kind == "grype" else "osv-db")})
    environment = [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                   {"name": "NO_COLOR", "value": "1"}]
    if kind == "grype": environment.append({"name": "XDG_CACHE_HOME", "value": "/inputs/grype-db"})
    if kind == "osv": environment.append({"name": "XDG_CACHE_HOME", "value": "/inputs/osv-db"})
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": spec["job"], "attempt_id": adapter_attempt_id,
        "image": {"image_id": image["image_id"], "digest": image["digest"]}, "argv": list(spec["argv"]),
        "environment": environment, "target_mounts": mounts, "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, spec["job"], source_snapshot_sha256, at or _clock()),
        "limits": dict(LIMITS)}


def execute(kind: str, *, run_id: str, adapter_attempt_id: str, source_snapshot_sha256: str,
            attempt_root: Path, target: Path | None = None, sbom_root: Path | None = None,
            database_root: Path | None = None, supplied_runtime: ce.ContainerRuntime | None = None) -> dict[str, Any]:
    spec = SPECS[kind]; rt = supplied_runtime or runtime(source_snapshot_sha256)
    try:
        registry = ce.load_image_registry(rt.images_dir)
    except ce.ContainerRequestError as exc:
        raise AdapterBlocked(f"{spec['job']}: B16 registry is unavailable") from exc
    if spec["image"] not in registry:
        raise AdapterBlocked(f"{spec['job']}: pinned image {spec['image']} has no current B16 record")
    image = registry[spec["image"]]
    req = request(kind, run_id=run_id, adapter_attempt_id=adapter_attempt_id,
                  source_snapshot_sha256=source_snapshot_sha256, image=image, target=target,
                  sbom_root=sbom_root, database_root=database_root, at=rt.clock())
    attempt_root = Path(attempt_root)
    if not attempt_root.is_absolute() or not attempt_root.is_dir() or attempt_root.is_symlink():
        raise AdapterBlocked(f"{spec['job']}: adapter attempt root must already be an absolute real directory")
    terminal = ce.run_container(rt, run_id=run_id, job_id=spec["job"], attempt_id=adapter_attempt_id,
                                attempt_root=attempt_root, request=req)
    expected_result_sha256 = terminal["result_sha256"]  # caller-held, never loaded back from the attempt
    host = {"host_flavor": rt.host_flavor, "docker_host": rt.docker_host,
            "docker_executable": rt.docker_executable, "container_user": rt.container_user}
    try:
        verified = ce.load_verified_result(attempt_root, run_id=run_id, job_id=spec["job"],
            attempt_id=adapter_attempt_id, request=req, images_dir=rt.images_dir,
            expected_result_sha256=expected_result_sha256, **host)
    except ce.ContainerRequestError as exc:
        raise AdapterBlocked(f"{spec['job']}: B13 result failed independent re-verification") from exc
    if verified["execution_status"] != "OK":
        raise AdapterBlocked(f"{spec['job']}: pinned tool ended {verified['execution_status']} ({verified['cause']})")
    output = attempt_root / "scratch" / spec["output"]
    if not output.is_file() or output.is_symlink():
        raise AdapterBlocked(f"{spec['job']}: pinned tool did not emit its required output")
    receipt = {"schema": PINNED_RECEIPT_SCHEMA, "run_id": run_id, "job_id": spec["job"],
        "attempt_id": adapter_attempt_id, "tool_id": spec["tool"], "image_id": image["image_id"],
        "image_digest": image["digest"], "result_sha256": _hash_file(output),
        "source_snapshot_sha256": source_snapshot_sha256, "completed_at": verified["finished_at"],
        "boundary_sha256": ce.boundary_sha256(), "network_mode": "none",
        "target_read_only": True, "scratch_writable": True}
    receipt_path = attempt_root / "pinned-tool-evidence.json"
    atomic_bytes(receipt_path, (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode())
    binding = {"attempt_root": str(attempt_root), "expected_result_sha256": expected_result_sha256,
        "expected_output_sha256": receipt["result_sha256"],
        "request": req, "images_dir": str(rt.images_dir), "host_flavor": rt.host_flavor,
        "docker_host": rt.docker_host, "docker_executable": str(rt.docker_executable),
        "container_user": rt.container_user}
    return {"tool_output": str(output), "tool_receipt": str(receipt_path),
            "expected_tool": {key: receipt[key] for key in ("tool_id", "image_id", "image_digest", "boundary_sha256")},
            "expected_result_sha256": expected_result_sha256, "request": req, "b13_attempt": binding}


def execute_registered(kind: str, *, snapshot_registry: Path, max_age_seconds: int,
                       warn_age_seconds: int | None = None,
                       run_id: str, adapter_attempt_id: str, source_snapshot_sha256: str,
                       attempt_root: Path, sbom_root: Path,
                       supplied_runtime: ce.ContainerRuntime | None = None) -> dict[str, Any]:
    if kind not in {"grype", "osv"}: raise AdapterBlocked("registered snapshots apply only to Grype and OSV")
    rt = supplied_runtime or runtime(source_snapshot_sha256)
    database_kind = "grype-db" if kind == "grype" else "osv"
    try:
        identity = snapshots.resolve(database_kind, snapshot_registry, max_age_seconds=max_age_seconds,
                                     warn_age_seconds=warn_age_seconds,
                                     now=datetime.fromisoformat(rt.clock().replace("Z", "+00:00")))
    except snapshots.SnapshotBlocked as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot absent") from exc
    except snapshots.SnapshotStale as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot stale") from exc
    except snapshots.SnapshotInvalid as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot invalid") from exc
    result = execute(kind, run_id=run_id, adapter_attempt_id=adapter_attempt_id,
        source_snapshot_sha256=source_snapshot_sha256, attempt_root=attempt_root,
        sbom_root=sbom_root, database_root=Path(identity["data_root"]), supplied_runtime=rt)
    result["database"] = {key: identity[key] for key in
        ("database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp")}
    result["database_freshness"] = {key: identity[key] for key in
        ("age_seconds", "warn_age_seconds", "max_age_seconds", "freshness", "warnings")}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=sorted(SPECS)); parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-id", required=True); parser.add_argument("--source-snapshot-sha256", required=True)
    parser.add_argument("--attempt-root", type=Path, required=True); parser.add_argument("--target", type=Path)
    parser.add_argument("--sbom-root", type=Path); parser.add_argument("--database-root", type=Path)
    args = parser.parse_args()
    try:
        value = execute(args.kind, run_id=args.run_id, adapter_attempt_id=args.attempt_id,
            source_snapshot_sha256=args.source_snapshot_sha256, attempt_root=args.attempt_root,
            target=args.target, sbom_root=args.sbom_root, database_root=args.database_root)
        print(json.dumps(value, sort_keys=True)); return 0
    except AdapterBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "cause": str(exc)}, sort_keys=True)); return 2


if __name__ == "__main__":
    raise SystemExit(main())
