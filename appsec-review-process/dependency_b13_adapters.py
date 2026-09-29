#!/usr/bin/env python3
"""B13 execution adapters for the dependency evidence workers.

All argv, mounts, limits and environment values are fixed here.  The caller retains the B13
``result_sha256`` outside the adapter attempt, and this module re-verifies it before exposing a
tool output or minting the small receipt consumed by :mod:`dependency_workers`.
"""
from __future__ import annotations

import tunables
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
from typing import Any

import container_execution as ce
from execution_state import atomic_bytes, atomic_json, beneath, data_path, digest, identifier
import permission_capabilities as pc
import dependency_snapshot_registry as snapshots
import tool_output_cache

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


def argv_for(kind: str) -> list[str]:
    """The pinned argv; scancode's worker processes come from the license-scan tunable
    (doom3-bfg: one process did not finish in 3600 s)."""
    argv = list(SPECS[kind]["argv"])
    if kind == "scancode":
        argv[2:2] = ["-n", str(tunables.value("02-license-scan", "scancode_processes"))]
    return argv


class AdapterBlocked(RuntimeError):
    pass



def exit_accepted(kind: str, verified: dict, attempt_root: Path) -> bool:
    """Non-zero exits that still produced the tool's full output. Shared by the adapter and the
    worker's re-verification."""
    if kind == "osv":
        return osv_exit_accepted(verified, attempt_root)
    if kind == "scancode":
        # scancode exits 1 when some files fail to scan (freeciv21: three .blend files) after
        # writing results for everything else; those files are a license coverage gap.
        if verified.get("execution_status") != "FAILED" or verified.get("cause") != "CONTAINER_EXIT_NONZERO" \
                or verified.get("exit_code") != 1:
            return False
        stderr = Path(attempt_root) / "logs" / "container" / "stderr.log"
        output = Path(attempt_root) / "scratch" / SPECS["scancode"]["output"]
        return (stderr.is_file() and output.is_file() and
                "Some files failed to scan properly" in stderr.read_text(errors="replace"))
    return False


# ADR-0013: a pinned tool that ends TIMEOUT, OOM_KILLED or with a non-zero exit that is not a
# documented finding/partial exit leaves no complete output. For these kinds that is a recorded
# coverage gap (the job publishes OK_WITH_GAPS with the verified B13 terminal as its evidence),
# not a blocked job. Integrity problems (re-verification, image, permission) still block, and a
# canceled or blocked container never becomes a gap.
TOOL_GAP_KINDS = frozenset({"scancode"})
TOOL_GAP_CAUSES = ("TIMEOUT", "OOM_KILLED", "CONTAINER_EXIT_NONZERO")
TOOL_GAP_SCHEMA = "appsec-review/pinned-tool-gap/1.0"


def tool_gap(kind: str, verified: dict, attempt_root: Path) -> str | None:
    """The gap text for a verified B13 terminal that is a tool-level failure, else None. Shared by
    the adapter and the worker's independent re-verification so both sides agree."""
    if kind not in TOOL_GAP_KINDS or verified.get("execution_status") == "OK":
        return None
    if exit_accepted(kind, verified, attempt_root):
        return None
    cause = verified.get("cause")
    if verified.get("execution_status") != "FAILED" or cause not in TOOL_GAP_CAUSES:
        return None
    detail = f"{cause} exit {verified.get('exit_code')}" if cause == "CONTAINER_EXIT_NONZERO" else cause
    return (f"LICENSE_SCAN_TOOL_GAP: {SPECS[kind]['tool']} ended {detail}; "
            "no license records for this source snapshot")


def osv_exit_accepted(verified: dict, attempt_root: Path) -> bool:
    """OSV exit 1 means findings; exit 127 with missing local ecosystem databases is a coverage
    gap (the scanned ecosystems still produced output), not a failed tool. Shared with the
    worker's independent re-verification so both sides agree."""
    if verified.get("execution_status") != "FAILED" or verified.get("cause") != "CONTAINER_EXIT_NONZERO":
        return False
    if verified.get("exit_code") == 1:
        return True
    stderr = Path(attempt_root) / "logs" / "container" / "stderr.log"
    return (verified.get("exit_code") == 127 and stderr.is_file() and
            "could not find local databases for ecosystems" in stderr.read_text(errors="replace"))

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
        "image": {"image_id": image["image_id"], "digest": image["digest"]}, "argv": argv_for(kind),
        "environment": environment, "target_mounts": mounts, "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, spec["job"], source_snapshot_sha256, at or _clock()),
        "limits": tunables.container_limits(spec["job"])}


def execute(kind: str, *, run_id: str, adapter_attempt_id: str, source_snapshot_sha256: str,
            attempt_root: Path, target: Path | None = None, sbom_root: Path | None = None,
            database_root: Path | None = None, supplied_runtime: ce.ContainerRuntime | None = None,
            input_identities: dict[str, str] | None = None) -> dict[str, Any]:
    """Run one pinned tool through B13, or reuse a cached verified attempt (``tool_output_cache``).
    ``input_identities`` names a mount by a content identity already re-hashed by the offline
    snapshot registry (its container path -> identity) instead of hashing that tree again."""
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
    cache = _cache_context(kind, req, rt, run_id=run_id, attempt_root=attempt_root,
                           source_snapshot_sha256=source_snapshot_sha256, input_identities=input_identities)
    if cache is not None:
        reused = _reuse(kind, cache, req=req, rt=rt, image=image, run_id=run_id,
                        source_snapshot_sha256=source_snapshot_sha256, attempt_root=attempt_root)
        if reused is not None:
            return reused
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
    finding_exit = exit_accepted(kind, verified, attempt_root)
    host_binding = _host_binding(rt)
    if verified["execution_status"] != "OK" and not finding_exit:
        gap = tool_gap(kind, verified, attempt_root)
        if gap is None:
            raise AdapterBlocked(f"{spec['job']}: pinned tool ended {verified['execution_status']} ({verified['cause']})")
        # No output is trusted: the binding carries no output hash and no receipt is minted. The
        # worker re-verifies the same B13 attempt and re-derives the same gap.
        binding = {"attempt_root": str(attempt_root), "expected_result_sha256": expected_result_sha256,
            "expected_output_sha256": None, "request": req, **host_binding}
        if cache is not None and verified["cause"] in tool_output_cache.CACHEABLE_GAP_CAUSES:
            _remember(cache, req, rt, input_identities, outcome="GAP", binding=binding, gap=gap)
        return _gap_result(spec, image, gap, binding)
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
        "expected_output_sha256": receipt["result_sha256"], "request": req, **host_binding}
    if cache is not None:
        _remember(cache, req, rt, input_identities, outcome="OUTPUT", binding=binding, gap=None)
    return _output_result(receipt, binding, output, receipt_path)


def _gap_result(spec: dict[str, Any], image: dict[str, Any], gap: str, binding: dict[str, Any]) -> dict[str, Any]:
    return {"tool_output": None, "tool_receipt": None, "tool_gap": gap,
            "expected_tool": {"tool_id": spec["tool"], "image_id": image["image_id"],
                              "image_digest": image["digest"], "boundary_sha256": ce.boundary_sha256()},
            "expected_result_sha256": binding["expected_result_sha256"], "request": binding["request"],
            "b13_attempt": binding}


def _output_result(receipt: dict[str, Any], binding: dict[str, Any], output: Path,
                   receipt_path: Path) -> dict[str, Any]:
    return {"tool_output": str(output), "tool_receipt": str(receipt_path),
            "expected_tool": {key: receipt[key] for key in ("tool_id", "image_id", "image_digest", "boundary_sha256")},
            "expected_result_sha256": binding["expected_result_sha256"], "request": binding["request"],
            "b13_attempt": binding}


# --- tool-output cache (brief N) --------------------------------------------------------------------
# The cache is a pointer to an earlier verified B13 attempt of the same run and job. A hit is reused
# only after the full independent re-verification below; dependency_workers re-verifies it again.
REUSE_SCHEMA = "appsec-review/tool-output-reuse/1"
_BINDING_FIELDS = frozenset({"attempt_root", "expected_result_sha256", "expected_output_sha256", "request",
                             "images_dir", "host_flavor", "docker_host", "docker_executable", "container_user"})
_STATIC_REQUEST_FIELDS = ("schema", "run_id", "job_id", "image", "argv", "environment", "scratch_path",
                          "log_path", "network", "limits")


def _host_binding(rt: ce.ContainerRuntime) -> dict[str, Any]:
    return {"images_dir": str(rt.images_dir), "host_flavor": rt.host_flavor, "docker_host": rt.docker_host,
            "docker_executable": str(rt.docker_executable), "container_user": rt.container_user}


def _input_digests(req: dict[str, Any], input_identities: dict[str, str] | None) -> dict[str, str]:
    """Content identity of every mount: a registry-verified snapshot identity, else a tree digest
    computed here over the mounted bytes. Never a value read from the mounted content."""
    identities = input_identities or {}
    return {mount["container_path"]: identities.get(mount["container_path"])
            or tool_output_cache.tree_digest(Path(mount["host_path"])) for mount in req["target_mounts"]}


def _cache_context(kind: str, req: dict[str, Any], rt: ce.ContainerRuntime, *, run_id: str, attempt_root: Path,
                   source_snapshot_sha256: str, input_identities: dict[str, str] | None) -> dict[str, Any] | None:
    """The cache key material, or None when the cache is off or cannot be used safely here. Only
    run-owned attempts (beneath the run's jobs/<job> tree) take part."""
    mode = tool_output_cache.run_mode()
    if not tool_output_cache.enabled(mode):
        return None
    try:
        owner = data_path(run_id, "jobs", req["job_id"])
        beneath(owner, attempt_root)
        inputs = _input_digests(req, input_identities)
    except (ValueError, OSError):
        return None
    material = {"mode": mode, "kind": kind, "run_id": run_id, "source_snapshot_sha256": source_snapshot_sha256,
                **{field: req[field] for field in _STATIC_REQUEST_FIELDS},
                "container_paths": [mount["container_path"] for mount in req["target_mounts"]],
                "inputs": inputs, "boundary_sha256": ce.boundary_sha256(), "host": _host_binding(rt)}
    return {"material": material, "key": tool_output_cache.key_of(material), "owner": str(owner)}


def _remember(cache: dict[str, Any], req: dict[str, Any], rt: ce.ContainerRuntime,
              input_identities: dict[str, str] | None, *, outcome: str, binding: dict[str, Any],
              gap: str | None) -> None:
    """Store a verified outcome, but only if the mounted bytes are still the ones keyed before the
    run (a tree that changed during the run is never cached)."""
    try:
        if _input_digests(req, input_identities) != cache["material"]["inputs"]:
            return
    except (ValueError, OSError):
        return
    tool_output_cache.store().put(cache["key"], cache["material"],
        {"kind": cache["material"]["kind"], "run_id": req["run_id"], "job_id": req["job_id"],
         "outcome": outcome, "tool_gap": gap, "b13_attempt": binding})


def _reuse(kind: str, cache: dict[str, Any], *, req: dict[str, Any], rt: ce.ContainerRuntime, image: dict[str, Any],
           run_id: str, source_snapshot_sha256: str, attempt_root: Path) -> dict[str, Any] | None:
    """A cache hit, re-verified end to end, or None (miss). A hit that fails any check is
    invalidated so the caller runs the tool fresh."""
    store = tool_output_cache.store()
    entry = store.get(cache["key"], cache["material"])
    if entry is None:
        return None
    try:
        result = _reverify_entry(kind, entry, req=req, rt=rt, image=image, run_id=run_id,
                                 source_snapshot_sha256=source_snapshot_sha256, owner=Path(cache["owner"]))
    except (AdapterBlocked, ce.ContainerRequestError, OSError, KeyError, TypeError, ValueError) as exc:
        store.invalidate(cache["key"], f"re-verification failed: {exc}"[:500])
        return None
    binding = result["b13_attempt"]
    reused_from = {"attempt_root": binding["attempt_root"], "attempt_id": binding["request"]["attempt_id"],
                   "expected_result_sha256": binding["expected_result_sha256"],
                   "expected_output_sha256": binding["expected_output_sha256"],
                   "cache_key": cache["key"], "cached_at": entry["created_at"]}
    atomic_json(Path(attempt_root) / "tool-output-reuse.json",
                {"schema": REUSE_SCHEMA, "run_id": run_id, "job_id": req["job_id"],
                 "attempt_id": req["attempt_id"], "tool_id": SPECS[kind]["tool"], "outcome": entry["outcome"],
                 "reused_from": reused_from, "reverified_at": rt.clock()})
    return {**result, "reused_from": reused_from}


def _reverify_entry(kind: str, entry: dict[str, Any], *, req: dict[str, Any], rt: ce.ContainerRuntime,
                    image: dict[str, Any], run_id: str, source_snapshot_sha256: str, owner: Path) -> dict[str, Any]:
    spec = SPECS[kind]
    binding = entry["b13_attempt"]
    if not isinstance(binding, dict) or set(binding) != _BINDING_FIELDS or entry.get("kind") != kind:
        raise AdapterBlocked("cached binding shape is not the adapter binding")
    if {key: binding[key] for key in _host_binding(rt)} != _host_binding(rt):
        raise AdapterBlocked("cached attempt was verified under a different host binding")
    cached_root = beneath(owner, Path(binding["attempt_root"]))
    if not cached_root.is_dir() or cached_root.is_symlink():
        raise AdapterBlocked("cached attempt root is absent or linked")
    cached_req = binding["request"]
    if not isinstance(cached_req, dict) or set(cached_req) != set(req):
        raise AdapterBlocked("cached request shape differs")
    if any(cached_req[field] != req[field] for field in _STATIC_REQUEST_FIELDS):
        raise AdapterBlocked("cached request differs from the fixed adapter request")
    if [m.get("container_path") for m in cached_req["target_mounts"]] != [m["container_path"] for m in req["target_mounts"]]:
        raise AdapterBlocked("cached request mounts differ")
    cached_attempt_id = identifier(cached_req["attempt_id"])
    evaluated_at = cached_req["permission"]["decision"]["evaluated_at"]
    if cached_req["permission"] != _permission(run_id, spec["job"], source_snapshot_sha256, evaluated_at):
        raise AdapterBlocked("cached permission decision is not the exact offline decision")
    # The mandatory independent B13 re-verification, against the result hash retained at store time.
    verified = ce.load_verified_result(cached_root, run_id=run_id, job_id=spec["job"], attempt_id=cached_attempt_id,
        request=cached_req, images_dir=rt.images_dir, host_flavor=rt.host_flavor, docker_host=rt.docker_host,
        docker_executable=rt.docker_executable, container_user=rt.container_user,
        expected_result_sha256=binding["expected_result_sha256"])
    if entry["outcome"] == "GAP":
        gap = tool_gap(kind, verified, cached_root)
        if (verified["cause"] not in tool_output_cache.CACHEABLE_GAP_CAUSES or gap is None
                or gap != entry.get("tool_gap") or binding["expected_output_sha256"] is not None):
            raise AdapterBlocked("cached gap does not re-derive from the verified attempt")
        return _gap_result(spec, image, gap, binding)
    if entry["outcome"] != "OUTPUT":
        raise AdapterBlocked("cached outcome is unknown")
    if verified["execution_status"] != "OK" and not exit_accepted(kind, verified, cached_root):
        raise AdapterBlocked("cached attempt did not complete successfully")
    output = cached_root / "scratch" / spec["output"]
    if not output.is_file() or output.is_symlink() or _hash_file(output) != binding["expected_output_sha256"]:
        raise AdapterBlocked("cached tool output differs from the retained hash")
    receipt_path = cached_root / "pinned-tool-evidence.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected_receipt = {"schema": PINNED_RECEIPT_SCHEMA, "run_id": run_id, "job_id": spec["job"],
        "attempt_id": cached_attempt_id, "tool_id": spec["tool"], "image_id": image["image_id"],
        "image_digest": image["digest"], "result_sha256": binding["expected_output_sha256"],
        "source_snapshot_sha256": source_snapshot_sha256, "completed_at": verified["finished_at"],
        "boundary_sha256": ce.boundary_sha256(), "network_mode": "none",
        "target_read_only": True, "scratch_writable": True}
    if receipt != expected_receipt:
        raise AdapterBlocked("cached receipt was not derived from the verified attempt")
    return _output_result(receipt, binding, output, receipt_path)


def execute_registered(kind: str, *, snapshot_registry: Path, max_age_seconds: int,
                       warn_age_seconds: int | None = None,
                       run_id: str, adapter_attempt_id: str, source_snapshot_sha256: str,
                       attempt_root: Path, sbom_root: Path,
                       supplied_runtime: ce.ContainerRuntime | None = None) -> dict[str, Any]:
    if kind not in {"grype", "osv"}: raise AdapterBlocked("registered snapshots apply only to Grype and OSV")
    rt = supplied_runtime or runtime(source_snapshot_sha256)
    resolved = resolve_registered_snapshot(kind, snapshot_registry=snapshot_registry,
        max_age_seconds=max_age_seconds, warn_age_seconds=warn_age_seconds,
        now=datetime.fromisoformat(rt.clock().replace("Z", "+00:00")))
    identity = resolved["database"]
    database_kind = identity["database_kind"]
    # Re-resolve the content-addressed data root for the fixed read-only mount. The second lookup
    # re-hashes the snapshot and therefore also closes a replacement race between the gate and B13.
    try:
        full_identity = snapshots.resolve(database_kind, snapshot_registry, max_age_seconds=max_age_seconds,
                                          warn_age_seconds=warn_age_seconds,
                                          now=datetime.fromisoformat(rt.clock().replace("Z", "+00:00")))
    except (snapshots.SnapshotBlocked, snapshots.SnapshotStale, snapshots.SnapshotInvalid) as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot changed during resolution") from exc
    # The registry re-hashed the snapshot: its identity keys the database mount in the cache.
    database_path = "/inputs/" + ("grype-db" if kind == "grype" else "osv-db")
    result = execute(kind, run_id=run_id, adapter_attempt_id=adapter_attempt_id,
        source_snapshot_sha256=source_snapshot_sha256, attempt_root=attempt_root,
        sbom_root=sbom_root, database_root=Path(full_identity["data_root"]), supplied_runtime=rt,
        input_identities={database_path: "snapshot:" + digest(identity)})
    if any(full_identity[key] != identity[key] for key in identity):
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot changed during resolution")
    result.update(resolved)
    return result


def resolve_registered_snapshot(kind: str, *, snapshot_registry: Path, max_age_seconds: int,
                                warn_age_seconds: int | None = None,
                                now: datetime) -> dict[str, Any]:
    """Resolve and fully validate a registered matcher snapshot without starting its tool.

    This is the applicability-gate seam for a matcher whose accepted input class is absent.  It
    deliberately retains the same content and age validation as ``execute_registered`` so a
    per-tool skip cannot make one of the SCA job's two declared database identities disappear.
    """
    if kind not in {"grype", "osv"}:
        raise AdapterBlocked("registered snapshots apply only to Grype and OSV")
    database_kind = "grype-db" if kind == "grype" else "osv"
    try:
        identity = snapshots.resolve(database_kind, snapshot_registry, max_age_seconds=max_age_seconds,
                                     warn_age_seconds=warn_age_seconds, now=now)
    except snapshots.SnapshotBlocked as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot absent") from exc
    except snapshots.SnapshotStale as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot stale") from exc
    except snapshots.SnapshotInvalid as exc:
        raise AdapterBlocked(f"{SPECS[kind]['job']}: {database_kind} snapshot invalid") from exc
    return {
        "database": {key: identity[key] for key in
                     ("database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp")},
        "database_freshness": {key: identity[key] for key in
                               ("age_seconds", "warn_age_seconds", "max_age_seconds", "freshness", "warnings")},
    }


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
