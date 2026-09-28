"""Pinned, static-only M02 adapter for native binary evidence.

The adapter mounts the immutable accepted ``02-native-build`` attempt read-only and invokes only
tools shipped in the registered ``audit-binary-analysis`` image.  Target binaries are arguments to
static parsers; they are never launched.  Every container result is re-verified through B13 before
its bounded raw output is parsed.
"""
from __future__ import annotations

import tunables
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import threading
from typing import Any, Callable

import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, digest, file_hash, read_json
import permission_capabilities as pc
from schema_validate import validate_document

IMAGE_ID = "audit-binary-analysis"
ADAPTER_ID = "appsec-review/binary-static-container-adapter"
ADAPTER_VERSION = "1.0"
RAW_FILE = "binary-static-raw.json"
RECEIPT_FILE = "binary-b13-receipts.json"
RAW_SCHEMA = "appsec-review/binary-static-evidence-input/1"
RECEIPT_SCHEMA = "appsec-review/binary-b13-receipts/1.0"
SUPPORTED = {"02-debug-symbol-index", "02-binary-triage", "02-binary-cfg"}
MAX_RAW_BYTES = tunables.shared("binary_raw_output_max_bytes")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash(value: Any) -> str:
    return "sha256:" + digest(value)


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable,
            "container_user": runtime.container_user}


def image_identity() -> dict[str, Any]:
    try:
        registry = ce.load_image_registry(ce.IMAGES_DIR)
    except ce.ContainerRequestError as exc:
        raise Blocked("binary evidence: the pinned container image registry is unavailable") from exc
    record = registry.get(IMAGE_ID)
    path = ce.IMAGES_DIR / f"{IMAGE_ID}.json"
    if record is None or not path.is_file() or path.is_symlink() or read_json(path) != record:
        raise Blocked("binary evidence: audit-binary-analysis has no unambiguous registered identity")
    return {"record": record, "record_sha256": "sha256:" + file_hash(path),
            "boundary_sha256": ce.boundary_sha256()}


def _runtime(source_sha256: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked("binary evidence: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source_sha256,
        registry_ceiling=[], clock=_utc, cancel=threading.Event())


def _permission(run_id: str, job: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job,
                   "capabilities": []}
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def _request(run_id: str, job: str, adapter_attempt: str, image: dict[str, Any],
             source: str, native_attempt: Path, binary_path: str) -> dict[str, Any]:
    if job in {"02-debug-symbol-index", "02-binary-triage"}:
        argv = ["/usr/local/bin/analyze-binary", "/workspace/" + binary_path,
                "/scratch/evidence"]
    else:
        argv = ["/usr/local/bin/angr-summary", "/workspace/" + binary_path]
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": job,
        "attempt_id": adapter_attempt,
        "image": {"image_id": IMAGE_ID, "digest": image["record"]["digest"]},
        "argv": argv,
        "environment": [{"name": "LANG", "value": "C"},
                        {"name": "LC_ALL", "value": "C"},
                        {"name": "NO_COLOR", "value": "1"},
                        {"name": "LOGNAME", "value": "appsec-worker"},
                        {"name": "USER", "value": "appsec-worker"}],
        "target_mounts": [{"host_path": str(native_attempt), "container_path": "/workspace"}],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, job, source, _utc()), "limits": tunables.container_limits(job)}


def _bounded_text(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_RAW_BYTES:
        raise Blocked("binary evidence: required container output is absent or exceeds its bound")
    return path.read_text(encoding="utf-8", errors="replace")


def _bounded_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_bounded_text(path))
    except ValueError as exc:
        raise Blocked("binary evidence: container output is not valid JSON") from exc
    if not isinstance(value, dict):
        raise Blocked("binary evidence: container JSON output is not an object")
    return value


_NM = re.compile(r"^\s*([0-9A-Fa-f]+)\s+(\S)\s+(.+?)\s*$")


def _debug_record(binary: dict[str, Any], raw_root: Path) -> dict[str, Any]:
    summary = _bounded_json(raw_root / "summary.json")
    symbols = []
    for line in _bounded_text(raw_root / "nm-symbols.txt").splitlines():
        match = _NM.match(line)
        if not match:
            continue
        symbols.append({"address": "0x" + match.group(1).lower(), "size": 0,
            "name": match.group(3), "kind": match.group(2), "source_path": None, "line": None})
    symbols = sorted(symbols, key=lambda item: (item["address"], item["name"]))[:100_000]
    has_debug = summary.get("has_debug_sections") is True
    status = "PRESENT" if has_debug else ("STRIPPED" if symbols else "MISSING")
    gaps = []
    if any(item["source_path"] is None for item in symbols):
        gaps.append("source-locations-unavailable")
    return {"binary_id": binary["binary_id"], "binary_sha256": binary["sha256"],
        "build_identity_sha256": binary["build_identity_sha256"], "symbol_status": status,
        "symbol_identity": _hash({"binary": binary["sha256"], "symbols": symbols}),
        "symbols": symbols, "gaps": gaps}


def _architecture(value: Any) -> str:
    text = str(value or "").lower()
    if any(mark in text for mark in ("x86_64", "x86-64", "amd64", "em_x86_64")): return "x86_64"
    if any(mark in text for mark in ("aarch64", "arm64")): return "aarch64"
    if "arm" in text: return "arm"
    if any(mark in text for mark in ("80386", "i386", "x86")): return "x86"
    return text or "unknown"


def _hardening(checksec: str) -> dict[str, str]:
    text = checksec.lower()
    return {
        "nx": "DISABLED" if "nx disabled" in text else ("ENABLED" if "nx enabled" in text else "UNKNOWN"),
        "pie": "DISABLED" if "no pie" in text else ("ENABLED" if " pie " in f" {text} " else "UNKNOWN"),
        "relro": "FULL" if "full relro" in text else ("PARTIAL" if "partial relro" in text else
                  ("NONE" if "no relro" in text else "UNKNOWN")),
        "stack_canary": "ABSENT" if "no canary" in text else
                        ("PRESENT" if "canary found" in text else "UNKNOWN"),
    }


def _triage_record(binary: dict[str, Any], raw_root: Path) -> dict[str, Any]:
    summary = _bounded_json(raw_root / "summary.json")
    kind = str(summary.get("format", "unknown")).upper()
    if kind not in {"ELF", "PE", "MACHO", "WASM"}: kind = "UNKNOWN"
    symbols = summary.get("symbol_count")
    stripped = "NO" if isinstance(symbols, int) and symbols > 0 else "YES"
    imports = summary.get("imports", summary.get("lief", {}).get("libraries", []))
    if not isinstance(imports, list): imports = []
    sections = summary.get("sections", [])
    if not isinstance(sections, list): sections = []
    return {"binary_id": binary["binary_id"], "binary_sha256": binary["sha256"],
        "build_identity_sha256": binary["build_identity_sha256"], "format": kind,
        "architecture": _architecture(summary.get("machine")),
        "hardening": _hardening(_bounded_text(raw_root / "checksec.txt")),
        "sections": [str(item) for item in sections[:10_000]],
        "imports": [str(item) for item in imports[:10_000]], "packed": "UNKNOWN",
        "stripped": stripped, "gaps": ["static-packer-classification-inconclusive"]}


def _cfg_record(binary: dict[str, Any], stdout: Path, upstream: dict[str, Any]) -> dict[str, Any]:
    summary = _bounded_json(stdout)
    raw_functions = summary.get("functions")
    raw_edges = summary.get("call_edges")
    if not isinstance(raw_functions, list) or not isinstance(raw_edges, list):
        raise Blocked("binary evidence: angr output omits its CFG arrays")
    debug = next((item for item in upstream["02-debug-symbol-index"]["result"]["records"]
                  if item["binary_id"] == binary["binary_id"]), None)
    if debug is None:
        raise Blocked("binary evidence: CFG has no matching accepted symbol record")
    symbol_by_address = {item["address"].lower(): item["symbol_id"] for item in debug["symbols"]}
    symbol_by_name = {item["name"]: item["symbol_id"] for item in debug["symbols"]}
    functions = []
    address_by_name = {}
    for item in raw_functions[:100_000]:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise Blocked("binary evidence: angr emitted an invalid function record")
        address, name = item["address"].lower(), str(item.get("name", ""))
        address_by_name.setdefault(name, address)
        functions.append({"address": address, "name": name,
            "block_count": int(item.get("block_count", 0)),
            "symbol_id": symbol_by_address.get(address, symbol_by_name.get(name))})
    declared = {item["address"] for item in functions}
    edges = []
    for item in raw_edges[:200_000]:
        if not isinstance(item, dict):
            raise Blocked("binary evidence: angr emitted an invalid call-edge record")
        caller = address_by_name.get(str(item.get("caller", "")))
        callee, site = str(item.get("target", "")).lower(), str(item.get("call_site", "")).lower()
        if caller in declared and callee in declared:
            edges.append({"caller_address": caller, "callee_address": callee, "call_site": site})
    gaps = [] if len(edges) == len(raw_edges) else ["unresolved-external-or-indirect-call-edges"]
    return {"binary_id": binary["binary_id"], "binary_sha256": binary["sha256"],
        "build_identity_sha256": binary["build_identity_sha256"],
        "architecture": _architecture(summary.get("architecture")),
        "functions": functions, "edges": edges, "gaps": gaps}


def materialize(run_id: str, job: str, attempt: Path, native_attempt: Path,
                inputs: dict[str, Any], *, runtime_factory: Callable[[str], ce.ContainerRuntime] = _runtime,
                run_container: Callable[..., dict[str, Any]] = ce.run_container,
                verify: Callable[..., dict[str, Any]] = ce.load_verified_result) -> dict[str, Any]:
    if job not in SUPPORTED:
        raise Blocked("binary evidence: adapter does not own this job")
    native, image = inputs["native_build"], inputs["image"]
    native_projection = {key: native[key] for key in native if key != "binaries"}
    records, receipts = [], []
    runtime = runtime_factory(native["source_snapshot_sha256"]) if native["binaries"] else None
    for ordinal, binary in enumerate(native["binaries"], start=1):
        relative = PurePosixPath(binary["artifact_path"])
        if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
            raise Blocked("binary evidence: accepted binary path is unsafe")
        adapter_attempt = f"binary-{ordinal:04d}-{attempt.name[:8]}"
        trial = attempt / "tools" / f"{ordinal:04d}"
        trial.mkdir(parents=True)
        request = _request(run_id, job, adapter_attempt, image,
                           native["source_snapshot_sha256"], native_attempt, relative.as_posix())
        terminal = run_container(runtime, run_id=run_id, job_id=job,
            attempt_id=adapter_attempt, attempt_root=trial, request=request)
        expected = terminal["result_sha256"]
        verify(trial, run_id=run_id, job_id=job, attempt_id=adapter_attempt,
            request=request, images_dir=runtime.images_dir, expected_result_sha256=expected,
            **_host(runtime))
        if terminal["execution_status"] != "OK":
            raise Blocked("binary evidence: pinned static analyzer did not complete")
        if job == "02-debug-symbol-index":
            record = _debug_record(binary, trial / "scratch/evidence")
            outputs = [trial / "scratch/evidence/summary.json",
                       trial / "scratch/evidence/nm-symbols.txt"]
        elif job == "02-binary-triage":
            record = _triage_record(binary, trial / "scratch/evidence")
            outputs = [trial / "scratch/evidence/summary.json",
                       trial / "scratch/evidence/checksec.txt"]
        else:
            outputs = [trial / "logs/container/stdout.log"]
            record = _cfg_record(binary, outputs[0], inputs["upstream"])
        records.append(record)
        receipts.append({"binary_id": binary["binary_id"], "binary_sha256": binary["sha256"],
            "adapter_attempt_id": adapter_attempt, "trial_path": trial.relative_to(attempt).as_posix(),
            "request_sha256": "sha256:" + file_hash(trial / "logs/container" / ce.REQUEST_FILE),
            "expected_result_sha256": expected,
            "output_files": [{"path": output.relative_to(trial).as_posix(),
                              "sha256": "sha256:" + file_hash(output)} for output in outputs]})
    raw = {"schema": RAW_SCHEMA, "job_id": job, "native_build": native_projection,
        "image": {"image_id": IMAGE_ID, "image_digest": image["record"]["digest"], "status": "PINNED"},
        "config": {"static_only": True, "adapter_id": ADAPTER_ID,
                   "adapter_version": ADAPTER_VERSION}, "records": records, "gaps": []}
    receipt = {"schema": RECEIPT_SCHEMA, "run_id": run_id, "job_id": job,
        "native_build": native_projection, "image_id": IMAGE_ID,
        "image_digest": image["record"]["digest"],
        "image_record_sha256": image["record_sha256"],
        "boundary_sha256": image["boundary_sha256"], "network_mode": "none",
        "target_execution": False, "operations": receipts}
    atomic_json(attempt / RAW_FILE, raw)
    atomic_json(attempt / RECEIPT_FILE, receipt)
    return raw


def validate_materialized(run_id: str, job: str, attempt: Path, native_attempt: Path,
                          inputs: dict[str, Any]) -> dict[str, Any]:
    raw, receipt = read_json(attempt / RAW_FILE), read_json(attempt / RECEIPT_FILE)
    errors = validate_document(raw, "binary-static-evidence-input.schema.json")
    errors += validate_document(receipt, "binary-evidence-b13-receipts.schema.json")
    if errors:
        raise Blocked(f"{job}: retained binary adapter evidence fails schema validation")
    native, image = inputs["native_build"], inputs["image"]
    projection = {key: native[key] for key in native if key != "binaries"}
    if (raw["job_id"] != job or raw["native_build"] != projection or
            receipt["run_id"] != run_id or receipt["job_id"] != job or
            receipt["native_build"] != projection or receipt["image_digest"] != image["record"]["digest"] or
            receipt["image_record_sha256"] != image["record_sha256"] or
            receipt["boundary_sha256"] != ce.boundary_sha256() or receipt["target_execution"] is not False or
            len(receipt["operations"]) != len(native["binaries"])):
        raise Blocked(f"{job}: retained binary adapter lineage is stale or incomplete")
    runtime = _runtime(native["source_snapshot_sha256"]) if native["binaries"] else None
    by_id = {item["binary_id"]: item for item in native["binaries"]}
    reparsed = []
    for ordinal, operation in enumerate(receipt["operations"], start=1):
        binary = by_id.get(operation["binary_id"])
        expected_trial = f"tools/{ordinal:04d}"
        if binary is None or operation["binary_sha256"] != binary["sha256"] or operation["trial_path"] != expected_trial:
            raise Blocked(f"{job}: retained binary operation crosses accepted identity")
        trial = attempt.joinpath(*PurePosixPath(expected_trial).parts)
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        if "sha256:" + file_hash(trial / "logs/container" / ce.REQUEST_FILE) != operation["request_sha256"]:
            raise Blocked(f"{job}: retained binary operation output changed")
        for output in operation["output_files"]:
            path = trial.joinpath(*PurePosixPath(output["path"]).parts)
            if "sha256:" + file_hash(path) != output["sha256"]:
                raise Blocked(f"{job}: retained binary operation output changed")
        verify_errors = ce.verify_container_result(trial, run_id=run_id, job_id=job,
            attempt_id=operation["adapter_attempt_id"], request=request, images_dir=runtime.images_dir,
            expected_result_sha256=operation["expected_result_sha256"], **_host(runtime))
        if verify_errors:
            raise Blocked(f"{job}: retained binary container receipt failed verification")
        if job == "02-debug-symbol-index": reparsed.append(_debug_record(binary, trial / "scratch/evidence"))
        elif job == "02-binary-triage": reparsed.append(_triage_record(binary, trial / "scratch/evidence"))
        else: reparsed.append(_cfg_record(binary, trial / "logs/container/stdout.log", inputs["upstream"]))
    if raw["records"] != reparsed:
        raise Blocked(f"{job}: retained raw records differ from hash-bound analyzer outputs")
    return raw
