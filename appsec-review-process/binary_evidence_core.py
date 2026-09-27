"""Nominal, static-only binary evidence workers for E06--E08.

Tool execution is intentionally outside this slice while M02 remains unresolved.  These workers
consume a closed, run-owned raw evidence record, re-verify the accepted native build and every
upstream result, and publish deterministic normalized evidence.  Target binaries are only hashed;
they are never executed.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

import native_build
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

SPECS = {
    "02-debug-symbol-index": ("debug-symbol-index", "debug-symbol-index.json", "debug-symbol-index.schema.json"),
    "02-binary-triage": ("binary-triage", "binary-triage-manifest.json", "binary-triage.schema.json"),
    "02-binary-cfg": ("binary-cfg", "cfg-manifest.json", "binary-cfg.schema.json"),
    "02-binary-intelligence-ingest": ("binary-intelligence", "binary-intelligence.json", "binary-intelligence.schema.json"),
}
RAW_SCHEMA = "appsec-review/binary-static-evidence-input/1"
M02_GAP = "m02-binary-analysis-image-pinning-unresolved"


def root(run_id: str, job: str) -> Path:
    return data_path(run_id, "jobs", job)


def control_path(run_id: str, job: str) -> Path:
    return data_path(run_id, "controls", "binary-evidence", f"{job}.json")


def _safe_rel(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Blocked(f"{label}: path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise Blocked(f"{label}: path escapes its immutable attempt")
    return path.as_posix()


def _hash(value: Any) -> str:
    return "sha256:" + digest(value)


def _native(run_id: str) -> tuple[Path, dict[str, Any]]:
    attempt = native_build.validate(run_id)
    pointer = read_json(native_build.root(run_id) / "accepted.json")
    result = read_json(attempt / native_build.RESULT)
    binaries = []
    for unit in result["units"]:
        build_identity = _hash({
            "source_revision": result["source_revision"], "unit_id": unit["unit_id"],
            "image_id": unit["image_id"], "image_digest": unit["image_digest"],
            "commands": unit["commands"], "compile_database": unit["compile_database"],
        })
        for item in unit["binaries"]:
            rel = _safe_rel(item["artifact_path"], "native-build binary")
            path = attempt / rel
            if not path.is_file() or path.is_symlink() or "sha256:" + file_hash(path) != item["sha256"]:
                raise Blocked("binary evidence: accepted native-build binary changed")
            binaries.append({
                "binary_id": "bin_" + item["sha256"][7:23], "unit_id": unit["unit_id"],
                "source_path": item["source_path"], "artifact_path": rel,
                "sha256": item["sha256"], "size_bytes": item["size_bytes"],
                "build_identity_sha256": build_identity,
            })
    binaries.sort(key=lambda x: (x["unit_id"], x["artifact_path"]))
    binding = {
        "job_id": native_build.JOB, "attempt_id": pointer["attempt_id"],
        "result_sha256": "sha256:" + file_hash(attempt / native_build.RESULT),
        "envelope_sha256": "sha256:" + file_hash(attempt / "result.json"),
        "source_revision": result["source_revision"], "binaries": binaries,
    }
    return attempt, binding


def _upstream(run_id: str, job: str) -> dict[str, Any]:
    deps = {
        "02-debug-symbol-index": [], "02-binary-triage": [],
        "02-binary-cfg": ["02-debug-symbol-index", "02-binary-triage"],
        "02-binary-intelligence-ingest": ["02-binary-triage", "02-binary-cfg"],
    }[job]
    values = {}
    for dep in deps:
        attempt = validate(run_id, dep)
        contract, result_name, _schema = SPECS[dep]
        pointer = read_json(root(run_id, dep) / "accepted.json")
        values[dep] = {
            "attempt_id": pointer["attempt_id"], "contract_id": contract,
            "result_sha256": "sha256:" + file_hash(attempt / result_name),
            "envelope_sha256": "sha256:" + file_hash(attempt / "result.json"),
            "result": read_json(attempt / result_name),
        }
    return values


def _code_hashes(job: str) -> dict[str, str]:
    contract, _result, schema = SPECS[job]
    wrapper = job[3:].replace("-", "_") + ".py"
    files = ["binary_evidence_core.py", wrapper, "publish_job_output.py",
             f"registry/output-contracts/{contract}.json"]
    values = {name: file_hash(ROOT / name) for name in files}
    values["schemas/" + schema] = file_hash(ROOT.parent / "schemas" / schema)
    return values


def current_inputs(run_id: str, job: str) -> dict[str, Any]:
    path = control_path(run_id, job)
    if not path.is_file() or path.is_symlink():
        raise Blocked(f"{job}: missing run-owned static evidence input")
    raw = read_json(path)
    _validate_raw(raw, job)
    _attempt, native = _native(run_id)
    if raw["native_build"] != {k: native[k] for k in ("job_id", "attempt_id", "result_sha256", "envelope_sha256", "source_revision")}:
        raise Blocked(f"{job}: raw evidence names a stale or cross-run native build")
    return {
        "run_id": run_id, "job_id": job, "native_build": native,
        "upstream": _upstream(run_id, job),
        "raw": raw, "raw_evidence_sha256": "sha256:" + file_hash(path),
        "config_sha256": _hash(raw["config"]), "code": _code_hashes(job),
    }


def _validate_raw(raw: Any, job: str) -> None:
    required = {"schema", "job_id", "native_build", "image", "config", "records", "gaps"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise Blocked(f"{job}: raw evidence has a non-closed top-level shape")
    if raw["schema"] != RAW_SCHEMA or raw["job_id"] != job:
        raise Blocked(f"{job}: raw evidence schema or job identity is wrong")
    native_keys = {"job_id", "attempt_id", "result_sha256", "envelope_sha256", "source_revision"}
    if not isinstance(raw["native_build"], dict) or set(raw["native_build"]) != native_keys:
        raise Blocked(f"{job}: raw native-build binding is not closed")
    image = raw["image"]
    if not isinstance(image, dict) or set(image) != {"image_id", "image_digest", "status"}:
        raise Blocked(f"{job}: image identity is not closed")
    if image["status"] != "M02_UNRESOLVED" or image["image_digest"] is not None:
        raise Blocked(f"{job}: nominal lane may not claim an M02 image identity")
    config = raw["config"]
    if not isinstance(config, dict) or set(config) != {"static_only", "adapter_id", "adapter_version"} or config["static_only"] is not True:
        raise Blocked(f"{job}: static-only configuration is required")
    if not isinstance(raw["records"], list) or not isinstance(raw["gaps"], list):
        raise Blocked(f"{job}: records and gaps must be arrays")
    if M02_GAP not in raw["gaps"]:
        raise Blocked(f"{job}: unresolved M02 prerequisite must remain explicit")


def _binary_map(inputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["binary_id"]: item for item in inputs["native_build"]["binaries"]}


def normalize(job: str, inputs: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    raw = inputs["raw"]
    binaries = _binary_map(inputs)
    records = []
    for item in raw["records"]:
        if not isinstance(item, dict) or item.get("binary_id") not in binaries:
            raise Blocked(f"{job}: record has unknown or missing binary_id")
        binary = binaries[item["binary_id"]]
        if item.get("binary_sha256") != binary["sha256"] or item.get("build_identity_sha256") != binary["build_identity_sha256"]:
            raise Blocked(f"{job}: record crosses binary or build identity")
        records.append(_normalize_record(job, item, binary, inputs))
    records.sort(key=lambda x: (x["binary_id"], json.dumps(x, sort_keys=True)))
    upstream = {name: {k: value[k] for k in ("attempt_id", "contract_id", "result_sha256", "envelope_sha256")}
                for name, value in sorted(inputs["upstream"].items())}
    schema = {
        "02-debug-symbol-index": "appsec-review/debug-symbol-index/1",
        "02-binary-triage": "appsec-review/binary-triage/1",
        "02-binary-cfg": "appsec-review/binary-cfg/1",
        "02-binary-intelligence-ingest": "appsec-review/binary-intelligence/1",
    }[job]
    return {
        "schema": schema, "run_id": inputs["run_id"], "job_id": job,
        "attempt_id": attempt_id, "status": "OK_WITH_GAPS",
        "native_build": {k: inputs["native_build"][k] for k in
                         ("job_id", "attempt_id", "result_sha256", "envelope_sha256", "source_revision")},
        "upstream": upstream, "image": raw["image"],
        "tool": {"adapter_id": raw["config"]["adapter_id"],
                 "adapter_version": raw["config"]["adapter_version"],
                 "config_sha256": inputs["config_sha256"],
                 "raw_evidence_sha256": inputs["raw_evidence_sha256"]},
        "records": records, "coverage_gaps": sorted(set(raw["gaps"])),
    }


def _base(item: dict[str, Any], binary: dict[str, Any]) -> dict[str, Any]:
    return {"binary_id": binary["binary_id"], "binary_sha256": binary["sha256"],
            "build_identity_sha256": binary["build_identity_sha256"]}


def _closed(item: dict[str, Any], keys: set[str], job: str) -> None:
    if set(item) != keys:
        raise Blocked(f"{job}: record shape is not closed")


def _normalize_record(job: str, item: dict[str, Any], binary: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    base = {"binary_id", "binary_sha256", "build_identity_sha256"}
    if job == "02-debug-symbol-index":
        _closed(item, base | {"symbol_status", "symbol_identity", "symbols", "gaps"}, job)
        if item["symbol_status"] not in {"PRESENT", "STRIPPED", "PARTIAL", "MISSING", "MISMATCH"}:
            raise Blocked(f"{job}: invalid symbol status")
        symbols = []
        for symbol in item["symbols"]:
            _closed(symbol, {"address", "size", "name", "kind", "source_path", "line"}, job)
            source = symbol["source_path"]
            if source is not None: _safe_rel(source, f"{job} symbol source")
            symbols.append(dict(symbol))
        symbols.sort(key=lambda x: (x["address"], x["name"], x["source_path"] or "", x["line"] or 0))
        duplicate = len({(x["address"], x["name"]) for x in symbols}) != len(symbols)
        gaps = sorted(set(item["gaps"] + (["duplicate-symbol-identity"] if duplicate else [])))
        return {**_base(item, binary), "symbol_status": item["symbol_status"],
                "symbol_identity": item["symbol_identity"], "symbols": symbols, "gaps": gaps}
    if job == "02-binary-triage":
        _closed(item, base | {"format", "architecture", "hardening", "sections", "imports", "packed", "stripped", "gaps"}, job)
        if item["format"] not in {"ELF", "PE", "MACHO", "WASM", "UNKNOWN"}:
            raise Blocked(f"{job}: unsupported format value")
        hardening = item["hardening"]
        if not isinstance(hardening, dict) or set(hardening) != {"nx", "pie", "relro", "stack_canary"}:
            raise Blocked(f"{job}: hardening inventory is not closed")
        return {**_base(item, binary), "format": item["format"], "architecture": item["architecture"],
                "hardening": hardening, "sections": sorted(set(item["sections"])),
                "imports": sorted(set(item["imports"])), "packed": item["packed"],
                "stripped": item["stripped"], "gaps": sorted(set(item["gaps"]))}
    if job == "02-binary-cfg":
        _closed(item, base | {"architecture", "functions", "edges", "gaps"}, job)
        upstream_bins = {r["binary_id"] for dep in inputs["upstream"].values() for r in dep["result"]["records"]}
        if binary["binary_id"] not in upstream_bins:
            raise Blocked(f"{job}: CFG binary absent from accepted triage/symbol lineage")
        functions = []
        for fn in item["functions"]:
            _closed(fn, {"address", "name", "block_count", "symbol_id"}, job)
            functions.append({**fn, "function_id": "fn_" + digest({"binary": binary["sha256"], "address": fn["address"]})[:16]})
        functions.sort(key=lambda x: (x["address"], x["name"]))
        ids = {x["function_id"] for x in functions}
        edges = []
        for edge in item["edges"]:
            _closed(edge, {"caller_address", "callee_address", "call_site"}, job)
            caller = "fn_" + digest({"binary": binary["sha256"], "address": edge["caller_address"]})[:16]
            callee = "fn_" + digest({"binary": binary["sha256"], "address": edge["callee_address"]})[:16]
            if caller not in ids or callee not in ids: raise Blocked(f"{job}: edge crosses the declared CFG")
            edges.append({"caller_function_id": caller, "callee_function_id": callee, "call_site": edge["call_site"]})
        edges.sort(key=lambda x: (x["caller_function_id"], x["call_site"], x["callee_function_id"]))
        return {**_base(item, binary), "architecture": item["architecture"],
                "functions": functions, "edges": edges, "gaps": sorted(set(item["gaps"]))}
    _closed(item, base | {"lead_type", "subject", "citations", "proof_obligation", "gaps"}, job)
    if item["lead_type"] not in {"attack-surface", "defense", "dependency", "symbol", "follow-up"}:
        raise Blocked(f"{job}: lead type is outside the closed evidence taxonomy")
    citations = []
    allowed = {(name, value["result_sha256"]) for name, value in inputs["upstream"].items()}
    for citation in item["citations"]:
        _closed(citation, {"job_id", "result_sha256", "binary_id", "record_identity"}, job)
        if (citation["job_id"], citation["result_sha256"]) not in allowed or citation["binary_id"] != binary["binary_id"]:
            raise Blocked(f"{job}: citation is stale or crosses binary identity")
        citations.append(dict(citation))
    citations.sort(key=lambda x: (x["job_id"], x["record_identity"]))
    identity = {"binary": binary["sha256"], "type": item["lead_type"], "subject": item["subject"], "citations": citations}
    return {**_base(item, binary), "lead_id": "blead_" + digest(identity)[:16],
            "lead_type": item["lead_type"], "subject": item["subject"], "citations": citations,
            "proof_obligation": item["proof_obligation"], "gaps": sorted(set(item["gaps"]))}


def _validate_attempt(run_id: str, job: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{job}: immutable inputs changed")
    _contract, result_name, schema = SPECS[job]
    result = read_json(attempt / result_name)
    if validate_document(result, schema):
        raise Blocked(f"{job}: result schema validation failed")
    if result != normalize(job, inputs, attempt.name):
        raise Blocked(f"{job}: normalized result no longer matches hash-bound raw evidence")


def run(run_id: str, dagster_id: str, job: str, force: bool = False) -> dict[str, Any]:
    contract, result_name, _schema = SPECS[job]
    base = root(run_id, job)
    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes(job): raise Blocked(f"{job}: implementation changed")
        result = normalize(job, inputs, allocation["attempt_id"])
        atomic_json(attempt / result_name, result)
        status = {"process": job, "status": "OK_WITH_GAPS", "run_id": run_id,
                  "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
                  "records": len(result["records"]), "static_only": True,
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job,
            dagster_run_id=dagster_id, worker_kind="deterministic", output_contract=contract,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status="OK_WITH_GAPS", summary=f"Published {len(result['records'])} static evidence record(s).",
            status_record=status, artifact_paths=[result_name, "status.json"], gaps=result["coverage_gaps"],
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, job, path, inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
        worker_kind="deterministic", output_contract=contract,
        resume_command=f"python -B appsec-review-process/{job[3:].replace('-', '_')}.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id, job),
        fingerprint_inputs=lambda value: _hash(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(job)},
        force=force, post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, job, attempt, inputs),
        blocked_summary=f"{job} preflight did not complete.", failed_summary=f"{job} did not publish.")


def validate(run_id: str, job: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id, job); pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id, job)
    attempt, _ = validate_published(base, pointer, _hash(inputs), expected_run_id=run_id, expected_job_id=job)
    _validate_attempt(run_id, job, attempt, inputs)
    return attempt
