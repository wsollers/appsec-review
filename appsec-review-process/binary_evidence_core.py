"""Nominal, static-only binary evidence workers for E06--E08.

The E06--E08 workers obtain their closed raw records through the M02 pinned-container adapter,
re-verify the accepted native build and every upstream result, and publish deterministic normalized
evidence.  Target binaries are statically parsed and are never executed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

import build_replay
import binary_evidence_adapter as adapter
import native_build
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
import registry_paths

SPECS = {
    "02-debug-symbol-index": ("debug-symbol-index", "debug-symbol-index.json", "debug-symbol-index.schema.json"),
    "02-binary-triage": ("binary-triage", "binary-triage-manifest.json", "binary-triage.schema.json"),
    "02-binary-cfg": ("binary-cfg", "cfg-manifest.json", "binary-cfg.schema.json"),
    "02-binary-intelligence-ingest": ("binary-intelligence", "binary-intelligence.json", "binary-intelligence.schema.json"),
}
PRIMARY_CONSUMER = {
    "02-debug-symbol-index": "02-binary-cfg",
    "02-binary-triage": "02-binary-cfg",
    "02-binary-cfg": "02-binary-intelligence-ingest",
    "02-binary-intelligence-ingest": "02-evidence-assembly",
}
RAW_SCHEMA = "appsec-review/binary-static-evidence-input/1"
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
APPLICABILITY = "applicability-receipt.json"
# Scale audit B (docs/scale-audit-unreal-engine.md): a producer whose records grow with the target
# publishes a small summary plus a JSONL records file bound by hash and count.  freeciv21 run
# 20260928T005228Z-5b0fac: the debug-symbol index was 77 MB against a 32 MiB result limit.
RECORDS_FILES = {"02-debug-symbol-index": "debug-symbol-index.records.jsonl"}


def split_records(job: str, result: dict[str, Any], destination: Path | None = None) -> dict[str, Any]:
    """Return the published summary for ``result``; optionally stream its records to JSONL."""
    name = RECORDS_FILES.get(job)
    if name is None:
        return result
    summary = {key: value for key, value in result.items() if key != "records"}
    hasher = hashlib.sha256()
    stream = destination.open("wb") if destination is not None else None
    try:
        for record in result["records"]:
            line = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    + "\n").encode("utf-8")
            hasher.update(line)
            if stream is not None:
                stream.write(line)
    finally:
        if stream is not None:
            stream.close()
    summary["records_file"] = {"path": name, "sha256": "sha256:" + hasher.hexdigest(),
                               "count": len(result["records"])}
    return summary


def load_records(job: str, attempt: Path, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Records of an accepted result, streamed from its hash-bound records file when split."""
    declared = result.get("records_file")
    if declared is None:
        return result["records"]
    if not isinstance(declared, dict) or declared.get("path") != RECORDS_FILES.get(job):
        raise Blocked(f"{job}: records file declaration is not the job's closed records file")
    path = attempt / declared["path"]
    if not path.is_file() or path.is_symlink() or "sha256:" + file_hash(path) != declared.get("sha256"):
        raise Blocked(f"{job}: published records file is missing, linked or changed")
    with path.open("r", encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream if line.strip()]
    if len(records) != declared.get("count"):
        raise Blocked(f"{job}: published records file count differs from its declaration")
    return records


def _hydrate(run_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Attach split upstream records in memory only; inputs.json keeps the hash-bound summary."""
    upstream = inputs.get("upstream") or {}
    if not any("records_file" in value.get("result", {}) for value in upstream.values()):
        return inputs
    hydrated = {}
    for dep, value in upstream.items():
        result = value["result"]
        if "records_file" in result:
            attempt = root(run_id, dep) / "attempts" / value["attempt_id"]
            value = {**value, "result": {**result, "records": load_records(dep, attempt, result)}}
        hydrated[dep] = value
    return {**inputs, "upstream": hydrated}


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


def _permissions(job: str) -> list[str]:
    value = read_json(registry_paths.template(job)).get("permissions")
    if (not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value)
            or len(value) != len(set(value))):
        raise Blocked(f"{job}: job template has no closed canonical permission binding")
    return value


def _native(run_id: str) -> tuple[Path, dict[str, Any]]:
    try:
        attempt = native_build.validate(run_id)
    except Blocked:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Blocked("binary evidence: accepted native-build publication is unavailable") from exc
    pointer = read_json(native_build.root(run_id) / "accepted.json")
    result = read_json(attempt / native_build.RESULT)
    inputs = read_json(attempt / "inputs.json")
    attested_tree = inputs.get("source_tree_sha256")
    target = Path(inputs.get("target_path", ""))
    if (not isinstance(attested_tree, str) or not attested_tree.startswith("sha256:") or
            not target.is_absolute() or build_replay.source_tree_sha256(target) != attested_tree):
        raise Blocked("binary evidence: E02 source_tree_sha256 is absent or differs from current source")
    envelope = read_json(attempt / "result.json")
    envelope_hashes = {item["path"]: "sha256:" + item["sha256"] for item in envelope["artifacts"]}
    binaries = []
    for unit in result["units"]:
        build_identity = _hash({
            "source_revision": result["source_revision"], "unit_id": unit["unit_id"],
            "image_id": unit["image_id"], "image_digest": unit["image_digest"],
            "commands": unit["commands"], "compile_database": unit["compile_database"],
        })
        for item in unit["binaries"]:
            # A byte-identical binary from another unit is the same evidence (the id is its hash).
            if any(b["sha256"] == item["sha256"] for b in binaries):
                continue
            rel = _safe_rel(item["artifact_path"], "native-build binary")
            path = attempt / rel
            if (not path.is_file() or path.is_symlink() or
                    "sha256:" + file_hash(path) != item["sha256"] or
                    envelope_hashes.get(rel) != item["sha256"]):
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
        "fingerprint": pointer["fingerprint"],
        "pointer_sha256": "sha256:" + file_hash(native_build.root(run_id) / "accepted.json"),
        "result_sha256": "sha256:" + file_hash(attempt / native_build.RESULT),
        "envelope_sha256": "sha256:" + pointer["envelope_sha256"],
        "source_revision": result["source_revision"],
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "source_tree_sha256": attested_tree, "binaries": binaries,
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
        attempt = validate(run_id, dep, consumer_job_id=job)
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
             registry_paths.contract_rel(contract), registry_paths.template_rel(job)]
    values = {name: file_hash(ROOT / name) for name in files}
    values["schemas/" + schema] = file_hash(ROOT.parent / "schemas" / schema)
    for name in ("binary-evidence-native.schema.json", "binary-evidence-authority.schema.json",
                 "binary-evidence-image.schema.json", "binary-evidence-tool.schema.json",
                 "binary-evidence-upstream.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    values["schemas/analysis-applicability-receipt.schema.json"] = file_hash(
        ROOT.parent / "schemas/analysis-applicability-receipt.schema.json")
    if job in adapter.SUPPORTED:
        values["binary_evidence_adapter.py"] = file_hash(ROOT / "binary_evidence_adapter.py")
        for name in ("binary-static-evidence-input.schema.json",
                     "binary-evidence-b13-receipts.schema.json"):
            values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _derive_intelligence_raw(native: dict[str, Any], upstream: dict[str, Any]) -> dict[str, Any]:
    """Derive review leads only from the accepted triage and CFG generations.

    This is a deterministic join, not a new binary-analysis authority.  Every emitted lead keeps
    the exact upstream record identity that supports it and remains a proof obligation rather than
    a finding or verdict.
    """
    required = {"02-binary-triage", "02-binary-cfg"}
    if set(upstream) != required:
        raise Blocked("02-binary-intelligence-ingest: accepted triage and CFG results are required")
    native_projection = {key: native[key] for key in
        ("job_id", "attempt_id", "fingerprint", "pointer_sha256", "result_sha256",
         "envelope_sha256", "source_revision", "source_snapshot_sha256", "source_tree_sha256")}
    results = {name: upstream[name]["result"] for name in sorted(required)}
    if any(value.get("native_build") != native_projection for value in results.values()):
        raise Blocked("02-binary-intelligence-ingest: upstream evidence crosses native-build generations")
    images = [value.get("image") for value in results.values()]
    if images[0] != images[1] or not isinstance(images[0], dict):
        raise Blocked("02-binary-intelligence-ingest: upstream evidence has mixed analysis images")

    triage = {item["binary_id"]: item for item in results["02-binary-triage"]["records"]}
    cfg = {item["binary_id"]: item for item in results["02-binary-cfg"]["records"]}
    binaries = {item["binary_id"]: item for item in native["binaries"]}
    if set(triage) != set(binaries) or set(cfg) != set(binaries):
        raise Blocked("02-binary-intelligence-ingest: upstream binary coverage is incomplete or mixed")

    def citation(job: str, binary_id: str, identity: str) -> dict[str, str]:
        return {"job_id": job, "result_sha256": upstream[job]["result_sha256"],
                "binary_id": binary_id, "record_identity": identity}

    records: list[dict[str, Any]] = []
    for binary_id in sorted(binaries):
        binary, triage_record, cfg_record = binaries[binary_id], triage[binary_id], cfg[binary_id]
        base = {"binary_id": binary_id, "binary_sha256": binary["sha256"],
                "build_identity_sha256": binary["build_identity_sha256"]}
        triage_citation = citation("02-binary-triage", binary_id, triage_record["triage_id"])
        gaps = sorted(set(triage_record.get("gaps", []) + cfg_record.get("gaps", [])))
        for imported in sorted(set(triage_record.get("imports", []))):
            records.append({**base, "lead_type": "dependency", "subject": f"Imported binary dependency: {imported}",
                "citations": [triage_citation],
                "proof_obligation": "Correlate the imported dependency with source/build ownership and reachable call sites.",
                "gaps": gaps})
        for check, state in sorted(triage_record.get("hardening", {}).items()):
            records.append({**base, "lead_type": "defense" if state is True else "follow-up",
                "subject": f"Binary hardening property {check}: {'present' if state is True else 'not confirmed'}",
                "citations": [triage_citation],
                "proof_obligation": "Confirm the property against the accepted binary and build configuration before drawing a security conclusion.",
                "gaps": gaps})
        for function in cfg_record.get("functions", []):
            records.append({**base, "lead_type": "symbol", "subject": f"Recovered binary function: {function['name']}",
                "citations": [citation("02-binary-cfg", binary_id, function["function_id"])],
                "proof_obligation": "Correlate the recovered function with exact source and data-flow evidence.",
                "gaps": gaps})
        for edge in cfg_record.get("edges", []):
            records.append({**base, "lead_type": "attack-surface", "subject": "Recovered binary call edge",
                "citations": [citation("02-binary-cfg", binary_id, edge["edge_id"])],
                "proof_obligation": "Determine whether untrusted input can reach this call edge in the accepted build.",
                "gaps": gaps})
        if not any(record["binary_id"] == binary_id for record in records):
            records.append({**base, "lead_type": "follow-up", "subject": "Binary evidence requires source correlation",
                "citations": [triage_citation],
                "proof_obligation": "Resolve the binary to source-level behavior before closing its review coverage.",
                "gaps": gaps})
    config = {"static_only": True, "adapter_id": "accepted-binary-evidence-join",
              "adapter_version": "1"}
    return {"schema": RAW_SCHEMA, "job_id": "02-binary-intelligence-ingest",
            "native_build": native_projection, "image": images[0], "config": config,
            "records": records, "gaps": sorted(set(gap for item in records for gap in item["gaps"]))}


def current_inputs(run_id: str, job: str) -> dict[str, Any]:
    if job in adapter.SUPPORTED:
        _attempt, native = _native(run_id)
        return {"run_id": run_id, "job_id": job, "native_build": native,
                "upstream": _upstream(run_id, job), "image": adapter.image_identity(),
                "code": _code_hashes(job)}
    if job == "02-binary-intelligence-ingest":
        _attempt, native = _native(run_id)
        upstream = _upstream(run_id, job)
        raw = _derive_intelligence_raw(native, upstream)
        return {"run_id": run_id, "job_id": job, "native_build": native,
                "upstream": upstream, "raw": raw,
                "raw_evidence_sha256": _hash(raw), "config_sha256": _hash(raw["config"]),
                "code": _code_hashes(job)}
    path = control_path(run_id, job)
    if not path.is_file() or path.is_symlink():
        raise Blocked(f"{job}: missing run-owned static evidence input")
    raw = read_json(path)
    _validate_raw(raw, job)
    _attempt, native = _native(run_id)
    if raw["native_build"] != {k: native[k] for k in ("job_id", "attempt_id", "fingerprint", "pointer_sha256", "result_sha256", "envelope_sha256", "source_revision", "source_snapshot_sha256", "source_tree_sha256")}:
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
    native_keys = {"job_id", "attempt_id", "fingerprint", "pointer_sha256", "result_sha256", "envelope_sha256", "source_revision", "source_snapshot_sha256", "source_tree_sha256"}
    if not isinstance(raw["native_build"], dict) or set(raw["native_build"]) != native_keys:
        raise Blocked(f"{job}: raw native-build binding is not closed")
    image = raw["image"]
    if not isinstance(image, dict) or set(image) != {"image_id", "image_digest", "status"}:
        raise Blocked(f"{job}: image identity is not closed")
    if (image["status"] != "PINNED" or not isinstance(image["image_digest"], str) or
            not image["image_digest"].startswith("sha256:")):
        raise Blocked(f"{job}: future normalization requires an M02-pinned image identity")
    config = raw["config"]
    if not isinstance(config, dict) or set(config) != {"static_only", "adapter_id", "adapter_version"} or config["static_only"] is not True:
        raise Blocked(f"{job}: static-only configuration is required")
    if not isinstance(raw["records"], list) or not isinstance(raw["gaps"], list):
        raise Blocked(f"{job}: records and gaps must be arrays")


def _binary_map(inputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    values = {item["binary_id"]: item for item in inputs["native_build"]["binaries"]}
    if len(values) != len(inputs["native_build"]["binaries"]):
        raise Blocked("binary evidence: accepted native build repeats a binary identity")
    return values


def _applicability(run_id: str, job: str, inputs: dict[str, Any]) -> dict[str, Any]:
    native = inputs["native_build"]
    skipped = not native["binaries"]
    return {"schema":"appsec-review/analysis-applicability-receipt/1.0", "run_id":run_id,
        "job_id":job, "decision":"SKIPPED_NA" if skipped else "APPLICABLE",
        "reason":"not-applicable-no-native-binaries" if skipped else None,
        "rationale":("The exact accepted native build contains zero binary artifacts."
                     if skipped else f"The exact accepted native build contains {len(native['binaries'])} binary artifact(s)."),
        "source_generation":native["source_snapshot_sha256"],
        "evidence":{"producer_job_id":native["job_id"], "producer_attempt_id":native["attempt_id"],
            "artifact_sha256":native["result_sha256"], "accepted_pointer_sha256":native["pointer_sha256"]}}


def normalize(job: str, inputs: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    raw = inputs["raw"]
    binaries = _binary_map(inputs)
    native_projection = {key: inputs["native_build"][key] for key in
        ("job_id", "attempt_id", "fingerprint", "pointer_sha256", "result_sha256",
         "envelope_sha256", "source_revision", "source_snapshot_sha256", "source_tree_sha256")}
    for name, upstream in inputs["upstream"].items():
        if upstream["result"].get("native_build") != native_projection:
            raise Blocked(f"{job}: accepted {name} result belongs to a mixed native-build generation")
    records = []
    for item in raw["records"]:
        if not isinstance(item, dict) or item.get("binary_id") not in binaries:
            raise Blocked(f"{job}: record has unknown or missing binary_id")
        binary = binaries[item["binary_id"]]
        if item.get("binary_sha256") != binary["sha256"] or item.get("build_identity_sha256") != binary["build_identity_sha256"]:
            raise Blocked(f"{job}: record crosses binary or build identity")
        records.append(_normalize_record(job, item, binary, inputs))
    records.sort(key=lambda x: (x["binary_id"], json.dumps(x, sort_keys=True)))
    aggregate_gaps = sorted(set(raw["gaps"] + [
        f"{record['binary_id']}:{gap}" for record in records for gap in record.get("gaps", [])]))
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
        "attempt_id": attempt_id, "status": ("SKIPPED" if not inputs["native_build"]["binaries"]
            else ("OK_WITH_GAPS" if aggregate_gaps else "OK")),
        "native_build": native_projection,
        "upstream": upstream, "authority": {"analysis_authority": "M02_PINNED_ADAPTER",
            "source_tree_sha256": inputs["native_build"]["source_tree_sha256"]}, "image": raw["image"],
        "tool": {"adapter_id": raw["config"]["adapter_id"],
                 "adapter_version": raw["config"]["adapter_version"],
                 "config_sha256": inputs["config_sha256"],
                 "raw_evidence_sha256": inputs["raw_evidence_sha256"]},
        "records": records, "coverage_gaps": aggregate_gaps,
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
            symbols.append({**symbol, "symbol_id": "sym_" + digest({"binary": binary["sha256"],
                "address": symbol["address"], "name": symbol["name"],
                "source_path": symbol["source_path"], "line": symbol["line"]})[:16]})
        symbols.sort(key=lambda x: (x["address"], x["name"], x["source_path"] or "", x["line"] or 0))
        duplicate = len({(x["address"], x["name"]) for x in symbols}) != len(symbols)
        automatic = [] if item["symbol_status"] == "PRESENT" else ["symbol-status:" + item["symbol_status"].lower()]
        gaps = sorted(set(item["gaps"] + automatic + (["duplicate-symbol-identity"] if duplicate else [])))
        return {**_base(item, binary), "symbol_status": item["symbol_status"],
                "symbol_identity": item["symbol_identity"], "symbols": symbols, "gaps": gaps}
    if job == "02-binary-triage":
        _closed(item, base | {"format", "architecture", "hardening", "sections", "imports", "packed", "stripped", "gaps"}, job)
        if item["format"] not in {"ELF", "PE", "MACHO", "WASM", "UNKNOWN"}:
            raise Blocked(f"{job}: unsupported format value")
        hardening = item["hardening"]
        if not isinstance(hardening, dict) or set(hardening) != {"nx", "pie", "relro", "stack_canary"}:
            raise Blocked(f"{job}: hardening inventory is not closed")
        gaps = list(item["gaps"])
        if item["format"] == "UNKNOWN": gaps.append("unsupported-or-unknown-binary-format")
        if item["architecture"] not in {"x86", "x86_64", "arm", "aarch64"}: gaps.append("unsupported-architecture")
        if item["packed"] != "NO": gaps.append("packed-state:" + item["packed"].lower())
        if item["stripped"] != "NO": gaps.append("stripped-state:" + item["stripped"].lower())
        triage_id = "triage_" + digest({"binary": binary["sha256"], "format": item["format"],
            "architecture": item["architecture"], "hardening": hardening})[:16]
        return {**_base(item, binary), "triage_id": triage_id, "format": item["format"], "architecture": item["architecture"],
                "hardening": hardening, "sections": sorted(set(item["sections"])),
                "imports": sorted(set(item["imports"])), "packed": item["packed"],
                "stripped": item["stripped"], "gaps": sorted(set(gaps))}
    if job == "02-binary-cfg":
        _closed(item, base | {"architecture", "functions", "edges", "gaps"}, job)
        debug_records = [r for r in inputs["upstream"]["02-debug-symbol-index"]["result"]["records"] if r["binary_id"] == binary["binary_id"]]
        triage_records = [r for r in inputs["upstream"]["02-binary-triage"]["result"]["records"] if r["binary_id"] == binary["binary_id"]]
        if len(debug_records) != 1 or len(triage_records) != 1 or triage_records[0]["architecture"] != item["architecture"]:
            raise Blocked(f"{job}: CFG does not exactly join one matching symbol/triage binary and architecture")
        symbol_ids = {s["symbol_id"] for s in debug_records[0]["symbols"]}
        functions = []
        for fn in item["functions"]:
            _closed(fn, {"address", "name", "block_count", "symbol_id"}, job)
            if fn["symbol_id"] is not None and fn["symbol_id"] not in symbol_ids:
                raise Blocked(f"{job}: CFG function cites an absent symbol identity")
            functions.append({**fn, "function_id": "fn_" + digest({"binary": binary["sha256"], "address": fn["address"]})[:16]})
        functions.sort(key=lambda x: (x["address"], x["name"]))
        ids = {x["function_id"] for x in functions}
        edges = []
        for edge in item["edges"]:
            _closed(edge, {"caller_address", "callee_address", "call_site"}, job)
            caller = "fn_" + digest({"binary": binary["sha256"], "address": edge["caller_address"]})[:16]
            callee = "fn_" + digest({"binary": binary["sha256"], "address": edge["callee_address"]})[:16]
            if caller not in ids or callee not in ids: raise Blocked(f"{job}: edge crosses the declared CFG")
            edges.append({"edge_id": "edge_" + digest({"binary": binary["sha256"], "caller": caller,
                "callee": callee, "site": edge["call_site"]})[:16],
                "caller_function_id": caller, "callee_function_id": callee, "call_site": edge["call_site"]})
        edges.sort(key=lambda x: (x["caller_function_id"], x["call_site"], x["callee_function_id"]))
        gaps = list(item["gaps"])
        if item["architecture"] not in {"x86", "x86_64", "arm", "aarch64"}: gaps.append("unsupported-architecture")
        if not functions: gaps.append("partial-or-empty-cfg")
        return {**_base(item, binary), "architecture": item["architecture"],
                "functions": functions, "edges": edges, "gaps": sorted(set(gaps))}
    _closed(item, base | {"lead_type", "subject", "citations", "proof_obligation", "gaps"}, job)
    if item["lead_type"] not in {"attack-surface", "defense", "dependency", "symbol", "follow-up"}:
        raise Blocked(f"{job}: lead type is outside the closed evidence taxonomy")
    citations = []
    allowed = {(name, value["result_sha256"]) for name, value in inputs["upstream"].items()}
    identities = {}
    for name, value in inputs["upstream"].items():
        found = set()
        for record in value["result"]["records"]:
            if record["binary_id"] != binary["binary_id"]: continue
            if "triage_id" in record: found.add(record["triage_id"])
            found.update(fn["function_id"] for fn in record.get("functions", []))
            found.update(edge["edge_id"] for edge in record.get("edges", []))
        identities[name] = found
    for citation in item["citations"]:
        _closed(citation, {"job_id", "result_sha256", "binary_id", "record_identity"}, job)
        if ((citation["job_id"], citation["result_sha256"]) not in allowed or
                citation["binary_id"] != binary["binary_id"] or
                citation["record_identity"] not in identities.get(citation["job_id"], set())):
            raise Blocked(f"{job}: citation is stale or crosses binary identity")
        citations.append(dict(citation))
    citations.sort(key=lambda x: (x["job_id"], x["record_identity"]))
    identity = {"binary": binary["sha256"], "type": item["lead_type"], "subject": item["subject"], "citations": citations}
    return {**_base(item, binary), "lead_id": "blead_" + digest(identity)[:16],
            "lead_type": item["lead_type"], "subject": item["subject"], "citations": citations,
            "proof_obligation": item["proof_obligation"], "gaps": sorted(set(item["gaps"]))}


def _materialized_inputs(run_id: str, job: str, attempt: Path,
                         inputs: dict[str, Any]) -> dict[str, Any]:
    inputs = _hydrate(run_id, inputs)
    if job not in adapter.SUPPORTED:
        return inputs
    native_attempt, current = _native(run_id)
    if current != inputs["native_build"]:
        raise Blocked(f"{job}: accepted native build changed after input allocation")
    raw = adapter.validate_materialized(run_id, job, attempt, native_attempt, inputs)
    return {**inputs, "raw": raw,
            "raw_evidence_sha256": "sha256:" + file_hash(attempt / adapter.RAW_FILE),
            "config_sha256": _hash(raw["config"])}


def _validate_attempt(run_id: str, job: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{job}: immutable inputs changed")
    effective = _materialized_inputs(run_id, job, attempt, inputs)
    _contract, result_name, schema = SPECS[job]
    result = read_json(attempt / result_name)
    if validate_document(result, schema):
        raise Blocked(f"{job}: result schema validation failed")
    expected = normalize(job, effective, attempt.name)
    if job in RECORDS_FILES and validate_document(expected, schema):
        raise Blocked(f"{job}: normalized records fail schema validation")
    if result != split_records(job, expected):
        raise Blocked(f"{job}: normalized result no longer matches hash-bound raw evidence")
    if job in RECORDS_FILES:
        load_records(job, attempt, result)  # the on-disk records file matches the declared hash
    lineage_keys = ("job_id", "attempt_id", "fingerprint", "pointer_sha256", "envelope_sha256", "result_sha256", "source_revision")
    native_lineage = {key: inputs["native_build"][key] for key in lineage_keys}
    permission = {"schema": PERMISSION_SCHEMA, "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": inputs["native_build"]["source_snapshot_sha256"],
        "permissions": _permissions(job)}
    lineage = {"schema": LINEAGE_SCHEMA, "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": inputs["native_build"]["source_snapshot_sha256"],
        "build_lineage_sha256": _hash(native_lineage)}
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{job}: evidence-assembly receipts changed")
    applicability = read_json(attempt / APPLICABILITY)
    if (applicability != _applicability(run_id, job, inputs) or
            validate_document(applicability, "analysis-applicability-receipt.schema.json")):
        raise Blocked(f"{job}: applicability receipt changed")


def run(run_id: str, dagster_run_id: str, job_id: str, force: bool = False) -> dict[str, Any]:
    job = job_id
    contract, result_name, _schema = SPECS[job]
    base = root(run_id, job)
    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes(job): raise Blocked(f"{job}: implementation changed")
        effective = _hydrate(run_id, inputs)
        if job in adapter.SUPPORTED:
            native_attempt, current = _native(run_id)
            if current != inputs["native_build"]:
                raise Blocked(f"{job}: accepted native build changed after input allocation")
            raw = adapter.materialize(run_id, job, attempt, native_attempt, effective)
            effective = {**effective, "raw": raw,
                "raw_evidence_sha256": "sha256:" + file_hash(attempt / adapter.RAW_FILE),
                "config_sha256": _hash(raw["config"])}
        result = normalize(job, effective, allocation["attempt_id"])
        records_name = RECORDS_FILES.get(job)
        atomic_json(attempt / result_name, split_records(
            job, result, attempt / records_name if records_name else None))
        lineage_keys = ("job_id", "attempt_id", "fingerprint", "pointer_sha256", "envelope_sha256", "result_sha256", "source_revision")
        native_lineage = {key: inputs["native_build"][key] for key in lineage_keys}
        atomic_json(attempt / "permission.json", {"schema": PERMISSION_SCHEMA, "run_id": run_id,
            "job_id": job, "source_snapshot_sha256": inputs["native_build"]["source_snapshot_sha256"],
            "permissions": _permissions(job)})
        atomic_json(attempt / "lineage.json", {"schema": LINEAGE_SCHEMA, "run_id": run_id,
            "job_id": job, "source_snapshot_sha256": inputs["native_build"]["source_snapshot_sha256"],
            "build_lineage_sha256": _hash(native_lineage)})
        atomic_json(attempt / APPLICABILITY, _applicability(run_id, job, inputs))
        status = {"process": job, "status": result["status"], "run_id": run_id,
                  "dagster_run_id": dagster_run_id, "attempt_id": allocation["attempt_id"],
                  "records": len(result["records"]), "static_only": True,
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        artifact_paths = [result_name, "status.json", "permission.json", "lineage.json", APPLICABILITY]
        if records_name:
            artifact_paths.append(records_name)
        if job in adapter.SUPPORTED:
            artifact_paths += [adapter.RAW_FILE, adapter.RECEIPT_FILE]
        skip_reason = "not-applicable-no-native-binaries" if result["status"] == "SKIPPED" else None
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job,
            dagster_run_id=dagster_run_id,
            worker_kind="pinned_container" if job in adapter.SUPPORTED else "deterministic_python",
            output_contract=contract,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=result["status"], summary=f"Published {len(result['records'])} static evidence record(s).",
            status_record=status, artifact_paths=artifact_paths, gaps=result["coverage_gaps"],
            skip_reason=skip_reason,
            consumer_job_id=PRIMARY_CONSUMER.get(job),
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, job, path, inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job, dagster_run_id=dagster_run_id,
        worker_kind="pinned_container" if job in adapter.SUPPORTED else "deterministic_python",
        output_contract=contract,
        resume_command=f"python -B appsec-review-process/{job[3:].replace('-', '_')}.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id, job),
        fingerprint_inputs=lambda value: _hash(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(job)},
        force=force, post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, job, attempt, inputs),
        consumer_job_id=PRIMARY_CONSUMER.get(job),
        blocked_summary=f"{job} preflight did not complete.", failed_summary=f"{job} did not publish.")


def validate(run_id: str, job: str, pointer: dict[str, Any] | None = None,
             consumer_job_id: str | None = None) -> Path:
    base = root(run_id, job); pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id, job)
    attempt, _ = validate_published(base, pointer, _hash(inputs), expected_run_id=run_id,
        expected_job_id=job, consumer_job_id=consumer_job_id or PRIMARY_CONSUMER.get(job))
    _validate_attempt(run_id, job, attempt, inputs)
    return attempt


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
