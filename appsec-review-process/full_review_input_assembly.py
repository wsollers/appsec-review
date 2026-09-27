#!/usr/bin/env python3
"""Assemble exact, run-owned launch requests for the standalone analysis families.

The assembler is deliberately not a scheduler.  It joins current accepted producer artifacts,
checks their source generation, resolves a small closed set of config references, and emits the
request dialect already consumed by each public orchestration adapter.  A later graph binding can
dispatch these requests without re-deriving or weakening their evidence lineage.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any

from bounded_analysis_workers import load_accepted
from bounded_transform_orchestration import REQUEST_SCHEMA as BOUNDED_SCHEMA, FACADES
from dependency_orchestration import (REQUEST_SCHEMA as DEPENDENCY_SCHEMA,
                                      JOBS as DEPENDENCY_JOBS, _PAYLOAD_KEYS, _TOOL_KEYS)
from execution_state import Blocked, atomic_json, digest, file_hash, identifier, read_json, tree_hashes
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from vendor_evidence_orchestration import REQUEST_SCHEMA as VENDOR_SCHEMA, WORKERS
from worker_result import artifact_records, terminal_envelope, validate_worker_result

JOB = "02-full-review-input-assembly"
CONTRACT = "full-review-input-assembly"
RESULT = "full-review-input-assembly.json"
PLAN_SCHEMA = "appsec-review/full-review-input-plan/1.0"
RESULT_SCHEMA = "appsec-review/full-review-input-assembly/1.0"
HASH = "sha256:"

_PLAN_KEYS = {"schema", "run_id", "source_generation", "generated_at", "accepted_sources", "launches"}
_SOURCE_KEYS = {"alias", "pointer_path", "job_id", "contract", "artifact", "artifact_schema",
                "generation_pointer"}
_LAUNCH_KEYS = {
    "bounded": {"adapter", "job_id", "upstream", "payload"},
    "vendor": {"adapter", "job_id", "source_root"},
    "dependency": {"adapter", "job_id", "payload", "tool"},
}


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise Blocked(f"full review input assembly: {label} shape is not closed")
    return value


def _relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise Blocked(f"full review input assembly: {label} must be a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked(f"full review input assembly: {label} must be a normalized relative path")
    return path


def _owned(run_root: Path, value: Any, label: str, *, kind: str | None = None) -> Path:
    relative = _relative(value, label)
    candidate = run_root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(run_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"full review input assembly: {label} is not a run-owned path") from exc
    if candidate.is_symlink() or (kind == "file" and not candidate.is_file()) or (
            kind == "directory" and not candidate.is_dir()):
        raise Blocked(f"full review input assembly: {label} has the wrong path kind")
    return candidate.absolute()


def _pointer(document: Any, pointer: Any, label: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise Blocked(f"full review input assembly: {label} must be an absolute JSON pointer")
    current = document
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise Blocked(f"full review input assembly: {label} does not resolve")
    return current


def _source_files(root: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Blocked("full review input assembly: source tree contains a symbolic link")
        if path.is_file():
            rows[path.relative_to(root).as_posix()] = HASH + file_hash(path)
    return rows


def _resolve(value: Any, *, run_root: Path, sources: dict[str, dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_resolve(item, run_root=run_root, sources=sources) for item in value]
    if not isinstance(value, dict):
        return value
    keys = set(value)
    if keys == {"$accepted", "pointer"}:
        alias = value["$accepted"]
        if alias not in sources:
            raise Blocked("full review input assembly: accepted source alias is unknown")
        return _resolve(_pointer(sources[alias]["document"], value["pointer"], f"{alias} value"),
                        run_root=run_root, sources=sources)
    if keys == {"$metadata", "field"}:
        alias, field = value["$metadata"], value["field"]
        if alias not in sources or field not in sources[alias]["binding"]:
            raise Blocked("full review input assembly: accepted metadata reference is unknown")
        return sources[alias]["binding"][field]
    if keys == {"$binding"}:
        alias = value["$binding"]
        if alias not in sources:
            raise Blocked("full review input assembly: binding source alias is unknown")
        source, binding = sources[alias], sources[alias]["binding"]
        artifact_path = source["pointer"].parent / "attempts" / binding["attempt_id"] / binding["artifact_path"]
        return {"attempt_id": binding["attempt_id"], "path": str(artifact_path.absolute()),
                "sha256": binding["artifact_sha256"], "accepted_path": str(source["pointer"].absolute())}
    if keys == {"$run_path", "kind"}:
        if value["kind"] not in {"file", "directory"}:
            raise Blocked("full review input assembly: run path kind is invalid")
        return str(_owned(run_root, value["$run_path"], "resolved run path", kind=value["kind"]))
    if keys == {"$source_files"}:
        root = _owned(run_root, value["$source_files"], "source file root", kind="directory")
        return _source_files(root)
    if any(isinstance(key, str) and key.startswith("$") for key in keys):
        raise Blocked("full review input assembly: resolver expression is not closed")
    return {key: _resolve(item, run_root=run_root, sources=sources) for key, item in value.items()}


def _referenced_aliases(value: Any) -> set[str]:
    if isinstance(value, list):
        return set().union(*(_referenced_aliases(item) for item in value), set())
    if not isinstance(value, dict):
        return set()
    aliases = {value[key] for key in ("$accepted", "$metadata", "$binding")
               if key in value and isinstance(value[key], str)}
    return aliases | set().union(*(_referenced_aliases(item) for item in value.values()), set())


def _load_sources(plan: dict[str, Any], run_root: Path) -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for raw in plan["accepted_sources"]:
        source = _closed(raw, _SOURCE_KEYS, "accepted source")
        alias = source["alias"]
        if not isinstance(alias, str) or not alias or alias in sources:
            raise Blocked("full review input assembly: accepted source aliases must be unique")
        pointer = _owned(run_root, source["pointer_path"], f"{alias} accepted pointer", kind="file")
        document, binding = load_accepted(pointer, run_id=plan["run_id"], job_id=source["job_id"],
            contract=source["contract"], artifact=source["artifact"], schema=source["artifact_schema"])
        if _pointer(document, source["generation_pointer"], f"{alias} source generation") != plan["source_generation"]:
            raise Blocked("full review input assembly: accepted sources contain a stale or mixed generation")
        sources[alias] = {"document": document, "binding": binding, "pointer": pointer, "spec": source}
    return sources


def _bounded(raw: dict[str, Any], plan: dict[str, Any], sources: dict[str, dict[str, Any]], run_root: Path) -> dict[str, Any]:
    job = raw["job_id"]
    if job not in FACADES or not isinstance(raw["upstream"], list) or not raw["upstream"]:
        raise Blocked("full review input assembly: bounded launch job or upstream is invalid")
    upstream = []
    for alias in raw["upstream"]:
        if alias not in sources:
            raise Blocked("full review input assembly: bounded upstream alias is unknown")
        source = sources[alias]
        spec = source["spec"]
        upstream.append({"pointer_path": str(source["pointer"].absolute()), "job_id": spec["job_id"],
                         "contract": spec["contract"], "artifact": spec["artifact"],
                         "schema": spec["artifact_schema"]})
    payload = _resolve(raw["payload"], run_root=run_root, sources=sources)
    payload_aliases = _referenced_aliases(raw["payload"])
    if not payload_aliases or not payload_aliases.issubset(set(raw["upstream"])):
        raise Blocked("full review input assembly: bounded payload must derive from its accepted upstream")
    expected_key = FACADES[job][2]
    if not isinstance(payload, dict) or set(payload) != {expected_key} or not isinstance(payload[expected_key], list):
        raise Blocked(f"full review input assembly: bounded payload must contain only {expected_key}")
    return {"schema": BOUNDED_SCHEMA, "run_id": plan["run_id"], "job_id": job,
            "source_generation": plan["source_generation"], "upstream": upstream, "payload": payload}


def _vendor(raw: dict[str, Any], plan: dict[str, Any], sources: dict[str, dict[str, Any]], run_root: Path) -> dict[str, Any]:
    job = raw["job_id"]
    if job not in WORKERS:
        raise Blocked("full review input assembly: vendor launch job is invalid")
    source_root = _resolve(raw["source_root"], run_root=run_root, sources=sources)
    if not isinstance(source_root, str):
        raise Blocked("full review input assembly: vendor source root did not resolve to a path")
    return {"schema": VENDOR_SCHEMA, "run_id": plan["run_id"], "job_id": job,
            "source_generation": plan["source_generation"], "generated_at": plan["generated_at"],
            "source_root": source_root}


def _dependency(raw: dict[str, Any], plan: dict[str, Any], sources: dict[str, dict[str, Any]], run_root: Path) -> dict[str, Any]:
    job = raw["job_id"]
    if job not in DEPENDENCY_JOBS:
        raise Blocked("full review input assembly: dependency launch job is invalid")
    kind = DEPENDENCY_JOBS[job]
    if kind != "sbom" and not _referenced_aliases(raw["payload"]):
        raise Blocked("full review input assembly: downstream dependency payload must bind accepted evidence")
    payload = _resolve(raw["payload"], run_root=run_root, sources=sources)
    tool = _resolve(raw["tool"], run_root=run_root, sources=sources)
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS[kind]:
        raise Blocked("full review input assembly: dependency payload shape is not closed")
    if not isinstance(tool, dict) or set(tool) != _TOOL_KEYS[kind]:
        raise Blocked("full review input assembly: dependency tool shape is not closed")
    return {"schema": DEPENDENCY_SCHEMA, "run_id": plan["run_id"], "job_id": job,
            "source_generation": plan["source_generation"], "generated_at": plan["generated_at"],
            "payload": payload, "tool": tool}


def assemble(plan_path: Path, run_root: Path, output_root: Path, *, attempt_id: str,
             started_at: str, finished_at: str) -> dict[str, Any]:
    """Build and accept one immutable bundle of exact orchestration requests."""
    run_root, output_root, plan_path = Path(run_root), Path(output_root), Path(plan_path)
    if not run_root.is_absolute() or not run_root.is_dir() or run_root.is_symlink():
        raise Blocked("full review input assembly: run root must be an absolute real directory")
    try:
        plan_path.resolve(strict=True).relative_to(run_root.resolve(strict=True))
        output_root.resolve(strict=False).relative_to(run_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked("full review input assembly: plan and output must be run-owned") from exc
    if plan_path.is_symlink() or not plan_path.is_file() or output_root.is_symlink():
        raise Blocked("full review input assembly: plan or output path is unsafe")
    plan = read_json(plan_path)
    _closed(plan, _PLAN_KEYS, "plan")
    if plan["schema"] != PLAN_SCHEMA or not isinstance(plan["accepted_sources"], list) or not isinstance(plan["launches"], list):
        raise Blocked("full review input assembly: plan identity or collections are invalid")
    identifier(plan["run_id"])
    identifier(attempt_id)
    plan_errors = validate_document(plan, "full-review-input-plan.schema.json")
    if plan_errors:
        raise Blocked("full review input assembly: plan schema failed: " + plan_errors[0])
    manifest = _owned(run_root, "inputs/artifact-manifest.json", "artifact manifest", kind="file")
    generation = HASH + file_hash(manifest)
    if plan["source_generation"] != generation:
        raise Blocked("full review input assembly: plan source generation is stale")
    sources = _load_sources(plan, run_root)
    attempt = output_root / "attempts" / attempt_id
    fingerprint = HASH + digest({"plan": plan, "source_bindings": {key: row["binding"] for key, row in sources.items()}})
    if attempt.exists() or (output_root / "accepted.json").exists():
        raise Blocked("full review input assembly: immutable output already exists")
    (attempt / "requests").mkdir(parents=True)
    builders = {"bounded": _bounded, "vendor": _vendor, "dependency": _dependency}
    request_rows, paths, seen = [], [], set()
    for raw in plan["launches"]:
        if not isinstance(raw, dict) or raw.get("adapter") not in _LAUNCH_KEYS:
            raise Blocked("full review input assembly: launch adapter is invalid")
        adapter = raw["adapter"]
        _closed(raw, _LAUNCH_KEYS[adapter], "launch")
        job = raw["job_id"]
        if not isinstance(job, str) or job in seen:
            raise Blocked("full review input assembly: launch job identities must be unique")
        seen.add(job)
        request = builders[adapter](raw, plan, sources, run_root)
        relative = f"requests/{job}.json"
        atomic_json(attempt / relative, request)
        paths.append(relative)
        aliases = sorted(_referenced_aliases(raw) |
                         {value for value in raw.get("upstream", []) if isinstance(value, str)})
        request_rows.append({"job_id": job, "adapter": adapter, "path": relative,
                             "sha256": HASH + file_hash(attempt / relative), "accepted_source_aliases": aliases})
    if not request_rows:
        raise Blocked("full review input assembly: at least one launch request is required")
    accepted = [{"alias": alias, **row["binding"]} for alias, row in sorted(sources.items())]
    result = {"schema": RESULT_SCHEMA, "run_id": plan["run_id"], "job_id": JOB,
              "attempt_id": attempt_id, "source_generation": generation,
              "plan_sha256": HASH + file_hash(plan_path), "accepted_sources": accepted,
              "requests": sorted(request_rows, key=lambda row: row["job_id"])}
    errors = validate_document(result, "full-review-input-assembly.schema.json")
    if errors:
        raise Blocked("full review input assembly: result schema failed: " + errors[0])
    atomic_json(attempt / RESULT, result)
    atomic_json(attempt / "status.json", {"process": JOB, "status": "OK", "requests": len(request_rows),
                "accepted_sources": len(accepted), "qualification": "accepted_nominal_happy_path"})
    paths += [RESULT, "status.json"]
    envelope = terminal_envelope(run_id=plan["run_id"], job_id=JOB, attempt_id=attempt_id,
        worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
        input_fingerprint=fingerprint, output_contract=CONTRACT, started_at=started_at,
        finished_at=finished_at, summary="assembled exact accepted-source analysis launch requests",
        artifacts=artifact_records(attempt, paths))
    if validate_worker_result(envelope):
        raise Blocked("full review input assembly: common envelope is invalid")
    atomic_json(attempt / "result.json", envelope)
    atomic_json(output_root / "latest.json", {"attempt_id": attempt_id, "updated_at": finished_at})
    atomic_json(output_root / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK",
        "run_id": plan["run_id"], "job": JOB, "attempt_id": attempt_id, "fingerprint": fingerprint,
        "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json"),
        "hashes": tree_hashes(attempt), "accepted_at": finished_at})
    return result


def validate(output_root: Path) -> dict[str, Any]:
    """Revalidate the currently accepted immutable assembly attempt."""
    output_root = Path(output_root)
    accepted = read_json(output_root / "accepted.json")
    attempt_id = identifier(accepted.get("attempt_id", ""))
    attempt = output_root / "attempts" / attempt_id
    envelope = read_json(attempt / "result.json")
    errors = validate_worker_result(envelope)
    if errors:
        raise Blocked("full review input assembly: common envelope is invalid: " + errors[0])
    if accepted.get("envelope_sha256") != file_hash(attempt / "result.json"):
        raise Blocked("full review input assembly: accepted envelope hash is stale")
    result = read_json(attempt / RESULT)
    schema_errors = validate_document(result, "full-review-input-assembly.schema.json")
    if schema_errors:
        raise Blocked("full review input assembly: result schema failed: " + schema_errors[0])
    for request in result.get("requests", []):
        path = attempt / request["path"]
        if not path.is_file() or request["sha256"] != HASH + file_hash(path):
            raise Blocked("full review input assembly: request artifact is missing or changed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    args = parser.parse_args()
    assemble(args.plan, args.run_root, args.output_root, attempt_id=args.attempt_id,
             started_at=args.started_at, finished_at=args.finished_at)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
