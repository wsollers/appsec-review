"""Bounded static-only intelligence ingestion for D05--D08.

Target content is untrusted evidence.  This module never imports, evaluates, or executes it and
never emits runtime observations.  Results are deterministic, redacted, and bound to the accepted
intake source inventory.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

import evidence_redaction as redaction
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json
import phase1
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

SPECS = {
    "02-doc-intelligence-ingest": ("doc-intelligence", "doc-intelligence.json", "doc-intelligence.schema.json"),
    "02-api-collection-intelligence-ingest": ("api-collection-intelligence", "api-collection-intelligence.json", "api-collection-intelligence.schema.json"),
    "02-test-intelligence-ingest": ("test-intelligence", "test-intelligence.json", "test-intelligence.schema.json"),
    "02-operations-doc-ingest": ("operations-doc-intelligence", "operations-doc-intelligence.json", "operations-doc-intelligence.schema.json"),
}
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 200
MAX_RECORDS = 1000
TEXT_SUFFIXES = {".md", ".markdown", ".rst", ".txt", ".adoc"}
TEST_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".py", ".js", ".ts", ".java", ".go", ".rs", ".cs", ".sh"}


def root(run_id: str, job: str) -> Path:
    return data_path(run_id, "jobs", job)


def _hash(value: Any) -> str:
    return "sha256:" + digest(value)


def _permissions(job: str) -> list[str]:
    value = read_json(ROOT / "registry/job-templates" / f"{job}.json").get("permissions")
    if not isinstance(value, list) or not value or len(value) != len(set(value)):
        raise Blocked(f"{job}: canonical template permissions are absent or invalid")
    return value


def _code_hashes(job: str) -> dict[str, str]:
    contract, _result, schema = SPECS[job]
    wrapper = job[3:].replace("-", "_") + ".py"
    names = ["static_intelligence_core.py", wrapper, "evidence_redaction.py",
             f"registry/job-templates/{job}.json", f"registry/output-contracts/{contract}.json"]
    values = {name: file_hash(ROOT / name) for name in names}
    values["schemas/" + schema] = file_hash(ROOT.parent / "schemas" / schema)
    values["schemas/static-intelligence-record.schema.json"] = file_hash(
        ROOT.parent / "schemas/static-intelligence-record.schema.json")
    return values


def _intake(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    pointer = phase1.accepted(run_id, phase1.JOB, fresh=True)
    if pointer is None or pointer.get("status") != "OK":
        raise Blocked("static intelligence: exact accepted intake is required")
    base = phase1.job_root(run_id, phase1.JOB, "whole")
    attempt = base / "attempts" / pointer["attempt_id"]
    source = read_json(attempt / "evidence/source.json")
    if source.get("fingerprint") != read_json(attempt / "outputs/intake.json").get("source_fingerprint"):
        raise Blocked("static intelligence: intake source identity mismatch")
    binding = {"job_id": phase1.JOB, "attempt_id": pointer["attempt_id"],
        "fingerprint": pointer["fingerprint"], "source_fingerprint": source["fingerprint"],
        "source_revision": source["revision"], "pointer_sha256": "sha256:" + file_hash(base / "accepted.json")}
    return attempt, source, binding


def current_inputs(run_id: str, job: str) -> dict[str, Any]:
    _attempt, source, binding = _intake(run_id)
    target = Path(source["target"])
    if not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise Blocked(f"{job}: intake target is not a real absolute directory")
    return {"run_id": run_id, "job_id": job, "target_path": str(target.resolve()),
            "source": binding, "source_files": source["files"], "code": _code_hashes(job)}


def _candidate(job: str, path: str) -> bool:
    p = PurePosixPath(path); low = path.lower(); name = p.name.lower(); suffix = p.suffix.lower()
    if job == "02-doc-intelligence-ingest":
        return suffix in TEXT_SUFFIXES and name not in {"readme", "readme.md", "readme.txt", "readme.rst"} and any(
            token in low for token in ("doc", "design", "architecture", "adr", "spec", "requirement", "product", "feature"))
    if job == "02-api-collection-intelligence-ingest":
        return suffix in {".json", ".yaml", ".yml", ".bru"} and any(
            token in low for token in ("openapi", "swagger", "postman", "insomnia", "bruno", ".bru"))
    if job == "02-test-intelligence-ingest":
        return suffix in TEST_SUFFIXES and (any(part in {"test", "tests", "spec", "specs"} for part in p.parts[:-1])
            or name.startswith(("test_", "spec_")) or ".test." in name or ".spec." in name)
    return suffix in TEXT_SUFFIXES and any(token in low for token in
        ("runbook", "operations", "operational", "incident", "support", "deploy", "oncall", "playbook"))


def _redacted(path: str, data: bytes) -> tuple[str | None, str, int]:
    outcome = redaction._process(data, path, redaction.DEFAULT_LIMITS)
    if outcome.disposition == "withheld" or outcome.data is None:
        return None, outcome.reason or "withheld", 0
    return outcome.data.decode("utf-8", errors="replace"), outcome.disposition, sum(outcome.counts.values())


def _summaries(job: str, path: str, text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    if job in {"02-doc-intelligence-ingest", "02-operations-doc-ingest"}:
        for number, line in enumerate(text.splitlines(), 1):
            value = line.strip().lstrip("#").strip()
            if value and (line.lstrip().startswith("#") or any(word in value.lower() for word in
                    ("must", "should", "actor", "service", "incident", "deploy", "data", "auth"))):
                records.append({"kind": "document-statement", "locator": f"line:{number}", "text": value[:500]})
    elif job == "02-test-intelligence-ingest":
        patterns = (r"\bdef\s+(test_[A-Za-z0-9_]+)", r"\b(?:TEST|TEST_F)\s*\(\s*([^,)]+)\s*,\s*([^,)]+)",
                    r"\b(?:it|test|describe)\s*\(\s*['\"]([^'\"]+)")
        for number, line in enumerate(text.splitlines(), 1):
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    records.append({"kind": "documented-test", "locator": f"line:{number}",
                                    "text": "/".join(part.strip() for part in match.groups() if part)[:500]})
    else:
        try:
            value = json.loads(text)
        except (ValueError, RecursionError):
            return []
        if isinstance(value, dict) and isinstance(value.get("paths"), dict):
            for route, methods in value["paths"].items():
                if not isinstance(methods, dict): continue
                for method in methods:
                    if method.lower() in {"get", "put", "post", "delete", "patch", "head", "options", "trace"}:
                        records.append({"kind": "api-endpoint", "locator": f"paths:{route}:{method.lower()}",
                                        "text": f"{method.upper()} {route}"})
        elif isinstance(value, dict):
            def walk(items: Any):
                if isinstance(items, list):
                    for item in items: walk(item)
                elif isinstance(items, dict):
                    request = items.get("request")
                    if isinstance(request, dict):
                        method = str(request.get("method", "UNKNOWN")).upper()
                        url = request.get("url")
                        rendered = url.get("raw") if isinstance(url, dict) else url
                        if isinstance(rendered, str):
                            records.append({"kind": "api-endpoint", "locator": "collection-request",
                                            "text": f"{method} {rendered}"[:500]})
                    walk(items.get("item", []))
            walk(value.get("item", []))
    return records


def extract(job: str, *, run_id: str, attempt_id: str, target: Path,
            source: dict[str, Any], source_files: dict[str, Any]) -> dict[str, Any]:
    candidates = [path for path, meta in source_files.items() if meta.get("kind") == "file" and _candidate(job, path)]
    readmes = [path for path in source_files if PurePosixPath(path).name.lower().startswith("readme")]
    gaps: list[str] = []
    if len(candidates) > MAX_FILES:
        raise Blocked(f"{job}: applicable input count exceeds bounded limit {MAX_FILES}")
    sources, records, identities = [], [], set()
    for relative in sorted(candidates):
        meta = source_files[relative]
        path = target.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file() or path.is_symlink() or file_hash(path) != meta["sha256"]:
            raise Blocked(f"{job}: accepted source changed: {relative}")
        if path.stat().st_size > MAX_FILE_BYTES:
            sources.append({"path": relative, "sha256": "sha256:" + meta["sha256"], "status": "OVERSIZED", "redactions": 0})
            gaps.append(f"oversized-input:{relative}"); continue
        text, disposition, count = _redacted(relative, path.read_bytes())
        sources.append({"path": relative, "sha256": "sha256:" + meta["sha256"],
                        "status": disposition.upper(), "redactions": count})
        if text is None:
            gaps.append(f"withheld-input:{relative}:{disposition}"); continue
        extracted = _summaries(job, relative, text)
        if job == "02-api-collection-intelligence-ingest" and not extracted:
            gaps.append(f"malformed-or-empty-api-collection:{relative}")
        for item in extracted:
            identity = (relative, item["kind"], item["locator"], item["text"])
            if identity in identities:
                gaps.append(f"duplicate-record:{relative}:{item['locator']}"); continue
            identities.add(identity)
            record_id = "intel_" + digest(identity)[:16]
            records.append({"record_id": record_id, "kind": item["kind"], "path": relative,
                "source_sha256": "sha256:" + meta["sha256"], "locator": item["locator"],
                "summary": item["text"], "semantics": "DOCUMENTED_STATIC_INTENT"})
            if len(records) > MAX_RECORDS:
                raise Blocked(f"{job}: extracted record count exceeds bounded limit {MAX_RECORDS}")
    records.sort(key=lambda x: (x["path"], x["locator"], x["record_id"]))
    sources.sort(key=lambda x: x["path"])
    if not candidates:
        gaps.append("readme-only-no-specialized-inputs" if readmes else "no-applicable-inputs")
    elif not records:
        gaps.append("zero-indexable-records")
    contract, _name, _schema = SPECS[job]
    return {"schema": f"appsec-review/{contract}/1", "run_id": run_id, "job_id": job,
        "attempt_id": attempt_id, "status": "OK_WITH_GAPS" if gaps else "OK",
        "source": source, "sources": sources, "records": records,
        "coverage_gaps": sorted(set(gaps)), "static_only": True}


def _validate_attempt(run_id: str, job: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes(job):
        raise Blocked(f"{job}: immutable inputs or implementation changed")
    _unused, live_source, binding = _intake(run_id)
    if binding != inputs["source"] or live_source["files"] != inputs["source_files"]:
        raise Blocked(f"{job}: accepted source generation changed")
    contract, result_name, schema = SPECS[job]
    expected = extract(job, run_id=run_id, attempt_id=attempt.name, target=Path(inputs["target_path"]),
                       source=inputs["source"], source_files=inputs["source_files"])
    found = read_json(attempt / result_name)
    if found != expected or validate_document(found, schema):
        raise Blocked(f"{job}: normalized static intelligence changed or fails schema")
    permission = {"schema": PERMISSION_SCHEMA, "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": "sha256:" + inputs["source"]["source_fingerprint"],
        "permissions": _permissions(job)}
    lineage = {"schema": LINEAGE_SCHEMA, "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": "sha256:" + inputs["source"]["source_fingerprint"],
        "build_lineage_sha256": None}
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{job}: F02 receipt changed")


def run(run_id: str, dagster_id: str, job: str, force: bool = False) -> dict[str, Any]:
    contract, result_name, _schema = SPECS[job]; base = root(run_id, job)
    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]
        result = extract(job, run_id=run_id, attempt_id=allocation["attempt_id"],
            target=Path(inputs["target_path"]), source=inputs["source"], source_files=inputs["source_files"])
        atomic_json(attempt / result_name, result)
        source_hash = "sha256:" + inputs["source"]["source_fingerprint"]
        atomic_json(attempt / "permission.json", {"schema": PERMISSION_SCHEMA, "run_id": run_id,
            "job_id": job, "source_snapshot_sha256": source_hash, "permissions": _permissions(job)})
        atomic_json(attempt / "lineage.json", {"schema": LINEAGE_SCHEMA, "run_id": run_id,
            "job_id": job, "source_snapshot_sha256": source_hash, "build_lineage_sha256": None})
        status = {"process": job, "status": result["status"], "run_id": run_id,
            "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
            "sources": len(result["sources"]), "records": len(result["records"]),
            "static_only": True, "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job,
            dagster_run_id=dagster_id, worker_kind="deterministic", output_contract=contract,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=result["status"], summary=f"Published {len(result['records'])} redacted static intelligence record(s).",
            status_record=status, artifact_paths=[result_name, "status.json", "permission.json", "lineage.json"],
            gaps=result["coverage_gaps"] or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, job, path, inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
        worker_kind="deterministic", output_contract=contract,
        resume_command=f"python -B appsec-review-process/{job[3:].replace('-', '_')}.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id, job), fingerprint_inputs=lambda value: _hash(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(job)}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, job, attempt, inputs),
        blocked_summary=f"{job} source validation blocked.", failed_summary=f"{job} did not publish.")


def validate(run_id: str, job: str, pointer=None) -> Path:
    inputs = current_inputs(run_id, job); base = root(run_id, job)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, _hash(inputs), expected_run_id=run_id, expected_job_id=job)
    _validate_attempt(run_id, job, attempt, inputs)
    return attempt
