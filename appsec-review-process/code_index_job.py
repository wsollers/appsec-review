"""Accepted ``02-code-index`` producer (brief U0.2, ADR-0032): the structural code index as a job.

A deterministic Python job, not an extension of ``02-evidence-index``: that index is built on the
source branch before any native or CPG work and is consumed by every lookup, so binding it to the
CPG would re-run it (and invalidate its consumers) whenever the CPG changes, and hold the source
index back until Joern finishes. This job waits for the accepted ``02-code-property-graph``,
``02-treesitter-ast`` (or its language-absent skip) and ``02-binary-triage`` (or its native skips),
binds each by accepted pointer, envelope and attempt-tree hashes (``dep_reachability_lifecycle``'s
rule), and publishes ``code-index.sqlite`` (``code_index.build``) plus ``code-index.json`` with the
database's sha256, its logical ``content_sha256``, the source bindings, the capabilities the
query tools are granted from, counts and gaps. Validation rebuilds the database from the bound
inputs and compares every row.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any

import code_index
import dep_reachability_lifecycle as bindings
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path, tree_hashes
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import registry_paths
from schema_validate import validate_document
import treesitter_ast_job

JOB = "02-code-index"
CONTRACT = "code-index"
RESULT = code_index.RESULT
SQLITE = code_index.SQLITE
SUMMARY = "code-index-summary.md"
SCHEMA_FILE = "code-index.schema.json"
TRIAGE_JOB = "02-binary-triage"
CONSUMER = "02-evidence-assembly"


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code() -> dict[str, str]:
    paths = ("code_index_job.py", "code_index.py", "reachability.py", "entry_exports.py", "lsp_driver.py",
             "treesitter_ast_job.py", registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT))
    values = {name: file_hash(ROOT / name) for name in paths}
    values["schemas/" + SCHEMA_FILE] = file_hash(ROOT.parent / "schemas" / SCHEMA_FILE)
    return values


def _source(run_id: str) -> str:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked(f"{JOB}: staged artifact manifest is required")
    return "sha256:" + file_hash(manifest)


def _optional(run_id: str, job: str, result: str, source: str) -> tuple[dict[str, Any] | None, list[str]]:
    pointer = data_path(run_id, "jobs", job) / "accepted.json"
    try:
        if pointer.is_file() and not pointer.is_symlink() and read_json(pointer).get("status") == "SKIPPED":
            return None, [f"source-skipped:{job}"]
    except (OSError, ValueError):
        pass
    binding, gap = bindings._accepted(run_id, job, result, source)
    if binding is None:
        return None, [gap]
    attempt = data_path(run_id, "jobs", job, "attempts", binding["attempt_id"])
    status = read_json(attempt / result).get("status")
    if status == "SKIPPED":
        return None, [f"source-skipped:{job}"]
    return binding, []


def _triage(run_id: str) -> tuple[dict[str, Any] | None, list[str]]:
    """The accepted binary triage attempt (pointer, envelope and tree verified) and the receipt that
    hashes every per-binary summary (``entry_exports.triage_binding``); its manifest carries no
    source generation, so the native-build lineage it was produced from is what binds it."""
    import entry_exports
    base = data_path(run_id, "jobs", TRIAGE_JOB)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None, [f"source-absent:{TRIAGE_JOB}"]
    try:
        pointer = read_json(pointer_path)
        attempt = base / "attempts" / str(pointer.get("attempt_id"))
        if (pointer.get("run_id") != run_id or pointer.get("job") != TRIAGE_JOB or attempt.is_symlink() or
                not attempt.is_dir() or tree_hashes(attempt) != pointer.get("hashes") or
                file_hash(attempt / pointer.get("envelope_path", "result.json")) != pointer.get("envelope_sha256")):
            return None, [f"source-not-current:{TRIAGE_JOB}"]
    except (OSError, ValueError, TypeError):
        return None, [f"source-not-current:{TRIAGE_JOB}"]
    if pointer.get("status") == "SKIPPED":
        return None, [f"source-skipped:{TRIAGE_JOB}"]
    if pointer.get("status") not in ("OK", "OK_WITH_GAPS"):
        return None, [f"source-not-current:{TRIAGE_JOB}"]
    return {"attempt_id": pointer["attempt_id"], "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
            **entry_exports.triage_binding(attempt)}, []


def current_inputs(run_id: str) -> dict[str, Any]:
    source = _source(run_id)
    cpg, cpg_gaps = bindings._cpg(run_id, source)
    if cpg is None:
        raise Blocked(f"{JOB}: no accepted code property graph for this source generation ({', '.join(cpg_gaps)})")
    treesitter, ts_gaps = _optional(run_id, treesitter_ast_job.JOB, treesitter_ast_job.RESULT, source)
    triage, triage_gaps = _triage(run_id)
    return {"run_id": run_id, "job": JOB, "source_snapshot_sha256": source, "cpg": cpg, "treesitter": treesitter,
            "binary_triage": triage, "input_gaps": sorted(cpg_gaps + ts_gaps + triage_gaps), "code": _code()}


def _derive(run_id: str, inputs: dict[str, Any], database: Path) -> dict[str, Any]:
    """Build the database from the bound inputs; returns the summary without file hashes."""
    cpg_attempt = data_path(run_id, "jobs", bindings.CPG_JOB, "attempts", inputs["cpg"]["attempt_id"])
    cpg_summary = read_json(cpg_attempt / bindings.CPG_RESULT)
    if "sha256:" + file_hash(cpg_attempt / bindings.CPG_RESULT) != inputs["cpg"]["result_sha256"]:
        raise Blocked(f"{JOB}: accepted CPG summary changed after binding")
    records = cpg_attempt / cpg_summary["records_file"]["path"]
    document = None
    if inputs["treesitter"] is not None:
        ts_attempt = data_path(run_id, "jobs", treesitter_ast_job.JOB, "attempts", inputs["treesitter"]["attempt_id"])
        if "sha256:" + file_hash(ts_attempt / treesitter_ast_job.RESULT) != inputs["treesitter"]["result_sha256"]:
            raise Blocked(f"{JOB}: accepted tree-sitter summary changed after binding")
        document = treesitter_ast_job.load_document(ts_attempt)
    tables, export_gaps = None, []
    if inputs["binary_triage"] is not None:
        import entry_exports
        attempt = data_path(run_id, "jobs", TRIAGE_JOB, "attempts", inputs["binary_triage"]["attempt_id"])
        if entry_exports.triage_binding(attempt).get("receipt_sha256") != inputs["binary_triage"].get("receipt_sha256"):
            raise Blocked(f"{JOB}: binary triage receipt changed after binding")
        tables, export_gaps = entry_exports.tables_from_triage(attempt)
    sources = {"cpg": {"job": bindings.CPG_JOB, **inputs["cpg"]},
               "treesitter": ({"job": treesitter_ast_job.JOB, **inputs["treesitter"]} if inputs["treesitter"] else None),
               "binary_triage": ({"job": TRIAGE_JOB, **inputs["binary_triage"]} if inputs["binary_triage"] else None)}
    summary = code_index.build(database, records=records, cpg_summary=cpg_summary, sources=sources,
                               treesitter=document, export_tables=tables, export_gaps=export_gaps,
                               source_gaps=inputs["input_gaps"])
    return {**summary, "run_id": run_id, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "status": "OK_WITH_GAPS" if summary["gaps"] else "OK"}


def _sha(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    template = read_json(registry_paths.template(JOB))
    common = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return ({"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": template["permissions"]},
            {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
             "build_lineage_sha256": "sha256:" + digest(inputs)})


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{JOB}: result fails schema validation")
    database = attempt / SQLITE
    if database.is_symlink() or not database.is_file() or _sha(database) != result["sqlite"]["sha256"]:
        raise Blocked(f"{JOB}: published database does not match its recorded sha256")
    scratch = Path(tempfile.mkdtemp(prefix="code-index-validate-"))
    try:
        rebuilt = _derive(run_id, inputs, scratch / SQLITE)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if {key: value for key, value in result.items() if key != "sqlite"} != rebuilt:
        raise Blocked(f"{JOB}: code index no longer matches its hash-bound inputs")
    connection = code_index.open_readonly(database)
    try:
        if code_index.content_sha256(connection) != result["content_sha256"]:
            raise Blocked(f"{JOB}: published database rows differ from its content_sha256")
    finally:
        connection.close()
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: canonical producer receipts changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        if inputs["code"] != _code():
            raise Blocked(f"{JOB}: implementation changed before execution")
        started = time.monotonic()
        summary = _derive(run_id, inputs, attempt / SQLITE)
        database = attempt / SQLITE
        result = {**summary, "sqlite": {"path": SQLITE, "sha256": _sha(database), "bytes": database.stat().st_size}}
        atomic_json(attempt / RESULT, result)
        seconds = round(time.monotonic() - started, 3)
        counts = result["counts"]
        (attempt / SUMMARY).write_text(
            "# Code index\n\n"
            f"- Methods {counts['methods']}, calls {counts['calls']}, types {counts['types']}, "
            f"tree-sitter functions {counts['ts_functions']}, exports {counts['exports']}.\n"
            f"- Database {result['sqlite']['bytes']} bytes, built in {seconds}s.\n"
            f"- Capabilities: {', '.join(k for k, v in sorted(result['capabilities'].items()) if v)}.\n"
            f"- Gaps: {len(result['gaps'])}.\n- Rows are locators; read the source before citing.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "methods": counts["methods"], "calls": counts["calls"],
                  "database_bytes": result["sqlite"]["bytes"], "build_seconds": seconds, "network": "none",
                  "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Code index: {counts['methods']} methods, {counts['calls']} calls.", status_record=status,
            artifact_paths=[RESULT, SQLITE, SUMMARY, "status.json", "permission.json", "lineage.json"],
            gaps=result["gaps"], consumer_job_id=CONSUMER,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/code_index_job.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        consumer_job_id=CONSUMER,
        blocked_summary="Code index preflight did not complete.",
        failed_summary="Code index did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs), expected_run_id=run_id,
                                    expected_job_id=JOB, consumer_job_id=CONSUMER)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument("run_id"); parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true"); args = parser.parse_args()
    print(run(args.run_id, args.dagster_id, args.force))
