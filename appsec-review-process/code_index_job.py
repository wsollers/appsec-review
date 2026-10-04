"""Accepted ``02-code-index`` producer (brief U0.2, ADR-0032): the structural code index as a job.

A deterministic Python job, not an extension of ``02-evidence-index``: that index is built on the
source branch before any native or CPG work and is consumed by every lookup, so binding it to the
CPG would re-run it (and invalidate its consumers) whenever the CPG changes, and hold the source
index back until Joern finishes. This job waits for the accepted ``02-code-property-graph``,
``02-treesitter-ast`` (or its language-absent skip), and optionally ``02-binary-triage``, ``02-ir-facts`` and
``02-debug-symbol-index`` (a skip of the last two binds nothing and is no gap: there is nothing native to
index). The CPG and the AST are source-only, so a native build that did not publish removes only the
native tables: without an accepted, current binary triage the export tables stay empty, ``exports`` is
false and a gap names the producer and its state (absent, skipped, not published, stale), never "no
exports". Each source is bound by accepted pointer, envelope and attempt-tree hashes
(``dep_reachability_lifecycle``'s rule), and publishes ``code-index.sqlite`` (``code_index.build``) plus ``code-index.json`` with the
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
from publish_job_output import NONCURRENT_SCHEMA, coordinate_worker_lifecycle, record_terminal_current, validate_published
import registry_paths
from schema_validate import validate_document
import treesitter_ast_job

JOB = "02-code-index"
CONTRACT = "code-index"
RESULT = code_index.RESULT
SQLITE = code_index.SQLITE
SUMMARY = "code-index-summary.md"
SCHEMA_FILE = "code-index.schema.json"
TRIAGE_JOB, TRIAGE_RESULT = "02-binary-triage", "binary-triage-manifest.json"
NATIVE_JOB = "02-native-build"
IR_JOB, IR_RESULT = "02-ir-facts", "ir-facts.json"
DEBUG_JOB, DEBUG_RESULT = "02-debug-symbol-index", "debug-symbol-index.json"
CONSUMER = "02-evidence-assembly"


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code() -> dict[str, str]:
    paths = ("code_index_job.py", "code_index.py", "reachability.py", "entry_exports.py", "lsp_driver.py",
             "treesitter_ast_job.py", "binary_evidence_core.py", registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT))
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


def _published(run_id: str, job: str) -> tuple[dict[str, Any] | None, Path | None, list[str]]:
    """The accepted attempt of a job whose manifest carries no source generation (pointer, envelope
    and tree verified; the native-build lineage it was produced from is what binds it): the
    attempt-binding head, the attempt, and gaps. A SKIPPED publication returns no attempt."""
    base = data_path(run_id, "jobs", job)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None, None, [f"source-absent:{job}"]
    try:
        pointer = read_json(pointer_path)
        if pointer.get("schema") == NONCURRENT_SCHEMA:   # its newest attempt failed: no older success is used
            return None, None, [f"source-not-published:{job}:{pointer.get('status') or 'UNKNOWN'}"]
        attempt = base / "attempts" / str(pointer.get("attempt_id"))
        if (pointer.get("run_id") != run_id or pointer.get("job") != job or attempt.is_symlink() or
                not attempt.is_dir() or tree_hashes(attempt) != pointer.get("hashes") or
                file_hash(attempt / pointer.get("envelope_path", "result.json")) != pointer.get("envelope_sha256")):
            return None, None, [f"source-not-current:{job}"]
    except (OSError, ValueError, TypeError):
        return None, None, [f"source-not-current:{job}"]
    if pointer.get("status") == "SKIPPED":
        return None, None, [f"source-skipped:{job}"]
    if pointer.get("status") not in ("OK", "OK_WITH_GAPS"):
        return None, None, [f"source-not-current:{job}"]
    return {"attempt_id": pointer["attempt_id"], "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path)}, attempt, []


def _native_current(run_id: str, job: str, attempt: Path, result: str) -> list[str]:
    """A native-evidence attempt binds the native build it came from (``native_build.pointer_sha256``,
    binary_evidence_core's rule). Its producer is now optional, so a later native build that did not
    publish, or replaced it, must not leave the older attempt bound: that is a gap, never its rows."""
    pointer = data_path(run_id, "jobs", NATIVE_JOB) / "accepted.json"
    try:
        bound = (read_json(attempt / result).get("native_build") or {}).get("pointer_sha256")
        current = read_json(pointer) if pointer.is_file() and not pointer.is_symlink() else None
    except (OSError, ValueError, AttributeError):
        return [f"source-not-current:{job}"]
    if current is None or current.get("schema") == NONCURRENT_SCHEMA:
        state = "absent" if current is None else current.get("status") or "UNKNOWN"
        return [f"source-not-current:{job}:{NATIVE_JOB}-{state}"]
    return [] if bound == "sha256:" + file_hash(pointer) else [f"source-not-current:{job}:{NATIVE_JOB}-replaced"]


def _triage(run_id: str) -> tuple[dict[str, Any] | None, list[str]]:
    """The accepted binary triage attempt and the receipt that hashes every per-binary summary
    (``entry_exports.triage_binding``), or None and the gap naming its state."""
    import entry_exports
    head, attempt, gaps = _published(run_id, TRIAGE_JOB)
    if attempt is None:
        return None, gaps
    stale = _native_current(run_id, TRIAGE_JOB, attempt, TRIAGE_RESULT)
    return (None, stale) if stale else ({**head, **entry_exports.triage_binding(attempt)}, [])


def _native_only(gaps: list[str]) -> list[str]:
    """A skipped native-evidence source (no native units, no debug symbols) has nothing to index: no gap."""
    return [gap for gap in gaps if not gap.startswith("source-skipped:")]


def _ir_facts(run_id: str, source: str) -> tuple[dict[str, Any] | None, list[str]]:
    binding, gaps = _optional(run_id, IR_JOB, IR_RESULT, source)
    return binding, _native_only(gaps)


def _debug_symbols(run_id: str) -> tuple[dict[str, Any] | None, list[str]]:
    head, attempt, gaps = _published(run_id, DEBUG_JOB)
    if attempt is None:
        return None, _native_only(gaps)
    try:
        result = read_json(attempt / DEBUG_RESULT)
    except (OSError, ValueError):
        return None, [f"source-not-current:{DEBUG_JOB}"]
    if result.get("status") == "SKIPPED":
        return None, []
    stale = _native_current(run_id, DEBUG_JOB, attempt, DEBUG_RESULT)
    if stale:
        return None, stale
    return {**head, "result_sha256": "sha256:" + file_hash(attempt / DEBUG_RESULT)}, []


def current_inputs(run_id: str) -> dict[str, Any]:
    source = _source(run_id)
    cpg, cpg_gaps = bindings._cpg(run_id, source)
    if cpg is None:
        raise Blocked(f"{JOB}: no accepted code property graph for this source generation ({', '.join(cpg_gaps)})")
    treesitter, ts_gaps = _optional(run_id, treesitter_ast_job.JOB, treesitter_ast_job.RESULT, source)
    triage, triage_gaps = _triage(run_id)
    ir, ir_gaps = _ir_facts(run_id, source)
    debug, debug_gaps = _debug_symbols(run_id)
    return {"run_id": run_id, "job": JOB, "source_snapshot_sha256": source, "cpg": cpg, "treesitter": treesitter,
            "binary_triage": triage, "ir_facts": ir, "debug_symbols": debug,
            "input_gaps": sorted(cpg_gaps + ts_gaps + triage_gaps + ir_gaps + debug_gaps), "code": _code()}


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
    ir_facts = debug_symbols = None
    if inputs["ir_facts"] is not None:
        path = data_path(run_id, "jobs", IR_JOB, "attempts", inputs["ir_facts"]["attempt_id"], IR_RESULT)
        if "sha256:" + file_hash(path) != inputs["ir_facts"]["result_sha256"]:
            raise Blocked(f"{JOB}: accepted IR facts changed after binding")
        ir_facts = read_json(path)
    if inputs["debug_symbols"] is not None:
        import binary_evidence_core
        attempt = data_path(run_id, "jobs", DEBUG_JOB, "attempts", inputs["debug_symbols"]["attempt_id"])
        if "sha256:" + file_hash(attempt / DEBUG_RESULT) != inputs["debug_symbols"]["result_sha256"]:
            raise Blocked(f"{JOB}: accepted debug-symbol index changed after binding")
        debug_symbols = binary_evidence_core.load_records(DEBUG_JOB, attempt, read_json(attempt / DEBUG_RESULT))
    sources = {"cpg": {"job": bindings.CPG_JOB, **inputs["cpg"]},
               "treesitter": ({"job": treesitter_ast_job.JOB, **inputs["treesitter"]} if inputs["treesitter"] else None),
               "binary_triage": ({"job": TRIAGE_JOB, **inputs["binary_triage"]} if inputs["binary_triage"] else None),
               "ir_facts": ({"job": IR_JOB, **inputs["ir_facts"]} if inputs["ir_facts"] else None),
               "debug_symbols": ({"job": DEBUG_JOB, **inputs["debug_symbols"]} if inputs["debug_symbols"] else None)}
    summary = code_index.build(database, records=records, cpg_summary=cpg_summary, sources=sources,
                               treesitter=document, export_tables=tables, export_gaps=export_gaps,
                               source_gaps=inputs["input_gaps"], ir_facts=ir_facts, debug_symbols=debug_symbols)
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
            f"tree-sitter functions {counts['ts_functions']}, exports {counts['exports']}, "
            f"inheritance edges {counts['type_edges']}, IR functions {counts['ir_functions']}, "
            f"debug symbols {counts['debug_symbols']}.\n"
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
