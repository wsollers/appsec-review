"""Accepted ``02-treesitter-ast`` producer (brief U0.1): the tree-sitter AST summary as a graph job.

``treesitter_ast.py`` runs from the vendored ``/opt/treesitter`` venv inside a pinned compiler image
(``image_id`` tunable, default ``audit-buildenv-cpp``) in the B13 boundary: network none, the target
checkout mounted read-only at ``/workspace``, and a content-addressed copy of ``treesitter_ast.py``
staged under the run's ``data/tooling/`` and mounted at ``/inputs/treesitter`` (the image carries the
parser and grammars only; no repo script is copied into it). Nothing executes target code: the
script parses bytes.

Large outputs use the records-file pattern of ``02-code-property-graph``: the result
``treesitter-ast.json`` carries the generator, totals, gaps and the document's ``content_sha256``;
``treesitter-ast.records.jsonl`` holds one file record per line. ``load_document`` rebuilds the full
``appsec-review/treesitter-ast/1`` document and checks its ``content_sha256``. A checkout with no
file any grammar can parse publishes SKIPPED ``not-applicable-language-absent``. Oversized,
unreadable or symlinked files and grammar gaps are recorded by the script as gaps, never dropped.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import threading
from typing import Any

import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import intake
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import registry_paths
from schema_validate import validate_document
import treesitter_ast
import tunables

JOB = "02-treesitter-ast"
CONTRACT = "treesitter-ast"
RESULT = "treesitter-ast.json"
RECORDS = "treesitter-ast.records.jsonl"
RECEIPT = "b13-receipt.json"
SUMMARY = "treesitter-ast-summary.md"
SCHEMA = "appsec-review/treesitter-ast-job/1"
SCHEMA_FILE = "treesitter-ast-job.schema.json"
SCRIPT = ROOT / "treesitter_ast.py"
MOUNT = "/inputs/treesitter"
PERMISSIONS = ["read-source", "write-run-data"]
CONSUMER = "02-code-index"
SKIP_REASON = "not-applicable-language-absent"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def image_id() -> str:
    return tunables.value(JOB, "image_id")


def _limits() -> dict[str, int]:
    return {"max_file_bytes": tunables.value(JOB, "max_file_bytes"),
            "max_files": tunables.value(JOB, "max_files"),
            "max_rows_per_file": tunables.value(JOB, "max_rows_per_file")}


def _code() -> dict[str, str]:
    paths = ("treesitter_ast_job.py", "treesitter_ast.py", registry_paths.template_rel(JOB),
             registry_paths.contract_rel(CONTRACT))
    values = {name: file_hash(ROOT / name) for name in paths}
    for name in (SCHEMA_FILE, "treesitter-ast.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _target(run_id: str) -> tuple[Path, str, str]:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked(f"{JOB}: staged artifact manifest is required")
    value = read_json(manifest).get("target", {}).get("repo_path")
    target = Path(value) if isinstance(value, str) else Path()
    if not value or not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise Blocked(f"{JOB}: target must be an absolute real checkout")
    identity = intake.source_identity(str(target.resolve()))
    return target.resolve(), "sha256:" + file_hash(manifest), identity.get("revision") or "unversioned"


def applicable_languages(target: Path) -> list[str]:
    """Languages with a grammar that have at least one file in the checkout (suffix, else shebang; no parse)."""
    found = set()
    for relative, path, problem in treesitter_ast.iter_files(target):
        if problem is None and path is not None:
            language = treesitter_ast.language_for(path)
            if language:
                found.add(language)
    return sorted(found)


def current_inputs(run_id: str) -> dict[str, Any]:
    from code_graph_evidence import source_tree_sha256
    target, source, revision = _target(run_id)
    languages = applicable_languages(target)
    inputs = {"run_id": run_id, "job": JOB, "target_path": str(target), "source_snapshot_sha256": source,
              "source_revision": revision, "source_tree_sha256": source_tree_sha256(target),
              "languages": languages, "limits": _limits(), "script_sha256": "sha256:" + file_hash(SCRIPT),
              "code": _code()}
    if not languages:
        return {**inputs, "mode": "SKIPPED_NA", "image": None, "boundary_sha256": None}
    image = ce.load_image_registry(ce.IMAGES_DIR).get(image_id())
    if image is None:
        raise Blocked(f"{JOB}: {image_id()} has no current B16 record")
    return {**inputs, "mode": "RUN", "image": image, "boundary_sha256": ce.boundary_sha256(),
            "container_limits": tunables.container_limits(JOB)}


def _stage_script(run_id: str, script_sha: str) -> Path:
    """A content-addressed copy of treesitter_ast.py outside the attempt (a mount may not be inside it)."""
    folder = data_path(run_id, "tooling", "treesitter-ast", script_sha.split(":", 1)[1][:32])
    target = folder / "treesitter_ast.py"
    if not target.is_file() or "sha256:" + file_hash(target) != script_sha:
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SCRIPT, target)
    if "sha256:" + file_hash(target) != script_sha:
        raise Blocked(f"{JOB}: staged treesitter_ast.py does not match its pinned hash")
    return folder


def _permission(run_id: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": JOB, "capabilities": []}
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source, "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"], container_user=defaults["container_user"],
        source_snapshot_sha256=source, registry_ceiling=[], clock=_utc, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def argv(limits: dict[str, int]) -> list[str]:
    # -B, not PYTHONDONTWRITEBYTECODE: the B13 request schema allowlists environment names and that one is
    # not on it, so every request was rejected before Docker ran (appsec-multi-vuln, 2026-09-30).
    return ["/opt/treesitter/bin/python", "-B", f"{MOUNT}/treesitter_ast.py", "--root", "/workspace", "--label", "workspace",
            "--out", "/scratch/treesitter-ast.json", "--stats", "/scratch/treesitter-ast.stats.json",
            *[item for key, value in sorted(limits.items()) for item in ("--" + key.replace("_", "-"), str(value))]]


def _request(run_id: str, attempt_id: str, inputs: dict[str, Any], staged: Path) -> dict[str, Any]:
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
        "image": {"image_id": image_id(), "digest": inputs["image"]["digest"]}, "argv": argv(inputs["limits"]),
        "environment": [{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"}],
        "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"},
                          {"host_path": str(staged), "container_path": MOUNT}],
        "scratch_path": "scratch", "log_path": "logs/container", "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, inputs["source_snapshot_sha256"], _utc()),
        "limits": inputs["container_limits"]}


def split(document: dict[str, Any], destination: Path | None) -> tuple[dict[str, Any], str, int]:
    """(trailer without files, records sha256, count); writes the JSONL when ``destination`` is set."""
    value = hashlib.sha256()
    stream = destination.open("wb") if destination is not None else None
    try:
        for record in document["files"]:
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
            value.update(line)
            if stream is not None:
                stream.write(line)
    finally:
        if stream is not None:
            stream.close()
    trailer = {key: item for key, item in document.items() if key != "files"}
    return trailer, "sha256:" + value.hexdigest(), len(document["files"])


def result_document(run_id: str, inputs: dict[str, Any], document: dict[str, Any] | None) -> dict[str, Any]:
    base = {"schema": SCHEMA, "run_id": run_id, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "source_revision": inputs["source_revision"], "source_tree_sha256": inputs["source_tree_sha256"],
            "image_id": image_id() if inputs["mode"] == "RUN" else None,
            "image_digest": inputs["image"]["digest"] if inputs["image"] else None,
            "script_sha256": inputs["script_sha256"], "languages": inputs["languages"],
            "claim_boundary": "STRUCTURAL_RETRIEVAL_NOT_FINDING_OR_RUNTIME_PROOF"}
    if document is None:
        return {**base, "status": "SKIPPED", "skip_reason": SKIP_REASON, "records_file": None, "content_sha256": None,
                "totals": None, "generator": None, "gaps": [], "gap_count": 0}
    if validate_document(document, "treesitter-ast.schema.json") or not treesitter_ast.verify(document):
        raise Blocked(f"{JOB}: tree-sitter document fails its schema or content hash")
    trailer, records_sha, count = split(document, None)
    gaps = trailer["gaps"]
    return {**base, "status": "OK_WITH_GAPS" if gaps else "OK", "skip_reason": None,
            "records_file": {"path": RECORDS, "sha256": records_sha, "count": count},
            "content_sha256": document["content_sha256"], "totals": trailer["totals"],
            "generator": trailer["generator"], "gaps": gaps[:200], "gap_count": len(gaps),
            "source_manifest_sha256": trailer["source_manifest_sha256"]}


def load_document(attempt: Path) -> dict[str, Any]:
    """The full ``appsec-review/treesitter-ast/1`` document of an accepted attempt, hash-checked."""
    attempt = Path(attempt)
    result = read_json(attempt / RESULT)
    records_file = result.get("records_file") or {}
    path = attempt / str(records_file.get("path"))
    if path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != records_file.get("sha256"):
        raise ValueError("tree-sitter records file does not match its recorded hash")
    raw = read_json(attempt / "tool" / "scratch" / "treesitter-ast.json")
    with path.open(encoding="utf-8") as handle:
        files = [json.loads(line) for line in handle if line.strip()]
    document = {**{key: value for key, value in raw.items() if key != "files"}, "files": files}
    if not treesitter_ast.verify(document) or document.get("content_sha256") != result.get("content_sha256"):
        raise ValueError("tree-sitter document does not match its content_sha256")
    return document


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": run_id, "job_id": JOB,
                  "source_snapshot_sha256": inputs["source_snapshot_sha256"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": run_id, "job_id": JOB,
               "source_snapshot_sha256": inputs["source_snapshot_sha256"],
               "build_lineage_sha256": "sha256:" + digest(inputs)}
    return permission, lineage


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or current_inputs(run_id) != inputs:
        raise Blocked(f"{JOB}: inputs or source generation changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{JOB}: result fails schema validation")
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: producer permission or lineage receipt changed")
    if inputs["mode"] == "SKIPPED_NA":
        if result != result_document(run_id, inputs, None):
            raise Blocked(f"{JOB}: skip record differs from its inputs")
        return
    receipt = read_json(attempt / RECEIPT)
    trial = attempt / receipt.get("trial_path", "")
    request = read_json(trial / "logs" / "container" / ce.REQUEST_FILE)
    runtime = _runtime(inputs["source_snapshot_sha256"])
    ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=receipt.get("adapter_attempt_id", ""),
        request=request, images_dir=runtime.images_dir, expected_result_sha256=receipt.get("expected_result_sha256", ""),
        **_host(runtime))
    raw = trial / "scratch" / "treesitter-ast.json"
    if not raw.is_file() or raw.is_symlink() or "sha256:" + file_hash(raw) != receipt.get("raw_sha256"):
        raise Blocked(f"{JOB}: raw tree-sitter output changed")
    if result != result_document(run_id, inputs, read_json(raw)):
        raise Blocked(f"{JOB}: published summary differs from its immutable tool output")
    if "sha256:" + file_hash(attempt / RECORDS) != result["records_file"]["sha256"]:
        raise Blocked(f"{JOB}: published records file changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if current_inputs(run_id) != inputs:
            raise Blocked(f"{JOB}: source or implementation changed before execution")
        attempt = allocation["attempt"]
        artifacts = [RESULT, SUMMARY, "status.json", "permission.json", "lineage.json"]
        if inputs["mode"] == "SKIPPED_NA":
            result = result_document(run_id, inputs, None)
        else:
            trial = attempt / "tool"; trial.mkdir(parents=True)
            adapter_id = "tsast-" + allocation["attempt_id"][:12]
            runtime = _runtime(inputs["source_snapshot_sha256"])
            request = _request(run_id, adapter_id, inputs, _stage_script(run_id, inputs["script_sha256"]))
            terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                        attempt_root=trial, request=request)
            ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id, request=request,
                images_dir=runtime.images_dir, expected_result_sha256=terminal["result_sha256"], **_host(runtime))
            if terminal["execution_status"] != "OK":
                raise RuntimeError(f"{JOB}: treesitter_ast.py ended {terminal['execution_status']}")
            raw = trial / "scratch" / "treesitter-ast.json"
            document = read_json(raw)
            result = result_document(run_id, inputs, document)
            split(document, attempt / RECORDS)
            atomic_json(attempt / RECEIPT, {"adapter_attempt_id": adapter_id, "trial_path": "tool",
                                            "expected_result_sha256": terminal["result_sha256"],
                                            "raw_sha256": "sha256:" + file_hash(raw)})
            artifacts += [RECORDS, RECEIPT]
        atomic_json(attempt / RESULT, result)
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        totals = result["totals"] or {}
        (attempt / SUMMARY).write_text("# Tree-sitter AST\n\n"
            + (f"- Skipped: {SKIP_REASON} (no file any pinned grammar parses).\n" if result["status"] == "SKIPPED" else
               f"- Files: {totals.get('files')}; functions {totals.get('functions')}, calls {totals.get('calls')}, "
               f"imports {totals.get('imports')}.\n- Gaps: {result['gap_count']}.\n")
            + "- Rows are locators; read the source before citing.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "files": totals.get("files", 0),
                  "gaps": result["gap_count"], "network": "none", "qualification": "implemented_not_qualified",
                  "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="pinned_container", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"tree-sitter AST: {totals.get('files', 0)} file(s).", status_record=status,
            artifact_paths=artifacts, gaps=sorted({gap["kind"] for gap in result["gaps"]}),
            skip_reason=result["skip_reason"], consumer_job_id=CONSUMER,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/treesitter_ast_job.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        consumer_job_id=CONSUMER,
        blocked_summary="Tree-sitter AST preflight did not complete.",
        failed_summary="Tree-sitter AST did not publish; no older success may be used.")


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
