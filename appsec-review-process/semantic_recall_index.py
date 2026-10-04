"""Accepted ``02-semantic-recall-index`` producer: optional LanceDB semantic recall over function spans.

Python cuts every chunk. The accepted ``02-code-index`` (bound by pointer, envelope, attempt tree and
database hash, same source generation) supplies the function spans: ``methods`` (CPG, end line from
tree-sitter where it matched) and ``ts_functions``; one chunk per distinct ``(file, start_line,
end_line)``, so a chunk's bounds ARE a function's span. Each chunk is read from the staged target
checkout only when the file's bytes match the hash the code index recorded, passed through the
evidence redactor (``code_snippets.redact_lines``), and capped at 4000 embedded chars (the locator
keeps the full span). Anything not embedded (changed or missing source, unknown span, redactor
withhold, truncation, the 200000-row cap, upstream code-index gaps) is a coverage gap, never silence.

``semantic_index_build.py`` (the legacy builder, moved) embeds the staged plan inside the pinned
image that carries lancedb + fastembed (``image_id`` tunable, default ``audit-static``) in the B13
boundary: network none, the plan and script mounted read-only at ``/inputs/semantic`` and the
preseeded model at ``/model``. The model is pinned by artifact hash in
``data/embedding-models/<model>.json`` and fetched once per host into ``data/feeds/embedding-models``
(``fetch-model`` below); a missing, unpinned or mismatched model BLOCKS before any container runs,
and the container re-hashes the model it loaded.

The attempt publishes ``semantic-recall-index.json`` (``semantic-recall-index.schema.json``; authority
``SEMANTIC_RECALL_ONLY_LOCATORS_REQUIRE_DEREFERENCE``), the locator sidecar
``semantic-recall-chunks.jsonl`` (no source text) and the LanceDB tree under ``tool/scratch``.
``query`` returns bounded locators only; a vector distance is a ranking hint, never evidence: every
hit is dereferenced against the accepted source bytes (``dereference``) before it can support a claim.
SQLite FTS5 (``02-evidence-index``) stays the lexical retrieval authority.

CLI:
  python -B appsec-review-process/semantic_recall_index.py <run_id> [--dagster-id ID] [--force]
  python -B appsec-review-process/semantic_recall_index.py fetch-model [--revision <40-hex commit>] [--pin]
  python -B appsec-review-process/semantic_recall_index.py model-status
  python -B appsec-review-process/semantic_recall_index.py query <attempt_dir> "<text>" [--limit N]
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
from typing import Any, Callable, Iterator

import code_index
import code_snippets
import container_execution as ce
import dep_reachability_lifecycle as bindings
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import intake
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import registry_paths
from schema_validate import validate_document
import semantic_index_build as sib
import tunables

JOB = "02-semantic-recall-index"
CONTRACT = "semantic-recall-index"
RESULT = "semantic-recall-index.json"
SIDECAR = "semantic-recall-chunks.jsonl"
RECEIPT = "semantic-recall-receipt.json"
SUMMARY = "semantic-recall-index-summary.md"
SCHEMA = "appsec-review/semantic-recall-index/1.0"
SCHEMA_FILE = "semantic-recall-index.schema.json"
AUTHORITY = "SEMANTIC_RECALL_ONLY_LOCATORS_REQUIRE_DEREFERENCE"
CODE_INDEX_JOB = "02-code-index"
SCRIPT = ROOT / "semantic_index_build.py"
MOUNT, MODEL_MOUNT = "/inputs/semantic", "/model"
INDEX_DIR = "tool/scratch/semantic-index"
PERMISSIONS = ["read-source", "read-run-data", "write-run-data"]
MAX_ROWS, MAX_CHUNK_CHARS, MAX_RESULTS = 200000, sib.MAX_CHUNK_CHARS, 100
LIMITS = {"max_rows": MAX_ROWS, "max_chunk_chars": MAX_CHUNK_CHARS, "max_results": MAX_RESULTS}
MAX_QUERY_CHARS, MAX_DEREFERENCE_LINES, MAX_LISTED_GAPS = 1000, 400, 200
REPO = ROOT.parent
MODEL_PIN = REPO / "data" / "embedding-models" / "jina-embeddings-v2-base-code.json"
FETCH_COMMAND = "python3 -B appsec-review-process/semantic_recall_index.py fetch-model"


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def image_id() -> str:
    return tunables.value(JOB, "image_id")


def _code() -> dict[str, str]:
    paths = ("semantic_recall_index.py", "semantic_index_build.py", "code_snippets.py", "evidence_redaction.py",
             registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT))
    values = {name: file_hash(ROOT / name) for name in paths}
    values["schemas/" + SCHEMA_FILE] = file_hash(REPO / "schemas" / SCHEMA_FILE)
    values["data/embedding-models/" + MODEL_PIN.name] = file_hash(MODEL_PIN)
    return values


# ---- preseeded, hash-pinned embedding model ------------------------------------------------------

def model_root() -> Path:
    configured = os.environ.get("APPSEC_EMBEDDING_MODEL_ROOT")
    return Path(configured) if configured else REPO / "data" / "feeds" / "embedding-models"


def _slug(model_id: str) -> str:
    return model_id.replace("/", "--")


def model_dir(pin: dict[str, Any], base: Path | None = None) -> Path:
    return (base or model_root()) / _slug(pin["model_id"]) / str(pin["revision"])


def model_binding(pin_path: Path = MODEL_PIN, base: Path | None = None) -> dict[str, Any]:
    """The preseeded model directory verified file by file against its committed pin, or BLOCKED."""
    pin = read_json(pin_path)
    if not pin.get("revision") or not pin.get("artifact_sha256") or not pin.get("files"):
        raise Blocked(f"{JOB}: embedding model {pin.get('model_id')} has no recorded pin in "
                      f"{pin_path.name}; preseed and pin it: {FETCH_COMMAND} --revision <commit> --pin")
    directory = model_dir(pin, base)
    if directory.is_symlink() or not directory.is_dir():
        raise Blocked(f"{JOB}: embedding model is not preseeded at {directory}; run {FETCH_COMMAND}")
    try:
        files = sib.model_files(directory)
    except FileNotFoundError as exc:
        raise Blocked(f"{JOB}: preseeded embedding model at {directory} is incomplete ({exc}); run {FETCH_COMMAND}")
    actual = "sha256:" + digest(files)
    if files != pin["files"] or actual != pin["artifact_sha256"]:
        raise Blocked(f"{JOB}: embedding model at {directory} does not match its pin "
                      f"({actual} != {pin['artifact_sha256']}); delete it and run {FETCH_COMMAND}")
    return {"model_id": pin["model_id"], "revision": pin["revision"], "artifact_sha256": actual,
            "path": str(directory.resolve())}


def fetch_model(revision: str | None = None, *, write_pin: bool = False, pin_path: Path = MODEL_PIN,
                base: Path | None = None) -> dict[str, Any]:
    """Host preparation (network, outside B13): download the pinned files of one immutable model
    revision and verify them against the committed pin; with no pin yet, ``write_pin`` records it."""
    import re
    import urllib.request
    pin = read_json(pin_path)
    revision = revision or pin.get("revision")
    if not revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise SystemExit("fetch-model: pass --revision <the model repository's 40-hex commit>")
    if pin.get("revision") and pin["revision"] != revision:
        raise SystemExit(f"fetch-model: the pin records revision {pin['revision']}; re-pinning is a reviewed change")
    directory = model_dir({**pin, "revision": revision}, base)
    for name in sib.MODEL_FILES:
        target = directory / name
        if target.is_file() and not target.is_symlink():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + ".partial")
        with urllib.request.urlopen(f"{pin['source']}/resolve/{revision}/{name}", timeout=600) as response, \
                partial.open("wb") as handle:
            shutil.copyfileobj(response, handle, 1 << 20)
        partial.replace(target)
    files = sib.model_files(directory)
    actual = "sha256:" + digest(files)
    if pin.get("artifact_sha256"):
        if actual != pin["artifact_sha256"] or files != pin["files"]:
            shutil.rmtree(directory)
            raise SystemExit(f"fetch-model: downloaded files hash {actual}, pin says {pin['artifact_sha256']}; removed")
        return model_binding(pin_path, base)
    if not write_pin:
        raise SystemExit(f"fetch-model: no pin recorded yet; downloaded {actual}. Re-run with --pin and commit "
                         f"{pin_path.relative_to(REPO) if pin_path.is_relative_to(REPO) else pin_path}")
    pin.update(revision=revision, files=files, artifact_sha256=actual, pinned_at=_utc())
    atomic_json(pin_path, pin)
    return model_binding(pin_path, base)


# ---- chunk plan from accepted function spans ----------------------------------------------------

def _hex(value: Any) -> str | None:
    return value.split(":", 1)[1] if isinstance(value, str) and value.startswith("sha256:") else value or None


def spans(database: Path) -> list[tuple[str, int, int | None, str, str | None, str]]:
    """Distinct function spans (file, start, end, symbol, language, kind); a CPG method wins a tie."""
    connection = code_index.open_readonly(database)
    try:
        rows = connection.execute(
            "SELECT file, start_line, end_line, full_name, language, 0 FROM methods "
            "WHERE is_external = 0 AND file IS NOT NULL AND start_line IS NOT NULL UNION ALL "
            "SELECT file, start_line, end_line, coalesce(name, ''), language, 1 FROM ts_functions "
            "WHERE start_line IS NOT NULL").fetchall()
    finally:
        connection.close()
    chosen: dict[tuple[str, int, int | None], tuple] = {}
    for file, start, end, symbol, language, rank in sorted(rows, key=lambda r: (r[0], r[1], r[2] or 0, r[5], r[3])):
        chosen.setdefault((file, start, end), (file, start, end, (symbol or "")[:1000], language,
                                               "method" if rank == 0 else "ts-function"))
    return [chosen[key] for key in sorted(chosen, key=lambda k: (k[0], k[1], k[2] or 0))]


def _file_hashes(database: Path) -> dict[str, str | None]:
    connection = code_index.open_readonly(database)
    try:
        return {path: _hex(sha) for path, sha in connection.execute("SELECT path, sha256 FROM files")}
    finally:
        connection.close()


def write_plan(target: Path, database: Path, *, max_file_bytes: int, plan_path: Path | None = None,
               sidecar_path: Path | None = None, max_rows: int = MAX_ROWS) -> dict[str, Any]:
    """Stream the embedding plan (with redacted text) and the locator sidecar (without) and return
    their hashes, the row count and the gaps. With no paths it only hashes (validation)."""
    plan_hash, sidecar_hash = hashlib.sha256(), hashlib.sha256()
    plan_out = plan_path.open("wb") if plan_path is not None else None
    sidecar_out = sidecar_path.open("wb") if sidecar_path is not None else None
    listed: list[str] = []
    counts = {"span-unknown": 0, "span-beyond-file": 0, "span-empty": 0, "redactor-withheld": 0,
              "truncated": 0, "max-rows": 0}
    rows = 0
    hashes = _file_hashes(database)
    try:
        current_file, lines, file_sha = None, None, None
        for file, start, end, symbol, language, kind in spans(database):
            if file != current_file:
                current_file, lines, file_sha = file, None, None
                path = code_snippets._safe_file(target, file)
                if path is None:
                    listed.append(f"source-missing:{file}")
                elif path.stat().st_size > max_file_bytes:
                    listed.append(f"file-too-large:{file}")
                else:
                    data = path.read_bytes()
                    file_sha = hashlib.sha256(data).hexdigest()
                    if hashes.get(file) not in (None, file_sha):
                        listed.append(f"source-changed:{file}")
                    else:
                        lines = data.decode("utf-8", errors="replace").splitlines()
            if lines is None:
                continue
            if end is None or end < start:
                counts["span-unknown"] += 1; continue
            if end > len(lines):
                counts["span-beyond-file"] += 1; continue
            if rows >= max_rows:
                counts["max-rows"] += 1; continue
            raw = lines[start - 1:end]
            redacted, markers = code_snippets.redact_lines(raw)
            if markers < 0:
                counts["redactor-withheld"] += 1; continue
            text = "\n".join(redacted).strip()
            if not text:
                counts["span-empty"] += 1; continue
            truncated = len(text) > MAX_CHUNK_CHARS
            counts["truncated"] += truncated
            text = text[:MAX_CHUNK_CHARS]
            locator = {"row_id": rows, "file": file, "start_line": start, "end_line": end, "symbol": symbol,
                       "language": language}
            plan_line = sib.plan_line({**locator, "text": text})
            sidecar_line = sib.plan_line({**locator, "kind": kind, "file_sha256": "sha256:" + file_sha,
                "text_sha256": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "raw_chars": len("\n".join(raw)), "max_line_chars": max((len(line) for line in raw), default=0),
                "truncated": truncated, "redaction_markers": markers})
            plan_hash.update(plan_line); sidecar_hash.update(sidecar_line)
            if plan_out is not None:
                plan_out.write(plan_line)
            if sidecar_out is not None:
                sidecar_out.write(sidecar_line)
            rows += 1
    finally:
        for handle in (plan_out, sidecar_out):
            if handle is not None:
                handle.close()
    gaps = sorted(listed)[:MAX_LISTED_GAPS]
    if len(listed) > MAX_LISTED_GAPS:
        gaps.append(f"more-file-gaps:{len(listed) - MAX_LISTED_GAPS}")
    messages = {"span-unknown": "function span(s) without an end line not embedded",
                "span-beyond-file": "function span(s) past the end of the verified file not embedded",
                "span-empty": "function span(s) with no text not embedded",
                "redactor-withheld": "function span(s) withheld by the evidence redactor",
                "truncated": f"chunk(s) embedded only to their first {MAX_CHUNK_CHARS} chars",
                "max-rows": f"function span(s) beyond the {MAX_ROWS}-row cap not embedded"}
    gaps += [f"{key}:{value} {messages[key]}" for key, value in counts.items() if value]
    return {"rows": rows, "plan_sha256": "sha256:" + plan_hash.hexdigest(),
            "sidecar_sha256": "sha256:" + sidecar_hash.hexdigest(), "gaps": gaps}


# ---- lifecycle -----------------------------------------------------------------------------------

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


def _code_index(run_id: str, source: str) -> tuple[dict[str, Any], dict[str, Any]]:
    binding, gap = bindings._accepted(run_id, CODE_INDEX_JOB, code_index.RESULT, source)
    if binding is None:
        raise Blocked(f"{JOB}: no accepted code index for this source generation ({gap})")
    attempt = data_path(run_id, "jobs", CODE_INDEX_JOB, "attempts", binding["attempt_id"])
    result = read_json(attempt / code_index.RESULT)
    database = attempt / code_index.SQLITE
    if database.is_symlink() or not database.is_file() or "sha256:" + file_hash(database) != result["sqlite"]["sha256"]:
        raise Blocked(f"{JOB}: accepted code index database does not match its recorded sha256")
    sources = result.get("sources") or {}
    generations = {"symbol_index_sha256": binding["result_sha256"],
                   "cpg_sha256": (sources.get("cpg") or {}).get("result_sha256"),
                   "ir_facts_sha256": (sources.get("ir_facts") or {}).get("result_sha256")}
    return ({**binding, "sqlite_sha256": result["sqlite"]["sha256"], "gaps": sorted(result.get("gaps", []))},
            generations)


def current_inputs(run_id: str) -> dict[str, Any]:
    from code_graph_evidence import source_tree_sha256
    target, source, revision = _target(run_id)
    index, generations = _code_index(run_id, source)
    model = model_binding()
    image = ce.load_image_registry(ce.IMAGES_DIR).get(image_id())
    if image is None:
        raise Blocked(f"{JOB}: {image_id()} has no current B16 record")
    return {"run_id": run_id, "job": JOB, "target_path": str(target), "source_snapshot_sha256": source,
            "source_revision": revision, "source_tree_sha256": source_tree_sha256(target),
            "code_index": index, "generation_bindings": generations, "model": model, "image": image,
            "boundary_sha256": ce.boundary_sha256(), "container_limits": tunables.container_limits(JOB),
            "batch_size": tunables.value(JOB, "batch_size"), "max_file_bytes": tunables.value(JOB, "max_file_bytes"),
            "script_sha256": "sha256:" + file_hash(SCRIPT), "code": _code()}


def _database(run_id: str, inputs: dict[str, Any]) -> Path:
    path = data_path(run_id, "jobs", CODE_INDEX_JOB, "attempts", inputs["code_index"]["attempt_id"], code_index.SQLITE)
    if "sha256:" + file_hash(path) != inputs["code_index"]["sqlite_sha256"]:
        raise Blocked(f"{JOB}: accepted code index changed after binding")
    return path


def manifest(run_id: str, inputs: dict[str, Any], rows: int, tree_sha256: str, gaps: list[str]) -> dict[str, Any]:
    return {"schema": SCHEMA, "run_id": run_id, "status": "OK_WITH_GAPS" if gaps else "OK", "authority": AUTHORITY,
            "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "source_tree_sha256": inputs["source_tree_sha256"], "generation_bindings": inputs["generation_bindings"],
            "embedding_model": {"model_id": inputs["model"]["model_id"],
                                "artifact_sha256": inputs["model"]["artifact_sha256"], "preseeded": True,
                                "network": "none"},
            "index": {"engine": "lancedb-vector", "table": sib.TABLE, "tree_sha256": tree_sha256, "rows": rows},
            "redaction": "required-before-embedding", "limits": dict(LIMITS), "coverage_gaps": gaps}


def _all_gaps(inputs: dict[str, Any], plan: dict[str, Any]) -> list[str]:
    return plan["gaps"] + [f"code-index:{gap}" for gap in inputs["code_index"]["gaps"]]


def _stage(run_id: str, attempt_id: str, inputs: dict[str, Any]) -> Path:
    """The plan and a copy of the builder, outside the attempt (a mount may not be inside it)."""
    folder = data_path(run_id, "tooling", "semantic-recall", attempt_id)
    folder.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCRIPT, folder / SCRIPT.name)
    if "sha256:" + file_hash(folder / SCRIPT.name) != inputs["script_sha256"]:
        raise Blocked(f"{JOB}: staged semantic_index_build.py does not match its pinned hash")
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


def argv(inputs: dict[str, Any]) -> list[str]:
    return ["/usr/bin/python3", "-B", f"{MOUNT}/{SCRIPT.name}", "build", "--plan", f"{MOUNT}/plan.jsonl",
            "--model", MODEL_MOUNT, "--model-id", inputs["model"]["model_id"], "--out", "/scratch/semantic-index",
            "--stats", "/scratch/semantic-index.stats.json", "--batch-size", str(inputs["batch_size"])]


def _request(run_id: str, attempt_id: str, inputs: dict[str, Any], staged: Path) -> dict[str, Any]:
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
        "image": {"image_id": image_id(), "digest": inputs["image"]["digest"]}, "argv": argv(inputs),
        "environment": [{"name": "LANG", "value": "C.UTF-8"}, {"name": "LC_ALL", "value": "C.UTF-8"},
                        {"name": "XDG_CACHE_HOME", "value": "/tmp/cache"}],
        "target_mounts": [{"host_path": str(staged), "container_path": MOUNT},
                          {"host_path": inputs["model"]["path"], "container_path": MODEL_MOUNT}],
        "scratch_path": "scratch", "log_path": "logs/container", "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, inputs["source_snapshot_sha256"], _utc()),
        "limits": inputs["container_limits"]}


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    common = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"]}
    return ({"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": PERMISSIONS},
            {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
             "build_lineage_sha256": "sha256:" + digest(inputs)})


def _check_stats(stats: dict[str, Any], plan: dict[str, Any], inputs: dict[str, Any]) -> None:
    if (stats.get("rows") != plan["rows"] or stats.get("embedded") != plan["rows"] or
            stats.get("plan_sha256") != plan["plan_sha256"]):
        raise Blocked(f"{JOB}: LanceDB rows do not match the staged plan")
    if stats.get("model_sha256") != inputs["model"]["artifact_sha256"]:
        raise Blocked(f"{JOB}: the container loaded a model other than the pinned one")


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or current_inputs(run_id) != inputs:
        raise Blocked(f"{JOB}: inputs, source generation or model changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, SCHEMA_FILE):
        raise Blocked(f"{JOB}: result fails schema validation")
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: producer permission or lineage receipt changed")
    receipt = read_json(attempt / RECEIPT)
    trial = attempt / receipt.get("trial_path", "")
    request = read_json(trial / "logs" / "container" / ce.REQUEST_FILE)
    runtime = _runtime(inputs["source_snapshot_sha256"])
    ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=receipt.get("adapter_attempt_id", ""),
        request=request, images_dir=runtime.images_dir, expected_result_sha256=receipt.get("expected_result_sha256", ""),
        **_host(runtime))
    stats_path = trial / "scratch" / "semantic-index.stats.json"
    if stats_path.is_symlink() or "sha256:" + file_hash(stats_path) != receipt.get("stats_sha256"):
        raise Blocked(f"{JOB}: container stats changed")
    plan = write_plan(Path(inputs["target_path"]), _database(run_id, inputs), max_file_bytes=inputs["max_file_bytes"])
    if (plan["plan_sha256"] != receipt.get("plan_sha256") or plan["sidecar_sha256"] != receipt.get("sidecar_sha256") or
            "sha256:" + file_hash(attempt / SIDECAR) != plan["sidecar_sha256"]):
        raise Blocked(f"{JOB}: chunk plan no longer matches its hash-bound inputs")
    _check_stats(read_json(stats_path), plan, inputs)
    if result != manifest(run_id, inputs, plan["rows"], sib.tree_sha256(attempt / INDEX_DIR), _all_gaps(inputs, plan)):
        raise Blocked(f"{JOB}: published manifest differs from its index tree or inputs")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if current_inputs(run_id) != inputs:
            raise Blocked(f"{JOB}: source, code index, model or implementation changed before execution")
        attempt = allocation["attempt"]
        staged = _stage(run_id, allocation["attempt_id"], inputs)
        plan = write_plan(Path(inputs["target_path"]), _database(run_id, inputs), max_file_bytes=inputs["max_file_bytes"],
                          plan_path=staged / "plan.jsonl", sidecar_path=attempt / SIDECAR)
        if plan["rows"] < 1:
            raise Blocked(f"{JOB}: no accepted function span could be embedded ({'; '.join(plan['gaps'][:5]) or 'no spans'})")
        trial = attempt / "tool"; trial.mkdir(parents=True)
        adapter_id = "semrec-" + allocation["attempt_id"][:12]
        runtime = _runtime(inputs["source_snapshot_sha256"])
        request = _request(run_id, adapter_id, inputs, staged)
        terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                    attempt_root=trial, request=request)
        ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id, request=request,
            images_dir=runtime.images_dir, expected_result_sha256=terminal["result_sha256"], **_host(runtime))
        if terminal["execution_status"] != "OK":
            raise RuntimeError(f"{JOB}: semantic_index_build.py ended {terminal['execution_status']}")
        stats_path = trial / "scratch" / "semantic-index.stats.json"
        _check_stats(read_json(stats_path), plan, inputs)
        (staged / "plan.jsonl").unlink()     # redacted source text; the sidecar and plan hash remain
        gaps = _all_gaps(inputs, plan)
        result = manifest(run_id, inputs, plan["rows"], sib.tree_sha256(attempt / INDEX_DIR), gaps)
        if validate_document(result, SCHEMA_FILE):
            raise Blocked(f"{JOB}: manifest fails schema validation")
        atomic_json(attempt / RESULT, result)
        atomic_json(attempt / RECEIPT, {"adapter_attempt_id": adapter_id, "trial_path": "tool",
                                        "expected_result_sha256": terminal["result_sha256"],
                                        "stats_sha256": "sha256:" + file_hash(stats_path),
                                        "plan_sha256": plan["plan_sha256"], "sidecar_sha256": plan["sidecar_sha256"],
                                        "index_path": INDEX_DIR})
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        (attempt / SUMMARY).write_text("# Semantic recall index\n\n"
            f"- {plan['rows']} function span(s) embedded with {inputs['model']['model_id']} "
            f"({inputs['model']['artifact_sha256']}).\n- Gaps: {len(gaps)}.\n"
            "- Hits are locators and a ranking hint only; dereference the source before citing. "
            "SQLite FTS5 stays the lexical authority.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id, "dagster_run_id": dagster_id,
                  "attempt_id": allocation["attempt_id"], "rows": plan["rows"], "coverage_gaps": len(gaps),
                  "network": "none", "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="pinned_container", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Semantic recall index: {plan['rows']} function span(s).", status_record=status,
            artifact_paths=[RESULT, SIDECAR, RECEIPT, SUMMARY, "status.json", "permission.json", "lineage.json"],
            gaps=sorted({gap.split(":", 1)[0] for gap in gaps}),
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/semantic_recall_index.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="Semantic recall index preflight did not complete.",
        failed_summary="Semantic recall index did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs), expected_run_id=run_id,
                                    expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


# ---- query: bounded locators only ---------------------------------------------------------------

_VERIFIED: dict[tuple[str, str], bool] = {}


def _locators(index_root: Path) -> Iterator[dict[str, Any]]:
    receipt = read_json(index_root / RECEIPT)
    path = index_root / SIDECAR
    if path.is_symlink() or "sha256:" + file_hash(path) != receipt.get("sidecar_sha256"):
        raise Blocked(f"{JOB}: locator sidecar does not match its receipt")
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def query(index_root: Path, text: str, *, limit: int = 10, embedder: Callable[[list], list] | None = None,
          store: Any = None, model_base: Path | None = None) -> list[dict[str, Any]]:
    """Up to ``limit`` (1..100) function locators ranked by vector similarity to ``text``:
    ``[{file, start_line, end_line, symbol, score}]``. Locators only; dereference before citing.
    ``embedder`` and ``store`` default to the pinned model and the attempt's LanceDB table."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RESULTS:
        raise ValueError(f"limit must be an integer in 1..{MAX_RESULTS}")
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_QUERY_CHARS:
        raise ValueError(f"query text must be 1..{MAX_QUERY_CHARS} chars")
    index_root = Path(index_root)
    document = read_json(index_root / RESULT)
    if validate_document(document, SCHEMA_FILE) or document.get("authority") != AUTHORITY:
        raise Blocked(f"{JOB}: {index_root} is not a schema-valid semantic recall index")
    rows = {row["row_id"]: row for row in _locators(index_root)}
    if len(rows) != document["index"]["rows"]:
        raise Blocked(f"{JOB}: locator sidecar row count differs from the manifest")
    if store is None:
        key = (str(index_root.resolve()), document["index"]["tree_sha256"])
        if not _VERIFIED.get(key):
            if sib.tree_sha256(index_root / INDEX_DIR) != document["index"]["tree_sha256"]:
                raise Blocked(f"{JOB}: LanceDB tree differs from its manifest")
            _VERIFIED[key] = True
        store = sib.LanceStore(index_root / INDEX_DIR)
    if embedder is None:
        model = model_binding(base=model_base)
        if model["artifact_sha256"] != document["embedding_model"]["artifact_sha256"]:
            raise Blocked(f"{JOB}: the index was built with another embedding model; never mix models")
        embedder = sib.fastembed_embedder(Path(model["path"]), model["model_id"])
    vector = embedder([text])[0]
    hits = []
    for hit in store.search(vector, limit)[:limit]:
        row = rows.get(hit["row_id"])
        if row is None:
            raise Blocked(f"{JOB}: index row {hit['row_id']} has no locator")
        hits.append({"file": row["file"], "start_line": row["start_line"], "end_line": row["end_line"],
                     "symbol": row["symbol"], "score": round(1.0 - float(hit["distance"]), 6)})
    return hits


def dereference(index_root: Path, target: Path, locator: dict[str, Any]) -> list[str]:
    """The cited lines of a query locator, read from ``target`` only when the file's bytes still
    match the hash the index was built from (at most ``MAX_DEREFERENCE_LINES``), else BLOCKED."""
    key = (locator.get("file"), locator.get("start_line"), locator.get("end_line"))
    row = next((r for r in _locators(Path(index_root)) if (r["file"], r["start_line"], r["end_line"]) == key), None)
    if row is None:
        raise Blocked(f"{JOB}: locator is not in this index")
    path = code_snippets._safe_file(Path(target), row["file"])
    if path is None:
        raise Blocked(f"{JOB}: {row['file']} is not a regular file under the target")
    data = path.read_bytes()
    if "sha256:" + hashlib.sha256(data).hexdigest() != row["file_sha256"]:
        raise Blocked(f"{JOB}: stale source: {row['file']} changed since the index was built")
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[row["start_line"] - 1:min(row["end_line"], row["start_line"] + MAX_DEREFERENCE_LINES - 1)]


def main(argv_: list[str] | None = None) -> int:
    import argparse
    import sys
    args = list(sys.argv[1:] if argv_ is None else argv_)
    if args[:1] == ["fetch-model"]:
        parser = argparse.ArgumentParser(prog="semantic_recall_index.py fetch-model")
        parser.add_argument("--revision"); parser.add_argument("--pin", action="store_true")
        options = parser.parse_args(args[1:])
        print(json.dumps(fetch_model(options.revision, write_pin=options.pin), indent=2))
        return 0
    if args[:1] == ["model-status"]:
        try:
            print(json.dumps(model_binding(), indent=2)); return 0
        except Blocked as exc:
            print(exc); return 1
    if args[:1] == ["query"]:
        parser = argparse.ArgumentParser(prog="semantic_recall_index.py query")
        parser.add_argument("index_root", type=Path); parser.add_argument("text")
        parser.add_argument("--limit", type=int, default=10)
        options = parser.parse_args(args[1:])
        print(json.dumps(query(options.index_root, options.text, limit=options.limit), indent=2))
        return 0
    parser = argparse.ArgumentParser(); parser.add_argument("run_id"); parser.add_argument("--dagster-id", default="manual")
    parser.add_argument("--force", action="store_true"); options = parser.parse_args(args)
    print(run(options.run_id, options.dagster_id, options.force))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
