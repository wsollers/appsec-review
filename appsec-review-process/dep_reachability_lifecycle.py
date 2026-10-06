"""Hash-bound inputs and derivation for the ``06-cve-reachability`` correlator (ADR-0023 decision 8).

``bindings`` names every source 06 reads, by hash: the accepted engine tables of
``06-reachability-codeql`` and ``06-reachability-ir`` (verified against their accepted pointer and
attempt tree hashes, same source generation and the same SCA attempt as the match set), the OSV
snapshot the run is bound to (``_osv``), and the run-supplied files under
``<run>/inputs/`` (reviewed map, entry points, language-server and tree-sitter hint documents).
``derive`` re-reads exactly those bindings (re-verifying each hash) and runs
``dep_reachability_correlator.correlate``. Both are deterministic, so ``validate`` re-derives
byte-for-byte. A source that is absent, stale or fails verification is not used and is named in
``gaps``; it never blocks the job (ADR-0013: run to report).

``_cpg``/``_codeql``/``_accepted`` stay the shared verification helpers the engine jobs use.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
from typing import Any

import dep_reachability
import dep_reachability_correlator as correlator
import dep_reachability_engines as engines
from execution_state import data_path, file_hash, read_json, run_path, tree_hashes
import reachability

RESULT = "outputs/dependency-reachability.json"
SUMMARY_JSON = "outputs/dependency-reachability-summary.json"
SUMMARY_MD = "outputs/dependency-reachability-summary.md"
ENGINE_RESULT = "engine-reachability.json"
CPG_JOB, CPG_RESULT = "02-code-property-graph", "code-property-graph.json"
REVIEWED_MAP = "cve-reachability-functions.json"
ENTRY_POINTS = "reachability-entry-points.json"
SUPPLIED = "dependency-reachability"          # <run>/inputs/dependency-reachability/{lsp,treesitter-ast.json}
CODE = ("dep_reachability.py", "dep_reachability_engines.py", "dep_reachability_correlator.py",
        "dep_reachability_lifecycle.py", "reachability.py")
SCHEMAS = ("dependency-reachability.schema.json", "dependency-reachability-match.schema.json",
           "dependency-reachability-summary.schema.json", "engine-reachability.schema.json",
           "engine-reachability-row.schema.json")


def _sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def _regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _accepted(run_id: str, job: str, result: str, source: str) -> tuple[dict[str, Any] | None, str | None]:
    """An accepted publication verified by pointer, envelope and attempt tree hashes, or a gap."""
    base = data_path(run_id, "jobs", job)
    pointer_path = base / "accepted.json"
    if not _regular(pointer_path):
        return None, f"engine-input-absent:{job}"
    try:
        pointer = read_json(pointer_path)
        attempt = base / "attempts" / str(pointer.get("attempt_id"))
        if (pointer.get("run_id") != run_id or pointer.get("job") != job or
                pointer.get("status") not in ("OK", "OK_WITH_GAPS") or attempt.is_symlink() or
                not attempt.is_dir() or tree_hashes(attempt) != pointer.get("hashes") or
                file_hash(attempt / pointer.get("envelope_path", "result.json")) != pointer.get("envelope_sha256")):
            return None, f"engine-input-not-current:{job}"
        document = read_json(attempt / result)
    except (OSError, ValueError, TypeError):
        return None, f"engine-input-not-current:{job}"
    if document.get("source_snapshot_sha256") != source:
        return None, f"engine-input-mixed-lineage:{job}"
    return {"attempt_id": pointer["attempt_id"], "accepted_pointer_sha256": _sha(pointer_path),
            "result_sha256": _sha(attempt / result)}, None


def _cpg(run_id: str, source: str) -> tuple[dict[str, Any] | None, list[str]]:
    binding, gap = _accepted(run_id, CPG_JOB, CPG_RESULT, source)
    if binding is None:
        return None, [gap]
    attempt = data_path(run_id, "jobs", CPG_JOB, "attempts", binding["attempt_id"])
    summary = read_json(attempt / CPG_RESULT)
    if summary.get("status") == "SKIPPED" or not isinstance(summary.get("records_file"), dict):
        return None, ["engine-input-absent:cpg-skipped"]
    return {**binding, "records_sha256": summary["records_file"].get("sha256")}, []


TS_JOB, TS_RESULT = "02-treesitter-ast", "treesitter-ast.json"


def _treesitter_job(run_id: str, source: str) -> dict[str, Any] | None:
    """The accepted ``02-treesitter-ast`` attempt of the same source generation, or None (hint only)."""
    binding, _gap = _accepted(run_id, TS_JOB, TS_RESULT, source)
    if binding is None:
        return None
    result = read_json(data_path(run_id, "jobs", TS_JOB, "attempts", binding["attempt_id"], TS_RESULT))
    return binding if isinstance(result.get("records_file"), dict) else None


def _supplied(run_id: str) -> dict[str, Any]:
    """Run-supplied files: reviewed map, entry points, LSP call-hierarchy docs, tree-sitter AST (hints)."""
    inputs = run_path(run_id) / "inputs"
    found: dict[str, Any] = {}
    for key, name in (("reviewed_map", REVIEWED_MAP), ("entry_points", ENTRY_POINTS)):
        path = inputs / name
        found[key] = {"path": f"inputs/{name}", "sha256": _sha(path)} if _regular(path) else None
    root = inputs / SUPPLIED
    lsp = {}
    for path in sorted((root / "lsp").glob("*.json")) if (root / "lsp").is_dir() else []:
        if _regular(path) and path.stem in engines.ENTRY_POINTS:
            lsp[path.stem] = _sha(path)
    ast = root / "treesitter-ast.json"
    found.update(lsp=lsp, treesitter=_sha(ast) if _regular(ast) else None)
    return found


def _table(run_id: str, engine: str, source: str, sca_attempt: str) -> tuple[dict[str, Any] | None, str | None]:
    """An engine table's accepted publication, bound by hashes and to the same SCA attempt."""
    job = correlator.ENGINE_JOBS[engine]
    binding, gap = _accepted(run_id, job, ENGINE_RESULT, source)
    if binding is None:
        return None, gap
    document = read_json(data_path(run_id, "jobs", job, "attempts", binding["attempt_id"], ENGINE_RESULT))
    from schema_validate import validate_document
    if validate_document(document, "engine-reachability.schema.json") or document.get("engine") != engine:
        return None, f"engine-input-invalid:{job}"
    if document["sca_binding"]["attempt_id"] != sca_attempt:
        return None, f"engine-input-stale:{job}"
    return {**binding, "status": document["status"]}, None


OSV_BINDING_SCHEMA = "appsec-review/osv-run-binding/1"


def osv_binding_path(run_id: str) -> Path:
    """The run's OSV snapshot binding, shared by 06-reachability-codeql/-ir and 06-cve-reachability."""
    return data_path(run_id, "reference-bindings", "osv.json")


def _osv(run_id: str, now: datetime | None = None) -> tuple[Any, dict[str, Any] | None, str | None]:
    """The OSV snapshot this run is bound to, reopened by id and re-verified, or (first launch, or the
    bound snapshot no longer verifies or is over the age ceiling) the current one, which is then bound.

    The OSV sync publishes a new snapshot id every two hours even when nothing changed upstream, so
    binding "current" re-ran every 06 job (and 07-14 after them) on each resume. Age is judged at the
    wall clock (``now``), never at the SCA completion time: a snapshot published after the SCA
    finished is not "in the future" (it was ``TIMESTAMP_IN_FUTURE`` and dropped OSV enrichment).
    An unusable feed is returned as a named gap, never silently."""
    import osv_lookup
    import osv_snapshot
    from execution_state import atomic_json
    moment = now or datetime.now(timezone.utc)
    root = osv_lookup.default_root()
    path = osv_binding_path(run_id)
    resolution = None
    try:
        bound = read_json(path) if _regular(path) else None
        if isinstance(bound, dict) and bound.get("schema") == OSV_BINDING_SCHEMA:
            candidate = osv_snapshot.resolve_bound_snapshot(root, snapshot_id=bound.get("snapshot_id"),
                                                            manifest_sha256=bound.get("manifest_sha256"), now=moment)
            resolution = candidate if candidate.usable else None
    except (OSError, ValueError, TypeError):
        resolution = None
    if resolution is None:
        try:
            resolution = osv_snapshot.resolve_snapshot(root, max_age=osv_snapshot.DEFAULT_MAX_AGE, now=moment)
        except Exception as exc:  # noqa: BLE001 - an unreadable feed is a gap, never a crash
            return None, None, f"osv-unavailable:{type(exc).__name__}"
        if resolution.usable:
            atomic_json(path, {"schema": OSV_BINDING_SCHEMA, "snapshot_id": resolution.identity["snapshot_id"],
                               "manifest_sha256": resolution.identity["manifest_sha256"]})
    source, gap = dep_reachability.open_osv(root, resolution=resolution)
    return source, (source.identity if source else None), gap


def bindings(run_id: str, source: str, generated_at: str, sca_attempt: str) -> dict[str, Any]:
    tables, gaps = {}, []
    for engine in correlator.PROOF_ENGINES:
        tables[engine], gap = _table(run_id, engine, source, sca_attempt)
        if gap:
            gaps.append(gap)
    osv, osv_identity, osv_gap = _osv(run_id)
    if osv is not None:
        osv.connection.close()
    if osv_gap:
        gaps.append(osv_gap)          # named in the document's coverage gaps, never silently dropped
    supplied = _supplied(run_id)
    if supplied["treesitter"] is None:      # a manually supplied document wins; else the accepted job output
        supplied["treesitter_job"] = _treesitter_job(run_id, source)
    return {"tables": tables, "osv": osv_identity, "osv_gap": osv_gap, "supplied": supplied,
            "gaps": sorted(gaps),
            "code": {name: file_hash(Path(__file__).resolve().parent / name) for name in CODE}}


class Stale(RuntimeError):
    """A bound input changed between binding and derivation."""


def _check(path: Path, expected: str) -> bytes:
    data = path.read_bytes() if _regular(path) else b""
    if engines.sha256_bytes(data) != expected:
        raise Stale(f"{path.name} changed after it was bound")
    return data


def derive(run_id: str, bound: dict[str, Any], *, sca: dict[str, Any], sbom: dict[str, Any],
           files: dict[str, str], generated_at: str) -> dict[str, Any]:
    """The ``06`` evidence rows, the per-match document and the summary from exactly ``bound``."""
    del files, generated_at   # the engines bound every witness to the projection before publishing
    tables: dict[str, dict[str, Any] | None] = {}
    for engine, binding in bound["tables"].items():
        if binding is None:
            tables[engine] = None
            continue
        path = data_path(run_id, "jobs", correlator.ENGINE_JOBS[engine], "attempts", binding["attempt_id"], ENGINE_RESULT)
        tables[engine] = json.loads(_check(path, binding["result_sha256"]))
    supplied = bound["supplied"]
    root = run_path(run_id) / "inputs" / SUPPLIED
    lsp = {language: json.loads(_check(root / "lsp" / f"{language}.json", sha))
           for language, sha in sorted(supplied["lsp"].items())}
    ast = json.loads(_check(root / "treesitter-ast.json", supplied["treesitter"])) if supplied["treesitter"] else None
    job = supplied.get("treesitter_job")
    if ast is None and job:
        import treesitter_ast_job
        attempt = data_path(run_id, "jobs", treesitter_ast_job.JOB, "attempts", job["attempt_id"])
        _check(attempt / treesitter_ast_job.RESULT, job["result_sha256"])
        ast = treesitter_ast_job.load_document(attempt)
    inputs = run_path(run_id) / "inputs"
    entries = (json.loads(_check(inputs / ENTRY_POINTS, supplied["entry_points"]["sha256"])).get("entry_points", [])
               if supplied["entry_points"] else [])
    engine_set = engines.EngineSet(lsp=lsp, treesitter=ast)
    identity = {"tables": bound["tables"], "supplied": supplied}
    result = correlator.correlate(sca=sca, sbom=sbom, tables=tables, engine_set=engine_set,
                                  entry_points=sorted({str(item) for item in entries}), osv=bound["osv"],
                                  identity=identity, input_gaps=bound["gaps"])
    result["summary"] = correlator.summary(result["document"], sbom, bound["tables"])
    return result
