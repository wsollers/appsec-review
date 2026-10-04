#!/usr/bin/env python3
"""04-owasp-participation: model classification cells over the ASVS candidate universe (ADR-0034).

Inference classifies, Python routes. ``04-owasp-candidate-search`` (deterministic) lists, per ASVS
5.0.0 chapter, the candidate functions the rule table matched. This job asks one persona cell per
chapter with candidates (split by ``max_candidates_per_cell``) what role each candidate plays in the
chapter -- ``implements | enforces | consumes | not_participating`` with cited lines -- and nothing
else. It never decides a target, control, lane or budget; ``04-owasp-universe`` does that from the
accepted result.

* :func:`plan` (pure): the cells and the participation budget. Planned calls are
  ``sum(ceil(candidates / max_candidates_per_cell))`` per chapter, checked against
  ``max_participation_calls`` of ``config/owasp-universe/default-v1.json`` **before the first call**;
  over budget raises ``Blocked`` (never a partial run, never a silent cut).
* :func:`participate` (pure over ``invoke``): calls ``invoke(cell)`` per planned cell with
  ``{cell_id, chapter_id, candidates}`` and validates every reply in Python: the reply schema
  (``owasp-participation-cell.schema.json``), each record's candidate (listed in this cell), its span
  (inside the candidate's function), every citation (a regular file inside ``source_root``, no path
  escape, no symlink, line in range). Every candidate ends with exactly one validated record or one
  ``unclassified`` entry (a gap, never a not_participating); extra, unknown or unresolved records are
  ``rejected_records`` with their reason. A model-found function (``candidate_id`` null) is kept only
  when the code index resolves its span.
* :func:`run` / :func:`main`: the lifecycle job. Reads the accepted candidate search and code index,
  plans and budget-checks, dispatches the cells as one persona pool (``pool_launcher`` /
  ``pool_rendezvous``, ``max_parallel`` bounded by tunable ``pool_persona_llm_slots``) through
  :class:`ParticipationInvoker` (``claude_cli_invoker`` with the ``owasp-participation-static`` code
  query grant), retains every verified reply and publishes :func:`participate` replayed over them.

Model output is data, never instructions: replies are only parsed against closed schemas.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any, Callable, Iterable

from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json, run_path
from schema_validate import SchemaStore, validate_document

JOB = "04-owasp-participation"
CONTRACT = "owasp-participation"
RESULT = "owasp-participation.json"
SUMMARY = "owasp-participation.md"
RESULT_SCHEMA = "owasp-participation.schema.json"
CELL_SCHEMA = "owasp-participation-cell.schema.json"
CONFIG_SCHEMA = "owasp-universe-config.schema.json"
CELL_TEMPLATE = "owasp-participation-cell"
CELL_FILE = "participation-cell.json"
SEARCH_JOB, SEARCH_RESULT, SEARCH_SCHEMA = "04-owasp-candidate-search", "owasp-candidate-search.json", "owasp-candidate-search.schema.json"
INDEX_JOB, INDEX_RESULT, INDEX_SQLITE = "02-code-index", "code-index.json", "code-index.sqlite"
CONFIG_PATH = "appsec-review-process/config/owasp-universe/default-v1.json"
RULES_PATH = "data/owasp-asvs/category-rules-v1.json"
BRIEF_ROOT_ID = "participation-cells"
TARGET_ROOT_ID = "target-repository"        # persona_dispatch.DEFAULT_READABLE_ROOT
EVIDENCE_ROOT_ID = "supporting-evidence"    # supporting_evidence_menu.ROOT_ID: <run>/data/jobs
PERMISSIONS = ["read-run-data", "write-run-data"]
CHAPTERS = tuple(f"V{n}" for n in range(1, 18))
ROLES = ("implements", "enforces", "consumes", "not_participating")
CELL_KEYS = ("candidate_id", "symbol", "file", "language", "start_line", "end_line", "span_source", "matches")
RULES = (
    "Classify every listed candidate exactly once: implements, enforces, consumes or not_participating.",
    "Cite only repository-relative path:line you read; a citation that does not resolve rejects the record.",
    "Classification only: no control verdicts, findings, severity, chapters, lanes or downstream work.",
    "Do not write cell ids, hashes or ordering; the orchestrator derives them.",
)


class CellFailed(RuntimeError):
    """A cell produced no reply (dispatch failed, canceled or unverified)."""


def _order(chapter: str) -> int:
    return CHAPTERS.index(chapter)


def _bare(value: Any) -> str | None:
    return value.removeprefix("sha256:") if isinstance(value, str) else None


def _gap_id(value: Any) -> str:
    return "gap-" + digest(value)[:20]


# --- planning and budget (pure) -------------------------------------------------------------------

def plan(candidate_search: dict[str, Any], config: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(budget, cells): one cell per chapter with candidates, split by ``max_candidates_per_cell``.
    Raises ``Blocked`` for an invalid config, a malformed candidate list or a plan over budget."""
    store = SchemaStore()
    if validate_document(config, CONFIG_SCHEMA, store):
        raise Blocked(f"{JOB}: universe config fails {CONFIG_SCHEMA}")
    per, limit = config["participation"]["max_candidates_per_cell"], config["participation"]["max_participation_calls"]
    by_chapter: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for row in candidate_search.get("candidates") or []:
        if not isinstance(row, dict) or row.get("chapter_id") not in CHAPTERS or not isinstance(row.get("candidate_id"), str):
            raise Blocked(f"{JOB}: candidate search holds a malformed candidate")
        if row["candidate_id"] in seen:
            raise Blocked(f"{JOB}: candidate {row['candidate_id']} is listed twice")
        seen.add(row["candidate_id"])
        by_chapter.setdefault(row["chapter_id"], []).append(row)
    cells = []
    for chapter in sorted(by_chapter, key=_order):
        rows = sorted(by_chapter[chapter], key=lambda r: (r["file"], r["start_line"], r["symbol"], r["candidate_id"]))
        count = math.ceil(len(rows) / per)
        if count > 99:
            raise Blocked(f"{JOB}: chapter {chapter} needs {count} cells; the cell id allows 99")
        for index in range(count):
            cells.append({"cell_id": f"asvs-{chapter}-{index + 1:02d}", "chapter_id": chapter,
                          "candidates": [{key: row[key] for key in CELL_KEYS if key in row}
                                         for row in rows[index * per:(index + 1) * per]]})
    budget = {"max_candidates_per_cell": per, "max_participation_calls": limit, "planned_calls": len(cells),
              "within_budget": len(cells) <= limit}
    if not budget["within_budget"]:
        raise Blocked(f"{JOB}: {len(cells)} planned participation calls exceed max_participation_calls {limit} "
                      f"({per} candidates per cell); a larger budget is a new reviewed config version")
    return budget, cells


# --- the snapshot reader (pure over the source root) ---------------------------------------------------

def source_reader(source_root: Path) -> Callable[[str], bytes | None]:
    """Bytes of one repository-relative regular file inside ``source_root``, or None: no absolute path,
    no ``..``/``.``/empty part, no ``.git``, no symlink at any level, nothing resolving outside the root."""
    base = Path(source_root).resolve()
    cache: dict[str, bytes | None] = {}

    def read(relative: str) -> bytes | None:
        if relative in cache:
            return cache[relative]
        data = None
        posix = PurePosixPath(relative) if isinstance(relative, str) and "\\" not in relative else None
        if posix is not None and posix.parts and not posix.is_absolute() and posix.parts[0] != ".git" and \
                not any(part in {"", ".", ".."} for part in relative.split("/")):
            cursor, safe = base, True
            for part in posix.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    safe = False
                    break
            try:
                inside = safe and cursor.resolve(strict=True).is_relative_to(base)
            except OSError:
                inside = False
            if inside and cursor.is_file():
                data = cursor.read_bytes()
        cache[relative] = data
        return data

    return read


def _lines(data: bytes) -> int:
    return len(data.splitlines())


def _resolve_found(index: sqlite3.Connection | None, record: dict[str, Any]) -> tuple[str, int, int] | None:
    """(symbol, start, end) of the indexed function in ``record['file']`` named ``record['symbol']`` whose
    span holds the record's start line (CPG methods first, then tree-sitter functions)."""
    if index is None:
        return None
    file, symbol, start = record["file"], record["symbol"], record["start_line"]
    row = index.execute(
        "SELECT name, start_line, COALESCE(end_line, start_line) FROM methods WHERE file=? AND is_external=0 "
        "AND ? IN (name, qualified, full_name) AND start_line<=? AND COALESCE(end_line, start_line)>=? "
        "ORDER BY start_line DESC, id LIMIT 1", (file, symbol, start, start)).fetchone()
    row = row or index.execute(
        "SELECT name, start_line, end_line FROM ts_functions WHERE file=? AND name=? AND start_line<=? AND end_line>=? "
        "ORDER BY start_line DESC LIMIT 1", (file, symbol, start, start)).fetchone()
    return (row[0], int(row[1]), int(row[2])) if row else None


# --- participation (pure over invoke) ------------------------------------------------------------------

def participate(candidate_search: dict[str, Any], config: dict[str, Any], *, invoke: Callable[[dict[str, Any]], Any],
                source_root: Path, index: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Plan, budget-check, call ``invoke`` once per cell and validate every reply.

    Returns the owasp-participation members ``budget, cells, records, unclassified, rejected_records,
    gaps``. ``index`` (an open code-index connection) resolves model-found functions; without it such
    records are rejected ``symbol_not_indexed``. Raises ``Blocked`` before any call when the plan is
    over budget or a candidate's file is not the snapshot's bytes."""
    budget, cells = plan(candidate_search, config)
    read = source_reader(Path(source_root))
    hashes: dict[str, str] = {}
    by_id = {row["candidate_id"]: row for row in candidate_search.get("candidates") or []}
    for row in by_id.values():
        data = read(row["file"])
        recorded = _bare(row.get("file_sha256"))
        if data is None or (recorded is not None and recorded != hashlib.sha256(data).hexdigest()):
            raise Blocked(f"{JOB}: candidate file {row['file']} is not the candidate search snapshot under source_root")
        hashes[row["file"]] = hashlib.sha256(data).hexdigest()
    store = SchemaStore()
    out_cells, records, unclassified, rejected, gaps = [], [], [], [], []

    def sha_of(path: str) -> str | None:
        if path not in hashes:
            data = read(path)
            hashes[path] = hashlib.sha256(data).hexdigest() if data is not None else None
        return hashes[path]

    def citations_of(record: dict[str, Any]) -> list[dict[str, Any]] | None:
        rows, seen = [], set()
        for item in record["citations"]:
            data = read(item["file"])
            if data is None or not 1 <= item["line"] <= _lines(data):
                return None
            key = (item["file"], item["line"])
            if key not in seen:
                seen.add(key)
                rows.append({"file": item["file"], "line": item["line"], "file_sha256": sha_of(item["file"])})
        return sorted(rows, key=lambda row: (row["file"], row["line"]))

    for cell in cells:
        cell_id, chapter = cell["cell_id"], cell["chapter_id"]
        listed = {row["candidate_id"]: by_id[row["candidate_id"]] for row in cell["candidates"]}
        order = list(listed)
        try:
            reply = invoke({"cell_id": cell_id, "chapter_id": chapter,
                            "candidates": json.loads(json.dumps(cell["candidates"]))})
        except Blocked:
            raise
        except Exception as exc:   # a cell that did not answer is a gap, never fatal (ADR-0013)
            out_cells.append({"cell_id": cell_id, "chapter_id": chapter, "candidate_ids": order, "outcome": "failed",
                              "reply_sha256": None})
            unclassified += [{"candidate_id": cid, "chapter_id": chapter, "cell_id": cell_id, "reason": "cell_failed"}
                             for cid in order]
            statement = f"Participation cell {cell_id} returned no reply ({type(exc).__name__}); {len(order)} candidate(s) unclassified."
            gaps.append({"gap_id": _gap_id(["cell_failed", cell_id]), "kind": "cell_failed", "chapter_ids": [chapter],
                         "statement": statement[:1000]})
            continue
        try:
            reply_sha = digest(reply)
        except (TypeError, ValueError):
            reply, reply_sha = None, None
        if reply is None or validate_document(reply, CELL_SCHEMA, store):
            out_cells.append({"cell_id": cell_id, "chapter_id": chapter, "candidate_ids": order,
                              "outcome": "invalid_reply", "reply_sha256": reply_sha})
            unclassified += [{"candidate_id": cid, "chapter_id": chapter, "cell_id": cell_id, "reason": "invalid_reply"}
                             for cid in order]
            gaps.append({"gap_id": _gap_id(["invalid_reply", cell_id]), "kind": "invalid_reply", "chapter_ids": [chapter],
                         "statement": f"Participation cell {cell_id} reply fails {CELL_SCHEMA}; {len(order)} candidate(s) unclassified."})
            continue
        out_cells.append({"cell_id": cell_id, "chapter_id": chapter, "candidate_ids": order, "outcome": "accepted",
                          "reply_sha256": reply_sha})
        accepted: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        failed: dict[str, str] = {}
        found: dict[tuple[str, int, int], int] = {}
        listed_spans = {(row["file"], row["start_line"]) for row in listed.values()}
        for position, record in enumerate(reply["records"]):
            cid = record["candidate_id"]
            citations = citations_of(record)
            if cid is not None:
                candidate = listed.get(cid)
                if candidate is None:
                    rejected.append({"cell_id": cell_id, "record_index": position, "reason": "unknown_candidate"}); continue
                start, end = record["start_line"], record["end_line"]
                if candidate["span_source"] == "treesitter":
                    inside = candidate["start_line"] <= start <= end <= candidate["end_line"]
                else:
                    inside = start <= candidate["start_line"] <= max(start, end)
                if record["file"] != candidate["file"] or not inside:
                    rejected.append({"cell_id": cell_id, "record_index": position, "reason": "span_mismatch"})
                    failed.setdefault(cid, "span_mismatch"); continue
                if citations is None:
                    rejected.append({"cell_id": cell_id, "record_index": position, "reason": "citation_unresolved"})
                    failed.setdefault(cid, "citation_unresolved"); continue
                accepted.setdefault(cid, []).append((position, {
                    "cell_id": cell_id, "chapter_id": chapter, "candidate_id": cid, "symbol": candidate["symbol"],
                    "file": candidate["file"], "file_sha256": hashes[candidate["file"]],
                    "start_line": candidate["start_line"], "end_line": candidate["end_line"], "role": record["role"],
                    "citations": citations, "rationale": record["rationale"]}))
                continue
            resolved = _resolve_found(index, record) if read(record["file"]) is not None else None
            if resolved is None:
                rejected.append({"cell_id": cell_id, "record_index": position, "reason": "symbol_not_indexed"}); continue
            symbol, start, end = resolved
            if not start <= record["start_line"] <= record["end_line"] <= end:
                rejected.append({"cell_id": cell_id, "record_index": position, "reason": "span_mismatch"}); continue
            if citations is None:
                rejected.append({"cell_id": cell_id, "record_index": position, "reason": "citation_unresolved"}); continue
            key = (record["file"], start, end)
            if key in found or (record["file"], start) in listed_spans:
                rejected.append({"cell_id": cell_id, "record_index": position, "reason": "duplicate_record"}); continue
            found[key] = position
            records.append({"cell_id": cell_id, "chapter_id": chapter, "candidate_id": None, "symbol": symbol,
                            "file": record["file"], "file_sha256": sha_of(record["file"]), "start_line": start,
                            "end_line": end, "role": record["role"], "citations": citations,
                            "rationale": record["rationale"]})
        for cid in order:
            rows = accepted.get(cid, [])
            distinct = {json.dumps({k: row[k] for k in ("role", "citations", "rationale")}, sort_keys=True) for _p, row in rows}
            if len(distinct) == 1:
                records.append(rows[0][1])
                rejected += [{"cell_id": cell_id, "record_index": p, "reason": "duplicate_record"} for p, _r in rows[1:]]
            elif rows:
                rejected += [{"cell_id": cell_id, "record_index": p, "reason": "duplicate_record"} for p, _r in rows]
                unclassified.append({"candidate_id": cid, "chapter_id": chapter, "cell_id": cell_id, "reason": "duplicate_record"})
            else:
                unclassified.append({"candidate_id": cid, "chapter_id": chapter, "cell_id": cell_id,
                                     "reason": failed.get(cid, "missing_record")})
    for chapter in CHAPTERS:
        missing = [row for row in unclassified if row["chapter_id"] == chapter
                   and row["reason"] not in {"cell_failed", "invalid_reply"}]
        if missing:
            reasons = ", ".join(f"{reason} {sum(1 for row in missing if row['reason'] == reason)}"
                                for reason in sorted({row["reason"] for row in missing}))
            gaps.append({"gap_id": _gap_id(["unclassified_candidates", chapter]), "kind": "unclassified_candidates",
                         "chapter_ids": [chapter],
                         "statement": f"{len(missing)} {chapter} candidate(s) have no validated classification ({reasons})."})
    cell_rank = {cell["cell_id"]: number for number, cell in enumerate(cells)}
    records.sort(key=lambda r: (cell_rank[r["cell_id"]], r["file"], r["start_line"], r["end_line"], r["symbol"], r["candidate_id"] or ""))
    unclassified.sort(key=lambda r: (cell_rank[r["cell_id"]], r["candidate_id"]))
    rejected.sort(key=lambda r: (cell_rank[r["cell_id"]], r["record_index"], r["reason"]))
    gaps.sort(key=lambda g: (_order(g["chapter_ids"][0]), g["kind"], g["gap_id"]))
    return {"budget": budget, "cells": out_cells, "records": records, "unclassified": unclassified,
            "rejected_records": rejected, "gaps": gaps}


def document(members: dict[str, Any], *, run_id: str, source_snapshot_sha256: str, candidate_search: dict[str, Any],
             code_index: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """The published owasp-participation document; ``Blocked`` when it fails its closed schema."""
    value = {"schema": "appsec-review/owasp-participation/1.0", "run_id": run_id, "job_id": JOB,
             "source_snapshot_sha256": source_snapshot_sha256, "status": "OK_WITH_GAPS" if members["gaps"] else "OK",
             "candidate_search": candidate_search, "code_index": code_index, "config": config, **members}
    errors = validate_document(value, RESULT_SCHEMA)
    if errors:
        raise Blocked(f"{JOB}: result fails {RESULT_SCHEMA} ({errors[0]})")
    return value


def summary(result: dict[str, Any]) -> str:
    lines = ["# ASVS chapter participation", "",
             f"{result['budget']['planned_calls']} cell(s) planned (limit {result['budget']['max_participation_calls']}); "
             f"{len(result['records'])} validated record(s), {len(result['unclassified'])} unclassified, "
             f"{len(result['rejected_records'])} rejected.", "",
             "| Chapter | Cells | implements | enforces | consumes | not_participating | unclassified |",
             "|---|---|---|---|---|---|---|"]
    for chapter in CHAPTERS:
        cells = [cell for cell in result["cells"] if cell["chapter_id"] == chapter]
        if not cells:
            continue
        counts = [sum(1 for r in result["records"] if r["chapter_id"] == chapter and r["role"] == role) for role in ROLES]
        lost = sum(1 for r in result["unclassified"] if r["chapter_id"] == chapter)
        lines.append(f"| {chapter} | {len(cells)} | " + " | ".join(map(str, counts)) + f" | {lost} |")
    if result["gaps"]:
        lines += ["", "## Gaps", ""] + [f"- {gap['kind']} ({', '.join(gap['chapter_ids'])}): {gap['statement']}"
                                         for gap in result["gaps"]]
    lines += ["", "Classification only: 04-owasp-universe decides every chapter target and budget.", ""]
    return "\n".join(lines)


# --- accepted inputs -----------------------------------------------------------------------------------

def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _accepted(run_id: str, job: str, artifact: str, schema: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    """(document, owasp binding, attempt dir) of one accepted publication. The binding comes from
    ``owasp_universe._accepted_input``, the same check 04-owasp-universe applies to the candidate search
    this result names, so the two bindings cannot disagree."""
    import owasp_universe
    try:
        value, binding = owasp_universe._accepted_input(run_id, job, artifact, schema, required=True)
    except Blocked as exc:
        raise Blocked(f"{JOB}: {exc}") from exc
    return value, binding, (data_path(run_id) / PurePosixPath(binding["artifact_path"])).parent


def load_config(path: str = CONFIG_PATH) -> tuple[dict[str, Any], dict[str, Any]]:
    value = json.loads((ROOT.parent / path).read_text(encoding="utf-8"))
    if validate_document(value, CONFIG_SCHEMA):
        raise Blocked(f"{JOB}: {path} fails {CONFIG_SCHEMA}")
    return value, {"path": path, "config_id": value["config_id"], "version": value["version"], "config_digest": digest(value)}


def _target(run_id: str) -> Path:
    manifest_path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    value = (read_json(manifest_path).get("target") or {}).get("repo_path")
    path = Path(value) if isinstance(value, str) and value else None
    if path is None or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    return path.resolve()


def _open_index(run_id: str, inputs: dict[str, Any]) -> sqlite3.Connection:
    database = (data_path(run_id) / PurePosixPath(inputs["code_index"]["artifact_path"])).parent / INDEX_SQLITE
    if database.is_symlink() or not database.is_file() or file_hash(database) != inputs["index_sqlite_sha256"]:
        raise Blocked(f"{JOB}: the code index database does not match its accepted summary")
    return sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro", uri=True)


def _code_hashes() -> dict[str, str]:
    import registry_paths
    paths = ["owasp_participation.py", registry_paths.template_rel(JOB), registry_paths.template_rel(CELL_TEMPLATE),
             registry_paths.contract_rel(CONTRACT), registry_paths.contract_rel("owasp-participation-cell"),
             "personas/roles/asvs-participation-classifier/role.json", "personas/personas/owasp-validator/persona.json",
             registry_paths.rel(registry_paths.TOOLING_PROFILES, "owasp-participation-static"),
             "04-asvs-masvs/task-owasp-participation-cell.md"]
    values = {path: file_hash(ROOT / path) for path in paths}
    for name in (RESULT_SCHEMA, CELL_SCHEMA, CONFIG_SCHEMA, SEARCH_SCHEMA):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def prepare(run_id: str) -> dict[str, Any]:
    """Bind the accepted candidate search, code index, config and checkout; plan and budget-check (no model)."""
    search, search_binding, _ = _accepted(run_id, SEARCH_JOB, SEARCH_RESULT, SEARCH_SCHEMA)
    index, index_binding, index_attempt = _accepted(run_id, INDEX_JOB, INDEX_RESULT, "code-index.schema.json")
    source = search["source_snapshot_sha256"]
    if index.get("source_snapshot_sha256") != source:
        raise Blocked(f"{JOB}: candidate search and code index bind different source snapshots")
    config, config_ref = load_config()
    budget, cells = plan(search, config)   # Blocked over budget: before any model call
    target = _target(run_id)
    read = source_reader(target)
    files = {}
    for path in sorted({row["file"] for cell in cells for row in cell["candidates"]}):
        data = read(path)
        if data is None:
            raise Blocked(f"{JOB}: candidate file {path} is not a regular file of the checkout")
        files[path] = {"sha256": "sha256:" + hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    summary_path = index_attempt / INDEX_RESULT
    names = {chapter["chapter_id"]: chapter["chapter_name"]
             for chapter in json.loads((ROOT.parent / RULES_PATH).read_text(encoding="utf-8"))["chapters"]}
    return {"run_id": run_id, "source_snapshot_sha256": source, "candidate_search": search_binding,
            "code_index": index_binding, "index_sqlite_sha256": _bare((index.get("sqlite") or {}).get("sha256")),
            "index_summary": {"path": index_binding["artifact_path"].removeprefix("jobs/"),
                              "sha256": "sha256:" + file_hash(summary_path), "bytes": summary_path.stat().st_size},
            "config": config_ref, "config_value": config, "candidates": search["candidates"], "budget": budget,
            "cells": [{"cell_id": cell["cell_id"], "chapter_id": cell["chapter_id"],
                       "chapter_name": names.get(cell["chapter_id"], cell["chapter_id"]), "candidates": cell["candidates"]}
                      for cell in cells],
            "files": files, "target_root": str(target), "code": _code_hashes()}


# --- the live invoker and pool -----------------------------------------------------------------------

def brief(cell: dict[str, Any], run_id: str) -> dict[str, Any]:
    return {"schema": "appsec-review/owasp-participation-cell-brief/1.0", "run_id": run_id, "job_id": JOB,
            "cell_id": cell["cell_id"], "chapter_id": cell["chapter_id"], "chapter_name": cell["chapter_name"],
            "standard": "OWASP ASVS 5.0.0", "candidates": cell["candidates"], "roles": list(ROLES), "rules": list(RULES),
            "reply_shape": f"{{\"records\": [...]}} validating {CELL_SCHEMA}; one record per listed candidate"}


def brief_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def coverage_errors(value: dict[str, Any], listed: Iterable[str]) -> list[str]:
    """Missing, duplicate and unknown candidate ids in one reply (the invoker's repair-loop check)."""
    listed = list(listed)
    ids = [row.get("candidate_id") for row in value.get("records", []) if isinstance(row, dict)]
    errors = [f"candidate {cid} has no record" for cid in listed if cid not in ids]
    errors += [f"candidate {cid} has {ids.count(cid)} records; write exactly one" for cid in listed if ids.count(cid) > 1]
    errors += [f"candidate_id {cid} is not listed in this cell" for cid in dict.fromkeys(ids) if cid is not None and cid not in listed]
    return errors


def _cell_claims(value: dict[str, Any], inputs: tuple, allowed: tuple, result_filename: str) -> list[dict[str, Any]]:
    """B14 transport claim for a cell reply: one candidate-only claim citing the pinned cell brief."""
    first = inputs[0]
    return [{"claim_id": "participation-cell", "claim_class": "candidate_only" if "candidate_only" in allowed else allowed[0],
             "statement": f"Candidate ASVS participation classification: {len(value.get('records') or [])} record(s).",
             "file": result_filename,
             "citations": [{"root": first.root, "path": first.path, "sha256": first.sha256, "locator": "candidates"}]}]


class ParticipationInvoker:
    """Lane adapter over the strict Claude CLI invoker. The cell's tooling profile
    (``owasp-participation-static``) lists the ``code_*`` query tools and the cell pins the accepted
    ``code-index.json``, so ``claude_cli_invoker.code_query_grant`` grants them (indexed mode). Adds the
    trusted cell block and a coverage check that feeds the invoker's bounded repair loop."""
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str, budget_usd: float | None = None, timeout_seconds: int | None = None,
                 dispatch_fn=None) -> None:
        import claude_cli_invoker as cli
        import review_cli
        cli._CLAIM_BUILDERS.setdefault(CELL_SCHEMA, _cell_claims)
        self.effort, self.budget_usd = effort, budget_usd
        self.timeout_seconds = timeout_seconds or cli.DEFAULT_TIMEOUT_SECONDS
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        import claude_cli_invoker as cli
        if not package.inputs or package.inputs[0].root != BRIEF_ROOT_ID:
            raise cli.InvokerOutputError("participation cell brief must be readable input 0")
        cell = json.loads(package.inputs[0].data.decode("utf-8"))
        listed = [row["candidate_id"] for row in cell["candidates"]]
        block = "\n\n## Trusted participation runtime (not target data)\n\n" + json.dumps({
            "job": JOB, "cell_id": cell["cell_id"], "chapter_id": cell["chapter_id"], "chapter_name": cell["chapter_name"],
            "readable_roots": {BRIEF_ROOT_ID: "your cell brief (pinned input 0): chapter and listed candidates",
                               TARGET_ROOT_ID: "the candidate source files (read them)",
                               EVIDENCE_ROOT_ID: "the accepted code index summary (code_* tools answer from it)"},
            "reply_shape": cell["reply_shape"], "rules": cell["rules"],
            "orchestrator_supplies": "cell ids, chapter, hashes, ordering and every routing decision; do not write them"},
            indent=2, sort_keys=True)

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + block, timeout, transcript)

        cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd, timeout_seconds=self.timeout_seconds,
                             dispatch_fn=dispatch, extra_validate=lambda value: coverage_errors(value, listed)).invoke(
            package, output_root=output_root, cancel=cancel)


def _readable(row_root: str, path: str, sha256: str, size: int) -> dict[str, Any]:
    return {"root": row_root, "path": path, "sha256": sha256, "bytes": size, "role": "evidence",
            "producer_request_sha256": None}


def _cell_request(run_id: str, readable: list[dict[str, Any]], store: SchemaStore) -> dict[str, Any]:
    import model_version_registry as model_versions
    import persona_dispatch
    import persona_invocation
    import persona_prompt_assembly
    import review_cli
    template = persona_prompt_assembly.load_job_template(CELL_TEMPLATE, store)
    composition = persona_dispatch._composition_block(CELL_TEMPLATE, template, store)
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if "candidate_only" not in ceiling["allowed"]:
        raise Blocked(f"{JOB}: registry composition forbids candidate_only participation claims")
    resolved = review_cli.resolve_model(CELL_TEMPLATE, template["budget_default"])
    return {"invocation_role": "produce", "invoker_id": "claude-cli",
            "outer_prompt": persona_prompt_assembly.assemble_outer_prompt(CELL_TEMPLATE, store=store),
            "persona": composition, "model": model_versions.model_identity_for(run_id, resolved["model"]),
            "tools": [], "budget": dict(persona_dispatch.PERSONA_BUDGETS[template["budget_default"]]),
            "readable_inputs": readable, "allowed_claim_classes": ["candidate_only"],
            "prohibited_claim_classes": sorted(set(ceiling["prohibited"]) | (set(ceiling["allowed"]) - {"candidate_only"})),
            "producers": []}


def _budget_usd() -> float | None:
    import persona_prompt_assembly
    import review_cli
    template = persona_prompt_assembly.load_job_template(CELL_TEMPLATE, SchemaStore())
    value = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(template["budget_default"])
    return float(value) if isinstance(value, (int, float)) else None


def max_parallel(cells: int) -> int:
    """Cells dispatched concurrently: the persona_llm resource pool size, never more than the cells."""
    import tunables
    return max(1, min(int(tunables.shared("pool_persona_llm_slots")), cells))


def run_pool(inputs: dict[str, Any], attempt: Path, invoker: Any) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Launch every planned cell as one persona pool and wait for all. Returns ({cell_id: verified reply
    bytes}, pool record). A cell without a verified reply is simply absent (a ``cell_failed`` gap)."""
    import container_execution
    import persona_dispatch
    import persona_invocation
    import pool_launcher
    import pool_rendezvous
    import pool_specification
    import resource_pools
    run_id, store = inputs["run_id"], SchemaStore()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    briefs = attempt / "cell-briefs"
    pool_parent, rendezvous = attempt / "pools", attempt / "rendezvous"
    for folder in (briefs, pool_parent, rendezvous):
        folder.mkdir(parents=True, exist_ok=True)
    summary_row = _readable(EVIDENCE_ROOT_ID, inputs["index_summary"]["path"], inputs["index_summary"]["sha256"],
                            inputs["index_summary"]["bytes"])
    groups = []
    for cell in inputs["cells"]:
        data = brief_bytes(brief(cell, run_id))
        atomic_bytes(briefs / f"{cell['cell_id']}.json", data)
        readable = [_readable(BRIEF_ROOT_ID, f"{cell['cell_id']}.json", "sha256:" + hashlib.sha256(data).hexdigest(), len(data))]
        readable += [_readable(TARGET_ROOT_ID, path, inputs["files"][path]["sha256"], inputs["files"][path]["bytes"])
                     for path in sorted({row["file"] for row in cell["candidates"]})]
        readable.append(summary_row)
        groups.append({"group_id": cell["cell_id"].lower(), "worker_kind": pool_specification.PERSONA, "count": 1,
                       "memory_heavy": False,
                       "permission": persona_dispatch._permission_block(JOB, run_id=run_id,
                                                                        source_snapshot_sha256=inputs["source_snapshot_sha256"], now=now),
                       "persona_request": _cell_request(run_id, readable, store), "tool_request": None})
    groups.sort(key=lambda group: group["group_id"])
    budget = groups[0]["persona_request"]["budget"]
    spec = {"schema": pool_specification.SPEC_ID, "pool_id": "owasp-participation", "lane": "04-asvs-masvs",
            "run_id": run_id, "job_id": JOB, "attempt_id": "part-" + digest(inputs)[:24], "budget_class": "standard",
            "pool_budget": {"max_instances": len(groups), "max_persona_input_units": len(groups) * budget["input_unit_limit"],
                            "max_persona_output_units": len(groups) * budget["output_unit_limit"],
                            "max_total_timeout_seconds": len(groups) * budget["timeout_seconds"]},
            "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]}, "wait_all": True,
            "rendezvous_timeout_seconds": len(groups) * budget["timeout_seconds"], "empty_pool_reason": None,
            "worker_groups": groups}
    models = tuple({json.dumps(g["persona_request"]["model"], sort_keys=True): g["persona_request"]["model"] for g in groups}.values())
    context = pool_specification.PoolContext(pool_parent=pool_parent, registry_dir=persona_invocation.REGISTRY_DIR,
        prompt_root=ROOT, readable_roots={BRIEF_ROOT_ID: briefs, TARGET_ROOT_ID: Path(inputs["target_root"]),
                                          EVIDENCE_ROOT_ID: data_path(run_id, "jobs").absolute()},
        allowed_models=models, invoker_id="claude-cli", images_dir=container_execution.IMAGES_DIR,
        host_flavor="windows" if os.name == "nt" else "posix", docker_host=None, docker_executable=None,
        container_user=None, mount_roots={}, source_snapshot_sha256=inputs["source_snapshot_sha256"], registry_ceiling=None)
    runtime = pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous, invoker=invoker, clock=lambda: now,
        stop_grace_seconds=5, cancel=pool_rendezvous.PoolCancel(), max_parallel=max_parallel(len(groups)),
        wait_limit_seconds=spec["rendezvous_timeout_seconds"], drain_seconds=10)
    launched = pool_launcher.launch(spec, context=context, runtime=runtime)
    pool_root = context.pool_parent / launched.pool_directory
    verified = pool_rendezvous.load_verified_manifest(pool_root, expected_spec=spec, context=context,
                                                      rendezvous_parent=rendezvous)
    by_group = {cell["cell_id"].lower(): cell["cell_id"] for cell in inputs["cells"]}
    replies: dict[str, bytes] = {}
    for item in verified.instances:
        cell_id = by_group.get(item.instance.entry.get("group_id"))
        if cell_id is None or item.state != pool_rendezvous.SUCCEEDED or item.result is None:
            continue
        matches = [entry for entry in item.result["outputs"] if entry["path"] == CELL_FILE]
        path = item.instance.attempt_root_path(pool_root) / item.result["output_root"] / CELL_FILE
        if len(matches) == 1 and not path.is_symlink() and path.is_file() and "sha256:" + file_hash(path) == matches[0]["sha256"]:
            replies[cell_id] = path.read_bytes()
    pool = {"pool_directory": launched.pool_directory, "pool_outcome": launched.outcome,
            "instance_count": launched.instance_count, "expansion_sha256": launched.expansion_sha256,
            "terminal_manifest_sha256": launched.terminal_manifest_sha256, "max_parallel": max_parallel(len(groups))}
    return replies, pool


def replay(replies: dict[str, bytes]) -> Callable[[dict[str, Any]], Any]:
    """``invoke`` over retained replies: a cell without a verified reply raises ``CellFailed``."""
    def invoke(cell: dict[str, Any]) -> Any:
        data = replies.get(cell["cell_id"])
        if data is None:
            raise CellFailed(f"cell {cell['cell_id']} has no verified reply")
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None   # invalid_reply
    return invoke


def build_result(inputs: dict[str, Any], replies: dict[str, bytes]) -> dict[str, Any]:
    index = _open_index(inputs["run_id"], inputs)
    try:
        members = participate({"candidates": inputs["candidates"]}, inputs["config_value"], invoke=replay(replies),
                              source_root=Path(inputs["target_root"]), index=index)
    finally:
        index.close()
    return document(members, run_id=inputs["run_id"], source_snapshot_sha256=inputs["source_snapshot_sha256"],
                    candidate_search=inputs["candidate_search"], code_index=inputs["code_index"], config=inputs["config"])


def _retained(attempt: Path, inputs: dict[str, Any]) -> dict[str, bytes]:
    folder = attempt / "cells"
    return {cell["cell_id"]: (folder / f"{cell['cell_id']}.json").read_bytes() for cell in inputs["cells"]
            if (folder / f"{cell['cell_id']}.json").is_file() and not (folder / f"{cell['cell_id']}.json").is_symlink()}


def _receipts(inputs: dict[str, Any], result: dict[str, Any], pool: dict[str, Any]) -> tuple[dict, dict, dict]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
                  "source_snapshot_sha256": inputs["source_snapshot_sha256"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "source_snapshot_sha256": inputs["source_snapshot_sha256"],
               "build_lineage_sha256": "sha256:" + digest({"candidate_search": inputs["candidate_search"],
                                                          "code_index": inputs["code_index"], "config": inputs["config"],
                                                          "pool": pool, "cells": [c["reply_sha256"] for c in result["cells"]]})}
    receipt = {"schema": "appsec-review/owasp-participation-pool-receipt/1.0", "run_id": inputs["run_id"], **pool,
               "planned_calls": result["budget"]["planned_calls"]}
    return permission, lineage, receipt


def _validate_attempt(attempt: Path, inputs: dict[str, Any], *, reprepare: bool = True) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if reprepare and prepare(inputs["run_id"]) != inputs:
        raise Blocked(f"{JOB}: accepted upstreams, config or the checkout changed")
    result = read_json(attempt / RESULT)
    if result != build_result(inputs, _retained(attempt, inputs)):
        raise Blocked(f"{JOB}: result differs from the retained cell replies and the checkout")
    pool = {key: value for key, value in read_json(attempt / "pool-receipt.json").items()
            if key not in {"schema", "run_id", "planned_calls"}}
    expected = _receipts(inputs, result, pool)
    if (read_json(attempt / "permission.json"), read_json(attempt / "lineage.json"),
            read_json(attempt / "pool-receipt.json")) != expected:
        raise Blocked(f"{JOB}: retained receipts changed")


def run(run_id: str, dagster_run_id: str, force: bool = False, *, invoker: Any = None) -> dict[str, Any]:
    """Plan and budget-check, dispatch the cell pool, publish the validated participation."""
    import review_cli
    from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        pool = {"pool_directory": None, "pool_outcome": "EMPTY", "instance_count": 0, "expansion_sha256": None,
                "terminal_manifest_sha256": None, "max_parallel": 0}
        replies: dict[str, bytes] = {}
        if inputs["cells"]:
            effort = review_cli.resolve_model(CELL_TEMPLATE, "standard").get("effort") or "high"
            replies, pool = run_pool(inputs, attempt, invoker or ParticipationInvoker(effort=effort, budget_usd=_budget_usd()))
        for cell_id, data in sorted(replies.items()):
            atomic_bytes(attempt / "cells" / f"{cell_id}.json", data)
        result = build_result(inputs, replies)
        atomic_json(attempt / RESULT, result)
        atomic_bytes(attempt / SUMMARY, summary(result).encode("utf-8"))
        permission, lineage, receipt = _receipts(inputs, result, pool)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "pool-receipt.json", receipt)
        gaps = [f"{gap['kind']}: {gap['statement']}" for gap in result["gaps"]]
        status = {"process": JOB, "status": result["status"], "result": RESULT,
                  "planned_calls": result["budget"]["planned_calls"], "records": len(result["records"]),
                  "unclassified": len(result["unclassified"]), "gaps": len(result["gaps"])}
        artifacts = [RESULT, SUMMARY, "permission.json", "lineage.json", "pool-receipt.json", "status.json"]
        artifacts += [f"cells/{cell_id}.json" for cell_id in sorted(replies)]
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
            worker_kind="pool_coordinator", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Classified {len(result['records'])} ASVS candidate(s) in {len(result['cells'])} cell(s); "
                    f"{len(result['unclassified'])} unclassified.",
            status_record=status, artifact_paths=artifacts, gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs, reprepare=False))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
        worker_kind="pool_coordinator", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/owasp_participation.py --run-id {run_id}",
        derive_inputs=lambda: prepare(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Accepted candidate search, code index, config or checkout were not current, or the plan is over budget.",
        failed_summary="Participation pool did not publish a validated result.")


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-owasp-participation")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--plan-only", action="store_true", help="print the cell plan and budget; no model call")
    args = parser.parse_args(argv)
    if args.plan_only:
        inputs = prepare(args.run_id)
        print(json.dumps({"budget": inputs["budget"], "cells": [{"cell_id": c["cell_id"], "candidates": len(c["candidates"])}
                                                                  for c in inputs["cells"]]}, indent=2))
    else:
        result = run(args.run_id, args.dagster_run_id, args.force)
        print(json.dumps({key: result.get(key) for key in ("attempt_id", "status")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
