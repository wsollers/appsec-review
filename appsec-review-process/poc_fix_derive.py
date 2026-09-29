#!/usr/bin/env python3
"""Derive step for the lane-12b ``poc-fix-author`` cell (persona reply -> strict PoC-and-fix record).

The persona sees one request workspace (``poc-fix-workspace``, readable input 0): one independently
verified, Critical, REACHABLE finding with its locations, reachability witness, hash-verified
snippets and the files and line windows it may cite. It supplies judgment only
(``poc-fix-persona.schema.json``): a light static PoC (or why none), a plain-language source-to-sink
explanation, the lines it relies on (path and line range) and a proposed fix as a unified diff.

This module keeps the books (ADR-0013):

* size caps beyond the schema (PoC and diff line counts, cited span length); an overrun goes back
  to the model through the invoker's bounded repair loop;
* citations: every cited path must be a workspace ``citable`` file and every range must sit inside
  one of its windows; Python attaches the pinned ``source_sha256`` and its basis. At least one
  cited range overlaps a finding location. A path, range or hash the workspace does not name is a
  repair error, never published;
* the fix diff may only touch citable files (``---``/``+++`` headers) and must carry a hunk;
* the denylist (:mod:`poc_fix_denylist`) over the PoC text and trigger, the lines the fix adds, and
  (prose rules) the explanation and rationale. A hit is **not** repaired: the part is withheld, its
  rule ids, lines and hash are recorded, and the job records a gap. Re-asking would teach the model
  to write around the filter;
* ids, labels (``UNVALIDATED``, ``PATCH_PROPOSED_UNVALIDATED``) and the claim limits.

Nothing here executes, compiles or applies anything.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import contract_derive
import poc_fix_denylist as denylist
from claude_cli_invoker import InvokerOutputError
from execution_state import digest
from schema_validate import SchemaStore, validate_document

PERSONA_SCHEMA = "poc-fix-persona.schema.json"
RECORD_SCHEMA = "poc-fix-record.schema.json"
CANDIDATES_SCHEMA = "poc-fix-candidates.schema.json"
WORKSPACE_SCHEMA = "poc-fix-workspace.schema.json"
WORKSPACE_SCHEMA_ID = "appsec-review/poc-fix-workspace/1.0"
WORKSPACE_ROOT_ID = "poc-fix-workspace"
BOUNDS = {"poc_chars": 2400, "poc_lines": 40, "explanation_chars": 2000, "fix_chars": 6000, "fix_lines": 80,
          "cited_lines_max": 8, "span_lines_max": 40}
CLAIM_LIMITS = {"executed": False, "validated": False, "target_modified": False, "fixed_claimed": False,
                "hostile_content_permitted": False}
# Every field the record declares where the persona schema does not (ADR-0013: Python derives it). An
# echo at any of the reply, poc, fix or cited_lines positions is dropped with a note, never repaired.
_ORCHESTRATOR_KEYS = contract_derive.orchestrator_keys(RECORD_SCHEMA, PERSONA_SCHEMA)
_PROMOTION_KEYS = {"severity", "cvss", "cvss_score", "priority", "verified", "validated", "finding", "fixed"}
_DIFF_FILE = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)")


def _sha_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_workspace(data: bytes) -> dict[str, Any]:
    try:
        workspace = json.loads(data)
    except ValueError as exc:
        raise InvokerOutputError("poc-fix workspace (readable input 0) is not JSON") from exc
    if not isinstance(workspace, dict) or workspace.get("schema") != WORKSPACE_SCHEMA_ID:
        raise InvokerOutputError("poc-fix workspace (readable input 0) is not a poc-fix workspace")
    return workspace


def workspace_bytes(workspace: dict[str, Any]) -> bytes:
    return (json.dumps(workspace, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("utf-8")


def _strip(row: Any, where: str, notes: list[str]) -> Any:
    if not isinstance(row, dict):
        return row
    out = {}
    for key, value in row.items():
        if key in _ORCHESTRATOR_KEYS:
            notes.append(f"{where}: ignored orchestrator field {key!r}; Python derives it")
            continue
        if key in _PROMOTION_KEYS:
            notes.append(f"{where}: ignored {key!r}; a PoC-and-fix record is unvalidated and rates nothing")
            continue
        out[key] = value
    return out


def normalize(reply: Any) -> tuple[Any, list[str]]:
    """Accept the persona shape and the wrappers models send (a one-item list); drop bookkeeping keys."""
    notes: list[str] = []
    value = reply
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, dict):
        return value, notes
    value = _strip(value, "reply", notes)
    for key in ("poc", "fix"):
        if key in value:
            value[key] = _strip(value[key], key, notes)
    if isinstance(value.get("cited_lines"), list):
        value["cited_lines"] = [_strip(row, f"cited_lines[{n}]", notes) for n, row in enumerate(value["cited_lines"])]
        for row in value["cited_lines"]:
            if isinstance(row, dict) and "end_line" not in row and isinstance(row.get("start_line"), int):
                row["end_line"] = row["start_line"]
    value.setdefault("no_poc_reason", None)
    return value, notes


def _overlaps(start: int, end: int, lo: int, hi: int) -> bool:
    return start <= hi and lo <= end


def check_citations(workspace: dict[str, Any], cited: list[dict[str, Any]], errors: list[str]) -> list[dict[str, Any]]:
    """Resolve model citations against the workspace; returns canonical citations (hash attached)."""
    citable = {row["path"]: row for row in workspace["citable"]}
    span_max = workspace["bounds"]["span_lines_max"]
    result: dict[tuple[str, int, int], dict[str, Any]] = {}
    for index, row in enumerate(cited):
        where = f"cited_lines[{index}]"
        path, start, end = row["path"], row["start_line"], row["end_line"]
        if path not in citable:
            errors.append(f"{where}: {path!r} is not a citable workspace file (citable: "
                          f"{', '.join(sorted(citable))[:300]})")
            continue
        if end < start:
            errors.append(f"{where}: end_line {end} is before start_line {start}")
            continue
        if end - start + 1 > span_max:
            errors.append(f"{where}: cites {end - start + 1} lines; at most {span_max} per range (span_lines_max)")
            continue
        entry = citable[path]
        if not any(window["start"] <= start and end <= window["end"] for window in entry["windows"]):
            windows = ", ".join(f"{w['start']}-{w['end']}" for w in entry["windows"])
            errors.append(f"{where}: {path}:{start}-{end} is outside the citable windows of that file ({windows})")
            continue
        key = (path, start, end)
        if key in result and result[key]["role"] != row["role"]:
            errors.append(f"{where}: {path}:{start}-{end} is cited twice with different roles")
            continue
        result[key] = {"path": path, "start_line": start, "end_line": end, "role": row["role"],
                       "source_sha256": entry["source_sha256"], "hash_basis": entry["hash_basis"]}
    citations = [result[key] for key in sorted(result)]
    if citations and not any(_overlaps(c["start_line"], c["end_line"], loc["line"], loc["end_line"])
                             for c in citations for loc in workspace["locations"] if loc["path"] == c["path"]):
        errors.append("cite at least one range that covers a finding location (the sink): " +
                      ", ".join(f"{loc['path']}:{loc['line']}" for loc in workspace["locations"])[:300])
    return citations


def diff_files(diff: str) -> list[str]:
    """Files a unified diff names in its ``---``/``+++`` headers (``/dev/null`` kept as is)."""
    return sorted({match.group(1) for line in str(diff).splitlines() for match in [_DIFF_FILE.match(line)] if match})


def _check_fix(workspace: dict[str, Any], fix: dict[str, Any], errors: list[str]) -> list[str]:
    bounds = workspace["bounds"]
    diff = fix["diff"]
    if len(diff) > bounds["fix_chars"] or len(diff.splitlines()) > bounds["fix_lines"]:
        errors.append(f"fix.diff: at most {bounds['fix_lines']} lines / {bounds['fix_chars']} characters")
    files = diff_files(diff)
    citable = {row["path"] for row in workspace["citable"]}
    if not files:
        errors.append("fix.diff: a unified diff with '--- a/<path>' and '+++ b/<path>' headers is required")
    for name in files:
        if name not in citable:
            errors.append(f"fix.diff: {name!r} is not a citable workspace file; a fix only changes the cited code")
    if not any(line.startswith("@@") for line in diff.splitlines()):
        errors.append("fix.diff: carries no '@@' hunk")
    return files


def _hits(text: str | None, field: str, rules: tuple[str, ...]) -> list[dict[str, Any]]:
    return [{**hit, "field": field} for hit in denylist.scan(text, rules)]


def derive(workspace: dict[str, Any], reply: Any, *, author: dict[str, Any],
           store: SchemaStore | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return (record, limitations) or raise InvokerOutputError (repairable mechanics only)."""
    store = store or SchemaStore()
    value, notes = normalize(reply)
    errors = [f"reply: {error}" for error in validate_document(value, PERSONA_SCHEMA, store)]
    if errors:
        raise InvokerOutputError(f"poc-fix reply fails {PERSONA_SCHEMA}: {len(errors)} error(s)", errors[:40])
    bounds = workspace["bounds"]
    poc, fix = value["poc"], value["fix"]
    if poc is None and not (isinstance(value["no_poc_reason"], str) and value["no_poc_reason"].strip()):
        errors.append("poc is null: give a no_poc_reason")
    if poc is not None:
        if len(poc["text"]) > bounds["poc_chars"] or len(poc["text"].splitlines()) > bounds["poc_lines"]:
            errors.append(f"poc.text: at most {bounds['poc_lines']} lines / {bounds['poc_chars']} characters; "
                          "a light PoC is a minimal input, call or short test")
    if len(value["explanation"]) > bounds["explanation_chars"]:
        errors.append(f"explanation: at most {bounds['explanation_chars']} characters")
    if len(value["cited_lines"]) > bounds["cited_lines_max"]:
        errors.append(f"cited_lines: at most {bounds['cited_lines_max']} ranges")
    citations = check_citations(workspace, value["cited_lines"], errors)
    files = _check_fix(workspace, fix, errors)
    if errors:
        raise InvokerOutputError(f"poc-fix reply does not resolve against the workspace: {len(errors)} error(s)", errors)

    poc_hits = (_hits(poc["text"], "poc.text", denylist.FULL) +
                _hits(poc["trigger_condition"], "poc.trigger_condition", denylist.FULL)) if poc else []
    prose_hits = _hits(value["explanation"], "explanation", denylist.PROSE)
    fix_hits = (_hits(denylist.added_lines(fix["diff"]), "fix.diff", denylist.FULL) +
                _hits(fix["rationale"], "fix.rationale", denylist.PROSE))
    if poc is None:
        poc_record = {"status": "NOT_PROVIDED", "kind": None, "language": None, "text": None,
                      "expected_effect": None, "trigger_condition": None, "text_sha256": None,
                      "reason": " ".join(value["no_poc_reason"].split())[:500], "denylist_hits": []}
    elif poc_hits:
        poc_record = {"status": "REJECTED_DENYLIST", "kind": poc["kind"], "language": poc["language"], "text": None,
                      "expected_effect": poc["expected_effect"], "trigger_condition": None,
                      "text_sha256": _sha_text(poc["text"]),
                      "reason": "withheld: the PoC text matched the lane-12b denylist ("
                                + ", ".join(sorted({hit["rule"] for hit in poc_hits})) + ")",
                      "denylist_hits": poc_hits}
    else:
        poc_record = {"status": "PROPOSED_UNVALIDATED", "kind": poc["kind"], "language": poc["language"],
                      "text": poc["text"], "expected_effect": poc["expected_effect"],
                      "trigger_condition": poc["trigger_condition"], "text_sha256": _sha_text(poc["text"]),
                      "reason": None, "denylist_hits": []}
    fix_record = {"status": "REJECTED_DENYLIST" if fix_hits else "PATCH_PROPOSED_UNVALIDATED",
                  "diff": None if fix_hits else fix["diff"], "rationale": None if fix_hits else fix["rationale"],
                  "files": files, "diff_sha256": _sha_text(fix["diff"]), "denylist_hits": fix_hits}
    record = {"request_id": workspace["request_id"], "claim_id": workspace["claim_id"], "label": "UNVALIDATED",
              "poc": poc_record, "explanation": None if prose_hits else value["explanation"],
              "explanation_status": "REJECTED_DENYLIST" if prose_hits else "ACCEPTED",
              "cited_lines": citations, "fix": fix_record, "author": author, "claim_limits": dict(CLAIM_LIMITS)}
    if prose_hits:
        record["poc"]["denylist_hits"] = record["poc"]["denylist_hits"] + prose_hits
    record = {"poc_fix_id": "pocfix-" + digest({key: record[key] for key in
                                                ("request_id", "claim_id", "poc", "cited_lines", "fix")})[:24],
              **record}
    problems = validate_document(record, RECORD_SCHEMA, store)
    if problems:   # a derive bug, never silent
        raise InvokerOutputError(f"derived record fails {RECORD_SCHEMA}", [problems[0]])
    return record, [note[:500] for note in dict.fromkeys(notes)]


def rejected_parts(record: dict[str, Any]) -> list[str]:
    """Human-readable gap details for every withheld part of a record."""
    parts = []
    for status, field, label in ((record["poc"]["status"], ("poc.text", "poc.trigger_condition"), "PoC text"),
                                 (record["explanation_status"], ("explanation",), "explanation")):
        if status == "REJECTED_DENYLIST":
            rules = sorted({hit["rule"] for hit in record["poc"]["denylist_hits"] if hit["field"] in field})
            parts.append(f"{label} withheld by the denylist ({', '.join(rules)})")
    if record["fix"]["status"] == "REJECTED_DENYLIST":
        rules = sorted({hit["rule"] for hit in record["fix"]["denylist_hits"]})
        parts.append(f"proposed fix withheld by the denylist ({', '.join(rules)})")
    return parts


def recheck(record: dict[str, Any], workspace: dict[str, Any]) -> list[str]:
    """Publication-time re-verification of a retained record (defence in depth); returns problems."""
    problems = [f"record: {error}" for error in validate_document(record, RECORD_SCHEMA)]
    if problems:
        return problems
    if (record["request_id"], record["claim_id"]) != (workspace["request_id"], workspace["claim_id"]):
        return ["record names another request or claim"]
    errors: list[str] = []
    cited = [{key: row[key] for key in ("path", "start_line", "end_line", "role")} for row in record["cited_lines"]]
    if check_citations(workspace, cited, errors) != record["cited_lines"]:
        errors.append("cited lines or their pinned hashes differ from the workspace")
    for text, field, rules in ((record["poc"]["text"], "poc.text", denylist.FULL),
                               (record["poc"]["trigger_condition"], "poc.trigger_condition", denylist.FULL),
                               (record["explanation"], "explanation", denylist.PROSE),
                               (denylist.added_lines(record["fix"]["diff"] or ""), "fix.diff", denylist.FULL),
                               (record["fix"]["rationale"], "fix.rationale", denylist.PROSE)):
        if denylist.scan(text, rules):
            errors.append(f"{field} carries denylisted material")
    if record["poc"]["text"] is not None and record["poc"]["text_sha256"] != _sha_text(record["poc"]["text"]):
        errors.append("poc.text hash differs")
    if record["fix"]["diff"] is not None and record["fix"]["diff_sha256"] != _sha_text(record["fix"]["diff"]):
        errors.append("fix.diff hash differs")
    expected = "pocfix-" + digest({key: record[key] for key in ("request_id", "claim_id", "poc", "cited_lines", "fix")})[:24]
    if record["poc_fix_id"] != expected:
        errors.append("poc_fix_id is not derived from the record")
    return errors


def candidates(record: dict[str, Any], evidence_sha256: str) -> dict[str, Any]:
    """The invoker's strict candidates document: exactly one candidate, the record."""
    return {"candidates": [{"candidate_id": record["poc_fix_id"], "subject_id": record["request_id"],
                            "assertion": json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                            "evidence_sha256": evidence_sha256, "claim_class": "candidate_only"}]}


def poc_fix_claims(value: dict[str, Any], inputs: tuple, allowed: tuple, result_filename: str) -> list[dict[str, Any]]:
    """Invoker claim builder: one candidate_only claim per candidate, cited to the workspace bytes."""
    if "candidate_only" not in allowed:
        raise InvokerOutputError("poc-fix candidates exceed the invocation claim ceiling")
    workspace = next((item for item in inputs if item.root == WORKSPACE_ROOT_ID), None)
    if workspace is None:
        raise InvokerOutputError("poc-fix cell has no workspace input")
    return [{"claim_id": row["candidate_id"], "claim_class": "candidate_only",
             "statement": f"unvalidated PoC-and-fix candidate {row['candidate_id']} for {row['subject_id']}"[:300],
             "file": result_filename,
             "citations": [{"root": workspace.root, "path": workspace.path, "sha256": workspace.sha256,
                            "locator": row["subject_id"]}]} for row in value["candidates"]]
