#!/usr/bin/env python3
"""Derive step for the 07-hypothesis-discovery hunter pool (persona reply -> strict candidates).

A hunter persona supplies judgment only (``hypothesis-hunt-persona.schema.json``): per hypothesis a
target path and line range, the vulnerability class (CWE when it can name one), attacker
preconditions, the evidence it read and a confidence.  This module owns the bookkeeping:

* the hunter identity (mode, persona, shard) from the trusted brief (readable input 0);
* path normalization and resolution against the exact pinned target bytes of this call: a path
  outside the checkout (absolute, ``..``, unknown) or a line past the end of the file is kept as a
  ``dropped`` record with the reason -- never repaired into a different location, never invented;
  a path that is not pinned in this call (the hunter found it through the evidence index) is kept
  with ``location_check: deferred`` and resolved against the checkout after the pool;
* evidence refs classified against the pinned inputs; the hypothesis location is always evidence;
* ids: ``subject_id`` from the location identity, ``candidate_id`` from the canonical record;
* the per-instance hypothesis limit (excess items become ``dropped`` records, in reply order).

A reply that is not the persona shape is sent back to the model through the invoker's bounded
repair loop.  Orchestrator-owned keys the model echoes out of habit are ignored; promotion keys
(severity, cvss, ...) are dropped and reported.  Free text is not parsed for grammar (ADR-0013):
the claim ledger keeps model words out of its own text when they would trip its promotion guard.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

import contract_derive
from claude_cli_invoker import InvokerOutputError
from execution_state import digest
from schema_validate import SchemaStore, validate_document

PERSONA_SCHEMA = "hypothesis-hunt-persona.schema.json"
CANDIDATES_SCHEMA = "hypothesis-hunt-candidates.schema.json"
RECORD_SCHEMA = "hunter-hypothesis.schema.json"
BRIEF_SCHEMA_ID = "appsec-review/hypothesis-hunt-brief/1.0"
BRIEF_ROOT_ID = "hunt-brief"
TARGET_ROOT_ID = "target-repository"    # persona_dispatch.DEFAULT_READABLE_ROOT
# Readable root ids a hunter may cite as 'root:path' (hunt brief, guides, evidence menu and its files).
KNOWN_ROOTS = frozenset({BRIEF_ROOT_ID, "hunt-guides", "evidence-menu", "supporting-evidence", "upstream-artifacts"})
MODES = {"general": "general-red-team-hunter", "known-list": "known-list-red-team-hunter"}
CONFIDENCE = ("low", "medium", "high")
MECHANISM_CHARS = 2000
TEXT_CHARS = 400
EVIDENCE_MAX = 16
PRECONDITIONS_MAX = 8

# Bookkeeping a hunter copies from the brief or the candidate wrapper; no schema position names it.
_ECHO_KEYS = frozenset({"hypothesis_id", "id", "candidate_id", "subject_id", "claim_class", "sha256",
                        "evidence_sha256", "assertion", "shard_id", "persona_id", "mode", "worker_id",
                        "worker_ids", "tier", "status"})
# Plus every field the record declares where the persona schema does not (ADR-0013: Python derives it).
_ORCHESTRATOR_KEYS = _ECHO_KEYS | contract_derive.orchestrator_keys(
    RECORD_SCHEMA, PERSONA_SCHEMA, (("hypotheses", "[]"), ()))
_PROMOTION_KEYS = {"severity", "cvss", "cvss_score", "finding", "verified", "risk", "risk_rating",
                   "exploitability_score", "priority"}
_ALIASES = {"file": "path", "file_path": "path", "filename": "path", "location_path": "path",
            "line": "start_line", "start": "start_line", "line_start": "start_line",
            "end": "end_line", "line_end": "end_line",
            "class": "vulnerability_class", "vulnerability": "vulnerability_class",
            "vulnerability_type": "vulnerability_class", "weakness": "vulnerability_class",
            "type": "vulnerability_class", "title": "vulnerability_class",
            "preconditions": "attacker_preconditions", "attacker_precondition": "attacker_preconditions",
            "description": "mechanism", "rationale": "mechanism", "reasoning": "mechanism",
            "explanation": "mechanism", "evidence_read": "evidence", "citations": "evidence",
            "references": "evidence", "component": "component_id"}
_LIST_ALIASES = ("hypotheses", "findings", "vulnerabilities", "candidates", "results")
_CWE_RE = re.compile(r"CWE[-_ ]?(\d{1,5})", re.IGNORECASE)
_LOC_RE = re.compile(r"^(?P<path>.+?):(?P<start>\d+)(?:\s*[-:]\s*L?(?P<end>\d+))?$")
_RANGE_RE = re.compile(r"^\s*L?(\d+)\s*(?:[-:]\s*L?(\d+))?\s*$")


def normalize_path(value: Any, known: Iterable[str] = ()) -> tuple[str | None, str | None]:
    """(repository-relative posix path, None) or (None, reason). Suffix-maps an absolute path onto
    exactly one known pinned path; never guesses between several."""
    if not isinstance(value, str) or not value.strip():
        return None, "path is empty"
    text = value.strip().replace("\\", "/")
    for prefix in (TARGET_ROOT_ID + ":", "target:", "repo:"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    while text.startswith("./"):
        text = text[2:]
    known = list(known)
    if text.startswith("/") or re.match(r"^[A-Za-z]:/", text):
        matches = [path for path in known if text.endswith("/" + path)]
        if len(matches) == 1:
            return matches[0], None
        return None, "absolute path outside the pinned checkout"
    parts = text.split("/")
    if any(part in {"", ".", ".."} for part in parts) or parts[0] == ".git":
        return None, "path is not a canonical repository-relative path"
    return text, None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("L").isdigit():
        return int(value.strip().lstrip("L"))
    return None


def _cwe(value: Any, notes: list[str], where: str) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return f"CWE-{value}"
    if isinstance(value, str):
        match = _CWE_RE.search(value)
        if match:
            return f"CWE-{int(match.group(1))}"
        if value.strip().isdigit():
            return f"CWE-{int(value.strip())}"
    notes.append(f"{where}: cwe {str(value)[:60]!r} is not a CWE id; recorded as null")
    return None


def _evidence_strings(value: Any) -> list[Any]:
    rows = value if isinstance(value, list) else ([value] if value not in (None, "") else [])
    out: list[Any] = []
    for row in rows:
        if isinstance(row, dict):
            ref = row.get("ref") or row.get("path") or row.get("file")
            line = _int(row.get("start_line", row.get("line")))
            end = _int(row.get("end_line"))
            if isinstance(ref, str) and line is not None:
                ref = f"{ref}:{line}" + (f"-{end}" if end and end != line else "")
            out.append(ref if isinstance(ref, str) else row)
        else:
            out.append(row)
    return out


def _normalize_item(row: Any, index: int, notes: list[str]) -> Any:
    if not isinstance(row, dict):
        return row
    where = f"hypotheses[{index}]"
    item: dict[str, Any] = {}
    for key, value in row.items():
        if key in _ORCHESTRATOR_KEYS:
            continue
        if key in _PROMOTION_KEYS:
            notes.append(f"{where}: ignored {key!r}; hunters propose candidates, they do not rate them")
            continue
        canonical = _ALIASES.get(key, key)
        if canonical in item and canonical != key:
            continue
        item[canonical] = value
    for alias, canonical in _ALIASES.items():   # a canonical key always wins over its alias
        if canonical in row and alias in row:
            item[canonical] = row[canonical]
    if "lines" in item:
        lines = item.pop("lines")
        if isinstance(lines, list) and lines and all(_int(x) is not None for x in lines):
            item.setdefault("start_line", _int(lines[0])); item.setdefault("end_line", _int(lines[-1]))
        elif isinstance(lines, (str, int)):
            match = _RANGE_RE.match(str(lines))
            if match:
                item.setdefault("start_line", int(match.group(1)))
                if match.group(2):
                    item.setdefault("end_line", int(match.group(2)))
    for key in ("location", "path"):
        text = item.get(key)
        if isinstance(text, str) and "start_line" not in item:
            match = _LOC_RE.match(text.strip())
            if match:
                item["path"] = match.group("path")
                item["start_line"] = int(match.group("start"))
                if match.group("end"):
                    item.setdefault("end_line", int(match.group("end")))
    item.pop("location", None)
    for key in ("start_line", "end_line"):
        if key in item and _int(item[key]) is not None:
            item[key] = _int(item[key])
    if "end_line" in item and item["end_line"] is None:
        item.pop("end_line")
    if "cwe" in item:
        item["cwe"] = _cwe(item["cwe"], notes, where)
    if isinstance(item.get("confidence"), str):
        value = item["confidence"].strip().lower()
        item["confidence"] = {"moderate": "medium", "med": "medium"}.get(value, value)
    if isinstance(item.get("attacker_preconditions"), str):
        item["attacker_preconditions"] = [item["attacker_preconditions"]]
    if "evidence" in item:
        item["evidence"] = _evidence_strings(item["evidence"])
    elif "path" in item:
        item["evidence"] = []
    return item


def normalize(reply: Any) -> tuple[Any, list[str]]:
    """Accept the persona reply and the shapes models actually send; return the persona shape."""
    notes: list[str] = []
    value = reply
    if isinstance(value, dict) and isinstance(value.get("candidates"), dict):
        value = value["candidates"]
    if isinstance(value, list):
        value = {"hypotheses": value}
    if isinstance(value, dict) and "hypotheses" not in value:
        for key in _LIST_ALIASES:
            if isinstance(value.get(key), list):
                value = {**{k: v for k, v in value.items() if k != key}, "hypotheses": value[key]}
                break
    if not isinstance(value, dict) or not isinstance(value.get("hypotheses"), list):
        return value, notes
    kept = {key: item for key, item in value.items() if key in {"hypotheses", "coverage_notes"}}
    for key in sorted(set(value) - set(kept)):
        notes.append(f"ignored top-level key {key!r}")
    kept["hypotheses"] = [_normalize_item(row, index, notes) for index, row in enumerate(value["hypotheses"])]
    if isinstance(kept.get("coverage_notes"), str):
        kept["coverage_notes"] = [kept["coverage_notes"]]
    return kept, notes


def read_brief(data: bytes) -> dict[str, Any]:
    try:
        brief = json.loads(data)
    except ValueError as exc:
        raise InvokerOutputError("hunter brief (readable input 0) is not JSON") from exc
    if not isinstance(brief, dict) or brief.get("schema") != BRIEF_SCHEMA_ID or brief.get("mode") not in MODES:
        raise InvokerOutputError("hunter brief (readable input 0) is not a hypothesis-hunt brief")
    return brief


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def class_key(record: dict[str, Any]) -> str:
    return record["cwe"] or re.sub(r"[^a-z0-9]+", "-", record["vulnerability_class"].lower()).strip("-")[:80]


def subject_id(path: str, start: int | None, key: str) -> str:
    return "hyp-" + digest({"path": path, "start_line": start, "class": key})[:24]


def _line_count(data: bytes) -> int:
    return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)


class _Pinned:
    """The exact pinned bytes of this call, by (root, path)."""

    def __init__(self, inputs: Iterable[Any]) -> None:
        self.items = {(item.root, item.path): item for item in inputs}
        self.targets = {path: item for (root, path), item in self.items.items() if root == TARGET_ROOT_ID}
        self.lines = {path: _line_count(item.data) for path, item in self.targets.items()}


def _evidence(ref: Any, pinned: _Pinned) -> dict[str, Any]:
    text = _clip(ref, 600) if isinstance(ref, str) else _clip(json.dumps(ref, sort_keys=True), 600)
    row = {"ref": text, "kind": "unresolved", "root": None, "path": None, "start_line": None, "end_line": None}
    if not isinstance(ref, str):
        return row
    body, start, end = text.strip(), None, None
    match = _LOC_RE.match(body)
    if match:
        body, start = match.group("path"), int(match.group("start"))
        end = int(match.group("end")) if match.group("end") else start
    root, sep, rest = body.partition(":")
    if sep and root != TARGET_ROOT_ID and (root in KNOWN_ROOTS or any(key[0] == root for key in pinned.items)):
        if (root, rest) in pinned.items:
            row.update(kind="pinned-input", root=root, path=rest, start_line=start, end_line=end)
        return row
    path, reason = normalize_path(body, pinned.targets)
    if path is None:
        return row
    if path in pinned.targets:
        if start is not None and not (1 <= start <= pinned.lines[path] and start <= (end or start)):
            return row
        row.update(kind="target-range", root=TARGET_ROOT_ID, path=path, start_line=start,
                   end_line=min(end, pinned.lines[path]) if end is not None else None)
    else:
        row.update(kind="target-deferred", root=TARGET_ROOT_ID, path=path, start_line=start, end_line=end)
    return row


def derive(brief: dict[str, Any], reply: Any, inputs: Iterable[Any], *, brief_sha256: str,
           store: SchemaStore | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return (hypothesis-hunt-candidates document, limitations) or raise InvokerOutputError."""
    store = store or SchemaStore()
    value, notes = normalize(reply)
    errors = [f"reply: {error}" for error in validate_document(value, PERSONA_SCHEMA, store)]
    if errors:
        raise InvokerOutputError(f"hunter reply fails {PERSONA_SCHEMA}: {len(errors)} error(s)", errors[:40])
    limits = brief.get("limits") or {}
    max_items = int(limits.get("max_hypotheses", 20))
    max_span = int(limits.get("max_line_span", 80))
    hunter = {"mode": brief["mode"], "persona_id": MODES[brief["mode"]], "shard_id": str(brief["shard_id"])}
    pinned = _Pinned(inputs)
    records: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(value["hypotheses"]):
        where = f"hypotheses[{index}]"
        mechanism = row["mechanism"]
        if len(" ".join(mechanism.split())) > MECHANISM_CHARS:
            notes.append(f"{where}: mechanism clipped to {MECHANISM_CHARS} characters")
        record = {"kind": "hypothesis", "hunter": hunter, "path": _clip(row["path"], 1024),
                  "start_line": row["start_line"], "end_line": row.get("end_line", row["start_line"]),
                  "file_sha256": None, "vulnerability_class": _clip(row["vulnerability_class"], 200),
                  "cwe": row.get("cwe"), "mechanism": _clip(mechanism, MECHANISM_CHARS),
                  "attacker_preconditions": [_clip(item, TEXT_CHARS) for item in
                                             row["attacker_preconditions"][:PRECONDITIONS_MAX]],
                  "confidence": row["confidence"], "evidence": [],
                  "component_id": _clip(row["component_id"], 200) if row.get("component_id") else None,
                  "location_check": "deferred", "drop_reason": None}
        path, reason = normalize_path(row["path"], pinned.targets)
        start, end = record["start_line"], record["end_line"]
        if path is None:
            record.update(kind="dropped", location_check="rejected", drop_reason=reason)
        elif start < 1:
            record.update(path=path, kind="dropped", location_check="rejected", drop_reason="start_line < 1")
        else:
            record["path"] = path
            if end < start:
                notes.append(f"{where}: end_line {end} before start_line {start}; used a single line")
                end = record["end_line"] = start
            if end - start > max_span:
                record.update(kind="dropped", location_check="rejected",
                              drop_reason=f"line range wider than {max_span} lines; name the construct")
            elif path in pinned.targets:
                lines = pinned.lines[path]
                if start > lines:
                    record.update(kind="dropped", location_check="rejected",
                                  drop_reason=f"start_line {start} is past the end of the file ({lines} lines)")
                else:
                    if end > lines:
                        notes.append(f"{where}: end_line {end} clipped to the file's {lines} lines")
                        record["end_line"] = lines
                    record.update(location_check="pinned", file_sha256=pinned.targets[path].sha256)
        if index >= max_items and record["kind"] == "hypothesis":
            record.update(kind="dropped", drop_reason=f"over the per-instance limit of {max_items} hypotheses")
        if record["kind"] == "hypothesis":
            location = f"{record['path']}:{record['start_line']}" + (
                f"-{record['end_line']}" if record["end_line"] != record["start_line"] else "")
            evidence, seen = [], set()
            for ref in [location, *row["evidence"][:EVIDENCE_MAX]]:
                item = _evidence(ref, pinned)
                identity = (item["kind"], item["root"], item["path"], item["start_line"], item["end_line"],
                            item["ref"] if item["kind"] == "unresolved" else None)
                if identity not in seen:
                    seen.add(identity); evidence.append(item)
            record["evidence"] = evidence
            dropped = sum(1 for item in evidence if item["kind"] == "unresolved")
            if dropped:
                notes.append(f"{where}: {dropped} evidence ref(s) do not resolve to a pinned input; kept as unresolved")
        errors_record = validate_document(record, RECORD_SCHEMA, store)
        if errors_record:   # derive bug or a model value the persona schema allowed; never silent
            raise InvokerOutputError("derived hunter record fails its schema", errors_record[:10])
        key = class_key(record)
        subject = subject_id(record["path"], record["start_line"], key)
        candidate = "hunt-" + digest(record)[:24]
        if candidate in records:
            notes.append(f"{where}: identical duplicate of an earlier hypothesis collapsed")
            continue
        records[candidate] = {"candidate_id": candidate, "subject_id": subject,
            "assertion": json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            "evidence_sha256": record["file_sha256"] or brief_sha256, "claim_class": "candidate_only"}
    document = {"candidates": [records[key] for key in sorted(records)]}
    problems = validate_document(document, CANDIDATES_SCHEMA, store)
    if problems:
        raise InvokerOutputError("derived hunter candidates fail their schema", problems[:10])
    return document, [note[:500] for note in dict.fromkeys(notes)]


def hunt_claims(value: dict[str, Any], inputs: tuple, allowed: tuple, result_filename: str) -> list[dict[str, Any]]:
    """Invoker claim builder: one candidate_only claim per candidate, cited to the target file bytes
    this call pinned (or to the brief for a dropped / deferred record)."""
    if "candidate_only" not in allowed:
        raise InvokerOutputError("hunter candidates exceed the invocation claim ceiling")
    pinned = {(item.root, item.path): item for item in inputs}
    brief = next((item for item in inputs if item.root == BRIEF_ROOT_ID), inputs[0] if inputs else None)
    claims = []
    for candidate in value["candidates"]:
        record = json.loads(candidate["assertion"])
        item = pinned.get((TARGET_ROOT_ID, record["path"])) if record["location_check"] == "pinned" else None
        if item is not None:
            citation = {"root": item.root, "path": item.path, "sha256": item.sha256,
                        "locator": f"L{record['start_line']}-L{record['end_line']}"}
        else:
            citation = {"root": brief.root, "path": brief.path, "sha256": brief.sha256,
                        "locator": candidate["subject_id"]}
        claims.append({"claim_id": candidate["candidate_id"], "claim_class": "candidate_only",
                       "statement": _clip(f"{record['kind']}: {record['vulnerability_class']} at "
                                          f"{record['path']}:{record['start_line']}", 300),
                       "file": result_filename, "citations": [citation]})
    return claims
