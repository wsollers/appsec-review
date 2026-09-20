#!/usr/bin/env python3
"""Threat-workbench intercom artifact bus (ADR-0008 task T06).

Intercom is structured artifact exchange between persona workcells, never a conversation. This
module owns the durable transcript and the rules that make it auditable:

- append-only JSONL with a per-record ``content_hash`` chained through ``previous_hash``;
- structural validation against ``schemas/threat-workbench-intercom-record.schema.json``;
- authorization: a ``response`` may only come from the workcell a ``challenge`` targeted, in wave 4;
  a ``challenge`` names what it challenges and cites counterevidence or the evidence it demands;
  the integrator authors nothing; an optional write policy limits record types per workcell;
- injection quarantine: record text that reads as an instruction to a reviewer is flagged
  ``injection_suspected`` and excluded from projections while staying in the transcript
  (``docs/design-v3.md`` 6.1: detection, not just avoidance);
- projections that hand a cell only the record types its ``intercom_reads`` allows, in an order
  that does not depend on write order;
- the open-record sweep the join copies into ``assumptions-and-gaps.json`` and ``dissent``.

Pure file semantics. No persona invocation, pool, wave runner or join lives here (T05/T07).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from execution_state import Lock, digest
from schema_validate import SchemaStore, validate_document

INTERCOM_SCHEMA = "appsec-review/threat-workbench-intercom-record/0.1"
INTERCOM_SCHEMA_FILE = "threat-workbench-intercom-record.schema.json"
RECORD_TYPES = ("question", "assumption", "proposed_model_edit", "proposed_threat",
                "proposed_attack_tree_node", "challenge", "coverage_gap", "response")
OPEN_STATUS = "open"
INTEGRATOR_AUTHORS = frozenset({"integrator", "integrator-join"})
CHALLENGE_WAVE = 3
RESPONSE_WAVE = 4

# Phrases that read as instructions to the reviewing agent rather than as data. Deliberately
# conservative: a false positive only moves a record out of the summary projection, never out of
# the transcript, and the flag is visible.
_INJECTION_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"^\s*(system|assistant|developer|important)\s*:",
    r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
    r"\bdisregard\s+(the\s+|your\s+|all\s+)?(instructions?|rules?|guidelines?|prompt)",
    r"\breviewers?\s+(must|should|shall)\b",
    r"\byou\s+(must|should|are\s+to)\s+(now\s+)?(skip|ignore|downgrade|omit|exclude|mark|treat|report|not\s+report)\b",
    r"\bdo\s+not\s+(report|mention|flag|model|include)\b",
    r"</?\s*(system|instructions?)\s*>",
    r"\bas\s+an?\s+(ai|llm|assistant|language\s+model)\b",
    r"\bout\s+of\s+scope\s+for\s+(this\s+)?review\b",
))


class IntercomError(ValueError):
    """A record was rejected before it reached the transcript."""


class IntercomTamperError(RuntimeError):
    """The transcript on disk no longer matches its own hash chain."""


def content_hash(record: dict[str, Any]) -> str:
    """sha256 over the canonical record without its own content_hash. previous_hash is inside, so
    the chain is part of every hash."""
    body = {key: value for key, value in record.items() if key != "content_hash"}
    return digest(body)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def suspect_injection(record: dict[str, Any]) -> list[str]:
    """Returns the matched phrases (empty when clean). Scans the fields a persona writes as prose."""
    reasons: list[str] = []
    for field in ("topic", "payload", "resolution"):
        for text in _strings(record.get(field)):
            for pattern in _INJECTION_PATTERNS:
                match = pattern.search(text)
                if match:
                    reasons.append(f"{field}: {match.group(0).strip()!r}")
                    break
    return reasons


class IntercomTranscript:
    """One append-only ``intercom-transcript.jsonl``; the lock is a sibling file.

    ``write_policy`` maps workcell_id to the record types it may author (a workcell's
    ``intercom_writes``). When omitted, only the built-in rules apply. ``model_record_authors`` maps
    canonical model record ids to the workcell that authored them; when supplied, a response is also
    checked against the authorship of the challenged model records.
    """

    def __init__(self, path: Path, *, write_policy: dict[str, Iterable[str]] | None = None,
                 store: SchemaStore | None = None) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.write_policy = {k: frozenset(v) for k, v in (write_policy or {}).items()}
        self.store = store or SchemaStore()

    # ---- reading --------------------------------------------------------------------------

    def records(self) -> list[dict[str, Any]]:
        """Reads and verifies the whole chain. Any break raises IntercomTamperError naming the
        first record that no longer fits."""
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        previous: str | None = None
        seen: set[str] = set()
        with self.path.open("r", encoding="utf-8") as stream:
            for index, line in enumerate(stream):
                line = line.rstrip("\n")
                if not line:
                    raise IntercomTamperError(f"line {index}: empty line inside transcript")
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise IntercomTamperError(f"line {index}: not JSON ({exc.msg})") from None
                record_id = record.get("record_id", f"<line {index}>")
                if record.get("previous_hash") != previous:
                    raise IntercomTamperError(
                        f"{record_id}: previous_hash does not match the preceding record")
                if record.get("content_hash") != content_hash(record):
                    raise IntercomTamperError(f"{record_id}: content_hash does not match content")
                if record_id in seen:
                    raise IntercomTamperError(f"{record_id}: duplicate record_id")
                seen.add(record_id)
                records.append(record)
                previous = record["content_hash"]
        return records

    # ---- writing --------------------------------------------------------------------------

    def append(self, record: dict[str, Any], *,
               model_record_authors: dict[str, str] | None = None) -> dict[str, Any]:
        """Validates, authorizes, hashes and durably appends one record. Returns the stored record
        (with content_hash and any injection flag filled in). Never rewrites an earlier line."""
        candidate = dict(record)
        with Lock(self.lock_path):
            existing = self.records()
            self._check_structure(candidate, existing)
            self._check_authorization(candidate, existing, model_record_authors or {})
            reasons = suspect_injection(candidate)
            if reasons:
                candidate["injection_suspected"] = True
            expected_previous = existing[-1]["content_hash"] if existing else None
            if candidate.get("previous_hash") != expected_previous:
                raise IntercomError(
                    f"{candidate['record_id']}: previous_hash must equal the last record's "
                    f"content_hash ({expected_previous!r})")
            computed = content_hash(candidate)
            supplied = candidate.get("content_hash")
            if supplied not in (None, computed):
                raise IntercomError(f"{candidate['record_id']}: supplied content_hash does not match content")
            candidate["content_hash"] = computed
            errors = validate_document(candidate, INTERCOM_SCHEMA_FILE, self.store)
            if errors:
                raise IntercomError(f"{candidate['record_id']}: " + "; ".join(errors))
            line = json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\n"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        return candidate

    def _check_structure(self, record: dict[str, Any], existing: list[dict[str, Any]]) -> None:
        # Validate before hashing so error messages name fields, not hashes. content_hash may be
        # absent at this point; the schema requires it, so check everything else first.
        probe = dict(record)
        probe.setdefault("content_hash", "0" * 64)
        errors = validate_document(probe, INTERCOM_SCHEMA_FILE, self.store)
        if errors:
            raise IntercomError(f"{record.get('record_id', '<no id>')}: " + "; ".join(errors))
        if any(r["record_id"] == record["record_id"] for r in existing):
            raise IntercomError(f"{record['record_id']}: duplicate record_id")
        if existing and record["wave"] < existing[-1]["wave"]:
            raise IntercomError(
                f"{record['record_id']}: wave {record['wave']} precedes the transcript's current "
                f"wave {existing[-1]['wave']}; waves only move forward")

    def _check_authorization(self, record: dict[str, Any], existing: list[dict[str, Any]],
                             model_record_authors: dict[str, str]) -> None:
        rid, author, rtype = record["record_id"], record["author_workcell_id"], record["record_type"]
        if author in INTEGRATOR_AUTHORS:
            raise IntercomError(f"{rid}: the integrator never authors intercom records")
        if self.write_policy:
            allowed = self.write_policy.get(author)
            if allowed is None:
                raise IntercomError(f"{rid}: workcell {author!r} has no intercom write policy")
            if rtype not in allowed:
                raise IntercomError(f"{rid}: workcell {author!r} may not author {rtype!r}")
        if rtype == "challenge":
            if record["wave"] != CHALLENGE_WAVE:
                raise IntercomError(f"{rid}: challenges are wave {CHALLENGE_WAVE} records")
            if not record["subject_record_ids"]:
                raise IntercomError(f"{rid}: a challenge must name the record ids it challenges")
            demanded = record["payload"].get("demanded_evidence")
            if not record["citations"] and not (isinstance(demanded, str) and demanded.strip()):
                raise IntercomError(
                    f"{rid}: a challenge must cite counterevidence or state the evidence it demands")
            if record["target"] in INTEGRATOR_AUTHORS:
                raise IntercomError(f"{rid}: a challenge targets the authoring workcell, not the integrator")
        elif rtype == "response":
            if record["wave"] != RESPONSE_WAVE:
                raise IntercomError(f"{rid}: responses are wave {RESPONSE_WAVE} records")
            by_id = {r["record_id"]: r for r in existing}
            challenges = [by_id[s] for s in record["subject_record_ids"]
                          if s in by_id and by_id[s]["record_type"] == "challenge"]
            if len(challenges) != 1:
                raise IntercomError(f"{rid}: a response names exactly one existing challenge in subject_record_ids")
            challenge = challenges[0]
            if challenge["target"] != author:
                raise IntercomError(
                    f"{rid}: only {challenge['target']!r}, the challenged workcell, may respond to "
                    f"{challenge['record_id']}; author is {author!r}")
            if record["target"] != challenge["author_workcell_id"]:
                raise IntercomError(f"{rid}: a response is addressed to the challenger")
            for subject in challenge["subject_record_ids"]:
                owner = model_record_authors.get(subject)
                if owner is not None and owner != author:
                    raise IntercomError(
                        f"{rid}: challenged record {subject!r} was authored by {owner!r}, not {author!r}")
        elif record["wave"] == RESPONSE_WAVE:
            raise IntercomError(f"{rid}: wave {RESPONSE_WAVE} carries responses only")


# ---- projections -------------------------------------------------------------------------------

def _sort_key(record: dict[str, Any]) -> tuple:
    return (record["wave"], record["record_type"], record["record_id"])


def project(records: Iterable[dict[str, Any]], *, reads: Iterable[str],
            include_quarantined: bool = False) -> list[dict[str, Any]]:
    """The records a cell may see: only the allowed types, quarantined records excluded unless
    asked for, in a deterministic order independent of write order."""
    allowed = frozenset(reads)
    unknown = allowed - set(RECORD_TYPES) - {"all"}
    if unknown:
        raise IntercomError(f"unknown record types in read policy: {sorted(unknown)}")
    chosen = [r for r in records
              if ("all" in allowed or r["record_type"] in allowed)
              and (include_quarantined or not r.get("injection_suspected"))]
    return sorted(chosen, key=_sort_key)


def quarantined(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((r for r in records if r.get("injection_suspected")), key=_sort_key)


# ---- open-record sweep ---------------------------------------------------------------------------

def sweep(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """What the join copies out at the end.

    ``unresolved``: every record still ``open`` that no later record resolves (by naming it in
    ``resolution.resolving_record_id``), each id exactly once.
    ``dissent``: one entry per challenge in the integrated model's dissent shape.
    """
    ordered = sorted(records, key=_sort_key)
    resolved_by: dict[str, str] = {}
    for record in ordered:
        target = record["resolution"].get("resolving_record_id")
        if target and target not in resolved_by:
            resolved_by[target] = record["record_id"]
    unresolved = [r["record_id"] for r in ordered
                  if r["status"] == OPEN_STATUS and r["record_id"] not in resolved_by]
    dissent = []
    responses = [r for r in ordered if r["record_type"] == "response"]
    for challenge in (r for r in ordered if r["record_type"] == "challenge"):
        answer = next((r for r in responses if challenge["record_id"] in r["subject_record_ids"]), None)
        if answer is None:
            status = "unresolved"
        elif answer["status"] == "withdrawn":
            status = "withdrawn"
        elif answer["status"] == "accepted":
            status = "amended"
        else:
            status = "unresolved"
        dissent.append({
            "challenge_record_id": challenge["record_id"],
            "response_record_id": answer["record_id"] if answer else None,
            "subject_record_ids": list(challenge["subject_record_ids"]),
            "status": status,
        })
    return {"unresolved": unresolved, "dissent": dissent, "quarantined": [r["record_id"] for r in quarantined(ordered)]}
