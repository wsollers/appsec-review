#!/usr/bin/env python3
"""Threat-workbench intercom artifact bus (ADR-0008 task T06).

Intercom is structured artifact exchange between persona workcells, never a conversation. This
module owns the durable transcript and the rules that make it auditable:

- append-only JSONL with a per-record ``content_hash`` chained through ``previous_hash``;
- structural validation against ``schemas/threat-workbench-intercom-record.schema.json``;
- authorization: ownership of every challenged record is resolved from an authoritative map the
  caller must supply (or from the transcript itself for intercom records) and unknown ownership
  fails closed; a ``challenge`` may only target the workcell that owns what it challenges, names
  its subjects and cites counterevidence or the evidence it demands; a ``response`` may only come
  from that owner, in wave 4; a record may only resolve an EARLIER record addressed to or written
  by its author; the integrator authors nothing; a write policy limits record types per workcell;
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
RESOLVING_STATUSES = frozenset({"answered", "accepted", "rejected", "withdrawn"})
WITHDRAWN_STATUS = "withdrawn"
# A response settles its challenge only by conceding it (accepted -> the record is amended) or by
# withdrawing the challenged record. "rejected", "answered" and "unresolved" leave the dissent open.
CHALLENGE_SETTLING_RESPONSE_STATUSES = frozenset({"accepted", "withdrawn"})
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
    ``intercom_writes``). When omitted, only the built-in rules apply.

    ``append`` requires ``model_record_authors``: the authoritative map from canonical model record
    id to the workcell that authored it, built by the runner from the frozen wave manifests. It is
    a required argument on purpose. Ownership decides who may be challenged and who may respond, and
    a check that can be skipped by leaving an argument out is not a check. Pass ``{}`` when no model
    records exist yet; a challenge whose subject has no known owner is then rejected.
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
               model_record_authors: dict[str, str]) -> dict[str, Any]:
        """Validates, authorizes, hashes and durably appends one record. Returns the stored record
        (with content_hash and any injection flag filled in). Never rewrites an earlier line."""
        if not isinstance(model_record_authors, dict):
            raise IntercomError("model_record_authors must be the authoritative ownership map (a dict)")
        candidate = dict(record)
        with Lock(self.lock_path):
            existing = self.records()
            self._check_structure(candidate, existing)
            self._check_authorization(candidate, existing, model_record_authors)
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
        by_id = {r["record_id"]: r for r in existing}
        self._check_resolution(record, by_id)
        if rtype == "challenge":
            if record["wave"] != CHALLENGE_WAVE:
                raise IntercomError(f"{rid}: challenges are wave {CHALLENGE_WAVE} records")
            if record["status"] != OPEN_STATUS:
                raise IntercomError(f"{rid}: a challenge is written open; its outcome is derived by the sweep")
            if not record["subject_record_ids"]:
                raise IntercomError(f"{rid}: a challenge must name the record ids it challenges")
            demanded = record["payload"].get("demanded_evidence")
            if not record["citations"] and not (isinstance(demanded, str) and demanded.strip()):
                raise IntercomError(
                    f"{rid}: a challenge must cite counterevidence or state the evidence it demands")
            if record["target"] in INTEGRATOR_AUTHORS:
                raise IntercomError(f"{rid}: a challenge targets the authoring workcell, not the integrator")
            owners = self._owners(rid, record["subject_record_ids"], by_id, model_record_authors)
            if owners != {record["target"]}:
                raise IntercomError(
                    f"{rid}: a challenge must target the one workcell that owns every challenged "
                    f"record; subjects are owned by {sorted(owners)}, target is {record['target']!r}")
            if author in owners:
                raise IntercomError(f"{rid}: a workcell cannot challenge its own records")
        elif rtype == "response":
            if record["wave"] != RESPONSE_WAVE:
                raise IntercomError(f"{rid}: responses are wave {RESPONSE_WAVE} records")
            challenges = [by_id[s] for s in record["subject_record_ids"]
                          if s in by_id and by_id[s]["record_type"] == "challenge"]
            if len(challenges) != 1:
                raise IntercomError(f"{rid}: a response names exactly one existing challenge in subject_record_ids")
            challenge = challenges[0]
            if _withdrawal_of(challenge, existing) is not None:
                raise IntercomError(f"{rid}: {challenge['record_id']} was withdrawn by its author; there is nothing to respond to")
            # Re-derive ownership rather than trusting the challenge's own target field.
            owners = self._owners(rid, challenge["subject_record_ids"], by_id, model_record_authors)
            if owners != {author}:
                raise IntercomError(
                    f"{rid}: only the workcell that owns the challenged records may respond to "
                    f"{challenge['record_id']}; they are owned by {sorted(owners)}, author is {author!r}")
            if challenge["target"] != author:
                raise IntercomError(
                    f"{rid}: only {challenge['target']!r}, the challenged workcell, may respond to "
                    f"{challenge['record_id']}; author is {author!r}")
            if record["target"] != challenge["author_workcell_id"]:
                raise IntercomError(f"{rid}: a response is addressed to the challenger")
        elif record["wave"] == RESPONSE_WAVE:
            raise IntercomError(f"{rid}: wave {RESPONSE_WAVE} carries responses only")

    @staticmethod
    def _owners(rid: str, subjects: list[str], by_id: dict[str, dict[str, Any]],
                model_record_authors: dict[str, str]) -> set[str]:
        """Owner of each subject: an intercom record's author comes from the tamper-evident
        transcript, a model record's from the authoritative map. Unknown ownership fails closed."""
        owners: set[str] = set()
        for subject in subjects:
            if subject in by_id:
                owners.add(by_id[subject]["author_workcell_id"])
            elif subject in model_record_authors:
                owners.add(model_record_authors[subject])
            else:
                raise IntercomError(f"{rid}: no known owner for challenged record {subject!r}; "
                                    "ownership must be authoritative, not assumed")
        return owners

    @staticmethod
    def _check_resolution(record: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> None:
        """resolves_record_id is a backward pointer, and resolving is an authority, not a courtesy.

        - self, forward and unknown references are rejected, so the transcript never holds one;
        - the resolved record must be named in subject_record_ids (no silent side effects);
        - a record is resolved once; the first resolver stands;
        - the TARGET of a record may answer, accept or reject it; its AUTHOR may only withdraw it.
          An author "accepting" its own open record would let one party close a disagreement alone;
        - a challenge is settled only by a response from the challenged owner that concedes it, or
          by its author withdrawing it. No other record type can clear a challenge.
        """
        rid = record["record_id"]
        resolved_id = record["resolution"]["resolves_record_id"]
        if resolved_id is None:
            return
        if resolved_id == rid:
            raise IntercomError(f"{rid}: a record cannot resolve itself")
        resolved = by_id.get(resolved_id)
        if resolved is None:
            raise IntercomError(f"{rid}: resolves_record_id {resolved_id!r} is not an earlier record in this transcript")
        if resolved_id not in record["subject_record_ids"]:
            raise IntercomError(f"{rid}: a record must name {resolved_id!r} in subject_record_ids to resolve it")
        if record["status"] not in RESOLVING_STATUSES:
            raise IntercomError(f"{rid}: a record with status {record['status']!r} does not resolve anything")
        earlier = next((r["record_id"] for r in by_id.values()
                        if r["resolution"]["resolves_record_id"] == resolved_id), None)
        if earlier is not None:
            raise IntercomError(f"{rid}: {resolved_id} was already resolved by {earlier}")
        author = record["author_workcell_id"]
        is_target = author == resolved["target"]
        is_author = author == resolved["author_workcell_id"]
        if not (is_target or is_author):
            raise IntercomError(
                f"{rid}: {resolved_id} may be resolved only by its target {resolved['target']!r} "
                f"or withdrawn by its author {resolved['author_workcell_id']!r}")
        if not is_target and record["status"] != WITHDRAWN_STATUS:
            raise IntercomError(
                f"{rid}: {author!r} authored {resolved_id} and may only withdraw it; "
                f"status {record['status']!r} belongs to its target {resolved['target']!r}")
        if resolved["record_type"] == "challenge" and is_target:
            if record["record_type"] != "response":
                raise IntercomError(f"{rid}: a challenge is settled only by a response from the challenged owner")
            if record["status"] not in CHALLENGE_SETTLING_RESPONSE_STATUSES:
                raise IntercomError(
                    f"{rid}: a response with status {record['status']!r} leaves {resolved_id} open; "
                    f"only {sorted(CHALLENGE_SETTLING_RESPONSE_STATUSES)} settle a challenge")


def _may_resolve(resolver: dict[str, Any], resolved: dict[str, Any]) -> bool:
    """The authority rule append() enforces, restated for records that did not pass through it:
    the target may resolve; the author may only withdraw."""
    author = resolver["author_workcell_id"]
    if author == resolved["target"]:
        return True
    return author == resolved["author_workcell_id"] and resolver["status"] == WITHDRAWN_STATUS


def _withdrawal_of(challenge: dict[str, Any], records: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    """The record, if any, by which a challenge's own author withdrew it."""
    for record in records:
        if (record["resolution"]["resolves_record_id"] == challenge["record_id"]
                and record["author_workcell_id"] == challenge["author_workcell_id"]
                and record["status"] == WITHDRAWN_STATUS
                and record["record_id"] != challenge["record_id"]):
            return record
    return None


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

def chain_order(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Append order, rebuilt from the hash chain so it does not depend on how the caller ordered
    its input. "Later" in this module always means later in this order."""
    pending = list(records)
    by_previous: dict[str | None, dict[str, Any]] = {}
    for record in pending:
        if record["previous_hash"] in by_previous:
            raise IntercomTamperError(f"{record['record_id']}: two records claim the same predecessor")
        by_previous[record["previous_hash"]] = record
    ordered: list[dict[str, Any]] = []
    cursor: str | None = None
    while cursor in by_previous:
        record = by_previous.pop(cursor)
        ordered.append(record)
        cursor = record["content_hash"]
    if by_previous:
        orphan = next(iter(by_previous.values()))
        raise IntercomTamperError(f"{orphan['record_id']}: not reachable from the start of the chain")
    return ordered


def sweep(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """What the join copies out at the end. Input order is irrelevant; append order is rebuilt
    from the hash chain.

    ``unresolved``: every record written ``open`` that no LATER, DISTINCT record resolves by
    naming it in ``resolution.resolves_record_id``; each id exactly once, in append order.
    ``invalid_resolutions``: self or forward references. ``append`` rejects these, so one can only
    come from records that did not pass through the bus; it is reported and never honoured.
    ``dissent``: one entry per challenge, in the integrated model's dissent shape. A challenge's
    outcome is derived once -- its author's withdrawal, else the first later response naming it --
    and that single outcome decides both its dissent status and whether it is in ``unresolved``.
    ``withdrawals``: which record withdrew which challenge (the dissent shape has no field for it).
    """
    ordered = chain_order(records)
    position = {r["record_id"]: index for index, r in enumerate(ordered)}
    resolved_by: dict[str, str] = {}
    invalid: list[dict[str, str]] = []
    for index, record in enumerate(ordered):
        target = record["resolution"]["resolves_record_id"]
        if target is None:
            continue
        if target == record["record_id"]:
            invalid.append({"record_id": record["record_id"], "reason": "self_reference"})
        elif target not in position or position[target] >= index:
            invalid.append({"record_id": record["record_id"], "reason": "forward_or_unknown_reference"})
        elif record["status"] not in RESOLVING_STATUSES:
            invalid.append({"record_id": record["record_id"], "reason": "non_resolving_status"})
        elif not _may_resolve(record, ordered[position[target]]):
            invalid.append({"record_id": record["record_id"], "reason": "unauthorized_resolver"})
        else:
            resolved_by.setdefault(target, record["record_id"])
    # One derivation of each challenge's outcome feeds BOTH projections, so "unresolved" and
    # "dissent" can never disagree about a challenge.
    dissent, withdrawals, open_challenges = [], [], set()
    for index, challenge in enumerate(ordered):
        if challenge["record_type"] != "challenge":
            continue
        later = ordered[index + 1:]
        withdrawal = _withdrawal_of(challenge, later)
        answer = None if withdrawal else next(
            (r for r in later if r["record_type"] == "response"
             and challenge["record_id"] in r["subject_record_ids"]), None)
        if withdrawal is not None:
            status = "withdrawn"
            withdrawals.append({"challenge_record_id": challenge["record_id"],
                                "withdrawn_by_record_id": withdrawal["record_id"]})
        elif answer is not None and answer["status"] == WITHDRAWN_STATUS:
            status = "withdrawn"
        elif answer is not None and answer["status"] == "accepted":
            status = "amended"
        else:
            status = "unresolved"
            open_challenges.add(challenge["record_id"])
        dissent.append({
            "challenge_record_id": challenge["record_id"],
            "response_record_id": answer["record_id"] if answer else None,
            "subject_record_ids": list(challenge["subject_record_ids"]),
            "status": status,
        })
    unresolved = []
    for record in ordered:
        if record["status"] != OPEN_STATUS:
            continue
        if record["record_type"] == "challenge":
            if record["record_id"] in open_challenges:
                unresolved.append(record["record_id"])
        elif record["record_id"] not in resolved_by:
            unresolved.append(record["record_id"])
    return {"unresolved": unresolved, "invalid_resolutions": invalid, "dissent": dissent,
            "withdrawals": withdrawals,
            "quarantined": [r["record_id"] for r in quarantined(ordered)]}
