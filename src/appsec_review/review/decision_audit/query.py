"""Closed, deterministic operator queries over one immutable, fully verified audit.

``role`` is an attribution filter, never an authorization claim. This adapter is
deliberately not registered as a worker tool, including for blinded verifiers.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from enum import StrEnum
import hashlib
import json
from typing import Any

from appsec_review.review.models import IntegrityError, Predicate, Role
from appsec_review.review.secret_redaction import redact_source_line
from appsec_review.storage import canonical_json

from . import contracts as c
from .reader import AcceptedAudit

QUERY_VERSION = "decision-audit-query/1"
_LEAD_STAGES = frozenset({c.Stage.COLLECTION, c.Stage.SEVERITY_TRIAGE, c.Stage.ADMISSION,
                          c.Stage.PACKAGE_ASSEMBLY, c.Stage.RED_DISCOVERY})

class Template(StrEnum):
    LEAD_TRACE = "lead_trace"
    CLAIM_BASIS = "claim_basis"
    VERIFICATION_COVERAGE = "verification_coverage"
    POPULATION = "population"


@dataclass(frozen=True, slots=True)
class Query:
    template: Template
    lead_id: str | None = None
    claim_id: str | None = None
    predicate: Predicate | None = None
    stage: c.Stage | None = None
    role: Role | None = None

    def __post_init__(self) -> None:
        for key, enum in (("template", Template), ("predicate", Predicate), ("stage", c.Stage), ("role", Role)):
            value = getattr(self, key)
            if value is not None:
                object.__setattr__(self, key, enum(value))
        allowed = {
            Template.LEAD_TRACE: {"lead_id"},
            Template.CLAIM_BASIS: {"claim_id"},
            Template.VERIFICATION_COVERAGE: {"claim_id", "predicate"},
            Template.POPULATION: {"stage", "role"},
        }
        selected = {key for key, value in asdict(self).items() if key != "template" and value is not None}
        if self.template not in allowed or not selected <= allowed[self.template]:
            raise ValueError("unsupported fields for decision audit query template")
        for key in ("lead_id", "claim_id"):
            value = getattr(self, key)
            if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 200
                                      or any(ord(char) < 32 for char in value)):
                raise ValueError("decision audit query identity is invalid")
        required = {Template.LEAD_TRACE: "lead_id", Template.CLAIM_BASIS: "claim_id"}.get(self.template)
        if required is not None and getattr(self, required) is None:
            raise ValueError(f"{self.template} requires {required}")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        # Identity strings and original citations remain resolving. Only the closed
        # explanation field contains prose; never redact hashes into unusable citations.
        result = {key: "\n".join(redact_source_line(line) for line in item.split("\n"))
                  if key == "text" and isinstance(item, str) else _redact(item) for key, item in value.items()}
        if isinstance(result.get("original_outcome"), dict) and result["original_outcome"]["value"] is not None:
            result["original_outcome"]["value"] = redact_source_line(result["original_outcome"]["value"])
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _matches(record: c.Product, query: Query) -> bool:
    subject = record.context.subject
    if query.claim_id is not None and query.claim_id != subject.claim_id.value:
        return False
    if query.template == Template.CLAIM_BASIS:
        return isinstance(record, c.DecisionBasisRecord)
    if query.template == Template.VERIFICATION_COVERAGE:
        return isinstance(record, c.VerificationRecord) and (
            query.predicate is None or any(row.predicate == query.predicate for row in record.predicates))
    if query.stage is not None and (not isinstance(record, c.DecisionRecord) or record.stage != query.stage):
        return False
    if query.role is not None:
        actor = (record.actor_role if isinstance(record, c.DecisionRecord) else
                 Role.INDEPENDENT_VERIFIER if isinstance(record, c.VerificationRecord) else None)
        if query.role != actor:
            return False
    return True


def _lead_trace(audit: AcceptedAudit, lead_id: str) -> tuple[tuple[c.Product, ...], dict[str, int]]:
    direct = {row.record_id for row in audit.records if row.context.subject.lead_id.value == lead_id}
    origins = {row.record_id: frozenset((ref.path, ref.sha256, ref.record_id.value)
                                      for ref in audit.origin_proposals(row)) for row in audit.records}
    selected_origins = frozenset(key for identity in direct for key in origins[identity])

    def other_lead_row(row: c.Product) -> bool:
        subject = row.context.subject
        return (isinstance(row, c.DecisionRecord) and row.stage in _LEAD_STAGES
                and subject.proposal_ref.value is None and subject.lead_id.value not in (None, lead_id))

    joined = tuple(row for row in audit.records
                   if not other_lead_row(row) and origins[row.record_id] & selected_origins)
    claims = {row.context.subject.claim_id.value for row in joined if row.context.subject.claim_id.value is not None}
    selected = direct | {row.record_id for row in joined}
    rows = tuple(row for row in audit.records if row.record_id in selected or (
        row.context.subject.claim_id.value in claims and row.context.subject.proposal_ref.value is None
        and not other_lead_row(row)))
    return rows, {"matched_proposals": len(selected_origins), "matched_claims": len(claims),
                  "unavailable_membership_records": len(direct & set(audit.lead_membership_unavailable))}


def _record_view(record: c.Product) -> dict[str, Any]:
    view = _redact(record.to_dict())
    view["source_schema"] = view.pop("schema")
    view["source_record"] = c.RecordRef.of(record).to_dict()
    view["view"] = "redacted_operator_projection"
    return view


def _offset(cursor: str | None, identity: str, total: int, limit: int) -> int:
    if cursor is None:
        return 0
    if not isinstance(cursor, str) or len(cursor) > 512:
        raise ValueError("invalid decision audit cursor")
    try:
        payload = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid decision audit cursor") from exc
    if (not isinstance(payload, dict) or set(payload) != {"identity", "offset"}
            or payload["identity"] != identity or type(payload["offset"]) is not int
            or not 0 < payload["offset"] < total or payload["offset"] % limit):
        raise ValueError("decision audit cursor does not bind this accepted manifest/query/page")
    return payload["offset"]


def execute(audit: AcceptedAudit, query: Query, *, limit: int | None = None,
            cursor: str | None = None) -> dict[str, Any]:
    """Return bounded redacted records, exact page accounting and original coverage omissions."""
    limit = audit.settings.page_size if limit is None else limit
    if type(limit) is not int or not 1 <= limit <= audit.settings.max_page_size:
        raise ValueError("decision audit limit exceeds max_page_size or is not positive")
    identity = hashlib.sha256(canonical_json({
        "query_version": QUERY_VERSION,
        "accepted_handoff": audit.accepted_handoff_sha256,
        "manifest": None if audit.reference is None else audit.reference.to_dict(),
        "query": asdict(query), "limit": limit})).hexdigest()
    if not audit.available:
        if cursor is not None:
            raise ValueError("unavailable decision audit has no continuation")
        return {"available": False, "unavailable_reason": _redact(audit.unavailable_reason),
                "query": asdict(query), "records": [], "total": None, "next_cursor": None,
                "coverage": None}
    if audit.reference is None or audit.manifest is None:
        raise IntegrityError("available decision audit has no accepted manifest")
    population, trace = (audit.records, None)
    if query.template == Template.LEAD_TRACE:
        population, trace = _lead_trace(audit, query.lead_id)
    rows = sorted((record for record in population if _matches(record, query)),
                  key=lambda record: (record.context.subject.claim_id.value or "",
                                      record.context.subject.lead_id.value or "",
                                      list(c.Stage).index(record.stage) if isinstance(record, c.DecisionRecord) else len(c.Stage),
                                      record.record_id))
    offset = _offset(cursor, identity, len(rows), limit)
    end = offset + limit
    next_cursor = None if end >= len(rows) else base64.urlsafe_b64encode(
        canonical_json({"identity": identity, "offset": end})).decode("ascii")
    selected = rows[offset:end]
    omissions = [{"record_id": row.record_id, "reason": "verified_reference_continuations_not_expanded",
                  "references": sum(ref.record_count for ref in row.context.continuations)}
                 for row in selected if row.context.continuations]
    if trace is not None and trace["unavailable_membership_records"]:
        omissions.append({"reason": "lead_proposal_membership_unavailable",
                          "records": trace["unavailable_membership_records"]})
    return {"available": True, "unavailable_reason": None, "query": asdict(query),
            "manifest": audit.reference.to_dict(), "records": [_record_view(row) for row in selected],
            "total": len(rows), "returned": len(selected), "offset": offset, "next_cursor": next_cursor,
            "coverage": [row.to_dict() for row in audit.manifest.coverage],
            "omissions": omissions, **({} if trace is None else {"trace": trace}),
            "notice": "Redacted views, not canonical artifacts; source_record binds original accepted bytes. "
                      "Claim outcomes retain their complete accepted basis, including other originating leads. "
                      "Judge dissent and counterevidence do not add supporting proof."}


__all__ = ["Query", "Template", "execute"]
