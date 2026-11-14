"""Model-free, allowlisted views of recorded review decisions; never a second adjudicator."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, replace
import hashlib
from typing import Any, Mapping

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.owasp_workbench.evidence import redact
from appsec_review.review.adjudication import DecidingRow
from appsec_review.review.ledger import Projection
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.models import Admissibility, CellStatus, IntegrityError, Predicate, RelationKind, Role
from appsec_review.review.secret_redaction import redact_message
from appsec_review.storage import canonical_json

from . import contracts as c
from .metadata import POLICY_VERSION, policy_document
from .publication import AuditUnavailable

PROJECTION_POLICY_VERSION = POLICY_VERSION
PROPOSAL_CAPTURE_SCHEMA = "appsec-review/proposal-membership-capture/1"
STRUCTURE_CAPTURE_SCHEMA = "appsec-review/verifier-structure-capture/1"


def policy_sha256(settings: DecisionAuditSettings) -> str:
    return str(policy_document(settings)["sha256"])


def link(value: str | None = None, absence: c.AbsenceReason = c.AbsenceReason.NOT_APPLICABLE) -> c.Link:
    if value is not None and redact(value)[1]:
        raise IntegrityError("secret-bearing original identity cannot enter the audit")
    return c.Link(value, None if value is not None else absence)


def check(value: bool | None, absence: c.AbsenceReason = c.AbsenceReason.LEGACY_UNRECORDED) -> c.Check:
    return c.Check(value, None if value is not None else absence)


def explanation(text: str | None) -> c.Explanation:
    if not text:
        return c.Explanation(None, c.AbsenceReason.NOT_PRODUCED, link())
    safe = redact_message(redact(text)[0], bound=c.MAX_EXPLANATION) or ""
    return c.Explanation(safe, None, link("redacted_or_bounded" if safe != text else None))


def labelled_text(value: Mapping[str, Any], names: tuple[str, ...]) -> str:
    parts = []
    for name in names:
        item = value.get(name)
        if item is not None:
            if not isinstance(item, str):
                raise IntegrityError("audit narrative field is not text")
            if item.strip():
                parts.append(f"{name} {item}")
    return "; ".join(parts)


@dataclass(frozen=True)
class Document:
    source: c.SourceRef
    value: Mapping[str, Any]

    def ref(self, identity: str | None = None, *uses: c.EvidenceUse) -> c.SourceRef:
        return replace(self.source, record_id=link(identity), uses=uses or (c.EvidenceUse.READ,))


@dataclass(frozen=True)
class ProjectionInputs:
    origin: c.Origin
    projection: Projection
    projection_document: Document
    lanes: tuple[Document, ...]
    package_sets: tuple[Document, ...]
    packages: tuple[Document, ...]
    adjudications: Document
    scores: Document
    findings: tuple[Document, ...]
    triage: Document
    receipts: Mapping[str, Document]
    request_checks: Mapping[str, Document]
    collection: LeadCollection | None
    lead_sources: Mapping[str, c.SourceRef]
    additional_expected_cells: Mapping[str, str]


@dataclass(frozen=True)
class AuditProjection:
    records: tuple[c.Product, ...]
    coverage: tuple[c.CoverageCount, ...]
    continuations: Mapping[str, tuple[c.SourceRef | c.RelationRef, ...]]


_FUTURE = c.FutureReferences(*(c.OptionalSources((), c.AbsenceReason.NOT_PRODUCED) for _ in range(3)))
_REASONS = {
    "invalid": c.ReasonCode.INVALID_OUTPUT, "timed_out": c.ReasonCode.TIMED_OUT,
    "not_launched": c.ReasonCode.NOT_LAUNCHED, "over_cap": c.ReasonCode.BUDGET_LIMIT,
    "rejected": c.ReasonCode.INVALID_OUTPUT, "failed": c.ReasonCode.INPUT_UNAVAILABLE,
    "blocked": c.ReasonCode.MISSING_EVIDENCE, "canceled": c.ReasonCode.INPUT_UNAVAILABLE,
}
_ROWS = {
    DecidingRow.DUPLICATE: c.ReasonCode.EXACT_DUPLICATE, DecidingRow.OUT_OF_SCOPE: c.ReasonCode.OUTSIDE_SCOPE,
    DecidingRow.UNRESOLVED_CONTRADICTION: c.ReasonCode.UNRESOLVED_CONTRADICTION,
    DecidingRow.DIRECT_CONTRADICTION: c.ReasonCode.DIRECT_CONTRADICTION,
    DecidingRow.CONFIRMED: c.ReasonCode.DIRECT_SUPPORT, DecidingRow.SUPPORTED: c.ReasonCode.MISSING_EVIDENCE,
    DecidingRow.INSUFFICIENT_EVIDENCE: c.ReasonCode.MISSING_EVIDENCE,
}
_OUTCOMES = {
    c.Stage.SEVERITY_TRIAGE: {"unresolved": "unknown"},
    c.Stage.PACKAGE_ASSEMBLY: {"supplied": "assembled"},
    c.Stage.RED_DISCOVERY: {"emitted": "proposed", "proposal": "proposed", "no_proposal": "explicit_no_claim"},
    c.Stage.PROPOSAL_NORMALIZATION: {"admitted": "normalized"},
    c.Stage.CLAIM_CAP: {"over_cap": "capped"},
    c.Stage.PUBLICATION: {"confirmed": "publishable", "supported": "verification_backlog",
                          "unavailable": "not_published"},
}


class _Projector:
    def __init__(self, inputs: ProjectionInputs, settings: DecisionAuditSettings, directory: str):
        self.i, self.settings, self.directory = inputs, settings, directory
        self.records: list[c.Product] = []
        self.unavailable_decisions = 0
        self.unavailable_verifications = 0
        self.unavailable_proposal_membership = False
        self.projected_bytes = 0
        self.continuations: dict[str, tuple[c.SourceRef | c.RelationRef, ...]] = {}
        self.packages = {item.value["package_id"]: item for item in inputs.packages}
        if len({item.value["claim_id"] for item in inputs.findings}) != len(inputs.findings):
            raise IntegrityError("duplicate finding claim membership")
        self.cells = {}
        for identity, rows in inputs.projection.cells.items():
            if len(rows) != 1:
                raise IntegrityError("audit requires exactly one accepted terminal result per cell")
            self.cells[identity] = rows[0]
        self.origins: dict[str, list[c.SourceRef]] = defaultdict(list)
        self.adjudications = {item["claim_id"]: item for item in inputs.adjudications.value["adjudications"]}
        if len(self.adjudications) != len(inputs.adjudications.value["adjudications"]):
            raise IntegrityError("duplicate claim adjudication")
        if set(self.adjudications) - set(inputs.projection.claims):
            raise IntegrityError("adjudication belongs to a foreign claim")
        self.claim_scores: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        score_ids = set()
        for score in inputs.scores.value["scores"]:
            if score["claim_id"] not in inputs.projection.claims or score["score_id"] in score_ids:
                raise IntegrityError("score has a foreign claim or duplicate identity")
            score_ids.add(score["score_id"])
            self.claim_scores[score["claim_id"]].append(score)
        self.capabilities = {row["cell_id"]: row for lane in inputs.lanes
                             for row in lane.value.get("capabilities", ())}

    def add(self, record: c.Product) -> c.Product:
        if len(self.records) >= self.settings.max_records:
            raise AuditUnavailable("max_records")
        self.projected_bytes += len(c.canonical_bytes(record))
        if self.projected_bytes > self.settings.max_input_bytes:
            raise AuditUnavailable("max_input_bytes:projected_output")
        self.records.append(record)
        return record

    def subject(self, *, lead: str | None = None, proposal: str | None = None, claim: str | None = None,
                adjudication: str | None = None, finding: str | None = None, package: str | None = None,
                cell: str | None = None, round_index: int | None = None) -> c.Subject:
        scope = self.packages[package].value.get("scope", {}) if package in self.packages else {}
        operation = scope.get("operation") or {}
        return c.Subject(link(lead), link(proposal), link(claim, c.AbsenceReason.PRE_CLAIM),
                         link(adjudication), link(finding), link(package),
                         link(operation.get("operation_id"), c.AbsenceReason.LEGACY_UNRECORDED),
                         link(scope.get("component_id"), c.AbsenceReason.LEGACY_UNRECORDED),
                         link(scope.get("build_unit_id"), c.AbsenceReason.LEGACY_UNRECORDED), link(cell),
                         c.Round(round_index, None if round_index is not None else c.AbsenceReason.LEGACY_UNRECORDED))

    def context(self, subject: c.Subject, *, sources=(), relations=(), proposals=(), text=None, gaps=()) -> c.Context:
        if not sources:
            sources = (self.i.projection_document.ref(),)
        fields = {c.ReferenceField.SOURCES: tuple(sources), c.ReferenceField.RELATIONS: tuple(relations),
                  c.ReferenceField.ORIGIN_PROPOSALS: tuple(proposals)}
        inline = {}
        refs = []
        room = c.MAX_INLINE_REFERENCES
        for field, values in fields.items():
            values = tuple(sorted(values, key=lambda row: canonical_json(row.to_dict())))
            inline[field] = values[:room]
            remaining = values[room:]
            room -= len(inline[field])
            while remaining:
                chunk = remaining[:min(self.settings.shard_records, c.MAX_SHARD_RECORDS)]
                while sum(len(canonical_json(row.to_dict())) for row in chunk) > self.settings.shard_bytes and len(chunk) > 1:
                    chunk = chunk[:len(chunk) // 2]
                if sum(len(canonical_json(row.to_dict())) for row in chunk) > self.settings.shard_bytes:
                    raise AuditUnavailable("reference_exceeds_shard_bytes")
                data = c.reference_bytes(field, chunk, origin=self.i.origin, claim_id=subject.claim_id)
                digest = hashlib.sha256(data).hexdigest()
                path = f"{self.directory}/continuations/{field}/{digest}.jsonl"
                refs.append(c.make_continuation(field, path, chunk, origin=self.i.origin, claim_id=subject.claim_id))
                self.continuations[path] = chunk
                remaining = remaining[len(chunk):]
        if len(refs) > c.MAX_INLINE_REFERENCES:
            raise AuditUnavailable("continuation_reference_limit")
        if len(set(gaps)) > c.MAX_INLINE_REFERENCES:
            raise AuditUnavailable("gap_reference_limit")
        return c.Context(self.i.origin, subject, inline[c.ReferenceField.SOURCES], inline[c.ReferenceField.RELATIONS],
                         inline[c.ReferenceField.ORIGIN_PROPOSALS], tuple(refs), _FUTURE, explanation(text),
                         tuple(sorted(set(gaps))))

    def decision(self, subject: c.Subject, stage: c.Stage, outcome: str, *, sources=(), relations=(), proposals=None,
                 text=None, gaps=(), reason=None, basis=c.BasisStatus.EXISTING_POLICY, row=None,
                 required=(), missing=(), receipt: Document | None = None,
                 original: c.Link | None = None) -> c.DecisionRecord:
        actor = self.cells.get(subject.cell_id.value)
        deciding_row = DecidingRow(row) if row is not None else None
        if proposals is None:
            proposals = self.origins.get(subject.claim_id.value, ())
        record = c.DecisionRecord(
            self.context(subject, sources=sources, relations=relations, proposals=proposals, text=text, gaps=gaps),
            stage, _OUTCOMES.get(stage, {}).get(outcome, outcome), original if original is not None else link(outcome), c.OptionalSource(
                receipt.ref(subject.cell_id.value) if receipt else None,
                None if receipt else c.AbsenceReason.NOT_PRODUCED),
            reason or _REASONS.get(outcome, c.ReasonCode.RECORDED_DECISION), basis,
            deciding_row, None if row else c.AbsenceReason.NOT_APPLICABLE,
            c.deciding_roles(deciding_row, required, relations), tuple(required), tuple(missing),
            actor.role if actor else None, None if actor else c.AbsenceReason.NOT_APPLICABLE)
        self.add(record)
        return record

    def leads(self) -> c.CoverageCount:
        lead_set = next((doc for doc in self.i.package_sets if doc.value["lane"] == "lead"), None)
        if lead_set is None:
            return c.CoverageCount(c.Population.LEADS, None, 0, 0, None, c.CoverageReason.INPUT_UNAVAILABLE)
        admission = lead_set.value["admission"]
        known = {lead.observation_id: lead for lead in self.i.collection.leads} if self.i.collection is not None else {}
        admitted_ids = [row["lead_id"] for row in admission]
        if len(set(admitted_ids)) != len(admitted_ids):
            raise IntegrityError("duplicate lead in accepted admission")
        if self.i.collection is not None:
            if len(known) != len(self.i.collection.leads) or set(known) != set(admitted_ids):
                raise IntegrityError("collected lead population differs from accepted admission")
        triage = {row["lead_id"]: row for row in self.i.triage.value.get("leads", ())}
        for entry in admission:
            identity = entry["lead_id"]
            lead = known.get(identity)
            source = self.i.lead_sources.get(identity)
            if lead is not None and source is None:
                raise IntegrityError("collected lead lacks its original accepted shard")
            subject = self.subject(lead=identity)
            if lead is None:
                text, gaps = None, ("audit:lead_provenance_legacy_unrecorded",)
            else:
                text = (f"family {lead.family}; scanner {lead.scanner}; rule {lead.rule_id}; "
                        f"reported_severity {lead.reported_severity}; severity_basis {lead.severity_basis}; "
                        f"suppression_status {lead.suppression_status}; duplicate_of {lead.duplicate_of}")
                gaps = ()
            self.decision(subject, c.Stage.COLLECTION, "collected", sources=(source,) if source else (lead_set.ref(identity),),
                          text=text, gaps=gaps, original=link())
            self.decision(subject, c.Stage.ADMISSION, entry["status"], sources=(lead_set.ref(identity),),
                          text="; ".join([*entry["reasons"], entry["residual_coverage"]]),
                          reason=c.ReasonCode.ADMISSION_POLICY)
            assessed = triage.get(identity)
            if assessed is not None:
                assessment = assessed.get("assessed")
                detail = labelled_text(assessment, ("value", "source", "basis", "rule_or_prompt_version", "reason")) \
                    if assessment else labelled_text(assessed.get("gap") or {}, ("code", "reason"))
                raw = assessment.get("value") if assessment else (assessed.get("gap") or {}).get("code")
                self.decision(subject, c.Stage.SEVERITY_TRIAGE, "assessed" if assessment else "unresolved",
                              sources=(self.i.triage.ref(identity),), text=detail,
                              original=link(raw, c.AbsenceReason.LEGACY_UNRECORDED),
                              basis=c.BasisStatus.NARRATIVE_ONLY if detail else c.BasisStatus.UNSTATED)
        for package in self.i.packages:
            for lead in package.value.get("lead_menu", ()):
                self.decision(self.subject(lead=lead["observation_id"], package=package.value["package_id"]),
                              c.Stage.PACKAGE_ASSEMBLY, "supplied", sources=(package.ref(
                                  lead["observation_id"], c.EvidenceUse.SUPPLIED),),
                              text="Package membership records supply, not a worker read or citation.", original=link())
        if self.i.collection is None:
            return c.CoverageCount(c.Population.LEADS, None, len(admission), 0, None, c.CoverageReason.LEGACY_UNAVAILABLE)
        return c.CoverageCount(c.Population.LEADS, len(admission), len(admission), 0, 0, None)

    def proposals(self) -> c.CoverageCount:
        capture = {}
        legacy_cells = set()
        for lane in self.i.lanes:
            document = lane.value.get("proposal_audit")
            if document is None:
                legacy_cells.update(lane.value["expected_cells"])
                continue
            if set(document) != {"schema", "items"} or document["schema"] != PROPOSAL_CAPTURE_SCHEMA:
                raise IntegrityError("unsupported proposal membership capture")
            for row in document["items"]:
                if set(row) != {"package_id", "cell_id", "round", "proposal_ref", "claim_id",
                                "decision", "reason", "receipt_sha256"}:
                    raise IntegrityError("malformed proposal membership capture")
                key = (row["cell_id"], row["proposal_ref"])
                if key in capture:
                    raise IntegrityError("duplicate original proposal membership")
                capture[key] = (row, lane)
        seen = set()
        unknown = False
        unavailable = 0
        for cell_id, cell in sorted(self.cells.items()):
            if cell.role not in (Role.RED_TEAM_ANALYST, Role.HYPOTHESIS_HUNTER):
                continue
            receipt = self.i.receipts.get(cell_id)
            if receipt is None or cell.status != CellStatus.SUCCEEDED:
                unknown = unknown or cell.status != CellStatus.NOT_LAUNCHED
                continue
            result = receipt.value["result"]
            round_index = self.capabilities.get(cell_id, {}).get("round")
            local_ids = [item["local_id"] for item in result["proposals"]]
            if len(set(local_ids)) != len(local_ids):
                raise IntegrityError("duplicate proposal in original receipt")
            lead_ids = [item["observation_id"] for item in result["lead_accounting"]]
            if len(set(lead_ids)) != len(lead_ids):
                raise IntegrityError("duplicate receipt-local lead accounting")
            owners: dict[str, set[str]] = defaultdict(set)
            for row in result["lead_accounting"]:
                membership = row["proposal_ids"]
                if (not isinstance(membership, list) or any(not isinstance(item, str) for item in membership)
                        or len(set(membership)) != len(membership) or not set(membership) <= set(local_ids)):
                    raise IntegrityError("invalid receipt-local lead proposal membership")
                for local in membership:
                    owners[local].add(row["observation_id"])
                why = self.lead_reason(receipt, cell.package_id, row)
                self.decision(self.subject(lead=row["observation_id"], cell=cell_id, package=cell.package_id,
                                           round_index=round_index),
                              c.Stage.RED_DISCOVERY, row["outcome"], sources=(receipt.ref(row["observation_id"]),),
                              proposals=tuple(receipt.ref(local) for local in membership),
                              text=why, basis=c.BasisStatus.NARRATIVE_ONLY if why else c.BasisStatus.UNSTATED,
                              receipt=receipt, gaps=row.get("gap_ids", ()))
            for proposal in result["proposals"]:
                local = proposal["local_id"]
                source_leads = proposal["source_lead_ids"]
                if (not isinstance(source_leads, list) or any(not isinstance(item, str) for item in source_leads)
                        or len(set(source_leads)) != len(source_leads) or set(source_leads) != owners[local]):
                    raise IntegrityError("proposal source leads disagree with original lead accounting")
                key = (cell_id, local)
                seen.add(key)
                source = receipt.ref(local)
                bound = capture.get(key)
                claim = None
                gaps = ()
                if bound is None:
                    if cell_id not in legacy_cells:
                        raise IntegrityError("fresh membership capture omits an emitted proposal")
                    outcome, why = "unavailable", "Original proposal-to-claim membership was not recorded."
                    gaps = ("audit:proposal_membership_legacy_unrecorded",)
                    unavailable += 1
                    self.unavailable_decisions += 1
                    self.unavailable_proposal_membership = True
                else:
                    row, lane = bound
                    if (row["package_id"], row["receipt_sha256"], row["round"]) != (
                            cell.package_id, cell.receipt_sha256, round_index):
                        raise IntegrityError("proposal capture differs from its original cell receipt")
                    claim = row["claim_id"]
                    if claim is not None and claim not in self.i.projection.claims:
                        raise IntegrityError("proposal capture names an absent claim")
                    outcome, why = row["decision"], row["reason"]
                    if outcome not in ("admitted", "rejected", "over_cap"):
                        raise IntegrityError("unsupported captured proposal disposition")
                    if claim is not None:
                        self.origins[claim].append(source)
                subject = self.subject(proposal=local, cell=cell_id, claim=claim,
                                       package=cell.package_id, round_index=round_index)
                if bound is None:
                    subject = replace(subject, claim_id=link(None, c.AbsenceReason.LEGACY_UNRECORDED))
                self.decision(subject, c.Stage.RED_DISCOVERY, "emitted", sources=(source,), receipt=receipt,
                              text=why if bound is None else None, gaps=gaps, original=link(), proposals=(source,))
                if bound is not None:
                    self.decision(subject, c.Stage.CLAIM_CAP if outcome == "over_cap" else c.Stage.PROPOSAL_NORMALIZATION,
                                  outcome, sources=(source, bound[1].ref(local)), text=why, receipt=receipt,
                                  proposals=(source,),
                                  reason=c.ReasonCode.MISSING_EVIDENCE if why == "unresolvable_citation" else None)
        if set(capture) - seen:
            raise IntegrityError("capture contains a proposal absent from original receipts")
        return c.CoverageCount(c.Population.PROPOSALS, None if unknown else len(seen), len(seen) - unavailable, 0,
                               None if unknown else unavailable, c.CoverageReason.FAILED_INPUT if unknown else
                               c.CoverageReason.LEGACY_UNAVAILABLE if unavailable else None)

    def lead_reason(self, receipt: Document, package_id: str, row: Mapping[str, Any]) -> str | None:
        compact = receipt.value.get("compact_result")
        if compact is None or row["outcome"] == "proposal":
            return row.get("reason")
        if not isinstance(compact, Mapping):
            raise IntegrityError("malformed compact red result")
        # package_view/1 assigns L1..Ln in the immutable package's lead-menu order.
        package = self.packages.get(package_id)
        if package is None:
            return None
        labels = {f"L{index + 1}": item["observation_id"]
                  for index, item in enumerate(package.value.get("lead_menu", ()))}
        group = "no_claim" if row["outcome"] == "no_proposal" else "blocked"
        for item in compact.get(group, ()):
            token = item if isinstance(item, str) else item["lead"]
            if labels.get(token, token) == row["observation_id"]:
                return None if isinstance(item, str) else item.get("why")
        return None

    def relations(self, claim_id: str) -> tuple[c.RelationRef, ...]:
        deciding = set(self.adjudications.get(claim_id, {}).get("counted_relation_ids", ()))
        required = {item["predicate"] for item in self.adjudications.get(claim_id, {}).get("predicates", ())
                    if item["required"]}
        found = []
        for relation in self.i.projection.relations.get(claim_id, ()):
            cell = self.cells.get(relation.producing_cell_id)
            if cell is None:
                raise IntegrityError("relation has no original producing cell")
            role = Role.ADJUDICATION_JUDGE if relation.provenance == Role.ADJUDICATION_JUDGE else cell.role
            counted = relation.relation_id in deciding
            noncounted = (c.NoncountedReason.JUDGE_NONDECIDING if role == Role.ADJUDICATION_JUDGE else
                          c.NoncountedReason.INCOMPLETE if not relation.complete else
                          c.NoncountedReason.QUALIFYING if relation.kind == RelationKind.QUALIFIES else
                          c.NoncountedReason.ANALYST_ASSESSED if relation.admissibility == Admissibility.ANALYST_ASSESSED else
                          c.NoncountedReason.INDIRECT if relation.admissibility == Admissibility.INDIRECT else
                          c.NoncountedReason.NOT_REQUIRED if relation.predicate not in required else
                          c.NoncountedReason.NOT_EVALUATED)
            found.append(c.RelationRef(relation.relation_id, claim_id, relation.predicate, relation.kind,
                                      relation.producing_cell_id, role, relation.admissibility, counted,
                                      None if counted else noncounted,
                                      self.i.projection_document.ref(relation.relation_id, c.EvidenceUse.CITED)))
        if deciding - {item.relation_id for item in found}:
            raise IntegrityError("adjudication counts an absent relation")
        return tuple(found)

    def cells_and_verifiers(self) -> c.CoverageCount:
        expected = dict(self.i.additional_expected_cells)
        independent = {}
        for lane in self.i.lanes:
            for identity, value in lane.value["expected_cells"].items():
                if identity in expected:
                    raise IntegrityError("duplicate expected cell")
                expected[identity] = value
            for claim, rows in lane.value["independence"].items():
                for row in rows:
                    independent[(claim, row["verifier_cell_id"])] = row
        if set(self.cells) - set(expected):
            raise IntegrityError("terminal cell is outside the expected population")
        unavailable = 0
        for identity in sorted(expected):
            cell = self.cells.get(identity)
            if cell is None:
                unavailable += 1
                self.unavailable_decisions += 1
                continue
            receipt = self.i.receipts.get(identity)
            round_index = self.capabilities.get(identity, {}).get("round")
            subject = self.subject(cell=identity, claim=cell.claim_id, package=cell.package_id, round_index=round_index)
            chain_verifier = cell.role == Role.INDEPENDENT_VERIFIER and cell.task == "chain_weakest_link_verifier"
            gaps = (*cell.gap_ids, *(("audit:chain_verification_has_no_claim_coverage_contract",) if chain_verifier else ()))
            self.decision(subject, c.Stage.CELL_EXECUTION, cell.status.value,
                          sources=(self.i.projection_document.ref(identity),), gaps=gaps, receipt=receipt,
                          text=receipt.value.get("reason") if receipt else None)
            if chain_verifier:
                self.unavailable_verifications += 1
            elif cell.role == Role.INDEPENDENT_VERIFIER:
                if cell.claim_id is None:
                    raise IntegrityError("verifier terminal result lacks its original claim")
                self.verifier(subject, cell, receipt, independent.get((cell.claim_id, identity)))
        return c.CoverageCount(c.Population.CELLS, len(expected), len(expected) - unavailable, 0, unavailable,
                               c.CoverageReason.INPUT_UNAVAILABLE if unavailable else None)

    def verifier(self, subject, cell, receipt, independence):
        relations = self.relations(cell.claim_id)
        own = [item for item in relations if item.producing_cell_id == cell.cell_id]
        result = independence or {}
        structure = result.get("audit", {})
        request = self.i.request_checks.get(cell.cell_id)
        observed = ("actor_distinct", "conversation_fresh", "prior_response_absent", "shared_actor_cache_absent")
        if structure and (set(structure) != {"schema", *observed, "request_check", "request_markers_absent"}
                          or structure["schema"] != STRUCTURE_CAPTURE_SCHEMA
                          or any(type(structure[key]) is not bool for key in observed)
                          or (structure["request_markers_absent"] is not None
                              and type(structure["request_markers_absent"]) is not bool)):
            raise IntegrityError("unsupported verifier structural capture")
        structural = [check(structure.get(key)) for key in observed]
        passed = (all(item.value is True for item in structural) and structure["request_markers_absent"]
                  if structure and request and structure["request_markers_absent"] is not None else None)
        blindness = c.Blindness(*structural, c.OptionalSource(request.ref(cell.cell_id) if request else None,
                               None if request else c.AbsenceReason.LEGACY_UNRECORDED), check(passed))
        required = {item["predicate"] for item in self.adjudications.get(cell.claim_id, {}).get("predicates", ())
                    if item["required"]}
        predicates = []
        original = {item.relation_id: item for item in self.i.projection.relations.get(cell.claim_id, ())}
        for predicate in Predicate:
            matching = [item for item in own if item.predicate == predicate]
            supported, contradicted, qualified = [], [], []
            reads = []
            for item in matching:
                relation = original[item.relation_id]
                own_read = (receipt is not None and "reused_from" not in receipt.value
                            and relation.retrieval_receipt_sha256 == cell.receipt_sha256
                            and relation.entity_id in receipt.value["seen_identities"])
                if own_read:
                    reads.append(receipt.ref(cell.cell_id, c.EvidenceUse.READ))
                bucket = (supported if item.kind == RelationKind.SUPPORTS and item.counted and own_read else
                          contradicted if item.kind == RelationKind.CONTRADICTS and item.counted and own_read else
                          qualified if item.kind == RelationKind.QUALIFIES else None)
                if bucket is not None:
                    bucket.append(item.relation_id)
            if max(len(supported), len(contradicted), len(qualified)) > c.MAX_INLINE_REFERENCES:
                raise AuditUnavailable("verifier_predicate_reference_limit")
            unknown = receipt is None or cell.status != CellStatus.SUCCEEDED
            coverage = (c.SupportCoverage.UNKNOWN if unknown else
                        c.SupportCoverage.CONFLICTED if supported and contradicted else
                        c.SupportCoverage.SUPPORTED if supported else
                        c.SupportCoverage.CONTRADICTED if contradicted else c.SupportCoverage.MISSING)
            predicates.append(c.PredicateCoverage(predicate, predicate in required,
                tuple({canonical_json(item.to_dict()): item for item in reads}.values()), tuple(supported),
                tuple(contradicted), tuple(qualified), coverage, c.AbsenceReason.UNAVAILABLE if unknown else None))
        eligible = (cell.status == CellStatus.SUCCEEDED and passed is True and bool(required) and all(
            item.coverage == c.SupportCoverage.SUPPORTED for item in predicates if item.required))
        own_artifacts = {(item.entity_id, item.shard_id, item.content_sha256) for item in original.values()
                         if item.producing_cell_id == cell.cell_id}
        other_artifacts = {(item.entity_id, item.shard_id, item.content_sha256) for item in original.values()
                           if item.producing_cell_id != cell.cell_id}
        overlap = tuple(sorted({identity for identity, _, _ in own_artifacts & other_artifacts}))
        if len(overlap) > c.MAX_INLINE_REFERENCES:
            raise AuditUnavailable("evidence_overlap_reference_limit")
        self.add(c.VerificationRecord(
            self.context(subject, sources=(self.i.projection_document.ref(cell.cell_id),),
                         relations=own, proposals=self.origins.get(cell.claim_id, ()),
                         gaps=tuple(result.get("gap_ids", ())) + (
                             ("audit:verifier_structure_legacy_unrecorded",) if not structure else ()) + (
                             ("audit:verifier_request_bytes_not_observed",)
                             if structure and structure["request_markers_absent"] is None else ()) + (
                             ("audit:verifier_memo_reuse_without_own_reads",)
                             if receipt is not None and "reused_from" in receipt.value else ())),
            cell.status, c.OptionalSource(receipt.ref(cell.cell_id) if receipt else None,
                                          None if receipt else c.AbsenceReason.NOT_PRODUCED),
            blindness, c.Diversity(check(result.get("provider_distinct") if cell.status == CellStatus.SUCCEEDED else None),
                                  check(result.get("verifier_model_distinct")),
                                  link(None, c.AbsenceReason.UNKNOWN_MODEL_REVISION)),
            tuple(predicates), c.EvidenceOverlap(overlap, (), check(True)),
            check(eligible if passed is not None else None), check(result.get("independent"))))

    def claims(self) -> None:
        for identity, view in sorted(self.i.projection.claims.items()):
            row = self.adjudications.get(identity)
            if row is None:
                raise AuditUnavailable("input_unavailable:adjudication")
            if row["state"] != view.claim.state:
                raise IntegrityError("adjudication and final claim state differ")
            relations = self.relations(identity)
            required = tuple(Predicate(item["predicate"]) for item in row["predicates"] if item["required"])
            missing = tuple(Predicate(item["predicate"]) for item in row["predicates"]
                            if item["required"] and item["outcome"] != "satisfied")
            subject = self.subject(claim=identity, package=view.claim.package_id, adjudication=row["adjudication_id"],
                                   round_index=row["round"])
            sources = (self.i.adjudications.ref(row["adjudication_id"]), self.i.projection_document.ref(identity))
            self.decision(subject, c.Stage.ADJUDICATION, row["state"], sources=sources, relations=relations,
                          proposals=self.origins.get(identity, ()), gaps=row["gap_ids"], row=row["deciding_row"],
                          required=required, missing=missing, reason=_ROWS[row["deciding_row"]],
                          text=f"Existing deciding row {row['deciding_row']}; policy={row['policy_sha256']}.")
            for judge in self.i.projection.judge_verdicts.get(identity, ()):
                judge_cell = self.cells[judge.cell_id]
                judged_subject = self.subject(claim=identity, cell=judge.cell_id, package=judge_cell.package_id,
                    round_index=self.capabilities.get(judge.cell_id, {}).get("round"))
                self.decision(judged_subject, c.Stage.JUDGE_REVIEW, judge.verdict.value,
                              sources=(self.i.projection_document.ref(judge.verdict_id),), text=judge.reason,
                              basis=c.BasisStatus.CITED_NONDECIDING)
            for score in self.claim_scores.get(identity, ()):
                outcome = "unrated" if "technical_severity" in score and score["technical_severity"] is None else "scored"
                self.decision(subject, c.Stage.SCORING, outcome, sources=(self.i.scores.ref(score["score_id"]),),
                              original=link(score.get("technical_severity"), c.AbsenceReason.NOT_PRODUCED),
                              text=labelled_text(score, ("technical_severity", "provider", "band")))
        for finding in self.i.findings:
            body = finding.value
            identity = body["claim_id"]
            row = self.adjudications[identity]
            view = self.i.projection.claims[identity]
            if (body["state"] not in ("confirmed", "supported") or body["state"] != row["state"]
                    or body["adjudication_id"] != row["adjudication_id"]):
                raise IntegrityError("finding is not an accepted supported or confirmed claim")
            subject = self.subject(claim=identity, package=view.claim.package_id, adjudication=row["adjudication_id"],
                                   finding=body["finding_package_id"], round_index=row["round"])
            self.decision(subject, c.Stage.PUBLICATION, body["state"],
                          sources=(finding.ref(body["finding_package_id"]),), reason=c.ReasonCode.PUBLICATION_POLICY)
            decisions = tuple(c.RecordRef.of(item) for item in self.records if isinstance(item, c.DecisionRecord)
                              and item.context.subject.claim_id.value == identity)
            verifications = [item for item in self.records if isinstance(item, c.VerificationRecord)
                             and item.context.subject.claim_id.value == identity]
            verifications.sort(key=lambda item: (item.existing_r6_passed.value is not True, item.record_id))
            if len(decisions) > c.MAX_INLINE_REFERENCES:
                raise AuditUnavailable("decision_basis_reference_limit")
            self.add(c.DecisionBasisRecord(
                self.context(subject, relations=self.relations(identity), proposals=self.origins.get(identity, ()),
                             gaps=() if self.origins.get(identity) and not self.unavailable_proposal_membership
                             else ("audit:proposal_membership_legacy_unrecorded",)),
                self.i.projection_document.ref(identity), finding.ref(body["finding_package_id"]),
                self.i.adjudications.ref(row["adjudication_id"]), decisions,
                c.OptionalRecord(c.RecordRef.of(verifications[0]) if verifications else None,
                                 None if verifications else c.AbsenceReason.NOT_COMMISSIONED),
                tuple(Predicate(item["predicate"]) for item in row["predicates"] if item["required"]),
                tuple(Predicate(item["predicate"]) for item in row["predicates"]
                      if item["required"] and item["outcome"] != "satisfied"),
                tuple(self.i.projection_document.ref(judge.verdict_id)
                      for judge in self.i.projection.judge_verdicts.get(identity, ())),
                tuple(self.i.scores.ref(score["score_id"]) for score in self.claim_scores.get(identity, ()))))


def project(inputs: ProjectionInputs, *, settings: DecisionAuditSettings, directory: str) -> AuditProjection:
    """Project verified inputs without mutating them or recalculating any deciding policy."""
    DecisionAuditSettings.from_mapping(asdict(settings), "decision_audit")
    if not settings.enabled:
        raise AuditUnavailable("disabled")
    if (inputs.origin.projection_policy_version != PROJECTION_POLICY_VERSION
            or inputs.origin.projection_policy_sha256 != policy_sha256(settings)):
        raise IntegrityError("audit policy differs from the accepted configuration")
    if (inputs.projection.head != inputs.origin.ledger_head_sha256
            or inputs.projection.sha256() != inputs.origin.projection_sha256
            or inputs.projection.to_json() != inputs.projection_document.value):
        raise IntegrityError("audit projection differs from accepted ledger projection")
    projector = _Projector(inputs, settings, directory)
    leads = projector.leads()
    proposals = projector.proposals()
    cells = projector.cells_and_verifiers()
    projector.claims()
    counts = tuple(c.CoverageCount(population, count + absent, count, 0, absent,
                                   c.CoverageReason.PARTIAL_INPUT if absent else None) for population, cls in (
        (c.Population.DECISIONS, c.DecisionRecord), (c.Population.VERIFICATIONS, c.VerificationRecord),
        (c.Population.BASES, c.DecisionBasisRecord)) for count in (
            sum(isinstance(item, cls) for item in projector.records),)
        for absent in (projector.unavailable_decisions if population == c.Population.DECISIONS else
                       projector.unavailable_verifications if population == c.Population.VERIFICATIONS else 0,))
    return AuditProjection(tuple(projector.records), (*counts, leads, cells, proposals), projector.continuations)
