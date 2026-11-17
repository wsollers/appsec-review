"""Protected, bounded dossiers: accepted evidence in, renderer-neutral documents out.

Only explicitly selected fields cross this boundary. Inference recordings, prompts and arbitrary
producer dictionaries are never copied. Literal redaction is deliberately conservative; the
accepted upstream artifacts retain their original bytes for authorized investigation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from typing import Any, Mapping, Sequence, cast

from appsec_review.jobs.completion_contracts import (
    DOSSIER_SCHEMA, DossierKind, FindingBinding, nonexecution_assurance, verify_nonexecution_assurance,
)
from appsec_review.review.models import IntegrityError
from appsec_review.review.decision_audit.contracts import DecisionRecord, VerificationRecord
from appsec_review.review.decision_audit.reader import AcceptedAudit
from appsec_review.review.secret_redaction import redact_source_line
from appsec_review.storage import canonical_json
from .digest import bullets, code, field, table
from .dimensions import DIMENSIONS, dimension_of_package, owasp_of_cwe_or_domain
from .model import Box, Document, Fields, Heading, Para, Stat, Stats
from .text import bound, bound_lines, clean
from .tokens import BoxKind, Limits

RENDERER = "appsec-review/dossier-renderer/1"
RISK_DIMENSIONS = ("technical_severity", "exploitability_confidence", "environmental_business_impact",
                   "remediation_priority")
POC_STATUSES = frozenset({"compile_verified", "compile_failed", "artifact_generated", "policy_denied",
                          "insufficient_evidence", "not_applicable", "unsafe_to_attempt"})
NOTICES = (
    "Protected developer artifact. Not a public report; source excerpts and generated functions are inert data.",
    "Compile-only assurance: nothing is linked, loaded or executed. Runtime verification was not performed.",
    "A confirmed finding is not automatically reproduced; a build-checked proposal is not a resolved finding.",
)
_DIM_BY_KEY = {dim.key: dim for dim in DIMENSIONS}


@dataclass(frozen=True, slots=True)
class DossierLimits:
    text_chars: int = 1800
    code_lines: int = 40
    code_chars: int = 4000
    evidence_rows: int = 24
    source_excerpts: int = 4

    def __post_init__(self) -> None:
        for key, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"dossier limit {key} must be positive")


class _Projection:
    def __init__(self, limits: DossierLimits):
        self.limits = limits
        self.cuts: list[dict[str, Any]] = []

    def text(self, value: Any, name: str, *, identity: bool = False) -> str:
        raw = clean(value, keep_newlines=True)
        redacted = raw if identity else "\n".join(redact_source_line(line, assignments=False)
                                                  for line in raw.split("\n"))
        text, cut = bound(redacted, self.limits.text_chars)
        if cut:
            self.cuts.append({"field": name, **asdict(cut)})
        return text

    def rows(self, values: Sequence[Any], name: str, *, limit: int | None = None) -> list[Any]:
        maximum = self.limits.evidence_rows if limit is None else limit
        ordered = sorted(values, key=lambda row: canonical_json(row))
        if len(ordered) > maximum:
            self.cuts.append({"field": name, "omitted": len(ordered) - maximum, "unit": "rows",
                              "sha256": hashlib.sha256(canonical_json(ordered)).hexdigest()})
        return ordered[:maximum]

    def source(self, text: str, name: str) -> str:
        redacted = "\n".join(redact_source_line(line) for line in clean(
            text, keep_newlines=True, code=True).split("\n"))
        text, cut = bound_lines(redacted, self.limits.code_lines, self.limits.code_chars)
        if cut:
            self.cuts.append({"field": name, **asdict(cut)})
        return text


def _safe_str(value: Any, max_chars: int = 600, *, identity: bool = False) -> str:
    raw = clean(value, keep_newlines=True)
    if not identity:
        raw = "\n".join(redact_source_line(line, assignments=False) for line in raw.split("\n"))
    kept, _ = bound(raw, max_chars)
    return kept


def _safe_diff(value: Any, limits: DossierLimits) -> str | None:
    if value is None:
        return None
    raw = clean(value, keep_newlines=True, code=True)
    if not raw:
        return None
    redacted = "\n".join(redact_source_line(line) for line in raw.split("\n"))
    kept, _ = bound_lines(redacted, limits.code_lines, limits.code_chars)
    return kept or None


def _build_classification_badge(
    *,
    state: str,
    title: str,
    weakness_cwe: str,
    security_predicate: str,
    ship_block: Mapping[str, str],
    evidence: Sequence[Mapping[str, Any]],
    sources: Sequence[Mapping[str, Any]],
    claim: Mapping[str, Any],
) -> dict[str, Any]:
    pseudo_pkg = {"title": title}
    pseudo_dossier = {"weakness_cwe": weakness_cwe, "security_predicate": security_predicate}
    dim_key = dimension_of_package(pseudo_pkg, pseudo_dossier)
    dim = _DIM_BY_KEY.get(dim_key) if dim_key else None
    domain_id = dim.domain_id if dim else "unclassified"
    domain_label = dim.label if dim else "Unclassified"
    owasp = owasp_of_cwe_or_domain(weakness_cwe or None, domain_id if dim else None) or "unmapped"
    tier = _safe_str(claim.get("resolution_tier"), 120, identity=True)
    if not tier:
        methods = [row["mapping_method"] for row in sources if row.get("mapping_method") and row["mapping_method"] != "not recorded"]
        tier = methods[0] if methods else ("source_excerpt_bound" if sources else "evidence_citation_only")
    scanners: set[str] = set()
    for s in claim.get("corroborating_scanners") or ():
        val = _safe_str(s, 120, identity=True)
        if val:
            scanners.add(val)
    for ev in evidence:
        for k in ("shard_id", "entity_kind"):
            val = _safe_str(ev.get(k), 120, identity=True)
            if val:
                scanners.add(val)
    reachability = "confirmed_reachable" if state == "confirmed" else (state or "unconfirmed")
    return {
        "severity": (ship_block.get("technical_severity") or "unassessed").lower(),
        "weakness_cwe": weakness_cwe or "not_recorded",
        "owasp_2025": owasp,
        "radar_domain_id": domain_id,
        "radar_domain_label": domain_label,
        "reachability_badge": reachability,
        "resolution_tier": tier,
        "corroborating_scanners": sorted(scanners)[:16],
        "ship_block_status": ship_block.get("status") or "not_recorded",
    }


def _build_taint_timeline(
    *,
    claim: Mapping[str, Any],
    finding: Mapping[str, Any],
    sources: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    raw_steps = claim.get("taint_path") or finding.get("taint_path") or ()
    steps: list[dict[str, Any]] = []
    if isinstance(raw_steps, Sequence) and not isinstance(raw_steps, (str, bytes)) and raw_steps:
        total = min(len(raw_steps), 24)
        for idx, item in enumerate(raw_steps[:total]):
            if not isinstance(item, Mapping):
                continue
            role = str(item.get("role") or "")
            if role not in {"source", "hop", "guard_check", "sink"}:
                role = "source" if idx == 0 else ("sink" if idx == total - 1 else "hop")
            path = _safe_str(item.get("path"), 240, identity=True)
            s_line = item.get("start_line") if isinstance(item.get("start_line"), int) else (
                item.get("line") if isinstance(item.get("line"), int) else None
            )
            e_line = item.get("end_line") if isinstance(item.get("end_line"), int) else s_line
            loc = f"{path}:{s_line}" if path and s_line is not None else (path or _safe_str(item.get("location"), 240) or "unlocated")
            steps.append({
                "step_index": len(steps) + 1,
                "role": role,
                "location": loc,
                "path": path,
                "start_line": s_line,
                "end_line": e_line,
                "symbol": _safe_str(item.get("symbol"), 180) or "not_recorded",
                "taint_transform": _safe_str(item.get("taint_transform") or item.get("transform"), 300) or "direct_propagation",
                "guard_disposition": _safe_str(item.get("guard_disposition") or item.get("guard"), 300) or "no_blocking_guard_on_path",
                "entity_id": _safe_str(item.get("entity_id"), 180, identity=True),
            })
    if steps:
        return steps

    candidates: list[dict[str, Any]] = []
    seen_locs: set[str] = set()
    for src in sources:
        path = src.get("path") or ""
        s_line = src.get("start_line") if isinstance(src.get("start_line"), int) else None
        e_line = src.get("end_line") if isinstance(src.get("end_line"), int) else s_line
        loc = f"{path}:{s_line}" if path and s_line is not None else (path or src.get("entity_id") or "unlocated")
        if loc in seen_locs:
            continue
        seen_locs.add(loc)
        candidates.append({
            "location": loc,
            "path": path,
            "start_line": s_line,
            "end_line": e_line,
            "symbol": src.get("source_id") or src.get("entity_id") or "not_recorded",
            "taint_transform": f"resolved via {src.get('mapping_method') or 'source_excerpt'}",
            "guard_disposition": "no_blocking_guard_established",
            "entity_id": src.get("entity_id") or "",
        })
    for ev in evidence:
        loc = ev.get("locator") or ev.get("entity_id") or "unlocated"
        if loc in seen_locs:
            continue
        seen_locs.add(loc)
        candidates.append({
            "location": loc,
            "path": ev.get("locator") or "",
            "start_line": None,
            "end_line": None,
            "symbol": ev.get("entity_id") or "not_recorded",
            "taint_transform": f"{ev.get('predicate') or 'evidence'} ({ev.get('kind') or 'citation'})",
            "guard_disposition": "analyst_assessed_nonblocking" if ev.get("strength") != "counted_direct" else "verified_unblocked_citation",
            "entity_id": ev.get("entity_id") or "",
        })
    total = min(len(candidates), 16)
    for idx, item in enumerate(candidates[:total]):
        role = "sink" if total == 1 else ("source" if idx == 0 else ("sink" if idx == total - 1 else "hop"))
        steps.append({"step_index": idx + 1, "role": role, **item})
    return steps


def _build_adjudication_summary(
    *,
    state: str,
    statement: str,
    preconditions: Sequence[str],
    missing_predicates: Sequence[str],
    evidence: Sequence[Mapping[str, Any]],
    sources: Sequence[Mapping[str, Any]],
    claim: Mapping[str, Any],
) -> dict[str, Any]:
    counted = [ev["relation_id"] for ev in evidence if ev["strength"] == "counted_direct"]
    analyst = [ev["relation_id"] for ev in evidence if ev["strength"] != "counted_direct"]
    basis_text = statement or "Accepted finding statement not recorded."
    if preconditions:
        basis_text = _safe_str(f"{basis_text} Preconditions: {'; '.join(preconditions[:4])}.", 900)
    guard_note = _safe_str(claim.get("guard_analysis"), 600)
    if not guard_note:
        if missing_predicates:
            guard_note = f"Open proof obligations remain: {', '.join(missing_predicates)}."
        elif state == "confirmed":
            guard_note = (
                f"Adjudication confirmed exploitability across {len(counted)} counted direct citation(s); "
                "candidate guards did not sanitize or block the taint path before the sink."
            )
        else:
            guard_note = f"Adjudication state is {state}; independent blocking guard was not established."
    src_by_entity = {src["entity_id"]: src for src in sources if src.get("entity_id")}
    resolving: list[dict[str, str]] = []
    for ev in evidence[:16]:
        matched_src = src_by_entity.get(ev["entity_id"])
        path = matched_src["path"] if matched_src else ""
        if matched_src and matched_src.get("start_line") is not None:
            span = f"{matched_src['start_line']}-{matched_src.get('end_line') or matched_src['start_line']}"
        else:
            span = "not_recorded"
        resolving.append({
            "relation_id": ev["relation_id"],
            "locator": ev["locator"] or path or ev["entity_id"],
            "path": path,
            "line_span": span,
            "content_sha256": ev["content_sha256"],
        })
    posture = "confirmed_independent" if state == "confirmed" and not missing_predicates else "bounded_adjudication"
    return {
        "exploitability_basis": _safe_str(basis_text, 900) or "Not recorded.",
        "guard_bypass_summary": guard_note,
        "verifier_posture": posture,
        "counted_direct_citations": counted,
        "analyst_assessed_citations": analyst,
        "resolving_citations": resolving,
    }


def _build_poc_harness_summary(poc_view: Mapping[str, Any] | None) -> dict[str, Any]:
    if poc_view is None:
        return {
            "available": False,
            "compile_status": "not_available",
            "compile_only_verified": False,
            "safety_badge": "not_performed_by_policy",
            "generated_code_execution": "not_performed_by_policy",
            "runtime_verified": False,
            "summary": "No PoC harness outcome was attached. Generated code execution is not_performed_by_policy.",
        }
    compile_ok = poc_view["status"] == "compile_verified"
    reason = poc_view.get("reason") or poc_view.get("description") or poc_view["notice"]
    return {
        "available": True,
        "compile_status": poc_view["status"],
        "compile_only_verified": compile_ok,
        "safety_badge": "not_performed_by_policy",
        "generated_code_execution": "not_performed_by_policy",
        "runtime_verified": False,
        "summary": _safe_str(
            f"Status: {poc_view['status']} ({'compile-only verified' if compile_ok else 'not compile-verified'}). "
            f"{reason} Execution: not_performed_by_policy.",
            600,
        ),
    }


def _build_remediation_guide(
    *,
    remedies: Sequence[Mapping[str, Any]],
    raw_remediation: Sequence[Mapping[str, Any]],
    weakness_cwe: str,
    security_predicate: str,
    limits: DossierLimits,
) -> dict[str, Any]:
    tier = "manual_design_required"
    violated = ""
    corrected = ""
    steps: list[str] = []
    checklist: list[str] = []
    for row in remedies:
        status = row.get("status") or ""
        check_map = {chk["dimension"]: chk["status"] for chk in row.get("checks") or ()}
        if status == "build_checked" or check_map.get("build") == "passed":
            tier = "build_checked"
        elif tier != "build_checked" and (
            status in {"static_checked", "in_memory_patch_and_syntax_verified"}
            or check_map.get("static_checks") == "passed"
            or check_map.get("patch_applicability") == "passed"
        ):
            tier = "in_memory_patch_and_syntax_verified"
        elif tier == "manual_design_required" and status in {"planned", "proposed"}:
            tier = "proposal_only"
        if not violated and row.get("violated_invariant"):
            violated = row["violated_invariant"]
        if not corrected and row.get("corrected_invariant"):
            corrected = row["corrected_invariant"]
        if row.get("corrected_invariant"):
            steps.append(f"Enforce invariant: {row['corrected_invariant']}")
        for iface in row.get("affected_interfaces") or ():
            steps.append(f"Update affected interface: {iface}")
        for prereq in row.get("deployment_prerequisites") or ():
            steps.append(f"Deployment prerequisite: {prereq}")
        for vc in row.get("validation_checks") or ():
            checklist.append(vc)
        if row.get("regression_safety"):
            checklist.append(f"Regression safety assertion: {row['regression_safety']}")
    proposed_diff: str | None = None
    for raw_row in sorted(raw_remediation, key=lambda r: canonical_json(r)):
        candidate = raw_row.get("proposed_patch") or raw_row.get("unified_diff")
        proposed_diff = _safe_diff(candidate, limits)
        if proposed_diff:
            break
    if not steps:
        target_desc = f"{weakness_cwe} ({security_predicate})" if weakness_cwe and security_predicate else (
            weakness_cwe or security_predicate or "the vulnerable sink"
        )
        steps.append(f"Introduce strict input validation or structural parameterization before {target_desc}.")
    checklist.append(
        "Verify fix compiles cleanly and passes existing unit/integration suites in CI "
        "(runtime regression is not_performed_by_policy during review)."
    )
    dedup_steps = list(dict.fromkeys(steps))[:12]
    dedup_checks = list(dict.fromkeys(checklist))[:12]
    return {
        "validation_tier": tier,
        "violated_invariant": violated or "Not recorded in upstream remediation plan.",
        "corrected_invariant": corrected or "Enforce explicit boundary validation prior to sink.",
        "proposed_diff": proposed_diff,
        "concrete_fix_steps": dedup_steps,
        "verification_checklist": dedup_checks,
    }


def audit_relation_ids(audit: AcceptedAudit, finding: Mapping[str, Any]) -> frozenset[str]:
    """Only a verified basis for these exact accepted finding bytes can extend excerpt selection."""
    basis = audit.basis(finding["claim_id"])
    if basis is None:
        return frozenset()
    if (basis.context.subject.finding_package_id.value != finding["finding_package_id"]
            or basis.context.subject.adjudication_id.value != finding["adjudication_id"]
            or basis.finding.sha256 != finding["sha256"]
            or basis.finding.path != finding["path"]):
        raise IntegrityError("dossier decision basis belongs to another accepted finding")
    return frozenset(row.relation_id for row in audit.relations(basis))


def _decision_basis(audit: AcceptedAudit, finding: Mapping[str, Any], relations: Mapping[str, Mapping[str, Any]],
                    provenance: Mapping[str, Any], project: _Projection) -> dict[str, Any]:
    identities = audit_relation_ids(audit, finding)
    if not identities <= set(relations):
        raise IntegrityError("dossier audit relations are absent from the accepted projection")
    basis = audit.basis(finding["claim_id"])
    if basis is None:
        return {"available": False, "reason": audit.unavailable_reason or "decision_basis_not_emitted",
                "coverage": [] if audit.manifest is None else [row.to_dict() for row in audit.manifest.coverage]}
    origin = basis.context.origin
    if (origin.ledger_head_sha256 != provenance.get("ledger_head_sha256")
            or origin.review_handoff_sha256 != (provenance.get("review_handoff") or {}).get("sha256")
            or {"path": basis.claim.path, "sha256": basis.claim.sha256} != provenance.get("projection")):
        raise IntegrityError("dossier audit basis does not bind this accepted ledger and review")
    evidence = []
    for relation in project.rows([row.to_dict() for row in audit.relations(basis)], "decision_basis.relations"):
        original = relations[relation["relation_id"]]
        evidence.append({key: project.text(relation[key], "decision_basis." + key, identity=key == "relation_id")
                         for key in ("relation_id", "predicate", "kind", "actor_role", "admissibility",
                                     "noncounted_reason")} | {
            "counted_by_existing_policy": relation["counted"],
            "entity_id": project.text(original["entity_id"], "decision_basis.entity_id", identity=True),
            "locator": project.text(original.get("locator"), "decision_basis.locator"),
            "source": relation["source"],
            "notice": "Original policy attribution, not added supporting evidence."})
    linked = {ref.record_id for ref in basis.decisions}
    decisions = [{"record_id": row.record_id, "stage": row.stage.value, "outcome": row.outcome,
                  "reason_code": row.reason_code.value, "basis_status": row.basis_status.value,
                  "explanation": project.text(row.context.explanation.text, "decision_basis.explanation"),
                  "explanation_absence_reason": row.context.explanation.absence_reason}
                 for row in audit.records if isinstance(row, DecisionRecord) and row.record_id in linked]
    verification = None
    if basis.verification.value is not None:
        record = cast(VerificationRecord, next(
            row for row in audit.records if row.record_id == basis.verification.value.record_id))
        verification = {
            "record_id": record.record_id, "status": record.status.value,
            "blindness": record.blindness.passed.to_dict(), "diversity": record.diversity.to_dict(),
            "confirmation_eligible": record.confirmation_eligible.to_dict(),
            "existing_r6_passed": record.existing_r6_passed.to_dict(),
            "predicates": project.rows([row.to_dict() for row in record.predicates], "decision_basis.predicates")}
    return {
        "available": True, "record_id": basis.record_id, "sha256": basis.sha256,
        "manifest": {"path": audit.reference.path, "sha256": audit.reference.sha256},
        "relations": evidence, "decisions": project.rows(decisions, "decision_basis.decisions"),
        "verification": verification, "verification_absence_reason": basis.verification.absence_reason,
        "judge_verdicts": project.rows([row.to_dict() for row in basis.judge_verdicts], "decision_basis.judges"),
        "required_predicates": [row.value for row in basis.required_predicates],
        "missing_predicates": [row.value for row in basis.missing_predicates],
        "coverage": [row.to_dict() for row in audit.manifest.coverage],
        "notice": "Judge dissent is nondeciding. Opposing, qualifying and noncounted citations are not new support."}


def build_dossier(*, run_id: str, kind: DossierKind | str, finding: Mapping[str, Any],
                  claim: Mapping[str, Any], relations: Sequence[Mapping[str, Any]],
                  excerpts: Sequence[Mapping[str, Any]] = (), poc: Mapping[str, Any] | None = None,
                  poc_source: str | None = None, remediation: Sequence[Mapping[str, Any]] = (),
                  chains: Sequence[Mapping[str, Any]] = (), provenance: Mapping[str, Any],
                  gaps: Sequence[str] = (), limits: DossierLimits = DossierLimits(),
                  decision_audit: AcceptedAudit | None = None) -> dict[str, Any]:
    """Build a closed, deterministic model from already verified accepted records."""
    kind = DossierKind(kind)
    binding = FindingBinding.from_mapping({key: finding[key] for key in (
        "claim_id", "finding_package_id", "sha256")})
    if claim.get("claim_id") != binding.claim_id or claim.get("state") != finding["state"]:
        raise IntegrityError("dossier claim disagrees with its accepted finding")
    if kind == DossierKind.CONFIRMED_FINDING and finding["state"] != "confirmed":
        raise IntegrityError("a confirmed-finding dossier requires a confirmed finding")
    if kind == DossierKind.POC and poc is None:
        raise IntegrityError("a PoC dossier requires an accepted candidate outcome")
    project = _Projection(limits)
    evidence = []
    cited = set(finding.get("direct_evidence", ())) | set(finding.get("analyst_assessed_evidence", ()))
    by_id = {row["relation_id"]: row for row in relations}
    if not cited <= set(by_id):
        raise IntegrityError("dossier finding cites relations absent from the accepted projection")
    for relation in project.rows([by_id[key] for key in cited], "evidence"):
        evidence.append({key: project.text(relation.get(key), "evidence." + key, identity=key in {
            "relation_id", "entity_id", "content_sha256", "retrieval_receipt_sha256", "shard_id"})
                         for key in ("relation_id", "predicate", "kind", "admissibility", "entity_id",
                                     "entity_kind", "content_sha256", "locator", "shard_id",
                                     "retrieval_receipt_sha256")} | {
            "complete": relation.get("complete") is True,
            "strength": "counted_direct" if relation["relation_id"] in finding.get("direct_evidence", ())
                        else "analyst_assessed_not_counted"})
    sources = []
    for row in project.rows(excerpts, "sources", limit=limits.source_excerpts):
        sources.append({
            "entity_id": project.text(row.get("identity"), "source.identity", identity=True),
            "path": project.text((row.get("location") or {}).get("path"), "source.path", identity=True),
            "source_id": project.text((row.get("location") or {}).get("source_id"), "source.id", identity=True),
            "file_sha256": project.text((row.get("location") or {}).get("file_sha256"), "source.hash", identity=True),
            "mapping_method": project.text((row.get("location") or {}).get("mapping_method") or "not recorded",
                                            "source.mapping"),
            "mapping_confidence": (row.get("location") or {}).get("confidence"),
            "mapping_ambiguous": (row.get("location") or {}).get("ambiguous"),
            "target_snapshot": project.text((row.get("location") or {}).get("target_snapshot"),
                                             "source.snapshot", identity=True),
            "start_line": row.get("excerpt_start_line"), "end_line": row.get("excerpt_end_line"),
            "excerpt": project.source(str(row.get("excerpt") or ""), "source.excerpt"),
            "upstream_truncated": row.get("excerpt_truncated") is True,
        })
    scores = []
    for score in project.rows(finding.get("scores", ()), "scores"):
        dimensions = {}
        for key in RISK_DIMENSIONS:
            dimension = score.get(key)
            dimensions[key] = None if dimension is None else {
                name: project.text(dimension.get(name), "risk." + key + "." + name)
                for name in ("scale", "rating", "value")}
        scores.append({"score_id": score["score_id"], "sha256": score["sha256"],
                       "provider": project.text((score.get("provider") or {}).get("id"), "score.provider", identity=True),
                       **dimensions, "missing_factors": sorted(score.get("missing_factors", ()))})
    poc_view = None
    if poc is not None:
        if poc.get("status") not in POC_STATUSES:
            raise IntegrityError("dossier PoC status is unsupported")
        verify_nonexecution_assurance(poc)
        poc_view = {key: project.text(poc.get(key), "poc." + key)
                    for key in ("status", "reason", "description")}
        poc_view.update(nonexecution_assurance())
        poc_view["notice"] = ("COMPILE VERIFIED ONLY - NOT RUNTIME PROOF" if poc["status"] == "compile_verified"
                              else "NOT RUNTIME PROOF - " + poc["status"].replace("_", " ").upper())
        poc_view["negative_control"] = "Compile-checked only when recorded; never observed to pass."
        poc_view["source"] = None if poc_source is None else project.source(poc_source, "poc.source")
        poc_view["files"] = {key: dict(ref) for key, ref in sorted((poc.get("files") or {}).items())
                             if key in {"source", "compile", "provenance"}}
    remedies = []
    for row in project.rows(remediation, "remediation"):
        details = {key: [project.text(item, "remediation." + key) for item in project.rows(
            row.get(key) or (), "remediation." + key)] for key in (
                "compatibility_effects", "affected_interfaces", "residual_risks", "deployment_prerequisites",
                "validation_checks", "scope_limitations")}
        specification = row.get("regression_spec") or {}
        safety = project.text(specification.get("safety_assertion"), "remediation.regression_safety")
        checks = row.get("checks") or {}
        check_views = [{"dimension": name, "status": project.text(checks[name].get("status"), "validation.status"),
                        "reason": project.text(checks[name].get("reason"), "validation.reason"),
                        "artifact": checks[name].get("artifact")}
                       for name in ("patch_applicability", "policy", "semantic_review", "static_checks", "build",
                                    "regression_compile", "runtime_regression") if name in checks]
        remedies.append({key: project.text(row.get(key), "remediation." + key)
                         for key in ("stage", "status", "reason", "violated_invariant", "corrected_invariant",
                                     )} | details | {
            "artifact": row.get("artifact"),
            "regression_safety": safety, "checks": check_views,
            "runtime_regression": "not_performed_by_policy",
            "notice": "Proposal/checks only. Not fixed, resolved, or regression verified."})
    chain_views = []
    for row in project.rows(chains, "chains"):
        chain_views.append({key: project.text(row.get(key), "chain." + key, identity=key == "chain_id")
                            for key in ("chain_id", "status", "objective")} | {
            "qualifications": [project.text(item, "chain.qualification")
                               for item in project.rows(row.get("qualifications", ()), "chain.qualifications")]})
    gap_list = set(gaps) | set(finding.get("gap_ids", ()))
    if not sources:
        gap_list.add("source_excerpt_unavailable: no resolving source excerpt was available")
    if any(row["upstream_truncated"] for row in sources):
        gap_list.add("source_excerpt_truncated: accepted retrieval returned bounded source")
    identity = {"run_id": run_id, "kind": kind.value, "finding": binding.as_dict()}
    title_proj = project.text(finding.get("title"), "title")
    lane_proj = project.text(finding.get("lane"), "lane")
    statement_proj = project.text(claim.get("statement"), "statement")
    cwe_proj = project.text(claim.get("weakness_cwe"), "weakness")
    pred_proj = project.text(claim.get("security_predicate"), "security_predicate")
    precond_proj = [project.text(item, "precondition")
                    for item in project.rows(claim.get("preconditions", ()), "preconditions")]
    ship_proj = {key: project.text((finding.get("ship_block") or {}).get(key), "shipment." + key)
                 for key in ("policy", "status", "technical_severity")}
    missing_preds = sorted(finding.get("missing_predicates", ()))
    gaps_proj = [project.text(item, "gap") for item in sorted(gap_list)]

    classification_badge = _build_classification_badge(
        state=finding["state"],
        title=title_proj,
        weakness_cwe=cwe_proj,
        security_predicate=pred_proj,
        ship_block=ship_proj,
        evidence=evidence,
        sources=sources,
        claim=claim,
    )
    taint_path_timeline = _build_taint_timeline(
        claim=claim, finding=finding, sources=sources, evidence=evidence
    )
    adjudication_summary = _build_adjudication_summary(
        state=finding["state"],
        statement=statement_proj,
        preconditions=precond_proj,
        missing_predicates=missing_preds,
        evidence=evidence,
        sources=sources,
        claim=claim,
    )
    poc_harness_summary = _build_poc_harness_summary(poc_view)
    remediation_guide = _build_remediation_guide(
        remedies=remedies,
        raw_remediation=remediation,
        weakness_cwe=cwe_proj,
        security_predicate=pred_proj,
        limits=limits,
    )

    audit_view = None if decision_audit is None else _decision_basis(
        decision_audit, finding, by_id, provenance, project)
    return {
        "schema": DOSSIER_SCHEMA,
        "dossier_id": "dossier-" + hashlib.sha256(canonical_json(identity)).hexdigest(),
        **identity, "visibility": "protected_developer", "renderer": RENDERER,
        "title": title_proj,
        "state": finding["state"], "lane": lane_proj,
        "statement": statement_proj,
        "weakness_cwe": cwe_proj,
        "security_predicate": pred_proj,
        "preconditions": precond_proj,
        "ship_block": ship_proj,
        "missing_predicates": missing_preds,
        "classification_badge": classification_badge,
        "taint_path_timeline": taint_path_timeline,
        "adjudication_summary": adjudication_summary,
        "poc_harness_summary": poc_harness_summary,
        "remediation_guide": remediation_guide,
        "evidence": evidence, "sources": sources, "scores": scores, "chains": chain_views,
        "poc": poc_view, "remediation": remedies,
        **({} if audit_view is None else {"decision_basis": audit_view}),
        "notices": list(NOTICES), "gaps": gaps_proj,
        "truncations": project.cuts,
        "provenance": {key: value for key, value in sorted(provenance.items()) if key in {
            "review_handoff", "poc_handoff", "remediation_planning_handoff", "remediation_validation_handoff",
            "finding_artifact", "projection", "ledger_head_sha256", "configuration_sha256",
            "settings_sha256", "attack_chain_manifest", "source_manifest"}},
    }



def dossier_document(dossier: Mapping[str, Any], *, source_date_epoch: int = 0) -> Document:
    """Human-oriented sections over the existing palette, type and inert code renderer."""
    if dossier.get("schema") != DOSSIER_SCHEMA:
        raise IntegrityError("unsupported dossier model")
    limits = Limits(text_chars=16000, value_chars=240, code_lines=200, code_chars=32000, rows=256, ids=32)
    badge = dossier.get("classification_badge") or {}
    timeline = dossier.get("taint_path_timeline") or ()
    adj = dossier.get("adjudication_summary") or {}
    poc_sum = dossier.get("poc_harness_summary") or {}
    rem_guide = dossier.get("remediation_guide") or {}

    reachability = badge.get("reachability_badge") or dossier["state"]
    owasp = badge.get("owasp_2025") or "unmapped"
    radar_label = badge.get("radar_domain_label") or "Unclassified"
    radar_id = badge.get("radar_domain_id") or "unclassified"
    res_tier = badge.get("resolution_tier") or "not_recorded"
    scanners = ", ".join(badge.get("corroborating_scanners") or ()) or "none"

    blocks: list[Any] = [
        Stats((Stat("Finding", dossier["state"].upper(), dossier["state"]),
               Stat("Technical severity", dossier["ship_block"]["technical_severity"] or "UNASSESSED"),
               Stat("Evidence citations", str(len(dossier["evidence"]))),
               Stat("Runtime proof", "NOT RUN", "insufficient_evidence"))),
        Box(BoxKind.GAP, "Assurance and handling", chip="NOTICE",
            items=(bullets(dossier["notices"], limits),)),
        Heading(1, "Severity, CWE/OWASP Mapping & Reachability Badge", "classification"),
        Box(BoxKind.CLAIM, dossier["title"], badges=(dossier["state"], reachability),
            items=(Para(dossier["statement"]), Fields((
                field("Claim", dossier["finding"]["claim_id"], limits, mono=True),
                field("Finding package", dossier["finding"]["finding_package_id"], limits, mono=True),
                field("Weakness / consequence", dossier["weakness_cwe"] + " / " + dossier["security_predicate"], limits),
                field("OWASP Top 10 (2025)", owasp, limits, mono=True),
                field("Security radar domain", f"{radar_label} ({radar_id})", limits),
                field("Reachability badge", reachability, limits, mono=True),
                field("Resolution tier", res_tier, limits, mono=True),
                field("Corroborating scanners / cells", scanners, limits, mono=True),
                field("Shipment policy", dossier["ship_block"]["policy"], limits),
                field("Shipment decision", dossier["ship_block"]["status"], limits))),
                Para("Preconditions"), bullets(dossier["preconditions"] or ["None recorded."], limits))),
        Heading(1, "Source-to-Sink Call & Taint Path Timeline", "taint-timeline"),
    ]
    if timeline:
        blocks.append(Box(
            BoxKind.EVIDENCE,
            "Ordered source-to-sink propagation and guard checks",
            items=(table(
                ("Step", "Role", "Location", "Symbol", "Taint Transform", "Guard Disposition"),
                [(str(step["step_index"]), step["role"], step["location"], step["symbol"],
                  step["taint_transform"], step["guard_disposition"])
                 for step in timeline],
                limits,
                widths=(0.07, 0.11, 0.22, 0.18, 0.21, 0.21),
                mono=(True, True, True, True, False, False),
            ),),
        ))
    else:
        blocks.append(Box(BoxKind.GAP, "No source-to-sink path recorded",
                          items=(Para("No ordered path steps were available for this finding."),)))

    blocks.append(Heading(1, "Adjudication & Red/Blue/Verifier Evidence Summary", "adjudication"))
    if adj:
        adj_items: list[Any] = [
            Fields((
                field("Verifier posture", adj.get("verifier_posture") or "bounded_adjudication", limits, mono=True),
                field("Counted direct citations", str(len(adj.get("counted_direct_citations") or ())), limits, mono=True),
                field("Analyst-assessed citations", str(len(adj.get("analyst_assessed_citations") or ())), limits, mono=True),
            )),
            Para("Red exploitability basis: " + (adj.get("exploitability_basis") or "Not recorded.")),
            Para("Blue guard evaluation: " + (adj.get("guard_bypass_summary") or "Not recorded.")),
        ]
        if adj.get("resolving_citations"):
            adj_items.append(table(
                ("Relation", "Locator", "Line Span", "Content SHA-256"),
                [(c["relation_id"], c["locator"], c["line_span"], c["content_sha256"][:16])
                 for c in adj["resolving_citations"]],
                limits,
                widths=(0.22, 0.38, 0.16, 0.24),
                mono=(True, True, True, True),
            ))
        blocks.append(Box(BoxKind.VERIFICATION, "Adjudication rationale and guard analysis", items=tuple(adj_items)))

    blocks.extend([
        Heading(1, "Risk dimensions", "risk"),
        Box(BoxKind.EVIDENCE, "Separate assessments, never a combined score",
            items=(Para("Technical severity, exploitability confidence, environmental/business impact and "
                        "remediation priority are independent. Unassessed dimensions remain unassessed."),)),
    ])
    for score in dossier["scores"]:
        rows = [(name.replace("_", " "), "Unassessed" if score[name] is None else score[name]["rating"],
                 "" if score[name] is None else score[name]["scale"]) for name in RISK_DIMENSIONS]
        blocks.append(Box(BoxKind.EVIDENCE, score["provider"], items=(
            table(("Dimension", "Rating", "Scale"), rows, limits, widths=(.44, .24, .28)),
            Fields((field("Score identity", score["score_id"], limits, mono=True),)),
            bullets(["Missing factor: " + item for item in score["missing_factors"]], limits))))
    if not dossier["scores"]:
        blocks.append(Box(BoxKind.GAP, "Risk scores unavailable", items=(Para("No accepted score package."),)))
    blocks.append(Heading(1, "Evidence and resolving source", "evidence"))
    for row in dossier["evidence"]:
        blocks.append(Box(BoxKind.EVIDENCE, row["predicate"].replace("_", " "),
                          meta=row["strength"].replace("_", " "), items=(Fields(tuple(
            field(label, row[key], limits, mono=key in {"relation_id", "entity_id", "content_sha256"})
            for label, key in (("Citation", "relation_id"), ("Entity", "entity_id"), ("Relation", "kind"),
                               ("Admissibility", "admissibility"), ("Location", "locator"),
                               ("Content hash", "content_sha256")))),)))
    for row in dossier["sources"]:
        blocks.append(Box(BoxKind.EVIDENCE, row["path"] or "Source mapping", items=(
            Fields((field("Resolving entity", row["entity_id"], limits, mono=True),
                    field("File SHA-256", row["file_sha256"], limits, mono=True),
                    field("Mapping method", row["mapping_method"], limits),
                    field("Mapping confidence", row["mapping_confidence"], limits),
                    field("Mapping ambiguous", row["mapping_ambiguous"], limits))),
            code(row["excerpt"], limits, caption=f"Lines {row['start_line']}-{row['end_line']} | redacted, inert excerpt"))))
    blocks.append(Box(BoxKind.GAP if dossier["missing_predicates"] else BoxKind.VERIFICATION,
                      "Missing proof predicates", items=(
        bullets(dossier["missing_predicates"] or ["None recorded in the accepted finding."], limits),)))
    basis = dossier.get("decision_basis")
    if basis is not None:
        blocks.append(Heading(1, "Protected decision basis", "decision-basis"))
        if not basis["available"]:
            blocks.append(Box(BoxKind.GAP, "Decision basis unavailable", items=(Para(basis["reason"]),)))
        else:
            blocks.append(Box(BoxKind.PROVENANCE, "Accepted decision projection", items=(
                Para(basis["notice"]), Fields((field("Record", basis["record_id"], limits, mono=True),)))))
            for row in basis["decisions"]:
                blocks.append(Box(BoxKind.PROVENANCE, row["stage"].replace("_", " "), items=(
                    Fields((field("Outcome", row["outcome"], limits),
                            field("Reason", row["reason_code"], limits))),
                    Para(row["explanation"] or str(row["explanation_absence_reason"])))))
            for row in basis["relations"]:
                blocks.append(Box(BoxKind.EVIDENCE, row["kind"].replace("_", " "), items=(
                    Fields(tuple(field(label, row[key], limits) for label, key in (
                        ("Citation", "relation_id"), ("Actor", "actor_role"), ("Predicate", "predicate"),
                        ("Admissibility", "admissibility"), ("Noncounted reason", "noncounted_reason"),
                        ("Counted by original policy", "counted_by_existing_policy"), ("Location", "locator")))),
                    Para(row["notice"]))))
            verifier = basis["verification"]
            blocks.append(Box(BoxKind.VERIFICATION if verifier else BoxKind.GAP, "Independent verification", items=(
                Para("Unavailable: " + str(basis["verification_absence_reason"])) if verifier is None else
                Fields((field("Status", verifier["status"], limits),
                        field("Structural blindness", verifier["blindness"], limits),
                        field("Model diversity", verifier["diversity"], limits),
                        field("Existing R6", verifier["existing_r6_passed"], limits))),)))
        blocks.append(Box(BoxKind.GAP, "Audit coverage (not a clean-target assertion)", items=(
            bullets([f"{row['population']}: emitted {row['emitted']}, omitted {row['omitted']}, "
                     f"unavailable {row['unavailable']}; reason {row['reason']}" for row in basis["coverage"]], limits),)))
    blocks.append(Heading(1, "Compile-Verified Proof-of-Concept Harness Summary", "poc"))
    if poc_sum:
        blocks.append(Box(
            BoxKind.VERIFICATION if poc_sum.get("compile_only_verified") else BoxKind.GAP,
            "PoC compile-check and non-execution assurance",
            chip="NOT PERFORMED BY POLICY",
            items=(
                Fields((
                    field("Compile status", poc_sum.get("compile_status") or "not_available", limits, mono=True),
                    field("Compile-only verified", "yes" if poc_sum.get("compile_only_verified") else "no", limits, mono=True),
                    field("Safety badge", poc_sum.get("safety_badge") or "not_performed_by_policy", limits, mono=True),
                    field("Generated code execution", poc_sum.get("generated_code_execution") or "not_performed_by_policy", limits, mono=True),
                )),
                Para(poc_sum.get("summary") or ""),
            ),
        ))
    poc = dossier["poc"]
    if poc is None:
        blocks.append(Box(BoxKind.GAP, "No accepted PoC outcome", items=(
            Para("No PoC outcome was available for this finding. The finding is not a runtime reproduction."),)))
    else:
        blocks.append(Box(BoxKind.VERIFICATION if poc["status"] == "compile_verified" else BoxKind.GAP,
                          poc["notice"], chip="COMPILE ONLY", items=(
            Fields((field("Producer status", poc["status"], limits),
                    field("Execution", poc["execution"], limits))),
            Para(poc["reason"]), Para(poc["description"]), Para(poc["negative_control"]))))
        if poc["source"] is not None:
            blocks.append(Box(BoxKind.EVIDENCE, "Generated functions (inert text)", items=(
                code(poc["source"], limits, caption="Untrusted generated source. Never executed by this pipeline."),)))
    blocks.append(Heading(1, "Validated Remediation Patch & Verification Checklist", "remediation"))
    if rem_guide:
        rem_items: list[Any] = [
            Fields((
                field("Validation tier", rem_guide.get("validation_tier") or "manual_design_required", limits, mono=True),
                field("Violated invariant", rem_guide.get("violated_invariant") or "Not recorded.", limits),
                field("Corrected invariant", rem_guide.get("corrected_invariant") or "Not recorded.", limits),
            )),
        ]
        if rem_guide.get("proposed_diff"):
            rem_items.append(code(rem_guide["proposed_diff"], limits, caption="Proposed unified remediation diff"))
        if rem_guide.get("concrete_fix_steps"):
            rem_items.extend([Para("Concrete fix guidance"), bullets(rem_guide["concrete_fix_steps"], limits)])
        if rem_guide.get("verification_checklist"):
            rem_items.extend([Para("Regression and verification checklist"), bullets(rem_guide["verification_checklist"], limits)])
        blocks.append(Box(BoxKind.VERIFICATION, "Developer remediation roadmap and checklist", items=tuple(rem_items)))
    for row in dossier["remediation"]:
        details = [label + ": " + text for label, key in (
            ("Compatibility", "compatibility_effects"), ("Affected interface", "affected_interfaces"),
            ("Residual risk", "residual_risks"), ("Deployment prerequisite", "deployment_prerequisites"),
            ("Required validation", "validation_checks"), ("Scope limitation", "scope_limitations"))
                   for text in row[key]]
        blocks.append(Box(BoxKind.VERIFICATION, row["stage"], chip="PROPOSAL / CHECK",
                          items=(Fields((field("Status", row["status"], limits),)),
                                 Para(row["reason"]), Para(row["violated_invariant"]),
                                 Para(row["corrected_invariant"]), bullets(details, limits),
                                 Para("Safe regression assertion: " + (row["regression_safety"] or "Not supplied.")),
                                 Para(row["notice"]))))
        for check in row["checks"]:
            blocks.append(Box(BoxKind.PROVENANCE, check["dimension"].replace("_", " "),
                              items=(Fields((field("Check disposition", check["status"], limits),)),
                                     Para(check["reason"]))))
    if not dossier["remediation"]:
        blocks.append(Box(BoxKind.GAP, "No accepted remediation attachment", items=(
            Para("No plan or validation was available. No remediation is claimed."),)))
    blocks.append(Heading(1, "Chain context and limitations", "chains"))
    for row in dossier["chains"]:
        blocks.append(Box(BoxKind.EVIDENCE, row["objective"], items=(
            Fields((field("Chain", row["chain_id"], limits, mono=True), field("Status", row["status"], limits))),
            bullets(row["qualifications"], limits))))
    if not dossier["chains"]:
        blocks.append(Box(BoxKind.GAP, "No accepted chain context", items=(
            Para("Component findings alone do not prove a connected attack chain."),)))
    blocks.append(Box(BoxKind.GAP, "Coverage and omissions", items=(
        bullets(dossier["gaps"] or ["No additional dossier gaps recorded; this is not a clean-target assertion."], limits),
        bullets([f"{cut['field']}: {cut['omitted']} more {cut['unit']}, sha256 {cut['sha256']}"
                 for cut in dossier["truncations"]], limits))))
    blocks.append(Heading(1, "Resolving provenance", "provenance"))
    rows = []
    for key, value in dossier["provenance"].items():
        if isinstance(value, Mapping):
            rows.append((key.replace("_", " "), value.get("path", ""), value.get("sha256", "")))
        elif value is not None:
            rows.append((key.replace("_", " "), "", value))
    for offset in range(0, len(rows), 4):
        blocks.append(Box(BoxKind.PROVENANCE, "Accepted artifact bindings", items=(
            table(("Artifact", "Run-relative path", "SHA-256"), rows[offset:offset + 4], limits,
                  widths=(.22, .40, .34), mono=(False, True, True)),)))
    return Document(title="Finding dossier" if dossier["kind"] == "confirmed_finding" else "Proof-of-concept dossier",
                    run_id=dossier["run_id"], subtitle=dossier["title"],
                    status_badge=dossier["state"].upper(), status_tone=dossier["state"],
                    source_date_epoch=source_date_epoch,
                    ledger_head=dossier["provenance"].get("ledger_head_sha256", ""),
                    blocks=tuple(blocks), named_gaps=tuple(dossier["gaps"]), renderer=RENDERER)
