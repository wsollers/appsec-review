"""Protected, bounded dossiers: accepted evidence in, renderer-neutral documents out.

Only explicitly selected fields cross this boundary. Inference recordings, prompts and arbitrary
producer dictionaries are never copied. Literal redaction is deliberately conservative; the
accepted upstream artifacts retain their original bytes for authorized investigation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from typing import Any, Mapping, Sequence

from appsec_review.jobs.completion_contracts import (
    DOSSIER_SCHEMA, DossierKind, FindingBinding, nonexecution_assurance, verify_nonexecution_assurance,
)
from appsec_review.review.models import IntegrityError
from appsec_review.review.secret_redaction import redact_source_line
from appsec_review.storage import canonical_json
from .digest import bullets, code, field, table
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


def build_dossier(*, run_id: str, kind: DossierKind | str, finding: Mapping[str, Any],
                  claim: Mapping[str, Any], relations: Sequence[Mapping[str, Any]],
                  excerpts: Sequence[Mapping[str, Any]] = (), poc: Mapping[str, Any] | None = None,
                  poc_source: str | None = None, remediation: Sequence[Mapping[str, Any]] = (),
                  chains: Sequence[Mapping[str, Any]] = (), provenance: Mapping[str, Any],
                  gaps: Sequence[str] = (), limits: DossierLimits = DossierLimits()) -> dict[str, Any]:
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
    return {
        "schema": DOSSIER_SCHEMA,
        "dossier_id": "dossier-" + hashlib.sha256(canonical_json(identity)).hexdigest(),
        **identity, "visibility": "protected_developer", "renderer": RENDERER,
        "title": project.text(finding.get("title"), "title"),
        "state": finding["state"], "lane": project.text(finding.get("lane"), "lane"),
        "statement": project.text(claim.get("statement"), "statement"),
        "weakness_cwe": project.text(claim.get("weakness_cwe"), "weakness"),
        "security_predicate": project.text(claim.get("security_predicate"), "security_predicate"),
        "preconditions": [project.text(item, "precondition")
                          for item in project.rows(claim.get("preconditions", ()), "preconditions")],
        "ship_block": {key: project.text((finding.get("ship_block") or {}).get(key), "shipment." + key)
                       for key in ("policy", "status", "technical_severity")},
        "missing_predicates": sorted(finding.get("missing_predicates", ())),
        "evidence": evidence, "sources": sources, "scores": scores, "chains": chain_views,
        "poc": poc_view, "remediation": remedies,
        "notices": list(NOTICES), "gaps": [project.text(item, "gap") for item in sorted(gap_list)],
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
    blocks: list[Any] = [
        Stats((Stat("Finding", dossier["state"].upper(), dossier["state"]),
               Stat("Technical severity", dossier["ship_block"]["technical_severity"] or "UNASSESSED"),
               Stat("Evidence citations", str(len(dossier["evidence"]))),
               Stat("Runtime proof", "NOT RUN", "insufficient_evidence"))),
        Box(BoxKind.GAP, "Assurance and handling", chip="NOTICE",
            items=(bullets(dossier["notices"], limits),)),
        Heading(1, "Finding brief", "finding"),
        Box(BoxKind.CLAIM, dossier["title"], badges=(dossier["state"],),
            items=(Para(dossier["statement"]), Fields((
                field("Claim", dossier["finding"]["claim_id"], limits, mono=True),
                field("Finding package", dossier["finding"]["finding_package_id"], limits, mono=True),
                field("Weakness / consequence", dossier["weakness_cwe"] + " / " + dossier["security_predicate"], limits),
                field("Shipment policy", dossier["ship_block"]["policy"], limits),
                field("Shipment decision", dossier["ship_block"]["status"], limits))),
                Para("Preconditions"), bullets(dossier["preconditions"] or ["None recorded."], limits))),
        Heading(1, "Risk dimensions", "risk"),
        Box(BoxKind.EVIDENCE, "Separate assessments, never a combined score",
            items=(Para("Technical severity, exploitability confidence, environmental/business impact and "
                        "remediation priority are independent. Unassessed dimensions remain unassessed."),)),
    ]
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
    blocks.append(Heading(1, "Proof of concept", "poc"))
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
    blocks.append(Heading(1, "Remediation assurance", "remediation"))
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
