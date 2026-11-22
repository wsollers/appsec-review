"""Technical-leadership report over accepted final-report and hash-bound dossier fields.

No model, target, network or clock is consulted. Narrative appears once per publishable finding;
backlog, withheld packages and coverage remain distinct. Source excerpts and payloads stay in the
protected dossiers. Rendering never changes adjudication, scoring or release policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from .dimensions import build_radar_tracker
from .dossier_receipts import FORMAT_LEGACY, FORMAT_UNLOADED
from .executive_posture import SUPPLY_CHAIN_REACHABILITY_REASON, build_attack_chain_cards, build_named_coverage_gaps
from .html import render_html
from .model import Box, Bullets, Cell, Document, Field, Fields, Heading, Para, Table
from .technical_evidence import attack_path, citations, provider_scores, source_location, standards
from .text import clean, metric_text
from .tokens import BoxKind, STATUS_TONES

# The schema's renderer-family identifier is unchanged; the measured source/template hashes
# distinguish this presentation from historical renders without rewriting historical contracts.
RENDERER = "appsec-review/executive-report/1"
TITLE = "Application security review"
SUBTITLE = "Technical report"
NOT_CLEAN = "This is a limit of the review, never evidence that the target is clean."
POLICY_STATEMENT = (
    "Generated proof-of-concept code and regression tests were compiled only and never executed. "
    "Compilation is not runtime proof; a failed or missing PoC does not contradict a finding, "
    "and a build-checked remediation proposal is not a verified fix.")


@dataclass(frozen=True, slots=True)
class BoundDossier:
    """One certified dossier, loaded only after its gate-bound bytes and identity are verified."""
    dossier_id: str
    kind: str
    finding: Mapping[str, Any]
    document: Mapping[str, Any] | None
    gap: str | None = None
    additional_formats: Mapping[str, Mapping[str, str]] | None = None


def words(value: Any) -> str:
    return clean(value).replace("_", " ")


def _bullets(values: Iterable[Any]) -> Bullets:
    return Bullets(tuple(clean(value) for value in values))


def _fields(rows: Iterable[tuple[str, Any]]) -> Fields:
    return Fields(tuple(Field(label, clean(value)) for label, value in rows))


def _table(headers: tuple[str, ...], rows: Iterable[Sequence[Any]], widths: tuple[float, ...]) -> Table:
    # The accepted inputs are already bounded. Do not truncate them again to force a page layout.
    return Table(headers, tuple(tuple(Cell(clean(value)) for value in row) for row in rows), widths)


def _yes(value: Any) -> str:
    return {True: "yes", False: "no"}.get(value, "unknown")


def _verification(item: Mapping[str, Any]) -> str:
    independence = item.get("independence") or {}
    if item.get("state") == "confirmed":
        if independence.get("independent") is True:
            text = ("Yes: an independent verifier confirmed this finding "
                    f"(separate provider: {_yes(independence.get('provider_distinct'))}; "
                    f"distinct verifier model: {_yes(independence.get('verifier_model_distinct'))}).")
        elif independence.get("independent") is False:
            text = "No: the accepted finding is confirmed, but its independence record explicitly says no."
        else:
            text = "Unknown: the accepted finding is confirmed, but verifier independence is not recorded."
    else:
        text = f"No: this finding is {words(item.get('label'))} and stays in the verification backlog."
    verdict = item.get("judge_verdict")
    if verdict:
        text += f" Judge verdict: {words(verdict.get('verdict'))}"
        text += " (the judge disagrees with the finding's state)." if verdict.get("disagrees_with_state") else "."
    return text


def merge_spans(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted((min(a, b), max(a, b)) for a, b in spans):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = merged[-1][0], max(merged[-1][1], end)
        else:
            merged.append((start, end))
    return merged


def _finding_blocks(index: int, item: Mapping[str, Any], bound: BoundDossier | None) -> list[Any]:
    dossier = bound.document if bound and bound.document is not None else {}
    identifier = f"F{index:02}"
    title = clean(item.get("title") or dossier.get("title") or item["finding_package_id"])
    refs = citations(dossier)
    missing = ("The certified protected dossier was not loaded into this rendering; see its certified reference."
               if bound and (bound.gap or "").startswith("executive_dossier_not_loaded:") else
               "The finding's dossier was not available to this report. Its narrative is unavailable, "
               "not evidence against the accepted finding.")
    items: list[Any] = [
        _fields((("Accepted state", words(item.get("state"))),
                 ("Technical severity", clean((item.get("ship_block") or {}).get("technical_severity"))
                  or "N/A — not rated; scoring factors unavailable"),
                 ("Independently confirmed", _verification(item)))),
        Para("Mechanism and impact", muted=True),
        Para(clean(dossier.get("statement")) or missing),
        Para("Accepted impact classification: " + (
            words(dossier.get("security_predicate")) or "unavailable")
             + ". Specific attacker gain beyond the accepted statement is not established; "
             "a weakness category alone does not prove code execution, data loss or reachability.", muted=True),
    ]
    severity = item.get("ship_block") or {}
    if severity.get("missing_factors"):
        items.append(Para("Severity factors unavailable: " + ", ".join(
            clean(value) for value in severity["missing_factors"]) + "."))
    if severity.get("technical_severity_floor") is not None:
        items.append(Para("Accepted severity bounds: " + clean(severity["technical_severity_floor"])
                          + " to " + clean(severity.get("technical_severity_ceiling")) + "."))
    preconditions = dossier.get("preconditions") or ()
    items += [Para("Preconditions (accepted claim assumptions, not independently observed here)", muted=True),
              _bullets(preconditions or ["Not recorded; no prerequisites are inferred."]),
              Para("Attack path: entry to vulnerable function", muted=True),
              Para("Cited means retained predicate evidence, not an observed execution. Analyst-assessed evidence "
                   "remains noncounted; claim preconditions remain assumed; missing transitions remain unknown. "
                   "Neither citation order nor a conditional CBMC witness establishes an ordered execution path.",
                   muted=True),
              _table(("Stage", "Accepted path evidence / limits", "Evidence"),
                     ((row.stage, row.assessment, row.references) for row in attack_path(dossier, refs)),
                     (.19, .65, .16)),
              Para("Evidence and limits", muted=True)]
    if refs:
        for ref in refs:
            items.append(Para(
                f"{ref.label}: {ref.relation_id}; predicate {words(ref.predicate)}; {ref.attribution}. "
                f"{ref.source} Content SHA-256 {ref.content_sha256}; retrieval receipt SHA-256 "
                f"{ref.receipt_sha256}."))
    else:
        items.append(Para("No retained predicate citation was supplied."))
    # Sources can be present without an evidence relation; retain them as context, not as a path.
    cited_entities = {row.get("entity_id") for row in dossier.get("evidence") or ()}
    for source in dossier.get("sources") or ():
        if source.get("entity_id") not in cited_entities:
            items.append(Para("Source context (not an execution edge): " + source_location(source)))
    limits = [*item.get("missing_predicates", ()), *dossier.get("gaps", ())]
    if bound and bound.gap:
        limits.append(bound.gap)
    for cut in dossier.get("truncations") or ():
        limits.append(f"Upstream truncation: {clean(cut.get('field'))}; {cut.get('omitted')} "
                      f"{clean(cut.get('unit'))}; original SHA-256 {clean(cut.get('sha256'))}.")
    if limits:
        items.append(_bullets(limits))
    basis = dossier.get("decision_basis") or {}
    if basis.get("available"):
        items.append(Para("Decision basis: " + clean(basis.get("record_id")) + "; SHA-256 "
                          + clean(basis.get("sha256")) + ". Judge dissent is nondeciding.", muted=True))
        for decision in basis.get("decisions") or ():
            items.append(Para(f"Accepted decision {clean(decision.get('record_id'))}: "
                              f"{words(decision.get('outcome'))}; "
                              f"{clean(decision.get('explanation')) or clean(decision.get('explanation_absence_reason'))}."))
        for relation in basis.get("relations") or ():
            items.append(Para(f"Decision relation {clean(relation.get('relation_id'))}: "
                              f"{words(relation.get('kind'))}; {words(relation.get('predicate'))}; "
                              f"counted by existing policy: {_yes(relation.get('counted_by_existing_policy'))}; "
                              f"{clean(relation.get('noncounted_reason'))}.", muted=True))
    items += [Para("CVE, CWE and scores", muted=True), _fields(standards(dossier))]
    items += [Para(score) for score in provider_scores(dossier)]
    items += [Para("Technical remediation and verification", muted=True)]
    remedies = dossier.get("remediation") or ()
    if not remedies:
        items.append(Para("No accepted remediation proposal or validation was supplied."))
    for remedy in remedies:
        items.append(Para(f"{words(remedy.get('stage'))}: {words(remedy.get('status'))}. "
                          f"{clean(remedy.get('reason'))}"))
        items.append(_fields((("Violated invariant", clean(remedy.get("violated_invariant")) or "not recorded"),
                              ("Corrected invariant", clean(remedy.get("corrected_invariant")) or "not recorded"))))
        for name in ("affected_interfaces", "compatibility_effects", "deployment_prerequisites",
                     "validation_checks", "residual_risks", "scope_limitations"):
            if remedy.get(name):
                items += [Para(words(name).capitalize(), muted=True), _bullets(remedy[name])]
        if remedy.get("regression_safety"):
            items.append(Para("Proposed regression safety assertion: " + clean(remedy["regression_safety"])))
        for check in remedy.get("checks") or ():
            items.append(Para(f"{words(check.get('dimension'))}: {words(check.get('status'))}; "
                              f"{clean(check.get('reason'))}."))
        items.append(Para("Proposal/checks only; not a verified fix. Runtime regression was not performed by policy.",
                          muted=True))
    items.append(_fields((("Finding package", item["finding_package_id"]),
                          ("Finding SHA-256", item.get("sha256")),
                          ("Dossier", bound.dossier_id if bound else "unavailable"))))
    return [Heading(2, f"{identifier} — {title}", identifier, new_page=index > 1),
            Box(BoxKind.CLAIM, "Technical finding", items=tuple(items))]


def _summary_blocks(report: Mapping[str, Any]) -> list[Any]:
    counts, status = report["summary"]["package_counts"], report["status"]
    complete = ("It may be presented as complete." if status["review_complete"] else
                "It may not be presented as complete. See Coverage and limitations for the recorded gaps.")
    return [
        Heading(1, "Scope and summary", "summary"),
        Box(BoxKind.RESULT, "Review scope", items=(
            Para(f"Run {clean(report['run_id'])}. Accepted review status: {words(status['review'])}; "
                 f"publication status: {words(status['publication'])}. {complete}"),
            Para("This report uses the accepted final gate and its hash-bound dossier summaries. "
                 "The retained bindings identify the reviewed scope; no additional target or deployment "
                 "inspection was performed by this renderer."),
            Para(f"{counts['publishable']} publishable confirmed findings; "
                 f"{counts['verification_backlog']} verification backlog; {counts['withheld']} withheld. "
                 "Finding state and verifier independence are distinct."),
            _table(("ID", "Technical issue", "Severity"),
                   ((f"F{index:02}", row.get("title") or row["finding_package_id"],
                     (row.get("ship_block") or {}).get("technical_severity") or "N/A")
                    for index, row in enumerate(report["findings"], 1)), (.10, .75, .15))
            if report["findings"] else Para("No publishable confirmed findings. " + NOT_CLEAN),
            Para("Summary IDs refer to the technical details below; severity is the accepted provider rating, "
                 "not an inferred CVSS score. No release recommendation is made here.", muted=True))),
        Box(BoxKind.RESULT, "Method and assurance", items=(
            Para(POLICY_STATEMENT),
            Para("CVSS describes technical severity for a versioned vector; EPSS is FIRST's date-specific "
                 "CVE-level forecast of exploitation in the wild over 30 days, not local compromise probability. "
                 "Neither is derived from severity words, CWE, or the other score. "
                 "This report does not fetch scores or infer advisory linkage."),
            Para("Standards references: FIRST CVSS — https://www.first.org/cvss/ ; "
                 "FIRST EPSS — https://www.first.org/epss/ ; MITRE CWE — https://cwe.mitre.org/ . "
                 "These explain terminology; they are not run evidence.", muted=True))),
    ]


def _attachment_blocks(report: Mapping[str, Any]) -> list[Any]:
    blocks: list[Any] = [Heading(1, "Related analysis and validation", "attachments")]
    cards = report.get("attack_chain_cards")
    if cards is None:
        cards = build_attack_chain_cards(report)
    blocks.append(Box(BoxKind.RESULT, "Attack-chain availability", items=(
        Para(clean(report["attack_chains"]["reason"])),
        Para("Certified component membership is not an ordered entry/hop/sink path. "
             "Any certified composed severity is retained separately from standalone findings.", muted=True))))
    for card in cards:
        blocks.append(Box(BoxKind.CLAIM, "Chain " + clean(card["chain_id"]),
                          meta=f"composed severity {clean(card['composed_severity'])}", items=(
            _fields((("Accepted chain status", card["status"]),
                     ("Composed severity", card["composed_severity"]),
                     ("Recorded chain gaps", card["gap_count"]),
                     ("Reported domain transition (not a source-resolved boundary)",
                      card.get("trust_boundary_crossed") or "unavailable"))),
            _bullets(f"Component {clean(step['claim_id'])}: {clean(step['title'])}"
                     for step in card["steps"]),
            Para("Components above are unordered for this presentation; no connecting execution edge is inferred.",
                 muted=True))))
    for key, title in (("poc_outcomes", "Proof-of-concept outcomes (compile only)"),
                       ("remediation_planning", "Remediation proposals"),
                       ("remediation_validation", "Remediation validation")):
        section = report[key]
        rows = []
        for row in section["items"]:
            finding = row.get("finding") or row
            rows.append((finding.get("finding_package_id") or "unavailable",
                         words(row.get("status")),
                         "See technical finding / protected attachment; no runtime verification asserted."))
        blocks.append(Box(BoxKind.RESULT if rows else BoxKind.GAP, title, items=(
            Para(clean(section["reason"])),
            _table(("Finding package", "Outcome", "Interpretation"), rows, (.43, .22, .35))
            if rows else Para("None available. " + NOT_CLEAN))))
    return blocks


def _backlog_blocks(report: Mapping[str, Any]) -> list[Any]:
    blocks: list[Any] = [Heading(1, "Verification backlog and withheld packages", "backlog")]
    for key, title in (("verification_backlog", "Supported but not independently confirmed"),
                       ("withheld", "Withheld from publication")):
        rows = report[key]
        blocks.append(Box(BoxKind.COUNTER, title, items=(
            _table(("Title / package", "Accepted state", "Missing verification / withholding reason"),
                   ((row.get("title") or row["finding_package_id"], words(row.get("state")),
                     "; ".join(clean(value) for value in (
                         row.get("withheld_reasons") or row.get("missing_predicates") or ()))
                     or "See accepted package; not independently confirmed for publication")
                    for row in rows), (.45, .15, .40))
            if rows else Para("None recorded."),)))
    return blocks


def _coverage_blocks(report: Mapping[str, Any], dossiers: Sequence[BoundDossier]) -> list[Any]:
    radar = report.get("radar_tracker") or build_radar_tracker(report)
    gaps = build_named_coverage_gaps(report, radar)
    other_gaps = [row for row in gaps if not row["gap_id"].startswith("radar_domain:")]
    # The named-gap projection includes the gate's gap/not-run rows. Print each there, not twice.
    items: list[Any] = [
        Para("Missing, skipped and partial coverage is not a clean verdict. " + NOT_CLEAN),
        _table(("Gap / scope", "Kind / disposition", "Limitation"),
               ((f"{row['gap_id']} / {row['affected_scope']}", f"{row['category']} / {row['disposition']}",
                 row["statement"]) for row in other_gaps), (.32, .20, .48))
        if other_gaps else Para("No additional gate/producer gaps recorded; domain coverage is below."),
    ]
    items += [Para(f"{row['limitation_id']}: " + (
        "See Method and assurance for compile-only nonexecution limits."
        if row["limitation_id"] == "compile_only_nonexecution" else row["statement"]))
              for row in report["limitations"]
              if row["kind"] == "notice"]
    items.append(Para("Recorded gap identifiers: " + (", ".join(report.get("gap_ids") or ()) or "none")))
    items.append(Para(f"{sum(row.document is not None for row in dossiers)} of {len(dossiers)} "
                      "gate-certified dossier documents verified against the gate's hashes and were read."))
    items += [Para(row.gap) for row in dossiers if row.gap]
    coverage = report["summary"].get("coverage") or {}
    items.append(Para(clean(coverage.get("statement")) or "No coverage statement recorded."))
    axes = radar["axes"]
    metric_rows = []
    for axis in axes:
        series = axis["series"]
        metric_rows.append((
            axis["label"], metric_text(series["surface_exposure"]["raw_count"]),
            metric_text(series["verified_coverage"]["score"], "%"),
            metric_text(series["corroborated_leads"]["raw_count"]),
            str(series["confirmed_high_critical"]["all_confirmed_count"]),
            words(axis["coverage_status"]) + "; " + ", ".join([
                *axis["gap_reasons"], *series["corroborated_leads"].get("gap_reasons", ())]),
        ))
    items += [
        Para("Domain measurements", muted=True),
        _table(("Domain", "Exposure", "Verified", "Leads", "Confirmed", "Limits"),
               metric_rows, (.24, .10, .10, .09, .11, .36)),
        Para("N/A means unknown, not measured zero. Package counts do not establish exposure, inspection or "
             "corroboration.", muted=True),
        Para(f"{radar['unclassified_packages']} packages are unclassified by the accepted domain vocabulary."),
    ]
    if radar.get("schema") == "appsec-review/security-radar-tracker/1":
        items.append(Para("Legacy radar /1 estimates are retained as recorded, not certified exposure, "
                          "inspection or corroboration measurements; legacy package-count estimates, "
                          "not measured corroboration."))
    posture = report.get("executive_posture") or {}
    reachable = posture.get("reachable_supply_chain_advisories_count")
    items.append(Para("Reported reachable supply-chain advisories: " + metric_text(reachable)
                      + (" (historical value, not a new certification)." if report.get("schema") in {
                          "appsec-review/final-report/2", "appsec-review/final-report/3"} else ".")))
    if reachable is None:
        items.append(Para(SUPPLY_CHAIN_REACHABILITY_REASON, muted=True))
    return [Heading(1, "Coverage and limitations", "limitations"),
            Box(BoxKind.GAP, "Accepted coverage", items=tuple(items))]


def _reference_blocks(report: Mapping[str, Any], dossiers: Sequence[BoundDossier]) -> list[Any]:
    provenance = report["provenance"]
    rows = []
    for key, value in provenance.items():
        if isinstance(value, Mapping):
            rows.append((words(key), value.get("path") or value.get("name") or "", value.get("sha256") or ""))
        else:
            rows.append((words(key), "", value))
    items: list[Any] = [_table(("Artifact", "Run-relative path / name", "SHA-256"), rows, (.22, .42, .36))]
    refs = {entry["dossier_id"]: entry for entry in report["dossiers"]["items"]}
    for row in dossiers:
        files = (refs.get(row.dossier_id) or {}).get("files") or {}
        items.append(Para(f"Dossier {row.dossier_id}: {words(row.kind)}; "
                          f"{'read' if row.document is not None else 'unavailable'}."))
        for name, ref in sorted({**files, **(row.additional_formats or {})}.items()):
            if isinstance(ref, Mapping):
                items.append(Para(f"{name}: {clean(ref.get('path'))}; SHA-256 {clean(ref.get('sha256'))}."))
        if not row.additional_formats:
            items.append(Para(FORMAT_UNLOADED if row.additional_formats is None else FORMAT_LEGACY, muted=True))
    items += [Para("Protected dossier references retain source excerpts and code; neither is reproduced here."),
              Para(f"Renderer family: {RENDERER}; report schema: {clean(report.get('schema'))}. "
                   "Exact implementation and template identities are retained in the run receipts.")]
    return [Heading(1, "References and provenance", "provenance"),
            Box(BoxKind.PROVENANCE, "Accepted artifact bindings", items=tuple(items))]


def executive_document(report: Mapping[str, Any], dossiers: Sequence[BoundDossier] = (),
                       *, source_date_epoch: int = 0) -> Document:
    loaded_ids = {row.dossier_id for row in dossiers}
    dossiers = tuple(sorted((*dossiers, *(
        BoundDossier(row["dossier_id"], row["kind"], row["finding"], None,
                     f"executive_dossier_not_loaded: {row['dossier_id']}: certified protected document "
                     "not loaded into this rendering; see its certified reference.")
        for row in report["dossiers"]["items"] if row["dossier_id"] not in loaded_ids
    )), key=lambda row: row.dossier_id))
    for row in dossiers:
        if row.document is not None and row.document.get("schema") != DOSSIER_SCHEMA:
            raise ValueError(f"unsupported dossier model for {row.dossier_id}")
    by_claim = {row.finding["claim_id"]: row for row in dossiers if row.kind == "confirmed_finding"}
    blocks = _summary_blocks(report)
    blocks.append(Heading(1, "Technical findings", "findings", new_page=bool(report["findings"])))
    for index, item in enumerate(report["findings"], 1):
        blocks += _finding_blocks(index, item, by_claim.get(item["claim_id"]))
    if not report["findings"]:
        blocks.append(Box(BoxKind.GAP, "No confirmed findings", items=(
            Para("No finding package is publishable as confirmed. " + NOT_CLEAN),)))
    blocks += _backlog_blocks(report)
    blocks += _attachment_blocks(report)
    blocks += _coverage_blocks(report, dossiers)
    blocks += _reference_blocks(report, dossiers)
    status = clean(report["status"]["review"])
    return Document(TITLE, clean(report["run_id"]), SUBTITLE, status.upper(),
                    STATUS_TONES.get(status, "unresolved"), source_date_epoch,
                    clean(report["provenance"].get("ledger_head_sha256")), tuple(blocks),
                    tuple(sorted(row.gap for row in dossiers if row.gap)), RENDERER)


def render_executive_html(report: Mapping[str, Any], dossiers: Sequence[BoundDossier] = (),
                          *, source_date_epoch: int = 0) -> str:
    return render_html(executive_document(report, dossiers, source_date_epoch=source_date_epoch))


__all__ = ["BoundDossier", "RENDERER", "executive_document", "render_executive_html", "words"]
