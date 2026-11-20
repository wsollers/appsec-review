"""The executive report: ``final-report.json`` plus the gate-bound dossiers, as a renderer-neutral document.

The readers are a project's tech lead and business owner. The document presents:
1. Executive Risk Posture Banner & Release Readiness Summary
2. 12-Axis, 4-Series Security Radar & Verification Funnel
3. Top Prioritized Remediation Roadmap (risk-first)
4. Confirmed Findings, Multi-Step Attack Chains & Trust-Boundary Breaches
5. Proof-of-Trigger Outcomes, Backlog/Withheld Packages, and Explicit Named Coverage Gaps & Provenance

It is a pure function of its inputs: the same report and the same bound dossier documents give an
equal :class:`Document`, with no clock, locale, environment or file read. Dossier source excerpts
are protected developer content and are never copied: only a path and a line range reach this
document. The document carries no exploit code, prompt or payload.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from .executive_posture import (
    SUPPLY_CHAIN_REACHABILITY_REASON,
    build_attack_chain_cards,
    build_executive_posture,
    build_named_coverage_gaps,
    build_remediation_roadmap,
)
from .digest import bullets, field, table
from .dossier_receipts import FORMAT_LEGACY, FORMAT_UNLOADED
from .dimensions import DIMENSIONS, build_radar_tracker
from .html import render_html
from .model import (
    Box,
    Document,
    Fields,
    Heading,
    Note,
    Para,
    RadarAxis,
    RadarChart,
    RadarLegendRow,
    RadarSeries,
    Stat,
    Stats,
)
from .text import bound, clean, metric_text
from .tokens import BoxKind, Limits, STATUS_TONES

RENDERER = "appsec-review/executive-report/1"
TITLE = "Executive security review report"
SUBTITLE = "For the project tech lead and business owner"
LIMITS = Limits(text_chars=1200, value_chars=240, rows=64, ids=32)
BULLET_CHARS = 600

NOT_CLEAN = "This is a limit of the review, never evidence that the target is clean."
POLICY_STATEMENT = (
    "\"Not performed by policy\" means that generated proof-of-concept code and regression tests were "
    "compiled only and never executed. A successful compilation shows that the generated code builds; "
    "it is not proof that the weakness can be triggered at runtime. A failed, refused or missing proof of "
    "concept does not contradict a finding, and a build-checked remediation proposal is not a verified fix.")
VERIFIED_WORDS = (
    "Finding state is copied from the accepted review; verifier independence is reported separately from "
    "its recorded qualifications. A finding in the verification backlog is supported by evidence but "
    "has not been independently confirmed.")

SHIP_BLOCK_WORDS = {
    "ship_blocking": "Blocks shipping: under the policy this must be fixed before a release.",
    "ship_blocking_pending_distinct_verification": (
        "Blocks shipping while a verification by a distinct model is pending: the policy treats it as blocking "
        "until that verification is recorded."),
    "needs_verification": "Needs verification before a release decision can rest on it.",
    "decision_pending": (
        "Decision pending: the technical severity is not rated yet because scoring factors are missing. "
        "This is neither a ship-blocking decision nor a clearance."),
    "not_ship_blocking": "Does not block shipping under the policy; it still needs to be fixed.",
}
SEVERITY_WORDS = {
    "critical": "Critical: exploitation would be straightforward and the damage severe.",
    "high": "High: a serious weakness that an attacker could turn into real damage.",
    "medium": "Medium: a real weakness whose exploitation needs favourable conditions or has limited impact.",
    "low": "Low: a weakness with small direct impact or demanding preconditions.",
}
SECTION_WORDS = {
    "available": "Available: the items below were produced and certified by the review.",
    "none_available": "None available.",
}
CAPABILITY_WORDS = {
    "SUCCEEDED": "ran and its outcomes were certified",
    "SKIPPED_NA": "ran and found nothing in scope (which is not clean coverage)",
    "SKIPPED_POLICY": "was not run; it is disabled by the run's frozen configuration",
    "GAP": "ran, but expected work is missing, failed, capped or has recorded gaps",
}

CONSEQUENCES = {
    "memory_corruption": "an attacker who reaches this code can corrupt the program's memory, which typically means "
                         "crashing the service and, with more effort, running code of their choosing inside it.",
    "out_of_bounds_read": "an attacker who reaches this code can make the program read memory it should not, which "
                          "leaks data such as secrets or internal addresses and can crash the service.",
    "use_after_free": "an attacker who reaches this code can make the program use memory after it was released, "
                      "which can crash the service or let the attacker run code inside it.",
    "integer_error": "an attacker who reaches this code can make a size or count calculation wrap or overflow, which "
                     "usually turns into a memory-corruption or logic defect further on.",
    "injection": "an attacker who reaches this code can smuggle their own instructions into something the program "
                 "builds from their input.",
    "command_injection": "an attacker who reaches this code can run operating-system commands of their choosing on "
                         "the host, with the privileges of the service.",
    "sql_injection": "an attacker who reaches this code can run their own database queries: reading, changing or "
                     "deleting data they should not have access to.",
    "code_injection": "an attacker who reaches this code can have the program execute code they supply.",
    "path_traversal": "an attacker who reaches this code can read or write files outside the directory the program "
                      "was meant to use, including configuration and secrets.",
    "ssrf": "an attacker who reaches this code can make the server send requests on their behalf to internal "
            "systems it can reach but the attacker cannot.",
    "deserialization": "an attacker who reaches this code can feed the program crafted serialized data that it "
                       "turns into objects, which often lets them run code or bypass checks.",
    "authn_bypass": "an attacker can act as a user without proving who they are.",
    "authz_bypass": "an attacker can do or see something their account is not allowed to.",
    "info_disclosure": "an attacker can learn data the program was meant to keep private.",
    "crypto_weakness": "protection that depends on this cryptography is weaker than intended; data it guards may be "
                       "readable or forgeable.",
    "race_condition": "an attacker who times their actions can make two operations interleave in a way the program "
                      "did not expect, which can bypass a check or corrupt state.",
    "resource_exhaustion": "an attacker can make the service consume memory, CPU, disk or connections until it "
                           "stops serving others.",
    "insecure_configuration": "a setting leaves a protection off or weaker than intended, so other defects or "
                              "attacks become easier.",
    "supply_chain_compromise": "a dependency or build input the program trusts can be used to introduce malicious "
                               "behaviour into what ships.",
}


@dataclass(frozen=True, slots=True)
class BoundDossier:
    """One dossier the gate certified: its document when its bytes verified, otherwise the named gap."""

    dossier_id: str
    kind: str
    finding: Mapping[str, Any]
    document: Mapping[str, Any] | None
    gap: str | None = None
    additional_formats: Mapping[str, Mapping[str, str]] | None = None


def words(value: Any) -> str:
    """A token (``ship_blocking``) as plain words, cleaned."""
    return clean(value).replace("_", " ")


def _text(value: Any, limit: int = LIMITS.text_chars) -> str:
    text, cut = bound(value, limit)
    return text + (f" (+{cut.omitted} more characters, sha256 {cut.sha256[:16]})" if cut else "")


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def _yes(value: Any) -> str:
    return {True: "yes", False: "no"}.get(value, "unknown")


def _bullets(items: Iterable[Any]) -> Any:
    return bullets(items, LIMITS, chars=BULLET_CHARS)


def _severity(rating: Any) -> str:
    token = clean(rating).lower()
    if not token:
        return "Not rated: the technical severity could not be assessed. This is a gap, not a low value."
    return SEVERITY_WORDS.get(token, f"{words(token).capitalize()} (on the provider's own scale).")


def _ship_block(block: Mapping[str, Any]) -> str:
    status = clean(block.get("status"))
    text = SHIP_BLOCK_WORDS.get(status, f"Ship-block status {words(status)}.")
    missing = [words(item) for item in block.get("missing_factors") or ()]
    if status == "decision_pending":
        text += " Missing: " + (", ".join(missing) if missing else "the technical severity rating itself") + "."
        if block.get("technical_severity_floor") is not None:
            text += (f" The missing factors leave the severity between {words(block['technical_severity_floor'])} "
                     f"and {words(block['technical_severity_ceiling'])}.")
    return text


def _verification(item: Mapping[str, Any]) -> str:
    independence = item.get("independence") or {}
    if item.get("state") == "confirmed":
        if independence.get("independent") is True:
            text = "Yes: an independent verifier confirmed this finding"
            text += (f" (separate provider: {_yes(independence.get('provider_distinct'))}; "
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
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _locations(dossier: Mapping[str, Any] | None) -> list[str]:
    by_path: dict[str, list[tuple[int, int]]] = {}
    unranged: list[str] = []
    for source in (dossier or {}).get("sources") or ():
        path = clean(source.get("path")) or "path not recorded"
        start, end = source.get("start_line"), source.get("end_line")
        if isinstance(start, int) and isinstance(end, int):
            by_path.setdefault(path, []).append((start, end))
        elif f"{path}, line range not recorded" not in unranged:
            unranged.append(f"{path}, line range not recorded")
    rows: list[str] = []
    for path in sorted(by_path):
        for start, end in merge_spans(by_path[path]):
            rows.append(f"{path}, lines {start}-{end}" if start != end else f"{path}, line {start}")
    return rows + unranged


def _attacker_gain(dossier: Mapping[str, Any] | None, item: Mapping[str, Any]) -> str:
    predicate = words((dossier or {}).get("security_predicate"))
    if not predicate:
        return ("The dossier that names the consequence was not available; the accepted finding states only "
                "the title and state shown here.")
    meaning = CONSEQUENCES.get(str((dossier or {}).get("security_predicate")))
    text = (f"The accepted security consequence is {predicate}: {meaning}" if meaning else
            f"The accepted security consequence is {predicate}: an attacker who reaches this code can bring it about.")
    preconditions = [_text(row, 300) for row in (dossier or {}).get("preconditions") or ()]
    if preconditions:
        text += " What the attacker needs first: " + "; ".join(preconditions) + "."
    return text


def _remediation(dossier: Mapping[str, Any] | None) -> list[str]:
    rows = []
    for row in (dossier or {}).get("remediation") or ():
        text = f"{words(row.get('stage')) or 'remediation'}: {words(row.get('status')) or 'status not recorded'}"
        if row.get("reason"):
            text += f". {_text(row['reason'], 300)}"
        if row.get("corrected_invariant"):
            text += f" Intended fix: {_text(row['corrected_invariant'], 300)}"
        rows.append(text + " (proposal or build check only; not a verified fix).")
    return rows


def _finding_box(index: int, item: Mapping[str, Any], dossier: BoundDossier | None) -> Box:
    document = dossier.document if dossier is not None else None
    block = item.get("ship_block") or {}
    title = _text(item.get("title") or (document or {}).get("title") or item.get("finding_package_id"), 200)
    statement = (document or {}).get("statement")
    not_loaded = dossier is not None and (dossier.gap or "").startswith("executive_dossier_not_loaded:")
    what = (_text(statement) if statement else
            "What is wrong: the certified protected dossier was not loaded into this rendering. Only the accepted "
            "title, state, severity and ship-block decision are shown; the narrative remains in its certified "
            "artifact, not absent from the review." if not_loaded else
            "What is wrong: the finding's dossier was not available to this report, so only the accepted title, "
            "state, severity and ship-block decision are shown. The absence of the narrative is a gap of this "
            "report, not of the finding.")
    weakness = clean((document or {}).get("weakness_cwe")) or "not recorded"
    locations = _locations(document)
    rows = [
        field("Weakness", weakness, LIMITS),
        field("Technical severity", _severity(block.get("technical_severity")), LIMITS, limit=LIMITS.text_chars),
        field("Ship-block status", _ship_block(block), LIMITS, limit=LIMITS.text_chars),
        field("Independently confirmed", _verification(item), LIMITS, limit=LIMITS.text_chars),
        field("Finding package", item.get("finding_package_id"), LIMITS, mono=True),
        field("Review lane", words(item.get("lane")), LIMITS),
    ]
    items: list[Any] = [
        Para(what),
        Fields(tuple(rows)),
        Para("Where it is", muted=True),
        _bullets(locations or ["No resolving source location was available to this report."]),
        Para("What an attacker gains", muted=True),
        Para(_attacker_gain(document, item)),
        Para("Remediation", muted=True),
        _bullets(_remediation(document) or ["No remediation proposal or validation was available."]),
    ]
    chains = [f"{clean(row.get('chain_id'))}: {words(row.get('status'))}; {_text(row.get('objective'), 300)}"
              for row in (document or {}).get("chains") or ()]
    if chains:
        items += [Para("Attack chains this finding takes part in", muted=True), _bullets(chains)]
    missing = [words(name) for name in item.get("missing_predicates") or ()]
    if missing:
        items += [Para("Proof predicates still missing", muted=True), _bullets(missing)]
    if dossier is not None and dossier.gap:
        items.append(Para(f"Dossier gap: {_text(dossier.gap, 400)}", muted=True))
    return Box(BoxKind.CLAIM, f"{index}. {title}", meta=words(item.get("state")),
               badges=(clean(item.get("state")),) if clean(item.get("state")) else (), items=tuple(items))


def _summary_blocks(report: Mapping[str, Any], radar: Mapping[str, Any]) -> list[Any]:
    status, summary = report["status"], report["summary"]
    counts, accounting, block = summary["package_counts"], summary["accounting"], summary["ship_block"]
    posture = report.get("executive_posture") or build_executive_posture(report, radar)
    sev = posture["confirmed_by_severity"]
    cci = posture["coverage_confidence_index"]
    gaps = [row for row in report["limitations"] if row["kind"] == "gap"]
    complete = bool(status.get("review_complete"))
    standing = (f"The review finished with status {words(status['review'])}, publication status "
                f"{words(status['publication'])}, and release readiness {words(posture['release_readiness'])}. ")
    standing += ("It may be presented as complete." if complete else
                 "It may not be presented as complete: " + (
                     f"{_plural(len(gaps), 'named gap')} limit it, listed below and in the limitations section."
                     if gaps else "its review status is not COMPLETE or it is marked incomplete."))
    by_status = block.get("by_status") or {}
    release = [f"{_plural(by_status.get(key, 0), 'finding')}: {SHIP_BLOCK_WORDS[key]}"
               for key in SHIP_BLOCK_WORDS if by_status.get(key)]
    readiness_tone = (
        "contradicted" if posture["release_readiness"] == "BLOCK_RELEASE"
        else ("insufficient_evidence" if posture["release_readiness"] == "REVIEW_REQUIRED_GAPS_PRESENT" else "confirmed")
    )
    return [
        Stats((
            Stat("Release readiness", words(posture["release_readiness"]), readiness_tone),
            Stat("Critical / High", f"{sev['critical']} / {sev['high']}",
                 "contradicted" if (sev["critical"] + sev["high"]) else "neutral"),
            Stat("Medium / Low", f"{sev['medium']} / {sev['low']}",
                 "insufficient_evidence" if (sev["medium"] + sev["low"]) else "neutral"),
            Stat("Chain-elevated", str(posture["chain_elevated_findings_count"]),
                 "contradicted" if posture["chain_elevated_findings_count"] else "neutral"),
            Stat("Supply-chain", metric_text(posture["reachable_supply_chain_advisories_count"]),
                 "coverage_gap" if posture["reachable_supply_chain_advisories_count"] is None else
                 "contradicted" if posture["reachable_supply_chain_advisories_count"] else "neutral"),
            Stat("Coverage confidence", f"{metric_text(cci['score'], '/100')} ({cci['verified_axes']}/12)",
                 "confirmed" if cci["gap_axes"] == 0 and complete else "coverage_gap"),
            Stat("Backlog / Withheld", f"{counts['verification_backlog']} / {counts['withheld']}",
                 "supported" if counts["verification_backlog"] else "neutral"),
            Stat("Review status", words(status["review"]), STATUS_TONES.get(status["review"], "unresolved")),
        )),
        Heading(1, "Executive summary", "summary"),
        Box(BoxKind.RESULT, "Executive risk posture and release readiness", items=(
            Para(standing),
            Fields((
                field("Release readiness", words(posture["release_readiness"]), LIMITS),
                field("Confirmed by severity",
                      f"critical {sev['critical']}, high {sev['high']}, medium {sev['medium']}, "
                      f"low {sev['low']}, unrated {sev['unrated']}", LIMITS),
                field("Chain-elevated findings", posture["chain_elevated_findings_count"], LIMITS),
                field("Reachable supply-chain", metric_text(posture["reachable_supply_chain_advisories_count"]), LIMITS),
                field("Coverage confidence",
                      f"{metric_text(cci['score'], '/100')} ({cci['verified_axes']} verified axes, "
                      f"{cci['gap_axes']} unverified coverage gap axes)", LIMITS),
                field("Review complete", "yes" if complete else "no", LIMITS),
                field("Claims reviewed", accounting.get("claims_total"), LIMITS),
                field("Finding packages", f"{counts['total']} total: {counts['publishable']} confirmed, "
                      f"{counts['verification_backlog']} awaiting verification, {counts['withheld']} withheld", LIMITS),
                field("Gap ratio", f"{accounting.get('gap_ratio', 0):.3f} (incomplete above "
                      f"{accounting.get('incomplete_gap_ratio', 0):.3f})", LIMITS),
            )),
            *((Para(SUPPLY_CHAIN_REACHABILITY_REASON, muted=True),)
              if posture.get("reachable_supply_chain_gap_reasons") else ()),
            Para(cci["statement"], muted=True),
            *(() if complete else (Para("Why the review is not complete", muted=True),
                                   _bullets([f"{words(row['limitation_id'])}: {_text(row['statement'])}" for row in gaps]
                                            or ["The review status or incompleteness flag alone withholds completeness."]))))),
        Box(BoxKind.RESULT, f"Release impact under {clean(block.get('policy')) or 'the ship-block policy'}", items=(
            _bullets(release or ["No finding carries a ship-block status."]),
            Para(VERIFIED_WORDS, muted=True))),
        Box(BoxKind.GAP, "What \"not performed by policy\" means", chip="NOTICE", items=(Para(POLICY_STATEMENT),)),
    ]


DIMENSION_SCALE_NOTE = (
    "Each funnel series is normalized to [0, 1] on its spoke; raw counts and coverage percentages appear in the "
    "companion table. Missing, skipped or partial domain coverage is explicitly marked as an Unverified Coverage "
    "Gap and is NEVER evidence that a security domain is clean.")


def _dimension_reading(axis: Mapping[str, Any]) -> str:
    series = axis["series"]
    confirmed_all = series["confirmed_high_critical"]["all_confirmed_count"]
    hc = series["confirmed_high_critical"]["raw_count"]
    claims = (sum(axis["package_counts"].values()) if "package_counts" in axis else
              series["corroborated_leads"]["raw_count"])
    cov_status = axis["coverage_status"]
    if confirmed_all:
        base = f"{_plural(confirmed_all, 'confirmed finding')} ({hc} high/critical) of {_plural(claims, 'accepted package')}."
    elif claims:
        base = f"{_plural(claims, 'accepted package')}, none confirmed. Not a clearance."
    elif cov_status == "verified_no_findings":
        base = "Explicitly inspected domain scope; no publishable findings in that population."
    else:
        base = "Unverified coverage gap: Uncovered: no claim was examined here."
    if cov_status in {"unverified_gap", "partial_coverage_gap"} and "gap" not in base.lower():
        base += f" Unverified coverage gap ({words(cov_status)})."
    if axis["gap_reasons"]:
        base += " " + ", ".join(axis["gap_reasons"]) + "."
    metric_gaps = series["corroborated_leads"].get("gap_reasons", ())
    if metric_gaps:
        base += " Metric gap: " + ", ".join(metric_gaps) + "."
    return base


def _dimension_blocks(report: Mapping[str, Any], radar_or_dossiers: Mapping[str, Any] | Sequence[BoundDossier]) -> list[Any]:
    if isinstance(radar_or_dossiers, Mapping):
        radar = radar_or_dossiers
    else:
        by_claim_doc = {
            row.finding["claim_id"]: row.document
            for row in radar_or_dossiers
            if row.kind == "confirmed_finding" and row.document is not None
        }
        radar = report.get("radar_tracker") or build_radar_tracker(report, by_claim_doc)
    axes_data = radar["axes"]
    unclassified = int(radar["unclassified_packages"])
    top_surface = max((ax["series"]["surface_exposure"]["raw_count"] for ax in axes_data
                       if ax["series"]["surface_exposure"]["raw_count"] is not None), default=None)
    top_leads = max((ax["series"]["corroborated_leads"]["raw_count"] for ax in axes_data
                     if ax["series"]["corroborated_leads"]["raw_count"] is not None), default=None)
    top_hc = max((ax["series"]["confirmed_high_critical"]["raw_count"] for ax in axes_data), default=0)

    chart = RadarChart(
        "12-axis security radar and 4-series verification funnel",
        tuple(RadarAxis(ax["label"], ax["key"]) for ax in axes_data),
        (
            RadarSeries(
                "Surface exposure",
                "not_reachable",
                tuple(ax["series"]["surface_exposure"]["unit"] for ax in axes_data),
                tuple(metric_text(ax["series"]["surface_exposure"]["raw_count"]) for ax in axes_data),
            ),
            RadarSeries(
                "Verified coverage",
                "supported",
                tuple(ax["series"]["verified_coverage"]["unit"] for ax in axes_data),
                tuple(
                    metric_text(ax["series"]["verified_coverage"]["score"], "%")
                    + (" GAP" if ax["series"]["verified_coverage"]["is_gap"] else "")
                    for ax in axes_data
                ),
            ),
            RadarSeries(
                "Corroborated leads",
                "proposed",
                tuple(ax["series"]["corroborated_leads"]["unit"] for ax in axes_data),
                tuple(metric_text(ax["series"]["corroborated_leads"]["raw_count"]) for ax in axes_data),
            ),
            RadarSeries(
                "Confirmed High/Critical",
                "contradicted",
                tuple(float(ax["series"]["confirmed_high_critical"]["unit"]) for ax in axes_data),
                tuple(
                    f"{ax['series']['confirmed_high_critical']['raw_count']}/{ax['series']['confirmed_high_critical']['all_confirmed_count']}"
                    for ax in axes_data
                ),
            ),
        ),
        scale_note=DIMENSION_SCALE_NOTE,
        legend=(
            RadarLegendRow("series", "Surface exposure", "Surface exposure",
                           f"explicitly measured exposed units; N/A is unknown; known rim is {metric_text(top_surface)}"),
            RadarLegendRow("series", "Verified coverage", "Verified coverage",
                           "percentage of exposed domain scope verified; <100% or unbound is an Unverified Coverage Gap"),
            RadarLegendRow("series", "Corroborated leads", "Corroborated leads",
                           (f"legacy package-count estimates, not measured corroboration; recorded rim is {metric_text(top_leads)}"
                            if radar.get("schema") == "appsec-review/security-radar-tracker/1" else
                            f"explicitly measured corroborated leads, not accepted packages; known rim is {metric_text(top_leads)}")),
            RadarLegendRow("series", "Confirmed High/Critical", "Confirmed High/Critical",
                           f"confirmed high/critical or chain-elevated findings (with total confirmed); rim is {top_hc}"),
            *(
                RadarLegendRow(
                    "axis",
                    dim.key,
                    dim.label,
                    f"{dim.counts}" + (
                        " [Unverified coverage gap]"
                        if axes_data[idx]["coverage_status"] in {"unverified_gap", "partial_coverage_gap"}
                        else ""
                    ),
                )
                for idx, dim in enumerate(DIMENSIONS)
            ),
        ),
    )
    table_rows = [
        (
            ax["key"],
            ax["label"],
            metric_text(ax["series"]["surface_exposure"]["raw_count"]),
            metric_text(ax["series"]["verified_coverage"]["score"], "%"),
            metric_text(ax["series"]["corroborated_leads"]["raw_count"]),
            f"{ax['series']['confirmed_high_critical']['raw_count']} ({ax['series']['confirmed_high_critical']['all_confirmed_count']})",
            _dimension_reading(ax),
        )
        for ax in axes_data
    ]
    items: list[Any] = [
        Para("The 12 security domains span application, native, API, cryptography, supply-chain, CI/CD and deployment "
             "surfaces across four funnel series: surface exposure, verified coverage, corroborated leads and "
             "confirmed high/critical findings."),
        table(
            ("Key", "Domain", "Exposure", "Verified", "Leads", "High/Crit (All)", "Posture & Reading"),
            table_rows,
            LIMITS,
            widths=(.06, .20, .08, .09, .07, .12, .34),
        ),
        Para(f"{_plural(unclassified, 'package')} named no member of the vocabulary and {'is' if unclassified == 1 else 'are'} "
             "counted in no dimension." if unclassified else
             "Every accepted package names a member of the vocabulary and is counted in one of the 12 security domains.",
             muted=True),
        Para("N/A means unknown, not measured zero. Package counts do not establish exposure, inspected scope or corroboration. "
             "An unverified coverage gap is never a clean verdict. " + NOT_CLEAN, muted=True),
    ]
    return [
        Heading(1, "Review coverage by security dimension", "dimensions"),
        chart,
        Box(BoxKind.EVIDENCE, "12-axis verification funnel", items=tuple(items)),
    ]


def _roadmap_blocks(report: Mapping[str, Any]) -> list[Any]:
    roadmap = build_remediation_roadmap(report)
    blocks: list[Any] = [Heading(1, "Prioritized remediation roadmap", "roadmap")]
    if not roadmap:
        blocks.append(Box(BoxKind.GAP, "No confirmed findings on remediation roadmap", items=(
            Para("No independently confirmed finding is present to schedule for remediation. " + NOT_CLEAN),
        )))
        return blocks
    rows = [
        (
            str(row["rank"]),
            words(row["priority_tier"]),
            row["technical_severity"],
            words(row["domain_id"]),
            _text(row["title"], 120),
            words(row["validation_status"]),
            f"{words(row['poc_posture']['status'])} ({words(row['poc_posture']['generated_code_execution'])})",
        )
        for row in roadmap
    ]
    blocks.append(Box(BoxKind.RESULT, "Risk-first remediation sequence", items=(
        Para("Ordered strictly risk-first: critical -> high -> chain-elevated -> quick-win dependency/config -> "
             "residual confirmed findings. Validation checks are static/build-only; generated code execution is "
             "not performed by policy."),
        table(
            ("#", "Tier", "Severity", "Domain", "Finding", "Patch validation", "PoC posture"),
            rows,
            LIMITS,
            widths=(.04, .14, .09, .14, .25, .14, .16),
        ),
    )))
    return blocks


def _capability_line(report: Mapping[str, Any], name: str) -> str:
    record = (report.get("capabilities") or {}).get(name) or {}
    disposition = clean(record.get("disposition"))
    text = f"The {words(name)} stage {CAPABILITY_WORDS.get(disposition, 'has disposition ' + words(disposition))}."
    return text + f" {_text(record.get('reason'), 400)}" if record.get("reason") else text


def _section_box(report: Mapping[str, Any], key: str, capability: str, title: str, rows: list[str],
                 none_text: str) -> Box:
    section = report[key]
    status = clean(section.get("status"))
    intro = SECTION_WORDS.get(status, f"Status {words(status)}.")
    items: list[Any] = [Para(f"{intro} {_text(section.get('reason'))}"), Para(_capability_line(report, capability), muted=True)]
    if status == "none_available" or not rows:
        items.append(Para(f"{none_text} {NOT_CLEAN}"))
        return Box(BoxKind.GAP, title, items=tuple(items))
    items.append(_bullets(rows))
    return Box(BoxKind.RESULT, title, items=tuple(items))


def _title_of(report: Mapping[str, Any]) -> dict[str, str]:
    return {row["finding_package_id"]: clean(row.get("title")) for row in
            (*report["findings"], *report["verification_backlog"], *report["withheld"])}


def _section_blocks(report: Mapping[str, Any], dossiers: Sequence[BoundDossier]) -> list[Any]:
    titles = _title_of(report)
    poc_by_claim = {row.finding["claim_id"]: row for row in dossiers if row.kind == "poc" and row.document}
    chains = [f"{clean(row['chain_id'])}: {words(row['status'])}; links {len(row.get('component_claim_ids') or ())} "
              f"claims; {_plural(row.get('gap_count', 0), 'recorded gap')}" for row in report["attack_chains"]["items"]]
    chain_cards = report.get("attack_chain_cards")
    if chain_cards is None:
        chain_cards = build_attack_chain_cards(report)
    card_boxes = []
    for card in chain_cards:
        step_lines = [
            f"Step {step['step_index']} [{step['role'].upper()}]: {step['claim_id']} "
            f"({words(step['domain_id'])}) ? {_text(step['title'], 160)}"
            for step in card["steps"]
        ] or ["No component steps recorded."]
        card_boxes.append(Box(
            BoxKind.CLAIM,
            f"Chain {clean(card['chain_id'])}",
            meta=f"composed severity {card['composed_severity']} | boundary: {card['trust_boundary_crossed']}",
            badges=(clean(card["status"]),),
            items=(
                Fields((
                    field("Composed severity", card["composed_severity"], LIMITS),
                    field("Trust boundary crossed", card["trust_boundary_crossed"], LIMITS),
                    field("Recorded chain gaps", card["gap_count"], LIMITS),
                )),
                Para("Step-by-step path (entry -> hop -> sink)", muted=True),
                _bullets(step_lines),
            ),
        ))

    pocs = []
    for row in report["poc_outcomes"]["items"]:
        text = f"{titles.get(row['finding_package_id']) or row['finding_package_id']}: {words(row['status'])}"
        if row.get("description"):
            text += f". {_text(row['description'], 300)}"
        poc = poc_by_claim.get(row.get("claim_id"))
        if poc is not None and (poc.document or {}).get("poc"):
            text += f" Dossier note: {_text((poc.document or {})['poc'].get('reason'), 300)}"
        pocs.append(text + " Compiled only, never executed.")
    plans = [f"{titles.get(row['finding']['finding_package_id']) or row['finding']['finding_package_id']}: "
             f"{words(row['status'])}" + ("" if row.get("plan") else " (no plan artifact)")
             for row in report["remediation_planning"]["items"]]
    validations = [f"{titles.get(row['finding']['finding_package_id']) or row['finding']['finding_package_id']}: "
                   f"{words(row['status'])}" + ("" if row.get("validation") else " (no validation artifact)")
                   for row in report["remediation_validation"]["items"]]
    return [
        Heading(1, "Attack chains", "chains"),
        _section_box(report, "attack_chains", "attack_chains", "Connected attack chains", chains,
                     "No confirmed or qualified attack chain was certified. Component findings alone do not prove a "
                     "connected chain, and the absence of a chain does not reduce any finding."),
        *card_boxes,
        Heading(1, "Proof-of-trigger outcomes", "poc"),
        _section_box(report, "poc_outcomes", "poc_generation", "Proof-of-concept outcomes (compile only)", pocs,
                     "No proof-of-concept outcome was certified."),
        Box(BoxKind.GAP, "Execution and negative controls", chip="NOTICE", items=(
            Para("Not performed by policy. Compilation is not runtime proof, and no negative control was observed to pass."),)),
        Heading(1, "Remediation", "remediation"),
        _section_box(report, "remediation_planning", "remediation_planning", "Remediation proposals", plans,
                     "No remediation proposal was certified."),
        _section_box(report, "remediation_validation", "remediation_validation", "Remediation validation", validations,
                     "No remediation validation was certified."),
        Box(BoxKind.GAP, "What remediation attachments mean", chip="NOTICE", items=(
            Para("Proposals and build or static checks do not change a finding's state or the shipment decision. "
                 "No regression was executed, so no fix is verified."),)),
    ]


def _backlog_blocks(report: Mapping[str, Any]) -> list[Any]:
    blocks: list[Any] = [Heading(1, "Verification backlog and withheld packages", "backlog")]
    backlog = report["verification_backlog"]
    if backlog:
        rows = [(clean(row.get("title")), words(row.get("state")), words(row["ship_block"].get("status")),
                 clean(row["ship_block"].get("technical_severity")) or "not rated") for row in backlog]
        blocks.append(Box(BoxKind.COUNTER, f"{_plural(len(backlog), 'finding')} supported but not independently confirmed",
                          items=(Para("Each needs an independent verification before it can count as confirmed. "
                                      "None is cleared and none is dismissed."),
                                 table(("Title", "State", "Ship-block status", "Severity"), rows, LIMITS,
                                       widths=(.46, .14, .24, .12)))))
    else:
        blocks.append(Box(BoxKind.RESULT, "Verification backlog", items=(Para("The verification backlog is empty."),)))
    withheld = report["withheld"]
    if withheld:
        rows = [(clean(row.get("title")) or clean(row.get("finding_package_id")), words(row.get("state")),
                 ", ".join(words(reason) for reason in row.get("withheld_reasons") or ()) or "reason not recorded")
                for row in withheld]
        blocks.append(Box(BoxKind.GAP, f"{_plural(len(withheld), 'package')} withheld from publication", items=(
            Para("A withheld package keeps its accepted state and ship-block status; it is listed, not hidden."),
            table(("Title", "State", "Withheld because"), rows, LIMITS, widths=(.44, .14, .38)))))
    return blocks


def _limitation_blocks(report: Mapping[str, Any], dossiers: Sequence[BoundDossier], radar: Mapping[str, Any]) -> list[Any]:
    grouped = {kind: [row for row in report["limitations"] if row["kind"] == kind] for kind in ("gap", "not_run", "notice")}
    coverage = report["summary"].get("coverage") or {}
    summary = ", ".join(f"{words(key)} {value}" for key, value in sorted((coverage.get("summary") or {}).items())) or "none"
    dossier_gaps = [f"{row.dossier_id}: {_text(row.gap, 400)}" for row in dossiers if row.gap]
    named_gaps = build_named_coverage_gaps(report, radar)
    gap_table_rows = [
        (row["gap_id"], words(row["category"]), words(row["affected_scope"]), row["disposition"], _text(row["statement"], 200))
        for row in named_gaps
    ]
    return [
        Heading(1, "Limitations and coverage", "limitations"),
        Box(BoxKind.GAP, f"Named coverage gaps and blind spots ({len(named_gaps)})", items=(
            Para("Every producer gap, unrun stage, syntactic-fallback scope, and unverified security domain is listed "
                 "explicitly below. " + NOT_CLEAN),
            table(("Gap ID", "Category", "Scope", "Disposition", "Summary"), gap_table_rows, LIMITS,
                  widths=(.20, .14, .16, .14, .32), mono=(True, False, False, True, False))
            if gap_table_rows else Para("No named coverage gaps or blind spots recorded."),
        )),
        Box(BoxKind.GAP, f"Gaps ({len(grouped['gap'])})", items=(
            Para("Each gap limits what this review can say. " + NOT_CLEAN),
            _bullets([f"{words(row['limitation_id'])}: {_text(row['statement'])}" for row in grouped["gap"]]
                     or ["No gap limitation is recorded."]))),
        Box(BoxKind.GAP, f"Stages not run ({len(grouped['not_run'])})", items=(
            _bullets([f"{words(row['limitation_id'])}: {_text(row['statement'])}" for row in grouped["not_run"]]
                     or ["Every configured stage ran."]),)),
        Box(BoxKind.RESULT, f"Notices ({len(grouped['notice'])})", items=(
            _bullets([f"{words(row['limitation_id'])}: {_text(row['statement'])}" for row in grouped["notice"]]
                     or ["No notice is recorded."]),)),
        Box(BoxKind.EVIDENCE, "Coverage", items=(
            Fields((field("Coverage cells", coverage.get("rows"), LIMITS),
                    field("Cells by outcome", summary, LIMITS, limit=LIMITS.text_chars))),
            Para(_text(coverage.get("statement") or "No coverage statement was recorded.")),
            Para(f"Recorded gap identifiers: {len(report.get('gap_ids') or ())} (listed in final-report.json).", muted=True))),
        Box(BoxKind.GAP if dossier_gaps else BoxKind.RESULT, "Dossiers available to this report", items=(
            Para(f"{sum(1 for row in dossiers if row.document)} of {len(dossiers)} gate-certified dossier documents "
                 "verified against the gate's hashes and were read for the finding narratives."),
            *((_bullets(dossier_gaps),) if dossier_gaps else ()))),
        Box(BoxKind.RESULT, "Notices from the report", items=(_bullets(report.get("notices") or ()),)),
    ]


def _appendix_blocks(report: Mapping[str, Any], dossiers: Sequence[BoundDossier]) -> list[Any]:
    provenance = report["provenance"]
    rows = []
    for key in ("gate_handoff", "gate_document", "review_handoff", "poc_handoff"):
        value = provenance.get(key)
        if isinstance(value, Mapping):
            rows.append((words(key), value.get("path", ""), value.get("sha256", "")))
    for key in ("accepted_manifest_sha256", "configuration_sha256", "ledger_head_sha256", "ship_block_policy_sha256"):
        if provenance.get(key) is not None:
            rows.append((words(key.removesuffix("_sha256")), "", provenance[key]))
    profile = provenance.get("configuration_profile")
    if isinstance(profile, Mapping):
        rows.append(("runtime profile " + clean(profile.get("name")), "", clean(profile.get("sha256")) or "none"))
    refs = {entry["dossier_id"]: entry for entry in report["dossiers"]["items"]}
    dossier_rows = []
    format_rows = []
    format_notices = []
    for row in dossiers:
        pdf = ((refs.get(row.dossier_id) or {}).get("files") or {}).get("pdf")
        dossier_rows.append((row.dossier_id, words(row.kind), "read" if row.document else "unavailable",
                             clean(pdf.get("path")) if isinstance(pdf, Mapping) else "no PDF"))
        if row.additional_formats:
            format_rows.extend((row.dossier_id, name, ref["path"], ref["sha256"])
                               for name, ref in sorted(row.additional_formats.items()))
        else:
            reason = FORMAT_UNLOADED if row.additional_formats is None else FORMAT_LEGACY
            format_notices.append(f"{row.dossier_id}: {reason}")
    blocks: list[Any] = [Heading(1, "Appendix: provenance", "provenance", new_page=True),
                         Box(BoxKind.PROVENANCE, "Accepted artifact bindings", items=(
                             table(("Artifact", "Run-relative path", "SHA-256"), rows, LIMITS,
                                   widths=(.22, .40, .34), mono=(False, True, True)),))]
    if dossier_rows:
        blocks.append(Box(BoxKind.PROVENANCE, "Protected dossier references", items=(
            Para("Dossiers are protected developer artifacts. Only loaded JSON was read through the gate's hashes; "
                 "their source excerpts and generated code stay in the dossiers."),
            table(("Dossier", "Kind", "Read", "PDF"), dossier_rows, LIMITS, widths=(.36, .16, .12, .32),
                  mono=(True, False, False, True)))))
        blocks.append(Box(BoxKind.PROVENANCE, "Certified protected dossier formats", items=(
            Para("References only; certifying a protected file does not make its contents public."),
            *((table(("Dossier", "Format", "Run-relative path", "SHA-256"), format_rows, LIMITS,
                     widths=(.20, .10, .42, .24), mono=(True, False, True, True)),) if format_rows else ()),
            *((_bullets(format_notices),) if format_notices else ()))))
    blocks.append(Box(BoxKind.PROVENANCE, "Renderers", items=(Fields((
        field("Executive report", RENDERER, LIMITS, mono=True),
        field("Markdown report", (report["renderers"]["markdown"] or {}).get("renderer"), LIMITS, mono=True),
        field("Report schema", report.get("schema"), LIMITS, mono=True))),)))
    return blocks


def executive_document(report: Mapping[str, Any], dossiers: Sequence[BoundDossier] = (),
                       *, source_date_epoch: int = 0) -> Document:
    """Build the executive report document from ``final-report.json`` and the gate-bound dossiers."""
    loaded_ids = {row.dossier_id for row in dossiers}
    dossiers = (*dossiers, *(
        BoundDossier(row["dossier_id"], row["kind"], row["finding"], None,
                     f"executive_dossier_not_loaded: {row['dossier_id']}: certified protected document "
                     "not loaded into this rendering; see its certified reference.")
        for row in report["dossiers"]["items"] if row["dossier_id"] not in loaded_ids
    ))
    for row in dossiers:
        if row.document is not None and row.document.get("schema") != DOSSIER_SCHEMA:
            raise ValueError(f"unsupported dossier model for {row.dossier_id}")
    by_claim_doc = {
        row.finding["claim_id"]: row.document
        for row in dossiers
        if row.kind == "confirmed_finding" and row.document is not None
    }
    radar = report.get("radar_tracker") or build_radar_tracker(report, by_claim_doc)
    by_claim = {row.finding["claim_id"]: row for row in dossiers if row.kind == "confirmed_finding"}
    blocks: list[Any] = _summary_blocks(report, radar)
    if radar.get("schema") == "appsec-review/security-radar-tracker/1":
        blocks.append(Note("Legacy radar /1 estimates are retained as recorded, not certified exposure or inspection measurements."))
    blocks += _dimension_blocks(report, radar)
    blocks += _roadmap_blocks(report)
    blocks.append(Heading(1, "Confirmed findings", "findings"))
    findings = report["findings"]
    if not findings:
        blocks.append(Box(BoxKind.GAP, "No confirmed findings", items=(
            Para("No finding package is publishable as independently confirmed. " + NOT_CLEAN),)))
    for index, item in enumerate(findings, 1):
        blocks.append(_finding_box(index, item, by_claim.get(item["claim_id"])))
    blocks += _section_blocks(report, dossiers)
    blocks += _backlog_blocks(report)
    blocks += _limitation_blocks(report, dossiers, radar)
    blocks += _appendix_blocks(report, dossiers)
    status = clean(report["status"]["review"])
    return Document(title=TITLE, run_id=clean(report["run_id"]), subtitle=SUBTITLE,
                    status_badge=status.upper(), status_tone=STATUS_TONES.get(status, "unresolved"),
                    source_date_epoch=source_date_epoch,
                    ledger_head=clean(report["provenance"].get("ledger_head_sha256")),
                    blocks=tuple(blocks),
                    named_gaps=tuple(sorted(row.gap for row in dossiers if row.gap)), renderer=RENDERER)


def render_executive_html(report: Mapping[str, Any], dossiers: Sequence[BoundDossier] = (),
                          *, source_date_epoch: int = 0) -> str:
    """Render ``final-report.html`` deterministically from ``final-report.json`` and bound dossiers."""
    return render_html(executive_document(report, dossiers, source_date_epoch=source_date_epoch))


__all__ = ["BoundDossier", "RENDERER", "executive_document", "render_executive_html", "words"]
