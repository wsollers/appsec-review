"""Render ``final-report.md`` from ``final-report.json``, deterministically.

The renderer is a pure function of the report, verified private-format references and two display
bounds: the same input gives byte-identical output. It reads no clock, locale, environment or file.
Every string that came from a
review artifact is shown inside a code span after control characters and backticks are removed, so
document text can never become Markdown structure or HTML.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.reporting.dimensions import build_radar_tracker
from appsec_review.reporting.dossier_receipts import FORMAT_LEGACY, FORMAT_UNLOADED
from appsec_review.reporting.text import metric_text
from appsec_review.reporting.executive_posture import (
    build_attack_chain_cards,
    build_executive_posture,
    build_named_coverage_gaps,
    build_remediation_roadmap,
)

from .report import RENDERER

DIMENSION_LABELS = (("technical_severity", "Technical severity"),
                    ("exploitability_confidence", "Exploitability confidence"),
                    ("environmental_business_impact", "Environmental and business impact"),
                    ("remediation_priority", "Remediation priority"))
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")


def code(value: Any) -> str:
    """A value as an inline code span that cannot break out of itself."""
    text = _CONTROL.sub(" ", str(value)).replace("`", "'").strip()
    return f"`{text}`"


def plain(value: Any) -> str:
    """Prose from a fixed generator, with markup characters neutralised."""
    text = _CONTROL.sub(" ", str(value)).strip()
    return re.sub(r"([\\`*{}\[\]<>#|~])", r"\\\1", text)


def _ids(values: Sequence[str], limit: int) -> str:
    shown = ", ".join(code(item) for item in values[:limit])
    rest = len(values) - limit
    if not values:
        return "none"
    if limit == 0:
        return f"{len(values)} (not listed here; see final-report.json)"
    return shown + (f" and {rest} more (see final-report.json)" if rest > 0 else "")


def _counts(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{key} {value}" for key, value in counts.items()) or "none"


def _dimension(value: Mapping[str, Any] | None) -> str:
    if value is None:
        return "not produced (a gap, not a low value)"
    rating = "unrated" if value["rating"] is None else code(value["rating"])
    number = "" if value.get("value") is None else f", value {value['value']}"
    return f"{rating} on scale {code(value['scale'])}{number}"


def _pending_lines(block: Mapping[str, Any]) -> list[str]:
    """The explicit label of a finding whose ship-block decision is pending (never "does not block")."""
    if block["status"] != "decision_pending":
        return []
    missing = ", ".join(code(name) for name in block["missing_factors"]) or "the technical severity rating itself"
    bounds = ""
    if block["technical_severity_floor"] is not None:
        bounds = (f"; the missing factors leave the severity between {code(block['technical_severity_floor'])} "
                  f"and {code(block['technical_severity_ceiling'])}")
    return [f"- **decision pending: severity not yet rated; what is missing: {missing}{bounds}**. "
            "This is neither a ship-blocking decision nor a release decision."]


def _judge(verdict: Mapping[str, Any] | None, independence: Mapping[str, Any]) -> str:
    """The accepted judge verdict, shown beside the state; a disagreement with the state is never hidden."""
    if verdict is None:
        return "no judge verdict (the judge did not run for this claim)"
    note = "; the judge disagrees with this finding's state" if verdict["disagrees_with_state"] else ""
    distinct = {True: "yes", False: "no", None: "unknown"}[independence.get("judge_model_distinct")]
    return f"{code(verdict['verdict'])}{note}; judge model distinct {distinct}"


def _finding(index: int, item: Mapping[str, Any], settings: Mapping[str, int], *, unconfirmed: bool = False) -> list[str]:
    block, independence = item["ship_block"], item["independence"]
    heading = "unconfirmed " if unconfirmed else ""
    lines = [f"### {index}. {code(item['title'])}", "",
             f"- {heading}finding package {code(item['finding_package_id'])}, claim {code(item['claim_id'])}, "
             f"lane {code(item['lane'])}, state {code(item['state'])} ({code(item['label'])})",
             f"- ship-block status {code(block['status'])} under {code(block['policy'])}; reasons: "
             f"{', '.join(code(reason) for reason in block['reasons']) or 'none'}",
             f"- technical severity used by the policy: {'unrated' if block['technical_severity'] is None else code(block['technical_severity'])}",
             *_pending_lines(block),
             f"- independence: independent verifier {'yes' if independence['independent'] else 'no'}, provider distinct "
             f"{'yes' if independence['provider_distinct'] else 'no'}, verifier model distinct "
             f"{'yes' if independence['verifier_model_distinct'] else 'no'}",
             f"- judge: {_judge(item['judge_verdict'], independence)}",
             f"- direct evidence relations ({len(item['direct_evidence'])}): "
             f"{_ids(item['direct_evidence'], settings['evidence'])}",
             f"- analyst-assessed relations, recorded but not counted ({len(item['analyst_assessed_evidence'])}): "
             f"{_ids(item['analyst_assessed_evidence'], settings['evidence'])}"]
    if item["missing_predicates"]:
        lines.append("- missing predicates: " + ", ".join(code(name) for name in item["missing_predicates"]))
    lines.append(f"- gaps ({len(item['gap_ids'])}): {_ids(item['gap_ids'], settings['gaps'])}")
    if item["scores"]:
        lines.append("- scores (separate dimensions, never combined):")
        for score in item["scores"]:
            provider = score["provider"]
            native = score["native"]
            label = "no native rating" if native["rating"] is None else f"native rating {code(native['rating'])}"
            lines.append(f"  - {code(provider['id'])} ({code(provider['implementation'])}), {label}")
            lines.extend(f"    - {title}: {_dimension(score[key])}" for key, title in DIMENSION_LABELS)
            assessment = score["severity_assessment"]
            bounds = (f", severity between {code(assessment['severity_floor'])} and {code(assessment['severity_ceiling'])}"
                      if assessment["assessment"] == "unrated" and assessment["severity_floor"] is not None else "")
            lines.append(f"    - severity assessment: {code(assessment['assessment'])}{bounds}")
            if score["missing_factors"]:
                lines.append("    - missing factors: " + ", ".join(code(name) for name in score["missing_factors"]))
    else:
        lines.append("- scores: none (a gap)")
    return lines + [""]


def _section(title: str, items: Iterable[Mapping[str, Any]], settings: Mapping[str, int], empty: str,
             *, unconfirmed: bool = False) -> list[str]:
    items = list(items)
    lines = [f"## {title}", ""]
    if not items:
        return lines + [empty, ""]
    for index, item in enumerate(items, 1):
        lines.extend(_finding(index, item, settings, unconfirmed=unconfirmed))
    return lines


def _dimensions(radar: Mapping[str, Any]) -> list[str]:
    """The 12-axis, 4-series security radar & verification funnel table."""
    axes = radar["axes"]
    unclassified = radar["unclassified_packages"]
    lines = [
        "## Coverage by security dimension",
        "",
        "| Key | Dimension | Surface exposure | Verified coverage | Corroborated leads | Confirmed High/Crit (All) | Coverage posture |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for ax in axes:
        s = ax["series"]
        posture = (
            code("UNVERIFIED_COVERAGE_GAP")
            if ax["coverage_status"] in {"unverified_gap", "partial_coverage_gap"}
            else code(ax["coverage_status"])
        )
        qualifications = list(ax["gap_reasons"]) + [
            f"metric: {reason}" for reason in s["corroborated_leads"].get("gap_reasons", ())
        ]
        lines.append(
            f"| {ax['key']} | {plain(ax['label'])} | {metric_text(s['surface_exposure']['raw_count'])} "
            f"({metric_text(s['surface_exposure']['score'])}) | {metric_text(s['verified_coverage']['score'], '%')} | "
            f"{metric_text(s['corroborated_leads']['raw_count'])} | "
            f"{s['confirmed_high_critical']['raw_count']} ({s['confirmed_high_critical']['all_confirmed_count']}) | "
            f"{posture}{'; ' + plain(', '.join(qualifications)) if qualifications else ''} |"
        )
    lines += [
        "",
        f"Claim and finding counts come from accepted packages' titles (`<predicate> (<CWE>)`); {unclassified} package(s) "
        "named no member of the vocabulary and are counted in no dimension. Missing, skipped or partial coverage "
        "is explicitly marked as an Unverified Coverage Gap and is never evidence that a security domain is clean. "
        "Exposure, inspection and corroboration require explicit telemetry; N/A means unknown, not zero. "
        "Corroboration metric gaps do not change independently measured coverage.",
        "",
    ]
    return lines


def _roadmap(report: Mapping[str, Any]) -> list[str]:
    roadmap = report.get("remediation_roadmap")
    if roadmap is None:
        roadmap = build_remediation_roadmap(report)
    lines = ["## Prioritized remediation roadmap", ""]
    if not roadmap:
        return lines + ["No confirmed finding packages require remediation scheduling.", ""]
    lines += [
        "| Rank | Tier | Severity | Domain | Package | Validation status | PoC posture |",
        "|---:|---|---|---|---|---|---|",
    ]
    for row in roadmap:
        poc = row["poc_posture"]
        lines.append(
            f"| {row['rank']} | {code(row['priority_tier'])} | {code(row['technical_severity'])} | "
            f"{code(row['domain_id'])} | {code(row['finding_package_id'])} | "
            f"{code(row['validation_status'])} | "
            f"{code(poc['status'])} ({code(poc['generated_code_execution'])}) |"
        )
    lines.append("")
    return lines


def render_markdown(report: Mapping[str, Any], *, evidence_ids: int, gap_ids: int,
                    dossier_formats: Mapping[str, Mapping[str, Mapping[str, str]] | None] | None = None) -> str:
    settings = {"evidence": evidence_ids, "gaps": gap_ids}
    status, summary = report["status"], report["summary"]
    counts, accounting = summary["package_counts"], summary["accounting"]
    block = summary["ship_block"]
    radar = report.get("radar_tracker") or build_radar_tracker(report)
    posture = report.get("executive_posture") or build_executive_posture(report, radar)
    sev = posture["confirmed_by_severity"]
    cci = posture["coverage_confidence_index"]

    lines = [
        "# Final security review report", "",
        f"- run {code(report['run_id'])}",
        f"- review status {code(status['review'])}; publication status {code(status['publication'])}; "
        f"release readiness {code(posture['release_readiness'])}",
        f"- review presented as complete: **{'yes' if status['review_complete'] else 'no'}**",
        f"- report renderer {code(RENDERER)}; PDF: {plain(report['renderers']['pdf']['reason'])}", ""]
    if not status["review_complete"]:
        lines += ["> This review is not complete. The limitations section lists why; none of it is a clean verdict.", ""]
    if radar.get("schema") == "appsec-review/security-radar-tracker/1":
        lines += ["> Legacy radar /1 estimates are retained as recorded, not certified exposure or inspection measurements.", ""]
    lines += ["## Summary", "",
              f"- executive risk posture: confirmed critical {sev['critical']}, high {sev['high']}, "
              f"medium {sev['medium']}, low {sev['low']}, unrated {sev['unrated']}; "
              f"chain-elevated findings {posture['chain_elevated_findings_count']}; "
              f"reachable supply-chain advisories {posture['reachable_supply_chain_advisories_count']}",
              f"- coverage confidence index: {metric_text(cci['score'], '/100')} ({cci['verified_axes']}/12 verified domains, "
              f"{cci['gap_axes']}/12 unverified coverage gap domains)",
              f"- claims reviewed: {accounting['claims_total']} "
              f"({_counts({k: v for k, v in accounting['claims_by_state'].items() if v})})",
              f"- finding packages: {counts['total']} = {counts['publishable']} publishable (confirmed) + "
              f"{counts['verification_backlog']} verification backlog (unconfirmed) + {counts['withheld']} withheld",
              f"- ship-block status counts under {code(block['policy'])}: {_counts(block['by_status'])}",
              f"  - lead lane: {_counts(block['by_lane']['lead'])}",
              f"  - hunt lane: {_counts(block['by_lane']['hunt'])}",
              *([f"- decision pending: {block['by_status']['decision_pending']} finding(s) have no technical severity "
                 "yet, so they are neither ship-blocking nor cleared; each is marked below with what is missing"]
                if block["by_status"]["decision_pending"] else []),
              f"- gap ratio {accounting['gap_ratio']:.3f} (incomplete above {accounting['incomplete_gap_ratio']:.3f}); "
              f"gaps by class: {_counts({k: v for k, v in accounting['gaps_by_class'].items() if v})}", ""]
    lines += _dimensions(radar)
    lines += _roadmap(report)
    lines += _section("Findings (confirmed)", report["findings"], settings, "No confirmed finding packages are publishable.")
    lines += ["## Attack chains", "", f"Status {code(report['attack_chains']['status'])}: {plain(report['attack_chains']['reason'])}"]
    chain_cards = report.get("attack_chain_cards")
    if chain_cards is None:
        chain_cards = build_attack_chain_cards(report)
    card_by_id = {c["chain_id"]: c for c in chain_cards}
    for item in report["attack_chains"]["items"]:
        lines.append(f"- {code(item['chain_id'])}: {code(item['status'])}; artifact {code(item['artifact']['path'])}")
        card = card_by_id.get(item["chain_id"])
        if card:
            lines.append(
                f"  - composed severity {code(card['composed_severity'])}; "
                f"trust boundary crossed {code(card['trust_boundary_crossed'])}; "
                f"steps: " + " -> ".join(f"{s['role']}:{code(s['claim_id'])}" for s in card["steps"])
            )
    lines += [""]
    lines += ["## Proof-of-trigger outcomes", "",
              f"Status {code(report['poc_outcomes']['status'])}: {plain(report['poc_outcomes']['reason'])}"]
    for item in report["poc_outcomes"]["items"]:
        lines.append(f"- {code(item['finding_package_id'])}: {code(item['status'])}")
        if "claim_id" in item:
            lines.append(f"  - claim {code(item['claim_id'])}: {plain(item['description'])}")
            if item.get("functions"):
                lines.append(f"  - test function {code(item['functions']['test_function'])}, negative control "
                             f"{code(item['functions']['negative_control'])}")
            if item.get("files"):
                lines.append("  - files: " + ", ".join(code(item["files"][key]["path"]) for key in (
                    "source", "compile", "readme", "provenance")))
    lines += [""]
    lines += ["Execution and negative controls: **not performed by policy**. Compilation is not runtime proof.", ""]
    for key, title, artifact_key in (("remediation_planning", "Remediation proposals", "plan"),
                                     ("remediation_validation", "Remediation validation", "validation")):
        section = report[key]
        lines += [f"## {title}", "", plain(section["reason"])]
        for item in section["items"]:
            artifact = item[artifact_key]
            lines.append(f"- {code(item['finding']['finding_package_id'])}: {code(item['status'])}; "
                         + (f"artifact {code(artifact['path'])}" if artifact else "no artifact available"))
        lines += ["", "These attachments do not change finding state or shipment decisions. "
                  "No regression was executed.", ""]
    lines += ["## Protected developer dossiers", "", plain(report["dossiers"]["reason"])]
    for item in report["dossiers"]["items"]:
        lines.append(f"- {code(item['dossier_id'])} ({code(item['kind'])}): {code(item['status'])}; "
                     + ", ".join(f"{key} {code(ref['path'])}" for key, ref in item["files"].items() if ref is not None))
        formats = (dossier_formats or {}).get(item["dossier_id"])
        if formats:
            lines.extend(f"  - certified protected {name} {code(ref['path'])}; SHA-256 {code(ref['sha256'])}"
                         for name, ref in sorted(formats.items()))
        else:
            lines.append("  - " + plain(FORMAT_UNLOADED if formats is None else FORMAT_LEGACY))
    lines += ["", "Dossier contents are protected developer artifacts, not embedded public report content.", ""]
    lines += ["## Capability accounting", ""]
    lines += [f"- {code(name)}: {code(record['disposition'])}; outcomes {record['item_count']}, "
              f"omitted {record['omitted_count']}, gaps {record['gap_count']}"
              for name, record in sorted(report["capabilities"].items())] + [""]
    lines += _section("Verification backlog (unconfirmed)", report["verification_backlog"], settings,
                      "The verification backlog is empty.", unconfirmed=True)
    lines += ["## Withheld packages", ""]
    if not report["withheld"]:
        lines += ["No finding package is withheld.", ""]
    for item in report["withheld"]:
        lines += [f"- {code(item['finding_package_id'])}, claim {code(item['claim_id'])}, lane {code(item['lane'])}, "
                  f"state {code(item['state'])}, ship-block status {code(item['ship_block']['status'])}; withheld because: "
                  + ", ".join(code(reason) for reason in item["withheld_reasons"])]
    if report["withheld"]:
        lines += [""]
    lines += ["## Limitations and gaps", ""]
    for item in report["limitations"]:
        lines.append(f"- {code(item['limitation_id'])} ({item['kind']}): {plain(item['statement'])}")
    named_gaps = report.get("named_coverage_gaps")
    if named_gaps is None:
        named_gaps = build_named_coverage_gaps(report, radar)
    if named_gaps:
        lines += [
            "",
            "| Gap ID | Category | Scope | Disposition |",
            "|---|---|---|---|",
        ]
        for ng in named_gaps:
            lines.append(
                f"| {code(ng['gap_id'])} | {code(ng['category'])} | "
                f"{plain(ng['affected_scope'])} | {code(ng['disposition'])} |"
            )
    lines += ["", f"Recorded gap identifiers ({len(report['gap_ids'])}): {_ids(report['gap_ids'], gap_ids)}", ""]
    lines += ["## Notices", ""] + [f"- {plain(text)}" for text in report["notices"]] + [""]
    provenance = report["provenance"]
    lines += ["## Provenance", "",
              f"- gate handoff {code(provenance['gate_handoff']['sha256'])}",
              f"- gate document {code(provenance['gate_document']['sha256'])}",
              f"- review handoff {code(provenance['review_handoff']['sha256'])}",
              f"- accepted manifest {code(provenance['accepted_manifest_sha256'])}",
              f"- ledger head {code(provenance['ledger_head_sha256'])}",
              f"- configuration {code(provenance['configuration_sha256'])}",
              f"- ship-block policy {code(provenance['ship_block_policy_sha256'])}", ""]
    if "configuration_profile" in provenance:
        lines.insert(-1, f"- runtime profile {code(provenance['configuration_profile']['name'])}")
    return "\n".join(lines).rstrip("\n") + "\n"
