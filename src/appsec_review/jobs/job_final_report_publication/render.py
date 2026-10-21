"""Render ``final-report.md`` from ``final-report.json``, deterministically.

The renderer is a pure function of the report document and two display bounds: the same input gives
byte-identical output. It reads no clock, locale, environment or file. Every string that came from a
review artifact is shown inside a code span after control characters and backticks are removed, so
document text can never become Markdown structure or HTML.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from .report import RENDERER

DIMENSION_LABELS = (("technical_severity", "Technical severity"),
                    ("exploitability_confidence", "Exploitability confidence"),
                    ("environmental_business_impact", "Environmental and business impact"),
                    ("remediation_priority", "Remediation priority"))
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")


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


def render_markdown(report: Mapping[str, Any], *, evidence_ids: int, gap_ids: int) -> str:
    settings = {"evidence": evidence_ids, "gaps": gap_ids}
    status, summary = report["status"], report["summary"]
    counts, accounting = summary["package_counts"], summary["accounting"]
    block = summary["ship_block"]
    lines = [
        "# Final security review report", "",
        f"- run {code(report['run_id'])}",
        f"- review status {code(status['review'])}; publication status {code(status['publication'])}",
        f"- review presented as complete: **{'yes' if status['review_complete'] else 'no'}**",
        f"- report renderer {code(RENDERER)}; PDF: {plain(report['renderers']['pdf']['reason'])}", ""]
    if not status["review_complete"]:
        lines += ["> This review is not complete. The limitations section lists why; none of it is a clean verdict.", ""]
    lines += ["## Summary", "",
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
    lines += _section("Findings (confirmed)", report["findings"], settings, "No confirmed finding packages are publishable.")
    lines += ["## Attack chains", "", f"Status {code(report['attack_chains']['status'])}: {plain(report['attack_chains']['reason'])}"]
    lines += [f"- {code(item)}" for item in report["attack_chains"]["items"]] + [""]
    lines += ["## Proof-of-trigger outcomes", "",
              f"Status {code(report['poc_outcomes']['status'])}: {plain(report['poc_outcomes']['reason'])}"]
    for item in report["poc_outcomes"]["items"]:
        lines.append(f"- {code(item['finding_package_id'])}: {code(item['status'])}")
        if "claim_id" in item:                                        # outcomes of job_poc_generation
            lines.append(f"  - claim {code(item['claim_id'])}: {plain(item['description'])}")
            if item.get("functions"):
                lines.append(f"  - test function {code(item['functions']['test_function'])}, negative control "
                             f"{code(item['functions']['negative_control'])}")
            if item.get("files"):
                lines.append("  - files: " + ", ".join(code(item["files"][key]["path"]) for key in (
                    "source", "compile", "readme", "provenance")))
    lines += [""]
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
