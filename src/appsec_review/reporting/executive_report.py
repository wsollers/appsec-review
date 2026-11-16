"""The executive report: ``final-report.json`` plus the gate-bound dossiers, as a renderer-neutral document.

The readers are a project's tech lead and business owner. The document says, in plain words, what each
confirmed weakness is, where it is, what an attacker gains, how severe it is, whether an independent
verifier confirmed it and whether it blocks shipping; then the review's status, limits and provenance.

It is a pure function of its inputs: the same report and the same bound dossier documents give an
equal :class:`Document`, with no clock, locale, environment or file read. Every string that came from
a review artifact is cleaned and bounded here and escaped by the renderer; nothing is written raw.
Dossier source excerpts are protected developer content and are never copied: only a path and a
line range reach this document. The document carries no exploit code, prompt or payload.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from .digest import bullets, field, table
from .model import Box, Document, Fields, Heading, Para, Stat, Stats
from .text import bound, clean
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
    "Confirmed means an independent verifier examined the claim and agreed with it. A finding in the "
    "verification backlog is supported by evidence but has not been independently confirmed.")

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


@dataclass(frozen=True, slots=True)
class BoundDossier:
    """One dossier the gate certified: its document when its bytes verified, otherwise the named gap."""

    dossier_id: str
    kind: str
    finding: Mapping[str, Any]            # {claim_id, finding_package_id, sha256}
    document: Mapping[str, Any] | None
    gap: str | None = None


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
        text = "Yes: an independent verifier confirmed this finding"
        if independence.get("independent"):
            text += (f" (separate provider: {_yes(independence.get('provider_distinct'))}; "
                     f"distinct verifier model: {_yes(independence.get('verifier_model_distinct'))})")
        text += "."
    else:
        text = f"No: this finding is {words(item.get('label'))} and stays in the verification backlog."
    verdict = item.get("judge_verdict")
    if verdict:
        text += f" Judge verdict: {words(verdict.get('verdict'))}"
        text += " (the judge disagrees with the finding's state)." if verdict.get("disagrees_with_state") else "."
    return text


def _locations(dossier: Mapping[str, Any] | None) -> list[str]:
    """Path and line range only; the excerpt is protected developer content and never leaves the dossier."""
    rows: list[str] = []
    for source in (dossier or {}).get("sources") or ():
        path = clean(source.get("path")) or "path not recorded"
        start, end = source.get("start_line"), source.get("end_line")
        if start is not None and end is not None:
            row = f"{path}, lines {start}-{end}" if start != end else f"{path}, line {start}"
        else:
            row = f"{path}, line range not recorded"
        if row not in rows:                     # several evidence rows resolve to the same lines
            rows.append(row)
    return rows


#: What each accepted consequence class lets an attacker do, for a reader who does not know the CWE. Keyed by the
#: closed ``security_predicate`` vocabulary of the review; an unlisted value falls back to a generic sentence.
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
    what = (_text(statement) if statement else
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
    items: list[Any] = [Para(what), Fields(tuple(rows)),
                        Para("Where it is", muted=True),
                        _bullets(locations or ["No resolving source location was available to this report."]),
                        Para("What an attacker gains", muted=True), Para(_attacker_gain(document, item)),
                        Para("Remediation", muted=True),
                        _bullets(_remediation(document) or ["No remediation proposal or validation was available."])]
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


def _summary_blocks(report: Mapping[str, Any]) -> list[Any]:
    status, summary = report["status"], report["summary"]
    counts, accounting, block = summary["package_counts"], summary["accounting"], summary["ship_block"]
    gaps = [row for row in report["limitations"] if row["kind"] == "gap"]
    complete = bool(status.get("review_complete"))
    standing = (f"The review finished with status {words(status['review'])} and publication status "
                f"{words(status['publication'])}. ")
    standing += ("It may be presented as complete." if complete else
                 "It may not be presented as complete: " + (
                     f"{_plural(len(gaps), 'named gap')} limit it, listed below and in the limitations section."
                     if gaps else "its review status is not COMPLETE or it is marked incomplete."))
    by_status = block.get("by_status") or {}
    release = [f"{_plural(by_status.get(key, 0), 'finding')}: {SHIP_BLOCK_WORDS[key]}"
               for key in SHIP_BLOCK_WORDS if by_status.get(key)]
    return [
        Stats((Stat("Confirmed findings", str(counts["publishable"]),
                    "confirmed" if counts["publishable"] else "neutral"),
               Stat("Verification backlog", str(counts["verification_backlog"]),
                    "supported" if counts["verification_backlog"] else "neutral"),
               Stat("Withheld", str(counts["withheld"]), "unresolved" if counts["withheld"] else "neutral"),
               Stat("Review status", words(status["review"]), STATUS_TONES.get(status["review"], "unresolved")))),
        Heading(1, "Executive summary", "summary"),
        Box(BoxKind.RESULT, "Where the review stands", items=(
            Para(standing),
            Fields((field("Review complete", "yes" if complete else "no", LIMITS),
                    field("Claims reviewed", accounting.get("claims_total"), LIMITS),
                    field("Finding packages", f"{counts['total']} total: {counts['publishable']} confirmed, "
                          f"{counts['verification_backlog']} awaiting verification, {counts['withheld']} withheld", LIMITS),
                    field("Gap ratio", f"{accounting.get('gap_ratio', 0):.3f} (incomplete above "
                          f"{accounting.get('incomplete_gap_ratio', 0):.3f})", LIMITS))),
            *(() if complete else (Para("Why the review is not complete", muted=True),
                                   _bullets([f"{words(row['limitation_id'])}: {_text(row['statement'])}" for row in gaps]
                                            or ["The review status or incompleteness flag alone withholds completeness."]))))),
        Box(BoxKind.RESULT, f"Release impact under {clean(block.get('policy')) or 'the ship-block policy'}", items=(
            _bullets(release or ["No finding carries a ship-block status."]),
            Para(VERIFIED_WORDS, muted=True))),
        Box(BoxKind.GAP, "What \"not performed by policy\" means", chip="NOTICE", items=(Para(POLICY_STATEMENT),)),
    ]


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


def _limitation_blocks(report: Mapping[str, Any], dossiers: Sequence[BoundDossier]) -> list[Any]:
    grouped = {kind: [row for row in report["limitations"] if row["kind"] == kind] for kind in ("gap", "not_run", "notice")}
    coverage = report["summary"].get("coverage") or {}
    summary = ", ".join(f"{words(key)} {value}" for key, value in sorted((coverage.get("summary") or {}).items())) or "none"
    dossier_gaps = [f"{row.dossier_id}: {_text(row.gap, 400)}" for row in dossiers if row.gap]
    return [
        Heading(1, "Limitations and coverage", "limitations"),
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
    for row in dossiers:
        pdf = ((refs.get(row.dossier_id) or {}).get("files") or {}).get("pdf")
        dossier_rows.append((row.dossier_id, words(row.kind), "read" if row.document else "unavailable",
                             clean(pdf.get("path")) if isinstance(pdf, Mapping) else "no PDF"))
    blocks: list[Any] = [Heading(1, "Appendix: provenance", "provenance", new_page=True),
                         Box(BoxKind.PROVENANCE, "Accepted artifact bindings", items=(
                             table(("Artifact", "Run-relative path", "SHA-256"), rows, LIMITS,
                                   widths=(.22, .40, .34), mono=(False, True, True)),))]
    if dossier_rows:
        blocks.append(Box(BoxKind.PROVENANCE, "Protected dossier references", items=(
            Para("Dossiers are protected developer artifacts. This report read their JSON through the gate's hashes; "
                 "their source excerpts and generated code stay in the dossiers."),
            table(("Dossier", "Kind", "Read", "PDF"), dossier_rows, LIMITS, widths=(.36, .16, .12, .32),
                  mono=(True, False, False, True)))))
    blocks.append(Box(BoxKind.PROVENANCE, "Renderers", items=(Fields((
        field("Executive report", RENDERER, LIMITS, mono=True),
        field("Markdown report", (report["renderers"]["markdown"] or {}).get("renderer"), LIMITS, mono=True),
        field("Report schema", report.get("schema"), LIMITS, mono=True))),)))
    return blocks


def executive_document(report: Mapping[str, Any], dossiers: Sequence[BoundDossier] = (),
                       *, source_date_epoch: int = 0) -> Document:
    """Build the executive report document from ``final-report.json`` and the gate-bound dossiers."""
    for row in dossiers:
        if row.document is not None and row.document.get("schema") != DOSSIER_SCHEMA:
            raise ValueError(f"unsupported dossier model for {row.dossier_id}")
    by_claim = {row.finding["claim_id"]: row for row in dossiers if row.kind == "confirmed_finding"}
    blocks: list[Any] = _summary_blocks(report)
    blocks.append(Heading(1, "Confirmed findings", "findings"))
    findings = report["findings"]
    if not findings:
        blocks.append(Box(BoxKind.GAP, "No confirmed findings", items=(
            Para("No finding package is publishable as independently confirmed. " + NOT_CLEAN),)))
    for index, item in enumerate(findings, 1):
        blocks.append(_finding_box(index, item, by_claim.get(item["claim_id"])))
    blocks += _section_blocks(report, dossiers)
    blocks += _backlog_blocks(report)
    blocks += _limitation_blocks(report, dossiers)
    blocks += _appendix_blocks(report, dossiers)
    status = clean(report["status"]["review"])
    return Document(title=TITLE, run_id=clean(report["run_id"]), subtitle=SUBTITLE,
                    status_badge=status.upper(), status_tone=STATUS_TONES.get(status, "unresolved"),
                    source_date_epoch=source_date_epoch,
                    ledger_head=clean(report["provenance"].get("ledger_head_sha256")),
                    blocks=tuple(blocks),
                    named_gaps=tuple(sorted(row.gap for row in dossiers if row.gap)), renderer=RENDERER)


__all__ = ["BoundDossier", "RENDERER", "executive_document", "words"]
