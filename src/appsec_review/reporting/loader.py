"""Build the renderer-neutral report document from one run directory (read-only, deterministic)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .digest import (STATE_WORDS, abbrev, bullets, counts_text, digest_mapping, field, id_list, scalar, state_field,
                     table, val)
from .evidence import package_boxes, package_title
from .interchange import (ROLE_ORDER, RED_ROLES, Call, Chain, build_chains, cell_provenance_box, make_call,
                          request_box, role_title, timeline)
from .model import (Block, Box, Document, Field, Fields, Heading, Item, Legend, Note, Para, Stat, Stats)
from .sources import JOB, Ledger, RunReader, file_sha256
from .text import anchor, bound, clean, sha256_value, token
from .tokens import STATUS_TONES, BoxKind, Limits

TITLE = "Security review report"
_RUN_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:\D|$)")


@dataclass(frozen=True, slots=True)
class Selection:
    """Which packages to render. ``limit`` keeps the first N after ordering; ``packages`` are id prefixes."""

    limit: int | None = None
    packages: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.limit is not None and self.limit < 1:
            raise ValueError("limit must be positive")


def _epoch(*candidates: Any, run_id: str) -> int:
    """A time taken from the run: a handoff completion time, else the run id's date, else the epoch."""
    for candidate in candidates:
        if isinstance(candidate, str):
            try:
                return int(datetime.fromisoformat(candidate.replace("Z", "+00:00")).astimezone(UTC).timestamp())
            except ValueError:
                continue
    match = _RUN_DATE.match(run_id)
    if match:
        try:
            return int(datetime(int(match[1]), int(match[2]), int(match[3]), tzinfo=UTC).timestamp())
        except ValueError:
            pass
    return 0


def load_document(run_dir: Path, *, limits: Limits = Limits(), selection: Selection = Selection()) -> Document:
    run_dir = Path(run_dir)
    reader = RunReader(run_dir)
    report_pair = reader.final_report()
    report: Mapping[str, Any] = report_pair[1] if report_pair else {}
    run_id = clean(report.get("run_id")) or clean(run_dir.name)
    ledger = reader.ledger()
    publication_handoff = reader.handoff("job_final_report_publication")
    gate_handoff = reader.handoff("job_final_publication_gate")

    blocks: list[Block] = []
    package_blocks, shown, total = _packages(reader, ledger, limits, selection)
    summary_blocks, _calls = _summary(reader, report, report_pair, ledger, limits, gate_handoff, total)
    blocks.extend(summary_blocks)
    if selection.limit or selection.packages:
        blocks.append(Note(f"This rendering shows {shown} of {total} reviewed packages (selection: "
                           f"{'first ' + str(selection.limit) if selection.limit else 'by id'}"
                           f"{', ids ' + ', '.join(bound(p, 40)[0] for p in selection.packages) if selection.packages else ''})."))
    blocks.append(Heading(1, "Reading guide", anchor("legend"), new_page=True))
    blocks.append(Legend())
    blocks.extend(package_blocks)
    gaps = tuple(bound(message, 240)[0] for message in reader.gaps)
    if gaps:
        blocks.insert(_after_summary(blocks), Box(BoxKind.GAP, "Artifacts this report could not read", meta=f"{len(gaps)} named gaps",
                      items=(Para("Each is a named gap in this rendering, not evidence about the target."),
                             bullets(gaps, limits, shown=12, chars=240))))
    provenance = report.get("provenance") if isinstance(report.get("provenance"), Mapping) else {}
    status = report.get("status") if isinstance(report.get("status"), Mapping) else {}
    handoff_time = (publication_handoff or {}).get("completed_at") or (gate_handoff or {}).get("completed_at")
    return Document(
        title=TITLE, run_id=run_id,
        subtitle=_subtitle(status),
        status_badge=token(status.get("review"), "UNKNOWN"), status_tone=STATUS_TONES.get(clean(status.get("review")), "unresolved"),
        source_date_epoch=_epoch(handoff_time, run_id=run_id),
        ledger_head=clean(provenance.get("ledger_head_sha256")) or "not available",
        blocks=tuple(blocks), named_gaps=gaps)


def _subtitle(status: Mapping[str, Any]) -> str:
    review = clean(status.get("review")).replace("_", " ").lower() or "unknown"
    publication = clean(status.get("publication")).replace("_", " ").lower() or "unknown"
    return f"{review.capitalize()} review, {publication}"


def _after_summary(blocks: Sequence[Block]) -> int:
    for index, block in enumerate(blocks):
        if isinstance(block, Heading) and block.level == 1 and block.text == "Reading guide":
            return index
    return len(blocks)


# -- summary ----------------------------------------------------------------------------------------

def _summary(reader: RunReader, report: Mapping[str, Any], report_pair: Any, ledger: Ledger, limits: Limits,
             gate_handoff: Mapping[str, Any] | None, reviewed_packages: int) -> tuple[list[Block], int]:
    blocks: list[Block] = []
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    accounting = summary.get("accounting") if isinstance(summary.get("accounting"), Mapping) else {}
    counts = summary.get("package_counts") if isinstance(summary.get("package_counts"), Mapping) else {}
    status = report.get("status") if isinstance(report.get("status"), Mapping) else {}
    receipts = _all_receipts(reader)
    calls = sum(1 for _ in _recording_files(reader))
    tokens_in = sum(_int(r.get("counts", {}).get("input_tokens")) for r in receipts)
    tokens_out = sum(_int(r.get("counts", {}).get("output_tokens")) for r in receipts)
    claims_total = accounting.get("claims_total", len(ledger.claims))
    stats = [Stat("Review", clean(status.get("review")) or "unknown", tone=STATUS_TONES.get(clean(status.get("review")), "unresolved")),
             Stat("Publication", (clean(status.get("publication")) or "unknown").replace("PUBLISHABLE_WITH_LIMITATIONS", "LIMITED"),
                  tone=STATUS_TONES.get(clean(status.get("publication")), "unresolved")),
             Stat("Claims", scalar(claims_total)),
             Stat("Packages reviewed", scalar(reviewed_packages)),
             Stat("Cells", scalar(len(ledger.cells) or len(receipts))),
             Stat("Model calls", scalar(calls)),
             Stat("Tokens in / out", f"{_compact(tokens_in)} / {_compact(tokens_out)}"),
             Stat("Gap ratio", f"{accounting['gap_ratio']:.2f}" if isinstance(accounting.get("gap_ratio"), (int, float)) else "-")]
    blocks.append(Heading(1, "Summary", anchor("summary")))
    blocks.append(Stats(tuple(stats)))
    if status and not status.get("review_complete", False):
        blocks.append(Box(BoxKind.GAP, "This review is not complete", items=(
            Para("The limitations below say why. None of it is a clean verdict: missing, skipped or failed coverage is a named gap, "
                 "never evidence that the target is free of defects."),)))
    # accounting tables
    items: list[Item] = []
    by_state = {k: v for k, v in (accounting.get("claims_by_state") or {}).items() if v} if isinstance(accounting.get("claims_by_state"), Mapping) else {}
    if by_state:
        items.append(table(("claim state", "count"), sorted(by_state.items()), limits, widths=(0.6, 0.3), badges=(True, False)))
    elif ledger.claims:
        tally = Counter(ledger.claim_state(claim_id) for claim_id in ledger.claim_order)
        items.append(table(("claim state", "count"), sorted(tally.items()), limits, widths=(0.6, 0.3), badges=(True, False)))
    else:
        items.append(Para("No claim reached the ledger.", muted=True))
    by_class = {k: v for k, v in (accounting.get("gaps_by_class") or {}).items() if v} if isinstance(accounting.get("gaps_by_class"), Mapping) else {}
    if by_class:
        items.append(table(("gap class", "count"), sorted(by_class.items(), key=lambda p: (-p[1], p[0])), limits, widths=(0.6, 0.3), max_rows=14))
    blocks.append(Box(BoxKind.PROVENANCE, "Accounting", items=tuple(items)))
    # findings, backlog, withheld
    blocks.append(Heading(2, "Findings", anchor("findings")))
    for name, key, empty in (("Confirmed findings", "findings", "No confirmed finding package is publishable."),
                             ("Verification backlog", "verification_backlog", "The verification backlog is empty."),
                             ("Withheld packages", "withheld", "No finding package is withheld.")):
        entries = [e for e in (report.get(key) or []) if isinstance(e, Mapping)] if isinstance(report.get(key), list) else []
        if not entries:
            blocks.append(Note(f"{name}: {empty}"))
            continue
        for entry in entries[: limits.rows]:
            blocks.append(_finding_box(name, entry, limits))
        if len(entries) > limits.rows:
            rest = entries[limits.rows:]
            blocks.append(Note(f"{name}: {len(rest)} more, sha256 {sha256_value(rest)}"))
    ship = summary.get("ship_block") if isinstance(summary.get("ship_block"), Mapping) else {}
    if isinstance(ship.get("by_status"), Mapping):
        blocks.append(Box(BoxKind.PROVENANCE, "Ship-block status", meta=clean(ship.get("policy")), items=(
            table(("status", "count"), sorted(ship["by_status"].items()), limits, widths=(0.6, 0.3)),)))
    # limitations
    blocks.append(Heading(2, "Limitations", anchor("limitations")))
    limitations = [e for e in (report.get("limitations") or []) if isinstance(e, Mapping)] if isinstance(report.get("limitations"), list) else []
    for entry in limitations[: limits.rows]:
        statement, cut = bound(entry.get("statement"), limits.text_chars)
        blocks.append(Box(BoxKind.GAP, clean(entry.get("limitation_id")) or "limitation",
                          meta=f"{scalar(entry.get('kind'))} · {scalar(entry.get('count'))}", items=(Para(statement, cut),)))
    if len(limitations) > limits.rows:
        rest = limitations[limits.rows:]
        blocks.append(Note(f"{len(rest)} more limitations, sha256 {sha256_value(rest)}"))
    if not limitations:
        blocks.append(Note("The final report lists no limitation."))
    notices = [clean(n) for n in report.get("notices", []) if isinstance(n, str)] if isinstance(report.get("notices"), list) else []
    if notices:
        blocks.append(Box(BoxKind.PROVENANCE, "Notices", items=(bullets(notices, limits, shown=6, chars=420),)))
    blocks.append(_provenance(report, report_pair, gate_handoff, limits))
    return blocks, calls


def _finding_box(group: str, entry: Mapping[str, Any], limits: Limits) -> Box:
    ship = entry.get("ship_block") if isinstance(entry.get("ship_block"), Mapping) else {}
    independence = entry.get("independence") if isinstance(entry.get("independence"), Mapping) else {}
    state = clean(entry.get("state"))
    rows = [state_field("state", state), field("label", entry.get("label"), limits),
            field("package", entry.get("finding_package_id"), limits, mono=True),
            field("claim", entry.get("claim_id"), limits, mono=True), field("lane", entry.get("lane"), limits),
            field("ship block", f"{scalar(ship.get('status'))} ({', '.join(clean(r) for r in ship.get('reasons', []) if isinstance(r, str)) or 'no reason'})", limits),
            field("independent verifier", independence.get("independent"), limits),
            field("direct evidence", len(entry.get("direct_evidence", [])) if isinstance(entry.get("direct_evidence"), list) else 0, limits),
            field("gaps", len(entry.get("gap_ids", [])) if isinstance(entry.get("gap_ids"), list) else 0, limits)]
    if entry.get("missing_predicates"):
        rows.append(field("missing predicates", entry.get("missing_predicates"), limits))
    if entry.get("withheld_reasons"):
        rows.append(field("withheld because", entry.get("withheld_reasons"), limits))
    return Box(BoxKind.CLAIM, bound(entry.get("title"), 140)[0] or "finding", meta=group,
               badges=(state,) if state in STATE_WORDS else (), items=(Fields(tuple(rows)),))


def _provenance(report: Mapping[str, Any], report_pair: Any, gate_handoff: Mapping[str, Any] | None, limits: Limits) -> Box:
    provenance = report.get("provenance") if isinstance(report.get("provenance"), Mapping) else {}
    rows = [field("run", report.get("run_id"), limits, mono=True),
            field("final report schema", report.get("schema"), limits, mono=True),
            field("ledger head", provenance.get("ledger_head_sha256"), limits, mono=True),
            field("accepted manifest", provenance.get("accepted_manifest_sha256"), limits, mono=True),
            field("configuration", provenance.get("configuration_sha256"), limits, mono=True),
            field("ship-block policy", provenance.get("ship_block_policy_sha256"), limits, mono=True)]
    for label, key in (("gate handoff", "gate_handoff"), ("gate document", "gate_document"), ("review handoff", "review_handoff")):
        ref = provenance.get(key)
        if isinstance(ref, Mapping):
            rows.append(field(label, f"{scalar(ref.get('path'))}  {scalar(ref.get('sha256'))}", limits, mono=True, limit=300))
    if report_pair:
        rows.append(Field("final-report.json sha256", file_sha256(report_pair[0]), mono=True))
    renderers = report.get("renderers") if isinstance(report.get("renderers"), Mapping) else {}
    pdf = renderers.get("pdf") if isinstance(renderers.get("pdf"), Mapping) else {}
    if pdf:
        rows.append(field("pdf state in final report", f"{scalar(pdf.get('state'))}", limits))
    return Box(BoxKind.PROVENANCE, "Provenance", items=(Fields(tuple(rows)),))


def _compact(count: int) -> str:
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    if count >= 10_000:
        return f"{count / 1_000:.0f}k"
    return f"{count:,}"


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _all_receipts(reader: RunReader) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted((reader.data / "jobs" / JOB / "cells").glob("cell-*/attempt-*.json")):
        value = reader.read_json(path, "cell receipt")
        if isinstance(value, dict):
            out.append(value)
    return out


def _recording_files(reader: RunReader):
    directory = reader.data / "inference-recordings" / JOB
    yield from sorted(directory.glob("*.json")) if directory.is_dir() else ()


# -- packages ---------------------------------------------------------------------------------------

def _packages(reader: RunReader, ledger: Ledger, limits: Limits, selection: Selection) -> tuple[list[Block], int, int]:
    index = reader.recording_index()
    cells_by_package: dict[str, list[str]] = {}
    for cell_id, cell in ledger.cells.items():
        cells_by_package.setdefault(clean(cell.get("package_id")), []).append(cell_id)
    for cell_id, paths in index.items():
        if cell_id not in ledger.cells:
            package_id = _package_id_from_recording(reader, paths)
            if package_id:
                cells_by_package.setdefault(package_id, []).append(cell_id)
    claims_by_package: dict[str, list[str]] = {}
    for claim_id in ledger.claim_order:
        claims_by_package.setdefault(clean(ledger.claims[claim_id].get("package_id")), []).append(claim_id)
    universe = sorted(set(cells_by_package) | set(claims_by_package) - {""},
                      key=lambda pid: (pid not in claims_by_package, pid))
    universe = [pid for pid in universe if pid]
    chosen = universe
    if selection.packages:
        chosen = [pid for pid in chosen if any(pid.startswith(prefix) or prefix in pid for prefix in selection.packages)]
    if selection.limit:
        chosen = chosen[: selection.limit]
    blocks: list[Block] = [Heading(1, "Reviewed packages", anchor("packages"), new_page=True)]
    if not universe:
        reader.gap("review packages: no package is known to the ledger or the model recordings")
        blocks.append(Note("No reviewed package could be identified from the ledger or the model recordings."))
    for number, package_id in enumerate(chosen, 1):
        blocks.extend(_package_section(reader, ledger, limits, index, package_id, number, len(chosen),
                                       sorted(cells_by_package.get(package_id, [])), claims_by_package.get(package_id, [])))
    return blocks, len(chosen), len(universe)


def _package_id_from_recording(reader: RunReader, paths: list[Path]) -> str:
    for _path, recording in reader.recordings(paths[:1]):
        package = _embedded_package(recording)
        if package:
            return clean(package.get("package_id"))
    return ""


def _embedded_package(recording: Mapping[str, Any]) -> Mapping[str, Any] | None:
    task_input = recording.get("request", {}).get("task_input")
    inner = task_input.get("input") if isinstance(task_input, Mapping) else None
    package = inner.get("package") if isinstance(inner, Mapping) else None
    return package if isinstance(package, Mapping) else None


def _package_section(reader: RunReader, ledger: Ledger, limits: Limits, index: Mapping[str, list[Path]], package_id: str,
                     number: int, count: int, cell_ids: list[str], claim_ids: list[str]) -> list[Block]:
    blocks: list[Block] = []
    cells = sorted(cell_ids, key=lambda cid: (ROLE_ORDER.get(clean(ledger.cells.get(cid, {}).get("role")), 9), cid))
    recordings: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    shown_cells = cells[: limits.cells_per_package]
    for cell_id in shown_cells:
        recordings[cell_id] = list(reader.recordings(index.get(cell_id, [])))
    package: Mapping[str, Any] | None = None
    source = ""
    assembled = reader.assembled_package(package_id)
    if assembled:
        package, source = assembled[1], reader.rel(assembled[0])
    else:
        for pairs in recordings.values():
            for _path, recording in pairs:
                embedded = _embedded_package(recording)
                if embedded:
                    package, source = embedded, "embedded in the model request"
                    break
            if package:
                break
    extra_pair = reader.review_package(package_id)
    extra = extra_pair[1] if extra_pair else None
    title = package_title(package) if package else "package content unavailable"
    lane = clean(package.get("lane")) if package else ""
    blocks.append(Heading(2, f"Package {number} of {count}: {title}", anchor("package", package_id),
                          subtitle=" · ".join(p for p in (lane, clean(package.get("lead_family") or package.get("kind")) if package else "", abbrev(package_id, 16)) if p),
                          new_page=number > 1))
    blocks.append(Heading(3, "Evidence passed in", anchor("evidence", package_id)))
    if package is None:
        reader.gap(f"package {package_id[:32]}: content not found in assembled packages, review packages or recordings")
        blocks.append(Box(BoxKind.GAP, "Package content is not available", items=(
            Para("Neither an assembled package, a review package nor a model recording carries this package. "
                 "The interchange below is rendered without its evidence."),)))
    else:
        echo_basis = None
        for pairs in recordings.values():
            for _p, recording in pairs:
                inner = recording["request"].get("task_input", {}).get("input", {}) if isinstance(recording["request"].get("task_input"), Mapping) else {}
                echo = inner.get("echo", {}).get("package", {}) if isinstance(inner, Mapping) and isinstance(inner.get("echo"), Mapping) else {}
                if isinstance(echo, Mapping) and echo.get("basis_sha256"):
                    echo_basis = clean(echo["basis_sha256"])
                    break
            if echo_basis:
                break
        blocks.extend(package_boxes(package, extra, source=source, echo_basis=echo_basis, limits=limits))
    # interchanges
    blocks.append(Heading(3, "Protocol interchange", anchor("interchange", package_id)))
    if not cells:
        blocks.append(Note("No review cell is recorded for this package."))
    for cell_id in shown_cells:
        blocks.extend(_cell_section(reader, ledger, limits, cell_id, recordings.get(cell_id, [])))
    if len(cells) > len(shown_cells):
        rest = cells[len(shown_cells):]
        roles = Counter(clean(ledger.cells.get(cid, {}).get("role")) for cid in rest)
        blocks.append(Note(f"{len(rest)} more cells ({counts_text(roles)}) are not rendered here, sha256 {sha256_value(rest)}."))
    # outcome
    blocks.append(Heading(3, "Outcome", anchor("outcome", package_id)))
    blocks.extend(_outcome(ledger, limits, package_id, cells, claim_ids))
    return blocks


def _cell_section(reader: RunReader, ledger: Ledger, limits: Limits, cell_id: str,
                  pairs: list[tuple[Path, dict[str, Any]]]) -> list[Block]:
    cell = ledger.cells.get(cell_id)
    receipts = [(path.stem, receipt, file_sha256(path)) for path, receipt in reader.cell_receipts(cell_id)]
    calls = [make_call(reader.rel(path), recording) for path, recording in pairs]
    chains = build_chains(calls)
    request = chains[0].leaf.request if chains else (pairs[0][1]["request"] if pairs else {})
    role = clean((cell or {}).get("role") or request.get("role") or "cell")
    persona = clean((cell or {}).get("persona") or request.get("persona") or "")
    model = clean(request.get("model") or (receipts[0][1].get("model") if receipts else "") or "")
    blocks: list[Block] = [Heading(4, f"{role_title(role)}" + (f" ({persona})" if persona else ""), anchor("cell", cell_id),
                                   subtitle=" · ".join(p for p in (model, clean((cell or {}).get("status")), abbrev(cell_id, 10)) if p))]
    if not chains:
        reader.gap(f"cell {cell_id[:24]}: no model recording")
        blocks.append(Box(BoxKind.GAP, "No model recording for this cell",
                          items=(Para("The cell has a receipt or ledger record but no recorded model call, so its interchange cannot be shown."),)))
    else:
        blocks.append(request_box(request, limits))
        blocks.extend(timeline(chains[0], role, limits))
        if len(chains) > 1:
            others = [f"{len(c.leaf.turns)} turns, {'error ' + clean(c.leaf.error.get('type')) if c.leaf.error else 'result'}" for c in chains[1:]]
            blocks.append(Box(BoxKind.PROVENANCE, f"{len(chains) - 1} other call chain(s) for this cell",
                              items=(Para("Retries or repairs. Only the longest chain is drawn."), bullets(others, limits, shown=5)),
                              collapsed=True))
    blocks.append(cell_provenance_box(cell_id, cell, receipts, chains, len(calls), limits))
    return blocks


# -- outcome ----------------------------------------------------------------------------------------

def _outcome(ledger: Ledger, limits: Limits, package_id: str, cells: list[str], claim_ids: list[str]) -> list[Block]:
    blocks: list[Block] = []
    if claim_ids:
        for claim_id in claim_ids[: limits.claims_per_package]:
            blocks.append(_claim_box(ledger, limits, claim_id))
        if len(claim_ids) > limits.claims_per_package:
            rest = claim_ids[limits.claims_per_package:]
            blocks.append(Note(f"{len(rest)} more claims, sha256 {sha256_value(rest)}."))
    else:
        blocks.append(Note("No claim reached the ledger for this package. This is a statement about the review, not about the target."))
    rows = []
    for cell_id in cells:
        cell = ledger.cells.get(cell_id, {})
        rows.append((role_title(clean(cell.get("role"))), cell.get("persona") or "-", cell.get("status") or "-",
                     cell.get("attempts", "-"), len(cell.get("gap_ids", [])) if isinstance(cell.get("gap_ids"), list) else 0))
    if rows:
        blocks.append(Box(BoxKind.PROVENANCE, "Cell outcomes", meta=f"{len(rows)} cells", items=(
            table(("role", "persona", "status", "attempts", "gaps"), rows, limits, widths=(0.28, 0.26, 0.16, 0.12, 0.10), max_rows=12),)))
    subjects = set(cells) | set(claim_ids) | {package_id}
    gaps = [gap for gap in ledger.gaps if clean(gap.get("subject_id")) in subjects]
    if gaps:
        by_class = Counter(clean(gap.get("gap_class")) for gap in gaps)
        ordered = sorted(gaps, key=lambda gap: (clean(gap.get("gap_class")), clean(gap.get("reason")), clean(gap.get("gap_id"))))
        reasons = [(gap.get("gap_class"), bound(gap.get("reason"), 160)[0], abbrev(gap.get("subject_id"), 10)) for gap in ordered]
        blocks.append(Box(BoxKind.GAP, "Gaps recorded in the ledger", meta=f"{len(gaps)} gaps · {counts_text(by_class, 4)}", items=(
            Para("A gap names missing, denied, failed or skipped coverage. It is never evidence that the target is clean.", muted=True),
            table(("class", "reason", "subject"), reasons, limits, widths=(0.20, 0.58, 0.18), mono=(False, False, True),
                  max_rows=limits.gaps_per_package))))
    return blocks


def _claim_box(ledger: Ledger, limits: Limits, claim_id: str) -> Box:
    claim = ledger.claims[claim_id]
    state = ledger.claim_state(claim_id)
    statement, cut = bound(claim.get("statement"), limits.text_chars)
    rows = [state_field("state", state), field("claim", claim_id, limits, mono=True), field("lane", claim.get("lane"), limits),
            field("weakness", claim.get("weakness_cwe") or "-", limits), field("security predicate", claim.get("security_predicate"), limits),
            field("origin cells", len(claim.get("origin_cell_ids", [])) if isinstance(claim.get("origin_cell_ids"), list) else 0, limits)]
    items: list[Item] = [Para(statement, cut), Fields(tuple(rows))]
    entities = claim.get("affected_entities") if isinstance(claim.get("affected_entities"), list) else []
    if entities:
        items.append(id_list("affected entities", entities, limits))
    pre = claim.get("preconditions") if isinstance(claim.get("preconditions"), list) else []
    if pre:
        items.append(Fields((field("preconditions", pre, limits),)))
    relations = ledger.relations.get(claim_id, [])
    if relations:
        tally = Counter(f"{clean(r.get('predicate'))}/{clean(r.get('kind'))}" for r in relations)
        items.append(Fields((Field("evidence relations", f"{len(relations)}: {counts_text(tally, 6)}"),)))
        rrows = [(r.get("predicate"), r.get("kind"), r.get("admissibility"), abbrev(r.get("entity_id")), r.get("complete")) for r in relations]
        items.append(table(("predicate", "kind", "admissibility", "entity", "complete"), rrows, limits,
                           widths=(0.20, 0.13, 0.22, 0.32, 0.09), mono=(False, False, False, True, False), max_rows=6))
    steps = ledger.transitions.get(claim_id, [])
    if steps:
        srows = [(s.get("round"), f"{clean(s.get('from_state'))} -> {clean(s.get('to_state'))}", bound(s.get("reason"), 180)[0]) for s in steps]
        items.append(table(("round", "transition", "reason"), srows, limits, widths=(0.08, 0.34, 0.54), max_rows=6))
    duplicate = ledger.duplicates.get(claim_id)
    if duplicate:
        items.append(Fields((field("duplicate of", duplicate.get("duplicate_of"), limits, mono=True),)))
    return Box(BoxKind.CLAIM, "Claim", meta=clean(claim.get("lane")), badges=(state,) if state in STATE_WORDS else (), items=tuple(items))
