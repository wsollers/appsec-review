"""The protocol interchange of one review cell, as a timeline of boxes.

A recording is one model call. Its request carries the transcript so far, so the calls of one cell
form chains in which each call extends the previous call's transcript by the worker turn it
returned and the application turn that answered it. The primary chain of a cell is its longest
one; shorter or divergent chains (retries, repairs after a model error) are counted and named, not
hidden.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .digest import (abbrev, bullets, counts_text, digest_mapping, field, id_list, scalar, table, val)
from .model import Box, Field, Fields, Item, Para, Truncation
from .text import bound, canonical, clean, sha256_text, sha256_value
from .tokens import BoxKind, Limits

RED_ROLES = frozenset({"hypothesis_hunter", "red_team_analyst"})
ROLE_ORDER = {"hypothesis_hunter": 0, "red_team_analyst": 1, "blue_team_refuter": 2, "independent_verifier": 3}
ROLE_TITLES = {"hypothesis_hunter": "Hypothesis hunter", "red_team_analyst": "Red team analyst",
               "blue_team_refuter": "Blue team refuter", "independent_verifier": "Independent verifier"}


def role_title(role: str) -> str:
    return ROLE_TITLES.get(role, role.replace("_", " ").capitalize())


@dataclass(frozen=True)
class Call:
    path: str
    key: str
    sequence: int
    request: Mapping[str, Any]
    result: Mapping[str, Any] | None
    error: Mapping[str, Any] | None
    turns: tuple[Mapping[str, Any], ...]
    hashes: tuple[str, ...]


@dataclass(frozen=True)
class Chain:
    leaf: Call
    ancestors: tuple[Call, ...]       # calls whose transcripts are prefixes of the leaf's


def make_call(path: str, recording: Mapping[str, Any]) -> Call:
    request = recording["request"]
    transcript = request.get("transcript") if isinstance(request.get("transcript"), list) else []
    turns = tuple(turn for turn in transcript if isinstance(turn, Mapping))
    result = recording.get("result") if isinstance(recording.get("result"), Mapping) else None
    error = recording.get("error") if isinstance(recording.get("error"), Mapping) else None
    sequence = recording.get("sequence")
    return Call(path, clean(recording.get("key")), sequence if isinstance(sequence, int) else 0, request,
                result, error, turns, tuple(sha256_value(turn) for turn in turns))


def build_chains(calls: Sequence[Call]) -> list[Chain]:
    ordered = sorted(calls, key=lambda call: (len(call.turns), call.key, call.sequence))
    leaves = []
    for call in ordered:
        extended = any(len(other.turns) > len(call.turns) and other.hashes[: len(call.turns)] == call.hashes
                       for other in ordered)
        if not extended:
            leaves.append(call)
    chains = []
    for leaf in leaves:
        ancestors = tuple(call for call in ordered if call is not leaf and len(call.turns) <= len(leaf.turns)
                          and leaf.hashes[: len(call.turns)] == call.hashes)
        chains.append(Chain(leaf, ancestors))
    # primary first: most turns, then a chain that ended in a result rather than an error
    chains.sort(key=lambda chain: (-len(chain.leaf.turns), chain.leaf.error is not None, chain.leaf.key, chain.leaf.sequence))
    return chains


def _call_at(chain: Chain, length: int) -> Call | None:
    """The call that produced the worker turn following ``length`` transcript turns."""
    pool = [call for call in (*chain.ancestors, chain.leaf) if len(call.turns) == length]
    pool.sort(key=lambda call: (call.result is None, call.key, call.sequence))
    return pool[0] if pool else None


def _tokens(call: Call | None) -> str:
    if call is None or call.result is None:
        return ""
    result = call.result
    parts = [f"{scalar(result.get('input_tokens', 0))} in", f"{scalar(result.get('output_tokens', 0))} out"]
    if result.get("cache_tokens"):
        parts.append(f"{scalar(result['cache_tokens'])} cached")
    return " / ".join(parts) + " tokens"


def _meta(call: Call | None, extra: str = "") -> str:
    model = clean((call.request.get("model") if call else "") or "")
    pieces = [piece for piece in (model, _tokens(call), extra) if piece]
    return " · ".join(pieces)


def request_box(request: Mapping[str, Any], limits: Limits) -> Box:
    task_input = request.get("task_input") if isinstance(request.get("task_input"), Mapping) else {}
    capability = task_input.get("capability") if isinstance(task_input.get("capability"), Mapping) else {}
    inner = task_input.get("input") if isinstance(task_input.get("input"), Mapping) else {}
    protocol = task_input.get("turn_protocol") if isinstance(task_input.get("turn_protocol"), Mapping) else {}
    rows = [field("role", request.get("role"), limits), field("persona", request.get("persona") or "-", limits),
            field("task", task_input.get("task"), limits, mono=True), field("lens", inner.get("lens"), limits, mono=True),
            field("round", task_input.get("round"), limits),
            field("model", f"{scalar(request.get('model'))} via {scalar(request.get('provider'))}, reasoning {scalar(request.get('reasoning'))}", limits),
            field("token caps", f"{scalar(request.get('max_input_tokens'))} in / {scalar(request.get('max_output_tokens'))} out", limits),
            field("output schema", task_input.get("output_schema"), limits, mono=True),
            field("guidance bundle", request.get("guidance_bundle_sha256"), limits, mono=True)]
    items: list[Item] = [Fields(tuple(rows))]
    tools = [clean(tool) for tool in capability.get("tools", []) if isinstance(tool, str)] if isinstance(capability.get("tools"), list) else []
    if tools:
        shown = tools[:16]
        suffix = f" (+{len(tools) - 16} more)" if len(tools) > 16 else ""
        items[0] = Fields(tuple(rows) + (Field("tools offered", ", ".join(shown) + suffix, mono=True),))
    budget = [("turns", capability.get("max_turns")), ("queries", capability.get("max_queries")),
              ("rows per page", capability.get("page_size")), ("depth", capability.get("max_depth")),
              ("bytes per result", capability.get("max_result_bytes")),
              ("requests per turn", protocol.get("max_requests_per_turn"))]
    budget = [f"{value} {label}" for label, value in budget if value is not None]
    if budget:
        items[0] = Fields(items[0].rows + (field("limits", " / ".join(budget), limits),))
    repair = request.get("repair_errors")
    if isinstance(repair, list) and repair:
        items.append(Para(f"Repair errors fed back to the model ({len(repair)})", muted=True))
        items.append(bullets(repair, limits, shown=4))
    return Box(BoxKind.REQUEST, "Task and tools", meta="application to model", items=tuple(items))


def _ordinal(index: Any) -> str:
    """Requests are numbered from 1 in the worker turn; the application's 0-based index is shifted to match."""
    return str(index + 1) if isinstance(index, int) and not isinstance(index, bool) else scalar(index)


def _requests_table(content: Mapping[str, Any], limits: Limits) -> Item:
    requests = [item for item in content.get("requests", []) if isinstance(item, Mapping)] \
        if isinstance(content.get("requests"), list) else []
    rows = [(index + 1, item.get("tool"), canonical(item.get("parameters", {}))) for index, item in enumerate(requests)]
    return table(("#", "tool", "parameters"), rows, limits, widths=(0.05, 0.22, 0.69),
                 mono=(False, True, True), max_rows=limits.requests_per_turn)


def worker_turn_box(turn: Mapping[str, Any], call: Call | None, limits: Limits) -> Box:
    content = turn.get("content") if isinstance(turn.get("content"), Mapping) else {}
    number = scalar(turn.get("turn"))
    action = clean(content.get("action") or "unknown")
    count = len(content.get("requests", [])) if isinstance(content.get("requests"), list) else 0
    items: list[Item] = []
    if action == "retrieve":
        items.append(_requests_table(content, limits))
    else:
        items.extend(digest_mapping(content, limits))
    title = f"Turn {number}: retrieve ({count} request{'s' if count != 1 else ''})" if action == "retrieve" \
        else f"Turn {number}: {action}"
    return Box(BoxKind.RESPONSE, title, meta=_meta(call), items=tuple(items))


def _row_text(row: Mapping[str, Any]) -> str:
    kind, source, target = row.get("kind"), row.get("source_id"), row.get("target_id")
    if source or target:
        return f"{scalar(kind)} {abbrev(source)} -> {abbrev(target)}"
    payload = row.get("payload", row)
    return canonical(payload)


def application_turn_boxes(turn: Mapping[str, Any], limits: Limits) -> list[Box]:
    number = scalar(turn.get("turn"))
    responses = [item for item in turn.get("responses", []) if isinstance(item, Mapping)] \
        if isinstance(turn.get("responses"), list) else []
    ok = [item for item in responses if item.get("status") == "ok"]
    problems = [item for item in responses if item.get("status") != "ok"]
    meta_bits = [f"{scalar(turn.get('remaining_queries'))} queries left", f"{scalar(turn.get('remaining_turns'))} turns left"]
    if turn.get("final_required"):
        meta_bits.append("final answer required")
    boxes: list[Box] = []
    if ok or not problems:
        rows = []
        for response in ok:
            results = response.get("results") if isinstance(response.get("results"), list) else []
            flags = []
            if response.get("truncated"):
                flags.append("truncated")
            if response.get("withheld_out_of_scope"):
                flags.append(f"{scalar(response['withheld_out_of_scope'])} withheld out of scope")
            gaps = response.get("coverage_gaps")
            if isinstance(gaps, list) and gaps:
                flags.append(f"{len(gaps)} gaps")
            rows.append((_ordinal(response.get("index")), response.get("tool"), len(results), ", ".join(flags) or "-"))
        items: list[Item] = [table(("#", "tool", "rows", "notes"), rows, limits, widths=(0.05, 0.30, 0.09, 0.52),
                                   mono=(False, True, False, False), max_rows=limits.requests_per_turn)] if rows else \
            [Para("The application returned no result rows this turn.", muted=True)]
        samples = []
        for response in ok:
            for row in (response.get("results") or [])[:2]:
                if isinstance(row, Mapping):
                    samples.append((response.get("tool"), _row_text(row)))
        if samples:
            items.append(Para("Sample rows", muted=True))
            items.append(table(("tool", "row"), samples, limits, widths=(0.22, 0.74), mono=(True, True),
                               max_rows=limits.results_per_response))
        boxes.append(Box(BoxKind.RESULT, f"Turn {number}: retrieval result", meta=" · ".join(meta_bits), items=tuple(items)))
    if problems:
        rows = [(_ordinal(item.get("index")), clean(item.get("status")), item.get("code") or item.get("error_class") or "-",
                 item.get("reason") or item.get("tool") or "-") for item in problems]
        boxes.append(Box(BoxKind.FEEDBACK, f"Turn {number}: feedback to the model",
                         meta=f"{len(problems)} of {len(responses)} requests not served",
                         items=(Para("The application returned these as data. A denial is an answer to the model, not a failure of the review.", muted=True),
                                table(("#", "status", "code", "detail"), rows, limits, widths=(0.05, 0.14, 0.26, 0.51),
                                      mono=(False, False, True, False), max_rows=limits.requests_per_turn))))
    return boxes


def _title_of(proposal: Mapping[str, Any], default: str) -> tuple[str, str | None]:
    for key in ("title", "name", "summary", "hypothesis"):
        value = proposal.get(key)
        if isinstance(value, str) and value.strip():
            return bound(value, 100)[0], key
    return default, None


def final_boxes(role: str, content: Mapping[str, Any], call: Call | None, limits: Limits) -> list[Box]:
    number = scalar(content.get("turn", ""))
    body = content.get("result") if isinstance(content.get("result"), Mapping) else {}
    proposals = body.get("proposals") if isinstance(body.get("proposals"), list) else []
    kind = {"blue_team_refuter": BoxKind.COUNTER, "independent_verifier": BoxKind.VERIFICATION}.get(role, BoxKind.RESPONSE)
    chip = {"blue_team_refuter": "COUNTER", "independent_verifier": "VERIFIER"}.get(role)
    skip = ("schema", "proposals")
    boxes = [Box(kind, f"Final answer of the {role_title(role).lower()}", meta=_meta(call),
                 items=tuple(digest_mapping(body, limits, skip=skip)) or (Para("The answer carries no fields."),),
                 chip=chip)]
    for index, proposal in enumerate(proposals[: limits.rows], 1):
        if not isinstance(proposal, Mapping):
            continue
        title, used = _title_of(proposal, f"Proposal {index}")
        boxes.append(Box(BoxKind.CLAIM if role in RED_ROLES else kind, title, meta=f"proposal {index} of {len(proposals)}",
                         items=tuple(digest_mapping(proposal, limits, skip=("schema", used) if used else ("schema",))),
                         chip="PROPOSAL" if role in RED_ROLES else chip))
    if len(proposals) > limits.rows:
        rest = proposals[limits.rows:]
        boxes.append(Box(BoxKind.PROVENANCE, "More proposals",
                         items=(Para(f"{len(rest)} more proposals, sha256 {sha256_value(rest)}"),)))
    return boxes


def timeline(chain: Chain, role: str, limits: Limits) -> list[Box]:
    leaf = chain.leaf
    boxes: list[Box] = []
    turns = list(leaf.turns)
    pairs: list[list[Box]] = []
    for position, turn in enumerate(turns):
        if turn.get("from") == "worker":
            call = _call_at(chain, position)
            pairs.append([worker_turn_box(turn, call, limits)])
        else:
            if not pairs:
                pairs.append([])
            pairs[-1].extend(application_turn_boxes(turn, limits))
    keep = limits.turns_per_cell
    if len(pairs) > keep:
        head, tail = pairs[: keep - 2], pairs[-2:]
        omitted = pairs[keep - 2: -2]
        flat = [box for pair in omitted for box in pair]
        note = Box(BoxKind.PROVENANCE, f"{len(omitted)} middle turns omitted",
                   items=(Para(f"{len(omitted)} of {len(pairs)} turns are not shown, sha256 {sha256_value([b.title for b in flat])}. "
                               "All turns are in the model recording."),))
        pairs = [*head, [note], *tail]
    for pair in pairs:
        boxes.extend(pair)
    if leaf.error is not None:
        boxes.append(Box(BoxKind.FEEDBACK, "Model call failed", meta=_meta(leaf),
                         items=(Fields((field("error type", leaf.error.get("type"), limits, mono=True),
                                        field("message", leaf.error.get("message"), limits))),
                                Para("The failure is recorded as a typed gap; it is not read as a negative finding.", muted=True))))
    elif leaf.result is not None:
        proposal = leaf.result.get("proposal") if isinstance(leaf.result.get("proposal"), Mapping) else {}
        action = clean(proposal.get("action"))
        number = (len(leaf.turns) // 2) + 1
        if action == "final":
            boxes.extend(final_boxes(role, {"turn": number, "result": proposal.get("result")}, leaf, limits))
        elif action == "retrieve":
            boxes.append(worker_turn_box({"turn": number, "content": proposal}, leaf, limits))
            boxes.append(Box(BoxKind.GAP, "The cell ended before a final answer",
                             items=(Para("The last model turn was a retrieve request that the cell budget did not allow to run. "
                                         "No conclusion was reached, and none should be inferred."),)))
        else:
            boxes.append(Box(BoxKind.GAP, "The model returned no usable action",
                             items=(Para("The recorded answer carries no retrieve or final action."),)))
    return boxes


def cell_provenance_box(cell_id: str, cell: Mapping[str, Any] | None, receipts: Sequence[tuple[str, Mapping[str, Any], str]],
                        chains: Sequence[Chain], calls: int, limits: Limits) -> Box:
    rows = [field("cell", cell_id, limits, mono=True)]
    if cell:
        rows += [field("recorded status", cell.get("status"), limits), field("attempts", cell.get("attempts"), limits),
                 field("gaps", len(cell.get("gap_ids", [])) if isinstance(cell.get("gap_ids"), list) else 0, limits)]
    rows.append(field("model calls recorded", f"{calls} in {len(chains)} chain(s)", limits))
    items: list[Item] = [Fields(tuple(rows))]
    if receipts:
        table_rows = []
        for name, receipt, digest in receipts:
            counts = receipt.get("counts") if isinstance(receipt.get("counts"), Mapping) else {}
            table_rows.append((name, receipt.get("status"), receipt.get("reason") or "-", counts.get("turns", "-"),
                               counts.get("queries", "-"), counts.get("denials", "-"),
                               f"{counts.get('input_tokens', 0)}/{counts.get('output_tokens', 0)}", digest[:12]))
        items.append(Para("Attempt receipts", muted=True))
        items.append(table(("attempt", "status", "reason", "turns", "queries", "denials", "tokens in/out", "sha256"),
                           table_rows, limits, widths=(0.12, 0.11, 0.25, 0.07, 0.09, 0.09, 0.13, 0.14),
                           mono=(False, False, False, False, False, False, False, True), max_rows=4))
    return Box(BoxKind.PROVENANCE, "Cell provenance", collapsed=True, items=tuple(items))
