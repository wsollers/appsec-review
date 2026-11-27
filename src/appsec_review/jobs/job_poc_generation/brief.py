"""The brief the writer receives for one candidate (review-judge-and-poc.md, section 5.1, step "plan").

The brief is data: the finding package fields, the ``poc_basis`` and its identities resolved against the
labelled package view, the declarations at the sink and the safe build facts of the translation unit
that contains it, plus the closed limits the validators enforce. It also fixes what the validators
will expect (:class:`~.policy.Expectation`): the sink name, the functions on the brief's call path and
the numeric trigger constraints. None of those come from the model's answer.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

from appsec_review.storage import canonical_json

from .buildctx import BuildUnit, Headers, declarations, tu_declarations
from .candidates import PocCandidate
from .policy import Expectation, Requirement, numeric_requirement
from .settings import PocGenerationSettings

BRIEF_SCHEMA = "appsec-review/poc-writer-brief/1"
ANSWER_SCHEMA = "appsec-review/poc-writer-answer/1"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)*")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NOT_TYPES = frozenset({"std", "const", "struct", "class", "union", "enum", "void", "int", "char", "bool", "unsigned"})


class BriefTooLarge(ValueError):
    """The complete brief cannot fit the configured budget without dropping evidence."""


def check_brief_size(document: Mapping[str, Any], byte_limit: int) -> None:
    size = len(canonical_json(document))
    if size > byte_limit:
        raise BriefTooLarge(f"brief_byte_bound_exceeded: complete brief is {size} bytes; "
                            f"brief.max_brief_bytes is {byte_limit}; no evidence was dropped")


_SKIP_CALL_NAMES = frozenset({
    "main", "wmain", "WinMain", "wWinMain", "DllMain", "_start", "_main", "DllEntryPoint",
    "LLVMFuzzerTestOneInput",
})


def _core_row_and_calls(identity: str, item: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    loc = item.get("location") or {}
    path = str(loc.get("path") or "")
    start = int(loc.get("start_line") or loc.get("line") or 0)
    end = int(loc.get("end_line") or start)
    lines = f"{start}-{end}" if start and end and end != start else (str(start) if start else "")
    summary = str(item.get("summary") or item.get("name") or item.get("kind") or identity)[:240]
    row = {"label": "CORE", "ref": identity, "role": str(item.get("kind") or "retrieved"),
           "path": path, "lines": lines, "summary": summary}
    calls: list[str] = []

    def add_name(raw: Any) -> None:
        if not isinstance(raw, str):
            return
        for candidate in _function_names(raw):
            bare = candidate.rsplit("::", 1)[-1]
            if bare in _SKIP_CALL_NAMES or candidate in _SKIP_CALL_NAMES:
                continue
            if candidate not in calls:
                calls.append(candidate)

    add_name(item.get("name"))
    add_name(summary)
    payload = item.get("payload")
    stack: list[Any] = [payload] if isinstance(payload, (Mapping, list, tuple)) else []
    visited = 0
    while stack and visited < 64:
        cur = stack.pop()
        visited += 1
        if isinstance(cur, Mapping):
            for key in ("callee", "caller", "function", "enclosing_function", "symbol", "target_name", "sink_name"):
                val = cur.get(key)
                if isinstance(val, str):
                    add_name(val)
                elif isinstance(val, Mapping):
                    add_name(val.get("name"))
            for val in cur.values():
                if isinstance(val, (Mapping, list, tuple)):
                    stack.append(val)
        elif isinstance(cur, (list, tuple)):
            for elem in cur[:32]:
                if isinstance(elem, (Mapping, list, tuple)):
                    stack.append(elem)
    return row, calls


@dataclass(frozen=True, slots=True)
class Brief:
    document: Mapping[str, Any]
    expectation_inputs: Mapping[str, Any]
    sink_names: tuple[str, ...]
    gaps: tuple[str, ...]
    synthesized_header: str | None = None

    def expectation(self, functions: tuple[str, ...]) -> Expectation:
        triggers: list[Requirement] = []
        unchecked: list[str] = []
        for row in self.expectation_inputs["triggers"]:
            requirement = numeric_requirement(str(row.get("constraint", "")))
            if requirement is None:
                unchecked.append(str(row.get("constraint", ""))[:120])
            else:
                triggers.append(requirement)
        return Expectation(functions, self.sink_names, frozenset(self.expectation_inputs["path_calls"]),
                           tuple(triggers), tuple(unchecked))


def rows_by_label(document: Any) -> dict[str, Mapping[str, Any]]:
    """Every labelled row of a package view document, by label."""
    found: dict[str, Mapping[str, Any]] = {}

    def walk(node: Any) -> None:
        if isinstance(node, Mapping):
            label = node.get("label")
            if isinstance(label, str) and label not in found:
                found[label] = node
            for value in node.values():
                if isinstance(value, (Mapping, list)):
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    return found


def _function_names(summary: str) -> list[str]:
    """Function-looking qualified names in a call-site summary such as ``relay -> relay::parse_header (L7)``."""
    return [name for name in _NAME.findall(summary) if not re.fullmatch(r"L\d+|line", name)]


def build_brief(candidate: PocCandidate, *, finding: Mapping[str, Any], package: Mapping[str, Any],
                view: Any, sink: Mapping[str, Any] | None, unit: BuildUnit | None, headers: Headers | None,
                settings: PocGenerationSettings, answer_example: Mapping[str, Any] | None = None,
                core: Any = None) -> Brief:
    """Assemble the brief; ``gaps`` names everything the writer was not given."""
    gaps: list[str] = []
    labels = rows_by_label(view.document) if view is not None else {}
    identities = {row["ref"]: row for row in labels.values() if isinstance(row.get("ref"), str)}
    basis = candidate.poc_basis
    resolved: dict[str, Any] = {}
    core_path_calls: dict[str, list[str]] = {}
    for identity in (*basis.entry, *basis.path):
        row = identities.get(identity)
        if row is None and core is not None and hasattr(core, "find"):
            found = core.find(identity=identity, limit=1).get("results", ())
            if found:
                core_row, extra_calls = _core_row_and_calls(identity, found[0])
                resolved[identity] = core_row
                core_path_calls[identity] = extra_calls
                continue
        if row is None:
            gaps.append(f"poc_basis identity {identity} does not resolve in the package view")
            continue
        resolved[identity] = {key: value for key, value in row.items()
                              if key in {"label", "ref", "summary", "text", "path", "lines", "role", "tag"}}
    path_calls: set[str] = set()
    for identity in basis.path:
        row = resolved.get(identity)
        if row is not None:
            if identity in core_path_calls:
                path_calls.update(core_path_calls[identity])
            else:
                path_calls.update(_function_names(str(row.get("summary", ""))))
    sink_names = (str(sink["name"]),) if sink else ()
    if sink is None:
        gaps.append("the review package names no function that holds the sink")
    rows: list[Mapping[str, Any]] = []
    synth_hdr: str | None = None
    if unit is not None and headers is not None:
        call_targets = [*sink_names, *sorted(path_calls)]
        rows = declarations(unit, headers, call_targets, source_bytes=65536,
                            max_files=settings.brief.max_source_files, max_lines=settings.brief.declaration_lines)
        tu_rows, synth_hdr = tu_declarations(
            unit, rows, call_targets, headers=headers,
            allowed_std_headers=tuple(settings.policy.allowed_std_headers),
            source_bytes=65536, max_lines=settings.brief.declaration_lines,
        )
        if tu_rows:
            rows = [*rows, *tu_rows]
        # The struct and class layouts the prototypes name (the sizes the trigger must exceed or fit).
        words = {word for row in rows for line in row["text"] for word in _WORD.findall(line.split("|", 1)[-1])
                 if word not in _NOT_TYPES and len(word) > 2}
        if words:
            seen = {(row["path"], row["lines"]) for row in rows}
            rows += [row for row in declarations(
                unit, headers, sorted(words), source_bytes=65536, max_files=settings.brief.max_source_files,
                max_lines=settings.brief.declaration_lines, types_only=True) if (row["path"], row["lines"]) not in seen]
    if not rows:
        gaps.append("no prototype of the sink function was found in the project headers on the include path")
    document: dict[str, Any] = {
        "schema": BRIEF_SCHEMA,
        "answer_schema": ANSWER_SCHEMA,
        "claim": {"label": finding.get("label"), "state": candidate.state, "judge_verdict": candidate.judge_verdict,
                  "title": finding.get("title"), "lane": finding.get("lane"),
                  "missing_predicates": list(finding.get("missing_predicates", ()))},
        "poc_basis": basis.record(),
        "poc_basis_labels": resolved,
        "sink": dict(sink) if sink else None,
        "declarations": list(rows),
        "build_facts": unit.command.facts() if unit is not None else None,
        "package_view": view.document if view is not None else None,
        "limits": limits(settings),
        "gaps": gaps,
    }
    if answer_example is not None:
        document["answer_shape"] = dict(answer_example)
    check_brief_size(document, settings.brief.max_brief_bytes)
    return Brief(document, {"triggers": [dict(row) for row in basis.trigger], "path_calls": sorted(path_calls)},
                 sink_names, tuple(gaps), synthesized_header=synth_hdr)


def limits(settings: PocGenerationSettings) -> dict[str, Any]:
    """The closed limits the deterministic validators enforce, stated as data (not as instructions)."""
    bounds = settings.bounds
    return {"function_name": "poc_<lowercase words>", "max_function_lines": bounds.max_function_lines,
            "max_file_bytes": bounds.max_file_bytes, "max_includes": bounds.max_includes,
            "max_loop_iterations": bounds.max_loop_iterations, "max_array_elements": bounds.max_array_elements,
            "max_string_literal_bytes": bounds.max_string_literal_bytes,
            "allowed_standard_headers": sorted(settings.policy.allowed_std_headers),
            "allowed_standard_calls": sorted(settings.policy.call_allowlist),
            "allowed_types": sorted(settings.policy.type_allowlist),
            "project_calls": ("the sink and the functions of the brief's call path"
                              if settings.policy.project_calls == "sink_and_path" else "any project function")}


__all__ = ["ANSWER_SCHEMA", "BRIEF_SCHEMA", "Brief", "build_brief", "limits", "rows_by_label"]
