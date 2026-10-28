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

from .buildctx import BuildUnit, Headers, declarations
from .candidates import PocCandidate
from .policy import Expectation, Requirement, numeric_requirement
from .settings import PocGenerationSettings

BRIEF_SCHEMA = "appsec-review/poc-writer-brief/1"
ANSWER_SCHEMA = "appsec-review/poc-writer-answer/1"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_]*)*")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NOT_TYPES = frozenset({"std", "const", "struct", "class", "union", "enum", "void", "int", "char", "bool", "unsigned"})


@dataclass(frozen=True, slots=True)
class Brief:
    document: Mapping[str, Any]
    expectation_inputs: Mapping[str, Any]
    sink_names: tuple[str, ...]
    gaps: tuple[str, ...]

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
                settings: PocGenerationSettings, answer_example: Mapping[str, Any] | None = None) -> Brief:
    """Assemble the brief; ``gaps`` names everything the writer was not given."""
    gaps: list[str] = []
    labels = rows_by_label(view.document) if view is not None else {}
    identities = {row["ref"]: row for row in labels.values() if isinstance(row.get("ref"), str)}
    basis = candidate.poc_basis
    resolved: dict[str, Any] = {}
    for identity in (*basis.entry, *basis.path):
        row = identities.get(identity)
        if row is None:
            gaps.append(f"poc_basis identity {identity} does not resolve in the package view")
            continue
        resolved[identity] = {key: value for key, value in row.items()
                           if key in {"label", "ref", "summary", "text", "path", "lines", "role", "tag"}}
    path_calls: set[str] = set()
    for identity in basis.path:
        row = resolved.get(identity)
        if row is not None:
            path_calls.update(_function_names(str(row.get("summary", ""))))
    sink_names = (str(sink["name"]),) if sink else ()
    if sink is None:
        gaps.append("the review package names no function that holds the sink")
    rows: list[Mapping[str, Any]] = []
    if unit is not None and headers is not None:
        rows = declarations(unit, headers, [*sink_names, *sorted(path_calls)], source_bytes=65536,
                            max_files=settings.brief.max_source_files, max_lines=settings.brief.declaration_lines)
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
    if len(canonical_json(document)) > settings.brief.max_brief_bytes:
        document["package_view"] = _trimmed(view.document if view is not None else {}, settings)
        document["gaps"] = [*gaps, "the package view was reduced to fit the brief byte bound"]
        gaps.append("the package view was reduced to fit the brief byte bound")
    return Brief(document, {"triggers": [dict(row) for row in basis.trigger], "path_calls": sorted(path_calls)},
                 sink_names, tuple(gaps))


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


def _trimmed(view: Mapping[str, Any], settings: PocGenerationSettings) -> dict[str, Any]:
    keep = ("schema", "leads", "source", "neighborhood", "build", "material_gaps", "omitted")
    reduced = {key: view[key] for key in keep if key in view}
    neighborhood = dict(reduced.get("neighborhood") or {})
    for key in ("memory", "flows", "callees", "callers"):
        if key in neighborhood:
            neighborhood[key] = neighborhood[key][:4]
    reduced["neighborhood"] = neighborhood
    return reduced


__all__ = ["ANSWER_SCHEMA", "BRIEF_SCHEMA", "Brief", "build_brief", "limits", "rows_by_label"]
