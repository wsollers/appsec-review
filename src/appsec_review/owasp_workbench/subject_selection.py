"""Pure complete-source-subject selection; indexed locations are priorities, never proof.

Version 2 (T-5013) adds C and C++ beside Python. Each language has one recogniser module that
parses the accepted bytes once and names complete subjects (functions, the Python module, C/C++
named types). A subject carries its ``language`` so batching, packaging and the model worker consume
Python and C/C++ subjects through the same shape.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from . import c_subjects
from .obligations import _FUNCTIONS, _password_comparison, _route, _sql_call
from .standards import digest


SELECTION_RULE = "owasp-complete-source-subjects/2"
PYTHON = "python"
C_CPP = c_subjects.LANGUAGE
LANGUAGE_LABELS = {PYTHON: "Python", C_CPP: "C/C++"}
_PYTHON_NAMES = frozenset({"python", "python3"})
_NO_SUBJECT_GAP = {
    PYTHON: "no recognized subject for the four reviewed Python procedures",
    C_CPP: "no recognized subject for the reviewed C/C++ recogniser families",
}


def subject_language(path: str, language: str | None = None) -> str | None:
    """The recogniser language of an accepted source, or None when no recogniser reads it."""
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    if suffix == ".py" and (not language or language.lower() in _PYTHON_NAMES):
        return PYTHON
    if c_subjects.is_c_source(path, language):
        return C_CPP
    return None


@dataclass(frozen=True, slots=True)
class SourceSubject:
    kind: str
    name: str
    first: int
    last: int
    ast_sha256: str
    recognized: bool
    language: str = PYTHON
    # C/C++ only: recogniser family -> lines of the recognised calls, and the input-entry lines.
    families: Mapping[str, tuple[int, ...]] = field(default_factory=dict)
    entries: tuple[int, ...] = ()

    def record(self) -> dict[str, Any]:
        value = {"rule": SELECTION_RULE, "kind": self.kind, "name": self.name,
                 "lines": [self.first, self.last], "ast_sha256": self.ast_sha256, "language": self.language}
        if self.language == C_CPP:
            value["recognisers"] = {family: list(lines) for family, lines in sorted(self.families.items())}
            value["entries"] = list(self.entries)
            value["recogniser_version"] = c_subjects.RECOGNISER_VERSION
        return value


def parse_subjects(text: str, *, language: str = PYTHON) -> tuple[SourceSubject, ...]:
    """Parse accepted bytes once; retain original line positions and complete definition spans."""
    if language == PYTHON:
        return _parse_python(text)
    if language == C_CPP:
        return _parse_c(text)
    raise ValueError(f"no subject recogniser for language {language!r}")


def parse_gaps(text: str, *, language: str) -> tuple[str, ...]:
    """Scanner limitations that are not parse failures (C/C++ only; Python raises SyntaxError instead)."""
    return c_subjects.scan(text).gaps if language == C_CPP else ()


def _parse_c(text: str) -> tuple[SourceSubject, ...]:
    scan = c_subjects.scan(text)
    result = []
    for item in scan.functions:
        result.append(SourceSubject(item.kind, item.name, item.first, item.last,
                                    digest({"c": c_subjects.normalized(text, item)}), item.recognized,
                                    C_CPP, dict(item.families), item.entries))
    return tuple(sorted(result, key=lambda item: (item.first, item.last, item.kind, item.name)))


def _parse_python(text: str) -> tuple[SourceSubject, ...]:
    tree = ast.parse(text)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    recognized: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, _FUNCTIONS) and any(_route(item) for item in node.decorator_list):
            recognized.update((node, tree))
        if _sql_call(node, parents) or _password_comparison(node, parents):
            owner = node
            while owner is not tree and not isinstance(owner, _FUNCTIONS):
                owner = parents[owner]
            recognized.add(owner)

    result = []
    for node in ast.walk(tree):
        if not isinstance(node, (*_FUNCTIONS, ast.Module)):
            continue
        if isinstance(node, ast.Module):
            kind, name, first, last = "module", "<module>", 1, len(text.splitlines())
            if not last:
                continue
        else:
            names, ancestor = [node.name], node
            while ancestor in parents:
                ancestor = parents[ancestor]
                if isinstance(ancestor, (*_FUNCTIONS, ast.ClassDef)):
                    names.append(ancestor.name)
            kind, name = "function", ".".join(reversed(names))
            first = min(node.lineno, *(item.lineno for item in node.decorator_list)) if node.decorator_list else node.lineno
            last = node.end_lineno
        result.append(SourceSubject(kind, name, first, last,
                                    digest({"ast": ast.dump(node, include_attributes=False)}),
                                    node in recognized))
    return tuple(sorted(result, key=lambda item: (item.first, item.last, item.kind, item.name)))


def select_subjects(subjects: Sequence[SourceSubject], text: str, *, max_lines: int,
                    hints: Sequence[Mapping[str, Any]] = (), language: str = PYTHON
                    ) -> tuple[list[SourceSubject], list[str]]:
    """Prefer bounded module context for routes, then indexed complete subjects as fallback."""
    lines = text.splitlines()
    module = next((item for item in subjects if item.kind == "module" and item.recognized), None)
    if (module is not None and module.last - module.first + 1 <= max_lines
            and len("\n".join(lines[module.first - 1:module.last])) <= 16000):
        return [module], []

    def indexed(subject: SourceSubject) -> bool:
        return any(subject.first <= hint["start_line"] <= hint["end_line"] <= subject.last
                   for hint in hints)

    selected, gaps = [], []
    for subject in sorted((item for item in subjects if item.recognized),
                          key=lambda item: (not indexed(item), item.first, item.last, item.name)):
        if subject.last - subject.first + 1 > max_lines:
            gaps.append(f"{subject.name}: complete subject exceeds max_source_lines; 1 subject omitted")
        elif len("\n".join(lines[subject.first - 1:subject.last])) > 16000:
            gaps.append(f"{subject.name}: complete subject exceeds excerpt character cap; 1 subject omitted")
        else:
            selected.append(subject)
    if not any(item.recognized for item in subjects):
        gaps.append(_NO_SUBJECT_GAP[language])
    return selected, gaps
