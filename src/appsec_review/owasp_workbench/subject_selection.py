"""Pure complete-Python-subject selection; indexed locations are priorities, never proof."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .obligations import _FUNCTIONS, _password_comparison, _route, _sql_call
from .standards import digest


SELECTION_RULE = "owasp-complete-source-subjects/1"


@dataclass(frozen=True, slots=True)
class SourceSubject:
    kind: str
    name: str
    first: int
    last: int
    ast_sha256: str
    recognized: bool

    def record(self) -> dict[str, Any]:
        return {"rule": SELECTION_RULE, "kind": self.kind, "name": self.name,
                "lines": [self.first, self.last], "ast_sha256": self.ast_sha256}


def parse_subjects(text: str) -> tuple[SourceSubject, ...]:
    """Parse accepted bytes once; retain original line positions, decorators and nested names."""
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
                    hints: Sequence[Mapping[str, Any]] = ()) -> tuple[list[SourceSubject], list[str]]:
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
        gaps.append("no recognized subject for the four reviewed Python procedures")
    return selected, gaps
