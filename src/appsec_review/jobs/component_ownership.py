"""Deterministic component ownership for paths in a cataloged target."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from appsec_review.jobs.cataloging import source_ecosystem


@dataclass(frozen=True, slots=True)
class Ownership:
    status: str
    basis: str
    component_ids: tuple[str, ...] = ()
    candidates: tuple[str, ...] = ()


def _under(root: str, path: str) -> bool:
    return root in {"", "."} or path == root or path.startswith(root.rstrip("/") + "/")


def resolve_ownership(path: str | None, components: Iterable[Mapping[str, Any]]) -> Ownership:
    """Use the deepest root, then exact manifest and source ecosystem to break ties."""
    if not path:
        return Ownership("not_applicable", "no-path")
    deepest: list[Mapping[str, Any]] = []
    best = -1
    for component in components:
        root = str(component.get("root") or ".")
        if not _under(root, path):
            continue
        depth = 0 if root == "." else len(PurePosixPath(root).parts)
        if depth > best:
            best, deepest = depth, [component]
        elif depth == best:
            deepest.append(component)
    if not deepest:
        return Ownership("unowned", "no-component-root")
    candidates = tuple(sorted({str(item["component_id"]) for item in deepest}))
    if len(candidates) == 1:
        return Ownership("owned", "deepest-root", candidates, candidates)
    manifests = tuple(sorted({str(item["component_id"]) for item in deepest if item.get("manifest") == path}))
    if len(manifests) == 1:
        return Ownership("owned", "manifest-file", manifests, candidates)
    ecosystem = source_ecosystem(path)
    matches = tuple(sorted({str(item["component_id"]) for item in deepest
                            if ecosystem is not None and item.get("ecosystem") == ecosystem}))
    if len(matches) == 1:
        return Ownership("owned", "manifest-ecosystem", matches, candidates)
    if matches:
        return Ownership("shared", "manifest-ecosystem", matches, candidates)
    return Ownership("ambiguous", "no-ecosystem-match", (), candidates)


def resolve_root_ownership(path: str, roots: Iterable[tuple[str, str]]) -> str | None:
    """Resolve root-only inputs without assigning an equal-depth tie by identifier order."""
    decision = resolve_ownership(path, ({"root": root, "component_id": component_id}
                                        for root, component_id in roots))
    return decision.component_ids[0] if decision.status == "owned" else None
