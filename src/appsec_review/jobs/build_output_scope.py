"""Build-output dispositions: which workspace trees a build cataloguer lists per file, and why not.

A build workspace holds the target's own output beside content that is not the target's:
fetched dependency sources and their build trees, installer-recorded packages, and build-system
bookkeeping. Listing every such file as a target artifact row floods the target lane. This module
records one decision per tree root and replaces the cataloguers' ``rglob`` loops with a walk
that applies them (docs/architecture/native-build-output-discovery.md):

- ``classify_tree`` registers a root with a disposition, a basis, a confidence and the evidence
  that justified it. The deepest registered root governs a path; among bases for one root a
  configured exclusion outranks fact-level bases, which outrank a name heuristic. Two
  disagreeing fact-level bases leave the root ``per_file`` and record a conflict.
- ``walk`` yields the files a cataloguer should consider. Files under an ``excluded``,
  ``supply_chain`` or ``evidence`` root are counted with ``stat`` and never hashed; only a
  ``supply_chain`` root's ``keep`` paths (and, when asked, its linked binaries) are yielded,
  carrying the root's ``scope_role``. Configured ``[build_outputs]`` exclusions apply at every
  directory, inside classified roots too, and are recorded by name, pattern and scope.
- The recorder never emits gaps. Callers hold the evidence references and per-unit aggregates,
  so they emit gaps, using ``summarized_content_gap``, ``heuristic_gap`` and ``named_gaps``.

The workspace manifest is not affected: it still hashes every file, and the catalogue stays a
subset of it.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.config.assurance import ScopeRole
from appsec_review.config.build_outputs import SCOPE, BuildOutputExclusion, BuildOutputPolicy
from appsec_review.config.exclusions import ExclusionRule
from appsec_review.jobs.artifact_kinds import binary_role
from appsec_review.jobs.build_bookkeeping import (
    BookkeepingExclusions, BookkeepingReason, bookkeeping_reason, cargo_profile_directories,
)

SCHEMA = "appsec-review/build-output-dispositions/1"
EXAMPLE_LIMIT = 5
LINKED_KINDS = frozenset({"executable", "shared-library", "static-library"})
_LINKED_SUFFIXES = {".a": "static-library", ".lib": "static-library", ".so": "shared-library",
                    ".dll": "shared-library", ".dylib": "shared-library", ".exe": "executable"}


class Disposition(str, Enum):
    EXCLUDED = "excluded"
    SUPPLY_CHAIN = "supply_chain"
    EVIDENCE = "evidence"
    PER_FILE = "per_file"


class Basis(str, Enum):
    CONFIGURED_EXCLUSION = "configured-exclusion"
    BUILD_SYSTEM_FACT = "build-system-fact"
    INSTALLER_RECORD = "installer-record"
    EXECUTION_CAPTURE = "execution-capture"
    HEURISTIC = "heuristic"


class Confidence(str, Enum):
    FACT = "fact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


FACT_BASES = frozenset({Basis.BUILD_SYSTEM_FACT, Basis.INSTALLER_RECORD, Basis.EXECUTION_CAPTURE})
_BASIS_RANK = {Basis.CONFIGURED_EXCLUSION: 2, Basis.BUILD_SYSTEM_FACT: 1, Basis.INSTALLER_RECORD: 1,
               Basis.EXECUTION_CAPTURE: 1, Basis.HEURISTIC: 0}
_PRUNED = frozenset({Disposition.EXCLUDED, Disposition.SUPPLY_CHAIN, Disposition.EVIDENCE})


@dataclass(frozen=True, slots=True)
class Decision:
    """How the walk hands one file to a cataloguer.

    ``root`` and ``disposition`` name the governing tree (``None`` for ordinary target content);
    ``scope_role`` is set on a kept row from a ``supply_chain`` root; ``bookkeeping`` is the
    reason a file is build bookkeeping, which the cataloguer records through
    ``record_bookkeeping`` once it knows the file is a changed artifact candidate.
    """

    root: str | None = None
    disposition: str | None = None
    scope_role: str | None = None
    kept: bool = False
    bookkeeping: BookkeepingReason | None = None


@dataclass(slots=True)
class _Tree:
    root: str
    disposition: Disposition
    basis: Basis
    confidence: Confidence
    name: str
    reason: str
    evidence_ref: str | None
    pattern: str | None
    scope: str | None
    scope_role: str | None
    keep: set[str]
    keep_linked: bool
    conflict: bool = False
    files: int = 0
    bytes: int = 0
    kept: list[str] = field(default_factory=list)
    kept_omitted: int = 0
    examples: list[str] = field(default_factory=list)

    def document(self) -> dict[str, Any]:
        return {"root": self.root, "disposition": self.disposition.value, "basis": self.basis.value,
                "confidence": self.confidence.value, "name": self.name, "reason": self.reason,
                "evidence_ref": self.evidence_ref, "pattern": self.pattern, "scope": self.scope,
                "scope_role": self.scope_role, "files": self.files, "bytes": self.bytes,
                "kept": list(self.kept), "examples": list(self.examples)}


@dataclass(slots=True)
class _Excluded:
    path: str
    name: str
    pattern: str
    files: int = 0

    def document(self) -> dict[str, Any]:
        return {"path": self.path, "name": self.name, "pattern": self.pattern, "scope": SCOPE,
                "files": self.files}


def _normalize(root: str | PurePosixPath) -> str:
    text = str(root).replace("\\", "/").rstrip("/")
    parts = text.split("/")
    if not text or text.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"build-output root must be a workspace-relative POSIX path below the root: {root!r}")
    return text


def _linked(path: Path) -> bool:
    role, _container = binary_role(path)
    if role is not None:
        return role in LINKED_KINDS
    return _LINKED_SUFFIXES.get(path.suffix.lower()) is not None or ".so." in path.name


class BuildOutputDispositions:
    """One build unit's tree decisions, configured exclusions and bookkeeping tally."""

    def __init__(self, policy: BuildOutputPolicy | None = None, *, family: str = "native",
                 bookkeeping: BookkeepingExclusions | None = None) -> None:
        self.policy = policy if policy is not None else BuildOutputPolicy()
        self.family = family
        self.bookkeeping = bookkeeping if bookkeeping is not None else BookkeepingExclusions()
        self._rules: tuple[tuple[ExclusionRule, BuildOutputExclusion], ...] = self.policy.rules_for(family)
        self._trees: dict[str, _Tree] = {}
        self._excluded: list[_Excluded] = []
        self._layout_sources: list[dict[str, str]] = []
        self._conflicts: list[str] = []
        self._root_overruns = 0
        self._cargo_profiles: frozenset[str] = frozenset()

    # Registration -------------------------------------------------------------------------

    def classify_tree(self, root: str | PurePosixPath, *, disposition: str | Disposition,
                      basis: str | Basis, name: str, reason: str, confidence: str | Confidence,
                      evidence_ref: str | None = None, pattern: str | None = None, scope: str | None = None,
                      scope_role: str | None = None, keep: Iterable[str] = (),
                      keep_linked: bool = False) -> bool:
        """Register one tree decision; returns False when the configured root bound is exhausted.

        A heuristic below ``heuristic_min_confidence`` is recorded but stays ``per_file``.
        ``keep_linked`` additionally yields the root's executables and libraries as kept rows.
        """
        relative = _normalize(root)
        requested = Disposition(disposition)
        basis, confidence = Basis(basis), Confidence(confidence)
        if scope_role is not None:
            scope_role = ScopeRole(scope_role).value
        effective = requested
        if basis is Basis.HEURISTIC and not self.policy.heuristic_accepted(confidence.value):
            effective = Disposition.PER_FILE
        tree = _Tree(relative, effective, basis, confidence, str(name), str(reason), evidence_ref, pattern,
                     scope, scope_role, {_normalize(item) for item in keep}, keep_linked)
        existing = self._trees.get(relative)
        if existing is None:
            if len(self._trees) >= self.policy.discovery.max_layout_roots:
                self._root_overruns += 1
                return False
            self._trees[relative] = tree
            return True
        new_rank, old_rank = _BASIS_RANK[basis], _BASIS_RANK[existing.basis]
        if new_rank > old_rank:
            tree.keep |= existing.keep
            self._trees[relative] = tree
        elif new_rank == old_rank:
            if existing.disposition is effective and not existing.conflict:
                existing.keep |= tree.keep
                existing.keep_linked = existing.keep_linked or keep_linked
            elif basis in FACT_BASES:
                existing.disposition, existing.conflict = Disposition.PER_FILE, True
                if relative not in self._conflicts:
                    self._conflicts.append(relative)
            else:
                existing.disposition = Disposition.PER_FILE
        return True

    def add_layout_source(self, kind: str, path: str, sha256: str) -> None:
        self._layout_sources.append({"kind": str(kind), "path": str(path), "sha256": str(sha256)})

    def record_bookkeeping(self, reason: BookkeepingReason, relative: str) -> None:
        self.bookkeeping.record(reason, relative)

    # Walk ---------------------------------------------------------------------------------

    def walk(self, workspace: Path) -> Iterator[tuple[str, Decision]]:
        """Yield ``(workspace-relative path, Decision)`` for every file a cataloguer should consider.

        Sorted, symlink-free and deterministic. Counts restart on every walk.
        """
        for tree in self._trees.values():
            tree.files = tree.bytes = tree.kept_omitted = 0
            tree.kept, tree.examples = [], []
        self._excluded = []
        self._cargo_profiles = cargo_profile_directories(workspace) if self.family == "rust" else frozenset()
        yield from self._descend(workspace, "", None, None)

    def _rule(self, relative: str, *, directory: bool) -> tuple[ExclusionRule, BuildOutputExclusion] | None:
        for rule, exclusion in self._rules:
            if rule.matches_directory(relative) if directory else rule.matches(relative):
                return rule, exclusion
        return None

    def _exclude(self, relative: str, match: tuple[ExclusionRule, BuildOutputExclusion]) -> _Excluded:
        record = _Excluded(relative, match[1].name, match[0].pattern)
        self._excluded.append(record)
        return record

    def _descend(self, directory: Path, relative: str, tree: _Tree | None,
                 excluded: _Excluded | None) -> Iterator[tuple[str, Decision]]:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            return
        for entry in entries:
            child = f"{relative}/{entry.name}" if relative else entry.name
            try:
                if entry.is_symlink():
                    continue
                is_directory = entry.is_dir(follow_symlinks=False)
                is_file = not is_directory and entry.is_file(follow_symlinks=False)
            except OSError:
                continue
            if is_directory:
                if excluded is None and (match := self._rule(child, directory=True)) is not None:
                    yield from self._descend(Path(entry.path), child, tree, self._exclude(child, match))
                else:
                    governing = tree if excluded is not None else self._trees.get(child, tree)
                    yield from self._descend(Path(entry.path), child, governing, excluded)
                continue
            if not is_file:
                continue
            if excluded is not None:
                excluded.files += 1
                continue
            if (match := self._rule(child, directory=False)) is not None:
                self._exclude(child, match).files = 1
                continue
            if tree is None or tree.disposition is Disposition.PER_FILE:
                yield child, Decision(
                    root=tree.root if tree is not None else None,
                    disposition=tree.disposition.value if tree is not None else None,
                    bookkeeping=bookkeeping_reason(child, cargo=self.family == "rust",
                                                   cargo_profile_directories=self._cargo_profiles))
                continue
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            tree.files += 1
            tree.bytes += size
            if len(tree.examples) < EXAMPLE_LIMIT:
                tree.examples.append(child)
            if tree.disposition is not Disposition.SUPPLY_CHAIN:
                continue
            if child not in tree.keep and not (tree.keep_linked and _linked(Path(entry.path))):
                continue
            if len(tree.kept) >= self.policy.discovery.max_kept_per_root:
                tree.kept_omitted += 1
                continue
            tree.kept.append(child)
            yield child, Decision(root=tree.root, disposition=tree.disposition.value,
                                  scope_role=tree.scope_role, kept=True)

    # Results ------------------------------------------------------------------------------

    @property
    def conflicts(self) -> tuple[str, ...]:
        return tuple(self._conflicts)

    def roots(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._trees[root].document() for root in sorted(self._trees))

    def named_gaps(self) -> list[str]:
        """Conflicts and bound overruns the walk observed; callers add them to the unit's gaps."""
        gaps = [conflict_gap(root) for root in self._conflicts]
        gaps.extend(f"build-output-kept-bound-exceeded: {tree.root} kept {len(tree.kept)} linked files; "
                    f"{tree.kept_omitted} more stay counted only"
                    for root, tree in sorted(self._trees.items()) if tree.kept_omitted)
        if self._root_overruns:
            gaps.append(f"build-output-root-bound-exceeded: {self._root_overruns} roots beyond "
                        f"max_layout_roots stay per-file target content")
        return gaps

    def summary(self) -> dict[str, int]:
        """Telemetry counts; deliberately free of the keys aggregate_run_metrics sums."""
        trees = list(self._trees.values())
        return {
            "supply_chain_trees": sum(tree.disposition is Disposition.SUPPLY_CHAIN for tree in trees),
            "excluded_trees": len(self._excluded) + sum(tree.disposition is Disposition.EXCLUDED for tree in trees),
            "excluded_files": sum(item.files for item in self._excluded) + sum(
                tree.files for tree in trees if tree.disposition in _PRUNED) - sum(len(tree.kept) for tree in trees),
            "kept_rows": sum(len(tree.kept) for tree in trees),
            "heuristic_dispositions": sum(tree.basis is Basis.HEURISTIC for tree in trees),
            "conflicts": len(self._conflicts),
            "layout_sources_read": len(self._layout_sources),
        }

    def document(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "policy_identity": self.policy.identity,
                "layout_sources": [dict(item) for item in self._layout_sources],
                "roots": [dict(item) for item in self.roots()],
                "configured_exclusions": [item.document() for item in self._excluded],
                "bookkeeping": self.bookkeeping.document()}


def summarized_content_gap(count: int, unit_noun: str, files: int, bytes: int, evidence_ref: str,
                           lane: str) -> str:
    """The aggregated gap shared with the installer-record design, one per evidence source."""
    return (f"dependency-content-summarized: {count} {unit_noun} ({files} files, {bytes} bytes) recorded by "
            f"{evidence_ref} routed to {lane} review; per-file target review not performed")


def heuristic_gap(root: str, disposition: str, confidence: str) -> str:
    return f"build-output-heuristic: {root} classified {disposition} by directory name ({confidence})"


def conflict_gap(root: str) -> str:
    return f"build-output-classification-conflict: {root}"
