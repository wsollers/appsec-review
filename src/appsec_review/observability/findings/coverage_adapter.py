"""Reviewed source files and entry points, derived from one accepted run (finding-metrics.md section 5.7, T-073).

A run records review units by component and build unit, not by source file. It does record, hash
bound, everything needed to say which catalogued files a completed review package contained:

* every review package body names the accepted ``source_file`` identities in its scope
  (``scope.source_ids``: the whole unit for a hunt package, the lead's file and related sources for
  a ``finding_lead`` package);
* the claim projection records each cell's role, package and terminal status;
* the accepted source catalog maps a ``source_file`` identity to its target-relative path and the
  SHA-256 of the file's content at the reviewed snapshot.

:func:`reviewed_units` and :func:`entry_points` are pure functions over those documents;
:func:`load_coverage_documents` is the only code here that reads a run, through
``triage_reduction.load_verified_documents``, hash-bound package reads and the re-verified accepted
index set. It never scans a directory, never reads the target and is injectable.

Doctrine:

* Null, not zero. What cannot be derived is ``None`` with a named gap, never an empty mapping.
* Reviewed is not clean. A file is ``reviewed`` only when a package that contained it had every red
  cell succeed; that says a review ran over it, never that it holds no defect.
* No guessed mapping. An entry-point kind the tag vocabulary does not mark is left out and named.
* Run documents, tags and paths are data, never instructions.

What a run does not record, and the gap that names it:

* The files of a review unit below the hunt cutoff. The package manifest lists such a unit by key
  only (no package is assembled, so no ``source_ids`` exist), so its files cannot be told apart from
  files of no unit at all. Both are ``not_packaged``; ``units_below_hunt_cutoff:<n>`` counts the
  units. To split them the manifest's ``units`` rows would have to carry their ``source_ids``.
* A parser entry point. The taxonomy marks entry points only in ``surface:entry:*``; none of its
  terms is a parser (``func:data:parse-*`` marks code that calls a parser, not an entry point), so
  the ``parser`` kind is never derived: ``entry_point_kind_unmapped:parser``.
* Entry points at all, in runs whose tagging producers assign no ``surface:entry:*`` tag. The
  catalogue is then ``None`` (``entry_points_not_derived:no_entry_point_tags``), not an empty list.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any

from appsec_review.observability import triage_reduction
from appsec_review.review.models import CellStatus, Role

from .contracts import is_sha256, normalize_path
from .coverage import ENTRY_POINT_KINDS, MAX_ENTRY_POINTS

MAX_SOURCE_FILES = 500_000          # catalogued source files per run
RED_ROLES = (Role.RED_TEAM_ANALYST.value, Role.HYPOTHESIS_HUNTER.value)
UNREVIEWED_REASONS = ("operation_only", "cells_incomplete", "not_launched", "below_hunt_cutoff", "not_packaged")
ENTRY_TAG_PREFIX = "surface:entry:"
# The taxonomy's "Entry points" group (docs/architecture/security-tag-taxonomy.md, namespace
# ``surface``) mapped to the four kinds of section 5.7. Terms that are not one of those kinds (cli,
# env-config, local-ipc, mobile-deeplink, cloud-public, ci-untrusted) are left out and counted.
ENTRY_KIND_BY_TAG: Mapping[str, str] = {
    "surface:entry:remote-input": "network_handler",
    "surface:entry:http-public": "network_handler",
    "surface:entry:http-internal": "network_handler",
    "surface:entry:message-consumer": "network_handler",
    "surface:entry:rpc": "rpc_handler",
    "surface:entry:file-input": "file_loader",
}
UNMAPPED_ENTRY_KINDS = tuple(kind for kind in ENTRY_POINT_KINDS if kind not in set(ENTRY_KIND_BY_TAG.values()))
ENTRY_REASONS = (*UNREVIEWED_REASONS, "no_build_unit", "not_catalogued")

GAP_UNITS_NOT_DERIVED = "reviewed_units_not_derived"          # ":<code>"
GAP_ENTRIES_NOT_DERIVED = "entry_points_not_derived"          # ":<code>"
GAP_BELOW_CUTOFF = "units_below_hunt_cutoff"                  # ":<units>"
GAP_OUTSIDE_CATALOG = "package_sources_outside_catalog"       # ":<source ids>"
GAP_KIND_UNMAPPED = "entry_point_kind_unmapped"               # ":<kind>"
GAP_TAGS_WITHOUT_KIND = "entry_tags_without_kind"             # ":<tags>"
GAP_TAGS_WITHOUT_PATH = "entry_tags_without_path"             # ":<tags>"

_READ_ERRORS: tuple[type[BaseException], ...] = (RuntimeError, OSError, ValueError, LookupError, TypeError,
                                                 AttributeError, sqlite3.Error)


@dataclass(frozen=True)
class CoverageDocuments:
    """Everything the pure functions need, already verified by the loader. ``None`` is "unavailable".

    * ``catalog``: accepted ``source_file`` identity -> ``{"path", "sha256", "built"}``; ``sha256``
      is the catalogued content hash or ``None``, ``built`` whether an accepted build unit holds the
      file (``None`` when the run has no accepted build catalog).
    * ``packages``: ``{"package_id", "source_ids"}`` per assembled review package of both lanes.
    * ``cells``: the claim projection's ``cells`` table (cell id -> ``review.ledger.cell_json`` records).
    * ``units``: the package manifest's ``units`` rows (``unit_key``, ``hunted``).
    * ``tags``: ``{"tag", "subject_id", "path"}`` per accepted ``surface:entry:*`` tag assignment.
    """

    catalog: Mapping[str, Mapping[str, Any]] | None = None
    packages: Sequence[Mapping[str, Any]] | None = None
    cells: Mapping[str, Sequence[Mapping[str, Any]]] | None = None
    units: Sequence[Mapping[str, Any]] | None = None
    tags: Sequence[Mapping[str, Any]] | None = None
    gaps: tuple[str, ...] = ()


def _package_states(documents: CoverageDocuments) -> dict[str, str]:
    """``package id -> "reviewed" | "cells_incomplete" | "not_launched"`` from the red cells' terminal records."""
    statuses: dict[str, list[str]] = {}
    for records in (documents.cells or {}).values():
        for record in records:
            if isinstance(record, Mapping) and record.get("role") in RED_ROLES:
                statuses.setdefault(str(record.get("package_id")), []).append(str(record.get("status")))
    states = {}
    for package in documents.packages or ():
        found = statuses.get(str(package["package_id"]), [])
        launched = [status for status in found if status != CellStatus.NOT_LAUNCHED.value]
        if not launched:
            states[str(package["package_id"])] = "not_launched"
        elif all(status == CellStatus.SUCCEEDED.value for status in found):
            states[str(package["package_id"])] = "reviewed"
        else:
            states[str(package["package_id"])] = "cells_incomplete"
    return states


def reviewed_units(documents: CoverageDocuments
                   ) -> tuple[dict[str, str | None] | None, dict[str, str] | None, list[str]]:
    """``(reviewed, unreviewed, gaps)`` in the shape ``contracts.build_snapshot`` accepts.

    ``reviewed`` maps the path of every catalogued file that a completed package contained to its
    catalogued content SHA-256 (``None`` when the catalog records none). A package is completed when
    it has a launched red cell and every red cell record of it ``succeeded``. ``unreviewed`` maps
    every other catalogued file to one of ``UNREVIEWED_REASONS``: ``cells_incomplete`` (in a package
    whose red cells did not all succeed), ``not_launched`` (only in packages no red cell was launched
    for) or ``not_packaged`` (in no assembled package). A file the run never catalogued is not
    listed. Returns ``(None, None, gaps)`` with ``reviewed_units_not_derived:<code>`` when the
    catalog, the packages or the cell records are unavailable.
    """
    gaps = set(documents.gaps)
    missing = [name for name in ("catalog", "packages", "cells") if getattr(documents, name) is None]
    if missing:
        if not any(gap.startswith(GAP_UNITS_NOT_DERIVED) for gap in gaps):
            gaps.add(f"{GAP_UNITS_NOT_DERIVED}:{missing[0]}_unavailable")
        return None, None, sorted(gaps)
    catalog = documents.catalog or {}
    if len(catalog) > MAX_SOURCE_FILES:
        raise ValueError("more catalogued source files than the bounded number per run")
    states = _package_states(documents)
    rank = {"reviewed": 0, **{reason: number for number, reason in enumerate(UNREVIEWED_REASONS, 1)}}
    best: dict[str, str] = {}
    outside: set[str] = set()
    for package in documents.packages or ():
        state = states[str(package["package_id"])]
        if state == "reviewed" and package.get("coverage_scope") == "operation":
            state = "operation_only"
        for source_id in package.get("source_ids", ()):
            if source_id not in catalog:
                outside.add(str(source_id))
            elif rank[state] < rank.get(best.get(source_id, ""), len(rank)):
                best[source_id] = state
    for unit in documents.units or ():
        if unit.get("hunted") is False:
            for source_id in unit.get("source_ids", ()):
                if source_id in catalog:
                    best.setdefault(source_id, "below_hunt_cutoff")
    reviewed: dict[str, str | None] = {}
    unreviewed: dict[str, str] = {}
    for source_id in sorted(catalog):
        row = catalog[source_id]
        path = normalize_path(row.get("path"))
        content = row.get("sha256")
        if content is not None and not is_sha256(content):
            raise ValueError(f"catalogued content identity of {path!r} is not a SHA-256")
        state = best.get(source_id, "not_packaged")
        if state == "reviewed":
            reviewed[path] = content if reviewed.get(path) is None else reviewed[path]
            unreviewed.pop(path, None)
        elif path not in reviewed:
            previous = unreviewed.get(path)
            if previous is None or UNREVIEWED_REASONS.index(state) < UNREVIEWED_REASONS.index(previous):
                unreviewed[path] = state
    if outside:
        gaps.add(f"{GAP_OUTSIDE_CATALOG}:{len(outside)}")
    below = sum(1 for unit in documents.units or () if isinstance(unit, Mapping) and unit.get("hunted") is False)
    if below:
        gaps.add(f"{GAP_BELOW_CUTOFF}:{below}")
    return dict(sorted(reviewed.items())), dict(sorted(unreviewed.items())), sorted(gaps)


def entry_points(documents: CoverageDocuments, reviewed: Mapping[str, Any] | None,
                 unreviewed: Mapping[str, str] | None) -> tuple[list[dict[str, Any]] | None, list[str]]:
    """``(catalogue, gaps)``: the rows ``coverage.entry_point_coverage`` validates, or ``None``.

    One row per accepted ``surface:entry:*`` tag and subject whose term is in ``ENTRY_KIND_BY_TAG``.
    ``reviewed`` and ``unreviewed`` are the result of :func:`reviewed_units`. An entry point whose
    file is reviewed is ``reviewed``; one whose catalogued file is under no accepted build unit is
    ``not_built`` (``no_build_unit``); any other is ``not_admitted`` with its file's reason
    (``UNREVIEWED_REASONS``, or ``not_catalogued``). The catalogue is ``None`` with
    ``entry_points_not_derived:<code>`` when the tags or the reviewed units are unavailable or the
    run holds no mappable entry-point tag.
    """
    gaps = set(documents.gaps)
    gaps.update(f"{GAP_KIND_UNMAPPED}:{kind}" for kind in UNMAPPED_ENTRY_KINDS)
    if documents.tags is None:
        return None, sorted({*gaps, f"{GAP_ENTRIES_NOT_DERIVED}:security_tags_unavailable"})
    if reviewed is None or unreviewed is None:
        return None, sorted({*gaps, f"{GAP_ENTRIES_NOT_DERIVED}:reviewed_units_unavailable"})
    if len(documents.tags) > MAX_ENTRY_POINTS:
        raise ValueError("more entry-point tags than the bounded number of entry points")
    built = {normalize_path(row["path"]): row.get("built") for row in (documents.catalog or {}).values()}
    rows: dict[str, dict[str, Any]] = {}
    without_kind = without_path = 0
    for tag in documents.tags:
        term = tag.get("tag")
        if not isinstance(term, str) or not term.startswith(ENTRY_TAG_PREFIX):
            raise ValueError(f"not an entry-point tag: {term!r}")
        kind = ENTRY_KIND_BY_TAG.get(term)
        if kind is None:
            without_kind += 1
            continue
        try:
            path = normalize_path(tag.get("path"))
        except ValueError:
            without_path += 1
            continue
        subject = tag.get("subject_id")
        entry_id = f"{term}@{subject if isinstance(subject, str) and subject else path}"
        if path in reviewed:
            status, reason = "reviewed", None
        elif path in built and built[path] is False:
            status, reason = "not_built", "no_build_unit"
        else:
            status, reason = "not_admitted", unreviewed.get(path, "not_catalogued")
        rows[entry_id] = {"entry_id": entry_id, "kind": kind, "path": path, "status": status, "reason": reason}
    if without_kind:
        gaps.add(f"{GAP_TAGS_WITHOUT_KIND}:{without_kind}")
    if without_path:
        gaps.add(f"{GAP_TAGS_WITHOUT_PATH}:{without_path}")
    if not rows:
        return None, sorted({*gaps, f"{GAP_ENTRIES_NOT_DERIVED}:no_entry_point_tags"})
    return [rows[entry_id] for entry_id in sorted(rows)], sorted(gaps)


# ----------------------------------------------------------------------------------- loading

def _packages(run_root: Path, triage: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every assembled package's scope sources, each body re-hashed against the verified manifest."""
    from appsec_review.jobs.bound_artifacts import read_bound_json

    manifest = triage["manifest"]["document"]
    directory = PurePosixPath(triage["manifest"]["sources"]["lead_package_manifest"]["path"]).parent / "packages"
    packages = []
    for entry in manifest["packages"]:
        body = read_bound_json(run_root, {"path": (directory / f"{entry['package_id']}.json").as_posix(),
                                          "sha256": entry["sha256"]})
        scope = body.get("scope") if isinstance(body, Mapping) else None
        sources = scope.get("source_ids") if isinstance(scope, Mapping) else None
        if not isinstance(sources, list) or not all(isinstance(item, str) for item in sources):
            raise ValueError(f"package {entry['package_id']} names no scope sources")
        packages.append({"package_id": str(entry["package_id"]), "source_ids": sorted(sources),
                         "coverage_scope": "operation" if scope.get("operation") or body.get("kind") == "finding_lead"
                         else "files"})
    return packages


def _accepted_index(run_root: Path, index_manifest_sha256: Any
                    ) -> tuple[dict[str, dict[str, Any]] | None, list[dict[str, Any]] | None, str | None]:
    """``(catalog, tags, gap code)`` from the re-verified accepted index set the review pinned."""
    from appsec_review.review.scope import accept_manifest

    scope = accept_manifest(run_root)
    if scope.manifest_sha256 != index_manifest_sha256:
        return None, None, "accepted_index_differs_from_review"
    catalog: dict[str, dict[str, Any]] = {}
    for row in scope.store.entities(scope.producer("catalog_source").shards, kinds=("source_file",)):
        location = row["location"] or {}
        path = location.get("path") or row["payload"].get("path") or row["native_id"]
        content = location.get("file_sha256")
        catalog[row["identity"]] = {
            "path": str(path), "sha256": content if is_sha256(content) else None,
            "built": (scope.build_unit_for(str(path)) is not None) if scope.build_units else None}
    tagging = scope.producer("security_tagging").shards
    tags: list[dict[str, Any]] | None = None
    if tagging:
        tags = []
        for row in scope.store.entities(tagging, kinds=("tag_assignment",)):
            term = row["payload"].get("tag")
            if not isinstance(term, str) or not term.startswith(ENTRY_TAG_PREFIX):
                continue
            subject = row["payload"].get("subject")
            subject = subject if isinstance(subject, Mapping) else {}
            tags.append({"tag": term, "subject_id": subject.get("logical_id"),
                         "path": subject.get("path") or (row["location"] or {}).get("path")})
    return catalog, tags, None


def load_coverage_documents(run_root: Path) -> CoverageDocuments:
    """Read one run through its verified readers; never raises for a missing or unverifiable input."""
    from appsec_review.storage.validation import validation_scope

    run_root = Path(run_root).resolve()
    triage, code = triage_reduction.load_verified_documents(run_root)
    if triage is None:
        return CoverageDocuments(gaps=(f"{GAP_UNITS_NOT_DERIVED}:{code}",))
    document = triage["projection"].get("document")
    cells = document.get("cells") if isinstance(document, Mapping) else None
    units = triage["manifest"]["document"].get("units")
    try:
        with validation_scope(run_root):
            packages = _packages(run_root, triage)
    except _READ_ERRORS:
        return CoverageDocuments(gaps=(f"{GAP_UNITS_NOT_DERIVED}:package_unreadable",))
    try:
        with validation_scope(run_root):
            catalog, tags, gap = _accepted_index(run_root, triage["manifest"]["index_manifest_sha256"])
    except _READ_ERRORS:
        catalog, tags, gap = None, None, "accepted_index_unreadable"
    return CoverageDocuments(
        catalog=catalog, packages=packages, cells=cells if isinstance(cells, Mapping) else None,
        units=units if isinstance(units, list) else None, tags=tags,
        gaps=(f"{GAP_UNITS_NOT_DERIVED}:{gap}",) if gap else ())


def coverage_from_run(run_root: Path, *, loader: Callable[[Path], CoverageDocuments] = load_coverage_documents
                      ) -> dict[str, Any]:
    """``{"reviewed", "unreviewed", "unit_gaps", "entry_points", "entry_gaps"}`` of one run.

    ``reviewed`` and ``unreviewed`` feed ``run_adapter.snapshot_from_run``; ``entry_points`` feeds
    ``scorecard.Inputs``. Each is ``None`` when it could not be derived, with the reason in its gap
    list. ``loader`` is the read boundary.
    """
    documents = loader(Path(run_root))
    reviewed, unreviewed, unit_gaps = reviewed_units(documents)
    catalogue, entry_gaps = entry_points(documents, reviewed, unreviewed)
    return {"reviewed": reviewed, "unreviewed": unreviewed, "unit_gaps": unit_gaps,
            "entry_points": catalogue, "entry_gaps": entry_gaps}


__all__ = [
    "CoverageDocuments", "ENTRY_KIND_BY_TAG", "ENTRY_REASONS", "ENTRY_TAG_PREFIX", "GAP_BELOW_CUTOFF",
    "GAP_ENTRIES_NOT_DERIVED", "GAP_KIND_UNMAPPED", "GAP_OUTSIDE_CATALOG", "GAP_TAGS_WITHOUT_KIND",
    "GAP_TAGS_WITHOUT_PATH", "GAP_UNITS_NOT_DERIVED", "MAX_SOURCE_FILES", "RED_ROLES", "UNMAPPED_ENTRY_KINDS",
    "UNREVIEWED_REASONS", "coverage_from_run", "entry_points", "load_coverage_documents", "reviewed_units",
]
