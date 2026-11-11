"""Binding crash buckets to the reviewed revision (finding-metrics.md section 7.4, T-072).

A crash is from some shipped build, rarely the revision under review. A bucket binds at the first
tier that holds, strongest first:

* ``build_matched``: one of the bucket's module identifiers is an identifier of the build under review;
* ``revision_matched``: the bucket's changelist or version is the reviewed revision;
* ``symbol_matched``: a frame names a function or a file that exists at the reviewed revision. This
  is the common and the weakest tier, and it is always reported as such;
* ``unbound``: counted and otherwise unused.

Everything compared here is untrusted crash data against caller-supplied sets. Comparison is plain
equality; nothing is evaluated, and the output carries only the closed tier and reason vocabularies
and frame indices. A tier that could not be evaluated is a named reason, never a silent ``unbound``.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping
import re
from typing import Any

from ..contracts import BindingTier, counts
from .records import check_evidence, normalize_report

REASONS = ("changelist_matched", "code_id_matched", "debug_id_matched", "file_matched", "function_matched",
           "no_match", "symbols_unavailable", "version_matched")
_PUNCTUATION = re.compile(r"[^0-9a-z]")


def identifier_key(value: Any) -> str | None:
    """A module identifier for comparison: lower case with everything but letters and digits removed."""
    if not isinstance(value, str):
        return None
    return _PUNCTUATION.sub("", value.lower()) or None


def _strings(value: Any, name: str, *, optional: bool) -> frozenset[str] | None:
    if value is None and optional:
        return None
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Collection) or any(
            not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a collection of strings")
    return frozenset(value)


def _bind(report: Mapping[str, Any], debug_ids: frozenset[str], revision: str | None,
          known_functions: frozenset[str] | None, known_paths: frozenset[str] | None) -> dict[str, Any]:
    reasons: set[str] = set()
    for module in report["build"]["modules"]:
        for field in ("debug_id", "code_id"):
            if identifier_key(module[field]) in debug_ids:
                reasons.add(f"{field}_matched")
    if reasons:
        return {"tier": BindingTier.BUILD_MATCHED.value, "matched_frames": [], "reasons": sorted(reasons)}
    if revision is not None:
        reasons = {f"{field}_matched" for field in ("changelist", "version") if report["build"][field] == revision}
        if reasons:
            return {"tier": BindingTier.REVISION_MATCHED.value, "matched_frames": [], "reasons": sorted(reasons)}
    if known_functions is None and known_paths is None:
        return {"tier": BindingTier.UNBOUND.value, "matched_frames": [], "reasons": ["symbols_unavailable"]}
    matched = []
    for index, frame in enumerate(report["frames"]):
        by_function = known_functions is not None and frame["function"] is not None \
            and frame["function"] in known_functions
        by_file = known_paths is not None and frame["file"] is not None and frame["file"] in known_paths
        if by_function or by_file:
            matched.append(index)
            reasons |= {name for name, hit in (("function_matched", by_function), ("file_matched", by_file)) if hit}
    if matched:
        return {"tier": BindingTier.SYMBOL_MATCHED.value, "matched_frames": matched, "reasons": sorted(reasons)}
    return {"tier": BindingTier.UNBOUND.value, "matched_frames": [], "reasons": ["no_match"]}


def _arguments(debug_ids: Any, revision: Any, known_functions: Any, known_paths: Any) -> tuple[Any, ...]:
    if revision is not None and (not isinstance(revision, str) or not revision):
        raise ValueError("revision must be a non-empty string or null")
    keys = frozenset(key for key in (identifier_key(item) for item in _strings(debug_ids, "debug_ids", optional=False)
                                     or ()) if key)
    return (keys, revision, _strings(known_functions, "known_functions", optional=True),
            _strings(known_paths, "known_paths", optional=True))


def bind(report: Mapping[str, Any], *, debug_ids: Collection[str] = frozenset(), revision: str | None = None,
         known_functions: Collection[str] | None = None,
         known_paths: Collection[str] | None = None) -> dict[str, Any]:
    """``{"tier", "matched_frames", "reasons"}`` for one normalized crash report.

    ``debug_ids`` are the module identifiers of the build under review (PDB GUID and age, ELF
    build-ID, Mach-O UUID); a report module matches by ``debug_id`` or ``code_id``, compared without
    case or punctuation. ``revision`` matches the report's ``build.changelist`` or ``build.version``
    exactly. ``known_functions`` (qualified function names at the reviewed revision) and
    ``known_paths`` (target-relative paths) decide ``symbol_matched``; ``matched_frames`` lists the
    indices of the frames that matched and is empty at the two stronger tiers, where the whole stack
    is from the reviewed build. Both being ``None`` means the symbol tier cannot be evaluated
    (reason ``symbols_unavailable``), which differs from an empty set (reason ``no_match``).
    """
    return _bind(normalize_report(report), *_arguments(debug_ids, revision, known_functions, known_paths))


def bind_all(evidence: Mapping[str, Any], *, debug_ids: Collection[str] = frozenset(), revision: str | None = None,
             known_functions: Collection[str] | None = None,
             known_paths: Collection[str] | None = None) -> dict[str, Any]:
    """Bind every bucket of a ``crash-evidence/1`` document.

    Returns ``{"bindings": [{"bucket_id", "adapter", "tier", "matched_frames", "reasons"}],
    "counts": {tier: n}}`` with the bindings in evidence order and the counts zero-filled over
    ``BindingTier`` (plus the house ``"null"`` row, always zero here).
    """
    arguments = _arguments(debug_ids, revision, known_functions, known_paths)
    bindings = [{"bucket_id": report["bucket_id"], "adapter": report["adapter"], **_bind(report, *arguments)}
                for report in check_evidence(evidence)["reports"]]
    return {"bindings": bindings,
            "counts": counts((item["tier"] for item in bindings), tuple(tier.value for tier in BindingTier))}


def check_bindings(evidence: Mapping[str, Any], bindings: Any) -> dict[tuple[str, str], dict[str, Any]]:
    """``(adapter, bucket_id) -> binding`` for a ``bind_all`` result that covers exactly the evidence's
    buckets; a missing, repeated, unknown or malformed binding is a ``ValueError``, never a subset."""
    rows = bindings.get("bindings") if isinstance(bindings, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("crash bindings must be a bind_all result")
    tiers = tuple(tier.value for tier in BindingTier)
    frames = {(report["adapter"], report["bucket_id"]): len(report["frames"]) for report in evidence["reports"]}
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row.get("adapter"), row.get("bucket_id")) if isinstance(row, Mapping) else None
        if (key not in frames or key in index or row.get("tier") not in tiers
                or not isinstance(row.get("matched_frames"), list)
                or any(isinstance(item, bool) or not isinstance(item, int) or not 0 <= item < frames[key]
                       for item in row["matched_frames"])):
            raise ValueError("crash bindings do not match the crash evidence")
        index[key] = dict(row)
    if len(index) != len(frames):
        raise ValueError("crash bindings do not cover every crash bucket")
    return index


__all__ = ["REASONS", "bind", "bind_all", "check_bindings", "identifier_key"]
