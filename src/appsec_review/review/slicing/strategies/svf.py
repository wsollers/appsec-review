"""``svf_points_to``: lines that touch a memory object an anchor line's pointers may point to.

Precision: ``Precision.COMPILER``. The facts are SVF's Andersen points-to sets over accepted bitcode, published
by ``jobs/job_svf_alias_analysis/job.py`` (``appsec-review/svf-alias-record/1`` and ``svf-memory-object/1``) and
joined to a source line exactly as ``review/memory_context.py`` does.

Input (``SliceSources.svf_records(path, line)``) is a sequence of accepted ``analysis`` shard entity rows in
the ``indexing.store.ShardSet.entities`` shape: the ``points_to_set`` and ``indirect_call_targets`` rows
located (non-ambiguously) at ``path:line``, plus the ``memory_object`` rows they ``REFERENCES`` (and any
``memory_object`` allocated on that line). Only these keys are read::

    {"identity": "asr:points_to_set:...", "kind": "points_to_set",
     "location": {"path": "native/guard.c", "start_line": 17, ...},
     "payload": {"role": "store", "points_to": ["obj:heap:/target/source/guard.c:15:20:#0@143"],
                 "objects": {"obj:heap:...": {"kind": "heap", ...}},
                 "complete": true, "incomplete_reasons": [], "open_world_reasons": []}}

    {"identity": "asr:memory_object:...", "kind": "memory_object",
     "location": {"path": "native/guard.c", "start_line": 15, ...} | None,     # the allocation site
     "payload": {"object_key": "obj:heap:/target/source/guard.c:15:20:#0@143",
                 "accessors": [{"site": "asr:points_to_set:...", "path": "native/guard.c", "line": 20,
                                "class": "free", ...}, ...],
                 "complete": true, "truncated": false, "open_world_reasons": []}}

    {"identity": "asr:indirect_call_targets:...", "kind": "indirect_call_targets",
     "payload": {"targets": [...], "complete": true, "open_world_reasons": []}}

``None`` means SVF records are unavailable for the file (the opt-in job did not run, the file is in no
analyzed module, or it is not C/C++); an empty sequence means analyzed and holding no pointer operation.

For every anchor line, each object pointed to by a ``points_to_set`` row of that line (and each object
allocated on it) contributes its allocation site (the ``memory_object`` row ``location``) and its accessor
sites (``payload.accessors[].path``/``line``) that fall inside a request function span, as
``Reason.ALIAS``. Andersen sets are already closed over copies, fields and calls, so one inversion is the
whole fan-in and no fixpoint is needed. A column-0 location (stack and global objects) names a whole line;
its line is still exact, so ``ambiguous`` is not a reason to drop it.

Limitations: only objects with a ``memory_object`` record (heap, stack, global) have located sites; the raw
driver locations in ``points_to_set.payload.objects`` use tool paths, not accepted paths, and are not read.
Indirect-call targets name functions, not lines, and contribute nothing. Accessor lists are bounded by the
producer. Open-world, truncated and incomplete records, objects without a record, and files without records
are named gaps: SVF may confirm an alias but never rules one out.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from appsec_review.review.slicing.contract import (
    GAP_NOT_APPLICABLE, GAP_TRUNCATED, LineKey, Precision, Reason, SliceContribution, SliceLine, SliceRequest,
    StrategyState,
)

NAME = "svf_points_to"
MAX_RECORDS_PER_LINE = 256
GAP_PARTIAL = "slice_strategy_partial"
POINTS_TO, MEMORY_OBJECT = "points_to_set", "memory_object"
_OBJECT_KINDS = frozenset({"heap", "stack", "global"})   # kinds the producer publishes a memory_object for


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _line(value: Any) -> int | None:
    return value if type(value) is int and value >= 1 else None


class SvfPointsTo:
    """Compiler-precision alias lines from SVF points-to records (see the module docstring for the input)."""

    name = NAME
    precision = Precision.COMPILER

    def expand(self, request: SliceRequest) -> SliceContribution:
        anchors = tuple(key for key in request.anchor_lines() if request.span_for(key) is not None)
        if not anchors:
            return self._none(f"{GAP_NOT_APPLICABLE}: {NAME}: no anchor line lies inside a function span")
        anchor_set = frozenset(anchors)
        spans = sorted(request.functions, key=lambda item: (item.path, item.first, item.last, item.file_sha256))

        def in_span(path: Any, line: Any) -> LineKey | None:
            line = _line(line)
            if not isinstance(path, str) or line is None:
                return None
            span = next((item for item in spans if item.path == path and item.first <= line <= item.last), None)
            return None if span is None else LineKey(path, span.file_sha256, line)

        found: dict[LineKey, set[Reason]] = defaultdict(set)
        missing: set[str] = set()
        incomplete: dict[str, set[str]] = {}
        open_world: set[str] = set()
        unresolved: set[str] = set()
        cut = available = 0
        for anchor in anchors:
            rows = request.sources.svf_records(anchor.path, anchor.line)
            if rows is None:
                missing.add(anchor.path)
                continue
            available += 1
            rows = sorted((row for row in rows if isinstance(row, Mapping)),
                          key=lambda row: (str(row.get("kind")), str(row.get("identity"))))
            if len(rows) > MAX_RECORDS_PER_LINE:
                cut += 1
                rows = rows[:MAX_RECORDS_PER_LINE]
            sites = [row for row in rows if row.get("kind") == POINTS_TO]
            referenced: dict[str, str | None] = {}
            for site in sites:
                payload = _mapping(site.get("payload"))
                details = _mapping(payload.get("objects"))
                for key in payload.get("points_to") or ():
                    referenced[str(key)] = _mapping(details.get(key)).get("kind")
            objects: dict[str, Mapping[str, Any]] = {}
            for row in rows:
                if row.get("kind") != MEMORY_OBJECT:
                    continue
                key = str(_mapping(row.get("payload")).get("object_key"))
                location = _mapping(row.get("location"))
                if key in referenced or (location.get("path") == anchor.path and location.get("start_line") == anchor.line):
                    objects[key] = row
            unresolved.update(key for key, kind in referenced.items()
                              if key not in objects and (kind is None or kind in _OBJECT_KINDS))
            for row in [*(row for row in rows if row.get("kind") != MEMORY_OBJECT), *objects.values()]:
                payload = _mapping(row.get("payload"))
                open_world.update(str(reason) for reason in payload.get("open_world_reasons") or ())
                if payload.get("complete") is not True:
                    reasons = [str(item) for item in payload.get("incomplete_reasons") or ()]
                    if payload.get("truncated"):
                        reasons.append("truncated")
                    incomplete[str(row.get("identity"))] = set(reasons or ["incomplete"])
            for row in objects.values():
                location = _mapping(row.get("location"))
                sites_of = [(location.get("path"), location.get("start_line"))]
                sites_of += [(item.get("path"), item.get("line"))
                             for item in _mapping(row.get("payload")).get("accessors") or () if isinstance(item, Mapping)]
                for path, line in sites_of:
                    key = in_span(path, line)
                    if key is not None and key not in anchor_set:
                        found[key].add(Reason.ALIAS)
        if not available:
            return self._none(f"{GAP_NOT_APPLICABLE}: {NAME}: no SVF records for {', '.join(sorted(missing))} "
                              "(job_svf_alias_analysis is opt-in or did not cover the file)")
        gaps: list[str] = []
        if missing:
            gaps.append(f"{GAP_NOT_APPLICABLE}: {NAME}: no SVF records for {', '.join(sorted(missing))} "
                        "(job_svf_alias_analysis is opt-in or did not cover the file)")
        if cut:
            gaps.append(f"{GAP_TRUNCATED}: {NAME}: {cut} anchor line(s) held more than "
                        f"MAX_RECORDS_PER_LINE={MAX_RECORDS_PER_LINE} SVF records; the rest were not read")
        if open_world:
            gaps.append(f"{GAP_PARTIAL}: {NAME}: SVF records at the anchor lines come from open-world modules "
                        f"({', '.join(sorted(open_world))}); they may confirm but never rule out an alias")
        if incomplete:
            reasons = sorted({reason for values in incomplete.values() for reason in values})
            gaps.append(f"{GAP_PARTIAL}: {NAME}: {len(incomplete)} SVF record(s) at the anchor lines are incomplete "
                        f"({', '.join(reasons)}); aliases may be missing")
        if unresolved:
            gaps.append(f"{GAP_PARTIAL}: {NAME}: {len(unresolved)} pointed-to object(s) have no memory_object record; "
                        "their other access sites are unknown")
        lines = tuple(SliceLine(key, frozenset(reasons), NAME, Precision.COMPILER)
                      for key, reasons in sorted(found.items()))
        state = StrategyState.PARTIAL if gaps else StrategyState.APPLIED
        return SliceContribution(NAME, Precision.COMPILER, state, lines, tuple(gaps))

    @staticmethod
    def _none(*gaps: str) -> SliceContribution:
        return SliceContribution(NAME, Precision.COMPILER, StrategyState.NOT_APPLICABLE, (), tuple(gaps))


__all__ = ["GAP_PARTIAL", "MAX_RECORDS_PER_LINE", "NAME", "SvfPointsTo"]
