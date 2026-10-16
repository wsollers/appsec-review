"""SVF memory context for C/C++ finding-lead packages (docs/architecture/svf-alias-producer.md, section 7).

Joins a lead to the accepted ``job_svf_alias_analysis`` records at its source line, whatever scanner
reported it: the ``points_to_set`` records of the pointer sites on that line, the
``indirect_call_targets`` records of its indirect calls, and the ``memory_object`` records those sites
reference (allocation site, allocator and bounded accessor fan-in). The package embeds identities
only; each one is cited and re-resolved like any other context entry. Every reason the context is
missing, partial or bounded is a named ``svf_points_to`` gap, never an empty clean result.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from appsec_review.graph.svf_crosscheck import function_tail
from appsec_review.indexing.store import shard_key
from appsec_review.review.scope import AcceptedScope, ScopeGap
from appsec_review.review.units import ContextEntry, context_entry


MEMORY_CONTEXT_RULE = "appsec-review/package-memory-context/1"
SVF_PRODUCER = "svf_points_to"
SVF_JOB = "job_svf_alias_analysis"
POINTS_TO_ROLE, INDIRECT_CALL_ROLE, MEMORY_OBJECT_ROLE = "points_to", "indirect_call", "memory_object"
_LINE_KINDS = ("points_to_set", "indirect_call_targets")
C_FAMILY_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"})


@dataclass(frozen=True, slots=True)
class _Record:
    identity: str
    kind: str
    payload: Mapping[str, Any]
    shard_sha256: str


@dataclass(frozen=True, slots=True)
class MemoryLeadContext:
    entries: tuple[ContextEntry, ...]
    gaps: tuple[ScopeGap, ...]
    functions: tuple[str, ...]          # unqualified names of the functions the line's sites belong to


def _is_svf_shard(shard: Mapping[str, Any]) -> bool:
    producer = shard.get("producer") or {}
    return shard.get("name") == "analysis" and producer.get("job") == SVF_JOB \
        and str(shard.get("shard_id", "")).startswith("svf-")


def is_c_family(path: str | None) -> bool:
    return bool(path) and PurePosixPath(str(path)).suffix.lower() in C_FAMILY_SUFFIXES


class MemoryContext:
    """Accepted SVF records indexed by source line; pure reads of verified shards."""

    def __init__(self, scope: AcceptedScope, *, max_entries: int):
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        shards = sorted(scope.select(_is_svf_shard), key=shard_key)
        self.available = bool(shards)
        self.by_line: dict[tuple[str, int], list[_Record]] = defaultdict(list)
        self.objects: dict[str, _Record] = {}
        self.references: dict[str, set[str]] = defaultdict(set)
        self.paths: set[str] = set()
        self.unavailable: list[str] = []
        store = scope.store
        for shard in shards:
            sha = scope.shard_sha256(shard)
            for row in store.entities((shard,), kinds=(*_LINE_KINDS, "memory_object")):
                payload = row["payload"] if isinstance(row["payload"], Mapping) else {}
                record = _Record(str(row["identity"]), str(row["kind"]), payload, sha)
                if record.kind == "memory_object":
                    self.objects[record.identity] = record
                    continue
                location = row.get("location") or {}
                if location.get("path") and location.get("start_line") and not location.get("ambiguous"):
                    self.by_line[(str(location["path"]), int(location["start_line"]))].append(record)
                    self.paths.add(str(location["path"]))
            for relation in store.relations((shard,), kinds=("REFERENCES",)):
                self.references[str(relation["source_id"])].add(str(relation["target_id"]))
            for row in store.coverage((shard,)):
                if row["status"] == "unavailable":
                    self.unavailable.append(f"{row['area']}: {row['gap'] or 'unavailable'}")

    def lead_context(self, path: str | None, line: int | None, subject: str) -> MemoryLeadContext:
        if not is_c_family(path):
            return MemoryLeadContext((), (), ())
        if not self.available:
            return MemoryLeadContext((), (ScopeGap(
                SVF_PRODUCER, subject, "missing",
                "no accepted SVF points-to shard (job_svf_alias_analysis is opt-in or did not run); memory "
                "context for this C/C++ lead is unknown, not empty"),), ())
        if line is None:
            return MemoryLeadContext((), (ScopeGap(SVF_PRODUCER, subject, "ambiguous",
                                                   "lead has no source line; SVF records cannot be joined"),), ())
        records = sorted(self.by_line.get((str(path), int(line)), ()), key=lambda item: (item.kind, item.identity))
        if not records:
            where = f"{path}:{line}"
            reason = (f"no SVF pointer site or indirect call at {where}; the line may hold no pointer operation"
                      if path in self.paths else
                      f"{path} is in no analyzed SVF module" + (f" ({'; '.join(self.unavailable[:3])})"
                                                                if self.unavailable else ""))
            return MemoryLeadContext((), (ScopeGap(SVF_PRODUCER, subject, "unavailable", reason),), ())
        objects: dict[str, _Record] = {}
        for record in records:
            for target in sorted(self.references.get(record.identity, ())):
                if target in self.objects:
                    objects[target] = self.objects[target]
        entries = [context_entry(item.identity, POINTS_TO_ROLE if item.kind == "points_to_set" else INDIRECT_CALL_ROLE,
                                 item.shard_sha256) for item in records]
        entries += [context_entry(item.identity, MEMORY_OBJECT_ROLE, item.shard_sha256)
                    for item in sorted(objects.values(), key=lambda value: value.identity)]
        gaps: list[ScopeGap] = []
        reasons = sorted({reason for item in [*records, *objects.values()]
                          for reason in item.payload.get("open_world_reasons", ())})
        if reasons:
            gaps.append(ScopeGap(SVF_PRODUCER, subject, "partial",
                                 f"SVF records at this line come from open-world modules ({', '.join(reasons)}); "
                                 "they may confirm but never rule out an alias, target or accessor"))
        incomplete = [item for item in [*records, *objects.values()] if not item.payload.get("complete", False)]
        if incomplete and not reasons:
            gaps.append(ScopeGap(SVF_PRODUCER, subject, "partial",
                                 f"{len(incomplete)} SVF record(s) at this line are truncated or incomplete"))
        if len(entries) > self.max_entries:
            omitted = len(entries) - self.max_entries
            entries = self._balanced(entries)
            gaps.append(ScopeGap(SVF_PRODUCER, subject, "truncated",
                                 f"{omitted} SVF context entr{'y' if omitted == 1 else 'ies'} exceeded "
                                 f"max_memory_context_entries={self.max_entries}"))
        functions = sorted({function_tail(item.payload.get("function_demangled") or item.payload.get("function"))
                            for item in records} - {""})
        return MemoryLeadContext(tuple(entries), tuple(gaps), tuple(functions))

    def _balanced(self, entries: Iterable[ContextEntry]) -> list[ContextEntry]:
        """Round-robin by role so objects are kept when a line holds many sites."""
        buckets: dict[str, list[ContextEntry]] = defaultdict(list)
        for entry in entries:
            buckets[entry.role].append(entry)
        chosen: list[ContextEntry] = []
        depth = 0
        while len(chosen) < self.max_entries and any(depth < len(bucket) for bucket in buckets.values()):
            for role in (MEMORY_OBJECT_ROLE, POINTS_TO_ROLE, INDIRECT_CALL_ROLE):
                bucket = buckets.get(role, [])
                if depth < len(bucket) and len(chosen) < self.max_entries:
                    chosen.append(bucket[depth])
            depth += 1
        return chosen
