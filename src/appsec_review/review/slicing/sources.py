"""``SliceSources`` over an accepted scope: the read-only data the slice strategies may use.

``AcceptedSliceSources`` answers the four ``contract.SliceSources`` questions from accepted, verified inputs
only. Every answer is bounded per file and cached per ``(path, file_sha256)`` / ``path``:

* ``source_lines(path, sha)``: every line of the accepted ``source_file`` entity of ``path``, read through
  ``RetrievalCore.read_source_lines`` (target or run-bound generated-source custody, digest-verified), and
  accepted only when the verified file hash equals ``sha``. Anything else is ``(None, reason)``.
* ``ir_flows(path)``: the ``ir_entity`` rows with ``payload.fact == "flow"`` located in ``path`` from the
  accepted graph ``producer_neighborhood`` shards (``jobs/job_code_graph_index/producers.py``). ``None``
  when no such shard is accepted.
* ``svf_records(path, line)``: the ``review.memory_context`` join: the non-ambiguous ``points_to_set`` and
  ``indirect_call_targets`` rows at ``path:line`` of the accepted ``job_svf_alias_analysis`` shards, the
  ``memory_object`` rows they ``REFERENCES``, and the ``memory_object`` rows allocated on that line. ``None``
  when no SVF shard is accepted, the file is not C/C++, or no analyzed record lies in the file.
* ``syntax_rows(path)``: every ``ast_node`` row of ``path`` in the accepted ``job_tree_sitter_ast`` analysis
  shards. ``None`` when no such shard is accepted, or (with a ``slice_truncated`` facade gap) when the file
  holds more than ``max_syntax_rows`` nodes.

``gaps()`` returns the facade's own named gaps (sorted, unique); the package assembler passes them to the
composer as inherited gaps. A ``None`` answer makes the strategy report ``not_applicable`` with its own gap.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
import json
from typing import Any

from appsec_review.graph.contract import GRAPH_INDEX
from appsec_review.indexing.store import _LOCATION, open_shard, shard_key
from appsec_review.review.memory_context import _is_svf_shard, is_c_family
from appsec_review.review.scope import AcceptedScope
from appsec_review.review.slicing.contract import GAP_TRUNCATED

PRODUCERS_KIND = "producer_neighborhood"
TREE_SITTER_JOB = "job_tree_sitter_ast"
MAX_SYNTAX_ROWS = 20000
MAX_IR_FLOWS = 2000
_SVF_LINE_KINDS = ("points_to_set", "indirect_call_targets")

ReadSource = Callable[[str], tuple[Mapping[str, Any] | None, str | None]]


def _same_path(location: Mapping[str, Any] | None, path: str) -> bool:
    found = (location or {}).get("path")
    return isinstance(found, str) and (found == path or found.endswith("/" + path))


class AcceptedSliceSources:
    """``SliceSources`` backed by the accepted scope; ``read_source`` and ``core`` are injectable for tests."""

    def __init__(self, scope: AcceptedScope, *, core: Any = None, read_source: ReadSource | None = None,
                 max_syntax_rows: int = MAX_SYNTAX_ROWS):
        if max_syntax_rows < 1:
            raise ValueError("max_syntax_rows must be positive")
        self.scope = scope
        self._core = core
        self._read_source = read_source
        self.max_syntax_rows = max_syntax_rows
        self._gaps: dict[str, set[str]] = defaultdict(set)
        self._lines: dict[tuple[str, str], tuple[tuple[str, ...] | None, str | None]] = {}
        self._flows: dict[str, list[dict[str, Any]]] = {}
        self._syntax: dict[str, list[dict[str, Any]] | None] = {}
        self._svf: dict[str, Any] | None = None
        self._producer_shards = tuple(sorted(scope.select(
            lambda shard: shard["name"] == GRAPH_INDEX
            and (shard.get("producer") or {}).get("kind") == PRODUCERS_KIND), key=shard_key))
        self._svf_shards = tuple(sorted(scope.select(_is_svf_shard), key=shard_key))
        self._syntax_shards = tuple(sorted(scope.select(
            lambda shard: shard["name"] == "analysis"
            and (shard.get("producer") or {}).get("job") == TREE_SITTER_JOB), key=shard_key))

    def gaps(self, paths: Iterable[str] | None = None) -> tuple[str, ...]:
        """The facade's own gaps for ``paths`` (every path when ``None``), sorted and unique."""
        chosen = self._gaps if paths is None else {path: self._gaps.get(path, set()) for path in paths}
        return tuple(sorted({gap for found in chosen.values() for gap in found}))

    # -- source text -----------------------------------------------------------------------------------
    def _reader(self) -> ReadSource:
        if self._read_source is None:
            if self._core is None:
                from appsec_review.retrieval.core import RetrievalCore
                self._core = RetrievalCore(self.scope.run_root.parent, self.scope.run_id,
                                           manifest_sha256=self.scope.manifest_sha256,
                                           manifest_path=self.scope.manifest_path)
            core = self._core
            self._read_source = lambda identity: core.read_source_lines(identity=identity)
        return self._read_source

    def source_lines(self, path: str, file_sha256: str) -> tuple[Sequence[str] | None, str | None]:
        key = (path, file_sha256)
        if key not in self._lines:
            self._lines[key] = self._load_lines(path, file_sha256)
        return self._lines[key]

    def _load_lines(self, path: str, file_sha256: str) -> tuple[tuple[str, ...] | None, str | None]:
        source = self.scope.source_for(path)
        if source is None:
            return None, "no accepted source_file entity for the path"
        try:
            found, reason = self._reader()(source.identity)
        except Exception as exc:  # noqa: BLE001 - an unreadable source is a named gap, never a package failure
            return None, f"source read failed: {type(exc).__name__}"
        if found is None:
            return None, reason or "source is unavailable"
        if (found.get("location") or {}).get("file_sha256") != file_sha256:
            return None, "the verified file hash differs from the path fact's file hash"
        return tuple(str(line) for line in found.get("lines") or ()), None

    # -- LLVM IR flow rows ---------------------------------------------------------------------------
    def ir_flows(self, path: str) -> Sequence[Mapping[str, Any]] | None:
        if not self._producer_shards:
            return None
        if path not in self._flows:
            rows: dict[str, dict[str, Any]] = {}
            for row in self.scope.store.entities(self._producer_shards, kinds=("ir_entity",)):
                payload = row["payload"] if isinstance(row["payload"], Mapping) else {}
                if payload.get("fact") == "flow" and _same_path(row.get("location"), path):
                    rows.setdefault(str(row["identity"]), row)
            ordered = [rows[key] for key in sorted(rows)]
            if len(ordered) > MAX_IR_FLOWS:
                self._gaps[path].add(f"{GAP_TRUNCATED}: llvm_ir flow rows for {path} exceed {MAX_IR_FLOWS}; "
                               f"{len(ordered) - MAX_IR_FLOWS} omitted")
                ordered = ordered[:MAX_IR_FLOWS]
            self._flows[path] = ordered
        return self._flows[path]

    # -- SVF records ---------------------------------------------------------------------------------
    def _svf_index(self) -> dict[str, Any]:
        if self._svf is None:
            by_line: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
            allocated: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
            objects: dict[str, dict[str, Any]] = {}
            references: dict[str, set[str]] = defaultdict(set)
            paths: set[str] = set()
            store = self.scope.store
            for row in store.entities(self._svf_shards, kinds=(*_SVF_LINE_KINDS, "memory_object")):
                location = row.get("location") or {}
                if row["kind"] == "memory_object":
                    objects[str(row["identity"])] = row
                    if location.get("path") and location.get("start_line"):
                        allocated[(str(location["path"]), int(location["start_line"]))][str(row["identity"])] = row
                    continue
                if location.get("path") and location.get("start_line") and not location.get("ambiguous"):
                    by_line[(str(location["path"]), int(location["start_line"]))][str(row["identity"])] = row
                    paths.add(str(location["path"]))
            for relation in store.relations(self._svf_shards, kinds=("REFERENCES",)):
                references[str(relation["source_id"])].add(str(relation["target_id"]))
            self._svf = {"by_line": by_line, "allocated": allocated, "objects": objects,
                         "references": references, "paths": paths}
        return self._svf

    def svf_records(self, path: str, line: int) -> Sequence[Mapping[str, Any]] | None:
        if not self._svf_shards or not is_c_family(path):
            return None
        index = self._svf_index()
        if path not in index["paths"]:
            return None
        found: dict[str, Mapping[str, Any]] = dict(index["by_line"].get((path, int(line)), {}))
        for identity in list(found):
            for target in sorted(index["references"].get(identity, ())):
                if target in index["objects"]:
                    found.setdefault(target, index["objects"][target])
        found.update(index["allocated"].get((path, int(line)), {}))
        return [found[key] for key in sorted(found)]

    # -- tree-sitter syntax rows ---------------------------------------------------------------------
    def syntax_rows(self, path: str) -> Sequence[Mapping[str, Any]] | None:
        if not self._syntax_shards:
            return None
        if path not in self._syntax:
            self._syntax[path] = self._load_syntax(path)
        return self._syntax[path]

    def _load_syntax(self, path: str) -> list[dict[str, Any]] | None:
        rows: dict[str, dict[str, Any]] = {}
        sql = ("SELECT e.identity, e.kind, e.native_id, e.name, e.text, e.payload_json, "
               + ", ".join(f"l.{name}" for name in _LOCATION)
               + " FROM entities e JOIN locations l ON l.entity_id = e.identity"
               " WHERE e.kind = 'ast_node' AND l.path = ? ORDER BY e.identity LIMIT ?")
        for shard in self._syntax_shards:
            with open_shard(self.scope.run_root, shard) as database:
                for row in database.execute(sql, (path, self.max_syntax_rows + 1)):
                    rows.setdefault(str(row["identity"]), {
                        "identity": row["identity"], "kind": row["kind"], "native_id": row["native_id"],
                        "name": row["name"], "text": row["text"], "payload": json.loads(row["payload_json"]),
                        "location": {name: row[name] for name in _LOCATION}})
            if len(rows) > self.max_syntax_rows:
                self._gaps[path].add(f"{GAP_TRUNCATED}: tree_sitter rows for {path} exceed {self.max_syntax_rows}; the "
                               "syntax strategy does not read the file")
                return None
        return [rows[key] for key in sorted(rows)]


class UnavailableSliceSources:
    """``SliceSources`` when no facade can be built: every answer is unavailable, with the reason."""

    def __init__(self, reason: str):
        self.reason = reason

    def gaps(self, paths: Iterable[str] | None = None) -> tuple[str, ...]:
        return ()

    def source_lines(self, path: str, file_sha256: str) -> tuple[None, str]:
        return None, self.reason

    def ir_flows(self, path: str) -> None:
        return None

    def svf_records(self, path: str, line: int) -> None:
        return None

    def syntax_rows(self, path: str) -> None:
        return None


__all__ = ["AcceptedSliceSources", "MAX_IR_FLOWS", "MAX_SYNTAX_ROWS", "PRODUCERS_KIND", "TREE_SITTER_JOB",
           "UnavailableSliceSources"]
