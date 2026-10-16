"""Flow graphs, analyzer diagnostics, clangd symbols and Joern CPG rows attached to a CodeQL neighborhood.

docs/architecture/seeded-neighborhoods.md section 9 is normative. ``query_codeql_neighborhood`` with
``include`` of ``flow``, ``diagnostics``, ``symbols`` or ``cpg`` reads the scope's ``producer_neighborhood``
shard (published by ``job_code_graph_index``) for the closure functions it already resolved. Nothing here
runs an analyzer or scans a target: a function the producers did not cover yields a named
``outside_precomputed_neighborhood`` gap, never an empty answer that reads as clean.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
import json
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from appsec_review.graph.contract import GRAPH_INDEX
from appsec_review.retrieval.graph import _restore_paths

if TYPE_CHECKING:  # pragma: no cover
    from appsec_review.retrieval.neighborhood import _Neighborhood

PRODUCERS_KIND = "producer_neighborhood"
PRODUCER_FACTS = ("flow", "diagnostics", "symbols", "cpg")
_ROW_KIND = {"flow": "ir_entity", "diagnostics": "tool_observation", "symbols": "symbol", "cpg": "tool_observation"}
_BASE = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE "
MAX_ROWS_PER_KIND = 2000      # rows read from one producers shard per fact (the publisher bounds each below this)
MAX_NAMED_MISSING = 5


def _tail(name: Any) -> str:
    text = str(name or "")
    if "(" in text:
        text = text[:text.index("(")]
    return text.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()


def _names(name: Any) -> frozenset[str]:
    text = str(name or "").strip()
    return frozenset(value for value in (text, _tail(text)) if value)


def _chain(parents: Mapping[str, Any], block: str, limit: int = 64) -> list[str]:
    """Blocks that (post-)dominate ``block``, nearest first, up to the entry/exit."""
    found: list[str] = []
    current = parents.get(block)
    while isinstance(current, str) and current not in found and len(found) < limit:
        found.append(current)
        current = parents.get(current)
    return found


def seed_block(flow: Mapping[str, Any], line: int) -> dict[str, Any] | None:
    """The smallest basic block holding ``line`` with its successors and (post-)dominator chains."""
    covering = [block for block in flow.get("blocks") or ()
                if isinstance(block, Mapping) and isinstance(block.get("start_line"), int)
                and isinstance(block.get("end_line"), int) and block["start_line"] <= line <= block["end_line"]]
    if not covering:
        return None
    block = min(covering, key=lambda item: (item["end_line"] - item["start_line"], str(item.get("id"))))
    name = str(block.get("id"))
    return {"block": name, "label": block.get("label"), "start_line": block["start_line"],
            "end_line": block["end_line"], "successors": list(block.get("successors") or ()),
            "dominated_by": _chain(flow.get("dominators") or {}, name),
            "post_dominated_by": _chain(flow.get("post_dominators") or {}, name)}


class _Closure:
    """The closure functions of one request: identity, name variants and source span."""

    def __init__(self, entries: list[dict[str, Any]]):
        self.entries = entries

    def match(self, payload: Mapping[str, Any], location: Mapping[str, Any] | None, *,
              names: Sequence[str] = (), links: Sequence[str] = (), by_span: bool = False,
              path: str | None = None) -> dict[str, Any] | None:
        variants = frozenset(names)
        for entry in self.entries:
            if path is not None and entry["path"] and not (entry["path"] == path or entry["path"].endswith("/" + path)):
                continue  # a name shared with a function of another file is not this function
            if entry["identity"] in links or (variants & entry["names"]):
                return entry
        if location is not None:
            for entry in self.entries:
                if entry["path"] and location["path"] == entry["path"] and entry["start_line"] is not None:
                    low, high = entry["start_line"], entry["end_line"] or entry["start_line"]
                    inside = (low <= location["start_line"] <= high) if by_span else (
                        location["start_line"] <= high and low <= location["end_line"])
                    if inside:
                        return entry
        return None


def _closure(walk: "_Neighborhood", call_databases, functions: Sequence[tuple[int, str]]) -> _Closure:
    entries = []
    for depth, identity in functions:
        for _, database in call_databases:
            row = database.execute(_BASE + "e.identity = ?", (identity,)).fetchone()
            if row is not None:
                entries.append({"identity": identity, "depth": depth, "name": str(row["native_id"]),
                                "names": _names(row["native_id"]), "path": row["path"],
                                "start_line": row["start_line"], "end_line": row["end_line"]})
                break
    return _Closure(entries)


def attach(walk: "_Neighborhood", stack: ExitStack, deadline: float, call_databases,
           functions: Sequence[tuple[int, str]], wanted: Sequence[str]) -> list[dict[str, Any]]:
    """Rows of the wanted producer facts for the closure functions, each tagged ``fact`` and ``for_function``."""
    shards = [shard for shard in walk.core.indexes.get(GRAPH_INDEX, ())
              if (shard.get("producer") or {}).get("kind") == PRODUCERS_KIND
              and (shard.get("producer") or {}).get("scope_id") == walk.scope_id]
    if not shards:
        walk.gaps.append(f"accepted graph producer-neighborhood index is unavailable for {walk.scope_id}; flow, "
                         "diagnostics, clangd symbols and CPG rows were not published")
        return []
    databases = [(shard, stack.enter_context(closing(walk.core._database(shard, deadline)))) for shard in shards]
    for shard in shards:
        walk.gaps.extend(str(gap)[:300] for gap in list(shard.get("gaps") or ())[:3])
    closure = _closure(walk, call_databases, functions)
    seed_line = None
    if walk.kind == "seed":
        from appsec_review.retrieval.neighborhood import _parse_seed

        seed_path, seed_line = _parse_seed(walk.value)
    found: list[dict[str, Any]] = []
    covered: dict[str, set[str]] = {name: set() for name in wanted}
    for name in wanted:
        for shard, database in databases:
            walk.core._check_deadline(deadline)
            for row in database.execute(_BASE + "e.kind = ? ORDER BY e.identity LIMIT ?",
                                        (_ROW_KIND[name], MAX_ROWS_PER_KIND)):
                raw = json.loads(row["payload_json"])
                if raw.get("fact") != name:
                    continue
                location = ({"path": row["path"], "start_line": row["start_line"], "end_line": row["end_line"]}
                            if row["path"] is not None else None)
                if name == "flow":
                    entry = closure.match(raw, location, names=raw.get("names") or ())
                elif name == "cpg":
                    entry = closure.match(raw, None, names=raw.get("names") or (), path=raw.get("path"))
                elif name == "symbols":
                    entry = closure.match(raw, location, names=raw.get("names") or (),
                                          links=[link.get("codeql_symbol") for link in raw.get("cross_reference") or ()
                                                 if isinstance(link, Mapping)])
                else:
                    entry = closure.match(raw, location, names=_names(raw.get("function")) if raw.get("function") else (),
                                          by_span=True)
                if entry is None:
                    continue
                item = walk.core._entity(row, GRAPH_INDEX)
                item["payload"] = _restore_paths(raw, item["payload"])
                item["shard_id"] = str(shard.get("shard_id", "default"))
                item.update(fact=name, for_function=entry["identity"], function_depth=entry["depth"])
                if name == "flow" and seed_line is not None and location is not None \
                        and (location["path"] == seed_path or location["path"].endswith("/" + seed_path)):
                    block = seed_block(raw["flow"], seed_line)
                    if block is not None:
                        item["seed_block"] = block
                covered[name].add(entry["identity"])
                found.append(item)
    subjects = {identity for identity, _ in walk.subjects}
    flows = [item for item in found if item["fact"] == "flow"]
    if flows and any(not isinstance(item["payload"].get("source_cfg"), Mapping) for item in flows):
        walk.gaps.append("flow: source_cfg is absent for "
                         f"{sum(1 for item in flows if not isinstance(item['payload'].get('source_cfg'), Mapping))} "
                         "function(s); only the LLVM IR flow is available for them (source_cfg_unavailable)")
    for name in wanted:
        missing = [entry for entry in closure.entries if entry["identity"] not in covered[name]]
        if name == "diagnostics":
            continue  # a function with no diagnostic is not a gap; absence outside the neighborhood is the seeded gap
        if subjects - covered[name]:
            walk.gap("outside_precomputed_neighborhood",
                     f"no {name} was published for {len(subjects - covered[name])} seed function(s); the producers "
                     "did not cover them, which is not evidence that they have none")
        elif missing:
            walk.gaps.append(f"{name}: {len(missing)} closure function(s) have none published "
                             f"(e.g. {', '.join(entry['name'][:80] for entry in missing[:MAX_NAMED_MISSING])})")
    return found
