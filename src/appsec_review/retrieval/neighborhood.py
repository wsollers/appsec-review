"""``list_codeql_databases`` and ``query_codeql_neighborhood``: bounded reads of seeded CodeQL graphs.

docs/architecture/seeded-codeql-neighborhoods.md sections 7 and 8 are normative. Nothing here runs
CodeQL or scans a target: every answer is read from hash-verified ``graph`` shards that
``job_code_graph_index`` published, namely one ``codeql_database`` card per CodeQL scope and the
scope's fact-family shards. The call closure composes ``retrieval.graph._GraphQuery`` (the same
bounded walk ``query_code_graph`` runs) over the card scope's ``call_site`` shard, and the attached
fact families reuse its selection per closure function; no closure or selection logic lives here.

Seeded output is a sample around findings. Every bound reached, every unexpanded frontier and every
subject outside the precomputed neighborhood is a *named* gap (``database_unknown``,
``outside_precomputed_neighborhood``, ``depth_exceeds_precomputed``, ``frontier``,
``limit_reached``, ``depth_reached``); an empty result is never a claim of absence.

The Python-only ``graph_scopes`` keyword restricts the visible cards to the CodeQL scopes a review
capability grants. It is not a tool argument: the MCP schema is closed over the model-visible
parameters, and an ungranted database is indistinguishable from an unknown one.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
from dataclasses import dataclass
import json
import re
import sqlite3
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Sequence

from appsec_review.graph.contract import GRAPH_INDEX, MAX_TOOL_DEPTH, MAX_TOOL_LIMIT, Family, GraphSettings, Mode
from appsec_review.retrieval import producer_facts
from appsec_review.retrieval.graph import _GraphQuery, _restore_paths
from appsec_review.retrieval.model import EntityKind, LogicalIdentity, normalize_relative_path

if TYPE_CHECKING:  # pragma: no cover
    from appsec_review.retrieval.core import RetrievalCore

LIST_CODEQL_DATABASES = "list_codeql_databases"
QUERY_CODEQL_NEIGHBORHOOD = "query_codeql_neighborhood"
CARD_SCHEMA = "appsec-review/codeql-database/1"
CARD_PRODUCER_KIND = "codeql_database"
SUMMARY_KIND = "neighborhood_summary"
DIRECTIONS = ("callers", "callees", "both")
INCLUDES = ("calls", "sinks", "entry_points", "guards", "ranges", "paths", "flow", "diagnostics", "symbols", "cpg")
DEFAULT_INCLUDE = ("calls", "sinks")
LANGUAGE_PATTERN = "^[A-Za-z0-9_+.#-]{1,64}$"
SEED_PATTERN = r"^.{1,4096}:[0-9]{1,9}$"
GAP_NAMES = ("database_unknown", "outside_precomputed_neighborhood", "depth_exceeds_precomputed", "frontier",
             "limit_reached", "depth_reached")
MAX_LIST_SEEDS = 20           # seed-ledger entries returned per card by list_codeql_databases
MAX_LIST_SOURCES = 3          # sources returned per listed seed
MAX_LIST_GAPS = 10
CLOSURE_BOUND = 500           # call-site rows per closure walk; fixed so pages are stable below it
MAX_SUBJECTS = 8              # distinct symbols one subject may resolve to (overloads share a name)
MAX_FACT_FUNCTIONS = 25       # closure functions whose sink/entry/path facts are attached
MAX_FACT_SINKS = 25           # sink sites whose guards and ranges are attached
MAX_FRONTIER = 20             # frontier symbols named in the summary row
_LANGUAGE = re.compile(LANGUAGE_PATTERN)
_SEED = re.compile(SEED_PATTERN)
_BASE = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE ")
_DIRECTION_MODES = {"callers": (Mode.CALLERS,), "callees": (Mode.CALLEES,), "both": (Mode.CALLERS, Mode.CALLEES)}
_FACT_ORDER = {"sinks": 0, "entry_points": 1, "guards": 2, "ranges": 3, "paths": 4, "flow": 5, "diagnostics": 6,
               "symbols": 7, "cpg": 8}
_FACT_MODE = {"sinks": Mode.SINKS, "entry_points": Mode.ENTRY_POINTS, "paths": Mode.PATHS,
              "guards": Mode.GUARDS, "ranges": Mode.RANGES}


def _violation(reason: str) -> ValueError:
    return ValueError(f"schema_violation: {reason}")


def _limit(core: "RetrievalCore", limit: Any) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= min(MAX_TOOL_LIMIT,
                                                                                          core.limits.max_results):
        raise ValueError("result limit exceeds bound")
    return limit


def _scopes(graph_scopes: Iterable[str] | None) -> frozenset[str] | None:
    return None if graph_scopes is None else frozenset(str(item) for item in graph_scopes)


@dataclass(frozen=True)
class _Card:
    shard: Mapping[str, Any]
    row: sqlite3.Row
    payload: Mapping[str, Any]

    @property
    def identity(self) -> str:
        return str(self.row["identity"])

    @property
    def scope_id(self) -> str:
        return str(self.payload.get("scope_id") or (self.shard.get("producer") or {}).get("scope_id") or "")


def _card_shards(core: "RetrievalCore", scopes: frozenset[str] | None) -> list[Mapping[str, Any]]:
    found = [shard for shard in core.indexes.get(GRAPH_INDEX, ())
             if (shard.get("producer") or {}).get("kind") == CARD_PRODUCER_KIND]
    if scopes is not None:
        found = [shard for shard in found if (shard.get("producer") or {}).get("scope_id") in scopes]
    return found


def _load_cards(core: "RetrievalCore", deadline: float, scopes: frozenset[str] | None) -> list[_Card]:
    """Every visible database card, ordered by (scope id, identity)."""
    cards: list[_Card] = []
    for shard in _card_shards(core, scopes):
        core._check_deadline(deadline)
        with closing(core._database(shard, deadline)) as database:
            for row in database.execute(_BASE + "e.kind = ? ORDER BY e.identity LIMIT 8",
                                        (EntityKind.CODEQL_DATABASE.value,)):
                payload = json.loads(row["payload_json"])
                if isinstance(payload, dict) and payload.get("schema") == CARD_SCHEMA:
                    cards.append(_Card(shard, row, payload))
    return sorted(cards, key=lambda card: (card.scope_id, card.identity))


def _compact_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The card payload with the seed ledger bounded for a listing (the card keeps the full ledger)."""
    seeded = dict(payload.get("seeded") or {})
    seeds = list(seeded.get("seeds") or ())
    seeded["seeds"] = [{**seed, "sources": list(seed.get("sources") or ())[:MAX_LIST_SOURCES]}
                       for seed in seeds[:MAX_LIST_SEEDS] if isinstance(seed, Mapping)]
    seeded["seeds_omitted"] = max(0, len(seeds) - MAX_LIST_SEEDS)
    seeded["gaps"] = list(seeded.get("gaps") or ())[:MAX_LIST_GAPS]
    value = {key: child for key, child in payload.items() if key != "seeded"}
    value["seeded"] = seeded
    value["gaps"] = list(payload.get("gaps") or ())[:MAX_LIST_GAPS]
    return value


def _card_row(core: "RetrievalCore", card: _Card) -> dict[str, Any]:
    item = core._entity(card.row, GRAPH_INDEX)
    compact = _compact_payload(card.payload)
    item["payload"] = _restore_paths(compact, core._safe_payload(compact))
    item["shard_id"] = str(card.shard.get("shard_id", "default"))
    return item


# ------------------------------------------------------------------------------ list_codeql_databases


def list_codeql_databases(core: "RetrievalCore", *, language: str | None = None, limit: int = 20,
                          cursor: str | None = None,
                          graph_scopes: Iterable[str] | None = None) -> dict[str, Any]:
    """The database cards a model may ask about: language, root, seeding, depth, coverage and gaps."""
    limit = _limit(core, limit)
    if language is not None and (not isinstance(language, str) or not _LANGUAGE.fullmatch(language)):
        raise _violation("language is not a language name")
    scopes = _scopes(graph_scopes)
    parameters = {"language": language, "limit": limit, "cursor": cursor,
                  "graph_scopes": None if scopes is None else sorted(scopes)}
    request_hash = core._request_hash(LIST_CODEQL_DATABASES, parameters)
    offset = core._offset(cursor, request_hash)

    def operation(deadline: float):
        cards = _load_cards(core, deadline, scopes)
        if language is not None:
            wanted = language.lower()
            cards = [card for card in cards if wanted in {
                str(card.payload.get("language", "")).lower(),
                *(str(item).lower() for item in card.payload.get("source_languages") or ())}]
        page = cards[offset:offset + limit]
        gaps: list[str] = []
        if not cards:
            gaps.append("no accepted CodeQL database card matches; no database is available to this request, which "
                        "is not evidence that the target has none or is clean")
        gaps.extend(f"codeql_database {card.scope_id}: coverage {card.payload.get('coverage')}: {gap}"
                    for card in page if card.payload.get("coverage") != "complete"
                    for gap in list(card.payload.get("gaps") or ())[:2])
        return [_card_row(core, card) for card in page], gaps, len(cards) > offset + limit, offset
    return core._execute(LIST_CODEQL_DATABASES, parameters, operation)


# ------------------------------------------------------------------------------ query_codeql_neighborhood


def _parse_seed(seed: str) -> tuple[str, int]:
    if not isinstance(seed, str) or not _SEED.fullmatch(seed):
        raise _violation("seed must be a ledger seed as path:line")
    path, _, line = seed.rpartition(":")
    try:
        return normalize_relative_path(path), int(line)
    except ValueError:
        raise _violation("seed path must be target-relative") from None


def _validate(core: "RetrievalCore", *, database: Any, seed: Any, symbol: Any, observation: Any, direction: Any,
              depth: Any, include: Any) -> tuple[tuple[str, ...], str | None]:
    try:
        if LogicalIdentity.parse(database).kind is not EntityKind.CODEQL_DATABASE:
            raise ValueError
    except (ValueError, TypeError):
        raise _violation("database must be a codeql_database identity") from None
    given = [name for name, value in (("seed", seed), ("symbol", symbol), ("observation", observation))
             if value is not None]
    if len(given) != 1:
        raise _violation("exactly one of seed, symbol or observation is required")
    if seed is not None:
        _parse_seed(seed)
    if symbol is not None and (not isinstance(symbol, str) or not 1 <= len(symbol) <= 4096):
        raise _violation("symbol must be a symbol identity or a qualified function name")
    if isinstance(symbol, str) and symbol.startswith("asr:"):
        try:
            if LogicalIdentity.parse(symbol).kind is not EntityKind.SYMBOL:
                raise ValueError
        except ValueError:
            raise _violation("symbol identity must be a symbol") from None
    if observation is not None:
        try:
            if LogicalIdentity.parse(observation).kind is not EntityKind.TOOL_OBSERVATION:
                raise ValueError
        except (ValueError, TypeError):
            raise _violation("observation must be a tool_observation identity") from None
    if direction not in DIRECTIONS:
        raise _violation("direction is not in the closed set")
    if depth is not None and (isinstance(depth, bool) or not isinstance(depth, int)
                              or not 0 <= depth <= MAX_TOOL_DEPTH):
        raise _violation(f"depth must be an integer between 0 and {MAX_TOOL_DEPTH}")
    if include is None:
        include = list(DEFAULT_INCLUDE)
    if not isinstance(include, (list, tuple)) or not include or len(set(include)) != len(include) \
            or any(item not in INCLUDES for item in include):
        raise _violation("include must be a unique, non-empty subset of the fact families")
    return tuple(item for item in INCLUDES if item in include), given[0]


class _Neighborhood:
    """One request: resolve the subject, walk the closure, attach facts, assemble the page."""

    def __init__(self, core: "RetrievalCore", settings: GraphSettings, card: _Card, *, subject: tuple[str, str],
                 direction: str, depth: int | None, include: Sequence[str], bound: int):
        self.core, self.settings, self.card = core, settings, card
        self.kind, self.value = subject
        self.direction, self.requested_depth, self.include, self.bound = direction, depth, tuple(include), bound
        self.payload = card.payload
        self.scope_id = card.scope_id
        self.seeded_mode = self.payload.get("mode") == "seeded"
        self.gaps: list[str] = []
        self.names: set[str] = set()
        self.subjects: list[tuple[str, str]] = []
        self.truncated = False

    # -- gaps -----------------------------------------------------------------------------------
    def gap(self, name: str, text: str) -> None:
        assert name in GAP_NAMES
        self.gaps.append(f"{name}: {text}")
        self.names.add(name)

    def adopt(self, query: _GraphQuery) -> None:
        """Query gaps, with the closure's own bound messages also under their stable names."""
        for text in query.gaps:
            if "closure depth bound" in text:
                self.gap("depth_reached", text)
            elif "result bound" in text or "result limit" in text:
                self.gap("limit_reached", text)
            else:
                self.gaps.append(text)

    # -- bounds ---------------------------------------------------------------------------------
    def depth_bounds(self) -> tuple[int, int]:
        cap = min(MAX_TOOL_DEPTH, self.settings.max_call_depth, self.core.limits.max_depth)
        seed_depth = self.payload.get("seed_depth")
        if self.seeded_mode and isinstance(seed_depth, int) and not isinstance(seed_depth, bool):
            cap = min(cap, seed_depth)
        applied = cap if self.requested_depth is None else self.requested_depth
        if applied > cap:
            self.gap("depth_exceeds_precomputed",
                     f"requested depth {applied} exceeds the precomputed depth {cap}; the walk is clamped to {cap}")
            applied = cap
        return applied, cap

    # -- shards ---------------------------------------------------------------------------------
    def shards(self, family: Family) -> list[Mapping[str, Any]]:
        return [shard for shard in self.core.indexes.get(GRAPH_INDEX, ())
                if (shard.get("producer") or {}).get("family") == family.value
                and (shard.get("producer") or {}).get("scope_id") == self.scope_id]

    def open(self, stack: ExitStack, family: Family, deadline: float):
        return [(shard, stack.enter_context(closing(self.core._database(shard, deadline))))
                for shard in self.shards(family)]

    # -- subject --------------------------------------------------------------------------------
    def symbols_named(self, databases, name: str) -> list[tuple[str, str]]:
        found: dict[str, str] = {}
        for _, database in databases:
            for row in database.execute("SELECT identity, native_id FROM entities WHERE kind='symbol' AND "
                                        "native_id = ? ORDER BY identity LIMIT ?", (name, MAX_SUBJECTS + 1)):
                found[str(row["identity"])] = str(row["native_id"])
        return sorted(found.items())

    def ledger(self) -> list[Mapping[str, Any]]:
        seeds = (self.payload.get("seeded") or {}).get("seeds") or ()
        return [seed for seed in seeds if isinstance(seed, Mapping)]

    def resolve(self, databases) -> None:
        names: list[str] = []
        if self.kind == "symbol":
            if self.value.startswith("asr:"):
                for _, database in databases:
                    row = database.execute("SELECT identity, native_id FROM entities WHERE kind='symbol' AND "
                                           "identity = ?", (self.value,)).fetchone()
                    if row is not None:
                        self.subjects = [(str(row["identity"]), str(row["native_id"]))]
                        break
                if not self.subjects:
                    self.gap("outside_precomputed_neighborhood",
                             "the symbol is not in the call graph exported for this database")
                return
            names = [self.value]
        elif self.kind == "seed":
            path, line = _parse_seed(self.value)
            covering = [seed for seed in self.ledger() if seed.get("path") == path
                        and isinstance(seed.get("start_line"), int) and isinstance(seed.get("end_line"), int)
                        and seed["start_line"] <= line <= seed["end_line"]]
            if not covering:
                self.gap("outside_precomputed_neighborhood",
                         f"{path}:{line} is not a location in this database's seed ledger")
                return
            blocked = [seed for seed in covering if seed.get("status") != "resolved"]
            names = sorted({str(name) for seed in covering if seed.get("status") == "resolved"
                            for name in seed.get("functions") or ()})
            if blocked and not names:
                self.gap("outside_precomputed_neighborhood",
                         f"the seed at {path}:{line} is {blocked[0].get('status')} in the ledger and seeded no "
                         "function")
                return
        else:  # observation
            matching = [seed for seed in self.ledger() if any(
                isinstance(source, Mapping) and source.get("observation_id") == self.value
                for source in seed.get("sources") or ())]
            if not matching:
                self.gap("outside_precomputed_neighborhood",
                         "the observation is not a source of any seed in this database's ledger")
                return
            names = sorted({str(name) for seed in matching if seed.get("status") == "resolved"
                            for name in seed.get("functions") or ()})
            if not names:
                self.gap("outside_precomputed_neighborhood",
                         f"the observation's seed is {matching[0].get('status')} in the ledger and seeded no function")
                return
        subjects: dict[str, str] = {}
        for name in names:
            matches = self.symbols_named(databases, name)
            if not matches:
                self.gap("outside_precomputed_neighborhood",
                         f"function {name[:200]} has no exported call or fact in this database")
            if len(matches) > 1:
                self.gaps.append(f"ambiguous_subject: {len(matches)} symbols are named {name[:200]}; all are walked")
            subjects.update(matches)
        self.subjects = sorted(subjects.items())[:MAX_SUBJECTS]
        if len(subjects) > MAX_SUBJECTS:
            self.gap("limit_reached", f"the subject resolves to {len(subjects)} symbols; the first {MAX_SUBJECTS} "
                                      "are walked")

    # -- closure --------------------------------------------------------------------------------
    def closure(self, databases, deadline: float, depth: int) -> tuple[list[dict[str, Any]], list[tuple[int, str]]]:
        """Call-site rows and the closure's functions as ``(depth, symbol)``, nearest first."""
        rows: dict[tuple[str, str], dict[str, Any]] = {}
        functions: dict[str, int] = {identity: 0 for identity, _ in self.subjects}
        if depth < 1:
            return [], sorted((0, identity) for identity in functions)
        frontier: set[str] = set()
        for identity, _name in self.subjects:
            for mode in _DIRECTION_MODES[self.direction]:
                query = _GraphQuery(self.core, self.settings, mode=mode, subject=identity, depth=depth,
                                    sink_class=None, source_class=None)
                found, truncated = query._closure(databases, deadline, self.bound)
                self.truncated = self.truncated or truncated
                self.adopt(query)
                for row in found:
                    key = (row["identity"], mode.value)
                    next_symbols = sorted(query._neighbors(databases, row["identity"], row["payload"]))
                    row.update(direction=mode.value, from_symbol=identity, next_symbols=next_symbols)
                    if key not in rows or row["depth"] < rows[key]["depth"]:
                        rows[key] = row
                    for symbol in next_symbols:
                        functions[symbol] = min(functions.get(symbol, row["depth"]), row["depth"])
        if self.seeded_mode:
            for row in rows.values():
                edge = ("SELECT 1 FROM relations WHERE kind='CALLS' AND target_id=? LIMIT 1"
                        if row["direction"] == "callers" else
                        "SELECT 1 FROM relations WHERE kind='CONTAINS' AND source_id=? LIMIT 1")
                row["frontier_symbols"] = [symbol for symbol in row["next_symbols"] if not any(
                    database.execute(edge, (symbol,)).fetchone() for _, database in databases)]
                row["frontier"] = bool(row["frontier_symbols"])
                frontier.update(row["frontier_symbols"])
        else:
            for row in rows.values():
                row["frontier"], row["frontier_symbols"] = False, []
        self.frontier = sorted(frontier)
        if frontier:
            self.gap("frontier",
                     f"{len(frontier)} function(s) lie at the boundary of the precomputed neighborhood and were not "
                     "expanded; their onward edges are absent from the export, not nonexistent")
        ordered = sorted(rows.values(), key=lambda row: (row["depth"], row["direction"], row["identity"]))
        return ordered, sorted((depth_of, identity) for identity, depth_of in functions.items())

    frontier: list[str] = []

    # -- facts ----------------------------------------------------------------------------------
    def facts(self, stack: ExitStack, deadline: float, functions: Sequence[tuple[int, str]]
              ) -> list[dict[str, Any]]:
        wanted = [name for name in self.include if name != "calls"]
        if not wanted:
            return []
        scoped = [identity for _depth, identity in functions[:MAX_FACT_FUNCTIONS]]
        depth_of = {identity: depth for depth, identity in functions}
        if len(functions) > MAX_FACT_FUNCTIONS:
            self.gap("limit_reached", f"facts are attached for the {MAX_FACT_FUNCTIONS} nearest of "
                                      f"{len(functions)} closure functions")
        found: dict[tuple[str, str], dict[str, Any]] = {}
        producer_wanted = [name for name in wanted if name in producer_facts.PRODUCER_FACTS]
        wanted = [name for name in wanted if name not in producer_facts.PRODUCER_FACTS]

        def collect(name: str, mode: Mode, databases, subjects: Sequence[str], label: str) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for identity in subjects:
                query = _GraphQuery(self.core, self.settings, mode=mode, subject=identity, depth=None,
                                    sink_class=None, source_class=None)
                for row in query._select(databases, deadline, self.bound):
                    row.update(fact=name, **{label: identity})
                    key = (name, row["identity"])
                    if key not in found:
                        found[key] = row
                        rows.append(row)
                self.adopt(query)
            return rows

        sink_rows: list[dict[str, Any]] = []
        if {"sinks", "guards", "ranges"} & set(wanted):
            sink_dbs = self.open(stack, Family.SINK_SITE, deadline)
            if not sink_dbs:
                self.gaps.append(f"accepted graph sink_site index is unavailable for {self.scope_id}")
            sink_rows = collect("sinks", Mode.SINKS, sink_dbs, scoped, "for_function")
            if "sinks" not in wanted:
                for row in sink_rows:
                    found.pop(("sinks", row["identity"]), None)
        for name in ("entry_points", "paths"):
            if name in wanted:
                family = Family.ENTRY_POINT if name == "entry_points" else Family.DATAFLOW_PATH
                databases = self.open(stack, family, deadline)
                if not databases:
                    self.gaps.append(f"accepted graph {family.value} index is unavailable for {self.scope_id}")
                collect(name, _FACT_MODE[name], databases, scoped, "for_function")
        for name in ("guards", "ranges"):
            if name in wanted:
                family = Family.GUARD_FACT if name == "guards" else Family.RANGE_FACT
                databases = self.open(stack, family, deadline)
                if not databases:
                    self.gaps.append(f"accepted graph {family.value} index is unavailable for {self.scope_id}")
                sinks = sorted(row["identity"] for row in sink_rows)
                if len(sinks) > MAX_FACT_SINKS:
                    self.gap("limit_reached", f"{name} are attached for the first {MAX_FACT_SINKS} of {len(sinks)} "
                                              "sink sites in the closure")
                collect(name, _FACT_MODE[name], databases, sinks[:MAX_FACT_SINKS], "for_sink")
        if producer_wanted:
            for row in producer_facts.attach(self, stack, deadline, self.open(stack, Family.CALL_SITE, deadline),
                                             functions[:MAX_FACT_FUNCTIONS], producer_wanted):
                found[(row["fact"], row["identity"])] = row
        for row in found.values():
            row["function_depth"] = depth_of.get(row.get("for_function") or "", 0)
        return sorted(found.values(), key=lambda row: (_FACT_ORDER[row["fact"]], row["function_depth"],
                                                       row["identity"]))

    # -- run ------------------------------------------------------------------------------------
    def run(self, deadline: float) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
        applied, maximum = self.depth_bounds()
        with ExitStack() as stack:
            call_dbs = self.open(stack, Family.CALL_SITE, deadline)
            if not call_dbs:
                self.gap("outside_precomputed_neighborhood",
                         f"database {self.scope_id} publishes no call graph (coverage "
                         f"{self.payload.get('coverage')}); nothing is precomputed to expand")
                return [], "unavailable", {"applied": applied, "maximum": maximum}
            self.resolve(call_dbs)
            if not self.subjects:
                return [], "unavailable", {"applied": applied, "maximum": maximum}
            calls, functions = self.closure(call_dbs, deadline, applied)
            facts = self.facts(stack, deadline, functions)
        items = ([*calls] if "calls" in self.include else []) + facts
        for row in items:
            row["database"] = self.card.identity
        return items, "", {"applied": applied, "maximum": maximum}


def query_codeql_neighborhood(core: "RetrievalCore", settings: GraphSettings, *, database: str,
                              seed: str | None = None, symbol: str | None = None, observation: str | None = None,
                              direction: str = "both", depth: int | None = None, limit: int = 20,
                              include: Sequence[str] | None = None, cursor: str | None = None,
                              graph_scopes: Iterable[str] | None = None) -> dict[str, Any]:
    """The precomputed call closure around one subject of one database, with attached fact families."""
    limit = _limit(core, limit)
    included, kind = _validate(core, database=database, seed=seed, symbol=symbol, observation=observation,
                               direction=direction, depth=depth, include=include)
    subject = (kind, {"seed": seed, "symbol": symbol, "observation": observation}[kind])
    scopes = _scopes(graph_scopes)
    parameters = {"database": database, "seed": seed, "symbol": symbol, "observation": observation,
                  "direction": direction, "depth": depth, "include": list(included), "limit": limit,
                  "cursor": cursor, "graph_scopes": None if scopes is None else sorted(scopes)}
    request_hash = core._request_hash(QUERY_CODEQL_NEIGHBORHOOD, parameters)
    offset = core._offset(cursor, request_hash)

    def operation(deadline: float):
        cards = [card for card in _load_cards(core, deadline, scopes) if card.identity == database]
        summary: dict[str, Any] = {
            "kind": SUMMARY_KIND, "index": GRAPH_INDEX, "database": database,
            "subject": {kind: str(subject[1])[:256]}, "direction": direction, "include": list(included)}
        if not cards:
            gaps = ["database_unknown: no accepted CodeQL database card has this identity"]
            summary.update(status="unavailable", gap_names=["database_unknown"], frontier={"count": 0, "symbols": []})
            return [summary][offset:offset + limit], gaps, False, offset
        card = cards[0]
        walk = _Neighborhood(core, settings, card, subject=subject, direction=direction, depth=depth,
                             include=included, bound=max(offset + limit + 1, CLOSURE_BOUND))
        items, _unused, depths = walk.run(deadline)
        combined_length = 1 + len(items)
        has_more = combined_length > offset + limit or (walk.truncated and combined_length >= offset + limit)
        if has_more:
            walk.gap("limit_reached", f"query_codeql_neighborhood result limit {limit} reached; further rows are "
                                      "available through the cursor")
        card_state = str(card.payload.get("coverage"))
        gaps = [*walk.gaps, *(f"codeql_database {card.scope_id}: coverage {card_state}: {gap}"
                              for gap in list(card.payload.get("gaps") or ())[:3] if card_state != "complete")]
        status = ("unavailable" if not walk.subjects else
                  "complete" if card_state == "complete" and not walk.gaps else "partial")
        counts: dict[str, int] = {}
        for item in items:
            name = item.get("fact") or "calls"
            counts[name] = counts.get(name, 0) + 1
        summary.update(
            scope_id=card.scope_id, mode=card.payload.get("mode"), status=status,
            depth={"applied": depths["applied"], "maximum": depths["maximum"],
                   "precomputed": card.payload.get("seed_depth")},
            subject={kind: str(subject[1])[:256], "symbols": [{"identity": identity, "name": name[:256]}
                                                              for identity, name in walk.subjects]},
            frontier={"count": len(walk.frontier), "symbols": walk.frontier[:MAX_FRONTIER]},
            gap_names=sorted(walk.names), counts=dict(sorted(counts.items())), returned_total=len(items))
        combined = [summary, *items]
        return combined[offset:offset + limit], gaps, has_more, offset, walk.truncated
    return core._execute(QUERY_CODEQL_NEIGHBORHOOD, parameters, operation)


__all__ = ["CARD_SCHEMA", "GAP_NAMES", "LIST_CODEQL_DATABASES", "QUERY_CODEQL_NEIGHBORHOOD", "SUMMARY_KIND",
           "list_codeql_databases", "query_codeql_neighborhood"]
