"""``query_code_graph``: bounded reads of accepted ``graph`` shards.

docs/architecture/code-graph-precomputation.md section 5 is the normative specification. Nothing here
analyses code: every mode reads hash-verified facts and relations that ``job_code_graph_index``
published, and the ``callers``/``callees`` closure is a bounded walk over stored ``CALLS`` and
``CONTAINS`` relations. Every bound reached, every unsound frontier and every missing shard is a named
gap; an empty result is never a claim of absence.

Shard contract read here (published by ``job_code_graph_index``): one ``graph`` shard per
``(scope, family)`` whose manifest ``producer`` carries ``family`` (a ``Family`` value) and, when known,
``scope_id``. Graph fact payloads follow ``appsec-review/graph-fact/1``.
"""
from __future__ import annotations

from contextlib import ExitStack, closing
import json
import sqlite3
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from appsec_review.graph.contract import (
    DEPTH_MODES, GRAPH_INDEX, MAX_TOOL_DEPTH, MAX_TOOL_LIMIT, MODE_FAMILY, MODE_SUBJECT_KINDS, QUERY_CODE_GRAPH,
    SINK_CLASS_MODES, SOURCE_CLASS_MODES, Dispatch, Family, GraphSettings, GuardState, Mode, SinkClass, SourceClass,
)
from appsec_review.retrieval.model import EntityKind, LogicalIdentity, RelationKind, normalize_relative_path

if TYPE_CHECKING:  # pragma: no cover
    from appsec_review.retrieval.core import RetrievalCore

TOOL_RULE = "query-code-graph/1"
_BASE = "SELECT e.*, l.*, {sort} AS sort_key FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE "
_GUARD_ORDER = "CASE json_extract(e.payload_json, '$.result.guard_state') " + " ".join(
    f"WHEN '{state.value}' THEN {rank}" for rank, state in enumerate(GuardState)) + f" ELSE {len(GuardState)} END"
_LAST = 2_147_483_647
_SORT = {
    Mode.PATHS: f"COALESCE(CAST(json_extract(e.payload_json, '$.result.hop_count') AS INTEGER), {_LAST})",
    Mode.GUARDS: _GUARD_ORDER,
    Mode.RANGES: f"COALESCE(CAST(json_extract(e.payload_json, '$.result.operand_index') AS INTEGER), {_LAST})",
}


def request_error(parameters: Mapping[str, Any]) -> str | None:
    """The structural check shared by the core and the review-cell capability (section 5.1/5.2).

    Returns a bounded reason when the mode, subject kind, ``depth`` or class filters do not fit
    together; ``None`` when the request is well-formed. Caps (limit, depth bound) are checked
    separately by each caller because they depend on its own limits.
    """
    try:
        mode = Mode(parameters.get("mode"))
    except ValueError:
        return "mode is not in the closed set"
    try:
        kind = LogicalIdentity.parse(parameters.get("subject")).kind
    except (ValueError, TypeError):
        return "subject must be an exact logical identity"
    if kind not in MODE_SUBJECT_KINDS[mode]:
        return f"mode {mode.value} does not accept a {kind.value} subject"
    if parameters.get("depth") is not None:
        if mode not in DEPTH_MODES:
            return "depth applies only to callers and callees"
        depth = parameters["depth"]
        if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= MAX_TOOL_DEPTH:
            return f"depth must be an integer between 1 and {MAX_TOOL_DEPTH}"
    for name, modes, vocabulary in (("sink_class", SINK_CLASS_MODES, SinkClass),
                                    ("source_class", SOURCE_CLASS_MODES, SourceClass)):
        value = parameters.get(name)
        if value is None:
            continue
        if mode not in modes:
            return f"{name} does not apply to mode {mode.value}"
        try:
            vocabulary(value)
        except ValueError:
            return f"{name} is not in the closed set"
    return None


def _restore_paths(raw: Any, safe: Any) -> Any:
    """Graph step/condition locations keep their target-relative path.

    ``RetrievalCore._safe_payload`` drops every ``path`` key as defense in depth; a graph fact's embedded
    ``SourceLocation`` is only resolvable with it, so a path that is a canonical target-relative path is
    put back. Anything that is not (absolute, traversal, non-string) stays dropped.
    """
    if isinstance(raw, Mapping) and isinstance(safe, dict):
        for key, child in safe.items():
            if key in raw:
                safe[key] = _restore_paths(raw[key], child)
        value = raw.get("path")
        if isinstance(value, str):
            try:
                safe["path"] = normalize_relative_path(value)
            except ValueError:
                pass
        return safe
    if isinstance(raw, (list, tuple)) and isinstance(safe, list):
        return [_restore_paths(item, child) for item, child in zip(raw, safe)]
    return safe


class _GraphQuery:
    def __init__(self, core: "RetrievalCore", settings: GraphSettings, *, mode: Mode, subject: str,
                 depth: int | None, sink_class: str | None, source_class: str | None):
        self.core, self.settings = core, settings
        self.mode, self.family = mode, MODE_FAMILY[mode]
        self.subject, self.subject_kind = subject, LogicalIdentity.parse(subject).kind
        self.depth, self.sink_class, self.source_class = depth, sink_class, source_class
        self.gaps: list[str] = []

    # -- shards ---------------------------------------------------------------------------------
    def _shards(self, family: Family | None = None) -> list[Mapping[str, Any]]:
        return [shard for shard in self.core.indexes.get(GRAPH_INDEX, ())
                if family is None or (shard.get("producer") or {}).get("family") == family.value]

    def _subject_scopes(self, databases: Iterable[tuple[Mapping[str, Any], sqlite3.Connection]]) -> list[str]:
        """Scope ids the subject is known in, from graph fact payloads or shard producers."""
        scopes: set[str] = set()
        for shard, database in databases:
            rows = database.execute(
                "SELECT DISTINCT json_extract(e.payload_json, '$.scope.scope_id') AS scope FROM entities e "
                "WHERE e.identity=? OR e.identity IN (SELECT target_id FROM relations WHERE source_id=?) "
                "OR e.identity IN (SELECT source_id FROM relations WHERE target_id=?) LIMIT 8",
                (self.subject, self.subject, self.subject)).fetchall()
            found = {str(row["scope"]) for row in rows if row["scope"]}
            if not found and rows:
                producer_scope = (shard.get("producer") or {}).get("scope_id")
                if producer_scope:
                    found.add(str(producer_scope))
            scopes |= found
        return sorted(scopes)

    def _coverage(self, shard: Mapping[str, Any], database: sqlite3.Connection) -> list[tuple[str, str, str | None]]:
        shard_id = str(shard.get("shard_id", "default"))
        rows = [(row["area"], row["status"], row["gap"]) for row in database.execute(
            "SELECT area, status, gap FROM coverage ORDER BY area, status, gap")]
        for area, status, gap in rows:
            self.gaps.append(f"{GRAPH_INDEX}/{shard_id}: coverage {area}: {status}" + (f": {gap}" if gap else ""))
        self.gaps.extend(f"{GRAPH_INDEX}/{shard_id}: {gap}" for gap in shard.get("gaps", ()))
        return rows

    def _row(self, row: sqlite3.Row, shard: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
        item = self.core._entity(row, GRAPH_INDEX)
        item["payload"] = _restore_paths(json.loads(row["payload_json"]), item["payload"])
        item["shard_id"] = str(shard.get("shard_id", "default"))
        item.update(extra)
        return item

    # -- run ------------------------------------------------------------------------------------
    def run(self, deadline: float, offset: int, limit: int) -> tuple:
        bound = offset + limit + 1
        family_shards = self._shards(self.family)
        with ExitStack() as stack:
            def open_all(shards):
                return [(shard, stack.enter_context(closing(self.core._database(shard, deadline))))
                        for shard in shards]
            family_dbs = open_all(family_shards)
            other_dbs = open_all([shard for shard in self._shards() if shard not in family_shards])
            scopes = self._subject_scopes(family_dbs + other_dbs)
            covered = {str((shard.get("producer") or {}).get("scope_id")) for shard in family_shards}
            scope_text = ", ".join(scopes) if scopes else "the subject's scope (subject not found in accepted graph shards)"
            if not family_shards:
                self.gaps.append(f"accepted graph {self.family.value} index is unavailable for {scope_text}")
            else:
                missing = [scope for scope in scopes if scope not in covered and "None" not in covered]
                if missing:
                    self.gaps.append(f"accepted graph {self.family.value} index is unavailable for "
                                     f"{', '.join(missing)}")
            coverage: list[tuple[str, str, str | None]] = []
            for shard, database in family_dbs:
                self.core._check_deadline(deadline)
                coverage.extend(self._coverage(shard, database))
            truncated = False
            if self.mode in DEPTH_MODES:
                rows, truncated = self._closure(family_dbs, deadline, bound)
            elif self.mode is Mode.SARIF_PATH:
                # Broken correlations hang on the sink_site (no path joins the flow's endpoints).
                sink_dbs = [(shard, database) for shard, database in other_dbs
                            if (shard.get("producer") or {}).get("family") == Family.SINK_SITE.value]
                rows = self._sarif(family_dbs + sink_dbs, deadline, bound)
            else:
                rows = self._select(family_dbs, deadline, bound)
        page = rows[offset:offset + limit]
        has_more = len(rows) > offset + limit
        if has_more:
            truncated = True
            self.gaps.append(f"query_code_graph result limit {limit} reached; further {self.family.value} rows are "
                             "available through the cursor")
        if not rows and family_shards and coverage and all(status == "complete" for _, status, _ in coverage):
            self.gaps.append(
                f"no {self.family.value} row for this subject within the catalog, bounds and model coverage of the "
                "accepted graph export; absence is a gap, not evidence that none exists")
        return page, self.gaps, has_more, offset, truncated

    # -- subject-scoped selection ---------------------------------------------------------------
    def _subject_clause(self) -> tuple[str, list[Any]] | None:
        subject, kind, mode = self.subject, self.subject_kind, self.mode
        contains = "e.identity IN (SELECT target_id FROM relations WHERE kind='CONTAINS' AND source_id=?)"
        if mode in {Mode.SINKS, Mode.ENTRY_POINTS}:
            if kind is EntityKind.SYMBOL:
                return (f"({contains} OR json_extract(e.payload_json, '$.result.enclosing_function.symbol') = ?)",
                        [subject, subject])
            if kind is EntityKind.SOURCE_FILE:
                path = self._subject_path()
                return (f"({contains} OR l.path = ?)", [subject, path]) if path else None
            if kind is EntityKind.COMPONENT:
                component = self._subject_entity()
                if component is None:
                    return None
                return (f"({contains} OR json_extract(e.payload_json, '$.scope.component_id') = ?)",
                        [subject, str(component.get("native_id"))])
            self.gaps.append(f"{kind.value} membership is resolved only through graph CONTAINS relations from the "
                             "subject; facts without such a relation are not returned")
            return contains, [subject]
        if mode is Mode.PATHS:
            steps = "EXISTS (SELECT 1 FROM json_each(e.payload_json, '$.result.steps') s WHERE "
            if kind is EntityKind.SINK_SITE:
                return "json_extract(e.payload_json, '$.result.sink.sink_site') = ?", [subject]
            if kind is EntityKind.ENTRY_POINT:
                return "json_extract(e.payload_json, '$.result.source.entry_point') = ?", [subject]
            if kind is EntityKind.SYMBOL:
                return steps + "json_extract(s.value, '$.symbol') = ?)", [subject]
            path = self._subject_path()
            if not path:
                return None
            return f"(l.path = ? OR {steps}json_extract(s.value, '$.location.path') = ?))", [path, path]
        if mode is Mode.GUARDS:
            return ("(json_extract(e.payload_json, '$.result.sink.sink_site') = ? OR e.identity IN "
                    "(SELECT source_id FROM relations WHERE kind='GUARDS' AND target_id=?))", [subject, subject])
        if mode is Mode.RANGES:
            return ("(json_extract(e.payload_json, '$.result.sink.sink_site') = ? OR e.identity IN "
                    "(SELECT source_id FROM relations WHERE kind='DERIVED_FROM' AND target_id=?))", [subject, subject])
        if mode is Mode.SUMMARY:
            return ("(json_extract(e.payload_json, '$.result.function.symbol') = ? OR e.identity IN "
                    "(SELECT source_id FROM relations WHERE kind='DERIVED_FROM' AND target_id=?))", [subject, subject])
        raise AssertionError(f"unhandled mode {mode}")  # pragma: no cover

    def _subject_entity(self) -> Mapping[str, Any] | None:
        found = self.core.find(identity=self.subject, limit=1)["results"]
        if not found:
            self.gaps.append(f"subject {self.subject_kind.value} was not found in accepted indexes")
            return None
        return found[0]

    def _subject_path(self) -> str | None:
        entity = self._subject_entity()
        if entity is None:
            return None
        location = entity.get("location") or {}
        if not location.get("path"):
            self.gaps.append("subject source_file has no resolving location")
            return None
        return str(location["path"])

    def _select(self, databases, deadline: float, bound: int) -> list[dict[str, Any]]:
        clause = self._subject_clause()
        if clause is None:
            return []
        condition, values = clause
        conditions, values = ["e.kind = ?", condition], [self.family.value, *values]
        for name, value, field in (("sink_class", self.sink_class, {Mode.SINKS: "$.result.sink_class",
                                                                     Mode.PATHS: "$.result.sink.sink_class"}),
                                   ("source_class", self.source_class, {
                                       Mode.ENTRY_POINTS: "$.result.source_class",
                                       Mode.PATHS: "$.result.source.source_class"})):
            if value is not None:
                conditions.append("json_extract(e.payload_json, ?) = ?")
                values.extend((field[self.mode], value))
        sql = (_BASE.format(sort=_SORT.get(self.mode, "0")) + " AND ".join(conditions)
               + " ORDER BY sort_key, e.identity LIMIT ?")
        found: list[tuple[int, str, str, dict[str, Any]]] = []
        for shard, database in databases:
            self.core._check_deadline(deadline)
            for row in database.execute(sql, [*values, bound]):
                item = self._row(row, shard)
                found.append((int(row["sort_key"]), row["identity"], item["shard_id"], item))
        found.sort(key=lambda item: item[:3])
        return [item[3] for item in found[:bound]]

    # -- SARIF correlation ----------------------------------------------------------------------
    def _sarif(self, databases, deadline: float, bound: int) -> list[dict[str, Any]]:
        """One row per correlated code flow (``graph-sarif-correlation/1``).

        ``job_code_graph_index`` publishes one ``DERIVED_FROM`` relation per (path, observation) whose
        payload lists every correlated code flow in order (``code_flows``), and, for a flow whose sink
        matched but no path joins it, a ``DERIVED_FROM`` from the ``sink_site`` with state ``broken``.
        Each bridged or partial code flow becomes one ``dataflow_path`` row; partial and broken flows are
        named gaps, and a broken flow never yields a path row.
        """
        from appsec_review.graph.correlate import CORRELATION_RULE

        sql = ("SELECT e.*, l.*, r.relation_id AS correlation_id, r.exact AS correlation_exact, "
               "r.ambiguity AS correlation_ambiguity, r.payload_json AS correlation_json, 0 AS sort_key "
               "FROM relations r JOIN entities e ON e.identity = r.source_id "
               "LEFT JOIN locations l ON l.entity_id = e.identity "
               "WHERE r.kind = ? AND r.target_id = ? AND e.kind IN (?, ?) "
               "AND json_extract(r.payload_json, '$.rule') = ? ORDER BY e.identity LIMIT ?")
        found: list[tuple[int, int, str, str, dict[str, Any]]] = []
        correlations = 0
        for shard, database in databases:
            self.core._check_deadline(deadline)
            for row in database.execute(sql, (RelationKind.DERIVED_FROM.value, self.subject,
                                              Family.DATAFLOW_PATH.value, Family.SINK_SITE.value, CORRELATION_RULE,
                                              bound)):
                correlations += 1
                relation = self.core._safe_payload(json.loads(row["correlation_json"]))
                flows = relation.get("code_flows") if isinstance(relation, Mapping) else None
                if not isinstance(flows, list) or not flows:
                    self.gaps.append(f"sarif correlation {row['correlation_id']} lists no code flows")
                    continue
                for flow in flows:
                    if not isinstance(flow, Mapping):
                        continue
                    code_flow, thread_flow = flow.get("code_flow"), flow.get("thread_flow", 0)
                    state = flow.get("state")
                    if row["kind"] != Family.DATAFLOW_PATH.value:
                        state = "broken"
                    if state != "bridged":
                        counts = {name: len(flow.get(name) or ()) if isinstance(flow.get(name), list)
                                  else flow.get(name) for name in ("matched_steps", "ambiguous_steps",
                                                                   "unmatched_steps")}
                        self.gaps.append(
                            f"sarif correlation code_flow {code_flow} is {state or 'unknown'} (thread_flow "
                            f"{thread_flow}): matched {counts['matched_steps']}, ambiguous "
                            f"{counts['ambiguous_steps']}, unmatched {counts['unmatched_steps']}"
                            + (f"; reason {flow['reason']}" if flow.get("reason") else ""))
                    if state not in {"bridged", "partial"}:
                        continue
                    item = self._row(row, shard, correlation={
                        "relation_id": row["correlation_id"],
                        "exact": bool(row["correlation_exact"]) and state == "bridged",
                        "ambiguity": row["correlation_ambiguity"], "rule": relation.get("rule"),
                        "relation_state": relation.get("state"), **dict(flow)})
                    found.append((int(code_flow) if isinstance(code_flow, int) else _LAST,
                                  int(thread_flow) if isinstance(thread_flow, int) else _LAST,
                                  row["identity"], item["shard_id"], item))
        if not correlations:
            self.gaps.append("no accepted SARIF correlation exists for this observation; its CodeQL flow is not "
                             "bridged to a graph path")
        found.sort(key=lambda item: item[:4])
        return [item[4] for item in found[:bound]]

    # -- callers / callees closure --------------------------------------------------------------
    def _closure(self, databases, deadline: float, bound: int) -> tuple[list[dict[str, Any]], bool]:
        callers = self.mode is Mode.CALLERS
        site_sql = _BASE.format(sort="0") + "e.kind = 'call_site' AND e.identity IN (" + (
            "SELECT source_id FROM relations WHERE kind='CALLS' AND target_id=?" if callers else
            "SELECT target_id FROM relations WHERE kind='CONTAINS' AND source_id=?") + ") ORDER BY e.identity LIMIT ?"
        touch_sql = ("SELECT 1 FROM relations WHERE (kind='CALLS' AND target_id=?) OR "
                     "(kind='CONTAINS' AND source_id=?) LIMIT 1")
        unresolved_sql = (_BASE.format(sort="0") + "e.kind = 'call_site' AND "
                          "json_extract(e.payload_json, '$.result.callee.dispatch') = ? ORDER BY e.identity LIMIT ?")
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        expanded, frontier = {self.subject}, {self.subject}
        unresolved_done: set[str] = set()
        depth = int(self.depth or 1)
        for level in range(1, depth + 1):
            level_rows: dict[str, tuple[Mapping[str, Any], sqlite3.Row, str | None]] = {}
            for shard, database in databases:
                shard_id = str(shard.get("shard_id", "default"))
                for symbol in sorted(frontier):
                    self.core._check_deadline(deadline)
                    for row in database.execute(site_sql, (symbol, bound)):
                        level_rows.setdefault(row["identity"], (shard, row, None))
                    if callers and shard_id not in unresolved_done and database.execute(
                            touch_sql, (symbol, symbol)).fetchone():
                        unresolved_done.add(shard_id)
                        count = 0
                        for row in database.execute(unresolved_sql, (Dispatch.UNRESOLVED_INDIRECT.value, bound)):
                            count += 1
                            level_rows.setdefault(row["identity"], (shard, row, "unresolved_indirect_candidate"))
                        if count:
                            self.gaps.append(
                                f"{GRAPH_INDEX}/{shard_id}: callers closure is unsound: unresolved indirect call "
                                "sites in this scope may call the frontier and are returned as candidate rows")
            new = sorted(identity for identity in level_rows if identity not in seen)
            next_frontier: set[str] = set()
            for identity in new:
                if len(rows) >= bound:
                    self.gaps.append(f"{self.mode.value} closure stopped at the result bound at depth {level}")
                    return rows, True
                seen.add(identity)
                shard, row, role = level_rows[identity]
                extra: dict[str, Any] = {"depth": level}
                if role:
                    extra["closure_role"] = role
                rows.append(self._row(row, shard, **extra))
                if role is None:
                    next_frontier |= self._neighbors(databases, identity, json.loads(row["payload_json"]))
            frontier = next_frontier - expanded
            expanded |= frontier
            if not frontier:
                return rows, False
        # The depth bound was reached with an unexpanded frontier: say whether rows lie beyond it.
        for shard, database in databases:
            for symbol in sorted(frontier):
                self.core._check_deadline(deadline)
                if database.execute(site_sql, (symbol, 1)).fetchone():
                    self.gaps.append(f"{self.mode.value} closure depth bound {depth} reached; deeper call sites "
                                     "were not expanded")
                    return rows, True
        return rows, False

    def _neighbors(self, databases, site: str, payload: Mapping[str, Any]) -> set[str]:
        """The next frontier symbol(s) of one call site: its caller (callers) or callee (callees)."""
        callers = self.mode is Mode.CALLERS
        result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
        side = result.get("caller" if callers else "callee")
        found: set[str] = set()
        if isinstance(side, Mapping) and isinstance(side.get("symbol"), str):
            found.add(side["symbol"])
        sql = ("SELECT source_id AS other FROM relations WHERE kind='CONTAINS' AND target_id=?" if callers else
               "SELECT target_id AS other FROM relations WHERE kind='CALLS' AND source_id=?")
        for _, database in databases:
            found.update(str(row["other"]) for row in database.execute(sql + " ORDER BY other LIMIT 64", (site,)))
        valid = set()
        for value in found:
            try:
                if LogicalIdentity.parse(value).kind is EntityKind.SYMBOL:
                    valid.add(value)
            except ValueError:
                continue
        return valid


def query_code_graph(core: "RetrievalCore", settings: GraphSettings, *, mode: str, subject: str,
                     depth: int | None = None, sink_class: str | None = None, source_class: str | None = None,
                     limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
    """Run one ``query_code_graph`` request against ``core``'s accepted manifest."""
    error = request_error({"mode": mode, "subject": subject, "depth": depth, "sink_class": sink_class,
                           "source_class": source_class})
    if error:
        raise ValueError(f"schema_violation: {error}")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= min(MAX_TOOL_LIMIT,
                                                                                          core.limits.max_results):
        raise ValueError("result limit exceeds bound")
    parsed = Mode(mode)
    if parsed in DEPTH_MODES:
        cap = min(MAX_TOOL_DEPTH, settings.max_call_depth, core.limits.max_depth)
        depth = 1 if depth is None else depth
        if not 1 <= depth <= cap:
            raise ValueError(f"depth exceeds bound {cap}")
    parameters = {"mode": parsed.value, "subject": subject, "depth": depth, "sink_class": sink_class,
                  "source_class": source_class, "limit": limit, "cursor": cursor}
    request_hash = core._request_hash(QUERY_CODE_GRAPH, parameters)
    offset = core._offset(cursor, request_hash)
    query = _GraphQuery(core, settings, mode=parsed, subject=subject, depth=depth, sink_class=sink_class,
                        source_class=source_class)
    return core._execute(QUERY_CODE_GRAPH, parameters, lambda deadline: query.run(deadline, offset, limit))


__all__ = ["TOOL_RULE", "query_code_graph", "request_error"]
