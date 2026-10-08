"""Transport-independent, run-pinned retrieval semantics."""

from __future__ import annotations

from dataclasses import dataclass
import base64
from contextvars import ContextVar
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time
import uuid
from typing import Any, Callable, Iterable, Mapping

from appsec_review.observability import PipelineLog
from appsec_review.retrieval.index import INDEX_NAMES, load_verified_manifest
from appsec_review.retrieval.interfaces import ArtifactQueryRequest
from appsec_review.retrieval.model import (
    EntityKind, LogicalIdentity, RelationKind, canonical_json, normalize_relative_path,
    sanitize_producer_data,
)
from appsec_review.storage import RunStore, file_sha256


RESPONSE_SCHEMA = "appsec-review/retrieval-response/1"
_RUN_ID = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{4}$")
_WORD = re.compile(r"[\w.$:/@+-]+", re.UNICODE)
_ACTIVE_MCP: ContextVar[Mapping[str, str] | None] = ContextVar("active_appsec_mcp", default=None)


@dataclass(frozen=True, slots=True)
class RetrievalLimits:
    max_results: int = 100
    max_response_bytes: int = 256 * 1024
    max_depth: int = 8
    timeout_ms: int = 2_000
    max_excerpt_bytes: int = 64 * 1024


class RetrievalGap(RuntimeError):
    """A truthful unavailability result, not evidence of an empty target."""


class ShardGroup(tuple):
    """Tuple of accepted shards with mapping compatibility for a single legacy shard."""

    def __getitem__(self, key):
        if isinstance(key, str):
            if len(self) != 1:
                raise TypeError("a logical index with multiple shards has no single mapping value")
            return tuple.__getitem__(self, 0)[key]
        return tuple.__getitem__(self, key)


def _artifact_in_handoff(handoff: Mapping[str, Any], path: str, sha256: str) -> bool:
    return any(item.get("path") == path and item.get("sha256") == sha256 for item in handoff.get("artifacts", []))


def resolve_accepted_manifest(run_root: Path) -> tuple[Path, str]:
    pointer_path = run_root / "data" / "indices" / "accepted.json"
    if not pointer_path.is_file():
        raise RetrievalGap("accepted index manifest is unavailable")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    if pointer.get("schema") != "appsec-review/accepted-index-set/1":
        raise RetrievalGap("accepted index pointer schema is unsupported")
    if pointer.get("run_id") != run_root.name:
        raise ValueError("accepted index pointer run isolation mismatch")
    handoff_path = (run_root / str(pointer.get("handoff_path", ""))).resolve()
    manifest_path = (run_root / str(pointer.get("manifest_path", ""))).resolve()
    if run_root not in handoff_path.parents or run_root not in manifest_path.parents:
        raise ValueError("accepted index pointer escapes run")
    if file_sha256(handoff_path) != pointer.get("handoff_sha256"):
        raise ValueError("accepted handoff integrity mismatch")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if handoff.get("status") != "ACCEPTED" or handoff.get("schema") != "appsec-review/job-handoff/1":
        raise RetrievalGap("index producer handoff is not accepted")
    manifest_sha = str(pointer.get("manifest_sha256", ""))
    if not _artifact_in_handoff(handoff, manifest_path.relative_to(run_root).as_posix(), manifest_sha):
        raise ValueError("accepted manifest is not bound to its producer handoff")
    return manifest_path, manifest_sha


class RetrievalCore:
    """Read immutable shards for exactly one accepted run and manifest set."""

    def __init__(self, runs_dir: Path, run_id: str, *, manifest_sha256: str | None = None,
                 limits: RetrievalLimits | None = None, clock: Callable[[], float] = time.monotonic):
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("invalid run id")
        self.run_root = RunStore(Path(runs_dir)).resolve(run_id)
        manifest_path, accepted_sha = resolve_accepted_manifest(self.run_root)
        if manifest_sha256 is not None and not hmac.compare_digest(accepted_sha, manifest_sha256):
            raise ValueError("MCP session manifest pin does not match accepted index set")
        self.manifest, self.manifest_sha256 = load_verified_manifest(self.run_root, manifest_path, accepted_sha)
        if self.manifest.get("run_id") != run_id:
            raise ValueError("manifest run isolation mismatch")
        self.run_id = run_id
        self.target_root = Path(str(self.manifest["target_root"])).resolve()
        self.limits = limits or RetrievalLimits()
        self.clock = clock
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for item in self.manifest["indexes"]:
            grouped.setdefault(str(item["name"]), []).append(item)
        self.indexes = {name: ShardGroup(sorted(items, key=lambda item: str(item.get("shard_id", "default"))))
                        for name, items in grouped.items()}
        self._cursor_key = hashlib.sha256(f"{run_id}:{self.manifest_sha256}".encode()).digest()
        self.log = PipelineLog(self.run_root)
        self.mcp_session_id = hashlib.sha256(
            f"{run_id}:{self.manifest_sha256}".encode()).hexdigest()

    def begin_mcp_invocation(self, tool: str, parameters: Mapping[str, Any]) -> tuple[object, Mapping[str, str]]:
        invocation = {"mcp_session_id": self.mcp_session_id,
                      "mcp_invocation_id": uuid.uuid4().hex,
                      "mcp_tool": tool,
                      "request_sha256": self._request_hash(tool, parameters)}
        token = _ACTIVE_MCP.set(invocation)
        self.log.write("MCP_TOOL_STARTED", run_id=self.run_id, job_id="retrieval", trigger="mcp",
                       orchestrator="retrieval", details={**invocation,
                       "manifest_sha256": self.manifest_sha256})
        return token, invocation

    def complete_mcp_invocation(self, token: object, invocation: Mapping[str, str], *,
                                response: Mapping[str, Any] | None = None,
                                error: BaseException | None = None, duration_ms: int = 0) -> None:
        details = {**invocation, "manifest_sha256": self.manifest_sha256,
                   "terminal_status": "FAILED" if error else "SUCCEEDED",
                   "error_class": type(error).__name__ if error else None,
                   "result_count": len(response.get("results", ())) if response else 0,
                   "gap_count": len(response.get("coverage_gaps", ())) if response else 0,
                   "truncated": bool(response.get("truncated")) if response else False,
                   "duration_ms": duration_ms}
        self.log.write("MCP_TOOL_COMPLETED", run_id=self.run_id, job_id="retrieval", trigger="mcp",
                       orchestrator="retrieval", details=details)
        _ACTIVE_MCP.reset(token)

    def _database(self, identity: Mapping[str, Any], deadline: float) -> sqlite3.Connection:
        name = str(identity["name"])
        if name not in INDEX_NAMES:
            raise ValueError("invalid index name")
        path = (self.run_root / identity["relative_path"]).resolve()
        if self.run_root not in path.parents or not path.is_file():
            raise ValueError(f"index is unavailable: {name}")
        if not hmac.compare_digest(file_sha256(path), str(identity["sha256"])):
            raise ValueError(f"index integrity mismatch: {name}")
        uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
        database = sqlite3.connect(uri, uri=True, timeout=0.1)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only=ON")
        metadata = dict(database.execute("SELECT key, value FROM metadata"))
        if (metadata.get("schema"), metadata.get("name"), metadata.get("fingerprint"),
                metadata.get("shard_id", "default")) != (
                identity["schema"], name, identity["fingerprint"], identity.get("shard_id", "default")):
            database.close()
            raise ValueError(f"index metadata mismatch: {name}/{identity.get('shard_id', 'default')}")
        database.set_progress_handler(lambda: 1 if self.clock() > deadline else 0, 1000)
        return database

    def _check_deadline(self, deadline: float) -> None:
        if self.clock() > deadline:
            raise sqlite3.OperationalError("interrupted")

    def _cursor(self, offset: int, request_hash: str) -> str:
        payload = canonical_json({"offset": offset, "request": request_hash})
        signature = hmac.new(self._cursor_key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    @staticmethod
    def _request_hash(tool: str, parameters: Mapping[str, Any]) -> str:
        stable = {key: value for key, value in parameters.items() if key != "cursor"}
        return hashlib.sha256(canonical_json({"tool": tool, **stable})).hexdigest()

    def _offset(self, cursor: str | None, request_hash: str) -> int:
        if cursor is None:
            return 0
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            payload, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(signature, hmac.new(self._cursor_key, payload, hashlib.sha256).digest()):
                raise ValueError
            value = json.loads(payload)
            if value.get("request") != request_hash or not isinstance(value.get("offset"), int) or value["offset"] < 0:
                raise ValueError
            return value["offset"]
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid or tampered cursor") from exc

    def _names(self, requested: Iterable[str] | None) -> tuple[str, ...]:
        names = tuple(requested or self.indexes.keys())
        if len(names) != len(set(names)):
            raise ValueError("index selection is duplicated")
        if any(name not in INDEX_NAMES for name in names):
            raise ValueError("invalid index selection")
        return tuple(sorted(names))

    @staticmethod
    def _entity(row: sqlite3.Row, index: str) -> dict[str, Any]:
        payload = RetrievalCore._safe_payload(json.loads(row["payload_json"]))
        value = {
            "identity": row["identity"], "kind": row["kind"], "native_id": row["native_id"],
            "name": row["name"], "payload": payload, "index": index,
        }
        if "path" in row.keys() and row["path"] is not None:
            value["location"] = {key: row[key] for key in (
                "path", "file_sha256", "start_byte", "end_byte", "start_line", "end_line",
                "start_column", "end_column", "mapping_method", "confidence", "ambiguous",
            )}
        else:
            value["artifact_reference"] = {"index": index, "identity": row["identity"]}
        return value

    @staticmethod
    def _safe_payload(value: Any, *, depth: int = 0) -> Any:
        """Defense in depth: never serialize protected command or raw-content fields."""
        denied = re.compile(
            r"(?i)^(argv|command(?:_line|_text)?|credentials?|environment|model(?:_output|_text)?|"
            r"raw_artifacts?|source_text|stderr|stdout|protected(?:_artifacts?|_data)?)$"
        )
        if depth > 6:
            return "<truncated>"
        if isinstance(value, Mapping):
            return {str(key)[:128]: RetrievalCore._safe_payload(child, depth=depth + 1)
                    for key, child in list(value.items())[:200]
                    if not denied.fullmatch(str(key)) and str(key) != "path"}
        if isinstance(value, (list, tuple)):
            return [RetrievalCore._safe_payload(child, depth=depth + 1) for child in list(value)[:500]]
        return sanitize_producer_data(value, depth=depth)

    def _envelope(self, *, tool: str, results: list[dict[str, Any]], gaps: Iterable[str],
                  started: float, request_hash: str, offset: int = 0, has_more: bool = False,
                  truncated: bool = False) -> dict[str, Any]:
        unique_gaps = list(dict.fromkeys(str(item) for item in gaps))[:200]
        response = {
            "schema": RESPONSE_SCHEMA, "tool": tool, "run_id": self.run_id,
            "index_manifest": {"schema": self.manifest["schema"], "sha256": self.manifest_sha256,
                               "content_sha256": self.manifest["content_sha256"]},
            "indexes": [{key: value[key] for key in ("name", "schema", "sha256", "fingerprint", "shard_id")}
                        for value in self.manifest["indexes"]],
            "results": results, "pagination": {"next_cursor": None}, "coverage_gaps": unique_gaps,
            "truncated": truncated, "duration_ms": max(0, int((self.clock() - started) * 1000)),
        }
        if has_more:
            response["pagination"]["next_cursor"] = self._cursor(offset + len(results), request_hash)
        while len(canonical_json(response)) > self.limits.max_response_bytes and response["results"]:
            response["results"].pop()
            response["truncated"] = True
            response["pagination"]["next_cursor"] = self._cursor(offset + len(response["results"]), request_hash)
        if len(canonical_json(response)) > self.limits.max_response_bytes:
            response["coverage_gaps"] = ["response metadata exceeded byte budget"]
            response["indexes"] = []
            response["truncated"] = True
        return response

    def _audit(self, tool: str, request_hash: str, filters: Mapping[str, Any], response: Mapping[str, Any]) -> None:
        invocation = _ACTIVE_MCP.get()
        event = "RETRIEVAL_SUBOP_COMPLETED" if invocation else "RETRIEVAL_QUERY"
        self.log.write(event, run_id=self.run_id, job_id="retrieval", trigger="mcp",
                       orchestrator="retrieval", details={
                            "mcp_tool": tool, "manifest_sha256": self.manifest_sha256,
                            "query_sha256": request_hash, "filters": filters,
                            "result_count": len(response["results"]), "gaps": response["coverage_gaps"],
                            "truncated": response["truncated"], "duration_ms": response["duration_ms"],
                            "parent_invocation_id": invocation.get("mcp_invocation_id") if invocation else None,
                            "mcp_session_id": invocation.get("mcp_session_id") if invocation else self.mcp_session_id,
                       })

    def _execute(self, tool: str, parameters: Mapping[str, Any], operation: Callable[[float], tuple]) -> dict[str, Any]:
        started = self.clock()
        request_hash = self._request_hash(tool, parameters)
        deadline = started + self.limits.timeout_ms / 1000
        try:
            outcome = operation(deadline)
            if len(outcome) == 5:
                results, gaps, has_more, offset, operation_truncated = outcome
            else:
                results, gaps, has_more, offset = outcome
                operation_truncated = False
            timed_out = False
        except sqlite3.OperationalError as exc:
            if "interrupted" not in str(exc).lower():
                raise
            results, gaps, has_more, offset, timed_out, operation_truncated = (
                [], ["query execution-time budget exceeded"], False, 0, True, False)
        response = self._envelope(tool=tool, results=results, gaps=gaps, started=started,
                                  request_hash=request_hash, offset=offset, has_more=has_more,
                                  truncated=timed_out or operation_truncated)
        filters = {key: value for key, value in parameters.items() if key not in {"query", "cursor"}}
        self._audit(tool, request_hash, filters, response)
        return response

    def search(self, *, query: str, indexes: Iterable[str] | None = None, kinds: Iterable[str] = (),
               limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
        tokens = _WORD.findall(query or "")[:32]
        if not tokens:
            raise ValueError("search query requires searchable terms")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        names, kind_values = self._names(indexes), tuple(kinds)
        for kind in kind_values:
            EntityKind(kind)
        expression = " AND ".join('"' + token.replace('"', '""') + '"' for token in tokens)
        parameters = {"query": query, "indexes": names, "kinds": kind_values, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("search", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[tuple[float, str, dict[str, Any]]] = []
            gaps: list[str] = ["accepted index set is empty"] if not names else []
            for name in names:
                self._check_deadline(deadline)
                if name not in self.indexes:
                    gaps.append(f"{name} index is unavailable")
                    continue
                for shard in self.indexes[name]:
                    with self._database(shard, deadline) as database:
                        sql = """SELECT e.*, l.*, bm25(search_fts) AS rank FROM search_fts
                                 JOIN entities e ON e.identity=search_fts.identity
                                 LEFT JOIN locations l ON l.entity_id=e.identity
                                 WHERE search_fts MATCH ?"""
                        values: list[Any] = [expression]
                        if kind_values:
                            sql += " AND e.kind IN (" + ",".join("?" for _ in kind_values) + ")"
                            values.extend(kind_values)
                        sql += " ORDER BY rank, e.identity LIMIT ?"
                        values.append(offset + limit + 1)
                        for row in database.execute(sql, values):
                            value = self._entity(row, name)
                            value["shard_id"] = shard.get("shard_id", "default")
                            found.append((float(row["rank"]), row["identity"], str(shard.get("shard_id", "default")), value))
                        gaps.extend(f"{name}/{shard.get('shard_id', 'default')}: {item['gap']}"
                                    for item in database.execute(
                            "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))
                    gaps.extend(f"{name}/{shard.get('shard_id', 'default')}: {gap}"
                                for gap in shard.get("gaps", ()))
            found.sort(key=lambda item: (item[0], item[1], item[2]))
            page = [item[3] for item in found[offset:offset + limit]]
            return page, gaps, len(found) > offset + limit, offset
        return self._execute("search", parameters, operation)

    def find(self, *, identity: str | None = None, kind: str | None = None, name: str | None = None,
             path: str | None = None, indexes: Iterable[str] | None = None, limit: int = 20,
             cursor: str | None = None) -> dict[str, Any]:
        if identity is None and kind is None and name is None and path is None:
            raise ValueError("find requires at least one structured filter")
        if identity is not None:
            LogicalIdentity.parse(identity)
        if kind is not None:
            EntityKind(kind)
        if path is not None:
            path = normalize_relative_path(path)
        if name is not None and (not name or len(name) > 4096):
            raise ValueError("invalid exact name")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        names = self._names(indexes)
        parameters = {"identity": identity, "kind": kind, "name": name, "path": path,
                      "indexes": names, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("find", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found, gaps = [], ["accepted index set is empty"] if not names else []
            for index_name in names:
                self._check_deadline(deadline)
                if index_name not in self.indexes:
                    gaps.append(f"{index_name} index is unavailable")
                    continue
                clauses, values = [], []
                for column, value in (("e.identity", identity), ("e.kind", kind), ("e.name", name), ("l.path", path)):
                    if value is not None:
                        clauses.append(column + "=?")
                        values.append(value)
                sql = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE " + " AND ".join(clauses)
                sql += " ORDER BY e.identity LIMIT ?"
                values.append(offset + limit + 1)
                for shard in self.indexes[index_name]:
                    with self._database(shard, deadline) as database:
                        for row in database.execute(sql, values):
                            item = self._entity(row, index_name)
                            item["shard_id"] = shard.get("shard_id", "default")
                            found.append(item)
            found.sort(key=lambda item: (item["identity"], item["index"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("find", parameters, operation)

    def read_excerpt(self, *, identity: str, context_lines: int = 2) -> dict[str, Any]:
        LogicalIdentity.parse(identity)
        if not 0 <= context_lines <= 20:
            raise ValueError("context line bound exceeded")
        parameters = {"identity": identity, "context_lines": context_lines}

        def operation(deadline: float):
            self._check_deadline(deadline)
            matches = self.find(identity=identity, limit=2)["results"]
            if not matches:
                return [], ["source identity was not found in accepted indexes"], False, 0
            match = matches[0]
            location = match.get("location")
            if location is None:
                return [], ["entity has no resolving source location"], False, 0
            source = (self.target_root / normalize_relative_path(location["path"])).resolve()
            if self.target_root not in source.parents or not source.is_file():
                return [], ["indexed source is unavailable"], False, 0
            if file_sha256(source) != location["file_sha256"]:
                return [], ["target source changed after indexing"], False, 0
            data = source.read_bytes()
            if len(data) > 16 * 1024 * 1024:
                return [], ["source exceeds excerpt verification bound"], False, 0
            try:
                lines = data.decode("utf-8").splitlines()
            except UnicodeDecodeError:
                return [], ["source excerpt is not UTF-8 text"], False, 0
            start = max(1, int(location["start_line"]) - context_lines)
            end = min(len(lines), int(location["end_line"]) + context_lines)
            excerpt = "\n".join(lines[start - 1:end])
            encoded = excerpt.encode()
            truncated = len(encoded) > self.limits.max_excerpt_bytes
            if truncated:
                excerpt = encoded[:self.limits.max_excerpt_bytes].decode("utf-8", errors="ignore")
            result = {**match, "excerpt": excerpt, "excerpt_start_line": start,
                      "excerpt_end_line": end, "excerpt_truncated": truncated}
            return [result], [], False, 0
        return self._execute("read_excerpt", parameters, operation)

    def trace(self, *, identity: str, relations: Iterable[str] = (), depth: int = 2,
              limit: int = 50) -> dict[str, Any]:
        LogicalIdentity.parse(identity)
        if not 1 <= depth <= self.limits.max_depth or not 1 <= limit <= self.limits.max_results:
            raise ValueError("trace bound exceeded")
        kinds = tuple(relations)
        for kind in kinds:
            RelationKind(kind)
        parameters = {"identity": identity, "relations": kinds, "depth": depth, "limit": limit}

        def operation(deadline: float):
            frontier, seen, results, gaps = {identity}, {identity}, [], []
            for level in range(1, depth + 1):
                self._check_deadline(deadline)
                next_frontier = set()
                for index_name in sorted(self.indexes):
                    self._check_deadline(deadline)
                    for shard in self.indexes[index_name]:
                        with self._database(shard, deadline) as database:
                            for current in sorted(frontier):
                                sql = "SELECT * FROM relations WHERE (source_id=? OR target_id=?)"
                                values: list[Any] = [current, current]
                                if kinds:
                                    sql += " AND kind IN (" + ",".join("?" for _ in kinds) + ")"
                                    values.extend(kinds)
                                sql += " ORDER BY relation_id LIMIT ?"
                                values.append(limit + 1)
                                for row in database.execute(sql, values):
                                    value = dict(row)
                                    value["index"] = index_name
                                    value["shard_id"] = shard.get("shard_id", "default")
                                    value["payload"] = self._safe_payload(json.loads(value.pop("payload_json")))
                                    value["depth"] = level
                                    results.append(value)
                                    other = row["target_id"] if row["source_id"] == current else row["source_id"]
                                    if other not in seen:
                                        seen.add(other)
                                        next_frontier.add(other)
                                    if not row["exact"]:
                                        gaps.append("trace includes an explicitly ambiguous relationship")
                                    if len(results) > limit:
                                        return results[:limit], gaps + ["trace result bound reached"], False, 0, True
                frontier = next_frontier
                if not frontier:
                    break
            return results, gaps, False, 0, False
        return self._execute("trace", parameters, operation)

    def resolve_evidence(self, *, identity: str, limit: int = 50) -> dict[str, Any]:
        parsed = LogicalIdentity.parse(identity)
        if parsed.kind not in {EntityKind.TOOL_OBSERVATION, EntityKind.EVIDENCE_ARTIFACT, EntityKind.FINDING_PACKAGE}:
            raise ValueError("resolve_evidence requires an evidence-bearing identity")
        entity = self.find(identity=identity, limit=1)["results"]
        trace = self.trace(identity=identity, relations=(RelationKind.OBSERVED_AT, RelationKind.DERIVED_FROM,
                           RelationKind.SUPPORTS, RelationKind.CONTRADICTS), depth=2, limit=limit)
        parameters = {"identity": identity, "limit": limit}
        return self._execute("resolve_evidence", parameters, lambda deadline: (
            [{"entity": entity[0] if entity else None, "relationships": trace["results"]}],
            ([] if entity else ["evidence identity was not found"]) + trace["coverage_gaps"], False, 0,
        ))

    def coverage(self, *, indexes: Iterable[str] | None = None) -> dict[str, Any]:
        names = self._names(indexes)
        parameters = {"indexes": names}

        def operation(deadline: float):
            results, gaps = [], ["accepted index set is empty"] if not names else []
            for name in names:
                self._check_deadline(deadline)
                if name not in self.indexes:
                    gaps.append(f"{name} index is unavailable")
                    continue
                for shard in self.indexes[name]:
                    with self._database(shard, deadline) as database:
                        rows = [dict(row) for row in database.execute(
                            "SELECT area, status, gap FROM coverage ORDER BY area, status, gap")]
                    shard_id = str(shard.get("shard_id", "default"))
                    results.append({"identity": f"coverage:{name}:{shard_id}:{shard['sha256']}",
                                    "artifact_reference": {"index": name, "shard_id": shard_id,
                                                           "sha256": shard["sha256"]},
                                    "index": name, "shard_id": shard_id, "coverage": rows})
                    gaps.extend(f"{name}/{shard_id}: {row['gap']}" for row in rows if row["gap"])
                    gaps.extend(f"{name}/{shard_id}: {gap}" for gap in shard.get("gaps", ()))
            return results, gaps, False, 0
        return self._execute("coverage", parameters, operation)

    def query_artifacts(
        self, request: ArtifactQueryRequest | None = None, *,
        artifact_identity: str | None = None, sha256: str | None = None,
        kind: str | None = None, format: str | None = None,
        language: str | None = None, runtime: str | None = None,
        platform: str | None = None, architecture: str | None = None,
        build_unit: str | None = None, project: str | None = None,
        component: str | None = None, producing_build_action: str | None = None,
        package: str | None = None, purl: str | None = None,
        scanner: str | None = None, tool: str | None = None,
        coverage_status: str | None = None, shard: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query accepted produced artifacts and their bounded indexed evidence by exact facets."""
        if request is not None:
            supplied = any(value is not None for value in (
                artifact_identity, sha256, kind, format, language, runtime, platform, architecture,
                build_unit, project, component, producing_build_action, package, purl, scanner,
                tool, coverage_status, shard, cursor)) or limit != 20
            if supplied:
                raise ValueError("artifact request object cannot be combined with keyword filters")
            return self.query_artifacts(**request.filters, limit=request.limit, cursor=request.cursor)
        request = ArtifactQueryRequest(
            artifact_identity=artifact_identity, sha256=sha256, kind=kind, format=format,
            language=language, runtime=runtime, platform=platform, architecture=architecture,
            build_unit=build_unit, project=project, component=component,
            producing_build_action=producing_build_action, package=package, purl=purl,
            scanner=scanner, tool=tool, coverage_status=coverage_status, shard=shard,
            limit=limit, cursor=cursor,
        )
        if artifact_identity is not None:
            LogicalIdentity.parse(artifact_identity)
        if sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("artifact sha256 must be lowercase hexadecimal")
        if kind is not None:
            EntityKind(kind)
        if producing_build_action is not None:
            parsed_action = LogicalIdentity.parse(producing_build_action)
            if parsed_action.kind is not EntityKind.BUILD_ACTION:
                raise ValueError("producing build action requires a build_action identity")
        if coverage_status is not None and coverage_status not in {
                "complete", "partial", "unavailable", "stale"}:
            raise ValueError("invalid artifact coverage status")
        if shard is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", shard):
            raise ValueError("invalid artifact shard")

        parameters = {**request.filters, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_artifacts", parameters)
        offset = self._offset(cursor, request_hash)
        json_paths: dict[str, tuple[str, ...]] = {
            "sha256": ("$.sha256", "$.artifact.sha256"),
            "format": ("$.format", "$.kind", "$.classification.format"),
            "language": ("$.language", "$.producer_family", "$.classification.language"),
            "runtime": ("$.runtime", "$.classification.runtime"),
            "platform": ("$.platform", "$.classification.platform"),
            "architecture": ("$.architecture", "$.arch", "$.classification.architecture"),
            "build_unit": ("$.build_unit_id", "$.artifact.build_unit_id"),
            "project": ("$.project", "$.project_id", "$.artifact.project"),
            "component": ("$.component", "$.component_id", "$.artifact.component"),
            "package": ("$.package", "$.package_id", "$.parent_artifact", "$.artifact.package"),
            "purl": ("$.purl", "$.package_purl", "$.artifact.purl"),
            "scanner": ("$.scanner_identity", "$.tool_identity.scanner", "$.tool_identity.id"),
            "tool": ("$.tool", "$.tool_identity.tool", "$.tool_identity.name", "$.tool_identity.id"),
        }

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            produced_ids: set[str] | None = None
            if producing_build_action is not None:
                produced_ids = set()
                for relation_index in sorted(self.indexes):
                    for relation_shard in self.indexes[relation_index]:
                        self._check_deadline(deadline)
                        with self._database(relation_shard, deadline) as database:
                            produced_ids.update(str(row[0]) for row in database.execute(
                                "SELECT source_id FROM relations WHERE kind=? AND target_id=? "
                                "ORDER BY source_id",
                                (RelationKind.GENERATED_FROM.value, producing_build_action)))
            candidates = [
                (index_name, identity) for index_name in ("artifacts", "observations", "evidence")
                for identity in self.indexes.get(index_name, ())
                if shard is None or str(identity.get("shard_id", "default")) == shard
            ]
            if "artifacts" not in self.indexes:
                gaps.append("artifacts index is unavailable")
            if (scanner is not None or tool is not None) and "observations" not in self.indexes:
                gaps.append("artifact scanner observation indexes are unavailable")
            if shard is not None and not candidates:
                gaps.append(f"artifact shard is unavailable: {shard}")
            for index_name, identity in candidates:
                self._check_deadline(deadline)
                clauses: list[str] = []
                values: list[Any] = []
                if artifact_identity is not None:
                    clauses.append("e.identity=?")
                    values.append(artifact_identity)
                if kind is not None:
                    clauses.append("e.kind=?")
                    values.append(kind)
                for filter_name, paths in json_paths.items():
                    expected = request.filters.get(filter_name)
                    if expected is None:
                        continue
                    clauses.append("(" + " OR ".join(
                        "json_extract(e.payload_json, ?) = ?" for _ in paths) + ")")
                    for path in paths:
                        values.extend((path, expected))
                if produced_ids is not None:
                    if not produced_ids:
                        continue
                    clauses.append("e.identity IN (" + ",".join("?" for _ in produced_ids) + ")")
                    values.extend(sorted(produced_ids))
                if coverage_status is not None:
                    clauses.append("EXISTS (SELECT 1 FROM coverage c WHERE c.status=?)")
                    values.append(coverage_status)
                sql = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity"
                if clauses:
                    sql += " WHERE " + " AND ".join(clauses)
                sql += " ORDER BY e.identity LIMIT ?"
                values.append(offset + limit + 1)
                with self._database(identity, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, index_name)
                        item["shard_id"] = str(identity.get("shard_id", "default"))
                        item["index_identity"] = {key: identity[key] for key in
                            ("name", "schema", "sha256", "fingerprint", "shard_id")}
                        found.append(item)
                    gaps.extend(f"{index_name}/{identity.get('shard_id', 'default')}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))
                gaps.extend(f"{index_name}/{identity.get('shard_id', 'default')}: {gap}"
                            for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item["identity"], item["index"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset

        return self._execute("query_artifacts", parameters, operation)

    def query_ci_configuration(
        self, *, provider: str | None = None, pipeline: str | None = None,
        workflow: str | None = None, stage: str | None = None, job: str | None = None,
        step: str | None = None, tool: str | None = None, rule: str | None = None,
        category: str | None = None, canonical_finding: str | None = None,
        shard: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query accepted CI observation/finding shards by exact normalized facets."""
        filters = {key: value for key, value in {
            "provider": provider, "pipeline": pipeline, "workflow": workflow, "stage": stage,
            "job": job, "step": step, "tool_id": tool, "native_rule_id": rule,
            "category": category, "finding_id": canonical_finding,
        }.items() if value is not None}
        if any(not value or len(value) > 4096 for value in filters.values()):
            raise ValueError("invalid CI query facet")
        if shard is not None and (not shard or len(shard) > 128):
            raise ValueError("invalid CI shard")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"provider": provider, "pipeline": pipeline, "workflow": workflow,
                      "stage": stage, "job": job, "step": step, "tool": tool, "rule": rule,
                      "category": category, "canonical_finding": canonical_finding,
                      "shard": shard, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_ci_configuration", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            candidates = [
                (name, item) for name in ("observations", "evidence")
                for item in self.indexes.get(name, ())
                if str(item.get("shard_id", "")).startswith("ci_")
                and (shard is None or str(item.get("shard_id")) == shard)
            ]
            if not candidates:
                gaps.append("accepted CI configuration indexes are unavailable")
            for index_name, identity in candidates:
                self._check_deadline(deadline)
                clauses = []
                values: list[Any] = []
                for key, value in filters.items():
                    clauses.append("json_extract(e.payload_json, ?) = ?")
                    values.extend((f"$.{key}", value))
                sql = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity"
                if clauses:
                    sql += " WHERE " + " AND ".join(clauses)
                sql += " ORDER BY e.identity LIMIT ?"
                values.append(offset + limit + 1)
                with self._database(identity, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, index_name)
                        item["shard_id"] = identity.get("shard_id", "default")
                        found.append(item)
                    gaps.extend(f"{index_name}/{identity.get('shard_id')}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))
                gaps.extend(f"{index_name}/{identity.get('shard_id')}: {gap}"
                            for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item["identity"], item["index"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("query_ci_configuration", parameters, operation)

    def query_build_security(
        self, *, project: str | None = None, build_root: str | None = None,
        build_action: str | None = None, configuration: str | None = None,
        compile_unit: str | None = None, linked_artifact: str | None = None,
        producer: str | None = None, shard: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query the immutable build-security family without scanning target or run trees."""
        filters = {key: value for key, value in {
            "project": project, "build_root": build_root, "build_action": build_action,
            "configuration": configuration, "compile_unit": compile_unit,
            "linked_artifact": linked_artifact, "producer": producer, "shard": shard,
        }.items() if value is not None}
        if any(not isinstance(value, str) or not value or len(value) > 4096 for value in filters.values()):
            raise ValueError("build-security scope values must be bounded non-empty strings")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {**filters, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_build_security", parameters)
        offset = self._offset(cursor, request_hash)

        def matches(payload: Mapping[str, Any], shard_id: str) -> bool:
            aliases = {
                "project": payload.get("project"), "build_root": payload.get("build_root"),
                "build_action": payload.get("build_action_id"),
                "configuration": payload.get("configuration"),
                "compile_unit": payload.get("compile_unit_id") or payload.get("compile_unit"),
                "linked_artifact": (payload.get("linked_artifact") or payload.get("artifact_id") or
                                    payload.get("linked_artifact_ids")),
                "shard": shard_id,
            }
            raw_producer = payload.get("producer")
            if isinstance(raw_producer, Mapping):
                aliases["producer"] = raw_producer.get("job") or raw_producer.get("tool")
            else:
                aliases["producer"] = raw_producer
            for key, expected in filters.items():
                actual = aliases.get(key)
                if isinstance(actual, (list, tuple, set)):
                    if expected not in {str(item) for item in actual}:
                        return False
                elif str(actual) != expected:
                    return False
            return True

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            if "build_security" not in self.indexes:
                return [], ["build_security index is unavailable"], False, offset
            for identity in self.indexes["build_security"]:
                self._check_deadline(deadline)
                shard_id = str(identity.get("shard_id", "default"))
                if shard is not None and shard_id != shard:
                    continue
                with self._database(identity, deadline) as database:
                    rows = database.execute(
                        "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                        "ORDER BY e.identity"
                    )
                    for row in rows:
                        payload = json.loads(row["payload_json"])
                        if matches(payload, shard_id):
                            item = self._entity(row, "build_security")
                            item["shard_id"] = shard_id
                            found.append(item)
                    gaps.extend(f"build_security/{shard_id}: {row['gap']}" for row in database.execute(
                        "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))
                gaps.extend(f"build_security/{shard_id}: {gap}" for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item["shard_id"], item["identity"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset

        return self._execute("query_build_security", parameters, operation)
