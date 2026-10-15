"""Transport-independent, run-pinned retrieval semantics."""

from __future__ import annotations

from dataclasses import dataclass
import base64
from contextvars import ContextVar
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import sqlite3
import time
import uuid
from typing import TYPE_CHECKING, Any, Callable, Iterable, Mapping

from appsec_review.observability import PipelineLog
from appsec_review.retrieval.index import (
    INDEX_NAMES, MANIFEST_SCHEMA, IndexIdentity, load_verified_manifest, write_manifest,
)
from appsec_review.retrieval.interfaces import ArtifactQueryRequest
from appsec_review.retrieval.model import (
    EntityKind, LogicalIdentity, RelationKind, canonical_json, normalize_relative_path,
    sanitize_producer_data,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA, QUERY_SETS
from appsec_review.storage import RunStore, file_sha256

if TYPE_CHECKING:  # pragma: no cover - graph.contract imports retrieval.model, so it is loaded lazily
    from appsec_review.graph.contract import GraphSettings


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


class RetrievalIntegrityError(ValueError):
    """An accepted pointer, manifest, or shard failed an integrity or isolation check.

    It subclasses ``ValueError`` for existing callers; review code treats it as a framework-integrity
    failure, never as a tool gap.
    """


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
        raise RetrievalIntegrityError("accepted index pointer run isolation mismatch")
    handoff_path = (run_root / str(pointer.get("handoff_path", ""))).resolve()
    manifest_path = (run_root / str(pointer.get("manifest_path", ""))).resolve()
    if run_root not in handoff_path.parents or run_root not in manifest_path.parents:
        raise RetrievalIntegrityError("accepted index pointer escapes run")
    if file_sha256(handoff_path) != pointer.get("handoff_sha256"):
        raise RetrievalIntegrityError("accepted handoff integrity mismatch")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if handoff.get("status") != "ACCEPTED" or handoff.get("schema") != "appsec-review/job-handoff/1":
        raise RetrievalGap("index producer handoff is not accepted")
    manifest_sha = str(pointer.get("manifest_sha256", ""))
    if not _artifact_in_handoff(handoff, manifest_path.relative_to(run_root).as_posix(), manifest_sha):
        raise RetrievalIntegrityError("accepted manifest is not bound to its producer handoff")
    return manifest_path, manifest_sha


def resolve_context_manifest(context: Any) -> tuple[Path, str]:
    """Resolve the immutable retrieval input pinned when this job attempt was claimed."""

    path = getattr(context, "input_manifest_path", None)
    sha256 = getattr(context, "input_manifest_sha256", None)
    if path is None or sha256 is None:
        return resolve_accepted_manifest(Path(context.run_root))
    run_root = Path(context.run_root).resolve()
    resolved = Path(path).resolve()
    if run_root not in resolved.parents or not resolved.is_file():
        raise RetrievalIntegrityError("job input manifest escapes the application run or is unavailable")
    if file_sha256(resolved) != sha256:
        raise RetrievalIntegrityError("job input manifest changed after the attempt was claimed")
    return resolved, str(sha256)


def _accepted_handoff(run_root: Path, job_id: str, expected_sha256: str) -> tuple[Mapping[str, Any], Path]:
    attempts = run_root / "data" / "jobs" / job_id / "attempts"
    matches = []
    for path in sorted(attempts.glob("attempt_*/handoff.json")):
        if file_sha256(path) == expected_sha256:
            matches.append(path)
    if len(matches) != 1:
        raise RetrievalIntegrityError(f"expected exactly one accepted handoff for {job_id}")
    path = matches[0]
    handoff = json.loads(path.read_text(encoding="utf-8"))
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or
            handoff.get("status") != "ACCEPTED" or handoff.get("job_id") != job_id):
        raise RetrievalIntegrityError(f"invalid accepted handoff for {job_id}")
    return handoff, path


def _handoff_manifest_roots(
    run_root: Path, handoffs: Mapping[str, str], seen: frozenset[tuple[str, str]] = frozenset(),
) -> dict[tuple[str, str], Path]:
    roots: dict[tuple[str, str], Path] = {}
    for job_id, handoff_sha in sorted(handoffs.items()):
        key = (job_id, handoff_sha)
        if key in seen:
            raise RetrievalIntegrityError("accepted handoff dependency cycle")
        handoff, _ = _accepted_handoff(run_root, job_id, handoff_sha)
        manifests: dict[tuple[str, str], Path] = {}
        for output in handoff.get("outputs", {}).values():
            raw = output.get("index_manifest") if isinstance(output, Mapping) else None
            if not isinstance(raw, Mapping):
                continue
            relative, sha256 = raw.get("path"), raw.get("sha256")
            if not isinstance(relative, str) or not isinstance(sha256, str):
                raise RetrievalIntegrityError(f"invalid index manifest identity in {job_id} handoff")
            path = (run_root / relative).resolve()
            if run_root not in path.parents or not _artifact_in_handoff(handoff, relative, sha256):
                raise RetrievalIntegrityError(f"index manifest is not bound to {job_id} handoff")
            document = json.loads(path.read_text(encoding="utf-8"))
            if document.get("schema") != MANIFEST_SCHEMA:
                continue
            manifests[(relative, sha256)] = path
        if manifests:
            roots.update(manifests)
        else:
            upstream = handoff.get("upstream_handoff_sha256", {})
            if not isinstance(upstream, Mapping):
                raise RetrievalIntegrityError(f"invalid upstream handoff set for {job_id}")
            roots.update(_handoff_manifest_roots(
                run_root, {str(name): str(value) for name, value in upstream.items()}, seen | {key}))
    return roots


def _flatten_manifest(
    run_root: Path, path: Path, sha256: str,
    seen: frozenset[tuple[str, str]] = frozenset(),
    verified: dict[tuple[Path, str], Mapping[str, Any]] | None = None,
    flattened: dict[tuple[str, str], tuple[dict[tuple[str, str], Mapping[str, Any]],
                                           frozenset[tuple[str, str]]]] | None = None,
) -> tuple[dict[tuple[str, str], Mapping[str, Any]], frozenset[tuple[str, str]]]:
    """Flatten one manifest lineage; ``verified`` and ``flattened`` memoize shared ancestors."""
    verified = {} if verified is None else verified
    flattened = {} if flattened is None else flattened
    relative = path.relative_to(run_root).as_posix()
    identity = (relative, sha256)
    if identity in seen:
        raise RetrievalIntegrityError("index manifest dependency cycle")
    if identity in flattened:
        values, lineage = flattened[identity]
        return dict(values), lineage
    document, _ = load_verified_manifest(run_root, path, sha256, verified=verified)
    values: dict[tuple[str, str], Mapping[str, Any]] = {}
    lineage: set[tuple[str, str]] = {identity}
    for upstream in document.get("upstream_manifests", ()):
        upstream_path = (run_root / str(upstream.get("path", ""))).resolve()
        upstream_sha = str(upstream.get("sha256", ""))
        inherited, ancestors = _flatten_manifest(run_root, upstream_path, upstream_sha, seen | {identity},
                                                 verified, flattened)
        values.update(inherited)
        lineage.update(ancestors)
    for raw in document.get("indexes", ()):
        key = (str(raw.get("name")), str(raw.get("shard_id", "default")))
        values[key] = dict(raw)
    flattened[identity] = (values, frozenset(lineage))
    return dict(values), frozenset(lineage)


def materialize_attempt_input_manifest(
    *, run_root: Path, attempt_root: Path, run_id: str, target_snapshot: str,
    target_root: Path | None, upstream_handoffs: Mapping[str, str],
) -> tuple[Path | None, str | None]:
    """Pin and merge the exact retrieval manifests reachable from this attempt's handoffs."""

    run_root = Path(run_root).resolve()
    roots = _handoff_manifest_roots(run_root, upstream_handoffs)
    if not roots:
        return None, None
    if len(roots) == 1:
        (relative, sha256), path = next(iter(roots.items()))
        load_verified_manifest(run_root, path, sha256)
        return path, sha256
    # Upstream lineages share ancestors (every job inherits the catalog manifest, for example), so
    # one verification and flattening per manifest serves every root of this attempt.
    verified: dict[tuple[Path, str], Mapping[str, Any]] = {}
    flattened: dict[tuple[str, str], Any] = {}
    expanded = []
    for identity, path in roots.items():
        values, lineage = _flatten_manifest(run_root, path, identity[1], verified=verified, flattened=flattened)
        expanded.append((identity, values, lineage))
    merged: dict[tuple[str, str], tuple[Mapping[str, Any], tuple[str, str]]] = {}
    for root_identity, values, lineage in sorted(expanded, key=lambda item: (len(item[2]), item[0])):
        for key, value in values.items():
            prior = merged.get(key)
            if prior is None or prior[0] == value:
                merged[key] = (value, root_identity)
                continue
            prior_root = prior[1]
            prior_lineage = next(item[2] for item in expanded if item[0] == prior_root)
            if prior_root in lineage:
                merged[key] = (value, root_identity)
            elif root_identity not in prior_lineage:
                raise RetrievalIntegrityError(
                    f"parallel upstream manifests conflict for index shard {key[0]}/{key[1]}")
    destination = attempt_root / "inputs" / "retrieval-manifest.json"
    identities = [IndexIdentity(**{**value, "gaps": tuple(value.get("gaps", ()))})
                  for value, _root in merged.values()]
    write_manifest(
        destination, run_id=run_id, target_snapshot=target_snapshot,
        target_root=target_root or run_root, indexes=identities,
        upstream_manifests=tuple({"path": identity[0], "sha256": identity[1]} for identity in sorted(roots)),
    )
    sha256 = file_sha256(destination)
    load_verified_manifest(run_root, destination, sha256, verified=verified)
    return destination, sha256


class RetrievalCore:
    """Read immutable shards for exactly one accepted run and manifest set."""

    def __init__(self, runs_dir: Path, run_id: str, *, manifest_sha256: str | None = None,
                 manifest_path: Path | None = None,
                 limits: RetrievalLimits | None = None, clock: Callable[[], float] = time.monotonic,
                 graph_settings: GraphSettings | None = None):
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("invalid run id")
        self.run_root = RunStore(Path(runs_dir)).resolve(run_id)
        if graph_settings is None:
            # The run-bound jobs.job_code_graph_index.settings.graph bounds, so review cells and MCP
            # sessions use the caps the run was configured with; contract defaults when unconfigured.
            # This verifies the run-bound configuration before manifest loading consults it (for
            # the Swift policy), so a tampered configuration is a retrieval integrity failure.
            from appsec_review.graph.settings import RunConfigurationError, run_graph_settings
            try:
                graph_settings = run_graph_settings(self.run_root)
            except RunConfigurationError as exc:
                raise RetrievalIntegrityError(str(exc)) from exc
        self.graph_settings = graph_settings
        if manifest_path is None:
            manifest_path, accepted_sha = resolve_accepted_manifest(self.run_root)
        else:
            manifest_path = Path(manifest_path).resolve()
            if self.run_root not in manifest_path.parents or not manifest_path.is_file():
                raise RetrievalIntegrityError("explicit retrieval manifest is unavailable or escapes the run")
            accepted_sha = file_sha256(manifest_path)
        if manifest_sha256 is not None and not hmac.compare_digest(accepted_sha, manifest_sha256):
            raise RetrievalIntegrityError("MCP session manifest pin does not match accepted index set")
        try:
            self.manifest, self.manifest_sha256 = load_verified_manifest(self.run_root, manifest_path, accepted_sha)
        except RetrievalIntegrityError:
            raise
        except ValueError as exc:
            # Manifest, shard and run-bound configuration checks (including the Swift policy's
            # resolved-configuration hash) are framework-integrity failures, never tool gaps.
            raise RetrievalIntegrityError(str(exc)) from exc
        if self.manifest.get("run_id") != run_id:
            raise RetrievalIntegrityError("manifest run isolation mismatch")
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
            raise RetrievalIntegrityError(f"index integrity mismatch: {name}")
        uri = f"file:{path.as_posix()}?mode=ro&immutable=1"
        database = sqlite3.connect(uri, uri=True, timeout=0.1)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only=ON")
        metadata = dict(database.execute("SELECT key, value FROM metadata"))
        if (metadata.get("schema"), metadata.get("name"), metadata.get("fingerprint"),
                metadata.get("shard_id", "default")) != (
                identity["schema"], name, identity["fingerprint"], identity.get("shard_id", "default")):
            database.close()
            raise RetrievalIntegrityError(f"index metadata mismatch: {name}/{identity.get('shard_id', 'default')}")
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
        byte_gap = "response byte budget reached; trailing results were withheld (continue with the cursor)"
        while len(canonical_json(response)) > self.limits.max_response_bytes and response["results"]:
            response["results"].pop()
            response["truncated"] = True
            if byte_gap not in response["coverage_gaps"]:
                response["coverage_gaps"].append(byte_gap)
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
                        gaps.extend(f"{index_name}/{shard.get('shard_id', 'default')}: {item['gap']}"
                                    for item in database.execute(
                            "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))
                    gaps.extend(f"{index_name}/{shard.get('shard_id', 'default')}: {gap}"
                                for gap in shard.get("gaps", ()))
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

    def coverage(self, *, indexes: Iterable[str] | None = None, limit: int = 50,
                 cursor: str | None = None) -> dict[str, Any]:
        names = self._names(indexes)
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"indexes": names, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("coverage", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            results, gaps = [], ["accepted index set is empty"] if not names else []
            selected = []
            for name in names:
                self._check_deadline(deadline)
                if name not in self.indexes:
                    gaps.append(f"{name} index is unavailable")
                    continue
                selected.extend((name, shard) for shard in self.indexes[name])
            for name, shard in selected[offset:offset + limit]:
                self._check_deadline(deadline)
                with self._database(shard, deadline) as database:
                    rows = [dict(row) for row in database.execute(
                        "SELECT area, status, gap FROM coverage ORDER BY area, status, gap")]
                    count_metadata = dict(database.execute(
                        "SELECT key, value FROM metadata WHERE key IN ('entity_kind_counts', 'relation_kind_counts')"))
                    entity_kinds = (json.loads(count_metadata["entity_kind_counts"])
                                    if "entity_kind_counts" in count_metadata else None)
                    relation_kinds = (json.loads(count_metadata["relation_kind_counts"])
                                      if "relation_kind_counts" in count_metadata else None)
                shard_id = str(shard.get("shard_id", "default"))
                results.append({"identity": f"coverage:{name}:{shard_id}:{shard['sha256']}",
                                "artifact_reference": {"index": name, "shard_id": shard_id,
                                                       "sha256": shard["sha256"]},
                                "index": name, "shard_id": shard_id,
                                "producer": self._safe_payload(shard.get("producer", {})),
                                "entity_kinds": entity_kinds, "relation_kinds": relation_kinds,
                                "entity_count": sum(entity_kinds.values()) if entity_kinds is not None else None,
                                "relation_count": sum(relation_kinds.values()) if relation_kinds is not None else None,
                                "coverage": rows})
                if entity_kinds is None or relation_kinds is None:
                    gaps.append(f"{name}/{shard_id}: index kind counts unavailable")
                gaps.extend(f"{name}/{shard_id}: {row['gap']}" for row in rows if row["gap"])
                gaps.extend(f"{name}/{shard_id}: {gap}" for gap in shard.get("gaps", ()))
            return results, gaps, len(selected) > offset + limit, offset
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

    def query_codeql(
        self, *, language: str | None = None, source_language: str | None = None,
        scope: str | None = None, build_unit: str | None = None,
        rule: str | None = None, level: str | None = None, path: str | None = None,
        shard: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query accepted CodeQL observations by exact bounded facets."""
        filters = {key: value for key, value in {
            "language": language, "scope_id": scope, "build_unit_id": build_unit,
            "rule_id": rule, "producer_level": level,
        }.items() if value is not None}
        if any(not value or len(value) > 4096 for value in (*filters.values(), *(
                [source_language] if source_language is not None else []),
                *([path] if path is not None else []))):
            raise ValueError("invalid CodeQL query facet")
        if shard is not None and not re.fullmatch(r"codeql-[A-Za-z0-9_.-]{1,120}", shard):
            raise ValueError("invalid CodeQL shard")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"language": language, "source_language": source_language, "scope": scope,
                      "build_unit": build_unit, "rule": rule, "level": level, "path": path,
                      "shard": shard, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_codeql", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            candidates = [item for item in self.indexes.get("observations", ())
                          if str(item.get("shard_id", "")).startswith("codeql-")
                          and (shard is None or str(item.get("shard_id")) == shard)]
            if not candidates:
                gaps.append("accepted CodeQL observation indexes are unavailable")
            for identity in candidates:
                self._check_deadline(deadline)
                clauses, values = ["e.kind = 'tool_observation'",
                                   "json_extract(e.payload_json, '$.producer') = 'codeql'"], []
                for key, value in filters.items():
                    clauses.append("json_extract(e.payload_json, ?) = ?")
                    values.extend((f"$.{key}", value))
                if source_language is not None:
                    clauses.append("EXISTS (SELECT 1 FROM json_each(e.payload_json, '$.source_languages') "
                                   "WHERE json_each.value = ?)")
                    values.append(source_language)
                if path is not None:
                    clauses.append("l.path = ?")
                    values.append(path)
                sql = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                       "WHERE " + " AND ".join(clauses) + " ORDER BY e.identity LIMIT ?")
                values.append(offset + limit + 1)
                shard_id = str(identity.get("shard_id", "default"))
                with self._database(identity, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, "observations")
                        item["shard_id"] = shard_id
                        found.append(item)
                    gaps.extend(f"observations/{shard_id}: {row['gap']}" for row in database.execute(
                        "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))
                gaps.extend(f"observations/{shard_id}: {gap}" for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item["shard_id"], item["identity"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("query_codeql", parameters, operation)

    def query_change_context(
        self, *, scope: str | None = None, path: str | None = None, component: str | None = None,
        signal: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Return accepted change-context priority records in rank order by exact facets.

        Records order review work and are never findings; unavailable coverage is returned as gaps.
        """
        signals = ("fast_review_change_count", "stale_approval_change_count", "unapproved_mainline_change_count",
                   "off_hours_change_count", "pre_deployment_change_count", "sprawling_change_count",
                   "repeated_repair_peak", "fix_on_fix_event_count", "untested_production_change_count",
                   "lifetime_principal_author_share", "departed_dominant_owner")
        if scope is not None and scope not in {"file", "function", "component"}:
            raise ValueError("invalid change context scope")
        if signal is not None and signal not in signals:
            raise ValueError("invalid change context signal")
        if any(value is not None and (not value or len(value) > 4096) for value in (path, component)):
            raise ValueError("invalid change context facet")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"scope": scope, "path": path, "component": component, "signal": signal,
                      "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_change_context", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            candidates = [item for item in self.indexes.get("history", ())
                          if str(item.get("shard_id", "")) == "change-context"]
            if not candidates:
                gaps.append("accepted change-context index is unavailable")
            for identity in candidates:
                self._check_deadline(deadline)
                clauses, values = ["e.kind = 'change_context_signal'"], []
                for key, value in (("scope", scope), ("path", path), ("component_id", component)):
                    if value is not None:
                        clauses.append("json_extract(e.payload_json, ?) = ?")
                        values.extend((f"$.{key}", value))
                if signal is not None:
                    clauses.append("CAST(json_extract(e.payload_json, ?) AS REAL) > 0")
                    values.append(f"$.metrics.{signal}")
                sql = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE " +
                       " AND ".join(clauses) + " ORDER BY json_extract(e.payload_json, '$.scope'), "
                       "CAST(json_extract(e.payload_json, '$.rank') AS INTEGER), e.identity LIMIT ?")
                values.append(offset + limit + 1)
                with self._database(identity, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, "history")
                        item["shard_id"] = "change-context"
                        found.append(item)
                    gaps.extend(f"history/change-context: {row['area']}: {row['status']}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT area, status, gap FROM coverage WHERE status != 'complete' ORDER BY area"))
                gaps.extend(f"history/change-context: {gap}" for gap in identity.get("gaps", ()))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("query_change_context", parameters, operation)

    def query_hotspots(
        self, *, scope: str | None = None, path: str | None = None,
        min_score: float = 0.0, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Return bounded ranked priority items, with their metric and evidence payloads."""
        if scope is not None and scope not in {"file", "function"}:
            raise ValueError("invalid hotspot scope")
        if path is not None:
            path = normalize_relative_path(path)
        if isinstance(min_score, bool) or not isinstance(min_score, (int, float)) or not math.isfinite(min_score) \
                or not 0 <= min_score <= 100:
            raise ValueError("invalid hotspot minimum score")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"scope": scope, "path": path, "min_score": min_score, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_hotspots", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            candidates = self.indexes.get("priority", ())
            if not candidates:
                gaps.append("accepted priority index is unavailable")
            for shard in candidates:
                self._check_deadline(deadline)
                clauses = ["e.kind = 'priority_item'",
                           "CAST(json_extract(e.payload_json, '$.score') AS REAL) >= ?"]
                values: list[Any] = [min_score]
                for key, value in (("scope", scope), ("path", path)):
                    if value is not None:
                        clauses.append("json_extract(e.payload_json, ?) = ?")
                        values.extend((f"$.{key}", value))
                sql = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE " +
                       " AND ".join(clauses) + " ORDER BY CAST(json_extract(e.payload_json, '$.rank') AS INTEGER), "
                       "e.identity LIMIT ?")
                values.append(offset + limit + 1)
                with self._database(shard, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, "priority")
                        item["shard_id"] = shard.get("shard_id", "default")
                        found.append(item)
                    gaps.extend(f"priority/{shard['shard_id']}: {row['area']}: {row['status']}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT area, status, gap FROM coverage WHERE status != 'complete' ORDER BY area"))
                gaps.extend(f"priority/{shard['shard_id']}: {gap}" for gap in shard.get("gaps", ()))
            found.sort(key=lambda item: (int(item["payload"].get("rank", 0)), item["identity"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("query_hotspots", parameters, operation)

    def query_precomputed(
        self, *, query_set: str, subject: str | None = None, path: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read a named run-owned fact set; never compute a graph or execute a query at inference time."""
        if query_set not in QUERY_SETS:
            raise ValueError("invalid precomputed query set")
        if subject is not None:
            LogicalIdentity.parse(subject)
        if path is not None:
            path = normalize_relative_path(path)
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"query_set": query_set, "subject": subject, "path": path,
                      "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_precomputed", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            candidates = [shard for shard in self.indexes.get("precomputed", ())
                          if shard.get("producer", {}).get("query_set") == query_set]
            if not candidates:
                gaps.append(f"accepted precomputed {query_set} index is unavailable")
            for shard in candidates:
                self._check_deadline(deadline)
                clauses = ["e.kind = 'precomputed_fact'", "json_extract(e.payload_json, '$.query_set') = ?"]
                values: list[Any] = [query_set]
                if subject is not None:
                    clauses.append("json_extract(e.payload_json, '$.subject_identity') = ?")
                    values.append(subject)
                if path is not None:
                    clauses.append("(l.path = ? OR json_extract(e.payload_json, '$.subject_path') = ?)")
                    values.extend((path, path))
                sql = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE " +
                       " AND ".join(clauses) + " ORDER BY e.identity LIMIT ?")
                values.append(offset + limit + 1)
                with self._database(shard, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, "precomputed")
                        if item["payload"].get("schema") != FACT_SCHEMA:
                            gaps.append(f"precomputed/{shard['shard_id']}: unsupported fact schema")
                            continue
                        item["shard_id"] = shard.get("shard_id", "default")
                        found.append(item)
                    areas = list(database.execute("SELECT area, status, gap FROM coverage ORDER BY area"))
                    if not any(row["area"] == query_set for row in areas):
                        gaps.append(f"precomputed/{shard['shard_id']}: query-set coverage is unavailable")
                    gaps.extend(f"precomputed/{shard['shard_id']}: {row['area']}: {row['status']}: {row['gap']}"
                                for row in areas if row["status"] != "complete")
                gaps.extend(f"precomputed/{shard['shard_id']}: {gap}" for gap in shard.get("gaps", ()))
            found.sort(key=lambda item: item["identity"])
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("query_precomputed", parameters, operation)

    def query_code_graph(
        self, *, mode: str, subject: str, depth: int | None = None, sink_class: str | None = None,
        source_class: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read accepted code-graph facts by mode and exact subject; see ``retrieval/graph.py``."""
        from appsec_review.retrieval.graph import query_code_graph
        return query_code_graph(self, self.graph_settings, mode=mode, subject=subject, depth=depth,
                                sink_class=sink_class, source_class=source_class, limit=limit, cursor=cursor)

    def _lead_states(self, deadline: float) -> tuple[dict[str, Mapping[str, Any]], list[str]]:
        """Suppression and duplicate state from the accepted scanner_correlation lead facts."""
        shards = [shard for shard in self.indexes.get("precomputed", ())
                  if shard.get("producer", {}).get("query_set") == "scanner_correlation"]
        if not shards:
            return {}, ["accepted scanner_correlation lead facts are unavailable: suppression and duplicate "
                        "state is unknown"]
        states: dict[str, Mapping[str, Any]] = {}
        candidate_bound = max(1_000, self.limits.max_results * 100)
        for shard in shards:
            with self._database(shard, deadline) as database:
                for row in database.execute(
                        "SELECT payload_json FROM entities WHERE kind='precomputed_fact' "
                        "AND json_extract(payload_json, '$.fact_type') = 'lead'"):
                    self._check_deadline(deadline)
                    if len(states) >= candidate_bound:
                        return {}, ["scanner lead-state candidate bound exceeded; narrow the observation query"]
                    result = json.loads(row["payload_json"]).get("result") or {}
                    if isinstance(result.get("observation_id"), str):
                        states[result["observation_id"]] = {key: result.get(key) for key in (
                            "suppressed", "suppression_status", "suppression_ids", "duplicate_of", "duplicate_method",
                            "component_id", "flow_ids")}
        return states, []

    def query_observations(
        self, *, scanner: str | None = None, rule: str | None = None, severity: str | None = None,
        observation_class: str | None = None, suppressed: bool | None = None, duplicate: bool | None = None,
        source: str | None = None, artifact: str | None = None, path: str | None = None,
        start_line: int | None = None, end_line: int | None = None, shard: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Filter accepted observation shards by exact scanner, rule, reported severity, suppression and scope.

        Severity is normalized from the indexed payload by a versioned rule; raw scanner output is never
        read. Results are tool observations ordered by reported severity; they are never confirmed findings.
        """
        from appsec_review.retrieval.observations import (
            OBSERVATION_CLASSES, REPORTED_SEVERITIES, SEVERITY_ORDER, classify, normalize_reported_severity,
            rule_of, scanner_of,
        )
        for name, value in (("scanner", scanner), ("rule", rule)):
            if value is not None and (not isinstance(value, str) or not value or len(value) > 4096):
                raise ValueError(f"invalid observation filter: {name}")
        if severity is not None and severity not in REPORTED_SEVERITIES:
            raise ValueError("invalid normalized reported severity")
        if observation_class is not None and observation_class not in OBSERVATION_CLASSES:
            raise ValueError("invalid observation class")
        for name, value in (("suppressed", suppressed), ("duplicate", duplicate)):
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"invalid observation filter: {name}")
        if source is not None and LogicalIdentity.parse(source).kind is not EntityKind.SOURCE_FILE:
            raise ValueError("source filter requires a source_file identity")
        if artifact is not None:
            LogicalIdentity.parse(artifact)
        if path is not None:
            path = normalize_relative_path(path)
        for name, value in (("start_line", start_line), ("end_line", end_line)):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
                raise ValueError(f"invalid observation filter: {name}")
        if (start_line is not None or end_line is not None) and path is None:
            raise ValueError("a line filter requires an exact path")
        if shard is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", shard):
            raise ValueError("invalid observation shard")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"scanner": scanner, "rule": rule, "severity": severity, "observation_class": observation_class,
                      "suppressed": suppressed, "duplicate": duplicate, "source": source, "artifact": artifact,
                      "path": path, "start_line": start_line, "end_line": end_line, "shard": shard,
                      "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_observations", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[tuple[int, str, dict[str, Any]]] = []
            gaps: list[str] = []
            candidate_bound = max(1_000, self.limits.max_results * 100)
            scanned = 0
            candidates = [item for item in self.indexes.get("observations", ())
                          if shard is None or str(item.get("shard_id")) == shard]
            if not candidates:
                gaps.append("accepted observation indexes are unavailable" if shard is None
                            else f"observation shard is unavailable: {shard}")
            states, state_gaps = self._lead_states(deadline)
            gaps.extend(state_gaps)
            if (suppressed is not None or duplicate is not None) and state_gaps:
                return [], gaps + ["suppression/duplicate filters cannot be evaluated; no result is a clean answer"], \
                    False, offset
            for identity in candidates:
                self._check_deadline(deadline)
                shard_id = str(identity.get("shard_id", "default"))
                clauses, values = ["e.kind = 'tool_observation'"], []
                if path is not None:
                    clauses.append("l.path = ?")
                    values.append(path)
                if start_line is not None:
                    clauses.append("l.end_line >= ?")
                    values.append(start_line)
                if end_line is not None:
                    clauses.append("l.start_line <= ?")
                    values.append(end_line)
                for relation, target in ((RelationKind.OBSERVED_AT.value, source), (RelationKind.DERIVED_FROM.value, artifact)):
                    if target is not None:
                        clauses.append("EXISTS (SELECT 1 FROM relations r WHERE r.source_id = e.identity "
                                       "AND r.kind = ? AND r.target_id = ?)")
                        values.extend((relation, target))
                sql = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE " +
                       " AND ".join(clauses) + " ORDER BY e.identity")
                with self._database(identity, deadline) as database:
                    for row in database.execute(sql, values):
                        self._check_deadline(deadline)
                        scanned += 1
                        if scanned > candidate_bound:
                            return [], gaps + ["observation candidate bound exceeded; narrow the filters"], \
                                False, offset, True
                        payload = json.loads(row["payload_json"])
                        if scanner is not None and scanner_of(payload) != scanner:
                            continue
                        if rule is not None and rule_of(payload) != rule:
                            continue
                        reported = normalize_reported_severity(payload)
                        if severity is not None and reported["value"] != severity:
                            continue
                        kind = classify(payload)
                        if observation_class is not None and kind != observation_class:
                            continue
                        state = states.get(row["identity"])
                        if suppressed is not None and (state is None or bool(state.get("suppressed")) != suppressed):
                            continue
                        if duplicate is not None and (state is None or bool(state.get("duplicate_of")) != duplicate):
                            continue
                        item = self._entity(row, "observations")
                        item.update(shard_id=shard_id, scanner=scanner_of(payload), rule_id=rule_of(payload),
                                    observation_class=kind, reported_severity=reported,
                                    lead_state=dict(state) if state is not None else None,
                                    authority="tool observation; scanner severity orders review and is not an "
                                              "adjudicated finding severity")
                        found.append((SEVERITY_ORDER[reported["value"]], row["identity"], item))
                    gaps.extend(f"observations/{shard_id}: {row['area']}: {row['status']}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT area, status, gap FROM coverage WHERE status != 'complete' ORDER BY area"))
                gaps.extend(f"observations/{shard_id}: {gap}" for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item[0], item[1], item[2]["shard_id"]))
            page = [item[2] for item in found[offset:offset + limit]]
            return page, gaps, len(found) > offset + limit, offset
        return self._execute("query_observations", parameters, operation)

    def query_dataset_inventory(
        self, *, record_type: str | None = None, job: str | None = None, family: str | None = None,
        disposition: str | None = None, coverage_state: str | None = None, sensitivity: str | None = None,
        cell_type: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Bounded catalog of accepted datasets, the publication audit and coverage matrices."""
        allowed = {"record_type": {"dataset", "audit", "coverage_cell"},
                   "disposition": {"indexed", "artifact_only", "protected", "unavailable"},
                   "coverage_state": {"complete", "partial", "stale", "unavailable"},
                   "sensitivity": {"public", "internal", "sensitive", "secret"},
                   "cell_type": {"language", "build_unit", "producer_consumer", "input_source", "query_set",
                                 "graph_follow_up", "fts_validation"}}
        filters = {"record_type": record_type, "job_id": job, "family": family, "disposition": disposition,
                   "coverage_state": coverage_state, "sensitivity": sensitivity, "cell_type": cell_type}
        for key, value in filters.items():
            if value is None:
                continue
            name = {"job_id": "job"}.get(key, key)
            if not isinstance(value, str) or not value or len(value) > 256 or (
                    name in allowed and value not in allowed[name]):
                raise ValueError(f"invalid dataset inventory filter: {name}")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {**{("job" if key == "job_id" else key): value for key, value in filters.items()},
                      "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_dataset_inventory", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            candidates = self.indexes.get("inventory", ())
            if not candidates:
                gaps.append("accepted dataset inventory is unavailable")
            for identity in candidates:
                self._check_deadline(deadline)
                clauses, values = [], []
                for key, value in filters.items():
                    if value is not None:
                        clauses.append("json_extract(e.payload_json, ?) = ?")
                        values.extend((f"$.{key}", value))
                sql = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity"
                if clauses:
                    sql += " WHERE " + " AND ".join(clauses)
                sql += " ORDER BY e.identity LIMIT ?"
                values.append(offset + limit + 1)
                shard_id = str(identity.get("shard_id", "default"))
                with self._database(identity, deadline) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, "inventory")
                        item["shard_id"] = shard_id
                        found.append(item)
                    gaps.extend(f"inventory/{shard_id}: {row['area']}: {row['status']}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT area, status, gap FROM coverage WHERE status != 'complete' ORDER BY area"))
                gaps.extend(f"inventory/{shard_id}: {gap}" for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item["identity"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset
        return self._execute("query_dataset_inventory", parameters, operation)
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
