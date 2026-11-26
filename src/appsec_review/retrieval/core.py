"""Transport-independent, run-pinned retrieval semantics."""

from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass, field, replace
import base64
from contextvars import ContextVar, Token
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import sqlite3
from threading import RLock
from types import MappingProxyType
import time
import uuid
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Mapping, Sequence

from appsec_review.interchange import decode_handoff
from appsec_review.observability import PipelineLog
from appsec_review.observability.spans import count_work
from appsec_review.retrieval._query_work import _QUERY, _QueryWork, connect_shard
from appsec_review.retrieval.index import (
    INDEX_NAMES, MANIFEST_SCHEMA, IndexIdentity, IndexSelection, SelectedShardFacts, load_verified_manifest, write_manifest,
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
_CALLER: ContextVar[Mapping[str, Any]] = ContextVar("appsec_retrieval_caller", default={})


@contextmanager
def retrieval_caller(*, job_id: str, caller_kind: str, cell_id: str | None = None,
                     role: str | None = None, turn: int | None = None, if_unset: bool = False) -> Iterator[None]:
    """Application-only audit context; omitted cell coordinates inherit the enclosing coordinates."""
    current = _CALLER.get()
    if if_unset and (current or _ACTIVE_MCP.get() is not None):
        yield
        return
    coordinates = {key: value for key, value in (("cell_id", cell_id), ("role", role), ("turn", turn))
                   if value is not None}
    token = _CALLER.set({**current, **coordinates, "job_id": job_id, "caller_kind": caller_kind})
    try:
        yield
    finally:
        _CALLER.reset(token)


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


class _IndexGroups(dict[str, ShardGroup]):
    """Observe the full candidate group at selection, before routing, producer filters or paging."""

    def __getitem__(self, name):
        group = super().__getitem__(name)
        work = _QUERY.get()
        if work is not None and work.indexes == self:
            work.consider(name)
        return group

    def get(self, name, default=None):
        return self[name] if name in self else default


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
    relative = handoff_path.relative_to(run_root).parts
    if len(relative) != 6 or relative[:2] != ("data", "jobs") or relative[3] != "attempts":
        raise RetrievalIntegrityError("accepted handoff producer path is invalid")
    count_work("handoff_validations")
    try:
        handoff = decode_handoff(json.loads(handoff_path.read_text(encoding="utf-8")),
                                 run_id=run_root.name, job_id=relative[2])
    except ValueError as exc:
        raise RetrievalIntegrityError("index producer handoff is not accepted") from exc
    manifest_sha = str(pointer.get("manifest_sha256", ""))
    if not _artifact_in_handoff(handoff, manifest_path.relative_to(run_root).as_posix(), manifest_sha):
        raise RetrievalIntegrityError("accepted manifest is not bound to its producer handoff")
    from appsec_review.storage.shared import verify_handoff, consume_handoff
    verify_handoff(run_root, handoff)
    consume_handoff(run_root, handoff)
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
    from appsec_review.storage.shared import safe_path
    if not re.fullmatch(r"[a-z][a-z0-9_]*", job_id):
        raise RetrievalIntegrityError("invalid claimed upstream job identity")
    attempts = safe_path(run_root, f"data/jobs/{job_id}/attempts")
    matches = []
    for path in sorted(attempts.glob("attempt_*/handoff.json")):
        path = safe_path(run_root, path.relative_to(run_root).as_posix())
        if file_sha256(path) == expected_sha256:
            matches.append(path)
    if len(matches) != 1:
        raise RetrievalIntegrityError(f"expected exactly one accepted handoff for {job_id}")
    path = matches[0]
    count_work("handoff_validations")
    try:
        handoff = decode_handoff(json.loads(path.read_text(encoding="utf-8")),
                                 run_id=run_root.name, job_id=job_id)
    except ValueError as exc:
        raise RetrievalIntegrityError(f"invalid accepted handoff for {job_id}") from exc
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
    evidence_target_snapshot: str | None = None,
) -> tuple[Path | None, str | None]:
    """Pin and merge the exact retrieval manifests reachable from this attempt's handoffs."""

    run_root = Path(run_root).resolve()
    roots = _handoff_manifest_roots(run_root, upstream_handoffs)
    if not roots:
        return None, None
    verified: dict[tuple[Path, str], Mapping[str, Any]] = {}
    if evidence_target_snapshot is not None:
        for (_relative, digest), path in roots.items():
            document, _ = load_verified_manifest(run_root, path, digest, verified=verified)
            if (document.get("run_id") != run_id
                    or document.get("target_snapshot") != evidence_target_snapshot):
                raise RetrievalIntegrityError("upstream manifest differs from authenticated evidence binding")
        target_snapshot = evidence_target_snapshot
    if len(roots) == 1:
        (relative, sha256), path = next(iter(roots.items()))
        load_verified_manifest(run_root, path, sha256, verified=verified)
        return path, sha256
    # Upstream lineages share ancestors (every job inherits the catalog manifest, for example), so
    # one verification and flattening per manifest serves every root of this attempt.
    flattened: dict[tuple[str, str], Any] = {}
    if target_snapshot == "none":
        # A job that does not read the target has no snapshot of its own (the launch binds "none"). The
        # composed manifest carries the snapshot its upstream manifests agree on; they must agree.
        snapshots = {str(load_verified_manifest(run_root, path, identity[1], verified=verified)[0]
                         .get("target_snapshot")) for identity, path in roots.items()}
        if len(snapshots) != 1:
            raise RetrievalIntegrityError(
                "upstream manifests disagree on the target snapshot: " + ", ".join(sorted(snapshots)))
        target_snapshot = snapshots.pop()
    expanded = []
    for identity, path in roots.items():
        values, lineage = _flatten_manifest(run_root, path, identity[1], verified=verified, flattened=flattened)
        expanded.append((identity, values, lineage))
    maximal = [item for item in expanded if not any(
        item[0] in other[2] for other in expanded if other[0] != item[0])]
    if len(maximal) == 1:
        identity = maximal[0][0]
        document, _ = load_verified_manifest(run_root, roots[identity], identity[1], verified=verified)
        direct = {(str(item["name"]), str(item.get("shard_id", "default"))): item
                  for item in document["indexes"]}
        if direct == maximal[0][1]:
            return roots[identity], identity[1]
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


# A RETRIEVAL_QUERY audit record samples this many coverage gaps, each cut to this many characters.
AUDIT_GAP_SAMPLE = 5
AUDIT_GAP_CHARS = 160


@dataclass(frozen=True, slots=True)
class _ShardSnapshot:
    # No authority, response dictionaries, or open handles are retained.
    stamp: tuple[int, ...]
    metadata: tuple[tuple[str, str], ...]
    coverage: tuple[tuple[str, str, str | None], ...]
    selected: Mapping[bytes, SelectedShardFacts] | None = None
    kind_counts: tuple[tuple[str, int], ...] | None = None
    projection_counts: tuple[tuple[str, int], ...] = ()

    def gaps(self, shard: Mapping[str, Any], *, incomplete_only: bool = False) -> list[str]:
        return list(dict.fromkeys([
            *(gap for _, status, gap in self.coverage
              if gap is not None and (not incomplete_only or status != "complete")),
            *shard.get("gaps", ()),
        ]))


@dataclass(slots=True)
class _ShardCache:
    lock: RLock = field(default_factory=RLock)
    snapshot: _ShardSnapshot | None = None


@dataclass(slots=True)
class _IndexRoutes:
    lock: RLock = field(default_factory=RLock)
    by_identity: Mapping[str, tuple[tuple[str, str, str], ...]] | None = None


def _shard_key(shard: Mapping[str, Any]) -> tuple[str, str, str]:
    return shard["name"], shard.get("shard_id", "default"), shard["sha256"]


def _file_stamp(path: Path) -> tuple[int, ...]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _projection_counts(database: sqlite3.Connection, shard: Mapping[str, Any]) -> tuple[tuple[str, int], ...]:
    # Count queryable rows, not generic AST or inventory entities from a different producer.
    from .syntax_contract import CFG_SCHEMA, SCHEMA as SYNTAX_SCHEMA

    name = shard["name"]
    if name == "analysis" and shard.get("producer", {}).get("job") == "job_tree_sitter_ast":
        cfg, syntax = database.execute(
            "SELECT count(*) FILTER (WHERE json_extract(e.payload_json, '$.cfg.schema')=?), "
            "count(*) FILTER (WHERE json_extract(e.payload_json, '$.syntax.schema')=? "
            "AND json_type(e.payload_json, '$.syntax.source_identity')='text') "
            "FROM entities e JOIN locations l ON e.identity=l.entity_id WHERE e.kind='ast_node'",
            (CFG_SCHEMA, SYNTAX_SCHEMA)).fetchone()
        return (("cfg_function", cfg), ("syntax", syntax))
    if name == "inventory":
        count, = database.execute(
            "SELECT count(*) FROM entities WHERE json_extract(payload_json, '$.job_id')='job_sanitizer_build' "
            "AND json_extract(payload_json, '$.record_type')='sanitizer_readiness'").fetchone()
        return (("sanitizer_readiness", count),)
    return ()


class RetrievalCore:
    """Read immutable shards for exactly one accepted run and manifest set."""

    def __init__(self, runs_dir: Path, run_id: str, *, manifest_sha256: str | None = None,
                 manifest_path: Path | None = None,
                 limits: RetrievalLimits | None = None, clock: Callable[[], float] = time.monotonic,
                 graph_settings: GraphSettings | None = None, log: PipelineLog | None = None,
                 shard_filter: Callable[[Mapping[str, Any]], bool] | None = None,
                 selection: IndexSelection | None = None):
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("invalid run id")
        if selection is not None and (manifest_path is None or manifest_sha256 is None):
            raise RetrievalIntegrityError("selected source views require an explicit manifest path and pin")
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
        from appsec_review.storage.validation import validation_scope
        with validation_scope(self.run_root):
            if manifest_path is None:
                manifest_path, accepted_sha = resolve_accepted_manifest(self.run_root)
            else:
                manifest_path = (Path(manifest_path).absolute() if selection is not None
                                 else Path(manifest_path).resolve())
                if self.run_root not in manifest_path.parents or not manifest_path.is_file():
                    raise RetrievalIntegrityError("explicit retrieval manifest is unavailable or escapes the run")
                accepted_sha = file_sha256(manifest_path)
            if manifest_sha256 is not None and not hmac.compare_digest(accepted_sha, manifest_sha256):
                raise RetrievalIntegrityError("MCP session manifest pin does not match accepted index set")
            try:
                self.manifest, self.manifest_sha256 = load_verified_manifest(
                    self.run_root, manifest_path, accepted_sha, selection=selection)
            except RetrievalIntegrityError:
                raise
            except ValueError as exc:
                # Invalid evidence and configuration remain framework-integrity failures, never tool gaps.
                raise RetrievalIntegrityError(str(exc)) from exc
        if self.manifest.get("run_id") != run_id:
            raise RetrievalIntegrityError("manifest run isolation mismatch")
        self.run_id = run_id
        self.target_root = Path(str(self.manifest["target_root"])).resolve()
        self.limits = limits or RetrievalLimits()
        self.clock = clock
        self.selection = selection
        self.view_identity = (selection.view_identity(self.manifest_sha256)
                              if selection is not None else self.manifest_sha256)
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for item in self.manifest["indexes"]:
            if selection is not None and not selection.includes(item):
                continue
            if shard_filter is not None and not shard_filter(item):
                continue
            grouped.setdefault(str(item["name"]), []).append(item)
        self.indexes = _IndexGroups({name: ShardGroup(sorted(items, key=lambda item: str(item.get("shard_id", "default"))))
                        for name, items in grouped.items()})
        self._routes = {name: _IndexRoutes() for name in self.indexes}
        self._shard_cache = {_shard_key(shard): _ShardCache() for group in self.indexes.values() for shard in group}
        view_identity = f"{run_id}:{self.view_identity}"
        if shard_filter is not None:
            view_identity += ":" + hashlib.sha256(canonical_json([
                (name, row.get("shard_id", "default"), row["sha256"])
                for name, rows in sorted(self.indexes.items()) for row in rows])).hexdigest()
        self._cursor_key = hashlib.sha256(view_identity.encode()).digest()
        # Public receipt for this exact run, manifest and shard selection; never expose the cursor MAC key.
        self.read_view_sha256 = hashlib.sha256(("review-read-view\0" + view_identity).encode()).hexdigest()
        self.log = log if log is not None else PipelineLog(self.run_root)
        self.mcp_session_id = hashlib.sha256(
            view_identity.encode()).hexdigest()

    def begin_mcp_invocation(self, tool: str, parameters: Mapping[str, Any]) -> tuple[tuple[Token, Token], Mapping[str, str]]:
        invocation = {"mcp_session_id": self.mcp_session_id,
                      "mcp_invocation_id": uuid.uuid4().hex,
                      "mcp_tool": tool,
                      "request_sha256": self._request_hash(tool, parameters)}
        self.log.write("MCP_TOOL_STARTED", run_id=self.run_id, job_id="retrieval", trigger="mcp",
                       orchestrator="retrieval", details={**invocation,
                       "manifest_sha256": self.manifest_sha256})
        work = _QueryWork(tool, invocation["request_sha256"], self.clock(), self.indexes)
        return (_ACTIVE_MCP.set(invocation), _QUERY.set(work)), invocation

    def complete_mcp_invocation(self, token: tuple[Token, Token], invocation: Mapping[str, str], *,
                                response: Mapping[str, Any] | None = None,
                                error: BaseException | None = None, duration_ms: int = 0) -> None:
        invocation_token, work_token = token
        work = _QUERY.get()
        assert work is not None
        details = {**invocation, **work.metrics(), "manifest_sha256": self.manifest_sha256,
                   "terminal_status": "FAILED" if error else "SUCCEEDED",
                   "error_class": type(error).__name__ if error else None,
                   "result_count": len(response.get("results", ())) if response else 0,
                   "gap_count": len(response.get("coverage_gaps", ())) if response else 0,
                   "truncated": bool(response.get("truncated")) if response else False,
                   "gaps_truncated": bool(response and response.get("gaps_truncated")),
                   "duration_ms": duration_ms}
        try:
            self.log.write("MCP_TOOL_COMPLETED", run_id=self.run_id, job_id="retrieval", trigger="mcp",
                           orchestrator="retrieval", details=details)
        finally:
            _QUERY.reset(work_token)
            _ACTIVE_MCP.reset(invocation_token)
            if enclosing := _QUERY.get():
                enclosing.include(work)

    def _database(self, identity: Mapping[str, Any], deadline: float, *, capture=None) -> sqlite3.Connection:
        work = _QUERY.get()
        if work is not None and work.indexes == self.indexes:
            # A caller may already have a descriptor (e.g. a verified citation).
            work.consider(identity["name"])
        if self.selection is not None:
            from appsec_review.retrieval.index import open_selected_shard
            try:
                database = open_selected_shard(self.run_root, identity, selection=self.selection,
                                               manifest=self.manifest, capture=capture)
            except ValueError as exc:
                raise RetrievalIntegrityError(str(exc)) from exc
            try:
                database.set_progress_handler(lambda: 1 if self.clock() > deadline else 0, 1000)
            except BaseException:
                database.close()
                raise
            return database
        return self._verified_database(identity, deadline)

    def _verified_path(self, identity: Mapping[str, Any]) -> Path:
        from appsec_review.runtime.inputs import observe_shard
        observe_shard(self.run_root, identity)
        from appsec_review.storage.shared import safe_path
        from appsec_review.storage.validation import verified_digest

        name = str(identity["name"])
        if name not in INDEX_NAMES:
            raise ValueError("invalid index name")
        path = safe_path(self.run_root, identity["relative_path"])
        if not path.is_file():
            raise ValueError(f"index is unavailable: {name}")
        try:
            verified_digest(self.run_root, path, str(identity["sha256"]))
        except ValueError as exc:
            raise RetrievalIntegrityError(f"index integrity mismatch: {name}") from exc
        return path

    def _verified_database(self, identity: Mapping[str, Any], deadline: float) -> sqlite3.Connection:
        path = self._verified_path(identity)
        name = identity["name"]
        uri = f"{path.as_uri()}?mode=ro&immutable=1"
        database = connect_shard(uri, timeout=0.1)
        try:
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA query_only=ON")
            cache = self._shard_cache.get(_shard_key(identity))
            snapshot = cache.snapshot if cache is not None else None
            metadata = dict(snapshot.metadata if snapshot is not None and snapshot.stamp == _file_stamp(path)
                            else database.execute("SELECT key, value FROM metadata"))
            if (metadata.get("schema"), metadata.get("name"), metadata.get("fingerprint"),
                    metadata.get("shard_id", "default")) != (
                    identity["schema"], name, identity["fingerprint"], identity.get("shard_id", "default")):
                raise RetrievalIntegrityError(f"index metadata mismatch: {name}/{identity.get('shard_id', 'default')}")
            database.set_progress_handler(lambda: 1 if self.clock() > deadline else 0, 1000)
        except BaseException:
            database.close()
            raise
        return database

    @contextmanager
    def _routed_read(self, shard: Mapping[str, Any], deadline: float, *,
                     read_rows: bool = False, counts: bool = False
                     ) -> Iterator[tuple[_ShardSnapshot, sqlite3.Connection | None]]:
        """Consult this shard's facts under *this* caller's grants, including for negatives."""
        from appsec_review.storage.shared import safe_path

        key = _shard_key(shard)
        cache = self._shard_cache[key]
        with ExitStack() as stack:
            if not cache.lock.acquire(timeout=max(0, deadline - self.clock())):
                raise sqlite3.OperationalError("interrupted")
            try:
                self._check_deadline(deadline)
                database = None
                snapshot = cache.snapshot
                build_counts = counts and (snapshot is None or snapshot.kind_counts is None)
                work = _QUERY.get()
                if work is not None:
                    if snapshot is None or build_counts:
                        work.snapshot_cache_misses += 1
                    else:
                        work.snapshot_cache_hits += 1
                needs_database = snapshot is None or build_counts or read_rows
                captured = {}
                if self.selection is not None:
                    if snapshot is None:
                        database = stack.enter_context(closing(self._database(shard, deadline, capture=captured)))
                    elif needs_database:
                        database = stack.enter_context(closing(self._database(shard, deadline)))
                    else:
                        from .index import _preflight_selected_shard
                        assert snapshot.selected is not None
                        try:
                            _preflight_selected_shard(self.run_root, shard, selection=self.selection,
                                                     manifest=self.manifest, facts=snapshot.selected)
                        except ValueError as exc:
                            raise RetrievalIntegrityError(str(exc)) from exc
                path = safe_path(self.run_root, shard["relative_path"])
                try:
                    before = _file_stamp(path)
                except OSError as exc:
                    raise RetrievalIntegrityError(f"index is unavailable: {key[0]}/{key[1]}") from exc
                # verified_digest can reuse a digest/admission in an ambient validation scope.
                # Don't let that attest an in-place rewrite, even with size and mtime restored.
                if snapshot is not None and before != snapshot.stamp:
                    raise RetrievalIntegrityError(f"index integrity mismatch: {key[0]}/{key[1]}")
                if self.selection is None:
                    if needs_database:
                        database = stack.enter_context(closing(self._database(shard, deadline)))
                    else:
                        self._verified_path(shard)
                if snapshot is None:
                    assert database is not None
                    metadata = tuple((k, v) for k, v in database.execute("SELECT key, value FROM metadata"))
                    coverage = tuple((a, s, g) for a, s, g in database.execute(
                        "SELECT area, status, gap FROM coverage ORDER BY area, status, gap"))
                    snapshot = _ShardSnapshot(before, metadata, coverage,
                                              MappingProxyType(captured) if self.selection is not None else None)
                if build_counts:
                    assert database is not None
                    kinds = tuple((k, n) for k, n in database.execute(
                        "SELECT kind, count(*) FROM entities GROUP BY kind ORDER BY kind"))
                    snapshot = replace(snapshot, kind_counts=kinds, projection_counts=_projection_counts(database, shard))
                self._check_deadline(deadline)
                if before != _file_stamp(path):
                    raise RetrievalIntegrityError(f"index changed during read: {key[0]}/{key[1]}")
                cache.snapshot = snapshot
            finally:
                cache.lock.release()
            yield snapshot, database
            self._check_deadline(deadline)
            if before != _file_stamp(path):
                raise RetrievalIntegrityError(f"index changed during read: {key[0]}/{key[1]}")

    def _check_deadline(self, deadline: float) -> None:
        if self.clock() > deadline:
            raise sqlite3.OperationalError("interrupted")

    def _cursor(self, offset: int, request_hash: str, *, position: Any = None) -> str:
        value = {"offset": offset, "request": request_hash}
        if position is not None:
            value["position"] = position
        payload = canonical_json(value)
        signature = hmac.new(self._cursor_key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")

    @staticmethod
    def _request_hash(tool: str, parameters: Mapping[str, Any]) -> str:
        stable = {key: value for key, value in parameters.items() if key != "cursor"}
        return hashlib.sha256(canonical_json({"tool": tool, **stable})).hexdigest()

    def _offset(self, cursor: str | None, request_hash: str) -> int:
        return self._cursor_state(cursor, request_hash)["offset"]

    def _cursor_state(self, cursor: str | None, request_hash: str) -> dict[str, Any]:
        if cursor is None:
            return {"offset": 0}
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            payload, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(signature, hmac.new(self._cursor_key, payload, hashlib.sha256).digest()):
                raise ValueError
            value = json.loads(payload)
            if value.get("request") != request_hash or not isinstance(value.get("offset"), int) or value["offset"] < 0:
                raise ValueError
            return value
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid or tampered cursor") from exc

    def _names(self, requested: Iterable[str] | None, *, empty_is_all: bool = True) -> tuple[str, ...]:
        names = tuple(self.indexes if requested is None or (empty_is_all and not requested) else requested)
        if len(names) != len(set(names)):
            raise ValueError("index selection is duplicated")
        if any(name not in INDEX_NAMES for name in names):
            raise ValueError("invalid index selection")
        return tuple(sorted(names))

    @staticmethod
    def _entity(row: sqlite3.Row, index: str) -> dict[str, Any]:
        raw = json.loads(row["payload_json"])
        payload = RetrievalCore._safe_payload(raw)
        if row["kind"] == EntityKind.TOOL_OBSERVATION.value:
            from .observations import observation_projection
            if "common" not in raw:
                payload["common"] = RetrievalCore._safe_common(observation_projection(raw).as_dict())
                payload["provenance_gaps"] = ["provenance_unavailable"]
                count_work("provenance_gaps")
        value = {
            "identity": row["identity"], "kind": row["kind"], "native_id": row["native_id"],
            "name": row["name"], "payload": payload, "index": index,
        }
        if "path" in row.keys() and row["path"] is not None:
            value["location"] = {key: row[key] for key in (
                "path", "file_sha256", "start_byte", "end_byte", "start_line", "end_line",
                "start_column", "end_column", "mapping_method", "confidence", "ambiguous",
            )}
            if "producer_location_json" in row.keys() and row["producer_location_json"]:
                from .source_resolution import source_native
                native = json.loads(row["producer_location_json"])
                if isinstance(native, Mapping) and ("source_backing" in native or "source_domain" in native):
                    value["location"]["producer_location"] = source_native(native)
        else:
            value["artifact_reference"] = {"index": index, "identity": row["identity"]}
        return value

    @staticmethod
    def _safe_common(value: Any) -> dict[str, Any]:
        from appsec_review.interchange import observation_metadata_from_mapping
        common = observation_metadata_from_mapping(value).as_dict()
        # Only the closed common-reference fields may retain canonical artifact paths.
        references = common["evidence_refs"]
        for reference in references:
            for field in ("artifact", "execution_reference", "retention_receipt"):
                artifact = reference[field]
                if artifact is None:
                    continue
                path = artifact["path"]
                pattern = {
                    "artifact": r"data/shared/objects/[0-9a-f]{64}",
                    "retention_receipt": (
                        r"data/jobs/[a-z][a-z0-9_]*/attempts/attempt_[0-9]+/"
                        r"shared/native-output/[0-9a-f]{64}\.json"),
                    "execution_reference": (
                        r"data/(?:codeql/scopes/[^/]+/queries/.+/executions/query|"
                        r"jobs/[a-z][a-z0-9_]*/attempts/attempt_[0-9]+/.+)/receipt\.json|"
                        r"data/jobs/job_evidence_collection/attempts/attempt_[0-9]+/steps/[^/]+/tasks/[^/]+/"
                        r"scratch/(?:invocation_[0-9]+/)?attempt_[0-9]+/execution\.json|"
                        r"data/jobs/job_artifact_security_analysis/attempts/attempt_[0-9]+/steps/analyze/tasks/"
                        r"[^/]+/containers/[^/]+/execution\.json|"
                        r"data/clang-static/[A-Za-z0-9._-]+/(?:tidy|analyze)/execution\.json"),
                }[field]
                if not re.fullmatch(pattern, path):
                    raise RetrievalIntegrityError("common observation artifact path is outside its allowed namespace")
                if field == "artifact" and path != f"data/shared/objects/{artifact['sha256']}":
                    raise RetrievalIntegrityError("common native artifact identity mismatch")
        count_work("observation_references", len(references))
        return common

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
            return {str(key)[:128]: (RetrievalCore._safe_common(child) if key == "common" and depth == 0
                                   else RetrievalCore._safe_payload(child, depth=depth + 1))
                    for key, child in list(value.items())[:200]
                    if not denied.fullmatch(str(key)) and str(key) != "path"}
        if isinstance(value, (list, tuple)):
            return [RetrievalCore._safe_payload(child, depth=depth + 1) for child in list(value)[:500]]
        return sanitize_producer_data(value, depth=depth)

    def _envelope(self, *, tool: str, results: list[dict[str, Any]], gaps: Iterable[str],
                  started: float, request_hash: str, offset: int = 0, has_more: bool = False,
                  truncated: bool = False, page_cursors: list[str] | None = None,
                  status: str = "ok") -> dict[str, Any]:
        unique_gaps = list(dict.fromkeys(str(item) for item in gaps))
        gaps_truncated = len(unique_gaps) > 200
        if gaps_truncated:
            unique_gaps = [*unique_gaps[:199],
                           f"truncated: {len(unique_gaps) - 199} additional coverage gap(s) omitted"]
        response = {
            "schema": RESPONSE_SCHEMA, "tool": tool, "run_id": self.run_id,
            "gaps_truncated": gaps_truncated, "status": status,
            "index_manifest": {"schema": self.manifest["schema"], "sha256": self.manifest_sha256,
                               "content_sha256": self.manifest["content_sha256"]},
            "indexes": [{key: value[key] for key in ("name", "schema", "sha256", "fingerprint", "shard_id")}
                        for value in self.manifest["indexes"]],
            "results": results, "pagination": {"next_cursor": None}, "coverage_gaps": unique_gaps,
            "truncated": truncated, "duration_ms": max(0, int((self.clock() - started) * 1000)),
        }

        def continuation() -> str:
            return (page_cursors[len(response["results"])] if page_cursors is not None
                    else self._cursor(offset + len(response["results"]), request_hash))

        if has_more:
            response["pagination"]["next_cursor"] = continuation()
        byte_gap = "response byte budget reached; trailing results were withheld (continue with the cursor)"
        while len(canonical_json(response)) > self.limits.max_response_bytes and response["results"]:
            response["results"].pop()
            response["truncated"] = True
            if byte_gap not in response["coverage_gaps"]:
                response["coverage_gaps"].append(byte_gap)
            response["pagination"]["next_cursor"] = continuation()
        if len(canonical_json(response)) > self.limits.max_response_bytes:
            response["gaps_truncated"] = bool(response["coverage_gaps"])
            response["coverage_gaps"] = ["response metadata exceeded byte budget"]
            response["indexes"] = []
        return response

    @contextmanager
    def _query_scope(self, tool: str, parameters: Mapping[str, Any], *, query_sha256: str | None = None,
                     filters: Mapping[str, Any] | None = None, indexes: Iterable[str] = ()) -> Iterator[_QueryWork]:
        parent = _QUERY.get()
        started = self.clock()
        work = _QueryWork(tool, query_sha256 or self._request_hash(tool, parameters), started, self.indexes)
        # A bounded query can time out before it reaches the first shard in its declared index set.
        for name in indexes:
            work.consider(name)
        if filters is None:
            filters = {key: value for key, value in parameters.items() if key not in {"query", "cursor"}}
        token = _QUERY.set(work)
        try:
            yield work
            if work.response is None:
                raise RuntimeError("retrieval query missing completion")
        except Exception as exc:
            timed_out = (isinstance(exc, RetrievalGap) and isinstance(exc.__cause__, sqlite3.OperationalError)
                         and "interrupted" in str(exc.__cause__).lower())
            self._audit(work, parent, filters, {"status": "timeout" if timed_out else "error",
                        "truncated": timed_out, "coverage_gaps": [str(exc)] if timed_out else []})
            raise
        else:
            self._audit(work, parent, filters, work.response, duration_ms=work.duration_ms,
                        result_count=work.result_count)
        finally:
            _QUERY.reset(token)
            if parent is not None:
                parent.include(work)

    @contextmanager
    def application_query(self, tool: str, parameters: Mapping[str, Any], *, query_sha256: str | None = None
                          ) -> Iterator[Callable[[Mapping[str, Any]], None]]:
        """Enclose an application fan-out. Complete it once with its final (possibly bounded) response."""
        with self._query_scope(tool, parameters, query_sha256=query_sha256) as work:
            yield work.complete

    def _audit(self, work: _QueryWork, parent: _QueryWork | None, filters: Mapping[str, Any],
               response: Mapping[str, Any], *, duration_ms: int | None = None, result_count: int | None = None) -> None:
        invocation = _ACTIVE_MCP.get()
        event = "RETRIEVAL_SUBOP_COMPLETED" if parent or invocation else "RETRIEVAL_QUERY"
        if duration_ms is None:
            duration_ms = max(0, int((self.clock() - work.started) * 1000))
        # The run-wide pipeline log is read by later jobs and by reporting; an audit record stays small.
        # The full gap list is in the response the caller received; here it is counted, hashed and sampled.
        gaps = [str(item) for item in response.get("coverage_gaps", ())]
        caller = _CALLER.get()
        self.log.write(event, run_id=self.run_id, job_id=caller.get("job_id", "retrieval"), trigger="mcp",
                       orchestrator="retrieval", details={
                            **caller, **work.metrics(), "status": response.get("status", "ok"),
                            "mcp_tool": work.tool, "manifest_sha256": self.manifest_sha256,
                            "query_sha256": work.request_hash, "filters": filters,
                            "result_count": len(response.get("results", ())) if result_count is None else result_count,
                            "gap_count": len(gaps),
                            "gaps_sha256": hashlib.sha256(canonical_json(gaps)).hexdigest(),
                            "gaps": [gap[:AUDIT_GAP_CHARS] for gap in gaps[:AUDIT_GAP_SAMPLE]],
                            "truncated": bool(response.get("truncated")), "duration_ms": duration_ms,
                            "gaps_truncated": bool(response.get("gaps_truncated")),
                            "parent_tool": parent.tool if parent else None,
                            "parent_query_sha256": parent.request_hash if parent else None,
                            "parent_invocation_id": invocation.get("mcp_invocation_id") if invocation else None,
                            "mcp_session_id": invocation.get("mcp_session_id") if invocation else self.mcp_session_id,
                       })

    _TOOL_INDEXES: dict[str, tuple[str, ...]] = {
        "query_artifacts": ("artifacts", "observations", "evidence"),
        "query_ci_configuration": ("observations", "evidence"),
        "query_codeql": ("observations",),
        "query_change_context": ("history",),
        "query_hotspots": ("priority",),
        "query_precomputed": ("precomputed",),
        "query_observations": ("observations",),
        "query_dataset_inventory": ("inventory",),
        "query_build_security": ("build_security",),
        "query_threat_boundaries": ("precomputed",),
        "query_auth_surfaces": ("precomputed",),
        "query_crypto_usage": ("precomputed",),
        "query_input_surfaces": ("precomputed",),
        "query_owasp_gaps": ("precomputed",),
        "query_doc_drift": ("precomputed", "observations"),
        "query_sca_reachability": ("precomputed", "observations", "inventory"),
        "query_sanitizer_readiness": ("build_security", "inventory"),
        "query_code_graph": ("graph",),
        "query_cpg_slice": ("analysis",),
        "query_call_paths": ("analysis",),
        "cited_cpg_nodes": ("analysis",),
        "query_syntax": ("analysis",),
        "query_cfg_function": ("analysis",),
        "query_guard_dominators": ("analysis",),
        "query_debug_symbols": ("compiled", "graph"),
        "list_codeql_databases": ("graph",),
        "query_codeql_neighborhood": ("graph", "precomputed"),
    }

    def _declared_indexes(self, tool: str, parameters: Mapping[str, Any]) -> Iterable[str]:
        if tool == "trace":
            return self.indexes
        if tool in {"read_excerpt", "resolve_evidence"}:
            return ()
        if "indexes" in parameters:
            selected = parameters["indexes"]
            return selected if selected else self.indexes
        if tool == "query_engineering_signals":
            fam = parameters.get("signal_family")
            names: list[str] = []
            if fam in {None, "history", "change_context"}:
                names.extend(("precomputed", "history"))
            if fam in {None, "priority"}:
                names.append("priority")
            if fam in {None, "test_coverage", "profile"}:
                names.extend(("analysis", "observations", "evidence"))
            return names
        return self._TOOL_INDEXES.get(tool, ())

    def _execute(self, tool: str, parameters: Mapping[str, Any], operation: Callable[[float], tuple]) -> dict[str, Any]:
        indexes = self._declared_indexes(tool, parameters)
        with self._query_scope(tool, parameters, indexes=indexes) as work:
            response = self._execute_response(work, operation)
            work.complete(response, duration_ms=response["duration_ms"])
            return response

    def _execute_response(self, work: _QueryWork, operation: Callable[[float], tuple]) -> dict[str, Any]:
        from appsec_review.storage.validation import validation_scope

        started = work.started
        deadline = started + self.limits.timeout_ms / 1000
        page_cursors = None
        try:
            with validation_scope(self.run_root):
                outcome = operation(deadline)
            if len(outcome) == 6:
                # Keyset pages supply a cursor at each result boundary, including the empty
                # prefix, so byte-budget withholding cannot skip unreturned results.
                results, gaps, has_more, offset, operation_truncated, page_cursors = outcome
            elif len(outcome) == 5:
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
        return self._envelope(tool=work.tool, results=results, gaps=gaps, started=started,
                              request_hash=work.request_hash, offset=offset, has_more=has_more,
                              truncated=timed_out or operation_truncated, page_cursors=page_cursors,
                              status="timeout" if timed_out else "ok")

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
                    with closing(self._database(shard, deadline)) as database:
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

    def _exact_rows(self, identities: frozenset[str], names: tuple[str, ...], deadline: float, *,
                    kind=None, name=None, path=None):
        matches = {eid: [] for eid in identities}
        gaps = [] if names else ["accepted index set is empty"]
        conditions, filters = [], []
        for column, value in (("e.kind", kind), ("e.name", name), ("l.path", path)):
            if value is not None:
                conditions.append(f" AND {column}=?")
                filters.append(value)
        for index in names:  # names and shards are sorted: first match agrees with find's tie-break.
            self._check_deadline(deadline)
            if index not in self.indexes:
                gaps.append(f"{index} index is unavailable")
                continue
            self._index_exact_rows(index, identities, deadline, matches, gaps, conditions, filters)
        self._check_deadline(deadline)
        return matches, gaps

    def _index_exact_rows(self, index, identities, deadline, matches, gaps, conditions, filters):
        cache = self._routes[index]
        with ExitStack() as stack:
            routes = cache.by_identity
            if routes is None:
                if not cache.lock.acquire(timeout=max(0, deadline - self.clock())):
                    raise sqlite3.OperationalError("interrupted")
                stack.callback(cache.lock.release)
                routes = cache.by_identity
            work = _QUERY.get()
            if work is not None:
                work.route(routes is not None)
            building, routed = {}, {}
            if routes is not None:
                for eid in identities:
                    for key in routes.get(eid, ()):
                        routed.setdefault(key, []).append(eid)
            for shard in self.indexes[index]:
                key = _shard_key(shard)
                candidates = routed.get(key, [])
                # Gaps, integrity and grants depend even on nonmatching shards. Payload
                # queries do not: in a warm index only direct reverse-route hits open SQLite.
                with self._routed_read(shard, deadline, read_rows=routes is None or bool(candidates)) as (facts, db):
                    gaps.extend(f"{index}/{key[1]}: {gap}" for gap in facts.gaps(shard, incomplete_only=True))
                    if routes is None:
                        assert db is not None
                        for eid, in db.execute("SELECT identity FROM entities"):
                            building.setdefault(eid, []).append(key)
                            if eid in identities:
                                candidates.append(eid)
                    candidates.sort()
                    for start in range(0, len(candidates), 500):
                        self._check_deadline(deadline)
                        batch = candidates[start:start + 500]
                        slots = ",".join("?" for _ in batch)
                        sql = ("SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                               f"WHERE e.identity IN ({slots})" + "".join(conditions) + " ORDER BY e.identity")
                        assert db is not None
                        for row in db.execute(sql, [*batch, *filters]):
                            item = self._entity(row, index)
                            item["shard_id"] = key[1]
                            matches[item["identity"]].append(item)
            if routes is None:
                complete = MappingProxyType({eid: tuple(keys) for eid, keys in building.items()})
                self._check_deadline(deadline)
                cache.by_identity = complete

    def resolve_identities(self, identities: Iterable[str], *, indexes: Iterable[str] | None = None
                           ) -> dict[str, dict[str, Any]]:
        """Run one batched lookup, retaining a normal, independently auditable find(limit=1) per ID."""
        ids = tuple(dict.fromkeys(identities))
        names = self._names(indexes, empty_is_all=False)
        for eid in ids:
            LogicalIdentity.parse(eid)
        filters = {"identity_count": len(ids), "indexes": names}
        with self._query_scope("resolve_identities", {"identities": ids, "indexes": names}, filters=filters,
                               indexes=names if ids else ()) as batch:
            responses = self._batch_responses(batch, ids, names) if ids else {}
            # Count physical work only on the batch. Per-ID finds are logical views of that one read.
            batch.complete({
                "status": "timeout" if any(r["status"] == "timeout" for r in responses.values()) else "ok",
                "coverage_gaps": dict.fromkeys(g for r in responses.values() for g in r["coverage_gaps"]),
                "truncated": any(r["truncated"] for r in responses.values()),
                "gaps_truncated": any(r["gaps_truncated"] for r in responses.values()),
            }, result_count=sum(len(r["results"]) for r in responses.values()))
            return responses

    def _batch_responses(self, batch: _QueryWork, ids: tuple[str, ...], names: tuple[str, ...]
                         ) -> dict[str, dict[str, Any]]:
        from appsec_review.storage.validation import validation_scope

        try:
            with validation_scope(self.run_root):
                matches, gaps = self._exact_rows(frozenset(ids), names, batch.started + self.limits.timeout_ms / 1000)
            timed_out = False
        except sqlite3.OperationalError as exc:
            if "interrupted" not in str(exc).lower():
                raise
            matches, gaps, timed_out = {}, ["query execution-time budget exceeded"], True
        responses = {}
        for eid in ids:
            parameters = {"identity": eid, "kind": None, "name": None, "path": None, "indexes": names, "limit": 1}
            with self._query_scope("find", parameters) as synthetic:
                rows = matches.get(eid, [])
                response = self._envelope(tool="find", results=rows[:1], gaps=gaps, started=batch.started,
                                          request_hash=synthetic.request_hash, has_more=len(rows) > 1,
                                          truncated=timed_out, status="timeout" if timed_out else "ok")
                synthetic.complete(response)
                responses[eid] = response
        return responses

    def dataset_inventory(self, indexes: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
        """Verified, view-local actual row counts; timeout never masquerades as an empty dataset."""
        names = self._names(indexes, empty_is_all=False)
        filters = {"indexes": names}
        with self._query_scope("dataset_inventory", filters, indexes=names) as work:
            inventory = self._dataset_inventory(names, work.started + self.limits.timeout_ms / 1000)
            work.complete({
                "coverage_gaps": dict.fromkeys(gap for rows in inventory.values() for row in rows
                                               for gap in row["coverage_gaps"]),
            }, result_count=sum(map(len, inventory.values())))
            return inventory

    def _dataset_inventory(self, names: tuple[str, ...], deadline: float) -> dict[str, list[dict[str, Any]]]:
        from appsec_review.storage.validation import validation_scope

        inventory = {index: [] for index in names}
        try:
            with validation_scope(self.run_root):
                for index, records in inventory.items():
                    for shard in self.indexes.get(index, ()):
                        with self._routed_read(shard, deadline, counts=True) as (facts, _):
                            assert facts.kind_counts is not None
                            counts = dict(facts.kind_counts)
                            records.append({"shard_id": shard.get("shard_id", "default"), "sha256": shard["sha256"],
                                            "producer": self._safe_payload(shard.get("producer", {})),
                                            "entity_count": sum(counts.values()), "kind_counts": counts,
                                            "projection_counts": dict(facts.projection_counts),
                                            "coverage_gaps": facts.gaps(shard)})
                self._check_deadline(deadline)
        except sqlite3.OperationalError as exc:
            if "interrupted" not in str(exc).lower():
                raise
            raise RetrievalGap("dataset inventory execution-time budget exceeded") from exc
        return inventory

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
        names = self._names(indexes, empty_is_all=identity is None)
        parameters = {"identity": identity, "kind": kind, "name": name, "path": path,
                      "indexes": names, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("find", parameters)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            if identity is not None:
                matches, gaps = self._exact_rows(frozenset((identity,)), names, deadline, kind=kind, name=name, path=path)
                rows = matches[identity]
                return rows[offset:offset + limit], gaps, len(rows) > offset + limit, offset
            found, gaps = [], ["accepted index set is empty"] if not names else []
            for index_name in names:
                self._check_deadline(deadline)
                if index_name not in self.indexes:
                    gaps.append(f"{index_name} index is unavailable")
                    continue
                clauses, values = [], []
                for column, value in (("e.kind", kind), ("e.name", name), ("l.path", path)):
                    if value is not None:
                        clauses.append(column + "=?")
                        values.append(value)
                sql = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE " + " AND ".join(clauses)
                sql += " ORDER BY e.identity LIMIT ?"
                values.append(offset + limit + 1)
                for shard in self.indexes[index_name]:
                    with closing(self._database(shard, deadline)) as database:
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
            found = self.find(identity=identity, limit=2)
            if found["status"] == "timeout":
                raise sqlite3.OperationalError("interrupted")
            matches = found["results"]
            if not matches:
                return [], ["source identity was not found in accepted indexes"], False, 0
            match = matches[0]
            location = match.get("location")
            if location is None:
                return [], ["entity has no resolving source location"], False, 0
            try:
                data = self._source_data(location)
            except (OSError, ValueError) as exc:
                return [], [str(exc)], False, 0
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

    def read_source_lines(self, *, identity: str) -> tuple[dict[str, Any] | None, str | None]:
        """Every line of the verified source file that holds ``identity``'s accepted location.

        Returns ``({"location": ..., "lines": [...]}, None)`` or ``(None, reason)``. Like
        ``read_excerpt``, this resolves an accepted entity to target bytes or explicit,
        run-bound generated-source custody. Both paths verify the source digest, UTF-8,
        and byte bound. Generated paths never fall back to the target tree. Review-package
        spans are therefore always read through an accepted, resolving entity.
        """
        LogicalIdentity.parse(identity)
        found = self.find(identity=identity, limit=2)
        if found["status"] == "timeout":
            return None, "query execution-time budget exceeded"
        matches = found["results"]
        if not matches:
            return None, "source identity was not found in accepted indexes"
        location = matches[0].get("location")
        if location is None:
            return None, "entity has no resolving source location"
        try:
            data = self._source_data(location)
        except (OSError, ValueError) as exc:
            return None, str(exc)
        try:
            lines = data.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            return None, "source excerpt is not UTF-8 text"
        return {"location": dict(location), "lines": lines}, None

    def _source_data(self, location: Mapping[str, Any]) -> bytes:
        from .source_resolution import read_source_bytes
        return read_source_bytes(
            self.run_root, self.target_root, target_snapshot=str(self.manifest["target_snapshot"]),
            path=location["path"], sha256=location["file_sha256"],
            native=location.get("producer_location"))

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
                        with closing(self._database(shard, deadline)) as database:
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

        def operation(deadline: float):
            found = self.find(identity=identity, limit=1)
            if found["status"] == "timeout":
                raise sqlite3.OperationalError("interrupted")
            self._check_deadline(deadline)
            trace = self.trace(identity=identity, relations=(RelationKind.OBSERVED_AT, RelationKind.DERIVED_FROM,
                               RelationKind.SUPPORTS, RelationKind.CONTRADICTS), depth=2, limit=limit)
            if trace["status"] == "timeout":
                raise sqlite3.OperationalError("interrupted")
            self._check_deadline(deadline)
            entity = found["results"]
            return ([{"entity": entity[0] if entity else None, "relationships": trace["results"]}],
                    ([] if entity else ["evidence identity was not found"]) + trace["coverage_gaps"], False, 0)

        return self._execute("resolve_evidence", {"identity": identity, "limit": limit}, operation)

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
                with self._routed_read(shard, deadline) as (facts, _):
                    rows = [{"area": area, "status": status, "gap": gap} for area, status, gap in facts.coverage]
                    metadata = dict(facts.metadata)
                    entity_kinds = (json.loads(metadata["entity_kind_counts"])
                                    if "entity_kind_counts" in metadata else None)
                    relation_kinds = (json.loads(metadata["relation_kind_counts"])
                                      if "relation_kind_counts" in metadata else None)
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
                        with closing(self._database(relation_shard, deadline)) as database:
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
                with closing(self._database(identity, deadline)) as database:
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
                with closing(self._database(identity, deadline)) as database:
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
                with closing(self._database(identity, deadline)) as database:
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
                          if str(item.get("shard_id", "")) == "change-context" or
                          str(item.get("shard_id", "")).startswith("change-context-")]
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
                with closing(self._database(identity, deadline)) as database:
                    for row in database.execute(sql, values):
                        item = self._entity(row, "history")
                        item["shard_id"] = identity["shard_id"]
                        found.append(item)
                    gaps.extend(f"history/{identity['shard_id']}: {row['area']}: {row['status']}: {row['gap']}"
                                for row in database.execute(
                                    "SELECT area, status, gap FROM coverage WHERE status != 'complete' ORDER BY area"))
                gaps.extend(f"history/{identity['shard_id']}: {gap}" for gap in identity.get("gaps", ()))
            found.sort(key=lambda item: (item["payload"].get("scope", ""), int(item["payload"].get("rank", 0)),
                                         item["shard_id"], item["identity"]))
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
                with closing(self._database(shard, deadline)) as database:
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
                with closing(self._database(shard, deadline)) as database:
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

    def query_debug_symbols(self, *, mode: str, artifact_identity: str | None = None,
                            subject: str | None = None, address: int | None = None,
                            limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
        from appsec_review.retrieval.debug_symbols import query_debug_symbols
        return query_debug_symbols(self, mode=mode, artifact_identity=artifact_identity, subject=subject,
                                   address=address, limit=limit, cursor=cursor)

    def query_syntax(self, *, mode: str, subject: str, name: str | None = None,
                     limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
        from .syntax import query_syntax
        return query_syntax(self, mode=mode, subject=subject, name=name, limit=limit, cursor=cursor)

    def query_code_graph(
        self, *, mode: str, subject: str, depth: int | None = None, sink_class: str | None = None,
        source_class: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read accepted code-graph facts by mode and exact subject; see ``retrieval/graph.py``."""
        from appsec_review.retrieval.graph import query_code_graph
        return query_code_graph(self, self.graph_settings, mode=mode, subject=subject, depth=depth,
                                sink_class=sink_class, source_class=source_class, limit=limit, cursor=cursor)

    def list_codeql_databases(
        self, *, language: str | None = None, limit: int = 20, cursor: str | None = None,
        graph_scopes: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """List the accepted CodeQL database cards; see ``retrieval/neighborhood.py``."""
        from appsec_review.retrieval.neighborhood import list_codeql_databases
        return list_codeql_databases(self, language=language, limit=limit, cursor=cursor, graph_scopes=graph_scopes)

    def query_codeql_neighborhood(
        self, *, database: str, seed: str | None = None, symbol: str | None = None,
        observation: str | None = None, direction: str = "both", depth: int | None = None, limit: int = 20,
        include: Sequence[str] | None = None, cursor: str | None = None,
        graph_scopes: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Read the precomputed call closure around one subject of one database; no CodeQL runs."""
        from appsec_review.retrieval.neighborhood import query_codeql_neighborhood
        return query_codeql_neighborhood(
            self, self.graph_settings, database=database, seed=seed, symbol=symbol, observation=observation,
            direction=direction, depth=depth, limit=limit, include=include, cursor=cursor, graph_scopes=graph_scopes)

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
            with closing(self._database(shard, deadline)) as database:
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
        seed: str | None = None, function: str | None = None, fix_it: bool | None = None,
        min_trace_length: int | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Filter accepted observation shards by exact scanner, rule, reported severity, suppression and scope.

        ``seed`` (``path:line``), ``function``, ``fix_it`` and ``min_trace_length`` select the seeded
        Clang-Tidy / Clang Static Analyzer diagnostics (docs/architecture/seeded-neighborhoods.md section 9):
        the seed is a ledger location the diagnostic was labelled against, the function is the IR function
        that holds it, ``fix_it`` is whether the check proposes a fix-it, and the trace length is the number
        of analyzer path steps. An observation that carries none of those fields never matches them.

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
        seed_path, seed_line = None, None
        if seed is not None:
            if not isinstance(seed, str) or not re.fullmatch(r"^.{1,4096}:[0-9]{1,9}$", seed):
                raise ValueError("invalid observation filter: seed")
            seed_path, _, text = seed.rpartition(":")
            seed_path, seed_line = normalize_relative_path(seed_path), int(text)
        if function is not None and (not isinstance(function, str) or not 1 <= len(function) <= 4096):
            raise ValueError("invalid observation filter: function")
        if fix_it is not None and not isinstance(fix_it, bool):
            raise ValueError("invalid observation filter: fix_it")
        if min_trace_length is not None and (isinstance(min_trace_length, bool) or not isinstance(min_trace_length, int)
                                             or not 0 <= min_trace_length <= 100_000):
            raise ValueError("invalid observation filter: min_trace_length")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        parameters = {"scanner": scanner, "rule": rule, "severity": severity, "observation_class": observation_class,
                      "suppressed": suppressed, "duplicate": duplicate, "source": source, "artifact": artifact,
                      "path": path, "start_line": start_line, "end_line": end_line, "shard": shard,
                      "seed": seed, "function": function, "fix_it": fix_it, "min_trace_length": min_trace_length,
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
                with closing(self._database(identity, deadline)) as database:
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
                        if not self._analyzer_filters(payload, row["path"], seed_path, seed_line, function, fix_it,
                                                      min_trace_length):
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

    @staticmethod
    def _analyzer_filters(payload: Mapping[str, Any], location_path: str | None, seed_path: str | None,
                          seed_line: int | None, function: str | None, fix_it: bool | None,
                          min_trace_length: int | None) -> bool:
        """The seeded-analyzer filters of ``query_observations``; an observation without the field never matches."""
        label = payload.get("seeded") if isinstance(payload.get("seeded"), Mapping) else None
        if seed_path is not None:
            seeds = (label or {}).get("seeds") or ()
            hit = any(isinstance(entry, (list, tuple)) and len(entry) == 3 and isinstance(entry[1], int)
                      and isinstance(entry[2], int) and entry[1] <= seed_line <= entry[2]
                      and (entry[0] == seed_path or str(location_path or "").endswith("/" + seed_path)
                           or location_path == seed_path) for entry in seeds)
            if not hit:
                return False
        if function is not None and (label or {}).get("function") != function:
            return False
        if fix_it is not None and ("fix_it" not in payload or bool(payload["fix_it"]) is not fix_it):
            return False
        if min_trace_length is not None and int(payload.get("trace_length", -1) if isinstance(
                payload.get("trace_length"), int) else -1) < min_trace_length:
            return False
        return True

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
                with closing(self._database(identity, deadline)) as database:
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
                with closing(self._database(identity, deadline)) as database:
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


    def query_cfg_function(
        self, *, subject: str | None = None, function_name: str | None = None,
        path: str | None = None, limit: int = 20, cursor: str | None = None,
        block_limit: int | None = None, edge_limit: int | None = None,
        _cell_fits: Callable[[dict], bool] | None = None, _cell_line: int | None = None,
    ) -> dict[str, Any]:
        """Read accepted CFGs; either item limit selects compact pages of one function at a time."""
        from appsec_review.retrieval.syntax import query_cfg_function
        return query_cfg_function(
            self, subject=subject, function_name=function_name, path=path, limit=limit, cursor=cursor,
            block_limit=block_limit, edge_limit=edge_limit, _cell_fits=_cell_fits, _cell_line=_cell_line,
        )

    def query_guard_dominators(
        self, *, subject: str | None = None, path: str | None = None,
        line: int | None = None, node_id: str | None = None, polarity: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read precomputed branch guard polarity and dominating checks from Tree-sitter CFG shards."""
        from appsec_review.retrieval.syntax import query_guard_dominators
        return query_guard_dominators(
            self, subject=subject, path=path, line=line, node_id=node_id,
            polarity=polarity, limit=limit, cursor=cursor,
        )

    def query_cpg_slice(
        self, *, criterion_node_id: str | None = None, path: str | None = None,
        line: int | None = None, function_name: str | None = None,
        direction: str = "backward", max_depth: int = 8,
        edge_kinds: Sequence[str] | None = None, limit: int = 50, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read precomputed backward/forward program slices from alternate CPG shards."""
        from appsec_review.retrieval.graph import query_cpg_slice
        return query_cpg_slice(
            self, criterion_node_id=criterion_node_id, path=path, line=line,
            function_name=function_name, direction=direction, max_depth=max_depth,
            edge_kinds=edge_kinds, limit=limit, cursor=cursor,
        )

    def query_call_paths(
        self, *, source: str | None = None, sink: str | None = None,
        sink_class: str | None = None, entrypoint_only: bool = False,
        language: str | None = None, max_hops: int = 10,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read precomputed multi-hop call/reachability paths from alternate CPG shards."""
        from appsec_review.retrieval.graph import query_call_paths
        return query_call_paths(
            self, source=source, sink=sink, sink_class=sink_class,
            entrypoint_only=entrypoint_only, language=language,
            max_hops=max_hops, limit=limit, cursor=cursor,
        )

    def _query_precomputed_filtered(
        self, tool_name: str, query_set: str, parameters: Mapping[str, Any],
        predicate: Callable[[Mapping[str, Any], Mapping[str, Any]], bool],
        *, subject: str | None = None, path: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        from contextlib import ExitStack, closing
        import heapq

        if subject is not None:
            LogicalIdentity.parse(subject)
        if path is not None:
            path = normalize_relative_path(path)
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        full_params = {**parameters, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash(tool_name, full_params)
        state = self._cursor_state(cursor, request_hash)
        offset = state["offset"]
        position = state.get("position", ["", ""])
        if (not isinstance(position, list) or len(position) != 2
                or any(not isinstance(part, str) for part in position)
                or (offset and "position" not in state)):
            raise ValueError("invalid filtered-query cursor; restart pagination")

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            page_cursors = [self._cursor(offset, request_hash, position=position)]
            shards = [
                shard for shard in self.indexes.get("precomputed", ())
                if shard.get("producer", {}).get("query_set") == query_set
            ]
            if not shards:
                gaps.append(f"precomputed query set {query_set} is unavailable")
            # Merge ordered shard cursors, retaining one lookahead per shard. The existing
            # configured result ceiling also bounds Python predicate work in each scan page.
            pending = []
            scanned = 0
            with ExitStack() as stack:
                for shard in shards:
                    self._check_deadline(deadline)
                    shard_id = str(shard.get("shard_id", "default"))
                    database = stack.enter_context(closing(self._database(shard, deadline)))
                    clauses = ["e.kind='precomputed_fact'",
                               "(e.identity > ? OR (e.identity = ? AND ? > ?))"]
                    values: list[Any] = [position[0], position[0], shard_id, position[1]]
                    if subject is not None:
                        clauses.append("(json_extract(e.payload_json, '$.subject_identity') = ? OR e.identity = ?)")
                        values.extend((subject, subject))
                    if path is not None:
                        clauses.append("COALESCE(l.path, json_extract(e.payload_json, '$.subject_path')) = ?")
                        values.append(path)
                    if tool_name == "query_threat_boundaries":
                        for key in ("boundary_id", "trust_level"):
                            if parameters.get(key) is not None:
                                clauses.append(f"json_extract(e.payload_json, '$.result.{key}') = ?")
                                values.append(parameters[key])
                        if parameters.get("path") is not None:
                            clauses.append(
                                "(json_extract(e.payload_json, '$.subject_path') = ? OR EXISTS "
                                "(SELECT 1 FROM json_each(e.payload_json, '$.result.source_paths') WHERE value = ?))")
                            values.extend((parameters["path"], parameters["path"]))
                    rows = iter(database.execute(
                        "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity WHERE "
                        + " AND ".join(clauses) + " ORDER BY e.identity LIMIT ?",
                        [*values, self.limits.max_results + 1]))
                    row = next(rows, None)
                    if row is not None:
                        heapq.heappush(pending, (row["identity"], shard_id, row, rows))
                    gaps.extend(
                        f"precomputed/{shard_id}: {r['area']}: {r['status']}: {r['gap']}"
                        for r in database.execute(
                            "SELECT area, status, gap FROM coverage WHERE status != 'complete' ORDER BY area"
                        )
                    )
                    gaps.extend(f"precomputed/{shard_id}: {g}" for g in shard.get("gaps", ()))
                while pending and scanned < self.limits.max_results and len(found) < limit:
                    self._check_deadline(deadline)
                    identity, shard_id, row, rows = heapq.heappop(pending)
                    scanned += 1
                    payload = json.loads(row["payload_json"])
                    result_obj = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
                    matches = predicate(payload, result_obj)
                    self._check_deadline(deadline)
                    if matches:
                        item = self._entity(row, "precomputed")
                        item["shard_id"] = shard_id
                        found.append(item)
                        page_cursors.append(self._cursor(offset + len(found), request_hash,
                                                         position=[identity, shard_id]))
                    else:
                        page_cursors[-1] = self._cursor(offset + len(found), request_hash,
                                                       position=[identity, shard_id])
                    following = next(rows, None)
                    if following is not None:
                        heapq.heappush(pending, (following["identity"], shard_id, following, rows))
            scan_truncated = bool(pending) and scanned == self.limits.max_results and len(found) < limit
            if scan_truncated:
                gaps.append(f"precomputed candidate scan bound of {self.limits.max_results} reached; "
                            "more candidates remain, continue with the cursor")
            return found, gaps, bool(pending), offset, scan_truncated, page_cursors

        return self._execute(tool_name, full_params, operation)

    def query_threat_boundaries(
        self, *, subject: str | None = None, path: str | None = None,
        boundary_id: str | None = None, trust_level: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query indexed threat-model trust boundaries, cross-boundary flows, entry points, and STRIDE threats."""
        for label, val in (("boundary_id", boundary_id), ("trust_level", trust_level)):
            if val is not None and (not isinstance(val, str) or not val or len(val) > 512):
                raise ValueError(f"invalid threat boundary filter: {label}")

        def pred(_payload: Mapping[str, Any], res: Mapping[str, Any]) -> bool:
            if boundary_id is not None and res.get("boundary_id") != boundary_id:
                return False
            if trust_level is not None and res.get("trust_level") != trust_level:
                return False
            return True

        norm_path = normalize_relative_path(path) if path is not None else None
        params = {"subject": subject, "path": norm_path, "boundary_id": boundary_id, "trust_level": trust_level}
        if norm_path is not None:
            # Threat boundaries store source_paths array in result as well as subject_path
            def path_pred(payload: Mapping[str, Any], res: Mapping[str, Any]) -> bool:
                if not pred(payload, res):
                    return False
                src_paths = res.get("source_paths") or ()
                return payload.get("subject_path") == norm_path or norm_path in src_paths

            return self._query_precomputed_filtered(
                "query_threat_boundaries", "threat_boundaries", params, path_pred,
                subject=subject, path=None, limit=limit, cursor=cursor,
            )
        return self._query_precomputed_filtered(
            "query_threat_boundaries", "threat_boundaries", params, pred,
            subject=subject, path=None, limit=limit, cursor=cursor,
        )

    def query_owasp_gaps(
        self, *, subject: str | None = None, component_id: str | None = None,
        control_id: str | None = None, status: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query independently assessed not_satisfied controls with resolving evidence."""
        from appsec_review.owasp_workbench.engine import verified_control_gap_candidate

        for label, val in (("component_id", component_id), ("control_id", control_id), ("status", status)):
            if val is not None and (not isinstance(val, str) or not val or len(val) > 512):
                raise ValueError(f"invalid OWASP gap filter: {label}")
        if status is not None and status != "not_satisfied":
            raise ValueError("status must be not_satisfied")

        def pred(_payload: Mapping[str, Any], res: Mapping[str, Any]) -> bool:
            evidence = res.get("evidence") or ()
            is_verified = (
                verified_control_gap_candidate(res)
                and res.get("unresolved_evidence") == 0
                and bool(evidence)
                and all(isinstance(item, Mapping) and item.get("resolved") is True
                        and item.get("source_identity") for item in evidence)
            )
            if not is_verified:
                return False
            if component_id is not None and res.get("component_id") != component_id:
                return False
            if control_id is not None:
                cid = str(res.get("control_identity") or "")
                if cid != control_id and not cid.endswith(":" + control_id):
                    return False
            if status is not None and res.get("control_status") != status:
                return False
            return True

        params = {"subject": subject, "component_id": component_id, "control_id": control_id, "status": status}
        return self._query_precomputed_filtered(
            "query_owasp_gaps", "control_evidence", params, pred,
            subject=subject, limit=limit, cursor=cursor,
        )

    def query_doc_drift(
        self, *, subject: str | None = None, path: str | None = None,
        drift_kind: str | None = None, severity: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query recognized drift kinds, keeping missing coverage separate from drift evidence."""
        kinds = {"missing_auth_middleware", "undocumented_route", "unmapped_declared_operation",
                 "parameter_constraint_drift", "role_or_scope_mismatch"}
        for label, val in (("drift_kind", drift_kind), ("severity", severity)):
            if val is not None and (not isinstance(val, str) or not val or len(val) > 256):
                raise ValueError(f"invalid doc drift filter: {label}")
        if drift_kind is not None and drift_kind not in kinds:
            raise ValueError(f"drift_kind must be one of {sorted(kinds)}")
        if subject is not None:
            LogicalIdentity.parse(subject)
        norm_path = normalize_relative_path(path) if path is not None else None
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        params = {"subject": subject, "path": norm_path, "drift_kind": drift_kind,
                  "severity": severity, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_doc_drift", params)
        offset = self._offset(cursor, request_hash)

        def shard_gaps(database: sqlite3.Connection, shard: Mapping[str, Any]) -> set[str]:
            return {*(str(gap) for gap in shard.get("gaps", ())), *(row["gap"] for row in database.execute(
                "SELECT gap FROM coverage WHERE gap IS NOT NULL AND status != 'complete'"))}

        def local_gaps(payload: Mapping[str, Any], shared: set[str]) -> list[str]:
            return list(dict.fromkeys(str(gap) for gap in payload.get("gaps") or () if str(gap) not in shared))

        def projected(row: sqlite3.Row, index: str, shared: set[str]) -> dict[str, Any]:
            item = self._entity(row, index)
            if "gaps" in item["payload"]:
                item["payload"]["gaps"] = local_gaps(item["payload"], shared)
            return item

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            doc_shards = [
                s for s in self.indexes.get("precomputed", ())
                if s.get("producer", {}).get("query_set") == "document_context"
            ]
            obs_shards = [
                s for s in self.indexes.get("observations", ())
                if str(s.get("producer", {}).get("job", "")) == "job_document_issue_analysis"
                or str(s.get("shard_id", "")).startswith("document")
            ]
            if not any(s.get("producer", {}).get("job") == "job_document_issue_analysis"
                       for s in doc_shards) and not obs_shards:
                gaps.append("accepted document drift projection is unavailable; document_context alone is not drift coverage")
            for shard in doc_shards:
                self._check_deadline(deadline)
                shard_id = str(shard.get("shard_id", "default"))
                with closing(self._database(shard, deadline)) as database:
                    shared = shard_gaps(database, shard)
                    gaps.extend(f"precomputed/{shard_id}: {gap}" for gap in sorted(shared))
                    for row in database.execute(
                        "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                        "WHERE e.kind='precomputed_fact' ORDER BY e.identity"
                    ):
                        payload = json.loads(row["payload_json"])
                        res = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
                        subjects = {row["identity"], payload.get("subject_identity"),
                                    res.get("handler_source_id"), res.get("spec_source_id")}
                        if subject is not None and subject not in subjects:
                            continue
                        row_path = row["path"] or payload.get("subject_path")
                        if norm_path is not None and row_path != norm_path:
                            continue
                        gaps.extend(f"{row['identity']}: {gap}" for gap in local_gaps(payload, shared))
                        dk = res.get("drift_kind")
                        if not isinstance(dk, str) or dk not in kinds:
                            if dk is not None:
                                gaps.append(f"{row['identity']}: unsupported drift kind {dk}")
                            continue
                        if drift_kind is not None and dk != drift_kind:
                            continue
                        sev = str(res.get("severity") or "medium")
                        if severity is not None and sev != severity:
                            continue
                        item = projected(row, "precomputed", shared)
                        item["shard_id"] = shard_id
                        item["drift_kind"] = dk
                        found.append(item)
            for shard in obs_shards:
                self._check_deadline(deadline)
                shard_id = str(shard.get("shard_id", "default"))
                with closing(self._database(shard, deadline)) as database:
                    shared = shard_gaps(database, shard)
                    gaps.extend(f"observations/{shard_id}: {gap}" for gap in sorted(shared))
                    for row in database.execute(
                        "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                        "ORDER BY e.identity"
                    ):
                        payload = json.loads(row["payload_json"])
                        if subject is not None and row["identity"] != subject:
                            continue
                        if norm_path is not None and row["path"] != norm_path:
                            continue
                        gaps.extend(f"{row['identity']}: {gap}" for gap in local_gaps(payload, shared))
                        dk = payload.get("drift_kind")
                        if not isinstance(dk, str) or dk not in kinds:
                            gaps.append(f"{row['identity']}: no recognized document drift kind")
                            continue
                        if drift_kind is not None and dk != drift_kind:
                            continue
                        sev = str(payload.get("severity") or "medium")
                        if severity is not None and sev != severity:
                            continue
                        item = projected(row, "observations", shared)
                        item["shard_id"] = shard_id
                        item["drift_kind"] = dk
                        found.append(item)
            found.sort(key=lambda item: (item["identity"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset

        return self._execute("query_doc_drift", params, operation)

    def query_engineering_signals(
        self, *, path: str | None = None, subject: str | None = None,
        signal_family: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query indexed git history, change-context, test-coverage, execution-profile, and priority signals."""
        allowed_families = {"history", "change_context", "test_coverage", "profile", "priority"}
        if signal_family is not None and signal_family not in allowed_families:
            raise ValueError(f"signal_family must be one of {sorted(allowed_families)}")
        if subject is not None:
            LogicalIdentity.parse(subject)
        norm_path = normalize_relative_path(path) if path is not None else None
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        params = {"path": norm_path, "subject": subject, "signal_family": signal_family,
                  "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_engineering_signals", params)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            sources: list[tuple[str, str, Mapping[str, Any]]] = []
            if signal_family in {None, "history", "change_context"}:
                for s in self.indexes.get("precomputed", ()):
                    if s.get("producer", {}).get("query_set") == "history_context":
                        sources.append(("history", "precomputed", s))
                for s in self.indexes.get("history", ()):
                    fam = "change_context" if str(s.get("shard_id", "")).startswith("change") else "history"
                    if signal_family in {None, fam}:
                        sources.append((fam, "history", s))
            if signal_family in {None, "priority"}:
                for s in self.indexes.get("priority", ()):
                    sources.append(("priority", "priority", s))
            if signal_family in {None, "test_coverage", "profile"}:
                for idx_name in ("analysis", "observations", "evidence"):
                    for s in self.indexes.get(idx_name, ()):
                        job_name = str(s.get("producer", {}).get("job", ""))
                        if job_name == "job_test_coverage" and signal_family in {None, "test_coverage"}:
                            sources.append(("test_coverage", idx_name, s))
                        elif job_name == "job_profile_data" and signal_family in {None, "profile"}:
                            sources.append(("profile", idx_name, s))
            if not sources:
                gaps.append("engineering signal shards are unavailable for the requested scope")
            for fam, idx_name, shard in sources:
                self._check_deadline(deadline)
                shard_id = str(shard.get("shard_id", "default"))
                with closing(self._database(shard, deadline)) as database:
                    query = "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                    arguments: list[Any] = []
                    if fam == "profile":
                        filters = []
                        if norm_path is not None:
                            filters.append(
                                "COALESCE(NULLIF(l.path, ''), NULLIF(json_extract(e.payload_json, '$.subject_path'), ''), "
                                "NULLIF(json_extract(e.payload_json, '$.path'), ''), "
                                "json_extract(e.payload_json, '$.source')) = ?")
                            arguments.append(norm_path)
                        if subject is not None:
                            filters.append("(e.identity = ? OR json_extract(e.payload_json, '$.subject_identity') = ?)")
                            arguments.extend((subject, subject))
                        if filters:
                            query += "WHERE " + " AND ".join(filters) + " "
                        # Filter before bounding: reported profile paths are not verified locations.
                        query += "ORDER BY e.identity LIMIT ?"
                        arguments.append(offset + limit + 1)
                    else:
                        query += "ORDER BY e.identity"
                    for row in database.execute(query, arguments):
                        self._check_deadline(deadline)
                        payload = json.loads(row["payload_json"])
                        row_path = row["path"] or payload.get("subject_path") or payload.get("path")
                        if fam == "profile":
                            row_path = row_path or payload.get("source")
                        if norm_path is not None and row_path != norm_path:
                            continue
                        if subject is not None and row["identity"] != subject and payload.get("subject_identity") != subject:
                            continue
                        item = self._entity(row, idx_name)
                        item["shard_id"] = shard_id
                        item["signal_family"] = fam
                        found.append(item)
                    if fam == "profile":
                        gaps.extend(
                            f"{idx_name}/{shard_id}: {row['gap'] or row['area'] + ' coverage is ' + row['status']}"
                            for row in database.execute(
                                "SELECT area, status, gap FROM coverage WHERE status != 'complete' "
                                "ORDER BY area, status, gap"))
                if fam == "profile":
                    gaps.extend(f"{idx_name}/{shard_id}: {gap}" for gap in shard.get("gaps", ()))
            found.sort(key=lambda item: (item["signal_family"], item["identity"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset

        return self._execute("query_engineering_signals", params, operation)

    def query_sca_reachability(
        self, *, subject: str | None = None, package: str | None = None,
        advisory_id: str | None = None, reachability_class: str | None = None,
        limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query indexed dependency advisories and SCA/FFI symbol reachability records."""
        for label, val in (("package", package), ("advisory_id", advisory_id), ("reachability_class", reachability_class)):
            if val is not None and (not isinstance(val, str) or not val or len(val) > 512):
                raise ValueError(f"invalid SCA reachability filter: {label}")
        if subject is not None:
            LogicalIdentity.parse(subject)
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        params = {"subject": subject, "package": package, "advisory_id": advisory_id,
                  "reachability_class": reachability_class, "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_sca_reachability", params)
        offset = self._offset(cursor, request_hash)

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            adv_shards = [
                ("precomputed", s) for s in self.indexes.get("precomputed", ())
                if s.get("producer", {}).get("query_set") == "dependency_advisories"
            ]
            dep_shards = [
                (idx_name, s)
                for idx_name in ("observations", "inventory")
                for s in self.indexes.get(idx_name, ())
                if s.get("producer", {}).get("job") == "job_dependency_intelligence"
            ]
            if not adv_shards and not dep_shards:
                gaps.append("dependency advisory and SCA reachability shards are unavailable")
            for idx_name, shard in (*adv_shards, *dep_shards):
                self._check_deadline(deadline)
                shard_id = str(shard.get("shard_id", "default"))
                with closing(self._database(shard, deadline)) as database:
                    for row in database.execute(
                        "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                        "ORDER BY e.identity"
                    ):
                        payload = json.loads(row["payload_json"])
                        res = payload.get("result") if isinstance(payload.get("result"), Mapping) else payload
                        if subject is not None and row["identity"] != subject and payload.get("subject_identity") != subject:
                            continue
                        pkg = str(res.get("package_name") or res.get("package") or res.get("name") or payload.get("name") or "")
                        adv = str(res.get("advisory") or res.get("advisory_id") or payload.get("advisory_id") or "")
                        rc = str(res.get("reachability") or res.get("reachability_class")
                                 or payload.get("reachability") or payload.get("reachability_class") or "")
                        if package is not None and package not in {pkg, str(res.get("purl") or "")}:
                            continue
                        if advisory_id is not None and adv != advisory_id:
                            continue
                        if reachability_class is not None and rc != reachability_class:
                            continue
                        item = self._entity(row, idx_name)
                        item["shard_id"] = shard_id
                        found.append(item)
            found.sort(key=lambda item: (item["identity"], item["shard_id"]))
            return found[offset:offset + limit], gaps, len(found) > offset + limit, offset

        return self._execute("query_sca_reachability", params, operation)

    def query_sanitizer_readiness(
        self, *, build_unit: str | None = None, sanitizer: str | None = None,
        status: str | None = None, limit: int = 20, cursor: str | None = None,
    ) -> dict[str, Any]:
        """Query indexed build evidence, not runtime verification; never open protected workspaces."""
        for label, val in (("build_unit", build_unit), ("sanitizer", sanitizer), ("status", status)):
            if val is not None and (not isinstance(val, str) or not val or len(val) > 512):
                raise ValueError(f"invalid sanitizer readiness filter: {label}")
        if not 1 <= limit <= self.limits.max_results:
            raise ValueError("result limit exceeds bound")
        params = {"build_unit": build_unit, "sanitizer": sanitizer, "status": status,
                  "limit": limit, "cursor": cursor}
        request_hash = self._request_hash("query_sanitizer_readiness", params)
        state = self._cursor_state(cursor, request_hash)
        offset = state["offset"]
        position = state.get("position", ["", "", ""])
        if (not isinstance(position, list) or len(position) != 3
                or any(not isinstance(part, str) for part in position)
                or (offset and "position" not in state)):
            raise ValueError("invalid sanitizer-query cursor; restart pagination")
        aliases = {"asan": "address", "ubsan": "undefined"}
        selected_sanitizer = aliases.get(sanitizer.lower(), sanitizer.lower()) if sanitizer else None

        def operation(deadline: float):
            found: list[dict[str, Any]] = []
            gaps: list[str] = []
            readiness_coverage = False
            shards = [(index, shard) for index in ("build_security", "inventory")
                      for shard in self.indexes.get(index, ())]
            for index, shard in shards:
                self._check_deadline(deadline)
                shard_id = str(shard.get("shard_id", "default"))
                with closing(self._database(shard, deadline)) as database:
                    coverage = list(database.execute(
                        "SELECT area, status, gap FROM coverage WHERE area='sanitizer-readiness'"
                        if index == "inventory" else "SELECT area, status, gap FROM coverage"))
                    if index == "inventory" and coverage:
                        readiness_coverage = True
                    gaps.extend(f"{index}/{shard_id}: {row['status']}: {row['gap']}"
                                for row in coverage if row["status"] != "complete")
                    if [index, shard_id] < position[:2]:
                        continue
                    clauses, values = [], []
                    if index == "inventory":
                        clauses += ["json_extract(e.payload_json, '$.job_id')='job_sanitizer_build'",
                                    "json_extract(e.payload_json, '$.record_type')='sanitizer_readiness'"]
                    if [index, shard_id] == position[:2]:
                        clauses.append("e.identity > ?")
                        values.append(position[2])
                    if build_unit is not None:
                        clauses.append("COALESCE(json_extract(e.payload_json, '$.build_unit_id'), "
                                       "json_extract(e.payload_json, '$.build_action_id'), "
                                       "json_extract(e.payload_json, '$.project')) = ?")
                        values.append(build_unit)
                    if selected_sanitizer is not None:
                        clauses.append("LOWER(json_extract(e.payload_json, '$.sanitizer')) IN (?, ?)")
                        short = {"address": "asan", "undefined": "ubsan"}.get(selected_sanitizer, selected_sanitizer)
                        values.extend((selected_sanitizer, short))
                    if status is not None:
                        clauses.append("COALESCE(json_extract(e.payload_json, '$.status'), "
                                       "json_extract(e.payload_json, '$.readiness')) = ?")
                        values.append(status)
                    for row in database.execute(
                        "SELECT e.*, l.* FROM entities e LEFT JOIN locations l ON l.entity_id=e.identity "
                        + ("WHERE " + " AND ".join(clauses) if clauses else "")
                        + " ORDER BY e.identity LIMIT ?", [*values, limit + 1]):
                        self._check_deadline(deadline)
                        item = self._entity(row, index)
                        item["shard_id"] = shard_id
                        found.append(item)
            if not readiness_coverage:
                gaps.append("per-unit sanitizer readiness is unavailable")
            found.sort(key=lambda item: (item["index"], item["shard_id"], item["identity"]))
            page = found[:limit]
            for item in page:
                gaps.extend(str(gap) for gap in item["payload"].get("gaps", ()))
            page_cursors = [self._cursor(offset, request_hash, position=position)]
            page_cursors.extend(self._cursor(
                offset + ordinal, request_hash, position=[item["index"], item["shard_id"], item["identity"]])
                for ordinal, item in enumerate(page, 1))
            return page, gaps, len(found) > limit, offset, False, page_cursors

        return self._execute("query_sanitizer_readiness", params, operation)
