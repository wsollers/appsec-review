"""The real ``EvidenceView``: bounded questions over the attempt's admitted index shards (T-107).

Design: docs/architecture/dfd-and-threat-model-generation.md sections 3, 3.1, 4.1 and 7. This is the
only threat-model module that touches run data. It never reads the target tree, never reads another
job's ``latest.json`` itself and never opens a shard that is not bound in an admitted handoff.

How a read is admitted
    Every handoff comes from ``indexing.store.accepted_handoff``, which is
    ``runtime.consume.accepted_upstream(..., required=False)`` plus ``verify_handoff``. Inside the
    runner's unit scope that resolves the claim's pin for a producer the job's contract declares, and
    an undeclared producer fails there. Every shard is opened with ``indexing.store.open_shard``,
    whose ``runtime.inputs.observe_shard`` records the read receipt and refuses a shard of an
    undeclared output kind, one not bound in the supplied handoff, or one whose bytes changed. The
    view repeats the binding and byte checks itself, so they also hold outside a runner scope (unit
    tests, operator tooling), where ``accepted_upstream`` falls back to the hash-verified pointer and
    ``observe_shard`` records nothing.

Which shards answer for an output kind
    The producer's own shards (``producer.job``) listed by the verified manifests its handoff names,
    owned by the output kind under ``runtime.datasets.shard_owner`` applied to the dataset contract
    pinned in the producing attempt's claim (``runtime.inputs.producer_contract``). No shard is
    matched by name. A shard of the producer that no declaration owns is an error, as it is at
    admission.

Shard layout relied on (``retrieval/index.py``): ``entities(identity, kind, native_id, name, text,
payload_json)`` (:279-282), ``locations(entity_id, path, file_sha256, start_byte, end_byte,
start_line, end_line, ...)`` (:283-292), ``relations(relation_id, kind, source_id, target_id, exact,
confidence, ambiguity, payload_json)`` (:293-297) and ``search_fts(identity UNINDEXED, name, path,
text)`` with the ``unicode61`` tokenizer (:302-304). The tree-sitter producer writes
``text = "<node type> <written name>"`` (``jobs/job_tree_sitter_ast/normalize.py:130-133``).

Records
    ``entity_id`` is ``entities.identity`` exactly as stored; a relation's is its stored
    ``relations.relation_id`` (already derived by the producer from the relation type, source id,
    target id, exactness and ambiguity, ``retrieval/model.py:223-227``). ``payload`` is the decoded
    ``payload_json``: JSON objects, arrays, strings, integers, booleans, ``null`` and finite numbers
    pass through; a non-finite number (``NaN``, ``Infinity``, an overflowing literal) becomes
    ``None``; a payload that is not a JSON object becomes ``{}``. A relation's payload is its stored
    payload with ``source_id`` and ``target_id`` set from the relation's columns (the columns win
    over equally named payload keys). ``span`` is built from the location row when it forms a valid
    ``SourceSpan`` and is otherwise ``None``; a relation has none. ``content_sha256`` is always
    ``None``: the shard schema stores no per-entity content digest.

Entity or relation
    ``entities(..., kind)`` looks ``kind`` up in each selected shard's entity table first; only when
    that shard holds no entity of the kind does it list the shard's relations of that type.

Cost
    Each query re-verifies the digest of every shard it opens. A caller that asks many questions
    (one ``search_calls`` per catalogued callee) should hold
    ``storage.validation.validation_scope(run_root)`` around them, which hashes an unchanged file
    once.

A view caches handoffs and shard ownership for its lifetime. Build one per unit handler; it is not
meant to be shared between threads.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from appsec_review.indexing.store import accepted_handoff, handoff_manifests, open_shard
from appsec_review.runtime.consume import UpstreamIntegrityError
from appsec_review.runtime.datasets import shard_owner
from appsec_review.runtime.inputs import producer_contract
from appsec_review.runtime.selection import resolved_job_is_enabled
from appsec_review.storage.shared import safe_path
from appsec_review.storage.validation import observed_digest, validation_scope
from appsec_review.threat_model.contract import EvidenceRecord, EvidenceRef, InputState, Publication, SourceSpan
from appsec_review.threat_model.view import InputStatus, Page

DECLARED_INPUTS: tuple[tuple[str, str], ...] = (
    ("job_target_catalog", "build_units"),
    ("job_target_catalog", "components"),
    ("job_target_catalog", "source_files"),
    ("job_artifact_indexing", "artifact_catalog"),
    ("job_artifact_indexing", "artifact_relationships"),
    ("job_language_build", "build_actions"),
    ("job_cpp_compiled_analysis", "cpp_build_graph"),
    ("job_code_graph_index", "code_graph_facts"),
    ("job_tree_sitter_ast", "tree_sitter_ast"),
    ("job_review_prioritization", "priority_items"),
)
SYNTAX_INPUT = ("job_tree_sitter_ast", "tree_sitter_ast")

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ASCII_TOKEN = re.compile(r"[A-Za-z0-9]")
_CONTROL = re.compile(r"[\x00-\x1f]")
_ENTITY_COLUMNS = ("e.identity, e.kind, e.name, e.payload_json, l.path, l.file_sha256, l.start_line, l.end_line, "
                   "l.start_byte, l.end_byte")
_ENTITIES = f"SELECT {_ENTITY_COLUMNS} FROM entities e LEFT JOIN locations l ON l.entity_id = e.identity"
_RELATIONS = "SELECT relation_id, kind, source_id, target_id, payload_json FROM relations"
_CALL = ("e.kind = 'ast_node' AND json_extract(e.payload_json, '$.syntax.category') = 'call_expression' "
         "AND json_extract(e.payload_json, '$.syntax.written_name') = ?")
_CALLS_FTS = (f"SELECT {_ENTITY_COLUMNS} FROM search_fts JOIN entities e ON e.identity = search_fts.identity "
              f"LEFT JOIN locations l ON l.entity_id = e.identity WHERE search_fts MATCH ? AND {_CALL} "
              "ORDER BY e.identity LIMIT ?")
_CALLS_SCAN = f"{_ENTITIES} WHERE {_CALL} ORDER BY e.identity LIMIT ?"


@dataclass(frozen=True, slots=True)
class _Producer:
    """One admitted handoff with the shards its pinned dataset contract assigns to each output kind."""
    sha256: str
    coverage_disposition: str
    gap_count: int
    artifacts: Mapping[str, str]
    owned: Mapping[str, tuple[Mapping[str, Any], ...]]


def _shard_id(shard: Mapping[str, Any]) -> str:
    return str(shard.get("shard_id", "default"))


def _clean(value: Any) -> Any:
    """Decoded JSON restricted to what the contract freezes; a non-finite number becomes ``None``."""
    if isinstance(value, dict):
        return {str(key): _clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _payload(text: Any) -> dict[str, Any]:
    value = _clean(json.loads(str(text), parse_constant=lambda _name: None))
    return value if isinstance(value, dict) else {}


def _span(row: sqlite3.Row) -> SourceSpan | None:
    if row["path"] is None or row["file_sha256"] is None or row["start_line"] is None or row["end_line"] is None:
        return None
    try:
        return SourceSpan(str(row["path"]), str(row["file_sha256"]), int(row["start_line"]), int(row["end_line"]),
                          None if row["start_byte"] is None else int(row["start_byte"]),
                          None if row["end_byte"] is None else int(row["end_byte"]))
    except ValueError:
        return None  # a location the contract cannot express is not a citable span


def _fts_phrase(name: str) -> str:
    return '{text} : "' + name.replace('"', '""') + '"'


class IndexEvidenceView:
    """``EvidenceView`` over the accepted shards of the declared inputs of one attempt.

    ``upstream_handoffs`` is the claim's admitted ``{producer: handoff sha256}`` mapping
    (``unit.job.upstream_handoffs``). When it is given, a producer it does not name is ``absent``
    without any lookup and a handoff whose digest differs from the pin is refused; when it is
    ``None`` the view takes whatever ``accepted_upstream`` admits (the pins of the active runner
    scope, or the verified pointer outside one). ``inputs`` bounds what may be asked at all.
    """

    def __init__(self, run_root: Path, upstream_handoffs: Mapping[str, str] | None = None, *,
                 inputs: Iterable[tuple[str, str]] = DECLARED_INPUTS) -> None:
        self.run_root = Path(run_root).resolve()
        self._pins = None if upstream_handoffs is None else dict(upstream_handoffs)
        self._inputs = frozenset((str(producer), str(output_kind)) for producer, output_kind in inputs)
        self._producers: dict[str, _Producer | None] = {}
        self._disabled_jobs: frozenset[str] | None = None

    # -- admission -------------------------------------------------------------------------------

    def _declared(self, producer: str, output_kind: str) -> None:
        if (producer, output_kind) not in self._inputs:
            raise ValueError(f"undeclared threat-model input: {producer}/{output_kind}")

    def _producer(self, producer: str) -> _Producer | None:
        if producer in self._producers:
            return self._producers[producer]
        found: _Producer | None = None
        accepted = None if self._pins is not None and producer not in self._pins \
            else accepted_handoff(self.run_root, producer)
        if accepted is not None:
            if self._pins is not None and accepted.sha256 != self._pins[producer]:
                raise UpstreamIntegrityError(
                    f"accepted {producer} handoff is not the one this attempt admitted; "
                    "read it inside the attempt's runtime scope")
            handoff = accepted.handoff
            declarations = producer_contract(self.run_root, handoff)
            shards: dict[tuple[str, str, str], Mapping[str, Any]] = {}
            for manifest in handoff_manifests(self.run_root, handoff):
                for shard in manifest["document"]["indexes"]:
                    if shard.get("producer", {}).get("job") == producer:
                        shards[(str(shard["name"]), _shard_id(shard), str(shard["sha256"]))] = shard
            owned: dict[str, list[Mapping[str, Any]]] = {}
            for key in sorted(shards):
                owner = shard_owner(declarations, key[0], key[1])
                owned.setdefault(owner.output_kind, []).append(shards[key])
            coverage = handoff["coverage"]
            found = _Producer(
                accepted.sha256, str(coverage["disposition"]), int(coverage["gap_count"]),
                MappingProxyType({str(item["path"]): str(item["sha256"]) for item in handoff["artifacts"]}),
                MappingProxyType({kind: tuple(items) for kind, items in owned.items()}))
        self._producers[producer] = found
        return found

    def _disabled(self, producer: str) -> bool:
        """Whether the run's frozen resolved configuration disables ``producer`` (unknown is ``False``)."""
        if self._disabled_jobs is None:
            disabled = set()
            try:
                document = json.loads(safe_path(self.run_root, "data/configuration/resolved.json").read_bytes())
                jobs = document["jobs"]
                for name, value in jobs.items():
                    try:
                        if isinstance(value, Mapping) and not resolved_job_is_enabled(str(name), value):
                            disabled.add(str(name))
                    except ValueError:
                        continue
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                disabled = set()
            self._disabled_jobs = frozenset(disabled)
        return producer in self._disabled_jobs

    def _open(self, found: _Producer, shard: Mapping[str, Any]) -> sqlite3.Connection:
        relative, digest = str(shard["relative_path"]), str(shard["sha256"])
        if found.artifacts.get(relative) != digest:
            raise UpstreamIntegrityError(f"index shard is not bound to its admitted handoff: {relative}")
        with validation_scope(self.run_root):
            path = safe_path(self.run_root, relative)
            if not path.is_file() or path.is_symlink() or observed_digest(self.run_root, path) != digest:
                raise UpstreamIntegrityError(f"index shard bytes changed after acceptance: {relative}")
            database = open_shard(self.run_root, shard)
        database.execute("PRAGMA query_only=ON")
        return database

    # -- EvidenceView ----------------------------------------------------------------------------

    def input_status(self, producer: str, output_kind: str) -> InputStatus:
        """State of one declared input.

        ``absent``: the attempt admitted no handoff of the producer. ``disabled``: no handoff, or a
        handoff that published no shard of the output kind, and the run's frozen
        ``data/configuration/resolved.json`` sets the producer's ``settings.enabled`` to false (the
        rule of ``runtime.selection.resolved_job_is_enabled``); when that file is missing or
        unreadable the answer is ``absent``/``empty``, never a guess. ``empty``: handoff admitted,
        no shard owned by the output kind. ``partial``: the handoff's ``coverage.disposition`` is
        not ``complete`` or its ``coverage.gap_count`` (the count joined from its outcomes) is not
        zero. ``not_registered`` is never returned: a handler cannot tell an unregistered producer
        from an unsupplied one without the job registry.
        """
        self._declared(producer, output_kind)
        found = self._producer(producer)
        if found is None:
            return InputStatus(InputState.DISABLED if self._disabled(producer) else InputState.ABSENT)
        if not found.owned.get(output_kind):
            state = InputState.DISABLED if self._disabled(producer) else InputState.EMPTY
        elif found.coverage_disposition != "complete" or found.gap_count:
            state = InputState.PARTIAL
        else:
            state = InputState.READ
        return InputStatus(state, found.sha256, found.coverage_disposition, found.gap_count)

    def entities(self, producer: str, output_kind: str, kind: str, *, limit: int) -> Page:
        """Entities (or, failing those, relations) of ``kind`` in ``(entity_id, shard sha256)`` order."""
        self._declared(producer, output_kind)
        bound = self._limit(limit)
        if not isinstance(kind, str) or not kind:
            return Page()
        found = self._producer(producer)
        records: list[EvidenceRecord] = []
        for shard in () if found is None else found.owned.get(output_kind, ()):
            publication = self._publication(producer, output_kind, shard)
            with closing(self._open(found, shard)) as database:
                rows = database.execute(f"{_ENTITIES} WHERE e.kind = ? ORDER BY e.identity LIMIT ?",
                                        (kind, bound + 1)).fetchall()
                if rows:
                    records.extend(self._entity(row, publication) for row in rows)
                    continue
                records.extend(self._relation(row, publication) for row in database.execute(
                    f"{_RELATIONS} WHERE kind = ? ORDER BY relation_id LIMIT ?", (kind, bound + 1)))
        return self._page(records, bound)

    def search_calls(self, name: str, *, limit: int) -> Page:
        """Tree-sitter ``call_expression`` nodes whose ``syntax.written_name`` is exactly ``name``.

        ``name`` is data: it is only ever a bound SQL parameter or a quoted FTS5 phrase. A name with
        an ASCII letter or digit and no control character is found through ``search_fts`` (the
        phrase is a superset filter) and then matched exactly with ``json_extract``; any other name
        is matched by ``json_extract`` alone. Every returned record is checked again on its decoded
        payload, so a non-exact match is never returned.
        """
        bound = self._limit(limit)
        if not isinstance(name, str) or not name:
            return Page()
        found = self._producer(SYNTAX_INPUT[0]) if SYNTAX_INPUT in self._inputs else None
        indexed = bool(_ASCII_TOKEN.search(name)) and not _CONTROL.search(name)
        records: list[EvidenceRecord] = []
        overflow = False
        for shard in () if found is None else found.owned.get(SYNTAX_INPUT[1], ()):
            publication = self._publication(*SYNTAX_INPUT, shard)
            with closing(self._open(found, shard)) as database:
                rows = (database.execute(_CALLS_FTS, (_fts_phrase(name), name, bound + 1)) if indexed
                        else database.execute(_CALLS_SCAN, (name, bound + 1))).fetchall()
            overflow = overflow or len(rows) > bound
            for row in rows:
                record = self._entity(row, publication)
                syntax = record.payload.get("syntax")
                if isinstance(syntax, Mapping) and syntax.get("category") == "call_expression" \
                        and syntax.get("written_name") == name:
                    records.append(record)
        page = self._page(records, bound)
        return Page(page.records, page.truncated or overflow)

    # -- citation resolver -----------------------------------------------------------------------

    def resolves(self, ref: EvidenceRef) -> bool:
        """Whether a citation still points at admitted evidence. A bad reference is ``False``.

        ``index_entity``: the publication names a declared input, its shard is one this view admitted
        for that output kind with the same index, shard id and SHA-256, the entity (or relation)
        with that identity exists there with the same kind, the reference's locator (when it has
        one) equals the locator of the entity's location, and the reference carries no content
        digest (the shards store none to compare). ``run_artifact``: ``entity_id`` is a run-relative
        path bound, with ``publication.sha256``, in the admitted handoff of the declared producer
        ``publication.job``; the artifact's bytes are not re-read. An integrity failure of admitted
        material (a changed shard or handoff) is not a bad reference and raises.
        """
        if not isinstance(ref, EvidenceRef) or not isinstance(ref.publication, Publication) \
                or not isinstance(ref.entity_id, str) or not isinstance(ref.entity_kind, str):
            return False
        publication = ref.publication
        if not isinstance(publication.sha256, str) or not _SHA256.fullmatch(publication.sha256):
            return False
        if ref.kind == "run_artifact":
            if publication.job not in {producer for producer, _ in self._inputs}:
                return False
            found = self._producer(publication.job)
            return found is not None and found.artifacts.get(ref.entity_id) == publication.sha256
        if ref.kind != "index_entity" or (publication.job, publication.output_kind) not in self._inputs \
                or ref.content_sha256 is not None or (ref.locator is not None and not isinstance(ref.locator, str)):
            return False
        found = self._producer(publication.job)
        shard = None if found is None else next(
            (item for item in found.owned.get(publication.output_kind, ())
             if str(item["sha256"]) == publication.sha256 and str(item["name"]) == publication.index
             and _shard_id(item) == publication.shard_id), None)
        if found is None or shard is None:
            return False
        with closing(self._open(found, shard)) as database:
            row = database.execute(f"{_ENTITIES} WHERE e.identity = ?", (ref.entity_id,)).fetchone()
            if row is not None:
                span = _span(row)
                return row["kind"] == ref.entity_kind and (
                    ref.locator is None or (span is not None and span.locator == ref.locator))
            relation = database.execute(f"{_RELATIONS} WHERE relation_id = ?", (ref.entity_id,)).fetchone()
        return relation is not None and relation["kind"] == ref.entity_kind and ref.locator is None

    # -- records ---------------------------------------------------------------------------------

    @staticmethod
    def _limit(limit: int) -> int:
        if type(limit) is not int or limit < 1:
            raise ValueError("query limit must be a positive integer")
        return limit

    @staticmethod
    def _publication(producer: str, output_kind: str, shard: Mapping[str, Any]) -> Publication:
        return Publication(producer, output_kind, str(shard["name"]), _shard_id(shard), str(shard["sha256"]))

    @staticmethod
    def _entity(row: sqlite3.Row, publication: Publication) -> EvidenceRecord:
        return EvidenceRecord(str(row["identity"]), str(row["kind"]), str(row["name"]), _payload(row["payload_json"]),
                              publication, _span(row), None)

    @staticmethod
    def _relation(row: sqlite3.Row, publication: Publication) -> EvidenceRecord:
        source, target = str(row["source_id"]), str(row["target_id"])
        return EvidenceRecord(str(row["relation_id"]), str(row["kind"]), f"{source} -> {target}",
                              {**_payload(row["payload_json"]), "source_id": source, "target_id": target},
                              publication, None, None)

    @staticmethod
    def _page(records: list[EvidenceRecord], bound: int) -> Page:
        ordered = sorted(records, key=lambda item: (item.entity_id, item.publication.sha256))
        return Page(tuple(ordered[:bound]), len(ordered) > bound)
