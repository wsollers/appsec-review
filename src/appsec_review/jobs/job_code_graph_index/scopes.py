"""Accepted inputs, stage codec, checkpoints and shard publication for ``job_code_graph_index``.

docs/architecture/code-graph-precomputation.md sections 7.1 to 7.4 are normative. Everything here
reads run-owned, hash-verified material only: the accepted ``job_codeql_analysis`` handoff (its
``export.scopes`` index, plan and per-scope export manifests), the accepted retrieval manifest
(clangd, LLVM IR, Clang AST, CodeQL observation and prioritization shards) and the accepted
target bytes the CodeQL plan names. Nothing runs an analyzer or scans a target tree.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.codeql.runtime import GraphExportIntegrityError, load_graph_exports
from appsec_review.graph.contract import (
    ADMISSIBILITY_RULE, CROSS_CHECK_RULE, GRAPH_INDEX, NORMALIZE_RULE, Coverage, Family, GraphFact, GraphSettings,
    Producer,
)
from appsec_review.graph.correlate import CORRELATION_RULE
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import COLUMNS_PATH, CoverageRow
from appsec_review.indexing.store import ShardSet, accepted_handoff, handoff_manifests, open_shard, shard_key
from appsec_review.jobs.job_codeql_analysis.job import GRAPH_EXPORTS_SCHEMA
from appsec_review.retrieval import (
    EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord, SourceLocation,
)
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json, canonical_json, file_sha256

JOB_ID = "job_code_graph_index"
CODEQL_JOB = "job_codeql_analysis"
PRIORITY_JOB = "job_review_prioritization"
STAGE_SCHEMA = "appsec-review/code-graph-stage/1"
CHECKPOINT_SCHEMA = "appsec-review/code-graph-checkpoint/1"
SCOPE_IDENTITY_SCHEMA = "appsec-review/code-graph-scope/1"
SUCCEEDED = "SUCCEEDED"
RULES = {"normalize": NORMALIZE_RULE, "cross_check": CROSS_CHECK_RULE, "correlation": CORRELATION_RULE,
         "admissibility": ADMISSIBILITY_RULE}
SECONDARY_PRODUCERS = (Producer.CLANGD, Producer.LLVM_IR, Producer.CLANG_AST)
# Bound on the coverage-gap lines naming individual broken SARIF correlations per scope.
MAX_BROKEN_GAPS = 20


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def implementation_identity() -> str:
    """Hash of every module whose behavior shapes a published graph shard."""
    source = Path(__file__).resolve()
    package = source.parents[2]
    files = [*sorted(source.parent.glob("*.py")), *sorted((package / "graph").glob("*.py")),
             package / "codeql" / "runtime.py", package / "jobs" / "job_codeql_analysis" / "sarif.py"]
    value = hashlib.sha256()
    for path in files:
        value.update(path.relative_to(package).as_posix().encode() + b"\0" + path.read_bytes())
    return value.hexdigest()


def artifact(run_root: Path, path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    if run_root.resolve() not in resolved.parents or not resolved.is_file() or path.is_symlink():
        raise IntegrityError(f"code-graph artifact is outside the run or missing: {path.name}")
    return {"path": resolved.relative_to(run_root.resolve()).as_posix(), "sha256": file_sha256(resolved),
            "size_bytes": resolved.stat().st_size}


def read_artifact(run_root: Path, identity: Mapping[str, Any]) -> Any:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise IntegrityError(f"run-owned artifact is unavailable: {identity.get('path')}")
    if file_sha256(path) != identity.get("sha256"):
        raise IntegrityError(f"run-owned artifact changed: {identity.get('path')}")
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- accepted CodeQL inputs


def load_codeql_inputs(run_root: Path, source_fingerprint: str) -> dict[str, Any]:
    """The accepted CodeQL handoff's per-scope export records, joined with the plan's scope files.

    Only material bound to the accepted handoff is read: its ``export.scopes`` index artifact, its
    result and plan, and per scope the export manifest identity the handoff carries. The export job's
    own ``export-checkpoint.json`` is never consulted.
    """
    accepted = accepted_handoff(run_root, CODEQL_JOB)
    if accepted is None:
        raise IntegrityError("an accepted job_codeql_analysis handoff is required")
    handoff = accepted.handoff
    if handoff.get("job_id") != CODEQL_JOB:
        raise IntegrityError("accepted CodeQL handoff names a different producer")
    if handoff.get("source_fingerprint") != source_fingerprint:
        raise IntegrityError("accepted CodeQL handoff is bound to a different target snapshot")
    bound = {str(item.get("path")): str(item.get("sha256")) for item in handoff.get("artifacts", ())
             if isinstance(item, Mapping)}

    def read_bound(identity: Any, what: str) -> Any:
        if not isinstance(identity, Mapping) or bound.get(str(identity.get("path"))) != identity.get("sha256"):
            raise IntegrityError(f"accepted CodeQL handoff does not bind its {what}")
        return read_artifact(run_root, identity)

    export_output = (handoff.get("outputs") or {}).get("export.scopes")
    if not isinstance(export_output, Mapping):
        raise IntegrityError("accepted CodeQL handoff publishes no export.scopes output")
    index = read_bound(export_output.get("artifact"), "graph export index")
    if not isinstance(index, Mapping) or index.get("schema") != GRAPH_EXPORTS_SCHEMA:
        raise IntegrityError("accepted CodeQL graph export index schema is unsupported")
    result_path = str((handoff.get("resolving_paths") or {}).get("result", ""))
    result = read_bound({"path": result_path, "sha256": bound.get(result_path)}, "result")
    plan_identity = ((result.get("outputs") or {}).get("plan.inventory") or {}).get("plan")
    plan = read_bound(plan_identity, "plan")
    plan_scopes = {str(item["scope_id"]): item for item in plan.get("scopes", ())}
    records: list[dict[str, Any]] = []
    for item in index.get("exports", ()):
        scope_id = str(item.get("scope_id") or "")
        planned = plan_scopes.get(scope_id)
        if planned is None:
            raise IntegrityError(f"CodeQL export scope {scope_id or '<unnamed>'} is absent from the accepted plan")
        for key in ("language", "root", "build_unit_id"):
            if item.get(key) != planned.get(key):
                raise IntegrityError(f"CodeQL export scope {scope_id} {key} differs from the accepted plan")
        status = str(item.get("export_status") or "")
        record: dict[str, Any] = {
            "scope_id": scope_id, "language": str(planned["language"]), "root": str(planned.get("root") or "."),
            "build_unit_id": planned.get("build_unit_id"), "database_identity": item.get("database_identity"),
            "export_status": status, "reason": item.get("reason"),
            "export_gaps": [str(gap) for gap in item.get("gaps", ())],
            "files": sorted(({"path": str(entry["path"]), "sha256": str(entry["sha256"])}
                             for entry in planned.get("files", ())), key=lambda entry: entry["path"]),
        }
        if status == SUCCEEDED:
            manifest = item.get("export_manifest")
            if not isinstance(manifest, Mapping) or bound.get(str(manifest.get("path"))) != manifest.get("sha256"):
                raise IntegrityError(f"CodeQL export manifest of {scope_id} is not bound to the accepted handoff")
            pack = item.get("export_pack")
            if not isinstance(pack, Mapping) or not pack.get("tree_sha256") or not pack.get("columns_sha256"):
                raise IntegrityError(f"CodeQL export pack identity of {scope_id} is missing")
            record["export_manifest"] = {"path": str(manifest["path"]), "sha256": str(manifest["sha256"])}
            record["export_pack"] = dict(pack)
        records.append(record)
    if len({item["scope_id"] for item in records}) != len(records):
        raise IntegrityError("accepted CodeQL export index repeats a scope")
    return {"handoff": {"path": accepted.path, "sha256": accepted.sha256},
            "scopes": sorted(records, key=lambda item: item["scope_id"])}


def verify_exports(run_root: Path, record: Mapping[str, Any], settings: GraphSettings) -> dict[str, Any]:
    """Verify one scope's export directory against the accepted manifest identity; return its exports."""
    manifest = record["export_manifest"]
    path = (run_root / str(manifest["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise IntegrityError(f"CodeQL graph export manifest of {record['scope_id']} is missing")
    if file_sha256(path) != manifest["sha256"]:
        raise IntegrityError(f"CodeQL graph export manifest of {record['scope_id']} differs from the accepted "
                             "handoff")
    columns = hashlib.sha256(COLUMNS_PATH.read_bytes()).hexdigest()
    if record["export_pack"].get("columns_sha256") != columns:
        raise IntegrityError(f"CodeQL graph export of {record['scope_id']} was produced for a different "
                             "columns.json contract")
    try:
        return load_graph_exports(path.parent, bytes_limit=settings.max_export_bytes)
    except (GraphExportIntegrityError, ValueError) as error:
        raise IntegrityError(f"CodeQL graph export of {record['scope_id']}: {error}") from error


def scope_sources(target_root: Path | None, files: Sequence[Mapping[str, Any]]) -> dict[str, SourceFile]:
    """Accepted source bytes of one scope, each verified against the planned SHA-256."""
    if target_root is None:
        raise IntegrityError("code-graph indexing requires the accepted target root")
    root = Path(target_root).resolve()
    sources: dict[str, SourceFile] = {}
    for item in files:
        relative = PurePosixPath(str(item["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise IntegrityError(f"CodeQL scope file path is not target-relative: {relative}")
        path = root.joinpath(*relative.parts)
        if not path.is_file() or path.is_symlink():
            raise IntegrityError(f"accepted source file is missing: {relative}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise IntegrityError(f"accepted source file changed after acceptance: {relative}")
        sources[relative.as_posix()] = SourceFile(str(item["sha256"]), data)
    return sources


def codeql_version(run_root: Path) -> str:
    """The CodeQL CLI version from the run-bound resolved configuration, or ``unknown``."""
    destination = run_root / "data" / "configuration"
    try:
        manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        resolved = destination / "resolved.json"
        if file_sha256(resolved) != manifest.get("resolved_sha256"):
            raise IntegrityError("run-owned resolved configuration hash mismatch")
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unknown"
    for table in ("jobs", "pending_jobs"):
        version = (((document.get(table) or {}).get(CODEQL_JOB) or {}).get("settings") or {}).get("version")
        if isinstance(version, str) and version:
            return version
    return "unknown"


# --------------------------------------------------------------------------- accepted secondary shards


def shard_ref(shard: Mapping[str, Any]) -> dict[str, str]:
    return {"name": str(shard["name"]), "shard_id": str(shard.get("shard_id", "default")),
            "sha256": str(shard["sha256"])}


def secondary_producer(shard: Mapping[str, Any]) -> Producer | None:
    producer = shard.get("producer") or {}
    shard_id = str(shard.get("shard_id", ""))
    if shard.get("name") != "analysis":
        return None
    if producer.get("job") == "job_cpp_symbol_index" and shard_id.startswith("clangd-") \
            and not shard_id.startswith("clangd-coverage-"):
        return Producer.CLANGD
    if producer.get("job") == "job_cpp_compiled_analysis" and producer.get("branch") == "ir":
        return Producer.LLVM_IR
    if producer.get("job") == "job_cpp_compiled_analysis" and producer.get("branch") == "ast":
        return Producer.CLANG_AST
    return None


SECONDARY_JOBS = ("job_cpp_symbol_index", "job_cpp_compiled_analysis")


def restored_secondary(run_root: Path, present: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """clangd, IR and AST shards an accepted producer published but the accepted manifest dropped.

    ``job_codeql_analysis`` publishes a manifest of its own shards only (its siblings are referenced
    as verified upstream manifests, not composed), so by the time this job runs the accepted manifest
    no longer lists the C/C++ secondary shards. They are taken back from the producers' own accepted
    handoffs, whose manifests are re-verified, exactly as ``job_review_data_indexing`` restores dropped
    shards; only shards the handoff's own job produced are eligible.
    """
    by_key = {shard_key(item) for item in present}
    restored: dict[tuple[str, str], dict[str, Any]] = {}
    for job_id in SECONDARY_JOBS:
        accepted = accepted_handoff(run_root, job_id)
        if accepted is None:
            continue
        for manifest in handoff_manifests(run_root, accepted.handoff):
            for shard in manifest["document"].get("indexes", ()):
                if (shard.get("producer") or {}).get("job") != job_id or secondary_producer(shard) is None:
                    continue
                key = shard_key(shard)
                if key not in by_key and key not in restored:
                    restored[key] = dict(shard)
    return [restored[key] for key in sorted(restored)]


def assign_secondary(run_root: Path, shards: Iterable[Mapping[str, Any]],
                     scopes: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Give each accepted clangd/IR/AST shard to exactly one CodeQL scope.

    A shard belongs to the scope whose planned files hold the most of the shard's located paths (ties by
    scope id). A shard never serves two scopes, so a cross-check verdict can never mix evidence from
    two build units. A shard that touches no scope file is not used.
    """
    files = {str(scope["scope_id"]): {str(item["path"]) for item in scope["files"]}
             for scope in scopes if scope["export_status"] == SUCCEEDED}
    assigned: dict[str, dict[str, list[dict[str, Any]]]] = {
        scope_id: {producer.value: [] for producer in SECONDARY_PRODUCERS} for scope_id in files}
    for shard in sorted(shards, key=shard_key):
        producer = secondary_producer(shard)
        if producer is None:
            continue
        with open_shard(run_root, shard) as database:
            paths = {str(row[0]) for row in database.execute("SELECT DISTINCT path FROM locations")}
        overlap = sorted(((-len(paths & members), scope_id) for scope_id, members in files.items()
                          if paths & members))
        if overlap:
            assigned[overlap[0][1]][producer.value].append(dict(shard))
    return assigned


def observation_shards(shard_set: ShardSet, scope: Mapping[str, Any]) -> list[dict[str, Any]]:
    prefix = f"codeql-{scope['language']}-{scope['scope_id']}-"
    return [dict(shard) for shard in shard_set.select(index="observations", job=CODEQL_JOB, prefix=prefix)]


def priority_shards(shard_set: ShardSet) -> list[dict[str, Any]]:
    return [dict(shard) for shard in shard_set.select(index="priority", job=PRIORITY_JOB)]


# --------------------------------------------------------------------------- scope identity and checkpoints


def scope_identity(scope: Mapping[str, Any], *, snapshot: str, catalog_sha256: str, columns_sha256: str,
                   settings: GraphSettings, tool_version: str, implementation: str) -> str:
    """Section 7.3: everything a scope's graph shards depend on, and nothing else."""
    inputs = scope["inputs"]
    return digest({
        "schema": SCOPE_IDENTITY_SCHEMA, "target_snapshot": snapshot, "scope_id": scope["scope_id"],
        "language": scope["language"], "root": scope["root"], "build_unit_id": scope["build_unit_id"],
        "database_identity": scope["database_identity"], "export_status": scope["export_status"],
        "reason": scope.get("reason"), "export_gaps": scope.get("export_gaps", []),
        "export_manifest_sha256": (scope.get("export_manifest") or {}).get("sha256"),
        "export_pack": scope.get("export_pack"), "files": scope["files"], "catalog_sha256": catalog_sha256,
        "columns_sha256": columns_sha256, "rules": RULES, "settings": asdict(settings),
        "tool_version": tool_version, "implementation": implementation,
        "secondary": {name: [shard_ref(item) for item in values]
                      for name, values in sorted(inputs["secondary"].items())},
        "observations": [shard_ref(item) for item in inputs["observations"]],
        "priority": None if inputs["priority"] is None else [shard_ref(item) for item in inputs["priority"]],
    })


def scope_root(run_root: Path, scope_id: str) -> Path:
    if not scope_id or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for character in scope_id):
        raise IntegrityError(f"CodeQL scope id is not a safe path segment: {scope_id!r}")
    return run_root / "data" / "code-graph" / "scopes" / scope_id


def reuse_checkpoint(run_root: Path, scope_id: str, identity: str) -> dict[str, Any] | None:
    """A prior scope result whose shards still verify, or ``None`` (absent, stale or unverifiable).

    A checkpoint whose identity matches but whose shards no longer verify is an unverifiable
    leftover: it and its shard files are deleted and the scope is rebuilt, never republished.
    """
    path = scope_root(run_root, scope_id) / "checkpoint.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        document = None
    if not isinstance(document, Mapping) or document.get("schema") != CHECKPOINT_SCHEMA \
            or document.get("identity") != identity:
        return None
    result = document.get("result") or {}
    shards = result.get("shards") if isinstance(result, Mapping) else None
    valid = isinstance(shards, list) and bool(shards) and result.get("scope_id") == scope_id
    for shard in shards or ():
        candidate = (run_root / str(shard.get("relative_path", ""))).resolve()
        if run_root.resolve() not in candidate.parents or not candidate.is_file() \
                or file_sha256(candidate) != shard.get("sha256"):
            valid = False
    if not valid:
        for shard in shards or ():
            candidate = (run_root / str(shard.get("relative_path", ""))).resolve()
            if run_root.resolve() in candidate.parents and candidate.is_file():
                candidate.unlink()
        path.unlink()
        return None
    return {**dict(result), "checkpoint_reused": True}


def save_checkpoint(run_root: Path, scope_id: str, identity: str, result: Mapping[str, Any]) -> dict[str, Any]:
    path = scope_root(run_root, scope_id) / "checkpoint.json"
    atomic_json(path, {"schema": CHECKPOINT_SCHEMA, "identity": identity, "result": dict(result)})
    return artifact(run_root, path)


# --------------------------------------------------------------------------- stage codec


def _location(value: SourceLocation | None) -> dict[str, Any] | None:
    return asdict(value) if value is not None else None


def _parse_location(value: Mapping[str, Any] | None) -> SourceLocation | None:
    return SourceLocation(**dict(value)) if value is not None else None


def encode_stage(scope_id: str, facts: Sequence[GraphFact], symbols: Sequence[EntityRecord],
                 relations: Sequence[RelationRecord], coverage: Sequence[CoverageRow],
                 summary: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": STAGE_SCHEMA, "scope_id": scope_id,
        "facts": [{"identity": item.identity.value, "name": item.name, "payload": item.payload,
                   "location": _location(item.location)} for item in facts],
        "symbols": [{"identity": item.identity.value, "native_id": item.native_id, "name": item.name,
                     "text": item.text, "payload": item.payload, "location": _location(item.location)}
                    for item in symbols],
        "relations": [{"kind": item.kind.value, "source_id": item.source_id, "target_id": item.target_id,
                       "exact": item.exact, "confidence": item.confidence, "ambiguity": item.ambiguity,
                       "payload": item.payload} for item in relations],
        "coverage": [{"family": row.family.value, "status": row.status.value, "gaps": list(row.gaps),
                      "facts": row.facts, "counts": dict(row.counts)} for row in coverage],
        "summary": dict(summary),
    }


def decode_stage(document: Mapping[str, Any]) -> tuple[list[GraphFact], list[EntityRecord], list[RelationRecord],
                                                       list[CoverageRow]]:
    if document.get("schema") != STAGE_SCHEMA:
        raise IntegrityError("code-graph stage document schema is unsupported")
    scope_id = str(document["scope_id"])
    facts = [GraphFact(LogicalIdentity.parse(item["identity"]), item["name"], item["payload"],
                       _parse_location(item["location"])) for item in document["facts"]]
    symbols = [EntityRecord(LogicalIdentity.parse(item["identity"]), item["native_id"], item["name"], item["text"],
                            item["payload"], _parse_location(item["location"])) for item in document["symbols"]]
    relations = [RelationRecord(RelationKind(item["kind"]), item["source_id"], item["target_id"], item["exact"],
                                item["confidence"], item["ambiguity"], item["payload"])
                 for item in document["relations"]]
    coverage = [CoverageRow(scope_id, Family(item["family"]), Coverage(item["status"]), tuple(item["gaps"]),
                            int(item["facts"]), dict(item["counts"])) for item in document["coverage"]]
    return facts, symbols, relations, coverage


def write_stage(run_root: Path, scope_id: str, name: str, document: Mapping[str, Any]) -> dict[str, Any]:
    path = scope_root(run_root, scope_id) / "work" / f"{name}.json"
    atomic_json(path, dict(document))
    return artifact(run_root, path)


def with_gaps(row: CoverageRow, gaps: Sequence[str], *, partial: bool = True, facts: int | None = None,
              counts: Mapping[str, int] | None = None) -> CoverageRow:
    status = row.status
    if partial and gaps and status is Coverage.COMPLETE:
        status = Coverage.PARTIAL
    merged = dict(row.counts)
    for key, value in (counts or {}).items():
        if value:
            merged[key] = value
    return CoverageRow(row.scope_id, row.family, status, tuple(dict.fromkeys([*row.gaps, *gaps])),
                       row.facts if facts is None else facts, merged)


# --------------------------------------------------------------------------- shard publication


def shard_id_for(scope_id: str, family: Family) -> str:
    return f"graph-{scope_id}-{family.value}"


def _producer(scope: Mapping[str, Any], family: Family, catalog_sha256: str, unit_id: str) -> dict[str, Any]:
    return {"job": JOB_ID, "unit": unit_id, "family": family.value, "language": scope["language"],
            "scope_id": scope["scope_id"], "build_unit_id": scope["build_unit_id"], "rule": NORMALIZE_RULE,
            "catalog_sha256": catalog_sha256}


def _publish_one(run_root: Path, *, scope: Mapping[str, Any], family: Family, snapshot: str, identity: str,
                 entities: Sequence[EntityRecord], relations: Sequence[RelationRecord], row: CoverageRow,
                 catalog_sha256: str, unit_id: str) -> dict[str, Any]:
    shard_id = shard_id_for(scope["scope_id"], family)
    fingerprint = digest({"schema": INDEX_SCHEMA, "index": GRAPH_INDEX, "shard_id": shard_id,
                          "scope_identity": identity})
    path = run_root / "data" / "indices" / GRAPH_INDEX / shard_id / f"{fingerprint}.sqlite"
    if path.exists():
        path.unlink()  # an unverifiable leftover of an interrupted attempt; never accepted as is
    builder = IndexBuilder(path, name=GRAPH_INDEX, fingerprint=fingerprint, target_snapshot=snapshot,
                           shard_id=shard_id)
    seen: set[str] = set()
    for entity in sorted(entities, key=lambda item: item.identity.value):
        if entity.identity.value not in seen:
            seen.add(entity.identity.value)
            builder.add_entity(entity)
    relation_ids: set[str] = set()
    for relation in sorted(relations, key=lambda item: (item.relation_id, canonical_json(item.payload or {}))):
        if relation.relation_id not in relation_ids:
            relation_ids.add(relation.relation_id)
            builder.add_relation(relation)
    builder.add_coverage(row.area, row.status.value, row.gap)
    sha = builder.build()
    gaps = tuple(gap[:300] for gap in row.gaps[:50])
    index = IndexIdentity(GRAPH_INDEX, INDEX_SCHEMA, sha, fingerprint, path.relative_to(run_root).as_posix(),
                          _producer(scope, family, catalog_sha256, unit_id), gaps, shard_id)
    return asdict(index)


def publish_scope(run_root: Path, *, scope: Mapping[str, Any], snapshot: str, identity: str,
                  facts: Sequence[GraphFact], symbols: Sequence[EntityRecord], relations: Sequence[RelationRecord],
                  coverage: Sequence[CoverageRow], catalog_sha256: str, unit_id: str) -> list[dict[str, Any]]:
    """One ``graph`` shard per family; symbols ride in ``call_site``, each relation with its fact endpoint."""
    family_of = {fact.identity.value: fact.family for fact in facts}
    symbol_ids = {item.identity.value for item in symbols}
    grouped: dict[Family, list[RelationRecord]] = {family: [] for family in Family}
    for relation in relations:
        family = family_of.get(relation.source_id) or family_of.get(relation.target_id)
        if family is None and (relation.source_id in symbol_ids or relation.target_id in symbol_ids):
            family = Family.CALL_SITE
        if family is None:
            raise IntegrityError(f"graph relation {relation.kind.value} touches no fact or symbol of "
                                 f"{scope['scope_id']}")
        grouped[family].append(relation)
    rows = {row.family: row for row in coverage}
    shards = []
    for family in Family:
        entities = [fact.to_entity() for fact in facts if fact.family is family]
        if family is Family.CALL_SITE:
            entities.extend(symbols)
        shards.append(_publish_one(run_root, scope=scope, family=family, snapshot=snapshot, identity=identity,
                                   entities=entities, relations=grouped[family], row=rows[family],
                                   catalog_sha256=catalog_sha256, unit_id=unit_id))
    return shards


def unavailable_coverage(scope: Mapping[str, Any]) -> list[CoverageRow]:
    status = scope["export_status"] or "UNKNOWN"
    detail = scope.get("reason") or "; ".join(scope.get("export_gaps") or ()) or "no usable graph export"
    gap = f"export_unavailable: CodeQL graph export {status.lower()}: {detail}"
    return [CoverageRow(scope["scope_id"], family, Coverage.UNAVAILABLE, (gap,), 0, {}) for family in Family]


def coverage_dicts(coverage: Sequence[CoverageRow]) -> list[dict[str, Any]]:
    return [row.as_dict() for row in coverage]
