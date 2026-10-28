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

from appsec_review import seeding
from appsec_review.codeql.runtime import GraphExportIntegrityError, load_graph_exports
from appsec_review.graph.catalog import LANGUAGE_ALIASES
from appsec_review.graph.contract import (
    ADMISSIBILITY_RULE, CROSS_CHECK_RULE, GRAPH_INDEX, NORMALIZE_RULE, Coverage, Family, GraphFact, GraphSettings,
    Producer,
)
from appsec_review.graph.correlate import CORRELATION_RULE
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import COLUMNS_PATH, CoverageRow
from appsec_review.indexing.store import ShardSet, accepted_handoff, handoff_manifests, open_shard, shard_key
from appsec_review.jobs.job_code_graph_index import producers
from appsec_review.jobs.job_codeql_analysis.job import GRAPH_EXPORTS_SCHEMA
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation,
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
SECONDARY_PRODUCERS = (Producer.CLANGD, Producer.LLVM_IR, Producer.CLANG_AST, Producer.SVF)
# Producers read through ``crosscheck.read_secondary``; SVF rows are read by ``svf_crosscheck.read_svf``.
CALL_EDGE_PRODUCERS = (Producer.CLANGD, Producer.LLVM_IR, Producer.CLANG_AST)
SVF_JOB = "job_svf_alias_analysis"
# Producers whose seeded output is observations, not graph shards: they reach the database card only.
ANALYZER_JOBS = {"job_clang_static_analysis": Producer.CLANG_STATIC, "job_cpg_analysis": Producer.JOERN_CPG}
CARD_PRODUCER_ORDER = (Producer.CODEQL_EXPORT, Producer.LLVM_IR, Producer.CLANG_AST, Producer.CLANG_STATIC,
                       Producer.CLANGD, Producer.JOERN_CPG)
MAX_PRODUCER_GAPS = 5
# Bound on the coverage-gap lines naming individual broken SARIF correlations per scope.
MAX_BROKEN_GAPS = 20
# The database card (docs/architecture/seeded-codeql-neighborhoods.md section 7).
DATABASE_CARD_SCHEMA = "appsec-review/codeql-database/1"
DATABASE_KIND = "codeql_database"
# The flow / diagnostics / clangd-symbol rows of a scope (docs/architecture/seeded-neighborhoods.md section 9).
PRODUCERS_KIND = producers.PRODUCERS_KIND
MAX_CARD_SEEDS = 200
MAX_CARD_SOURCES = 8
MAX_CARD_GAPS = 20


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


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


def bounded_seeded(value: Any) -> dict[str, Any] | None:
    """The export record's ``seeded`` ledger, re-bounded; ``None`` for a record that carries none.

    The ledger is producer data: seeds are capped at the section 6 bound, sources per seed at
    ``MAX_CARD_SOURCES`` and strings at 300 characters, so a card can never grow with the target.
    """
    if not isinstance(value, Mapping):
        return None

    def text(item: Any) -> str:
        return str(item)[:300]

    def count(item: Any) -> int | None:
        return item if isinstance(item, int) and not isinstance(item, bool) and item >= 0 else None

    seeds = []
    for seed in list(value.get("seeds") or ())[:MAX_CARD_SEEDS]:
        if not isinstance(seed, Mapping):
            continue
        sources = [{key: text(source[key]) for key in ("scanner", "rule", "severity", "observation_id")
                    if source.get(key) is not None}
                   for source in list(seed.get("sources") or ())[:MAX_CARD_SOURCES] if isinstance(source, Mapping)]
        seeds.append({"path": text(seed.get("path", "")), "start_line": count(seed.get("start_line")),
                      "end_line": count(seed.get("end_line")), "status": text(seed.get("status", "")),
                      "functions": [text(name) for name in list(seed.get("functions") or ())[:16]],
                      "sources": sorted(sources, key=canonical_json)})
    histogram = value.get("depth_histogram")
    return {
        "mode": text(value.get("mode") or "whole_program"), "depth": count(value.get("depth")),
        "seed_limit": count(value.get("seed_limit")), "seed_count": count(value.get("seed_count")) or 0,
        "resolved_seed_count": count(value.get("resolved_seed_count")) or 0,
        "neighborhood_function_count": count(value.get("neighborhood_function_count")) or 0,
        "depth_histogram": {text(key): count(item) or 0 for key, item in sorted(histogram.items())}
        if isinstance(histogram, Mapping) else {},
        "seeds": seeds, "gaps": [text(gap) for gap in list(value.get("gaps") or ())[:MAX_CARD_GAPS]],
    }


def is_seeded(scope: Mapping[str, Any]) -> bool:
    return (scope.get("seeded") or {}).get("mode") == "seeded"


# --------------------------------------------------------------------------- accepted CodeQL inputs


def load_codeql_inputs(run_root: Path, source_fingerprint: str) -> dict[str, Any]:
    """The accepted CodeQL handoff's per-scope export records, joined with the plan's scope files.

    Only material bound to the accepted handoff is read: its graph export index artifact, its
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

    outputs = handoff.get("outputs") or {}
    if "execution.scopes" in outputs:
        execution = outputs["execution.scopes"]
        if not isinstance(execution, Mapping):
            raise IntegrityError("accepted CodeQL execution.scopes output is invalid")
        export_index = execution.get("graph_export_artifact")
    else:
        legacy = outputs.get("export.scopes")
        if not isinstance(legacy, Mapping):
            raise IntegrityError("accepted CodeQL handoff publishes no graph export index")
        export_index = legacy.get("artifact")
    index = read_bound(export_index, "graph export index")
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
            "source_languages": sorted({str(value) for value in planned.get("source_languages") or ()}
                                       or {str(planned["language"])}),
            "seeded": bounded_seeded(item.get("seeded")),
            "files": sorted(({"path": str(entry["path"]), "sha256": str(entry["sha256"])}
                             for entry in planned.get("files", ())), key=lambda entry: entry["path"]),
        }
        if status == SUCCEEDED:
            manifest = item.get("export_manifest")
            if not isinstance(manifest, Mapping) or bound.get(str(manifest.get("path"))) != manifest.get("sha256"):
                raise IntegrityError(f"CodeQL export manifest of {scope_id} is not bound to the accepted handoff")
            pack = item.get("export_pack")
            if not isinstance(pack, Mapping):
                raise IntegrityError(f"CodeQL export pack identity of {scope_id} is missing")
            record["export_manifest"] = {"path": str(manifest["path"]), "sha256": str(manifest["sha256"])}
            record["export_pack"] = dict(pack)
        records.append(record)
    if len({item["scope_id"] for item in records}) != len(records):
        raise IntegrityError("accepted CodeQL export index repeats a scope")
    if {item["scope_id"] for item in records} != set(plan_scopes):
        raise IntegrityError("accepted CodeQL export index omits a planned scope")
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
    if producer.get("job") == SVF_JOB and shard_id.startswith("svf-") and not shard_id.startswith("svf-coverage-"):
        return Producer.SVF
    return None


SECONDARY_JOBS = ("job_cpp_symbol_index", "job_cpp_compiled_analysis", SVF_JOB, *ANALYZER_JOBS)


def analyzer_producer(shard: Mapping[str, Any]) -> Producer | None:
    """clang-static or joern-cpg: an ``observations`` shard of the analyzer job whose producer names a project."""
    producer = shard.get("producer") or {}
    if shard.get("name") != "observations" or "project_root" not in producer:
        return None
    return ANALYZER_JOBS.get(str(producer.get("job")))


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
                if (shard.get("producer") or {}).get("job") != job_id or (
                        secondary_producer(shard) is None and analyzer_producer(shard) is None):
                    continue
                key = shard_key(shard)
                if key not in by_key and key not in restored:
                    restored[key] = dict(shard)
    return [restored[key] for key in sorted(restored)]


def _native_scope(scope: Mapping[str, Any]) -> bool:
    return LANGUAGE_ALIASES.get(str(scope.get("language") or "").strip().lower()) == "cpp"


def assign_secondary(run_root: Path, shards: Iterable[Mapping[str, Any]],
                     scopes: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Give each accepted native secondary shard to exactly one compatible C/C++ CodeQL scope.

    A shard belongs to the scope whose planned files hold the most of the shard's located paths (ties by
    scope id). A shard never serves two scopes, so a cross-check verdict can never mix evidence from
    two build units. A shard that touches no scope file is not used.
    """
    files = {str(scope["scope_id"]): {str(item["path"]) for item in scope["files"]}
             for scope in scopes if scope["export_status"] == SUCCEEDED and _native_scope(scope)}
    assigned: dict[str, dict[str, list[dict[str, Any]]]] = {
        str(scope["scope_id"]): {producer.value: [] for producer in SECONDARY_PRODUCERS}
        for scope in scopes if scope["export_status"] == SUCCEEDED}
    if not files:
        return assigned
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


def project_root_key(value: Any) -> str:
    text = str(value or "").strip("/")
    return "" if text in {"", "."} else text


def assign_analyzers(shards: Iterable[Mapping[str, Any]],
                     scopes: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """clang-static and joern-cpg shards go to compatible C/C++ scopes of the same project root."""
    roots: dict[str, list[str]] = {}
    for scope in scopes:
        if _native_scope(scope):
            roots.setdefault(project_root_key(scope.get("root")), []).append(str(scope["scope_id"]))
    assigned = {str(scope["scope_id"]): {producer.value: [] for producer in ANALYZER_JOBS.values()}
                for scope in scopes}
    for shard in sorted(shards, key=shard_key):
        producer = analyzer_producer(shard)
        if producer is None:
            continue
        for scope_id in roots.get(project_root_key(shard["producer"]["project_root"]), ()):
            assigned[scope_id][producer.value].append(dict(shard))
    return assigned


def observation_shards(shard_set: ShardSet, scope: Mapping[str, Any]) -> list[dict[str, Any]]:
    prefix = f"codeql-{scope['language']}-{scope['scope_id']}-"
    return [dict(shard) for shard in shard_set.select(index="observations", job=CODEQL_JOB, prefix=prefix)]


def priority_shards(shard_set: ShardSet) -> list[dict[str, Any]]:
    return [dict(shard) for shard in shard_set.select(index="priority", job=PRIORITY_JOB)]


# --------------------------------------------------------------------------- scope identity and checkpoints


def scope_identity(scope: Mapping[str, Any], *, snapshot: str, catalog_release: str, columns_release: str,
                   settings: GraphSettings, tool_version: str, implementation: str) -> str:
    """Section 7.3: everything a scope's graph shards depend on, and nothing else."""
    inputs = scope["inputs"]
    return digest({
        "schema": SCOPE_IDENTITY_SCHEMA, "target_snapshot": snapshot, "scope_id": scope["scope_id"],
        "language": scope["language"], "root": scope["root"], "build_unit_id": scope["build_unit_id"],
        "database_identity": scope["database_identity"], "export_status": scope["export_status"],
        "reason": scope.get("reason"), "export_gaps": scope.get("export_gaps", []),
        "seeded": scope.get("seeded"), "source_languages": scope.get("source_languages"),
        "export_manifest_sha256": (scope.get("export_manifest") or {}).get("sha256"),
        "files": scope["files"], "catalog_release": catalog_release,
        "columns_release": columns_release, "rules": RULES, "settings": asdict(settings),
        "tool_version": tool_version, "implementation": implementation,
        "secondary": {name: [shard_ref(item) for item in values]
                      for name, values in sorted(inputs["secondary"].items())},
        "analyzers": {name: [shard_ref(item) for item in values]
                      for name, values in sorted((inputs.get("analyzers") or {}).items())},
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


def seeded_gap(seeded: Mapping[str, Any]) -> str:
    return seeding.coverage_gap(seeded)


def apply_seeded_coverage(scope: Mapping[str, Any], coverage: Sequence[CoverageRow]) -> list[CoverageRow]:
    """Section 7: a seeded scope's usable family rows are ``partial`` with the neighborhood gap.

    Seeded output is a sample around findings, never a claim about the program, so no seeded
    family is ever ``complete``. An ``unavailable`` row stays unavailable (it has no facts to qualify).
    """
    if not is_seeded(scope):
        return list(coverage)
    gap = seeded_gap(scope["seeded"])
    return [row if row.status is Coverage.UNAVAILABLE else with_gaps(row, [gap]) for row in coverage]


def database_coverage(scope: Mapping[str, Any], coverage: Sequence[CoverageRow]) -> tuple[Coverage, list[str]]:
    """The card's own coverage state and gap lines.

    A usable export is as covered as its family rows. A scope without one is ``unavailable``, except
    a seeded scope whose export was skipped for lack of finding locations: that scope is ``partial``
    (specification section 4), never clean.
    """
    seeded = scope.get("seeded") or {}
    gaps = list(seeded.get("gaps") or ())
    statuses = {row.status for row in coverage}
    if scope["export_status"] == SUCCEEDED:
        if statuses == {Coverage.COMPLETE}:
            state = Coverage.COMPLETE
        elif statuses == {Coverage.UNAVAILABLE}:
            state = Coverage.UNAVAILABLE
        else:
            state = Coverage.PARTIAL
        if is_seeded(scope):
            state = Coverage.PARTIAL if state is not Coverage.UNAVAILABLE else state
            gaps.append(seeded_gap(seeded))
    else:
        detail = scope.get("reason") or "; ".join(scope.get("export_gaps") or ()) or "no usable graph export"
        gaps.append(f"export_unavailable: CodeQL graph export {(scope['export_status'] or 'UNKNOWN').lower()}: "
                    f"{detail}")
        skipped = is_seeded(scope) and not seeded.get("resolved_seed_count")
        state = Coverage.PARTIAL if skipped else Coverage.UNAVAILABLE
    for row in coverage:
        gaps.extend(row.gaps[:2])
    return state, [gap[:300] for gap in dict.fromkeys(gaps)][:MAX_CARD_GAPS]


def _producer_entry(name: Producer, seeded: Mapping[str, Any] | None, *, shards: int = 1,
                    failed: bool = False) -> dict[str, Any]:
    """One ``producers`` row of the database card: what ran, whether it was seeded, how deep, what is missing."""
    if not shards:
        return {"name": name.value, "state": "not_run", "seeded": False, "depth": None,
                "gaps": [f"producer_not_run: no accepted {name.value} output covers this database's project"]}
    record = seeded or {}
    mode = record.get("mode") or "whole_program"
    if mode != "seeded":
        state = "failed" if failed else "whole_program"
    elif record.get("skipped") or not record.get("seed_count"):
        state = "skipped"
    elif not record.get("resolved_seed_count"):
        state = "failed"
    else:
        state = "seeded"
    gaps = [str(gap)[:300] for gap in dict.fromkeys(record.get("gaps") or ())][:MAX_PRODUCER_GAPS]
    return {"name": name.value, "state": state, "seeded": mode == "seeded",
            "depth": record.get("depth") if mode == "seeded" else None, "gaps": gaps}


def _merge_entries(name: Producer, records: Sequence[Mapping[str, Any] | None]) -> dict[str, Any]:
    """Several shards of one producer in one scope: the weakest state, the deepest depth, the gaps united."""
    entries = [_producer_entry(name, record) for record in records]
    if not entries:
        return _producer_entry(name, None, shards=0)
    rank = {"failed": 0, "skipped": 1, "whole_program": 2, "seeded": 3, "not_run": 4}
    state = min((entry["state"] for entry in entries), key=lambda item: rank[item])
    depths = [entry["depth"] for entry in entries if entry["depth"] is not None]
    gaps = [gap for entry in entries for gap in entry["gaps"]]
    return {"name": name.value, "state": state, "seeded": any(entry["seeded"] for entry in entries),
            "depth": max(depths) if depths else None,
            "gaps": [gap for gap in dict.fromkeys(gaps)][:MAX_PRODUCER_GAPS]}


def card_producers(scope: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Section 7: every producer that can serve this database and what it contributed, in a fixed order.

    The CodeQL entry comes from the export's own ledger. The others come from the ``seeded`` record each
    accepted shard carries in its producer identity; a producer with no accepted shard is ``not_run``,
    never an omission, so a consumer sees which neighborhoods exist before opening any of them.
    """
    inputs = scope.get("inputs") or {}
    codeql = scope.get("seeded")
    rows = {Producer.CODEQL_EXPORT.value: _producer_entry(
        Producer.CODEQL_EXPORT, codeql, failed=scope["export_status"] != SUCCEEDED
        and not (codeql or {}).get("skipped"))}
    for table in ("secondary", "analyzers"):
        for name, shards in sorted((inputs.get(table) or {}).items()):
            rows[name] = _merge_entries(Producer(name), [(shard.get("producer") or {}).get("seeded")
                                                         for shard in shards])
    for producer in CARD_PRODUCER_ORDER:
        rows.setdefault(producer.value, _producer_entry(producer, None, shards=0))
    return [rows[producer.value] for producer in CARD_PRODUCER_ORDER]


def database_card(scope: Mapping[str, Any], *, snapshot: str, coverage: Sequence[CoverageRow]) -> EntityRecord:
    """One ``codeql_database`` card (``appsec-review/codeql-database/1``) per CodeQL scope.

    The card answers "which databases exist, what each was seeded from, how deep, and what is not
    covered" without opening a family shard. Its identity derives from the snapshot, the scope, the
    database identity and the export identity, so a different database, export pack, seed set, mode or
    depth is a different card. It carries no source location: a database has no single span.
    """
    seeded = scope.get("seeded") or {}
    manifest = (scope.get("export_manifest") or {}).get("sha256")
    pack = scope.get("export_pack") or {}
    export_identity = digest({"manifest_sha256": manifest, "pack_tree_sha256": pack.get("tree_sha256"),
                              "columns_sha256": pack.get("columns_sha256")}) if manifest else None
    state, gaps = database_coverage(scope, coverage)
    identity = LogicalIdentity.derive(EntityKind.CODEQL_DATABASE, snapshot, {
        "scope_id": scope["scope_id"], "database_identity": scope.get("database_identity"),
        "export_identity": export_identity, "export_status": scope["export_status"]})
    block = {"scope_id": scope["scope_id"], "language": scope["language"], "build_unit_id": scope["build_unit_id"],
             "component_id": None}
    payload = {
        "schema": DATABASE_CARD_SCHEMA, "scope": block, "scope_id": scope["scope_id"],
        "language": scope["language"], "source_languages": list(scope.get("source_languages") or ()),
        "root": scope["root"], "build_unit_id": scope["build_unit_id"], "component_id": None,
        "database_identity": scope.get("database_identity"), "export_identity": export_identity,
        "export_status": scope["export_status"],
        "mode": seeded.get("mode") or "whole_program", "seed_depth": seeded.get("depth"),
        "seed_limit": seeded.get("seed_limit"), "seed_count": seeded.get("seed_count", 0),
        "resolved_seed_count": seeded.get("resolved_seed_count", 0),
        "neighborhood_function_count": seeded.get("neighborhood_function_count", 0),
        "seeded": seeded, "producers": card_producers(scope), "coverage": state.value,
        "families": {row.family.value: {"status": row.status.value, "facts": row.facts,
                                        "counts": dict(sorted(row.counts.items()))} for row in coverage},
        "gaps": gaps,
    }
    text = (f"codeql database {scope['scope_id']} {scope['language']} {payload['mode']} "
            f"seeds {payload['resolved_seed_count']} of {payload['seed_count']}")
    return EntityRecord(identity, str(scope["scope_id"]), f"{scope['language']} database {scope['scope_id']}", text,
                        payload, None)


# --------------------------------------------------------------------------- shard publication


def shard_id_for(scope_id: str, family: Family) -> str:
    return f"graph-{scope_id}-{family.value}"


def database_shard_id(scope_id: str) -> str:
    """Shard ids may not hold ``:`` (``[A-Za-z0-9_.-]{1,128}``), so the card shard is ``graph-<scope>-database``."""
    return f"graph-{scope_id}-database"


def producers_shard_id(scope_id: str) -> str:
    return f"graph-{scope_id}-producers"


def _producer(scope: Mapping[str, Any], family: Family | None, catalog_release: str, unit_id: str,
              kind: str = DATABASE_KIND) -> dict[str, Any]:
    value = {"job": JOB_ID, "unit": unit_id, "language": scope["language"], "scope_id": scope["scope_id"],
             "build_unit_id": scope["build_unit_id"], "rule": NORMALIZE_RULE, "catalog_release": catalog_release}
    # A fact-family shard names its family; the database-card shard names its kind instead, so no
    # consumer mistakes it for a seven-family fact shard.
    return {**value, "family": family.value} if family is not None else {**value, "kind": kind}


def _publish_one(run_root: Path, *, scope: Mapping[str, Any], family: Family | None, snapshot: str, identity: str,
                 entities: Sequence[EntityRecord], relations: Sequence[RelationRecord],
                 area: str, status: str, gaps: Sequence[str], catalog_release: str, unit_id: str,
                 kind: str = DATABASE_KIND) -> dict[str, Any]:
    shard_id = (shard_id_for(scope["scope_id"], family) if family is not None else
                producers_shard_id(scope["scope_id"]) if kind == PRODUCERS_KIND else
                database_shard_id(scope["scope_id"]))
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
    builder.add_coverage(area, status, "; ".join(gaps)[:4096] or None)
    sha = builder.build()
    index = IndexIdentity(GRAPH_INDEX, INDEX_SCHEMA, sha, fingerprint, path.relative_to(run_root).as_posix(),
                          _producer(scope, family, catalog_release, unit_id, kind),
                          tuple(gap[:300] for gap in gaps[:50]), shard_id)
    return asdict(index)


def publish_scope(run_root: Path, *, scope: Mapping[str, Any], snapshot: str, identity: str,
                  facts: Sequence[GraphFact], symbols: Sequence[EntityRecord], relations: Sequence[RelationRecord],
                  coverage: Sequence[CoverageRow], catalog_release: str, unit_id: str,
                  card: EntityRecord | None = None,
                  neighborhood: producers.ProducerRows | None = None) -> list[dict[str, Any]]:
    """One ``graph`` shard per family plus the database-card shard and the producer-neighborhood shard.

    Symbols ride in ``call_site``, each relation with its fact endpoint. ``card`` (the scope's
    :func:`database_card`) is published as one more shard of the same index; it is not a fact family.
    """
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
        row = rows[family]
        shards.append(_publish_one(run_root, scope=scope, family=family, snapshot=snapshot, identity=identity,
                                   entities=entities, relations=grouped[family], area=row.area,
                                   status=row.status.value, gaps=row.gaps, catalog_release=catalog_release,
                                   unit_id=unit_id))
    if card is not None:
        state = card.payload["coverage"]
        shards.append(_publish_one(run_root, scope=scope, family=None, snapshot=snapshot, identity=identity,
                                   entities=[card], relations=(), area=f"graph:{scope['scope_id']}:database",
                                   status=state, gaps=card.payload["gaps"], catalog_release=catalog_release,
                                   unit_id=unit_id))
    if neighborhood is not None:
        shards.append(_publish_one(run_root, scope=scope, family=None, snapshot=snapshot, identity=identity,
                                   entities=neighborhood.entities, relations=(),
                                   area=f"graph:{scope['scope_id']}:producers", status=neighborhood.status,
                                   gaps=neighborhood.gaps, catalog_release=catalog_release, unit_id=unit_id,
                                   kind=PRODUCERS_KIND))
    return shards


def unavailable_coverage(scope: Mapping[str, Any]) -> list[CoverageRow]:
    status = scope["export_status"] or "UNKNOWN"
    detail = scope.get("reason") or "; ".join(scope.get("export_gaps") or ()) or "no usable graph export"
    gap = f"export_unavailable: CodeQL graph export {status.lower()}: {detail}"
    return [CoverageRow(scope["scope_id"], family, Coverage.UNAVAILABLE, (gap,), 0, {}) for family in Family]


def coverage_dicts(coverage: Sequence[CoverageRow]) -> list[dict[str, Any]]:
    return [row.as_dict() for row in coverage]
