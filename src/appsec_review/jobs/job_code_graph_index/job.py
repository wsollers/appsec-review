"""``job_code_graph_index``: normalize accepted CodeQL graph exports into the ``graph`` index.

docs/architecture/code-graph-precomputation.md (D4, sections 7.1 to 7.4) is normative. Units:

``load.accepted_inputs``
    Reads the accepted ``job_codeql_analysis`` handoff and the accepted retrieval manifest, verifies
    every succeeded scope's export directory against the export-manifest identity bound to that
    handoff (a mismatch is an :class:`IntegrityError`), checks the graph catalog against the run-bound
    CodeQL export pin, restores clangd/IR/AST shards the accepted manifest dropped from their producers'
    verified handoffs, assigns each clangd/IR/AST shard to exactly one CodeQL scope, computes every
    scope's checkpoint identity and reuses verified checkpoints.
``normalize.scopes``
    ``graph.normalize.normalize_scope`` per scope that needs a rebuild.
``crosscheck.scopes``
    ``graph.crosscheck.cross_check`` with only that scope's own secondary shards; disagreements and
    ``secondary_only`` facts make the ``call_site`` coverage row partial.
``correlate.scopes``
    ``graph.correlate.correlate`` with the scope's CodeQL observations (and the prioritization shard
    when accepted); broken flows become ``dataflow_path`` coverage gaps. Publishes one ``graph`` shard
    per ``(scope, family)`` and the scope checkpoint. A scope without a usable export publishes seven
    coverage-only shards with ``unavailable`` rows and no entities.
``acceptance.publish_handoff``
    Composes the graph shards onto the current accepted manifest, replacing only this job's earlier
    shards.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
from pathlib import Path
from typing import Any

from appsec_review.graph.catalog import Catalog, load_catalog
from appsec_review.graph.contract import Coverage, Family, GraphSettings, Producer
from appsec_review.graph.correlate import correlate
from appsec_review.graph.crosscheck import CrossCheckInputs, cross_check, read_secondary
from appsec_review.graph.svf_crosscheck import read_svf, svf_cross_check
from appsec_review.graph.normalize import COLUMNS_PATH, EXPORT_UPSTREAM_INDEX, normalize_scope
from appsec_review.graph.settings import RunConfigurationError, catalog_pins, run_configuration
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval import IndexIdentity, write_manifest
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from . import scopes as s
from .datasets import CONSUMES, DATASETS

JOB_ID = s.JOB_ID
SCHEMA = "appsec-review/code-graph-index/1"
TOPOLOGY = (("load", "accepted_inputs"), ("normalize", "scopes"), ("crosscheck", "scopes"),
            ("correlate", "scopes"), ("acceptance", "publish_handoff"))
_SETTING_KEYS = frozenset({"workers", "graph"})


def graph_settings(unit: UnitContext) -> GraphSettings:
    return GraphSettings.from_mapping(unit.job.config.settings.get("graph"))


def _workers(unit: UnitContext) -> int:
    return max(1, int(unit.job.config.settings.get("workers", 1)))


def _map(unit: UnitContext, function: Callable[[Any], Any], values: list[Any]) -> list[Any]:
    with ThreadPoolExecutor(max_workers=_workers(unit)) as pool:
        return list(pool.map(function, values))


def _status(gaps: list[str], *, empty: bool) -> str:
    return "NOT_APPLICABLE" if empty else "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"


def _scope_block(scope: Mapping[str, Any]) -> dict[str, Any]:
    return {"scope_id": scope["scope_id"], "language": scope["language"], "build_unit_id": scope["build_unit_id"],
            "component_id": None}


def _validate(context, _result) -> None:
    steps = context.config.steps
    if tuple(steps) != tuple(step for step, _task in TOPOLOGY):
        raise ValueError("code-graph index topology does not match central configuration")
    for step, task in TOPOLOGY:
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"code-graph index task configuration mismatch: {step}")
    unknown = set(context.config.settings) - _SETTING_KEYS
    if unknown:
        raise ValueError("jobs.job_code_graph_index.settings has unknown settings: " + ", ".join(sorted(unknown)))
    GraphSettings.from_mapping(context.config.settings.get("graph"))


def verify_catalog_pin(run_root: Path, current: Catalog, scopes: list[Mapping[str, Any]]) -> None:
    """The catalog read here must be the one the run's CodeQL export configuration pins.

    ``jobs.job_codeql_analysis.settings.languages.<language>.export_queries.catalog_sha256`` in the
    run-bound resolved configuration names the catalog every succeeded export was verified against
    (``_verify_export_sources``). A different catalog here would classify facts under rules the run
    never pinned, so any mismatch, or a run without a bound configuration, is an integrity error.
    """
    exported = sorted({str(scope["language"]) for scope in scopes if scope["export_status"] == s.SUCCEEDED})
    if not exported:
        return
    try:
        document = run_configuration(run_root)
    except RunConfigurationError as error:
        raise IntegrityError(str(error)) from error
    if document is None:
        raise IntegrityError("the run has no bound configuration; the graph catalog pin cannot be verified")
    pins = catalog_pins(document)
    for language in exported:
        pinned = pins.get(language, frozenset())
        if current.sha256 not in pinned:
            raise IntegrityError(
                f"graph catalog {current.sha256} differs from the {language} pin in "
                f"jobs.job_codeql_analysis.settings.languages.{language}.export_queries.catalog_sha256 "
                f"({', '.join(sorted(pinned)) or 'none configured'})")


def build_job(*, catalog_path: Path | None = None) -> Job:
    """Build the job; ``catalog_path`` overrides the repository catalog (tests only)."""

    def catalog() -> Catalog:
        return load_catalog(catalog_path)

    def loaded_catalog(unit: UnitContext) -> Catalog:
        value = catalog()
        if value.sha256 != unit.output("load.accepted_inputs")["catalog"]["sha256"]:
            raise IntegrityError("the graph catalog changed during this attempt")
        return value

    def scopes_needing(unit: UnitContext) -> list[Mapping[str, Any]]:
        return [scope for scope in unit.output("load.accepted_inputs")["scopes"]
                if scope["reused"] is None and scope["export_status"] == s.SUCCEEDED]

    def load(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        settings = graph_settings(unit)
        codeql = s.load_codeql_inputs(run_root, unit.job.source_fingerprint)
        manifest_path, manifest_sha = resolve_context_manifest(unit.job)
        manifest, _ = load_verified_manifest(run_root, manifest_path, manifest_sha)
        shard_set = ShardSet(run_root, manifest["indexes"])
        current = catalog()
        verify_catalog_pin(run_root, current, codeql["scopes"])
        columns = hashlib.sha256(COLUMNS_PATH.read_bytes()).hexdigest()
        tool_version = s.codeql_version(run_root)
        implementation = s.implementation_identity()
        restored = s.restored_secondary(run_root, shard_set.shards)
        secondary = s.assign_secondary(run_root, [*shard_set.shards, *restored], codeql["scopes"])
        priority = s.priority_shards(shard_set) or None
        values: list[dict[str, Any]] = []
        for record in codeql["scopes"]:
            scope = dict(record)
            if scope["export_status"] == s.SUCCEEDED:
                s.verify_exports(run_root, scope, settings)
                s.scope_sources(unit.job.target_root, scope["files"])
            scope["inputs"] = {
                "secondary": secondary.get(scope["scope_id"], {producer.value: [] for producer in s.SECONDARY_PRODUCERS}),
                "observations": s.observation_shards(shard_set, scope), "priority": priority}
            scope["identity"] = s.scope_identity(
                scope, snapshot=unit.job.source_fingerprint, catalog_sha256=current.sha256, columns_sha256=columns,
                settings=settings, tool_version=tool_version, implementation=implementation)
            scope["reused"] = s.reuse_checkpoint(run_root, scope["scope_id"], scope["identity"])
            values.append(scope)
        document = {
            "schema": SCHEMA, "codeql_handoff": codeql["handoff"],
            "accepted_manifest": {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": manifest_sha},
            "catalog": {"sha256": current.sha256, "version": current.version, "revision": current.revision},
            "columns_sha256": columns, "settings": asdict(settings), "tool_version": tool_version,
            "implementation": implementation, "restored_secondary": restored, "scopes": values}
        summary = unit.unit_root / "code-graph-inputs.json"
        atomic_json(summary, {**document, "scopes": [
            {key: scope[key] for key in ("scope_id", "language", "build_unit_id", "export_status", "identity")}
            | {"reused": scope["reused"] is not None} for scope in values]})
        unit.job.events.write("CODE_GRAPH_INPUTS_LOADED", scope_count=len(values),
                              reused_count=sum(scope["reused"] is not None for scope in values),
                              restored_secondary_count=len(restored), catalog_sha256=current.sha256)
        return {**document, "artifact": s.artifact(run_root, summary), "scope_count": len(values),
                "reused_count": sum(scope["reused"] is not None for scope in values), "gaps": [],
                "terminal_status": "SUCCEEDED" if values else "NOT_APPLICABLE"}

    def normalize(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        run_root, settings = unit.job.run_root, graph_settings(unit)
        current = loaded_catalog(unit)

        def one(scope: Mapping[str, Any]) -> dict[str, Any]:
            exports = s.verify_exports(run_root, scope, settings)
            sources = s.scope_sources(unit.job.target_root, scope["files"])
            result = normalize_scope(
                exports, scope={**_scope_block(scope), "root": scope["root"], "files": scope["files"]},
                target_snapshot=unit.job.source_fingerprint, sources=sources, catalog=current, settings=settings,
                tool_version=loaded["tool_version"], export_pack_sha256=str(scope["export_pack"]["tree_sha256"]),
                upstream=[{"index": EXPORT_UPSTREAM_INDEX, "shard_id": f"{scope['scope_id']}:export-manifest",
                           "sha256": scope["export_manifest"]["sha256"]}])
            stage = s.write_stage(run_root, scope["scope_id"], "normalized", s.encode_stage(
                scope["scope_id"], result.facts, result.symbols, result.relations, result.coverage, {}))
            gaps = [f"{scope['scope_id']}: {row.family.value}: {row.status.value}"
                    for row in result.coverage if row.status is not Coverage.COMPLETE]
            return {"scope_id": scope["scope_id"], "stage": stage, "facts": len(result.facts),
                    "symbols": len(result.symbols), "relations": len(result.relations), "gaps": gaps}

        results = _map(unit, one, scopes_needing(unit))
        gaps = [gap for item in results for gap in item["gaps"]]
        return {"scopes": results, "scope_count": len(results), "gaps": gaps,
                "terminal_status": _status(gaps, empty=not results)}

    def crosscheck(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        stages = {item["scope_id"]: item["stage"] for item in unit.output("normalize.scopes")["scopes"]}
        shard_set = ShardSet(run_root, [shard for scope in scopes_needing(unit)
                                        for values in scope["inputs"]["secondary"].values() for shard in values])

        def one(scope: Mapping[str, Any]) -> dict[str, Any]:
            facts, symbols, relations, coverage = s.decode_stage(s.read_artifact(run_root, stages[scope["scope_id"]]))
            sources = s.scope_sources(unit.job.target_root, scope["files"])
            secondary = {producer: tuple(
                read_secondary(shard_set, shard, producer,
                               tool_version=str((shard.get("producer") or {}).get("tool_version") or "unknown"))
                for shard in scope["inputs"]["secondary"].get(producer.value, ())) for producer in s.CALL_EDGE_PRODUCERS}
            svf = tuple(read_svf(shard_set, shard) for shard in scope["inputs"]["secondary"].get(Producer.SVF.value, ()))
            result = cross_check(facts, CrossCheckInputs(clangd=secondary[Producer.CLANGD],
                                                         llvm_ir=secondary[Producer.LLVM_IR],
                                                         clang_ast=secondary[Producer.CLANG_AST]),
                                 target_snapshot=unit.job.source_fingerprint, scope=_scope_block(scope),
                                 sources=sources, graph_symbols=symbols)
            svf_result = svf_cross_check(result.facts, svf, target_snapshot=unit.job.source_fingerprint,
                                         scope=_scope_block(scope))
            summary = dict(result.summary)
            summary["svf"] = dict(svf_result.summary)
            for state, count in svf_result.summary.get("states", {}).items():
                summary.setdefault("svf_states", {})[state] = count
            calls = [fact for fact in svf_result.facts if fact.family is Family.CALL_SITE]
            disagreements = int(summary["states"].get("disagree", 0))
            svf_disagreements = int(svf_result.summary.get("states", {}).get("disagree", 0))
            secondary_only = sum(int(value) for value in summary.get("secondary_only", {}).values()) + \
                int(svf_result.summary.get("secondary_only", 0))
            gaps = [*summary.get("gaps", ())]
            if disagreements:
                gaps.append(f"cross_check_disagreements: {disagreements} call_site facts are contradicted by a "
                            "secondary producer and are not direct-eligible")
            if svf_disagreements:
                gaps.append(f"svf_cross_check_disagreements: {svf_disagreements} facts are contradicted by closed-world "
                            "SVF points-to results and are not direct-eligible")
            if secondary_only:
                gaps.append(f"secondary_only: {secondary_only} call sites are reported only by a secondary producer "
                            "(missing CodeQL coverage, not a CodeQL negative)")
            coverage = [s.with_gaps(row, gaps, facts=len(calls), counts={
                "cross_check_disagreements": disagreements, "secondary_only": secondary_only})
                if row.family is Family.CALL_SITE else row for row in coverage]
            stage = s.write_stage(run_root, scope["scope_id"], "crosschecked", s.encode_stage(
                scope["scope_id"], svf_result.facts, symbols,
                [*relations, *result.relations, *svf_result.relations], coverage,
                {"cross_check": summary}))
            return {"scope_id": scope["scope_id"], "stage": stage, "states": summary["states"],
                    "secondary_only": secondary_only, "symbol_links": summary.get("symbol_links", 0),
                    "producers": summary.get("producers", {}),
                    "gaps": [f"{scope['scope_id']}: {gap}" for gap in gaps]}

        results = _map(unit, one, [scope for scope in scopes_needing(unit) if scope["scope_id"] in stages])
        gaps = [gap for item in results for gap in item["gaps"]]
        return {"scopes": results, "scope_count": len(results), "gaps": gaps,
                "terminal_status": _status(gaps, empty=not results)}

    def correlate_scopes(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        run_root = unit.job.run_root
        catalog_sha = loaded["catalog"]["sha256"]
        stages = {item["scope_id"]: item["stage"] for item in unit.output("crosscheck.scopes")["scopes"]}
        if stages:
            loaded_catalog(unit)

        def one(scope: Mapping[str, Any]) -> dict[str, Any]:
            if scope["reused"] is not None:
                return dict(scope["reused"])
            if scope["export_status"] != s.SUCCEEDED:
                coverage = s.unavailable_coverage(scope)
                shards = s.publish_scope(run_root, scope=scope, snapshot=unit.job.source_fingerprint,
                                         identity=scope["identity"], facts=(), symbols=(), relations=(),
                                         coverage=coverage, catalog_sha256=catalog_sha, unit_id=unit.unit_id)
                summary: dict[str, Any] = {}
            else:
                facts, symbols, relations, coverage = s.decode_stage(
                    s.read_artifact(run_root, stages[scope["scope_id"]]))
                sources = s.scope_sources(unit.job.target_root, scope["files"])
                observation_set = ShardSet(run_root, scope["inputs"]["observations"])
                observations = list(observation_set.entities(observation_set.shards, kinds=("tool_observation",)))
                priority = None
                if scope["inputs"]["priority"] is not None:
                    priority_set = ShardSet(run_root, scope["inputs"]["priority"])
                    priority = list(priority_set.entities(priority_set.shards,
                                                          kinds=("review_signal", "review_flow_step")))
                result = correlate(facts, observations, sources=sources, priority=priority)
                summary = dict(result.summary)
                broken = list(summary.get("broken", ()))
                gaps = [*summary.get("gaps", ())]
                gaps.extend(f"sarif_correlation_broken: observation {item['observation']} code_flow "
                            f"{item['code_flow']}.{item['thread_flow']}: {item['reason']}"
                            for item in broken[:s.MAX_BROKEN_GAPS])
                if len(broken) > s.MAX_BROKEN_GAPS:
                    gaps.append(f"sarif_correlation_broken: {len(broken) - s.MAX_BROKEN_GAPS} further broken "
                                "code flows are not listed")
                coverage = [s.with_gaps(row, gaps, counts={"sarif_correlation_broken": len(broken)})
                            if row.family is Family.DATAFLOW_PATH else row for row in coverage]
                shards = s.publish_scope(run_root, scope=scope, snapshot=unit.job.source_fingerprint,
                                         identity=scope["identity"], facts=facts, symbols=symbols,
                                         relations=[*relations, *result.relations], coverage=coverage,
                                         catalog_sha256=catalog_sha, unit_id=unit.unit_id)
            gaps = [f"{row.area}: {row.status.value}" + (f": {row.gap}" if row.gap else "")
                    for row in coverage if row.status is not Coverage.COMPLETE]
            value = {"scope_id": scope["scope_id"], "language": scope["language"],
                     "build_unit_id": scope["build_unit_id"], "export_status": scope["export_status"],
                     "shards": shards, "coverage": s.coverage_dicts(coverage),
                     "counts": {"facts": sum(row.facts for row in coverage),
                                "code_flows": int(summary.get("code_flows", 0) or 0),
                                "correlation_states": dict(summary.get("states", {}))},
                     "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}
            checkpoint = s.save_checkpoint(run_root, scope["scope_id"], scope["identity"], value)
            return {**value, "checkpoint": checkpoint, "checkpoint_reused": False}

        results = _map(unit, one, list(loaded["scopes"]))
        gaps = [gap for item in results for gap in item["gaps"]]
        return {"scopes": results, "scope_count": len(results),
                "reused_count": sum(bool(item.get("checkpoint_reused")) for item in results), "gaps": gaps,
                "terminal_status": _status(gaps, empty=not results)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, published = unit.output("load.accepted_inputs"), unit.output("correlate.scopes")
        run_root = unit.job.run_root
        upstream_path, upstream_sha = resolve_context_manifest(unit.job)
        upstream, _ = load_verified_manifest(run_root, upstream_path, upstream_sha)
        # Secondary shards the accepted manifest had dropped were consumed from their producers' own
        # verified handoffs; this manifest composes them back so every consumed shard stays resolvable.
        restored = [item for item in loaded.get("restored_secondary", ())
                    if (str(item["name"]), str(item.get("shard_id", "default"))) not in {
                        (str(entry["name"]), str(entry.get("shard_id", "default"))) for entry in upstream["indexes"]}]
        present = {(str(item["name"]), str(item.get("shard_id", "default")), str(item["sha256"]))
                   for item in (*upstream["indexes"], *restored)}
        consumed = {(shard["name"], shard["shard_id"], shard["sha256"])
                    for scope in loaded["scopes"] for values in (
                        *scope["inputs"]["secondary"].values(), scope["inputs"]["observations"],
                        scope["inputs"]["priority"] or ()) for shard in map(s.shard_ref, values)}
        missing = sorted(consumed - present)
        if missing:
            raise IntegrityError("the accepted manifest no longer holds the shards this graph was built from: "
                                 + ", ".join(f"{name}/{shard_id}" for name, shard_id, _ in missing[:10]))
        base = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                for item in (*upstream["indexes"], *restored) if (item.get("producer") or {}).get("job") != JOB_ID]
        indexes = [IndexIdentity(**{**shard, "gaps": tuple(shard.get("gaps", ()))})
                   for scope in published["scopes"] for shard in scope["shards"]]
        manifest_path = run_root / "data" / "indices" / "manifests" / f"code-graph-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or Path(), indexes=[*base, *indexes],
                       upstream_manifests=({"path": upstream_path.relative_to(run_root).as_posix(),
                                            "sha256": upstream_sha},))
        load_verified_manifest(run_root, manifest_path, file_sha256(manifest_path))
        families: dict[str, dict[str, int]] = {family.value: {state.value: 0 for state in Coverage} for family in Family}
        for scope in published["scopes"]:
            for row in scope["coverage"]:
                families[row["family"]][row["status"]] += 1
        counts = {"scopes": len(published["scopes"]), "shards": len(indexes),
                  "reused_scopes": published["reused_count"],
                  "facts": sum(int(scope["counts"]["facts"]) for scope in published["scopes"])}
        summary_path = unit.unit_root / "code-graph-summary.json"
        atomic_json(summary_path, {"schema": SCHEMA, "codeql_handoff": loaded["codeql_handoff"],
                                   "catalog": loaded["catalog"], "counts": counts, "families": families,
                                   "scopes": [{key: scope[key] for key in (
                                       "scope_id", "language", "build_unit_id", "export_status", "coverage",
                                       "counts", "gaps")} for scope in published["scopes"]],
                                   "gaps": published["gaps"]})
        unit.job.events.write("CODE_GRAPH_INDEX_COMPLETED", **counts, gap_count=len(published["gaps"]))
        return {"schema": SCHEMA, "artifact": s.artifact(run_root, summary_path),
                "index_manifest": s.artifact(run_root, manifest_path), "item_count": counts["facts"],
                "counts": counts, "families": families, "gaps": published["gaps"],
                "terminal_status": published["terminal_status"]}

    units = (
        Unit("load.accepted_inputs", load),
        Unit("normalize.scopes", normalize, ("load.accepted_inputs",)),
        Unit("crosscheck.scopes", crosscheck, ("load.accepted_inputs", "normalize.scopes")),
        Unit("correlate.scopes", correlate_scopes, ("load.accepted_inputs", "crosscheck.scopes")),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_inputs", "correlate.scopes")),
    )
    implementation = hashlib.sha256((s.implementation_identity() + (
        f":catalog={catalog_path}" if catalog_path is not None else "")).encode()).hexdigest()
    return Job(JOB_ID, "code_graph_index", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units, datasets=DATASETS,
               consumes=CONSUMES)
