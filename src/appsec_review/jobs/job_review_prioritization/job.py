"""Structural metrics, boundary heuristics, and the LLM Prioritization Score.

The job consumes the accepted Tree-sitter AST shards (required) plus, when present, the accepted
source-history, evidence-collection (Semgrep), and CodeQL handoffs.  It never executes target code
and runs in-process: every input is an accepted, hash-verified artifact or target byte string.
A high score means "review first"; nothing here is a vulnerability finding.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.observability.spans import operation_span
from appsec_review.runtime.resources import Reservation, ResourceAdmission
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.swift_policy import SWIFT_KNOWN_GAP, is_swift_language, is_swift_path
from appsec_review.jobs.component_ownership import resolve_root_ownership
from appsec_review.jobs.delivery_scope import POLICY_IDENTITY, delivery_gap, scope_fields, source_in_scope
from appsec_review.retrieval.source_resolution import read_source_bytes, source_native

from . import scoring
from .complexity import COGNITIVE_DEVIATIONS, COGNITIVE_IDENTITY, CYCLOMATIC_IDENTITY, file_summary, function_units
from .dependencies import GRAPH_IDENTITY, GraphBuilder, extract, import_modules
from .heuristics import Extractor
from .inputs import accepted_handoff, has_handoff, read_json
from .languages import MAPPING_IDENTITY, SPECS, UNSCORED_GRAMMARS
from .rules import RULES_IDENTITY
from .semantic import CODEQL_LANGUAGES, codeql_paths, semgrep_signals
from .streaming import FilesDocumentWriter, ShardRowIndex
from .syntax import SourceFile, build_tree, code_lines
from appsec_review.jobs.job_review_prioritization.datasets import CONSUMES, DATASETS


SCHEMA = "appsec-review/review-prioritization/1"
JOB_ID = "job_review_prioritization"
SHARD_ID = "review-prioritization"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "load": ("accepted_inputs",),
    "extract": ("syntax_metrics", "dependency_graph", "semantic_evidence"),
    "prioritize": ("score",),
    "publish": ("index_priority", "publish_handoff"),
}
INT_SETTINGS = {
    "max_files": (1, 1_000_000), "max_file_bytes": (1, 64 * 1024 * 1024), "max_functions": (1, 5_000_000),
    "max_signals_per_file": (1, 100_000), "max_import_records": (1, 5_000_000), "max_semantic_paths": (0, 1_000_000),
    "max_flow_steps_per_path": (2, 10_000),
    "custom_parsing_min_operations": (1, 100_000), "state_mutation_min_operations": (1, 100_000),
    "scored_threshold": (1, 10_000),
}
INDEX_SETTINGS = {"file_top_fraction": float, "file_top_count": int, "function_top_fraction": float,
                  "function_top_count": int, "max_indexed_items": int, "max_evidence_links_per_item": int,
                  "max_graph_neighbors": int}
# Admission ledger reservation for the in-process syntax_metrics step: (minimum, maximum) per key.
RESERVATION_SETTINGS = {"cpu": (1, 256), "memory_mb": (1, 1024 * 1024), "io_slots": (0, 256),
                        "admission_timeout_seconds": (1, 7 * 24 * 3600)}
# Catalog language -> grammar for languages this batch scores (".tsx" files route to the TSX grammar).
SCORED_LANGUAGES = {"C": "c", "C++": "cpp", "C/C++": "cpp", "Java": "java", "C#": "csharp", "Go": "go",
                    "JavaScript": "javascript", "TypeScript": "typescript", "Rust": "rust", "PHP": "php",
                    "Ruby": "ruby"}
CATEGORY_ORDER = ("privilege_shift", "semantic_path", "sink", "ingress", "sensitive_wrapper", "state_mutation",
                  "custom_parsing", "parser", "middleware", "validator", "suppression", "public_api")
SKIPPED = {"SKIPPED_NA", "SKIPPED_POLICY"}


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Any) -> dict[str, Any]:
    path = unit.unit_root / "artifacts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _identity(prefix: str, *values: Any) -> str:
    return f"{prefix}-" + hashlib.sha256(canonical_json(list(values))).hexdigest()[:24]


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _settings(context) -> Mapping[str, Any]:
    settings = context.config.settings
    for key, (low, high) in INT_SETTINGS.items():
        if type(settings.get(key)) is not int or not low <= settings[key] <= high:
            raise ValueError(f"review prioritization setting is invalid: {key}")
    for key, low, high in (("custom_parsing_min_density", 0.0, 100.0), ("min_edge_confidence", 0.0, 1.0)):
        if not _number(settings.get(key)) or not low <= float(settings[key]) <= high:
            raise ValueError(f"review prioritization setting is invalid: {key}")
    thresholds = settings.get("cyclomatic_thresholds")
    if not isinstance(thresholds, list) or not thresholds or any(type(item) is not int or item < 1 for item in thresholds) \
            or thresholds != sorted(set(thresholds)) or settings["scored_threshold"] not in thresholds:
        raise ValueError("review prioritization cyclomatic thresholds must be ascending positive integers that "
                         "include scored_threshold")
    if type(settings.get("count_error_propagation")) is not bool:
        raise ValueError("review prioritization setting is invalid: count_error_propagation")
    if settings.get("normalization_population") not in {"run", "language"}:
        raise ValueError("review prioritization normalization_population must be run or language")
    weights = settings.get("priority_weights")
    if not isinstance(weights, Mapping) or not weights:
        raise ValueError("review prioritization priority_weights are required")
    for key, value in weights.items():
        if key not in scoring.FEATURES:
            raise ValueError(f"unknown review prioritization feature: {key}")
        if not _number(value) or value < 0:
            raise ValueError(f"review prioritization weight is invalid: {key}")
    if not any(float(value) > 0 for value in weights.values()):
        raise ValueError("review prioritization needs at least one positive weight")
    index = settings.get("index")
    if not isinstance(index, Mapping) or set(index) != set(INDEX_SETTINGS):
        raise ValueError("review prioritization index settings are invalid")
    for key, kind in INDEX_SETTINGS.items():
        value = index[key]
        if kind is float and (not _number(value) or not 0 < float(value) <= 1):
            raise ValueError(f"review prioritization index setting is invalid: {key}")
        if kind is int and (type(value) is not int or value < 0 or (key.startswith("max_") and value < 1)):
            raise ValueError(f"review prioritization index setting is invalid: {key}")
    sources = settings.get("sources")
    if not isinstance(sources, Mapping) or set(sources) != {"history", "semgrep", "codeql"} or any(
            type(value) is not bool for value in sources.values()):
        raise ValueError("review prioritization sources must enable or disable history, semgrep, and codeql")
    reservation = settings.get("syntax_metrics_reservation")
    if not isinstance(reservation, Mapping) or set(reservation) != set(RESERVATION_SETTINGS) or any(
            type(reservation[key]) is not int or not low <= reservation[key] <= high
            for key, (low, high) in RESERVATION_SETTINGS.items()):
        raise ValueError("review prioritization syntax_metrics_reservation is invalid")
    return settings


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("review prioritization topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"review prioritization task order mismatch: {step}")
    _settings(context)


def _status(gaps: list[str]) -> str:
    return "PARTIAL" if gaps else "SUCCEEDED"


def _component(path: str, roots: list[tuple[str, str]]) -> str | None:
    return resolve_root_ownership(path, roots)


def _load_inputs(run_root: Path) -> dict[str, Any]:
    intake_handoff, _ = accepted_handoff(run_root, "job_review_intake")
    catalog_handoff, catalog_sha = accepted_handoff(run_root, "job_target_catalog")
    tree_handoff, tree_sha = accepted_handoff(run_root, "job_tree_sitter_ast")
    intake = read_json(run_root, intake_handoff["outputs"]["publish_intake.publish_handoff"]["artifact"])
    catalog = read_json(run_root, catalog_handoff["outputs"]["publish_catalog.publish_handoff"]["artifact"])
    tree = read_json(run_root, tree_handoff["outputs"]["acceptance.publish_handoff"]["artifact"])
    if intake.get("schema") != "appsec-review/review-intake/1" or catalog.get("schema") != "appsec-review/target-catalog/1" \
            or tree.get("schema") != "appsec-review/tree-sitter-ast/1":
        raise ValueError("review prioritization inputs use unsupported schemas")
    if catalog.get("source_fingerprint") != intake.get("fingerprint", {}).get("sha256") or \
            tree.get("target_snapshot") != catalog.get("source_fingerprint"):
        raise ValueError("target snapshot, catalog, and Tree-sitter identities disagree")
    partition = read_json(run_root, catalog["artifacts"]["repository_discovery.partition_repository"])
    components = read_json(run_root, catalog["artifacts"]["component_discovery.catalog_components"])
    roots = sorted(((str(item.get("root") or "."), str(item["component_id"])) for item in components.get("components", ())),
                   key=lambda item: (-len(item[0]) if item[0] not in {"", "."} else 1, item[1]))
    files = {str(item["path"]): {"sha256": item["sha256"], "size_bytes": int(item["size_bytes"]),
                                 "language": item.get("language"), "generated": bool(item.get("generated")),
                                 **scope_fields(item),
                                 "component_id": _component(str(item["path"]), roots)}
             for item in partition.get("files", ())}
    for item in tree.get("generated_sources", ()):
        if not isinstance(item, Mapping) or not source_in_scope(item):
            raise ValueError("invalid generated source in accepted AST handoff")
        native = source_native(item)
        if not native or item["path"] in files:
            raise ValueError("generated source backing absent or logical path duplicated")
        read_source_bytes(run_root, Path("."), target_snapshot=catalog["source_fingerprint"],
                          path=item["path"], sha256=item["sha256"], native=native)
        files[item["path"]] = {**item, **scope_fields(item), **native,
                               "component_id": _component(str(item["workspace_path"]), roots)}
    return {"source_fingerprint": catalog["source_fingerprint"], "catalog_handoff_sha256": catalog_sha,
            "tree_sitter_handoff_sha256": tree_sha, "tree_sitter_artifact": tree_handoff["outputs"][
                "acceptance.publish_handoff"]["artifact"], "files": files,
            "components": [component for _root, component in roots]}


def _target_bytes(unit: UnitContext, path: str, sha256: str,
                  source: Mapping[str, Any] | None = None) -> bytes:
    return read_source_bytes(
        unit.job.run_root, unit.job.target_root or Path(),
        target_snapshot=str(getattr(unit.job, "source_fingerprint", "")),
        path=path, sha256=sha256, native=source_native(source or {}))


def _count(items: list[Mapping[str, Any]], key: str = "category") -> dict[str, int]:
    return dict(sorted(Counter(str(item[key]) for item in items).items()))


def _ordered(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {name: position for position, name in enumerate(CATEGORY_ORDER)}
    return sorted(signals, key=lambda item: (order.get(item["category"], len(order)), item.get("start_line") or 0,
                                             item["rule_id"]))


def _innermost(units: list[Mapping[str, Any]], line: int) -> str | None:
    best = None
    for unit in units:
        if unit["start_line"] <= line <= unit["end_line"] and (
                best is None or unit["start_byte"] >= best["start_byte"]):
            best = unit
    return best["function_id"] if best else None


def build_job() -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        inputs = _load_inputs(unit.job.run_root)
        policy_gaps: list[str] = []
        if not unit.job.tools.enable_swift:
            filtered = {path: value for path, value in inputs["files"].items()
                        if not (is_swift_path(path) or is_swift_language(value.get("language")))}
            if len(filtered) != len(inputs["files"]):
                policy_gaps.append(SWIFT_KNOWN_GAP)
            inputs["files"] = filtered
        if inputs["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match accepted inputs")
        optional = {name: has_handoff(unit.job.run_root, job_id) for name, job_id in (
            ("history", "job_source_history_analysis"), ("semgrep", "job_evidence_collection"),
            ("codeql", "job_codeql_analysis"))}
        unit.job.events.write("REVIEW_PRIORITIZATION_STARTED", file_count=len(inputs["files"]),
                              optional_inputs=optional, sources=dict(settings["sources"]))
        return {"inputs": {key: value for key, value in inputs.items() if key != "files"},
                "files_artifact": _write(unit, "catalog-files.json", inputs["files"]), "optional": optional,
                "gaps": policy_gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if policy_gaps else "SUCCEEDED"}

    def catalog_files(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
        return read_json(unit.job.run_root, unit.output("load.accepted_inputs")["files_artifact"])

    def syntax_metrics(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        reservation = settings["syntax_metrics_reservation"]
        action = "review_prioritization.syntax_metrics"
        admission = ResourceAdmission(unit.job.metadata_root, unit.job.review_policy.resources)
        request = Reservation(reservation["cpu"], reservation["memory_mb"], reservation["io_slots"])
        with admission.reserve(request, events=unit.job.events, action=action,
                               timeout_seconds=reservation["admission_timeout_seconds"],
                               unit_id=unit.unit_id) as lease_id, \
                operation_span(unit.job.events, action, unit_id=unit.unit_id, resource_lease_id=lease_id):
            return extract_syntax(unit, settings)

    def extract_syntax(unit: UnitContext, settings: Mapping[str, Any]) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        files = catalog_files(unit)
        tree = read_json(unit.job.run_root, loaded["inputs"]["tree_sitter_artifact"])
        reasons: dict[str, list[str]] = defaultdict(list)
        shard_rows: list[Mapping[str, Any]] = []
        for disposition in tree.get("dispositions", ()):
            for gap in disposition.get("gaps", ()):
                path, _, reason = str(gap).partition(": ")
                if path in files:
                    reasons[path].append(reason)
            if "artifact" not in disposition:
                language = str(disposition.get("language"))
                for path, value in files.items():
                    if value["language"] == language or (language == "TSX" and path.endswith(".tsx")):
                        reasons[path].append(f"tree-sitter scope {disposition.get('terminal_status')}: "
                                             f"{disposition.get('reason') or 'no shard'}")
                continue
            shard_rows.append(disposition["artifact"])
        del tree
        path_gaps: list[tuple[str, str]] = []
        unscored: Counter[str] = Counter()
        skipped: Counter[str] = Counter()
        candidates: list[str] = []
        # Decide from catalog metadata alone, before any AST row or target byte is loaded.
        for path in sorted(files):
            value = files[path]
            language = value["language"]
            grammar = SCORED_LANGUAGES.get(str(language))
            if grammar is None:
                if language is None:
                    skipped["not_source"] += 1
                else:
                    unscored[str(language)] += 1
                continue
            if not source_in_scope(value):
                skipped["out_of_delivery_scope"] += 1
                continue
            if value["size_bytes"] > int(settings["max_file_bytes"]):
                skipped["file_byte_bound"] += 1
                path_gaps.append((path, "file_byte_bound_reached"))
                continue
            candidates.append(path)
        function_budget = int(settings["max_functions"])
        thresholds = list(settings["cyclomatic_thresholds"])
        limit = int(settings["max_signals_per_file"])
        aggregates: dict[str, dict[str, Any]] = {}
        file_count = function_count = processed = 0
        artifact_path = unit.unit_root / "artifacts" / "syntax-facts.json"
        writer = FilesDocumentWriter(artifact_path)
        try:
            with ShardRowIndex(unit.job.run_root, shard_rows, candidates, unit.unit_root / "scratch") as index:
                for path in candidates:
                    value = files[path]
                    file_gaps = sorted(set(reasons.get(path, ())))
                    if not index.has_rows(path):
                        path_gaps.append((path, f"ast_unavailable ({'; '.join(file_gaps) or 'no accepted Tree-sitter rows'})"))
                        continue
                    if any("node limit" in reason or "limit" in reason for reason in file_gaps):
                        path_gaps.append((path, f"ast_truncated ({'; '.join(file_gaps)})"))
                        continue
                    if processed >= int(settings["max_files"]):
                        path_gaps.append((path, "file_bound_reached"))
                        continue
                    rows = index.rows(path)
                    if any(row.get("file_sha256") != value["sha256"] for row in rows):
                        raise ValueError(f"Tree-sitter rows do not match the accepted catalog hash: {path}")
                    row_grammar = str(rows[0]["location"]["producer_location"].get("grammar"))
                    if row_grammar in UNSCORED_GRAMMARS or row_grammar not in SPECS:
                        unscored[f"grammar:{row_grammar}"] += 1
                        continue
                    processed += 1
                    spec = SPECS[row_grammar]
                    data = _target_bytes(unit, path, value["sha256"], value)
                    root, errors = build_tree(rows)
                    del rows
                    source = SourceFile(path, value["sha256"], row_grammar, spec.language, data, root, errors)
                    units, truncated = function_units(source, spec, count_error_propagation=bool(
                        settings["count_error_propagation"]), limit=max(0, function_budget))
                    function_budget -= len(units)
                    imports, declarations = extract(source, spec)
                    extractor = Extractor(source, spec, units, import_modules(imports), settings)
                    extractor.run()
                    for item in extractor.signals:
                        item["signal_id"] = _identity("sig", item["producer"], item["rule_id"], item["path"],
                                                      item["start_byte"], item["end_byte"], item["function_id"],
                                                      item["category"], item["surface"])
                    for item in extractor.suppressions:
                        item["signal_id"] = _identity("sup", item["rule_id"], item["path"], item["start_byte"],
                                                      item["end_byte"])
                    sloc = len(code_lines(root))
                    file_record_gaps = [gap] if (gap := delivery_gap(value)) else []
                    if errors or "parse diagnostics present" in file_gaps:
                        file_record_gaps.append(f"parse_errors:{errors}")
                    unsupported: Counter[str] = Counter()
                    for item in units:
                        item.pop("_node", None)
                        unsupported.update(item["unsupported_constructs"])
                        owned = [signal for signal in extractor.signals if signal["function_id"] == item["function_id"]]
                        suppressions = [entry for entry in extractor.suppressions
                                        if entry["function_id"] == item["function_id"]]
                        item["signal_counts"] = _count(owned)
                        item["suppression_counts"] = _count(suppressions)
                        item["suppression_count"] = len(suppressions)
                    file_record_gaps.extend(f"unsupported_construct:{name}:{count}"
                                            for name, count in sorted(unsupported.items()))
                    if truncated:
                        file_record_gaps.append("function_bound_reached")
                    signals = _ordered(extractor.signals)
                    if len(signals) > limit:
                        file_record_gaps.append(f"signals_truncated:{len(signals) - limit}")
                    summary = file_summary(units, sloc, thresholds)
                    writer.add(path, {
                        "path": path, "sha256": value["sha256"], "size_bytes": value["size_bytes"],
                        "line_count": source.line_count(), "language": spec.language, "grammar": row_grammar,
                        "component_id": value["component_id"], "parse_error_count": errors,
                        "generated": bool(value.get("generated")), **scope_fields(value),
                        **source_native(value),
                        "canonical_artifact_identity": value.get("canonical_artifact_identity"),
                        "build_unit_id": value.get("build_unit_id"), "workspace_path": value.get("workspace_path"),
                        **summary,
                        "signal_counts": _count(extractor.signals), "suppression_counts": _count(extractor.suppressions),
                        "suppression_count": len(extractor.suppressions), "units": units, "signals": signals[:limit],
                        "suppressions": extractor.suppressions[:limit], "imports": imports,
                        "declarations": declarations, "gaps": file_record_gaps,
                    })
                    path_gaps.extend((path, gap) for gap in file_record_gaps)
                    totals = aggregates.setdefault(spec.language, {
                        "file_count": 0, "function_count": 0, "sloc": 0, "cyclomatic_sum": 0,
                        "above": dict.fromkeys(thresholds, 0), "suppression_count": 0})
                    cyclomatic = [int(item["cyclomatic"]) for item in units]
                    totals["file_count"] += 1
                    totals["function_count"] += len(cyclomatic)
                    totals["sloc"] += summary["sloc"]
                    totals["cyclomatic_sum"] += sum(cyclomatic)
                    for threshold in thresholds:
                        totals["above"][threshold] += sum(1 for item in cyclomatic if item > threshold)
                    totals["suppression_count"] += len(extractor.suppressions)
                    file_count += 1
                    function_count += len(units)
            # Stable sort keeps per-file gaps in catalog path order, as before the pre-filter existed.
            gaps = [f"{path}: {gap}" for path, gap in sorted(path_gaps, key=lambda item: item[0])]
            gaps.extend(f"language_not_scored:{language} ({count} files)"
                        for language, count in sorted(unscored.items()))
            if function_budget <= 0:
                gaps.append("function_bound_reached")
            by_language = {language: {
                "file_count": totals["file_count"], "function_count": totals["function_count"], "sloc": totals["sloc"],
                "cyclomatic_average": round(totals["cyclomatic_sum"] / totals["function_count"], 6)
                if totals["function_count"] else None,
                "share_above_threshold": {str(threshold): round(totals["above"][threshold] / totals["function_count"], 6)
                                          if totals["function_count"] else None for threshold in thresholds},
                "suppression_count": totals["suppression_count"],
            } for language, totals in sorted(aggregates.items())}
            writer.finish({"schema": "appsec-review/review-prioritization-syntax/1",
                           "identities": {"cyclomatic": CYCLOMATIC_IDENTITY, "cognitive": COGNITIVE_IDENTITY,
                                          "rules": RULES_IDENTITY, "mapping": MAPPING_IDENTITY},
                           "by_language": by_language})
        except BaseException:
            writer.abort()
            raise
        skipped_counts = dict(sorted(skipped.items()))
        unit.job.events.write("REVIEW_PRIORITIZATION_SYNTAX_EXTRACTED", file_count=file_count,
                              function_count=function_count, gap_count=len(gaps), skipped=skipped_counts)
        return {"artifact": _artifact(unit.job.run_root, artifact_path), "file_count": file_count,
                "function_count": function_count, "skipped": skipped_counts, "gaps": gaps,
                "terminal_status": _status(gaps)}

    def syntax_doc(unit: UnitContext) -> Mapping[str, Any]:
        return read_json(unit.job.run_root, unit.output("extract.syntax_metrics")["artifact"])

    def dependency_graph(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        files = catalog_files(unit)
        facts = syntax_doc(unit)["files"]
        builder = GraphBuilder({path: {"grammar": value["grammar"], "imports": value["imports"],
                                       "declarations": value["declarations"]} for path, value in facts.items()},
                               files, lambda path: _target_bytes(unit, path, files[path]["sha256"], files[path]),
                               min_confidence=float(settings["min_edge_confidence"]),
                               max_records=int(settings["max_import_records"]))
        graph = builder.build({path: value["component_id"] for path, value in files.items()})
        gaps: list[str] = []
        unresolved = {path: value for path, value in graph["files"].items()
                      if value["unresolved_import_count"] or value["dynamic_import_count"]}
        for path, value in sorted(unresolved.items()):
            items = [f"{item['specifier']} ({item['method']})" for item in value["imports"]
                     if item["status"] in {"unresolved", "dynamic"}]
            gaps.append(f"{path}: unresolved_or_dynamic_imports: {'; '.join(items[:10])}")
        if graph["truncated"]:
            gaps.append("import_record_bound_reached")
        unit.job.events.write("REVIEW_PRIORITIZATION_GRAPH_BUILT", edge_count=len(graph["edges"]),
                              module_count=len(graph["modules"]), unresolved_file_count=len(unresolved))
        return {"artifact": _write(unit, "dependency-graph.json", graph), "edge_count": len(graph["edges"]),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def semantic_evidence(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        facts = syntax_doc(unit)["files"]
        files = catalog_files(unit)
        gaps: list[str] = []
        if settings["sources"]["semgrep"]:
            semgrep = semgrep_signals(unit.job.run_root, unit.job.repository_root)
        else:
            semgrep = {"status": "SKIPPED_POLICY", "signals": [], "gaps": ["semgrep_review_signals_disabled"]}
        if settings["sources"]["codeql"]:
            codeql = codeql_paths(unit.job.run_root, limit=int(settings["max_semantic_paths"]),
                                  step_limit=int(settings["max_flow_steps_per_path"]))
        else:
            codeql = {"status": "SKIPPED_POLICY", "paths": [], "languages": {}, "gaps": ["semantic_paths_disabled"]}
        gaps.extend([*semgrep["gaps"], *codeql["gaps"]])
        signals = []
        for item in semgrep["signals"]:
            path = item["path"]
            if path not in files or (item.get("file_sha256") and item["file_sha256"] != files[path]["sha256"]):
                gaps.append(f"{path}: semgrep_signal_not_bound_to_accepted_file")
                continue
            item["file_sha256"] = files[path]["sha256"]
            item["function_id"] = _innermost(facts.get(path, {}).get("units", []), item["start_line"])
            item["signal_id"] = _identity("sig", "semgrep", item["rule_id"], path, item["start_line"],
                                          item["end_line"], item["category"])
            signals.append(item)
        paths = []
        for item in codeql["paths"]:
            ends = [step["location"] for step in item["flow_steps"]]
            if any(end["path"] not in files or end.get("file_sha256") not in {None, files[end["path"]]["sha256"]}
                   for end in ends):
                gaps.append(f"semantic path {item['path_id']} is not bound to accepted files")
                continue
            item["flow_functions"] = list(dict.fromkeys(
                function_id for step in item["flow_steps"]
                if (function_id := _innermost(
                    facts.get(step["location"]["path"], {}).get("units", []),
                    int(step["location"]["start_line"]))) is not None))
            item["source_function"] = _innermost(facts.get(item["source"]["path"], {}).get("units", []),
                                                 int(item["source"]["start_line"]))
            item["sink_function"] = _innermost(facts.get(item["sink"]["path"], {}).get("units", []),
                                               int(item["sink"]["start_line"]))
            item["signal_id"] = item["path_id"]
            paths.append(item)
        document = {"schema": "appsec-review/review-prioritization-semantic/1",
                    "semgrep": {key: value for key, value in semgrep.items() if key != "signals"},
                    "codeql": {key: value for key, value in codeql.items() if key != "paths"},
                    "semgrep_signals": signals, "semantic_paths": paths}
        return {"artifact": _write(unit, "semantic-evidence.json", document), "semgrep_status": semgrep["status"],
                "codeql_status": codeql["status"], "signal_count": len(signals), "path_count": len(paths),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def history_values(unit: UnitContext, settings: Mapping[str, Any]) -> tuple[dict[str, Any], list[str], str]:
        if not settings["sources"]["history"]:
            return {"files": {}, "symbols": {}}, ["history_hotspots_disabled"], "SKIPPED_POLICY"
        if not has_handoff(unit.job.run_root, "job_source_history_analysis"):
            return {"files": {}, "symbols": {}}, ["history_hotspots_unavailable: source history analysis has no accepted handoff"], "UNAVAILABLE"
        from appsec_review.jobs.job_source_history_analysis import load_accepted_history
        history = load_accepted_history(unit.job.run_root) or {}
        decision = str(history.get("decision"))
        signals_identity = history.get("ranking", {}).get("signals")
        if not signals_identity:
            return {"files": {}, "symbols": {}}, [f"history_hotspots_unavailable: history decision {decision}"], "UNAVAILABLE"
        document = read_json(unit.job.run_root, signals_identity)
        if document.get("schema") != "appsec-review/source-history-signals/2":
            raise ValueError("accepted history signals use an unsupported SII schema")
        values = {
            "files": {path: float(value["sii"]["score"]) for path, value in document.get("files", {}).items()
                      if value.get("sii")},
            "symbols": {(value["path"], int(value["start_byte"]), int(value["end_byte"])):
                        float(value["sii"]["score"])
                        for value in document.get("symbols", {}).values() if value.get("sii")},
        }
        status = "EXACT" if history.get("binding") == "exact" else "PARTIAL"
        gaps = [f"history: {gap}" for gap in history.get("gaps", ())][:20]
        return values, gaps, status

    def score(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        facts = syntax_doc(unit)["files"]
        graph = read_json(unit.job.run_root, unit.output("extract.dependency_graph")["artifact"])
        semantic = read_json(unit.job.run_root, unit.output("extract.semantic_evidence")["artifact"])
        history, history_gaps, history_status = history_values(unit, settings)
        covered_languages = {language for language, status in semantic["codeql"].get("languages", {}).items()
                             if status == "SUCCEEDED"}
        semgrep_by_file: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for item in semantic["semgrep_signals"]:
            semgrep_by_file[item["path"]].append(item)
        paths_by_file: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for item in semantic["semantic_paths"]:
            for end in {step["location"]["path"] for step in item["flow_steps"]}:
                paths_by_file[end].append(item)
        scored = str(settings["scored_threshold"])
        file_items: list[dict[str, Any]] = []
        function_items: list[dict[str, Any]] = []
        for path, record in sorted(facts.items()):
            coupling = graph["files"].get(path, {})
            semantic_available = CODEQL_LANGUAGES.get(record["language"]) in covered_languages
            if history_status in {"EXACT", "PARTIAL"}:
                hotspot = history["files"].get(path)
            else:
                hotspot = None
            inherited = {"afferent_coupling": coupling.get("afferent_coupling"),
                         "efferent_coupling": coupling.get("efferent_coupling"),
                         "instability": coupling.get("instability"), "history_hotspot": hotspot}
            semgrep_counts = Counter(item["category"] for item in semgrep_by_file.get(path, ()))
            file_paths = paths_by_file.get(path, [])
            features = {
                "cyclomatic": record["cyclomatic_max"], "cognitive": record["cognitive_max"],
                "complexity_density": record["complexity_density"],
                "share_above_threshold": record["share_above_threshold"].get(scored),
                "suppression_density": round(record["suppression_count"] / record["sloc"], 6) if record["sloc"] else None,
                **{name: int(record["signal_counts"].get(name, 0)) + semgrep_counts.get(name, 0)
                   for name in scoring.SIGNAL_FEATURES},
                "semantic_path": len(file_paths) if semantic_available else None, **inherited,
            }
            evidence = [*(item["signal_id"] for item in file_paths),
                        *(item["signal_id"] for item in record["signals"]),
                        *(item["signal_id"] for item in semgrep_by_file.get(path, ())),
                        *(item["signal_id"] for item in record["suppressions"])]
            file_items.append({"item_id": f"file:{path}", "scope": "file", "path": path, "name": path,
                               "generated": bool(record.get("generated")), **scope_fields(record),
                               **source_native(record),
                               "canonical_artifact_identity": record.get("canonical_artifact_identity"),
                               "language": record["language"], "component_id": record["component_id"],
                               "start_line": 1, "features": features, "evidence": list(dict.fromkeys(evidence)),
                               "coupling_lower_bound": coupling.get("coupling_lower_bound", False),
                               "gaps": record["gaps"]})
            for item in record["units"]:
                function_id = item["function_id"]
                semgrep_owned = [signal for signal in semgrep_by_file.get(path, ()) if signal["function_id"] == function_id]
                owned_paths = [value for value in file_paths
                               if function_id in value.get("flow_functions", ())]
                unit_features = {
                    "cyclomatic": item["cyclomatic"], "cognitive": item["cognitive"],
                    "complexity_density": item["complexity_density"],
                    "suppression_density": round(item["suppression_count"] / item["sloc"], 6) if item["sloc"] else None,
                    **{name: int(item["signal_counts"].get(name, 0)) +
                       sum(1 for signal in semgrep_owned if signal["category"] == name)
                       for name in scoring.SIGNAL_FEATURES},
                    "semantic_path": len(owned_paths) if semantic_available else None, **inherited,
                }
                unit_features["history_hotspot"] = history["symbols"].get(
                    (path, int(item["start_byte"]), int(item["end_byte"]))) if history_status in {"EXACT", "PARTIAL"} else None
                links = [*(value["signal_id"] for value in owned_paths),
                         *(signal["signal_id"] for signal in record["signals"] if signal["function_id"] == function_id),
                         *(signal["signal_id"] for signal in semgrep_owned),
                         *(entry["signal_id"] for entry in record["suppressions"] if entry["function_id"] == function_id)]
                function_items.append({
                    "generated": bool(record.get("generated")), **scope_fields(record),
                    **source_native(record),
                    "canonical_artifact_identity": record.get("canonical_artifact_identity"),
                    "item_id": f"function:{function_id}", "scope": "function", "path": path, "function_id": function_id,
                    "name": item["qualified_name"], "language": record["language"], "component_id": record["component_id"],
                    "start_line": item["start_line"], "end_line": item["end_line"], "start_byte": item["start_byte"],
                    "end_byte": item["end_byte"], "start_column": item["start_column"], "end_column": item["end_column"],
                    "anonymous": item["anonymous"], "parent_function": item["parent_function"],
                    "features": unit_features, "evidence": list(dict.fromkeys(links)),
                    "metrics": {key: item[key] for key in (
                        "sloc", "cyclomatic_with_error_propagation", "cyclomatic_without_error_propagation",
                        "error_propagation", "decisions", "increments", "max_nesting", "recursive", "parse_error",
                        "unsupported_constructs", "custom_parsing", "state_mutation", "wrapper_surfaces")},
                    "coupling_lower_bound": coupling.get("coupling_lower_bound", False),
                    "gaps": ["parse_error"] if item["parse_error"] else [],
                })
        weights = {key: float(value) for key, value in settings["priority_weights"].items()}
        population = str(settings["normalization_population"])
        ranked_files = scoring.rank(file_items, weights, scoring.FILE_FEATURES, population=population)
        ranked_functions = scoring.rank(function_items, weights, scoring.FUNCTION_FEATURES, population=population)
        index = settings["index"]
        ceiling = int(index["max_indexed_items"])
        file_count = scoring.selection_size(len(ranked_files), fraction=float(index["file_top_fraction"]),
                                            count=int(index["file_top_count"]), ceiling=ceiling)
        function_count = scoring.selection_size(len(ranked_functions), fraction=float(index["function_top_fraction"]),
                                                count=int(index["function_top_count"]),
                                                ceiling=max(0, ceiling - file_count))
        gaps = list(history_gaps)
        document = {"schema": "appsec-review/review-prioritization-ranking/1", "identity": scoring.SCORE_IDENTITY,
                    "authority": "a high score means review first; it is never a vulnerability finding",
                    "weights": weights, "population": population, "history_status": history_status,
                    "selection": {"files": file_count, "functions": function_count},
                    "files": ranked_files, "functions": ranked_functions}
        return {"artifact": _write(unit, "priority.json", document), "file_count": len(ranked_files),
                "function_count": len(ranked_functions), "selected_files": file_count,
                "selected_functions": function_count, "history_status": history_status, "gaps": gaps,
                "terminal_status": _status(gaps)}

    def _line_location(snapshot: str, data: bytes, path: str, sha256: str, start_line: int, end_line: int,
                       method: str, confidence: float, producer: Mapping[str, Any]) -> SourceLocation:
        offsets = [0, *(match.end() for match in re.finditer(b"\n", data))]
        start_line = max(1, min(start_line, len(offsets)))
        end_line = max(start_line, min(end_line, len(offsets)))
        end_byte = offsets[end_line] if end_line < len(offsets) else len(data)
        return SourceLocation(snapshot, path, sha256, offsets[start_line - 1], max(offsets[start_line - 1], end_byte),
                              start_line, end_line, 1, 1, producer, method, confidence)

    def index_priority(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        snapshot = unit.job.source_fingerprint
        syntax_output = unit.output("extract.syntax_metrics")
        ranking_output = unit.output("prioritize.score")
        graph_output = unit.output("extract.dependency_graph")
        semantic_output = unit.output("extract.semantic_evidence")
        facts = syntax_doc(unit)["files"]
        ranking = read_json(unit.job.run_root, ranking_output["artifact"])
        graph = read_json(unit.job.run_root, graph_output["artifact"])
        semantic = read_json(unit.job.run_root, semantic_output["artifact"])
        files = catalog_files(unit)
        selected_files = ranking["files"][:ranking["selection"]["files"]]
        selected_functions = ranking["functions"][:ranking["selection"]["functions"]]
        evidence_limit = int(settings["index"]["max_evidence_links_per_item"])
        evidence_records: dict[str, Mapping[str, Any]] = {}
        for record in facts.values():
            for item in [*record["signals"], *record["suppressions"]]:
                evidence_records[item["signal_id"]] = item
        for item in semantic["semgrep_signals"]:
            evidence_records[item["signal_id"]] = item
        for item in semantic["semantic_paths"]:
            evidence_records[item["signal_id"]] = item
        fingerprint = index_fingerprint(
            name="priority", target_snapshot=snapshot,
            producer_artifacts=[value["artifact"] for value in (syntax_output, graph_output, semantic_output,
                                                                ranking_output)],
            tool_identity={"job": JOB_ID, "score": scoring.SCORE_IDENTITY, "rules": RULES_IDENTITY,
                           "config": hashlib.sha256(canonical_json(dict(settings))).hexdigest()},
            parser_identity="tree-sitter-accepted-shards", normalizer_identity=MAPPING_IDENTITY + "+" + POLICY_IDENTITY,
            mapping_identity=GRAPH_IDENTITY)
        path = unit.job.run_root / "data" / "indices" / "priority" / SHARD_ID / f"{fingerprint}.sqlite"
        gaps = sorted(set([*syntax_output["gaps"], *graph_output["gaps"], *semantic_output["gaps"],
                           *ranking_output["gaps"]]))
        data_cache: dict[str, bytes] = {}

        def data_of(file_path: str) -> bytes:
            if file_path not in data_cache:
                data_cache[file_path] = _target_bytes(unit, file_path, files[file_path]["sha256"], files[file_path])
            return data_cache[file_path]

        if not path.exists():
            builder = IndexBuilder(path, name="priority", fingerprint=fingerprint, target_snapshot=snapshot,
                                   shard_id=SHARD_ID)
            entity_ids: dict[str, str] = {}
            evidence_ids: dict[str, str] = {}

            def evidence_entity(signal_id: str) -> str | None:
                if signal_id in evidence_ids:
                    return evidence_ids[signal_id]
                record = evidence_records.get(signal_id)
                if record is None:
                    return None
                identity = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, snapshot, {"signal_id": signal_id})
                if record.get("category") == "semantic_path":
                    sink = record["sink"]
                    location = _line_location(snapshot, data_of(sink["path"]), sink["path"], files[sink["path"]]["sha256"],
                                              int(sink["start_line"]), int(sink["end_line"]), "codeql-sarif-flow-step",
                                              1.0, {"producer": "codeql", "role": "sink", **source_native(files[sink["path"]])})
                    text = (f"semantic_path {record['rule_id']} {record['source']['path']}:{record['source']['start_line']}"
                            f" -> {sink['path']}:{sink['start_line']} steps {record['steps']}")
                elif record.get("producer") == "semgrep":
                    location = _line_location(snapshot, data_of(record["path"]), record["path"],
                                              files[record["path"]]["sha256"], int(record["start_line"]),
                                              int(record["end_line"]), "semgrep-line-location", 0.9,
                                              {"producer": "semgrep", "rule_id": record["rule_id"],
                                               **source_native(files[record["path"]])})
                    text = f"{record['category']} {record['surface']} {record['rule_id']} semgrep"
                else:
                    location = SourceLocation(snapshot, record["path"], record["file_sha256"], int(record["start_byte"]),
                                              int(record["end_byte"]), int(record["start_line"]), int(record["end_line"]),
                                              int(record["start_column"]), int(record["end_column"]),
                                              {"producer": "tree-sitter", "rule_id": record["rule_id"],
                                               **source_native(files[record["path"]])},
                                              "tree-sitter-byte-and-point-exact", 1.0)
                    kind = "suppression " + str(record.get("tool")) if signal_id.startswith("sup-") else record["surface"]
                    text = f"{record['category']} {kind} {record['rule_id']} {record.get('basis')}"
                payload = {**record, "authority": "review lead; not a finding"}
                builder.add_entity(EntityRecord(identity, signal_id, str(record.get("rule_id")), text, payload, location))
                evidence_ids[signal_id] = identity.value
                if record.get("category") == "semantic_path":
                    previous = None
                    for step in record["flow_steps"]:
                        point = step["location"]
                        step_identity = LogicalIdentity.derive(EntityKind.REVIEW_FLOW_STEP, snapshot, {
                            "path_id": signal_id, "ordinal": step["ordinal"], "source": point,
                        })
                        step_location = _line_location(
                            snapshot, data_of(point["path"]), point["path"], files[point["path"]]["sha256"],
                            int(point["start_line"]), int(point["end_line"]), "codeql-sarif-flow-step", 1.0,
                            {"producer": "codeql", "path_id": signal_id, "ordinal": step["ordinal"],
                             **source_native(files[point["path"]])})
                        step_text = (f"flow step {step['ordinal']} of {signal_id} "
                                     f"{point['path']}:{point['start_line']} {step['message']}")
                        builder.add_entity(EntityRecord(step_identity, f"{signal_id}:{step['ordinal']}",
                                                        f"flow step {step['ordinal']}", step_text,
                                                        {"path_id": signal_id, "ordinal": step["ordinal"],
                                                         "message": step["message"], "producer": "codeql",
                                                         "basis": "verified_semantic_path"}, step_location))
                        builder.add_relation(RelationRecord(RelationKind.CONTAINS, identity.value,
                                                            step_identity.value, True, 1.0))
                        if previous is not None:
                            builder.add_relation(RelationRecord(RelationKind.FLOWS_TO, previous,
                                                                step_identity.value, True, 1.0,
                                                                payload={"path_id": signal_id}))
                        previous = step_identity.value
                return identity.value

            for item in [*selected_files, *selected_functions]:
                identity = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, snapshot, {"item_id": item["item_id"]})
                entity_ids[item["item_id"]] = identity.value
                record = facts[item["path"]]
                if item["scope"] == "function":
                    location = SourceLocation(snapshot, item["path"], record["sha256"], int(item["start_byte"]),
                                              int(item["end_byte"]), int(item["start_line"]), int(item["end_line"]),
                                              int(item["start_column"]), int(item["end_column"]),
                                              {"producer": "tree-sitter", "function_id": item["function_id"],
                                               **source_native(files[item["path"]])},
                                              "tree-sitter-byte-and-point-exact", 1.0)
                else:
                    location = SourceLocation(snapshot, item["path"], record["sha256"], 0, int(record["size_bytes"]), 1,
                                              max(1, int(record["line_count"])), 1, 1, {"producer": "tree-sitter",
                                                                                        "scope": "file",
                                                                                        **source_native(files[item["path"]])},
                                              "tree-sitter-file-span", 1.0)
                top = sorted(item["percentiles"].items(), key=lambda pair: (-pair[1], pair[0]))[:5]
                text = (f"review priority {item['scope']} rank {item['rank']} score {item['score']} {item['language']} "
                        f"{item['name']} top features " + " ".join(f"{name}={item['features'][name]}" for name, _ in top))
                linked = item["evidence"][:evidence_limit]
                payload = {**item, "evidence": linked, "evidence_truncated": max(0, len(item["evidence"]) - evidence_limit),
                           "score_identity": scoring.SCORE_IDENTITY, "weights": ranking["weights"],
                           "population": ranking["population"],
                           "authority": "review-first ordering; never a vulnerability finding"}
                builder.add_entity(EntityRecord(identity, item["item_id"], item["name"], text, payload, location))
                for signal_id in linked:
                    target = evidence_entity(signal_id)
                    if target is not None:
                        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value, target, True, 1.0))
            for item in selected_functions:
                parent = entity_ids.get(f"file:{item['path']}")
                if parent is not None:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, parent, entity_ids[item["item_id"]],
                                                        True, 1.0))
            selected_paths = {item["path"] for item in [*selected_files, *selected_functions]}
            context_ids: dict[str, str] = {}
            graph_neighbor_limit = int(settings["index"]["max_graph_neighbors"])

            def file_node(file_path: str) -> str | None:
                selected = entity_ids.get(f"file:{file_path}")
                if selected is not None:
                    return selected
                if file_path in context_ids:
                    return context_ids[file_path]
                if len(context_ids) >= graph_neighbor_limit:
                    return None
                info = files[file_path]
                file_bytes = data_of(file_path)
                identity = LogicalIdentity.derive(EntityKind.REVIEW_CONTEXT_FILE, snapshot, {"path": file_path})
                location = SourceLocation(snapshot, file_path, info["sha256"], 0, len(file_bytes), 1,
                                          max(1, len(file_bytes.splitlines())), 1, 1,
                                          {"producer": "accepted-source", "scope": "dependency-context",
                                           **source_native(info)},
                                          "accepted-file-span", 1.0)
                builder.add_entity(EntityRecord(identity, file_path, file_path,
                                                f"dependency context {file_path}",
                                                {"path": file_path, "scope": "dependency-context",
                                                 **scope_fields(info), **source_native(info),
                                                 "authority": "graph context; not a vulnerability finding"}, location))
                context_ids[file_path] = identity.value
                return identity.value

            indexed_edges: set[tuple[str, str]] = set()
            for edge in sorted(graph["edges"], key=lambda item: (item["from"], item["to"],
                                                               -float(item["confidence"]), item["line"])):
                if edge["from"] not in selected_paths and edge["to"] not in selected_paths:
                    continue
                edge_key = (edge["from"], edge["to"])
                if edge_key in indexed_edges:
                    continue
                left, right = file_node(edge["from"]), file_node(edge["to"])
                if left is None or right is None:
                    gaps.append("dependency_graph_context_bound_reached")
                    continue
                exact = float(edge["confidence"]) >= 1.0
                builder.add_relation(RelationRecord(
                    RelationKind.DEPENDS_ON, left, right, exact, float(edge["confidence"]),
                    None if exact else f"import resolved by {edge['method']}",
                    {"method": edge["method"], "line": edge["line"]}))
                indexed_edges.add(edge_key)
            for item in selected_functions:
                if f"file:{item['path']}" not in entity_ids and item["path"] in context_ids:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, context_ids[item["path"]],
                                                        entity_ids[item["item_id"]], True, 1.0))
            syntax_gaps = [gap for gap in syntax_output["gaps"]]
            builder.add_coverage("complexity", "partial" if syntax_gaps else "complete", "; ".join(syntax_gaps[:20]) or None)
            builder.add_coverage("dependency-graph", "partial" if graph_output["gaps"] else "complete",
                                 "; ".join(graph_output["gaps"][:20]) or None)
            semgrep_status = semantic_output["semgrep_status"]
            builder.add_coverage("semgrep-review-signals", "complete" if semgrep_status == "SUCCEEDED" else
                                 "partial" if semgrep_status == "PARTIAL" else "unavailable",
                                 "; ".join(semantic["semgrep"].get("gaps", [])[:10]) or None)
            codeql_status = semantic_output["codeql_status"]
            builder.add_coverage("codeql-semantic-paths", "complete" if codeql_status == "SUCCEEDED" else
                                 "partial" if codeql_status == "PARTIAL" else "unavailable",
                                 "; ".join(semantic["codeql"].get("gaps", [])[:10]) or None)
            history_status = ranking_output["history_status"]
            builder.add_coverage("history-hotspots", "complete" if history_status == "EXACT" else
                                 "partial" if history_status == "PARTIAL" else "unavailable",
                                 "; ".join(ranking_output["gaps"][:10]) or history_status)
            builder.add_coverage("prioritization", "partial" if gaps else "complete",
                                 f"indexed {len(selected_files)} of {len(ranking['files'])} files and "
                                 f"{len(selected_functions)} of {len(ranking['functions'])} functions")
            builder.build()
        identity = IndexIdentity("priority", "appsec-review/retrieval-index/2", file_sha256(path), fingerprint,
                                 _rel(unit.job.run_root, path), {"job": JOB_ID}, tuple(gaps[:200]), SHARD_ID)
        upstream_path, upstream_sha = resolve_context_manifest(unit.job)
        upstream, _ = load_verified_manifest(unit.job.run_root, upstream_path, upstream_sha)
        base = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in upstream["indexes"]
                if item.get("producer", {}).get("job") != JOB_ID]
        manifest_path = (unit.job.run_root / "data" / "indices" / "manifests" /
                         f"review-prioritization-{unit.job.attempt_id}.json")
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=snapshot,
                       target_root=(unit.job.target_root or Path()).resolve(), indexes=[*base, identity],
                       upstream_manifests=({"path": _rel(unit.job.run_root, upstream_path), "sha256": upstream_sha},))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        return {"index_identity": asdict(identity), "manifest": _artifact(unit.job.run_root, manifest_path),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = unit.output("load.accepted_inputs")
        syntax_output = unit.output("extract.syntax_metrics")
        semantic_output = unit.output("extract.semantic_evidence")
        ranking_output = unit.output("prioritize.score")
        indexed = unit.output("publish.index_priority")
        syntax = syntax_doc(unit)
        ranking = read_json(unit.job.run_root, ranking_output["artifact"])

        def summary(item: Mapping[str, Any]) -> dict[str, Any]:
            return {key: item.get(key) for key in ("item_id", "scope", "path", "function_id", "name", "language",
                                                   "start_line", "rank", "score", "feature_coverage", "missing_features")}

        gaps = list(indexed["gaps"])
        document = {
            "schema": SCHEMA, "target_snapshot": unit.job.source_fingerprint,
            "authority": "metrics and signals prioritize review; a high score means review first and is never a "
                         "vulnerability finding; missing coverage is a named gap, never a clean result",
            "identities": {"cyclomatic": CYCLOMATIC_IDENTITY, "cognitive": COGNITIVE_IDENTITY,
                           "cognitive_deviations": list(COGNITIVE_DEVIATIONS), "import_graph": GRAPH_IDENTITY,
                           "rules": RULES_IDENTITY, "language_map": MAPPING_IDENTITY, "score": scoring.SCORE_IDENTITY},
            "inputs": {"catalog_handoff_sha256": loaded["inputs"]["catalog_handoff_sha256"],
                       "tree_sitter_handoff_sha256": loaded["inputs"]["tree_sitter_handoff_sha256"],
                       "optional": loaded["optional"]},
            "sources": {"tree_sitter": syntax_output["terminal_status"], "semgrep": semantic_output["semgrep_status"],
                        "codeql": semantic_output["codeql_status"], "history": ranking_output["history_status"]},
            "settings": {"cyclomatic_thresholds": settings["cyclomatic_thresholds"],
                         "scored_threshold": settings["scored_threshold"],
                         "count_error_propagation": settings["count_error_propagation"],
                         "normalization_population": settings["normalization_population"],
                         "weights": ranking["weights"], "index": dict(settings["index"])},
            "summary": {"file_count": ranking_output["file_count"], "function_count": ranking_output["function_count"],
                        "indexed_files": ranking_output["selected_files"],
                        "indexed_functions": ranking_output["selected_functions"],
                        "by_language": syntax["by_language"]},
            "top_files": [summary(item) for item in ranking["files"][:ranking["selection"]["files"]]],
            "top_functions": [summary(item) for item in ranking["functions"][:ranking["selection"]["functions"]]],
            "artifacts": {"syntax": syntax_output["artifact"],
                          "dependency_graph": unit.output("extract.dependency_graph")["artifact"],
                          "semantic": semantic_output["artifact"], "ranking": ranking_output["artifact"]},
            "gaps": gaps, "index_manifest": indexed["manifest"],
        }
        artifact = _write(unit, "review-prioritization.json", document)
        unit.job.events.write("REVIEW_PRIORITIZATION_COMPLETED", file_count=ranking_output["file_count"],
                              function_count=ranking_output["function_count"], gap_count=len(gaps))
        return {"schema": SCHEMA, "artifact": artifact, "index_manifest": indexed["manifest"],
                "item_count": ranking_output["file_count"] + ranking_output["function_count"], "gaps": gaps,
                "terminal_status": _status(gaps)}

    units = (
        Unit("load.accepted_inputs", load),
        Unit("extract.syntax_metrics", syntax_metrics, ("load.accepted_inputs",)),
        Unit("extract.dependency_graph", dependency_graph, ("extract.syntax_metrics",)),
        Unit("extract.semantic_evidence", semantic_evidence, ("extract.syntax_metrics",)),
        Unit("prioritize.score", score, ("extract.dependency_graph", "extract.semantic_evidence")),
        Unit("publish.index_priority", index_priority, ("prioritize.score",)),
        Unit("publish.publish_handoff", publish, ("publish.index_priority",)),
    )
    return Job(JOB_ID, "review_prioritization", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA,
               units=units,
               datasets=DATASETS, consumes=CONSUMES)


def load_accepted_prioritization(run_root: Path) -> Mapping[str, Any] | None:
    """Return the accepted prioritization document, or ``None`` when the job has not run."""
    if not has_handoff(Path(run_root), JOB_ID):
        return None
    handoff, handoff_sha = accepted_handoff(Path(run_root), JOB_ID)
    document = read_json(Path(run_root), handoff["outputs"]["publish.publish_handoff"]["artifact"])
    if document.get("schema") != SCHEMA:
        raise ValueError("accepted review prioritization schema is unsupported")
    return {**document, "handoff_sha256": handoff_sha}
