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
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from . import scoring
from .complexity import COGNITIVE_DEVIATIONS, COGNITIVE_IDENTITY, CYCLOMATIC_IDENTITY, file_summary, function_units
from .dependencies import GRAPH_IDENTITY, GraphBuilder, extract, import_modules
from .heuristics import Extractor
from .inputs import accepted_handoff, has_handoff, read_json, read_lines
from .languages import MAPPING_IDENTITY, SPECS, UNSCORED_GRAMMARS
from .rules import RULES_IDENTITY
from .semantic import CODEQL_LANGUAGES, codeql_paths, semgrep_signals
from .syntax import SourceFile, build_tree, code_lines


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
    "custom_parsing_min_operations": (1, 100_000), "state_mutation_min_operations": (1, 100_000),
    "scored_threshold": (1, 10_000),
}
INDEX_SETTINGS = {"file_top_fraction": float, "file_top_count": int, "function_top_fraction": float,
                  "function_top_count": int, "max_indexed_items": int, "max_evidence_links_per_item": int}
# Catalog language -> grammar for languages this batch scores (".tsx" files route to the TSX grammar).
SCORED_LANGUAGES = {"C": "c", "C++": "cpp", "C/C++": "cpp", "Java": "java", "C#": "csharp", "Go": "go",
                    "JavaScript": "javascript", "TypeScript": "typescript", "Rust": "rust", "PHP": "php"}
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
    for root, component in roots:
        if root in {"", "."} or path == root or path.startswith(root.rstrip("/") + "/"):
            return component
    return None


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
                                 "component_id": _component(str(item["path"]), roots)}
             for item in partition.get("files", ())}
    return {"source_fingerprint": catalog["source_fingerprint"], "catalog_handoff_sha256": catalog_sha,
            "tree_sitter_handoff_sha256": tree_sha, "tree_sitter_artifact": tree_handoff["outputs"][
                "acceptance.publish_handoff"]["artifact"], "files": files,
            "components": [component for _root, component in roots]}


def _target_bytes(unit: UnitContext, path: str, sha256: str) -> bytes:
    target = (unit.job.target_root or Path()).resolve()
    candidate = (target / Path(*PurePosixPath(path).parts)).resolve()
    if target not in candidate.parents or candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"accepted target file is unavailable or escapes the target: {path}")
    data = candidate.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError(f"accepted target bytes changed: {path}")
    return data


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
        if inputs["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match accepted inputs")
        optional = {name: has_handoff(unit.job.run_root, job_id) for name, job_id in (
            ("history", "job_source_history_analysis"), ("semgrep", "job_evidence_collection"),
            ("codeql", "job_codeql_analysis"))}
        unit.job.events.write("REVIEW_PRIORITIZATION_STARTED", file_count=len(inputs["files"]),
                              optional_inputs=optional, sources=dict(settings["sources"]))
        return {"inputs": {key: value for key, value in inputs.items() if key != "files"},
                "files_artifact": _write(unit, "catalog-files.json", inputs["files"]), "optional": optional,
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def catalog_files(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
        return read_json(unit.job.run_root, unit.output("load.accepted_inputs")["files_artifact"])

    def syntax_metrics(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
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
        rows_by_path: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for identity in shard_rows:
            for row in read_lines(unit.job.run_root, identity):
                rows_by_path[str(row["path"])].append(row)
        gaps: list[str] = []
        unscored: Counter[str] = Counter()
        records: dict[str, dict[str, Any]] = {}
        function_budget = int(settings["max_functions"])
        thresholds = list(settings["cyclomatic_thresholds"])
        processed = 0
        for path in sorted(files):
            value = files[path]
            language = value["language"]
            grammar = SCORED_LANGUAGES.get(str(language))
            if grammar == "typescript" and path.endswith(".tsx"):
                grammar = "tsx"
            if grammar is None:
                if language is not None:
                    unscored[str(language)] += 1
                continue
            file_gaps = sorted(set(reasons.get(path, ())))
            rows = rows_by_path.get(path)
            if value["generated"]:
                gaps.append(f"{path}: generated_file_not_scored")
                continue
            if not rows:
                gaps.append(f"{path}: ast_unavailable ({'; '.join(file_gaps) or 'no accepted Tree-sitter rows'})")
                continue
            if any("node limit" in reason or "limit" in reason for reason in file_gaps):
                gaps.append(f"{path}: ast_truncated ({'; '.join(file_gaps)})")
                continue
            if processed >= int(settings["max_files"]):
                gaps.append(f"{path}: file_bound_reached")
                continue
            if value["size_bytes"] > int(settings["max_file_bytes"]):
                gaps.append(f"{path}: file_byte_bound_reached")
                continue
            if any(row.get("file_sha256") != value["sha256"] for row in rows):
                raise ValueError(f"Tree-sitter rows do not match the accepted catalog hash: {path}")
            row_grammar = str(rows[0]["location"]["producer_location"].get("grammar"))
            if row_grammar in UNSCORED_GRAMMARS or row_grammar not in SPECS:
                unscored[f"grammar:{row_grammar}"] += 1
                continue
            processed += 1
            spec = SPECS[row_grammar]
            data = _target_bytes(unit, path, value["sha256"])
            root, errors = build_tree(rows)
            source = SourceFile(path, value["sha256"], row_grammar, spec.language, data, root, errors)
            units, truncated = function_units(source, spec, count_error_propagation=bool(
                settings["count_error_propagation"]), limit=max(0, function_budget))
            function_budget -= len(units)
            imports, declarations = extract(source, spec)
            extractor = Extractor(source, spec, units, import_modules(imports), settings)
            extractor.run()
            for item in extractor.signals:
                item["signal_id"] = _identity("sig", item["producer"], item["rule_id"], item["path"], item["start_byte"],
                                              item["end_byte"], item["function_id"], item["category"], item["surface"])
            for item in extractor.suppressions:
                item["signal_id"] = _identity("sup", item["rule_id"], item["path"], item["start_byte"], item["end_byte"])
            sloc = len(code_lines(root))
            file_record_gaps = []
            if errors or "parse diagnostics present" in file_gaps:
                file_record_gaps.append(f"parse_errors:{errors}")
            unsupported: Counter[str] = Counter()
            for item in units:
                item.pop("_node", None)
                unsupported.update(item["unsupported_constructs"])
                owned = [signal for signal in extractor.signals if signal["function_id"] == item["function_id"]]
                suppressions = [entry for entry in extractor.suppressions if entry["function_id"] == item["function_id"]]
                item["signal_counts"] = _count(owned)
                item["suppression_counts"] = _count(suppressions)
                item["suppression_count"] = len(suppressions)
            file_record_gaps.extend(f"unsupported_construct:{name}:{count}" for name, count in sorted(unsupported.items()))
            if truncated:
                file_record_gaps.append("function_bound_reached")
            signals = _ordered(extractor.signals)
            limit = int(settings["max_signals_per_file"])
            if len(signals) > limit:
                file_record_gaps.append(f"signals_truncated:{len(signals) - limit}")
            records[path] = {
                "path": path, "sha256": value["sha256"], "size_bytes": value["size_bytes"],
                "line_count": source.line_count(), "language": spec.language, "grammar": row_grammar,
                "component_id": value["component_id"], "parse_error_count": errors,
                **file_summary(units, sloc, thresholds),
                "signal_counts": _count(extractor.signals), "suppression_counts": _count(extractor.suppressions),
                "suppression_count": len(extractor.suppressions), "units": units, "signals": signals[:limit],
                "suppressions": extractor.suppressions[:limit], "imports": imports, "declarations": declarations,
                "gaps": file_record_gaps,
            }
            gaps.extend(f"{path}: {gap}" for gap in file_record_gaps)
        gaps.extend(f"language_not_scored:{language} ({count} files)" for language, count in sorted(unscored.items()))
        if function_budget <= 0:
            gaps.append("function_bound_reached")
        by_language: dict[str, dict[str, Any]] = {}
        for language in sorted({item["language"] for item in records.values()}):
            members = [item for item in records.values() if item["language"] == language]
            values = [int(unit_value["cyclomatic"]) for item in members for unit_value in item["units"]]
            by_language[language] = {
                "file_count": len(members), "function_count": len(values), "sloc": sum(item["sloc"] for item in members),
                "cyclomatic_average": round(sum(values) / len(values), 6) if values else None,
                "share_above_threshold": {str(limit): round(sum(1 for value in values if value > limit) / len(values), 6)
                                          if values else None for limit in thresholds},
                "suppression_count": sum(item["suppression_count"] for item in members),
            }
        document = {"schema": "appsec-review/review-prioritization-syntax/1",
                    "identities": {"cyclomatic": CYCLOMATIC_IDENTITY, "cognitive": COGNITIVE_IDENTITY,
                                   "rules": RULES_IDENTITY, "mapping": MAPPING_IDENTITY},
                    "files": records, "by_language": by_language}
        unit.job.events.write("REVIEW_PRIORITIZATION_SYNTAX_EXTRACTED", file_count=len(records),
                              function_count=sum(len(item["units"]) for item in records.values()), gap_count=len(gaps))
        return {"artifact": _write(unit, "syntax-facts.json", document), "file_count": len(records),
                "function_count": sum(len(item["units"]) for item in records.values()), "gaps": gaps,
                "terminal_status": _status(gaps)}

    def syntax_doc(unit: UnitContext) -> Mapping[str, Any]:
        return read_json(unit.job.run_root, unit.output("extract.syntax_metrics")["artifact"])

    def dependency_graph(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        files = catalog_files(unit)
        facts = syntax_doc(unit)["files"]
        builder = GraphBuilder({path: {"grammar": value["grammar"], "imports": value["imports"],
                                       "declarations": value["declarations"]} for path, value in facts.items()},
                               files, lambda path: _target_bytes(unit, path, files[path]["sha256"]),
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
            codeql = codeql_paths(unit.job.run_root, limit=int(settings["max_semantic_paths"]))
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
            ends = [item["source"], item["sink"]]
            if any(end["path"] not in files or end.get("file_sha256") not in {None, files[end["path"]]["sha256"]}
                   for end in ends):
                gaps.append(f"semantic path {item['path_id']} is not bound to accepted files")
                continue
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

    def history_values(unit: UnitContext, settings: Mapping[str, Any]) -> tuple[dict[str, float | None], list[str], str]:
        if not settings["sources"]["history"]:
            return {}, ["history_hotspots_disabled"], "SKIPPED_POLICY"
        if not has_handoff(unit.job.run_root, "job_source_history_analysis"):
            return {}, ["history_hotspots_unavailable: source history analysis has no accepted handoff"], "UNAVAILABLE"
        from appsec_review.jobs.job_source_history_analysis import load_accepted_history
        history = load_accepted_history(unit.job.run_root) or {}
        decision = str(history.get("decision"))
        signals_identity = history.get("ranking", {}).get("signals")
        if not signals_identity:
            return {}, [f"history_hotspots_unavailable: history decision {decision}"], "UNAVAILABLE"
        document = read_json(unit.job.run_root, signals_identity)
        values: dict[str, float | None] = {}
        for path, value in document.get("files", {}).items():
            attention = value.get("attention") or {}
            values[path] = float(attention.get("score", 0.0)) if attention else 0.0
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
            for end in {item["source"]["path"], item["sink"]["path"]}:
                paths_by_file[end].append(item)
        scored = str(settings["scored_threshold"])
        file_items: list[dict[str, Any]] = []
        function_items: list[dict[str, Any]] = []
        for path, record in sorted(facts.items()):
            coupling = graph["files"].get(path, {})
            semantic_available = CODEQL_LANGUAGES.get(record["language"]) in covered_languages
            if history_status in {"EXACT", "PARTIAL"}:
                hotspot = history.get(path, 0.0 if history_status == "EXACT" else None)
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
            evidence = [*(item["signal_id"] for item in record["signals"]),
                        *(item["signal_id"] for item in semgrep_by_file.get(path, ())),
                        *(item["signal_id"] for item in file_paths),
                        *(item["signal_id"] for item in record["suppressions"])]
            file_items.append({"item_id": f"file:{path}", "scope": "file", "path": path, "name": path,
                               "language": record["language"], "component_id": record["component_id"],
                               "start_line": 1, "features": features, "evidence": list(dict.fromkeys(evidence)),
                               "coupling_lower_bound": coupling.get("coupling_lower_bound", False),
                               "gaps": record["gaps"]})
            for item in record["units"]:
                function_id = item["function_id"]
                semgrep_owned = [signal for signal in semgrep_by_file.get(path, ()) if signal["function_id"] == function_id]
                owned_paths = [value for value in file_paths
                               if function_id in {value.get("source_function"), value.get("sink_function")}]
                unit_features = {
                    "cyclomatic": item["cyclomatic"], "cognitive": item["cognitive"],
                    "complexity_density": item["complexity_density"],
                    "suppression_density": round(item["suppression_count"] / item["sloc"], 6) if item["sloc"] else None,
                    **{name: int(item["signal_counts"].get(name, 0)) +
                       sum(1 for signal in semgrep_owned if signal["category"] == name)
                       for name in scoring.SIGNAL_FEATURES},
                    "semantic_path": len(owned_paths) if semantic_available else None, **inherited,
                }
                links = [*(signal["signal_id"] for signal in record["signals"] if signal["function_id"] == function_id),
                         *(signal["signal_id"] for signal in semgrep_owned), *(value["signal_id"] for value in owned_paths),
                         *(entry["signal_id"] for entry in record["suppressions"] if entry["function_id"] == function_id)]
                function_items.append({
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
            parser_identity="tree-sitter-accepted-shards", normalizer_identity=MAPPING_IDENTITY,
            mapping_identity=GRAPH_IDENTITY)
        path = unit.job.run_root / "data" / "indices" / "priority" / SHARD_ID / f"{fingerprint}.sqlite"
        gaps = sorted(set([*syntax_output["gaps"], *graph_output["gaps"], *semantic_output["gaps"],
                           *ranking_output["gaps"]]))
        data_cache: dict[str, bytes] = {}

        def data_of(file_path: str) -> bytes:
            if file_path not in data_cache:
                data_cache[file_path] = _target_bytes(unit, file_path, files[file_path]["sha256"])
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
                                              1.0, {"producer": "codeql", "role": "sink"})
                    text = (f"semantic_path {record['rule_id']} {record['source']['path']}:{record['source']['start_line']}"
                            f" -> {sink['path']}:{sink['start_line']} steps {record['steps']}")
                elif record.get("producer") == "semgrep":
                    location = _line_location(snapshot, data_of(record["path"]), record["path"],
                                              files[record["path"]]["sha256"], int(record["start_line"]),
                                              int(record["end_line"]), "semgrep-line-location", 0.9,
                                              {"producer": "semgrep", "rule_id": record["rule_id"]})
                    text = f"{record['category']} {record['surface']} {record['rule_id']} semgrep"
                else:
                    location = SourceLocation(snapshot, record["path"], record["file_sha256"], int(record["start_byte"]),
                                              int(record["end_byte"]), int(record["start_line"]), int(record["end_line"]),
                                              int(record["start_column"]), int(record["end_column"]),
                                              {"producer": "tree-sitter", "rule_id": record["rule_id"]},
                                              "tree-sitter-byte-and-point-exact", 1.0)
                    kind = "suppression " + str(record.get("tool")) if signal_id.startswith("sup-") else record["surface"]
                    text = f"{record['category']} {kind} {record['rule_id']} {record.get('basis')}"
                payload = {**record, "authority": "review lead; not a finding"}
                builder.add_entity(EntityRecord(identity, signal_id, str(record.get("rule_id")), text, payload, location))
                evidence_ids[signal_id] = identity.value
                return identity.value

            for item in [*selected_files, *selected_functions]:
                identity = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, snapshot, {"item_id": item["item_id"]})
                entity_ids[item["item_id"]] = identity.value
                record = facts[item["path"]]
                if item["scope"] == "function":
                    location = SourceLocation(snapshot, item["path"], record["sha256"], int(item["start_byte"]),
                                              int(item["end_byte"]), int(item["start_line"]), int(item["end_line"]),
                                              int(item["start_column"]), int(item["end_column"]),
                                              {"producer": "tree-sitter", "function_id": item["function_id"]},
                                              "tree-sitter-byte-and-point-exact", 1.0)
                else:
                    location = SourceLocation(snapshot, item["path"], record["sha256"], 0, int(record["size_bytes"]), 1,
                                              max(1, int(record["line_count"])), 1, 1, {"producer": "tree-sitter",
                                                                                        "scope": "file"},
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
            for edge in graph["edges"]:
                left, right = entity_ids.get(f"file:{edge['from']}"), entity_ids.get(f"file:{edge['to']}")
                if left is not None and right is not None:
                    exact = float(edge["confidence"]) >= 1.0
                    builder.add_relation(RelationRecord(
                        RelationKind.DEPENDS_ON, left, right, exact, float(edge["confidence"]),
                        None if exact else f"import resolved by {edge['method']}",
                        {"method": edge["method"], "line": edge["line"]}))
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
        upstream_path, upstream_sha = resolve_accepted_manifest(unit.job.run_root)
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
    sources = sorted(Path(__file__).parent.glob("*.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        try:
            return file_sha256(root / "rules" / "semgrep" / "rules.lock.json")
        except OSError:
            return "semgrep-rules-lock:UNAVAILABLE"

    return Job(JOB_ID, "review_prioritization", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, runtime_identity=runtime_identity,
               units=units)


def load_accepted_prioritization(run_root: Path) -> Mapping[str, Any] | None:
    """Return the accepted prioritization document, or ``None`` when the job has not run."""
    if not has_handoff(Path(run_root), JOB_ID):
        return None
    handoff, handoff_sha = accepted_handoff(Path(run_root), JOB_ID)
    document = read_json(Path(run_root), handoff["outputs"]["publish.publish_handoff"]["artifact"])
    if document.get("schema") != SCHEMA:
        raise ValueError("accepted review prioritization schema is unsupported")
    return {**document, "handoff_sha256": handoff_sha}
