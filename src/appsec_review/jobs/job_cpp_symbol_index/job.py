"""Independent C/C++ semantic symbol index built with the pinned clangd-indexer.

The job consumes only the accepted ``job_cpp_compiled_analysis`` handoff. For every accepted
project scope it runs ``tool-clangd-indexer`` over the exact accepted compile commands, then
normalizes declarations, definitions, and call/reference edges between accepted symbols into an
``analysis`` retrieval shard. It does not depend on, or wait for, any other indexing job.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

from appsec_review.jobs.cpp_index_scopes import (
    IndexScope, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from .clangd_yaml import iter_tagged, parse_documents


JOB_ID = "job_cpp_symbol_index"
SCHEMA = "appsec-review/cpp-symbol-index/1"
TOOL_ID = "tool-clangd-indexer"
NORMALIZER = "clangd-yaml-normalizer/1"
CALL_BIT = 16  # clangd RefKind::Call
_PROCESSED = re.compile(r"^\[[0-9]+/([0-9]+)\] Processing file (.+)$", re.M)


def _settings(unit: UnitContext) -> Mapping[str, int]:
    settings = unit.job.config.settings
    return {name: int(settings[name]) for name in (
        "workers", "max_documents_per_scope", "max_symbols_per_scope",
        "max_relations_per_scope", "locations_per_relation")}


def _container_path(uri: Any) -> str | None:
    if not isinstance(uri, str) or not uri.startswith("file://"):
        return None
    return unquote(urlparse(uri).path)


def _position(value: Any) -> tuple[int, int] | None:
    try:
        return int(value["Line"]) + 1, int(value["Column"]) + 1  # clangd positions are 0-based
    except (KeyError, TypeError, ValueError):
        return None


def _accepted_location(unit: UnitContext, scope: IndexScope, value: Any,
                       sizes: dict[str, int]) -> tuple[SourceLocation, dict] | None:
    if not isinstance(value, Mapping):
        return None
    path = _container_path(value.get("FileURI"))
    accepted = scope.accepted_file(path) if path else None
    start, end = _position(value.get("Start")), _position(value.get("End"))
    if accepted is None or start is None:
        return None
    end = end or start
    target_path = str(accepted["target_path"])
    if target_path not in sizes:  # verify each accepted source once per scope, not per symbol
        target_file = (unit.job.target_root or Path()) / Path(*PurePosixPath(target_path).parts)
        if not target_file.is_file() or target_file.is_symlink() or file_sha256(target_file) != accepted["sha256"]:
            raise ValueError(f"clangd symbol source changed after acceptance: {target_path}")
        sizes[target_path] = target_file.stat().st_size
    location = SourceLocation(
        unit.job.source_fingerprint, target_path, str(accepted["sha256"]), 0, sizes[target_path],
        start[0], end[0], start[1], end[1],
        {"uri": str(value.get("FileURI"))[:4096], "line": start[0], "column": start[1]},
        "clangd-uri-exact-path", 1.0, False)
    return location, {"path": target_path, "line": start[0], "column": start[1],
                      "end_line": end[0], "end_column": end[1]}


def _symbol_identity(scope: IndexScope, clangd_id: str) -> LogicalIdentity:
    return LogicalIdentity.derive(EntityKind.SYMBOL, scope.case_snapshot,
                                  {"project_id": scope.project_id, "producer": "clangd",
                                   "clangd_id": clangd_id})


def normalize_scope(unit: UnitContext, scope: IndexScope, execution: Mapping[str, Any],
                    limits: Mapping[str, int], builder: IndexBuilder, shard: str) -> dict[str, Any]:
    """Normalize one clangd YAML index into the builder; return counts and gaps."""
    gaps: list[str] = []
    run_root = unit.job.run_root
    if execution["timed_out"]:
        gaps.append("clangd-indexer timed out")
    elif execution["oom_killed"]:
        gaps.append("clangd-indexer was OOM-killed")
    elif execution["exit_code"] != 0:
        gaps.append(f"clangd-indexer exited with status {execution['exit_code']}")
    if execution["stdout_truncated"]:
        gaps.append("clangd index output exceeded the tool output bound and was truncated")
    stderr = (run_root / execution["stderr_path"]).read_text(encoding="utf-8", errors="replace")
    processed = {match.group(2).strip() for match in _PROCESSED.finditer(stderr)}
    expected = {row["file"] for row in scope.container_compile_database()}
    missing = sorted(expected - processed)
    if missing:
        gaps.append(f"clangd-indexer processed {len(expected) - len(missing)} of {len(expected)} "
                    "translation units")
    text = (run_root / execution["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    try:
        documents, truncated_tail, capped = parse_documents(
            text, document_limit=limits["max_documents_per_scope"])
    except ValueError as exc:
        documents, truncated_tail, capped = [], False, False
        gaps.append(f"clangd index output is malformed: {exc}")
    if truncated_tail:
        gaps.append("clangd index output ended inside a document")
    if capped:
        gaps.append("clangd index document limit reached")

    symbols: dict[str, LogicalIdentity] = {}
    sizes: dict[str, int] = {}
    external = 0
    for value in iter_tagged(documents, "Symbol"):
        clangd_id = str(value.get("ID", ""))
        if not re.fullmatch(r"[0-9A-F]{16}", clangd_id) or clangd_id in symbols:
            continue
        definition = _accepted_location(unit, scope, value.get("Definition"), sizes)
        declaration = _accepted_location(unit, scope, value.get("CanonicalDeclaration"), sizes)
        chosen = definition or declaration
        if chosen is None:
            external += 1  # declared only outside accepted sources (system or SDK headers)
            continue
        if len(symbols) >= limits["max_symbols_per_scope"]:
            gaps.append("clangd symbol limit reached")
            break
        info = value.get("SymInfo") if isinstance(value.get("SymInfo"), Mapping) else {}
        name = str(value.get("Name", ""))[:1024]
        qualified = (str(value.get("Scope", "")) + name)[:4096]
        identity = _symbol_identity(scope, clangd_id)
        symbols[clangd_id] = identity
        builder.add_entity(EntityRecord(identity, clangd_id, qualified,
            f"{info.get('Kind', 'Symbol')} {qualified}{value.get('Signature', '')}"[:16384],
            {"producer": "clangd", "clangd_id": clangd_id, "kind": str(info.get("Kind", ""))[:64],
             "lang": str(info.get("Lang", ""))[:32], "scope": str(value.get("Scope", ""))[:2048],
             "signature": str(value.get("Signature", ""))[:2048],
             "return_type": str(value.get("ReturnType", ""))[:2048],
             "type": str(value.get("Type", ""))[:2048],
             "template_arguments": str(value.get("TemplateSpecializationArgs", ""))[:2048],
             "reference_count": int(value.get("References", 0) or 0)
             if str(value.get("References", "0")).isdigit() else 0,
             "definition": definition[1] if definition else None,
             "declaration": declaration[1] if declaration else None,
             "project_id": scope.project_id, "shard_id": shard},
            chosen[0]))

    edges: dict[tuple[RelationKind, str, str], dict[str, Any]] = {}
    unresolved_refs = 0
    for value in iter_tagged(documents, "Refs"):
        target = symbols.get(str(value.get("ID", "")))
        references = value.get("References") if isinstance(value.get("References"), list) else []
        for reference in references:
            container = reference.get("Container", {}) if isinstance(reference, Mapping) else {}
            source = symbols.get(str(container.get("ID", "")) if isinstance(container, Mapping) else "")
            if target is None or source is None or source == target:
                unresolved_refs += 1
                continue
            kind_bits = int(reference.get("Kind", 0)) if str(reference.get("Kind", "0")).isdigit() else 0
            kind = RelationKind.CALLS if kind_bits & CALL_BIT else RelationKind.REFERENCES
            key = (kind, source.value, target.value)
            if key not in edges:
                if len(edges) >= limits["max_relations_per_scope"]:
                    gaps.append("clangd relation limit reached")
                    break
                edges[key] = {"occurrences": 0, "locations": []}
            edge = edges[key]
            edge["occurrences"] += 1
            location = reference.get("Location", {})
            path = _container_path(location.get("FileURI")) if isinstance(location, Mapping) else None
            accepted = scope.accepted_file(path) if path else None
            start = _position(location.get("Start")) if isinstance(location, Mapping) else None
            if accepted and start and len(edge["locations"]) < limits["locations_per_relation"]:
                edge["locations"].append({"path": str(accepted["target_path"]), "line": start[0],
                                          "column": start[1], "ref_kind": kind_bits})
    for (kind, source, target), edge in sorted(edges.items(), key=lambda item: (item[0][0].value, *item[0][1:])):
        builder.add_relation(RelationRecord(kind, source, target, True, 1.0, None,
                                            {"producer": "clangd", **edge}))
    unique = list(dict.fromkeys(gaps))
    if execution["exit_code"] != 0 and not symbols:
        status = "unavailable"
    else:
        status = "partial" if unique else "complete"
    builder.add_coverage(f"clangd:{scope.project_id}"[:256], status, "; ".join(unique[:10]) or None)
    return {"symbols": len(symbols), "external_symbols": external, "relations": len(edges),
            "unresolved_references": unresolved_refs, "translation_units": len(expected),
            "processed_translation_units": len(expected) - len(missing), "gaps": unique,
            "coverage": status}


def _index_scope(unit: UnitContext, scope: IndexScope, executor_factory: Any) -> dict[str, Any]:
    limits = _settings(unit)
    root = unit.job.run_root / "data" / "code-index" / "clangd" / scope.scope_id
    identity = checkpoint_identity({
        "schema": SCHEMA, "scope": scope.as_dict(), "normalizer": NORMALIZER,
        "tool": tool_identity(unit.job.repository_root, TOOL_ID) if executor_factory is None
        else {"tool_id": TOOL_ID, "injected_executor": True},
        "limits": {key: value for key, value in limits.items() if key != "workers"}})
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root)
    if reused is not None:
        return reused
    execution = execute_scope_tool(
        unit, scope, TOOL_ID,
        ("/opt/clangd/clangd_23.1.0/bin/clangd-indexer", "--executor=all-TUs", "--format=yaml",
         "/scratch/compile_commands.json"), root / "run", executor_factory)
    shard = f"clangd-{scope.scope_id}"
    artifacts = [execution["receipt"], execution["compile_database"], dict(scope.compile_database)]
    fingerprint = index_fingerprint(
        name="analysis", target_snapshot=scope.case_snapshot, producer_artifacts=artifacts,
        tool_identity={"tool": TOOL_ID, "image": execution["image_id"],
                       "image_digest": execution["image_digest"]},
        parser_identity="clangd-yaml-parser/1", normalizer_identity=NORMALIZER,
        mapping_identity="cpp-source-mapping/3")
    path = (unit.job.run_root / "data" / "indices" / "analysis" /
            f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite")
    builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    counts = normalize_scope(unit, scope, execution, limits, builder, shard)
    sha = file_sha256(path) if path.exists() else builder.build()
    index = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id},
                          tuple(counts["gaps"]), shard)
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "execution": {key: execution[key] for key in ("receipt", "compile_database", "exit_code",
                                                              "timed_out", "oom_killed", "image_id")},
              "index_identity": asdict(index), "counts": counts, "gaps": counts["gaps"],
              "terminal_status": "COMPLETED_WITH_GAPS" if counts["gaps"] else "SUCCEEDED"}
    save_scope_checkpoint(root / "checkpoint.json", identity, result)
    return result


def _validate(context, _result) -> None:
    steps = context.config.steps
    if tuple(steps) != ("load", "index", "acceptance"):
        raise ValueError("C++ symbol-index topology does not match central configuration")
    for step, task in (("load", "accepted_cpp"), ("index", "scopes"), ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"C++ symbol-index task configuration mismatch: {step}")


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("symbol-index target snapshot differs from the accepted C++ build")
        unit.job.events.write("CPP_SYMBOL_INDEX_SCOPES_LOADED", scope_count=len(scopes),
                              unavailable_count=len(unavailable))
        return {"upstream": {"handoff_sha256": accepted["handoff_sha256"], "manifest": accepted["manifest"]},
                "scopes": [scope.as_dict() for scope in scopes], "unavailable": unavailable}

    def index(unit: UnitContext) -> Mapping[str, Any]:
        _accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and index")
        with ThreadPoolExecutor(max_workers=max(1, _settings(unit)["workers"])) as pool:
            results = list(pool.map(lambda scope: _index_scope(unit, scope, executor_factory), scopes))
        gaps = [f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]]
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = ("NOT_APPLICABLE" if not results and not unavailable else
                  "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED")
        return {"scopes": results, "scope_count": len(results), "gaps": gaps, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, indexed = unit.output("load.accepted_cpp"), unit.output("index.scopes")
        manifest = publish_scope_indexes(unit, job_id=JOB_ID, index_name="analysis", prefix="clangd",
                                         results=indexed["scopes"], unavailable=loaded["unavailable"],
                                         gaps=indexed["gaps"])
        counts = {key: sum(int(item["counts"][key]) for item in indexed["scopes"])
                  for key in ("symbols", "external_symbols", "relations", "translation_units",
                              "processed_translation_units")}
        summary_path = unit.unit_root / "cpp-symbol-index-summary.json"
        atomic_json(summary_path, {"schema": SCHEMA, "upstream": loaded["upstream"], "counts": counts,
                                   "scopes": indexed["scopes"], "unavailable": loaded["unavailable"],
                                   "gaps": indexed["gaps"]})
        unit.job.events.write("CPP_SYMBOL_INDEX_COMPLETED", **counts, gap_count=len(indexed["gaps"]))
        return {"schema": SCHEMA, "artifact": artifact(unit.job.run_root, summary_path),
                "index_manifest": manifest,
                "item_count": counts["symbols"], "counts": counts, "gaps": indexed["gaps"],
                "terminal_status": indexed["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("index.scopes", index, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "index.scopes")),
    )
    implementation = hashlib.sha256(
        b"".join(path.read_bytes() for path in sorted(Path(__file__).parent.glob("*.py"))) +
        Path(__file__).parents[1].joinpath("cpp_index_scopes.py").read_bytes() +
        (b"injected-executor" if executor_factory else b"container-executor")).hexdigest()
    return Job(JOB_ID, "cpp_symbol_index", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units)
