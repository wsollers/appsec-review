"""SVF points-to producer over accepted C/C++ scopes (docs/architecture/svf-alias-producer.md).

Each accepted ``job_cpp_compiled_analysis`` scope is planned into linked modules (one per captured
link command, single-unit modules for unlinked compile units). One ``tool-svf`` container per scope
compiles the needed units to bitcode with clang-18, links each module with LLVM 21 and runs the
repository-owned SVF driver under per-module bounds. Results are published into the ``analysis``
index as ``points_to_set`` and ``indirect_call_targets`` records with exact source points, plus one
coverage row per module. They are cross-check inputs for ``job_code_graph_index``; nothing here is a
finding, and a module that is not closed-world says so on every record it publishes.
"""

from __future__ import annotations

from appsec_review.storage.shared import PublicationThreadPoolExecutor as ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.jobs.cpp_index_scopes import (
    IndexScope, accepted_cpp_scopes, artifact, checkpoint_identity, execute_scope_tool,
    partition_compile_commands, publish_scope_indexes, save_scope_checkpoint, scope_checkpoint, tool_identity,
)
from appsec_review.jobs.engineering_contracts import SVF_ALIAS_HANDOFF_SCHEMA
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json
from .datasets import CONSUMES, DATASETS
from .planning import MODULE_LINK, PlannedModule, plan_modules


JOB_ID = "job_svf_alias_analysis"
TOOL_ID = "tool-svf"
PLAN_SCHEMA = "appsec-review/svf-plan/1"
RESULT_SCHEMA = "appsec-review/svf-run/1"
DRIVER_SCHEMA = "appsec-review/svf-alias-output/1"
FACT_SCHEMA = "appsec-review/svf-alias-record/1"
OBJECT_SCHEMA = "appsec-review/svf-memory-object/1"
OBJECT_RULE = "svf-memory-object/1"
ADAPTER = "svf-alias-adapter/1"
MAPPING_METHOD = "llvm-dilocation"
ARGV = ("/opt/appsec/svf.py", "run", "/scratch/plan.json", "/scratch/result.json")
SHARD_PREFIX = "svf"
DEBUG_INFO_UPGRADED_LOSSY = "debug_info_upgraded_lossy"
MISSING_BITCODE = "missing_bitcode"
_ROLES = frozenset({"load", "store", "call_arg", "compare"})
# Accessor classes of a memory object, in the order its bounded accessor list keeps them.
ACCESSOR_ORDER = ("free", "write", "read", "compare", "pass")
_DEALLOCATORS = frozenset({"free", "cfree", "realloc", "reallocarray"})
_DEALLOCATOR_PREFIXES = ("_ZdlPv", "_ZdaPv")   # every operator delete / delete[] overload
# Objects whose accessor fan-in is meaningful; functions and SVF's shared constant object are not.
_OBJECT_KINDS = frozenset({"heap", "stack", "global"})
_POSITIVE = ("workers", "max_modules_per_scope", "max_module_bitcode_bytes", "max_module_output_bytes",
             "max_output_bytes", "field_limit", "max_sites", "max_pts_size", "max_indirect_calls",
             "max_targets_per_call", "max_unmodeled_names", "compile_timeout_seconds", "link_timeout_seconds",
             "module_timeout_seconds", "andersen_time_limit_seconds", "max_objects_per_module",
             "max_accessors_per_object")
_DRIVER_BOUNDS = ("max_module_bitcode_bytes", "max_module_output_bytes", "field_limit", "max_sites",
                  "max_pts_size", "max_indirect_calls", "max_targets_per_call", "max_unmodeled_names",
                  "compile_timeout_seconds", "link_timeout_seconds", "module_timeout_seconds",
                  "andersen_time_limit_seconds")


def _validated_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(settings.get("enabled"), bool):
        raise ValueError("jobs.job_svf_alias_analysis.settings.enabled must be a boolean")
    values: dict[str, Any] = {"enabled": settings["enabled"]}
    for key in _POSITIVE:
        value = settings.get(key)
        if type(value) is not int or value <= 0:
            raise ValueError(f"SVF setting {key} must be a positive integer")
        values[key] = value
    if values["andersen_time_limit_seconds"] >= values["module_timeout_seconds"]:
        raise ValueError("andersen_time_limit_seconds must be below module_timeout_seconds")
    return values


def _settings(unit: UnitContext) -> dict[str, Any]:
    return _validated_settings(unit.job.config.settings)


def _read_bounded_json(path: Path, max_bytes: int, what: str) -> tuple[Any, str | None]:
    """Read one tool-written JSON document; anything unusable is a named gap, never empty-clean."""
    if not path.is_file() or path.is_symlink():
        return None, f"{what} was not produced"
    if path.stat().st_size > max_bytes:
        return None, f"{what} exceeded the {max_bytes}-byte bound"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, ValueError):
        return None, f"{what} was malformed JSON"


class _Sources:
    """Line offsets of accepted scope sources, for mapping DILocation points to byte offsets."""

    def __init__(self, scope: IndexScope):
        self.scope = scope
        self._cache: dict[str, tuple[Mapping[str, Any], bytes, list[int]]] = {}

    def point(self, file: Any, line: Any, column: Any) -> SourceLocation | None:
        if not isinstance(file, str) or type(line) is not int or type(column) is not int or line < 1 or column < 0:
            return None
        accepted = self.scope.accepted_file(file)
        if accepted is None:
            return None
        key = str(accepted["target_path"])
        if key not in self._cache:
            relative = str(accepted["scratch_path"])[len("source/"):]
            data = (self.scope.case_root / "source" / Path(*relative.split("/"))).read_bytes()
            offsets = [0, *(index + 1 for index, value in enumerate(data) if value == 10)]
            self._cache[key] = (accepted, data, offsets)
        accepted, data, offsets = self._cache[key]
        if line > len(offsets):
            return None
        line_start = offsets[line - 1]
        line_end = offsets[line] - 1 if line < len(offsets) else len(data)
        if column >= 1:
            start = min(line_start + column - 1, line_end)
            end, start_column, end_column, ambiguous = start, column, column, False
        else:  # column 0: the location names the whole line
            start, end, start_column, end_column, ambiguous = line_start, line_end, 1, max(1, line_end - line_start), True
        return SourceLocation(
            target_snapshot=self.scope.case_snapshot, path=key, file_sha256=str(accepted["sha256"]),
            start_byte=start, end_byte=end, start_line=line, end_line=line, start_column=start_column,
            end_column=end_column, producer_location={"producer": "svf", "file": file, "line": line, "column": column},
            mapping_method=MAPPING_METHOD, confidence=1.0, ambiguous=ambiguous,
        )


def _valid_driver_document(document: Any, settings: Mapping[str, Any]) -> str | None:
    if not isinstance(document, Mapping) or document.get("schema") != DRIVER_SCHEMA:
        return "analysis output envelope was malformed"
    module = document.get("module")
    sites, calls, objects = document.get("sites"), document.get("indirect_calls"), document.get("objects")
    if not isinstance(module, Mapping) or not isinstance(sites, list) or not isinstance(calls, list) \
            or not isinstance(objects, Mapping):
        return "analysis output sections were malformed"
    if len(sites) > settings["max_sites"] or len(calls) > settings["max_indirect_calls"]:
        return "analysis output exceeded its site or indirect-call bound"
    if not isinstance(module.get("open_world_reasons"), list):
        return "analysis output module block was malformed"
    for site in sites:
        if not isinstance(site, Mapping) or site.get("role") not in _ROLES \
                or not isinstance(site.get("points_to"), list) or len(site["points_to"]) > settings["max_pts_size"] \
                or not isinstance(site.get("incomplete_reasons"), list):
            return "analysis output contained a malformed pointer site"
    for call in calls:
        if not isinstance(call, Mapping) or not isinstance(call.get("targets"), list) \
                or len(call["targets"]) > settings["max_targets_per_call"]:
            return "analysis output contained a malformed indirect call"
    return None


def _module_records(scope: IndexScope, sources: _Sources, planned: PlannedModule, outcome: Mapping[str, Any],
                    document: Mapping[str, Any], tool_version: str) -> tuple[list[EntityRecord], dict[str, int], list[str]]:
    """Normalize one analyzed module into source-located records; returns records, counts and reasons."""
    driver_reasons = [str(item) for item in document["module"]["open_world_reasons"]]
    open_world = list(dict.fromkeys([*planned.open_world_reasons, *driver_reasons,
                                     *([MISSING_BITCODE] if outcome.get("gaps") else [])]))
    if planned.kind != MODULE_LINK and "not_in_link_unit" not in open_world:
        open_world.append("not_in_link_unit")
    closed_world = not open_world
    base = {"schema": FACT_SCHEMA, "producer": "svf", "tool_version": tool_version, "scope_id": scope.scope_id,
            "module_id": planned.module_id, "module_label": planned.label, "module_kind": planned.kind,
            "module_closed_world": closed_world, "open_world_reasons": open_world,
            "unmodeled_externals": list(document["module"].get("unmodeled_externals", ()))[:64],
            "authority": "computed points-to over accepted bitcode; a cross-check input, not a finding"}
    objects = document["objects"]
    records: list[EntityRecord] = []
    counts = {"sites": 0, "indirect_calls": 0, "outside_accepted_sources": 0}
    ordinals: dict[tuple[Any, ...], int] = {}

    def ordinal(key: tuple[Any, ...]) -> int:
        ordinals[key] = ordinals.get(key, -1) + 1
        return ordinals[key]

    for site in document["sites"]:
        location = sources.point(site.get("file"), site.get("line"), site.get("column"))
        if location is None:
            counts["outside_accepted_sources"] += 1
            continue
        native = (location.path, location.start_line, site.get("column"), site["role"], site.get("operand"))
        identity = LogicalIdentity.derive(EntityKind.POINTS_TO_SET, scope.case_snapshot, {
            "scope_id": scope.scope_id, "module_id": planned.module_id, "path": location.path,
            "line": location.start_line, "column": site.get("column"), "role": site["role"],
            "operand": site.get("operand"), "ordinal": ordinal(native)})
        points_to = [str(key) for key in site["points_to"]]
        incomplete = [str(item) for item in site["incomplete_reasons"]]
        payload = {**base, "role": site["role"], "operand": site.get("operand"), "callee": site.get("callee"),
                   "function": site.get("function"), "function_demangled": site.get("function_demangled"),
                   "points_to": points_to,
                   "objects": {key: objects[key] for key in points_to if isinstance(objects.get(key), Mapping)},
                   "truncated": bool(site.get("truncated")), "incomplete_reasons": incomplete,
                   "complete": not site.get("truncated") and not incomplete}
        records.append(EntityRecord(identity, identity.value, f"{site['role']}@{location.path}:{location.start_line}",
                                    f"points-to {site['role']} {site.get('function', '')}", payload, location))
        counts["sites"] += 1
    for call in document["indirect_calls"]:
        location = sources.point(call.get("file"), call.get("line"), call.get("column"))
        if location is None:
            counts["outside_accepted_sources"] += 1
            continue
        native = (location.path, location.start_line, call.get("column"), "indirect_call")
        identity = LogicalIdentity.derive(EntityKind.INDIRECT_CALL_TARGETS, scope.case_snapshot, {
            "scope_id": scope.scope_id, "module_id": planned.module_id, "path": location.path,
            "line": location.start_line, "column": call.get("column"), "ordinal": ordinal(native)})
        targets = [{"name": str(item.get("name", "")), "demangled": str(item.get("demangled", item.get("name", "")))}
                   for item in call["targets"] if isinstance(item, Mapping)]
        payload = {**base, "function": call.get("function"), "function_demangled": call.get("function_demangled"),
                   "targets": targets, "target_count": int(call.get("target_count", len(targets))),
                   "truncated": bool(call.get("truncated")), "complete": not call.get("truncated")}
        records.append(EntityRecord(identity, identity.value, f"indirect-call@{location.path}:{location.start_line}",
                                    f"indirect call targets {call.get('function', '')}", payload, location))
        counts["indirect_calls"] += 1
    reasons = []
    if document.get("sites_truncated"):
        reasons.append(f"pointer-site bound reached in module {planned.label}")
    if document.get("indirect_calls_truncated"):
        reasons.append(f"indirect-call bound reached in module {planned.label}")
    if int(outcome.get("debug_info_warnings") or 0):
        reasons.append(f"{DEBUG_INFO_UPGRADED_LOSSY}: {outcome['debug_info_warnings']} debug-info warnings in module "
                       f"{planned.label}")
    reasons += [f"open world ({reason}) in module {planned.label}" for reason in open_world]
    return records, counts, reasons


def accessor_class(payload: Mapping[str, Any]) -> str:
    """free | write | read | compare | pass for one pointer-site record."""
    role = payload.get("role")
    if role == "call_arg":
        callee = str(payload.get("callee") or "")
        return "free" if callee in _DEALLOCATORS or callee.startswith(_DEALLOCATOR_PREFIXES) else "pass"
    return {"store": "write", "load": "read", "compare": "compare"}.get(str(role), "pass")


def _memory_objects(scope: IndexScope, sources: _Sources, planned: PlannedModule, document: Mapping[str, Any],
                    sites: list[EntityRecord], settings: Mapping[str, Any]
                    ) -> tuple[list[EntityRecord], list[RelationRecord], int, list[str]]:
    """Invert one module's points-to sets into per-object accessor fan-in (design section 4.4).

    Andersen sets are already transitively closed over copies, fields and calls, so one inversion is
    the whole fan-in; no deeper walk adds information. Each object keeps its allocation site and
    allocator plus at most ``max_accessors_per_object`` accessors ordered free, write, read, compare,
    pass, then by location; the rest are counted. A list is complete only when it is untruncated,
    the module exported every site and the module is closed-world.
    """
    raw_counts: dict[str, int] = {}
    for site in document["sites"]:
        for key in site.get("points_to", ()):
            raw_counts[str(key)] = raw_counts.get(str(key), 0) + 1
    accessors: dict[str, list[EntityRecord]] = {}
    for record in sites:
        for key in record.payload["points_to"]:
            if (document["objects"].get(key) or {}).get("kind") in _OBJECT_KINDS:
                accessors.setdefault(key, []).append(record)
    keys = sorted(accessors)
    reasons: list[str] = []
    if len(keys) > settings["max_objects_per_module"]:
        reasons.append(f"memory-object bound reached in module {planned.label}: "
                       f"{len(keys) - settings['max_objects_per_module']} of {len(keys)} objects not published")
        keys = keys[:settings["max_objects_per_module"]]
    bound = settings["max_accessors_per_object"]
    module = sites[0].payload
    objects: list[EntityRecord] = []
    relations: list[RelationRecord] = []
    for key in keys:
        detail = document["objects"][key]
        raw_location = detail.get("location") or {}
        location = sources.point(raw_location.get("file"), raw_location.get("line"), raw_location.get("column"))
        identity = LogicalIdentity.derive(EntityKind.MEMORY_OBJECT, scope.case_snapshot, {
            "scope_id": scope.scope_id, "module_id": planned.module_id, "object_key": key})
        ordered = sorted(accessors[key], key=lambda item: (
            ACCESSOR_ORDER.index(accessor_class(item.payload)), item.location.path, item.location.start_line,
            item.location.start_column, item.identity.value))
        counts = {name: 0 for name in ACCESSOR_ORDER}
        for item in ordered:
            counts[accessor_class(item.payload)] += 1
        kept = ordered[:bound]
        truncated = len(ordered) > bound
        payload = {
            "schema": OBJECT_SCHEMA, "rule": OBJECT_RULE, "producer": "svf", "tool_version": module["tool_version"],
            "scope_id": scope.scope_id, "module_id": planned.module_id, "module_label": planned.label,
            "module_kind": planned.kind, "module_closed_world": module["module_closed_world"],
            "open_world_reasons": module["open_world_reasons"], "object_key": key, "kind": detail.get("kind"),
            "name": detail.get("name") or None, "field": detail.get("field", 0),
            "allocator": detail.get("allocator"), "allocator_demangled": detail.get("allocator_demangled"),
            "allocation": ({"file": raw_location.get("file"), "line": raw_location.get("line"),
                            "column": raw_location.get("column"), "in_accepted_source": location is not None}
                           if raw_location else None),
            "accessors": [{"site": item.identity.value, "class": accessor_class(item.payload),
                           "role": item.payload["role"], "callee": item.payload.get("callee"),
                           "function": item.payload.get("function"),
                           "function_demangled": item.payload.get("function_demangled"),
                           "path": item.location.path, "line": item.location.start_line,
                           "column": item.location.start_column} for item in kept],
            "accessor_counts": counts, "accessor_total": len(ordered), "truncated": truncated,
            "accessors_outside_accepted_sources": max(0, raw_counts.get(key, 0) - len(ordered)),
            "complete": not truncated and not document.get("sites_truncated") and bool(module["module_closed_world"]),
            "authority": "computed points-to over accepted bitcode; a cross-check input, not a finding",
        }
        label = detail.get("allocator_demangled") or detail.get("kind") or "object"
        objects.append(EntityRecord(identity, key, f"{detail.get('kind')} object ({label})",
                                    f"memory object {detail.get('kind')} {label}", payload, location))
        for item in ordered:
            relations.append(RelationRecord(RelationKind.REFERENCES, item.identity.value, identity.value, True, 1.0,
                                            None, {"rule": OBJECT_RULE, "class": accessor_class(item.payload)}))
        if truncated:
            reasons.append(f"accessor bound reached for {key} in module {planned.label}")
    return objects, relations, len(keys), list(dict.fromkeys(reasons))


def _plan_document(modules: tuple[PlannedModule, ...], settings: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema": PLAN_SCHEMA,
            "modules": [{"module_id": item.module_id, "kind": item.kind, "label": item.label,
                         "compile_indexes": list(item.compile_indexes)} for item in modules],
            "bounds": {key: settings[key] for key in _DRIVER_BOUNDS}}


def _analyze_scope(unit: UnitContext, scope: IndexScope, link_commands: list[Mapping[str, Any]],
                   executor_factory: Any) -> dict[str, Any]:
    settings = _settings(unit)
    supported, _ = partition_compile_commands(scope.compile_commands)
    plan = plan_modules(supported, link_commands, max_modules=settings["max_modules_per_scope"])
    root = unit.job.run_root / "data" / "svf" / scope.scope_id
    identity = checkpoint_identity({
        "schema": SVF_ALIAS_HANDOFF_SCHEMA, "adapter": ADAPTER, "scope": scope.as_dict(),
        "link_commands": link_commands, "settings": settings,
        "tool": tool_identity(unit.job.repository_root, TOOL_ID) if executor_factory is None
        else {"tool_id": TOOL_ID, "injected_executor": True},
    })
    reused = scope_checkpoint(root / "checkpoint.json", identity, unit.job.run_root, scope)
    if reused is not None:
        return dict(reused)

    gaps: list[str] = list(plan.gaps)
    raw_artifacts: list[Mapping[str, Any]] = [dict(scope.compile_database)]
    execution: dict[str, Any] = {}
    outcomes: dict[str, Mapping[str, Any]] = {}
    documents: dict[str, Mapping[str, Any]] = {}
    tool_version = "unknown"
    scratch = root / "run"
    try:
        execution = execute_scope_tool(unit, scope, TOOL_ID, ARGV, scratch, executor_factory,
                                       file_size_limit_bytes=settings["max_module_output_bytes"] + 1,
                                       documents={"plan.json": _plan_document(plan.modules, settings)})
    except Exception as exc:
        gaps.append(f"tool-svf image unavailable: {type(exc).__name__}: {exc}")
    if execution:
        raw_artifacts.extend((execution["receipt"], execution["compile_database"]))
        failure = ("timed out" if execution["timed_out"] else "was OOM-killed" if execution["oom_killed"]
                   else "output exceeded its execution bound" if execution["file_size_limit_reached"]
                   else f"exited with status {execution['exit_code']}" if execution["exit_code"] != 0 else None)
        if failure:
            gaps.append(f"tool-svf {failure}")
        else:
            result, error = _read_bounded_json(scratch / "result.json", settings["max_output_bytes"], "SVF run result")
            if error is None and (not isinstance(result, Mapping) or result.get("schema") != RESULT_SCHEMA
                                  or not isinstance(result.get("modules"), list)):
                error = "SVF run result envelope was malformed"
            if error:
                gaps.append(error)
            else:
                raw_artifacts.append(artifact(unit.job.run_root, scratch / "result.json"))
                tool_version = str(result.get("tool_version") or "unknown")
                for record in result.get("compile", ()):
                    if isinstance(record, Mapping) and not record.get("produced"):
                        gaps.append(f"compile unit {record.get('index')} ({record.get('file')}) did not produce "
                                    "bitcode" + (" (timed out)" if record.get("timeout") else ""))
                for outcome in result["modules"]:
                    if isinstance(outcome, Mapping) and isinstance(outcome.get("module_id"), str):
                        outcomes[outcome["module_id"]] = outcome

    shard = f"{SHARD_PREFIX}-{scope.scope_id}"
    sources = _Sources(scope)
    records: list[EntityRecord] = []
    relations: list[RelationRecord] = []
    module_rows: list[tuple[str, str, str | None]] = []
    totals = {"modules": len(plan.modules), "analyzed": 0, "closed_world": 0, "sites": 0, "indirect_calls": 0,
              "outside_accepted_sources": 0, "memory_objects": 0}
    for planned in plan.modules:
        outcome = outcomes.get(planned.module_id)
        label = f"{SHARD_PREFIX}:{scope.project_id}:{planned.label}"
        if outcome is None:
            reason = "module was not analyzed: " + (gaps[-1] if gaps else "missing from the SVF run result")
            module_rows.append((label, "unavailable", reason[:4096]))
            continue
        module_gaps = [str(item) for item in outcome.get("gaps", ())]
        if outcome.get("status") != "analyzed":
            reason = f"{outcome.get('status')}: " + ("; ".join(module_gaps) or "no detail")
            module_rows.append((label, "unavailable", reason[:4096]))
            gaps.append(f"module {planned.label}: {reason[:1024]}")
            continue
        output = scratch / str(outcome.get("output", ""))
        if scratch.resolve() not in output.resolve().parents:
            module_rows.append((label, "unavailable", "analysis output path escapes the scope scratch"))
            gaps.append(f"module {planned.label}: analysis output path escapes the scope scratch")
            continue
        document, error = _read_bounded_json(output, settings["max_module_output_bytes"], "analysis output")
        error = error or _valid_driver_document(document, settings)
        if error:
            module_rows.append((label, "unavailable", error))
            gaps.append(f"module {planned.label}: {error}")
            continue
        raw_artifacts.append(artifact(unit.job.run_root, output))
        module_records, counts, reasons = _module_records(scope, sources, planned, outcome, document, tool_version)
        sites = [item for item in module_records if item.identity.kind is EntityKind.POINTS_TO_SET]
        objects, object_relations, object_count, object_reasons = (
            _memory_objects(scope, sources, planned, document, sites, settings) if sites else ([], [], 0, []))
        records.extend(module_records)
        records.extend(objects)
        relations.extend(object_relations)
        reasons = [*reasons, *object_reasons]
        totals["memory_objects"] += object_count
        totals["analyzed"] += 1
        totals["closed_world"] += int(module_records[0].payload["module_closed_world"]) if module_records else int(
            not planned.open_world_reasons and not document["module"]["open_world_reasons"] and not module_gaps)
        for key in ("sites", "indirect_calls", "outside_accepted_sources"):
            totals[key] += counts[key]
        problems = [*module_gaps, *reasons]
        module_rows.append((label, "partial" if problems else "complete", "; ".join(problems)[:4096] or None))
        gaps.extend(f"module {planned.label}: {item}" for item in module_gaps)

    fingerprint = index_fingerprint(
        name="analysis", target_snapshot=scope.case_snapshot, producer_artifacts=raw_artifacts,
        tool_identity={"tool": TOOL_ID, "image": execution.get("image_digest"), "tool_version": tool_version},
        parser_identity=ADAPTER, normalizer_identity=ADAPTER, mapping_identity=MAPPING_METHOD + "/1",
    )
    path = unit.job.run_root / "data" / "indices" / "analysis" / \
        f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite"
    builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    for record in records:
        builder.add_entity(record)
    for relation in relations:
        builder.add_relation(relation)
    for label, status, reason in module_rows:
        builder.add_coverage(label, status, reason)
    if not module_rows:
        builder.add_coverage(f"{SHARD_PREFIX}:{scope.project_id}", "unavailable", "no compile units to analyze")
        gaps.append("no compile units to analyze")
    sha = builder.build()
    gaps = list(dict.fromkeys(gaps))
    index = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha, fingerprint,
                          path.relative_to(unit.job.run_root).as_posix(),
                          {"job": JOB_ID, "unit": unit.unit_id, "scope_id": scope.scope_id,
                           "tool_version": tool_version}, tuple(gaps), shard)
    status = "SUCCEEDED" if not gaps and all(row[1] == "complete" for row in module_rows) else "COMPLETED_WITH_GAPS"
    if totals["analyzed"] == 0:
        status = "FAILED" if module_rows else "COMPLETED_WITH_GAPS"
    result = {"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
              "accepted_compile_database": dict(scope.compile_database), "execution": execution,
              "plan": plan.as_dict(), "counts": totals, "record_count": len(records),
              "index_identity": asdict(index), "gaps": gaps, "terminal_status": status,
              "not_applicable_inputs": scope.not_applicable_inputs()}
    save_scope_checkpoint(root / "checkpoint.json", identity, result)
    return result


def _link_commands(accepted: Mapping[str, Any], case_id: str) -> list[Mapping[str, Any]]:
    catalogs = accepted["result"].get("outputs", {}).get("catalog.projects", {}).get("projects", {})
    commands = (catalogs.get(case_id) or {}).get("link_commands") or []
    return [dict(item) for item in commands if isinstance(item, Mapping)]


def _validate(context: Any, _result: Any) -> None:
    if tuple(context.config.steps) != ("load", "analyze", "acceptance"):
        raise ValueError("SVF alias-analysis topology does not match central configuration")
    for step, task in (("load", "accepted_cpp"), ("analyze", "scopes"), ("acceptance", "publish_handoff")):
        if tuple(context.config.step(step).tasks) != (task,):
            raise ValueError(f"SVF alias-analysis task configuration mismatch: {step}")
    _validated_settings(context.config.settings)


def build_job(*, executor_factory: Any = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("SVF alias-analysis target snapshot differs from accepted C++ analysis")
        return {"upstream": {"handoff_sha256": accepted["handoff_sha256"], "manifest": accepted["manifest"]},
                "scopes": [scope.as_dict() for scope in scopes], "unavailable": unavailable}

    def analyze(unit: UnitContext) -> Mapping[str, Any]:
        accepted, scopes, unavailable = accepted_cpp_scopes(unit.job.run_root)
        planned = {item["scope_id"] for item in unit.output("load.accepted_cpp")["scopes"]}
        if {scope.scope_id for scope in scopes} != planned:
            raise ValueError("accepted C++ scopes changed between load and analysis")
        runnable = [scope for scope in scopes if scope.container_compile_database()]
        skipped = [{"scope_id": scope.scope_id, "case_id": scope.case_id, "project_id": scope.project_id,
                    "terminal_status": "SKIPPED_NA", "gaps": [], "not_applicable_inputs": scope.not_applicable_inputs()}
                   for scope in scopes if not scope.container_compile_database()]
        with ThreadPoolExecutor(max_workers=max(1, _settings(unit)["workers"])) as pool:
            results = list(pool.map(lambda scope: _analyze_scope(
                unit, scope, _link_commands(accepted, scope.case_id), executor_factory), runnable))
        gaps = [f"{item['case_id']}: {gap}" for item in results for gap in item["gaps"]]
        gaps.extend(f"{case_id}: {reason}" for case_id, reason in unavailable.items())
        status = "NOT_APPLICABLE" if not results and not unavailable else (
            "SUCCEEDED" if results and not gaps else "COMPLETED_WITH_GAPS")
        return {"scopes": results, "scope_count": len(results), "gaps": gaps,
                "not_applicable_scopes": skipped, "terminal_status": status}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, analyzed = unit.output("load.accepted_cpp"), unit.output("analyze.scopes")
        manifest = publish_scope_indexes(
            unit, job_id=JOB_ID, index_name="analysis", prefix=SHARD_PREFIX,
            results=analyzed["scopes"], unavailable=loaded["unavailable"], gaps=analyzed["gaps"],
        )
        counts = {"scopes": len(analyzed["scopes"]),
                  "records": sum(item["record_count"] for item in analyzed["scopes"]),
                  "modules": sum(item["counts"]["modules"] for item in analyzed["scopes"]),
                  "closed_world_modules": sum(item["counts"]["closed_world"] for item in analyzed["scopes"]),
                  "gap_count": len(analyzed["gaps"])}
        summary = unit.unit_root / "svf-alias-analysis-summary.json"
        atomic_json(summary, {"schema": SVF_ALIAS_HANDOFF_SCHEMA, "upstream": loaded["upstream"], "counts": counts,
                              "scopes": analyzed["scopes"], "unavailable": loaded["unavailable"],
                              "gaps": analyzed["gaps"]})
        return {"schema": SVF_ALIAS_HANDOFF_SCHEMA, "artifact": artifact(unit.job.run_root, summary),
                "index_manifest": manifest, "item_count": counts["records"], "counts": counts,
                "gaps": analyzed["gaps"], "terminal_status": analyzed["terminal_status"]}

    units = (
        Unit("load.accepted_cpp", load),
        Unit("analyze.scopes", analyze, ("load.accepted_cpp",)),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_cpp", "analyze.scopes")),
    )
    implementation = hashlib.sha256(
        b"".join(path.read_bytes() for path in sorted(Path(__file__).parent.glob("*.py"))) +
        (b"injected-executor" if executor_factory else b"container-executor")
    ).hexdigest()
    return Job(JOB_ID, "svf_alias_analysis", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=SVF_ALIAS_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, consumes=CONSUMES)
