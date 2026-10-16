"""Seeded LLVM IR and Clang AST: replay only the translation units that hold finding locations.

Seeded mode runs from the findings outward (``docs/architecture/seeded-neighborhoods.md``):

* the seed plan comes from accepted observation shards (``appsec_review.seeding``);
* ``select_units`` names the translation units whose source can contain a seed; only those are
  replayed. There is no whole-program fallback: a seed no unit contains is a named gap;
* IR gives each replayed unit's functions, calls and flow graph; ``expand`` bounds the call-graph
  neighborhood of the seed functions; only that neighborhood is published;
* the same units are replayed once more for Clang's source-level CFG (``debug.DumpCFG``), attached to the
  IR function of the same name as ``source_cfg``; a failed or ambiguous match is a named gap, never a guess;
* AST is replayed for the units that define neighborhood functions, filtered to their names, so it
  depends on the IR result.

Every unresolved seed keeps the reason it stayed unresolved; neither a failed replay nor a missing
unit ever raises coverage. Callers in translation units that were not replayed are not visible; that
is the standing ``frontier`` gap, not evidence that no such caller exists.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

from appsec_review import seeding
from appsec_review.config.seeding import SeededSettings
from appsec_review.jobs.cpp_index_scopes import project_prefix
from appsec_review.retrieval import (
    EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord,
)
from appsec_review.runtime import UnitContext
from appsec_review.seeding import neighborhood as walk
from appsec_review.seeding import record, units as unit_selection
from appsec_review.storage import canonical_json, tool_input_json

from .clang_cfg import NO_BLOCK_LINES_GAP, SourceCfg, parse_cfgs
from .llvm_ir import IrFunction, parse_module

SEEDED_IMPL = "cpp-seeded-compiled/2"
MAX_IR_BYTES = 64 * 1024 * 1024
MAX_CFG_BYTES = 16 * 1024 * 1024
REPLAY = {"ir": "replay-ir.json", "ast": "replay-ast.json", "cfg": "replay-cfg.json"}
AREA = {"ir": "llvm-ir", "ast": "clang-ast"}
STANDING_FRONTIER = (
    "frontier: callers of external-linkage neighborhood functions are visible only from the {units} "
    "replayed translation unit(s); callers in other translation units are absent, not nonexistent")


def _base():
    from . import job
    return job


def settings_of(unit: UnitContext) -> SeededSettings:
    return SeededSettings.from_job_settings(unit.job.config.settings)


def plan_for(unit: UnitContext, catalogs: Mapping[str, Mapping[str, Any]],
             settings: SeededSettings) -> seeding.SeedPlan:
    """Seeds of every buildable project in one pass over the accepted observation shards."""
    scopes = [seeding.project_scope(case_id, value["mapping"]) for case_id, value in sorted(catalogs.items())]
    return seeding.seed_plan(unit.job, scopes, settings)


def identity_values(settings: SeededSettings, scope_seeds: seeding.ScopeSeeds, **extra: Any) -> dict[str, Any]:
    """The seeded part of a checkpoint identity: bounds, mode and the sorted seed set."""
    return {"seeded": {**settings.identity(), "seeds": [list(row) for row in sorted(scope_seeds.rows)],
                       "impl": SEEDED_IMPL, **extra}}


def _select(unit: UnitContext, case_id: str, commands: Sequence[Mapping[str, Any]],
            settings: SeededSettings, scope_seeds: seeding.ScopeSeeds) -> unit_selection.UnitSelection:
    reader = seeding.source_reader(_base()._case_root(unit, case_id) / "source")
    return unit_selection.select_units(commands, scope_seeds.seeds, unit_limit=settings.unit_limit,
                                       include_scan_files=settings.include_scan_files, read_text=reader)


def clear_replay(unit: UnitContext, case_id: str, mode: str) -> None:
    root = _base()._case_root(unit, case_id)
    for name in (mode, "cfg") if mode == "ir" else (mode,):
        (root / REPLAY[name]).unlink(missing_ok=True)
        shutil.rmtree(root / "analysis" / name, ignore_errors=True)


def _write_replay(unit: UnitContext, case_id: str, mode: str, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    root = _base()._case_root(unit, case_id)
    # Renumbered from zero: the tool's receipt and ``tu-NNNN`` outputs index this subset only.
    tool_input_json(root / REPLAY[mode], [dict(row) for row in rows])
    return _base()._artifact(unit.job.run_root, root / REPLAY[mode])


def _publish(unit: UnitContext, case_id: str, mode: str, cataloged: Mapping[str, Any], *, builder, path,
             fingerprint: str, shard: str, gaps: list[str], section: Mapping[str, Any], coverage: str,
             skipped: bool = False, extras: Mapping[str, Any] | None = None,
             checkpointable: bool = True) -> dict[str, Any]:
    """Write the ledger artifact, qualify the coverage and finish the shard."""
    base = _base()
    ledger = base._json_artifact(unit, base._case_root(unit, case_id) / f"seeded-{mode}-ledger.json",
                                 {"schema": record.RECORD_SCHEMA, "branch": mode, "project": case_id,
                                  "seeded": section})
    compact = seeding.compact_record({**section, "gaps": list(dict.fromkeys([*gaps, *section.get("gaps", ())]))},
                                     ledger=ledger, skipped=skipped)
    sample = seeding.coverage_gap(section)
    text = "; ".join([sample, *gaps][:10])
    builder.add_coverage(AREA[mode], "unavailable" if coverage == "unavailable" else "partial", text)
    result = dict(base._finish_index(unit, builder, path, fingerprint, shard, "analysis", mode, gaps,
                                     seeded=compact))
    result.update(extras or {})
    result.update(seeded=compact, ledger=ledger, checkpointable=checkpointable)
    return result


def _skipped(unit: UnitContext, case_id: str, mode: str, cataloged: Mapping[str, Any],
             settings: SeededSettings, plan: seeding.SeedPlan, scope_seeds: seeding.ScopeSeeds) -> dict[str, Any]:
    """Zero seeds: no replay, a named gap, a partial (never complete) shard."""
    base = _base()
    section = seeding.ledger.skipped_section(depth=settings.depth, seed_limit=settings.seed_limit,
                                              scope_seeds=scope_seeds, plan=plan)
    gaps = list(section["gaps"])
    builder, path, fingerprint, shard = base._new_builder(
        unit, "analysis", case_id, mode, [cataloged["compile_database"]], gaps,
        {"tool": AREA[mode], "status": "skipped-no-seeds", **identity_values(settings, scope_seeds)},
        cataloged["mapping"]["case_snapshot"])
    return _publish(unit, case_id, mode, cataloged, builder=builder, path=path, fingerprint=fingerprint,
                    shard=shard, gaps=gaps, section=section, coverage="partial", skipped=True,
                    extras={"entity_count": 0})


def _function_path(root: str, function: IrFunction) -> str | None:
    """Target-relative path of a function defined in the project, else ``None`` (system header)."""
    if not function.path or function.path.startswith("/") or ".." in function.path.split("/"):
        return None
    return project_prefix(root) + function.path


def _seed_function(functions: Sequence[IrFunction], seed: seeding.Seed) -> IrFunction | None:
    """The innermost function whose body overlaps the seed's line range in the seed's file."""
    inside = [fn for fn in functions if fn.path == seed.path and fn.start_line <= seed.end_line and
              seed.start_line <= max(fn.end_line, fn.start_line)]
    if not inside:
        return None
    return min(inside, key=lambda fn: (fn.end_line - fn.start_line, fn.name, fn.linkage_name))


def _tail(name: str) -> str:
    return name.rsplit("::", 1)[-1]


def _source_cfgs(unit: UnitContext, case_id: str, root: Path, subset: Sequence[Mapping[str, Any]],
                 settings: SeededSettings, executor_factory: Any, gaps: list[str]
                 ) -> tuple[dict[int, list[SourceCfg]], Mapping[str, Any] | None, Mapping[str, Any] | None]:
    """Replay the selected units for ``debug.DumpCFG`` text: (cfgs per unit position, replay and run artifacts).

    Any failure is a named gap and an empty result; the IR flow graph is published either way.
    """
    base = _base()
    shutil.rmtree(root / "analysis" / "cfg", ignore_errors=True)
    replay = _write_replay(unit, case_id, "cfg", subset)
    execution = base._run_tool(unit, case_id, ("cfg",), executor_factory, label="cfg")
    found: dict[int, list[SourceCfg]] = {}
    if execution["timed_out"] or execution["oom_killed"]:
        gaps.append(f"source_cfg_unavailable: {case_id} cfg replay "
                    f"{'timed out' if execution['timed_out'] else 'ran out of memory'}")
        return found, replay, execution
    failures = base.replay_failures(root, "cfg", subset)
    if failures is None:
        gaps.append(f"source_cfg_unavailable: {case_id} cfg replay receipt unusable (exit {execution['exit_code']})")
        return found, replay, execution
    for position, command in enumerate(subset):
        if position in failures:
            gaps.append("source_cfg_unavailable: " + failures[position])
            continue
        path = root / "analysis" / "cfg" / f"tu-{position:04d}.cfg.txt"
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CFG_BYTES:
            gaps.append(f"source_cfg_unavailable: {command['target_path']}: CFG text unavailable or over bound")
            continue
        module = parse_cfgs(path.read_text(encoding="utf-8", errors="replace"), block_limit=settings.block_limit)
        found[position] = list(module.functions)
        gaps.extend(f"{command['target_path']}: {gap}" for gap in module.gaps)
    return found, replay, execution


def _match_cfgs(local: Sequence[tuple[int, IrFunction]], members: Mapping[str, int],
                cfgs: Mapping[int, Sequence[SourceCfg]]) -> tuple[dict[tuple[int, str], SourceCfg], list[str], list[str]]:
    """(cfg per (unit position, IR linkage name), ambiguous names, names without a CFG) for neighborhood functions."""
    matched: dict[tuple[int, str], SourceCfg] = {}
    ambiguous: set[str] = set()
    missing: set[str] = set()
    for pos, fn in local:
        if fn.name not in members:
            continue
        if pos not in cfgs:
            missing.add(fn.name)
            continue
        wanted = _tail(fn.name)
        same_ir = [other for other_pos, other in local if other_pos == pos and _tail(other.name) == wanted]
        same_cfg = [cfg for cfg in cfgs[pos] if cfg.name == wanted]
        if len(same_ir) == 1 and len(same_cfg) == 1:
            matched[(pos, fn.linkage_name)] = same_cfg[0]
        elif len(same_ir) > 1 or len(same_cfg) > 1:
            ambiguous.add(fn.name)
        else:
            missing.add(fn.name)
    return matched, sorted(ambiguous), sorted(missing)


def ir_result(unit: UnitContext, case_id: str, cataloged: Mapping[str, Any], settings: SeededSettings,
              plan: seeding.SeedPlan, executor_factory: Any) -> dict[str, Any]:
    base = _base()
    root = base._case_root(unit, case_id)
    scope_seeds = plan.for_scope(case_id)
    commands = cataloged["compile_commands"]
    mapping = cataloged["mapping"]
    clear_replay(unit, case_id, "ir")
    if not scope_seeds.seeds:
        return _skipped(unit, case_id, "ir", cataloged, settings, plan, scope_seeds)
    selection = _select(unit, case_id, commands, settings, scope_seeds)
    reasons = {key: record.REASON_NO_UNIT for key in selection.uncovered}
    gaps: list[str] = list(selection.gaps)
    identity = identity_values(settings, scope_seeds)

    def finish(section: Mapping[str, Any], *, builder, path, fingerprint, shard, coverage="partial", **more):
        return _publish(unit, case_id, "ir", cataloged, builder=builder, path=path, fingerprint=fingerprint,
                        shard=shard, gaps=gaps, section=section, coverage=coverage, **more)

    if not selection.selected:
        section = record.with_reasons(seeding.ledger.seeded_section(
            depth=settings.depth, seed_limit=settings.seed_limit, scope_seeds=scope_seeds, plan=plan), reasons)
        gaps.extend(gap for gap in section["gaps"] if gap not in gaps)
        builder, path, fingerprint, shard = base._new_builder(
            unit, "analysis", case_id, "ir", [cataloged["compile_database"]], gaps,
            {"tool": AREA["ir"], "status": "no-translation-unit", **identity}, mapping["case_snapshot"])
        return finish(section, builder=builder, path=path, fingerprint=fingerprint, shard=shard,
                      extras={"entity_count": 0})
    subset = [commands[index] for index in selection.selected]
    replay = _write_replay(unit, case_id, "ir", subset)
    execution = base._run_tool(unit, case_id, ("ir",), executor_factory)
    tool_gap = None if execution["exit_code"] == 0 else f"{case_id} ir failed with exit {execution['exit_code']}"
    failures: dict[int, str] | None = None
    if not execution["timed_out"] and not execution["oom_killed"]:
        failures = base.replay_failures(root, "ir", subset)
        if execution["exit_code"] == 2 and failures:
            tool_gap = None
        elif tool_gap and failures:
            tool_gap += "; " + "; ".join(list(failures.values())[:5])
    if failures is None and tool_gap is None:
        tool_gap = f"{case_id} ir replay receipt unusable"
    tool_identity = {"tool": "clang-18-llvm-ir", "image": execution["image_id"], **identity}
    artifacts = [execution["execution"], cataloged["compile_database"], replay]
    if tool_gap:
        gaps.append(tool_gap)
        reasons.update({key: record.REASON_RUN_FAILED for key in selection.by_seed})
        section = record.with_reasons(seeding.ledger.seeded_section(
            depth=settings.depth, seed_limit=settings.seed_limit, scope_seeds=scope_seeds, plan=plan), reasons)
        gaps.extend(gap for gap in section["gaps"] if gap not in gaps)
        builder, path, fingerprint, shard = base._new_builder(
            unit, "analysis", case_id, "ir", artifacts, gaps, tool_identity, mapping["case_snapshot"])
        return finish(section, builder=builder, path=path, fingerprint=fingerprint, shard=shard,
                      coverage="unavailable", extras={"entity_count": 0}, checkpointable=False)
    failures = failures or {}
    parsed: list[tuple[int, IrFunction]] = []
    external_calls: dict[str, list[tuple[str, int | None]]] = {}
    for position, command in enumerate(subset):
        if position in failures:
            gaps.append(failures[position])
            continue
        ir_path = root / "analysis" / "ir" / f"tu-{position:04d}.ll"
        if not ir_path.is_file() or ir_path.is_symlink() or ir_path.stat().st_size > MAX_IR_BYTES:
            gaps.append(f"{command['target_path']}: LLVM IR output unavailable or over bound")
            failures[position] = gaps[-1]
            continue
        module = parse_module(ir_path.read_text(encoding="utf-8", errors="replace"),
                              block_limit=settings.block_limit)
        for function in module.functions:
            parsed.append((position, function))
        if module.unparsed:
            gaps.append(f"{command['target_path']}: {len(module.unparsed)} function(s) carry no debug "
                        "subprogram and were not parsed (compile with -g)")
    local = [(pos, fn) for pos, fn in parsed if _function_path(mapping["root"], fn) is not None]
    defs: dict[str, list[tuple[int, IrFunction]]] = {}
    callees: dict[str, set[str]] = {}
    callers: dict[str, set[str]] = {}
    for pos, fn in local:
        defs.setdefault(fn.name, []).append((pos, fn))
        for call in fn.calls:
            callees.setdefault(fn.name, set()).add(call.callee)
            callers.setdefault(call.callee, set()).add(fn.name)
    functions = [fn for _, fn in local]
    seed_functions: dict[tuple[str, int, int], IrFunction] = {}
    for seed in scope_seeds.seeds:
        found = _seed_function(functions, seed)
        if found is not None:
            seed_functions[seed.key] = found
    for key, indexes in selection.by_seed.items():
        positions = {selection.selected.index(index) for index in indexes}
        if key not in seed_functions and positions <= set(failures):
            reasons[key] = record.REASON_RUN_FAILED
    walked = walk.expand({fn.name for fn in seed_functions.values()}, callers, callees,
                         depth=settings.depth, function_limit=settings.function_limit, observed=defs)
    members = walked.distance
    gaps.extend(gap for gap in walked.gaps if gap not in gaps)
    cfg_gaps: list[str] = []
    cfgs, cfg_replay, cfg_execution = _source_cfgs(unit, case_id, root, subset, settings, executor_factory, cfg_gaps)
    source_cfg, cfg_ambiguous, cfg_missing = _match_cfgs(local, members, cfgs)
    if cfg_execution is not None:
        artifacts.extend(item for item in (cfg_execution["execution"], cfg_replay) if item is not None)
    external = sorted({fn.name for name in members for _, fn in defs.get(name, ()) if not fn.internal})
    if external:
        gaps.append(STANDING_FRONTIER.format(units=len(subset)))
    gaps.extend(cfg_gaps)
    if source_cfg:
        gaps.append(NO_BLOCK_LINES_GAP)
    if cfg_ambiguous:
        gaps.append("source_cfg_ambiguous: overloaded definitions were not given a CFG: " + ", ".join(cfg_ambiguous[:20]))
    if cfg_missing and cfgs:
        gaps.append("source_cfg_unmatched: no CFG matched the neighborhood function(s): " + ", ".join(cfg_missing[:20]))
    for pos, fn in local:
        if fn.name in members and fn.truncated:
            gaps.append(f"{walk.EXPORT_TRUNCATED}: {fn.name} flow was cut at {', '.join(fn.truncated)}")
    document = {"columns": ["seed_path", "seed_start_line", "seed_end_line", "function_name", "function_path",
                            "function_start_line", "function_start_column"],
                "rows": [[key[0], key[1], key[2], fn.name, fn.path, fn.start_line, 1]
                         for key, fn in sorted(seed_functions.items())]}
    hood = {"columns": ["function_name", "function_path", "function_start_line", "function_start_column", "depth"],
            "rows": [[name, defs[name][0][1].path if name in defs else "",
                      defs[name][0][1].start_line if name in defs else 0, 1, members[name]]
                     for name in walked.functions]}
    section = record.with_reasons(seeding.ledger.seeded_section(
        depth=settings.depth, seed_limit=settings.seed_limit, scope_seeds=scope_seeds, plan=plan,
        seed_functions=document, neighborhood=hood), reasons)
    gaps.extend(gap for gap in section["gaps"] if gap not in gaps)
    builder, path, fingerprint, shard = base._new_builder(
        unit, "analysis", case_id, "ir", artifacts, gaps, tool_identity, mapping["case_snapshot"])
    snapshot = unit.job.source_fingerprint
    target = unit.job.target_root or Path()
    entity_ids: dict[str, str] = {}
    for name in walked.functions:
        for pos, fn in sorted(defs.get(name, ()), key=lambda item: (item[1].linkage_name, item[0])):
            target_path = _function_path(mapping["root"], fn)
            if target_path is None or not (target / target_path).is_file():
                continue
            compile_unit = subset[pos]["compile_unit_id"]
            identity_value = LogicalIdentity.derive(EntityKind.IR_ENTITY, mapping["case_snapshot"],
                {"compile_unit_id": compile_unit, "function": fn.linkage_name,
                 "definition_line": fn.start_line})
            builder.add_entity(EntityRecord(identity_value, f"{pos}:{fn.linkage_name}", fn.name,
                f"define {fn.linkage_name}",
                {"kind": "function", "linkage_name": fn.linkage_name, "internal": fn.internal,
                 "distance": members[name], "flow": fn.flow(), "seeded": True,
                 **({"source_cfg": source_cfg[(pos, fn.linkage_name)].to_payload()}
                    if (pos, fn.linkage_name) in source_cfg else {}),
                 "project_id": mapping["project_id"], "compile_unit_id": compile_unit, "shard_id": shard},
                base._location(snapshot, target, target_path, fn.start_line, 1, method="ir-debug-info")))
            entity_ids.setdefault(f"{pos}:{fn.name}", identity_value.value)
            if len(defs[name]) == 1:
                entity_ids[fn.name] = identity_value.value
    declarations: dict[str, str] = {}
    for name in walked.functions:
        if name in defs:
            continue
        site = min(((_function_path(mapping["root"], fn), call.line or 1, fn.linkage_name)
                    for caller in callers.get(name, ()) if caller in members
                    for _, fn in defs.get(caller, ()) for call in fn.calls if call.callee == name
                    if _function_path(mapping["root"], fn) is not None), default=None)
        if site is None or not (target / site[0]).is_file():
            continue
        identity_value = LogicalIdentity.derive(EntityKind.IR_ENTITY, mapping["case_snapshot"],
            {"project_id": mapping["project_id"], "declared": name, "site": [site[0], site[1]]})
        builder.add_entity(EntityRecord(identity_value, f"declared:{name}", name, f"declare {name}",
            {"kind": "declaration", "distance": members[name], "seeded": True,
             "project_id": mapping["project_id"], "shard_id": shard},
            base._location(snapshot, target, site[0], site[1], 1, ambiguous=True, method="ir-call-site")))
        declarations[name] = identity_value.value
    edges = 0
    seen: set[tuple[str, str]] = set()
    ambiguous: set[str] = set()
    for pos, fn in local:
        source = entity_ids.get(f"{pos}:{fn.name}")
        if fn.name not in members or source is None:
            continue
        for call in fn.calls:
            if call.callee not in members:
                continue
            target_id = (entity_ids.get(f"{pos}:{call.callee}") or entity_ids.get(call.callee) or
                         declarations.get(call.callee))
            if target_id is None and len(defs.get(call.callee, ())) > 1:
                ambiguous.add(call.callee)
            if target_id is None or (source, target_id) in seen:
                continue
            seen.add((source, target_id))
            builder.add_relation(RelationRecord(RelationKind.CALLS, source, target_id, True, 1.0,
                                                payload={"mapping": "ir-direct-call", "line": call.line}))
            edges += 1
    if ambiguous:
        gaps.append("ambiguous cross-translation-unit IR callees were not related: " +
                    ", ".join(sorted(ambiguous)[:20]))
    blocks = sum(len(fn.blocks) for _, fn in local if fn.name in members)
    handoff = {"neighborhood": {name: members[name] for name in walked.functions},
               "function_units": {name: sorted({selection.selected[pos] for pos, _ in defs[name]})
                                  for name in walked.functions if name in defs},
               "seed_functions": [row[:4] for row in document["rows"]],
               # project-relative [path, first line, last line] of each neighborhood function: lets a
               # line-located producer (Clang-Tidy, the Static Analyzer) label what is inside it.
               "ranges": {name: [defs[name][0][1].path, defs[name][0][1].start_line,
                                 max(defs[name][0][1].end_line, defs[name][0][1].start_line)]
                          for name in walked.functions if name in defs}}
    return finish(section, builder=builder, path=path, fingerprint=fingerprint, shard=shard,
                  checkpointable=not failures,
                  extras={"entity_count": len(builder.entities), "basic_block_count": blocks,
                          "call_edge_count": edges, "source_cfg_count": len(source_cfg), "handoff": handoff,
                          "handoff_sha256": hashlib.sha256(canonical_json(handoff)).hexdigest()})


def ast_result(unit: UnitContext, case_id: str, cataloged: Mapping[str, Any], settings: SeededSettings,
               plan: seeding.SeedPlan, ir_output: Mapping[str, Any] | None, executor_factory: Any) -> dict[str, Any]:
    base = _base()
    root = base._case_root(unit, case_id)
    scope_seeds = plan.for_scope(case_id)
    commands = cataloged["compile_commands"]
    mapping = cataloged["mapping"]
    clear_replay(unit, case_id, "ast")
    if not scope_seeds.seeds:
        return _skipped(unit, case_id, "ast", cataloged, settings, plan, scope_seeds)
    handoff = (ir_output or {}).get("handoff")
    identity = identity_values(settings, scope_seeds, ir=(ir_output or {}).get("handoff_sha256"))
    gaps: list[str] = []
    reasons: dict[tuple[str, int, int], str] = {}
    if not isinstance(handoff, Mapping) or not handoff.get("function_units"):
        # The AST is anchored to the IR neighborhood: without it nothing is replayed.
        gaps.append("ast_without_neighborhood: the seeded LLVM IR neighborhood is unavailable or empty, so "
                    "no Clang AST was replayed; this is a gap, not a clean result")
        reasons.update({seed.key: record.REASON_NOT_RUN for seed in scope_seeds.seeds})
        section = record.with_reasons(seeding.ledger.seeded_section(
            depth=settings.depth, seed_limit=settings.seed_limit, scope_seeds=scope_seeds, plan=plan), reasons)
        gaps.extend(gap for gap in section["gaps"] if gap not in gaps)
        builder, path, fingerprint, shard = base._new_builder(
            unit, "analysis", case_id, "ast", [cataloged["compile_database"]], gaps,
            {"tool": AREA["ast"], "status": "no-neighborhood", **identity}, mapping["case_snapshot"])
        return _publish(unit, case_id, "ast", cataloged, builder=builder, path=path, fingerprint=fingerprint,
                        shard=shard, gaps=gaps, section=section, coverage="partial",
                        extras={"entity_count": 0}, checkpointable=False)
    names_by_row: dict[int, list[str]] = {}
    for name, rows in handoff["function_units"].items():
        for index in rows:
            names_by_row.setdefault(int(index), []).append(name)
    selected = sorted(names_by_row)[:settings.unit_limit]
    if len(names_by_row) > len(selected):
        gaps.append(f"{unit_selection.UNIT_LIMIT_REACHED}: unit_limit {settings.unit_limit} reached; "
                    f"{len(names_by_row) - len(selected)} translation unit(s) were not replayed for the AST")
    subset = [{**commands[index], "ast_filters": sorted(names_by_row[index])[:400]} for index in selected]
    replay = _write_replay(unit, case_id, "ast", subset)
    execution = base._run_tool(unit, case_id, ("ast",), executor_factory)
    tool_gap = None if execution["exit_code"] == 0 else f"{case_id} ast failed with exit {execution['exit_code']}"
    failures: dict[int, str] | None = None
    if not execution["timed_out"] and not execution["oom_killed"]:
        failures = base.replay_failures(root, "ast", subset)
        if execution["exit_code"] == 2 and failures:
            tool_gap = None
        elif tool_gap and failures:
            tool_gap += "; " + "; ".join(list(failures.values())[:5])
    if failures is None and tool_gap is None:
        tool_gap = f"{case_id} ast replay receipt unusable"
    tool_identity = {"tool": "clang-18", "image": execution["image_id"], "callee_decl": 1, **identity}
    artifacts = [execution["execution"], cataloged["compile_database"], replay]
    failures = dict(failures or {})
    failed_rows = {selected[pos] for pos in failures}
    resolved_rows = set(selected) if not tool_gap else set()
    # A seed is resolved for the AST when its function was dumped by a unit that replayed cleanly.
    functions = {tuple(row[:3]): row[3] for row in handoff["seed_functions"]}
    document = {"columns": ["seed_path", "seed_start_line", "seed_end_line", "function_name"],
                "rows": []}
    for seed in scope_seeds.seeds:
        name = functions.get(seed.key)
        if name is None:
            continue
        rows = set(handoff["function_units"].get(name, ()))
        if rows & resolved_rows - failed_rows:
            document["rows"].append([*seed.key, name])
        else:
            reasons[seed.key] = record.REASON_RUN_FAILED
    hood = {"columns": ["function_name", "function_path", "function_start_line", "function_start_column", "depth"],
            "rows": [[name, "", 0, 1, depth] for name, depth in sorted(handoff["neighborhood"].items(),
                                                                       key=lambda item: (item[1], item[0]))
                     if set(handoff["function_units"].get(name, ())) & resolved_rows - failed_rows]}
    section = record.with_reasons(seeding.ledger.seeded_section(
        depth=settings.depth, seed_limit=settings.seed_limit, scope_seeds=scope_seeds, plan=plan,
        seed_functions=document, neighborhood=hood), reasons)
    for gap in (ir_output or {}).get("seeded", {}).get("gaps", ()):
        if gap.startswith((walk.LIMIT_REACHED, walk.DEPTH_REACHED, walk.FRONTIER)) and gap not in gaps:
            gaps.append(gap)
    if tool_gap:
        gaps.append(tool_gap)
    gaps.extend(gap for gap in section["gaps"] if gap not in gaps)
    builder, path, fingerprint, shard = base._new_builder(
        unit, "analysis", case_id, "ast", artifacts, gaps, tool_identity, mapping["case_snapshot"])
    if tool_gap:
        return _publish(unit, case_id, "ast", cataloged, builder=builder, path=path, fingerprint=fingerprint,
                        shard=shard, gaps=gaps, section=section, coverage="unavailable",
                        extras={"entity_count": 0}, checkpointable=False)
    count = base._add_ast_entities(unit, case_id, {**cataloged, "compile_commands": subset}, failures,
                                   builder, shard, gaps)
    gaps[:] = list(dict.fromkeys(gaps))
    return _publish(unit, case_id, "ast", cataloged, builder=builder, path=path, fingerprint=fingerprint,
                    shard=shard, gaps=gaps, section=section, coverage="partial",
                    extras={"entity_count": count}, checkpointable=not failures)
