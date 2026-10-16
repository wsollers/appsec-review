from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_svf_alias_analysis import JOB_ID, TOOL_ID, build_job
from appsec_review.jobs.job_svf_alias_analysis.job import (
    FACT_SCHEMA, PLAN_SCHEMA, _analyze_scope, _validate, _validated_settings,
)
from appsec_review.jobs.job_svf_alias_analysis.planning import (
    ARCHIVE_MEMBERS_UNRESOLVED, LINK_INPUT_UNRESOLVED, MODULE_LINK, MODULE_TRANSLATION_UNIT, NOT_IN_LINK_UNIT,
    module_id, plan_modules,
)
from appsec_review.storage import file_sha256
from tests.fixtures.svf.builder import LINK_COMMANDS, SETTINGS, ReplayExecutor, scope, unit


def _rows(path: Path, sql: str) -> list[sqlite3.Row]:
    database = sqlite3.connect(path)
    database.row_factory = sqlite3.Row
    try:
        return list(database.execute(sql))
    finally:
        database.close()


def _run(tmp_path: Path, executor: ReplayExecutor | None = None, *, settings=None, links=LINK_COMMANDS):
    run_root = tmp_path / "run"
    accepted = scope(run_root)
    context = unit(run_root, settings)
    executor = executor or ReplayExecutor(run_root)
    return run_root, accepted, executor, _analyze_scope(context, accepted, links, lambda _unit: executor)


def _entities(run_root: Path, result) -> list[dict]:
    shard = run_root / result["index_identity"]["relative_path"]
    rows = _rows(shard, "SELECT e.kind, e.payload_json, l.path, l.start_line, l.start_column, l.ambiguous "
                        "FROM entities e LEFT JOIN locations l ON l.entity_id = e.identity ORDER BY e.identity")
    return [{"kind": row["kind"], "payload": json.loads(row["payload_json"]), "path": row["path"],
             "line": row["start_line"], "column": row["start_column"], "ambiguous": row["ambiguous"]} for row in rows]


def _coverage(run_root: Path, result) -> dict[str, tuple[str, str | None]]:
    shard = run_root / result["index_identity"]["relative_path"]
    return {row["area"]: (row["status"], row["gap"])
            for row in _rows(shard, "SELECT area, status, gap FROM coverage")}


# --------------------------------------------------------------------------- planning


def _rows_for(*names: str) -> list[dict]:
    return [{"target_path": f"src/{name}.c", "output_path": f"build/{name}.o"} for name in names]


def test_link_command_becomes_one_module_and_unlinked_units_stand_alone() -> None:
    plan = plan_modules(_rows_for("a", "b", "c"), [{"output_path": "build/app", "input_paths": ["build/a.o", "build/b.o"]}],
                        max_modules=8)
    assert [(m.kind, m.label, m.compile_indexes) for m in plan.modules] == [
        (MODULE_LINK, "build/app", (0, 1)), (MODULE_TRANSLATION_UNIT, "src/c.c", (2,))]
    assert plan.modules[0].open_world_reasons == ()
    assert plan.modules[1].open_world_reasons == (NOT_IN_LINK_UNIT,)
    assert plan.gaps == ()


def test_static_archives_expand_through_their_own_command_and_shared_libraries_stay_external() -> None:
    links = [
        {"output_path": "build/libcore.a", "input_paths": ["build/a.o", "build/b.o"]},
        {"output_path": "build/libnet.so", "input_paths": ["build/c.o"]},
        {"output_path": "build/app", "input_paths": ["build/d.o", "build/libcore.a", "build/libnet.so"]},
    ]
    plan = plan_modules(_rows_for("a", "b", "c", "d"), links, max_modules=8)
    modules = {m.label: m for m in plan.modules}
    assert set(modules) == {"build/app", "build/libnet.so"}  # the archive is never its own module
    assert modules["build/app"].compile_indexes == (0, 1, 3)
    assert modules["build/app"].open_world_reasons == ()
    assert any("shared library input kept external: build/libnet.so" in note for note in modules["build/app"].notes)
    assert modules["build/libnet.so"].compile_indexes == (2,)


def test_unresolved_archives_and_inputs_are_named_open_world_reasons() -> None:
    links = [{"output_path": "build/app", "input_paths": ["build/a.o", "build/libthird.a", "build/blob.bin"]}]
    plan = plan_modules(_rows_for("a"), links, max_modules=8)
    module = plan.modules[0]
    assert module.compile_indexes == (0,)
    assert module.open_world_reasons == (ARCHIVE_MEMBERS_UNRESOLVED, LINK_INPUT_UNRESOLVED)


def test_module_bound_omits_trailing_modules_with_a_gap_and_ids_are_deterministic() -> None:
    rows = _rows_for("a", "b", "c")
    plan = plan_modules(rows, [], max_modules=2)
    assert [m.label for m in plan.modules] == ["src/a.c", "src/b.c"]
    assert [m.label for m in plan.omitted] == ["src/c.c"]
    assert plan.gaps == ("module bound reached: 1 of 3 planned modules were not analyzed",)
    assert plan_modules(rows, [], max_modules=2) == plan
    assert plan.modules[0].module_id == module_id(MODULE_TRANSLATION_UNIT, "src/a.c", (0,))
    with pytest.raises(ValueError):
        plan_modules(rows, [], max_modules=0)


# --------------------------------------------------------------------------- scope analysis


def test_recorded_run_publishes_located_points_to_and_indirect_call_records(tmp_path: Path) -> None:
    run_root, _scope, executor, result = _run(tmp_path)
    request = executor.requests[0]
    assert request.tool_id == TOOL_ID
    assert request.argv == ("/opt/appsec/svf.py", "run", "/scratch/plan.json", "/scratch/result.json")
    plan = json.loads((request.scratch_root / "plan.json").read_text(encoding="utf-8"))
    assert plan["schema"] == PLAN_SCHEMA
    assert [(m["kind"], m["compile_indexes"]) for m in plan["modules"]] == [("link", [0, 1, 2]), ("translation_unit", [3])]
    assert result["counts"]["modules"] == 2 and result["counts"]["analyzed"] == 2
    shard = run_root / result["index_identity"]["relative_path"]
    assert file_sha256(shard) == result["index_identity"]["sha256"]
    assert result["index_identity"]["name"] == "analysis"
    assert result["index_identity"]["shard_id"] == "svf-cpp-scope-svf"
    assert result["index_identity"]["producer"]["job"] == JOB_ID

    entities = _entities(run_root, result)
    calls = [item for item in entities if item["kind"] == "indirect_call_targets" and item["path"] == "native/callbacks.c"]
    assert len(calls) == 1
    call = calls[0]
    assert (call["path"], call["line"], call["column"], call["ambiguous"]) == ("native/callbacks.c", 18, 12, 0)
    assert [t["demangled"] for t in call["payload"]["targets"]] == ["copy_handler", "length_handler"]
    assert call["payload"]["schema"] == FACT_SCHEMA and call["payload"]["module_closed_world"] is True
    assert call["payload"]["complete"] is True

    sites = {(item["path"], item["line"], item["column"], item["payload"]["role"], item["payload"]["operand"]): item
             for item in entities if item["kind"] == "points_to_set"}
    alias_compare = sites[("native/guard.c", 8, 15, "compare", 0)]["payload"]
    alias_store = sites[("native/guard.c", 9, 22, "store", -1)]["payload"]
    assert alias_compare["points_to"] == alias_store["points_to"] and alias_compare["complete"]
    unrelated_compare = sites[("native/guard.c", 16, 17, "compare", 0)]["payload"]
    unrelated_store = sites[("native/guard.c", 17, 18, "store", -1)]["payload"]
    assert not set(unrelated_compare["points_to"]) & set(unrelated_store["points_to"])
    null_operand = sites[("native/guard.c", 16, 17, "compare", 1)]["payload"]
    assert null_operand["points_to"] == [] and null_operand["incomplete_reasons"] == ["empty_points_to_set"]
    assert all(key in alias_store["objects"] for key in alias_store["points_to"])


def test_open_world_module_is_marked_on_every_record_and_its_coverage_is_partial(tmp_path: Path) -> None:
    run_root, _scope, _executor, result = _run(tmp_path)
    plugin = [item["payload"] for item in _entities(run_root, result) if item["path"] == "native/plugin.c"]
    assert plugin and all(not payload["module_closed_world"] for payload in plugin)
    assert set(plugin[0]["open_world_reasons"]) == {"not_in_link_unit", "dynamic_loading",
                                                    "unmodeled_external_functions"}
    assert plugin[0]["unmodeled_externals"] == ["dlsym"]
    string_literal = [p for p in plugin if p.get("role") == "call_arg" and p.get("operand") == 1]
    assert string_literal[0]["points_to"] == ["obj:constant:shared"]
    coverage = _coverage(run_root, result)
    assert coverage["svf:cpp:native:build/app"] == ("complete", None)
    status, reason = coverage["svf:cpp:native:native/plugin.c"]
    assert status == "partial" and "dynamic_loading" in reason
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["counts"]["closed_world"] == 1


def test_container_failure_makes_every_module_unavailable_and_the_scope_failed(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    _run_root, _scope, _executor, result = _run(tmp_path, ReplayExecutor(run_root, exit_code=3))
    assert result["terminal_status"] == "FAILED"
    assert "tool-svf exited with status 3" in result["gaps"]
    assert {status for status, _ in _coverage(run_root, result).values()} == {"unavailable"}
    assert result["record_count"] == 0


def test_timeout_and_missing_image_are_named_gaps(tmp_path: Path) -> None:
    run_root = tmp_path / "a" / "run"
    _r, _s, _e, timed_out = _run(tmp_path / "a", ReplayExecutor(run_root, timed_out=True))
    assert "tool-svf timed out" in timed_out["gaps"]
    run_root = tmp_path / "b" / "run"
    _r, _s, _e, missing = _run(tmp_path / "b", ReplayExecutor(run_root, raise_error=RuntimeError("no image")))
    assert any(gap.startswith("tool-svf image unavailable: RuntimeError: no image") for gap in missing["gaps"])
    assert missing["terminal_status"] == "FAILED"


def test_malformed_or_missing_run_result_is_a_gap_never_clean(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    _r, _s, _e, result = _run(tmp_path, ReplayExecutor(run_root, write_result=False))
    assert "SVF run result was not produced" in result["gaps"]
    assert result["record_count"] == 0

    def envelope(document, _outputs):
        document["schema"] = "something-else"
    run_root = tmp_path / "x" / "run"
    _r, _s, _e, result = _run(tmp_path / "x", ReplayExecutor(run_root, mutate=envelope))
    assert "SVF run result envelope was malformed" in result["gaps"]


def test_module_level_failures_are_unavailable_rows_and_siblings_still_publish(tmp_path: Path) -> None:
    def fail_plugin(document, _outputs):
        plugin = next(m for m in document["modules"] if m["kind"] == "translation_unit")
        plugin.update({"status": "link_failed", "gaps": ["link_failed: duplicate symbol"]})
    run_root = tmp_path / "run"
    _r, _s, _e, result = _run(tmp_path, ReplayExecutor(run_root, mutate=fail_plugin))
    coverage = _coverage(run_root, result)
    assert coverage["svf:cpp:native:native/plugin.c"][0] == "unavailable"
    assert "duplicate symbol" in coverage["svf:cpp:native:native/plugin.c"][1]
    assert coverage["svf:cpp:native:build/app"][0] == "complete"
    assert any(item["path"] == "native/callbacks.c" for item in _entities(run_root, result))


def test_driver_output_over_its_bounds_or_escaping_scratch_is_rejected(tmp_path: Path) -> None:
    def oversized(_document, outputs):
        for output in outputs.values():
            output["sites"] = output["sites"] * 400
    run_root = tmp_path / "run"
    _r, _s, _e, result = _run(tmp_path, ReplayExecutor(run_root, mutate=oversized))
    assert any("exceeded its site or indirect-call bound" in gap for gap in result["gaps"])

    def escape(document, _outputs):
        document["modules"][0]["output"] = "../../outside.json"
    run_root = tmp_path / "e" / "run"
    _r, _s, _e, result = _run(tmp_path / "e", ReplayExecutor(run_root, mutate=escape))
    assert any("escapes the scope scratch" in gap for gap in result["gaps"])


def test_missing_bitcode_and_lossy_debug_info_are_reported_on_the_module(tmp_path: Path) -> None:
    def degrade(document, _outputs):
        app = next(m for m in document["modules"] if m["kind"] == "link")
        app["gaps"] = ["missing_bitcode: compile unit 1 (/target/source/guard.c) did not produce bitcode"]
        app["debug_info_warnings"] = 2
    run_root = tmp_path / "run"
    _r, _s, _e, result = _run(tmp_path, ReplayExecutor(run_root, mutate=degrade))
    status, reason = _coverage(run_root, result)["svf:cpp:native:build/app"]
    assert status == "partial" and "debug_info_upgraded_lossy" in reason and "missing_bitcode" in reason
    app = [item["payload"] for item in _entities(run_root, result) if item["path"] == "native/callbacks.c"]
    assert app and all(p["module_closed_world"] is False and "missing_bitcode" in p["open_world_reasons"] for p in app)


def test_sites_outside_accepted_sources_are_counted_not_published(tmp_path: Path) -> None:
    def system_header(_document, outputs):
        for output in outputs.values():
            output["sites"][0]["file"] = "/usr/include/string.h"
    run_root = tmp_path / "run"
    _r, _s, _e, result = _run(tmp_path, ReplayExecutor(run_root, mutate=system_header))
    assert result["counts"]["outside_accepted_sources"] == 2
    assert all(item["path"].startswith("native/") for item in _entities(run_root, result))


def test_rerun_reuses_the_verified_scope_checkpoint(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    accepted = scope(run_root)
    context = unit(run_root)
    executor = ReplayExecutor(run_root)
    first = _analyze_scope(context, accepted, LINK_COMMANDS, lambda _unit: executor)
    second = _analyze_scope(context, accepted, LINK_COMMANDS, lambda _unit: executor)
    assert len(executor.requests) == 1
    assert second["checkpoint_reused"] is True
    assert second["index_identity"]["sha256"] == first["index_identity"]["sha256"]


# --------------------------------------------------------------------------- configuration


def test_settings_validation_rejects_bad_values() -> None:
    assert _validated_settings(SETTINGS)["max_sites"] == 2000
    with pytest.raises(ValueError, match="enabled"):
        _validated_settings({**SETTINGS, "enabled": "yes"})
    with pytest.raises(ValueError, match="max_pts_size"):
        _validated_settings({**SETTINGS, "max_pts_size": 0})
    with pytest.raises(ValueError, match="andersen_time_limit_seconds"):
        _validated_settings({**SETTINGS, "andersen_time_limit_seconds": 120, "module_timeout_seconds": 120})


def test_topology_validation_matches_central_configuration() -> None:
    def config(steps):
        return SimpleNamespace(config=SimpleNamespace(
            steps={name: None for name in steps}, settings=SETTINGS,
            step=lambda name: SimpleNamespace(tasks={"load": ("accepted_cpp",), "analyze": ("scopes",),
                                                     "acceptance": ("publish_handoff",)}[name])))
    _validate(config(("load", "analyze", "acceptance")), None)
    with pytest.raises(ValueError, match="topology"):
        _validate(config(("load", "acceptance")), None)


def test_central_configuration_declares_the_job_disabled_by_default() -> None:
    import tomllib
    document = tomllib.loads((Path(__file__).parents[1] / "appsec-review.toml").read_text(encoding="utf-8"))
    job = document["jobs"][JOB_ID]
    assert job["settings"]["enabled"] is False
    _validated_settings(job["settings"])
    assert tuple(job["steps"]) == ("load", "analyze", "acceptance")
    built = build_job()
    assert built.job_id == JOB_ID and {item.output_kind for item in built.datasets} >= {"svf_alias_sets"}


# --------------------------------------------------------------------------- memory-object fan-in


def test_each_object_publishes_allocator_and_accessor_fan_in_with_frees_first(tmp_path: Path) -> None:
    run_root, _scope, _executor, result = _run(tmp_path)
    entities = _entities(run_root, result)
    objects = {(item["path"], item["line"]): item["payload"] for item in entities if item["kind"] == "memory_object"
               and item["payload"]["module_kind"] == "link"}
    checked = objects[("native/guard.c", 14)]
    assert checked["schema"] == "appsec-review/svf-memory-object/1"
    assert (checked["kind"], checked["allocator"], checked["allocator_demangled"]) == ("heap", "malloc", "malloc")
    assert checked["allocation"]["in_accepted_source"] is True
    assert [(a["class"], a["line"]) for a in checked["accessors"]] == [("free", 19), ("compare", 16)]
    assert checked["accessor_counts"] == {"free": 1, "write": 0, "read": 0, "compare": 1, "pass": 0}
    assert checked["complete"] is True and checked["truncated"] is False
    written = objects[("native/guard.c", 15)]
    assert [a["class"] for a in written["accessors"]] == ["free", "write"]
    assert result["counts"]["memory_objects"] >= 2
    keys = {item["payload"]["object_key"] for item in entities if item["kind"] == "memory_object"}
    assert "obj:constant:shared" not in keys  # the shared constant object never gets an accessor index

    shard = run_root / result["index_identity"]["relative_path"]
    references = _rows(shard, "SELECT payload_json FROM relations WHERE kind = 'REFERENCES'")
    assert references and all(json.loads(row["payload_json"])["rule"] == "svf-memory-object/1" for row in references)


def test_accessor_and_object_bounds_truncate_with_named_reasons(tmp_path: Path) -> None:
    run_root, _scope, _executor, result = _run(tmp_path / "a", settings={**SETTINGS, "max_accessors_per_object": 1})
    objects = [item["payload"] for item in _entities(run_root, result) if item["kind"] == "memory_object"]
    assert all(len(item["accessors"]) <= 1 for item in objects)
    truncated = [item for item in objects if item["truncated"]]
    assert truncated and all(item["complete"] is False and item["accessor_total"] > 1 for item in truncated)
    assert "accessor bound reached" in _coverage(run_root, result)["svf:cpp:native:build/app"][1]

    run_root, _scope, _executor, result = _run(tmp_path / "b", settings={**SETTINGS, "max_objects_per_module": 1})
    app = [item for item in _entities(run_root, result)
           if item["kind"] == "memory_object" and item["payload"]["module_kind"] == "link"]
    assert len(app) == 1
    assert "memory-object bound reached" in _coverage(run_root, result)["svf:cpp:native:build/app"][1]


def test_accessor_classes_cover_frees_writes_reads_compares_and_passes() -> None:
    from appsec_review.jobs.job_svf_alias_analysis.job import accessor_class
    assert accessor_class({"role": "call_arg", "callee": "_ZdaPv"}) == "free"
    assert accessor_class({"role": "call_arg", "callee": "_ZdlPvm"}) == "free"
    assert accessor_class({"role": "call_arg", "callee": "free"}) == "free"
    assert accessor_class({"role": "call_arg", "callee": "memcpy"}) == "pass"
    assert [accessor_class({"role": role}) for role in ("store", "load", "compare")] == ["write", "read", "compare"]
