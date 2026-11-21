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


@pytest.mark.parametrize("largest", [
    "max_module_bitcode_bytes", "max_module_output_bytes", "max_output_bytes",
], ids=["bitcode", "module-json", "run-json"])
def test_process_file_limit_admits_each_configured_artifact_bound(tmp_path: Path, largest: str) -> None:
    settings = {**SETTINGS, "max_module_bitcode_bytes": 100000,
                "max_module_output_bytes": 100000, "max_output_bytes": 100000, largest: 200000}
    _, _, executor, _ = _run(tmp_path, settings=settings)
    assert executor.requests[0].file_size_limit_bytes == 200001


@pytest.mark.parametrize("cause", ["truncated", "pointer_not_modeled", "unknown_object"])
def test_omitted_points_to_accessors_cannot_publish_complete_objects(tmp_path: Path, cause: str) -> None:
    """Inert emitter-shaped mutations, not newly recorded native SVF output."""
    def omit_free(document, outputs):
        app = next(m for m in document["modules"] if m["kind"] == "link")
        output = outputs[app["module_id"]]
        freed = next(s for s in output["sites"] if s.get("callee") == "free" and s["line"] == 19)
        if cause == "truncated":
            freed["points_to"] = ["obj:constant:shared"]
            freed["truncated"] = True
        else:
            freed["points_to"] = []
            freed["incomplete_reasons"] = [cause]
    root = tmp_path / "run"
    _, _, _, result = _run(tmp_path, ReplayExecutor(root, mutate=omit_free),
                           settings={**SETTINGS, "max_pts_size": 1})
    obj = next(item["payload"] for item in _entities(root, result)
               if item["kind"] == "memory_object" and item["path"] == "native/guard.c" and item["line"] == 14)
    assert obj["accessor_counts"]["free"] == 0
    assert obj["complete"] is False
    assert obj["incomplete_reasons"]
    assert _coverage(root, result)["svf:cpp:native:build/app"][0] == "partial"
    assert any(("points-to" if cause == "truncated" else cause) in gap for gap in result["gaps"])


def test_truncated_indirect_targets_are_partial_module_coverage(tmp_path: Path) -> None:
    def truncate(_document, outputs):
        call = next(output["indirect_calls"][0] for output in outputs.values()
                    if output["module"]["open_world_reasons"] == [])
        call["targets"] = call["targets"][:1]
        call["truncated"] = True
    root = tmp_path / "run"
    _, _, _, result = _run(tmp_path, ReplayExecutor(root, mutate=truncate))
    assert _coverage(root, result)["svf:cpp:native:build/app"][0] == "partial"
    assert any("target" in gap for gap in result["gaps"])


@pytest.mark.parametrize("artifact_name", [
    "result.json", "alias.json", "plan.json", "compile_commands.json", "execution.json", "stdout.bin", "stderr.bin",
], ids=["result", "driver", "plan", "compile-db", "receipt", "stdout", "stderr"])
@pytest.mark.parametrize("damage", ["delete", "alter", "symlink"])
def test_scope_checkpoint_rejects_damaged_parser_evidence(tmp_path: Path, artifact_name: str, damage: str) -> None:
    from appsec_review.jobs.cpp_index_scopes import CheckpointIntegrityError
    root, accepted, executor, _ = _run(tmp_path)
    scratch = executor.requests[0].scratch_root
    evidence = next(scratch.rglob(artifact_name))
    original = evidence.read_bytes()
    evidence.unlink()
    if damage == "alter":
        evidence.write_bytes(original + b" ")
    elif damage == "symlink":
        replacement = scratch / "replacement"
        replacement.write_bytes(original)
        evidence.symlink_to(replacement)
    with pytest.raises(CheckpointIntegrityError):
        _analyze_scope(unit(root), accepted, LINK_COMMANDS, lambda _unit: executor)
    assert len(executor.requests) == 1


def test_changed_scope_identity_preserves_prior_raw_evidence(tmp_path: Path) -> None:
    root, accepted, executor, _ = _run(tmp_path)
    first_scratch = executor.requests[0].scratch_root
    pinned = {path: path.read_bytes() for path in first_scratch.rglob("*") if path.is_file()}
    _analyze_scope(unit(root, {**SETTINGS, "max_pts_size": 63}), accepted, LINK_COMMANDS, lambda _unit: executor)
    assert len(executor.requests) == 2
    assert executor.requests[1].scratch_root != first_scratch
    assert all(path.read_bytes() == data for path, data in pinned.items())


@pytest.mark.parametrize("signal", ["stop", "interrupt"])
def test_scope_control_flow_is_not_converted_into_a_module_gap(tmp_path: Path, signal: str) -> None:
    from appsec_review.runtime.execution_safety import ReviewStopped
    error = ReviewStopped if signal == "stop" else KeyboardInterrupt
    root = tmp_path / "run"
    with pytest.raises(error):
        _run(tmp_path, ReplayExecutor(root, raise_error=error()))
    assert not list((root / "data" / "svf").rglob("checkpoint.json"))


@pytest.mark.parametrize("mutation", [
    "target-string", "target-name", "target-count", "target-boolean-count", "target-missing-flag",
    "target-flag", "object-string", "object-location", "object-field", "missing-object",
    "point-key", "site-role", "site-operand", "site-flag", "site-reasons", "module-reasons",
    "module-externals", "global-flag", "andersen-incomplete",
])
def test_malformed_driver_module_is_unavailable_without_losing_sibling(tmp_path: Path, mutation: str) -> None:
    """Mutations model malformed external JSON; the parser/normalizer are real."""
    def malformed(document, outputs):
        app = next(m for m in document["modules"] if m["kind"] == "link")
        output = outputs[app["module_id"]]
        call, site = output["indirect_calls"][0], output["sites"][0]
        key = site["points_to"][0]
        if mutation == "target-string":
            call["targets"] = ["copy_handler"]
        elif mutation == "target-name":
            call["targets"][0]["name"] = {}
        elif mutation == "target-count":
            call["target_count"] = 3
        elif mutation == "target-boolean-count":
            call["target_count"] = True
        elif mutation == "target-missing-flag":
            del call["truncated"]
        elif mutation == "target-flag":
            call["truncated"] = "false"
        elif mutation == "object-string":
            output["objects"][key] = "not an object"
        elif mutation == "object-location":
            output["objects"][key]["location"] = "not a location"
        elif mutation == "object-field":
            output["objects"][key]["field"] = []
        elif mutation == "missing-object":
            del output["objects"][key]
        elif mutation == "point-key":
            site["points_to"] = [{}]
        elif mutation == "site-role":
            site["role"] = []
        elif mutation == "site-operand":
            site["operand"] = {}
        elif mutation == "site-flag":
            site["truncated"] = "false"
        elif mutation == "site-reasons":
            site["incomplete_reasons"] = [{}]
        elif mutation == "module-reasons":
            output["module"]["open_world_reasons"] = [{}]
        elif mutation == "module-externals":
            output["module"]["unmodeled_externals"] = None
        elif mutation == "global-flag":
            output["sites_truncated"] = "false"
        else:
            output["andersen"]["completed"] = False
    root = tmp_path / "run"
    _, _, _, result = _run(tmp_path, ReplayExecutor(root, mutate=malformed))
    coverage = _coverage(root, result)
    assert coverage["svf:cpp:native:build/app"][0] == "unavailable"
    assert coverage["svf:cpp:native:native/plugin.c"][0] == "partial"
    assert result["counts"]["analyzed"] == 1
    assert all(item["payload"]["module_kind"] != "link" for item in _entities(root, result))
    assert any("malformed" in gap or "incomplete" in gap for gap in result["gaps"])


@pytest.mark.parametrize("mutation", ["gaps", "debug-count", "duplicate-module", "compile-section", "compile-produced"])
def test_malformed_run_nested_sections_are_named_gaps(tmp_path: Path, mutation: str) -> None:
    def malformed(document, _outputs):
        if mutation == "gaps":
            document["modules"][0]["gaps"] = None
        elif mutation == "debug-count":
            document["modules"][0]["debug_info_warnings"] = "bad"
        elif mutation == "duplicate-module":
            document["modules"].append(dict(document["modules"][0]))
        elif mutation == "compile-section":
            document["compile"] = None
        else:
            document["compile"][0]["produced"] = "false"
    root = tmp_path / "run"
    _, _, _, result = _run(tmp_path, ReplayExecutor(root, mutate=malformed))
    assert result["terminal_status"] != "SUCCEEDED"
    assert any("malformed" in gap or "duplicate" in gap for gap in result["gaps"])


@pytest.mark.parametrize(("mode", "expected"), [
    ("open-world", "COMPLETED_WITH_GAPS"), ("missing", "FAILED"), ("failed", "FAILED"),
], ids=["partial", "missing", "failed"])
def test_nested_scope_outcomes_reach_real_aggregate_publication(monkeypatch, tmp_path: Path, mode: str,
                                                              expected: str) -> None:
    from types import MappingProxyType
    from appsec_review.runtime import UnitContext
    from appsec_review.retrieval import write_manifest
    import appsec_review.jobs.job_svf_alias_analysis.job as module

    root = tmp_path / "run"
    accepted = scope(root)
    context = unit(root)
    # Freeze an empty upstream index set; actual publication composes the produced SVF shard.
    manifest_path = root / "manifest.json"
    context.job.run_id = root.name
    write_manifest(manifest_path, run_id=root.name, target_snapshot=context.job.source_fingerprint,
                   target_root=context.job.target_root, indexes=[])
    context.job.input_manifest_path = manifest_path
    context.job.input_manifest_sha256 = file_sha256(manifest_path)
    upstream = {"handoff": {"source_fingerprint": context.job.source_fingerprint}, "handoff_sha256": "e" * 64,
                "manifest": {"path": "manifest.json", "sha256": file_sha256(manifest_path),
                             "size_bytes": manifest_path.stat().st_size},
                "result": {"outputs": {"catalog.projects": {"projects": {
                    accepted.case_id: {"link_commands": LINK_COMMANDS}}}}}}
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: (upstream, [accepted], {}))

    def mutate(document, _outputs):
        if mode == "missing":
            document["modules"] = []
        elif mode == "failed":
            for outcome in document["modules"]:
                outcome.update(status="analysis_failed", gaps=["inert tool failure"])
    executor = ReplayExecutor(root, mutate=mutate)
    outputs = {}
    for task in build_job(executor_factory=lambda _unit: executor).units:
        step, name = task.unit_id.split(".")
        task_root = context.unit_root / step / name
        task_root.mkdir(parents=True, exist_ok=True)
        outputs[task.unit_id] = task.handler(UnitContext(
            context.job, task.unit_id, step, name, task_root, MappingProxyType(outputs)))
    analyzed, published = outputs["analyze.scopes"], outputs["acceptance.publish_handoff"]
    assert analyzed["terminal_status"] == published["terminal_status"] == expected
    assert published["gaps"] and published["counts"]["gap_count"] == len(published["gaps"])
    assert published["item_count"] > 0 if mode == "open-world" else published["item_count"] == 0
    assert all(cause in " ".join(published["gaps"])
               for _, reason in _coverage(root, analyzed["scopes"][0]).values() if reason
               for cause in reason.split("; "))


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
    document = tomllib.loads((Path(__file__).resolve().parents[3] / "appsec-review.toml").read_text(encoding="utf-8"))
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


def test_central_configuration_ships_the_design_tunables() -> None:
    """The depth and fan-in/fan-out tunables in appsec-review.toml equal design section 7.1."""
    import re
    import tomllib
    root = Path(__file__).resolve().parents[3]
    document = tomllib.loads((root / "appsec-review.toml").read_text(encoding="utf-8"))
    design = (root / "docs" / "architecture" / "svf-alias-producer.md").read_text(encoding="utf-8")
    table = design.split("### 7.1 Tunables", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| `(\w+)` \| `([\w.]+)` \| [^|]+ \| (\d+) \|", table, flags=re.M)
    assert {name for name, _table, _value in rows} == {
        "max_accessors_per_object", "max_objects_per_module", "max_memory_context_entries", "max_callers",
        "caller_depth"}
    for name, location, value in rows:
        settings = document
        for part in location.split("."):
            settings = settings[part]
        assert settings[name] == int(value), (location, name)


def test_planning_edge_cases_and_driver_document_validation(tmp_path: Path) -> None:
    from appsec_review.jobs.job_svf_alias_analysis.job import (
        DRIVER_SCHEMA,
        _Sources,
        _module_records,
        _read_bounded_json,
        _valid_driver_document,
    )
    from appsec_review.jobs.job_svf_alias_analysis.planning import PlannedModule

    # Compile row without output_path + link command with zero resolved compile units
    plan = plan_modules(
        [{"target_path": "src/no_obj.c", "output_path": None}],
        [{"output_path": "build/empty_app", "input_paths": ["build/missing.o"]}],
        max_modules=4,
    )
    assert [m.label for m in plan.modules] == ["src/no_obj.c"]

    # _read_bounded_json oversize + malformed JSON
    oversize = tmp_path / "big.json"
    oversize.write_text("x" * 100, encoding="utf-8")
    assert _read_bounded_json(oversize, 20, "test doc") == (None, "test doc exceeded the 20-byte bound")
    malformed = tmp_path / "bad.json"
    malformed.write_text("{bad", encoding="utf-8")
    assert _read_bounded_json(malformed, 200, "test doc") == (None, "test doc was malformed JSON")

    # _Sources.point edge cases
    acc_scope = scope(tmp_path / "src_run")
    srcs = _Sources(acc_scope)
    assert srcs.point(None, 1, 1) is None
    assert srcs.point("/target/source/guard.c", 0, 1) is None
    assert srcs.point("/target/source/guard.c", 9999, 1) is None
    col0 = srcs.point("/target/source/guard.c", 1, 0)
    assert col0 is not None and col0.ambiguous is True

    # _valid_driver_document rejection cases
    assert _valid_driver_document("bad", SETTINGS) == "analysis output envelope was malformed"
    assert _valid_driver_document({"schema": DRIVER_SCHEMA}, SETTINGS) == "analysis output sections were malformed"
    assert _valid_driver_document(
        {"schema": DRIVER_SCHEMA, "module": {}, "sites": [], "indirect_calls": [], "objects": {}},
        SETTINGS,
    ) == "analysis output module block was malformed"
    assert _valid_driver_document(
        {
            "schema": DRIVER_SCHEMA,
            "module": {"open_world_reasons": []},
            "sites": [{"role": "invalid"}],
            "indirect_calls": [],
            "objects": {},
        },
        SETTINGS,
    ) == "analysis output contained a malformed pointer site"
    assert _valid_driver_document(
        {
            "schema": DRIVER_SCHEMA,
            "module": {"open_world_reasons": []},
            "sites": [],
            "indirect_calls": [{"targets": "bad"}],
            "objects": {},
        },
        SETTINGS,
    ) == "analysis output contained a malformed indirect call"

    # _module_records: translation_unit without pre-existing not_in_link_unit, unmapped indirect call, truncation flags
    tu_mod = PlannedModule("m-tu", MODULE_TRANSLATION_UNIT, "native/guard.c", (0,), ())
    recs, counts, reasons = _module_records(
        acc_scope,
        srcs,
        tu_mod,
        {},
        {
            "schema": DRIVER_SCHEMA,
            "module": {"open_world_reasons": []},
            "sites": [],
            "indirect_calls": [{"file": "/usr/include/ext.h", "line": 1, "column": 1, "targets": []}],
            "objects": {},
            "sites_truncated": True,
            "indirect_calls_truncated": True,
        },
        "3.3.0",
    )
    assert recs == [] and counts["outside_accepted_sources"] == 1
    assert any("pointer-site bound reached" in r for r in reasons)
    assert any("indirect-call bound reached" in r for r in reasons)
    assert any("not_in_link_unit" in r for r in reasons)


def test_compile_unit_failures_empty_scope_and_build_job_pipeline(monkeypatch, tmp_path: Path) -> None:
    from types import MappingProxyType
    from appsec_review.jobs.cpp_index_scopes import IndexScope
    from appsec_review.jobs.engineering_contracts import SVF_ALIAS_HANDOFF_SCHEMA
    import appsec_review.jobs.job_svf_alias_analysis.job as module
    from appsec_review.runtime import UnitContext

    # 1. Compile unit failures (with and without timeout) recorded in gaps
    def add_compile_failures(document, _outputs):
        document["compile"] = [
            {"index": 0, "file": "/target/source/a.c", "produced": False, "timeout": False},
            {"index": 1, "file": "/target/source/b.c", "produced": False, "timeout": True},
        ]

    run_root_cf = tmp_path / "cf" / "run"
    _r, _s, _e, res_cf = _run(tmp_path / "cf", ReplayExecutor(run_root_cf, mutate=add_compile_failures))
    assert any("compile unit 0 (/target/source/a.c) did not produce bitcode" in g for g in res_cf["gaps"])
    assert any("compile unit 1 (/target/source/b.c) did not produce bitcode (timed out)" in g for g in res_cf["gaps"])

    # 2. Scope with zero supported compile commands directly in _analyze_scope
    base_scope = scope(tmp_path / "empty_scope" / "run")
    asm_scope = IndexScope(
        scope_id="cpp-scope-asm",
        case_id="case-asm",
        project_id="cpp:asm",
        root="asm",
        case_snapshot=base_scope.case_snapshot,
        case_root=base_scope.case_root,
        files=base_scope.files,
        compile_commands=({"target_path": "asm/start.S", "arguments": ["clang-18", "/scratch/source/start.S"]},),
        compile_database=base_scope.compile_database,
        _by_relative=base_scope._by_relative,
    )
    empty_ctx = unit(tmp_path / "empty_scope" / "run")
    empty_res = _analyze_scope(empty_ctx, asm_scope, [], lambda _u: ReplayExecutor(tmp_path / "empty_scope" / "run"))
    assert "no compile units to analyze" in empty_res["gaps"]
    assert empty_res["terminal_status"] == "COMPLETED_WITH_GAPS"

    # 3. Full build_job units: load.accepted_cpp -> analyze.scopes -> acceptance.publish_handoff
    pipe_root = tmp_path / "pipe" / "run"
    pipe_scope = scope(pipe_root)
    pipe_ctx = unit(pipe_root)
    accepted_payload = {
        "handoff": {"source_fingerprint": pipe_ctx.job.source_fingerprint},
        "handoff_sha256": "e" * 64,
        "manifest": {"path": "manifest.json"},
        "result": {
            "outputs": {
                "catalog.projects": {
                    "projects": {pipe_scope.case_id: {"link_commands": LINK_COMMANDS}}
                }
            }
        },
    }
    executor = ReplayExecutor(pipe_root)
    job = build_job(executor_factory=lambda _u: executor)
    load_fn = next(u.handler for u in job.units if u.unit_id == "load.accepted_cpp")
    analyze_fn = next(u.handler for u in job.units if u.unit_id == "analyze.scopes")
    publish_fn = next(u.handler for u in job.units if u.unit_id == "acceptance.publish_handoff")

    # Snapshot mismatch rejected
    monkeypatch.setattr(
        module,
        "accepted_cpp_scopes",
        lambda _r: ({**accepted_payload, "handoff": {"source_fingerprint": "0" * 64}}, [pipe_scope], {}),
    )
    with pytest.raises(ValueError, match="target snapshot differs"):
        load_fn(pipe_ctx)

    # Valid load
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _r: (accepted_payload, [pipe_scope, asm_scope], {}))
    loaded = load_fn(pipe_ctx)
    assert loaded["upstream"]["handoff_sha256"] == "e" * 64
    assert len(loaded["scopes"]) == 2

    # Scope set mismatch rejected
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _r: (accepted_payload, [pipe_scope], {}))
    analyze_ctx = UnitContext(
        pipe_ctx.job, "analyze.scopes", "analyze", "scopes", pipe_ctx.unit_root,
        MappingProxyType({"load.accepted_cpp": loaded}),
    )
    with pytest.raises(ValueError, match="scopes changed between load and analysis"):
        analyze_fn(analyze_ctx)

    # NOT_APPLICABLE when no runnable scopes and no unavailable scopes
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _r: (accepted_payload, [asm_scope], {}))
    na_ctx = UnitContext(
        pipe_ctx.job, "analyze.scopes", "analyze", "scopes", pipe_ctx.unit_root,
        MappingProxyType({"load.accepted_cpp": {"scopes": [asm_scope.as_dict()]}}),
    )
    na_res = analyze_fn(na_ctx)
    assert na_res["terminal_status"] == "NOT_APPLICABLE"
    assert na_res["not_applicable_scopes"][0]["terminal_status"] == "SKIPPED_NA"

    # Runnable + unavailable scopes -> COMPLETED_WITH_GAPS + publish_handoff
    unavail = {"case-missing": "accepted C++ project has no compile commands"}
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _r: (accepted_payload, [pipe_scope, asm_scope], unavail))
    analyzed = analyze_fn(analyze_ctx)
    assert analyzed["scope_count"] == 1
    assert analyzed["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("case-missing:" in g for g in analyzed["gaps"])

    manifest_file = pipe_root / "manifest.json"
    manifest_file.write_text("{}", encoding="utf-8")
    manifest_id = {"path": "manifest.json", "sha256": file_sha256(manifest_file), "size_bytes": 2}
    monkeypatch.setattr(module, "publish_scope_indexes", lambda *_a, **_kw: manifest_id)
    pub_ctx = UnitContext(
        pipe_ctx.job, "acceptance.publish_handoff", "acceptance", "publish_handoff", pipe_ctx.unit_root,
        MappingProxyType({"load.accepted_cpp": {**loaded, "unavailable": unavail}, "analyze.scopes": analyzed}),
    )
    published = publish_fn(pub_ctx)
    assert published["schema"] == SVF_ALIAS_HANDOFF_SCHEMA
    assert published["counts"]["scopes"] == 1
    assert published["counts"]["modules"] == 2
    assert published["counts"]["closed_world_modules"] == 1
    summary_path = pipe_root / published["artifact"]["path"]
    assert summary_path.is_file() and file_sha256(summary_path) == published["artifact"]["sha256"]
