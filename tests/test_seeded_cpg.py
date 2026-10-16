"""Seeded Joern/c2cpg, enabled path only (docs/architecture/seeded-neighborhoods.md). No Joern is run."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sqlite3

from appsec_review import seeding
from appsec_review.jobs import cpp_seeded
from appsec_review.jobs.job_cpg_analysis import job as cpg_job
from appsec_review.jobs.job_cpg_analysis import seeded
from tests import seeded_clang_support as sc

UNITS = ("src/net.cpp", "src/util.cpp")


def _unit(staged, *, seeded_settings=sc.SEEDED):
    unit = staged.unit("generate.scopes", {}, seeded=seeded_settings, job_id="job_cpg_analysis")
    unit.job.config.settings.update(sc.CPG_SETTINGS)
    return unit


def _run(staged, executor, *, seeded_settings=sc.SEEDED, unit=None):
    unit = unit or _unit(staged, seeded_settings=seeded_settings)
    scope = sc.index_scope(staged)
    settings = cpp_seeded.settings_of(unit)
    plan = cpp_seeded.plan_for(unit, [scope], settings) if settings.seeded else None
    run = None if plan is None else seeded.Run(settings, plan, plan.for_scope(sc.CASE))
    return cpg_job._generate(unit, scope, lambda _u: executor, run), unit


def _coverage(staged, result) -> list[tuple]:
    path = staged.run_root / result["index_identity"]["relative_path"]
    return sqlite3.connect(path).execute("select status from coverage").fetchall()


def test_c2cpg_reads_only_the_seeded_units_never_the_whole_program(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.CpgExecutor(staged.run_root)
    result, _ = _run(staged, executor)
    assert len(staged.rows) == 12
    assert [files for files, _argv in executor.calls] == [UNITS]
    argv = executor.calls[0][1]
    regex = argv[argv.index("--exclude-regex") + 1]
    assert result["analyzed_files"] == list(UNITS)
    # The exclusion keeps exactly the selected sources and skips every other C/C++ file.
    every = [row["file"].removeprefix("/scratch/source/").removeprefix("/target/source/") for row in staged.rows]
    assert sorted(name for name in every if not re.match(regex, "/target/source/" + name)) == list(UNITS)
    record = result["index_identity"]["producer"]["seeded"]
    assert record["resolved_seed_count"] == 2 and record["status_counts"] == {"resolved": 2}
    # The export gives a neighborhood, never the program: coverage is partial and the limits are named.
    assert _coverage(staged, result) == [("partial",)] and seeded.EXPORT_SCOPE_GAP in result["gaps"]
    assert seeded.NO_EXPORT_GAP not in result["gaps"]
    assert [call[0] for call in executor.exports] == ["/opt/joern/joern-cli/joern-export"]


def test_zero_seeds_runs_no_container_and_names_the_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[])
    executor = sc.CpgExecutor(staged.run_root)
    result, _ = _run(staged, executor)
    assert executor.calls == []
    assert result["gaps"][0] == seeding.NO_SEEDS_GAP or seeding.NO_SEEDS_GAP in result["gaps"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["cpg"] is None
    assert result["index_identity"]["producer"]["seeded"]["skipped"] is True
    assert _coverage(staged, result) != [("complete",)]


def test_a_failed_build_is_a_gap_on_every_seed_and_is_not_checkpointed(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.CpgExecutor(staged.run_root, exit_code=3)
    result, unit = _run(staged, executor)
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {entry["status"] for entry in ledger} == {"unresolved"} and {entry["reason"] for entry in ledger} == {"producer_failed"}
    assert any("exited with status 3" in gap for gap in result["gaps"])
    _run(staged, executor, unit=unit)
    assert len(executor.calls) == 2


def test_identity_resumes_per_producer_and_changes_with_mode_depth_limit_and_seed_set(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.CpgExecutor(staged.run_root)
    _run(staged, executor)
    _run(staged, executor)
    assert len(executor.calls) == 1
    for override in ({"depth": 2}, {"seed_limit": 3}, {"unit_limit": 1}):
        _run(staged, executor, seeded_settings={**sc.SEEDED, **override})
    assert len(executor.calls) == 4
    _run(staged, executor, seeded_settings=None)
    assert len(executor.calls[-1][0]) == 12
    other = sc.stage(tmp_path / "other", observations=[sc.observation("proj/src/util.cpp", 14)])
    other_executor = sc.CpgExecutor(other.run_root)
    _run(other, other_executor)
    assert [files for files, _ in other_executor.calls] == [UNITS[1:]]


def test_shards_are_byte_identical_across_runs(tmp_path: Path) -> None:
    outputs = []
    for name in ("a", "b"):
        staged = sc.stage(tmp_path / name)
        result, _ = _run(staged, sc.CpgExecutor(staged.run_root))
        outputs.append((result["index_identity"]["sha256"], result["index_identity"]["producer"]["seeded"],
                        result["ledger"]["sha256"]))
    assert outputs[0] == outputs[1]


def test_unit_limit_is_a_named_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    result, _ = _run(staged, sc.CpgExecutor(staged.run_root), seeded_settings={**sc.SEEDED, "unit_limit": 1})
    assert any(gap.startswith("unit_limit_reached") for gap in result["gaps"])


def test_the_disabled_path_is_unchanged_and_runs_no_container(monkeypatch, tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.CpgExecutor(staged.run_root)
    scope = sc.index_scope(staged)
    unit = staged.unit("generate.scopes", {"load.accepted_cpp": {"scopes": [scope.as_dict()]}},
                       seeded=sc.SEEDED, job_id="job_cpg_analysis")
    unit.job.config.settings.update({**sc.CPG_SETTINGS, "enabled": False})
    job = cpg_job.build_job(executor_factory=lambda _u: executor)
    handler = next(item for item in job.units if item.unit_id == "generate.scopes").handler
    monkeypatch.setattr(cpg_job, "accepted_cpp_scopes", lambda _root: ({"handoff": {}}, [scope], {}))
    result = handler(unit)
    assert executor.calls == [] and result["scopes"] == [] and result["disabled"] == [sc.CASE]
    assert result["gaps"] == [f"{sc.CASE}: {cpg_job.JOERN_DISABLED}"]


def _functions(staged, result) -> dict[str, dict]:
    path = staged.run_root / result["index_identity"]["relative_path"]
    rows = sqlite3.connect(path).execute("select name, payload_json from entities where kind = 'ast_node'").fetchall()
    return {name: json.loads(payload) for name, payload in rows}


def test_the_export_is_published_as_bounded_function_rows(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    result, _ = _run(staged, sc.CpgExecutor(staged.run_root))
    functions = _functions(staged, result)
    assert {"handle_packet", "log_event", "clamp_len", "checked_len", "copy_field"} <= set(functions)
    copy = functions["copy_field"]
    assert copy["fact"] == "cpg" and copy["path"] == "src/util.cpp" and (copy["line"], copy["line_end"]) == (11, 16)
    assert [call["name"] for call in copy["calls"]] == ["checked_len", "memcpy"]
    assert [item["condition"] for item in copy["branches"]] == ["src == nullptr"]
    assert functions["clamp_len"]["branches"][1] == {"kind": "IF", "line": 5, "code": "if (n > 64) return 64;",
                                                     "condition": "n > 64"}
    # Joern did not resolve this callee (it lives in another unit): the row says so rather than guessing.
    assert next(call for call in functions["handle_packet"]["calls"] if call["name"] == "copy_field")["callee_resolved"] is False
    assert copy["reaching_def_edges"] > 0
    assert result["cpg_export_function_count"] == len(functions) and result["cpg_export"]["sha256"]
    # The raw CSV tree is not retained; the c2cpg receipt is untouched by the export's own scratch.
    assert any("cpg_calls_name_matched" in gap for gap in result["gaps"]) and any("cpg_no_cfg_edges" in gap for gap in result["gaps"])


def test_a_failed_export_is_a_named_gap_and_publishes_no_function_rows(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    result, _ = _run(staged, sc.CpgExecutor(staged.run_root, export_exit_code=4))
    assert result["cpg"] is not None and result["cpg_export"] is None
    assert any("Joern export exited with status 4" in gap for gap in result["gaps"])
    assert seeded.NO_EXPORT_GAP in result["gaps"] and seeded.EXPORT_SCOPE_GAP not in result["gaps"]
    assert _functions(staged, result) == {} and _coverage(staged, result) == [("unavailable",)]
