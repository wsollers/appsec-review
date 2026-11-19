"""Seeded Clang-Tidy and Clang Static Analyzer (docs/architecture/seeded-neighborhoods.md 5-8)."""
from __future__ import annotations

import json
import hashlib
from copy import deepcopy
from pathlib import Path
import sqlite3

import pytest

from appsec_review import seeding
from appsec_review.jobs.job_clang_static_analysis import job as static_job
from appsec_review.jobs.job_clang_static_analysis import seeded
from tests import seeded_clang_support as sc

UNITS = ("src/net.cpp", "src/util.cpp")


def _unit(staged, *, seeded_settings=sc.SEEDED):
    unit = staged.unit("analyze.scopes", {}, seeded=seeded_settings, job_id="job_clang_static_analysis")
    unit.job.config.settings.update(sc.STATIC_SETTINGS)
    return unit


def _hood(staged, executor=None):
    """The neighborhood the seeded IR job publishes for the same project (the real handler, recorded IR)."""
    from appsec_review.jobs.job_cpp_compiled_analysis import build_job

    ir_executor = executor or sc.FixtureExecutor(staged.run_root)
    unit = staged.unit("ir.projects", {"catalog.projects": {"projects": {sc.CASE: staged.cataloged}}})
    ir = next(item for item in build_job(executor_factory=lambda _u: ir_executor).units
              if item.unit_id == "ir.projects").handler(unit)
    return {"result": {"outputs": {"ir.projects": ir}}}


def _run(staged, executor, *, accepted=None, seeded_settings=sc.SEEDED, unit=None):
    unit = unit or _unit(staged, seeded_settings=seeded_settings)
    scope = sc.index_scope(staged)
    plan = seeded.plan_for(unit, [scope], seeded.settings_of(unit)) if seeded.settings_of(unit).seeded else None
    run = None if plan is None else seeded.Run(seeded.settings_of(unit), plan, plan.for_scope(sc.CASE),
                                               seeded.neighborhood_of(accepted or {}, sc.CASE))
    return static_job._analyze_scope(unit, scope, lambda _u: executor, run), unit


def _observations(staged, result) -> list[dict]:
    path = staged.run_root / result["index_identity"]["relative_path"]
    return [json.loads(row[5]) | {"_path": json.loads(row[5]).get("path")} for row in
            sqlite3.connect(path).execute("select * from entities where kind = 'tool_observation'")]


HEADER_SEED = ("include/util.h", 3, 3)
HEADER_SOURCE = b"#pragma once\ninline int shared(int value) {\n  return value;\n}\n"
HEADER_IR = """define linkonce_odr i32 @_Z6sharedi(i32 %value) !dbg !1 {
entry:
  ret i32 %value, !dbg !3
}
!1 = distinct !DISubprogram(name: "shared", linkageName: "_Z6sharedi", file: !2, line: 2)
!2 = !DIFile(filename: "include/util.h", directory: "/scratch/source")
!3 = !DILocation(line: 3, column: 3, scope: !1)
"""


def _header_hood(tmp_path, *, varying_ranges=False):
    """Two compiler modules defining the same physical header function, through the real producer."""
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/include/util.h", 3)])
    for path in (staged.target / "proj/include/util.h", staged.case_root / "source/include/util.h"):
        path.write_bytes(HEADER_SOURCE)
    record = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/include/util.h")
    record["sha256"] = hashlib.sha256(HEADER_SOURCE).hexdigest()
    staged.rows[:] = [row for row in staged.rows if Path(row["file"]).stem in {"net", "util"}]
    database = staged.case_root / "normalized-compile-commands.json"
    database.write_text(json.dumps(staged.rows), encoding="utf-8")
    staged.cataloged["compile_database"].update(
        sha256=hashlib.sha256(database.read_bytes()).hexdigest(), size_bytes=database.stat().st_size)

    class HeaderExecutor(sc.FixtureExecutor):
        def execute(self, request):
            result = super().execute(request)
            if request.argv[1] == "ir":
                for index, path in enumerate(sorted((request.scratch_root / "analysis/ir").glob("tu-*.ll"))):
                    text = HEADER_IR.replace("line: 3, column", "line: 4, column") if varying_ranges and index else HEADER_IR
                    path.write_text(text, encoding="utf-8")
            return result

    accepted = _hood(staged, HeaderExecutor(staged.run_root))
    handoff = _ir_handoff(accepted)
    assert len(handoff["seed_functions"]) == len(handoff["ranges"]) == 2
    assert {row[:3] for row in map(tuple, handoff["seed_functions"])} == {HEADER_SEED}
    seeds = seeding.ScopeSeeds(sc.CASE, (seeding.Seed(*HEADER_SEED),), total=1)
    return staged, accepted, seeds


def _ir_handoff(accepted):
    return accepted["result"]["outputs"]["ir.projects"]["projects"][sc.CASE]["handoff"]


def test_header_seed_keeps_every_producer_identity_and_its_association(tmp_path):
    _, accepted, seeds = _header_hood(tmp_path)
    hood = seeded.neighborhood_of(accepted, sc.CASE)
    placement = seeded.classify("include/util.h", 2, seeds, hood)
    assert placement["label"] == seeded.IN_SEED_FUNCTION
    assert placement["seeds"] == [list(HEADER_SEED)]
    assert hood.seed_functions[HEADER_SEED] == tuple(sorted(_ir_handoff(accepted)["ranges"]))
    assert placement["function"] is None
    assert placement["function_candidates"] == sorted(_ir_handoff(accepted)["ranges"])
    assert placement["function_ambiguity"] == "multiple_innermost_functions_without_translation_unit"


def test_partial_seed_association_is_qualified_without_an_arbitrary_function(tmp_path):
    _, accepted, seeds = _header_hood(tmp_path)
    handoff = _ir_handoff(accepted)
    handoff["seed_functions"] = handoff["seed_functions"][:1]
    hood = seeded.neighborhood_of(accepted, sc.CASE)
    placement = seeded.classify("include/util.h", 2, seeds, hood)
    assert placement["label"] == seeded.IN_NEIGHBORHOOD
    assert placement["function"] is None and placement["seeds"] == []
    assert placement["candidate_seeds"] == [list(HEADER_SEED)]
    assert placement["function_candidates"] == sorted(handoff["ranges"])
    at_seed = seeded.classify("include/util.h", 3, seeds, hood)
    assert at_seed["label"] == seeded.AT_SEED and at_seed["seeds"] == [list(HEADER_SEED)]
    assert at_seed["function"] is None


def test_different_tu_range_widths_do_not_select_a_translation_unit(tmp_path):
    _, accepted, seeds = _header_hood(tmp_path, varying_ranges=True)
    hood = seeded.neighborhood_of(accepted, sc.CASE)
    placement = seeded.classify("include/util.h", 2, seeds, hood)
    assert placement["function"] is None
    assert placement["function_candidates"] == sorted(_ir_handoff(accepted)["ranges"])
    assert placement["label"] == seeded.IN_SEED_FUNCTION and placement["seeds"] == [list(HEADER_SEED)]


def test_header_membership_hash_keeps_all_identities_but_not_row_order(tmp_path):
    _, accepted, _ = _header_hood(tmp_path)
    original = seeded.neighborhood_of(accepted, sc.CASE).sha256()
    reordered = deepcopy(accepted)
    rows = _ir_handoff(reordered)["seed_functions"]
    rows[:] = list(reversed(rows)) + rows[:1]
    assert seeded.neighborhood_of(reordered, sc.CASE).sha256() == original
    for position in range(2):
        partial = deepcopy(accepted)
        _ir_handoff(partial)["seed_functions"].pop(position)
        assert seeded.neighborhood_of(partial, sc.CASE).sha256() != original
    changed_depth = deepcopy(accepted)
    neighborhood = _ir_handoff(changed_depth)["neighborhood"]
    first = sorted(neighborhood)[0]
    neighborhood[first] += 1
    assert seeded.neighborhood_of(changed_depth, sc.CASE).sha256() != original


def test_legacy_single_function_handoff_keeps_unambiguous_placement():
    handoff = {"ranges": {"shared": ["include/util.h", 2, 4]}, "neighborhood": {"shared": 0},
               "seed_functions": [[*HEADER_SEED, "shared"]]}
    accepted = {"result": {"outputs": {"ir.projects": {"projects": {sc.CASE: {"handoff": handoff}}}}}}
    hood = seeded.neighborhood_of(accepted, sc.CASE)
    seeds = seeding.ScopeSeeds(sc.CASE, (seeding.Seed(*HEADER_SEED),), total=1)
    assert seeded.classify("include/util.h", 2, seeds, hood) == {
        "label": seeded.IN_SEED_FUNCTION, "seeds": [list(HEADER_SEED)],
        "function": "shared", "outside_neighborhood": False}


def test_header_ambiguity_survives_real_diagnostic_publication_and_cache_changes(tmp_path):
    staged, accepted, _ = _header_hood(tmp_path)

    class HeaderDiagnostics(sc.StaticExecutor):
        def __init__(self):
            super().__init__(staged.run_root, diagnostics={("tidy", "util"): [(2, "header-rule", 0, False)]})

        def execute(self, request):
            result = super().execute(request)
            if request.argv[1] == "tidy":
                path = request.scratch_root / "tidy.json"
                document = json.loads(path.read_text())
                for diagnostic in document["diagnostics"]:
                    diagnostic["path"] = "/target/source/include/util.h"
                path.write_text(json.dumps(document), encoding="utf-8")
            return result

    full, _ = _run(staged, HeaderDiagnostics(), accepted=accepted)
    observations = _observations(staged, full)
    assert len(observations) == 1
    placement = observations[0]["seeded"]
    assert placement["label"] == seeded.IN_SEED_FUNCTION
    assert placement["seeds"] == [list(HEADER_SEED)] and placement["function"] is None
    assert placement["function_candidates"] == sorted(_ir_handoff(accepted)["ranges"])
    assert "function_ambiguity" in placement
    reordered = deepcopy(accepted)
    _ir_handoff(reordered)["seed_functions"].reverse()
    executor = HeaderDiagnostics()
    reused, _ = _run(staged, executor, accepted=reordered)
    assert executor.calls == [] and reused["index_identity"]["sha256"] == full["index_identity"]["sha256"]
    partial = deepcopy(accepted)
    _ir_handoff(partial)["seed_functions"].pop(0)
    executor = HeaderDiagnostics()
    changed, _ = _run(staged, executor, accepted=partial)
    assert len(executor.calls) == 2
    assert changed["index_identity"]["sha256"] != full["index_identity"]["sha256"]
    placement = _observations(staged, changed)[0]["seeded"]
    assert placement["label"] == seeded.IN_NEIGHBORHOOD and placement["seeds"] == []
    assert placement["candidate_seeds"] == [list(HEADER_SEED)]


def test_only_the_seeded_units_are_analyzed_never_the_whole_program(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, executor)
    assert len(staged.rows) == 12
    assert executor.calls == [("clang-tidy", UNITS), ("clang-static-analyzer", UNITS)]
    assert result["analyzed_units"] == ["unit:src/net.cpp", "unit:src/util.cpp"]
    record = result["index_identity"]["producer"]["seeded"]
    assert record["resolved_seed_count"] == 2 and record["status_counts"] == {"resolved": 2}


def test_zero_seeds_is_a_clean_skip_with_a_named_gap_and_partial_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[])
    executor = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, executor)
    assert executor.calls == []
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["gaps"][0] == seeding.NO_SEEDS_GAP
    assert result["observation_count"] == 0
    assert result["index_identity"]["producer"]["seeded"]["skipped"] is True
    path = staged.run_root / result["index_identity"]["relative_path"]
    status = sqlite3.connect(path).execute("select status from coverage").fetchall()
    assert status == [("partial",)]


def test_diagnostics_carry_seed_label_trace_length_and_fix_it(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    accepted = _hood(staged)
    result, _ = _run(staged, sc.StaticExecutor(staged.run_root), accepted=accepted)
    by_rule = {item["native_rule_id"]: item for item in _observations(staged, result)}
    at_seed = by_rule["bugprone-not-null-terminated-result"]
    assert at_seed["seeded"]["label"] == seeded.AT_SEED and at_seed["fix_it"] is True
    identities = [key for key, function in _ir_handoff(accepted)["functions"].items()
                  if function["name"] == "copy_field"]
    assert len(identities) == 1
    assert at_seed["seeded"]["seeds"] == [["src/util.cpp", 14, 14]]
    assert at_seed["seeded"]["function"] == identities[0]
    assert by_rule["unix.cstring.NullArg"]["trace_length"] == 3
    assert by_rule["cppcoreguidelines-avoid-c-arrays"]["seeded"]["label"] == seeded.IN_SEED_FUNCTION
    assert by_rule["readability-magic-numbers"]["seeded"]["label"] == seeded.IN_NEIGHBORHOOD
    outside = by_rule["misc-use-internal-linkage"]
    assert outside["seeded"]["label"] == seeded.OUTSIDE and outside["seeded"]["outside_neighborhood"] is True
    assert outside["seeded"]["seeds"] == []


def test_without_a_neighborhood_labels_are_unclassified_and_the_gap_is_named(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    result, _ = _run(staged, sc.StaticExecutor(staged.run_root))
    labels = {item["native_rule_id"]: item["seeded"]["label"] for item in _observations(staged, result)}
    assert labels["bugprone-not-null-terminated-result"] == seeded.AT_SEED
    assert labels["misc-use-internal-linkage"] == seeded.UNCLASSIFIED
    assert seeded.NEIGHBORHOOD_UNAVAILABLE in result["gaps"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_a_failed_unit_is_a_gap_on_its_seeds_and_never_clean(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.StaticExecutor(staged.run_root, fail=(("analyze", "net"),))
    result, _ = _run(staged, executor, accepted=_hood(staged))
    record = result["index_identity"]["producer"]["seeded"]
    assert record["status_counts"] == {"resolved": 1, "unresolved": 1}
    assert any("clang-static-analyzer failed on proj/src/net.cpp" in gap and "fixture failure" in gap for gap in result["gaps"])
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {(row["path"], row["status"], row.get("reason")) for row in ledger} == {
        ("src/net.cpp", "unresolved", "producer_failed"), ("src/util.cpp", "resolved", None)}
    path = staged.run_root / result["index_identity"]["relative_path"]
    assert sqlite3.connect(path).execute("select status from coverage").fetchall() == [("partial",)]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    # the unit that did analyze keeps its diagnostics
    assert "unix.cstring.NullArg" in {item["native_rule_id"] for item in _observations(staged, result)}


def test_a_failure_is_not_checkpointed_so_resume_retries_it(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    unit = _unit(staged)
    _run(staged, sc.StaticExecutor(staged.run_root, fail=(("tidy", "util"),)), unit=unit)
    healthy = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, healthy, unit=unit)
    assert len(healthy.calls) == 2
    assert result["index_identity"]["producer"]["seeded"]["status_counts"] == {"resolved": 2}


def test_a_seed_without_a_translation_unit_and_a_not_applicable_seed_are_named(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 14),
                                              sc.observation("proj/include/orphan.h", 3)])
    executor = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, executor)
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]
    assert ledger["status_counts"].get("resolved") == 1
    assert executor.calls[0][1] == ("src/util.cpp",)


def test_a_seed_in_an_unsupported_unit_is_not_applicable_never_failed_or_clean(monkeypatch, tmp_path: Path) -> None:
    from appsec_review.jobs.cpp_index_scopes import partition_compile_commands as real
    from appsec_review.tool_inputs import InputDecision, ReasonCode

    def partition(commands):
        rows = list(commands)
        kept = [row for row in rows if not row["target_path"].endswith("util.cpp")]
        dropped = tuple(InputDecision(row["target_path"], "clang", ReasonCode.INPUT_FORMAT_UNSUPPORTED, "unsupported")
                        for row in rows if row["target_path"].endswith("util.cpp"))
        return kept, dropped

    monkeypatch.setattr("appsec_review.jobs.cpp_seeded.partition_compile_commands", partition)
    staged = sc.stage(tmp_path)
    executor = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, executor)
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {(row["path"], row["status"], row.get("reason")) for row in ledger} == {
        ("src/net.cpp", "resolved", None), ("src/util.cpp", "unresolved", "not_applicable")}
    assert not any(gap.startswith("seed_without_translation_unit") for gap in result["gaps"])
    assert executor.calls[0][1] == ("src/net.cpp",)
    path = staged.run_root / result["index_identity"]["relative_path"]
    assert sqlite3.connect(path).execute("select status from coverage").fetchall() == [("partial",)]


def test_resume_identity_is_per_producer_and_the_seed_set_reuses_or_reruns(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    unit = _unit(staged)
    first, _ = _run(staged, sc.StaticExecutor(staged.run_root), unit=unit)
    again = sc.StaticExecutor(staged.run_root)
    reused, _ = _run(staged, again, unit=unit)
    assert again.calls == [] and reused["index_identity"]["sha256"] == first["index_identity"]["sha256"]
    for key, value in (("depth", 2), ("seed_limit", 100), ("unit_limit", 1)):
        executor = sc.StaticExecutor(staged.run_root)
        _run(staged, executor, unit=_unit(staged, seeded_settings={**sc.SEEDED, key: value}))
        assert executor.calls, key
    changed = sc.stage(tmp_path / "other", observations=[sc.observation("proj/src/util.cpp", 14)])
    executor = sc.StaticExecutor(changed.run_root)
    _run(changed, executor)
    assert executor.calls[0][1] == ("src/util.cpp",)


def test_bounds_are_named_gaps(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, executor, seeded_settings={**sc.SEEDED, "unit_limit": 1})
    assert executor.calls[0][1] == ("src/net.cpp",)
    assert any(gap.startswith("unit_limit_reached") for gap in result["gaps"])
    assert result["index_identity"]["producer"]["seeded"]["status_counts"] == {"resolved": 1, "unresolved": 1}


def test_shards_are_byte_identical_across_runs(tmp_path: Path) -> None:
    hashes = []
    for name in ("a", "b"):
        staged = sc.stage(tmp_path / name)
        result, _ = _run(staged, sc.StaticExecutor(staged.run_root), accepted=_hood(staged))
        hashes.append(result["index_identity"]["sha256"])
    assert hashes[0] == hashes[1]


def test_a_wrapper_that_reports_no_units_fails_the_whole_engine_not_one_unit(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.StaticExecutor(staged.run_root, fail=(("tidy", "net"),), report_units=False)
    result, _ = _run(staged, executor)
    assert "clang-tidy exited with status 1" in result["gaps"]
    assert result["index_identity"]["producer"]["seeded"]["status_counts"] == {"unresolved": 2}


def test_whole_program_mode_is_unchanged_by_the_seeded_hooks(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.StaticExecutor(staged.run_root)
    result, _ = _run(staged, executor, seeded_settings=None)
    assert len(executor.calls[0][1]) == 12 and "seeded" not in result["index_identity"]["producer"]
