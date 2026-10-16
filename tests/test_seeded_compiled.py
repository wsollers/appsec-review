"""Seeded Clang AST and LLVM IR (docs/architecture/seeded-neighborhoods.md 5, 6, 7), on the 12-unit fixture."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review import seeding
from appsec_review.jobs.job_cpp_compiled_analysis import build_job, seeded
from tests import seeded_clang_support as sc

REPLAYED = ("proj/src/net.cpp", "proj/src/util.cpp")


def _handlers(executor):
    job = build_job(executor_factory=lambda unit: executor)
    return {unit.unit_id: unit for unit in job.units}


def _run(staged, executor, name: str, *, seeded_settings=sc.SEEDED, ir=None):
    """Run the real branch handler of one unit against the staged project."""
    outputs = {"catalog.projects": {"projects": {sc.CASE: staged.cataloged}}}
    if ir is not None:
        outputs["ir.projects"] = ir
    unit = staged.unit(f"{name}.projects", outputs, seeded=seeded_settings)
    return _handlers(executor)[f"{name}.projects"].handler(unit), unit


def _pair(staged, executor, **kwargs):
    ir, _ = _run(staged, executor, "ir", **kwargs)
    ast, _ = _run(staged, executor, "ast", ir=ir, **kwargs)
    return ir, ast


def _rows(staged, output: dict, table: str = "entities") -> list[tuple]:
    path = staged.run_root / output["projects"][sc.CASE]["artifact"]["path"]
    return sqlite3.connect(path).execute(f"select * from {table}").fetchall()


def _coverage(staged, output: dict) -> list[tuple]:
    path = staged.run_root / output["projects"][sc.CASE]["artifact"]["path"]
    return sqlite3.connect(path).execute("select area, status, gap from coverage").fetchall()


def test_only_the_seeded_units_are_replayed_never_the_whole_program(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root)
    assert len(staged.rows) == 12
    _pair(staged, executor)
    assert executor.calls == [("ir", REPLAYED), ("cfg", REPLAYED), ("ast", REPLAYED)]
    assert not any(len(units) > 2 for _, units in executor.calls)


def test_seeded_ir_publishes_the_neighborhood_with_flow_and_calls(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    result = ir["projects"][sc.CASE]
    assert result["handoff"]["neighborhood"] == {"copy_field": 0, "handle_packet": 0, "checked_len": 1,
                                                 "log_event": 1, "clamp_len": 2}
    assert result["call_edge_count"] == 4 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    record = result["index_identity"]["producer"]["seeded"]
    assert record["resolved_seed_count"] == 2 and record["status_counts"] == {"resolved": 2}
    assert [name for _, status, _ in [row for row in _coverage(staged, ir)] for name in [status]] == ["partial"]
    flows = [json.loads(row[5]) for row in _rows(staged, ir)]
    function = next(item for item in flows if item.get("linkage_name", "").startswith("_Z10copy_field"))
    assert function["flow"]["blocks"] and function["flow"]["dominators"] and function["seeded"] is True


def _payloads(staged, output: dict) -> dict[str, dict]:
    return {row[3]: json.loads(row[5]) for row in _rows(staged, output)}


def test_source_cfg_is_attached_to_the_neighborhood_functions_with_a_named_line_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    result = ir["projects"][sc.CASE]
    payloads = _payloads(staged, ir)
    cfg = payloads["copy_field"]["source_cfg"]
    assert cfg["producer"] == "clang-cfg" and cfg["entry"] and cfg["exit"] and cfg["branches"] == 1
    branch = next(block for block in cfg["blocks"] if block["terminator"] == "if")
    assert branch["condition"] == "src == nullptr" and len(branch["successors"]) == 2
    assert any(call == "memcpy(dst, src, n)" for block in cfg["blocks"] for call in block["calls"])
    assert result["source_cfg_count"] == 5
    assert set(payloads) == {"copy_field", "handle_packet", "checked_len", "log_event", "clamp_len"}
    assert all("source_cfg" in value for value in payloads.values())
    assert any(gap.startswith("source_cfg_no_block_lines") for gap in result["gaps"])
    assert {status for _, status, _ in _coverage(staged, ir)} == {"partial"}


def test_a_failed_cfg_replay_keeps_the_ir_flow_and_names_the_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root, fail=(("cfg", "util"),))
    ir, _ = _run(staged, executor, "ir")
    result = ir["projects"][sc.CASE]
    payloads = _payloads(staged, ir)
    assert any(gap.startswith("source_cfg_unavailable") and "proj/src/util.cpp" in gap for gap in result["gaps"])
    assert "source_cfg" not in payloads["copy_field"] and "flow" in payloads["copy_field"]
    assert "source_cfg" in payloads["handle_packet"]
    assert any(gap.startswith("source_cfg_unmatched") and "copy_field" in gap for gap in result["gaps"])
    assert {status for _, status, _ in _coverage(staged, ir)} == {"partial"}


def test_zero_seeds_is_a_clean_skip_with_a_named_gap_and_partial_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[])
    executor = sc.FixtureExecutor(staged.run_root)
    ir, ast = _pair(staged, executor)
    assert executor.calls == []
    for output in (ir, ast):
        result = output["projects"][sc.CASE]
        assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and output["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert result["gaps"][0] == seeding.NO_SEEDS_GAP and result["entity_count"] == 0
        assert result["index_identity"]["producer"]["seeded"]["skipped"] is True
        assert {status for _, status, _ in _coverage(staged, output)} == {"partial"}


def test_a_failed_replay_is_a_gap_on_the_seeds_it_carried_and_never_raises_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root, fail=(("ir", "util"),))
    ir, ast = _pair(staged, executor)
    result = ir["projects"][sc.CASE]
    assert any("proj/src/util.cpp" in gap and "failed" in gap for gap in result["gaps"])
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    by_path = {entry["path"]: entry for entry in ledger}
    assert by_path["src/util.cpp"]["status"] == "unresolved" and by_path["src/util.cpp"]["reason"] == "producer_failed"
    assert by_path["src/net.cpp"]["status"] == "resolved"
    assert {status for _, status, _ in _coverage(staged, ir)} == {"partial"}
    assert result["checkpointable"] is False
    # The AST is anchored to the IR neighborhood: the failed unit is not replayed for it either.
    assert ("ast", REPLAYED[:1]) == executor.calls[-1] or all("util" not in unit for unit in executor.calls[-1][1])


def test_a_total_replay_failure_is_unavailable_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root, exit_code=9)
    ir, ast = _pair(staged, executor)
    result = ir["projects"][sc.CASE]
    assert {status for _, status, _ in _coverage(staged, ir)} == {"unavailable"}
    assert result["entity_count"] == 0 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    # No IR neighborhood means no AST replay at all, and the seeds say why.
    assert [call for call in executor.calls if call[0] == "ast"] == []
    ast_result = ast["projects"][sc.CASE]
    assert any(gap.startswith("ast_without_neighborhood") for gap in ast_result["gaps"])
    ledger = json.loads((staged.run_root / ast_result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {entry["reason"] for entry in ledger} == {"not_run"}


def test_a_seed_in_no_translation_unit_is_a_named_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/include/orphan.h", 3),
                                              sc.observation("proj/src/util.cpp", 14)])
    # The file is in the mapping (a header nothing includes) but belongs to no replayed unit.
    (staged.target / "proj" / "include" / "orphan.h").write_text("int orphan();\n")
    staged.mapping["files"].append({"target_path": "proj/include/orphan.h", "scratch_path": "source/include/orphan.h",
                                    "sha256": "d" * 64})
    executor = sc.FixtureExecutor(staged.run_root)
    ir, _ = _run(staged, executor, "ir")
    result = ir["projects"][sc.CASE]
    assert any(gap.startswith("seed_without_translation_unit") for gap in result["gaps"])
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {entry["path"]: entry.get("reason") for entry in ledger}["include/orphan.h"] == "no_translation_unit"
    assert executor.calls == [("ir", ("proj/src/util.cpp",)), ("cfg", ("proj/src/util.cpp",))]


@pytest.mark.parametrize("override, expected", [
    ({"function_limit": 2}, "limit_reached"),
    ({"depth": 1}, "depth_reached"),
    ({"block_limit": 1}, "export_truncated"),
    ({"unit_limit": 1}, "unit_limit_reached"),
])
def test_named_bounds_produce_named_gaps(tmp_path: Path, override: dict, expected: str) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir", seeded_settings={**sc.SEEDED, **override})
    assert any(gap.startswith(expected) for gap in ir["projects"][sc.CASE]["gaps"]), ir["projects"][sc.CASE]["gaps"]


def test_every_ir_neighborhood_carries_a_frontier_gap_for_unreplayed_callers(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    assert any(gap.startswith("frontier") for gap in ir["projects"][sc.CASE]["gaps"])


def test_ast_call_expressions_name_their_callee(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    _, ast = _pair(staged, sc.FixtureExecutor(staged.run_root))
    calls = [json.loads(row[5]) for row in _rows(staged, ast) if json.loads(row[5])["kind"] == "CallExpr"]
    callees = {item["referenced_decl"]["name"] for item in calls if item["referenced_decl"]}
    assert {"checked_len", "copy_field", "clamp_len"} <= callees


def test_resume_identity_is_per_producer(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root)
    ir, ast = _pair(staged, executor)
    assert len(executor.calls) == 3
    # Unchanged settings and seed set: both producers reuse their checkpoints, nothing is replayed.
    again_ir, again_ast = _pair(staged, executor)
    assert len(executor.calls) == 3
    assert again_ir["projects"][sc.CASE]["checkpoint_reused"] and again_ast["projects"][sc.CASE]["checkpoint_reused"]
    # A different depth changes both seeded producers' identity: both run again.
    _pair(staged, executor, seeded_settings={**sc.SEEDED, "depth": 2})
    assert [mode for mode, _ in executor.calls[3:]] == ["ir", "cfg", "ast"]
    # A different mode (whole program) is a different identity again, and replays every unit.
    whole = sc.FixtureExecutor(staged.run_root)
    _run(staged, whole, "ir", seeded_settings=None)
    assert len(whole.calls[0][1]) == 12


def test_a_changed_seed_set_reruns_the_ir_and_the_ast(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root)
    _pair(staged, executor)
    changed = sc.stage(tmp_path / "other", observations=[sc.observation("proj/src/util.cpp", 14)])
    # Same case root layout, different seed set: the checkpoint identity differs, so nothing is reused.
    other = sc.FixtureExecutor(changed.run_root)
    ir, _ = _pair(changed, other)
    assert not ir["projects"][sc.CASE].get("checkpoint_reused") and other.calls[0] == ("ir", REPLAYED[1:])


def test_shards_and_records_are_byte_identical_across_runs(tmp_path: Path) -> None:
    outputs = []
    for name in ("a", "b"):
        staged = sc.stage(tmp_path / name)
        ir, ast = _pair(staged, sc.FixtureExecutor(staged.run_root))
        outputs.append([(item["projects"][sc.CASE]["index_identity"]["sha256"],
                         item["projects"][sc.CASE]["index_identity"]["producer"]["seeded"],
                         item["projects"][sc.CASE]["ledger"]["sha256"]) for item in (ir, ast)])
    assert outputs[0] == outputs[1]
