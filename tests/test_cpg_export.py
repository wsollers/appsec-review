"""The bounded Joern neo4jcsv export reader (recorded from the real tool-joern 4.0.630 on the seeded fixture)."""
from __future__ import annotations

from pathlib import Path
import shutil

from appsec_review.jobs.job_cpg_analysis import export

RECORDED = Path(__file__).parent / "fixtures" / "seeded_clang" / "recorded" / "cpg" / "export"


def test_functions_calls_branches_and_data_dependence_come_from_the_recorded_export() -> None:
    parsed = export.read_export(RECORDED)
    order = [(item.path, item.line or 0) for item in parsed.functions]
    assert order == sorted(order)
    by_name = {item.name: item for item in parsed.functions}
    # Pseudo methods (<global>, <includes>) never become functions.
    assert "<global>" not in by_name
    assert [call.name for call in by_name["copy_field"].calls] == ["checked_len", "memcpy"]
    assert by_name["copy_field"].operator_calls > 0 and by_name["copy_field"].reaching_def_edges > 0
    assert [(item.kind, item.line, item.condition) for item in by_name["clamp_len"].branches] == [
        ("IF", 4, "n < 0"), ("IF", 5, "n > 64")]
    # A header declaration has no body and is marked so.
    assert by_name["memcpy"].has_body is False and by_name["clamp_len"].has_body is True
    assert export.NO_CALL_EDGES_GAP in parsed.gaps and export.NO_CFG_GAP in parsed.gaps
    assert parsed.as_dict() == export.read_export(RECORDED).as_dict()


def test_an_empty_or_methodless_export_is_a_named_gap_not_a_clean_result(tmp_path: Path) -> None:
    parsed = export.read_export(tmp_path)
    assert parsed.functions == [] and parsed.gaps and parsed.gaps[0].startswith("cpg_export_no_methods")


def test_row_and_per_function_bounds_are_named_gaps(tmp_path: Path, monkeypatch) -> None:
    shutil.copytree(RECORDED, tmp_path / "export")
    monkeypatch.setattr(export, "MAX_CALLS_PER_FUNCTION", 1)
    parsed = export.read_export(tmp_path / "export")
    copy = next(item for item in parsed.functions if item.name == "copy_field")
    assert len(copy.calls) == 1 and copy.cut == ["calls"]
    assert any("copy_field lists a bounded subset" in gap for gap in parsed.gaps)
    monkeypatch.setattr(export, "MAX_ROWS", 2)
    assert any("was cut at 2 rows" in gap for gap in export.read_export(tmp_path / "export").gaps)


def test_a_symlinked_table_is_not_read(tmp_path: Path) -> None:
    shutil.copytree(RECORDED, tmp_path / "export")
    data = tmp_path / "export" / "nodes_METHOD_data.csv"
    real = tmp_path / "real.csv"
    shutil.move(data, real)
    data.symlink_to(real)
    assert export.read_export(tmp_path / "export").functions == []
