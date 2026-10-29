"""Part I (run overview) and appendix of the telemetry report: content, bounding and determinism."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Iterator

from appsec_review.reporting.model import BarChart, Box, Heading, Stats, Table, Timeline
from appsec_review.reporting.telemetry import RENDERER, load_inputs
from appsec_review.reporting.telemetry.overview import (CELL_CHARS, VALUE_CHARS, appendix_sections,
                                                        overview_sections)
from appsec_review.reporting.tokens import BoxKind

from .fixture import HOSTILE, MODEL
from .telemetry_fixture import JOBS, RUN_ID, build_telemetry_run


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif dataclasses.is_dataclass(value):
        for field in dataclasses.fields(value):
            yield from _strings(getattr(value, field.name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _strings(item)


def _blocks(run_dir: Path) -> tuple[Any, ...]:
    inputs = load_inputs(run_dir)
    return (*overview_sections(inputs), *appendix_sections(inputs))


def _box(blocks: tuple[Any, ...], title: str) -> Box:
    return next(block for block in blocks if isinstance(block, Box) and block.title == title)


def _stats(blocks: tuple[Any, ...]) -> dict[str, tuple[str, str]]:
    stats = next(block for block in blocks if isinstance(block, Stats))
    return {stat.label: (stat.value, stat.tone) for stat in stats.items}


def test_overview_structure_stats_and_timeline(tmp_path: Path) -> None:
    blocks = _blocks(build_telemetry_run(tmp_path))
    headings = [(block.level, block.text) for block in blocks if isinstance(block, Heading)]
    assert headings == [(1, "Run overview"), (2, "Run timeline"), (2, "Where the time went"),
                        (2, "Run-wide usage"), (2, "Data quality"), (1, "Provenance")]
    stats = _stats(blocks)
    assert stats["Completion"] == ("completed with gaps", "insufficient_evidence")
    assert stats["Wall time"][0] == "16m 52s"
    assert stats["Jobs"] == ("4", "contradicted")      # one publication attempt failed
    assert stats["Model calls"][0] == "5" and stats["Tool calls"][0] == "2"
    assert stats["Tokens (in + out)"] == ("9.3k", "insufficient_evidence")  # one call recorded no usage
    assert stats["Named gaps"] == ("0", "neutral")
    clean = _box(blocks, "Data quality")
    assert (clean.kind, clean.meta) == (BoxKind.PROVENANCE, "0 gaps")  # no gap styling without a gap

    timeline = next(block for block in blocks if isinstance(block, Timeline))
    assert timeline.total_ms == 1_012_000 and timeline.omitted is None
    assert [lane.label for lane in timeline.lanes] == [
        JOBS[0], JOBS[1], JOBS[2], f"{JOBS[3]} (a1)", f"{JOBS[3]} (a2)"]
    assert [lane.segments[0].tone for lane in timeline.lanes] == [
        "confirmed", "insufficient_evidence", "confirmed", "contradicted", "confirmed"]
    assert (timeline.lanes[0].segments[0].start_ms, timeline.lanes[0].segments[0].end_ms) == (1000, 61000)
    assert timeline.lanes[0].annotation == "1m 00s"

    bars = next(block for block in blocks if isinstance(block, BarChart))
    assert [bar.label for bar in bars.bars] == [JOBS[2], JOBS[1], JOBS[3], JOBS[0]]  # longest first, "-" excluded
    assert bars.bars[0].display == "13m 56s"

    time = _box(blocks, "Critical path and concurrency").items[0]
    values = {field.label: field.value for field in time.rows}
    assert values["Critical path candidate"] == "job_inference_security_review/main/main.run"
    assert values["Share of wall time"] == "82.6%" and values["Parallelism"] == "1.22x (task time / wall time)"
    assert values["Queue delay p50 / p95 / max"] == "400 ms / 1.2 s / 1.2 s"

    operations = _box(blocks, "Slowest operations").items[0]
    assert isinstance(operations, Table) and len(operations.rows) == 12
    assert operations.omitted is not None and operations.omitted.omitted == 4
    assert not any(row[0].text.endswith("/-") for row in operations.rows)


def test_operation_labels_name_run_and_job_level_operations() -> None:
    from appsec_review.reporting.telemetry.overview import _operation_label
    assert _operation_label("-/-/-/-") == "(run)"
    assert _operation_label("job_x/-/-/-") == "job_x (job)"
    assert _operation_label("job_x/main/main.run/-") == "job_x/main/main.run"
    assert _operation_label("job_x/-/t1/cppcheck") == "job_x/-/t1/cppcheck"


def test_model_usage_marks_missing_tokens_unavailable(tmp_path: Path) -> None:
    table = _box(_blocks(build_telemetry_run(tmp_path)), "Model usage").items[0]
    rows = {(row[0].text, row[1].text): [cell.text for cell in row[2:]] for row in table.rows}
    assert rows[(MODEL, "verifier")] == ["1", "0", "n/a", "n/a", "n/a", "20.0 s"]
    assert rows[(MODEL, "blue")] == ["1", "0", "5,400", "900", "4,096", "8.0 s"]
    assert rows[(MODEL, "red")] == ["1", "0", "1,200", "300", "0", "12.5 s"]
    hostile = next(key for key in rows if key[0] != MODEL)
    assert rows[hostile][:2] == ["1", "1"]                      # the failed call is counted


def test_hostile_strings_are_cleaned_and_bounded(tmp_path: Path) -> None:
    blocks = _blocks(build_telemetry_run(tmp_path))
    strings = list(_strings(blocks))
    for text in strings:
        assert not any(ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0 for char in text), text
        assert "\u202e" not in text and "\u202c" not in text
        assert len(text) <= VALUE_CHARS + 260, text[:80]
    hostile = [text for text in strings if "write18" in text]
    assert hostile and all(len(text) <= VALUE_CHARS + 40 for text in hostile)
    tools = _box(blocks, "Tool calls").items[0]
    assert all(len(row[0].text) <= CELL_CHARS + 1 for row in tools.rows)
    assert {row[0].text for row in tools.rows} >= {"cppcheck"}
    assert HOSTILE not in strings


def test_empty_summary_and_missing_log_degrade_to_unavailable(tmp_path: Path) -> None:
    run_dir = build_telemetry_run(tmp_path)
    (run_dir / "data" / "telemetry" / "summary.json").write_text(
        json.dumps({"schema": "appsec-review/run-metrics/4", "run_id": RUN_ID}), encoding="utf-8")
    (run_dir / "data" / "logs" / "pipeline.jsonl").unlink()
    blocks = _blocks(run_dir)
    stats = _stats(blocks)
    assert stats["Wall time"][0] == "unavailable" and stats["Model calls"][0] == "unavailable"
    assert stats["Tokens (in + out)"][0] == "unavailable" and stats["Jobs"][0] == "unavailable"
    assert stats["Named gaps"] == ("2", "coverage_gap")
    assert not any(isinstance(block, (Timeline, BarChart)) for block in blocks)
    quality = _box(blocks, "Data quality")
    assert (quality.kind, quality.meta) == (BoxKind.GAP, "2 gaps")
    text = " ".join(_strings(quality))
    assert "metrics_summary_schema_mismatch" in text and "pipeline_event_log_missing" in text
    assert "not zero work" in text
    provenance = {field.label: field.value for field in _box(blocks, "Sources").items[0].rows}
    assert provenance["Event log sha256"] == "unavailable" and provenance["Events read"] == "unavailable"
    assert provenance["Report renderer"] == RENDERER


def test_running_run_extends_lane_and_lists_running_work(tmp_path: Path) -> None:
    blocks = _blocks(build_telemetry_run(tmp_path, outcome="RUNNING"))
    timeline = next(block for block in blocks if isinstance(block, Timeline))
    review = next(lane for lane in timeline.lanes if lane.label == JOBS[2])
    assert review.segments[0].end_ms == timeline.total_ms and review.annotation.endswith("(running)")
    assert review.segments[0].tone == "proposed"
    assert _stats(blocks)["Completion"][0] == "unknown"


def test_overview_is_deterministic(tmp_path: Path) -> None:
    assert _blocks(build_telemetry_run(tmp_path / "a")) == _blocks(build_telemetry_run(tmp_path / "b"))
    recomputed = _blocks(build_telemetry_run(tmp_path / "c", write_summary=False))
    assert _box(recomputed, "Data quality").items[0].rows[0].value.startswith("recomputed")
