"""Part II of the telemetry report: per-job supporting detail."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import unicodedata

from appsec_review.reporting.model import Box, Cell, Fields, Heading, Note, Stats, Table
from appsec_review.reporting.telemetry import load_inputs
from appsec_review.reporting.telemetry.inputs import JobSpan
from appsec_review.reporting.telemetry.jobs import MAX_JOBS, job_sections

from .telemetry_fixture import JOBS, build_telemetry_run


def _sections(tmp_path: Path, **kwargs):
    return job_sections(load_inputs(build_telemetry_run(tmp_path, **kwargs)))


def _job(blocks, job_id: str) -> list:
    """The blocks of one job's level-2 section."""
    start = next(i for i, b in enumerate(blocks) if isinstance(b, Heading) and b.level == 2 and b.text == job_id)
    end = next((i for i, b in enumerate(blocks[start + 1:], start + 1) if isinstance(b, Heading) and b.level <= 2),
               len(blocks))
    return list(blocks[start:end])


def _table(blocks, title: str) -> Table:
    return next(item for b in blocks if isinstance(b, Box) and b.title == title for item in b.items
                if isinstance(item, Table))


def _row(table: Table, first: str) -> tuple[Cell, ...]:
    return next(row for row in table.rows if first in (row[0].text, row[1].text))


def _strings(blocks):
    for block in blocks:
        if isinstance(block, Heading):
            yield block.text
            yield block.subtitle
        elif isinstance(block, Stats):
            yield from (part for stat in block.items for part in (stat.label, stat.value))
        elif isinstance(block, Box):
            yield block.title
            yield block.meta
            for item in block.items:
                if isinstance(item, Table):
                    yield from (cell.text for row in item.rows for cell in row)
                elif isinstance(item, Fields):
                    yield from (row.value for row in item.rows)
                else:
                    yield from getattr(item, "items", ())


def test_headings_follow_timeline_with_attempt_subsections(tmp_path: Path) -> None:
    blocks = _sections(tmp_path)
    top = blocks[0]
    assert isinstance(top, Heading) and top.level == 1 and top.text == "Job details" and top.new_page
    assert [b.text for b in blocks if isinstance(b, Heading) and b.level == 2] == list(JOBS)
    publish = _job(blocks, JOBS[3])
    assert [b.text for b in publish if isinstance(b, Heading) and b.level == 3] == ["Attempt a1", "Attempt a2"]
    assert [b.items[0].value for b in publish if isinstance(b, Stats)] == ["FAILED", "SUCCEEDED"]
    assert any(isinstance(b, Box) and b.title == "Job gaps" and "FAILED" in b.items[0].items[0] for b in publish)
    anchors = [b.anchor for b in blocks if isinstance(b, Heading)]
    assert len(anchors) == len(set(anchors))
    # Single-attempt jobs have no attempt sub-heading.
    assert not [b for b in _job(blocks, JOBS[0]) if isinstance(b, Heading) and b.level == 3]


def test_attempt_stats_tasks_tools_and_subsystems(tmp_path: Path) -> None:
    blocks = _sections(tmp_path)
    build = _job(blocks, JOBS[1])
    stats = {s.label: s for s in next(b for b in build if isinstance(b, Stats)).items}
    assert len(stats) == 8  # two full rows of four cards
    assert stats["Status"].tone == "insufficient_evidence"
    assert stats["Events"].value.isdigit() and stats["Gaps"].tone in ("neutral", "coverage_gap")
    assert (stats["Wall time"].value, stats["Queue delay"].value, stats["Tool calls"].value) == ("4m 00s", "1.2 s", "2")
    assert stats["Model calls"].value == "0" and stats["Tokens in+out"].value == "unavailable"
    tasks = _table(build, "Steps and tasks")
    assert [c.text for c in tasks.rows[0]] == ["main.run", "main", "Succeeded", "4m 00s"]
    tools = _table(build, "Tool invocations")
    assert [c.text for c in _row(tools, "t-cppcheck")] == ["cppcheck", "t-cppcheck", "45.0 s", "Succeeded", "3"]
    hostile = _row(tools, "t-hostile")
    assert (hostile[3].badge, hostile[3].badge_label, hostile[3].text) == ("contradicted", "FAILED", "FAILED")
    images = _table(build, "Project image builds")
    assert [c.text for c in images.rows[0]] == ["unit-cpp", "cpp", "Built", "2m 00s"]
    review = _job(blocks, JOBS[2])
    transitions = _table(review, "Finding transitions")
    assert [(r[1].text, r[2].text) for r in transitions.rows] == [("NONE", "CANDIDATE"), ("CANDIDATE", "CONFIRMED")]


def _check_model_calls(blocks) -> None:
    review = _job(blocks, JOBS[2])
    calls = _table(review, "Model calls")
    assert [r[0].text for r in calls.rows] == ["m-red-1", "m-blue-1", "m-verify-1", "m-red-2"]
    assert [c.text for c in _row(calls, "m-blue-1")[3:9]] == ["8.0 s", "5,400", "900", "4,096", "700", "Accepted"]
    assert [c.text for c in _row(calls, "m-verify-1")[4:8]] == ["n/a"] * 4
    failed = _row(calls, "m-red-2")
    assert (failed[8].badge, failed[8].badge_label, failed[8].text) == ("contradicted", "FAILED", "FAILED")
    assert failed[9].text.startswith("\\input{/etc/passwd}") and len(failed[9].text) <= 120
    assert len(failed[2].text) <= 60
    stats = {s.label: s.value for s in next(b for b in review if isinstance(b, Stats)).items}
    assert stats["Model calls"] == "4" and stats["Tokens in+out"] == "7.8k (partial)"


def test_model_calls_from_summary(tmp_path: Path) -> None:
    _check_model_calls(_sections(tmp_path))


def test_empty_summary_falls_back_to_events(tmp_path: Path) -> None:
    inputs = replace(load_inputs(build_telemetry_run(tmp_path)), summary={}, summary_source="unavailable")
    _check_model_calls(job_sections(inputs))


def test_running_job_is_still_running_with_gap(tmp_path: Path) -> None:
    review = _job(_sections(tmp_path, outcome="RUNNING"), JOBS[2])
    stats = {s.label: s for s in next(b for b in review if isinstance(b, Stats)).items}
    assert stats["Status"].value == "RUNNING" and stats["Wall time"].value == "still running"
    fields = next(item for b in review if isinstance(b, Box) and b.title == "Attempt" for item in b.items)
    assert {row.label: row.value for row in fields.rows}["Ended at"] == "still running"
    assert _row(_table(review, "Steps and tasks"), "main.run")[3].text == "still running"
    gaps = next(b for b in review if isinstance(b, Box) and b.title == "Job gaps")
    assert gaps.kind.value == "gap" and any("still running" in item for item in gaps.items[0].items)


def test_hostile_text_is_cleaned_and_bounded(tmp_path: Path) -> None:
    for outcome in ("COMPLETED_WITH_GAPS", "FAILED", "RUNNING"):
        for text in _strings(_sections(tmp_path / outcome, outcome=outcome)):
            assert isinstance(text, str) and len(text) <= 240
            assert not any(unicodedata.category(ch)[0] == "C" for ch in text), repr(text)


def test_deterministic_and_degenerate_inputs(tmp_path: Path) -> None:
    assert _sections(tmp_path / "a") == _sections(tmp_path / "b")
    inputs = load_inputs(build_telemetry_run(tmp_path / "c"))
    assert job_sections(replace(inputs, jobs=(), events=())) == ()
    spans = tuple(JobSpan(f"job_{i:03d}", "a1", "RUNNING", i, None, "2026-10-21T10:00:00+00:00", None, 0)
                  for i in range(MAX_JOBS + 5))
    blocks = job_sections(replace(inputs, summary={}, events=(), jobs=spans))
    assert len([b for b in blocks if isinstance(b, Heading) and b.level == 2]) == MAX_JOBS
    assert isinstance(blocks[-1], Note) and blocks[-1].text.startswith("5 more jobs")


def test_inclusive_retrieval_metrics_subop_exclusion_and_cache_write_columns(tmp_path: Path) -> None:
    import hashlib
    import json
    from .fixture import MODEL

    run_dir = build_telemetry_run(tmp_path, write_summary=False)
    events_path = run_dir / "data" / "logs" / "pipeline.jsonl"
    records = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    insert_at = next(
        idx for idx, rec in enumerate(records)
        if rec["job_id"] == JOBS[2] and rec["event_type"] == "JOB_SUCCEEDED"
    )
    stamp = records[insert_at - 1]["timestamp"]
    injected = [
        ("RETRIEVAL_QUERY", "review", "q-1", {
            "shards_candidate": 6, "shards_opened": 2,
            "snapshot_cache_hits": 3, "snapshot_cache_misses": 1, "route_cache_hit": True,
        }),
        ("RETRIEVAL_QUERY", "review", "q-2", {
            "shards_candidate": 4, "shards_opened": 1,
            "snapshot_cache_hits": 2, "snapshot_cache_misses": 0, "route_cache_hit": False,
        }),
        ("RETRIEVAL_QUERY", "review", "q-legacy", {}),
        ("RETRIEVAL_SUBOP_COMPLETED", "review", "subop-fts", {"duration_ms": 450000}),
        ("MODEL_CALL_STARTED", "review", "m-replay-1", {
            "model_invocation_id": "m-replay-1", "provider": "anthropic", "model": MODEL, "role": "blue",
        }),
        ("MODEL_CALL_COMPLETED", "review", "m-replay-1", {
            "model_invocation_id": "m-replay-1", "provider": "anthropic", "model": MODEL, "role": "blue",
            "duration_ms": 500, "retry_count": 0, "terminal_status": "succeeded",
            "execution_mode": "replay", "usage_source": "replay",
            "input_tokens": 9000, "output_tokens": 1500, "cache_tokens": 8192, "cache_write_tokens": 512,
        }),
    ]
    extra_records = [
        {
            "schema": "appsec-review/telemetry-event/1",
            "sequence": 1,
            "timestamp": stamp,
            "level": "INFO",
            "event_type": ev_type,
            "run_id": run_dir.name,
            "job_id": JOBS[2],
            "attempt_id": "a1",
            "step_id": step,
            "task_id": task,
            "process": {"pid": 1, "name": "fixture"},
            "trigger": "manual",
            "orchestrator": "dagster",
            "message": ev_type.lower(),
            "details": details,
            "event_id": "0" * 64,
        }
        for ev_type, step, task, details in injected
    ]
    merged = records[:insert_at] + extra_records + records[insert_at:]
    for seq, rec in enumerate(merged, 1):
        rec["sequence"] = seq
        rec["event_id"] = hashlib.sha256(f"{run_dir.name}:{seq}:{rec['event_type']}".encode()).hexdigest()
    events_path.write_bytes(
        b"".join((json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8") for rec in merged)
    )

    inputs = load_inputs(run_dir)
    assert inputs.summary_source == "recomputed"
    assert inputs.summary["retrieval_queries"] == {
        "count": 3,
        "route_hits": 1,
        "route_lookups": 2,
        "shards_candidate": 10,
        "shards_candidate_measured_queries": 2,
        "shards_opened": 3,
        "shards_opened_measured_queries": 2,
        "snapshot_cache_hits": 5,
        "snapshot_cache_hits_measured_queries": 2,
        "snapshot_cache_misses": 1,
        "snapshot_cache_misses_measured_queries": 2,
    }

    blocks = job_sections(inputs)
    review = _job(blocks, JOBS[2])
    tasks = _table(review, "Steps and tasks")
    assert all("subop-fts" not in row[0].text for row in tasks.rows)
    calls = _table(review, "Model calls")
    assert calls.headers[6:8] == ("Cache read", "Cache write")
    assert [c.text for c in _row(calls, "m-replay-1")[3:9]] == [
        "500 ms", "9,000", "1,500", "8,192", "512", "Succeeded",
    ]
    assert _row(calls, "m-red-1")[7].text == "n/a"
