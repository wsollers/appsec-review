"""T-5027: the pipeline log fsyncs only what must be durable now.

Run 2026-11-15-0005 recorded 22,903 ``telemetry.fsync`` phases costing 1,303 s off-CPU in one lane unit's 109
minutes, one per record under the shared lock. Records stay write-through (other processes read the log as
control state); errors, failures and stops fsync as they are written, and every touched log is fsynced at exit.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from appsec_review.observability import events
from appsec_review.observability.events import PipelineLog, sync_all


@pytest.fixture
def fsyncs(monkeypatch):
    with events._TOUCHED_LOCK:      # the touched set is process-wide; other tests in this worker wrote logs too
        events._TOUCHED.clear()
    calls: list[int] = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (calls.append(fd), real(fd)) and None)
    return calls


def emit(log: PipelineLog, kind: str, level: str = "INFO", **details):
    return log.write(kind, run_id="2026-11-15-0005", job_id="job", attempt_id="attempt-1", level=level, details=details)


def test_plain_records_write_through_without_fsync_and_keep_their_order(tmp_path: Path, fsyncs) -> None:
    log = PipelineLog(tmp_path)
    for index in range(5):
        emit(log, "CELL", number=index)
        assert len(log.path.read_bytes().splitlines()) == index + 1      # visible to any process at once
    assert fsyncs == []
    records, torn = log.read()
    assert torn is False and [record["sequence"] for record in records] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("kind, level", [("RETRIEVAL_FAILED", "INFO"), ("CELL", "ERROR"), ("STOP", "INFO")])
def test_errors_failures_and_stops_fsync_as_they_are_written(tmp_path: Path, fsyncs, kind, level) -> None:
    log = PipelineLog(tmp_path)
    emit(log, "CELL", number=1)
    emit(log, kind, level=level)
    assert len(fsyncs) == 1
    emit(log, "OPERATION_PROGRESS", span_id="s1")
    assert len(fsyncs) == 1


def test_exit_sync_fsyncs_each_touched_log_once(tmp_path: Path, fsyncs) -> None:
    first, second = PipelineLog(tmp_path / "a"), PipelineLog(tmp_path / "b")
    for _ in range(3):
        emit(first, "CELL")
    emit(second, "CELL")
    assert fsyncs == []
    sync_all()
    assert len(fsyncs) == 2
    sync_all()                        # nothing touched since; nothing to sync
    assert len(fsyncs) == 2
    emit(first, "CELL")
    sync_all()
    assert len(fsyncs) == 3


def test_a_removed_log_does_not_fail_the_exit_sync(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    emit(log, "CELL")
    log.path.unlink()
    sync_all()
    assert not events._TOUCHED
