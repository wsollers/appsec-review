"""The run-wide pipeline log is scanned as a stream, never loaded whole, when one fact is wanted."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.observability.events import PipelineLog


def _log(root: Path, count: int) -> PipelineLog:
    log = PipelineLog(root)
    for index in range(count):
        log.write("RUN_STARTED" if index == 0 else "OPERATION_PROGRESS", run_id="r1")
    return log


def test_contains_stops_at_the_first_match_and_never_reads_the_file_whole(tmp_path, monkeypatch) -> None:
    """Regression for smoke-cpp run 2026-11-14-0003: poc_generation__begin parsed a 2.06 GB log into memory to
    find RUN_STARTED and was killed by the 5 GiB cgroup limit."""
    log = _log(tmp_path, 6)
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("the whole log was read into memory"))
    seen = []

    def wanted(record):
        seen.append(record["sequence"])
        return record["event_type"] == "RUN_STARTED"

    assert log.contains(wanted) and seen == [1]
    assert not log.contains(lambda record: record["event_type"] == "STEP_FAILED")
    assert [record["sequence"] for record in log.iterate()] == [1, 2, 3, 4, 5, 6]


def test_iterate_ignores_a_torn_tail_and_refuses_a_broken_sequence(tmp_path) -> None:
    log = _log(tmp_path, 3)
    with log.path.open("ab") as stream:
        stream.write(b'{"sequence": 4, "event_type": "torn"')
    assert [record["sequence"] for record in log.iterate()] == [1, 2, 3]
    lines = log.path.read_bytes().splitlines(keepends=True)[:3]
    broken = json.loads(lines[1]); broken["sequence"] = 9
    log.path.write_bytes(lines[0] + json.dumps(broken).encode() + b"\n" + lines[2])
    with pytest.raises(ValueError, match="invalid pipeline log sequence"):
        list(log.iterate())
    assert list(PipelineLog(tmp_path / "missing").iterate()) == []
