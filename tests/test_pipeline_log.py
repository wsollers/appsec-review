from __future__ import annotations

import json
import os
from multiprocessing import get_context
from pathlib import Path

from appsec_review.observability import PipelineLog
from appsec_review.cli import main


def _writer(root: str, worker: int, count: int) -> None:
    log = PipelineLog(Path(root))
    for index in range(count):
        log.write("STRESS", run_id="run", job_id=f"job_{worker}", attempt_id="attempt_0001",
                  details={"worker": worker, "index": index, "token": "must-redact"})


def test_process_safe_log_has_contiguous_order_and_redaction(tmp_path: Path) -> None:
    context = get_context("spawn")
    processes = [context.Process(target=_writer, args=(str(tmp_path), worker, 15)) for worker in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    records, torn = PipelineLog(tmp_path).read()
    assert not torn
    assert [item["sequence"] for item in records] == list(range(1, 61))
    assert all(item["details"]["token"] == "<redacted>" for item in records)


def test_torn_final_record_is_ignored_and_recovered(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("FIRST", run_id="run")
    with log.path.open("ab") as stream:
        stream.write(b'{"sequence":2')
    records, torn = log.read()
    assert len(records) == 1 and torn
    log.write("SECOND", run_id="run")
    records, torn = log.read()
    assert not torn
    assert [record["sequence"] for record in records] == [1, 2]
    assert all(json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines())


def test_writer_failure_releases_kernel_lock(tmp_path: Path, monkeypatch) -> None:
    log = PipelineLog(tmp_path)
    original = os.fsync
    calls = 0
    def fail_once(descriptor):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected writer failure")
        return original(descriptor)
    monkeypatch.setattr(os, "fsync", fail_once)
    try:
        try:
            log.write("FAILED_WRITE", run_id="run")
        except OSError:
            pass
        log.write("RECOVERED_WRITE", run_id="run")
    finally:
        monkeypatch.setattr(os, "fsync", original)
    records, torn = log.read()
    assert not torn
    assert records[-1]["event_type"] == "RECOVERED_WRITE"


def test_cli_filters_global_log_without_external_tools(tmp_path: Path, capsys) -> None:
    source = Path(__file__).parents[1] / "appsec-review.toml"
    config = tmp_path / "appsec-review.toml"
    config.write_bytes(source.read_bytes())
    run_root = tmp_path / "runs/2026-10-08-0001"
    log = PipelineLog(run_root)
    log.write("ONE", run_id=run_root.name, job_id="job_review_intake", attempt_id="attempt_0001")
    log.write("TWO", run_id=run_root.name, job_id="job_target_catalog", attempt_id="attempt_0001")
    assert main(["--config", str(config), "logs", "--run-id", run_root.name,
                 "--job", "job_target_catalog", "--raw"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == "TWO"
