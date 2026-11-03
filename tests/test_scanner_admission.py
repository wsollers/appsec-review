from contextvars import Context
from dataclasses import replace
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.config.assurance import ResourceBudget
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest
from appsec_review.observability import EventLog, PipelineLog, aggregate_run_metrics
from appsec_review.runtime import resources
from tests.test_container_runtime import DIGEST, catalog


def _catalog(tmp_path: Path, tool_id: str, admission_seconds: int = 3600):
    original = catalog(tmp_path)
    tool = replace(original.tool("tool-fixture"), tool_id=tool_id, timeout_seconds=600)
    return replace(original, policy=MappingProxyType({
        **original.policy, "admission_timeout_seconds": admission_seconds}),
        tools=MappingProxyType({tool_id: tool}))


def _events(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.parametrize("tool_id", ("tool-checkov", "tool-syft"))
def test_live_io_contention_can_outlast_execution_budget_without_spending_it(
        tmp_path, monkeypatch, tool_id):
    metadata = tmp_path / "metadata"
    event_path = tmp_path / "events.jsonl"
    events = EventLog(event_path, PipelineLog(tmp_path / "run"), {"run_id": tmp_path.name})
    budget = ResourceBudget(cpu=8, memory_mb=10240, io_slots=1, staging_memory_mb=512)
    admission = resources.ResourceAdmission(metadata, budget)
    holder_context = Context()
    holder = holder_context.run(
        admission.reserve, resources.Reservation(2, 1536), events=events, action="holder.fixture")
    holder_context.run(holder.__enter__)
    clock = 0.0
    released = False
    calls = []

    def advance(_delay):
        nonlocal clock, released
        clock += 100
        if clock >= 700 and not released:
            holder_context.run(holder.__exit__, None, None, None)
            released = True

    def runner(argv, timeout):
        argv = tuple(argv)
        calls.append((argv, timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            return CommandOutcome(0, DIGEST.encode(), b"")
        if argv[:2] == ("docker", "run"):
            leases = json.loads((metadata / "resource-admission" / "leases.json").read_text())["leases"]
            assert len(leases) == 1
            assert next(iter(leases.values()))["reservation"] == {
                "cpu": 2, "memory_mb": 1536, "io_slots": 1}
            assert timeout == 600
            assert argv[argv.index("--cpus") + 1] == "2"
            assert argv[argv.index("--memory") + 1] == "1g"
            return CommandOutcome(0, b"", b"")
        if argv[:2] == ("docker", "rm"):
            return CommandOutcome(0, b"", b"")
        raise AssertionError(argv)

    monkeypatch.setattr(resources.time, "monotonic", lambda: clock)
    monkeypatch.setattr(resources.time, "sleep", advance)
    target = tmp_path / "target"
    target.mkdir()
    try:
        with resources.review_resource_scope(metadata, budget, events):
            result = ContainerExecutor(_catalog(tmp_path, tool_id), tmp_path / "run", runner=runner).execute(
                ExecutionRequest(tool_id, ("/bin/fixture",), target, tmp_path / "run" / "scratch"))
    finally:
        if not released:
            holder_context.run(holder.__exit__, None, None, None)
    assert result.exit_code == 0 and not result.timed_out
    assert result.limits["timeout_seconds"] == 600
    assert result.limits["admission_timeout_seconds"] == 3600
    assert result.limits["memory"] == "1g"
    assert len([argv for argv, _timeout in calls if argv[:2] == ("docker", "run")]) == 1
    emitted = [event for event in _events(event_path) if event.get("operation_id") == f"scanner.{tool_id}"]
    admitted = next(event for event in emitted if event["event"] == "RESOURCE_ADMITTED")
    assert admitted["queue_delay_ms"] == 700000
    assert admitted["admission_timeout_seconds"] == 3600
    assert not any(event["event"] == "RESOURCE_TIMED_OUT" for event in emitted)
    metrics = aggregate_run_metrics(tmp_path / "run")
    admission_metric = next(value for value in metrics["resource_admissions"]
                            if value["stage"] == f"scanner.{tool_id}")
    assert admission_metric["status"] == "ADMITTED"
    assert admission_metric["queue_delay_ms"] == 700000
    assert admission_metric["admission_timeout_seconds"] == 3600
    assert json.loads((metadata / "resource-admission" / "leases.json").read_text())["leases"] == {}


def test_scanner_admission_expires_without_launching_or_reclaiming_live_holder(tmp_path, monkeypatch):
    metadata = tmp_path / "metadata"
    event_path = tmp_path / "events.jsonl"
    events = EventLog(event_path, PipelineLog(tmp_path / "run"), {"run_id": tmp_path.name})
    budget = ResourceBudget(io_slots=1)
    admission = resources.ResourceAdmission(metadata, budget)
    holder_context = Context()
    holder = holder_context.run(
        admission.reserve, resources.Reservation(2, 1536), events=events, action="holder.fixture")
    holder_id = holder_context.run(holder.__enter__)
    clock = 0.0

    def advance(_delay):
        nonlocal clock
        clock += 100

    def never_run(_argv, _timeout):
        pytest.fail("scanner or image control started before admission")

    monkeypatch.setattr(resources.time, "monotonic", lambda: clock)
    monkeypatch.setattr(resources.time, "sleep", advance)
    target = tmp_path / "target"
    target.mkdir()
    try:
        with resources.review_resource_scope(metadata, budget, events):
            with pytest.raises(TimeoutError, match="admission timed out waiting for aggregate capacity"):
                ContainerExecutor(_catalog(tmp_path, "tool-syft", 300), tmp_path / "run",
                                  runner=never_run).execute(
                    ExecutionRequest("tool-syft", ("/bin/fixture",), target, tmp_path / "run" / "scratch"))
        assert set(json.loads((metadata / "resource-admission" / "leases.json").read_text())["leases"]) == {
            holder_id}
        emitted = [event for event in _events(event_path) if event.get("operation_id") == "scanner.tool-syft"]
        timeout = next(event for event in emitted if event["event"] == "RESOURCE_TIMED_OUT")
        assert timeout["queue_delay_ms"] == 300000
        assert timeout["admission_timeout_seconds"] == 300
        assert not any(event["event"] == "RESOURCE_ADMITTED" for event in emitted)
        admission_metric = next(value for value in aggregate_run_metrics(tmp_path / "run")["resource_admissions"]
                                if value["stage"] == "scanner.tool-syft")
        assert admission_metric["status"] == "TIMED_OUT"
        assert admission_metric["queue_delay_ms"] == 300000
        assert admission_metric["admission_timeout_seconds"] == 300
    finally:
        holder_context.run(holder.__exit__, None, None, None)


def test_scanner_execution_timeout_remains_a_failure_with_longer_admission_budget(tmp_path):
    calls = []

    def runner(argv, timeout):
        argv = tuple(argv)
        calls.append((argv, timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            return CommandOutcome(0, DIGEST.encode(), b"")
        if argv[:2] == ("docker", "run"):
            assert timeout == 600
            return CommandOutcome(None, b"", b"scanner execution timed out", timed_out=True)
        if argv[:2] in {("docker", "kill"), ("docker", "rm")}:
            return CommandOutcome(0, b"", b"")
        if argv[:3] == ("docker", "container", "inspect"):
            return CommandOutcome(0, b"false", b"")
        raise AssertionError(argv)

    target = tmp_path / "target"
    target.mkdir()
    result = ContainerExecutor(_catalog(tmp_path, "tool-gitleaks"), tmp_path / "run",
                               runner=runner).execute(
        ExecutionRequest("tool-gitleaks", ("/bin/fixture",), target, tmp_path / "run" / "scratch"))
    assert result.timed_out and result.terminal_status == "TIMEOUT"
    assert result.limits["timeout_seconds"] == 600
    assert result.limits["admission_timeout_seconds"] == 3600
    assert len([argv for argv, _timeout in calls if argv[:2] == ("docker", "run")]) == 1


def test_legacy_resource_admission_metrics_do_not_fabricate_a_queue_budget(tmp_path):
    EventLog(tmp_path / "events.jsonl", PipelineLog(tmp_path), {"run_id": tmp_path.name}).write(
        "RESOURCE_TIMED_OUT", span_id="legacy", operation_id="scanner.tool-syft", queue_delay_ms=600000)
    metric, = aggregate_run_metrics(tmp_path)["resource_admissions"]
    assert metric["queue_delay_ms"] == 600000
    assert metric["admission_timeout_seconds"] is None


@pytest.mark.parametrize("value", (None, 0, -1, True, 3.5, "3600"))
def test_scanner_admission_budget_requires_explicit_positive_integer(tmp_path, value):
    original = catalog(tmp_path)
    with pytest.raises(ValueError, match="admission_timeout_seconds"):
        replace(original, policy=MappingProxyType({**original.policy, "admission_timeout_seconds": value}))


def test_scanner_admission_budget_cannot_be_omitted(tmp_path):
    original = catalog(tmp_path)
    with pytest.raises(ValueError, match="admission_timeout_seconds"):
        replace(original, policy=MappingProxyType({
            key: value for key, value in original.policy.items() if key != "admission_timeout_seconds"}))


def test_central_admission_budget_does_not_change_baked_tool_execution_limits():
    loaded = load_catalog(Path(__file__).resolve().parents[1])
    assert loaded.admission_timeout_seconds == 3600
    for tool_id in ("tool-checkov", "tool-syft", "tool-gitleaks"):
        tool = loaded.tool(tool_id)
        assert tool.timeout_seconds == 600
        assert tool.cpus == "2" and tool.memory == "1g"
        assert "admission_timeout_seconds" not in tool.metadata
