"""The end-of-review telemetry report hooks, the ``telemetry`` CLI and the scripts' ``--kind``."""
from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config.telemetry_report import TelemetryReportSettings
from appsec_review.reporting import telemetry_finalize
from appsec_review.reporting.__main__ import main
from appsec_review.reporting.telemetry_finalize import finalize_telemetry_report
from appsec_review.reporting.telemetry_render import TelemetryReportReceipt

from .telemetry_fixture import RUN_ID, build_telemetry_run

ROOT = Path(__file__).resolve().parents[2]


def _receipt(status: str, report_dir: Path | None = None) -> TelemetryReportReceipt:
    return TelemetryReportReceipt(MappingProxyType({"run_id": RUN_ID, "status": status, "named_gaps": [],
                                                    "files": []}), report_dir)


def test_finalize_passes_settings_and_root_and_returns_the_receipt(tmp_path: Path) -> None:
    calls = []
    settings = TelemetryReportSettings(render_pdf=False)

    def renderer(run_dir, given, *, repository_root):
        calls.append((run_dir, given, repository_root))
        return _receipt("tex_only")

    receipt = finalize_telemetry_report(tmp_path / "run", settings, repository_root=tmp_path, renderer=renderer)
    assert receipt.status == "tex_only"
    assert calls == [(tmp_path / "run", settings, tmp_path)]


def test_finalize_swallows_renderer_errors_and_logs_once(tmp_path: Path, caplog) -> None:
    def renderer(*_args, **_kwargs):
        raise RuntimeError("secret detail never logged")

    with caplog.at_level(logging.WARNING, logger=telemetry_finalize.__name__):
        assert finalize_telemetry_report(tmp_path / "run-x", TelemetryReportSettings(), renderer=renderer) is None
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "RuntimeError" in message and "run-x" in message and "secret detail" not in message


def test_finalize_is_a_no_op_when_disabled(tmp_path: Path) -> None:
    def renderer(*_args, **_kwargs):
        raise AssertionError("must not render")

    assert finalize_telemetry_report(tmp_path, TelemetryReportSettings(enabled=False), renderer=renderer) is None
    assert not tmp_path.joinpath("data").exists()


def _calls_in(function: ast.FunctionDef) -> list[str]:
    return [node.func.id for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]


def test_dagster_complete_op_reports_after_its_final_metrics() -> None:
    tree = ast.parse((ROOT / "src/appsec_review/orchestration/dagster/adapter.py").read_text(encoding="utf-8"))
    complete = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "complete")
    body = [ast.unparse(statement) for statement in complete.body]
    metrics = body.index("write_run_metrics(run_root)")
    assert body[metrics + 1] == ("finalize_telemetry_report(run_root, config.telemetry_report, "
                                 "repository_root=config.runtime.repository_root)")
    assert _calls_in(complete).count("finalize_telemetry_report") == 1
    assert "telemetry_report=config.telemetry_report" in ast.unparse(tree)


@pytest.fixture
def error_state():
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import error_state as module
    return module


def _failed_run_root(tmp_path: Path, application_id: str = "2026-10-29-0001") -> Path:
    root = tmp_path / application_id
    manifest = root / "data/configuration/manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"failure_finalization": "appsec-review/split-failure-finalization/1"}))
    return root


@pytest.mark.parametrize("status", ["FAILURE", "CANCELED"])
def test_failed_and_cancelled_runs_report_after_metrics_on_both_paths(tmp_path: Path, monkeypatch, error_state,
                                                                       status) -> None:
    status = getattr(error_state.DagsterRunStatus, status)
    root = _failed_run_root(tmp_path)
    order = []
    monkeypatch.setattr(error_state, "write_run_metrics", lambda path: order.append(("metrics", path)))
    monkeypatch.setattr(error_state, "finalize_telemetry_report",
                        lambda path, settings, *, repository_root: order.append(("report", path, settings,
                                                                                 repository_root)))
    source = SimpleNamespace(run_id="dagster-1", status=status,
                             tags={"appsec/application_run_id": root.name, "appsec/trigger": "manual"})
    instance = SimpleNamespace(
        get_run_by_id=lambda _run_id: SimpleNamespace(**vars(source), job_name="wave1_review"),
        get_records_for_run=lambda *_args, **_kwargs: SimpleNamespace(records=[]))
    settings = TelemetryReportSettings(render_pdf=False)
    for _attempt in range(2):  # first finalization, then the idempotent repeat (receipt already exists)
        error_state.record_error_state(instance, "dagster-1", tmp_path, telemetry_report=settings,
                                       repository_root=tmp_path)
    assert order == [("metrics", root), ("report", root, settings, tmp_path)] * 2
    records = [json.loads(line) for line in (root / "data/logs/pipeline.jsonl").read_text().splitlines()]
    assert [record["event_type"] for record in records][-1] == "RUN_COMPLETED"


def test_error_state_without_settings_or_for_legacy_runs_never_reports(tmp_path: Path, monkeypatch,
                                                                       error_state) -> None:
    monkeypatch.setattr(error_state, "write_run_metrics", lambda path: None)
    monkeypatch.setattr(error_state, "finalize_telemetry_report",
                        lambda *_args, **_kwargs: pytest.fail("must not report"))
    root = _failed_run_root(tmp_path)
    failure = error_state.DagsterRunStatus.FAILURE
    source = SimpleNamespace(run_id="d", status=failure, job_name="wave1_review",
                             tags={"appsec/application_run_id": root.name})
    instance = SimpleNamespace(get_run_by_id=lambda _run_id: source,
                               get_records_for_run=lambda *_args, **_kwargs: SimpleNamespace(records=[]))
    error_state.record_error_state(instance, "d", tmp_path)
    legacy = SimpleNamespace(run_id="e", status=failure, job_name="wave1_review",
                             tags={"appsec/application_run_id": "missing-run"})
    instance.get_run_by_id = lambda _run_id: legacy
    error_state.record_error_state(instance, "e", tmp_path, telemetry_report=TelemetryReportSettings())


def test_cli_tex_writes_the_report_without_docker(tmp_path: Path, capsys) -> None:
    run_dir = build_telemetry_run(tmp_path / "runs")
    out = tmp_path / "out"
    assert main(["telemetry", "--run", RUN_ID, "--runs-dir", str(tmp_path / "runs"), "--out", str(out)]) == 0
    tex = (out / "telemetry-report.tex").read_text(encoding="utf-8")
    assert RUN_ID in tex and "\\documentclass" in tex
    assert json.loads(capsys.readouterr().out)["format"] == "tex"
    assert not (run_dir / "data/telemetry/report").exists()


@pytest.mark.parametrize("status, code", [("rendered", 0), ("tex_only", 0), ("failed", 1), ("disabled", 1)])
def test_cli_pdf_maps_receipt_status_to_exit_code(tmp_path: Path, capsys, status, code) -> None:
    run_dir = build_telemetry_run(tmp_path / "runs")
    seen = []

    def renderer(run, settings, *, repository_root):
        seen.append((run, settings, repository_root))
        return _receipt(status, None if status == "disabled" else run / "data/telemetry/report")

    assert main(["telemetry", "--run", str(run_dir), "--format", "pdf"], telemetry_renderer=renderer) == code
    assert seen == [(run_dir, TelemetryReportSettings(), None)]
    assert json.loads(capsys.readouterr().out)["status"] == status


def test_cli_usage_errors_exit_2(tmp_path: Path, capsys) -> None:
    build_telemetry_run(tmp_path / "runs")
    assert main(["telemetry", "--run", RUN_ID, "--runs-dir", str(tmp_path / "runs"), "--format", "tex"]) == 2
    assert main(["telemetry", "--run", "missing", "--runs-dir", str(tmp_path / "runs")]) == 2
    with pytest.raises(SystemExit) as exited:
        main(["telemetry", "--run", RUN_ID, "--format", "html"])
    assert exited.value.code == 2
