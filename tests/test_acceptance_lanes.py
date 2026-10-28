from multiprocessing import get_context
from pathlib import Path
import time

import pytest

from appsec_review.acceptance.lanes import LaneSpec, LaneTier, LaneWorkspace
from appsec_review.observability.events import PipelineLog


def _review_heartbeat(root, ready, stop) -> None:
    pipeline = PipelineLog(Path(root))
    deadline = time.monotonic() + 20
    while not stop.is_set() and time.monotonic() < deadline:
        pipeline.write("REVIEW_HEARTBEAT", run_id="simulated-running-review")
        ready.set()
        stop.wait(0.01)


def test_lane_contract_bounds_selection_and_workers() -> None:
    spec = LaneSpec("review-chain", ("tests/test_final_report.py",))
    assert spec.tier is LaneTier.HERMETIC
    for changes in ({"workers": 3}, {"workers": True}, {"deadline_seconds": 0},
                    {"nodes": ()}, {"case_deadline_seconds": 721}, {"name": "../runs"}):
        with pytest.raises(ValueError):
            LaneSpec(**{"name": spec.name, "nodes": spec.nodes, **changes})


def test_control_fixture_selects_only_explicitly_pinned_abridged_catalogs(tmp_path: Path) -> None:
    from appsec_review.owasp_workbench.standards import load_catalogs
    from tests.integration.test_control_evidence_acceptance import ROOT, _prepare

    workspace = LaneWorkspace.create(tmp_path, "control-config")
    config, _ = _prepare(workspace)
    settings = config.job("job_owasp_control_assessment").settings["standards"]
    catalogs = load_catalogs(ROOT, settings)
    assert len(catalogs) == 5
    assert all(catalog.fixture and catalog.coverage["completeness"] == "abridged_fixture"
               for catalog in catalogs.values())
    assert all(source["catalog_path"].startswith("tests/fixtures/acceptance_controls/owasp/")
               for source in settings.values())


def test_acceptance_uses_isolated_roots_and_production_telemetry(tmp_path: Path) -> None:
    production = tmp_path / "runs" / "live"
    production.mkdir(parents=True)
    sentinel = production / "metrics.json"
    sentinel.write_bytes(b"live-review-metrics")
    first = LaneWorkspace.create(tmp_path, "review-chain")
    second = LaneWorkspace.create(tmp_path, "review-chain")
    assert first.root != second.root
    assert first.root.is_relative_to(tmp_path / "test" / "tmp" / "acceptance")
    assert first.runs_dir != tmp_path / "runs"
    with first.span("acceptance.case"):
        first.emit("ACCEPTANCE_CASE_COMPLETED", duration_ms=1.25, outcome="passed")
    records, torn = first.pipeline.read()
    assert not torn
    assert [row["event_type"] for row in records] == [
        "OPERATION_STARTED", "ACCEPTANCE_CASE_COMPLETED", "OPERATION_COMPLETED"]
    assert all(row["schema"] == "appsec-review/telemetry-event/1" for row in records)
    assert all(row["trigger"] == "acceptance" for row in records)
    assert records[-1]["details"]["duration_ms"] >= 0
    assert records[-1]["details"]["resources"]["cpu_user_seconds"] >= 0
    assert sentinel.read_bytes() == b"live-review-metrics"


def test_owned_paths_cannot_escape_or_select_production_state(tmp_path: Path) -> None:
    workspace = LaneWorkspace.create(tmp_path, "signals")
    assert workspace.require_owned_path(workspace.runs_dir) == workspace.runs_dir
    with pytest.raises(ValueError, match="inside"):
        workspace.require_owned_path(tmp_path / "runs")
    assert all(key.startswith("APPSEC_ACCEPTANCE_") for key in workspace.environment())


def test_redirected_scratch_is_refused(tmp_path: Path) -> None:
    (tmp_path / "test").mkdir()
    target = tmp_path / "runs"
    target.mkdir()
    try:
        (tmp_path / "test" / "tmp").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("host cannot create directory symlinks")
    with pytest.raises(ValueError, match="redirected"):
        LaneWorkspace.create(tmp_path, "signals")
    assert not list(target.iterdir())


def test_acceptance_metrics_remain_separate_while_an_owned_review_process_runs(tmp_path: Path) -> None:
    context = get_context("spawn")
    ready, stop = context.Event(), context.Event()
    review_root = tmp_path / "simulated-review"
    process = context.Process(target=_review_heartbeat, args=(str(review_root), ready, stop))
    process.start()
    try:
        assert ready.wait(10), "owned simulated review did not start"
        assert process.is_alive()
        workspace = LaneWorkspace.create(tmp_path, "concurrent-review")
        with workspace.span("acceptance.concurrent"):
            for ordinal in range(10):
                workspace.emit("ACCEPTANCE_SAMPLE", ordinal=ordinal)
        assert process.is_alive(), "acceptance interrupted the owned review process"
    finally:
        stop.set()
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join(5)
        assert not process.is_alive(), "owned simulated review process was not cleaned up"
    assert process.exitcode == 0
    acceptance, torn = workspace.pipeline.read()
    review, review_torn = PipelineLog(review_root).read()
    assert not torn and not review_torn and len(review) >= 1
    assert all(row["run_id"] == workspace.invocation_id for row in acceptance)
    assert all(row["run_id"] == "simulated-running-review" for row in review)
    assert all(row["event_type"] == "REVIEW_HEARTBEAT" for row in review)
    assert acceptance[-1]["details"]["resources"]["measurement_scope"] == "process_inclusive_not_additive"
