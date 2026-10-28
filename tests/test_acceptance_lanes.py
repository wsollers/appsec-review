from pathlib import Path

import pytest

from appsec_review.acceptance.lanes import LaneSpec, LaneTier, LaneWorkspace


def test_lane_contract_bounds_selection_and_workers() -> None:
    spec = LaneSpec("review-chain", ("tests/test_final_report.py",))
    assert spec.tier is LaneTier.HERMETIC
    for changes in ({"workers": 3}, {"workers": True}, {"deadline_seconds": 0},
                    {"nodes": ()}, {"case_deadline_seconds": 721}, {"name": "../runs"}):
        with pytest.raises(ValueError):
            LaneSpec(**{"name": spec.name, "nodes": spec.nodes, **changes})


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
