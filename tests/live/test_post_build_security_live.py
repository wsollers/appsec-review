"""Live Dagster post-build security assessment acceptance check."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("dagster")

from appsec_review.orchestration.dagster import build_definitions

pytestmark = pytest.mark.live


@pytest.mark.skipif(
    not os.environ.get("APPSEC_CPP_ACCEPTANCE_TARGET"),
    reason="live 12-case C++ acceptance target/image was not supplied",
)
def test_live_cpp_post_build_acceptance_uses_real_dagster_path(monkeypatch: pytest.MonkeyPatch) -> None:
    target = Path(os.environ["APPSEC_CPP_ACCEPTANCE_TARGET"]).resolve(strict=True)
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config = Path(__file__).resolve().parents[2] / "appsec-review.toml"
    result = build_definitions(config).get_job_def("wave1_review").execute_in_process()
    assert result.success
    run_ids = set()
    for event in result.all_node_events:
        if event.is_step_output and event.step_key == "post_build_security_assessment__finalize":
            metadata = event.event_specific_data.metadata
            if "application_run_id" in metadata:
                run_ids.add(metadata["application_run_id"].value)
    assert len(run_ids) == 1
    run_root = config.parent / "runs" / run_ids.pop()
    accepted = json.loads((run_root / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
    assert "build-security" in accepted["manifest_path"]
