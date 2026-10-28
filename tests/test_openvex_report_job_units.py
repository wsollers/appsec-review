from __future__ import annotations

from dataclasses import replace
import json

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_final_report_publication.job import build_job
from appsec_review.jobs.job_openvex_export.contracts import ExportError
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import UnitContext
from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT, enabled_settings
from tests.test_openvex_job_units import ExportUnits

REPORT = "job_final_report_publication"


class ReportUnits:
    def __init__(self, exports):
        self.exports = exports
        self.job = build_job(repository_root=ROOT)
        config = load_config(ROOT / "appsec-review.toml", profile="dev", overlay="")
        attempt = exports.disk.root / "data" / "jobs" / REPORT / "attempts" / "unit"
        self.context = replace(
            exports.context, attempt_root=attempt, config=config.job(REPORT),
            events=EventLog(attempt / "logs" / "events.jsonl"),
        )
        self.outputs = {}

    def execute(self, unit_id):
        unit = next(unit for unit in self.job.units if unit.unit_id == unit_id)
        step, task = unit_id.split(".")
        path = self.context.attempt_root / "steps" / step / "tasks" / task
        path.mkdir(parents=True, exist_ok=True)
        result = unit.handler(UnitContext(self.context, unit_id, step, task, path, self.outputs))
        self.outputs[unit_id] = dict(result)
        return result

    def assemble(self):
        self.execute("load.accepted_gate")
        self.execute("report.assemble")
        self.execute("report.render")
        return json.loads((self.exports.disk.root / self.outputs["report.assemble"]["artifact"]["path"]).read_bytes())


@pytest.mark.parametrize("state", ["disabled", "not_run", "available", "no_statements"])
def test_report_handlers_reprove_optional_export_and_preserve_gate_decisions(tmp_path, monkeypatch, state):
    settings = enabled_settings(enabled=state != "disabled")
    disk = AcceptedInputDisk(tmp_path, monkeypatch, settings=settings,
                             buckets=() if state == "no_statements" else ("publishable",))
    exports = ExportUnits(disk)
    if state in {"available", "no_statements"}:
        exports.assemble()
        exports.accept()
    reports = ReportUnits(exports)
    report = reports.assemble()
    reports.execute("acceptance.publish_handoff")
    assert report["openvex_export"]["state"] == state
    assert report["summary"]["package_counts"] == disk.gate["package_counts"]
    assert report["summary"]["ship_block"] == disk.gate["ship_block"]
    assert report["status"]["review"] == disk.gate["review"]["status"]
    if state in {"not_run", "no_statements"}:
        assert any(row["limitation_id"] == f"openvex_export_{state}" for row in report["limitations"])
    else:
        assert report["limitations"] == disk.gate["limitations"]


def test_report_acceptance_rejects_an_export_arriving_after_assembly(tmp_path, monkeypatch):
    exports = ExportUnits(AcceptedInputDisk(tmp_path, monkeypatch))
    reports = ReportUnits(exports)
    assert reports.assemble()["openvex_export"]["state"] == "not_run"
    exports.assemble()
    exports.accept()
    with pytest.raises(IntegrityError, match="OpenVEX acceptance changed"):
        reports.execute("acceptance.publish_handoff")


def test_report_load_fails_on_corrupt_export_not_a_not_run_fallback(tmp_path, monkeypatch):
    exports = ExportUnits(AcceptedInputDisk(tmp_path, monkeypatch))
    exports.assemble()
    exports.accept()
    reference = exports.result()["document"]
    path = exports.disk.root / reference["path"]
    path.write_bytes(b"{}")
    with pytest.raises(ExportError):
        ReportUnits(exports).execute("load.accepted_gate")
