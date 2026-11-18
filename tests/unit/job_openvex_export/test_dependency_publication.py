from copy import deepcopy
import json

import pytest

from appsec_review.jobs.job_openvex_export import contracts as c, inputs
from appsec_review.jobs.job_openvex_export.datasets import CONTRACT
from appsec_review.jobs.job_openvex_export.dependencies import DEPENDENCY_JOB
from appsec_review.runtime.consume import upstream_scope
from tests.openvex_input_support import AcceptedInputDisk
from tests.test_openvex_job_units import ExportUnits


def dependency(disk):
    advisory = {
        "advisory_id": "CVE-2026-12345", "cve_ids": ["CVE-2026-12345"],
        "package_name": "example", "package_version": "1.0", "purl": "pkg:pypi/example@1.0",
        "ecosystem": "pypi", "severity": "high", "direct": True, "match_sources": ["accepted-osv"],
        "affected_symbols": ["parse"], "affected_modules": ["example"], "reachability": "symbol_reachable",
        "ffi_mechanisms": [], "call_sites": [{"path": "source.py", "line": 3, "symbol": "parse"}],
        "dependency_ids": ["dep-1"],
    }
    unreachable = {**advisory, "advisory_id": "CVE-2026-12346", "cve_ids": ["CVE-2026-12346"],
                   "reachability": "unreachable_in_target", "call_sites": []}
    document = {
        "schema": "appsec-review/sca-reachability/1", "source_fingerprint": disk.snapshot,
        "configured_osv_mode": "index", "osv_matching_mode": "index",
        "advisories": [advisory, unreachable],
        "telemetry": {"advisories_matched": 2, "osv_matching_mode": "index",
                      "symbol_reachable_count": 1, "ffi_boundary_matches": 0},
    }
    ref = disk.put(f"data/jobs/{DEPENDENCY_JOB}/attempts/attempt_0001/sca-reachability.json", document)
    handoff = disk.handoff(DEPENDENCY_JOB, {"publication.publish_handoff": {"sca_reachability": ref, "gaps": []}})
    handoff["attempt_id"] = "attempt_0001"
    accepted = disk.publish(DEPENDENCY_JOB, handoff)
    return ref, accepted


def test_real_openvex_units_publish_conservative_dependency_companion_and_reject_tampering(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    _, accepted = dependency(disk)
    units = ExportUnits(disk)
    pins = {inputs.GATE_JOB: disk.gate_job_ref["sha256"], inputs.REVIEW_JOB: disk.review_job_ref["sha256"],
            DEPENDENCY_JOB: accepted["sha256"]}
    with upstream_scope(disk.root, c.JOB_ID, pins, contract=CONTRACT):
        assembled = units.assemble()
        result = units.execute("acceptance.publish_handoff")
        companion = assembled["dependencies"]
        assert result["dependencies"] == companion
        assert companion["statements_by_status"] == {"affected": 1, "not_affected": 0, "under_investigation": 1}
        doc = json.loads((disk.root / companion["document"]["path"]).read_bytes())
        assert [row["status"] for row in doc["statements"]] == ["affected", "under_investigation"]
        assert all("justification" not in row for row in doc["statements"])
        assert companion["gaps"] and result["terminal_status"] == "COMPLETED_WITH_GAPS"
        (disk.root / companion["document"]["path"]).write_bytes(b"{}")
        with pytest.raises(c.ExportError):
            units.execute("acceptance.publish_handoff")


def test_unadmitted_dependency_pointer_is_not_consumed_and_gate_pin_survives_pointer_movement(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    dependency(disk)
    units = ExportUnits(disk)
    pins = {inputs.GATE_JOB: disk.gate_job_ref["sha256"], inputs.REVIEW_JOB: disk.review_job_ref["sha256"]}
    with upstream_scope(disk.root, c.JOB_ID, pins, contract=CONTRACT):
        assert units.assemble()["dependencies"] is None
    # A direct declared read without its required pin is rejected, even though latest exists.
    with upstream_scope(disk.root, c.JOB_ID, {}, contract=CONTRACT):
        with pytest.raises(c.ExportError):
            inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), inputs.GATE_JOB)


def test_pinned_dependency_is_not_replaced_by_a_newer_accepted_pointer(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    _, accepted = dependency(disk)
    handoff = json.loads((disk.root / accepted["path"]).read_bytes())
    newer = deepcopy(handoff)
    newer["attempt_id"] = "attempt_0002"
    disk.publish(DEPENDENCY_JOB, newer)
    with upstream_scope(disk.root, c.JOB_ID, {DEPENDENCY_JOB: accepted["sha256"]}, contract=CONTRACT):
        result = inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), DEPENDENCY_JOB)
        assert result.sha256 == accepted["sha256"]
