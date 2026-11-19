from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_dependency_intelligence.job import build_job as dependency_job
from appsec_review.jobs.job_openvex_export import contracts as c, inputs
from appsec_review.jobs.job_openvex_export.datasets import CONTRACT
from appsec_review.jobs.job_openvex_export.dependencies import DEPENDENCY_JOB, dependency_projection
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.inputs import input_read_scope
from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT
from tests.test_openvex_job_units import ExportUnits


def dependency(disk, *, include_reachability=True, source_fingerprint=None):
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
        "schema": "appsec-review/sca-reachability/1",
        "source_fingerprint": source_fingerprint or disk.snapshot,
        "configured_osv_mode": "index", "osv_matching_mode": "index",
        "advisories": [advisory, unreachable],
        "telemetry": {"advisories_matched": 2, "osv_matching_mode": "index",
                      "symbol_reachable_count": 1, "ffi_boundary_matches": 0},
    }
    prefix = f"data/jobs/{DEPENDENCY_JOB}/attempts/attempt_0001"
    ref = disk.put(f"{prefix}/sca-reachability.json", document)
    discovery = disk.put(f"{prefix}/native-discovery.json", {"candidates": []})
    # Execute the real producer's publication unit, not its external acquisition/inference stages.
    outputs = {
        "inputs.load_accepted": {
            "upstream_handoffs": {},
            "unity_inventory_artifact": disk.put(f"{prefix}/unity.json", {"packages": []}),
        },
        "resolution.detect_dependencies": {"native_discovery": discovery},
        "resolution.curate_components": {"artifact": disk.put(f"{prefix}/curation.json", {})},
        "resolution.investigate_components": {
            "native_discovery": discovery, "artifact": disk.put(f"{prefix}/metadata.json", {}),
        },
        "resolution.infer_repositories": {"dependencies": [
            {"dependency_id": "dep-1", "name": "example", "version": "1.0", "purl": "pkg:pypi/example@1.0"},
        ]},
        "repositories.deduplicate": {"repositories": []},
        "scorecards.fetch": {"records": [], "request_count": 0, "repository_count": 0, "cache_hit_count": 0},
        "publication.publish_context": {
            "index_identity": {}, "index_manifest": disk.manifest_ref, "gaps": [],
            "telemetry": document["telemetry"],
            **({"sca_reachability": ref} if include_reachability else {}),
        },
        "publication.publish_sbom": {},
        "publication.native_advisory_lookup": {},
    }
    unit = next(unit for unit in dependency_job().units if unit.unit_id == "acceptance.publish_handoff")
    step, task = unit.unit_id.split(".")
    unit_root = disk.root / prefix / "steps" / step / "tasks" / task
    unit_root.mkdir(parents=True)
    context = UnitContext(
        SimpleNamespace(run_root=disk.root, source_fingerprint=disk.snapshot),
        unit.unit_id, step, task, unit_root, outputs,
    )
    published = dict(unit.handler(context))
    handoff = disk.handoff(DEPENDENCY_JOB, {unit.unit_id: published})
    handoff["attempt_id"] = "attempt_0001"
    accepted = disk.publish(DEPENDENCY_JOB, handoff)
    return ref, accepted


def test_real_openvex_units_publish_conservative_dependency_companion_and_reject_tampering(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reference, accepted = dependency(disk)
    units = ExportUnits(disk)
    pins = {inputs.GATE_JOB: disk.gate_job_ref["sha256"], inputs.REVIEW_JOB: disk.review_job_ref["sha256"],
            DEPENDENCY_JOB: accepted["sha256"]}
    with input_read_scope(replace(units.context, contract=CONTRACT, upstream_handoffs=pins)) as reads:
        assembled = units.assemble()
        result = units.execute("acceptance.publish_handoff")
        companion = assembled["dependencies"]
        assert result["dependencies"] == companion
        assert companion["statements_by_status"] == {"affected": 1, "not_affected": 0, "under_investigation": 1}
        doc = json.loads((disk.root / companion["document"]["path"]).read_bytes())
        assert [row["status"] for row in doc["statements"]] == ["affected", "under_investigation"]
        assert all("justification" not in row for row in doc["statements"])
        assert companion["gaps"] and result["terminal_status"] == "COMPLETED_WITH_GAPS"
        accounting = json.loads((disk.root / companion["artifact"]["path"]).read_bytes())
        assert accounting["source"] == {
            "handoff": accepted, "artifact": reference, "gate": disk.gate_ref,
        }
        observed = [row for row in reads.document()["reads"]
                    if row["producer"] == DEPENDENCY_JOB and row["output_kind"] == "handoff"]
        assert len(observed) == 1
        assert observed[0]["handoff_sha256"] == accepted["sha256"]
        assert observed[0]["attempt_id"] == "attempt_0001"
        assert observed[0]["target_snapshot"] == disk.snapshot
        assert observed[0]["read"] is True
    with upstream_scope(disk.root, c.JOB_ID, pins, contract=CONTRACT):
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
    reference, accepted = dependency(disk)
    handoff = json.loads((disk.root / accepted["path"]).read_bytes())
    newer = deepcopy(handoff)
    newer["attempt_id"] = "attempt_0002"
    disk.publish(DEPENDENCY_JOB, newer)
    with upstream_scope(disk.root, c.JOB_ID, {DEPENDENCY_JOB: accepted["sha256"]}, contract=CONTRACT):
        result = inputs._accepted(inputs.BoundedInputReader(disk.root, disk.settings), DEPENDENCY_JOB)
        assert result.sha256 == accepted["sha256"]
    units = ExportUnits(disk)
    pins = {inputs.GATE_JOB: disk.gate_job_ref["sha256"], inputs.REVIEW_JOB: disk.review_job_ref["sha256"],
            DEPENDENCY_JOB: accepted["sha256"]}
    with upstream_scope(disk.root, c.JOB_ID, pins, contract=CONTRACT):
        companion = units.assemble()["dependencies"]
    accounting = json.loads((disk.root / companion["artifact"]["path"]).read_bytes())
    assert accounting["source"]["handoff"] == accepted
    assert accounting["source"]["artifact"] == reference


@pytest.mark.parametrize(("mutation", "reason"), [
    ("missing", c.ExportFailureReason.INPUT_MISSING),
    ("tampered", c.ExportFailureReason.INPUT_TAMPERED),
    ("snapshot", c.ExportFailureReason.IDENTITY_CONFLICT),
])
def test_dependency_publication_refuses_missing_or_conflicting_reachability(tmp_path, monkeypatch, mutation, reason):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reference, accepted = dependency(
        disk, include_reachability=mutation != "missing",
        source_fingerprint="f" * 64 if mutation == "snapshot" else None,
    )
    if mutation == "tampered":
        (disk.root / reference["path"]).write_bytes(b"{}")
    units = ExportUnits(disk)
    pins = {inputs.GATE_JOB: disk.gate_job_ref["sha256"], inputs.REVIEW_JOB: disk.review_job_ref["sha256"],
            DEPENDENCY_JOB: accepted["sha256"]}
    with upstream_scope(disk.root, c.JOB_ID, pins, contract=CONTRACT):
        with pytest.raises(c.ExportError) as error:
            units.execute("load.verify_inputs")
    assert error.value.reason == reason


def test_dependency_publication_requires_the_certified_configuration(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    _, accepted = dependency(disk)
    verified = inputs.verify_inputs(disk.root, disk.settings, ROOT)
    configuration = c.ArtifactRef.from_mapping(disk.put("data/configuration/other.json", {}))
    verified = replace(
        verified, provenance=replace(verified.provenance, resolved_configuration=configuration),
        input_inventory=(*verified.input_inventory, c.SizedArtifactRef(
            configuration.path, configuration.sha256, (disk.root / configuration.path).stat().st_size)),
    )
    with upstream_scope(disk.root, c.JOB_ID, {DEPENDENCY_JOB: accepted["sha256"]}, contract=CONTRACT):
        with pytest.raises(c.ExportError, match="configuration differs") as error:
            dependency_projection(disk.root, verified, disk.settings, ROOT, "test-release")
    assert error.value.reason == c.ExportFailureReason.IDENTITY_CONFLICT
