from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_dependency_intelligence.job import build_job as dependency_job
from appsec_review.jobs.job_dependency_intelligence.reachability import (
    DependencyIntelligenceSettings, evaluate_sca_reachability,
)
from appsec_review.interchange import GapCode, producer_gap, validate_unit_output
from appsec_review.jobs.job_openvex_export import contracts as c, inputs
from appsec_review.jobs.job_openvex_export.datasets import CONTRACT
from appsec_review.jobs.job_openvex_export.dependencies import DEPENDENCY_JOB, dependency_projection
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.inputs import input_read_scope
from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT, enabled_settings
from tests.test_openvex_job_units import ExportUnits


def dependency(disk, *, include_reachability=True, source_fingerprint=None, document=None, gaps=()):
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
    document = document if document is not None else {
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
            "index_identity": {}, "index_manifest": disk.manifest_ref, "gaps": list(gaps),
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


def produced_reachability(disk, *, scenario="reachable"):
    """Run the actual SCA serializer over tiny, hash-bound Python/non-Python inputs."""
    target = disk.root / "source-fixture"
    target.mkdir()
    native = scenario == "native"
    source = b'import example\nexample.parse("input")\n'
    if native:
        source = b'import example from "example"; example.parse("input");\n'
    path = target / ("main.js" if native else "main.py")
    path.write_bytes(source)
    dependencies = [{
        "dependency_id": "dep-1", "name": "example", "version": "1.0",
        "purl": "pkg:pypi/example@1.0", "ecosystem": "pypi", "direct": True,
    }]
    observation = {
        "advisory": "CVE-2026-12345", "package": "example", "version": "1.0",
        "purl": "pkg:pypi/example@1.0", "ecosystem": "pypi",
        "affected_symbols": ["example.parse"], "affected_modules": ["example"],
    }
    if scenario in {"null", "null-version", "no-purl", "invalid-purl"}:
        observation["purl"] = "not-a-package-url" if scenario == "invalid-purl" else None
        if scenario == "null":
            observation["ecosystem"] = None
        if scenario == "null-version":
            observation["version"] = None
    elif scenario == "null-metadata":
        observation.update(purl="pkg:pypi/example", ecosystem=None, version=None)
    elif scenario == "ambiguous":
        dependencies.append({
            **dependencies[0], "dependency_id": "dep-2", "version": "2.0", "purl": "pkg:pypi/example@2.0",
        })
    observations = [] if scenario == "empty" else [observation]
    if scenario == "mixed":
        observations.append({**observation, "advisory": "CVE-2026-12346", "purl": None, "ecosystem": None})
    return evaluate_sca_reachability(
        source_fingerprint=disk.snapshot, repository_root=ROOT, run_root=disk.root,
        target_root=target, dependencies=dependencies,
        scanner_advisories=observations,
        partition_files=[{"path": path.name, "sha256": hashlib.sha256(source).hexdigest()}],
        settings=DependencyIntelligenceSettings(osv_version_matching="disabled"),
    )


def admitted(disk, accepted):
    return upstream_scope(disk.root, c.JOB_ID, {
        inputs.GATE_JOB: disk.gate_job_ref["sha256"],
        inputs.REVIEW_JOB: disk.review_job_ref["sha256"],
        DEPENDENCY_JOB: accepted["sha256"],
    }, contract=CONTRACT)


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


@pytest.mark.parametrize("changed", ["configuration", "snapshot"])
def test_dependency_product_identifies_exact_source_and_configuration(tmp_path, monkeypatch, changed):
    documents, products = [], []
    for index in range(2):
        root = tmp_path / str(index)
        root.mkdir()
        settings = enabled_settings(repository_iri="https://example.test/repository")
        if changed == "configuration" and index:
            settings = replace(settings, action_statement="Review the accepted evidence.")
        disk = AcceptedInputDisk(root, monkeypatch, settings=settings,
                                 snapshot=str(index + 1) * 64 if changed == "snapshot" else None)
        _, accepted = dependency(disk, document=produced_reachability(disk))
        with admitted(disk, accepted):
            verified = inputs.verify_inputs(disk.root, disk.settings, ROOT)
            _, payload = dependency_projection(disk.root, verified, disk.settings, ROOT, "test-release")
        document = json.loads(payload)
        product = document["statements"][0]["products"][0]
        assert product["@id"] == c.source_product_id(
            verified.source.repository_iri, disk.snapshot, disk.config_ref["sha256"])
        assert product["subcomponents"] == [{"identifiers": {"purl": "pkg:pypi/example@1.0"}}]
        documents.append(payload)
        products.append(product["@id"])
    assert documents[0] != documents[1]
    assert products[0] != products[1]


@pytest.mark.parametrize("scenario", ["empty", "reachable"])
def test_dependency_preserves_producer_gaps_independent_of_statement_status(tmp_path, monkeypatch, scenario):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    document = produced_reachability(disk, scenario=scenario)
    legacy = {"dependency_id": "dep-1", "kind": "lookup_failed", "detail": "original lookup failure"}
    structured = producer_gap(GapCode.TRUNCATED, "source_file_limit_exceeded", scope_id="dep-1")
    _, accepted = dependency(disk, document=document, gaps=[structured, structured, legacy])
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        assembled = units.assemble()
        published = units.execute("acceptance.publish_handoff")
    companion = assembled["dependencies"]
    result = json.loads((disk.root / companion["artifact"]["path"]).read_bytes())
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["gaps"].count(structured) == 1
    reasons = [gap["reason"] for gap in result["gaps"]]
    assert all(reason in reasons for reason in document["gaps"])
    legacy_gap = next(gap for gap in result["gaps"] if "original lookup failure" in gap["reason"])
    assert json.loads(legacy_gap["reason"]) == legacy
    assert {**accepted, "size_bytes": (disk.root / accepted["path"]).stat().st_size} in legacy_gap["evidence_refs"]
    assert all(gap in published["gaps"] for gap in result["gaps"])
    validate_unit_output(published, unit_id="acceptance.publish_handoff", strict_gaps=True)
    if scenario == "empty":
        assert result["document"] is None
    else:
        vex = json.loads((disk.root / result["document"]["path"]).read_bytes())
        assert [row["status"] for row in vex["statements"]] == ["affected"]
        assert all(reason in vex["statements"][0]["status_notes"] for reason in document["gaps"])
        assert vex["statements"][0]["status_notes"].count("source_file_limit_exceeded") == 1


@pytest.mark.parametrize("scenario", ["null", "null-version", "no-purl", "invalid-purl"])
def test_unprojectable_producer_coordinates_are_accounted_without_breaking_primary_export(
        tmp_path, monkeypatch, scenario):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    document = produced_reachability(disk, scenario=scenario)
    reference, accepted = dependency(disk, document=document)
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        assembled = units.assemble()
        published = units.execute("acceptance.publish_handoff")
    assert published["item_count"] == 1
    assert assembled["document"] is not None
    companion = published["dependencies"]
    assert companion["document"] is None
    assert sum(companion["statements_by_status"].values()) == 0
    gaps = [gap for gap in companion["gaps"] if "coordinate" in gap["reason"]]
    assert len(gaps) == 1
    assert "CVE-2026-12345" in gaps[0]["reason"] and "example" in gaps[0]["reason"]
    assert {**reference, "size_bytes": (disk.root / reference["path"]).stat().st_size} in gaps[0]["evidence_refs"]
    assert companion["gaps"] and published["terminal_status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("scenario", ["ambiguous", "native"])
def test_producer_ambiguous_and_non_python_evidence_never_becomes_positive_or_clean(
        tmp_path, monkeypatch, scenario):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    document = produced_reachability(disk, scenario=scenario)
    assert document["advisories"][0]["reachability"] != "symbol_reachable"
    _, accepted = dependency(disk, document=document)
    with admitted(disk, accepted):
        verified = inputs.verify_inputs(disk.root, disk.settings, ROOT)
        result, payload = dependency_projection(disk.root, verified, disk.settings, ROOT, "test-release")
    assert result["statements_by_status"] == {"affected": 0, "not_affected": 0, "under_investigation": 1}
    assert json.loads(payload)["statements"][0]["status"] == "under_investigation"
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("scenario", ["mixed", "null-metadata"])
def test_available_purl_is_preserved_beside_nullable_coordinates(tmp_path, monkeypatch, scenario):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    document = produced_reachability(disk, scenario=scenario)
    if scenario == "null-metadata":
        assert document["advisories"][0]["package_version"] is None
        assert document["advisories"][0]["ecosystem"] is None
    _, accepted = dependency(disk, document=document)
    with admitted(disk, accepted):
        verified = inputs.verify_inputs(disk.root, disk.settings, ROOT)
        result, payload = dependency_projection(disk.root, verified, disk.settings, ROOT, "test-release")
    statements = json.loads(payload)["statements"]
    assert len(statements) == 1
    assert statements[0]["products"][0]["subcomponents"] == [
        {"identifiers": {"purl": document["advisories"][0]["purl"]}}]
    assert statements[0]["status"] == ("affected" if scenario == "mixed" else "under_investigation")
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    if scenario == "mixed":
        assert any("CVE-2026-12346" in gap["reason"] and "coordinate" in gap["reason"] for gap in result["gaps"])


def test_empty_dependency_result_uses_result_not_document_bound_at_creation_and_acceptance(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=(), settings=enabled_settings(max_document_bytes=1))
    _, accepted = dependency(disk, document=produced_reachability(disk, scenario="empty"))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        assembled = units.assemble()
        published = units.execute("acceptance.publish_handoff")
    assert assembled["document"] is None
    assert published["dependencies"]["document"] is None
    result = disk.root / published["dependencies"]["artifact"]["path"]
    assert 1 < result.stat().st_size <= c.MAX_RESULT_BYTES


def test_dependency_result_bound_is_enforced_before_writing_accounting(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=())
    document = produced_reachability(disk, scenario="empty")
    document["gaps"].append("original failure: " + "x" * c.MAX_RESULT_BYTES)
    _, accepted = dependency(disk, document=document)
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        units.execute("load.verify_inputs")
        with pytest.raises(c.ExportError) as error:
            units.execute("export.assemble")
    assert error.value.reason == c.ExportFailureReason.BOUND_EXCEEDED
    assert not (units.context.attempt_root / "steps/export/tasks/assemble/openvex-dependencies-result.json").exists()
    events = [json.loads(row) for row in units.context.events.path.read_text().splitlines()]
    assert not any(row["event"] == "OPENVEX_EXPORT_COMPLETED" for row in events)


def test_dependency_inventory_is_in_verified_inputs_and_input_telemetry(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reference, accepted = dependency(disk, document=produced_reachability(disk))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        loaded = units.execute("load.verify_inputs")
    verified = c.VerifiedInputs.from_mapping(json.loads((disk.root / loaded["artifact"]["path"]).read_bytes()))
    inventory = {ref.path: ref for ref in verified.input_inventory}
    assert reference["path"] in inventory
    assert accepted["path"] in inventory
    assert inventory[reference["path"]].sha256 == reference["sha256"]
    assert len(inventory) == len(verified.input_inventory)
    events = [json.loads(row) for row in units.context.events.path.read_text().splitlines()]
    event = next(row for row in events if row["event"] == "OPENVEX_INPUTS_VERIFIED")
    assert event["binding_count"] == len(inventory)
    assert event["input_bytes"] == sum(ref.size_bytes for ref in inventory.values())


@pytest.mark.parametrize("bound", ["max_bindings", "max_total_input_bytes"])
def test_dependency_inputs_share_the_configured_aggregate_bound(tmp_path, monkeypatch, bound):
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    disk = AcceptedInputDisk(baseline, monkeypatch, buckets=())
    units = ExportUnits(disk)
    loaded = units.execute("load.verify_inputs")
    verified = c.VerifiedInputs.from_mapping(json.loads((disk.root / loaded["artifact"]["path"]).read_bytes()))
    limit = len(verified.input_inventory) if bound == "max_bindings" else verified.total_input_bytes + 1000
    bounded = tmp_path / "bounded"
    bounded.mkdir()
    overrides = {bound: limit}
    if bound == "max_total_input_bytes":
        overrides["max_artifact_bytes"] = limit
    disk = AcceptedInputDisk(bounded, monkeypatch, buckets=(), settings=enabled_settings(**overrides))
    _, accepted = dependency(disk, document=produced_reachability(disk, scenario="empty"))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        with pytest.raises(c.ExportError) as error:
            units.execute("load.verify_inputs")
    assert error.value.reason == c.ExportFailureReason.BOUND_EXCEEDED
    assert not (units.context.attempt_root / "steps/load/tasks/verify_inputs/verified-inputs.json").exists()


def test_complete_dependency_inventory_fits_its_exact_unique_binding_bound(tmp_path, monkeypatch):
    initial = tmp_path / "initial"
    initial.mkdir()
    disk = AcceptedInputDisk(initial, monkeypatch, buckets=())
    _, accepted = dependency(disk, document=produced_reachability(disk, scenario="empty"))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        loaded = units.execute("load.verify_inputs")
    verified = c.VerifiedInputs.from_mapping(json.loads((disk.root / loaded["artifact"]["path"]).read_bytes()))
    bounded = tmp_path / "bounded"
    bounded.mkdir()
    disk = AcceptedInputDisk(
        bounded, monkeypatch, buckets=(), settings=enabled_settings(max_bindings=len(verified.input_inventory)))
    _, accepted = dependency(disk, document=produced_reachability(disk, scenario="empty"))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        units.assemble()
        published = units.execute("acceptance.publish_handoff")
    assert published["dependencies"]["document"] is None


def test_dependency_input_tampering_after_load_is_rejected_before_publication(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    reference, accepted = dependency(disk, document=produced_reachability(disk))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        units.execute("load.verify_inputs")
        (disk.root / reference["path"]).write_bytes(b"{}\n")
        with pytest.raises(c.ExportError):
            units.execute("export.assemble")
    assert "export.assemble" not in units.outputs


def test_dependency_telemetry_is_separate_and_only_emitted_after_output_reproof(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=())
    _, accepted = dependency(disk, document=produced_reachability(disk))
    units = ExportUnits(disk)
    with admitted(disk, accepted):
        units.assemble()
        events = [json.loads(row) for row in units.context.events.path.read_text().splitlines()]
        assert not any("openvex.cve_total_statements" in row for row in events)
        result = units.execute("acceptance.publish_handoff")
    events = [json.loads(row) for row in units.context.events.path.read_text().splitlines()]
    completed = next(row for row in events if row["event"] == "OPENVEX_EXPORT_COMPLETED")
    assert completed["openvex.cve_statements_by_status"] == {
        "affected": 1, "not_affected": 0, "under_investigation": 0,
    }
    assert completed["openvex.cve_total_statements"] == 1
    assert completed["openvex.cve_coverage_gap_statements"] == 0
    assert result["item_count"] == 0
    with admitted(disk, accepted):
        (disk.root / result["dependencies"]["artifact"]["path"]).write_bytes(b"{}\n")
        with pytest.raises(c.ExportError):
            units.execute("acceptance.publish_handoff")
    events = [json.loads(row) for row in units.context.events.path.read_text().splitlines()]
    assert sum(row["event"] == "OPENVEX_EXPORT_COMPLETED" for row in events) == 1
