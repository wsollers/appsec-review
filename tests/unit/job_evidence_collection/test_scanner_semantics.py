"""Offline regressions for EC-01/02/03/04/05/07 (T-5132/T-5133/T-5134)."""

from dataclasses import replace
from itertools import permutations
import json

import pytest

from appsec_review.jobs.job_evidence_collection import job as ec_job
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS, Applicability
from appsec_review.jobs.job_evidence_collection.evidence import EvidenceBounds, build_envelope, corroborate_sast_records
from appsec_review.provenance import select_native, verify_native_reference
from appsec_review.storage import canonical_json, file_sha256
from .support import FakeExecutor, ROOT, attempt_scope, make_unit_context, seed_accepted_catalog_and_plan


@pytest.mark.parametrize("tool_id", sorted(ADAPTERS))
def test_error_shaped_report_is_not_an_empty_success(tool_id):
    payload = (b"<error>analysis failed</error>" if tool_id in {"tool-cppcheck", "tool-spotbugs"}
               else b'{"error":"analysis failed"}')
    try:
        records = ADAPTERS[tool_id].parse(payload)
    except ValueError:
        return
    assert any(record.get("coverage_gap") for record in records)


@pytest.mark.parametrize("tool_id,payload", [
    ("tool-gosec", {"Issues": None}),
    ("tool-osv-scanner", {"results": None}),
    ("tool-trivy", {"SchemaVersion": 2, "ArtifactName": "/scratch/inputs", "ArtifactType": "filesystem"}),
    ("tool-phpstan", {"files": [], "errors": []}),
])
def test_native_empty_nullable_collections_remain_supported(tool_id, payload):
    assert ADAPTERS[tool_id].parse(canonical_json(payload)) == []


@pytest.mark.parametrize("tool_id,payload,selector,detail", [
    ("tool-gosec", {"Issues": [], "Golang errors": {"a.go": ["loader failed"]}},
     "/Golang errors/a.go", "loader failed"),
    ("tool-phpstan", {"files": {}, "errors": ["analysis failed"]}, "/errors/0", "analysis failed"),
    ("tool-syft", {"artifacts": [], "error": "inventory failed"}, "/error", "inventory failed"),
    ("tool-pmd", {"files": [], "processingErrors": [{"msg": "parser failed"}]},
     "/processingErrors/0", "parser failed"),
])
def test_native_diagnostics_keep_exact_selectors_and_failure_text(tool_id, payload, selector, detail):
    diagnostic, = ADAPTERS[tool_id].parse(canonical_json(payload))
    assert diagnostic["gap_only"] is True
    assert diagnostic["_native_selector"]["value"] == selector
    assert detail in diagnostic["coverage_gap"]


@pytest.mark.parametrize("detail", ['<Errors missingClasses="1"/>', '<MissingClass>Unknown</MissingClass>'])
def test_spotbugs_native_missing_classes_are_coverage_gaps(detail):
    diagnostic, = ADAPTERS["tool-spotbugs"].parse(f"<BugCollection>{detail}</BugCollection>".encode())
    assert diagnostic["gap_only"] is True
    assert diagnostic["_native_selector"]["kind"] == "xml_ordinal"
    assert "SpotBugs reported" in diagnostic["coverage_gap"]


@pytest.mark.parametrize("tool_id,payload,status,diagnostic", [
    ("tool-shellcheck", {"error": "scanner failed"}, "FAILED", "parser incompatibility"),
    ("tool-phpstan", {"totals": {"errors": 1, "file_errors": 0}, "files": {},
                      "errors": ["No files found to analyse."]}, "PARTIAL", "No files found to analyse."),
])
def test_native_error_survives_execution_and_publication(tmp_path, tool_id, payload, status, diagnostic):
    adapter = ADAPTERS[tool_id]
    stem = tool_id.removeprefix("tool-")
    unit, catalog, _ = make_unit_context(
        tmp_path, unit_id=f"source_sast.{stem}_scan",
        target_files={"run.sh": "#!/bin/sh\n", "a.php": "<?php\n"},
        settings_override={"tool_retries": 0})

    class ReportExecutor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            (self.run_root / result.stdout_path).write_bytes(canonical_json(payload))
            return replace(result, exit_code=1 if tool_id == "tool-phpstan" else 0)

    with attempt_scope(unit):
        output = ec_job._execute_tool(
            unit, adapter, catalog, lambda u: ReportExecutor(ROOT, u.job.run_root, []), None)
    assert output["terminal_status"] == status
    assert output["record_count"] == 0
    assert any(diagnostic in gap for gap in output["gaps"])
    evidence = ec_job._read_artifact(unit.job.run_root, output["artifact"])
    assert evidence["terminal_status"] == status
    assert verify_native_reference(unit.job.run_root, output["native_outputs"][0]).read_bytes() == canonical_json(payload)


def _envelope(tmp_path, observations):
    return build_envelope(
        tool={"id": "tool-semgrep"}, target_fingerprint="f" * 64,
        applicability={"applicable": True}, coverage_scope={"paths": ["a.c"]},
        gaps=(), raw_artifacts=(), parser_identity="undeclared", observations=observations,
        cataloged_paths=["a.c"], terminal_status="SUCCEEDED", run_root=tmp_path)


@pytest.mark.parametrize("lines", [(1, 4, 6), (5, 6, 9)], ids=["bridge", "bucket-bridge"])
def test_cwe_clustering_is_order_independent_with_stable_identity(tmp_path, lines):
    observations = [
        {"rule_id": f"rule-{line}", "path": "a.c", "start_line": line, "end_line": line,
         "severity": "HIGH" if line == lines[-1] else "LOW", "category": "source_sast",
         "message": f"site {line}", "rule_mapping": {"cwe": "CWE-119"}}
        for line in lines]
    envelopes = [_envelope(tmp_path, order) for order in permutations(observations)]
    assert all(envelope["record_count"] == 1 for envelope in envelopes)
    assert len({canonical_json(envelope["records"]) for envelope in envelopes}) == 1
    assert envelopes[0]["records"][0]["severity"] == "HIGH"
    records = [_envelope(tmp_path, [observation])["records"][0] for observation in observations]
    documents = [corroborate_sast_records(
        {"tool-semgrep": {"records": list(order)}}, target_fingerprint="f" * 64)
        for order in permutations(records)]
    assert all(document["cluster_count"] == 1 for document in documents)
    assert len({canonical_json(document) for document in documents}) == 1


@pytest.mark.parametrize("tool_id", ["tool-gitleaks", "tool-syft"])
def test_directory_scanner_mount_contains_only_hash_pinned_selected_inputs(tmp_path, tool_id):
    adapter = ADAPTERS[tool_id]
    unit, catalog, _ = make_unit_context(
        tmp_path, unit_id=f"{adapter.capability}.{tool_id.removeprefix('tool-')}_scan",
        target_files={"selected.txt": "selected\n", "excluded.txt": "excluded\n"})
    requests = []

    class ScopeExecutor(FakeExecutor):
        def execute(self, request):
            requests.append(request)
            assert sorted(path.relative_to(request.target_root).as_posix()
                          for path in request.target_root.rglob("*") if path.is_file()) == ["selected.txt"]
            assert file_sha256(request.target_root / "selected.txt") == catalog.files[1]["sha256"]
            return super().execute(request)

    selection = Applicability(True, "accepted subset", ("selected.txt",), "directory")
    with attempt_scope(unit):
        output = ec_job._execute_tool(
            unit, adapter, catalog, lambda u: ScopeExecutor(ROOT, u.job.run_root, []), None, selection)
    assert requests and output["terminal_status"] == "SUCCEEDED"
    evidence = ec_job._read_artifact(unit.job.run_root, output["artifact"])
    assert evidence["coverage_scope"]["paths"] == ["selected.txt"]
    if tool_id == "tool-syft":
        assert evidence["source_inventory"] in evidence["raw_artifacts"]
        assert evidence["source_inventory"]["path"] == output["scanner_output"]


@pytest.mark.parametrize("damage", ["changed", "symlink", "uncataloged"])
def test_directory_submission_refuses_unpinned_source_bytes(tmp_path, damage):
    unit, catalog, _ = make_unit_context(
        tmp_path, unit_id="software_inventory.syft_scan", target_files={"selected.txt": "original"})
    source = unit.job.target_root / "selected.txt"
    if damage == "changed":
        source.write_text("changed")
    elif damage == "symlink":
        other = unit.job.target_root / "other.txt"
        other.write_text("original")
        source.unlink()
        source.symlink_to(other)
    else:
        catalog = replace(catalog, files=())

    class NoExecution(FakeExecutor):
        def execute(self, request):
            pytest.fail("unpinned input reached scanner")

    with attempt_scope(unit), pytest.raises(ValueError, match="accepted|escapes"):
        ec_job._execute_tool(
            unit, ADAPTERS["tool-syft"], catalog, lambda u: NoExecution(ROOT, u.job.run_root, []), None,
            Applicability(True, "selected", ("selected.txt",), "directory"))


def test_cppcheck_project_scope_excludes_unsubmitted_sources_and_names_gap(tmp_path):
    unit, catalog, _ = make_unit_context(
        tmp_path, unit_id="source_sast.cppcheck_scan", target_files={"a.c": "int a;\n", "b.c": "int b;\n"})
    database = unit.job.target_root / "compile_commands.json"
    database.write_text(json.dumps([{"directory": str(unit.job.target_root), "file": "a.c",
                                     "command": "cc -DMODE=1 a.c"}]))
    catalog = replace(catalog, compile_commands=({"path": "compile_commands.json"},))
    with attempt_scope(unit):
        output = ec_job._execute_tool(
            unit, ADAPTERS["tool-cppcheck"], catalog,
            lambda u: FakeExecutor(ROOT, u.job.run_root, []), None)
    evidence = ec_job._read_artifact(unit.job.run_root, output["artifact"])
    assert evidence["coverage_scope"]["paths"] == ["a.c"]
    assert evidence["coverage_scope"]["path_count"] == 1
    assert any("b.c" in gap and "not submitted" in gap for gap in output["gaps"])
    assert any("flags" in gap and "sanitized" in gap for gap in output["gaps"])
    assert output["terminal_status"] == "PARTIAL"
    assert evidence["not_applicable_inputs"]["count"] == 0


def test_published_not_applicable_totals_survive_bounded_detail_samples(tmp_path):
    paths = {f"file-{index:03d}.txt": "" for index in range(250)}
    unit, catalog, _ = make_unit_context(tmp_path, target_files=paths)
    seed_accepted_catalog_and_plan(unit.job.run_root, unit.job.target_root, files=list(catalog.files))
    unit.job.input_manifest_path = unit.job.run_root / "data/indices/manifests/catalog-attempt_0001.json"
    unit.job.input_manifest_sha256 = file_sha256(unit.job.input_manifest_path)
    selection = Applicability(True, "unsupported planned files", tuple(paths), "source_files")
    scan = ec_job._execute_tool(
        unit, ADAPTERS["tool-shellcheck"], catalog,
        lambda u: pytest.fail("unsupported inputs must not launch"), None, selection)
    unit.output = {"scan": scan}.__getitem__
    normalized = ec_job._normalize_tool(unit, "scan")
    unit.output = {"normalized": normalized}.__getitem__
    indexed = ec_job._build_producer_shard(unit, "normalized")
    unit.output = {"index": indexed}.__getitem__
    with attempt_scope(unit):
        assembled = ec_job._assemble_manifest(unit, ("index",))
    assert assembled["not_applicable_inputs"]["count"] == 250
    assert sum(assembled["not_applicable_inputs"]["by_reason"].values()) == 250
    assert len(assembled["not_applicable_inputs"]["items"]) == 200
    assert assembled["not_applicable_inputs"]["truncated"] is True
    unit.output = {"evidence_publication.assemble_manifest": assembled}.__getitem__
    publish = next(u for u in ec_job.build_job().units if u.unit_id == "evidence_publication.publish_handoff")
    published = ec_job._read_artifact(unit.job.run_root, publish.handler(unit)["artifact"])
    assert published["not_applicable_inputs"] == assembled["not_applicable_inputs"]
    assert published["dispositions"][0]["not_applicable_input_count"] == 250


def test_corroboration_recovers_late_agreement_before_per_tool_cap(tmp_path):
    unit, catalog, _ = make_unit_context(
        tmp_path, unit_id="source_sast.semgrep_scan",
        target_files={"a.c": "int a;\n"}, settings_override={"tool_retries": 0})
    findings = [{"check_id": f"low-{index}", "path": "/target/a.c",
                 "start": {"line": index + 10}, "end": {"line": index + 10},
                 "extra": {"message": "low priority", "severity": "INFO"}} for index in range(2)]
    critical = {"check_id": "critical", "path": "/target/a.c",
                "start": {"line": 6000}, "end": {"line": 6000},
                "extra": {"message": "important", "severity": "CRITICAL",
                          "metadata": {"cwe": "CWE-119"}}}

    class ReportExecutor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            rows = [*findings, critical] if request.tool_id == "tool-semgrep" else [critical]
            (request.scratch_root / "output.json").write_bytes(canonical_json(
                {"results": rows, "errors": [], "paths": {"scanned": ["/target/a.c"]}}))
            return result

    envelopes = {}
    with attempt_scope(unit):
        for tool_id in ("tool-semgrep", "tool-opengrep"):
            scan = ec_job._execute_tool(
                unit, ADAPTERS[tool_id], catalog,
                lambda u: ReportExecutor(ROOT, u.job.run_root, []), None)
            evidence = ec_job._read_artifact(unit.job.run_root, scan["artifact"])
            if tool_id == "tool-semgrep":
                source = evidence["native_observation_sources"][0]
                parsed = ADAPTERS[tool_id].parse(verify_native_reference(unit.job.run_root, source).read_bytes())
                observations = [{**row, "_native_refs": [select_native(source, row["_native_selector"]).as_dict()]}
                                for row in parsed]
                evidence = {**build_envelope(
                    tool=evidence["tool"], target_fingerprint=catalog.source_fingerprint,
                    applicability=evidence["applicability"], coverage_scope=evidence["coverage_scope"],
                    gaps=(), raw_artifacts=(), parser_identity=ADAPTERS[tool_id].parser_identity,
                    observations=observations, cataloged_paths=catalog.paths, terminal_status="SUCCEEDED",
                    run_root=unit.job.run_root, bounds=EvidenceBounds(max_records=2)),
                    "native_observation_sources": evidence["native_observation_sources"]}
                assert evidence["record_count"] == 2
                assert all(row["severity"] != "CRITICAL" for row in evidence["records"])
                assert evidence["telemetry"]["omitted_record_count"] == 1
            envelopes[tool_id] = ec_job._corroboration_envelope(unit, ADAPTERS[tool_id], catalog, evidence)
            # Each tool must own its evidence bytes; do not overwrite the preceding tool's artifact.
            unit.unit_root = unit.unit_root.parent / "opengrep_scan"
    corroborated = corroborate_sast_records(
        envelopes, target_fingerprint=catalog.source_fingerprint, max_findings_per_scope=2)
    important = next(row for row in corroborated["clusters"] if row["severity"] == "CRITICAL")
    assert important["corroborating_scanners"] == ["tool-opengrep", "tool-semgrep"]
    assert len(important["evidence_refs"]) == 2
    for ref in important["evidence_refs"]:
        assert verify_native_reference(unit.job.run_root, ref, resolve=True)["check_id"] == "critical"
    assert important["location"]["source_sha256"] == catalog.files[0]["sha256"]
    assert corroborated["cluster_count"] == 2
    assert corroborated["telemetry"]["raw_scanner_findings"] == 4
    assert corroborated["telemetry"]["omitted_cluster_count"] == 1


def test_default_record_bound_does_not_cap_corroboration_input(tmp_path):
    observations = [{"rule_id": f"low-{index}", "path": "a.c", "start_line": index + 10,
                     "end_line": index + 10, "severity": "LOW", "category": "source_sast",
                     "message": "low priority"} for index in range(5000)]
    observations.append({"rule_id": "critical", "path": "a.c", "start_line": 6000, "end_line": 6000,
                         "severity": "CRITICAL", "category": "source_sast", "message": "important"})
    uncapped = []
    envelope = build_envelope(
        tool={"id": "tool-semgrep"}, target_fingerprint="f" * 64, applicability={},
        coverage_scope={}, gaps=(), raw_artifacts=(), parser_identity="undeclared",
        observations=observations, cataloged_paths=["a.c"], terminal_status="SUCCEEDED",
        run_root=tmp_path, pre_cap_sink=uncapped.append)
    assert envelope["record_count"] == 5000
    assert len(uncapped) == 5001
    result = corroborate_sast_records(
        {"tool-semgrep": {"records": uncapped}}, target_fingerprint="f" * 64,
        max_findings_per_scope=1_000_000)
    assert result["cluster_count"] == 5001
    assert result["clusters"][0]["severity"] == "CRITICAL"


def test_final_assembly_replays_retained_partial_report_not_failed_retry(tmp_path):
    unit, catalog, _ = make_unit_context(
        tmp_path, unit_id="source_sast.phpstan_scan", target_files={"a.php": "<?php\n"})
    seed_accepted_catalog_and_plan(unit.job.run_root, unit.job.target_root, files=list(catalog.files))
    unit.job.input_manifest_path = unit.job.run_root / "data/indices/manifests/catalog-attempt_0001.json"
    unit.job.input_manifest_sha256 = file_sha256(unit.job.input_manifest_path)
    calls = []

    class RetryingExecutor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            document = {"files": {"/target/a.php": {"messages": [
                {"identifier": "sqli", "message": "query", "line": 2}]}},
                "errors": ["analysis incomplete"]}
            (self.run_root / result.stdout_path).write_bytes(canonical_json(document))
            return replace(result, exit_code=2 if len(self.calls) == 1 else 1)

    with attempt_scope(unit):
        scan = ec_job._execute_tool(
            unit, ADAPTERS["tool-phpstan"], catalog,
            lambda u: RetryingExecutor(ROOT, u.job.run_root, calls), None)
        assert scan["terminal_status"] == "PARTIAL"
        assert len(scan["native_outputs"]) == 2
        evidence = ec_job._read_artifact(unit.job.run_root, scan["artifact"])
        assert evidence["native_observation_sources"] == [scan["native_outputs"][1]]
        unit.output = {"scan": scan}.__getitem__
        normalized = ec_job._normalize_tool(unit, "scan")
        unit.output = {"normalized": normalized}.__getitem__
        indexed = ec_job._build_producer_shard(unit, "normalized")
        unit.output = {"index": indexed}.__getitem__
        assembled = ec_job._assemble_manifest(unit, ("index",))
        corroborated = ec_job._read_artifact(unit.job.run_root, assembled["corroborated_sast_evidence"])
        cluster, = corroborated["clusters"]
        assert cluster["corroboration_count"] == 1
        assert len(cluster["evidence_refs"]) == 1
        assert cluster["evidence_refs"][0]["execution_reference"] == scan["native_outputs"][1]["execution_reference"]
        assert any("analysis incomplete" in gap for gap in assembled["gaps"])
        assert any("exited with 2" in gap for gap in assembled["gaps"])
        source = evidence["native_observation_sources"][0]
        tampered = {**source, "artifact": {**source["artifact"], "sha256": "0" * 64}}
        with pytest.raises(ValueError):
            ec_job._corroboration_envelope(
                unit, ADAPTERS["tool-phpstan"], catalog, {**evidence, "native_observation_sources": [tampered]})
