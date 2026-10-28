"""Regression tests: tools are never launched on inputs outside their declared support.

Unsupported inputs are SKIPPED_NA with a reason and a separate count; they never become scanner failures.
Independent delivery-coverage gaps remain visible. A supported input on which a tool fails still yields a gap.
Every runner is injected.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.applicability import ProcessingDisposition, ReasonCode
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.job_artifact_security_analysis import (
    build_job as build_artifact_security, load_accepted_artifact_security_analysis,
)
from appsec_review.jobs.job_ci_configuration_analysis import build_job as build_ci
from appsec_review.jobs.job_clang_static_analysis.job import _analyze_scope
from appsec_review.jobs.job_evidence_collection import build_job as build_evidence
from appsec_review.jobs.job_evidence_collection.adapters import adapter_registry
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import _scanner_scope
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256
from appsec_review.tool_inputs import (
    InputDecision, TOOL_INPUT_SUPPORT, not_applicable_summary, osv_reported_no_package_sources,
    partition_formats, partition_paths,
)

from tests import test_artifact_security_analysis as asa_tests
from tests import test_ci_configuration_analysis as ci_tests
from tests import test_clang_static_analysis as clang_tests
from tests import test_evidence_collection_job as evidence_tests


# --- declared support -------------------------------------------------------------------------

def test_dockerfile_tools_accept_only_dockerfiles() -> None:
    paths = ["Dockerfile", "deploy/Dockerfile.prod", "build/app.dockerfile", "Containerfile",
             "Dockerfile.md", "dockerfile_utils.py", "docs/Dockerfile.txt", "Dockerfile.tmpl"]
    for tool in ("tool-hadolint", "tool-trivy"):
        partition = partition_paths(tool, paths)
        assert partition.supported == ("Dockerfile", "deploy/Dockerfile.prod", "build/app.dockerfile",
                                       "Containerfile")
        assert {item.path for item in partition.not_applicable} == {
            "Dockerfile.md", "dockerfile_utils.py", "docs/Dockerfile.txt", "Dockerfile.tmpl"}
        assert all(item.disposition is ProcessingDisposition.SKIPPED_NA and
                   item.reason_code is ReasonCode.INPUT_FORMAT_UNSUPPORTED and item.reason
                   for item in partition.not_applicable)


def test_shellcheck_dialect_comes_from_the_shebang() -> None:
    heads = {"a.sh": b"#!/bin/bash\necho\n", "b.sh": b"#!/usr/bin/env zsh\necho\n",
             "c.sh": b"echo no shebang\n", "d.sh": b"#!/usr/bin/env -S fish\n", "e.sh": None}
    partition = partition_paths("tool-shellcheck", list(heads), read_head=heads.get)
    assert partition.supported == ("a.sh", "c.sh", "e.sh")  # unreadable prefix: the tool decides
    assert [(item.path, "zsh" in item.reason or "fish" in item.reason)
            for item in partition.not_applicable] == [("b.sh", True), ("d.sh", True)]


def test_planner_and_adapters_share_one_declaration() -> None:
    files = tuple({"path": path, "sha256": "a" * 64} for path in (
        "Dockerfile", "dockerfile_utils.py", "Dockerfile.md", "main.tf", "app.py", "notes.md"))
    assert _scanner_scope("tool-hadolint", files, ()) == ("Dockerfile",)
    assert _scanner_scope("tool-checkov", files, ()) == tuple(item["path"] for item in files)
    assert _scanner_scope("tool-semgrep", files, ()) == ("dockerfile_utils.py", "app.py")
    assert set(adapter_registry()) <= set(TOOL_INPUT_SUPPORT)


def test_artifact_and_compile_unit_formats() -> None:
    blint = partition_formats("artifact:tool-blint", (("a", "elf"), ("b", "wasm"), ("c", "python-wheel")))
    assert blint.supported == ("a",)
    assert {item.path for item in blint.not_applicable} == {"b", "c"}
    units = partition_paths("clang:compile-unit", ["src/a.c", "src/b.cpp", "src/start.S", "src/k.cu"])
    assert units.supported == ("src/a.c", "src/b.cpp")


def test_only_the_documented_tool_reports_are_recognized() -> None:
    assert osv_reported_no_package_sources(128, b"No package sources found, --help for usage information.")
    assert not osv_reported_no_package_sources(1, b"No package sources found")
    assert not osv_reported_no_package_sources(128, b"failed to open database")
    with pytest.raises(ValueError):
        InputDecision("a", "tool", ReasonCode.PROCESSING_FAILED, "not an input-support reason")
    summary = not_applicable_summary([InputDecision("a.sh", "tool-shellcheck",
                                                    ReasonCode.INPUT_FORMAT_UNSUPPORTED, "zsh")])
    assert summary["count"] == 1 and summary["disposition"] == "SKIPPED_NA"


def test_semgrep_and_shellcheck_parsers_separate_unsupported_reports() -> None:
    semgrep = adapter_registry()["tool-semgrep"]
    records = semgrep.parse(json.dumps({"results": [], "errors": [], "paths": {"skipped": [
        {"path": "/target/a.rs", "reason": "wrong_language"},
        {"path": "/target/big.py", "reason": "exceeded_size_limit"}]}}).encode())
    assert [record.get("not_applicable_input") for record in records] == ["/target/a.rs", None]
    assert records[1]["coverage_gap"].startswith("engine skipped /target/big.py")
    shellcheck = adapter_registry()["tool-shellcheck"]
    records = shellcheck.parse(json.dumps({"comments": [
        {"file": "/target/x.sh", "line": 1, "code": 1071, "level": "error",
         "message": "ShellCheck only supports sh/bash/dash/ksh scripts. Sorry!"},
        {"file": "/target/y.sh", "line": 2, "code": 2086, "level": "info", "message": "quote"}]}).encode())
    assert records[0]["not_applicable_input"] == "/target/x.sh" and records[0]["gap_only"]
    assert records[1]["rule_id"] == 2086 and not records[1].get("gap_only")


# --- job_evidence_collection ------------------------------------------------------------------

class _RecordingExecutor(evidence_tests.FakeExecutor):
    def __init__(self, repository, run_root, calls, requests, shellcheck_payload=None):
        super().__init__(repository, run_root, calls)
        self.requests = requests
        self.shellcheck_payload = shellcheck_payload

    def execute(self, request):
        self.requests.append(request)
        result = super().execute(request)
        if request.tool_id == "tool-shellcheck" and self.shellcheck_payload is not None:
            (self.run_root / result.stdout_path).write_text(json.dumps(self.shellcheck_payload),
                                                             encoding="utf-8")
        return result


def _evidence_run(tmp_path: Path, files: dict[str, str], *, fail_tool: str | None = None,
                  shellcheck_payload=None):
    config, target = evidence_tests.fixture(tmp_path)
    for name, text in files.items():
        (target / name).write_text(text, encoding="utf-8")
    fingerprint = source_fingerprint(target)
    calls: list[str] = []
    requests: list = []
    factory = lambda unit: _RecordingExecutor(unit.job.repository_root, unit.job.run_root, calls, requests,
                                              shellcheck_payload)
    outcome = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_evidence(
        executor_factory=factory, fail_tool=fail_tool)]).run(target_root=target, source_fingerprint=fingerprint)
    published = outcome["jobs"]["job_evidence_collection"]["result"]["outputs"][
        "evidence_publication.publish_handoff"]
    return config, outcome, published, requests


def _disposition(published, tool_id):
    return next(item for item in published["dispositions"] if item["tool_id"] == tool_id)


def test_evidence_unsupported_shell_dialect_is_never_launched_and_not_a_gap(tmp_path: Path) -> None:
    config, outcome, published, requests = _evidence_run(
        tmp_path, {"legacy.sh": "#!/usr/bin/env zsh\nsetopt extendedglob\n"})
    plan = load_accepted_plan(config.runtime.runs_dir / outcome["run_id"])
    planned = next(item for item in plan["scanner_selections"] if item["scanner_id"] == "tool-shellcheck")
    assert {item["path"] for item in planned["scope"]} == {"legacy.sh", "run.sh"}
    shellcheck = [request for request in requests if request.tool_id == "tool-shellcheck"]
    assert shellcheck and all("/target/legacy.sh" not in request.argv for request in shellcheck)
    assert all("/target/run.sh" in request.argv for request in shellcheck)
    disposition = _disposition(published, "tool-shellcheck")
    assert disposition["terminal_status"] == "SUCCEEDED"
    assert disposition["not_applicable_input_count"] == 1
    assert not any("legacy.sh" in gap for gap in published["gaps"])
    skipped = [item for item in published["not_applicable_inputs"]["items"] if item["path"] == "legacy.sh" and item["tool"] == "tool-shellcheck"]
    assert skipped and skipped[0]["disposition"] == "SKIPPED_NA"
    assert skipped[0]["reason_code"] == "INPUT_FORMAT_UNSUPPORTED" and "zsh" in skipped[0]["reason"]


def test_evidence_tool_with_only_unsupported_inputs_is_not_applicable_without_gap(tmp_path: Path) -> None:
    config, target = evidence_tests.fixture(tmp_path)
    (target / "run.sh").write_text("#!/bin/fish\necho fixture\n", encoding="utf-8")
    fingerprint = source_fingerprint(target)
    calls: list[str] = []
    requests: list = []
    factory = lambda unit: _RecordingExecutor(unit.job.repository_root, unit.job.run_root, calls, requests)
    outcome = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_evidence(
        executor_factory=factory)]).run(target_root=target, source_fingerprint=fingerprint)
    published = outcome["jobs"]["job_evidence_collection"]["result"]["outputs"][
        "evidence_publication.publish_handoff"]
    assert "tool-shellcheck" not in calls
    disposition = _disposition(published, "tool-shellcheck")
    assert disposition["terminal_status"] == "NOT_APPLICABLE"
    assert disposition["gaps"] == [] and disposition["not_applicable_input_count"] == 1
    scan = outcome["jobs"]["job_evidence_collection"]["result"]["outputs"]["source_sast.shellcheck_scan"]
    assert scan["coverage_disposition"] == "SKIPPED_NA"


def test_evidence_supported_input_failure_is_still_a_gap(tmp_path: Path) -> None:
    _config, outcome, published, requests = _evidence_run(
        tmp_path, {"legacy.sh": "#!/usr/bin/env zsh\n"}, fail_tool="tool-shellcheck")
    disposition = _disposition(published, "tool-shellcheck")
    assert disposition["terminal_status"] == "FAILED"
    assert any("injected bounded failure" in gap for gap in disposition["gaps"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"


def test_evidence_tool_reported_unsupported_dialect_is_skipped_na(tmp_path: Path) -> None:
    payload = {"comments": [{"file": "/target/run.sh", "line": 1, "endLine": 1, "column": 1, "code": 1071,
                             "level": "error", "message": "ShellCheck only supports sh/bash/dash/ksh scripts."}]}
    _config, _outcome, published, _requests = _evidence_run(tmp_path, {}, shellcheck_payload=payload)
    disposition = _disposition(published, "tool-shellcheck")
    assert disposition["terminal_status"] == "SUCCEEDED" and disposition["record_count"] == 0
    assert disposition["not_applicable_input_count"] == 1
    item = next(value for value in published["not_applicable_inputs"]["items"] if value["path"] == "run.sh" and value["tool"] == "tool-shellcheck")
    assert item["reason_code"] == "TOOL_REPORTED_UNSUPPORTED_INPUT"


def test_evidence_source_without_any_analyzer_is_visible_coverage(tmp_path: Path) -> None:
    _config, _outcome, published, _requests = _evidence_run(tmp_path, {"setup.ps1": "Write-Host hi\n"})
    coverage = published["unsupported_coverage"]
    assert coverage["kind"] == "unsupported-language" and "setup.ps1" in coverage["paths"]
    assert coverage["languages"] == {"PowerShell": 1}
    assert any(gap.startswith("unsupported-language coverage: 1 ") for gap in published["gaps"])


# --- job_ci_configuration_analysis ------------------------------------------------------------

def _ci_run(tmp_path: Path, files: dict[str, str], *, fail_tool: str | None = None):
    config = ci_tests.isolated_config(tmp_path)
    target = tmp_path / "target"
    for name, text in files.items():
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(text, encoding="utf-8")
    calls: list[tuple[str, tuple[str, ...]]] = []
    factory = lambda unit: ci_tests.FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    outcome = GraphRunner(config, (build_intake(), build_catalog(), build_ci(
        executor_factory=factory, fail_tool=fail_tool))).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    return outcome["jobs"]["job_ci_configuration_analysis"]["result"]["outputs"], calls


WORKFLOW = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
ACTION = "name: setup\nruns:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"


def test_ci_action_metadata_is_not_handed_to_workflow_only_linters(tmp_path: Path) -> None:
    outputs, calls = _ci_run(tmp_path, {".github/workflows/ci.yml": WORKFLOW,
                                        ".github/actions/setup/action.yml": ACTION})
    argv = {tool: [args[-1] for name, args in calls if name == tool]
            for tool in ("tool-actionlint", "tool-checkov", "tool-zizmor")}
    assert argv["tool-actionlint"] == ["/target/.github/workflows/ci.yml"]
    assert argv["tool-checkov"] == ["/target/.github/workflows/ci.yml"]
    assert sorted(argv["tool-zizmor"]) == ["/target/.github/actions/setup/action.yml",
                                           "/target/.github/workflows/ci.yml"]
    actionlint = outputs["ci_analysis.github_actionlint_scan"]
    assert actionlint["terminal_status"] == "SUCCEEDED" and actionlint["gaps"] == []
    assert actionlint["not_applicable_inputs"]["items"][0]["path"] == ".github/actions/setup/action.yml"
    coverage = outputs["ci_coverage.join_coverage"]
    assert not any("action.yml" in gap for gap in coverage["gaps"])
    assert coverage["not_applicable_inputs"]["count"] == 2


def test_ci_linter_with_only_unsupported_definitions_is_not_launched(tmp_path: Path) -> None:
    outputs, calls = _ci_run(tmp_path, {".github/actions/setup/action.yml": ACTION})
    assert {name for name, _ in calls} == {"tool-zizmor"}
    actionlint = outputs["ci_analysis.github_actionlint_scan"]
    assert actionlint["terminal_status"] == "NOT_APPLICABLE" and actionlint["gaps"] == []
    assert actionlint["coverage_disposition"] == "SKIPPED_NA"


def test_ci_supported_definition_failure_is_still_a_gap(tmp_path: Path) -> None:
    outputs, _calls = _ci_run(tmp_path, {".github/workflows/ci.yml": WORKFLOW,
                                         ".github/actions/setup/action.yml": ACTION},
                              fail_tool="github_actionlint")
    actionlint = outputs["ci_analysis.github_actionlint_scan"]
    assert actionlint["terminal_status"] == "FAILED"
    assert any("ci.yml" in gap and "injected bounded failure" in gap for gap in actionlint["gaps"])
    assert not any("action.yml" in gap for gap in actionlint["gaps"])


# --- job_artifact_security_analysis -----------------------------------------------------------

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 64


def _asa_scanner(calls: list[str], *, osv_exit: int, osv_stderr: bytes, blint_exit: int = 0):
    def scanner(capability, path, artifact, timeout, limit):
        calls.append(capability)
        exit_code = {"osv": osv_exit, "blint": blint_exit}.get(capability, 0)
        return {"stdout": b"{}", "stderr": osv_stderr if capability == "osv" else b"",
                "exit_code": exit_code, "payload": b"{}",
                "tool_identity": {"scanner": capability, "image": "sha256:" + "e" * 64, "rules": "fixture"}}
    return scanner


def test_artifact_scanner_unsupported_formats_are_never_launched(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(tmp_path)
    calls: list[str] = []
    outcome = GraphRunner(config, [build_artifact_security(scanner_runner=_asa_scanner(
        calls, osv_exit=0, osv_stderr=b""))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    accepted = load_accepted_artifact_security_analysis(run_root)
    # WebAssembly is neither a native binary, JVM bytecode, nor an osv-scanner lockfile.
    assert not {"blint", "spotbugs", "osv"} & set(calls)
    osv = accepted["capabilities"]["osv"]
    delivery_gap = "build/module.wasm: delivery status is unknown (delivery_fact_unavailable)"
    assert osv["terminal_status"] == "COMPLETED_WITH_GAPS" and osv["gaps"] == [delivery_gap]
    assert osv["not_applicable_inputs"]["items"][0]["reason_code"] == "INPUT_FORMAT_UNSUPPORTED"
    assert not any("osv" in gap or "blint" in gap for gap in accepted["gaps"])
    # Neither the delivery uncertainty nor the built-in Wasm validator gap is a scanner support failure.
    assert all(gap == delivery_gap or "WebAssembly feature" in gap for gap in accepted["gaps"]), accepted["gaps"]
    assert outcome["status"] == "COMPLETED_WITH_GAPS"


def test_artifact_osv_empty_lockfile_report_is_skipped_na(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(
        tmp_path, payload=b"", name="requirements.txt", kind="generated-output")
    calls: list[str] = []
    GraphRunner(config, [build_artifact_security(scanner_runner=_asa_scanner(
        calls, osv_exit=128, osv_stderr=b"No package sources found, --help for usage information."))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    osv = load_accepted_artifact_security_analysis(run_root)["capabilities"]["osv"]
    assert "osv" in calls
    assert osv["gaps"] == ["build/requirements.txt: delivery status is unknown (delivery_fact_unavailable)"]
    assert osv["not_applicable_inputs"]["items"][0]["reason_code"] == "TOOL_REPORTED_UNSUPPORTED_INPUT"


def test_artifact_supported_scanner_failures_remain_gaps(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(tmp_path, payload=ELF)
    calls: list[str] = []
    outcome = GraphRunner(config, [build_artifact_security(scanner_runner=_asa_scanner(
        calls, osv_exit=128, osv_stderr=b"failed to load local database", blint_exit=2))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    accepted = load_accepted_artifact_security_analysis(run_root)
    assert "blint" in calls  # ELF is supported
    assert "osv" not in calls  # an ELF binary is not an osv-scanner lockfile
    assert any("blint scanner exited 2" in gap for gap in accepted["capabilities"]["blint"]["gaps"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"


def test_artifact_osv_failure_on_a_lockfile_is_a_gap_with_its_reason(tmp_path: Path) -> None:
    config, run_id, run_root, target, fingerprint, _ = asa_tests._fixture(
        tmp_path, payload=b"requests==2.19.0\n", name="requirements.txt", kind="generated-output")
    GraphRunner(config, [build_artifact_security(scanner_runner=_asa_scanner(
        [], osv_exit=128, osv_stderr=b"Scanning...\nfailed to load local database: zip: not a valid zip file\n"))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    gaps = load_accepted_artifact_security_analysis(run_root)["capabilities"]["osv"]["gaps"]
    assert any("osv scanner exited 128: failed to load local database: zip: not a valid zip file" in gap
               for gap in gaps), gaps


# --- Clang-family C/C++ scopes ----------------------------------------------------------------

def _clang_scope(tmp_path: Path, *, cpp: bool = True) -> IndexScope:
    base = clang_tests._scope(tmp_path)
    assembly = base.case_root / "source" / "start.S"
    assembly.write_text(".globl _start\n", encoding="utf-8")
    entry = {"target_path": "native/start.S", "scratch_path": "source/start.S", "sha256": file_sha256(assembly)}
    commands = ((*base.compile_commands,) if cpp else ()) + (
        {"target_path": "native/start.S", "arguments": ["clang-18", "/scratch/source/start.S"]},)
    return IndexScope(base.scope_id, base.case_id, base.project_id, base.root, base.case_snapshot,
                      base.case_root, (*base.files, entry), commands, base.compile_database,
                      {**base._by_relative, "start.S": entry})


def test_clang_scope_never_receives_unsupported_compile_units(tmp_path: Path) -> None:
    scope, unit = _clang_scope(tmp_path), clang_tests._unit(tmp_path)
    executor = clang_tests.FakeExecutor(unit.job.run_root)
    result = _analyze_scope(unit, scope, lambda _unit: executor)
    assert executor.calls == ["clang-tidy", "clang-static-analyzer"]
    database = json.loads((unit.job.run_root / "data" / "clang-static" / scope.scope_id / "tidy" /
                           "compile_commands.json").read_text(encoding="utf-8"))
    assert [row["file"] for row in database] == ["/target/source/main.cpp"]
    assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
    assert result["not_applicable_inputs"]["items"][0]["path"] == "native/start.S"


def test_clang_scope_supported_failure_is_still_a_gap(tmp_path: Path) -> None:
    scope, unit = _clang_scope(tmp_path), clang_tests._unit(tmp_path)
    executor = clang_tests.FakeExecutor(unit.job.run_root, fail="clang-tidy")
    result = _analyze_scope(unit, scope, lambda _unit: executor)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("clang-tidy exited with status 7" in gap for gap in result["gaps"])


def test_clang_scope_without_supported_units_is_not_launched(tmp_path: Path, monkeypatch) -> None:
    from types import MappingProxyType

    from appsec_review.jobs.job_clang_static_analysis import build_job as build_clang
    from appsec_review.jobs.job_clang_static_analysis import job as clang_job
    from appsec_review.runtime import UnitContext

    scope = _clang_scope(tmp_path, cpp=False)
    assert scope.container_compile_database() == []
    assert scope.as_dict()["supported_compile_unit_count"] == 0
    monkeypatch.setattr(clang_job, "accepted_cpp_scopes", lambda run_root: ({}, [scope], {}))
    executor = clang_tests.FakeExecutor(tmp_path / "run")
    analyze = next(item for item in build_clang(executor_factory=lambda _unit: executor).units
                   if item.unit_id == "analyze.scopes")
    base = clang_tests._unit(tmp_path)
    unit = UnitContext(base.job, "analyze.scopes", "analyze", "scopes", base.unit_root,
                       MappingProxyType({"load.accepted_cpp": {"scopes": [scope.as_dict()]}}))
    result = analyze.handler(unit)
    assert executor.calls == []
    assert result["terminal_status"] == "NOT_APPLICABLE" and result["gaps"] == []
    skipped = result["not_applicable_scopes"][0]
    assert skipped["terminal_status"] == "SKIPPED_NA"
    assert skipped["not_applicable_inputs"]["items"][0]["path"] == "native/start.S"


def test_checkov_is_offered_every_planned_file_and_arbitrates_recognition_itself() -> None:
    from appsec_review.jobs.job_evidence_collection.adapters import Applicability
    from appsec_review.jobs.job_evidence_collection.job import _filter_supported_inputs

    files = ("CMakePresets.json", "Dockerfile", ".github/workflows/ci.yml", "app.py", "notes.md", "pkg/stack.json")
    selection = Applicability(True, "planned", files, "checkov_typed_configuration")
    kept, skipped = _filter_supported_inputs(selection, adapter_registry()["tool-checkov"], None)
    assert skipped == () and kept.files == files
    assert partition_paths("tool-checkov", ["notes.md", "app.py"]).supported == ("notes.md", "app.py")
