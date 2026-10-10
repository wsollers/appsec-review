from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import load_catalog
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_evidence_collection import build_job, plan_applicability
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan
from appsec_review.runtime import GraphRunner, JobRunner


ROOT = Path(__file__).parents[1]
DIGEST = "sha256:" + "a" * 64


class FakeExecutor:
    def __init__(self, repository: Path, run_root: Path, calls: list[str]):
        self.catalog = load_catalog(repository)
        self.run_root = run_root
        self.calls = calls

    def resolve_image(self, tool):
        return DIGEST

    def execute(self, request):
        self.calls.append(request.tool_id)
        for mount in request.extra_mounts:  # tools run as uid 10001 and must read mounted inputs
            if mount.source.is_file():
                assert mount.source.stat().st_mode & 0o004, f"{mount.source} is unreadable by the tool user"
        request.scratch_root.mkdir(parents=True, exist_ok=True)
        stdout = request.scratch_root / "raw" / "stdout.bin"
        stderr = request.scratch_root / "raw" / "stderr.bin"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        payload = b"{}"
        stdout.write_bytes(payload)
        stderr.write_bytes(b"")
        output_names = {"tool-gitleaks": "output.json", "tool-semgrep": "output.json", "tool-opengrep": "output.json",
                        "tool-gosec": "output.json",
                        "tool-mobsfscan": "output.json", "tool-syft": "output.json", "tool-osv-scanner": "output.json",
                        "tool-grype": "output.json", "tool-trivy": "output.json", "tool-blint": "output.json"}
        if request.tool_id in output_names:
            (request.scratch_root / output_names[request.tool_id]).write_bytes(payload)
        if request.tool_id == "tool-spotbugs":
            (request.scratch_root / "output.xml").write_text("<BugCollection/>", encoding="utf-8")
        if request.tool_id == "tool-cppcheck":
            (request.scratch_root / "output.xml").write_text("<results><errors/></results>", encoding="utf-8")
        if request.tool_id == "tool-pmd":
            (request.scratch_root / "output.json").write_text('{"files":[]}', encoding="utf-8")
        receipt = request.scratch_root / "execution.json"
        receipt.write_text("{}", encoding="utf-8")
        rel = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id, "fixture:1", DIGEST, DIGEST,
            "argv", (), {}, "start", "end", 0, False, False, False, False,
            rel(stdout), rel(stderr), rel(receipt))


def fixture(tmp_path: Path):
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    shutil.copytree(ROOT / "containers", tmp_path / "containers")
    shutil.copytree(ROOT / "rules", tmp_path / "rules")
    if (ROOT / "data" / "feeds" / "osv").exists():
        shutil.copytree(ROOT / "data" / "feeds" / "osv", tmp_path / "data" / "feeds" / "osv")
    target = tmp_path / "target"
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / "main.py").write_text("print('fixture')\n", encoding="utf-8")
    (target / "main.go").write_text("package main\nfunc main(){}\n", encoding="utf-8")
    (target / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (target / "app.php").write_text("<?php echo 'fixture';\n", encoding="utf-8")
    (target / "run.sh").write_text("#!/bin/sh\necho fixture\n", encoding="utf-8")
    (target / "MainActivity.java").write_text("class MainActivity {}\n", encoding="utf-8")
    (target / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
    (target / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    (target / ".github" / "workflows" / "ci.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    (target / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}', encoding="utf-8")
    return load_config(tmp_path / "appsec-review.toml"), target


def test_job_has_explicit_dispositions_and_reuses_only_successful_tool_checkpoints(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    base = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    run_id = base["run_id"]
    planned = plan_applicability(config.runtime.runs_dir / run_id)
    assert len(planned) == 20 and {item["tool_id"] for item in planned}
    calls: list[str] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    gapped = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory, fail_tool="tool-shellcheck")]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert gapped["status"] == "COMPLETED_WITH_GAPS"
    assert "tool-grype" not in calls
    failed_output = gapped["jobs"]["job_evidence_collection"]["result"]["outputs"][
        "evidence_publication.publish_handoff"]
    assert next(item for item in failed_output["dispositions"]
                if item["tool_id"] == "tool-shellcheck")["terminal_status"] == "FAILED"
    before = list(calls)
    resumed = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory)]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert calls[len(before):] == ["tool-shellcheck"]
    output = resumed["jobs"]["job_evidence_collection"]["result"]["outputs"]["evidence_publication.publish_handoff"]
    assert len(output["dispositions"]) == len(planned)
    assert {item["terminal_status"] for item in output["dispositions"]} <= {"SUCCEEDED", "PARTIAL", "NOT_APPLICABLE", "BLOCKED"}
    telemetry = [json.loads(line) for line in (
        config.runtime.runs_dir / run_id / "data" / "logs" / "pipeline.jsonl"
    ).read_text(encoding="utf-8").splitlines()]
    reused_tools = [item["details"] for item in telemetry
                    if item["event_type"] == "TOOL_CHECKPOINT_REUSED"]
    assert {item["tool_id"] for item in reused_tools} >= {"tool-cppcheck", "tool-pmd"}
    assert all(item["checkpoint_reused"] and item["tool_identity"]["image_id"] == DIGEST
               for item in reused_tools)
    shard_events = [item["details"] for item in telemetry
                    if item["event_type"] == "PRODUCER_SHARD_COMPLETED"]
    assert {item["producer"] for item in shard_events} >= {"tool-cppcheck", "tool-pmd"}
    assert all("shard_identity" in item and "result_count" in item for item in shard_events)
    disabled = next(item for item in output["dispositions"] if item["tool_id"] == "tool-grype")
    assert disabled["terminal_status"] == "NOT_APPLICABLE"
    assert any("configured disabled" in gap for gap in disabled["gaps"])

    calls_after = list(calls)
    reused = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory)]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert calls == calls_after
    assert [item["action"] for item in reused["decisions"]] == ["REUSE", "REUSE", "REUSE", "REUSE"]


def test_job_refuses_dispatch_without_graph_target(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    base = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=fingerprint)
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [])
    with pytest.raises(ValueError, match="graph-provided target root"):
        JobRunner(config).run(build_job(executor_factory=factory), run_id=base["run_id"])


class SeiCertExecutor(FakeExecutor):
    """Captures Semgrep/OpenGrep requests and returns engine JSON with a CERT finding and an engine warning."""

    def __init__(self, repository: Path, run_root: Path, calls: list[str], requests: dict):
        super().__init__(repository, run_root, calls)
        self.requests = requests

    def execute(self, request):
        result = super().execute(request)
        if request.tool_id in {"tool-semgrep", "tool-opengrep"}:
            self.requests[request.tool_id] = request
            (request.scratch_root / "output.json").write_text(json.dumps({
                "results": [{
                    "check_id": "rules-sei-cert.cpp.appsec-review.sei-cert.cpp.err34-c.unchecked-conversion-function",
                    "path": "/target/main.cpp", "start": {"line": 1}, "end": {"line": 1},
                    "extra": {"message": "ERR34-C: conversion", "severity": "WARNING",
                              "metadata": {"cert": "ERR34-C", "coverage": "PARTIAL", "cwe": ["CWE-20"],
                                           "cert_url": "https://example.invalid/err34-c", "unrelated": "x"}},
                }],
                "errors": [{"level": "warn", "path": "/target/main.cpp", "message": "Syntax error at line 1"}],
                "paths": {"scanned": ["/target/main.cpp"]},
            }), encoding="utf-8")
        return result


def _evidence(run_root: Path, result: dict, tool_id: str) -> tuple[dict, dict]:
    outputs = result["jobs"]["job_evidence_collection"]["result"]["outputs"]
    item = next(entry for entry in outputs["evidence_publication.publish_handoff"]["dispositions"]
                if entry["tool_id"] == tool_id)
    scan = outputs[f"source_sast.{tool_id.removeprefix('tool-')}_scan"]
    return item, json.loads((run_root / scan["artifact"]["path"]).read_text(encoding="utf-8"))


def test_sei_cert_pack_runs_under_semgrep_and_opengrep_with_mapping_and_gaps(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    calls: list[str] = []
    requests: dict = {}
    factory = lambda unit: SeiCertExecutor(unit.job.repository_root, unit.job.run_root, calls, requests)
    result = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory)]).run(target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / result["run_id"]
    lock = json.loads((tmp_path / "rules" / "sei-cert" / "pack.lock.json").read_text(encoding="utf-8"))
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        request = requests[tool_id]
        mounts = {mount.target: mount for mount in request.extra_mounts}
        assert mounts["/rules-sei-cert"].read_only
        assert mounts["/rules-sei-cert"].source == tmp_path / "rules" / "sei-cert" / "rules"
        assert request.argv[request.argv.index("/rules-sei-cert") - 1] == "--config"
        item, evidence = _evidence(run_root, result, tool_id)
        assert item["terminal_status"] == "PARTIAL"
        assert any("engine reported warn for /target/main.cpp" in gap for gap in evidence["exclusions_and_gaps"])
        assert any("absence of findings is not CERT conformance" in gap for gap in evidence["exclusions_and_gaps"])
        pack = evidence["tool"]["rule_packs"]["appsec-review/sei-cert"]
        assert pack["rule_files_sha256"] == lock["rule_files_sha256"] and pack["tree_sha256"] == lock["tree_sha256"]
        record = evidence["records"][0]
        assert record["native_rule_id"] == "appsec-review.sei-cert.cpp.err34-c.unchecked-conversion-function"
        assert record["rule_mapping"] == {"cert": "ERR34-C", "cert_url": "https://example.invalid/err34-c",
                                          "coverage": "PARTIAL", "cwe": ["CWE-20"]}
        assert record["location"]["path"] == "main.cpp"
        assert len(record["location"]["source_sha256"]) == 64
    semgrep_argv = requests["tool-semgrep"].argv
    assert "/rules/security.yml" in semgrep_argv
    opengrep = requests["tool-opengrep"]
    assert "/rules/security.yml" not in opengrep.argv
    assert {arg for arg in opengrep.argv if arg.startswith("/target/")} == {"/target/main.cpp", "/target/MainActivity.java"}


def test_sei_cert_pack_lock_mismatch_blocks_both_engines(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    rule = tmp_path / "rules" / "sei-cert" / "rules" / "c" / "msc30-c.yml"
    rule.write_text(rule.read_text(encoding="utf-8").replace("pattern: rand()", "pattern: rand(...)"), encoding="utf-8")
    calls: list[str] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    result = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory)]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / result["run_id"]
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        item, evidence = _evidence(run_root, result, tool_id)
        assert item["terminal_status"] == "BLOCKED"
        assert any("SEI CERT rule pack is unavailable or does not match pack.lock.json" in gap
                   for gap in evidence["exclusions_and_gaps"])
        assert tool_id not in calls
