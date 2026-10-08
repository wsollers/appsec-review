from __future__ import annotations

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
        request.scratch_root.mkdir(parents=True, exist_ok=True)
        stdout = request.scratch_root / "raw" / "stdout.bin"
        stderr = request.scratch_root / "raw" / "stderr.bin"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        payload = b"{}"
        stdout.write_bytes(payload)
        stderr.write_bytes(b"")
        output_names = {"tool-gitleaks": "output.json", "tool-semgrep": "output.json", "tool-gosec": "output.json",
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
    assert len(planned) == 19 and {item["tool_id"] for item in planned}
    calls: list[str] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    gapped = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory, fail_tool="tool-shellcheck")]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert gapped["status"] == "COMPLETED_WITH_GAPS"
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
