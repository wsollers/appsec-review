"""Whole-graph GraphRunner/JobRunner integration tests for job_evidence_collection."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_evidence_collection import build_job
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner, JobRunner
from tests.unit.job_evidence_collection.support import FakeExecutor, fixture, write_osv_feed


def _evidence(run_root: Path, result: dict, tool_id: str) -> tuple[dict, dict]:
    outputs = result["jobs"]["job_evidence_collection"]["result"]["outputs"]
    item = next(
        value
        for key, value in outputs.items()
        if key.endswith("_scan") and isinstance(value, dict) and value.get("tool_id") == tool_id
    )
    path = run_root / item["artifact"]["path"]
    return item, json.loads(path.read_text(encoding="utf-8"))


def test_job_has_explicit_dispositions_and_reuses_only_successful_tool_checkpoints(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    write_osv_feed(tmp_path, ("npm",))
    calls: list[str] = []

    class ShellcheckFailOnce(FakeExecutor):
        def __init__(self, repository: Path, run_root: Path, call_log: list[str], fail_sc: bool):
            super().__init__(repository, run_root, call_log)
            self.fail_sc = fail_sc

        def execute(self, request):
            res = super().execute(request)
            if request.tool_id == "tool-shellcheck" and self.fail_sc:
                (self.run_root / res.stderr_path).write_bytes(b"simulated failure")
                return replace(res, exit_code=2)
            return res

    first_job = build_job(executor_factory=lambda u: ShellcheckFailOnce(u.job.repository_root, u.job.run_root, calls, True))
    first = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), first_job]).run(
        target_root=target,
        source_fingerprint=source_fingerprint(target),
    )
    assert first["jobs"]["job_evidence_collection"]["status"] == "COMPLETED_WITH_GAPS"
    outputs = first["jobs"]["job_evidence_collection"]["result"]["outputs"]
    dispositions = {item["tool_id"]: item for item in outputs["evidence_publication.assemble_manifest"]["dispositions"]}
    assert dispositions["tool-grype"]["terminal_status"] == "NOT_APPLICABLE"
    assert dispositions["tool-spotbugs"]["terminal_status"] == "NOT_APPLICABLE"
    assert dispositions["tool-shellcheck"]["terminal_status"] == "FAILED"
    assert dispositions["tool-gitleaks"]["terminal_status"] == "SUCCEEDED"

    run_root = config.runtime.runs_dir / first["run_id"]
    manifest = json.loads(
        (run_root / outputs["evidence_publication.publish_handoff"]["index_manifest"]["path"]).read_text(
            encoding="utf-8"
        )
    )
    registered = {
        (item["name"], item["shard_id"])
        for item in manifest["indexes"]
        if item.get("producer", {}).get("job") == "job_evidence_collection"
    }
    assert len(registered) == len(dispositions)

    calls.clear()
    second_job = build_job(executor_factory=lambda u: ShellcheckFailOnce(u.job.repository_root, u.job.run_root, calls, False))
    second = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), second_job]).run(
        target_root=target,
        source_fingerprint=source_fingerprint(target),
    )
    assert second["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    assert calls == ["tool-shellcheck"]


def test_job_refuses_dispatch_without_graph_target(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan()]).run(
        target_root=target,
        source_fingerprint=source_fingerprint(target),
    )
    assert upstream["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    runner = JobRunner(config, repository_root=tmp_path)
    with pytest.raises(ValueError, match="target root"):
        runner.run(
            build_job(executor_factory=lambda u: FakeExecutor(u.job.repository_root, u.job.run_root, [])),
            run_id=upstream["run_id"],
            source_fingerprint=source_fingerprint(target),
        )


def test_sei_cert_pack_runs_under_semgrep_and_opengrep_with_mapping_and_gaps(tmp_path: Path) -> None:
    config, target = fixture(tmp_path)
    (target / "cert.c").write_text("#include <stdlib.h>\nint f(void) { return rand(); }\n", encoding="utf-8")
    (target / "App.kt").write_text("fun main() {}\n", encoding="utf-8")
    calls: list[str] = []

    class SeiCertExecutor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            if request.tool_id in {"tool-semgrep", "tool-opengrep"}:
                assert "--config" in request.argv and "/rules-sei-cert" in request.argv
                mounts = {mount.target: mount for mount in request.extra_mounts}
                assert mounts["/rules-sei-cert"].read_only is True
                payload = {
                    "results": [{
                        "check_id": "rules-sei-cert.c.appsec-review.sei-cert.c.msc30-c.rand-call",
                        "path": "/target/cert.c",
                        "start": {"line": 2},
                        "end": {"line": 2},
                        "extra": {
                            "message": "MSC30-C candidate",
                            "severity": "WARNING",
                            "metadata": {"cert": "MSC30-C", "cwe": ["CWE-338"]},
                        },
                    }],
                    "errors": [{"level": "error", "rule_id": "bad-rule", "message": "parse failure"}],
                    "paths": {"scanned": ["/target/cert.c"], "skipped": [{"path": "/target/cert.c", "reason": "partial"}]},
                }
                (request.scratch_root / "output.json").write_text(json.dumps(payload), encoding="utf-8")
            return result

    result = GraphRunner(
        config,
        [
            build_intake(),
            build_catalog(),
            build_analysis_plan(),
            build_job(executor_factory=lambda u: SeiCertExecutor(u.job.repository_root, u.job.run_root, calls)),
        ],
    ).run(target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / result["run_id"]
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        item, evidence = _evidence(run_root, result, tool_id)
        assert item["terminal_status"] in {"SUCCEEDED", "PARTIAL"}
        assert evidence["tool"]["rule_packs"][tool_id]["assurance"] == "supplied_platform_excluded"
        assert tool_id in calls
