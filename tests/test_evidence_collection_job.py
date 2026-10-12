from __future__ import annotations

import hashlib
import json
import os
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
from appsec_review.rulepacks.sei_cert.pack import PackVerificationError, verify_pack, write_lock
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
        assert pack["verified"] is True and pack["verified_scope"] == "complete-pack"
        assert pack["rule_files_scope"].startswith("executable-rules-subset")
        assert pack["tree_file_count"] == len(lock["files"])
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


SEI_CERT_BLOCKED = "SEI CERT rule pack is unavailable or does not match pack.lock.json"


def _append(relative: str, data: str = "\n"):
    def mutate(pack: Path) -> None:
        with (pack / relative).open("a", encoding="utf-8") as stream:
            stream.write(data)
    return mutate


def _remove(relative: str):
    return lambda pack: (pack / relative).unlink()


def _add(relative: str, data: str = "{}\n"):
    return lambda pack: (pack / relative).write_text(data, encoding="utf-8")


def _symlink(pack: Path) -> None:
    (pack / "mappings" / "c-alias.json").symlink_to("c.json")


def _fifo(pack: Path) -> None:
    os.mkfifo(pack / "fixtures" / "c" / "pipe.c")


def _duplicate_lock_key(pack: Path) -> None:
    lock = pack / "pack.lock.json"
    text = lock.read_text(encoding="utf-8")
    # json.loads would silently keep the last value; the strict verifier must reject the document.
    lock.write_text(text.replace("{\n", '{\n  "schema": "appsec-review/sei-cert-rule-pack-lock/1",\n', 1),
                    encoding="utf-8")


PACK_MUTATIONS = {
    "rule-changed": (_append("rules/c/msc30-c.yml", "# changed\n"), "locked file changed: rules/c/msc30-c.yml"),
    "rule-removed": (_remove("rules/c/msc30-c.yml"), "locked file is missing: rules/c/msc30-c.yml"),
    "rule-added": (_add("rules/c/extra.yml", "rules: []\n"),
                   "unexpected file not recorded in pack.lock.json: rules/c/extra.yml"),
    "mapping-changed": (_append("mappings/c.json"), "locked file changed: mappings/c.json"),
    "mapping-removed": (_remove("mappings/c.json"), "locked file is missing: mappings/c.json"),
    "mapping-added": (_add("mappings/extra.json"), "unexpected file not recorded in pack.lock.json: mappings/extra.json"),
    "source-index-changed": (_append("sources/cert-source-index.json"),
                             "locked file changed: sources/cert-source-index.json"),
    "source-index-removed": (_remove("sources/cert-source-index.json"),
                             "locked file is missing: sources/cert-source-index.json"),
    "source-index-added": (_add("sources/extra.json"),
                           "unexpected file not recorded in pack.lock.json: sources/extra.json"),
    "fixture-changed": (_append("fixtures/c/msc30-c.c", "/* changed */\n"), "locked file changed: fixtures/c/msc30-c.c"),
    "fixture-removed": (_remove("fixtures/c/msc30-c.c"), "locked file is missing: fixtures/c/msc30-c.c"),
    "fixture-added": (_add("fixtures/c/extra.c", "int x;\n"),
                      "unexpected file not recorded in pack.lock.json: fixtures/c/extra.c"),
    "manifest-changed": (_append("pack.json"), "locked file changed: pack.json"),
    "manifest-removed": (_remove("pack.json"), "pack.json is missing"),
    "coverage-doc-changed": (_append("COVERAGE.md", "extra\n"), "locked file changed: COVERAGE.md"),
    "coverage-doc-removed": (_remove("COVERAGE.md"), "locked file is missing: COVERAGE.md"),
    "unexpected-root-file": (_add("NOTES.txt", "note\n"), "unexpected file not recorded in pack.lock.json: NOTES.txt"),
    "symlink": (_symlink, "symlinks are not allowed in the pack: mappings/c-alias.json"),
    "fifo": (_fifo, "non-regular file is not allowed in the pack: fixtures/c/pipe.c"),
    "duplicate-lock-key": (_duplicate_lock_key, "pack.lock.json: duplicate JSON key 'schema'"),
}


def test_unmodified_sei_cert_pack_identity_labels_both_digests(tmp_path: Path) -> None:
    pack = tmp_path / "sei-cert"
    shutil.copytree(ROOT / "rules" / "sei-cert", pack)
    lock_bytes = (pack / "pack.lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    record = verify_pack(pack).as_record()
    assert record["verified"] is True and record["verified_scope"] == "complete-pack"
    assert record["tree_sha256"] == lock["tree_sha256"]
    assert record["tree_scope"].startswith("complete-pack")
    assert record["tree_file_count"] == len(lock["files"])
    assert record["rule_files_sha256"] == lock["rule_files_sha256"] != record["tree_sha256"]
    assert record["rule_files_scope"].startswith("executable-rules-subset")
    assert record["rule_file_count"] == len(json.loads((pack / "pack.json").read_text(encoding="utf-8"))["rule_files"])
    assert record["lock_sha256"] == hashlib.sha256(lock_bytes).hexdigest()
    assert (record["id"], record["version"]) == (lock["pack"], lock["version"])


@pytest.mark.parametrize("case", sorted(PACK_MUTATIONS))
def test_sei_cert_pack_change_is_rejected_by_strict_verifier(tmp_path: Path, case: str) -> None:
    pack = tmp_path / "sei-cert"
    shutil.copytree(ROOT / "rules" / "sei-cert", pack)
    mutate, message = PACK_MUTATIONS[case]
    mutate(pack)
    with pytest.raises(PackVerificationError) as raised:
        verify_pack(pack)
    assert message in raised.value.problems


@pytest.mark.parametrize("case", sorted(PACK_MUTATIONS))
def test_sei_cert_pack_change_blocks_both_engines(tmp_path: Path, case: str) -> None:
    config, target = fixture(tmp_path)
    PACK_MUTATIONS[case][0](tmp_path / "rules" / "sei-cert")
    calls: list[str] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    result = GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory)]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / result["run_id"]
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        item, evidence = _evidence(run_root, result, tool_id)
        assert item["terminal_status"] == "BLOCKED"
        assert any(SEI_CERT_BLOCKED in gap for gap in evidence["exclusions_and_gaps"])
        assert evidence["tool"]["rule_packs"]["appsec-review/sei-cert"] == {"verified": False}
        assert tool_id not in calls


def test_sei_cert_pack_change_never_reuses_checkpoint_under_old_identity(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, target = fixture(tmp_path)
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(tmp_path / "appsec-review.toml"))
    pack = tmp_path / "rules" / "sei-cert"
    fingerprint = source_fingerprint(target)
    calls: list[str] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    graph = lambda: GraphRunner(config, [build_intake(), build_catalog(), build_analysis_plan(), build_job(
        executor_factory=factory)])
    first = graph().run(target_root=target, source_fingerprint=fingerprint)
    run_id = first["run_id"]
    run_root = config.runtime.runs_dir / run_id
    assert {"tool-semgrep", "tool-opengrep"} <= set(calls)
    old = _evidence(run_root, first, "tool-semgrep")[1]["tool"]["rule_packs"]["appsec-review/sei-cert"]

    # A locked mapping changes without re-locking: the job must re-run and block, not reuse.
    _append("mappings/c.json")(pack)
    before = len(calls)
    blocked = graph().run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert blocked["decisions"][-1]["action"] != "REUSE"
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        item, evidence = _evidence(run_root, blocked, tool_id)
        assert item["terminal_status"] == "BLOCKED" and not item.get("checkpoint_reused")
        assert evidence["tool"]["rule_packs"]["appsec-review/sei-cert"] == {"verified": False}
    assert not {"tool-semgrep", "tool-opengrep"} & set(calls[before:])

    # Re-locked, the pack verifies under a new complete-pack identity. The executable subset is
    # unchanged, so only the complete-pack binding prevents reuse of the old scan checkpoint.
    write_lock(pack)
    before = len(calls)
    relocked = graph().run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert {"tool-semgrep", "tool-opengrep"} <= set(calls[before:])
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        item, evidence = _evidence(run_root, relocked, tool_id)
        assert not item.get("checkpoint_reused")
        new = evidence["tool"]["rule_packs"]["appsec-review/sei-cert"]
        assert new["verified"] is True and new["tree_sha256"] != old["tree_sha256"]
        assert new["rule_files_sha256"] == old["rule_files_sha256"]
        assert new["lock_sha256"] != old["lock_sha256"]
