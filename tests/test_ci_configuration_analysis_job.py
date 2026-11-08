"""job_ci_configuration_analysis through the real runner (job pass 07).

Unit tests: the real configuration, the real GraphRunner with intake and the catalog, a small synthetic
target under tmp_path, and a fake only at the container boundary (tests/ci_support.FakeExecutor). No
Docker, no model, no network, no targets/ checkout. The static rules, discovery and correlation key are
unit-tested in tests/test_ci_configuration_analysis.py; this file proves what the job publishes, how its
bounded gaps become producer-gap/1 records, how a failing or unavailable linter is reported while its
siblings survive, and the job's telemetry.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_ci_configuration_analysis import build_job
from appsec_review.jobs.job_ci_configuration_analysis.job import JOB_ID, SPECS, CiConfigurationAnalysisFailed, analysis_bounds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from tests.ci_support import DIGEST, FakeExecutor
from tests.telemetry_support import assert_job_lifecycle, job_events

ROOT = Path(__file__).resolve().parents[1]

WORKFLOW = """name: build
on:
  pull_request_target:
    branches: [main]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: curl -sSL https://example.invalid/install.sh | sh
        continue-on-error: true
      - run: echo "${{ secrets.DEPLOY_TOKEN }}"
"""
GITLAB = """stages: [build]
build:
  stage: build
  image: node:latest
  script:
    - npm ci
"""
JENKINS = """pipeline {
  agent any
  stages {
    stage('Build') {
      steps { sh 'make' }
    }
  }
}
"""
TRAVIS = "language: c\nscript: make\n"
TARGET = {".github/workflows/build.yml": WORKFLOW, ".gitlab-ci.yml": GITLAB, "Jenkinsfile": JENKINS, ".travis.yml": TRAVIS,
          "src/main.c": "int main(void) { return 0; }\n", "Makefile": "all:\n\t$(CC) src/main.c -o main\n"}


def _config(tmp_path: Path):
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    shutil.copytree(ROOT / "containers", tmp_path / "containers")
    (tmp_path / "profiles").mkdir()
    return load_config(tmp_path / "appsec-review.toml", profile="dev")


def _target(tmp_path: Path, files: dict[str, str] = TARGET) -> Path:
    target = tmp_path / "target"
    for relative, text in files.items():
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text(text, encoding="utf-8")
    return target


def _run(config, target: Path, job):
    try:
        outcome = GraphRunner(config, [build_intake(), build_catalog(), job]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    except RuntimeError as error:
        [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
        return {"status": "FAILED", "error": str(error), "run_id": run_root.name}, run_root
    return outcome, config.runtime.runs_dir / outcome["run_id"]


def _outputs(outcome) -> dict:
    return outcome["jobs"][JOB_ID]["result"]["outputs"]


def test_a_mixed_target_publishes_definitions_observations_findings_and_coverage(tmp_path: Path) -> None:
    config = _config(tmp_path)
    calls: list[tuple[str, tuple[str, ...]]] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    outcome, run_root = _run(config, _target(tmp_path), build_job(executor_factory=factory))
    # The travis file has no linter: that is a reported gap, so the attempt completes with gaps.
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    outputs = _outputs(outcome)
    discovered = outputs["ci_discovery.discover_definitions"]
    assert [(d["provider"], d["path"]) for d in discovered["definitions"]] == [
        ("github", ".github/workflows/build.yml"), ("gitlab", ".gitlab-ci.yml"), ("jenkins", "Jenkinsfile"), ("other", ".travis.yml")]
    assert discovered["gaps"] == []
    # External linters ran only over their provider's definitions, mounted read-only under /target.
    assert {tool for tool, _ in calls} == {"tool-zizmor", "tool-checkov", "tool-actionlint"}
    assert all(argv[-1].startswith("/target/") for _, argv in calls)
    assert sorted(argv[-1] for tool, argv in calls if tool == "tool-checkov") == ["/target/.github/workflows/build.yml", "/target/.gitlab-ci.yml"]
    # The static GitHub rules found the workflow's problems; every record is bound to a source line.
    github = outputs["ci_observation_publication.github_schema_index"]
    rules = {record["native_rule_id"] for record in github["records"]}
    assert {"CI-UNTRUSTED-TRIGGER", "CI-WRITE-ALL", "CI-MUTABLE-DEPENDENCY", "CI-PIPE-COMMAND", "CI-CONTINUE-ON-ERROR", "CI-SECRET-OUTPUT"} <= rules
    assert all(record["path"] == ".github/workflows/build.yml" and record["start_line"] >= 1 for record in github["records"])
    assert all("DEPLOY_TOKEN" not in record["message"] for record in github["records"]), "secret references are redacted"
    assert github["terminal_status"] == "SUCCEEDED" and github["gaps"] == []
    # Providers with no definitions are NOT_APPLICABLE and carry no gap at all.
    for spec in SPECS:
        if spec.provider in {"azure", "circleci", "bitbucket", "teamcity"}:
            scan = outputs[f"ci_analysis.{spec.key}_scan"]
            assert scan["terminal_status"] == "NOT_APPLICABLE" and scan["gaps"] == [] and scan["record_count"] == 0, spec.key
    # The provider without a linter is a reported gap scoped to its definition.
    [other] = outputs["ci_analysis.other_discovery_scan"]["gaps"]
    assert other["code"] == "producer_reported_gap" and other["scope_id"] == ".travis.yml" and other["retryable"] is False
    assert other["unit_id"] == "ci_analysis.other_discovery_scan"
    # The gitlab static scan sees the mutable image tag; the fake linters returned no observations.
    assert {r["native_rule_id"] for r in outputs["ci_observation_publication.gitlab_schema_index"]["records"]} == {"CI-MUTABLE-DEPENDENCY"}
    coverage = outputs["ci_coverage.join_coverage"]
    assert coverage["coverage_status"] == "partial" and coverage["definitions_by_provider"]["github"] == 1
    assert [g["gap_id"] for g in coverage["gap_records"]] == [other["gap_id"]] and coverage["gaps"] == []
    published = outputs["ci_coverage.publish_handoff"]
    assert published["terminal_status"] == "SUCCEEDED" and published["finding_count"] >= 7
    assert published["gaps"] == [] and published["gap_count"] == 1 and published["coverage_status"] == "partial"
    document = json.loads((run_root / published["artifact"]["path"]).read_bytes())
    assert document["gaps"] == [other["reason"]], "the handoff document keeps the human reasons"
    assert document["index_manifest"]["sha256"] and document["finding_count"] == published["finding_count"]
    # Telemetry: discovery counts, one scan event per tool unit, the publication, the lifecycle.
    [found] = job_events(run_root, JOB_ID, "CI_DEFINITIONS_DISCOVERED")
    assert found["definition_count"] == 4 and found["by_provider"]["github"] == 1 and found["by_provider"]["azure"] == 0
    scanned = job_events(run_root, JOB_ID, "CI_TOOL_SCANNED")
    assert len(scanned) == len(SPECS) and {s["tool_id"] for s in scanned} == {spec.tool_id for spec in SPECS}
    github_schema = next(s for s in scanned if s["unit_id"] == "ci_analysis.github_schema_scan")
    assert github_schema["terminal_status"] == "SUCCEEDED" and github_schema["record_count"] == github["record_count"]
    [publication] = job_events(run_root, JOB_ID, "CI_ANALYSIS_PUBLISHED")
    assert publication["finding_count"] == published["finding_count"] and publication["gap_count"] == 1
    assert_job_lifecycle(run_root, JOB_ID, terminal="COMPLETED_WITH_GAPS")


def test_a_github_only_target_with_every_linter_succeeding_is_a_clean_success(tmp_path: Path) -> None:
    config = _config(tmp_path)
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [])
    outcome, run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}), build_job(executor_factory=factory))
    assert outcome["status"] == "SUCCEEDED", outcome
    outputs = _outputs(outcome)
    assert outputs["ci_coverage.join_coverage"]["coverage_status"] == "complete"
    assert outputs["ci_coverage.publish_handoff"]["terminal_status"] == "SUCCEEDED"
    assert all(outputs[f"ci_analysis.{spec.key}_scan"]["gaps"] == [] for spec in SPECS)
    assert_job_lifecycle(run_root, JOB_ID, terminal="SUCCEEDED")


def test_a_failing_linter_is_a_producer_failed_gap_and_its_siblings_survive(tmp_path: Path) -> None:
    config = _config(tmp_path)
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [])
    outcome, run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}),
                             build_job(executor_factory=factory, fail_tool="github_zizmor"))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    outputs = _outputs(outcome)
    zizmor = outputs["ci_analysis.github_zizmor_scan"]
    assert zizmor["terminal_status"] == "FAILED" and zizmor["record_count"] == 0
    [gap] = zizmor["gaps"]
    assert gap["code"] == "producer_failed" and gap["scope_id"] == ".github/workflows/build.yml" and gap["retryable"] is False
    assert "injected bounded failure" in gap["reason"]
    assert outputs["ci_analysis.github_schema_scan"]["terminal_status"] == "SUCCEEDED"
    assert outputs["ci_analysis.github_checkov_scan"]["terminal_status"] == "SUCCEEDED"
    assert outputs["ci_correlation.correlate_findings"]["finding_count"] > 0
    assert [g["gap_id"] for g in outputs["ci_coverage.join_coverage"]["gap_records"]] == [gap["gap_id"]]
    index = outputs["ci_observation_publication.github_zizmor_index"]
    assert index["index_identity"]["gaps"] == [gap["reason"]], "the retrieval index carries the reason"
    scanned = next(s for s in job_events(run_root, JOB_ID, "CI_TOOL_SCANNED") if s["tool_id"] == "tool-zizmor")
    assert scanned["terminal_status"] == "FAILED" and scanned["gap_count"] == 1
    assert_job_lifecycle(run_root, JOB_ID, terminal="COMPLETED_WITH_GAPS")


def test_an_unavailable_pinned_image_is_a_retryable_producer_blocked_gap(tmp_path: Path) -> None:
    config = _config(tmp_path)

    def factory(unit):
        raise RuntimeError("image not present on the local daemon")

    outcome, run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}), build_job(executor_factory=factory))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    outputs = _outputs(outcome)
    for key in ("github_zizmor", "github_checkov", "github_actionlint"):
        scan = outputs[f"ci_analysis.{key}_scan"]
        [gap] = scan["gaps"]
        assert scan["terminal_status"] == "FAILED" and gap["code"] == "producer_blocked" and gap["retryable"] is True
        assert "pinned offline image unavailable" in gap["reason"] and gap["scope_id"] is None
    assert outputs["ci_analysis.github_schema_scan"]["terminal_status"] == "SUCCEEDED"
    assert len(outputs["ci_coverage.join_coverage"]["gap_records"]) == 3
    assert_job_lifecycle(run_root, JOB_ID, terminal="COMPLETED_WITH_GAPS")


def test_a_linter_exit_code_outside_the_accepted_set_is_a_producer_failed_gap_per_definition(tmp_path: Path) -> None:
    config = _config(tmp_path)
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [], exit_code=2)
    outcome, _run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}), build_job(executor_factory=factory))
    outputs = _outputs(outcome)
    for key in ("github_zizmor", "github_checkov", "github_actionlint"):
        [gap] = outputs[f"ci_analysis.{key}_scan"]["gaps"]
        assert gap["code"] == "producer_failed" and "exit=2" in gap["reason"] and gap["scope_id"] == ".github/workflows/build.yml"


def test_linter_observations_are_parsed_redacted_and_correlated_with_the_static_rules(tmp_path: Path) -> None:
    config = _config(tmp_path)
    checkov = json.dumps({"results": {"failed_checks": [
        {"check_id": "CKV_GHA_7", "check_name": "workflow_dispatch inputs", "file_line_range": [3, 4],
         "severity": "HIGH"}]}}).encode()
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [], stdout={"tool-checkov": checkov})
    outcome, run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}), build_job(executor_factory=factory))
    outputs = _outputs(outcome)
    assert outputs["ci_observation_publication.github_zizmor_index"]["records"] == [], "only checkov spoke"
    checkov_records = outputs["ci_observation_publication.github_checkov_index"]["records"]
    [record] = checkov_records
    assert (record["native_rule_id"], record["severity"], record["start_line"], record["end_line"]) == ("CKV_GHA_7", "high", 3, 4)
    assert record["pipeline"] == ".github/workflows/build.yml" and record["observation_id"].startswith("cio:")
    findings = outputs["ci_correlation.correlate_findings"]["findings"]
    assert any(f["tools"] == ["tool-checkov"] and f["start_line"] == 3 for f in findings)
    assert all(f["exact_duplicate_count"] >= 1 and f["finding_id"].startswith("cif:") for f in findings)
    assert outcome["status"] == "SUCCEEDED"


def test_a_target_without_ci_definitions_is_not_applicable_everywhere_and_succeeds(tmp_path: Path) -> None:
    config = _config(tmp_path)
    factory = lambda unit: pytest.fail("no linter may be launched without a definition")
    outcome, run_root = _run(config, _target(tmp_path, {"src/main.c": TARGET["src/main.c"], "Makefile": TARGET["Makefile"]}),
                             build_job(executor_factory=factory))
    assert outcome["status"] == "SUCCEEDED"
    outputs = _outputs(outcome)
    assert all(outputs[f"ci_analysis.{spec.key}_scan"]["terminal_status"] == "NOT_APPLICABLE" for spec in SPECS)
    assert outputs["ci_coverage.publish_handoff"]["finding_count"] == 0 and outputs["ci_coverage.join_coverage"]["coverage_status"] == "complete"
    [found] = job_events(run_root, JOB_ID, "CI_DEFINITIONS_DISCOVERED")
    assert found["definition_count"] == 0
    assert_job_lifecycle(run_root, JOB_ID, terminal="SUCCEEDED")


def _config_with_setting(tmp_path: Path, key: str, value: int):
    """The real configuration with one value in the CI job's settings block replaced."""
    _config(tmp_path)
    text = (tmp_path / "appsec-review.toml").read_text(encoding="utf-8")
    block = text.index("[jobs.job_ci_configuration_analysis.settings]")
    end = text.index("\n[", block)
    assert text.count(f"{key} = ", block, end) == 1
    line = text.index(f"{key} = ", block)
    text = text[:line] + f"{key} = {value}" + text[text.index("\n", line):]
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    return load_config(tmp_path / "appsec-review.toml", profile="dev")


def test_discovery_bound_is_a_truncated_gap_on_the_discovery_unit(tmp_path: Path) -> None:
    config = _config_with_setting(tmp_path, "max_files", 1)
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [])
    outcome, _run_root = _run(config, _target(tmp_path), build_job(executor_factory=factory))
    discovered = _outputs(outcome)["ci_discovery.discover_definitions"]
    assert len(discovered["definitions"]) == 1
    [gap] = discovered["gaps"]
    assert gap["code"] == "truncated" and "max_files=1" in gap["reason"] and gap["unit_id"] == "ci_discovery.discover_definitions"
    assert gap["gap_id"] in {g["gap_id"] for g in _outputs(outcome)["ci_coverage.join_coverage"]["gap_records"]}


def test_out_of_range_bounds_are_refused_at_claim_time_not_inside_a_unit() -> None:
    with pytest.raises(ValueError, match="bounds are outside"):
        analysis_bounds({"max_files": 0})
    with pytest.raises(ValueError, match="observation bound"):
        analysis_bounds({"max_observations_per_tool": 1_000_000})
    assert analysis_bounds({}) == (128, 1_048_576, 5_000)


def test_configured_topology_matches_the_job_and_the_job_is_strict() -> None:
    from appsec_review.jobs.job_ci_configuration_analysis.job import TOPOLOGY
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    job = config.jobs[JOB_ID]
    assert tuple(job.steps) == tuple(TOPOLOGY)
    for step, tasks in TOPOLOGY.items():
        assert tuple(job.step(step).tasks) == tasks
    built = build_job()
    assert {unit.unit_id for unit in built.units} == {f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks}
    assert built.strict_gaps is True
    assert issubclass(CiConfigurationAnalysisFailed, RuntimeError)


def test_a_definition_over_the_file_bound_is_a_scoped_reported_gap_on_every_static_reader(tmp_path: Path) -> None:
    config = _config_with_setting(tmp_path, "max_file_bytes", 16)
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [])
    outcome, _run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}), build_job(executor_factory=factory))
    outputs = _outputs(outcome)
    [gap] = outputs["ci_analysis.github_schema_scan"]["gaps"]
    assert gap["code"] == "producer_reported_gap" and gap["scope_id"] == ".github/workflows/build.yml"
    assert "max_file_bytes" in gap["reason"] and not gap["retryable"]
    assert outputs["ci_analysis.github_schema_scan"]["record_count"] == 0
    [hierarchy_gap] = outputs["ci_enrichment.build_hierarchy"]["gaps"]
    assert hierarchy_gap["code"] == "producer_reported_gap" and "hierarchy max_file_bytes" in hierarchy_gap["reason"]
    assert outputs["ci_enrichment.build_hierarchy"]["node_count"] == 0
    assert outcome["status"] == "COMPLETED_WITH_GAPS"


def test_the_observation_bound_keeps_the_first_observations_and_declares_truncation(tmp_path: Path) -> None:
    config = _config_with_setting(tmp_path, "max_observations_per_tool", 1)
    checkov = json.dumps({"results": {"failed_checks": [
        {"check_id": "CKV_GHA_7", "check_name": "first", "file_line_range": [3, 4]},
        {"check_id": "CKV_GHA_1", "check_name": "second", "file_line_range": [5, 5]}]}}).encode()
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, [], stdout={"tool-checkov": checkov})
    outcome, _run_root = _run(config, _target(tmp_path, {".github/workflows/build.yml": WORKFLOW}), build_job(executor_factory=factory))
    outputs = _outputs(outcome)
    scan = outputs["ci_analysis.github_checkov_scan"]
    assert scan["record_count"] == 1 and scan["terminal_status"] == "PARTIAL"
    [gap] = scan["gaps"]
    assert gap["code"] == "truncated" and gap["scope_id"] is None and "observation bound reached at 1" in gap["reason"]
    [record] = outputs["ci_observation_publication.github_checkov_index"]["records"]
    assert record["native_rule_id"] == "CKV_GHA_7"
