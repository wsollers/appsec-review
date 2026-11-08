"""job_target_catalog through the real runner over the topology fixture monorepo.

Unit tests: the real configuration, the real GraphRunner (intake as the producer, built without a
provider check), the committed fixture under test/topology/monorepo as the target. No Docker, no
model, no network. Discovery's own decisions are unit-tested in tests/test_build_discovery.py; this
file proves what the published catalog carries for a monorepo and how the job fails and reports.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_catalog.job import TOPOLOGY
from appsec_review.runtime import GraphRunner
from tests.telemetry_support import assert_job_lifecycle, job_events

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "test" / "topology" / "monorepo"
JOB_ID = "job_target_catalog"


def _config(tmp_path: Path):
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    return load_config(tmp_path / "appsec-review.toml", profile="dev")


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target, ignore=shutil.ignore_patterns("MANIFEST.json"))
    return target


def _run(config, target: Path, catalog):
    try:
        outcome = GraphRunner(config, [build_intake(), catalog]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    except RuntimeError as error:
        outcome = {"status": "FAILED", "error": str(error)}
    [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
    return outcome, run_root


def _artifact(run_root: Path, name: str) -> dict:
    return json.loads(next(run_root.rglob(f"jobs/{JOB_ID}/attempts/*/**/{name}")).read_text(encoding="utf-8"))


def test_the_catalog_of_a_monorepo_names_every_build_shape_once(tmp_path: Path) -> None:
    config = _config(tmp_path)
    target = _target(tmp_path)
    outcome, run_root = _run(config, target, build_catalog())
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome
    systems = _artifact(run_root, "build-systems.json")
    units = {(unit["root"], unit["build_system"]): unit for unit in systems["build_units"]}
    # The settings-only Gradle root is one unit that names its modules; the modules stay units.
    assert units[("client-android", "gradle")]["workspace"] == {
        "manager": "gradle", "role": "root", "root": "client-android",
        "members": ["client-android/app", "client-android/lib"]}
    assert units[("client-android/app", "gradle")]["workspace"]["role"] == "member"
    # The Xcode project is a swift/xcodebuild unit under the Swift policy, rooted at the bundle's parent.
    ios = units[("client-ios", "xcodebuild")]
    assert ios["family"] == "swift" and ios["language"] == "swift" and ios["descriptor_facts"]["kind"] == "xcode-project"
    # Cargo and Go workspaces are stated as facts on root and members.
    assert units[("rust", "cargo")]["workspace"]["members"] == ["rust/cli", "rust/core"]
    assert units[("go", "go")]["workspace"]["members"] == ["go/shared", "go/svc"]
    assert units[("rust/cli", "cargo")]["workspace"] == {"manager": "cargo", "role": "member", "root": "rust"}
    # A sibling source a Makefile names is that unit's component; no manufactured root for common/.
    assert ("common", "direct-native") not in units
    assert [c["path"] for c in units[("tools/packer", "make")]["native_components"]] == ["common/src/util.c"]
    # The vendored test Makefile that reaches ../src stays a unit (ownership is the plan's, T-035).
    assert ("server/third_party/tinylib/test", "make") in units
    # Unity is an engine project, PHP without composer is a source-only scope.
    assert units[("client-unity", "unity")]["engine"]
    assert any(scope["root"] == "website/public" and scope["language"] == "php" for scope in systems["source_only_scopes"])
    assert ("website/public", "composer") not in units and ("website/lib", "composer") in units
    # Every unit carries the profile it needs.
    targets = {(t["root"], t["build_system"]): t for t in _artifact(run_root, "build-targets.json")["targets"]}
    assert targets[("client-android", "gradle")]["required_image_profile"] == "android"
    assert targets[("client-ios", "xcodebuild")]["required_image_profile"] == "swift"
    assert targets[("server", "cmake")]["required_image_profile"] == "native"
    # Telemetry: the lifecycle and the catalog's own completion event with its receipts.
    assert_job_lifecycle(run_root, JOB_ID, terminal=outcome["status"])
    [cataloged] = job_events(run_root, JOB_ID, "REVIEW_SCOPE_CATALOGED")
    for key in ("source_receipt", "project_receipt", "build_target_receipt", "catalog_receipt"):
        assert (run_root / cataloged[key]["path"]).is_file(), key
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_text(encoding="utf-8"))
    handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
    assert handoff["outputs"]["publish_catalog.publish_handoff"]["index_manifest"]["path"].startswith("data/indices/manifests/")


@pytest.mark.parametrize("unit_id", ["repository_discovery.partition_repository", "build_discovery.catalog_build_targets",
                                     "publish_catalog.validate_catalog"], ids=["partition", "targets", "validate"])
def test_a_failing_unit_fails_the_attempt_keeps_upstream_evidence_and_publishes_nothing(tmp_path: Path, unit_id: str) -> None:
    config = _config(tmp_path)
    target = _target(tmp_path)
    outcome, run_root = _run(config, target, build_catalog(fail_task=unit_id))
    assert outcome["status"] == "FAILED" and f"injected bounded failure: {unit_id}" in outcome["error"]
    assert not (run_root / "data/jobs" / JOB_ID / "latest.json").exists()
    step, task = unit_id.split(".")
    receipt = json.loads(next(run_root.rglob(f"jobs/{JOB_ID}/attempts/*/steps/{step}/tasks/{task}/status.json"))
                         .read_text(encoding="utf-8"))
    assert receipt["status"] == "FAILED" and receipt["error"]["type"] == "RuntimeError"
    if unit_id != "repository_discovery.partition_repository":
        # Units the failed one did not depend on still ran and left their artifacts.
        assert next(run_root.rglob(f"jobs/{JOB_ID}/attempts/*/**/repository-partition.json")).is_file()
    assert job_events(run_root, JOB_ID, "REVIEW_SCOPE_CATALOGED") == []
    assert_job_lifecycle(run_root, JOB_ID, terminal="FAILED")


def test_the_catalog_is_reused_on_resume_and_rebuilt_when_the_target_changes(tmp_path: Path) -> None:
    from tests.release_support import write_release
    config = _config(tmp_path)
    write_release(tmp_path, ("job_review_intake", JOB_ID))
    target = _target(tmp_path)
    fingerprint = source_fingerprint(target)
    first = GraphRunner(config, [build_intake(), build_catalog()]).run(target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / first["run_id"]
    second = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    assert {item["job_id"]: item["action"] for item in second["decisions"]} == {
        "job_review_intake": "REUSE", JOB_ID: "REUSE"}
    assert len(list((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())) == 1
    # A changed target is a new fingerprint: planning a resume against it re-runs intake and the catalog.
    (target / "server" / "src" / "extra.c").write_text("int extra(void) { return 1; }\n", encoding="utf-8")
    third = GraphRunner(config, [build_intake(), build_catalog()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target), run_id=first["run_id"])
    # Intake re-runs for the new fingerprint; the catalog downstream of it is invalidated and rebuilt.
    assert {item["job_id"]: item["action"] for item in third["decisions"]} == {
        "job_review_intake": "RUN", JOB_ID: "INVALIDATE"}
    assert len(list((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())) == 2
    assert_job_lifecycle(run_root, JOB_ID, terminal=third["status"], attempts=2)


def test_configured_topology_matches_the_job() -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    job = config.jobs[JOB_ID]
    assert tuple(job.steps) == tuple(TOPOLOGY)
    for step, tasks in TOPOLOGY.items():
        assert tuple(job.step(step).tasks) == tasks
    built = build_catalog()
    # Units are ordered by dependency (discover_projects follows discover_build_systems); the set matches.
    assert {unit.unit_id for unit in built.units} == {f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks}
    assert not built.strict_gaps, "the catalog still publishes free-text index gaps (legacy list; T-055)"
