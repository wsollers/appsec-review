"""T-113: pre-walk graph/target cases retained as acceptance, not bounded integration.

Case bodies are preserved. Shared helpers stay at their existing import paths so the
other machine's unit tier and other jobs do not require edits. Not run by this walk.
"""

from __future__ import annotations
from pathlib import Path, PurePosixPath
import shutil
import pytest
from appsec_review.config import load_config
from appsec_review.config.host_pins import load_host_pins
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner

from tests.integration.test_node_project_builds import (
    CASES,
    NodeCase,
    PROJECTS,
    RECORD_ROLE,
    ROOT,
    SUMMARY_GAP,
    _RecipeProvider,
    _assert_installed_dependency_rows,
    _diagnostics,
    _needs_registry,
    _probe_events,
    node_image as _node_image,
)

node_image = _node_image

@pytest.fixture(scope="module", autouse=True)
def require_target():
    if not PROJECTS.is_dir():
        pytest.skip("missing target checkout: targets/appsec-multi-vuln")

@pytest.mark.parametrize("case", CASES, ids=lambda case: case.project)
def test_node_project_builds_through_the_pipeline(tmp_path: Path, case: NodeCase,
                                                  node_image: dict[str, str]) -> None:
    source = PROJECTS / Path(*PurePosixPath(case.project).parts)
    assert source.is_dir(), f"multivuln Node project is missing: {case.project}"
    if node_image["registry_error"] and _needs_registry(source):
        pytest.skip("environment gap: build containers cannot reach the npm registry: "
                    + node_image["registry_error"])
    config_path = tmp_path / "appsec-review.toml"
    shutil.copyfile(ROOT / "appsec-review.toml", config_path)
    target = tmp_path / "target" / Path(*PurePosixPath(case.project).parts)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("node_modules", ".git"))
    config = load_config(config_path, host_pins=load_host_pins(ROOT))
    fingerprint = source_fingerprint(target)

    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=_RecipeProvider(target, case).complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    run_id = upstream["run_id"]
    run_root = config.runtime.runs_dir / run_id
    GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    GraphRunner(config, [build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)

    accepted = load_accepted_builds(run_root)
    probes = {str(item.get("root")): item for item in accepted.get("probe_receipts", ())
              if item.get("family") == "node"}
    receipts = {str(item.get("root")): item
                for item in load_accepted_language_build(run_root)["receipts"]
                if item.get("family") == "node"}
    assert set(probes) == {unit.root for unit in case.units}, probes.keys()
    blocked_native = [item for item in accepted.get("probe_receipts", ())
                      if item.get("family") == "native" and item.get("terminal_status") == "BLOCKED"]

    for unit in case.units:
        probe = probes[unit.root]
        assert probe["terminal_status"] == "SUCCEEDED", (
            f"probe {unit.root}: {probe.get('gaps')}\n{_diagnostics(run_root, probe)}")
        events = _probe_events(run_root, probe)
        assert any(event.get("kind") == "process_exec" for event in events)
        receipt = receipts[unit.root]
        assert receipt["terminal_status"] == unit.language_status, (
            f"language build {unit.root}: {receipt.get('gaps')}\n{_diagnostics(run_root, receipt)}")
        decisions = {item["feature"]: item for item in receipt.get("processing_decisions", ())}
        assert decisions["compiler-artifact-collection"]["disposition"] == unit.compiler_artifacts, (
            receipt.get("gaps"))
        if unit.language_gap is not None:
            assert any(unit.language_gap in gap for gap in receipt["gaps"]), receipt["gaps"]
            continue
        assert [gap for gap in receipt["gaps"] if not gap.startswith(SUMMARY_GAP)] == [], receipt["gaps"]
        assert receipt["commands"] and all(command["exit_code"] == 0 for command in receipt["commands"])
        assert all((command.get("execution_capture") or {}).get("complete") is True
                   for command in receipt["commands"]), "language build ran without complete capture"
        workspace = run_root / receipt["workspace"]
        produced = {item["workspace_path"]: item for item in receipt["artifacts"]
                    if item.get("artifact_origin") == "build-output"}
        for output in unit.outputs:
            path = workspace / Path(*PurePosixPath(output).parts)
            assert path.is_file() and path.stat().st_size > 0, f"missing build output {output}"
        assert set(unit.artifact_kinds) <= {item["kind"] for item in produced.values()}, produced
        if unit.compiler_artifacts == "SKIPPED_NA":
            assert not [item for item in produced.values() if item["kind"] != "package-metadata"
                        and (item.get("dependency_metadata") or {}).get("role") != RECORD_ROLE]
        _assert_installed_dependency_rows(workspace, receipt, unit)
        if unit.native_compile is not None:
            # node-gyp's C++ compiles are captured for native analysis.
            compiles = [event for event in events if event.get("kind") == "process_exec"
                        and PurePosixPath(str(event.get("executable", ""))).name in {"g++", "c++"}
                        and any(str(value).endswith(unit.native_compile)
                                for value in event.get("argv", ()))]
            assert compiles, "node-gyp g++ compile invocation was not captured"
            # The language build publishes the same compiles as the unit's native components.
            assert receipt.get("native_components"), receipt.keys()
            addon = workspace / "build" / "Release" / "case087.node"
            assert addon.read_bytes()[:4] == b"\x7fELF"
    if case.project == "node-addon/case-087":
        # Coordination contract: a node-gyp addon is owned by the node unit, so the native
        # family must not emit a second, unbuildable direct-native unit for its sources.
        assert not blocked_native, [item.get("gaps") for item in blocked_native]
