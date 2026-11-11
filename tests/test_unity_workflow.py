from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.jobs.discovery_assignment import assign_paths
from appsec_review.jobs.build_discovery import discover_build_inventory, discover_build_units, required_image_profile
from appsec_review.jobs.cataloging import Bounds, inventory
from appsec_review.jobs.job_target_analysis_plan.planning import (
    ambiguity_reasons, deterministic_plan, summarize_catalog, validate_plan,
)
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.reporting.model import Box, Table
from appsec_review.reporting.telemetry.overview import _engine_builds
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "unity_workflow"


@pytest.mark.parametrize("suite", ["integration", "acceptance", "live"])
def test_manual_suites_require_explicit_selection(suite: str) -> None:
    from tests.conftest import pytest_ignore_collect

    path = ROOT / "tests" / suite
    implicit = SimpleNamespace(args_source=pytest.Config.ArgsSource.TESTPATHS)
    explicit = SimpleNamespace(args_source=pytest.Config.ArgsSource.ARGS)
    assert pytest_ignore_collect(path, implicit) is True
    assert pytest_ignore_collect(path, explicit) is None


def _catalog(target: Path):
    observed = inventory(target)
    units = discover_build_units(observed["files"], read_text=lambda path: (target / path).read_text())
    for unit in units:
        unit["descriptor_package"] = {"documents": [], "inventory": unit["markers"], "gaps": []}
        unit["required_image_profile"] = required_image_profile(unit)
    return {
        "files": observed["files"], "source_fingerprint": observed["snapshot"]["sha256"],
        "catalog_handoff_sha256": "c" * 64, "build_units": units,
        "components": [{"component_id": "unity", "root": ".", "manifest": "ProjectSettings/ProjectVersion.txt"}],
        "projects": [], "build_files": [], "compile_databases": [], "gaps": [],
    }


def test_unity_descriptors_survive_ordinary_inventory_quotas(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path / "z-game")
    (tmp_path / "a-noise.txt").write_text("noise")
    result = inventory(tmp_path, Bounds(max_files=1, max_total_bytes=5))
    retained = {item["path"] for item in result["files"]}
    assert {"z-game/ProjectSettings/ProjectVersion.txt", "z-game/ProjectSettings/ProjectSettings.asset",
            "z-game/Packages/manifest.json", "z-game/Packages/packages-lock.json",
            "z-game/Assets/Scripts/Fixture.asmdef"} <= retained
    units = discover_build_units(result["files"], read_text=lambda path: (tmp_path / path).read_text())
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("z-game", "dotnet", "unity")]
    assert required_image_profile(units[0]) == "unity"
    assert result["file_discovery"]["content_files_omitted"] > 0
    assert result["file_discovery"]["descriptors_unavailable"] == 0


def test_unity_keeps_csharp_language_but_generated_ide_is_not_build_authority(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path / "game")
    result = inventory(tmp_path)
    units = discover_build_units(result["files"], read_text=lambda path: (tmp_path / path).read_text())
    assert len(units) == 1 and units[0]["engine"]["kind"] == "unity"
    assert any(item["language"] == "C#" for item in result["files"])
    assert units[0]["build_system"] == "unity" and units[0]["family"] == "dotnet"
    (tmp_path / "standalone").mkdir()
    (tmp_path / "standalone" / "service.csproj").write_text("<Project />")
    units = discover_build_units(inventory(tmp_path)["files"],
                                 read_text=lambda path: (tmp_path / path).read_text())
    assert {(item["root"], item["build_system"]) for item in units} == {
        ("game", "unity"), ("standalone", "dotnet")}


def test_assets_and_scene_names_do_not_establish_a_unity_project(tmp_path: Path) -> None:
    (tmp_path / "Assets").mkdir()
    (tmp_path / "Assets" / "scene.unity").write_text("not a project")
    assert discover_build_units(inventory(tmp_path)["files"], read_text=lambda _path: "") == []


@pytest.mark.parametrize("nested", [False, True])
def test_a_native_plugin_tree_under_assets_is_its_own_cmake_unit_and_a_loose_source_is_orphaned(tmp_path: Path, nested: bool) -> None:
    """native_components is retired (T-056.2, plan §2.1 decision 1): a C++ source under a Unity
    project is evidence of the build point that names it, or an orphan — never attached to the
    Unity unit by position."""
    target = tmp_path / "game" if nested else tmp_path
    shutil.copytree(FIXTURE, target, dirs_exist_ok=True)
    if nested:
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\nproject(outer C)\nadd_executable(outer outer.c)\n")
        (tmp_path / "outer.c").write_text("int main(void) { return 0; }\n")
    plugin = target / "Assets" / "Plugins"
    plugin.mkdir()
    (plugin / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\nproject(plugin CXX)\nadd_library(plugin SHARED plugin.cpp)\n")
    (plugin / "plugin.cpp").write_text("int plugin() { return 0; }\n")
    (target / "Assets" / "other.cpp").write_text("int other() { return 0; }\n")
    inventory_files = inventory(tmp_path)["files"]
    discovered = discover_build_inventory(inventory_files, read_text=lambda path: (tmp_path / path).read_text())
    units = discovered["units"]
    unity = next(item for item in units if item["build_system"] == "unity")
    prefix = "game/" if nested else ""
    assert "native_components" not in unity
    [plugin_unit] = [item for item in units if item["root"] == prefix + "Assets/Plugins" and item["build_system"] == "cmake"]
    assert [(p["name"], p["sources"]) for p in plugin_unit["build_points"]] == [("plugin", [prefix + "Assets/Plugins/plugin.cpp"])]
    [orphan] = [o for o in discovered["orphaned_sources"] if o["path"] == prefix + "Assets/other.cpp"]
    assert orphan["reason"] == "no_build_point" and orphan["nearest_unit"]["build_system"] == "unity"
    assignment = assign_paths(inventory_files, discovered)
    assert assignment[prefix + "Assets/Plugins/plugin.cpp"] == f"evidence_of:{prefix}Assets/Plugins|cmake#plugin"
    assert assignment[prefix + "Assets/other.cpp"] == "orphaned:no_build_point"


def test_unity_plan_is_deterministic_without_inferred_generic_dotnet_recipe(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path, dirs_exist_ok=True)
    catalog = _catalog(tmp_path)
    summary = summarize_catalog(catalog, max_items=100, max_bytes=65536, sample_per_prefix=4)
    assert "buildable units require inference-derived build recipes" not in ambiguity_reasons(summary)
    plan = deterministic_plan(catalog, summary)
    action, = plan["build_topology"]["build_actions"]
    assert action["engine"]["kind"] == "unity"
    assert action["required_image_profile"] == "unity" and action["requires_inference"] is False
    assert action["recipe"] is None and action["executable"] is False
    validate_plan(plan, catalog)
    altered = deepcopy(plan)
    altered["build_topology"]["build_actions"][0]["engine"]["declared_version"] = "2021.1.1f1"
    with pytest.raises(ValueError, match="facts differ"):
        validate_plan(altered, catalog)


def test_build_discovery_rejects_descriptor_changes_after_catalog(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path / "target")
    target = tmp_path / "target"
    files = inventory(target)["files"]
    (target / "ProjectSettings" / "ProjectVersion.txt").write_text("m_EditorVersion: 2021.1.1f1\n")
    job = build_catalog()
    handler = next(item.handler for item in job.units if item.unit_id == "build_discovery.discover_build_systems")
    unit = SimpleNamespace(
        unit_id="build_discovery.discover_build_systems", job=SimpleNamespace(target_root=target),
        output=lambda _key: {"files": files})
    with pytest.raises(ValueError, match="differs from the accepted catalog"):
        handler(unit)


def test_catalog_declares_engine_discovery_before_project_consumers() -> None:
    available = set()
    for unit in build_catalog().units:
        assert set(unit.dependencies) <= available, unit.unit_id
        available.add(unit.unit_id)


def test_engine_telemetry_and_report_preserve_nonexecution_and_failure(tmp_path: Path) -> None:
    def receipt(name, document):
        path = tmp_path / "data" / name
        atomic_json(path, document)
        return {"path": path.relative_to(tmp_path).as_posix(), "sha256": file_sha256(path),
                "size_bytes": path.stat().st_size}

    source = receipt("source.json", {"source_metrics_semantics": "appsec-review/source-counting/1"})
    projects = receipt("projects.json", {"projects": [{"root": "."}]})
    targets = receipt("targets.json", {"targets": [
        {"family": "dotnet", "engine": {"kind": "unity"}}]})
    builds = receipt("builds.json", {"schema": "appsec-review/language-build-handoff/2", "receipts": [
        {"family": "dotnet", "build_unit_id": "unity-a", "root": ".", "engine": {"kind": "unity"},
         "terminal_status": "NOT_REQUESTED", "gaps": ["Unity builds disabled"], "artifacts": []},
        {"family": "dotnet", "build_unit_id": "unity-b", "root": ".", "engine": {"kind": "unity"},
         "terminal_status": "FAILED", "gaps": ["Unity editor failed"], "artifacts": []}]})
    log = PipelineLog(tmp_path)
    log.write("REVIEW_SCOPE_CATALOGED", run_id="run", details={
        "source_receipt": source, "project_receipt": projects, "build_target_receipt": targets})
    log.write("LANGUAGE_BUILDS_RECORDED", run_id="run", details={"receipt": builds})
    review = aggregate_run_metrics(tmp_path)["review"]
    assert review["build_units"]["discovered_by_engine"] == {"unity": 1}
    assert review["build_units"]["by_engine"] == {
        "unity": {"outcomes": {"FAILED": 1, "NOT_REQUESTED": 1}, "gap_count": 2}}
    assert review["build_units"]["by_language"]["dotnet"]["failure"] == 1
    assert review["build_units"]["by_language"]["dotnet"]["not_applicable"] == 1
    box = _engine_builds(SimpleNamespace(summary={"review": review}))
    assert isinstance(box, Box) and box.title == "Engine build coverage"
    assert isinstance(box.items[0], Table)
    assert [cell.text for cell in box.items[0].rows[0]] == [
        "unity", "1", "FAILED: 1, NOT_REQUESTED: 1", "2"]


def test_project_lane_executes_engine_once_without_generic_image_or_dispatch(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.config import load_config
    from appsec_review.jobs.job_project_build import build_job
    from appsec_review.jobs import unity_build

    calls = []
    action = {"build_unit_id": "build-unit-" + "a" * 20, "family": "dotnet",
              "build_system": "unity", "root": ".", "engine": {"kind": "unity"}}
    receipt = {**action, "schema": "appsec-review/language-build-receipt/1",
               "terminal_status": "SUCCEEDED", "artifacts": [], "commands": [], "gaps": []}

    def execute(unit, received, settings, *, executor_factory=None):
        calls.append(received)
        return receipt

    monkeypatch.setattr(unity_build, "execute_unity_build", execute)
    config = load_config(ROOT / "appsec-review.toml")
    outputs = {"plan.load_recipes": {"actions": [action]}}
    unit = SimpleNamespace(job=SimpleNamespace(config=config.job("job_project_build")), output=outputs.__getitem__)
    job = build_job(image_resolver_factory=lambda _unit: object())
    handlers = {item.unit_id: item.handler for item in job.units}
    image = handlers["image.dotnet"](unit)
    assert image["entries"] == [] and image["image_count"] == 0
    outputs["image.dotnet"] = image
    outputs["probe.dotnet"] = handlers["probe.dotnet"](unit)
    assert calls == [action]
    assert outputs["probe.dotnet"]["receipts"][0]["terminal_status"] == "SUCCEEDED"
    assert handlers["build_dispatch.dotnet"](unit)["dispatches"] == []


def test_language_lane_forwards_engine_receipt_without_dotnet_reexecution(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.config import load_config
    from appsec_review.jobs.job_language_build import job as language

    receipt = {
        "schema": "appsec-review/language-build-receipt/1", "build_unit_id": "build-unit-" + "a" * 20,
        "family": "dotnet", "build_system": "unity", "root": ".", "engine": {"kind": "unity"},
        "terminal_status": "FAILED", "artifacts": [], "commands": [],
        "gaps": ["Unity Editor build failed"]}
    accepted = {"probe_receipts": [receipt], "build_dispatches": []}
    monkeypatch.setattr(language, "_dispatches", lambda *_args, **_kwargs: ([], accepted))
    monkeypatch.setattr(language, "resolved_configuration_identity", lambda _root: "c" * 64)
    monkeypatch.setattr(language, "_execute_one", lambda *_args, **_kwargs: pytest.fail("Unity rebuilt as dotnet"))
    config = load_config(ROOT / "appsec-review.toml")
    outputs = {}
    unit = SimpleNamespace(
        job=SimpleNamespace(config=config.job("job_language_build"), run_root=tmp_path),
        output=outputs.__getitem__)
    handlers = {item.unit_id: item.handler for item in language.build_job().units}
    outputs["load.dotnet"] = handlers["load.dotnet"](unit)
    result = handlers["execute.dotnet"](unit)
    assert result["receipts"] == [receipt] and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert outputs["load.dotnet"]["unavailable"] == []


@pytest.mark.parametrize("provisioned", [False, True])
def test_unity_build_receipts_preserve_inventory_and_reach_artifact_consumers(
        tmp_path: Path, provisioned: bool) -> None:
    from appsec_review.config import load_config
    from appsec_review.jobs.cataloging import source_fingerprint
    from appsec_review.jobs.job_artifact_indexing import build_job as artifacts, load_accepted_artifact_index
    from appsec_review.jobs.job_language_build import build_job as languages, load_accepted_language_build
    from appsec_review.jobs.job_project_build import build_job as projects, load_accepted_builds
    from appsec_review.jobs.job_review_intake import build_job as intake
    from appsec_review.jobs.job_target_analysis_plan import build_job as planning, load_accepted_plan
    from appsec_review.runtime import GraphRunner

    from tests.test_unity_build import Docker, configured

    text = (ROOT / "appsec-review.toml").read_text()
    executor = None
    if provisioned:
        settings = configured(editor_revision="0123456789ab")
        executor = Docker(settings)
        settings_text = "\n".join(f"{key} = {json.dumps(value)}" for key, value in settings.view().items())
        text = text.replace("[jobs.job_project_build.settings.unity]\nenabled = false",
                            "[jobs.job_project_build.settings.unity]\n" + settings_text)
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(text)
    config = load_config(config_path)
    runs = tmp_path / "runs"
    config = replace(config, runtime=replace(config.runtime, runs_dir=runs, metadata_dir=runs / "metadata"))
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    snapshot = source_fingerprint(target)
    result = GraphRunner(config, [
        intake(), build_catalog(), planning(),
        projects(unity_executor_factory=executor.factory if executor else None), languages(), artifacts(),
    ]).run(target_root=target, source_fingerprint=snapshot)
    assert result["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, result
    run_root = runs / result["run_id"]
    plan = load_accepted_plan(run_root)
    action, = plan["build_topology"]["build_actions"]
    assert action["engine"]["declared_version"] == "2022.3.62f1"
    assert action["descriptor_facts"]["configuration_fingerprint"]["status"] == "partial"
    built = load_accepted_builds(run_root)
    receipt, = built["probe_receipts"]
    assert receipt["terminal_status"] == ("SUCCEEDED" if provisioned else "NOT_REQUESTED")
    if provisioned:
        assert len(receipt["commands"]) == 3 and receipt["artifacts"]
        assert all((run_root / artifact["path"]).is_file() for artifact in receipt["artifacts"])
        assert receipt["capture_provenance"]["compiler_execution_observed"] is False
        assert any("capture" in gap.lower() for gap in receipt["gaps"])
        assert executor is not None
        assert sum(argv[:2] == ("docker", "run") for argv, _timeout in executor.calls) == 3
    else:
        assert receipt["commands"] == [] and receipt["artifacts"] == [] and receipt["gaps"]
    accepted = load_accepted_language_build(run_root)
    assert accepted["receipts"] == [receipt]
    assert load_accepted_artifact_index(run_root)["source_fingerprint"] == snapshot
    assert source_fingerprint(target) == snapshot
