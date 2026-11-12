"""job_project_build: the unit graph, configuration validation, the publish aggregation and the
pure helpers of job.py, without running a graph, a container or an image resolver."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_project_build import job as project_job
from appsec_review.jobs.job_project_build.job import (
    BUILD_FAMILIES, SCHEMA, STATIC_LANES, _image_dict, _kind, _normalized_argv, _safe_root, _snapshot,
    _validate_config, _validate_expected_outputs, build_job, node_installer_command,
)

ROOT = Path(__file__).resolve().parents[3]


def _units():
    return {unit.unit_id: unit for unit in build_job().units}


# --- graph shape ---------------------------------------------------------------------------------

def test_graph_fans_out_per_family_and_lane_and_joins_at_publication() -> None:
    units = _units()
    expected = {"plan.load_recipes", "acceptance.publish_handoff",
                *(f"image.{f}" for f in BUILD_FAMILIES), *(f"static_dispatch.{lane}" for lane in STATIC_LANES),
                *(f"probe.{f}" for f in BUILD_FAMILIES), *(f"build_dispatch.{f}" for f in BUILD_FAMILIES)}
    assert set(units) == expected and len(units) == 2 + 9 + 10 + 9 + 9
    assert units["plan.load_recipes"].dependencies == ()
    for family in BUILD_FAMILIES:
        assert units[f"image.{family}"].dependencies == ("plan.load_recipes",)
        assert units[f"probe.{family}"].dependencies == (f"image.{family}",)
        assert units[f"build_dispatch.{family}"].dependencies == (f"image.{family}", f"probe.{family}")
    for lane in STATIC_LANES:
        assert units[f"static_dispatch.{lane}"].dependencies == ("plan.load_recipes",)
    assert units["acceptance.publish_handoff"].dependencies == (
        *(f"static_dispatch.{lane}" for lane in STATIC_LANES), *(f"build_dispatch.{f}" for f in BUILD_FAMILIES))
    assert STATIC_LANES == ("global", *BUILD_FAMILIES)


def test_job_identity_and_contract() -> None:
    job = build_job()
    assert (job.job_id, job.name, job.schema_identity) == ("job_project_build", "project_build", SCHEMA)
    assert job.strict_gaps is True and job.input_validators == (_validate_config,)
    assert job.contract is not None and job.consumes == job.contract.consumes
    assert "job_target_analysis_plan" in job.consumes


def test_every_handler_scopes_its_gaps_to_the_unit_or_the_named_build_unit(tmp_path: Path) -> None:
    """The ``typed`` wrapper turns free-text gaps into producer-gap records scoped by unit."""
    units = _units()
    plan = SimpleNamespace(outputs={}, unit_id="static_dispatch.go", job=SimpleNamespace(run_root=tmp_path))
    # static_dispatch for a family with no actions is the smallest real handler
    plan.outputs["plan.load_recipes"] = {"actions": [], "scanner_selections": {}, "execution_graph": {"edges": []}}
    plan.output = lambda key: plan.outputs[key]
    result = units["static_dispatch.go"].handler(plan)
    assert result["dispatches"] == [] and result["gaps"] == []
    assert isinstance(result["gaps"], list)


# --- _validate_config ----------------------------------------------------------------------------

def _real_job():
    return load_config(ROOT / "appsec-review.toml").job("job_project_build")


def _context(job) -> SimpleNamespace:
    return SimpleNamespace(config=job)


def test_shipped_configuration_passes_validation() -> None:
    _validate_config(_context(_real_job()), None)


def test_validation_refuses_a_changed_topology_or_task_order() -> None:
    job = _real_job()
    reordered = SimpleNamespace(settings=job.settings, steps={k: job.steps[k] for k in reversed(list(job.steps))},
                                step=job.step)
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate_config(_context(reordered), None)

    def step(step_id):
        value = job.step(step_id)
        if step_id == "probe":
            return SimpleNamespace(tasks={k: value.tasks[k] for k in reversed(list(value.tasks))})
        return value
    reordered_tasks = SimpleNamespace(settings=job.settings, steps=job.steps, step=step)
    with pytest.raises(ValueError, match="task order mismatch: probe"):
        _validate_config(_context(reordered_tasks), None)


@pytest.mark.parametrize(("settings_change", "message"), [
    ({"force_buildability_probe": "yes"}, "force_buildability_probe must be boolean"),
    ({"repair_attempts": 2}, "repair_attempts must be an integer between 3 and 10"),
    ({"repair_attempts": 11}, "repair_attempts must be an integer between 3 and 10"),
    ({"repair_attempts": True}, "repair_attempts must be an integer between 3 and 10"),
    ({"model": {"enabled": True}}, "repair model settings are invalid"),
    ({"model": "__drop_timeout__"}, "repair model settings are invalid"),
    ({"model": {"__set__": {"enabled": "true"}}}, "repair model enabled must be boolean"),
    ({"model": {"__set__": {"max_output_tokens": 0}}}, "repair model limits must be positive integers"),
    ({"model": {"__set__": {"timeout_seconds": "180"}}}, "repair model limits must be positive integers"),
], ids=["force-string", "attempts-low", "attempts-high", "attempts-bool", "model-partial", "model-missing-key",
        "model-enabled", "model-zero", "model-string"])
def test_validation_refuses_malformed_settings(settings_change, message) -> None:
    job = _real_job()
    settings = dict(job.settings)
    for key, value in settings_change.items():
        if key == "model" and value == "__drop_timeout__":
            settings["model"] = {k: v for k, v in job.settings["model"].items() if k != "timeout_seconds"}
        elif key == "model" and isinstance(value, dict) and "__set__" in value:
            settings["model"] = {**job.settings["model"], **value["__set__"]}
        else:
            settings[key] = value
    with pytest.raises(ValueError, match=message):
        _validate_config(_context(SimpleNamespace(settings=settings, steps=job.steps, step=job.step)), None)


def test_validation_requires_a_profile_for_every_family_and_android() -> None:
    job = _real_job()
    profiles = {name: value for name, value in job.settings["profiles"].items() if name != "wasm"}
    settings = {**job.settings, "profiles": profiles}
    with pytest.raises(ValueError, match="profiles must cover every build family"):
        _validate_config(_context(SimpleNamespace(settings=settings, steps=job.steps, step=job.step)), None)


# --- publish aggregation ----------------------------------------------------------------------------

def _publish_context(tmp_path: Path, *, image_gaps=(), probe_receipts=(), build_dispatches=(), static=(),
                     decisions=()) -> SimpleNamespace:
    outputs = {"plan.load_recipes": {"actions": [{"build_unit_id": "build-unit-a"}], "execution_graph": {"edges": []},
                                     "processing_decisions": list(decisions)}}
    for family in BUILD_FAMILIES:
        outputs[f"image.{family}"] = {"gaps": list(image_gaps) if family == "native" else []}
        outputs[f"probe.{family}"] = {"receipts": list(probe_receipts) if family == "native" else [], "gaps": []}
        outputs[f"build_dispatch.{family}"] = {"dispatches": list(build_dispatches) if family == "native" else [],
                                               "gaps": []}
    for lane in STATIC_LANES:
        outputs[f"static_dispatch.{lane}"] = {"dispatches": list(static) if lane == "global" else [], "gaps": []}
    run_root = tmp_path / "run"
    job = SimpleNamespace(run_root=run_root, attempt_root=run_root / "attempt", source_fingerprint="f" * 40)
    return SimpleNamespace(job=job, unit_id="acceptance.publish_handoff", outputs=outputs,
                           output=lambda key: outputs[key])


def test_publish_aggregates_images_probes_and_dispatches_into_one_artifact(tmp_path: Path) -> None:
    receipt = {"build_unit_id": "build-unit-a", "family": "native", "terminal_status": "SUCCEEDED", "gaps": [],
               "artifacts": [{"path": "x"}, {"path": "y"}], "probe_disposition": "REUSED"}
    context = _publish_context(tmp_path, probe_receipts=[receipt], build_dispatches=[{"root": "native"}],
                               static=[{"lane": "global"}])
    result = _units()["acceptance.publish_handoff"].handler(context)
    assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
    assert (result["probe_count"], result["probe_reused_count"]) == (1, 1)
    assert (result["static_dispatch_count"], result["build_dispatch_count"]) == (1, 1)
    artifact = result["artifact"]
    assert artifact["path"] == "attempt/artifacts/project-build/accepted-project-build-dispatch.json"
    document = json.loads((tmp_path / "run" / artifact["path"]).read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA and document["execution_mode"] == "iterative"
    assert document["source_fingerprint"] == "f" * 40
    assert document["probe_receipts"] == [receipt] and document["probe_artifact_count"] == 2
    assert document["build_dispatches"] == [{"root": "native"}] and document["static_dispatches"] == [{"lane": "global"}]
    assert set(document["images"]) == set(BUILD_FAMILIES) and set(document["probes"]) == set(BUILD_FAMILIES)


def test_publish_carries_every_gap_as_a_scoped_producer_gap_record(tmp_path: Path) -> None:
    context = _publish_context(tmp_path, image_gaps=["build-unit-a: validated inference build recipe is unavailable",
                                                      "image build timed out"])
    result = _units()["acceptance.publish_handoff"].handler(context)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    scopes = {(gap["scope_id"], gap["reason"]) for gap in result["gaps"]}
    assert scopes == {("build-unit-a", "build-unit-a: validated inference build recipe is unavailable"),
                      ("acceptance.publish_handoff", "image build timed out")}
    assert all(gap["schema"] == "appsec-review/producer-gap/1" for gap in result["gaps"])


# --- pure helpers ------------------------------------------------------------------------------------

def test_safe_root_accepts_the_target_and_regular_subdirectories_only(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "lib" / "src").mkdir(parents=True)
    (target / "file.txt").write_text("x", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (target / "link").symlink_to(outside, target_is_directory=True)
    assert _safe_root(target, ".") == target.resolve()
    assert _safe_root(target, "lib/src") == (target / "lib" / "src").resolve()
    for relative, message in (("../outside", "root is invalid"), ("/lib", "root is invalid"),
                              ("", "root is invalid"), ("file.txt", "not a regular directory"),
                              ("link", "escapes the target")):
        with pytest.raises(ValueError, match=message):
            _safe_root(target, relative)
    with pytest.raises(FileNotFoundError):
        _safe_root(target, "missing")


@pytest.mark.parametrize(("relative", "expected"), [
    ("build/app.o", ("object", "o")),
    ("build/libfmt.a", ("static-library", "a")),
    ("out/app.apk", ("android-apk", "zip")),
    ("app/build/intermediates/merged_res/debug/values.xml", ("android-intermediate", "xml")),
    ("app/build/outputs/apk/debug/output-metadata.json", ("android-metadata", "json")),
    ("target/release/libcore.rlib", ("rust-library", "ar")),
    ("classes/Main.class", ("jvm-class", "class")),
    ("dist/app.jar", ("jar", "jar")),
    ("src/main.cpp", None),
    ("README.md", None),
], ids=["object", "archive", "apk", "android-intermediate", "android-metadata", "rlib", "class", "jar", "source", "doc"])
def test_output_kinds_come_from_the_typed_vocabulary(tmp_path: Path, relative, expected) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\0" * 8)
    assert _kind(path) == expected


def test_normalized_argv_strips_the_source_dir_and_wrapper_scripts() -> None:
    recipe = {"source_dir": "svc/api"}
    assert _normalized_argv(recipe, ["mvnw", "-f", "svc/api/pom.xml", "package", "svc/api"]) == (
        "mvn", "-f", "pom.xml", "package", ".")
    assert _normalized_argv(recipe, ["gradlew", "build", "svc/api-other"]) == ("gradle", "build", "svc/api-other")
    assert _normalized_argv({"source_dir": "."}, ["cmake", "--build", "./build"]) == ("cmake", "--build", "./build")


@pytest.mark.parametrize(("argv", "expected"), [
    (["npm", "ci"], True), (["npm", "--prefix", "web", "install"], True), (["npm", "-C", "web", "i"], True),
    (["pnpm", "install", "--frozen-lockfile"], True), (["yarn", "install"], True),
    (["npm", "run", "build"], False), (["npm", "--prefix", "web"], False), (["yarn", "ci"], False),
    (["pip", "install"], False), ([], False), (["npm", "--silent", "ci"], True),
], ids=["ci", "prefix", "C", "pnpm", "yarn", "run", "prefix-only", "yarn-ci", "pip", "empty", "flag-then-ci"])
def test_node_installer_commands_are_recognized_past_valued_options(argv, expected) -> None:
    assert node_installer_command(argv) is expected


def test_snapshot_hashes_regular_files_skips_cache_and_symlinks_and_bounds_the_count(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / ".appsec-cache").mkdir()
    (tmp_path / ".appsec-cache" / "c.txt").write_text("c", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(tmp_path / "a.txt")
    snapshot = _snapshot(tmp_path, 10)
    assert set(snapshot) == {"a.txt", "sub/b.txt"} and all(len(digest) == 64 for digest in snapshot.values())
    with pytest.raises(ValueError, match="file-count bound exceeded"):
        _snapshot(tmp_path, 1)


def test_expected_outputs_may_not_escape_the_workspace(tmp_path: Path) -> None:
    (tmp_path / "ws").mkdir()
    with pytest.raises(ValueError, match="escaped the run-owned workspace"):
        _validate_expected_outputs(tmp_path / "ws", {"expected_outputs": ["../elsewhere"]})
    assert _validate_expected_outputs(tmp_path / "ws", {"expected_outputs": []}) == []


def test_image_dict_exposes_every_slot_plus_the_user_and_a_clean_status() -> None:
    class Image:
        __slots__ = ("image_id", "recipe_identity")

        def __init__(self):
            self.image_id = "sha256:" + "a" * 64
            self.recipe_identity = "r" * 64

    assert _image_dict(Image(), "65532:65532") == {"image_id": "sha256:" + "a" * 64, "recipe_identity": "r" * 64,
                                                  "user": "65532:65532", "terminal_status": "SUCCEEDED", "gaps": []}
