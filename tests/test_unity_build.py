from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.unity import UnityBuildSettings, parse_unity_build_settings
from appsec_review.container_runtime import BuildContainerExecutor
from appsec_review.jobs.artifact_kinds import ARTIFACT_KINDS
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.unity_build import execute_unity_build
from appsec_review.runtime import execution_safety as safety
from appsec_review.storage import file_sha256


IMAGE = "sha256:" + "1" * 64
VERSION = "2022.3.62f1"


def configured(**changes) -> UnityBuildSettings:
    return parse_unity_build_settings({
        "enabled": True, "tag": "local/unity:2022.3.62f1", "image_id": IMAGE,
        "user": "1000:1000", "editor_version": VERSION,
        "editor_executable": "/opt/unity/Editor/Unity", "target": "StandaloneLinux64",
        "architecture": "x86_64", "scripting_backend": "Mono",
        "modules": ["StandaloneLinux64"], "license_ready": True,
        "output_path": "Build/app", **changes,
    })


def context(tmp_path: Path, relative: str = "."):
    target, run = tmp_path / "source", tmp_path / "run"
    project = target if relative == "." else target / relative
    (project / "ProjectSettings").mkdir(parents=True)
    (project / "Assets").mkdir()
    (project / "Assets" / "Game.cs").write_text("public class Game {}\n", encoding="utf-8")
    (project / "ProjectSettings" / "ProjectVersion.txt").write_text(
        f"m_EditorVersion: {VERSION}\n", encoding="utf-8")
    run.mkdir()
    unit = SimpleNamespace(job=SimpleNamespace(
        target_root=target, run_root=run, source_fingerprint=source_fingerprint(target),
        attempt_id="attempt-001", run_id="run-001",
    ))
    action = {
        "build_unit_id": "unity-game", "family": "dotnet", "build_system": "unity",
        "root": relative, "engine": {"kind": "unity", "declared_version": VERSION},
        "descriptor_facts": {"root_state": "validated", "engine_conflict": False},
    }
    return unit, action, project


class Docker:
    """Only the external process boundary is fake; the shared executor is real."""

    def __init__(self, settings: UnityBuildSettings, **changes):
        self.settings = settings
        self.calls = []
        self.profiles = []
        self.image = IMAGE
        self.image_exit = 0
        self.version = VERSION
        self.preflight = {}
        self.preflight_output = None
        self.failure_stage = None
        self.code = 7
        self.timed_out = False
        self.output_mode = "file"
        self.extra_stdout = b""
        self.extra_stderr = b""
        self.error = None
        self.on_build = None
        self.on_preflight = None
        for key, value in changes.items():
            setattr(self, key, value)

    def factory(self, unit, profile):
        self.profiles.append(profile)
        return BuildContainerExecutor(
            profile, runner=self, timeout_seconds=self.settings.timeout_seconds,
            output_bytes=self.settings.output_bytes)

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append((argv, timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            return self.image_exit, self.image.encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            return 0, b"", b"", False
        assert argv[:2] == ("docker", "run"), "unexpected external command"
        executable = argv.index("--entrypoint")
        command = argv[executable + 3:]
        environment = dict(argv[index + 1].split("=", 1) for index, value in enumerate(argv)
                           if value == "--env")
        mount = argv[argv.index("--mount") + 1]
        workspace = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
        output = workspace / environment["APPSEC_UNITY_OUTPUT"].removeprefix("/workspace/")
        stage = "editor-version" if "-version" in command else (
            "preflight" if command[-1].endswith(".Preflight") else "build")
        if self.error is not None and stage == self.failure_stage:
            raise self.error
        if stage == self.failure_stage:
            return self.code, self.extra_stdout, self.extra_stderr, self.timed_out
        if stage == "editor-version":
            return 0, self.version.encode(), b"", False
        if stage == "preflight":
            if self.on_preflight:
                self.on_preflight(workspace, output)
            facts = {
                "token": environment["APPSEC_UNITY_TOKEN"],
                "editor_version": self.settings.editor_version,
                "editor_full_version": self.settings.editor_version + " (" + (self.settings.editor_revision or "abcdef123456") + ")",
                "target": self.settings.target, "architecture": self.settings.architecture,
                "scripting_backend": self.settings.scripting_backend,
                "license_ready": True, "module_ready": True, **self.preflight,
            }
            stdout = (b"APPSEC_UNITY_PREFLIGHT " + json.dumps(facts).encode() + b"\n"
                      if self.preflight_output is None else self.preflight_output)
            return 0, stdout, b"", False
        output.parent.mkdir(parents=True, exist_ok=True)
        if self.output_mode == "file":
            output.write_bytes(b"\x7fELF" + b"\0" * 60)
            data = output.parent / (output.name + "_Data")
            data.mkdir()
            (data / "globalgamemanagers").write_bytes(b"player data")
        elif self.output_mode == "directory":
            output.mkdir()
            (output / "index.html").write_bytes(b"<html>game</html>")
        elif self.output_mode == "symlink":
            output.symlink_to(workspace.parent / "outside")
        elif self.output_mode == "empty":
            output.write_bytes(b"")
        elif self.output_mode == "sibling-symlink":
            output.write_bytes(b"player")
            (output.parent / "escaping").symlink_to(workspace.parent)
        elif self.output_mode == "nonregular":
            os.mkfifo(output)
        elif self.output_mode != "missing":
            raise AssertionError("unknown fake output mode")
        if self.on_build:
            self.on_build(workspace, output)
        return 0, self.extra_stdout or b"Build succeeded\n", self.extra_stderr, False


def execute(tmp_path, *, settings=None, action_change=None, relative=".", **runner_changes):
    unit, action, project = context(tmp_path, relative)
    settings = settings or configured()
    action.update(action_change or {})
    runner = Docker(settings, **runner_changes)
    receipt = execute_unity_build(unit, action, settings, executor_factory=runner.factory)
    return receipt, runner, unit, action, project


def test_defaults_are_disabled_immutable_and_without_capabilities():
    settings = parse_unity_build_settings(None)
    assert settings == parse_unity_build_settings({})
    assert settings.enabled is False and settings.license_ready is False
    assert not settings.image_id and not settings.editor_executable and not settings.modules
    assert not settings.output_path
    with pytest.raises(FrozenInstanceError):
        settings.enabled = True
    assert parse_unity_build_settings(configured().view()) == configured()


@pytest.mark.parametrize("changes", [
    {"enabled": "true"}, {"license_ready": 1}, {"token": "private-token"},
    {"environment": {"UNITY_SERIAL": "private-serial"}}, {"command": ["Unity"]},
    {"tag": "registry:latest"}, {"tag": "https://user:password@registry/unity:1"},
    {"image_id": "local/unity:2022"}, {"user": "0:1000"}, {"user": "1000:0"},
    {"editor_version": "latest"}, {"editor_revision": "non-hex-revision"},
    {"editor_executable": "Unity"}, {"editor_executable": "/opt/../Unity"},
    {"editor_executable": "/opt/Unity --serial secret"}, {"target": "Unspecified"},
    {"architecture": "x86"}, {"scripting_backend": "any"},
    {"modules": "StandaloneLinux64"}, {"modules": ["StandaloneLinux64"] * 2},
    {"modules": [None]}, {"modules": ["Unknown"]},
    {"execute_method": "Class.Build;bad"}, {"execute_method": "Build"},
    {"output_path": "../app"}, {"output_path": "/outside/app"},
    {"output_path": "Build/../app"}, {"output_path": "Build//app"},
    {"output_path": "Assets/app"}, {"output_path": "app"},
    {"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 86401},
    {"output_bytes": 0}, {"output_bytes": 16777217},
    {"artifact_count_limit": 0}, {"artifact_count_limit": 100001},
])
def test_strict_settings_reject_credentials_commands_invalid_paths_and_unbounded_values(changes):
    with pytest.raises(ValueError):
        configured(**changes)


@pytest.mark.parametrize("value", [[], "unity", 1, False])
def test_nonmapping_settings_are_rejected(value):
    with pytest.raises(ValueError):
        parse_unity_build_settings(value)


def test_disabled_and_missing_capabilities_do_not_create_executor(tmp_path):
    unit, action, _ = context(tmp_path)
    calls = []
    factory = lambda *args: calls.append(args)
    receipt = execute_unity_build(unit, action, UnityBuildSettings(), executor_factory=factory)
    assert receipt["terminal_status"] == "NOT_REQUESTED"
    receipt = execute_unity_build(unit, action, UnityBuildSettings(enabled=True), executor_factory=factory)
    assert receipt["terminal_status"] == "BLOCKED"
    assert any("editor_executable" in gap for gap in receipt["gaps"])
    assert receipt["commands"] == [] and receipt["artifacts"] == [] and not calls
    assert not (unit.job.run_root / "data").exists()


@pytest.mark.parametrize("key,value,gap", [
    ("tag", "", "tag"), ("image_id", "", "image_id"), ("user", "", "user"),
    ("editor_executable", "", "editor_executable"), ("output_path", "", "output_path"),
    ("license_ready", False, "license"), ("modules", [], "module"),
    ("editor_version", "2020.3.48f1", "editor"),
])
def test_missing_declared_capability_blocks_before_image_resolution(tmp_path, key, value, gap):
    receipt, runner, *_ = execute(tmp_path, settings=configured(**{key: value}))
    assert receipt["terminal_status"] == "BLOCKED"
    assert any(gap in reason for reason in receipt["gaps"])
    assert not runner.calls and not runner.profiles


@pytest.mark.parametrize("target,architecture,backend", [
    ("iOS", "arm64", "IL2CPP"), ("tvOS", "arm64", "IL2CPP"),
    ("StandaloneOSX", "x86_64", "Mono"),
    ("StandaloneWindows64", "x86_64", "IL2CPP"), ("Android", "arm64", "Mono"),
    ("WebGL", "x86_64", "IL2CPP"), ("StandaloneLinux64", "arm64", "IL2CPP"),
])
def test_unavailable_platform_or_backend_is_a_named_gap_not_execution(tmp_path, target, architecture, backend):
    receipt, runner, *_ = execute(tmp_path, settings=configured(
        target=target, modules=[target], architecture=architecture, scripting_backend=backend))
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls
    assert any("Linux" in gap for gap in receipt["gaps"])


@pytest.mark.parametrize("target,architecture,backend,cli", [
    ("StandaloneLinux64", "x86_64", "Mono", "Linux64"),
    ("StandaloneLinux64", "x86_64", "IL2CPP", "Linux64"),
    ("StandaloneWindows64", "x86_64", "Mono", "Win64"),
    ("Android", "arm64", "IL2CPP", "Android"), ("Android", "armv7", "Mono", "Android"),
    ("WebGL", "wasm32", "IL2CPP", "WebGL"),
])
def test_success_requires_actual_commands_outputs_and_workspace_identity(tmp_path, target, architecture, backend, cli):
    settings = configured(target=target, modules=[target], architecture=architecture, scripting_backend=backend)
    receipt, runner, unit, _, project = execute(tmp_path, settings=settings)
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert receipt["schema"] == "appsec-review/language-build-receipt/1"
    assert receipt["family"] == "dotnet" and receipt["build_system"] == "unity"
    assert receipt["probe_disposition"] == "COMPUTED" and receipt["image_id"] == IMAGE
    assert receipt["source_fingerprint"] == source_fingerprint(unit.job.target_root)
    assert [command["stage"] for command in receipt["commands"]] == ["editor-version", "preflight", "build"]
    assert len({command["command_id"] for command in receipt["commands"]}) == 3
    for command in receipt["commands"]:
        assert command["exit_code"] == 0 and not command["timed_out"] and not command["cancelled"]
        assert command["tool"] == "Unity" and command["tool_kind"] in {"build-driver", "toolchain-preflight"}
        assert command["working_directory"] == "."
        assert command["environment_facts"]["APPSEC_UNITY_OUTPUT"] == "set"
        for stream in ("stdout", "stderr"):
            identity = command[stream]
            assert identity["sha256"] == file_sha256(unit.job.run_root / identity["path"])
            assert identity["captured_bytes"] <= settings.output_bytes
    workspace = unit.job.run_root / receipt["workspace"]
    manifest = json.loads((unit.job.run_root / receipt["workspace_manifest"]["path"]).read_text())
    assert manifest["schema"] == "appsec-review/build-workspace-manifest/1"
    assert receipt["workspace_manifest"]["sha256"] == file_sha256(
        unit.job.run_root / receipt["workspace_manifest"]["path"])
    for name, digest in manifest["files"].items():
        assert digest == file_sha256(workspace / name)
    assert len(receipt["artifacts"]) == 2
    for artifact in receipt["artifacts"]:
        assert artifact["kind"] in ARTIFACT_KINDS
        assert artifact["sha256"] == file_sha256(unit.job.run_root / artifact["path"])
        assert (workspace / artifact["workspace_path"]).is_file()
        assert artifact["mapping"] == "exact-workspace-path" and artifact["mapping_confidence"] == 1
    assert receipt["capture_provenance"]["compiler_execution_observed"] is False
    assert any("compiler/linker" in gap for gap in receipt["gaps"])
    assert not (project / "Build").exists() and not (project / "Assets" / "Editor").exists()
    calls = [argv for argv, timeout in runner.calls if argv[:2] == ("docker", "run")]
    assert len(calls) == 3
    for call in calls:
        assert call[call.index("--network") + 1] == "bridge"
        assert call[call.index("--entrypoint") + 1] == settings.editor_executable
        assert call[call.index("--entrypoint") + 2] == IMAGE
        assert "--read-only" in call and "--cap-drop" in call
    assert calls[-1][calls[-1].index("-buildTarget") + 1] == cli
    assert all(timeout == settings.timeout_seconds for argv, timeout in runner.calls if "run" in argv)


def test_custom_method_nested_root_and_explicit_fixture_output(tmp_path):
    settings = configured(output_path="build/Case095.x86_64",
                          execute_method="AppSecCorpus.Editor.CorpusBuild.Build")
    receipt, runner, unit, _, project = execute(tmp_path, settings=settings, relative="games/demo")
    assert receipt["terminal_status"] == "SUCCEEDED"
    build = [argv for argv, _ in runner.calls if argv[:2] == ("docker", "run")][-1]
    assert build[-1] == settings.execute_method
    assert build[build.index("-projectPath") + 1] == "/workspace/games/demo"
    assert "APPSEC_UNITY_OUTPUT=/workspace/games/demo/build/Case095.x86_64" in build
    assert build[build.index("--workdir") + 1] == "/workspace/games/demo"
    assert all(item["workspace_path"].startswith("games/demo/build/") for item in receipt["artifacts"])
    assert not (project / "build").exists()
    bridge = unit.job.run_root / receipt["prepared_inputs"][0]["path"]
    source = bridge.read_text()
    assert "BuildPipeline.BuildPlayer" in source and "EditorBuildSettings.scenes" in source
    assert "BuildResult.Succeeded" in source and "PlayerSettings.Set" not in source


@pytest.mark.parametrize("field,value", [
    ("editor_version", "2022.3.61f1"), ("target", "Android"),
    ("architecture", "arm64"), ("scripting_backend", "IL2CPP"),
    ("license_ready", False), ("module_ready", False), ("license_ready", 1),
    ("token", "different-run"),
])
def test_actual_preflight_mismatch_blocks_without_build(tmp_path, field, value):
    receipt, runner, *_ = execute(tmp_path, preflight={field: value})
    assert receipt["terminal_status"] == "BLOCKED" and not receipt["artifacts"]
    assert len(receipt["commands"]) == 2
    assert all(not argv[-1].endswith(".Build") for argv, _ in runner.calls)
    assert receipt["workspace_manifest"]


@pytest.mark.parametrize("output", [
    b"Unity licensing error\n", b"APPSEC_UNITY_PREFLIGHT {}\n",
    b"APPSEC_UNITY_PREFLIGHT not-json\n",
    b"APPSEC_UNITY_PREFLIGHT {}\nAPPSEC_UNITY_PREFLIGHT {}\n",
])
def test_missing_or_malformed_preflight_never_establishes_build_capability(tmp_path, output):
    receipt, *_ = execute(tmp_path, preflight_output=output)
    assert receipt["terminal_status"] == "BLOCKED"
    assert len(receipt["commands"]) == 2 and not receipt["artifacts"]


@pytest.mark.parametrize("changes", [
    {"image": "sha256:" + "2" * 64}, {"image_exit": 1},
    {"version": "2022.3.61f1"}, {"version": ""},
    {"failure_stage": "editor-version", "code": 127},
    {"failure_stage": "preflight", "code": 1},
])
def test_actual_missing_image_editor_or_license_blocks(tmp_path, changes):
    receipt, *_ = execute(tmp_path, **changes)
    assert receipt["terminal_status"] == "BLOCKED" and not receipt["artifacts"]
    assert receipt["gaps"]


@pytest.mark.parametrize("stage", ["editor-version", "preflight", "build"])
def test_timeout_is_failed_and_shared_executor_removes_timed_out_container(tmp_path, stage):
    receipt, runner, *_ = execute(tmp_path, failure_stage=stage, code=None, timed_out=True)
    assert receipt["terminal_status"] == "FAILED"
    assert receipt["commands"][-1]["timed_out"] is True
    assert not receipt["artifacts"]
    assert any(argv[:3] == ("docker", "rm", "--force") for argv, _ in runner.calls)


@pytest.mark.parametrize("code", [-2, -15, 130, 143])
def test_cancellation_has_distinct_status_and_retains_command_and_workspace_evidence(tmp_path, code):
    receipt, *_ = execute(tmp_path, failure_stage="build", code=code)
    assert receipt["terminal_status"] == "CANCELLED" and not receipt["artifacts"]
    assert receipt["commands"][-1]["cancelled"] is True
    assert receipt["workspace_manifest"]


def test_process_exit_failure_is_not_promoted_by_existing_output(tmp_path):
    receipt, *_ = execute(tmp_path, failure_stage="build", code=42)
    assert receipt["terminal_status"] == "FAILED"
    assert receipt["commands"][-1]["exit_code"] == 42 and not receipt["artifacts"]


@pytest.mark.parametrize("mode", ["missing", "empty", "symlink", "sibling-symlink", "nonregular"])
def test_missing_empty_escaped_symlink_and_nonregular_outputs_fail(tmp_path, mode):
    receipt, _, unit, *_ = execute(tmp_path, output_mode=mode)
    assert receipt["terminal_status"] == "FAILED" and not receipt["artifacts"]
    assert any("output" in gap for gap in receipt["gaps"])
    manifest = json.loads((unit.job.run_root / receipt["workspace_manifest"]["path"]).read_text())
    assert manifest["files"]
    assert manifest["complete"] is (mode not in {"symlink", "sibling-symlink", "nonregular"})


def test_explicit_directory_output_has_hashes_and_cannot_exceed_artifact_bound(tmp_path):
    receipt, *_ = execute(tmp_path, output_mode="directory", settings=configured(output_path="Build/WebGL"))
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert receipt["artifacts"][0]["workspace_path"] == "Build/WebGL/index.html"
    other = tmp_path / "other"
    other.mkdir()
    receipt, *_ = execute(other, settings=configured(artifact_count_limit=1))
    assert receipt["terminal_status"] == "FAILED" and not receipt["artifacts"]


def test_nonempty_siblings_do_not_hide_an_empty_primary_player(tmp_path):
    receipt, *_ = execute(tmp_path, on_build=lambda workspace, output: output.write_bytes(b""))
    assert receipt["terminal_status"] == "FAILED" and not receipt["artifacts"]


def test_preflight_cannot_supply_artifacts_in_place_of_the_build_command(tmp_path):
    def create(workspace, output):
        output.parent.mkdir(parents=True)
        (output.parent / "stale").write_bytes(b"not created by build")
    receipt, *_ = execute(tmp_path, on_preflight=create)
    assert receipt["terminal_status"] == "BLOCKED" and not receipt["artifacts"]
    assert len(receipt["commands"]) == 2


def test_source_and_preexisting_outputs_are_never_modified(tmp_path):
    unit, action, project = context(tmp_path)
    (project / "Build").mkdir()
    (project / "Build" / "app").write_bytes(b"prior output")
    unit.job.source_fingerprint = source_fingerprint(unit.job.target_root)
    runner = Docker(configured())
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls
    assert (project / "Build" / "app").read_bytes() == b"prior output"
    assert source_fingerprint(unit.job.target_root) == unit.job.source_fingerprint


def test_unchanged_copied_siblings_cannot_be_published_as_new_build_outputs(tmp_path):
    unit, action, project = context(tmp_path)
    (project / "Build").mkdir()
    (project / "Build" / "old-library.so").write_bytes(b"old")
    unit.job.source_fingerprint = source_fingerprint(unit.job.target_root)
    runner = Docker(configured())
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls
    assert not receipt["artifacts"]


def test_source_symlink_and_symlinked_build_root_are_rejected(tmp_path):
    unit, action, project = context(tmp_path)
    (project / "Assets" / "escape").symlink_to(tmp_path / "outside")
    unit.job.source_fingerprint = source_fingerprint(unit.job.target_root)
    runner = Docker(configured())
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls
    other = tmp_path / "other"
    other.mkdir()
    unit, action, project = context(other)
    (project / "redirect").symlink_to(project, target_is_directory=True)
    action["root"] = "redirect"
    unit.job.source_fingerprint = source_fingerprint(unit.job.target_root)
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls


def test_run_owned_root_symlink_cannot_escape_or_overwrite(tmp_path):
    unit, action, _ = context(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (unit.job.run_root / "data").symlink_to(outside, target_is_directory=True)
    runner = Docker(configured())
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls
    assert list(outside.iterdir()) == []


def test_repeated_execution_cannot_replace_the_first_workspace_or_receipt(tmp_path):
    receipt, runner, unit, action, _ = execute(tmp_path)
    workspace = unit.job.run_root / receipt["workspace"]
    stored = workspace.parent / "receipt.json"
    original = stored.read_bytes()
    repeated = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert repeated["terminal_status"] == "BLOCKED"
    assert stored.read_bytes() == original
    assert len([argv for argv, _ in runner.calls if argv[:2] == ("docker", "run")]) == 3


def test_original_source_change_is_detected_before_and_after_build(tmp_path):
    unit, action, project = context(tmp_path)
    (project / "Assets" / "Game.cs").write_text("changed")
    runner = Docker(configured())
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls
    other = tmp_path / "other"
    other.mkdir()
    unit, action, project = context(other)
    runner = Docker(configured(), on_build=lambda *_: (project / "Assets" / "Game.cs").write_text("changed"))
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "FAILED" and not receipt["artifacts"]


@pytest.mark.parametrize("change", [
    {"engine": {"kind": "unity", "declared_version": "2022.3.61f1"}},
    {"engine": {"kind": "unity"}}, {"engine": {"kind": "other", "declared_version": VERSION}},
    {"engine": {"kind": "unity", "declared_version": VERSION, "declared_revision": "abcdef1"}},
    {"descriptor_facts": {"engine_conflict": True}},
    {"descriptor_facts": {"root_state": "ambiguous"}},
    {"descriptor_facts": {"target": "Android"}},
    {"descriptor_facts": {"scripting_backend": "IL2CPP"}},
])
def test_conflicting_or_missing_project_authority_blocks(tmp_path, change):
    receipt, runner, *_ = execute(tmp_path, action_change=change)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls


def test_informational_inventory_gaps_do_not_block_actual_configured_execution(tmp_path):
    receipt, *_ = execute(tmp_path, action_change={
        "gaps": ["package resolution unknown"],
        "descriptor_facts": {"root_state": "validated", "unknown_inputs": ["sdk"]},
    })
    assert receipt["terminal_status"] == "SUCCEEDED"


def test_source_editor_authority_and_actual_editor_revision_are_verified(tmp_path):
    settings = configured(editor_revision="abcdef123456")
    unit, action, project = context(tmp_path)
    path = project / "ProjectSettings" / "ProjectVersion.txt"
    path.write_text(f"m_EditorVersion: {VERSION}\nm_EditorVersionWithRevision: {VERSION} (abcdef123456)\n")
    action["engine"]["declared_revision"] = settings.editor_revision
    unit.job.source_fingerprint = source_fingerprint(unit.job.target_root)
    runner = Docker(settings)
    receipt = execute_unity_build(unit, action, settings, executor_factory=runner.factory)
    assert receipt["terminal_status"] == "SUCCEEDED"
    other = tmp_path / "other"
    other.mkdir()
    receipt, *_ = execute(other, settings=settings, preflight={
        "editor_full_version": VERSION + " (123456abcdef)",
    })
    assert receipt["terminal_status"] == "BLOCKED"


@pytest.mark.parametrize("version_text", [
    "m_EditorVersion: 2022.3.61f1\n",
    f"m_EditorVersion: {VERSION}\nm_EditorVersion: {VERSION}\n",
    f"m_EditorVersion: {VERSION}\nm_EditorVersionWithRevision: 2021.3.1f1 (abcdef123456)\n",
    f"m_EditorVersion: {VERSION}\nm_EditorVersionWithRevision: invalid\n",
])
def test_copied_source_editor_authority_is_verified_independently_of_action(tmp_path, version_text):
    unit, action, project = context(tmp_path)
    (project / "ProjectSettings" / "ProjectVersion.txt").write_text(version_text)
    unit.job.source_fingerprint = source_fingerprint(unit.job.target_root)
    runner = Docker(configured())
    receipt = execute_unity_build(unit, action, configured(), executor_factory=runner.factory)
    assert receipt["terminal_status"] == "BLOCKED" and not runner.calls


def test_credential_logs_are_redacted_bounded_and_external_exception_messages_are_not_published(tmp_path):
    secret = b"UNITY_SERIAL=private-license-value\nAuthorization: Bearer private-token-value\n"
    receipt, _, unit, *_ = execute(tmp_path, settings=configured(output_bytes=1024),
                                   extra_stdout=secret + b"X" * 2000, extra_stderr=secret)
    assert receipt["terminal_status"] == "SUCCEEDED"
    command = receipt["commands"][-1]
    assert command["stdout"]["truncated"] is True and command["stdout"]["redacted"] is True
    for stream in ("stdout", "stderr"):
        retained = (unit.job.run_root / command[stream]["path"]).read_bytes()
        assert b"private-license-value" not in retained and b"private-token-value" not in retained
        assert len(retained) <= 1024
    assert "private-license-value" not in json.dumps(receipt)
    other = tmp_path / "other"
    other.mkdir()
    receipt, *_ = execute(other, failure_stage="build", error=RuntimeError("Unity private-value-not-for-output"))
    assert receipt["terminal_status"] == "FAILED"
    assert "private-value-not-for-output" not in json.dumps(receipt)


def test_runtime_cancellation_persists_receipt_and_does_not_ignore_active_safety(tmp_path, monkeypatch):
    receipt, *_ = execute(tmp_path, failure_stage="build", error=safety.ReviewStopped("stop"))
    assert receipt["terminal_status"] == "CANCELLED"
    assert receipt["commands"][-1]["cancelled"]
    # This read-only control-flow assertion exercises the safety stop before any
    # container command; no admission controller or live process is started.
    other = tmp_path / "other"
    other.mkdir()
    unit, action, _ = context(other)
    envelope = safety.policy("11111111-1111-4111-8111-111111111111", {
        "source_commit": "a" * 40, "target_commit": "b" * 40, "configuration": {},
    })
    requests = []

    def controller(self, command, **fields):
        requests.append(command)
        if len(requests) > 1:
            raise safety.ReviewStopped("external controller stopped")
        return {"ok": True}

    monkeypatch.setattr(safety.SafetyClient, "request", controller)
    with safety.safety_scope(envelope):
        with pytest.raises(safety.ReviewStopped):
            execute_unity_build(unit, action, configured(), executor_factory=Docker(configured()).factory)
    assert requests == ["check", "check"]


@pytest.mark.parametrize("change", [
    {"build_unit_id": "../outside"}, {"root": "../source"}, {"root": "/source"},
    {"root": "game/./other"}, {"build_system": "msbuild"}, {"family": "native"},
])
def test_invalid_action_paths_and_wrong_execution_lane_are_rejected(tmp_path, change):
    unit, action, _ = context(tmp_path)
    action.update(change)
    with pytest.raises(ValueError):
        execute_unity_build(unit, action, configured(), executor_factory=Docker(configured()).factory)
    assert not (unit.job.run_root / "data").exists()


def test_settings_identity_is_canonical_and_changes_for_material_config():
    base = configured()
    assert base.identity == parse_unity_build_settings(dict(reversed(list(base.view().items())))).identity
    for changed in (replace(base, image_id="sha256:" + "2" * 64),
                    replace(base, output_path="Build/other"), replace(base, scripting_backend="IL2CPP"),
                    replace(base, editor_revision="abcdef1"), replace(base, execute_method="Builder.Build")):
        assert changed.identity != base.identity


def test_build_fingerprint_changes_with_configured_noncredential_inputs(tmp_path):
    receipt, *_ = execute(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    changed, *_ = execute(other, settings=configured(output_path="Build/different"))
    assert changed["source_fingerprint"] == receipt["source_fingerprint"]
    assert changed["fingerprint"] != receipt["fingerprint"]


@pytest.mark.parametrize("identity", [
    "a" * 64, {}, {"schema": "unknown", "sha256": "a" * 64},
    {"schema": "appsec-review/unity-configuration-fingerprint/1", "sha256": "invalid"},
])
def test_invalid_configuration_identity_is_rejected(tmp_path, identity):
    unit, action, _ = context(tmp_path)
    action["descriptor_facts"]["configuration_fingerprint"] = identity
    with pytest.raises(ValueError):
        execute_unity_build(unit, action, configured(), executor_factory=Docker(configured()).factory)


def test_supplied_configuration_fingerprint_identity_is_retained_without_unsanitized_inputs(tmp_path):
    fingerprint = {
        "schema": "appsec-review/unity-configuration-fingerprint/1", "sha256": "a" * 64,
        "status": "partial", "inputs": {"password": "do-not-publish"}, "unknown_inputs": ["sdk"],
    }
    receipt, *_ = execute(tmp_path, action_change={"descriptor_facts": {"configuration_fingerprint": fingerprint}})
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert receipt["configuration_fingerprint"]["sha256"] == fingerprint["sha256"]
    assert "do-not-publish" not in json.dumps(receipt)
