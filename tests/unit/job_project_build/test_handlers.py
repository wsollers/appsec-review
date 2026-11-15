"""Code-level unit tests for job_project_build.job helpers, probe/repair loops, and step handlers."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime import BuildProfile, ProjectImageBuildError
from appsec_review.container_runtime.project_images import ProjectImage
from appsec_review.inference.errors import ModelOutputError
from appsec_review.inference.request import ModelResult
from appsec_review.jobs import build_topology_artifacts
from appsec_review.jobs.job_project_build import job as project_job
from appsec_review.jobs.job_project_build.datasets import DATASETS
from appsec_review.jobs.job_project_build.job import (
    BUILD_FAMILIES, REPAIR_CACHE_SCHEMA, SCHEMA, STATIC_LANES, ProjectBuildFailed,
    _capture_identity, _copy_source, _declares_source_directory, _deterministic_jvm_recipe,
    _deterministic_native_recipe, _deterministic_phpize_recipe, _image_dict, _infer_repair,
    _materialize_build_layout, _outputs, _prepared_dispatch, _probe_cache, _probe_diagnostics,
    _probe_one, _probe_stream, _probe_with_repairs, _repair_cache, _repair_guidance,
    _retained_stream, _reuse_accepted_repair, _validate_expected_outputs, build_job,
    load_accepted_builds,
)
from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA
from appsec_review.runtime import execution_safety as safety
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.resources import ImagePreparationUnavailable
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[3]
IMAGE_ID = "sha256:" + "a" * 64
ALT_IMAGE_ID = "sha256:" + "b" * 64
BUILD_UNIT = "build-unit-" + "1" * 16


def _events() -> SimpleNamespace:
    records: list[tuple[str, dict[str, Any]]] = []
    return SimpleNamespace(records=records, write=lambda kind, **fields: records.append((kind, fields)))


def _project_image(*, recipe_identity: str = "r" * 64, family: str = "python",
                   image_id: str = IMAGE_ID, reused: bool = False) -> ProjectImage:
    return ProjectImage(
        schema="appsec-review/project-image/1",
        recipe_identity=recipe_identity,
        family=family,
        base_image_id=IMAGE_ID,
        image_tag=f"appsec/{family}:test",
        image_id=image_id,
        dockerfile_sha256="d" * 64,
        customized=image_id != IMAGE_ID,
        reused=reused,
        dependency_hashes={},
        dockerfile_path="Dockerfile",
    )


def _unit_context(tmp_path: Path, *, unit_id: str = "probe.python", reusable: bool = True,
                  force_probe: bool = False, model_enabled: bool = True,
                  repair_attempts: int = 3) -> SimpleNamespace:
    app_cfg = load_config(ROOT / "appsec-review.toml")
    job_cfg = app_cfg.job("job_project_build")
    settings = {
        **job_cfg.settings,
        "force_buildability_probe": force_probe,
        "repair_attempts": repair_attempts,
        "model": {**job_cfg.settings["model"], "enabled": model_enabled},
    }
    job_cfg = replace(job_cfg, settings=settings)
    releases = (
        ComponentReleases({"platform": "p1", "build_toolchain": "b1", "validation": "v1"})
        if reusable
        else ComponentReleases({})
    )
    policy = replace(app_cfg.review_policy, releases=releases)
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "main.py").write_text("print('ok')\n", encoding="utf-8")
    run_root = tmp_path / "run"
    run_root.mkdir(parents=True, exist_ok=True)
    attempt_root = run_root / "data" / "jobs" / "job_project_build" / "attempts" / "attempt_0001"
    unit_root = attempt_root / "steps" / unit_id.split(".")[0] / "tasks" / unit_id.split(".")[1]
    unit_root.mkdir(parents=True, exist_ok=True)
    metadata_root = tmp_path / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    fp = project_job.source_fingerprint(target)
    outputs: dict[str, Any] = {}
    job = SimpleNamespace(
        run_root=run_root,
        run_id="run-0001",
        attempt_id="attempt_0001",
        attempt_root=attempt_root,
        target_root=target,
        metadata_root=metadata_root,
        repository_root=ROOT,
        source_fingerprint=fp,
        config=job_cfg,
        review_policy=policy,
        events=_events(),
        upstream_handoffs={"job_target_analysis_plan": "9" * 64},
    )
    return SimpleNamespace(
        job=job, unit_id=unit_id, unit_root=unit_root,
        outputs=outputs, output=outputs.__getitem__,
    )


# --- workspace copying, layout adaptation, streams, and output classification --------------------

def test_copy_source_guards_workspace_symlinks_and_parent_dependencies(tmp_path: Path) -> None:
    ctx = _unit_context(tmp_path)
    target = ctx.job.target_root
    (target / "sub").mkdir()
    (target / "sub" / "app.py").write_text("x = 1\n", encoding="utf-8")

    # Escaped workspace deletion is refused when workspace already exists outside build/probes
    outside_ws = tmp_path / "outside-ws"
    outside_ws.mkdir()
    with pytest.raises(ValueError, match="probe workspace deletion escaped"):
        _copy_source(ctx, {"root": "sub", "recipe": {}}, outside_ws)

    # Pre-existing workspace inside data/build/probes is safely cleaned and replaced
    ws = ctx.job.run_root / "data" / "build" / "probes" / BUILD_UNIT / "workspace"
    ws.mkdir(parents=True)
    (ws / "stale.txt").write_text("stale", encoding="utf-8")
    _copy_source(ctx, {"root": "sub", "recipe": {}}, ws)
    assert not (ws / "stale.txt").exists() and (ws / "sub" / "app.py").is_file()

    # Escaped dependency file is refused
    outside_dep = tmp_path / "secret.txt"
    outside_dep.write_text("secret", encoding="utf-8")
    (target / "dep-link.txt").symlink_to(outside_dep)
    with pytest.raises(ValueError, match="build dependency escaped"):
        _copy_source(ctx, {"root": "sub", "recipe": {"dependency_files": ["dep-link.txt"]}}, ws)

    # Symlink inside copied source is refused
    (target / "sub" / "bad_link.py").symlink_to(target / "main.py")
    with pytest.raises(ValueError, match="unsupported symlink"):
        _copy_source(ctx, {"root": "sub", "recipe": {}}, ws)


def test_maven_layout_adaptation_and_pom_source_directory_guards(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    src_root = ws / "svc"
    (src_root / "src").mkdir(parents=True)
    (src_root / "src" / "App.java").write_text("class App {}\n", encoding="utf-8")

    # Non-mapping recipe returns []
    assert _materialize_build_layout({"family": "java", "build_system": "maven", "recipe": None}, ws) == []

    # Invalid XML in pom.xml returns False from _declares_source_directory (allowing adaptation)
    (src_root / "pom.xml").write_text("<project><broken", encoding="utf-8")
    assert _declares_source_directory(src_root) is False

    # Declared <sourceDirectory> suppresses adaptation
    (src_root / "pom.xml").write_text(
        "<project><build><sourceDirectory>src</sourceDirectory></build></project>", encoding="utf-8"
    )
    assert _declares_source_directory(src_root) is True
    assert _materialize_build_layout(
        {"family": "java", "build_system": "maven", "recipe": {"source_dir": "svc"}}, ws
    ) == []

    # Over >60 java files suppresses adaptation
    (src_root / "pom.xml").write_text("<project/>", encoding="utf-8")
    for idx in range(62):
        (src_root / "src" / f"Extra{idx}.java").write_text(f"class Extra{idx} {{}}\n", encoding="utf-8")
    assert _materialize_build_layout(
        {"family": "java", "build_system": "maven", "recipe": {"source_dir": "svc"}}, ws
    ) == []


def test_outputs_and_expected_outputs_cover_bounds_cache_bookkeeping_and_created_build_dir(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    ws = run_root / "ws"
    (ws / ".appsec-cache").mkdir(parents=True)
    (ws / ".appsec-cache" / "cached.jar").write_bytes(b"1234")
    (ws / "CMakeFiles" / "CMakeTmp").mkdir(parents=True)
    (ws / "CMakeFiles" / "CMakeTmp" / "probe.o").write_bytes(b"1234")
    (ws / "a.jar").write_bytes(b"aaaa")
    (ws / "b.jar").write_bytes(b"bbbb")
    (ws / "same.jar").write_bytes(b"same")

    before = {"same.jar": file_sha256(ws / "same.jar")}
    listed = _outputs(run_root, ws, before, limit=1)
    assert len(listed) == 1 and listed[0]["workspace_path"] == "a.jar"

    # Empty created_build_dir does not satisfy expected_outputs; escaped output raises
    empty_build = ws / "build"
    empty_build.mkdir()
    assert _validate_expected_outputs(ws, {"expected_outputs": ["build"]}, created_build_dir="build") == [
        "required build output is missing: build"
    ]
    with pytest.raises(ValueError, match="escaped the run-owned workspace"):
        _validate_expected_outputs(ws, {"expected_outputs": ["../outside"]})


def test_probe_stream_retained_stream_and_capture_identity_variants(tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / "run"
    logs = run_root / "logs"
    logs.mkdir(parents=True)

    # Inline truncated stream with diagnostic tail
    inline_res = SimpleNamespace(stdout=b"head", stdout_bytes=20, stdout_truncated=True, stdout_tail=b"tail")
    inline_id = _probe_stream(run_root, logs / "cmd.stdout", inline_res, "stdout", limit=4)
    assert inline_id["truncated"] is True and inline_id["diagnostic_tail"]["byte_count"] == 4

    # Complete-file stream
    complete_src = tmp_path / "complete.stdout"
    complete_src.write_bytes(b"full output bytes")
    file_res = SimpleNamespace(stdout=b"full", stdout_file=complete_src, stdout_truncated=True)
    file_id = _probe_stream(run_root, logs / "file.stdout", file_res, "stdout", limit=16)
    assert file_id["storage"] == "complete-file" and file_id["truncated"] is False
    assert file_id["preview_truncated"] is True and file_id["preview_limit_bytes"] == 4

    # Retained stream with and without truncation
    short_ret = _retained_stream(run_root, logs / "ret-short.log", b"abc", limit=10)
    assert short_ret["truncated"] is False and "diagnostic_tail" not in short_ret
    long_ret = _retained_stream(run_root, logs / "ret-long.log", b"0123456789", limit=10)
    assert long_ret["truncated"] is True and long_ret["diagnostic_tail"]["byte_count"] == 10

    # _capture_identity missing record vs verified record
    ctx = _unit_context(tmp_path)
    with pytest.raises(RuntimeError, match="build execution capture record is required"):
        _capture_identity(ctx, SimpleNamespace(capture_record=None), build_unit_id=BUILD_UNIT, family="python")

    cap_file = tmp_path / "cap.json"
    cap_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        project_job, "verify_capture_record",
        lambda path, **kw: SimpleNamespace(identity={"path": "cap.json", "sha256": "1" * 64}, gaps=["cap-gap"]),
    )
    cap_id, cap_gaps = _capture_identity(
        ctx, SimpleNamespace(capture_record=cap_file), build_unit_id=BUILD_UNIT, family="python"
    )
    assert cap_id["sha256"] == "1" * 64 and cap_gaps == ["cap-gap"]


# --- deterministic recipes -----------------------------------------------------------------------

def test_deterministic_native_and_phpize_and_jvm_recipes(tmp_path: Path) -> None:
    ctx = _unit_context(tmp_path)
    target = ctx.job.target_root

    # Native CMake recipe
    assert _deterministic_native_recipe(ctx, {"family": "go", "build_system": "cmake", "root": "."}) is None
    assert _deterministic_native_recipe(
        ctx, {"family": "native", "build_system": "cmake", "root": ".", "build_unit_id": BUILD_UNIT}
    ) is None  # no CMakeLists.txt yet

    (target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\nproject(p)\n", encoding="utf-8")
    cmake_recipe = _deterministic_native_recipe(
        ctx, {"family": "native", "build_system": "cmake", "root": ".", "build_unit_id": BUILD_UNIT}
    )
    assert cmake_recipe is not None and cmake_recipe["configure_commands"][0][0] == "cmake"

    # Existing non-cmake command in selected recipe returns None
    assert _deterministic_native_recipe(
        ctx, {
            "family": "native", "build_system": "cmake", "root": ".", "build_unit_id": BUILD_UNIT,
            "recipe": {"configure_commands": [["make"]], "build_commands": []},
        }
    ) is None

    # Phpize recipe
    assert _deterministic_phpize_recipe(ctx, {"family": "python", "build_system": "phpize", "root": "."}) is None
    php_dir = target / "ext"
    php_dir.mkdir()
    assert _deterministic_phpize_recipe(
        ctx, {"family": "php", "build_system": "phpize", "root": "ext", "build_unit_id": BUILD_UNIT}
    ) is None
    (php_dir / "config.m4").write_text("dnl no macro here\n", encoding="utf-8")
    assert _deterministic_phpize_recipe(
        ctx, {"family": "php", "build_system": "phpize", "root": "ext", "build_unit_id": BUILD_UNIT}
    ) is None
    (php_dir / "config.m4").write_text(
        "PHP_ARG_ENABLE([sample], [enable sample])\nPHP_NEW_EXTENSION(sample, sample.c, $ext_shared)\n",
        encoding="utf-8",
    )
    php_recipe = _deterministic_phpize_recipe(
        ctx, {"family": "php", "build_system": "phpize", "root": "ext", "build_unit_id": BUILD_UNIT}
    )
    assert php_recipe is not None
    assert php_recipe["configure_commands"] == [["phpize"], ["./configure", "--enable-sample"]]
    assert php_recipe["expected_outputs"] == ["ext/modules/sample.so"]

    # JVM non-java / empty sources returns None; Java-only sources emit javac + jar
    assert _deterministic_jvm_recipe(ctx, {"family": "python", "build_system": "javac", "root": "."}) is None
    assert _deterministic_jvm_recipe(
        ctx, {"family": "java", "build_system": "javac", "root": "ext", "build_unit_id": BUILD_UNIT}
    ) is None
    java_dir = target / "jonly"
    java_dir.mkdir()
    (java_dir / "Hello.java").write_text("class Hello {}\n", encoding="utf-8")
    jvm_recipe = _deterministic_jvm_recipe(
        ctx, {"family": "java", "build_system": "javac", "root": "jonly", "build_unit_id": BUILD_UNIT}
    )
    assert jvm_recipe is not None and [cmd[0] for cmd in jvm_recipe["build_commands"]] == ["javac", "jar"]


# --- _probe_one, _probe_diagnostics, _infer_repair, _reuse_accepted_repair, _probe_with_repairs --

def _sample_recipe(family: str = "python", *, network_required: bool = False,
                   expected_outputs: list[str] | None = None,
                   environment: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "schema": "appsec-review/build-recipe/1",
        "build_unit_id": BUILD_UNIT,
        "image_profile": family,
        "source_dir": ".",
        "build_dir": "build",
        "system_packages": [],
        "environment": {"APP_FLAG": "1"} if environment is None else dict(environment),
        "dependency_files": ["requirements.txt"] if family == "python" else ["package.json"],
        "configure_commands": [],
        "build_commands": [["python3", "-m", "compileall", "."]],
        "expected_outputs": expected_outputs or [],
        "network_required": network_required,
        "reason": "accepted recipe",
    }


def test_probe_one_covers_blocked_cache_reuse_execution_failure_and_safety_stops(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(build_topology_artifacts, "guard_cache_action", lambda *a, **kw: {})
    ctx = _unit_context(tmp_path)
    (ctx.job.target_root / "requirements.txt").write_text("", encoding="utf-8")
    ctx.job.source_fingerprint = project_job.source_fingerprint(ctx.job.target_root)

    # Missing recipe or image -> BLOCKED
    blocked_no_recipe = _probe_one(ctx, {"action": {"build_unit_id": BUILD_UNIT, "family": "python"}})
    assert blocked_no_recipe["terminal_status"] == "BLOCKED"
    blocked_no_image = _probe_one(
        ctx, {"action": {"build_unit_id": BUILD_UNIT, "family": "python", "recipe": _sample_recipe()},
              "image": None, "gaps": ["img unavailable"]}
    )
    assert blocked_no_image["terminal_status"] == "BLOCKED" and blocked_no_image["gaps"] == ["img unavailable"]

    img = _image_dict(_project_image(), "1000:1000")
    entry = {
        "action": {"build_unit_id": BUILD_UNIT, "family": "python", "root": ".",
                   "build_system": "python", "recipe": _sample_recipe()},
        "image": img,
    }

    # Target snapshot drift before probe raises
    drifted = _unit_context(tmp_path)
    drifted.job.source_fingerprint = "0" * 40
    with pytest.raises(ValueError, match="target changed after the accepted review snapshot"):
        _probe_one(drifted, entry)

    # Missing execute_captured raises RuntimeError
    bad_exec = SimpleNamespace(resolve=lambda: None)
    with pytest.raises(RuntimeError, match="project builds require execution capture"):
        _probe_one(ctx, entry, executor_factory=lambda _u, _p: bad_exec)

    # Node network_required without restore requires prepare_node_dependencies
    node_entry = {
        "action": {
            "build_unit_id": BUILD_UNIT, "family": "node", "root": ".", "build_system": "node",
            "recipe": _sample_recipe(
                "node", network_required=True,
                environment={"APP_FLAG": "1", "API_TOKEN": "redacted"},
            ),
        },
        "image": _image_dict(_project_image(family="node"), "1000:1000"),
    }
    (ctx.job.target_root / "package.json").write_text("{}\n", encoding="utf-8")
    ctx.job.source_fingerprint = project_job.source_fingerprint(ctx.job.target_root)
    with pytest.raises(RuntimeError, match="dependency-view executor"):
        _probe_one(ctx, node_entry, executor_factory=lambda _u, _p: bad_exec)

    # Successful execution writes cache, redacts secret keys in environment_facts, and reuses on second call
    monkeypatch.setattr(
        project_job, "verify_capture_record",
        lambda path, **kw: SimpleNamespace(identity={"path": "cap.json", "sha256": "2" * 64}, gaps=[]),
    )

    def _make_executor(*, exit_code: int = 0, timed_out: bool = False):
        prepared: list[Path] = []

        def _exec_captured(command, *, workspace, capture_directory, **kw):
            capture_directory.mkdir(parents=True, exist_ok=True)
            cap = capture_directory / "record.json"
            cap.write_text("{}", encoding="utf-8")
            (workspace / "dist.jar").write_bytes(b"jar-bytes")
            return SimpleNamespace(
                argv=list(command), exit_code=exit_code, timed_out=timed_out,
                stdout=b"ok\n", stderr=b"", capture_record=cap,
            )

        return SimpleNamespace(
            prepared=prepared,
            resolve=lambda: None,
            prepare_node_dependencies=lambda *, workspace, **kw: prepared.append(workspace),
            execute_captured=_exec_captured,
        )

    exec_ok = _make_executor(exit_code=0)
    node_res = _probe_one(ctx, node_entry, executor_factory=lambda _u, _p: exec_ok)
    assert node_res["terminal_status"] == "SUCCEEDED" and len(exec_ok.prepared) == 1
    assert node_res["commands"][0]["environment_facts"] == {"APP_FLAG": "set"}

    # Second call hits probe cache and returns REUSED
    reused_res = _probe_one(ctx, node_entry, executor_factory=lambda _u, _p: exec_ok)
    assert reused_res["probe_disposition"] == "REUSED" and reused_res["checkpoint_reused"] is True

    # Non-reusable releases emit CHECKPOINT_MISSED and run fresh; non-zero exit records FAILED
    non_reusable = _unit_context(tmp_path / "nr", reusable=False)
    (non_reusable.job.target_root / "requirements.txt").write_text("", encoding="utf-8")
    non_reusable.job.source_fingerprint = project_job.source_fingerprint(non_reusable.job.target_root)
    fail_res = _probe_one(non_reusable, entry, executor_factory=lambda _u, _p: _make_executor(exit_code=2))
    assert fail_res["terminal_status"] == "FAILED"
    assert any("exited 2" in g for g in fail_res["gaps"])
    assert any(kind == "CHECKPOINT_MISSED" for kind, _ in non_reusable.job.events.records)

    # _probe_diagnostics reads stdout/stderr tails and rejects escaped paths
    diag = _probe_diagnostics(non_reusable, fail_res)
    assert diag["terminal_status"] == "FAILED" and diag["stdout_tail"] == "ok\n"
    escaped_receipt = {"commands": [{"ordinal": 1, "stdout": {"path": "../outside.log"}, "stderr": None}]}
    with pytest.raises(ValueError, match="probe diagnostic path is invalid"):
        _probe_diagnostics(non_reusable, escaped_receipt)


def test_repair_guidance_infer_repair_reuse_accepted_repair_and_probe_with_repairs(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(build_topology_artifacts, "guard_cache_action", lambda *a, **kw: {})
    monkeypatch.setattr(build_topology_artifacts, "guard_action", lambda _r, act, **kw: {"enforcement": []})
    monkeypatch.setattr(
        build_topology_artifacts, "bind_actions",
        lambda _r, acts, **kw: [{**dict(a), "topology_refinement": {"path": "x", "sha256": "0" * 64}} for a in acts],
    )
    ctx = _unit_context(tmp_path)
    (ctx.job.target_root / "requirements.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
    ctx.job.source_fingerprint = project_job.source_fingerprint(ctx.job.target_root)

    # Fallback application_root branch in _repair_guidance when repository_root lacks prompt-fragments
    fallback_ctx = _unit_context(tmp_path)
    fallback_ctx.job.repository_root = tmp_path / "empty-repo"
    persona, role, guidance, sha = _repair_guidance(fallback_ctx, "python", ctx.job.config.settings["model"])
    assert persona and role and guidance and len(sha) == 64

    # _infer_repair writes raw_response and validates proposal (rejecting invalid proposals)
    recipe = _sample_recipe("python")
    action = {"build_unit_id": BUILD_UNIT, "family": "python", "root": ".", "build_system": "python",
              "recipe": recipe, "package_hints": ["libssl-dev"]}
    valid_proposal = {
        "schema": REPAIR_SCHEMA,
        "system_packages": ["libssl-dev"],
        "environment": {"PIP_BREAK_SYSTEM_PACKAGES": "1"},
        "package_manager": None,
        "dependency_restores": [{"manifest": "requirements.txt"}],
        "reason": "install libssl-dev and restore requirements",
    }

    def _good_infer(_req, *, timeout_seconds):
        return ModelResult(
            proposal=valid_proposal, raw_response='{"ok":true}',
            input_tokens=10, output_tokens=10, cache_tokens=0,
        )

    got = _infer_repair(
        ctx, action=action, recipe=recipe, dockerfile=b"FROM base\n",
        diagnostics={"terminal_status": "FAILED"}, attempts=[], repair_number=1, infer=_good_infer,
    )
    assert got == valid_proposal
    assert (ctx.unit_root / BUILD_UNIT / "repair-001" / "model-response.txt").is_file()

    def _bad_infer(_req, *, timeout_seconds):
        return ModelResult(
            proposal={**valid_proposal, "system_packages": ["bad;pkg"]}, raw_response=None,
            input_tokens=5, output_tokens=5, cache_tokens=0,
        )

    with pytest.raises(ModelOutputError):
        _infer_repair(
            ctx, action=action, recipe=recipe, dockerfile=b"FROM base\n",
            diagnostics={"terminal_status": "FAILED"}, attempts=[], repair_number=2, infer=_bad_infer,
        )

    # _probe_with_repairs: model disabled returns FAILED with disabled gap
    profile = BuildProfile("python", "appsec/python:test", IMAGE_ID, "1000:1000")
    base_img = _project_image(recipe_identity="b" * 64, family="python")
    entry = {"action": action, "image": _image_dict(base_img, "1000:1000"), "base_recipe_identity": "b" * 64}

    probe_calls = {"n": 0}

    def _fake_probe_one(_unit, current_entry, _ef=None, *, attempt_number=1):
        probe_calls["n"] += 1
        ok = attempt_number >= 2 and current_entry["action"]["recipe"].get("system_packages") == ["libssl-dev"]
        return {
            "build_unit_id": BUILD_UNIT, "family": "python", "root": ".", "build_system": "python",
            "recipe_identity": current_entry["image"]["recipe_identity"],
            "image_id": current_entry["image"]["image_id"],
            "terminal_status": "SUCCEEDED" if ok else "FAILED",
            "probe_disposition": "PROBED" if ok else "FAILED",
            "commands": [], "artifacts": [], "gaps": [] if ok else ["probe failed"],
        }

    monkeypatch.setattr(project_job, "_probe_one", _fake_probe_one)

    disabled_ctx = _unit_context(tmp_path, model_enabled=False)
    disabled_res = _probe_with_repairs(
        disabled_ctx, entry, profile=profile, resolver=None, infer=_good_infer
    )
    assert disabled_res["terminal_status"] == "FAILED"
    assert "build image repair model is disabled" in disabled_res["gaps"]

    # _probe_with_repairs: succeeds on repair attempt 1 and writes _repair_cache, then _reuse_accepted_repair hits!
    repaired_img = _project_image(recipe_identity="c" * 64, family="python", image_id=ALT_IMAGE_ID)
    resolver = SimpleNamespace(
        definition=lambda _rec, _prof: ("b" * 64, b"FROM python:base\n"),
        resolve=lambda _rec, _prof: (repaired_img, b"built\n", b""),
    )
    repaired_res = _probe_with_repairs(ctx, entry, profile=profile, resolver=resolver, infer=_good_infer)
    assert repaired_res["terminal_status"] == "SUCCEEDED"
    assert repaired_res["recipe_provenance"] == "inference-image-repair"
    assert _repair_cache(ctx, "b" * 64).is_file()

    reused = _reuse_accepted_repair(ctx, action, "b" * 64, resolver, profile)
    assert reused is not None and reused[0]["recipe_provenance"] == "reused-image-repair"

    # _reuse_accepted_repair: rebuilt image with different image_id returns None; ImagePreparationUnavailable logs miss
    rebuilt_resolver = SimpleNamespace(
        resolve=lambda _rec, _prof: (
            _project_image(recipe_identity="c" * 64, family="python", image_id="sha256:" + "e" * 64), b"", b""
        )
    )
    assert _reuse_accepted_repair(ctx, action, "b" * 64, rebuilt_resolver, profile) is None

    unavail_resolver = SimpleNamespace(
        definition=lambda _rec, _prof: ("b" * 64, b"FROM python:base\n"),
        resolve=lambda _rec, _prof: (_ for _ in ()).throw(ImagePreparationUnavailable("docker daemon down")),
    )
    assert _reuse_accepted_repair(ctx, action, "b" * 64, unavail_resolver, profile) is None

    # _probe_with_repairs: ImagePreparationUnavailable stops immediately with BLOCKED
    blocked_repair = _probe_with_repairs(
        ctx, entry, profile=profile, resolver=unavail_resolver, infer=_good_infer
    )
    assert blocked_repair["terminal_status"] == "BLOCKED"

    # _probe_with_repairs: ProjectImageBuildError retries until repair_limit and returns FAILED
    err_resolver = SimpleNamespace(
        definition=lambda _rec, _prof: ("b" * 64, b"FROM python:base\n"),
        resolve=lambda _rec, _prof: (_ for _ in ()).throw(
            ProjectImageBuildError("apt failed", stdout=b"out", stderr=b"err")
        ),
    )
    exhausted = _probe_with_repairs(
        ctx, entry, profile=profile, resolver=err_resolver, infer=_good_infer
    )
    assert exhausted["terminal_status"] == "FAILED" and exhausted["repair_attempt_count"] == 3


# --- load_accepted_builds ------------------------------------------------------------------------

def test_load_accepted_builds_validates_artifact_enforcement_and_execution_mode(
    tmp_path: Path, monkeypatch
) -> None:
    def _publish_builds(root: Path, payload: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
        attempt = root / "data" / "jobs" / "job_project_build" / "attempts" / "attempt_0001"
        art = attempt / "artifacts" / "project-build" / "accepted-project-build-dispatch.json"
        art.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(art, payload)
        ref = {
            "path": art.relative_to(root).as_posix(),
            "sha256": file_sha256(art),
            "size_bytes": art.stat().st_size,
        }
        handoff = attempt / "handoff.json"
        write_fixture_handoff(root, handoff, {
            "job_id": "job_project_build",
            "attempt_id": "attempt_0001",
            "source_fingerprint": "f" * 40,
            "outputs": {"acceptance.publish_handoff": {"terminal_status": "SUCCEEDED", "artifact": ref, "gaps": []}},
        })
        atomic_json(root / "data" / "jobs" / "job_project_build" / "latest.json", {
            "attempt_id": "attempt_0001",
            "handoff_path": handoff.relative_to(root).as_posix(),
            "handoff_sha256": file_sha256(handoff),
        })
        return art, ref

    run_root = tmp_path / "run"
    doc = {
        "schema": SCHEMA,
        "source_fingerprint": "f" * 40,
        "execution_graph": {"edges": []},
        "probe_receipts": [],
        "build_dispatches": [{"build_unit_id": BUILD_UNIT}],
    }
    art_path, art_ref = _publish_builds(run_root, doc)

    loaded = load_accepted_builds(run_root)
    assert loaded["schema"] == SCHEMA and loaded["project_build_artifact_sha256"] == art_ref["sha256"]

    with pytest.raises(ValueError, match="execution reader mode must be explicit"):
        load_accepted_builds(run_root, for_execution=1)  # type: ignore[arg-type]

    checked: list[str] = []
    monkeypatch.setattr(
        build_topology_artifacts, "guard_cache_action",
        lambda _r, d, **kw: checked.append(d["build_unit_id"]),
    )
    load_accepted_builds(run_root, for_execution=True)
    assert checked == [BUILD_UNIT]

    # Tampered artifact bytes fail closed
    atomic_json(art_path, {**doc, "probe_receipts": [{"family": "native", "commands": [{"ordinal": 1}], "enforcement": []}]})
    with pytest.raises(ValueError, match="project-build artifact identity changed"):
        load_accepted_builds(run_root)

    # Native receipt without enforcement record fails closed when handoff hash matches
    enf_root = tmp_path / "run-bad-enf"
    _publish_builds(enf_root, {**doc, "probe_receipts": [{"family": "native", "commands": [{"ordinal": 1}], "enforcement": []}]})
    with pytest.raises(ValueError, match="native build must retain exactly one captured enforcement record"):
        load_accepted_builds(enf_root)

    # Unsupported schema fails closed
    schema_root = tmp_path / "run-bad-schema"
    _publish_builds(schema_root, {**doc, "schema": "appsec-review/project-build-dispatch/0"})
    with pytest.raises(ValueError, match="project-build dispatch schema is unsupported"):
        load_accepted_builds(schema_root)


# --- step handlers: plan, image, static_dispatch, probe, build_dispatch, publish -----------------

def test_step_handlers_plan_image_static_probe_build_dispatch_and_publish(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(build_topology_artifacts, "selected_cache_actions", lambda _r: {})
    monkeypatch.setattr(
        build_topology_artifacts, "bind_actions",
        lambda _r, acts, **kw: [{**dict(a), "topology_refinement": {"path": "x", "sha256": "0" * 64}} for a in acts],
    )
    monkeypatch.setattr(
        build_topology_artifacts, "guard_action",
        lambda _r, act, **kw: {
            "enforcement": [{"proof_kind": "captured_invocation", "status": "unknown", "unresolved_inputs": ["x"]}]
        },
    )
    monkeypatch.setattr(project_job, "resolved_configuration_identity", lambda _r: "c" * 64)
    monkeypatch.setattr(project_job, "selected_graph", lambda actions, **kw: {"nodes": len(actions), "edges": []})

    ctx = _unit_context(tmp_path, unit_id="plan.load_recipes")
    (ctx.job.target_root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\nproject(p)\n", encoding="utf-8")

    # Graphless plan is refused
    monkeypatch.setattr(
        project_job, "load_accepted_plan",
        lambda _r: {"build_topology": {"build_actions": [], "executable_graph": None}, "scanner_selections": []},
    )
    units = {u.unit_id: u for u in build_job(
        image_resolver_factory=lambda _u: SimpleNamespace(
            resolve=lambda rec, prof: (_project_image(family=prof.name), b"img-out", b"")
        ),
        unity_executor_factory=lambda: None,
    ).units}
    with pytest.raises(ValueError, match="graphless target plans require replanning"):
        units["plan.load_recipes"].handler(ctx)

    # Full plan with native cmake, blocked go (missing recipe), unity dotnet, and source_only_scopes
    accepted_plan = {
        "build_topology": {
            "build_actions": [
                {
                    "build_unit_id": BUILD_UNIT, "family": "native", "root": ".", "build_system": "cmake",
                    "descriptor_package": {
                        "documents": [{"path": "CMakeLists.txt", "sha256": "1" * 64, "content": "project(p)\n"}],
                        "gaps": [],
                    },
                },
                {
                    "build_unit_id": "build-unit-go", "family": "go", "root": ".", "build_system": "go",
                    "descriptor_package": {
                        "documents": [{"path": "go.mod", "sha256": "2" * 64, "content": "module ex\n"}],
                        "gaps": [],
                    },
                },
                {
                    "build_unit_id": "build-unit-unity", "family": "dotnet", "root": ".", "build_system": "unity",
                    "descriptor_package": {
                        "documents": [{"path": "Assembly-CSharp.csproj", "sha256": "3" * 64, "content": "<Project/>"}],
                        "gaps": [],
                    },
                },
            ],
            "executable_graph": {"edges": []},
            "relationships": [],
            "source_only_scopes": [
                {
                    "scope_id": "scope-py",
                    "language": "python",
                    "root": "scripts",
                    "sources": [{"path": "scripts/run.py", "sha256": "4" * 64}],
                }
            ],
        },
        "scanner_selections": [
            {"scanner_id": "semgrep", "reason": "selected", "scope": [{"path": "main.c"}, {"path": "other/x.py"}]}
        ],
    }
    monkeypatch.setattr(project_job, "load_accepted_plan", lambda _r: accepted_plan)
    planned = units["plan.load_recipes"].handler(ctx)
    assert planned["action_count"] == 3 and planned["terminal_status"] == "GAP"
    assert any("build-unit-go" in g["reason"] for g in planned["gaps"])

    # Wire plan output into downstream step contexts
    ctx.outputs["plan.load_recipes"] = planned

    # image.native succeeds; image.go records missing-recipe BLOCKED; image.dotnet skips unity -> NOT_APPLICABLE
    ctx.unit_id = "image.native"
    img_native = units["image.native"].handler(ctx)
    assert img_native["terminal_status"] == "SUCCEEDED" and img_native["image_count"] == 1
    ctx.outputs["image.native"] = img_native

    ctx.unit_id = "image.go"
    img_go = units["image.go"].handler(ctx)
    assert img_go["terminal_status"] == "COMPLETED_WITH_GAPS" and img_go["entries"][0]["terminal_status"] == "BLOCKED"
    ctx.outputs["image.go"] = img_go

    ctx.unit_id = "image.dotnet"
    img_dotnet = units["image.dotnet"].handler(ctx)
    assert img_dotnet["terminal_status"] == "NOT_APPLICABLE"
    ctx.outputs["image.dotnet"] = img_dotnet

    # static_dispatch.global and static_dispatch.native
    ctx.unit_id = "static_dispatch.native"
    st_native = units["static_dispatch.native"].handler(ctx)
    assert st_native["dispatch_count"] == 1 and st_native["dispatches"][0]["workflow"] == "lang_jobflow_static"

    sub_plan = {
        "actions": [{"build_unit_id": BUILD_UNIT, "family": "native", "root": "native"}],
        "scanner_selections": [
            {"scanner_id": "semgrep", "reason": "r", "scope": [{"path": "native/a.c"}, {"path": "docs/x.md"}]}
        ],
    }
    global_ctx = _unit_context(tmp_path, unit_id="static_dispatch.global")
    global_ctx.outputs["plan.load_recipes"] = sub_plan
    st_global = units["static_dispatch.global"].handler(global_ctx)
    assert st_global["dispatch_count"] == 1 and st_global["dispatches"][0]["scope"] == [{"path": "docs/x.md"}]

    # probe.native runs _execute_one and captures receipt; error path raises ProjectBuildFailed
    import appsec_review.jobs.job_language_build.job as lang_job
    monkeypatch.setattr(
        lang_job, "_execute_one",
        lambda _u, disp, _p, _ef, **kw: {
            "build_unit_id": disp["build_unit_id"], "family": "native", "terminal_status": "SUCCEEDED",
            "artifacts": [{"path": "a.o"}], "commands": [{"ordinal": 1}], "gaps": [], "enforcement": [{"ok": True}],
        },
    )
    ctx.unit_id = "probe.native"
    pr_native = units["probe.native"].handler(ctx)
    assert pr_native["terminal_status"] == "SUCCEEDED"
    assert pr_native["receipts"][0]["probe_disposition"] == "CAPTURED"
    ctx.outputs["probe.native"] = pr_native

    # probe.dotnet delegates unity actions to execute_unity_build
    import appsec_review.jobs.unity_build as unity_mod
    monkeypatch.setattr(
        unity_mod, "execute_unity_build",
        lambda _u, act, _s, **kw: {
            "build_unit_id": act["build_unit_id"], "family": "dotnet", "terminal_status": "SUCCEEDED",
            "artifacts": [], "commands": [], "gaps": [],
        },
    )
    ctx.unit_id = "probe.dotnet"
    pr_dotnet = units["probe.dotnet"].handler(ctx)
    assert pr_dotnet["probe_count"] == 1 and pr_dotnet["receipts"][0]["probe_disposition"] == "COMPUTED"
    ctx.outputs["probe.dotnet"] = pr_dotnet

    # build_dispatch.native binds native receipt & execution_owner="job_project_build"; build_dispatch.python carries gaps
    ctx.unit_id = "build_dispatch.native"
    bd_native = units["build_dispatch.native"].handler(ctx)
    assert bd_native["terminal_status"] == "SUCCEEDED"
    assert bd_native["dispatches"][0]["execution_owner"] == "job_project_build"
    ctx.outputs["build_dispatch.native"] = bd_native

    ctx.unit_id = "probe.go"
    pr_go = units["probe.go"].handler(ctx)
    assert pr_go["terminal_status"] == "NOT_APPLICABLE"
    ctx.outputs["probe.go"] = pr_go

    ctx.unit_id = "build_dispatch.go"
    bd_go = units["build_dispatch.go"].handler(ctx)
    assert bd_go["terminal_status"] == "COMPLETED_WITH_GAPS" and bd_go["dispatches"] == []
    ctx.outputs["build_dispatch.go"] = bd_go

    # Fill remaining families/lanes and run acceptance.publish_handoff (exercising finalize_processing)
    for fam in BUILD_FAMILIES:
        ctx.outputs.setdefault(f"image.{fam}", {"entries": [], "gaps": []})
        ctx.outputs.setdefault(f"probe.{fam}", {"receipts": [], "gaps": []})
        ctx.outputs.setdefault(f"build_dispatch.{fam}", {"dispatches": [], "gaps": []})
    for lane in STATIC_LANES:
        ctx.outputs.setdefault(f"static_dispatch.{lane}", {"dispatches": [], "gaps": []})
    ctx.outputs["static_dispatch.native"] = st_native
    ctx.unit_id = "acceptance.publish_handoff"
    pub = units["acceptance.publish_handoff"].handler(ctx)
    assert pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert pub["probe_count"] == 2 and pub["build_dispatch_count"] == 1

    # Verify probe.native failure writes failure.json and raises ProjectBuildFailed
    monkeypatch.setattr(
        lang_job, "_execute_one",
        lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("compiler crashed")),
    )
    ctx.unit_id = "probe.native"
    with pytest.raises(ProjectBuildFailed, match="compiler crashed"):
        units["probe.native"].handler(ctx)
    assert (ctx.unit_root / BUILD_UNIT / "failure.json").is_file()

    # Verify image_handler error branches (ProjectImageBuildError & ImagePreparationUnavailable) and blocked/connected probe.native
    err_units = {u.unit_id: u for u in build_job(
        image_resolver_factory=lambda _u: SimpleNamespace(
            resolve=lambda _rec, _prof: (_ for _ in ()).throw(
                ProjectImageBuildError("docker build failed", stdout=b"s", stderr=b"e")
            )
        ),
        unity_executor_factory=lambda: None,
    ).units}
    err_ctx = _unit_context(tmp_path / "img-err", unit_id="image.native")
    err_ctx.outputs["plan.load_recipes"] = {
        "actions": [{
            "build_unit_id": BUILD_UNIT, "family": "native", "root": ".", "build_system": "cmake",
            "recipe": _sample_recipe("native"),
        }],
        "execution_graph": {"edges": []},
    }
    img_failed = err_units["image.native"].handler(err_ctx)
    assert img_failed["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert img_failed["entries"][0]["terminal_status"] == "FAILED"

    err_ctx.outputs["image.native"] = img_failed
    err_ctx.unit_id = "probe.native"
    blocked_probe = err_units["probe.native"].handler(err_ctx)
    assert blocked_probe["receipts"][0]["terminal_status"] == "BLOCKED"

    # Connected native unit is skipped in probe.native (owned by job_build_iteration)
    err_ctx.outputs["plan.load_recipes"]["execution_graph"] = {
        "edges": [{"producer_build_unit_id": BUILD_UNIT, "consumer_build_unit_id": "other"}]
    }
    connected_probe = err_units["probe.native"].handler(err_ctx)
    assert connected_probe["terminal_status"] == "NOT_APPLICABLE" and connected_probe["probe_count"] == 0