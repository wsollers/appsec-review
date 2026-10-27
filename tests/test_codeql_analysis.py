from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import threading
import time
import tomllib
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan, replay_commands
from appsec_review.jobs.job_codeql_analysis.sarif import map_location, normalize_sarif
from appsec_review.config.codeql import CodeQLExecutionMode, parse_codeql_settings
from appsec_review.codeql.runtime import (
    CodeQLExecutor,
    CodeQLImage,
    CodeQLImageResolver,
    _bounded_stream,
    load_asset_lock,
    tree_manifest,
)
from appsec_review.jobs.job_codeql_analysis.job import (
    FrameworkIntegrityError,
    _database_identity,
    _normalize_one,
    _query_identity,
    _query_profiles,
    _stage_manifest_workspace,
    _stage_workspace,
    _validate_scope_assets,
    _verify_workspace_manifest,
    publication_status,
)
from appsec_review.storage import canonical_json


IMAGE = "sha256:" + "1" * 64
ROOT = Path(__file__).parents[1]


def _workspace_manifest(workspace: Path) -> dict[str, object]:
    return {
        "schema": "appsec-review/build-workspace-manifest/1",
        "files": {
            path.relative_to(workspace).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(workspace.rglob("*"))
            if path.is_file() and not path.is_symlink()
        },
    }


def _symlink_or_skip(link: Path, target: str | Path, *, target_is_directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")


def test_materialized_workspace_staging_omits_manifest_backed_npm_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    executable = source / "node_modules" / "esbuild" / "bin" / "esbuild"
    executable.parent.mkdir(parents=True)
    executable.write_text("binary", encoding="utf-8")
    npm_bin = source / "node_modules" / ".bin"
    npm_bin.mkdir()
    _symlink_or_skip(npm_bin / "esbuild", "../esbuild/bin/esbuild")
    manifest = _workspace_manifest(source)

    staged = tmp_path / "staged"
    _stage_manifest_workspace(source, staged, manifest, file_limit=10)

    assert (staged / "node_modules" / "esbuild" / "bin" / "esbuild").read_text() == "binary"
    assert not (staged / "node_modules" / ".bin" / "esbuild").exists()


def test_materialized_workspace_staging_omits_container_owned_node_modules_symlink(
        tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = source / "projects" / "typescript" / "case-032"
    project.mkdir(parents=True)
    (project / "package.json").write_text("{}", encoding="utf-8")
    _symlink_or_skip(
        project / "node_modules",
        "/opt/project/projects/typescript/case-032/node_modules",
        target_is_directory=True,
    )
    manifest = _workspace_manifest(source)

    staged = tmp_path / "staged"
    _stage_manifest_workspace(source, staged, manifest, file_limit=10)

    assert (staged / "projects" / "typescript" / "case-032" / "package.json").is_file()
    assert not (staged / "projects" / "typescript" / "case-032" / "node_modules").is_symlink()


def test_materialized_workspace_staging_omits_pinned_npm_workspace_directory_links(
        tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = source / "projects" / "northwinds-v1"
    modules = project / "node_modules" / "@northwinds"
    modules.mkdir(parents=True)
    (project / "package.json").write_text(
        '{"workspaces":["backend","frontend"]}', encoding="utf-8")
    for name in ("backend", "frontend"):
        package = project / name
        package.mkdir()
        (package / "index.ts").write_text(f'export const name = "{name}";', encoding="utf-8")
        _symlink_or_skip(modules / name, f"../../{name}", target_is_directory=True)
    manifest = _workspace_manifest(source)

    staged = tmp_path / "staged"
    _stage_manifest_workspace(source, staged, manifest, file_limit=3)

    assert _workspace_manifest(staged) == manifest
    assert (staged / "projects" / "northwinds-v1" / "frontend" / "index.ts").is_file()
    assert not any(path.is_symlink() for path in staged.rglob("*"))
    assert not (staged / "projects" / "northwinds-v1" / "node_modules").exists()


@pytest.mark.parametrize("target_kind", ["absolute", "outside", "dangling", "self", "pair", "ancestor"])
def test_materialized_workspace_staging_rejects_unsafe_directory_links(
        tmp_path: Path, target_kind: str) -> None:
    source = tmp_path / "source"
    real = source / "real"
    real.mkdir(parents=True)
    (real / "index.ts").write_text("export {};", encoding="utf-8")
    link = real / "link" if target_kind == "ancestor" else source / "link"
    targets = {
        "absolute": real,
        "outside": "../outside",
        "dangling": "missing",
        "self": "link",
        "pair": "other",
        "ancestor": ".",
    }
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "untrusted.ts").write_text("outside", encoding="utf-8")
    if target_kind == "pair":
        _symlink_or_skip(source / "other", "link", target_is_directory=True)
    manifest = _workspace_manifest(source)
    _symlink_or_skip(link, targets[target_kind], target_is_directory=True)

    with pytest.raises(FrameworkIntegrityError, match=r"(unsafe|invalid) symlink.*link"):
        _stage_manifest_workspace(source, tmp_path / "staged", manifest, file_limit=10)
    assert not (tmp_path / "staged").exists()


@pytest.mark.parametrize("mutation", ["unlisted", "changed", "empty", "nested_escape", "file_bound"])
def test_materialized_workspace_directory_link_does_not_bypass_manifest(
        tmp_path: Path, mutation: str) -> None:
    source = tmp_path / "source"
    package = source / "frontend"
    package.mkdir(parents=True)
    payload = package / "index.ts"
    payload.write_text("export {};", encoding="utf-8")
    manifest = _workspace_manifest(source)
    _symlink_or_skip(source / "linked", "frontend", target_is_directory=True)
    if mutation == "unlisted":
        (package / "extra.ts").write_text("unlisted", encoding="utf-8")
    elif mutation == "changed":
        payload.write_text("changed", encoding="utf-8")
    elif mutation == "empty":
        payload.unlink()
        manifest = _workspace_manifest(source)
    elif mutation == "nested_escape":
        outside = tmp_path / "outside.ts"
        outside.write_text("untrusted", encoding="utf-8")
        _symlink_or_skip(package / "escape", "../../outside.ts")

    with pytest.raises(FrameworkIntegrityError):
        _stage_manifest_workspace(source, tmp_path / "staged", manifest,
                                  file_limit=0 if mutation == "file_bound" else 10)
    assert not (tmp_path / "staged").exists()


def test_materialized_workspace_strict_verification_still_rejects_directory_links(
        tmp_path: Path) -> None:
    source = tmp_path / "source"
    package = source / "frontend"
    package.mkdir(parents=True)
    (package / "index.ts").write_text("export {};", encoding="utf-8")
    manifest = _workspace_manifest(source)
    _symlink_or_skip(source / "linked", "frontend", target_is_directory=True)

    with pytest.raises(FrameworkIntegrityError, match="contains a symlink: 'linked'"):
        _verify_workspace_manifest(source, manifest, file_limit=10)


def test_materialized_workspace_symlink_error_identifies_scope(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job

    source = tmp_path / "source"
    source.mkdir()
    manifest = _workspace_manifest(source)
    _symlink_or_skip(source / "linked", "missing", target_is_directory=True)
    unit = SimpleNamespace(job=SimpleNamespace(target_root=tmp_path, run_root=tmp_path))
    scope = SimpleNamespace(scope_id="codeql-unit-northwinds", root="frontend", files=(),
                            language="javascript", mode="none")
    monkeypatch.setattr(codeql_job, "_safe_json", lambda *args: manifest)
    monkeypatch.setattr(codeql_job, "_settings", lambda unit: SimpleNamespace(database_file_limit=10))

    with pytest.raises(FrameworkIntegrityError, match=r"codeql-unit-northwinds.*frontend.*linked.*missing"):
        _stage_workspace(unit, scope, {"workspace_manifest": {}, "workspace": "source"},
                         tmp_path / "staged")


def test_materialized_workspace_staging_rejects_mismatched_container_node_modules_symlink(
        tmp_path: Path) -> None:
    source = tmp_path / "source"
    project = source / "projects" / "typescript" / "case-032"
    project.mkdir(parents=True)
    (project / "package.json").write_text("{}", encoding="utf-8")
    _symlink_or_skip(
        project / "node_modules",
        "/opt/project/projects/typescript/other/node_modules",
        target_is_directory=True,
    )

    with pytest.raises(FrameworkIntegrityError, match="unsafe symlink"):
        _stage_manifest_workspace(source, tmp_path / "staged", _workspace_manifest(source),
                                  file_limit=10)


def test_materialized_workspace_staging_rejects_escaping_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    retained = source / "package.json"
    retained.write_text("{}", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("untrusted", encoding="utf-8")
    _symlink_or_skip(source / "escape", outside)

    with pytest.raises(FrameworkIntegrityError, match="unsafe symlink"):
        _stage_manifest_workspace(source, tmp_path / "staged", _workspace_manifest(source),
                                  file_limit=10)


def test_materialized_workspace_staging_rejects_manifest_path_through_symlink(
        tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    real = source / "real"
    real.mkdir()
    payload = real / "payload.js"
    payload.write_text("payload", encoding="utf-8")
    _symlink_or_skip(source / "linked", "real", target_is_directory=True)
    manifest = _workspace_manifest(source)
    manifest_files = manifest["files"]
    assert isinstance(manifest_files, dict)
    manifest_files["linked/payload.js"] = hashlib.sha256(payload.read_bytes()).hexdigest()

    with pytest.raises(FrameworkIntegrityError, match="identity changed"):
        _stage_manifest_workspace(source, tmp_path / "staged", manifest, file_limit=10)


def test_materialized_workspace_staging_rejects_hash_change(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "package.json").write_text("{}", encoding="utf-8")
    manifest = _workspace_manifest(source)
    (source / "package.json").write_text('{"changed":true}', encoding="utf-8")

    with pytest.raises(FrameworkIntegrityError, match="identity changed"):
        _stage_manifest_workspace(source, tmp_path / "staged", manifest, file_limit=10)


def test_central_codeql_asset_lock_matches_tracked_lock() -> None:
    config = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    settings = config["jobs"]["job_codeql_analysis"]["settings"]
    lock = load_asset_lock(ROOT)
    assert "sha256" not in lock
    for language, configured in settings["languages"].items():
        locked = lock["query_packs"][language]
        assert configured.get("additional_queries", []) == locked.get("additional_suites", [])
        assert configured.get("custom_queries", []) == lock.get("custom_query_packs", {}).get(language, [])


def test_go_extended_suite_missing_from_lock_reproduces_review_failure() -> None:
    config = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    settings = parse_codeql_settings(config["jobs"]["job_codeql_analysis"]["settings"])
    lock = load_asset_lock(ROOT)
    scope = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("go/main.go")],
        receipts=[receipt("go", "go", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"go"}, source_image_id=IMAGE,
    ).scopes[0]
    assert scope.language == "go"
    assert [query.query_id for query in settings.languages["go"].additional_queries] == [
        "security-extended"]
    _validate_scope_assets(scope, settings, lock)

    go_without_extended = dict(lock["query_packs"]["go"])
    go_without_extended.pop("additional_suites")
    broken_lock = {**lock, "query_packs": {**lock["query_packs"], "go": go_without_extended}}
    with pytest.raises(FrameworkIntegrityError,
                       match="CodeQL go additional query assets differ from the lock"):
        _validate_scope_assets(scope, settings, broken_lock)


def test_codeql_timeout_removes_its_container_before_its_volume(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(argv, _timeout):
        calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, (IMAGE + "\n").encode(), b"", False
        if "/opt/appsec/codeql_runner.py" in argv:
            return None, b"", b"", True
        return 0, b"", b"", False

    image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, IMAGE, IMAGE,
                        "build:local", IMAGE, "codeql:local", "10001:10001",
                        "b" * 64, "c" * 64, False, "manifest.json")
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024)
    (tmp_path / "scratch").mkdir()
    result = CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
        "database", ("--language", "csharp", "--database", "database"),
        scratch_root=tmp_path / "scratch")
    database_run = next(call for call in calls if "/opt/appsec/codeql_runner.py" in call)
    name = database_run[database_run.index("--name") + 1]
    removal = calls.index(("docker", "rm", "--force", name))
    volume_removal = next(index for index, call in enumerate(calls) if call[:3] == ("docker", "volume", "rm"))
    assert calls.index(database_run) < removal < volume_removal
    assert result.timed_out is True


def test_codeql_build_execution_uses_bridge_network(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(argv, _timeout):
        calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, (IMAGE + "\n").encode(), b"", False
        if "/opt/appsec/codeql_runner.py" in argv:
            (tmp_path / "scratch" / "database-export").mkdir()
        return 0, b"ok", b"", False

    image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, IMAGE, IMAGE,
                        "build:local", IMAGE, "codeql:local", "10001:10001",
                        "b" * 64, "c" * 64, False, "manifest.json")
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024)
    result = CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
        "database", ("--language", "csharp", "--database", "database"),
        scratch_root=tmp_path / "scratch")
    database_run = next(call for call in calls if "/opt/appsec/codeql_runner.py" in call)
    assert database_run[database_run.index("--network") + 1] == "bridge"
    assert "--staged-database" in database_run
    assert any("type=volume,src=appsec-codeql-" in value and "dst=/scratch/database" in value
               for value in database_run)
    assert len([call for call in calls if call[:3] == ("docker", "volume", "rm")]) == 1
    assert result.limits["network"] == "bridge"
    assert (tmp_path / "scratch" / "database").is_dir()


def test_codeql_execution_survives_a_moved_derived_tag_but_not_a_missing_image(tmp_path: Path) -> None:
    moved = "sha256:" + "9" * 64
    present = {IMAGE}

    def runner(argv, _timeout):
        if argv[:3] == ("docker", "image", "inspect"):
            reference = argv[3]
            if reference == "codeql:local":
                return 0, (moved + "\n").encode(), b"", False
            if reference in present:
                return 0, (reference + "\n").encode(), b"", False
            return 1, b"", b"Error: No such image", False
        if "/opt/appsec/codeql_runner.py" in argv:
            (tmp_path / "scratch" / "database-export").mkdir(exist_ok=True)
        return 0, b"ok", b"", False

    image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, IMAGE, IMAGE,
                        "build:local", IMAGE, "codeql:local", "10001:10001",
                        "b" * 64, "c" * 64, False, "manifest.json")
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024)
    executor = CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner)
    arguments = ("--language", "csharp", "--database", "database")
    # Another process rebuilt the same identity and moved the tag; the pinned id still runs.
    assert executor.execute("database", arguments, scratch_root=tmp_path / "scratch").image_id == IMAGE
    present.clear()
    with pytest.raises(ValueError, match="is unavailable: Error: No such image"):
        executor.execute("database", arguments, scratch_root=tmp_path / "scratch")


def source(path: str, digest: str = "a" * 64) -> dict[str, object]:
    return {"path": path, "sha256": digest, "size_bytes": 12}


def receipt(family: str, root: str, unit: str, *, status: str = "SUCCEEDED",
            commands: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "family": family, "root": root, "build_unit_id": unit, "terminal_status": status,
        "workspace": f"data/build/{family}/{unit}/workspace" if status == "SUCCEEDED" else None,
        "commands": ([{"ordinal": 1, "role": "build"}] if commands is None else commands),
        "recipe": {"configure_commands": [], "build_commands": [["build"]]},
        "fingerprint": (unit[-1] * 64), "recipe_identity": "2" * 64,
        "dependency_identity": "3" * 64,
        "workspace_manifest": {"path": f"{unit}.json", "sha256": "4" * 64},
        "image": {"image_id": IMAGE},
    }


def test_routes_every_supported_mode_and_keeps_kotlin_and_typescript_visible() -> None:
    files = [
        source("cpp/a.cpp"), source("go/main.go"), source("jvm/A.java"), source("jvm/B.kt"),
        source("dotnet/A.cs"), source("node/a.js"), source("node/b.ts"), source("py/a.py"),
        source("ruby/a.rb"),
        source("rust/a.rs"), source("rust/Cargo.toml"), source("rust/Cargo.lock"),
        source(".github/workflows/ci.yml"), source("web/a.php"),
    ]
    receipts = [
        receipt("native", "cpp", "build-unit-aaaaaaaaaaaaaaaaaaaa"),
        receipt("go", "go", "build-unit-bbbbbbbbbbbbbbbbbbbb"),
        receipt("java", "jvm", "build-unit-cccccccccccccccccccc"),
        receipt("dotnet", "dotnet", "build-unit-dddddddddddddddddddd"),
        receipt("node", "node", "build-unit-eeeeeeeeeeeeeeeeeeee", commands=[]),
        receipt("python", "py", "build-unit-ffffffffffffffffffff", commands=[]),
        receipt("rust", "rust", "build-unit-11111111111111111111", commands=[]),
    ]
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=files, receipts=receipts,
        supported_extractors={"cpp", "go", "java", "csharp", "javascript", "python", "ruby", "rust", "actions"},
        source_image_id=IMAGE,
    )
    by_language = {item.language: item for item in plan.scopes}
    assert set(by_language) == {"cpp", "go", "java", "csharp", "javascript", "python", "ruby", "rust", "actions"}
    assert {name: by_language[name].mode for name in by_language} == {
        "cpp": "manual", "go": "manual", "java": "manual", "csharp": "manual",
        "javascript": "none", "python": "none", "ruby": "none", "rust": "none", "actions": "none",
    }
    assert by_language["java"].source_languages == ("Java", "Kotlin")
    assert by_language["javascript"].source_languages == ("JavaScript", "TypeScript")
    assert all(not by_language[name].commands_permitted
               for name in ("javascript", "python", "ruby", "rust", "actions"))
    assert [item["status"] for item in plan.non_applicable] == ["SKIPPED_NA"]
    assert plan.non_applicable[0]["language"] == "php"


def test_failed_sibling_is_a_gap_without_erasing_successful_scope() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("one/a.go"), source("two/b.go")],
        receipts=[receipt("go", "one", "build-unit-aaaaaaaaaaaaaaaaaaaa"),
                  receipt("go", "two", "build-unit-bbbbbbbbbbbbbbbbbbbb", status="BLOCKED")],
        supported_extractors={"go"}, source_image_id=IMAGE,
    )
    assert [item.root for item in plan.scopes] == ["one"]
    assert any("build-unit-bbbbbbbbbbbbbbbbbbbb/go" in gap for gap in plan.gaps)


def test_dotnet_does_not_claim_visual_basic_or_fsharp() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("net/a.cs"), source("net/b.vb"), source("net/c.fs")],
        receipts=[receipt("dotnet", "net", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"csharp"}, source_image_id=IMAGE,
    )
    assert len(plan.scopes) == 1 and plan.scopes[0].language == "csharp"
    assert any(gap.startswith("Visual Basic:") for gap in plan.gaps)
    assert any(gap.startswith("F#:") for gap in plan.gaps)


def test_missing_runtime_extractor_is_not_silently_planned() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("go/main.go")],
        receipts=[receipt("go", "go", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"python"}, source_image_id=IMAGE,
    )
    assert not plan.scopes
    assert "pinned runtime did not report the required extractor" in plan.gaps[0]


def test_uncovered_planned_source_is_completed_with_gaps_not_succeeded() -> None:
    # A Python-only target on a host whose CodeQL runtime is unavailable plans source:python as a
    # TOOLCHAIN_UNAVAILABLE gap with no scope; the empty result must not publish as SUCCEEDED.
    gap = {"project_id": "source:python", "disposition": "GAP", "reason_code": "TOOLCHAIN_UNAVAILABLE"}
    covered = {"project_id": "source:python", "disposition": "SUCCEEDED", "reason_code": "PROCESSING_SUCCEEDED"}
    skipped = {"project_id": "source:go", "disposition": "SKIPPED_NA", "reason_code": "SOURCE_ABSENT"}
    assert publication_status([gap], []) == "COMPLETED_WITH_GAPS"
    assert publication_status([covered, gap], [{"terminal_status": "SUCCEEDED"}]) == "COMPLETED_WITH_GAPS"
    assert publication_status([covered], [{"terminal_status": "FAILED"}]) == "COMPLETED_WITH_GAPS"
    assert publication_status([covered, skipped], [{"terminal_status": "SUCCEEDED"}]) == "SUCCEEDED"
    assert publication_status([], []) == "SUCCEEDED"


def test_manual_requires_commands_but_source_modes_prohibit_them() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("cpp/a.cpp"), source("py/a.py")],
        receipts=[receipt("native", "cpp", "build-unit-aaaaaaaaaaaaaaaaaaaa", commands=[]),
                  receipt("python", "py", "build-unit-bbbbbbbbbbbbbbbbbbbb")],
        supported_extractors={"cpp", "python"}, source_image_id=IMAGE,
    )
    assert [item.language for item in plan.scopes] == ["python"]
    assert plan.scopes[0].mode == "none" and not plan.scopes[0].commands_permitted
    assert any("accepted compiled build has no exact replayable command set" in gap
               for gap in plan.gaps)


def test_python_native_extension_partitions_source_and_native_once() -> None:
    unit = receipt("python", "pkg", "build-unit-aaaaaaaaaaaaaaaaaaaa")
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("pkg/setup.py"), source("pkg/src/extension.c")],
        receipts=[unit], supported_extractors={"python", "cpp"}, source_image_id=IMAGE,
    )
    assert [(item.language, item.mode, item.build_unit_id) for item in plan.scopes] == [
        ("cpp", "manual", unit["build_unit_id"]),
        ("python", "none", unit["build_unit_id"]),
    ]
    assigned = [record["path"] for item in plan.scopes for record in item.files]
    assert sorted(assigned) == ["pkg/setup.py", "pkg/src/extension.c"]
    assert len(assigned) == len(set(assigned))


def test_node_native_failure_does_not_mask_source_scope() -> None:
    unit = receipt("node", "addon", "build-unit-bbbbbbbbbbbbbbbbbbbb", commands=[])
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("addon/index.js"), source("addon/src/addon.cc")],
        receipts=[unit], supported_extractors={"javascript", "cpp"}, source_image_id=IMAGE,
    )
    assert [(item.language, item.mode) for item in plan.scopes] == [("javascript", "none")]
    assert [item["path"] for item in plan.scopes[0].files] == ["addon/index.js"]
    assert any("build-unit-bbbbbbbbbbbbbbbbbbbb/cpp" in gap and
               "no exact replayable command set" in gap for gap in plan.gaps)


def test_java_commands_without_roles_derive_order_from_accepted_recipe() -> None:
    java = receipt("java", "jvm", "build-unit-aaaaaaaaaaaaaaaaaaaa",
                   commands=[{"ordinal": 1}, {"ordinal": 2}])
    java["recipe"] = {"configure_commands": [["configure"]],
                      "build_commands": [["build"]]}
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("jvm/A.java"), source("jvm/B.kt")],
        receipts=[java], supported_extractors={"java"}, source_image_id=IMAGE,
    )
    assert len(plan.scopes) == 1
    assert plan.scopes[0].source_languages == ("Java", "Kotlin")


def test_android_gradle_scripts_do_not_invent_kotlin_source_coverage() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("android/app/src/main/java/example/Main.java"),
               source("android/app/build.gradle.kts"),
               source("android/settings.gradle.kts")],
        receipts=[receipt("java", "android", "build-unit-androidandroidandroid")],
        supported_extractors={"java"}, source_image_id=IMAGE,
    )
    assert plan.scopes[0].source_languages == ("Java",)
    assert [item["path"] for item in plan.scopes[0].files] == [
        "android/app/src/main/java/example/Main.java"]


def test_replay_commands_ignores_labeled_catalog_commands() -> None:
    go = receipt("go", "go", "build-unit-bbbbbbbbbbbbbbbbbbbb", commands=[
        {"ordinal": 1, "role": "build"},
        {"ordinal": 2, "role": "catalog"},
    ])

    assert replay_commands(go) == ((go["commands"][0], "build"),)


def test_replay_commands_rejects_ambiguous_unlabeled_inventory() -> None:
    java = receipt("java", "jvm", "build-unit-cccccccccccccccccccc", commands=[
        {"ordinal": 1}, {"ordinal": 2}, {"ordinal": 3},
    ])
    java["recipe"] = {"configure_commands": [["configure"]],
                      "build_commands": [["build"]]}

    assert replay_commands(java) is None


def test_rust_cannot_be_represented_as_manual() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("rust/a.rs"), source("rust/Cargo.toml"), source("rust/Cargo.lock")],
        receipts=[receipt("rust", "rust", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"rust"}, source_image_id=IMAGE,
    )
    assert plan.scopes[0].mode == "none"
    with pytest.raises(ValueError, match="Rust extractor"):
        replace(plan.scopes[0], mode="manual", commands_permitted=True)


def test_ruby_uses_source_mode_while_swift_remains_a_platform_gap() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("lib/a.rb"), source("ios/a.swift")], receipts=[],
        supported_extractors={"ruby", "swift"}, source_image_id=IMAGE,
    )
    assert [(scope.language, scope.mode, scope.source_languages) for scope in plan.scopes] == [
        ("ruby", "none", ("Ruby",))]
    assert not any(gap.startswith("Ruby:") for gap in plan.gaps)
    assert any(gap.startswith("Swift:") for gap in plan.gaps)


def test_missing_ruby_extractor_is_a_gap_not_false_coverage() -> None:
    plan = build_codeql_plan(source_fingerprint="f" * 64, files=[source("lib/a.rb")], receipts=[],
                             supported_extractors={"python"}, source_image_id=IMAGE)
    assert not plan.scopes
    assert plan.gaps == ("ruby: accepted source exists but the runtime reported no extractor",)


def test_actions_are_planned_only_for_accepted_workflow_files() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source(".github/workflows/ci.yaml"), source("docs/example.yml")], receipts=[],
        supported_extractors={"actions"}, source_image_id=IMAGE,
    )
    assert len(plan.scopes) == 1
    assert [item["path"] for item in plan.scopes[0].files] == [".github/workflows/ci.yaml"]


def test_source_only_projects_do_not_require_language_build_receipts() -> None:
    plan = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source("web/a.js"), source("typed/a.ts"), source("py/a.py"),
               source("rust/src/main.rs"), source("rust/Cargo.toml")],
        receipts=[], projects=[{"root": "web"}, {"root": "typed"}, {"root": "rust"}],
        supported_extractors={"javascript", "python", "rust"}, source_image_id=IMAGE,
    )
    assert [(item.language, item.root, item.mode) for item in plan.scopes] == [
        ("javascript", "typed", "none"), ("javascript", "web", "none"),
        ("python", "py", "none"),
    ]
    assert all(item.build_unit_id is None and not item.commands_permitted for item in plan.scopes)
    assert any("Cargo.lock prerequisite is absent" in gap for gap in plan.gaps)


def test_sarif_normalization_maps_results_and_code_flow_steps() -> None:
    files = [source("project/src/a.ts"), source("project/src/b.ts", "b" * 64)]
    sarif = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"rules": [{"id": "js/x", "helpUri": "https://example.invalid/x",
                                                "shortDescription": {"text": "x"}}]}},
            "results": [{
                "ruleId": "js/x", "level": "warning", "message": {"text": "observed"},
                "partialFingerprints": {"primaryLocationLineHash": "abc"},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": "file:///scratch/workspace/project/src/a.ts"},
                    "region": {"startLine": 4, "startColumn": 2}}}],
                "codeFlows": [{"threadFlows": [{"locations": [{"location": {
                    "message": {"text": "source"}, "physicalLocation": {
                        "artifactLocation": {"uri": "/scratch/workspace/project/src/b.ts"},
                        "region": {"startLine": 2, "startColumn": 1}}}}]}]}],
            }],
        }],
    }
    records, gaps = normalize_sarif(sarif, files=files, root="project",
                                    query_identity="query", result_limit=10)
    assert gaps == []
    assert records[0]["location"]["path"] == "project/src/a.ts"
    assert records[0]["flows"][0]["location"]["path"] == "project/src/b.ts"
    assert records[0]["payload"]["help_uri"] == "https://example.invalid/x"
    assert records[0]["payload"]["supporting_relations"] == [1]


def test_sarif_ambiguity_and_unmapped_locations_are_preserved_as_gaps() -> None:
    files = [source("one/src/a.py"), source("two/src/a.py", "b" * 64)]
    physical = {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": "bad"}}
    mapped = map_location(physical, files=files, root=".")
    assert mapped.path is None and mapped.ambiguous
    assert mapped.candidates == ("one/src/a.py", "two/src/a.py")
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [{
        "ruleId": "py/x", "message": {"text": "x"},
        "locations": [{"physicalLocation": physical}],
    }]}]}
    records, gaps = normalize_sarif(sarif, files=files, root=".", query_identity="q", result_limit=10)
    assert records[0]["location"]["ambiguous"] is True
    assert "no uniquely mapped source location" in gaps[0]


def test_partial_and_malformed_sarif_results_do_not_erase_valid_siblings() -> None:
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": [
        "malformed",
        {"ruleId": "py/x", "message": {"text": "x"}, "locations": []},
    ]}]}
    records, gaps = normalize_sarif(sarif, files=[source("a.py")], root=".",
                                    query_identity="q", result_limit=10)
    assert len(records) == 1
    assert any("was not an object" in gap for gap in gaps)
    assert any("no uniquely mapped" in gap for gap in gaps)


def test_sarif_contract_rejects_malformed_top_level() -> None:
    with pytest.raises(ValueError, match="contract"):
        normalize_sarif({"version": "1.0"}, files=[], root=".", query_identity="q", result_limit=1)


def _normalization_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job

    settings = SimpleNamespace(sarif_bytes_limit=1024 * 1024, result_limit=100, concurrency=2)
    monkeypatch.setattr(codeql_job, "_settings", lambda unit: settings)
    scopes = build_codeql_plan(
        source_fingerprint="f" * 64,
        files=[source(".github/workflows/ci.yml"), source("app.py")], receipts=[],
        supported_extractors={"actions", "python"}, source_image_id=IMAGE,
    ).scopes
    queries = []
    for scope in scopes:
        sarif_path = tmp_path / f"{scope.language}.sarif"
        sarif_path.write_text(json.dumps({"version": "2.1.0", "runs": [{
            "tool": {"driver": {}}, "results": [{
                "ruleId": "test/rule", "message": {"text": "observation"}, "locations": [],
            }],
        }]}), encoding="utf-8")
        queries.append({
            "scope": asdict(scope), "query_profile": {"query_id": "default", "kind": "default"},
            "database_identity": "d" * 64, "query_identity": "q" * 64,
            "terminal_status": "SUCCEEDED", "database_reused": True, "query_reused": True,
            "gaps": [], "sarif": {
                "path": sarif_path.name, "sha256": hashlib.sha256(sarif_path.read_bytes()).hexdigest(),
                "size_bytes": sarif_path.stat().st_size,
            },
        })
    assert len(queries) == 2
    unit = SimpleNamespace(
        job=SimpleNamespace(run_root=tmp_path, source_fingerprint="f" * 64),
        unit_id="normalize.scopes", output=lambda name: {"queries": queries},
    )
    return unit, queries


def test_normalize_scopes_resumes_mixed_reused_and_fresh_shards(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from appsec_review.jobs.job_codeql_analysis.job import build_job

    unit, queries = _normalization_fixture(tmp_path, monkeypatch)
    first = _normalize_one(unit, queries[0])
    path = tmp_path / first["index"]["path"]
    before = path.stat()
    def normalize():
        values = [_normalize_one(unit, query) for query in queries]
        return {"scopes": values, "observation_count": sum(item["observation_count"] for item in values)}
    resumed = normalize()
    repeated = normalize()

    assert resumed == repeated
    assert resumed["scopes"][0] == first
    assert len(resumed["scopes"]) == 2
    assert resumed["observation_count"] == 2
    assert len(list((tmp_path / "data/indices/observations").iterdir())) == 2
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert hashlib.sha256(path.read_bytes()).hexdigest() == first["index"]["sha256"]


def test_normalizer_release_changes_only_normalized_publication(tmp_path, monkeypatch):
    from appsec_review.config.assurance import ComponentReleases, ReviewPolicy

    unit, queries = _normalization_fixture(tmp_path, monkeypatch)
    unit.job.review_policy = ReviewPolicy(releases=ComponentReleases({"codeql_normalizer": "v1"}))
    first = _normalize_one(unit, queries[0])
    original = tmp_path / first["index"]["path"]
    original_bytes = original.read_bytes()
    unit.job.review_policy = ReviewPolicy(releases=ComponentReleases({"codeql_normalizer": "v2"}))
    second = _normalize_one(unit, queries[0])
    assert second["index"]["path"] != first["index"]["path"]
    assert second["observation_count"] == first["observation_count"]
    assert queries[0]["database_reused"] and queries[0]["query_reused"]
    assert original.read_bytes() == original_bytes
    assert _normalize_one(unit, queries[0]) == second


@pytest.mark.parametrize("invalid_output", [None, "success_without_index", "failure_without_gap"])
def test_normalization_admission_timeout_publishes_successful_sibling(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_output: str | None) -> None:
    from appsec_review.config.assurance import ReviewPolicy
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job
    from appsec_review.observability import EventLog
    from appsec_review.retrieval.index import load_verified_manifest, write_manifest
    from appsec_review.storage import file_sha256

    unit, queries = _normalization_fixture(tmp_path, monkeypatch)
    settings = parse_codeql_settings(_settings_value())
    settings = replace(settings, concurrency=1,
                       export_queries=replace(settings.export_queries, enabled=False))
    plan = build_codeql_plan(
        source_fingerprint=unit.job.source_fingerprint,
        files=[source(".github/workflows/ci.yml"), source("app.py")], receipts=[],
        supported_extractors={"actions", "python"}, source_image_id=IMAGE,
    )
    by_scope = {query["scope"]["scope_id"]: query for query in queries}
    target = tmp_path / "target"
    target.mkdir()
    unit.job.target_root = target
    unit.job.run_id = tmp_path.name
    unit.job.attempt_id = "attempt_0001"
    unit.job.attempt_root = tmp_path / "data/jobs/job_codeql_analysis/attempts/attempt_0001"
    unit.job.metadata_root = tmp_path / "metadata"
    unit.job.review_policy = ReviewPolicy()
    unit.job.events = EventLog(tmp_path / "events.jsonl")
    unit.unit_id = "execution.scopes"
    upstream = tmp_path / "data/indices/manifests/upstream.json"
    write_manifest(upstream, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=target, indexes=[])
    monkeypatch.setattr(codeql_job, "_settings", lambda _: settings)
    monkeypatch.setattr(codeql_job, "_plan_from", lambda _: plan)
    monkeypatch.setattr(codeql_job, "_receipt_map", lambda _: {})
    monkeypatch.setattr(codeql_job, "_database_isolated",
                        lambda _, scope, receipts: by_scope[scope.scope_id])
    monkeypatch.setattr(codeql_job, "_query_one",
                        lambda _, value, profile: {**value, "query_profile": dict(profile)})
    monkeypatch.setattr(codeql_job, "_export_isolated",
                        lambda _, value, **kwargs: {**value, "export_status": "NOT_APPLICABLE"})
    monkeypatch.setattr(codeql_job, "resolve_context_manifest",
                        lambda _: (upstream, file_sha256(upstream)))
    reserve = codeql_job.ResourceAdmission.reserve
    failures = []

    @contextmanager
    def fail_one_normalization(self, request, **kwargs):
        if kwargs["action"] == "codeql.normalize" and not failures:
            failures.append(kwargs["action"])
            raise TimeoutError("fixture normalization admission timeout")
        with reserve(self, request, **kwargs) as lease:
            yield lease

    monkeypatch.setattr(codeql_job.ResourceAdmission, "reserve", fail_one_normalization)
    handlers = {item.unit_id: item.handler for item in codeql_job.build_job().units}
    executed = handlers["execution.scopes"](unit)
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    admissions = {event["span_id"]: event for event in events if event["event"] == "RESOURCE_ADMITTED"}
    actions = [event for event in events if event["event"] == "OPERATION_COMPLETED"
               and event["operation_id"] in {"codeql.database", "codeql.query", "codeql.normalize"}]
    assert len(actions) == 5
    assert {event["scope_id"] for event in actions} == set(by_scope)
    for action in actions:
        admitted = admissions[action["resource_lease_id"]]
        assert action["scope_id"] == admitted["scope_id"]
        assert action["query_profile"] == admitted["query_profile"]
        assert action["unit_id"] == admitted["unit_id"] == "execution.scopes"
        assert admitted["queue_delay_ms"] >= 0
    failed = [item for item in executed["scopes"] if item["terminal_status"] == "FAILED"]
    succeeded = [item for item in executed["scopes"] if item["terminal_status"] == "SUCCEEDED"]
    assert len(failed) == len(succeeded) == len(failures) == 1
    assert "index_identity" not in failed[0]
    assert succeeded[0]["observation_count"] == executed["observation_count"] == 1
    reason = "CodeQL normalize operational failure (TimeoutError)"
    assert reason in failed[0]["gaps"] and reason in executed["gaps"]
    outputs = {"execution.scopes": executed, "plan.inventory": {"upstream_manifests": []}}
    unit.output = outputs.__getitem__
    unit.unit_id = "acceptance.publish_handoff"
    if invalid_output is not None:
        if invalid_output == "success_without_index":
            failed[0]["terminal_status"] = "SUCCEEDED"
        else:
            failed[0]["gaps"] = []
        with pytest.raises(FrameworkIntegrityError, match="without an explicit failure gap"):
            handlers["acceptance.publish_handoff"](unit)
        return
    published = handlers["acceptance.publish_handoff"](unit)
    assert published["scope_count"] == 2 and published["item_count"] == 1
    assert published["terminal_status"] != "SUCCEEDED"
    assert reason in published["gaps"]
    summary = json.loads((tmp_path / published["artifact"]["path"]).read_bytes())
    statuses = {item["scope_id"]: item["terminal_status"] for item in summary["scopes"]}
    assert statuses == {failed[0]["scope"]["scope_id"]: "FAILED",
                        succeeded[0]["scope"]["scope_id"]: "SUCCEEDED"}
    manifest, _ = load_verified_manifest(tmp_path, tmp_path / published["index_manifest"]["path"],
                                        published["index_manifest"]["sha256"])
    assert [item["sha256"] for item in manifest["indexes"]] == [succeeded[0]["index"]["sha256"]]


@pytest.mark.parametrize("corrupt", [False, True])
def test_normalize_scope_rejects_conflicting_or_corrupt_shard(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corrupt: bool) -> None:
    unit, queries = _normalization_fixture(tmp_path, monkeypatch)
    first = _normalize_one(unit, queries[0])
    path = tmp_path / first["index"]["path"]
    if corrupt:
        path.write_bytes(b"corrupt")
    else:
        queries[0]["gaps"] = ["different evidence with unchanged producer identity"]
    before = path.read_bytes()
    with pytest.raises(ValueError, match="immutable index shard"):
        _normalize_one(unit, queries[0])
    assert path.read_bytes() == before


def test_normalize_changed_sarif_publishes_new_shard_and_preserves_prior(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit, queries = _normalization_fixture(tmp_path, monkeypatch)
    query = queries[0]
    first = _normalize_one(unit, query)
    prior = tmp_path / first["index"]["path"]
    before = prior.read_bytes()
    sarif_path = tmp_path / query["sarif"]["path"]
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    sarif["runs"][0]["results"][0]["message"]["text"] = "changed observation"
    sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
    query["sarif"] = {
        "path": sarif_path.name, "sha256": hashlib.sha256(sarif_path.read_bytes()).hexdigest(),
        "size_bytes": sarif_path.stat().st_size,
    }
    changed = _normalize_one(unit, query)
    assert changed["index"]["path"] != first["index"]["path"]
    assert _normalize_one(unit, query) == changed
    assert prior.read_bytes() == before


def _settings_value() -> dict[str, object]:
    lock = json.loads((ROOT / "containers/tools/codeql/assets.lock.json").read_text(encoding="utf-8"))
    modes = {"cpp": "manual", "go": "manual", "java": "manual", "csharp": "manual",
             "javascript": "none", "python": "none", "ruby": "none", "rust": "none", "actions": "none"}
    source_languages = {"cpp": ["C", "C++"], "go": ["Go"], "java": ["Java", "Kotlin"],
                        "csharp": ["C#"], "javascript": ["JavaScript", "TypeScript"],
                        "python": ["Python"], "ruby": ["Ruby"], "rust": ["Rust"],
                        "actions": ["GitHub Actions"]}
    prerequisites = {name: [] for name in modes}
    prerequisites["javascript"] = ["bundled-typescript"]
    prerequisites["rust"] = ["Cargo.toml", "Cargo.lock", "bundled-rust-indexer"]
    languages = {}
    for name, mode in modes.items():
        pack = lock["query_packs"][name]
        languages[name] = {"enabled": True, "mode": mode, "platform": "linux-x86_64",
            "extractor_tree_sha256": lock["extractors"][name]["tree_sha256"],
            "extractor_file_count": lock["extractors"][name]["file_count"],
            "query_pack": pack["name"], "query_pack_version": pack["version"],
            "query_suite": pack["suite"], "query_suite_sha256": pack["suite_sha256"],
            "query_pack_sha256": pack["qlpack_sha256"], "query_lock_sha256": pack["lock_sha256"],
            "source_languages": source_languages[name], "prerequisites": prerequisites[name],
            "additional_queries": pack.get("additional_suites", []),
            "custom_queries": lock.get("custom_query_packs", {}).get(name, [])}
    return {"enabled": True, "source_image_tag": lock["source_image"]["tag"],
        "source_image_id": lock["source_image"]["image_id"],
        "version": "2.27.0", "commit": "b47b3e59262c95aff4eeb84ac72d09e25a9c37e9",
        "cli_sha256": lock["codeql"]["cli_sha256"], "license_sha256": lock["codeql"]["license_sha256"],
        "asset_lock_sha256": "0" * 64, "runtime_user": "10001:10001",
        "retention": "run-owned", "concurrency": 4, "inventory_timeout_seconds": 300,
        "database_timeout_seconds": 1800, "query_timeout_seconds": 1800, "output_bytes": 1024,
        "database_file_limit": 200000, "database_bytes_limit": 8589934592,
        "sarif_bytes_limit": 268435456, "result_limit": 100000, "threads": 2,
        "ram_mb": 4096, "max_paths": 4, "languages": languages}


def test_typed_codeql_configuration_enforces_language_contracts() -> None:
    value = _settings_value()
    settings = parse_codeql_settings(value)
    assert settings.languages["java"].source_languages == ("Java", "Kotlin")
    assert settings.languages["rust"].mode == "source"
    assert settings.languages["ruby"].mode == "source"
    assert settings.languages["cpp"].query_suite == "codeql-suites/cpp-code-scanning.qls"
    assert [(item.query_id, item.query_suite) for item in settings.languages["cpp"].custom_queries] == [
        ("cert-cpp", "codeql-suites/cert-cpp-default.qls")]
    broken = _settings_value()
    broken["languages"]["java"]["source_languages"] = ["Java"]
    with pytest.raises(ValueError, match="Kotlin"):
        parse_codeql_settings(broken)


def test_database_and_query_checkpoint_inputs_invalidate_independently() -> None:
    settings = parse_codeql_settings(_settings_value())
    scope = build_codeql_plan(
        source_fingerprint="f" * 64, files=[source("go/main.go")],
        receipts=[receipt("go", "go", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        supported_extractors={"go"}, source_image_id=IMAGE,
    ).scopes[0]
    unit = SimpleNamespace(job=SimpleNamespace(source_fingerprint="f" * 64),
                           output=lambda _name: {"upstream_handoffs": {"job": {"sha256": "9" * 64}}})
    lock = {"sha256": "8" * 64}
    replay = {"commands": [{"argv_sha256": "7" * 64}]}
    database = _database_identity(unit, scope, image_identity="6" * 64, replay=replay,
                                  settings=settings, asset_lock=lock)
    language = settings.languages["go"]
    profile = _query_profiles(language)[0]
    query = _query_identity({"database_identity": database, "database_tree_sha256": "5" * 64},
                            profile, settings)
    changed_language = replace(language, query_suite="codeql-suites/go-security-extended.qls")
    changed_settings = replace(settings, languages=MappingProxyType(
        {**settings.languages, "go": changed_language}))
    assert _database_identity(unit, scope, image_identity="6" * 64, replay=replay,
                              settings=changed_settings, asset_lock=lock) == database
    assert _query_identity({"database_identity": database, "database_tree_sha256": "5" * 64},
                           _query_profiles(changed_language)[0], changed_settings) != query
    assert _database_identity(unit, scope, image_identity="6" * 64,
                              replay={"commands": [{"argv_sha256": "4" * 64}]},
                              settings=settings, asset_lock=lock) != database
    unrelated = SimpleNamespace(job=SimpleNamespace(source_fingerprint="0" * 64),
                                output=lambda _name: {"upstream_handoffs": {"sibling": {"sha256": "1" * 64}}})
    assert _database_identity(unrelated, scope, image_identity="6" * 64, replay=replay,
                              settings=settings, asset_lock={"sha256": "0" * 64}) == database
    extractor_changed = replace(language, extractor_tree_sha256="0" * 64)
    extractor_settings = replace(settings, languages=MappingProxyType(
        {**settings.languages, "go": extractor_changed}))
    assert _database_identity(unit, scope, image_identity="6" * 64, replay=replay,
                              settings=extractor_settings, asset_lock=lock) == database
    from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
    released = SimpleNamespace(job=SimpleNamespace(review_policy=ReviewPolicy(
        releases=ComponentReleases({"extractor_go": "updated-release"}))))
    assert _database_identity(released, scope, image_identity="6" * 64, replay=replay,
                              settings=settings, asset_lock=lock) != database
    mode_language = replace(language, mode=CodeQLExecutionMode.SOURCE)
    mode_settings = replace(settings, languages=MappingProxyType(
        {**settings.languages, "go": mode_language}))
    assert _database_identity(unit, scope, image_identity="6" * 64, replay=replay,
                              settings=mode_settings, asset_lock=lock) != database
    broken = _settings_value()
    broken["languages"]["csharp"]["source_languages"] = ["C#", "Visual Basic"]
    with pytest.raises(ValueError, match="VB"):
        parse_codeql_settings(broken)


@pytest.mark.parametrize("path,value,expected", [
    (("files", 0, "sha256"), "b" * 64, (True, True)),
    (("receipts", 0, "dependency_identity"), "b" * 64, (True, True)),
    (("receipts", 0, "recipe_identity"), "b" * 64, (True, True)),
    (("receipts", 0, "workspace_manifest", "sha256"), "b" * 64, (True, True)),
    (("receipts", 0, "image", "image_id"), "sha256:" + "b" * 64, (True, True)),
    (("replay", "commands", 0, "argv_sha256"), "b" * 64, (True, True)),
    (("replay", "environment"), {"GOFLAGS": "-tags=changed"}, (True, True)),
    (("image_identity",), "b" * 64, (True, True)),
    (("releases", "platform"), "v2", (True, True)),
    (("releases", "build_toolchain"), "v2", (True, True)),
    (("releases", "codeql"), "v2", (True, True)),
    (("releases", "codeql_runner"), "v2", (True, True)),
    (("releases", "extractor_go"), "v2", (True, True)),
    (("mode",), "first_party_managed", (True, True)),
    (("settings", "threads"), 3, (True, True)),
    (("settings", "ram_mb"), 6144, (True, True)),
    (("settings", "database_file_limit"), 100000, (True, True)),
    (("settings", "database_bytes_limit"), 4294967296, (True, True)),
    (("query_release",), "v2", (False, True)),
    (("settings", "languages", "go", "query_suite"),
     "codeql-suites/go-security-extended.qls", (False, True)),
    (("settings", "result_limit"), 50000, (False, True)),
    (("settings", "sarif_bytes_limit"), 134217728, (False, True)),
    (("settings", "max_paths"), 2, (False, True)),
    (("receipts", 0, "fingerprint"), "b" * 64, (False, False)),
    (("receipts", 0, "workspace_manifest", "path"), "new-attempt/manifest.json", (False, False)),
    (("receipts", 0, "workspace"), "new-attempt/workspace", (False, False)),
    (("receipts", 0, "invocation_id"), "new-invocation", (False, False)),
    (("receipts", 0, "timestamp"), "later", (False, False)),
    (("replay", "protected_commands"), {"path": "new-attempt/commands.json"}, (False, False)),
    (("releases", "extractor_java"), "v2", (False, False)),
    (("releases", "codeql_normalizer"), "v2", (False, False)),
    (("settings", "asset_lock_sha256"), "b" * 64, (False, False)),
    (("settings", "languages", "go", "extractor_tree_sha256"), "b" * 64, (False, False)),
])
def test_codeql_material_provenance_invalidation_matrix(tmp_path, path, value, expected):
    from copy import deepcopy
    from appsec_review.config.assurance import AssuranceMode, ComponentReleases, ReviewPolicy

    inputs = {
        "files": [source("go/main.go")],
        "receipts": [receipt("go", "go", "build-unit-aaaaaaaaaaaaaaaaaaaa")],
        "settings": _settings_value(),
        "replay": {"commands": [{"argv_sha256": "7" * 64}], "environment": {},
                   "protected_commands": {"path": "old-attempt/commands.json"}},
        "image_identity": "6" * 64, "query_release": "v1", "mode": "strict",
        "releases": {name: "v1" for name in (
            "platform", "build_toolchain", "codeql", "codeql_runner",
            "extractor_go", "extractor_java", "codeql_normalizer")},
    }

    def identities(values):
        settings = parse_codeql_settings(values["settings"])
        scope = build_codeql_plan(
            source_fingerprint="f" * 64, files=values["files"], receipts=values["receipts"],
            supported_extractors={"go"}, source_image_id=IMAGE).scopes[0]
        policy = ReviewPolicy(mode=AssuranceMode(values["mode"]), project_id="fixture",
                              approved_first_party_projects=("fixture",),
                              target_root=str(tmp_path), custody="application_private_v1",
                              releases=ComponentReleases(values["releases"]))
        unit = SimpleNamespace(job=SimpleNamespace(review_policy=policy))
        database = _database_identity(
            unit, scope, image_identity=values["image_identity"], replay=values["replay"],
            settings=settings, asset_lock={"sha256": values["settings"]["asset_lock_sha256"]})
        query = _query_identity(
            {"database_identity": database, "database_tree_sha256": "5" * 64},
            _query_profiles(settings.languages["go"])[0], settings,
            query_release=values["query_release"])
        return database, query

    baseline = identities(inputs)
    changed = deepcopy(inputs)
    container = changed
    for component in path[:-1]:
        container = container[component]
    container[path[-1]] = value
    assert tuple(left != right for left, right in zip(baseline, identities(changed))) == expected


def test_cpp_default_and_custom_queries_have_independent_identities() -> None:
    settings = parse_codeql_settings(_settings_value())
    language = settings.languages["cpp"]
    profiles = _query_profiles(language)
    assert [(item["query_id"], item["kind"]) for item in profiles] == [
        ("default", "default"), ("security-extended", "pack"), ("cert-cpp", "custom")]
    database = {"database_identity": "1" * 64, "database_tree_sha256": "2" * 64}
    identities = [_query_identity(database, profile, settings) for profile in profiles]
    assert len(set(identities)) == 3

    changed_custom = replace(language.custom_queries[0], query_suite_sha256="3" * 64)
    changed_language = replace(language, custom_queries=(changed_custom,))
    changed_settings = replace(settings, languages=MappingProxyType(
        {**settings.languages, "cpp": changed_language}))
    changed_profiles = _query_profiles(changed_language)
    assert _query_identity(database, changed_profiles[0], changed_settings) == identities[0]
    assert _query_identity(database, changed_profiles[-1], changed_settings) == identities[-1]
    assert _query_identity(database, changed_profiles[-1], changed_settings,
                           query_release="updated-release") != identities[-1]


def test_runner_has_no_supplied_tree_fingerprinter(tmp_path: Path) -> None:
    runner_path = ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py"
    spec = importlib.util.spec_from_file_location("appsec_review_codeql_runner", runner_path)
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    (tmp_path / "a").mkdir()
    (tmp_path / "a.b").write_text("dot", encoding="utf-8")
    (tmp_path / "a" / "Z").write_text("nested", encoding="utf-8")
    assert not hasattr(runner, "_tree")
    assert runner._canonical(["build", "--flag"]) == canonical_json(["build", "--flag"])
    assert runner._working_directory(tmp_path, ".") == tmp_path


def test_csharp_default_and_extended_pack_queries_have_independent_identities() -> None:
    settings = parse_codeql_settings(_settings_value())
    language = settings.languages["csharp"]
    profiles = _query_profiles(language)
    assert [(item["query_id"], item["kind"]) for item in profiles] == [
        ("default", "default"), ("security-extended", "pack")]
    database = {"database_identity": "1" * 64, "database_tree_sha256": "2" * 64}
    assert len({_query_identity(database, profile, settings) for profile in profiles}) == 2


def test_rust_default_and_extended_pack_queries_have_independent_identities() -> None:
    settings = parse_codeql_settings(_settings_value())
    language = settings.languages["rust"]
    profiles = _query_profiles(language)
    assert [(item["query_id"], item["kind"]) for item in profiles] == [
        ("default", "default"), ("security-extended", "pack")]
    database = {"database_identity": "1" * 64, "database_tree_sha256": "2" * 64}
    assert len({_query_identity(database, profile, settings) for profile in profiles}) == 2


def test_derived_image_dockerfile_declares_both_global_build_arguments() -> None:
    lines = (ROOT / "containers" / "tools" / "codeql" / "Dockerfile").read_text(
        encoding="utf-8").splitlines()

    assert lines[:3] == ["ARG CODEQL_SOURCE_IMAGE", "ARG BUILD_IMAGE",
                         "FROM ${CODEQL_SOURCE_IMAGE} AS codeql_source"]


@pytest.mark.parametrize("dockerfile", ["Dockerfile", "Dockerfile.source"])
def test_codeql_image_opens_precompiled_assets_before_switching_user(
        tmp_path: Path, dockerfile: str) -> None:
    text = (ROOT / "containers/tools/codeql" / dockerfile).read_text()
    command = "chmod -R a+rX /opt/codeql"
    assert command in text
    assert text.index("USER 0:0") < text.index(command) < text.index("USER ${RUNTIME_USER}")
    if dockerfile == "Dockerfile":
        assert text.index("COPY --from=codeql_source /opt/codeql /opt/codeql") < text.index(command)
    if os.name != "posix":
        pytest.skip("POSIX permission semantics required")

    payload = tmp_path / "codeql"
    precompiled = payload / "qlpacks" / ".codeql" / "precompiled"
    precompiled.mkdir(parents=True)
    artifact = precompiled / "shared.bytes.qlx"
    artifact.write_bytes(b"precompiled-query")
    artifact.chmod(0o600)
    executable = payload / "codeql"
    executable.write_bytes(b"executable")
    executable.chmod(0o700)
    for directory in (payload, *precompiled.parents):
        if directory == tmp_path:
            break
        directory.chmod(0o700)
    precompiled.chmod(0o700)

    argv = shlex.split(command)
    subprocess.run([*argv[:-1], str(payload)], check=True)
    assert artifact.read_bytes() == b"precompiled-query"
    assert artifact.stat().st_mode & 0o777 == 0o644
    assert executable.stat().st_mode & 0o777 == 0o755
    assert all(path.stat().st_mode & 0o777 == 0o755
               for path in (payload, payload / "qlpacks", precompiled.parent, precompiled))


def test_derived_image_build_holds_the_global_docker_build_lock(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_id = "sha256:" + "1" * 64
    derived_id = "sha256:" + "2" * 64
    settings = SimpleNamespace(source_image_tag="codeql-source:test", source_image_id=source_id)
    held: set[Path] = set()
    observed: set[Path] = set()

    @contextmanager
    def fake_lock(path: Path, timeout_seconds: int):
        assert timeout_seconds == 30
        held.add(path)
        observed.add(path)
        try:
            yield
        finally:
            held.remove(path)

    def runner(argv: tuple[str, ...], _timeout: int):
        if argv[:3] == ("docker", "image", "inspect"):
            reference = argv[3]
            value = derived_id if reference.startswith("appsec-review-codeql:") else source_id
            return 0, (value + "\n").encode(), b"", False
        if argv[:3] == ("docker", "image", "tag"):
            return 0, b"", b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            assert tmp_path / "metadata" / "codeql-images" / "docker-build.lock" in held
            assert any(path.name == "build.lock" for path in held)
            return 0, b"built", b"", False
        raise AssertionError(argv)

    monkeypatch.setattr("appsec_review.codeql.runtime.bounded_file_lock", fake_lock)
    resolver = CodeQLImageResolver(repository_root=ROOT, metadata_root=tmp_path / "metadata",
                                   settings=settings, timeout_seconds=30, runner=runner)
    image, _stdout, _stderr = resolver.resolve(
        build_image_tag=settings.source_image_tag, build_image_id=source_id,
        runtime_user="10001:10001")
    assert image.image_id == derived_id
    assert not held
    assert tmp_path / "metadata" / "codeql-images" / "docker-build.lock" in observed
    assert any(path.name == "build.lock" for path in observed)


def test_concurrent_derived_image_resolution_waits_and_reuses(
        tmp_path: Path) -> None:
    from appsec_review.config.assurance import ComponentReleases
    source_id = "sha256:" + "1" * 64
    derived_id = "sha256:" + "2" * 64
    settings = SimpleNamespace(source_image_tag="codeql-source:test", source_image_id=source_id)
    guard = threading.Lock()
    built = False
    build_count = 0

    def runner(argv: tuple[str, ...], _timeout: int):
        nonlocal built, build_count
        if argv[:3] == ("docker", "image", "inspect"):
            reference = argv[3]
            with guard:
                value = derived_id if reference.startswith("appsec-review-codeql:") and built else source_id
                exists = not reference.startswith("appsec-review-codeql:") or built
            return ((0, (value + "\n").encode(), b"", False) if exists else
                    (1, b"", b"", False))
        if argv[:3] == ("docker", "image", "tag"):
            return 0, b"", b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            with guard:
                build_count += 1
            time.sleep(0.05)
            with guard:
                built = True
            return 0, b"built", b"", False
        raise AssertionError(argv)

    resolver = CodeQLImageResolver(repository_root=ROOT, metadata_root=tmp_path / "metadata",
                                   settings=settings, timeout_seconds=30, runner=runner,
                                   releases=ComponentReleases({"codeql": "fixture/1",
                                                               "codeql_runner": "fixture/1"}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        images = list(pool.map(lambda _ordinal: resolver.resolve(
            build_image_tag=settings.source_image_tag, build_image_id=source_id,
            runtime_user="10001:10001")[0], (1, 2)))

    assert build_count == 1
    assert sorted(image.reused for image in images) == [False, True]


def test_bounded_logs_retain_head_tail_and_total_size(tmp_path: Path) -> None:
    path = tmp_path / "stream.bin"
    digest, total, truncated, tail = _bounded_stream(path, b"0123456789", 6)
    assert path.read_bytes() == b"012789"
    assert total == 10 and truncated and tail == 3 and len(digest) == 64


def test_database_tree_manifest_detects_changes(tmp_path: Path) -> None:
    database = tmp_path / "db"
    database.mkdir()
    (database / "a").write_text("one", encoding="utf-8")
    before = tree_manifest(database, file_limit=10, bytes_limit=100)
    (database / "a").write_text("two", encoding="utf-8")
    after = tree_manifest(database, file_limit=10, bytes_limit=100)
    assert before["tree_sha256"] != after["tree_sha256"]


def test_codeql_execution_leaves_nothing_in_the_scope_world_writable_even_when_the_runner_opens_it(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    sibling = scratch / "export" / "staged"
    sibling.mkdir(parents=True)
    sibling.chmod(0o777)

    def runner(argv, _timeout):
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, (IMAGE + "\n").encode(), b"", False
        if "/opt/appsec/codeql_runner.py" in argv:
            exported = scratch / "database-export" / "db-cpp"
            exported.mkdir(parents=True)
            exported.chmod(0o777)
            (exported / "data.bin").write_bytes(b"x")
            (exported / "data.bin").chmod(0o666)
        return 0, b"ok", b"", False

    image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, IMAGE, IMAGE,
                        "build:local", IMAGE, "codeql:local", "10001:10001",
                        "b" * 64, "c" * 64, False, "manifest.json")
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024)
    CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
        "database", ("--language", "cpp", "--database", "database"), scratch_root=scratch)

    opened = [str(path.relative_to(scratch)) for path in [scratch, *scratch.rglob("*")]
              if not path.is_symlink() and path.stat().st_mode & 0o002]
    assert opened == []
    assert (scratch / "database" / "db-cpp" / "data.bin").is_file()
