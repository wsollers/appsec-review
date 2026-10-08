from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from appsec_review.config import CppCompiledAnalysisSettings, load_config
from appsec_review.jobs.job_cpp_compiled_analysis.codeql import (
    CodeQLImageResolver, database_identity, load_sarif, query_identity, tree_manifest,
    validate_assets,
)
from appsec_review.jobs.job_cpp_compiled_analysis.job import (
    _make_codeql_directories_writable, _sarif_target_path, _stage_codeql_workspace,
)


ROOT = Path(__file__).parents[1]
SOURCE_ID = "sha256:13b904d24be951043e641cd6125d4c1eb1f750040a61d005c00a94a0dee4f1b3"
BUILD_ID = "sha256:" + "b" * 64
DERIVED_ID = "sha256:" + "d" * 64


def _settings():
    typed = load_config(ROOT / "appsec-review.toml").job("job_cpp_compiled_analysis").typed_settings
    assert isinstance(typed, CppCompiledAnalysisSettings)
    return typed.codeql


def test_codeql_configuration_is_enabled_typed_and_asset_locked() -> None:
    settings = _settings()
    lock = validate_assets(ROOT, settings)
    assert settings.enabled is True
    assert settings.source_image_id == SOURCE_ID
    assert lock["query_pack"]["suite"] == "codeql-suites/cpp-security-and-quality.qls"


def test_query_changes_invalidate_query_without_invalidating_database() -> None:
    settings = _settings()
    replay = {"recipe_identity": "recipe", "build_image_id": BUILD_ID,
              "dependency_hashes": {"CMakeLists.txt": "a" * 64},
              "protected_commands": [{"sha256": "c" * 64}]}
    first_database = database_identity(settings, target_snapshot="target", case_snapshot="case",
                                       replay=replay, image_identity="image")
    changed = replace(settings, query_suite="codeql-suites/cpp-code-scanning.qls")
    assert database_identity(changed, target_snapshot="target", case_snapshot="case",
                             replay=replay, image_identity="image") == first_database
    assert query_identity(settings, database_tree_sha256="e" * 64, image_id=DERIVED_ID) != query_identity(
        changed, database_tree_sha256="e" * 64, image_id=DERIVED_ID)


def test_derived_image_binds_source_and_accepted_build_image(tmp_path: Path) -> None:
    built = False
    calls: list[tuple[str, ...]] = []
    settings = _settings()

    def runner(argv, _timeout):
        nonlocal built
        command = tuple(argv)
        calls.append(command)
        if command[:3] == ("docker", "image", "inspect"):
            reference = command[3]
            identities = {"audit-codeql:local": SOURCE_ID, "accepted:local": BUILD_ID}
            if reference.startswith("appsec-review-codeql-cpp:") and built:
                return 0, (DERIVED_ID + "\n").encode(), b"", False
            value = identities.get(reference)
            return ((0, (value + "\n").encode(), b"", False) if value else
                    (1, b"", b"missing", False))
        if command[:3] == ("docker", "image", "tag"):
            return 0, b"", b"", False
        if command[:2] == ("docker", "run"):
            paths = command[command.index(SOURCE_ID) + 1:]
            digests = {
                "/opt/codeql/codeql": settings.cli_sha256,
                "/opt/codeql/cpp/tools/linux64/extractor": settings.extractor_sha256,
                "/opt/codeql/LICENSE.md": settings.license_sha256,
                f"/opt/codeql/qlpacks/codeql/cpp-queries/{settings.query_pack_version}/qlpack.yml":
                    settings.query_pack_sha256,
                f"/opt/codeql/qlpacks/codeql/cpp-queries/{settings.query_pack_version}/codeql-pack.lock.yml":
                    settings.query_lock_sha256,
                f"/opt/codeql/qlpacks/codeql/cpp-queries/{settings.query_pack_version}/{settings.query_suite}":
                    settings.query_suite_sha256,
            }
            return 0, "".join(f"{digests[path]}  {path}\n" for path in paths).encode(), b"", False
        if command[:3] == ("docker", "buildx", "build"):
            built = True
            return 0, b"built", b"", False
        raise AssertionError(command)

    resolver = CodeQLImageResolver(repository_root=ROOT, metadata_root=tmp_path,
                                    settings=settings, runner=runner)
    image, _, _ = resolver.resolve(build_image_tag="accepted:local", build_image_id=BUILD_ID,
                                   runtime_user="10001:10001")
    assert image.source_image_id == SOURCE_ID
    assert image.build_image_id == BUILD_ID
    assert image.image_id == DERIVED_ID
    build = next(command for command in calls if command[:3] == ("docker", "buildx", "build"))
    assert "--network" in build and build[build.index("--network") + 1] == "none"
    assert f"RUNTIME_USER=10001:10001" in build


def test_database_manifest_and_sarif_are_bounded(tmp_path: Path) -> None:
    database = tmp_path / "database"
    database.mkdir()
    (database / "a").write_bytes(b"one")
    (database / "b").write_bytes(b"two")
    manifest = tree_manifest(database, file_limit=2, bytes_limit=6)
    assert manifest["file_count"] == 2 and manifest["size_bytes"] == 6
    with pytest.raises(ValueError, match="file count"):
        tree_manifest(database, file_limit=1, bytes_limit=6)

    sarif = tmp_path / "result.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": [{"ruleId": "x"}]}]}),
                     encoding="utf-8")
    assert load_sarif(sarif, bytes_limit=1024, result_limit=1)["runs"][0]["results"][0]["ruleId"] == "x"
    with pytest.raises(ValueError, match="result count"):
        load_sarif(sarif, bytes_limit=1024, result_limit=0)


def test_sarif_paths_resolve_only_to_accepted_source_mapping() -> None:
    mapping = {"root": "projects/native/sample", "files": [
        {"target_path": "projects/native/sample/src/main.cpp"},
        {"target_path": "projects/native/sample/src/helper.cpp"},
    ]}
    assert _sarif_target_path("projects/native/sample/src/main.cpp", mapping) == (
        "projects/native/sample/src/main.cpp")
    assert _sarif_target_path("file:///scratch/workspace/projects/native/sample/src/helper.cpp", mapping) == (
        "projects/native/sample/src/helper.cpp")
    assert _sarif_target_path("../../outside.cpp", mapping) is None


def test_staged_workspace_directories_are_writable_by_the_analysis_user(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "projects" / "native" / "sample" / "CMakeLists.txt"
    source.parent.mkdir(parents=True)
    source.write_text("project(sample)\n", encoding="utf-8")
    catalog = {"mapping": {"files": [{
        "target_path": "projects/native/sample/CMakeLists.txt",
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }]}}
    root = tmp_path / "scratch"
    root.mkdir()
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))

    _stage_codeql_workspace(unit, catalog, root)

    project = root / "workspace" / "projects" / "native" / "sample"
    assert (project / "CMakeLists.txt").read_bytes() == source.read_bytes()
    for directory in (root / "workspace", project):
        assert stat.S_IMODE(directory.stat().st_mode) & 0o222 == 0o222

    query_database = root / "query-database"
    query_log = query_database / "log"
    query_log.mkdir(parents=True)
    cache_lock = query_database / "cache.lock"
    cache_lock.write_text("locked", encoding="utf-8")
    cache_lock.chmod(0o444)
    _make_codeql_directories_writable(query_database, writable_files=True)
    for directory in (query_database, query_log):
        assert stat.S_IMODE(directory.stat().st_mode) & 0o222 == 0o222
    assert stat.S_IMODE(cache_lock.stat().st_mode) & 0o222 == 0o222
