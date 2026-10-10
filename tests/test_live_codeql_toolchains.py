from __future__ import annotations

from collections.abc import Callable
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.codeql.runtime import (
    CodeQLExecutor,
    CodeQLImage,
    CodeQLImageResolver,
    load_sarif,
    tree_manifest,
)
from appsec_review.config import load_config
from appsec_review.container_runtime import profiles_from_settings
from appsec_review.jobs.job_codeql_analysis.sarif import normalize_sarif
from appsec_review.jobs.job_codeql_analysis.job import _accepted_replay
from appsec_review.storage import atomic_json, canonical_json, file_sha256


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "build_toolchains"


def _image_available(reference: str) -> bool:
    try:
        return subprocess.run(
            ["docker", "image", "inspect", reference], capture_output=True,
            timeout=30, check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@pytest.fixture(scope="module")
def live_codeql_runtime(tmp_path_factory: pytest.TempPathFactory):
    config = load_config(ROOT / "appsec-review.toml")
    settings = config.job("job_codeql_analysis").typed_settings
    assert settings is not None
    if not _image_available(settings.source_image_tag):
        pytest.skip("licensed pinned CodeQL image is not locally available")
    profiles = profiles_from_settings(config.job("job_project_build").settings["profiles"])
    root = tmp_path_factory.mktemp("live-codeql")
    run_root = root / "run"
    metadata_root = root / "metadata"
    run_root.mkdir()
    resolver = CodeQLImageResolver(repository_root=ROOT, metadata_root=metadata_root,
                                   settings=settings, timeout_seconds=1800)
    images: dict[str, CodeQLImage] = {}

    def image_for(profile_name: str) -> CodeQLImage:
        if profile_name == "source":
            tag, image_id = settings.source_image_tag, settings.source_image_id
        else:
            profile = profiles[profile_name]
            tag, image_id = profile.tag, profile.image_id
        if profile_name not in images:
            images[profile_name] = resolver.resolve(
                build_image_tag=tag, build_image_id=image_id,
                runtime_user=settings.runtime_user,
            )[0]
        return images[profile_name]

    return settings, run_root, image_for


def _write_replay(path: Path, run_root: Path, build_image_id: str,
                  commands: tuple[tuple[str, tuple[str, ...], dict[str, str]], ...]) -> None:
    rows, configure, build = [], [], []
    protected = path.parent / "accepted-build-commands"
    protected.mkdir(parents=True, exist_ok=True)
    for ordinal, (working_directory, argv, environment) in enumerate(commands, 1):
        role = "configure" if len(commands) > 1 and ordinal == 1 else "build"
        (configure if role == "configure" else build).append(list(argv))
        command_path = protected / f"command-{ordinal:03d}.json"
        atomic_json(command_path, {"schema": "appsec-review/protected-build-command/2",
                                  "argv": list(argv), "working_directory": working_directory,
                                  "environment": environment, "access": "run-owned-protected"})
        argv_sha256 = hashlib.sha256(canonical_json(list(argv))).hexdigest()
        rows.append({
            "ordinal": ordinal, "role": role, "argv_sha256": argv_sha256,
            "working_directory": working_directory, "image_id": build_image_id,
            "protected_argv": {"path": command_path.relative_to(run_root).as_posix(),
                               "sha256": file_sha256(command_path)},
        })
    receipt = {"schema": "appsec-review/language-build-receipt/1", "terminal_status": "SUCCEEDED",
               "recipe_identity": "1" * 64,
               "recipe": {"configure_commands": configure, "build_commands": build},
               "image": {"image_id": build_image_id, "dependency_hashes": {}},
               "commands": rows}
    replay = _accepted_replay(SimpleNamespace(job=SimpleNamespace(run_root=run_root)), receipt)
    assert [tuple(item["argv"]) for item in replay["commands"]] == [item[1] for item in commands]
    atomic_json(path, replay)


LIVE_SCOPES = (
    ("cpp", "native", "manual", "native", (
        ("native", ("cmake", "-S", ".", "-B", "codeql-build"), {}),
        ("native", ("cmake", "--build", "codeql-build"), {}),
    )),
    ("go", "go", "manual", "go", (
        ("go", ("go", "build", "-o", "codeql-app", "."),
         {"GOCACHE": "/tmp/go-cache", "GOMODCACHE": "/tmp/go-mod"}),
    )),
    ("java", "java", "manual", "java", (
        ("java", ("mvn", "-Dmaven.repo.local=/tmp/m2", "-DskipTests", "package"), {}),
    )),
    ("csharp", "dotnet", "manual", ".", (
        (".", ("dotnet", "restore", "appsec-fixture.csproj"),
         {"DOTNET_CLI_HOME": "/tmp/dotnet", "NUGET_PACKAGES": "/scratch/workspace/.nuget/packages"}),
        (".", ("dotnet", "build", "appsec-fixture.csproj", "--no-restore"),
         {"DOTNET_CLI_HOME": "/tmp/dotnet", "NUGET_PACKAGES": "/scratch/workspace/.nuget/packages"}),
    )),
    ("javascript", "source", "none", "typescript", ()),
    ("python", "source", "none", "python", ()),
    ("rust", "rust", "none", "rust", ()),
    ("actions", "source", "none", ".", ()),
)


def test_live_codeql_inventory_matches_the_pinned_extractors_and_query_packs(
        live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    scratch = run_root / "inventory"
    scratch.mkdir(parents=True)
    shutil.copyfile(ROOT / "containers/tools/codeql/assets.lock.json", scratch / "assets.lock.json")
    execution = CodeQLExecutor(image=image_for("source"), run_root=run_root, settings=settings).execute(
        "inventory", ("--output", "inventory.json", "--asset-lock", "assets.lock.json"),
        scratch_root=scratch,
    )
    assert not execution.timed_out and execution.exit_code == 0
    inventory = json.loads((scratch / "inventory.json").read_text(encoding="utf-8"))
    assert set(settings.languages) <= set(inventory["extractors"])
    assert set(inventory["query_packs"]) == set(settings.languages)
    assert inventory["custom_query_packs"]["cpp"][0]["query_id"] == "cert-cpp"


@pytest.mark.parametrize(
    ("language", "profile", "mode", "source_subroot", "commands"),
    LIVE_SCOPES, ids=[value[0] for value in LIVE_SCOPES],
)
def test_live_codeql_database_default_and_applicable_extended_queries(
        live_codeql_runtime, language: str, profile: str, mode: str,
        source_subroot: str,
        commands: tuple[tuple[str, tuple[str, ...], dict[str, str]], ...]) -> None:
    settings, run_root, image_for = live_codeql_runtime
    scratch = run_root / f"scope-{language}"
    workspace = scratch / "workspace"
    shutil.copytree(FIXTURE / "dotnet" if language == "csharp" else FIXTURE, workspace)
    database_arguments = [
        "--mode", mode, "--language", language, "--workspace", "workspace",
        "--source-subroot", source_subroot, "--database", "database",
        "--threads", str(settings.threads), "--ram", str(settings.ram_mb),
    ]
    if commands:
        codeql_image = image_for(profile)
        _write_replay(scratch / "replay.json", run_root, codeql_image.build_image_id, commands)
        database_arguments[4:4] = ["--replay", "replay.json"]
    else:
        codeql_image = image_for(profile)
    executor = CodeQLExecutor(image=codeql_image, run_root=run_root, settings=settings)
    database = executor.execute("database", tuple(database_arguments), scratch_root=scratch)
    database_detail = (run_root / database.stderr_path).read_text(encoding="utf-8", errors="replace")
    assert not database.timed_out and database.exit_code == 0, database_detail[-12000:]
    manifest = tree_manifest(scratch / "database", file_limit=settings.database_file_limit,
                             bytes_limit=settings.database_bytes_limit)
    assert manifest["file_count"] > 0 and manifest["tree_sha256"]

    source_files = [{"path": path.relative_to(workspace).as_posix(),
                     "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
                    for path in workspace.rglob("*") if path.is_file() and
                    path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs"}]

    def assert_observation_identity(sarif_value, relative: str, query_id: str) -> None:
        sarif_path = scratch / relative
        query_identity = file_sha256(sarif_path)
        records, gaps = normalize_sarif(
            sarif_value, files=source_files, root=source_subroot,
            query_identity=query_identity, result_limit=settings.result_limit)
        observation_path = sarif_path.with_suffix(".observations.json")
        atomic_json(observation_path, {"query_identity": query_identity, "query_id": query_id,
                                      "observations": records, "gaps": gaps})
        digest = file_sha256(observation_path)
        assert len(digest) == 64 and file_sha256(sarif_path) == query_identity

    configured = settings.languages[language]
    output = "queries/default.sarif"
    query = executor.execute("query", (
        "--database", "database", "--output", output,
        "--pack", configured.query_pack, "--pack-version", configured.query_pack_version,
        "--suite", configured.query_suite, "--threads", str(settings.threads),
        "--ram", str(settings.ram_mb), "--max-paths", str(settings.max_paths),
    ), scratch_root=scratch)
    query_detail = (run_root / query.stderr_path).read_text(encoding="utf-8", errors="replace")
    assert not query.timed_out and query.exit_code == 0, query_detail[-12000:]
    sarif = load_sarif(scratch / output, bytes_limit=settings.sarif_bytes_limit,
                       result_limit=settings.result_limit)
    assert sarif["version"] == "2.1.0" and sarif["runs"]
    assert_observation_identity(sarif, output, "default")
    if language == "csharp":
        assert sum(len(run.get("results", ())) for run in sarif["runs"]) > 0
    if language == "rust":
        notifications = [
            str(item.get("message", {}).get("text", ""))
            for run in sarif["runs"]
            for invocation in run.get("invocations", ())
            for item in invocation.get("toolExecutionNotifications", ())
        ]
        assert "File successfully extracted." in notifications
        assert not any("semantic analyzer unavailable" in item for item in notifications)

    for additional in configured.additional_queries:
        additional_output = f"queries/{additional.query_id}.sarif"
        extended = executor.execute("query", (
            "--database", "database", "--output", additional_output,
            "--pack", configured.query_pack, "--pack-version", configured.query_pack_version,
            "--suite", additional.query_suite, "--threads", str(settings.threads),
            "--ram", str(settings.ram_mb), "--max-paths", str(settings.max_paths),
        ), scratch_root=scratch)
        extended_detail = (run_root / extended.stderr_path).read_text(
            encoding="utf-8", errors="replace")
        assert not extended.timed_out and extended.exit_code == 0, extended_detail[-12000:]
        additional_sarif = load_sarif(
            scratch / additional_output, bytes_limit=settings.sarif_bytes_limit,
            result_limit=settings.result_limit)
        assert additional_sarif["version"] == "2.1.0" and additional_sarif["runs"]
        assert_observation_identity(additional_sarif, additional_output, additional.query_id)
        if language == "csharp":
            assert sum(len(run.get("results", ())) for run in additional_sarif["runs"]) > 0

    if language == "cpp":
        custom = configured.custom_queries[0]
        custom_output = "queries/cert-cpp.sarif"
        extended = executor.execute("query", (
            "--database", "database", "--output", custom_output,
            "--suite-path", f"{custom.root}/{custom.query_suite}",
            "--threads", str(settings.threads), "--ram", str(settings.ram_mb),
            "--max-paths", str(settings.max_paths),
        ), scratch_root=scratch)
        extended_detail = (run_root / extended.stderr_path).read_text(encoding="utf-8", errors="replace")
        assert not extended.timed_out and extended.exit_code == 0, extended_detail[-12000:]
        custom_sarif = load_sarif(scratch / custom_output, bytes_limit=settings.sarif_bytes_limit,
                                  result_limit=settings.result_limit)
        assert custom_sarif["version"] == "2.1.0" and custom_sarif["runs"]
        assert_observation_identity(custom_sarif, custom_output, custom.query_id)

    # Dagster removes per-profile database copies immediately after query completion. Prove the
    # non-root container's recursively created cache directories are removable by the run owner.
    shutil.rmtree(scratch / "database")
