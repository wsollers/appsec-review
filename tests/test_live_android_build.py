from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from appsec_review.codeql.runtime import CodeQLExecutor, CodeQLImageResolver, load_sarif
from appsec_review.config import load_config
from appsec_review.container_runtime import (
    BuildContainerExecutor, CaptureScope, profiles_from_settings, verify_capture_record,
)
from appsec_review.storage import atomic_json, canonical_json


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "targets" / "appsec-multi-vuln" / "projects" / "android" / "case-092"


def _android_profile():
    config = load_config(ROOT / "appsec-review.toml")
    profile = profiles_from_settings(
        config.job("job_project_build").settings["profiles"])["android"]
    inspected = subprocess.run(
        ["docker", "image", "inspect", profile.tag, "--format", "{{.Id}}"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if inspected.returncode != 0:
        pytest.skip(f"live Android build image is unavailable: {profile.tag}")
    assert inspected.stdout.strip() == profile.image_id
    return config, profile


def test_live_android_fixture_build_has_complete_capture_and_valid_apk(tmp_path: Path) -> None:
    if not FIXTURE.is_dir():
        pytest.skip("case-092 Android fixture is unavailable")
    config, profile = _android_profile()
    capture_config = config.job("job_project_build").build_capture
    assert capture_config is not None and capture_config.backend == "ptrace"
    workspace = tmp_path / "workspace"
    shutil.copytree(FIXTURE, workspace)
    capture_directory = workspace / ".capture" / "assemble-debug"
    scope = CaptureScope(
        "live-android-capture", "job_project_build", "attempt_0001",
        "build-unit-android-case-092", "java")
    executor = BuildContainerExecutor(
        profile, timeout_seconds=900, output_bytes=16 * 1024 * 1024)
    executor.resolve()
    result = executor.execute_captured(
        ("gradle", "--no-daemon", ":app:assembleDebug"),
        workspace=workspace, working_directory=".", environment={},
        capture_directory=capture_directory, capture_config=capture_config, scope=scope)
    detail = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")[-16000:]
    assert not result.timed_out and result.exit_code == 0, detail
    assert result.capture_record is not None
    verified = verify_capture_record(result.capture_record, run_root=tmp_path, scope=scope)
    assert verified.gaps == ()
    assert verified.document["coverage"]["complete"] is True
    assert verified.document["events"]["counts"]["process_exec"] > 0
    assert verified.document["events"]["counts"]["file_open"] > 0
    assert verified.document["tool_calls"]["retained"] > 0
    assert result.stdout_file is not None and result.stderr_file is not None
    assert result.stdout_file.stat().st_size == verified.document["streams"]["stdout"]["bytes"]
    assert result.stderr_file.stat().st_size == verified.document["streams"]["stderr"]["bytes"]
    executables = {
        str(event.get("executable", "")) for event in verified.events()
        if event.get("kind") == "process_exec"
    }
    assert any(path.endswith("/java") for path in executables)
    assert any(path.endswith("/javac") for path in executables)
    assert any(path.endswith("/aapt2") for path in executables)

    apk = workspace / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
    assert apk.is_file() and apk.stat().st_size > 0
    with zipfile.ZipFile(apk) as archive:
        assert archive.testzip() is None
        assert {"AndroidManifest.xml", "resources.arsc"} <= set(archive.namelist())
    record = json.loads(result.capture_record.read_text(encoding="utf-8"))
    assert record["secret_scan"]["findings"]["count"] == 0

    codeql_settings = config.job("job_codeql_analysis").typed_settings
    assert codeql_settings is not None
    resolver = CodeQLImageResolver(
        repository_root=ROOT, metadata_root=tmp_path / "metadata", settings=codeql_settings,
        timeout_seconds=codeql_settings.database_timeout_seconds,
        output_bytes=codeql_settings.output_bytes)
    codeql_image, _stdout, _stderr = resolver.resolve(
        build_image_tag=profile.tag, build_image_id=profile.image_id,
        runtime_user=profile.user)
    codeql_root = tmp_path / "codeql"
    shutil.copytree(FIXTURE, codeql_root / "workspace")
    command = ["gradle", "--no-daemon", ":app:assembleDebug"]
    atomic_json(codeql_root / "protected-replay.json", {
        "schema": "appsec-review/codeql-build-replay/1",
        "commands": [{
            "ordinal": 1, "argv": command,
            "argv_sha256": hashlib.sha256(canonical_json(command)).hexdigest(),
            "working_directory": ".", "environment": {}, "role": "build",
        }],
    })
    codeql = CodeQLExecutor(
        image=codeql_image, run_root=tmp_path, settings=codeql_settings)
    database = codeql.execute("database", (
        "--mode", "manual", "--language", "java", "--replay", "protected-replay.json",
        "--workspace", "workspace", "--source-subroot", ".", "--database", "database",
        "--threads", str(codeql_settings.threads), "--ram", str(codeql_settings.ram_mb),
    ), scratch_root=codeql_root)
    assert not database.timed_out and database.exit_code == 0, (
        (tmp_path / database.stderr_path).read_text(encoding="utf-8", errors="replace"))
    java = codeql_settings.languages["java"]
    query = codeql.execute("query", (
        "--database", "database", "--output", "default.sarif",
        "--pack", java.query_pack, "--pack-version", java.query_pack_version,
        "--suite", java.query_suite,
        "--threads", str(codeql_settings.threads), "--ram", str(codeql_settings.ram_mb),
        "--max-paths", str(codeql_settings.max_paths),
    ), scratch_root=codeql_root)
    assert not query.timed_out and query.exit_code == 0, (
        (tmp_path / query.stderr_path).read_text(encoding="utf-8", errors="replace"))
    sarif = load_sarif(codeql_root / "default.sarif",
                       bytes_limit=codeql_settings.sarif_bytes_limit,
                       result_limit=codeql_settings.result_limit)
    assert sarif["runs"]
