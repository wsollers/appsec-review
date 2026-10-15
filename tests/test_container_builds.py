from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import threading
import time
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / "containers" / "build.py"
SPEC = importlib.util.spec_from_file_location("container_build", BUILD_PATH)
assert SPEC and SPEC.loader
container_build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(container_build)


def _usable_bash() -> bool:
    executable = shutil.which("bash")
    if not executable:
        return False
    probe = subprocess.run([executable, "-lc", "exit 0"], capture_output=True, timeout=10)
    return probe.returncode == 0


def test_catalog_accounts_for_every_audited_image() -> None:
    catalog = container_build.load_catalog()
    assert container_build.validate(catalog) == []
    audited = [item for item in catalog["images"] if "legacy_class" in item]
    assert len(audited) == 42
    assert {item["state"] for item in audited} <= {"enabled", "deferred", "replaced", "retired"}


def test_catalog_validation_rejects_tool_runtime_policy_drift(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    relative = Path("containers/tools/clang-static-analysis/tool.toml")
    source = ROOT / relative
    drifted = tmp_path / "tool.toml"
    drifted.write_text(source.read_text(encoding="utf-8").replace(
        'memory = "1g"', 'memory = "2g"'), encoding="utf-8")
    original_safe_path = container_build.safe_path

    def safe_path(value):
        return drifted if Path(value) == relative else original_safe_path(value)

    monkeypatch.setattr(container_build, "safe_path", safe_path)
    assert "tool-clang-static-analysis: memory does not match central runtime policy" in (
        container_build.validate(catalog))


def test_container_docs_track_current_enabled_inventory() -> None:
    catalog = container_build.load_catalog()
    enabled = [item for item in catalog["images"] if item["state"] == "enabled"]
    counts = {kind: sum(item.get("kind") == kind for item in enabled)
              for kind in ("tool", "base", "buildenv")}
    readme = " ".join((ROOT / "containers" / "README.md").read_text(encoding="utf-8").split())
    migration = " ".join((ROOT / "docs" / "reviews" / "container-migration.md")
                         .read_text(encoding="utf-8").split())
    assert f"contains {len(enabled)} images: {counts['tool']} tool images" in readme
    assert f"{counts['tool']} enabled tool images plus {counts['base']} bases" in migration
    assert counts == {"tool": 30, "base": 4, "buildenv": 8}


def test_dependency_order_puts_base_before_tool() -> None:
    catalog = container_build.load_catalog()
    order = container_build.dependency_order(["tool-gitleaks"], catalog)
    assert order == ["base-ubuntu", "tool-gitleaks"]


def test_android_buildenv_is_hash_locked_and_registered_by_image_id() -> None:
    catalog = container_build.load_catalog()
    image = catalog["by_id"]["audit-buildenv-android"]
    assert image["kind"] == "buildenv"
    assert image["build_network"] == "default"
    assert image["image_id"].startswith("sha256:") and len(image["image_id"]) == 71
    lock_path = ROOT / image["assets_lock"]
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    assert {item["version"] for item in lock["artifacts"]} == {
        "8.9", "15859902", "35_r02", "35.0.0", "37.0.1"}
    assert all(len(item["sha256"]) == 64 and item["bytes"] > 0 for item in lock["artifacts"])
    assert all(item["signature_verification"]["status"] in {
        "verified", "not-performed", "not-published"} for item in lock["artifacts"])

    with (ROOT / "appsec-review.toml").open("rb") as stream:
        config = tomllib.load(stream)
    profile = config["jobs"]["job_project_build"]["settings"]["profiles"]["android"]
    assert profile == {"tag": image["tag"], "image_id": image["image_id"],
                       "user": "10001:10001"}


def test_continue_on_error_still_returns_failure(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)

    def fake_build(item, run_dir, **_options):
        status = "failed" if item["id"] == "base-ubuntu" else "passed"
        return {"id": item["id"], "tag": item["tag"], "status": status,
                "duration_seconds": 0.01, "digest": None, "fetch_log": None,
                "build_log": None, **({"error": "fixture"} if status == "failed" else {})}

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = argparse.Namespace(ids=["tool-gitleaks", "base-python"], all=False,
                              jobs=2, continue_on_error=True)
    assert container_build.execute_build(args, catalog) == 1
    summary = json.loads(next(tmp_path.glob("*/summary.json")).read_text())
    by_id = {item["id"]: item for item in summary["results"]}
    assert by_id["base-ubuntu"]["status"] == "failed"
    assert by_id["tool-gitleaks"]["status"] == "blocked"
    assert by_id["base-python"]["status"] == "passed"


def test_parallel_builds_never_exceed_jobs(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)
    guard = threading.Lock()
    active = 0
    maximum = 0

    def fake_build(item, run_dir, **_options):
        nonlocal active, maximum
        with guard:
            active += 1
            maximum = max(maximum, active)
        time.sleep(0.05)
        with guard:
            active -= 1
        return {"id": item["id"], "tag": item["tag"], "status": "passed",
                "duration_seconds": 0.05, "digest": "sha256:fixture",
                "fetch_log": None, "build_log": None}

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = argparse.Namespace(ids=["base-ubuntu", "base-python", "base-php", "base-jre"],
                              all=False, jobs=2, continue_on_error=True)
    assert container_build.execute_build(args, catalog) == 0
    assert maximum == 2


@pytest.mark.skipif(not _usable_bash() or not shutil.which("pwsh"),
                    reason="Bash and PowerShell are both required for launcher parity")
def test_bash_and_powershell_selection_parity() -> None:
    ids = ["tool-gitleaks", "tool-semgrep"]
    bash = subprocess.run(["bash", "containers/build-all.sh",
                           "list", "--json", *ids], cwd=ROOT, capture_output=True,
                          text=True, check=True)
    powershell = subprocess.run(["pwsh", "-NoProfile", "-File",
                                 str(ROOT / "containers" / "build-all.ps1"),
                                 "list", "--json", *ids], cwd=ROOT, capture_output=True,
                                text=True, check=True)
    assert json.loads(bash.stdout) == json.loads(powershell.stdout)


def test_named_build_contexts_are_validated_and_passed_to_docker(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    item = dict(catalog["by_id"]["tool-joern"])
    assert item["build_contexts"] == {"shared": "containers/tools/shared"}
    catalog["by_id"]["tool-joern"] = catalog["images"][[i["id"] for i in catalog["images"]].index(
        "tool-joern")] = {**item, "build_contexts": {"shared": "../outside"}}
    assert any("tool-joern" in error and "escapes" in error for error in container_build.validate(catalog))

    calls = []
    monkeypatch.setattr(container_build, "fetch_one", lambda item, log: None)
    monkeypatch.setattr(container_build, "run_logged", lambda argv, log, timeout: calls.append(argv) or
                        subprocess.CompletedProcess(argv, 1))
    container_build.build_one(item, tmp_path)
    (argv,) = calls
    assert argv[argv.index("--build-context") + 1] == (
        "shared=" + str(container_build.safe_path("containers/tools/shared")))
    assert "--network=none" in argv


def test_build_timeout_is_passed_to_each_image_and_bounded(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)
    seen = []

    def fake_build(item, run_dir, *, timeout_seconds):
        seen.append(timeout_seconds)
        return {"id": item["id"], "tag": item["tag"], "status": "passed", "duration_seconds": 0.01,
                "digest": "sha256:fixture", "fetch_log": None, "build_log": None}

    monkeypatch.setattr(container_build, "build_one", fake_build)
    args = container_build.parser().parse_args(["build", "base-ubuntu", "--timeout-seconds", "120"])
    assert container_build.execute_build(args, catalog) == 0
    assert seen == [120]
    assert json.loads(next(tmp_path.glob("*/summary.json")).read_text())["timeout_seconds"] == 120
    with pytest.raises(ValueError, match="build timeout"):
        container_build.execute_build(container_build.parser().parse_args(
            ["build", "base-ubuntu", "--timeout-seconds", "5"]), catalog)


def test_a_docker_build_timeout_is_a_failed_image(monkeypatch, tmp_path: Path) -> None:
    item = container_build.load_catalog()["by_id"]["base-ubuntu"]
    monkeypatch.setattr(container_build, "fetch_one", lambda item, log: None)

    def expire(argv, log, timeout):
        raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr(container_build, "run_logged", expire)
    result = container_build.build_one(item, tmp_path, timeout_seconds=60)
    assert result["status"] == "failed" and result["error"] == "docker build timed out after 60 seconds"
