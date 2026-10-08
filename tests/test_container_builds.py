from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import threading
import time
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


def test_dependency_order_puts_base_before_tool() -> None:
    catalog = container_build.load_catalog()
    order = container_build.dependency_order(["tool-gitleaks"], catalog)
    assert order == ["base-ubuntu", "tool-gitleaks"]


def test_continue_on_error_still_returns_failure(monkeypatch, tmp_path: Path) -> None:
    catalog = container_build.load_catalog()
    monkeypatch.setattr(container_build, "RUN_ROOT", tmp_path)

    def fake_build(item, run_dir):
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

    def fake_build(item, run_dir):
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
