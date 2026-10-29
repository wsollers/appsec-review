"""The render scripts: syntax, help, argument errors and the HTML path (no Docker)."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from .fixture import RUN_ID, build_fixture

ROOT = Path(__file__).resolve().parents[2]
BASH_SCRIPT = ROOT / "scripts" / "render-report.sh"
PS_SCRIPT = ROOT / "scripts" / "render-report.ps1"
bash = shutil.which("bash")
pwsh = shutil.which("pwsh")
needs_bash = pytest.mark.skipif(bash is None or os.name == "nt", reason="needs a POSIX bash")


def run_script(*args: str, env: dict[str, str] | None = None, cwd: Path | None = None):
    merged = {**os.environ, "APPSEC_PYTHON": sys.executable, **(env or {})}
    return subprocess.run([bash, str(BASH_SCRIPT), *args], capture_output=True, text=True, env=merged, cwd=cwd, timeout=120)


@needs_bash
def test_bash_syntax_and_shellcheck() -> None:
    assert subprocess.run([bash, "-n", str(BASH_SCRIPT)]).returncode == 0
    if shutil.which("shellcheck"):
        assert subprocess.run(["shellcheck", str(BASH_SCRIPT), str(ROOT / "containers/report/latex/render-pdf.sh")]).returncode == 0
    assert 'set -euo pipefail' in BASH_SCRIPT.read_text(encoding="utf-8")


@needs_bash
def test_help_lists_the_parameters() -> None:
    done = run_script("--help")
    assert done.returncode == 0
    for word in ("--run", "--format pdf|html", "--runs-dir", "--output-dir", "--limit", "--package", "--image"):
        assert word in done.stdout


@needs_bash
@pytest.mark.parametrize("args, message", [
    ([], "--run is required"),
    (["--run", "x", "--format", "docx"], "--format must be pdf or html"),
    (["--run", "x", "--limit", "0"], "--limit must be a positive integer"),
    (["--run", "x", "--bogus"], "unknown argument"),
    (["--run"], "needs a value"),
    (["--run", "no-such-run", "--runs-dir", "/nonexistent-runs"], "not found"),
])
def test_argument_errors_exit_2(args: list[str], message: str) -> None:
    done = run_script(*args)
    assert done.returncode == 2 and message in done.stderr


@needs_bash
def test_html_from_any_directory_with_spaces(tmp_path: Path) -> None:
    runs = tmp_path / "runs dir"
    build_fixture(runs)
    out = tmp_path / "out dir"
    elsewhere = tmp_path / "some where"
    elsewhere.mkdir()
    done = run_script("--run", RUN_ID, "--runs-dir", str(runs), "--output-dir", str(out), "--format=html", cwd=elsewhere)
    assert done.returncode == 0, done.stderr
    target = out / f"{RUN_ID}.html"
    assert done.stdout.strip() == str(target)
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert not [p for p in out.iterdir() if p.name.startswith(".render-")]  # staging is removed


@needs_bash
def test_pdf_without_docker_or_image_says_how_to_build(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    build_fixture(runs)
    done = run_script("--run", RUN_ID, "--runs-dir", str(runs), "--output-dir", str(tmp_path / "o"), "--format", "pdf",
                      env={"APPSEC_DOCKER_BIN": "docker-that-does-not-exist"})
    assert done.returncode == 2 and "Docker is required" in done.stderr and "--format html" in done.stderr
    fake = tmp_path / "fake-docker"
    fake.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    fake.chmod(0o755)
    done = run_script("--run", RUN_ID, "--runs-dir", str(runs), "--output-dir", str(tmp_path / "o"), "--format", "pdf",
                      env={"APPSEC_DOCKER_BIN": str(fake)})
    assert done.returncode == 2 and "build-all.sh build tool-report-latex" in done.stderr


def test_powershell_script_declares_the_same_parameters() -> None:
    text = PS_SCRIPT.read_text(encoding="utf-8")
    for name in ("$Run", "$Kind", "$Format", "$RunsDir", "$OutputDir", "$Config", "$Limit", "$Package", "$MaxCells",
                 "$Image", "$KeepWork", "$Help"):
        assert name in text
    assert "ValidateSet('pdf', 'html', 'tex')" in text and "--network" in text and "tool-report-latex" in text
    assert "ValidateSet('review', 'telemetry')" in text and "'appsec_review.reporting', 'telemetry'" in text


@needs_bash
def test_help_documents_the_telemetry_kind() -> None:
    done = run_script("--help")
    assert done.returncode == 0
    for word in ("--kind review|telemetry", "--kind telemetry", "pdf|tex", "--config <toml>"):
        assert word in done.stdout


@needs_bash
@pytest.mark.parametrize("args, message", [
    (["--run", "x", "--kind", "dossier"], "--kind must be review or telemetry"),
    (["--run", "x", "--kind", "telemetry", "--format", "html"], "--format must be pdf or tex for --kind telemetry"),
    (["--run", "x", "--kind", "telemetry", "--limit", "2"], "apply only to --kind review"),
    (["--run", "x", "--format", "tex"], "--format must be pdf or html"),
    (["--run", "x", "--config", "a.toml"], "--config applies only to --kind telemetry"),
])
def test_kind_argument_errors_exit_2(args: list[str], message: str) -> None:
    done = run_script(*args)
    assert done.returncode == 2 and message in done.stderr


@needs_bash
def test_telemetry_tex_delegates_to_the_python_cli(tmp_path: Path) -> None:
    from .telemetry_fixture import RUN_ID as TELEMETRY_RUN_ID, build_telemetry_run
    build_telemetry_run(tmp_path / "runs")
    out = tmp_path / "out dir"
    done = run_script("--kind=telemetry", "--run", TELEMETRY_RUN_ID, "--runs-dir", str(tmp_path / "runs"),
                      "--format", "tex", "--output-dir", str(out))
    assert done.returncode == 0, done.stderr
    assert TELEMETRY_RUN_ID in (out / "telemetry-report.tex").read_text(encoding="utf-8")


@pytest.mark.skipif(pwsh is None, reason="pwsh is not installed")
def test_powershell_script_parses_and_prints_help() -> None:
    parse = subprocess.run([pwsh, "-NoProfile", "-Command",
                            f"$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('{PS_SCRIPT}',[ref]$null,[ref]$e);"
                            "if($e.Count){$e|ForEach-Object{$_.Message};exit 1}"], capture_output=True, text=True, timeout=120)
    assert parse.returncode == 0, parse.stdout + parse.stderr
    helped = subprocess.run([pwsh, "-NoProfile", "-File", str(PS_SCRIPT), "-Help"], capture_output=True, text=True, timeout=120)
    assert helped.returncode == 0 and "-Format pdf|html" in helped.stdout
