"""Operator scripts: syntax, help, and behavior against fakes (never the real Dagster stack)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from tests.operator_support import (
    CODE_ID, PROJECT, REPOSITORY, WEBSERVER_ID, FakeDagster, Sandbox, plan_data, run, run_data, runs_data, step,
)

import ops  # noqa: E402  (tests.operator_support puts deploy/dagster/bin on sys.path)
import ops_clean  # noqa: E402
import ops_tests  # noqa: E402
import review_run  # noqa: E402

SCRIPTS = REPOSITORY / "scripts"
NAMES = ("stack-start", "stack-stop", "stack-restart", "stack-rebuild", "stack-status", "stack-logs", "review-start",
         "review-watch", "review-status", "review-stop", "review-stop-id", "clean-temp", "run-tests")
APP_ID = "2026-10-21-0007"
UUID_ONE = "11111111-1111-4111-8111-111111111111"
UUID_TWO = "22222222-2222-4222-8222-222222222222"
HOUR = 3600


@pytest.fixture
def dagster():
    server = FakeDagster()
    yield server
    server.close()


@pytest.fixture
def box(tmp_path: Path, dagster: FakeDagster) -> Sandbox:
    class SubmissionSandbox(Sandbox):
        def save(self) -> None:
            for item in self.state.get("containers", []):
                item["Image"] = "sha256:" + "2" * 64
            super().save()

    sandbox = SubmissionSandbox(tmp_path, dagster)
    (sandbox.repo / "targets" / "appsec-multi-vuln").mkdir()
    (sandbox.repo / "profiles").mkdir()
    for profile in ("prod", "copilot-dev", "copilot-prod"):
        (sandbox.repo / "profiles" / f"{profile}.toml").write_text("# test profile\n", encoding="utf-8")
    git = sandbox.bin / "git"
    git.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "if args[2:] == ['rev-parse', '--show-toplevel']: print(args[1])\n"
        "elif args[2:] == ['rev-parse', 'HEAD']: print(os.environ.get('FAKE_GIT_HEAD', '1' * 40))\n"
        "elif args[2:4] == ['status', '--porcelain']: print(os.environ.get('FAKE_GIT_STATUS', ''))\n"
        "else: sys.exit(1)\n",
        encoding="utf-8")
    git.chmod(0o755)
    return sandbox


def real(script: str, *arguments: str) -> subprocess.CompletedProcess:
    environment = {**os.environ, "APPSEC_PYTHON": sys.executable}
    return subprocess.run(["bash", str(SCRIPTS / f"{script}.sh"), *arguments], text=True, capture_output=True,
                          env=environment, cwd="/", timeout=60, check=False)


# -- syntax, twins, help --------------------------------------------------------------------------
@pytest.mark.parametrize("name", NAMES)
def test_scripts_are_executable_strict_bash_with_a_powershell_twin(name: str) -> None:
    script = SCRIPTS / f"{name}.sh"
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n") and "set -euo pipefail" in text
    assert os.access(script, os.X_OK)
    assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0
    twin = (SCRIPTS / f"{name}.ps1").read_text(encoding="utf-8")
    assert "Set-StrictMode -Version Latest" in twin and "$ErrorActionPreference = 'Stop'" in twin
    assert "[switch]$Wsl" in twin and "[switch]$Help" in twin and "Ubuntu-24.04" in twin
    if "DryRun" in twin:
        assert "--dry-run" in real(name, "--help").stdout
    # Shared logic lives in the lib files, never copied into a script.
    assert "docker" not in text and "curl" not in text


def test_shared_libraries_are_strict() -> None:
    assert subprocess.run(["bash", "-n", str(SCRIPTS / "lib" / "common.sh")], check=False).returncode == 0
    assert "Set-StrictMode -Version Latest" in (SCRIPTS / "lib" / "common.ps1").read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_shellcheck_is_clean() -> None:
    files = [str(path) for path in [*SCRIPTS.glob("*.sh"), SCRIPTS / "lib" / "common.sh"]]
    result = subprocess.run(["shellcheck", "-x", *files], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stdout


def test_powershell_root_comes_from_the_start_directory_then_the_script_location() -> None:
    text = (SCRIPTS / "lib" / "common.ps1").read_text(encoding="utf-8")
    # The checkout is found from $env:APPSEC_REPO_ROOT, then the current directory's parents, then the script file.
    assert text.index("APPSEC_REPO_ROOT") < text.index("Find-RepoRoot $here") < text.index("script location")
    assert "Get-Location -PSProvider FileSystem" in text and "Split-Path -Parent" in text
    assert "appsec-review.toml" in text and "ops.py" in text
    # With -Wsl the distribution comes from a \\wsl.localhost\<distro>\ checkout unless -Distro was given.
    assert "(?<distro>" in text and "repository: $($script:OpsRoot)" in text


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not installed")
def test_powershell_finds_the_checkout_from_a_subdirectory_and_honours_the_override(tmp_path: Path) -> None:
    checkout = tmp_path / "elsewhere" / "appsec-review"
    (checkout / "deploy" / "dagster" / "bin").mkdir(parents=True)
    (checkout / "appsec-review.toml").write_text("", encoding="utf-8")
    (checkout / "deploy" / "dagster" / "bin" / "ops.py").write_text("", encoding="utf-8")
    nested = checkout / "src" / "deep"
    nested.mkdir(parents=True)
    lib = SCRIPTS / "lib" / "common.ps1"

    def probe(start: Path, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        command = f". '{lib}'; '{{0}}|{{1}}' -f $script:OpsRoot, $script:OpsRootSource"
        env = {**os.environ, "APPSEC_REPO_ROOT": "", **(environment or {})}
        return subprocess.run(["pwsh", "-NoProfile", "-Command", command], cwd=start, env=env, text=True,
                              capture_output=True, check=False)

    found = probe(nested)
    assert found.stdout.strip() == f"{checkout}|current directory", found.stderr
    outside = probe(tmp_path)  # no checkout above this directory: the script's own checkout is used
    assert outside.stdout.strip().endswith("|script location"), outside.stderr
    chosen = probe(tmp_path, {"APPSEC_REPO_ROOT": str(checkout)})
    assert chosen.stdout.strip() == f"{checkout}|APPSEC_REPO_ROOT", chosen.stderr
    bad = probe(tmp_path, {"APPSEC_REPO_ROOT": str(tmp_path)})
    assert bad.returncode != 0 and "not an appsec-review checkout" in bad.stderr


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not installed")
@pytest.mark.parametrize("path", sorted(SCRIPTS.rglob("*.ps1")), ids=lambda path: path.name)
def test_powershell_scripts_parse(path: Path) -> None:
    command = ("$e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
               f"'{path}', [ref]$t, [ref]$e); if ($e.Count) {{ $e | Out-String | Write-Error; exit 1 }}")
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", command], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("name", NAMES)
def test_help_lists_usage_and_the_powershell_twin(name: str) -> None:
    result = real(name, "--help")
    assert result.returncode == 0
    assert f"usage: scripts/{name}.sh" in result.stdout and f"scripts/{name}.ps1" in result.stdout


@pytest.mark.parametrize("name,arguments", [
    ("stack-start", ["--bogus"]), ("stack-logs", ["nosuchservice"]), ("review-stop-id", []),
    ("review-stop-id", ["not-an-id"]), ("run-tests", ["nosuchsuite", "--dry-run"]),
    ("clean-temp", ["--yes", "--dry-run"]), ("clean-temp", ["--older-than", "soon"]), ("review-watch", ["--interval"]),
])
def test_bad_arguments_exit_with_usage_status(name: str, arguments: list[str]) -> None:
    result = real(name, *arguments)
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stderr.strip()


def test_arguments_after_double_dash_are_only_for_run_tests() -> None:
    assert real("stack-status", "--", "x").returncode == 2


# -- stack ----------------------------------------------------------------------------------------
def test_stack_start_runs_lifecycle_start_and_checks_health_overlay_and_probe(box: Sandbox) -> None:
    box.dagster.runs()
    result = box.run("stack-start")
    assert result.returncode == 0, result.stdout + result.stderr
    assert [call["argv"] for call in box.lifecycle_calls()] == [["start"]]
    for service in ops.SERVICES:
        assert f"{service}" in result.stdout
    assert "overlay        ok" in result.stdout and "model probe    ok" in result.stdout
    exec_calls = [call for call in box.docker_calls() if call[:1] == ["exec"]]
    assert exec_calls and exec_calls[0][1] == CODE_ID and exec_calls[0][2:4] == ["claude", "-p"]
    assert "hunter2-secret" not in result.stdout + result.stderr


def test_stack_start_builds_when_asked_or_when_the_image_is_missing(box: Sandbox) -> None:
    box.dagster.runs()
    assert box.run("stack-start", "--build", "--no-probe").returncode == 0
    assert [call["argv"] for call in box.lifecycle_calls()] == [["build"], ["start"]]
    box.lifecycle_log.unlink()
    del box.state["images"][ops.image_tag()]
    box.save()
    assert box.run("stack-start", "--no-probe").returncode == 0
    assert [call["argv"] for call in box.lifecycle_calls()] == [["build"], ["start"]]


def test_stack_start_dry_run_changes_nothing(box: Sandbox) -> None:
    box.dagster.runs()
    result = box.run("stack-start", "--build", "--dry-run")
    assert result.returncode == 0 and "lifecycle.py build" in result.stdout and "lifecycle.py start" in result.stdout
    assert box.lifecycle_calls() == []


def test_stack_start_reports_a_missing_claude_overlay(box: Sandbox) -> None:
    box.stack(files=[str(box.deploy / "compose.yaml")])
    box.dagster.runs()
    result = box.run("stack-start", "--no-probe")
    assert result.returncode == 1
    assert "overlay        MISSING" in result.stdout and ops.overlay_name() in result.stdout


def test_stack_start_explains_an_expired_oauth_token(box: Sandbox) -> None:
    box.stack(probe={"match": "claude -p", "rc": 1, "stderr": "API Error: 401 OAuth token has expired. Please run /login"})
    box.dagster.runs()
    result = box.run("stack-start")
    assert result.returncode == 1
    assert "expired or missing" in result.stdout and 'claude -p "ok"' in result.stdout


def test_stack_start_redacts_a_token_in_probe_output(box: Sandbox) -> None:
    box.stack(probe={"match": "claude -p", "rc": 2, "stderr": "boom sk-ant-api03-ABCDEFGH_secret"})
    box.dagster.runs()
    result = box.run("stack-start")
    assert "sk-ant" not in result.stdout and "[redacted]" in result.stdout


def test_stack_start_with_unhealthy_service_fails(box: Sandbox) -> None:
    box.state["containers"][2]["State"]["Health"]["Status"] = "unhealthy"
    box.save()
    box.dagster.runs()
    result = box.run("stack-start", "--no-probe")
    assert result.returncode == 1 and "daemon" in result.stdout and "unhealthy" in result.stdout


def test_stack_start_guards_a_rebuild_while_a_run_is_active(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "STARTED", app=APP_ID))
    refused = box.run("stack-start", "--build", "--no-probe")
    assert refused.returncode == 3 and UUID_ONE in refused.stderr
    assert box.lifecycle_calls() == []
    forced = box.run("stack-start", "--build", "--no-probe", "--force")
    assert forced.returncode == 0 and "warning" in forced.stdout
    assert [call["argv"] for call in box.lifecycle_calls()] == [["build"], ["start"]]
    # A plain start of a running stack recreates nothing, so it is not blocked.
    box.lifecycle_log.unlink()
    assert box.run("stack-start", "--no-probe").returncode == 0


def test_stack_scripts_refuse_a_stack_created_by_another_checkout(box: Sandbox) -> None:
    box.stack(files=["/elsewhere/appsec-review/deploy/dagster/compose.yaml"])
    box.dagster.runs()
    for name in ("stack-start", "stack-stop", "stack-restart", "stack-rebuild", "review-start"):
        result = box.run(name, "--dry-run")
        assert result.returncode == 3 and "/elsewhere/appsec-review" in result.stderr, name
    assert box.lifecycle_calls() == []


def test_stack_stop_refuses_while_a_run_is_active_unless_forced(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "STARTED", app=APP_ID))
    refused = box.run("stack-stop")
    assert refused.returncode == 3 and "--force" in refused.stderr and box.lifecycle_calls() == []
    forced = box.run("stack-stop", "--force")
    assert forced.returncode == 0 and [call["argv"] for call in box.lifecycle_calls()] == [["stop"]]
    assert "volumes and images are kept" in forced.stdout


def test_stack_stop_with_no_active_run_stops_and_keeps_volumes(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "SUCCESS", app=APP_ID))
    assert box.run("stack-stop").returncode == 0
    assert [call["argv"] for call in box.lifecycle_calls()] == [["stop"]]
    assert not [call for call in box.docker_calls() if call[:1] == ["rm"] or call[:2] == ["volume", "rm"]]


def test_purge_volumes_needs_yes_and_prints_what_it_removes(box: Sandbox) -> None:
    box.dagster.runs()
    refused = box.run("stack-stop", "--purge-volumes")
    assert refused.returncode == 3 and "--yes" in refused.stderr
    assert f"{PROJECT}_postgres-data" in refused.stdout and f"{PROJECT}_dagster-storage" in refused.stdout
    assert box.lifecycle_calls() == []
    confirmed = box.run("stack-stop", "--purge-volumes", "--yes")
    assert confirmed.returncode == 0
    calls = box.docker_calls()
    assert ["volume", "rm", f"{PROJECT}_postgres-data", f"{PROJECT}_dagster-storage"] in calls
    assert any(call[0] == "rm" and len(call) == 5 for call in calls)


def test_purge_volumes_dry_run_removes_nothing(box: Sandbox) -> None:
    box.dagster.runs()
    result = box.run("stack-stop", "--purge-volumes", "--yes", "--dry-run")
    assert result.returncode == 0
    assert not [call for call in box.docker_calls() if call[:1] == ["rm"] or call[:2] == ["volume", "rm"]]
    assert box.lifecycle_calls() == []


def test_stack_restart_stops_then_starts_and_carries_the_running_settings_over(box: Sandbox) -> None:
    box.stack(settings={ops.TARGET_VARIABLE: "/opt/app/targets/demo", ops.RECORDING_VARIABLE: "record",
                        ops.OVERLAY_VARIABLE: ""})
    box.dagster.runs()
    result = box.run("stack-restart", "--no-probe")
    assert result.returncode == 0, result.stdout + result.stderr
    calls = box.lifecycle_calls()
    assert [call["argv"] for call in calls] == [["stop"], ["start"]]
    for call in calls:
        assert call["env"] == {ops.TARGET_VARIABLE: "/opt/app/targets/demo", ops.RECORDING_VARIABLE: "record"}
    assert "carried over from the running stack" in result.stdout


def test_stack_restart_applies_requested_settings_and_is_guarded(box: Sandbox) -> None:
    (box.repo / "test" / "acceptance" / "cap.toml").write_text("x = 1\n", encoding="utf-8")
    box.dagster.runs(run(UUID_ONE, "STARTED", app=APP_ID))
    assert box.run("stack-restart", "--target", "demo").returncode == 3
    assert box.lifecycle_calls() == []
    box.dagster.runs()
    result = box.run("stack-restart", "--no-probe", "--target", "demo", "--overlay", "cap.toml", "--recording", "record")
    assert result.returncode == 0, result.stdout + result.stderr
    assert box.lifecycle_calls()[-1]["env"] == {
        ops.TARGET_VARIABLE: "/opt/app/targets/demo", ops.OVERLAY_VARIABLE: "/opt/app/test/acceptance/cap.toml",
        ops.RECORDING_VARIABLE: "record"}


def test_stack_restart_code_location_only_uses_reload(box: Sandbox) -> None:
    box.dagster.runs()
    assert box.run("stack-restart", "--code-location-only").returncode == 0
    assert [call["argv"] for call in box.lifecycle_calls()] == [["reload"]]


def test_stack_rebuild_builds_then_recreates_with_the_guard(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "QUEUED"))
    assert box.run("stack-rebuild").returncode == 3 and box.lifecycle_calls() == []
    box.dagster.runs()
    result = box.run("stack-rebuild", "--no-probe")
    assert result.returncode == 0
    assert [call["argv"] for call in box.lifecycle_calls()] == [["build"], ["start"]]


def test_stack_commands_never_call_compose_directly(box: Sandbox) -> None:
    box.dagster.runs()
    box.run("stack-restart", "--no-probe")
    box.run("stack-stop")
    assert not [call for call in box.docker_calls() if call[:1] == ["compose"]]


def test_stack_status_gives_the_one_screen_overview(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_TWO, "STARTED", app="2026-10-21-0008"), run(UUID_ONE, "SUCCESS", app=APP_ID))
    result = box.run("stack-status")
    assert result.returncode == 0, result.stdout
    for text in ("postgres", "code-location", "compose.claude.yaml", ops.image_tag(), "2026-10-20T00:00:00",
                 "1 non-terminal run(s)", "2026-10-21-0008", "runs/", "test/tmp", "GiB free", "127.0.0.1"):
        assert text in result.stdout or text == "compose.claude.yaml" and ops.overlay_name() in result.stdout, text
    assert "hunter2-secret" not in result.stdout


def test_stack_status_exits_nonzero_when_the_stack_is_down(box: Sandbox) -> None:
    box.stack(running=False)
    box.dagster.script("OpsRuns", runs_data())
    assert box.run("stack-status").returncode == 1


def test_stack_logs_reads_one_service_through_docker_logs(box: Sandbox) -> None:
    result = box.run("stack-logs", "daemon", "--tail", "5")
    assert result.returncode == 0 and "log line from" in result.stdout
    logs = [call for call in box.docker_calls() if call[:1] == ["logs"]]
    assert len(logs) == 1 and logs[0][:3] == ["logs", "--tail", "5"]
    assert box.run("stack-logs", "--follow").returncode == 2


# -- review start ---------------------------------------------------------------------------------
@pytest.mark.parametrize("stop_policy", [False, True])
def test_review_start_launches_wave1_review_through_the_webserver(box: Sandbox, stop_policy: bool) -> None:
    box.dagster.runs()
    box.dagster.script("OpsRun", run_data(run("x", "STARTED", app="2026-10-21-0012")))
    result = box.run("review-start", "--id-wait", "2",
                     *(["--stop-on-first-error"] if stop_policy else []))
    assert result.returncode == 0, result.stdout + result.stderr
    launch = [call for call in box.docker_calls() if "launch" in call]
    assert len(launch) == 1
    argv = launch[0]
    assert argv[:4] == ["exec", WEBSERVER_ID, "dagster", "job"] and argv[4] == "launch"
    assert argv[argv.index("-j") + 1] == "wave1_review"
    assert argv[argv.index("-w") + 1] == "/opt/dagster/home/workspace.yaml" and argv[argv.index("-l") + 1] == "appsec_review"
    tags = json.loads(argv[argv.index("--tags") + 1])
    assert set(tags) == ({"appsec/submission_identity", "appsec/safety_identity", "dagster/max_retries"}
                         if stop_policy else {"appsec/submission_identity"}) | {"appsec/profile", "appsec/overlay"}
    assert tags["appsec/profile"] == "dev" and tags["appsec/overlay"] == "none"
    intent = review_run.read_submission(box.repo)
    assert intent["state"] == "SUBMITTED"
    assert tags["appsec/submission_identity"] == intent["identity_sha256"]
    dagster_id = argv[argv.index("--run-id") + 1]
    if stop_policy:
        from appsec_review.runtime import execution_safety as safety
        envelope = json.loads(argv[argv.index("--config-json") + 1])["execution"]["config"]["safety"]
        assert envelope["dagster_run_id"] == dagster_id
        assert envelope["submission"] == intent["identity"]
        assert tags["appsec/safety_identity"] == safety.identity(envelope)
        assert tags["dagster/max_retries"] == "0"
        assert "[switch]$StopOnFirstError" in (REPOSITORY / "scripts/review-start.ps1").read_text()
    else:
        assert "--config-json" not in argv
    assert f"dagster run id:      {dagster_id}" in result.stdout
    assert "application run id:  2026-10-21-0012" in result.stdout and f"/runs/{dagster_id}" in result.stdout
    assert box.dagster.calls("OpsRun")[0] == {"runId": dagster_id}


def test_review_start_passes_the_application_run_tag_to_resume_a_run(box: Sandbox) -> None:
    box.dagster.runs()
    (box.repo / "runs" / "2026-10-21-0003").mkdir()
    result = box.run("review-start", "--run-id", "2026-10-21-0003")
    assert result.returncode == 0
    argv = next(call for call in box.docker_calls() if "launch" in call)
    tags = json.loads(argv[argv.index("--tags") + 1])
    assert tags["appsec/application_run_id"] == "2026-10-21-0003"
    assert tags["appsec/submission_identity"] == review_run.read_submission(box.repo)["identity_sha256"]
    assert "application run id:  2026-10-21-0003" in result.stdout
    missing = box.run("review-start", "--run-id", "2026-10-21-0999")
    assert missing.returncode == 4
    assert box.run("review-start", "--run-id", "latest").returncode == 2


def test_review_start_refuses_when_a_run_is_active_unless_forced(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "STARTED", app=APP_ID))
    refused = box.run("review-start", "--id-wait", "1")
    assert refused.returncode == 3 and UUID_ONE in refused.stderr
    assert not [call for call in box.docker_calls() if "launch" in call]
    forced = box.run("review-start", "--force", "--id-wait", "1")
    assert forced.returncode == 0 and len([call for call in box.docker_calls() if "launch" in call]) == 1


def test_review_start_refuses_when_the_stack_is_down(box: Sandbox) -> None:
    box.stack(running=False)
    result = box.run("review-start")
    assert result.returncode == 3 and "stack-start" in result.stderr
    assert not [call for call in box.docker_calls() if "launch" in call]


def test_review_start_refuses_a_target_the_container_was_not_created_with(box: Sandbox) -> None:
    (box.repo / "targets" / "other").mkdir()
    box.stack(settings={ops.TARGET_VARIABLE: "/opt/app/targets/demo"})
    box.dagster.runs()
    result = box.run("review-start", "--target", "other")
    assert result.returncode == 3 and "stack-restart --target" in result.stderr and "/opt/app/targets/demo" in result.stderr
    assert box.run("review-start", "--target", "missing").returncode == 4
    accepted = box.run("review-start", "--target", "demo", "--id-wait", "1")
    assert accepted.returncode == 0 and "target:    /opt/app/targets/demo" in accepted.stdout
    container_path = box.run("review-start", "--target", "/opt/app/targets/demo", "--dry-run")
    assert container_path.returncode == 3 and "remains SUBMITTED" in container_path.stderr


def test_review_start_checks_recording_and_selects_the_overlay_per_run(box: Sandbox) -> None:
    (box.repo / "test" / "acceptance" / "cap.toml").write_text("x = 1\n", encoding="utf-8")
    box.stack(settings={ops.OVERLAY_VARIABLE: "/opt/app/test/acceptance/cap.toml", ops.RECORDING_VARIABLE: "record"})
    box.dagster.runs()
    default = box.run("review-start", "--recording", "record", "--dry-run")
    assert default.returncode == 0 and "overlay:   /opt/app/test/acceptance/cap.toml (container default)" in default.stdout
    mismatch = box.run("review-start", "--recording", "off", "--dry-run")
    assert mismatch.returncode == 3 and "APPSEC_REVIEW_MODEL_RECORDING=record" in mismatch.stderr
    dropped = box.run("review-start", "--overlay", "none", "--id-wait", "1")
    assert dropped.returncode == 0 and "overlay:   (none) (requested)" in dropped.stdout
    argv = next(call for call in box.docker_calls() if "launch" in call)
    assert json.loads(argv[argv.index("--tags") + 1])["appsec/overlay"] == "none"
    outside = box.base / "outside.toml"
    outside.write_text("x = 1\n", encoding="utf-8")
    assert box.run("review-start", "--overlay", str(outside), "--dry-run").returncode == 2


def test_review_start_dry_run_prints_the_launch_command_and_launches_nothing(box: Sandbox) -> None:
    box.dagster.runs()
    result = box.run("review-start", "--dry-run")
    assert result.returncode == 0 and "dagster job launch" in result.stdout and "dry run: nothing launched" in result.stdout
    assert not [call for call in box.docker_calls() if "launch" in call]
    assert not review_run.submission_directory(box.repo).exists()


def test_review_start_stops_on_a_moved_image_pin(box: Sandbox) -> None:
    box.state["images"]["img:p1"]["id"] = "sha256:moved"
    box.save()
    box.dagster.runs()
    result = box.run("review-start")
    assert result.returncode == 3 and "preflight failed" in result.stderr
    assert not [call for call in box.docker_calls() if "launch" in call]


@pytest.mark.parametrize("stop_policy", [False, True])
def test_single_submission_concurrent_invocations_launch_once(box: Sandbox, stop_policy: bool) -> None:
    box.dagster.runs()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: box.run("review-start", "--id-wait", "0",
            *(["--stop-on-first-error"] if stop_policy else [])), range(2)))
    assert sorted(result.returncode for result in results) == [0, 3]
    assert len([call for call in box.docker_calls() if "launch" in call]) == 1
    record = review_run.read_submission(box.repo)
    assert record["state"] == "SUBMITTED"
    assert record["identity"]["source_commit"] == "1" * 40
    assert record["identity"]["target_commit"] == "1" * 40
    assert record["identity"]["configuration"]["base_sha256"]


@pytest.mark.parametrize("stop_policy", [False, True])
def test_single_submission_lost_response_retains_intent(box: Sandbox, stop_policy: bool) -> None:
    box.dagster.runs()
    box.stack(probe={"match": "dagster job launch", "rc": 1, "stderr": "connection lost after submission"})
    flags = ["--stop-on-first-error"] if stop_policy else []
    result = box.run("review-start", "--id-wait", "0", *flags)
    assert result.returncode == 1 and "UNCERTAIN" in result.stderr
    record = review_run.read_submission(box.repo)
    assert record["state"] == "UNCERTAIN"
    again = box.run("review-start", "--force", "--id-wait", "0", *flags)
    assert again.returncode == 3 and record["dagster_run_id"] in again.stderr
    assert review_run.read_submission(box.repo) == record
    assert len([call for call in box.docker_calls() if "launch" in call]) == 1


def test_single_submission_preflight_failure_does_not_launch(box: Sandbox) -> None:
    box.dagster.runs()
    box.state["images"]["img:p1"]["id"] = "sha256:moved"
    box.save()
    result = box.run("review-start", "--id-wait", "0")
    assert result.returncode == 3 and "preflight failed" in result.stderr
    assert review_run.read_submission(box.repo) is None
    assert not [call for call in box.docker_calls() if "launch" in call]


@pytest.mark.parametrize("changed", ["source", "target", "configuration", "image"])
def test_single_submission_identity_mismatch_refuses(box: Sandbox, changed: str) -> None:
    box.dagster.runs()
    assert box.run("review-start", "--id-wait", "0").returncode == 0
    record = review_run.read_submission(box.repo)
    extra = {}
    if changed == "source":
        extra["FAKE_GIT_HEAD"] = "3" * 40
    elif changed == "target":
        box.stack(settings={ops.TARGET_VARIABLE: "/opt/app/targets/demo"})
    elif changed == "configuration":
        with (box.repo / "appsec-review.toml").open("a", encoding="utf-8") as stream:
            stream.write("\n# changed configuration\n")
    else:
        for item in box.state["containers"]:
            item["Image"] = "sha256:" + "4" * 64
        box.state_file.write_text(json.dumps(box.state), encoding="utf-8")
    result = box.run("review-start", "--id-wait", "0", extra=extra)
    assert result.returncode == 3 and "identity mismatch" in result.stderr
    assert review_run.read_submission(box.repo) == record
    assert len([call for call in box.docker_calls() if "launch" in call]) == 1


def test_single_submission_helper_cannot_bypass_guard(box: Sandbox) -> None:
    box.dagster.runs()
    assert box.run("review-start", "--id-wait", "0").returncode == 0
    result = subprocess.run(
        [sys.executable, str(box.deploy / "bin" / "review_run.py"), "submit",
         "--run-id", UUID_TWO, "--url", box.dagster.url],
        env=box.environment(), capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 3 and "remains SUBMITTED" in result.stderr
    assert len([call for call in box.docker_calls() if "launch" in call]) == 1


def test_single_submission_helper_binds_explicit_uuid(box: Sandbox) -> None:
    box.dagster.runs()
    box.dagster.script("ReviewRun", run_data(run(UUID_ONE, "STARTED")))
    result = subprocess.run(
        [sys.executable, str(box.deploy / "bin" / "review_run.py"), "submit",
         "--run-id", UUID_ONE, "--url", box.dagster.url],
        env=box.environment(), capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    record = review_run.read_submission(box.repo)
    assert record["dagster_run_id"] == UUID_ONE and record["state"] == "SUBMITTED"
    assert len([call for call in box.docker_calls() if "launch" in call]) == 1


def test_single_submission_explicit_terminal_reconciliation_does_not_launch(box: Sandbox) -> None:
    box.dagster.runs()
    assert box.run("review-start", "--id-wait", "0").returncode == 0
    record = review_run.read_submission(box.repo)
    item = run(record["dagster_run_id"], "FAILURE")
    item["tags"].append({"key": "appsec/submission_identity", "value": record["identity_sha256"]})
    box.dagster.script("ReviewRun", run_data(item))
    result = subprocess.run(
        [sys.executable, str(box.deploy / "bin" / "review_run.py"), "reconcile",
         "--run-id", record["dagster_run_id"], "--url", box.dagster.url],
        env=box.environment(), capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert review_run.read_submission(box.repo)["state"] == "RECONCILED"
    assert len([call for call in box.docker_calls() if "launch" in call]) == 1
    assert box.run("review-start", "--id-wait", "0").returncode == 0
    archived = review_run.submission_directory(box.repo) / f"{record['dagster_run_id']}.json"
    assert json.loads(archived.read_text())["terminal_status"] == "FAILURE"
    assert len([call for call in box.docker_calls() if "launch" in call]) == 2


@pytest.mark.parametrize("status,matching", [("STARTED", True), ("FAILURE", False)])
def test_single_submission_unconfirmed_reconciliation_retains_intent(
        box: Sandbox, status: str, matching: bool) -> None:
    box.dagster.runs()
    assert box.run("review-start", "--id-wait", "0").returncode == 0
    record = review_run.read_submission(box.repo)
    item = run(record["dagster_run_id"], status)
    if matching:
        item["tags"].append({"key": "appsec/submission_identity", "value": record["identity_sha256"]})
    box.dagster.script("ReviewRun", run_data(item))
    result = subprocess.run(
        [sys.executable, str(box.deploy / "bin" / "review_run.py"), "reconcile",
         "--run-id", record["dagster_run_id"], "--url", box.dagster.url],
        env=box.environment(), capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 1 and "intent retained" in result.stderr
    assert review_run.read_submission(box.repo) == record


def test_single_submission_dirty_checkout_refuses_without_intent(box: Sandbox) -> None:
    box.dagster.runs()
    result = box.run("review-start", "--id-wait", "0", extra={"FAKE_GIT_STATUS": " M source.c"})
    assert result.returncode == 3 and "clean target" in result.stderr
    assert review_run.read_submission(box.repo) is None
    assert not [call for call in box.docker_calls() if "launch" in call]


# -- review watch / status ------------------------------------------------------------------------
T0 = 1_700_000_000.0


def watch_script(dagster: FakeDagster) -> None:
    first = [step("model_connectivity__begin", "SUCCESS", T0 + 1, T0 + 2)]
    second = first + [step("target_catalog__begin", "IN_PROGRESS", T0 + 120)]
    third = second + [step("target_catalog__scan", "FAILURE", T0 + 150, T0 + 160),
                      step("source_history__begin", "SUCCESS", T0 + 180, T0 + 181)]
    dagster.runs(run(UUID_ONE, "STARTED", app=APP_ID, start=T0))
    dagster.script("OpsRun", run_data(run(UUID_ONE, "STARTED", app=APP_ID, start=T0, steps=first)),
                   run_data(run(UUID_ONE, "STARTED", app=APP_ID, start=T0, steps=second)),
                   run_data(run(UUID_ONE, "STARTED", app=APP_ID, start=T0, steps=second)),
                   run_data(run(UUID_ONE, "FAILURE", app=APP_ID, start=T0, end=T0 + 300, steps=third)))
    dagster.script("OpsPlan", plan_data("model_connectivity", "target_catalog", "source_history"))


def test_review_watch_prints_one_line_per_new_job_and_the_final_status(box: Sandbox) -> None:
    watch_script(box.dagster)
    result = box.run("review-watch", "--interval", "0.05")
    lines = result.stdout.splitlines()
    started = [line for line in lines if line.startswith("[")]
    assert [line.split("started ")[1] for line in started] == [
        "model_connectivity (1/3 jobs)", "target_catalog (2/3 jobs)", "source_history (3/3 jobs)"]
    assert "[   2.0 min] started target_catalog" in result.stdout
    assert [line for line in lines if line.startswith("FAILED step")] == ["FAILED step target_catalog__scan"]
    assert lines[-1].startswith("FINAL FAILURE after 5.0 min, 3/3 jobs started") and APP_ID in lines[-1]
    assert result.returncode == 1


def test_review_watch_exits_zero_on_success_and_accepts_an_application_run_id(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "SUCCESS", app=APP_ID, start=T0))
    box.dagster.script("OpsRun", run_data(run(UUID_ONE, "SUCCESS", app=APP_ID, start=T0, end=T0 + 60,
                                              steps=[step("a__begin", "SUCCESS", T0 + 1, T0 + 5)])))
    box.dagster.script("OpsPlan", plan_data("a"))
    result = box.run("review-watch", "--run", APP_ID)
    assert result.returncode == 0 and result.stdout.splitlines()[-1].startswith("FINAL SUCCESS")
    assert result.stdout.count("started a") == 1


def test_review_watch_once_prints_a_snapshot(box: Sandbox) -> None:
    watch_script(box.dagster)
    result = box.run("review-watch", "--once")
    assert result.returncode == 0
    assert result.stdout.count("started ") == 1 and "status STARTED" in result.stdout
    assert len(box.dagster.calls("OpsRun")) == 1


def test_review_watch_gives_up_when_dagster_stays_unreachable(box: Sandbox) -> None:
    result = box.run("review-watch", "--run", UUID_ONE, "--interval", "0.01", extra={"APPSEC_DAGSTER_URL": "http://127.0.0.1:9/graphql"})
    assert result.returncode in {1, 3, 4} and "unreachable" in result.stdout + result.stderr


def test_review_status_lists_runs_and_the_active_runs_steps(box: Sandbox) -> None:
    active = run(UUID_ONE, "STARTED", app=APP_ID, start=T0, steps=[
        step("a__begin", "SUCCESS", T0 + 1, T0 + 2), step("a__finalize", "SUCCESS", T0 + 3, T0 + 4),
        step("b__begin", "SUCCESS", T0 + 5, T0 + 6), step("b__unit", "IN_PROGRESS", T0 + 7)])
    box.dagster.runs(active, run(UUID_TWO, "FAILURE", start=T0 - 100, end=T0 - 50))
    box.dagster.script("OpsRun", run_data(active))
    box.dagster.script("OpsPlan", plan_data("a", "b", "c"))
    result = box.run("review-status", "--limit", "5")
    assert result.returncode == 0
    assert "STARTED" in result.stdout and "FAILURE" in result.stdout and APP_ID in result.stdout
    assert f"active {UUID_ONE}: 2/3 jobs started, 1 finished; current steps: b__unit" in result.stdout


# -- review stop ----------------------------------------------------------------------------------
def stop_script(dagster: FakeDagster, *active: dict) -> None:
    dagster.runs(*active)
    finished = [{**item, "status": "CANCELED"} for item in active]
    dagster.script("RecoveryRuns", runs_data(*active), runs_data(*finished))
    dagster.script("RecoverRun", {"terminateRun": {"__typename": "TerminateRunSuccess"}})


def evidence(box: Sandbox) -> dict:
    files = sorted((box.repo / "runs" / "metadata" / "dagster-recovery").glob("*.json"))
    assert len(files) == 1
    return json.loads(files[0].read_text(encoding="utf-8"))


def test_review_stop_ends_the_single_active_run_with_the_safe_policy(box: Sandbox) -> None:
    one = run(UUID_ONE, "STARTED", app=APP_ID)
    stop_script(box.dagster, one)
    box.dagster.routes["OpsRuns"] = [runs_data(one, run(UUID_TWO, "SUCCESS"))]
    result = box.run("review-stop")
    assert result.returncode == 0, result.stdout + result.stderr
    assert box.dagster.calls("RecoverRun") == [{"runId": UUID_ONE, "policy": "SAFE_TERMINATE"}]
    report = evidence(box)
    assert report["policy"] == "SAFE_TERMINATE" and report["runs"][0]["finalStatus"] == "CANCELED"
    assert report["reason"].startswith("operator review-stop")


def test_review_stop_now_uses_the_immediate_policy_and_a_reason(box: Sandbox) -> None:
    one = run(UUID_ONE, "STARTED", app=APP_ID)
    stop_script(box.dagster, one)
    result = box.run("review-stop", "--now", "--reason", "owner asked")
    assert result.returncode == 0
    assert box.dagster.calls("RecoverRun")[0]["policy"] == "MARK_AS_CANCELED_IMMEDIATELY"
    assert evidence(box)["reason"] == "owner asked"


def test_review_stop_needs_yes_for_more_than_one_run(box: Sandbox) -> None:
    runs = [run(UUID_ONE, "STARTED", app=APP_ID), run(UUID_TWO, "QUEUED")]
    stop_script(box.dagster, *runs)
    refused = box.run("review-stop")
    assert refused.returncode == 3 and "--yes" in refused.stderr and UUID_TWO in refused.stdout
    assert box.dagster.calls("RecoverRun") == []
    confirmed = box.run("review-stop", "--yes")
    assert confirmed.returncode == 0
    assert sorted(call["runId"] for call in box.dagster.calls("RecoverRun")) == [UUID_ONE, UUID_TWO]


def test_review_stop_with_nothing_active_is_a_no_op(box: Sandbox) -> None:
    box.dagster.runs(run(UUID_ONE, "SUCCESS"))
    result = box.run("review-stop")
    assert result.returncode == 0 and "nothing to stop" in result.stdout and box.dagster.calls("RecoverRun") == []


def test_review_stop_dry_run_terminates_nothing(box: Sandbox) -> None:
    stop_script(box.dagster, run(UUID_ONE, "STARTED"))
    result = box.run("review-stop", "--dry-run")
    assert result.returncode == 0 and "recover_runs.py" in result.stdout and box.dagster.calls("RecoverRun") == []


def test_review_stop_id_resolves_an_application_run_id(box: Sandbox) -> None:
    other = run(UUID_TWO, "STARTED", app="2026-10-21-0009")
    target = run(UUID_ONE, "STARTED", app=APP_ID)
    stop_script(box.dagster, target, other)
    result = box.run("review-stop-id", APP_ID)
    assert result.returncode == 0, result.stdout + result.stderr
    assert box.dagster.calls("RecoverRun") == [{"runId": UUID_ONE, "policy": "SAFE_TERMINATE"}]


def test_review_stop_id_accepts_a_dagster_run_id_and_now(box: Sandbox) -> None:
    one = run(UUID_ONE, "STARTED", app=APP_ID)
    stop_script(box.dagster, one)
    box.dagster.script("OpsRun", run_data(one))
    result = box.run("review-stop-id", UUID_ONE, "--now")
    assert result.returncode == 0
    assert box.dagster.calls("RecoverRun") == [{"runId": UUID_ONE, "policy": "MARK_AS_CANCELED_IMMEDIATELY"}]


def test_review_stop_id_refuses_a_terminal_run_and_reports_unknown_ids(box: Sandbox) -> None:
    done = run(UUID_ONE, "SUCCESS", app=APP_ID)
    box.dagster.runs(done)
    box.dagster.script("OpsRun", run_data(done))
    terminal = box.run("review-stop-id", APP_ID)
    assert terminal.returncode == 3 and "already terminal (SUCCESS)" in terminal.stderr
    assert box.run("review-stop-id", UUID_ONE).returncode == 3
    missing = box.run("review-stop-id", "2026-01-01-0001")
    assert missing.returncode == 4 and "no Dagster run belongs to application run 2026-01-01-0001" in missing.stderr
    box.dagster.script("OpsRun", {"runOrError": {"__typename": "RunNotFoundError", "message": "Run does not exist"}})
    assert box.run("review-stop-id", UUID_TWO).returncode == 4
    assert box.dagster.calls("RecoverRun") == []


def test_review_stop_id_needs_yes_when_an_application_run_has_several_active_runs(box: Sandbox) -> None:
    stop_script(box.dagster, run(UUID_ONE, "STARTED", app=APP_ID), run(UUID_TWO, "STARTED", app=APP_ID))
    assert box.run("review-stop-id", APP_ID).returncode == 3
    assert box.run("review-stop-id", APP_ID, "--yes").returncode == 0
    assert len(box.dagster.calls("RecoverRun")) == 2


# -- clean-temp -----------------------------------------------------------------------------------
def aged(path: Path, hours: float) -> None:
    stamp = time.time() - hours * HOUR
    for item in [path, *(path.rglob("*") if path.is_dir() else [])]:
        os.utime(item, (stamp, stamp), follow_symlinks=False)


def temp_tree(box: Sandbox) -> Path:
    tmp = box.repo / "test" / "tmp"
    (tmp / "old-session").mkdir()
    (tmp / "old-session" / "data.bin").write_bytes(b"x" * 2048)
    (tmp / "fresh-session").mkdir()
    (tmp / "fresh-session" / "data.bin").write_bytes(b"y" * 10)
    (tmp / "old.log").write_text("log", encoding="utf-8")
    aged(tmp / "old-session", 5)
    aged(tmp / "old.log", 3)
    return tmp


def protected_files(box: Sandbox) -> list[Path]:
    files = [box.repo / "runs" / "run.json", box.repo / "data" / "feed.json", box.repo / "targets" / "demo" / "src.c",
             box.repo / "test" / "acceptance" / "expect.toml", box.repo / "old" / "legacy.txt"]
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("keep", encoding="utf-8")
        aged(path, 100)
    return files


def test_clean_temp_is_a_dry_run_by_default(box: Sandbox) -> None:
    tmp = temp_tree(box)
    result = box.run("clean-temp")
    assert result.returncode == 0, result.stderr
    assert "would delete" in result.stdout and "old-session" in result.stdout and "fresh-session" in result.stdout
    assert "nothing was deleted; add --yes" in result.stdout and "2 to delete" in result.stdout
    assert (tmp / "old-session").is_dir() and (tmp / "old.log").exists()


def test_clean_temp_yes_deletes_only_old_entries_and_never_protected_trees(box: Sandbox) -> None:
    tmp = temp_tree(box)
    keep = protected_files(box)
    result = box.run("clean-temp", "--yes")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp / "old-session").exists() and not (tmp / "old.log").exists()
    assert (tmp / "fresh-session" / "data.bin").is_file()
    assert all(path.read_text(encoding="utf-8") == "keep" for path in keep)
    assert "2 deleted" in result.stdout and "1 kept (recent)" in result.stdout
    assert "protected and never touched: runs/, data/, targets/, old/, test/acceptance/" in result.stdout


def test_clean_temp_age_option_and_zero(box: Sandbox) -> None:
    tmp = temp_tree(box)
    assert box.run("clean-temp", "--yes", "--older-than", "10h").returncode == 0
    assert (tmp / "old-session").exists()
    assert box.run("clean-temp", "--yes", "--older-than", "0").returncode == 0
    assert not list(tmp.iterdir())


def test_clean_temp_refuses_symlink_escapes(box: Sandbox) -> None:
    tmp = box.repo / "test" / "tmp"
    outside = box.base / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("keep", encoding="utf-8")
    (tmp / "escape").mkdir()
    (tmp / "escape" / "link").symlink_to(outside, target_is_directory=True)
    (tmp / "toplink").symlink_to(outside, target_is_directory=True)
    inner = tmp / "inside"
    inner.mkdir()
    (inner / "target.txt").write_text("t", encoding="utf-8")
    (inner / "ok-link").symlink_to(inner / "target.txt")
    for path in (tmp / "escape", inner):
        aged(path, 5)
    result = box.run("clean-temp", "--yes", "--older-than", "0")
    assert result.returncode == 0, result.stdout
    assert (outside / "precious.txt").read_text(encoding="utf-8") == "keep"
    assert (tmp / "escape").is_dir() and os.path.lexists(tmp / "toplink")
    assert "points outside test/tmp" in result.stdout and "top-level symlink" in result.stdout
    assert not inner.exists()


def test_clean_temp_refuses_a_test_tmp_that_leaves_the_repository(box: Sandbox) -> None:
    outside = box.base / "elsewhere"
    outside.mkdir()
    (outside / "file.txt").write_text("keep", encoding="utf-8")
    shutil.rmtree(box.repo / "test" / "tmp")
    (box.repo / "test" / "tmp").symlink_to(outside, target_is_directory=True)
    for flags in ([], ["--yes", "--older-than", "0"]):
        result = box.run("clean-temp", *flags)
        assert result.returncode == 3 and "outside the repository's test/tmp" in result.stderr + result.stdout
    assert (outside / "file.txt").exists()


def test_clean_temp_skips_git_tracked_entries(box: Sandbox) -> None:
    tmp = box.repo / "test" / "tmp"
    (tmp / "tracked").mkdir()
    (tmp / "tracked" / "file.txt").write_text("t", encoding="utf-8")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(box.repo)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "-f", "test/tmp/tracked/file.txt"], check=True)
    subprocess.run([*git, "commit", "-qm", "x"], check=True)
    aged(tmp / "tracked", 9)
    result = box.run("clean-temp", "--yes")
    assert result.returncode == 0 and "contains git-tracked files" in result.stdout
    assert (tmp / "tracked" / "file.txt").exists()


def test_clean_temp_works_from_any_directory(box: Sandbox, tmp_path: Path) -> None:
    elsewhere = tmp_path / "other dir"
    elsewhere.mkdir()
    temp_tree(box)
    result = box.run("clean-temp", cwd=elsewhere)
    assert result.returncode == 0 and str(box.repo / "test" / "tmp") in result.stdout


def test_clean_temp_docker_only_lists(box: Sandbox) -> None:
    box.state["ps_names"] = ["appsec-review-build-abc\tExited (0) 2 hours ago", "unrelated\tUp"]
    box.state["volumes"] = ["appsec-codeql-123", f"{PROJECT}_postgres-data"]
    box.save()
    result = box.run("clean-temp", "--docker")
    assert result.returncode == 0
    assert "container: appsec-review-build-abc" in result.stdout and "volume: appsec-codeql-123" in result.stdout
    assert "unrelated" not in result.stdout and PROJECT not in result.stdout
    assert not [call for call in box.docker_calls() if call[:1] in (["rm"], ["rmi"]) or call[:2] == ["volume", "rm"]]


def test_clean_temp_without_a_test_tmp_directory(box: Sandbox) -> None:
    shutil.rmtree(box.repo / "test" / "tmp")
    result = box.run("clean-temp", "--yes")
    assert result.returncode == 0 and "does not exist" in result.stdout


def test_parse_age() -> None:
    assert ops_clean.parse_age("2h") == 7200 and ops_clean.parse_age("30m") == 1800 and ops_clean.parse_age("0") == 0
    assert ops_clean.parse_age("1.5d") == 129600
    with pytest.raises(ValueError):
        ops_clean.parse_age("2 hours")


# -- run-tests ------------------------------------------------------------------------------------
def test_run_tests_builds_the_pytest_command_for_a_suite(box: Sandbox) -> None:
    for name in ("tests/review", "tests/orchestration", "tests/graph"):
        (box.repo / name).mkdir(parents=True)
    (box.repo / "tests" / "test_documentation.py").write_text("", encoding="utf-8")
    result = box.run("run-tests", "review", "--dry-run")
    assert result.returncode == 0
    command = next(line for line in result.stdout.splitlines() if line.startswith("+ "))
    assert " -m pytest -q -rfE --basetemp=test/tmp/tests-review-" in command and command.endswith(" tests/review")
    assert "test/tmp/logs/tests-review-" in result.stdout
    default = box.run("run-tests", "--dry-run")
    assert "--basetemp=test/tmp/tests-fast-" in default.stdout and "--ignore=tests/live" in default.stdout
    assert "--ignore=tests/integration" in default.stdout and "WARNING" not in default.stdout
    docs = box.run("run-tests", "docs", "--dry-run")
    assert "tests/test_documentation.py" in docs.stdout


def test_run_tests_free_expression_after_double_dash(box: Sandbox) -> None:
    result = box.run("run-tests", "--dry-run", "--", "tests/test_config.py", "-k", "overlay and not slow")
    assert result.returncode == 0
    assert "--basetemp=test/tmp/tests-custom-" in result.stdout
    assert "tests/test_config.py -k 'overlay and not slow'" in result.stdout
    assert box.run("run-tests", "review", "--dry-run", "--", "x").returncode == 2


def test_run_tests_live_prints_a_warning(box: Sandbox) -> None:
    result = box.run("run-tests", "live", "--dry-run")
    assert "WARNING: the live suite needs Docker" in result.stdout


def test_run_tests_recognizes_known_failures_and_reports_counts(box: Sandbox) -> None:
    box.pytest_output.write_text("FAILED tests/a.py::test_known - assert 0\nFAILED tests/b.py::test_new - boom\n"
                                 "2 failed, 5 passed in 1.20s\n", encoding="utf-8")
    known = box.repo / "scripts" / "known-failures.txt"
    known.write_text(known.read_text(encoding="utf-8") + "tests/a.py::test_known | seeded for the test\n", encoding="utf-8")
    environment = {"APPSEC_PYTHON": box.install_fake_python(), "FAKE_PYTEST_RC": "1"}
    result = box.run("run-tests", "--", "tests/a.py", extra=environment)
    assert result.returncode == 1
    assert "2 failures, 1 known" in result.stdout and "NEW     tests/b.py::test_new" in result.stdout
    assert "known   tests/a.py::test_known  (seeded for the test)" in result.stdout
    assert "2 failed, 5 passed" in result.stdout
    logs = list((box.repo / "test" / "tmp" / "logs").glob("tests-custom-*.log"))
    assert len(logs) == 1 and "test_new" in logs[0].read_text(encoding="utf-8")
    assert "--basetemp=test/tmp/tests-custom-" in box.pytest_log.read_text(encoding="utf-8")


def test_run_tests_succeeds_when_only_known_failures_remain_unless_strict(box: Sandbox) -> None:
    box.pytest_output.write_text("FAILED tests/test_documentation.py::test_current_documentation_local_links_resolve - x\n"
                                 "1 failed, 9 passed in 1s\n", encoding="utf-8")
    environment = {"APPSEC_PYTHON": box.install_fake_python(), "FAKE_PYTEST_RC": "1"}
    ok = box.run("run-tests", "--", "tests", extra=environment)
    assert ok.returncode == 0 and "1 failures, 1 known" in ok.stdout and "only known failures remain" in ok.stdout
    assert box.run("run-tests", "--strict", "--", "tests", extra=environment).returncode == 1


def test_run_tests_parallel_falls_back_without_xdist(box: Sandbox) -> None:
    box.pytest_output.write_text("3 passed in 1s\n", encoding="utf-8")
    environment = {"APPSEC_PYTHON": box.install_fake_python()}
    result = box.run("run-tests", "--parallel", "--", "tests", extra=environment)
    assert result.returncode == 0 and "pytest-xdist is not installed" in result.stdout
    assert "-n auto" not in box.pytest_log.read_text(encoding="utf-8")
    assert "0 failures, 0 known" in result.stdout and "3 passed" in result.stdout


def test_run_tests_background_returns_the_log_path_at_once(box: Sandbox) -> None:
    box.pytest_output.write_text("3 passed in 1s\n", encoding="utf-8")
    environment = {"APPSEC_PYTHON": box.install_fake_python()}
    result = box.run("run-tests", "--background", "--", "tests", extra=environment)
    assert result.returncode == 0 and "started in the background" in result.stdout and "tail -f" in result.stdout
    log = Path(next(line for line in result.stdout.splitlines() if line.startswith("log: ")).removeprefix("log: "))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and "3 passed" not in (log.read_text(encoding="utf-8") if log.exists() else ""):
        time.sleep(0.1)
    assert "3 passed" in log.read_text(encoding="utf-8")


# -- python helpers -------------------------------------------------------------------------------
def test_known_failures_file_seeds_the_documented_failures() -> None:
    known = ops_tests.load_known(REPOSITORY)
    assert set(known) >= {
        "tests/test_documentation.py::test_current_documentation_local_links_resolve",
        "tests/review/test_inference_review_schemas.py::test_enums_match_python_contract[entity_kind-EntityKind]",
        "tests/review/test_inference_review_config.py::test_pool_mapping_is_job_aware"}
    assert all(reason for reason in known.values())


@pytest.mark.parametrize("suite", sorted(ops_tests.SUITES))
def test_every_suite_names_existing_paths(suite: str) -> None:
    arguments = ops_tests.suite_arguments(REPOSITORY, suite)
    paths = [item for item in arguments if not item.startswith("-")]
    assert paths and all((REPOSITORY / item).exists() for item in paths)


def test_fast_suite_excludes_live_and_integration_tests() -> None:
    arguments = ops_tests.suite_arguments(REPOSITORY, "fast")
    assert "--ignore=tests/live" in arguments and "--ignore=tests/integration" in arguments
    assert "--ignore-glob=tests/test_live_*.py" in arguments
    assert "tests/live" in ops_tests.suite_arguments(REPOSITORY, "live")


def test_parse_output_separates_known_from_new_failures() -> None:
    text = "FAILED a.py::one - x\nERROR b.py::two - y\nFAILED a.py::one - x\n= 1 failed, 1 error, 7 passed, 2 skipped in 3s =\n"
    result = ops_tests.parse_output(text, {"a.py::one": "known"})
    assert result.known == ["a.py::one"] and result.failures == ["b.py::two"]
    assert result.counts == {"failed": 1, "error": 1, "passed": 7, "skipped": 2}


def test_watch_prints_each_job_once_across_polls() -> None:
    watch = ops.Watch(total=2)
    snapshot = run(UUID_ONE, "STARTED", start=T0, steps=[step("a__begin", "SUCCESS", T0 + 60, T0 + 61)])
    assert watch.update(snapshot) == ["[   1.0 min] started a (1/2 jobs)"]
    assert watch.update(snapshot) == []
    assert watch.update({**snapshot, "status": "SUCCESS", "endTime": T0 + 120})[-1].startswith("FINAL SUCCESS after 2.0 min")


def test_resolve_target_and_overlay_validate_their_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ops, "ROOT", tmp_path)
    (tmp_path / "targets" / "demo").mkdir(parents=True)
    (tmp_path / "test" / "acceptance" / "set").mkdir(parents=True)
    (tmp_path / "test" / "acceptance" / "set" / "o.toml").write_text("x=1", encoding="utf-8")
    assert ops.resolve_target("demo") == "/opt/app/targets/demo"
    assert ops.resolve_target("/opt/app/targets/x/") == "/opt/app/targets/x"
    for bad in ("../etc", "a/b", ""):
        with pytest.raises(ops.OpsError):
            ops.resolve_target(bad)
    with pytest.raises(ops.OpsError) as missing:
        ops.resolve_target("nope")
    assert missing.value.code == ops.NOT_FOUND
    assert ops.resolve_overlay("set/o.toml") == "/opt/app/test/acceptance/set/o.toml"
    assert ops.resolve_overlay("none") == ""
    assert ops.resolve_recording("off") == "" and ops.resolve_recording("record") == "record"


def test_effective_settings_carry_running_values_and_report_changes() -> None:
    code = ops.Container("1", "n", "code-location", "running", "healthy", "i", (), {
        ops.TARGET_VARIABLE: "/a", ops.RECORDING_VARIABLE: ""})
    settings, changed = ops.effective_settings([code], {})
    assert settings == {ops.TARGET_VARIABLE: "/a"} and not changed
    settings, changed = ops.effective_settings([code], {ops.TARGET_VARIABLE: "/b"})
    assert settings == {ops.TARGET_VARIABLE: "/b"} and changed
    assert ops.effective_settings([], {ops.TARGET_VARIABLE: "/b"}) == ({ops.TARGET_VARIABLE: "/b"}, False)


def test_redact_hides_tokens_and_truncates() -> None:
    text = "failed with sk-ant-api03-abcdef and Bearer abc.def and " + "x" * 80
    cleaned = ops.redact(text, 500)
    assert "sk-ant" not in cleaned and "abc.def" not in cleaned and "xxxx" not in cleaned
    assert len(ops.redact("y " * 500)) <= 400


# -- runtime profile ------------------------------------------------------------------------------
def test_stack_start_passes_the_requested_profile_to_lifecycle_and_prints_it(box: Sandbox) -> None:
    box.dagster.runs()
    dev = box.run("stack-start", "--no-probe")
    assert dev.returncode == 0 and "profile: dev" in dev.stdout and "more capable models" not in dev.stdout
    assert ops.PROFILE_VARIABLE not in box.lifecycle_calls()[-1]["env"]
    prod = box.run("stack-start", "--no-probe", "--profile", "prod")
    assert prod.returncode == 0, prod.stdout + prod.stderr
    assert box.lifecycle_calls()[-1]["env"][ops.PROFILE_VARIABLE] == "prod"
    assert "profile: prod" in prod.stdout and "more capable models" in prod.stdout


def test_profile_must_be_dev_or_prod(box: Sandbox) -> None:
    for script in ("stack-start", "stack-restart", "stack-rebuild", "review-start"):
        assert box.run(script, "--profile", "staging").returncode == 2


def test_stack_restart_carries_the_running_profile_over_and_switches_it_when_asked(box: Sandbox) -> None:
    box.stack(settings={ops.PROFILE_VARIABLE: "prod"})
    box.dagster.runs()
    assert box.run("stack-restart", "--no-probe").returncode == 0
    assert [call["env"] for call in box.lifecycle_calls()] == [{ops.PROFILE_VARIABLE: "prod"}] * 2
    assert box.run("stack-restart", "--no-probe", "--profile", "dev").returncode == 0
    assert box.lifecycle_calls()[-1]["env"] == {ops.PROFILE_VARIABLE: "dev"}


@pytest.mark.parametrize("profile", ["prod", "copilot-prod"])
def test_changing_the_profile_of_a_running_stack_is_guarded_by_active_runs(box: Sandbox, profile: str) -> None:
    box.dagster.runs(run(UUID_ONE, "STARTED", app=APP_ID))
    assert box.run("stack-restart", "--profile", profile).returncode == 3
    assert box.lifecycle_calls() == []


@pytest.mark.parametrize("profile", ["prod", "copilot-prod"])
def test_stack_rebuild_takes_the_profile(box: Sandbox, profile: str) -> None:
    box.dagster.runs()
    assert box.run("stack-rebuild", "--no-probe", "--profile", profile).returncode == 0
    assert [call["env"][ops.PROFILE_VARIABLE] for call in box.lifecycle_calls()] == [profile, profile]


def test_review_start_selects_the_profile_per_run_within_the_provider_family(box: Sandbox) -> None:
    box.dagster.runs()
    refused = box.run("review-start", "--profile", "copilot-prod", "--dry-run")
    assert refused.returncode == 3 and "stack-restart --profile copilot-prod" in refused.stderr
    assert "profile:   dev (container default)" in box.run("review-start", "--dry-run").stdout
    accepted = box.run("review-start", "--profile", "prod", "--id-wait", "1")
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert "profile:   prod (requested)" in accepted.stdout and "more capable models" in accepted.stdout
    argv = next(call for call in box.docker_calls() if "launch" in call)
    tags = json.loads(argv[argv.index("--tags") + 1])
    assert tags["appsec/profile"] == "prod" and tags["appsec/overlay"] == "none"
    assert review_run.read_submission(box.repo)["identity"]["configuration"]["profile"] == "prod"


def test_review_start_keeps_a_copilot_stack_on_copilot_profiles(box: Sandbox) -> None:
    box.stack(settings={ops.PROFILE_VARIABLE: "copilot-dev"})
    box.dagster.runs()
    refused = box.run("review-start", "--profile", "dev", "--dry-run")
    assert refused.returncode == 3 and "stack-restart --profile dev" in refused.stderr
    copilot = box.run("review-start", "--profile", "copilot-prod", "--dry-run")
    assert copilot.returncode == 0, copilot.stdout + copilot.stderr
    assert "profile:   copilot-prod (requested)" in copilot.stdout
    assert "profile:   copilot-dev (container default)" in box.run("review-start", "--dry-run").stdout


def test_stack_status_shows_the_profile(box: Sandbox) -> None:
    box.dagster.runs()
    assert "profile: dev" in box.run("stack-status").stdout
    box.stack(settings={ops.PROFILE_VARIABLE: "prod"})
    assert "profile: prod" in box.run("stack-status").stdout


@pytest.mark.parametrize("profile", ["copilot-dev", "copilot-prod"])
def test_copilot_stack_keeps_its_overlay_image_and_account_probe(box: Sandbox, profile: str) -> None:
    box.stack(settings={ops.PROFILE_VARIABLE: profile},
              files=[str(box.deploy / "compose.yaml"), str(box.deploy / "compose.copilot.yaml")])
    box.dagster.runs()
    result = box.run("stack-start", "--profile", profile)
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("more capable models" in result.stdout) == (profile == "copilot-prod")
    assert "model catalog  ok" in result.stdout
    assert box.lifecycle_calls()[-1]["env"][ops.PROFILE_VARIABLE] == profile
    assert ops.image_tag(profile).endswith("-copilot")
    stopped = box.run("stack-stop")
    assert stopped.returncode == 0, stopped.stdout + stopped.stderr
    assert box.lifecycle_calls()[-1]["env"][ops.PROFILE_VARIABLE] == profile


@pytest.mark.parametrize("name", ["stack-start", "stack-restart", "stack-rebuild", "review-start"])
def test_powershell_twins_take_a_profile_parameter(name: str) -> None:
    assert "[ValidateSet('dev', 'prod', 'copilot-dev', 'copilot-prod')][string]$Profile" in (SCRIPTS / f"{name}.ps1").read_text(encoding="utf-8")
    assert "--profile" in real(name, "--help").stdout
