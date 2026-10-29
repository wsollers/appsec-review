from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tomllib

import pytest
import yaml


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "dagster" / "bin"))
import host  # noqa: E402
from host import deployment_profile, provider_overlay, project_name, reject_other_deployments, validate_workspace  # noqa: E402
from host import dagster_url, url_or_default, web_port  # noqa: E402

DEPLOYMENT = Path(__file__).resolve().parents[1] / "deploy" / "dagster"
PORT = "APPSEC_DAGSTER_WEB_PORT"


def test_webserver_host_port_is_configurable_with_unchanged_default() -> None:
    compose = yaml.safe_load((DEPLOYMENT / "compose.yaml").read_text(encoding="utf-8"))
    assert compose["services"]["webserver"]["ports"] == ["127.0.0.1:${APPSEC_DAGSTER_WEB_PORT:-3000}:3000"]
    for overlay in DEPLOYMENT.glob("compose.*.yaml"):
        services = yaml.safe_load(overlay.read_text(encoding="utf-8")).get("services") or {}
        assert all("ports" not in service for service in services.values()), overlay.name
    assert "# APPSEC_DAGSTER_WEB_PORT=3000" in (DEPLOYMENT / ".env.example").read_text(encoding="utf-8")


def test_web_port_defaults_to_3000_and_follows_compose_precedence(tmp_path: Path) -> None:
    environment = tmp_path / ".env"
    assert web_port(environment, {}) == 3000
    assert dagster_url("/graphql", environment, {}) == "http://127.0.0.1:3000/graphql"
    environment.write_text(f"{PORT}=3001\n", encoding="utf-8")
    assert dagster_url("/graphql", environment, {}) == "http://127.0.0.1:3001/graphql"
    assert dagster_url("", environment, {PORT: "13000"}) == "http://127.0.0.1:13000"
    assert web_port(environment, {PORT: ""}) == 3001
    environment.write_text(f"# {PORT}=3001\n{PORT}=\n", encoding="utf-8")
    assert web_port(environment, {}) == 3000


@pytest.mark.parametrize("value", ["0", "65536", "abc", "3000x", "-1", "30 00", "３０００"])
def test_invalid_web_port_is_refused(tmp_path: Path, value: str) -> None:
    with pytest.raises(RuntimeError, match=f"{PORT} must be an integer from 1 to 65535"):
        web_port(None, {PORT: value})
    environment = tmp_path / ".env"
    environment.write_text(f"{PORT}={value}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match=PORT):
        web_port(environment, {})


def test_helper_url_defaults_use_the_port_and_refuse_invalid(monkeypatch, capsys) -> None:
    import argparse

    parser = argparse.ArgumentParser()
    monkeypatch.setenv(PORT, "3002")
    assert url_or_default(parser, None, "/graphql") == "http://127.0.0.1:3002/graphql"
    assert url_or_default(parser, "http://example.invalid:9/graphql", "/graphql") == "http://example.invalid:9/graphql"
    monkeypatch.setenv(PORT, "99999")
    assert url_or_default(parser, "http://127.0.0.1:9", "") == "http://127.0.0.1:9"
    with pytest.raises(SystemExit) as raised:
        url_or_default(parser, None, "")
    assert raised.value.code == 2
    assert f"{PORT} must be an integer from 1 to 65535" in capsys.readouterr().err


def test_ops_default_url_uses_port_unless_url_given(monkeypatch, tmp_path: Path, capsys) -> None:
    import ops

    monkeypatch.setattr(ops, "DEPLOYMENT", tmp_path)
    monkeypatch.delenv("APPSEC_DAGSTER_URL", raising=False)
    monkeypatch.delenv(PORT, raising=False)
    assert ops.default_url() == "http://127.0.0.1:3000/graphql"
    (tmp_path / ".env").write_text(f"{PORT}=3001\n", encoding="utf-8")
    assert ops.default_url() == "http://127.0.0.1:3001/graphql"
    monkeypatch.setenv("APPSEC_DAGSTER_URL", "http://127.0.0.1:9/graphql")
    assert ops.default_url() == "http://127.0.0.1:9/graphql"
    monkeypatch.delenv("APPSEC_DAGSTER_URL")
    monkeypatch.setenv(PORT, "not-a-port")

    def forbidden(_args):
        pytest.fail("an invalid web port reached a command handler")

    monkeypatch.setattr(ops, "cmd_stack_status", forbidden)
    assert ops.main(["stack-status"]) == ops.USAGE
    assert f"{PORT} must be an integer from 1 to 65535" in capsys.readouterr().err


def test_validate_deployment_refuses_invalid_web_port(monkeypatch, tmp_path: Path) -> None:
    environment = tmp_path / ".env"
    environment.write_text(f"APPSEC_DEPLOYMENT_PLATFORM=linux\nAPPSEC_COMPOSE_PROJECT={project_name('linux')}\n"
                           f"{PORT}=70000\n", encoding="utf-8")
    monkeypatch.setattr(host, "actual_platform", lambda: "linux")
    monkeypatch.delenv(PORT, raising=False)
    with pytest.raises(RuntimeError, match=PORT):
        host.validate_deployment(tmp_path, environment, "linux")
    environment.write_text(environment.read_text(encoding="utf-8").replace("70000", "3001"), encoding="utf-8")
    host.validate_deployment(tmp_path, environment, "linux")


def test_application_codeql_runner_has_exact_readonly_host_backing():
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "deploy/dagster/compose.yaml").read_text())
    mounts = compose["services"]["code-location"]["volumes"]
    asset = "containers/tools/codeql/codeql_runner.py"
    matching = [mount for mount in mounts if f":/opt/app/{asset}" in mount]
    assert matching == [f"../../{asset}:/opt/app/{asset}:ro"]
    assert (root / asset).is_file() and not (root / asset).is_symlink()


def test_review_host_preinstalled_runtime_bindings_use_declared_application_runner():
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "appsec-review.toml").read_text())
    settings = config["jobs"]["job_codeql_analysis"]["settings"]
    mappings = settings["preinstalled_runtimes"]
    releases = config["review_policy"]["releases"]
    cpp = config["jobs"]["job_project_build"]["settings"]["profiles"]["native"]
    assert {entry["build_image_id"] for entry in mappings} == {
        settings["source_image_id"], cpp["image_id"]}
    assert len(mappings) == 2
    for entry in mappings:
        assert entry["source_image_id"] == settings["source_image_id"]
        assert entry["runtime_user"] == "1000:1000"
        assert entry["runner_source"] == "application"
        assert entry["codeql_release_id"] == releases["codeql"]
        assert entry["runner_release_id"] == releases["codeql_runner"]


@pytest.mark.parametrize("profile", ["copilot-dev", "copilot-prod"])
def test_copilot_overlay_and_environment_precedence(tmp_path, monkeypatch, profile):
    environment = tmp_path / ".env"
    environment.write_text(f"APPSEC_REVIEW_PROFILE={profile}\n")
    monkeypatch.delenv("APPSEC_REVIEW_PROFILE", raising=False)
    assert deployment_profile(environment) == profile
    for platform in ("wsl", "linux", "windows"):
        assert provider_overlay(platform, profile) == "compose.copilot.yaml"
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "dev")
    assert deployment_profile(environment) == "dev"
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "invalid")
    with pytest.raises(RuntimeError, match="unknown runtime profile"):
        deployment_profile(environment)


def test_projects_have_separate_names() -> None:
    assert project_name("windows") != project_name("wsl")
    assert project_name("wsl") != project_name("linux")


def test_wsl_checkout_must_be_under_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    (tmp_path / "home" / "repo").mkdir(parents=True)
    validate_workspace(tmp_path / "home" / "repo", "wsl")
    with pytest.raises(RuntimeError, match="WSL home"):
        validate_workspace(tmp_path / "mounted" / "repo", "wsl")


def test_start_rejects_other_stack(monkeypatch) -> None:
    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, "appsec-review-dagster-windows\nunrelated-project\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="appsec-review-dagster-windows"):
        reject_other_deployments("wsl")
    reject_other_deployments("windows")


def test_native_markers_refuse_compose_lifecycle_and_ops(monkeypatch, capsys) -> None:
    import lifecycle
    import ops

    monkeypatch.setenv("APPSEC_NATIVE_DEPLOYMENT_ID", "fixture")

    def forbidden(*_args, **_kwargs):
        pytest.fail("prepared native configuration reached a Compose subprocess")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(RuntimeError, match="ambient engine fallback is prohibited"):
        lifecycle.main()
    assert ops.main(["stack-status"]) == ops.REFUSED
    assert "ambient engine fallback is prohibited" in capsys.readouterr().err
