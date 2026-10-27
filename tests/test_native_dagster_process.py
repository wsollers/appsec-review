from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from appsec_review.config.native_dagster import NativeDagsterConfig
from appsec_review.orchestration.dagster.native import (
    CONFIG_ENV, IDENTITY_ENV, child_environment, prepare_instance,
)


def configuration(tmp_path):
    return NativeDagsterConfig(
        deployment_id="fixture", repository_root=str(Path.cwd()),
        python_executable=sys.executable, dagster_home=str(tmp_path / "instance"),
        review_config=str(tmp_path / "review.toml"), runtime_profile="copilot-prod",
        engine_contract=str(tmp_path / "engine.toml"), client_uid=max(os.geteuid(), 1),
        postgres_host="127.0.0.1", postgres_port=15432, postgres_database="fixture",
        postgres_user="fixture", postgres_password_env="FIXTURE_POSTGRES_PASSWORD",
        grpc_port=14000, webserver_port=13000)


def save_config(path, config):
    path.write_text("[native_dagster]\n" + "\n".join(
        f"{key} = {json.dumps(value)}" for key, value in asdict(config).items()))
    path.chmod(0o600)
    return path


def test_prepare_native_instance_is_private_immutable_and_does_not_launch(tmp_path, monkeypatch):
    config = configuration(tmp_path)
    path = save_config(tmp_path / "native.toml", config)
    monkeypatch.setattr(os, "geteuid", lambda: config.client_uid)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("preparation launched a process"))
    result = prepare_instance(path)
    assert result["state"] == "PREPARED"
    home = Path(config.dagster_home)
    contents = {item.name: item.read_bytes() for item in home.iterdir()}
    assert set(contents) == {"dagster.yaml", "workspace.yaml", "native-instance.json"}
    assert not home.stat().st_mode & 0o077
    assert all(not item.stat().st_mode & 0o077 for item in home.iterdir())
    assert json.loads(contents["dagster.yaml"]) == config.instance_config()
    assert prepare_instance(path) == result
    assert contents == {item.name: item.read_bytes() for item in home.iterdir()}
    save_config(path, replace(config, runtime_profile="prod"))
    with pytest.raises(RuntimeError, match="drift"):
        prepare_instance(path)
    assert contents == {item.name: item.read_bytes() for item in home.iterdir()}


def test_native_prepare_refuses_occupied_or_interrupted_instance(tmp_path, monkeypatch):
    config = configuration(tmp_path)
    path = save_config(tmp_path / "native.toml", config)
    monkeypatch.setattr(os, "geteuid", lambda: config.client_uid)
    home = Path(config.dagster_home)
    home.mkdir(mode=0o700)
    existing = home / "dagster.yaml"
    existing.write_text("existing-instance")
    with pytest.raises(RuntimeError, match="occupied or incompletely prepared"):
        prepare_instance(path)
    assert existing.read_text() == "existing-instance"


@pytest.mark.parametrize("inherited", [
    {"DOCKER_HOST": ""}, {"DOCKER_CONTEXT": "desktop-linux"}, {"DOCKER_CONFIG": "/credentials"},
    {"APPSEC_NATIVE_UNKNOWN": ""}, {"APPSEC_REVIEW_PROFILE": "dev"},
    {IDENTITY_ENV: "{}"}, {CONFIG_ENV: "/different/config.toml"},
])
def test_native_environment_rejects_ambient_engine_and_identity_drift(tmp_path, monkeypatch, inherited):
    config = configuration(tmp_path)
    path = save_config(tmp_path / "native.toml", config)
    monkeypatch.setattr(os, "geteuid", lambda: config.client_uid)
    with pytest.raises(ValueError):
        child_environment(path, inherited)


@pytest.mark.skipif(os.geteuid() == 0, reason="native run children must be non-root")
@pytest.mark.parametrize("drift", [None, "instance", "namespace"])
def test_actual_native_child_inherits_and_checks_explicit_instance_identity(tmp_path, drift):
    config = configuration(tmp_path)
    path = save_config(tmp_path / "native.toml", config)
    inherited = {key: value for key, value in os.environ.items()
                 if not key.startswith(("DOCKER_", "APPSEC_NATIVE_"))
                 and key not in config.environment()}
    environment = child_environment(path, inherited)
    if drift == "instance":
        environment["DAGSTER_HOME"] = str(tmp_path / "wrong-instance")
    elif drift == "namespace":
        identity = json.loads(environment[IDENTITY_ENV])
        identity["namespaces"]["mnt"] = "mnt:[wrong]"
        environment[IDENTITY_ENV] = json.dumps(identity)
    child = subprocess.run(
        [sys.executable, "-c",
         "from appsec_review.orchestration.dagster.native import validate_child_environment; "
         "print(validate_child_environment().deployment_id)"],
        cwd=config.repository_root, env=environment, capture_output=True, text=True,
        timeout=30, check=False)
    if drift is None:
        assert child.returncode == 0, child.stderr
        assert child.stdout.strip() == config.deployment_id
    else:
        assert child.returncode != 0
        assert "native child" in child.stderr
