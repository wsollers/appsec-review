from dataclasses import asdict, replace
import os

import pytest

from appsec_review.config.native_dagster import NativeDagsterConfig, load_native_dagster_config


@pytest.fixture
def native_config(tmp_path):
    return NativeDagsterConfig(
        deployment_id="native-fixture", repository_root=str(tmp_path / "checkout"),
        python_executable=str(tmp_path / "checkout/.venv/bin/python"),
        dagster_home=str(tmp_path / "instance"), review_config=str(tmp_path / "review.toml"),
        runtime_profile="copilot-prod", engine_contract=str(tmp_path / "engine.toml"),
        client_uid=1000, postgres_host="127.0.0.1", postgres_port=15432,
        postgres_database="operator_fixture", postgres_user="appsec",
        postgres_password_env="NATIVE_POSTGRES_PASSWORD", grpc_port=14000, webserver_port=13000)


def test_native_config_preserves_explicit_storage_and_serial_run_contract(native_config):
    instance = native_config.instance_config()
    database = instance["storage"]["postgres"]["postgres_db"]
    assert database == {
        "hostname": "127.0.0.1", "port": 15432, "db_name": "operator_fixture",
        "username": "appsec", "password": {"env": "NATIVE_POSTGRES_PASSWORD"},
        "params": {"connect_timeout": "5", "options": "-c statement_timeout=5000 -c lock_timeout=5000",
                   "keepalives": "1", "keepalives_idle": "2", "keepalives_interval": "1",
                   "keepalives_count": "3", "tcp_user_timeout": "5000"}}
    assert instance["run_coordinator"]["config"]["max_concurrent_runs"] == 1
    assert instance["run_launcher"]["class"] == "DefaultRunLauncher"
    assert instance["compute_logs"]["config"]["base_dir"] == native_config.dagster_home + "/compute-logs"
    assert instance["local_artifact_storage"]["config"]["base_dir"] == native_config.dagster_home + "/artifacts"
    assert native_config.workspace_config()["load_from"][0]["grpc_server"] == {
        "host": "127.0.0.1", "port": 14000, "location_name": "appsec_review"}


def test_native_process_specs_share_only_explicit_instance_and_config(native_config):
    environment = native_config.environment()
    assert environment["DAGSTER_HOME"] == native_config.dagster_home
    assert environment["APPSEC_REVIEW_CONFIG"] == native_config.review_config
    assert environment["APPSEC_REVIEW_PROFILE"] == "copilot-prod"
    assert environment["APPSEC_NATIVE_ENGINE_CONTRACT"] == native_config.engine_contract
    assert "DOCKER_HOST" not in environment and "DOCKER_CONTEXT" not in environment
    commands = native_config.commands()
    assert set(commands) == {"code-location", "scheduler", "webserver"}
    assert commands["code-location"][0] == native_config.python_executable
    assert "-m" in commands["code-location"]
    for name in ("scheduler", "webserver"):
        assert native_config.dagster_home + "/workspace.yaml" in commands[name]
        assert commands[name][0].startswith(native_config.repository_root + "/.venv/bin/")
    assert all("docker" not in command and "/opt/app" not in command for command in commands.values())


@pytest.mark.parametrize("field,value", [
    ("postgres_host", "postgres"), ("postgres_host", "0.0.0.0"), ("postgres_host", True),
    ("client_uid", 0), ("client_uid", True), ("grpc_port", 15432),
    ("webserver_port", 65536), ("postgres_password_env", "literal password"),
    ("dagster_home", "/var/dagster"), ("repository_root", "../checkout"),
    ("engine_contract", "/run/../unsafe"), ("engine_contract", "/run/./unsafe"), ("runtime_profile", ""),
])
def test_native_config_rejects_ambient_or_invalid_bindings(native_config, field, value):
    with pytest.raises(ValueError):
        replace(native_config, **{field: value})


def test_native_config_file_is_closed_and_contains_no_implicit_defaults(native_config, tmp_path):
    import json

    path = tmp_path / "native.toml"
    lines = ["[native_dagster]"]
    for key, value in asdict(native_config).items():
        lines.append(f"{key} = {json.dumps(value)}")
    path.write_text("\n".join(lines))
    assert load_native_dagster_config(path) == native_config
    path.write_text("\n".join([*lines, 'docker_context = "desktop-linux"']))
    with pytest.raises(ValueError, match="unknown"):
        load_native_dagster_config(path)
    path.write_text('[native_dagster]\ndeployment_id = "incomplete"\n')
    with pytest.raises(ValueError, match="incomplete"):
        load_native_dagster_config(path)


@pytest.mark.parametrize("marker", [
    "APPSEC_NATIVE_DEPLOYMENT_ID", "APPSEC_NATIVE_ENGINE_CONTRACT", "APPSEC_NATIVE_UNKNOWN",
])
def test_native_preparation_cannot_silently_enable_ambient_execution(monkeypatch, marker):
    from appsec_review.config.native_dagster import reject_uncommissioned_native_execution

    for name in tuple(os.environ):
        if name.startswith("APPSEC_NATIVE_"):
            monkeypatch.delenv(name)
    reject_uncommissioned_native_execution()
    monkeypatch.setenv(marker, "")
    with pytest.raises(RuntimeError, match="ambient Docker fallback is prohibited"):
        reject_uncommissioned_native_execution()


def test_native_definitions_and_launch_reject_before_loading_or_claiming(monkeypatch):
    from appsec_review.orchestration.dagster import adapter
    from appsec_review.runtime import launch

    def forbidden(*args, **kwargs):
        pytest.fail("uncommissioned native launch reached configuration or application work")

    monkeypatch.setenv("APPSEC_NATIVE_DEPLOYMENT_ID", "fixture")
    monkeypatch.setattr(adapter, "load_config", forbidden)
    with pytest.raises(RuntimeError, match="native execution is unavailable"):
        adapter.build_definitions()
    with pytest.raises(RuntimeError, match="native execution is unavailable"):
        launch.begin(None, None, None, run_id=None, trigger="manual", orchestration={})
