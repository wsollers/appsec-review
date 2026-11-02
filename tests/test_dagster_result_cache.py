"""The Garnet result cache is a digest-pinned, internal, fail-open dependency of the code location."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deploy" / "dagster"
sys.path.insert(0, str(DEPLOYMENT / "bin"))
import host  # noqa: E402
import ops  # noqa: E402
import smoke  # noqa: E402

SERVICE = "result-cache"
PASSWORD = "APPSEC_RESULT_CACHE_PASSWORD"
CONFIG_TARGET = "/run/appsec-result-cache/garnet.conf"


def _compose(name: str = "compose.yaml") -> dict:
    return yaml.safe_load((DEPLOYMENT / name).read_text(encoding="utf-8"))


def _requirements(name: str) -> dict[str, str]:
    lines = (DEPLOYMENT / name).read_text(encoding="utf-8").splitlines()
    pins = [line.split("#", 1)[0].strip() for line in lines]
    return dict(pin.split("==", 1) for pin in pins if pin)


def test_result_cache_is_a_digest_pinned_unpublished_bounded_service() -> None:
    cache = _compose()["services"][SERVICE]
    assert re.fullmatch(r"ghcr\.io/microsoft/garnet:2\.2\.5@sha256:[0-9a-f]{64}", cache["image"])
    assert not {"build", "ports", "pull_policy", "volumes"} & set(cache)
    assert cache["cgroup_parent"] == "appsecreview-services.slice"
    assert cache["mem_limit"] == cache["memswap_limit"] == "512m"
    assert cache["cpus"] == 0.5 and cache["pids_limit"] == 256
    assert cache["restart"] == "unless-stopped"
    command = cache["command"]
    assert command[command.index("--config-import-path") + 1] == CONFIG_TARGET
    assert command[command.index("--port") + 1] == "6379" and "--memory" in command
    assert not {"--password", "--auth", "--storage-tier"} & set(command)
    assert "--protected-mode" not in command and "PASSWORD" not in json.dumps(cache["healthcheck"])
    for overlay in ("compose.windows.yaml", "compose.claude.yaml", "compose.copilot.yaml"):
        assert SERVICE not in (_compose(overlay).get("services") or {}), overlay


def test_the_password_reaches_garnet_only_through_a_config_file() -> None:
    compose = _compose()
    cache = compose["services"][SERVICE]
    mount, = cache["configs"]
    assert mount["target"] == CONFIG_TARGET and mount["mode"] == 0o444
    content = compose["configs"][mount["source"]]["content"]
    required = "${APPSEC_RESULT_CACHE_PASSWORD:?Run deploy/dagster/bin/bootstrap.py first}"
    assert json.loads(content.replace(required, "secret")) == {"AuthenticationMode": "Password",
                                                                 "Password": "secret"}
    assert PASSWORD not in json.dumps({key: value for key, value in cache.items() if key != "configs"})


def test_only_the_code_location_gets_the_password_and_it_never_waits_for_cache_health() -> None:
    services = _compose()["services"]
    holders = {name for name, service in services.items() if PASSWORD in (service.get("environment") or {})}
    assert holders == {"code-location"}
    code = services["code-location"]
    assert code["environment"][PASSWORD] == "${APPSEC_RESULT_CACHE_PASSWORD:?Run deploy/dagster/bin/bootstrap.py first}"
    assert code["depends_on"][SERVICE] == {"condition": "service_started", "required": False}
    for name in set(services) - {"code-location"}:
        assert SERVICE not in (services[name].get("depends_on") or {}), name
    assert SERVICE not in host.IMAGE_SERVICES and SERVICE not in ops.SERVICES
    assert ops.OPTIONAL_SERVICES == (SERVICE,) and ops.ALL_SERVICES == ops.SERVICES + ops.OPTIONAL_SERVICES


def _resolved() -> dict:
    services = _compose()["services"]
    resolved = json.loads(json.dumps(services))
    resolved["code-location"]["environment"][PASSWORD] = "0" * 64
    return resolved


def test_smoke_check_accepts_the_shipped_result_cache_contract() -> None:
    smoke.check_result_cache(_resolved())


@pytest.mark.parametrize(("service", "change", "message"), [
    (SERVICE, {"image": "ghcr.io/microsoft/garnet:2.2.5"}, "digest-pinned"),
    (SERVICE, {"build": {"context": "."}}, "never build"),
    (SERVICE, {"ports": [{"target": 6379, "published": "6379"}]}, "host ports"),
    ("code-location", {"environment": {}}, "must receive APPSEC_RESULT_CACHE_PASSWORD"),
    ("code-location", {"depends_on": {SERVICE: {"condition": "service_healthy", "required": False}}}, "fail-open"),
    ("code-location", {"depends_on": {SERVICE: {"condition": "service_started", "required": True}}}, "fail-open"),
])
def test_smoke_check_rejects_a_broken_result_cache_contract(service, change, message) -> None:
    resolved = _resolved()
    resolved[service] = {**resolved[service], **change}
    with pytest.raises(RuntimeError, match=message):
        smoke.check_result_cache(resolved)


def test_env_example_declares_the_cache_secret() -> None:
    assert PASSWORD in host.read_environment(DEPLOYMENT / ".env.example")


def test_redis_client_is_required_and_locked_at_the_same_version() -> None:
    requirements = _requirements("requirements.txt")
    lock = _requirements("requirements.lock.txt")
    assert requirements["redis"] == lock["redis"] == "8.1.0"
    assert {name: lock.get(name) for name in requirements} == requirements


@pytest.fixture
def bootstrap(tmp_path: Path):
    bin_directory = tmp_path / "deploy" / "dagster" / "bin"
    bin_directory.mkdir(parents=True)
    for name in ("bootstrap.py", "host.py"):
        shutil.copy2(DEPLOYMENT / "bin" / name, bin_directory / name)
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path),
                   "APPSEC_COPILOT_HOME": str(tmp_path / "absent")}

    def run() -> dict[str, str]:
        subprocess.run([sys.executable, str(bin_directory / "bootstrap.py")], check=True, capture_output=True,
                       text=True, env=environment, cwd=tmp_path)
        return host.read_environment(bin_directory.parent / ".env")

    return run, bin_directory.parent / ".env"


@pytest.mark.skipif(os.name == "nt", reason="bootstrap records POSIX uid/gid; the WSL/Linux path is covered")
def test_bootstrap_generates_the_cache_secret_once_and_keeps_existing_secrets(bootstrap) -> None:
    run, environment = bootstrap
    first = run()
    assert re.fullmatch(r"[0-9a-f]{64}", first[PASSWORD])
    assert first[PASSWORD] != first["DAGSTER_POSTGRES_PASSWORD"]
    assert run()[PASSWORD] == first[PASSWORD]
    environment.write_text("DAGSTER_POSTGRES_PASSWORD=kept-database\nAPPSEC_REVIEW_TARGET=freeciv\n",
                           encoding="utf-8")
    upgraded = run()
    assert upgraded["DAGSTER_POSTGRES_PASSWORD"] == "kept-database"
    assert upgraded["APPSEC_REVIEW_TARGET"] == "freeciv"
    assert re.fullmatch(r"[0-9a-f]{64}", upgraded[PASSWORD])
    environment.write_text(environment.read_text(encoding="utf-8").replace(upgraded[PASSWORD], "kept-cache"),
                           encoding="utf-8")
    assert run()[PASSWORD] == "kept-cache"
