import json
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime import engine_broker
from appsec_review.container_runtime.buildkit_worker import EnforcementUnavailable, native_docker_topology
from tests.test_bounded_image_build_service import (
    forbid_real_execution, real_driver_harness,  # noqa: F401
)
from tests.test_native_engine_broker import native  # noqa: F401


NATIVE = {
    "CgroupDriver": "cgroupfs", "CgroupVersion": "2", "OSType": "linux",
    "OperatingSystem": "Ubuntu 22.04.5 LTS", "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
}


def test_client_plugins_and_hostname_do_not_identify_the_server():
    assert native_docker_topology({
        **NATIVE, "Name": "desktop-workstation",
        "ClientInfo": {"Context": "desktop-linux", "Plugins": [
            {"Name": "desktop", "Path": "/usr/local/lib/docker/cli-plugins/docker-desktop",
             "Err": "failed to fetch metadata: input/output error"}]},
    })


@pytest.mark.parametrize("changes", [
    {"CgroupDriver": "systemd"}, {"CgroupVersion": "1"}, {"OSType": "windows"},
    {"OperatingSystem": "Docker Desktop"}, {"OperatingSystem": "DockerDesktop"},
    {"KernelVersion": "6.10.14-linuxkit"},
    {"Labels": ["com.docker.desktop.address=unix:///private/desktop.sock"]},
    {"OperatingSystem": None}, {"KernelVersion": []}, {"Labels": ["ok", 1]},
])
def test_server_topology_and_desktop_markers_still_refuse(changes):
    assert not native_docker_topology({**NATIVE, **changes})


@pytest.mark.parametrize("desktop_server", [False, True])
def test_builder_uses_server_metadata_not_client_plugins(tmp_path, monkeypatch, desktop_server):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, _):
        original = commands.run

        def run(argv, timeout, **kwargs):
            if argv[3:4] == ["info"]:
                value = {**NATIVE, "ClientInfo": {"Plugins": [{"Name": "desktop"}]}}
                if desktop_server:
                    value["OperatingSystem"] = "Docker Desktop"
                return 0, json.dumps(value).encode(), b""
            return original(argv, timeout, **kwargs)

        monkeypatch.setattr(commands, "run", run)
        harness.prepare_context()
        prepared = harness.prepare()
        assert prepared["state"] == ("UNKNOWN" if desktop_server else "PREPARED")
        if desktop_server:
            assert "native local cgroupfs/v2 Docker" in prepared["error"]
        assert harness.request("cleanup")["state"] == "CLEANED"


@pytest.mark.parametrize("desktop_server", [False, True])
def test_native_driver_uses_the_same_server_topology_guard(native, monkeypatch, desktop_server):
    value = {
        **NATIVE, "ID": native.config.native_engine.engine_id, "Architecture": "amd64",
        "ClientInfo": {"Plugins": [{"Name": "desktop"}]},
    }
    if desktop_server:
        value["OperatingSystem"] = "Docker Desktop"
    runner = SimpleNamespace(run=lambda *args, **kwargs: (0, json.dumps(value).encode(), b""))
    proof = SimpleNamespace(host=lambda: {})
    monkeypatch.setattr(engine_broker, "static_gate", lambda config: None)
    monkeypatch.setattr(engine_broker, "private_path", lambda *args, **kwargs: None)
    driver = engine_broker.NativeExecutionDriver(native.config, runner=runner, proof=proof)
    if desktop_server:
        with pytest.raises(EnforcementUnavailable, match="native engine identity"):
            driver.check_host()
    else:
        driver.check_host()
