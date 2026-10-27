from types import SimpleNamespace
from contextlib import contextmanager
import json
import os

import pytest

from appsec_review.orchestration.dagster.native import prepare_instance
from appsec_review.orchestration.dagster.native_lifecycle import NativeSupervisor, active_runs
from appsec_review.container_runtime.buildkit_worker import process_token
from tests.test_native_dagster_process import configuration, save_config


class Ready:
    def __init__(self):
        self.active = False
        self.clean = True
        self.calls = []

    def before_start(self):
        self.calls.append("lifetime-and-storage")
        if self.active:
            raise RuntimeError("active review or sync")

    def connected(self):
        self.calls.append("connected")
        return True

    def before_stop(self):
        self.calls.append("before-stop")
        if self.active:
            raise RuntimeError("active review or sync")

    def shutdown_complete(self):
        return self.clean


@pytest.fixture
def supervisor(tmp_path):
    config = configuration(tmp_path)
    path = save_config(tmp_path / "native.toml", config)
    prepare_instance(path)
    ready, identities, calls = Ready(), {}, []
    controller = None

    def spawn(command, **kwargs):
        state = json.loads(controller.path.read_bytes())
        assert state["state"] == "STARTING" and state["pending"] is not None
        assert ready.calls[0] == "lifetime-and-storage"
        pid = 10000 + len(calls)
        identities[pid] = f"fixture:{pid}"
        calls.append((command, kwargs))
        return SimpleNamespace(pid=pid, poll=lambda: None)

    def terminate(pid, token, signum):
        assert identities[pid] == token
        identities.pop(pid)

    @contextmanager
    def ownership(config):
        ready.calls.append("database-lock")
        yield
        ready.calls.append("database-unlock")

    identity = lambda pid: process_token(pid) if pid == os.getpid() else identities.get(pid)
    controller = NativeSupervisor(path, ready, spawn=spawn, identity=identity,
                                  terminate=terminate, ownership=ownership)
    return controller, ready, identities, calls


def test_native_supervisor_orders_readiness_identity_and_safe_shutdown(supervisor):
    controller, ready, identities, calls = supervisor
    assert controller.start()["state"] == "RUNNING"
    assert len(calls) == 3
    for command, kwargs in calls:
        assert kwargs["cwd"] == controller.config.repository_root
        assert kwargs["env"]["DAGSTER_HOME"] == controller.config.dagster_home
        assert kwargs["env"]["APPSEC_NATIVE_DEPLOYMENT_CONFIG"] == str(controller.config_path)
        assert not command[0].endswith("docker")
    assert set(controller.status()["observed"].values()) == {"RUNNING"}
    with pytest.raises(RuntimeError, match="ownership is retained"):
        controller.start()
    assert controller.stop()["state"] == "STOPPED"
    assert not identities
    assert ready.calls[-1] == "database-unlock"


@pytest.mark.parametrize("block", ["active", "replaced", "descendants"])
def test_native_stop_refuses_active_sync_replaced_pid_or_unconfirmed_descendants(supervisor, block):
    controller, ready, identities, calls = supervisor
    controller.start()
    if block == "active":
        ready.active = True
    elif block == "replaced":
        identities[next(iter(identities))] = "replacement"
    else:
        ready.clean = False
    with pytest.raises(RuntimeError):
        controller.stop()
    assert controller.status()["state"] != "STOPPED"
    if block != "descendants":
        assert len(identities) == 3


def test_native_ambiguous_spawn_retains_intent_and_never_starts_a_second_generation(supervisor):
    controller, ready, identities, calls = supervisor

    def unknown(*args, **kwargs):
        raise OSError("spawn outcome unavailable")

    controller.spawn = unknown
    with pytest.raises(OSError):
        controller.start()
    assert controller.status()["state"] == "UNKNOWN"
    assert controller.status()["pending"] == "code-location"
    with pytest.raises(RuntimeError, match="pending spawn"):
        controller.stop()
    with pytest.raises(RuntimeError, match="ownership is retained"):
        controller.start()


def test_active_run_guard_checks_every_job_not_only_review():
    observed = []
    instance = SimpleNamespace(get_runs=lambda **kwargs: observed.append(kwargs) or ["sync"])
    assert active_runs(instance)
    assert observed[0]["limit"] == 1
    assert observed[0]["filters"].job_name is None
