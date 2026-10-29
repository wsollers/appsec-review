"""Real driver/journal logic with fake process controls; no daemon/cgroup operations."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime import engine_broker as engine
from appsec_review.container_runtime import image_builder_service as services
from appsec_review.runtime import resources
from tests.test_bounded_image_build_service import forbid_real_execution  # noqa: F401
from tests.test_native_engine_broker import native, create_payload, lease, request  # noqa: F401


def test_native_gate_is_executable_under_private_service_umask_and_pid_mode_is_default(
        native, tmp_path, monkeypatch):
    class CreatedCommandReached(Exception):
        pass

    parent = tmp_path / "fake-cgroups"
    parent.mkdir()
    policy = SimpleNamespace(**vars(native.config.native_engine))
    policy.execution_cgroup_parent = str(parent)
    config = SimpleNamespace(**{**vars(native.config), "native_engine": policy})
    gate = tmp_path / "static-gate"
    gate.write_bytes(b"fixture only, never executed")
    monkeypatch.setattr(engine, "static_gate", lambda config: gate)
    driver = engine.NativeExecutionDriver(config, proof=SimpleNamespace(limits=lambda *args: {}))
    monkeypatch.setattr(driver, "_begin", lambda record: None)
    monkeypatch.setattr(driver, "inventory", lambda *args: None)
    monkeypatch.setattr(driver, "image", lambda image: {"Config": {"Env": []}})
    seen = []

    def command(argv):
        seen.append(argv)
        raise CreatedCommandReached()

    monkeypatch.setattr(driver, "_run", command)
    payload, _ = create_payload(native)
    record = {
        "directory": str(tmp_path / "private-control"), "execution_id": payload["execution_id"],
        "execution_token": "a" * 32, "payload": payload, "binding": native.client.contract.binding,
        "driver": {}, "command_policy": asdict(config.native_engine.commands[0]),
        "image_policy": asdict(config.native_engine.images[0]), "mount_policies": [],
    }
    previous = os.umask(0o077)
    try:
        with pytest.raises(CreatedCommandReached):
            driver.create(record, lambda: None)
    finally:
        os.umask(previous)
    directory = Path(record["directory"])
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "gate").stat().st_mode & 0o777 == 0o755
    assert (directory / "gate/gate").stat().st_mode & 0o777 == 0o555
    assert (directory / "gate/launch.bin").stat().st_mode & 0o777 == 0o444
    assert "--pid" not in seen[0]
    assert seen[0][seen[0].index("--ipc") + 1] == "private"
    assert seen[0][seen[0].index("--cgroupns") + 1] == "private"


@pytest.fixture
def pending_create(native, tmp_path, monkeypatch):
    payload, _ = create_payload(native)
    with lease(native):
        resources.track_container(payload["name"])
        created = request(native, "execution.create", payload)
        record = native.broker.get(created["execution_id"])
        parent = tmp_path / "executions"
        group = parent / record["execution_id"]
        group.mkdir(parents=True)
        (group / "cgroup.events").write_text("populated 0\n")
        info = group.stat()
        record.update(state="UNKNOWN", quarantine="native_operation_unconfirmed")
        record["driver"] = {
            "create_pending": True, "cgroup": str(group),
            "cgroup_identity": [info.st_dev, info.st_ino], "cgroup_pending": False,
        }
        native.broker.save(record)
    native.service.close()
    containers = tmp_path / "private-docker/containers"
    containers.mkdir(parents=True)
    policy = SimpleNamespace(**vars(native.config.native_engine))
    policy.execution_cgroup_parent = str(parent)
    config = SimpleNamespace(**{
        **vars(native.config), "docker_helper_scope": SimpleNamespace(data_root=str(containers.parent)),
        "native_engine": policy,
    })
    contract = record["service_contract"]
    monkeypatch.setattr(engine, "service_contract", lambda config: contract)
    monkeypatch.setattr(engine, "private_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, "process_token", lambda pid: None)
    return config, containers, group, record


def test_stopped_private_empty_engine_settles_only_its_exact_prelaunch_intent(pending_create):
    config, _, group, original = pending_create
    engine.confirm_stopped_create_absence(config)
    records, owners = engine._operator_records(config)
    assert owners == 0 and len(records) == 1
    record = records[0]
    assert record["state"] == "REMOVED"
    assert record["resolved_quarantine"] == original["quarantine"]
    assert record["stopped_create_absence"]["private_container_metadata_empty"]
    assert record["removal"]["binding"] == original["binding"]
    assert not record.get("enforcement") and "exit_code" not in record
    assert group.exists()
    proof = engine.EngineCleanupConfirmation(config)
    entry = {
        "containers": [record["payload"]["name"]], "container_cleanup": "removed",
        "native_engine_scope": {**record["binding"], "resource_budget": config.resources.view()},
        "pid": record["peer"]["pid"], "process_identity": record["peer"]["start_token"],
        "quarantine": "native_broker_outcome_unknown",
    }
    assert proof.confirmed_cleanup(entry)


@pytest.mark.parametrize("unsafe", [
    "stopped-container", "live-client", "launched", "released", "changed-group", "populated",
    "foreign-owner", "foreign-run", "no-private-engine", "invalid-execution", "invalid-token",
    "invalid-lease", "changed-contract", "launched-pid", "started",
])
def test_stopped_create_recovery_refuses_incomplete_or_foreign_proof(pending_create, monkeypatch, unsafe):
    config, containers, group, record = pending_create
    original_id = record["execution_id"]
    database = Path(config.state_root) / "intents.sqlite3"
    if unsafe == "stopped-container":
        (containers / ("b" * 64)).mkdir()
    elif unsafe == "live-client":
        monkeypatch.setattr(engine, "process_token", lambda pid: record["peer"]["start_token"])
    elif unsafe == "launched":
        record["driver"]["launch_pending"] = True
    elif unsafe == "released":
        record["driver"]["released"] = True
    elif unsafe == "changed-group":
        record["driver"]["cgroup_identity"][1] += 1
    elif unsafe == "populated":
        (group / "cgroup.events").write_text("populated 1\n")
    elif unsafe == "foreign-run":
        record["binding"]["run_id"] = "foreign"
    elif unsafe == "no-private-engine":
        config.docker_helper_scope = None
    elif unsafe == "invalid-execution":
        record["execution_id"] = "../outside"
    elif unsafe == "invalid-token":
        record["execution_token"] = "invalid"
    elif unsafe == "invalid-lease":
        record["binding"]["lease_id"] = "invalid"
    elif unsafe == "changed-contract":
        record["service_contract"] = {"foreign": True}
    elif unsafe == "launched-pid":
        record["driver"]["launcher"] = {"pid": 4321}
    elif unsafe == "started":
        record["driver"]["started_at"] = 1
    with sqlite3.connect(database) as connection:
        if unsafe == "foreign-owner":
            connection.execute("UPDATE engine_interlock SET owner=?", ('{\"kind\":\"foreign\"}',))
        connection.execute("UPDATE engine_executions SET record=? WHERE id=?",
                           (engine.encoded(record).decode(), original_id))
    with pytest.raises(engine.EnforcementUnavailable):
        engine.confirm_stopped_create_absence(config)
    records, owners = engine._operator_records(config)
    assert records[0]["state"] == "UNKNOWN" and owners == 1


def test_current_operator_release_keeps_original_prior_contract(native, monkeypatch):
    current = replace(native.config, native_engine=replace(
        native.config.native_engine, runtime_root="/new-operator/lib", runtime_release_id="new"))
    seen = []
    monkeypatch.setattr(services, "BuilderAdmission", lambda config: SimpleNamespace(
        release=lambda: seen.append(config)))
    services.release_prior_runtime(current, native.config)
    assert seen == [native.config]


def test_stopped_create_can_settle_an_already_absent_exact_cgroup(pending_create):
    config, _, group, _ = pending_create
    (group / "cgroup.events").unlink()
    group.rmdir()
    engine.confirm_stopped_create_absence(config)
    engine.confirm_stopped_create_absence(config)
    records, owners = engine._operator_records(config)
    assert records[0]["state"] == "REMOVED" and owners == 0


def test_missing_cgroup_does_not_settle_pending_creation(pending_create):
    config, _, group, record = pending_create
    (group / "cgroup.events").unlink()
    group.rmdir()
    record["driver"]["cgroup_pending"] = True
    with sqlite3.connect(Path(config.state_root) / "intents.sqlite3") as connection:
        connection.execute("UPDATE engine_executions SET record=? WHERE id=?",
                           (engine.encoded(record).decode(), record["execution_id"]))
    with pytest.raises(engine.EnforcementUnavailable, match="creation remains unresolved"):
        engine.confirm_stopped_create_absence(config)


def test_lifetime_retains_capacity_until_stopped_proof_precedes_native_settlement(native, monkeypatch):
    native.service.close()
    seen = []

    def settle(config):
        assert native.lifetime._anchor()["state"] == "RESERVED"
        native.lifetime._verify_ledger(native.lifetime._anchor())
        seen.append(config)

    monkeypatch.setattr(engine, "confirm_stopped_create_absence", settle)
    native.lifetime.proof.stopped_result = False
    with pytest.raises(engine.EnforcementUnavailable, match="termination is unconfirmed"):
        native.lifetime.release()
    assert seen == []
    assert native.lifetime._anchor()["state"] == "RESERVED"
    native.lifetime.proof.stopped_result = True
    native.lifetime.release()
    assert seen == [native.config]
    assert native.lifetime._anchor()["state"] == "RELEASED"
    native.lifetime.release()
    assert seen == [native.config]
