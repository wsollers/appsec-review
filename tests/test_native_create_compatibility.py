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


def _inspected(record, security_options):
    return [{
        "Id": record["driver"]["container_id"], "Image": record["payload"]["image_id"],
        "State": {"Status": "created", "Running": False},
        "Config": {"Labels": {"appsec.native.execution": record["execution_id"],
                              "appsec.native.token": record["execution_token"],
                              "appsec.native.service": record["binding"]["service_generation"]},
                   "User": record["image_policy"]["user"], "Tty": False,
                   "Entrypoint": ["/run/appsec-gate/gate"], "Cmd": None,
                   "WorkingDir": record["payload"]["workdir"]},
        "HostConfig": {"Privileged": False, "Devices": [], "DeviceRequests": None, "CapAdd": None,
                       "CapDrop": ["ALL"], "ReadonlyRootfs": True, "PidMode": "", "IpcMode": "private",
                       "NetworkMode": "none", "CgroupnsMode": "private", "UTSMode": "", "UsernsMode": "",
                       "Sysctls": None, "ExtraHosts": None, "Links": None, "PortBindings": {},
                       "PublishAllPorts": False, "Tmpfs": {}, "Ulimits": [],
                       "LogConfig": {"Type": "none", "Config": {}}, "SecurityOpt": security_options},
        "Mounts": [{"Type": "bind", "Source": record["driver"]["mounts"][0]["source"],
                    "Destination": "/run/appsec-gate", "Mode": "", "RW": False, "Propagation": "rprivate"}],
    }]


@pytest.fixture
def created_record(native, tmp_path, monkeypatch):
    payload, _ = create_payload(native)
    payload = {**payload, "network": "none", "tmpfs": [], "fsize_bytes": None}
    profile = {"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1,
               "syscalls": [{"action": "SCMP_ACT_ALLOW", "names": ["read", "ptrace"]}]}
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text(json.dumps(profile, indent=2))
    record = {
        "execution_id": payload["execution_id"], "execution_token": "a" * 32, "payload": payload,
        "binding": native.client.contract.binding, "image_policy": asdict(native.config.native_engine.images[0]),
        "driver": {"container_id": "c" * 64, "seccomp": str(seccomp), "mounts": [
            {"source": str(tmp_path / "gate"), "destination": "/run/appsec-gate", "read_only": True}]},
    }
    driver = engine.NativeExecutionDriver(native.config, proof=SimpleNamespace())
    inspection = {}

    def command(argv):
        if argv[-3:-1] == ["container", "inspect"] or "inspect" in argv:
            return json.dumps(inspection["value"]).encode()
        return (record["driver"]["container_id"] + "\n").encode()

    monkeypatch.setattr(driver, "_run", command)
    return SimpleNamespace(driver=driver, record=record, profile=profile, inspection=inspection)


def test_native_inspection_accepts_docker_cli_inlined_seccomp_profile(created_record):
    # Docker CLI reads --security-opt seccomp=<file> and stores the compacted content, not the path.
    inline = json.dumps(created_record.profile, separators=(",", ":"))
    created_record.inspection["value"] = _inspected(
        created_record.record, ["no-new-privileges:true", "seccomp=" + inline])
    assert created_record.driver._inspect_native(created_record.record)["Id"] == "c" * 64


@pytest.mark.parametrize("options", [
    lambda record, profile: ["no-new-privileges:true", "seccomp=" + record["driver"]["seccomp"]],
    lambda record, profile: ["no-new-privileges:true", "seccomp=unconfined"],
    lambda record, profile: ["no-new-privileges:true", "seccomp=" + json.dumps(
        {**profile, "defaultAction": "SCMP_ACT_ALLOW"})],
    lambda record, profile: ["no-new-privileges:true", "seccomp=" + json.dumps(
        {**profile, "defaultErrnoRet": True})],
    lambda record, profile: ["seccomp=" + json.dumps(profile)],
    lambda record, profile: ["no-new-privileges:true", "seccomp=" + json.dumps(profile),
                             "apparmor=unconfined"],
    lambda record, profile: None,
])
def test_native_inspection_rejects_any_other_seccomp_or_security_options(created_record, options):
    created_record.inspection["value"] = _inspected(
        created_record.record, options(created_record.record, created_record.profile))
    with pytest.raises(engine.EnforcementUnavailable):
        created_record.driver._inspect_native(created_record.record)


def test_native_inspection_with_lost_profile_is_unknown_not_accepted(created_record):
    created_record.inspection["value"] = _inspected(
        created_record.record, ["no-new-privileges:true", "seccomp=" + json.dumps(created_record.profile)])
    Path(created_record.record["driver"]["seccomp"]).unlink()
    with pytest.raises(engine.OutcomeUnknown):
        created_record.driver._inspect_native(created_record.record)


def test_prior_engine_reconcile_runs_serve_restart_cleanup_under_prior_contract(native, monkeypatch):
    current = replace(native.config, native_engine=replace(
        native.config.native_engine, runtime_root="/new-operator/lib", runtime_release_id="new"))
    calls = []
    admission = SimpleNamespace(verify=lambda: calls.append("verify"))
    monkeypatch.setattr(services, "prior_runtime_admission", lambda config, prior: (
        calls.append(("admission", config, prior)) or admission))

    class Service:
        def __init__(self, config, *, admission):
            calls.append(("service", config, admission))
            self.driver = SimpleNamespace(proof=SimpleNamespace(host=lambda: calls.append("host")))
            self.engine_broker = SimpleNamespace(
                driver=SimpleNamespace(check_host=lambda: calls.append("engine")),
                records=lambda: [{"execution_id": "e", "state": "REMOVED", "removal": {}}])

        def reconcile(self, *, restart):
            calls.append(("reconcile", restart))

        def close(self):
            calls.append("close")

    monkeypatch.setattr(services, "ImageBuilderService", Service)
    monkeypatch.setattr(services.os, "geteuid", lambda: 0)
    assert services.reconcile_prior_engine(current, native.config) == [
        {"execution_id": "e", "state": "REMOVED", "quarantine": None}]
    assert calls == [("admission", current, native.config), ("service", native.config, admission),
                     "verify", "host", "engine", ("reconcile", True), "close"]


def test_prior_engine_reconcile_refuses_policy_change_and_always_releases_service(native, monkeypatch):
    changed = replace(native.config, native_engine=replace(
        native.config.native_engine, runtime_release_id="new", engine_generation="other"))
    with pytest.raises(engine.EnforcementUnavailable, match="cannot change"):
        services.reconcile_prior_engine(changed, native.config)
    closed = []
    monkeypatch.setattr(services, "prior_runtime_admission", lambda config, prior: SimpleNamespace(
        verify=lambda: (_ for _ in ()).throw(engine.EnforcementUnavailable("not reserved"))))
    monkeypatch.setattr(services, "ImageBuilderService", lambda config, admission: SimpleNamespace(
        engine_broker=object(), close=lambda: closed.append(True)))
    monkeypatch.setattr(services.os, "geteuid", lambda: 0)
    with pytest.raises(engine.EnforcementUnavailable, match="not reserved"):
        services.reconcile_prior_engine(native.config, native.config)
    assert closed == [True]


class _CreateReached(Exception):
    pass


@pytest.fixture
def mount_create(native, tmp_path, monkeypatch):
    parent = tmp_path / "fake-cgroups"
    parent.mkdir()
    policy = SimpleNamespace(**vars(native.config.native_engine))
    policy.execution_cgroup_parent = str(parent)
    config = SimpleNamespace(**{**vars(native.config), "native_engine": policy})
    gate = tmp_path / "static-gate"
    gate.write_bytes(b"fixture only, never executed")
    monkeypatch.setattr(engine, "static_gate", lambda config: gate)
    monkeypatch.setattr(engine, "private_path", lambda *args, **kwargs: None)
    driver = engine.NativeExecutionDriver(config, proof=SimpleNamespace(limits=lambda *args: {}))
    monkeypatch.setattr(driver, "_begin", lambda record: None)
    monkeypatch.setattr(driver, "inventory", lambda *args: None)
    monkeypatch.setattr(driver, "image", lambda image: {"Config": {"Env": []}})
    seen = []

    def command(argv):
        seen.append(argv)
        raise _CreateReached()

    monkeypatch.setattr(driver, "_run", command)
    root = tmp_path / "mount-root"
    root.mkdir()
    payload, _ = create_payload(native)

    def build(relative):
        return {
            "directory": str(tmp_path / "private-control"), "execution_id": payload["execution_id"],
            "execution_token": "a" * 32, "payload": payload, "binding": native.client.contract.binding,
            "driver": {}, "command_policy": asdict(config.native_engine.commands[0]),
            "image_policy": asdict(config.native_engine.images[0]), "peer": {"uid": os.getuid()},
            "mount_policies": [{"mount_id": "scratch", "source_root": str(root), "destination": "/scratch",
                                "kind": "run", "read_only": False, "relative_path": relative}],
        }

    yield SimpleNamespace(driver=driver, seen=seen, root=root, build=build)
    for descriptors in driver.handles.values():
        for descriptor in descriptors:
            os.close(descriptor)


def _bind_options(argv):
    return [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]


@pytest.mark.parametrize("relative", [".", "work", "work/nested"])
def test_native_create_binds_real_host_path_never_proc_descriptor(mount_create, relative):
    (mount_create.root / "work/nested").mkdir(parents=True)
    record = mount_create.build(relative)
    with pytest.raises(_CreateReached):
        mount_create.driver.create(record, lambda: None)
    expected = str(mount_create.root) if relative == "." else str(mount_create.root / relative)
    info = os.stat(expected)
    pinned = record["driver"]["mounts"][1]
    assert pinned["source"] == expected
    assert pinned["identity"] == [info.st_dev, info.st_ino]
    options = _bind_options(mount_create.seen[0])
    assert f"type=bind,source={expected},target=/scratch" in options
    assert not any("/proc/" in option for option in options)


def test_native_create_binds_single_link_regular_file_by_real_path(mount_create):
    source = mount_create.root / "input.bin"
    source.write_bytes(b"fixture")
    record = mount_create.build("input.bin")
    with pytest.raises(_CreateReached):
        mount_create.driver.create(record, lambda: None)
    info = source.stat()
    assert info.st_nlink == 1
    assert record["driver"]["mounts"][1]["source"] == str(source)
    assert record["driver"]["mounts"][1]["identity"] == [info.st_dev, info.st_ino]
    assert f"type=bind,source={source},target=/scratch" in _bind_options(mount_create.seen[0])


@pytest.mark.parametrize("relative", ["link/inner", "final"])
def test_native_create_rejects_intermediate_or_final_symlink(mount_create, relative):
    (mount_create.root / "real/inner").mkdir(parents=True)
    (mount_create.root / "link").symlink_to(mount_create.root / "real")
    (mount_create.root / "final").symlink_to(mount_create.root / "real")
    with pytest.raises((OSError, engine.EnforcementUnavailable)):
        mount_create.driver.create(mount_create.build(relative), lambda: None)
    assert mount_create.seen == []


def test_native_create_aborts_when_source_is_swapped_before_create(mount_create, monkeypatch):
    work = mount_create.root / "work"
    work.mkdir()
    original = mount_create.driver._pin_mount
    calls = []

    def swapped(policy, relative, uid):
        calls.append(relative)
        if len(calls) == 2:
            work.rename(mount_create.root / "moved")
            work.mkdir()
        return original(policy, relative, uid)

    monkeypatch.setattr(mount_create.driver, "_pin_mount", swapped)
    record = mount_create.build("work")
    with pytest.raises(engine.EnforcementUnavailable, match="changed before create"):
        mount_create.driver.create(record, lambda: None)
    assert calls == ["work", "work"]
    assert mount_create.seen == []
    assert len(mount_create.driver.handles[record["execution_id"]]) == 1


def test_native_create_rejects_unsafe_mount_option_characters_after_policy(mount_create):
    unsafe = mount_create.root / "a,readonly=false"
    unsafe.mkdir()
    with pytest.raises(engine.EnforcementUnavailable, match="unsafe"):
        mount_create.driver.create(mount_create.build(unsafe.name), lambda: None)
    assert mount_create.seen == []


@pytest.mark.parametrize("relative", ["a,b", "a=b", "a\nb", 'a"b', "a\x7fb", "a\tb"])
def test_broker_rejects_mount_subpath_unsafe_for_bind_options(native, relative):
    payload, _ = create_payload(native)
    payload["mounts"] = [{"mount_id": "scratch", "relative_path": relative}]
    with lease(native):
        resources.track_container(payload["name"])
        with pytest.raises(PermissionError, match="not normalized"):
            request(native, "execution.create", payload)
        assert "create" not in native.engine.calls
        resources.container_stopped(payload["name"])


def test_native_inspection_compares_bind_against_recorded_real_path(created_record, tmp_path):
    record = created_record.record
    real = tmp_path / "run-root/work"
    record["driver"]["mounts"].append(
        {"source": str(real), "destination": "/scratch", "read_only": False, "identity": [1, 2]})
    inspection = _inspected(record, ["no-new-privileges:true", "seccomp=" + json.dumps(created_record.profile)])
    bind = {"Type": "bind", "Source": str(real), "Destination": "/scratch", "Mode": "", "RW": True,
            "Propagation": "rprivate"}
    inspection[0]["Mounts"].append(bind)
    created_record.inspection["value"] = inspection
    assert created_record.driver._inspect_native(record)["Id"] == "c" * 64
    bind["Source"] = str(tmp_path / "substituted")
    with pytest.raises(engine.EnforcementUnavailable):
        created_record.driver._inspect_native(record)


def _identity(path):
    value = os.stat(path, follow_symlinks=False)
    return [value.st_dev, value.st_ino]


@pytest.fixture
def fake_proc_root(tmp_path):
    root = tmp_path / "proc-root"
    (root / "run/appsec-gate").mkdir(parents=True)
    (root / "work/input.txt").parent.mkdir(parents=True)
    (root / "work/input.txt").write_text("fixture")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_text("host")
    return SimpleNamespace(root=root, outside=outside)


@pytest.mark.parametrize("destination", ["/run/appsec-gate", "/work/input.txt"])
def test_contained_identity_matches_directory_and_file_destinations(fake_proc_root, destination):
    expected = _identity(fake_proc_root.root / destination[1:])
    assert engine.contained_identity(str(fake_proc_root.root), destination) == expected
    descriptor = os.open(fake_proc_root.root, os.O_PATH | os.O_DIRECTORY)
    try:
        assert engine.contained_identity(descriptor, destination) == expected
        os.fstat(descriptor)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("link, target, destination", [
    ("final", "outside/file", "/final"), ("middle", "outside", "/middle/file"),
    ("relative", "run/appsec-gate", "/relative"), ("absolute", "/", "/absolute/etc")])
def test_contained_identity_never_follows_image_symlinks(fake_proc_root, link, target, destination):
    if not target.startswith("/"):
        target = str(fake_proc_root.root.parent / target) if target.startswith("outside") else target
    os.symlink(target, fake_proc_root.root / link)
    with pytest.raises(engine.EnforcementUnavailable):
        engine.contained_identity(str(fake_proc_root.root), destination)


@pytest.mark.parametrize("destination", ["/run/../work", "/run//appsec-gate", "/run/", "run", "/./run"])
def test_contained_identity_rejects_unnormalized_destinations(fake_proc_root, destination):
    with pytest.raises(engine.EnforcementUnavailable):
        engine.contained_identity(str(fake_proc_root.root), destination)


def test_contained_identity_reports_mismatch_against_pinned_identity(fake_proc_root):
    observed = engine.contained_identity(str(fake_proc_root.root), "/work/input.txt")
    assert observed != _identity(fake_proc_root.outside / "file")


def test_mount_points_decode_escaped_fields():
    mountinfo = (
        "1 0 8:1 / / ro,relatime - overlay overlay rw\n"
        "2 1 8:1 /host/run\\040dir /run/appsec\\040gate ro,nosuid - ext4 /dev/sda1 rw\n"
        "3 1 0:5 / /scratch rw - tmpfs tmpfs rw\n")
    points = engine.mount_points(mountinfo)
    assert "/run/appsec gate" in points and "/scratch" in points
    assert "/run/appsec\\040gate" not in points and "/absent" not in points


@pytest.fixture
def gated_start(native, tmp_path, monkeypatch):
    directory = tmp_path / "private-control"
    (directory / "gate").mkdir(parents=True)
    commands, events = [], []
    command = SimpleNamespace(finished=True)
    runner = SimpleNamespace(
        start=lambda argv, capture_limit: events.append(("start", argv)) or command,
        launcher=lambda command: {"pid": 2**31 - 1, "start_token": "boot:1"},
        stop=lambda command: events.append("stop"))
    proof = SimpleNamespace(execution=lambda inspection, record: {"proved": True},
                            stop_launcher=lambda launcher, timeout: True)
    driver = engine.NativeExecutionDriver(native.config, runner=runner, proof=proof)
    present = {"value": True}
    inspection = {"Id": "c" * 64, "State": {"Running": True, "StartedAt": "2026-10-29T00:00:00Z"}}
    monkeypatch.setattr(driver, "_begin", lambda record: None)
    monkeypatch.setattr(driver, "inventory", lambda *args: None)
    monkeypatch.setattr(driver, "check_host", lambda: None)
    monkeypatch.setattr(driver, "_drain", lambda record, save: None)
    monkeypatch.setattr(driver, "_network", lambda record=None: None)
    monkeypatch.setattr(driver, "_empty_group", lambda record: True)
    monkeypatch.setattr(driver, "_inspect_native", lambda record: inspection if present["value"] else None)

    def run(argv):
        commands.append(argv[3:])
        if argv[3:5] == ["container", "rm"]:
            present["value"] = False
        return b""

    monkeypatch.setattr(driver, "_run", run)
    record = {"directory": str(directory), "execution_id": "e" * 32, "execution_token": "a" * 32,
              "payload": {"network": "none"}, "driver": {"container_id": "c" * 64}}
    return SimpleNamespace(driver=driver, record=record, commands=commands, proof=proof,
                           release=directory / "gate/release.token", directory=directory)


def test_native_start_releases_gate_only_after_verified_execution(gated_start):
    gated_start.driver.start(gated_start.record, lambda: None)
    assert gated_start.release.read_text() == "a" * 32
    assert gated_start.record["driver"]["released"] is True
    assert gated_start.record["enforcement"] == {"proved": True}
    assert not any(argv[1] in {"kill", "rm"} for argv in gated_start.commands)


def test_native_start_kills_gated_container_when_verification_fails(gated_start):
    def unproved(inspection, record):
        raise engine.EnforcementUnavailable("native bind mount identity changed")

    gated_start.proof.execution = unproved
    descriptor = os.open(gated_start.directory, os.O_RDONLY | os.O_DIRECTORY)
    gated_start.driver.handles[gated_start.record["execution_id"]] = [descriptor]
    with pytest.raises(engine.EnforcementUnavailable):
        gated_start.driver.start(gated_start.record, lambda: None)
    assert gated_start.commands == [["container", "kill", "--signal", "KILL", "c" * 64],
                                    ["container", "rm", "--force", "c" * 64]]
    assert not gated_start.release.exists()
    assert not gated_start.release.with_suffix(".pending").exists()
    assert not gated_start.record["driver"].get("released")
    os.fstat(descriptor)
    assert gated_start.driver.remove(gated_start.record, lambda: None) is True
    with pytest.raises(OSError):
        os.fstat(descriptor)
    assert gated_start.driver.remove(gated_start.record, lambda: None) is True
    assert not any(argv[1] == "rm" for argv in gated_start.commands[2:])


def test_native_start_abort_is_best_effort_when_kill_fails(gated_start, monkeypatch):
    def unproved(inspection, record):
        raise engine.OutcomeUnknown("native gate has no resolving PID")

    gated_start.proof.execution = unproved
    original = gated_start.driver._run

    def failing(argv):
        original(argv)
        if argv[3:5] == ["container", "kill"]:
            raise RuntimeError("bounded worker command failed: not running")
        return b""

    monkeypatch.setattr(gated_start.driver, "_run", failing)
    with pytest.raises(engine.OutcomeUnknown):
        gated_start.driver.start(gated_start.record, lambda: None)
    assert [argv[1] for argv in gated_start.commands] == ["kill", "rm"]
    assert not gated_start.release.exists()