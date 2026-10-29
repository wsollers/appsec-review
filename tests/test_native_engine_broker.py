"""Real broker journal/client/lease control with a fake engine; no privileged operations."""
import base64
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from appsec_review.config.native_engine import (
    NativeArgument, NativeCommand, NativeEngineConfig, NativeGrant, NativeImage, NativeMount, NativeTmpfs,
)
from appsec_review.container_runtime.builder_admission import BuilderAdmission
from appsec_review.container_runtime.engine_broker import EngineBroker, encoded, SCHEMA
from appsec_review.container_runtime.image_builder_service import ImageBuilderService, Peer
from appsec_review.container_runtime.native_client import NativeClient, NativeClientContract
from appsec_review.runtime import resources
from appsec_review.runtime.resources import Reservation, ResourceAdmission, process_identity
from tests.test_bounded_image_build_service import (
    BASE, FakeDriver, FakeLifetimeProof, configuration, forbid_real_execution,  # noqa: F401
)


class FakeEngine:
    def __init__(self):
        self.broker = None
        self.calls = []
        self.confirmed = True
        self.unrelated_stopped = False

    def check_host(self):
        self.calls.append("host")

    def inventory(self, record=None):
        if self.unrelated_stopped:
            raise RuntimeError("unrelated stopped container")

    def image(self, image_id, reference=None):
        self.calls.append("image")
        return {"Id": image_id}

    def create(self, record, save):
        assert self.broker.get(record["execution_id"])["create_dispatched"]
        assert self.broker.interlock.owner() is not None
        self.inventory()
        self.calls.append("create")
        record["driver"]["container_id"] = "f" * 64
        save()

    def start(self, record, save):
        assert self.broker.get(record["execution_id"])["state"] == "STARTING"
        self.calls.append("start")
        record["enforcement"] = {"fixture": True}
        save()

    def status(self, record, save):
        self.calls.append("status")
        return {"state": "EXITED", "exit_code": 0}

    def cancel(self, record, save):
        self.calls.append("cancel")
        return self.confirmed

    def remove(self, record, save):
        assert self.broker.get(record["execution_id"])["state"] == "REMOVING"
        self.calls.append("remove")
        return self.confirmed

    def logs(self, record, stream, offset, maximum, save):
        value = b"fixture result" if stream == "stdout" else b""
        data = value[offset:offset + maximum]
        return {"stream": stream, "offset": offset, "next_offset": offset + len(data),
                "data_b64": base64.b64encode(data).decode(), "captured_bytes": len(value),
                "observed_bytes": len(value), "total_bytes": len(value), "truncated": False,
                "eof": offset + len(data) == len(value), "complete": True}


@pytest.fixture
def native(tmp_path, request):
    config, context = configuration(tmp_path)
    engine_domain = getattr(request, "param", False) == "engine-domain"
    target = tmp_path / "target"
    target.mkdir()
    native = NativeEngineConfig(
        endpoint=str(tmp_path / "broker.sock"), service_generation="1" * 32,
        engine_id="engine-fixture", engine_generation="1234:boot:1",
        execution_cgroup_parent="/sys/fs/cgroup/native-executions",
        gate_binary="/operator/gate", gate_release_id="gate-1",
        runtime_python="/operator/python", runtime_root="/operator/lib", runtime_release_id="runtime-1",
        syscall_allowlist=("read", "write", "exit_group"),
        images=(NativeImage(BASE, "image-1", f"{os.getuid()}:{os.getgid()}", ("python",),
                            aliases=("base:release",),
                            allow_derived=getattr(request, "param", False) is True or engine_domain),),
        commands=(NativeCommand("python", "/usr/bin/python3", arguments=(NativeArgument("literal",
                                  values=("worker.py",)),), environment_keys=("HOME",)),),
        grants=(NativeGrant(os.getuid(), "tenant", "project", "run-one", "target-one", "config-1",
                            str(context.run_root), str(target), (BASE,), ("target", "scratch")),),
        mounts=(NativeMount("target", str(target), "/target", "target"),
                NativeMount("scratch", str(context.run_root), "/scratch", "run", False)),
        tmpfs=(NativeTmpfs("/tmp", 1024),))
    config = replace(config, native_engine=native)
    if engine_domain:
        from appsec_review.config.image_builder_service import DockerHelperScope, EngineDomainConfig

        metadata = tmp_path / "engine-metadata"
        metadata.mkdir(mode=0o700)
        config = replace(
            config, resource_mode="concurrency_only", lifetime_domain="engine",
            host_cgroup="/sys/fs/cgroup/engine-domain/builder",
            docker_helper_scope=DockerHelperScope("/var/lib/builder-private", "/run/builder-private"),
            native_engine=replace(native, application_cgroup="/sys/fs/cgroup/application-private"),
            engine_domain=EngineDomainConfig(str(metadata), "/sys/fs/cgroup/engine-domain",
                                            ("/sys/fs/cgroup/engine-domain/docker.service",
                                             "/sys/fs/cgroup/engine-domain/containerd.service")))
        context.review_policy = replace(context.review_policy, image_builder=replace(
            context.review_policy.image_builder, resource_mode="concurrency_only", lifetime_domain="engine"))
    lifetime = BuilderAdmission(config, proof=FakeLifetimeProof(config))
    if engine_domain:
        class DomainProof:
            enough = True

            def groups(self):
                return {"engine": {"path": config.engine_domain.cgroup, "device": 1, "inode": 123}}

            def live(self):
                if not self.enough:
                    raise RuntimeError("engine headroom is insufficient")

        lifetime.engine_admission.proof = DomainProof()
    lifetime.reserve()
    service = ImageBuilderService(config, driver=FakeDriver(), admission=lifetime)
    if engine_domain:
        from tests.test_bounded_image_build_service import concurrency_only_observations
        service.driver.limits = concurrency_only_observations()
    service.driver.service = service
    engine = FakeEngine()
    broker = EngineBroker(service, driver=engine)
    service.engine_broker = broker
    engine.broker = broker
    binding = {key: getattr(native.grants[0], key) for key in (
        "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id")}
    binding.update({key: getattr(native, key) for key in (
        "service_generation", "engine_id", "engine_generation")})
    contract = NativeClientContract(
        native.endpoint, str(context.metadata_root), str(context.run_root), str(target),
        os.getuid(), os.getgid(), os.getpid(), process_identity(os.getpid()), binding, config.resources,
        tuple({key: getattr(mount, key) for key in ("mount_id", "source_root", "destination", "read_only")}
              for mount in native.mounts), {"python3": "/usr/bin/python3"})
    client = NativeClient(contract)
    peer = Peer(os.getpid(), os.getuid(), os.getgid(), process_identity(os.getpid()))
    value = SimpleNamespace(config=config, context=context, service=service, engine=engine,
                            broker=broker, client=client, peer=peer, lifetime=lifetime)
    yield value
    service.close()


def message(native, action, payload, nonce=None):
    return encoded({"schema": SCHEMA, "request_id": nonce or uuid4().hex, "action": action,
                    "binding": native.client.binding(), "payload": payload})


def request(native, action, payload, nonce=None):
    return json.loads(native.broker.dispatch(message(native, action, payload, nonce), native.peer))["result"]


def lease(native):
    admission = ResourceAdmission(native.context.metadata_root, native.config.resources,
                                  require_container_removal=True)
    return admission.reserve(Reservation(2, 4608), events=native.context.events, action="native.fixture")


def create_payload(native):
    from tests.test_native_commands import command
    from appsec_review.container_runtime.native_commands import parse_native_command

    argv = command()
    argv[argv.index("--name") + 1] = "appsec-" + uuid4().hex[:20]
    argv[argv.index("--user") + 1] = f"{os.getuid()}:{os.getgid()}"
    for index, value in enumerate(argv):
        if value.startswith("type=bind,src=/fixture/target"):
            argv[index] = f"type=bind,src={native.client.contract.target_root},dst=/target,readonly"
        if value.startswith("type=bind,src=/fixture/run"):
            argv[index] = f"type=bind,src={native.client.contract.run_root},dst=/scratch"
    return native.client._create(parse_native_command(argv)), argv


def test_native_client_to_broker_uses_real_lease_and_intent_before_engine(native, monkeypatch):
    _, argv = create_payload(native)
    monkeypatch.setattr(native.client, "request",
                        lambda action, payload, **kw: request(native, action, payload))
    with lease(native):
        outcome = native.client.run(argv, 30)
        assert outcome == (0, b"fixture result", b"", False)
        name = argv[argv.index("--name") + 1]
        assert native.broker.interlock.owner() is not None
        assert native.client.run(("docker", "rm", "--force", name), 30)[0] == 0
        assert native.client.run(("docker", "container", "inspect", name,
                                 "--format", "{{.State.Running}}"), 30)[2] == (
                                     f"Error: No such container: {name}".encode())
        resources.container_stopped(name)
        assert native.broker.interlock.owner() is None
    leases = json.loads((native.context.metadata_root / "resource-admission/leases.json").read_text())["leases"]
    assert set(leases) == {native.config.admission.lease_id}
    assert native.engine.calls.count("create") == 1
    assert native.engine.calls.count("start") == 1


@pytest.mark.parametrize("field,value", [
    ("cpu", 9), ("memory_mb", 99999), ("pids", 99999), ("network", "host"),
    ("executable", "/bin/sh"), ("environment", {"DOCKER_HOST": "unix:///socket"}),
    ("mounts", [{"mount_id": "scratch", "relative_path": "../outside"}]),
    ("arguments", ["unapproved.py"]), ("fsize_bytes", 2**63),
])
def test_broker_rejects_client_selected_policy_expansion(native, field, value):
    payload, _ = create_payload(native)
    payload[field] = value
    with lease(native):
        resources.track_container(payload["name"])
        with pytest.raises((ValueError, PermissionError, RuntimeError)):
            request(native, "execution.create", payload)
        assert "create" not in native.engine.calls
        resources.container_stopped(payload["name"])


@pytest.mark.parametrize("field", ["lease_id", "configuration_id", "engine_generation", "service_generation"])
def test_broker_rejects_cross_lease_config_or_engine_generation(native, field):
    with lease(native):
        raw = json.loads(message(native, "image.inspect", {"reference": "base:release"}))
        raw["binding"][field] = "f" * 32
        with pytest.raises((PermissionError, RuntimeError)):
            native.broker.dispatch(encoded(raw), native.peer)
        assert "image" not in native.engine.calls


def test_broker_nonce_replay_does_not_duplicate_creation(native):
    payload, _ = create_payload(native)
    with lease(native):
        resources.track_container(payload["name"])
        nonce = uuid4().hex
        first = request(native, "execution.create", payload, nonce)
        assert request(native, "execution.create", payload, nonce) == first
        assert native.engine.calls.count("create") == 1
        result = request(native, "execution.remove",
                         {key: first[key] for key in ("execution_id", "execution_token")})
        assert result["state"] == "REMOVED"
        resources.container_stopped(payload["name"])


def test_cleanup_has_reserved_messages_after_execution_request_budget_exhaustion(native):
    payload, _ = create_payload(native)
    with lease(native):
        resources.track_container(payload["name"])
        created = request(native, "execution.create", payload)
        reference = {key: created[key] for key in ("execution_id", "execution_token")}
        record = native.broker.get(created["execution_id"])
        record["request_count"] = native.config.native_engine.max_requests_per_execution
        native.broker.save(record)
        with pytest.raises(RuntimeError, match="message bound exhausted"):
            request(native, "execution.status", reference)
        nonce = uuid4().hex
        assert request(native, "execution.cancel", reference, nonce)["state"] == "STOPPED"
        assert request(native, "execution.cancel", reference, nonce)["state"] == "STOPPED"
        with pytest.raises(RuntimeError, match="original request nonce"):
            request(native, "execution.cancel", reference)
        assert request(native, "execution.remove", reference)["state"] == "REMOVED"
        assert native.broker.interlock.owner() is None
        resources.container_stopped(payload["name"])


def test_client_confirmed_removal_does_not_need_another_exhausted_status_request(native, monkeypatch):
    payload, _ = create_payload(native)
    monkeypatch.setattr(native.client, "request",
                        lambda action, payload, **kw: request(native, action, payload, kw.get("request_id")))
    with lease(native):
        resources.track_container(payload["name"])
        created = request(native, "execution.create", payload)
        native.client.executions[payload["name"]] = created
        record = native.broker.get(created["execution_id"])
        record["request_count"] = native.config.native_engine.max_requests_per_execution
        native.broker.save(record)
        assert native.client.run(("docker", "rm", "--force", payload["name"]), 30)[0] == 0
        assert native.client.run(("docker", "rm", "--force", payload["name"]), 30)[0] == 0
        assert native.client.run(("docker", "container", "inspect", payload["name"],
                                  "--format", "{{.State.Running}}"), 30)[0] == 1
        assert native.engine.calls.count("remove") == 1
        resources.container_stopped(payload["name"])


def test_confirmed_removal_resolves_broker_quarantine_without_discarding_its_reason(native):
    payload, _ = create_payload(native)
    with lease(native):
        resources.track_container(payload["name"])
        created = request(native, "execution.create", payload)
        record = native.broker.get(created["execution_id"])
        record.update(state="UNKNOWN", quarantine="native_operation_unconfirmed")
        native.broker.save(record)
        response = request(native, "execution.remove", {
            key: created[key] for key in ("execution_id", "execution_token")})
        assert response["state"] == "REMOVED" and "quarantine" not in response
        assert native.broker.get(created["execution_id"])["resolved_quarantine"] == "native_operation_unconfirmed"
        resources.container_stopped(payload["name"])

@pytest.mark.parametrize("helper", ["runc", "containerd-shim-runc-v2"])
def test_native_helper_requires_its_declared_capped_execution_parent(native, monkeypatch, helper):
    from appsec_review.container_runtime.buildkit_worker import KernelProof

    proof = KernelProof(native.config)
    limits = []
    monkeypatch.setattr(proof, "limits", lambda *values: limits.append(values))
    root = Path(native.config.native_engine.execution_cgroup_parent)
    proof._helper_group(helper, root / "owned")
    assert limits == [(root, 8, 9216 * 1024**2)]
    for group in (root.with_name("unrelated"), Path("/sys/fs/cgroup/another-native-daemon")):
        with pytest.raises(RuntimeError, match="escapes"):
            proof._helper_group(helper, group)
    for daemon in ("dockerd", "containerd"):
        with pytest.raises(RuntimeError, match="escapes"):
            proof._helper_group(daemon, root)

    def unavailable(*args):
        raise FileNotFoundError("missing cgroup limit")

    monkeypatch.setattr(proof, "limits", unavailable)
    with pytest.raises(FileNotFoundError):
        proof._helper_group(helper, root / "owned")


@pytest.mark.parametrize("trigger", ["stopped-inventory", "disconnect", "restart"])
def test_unknown_work_holds_interlock_and_capacity_until_confirmed_removal(native, trigger):
    payload, _ = create_payload(native)
    native.engine.unrelated_stopped = trigger == "stopped-inventory"
    with lease(native):
        resources.track_container(payload["name"])
        response = request(native, "execution.create", payload)
        native.engine.confirmed = False
        if trigger == "disconnect":
            native.broker.disconnected({"action": "execution.create", "payload": payload})
        native.broker.reconcile(restart=True)
        assert native.broker.get(payload["execution_id"])["state"] == "UNKNOWN"
        assert native.broker.interlock.owner() is not None
    native.engine.confirmed = True
    native.engine.unrelated_stopped = False
    native.broker.reconcile(restart=True)
    assert native.broker.get(payload["execution_id"])["state"] == "REMOVED"
    assert native.broker.interlock.owner() is None
    assert response["execution_id"] == payload["execution_id"]
