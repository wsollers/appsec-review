"""Offline service/driver tests. No Docker, subprocesses, sockets or host cgroups.

Frozen selector for later resource approval:
``tests/test_bounded_image_build_service.py``
These tests are authored separately from commissioning and do not establish that
the real host, BuildKit image, egress proxy or cgroup delegation is usable.
"""
import base64
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

pytest.importorskip("fcntl", reason="the builder admission service is POSIX-only")

from appsec_review.config.assurance import ResourceBudget, parse_review_policy
from appsec_review.config.image_builder_service import (
    BuilderAdmissionConfig, BuilderGrant, BuilderImage, ImageBuilderServiceConfig, load_image_builder_service,
)
from appsec_review.container_runtime.builder_admission import BuilderAdmission
from appsec_review.container_runtime import buildkit_worker as workers
from appsec_review.container_runtime import image_builder as clients
from appsec_review.container_runtime import image_builder_service as services
from appsec_review.observability.events import EventLog
from appsec_review.runtime.resources import review_resource_scope
from appsec_review.runtime.resources import process_identity
from appsec_review.signing.core import SignatureVerificationError


BASE = "sha256:" + "a" * 64
BUILT = "sha256:" + "b" * 64
WORKER_IMAGE = "sha256:" + "c" * 64
CID = "d" * 64
MANIFEST = "sha256:" + "e" * 64
LIMITS = {
    "cpu_quota_us": 100000, "cpu_period_us": 100000, "memory_max": 4096 * 1024 * 1024,
    "host_cpu_quota_us": 100000, "host_cpu_period_us": 100000, "host_memory_max": 512 * 1024 * 1024,
}


@pytest.fixture(autouse=True)
def forbid_real_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("offline test attempted a real subprocess or socket")
    monkeypatch.setattr(workers.subprocess, "Popen", forbidden)
    monkeypatch.setattr(services.socket, "socket", forbidden)
    monkeypatch.setattr(os, "fork", forbidden)


def configuration(tmp_path, resource_mode="bounded"):
    state = tmp_path / "operator"
    state.mkdir(mode=0o700)
    run_root = tmp_path / "runs" / "run-one"
    run_root.mkdir(parents=True)
    metadata = tmp_path / "runs" / "metadata"
    namespace = hashlib.sha256(services.encoded({
        "tenant": "tenant", "project": "project", "run_root": str(run_root), "builder": "builder-release",
    })).hexdigest()[:24]
    context_root = metadata / "bounded-image-contexts"
    grant = BuilderGrant(
        uid=os.getuid(), tenant_id="tenant", project_id="project", run_id="run-one",
        run_root=str(run_root), target_snapshot="target-one", namespace=namespace,
        client_context_root=str(context_root), service_context_root=str(context_root),
    )
    config = ImageBuilderServiceConfig(
        endpoint=str(tmp_path / "builder.sock"), state_root=str(state), release_id="builder-release",
        worker_image_id=WORKER_IMAGE, worker_release_id="buildkit-release",
        host_cgroup="/sys/fs/cgroup/builder-host", worker_cgroup_parent="/sys/fs/cgroup/builder-workers",
        docker_endpoint=str(tmp_path / "docker.sock"), docker_binary="/usr/bin/docker",
        skopeo_binary="/usr/bin/skopeo", docker_release_id="docker-release",
        skopeo_release_id="skopeo-release", grants=(grant,),
        resource_mode=resource_mode,
        images=(BuilderImage(alias="base:release", image_id=BASE, release_id="base-release"),),
        admission=BuilderAdmissionConfig(metadata_root=str(metadata), uid=os.getuid(),
                                         gid=os.getgid(), lease_id=uuid4().hex),
    )
    policy = parse_review_policy({
        "project_id": "project",
        "image_builder": {"endpoint": config.endpoint, "tenant_id": "tenant", "release_id": config.release_id,
                          "resource_mode": resource_mode},
    })
    context = SimpleNamespace(
        review_policy=policy, run_root=run_root, metadata_root=metadata,
        target_root=tmp_path / "target", source_fingerprint="target-one",
        events=EventLog(run_root / "events.jsonl"),
    )
    return config, context


@pytest.mark.parametrize("helper,arguments", [
    ("dockerd", ["dockerd", "--exec-root", "/run/other-engine"]),
    ("containerd", ["containerd", "--config", "/run/other-engine/containerd/config.toml"]),
    ("containerd-shim-runc-v2", ["shim", "-address", "/run/other-engine/containerd.sock"]),
    ("runc", ["runc", "--root", "/run/builder-private-other/runc"]),
])
def test_dedicated_helper_scope_excludes_unrelated_infrastructure(tmp_path, monkeypatch, helper, arguments):
    from appsec_review.config.image_builder_service import DockerHelperScope

    config, _ = configuration(tmp_path)
    config = replace(config, docker_helper_scope=DockerHelperScope(
        "/var/lib/builder-private", "/run/builder-private"))
    proof = workers.KernelProof(config)
    monkeypatch.setattr(proof, "_process", lambda pid: (1, arguments))
    assert not proof._owned_helper(helper, 102, 101, Path("/sys/fs/cgroup/other-engine"))


@pytest.mark.parametrize("helper,arguments,parent", [
    ("containerd", ["containerd", "--config", "/run/builder-private/containerd/config.toml"], 1),
    ("containerd-shim-runc-v2", ["shim", "-address", "/run/builder-private/containerd.sock"], 1),
    ("runc", ["runc", "--root=/run/builder-private/runc"], 1),
    ("runc", ["runc"], 101),
])
def test_dedicated_scope_still_rejects_escaped_owned_helpers(tmp_path, monkeypatch, helper, arguments, parent):
    from appsec_review.config.image_builder_service import DockerHelperScope

    config, _ = configuration(tmp_path)
    config = replace(config, docker_helper_scope=DockerHelperScope(
        "/var/lib/builder-private", "/run/builder-private"))
    proof = workers.KernelProof(config)
    monkeypatch.setattr(proof, "_process", lambda pid: (parent, arguments))
    group = Path("/sys/fs/cgroup/escaped")
    assert proof._owned_helper(helper, 102, 101, group)
    with pytest.raises(workers.EnforcementUnavailable, match="escapes"):
        proof._helper_group(helper, group)


def test_helper_scope_preserves_default_and_rejects_ambiguous_roots(tmp_path):
    from appsec_review.config.image_builder_service import DockerHelperScope

    config, _ = configuration(tmp_path)
    proof = workers.KernelProof(config)
    assert proof._owned_helper("dockerd", 102, 101, Path("/sys/fs/cgroup/other"))
    with pytest.raises(workers.EnforcementUnavailable, match="ambiguous"):
        proof._option(["runc", "--root=/run/one", "--root", "/run/two"], "--root")
    for data, execution in (("/var/lib", "/run/private"), ("/private", "/private/exec")):
        with pytest.raises(ValueError):
            DockerHelperScope(data, execution)
    with pytest.raises(ValueError, match="client custody"):
        replace(config, docker_helper_scope=DockerHelperScope(
            config.grants[0].run_root + "/engine", "/run/builder-private"))


def test_escaped_child_of_reparented_owned_shim_remains_in_custody(tmp_path, monkeypatch):
    from appsec_review.config.image_builder_service import DockerHelperScope

    config, _ = configuration(tmp_path)
    config = replace(config, docker_helper_scope=DockerHelperScope(
        "/var/lib/builder-private", "/run/builder-private"))
    proof = workers.KernelProof(config)
    processes = {103: (102, ["runc", "init"]),
                 102: (1, ["shim", "-address", "/run/builder-private/containerd.sock"])}
    monkeypatch.setattr(proof, "_process", lambda pid: processes[pid])
    monkeypatch.setattr(proof, "process_cgroup", lambda pid: Path("/sys/fs/cgroup/escaped"))
    assert proof._owned_helper("runc", 103, 101, Path("/sys/fs/cgroup/escaped"))
    with pytest.raises(workers.EnforcementUnavailable, match="escapes"):
        proof._helper_group("runc", Path("/sys/fs/cgroup/escaped"))


@pytest.mark.parametrize("baseline_mb,host_mb,inactive_mb,dirty_mb,foreign,passes", [
    (1700, 100, 1000, 0, False, True),
    (1700, 100, 0, 0, False, False),
    (1700, 100, 1000, 1000, False, False),
    (100, 513, 0, 0, False, False),
    (100, 100, 0, 0, True, False),
])
def test_engine_domain_memory_proof_retains_dirty_and_owned_overhead_costs(
        tmp_path, monkeypatch, baseline_mb, host_mb, inactive_mb, dirty_mb, foreign, passes):
    from appsec_review.config.image_builder_service import DockerHelperScope, EngineDomainConfig
    from appsec_review.container_runtime import engine_admission

    config, _ = configuration(tmp_path)
    root = "/sys/fs/cgroup/engine-private"
    config = replace(
        config, resource_mode="concurrency_only", lifetime_domain="engine",
        host_cgroup=root + "/builder",
        docker_helper_scope=DockerHelperScope("/var/lib/builder-private", "/run/builder-private"),
        engine_domain=EngineDomainConfig(str(tmp_path / "engine-metadata"), root, (root + "/docker",)))
    real_path = Path

    def mapped(value):
        text = str(value)
        return real_path(str(tmp_path / "kernel") + text[len(root):]) if text.startswith(root) else real_path(value)

    monkeypatch.setattr(engine_admission, "Path", mapped)
    for group, memory, inactive, dirty in (
            (root, baseline_mb + host_mb, inactive_mb, dirty_mb),
            (root + "/builder", host_mb, 0, 0),
            (root + "/docker", baseline_mb, inactive_mb, dirty_mb)):
        path = mapped(group)
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        (path / "cpu.max").write_text("200000 100000")
        (path / "memory.max").write_text(str(2048 * 1024**2))
        (path / "memory.swap.max").write_text("0")
        (path / "memory.current").write_text(str(memory * 1024**2))
        (path / "memory.stat").write_text(
            f"inactive_file {inactive * 1024**2}\nfile_dirty {dirty * 1024**2}\nfile_writeback 0\n")
        (path / "cgroup.procs").write_text("")
    if foreign:
        (mapped(root) / "cgroup.procs").write_text(str(os.getpid()))
    proof = engine_admission.EngineDomainProof(config)
    if passes:
        proof.live()
    else:
        with pytest.raises(workers.EnforcementUnavailable, match="consumer" if foreign else "headroom"):
            proof.live()


class FakeDriver:
    def __init__(self):
        self.calls = []
        self.limits = deepcopy(LIMITS)
        self.confirmed = True
        self.error = None
        self.result = {"state": "SUCCEEDED", "exit_code": 0, "image_id": BUILT,
                       "stdout": base64.b64encode(b"built").decode(), "stderr": ""}
        self.service = None

    def prepare(self, record, save):
        self.calls.append("prepare")
        assert self.service.store.get(record["binding"]["build_id"])["prepare_dispatched"] is True
        if self.error:
            raise self.error
        for name in ("context", "inputs"):
            (Path(record["directory"]) / name).mkdir(mode=0o755)
        return deepcopy(self.limits)

    def start(self, record, save):
        self.calls.append("start")
        persisted = self.service.store.get(record["binding"]["build_id"])
        assert persisted["state"] == "STARTING" and persisted["start"] == record["start"]
        assert (Path(record["directory"]) / "context" / "Dockerfile").is_file()

    def status(self, record, save):
        self.calls.append("status")
        return deepcopy(self.result)

    def cancel(self, record, save):
        self.calls.append("cancel")
        assert self.service.store.get(record["binding"]["build_id"])["state"] in {"CANCELLING", "CLEANING"}
        return self.confirmed

    def cleanup(self, record, save):
        self.calls.append("cleanup")
        return self.confirmed


class FakeLifetimeProof:
    def __init__(self, config):
        self.config = config
        self.generation = 1
        self.stopped_result = True
        self.live_members = []

    def groups(self):
        return {name: {"path": path, "device": 1, "inode": self.generation + index}
                for index, (name, path) in enumerate((
                    ("host", self.config.host_cgroup), ("workers", self.config.worker_cgroup_parent)))}

    def members(self):
        return deepcopy(self.live_members)

    def stopped(self, members):
        return self.stopped_result


class ProtocolAdmissionFixture(BuilderAdmission):
    """Protocol/driver-only tests fake worker admission; lifetime ledger stays real."""

    def verify_build(self, binding, peer, worker, *, preparing=False):
        pass


class Harness:
    def __init__(self, tmp_path, driver=None, *, require_worker_reservation=False, resource_mode="bounded"):
        self.config, self.context = configuration(tmp_path)
        self.config = replace(self.config, resource_mode=resource_mode)
        self.context.review_policy = replace(
            self.context.review_policy,
            image_builder=replace(self.context.review_policy.image_builder, resource_mode=resource_mode))
        self.peer = (services.Peer(os.getpid(), os.getuid(), os.getgid(), process_identity(os.getpid()))
                     if require_worker_reservation else services.Peer(1234, os.getuid(), os.getgid(), "boot:123"))
        self.live = True
        self.now = 10.0
        self.driver = driver or FakeDriver()
        if resource_mode == "concurrency_only" and isinstance(self.driver, FakeDriver):
            self.driver.limits = concurrency_only_observations()
        self.lifetime_proof = FakeLifetimeProof(self.config)
        admission_type = BuilderAdmission if require_worker_reservation else ProtocolAdmissionFixture
        self.lifetime = admission_type(self.config, proof=self.lifetime_proof)
        self.lifetime.reserve()
        self.service = self.open()
        self.binding = None
        self.worker = None

    def open(self):
        service = services.ImageBuilderService(
            self.config, driver=self.driver, admission=self.lifetime, clock=lambda: self.now,
            alive=lambda pid: self.peer.start_token if self.live and pid == self.peer.pid else None,
        )
        if isinstance(self.driver, FakeDriver):
            self.driver.service = service
        return service

    def prepare_context(self):
        grant = self.config.grants[0]
        build_id = uuid4().hex
        path = Path(grant.client_context_root) / grant.namespace / build_id / "context"
        path.mkdir(parents=True, mode=0o700)
        path.parent.chmod(0o700)
        self.binding = {
            "build_id": build_id, "tenant_id": grant.tenant_id, "project_id": grant.project_id,
            "run_id": grant.run_id, "target_snapshot": grant.target_snapshot,
            "release_id": self.config.release_id, "namespace": grant.namespace,
            "recipe_identity": "declared-recipe", "context": str(path),
            "output_tag": "derived:" + grant.namespace[:12] + "-recipe",
        }
        self.worker = None
        return path

    def request(self, action, extra=None, *, nonce=None, peer=None, binding=None, worker="current"):
        request = {
            "schema": services.SCHEMA, "request_id": nonce or uuid4().hex, "action": action,
            "body": {"binding": deepcopy(binding or self.binding),
                     "resource_budget": self.context.review_policy.resources.view(),
                     "worker": deepcopy(self.worker if worker == "current" else worker), **(extra or {})},
        }
        response = json.loads(self.service.dispatch(services.encoded(request), peer or self.peer))
        assert response["request_id"] == request["request_id"]
        assert response["body"]["binding"] == request["body"]["binding"]
        self.worker = response["body"]["worker"]
        return response["body"]

    def prepare(self):
        return self.request("prepare", {"limits": self.config.requested_limits})

    def start(self, **overrides):
        return self.request("start", {"network": "none", "build_args": {}, "image_inputs": {}, **overrides})


@pytest.fixture
def harness(tmp_path):
    harness = Harness(tmp_path)
    yield harness
    harness.service.close()


@pytest.fixture(params=("bounded", "concurrency_only"))
def admitted_harness(tmp_path, request):
    harness = Harness(tmp_path, require_worker_reservation=True, resource_mode=request.param)
    yield harness
    harness.service.close()


def test_service_full_accepted_client_flow_and_receipt(admitted_harness, monkeypatch):
    harness = admitted_harness
    class Transport:
        def __init__(self, owner):
            self.owner = owner

        def request(self, action, body, timeout):
            assert timeout > 0
            request = {"schema": services.SCHEMA, "request_id": uuid4().hex, "action": action, "body": body}
            value = json.loads(harness.service.dispatch(services.encoded(request), harness.peer))
            assert value["request_id"] == request["request_id"]
            return value["body"]

    monkeypatch.setattr(clients, "UnixBuilderClient", Transport)
    context = harness.context
    with review_resource_scope(context.metadata_root, context.review_policy.resources, context.events), \
            clients.image_builder_scope(context):
        tag = "derived:" + clients.builder_namespace()[:12] + "-fixture"
        with clients.bounded_image_preparation(identity="recipe-one", tag=tag, timeout_seconds=60) as session:
            (session.context / "Dockerfile").write_text("FROM base:release\nRUN [\"true\"]\n")
            assert session.build(network="none") == (0, b"built", b"", False)
        clients.verify_builder_receipt(session.receipt(), identity="recipe-one", tag=tag, image_id=BUILT)
    record = harness.service.store.get(session.build_id)
    assert record["state"] == "CLEANED" and record["execution"]["image_id"] == BUILT
    assert not session.context.exists() and not Path(record["directory"]).exists()
    assert harness.driver.calls == ["prepare", "start", "status", "cancel", "cleanup"]


def test_lost_responses_repeated_requests_do_not_repeat_side_effects(harness):
    path = harness.prepare_context()
    nonce = uuid4().hex
    first = harness.request("prepare", {"limits": harness.config.requested_limits}, nonce=nonce, worker=None)
    second = harness.request("prepare", {"limits": harness.config.requested_limits}, nonce=nonce, worker=None)
    assert first == second and harness.driver.calls == ["prepare"]
    path.joinpath("Dockerfile").write_text("FROM base:release\n")
    harness.start()
    harness.start()
    assert harness.driver.calls.count("start") == 1
    harness.request("status")
    assert harness.request("cleanup")["state"] == "CLEANED"
    assert harness.request("cleanup")["state"] == "CLEANED"
    assert harness.driver.calls.count("cleanup") == 1


def test_nonce_reuse_with_changed_action_is_rejected(harness):
    harness.prepare_context()
    nonce = uuid4().hex
    harness.request("prepare", {"limits": harness.config.requested_limits}, nonce=nonce)
    with pytest.raises(ValueError, match="nonce"):
        harness.request("status", nonce=nonce)


def test_lost_prepare_response_still_allows_exact_owner_cleanup(harness):
    harness.prepare_context()
    prepared = harness.prepare()
    cancelled = harness.request("cancel", worker=None)
    assert cancelled["worker"] == prepared["worker"]
    assert harness.request("cleanup")["state"] == "CLEANED"


def test_request_budget_still_allows_confirmed_cleanup(harness, monkeypatch):
    harness.prepare_context()
    harness.prepare()
    monkeypatch.setattr(services, "MAX_MESSAGES_PER_BUILD", 1)
    with pytest.raises(ValueError, match="budget"):
        harness.request("status")
    assert harness.request("cleanup")["state"] == "CLEANED"


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "other"), ("project_id", "other"), ("run_id", "other"),
    ("target_snapshot", "other"), ("release_id", "other"), ("namespace", "0" * 24),
    ("context", "/outside/context"), ("output_tag", "other:public"),
])
def test_rejects_binding_and_path_changes_before_side_effects(harness, field, value):
    harness.prepare_context()
    binding = {**harness.binding, field: value}
    with pytest.raises((ValueError, PermissionError)):
        harness.request("prepare", {"limits": harness.config.requested_limits}, binding=binding)
    assert not harness.driver.calls


def test_peer_uid_pid_generation_and_worker_are_bound(harness):
    harness.prepare_context()
    with pytest.raises(PermissionError):
        harness.request("prepare", {"limits": harness.config.requested_limits},
                        peer=replace(harness.peer, uid=harness.peer.uid + 1))
    harness.prepare()
    for peer in (replace(harness.peer, pid=5678), replace(harness.peer, start_token="reused-pid")):
        with pytest.raises(PermissionError):
            harness.request("status", peer=peer)
    with pytest.raises(PermissionError, match="worker"):
        harness.request("cancel", worker={"id": harness.worker["id"], "start_token": "replacement"})


@pytest.mark.parametrize("kind", ["symlink-root", "symlink-file", "hardlink", "fifo", "oversized"])
def test_rejects_hostile_context_files_without_worker_start(harness, kind, tmp_path):
    path = harness.prepare_context()
    if kind == "symlink-root":
        path.rmdir()
        path.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(OSError):
            harness.prepare()
        assert harness.driver.calls == []
        return
    harness.prepare()
    path.joinpath("Dockerfile").write_text("FROM base:release\n")
    if kind == "symlink-file":
        path.joinpath("payload").symlink_to(tmp_path)
    elif kind == "hardlink":
        os.link(path / "Dockerfile", path / "payload")
    elif kind == "fifo":
        os.mkfifo(path / "payload")
    else:
        harness.service.config = replace(harness.config, max_context_bytes=8)
    assert harness.start()["state"] == "UNKNOWN"
    assert "start" not in harness.driver.calls


def test_replaced_context_is_not_removed_or_claimed_clean(harness):
    path = harness.prepare_context()
    harness.prepare()
    displaced = path.with_name("displaced-context")
    path.rename(displaced)
    path.mkdir(mode=0o700)
    assert harness.request("cleanup")["state"] == "UNKNOWN"
    assert displaced.exists() and path.exists()


@pytest.mark.parametrize("field,value", [
    ("cpu_quota_us", 200000), ("memory_max", 5 * 1024**3),
    ("host_cpu_quota_us", 200000), ("host_memory_max", 1024**3),
    ("cpu_period_us", 0), ("memory_max", True), ("host_memory_max", None),
])
def test_observed_enforcement_missing_or_wrong_retains_intent(harness, field, value):
    harness.prepare_context()
    harness.driver.limits[field] = value
    assert harness.prepare()["state"] == "UNKNOWN"
    assert harness.service.store.records()[0]["state"] != "CLEANED"
    assert harness.request("cleanup")["state"] == "CLEANED"


@pytest.mark.parametrize("confirmed", [True, False])
def test_cancel_and_cleanup_require_independent_confirmation(harness, confirmed):
    harness.prepare_context()
    harness.prepare()
    harness.driver.confirmed = confirmed
    cancel = harness.request("cancel")
    cleaned = harness.request("cleanup")
    assert cancel["state"] == ("CANCELLED" if confirmed else "UNKNOWN")
    assert cleaned["state"] == ("CLEANED" if confirmed else "UNKNOWN")
    assert cleaned.get("work_stopped", False) is confirmed
    if not confirmed:
        harness.prepare_context()
        with pytest.raises(workers.EnforcementUnavailable, match="admission"):
            harness.prepare()


@pytest.mark.parametrize("reason", ["death", "idle", "deadline", "restart"])
def test_dead_owner_and_restart_cleanup_do_not_need_client(harness, reason):
    path = harness.prepare_context()
    harness.prepare()
    path.joinpath("Dockerfile").write_text("FROM base:release\n")
    harness.start()
    if reason == "death":
        harness.live = False
    elif reason == "idle":
        harness.now += harness.config.owner_idle_seconds + 1
    elif reason == "deadline":
        harness.now += harness.config.build_timeout_seconds + 1
    else:
        harness.service.close()
        harness.service = harness.open()
    harness.service.reconcile(restart=reason == "restart")
    assert harness.service.store.records()[0]["state"] == "CLEANED"
    assert not path.exists()


def test_restart_retains_unknown_worker_reservation(harness):
    harness.prepare_context()
    harness.driver.error = workers.OutcomeUnknown("create response lost")
    assert harness.prepare()["state"] == "UNKNOWN"
    harness.driver.confirmed = False
    harness.service.close()
    harness.service = harness.open()
    harness.service.reconcile(restart=True)
    assert harness.service.store.records()[0]["state"] == "UNKNOWN"
    assert harness.driver.calls.count("prepare") == 1
    assert harness.prepare()["state"] == "UNKNOWN"
    assert harness.driver.calls.count("prepare") == 1


def test_limits_cannot_be_boolean_equivalents(harness):
    harness.prepare_context()
    limits = {**harness.config.requested_limits, "cpu": True}
    with pytest.raises(workers.EnforcementUnavailable):
        harness.request("prepare", {"limits": limits})
    assert harness.driver.calls == []


@pytest.mark.parametrize("result", [
    {"state": "SUCCEEDED", "exit_code": 0, "stdout": "", "stderr": ""},
    {"state": "SUCCEEDED", "exit_code": 2, "image_id": BUILT, "stdout": "", "stderr": ""},
    {"state": "SUCCEEDED", "exit_code": 0, "image_id": "base:release", "stdout": "", "stderr": ""},
    {"state": "SUCCEEDED", "exit_code": 0, "image_id": BUILT, "stdout": "!", "stderr": ""},
    {"state": "SUCCEEDED", "exit_code": 0, "image_id": BUILT,
     "stdout": base64.b64encode(b"x" * (services.MAX_LOG_BYTES + 1)).decode(), "stderr": ""},
])
def test_hostile_results_never_become_success(harness, result):
    path = harness.prepare_context()
    harness.prepare()
    path.joinpath("Dockerfile").write_text("FROM base:release\n")
    harness.start()
    harness.driver.result = result
    assert harness.request("status")["state"] == "UNKNOWN"
    assert "execution" not in harness.service.store.records()[0]


@pytest.mark.parametrize("text", [
    "FROM unknown:latest\n", "FROM base:release\nCOPY --from=unknown:latest /x /x\n",
    "# syntax=docker/dockerfile:latest\nFROM base:release\n",
    "# escape=`\nFROM base:release\n", "FROM base:release\nADD https://example.invalid/a /a\n",
    "FROM base:release\nRUN --mount=from=unknown:latest true\n",
    "FROM base:release\nONBUILD COPY --from=unknown:latest /x /x\n",
    "ARG BUILD_IMAGE\nFROM ${BUILD_IMAGE}\n",
])
def test_implicit_base_frontend_and_copy_pulls_are_denied(text):
    with pytest.raises((ValueError, PermissionError)):
        services.validate_dockerfile(text, {"base:release"}, {})


def test_derived_multistage_and_package_recipes_remain_supported():
    services.validate_dockerfile(
        "ARG BUILD_IMAGE\nFROM ${BUILD_IMAGE} AS build\nRUN apt-get update\n"
        "FROM base:release\nCOPY --from=build /a /a\n"
        "COPY --from=0 /b /b\nUSER 10001:10001\n",
        {"base:release"}, {"BUILD_IMAGE": "base:release"},
    )


@pytest.mark.parametrize("wire", [
    b'{"schema":1,"schema":2}', b'{"schema":NaN}', b"[" + b" " * services.MAX_MESSAGE_BYTES,
    services.encoded({"schema": services.SCHEMA, "request_id": "bad", "action": "status", "body": {}}),
    services.encoded({"schema": services.SCHEMA, "request_id": "a" * 32, "action": [], "body": {}}),
])
def test_hostile_protocol_frames_are_rejected(wire):
    with pytest.raises(ValueError):
        services.decode_message(wire)


def test_so_peercred_and_native_namespace_authentication_are_enforced(monkeypatch):
    class Channel:
        def getsockopt(self, level, option, size):
            assert option == services.socket.SO_PEERCRED and size == 12
            return services.struct.pack("3i", 1234, 1000, 1000)
    monkeypatch.setattr(services, "process_token", lambda pid: "boot:123")
    monkeypatch.setattr(services.os, "readlink", lambda path: "same-namespace")
    assert services.authenticated_peer(Channel()) == services.Peer(1234, 1000, 1000, "boot:123")
    monkeypatch.setattr(services.os, "readlink", lambda path: "client" if "/1234/" in path else "service")
    with pytest.raises(PermissionError, match="mapped"):
        services.authenticated_peer(Channel())


class FakeProof:
    def __init__(self):
        self.fail = False
        self.empty = True

    def host(self):
        if self.fail:
            raise workers.EnforcementUnavailable("fake delegated enforcement missing")
        return {key: value for key, value in self.limits.items() if key.startswith("host_")}

    def worker(self, inspection, record):
        if inspection["Id"] != record["driver"]["container_id"]:
            raise workers.EnforcementUnavailable("replaced native worker")
        return {key: value for key, value in self.limits.items() if not key.startswith("host_")}

    def stopped(self, cid):
        return self.empty

    def stop_launcher(self, handle, timeout):
        assert handle == {"pid": 5678, "start_token": "launcher-generation"}
        return self.empty


class FakeCommands:
    """Exercises real driver command construction without running a command."""
    def __init__(self):
        self.calls = []
        self.container = None
        self.metadata = {"containerimage.config.digest": BUILT}
        self.tagged = BASE
        self.job = None
        self.fail_load = False
        self.fail_create = False
        self.sandbox = "sandbox"

    def run(self, argv, timeout, *, output=None, output_limit=None):
        assert timeout > 0
        self.calls.append(argv)
        if argv[0].endswith("skopeo"):
            destination = Path(argv[-1][4:].rsplit(":", 1)[0])
            (destination / "blobs" / "sha256").mkdir(parents=True)
            (destination / "index.json").write_text(json.dumps({"manifests": [{"digest": MANIFEST}]}))
            (destination / "blobs" / "sha256" / MANIFEST.split(":")[1]).write_text(
                json.dumps({"config": {"digest": BASE}}))
            return 0, b"", b""
        args = argv[3:]
        value = None
        if args[0] == "info":
            value = {"CgroupDriver": "cgroupfs", "CgroupVersion": "2", "OSType": "linux"}
        elif args[:2] == ["image", "inspect"]:
            image_id = args[2] if args[2].startswith("sha256:") else self.tagged
            value = [{"Id": image_id, "Config": {}}]
        elif args[:2] == ["container", "create"]:
            if self.fail_create:
                raise workers.OutcomeUnknown("create response lost")
            self.container = {
                "Id": CID, "Image": WORKER_IMAGE,
                "State": {"Running": True, "Pid": 4321, "StartedAt": "fixture-generation"},
                "Config": {"Labels": {
                    value.split("=", 1)[0]: value.split("=", 1)[1]
                    for index, value in enumerate(args) if index and args[index - 1] == "--label"
                }},
            }
            return 0, CID.encode(), b""
        elif args[:2] == ["container", "ls"]:
            if "--quiet" in args:
                return 0, CID.encode() if self.container else b"", b""
            return 0, json.dumps(CID).encode() if self.container else b"", b""
        elif args[:2] == ["container", "inspect"]:
            value = [deepcopy(self.container)]
        elif args[:2] == ["container", "start"]:
            return 0, CID.encode(), b""
        elif args[:2] == ["container", "rm"]:
            self.container = None
            return 0, CID.encode(), b""
        elif args[0] == "exec" and "workers" in args:
            value = [{"ID": "buildkit-one", "Labels": {
                "org.mobyproject.buildkit.worker.oci.process-mode": self.sandbox,
                "org.mobyproject.buildkit.worker.snapshotter": "native",
            }}]
        elif args[0] == "exec" and args[-1] == "/output/result.json":
            value = self.metadata
        elif args[0] == "exec" and args[-1] == "/output/image.tar":
            assert output_limit > 0
            output.write_bytes(b"fake image export, not a usable archive")
            return 0, b"", b""
        elif args[:2] == ["image", "load"]:
            if self.fail_load:
                raise workers.OutcomeUnknown("daemon import completion is unknown")
            self.tagged = self.metadata["containerimage.config.digest"]
            return 0, b"loaded", b""
        else:
            raise AssertionError(f"unexpected fake command: {args}")
        return 0, json.dumps(value).encode(), b""

    def start(self, argv, *, capture_limit):
        assert capture_limit == services.MAX_LOG_BYTES
        self.calls.append(argv)
        self.job = SimpleNamespace(stdout=bytearray(b"built"), stderr=bytearray())
        return self.job

    def poll(self, command):
        assert command is self.job
        return 0

    def launcher(self, command):
        assert command is self.job
        return {"pid": 5678, "start_token": "launcher-generation"}

    def stop(self, command):
        assert command is self.job


@contextmanager
def real_driver_harness(tmp_path, monkeypatch, resource_mode="bounded"):
    fake_commands, fake_proof = FakeCommands(), FakeProof()
    fake_proof.limits = deepcopy(LIMITS) if resource_mode == "bounded" else concurrency_only_observations()
    harness = Harness(tmp_path, resource_mode=resource_mode)
    driver = workers.BuildKitWorker(harness.config, runner=fake_commands, proof=fake_proof)
    harness.service.driver = driver
    # Only binary custody is bypassed. Context/state custody still uses the
    # service's original function and task-owned pytest paths.
    monkeypatch.setattr(workers, "private_path", lambda *args, **kwargs: None)
    try:
        yield harness, fake_commands, fake_proof
    finally:
        harness.service.close()


def concurrency_only_observations():
    return {
        prefix + key: value for prefix in ("", "host_") for key, value in {
            "resource_mode": "concurrency_only", "cpu_quota_us": None, "cpu_period_us": 100000,
            "memory_max": None, "swap_max": 0, "inherited_limits": [],
        }.items()
    }


@pytest.mark.parametrize("resource_mode", ("bounded", "concurrency_only"))
def test_real_driver_builds_exports_loads_and_proves_fresh_result_with_fakes(tmp_path, monkeypatch, resource_mode):
    with real_driver_harness(tmp_path, monkeypatch, resource_mode) as (harness, commands, _):
        path = harness.prepare_context()
        assert harness.prepare()["state"] == "PREPARED"
        path.joinpath("Dockerfile").write_text("FROM base:release\nRUN [\"true\"]\n")
        assert harness.start()["state"] == "RUNNING"
        result = harness.request("status")
        assert result["state"] == "SUCCEEDED" and result["image_id"] == BUILT
        assert harness.request("cleanup")["state"] == "CLEANED"
        solve = next(call for call in commands.calls if "--frontend" in call)
        assert "--no-cache" in solve and "--source-policy-file" in solve and "--oci-layout" in solve
        assert any(value.startswith("context:base:release=oci-layout://") for value in solve)
        assert not any("pull" == part or "push" == part for call in commands.calls for part in call)
        create = next(call for call in commands.calls if "create" in call)
        assert "--pull=never" in create and "--cap-drop=ALL" in create
        assert ("--cpu-quota" in create) is (resource_mode == "bounded")
        assert ("--memory" in create) is (resource_mode == "bounded")
        assert harness.config.docker_endpoint not in [
            value for index, value in enumerate(create) if index and create[index - 1] == "--mount"]


def test_tag_lookup_alone_cannot_replace_missing_solve_output(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, _):
        path = harness.prepare_context()
        harness.prepare()
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        harness.start()
        commands.metadata = {}
        commands.tagged = BASE
        assert harness.request("status")["state"] == "UNKNOWN"
        assert not any(call[3:5] == ["image", "load"] for call in commands.calls)


def test_uncertain_daemon_import_and_create_hold_durable_reservations(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, _):
        path = harness.prepare_context()
        harness.prepare()
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        harness.start()
        commands.fail_load = True
        assert harness.request("status")["state"] == "UNKNOWN"
        assert harness.request("cleanup")["state"] == "UNKNOWN"
        assert harness.service.store.records()[0]["driver"]["host_operation_pending"] is True


def test_lost_create_with_absent_container_does_not_prove_cleanup(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, _):
        harness.prepare_context()
        commands.fail_create = True
        assert harness.prepare()["state"] == "UNKNOWN"
        assert harness.request("cleanup")["state"] == "UNKNOWN"
        assert harness.service.store.records()[0]["driver"]["create_pending"] is True


@pytest.mark.parametrize("resource_mode", ("bounded", "concurrency_only"))
def test_real_driver_restart_reconciles_recorded_launcher_and_worker(tmp_path, monkeypatch, resource_mode):
    with real_driver_harness(tmp_path, monkeypatch, resource_mode) as (harness, commands, proof):
        path = harness.prepare_context()
        harness.prepare()
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        harness.start()
        before = harness.service.store.records()[0]
        assert before["driver"]["launcher"]["start_token"] == "launcher-generation"
        harness.service.driver = workers.BuildKitWorker(harness.config, runner=commands, proof=proof)
        harness.service.reconcile(restart=True)
        assert harness.service.store.records()[0]["state"] == "CLEANED"


def test_concurrency_only_service_keeps_sole_slot_until_independently_cleaned(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch, "concurrency_only") as (harness, _, proof):
        harness.prepare_context()
        assert harness.prepare()["state"] == "PREPARED"
        first_binding, first_worker = deepcopy(harness.binding), deepcopy(harness.worker)
        proof.empty = False
        assert harness.request("cleanup")["state"] == "UNKNOWN"
        harness.prepare_context()
        with pytest.raises(workers.EnforcementUnavailable, match="unresolved"):
            harness.prepare()
        proof.empty = True
        assert harness.request("cleanup", binding=first_binding, worker=first_worker)["state"] == "CLEANED"
        harness.worker = None
        assert harness.prepare()["state"] == "PREPARED"
        assert harness.request("cleanup")["state"] == "CLEANED"


@pytest.mark.parametrize("cpu,memory,swap,accepted", [
    ("max 100000", "max", "0", True),
    ("100000 100000", "max", "0", False),
    ("max 100000", "4096", "0", False),
    ("max 100000", "max", "max", False),
])
def test_concurrency_only_kernel_proof_does_not_claim_finite_caps(tmp_path, cpu, memory, swap, accepted):
    config, _ = configuration(tmp_path, "concurrency_only")
    root = tmp_path / "fake-cgroup"
    root.mkdir()
    (root / "cpu.max").write_text(cpu)
    (root / "memory.max").write_text(memory)
    (root / "memory.swap.max").write_text(swap)
    if accepted:
        observed = workers.KernelProof(config).builder_limits(root, 1, 4096)
        assert observed["cpu_quota_us"] is None and observed["memory_max"] is None
        assert observed["swap_max"] == 0 and observed["inherited_limits"] == []
    else:
        with pytest.raises(workers.EnforcementUnavailable):
            workers.KernelProof(config).builder_limits(root, 1, 4096)


@pytest.mark.parametrize("failure", ["host-enforcement", "process-sandbox", "cgroup-populated", "worker-replaced"])
def test_real_driver_refuses_unproved_enforcement_and_cleanup(tmp_path, monkeypatch, failure):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        harness.prepare_context()
        if failure == "host-enforcement":
            proof.fail = True
        if failure == "process-sandbox":
            commands.sandbox = "no-sandbox"
        prepared = harness.prepare()
        if failure in {"host-enforcement", "process-sandbox"}:
            assert prepared["state"] == "UNKNOWN"
            return
        if failure == "cgroup-populated":
            proof.empty = False
        else:
            commands.container["Id"] = "f" * 64
        assert harness.request("cleanup")["state"] == "UNKNOWN"


class SignedImages:
    """Image verifier fake: accepts only the given IDs, as if only they had trusted envelopes."""

    def __init__(self, *signed):
        self.signed, self.calls = set(signed), []

    def verify(self, image_id, *, reference=None):
        self.calls.append(image_id)
        if image_id not in self.signed:
            raise SignatureVerificationError(f"{image_id} has no trusted signature envelope")


def signed_driver(harness, commands, proof, verifier):
    harness.service.driver = workers.BuildKitWorker(
        harness.config, runner=commands, proof=proof, image_verifier=verifier)
    return harness.service.driver


def test_real_driver_verifies_pinned_worker_and_inputs_and_launches_by_id(tmp_path, monkeypatch):
    verifier = SignedImages(WORKER_IMAGE, BASE)
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        signed_driver(harness, commands, proof, verifier)
        harness.service._image_verifier = verifier
        path = harness.prepare_context()
        assert harness.prepare()["state"] == "PREPARED"
        assert verifier.calls == [WORKER_IMAGE]
        create = next(call for call in commands.calls if "create" in call)
        assert create[create.index("rootlesskit") + 1] == WORKER_IMAGE
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        assert harness.start()["state"] == "RUNNING"
        assert harness.request("status")["state"] == "SUCCEEDED"
        # The derived output is never treated as a signed input.
        assert BUILT not in verifier.calls and verifier.calls.count(BASE) == 2
        copy = next(call for call in commands.calls if call[0].endswith("skopeo"))
        assert f"docker-daemon:{BASE}" in copy


def test_real_driver_refuses_unsigned_worker_image_before_create(tmp_path, monkeypatch):
    verifier = SignedImages(BASE)
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        signed_driver(harness, commands, proof, verifier)
        harness.prepare_context()
        assert harness.prepare()["state"] == "UNKNOWN"
        record = harness.service.store.records()[0]
        assert "refusing to use BuildKit worker image" in record["error"]
        assert not any("create" in call for call in commands.calls)
        assert harness.request("cleanup")["state"] == "CLEANED"


def test_real_driver_refuses_worker_image_id_differing_from_pin(tmp_path, monkeypatch):
    verifier = SignedImages(WORKER_IMAGE, BASE)
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        signed_driver(harness, commands, proof, verifier)
        run = commands.run

        def retagged(argv, timeout, **kwargs):
            if argv[3:6] == ["image", "inspect", WORKER_IMAGE]:
                return 0, json.dumps([{"Id": "sha256:" + "9" * 64, "Config": {}}]).encode(), b""
            return run(argv, timeout, **kwargs)

        commands.run = retagged
        harness.prepare_context()
        assert harness.prepare()["state"] == "UNKNOWN"
        assert verifier.calls == [] and not any("create" in call for call in commands.calls)


def test_service_refuses_unsigned_declared_input_before_solve(tmp_path, monkeypatch):
    verifier = SignedImages(WORKER_IMAGE)
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        signed_driver(harness, commands, proof, verifier)
        harness.service._image_verifier = verifier
        path = harness.prepare_context()
        assert harness.prepare()["state"] == "PREPARED"
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        with pytest.raises(workers.ImageSignatureRefused, match="build input base:release"):
            harness.start()
        assert harness.service.store.records()[0]["state"] == "PREPARED"
        assert not any(call[0].endswith("skopeo") or "--frontend" in call for call in commands.calls)
        assert harness.request("cleanup")["state"] == "CLEANED"


def test_real_driver_refuses_unsigned_declared_input_before_transport(tmp_path, monkeypatch):
    verifier = SignedImages(WORKER_IMAGE)
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        signed_driver(harness, commands, proof, verifier)
        path = harness.prepare_context()
        harness.prepare()
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        assert harness.start()["state"] == "UNKNOWN"
        assert "refusing to use build input base:release image" in harness.service.store.records()[0]["error"]
        assert not any(call[0].endswith("skopeo") or "--frontend" in call for call in commands.calls)


@pytest.mark.parametrize("signed", [True, False, None])
def test_real_driver_verifies_pinned_egress_proxy_image(tmp_path, monkeypatch, signed):
    network, proxy, proxy_image = "1" * 64, "2" * 64, "sha256:" + "3" * 64
    config = replace(configuration(tmp_path)[0], network_id=network, proxy_container_id=proxy,
                     proxy_image_id=proxy_image, proxy_release_id="proxy-release",
                     proxy_url="http://10.0.0.2:3128", ip_release_id="ip-release")
    replies = {
        ("network", "inspect"): [{
            "Id": network, "Driver": "bridge", "Internal": True, "EnableIPv6": False,
            "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
            "Containers": {proxy: {"IPv4Address": "10.0.0.2/24"}}}],
        ("container", "inspect"): [{
            "Id": proxy, "Image": proxy_image, "State": {"Running": True, "Pid": 99},
            "Config": {"Labels": {"appsec.egress.release": "proxy-release"}},
            "HostConfig": {"CapDrop": ["ALL"], "ReadonlyRootfs": True}, "Mounts": []}],
    }
    runner = SimpleNamespace(run=lambda argv, timeout, **kwargs: (
        0, json.dumps([{"addr_info": []}] if argv[0] == config.ip_binary else replies[tuple(argv[3:5])]).encode(),
        b""))
    proof = SimpleNamespace(process_cgroup=lambda pid: Path(config.host_cgroup) / "proxy")
    verifier = SignedImages(proxy_image) if signed else SignedImages()
    monkeypatch.setattr(workers, "private_path", lambda *args, **kwargs: None)
    if signed is None:
        unloadable_signing_policy(monkeypatch)
    driver = workers.BuildKitWorker(config, runner=runner, proof=proof,
                                    image_verifier=None if signed is None else verifier)
    if signed:
        driver._network()
    else:
        with pytest.raises(workers.ImageSignatureRefused, match="egress proxy" if signed is False else "policy"):
            driver._network()
    assert verifier.calls == ([] if signed is None else [proxy_image])


def unloadable_signing_policy(monkeypatch):
    def unavailable():
        raise SignatureVerificationError("signing configuration could not be loaded")

    monkeypatch.setattr(workers, "default_image_verifier", unavailable)


def test_real_driver_refuses_prepare_when_signing_policy_cannot_load(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        unloadable_signing_policy(monkeypatch)
        harness.prepare_context()
        assert harness.prepare()["state"] == "UNKNOWN"
        record = harness.service.store.records()[0]
        assert "ImageSignatureRefused" in record["error"] and "policy unavailable" in record["error"]
        assert not any("create" in call for call in commands.calls)
        assert harness.request("cleanup")["state"] == "CLEANED"


def test_service_start_spec_refuses_when_signing_policy_cannot_load(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        signed_driver(harness, commands, proof, SignedImages(WORKER_IMAGE, BASE))
        path = harness.prepare_context()
        assert harness.prepare()["state"] == "PREPARED"
        unloadable_signing_policy(monkeypatch)
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        # A RuntimeError is what the serve loop catches; the request is refused, not the service.
        with pytest.raises(RuntimeError, match="policy unavailable") as raised:
            harness.start()
        assert isinstance(raised.value, workers.ImageSignatureRefused)
        assert harness.service.store.records()[0]["state"] == "PREPARED"
        assert not any(call[0].endswith("skopeo") or "--frontend" in call for call in commands.calls)
        assert harness.request("cleanup")["state"] == "CLEANED"


def test_real_driver_refuses_inputs_when_signing_policy_cannot_load(tmp_path, monkeypatch):
    with real_driver_harness(tmp_path, monkeypatch) as (harness, commands, proof):
        harness.service._image_verifier = SignedImages(BASE)
        path = harness.prepare_context()
        assert harness.prepare()["state"] == "PREPARED"
        unloadable_signing_policy(monkeypatch)
        path.joinpath("Dockerfile").write_text("FROM base:release\n")
        assert harness.start()["state"] == "UNKNOWN"
        assert "policy unavailable" in harness.service.store.records()[0]["error"]
        assert not any(call[0].endswith("skopeo") or "--frontend" in call for call in commands.calls)


@pytest.mark.parametrize("cpu,memory,swap", [
    ("max 100000", "4096", "0"), ("200000 100000", "4096", "0"),
    ("100000 100000", "max", "0"), ("100000 100000", "4096", "max"),
    ("0 100000", "4096", "0"),
])
def test_kernel_enforcement_reads_fake_cgroup_files_not_flags(tmp_path, cpu, memory, swap):
    config, _ = configuration(tmp_path)
    root = tmp_path / "fake-cgroup"
    root.mkdir()
    (root / "cpu.max").write_text(cpu)
    (root / "memory.max").write_text(memory)
    (root / "memory.swap.max").write_text(swap)
    with pytest.raises(workers.EnforcementUnavailable):
        workers.KernelProof(config).limits(root, 1, 4096)


def test_typed_service_config_refuses_mapping_capacity_and_uncommissioned_network(tmp_path):
    config, _ = configuration(tmp_path)
    for changes in ({"cpu": 2}, {"memory_mb": 4097}, {"host_overhead_mb": 513},
                    {"max_concurrency": 2}, {"worker_image_id": "buildkit:latest"},
                    {"worker_cgroup_parent": config.host_cgroup}):
        with pytest.raises(ValueError):
            replace(config, **changes)
    with pytest.raises(ValueError, match="translated"):
        replace(config.grants[0], service_context_root="/desktop/translated")
    with pytest.raises(ValueError, match="proxy"):
        replace(config, grants=(replace(config.grants[0], allow_network=True),))
    invalid = tmp_path / "invalid.toml"
    invalid.write_text("[image_builder_service]\nunknown = true\n")
    with pytest.raises(ValueError):
        load_image_builder_service(invalid)


@pytest.mark.parametrize("budget", [ResourceBudget(), ResourceBudget(cpu=9, memory_mb=12288)])
def test_typed_operator_toml_loads_exact_service_grants_and_releases(tmp_path, budget):
    config, _ = configuration(tmp_path)
    config = replace(config, resources=budget)
    lines = ["[image_builder_service]"]
    for key, value in vars(config).items():
        if key not in {"grants", "images", "admission", "resources"} and value is not None:
            lines.append(f"{key} = {json.dumps(value)}")
    lines.append("[image_builder_service.admission]")
    for key, value in vars(config.admission).items():
        lines.append(f"{key} = {json.dumps(value)}")
    lines.append("[image_builder_service.resources]")
    for key, value in config.resources.view().items():
        lines.append(f"{key} = {value}")
    for table in ("grants", "images"):
        for entry in getattr(config, table):
            lines.append(f"[[image_builder_service.{table}]]")
            for key, value in vars(entry).items():
                lines.append(f"{key} = {json.dumps(value)}")
    path = tmp_path / "service.toml"
    path.write_text("\n".join(lines))
    assert load_image_builder_service(path) == config


def test_changed_operator_configuration_cannot_clear_old_host_intents(harness):
    harness.prepare_context()
    harness.prepare()
    harness.service.close()
    changed = replace(harness.config, docker_endpoint=str(Path(harness.config.state_root) / "other.sock"))
    with pytest.raises(workers.EnforcementUnavailable, match="original operator"):
        services.ImageBuilderService(changed, driver=harness.driver)
    harness.service = harness.open()
    assert harness.service.store.records()[0]["state"] == "PREPARED"


def test_no_platform_or_recipe_payload_fingerprints_are_added(harness, monkeypatch):
    original = services.hashlib.sha256

    def metadata_only(data):
        value = json.loads(data)
        assert set(value) == {"tenant", "project", "run_root", "builder"}
        return original(data)

    monkeypatch.setattr(services.hashlib, "sha256", metadata_only)
    path = harness.prepare_context()
    harness.prepare()
    payload = b"FROM base:release\nRUN [\"true\"]\n"
    path.joinpath("Dockerfile").write_bytes(payload)
    harness.start()
    harness.request("status")
    persisted = services.encoded(harness.service.store.records()[0])
    assert b"dockerfile_sha" not in persisted and b"payload_sha" not in persisted
    assert harness.request("cleanup")["state"] == "CLEANED"


@pytest.mark.parametrize("exception", [PermissionError, ValueError, OSError, RuntimeError])
def test_request_failure_logging_exposes_only_fixed_event_and_exception_type(monkeypatch, exception):
    calls = []

    class FakeLogger:
        def warning(self, message, *args, **kwargs):
            calls.append((message, args, kwargs))

    monkeypatch.setattr(services, "LOGGER", FakeLogger())
    services._log_request_failure(exception("secret request; docker command; /private/operator/path"))
    assert calls == [("BOUNDED_IMAGE_BUILDER_REQUEST_REJECTED exception_type=%s",
                      (exception.__name__,), {})]


def test_request_failure_logging_bounds_and_sanitizes_exception_type(monkeypatch):
    calls = []
    monkeypatch.setattr(services, "LOGGER", SimpleNamespace(
        warning=lambda message, *args, **kwargs: calls.append((message, args, kwargs))))
    exception = type("Bad\nType" + "x" * 1000, (RuntimeError,), {})
    services._log_request_failure(exception("must not appear in diagnostics"))
    message, arguments, options = calls[0]
    assert message == "BOUNDED_IMAGE_BUILDER_REQUEST_REJECTED exception_type=%s"
    assert arguments == (("Bad_Type" + "x" * 1000)[:64],)
    assert options == {}
