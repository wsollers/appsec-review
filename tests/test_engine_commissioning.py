"""One-way commissioning retains the same real, continuously counted engine lease."""
from dataclasses import asdict, replace
import json
from pathlib import Path
from uuid import uuid4

import pytest

from appsec_review.config.image_builder_service import DockerHelperScope, EngineDomainConfig
from appsec_review.container_runtime import image_builder_service as services
from appsec_review.container_runtime.builder_admission import (
    BuilderAdmission, LifetimeProof, open_operator_journal, service_contract,
)
from appsec_review.container_runtime.builder_admission import _ledger as builder_ledger
from appsec_review.container_runtime.buildkit_worker import EnforcementUnavailable, KernelProof
from tests.test_bounded_image_build_service import (
    BASE, FakeLifetimeProof, Harness, configuration, forbid_real_execution,  # noqa: F401
)
from tests.test_native_engine_broker import native  # noqa: F401


class CommissioningProof(FakeLifetimeProof):
    ready = True
    checks = 0

    def commissioned(self):
        self.checks += 1
        if not self.ready:
            raise EnforcementUnavailable("real host proof refused commissioning")


class DomainProof:
    def groups(self):
        return {"engine": {"path": "/sys/fs/cgroup/engine-private", "device": 1, "inode": 123}}

    def live(self):
        pass


@pytest.fixture
def provisional(tmp_path):
    config, _ = configuration(tmp_path)
    metadata = tmp_path / "engine-metadata"
    metadata.mkdir(mode=0o700)
    config = replace(
        config, lifecycle_stage="provisioning", resource_mode="concurrency_only",
        lifetime_domain="engine", host_cgroup="/sys/fs/cgroup/engine-private/control",
        docker_helper_scope=DockerHelperScope(
            "/var/lib/builder-private", "/run/builder-private",
            "/run/builder-private/containerd/containerd.sock"),
        engine_domain=EngineDomainConfig(
            str(metadata), "/sys/fs/cgroup/engine-private",
            ("/sys/fs/cgroup/engine-private/docker.service",),
            control_lifetime_id=config.admission.lease_id))
    owner = admission(config)
    owner.reserve()
    return owner


def admission(config):
    result = BuilderAdmission(config, proof=CommissioningProof(config))
    result.engine_admission.proof = DomainProof()
    return result


def bank(owner):
    return owner.engine_admission._ledger().root / "leases.json"


def test_provisioning_refuses_clients_and_retains_counted_owner_on_recovery(provisional):
    original = bank(provisional).read_bytes()
    with pytest.raises(EnforcementUnavailable, match="not been reserved"):
        provisional.verify()
    provisional.proof.live_members = [{"pid": 456, "start_token": "boot:123"}]
    recovered = admission(provisional.config)
    recovered.proof.live_members = provisional.proof.live_members
    assert recovered.reserve() == provisional.config.admission.lease_id
    assert json.loads(recovered.path.read_text())["members"] == recovered.proof.live_members
    assert bank(provisional).read_bytes() == original
    entries = json.loads(original)["leases"]
    assert sum(value["reservation"]["cpu"] for value in entries.values()) == 2
    assert sum(value["reservation"]["memory_mb"] for value in entries.values()) == 2048


def test_finalization_pins_observed_assets_without_rebinding_or_releasing_lease(provisional):
    original = bank(provisional).read_bytes()
    from appsec_review.config.image_builder_service import BuilderImage
    config = replace(
        provisional.config, lifecycle_stage="configured",
        images=(*provisional.config.images, BuilderImage("extra:release", BASE, "extra-release")))
    owner = admission(config)
    owner.finalize_commissioning()
    owner.verify()
    assert owner.proof.checks == 1
    assert bank(owner).read_bytes() == original
    anchor = json.loads(owner.path.read_text())
    assert anchor["state"] == "RESERVED" and anchor["service_contract"] == owner.contract
    owner.finalize_commissioning()
    assert bank(owner).read_bytes() == original
    changed = admission(replace(config, images=provisional.config.images))
    with pytest.raises(EnforcementUnavailable, match="configuration"):
        changed.finalize_commissioning()


@pytest.mark.parametrize("change", ["cost", "custody", "generation", "host-proof", "occupied"])
def test_failed_commissioning_keeps_provisional_fence_and_both_reservations(provisional, change):
    config = replace(provisional.config, lifecycle_stage="configured")
    if change == "cost":
        config = replace(config, host_overhead_mb=256)
    elif change == "custody":
        config = replace(config, worker_release_id="another-worker")
    owner = admission(config)
    if change == "generation":
        owner.proof.generation += 1
    elif change == "host-proof":
        owner.proof.ready = False
    elif change == "occupied":
        journal = open_operator_journal(Path(config.state_root))
        journal.execute("INSERT INTO engine_interlock VALUES (1, '{}')")
        journal.commit()
        journal.close()
    before_bank, before_anchor = bank(owner).read_bytes(), owner.path.read_bytes()
    with pytest.raises(EnforcementUnavailable):
        owner.finalize_commissioning()
    assert bank(owner).read_bytes() == before_bank
    assert owner.path.read_bytes() == before_anchor


def test_provisional_retirement_requires_actual_shutdown_and_keeps_engine_baseline(provisional):
    original = bank(provisional).read_bytes()
    provisional.proof.stopped_result = False
    with pytest.raises(EnforcementUnavailable, match="termination"):
        provisional.release()
    assert bank(provisional).read_bytes() == original
    provisional.proof.stopped_result = True
    provisional.release()
    assert list(json.loads(bank(provisional).read_text())["leases"]) == ["existing-engine-services"]
    assert json.loads(provisional.path.read_text())["state"] == "RELEASED"
    with pytest.raises(EnforcementUnavailable, match="retired"):
        provisional.reserve()


def test_escaped_dedicated_daemon_is_still_owned_before_socket_publication(provisional, monkeypatch):
    proof = KernelProof(provisional.config)
    monkeypatch.setattr(proof, "_process",
                        lambda pid: (1, ["dockerd", "--exec-root=/run/builder-private"]))
    assert proof._owned_helper("dockerd", 500, -1, Path("/sys/fs/cgroup/escaped"))


def test_provisioning_is_not_available_without_an_explicit_engine_owner(provisional):
    with pytest.raises(ValueError, match="provisioning"):
        replace(provisional.config,
                engine_domain=replace(provisional.config.engine_domain, control_lifetime_id=None))
    with pytest.raises(ValueError, match="original admission"):
        replace(provisional.config,
                engine_domain=replace(provisional.config.engine_domain, control_lifetime_id="f" * 32))


@pytest.mark.parametrize("occupied", ["workers", "executions", "application"])
def test_real_commissioning_proof_refuses_any_active_noncontrol_scope(provisional, tmp_path, monkeypatch, occupied):
    roots = [Path(provisional.config.host_cgroup)]
    for name in ("workers", "executions", "application"):
        root = tmp_path / name
        root.mkdir()
        (root / "cgroup.events").write_text(f"populated {int(name == occupied)}\n")
        roots.append(root)
    proof = LifetimeProof(provisional.config)
    monkeypatch.setattr(proof, "_roots", lambda: roots)
    with pytest.raises(EnforcementUnavailable, match="empty application and action"):
        proof.commissioned()


def test_empty_owned_cgroups_do_not_hide_an_escaped_provisioning_helper(provisional, monkeypatch):
    proof = LifetimeProof(provisional.config)
    monkeypatch.setattr(proof, "empty", lambda: True)
    monkeypatch.setattr(KernelProof, "owned_helper_groups",
                        lambda self: iter([("runc", Path("/sys/fs/cgroup/escaped"))]))
    assert not proof.stopped([])


@pytest.mark.parametrize("arguments", [
    ["dockerd"],
    ["dockerd", "--containerd=/run/containerd/containerd.sock"],
    ["dockerd", "--containerd=/run/other-private/containerd.sock"],
])
def test_private_docker_roots_never_imply_private_containerd(provisional, arguments):
    with pytest.raises(EnforcementUnavailable, match="explicit private containerd"):
        KernelProof(provisional.config)._private_containerd(arguments)


@pytest.mark.parametrize("defect", [
    None, "uid", "group", "executable", "namespace", "root", "state", "address", "generation",
])
def test_real_private_containerd_proof_requires_socket_peer_store_and_generation(
        provisional, monkeypatch, defect):
    from types import SimpleNamespace
    from appsec_review.container_runtime import buildkit_worker as workers
    import stat
    import struct

    endpoint = provisional.config.docker_helper_scope.containerd_endpoint
    proof = KernelProof(provisional.config)
    class Socket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            pass
        def connect(self, path):
            assert path == endpoint
        def getsockopt(self, *args):
            return struct.pack("3i", 501, 1000 if defect == "uid" else 0, 0)
    monkeypatch.setattr(workers.socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(workers, "private_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(Path, "lstat", lambda self: SimpleNamespace(st_mode=stat.S_IFSOCK))
    tokens = iter(["boot:1", "boot:2" if defect == "generation" else "boot:1"])
    monkeypatch.setattr(workers, "process_token", lambda pid: next(tokens))
    monkeypatch.setattr(workers.os, "readlink",
                        lambda path: "/usr/bin/" + ("foreign" if defect == "executable" else "containerd"))
    monkeypatch.setattr(proof, "process_cgroup", lambda pid: Path(
        "/sys/fs/cgroup/escaped" if defect == "group" else provisional.config.host_cgroup + "/containerd"))
    def namespaces(pid):
        if defect == "namespace":
            raise EnforcementUnavailable("containerd namespace differs")
    monkeypatch.setattr(proof, "_same_host", namespaces)
    arguments = ["containerd", "--root=/var/lib/builder-private/containerd",
                 "--state=/run/builder-private/containerd", "--address=" + endpoint]
    if defect in {"root", "state", "address"}:
        arguments = [f"--{defect}=/shared/infra" if value.startswith(f"--{defect}=") else value
                     for value in arguments]
    monkeypatch.setattr(proof, "_process", lambda pid: (1, arguments))
    if defect:
        with pytest.raises(EnforcementUnavailable):
            proof._private_containerd(["dockerd", "--containerd=" + endpoint])
    else:
        proof._private_containerd(["dockerd", "--containerd=" + endpoint])

CURRENT_BOOT = "11111111-1111-4111-8111-111111111111"
OLD_BOOT = "22222222-2222-4222-8222-222222222222"
REAL_BOOT = Path("/proc/sys/kernel/random/boot_id").read_text().strip()


class RebootedDomainProof(DomainProof):
    def groups(self):
        return {"engine": {"path": "/sys/fs/cgroup/engine-private", "device": 1, "inode": 999}}


def successor(owner, *, boot=CURRENT_BOOT, name="operator-next"):
    """A new lifetime sharing the engine ledger, reserved after the host restart."""
    state = Path(owner.config.state_root).parent / name
    state.mkdir(mode=0o700)
    lease_id = uuid4().hex
    config = replace(
        owner.config, state_root=str(state), admission=replace(owner.config.admission, lease_id=lease_id),
        engine_domain=replace(owner.config.engine_domain, control_lifetime_id=lease_id))
    result = BuilderAdmission(config, proof=CommissioningProof(config), boot_id=lambda: boot)
    result.engine_admission.proof = RebootedDomainProof()
    return result


def rebooted(owner, members):
    anchor = json.loads(owner.path.read_text())
    anchor["members"] = members
    owner.path.write_text(json.dumps(anchor))
    result = BuilderAdmission(owner.config, proof=CommissioningProof(owner.config),
                              boot_id=lambda: CURRENT_BOOT)
    result.proof.generation += 1
    result.engine_admission.proof = RebootedDomainProof()
    return result


def test_previous_boot_lifetime_releases_despite_recreated_cgroups(provisional):
    owner = rebooted(provisional, [
        {"pid": 27386, "start_token": f"{OLD_BOOT}:7668879"},
        {"pid": 27390, "start_token": f"27390:{OLD_BOOT}:7668901"},
    ])
    recorded_groups = json.loads(owner.path.read_text())["groups"]
    owner.release()
    assert owner.proof.stopped_calls == [True]
    anchor = json.loads(owner.path.read_text())
    assert anchor["state"] == "RELEASED"
    assert anchor["release"]["basis"] == "previous_boot"
    assert anchor["release"]["recorded_boot_ids"] == [OLD_BOOT]
    assert anchor["release"]["current_boot_id"] == CURRENT_BOOT
    assert anchor["release"]["recorded_groups"] == recorded_groups
    baseline = anchor["release"]["engine_baseline"]
    assert baseline["basis"] == "previous_boot" and baseline["lease_id"] == "existing-engine-services"
    assert (baseline["recorded_boot_id"], baseline["current_boot_id"]) == (REAL_BOOT, CURRENT_BOOT)
    assert baseline["recorded_groups"] == DomainProof().groups()
    ledger = json.loads(bank(owner).read_text())
    assert ledger["leases"] == {} and ledger["dropped_persistent"] == [baseline]
    before = owner.path.read_bytes(), bank(owner).read_bytes()
    owner.release()
    assert (owner.path.read_bytes(), bank(owner).read_bytes()) == before
    with pytest.raises(EnforcementUnavailable):
        owner.reserve()
    following = successor(owner)
    following.reserve()
    leases = json.loads(bank(owner).read_text())["leases"]
    assert set(leases) == {"existing-engine-services", following.config.admission.lease_id}
    assert leases["existing-engine-services"]["persistent"]["groups"] == RebootedDomainProof().groups()
    assert "engine_baseline_release" not in json.loads(following.path.read_text())


def renumber_ledger(owner, *, device=16, inode=0, state=None):
    """Record the engine ledger identity as a host restart that renumbered its disk would."""
    anchor = json.loads(owner.path.read_text())
    recorded = anchor["ledger_identity"]
    anchor["ledger_identity"] = [recorded[0] + device, recorded[1] + inode]
    if state is not None:
        anchor["state"] = state
        anchor["release"] = {"basis": "previous_boot", "recorded_boot_ids": [OLD_BOOT]}
    owner.path.write_text(json.dumps(anchor))
    return recorded


@pytest.mark.parametrize("state", [None, "RELEASING"])
def test_previous_boot_release_accepts_a_renumbered_ledger_device(provisional, state):
    live = renumber_ledger(provisional, state=state)
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    owner.release()
    anchor = json.loads(owner.path.read_text())
    assert anchor["state"] == "RELEASED" and anchor["release"]["current_boot_id"] == CURRENT_BOOT
    rebinding = anchor["release"]["ledger_rebinding"]
    assert rebinding["basis"] == "previous_boot_device_renumber"
    assert (rebinding["recorded_device"], rebinding["observed_device"], rebinding["inode"]) == (
        live[0] + 16, live[0], live[1])
    assert rebinding["path"] == str(bank(owner).parent)
    assert json.loads(bank(owner).read_text())["leases"] == {}
    assert anchor["release"]["engine_baseline"]["basis"] == "previous_boot"


def test_same_boot_release_still_refuses_a_renumbered_ledger_device(provisional):
    renumber_ledger(provisional)
    before = bank(provisional).read_bytes()
    with pytest.raises(EnforcementUnavailable, match="ledger was rebound"):
        provisional.release()
    assert bank(provisional).read_bytes() == before
    assert "release" not in json.loads(provisional.path.read_text())


def test_previous_boot_release_still_refuses_a_different_ledger_inode(provisional):
    renumber_ledger(provisional, device=16, inode=1)
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    before = bank(owner).read_bytes()
    with pytest.raises(EnforcementUnavailable, match="ledger was rebound"):
        owner.release()
    assert bank(owner).read_bytes() == before
    assert json.loads(owner.path.read_text())["state"] == "RELEASING"


def test_client_ledger_device_renumber_is_accepted_only_when_explicitly_allowed(tmp_path):
    harness = Harness(tmp_path, require_worker_reservation=True)
    try:
        info = (Path(harness.context.metadata_root).resolve() / "resource-admission").lstat()
        renumbered_identity = [info.st_dev + 16, info.st_ino]
        with pytest.raises(EnforcementUnavailable, match="rebound"):
            builder_ledger(harness.config, expected_identity=renumbered_identity)
        with pytest.raises(EnforcementUnavailable, match="rebound"):
            builder_ledger(harness.config, expected_identity=[info.st_dev + 16, info.st_ino + 1],
                           renumbered=[])
        receipts = []
        builder_ledger(harness.config, expected_identity=renumbered_identity, renumbered=receipts)
        assert [(item["recorded_device"], item["observed_device"], item["inode"]) for item in receipts] == [
            (info.st_dev + 16, info.st_dev, info.st_ino)]
    finally:
        harness.service.close()


def test_reserve_drops_sole_baseline_retained_from_a_previous_boot(provisional):
    provisional.release()
    assert list(json.loads(bank(provisional).read_text())["leases"]) == ["existing-engine-services"]
    following = successor(provisional)
    following.reserve()
    receipt = json.loads(following.path.read_text())["engine_baseline_release"]
    assert (receipt["recorded_boot_id"], receipt["current_boot_id"]) == (REAL_BOOT, CURRENT_BOOT)
    leases = json.loads(bank(following).read_text())["leases"]
    assert leases["existing-engine-services"]["persistent"]["groups"] == RebootedDomainProof().groups()


def test_same_boot_baseline_with_changed_cgroups_is_still_refused(provisional):
    provisional.release()
    following = successor(provisional, boot=REAL_BOOT)
    before = bank(provisional).read_bytes()
    with pytest.raises(ValueError, match="rebound or changed"):
        following.reserve()
    assert bank(provisional).read_bytes() == before
    assert not following.path.exists()


def test_previous_boot_baseline_is_kept_while_another_lease_remains(provisional):
    path = bank(provisional)
    state = json.loads(path.read_text())
    other = dict(state["leases"]["existing-engine-services"], persistent={"kind": "other-lifetime"},
                 reservation={"cpu": 0, "memory_mb": 0, "io_slots": 0})
    state["leases"]["other-lifetime"] = other
    path.write_text(json.dumps(state))
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    owner.release()
    anchor = json.loads(owner.path.read_text())
    assert anchor["state"] == "RELEASED" and "engine_baseline" not in anchor["release"]
    assert set(json.loads(path.read_text())["leases"]) == {"existing-engine-services", "other-lifetime"}
    following = successor(owner)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="rebound or changed"):
        following.reserve()
    assert path.read_bytes() == before
    state = json.loads(path.read_text())
    del state["leases"]["other-lifetime"]
    path.write_text(json.dumps(state))
    following.reserve()
    assert json.loads(following.path.read_text())["engine_baseline_release"]["recorded_boot_id"] == REAL_BOOT


def legacy_baseline(owner, creator):
    path = bank(owner)
    state = json.loads(path.read_text())
    if creator == "missing":
        del state["leases"]["existing-engine-services"]["process_identity"]
    else:
        state["leases"]["existing-engine-services"]["process_identity"] = creator
    path.write_text(json.dumps(state))
    return path


@pytest.mark.parametrize("creator", [None, "missing"])
def test_legacy_baseline_without_creator_drops_on_previous_boot_release(provisional, creator):
    path = legacy_baseline(provisional, creator)
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    owner.release()
    baseline = json.loads(owner.path.read_text())["release"]["engine_baseline"]
    assert (baseline["recorded_boot_id"], baseline["current_boot_id"]) == (None, CURRENT_BOOT)
    assert json.loads(path.read_text())["leases"] == {}
    successor(owner).reserve()


@pytest.mark.parametrize("creator", [None, "missing"])
def test_legacy_baseline_without_creator_is_not_dropped_by_reserve(provisional, creator):
    provisional.release()
    path = legacy_baseline(provisional, creator)
    before = path.read_bytes()
    with pytest.raises(ValueError, match="rebound or changed"):
        successor(provisional).reserve()
    assert path.read_bytes() == before


@pytest.mark.parametrize("creator", ["boot:123", f"{OLD_BOOT}"])
def test_unparseable_baseline_creator_is_never_dropped(provisional, creator):
    path = legacy_baseline(provisional, creator)
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    owner.release()
    assert "engine_baseline" not in json.loads(owner.path.read_text())["release"]
    assert list(json.loads(path.read_text())["leases"]) == ["existing-engine-services"]
    with pytest.raises(ValueError, match="rebound or changed"):
        successor(owner).reserve()


@pytest.mark.parametrize("members", [
    [{"pid": 1, "start_token": f"{CURRENT_BOOT}:5"}],
    [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}, {"pid": 2, "start_token": f"{CURRENT_BOOT}:6"}],
    [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}, {"pid": 2, "start_token": "boot:123"}],
    [{"pid": 1, "start_token": OLD_BOOT}],
    [{"pid": 1}],
    [],
])
def test_previous_boot_release_requires_every_member_from_another_boot(provisional, members):
    owner = rebooted(provisional, members)
    before = owner.path.read_bytes(), bank(owner).read_bytes()
    with pytest.raises(EnforcementUnavailable, match="configuration or cgroups changed"):
        owner.release()
    assert (owner.path.read_bytes(), bank(owner).read_bytes()) == before


def test_previous_boot_release_still_requires_stopped_scopes(provisional):
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    owner.proof.stopped_result = False
    before = owner.path.read_bytes(), bank(owner).read_bytes()
    with pytest.raises(EnforcementUnavailable, match="termination"):
        owner.release()
    assert (owner.path.read_bytes(), bank(owner).read_bytes()) == before


def test_previous_boot_release_does_not_apply_to_changed_contracts(provisional):
    owner = rebooted(provisional, [{"pid": 1, "start_token": f"{OLD_BOOT}:5"}])
    changed = BuilderAdmission(replace(owner.config, host_overhead_mb=256),
                               proof=owner.proof, boot_id=lambda: CURRENT_BOOT)
    with pytest.raises(EnforcementUnavailable, match="configuration or cgroups changed"):
        changed.release()


def test_only_previous_boot_proof_treats_missing_cgroups_as_empty(provisional, tmp_path, monkeypatch):
    present = tmp_path / "present"
    present.mkdir()
    (present / "cgroup.events").write_text("populated 0\n")
    proof = LifetimeProof(provisional.config)
    monkeypatch.setattr(proof, "_roots", lambda: [present, tmp_path / "missing"])
    assert proof.empty(missing_ok=True)
    with pytest.raises(FileNotFoundError):
        proof.empty()


def recovery_runtime(config):
    """The operator config rebuilt for the installed release, pointing at the prior lifetime."""
    return replace(config, native_engine=replace(
        config.native_engine, runtime_root="/recovery-operator/lib", runtime_release_id="recovery-runtime"))


class RecreatedEngineDomain:
    def __init__(self, config):
        self.config = config

    def groups(self):
        return {"engine": {"path": self.config.engine_domain.cgroup, "device": 1, "inode": 999}}

    def live(self):
        pass


def restarted_admission(config):
    """Real admission after a host restart: new boot ID, recreated lifetime and engine cgroups."""
    result = BuilderAdmission(config, proof=CommissioningProof(config), boot_id=lambda: CURRENT_BOOT)
    result.proof.generation += 1
    result.engine_admission.proof = RecreatedEngineDomain(config)
    return result


def restart_prior_lifetime(native):
    native.service.close()
    anchor = json.loads(native.lifetime.path.read_text())
    anchor["members"] = [{"pid": 27386, "start_token": f"{OLD_BOOT}:7668879"}]
    native.lifetime.path.write_text(json.dumps(anchor))
    return anchor["groups"]


@pytest.mark.parametrize("native", ["engine-domain"], indirect=True)
def test_recovery_runtime_releases_prior_lifetime_reserved_in_a_previous_boot(native, monkeypatch):
    prior = native.config
    recorded_groups = restart_prior_lifetime(native)
    opened = []
    monkeypatch.setattr(services, "BuilderAdmission",
                        lambda config: opened.append(restarted_admission(config)) or opened[-1])
    services.release_prior_runtime(recovery_runtime(prior), prior)
    assert [owner.config for owner in opened] == [prior]
    owner = opened[0]
    assert owner.proof.stopped_calls == [True]
    anchor = json.loads(owner.path.read_text())
    assert anchor["state"] == "RELEASED" and anchor["service_contract"] == service_contract(prior)
    release = anchor["release"]
    assert (release["basis"], release["recorded_boot_ids"], release["current_boot_id"]) == (
        "previous_boot", [OLD_BOOT], CURRENT_BOOT)
    assert release["recorded_groups"] == recorded_groups != owner.proof.groups()
    baseline = release["engine_baseline"]
    assert baseline["basis"] == "previous_boot" and baseline["lease_id"] == "existing-engine-services"
    assert (baseline["recorded_boot_id"], baseline["current_boot_id"]) == (REAL_BOOT, CURRENT_BOOT)
    ledger = json.loads(bank(owner).read_text())
    assert ledger["leases"] == {} and ledger["dropped_persistent"] == [baseline]
    before = owner.path.read_bytes(), bank(owner).read_bytes()
    services.release_prior_runtime(recovery_runtime(prior), prior)
    assert (owner.path.read_bytes(), bank(owner).read_bytes()) == before


@pytest.mark.parametrize("native", ["engine-domain"], indirect=True)
def test_recovery_runtime_cannot_reserve_serve_or_release_the_prior_lifetime(native):
    restart_prior_lifetime(native)
    recovery = restarted_admission(recovery_runtime(native.config))
    before = recovery.path.read_bytes(), bank(recovery).read_bytes()
    for operation in (recovery.reserve, recovery.verify, recovery.release):
        with pytest.raises(EnforcementUnavailable, match="configuration or cgroups changed"):
            operation()
    assert (recovery.path.read_bytes(), bank(recovery).read_bytes()) == before
    assert json.loads(recovery.path.read_text())["state"] == "RESERVED"


@pytest.mark.parametrize("native", ["engine-domain"], indirect=True)
@pytest.mark.parametrize("field", ["state_root", "gate_binary"])
def test_recovery_runtime_cannot_also_rebind_prior_state_or_gate(native, monkeypatch, tmp_path, field):
    restart_prior_lifetime(native)
    current = recovery_runtime(native.config)
    if field == "state_root":
        state = tmp_path / "recovery-operator"
        state.mkdir(mode=0o700)
        current = replace(current, state_root=str(state))
    else:
        current = replace(current, native_engine=replace(current.native_engine, gate_binary="/foreign"))
    monkeypatch.setattr(services, "BuilderAdmission", lambda config: pytest.fail("rebound policy used"))
    before = native.lifetime.path.read_bytes(), bank(native.lifetime).read_bytes()
    with pytest.raises(EnforcementUnavailable, match="cannot change"):
        services.release_prior_runtime(current, native.config)
    assert (native.lifetime.path.read_bytes(), bank(native.lifetime).read_bytes()) == before


def legacy_contract(config):
    """The contract a release from before operator source mappings recorded: no source key at all."""
    value = json.loads(json.dumps(asdict(config)))
    for image in value["native_engine"]["images"]:
        assert image.pop("source_image_id") is None
    return value


@pytest.mark.parametrize("native", ["engine-domain"], indirect=True)
def test_prior_lifetime_recorded_before_source_mappings_still_releases(native, monkeypatch):
    prior = native.config
    anchor = json.loads(native.lifetime.path.read_text())
    assert anchor["service_contract"] == legacy_contract(prior) == service_contract(prior)
    restart_prior_lifetime(native)
    opened = []
    monkeypatch.setattr(services, "BuilderAdmission",
                        lambda config: opened.append(restarted_admission(config)) or opened[-1])
    services.release_prior_runtime(recovery_runtime(prior), prior)
    released = json.loads(opened[0].path.read_text())
    assert released["state"] == "RELEASED" and released["service_contract"] == legacy_contract(prior)
