"""One-way commissioning retains the same real, continuously counted engine lease."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config.image_builder_service import DockerHelperScope, EngineDomainConfig
from appsec_review.container_runtime.builder_admission import BuilderAdmission, LifetimeProof, open_operator_journal
from appsec_review.container_runtime.buildkit_worker import EnforcementUnavailable, KernelProof
from tests.test_bounded_image_build_service import (
    BASE, FakeLifetimeProof, configuration, forbid_real_execution,  # noqa: F401
)


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
        docker_helper_scope=DockerHelperScope("/var/lib/builder-private", "/run/builder-private"),
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
