"""Count dedicated control and existing engine consumers in one unchanged host domain.

The shared ancestor is a hard ceiling, not a per-builder cap. Baseline capacity
remains reserved after the dedicated service retires. Application and action work
must use their own domains; this ledger cannot authorize either.
"""
from __future__ import annotations

import os
from dataclasses import asdict
import json
from pathlib import Path

from appsec_review.config.assurance import ResourceBudget
from appsec_review.container_runtime.buildkit_worker import EnforcementUnavailable, KernelProof, private_path
from appsec_review.runtime.resources import Reservation, ResourceAdmission


BASELINE_LEASE = "existing-engine-services"
COMMISSIONING_FIELDS = frozenset({
    "grants", "images", "native_engine", "network_id", "proxy_container_id",
    "proxy_image_id", "proxy_release_id", "proxy_url", "ip_release_id", "lifecycle_stage",
})


def engine_control_binding(config):
    """Freeze control custody/costs, not identities produced during provisioning."""
    contract = asdict(config)
    for name in COMMISSIONING_FIELDS:
        contract.pop(name)
    return {
        "kind": "appsec-review/engine-control-lifetime/1",
        "contract": json.loads(json.dumps(contract)),
    }


class EngineDomainProof:
    def __init__(self, config):
        self.config = config
        self.domain = config.engine_domain

    def groups(self):
        domain = self.domain
        limits = KernelProof(self.config).limits(
            Path(domain.cgroup), domain.cpu, domain.memory_mb * 1024**2)
        if (limits["cpu_quota_us"] != domain.cpu * limits["cpu_period_us"]
                or limits["memory_max"] != domain.memory_mb * 1024**2):
            raise EnforcementUnavailable("engine admission requires the exact existing shared ceiling")
        result = {}
        for index, value in enumerate((domain.cgroup, *domain.baseline_cgroups)):
            path = Path(value)
            if path.resolve(strict=True) != path:
                raise EnforcementUnavailable("engine domain group is not canonical")
            private_path(path)
            info = path.stat()
            result[f"engine_domain_{index}"] = {
                "path": value, "device": info.st_dev, "inode": info.st_ino}
        return result

    def live(self):
        self.groups()
        domain, host = self.domain, Path(self.config.host_cgroup)
        root = Path(domain.cgroup)
        count = 0
        for path in root.rglob("cgroup.procs"):
            if path.is_symlink():
                raise EnforcementUnavailable("engine domain inventory contains a symlink")
            group = path.parent
            owned = group.is_relative_to(host)
            baseline = any(group.is_relative_to(value) for value in domain.baseline_cgroups)
            for value in path.read_text().split():
                count += 1
                if count > 4096:
                    raise EnforcementUnavailable("engine domain process inventory exceeds its bound")
                pid = int(value)
                try:
                    uid = Path(f"/proc/{pid}").stat().st_uid
                    executable = Path(os.readlink(f"/proc/{pid}/exe")).name
                except FileNotFoundError:
                    continue
                if (uid != 0 or not (owned or baseline)
                        or (baseline and executable not in {
                            "dockerd", "containerd", "containerd-shim-runc-v2", "runc", "docker-proxy"})):
                    raise EnforcementUnavailable("engine domain contains an unaccounted or non-engine consumer")
        # Exclude only clean inactive file cache. Dirty/writeback pages and slab
        # remain charged; observed working sets are not guaranteed maxima.
        def working_set(path):
            before = int((path / "memory.current").read_text())
            values = dict(line.split() for line in (path / "memory.stat").read_text().splitlines())
            current = max(before, int((path / "memory.current").read_text()))
            reclaimable = max(0, int(values["inactive_file"]) - int(values["file_dirty"])
                              - int(values["file_writeback"]))
            if reclaimable > current:
                raise EnforcementUnavailable("engine memory observation changed during measurement")
            return current - reclaimable

        overhead = working_set(host)
        baseline = working_set(root) - overhead
        if baseline < 0:
            raise EnforcementUnavailable("engine memory scope changed during measurement")
        if (baseline > (domain.memory_mb - self.config.host_overhead_mb) * 1024**2
                or overhead > self.config.host_overhead_mb * 1024**2):
            raise EnforcementUnavailable("existing engine consumers leave insufficient admitted memory headroom")
        return {
            "cgroup": domain.cgroup, "cpu": domain.cpu, "memory_bytes": domain.memory_mb * 1024**2,
            "baseline_reservation": {
                "cpu": domain.cpu - self.config.host_cpu,
                "memory_bytes": (domain.memory_mb - self.config.host_overhead_mb) * 1024**2},
            "control_reservation": {
                "cpu": self.config.host_cpu, "memory_bytes": self.config.host_overhead_mb * 1024**2},
            "observed_baseline_working_set_bytes": baseline,
            "observed_control_working_set_bytes": overhead,
        }


class EngineDomainAdmission:
    def __init__(self, config, binding, request, *, proof=None):
        self.config, self.request = config, request
        domain = config.engine_domain
        self.binding = (engine_control_binding(config)
                        if domain.control_lifetime_id is not None else binding)
        self.budget = ResourceBudget(cpu=domain.cpu, memory_mb=domain.memory_mb,
                                     io_slots=1, staging_memory_mb=1)
        self.baseline_request = Reservation(
            domain.cpu - request.cpu, domain.memory_mb - request.memory_mb, io_slots=0)
        self.proof = proof or EngineDomainProof(config)

    def _ledger(self, identity=None):
        metadata = Path(self.config.engine_domain.metadata_root)
        private_path(metadata)
        admission = ResourceAdmission(metadata, self.budget)
        if identity is None:
            admission.root.mkdir(mode=0o700, exist_ok=True)
        private_path(admission.root)
        info = admission.root.stat()
        if identity is not None and [info.st_dev, info.st_ino] != identity:
            raise EnforcementUnavailable("engine-domain admission ledger was rebound")
        return admission

    def _baseline_binding(self):
        return {"kind": "appsec-review/engine-domain-baseline/1", "groups": self.proof.groups()}

    def reserve(self):
        self.proof.live()
        admission = self._ledger()
        admission.reserve_persistent(BASELINE_LEASE, self.baseline_request, self._baseline_binding())
        admission.reserve_persistent(self.config.admission.lease_id, self.request, self.binding)
        info = admission.root.stat()
        return [info.st_dev, info.st_ino]

    def verify(self, identity):
        self.proof.live()
        admission = self._ledger(identity)
        admission.verify_persistent(BASELINE_LEASE, self.baseline_request, self._baseline_binding())
        admission.verify_persistent(self.config.admission.lease_id, self.request, self.binding)

    def release(self, identity):
        admission = self._ledger(identity)
        admission.verify_persistent(BASELINE_LEASE, self.baseline_request, self._baseline_binding())
        admission._release_persistent(self.config.admission.lease_id, self.request, self.binding)
