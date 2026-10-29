"""Count dedicated control and existing engine consumers in one unchanged host domain.

The shared ancestor is a hard ceiling, not a per-builder cap. Baseline capacity
remains reserved after the dedicated service retires. A reboot recreates the
baseline cgroups, so a baseline lease created in another boot is dropped (with a
previous_boot receipt) only while it is the ledger's sole lease; reserve then
records a fresh one. Application and action work must use their own domains;
this ledger cannot authorize either.
"""
from __future__ import annotations

import os
from dataclasses import asdict
import json
from pathlib import Path
import re
import time

from appsec_review.config.assurance import ResourceBudget
from appsec_review.container_runtime.buildkit_worker import EnforcementUnavailable, KernelProof, private_path
from appsec_review.runtime.resources import Reservation, ResourceAdmission


BASELINE_LEASE = "existing-engine-services"
BASELINE_KIND = "appsec-review/engine-domain-baseline/1"
# ResourceAdmission records the creating process as "<boot_id>:<start_time>".
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
LEASE_PROCESS = re.compile("(" + BOOT_ID.pattern + "):[0-9]+")
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
    def __init__(self, config, binding, request, *, proof=None, boot_id=None):
        if boot_id is None:
            from appsec_review.container_runtime.builder_admission import current_boot_id as boot_id
        self.config, self.request, self.boot_id = config, request, boot_id
        self.baseline_receipt = None
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
        return {"kind": BASELINE_KIND, "groups": self.proof.groups()}

    def _previous_boot_baseline(self, *, legacy):
        """Receipt for an otherwise exact baseline created in another boot, else None.

        ``legacy`` accepts a baseline without a recorded creator; only a lifetime
        release that just proved its own generation belonged to a previous boot passes it.
        """
        current = self.boot_id()

        def assess(entry):
            binding = entry.get("persistent")
            if (not BOOT_ID.fullmatch(current) or not isinstance(binding, dict)
                    or binding.get("kind") != BASELINE_KIND
                    or entry.get("reservation") != asdict(self.baseline_request)
                    or entry.get("action") != "image.builder.service"
                    or entry.get("containers") != [] or entry.get("builds") != []
                    or entry.get("quarantine")):
                return None
            creator = entry.get("process_identity")
            match = LEASE_PROCESS.fullmatch(creator) if isinstance(creator, str) else None
            if match is None and (creator is not None or not legacy):
                return None
            recorded = None if match is None else match.group(1)
            if recorded == current:
                return None
            return {"basis": "previous_boot", "lease_id": BASELINE_LEASE,
                    "recorded_boot_id": recorded, "current_boot_id": current,
                    "recorded_groups": binding.get("groups"), "observed_at": time.time()}
        return assess

    def reserve(self):
        self.proof.live()
        admission = self._ledger()
        self.baseline_receipt = admission._release_sole_persistent(
            BASELINE_LEASE, self._previous_boot_baseline(legacy=False))
        admission.reserve_persistent(BASELINE_LEASE, self.baseline_request, self._baseline_binding())
        admission.reserve_persistent(self.config.admission.lease_id, self.request, self.binding)
        info = admission.root.stat()
        return [info.st_dev, info.st_ino]

    def verify(self, identity):
        self.proof.live()
        admission = self._ledger(identity)
        admission.verify_persistent(BASELINE_LEASE, self.baseline_request, self._baseline_binding())
        admission.verify_persistent(self.config.admission.lease_id, self.request, self.binding)

    def release(self, identity, *, previous_boot=False):
        """Release this lifetime's lease; a previous-boot release skips the stale baseline check
        and drops that baseline when nothing else remains. Returns the drop receipt, if any."""
        admission = self._ledger(identity)
        if not previous_boot:
            admission.verify_persistent(BASELINE_LEASE, self.baseline_request, self._baseline_binding())
        admission._release_persistent(self.config.admission.lease_id, self.request, self.binding)
        if not previous_boot:
            return None
        return admission._release_sole_persistent(
            BASELINE_LEASE, self._previous_boot_baseline(legacy=True))
