"""Host-metadata leases for aggregate review-action admission."""
from __future__ import annotations

from _thread import RLock
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from functools import wraps
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Iterator
from uuid import uuid4

from appsec_review.config.assurance import ResourceBudget
from appsec_review.observability.events import EventLog
from appsec_review.storage import atomic_json, bounded_file_lock
from appsec_review.runtime import execution_safety as safety


def process_identity(pid: int) -> str | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text()
        started = value[value.rfind(")") + 2:].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"{boot}:{started}"
    except FileNotFoundError:
        return None


@dataclass
class ActiveLease:
    admission: "ResourceAdmission"
    lease_id: str
    request: "Reservation"
    execution_lock: RLock = field(default_factory=RLock)
    closed: bool = False


_ACTIVE: ContextVar[ActiveLease | None] = ContextVar("resource_lease", default=None)
_OWNER: ContextVar[tuple["ResourceAdmission", EventLog] | None] = ContextVar(
    "review_resource_owner", default=None)


@contextmanager
def review_resource_scope(metadata_root: Path, budget: ResourceBudget, events: EventLog, *,
                          require_container_removal: bool = False):
    from appsec_review.config.native_dagster import native_execution_requested

    if type(require_container_removal) is not bool:
        raise ValueError("container removal policy must be boolean")
    token = _OWNER.set((ResourceAdmission(
        metadata_root, budget,
        require_container_removal=(require_container_removal or native_execution_requested()
                                   or safety.active())), events))
    try:
        yield
    finally:
        _OWNER.reset(token)


def review_resources_active() -> bool:
    return _OWNER.get() is not None or _ACTIVE.get() is not None


class ImagePreparationUnavailable(RuntimeError):
    """The review has no approved resource-bounded image builder."""


def require_bounded_image_builder() -> None:
    if review_resources_active():
        from appsec_review.container_runtime.image_builder import require_builder
        require_builder()


@contextmanager
def _reserve_execution(*, cpu: str, memory: str, action: str, timeout_seconds: int):
    owner, active = _OWNER.get(), _ACTIVE.get()
    if owner is None and active is None:
        yield
        return
    if not isinstance(memory, str) or not re.fullmatch(r"[1-9][0-9]*[mg]", memory):
        raise ValueError("container memory must be a bounded MiB/GiB value")
    if active is not None:
        admission = active.admission
        if owner is not None and (
                owner[0].root != admission.root or owner[0].budget != admission.budget
                or owner[0].require_container_removal != admission.require_container_removal):
            raise ValueError("nested execution changed the enclosing resource contract")
    else:
        assert owner is not None
        admission = owner[0]
    request = Reservation(math.ceil(float(cpu)),
                          int(memory[:-1]) * (1024 if memory[-1] == "g" else 1)
                          + admission.budget.staging_memory_mb)
    if active is not None:
        with active.execution_lock:
            if active.closed:
                raise RuntimeError("container launch outlived its resource reservation")
            if any(value > getattr(active.request, name) for name, value in asdict(request).items()):
                raise ValueError("nested container exceeds the enclosing resource reservation")
            yield
        return
    with admission.reserve(request, events=owner[1], action=action, timeout_seconds=timeout_seconds):
        lease = _ACTIVE.get()
        assert lease is not None
        with lease.execution_lock:
            yield


@contextmanager
def reserve_execution(*, cpu: str, memory: str, action: str, timeout_seconds: int):
    with safety.operation(action), _reserve_execution(
            cpu=cpu, memory=memory, action=action, timeout_seconds=timeout_seconds):
        safety.check_running()
        yield


def bounded_execution(*, cpu: str, memory: str, action: str):
    """Reserve preparation and execution together for fixed-limit build executors."""
    def decorate(method):
        @wraps(method)
        def execute(self, *args, **kwargs):
            with reserve_execution(cpu=cpu, memory=memory, action=action,
                                   timeout_seconds=self.timeout_seconds):
                return method(self, *args, **kwargs)
        return execute
    return decorate


@contextmanager
def tracked_container(name: str, runner, *, label: str):
    track_container(name)
    try:
        safety.check_running()
        yield
    finally:
        with safety.cleanup_scope():
            _remove_tracked_container(name, runner, label=label)


def _remove_tracked_container(name: str, runner, *, label: str):
    removed = runner(("docker", "rm", "--force", name), 60)
    active = _ACTIVE.get()
    require_absence = (safety.active()
                       or active is not None and active.admission.require_container_removal)
    confirmed = not removed[3] and removed[0] == 0
    if require_absence or not confirmed:
        inspected = runner(("docker", "container", "inspect", name,
                            "--format", "{{.State.Running}}"), 60)
        if require_absence:
            absent = {f"{prefix}No such {kind}: {name}".encode()
                      for prefix in ("", "Error: ", "Error response from daemon: ")
                      for kind in ("container", "object")}
            confirmed = (not inspected[3] and inspected[0] not in (None, 0)
                         and inspected[2].strip() in absent)
        else:
            confirmed = not inspected[3] and (
                (inspected[0] == 0 and inspected[1].strip() == b"false")
                or (inspected[0] != 0 and b"No such" in inspected[2]))
    if confirmed:
        container_stopped(name)
    else:
        condition = "removal" if require_absence else "death"
        quarantine_resources(f"{label.lower()}_container_{condition}_unconfirmed")
        raise RuntimeError(f"{label} container {condition} is unconfirmed ({name}); resources quarantined")


def track_container(name: str) -> None:
    current = _ACTIVE.get()
    if current is not None:
        current.admission._container(current.lease_id, name, stopped=False)


def container_stopped(name: str) -> None:
    current = _ACTIVE.get()
    if current is not None:
        current.admission._container(current.lease_id, name, stopped=True)


def quarantine_resources(reason: str) -> None:
    current = _ACTIVE.get()
    if current is not None:
        current.admission._quarantine(current.lease_id, reason)


def track_image_build(build: dict, *, max_concurrency: int, timeout_seconds: float) -> str:
    active = _ACTIVE.get()
    if active is None or active.closed:
        raise RuntimeError("image builder requires an active resource reservation")
    deadline = time.monotonic() + timeout_seconds
    while True:
        safety.check_running()
        with bounded_file_lock(active.admission.root / "admission.lock", 30):
            path = active.admission.root / "leases.json"
            state = json.loads(path.read_text())
            builds = [item for lease in state["leases"].values() for item in lease.get("builds", ())]
            limit = min([max_concurrency, *(item["max_concurrency"] for item in builds)])
            if len(builds) < limit:
                state["leases"][active.lease_id].setdefault("builds", []).append(
                    {**build, "max_concurrency": max_concurrency})
                atomic_json(path, state)
                return active.lease_id
        if time.monotonic() >= deadline:
            raise TimeoutError("image builder concurrency admission timed out")
        time.sleep(0.05)


def update_image_build(build_id: str, *, worker: dict | None = None, stopped: bool = False) -> None:
    active = _ACTIVE.get()
    if active is None:
        raise RuntimeError("image builder lost its resource reservation")
    with bounded_file_lock(active.admission.root / "admission.lock", 30):
        path = active.admission.root / "leases.json"
        state = json.loads(path.read_text())
        builds = state["leases"][active.lease_id]["builds"]
        matches = [item for item in builds if item["build_id"] == build_id]
        if len(matches) != 1:
            raise ValueError("image build reservation is missing or ambiguous")
        if stopped:
            builds.remove(matches[0])
        elif worker is not None:
            matches[0]["worker"] = worker
        atomic_json(path, state)


@dataclass(frozen=True, slots=True)
class Reservation:
    cpu: int
    memory_mb: int
    io_slots: int = 1

    def __post_init__(self):
        if (any(type(value) is not int for value in asdict(self).values())
                or self.cpu < 1 or self.memory_mb < 1 or self.io_slots < 0):
            raise ValueError("invalid resource reservation")


class ResourceCapacityInfeasible(RuntimeError):
    """An operator must resolve permanent headroom; queueing cannot make this fit."""

    reason = "persistent_service_capacity_infeasible"
    requirement = "operator_capacity_resolution_required"

    def __init__(self, request: Reservation, permanent: dict, limits: dict):
        self.request = asdict(request)
        self.permanent = dict(permanent)
        self.required_budget = {name: value + permanent[name] for name, value in self.request.items()}
        self.available_budget = dict(limits)
        self.blocking_resources = tuple(name for name, value in self.required_budget.items() if value > limits[name])
        details = "; ".join(
            f"{name}: action {self.request[name]} + permanent {permanent[name]} > budget {limits[name]}"
            for name in self.blocking_resources)
        super().__init__(f"{self.requirement}: {self.reason}; {details}")


class ResourceAdmission:
    def __init__(self, metadata_root: Path, budget: ResourceBudget, *,
                 require_container_removal: bool = False):
        if type(require_container_removal) is not bool:
            raise ValueError("container removal policy must be boolean")
        self.root = metadata_root.resolve() / "resource-admission"
        self.budget = budget
        self.require_container_removal = require_container_removal

    def _check_permanent_feasibility(self, leases: dict, request: Reservation) -> None:
        persistent = [entry for entry in leases.values() if "persistent" in entry]
        limits = {name: min([getattr(self.budget, name), *(entry["limits"][name] for entry in persistent)])
                  for name in asdict(request)}
        used = {name: sum(entry["reservation"][name] for entry in persistent) for name in limits}
        if any(value + used[name] > limits[name] for name, value in asdict(request).items()):
            raise ResourceCapacityInfeasible(request, used, limits)

    def reserve_persistent(self, lease_id: str, request: Reservation, binding: dict) -> None:
        """Acquire/adopt counted capacity, never tied to the creating process's life.

        Operator services use their UID-dropping broker for client-owned ledgers.
        Ordinary reconciliation cannot remove these leases.
        """
        with bounded_file_lock(self.root / "admission.lock", 30):
            path = self.root / "leases.json"
            state = json.loads(path.read_text()) if path.exists() else {
                "schema": "appsec-review/resource-leases/1", "leases": {}}
            if state.get("schema") != "appsec-review/resource-leases/1":
                raise ValueError("unsupported host resource lease schema")
            if lease_id in state["leases"]:
                self._check_persistent(state, lease_id, request, binding)
                return
            self._check_permanent_feasibility(state["leases"], request)
            limits = {name: getattr(self.budget, name) for name in asdict(request)}
            used = {name: sum(entry["reservation"][name] for entry in state["leases"].values())
                    for name in limits}
            effective = {name: min([value, *(entry["limits"][name] for entry in state["leases"].values())])
                         for name, value in limits.items()}
            if any(used[name] + value > effective[name] for name, value in asdict(request).items()):
                raise TimeoutError("persistent service reservation exceeds available aggregate capacity")
            state["leases"][lease_id] = {
                "pid": os.getpid(), "process_identity": process_identity(os.getpid()),
                "containers": [], "builds": [], "reservation": asdict(request),
                "limits": limits, "action": "image.builder.service", "persistent": binding,
            }
            atomic_json(path, state)
            self._sync_persistent_directory()

    def _sync_persistent_directory(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _check_persistent(self, state: dict, lease_id: str, request: Reservation, binding: dict) -> None:
        limits = {name: getattr(self.budget, name) for name in asdict(request)}
        entry = state.get("leases", {}).get(lease_id)
        if (state.get("schema") != "appsec-review/resource-leases/1" or not isinstance(entry, dict)
                or entry.get("persistent") != binding or entry.get("reservation") != asdict(request)
                or entry.get("limits") != limits or entry.get("action") != "image.builder.service"
                or entry.get("containers") != [] or entry.get("builds") != [] or entry.get("quarantine")):
            raise ValueError("persistent service reservation is missing, rebound or changed")
        for name, limit in limits.items():
            effective = min([limit, *(item["limits"][name] for item in state["leases"].values())])
            if sum(item["reservation"][name] for item in state["leases"].values()) > effective:
                raise ValueError("persistent reservation ledger exceeds the aggregate budget")

    def verify_persistent(self, lease_id: str, request: Reservation, binding: dict) -> None:
        with bounded_file_lock(self.root / "admission.lock", 30):
            state = json.loads((self.root / "leases.json").read_text())
            self._check_persistent(state, lease_id, request, binding)

    def _release_persistent(self, lease_id: str, request: Reservation, binding: dict) -> None:
        """Only the operator lifetime adapter calls this after independent shutdown proof."""
        with bounded_file_lock(self.root / "admission.lock", 30):
            path = self.root / "leases.json"
            state = json.loads(path.read_text())
            self._check_persistent(state, lease_id, request, binding)
            del state["leases"][lease_id]
            atomic_json(path, state)
            self._sync_persistent_directory()

    def _container(self, lease_id: str, name: str, *, stopped: bool) -> None:
        with bounded_file_lock(self.root / "admission.lock", 30):
            path = self.root / "leases.json"
            state = json.loads(path.read_text())
            containers = state["leases"][lease_id]["containers"]
            if stopped:
                if name in containers:
                    containers.remove(name)
            elif name not in containers:
                containers.append(name)
            atomic_json(path, state)

    def _quarantine(self, lease_id: str, reason: str) -> None:
        with bounded_file_lock(self.root / "admission.lock", 30):
            path = self.root / "leases.json"
            state = json.loads(path.read_text())
            state["leases"][lease_id]["quarantine"] = reason
            atomic_json(path, state)

    def reconcile(self, confirmed_stopped, *, confirmed_cleanup=lambda entry: False,
                  confirmed_build_stopped=lambda build: False, lease_filter=lambda entry: True,
                  confirmed_removed=lambda name: False) -> list[str]:
        """Reclaim dead owners only after recorded containers and builds are independently stopped."""
        path = self.root / "leases.json"
        if not path.exists():
            return []
        removed = []
        with bounded_file_lock(self.root / "admission.lock", 30):
            state = json.loads(path.read_text())
            for lease_id, entry in list(state["leases"].items()):
                if "persistent" in entry:
                    continue
                if not lease_filter(dict(entry)):
                    continue
                identity = entry.get("process_identity")
                if identity is None:
                    continue
                if process_identity(entry["pid"]) == identity and not entry.get("owner_finished"):
                    continue
                cleanup = entry.get("container_cleanup", "stopped")
                if cleanup not in {"stopped", "removed"}:
                    raise ValueError("unsupported container cleanup policy")
                confirm = confirmed_removed if cleanup == "removed" else confirmed_stopped
                if (entry.get("quarantine") and not confirmed_cleanup(dict(entry))) or not all(
                        confirm(name) for name in entry.get("containers", ())):
                    continue
                if not all(confirmed_build_stopped(dict(build)) for build in entry.get("builds", ())):
                    continue
                removed.append(lease_id)
                del state["leases"][lease_id]
            atomic_json(path, state)
        return removed

    @contextmanager
    def reserve(self, request: Reservation, *, events: EventLog, action: str,
                timeout_seconds: int = 3600, unit_id: str | None = None,
                scope_id: str | None = None, query_profile: str | None = None) -> Iterator[str]:
        limits = {name: getattr(self.budget, name) for name in asdict(request)}
        if any(value > limits[name] for name, value in asdict(request).items()):
            raise ValueError(f"{action} reservation exceeds the configured aggregate resource budget")
        lease_id = uuid4().hex
        start = time.monotonic()
        correlation = {"span_id": lease_id, "operation_id": action, "unit_id": unit_id,
                       "scope_id": scope_id, "query_profile": query_profile}
        events.write("RESOURCE_ELIGIBLE", **correlation, reservation=asdict(request))
        path = self.root / "leases.json"
        while True:
            safety.check_running()
            with bounded_file_lock(self.root / "admission.lock", 30):
                state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
                    "schema": "appsec-review/resource-leases/1", "leases": {}}
                if state.get("schema") != "appsec-review/resource-leases/1":
                    raise ValueError("unsupported host resource lease schema")
                leases = state["leases"]
                try:
                    self._check_permanent_feasibility(leases, request)
                except ResourceCapacityInfeasible as exc:
                    events.write(
                        "RESOURCE_INFEASIBLE", **correlation, reason=exc.reason, requirement=exc.requirement,
                        reservation=exc.request, permanent_reservation=exc.permanent,
                        required_budget=exc.required_budget, available_budget=exc.available_budget,
                        blocking_resources=list(exc.blocking_resources),
                    )
                    raise
                effective = {name: min([limit, *(entry["limits"][name] for entry in leases.values())])
                             for name, limit in limits.items()}
                used = {name: sum(entry["reservation"][name] for entry in leases.values())
                        for name in limits}
                if all(used[name] + value <= effective[name] for name, value in asdict(request).items()):
                    leases[lease_id] = {"pid": os.getpid(), "process_identity": process_identity(os.getpid()),
                                        "containers": [], "reservation": asdict(request),
                                        "limits": limits, "action": action}
                    if self.require_container_removal:
                        leases[lease_id]["container_cleanup"] = "removed"
                    atomic_json(path, state)
                    break
            if time.monotonic() - start >= timeout_seconds:
                events.write("RESOURCE_TIMED_OUT", **correlation,
                             queue_delay_ms=int((time.monotonic() - start) * 1000),
                             reason="admission_timeout_or_unreconciled_lease")
                raise TimeoutError(f"{action} admission timed out; outstanding leases require reconciliation")
            time.sleep(0.05)
        active = ActiveLease(self, lease_id, request)
        token = _ACTIVE.set(active)
        try:
            events.write("RESOURCE_ADMITTED", **correlation,
                         queue_delay_ms=int((time.monotonic() - start) * 1000),
                         reservation=asdict(request))
            safety.check_running()
            yield lease_id
        finally:
            with active.execution_lock:
                active.closed = True
            _ACTIVE.reset(token)
            with bounded_file_lock(self.root / "admission.lock", 30):
                state = json.loads(path.read_text(encoding="utf-8"))
                if lease_id not in state["leases"]:
                    raise ValueError("active resource lease disappeared")
                lease = state["leases"][lease_id]
                retained = bool(lease.get("containers") or lease.get("builds") or lease.get("quarantine"))
                if retained:
                    reason = ("image_builder_cleanup_unconfirmed"
                              if lease.get("builds") and not lease.get("containers")
                              else "container_death_unconfirmed")
                    lease["quarantine"] = lease.get("quarantine", reason)
                    lease["owner_finished"] = True
                else:
                    del state["leases"][lease_id]
                atomic_json(path, state)
            events.write("RESOURCE_QUARANTINED" if retained else "RESOURCE_RELEASED",
                         **correlation)
