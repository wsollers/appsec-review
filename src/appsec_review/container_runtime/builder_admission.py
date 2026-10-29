"""Operator-owned builder lifetime admission and abandoned-build reconciliation.

Before commissioning daemon/proxy/service, run the service entrypoint with
``--reserve-lifetime``. Startup verifies this real, counted lease. Shutdown never
releases it: ``--release-lifetime`` requires unchanged, empty host/worker cgroups,
dead recorded members, an absent daemon listener, an inactive service and a clean
journal. ``--reconcile-admission`` supplies trusted callbacks to ResourceAdmission.

The permanent charge is 1 CPU/512 MiB (or smaller configured host limits), zero
active-build I/O slots. Existing client charges are deliberately unchanged:
one default active build plus the lifetime lease reserves 3 CPU/5632 MiB/1 I/O
inside the existing 8 CPU/10240 MiB/1 I/O budget. This is conservative duplicate
host accounting, not additional execution capacity.
Those are defaults, not a second hard-coded budget: every ledger operation uses
config.resources, pinned as part of the complete lifetime service contract.

An unchanged 8-CPU compiled action cannot fit beside the permanent 1-CPU host
charge. ResourceAdmission raises ResourceCapacityInfeasible immediately with
operator_capacity_resolution_required, rather than waiting for permanent costs
to disappear. A compiled peak of 9728 MiB plus the default 512 MiB exactly fills
the memory budget; any separately charged overhead must also fit. Synthetic
serial admission is not evidence of compiled-review readiness or coverage.

Root never opens the client ledger. A bounded, permanently privilege-dropped
child performs ledger operations as its owner; no chown or group-write access is
used. Operator journal snapshots are read before the drop, never from client
attestations. No generated-source or platform payload fingerprints are computed.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import sqlite3
import stat
import time

from appsec_review.config.image_builder_service import ImageBuilderServiceConfig
from appsec_review.container_runtime.buildkit_worker import (
    EnforcementUnavailable, KernelProof, bounded_json, private_path, process_token,
)
from appsec_review.runtime.resources import Reservation, ResourceAdmission, ResourceCapacityInfeasible
from appsec_review.storage import atomic_json, bounded_file_lock


LIFETIME_SCHEMA = "appsec-review/builder-lifetime/1"
BINDING_FIELDS = {
    "build_id", "tenant_id", "project_id", "run_id", "target_snapshot", "release_id",
    "namespace", "recipe_identity", "context", "output_tag",
}
MAX_BROKER_BYTES = 1024 * 1024


def service_contract(config: ImageBuilderServiceConfig) -> dict:
    value = asdict(config)
    if config.native_engine is None:
        value.pop("native_engine")
    return json.loads(json.dumps(value))


def open_operator_journal(root: Path) -> sqlite3.Connection:
    """Caller holds service.lock; both pre-reservation and serving use this schema."""
    private_path(root)
    database = root / "intents.sqlite3"
    if database.exists() or database.is_symlink():
        private_path(database, directory=False)
        if not stat.S_ISREG(database.lstat().st_mode):
            raise EnforcementUnavailable("operator journal is not a regular file")
    connection = sqlite3.connect(database)
    try:
        database.chmod(0o600)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=EXTRA")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS builds (id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS requests (
                uid INTEGER NOT NULL, nonce TEXT NOT NULL, build_id TEXT NOT NULL,
                request TEXT NOT NULL, PRIMARY KEY(uid, nonce));
            CREATE INDEX IF NOT EXISTS request_build ON requests(build_id);
            CREATE TABLE IF NOT EXISTS engine_interlock (slot INTEGER PRIMARY KEY CHECK(slot=1), owner TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS engine_executions (id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS engine_requests (
                nonce TEXT PRIMARY KEY, owner TEXT NOT NULL, request TEXT NOT NULL, response TEXT);
        """)
        connection.commit()
        return connection
    except BaseException:
        connection.close()
        raise


@contextmanager
def operator_lock(root: Path, name: str):
    private_path(root)
    descriptor = os.open(root / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _as_client(config: ImageBuilderServiceConfig, operation):
    """Drop permanently in a child BEFORE resolving any client-supplied path."""
    identity = config.admission
    if os.geteuid() == identity.uid:
        if os.getegid() != identity.gid:
            raise EnforcementUnavailable("admission broker GID differs from the ledger owner contract")
        return operation()
    if os.geteuid() != 0:
        raise EnforcementUnavailable("admission broker is neither operator nor ledger owner")
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        try:
            os.closerange(3, write_fd)
            os.closerange(write_fd + 1, 1048576)
            os.setgroups([])
            os.setgid(identity.gid)
            os.setuid(identity.uid)
            if os.geteuid() != identity.uid or os.getegid() != identity.gid:
                raise PermissionError("permanent privilege drop failed")
            reply = {"ok": True, "value": operation()}
        except BaseException as exc:
            reply = {"ok": False, "error_type": type(exc).__name__[:64]}
            if isinstance(exc, ResourceCapacityInfeasible):
                reply["capacity"] = {
                    "request": exc.request, "permanent": exc.permanent, "limits": exc.available_budget,
                }
        try:
            data = json.dumps(reply).encode()
            if len(data) > MAX_BROKER_BYTES:
                data = b'{"ok":false,"error_type":"OversizedAdmissionResponse"}'
            while data:
                data = data[os.write(write_fd, data):]
        finally:
            os._exit(0)
    os.close(write_fd)
    selector = selectors.DefaultSelector()
    os.set_blocking(read_fd, False)
    selector.register(read_fd, selectors.EVENT_READ)
    deadline, output, reaped = time.monotonic() + 60, bytearray(), False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("admission broker deadline exceeded")
            if not selector.select(remaining):
                continue
            data = os.read(read_fd, min(65536, MAX_BROKER_BYTES + 1 - len(output)))
            if not data:
                break
            output.extend(data)
            if len(output) > MAX_BROKER_BYTES:
                raise ValueError("admission broker response exceeded its bound")
        _, status = os.waitpid(pid, 0)
        reaped = True
        reply = json.loads(output)
        if status != 0 or reply.get("ok") is not True:
            if status == 0 and reply.get("error_type") == "ResourceCapacityInfeasible":
                capacity = reply["capacity"]
                raise ResourceCapacityInfeasible(
                    Reservation(**capacity["request"]), capacity["permanent"], capacity["limits"])
            raise EnforcementUnavailable("client admission operation was not confirmed")
        return reply["value"]
    finally:
        selector.close()
        os.close(read_fd)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


def _ledger(config: ImageBuilderServiceConfig, *, create=False, expected_identity=None) -> ResourceAdmission:
    identity = config.admission
    if os.geteuid() != identity.uid:
        raise PermissionError("client ledger operations require its actual owner UID")
    metadata = Path(identity.metadata_root)
    if create:
        metadata.mkdir(parents=True, mode=0o700, exist_ok=True)
    private_path(metadata, uid=identity.uid)
    root = metadata / "resource-admission"
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    private_path(root, uid=identity.uid)
    info = root.lstat()
    if info.st_uid != identity.uid:
        raise PermissionError("client admission directory is not owner-private")
    if create:
        root.chmod(0o700)
    elif info.st_mode & 0o077:
        raise PermissionError("client admission directory is not owner-private")
    if expected_identity is not None and [info.st_dev, info.st_ino] != expected_identity:
        raise EnforcementUnavailable("client admission directory was rebound")
    for name in ("admission.lock", "leases.json"):
        path = root / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            if create:
                continue
            raise
        mask = 0o022 if name == "admission.lock" else 0o077
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != identity.uid or info.st_mode & mask):
            raise PermissionError("client admission file is not an owner-private regular file")
    return ResourceAdmission(metadata, config.resources)


class LifetimeProof:
    def __init__(self, config: ImageBuilderServiceConfig):
        self.config = config

    def groups(self) -> dict:
        kernel = KernelProof(self.config)
        output = {}
        groups = [
            ("host", self.config.host_cgroup, self.config.host_cpu, self.config.host_overhead_mb),
            ("workers", self.config.worker_cgroup_parent, self.config.cpu, self.config.memory_mb),
        ]
        if self.config.native_engine is not None:
            native = self.config.native_engine
            groups.append(("executions", native.execution_cgroup_parent, native.cpu, native.memory_mb))
        for name, path, cpu, memory in groups:
            root = Path(path)
            if name in {"host", "workers"}:
                kernel.builder_limits(root, cpu, memory * 1024 * 1024)
            else:
                kernel.limits(root, cpu, memory * 1024 * 1024)
            info = root.stat()
            output[name] = {"path": path, "device": info.st_dev, "inode": info.st_ino}
        return output

    def members(self) -> list[dict]:
        output = {}
        for root in self._roots():
            for directory, _, _ in os.walk(root, followlinks=False):
                path = Path(directory)
                if path.is_symlink():
                    raise EnforcementUnavailable("cgroup subtree contains a symlink")
                for value in (path / "cgroup.procs").read_text().split():
                    pid = int(value)
                    token = process_token(pid)
                    if token is not None:
                        output[(pid, token)] = {"pid": pid, "start_token": token}
                    if len(output) > 4096:
                        raise EnforcementUnavailable("lifetime member inventory exceeds its bound")
        return list(output.values())

    def empty(self) -> bool:
        for root in self._roots():
            values = dict(line.split() for line in (root / "cgroup.events").read_text().splitlines())
            if values.get("populated") != "0":
                return False
        return True

    def _roots(self):
        roots = [Path(self.config.host_cgroup), Path(self.config.worker_cgroup_parent)]
        if self.config.native_engine is not None:
            roots.append(Path(self.config.native_engine.execution_cgroup_parent))
        return roots

    def stopped(self, members: list[dict]) -> bool:
        if not self.empty() or any(process_token(member["pid"]) == member["start_token"] for member in members):
            return False
        endpoint = Path(self.config.docker_endpoint)
        try:
            info = endpoint.lstat()
        except FileNotFoundError:
            private_path(endpoint.parent)
            return True
        private_path(endpoint, directory=False)
        if not stat.S_ISSOCK(info.st_mode):
            return False
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(1)
            try:
                channel.connect(str(endpoint))
            except ConnectionRefusedError:
                return True
        return False


def _journal_records(config: ImageBuilderServiceConfig) -> list[dict]:
    root = Path(config.state_root)
    private_path(root)
    database = root / "intents.sqlite3"
    private_path(database, directory=False)
    if not stat.S_ISREG(database.lstat().st_mode):
        raise EnforcementUnavailable("operator journal is not a regular file")
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("BEGIN")
        if connection.execute("SELECT COUNT(*) FROM builds").fetchone()[0] > config.max_records:
            raise EnforcementUnavailable("operator journal exceeds its configured bound")
        output = []
        for (value,) in connection.execute("SELECT record FROM builds"):
            if len(value) > MAX_BROKER_BYTES:
                raise EnforcementUnavailable("operator build record exceeds its bound")
            output.append(json.loads(value))
        return output
    finally:
        connection.close()


def _context_absent(config: ImageBuilderServiceConfig, record: dict) -> bool:
    if os.geteuid() != config.admission.uid:
        return False
    grant = record["grant"]
    root = Path(grant["client_context_root"])
    descriptor = None
    try:
        private_path(root, uid=config.admission.uid)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in (grant["namespace"], record["binding"]["build_id"]):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except FileNotFoundError:
                return True
            os.close(descriptor)
            descriptor = child
        for name in ("context", "cleanup-" + record["worker"]["start_token"]):
            try:
                os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


class JournalCleanupConfirmation:
    """Trusted snapshot; construct as operator, invoke callbacks as ledger owner.

    ``BuilderAdmission.reconcile()`` performs that ordering and UID transition.
    These two callbacks also plug directly into ResourceAdmission.reconcile when
    an operator has already taken the snapshot and permanently dropped privileges.
    """

    def __init__(self, config: ImageBuilderServiceConfig):
        self.config, self.contract = config, service_contract(config)
        self._records = {}
        for record in _journal_records(config):
            binding, worker = record.get("binding", {}), record.get("worker")
            cleanup = record.get("cleanup")
            expected = {"state": "CLEANED", "work_stopped": True, "context_released": True,
                        "binding": binding, "worker": worker, "service_contract": self.contract}
            if (record.get("state") != "CLEANED" or record.get("service_contract") != self.contract
                    or not config.resources.matches(record.get("resource_budget"))
                    or cleanup != expected or set(binding) != BINDING_FIELDS
                    or not isinstance(binding.get("build_id"), str)
                    or not re.fullmatch(r"[0-9a-f]{32}", binding["build_id"])
                    or not isinstance(worker, dict) or set(worker) != {"id", "start_token"}
                    or not isinstance(worker.get("start_token"), str)
                    or not re.fullmatch(r"[0-9a-f]{32}", worker["start_token"])
                    or record.get("grant") not in [asdict(grant) for grant in config.grants]):
                continue
            directory = Path(config.state_root) / binding["build_id"]
            if record.get("directory") != str(directory):
                continue
            try:
                directory.lstat()
            except FileNotFoundError:
                self._records[binding["build_id"]] = record

    def confirmed_build_stopped(self, build: dict) -> bool:
        if not isinstance(build, dict) or set(build) != BINDING_FIELDS | {
                "endpoint", "worker", "max_concurrency", "resource_budget"}:
            return False
        record = self._records.get(build.get("build_id"))
        if (record is None or build.get("endpoint") != self.config.endpoint
                or not self.config.resources.matches(build.get("resource_budget"))
                or type(build.get("max_concurrency")) is not int
                or build["max_concurrency"] != self.config.max_concurrency
                or build.get("worker") != record["worker"]
                or {key: build[key] for key in BINDING_FIELDS} != record["binding"]):
            return False
        return _context_absent(self.config, record)

    def confirmed_cleanup(self, entry: dict) -> bool:
        return (entry.get("quarantine") in {None, "image_builder_cleanup_unconfirmed"}
                and not entry.get("containers") and bool(entry.get("builds"))
                and all(self.confirmed_build_stopped(build) for build in entry["builds"]))


class BuilderAdmission:
    def __init__(self, config: ImageBuilderServiceConfig, *, proof=None):
        self.config = config
        self.proof = proof or LifetimeProof(config)
        self.root = Path(config.state_root)
        self.path = self.root / "lifetime.json"
        self.contract = service_contract(config)
        self.binding = {"kind": LIFETIME_SCHEMA, "service_contract": self.contract}
        self.request = Reservation(config.host_cpu, config.host_overhead_mb, io_slots=0)

    def _write_anchor(self, anchor: dict):
        atomic_json(self.path, anchor)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _anchor(self) -> dict:
        private_path(self.path, directory=False)
        anchor = bounded_json(self.path)
        if (anchor.get("schema") != LIFETIME_SCHEMA or anchor.get("service_contract") != self.contract
                or anchor.get("groups") != self.proof.groups()):
            raise EnforcementUnavailable("operator lifetime reservation configuration or cgroups changed")
        return anchor

    def reserve(self) -> str:
        """Run before starting the daemon, proxy or service; adopt only exact leases."""
        with operator_lock(self.root, "lifetime.lock"):
            if self.path.exists() or self.path.is_symlink():
                anchor = self._anchor()
                if anchor.get("state") != "RESERVED":
                    raise EnforcementUnavailable("retired lifetime IDs cannot be silently reused")
                self._verify_ledger(anchor)
                return self.config.admission.lease_id
            groups = self.proof.groups()
            if not self.proof.stopped([]):
                raise EnforcementUnavailable("pre-reservation requires stopped daemon/service/worker scopes")
            with operator_lock(self.root, "service.lock"):
                journal = open_operator_journal(self.root)
                try:
                    if journal.execute("SELECT COUNT(*) FROM builds").fetchone()[0]:
                        raise EnforcementUnavailable("an unanchored existing build journal cannot be adopted")
                finally:
                    journal.close()

            def acquire():
                admission = _ledger(self.config, create=True)
                admission.reserve_persistent(self.config.admission.lease_id, self.request, self.binding)
                info = admission.root.stat()
                return [info.st_dev, info.st_ino]

            ledger_identity = _as_client(self.config, acquire)
            self._write_anchor({
                "schema": LIFETIME_SCHEMA, "state": "RESERVED", "service_contract": self.contract,
                "groups": groups, "ledger_identity": ledger_identity, "members": [],
            })
            return self.config.admission.lease_id

    def _verify_ledger(self, anchor: dict):
        def verify():
            admission = _ledger(self.config, expected_identity=anchor["ledger_identity"])
            admission.verify_persistent(self.config.admission.lease_id, self.request, self.binding)
        _as_client(self.config, verify)

    def verify(self) -> None:
        """Startup/admission gate: verify actual counted capacity and retain members."""
        with operator_lock(self.root, "lifetime.lock"):
            anchor = self._anchor()
            if anchor.get("state") != "RESERVED":
                raise EnforcementUnavailable("builder lifetime capacity has not been reserved")
            self._verify_ledger(anchor)
            members = {(item["pid"], item["start_token"]): item for item in anchor["members"]}
            for member in self.proof.members():
                members[(member["pid"], member["start_token"])] = member
            if len(members) > 4096:
                raise EnforcementUnavailable("lifetime member history requires a stopped operator rotation")
            anchor["members"] = list(members.values())
            self._write_anchor(anchor)

    def verify_build(self, binding: dict, peer: dict, worker: dict | None, *, preparing=False) -> None:
        """Borrow only the caller's real, tracked worker reservation, never a declaration.

        track_image_build keeps this capacity quarantined after owner death until
        our independent cleanup receipt is accepted. Host capacity is additionally
        reserved for the whole service lifetime; no new per-build lease is needed.
        """
        with operator_lock(self.root, "lifetime.lock"):
            anchor = self._anchor()
            if anchor.get("state") != "RESERVED":
                raise EnforcementUnavailable("builder lifetime is not active")

            def verify():
                admission = _ledger(self.config, expected_identity=anchor["ledger_identity"])
                with bounded_file_lock(admission.root / "admission.lock", 30):
                    state = json.loads((admission.root / "leases.json").read_text())
                    admission._check_persistent(
                        state, self.config.admission.lease_id, self.request, self.binding)
                    matches = []
                    cpu, memory_mb = self.config.client_policy.build_reservation(self.config.resources)
                    required = {
                        "cpu": cpu,
                        "memory_mb": memory_mb + self.config.resources.staging_memory_mb,
                        "io_slots": 1,
                    }
                    for entry in state["leases"].values():
                        if ("persistent" in entry or entry.get("pid") != peer["pid"]
                                or entry.get("process_identity") != peer["start_token"]
                                or entry.get("owner_finished") or entry.get("quarantine")):
                            continue
                        if entry.get("limits") != {
                                name: getattr(self.config.resources, name) for name in required}:
                            continue
                        reservation = entry.get("reservation", {})
                        if any(type(reservation.get(name)) is not int or reservation[name] < value
                               for name, value in required.items()):
                            continue
                        for build in entry.get("builds", []):
                            if (any(build.get(name) != value for name, value in binding.items())
                                    or not self.config.resources.matches(build.get("resource_budget"))
                                    or build.get("endpoint") != self.config.endpoint
                                    or build.get("max_concurrency") != self.config.max_concurrency):
                                continue
                            observed = build.get("worker")
                            if observed != worker and not (preparing and observed is None):
                                continue
                            matches.append(entry)
                    if len(matches) != 1:
                        raise EnforcementUnavailable("worker lacks one matching live tracked client reservation")
            _as_client(self.config, verify)

    def reconcile(self) -> list[str]:
        """Reconcile only independently cleaned builder leases; leave every other kind alone."""
        with operator_lock(self.root, "lifetime.lock"):
            anchor = self._anchor()
            if anchor.get("state") not in {"RESERVED", "RELEASED"}:
                raise EnforcementUnavailable("lifetime transition is unresolved")
            if anchor["state"] == "RESERVED":
                self._verify_ledger(anchor)
            elif not self.proof.stopped(anchor["members"]):
                raise EnforcementUnavailable("retired lifetime scopes are no longer confirmed stopped")
            confirmation = JournalCleanupConfirmation(self.config)
            native_confirmation = None
            if self.config.native_engine is not None:
                from appsec_review.container_runtime.engine_broker import EngineCleanupConfirmation
                native_confirmation = EngineCleanupConfirmation(self.config)

            def reconcile():
                admission = _ledger(self.config, expected_identity=anchor["ledger_identity"])
                removed = admission.reconcile(
                    lambda name: False, confirmed_cleanup=confirmation.confirmed_cleanup,
                    confirmed_build_stopped=confirmation.confirmed_build_stopped,
                    lease_filter=lambda entry: bool(entry.get("builds")),
                )
                if native_confirmation is not None:
                    removed.extend(admission.reconcile(
                        lambda name: False, confirmed_removed=native_confirmation.confirmed_removed,
                        confirmed_cleanup=native_confirmation.confirmed_cleanup,
                        lease_filter=native_confirmation.lease_matches))
                return removed
            return _as_client(self.config, reconcile)

    def verify_native_execution(self, binding: dict, peer: dict, *, name=None, cpu=1, memory_mb=1,
                                allow_quarantine=False) -> None:
        """Only a real removed-only lease with an independently stored native run scope authorizes work."""
        with operator_lock(self.root, "lifetime.lock"):
            anchor = self._anchor()
            if anchor.get("state") != "RESERVED":
                raise EnforcementUnavailable("native engine lifetime is not active")
            def verify():
                admission = _ledger(self.config, expected_identity=anchor["ledger_identity"])
                with bounded_file_lock(admission.root / "admission.lock", 30):
                    state = json.loads((admission.root / "leases.json").read_text())
                    admission._check_persistent(state, self.config.admission.lease_id, self.request, self.binding)
                    entry = state["leases"].get(binding["lease_id"], {})
                    expected = {**binding, "resource_budget": self.config.resources.view()}
                    if (entry.get("pid") != peer["pid"] or entry.get("process_identity") != peer["start_token"]
                            or entry.get("owner_finished") or "persistent" in entry
                            or entry.get("native_engine_scope") != expected
                            or not self.config.resources.matches(
                                entry.get("native_engine_scope", {}).get("resource_budget"))
                            or (entry.get("quarantine") and not allow_quarantine) or entry.get("builds")
                            or entry.get("container_cleanup") != "removed"
                            or entry.get("limits") != {key: getattr(self.config.resources, key)
                                                       for key in ("cpu", "memory_mb", "io_slots")}
                            or (name is not None and name not in entry.get("containers", []))
                            or entry.get("reservation", {}).get("cpu", 0) < cpu
                            or entry.get("reservation", {}).get("memory_mb", 0)
                               < memory_mb + self.config.resources.staging_memory_mb
                            or entry.get("reservation", {}).get("io_slots", 0) < 1):
                        raise EnforcementUnavailable("native request lacks its exact active removed-only admission scope")
            _as_client(self.config, verify)

    def release(self) -> None:
        """Explicit operator shutdown, never a service/client finally block."""
        with operator_lock(self.root, "service.lock"), operator_lock(self.root, "lifetime.lock"):
            anchor = self._anchor()
            if anchor.get("state") == "RELEASED":
                return
            if anchor.get("state") not in {"RESERVED", "RELEASING"}:
                raise EnforcementUnavailable("lifetime reservation state is unknown")
            records = _journal_records(self.config)
            if self.config.native_engine is not None:
                from appsec_review.container_runtime.engine_broker import assert_engine_retired
                assert_engine_retired(self.config)
            confirmation = JournalCleanupConfirmation(self.config)
            if len(confirmation._records) != len(records):
                raise EnforcementUnavailable("unresolved worker intents retain lifetime capacity")
            if not _as_client(self.config, lambda: all(
                    _context_absent(self.config, record) for record in confirmation._records.values())):
                raise EnforcementUnavailable("released client contexts are missing proof or rebound")
            if not self.proof.stopped(anchor["members"]):
                raise EnforcementUnavailable("daemon, proxy, service or worker termination is unconfirmed")
            # A crash after ledger deletion must not permit startup from the old
            # anchor. RELEASING is a durable fail-closed retirement fence.
            anchor["state"] = "RELEASING"
            self._write_anchor(anchor)

            def release():
                admission = _ledger(self.config, expected_identity=anchor["ledger_identity"])
                admission._release_persistent(self.config.admission.lease_id, self.request, self.binding)
            _as_client(self.config, release)
            anchor["state"] = "RELEASED"
            self._write_anchor(anchor)
