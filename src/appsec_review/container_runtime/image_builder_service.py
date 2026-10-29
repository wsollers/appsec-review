"""Durable, authenticated bounded-image-builder/1 operator service.

Run only after commissioning with ``python -m
appsec_review.container_runtime.image_builder_service --config /operator/service.toml``.
The SQLite intent journal and per-build directories must remain operator-owned.
Uncertain work consumes the sole admission slot until independently confirmed
cleanup; restarting this service never turns uncertainty into success.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import select
import shutil
import shlex
import signal
import socket
import sqlite3
import stat
import struct
import time
from uuid import uuid4

from appsec_review.config.image_builder_service import (
    IMAGE_ID, BuilderGrant, ImageBuilderServiceConfig, identifier, load_image_builder_service,
)
from appsec_review.config.assurance import ResourceBudget, validate_concurrency_only_enforcement
from appsec_review.container_runtime.buildkit_worker import (
    BuildKitWorker, EnforcementUnavailable, OutcomeUnknown, private_path, process_token,
)
from appsec_review.container_runtime.builder_admission import BuilderAdmission, open_operator_journal, service_contract


SCHEMA = "appsec-review/bounded-image-builder/1"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
MAX_MESSAGES_PER_BUILD = 65536
BINDING_FIELDS = {
    "build_id", "tenant_id", "project_id", "run_id", "target_snapshot",
    "release_id", "namespace", "recipe_identity", "context", "output_tag",
}
ACTIONS = {"prepare", "start", "status", "cancel", "cleanup"}
LOGGER = logging.getLogger(__name__)


def _log_request_failure(error: BaseException) -> None:
    exception_type = re.sub(r"[^A-Za-z0-9_]", "_", type(error).__name__)[:64]
    LOGGER.warning("BOUNDED_IMAGE_BUILDER_REQUEST_REJECTED exception_type=%s", exception_type)


def encoded(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def decode_message(data: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError("builder message exceeds protocol bound")
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if (not isinstance(value, dict) or set(value) != {"schema", "request_id", "action", "body"}
            or value["schema"] != SCHEMA or not isinstance(value["action"], str) or value["action"] not in ACTIONS
            or not isinstance(value["request_id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["request_id"])
            or not isinstance(value["body"], dict)):
        raise ValueError("invalid builder envelope")
    return value


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int
    start_token: str


def authenticated_peer(channel: socket.socket) -> Peer:
    pid, uid, gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    token = process_token(pid)
    if token is None:
        raise PermissionError("client lifetime is unresolvable")
    for name in ("mnt", "pid", "user"):
        if os.readlink(f"/proc/{pid}/ns/{name}") != os.readlink(f"/proc/self/ns/{name}"):
            raise PermissionError("client path/identity namespace is not locally mapped")
    return Peer(pid, uid, gid, token)


class IntentStore:
    def __init__(self, root: Path):
        private_path(root)
        self.lock = os.fdopen(os.open(root / "service.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "r+b")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            self.connection = open_operator_journal(root)
        except BaseException:
            self.lock.close()
            raise

    def close(self):
        self.connection.close()
        self.lock.close()

    def records(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.connection.execute("SELECT record FROM builds")]

    def get(self, build_id: str) -> dict | None:
        row = self.connection.execute("SELECT record FROM builds WHERE id=?", (build_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, record: dict):
        with self.connection:
            self.connection.execute(
                "INSERT INTO builds VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET record=excluded.record",
                (record["binding"]["build_id"], encoded(record).decode()),
            )

    def nonce(self, peer: Peer, request: dict):
        value = encoded(request).decode()
        previous = self.connection.execute(
            "SELECT request FROM requests WHERE uid=? AND nonce=?", (peer.uid, request["request_id"])
        ).fetchone()
        if previous:
            if previous[0] != value:
                raise ValueError("request nonce was reused with different contents")
            return
        build_id = request["body"]["binding"]["build_id"]
        count = self.connection.execute(
            "SELECT COUNT(*) FROM requests WHERE build_id=?", (build_id,)).fetchone()[0]
        if count >= MAX_MESSAGES_PER_BUILD and request["action"] not in {"cancel", "cleanup"}:
            raise ValueError("build request budget exhausted")
        # Cleanup remains available at the bound. State/binding idempotency still
        # applies if a hostile client exhausts the status nonce ledger.
        if count < MAX_MESSAGES_PER_BUILD:
            with self.connection:
                self.connection.execute("INSERT INTO requests VALUES (?, ?, ?, ?)",
                                        (peer.uid, request["request_id"], build_id, value))


def _context_parent_fd(grant: BuilderGrant, binding: dict) -> int:
    root = Path(grant.service_context_root)
    private_path(root, uid=grant.uid)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in (grant.namespace, binding["build_id"]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != grant.uid or info.st_mode & (0o022 if part == grant.namespace else 0o077):
                raise PermissionError("context directory is not private to the authorized UID")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _context_fd(grant: BuilderGrant, binding: dict) -> int:
    parent = _context_parent_fd(grant, binding)
    try:
        descriptor = os.open("context", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(descriptor)
    if info.st_uid != grant.uid or info.st_mode & 0o077:
        os.close(descriptor)
        raise PermissionError("context directory is not private to the authorized UID")
    return descriptor


def _released_context(grant: BuilderGrant, binding: dict, worker: dict) -> bool:
    descriptor = None
    try:
        descriptor = _context_parent_fd(grant, binding)
        for name in ("context", "cleanup-" + worker["start_token"]):
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


def validate_dockerfile(text: str, aliases: set[str], arguments: dict[str, str]) -> None:
    """Accept the generated-recipe subset without implicit image/frontend pulls.

    Deliberately not a general Dockerfile parser. Ambiguous syntax, remote ADD,
    RUN mounts and ONBUILD must fail closed rather than widen this subset.
    """
    variables, stages, stage_count = dict(arguments), set(), 0
    pending = ""
    allowed = {"FROM", "ARG", "COPY", "RUN", "USER", "WORKDIR", "ENV", "LABEL",
               "SHELL", "CMD", "ENTRYPOINT", "EXPOSE", "VOLUME", "STOPSIGNAL"}

    def source(value: str):
        value = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                       lambda match: variables.get(match[1] or match[2], ""), value)
        if not value or "$" in value:
            raise ValueError("unresolved Dockerfile image source")
        return value

    for raw in text.splitlines():
        if raw.lstrip().startswith("#"):
            if re.match(r"\s*#\s*(syntax|escape)\s*=", raw, re.IGNORECASE):
                raise ValueError("external/alternate Dockerfile frontends are forbidden")
            continue
        if raw.rstrip().endswith("\\"):
            pending += raw.rstrip()[:-1] + " "
            continue
        line, pending = (pending + raw).strip(), ""
        if not line:
            continue
        pieces = line.split(None, 1)
        if len(pieces) != 2 or pieces[0].upper() not in allowed or "<<" in line:
            raise ValueError("Dockerfile is outside the bounded generated-recipe subset")
        instruction, operand = pieces[0].upper(), pieces[1]
        if instruction == "ARG":
            name, separator, default = operand.partition("=")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError("invalid Dockerfile ARG")
            if name not in arguments and separator:
                variables[name] = default
        elif instruction == "FROM":
            tokens = shlex.split(operand)
            if len(tokens) not in {1, 3} or (len(tokens) == 3 and tokens[1].lower() != "as"):
                raise ValueError("unsupported FROM syntax")
            image = source(tokens[0])
            if image != "scratch" and image not in aliases and image.lower() not in stages:
                raise PermissionError("implicit FROM pull is not operator-authorized")
            if len(tokens) == 3:
                if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]*", tokens[2]):
                    raise ValueError("invalid Dockerfile stage")
                stages.add(tokens[2].lower())
            stage_count += 1
        elif instruction == "COPY":
            if not stage_count:
                raise ValueError("COPY requires a build stage")
            # Only leading flags have semantics; quoted JSON source names do not.
            while operand.startswith("--"):
                flag, separator, operand = operand.partition(" ")
                if not separator:
                    raise ValueError("missing COPY operands")
                name, equals, value = flag.partition("=")
                if name not in {"--from", "--chown", "--chmod", "--link"}:
                    raise ValueError("unsupported COPY option")
                if name != "--link" and not equals:
                    raise ValueError("COPY options require unambiguous equals syntax")
                if name == "--from":
                    image = source(value)
                    previous_stage = image.isdecimal() and int(image) < stage_count - 1
                    if image not in aliases and image.lower() not in stages and not previous_stage:
                        raise PermissionError("implicit COPY image pull is not operator-authorized")
                operand = operand.lstrip()
        elif instruction == "RUN" and operand.startswith("--"):
            raise ValueError("RUN flags can introduce unbound mounts or network overrides")
        elif instruction not in {"ARG", "FROM"} and not stage_count:
            raise ValueError("instruction precedes the first stage")
    if pending or stage_count == 0:
        raise ValueError("incomplete Dockerfile")


def context_identity(grant: BuilderGrant, binding: dict, *, empty: bool = False) -> list[int]:
    descriptor = _context_fd(grant, binding)
    try:
        if empty:
            with os.scandir(descriptor) as entries:
                if next(entries, None) is not None:
                    raise ValueError("prepare requires an empty client staging context")
        info = os.fstat(descriptor)
        return [info.st_dev, info.st_ino]
    finally:
        os.close(descriptor)


def snapshot_context(record: dict, config: ImageBuilderServiceConfig):
    """Copy bounded regular files through directory FDs; never hash payload bytes."""
    grant = BuilderGrant(**record["grant"])
    source = _context_fd(grant, record["binding"])
    remaining = [config.max_context_files, config.max_context_bytes]
    destination = Path(record["directory"]) / "context"
    deadline = time.monotonic() + config.cleanup_timeout_seconds

    def copy_tree(descriptor: int, target: Path, depth: int):
        if depth > 64:
            raise ValueError("context nesting exceeds its bound")
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if time.monotonic() >= deadline:
                    raise TimeoutError("context snapshot deadline exceeded")
                remaining[0] -= 1
                if remaining[0] < 0:
                    raise ValueError("context file count exceeds its bound")
                info = entry.stat(follow_symlinks=False)
                if (info.st_uid != grant.uid or info.st_mode & 0o022
                        or info.st_dev != record["context_identity"][0]):
                    raise ValueError("context custody or mount identity changed")
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=descriptor)
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino, opened.st_uid) != (
                                info.st_dev, info.st_ino, grant.uid):
                            raise ValueError("context directory was replaced during staging")
                        target.joinpath(entry.name).mkdir(mode=0o755)
                        target.joinpath(entry.name).chmod(0o755)
                        copy_tree(child, target / entry.name, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    child = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                    dir_fd=descriptor)
                    try:
                        before = os.fstat(child)
                        if (before.st_uid != grant.uid or before.st_nlink != 1
                                or (before.st_ino, before.st_dev, before.st_mode) != (
                                    info.st_ino, info.st_dev, info.st_mode)):
                            raise ValueError("context file was replaced during staging")
                        with (target / entry.name).open("xb") as sink:
                            while True:
                                if time.monotonic() >= deadline:
                                    raise TimeoutError("context snapshot deadline exceeded")
                                chunk = os.read(child, min(65536, remaining[1] + 1))
                                if not chunk:
                                    break
                                remaining[1] -= len(chunk)
                                if remaining[1] < 0:
                                    raise ValueError("context byte count exceeds its bound")
                                sink.write(chunk)
                        after = os.fstat(child)
                        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                            raise ValueError("context file changed during staging")
                        (target / entry.name).chmod(0o755 if before.st_mode & 0o111 else 0o644)
                    finally:
                        os.close(child)
                else:
                    raise ValueError("context links, devices and special files are forbidden")

    try:
        info = os.fstat(source)
        if [info.st_dev, info.st_ino] != record["context_identity"]:
            raise ValueError("client context was replaced")
        copy_tree(source, destination, 0)
    finally:
        os.close(source)
    dockerfile = destination / "Dockerfile"
    if not dockerfile.is_file() or dockerfile.stat().st_size > MAX_MESSAGE_BYTES:
        raise ValueError("missing or oversized Dockerfile")
    validate_dockerfile(dockerfile.read_text(), set(record["start"]["authorized_inputs"]),
                        record["start"]["build_args"])


def release_context(record: dict) -> None:
    grant = BuilderGrant(**record["grant"])
    try:
        parent = _context_parent_fd(grant, record["binding"])
    except FileNotFoundError:
        private_path(Path(grant.service_context_root), uid=grant.uid)
        return
    tombstone = "cleanup-" + record["worker"]["start_token"]
    try:
        try:
            info = os.stat("context", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is not None:
            if [info.st_dev, info.st_ino] != record["context_identity"] or not stat.S_ISDIR(info.st_mode):
                raise OutcomeUnknown("client replaced context; cleanup is not confirmed")
            try:
                os.stat(tombstone, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                os.rename("context", tombstone, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                raise OutcomeUnknown("context cleanup destination already exists")
        try:
            info = os.stat(tombstone, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if [info.st_dev, info.st_ino] != record["context_identity"] or not stat.S_ISDIR(info.st_mode):
            raise OutcomeUnknown("context identity changed during release")
        shutil.rmtree(tombstone, dir_fd=parent)
    finally:
        os.close(parent)


class ImageBuilderService:
    def __init__(self, config: ImageBuilderServiceConfig, *, driver=None, admission=None,
                 clock=time.monotonic, alive=process_token):
        self.config, self.clock, self.alive = config, clock, alive
        self.store = IntentStore(Path(config.state_root))
        self.driver = driver or BuildKitWorker(config)
        self.admission = admission or BuilderAdmission(config)
        self.stopping = False
        self.contract = service_contract(config)
        if any(record["state"] != "CLEANED" and record.get("service_contract") != self.contract
               for record in self.store.records()):
            self.store.close()
            raise EnforcementUnavailable("unresolved intents require their original operator service configuration")
        self.engine_broker = None
        if config.native_engine is not None:
            from appsec_review.container_runtime.engine_broker import EngineBroker
            self.engine_broker = EngineBroker(self)

    def close(self):
        self.store.close()

    def _authorize(self, binding: object, peer: Peer) -> BuilderGrant:
        if peer.gid != self.config.admission.gid:
            raise PermissionError("client GID differs from the operator admission binding")
        if not isinstance(binding, dict) or set(binding) != BINDING_FIELDS:
            raise ValueError("invalid exact build binding")
        for name in BINDING_FIELDS - {"context", "output_tag", "namespace"}:
            identifier(binding[name])
        if not re.fullmatch(r"[0-9a-f]{32}", binding["build_id"]):
            raise ValueError("build ID must be a client-generated UUID")
        matches = [grant for grant in self.config.grants if
                   (grant.uid, grant.tenant_id, grant.project_id, grant.run_id, grant.target_snapshot) ==
                   (peer.uid, binding["tenant_id"], binding["project_id"],
                    binding["run_id"], binding["target_snapshot"])]
        if len(matches) != 1 or binding["release_id"] != self.config.release_id:
            raise PermissionError("run/tenant/project/release is not operator-authorized")
        grant = matches[0]
        expected_namespace = hashlib.sha256(encoded({
            "tenant": grant.tenant_id, "project": grant.project_id,
            "run_root": grant.run_root, "builder": self.config.release_id,
        })).hexdigest()[:24]
        if binding["namespace"] != grant.namespace or grant.namespace != expected_namespace:
            raise PermissionError("namespace is not bound to the authorized run metadata")
        expected = str(Path(grant.client_context_root) / grant.namespace / binding["build_id"] / "context")
        if binding["context"] != expected:
            raise PermissionError("context is outside the exact authorized mapping")
        tag = binding["output_tag"]
        if (not isinstance(tag, str) or len(tag) > 200
                or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[a-zA-Z0-9_.-]+", tag)
                or not tag.split(":")[-1].startswith(grant.namespace[:12])):
            raise PermissionError("output tag is not private to this run")
        return grant

    def _prior_output_ids(self, grant: BuilderGrant) -> set[str]:
        """Only operator-journal success and cleanup together authorize another layer."""
        allowed = set()
        for record in self.store.records():
            binding, worker = record.get("binding", {}), record.get("worker", {})
            execution = record.get("execution", {})
            if not isinstance(execution, dict):
                continue
            image_id = execution.get("image_id")
            if (record.get("state") != "CLEANED" or record.get("error") or record.get("quarantine")
                    or not self.config.resources.matches(record.get("resource_budget"))
                    or record.get("output_quarantined") or record.get("service_contract") != self.contract
                    or record.get("grant") != asdict(grant)
                    or not isinstance(binding, dict) or set(binding) != BINDING_FIELDS
                    or not isinstance(binding["build_id"], str)
                    or not re.fullmatch(r"[0-9a-f]{32}", binding["build_id"])
                    or any(binding.get(name) != getattr(grant, name) for name in (
                        "tenant_id", "project_id", "run_id", "namespace", "target_snapshot"))
                    or binding.get("release_id") != self.config.release_id
                    or not isinstance(worker, dict) or set(worker) != {"id", "start_token"}
                    or not isinstance(worker["id"], str)
                    or not re.fullmatch(r"appsec-builder-[0-9a-f]{32}", worker["id"])
                    or not isinstance(worker["start_token"], str)
                    or not re.fullmatch(r"[0-9a-f]{32}", worker["start_token"])
                    or execution.get("state") != "SUCCEEDED"
                    or type(execution.get("exit_code")) is not int or execution["exit_code"] != 0
                    or not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)):
                continue
            provenance = {"binding": binding, "worker": worker, "service_contract": self.contract}
            if (record.get("output_authorization") != {
                    **provenance, "state": "SUCCEEDED", "exit_code": 0, "image_id": image_id}
                    or record.get("cleanup") != {
                        **provenance, "state": "CLEANED", "work_stopped": True, "context_released": True}):
                continue
            directory = Path(self.config.state_root) / binding["build_id"]
            if record.get("directory") != str(directory):
                continue
            try:
                directory.lstat()
            except FileNotFoundError:
                if _released_context(grant, binding, worker):
                    allowed.add(image_id)
        return allowed

    def _start_spec(self, body: dict, grant: BuilderGrant) -> dict:
        network, arguments, images = (body.get(name) for name in ("network", "build_args", "image_inputs"))
        if (not isinstance(network, str) or network not in {"none", "default"}
                or (network == "default" and not grant.allow_network)):
            raise PermissionError("network policy is not authorized")
        if (not isinstance(arguments, dict) or set(arguments) - {"CODEQL_SOURCE_IMAGE", "BUILD_IMAGE", "RUNTIME_USER"}
                or any(not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value
                       for value in arguments.values())):
            raise ValueError("invalid build arguments")
        allowed = {image.image_id for image in self.config.images} | self._prior_output_ids(grant)
        if not isinstance(images, dict) or len(images) > 16:
            raise ValueError("invalid image input map")
        for tag, image_id in images.items():
            if (not isinstance(tag, str) or len(tag) > 200
                    or not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[a-zA-Z0-9_.-]+", tag)
                    or not tag.split(":")[-1].startswith(grant.namespace[:12])
                    or not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)
                    or image_id not in allowed):
                raise PermissionError("image input lacks a declared release or confirmed same-run output")
        aliases = {image.alias: image.image_id for image in self.config.images}
        if any(tag in aliases and aliases[tag] != image_id for tag, image_id in images.items()):
            raise PermissionError("image input cannot rebind a declared alias")
        return {"network": network, "build_args": arguments, "image_inputs": images,
                "authorized_inputs": {**aliases, **images}}

    def _response(self, record: dict) -> dict:
        response = {"binding": record["binding"], "worker": record["worker"], "state": record["state"],
                    "resource_budget": record["resource_budget"]}
        if record.get("limits") is not None:
            response.update(limits=record["limits"], private_context=True)
        if record.get("execution") is not None:
            response.update({key: value for key, value in record["execution"].items() if key != "state"})
        if record["state"] == "CLEANED":
            response.update(work_stopped=True, context_released=True)
        if record.get("error"):
            response["error"] = record["error"]
        return response

    def _save(self, record: dict):
        self.store.save(record)

    def _clean(self, record: dict):
        record["state"] = "CLEANING"
        self._save(record)
        if not self.driver.cleanup(record, lambda: self._save(record)):
            raise OutcomeUnknown("worker/host termination is unconfirmed")
        release_context(record)
        directory = Path(record["directory"])
        if directory.exists():
            private_path(directory)
            shutil.rmtree(directory)
        if self.engine_broker is not None:
            self.engine_broker.driver.inventory()
        record.update(state="CLEANED", error=None, cleaned_at=self.clock())
        record["cleanup"] = {
            "state": "CLEANED", "work_stopped": True, "context_released": True,
            "binding": record["binding"], "worker": record["worker"],
            "service_contract": record["service_contract"],
        }
        self._save(record)
        if self.engine_broker is not None:
            self.engine_broker.release_builder(record)

    def dispatch(self, message: bytes, peer: Peer) -> bytes:
        request = decode_message(message)
        body, action = request["body"], request["action"]
        fields = {"binding", "worker", "resource_budget"} | {
            "prepare": {"limits"}, "start": {"network", "build_args", "image_inputs"},
        }.get(action, set())
        if set(body) != fields:
            raise ValueError("unexpected action fields")
        grant = self._authorize(body["binding"], peer)
        if ResourceBudget.from_view(body["resource_budget"]) != self.config.resources:
            raise EnforcementUnavailable("client aggregate/staging budget differs from operator service")
        if self.alive(peer.pid) != peer.start_token:
            raise PermissionError("request owner changed or exited")
        if action in {"prepare", "start", "status"}:
            self.admission.verify()
        binding = body["binding"]
        record = self.store.get(binding["build_id"])
        if action == "prepare" and (record is None or record["state"] in {"PREPARING", "PREPARED"}):
            self.admission.verify_build(binding, asdict(peer), record["worker"] if record else None, preparing=True)
        elif action == "start" and record is not None and record["state"] == "PREPARED":
            self.admission.verify_build(binding, asdict(peer), record["worker"])
        elif action == "status" and record is not None and record["state"] == "RUNNING":
            self.admission.verify_build(binding, asdict(peer), record["worker"])
        if record is None:
            if action != "prepare" or body["worker"] is not None:
                raise ValueError("unknown build; prepare must precede side effects")
            if (not isinstance(body["limits"], dict) or body["limits"] != self.config.requested_limits
                    or (self.config.resource_mode == "bounded" and
                        any(type(value) is not int for value in body["limits"].values()))):
                raise EnforcementUnavailable("requested limits differ from the operator envelope")
            records = self.store.records()
            if len(records) >= self.config.max_records:
                raise EnforcementUnavailable("durable journal capacity requires operator rotation")
            if sum(item["state"] != "CLEANED" for item in records) >= self.config.max_concurrency:
                raise EnforcementUnavailable("service admission retains active or unresolved reservations")
            identity = context_identity(grant, binding, empty=True)
            record = {
                "binding": binding, "worker": {"id": "appsec-builder-" + uuid4().hex,
                                              "start_token": uuid4().hex},
                "peer": asdict(peer), "grant": asdict(grant), "state": "PREPARING",
                "service_contract": self.contract,
                "resource_budget": self.config.resources.view(),
                "limits_requested": body["limits"], "context_identity": identity,
                "directory": str(Path(self.config.state_root) / binding["build_id"]),
                "driver": {}, "created_at": self.clock(), "last_seen": self.clock(),
            }
            if self.engine_broker is not None:
                self.engine_broker.claim_builder(record)
            else:
                self._save(record)
        else:
            if not self.config.resources.matches(record.get("resource_budget")):
                raise EnforcementUnavailable("build changed its frozen resource budget")
            if record["binding"] != binding or record["peer"] != asdict(peer):
                raise PermissionError("build belongs to a different binding or process generation")
            if body["worker"] != record["worker"] and not (
                    action in {"prepare", "cancel", "cleanup"} and body["worker"] is None):
                raise PermissionError("worker generation mismatch")
            if action == "prepare" and body["limits"] != record["limits_requested"]:
                raise ValueError("repeated prepare changed limits")
        spec = self._start_spec(body, grant) if action == "start" else None
        if spec is not None and record.get("start") is not None and record["start"] != spec:
            raise ValueError("repeated start changed immutable solve inputs")
        self.store.nonce(peer, request)
        record["last_seen"] = self.clock()
        self._save(record)
        try:
            if action == "prepare" and record["state"] == "PREPARING":
                # A durable dispatch marker makes lost prepare responses replayable
                # without ever replaying an uncertain create request.
                if record.get("prepare_dispatched"):
                    raise OutcomeUnknown("prepare dispatch requires reconciliation")
                record["prepare_dispatched"] = True
                self._save(record)
                Path(record["directory"]).mkdir(mode=0o700)
                limits = self.driver.prepare(record, lambda: self._save(record))
                self._validate_limits(limits)
                record.update(state="PREPARED", limits=limits)
            elif action == "start" and record["state"] == "PREPARED":
                record.update(state="STARTING", start=spec, started_at=self.clock())
                self._save(record)
                snapshot_context(record, self.config)
                self.driver.start(record, lambda: self._save(record))
                record["state"] = "RUNNING"
            elif action == "status" and record["state"] == "RUNNING":
                self._poll(record)
            elif action == "cancel" and record["state"] != "CLEANED":
                record["state"] = "CANCELLING"
                self._save(record)
                if not self.driver.cancel(record, lambda: self._save(record)):
                    raise OutcomeUnknown("cancellation is not independently confirmed")
                record["state"] = "CANCELLED"
            elif action == "cleanup" and record["state"] != "CLEANED":
                self._clean(record)
            self._save(record)
        except (OSError, ValueError, RuntimeError) as exc:
            record.update(state="UNKNOWN", error=f"{type(exc).__name__}: {exc}"[:2048],
                          output_quarantined=True)
            self._save(record)
        response = encoded({"schema": SCHEMA, "request_id": request["request_id"], "body": self._response(record)})
        if len(response) > MAX_MESSAGE_BYTES:
            raise ValueError("response exceeded protocol bound")
        return response

    def _validate_limits(self, limits):
        if not isinstance(limits, dict):
            raise EnforcementUnavailable("driver supplied no kernel enforcement")
        if self.config.resource_mode == "concurrency_only":
            try:
                validate_concurrency_only_enforcement(limits)
            except ValueError as exc:
                raise EnforcementUnavailable(str(exc)) from exc
            return
        for prefix, cpu, memory in (("", self.config.cpu, self.config.memory_mb),
                                    ("host_", self.config.host_cpu, self.config.host_overhead_mb)):
            values = [limits.get(prefix + name) for name in ("cpu_quota_us", "cpu_period_us", "memory_max")]
            if (any(type(value) is not int or value <= 0 for value in values)
                    or values[0] > cpu * values[1] or values[2] > memory * 1024 * 1024):
                raise EnforcementUnavailable("driver's observed enforcement exceeds the reservation")

    def _poll(self, record: dict):
        result = self.driver.status(record, lambda: self._save(record))
        if not isinstance(result, dict):
            raise OutcomeUnknown("worker result is not a protocol object")
        state = result.get("state")
        if set(result) - {"state", "exit_code", "image_id", "stdout", "stderr"}:
            raise OutcomeUnknown("worker result contains unbound fields")
        if state == "RUNNING":
            return
        if (state not in {"SUCCEEDED", "FAILED"} or type(result.get("exit_code")) is not int
                or (result["exit_code"] == 0) != (state == "SUCCEEDED")):
            raise OutcomeUnknown("worker execution terminal is not confirmed")
        if state == "SUCCEEDED" and (
                not isinstance(result.get("image_id"), str) or not IMAGE_ID.fullmatch(result["image_id"])):
            raise OutcomeUnknown("worker output lacks its immutable image identity")
        import base64
        for name in ("stdout", "stderr"):
            value = result.get(name)
            if (not isinstance(value, str) or len(value) > 4 * ((MAX_LOG_BYTES + 2) // 3)
                    or len(base64.b64decode(value, validate=True)) > MAX_LOG_BYTES):
                raise OutcomeUnknown("worker logs exceed the protocol bound")
        record.update(state=state, execution=result)
        if state == "SUCCEEDED":
            record["output_authorization"] = {
                "binding": record["binding"], "worker": record["worker"],
                "service_contract": record["service_contract"], "state": "SUCCEEDED",
                "exit_code": 0, "image_id": result["image_id"],
            }

    def reconcile(self, *, restart: bool = False):
        for record in self.store.records():
            if record["state"] == "CLEANED":
                if self.engine_broker is not None:
                    self.engine_broker.release_builder(record)
                continue
            peer = record["peer"]
            expired = (self.clock() - record["last_seen"] >= self.config.owner_idle_seconds
                       or self.clock() - record["created_at"] >= self.config.build_timeout_seconds)
            try:
                if restart or expired or self.alive(peer["pid"]) != peer["start_token"]:
                    self._clean(record)
                elif record["state"] == "RUNNING":
                    self.admission.verify()
                    self.admission.verify_build(record["binding"], record["peer"], record["worker"])
                    self._poll(record)
                    self._save(record)
            except (OSError, ValueError, RuntimeError) as exc:
                record.update(state="UNKNOWN", error=f"{type(exc).__name__}: {exc}"[:2048],
                              output_quarantined=True)
                self._save(record)
        if self.engine_broker is not None:
            self.engine_broker.reconcile(restart=restart)
        try:
            self.admission.reconcile()
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            exception_type = re.sub(r"[^A-Za-z0-9_]", "_", type(exc).__name__)[:64]
            LOGGER.warning("BOUNDED_IMAGE_BUILDER_ADMISSION_RECONCILE_FAILED exception_type=%s", exception_type)

    def serve(self):
        if self.engine_broker is not None:
            from appsec_review.container_runtime.engine_broker import verify_runtime
            verify_runtime(self.config)
        uids = {grant.uid for grant in self.config.grants}
        if len(uids) != 1 or os.geteuid() != 0:
            raise EnforcementUnavailable("root service and one socket-owner UID are required")
        self.admission.verify()
        self.driver.proof.host()
        if self.engine_broker is not None:
            self.engine_broker.driver.check_host()
        self.reconcile(restart=True)
        endpoints = [(Path(self.config.endpoint), False)]
        if self.engine_broker is not None:
            endpoints.append((Path(self.config.native_engine.endpoint), True))
        with ExitStack() as stack:
            listeners, identities = {}, []
            try:
                for endpoint, native in endpoints:
                    private_path(endpoint.parent)
                    if endpoint.exists() or endpoint.is_symlink():
                        info = endpoint.lstat()
                        if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in uids or info.st_mode & 0o077:
                            raise EnforcementUnavailable("existing endpoint is not the private service socket")
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                            probe.settimeout(1)
                            try:
                                probe.connect(str(endpoint))
                            except ConnectionRefusedError:
                                endpoint.unlink()
                            else:
                                raise EnforcementUnavailable("existing service endpoint is still live")
                    listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
                    listener.bind(str(endpoint))
                    endpoint.chmod(0o600)
                    os.chown(endpoint, next(iter(uids)), -1)
                    identities.append((endpoint, endpoint.stat()))
                    listener.listen(4)
                    listener.setblocking(False)
                    listeners[listener] = native
                if self.engine_broker is not None:
                    from appsec_review.container_runtime.native_contracts import publish_client_contracts
                    publish_client_contracts(self.config)
                while not self.stopping:
                    self.reconcile()
                    ready, _, _ = select.select(list(listeners), [], [], 0.01)
                    for listener in ready:
                        channel, _ = listener.accept()
                        native, request = listeners[listener], None
                        with channel:
                            try:
                                peer = authenticated_peer(channel)
                                deadline = time.monotonic() + min(5, self.config.command_timeout_seconds)
                                maximum = 65536 if native else MAX_MESSAGE_BYTES
                                data = bytearray()
                                while not data.endswith(b"\n"):
                                    remaining = deadline - time.monotonic()
                                    if remaining <= 0:
                                        raise TimeoutError("request frame deadline exceeded")
                                    channel.settimeout(remaining)
                                    chunk = channel.recv(min(65536, maximum + 1 - len(data)))
                                    if not chunk:
                                        raise ValueError("incomplete request frame")
                                    data.extend(chunk)
                                    if len(data) > maximum:
                                        raise ValueError("request exceeds protocol bound")
                                if native:
                                    from appsec_review.container_runtime.engine_broker import decode_request
                                    reply = self.engine_broker.dispatch(bytes(data), peer)
                                    request = decode_request(bytes(data))
                                else:
                                    reply = self.dispatch(bytes(data), peer)
                                channel.settimeout(1)
                                channel.sendall(reply)
                            except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
                                if native and request is not None:
                                    self.engine_broker.disconnected(request)
                                _log_request_failure(exc)
            finally:
                self.reconcile(restart=True)
                for endpoint, identity in identities:
                    if endpoint.exists() and endpoint.stat().st_ino == identity.st_ino:
                        endpoint.unlink()


def reconcile_retired_runtime(config: ImageBuilderServiceConfig,
                              prior: ImageBuilderServiceConfig) -> list[str]:
    if config.native_engine is None or prior.native_engine is None:
        raise EnforcementUnavailable("cross-release reconciliation requires native runtime identities")
    current, previous = service_contract(config), service_contract(prior)
    for name in ("runtime_root", "runtime_release_id"):
        previous["native_engine"][name] = current["native_engine"][name]
    if current != previous:
        raise EnforcementUnavailable("retired reconciliation cannot change host, policy or admission bindings")
    return BuilderAdmission(prior).reconcile_retired()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--reserve-lifetime", action="store_true")
    operation.add_argument("--reconcile-admission", action="store_true")
    operation.add_argument("--reconcile-retired-admission", type=Path)
    operation.add_argument("--release-lifetime", action="store_true")
    operation.add_argument("--finalize-commissioning", action="store_true")
    arguments = parser.parse_args()
    if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
        raise SystemExit("authenticated native Linux Unix sockets are required")
    os.umask(0o077)
    private_path(arguments.config, directory=False)
    config = load_image_builder_service(arguments.config)
    if config.native_engine is not None:
        from appsec_review.container_runtime.engine_broker import verify_runtime
        verify_runtime(config)
    if arguments.reconcile_retired_admission is not None:
        private_path(arguments.reconcile_retired_admission, directory=False)
        prior = load_image_builder_service(arguments.reconcile_retired_admission)
        print(json.dumps(reconcile_retired_runtime(config, prior)))
        return
    admission = BuilderAdmission(config)
    if arguments.reserve_lifetime:
        print(admission.reserve())
        return
    if arguments.finalize_commissioning:
        admission.finalize_commissioning()
        return
    if arguments.reconcile_admission:
        print(json.dumps(admission.reconcile()))
        return
    if arguments.release_lifetime:
        admission.release()
        return
    admission.verify()
    service = ImageBuilderService(config, admission=admission)
    previous = {signum: signal.signal(signum, lambda *_: setattr(service, "stopping", True))
                for signum in (signal.SIGTERM, signal.SIGINT)}
    try:
        service.serve()
    finally:
        service.close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    main()
