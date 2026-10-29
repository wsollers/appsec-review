"""Client contract for an operator-commissioned, isolated image-building service."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time
from typing import Any, Mapping
from uuid import uuid4

from appsec_review.config.assurance import (
    ImageBuilderConfig, ResourceBudget, validate_concurrency_only_enforcement,
)
from appsec_review.runtime import resources as resource_runtime
from appsec_review.observability.spans import count_work, operation_span
from appsec_review.runtime.resources import (
    ImagePreparationUnavailable, quarantine_resources, reserve_execution, review_resources_active,
    track_image_build, update_image_build,
)
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage.shared import reference, safe_path, verify_reference


SCHEMA = "appsec-review/bounded-image-builder/1"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_LOG_BYTES = 64 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}")


@dataclass(frozen=True)
class BuilderOwner:
    config: ImageBuilderConfig
    project_id: str
    run_root: Path
    metadata_root: Path
    target_root: Path | None
    target_snapshot: str
    events: Any
    resources: ResourceBudget

    @property
    def namespace(self) -> str:
        return hashlib.sha256(canonical_json({
            "tenant": self.config.tenant_id, "project": self.project_id,
            "run_root": str(self.run_root.resolve()), "builder": self.config.release_id,
        })).hexdigest()[:24]


_OWNER: ContextVar[BuilderOwner | None] = ContextVar("image_builder_owner", default=None)


@contextmanager
def image_builder_scope(context):
    config = context.review_policy.image_builder
    owner = (BuilderOwner(config, context.review_policy.project_id, context.run_root, context.metadata_root,
                          context.target_root, context.source_fingerprint, context.events,
                          ResourceBudget.from_view(context.review_policy.resources.view()))
             if config is not None else None)
    token = _OWNER.set(owner)
    try:
        yield
    finally:
        _OWNER.reset(token)


def require_builder() -> BuilderOwner:
    owner = _OWNER.get()
    if owner is None:
        raise ImagePreparationUnavailable(
            "derived_image_preparation_unavailable: no operator-approved builder "
            "with a declared resource policy and confirmed cancellation")
    if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
        raise ImagePreparationUnavailable("bounded image builder requires authenticated Linux Unix sockets")
    review_owner, active = resource_runtime._OWNER.get(), resource_runtime._ACTIVE.get()
    admissions = ([review_owner[0]] if review_owner is not None else []) + (
        [active.admission] if active is not None else [])
    for admission in admissions:
        if (admission.budget != owner.resources
                or admission.root != owner.metadata_root.resolve() / "resource-admission"):
            raise ValueError("builder resource scope differs from its frozen budget or metadata store")
    return owner


def builder_namespace() -> str | None:
    owner = _OWNER.get()
    return owner.namespace if owner is not None else None


def verify_builder_receipt(ref: Mapping[str, Any], *, identity: str, tag: str, image_id: str) -> None:
    owner = require_builder()
    receipt = json.loads(verify_reference(owner.run_root, ref).read_bytes())
    binding = receipt.get("binding", {})
    if (receipt.get("schema") != SCHEMA
            or not owner.resources.matches(receipt.get("resource_budget"))
            or any(not isinstance(receipt.get(name), dict)
                   or not owner.resources.matches(receipt[name].get("resource_budget"))
                   for name in ("enforcement", "execution", "cleanup"))
            or binding.get("namespace") != owner.namespace
            or binding.get("recipe_identity") != identity or binding.get("output_tag") != tag
            or receipt.get("execution", {}).get("state") != "SUCCEEDED"
            or receipt.get("execution", {}).get("image_id") != image_id
            or receipt.get("cleanup", {}).get("state") != "CLEANED"):
        raise ValueError("cached image lacks its run-bound successful preparation receipt")
    if receipt["enforcement"].get("requested_limits") != owner.config.requested_limits:
        raise ValueError("cached image builder resource policy differs")


class UnixBuilderClient:
    def __init__(self, owner: BuilderOwner):
        self.owner = owner

    def request(self, action: str, body: Mapping[str, Any], timeout: float) -> dict[str, Any]:
        endpoint = Path(self.owner.config.endpoint)
        for root in (self.owner.run_root, self.owner.target_root):
            if root is not None and endpoint.resolve().is_relative_to(root.resolve()):
                raise ValueError("builder endpoint must be outside target and run custody")
        metadata = endpoint.lstat()
        parent = endpoint.parent.stat()
        if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid not in {0, os.getuid()}
                or metadata.st_mode & 0o022 or parent.st_uid not in {0, os.getuid()}
                or parent.st_mode & 0o022):
            raise ValueError("builder endpoint lacks operator-private custody")
        request_id = uuid4().hex
        request = canonical_json({"schema": SCHEMA, "request_id": request_id,
                                  "action": action, "body": body})
        if len(request) > MAX_RESPONSE_BYTES:
            raise ValueError("builder request exceeds its protocol bound")
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(max(0.001, timeout))
            channel.connect(str(endpoint))
            _, peer_uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid not in {0, os.getuid()}:
                raise ValueError("builder peer is not operator-owned")
            channel.sendall(request + b"\n")
            chunks, size = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("builder protocol response deadline exceeded")
                channel.settimeout(remaining)
                chunk = channel.recv(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ValueError("builder response exceeds its protocol bound")
                chunks.append(chunk)
        response = json.loads(b"".join(chunks))
        if (not isinstance(response, dict) or response.get("schema") != SCHEMA
                or response.get("request_id") != request_id or not isinstance(response.get("body"), dict)):
            raise ValueError("builder protocol response binding mismatch")
        return response["body"]


class ImageBuildSession:
    def __init__(self, owner: BuilderOwner, *, identity: str, tag: str, timeout_seconds: int):
        self.owner, self.build_id = owner, uuid4().hex
        self.root = safe_path(owner.run_root, f"data/orchestration/image-builds/{self.build_id}")
        self.context = safe_path(owner.metadata_root,
                                 f"bounded-image-contexts/{owner.namespace}/{self.build_id}/context")
        if not tag.split(":")[-1].startswith(owner.namespace[:12]):
            raise ValueError("builder output tag is not bound to its run and tenant namespace")
        self.binding = {
            "build_id": self.build_id, "tenant_id": owner.config.tenant_id, "project_id": owner.project_id,
            "run_id": owner.run_root.name, "target_snapshot": owner.target_snapshot,
            "release_id": owner.config.release_id, "namespace": owner.namespace,
            "recipe_identity": identity, "context": str(self.context), "output_tag": tag,
        }
        self.deadline = time.monotonic() + timeout_seconds
        self.client = UnixBuilderClient(owner)
        self.worker: dict[str, Any] | None = None
        self.enforcement: dict[str, Any] | None = None
        self.execution: dict[str, Any] | None = None
        self.output_image_id: str | None = None
        self.integrity_lost = False
        self.integrity_reason: str | None = None
        self.last_state = "UNSTARTED"

    def _quarantine_integrity(self, reason: str) -> None:
        self.integrity_lost = True
        self.integrity_reason = self.integrity_reason or reason
        quarantine_resources(self.integrity_reason)

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded image preparation deadline exceeded")
        return remaining

    def exchange(self, action: str, *, extra: Mapping[str, Any] | None = None,
                 timeout: float | None = None) -> dict[str, Any]:
        request = {"binding": self.binding, "worker": self.worker,
                   "resource_budget": self.owner.resources.view(), **dict(extra or {})}
        atomic_json(self.root / f"{action}-request.json", request)
        response = self.client.request(action, request, self.remaining() if timeout is None else timeout)
        atomic_json(self.root / f"{action}-response.json", response)
        if not self.owner.resources.matches(response.get("resource_budget")):
            self._quarantine_integrity("image_builder_budget_mismatch")
            raise ValueError("builder changed or omitted its frozen resource budget")
        if response.get("binding") != self.binding:
            self._quarantine_integrity("image_builder_binding_mismatch")
            raise ValueError("builder changed run, tenant, target, recipe or output binding")
        worker = response.get("worker")
        if (not isinstance(worker, dict) or set(worker) != {"id", "start_token"}
                or any(not isinstance(value, str) or not _ID.fullmatch(value) for value in worker.values())):
            self._quarantine_integrity("image_builder_worker_unknown")
            raise ValueError("builder worker identity is unavailable")
        if self.worker is not None and self.worker != worker:
            self._quarantine_integrity("image_builder_worker_replaced")
            raise ValueError("builder worker was replaced")
        self.worker = worker
        update_image_build(self.build_id, worker=worker)
        self.last_state = str(response.get("state", "UNKNOWN"))
        return response

    def prepare(self) -> None:
        self.root.mkdir(parents=True, mode=0o700)
        self.context.parent.mkdir(parents=True, mode=0o700)
        self.context.mkdir(parents=True, mode=0o700)
        config = self.owner.config
        response = self.exchange("prepare", extra={"limits": config.requested_limits})
        limits = response.get("limits", {})
        if not isinstance(limits, dict):
            raise ValueError("builder resource enforcement report is invalid")
        if self.last_state != "PREPARED" or response.get("private_context") is not True:
            raise ImagePreparationUnavailable("builder private isolation is unverified")
        if config.resource_mode == "concurrency_only":
            validate_concurrency_only_enforcement(limits)
            self.enforcement = {**response, "requested_limits": config.requested_limits}
            return
        quota, period, memory = (limits.get(name) for name in ("cpu_quota_us", "cpu_period_us", "memory_max"))
        if (self.last_state != "PREPARED" or response.get("private_context") is not True
                or any(type(value) is not int or value <= 0 for value in (quota, period, memory))
                or quota > config.cpu * period or memory > config.memory_mb * 1024 * 1024):
            raise ImagePreparationUnavailable("bounded builder enforcement or private isolation is unverified")
        host_quota, host_period, host_memory = (
            limits.get(name) for name in ("host_cpu_quota_us", "host_cpu_period_us", "host_memory_max"))
        if (any(type(value) is not int or value <= 0 for value in (host_quota, host_period, host_memory))
                or host_quota > config.host_cpu * host_period
                or host_memory > config.host_overhead_mb * 1024 * 1024):
            raise ImagePreparationUnavailable("bounded builder host overhead enforcement is unverified")
        self.enforcement = {**response, "requested_limits": config.requested_limits}

    def build(self, *, network: str, build_args: Mapping[str, str] | None = None,
              image_inputs: Mapping[str, str] | None = None):
        if network not in {"none", "default"}:
            raise ValueError("unsupported image build network policy")
        args = dict(build_args or {})
        if set(args) - {"CODEQL_SOURCE_IMAGE", "BUILD_IMAGE", "RUNTIME_USER"} or any(
                not isinstance(value, str) or not value or len(value) > 512 for value in args.values()):
            raise ValueError("unsupported bounded image build arguments")
        images = dict(image_inputs or {})
        if any(not isinstance(tag, str) or not tag.split(":")[-1].startswith(self.owner.namespace[:12])
               or not isinstance(identity, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity)
               for tag, identity in images.items()):
            raise ValueError("builder image input aliases are not private immutable bindings")
        response = self.exchange("start", extra={"network": network, "build_args": args, "image_inputs": images})
        count_work("builder_launches")
        while self.last_state in {"RUNNING", "QUEUED"}:
            time.sleep(min(0.1, self.remaining()))
            response = self.exchange("status")
        if self.last_state not in {"SUCCEEDED", "FAILED"} or type(response.get("exit_code")) is not int:
            raise RuntimeError("builder has no confirmed execution terminal")
        code = response["exit_code"]
        if (code == 0) != (self.last_state == "SUCCEEDED"):
            raise ValueError("builder execution status conflicts with exit code")
        image_id = response.get("image_id")
        if code == 0 and (not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)):
            raise ValueError("successful builder result lacks its immutable output image ID")
        logs = []
        for name in ("stdout", "stderr"):
            encoded = response.get(name)
            if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_LOG_BYTES + 2) // 3):
                raise ValueError("builder diagnostic stream is missing or oversized")
            value = base64.b64decode(encoded, validate=True)
            if len(value) > MAX_LOG_BYTES:
                raise ValueError("builder diagnostic stream exceeds its byte bound")
            logs.append(value)
        self.execution = response
        self.output_image_id = image_id if code == 0 else None
        return code, logs[0], logs[1], False

    def receipt(self) -> dict[str, Any]:
        return reference(self.owner.run_root, self.root / "terminal.json")

    def cleanup(self) -> None:
        deadline = time.monotonic() + self.owner.config.cleanup_timeout_seconds
        cancel_error = None
        try:
            self.exchange("cancel", timeout=max(0.001, deadline - time.monotonic()))
        except (OSError, ValueError, RuntimeError) as exc:
            cancel_error = f"{type(exc).__name__}: {exc}"[:2048]
        response = self.exchange("cleanup", timeout=max(0.001, deadline - time.monotonic()))
        if (self.last_state != "CLEANED" or response.get("work_stopped") is not True
                or response.get("context_released") is not True or self.integrity_lost):
            raise RuntimeError("builder work termination and context cleanup are unconfirmed")
        atomic_json(self.root / "terminal.json", {
            "schema": SCHEMA, "binding": self.binding, "worker": self.worker,
            "resource_budget": self.owner.resources.view(),
            "enforcement": self.enforcement, "execution": self.execution,
            "cleanup": response, "cancel_error": cancel_error,
        })
        update_image_build(self.build_id, stopped=True)


@contextmanager
def bounded_image_preparation(*, identity: str, tag: str, timeout_seconds: int):
    if not review_resources_active():
        yield None
        return
    owner = require_builder()
    session = ImageBuildSession(owner, identity=identity, tag=tag, timeout_seconds=timeout_seconds)
    config = owner.config
    cpu, memory_mb = config.build_reservation(owner.resources)
    with reserve_execution(cpu=str(cpu),
                           memory=f"{memory_mb}m",
                           action="image.prepare", timeout_seconds=math.ceil(session.remaining())):
        lease = track_image_build({**session.binding, "endpoint": config.endpoint,
                                   "resource_budget": owner.resources.view()},
                                  max_concurrency=config.max_concurrency,
                                  timeout_seconds=session.remaining())
        with operation_span(owner.events, "image.prepare", resource_lease_id=lease):
            try:
                session.prepare()
                yield session
            except BaseException as exc:
                atomic_json(session.root / "failure.json", {"type": type(exc).__name__, "message": str(exc)[:2048]})
                raise
            finally:
                try:
                    session.cleanup()
                except BaseException:
                    quarantine_resources(session.integrity_reason or (
                        "image_builder_integrity_unconfirmed" if session.integrity_lost
                        else "image_builder_cleanup_unconfirmed"))
                    raise
