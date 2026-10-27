"""Run-local immutable bytes and attempt-local computation/reuse receipts.

An object hash identifies bytes, not a computation or its first producer. Request directories
contain immutable references to *computed* receipts, never a replaceable "winning result".
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
from typing import Any, Mapping, TYPE_CHECKING

from .atomic import canonical_json, file_sha256
from .validation import current_validation, validation_operation, validation_scope, verified_digest

if TYPE_CHECKING:
    from appsec_review.runtime.job import JobContext

RECEIPT_SCHEMA = "appsec-review/shared-receipt/1"
REQUEST_SCHEMA = "appsec-review/shared-request/1"
OBJECTS = "data/shared/objects"
REQUESTS = "data/shared/requests"
NAMED = "data/shared/named"
_HASH = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-zA-Z0-9_-]+")
_ACTIVE: ContextVar[SharedArtifacts | None] = ContextVar("shared_artifact_attempt", default=None)
NAMED_LAYOUTS = {
    "index-shard": ("data/indices/",),
    "owasp-shard": ("data/indexes/owasp/",),
    "guidance": ("data/guidance/",),
    "review-package": ("data/review-packages/",),
    "review-cell": ("data/jobs/job_inference_security_review/cells/",),
    "cell-check": ("data/jobs/job_inference_security_review/cells/",),
}


def _hash(value: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("invalid shared content/fingerprint hash")
    return value


def safe_path(root: Path, relative: str) -> Path:
    """Reject noncanonical paths and every symlink, including links within the run."""
    parts = PurePosixPath(relative).parts
    if (not parts or PurePosixPath(relative).is_absolute() or "\\" in relative
            or ":" in relative or any(part in {".", ".."} for part in parts)
            or "/".join(parts) != relative):
        raise ValueError("shared artifact path is not run-relative canonical POSIX")
    root = Path(root).absolute()
    path = root
    for part in parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f"shared artifact symlink: {relative}")
    if root.is_symlink() or root.resolve() not in path.resolve().parents:
        raise ValueError("shared artifact path escapes run")
    return path


def reference(root: Path, path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    path = safe_path(root, relative)
    if not path.is_file():
        raise ValueError(f"shared artifact missing: {relative}")
    if relative.startswith(OBJECTS + "/"):
        identity = _hash(path.name)
        if expected_sha256 is not None and expected_sha256 != identity:
            raise ValueError("shared object path differs from expected identity")
        expected_sha256 = identity
    digest = (verified_digest(root, path, _hash(expected_sha256)) if expected_sha256 is not None
              else file_sha256(path))
    return {"path": relative, "sha256": digest, "size_bytes": path.stat().st_size}


def verify_reference(root: Path, ref: Mapping[str, Any]) -> Path:
    path = safe_path(root, ref["path"])
    if (not path.is_file() or verified_digest(root, path, _hash(ref["sha256"])) != ref["sha256"]
            or path.stat().st_size != ref["size_bytes"]):
        raise ValueError(f"shared artifact integrity mismatch: {ref['path']}")
    return path


def immutable_bytes(root: Path, relative: str, payload: bytes) -> dict[str, Any]:
    """Publish complete, fsynced bytes with an atomic no-replace link."""
    path = safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        safe_path(root, relative)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
                raise ValueError(f"immutable shared artifact conflicts: {relative}") from None
        return reference(root, path)
    finally:
        os.unlink(temporary)


def put_bytes(root: Path, payload: bytes) -> dict[str, Any]:
    return immutable_bytes(root, f"{OBJECTS}/{hashlib.sha256(payload).hexdigest()}", payload)


def put_file(root: Path, source: Path) -> dict[str, Any]:
    """Stream large objects; never keep a second durable copy of a SQLite shard."""
    safe_path(root, source.relative_to(root).as_posix())
    digest = file_sha256(source)
    relative = f"{OBJECTS}/{digest}"
    path = safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as stream:
            shutil.copyfileobj(stream, output)
            output.flush()
            os.fsync(output.fileno())
            copied_bytes = output.tell()
        from appsec_review.observability.spans import count_work
        count_work("copy_bytes", copied_bytes)
        count_work("copy_objects")
        if file_sha256(Path(temporary)) != digest:
            raise ValueError("shared artifact changed during publication")
        safe_path(root, relative)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or file_sha256(path) != digest:
                raise ValueError(f"immutable shared artifact conflicts: {relative}") from None
        return reference(root, path)
    finally:
        os.unlink(temporary)


def _link(root: Path, source: Path, relative: str, digest: str) -> dict[str, Any]:
    path = safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, path)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or file_sha256(path) != digest:
            raise ValueError(f"immutable shared artifact conflicts: {relative}") from None
    ref = reference(root, path)
    if ref["sha256"] != digest:
        raise ValueError("immutable source changed during publication")
    return ref


def put_private_file(root: Path, source: Path) -> dict[str, Any]:
    """Detach publication from a builder's potentially writable aliases."""
    return put_file(root, source)


def _read(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    raw = verify_reference(root, ref).read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError("shared metadata must be canonical JSON")
    return value


def _binding_path(namespace: str, obj: Mapping[str, Any]) -> str:
    return f"{NAMED}/{namespace}/{hashlib.sha256(obj['path'].encode()).hexdigest()}.json"


def verify_binding(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    value = _read(root, ref)
    namespace, obj = value["namespace"], value["object"]
    if (value.get("schema") != "appsec-review/shared-named/1"
            or namespace not in NAMED_LAYOUTS or not obj["path"].startswith(NAMED_LAYOUTS[namespace])
            or ref["path"] != _binding_path(namespace, obj)):
        raise ValueError("invalid named immutable binding")
    verify_reference(root, obj)
    return value


@validation_operation
def verify_receipt(root: Path, ref: Mapping[str, Any], *,
                   seen: frozenset[str] = frozenset()) -> dict[str, Any]:
    if ref["path"] in seen:
        raise ValueError("shared receipt provenance cycle")
    from appsec_review.observability.spans import count_work
    count_work("receipt_references")
    context = current_validation(root)
    key = ("receipt", ref["path"], _hash(ref["sha256"]))
    verify_reference(root, ref)
    if context is not None:
        with context.lock:
            admitted = context.admitted_receipts.get(ref["path"])
            if admitted is not None and admitted["sha256"] == ref["sha256"]:
                value = deepcopy(admitted["value"])
                for artifact in (value["object"], *value["dependencies"]):
                    path = safe_path(root, artifact["path"])
                    if not path.is_file() or path.stat().st_size != artifact["size_bytes"]:
                        raise ValueError("admitted receipt output is unavailable")
                return value
            if key in context.records:
                return deepcopy(context.records[key])
            value = _verify_receipt(root, ref, seen=seen)
            context.records[key] = deepcopy(value)
            count_work("receipt_validations")
            return value
    return _verify_receipt(root, ref, seen=seen)


def _verify_receipt(root: Path, ref: Mapping[str, Any], *,
                    seen: frozenset[str]) -> dict[str, Any]:
    value = _read(root, ref)
    if value.get("schema") != RECEIPT_SCHEMA or value.get("mode") not in {"computed", "reused"}:
        raise ValueError("invalid shared receipt schema/mode")
    if value.get("layout") not in {None, "named-immutable", "public-feed"}:
        raise ValueError("unsupported shared immutable layout")
    actor = value["actor"]
    if (not isinstance(actor, dict) or not isinstance(value.get("dependencies"), list)
            or not isinstance(value.get("object"), dict)):
        raise ValueError("invalid shared receipt fields")
    namespace, fingerprint = value["namespace"], _hash(value["fingerprint"])
    if namespace == "feed-snapshot" and value.get("layout") != "public-feed":
        raise ValueError("feed-snapshot receipt requires public-feed validation")
    if not _NAME.fullmatch(namespace):
        raise ValueError("invalid shared namespace")
    expected = f"data/jobs/{actor['job_id']}/attempts/{actor['attempt_id']}"
    if ref["path"] != f"{expected}/shared/{namespace}/{fingerprint}.json":
        raise ValueError("shared receipt identity differs from its attempt path")
    claim_path = verify_reference(root, actor["claim"])
    claim = json.loads(claim_path.read_bytes())
    if actor["claim"]["path"] != f"{expected}/claim.json" or any(
        claim.get(key) != actor[key] for key in ("run_id", "job_id", "attempt_id", "orchestration")
    ) or claim.get("attempt_path") != expected or actor["run_id"] != root.name:
        raise ValueError("shared receipt actor differs from its original claim")
    from appsec_review.runtime.datasets import read_dataset_contract
    _, declarations = read_dataset_contract(claim["dataset_contract"], actor["job_id"])
    if not (namespace in claim["dataset_contract"].get("shared_namespaces", ())
            or any(PurePosixPath(ref["path"]).match(pattern)
                   for declaration in declarations for pattern in declaration.artifacts)):
        raise ValueError("shared receipt is not declared by its pinned attempt contract")
    if not isinstance(value["computation"], dict):
        raise ValueError("invalid shared computation identity")
    for artifact in (value["object"], *value["dependencies"]):
        verify_reference(root, artifact)
        if artifact["path"].startswith(OBJECTS + "/") and artifact["path"] != f"{OBJECTS}/{artifact['sha256']}":
            raise ValueError("shared object filename differs from exact byte hash")
    producer = value["producer_receipt"]
    if value["mode"] == "computed":
        if producer is not None or value["legacy"] is not None:
            raise ValueError("computed receipt cannot invent an earlier producer")
        if value.get("layout") == "named-immutable":
            if namespace not in NAMED_LAYOUTS or any(
                not artifact["path"].startswith(NAMED_LAYOUTS[namespace])
                for artifact in (value["object"],)
            ):
                raise ValueError("shared named object is outside its registered immutable layout")
            if (len(value["dependencies"]) != 1
                    or value["dependencies"][0]["path"] != f"{OBJECTS}/{value['object']['sha256']}"
                    or value["dependencies"][0]["sha256"] != value["object"]["sha256"]):
                raise ValueError("named object lacks its exact-byte content reference")
            binding = reference(root, safe_path(root, _binding_path(namespace, value["object"])))
            if verify_binding(root, binding)["object"] != value["object"]:
                raise ValueError("named immutable object changed after publication")
        elif any(artifact["path"] != f"{OBJECTS}/{artifact['sha256']}"
               for artifact in (value["object"], *value["dependencies"])):
            raise ValueError("new computations must publish content-addressed objects")
    elif producer is not None:
        original = verify_receipt(root, producer, seen=seen | {ref["path"]})
        if namespace == "shared-input":
            if (fingerprint != hashlib.sha256(canonical_json(producer)).hexdigest()
                    or any(original[key] != value[key] for key in
                           ("object", "dependencies", "computation", "legacy"))
                    or value.get("layout") is not None):
                raise ValueError("shared input reference differs from its selected source")
        elif (original["mode"] != "computed" or any(original[key] != value[key] for key in
                ("namespace", "fingerprint", "object", "dependencies", "computation"))
                or value.get("layout") != original.get("layout") or value["legacy"] is not None):
            raise ValueError("reused receipt differs from producing computation")
    elif value["legacy"] != "unknown-original-producer" and value.get("layout") != "public-feed":
        raise ValueError("reused receipt lacks verified producer or explicit legacy provenance")
    if value.get("layout") == "public-feed":
        if namespace != "feed-snapshot":
            raise ValueError("public-feed proof has an invalid namespace")
        from .feed_provenance import verify_feed_receipt
        verify_feed_receipt(root, value, claim)
    return value


@dataclass(frozen=True)
class SharedArtifacts:
    run_root: Path
    attempt_root: Path
    actor: Mapping[str, Any]

    @classmethod
    def for_job(cls, context: JobContext) -> SharedArtifacts:
        claim_ref = reference(context.run_root, context.attempt_root / "claim.json")
        claim = json.loads(verify_reference(context.run_root, claim_ref).read_bytes())
        actor = {key: claim[key] for key in ("run_id", "job_id", "attempt_id", "orchestration")}
        original_invocation = dict(actor["orchestration"])
        current_invocation = dict(context.orchestration)
        if original_invocation.get("system") == "dagster" and original_invocation.get("run_id"):
            # Dagster correlates each task with its own node within the same invocation.
            original_invocation.pop("node", None)
            current_invocation.pop("node", None)
        if (actor["run_id"] != context.run_id or actor["attempt_id"] != context.attempt_id
                or actor["job_id"] != context.config.job_id
                or original_invocation != current_invocation):
            raise ValueError("shared publication context differs from original invocation")
        return cls(context.run_root, context.attempt_root, {**actor, "claim": claim_ref})

    def _slot(self, namespace: str, fingerprint: str) -> str:
        if not _NAME.fullmatch(namespace):
            raise ValueError("invalid shared namespace")
        return (self.attempt_root.relative_to(self.run_root).as_posix()
                + f"/shared/{namespace}/{_hash(fingerprint)}.json")

    def _record(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
                computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = (),
                mode: str, producer: Mapping[str, Any] | None = None, legacy: str | None = None,
                layout: str | None = None,
                ) -> tuple[dict[str, Any], dict[str, Any]]:
        value = {"schema": RECEIPT_SCHEMA, "namespace": namespace, "fingerprint": fingerprint,
                 "actor": dict(self.actor), "mode": mode, "object": dict(obj),
                 "dependencies": list(dependencies), "computation": dict(computation),
                 "producer_receipt": producer, "legacy": legacy}
        if layout is not None:
            value["layout"] = layout
        ref = immutable_bytes(self.run_root, self._slot(namespace, fingerprint), canonical_json(value))
        verify_receipt(self.run_root, ref)
        return value, ref

    def computed(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
                 computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = (),
                 layout: str | None = None,
                 ) -> dict[str, Any]:
        _, receipt = self._record(namespace, fingerprint, obj, computation=computation,
                                  dependencies=dependencies, mode="computed", layout=layout)
        immutable_bytes(self.run_root, f"{REQUESTS}/{namespace}/{fingerprint}/{receipt['sha256']}.json",
                        canonical_json({"schema": REQUEST_SCHEMA, "receipt": receipt}))
        return receipt

    def lookup(self, namespace: str, fingerprint: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        slot = safe_path(self.run_root, self._slot(namespace, fingerprint))
        if slot.exists():
            ref = reference(self.run_root, slot)
            value = verify_receipt(self.run_root, ref)
            if value["mode"] == "computed":
                self.computed(namespace, fingerprint, value["object"], computation=value["computation"],
                              dependencies=tuple(value["dependencies"]), layout=value.get("layout"))
            return value, ref
        directory = safe_path(self.run_root, f"{REQUESTS}/{namespace}/{_hash(fingerprint)}")
        if not directory.exists():
            return None
        candidates = []
        for path in sorted(directory.iterdir()):
            candidate = verify_request(self.run_root, reference(self.run_root, path))
            value = verify_receipt(self.run_root, candidate)
            candidates.append((candidate, value))
        if not candidates:
            return None
        # Stable among the complete candidates visible to this lookup. Once selected, the
        # attempt's receipt never changes when later computations publish another result.
        producer, value = candidates[0]
        return self._record(namespace, fingerprint, value["object"], computation=value["computation"],
                            dependencies=tuple(value["dependencies"]), mode="reused", producer=producer,
                            layout=value.get("layout"))

    def named(self, namespace: str, path: Path, *, computed: bool,
              computation: Mapping[str, Any] | None = None,
              expected_sha256: str | None = None) -> dict[str, Any]:
        """Record an explicitly registered immutable layout without copying its bytes."""
        obj = reference(self.run_root, path, expected_sha256=expected_sha256)
        if namespace not in NAMED_LAYOUTS or not obj["path"].startswith(NAMED_LAYOUTS[namespace]):
            raise ValueError("unregistered named immutable publication")
        fingerprint = hashlib.sha256(canonical_json(
            {"namespace": namespace, "path": obj["path"], "sha256": obj["sha256"]})).hexdigest()
        if computed:
            content = _link(self.run_root, path, f"{OBJECTS}/{obj['sha256']}", obj["sha256"])
            immutable_bytes(self.run_root, _binding_path(namespace, obj), canonical_json({
                "schema": "appsec-review/shared-named/1", "namespace": namespace, "object": obj}))
            return self.computed(namespace, fingerprint, obj, computation=computation or {},
                                 dependencies=(content,), layout="named-immutable")
        binding = safe_path(self.run_root, _binding_path(namespace, obj))
        if binding.exists():
            if verify_binding(self.run_root, reference(self.run_root, binding))["object"] != obj:
                raise ValueError("named immutable object changed after publication")
        hit = self.lookup(namespace, fingerprint)
        if hit is not None:
            return hit[1]
        if binding.exists():
            raise ValueError("named immutable publication has no complete producer receipt")
        return self.legacy(namespace, fingerprint, obj, computation=computation or {})[1]

    def legacy(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
               computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = ()
               ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self._record(namespace, fingerprint, obj, computation=computation, dependencies=dependencies,
                            mode="reused", legacy="unknown-original-producer")

    def consume_receipt(self, source: Mapping[str, Any]) -> dict[str, Any]:
        value = verify_receipt(self.run_root, source)
        if value.get("layout") == "public-feed":
            from .feed_provenance import consume_pin
            proof = _read(self.run_root, value["object"])
            from .feed_provenance import _configured_root
            root, _ = _configured_root(self.run_root, _read(self.run_root, self.actor["claim"]),
                                       proof["feed_id"])
            with publication_scope_for_owner(self):
                consumed = consume_pin(self.run_root, {
                    "feed_id": proof["feed_id"],
                    "snapshot_id": Path(proof["manifest"]["path"]).parent.name,
                    "manifest_sha256": proof["manifest"]["sha256"],
                    "directory": str(root / Path(proof["manifest"]["path"]).parent),
                    "provenance": source})
            if consumed is None:
                raise ValueError("claimed feed consumer did not record its use")
            return consumed
        while value["producer_receipt"] is not None:
            source = value["producer_receipt"]
            value = verify_receipt(self.run_root, source)
        if value["actor"] == self.actor:
            return dict(source)
        fingerprint = hashlib.sha256(canonical_json(source)).hexdigest()
        return self._record("shared-input", fingerprint, value["object"],
                            computation=value["computation"], dependencies=tuple(value["dependencies"]),
                            mode="reused", producer=source, legacy=value["legacy"])[1]


def verify_request(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    request = _read(root, ref)
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("invalid shared request schema")
    receipt = request["receipt"]
    value = verify_receipt(root, receipt)
    expected = f"{REQUESTS}/{value['namespace']}/{value['fingerprint']}/{receipt['sha256']}.json"
    if ref["path"] != expected or value["mode"] != "computed":
        raise ValueError("shared request does not identify a producing receipt")
    return receipt


@validation_operation
def attempt_artifacts(root: Path, attempt_root: Path) -> list[dict[str, Any]]:
    """Verify and return the complete receipt closure for handoff/resume integrity."""
    artifacts: dict[str, dict[str, Any]] = {}

    def collect(ref: Mapping[str, Any]) -> None:
        value = verify_receipt(root, ref)
        for artifact in (ref, value["actor"]["claim"], value["object"], *value["dependencies"]):
            artifacts[artifact["path"]] = dict(artifact)
        if value.get("layout") == "named-immutable":
            binding = reference(root, safe_path(root, _binding_path(value["namespace"], value["object"])))
            artifacts[binding["path"]] = binding
        if value["producer_receipt"]:
            collect(value["producer_receipt"])

    directory = attempt_root / "shared"
    if directory.exists() or directory.is_symlink():
        safe_path(root, directory.relative_to(root).as_posix())
        for namespace in sorted(directory.iterdir()):
            safe_path(root, namespace.relative_to(root).as_posix())
            if not namespace.is_dir() or not _NAME.fullmatch(namespace.name):
                raise ValueError("invalid shared receipt directory")
            for path in sorted(namespace.iterdir()):
                collect(reference(root, path))
    return list(artifacts.values())


@validation_operation
def verify_handoff(root: Path, handoff: Mapping[str, Any]) -> None:
    from .admission import consume_admission
    if consume_admission(root, handoff):
        return
    attempt = safe_path(root, handoff["resolving_paths"]["attempt"])
    pinned = {item["path"]: item["sha256"] for item in handoff["artifacts"]}
    for artifact in handoff["artifacts"]:
        if artifact["path"].startswith(OBJECTS + "/"):
            verify_reference(root, artifact)
        elif re.fullmatch(r"data/jobs/[^/]+/attempts/[^/]+/shared/[^/]+/[^/]+\.json", artifact["path"]):
            verify_receipt(root, artifact)
    for artifact in attempt_artifacts(root, attempt):
        if pinned.get(artifact["path"]) != artifact["sha256"]:
            raise ValueError(f"shared provenance missing from handoff: {artifact['path']}")


def consume_handoff(root: Path, handoff: Mapping[str, Any]) -> None:
    owner = current()
    if owner is not None:
        if owner.run_root != root:
            raise ValueError("shared input handoff belongs to another run")
        for artifact in handoff["artifacts"]:
            if re.fullmatch(r"data/jobs/[^/]+/attempts/[^/]+/shared/[^/]+/[^/]+\.json", artifact["path"]):
                owner.consume_receipt(artifact)


def audit_file(root: Path, relative: str) -> None:
    """Validate registered shared files; declaration never substitutes for integrity."""
    ref = reference(root, safe_path(root, relative))
    if relative.startswith(OBJECTS + "/"):
        if relative != f"{OBJECTS}/{_hash(Path(relative).name)}" or ref["sha256"] != Path(relative).name:
            raise ValueError("shared object exact-byte identity mismatch")
    elif relative.startswith(REQUESTS + "/"):
        verify_request(root, ref)
    elif relative.startswith(NAMED + "/"):
        verify_binding(root, ref)
    elif re.fullmatch(r"data/jobs/[^/]+/attempts/[^/]+/shared/[^/]+/[^/]+\.json", relative):
        verify_receipt(root, ref)
    else:
        raise ValueError("undeclared shared artifact")


def current() -> SharedArtifacts | None:
    return _ACTIVE.get()


class PublicationThreadPoolExecutor(ThreadPoolExecutor):
    """Preserve the invoking attempt across explicitly parallel producer tasks."""

    def submit(self, fn, /, *args, **kwargs):
        return super().submit(copy_context().run, fn, *args, **kwargs)


@contextmanager
def publication_scope(context: JobContext):
    """Bind provenance only for the explicit immutable writers using this module."""
    from appsec_review.runtime.scope import review_scope
    from appsec_review.runtime.resources import review_resource_scope
    from appsec_review.container_runtime.image_builder import image_builder_scope
    from appsec_review.container_runtime.native_client import native_engine_scope
    with review_resource_scope(context.metadata_root, context.review_policy.resources, context.events), \
            image_builder_scope(context), \
            native_engine_scope(context), \
            review_scope(context.repository_root, context.run_root, context.target_root), validation_scope(
            context.run_root, target_snapshot=getattr(context, "evidence_target_snapshot", None) or context.source_fingerprint,
            policy_identity=hashlib.sha256(canonical_json(context.review_policy.view())).hexdigest()), \
            publication_scope_for_owner(SharedArtifacts.for_job(context)):
        yield


@contextmanager
def publication_scope_for_owner(owner: SharedArtifacts):
    token = _ACTIVE.set(owner)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def publish_named(root: Path, path: Path, payload: bytes, *, namespace: str,
                  computation: Mapping[str, Any] | None = None,
                  shared: SharedArtifacts | None = None) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    safe_path(root, relative)
    if namespace not in NAMED_LAYOUTS:
        raise ValueError("unregistered named immutable publication")
    owner = shared or current()
    if owner is not None:
        if owner.run_root != root or not relative.startswith(NAMED_LAYOUTS[namespace]):
            raise ValueError("immutable publication belongs to another run")
        content = put_bytes(root, payload)
        obj = _link(root, verify_reference(root, content), relative, content["sha256"])
        owner.named(namespace, path, computed=True, computation=computation)
    else:
        obj = immutable_bytes(root, relative, payload)
    return obj


def consume_named(root: Path, path: Path, *, namespace: str,
                  shared: SharedArtifacts | None = None,
                  expected_sha256: str | None = None) -> None:
    owner = shared or current()
    if namespace not in NAMED_LAYOUTS:
        raise ValueError("unregistered named immutable consumption")
    safe_path(root, path.relative_to(root).as_posix())
    obj = reference(root, path, expected_sha256=expected_sha256)
    binding = safe_path(root, _binding_path(namespace, obj))
    if binding.exists():
        if verify_binding(root, reference(root, binding))["object"] != obj:
            raise ValueError("named immutable object changed after publication")
        fingerprint = hashlib.sha256(canonical_json(
            {"namespace": namespace, "path": obj["path"], "sha256": obj["sha256"]})).hexdigest()
        candidates = safe_path(root, f"{REQUESTS}/{namespace}/{fingerprint}")
        if owner is None:
            paths = sorted(candidates.iterdir()) if candidates.exists() else []
            if not paths:
                raise ValueError("named immutable publication has no complete producer receipt")
            for candidate in paths:
                verify_request(root, reference(root, candidate))
    if owner is not None:
        if owner.run_root != root:
            raise ValueError("immutable consumption belongs to another run")
        owner.named(namespace, path, computed=False, expected_sha256=obj["sha256"])
