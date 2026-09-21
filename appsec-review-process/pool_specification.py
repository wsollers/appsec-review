#!/usr/bin/env python3
"""Pool specification and deterministic instance expansion (backlog batch C01).

``appsec-review/pool-specification/1.0`` is one pool job as a recorded configuration: lane, worker
groups (worker kind, persona composition or registered tool image, count, scope, inputs, budget,
permission block, timeout), a pool-level budget, the resource-pool policy and ``wait_all``.
``appsec-review/pool-expansion/1.0`` is what one specification expands into: the ordered list of
every expected instance, each with a deterministic id, a private run-owned attempt root, the exact
B13 ``pinned-container-request`` or B14 ``persona-invocation-request`` it will be handed, its
derived resource pool and its input fingerprint.

Specification and expansion ONLY. Nothing here launches, waits, merges or talks to Dagster; that
is C02 and T10. What this module guarantees to them:

* :func:`plan_expansion` is THE rule for "is this specification expandable, and into what". The
  expander and the verifier both call it, so they cannot drift. It creates nothing.
* Every instance request already passes its own adapter's validators for that instance's ids
  (``container_execution.request_errors`` + ``request_mount_sources``,
  ``persona_invocation.resolve_request``), evaluated with ``context.pool_parent`` as the privacy
  boundary: nothing that is, contains, or lies beneath the pool parent is a mount or a readable
  input. Every pool root, instance root, request file and manifest lives beneath it.
* The manifest carries no timestamp and no host path. One specification derives one byte sequence.
* A pool with zero instances is a recorded state (``EMPTY`` plus a closed reason), not an error
  and not a success.
* No value read from a specification or from disk is echoed into a message.

See ``docs/pool-specification.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import container_execution as ce  # noqa: E402
from execution_state import atomic_bytes, beneath  # noqa: E402
import permission_capabilities as pc  # noqa: E402
import persona_invocation as pi  # noqa: E402
import resource_pools as rp  # noqa: E402
from schema_validate import SchemaStore, validate_document  # noqa: E402

SPEC_ID = "appsec-review/pool-specification/1.0"
EXPANSION_ID = "appsec-review/pool-expansion/1.0"
ID_DERIVATION_ID = "appsec-review/pool-instance-id/1.0"
FINGERPRINT_ID = "appsec-review/pool-instance-fingerprint/1.0"

SPEC_SCHEMA = "pool-specification.schema.json"
GROUP_SCHEMA = "pool-worker-group.schema.json"
EXPANSION_SCHEMA = "pool-expansion.schema.json"
INSTANCE_SCHEMA = "pool-expansion-instance.schema.json"

SPEC_FILE = "specification.json"
EXPANSION_FILE = "expansion.json"
REQUESTS_DIR = "requests"
INSTANCES_DIR = "instances"
POOL_ROOT_ENTRIES = (EXPANSION_FILE, INSTANCES_DIR, REQUESTS_DIR, SPEC_FILE)

PERSONA = pi.WORKER_KIND
PINNED_CONTAINER = ce.WORKER_KIND
WORKER_KINDS = (PERSONA, PINNED_CONTAINER)
# The part of each adapter request a specification may state. Everything else is assigned here.
PERSONA_TEMPLATE_FIELDS = ("invocation_role", "invoker_id", "outer_prompt", "persona", "model", "tools",
                           "budget", "readable_inputs", "allowed_claim_classes", "prohibited_claim_classes",
                           "producers")
TOOL_TEMPLATE_FIELDS = ("image", "argv", "environment", "target_mounts", "network", "limits")
# Writable paths inside an instance root are constants: a specification cannot choose them.
TOOL_SCRATCH_PATH = "scratch"
TOOL_LOG_PATH = "logs/container"
PERSONA_OUTPUT_ROOT = "outputs/persona"
PERSONA_LOG_PATH = "logs/persona"

EMPTY = "EMPTY"
POPULATED = "POPULATED"
EMPTY_POOL_REASONS = ("no_applicable_work", "scope_excluded", "upstream_produced_no_work")
BUDGET_CLASSES = tuple(rp.PERSONA_BUDGET_CELLS)

MAX_GROUPS = 32
MAX_GROUP_COUNT = 32
MAX_INSTANCES = 64
MAX_TOTAL_TIMEOUT_SECONDS = 7 * 86_400
POOL_BUDGET_BOUNDS: Mapping[str, tuple[int, int]] = {
    "max_instances": (0, MAX_INSTANCES),
    "max_persona_input_units": (0, MAX_INSTANCES * pi.BUDGET_BOUNDS["input_unit_limit"][1]),
    "max_persona_output_units": (0, MAX_INSTANCES * pi.BUDGET_BOUNDS["output_unit_limit"][1]),
    "max_total_timeout_seconds": (0, MAX_TOTAL_TIMEOUT_SECONDS),
}
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024

# Hex digits of the instance-id digest. 32 digits are 128 bits. A collision is still checked for,
# and fails closed; the tests shrink this to force one.
ID_HEX_CHARS = 32

_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")
_SCHEMA_PATH_RE = re.compile(r"\$[A-Za-z0-9_.\[\]]{0,200}\Z")

freeze = pi.freeze
thaw = pi.thaw


class PoolSpecError(ValueError):
    """The specification, the context or a path is unacceptable. Raised before anything is
    created. Messages name positions and rules only; they never quote a specification value."""


class PoolExpansionError(RuntimeError):
    """The expander could not create or prove its own pool root. Never a success: a pool root
    without a verified ``expansion.json`` is not an expansion."""


@dataclass(frozen=True)
class PoolContext:
    """Trusted, integrator-supplied side of one expansion or verification. Every field is
    required; there is no default anywhere.

    ``pool_parent`` is a run-owned directory dedicated to expansions of this pool job. It is the
    privacy boundary: no instance may mount or read anything that is, contains or lies beneath it.
    ``mount_roots`` are the declared directories a tool target mount must lie in. The remaining
    fields are the B14, B13 and B11 facts the adapters themselves will be given at launch.
    """
    pool_parent: Path
    registry_dir: Path
    prompt_root: Path
    readable_roots: Mapping[str, Path]
    allowed_models: tuple
    invoker_id: str | None
    images_dir: Path
    host_flavor: str
    docker_host: str | None
    mount_roots: tuple
    source_snapshot_sha256: str
    registry_ceiling: list | None


@dataclass(frozen=True)
class InstanceRequest:
    instance_id: str
    worker_kind: str
    relative_path: str
    request: Mapping[str, Any]
    data: bytes


@dataclass(frozen=True)
class ExpansionPlan:
    """The whole expansion of one specification, derived without touching the pool root."""
    specification: Mapping[str, Any]
    spec_sha256: str
    specification_bytes: bytes
    pool_directory: str
    manifest: Mapping[str, Any]
    manifest_bytes: bytes
    requests: tuple


# ---- small helpers -------------------------------------------------------------------------------

def _sha(value: Any) -> str:
    return "sha256:" + pc.digest(value)


def _bytes_sha(data: bytes) -> str:
    return pi._bytes_sha(data)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_bytes(document: Any) -> bytes:
    """The one byte form of every JSON document this module writes; the adapters' own form."""
    return pi.canonical_bytes(document)


def _unique_object(pairs: list) -> dict:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("repeated key")
    return dict(pairs)


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def parse_document(data: Any) -> dict:
    """Bytes -> JSON object, for any document this process did not just write. Bounded, UTF-8, no
    NaN/Infinity, and no object that repeats a key: a repeated key has two readings, and the one
    a parser drops is text no check ever saw."""
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_DOCUMENT_BYTES:
        raise PoolSpecError("document is not a bounded byte string")
    try:
        value = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise PoolSpecError("document is not UTF-8 JSON with exactly one reading") from None
    if not isinstance(value, dict):
        raise PoolSpecError("document is not a JSON object")
    return value


def _schema_locations(errors: list) -> str:
    """Schema messages quote values; their ``$.a.b[0]`` prefix is built from declared property
    names and indices only, so that prefix (and nothing else) is safe to report."""
    places = sorted({error.split(":", 1)[0] for error in errors})
    safe = [place for place in places if _SCHEMA_PATH_RE.match(place)]
    return f"{len(errors)} errors at " + ", ".join(safe[:8]) if safe else f"{len(errors)} errors"


def _identity(path: Path) -> tuple | None:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return (status.st_dev, status.st_ino)


def _chain(path: Path) -> set:
    """Identities of a path and every existing ancestor."""
    found = set()
    for part in [path, *path.parents]:
        identity = _identity(part)
        if identity is not None:
            found.add(identity)
    return found


def _real_directory(path: Any) -> bool:
    if not isinstance(path, Path) or not path.is_absolute():
        return False
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(status.st_mode)


# ---- identity ------------------------------------------------------------------------------------

def spec_sha256(spec: Any) -> str:
    return _sha(thaw(spec))


def pool_directory(spec_digest: str) -> str:
    """Name of the pool root beneath ``context.pool_parent``: a pure function of the specification."""
    return pc.digest([EXPANSION_ID, spec_digest])[:32]


def instance_id(spec_digest: str, group_id: str, ordinal: int) -> str:
    """``appsec-review/pool-instance-id/1.0``. A pure function of the specification hash (which
    covers run, job, attempt, pool id and every group), the group id and the ordinal inside the
    group. No host fact, no clock, no iteration order.

    The id is bare hex of a digest length on purpose. The V06 redactor treats ``prefix-<32 hex>``
    as a high-entropy secret, in file content and in a published path alike, and exempts a bare
    digest-length hex run; a prefixed id would not survive publication."""
    return pc.digest([ID_DERIVATION_ID, spec_digest, group_id, ordinal])[:ID_HEX_CHARS]


# ---- context -------------------------------------------------------------------------------------

def validate_context(context: Any) -> None:
    if not isinstance(context, PoolContext):
        raise TypeError("pool expansion requires a PoolContext")
    parent = context.pool_parent
    if not _real_directory(parent) or os.path.realpath(parent) != str(parent):
        raise PoolSpecError("context.pool_parent must be an absolute, existing, non-link directory in its "
                            "one real spelling")
    for ancestor in (parent, *parent.parents):
        # A pool root is private to its instances: a second pool created beneath one would sit
        # inside an instance's root (or beside the manifest) and change that attempt under it.
        if any(os.path.lexists(ancestor / name) for name in (EXPANSION_FILE, SPEC_FILE)):
            raise PoolSpecError("context.pool_parent lies inside another pool root")
    for name in ("registry_dir", "prompt_root", "images_dir"):
        if not isinstance(getattr(context, name), Path):
            raise PoolSpecError(f"context.{name} must be a path")
    roots = context.readable_roots
    if not isinstance(roots, Mapping) or not all(
            isinstance(key, str) and isinstance(value, Path) for key, value in roots.items()):
        raise PoolSpecError("context.readable_roots must map root ids to paths")
    if not isinstance(context.allowed_models, tuple):
        raise PoolSpecError("context.allowed_models must be a tuple; there is no default model")
    if context.invoker_id is not None and (
            not isinstance(context.invoker_id, str) or not _REG_RE.match(context.invoker_id)):
        raise PoolSpecError("context.invoker_id must be null or a registry-style invoker id")
    if context.host_flavor not in ("posix", "windows"):
        raise PoolSpecError("context.host_flavor must be 'posix' or 'windows'")
    if context.docker_host is not None and not isinstance(context.docker_host, str):
        raise PoolSpecError("context.docker_host must be null or one docker endpoint URL")
    if not isinstance(context.mount_roots, tuple) or not all(_real_directory(path) for path in context.mount_roots):
        raise PoolSpecError("context.mount_roots must be a tuple of absolute, existing, non-link directories")
    if not isinstance(context.source_snapshot_sha256, str) or not _SHA_RE.match(context.source_snapshot_sha256):
        raise PoolSpecError("context.source_snapshot_sha256 must be sha256:<64 hex>")
    if context.registry_ceiling is not None and not isinstance(context.registry_ceiling, list):
        raise PoolSpecError("context.registry_ceiling must be null or a list")


# ---- specification (pure) ------------------------------------------------------------------------

def spec_errors(spec: Any, store: SchemaStore | None = None) -> list:
    """Closed schema first, then every bound the schema subset cannot express. Pure: no disk, no
    registry, no context. :func:`plan_expansion` applies the rest."""
    if not isinstance(spec, Mapping):
        return ["specification is not an object"]
    spec = thaw(spec)
    if spec.get("wait_all") is not True:
        # `const: true` in the schema subset also admits the number 1; this does not.
        return ["wait_all must be the JSON value true: a pool that does not wait for every expected "
                "instance is not expressible in pool-specification 1.0"]
    groups = spec.get("worker_groups")
    if isinstance(groups, list):
        bad = [f"worker_groups[{index}].count must be an integer within 0..{MAX_GROUP_COUNT}"
               for index, group in enumerate(groups)
               if isinstance(group, dict) and (not _is_int(group.get("count"))
                                               or not 0 <= group["count"] <= MAX_GROUP_COUNT)]
        if bad:
            return bad
    schema_errors = validate_document(spec, SPEC_SCHEMA, store or SchemaStore())
    if schema_errors:
        return ["specification fails its closed schema (" + _schema_locations(schema_errors) + ")"]
    errors: list = []
    if len(groups) > MAX_GROUPS:
        errors.append(f"more than {MAX_GROUPS} worker groups")
    ids = [group["group_id"] for group in groups]
    if ids != sorted(set(ids)):
        errors.append("worker_groups must be sorted by group_id, and a group_id may appear once")
    for index, group in enumerate(groups):
        label = f"worker_groups[{index}]"
        wanted, other = (("persona_request", "tool_request") if group["worker_kind"] == PERSONA
                         else ("tool_request", "persona_request"))
        if group[wanted] is None or group[other] is not None:
            errors.append(f"{label}: exactly the request template of its worker kind must be present; "
                          "the other must be null")
        if group["permission"]["requirement"]["job_id"] != spec["job_id"]:
            errors.append(f"{label}.permission.requirement is declared for a different job than the pool's")
        decision = group["permission"]["decision"]
        if decision["run_id"] != spec["run_id"] or decision["job_id"] != spec["job_id"]:
            errors.append(f"{label}.permission.decision is bound to a different run or job than the pool's")
    total = sum(group["count"] for group in groups)
    if total > MAX_INSTANCES:
        errors.append(f"more than {MAX_INSTANCES} instances")
    for name, (low, high) in POOL_BUDGET_BOUNDS.items():
        if not low <= spec["pool_budget"][name] <= high:
            errors.append(f"pool_budget.{name} must be an integer within {low}..{high}")
    if total > spec["pool_budget"]["max_instances"]:
        errors.append("the groups expand to more instances than pool_budget.max_instances")
    if not 1 <= spec["rendezvous_timeout_seconds"] <= MAX_TOTAL_TIMEOUT_SECONDS:
        errors.append(f"rendezvous_timeout_seconds must be an integer within 1..{MAX_TOTAL_TIMEOUT_SECONDS}")
    if (total == 0) != (spec["empty_pool_reason"] is not None):
        errors.append("empty_pool_reason is required exactly when the pool expands to zero instances: an "
                      "empty pool is a recorded state with a reason, and a populated pool has none")
    allowed = spec["resource_pool_policy"]["allowed_pools"]
    if allowed != sorted(set(allowed)) or not set(allowed) <= set(rp.POOL_IDS):
        errors.append("resource_pool_policy.allowed_pools must be sorted, unique resource_pools pool ids")
    return errors


def _permission_errors(permission: Mapping[str, Any], *, run_id: str, job_id: str,
                       context: PoolContext, label: str) -> list:
    """A persisted decision is a cache. It must be exactly what its own requirement and grants
    derive, for this run, this job and the context's source snapshot, at its own ``evaluated_at``;
    and it must be GRANTED, because only a GRANTED decision has an input fingerprint (B11)."""
    decision = permission["decision"]
    if pc.validate_decision(decision):
        return [f"{label}.decision is not a self-consistent permission decision"]
    try:
        fresh = pc.evaluate(thaw(permission["requirement"]), thaw(permission["grants"]), {
            "run_id": run_id, "job_id": job_id, "source_snapshot_sha256": context.source_snapshot_sha256,
            "now": decision["evaluated_at"], "registry_ceiling": context.registry_ceiling})
    except pc.PermissionModelError:
        return [f"{label}: the permission model refuses this run, job or evaluation instant"]
    if fresh != decision:
        return [f"{label}.decision is not the decision its requirement and grants derive for this run, job "
                "and source snapshot at its own evaluated_at"]
    if decision["decision"] != pc.GRANTED:
        return [f"{label}.decision is not GRANTED: a denied worker has no input fingerprint and is not expandable"]
    return []


def _build_request(spec: Mapping[str, Any], group: Mapping[str, Any], attempt_id: str) -> dict:
    ids = {"run_id": spec["run_id"], "job_id": spec["job_id"], "attempt_id": attempt_id}
    if group["worker_kind"] == PERSONA:
        template = group["persona_request"]
        return {"schema": pi.REQUEST_ID, **ids,
                **{name: thaw(template[name]) for name in PERSONA_TEMPLATE_FIELDS},
                "output_root": PERSONA_OUTPUT_ROOT, "log_path": PERSONA_LOG_PATH,
                "permission": thaw(group["permission"]),
                "permission_fingerprint_sha256": group["permission"]["decision"]["fingerprint_material"]["sha256"]}
    template = group["tool_request"]
    return {"schema": ce.REQUEST_ID, **ids,
            **{name: thaw(template[name]) for name in TOOL_TEMPLATE_FIELDS},
            "scratch_path": TOOL_SCRATCH_PATH, "log_path": TOOL_LOG_PATH,
            "permission": thaw(group["permission"])}


def _tool_instance(request: dict, *, ids: Mapping[str, str], granted: list, registry: Mapping[str, Any],
                   mount_roots: set, context: PoolContext, label: str) -> tuple:
    """The B13 adapter's own rules for this instance, then the pool's. Returns (fingerprint
    material, identity, timeout)."""
    errors = ce.request_errors(request, **ids)
    if errors:
        raise PoolSpecError(f"{label}: the pinned-container adapter refuses this request: " + "; ".join(errors))
    try:
        record = ce.resolve_image(request["image"], registry)
    except ce.ContainerRequestError as exc:
        raise PoolSpecError(f"{label}: {exc}") from None
    allowed = {(c["parameters"]["scheme"], c["parameters"]["host"], c["parameters"]["port"])
               for c in granted if c["kind"] == "fixed-network-destination"}
    if any((d["scheme"], d["host"], d["port"]) not in allowed for d in request["network"]["destinations"]):
        raise PoolSpecError(f"{label}: a network destination is not in the capability set its decision grants")
    try:
        # The adapter's ONE mount rule, with the pool parent where the attempt root will be: a mount
        # may not be, contain or lie beneath it -- so not the pool root, not the manifest, not a
        # request file and not any instance's root, this pool's or a sibling pool's.
        ce.request_mount_sources(request, attempt_root=context.pool_parent, host_flavor=context.host_flavor,
                                 docker_host=context.docker_host)
    except ce.ContainerRequestError as exc:
        raise PoolSpecError(f"{label}: the pinned-container mount rule, applied at the pool parent, refuses "
                            f"this scope: {exc}") from None
    for index, mount in enumerate(request["target_mounts"]):
        if not _chain(Path(mount["host_path"])) & mount_roots:
            raise PoolSpecError(f"{label}: target_mounts[{index}] is outside every declared mount root")
    identity = {"worker_kind": PINNED_CONTAINER, "image_reference": ce.image_reference(record),
                "image_record_sha256": _sha(record)}
    return ce.fingerprint_material(request, record), identity, request["limits"]["timeout_seconds"]


def _persona_instance(request: dict, *, ids: Mapping[str, str], context: PoolContext, label: str) -> tuple:
    if context.invoker_id is None or request["invoker_id"] != context.invoker_id:
        raise PoolSpecError(f"{label}: invoker_id is not the invoker this context will launch")
    try:
        # The adapter's ONE resolver, with the pool parent where the attempt root will be: the
        # prompt and every readable input are read, hashed and refused if they lie beneath it.
        resolved = pi.resolve_request(
            request, **ids, attempt_root=context.pool_parent, registry_dir=context.registry_dir,
            prompt_root=context.prompt_root, readable_roots=context.readable_roots,
            allowed_models=context.allowed_models)
    except pi.PersonaRequestError as exc:
        raise PoolSpecError(f"{label}: the persona invocation adapter, resolving at the pool parent, refuses "
                            f"this request: {exc}") from None
    identity = {"worker_kind": PERSONA, "persona": thaw(request["persona"]), "model": thaw(request["model"]),
                "invoker_id": request["invoker_id"], "invocation_role": request["invocation_role"]}
    return pi.fingerprint_material(resolved), identity, request["budget"]["timeout_seconds"]


def plan_expansion(spec: Any, *, context: PoolContext) -> ExpansionPlan:
    """THE rule: whether a specification is expandable, and the exact expansion it derives.

    Shared by :func:`expand_pool` and :func:`verify_expansion`. Reads the registries, the prompt
    and the pinned inputs; creates nothing. Raises :class:`PoolSpecError` with fixed text."""
    validate_context(context)
    try:
        spec = json.loads(json.dumps(thaw(spec), allow_nan=False))
    except (TypeError, ValueError):
        raise PoolSpecError("specification is not a JSON document") from None
    errors = spec_errors(spec)
    if errors:
        raise PoolSpecError("pool specification rejected: " + "; ".join(errors))
    digest = spec_sha256(spec)
    slots = rp.persona_slot_request(spec["budget_class"])
    allowed_pools = set(spec["resource_pool_policy"]["allowed_pools"])
    mount_roots = {identity for identity in (_identity(path) for path in context.mount_roots) if identity}
    registry = None
    groups, instances, requests = [], [], []
    for index, group in enumerate(spec["worker_groups"]):
        label = f"worker_groups[{index}]"
        kind = group["worker_kind"]
        errors = _permission_errors(group["permission"], run_id=spec["run_id"], job_id=spec["job_id"],
                                    context=context, label=label + ".permission")
        if errors:
            raise PoolSpecError("pool specification rejected: " + "; ".join(errors))
        decision = group["permission"]["decision"]
        granted_kinds = sorted({capability["kind"] for capability in decision["capabilities"]})
        try:
            pool = rp.derive_pool(kind, granted_kinds, memory_heavy=group["memory_heavy"])
        except rp.PoolAssignmentError:
            raise PoolSpecError(f"{label}: no resource pool can be derived for this worker kind and its "
                                "granted permission kinds") from None
        if pool not in allowed_pools:
            raise PoolSpecError(f"{label}: derives a resource pool outside resource_pool_policy.allowed_pools")
        if kind == PINNED_CONTAINER and registry is None:
            try:
                registry = ce.load_image_registry(context.images_dir)
            except ce.ContainerRequestError:
                raise PoolSpecError("context.images_dir is not a valid container image registry") from None
        identity: dict | None = None
        members = []
        for ordinal in range(group["count"]):
            name = instance_id(digest, group["group_id"], ordinal)
            where = f"{label} instance {ordinal}"
            ids = {"run_id": spec["run_id"], "job_id": spec["job_id"], "attempt_id": name}
            request = _build_request(spec, group, name)
            if kind == PERSONA:
                material, identity, timeout = _persona_instance(request, ids=ids, context=context, label=where)
                writable = sorted((PERSONA_LOG_PATH, PERSONA_OUTPUT_ROOT))
            else:
                material, identity, timeout = _tool_instance(
                    request, ids=ids, granted=decision["capabilities"], registry=registry,
                    mount_roots=mount_roots, context=context, label=where)
                writable = sorted((TOOL_LOG_PATH, TOOL_SCRATCH_PATH))
            data = canonical_bytes(request)
            relative = f"{REQUESTS_DIR}/{name}.json"
            fingerprint = {"schema": FINGERPRINT_ID, "spec_sha256": digest, "instance_id": name,
                           "group_id": group["group_id"], "ordinal": ordinal, "worker_kind": kind,
                           "resource_pool": pool, "adapter_fingerprint": material}
            instances.append({
                "instance_id": name, "group_id": group["group_id"], "ordinal": ordinal, "worker_kind": kind,
                **ids, "attempt_root": f"{INSTANCES_DIR}/{name}",
                "request_schema": request["schema"],
                "request_file": {"path": relative, "sha256": _bytes_sha(data), "bytes": len(data)},
                "request_sha256": _sha(request), "writable_paths": writable,
                "log_path": PERSONA_LOG_PATH if kind == PERSONA else TOOL_LOG_PATH,
                "resource_pool": pool, "granted_permission_kinds": granted_kinds,
                "memory_heavy": group["memory_heavy"],
                "persona_slot_request": slots if kind == PERSONA else None,
                "timeout_seconds": timeout,
                "permission_fingerprint_sha256": material["permission_fingerprint_sha256"],
                "adapter_fingerprint_sha256": material["sha256"],
                "input_fingerprint": _sha(fingerprint)})
            requests.append(InstanceRequest(name, kind, relative, freeze(request), data))
            members.append(name)
        if identity is None:       # a group of zero instances is still a recorded, typed group
            identity = {"worker_kind": kind, "template_sha256": _sha(
                group["persona_request"] if kind == PERSONA else group["tool_request"])}
        groups.append({"group_id": group["group_id"], "worker_kind": kind, "count": group["count"],
                       "identity_sha256": _sha(identity), "instance_ids": members})
    _collision_errors(instances)
    totals = _totals(spec, instances, slots)
    specification_bytes = canonical_bytes(spec)
    manifest = {
        "schema": EXPANSION_ID, "specification": SPEC_ID, "spec_sha256": digest,
        "specification_file": {"path": SPEC_FILE, "sha256": _bytes_sha(specification_bytes),
                               "bytes": len(specification_bytes)},
        "id_derivation": ID_DERIVATION_ID, "pool_directory": pool_directory(digest),
        **{name: spec[name] for name in ("pool_id", "lane", "run_id", "job_id", "attempt_id", "budget_class",
                                         "wait_all", "rendezvous_timeout_seconds")},
        "state": POPULATED if instances else EMPTY, "empty_pool_reason": spec["empty_pool_reason"],
        "groups": groups, "instances": instances, "totals": totals,
    }
    manifest["expansion_sha256"] = expansion_sha256(manifest)
    schema_errors = validate_document(manifest, EXPANSION_SCHEMA)
    if schema_errors:
        raise PoolSpecError("the derived expansion is outside its own closed schema ("
                            + _schema_locations(schema_errors) + ")")
    return ExpansionPlan(specification=freeze(spec), spec_sha256=digest, specification_bytes=specification_bytes,
                         pool_directory=manifest["pool_directory"], manifest=freeze(manifest),
                         manifest_bytes=canonical_bytes(manifest), requests=tuple(requests))


def _collision_errors(instances: list) -> None:
    """No two instances may share an id, an attempt root, a request file, a container name or a
    writable path, compared case-insensitively. Fails closed; there is no re-roll."""
    for label, values in (
            ("instance id", [entry["instance_id"] for entry in instances]),
            ("attempt root", [entry["attempt_root"] for entry in instances]),
            ("request file", [entry["request_file"]["path"] for entry in instances]),
            # Derived, not recorded: `appsec-<hex>` does not survive the V06 redactor in a manifest.
            ("container name", [ce.container_name(entry["run_id"], entry["job_id"], entry["attempt_id"])
                                for entry in instances if entry["worker_kind"] == PINNED_CONTAINER]),
            ("writable path", [f"{entry['attempt_root']}/{path}" for entry in instances
                               for path in entry["writable_paths"]])):
        folded = [value.lower() for value in values]
        if len(folded) != len(set(folded)):
            raise PoolSpecError(f"two instances derive one {label}: the expansion fails closed")


def _totals(spec: Mapping[str, Any], instances: list, slots: int) -> dict:
    personas = [entry for entry in instances if entry["worker_kind"] == PERSONA]
    budgets = {group["group_id"]: group["persona_request"]["budget"] for group in spec["worker_groups"]
               if group["worker_kind"] == PERSONA}
    timeouts = [entry["timeout_seconds"] for entry in instances]
    pools: dict = {}
    for entry in instances:
        pools[entry["resource_pool"]] = pools.get(entry["resource_pool"], 0) + 1
    totals = {
        "instances": len(instances), "persona_instances": len(personas),
        "pinned_container_instances": len(instances) - len(personas),
        "persona_slot_request": slots,
        "persona_input_units": sum(budgets[entry["group_id"]]["input_unit_limit"] for entry in personas),
        "persona_output_units": sum(budgets[entry["group_id"]]["output_unit_limit"] for entry in personas),
        "timeout_seconds_sum": sum(timeouts), "timeout_seconds_max": max(timeouts, default=0),
        "resource_pools": [{"resource_pool": pool, "instances": pools[pool]} for pool in sorted(pools)],
    }
    budget = spec["pool_budget"]
    for total, ceiling in (("persona_input_units", "max_persona_input_units"),
                           ("persona_output_units", "max_persona_output_units"),
                           ("timeout_seconds_sum", "max_total_timeout_seconds")):
        if totals[total] > budget[ceiling]:
            raise PoolSpecError(f"pool specification rejected: the instances' {total} exceed pool_budget.{ceiling}")
    if totals["timeout_seconds_max"] > spec["rendezvous_timeout_seconds"]:
        raise PoolSpecError("pool specification rejected: rendezvous_timeout_seconds is shorter than one "
                            "instance's own timeout")
    return totals


def expansion_sha256(manifest: Mapping[str, Any]) -> str:
    """Integrity hash over every other field. Not an authenticator: the verifier re-derives."""
    return _sha({key: value for key, value in thaw(manifest).items() if key != "expansion_sha256"})


# ---- expansion on disk ---------------------------------------------------------------------------

def expand_pool(spec: Any, *, context: PoolContext) -> ExpansionPlan:
    """Creates the pool root once: ``instances/<id>/`` (empty, private), ``requests/<id>.json``,
    ``specification.json`` and, last, ``expansion.json``; then verifies what it wrote.

    Everything that can refuse a specification runs before the first directory is created. A pool
    root that exists is refused: an expansion is created once and never repaired in place."""
    plan = plan_expansion(spec, context=context)
    root = context.pool_parent / plan.pool_directory
    if os.path.lexists(root):
        raise PoolSpecError("the pool root already exists: an expansion is created once, and a new attempt "
                            "derives a new pool root")
    try:
        os.mkdir(root, 0o700)
    except OSError:
        raise PoolSpecError("the pool root could not be created exclusively beneath context.pool_parent") from None
    try:
        created = [root]
        for name in (INSTANCES_DIR, REQUESTS_DIR):
            os.mkdir(root / name, 0o700)
            created.append(root / name)
        for entry in plan.manifest["instances"]:
            path = root.joinpath(*entry["attempt_root"].split("/"))
            os.mkdir(path, 0o700)
            created.append(path)
        identities = [_identity(path) for path in created]
        if None in identities or len(set(identities)) != len(identities) or not all(
                _real_directory(path) for path in created):
            raise PoolExpansionError("two created roots are one directory, or a created root is not a directory")
        for item in plan.requests:
            atomic_bytes(root.joinpath(*item.relative_path.split("/")), item.data)
        atomic_bytes(root / SPEC_FILE, plan.specification_bytes)
        atomic_bytes(root / EXPANSION_FILE, plan.manifest_bytes)
    except OSError as exc:
        raise PoolExpansionError("the pool root could not be completed; it has no verified expansion.json "
                                 "and is not an expansion") from exc
    errors = verify_expansion(root, expected_spec=spec, context=context)
    if errors:
        raise PoolExpansionError("the pool root does not verify after it was written: " + "; ".join(errors))
    return plan


def _read_regular(root: Path, path: Path) -> bytes | None:
    """One regular, singly linked file beneath ``root``, reached without crossing a link."""
    try:
        beneath(root, path)
        before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            return None
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            data = stream.read(MAX_DOCUMENT_BYTES + 1)
    except (OSError, ValueError):
        return None
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or len(data) > MAX_DOCUMENT_BYTES:
        return None
    return data


def _listing(path: Path) -> list | None:
    try:
        with os.scandir(path) as entries:
            return sorted(entry.name for entry in entries)
    except OSError:
        return None


def _manifest_errors(raw: bytes, plan: ExpansionPlan) -> list:
    """Only reached when the bytes are not the derived bytes. Says which rule they break; every
    field name below is this module's own, never one read from the file."""
    try:
        found = parse_document(raw)
    except PoolSpecError:
        return ["expansion.json is not bounded UTF-8 JSON with exactly one reading"]
    schema_errors = validate_document(found, EXPANSION_SCHEMA)
    if schema_errors:
        return [f"expansion.json fails its closed schema ({len(schema_errors)} errors)"]
    errors = []
    if raw != canonical_bytes(found):
        errors.append("expansion.json is not in the canonical byte form")
    if found["expansion_sha256"] != expansion_sha256(found):
        errors.append("expansion_sha256 does not match the expansion record")
    expected = thaw(plan.manifest)
    errors.extend(f"expansion.json field {name} is not what the expected specification derives"
                  for name in sorted(expected) if found[name] != expected[name])
    return errors or ["expansion.json is not the byte sequence the expected specification derives"]


def verify_expansion(pool_root: Path, *, expected_spec: Any, context: PoolContext) -> list:
    """Re-derives the whole expansion from the expected specification and compares it with the
    bytes on disk. Read-only. Every argument is required.

    Every file the manifest hashes is READ and compared with the bytes the specification derives:
    ``specification.json``, every ``requests/<id>.json`` and ``expansion.json`` itself. A producer
    who edits one file and reseals every hash is refused, because no hash on disk is an input.
    Messages are fixed text: nothing read from the pool root is echoed."""
    try:
        plan = plan_expansion(expected_spec, context=context)
    except PoolSpecError as exc:
        return [f"the expected specification is not expandable, so no expansion of it can exist: {exc}"]
    if not isinstance(pool_root, Path) or pool_root != context.pool_parent / plan.pool_directory:
        return ["pool_root is not the pool directory the expected specification derives beneath "
                "context.pool_parent"]
    if not _real_directory(pool_root) or _identity(pool_root.parent) != _identity(context.pool_parent):
        return ["the pool root is missing, is a link or is not a directory"]
    if _listing(pool_root) != sorted(POOL_ROOT_ENTRIES):
        return ["the pool root does not hold exactly expansion.json, specification.json, instances and requests"]
    errors: list = []
    raw = _read_regular(pool_root, pool_root / EXPANSION_FILE)
    if raw is None:
        errors.append("expansion.json is missing, linked, hard-linked, oversized or unreadable")
    elif raw != plan.manifest_bytes:
        errors.extend(_manifest_errors(raw, plan))
    if _read_regular(pool_root, pool_root / SPEC_FILE) != plan.specification_bytes:
        errors.append("specification.json is not the canonical bytes of the expected specification")
    requests_dir, instances_dir = pool_root / REQUESTS_DIR, pool_root / INSTANCES_DIR
    if not _real_directory(requests_dir) or _listing(requests_dir) != sorted(
            item.relative_path.split("/")[1] for item in plan.requests):
        errors.append("the requests directory does not hold exactly one request file per expected instance")
    else:
        for index, item in enumerate(plan.requests):
            if _read_regular(pool_root, pool_root.joinpath(*item.relative_path.split("/"))) != item.data:
                errors.append(f"the request file of instances[{index}] is not the request the expected "
                              "specification derives")
    roots = [pool_root.joinpath(*entry["attempt_root"].split("/")) for entry in plan.manifest["instances"]]
    if not _real_directory(instances_dir) or _listing(instances_dir) != sorted(path.name for path in roots):
        errors.append("the instances directory does not hold exactly one private root per expected instance")
    else:
        identities = [_identity(path) for path in (pool_root, requests_dir, instances_dir, *roots)]
        if not all(_real_directory(path) for path in roots) or len(set(identities)) != len(identities):
            errors.append("an instance root is a link, is not a directory, or two roots are one directory")
    return errors


def load_verified_expansion(pool_root: Path, *, expected_spec: Any, context: PoolContext) -> ExpansionPlan:
    """The expansion C02 may rely on: verified against disk, returned from the re-derivation
    (deeply immutable), never from a caller's copy or from the file."""
    errors = verify_expansion(pool_root, expected_spec=expected_spec, context=context)
    if errors:
        raise PoolSpecError("pool expansion rejected: " + "; ".join(errors))
    return plan_expansion(expected_spec, context=context)
