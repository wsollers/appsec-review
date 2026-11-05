"""One run-owned build tree, durable accepted generations, and serialized retention.

Only ``paths.target`` and ``paths.install`` go into disposable build containers, at
``/workspace`` and ``/install`` respectively. Never mount the run or checkpoint store.
Callers hold ``writer()`` until their container has exited and its mounts are closed.
Release identities/ABI compatibility must be validated by the orchestration layer;
opaque identity strings here bind that validated decision, not prove it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import time
from typing import Any
import uuid

from appsec_review.config.build_workspaces import BuildWorkspacePolicy
from appsec_review.storage.atomic import atomic_json, canonical_json, canonical_json_sha256, file_sha256
from appsec_review.storage.lock import FileLock, LockUnavailable
from appsec_review.storage.shared import immutable_bytes, put_file, safe_path, verify_reference


_SCHEMA = "appsec-review/build-workspace/1"
_STATE = "data/build/workspace/state.json"
_OWNER = "data/build/workspace/owner.json"
_INPUT = "artifacts/build/workspace/input.json"
_DISPOSABLE = "workspace/build"
_HASH = re.compile(r"[0-9a-f]{64}")
_PRODUCT_KINDS = frozenset({"library", "executable", "headers", "package_metadata", "generated_source"})
_PRODUCT_ROLES = {
    "static_archive": "library", "import_library": "library", "runtime_shared": "library",
    "executable": "executable", "headers": "headers", "metadata": "package_metadata",
    "generated_source": "generated_source", "native_object": "generated_source",
    "managed_assembly": "package_metadata", "package": "package_metadata",
}
_TARGET_AXES = frozenset({"os", "isa", "abi", "sdk", "deployment", "device_kind", "hardware_generation"})
_VARIANT_KEYS = frozenset({"configuration", "target_arch", "execution_role", "linkage", "toolchain", "abi"})
TARGET_CONTAINER_PATH = "/workspace"
INSTALL_CONTAINER_PATH = "/install"


class WorkspaceError(RuntimeError):
    """Unsafe, missing, tainted or incompatible retained state; never a reuse hit."""


class ReconstructionMiss(WorkspaceError):
    """Required retained bytes/metadata are unavailable; restore/rebuild is required."""


def _identity(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise ValueError(f"{name} must be a non-empty accepted identity")
    return value


def _hash(value: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise WorkspaceError("invalid workspace content identity")
    return value


def _relative(value: str) -> str:
    if (not isinstance(value, str) or "\\" in value or ":" in value
            or value.startswith("/") or not value or "\0" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise WorkspaceError(f"noncanonical workspace path: {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class NodeBinding:
    """Exact build inputs. Upstreams are durable product-record identities, not labels."""

    node_id: str
    source_identity: str
    graph_identity: str
    configuration_identity: str
    recipe_identity: str
    image_identity: str
    toolchain_identity: str
    upstream_products: tuple[str, ...]
    execution_identity: str
    output_policy_identity: str

    def __post_init__(self) -> None:
        for key, value in asdict(self).items():
            if key != "upstream_products":
                _identity(value, key)
        if not isinstance(self.upstream_products, tuple):
            raise ValueError("upstream_products must be a tuple of durable product-record identities")
        for value in self.upstream_products:
            _hash(value)
        if len(set(self.upstream_products)) != len(self.upstream_products):
            raise ValueError("upstream_products repeats a product")

    def view(self) -> dict[str, Any]:
        value = asdict(self)
        value["upstream_products"] = list(self.upstream_products)
        return value


@dataclass(frozen=True, slots=True)
class ProductSpec:
    """A target/ or install/ path and its consumer-facing purpose.

    A directory exports its entire subtree. Symlink targets are included recursively,
    so a library's alias chain cannot outlive or omit the versioned library bytes.
    """

    path: str
    kind: str
    product_id: str
    interface: str
    variant: Mapping[str, str | None]
    role: str | None = None
    axes: Mapping[str, str | None] | None = None

    def __post_init__(self) -> None:
        _relative(self.path)
        if self.path.split("/")[0] not in {"target", "install"}:
            raise ValueError("products must be under target/ or install/")
        if self.kind not in _PRODUCT_KINDS:
            raise ValueError(f"unknown product kind: {self.kind}")
        _identity(self.product_id, "product_id")
        _identity(self.interface, "interface")
        if (not isinstance(self.variant, Mapping) or set(self.variant) != _VARIANT_KEYS
                or any(value is not None and (not isinstance(value, str) or not value.strip())
                       for value in self.variant.values())
                or self.variant["execution_role"] not in {"host", "target", None}):
            raise ValueError("variant must supply the six exact accepted topology variant fields")
        object.__setattr__(self, "variant", dict(self.variant))
        if self.role is not None and (
                not isinstance(self.role, str) or _PRODUCT_ROLES.get(self.role) != self.kind):
            raise ValueError("product role is unknown or conflicts with its kind")
        if self.axes is not None and (
                not isinstance(self.axes, Mapping) or set(self.axes) != _TARGET_AXES or any(
                    value is not None and (not isinstance(value, str) or not value.strip())
                    for value in self.axes.values())):
            raise ValueError("product axes must retain the seven exact nullable target axes")
        object.__setattr__(self, "axes", dict(self.axes) if self.axes is not None else None)

    @property
    def container_path(self) -> str:
        root, _, suffix = self.path.partition("/")
        base = TARGET_CONTAINER_PATH if root == "target" else INSTALL_CONTAINER_PATH
        return base + ("/" + suffix if suffix else "")


@dataclass(frozen=True, slots=True)
class WorkspacePaths:
    target: Path
    install: Path
    target_container: str = TARGET_CONTAINER_PATH
    install_container: str = INSTALL_CONTAINER_PATH


@dataclass(frozen=True, slots=True)
class ProductRecord:
    identity: str
    reference: Mapping[str, Any]
    binding: Mapping[str, Any]
    attempt_id: str
    products: tuple[ProductSpec, ...]


@dataclass(slots=True)
class RetentionReport:
    deleted: list[str] = field(default_factory=list)
    retained: dict[str, str] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError) as error:
        raise ReconstructionMiss(f"missing or malformed workspace metadata: {path}") from error
    if not isinstance(value, dict):
        raise ReconstructionMiss(f"workspace metadata must be an object: {path}")
    return value


def native_product_axes(path: Path) -> dict[str, Any]:
    """Read machine/class from bounded headers, including every retained archive member."""
    machines = {0x14C: ("x86", 32), 0x8664: ("x86_64", 64), 0xAA64: ("arm64", 64)}

    def header(head: bytes) -> tuple[str, int, bool]:
        if head.startswith(b"\x7fELF") and len(head) >= 20:
            order = {1: "<", 2: ">"}.get(head[5])
            bits = {1: 32, 2: 64}.get(head[4])
            machine = struct.unpack_from(order + "H", head, 18)[0] if order else None
            target = {3: ("x86", 32), 62: ("x86_64", 64), 183: ("arm64", 64)}.get(machine)
            if target and target[1] == bits:
                return (*target, False)
        if head[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                         b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"} and len(head) >= 16:
            order = "<" if head[0] in {0xCF, 0xCE} else ">"
            machine = struct.unpack_from(order + "I", head, 4)[0]
            target = {7: ("x86", 32), 0x01000007: ("x86_64", 64),
                      0x0100000C: ("arm64", 64)}.get(machine)
            if target and (head[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}) == (target[1] == 64):
                return (*target, False)
        if len(head) >= 20:
            if head[:4] == b"\0\0\xff\xff" and struct.unpack_from("<H", head, 4)[0] == 0:
                target = machines.get(struct.unpack_from("<H", head, 6)[0])
                if target and struct.unpack_from("<I", head, 12)[0] > 0:
                    return (*target, True)
            target = machines.get(struct.unpack_from("<H", head)[0])
            if target and 0 < struct.unpack_from("<H", head, 2)[0] <= 1024:
                return (*target, False)
        raise WorkspaceError("native retained binary machine/class is unresolved")

    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(64)
        if head.startswith(b"MZ") and len(head) == 64:
            offset = struct.unpack_from("<I", head, 60)[0]
            if not 64 <= offset <= min(size - 24, 1024 * 1024):
                raise WorkspaceError("native PE header is outside its bounded container")
            stream.seek(offset)
            pe = stream.read(26)
            if pe[:4] != b"PE\0\0":
                raise WorkspaceError("native PE signature is unresolved")
            target = machines.get(struct.unpack_from("<H", pe, 4)[0])
            magic = struct.unpack_from("<H", pe, 24)[0] if len(pe) >= 26 else None
            if not target or magic != (0x20B if target[1] == 64 else 0x10B):
                raise WorkspaceError("native PE machine/class is inconsistent")
            return {"isa": target[0], "bits": target[1], "import_library": False}
        if not head.startswith(b"!<arch>\n"):
            isa, bits, imported = header(head)
            return {"isa": isa, "bits": bits, "import_library": imported}
        offset, targets, imports, members = 8, set(), False, 0
        while offset < size:
            members += 1
            if members > 4096:
                raise WorkspaceError("native archive exceeds its bounded member closure")
            stream.seek(offset)
            member = stream.read(60)
            if len(member) != 60 or member[58:] != b"`\n":
                raise WorkspaceError("native archive member header is malformed")
            try:
                length = int(member[48:58].decode("ascii").strip())
                name = member[:16].decode("ascii").strip()
            except (ValueError, UnicodeError) as error:
                raise WorkspaceError("native archive member identity is malformed") from error
            start, end = offset + 60, offset + 60 + length
            if length < 0 or end > size:
                raise WorkspaceError("native archive member escapes its container")
            if name not in {"/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"}:
                if name.startswith("#1/"):
                    try:
                        name_size = int(name[3:])
                    except ValueError as error:
                        raise WorkspaceError("native BSD archive name is malformed") from error
                    if not 0 < name_size <= min(length, 4096):
                        raise WorkspaceError("native BSD archive name is outside its bound")
                    stream.seek(start)
                    try:
                        name = stream.read(name_size).rstrip(b"\0").decode("ascii")
                    except UnicodeError as error:
                        raise WorkspaceError("native BSD archive name is malformed") from error
                    start += name_size
                if not offset + 60 <= start <= end:
                    raise WorkspaceError("native archive name escapes its member")
                stream.seek(start)
                if name not in {"__.SYMDEF", "__.SYMDEF SORTED"}:
                    isa, bits, imported = header(stream.read(min(64, end - start)))
                    targets.add((isa, bits))
                    imports |= imported
            offset = end + length % 2
        if offset != size or len(targets) != 1:
            raise WorkspaceError("native archive member targets are absent, mixed or unresolved")
        isa, bits = targets.pop()
        return {"isa": isa, "bits": bits, "import_library": imports}


def verify_native_product(path: Path, spec: ProductSpec) -> None:
    if spec.role not in {"static_archive", "import_library", "runtime_shared", "executable", "native_object"}:
        return
    actual = native_product_axes(path)
    if not isinstance(spec.axes, Mapping) or actual["isa"] != spec.axes.get("isa"):
        raise WorkspaceError("native retained binary target differs from its accepted enforcement")
    if spec.role in {"static_archive", "import_library"} and (
            actual["import_library"] != (spec.role == "import_library")):
        raise WorkspaceError("native archive/import-library role differs from its actual members")


def verify_retained_product(run_dir: Path, generation_identity: str,
                            ref: Mapping[str, Any], binding: NodeBinding) -> dict[str, Any]:
    """Verify immutable generation/CAS custody without taking a writer or restoring mounts."""
    identity = _hash(generation_identity)
    generation = _json(safe_path(run_dir, f"artifacts/build/workspace/generations/{identity}.json"))
    snapshot_path = safe_path(run_dir, _INPUT)
    snapshot = _json(snapshot_path)
    if (canonical_json_sha256(generation) != identity or generation.get("schema") != _SCHEMA
            or not isinstance(generation.get("entries"), dict)
            or not isinstance(generation.get("accepted"), dict)
            or snapshot.get("schema") != _SCHEMA
            or snapshot.get("source_identity") != binding.source_identity
            or generation.get("input_identity") != hashlib.sha256(snapshot_path.read_bytes()).hexdigest()):
        raise ReconstructionMiss("retained product has no matching immutable source generation")
    WorkspaceWriter.validate_retained_entries(run_dir, generation["entries"])
    accepted = generation["accepted"]
    accepted_identities = {item["sha256"] for item in accepted.values()}
    for node, product_ref in accepted.items():
        product = WorkspaceWriter.read_retained_record(run_dir, product_ref)
        if (product["binding"]["node_id"] != node
                or product["binding"]["source_identity"] != binding.source_identity
                or product.get("input_identity") != generation["input_identity"]
                or not set(product["binding"]["upstream_products"]) <= accepted_identities):
            raise ReconstructionMiss("retained generation contains a changed producer or upstream")
        WorkspaceWriter._verify_entries(product["entries"], generation["entries"])
    value = WorkspaceWriter.read_retained_record(run_dir, ref)
    if value["binding"] != binding.view() or accepted.get(binding.node_id) != dict(ref):
        raise ReconstructionMiss("retained product is not the exact generation-bound producer")
    for item in value["products"]:
        spec = ProductSpec(**item)
        resolved = WorkspaceWriter._link_target(spec.path, generation["entries"])
        entry = value["entries"].get(resolved)
        if spec.role in {"static_archive", "import_library", "runtime_shared", "executable", "native_object"}:
            if not isinstance(entry, Mapping) or entry.get("kind") != "file":
                raise ReconstructionMiss("native retained product has no exact physical file")
            verify_native_product(safe_path(run_dir, f"data/shared/objects/{entry['sha256']}"), spec)
    return value


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic(path: Path, value: Any) -> None:
    atomic_json(path, value)
    _sync_directory(path.parent)


def _immutable(root: Path, relative: str, value: Any) -> dict[str, Any]:
    ref = immutable_bytes(root, relative, canonical_json(value))
    _sync_directory(safe_path(root, relative).parent)
    return ref


def _scan(root: Path, *, source: bool = False) -> dict[str, dict[str, Any]]:
    """Do not follow links, omit only Git control metadata, and hash exact file bytes."""
    entries: dict[str, dict[str, Any]] = {}
    if root.is_symlink() or not root.is_dir():
        raise ReconstructionMiss(f"workspace tree missing or replaced: {root}")

    def visit(path: Path, relative: str) -> None:
        details = path.lstat()
        item: dict[str, Any] = {"mode": stat.S_IMODE(details.st_mode), "mtime_ns": details.st_mtime_ns}
        if stat.S_ISLNK(details.st_mode):
            link = os.readlink(path)
            if os.path.isabs(link):
                raise WorkspaceError(f"absolute workspace symlink: {relative}")
            try:
                path.resolve(strict=True).relative_to(root.resolve())
            except (OSError, RuntimeError, ValueError) as error:
                raise WorkspaceError(f"escaping, broken or cyclic workspace symlink: {relative}") from error
            item.update(kind="symlink", link=link)
        elif stat.S_ISDIR(details.st_mode):
            item["kind"] = "directory"
            for child in sorted(path.iterdir()):
                if source and child.name == ".git":
                    continue
                visit(child, f"{relative}/{child.name}" if relative else child.name)
        elif stat.S_ISREG(details.st_mode):
            item.update(kind="file", sha256=file_sha256(path), size_bytes=details.st_size)
            after = path.lstat()
            if (details.st_ino, details.st_size, details.st_mtime_ns, details.st_ctime_ns) != (
                    after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise WorkspaceError(f"workspace file changed during capture: {relative}")
        else:
            raise WorkspaceError(f"unsupported workspace object: {relative}")
        if relative:
            entries[relative] = item

    visit(root, "")
    return dict(sorted(entries.items()))


def _copy_entries(source: Path, destination: Path, entries: Mapping[str, Any]) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for relative, item in sorted(entries.items(), key=lambda pair: (pair[0].count("/"), pair[0])):
        path = destination / relative
        if item["kind"] == "directory":
            path.mkdir()
        elif item["kind"] == "file":
            shutil.copyfile(source / relative, path, follow_symlinks=False)
        else:
            path.symlink_to(item["link"])
    _metadata(destination, entries)
    shutil.copystat(source, destination, follow_symlinks=False)


def _metadata(root: Path, entries: Mapping[str, Any]) -> None:
    # Apply directories last: restoring child entries changes parent timestamps.
    for relative, item in sorted(entries.items(), key=lambda pair: pair[0].count("/"), reverse=True):
        path = root / relative
        if item["kind"] != "symlink":
            path.chmod(item["mode"])
        os.utime(path, ns=(item["mtime_ns"], item["mtime_ns"]), follow_symlinks=False)


def _remove_tree(root: Path) -> None:
    """Only callers with a validated exact disposable boundary may call this."""
    if root.is_symlink() or not root.is_dir():
        raise WorkspaceError(f"refusing deletion of missing/replaced workspace: {root}")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise WorkspaceError("workspace deletion requires descriptor-relative safe rmtree")

    def writable_directories(parent: int, name: str) -> None:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode):
            return
        os.chmod(name, stat.S_IMODE(info.st_mode) | 0o700, dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            with os.scandir(descriptor) as children:
                for child in children:
                    if child.is_dir(follow_symlinks=False):
                        writable_directories(descriptor, child.name)
        finally:
            os.close(descriptor)

    parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        writable_directories(parent, root.name)
    finally:
        os.close(parent)
    shutil.rmtree(root)


class BuildWorkspace:
    """Metadata lives outside the production and registered replay deletion boundaries."""

    def __init__(self, run_dir: Path, *, replay_id: str | None = None):
        supplied = Path(run_dir).absolute()
        if supplied != supplied.resolve() or not supplied.is_dir():
            raise WorkspaceError("run_dir must be an existing nonsymlink canonical directory")
        self.run_dir = supplied
        self.replay_id = replay_id
        self.owner_relative, self.state_relative, self.disposable_relative = _OWNER, _STATE, _DISPOSABLE
        lock_relative = "data/build/workspace.lock"
        if replay_id is not None:
            _identity(replay_id, "replay_id")
            key = hashlib.sha256(replay_id.encode()).hexdigest()
            self.owner_relative = f"data/build/workspace/replays/{key}/owner.json"
            self.state_relative = f"data/build/workspace/replays/{key}/state.json"
            self.disposable_relative = f"workspace/build-replays/{key}"
            lock_relative = f"data/build/workspace/replays/{key}/writer.lock"
        self.root = safe_path(supplied, self.disposable_relative)
        self.paths = WorkspacePaths(self.root / "target", self.root / "install")
        self.lock_path = safe_path(supplied, lock_relative)
        self.lifecycle_lock = safe_path(supplied.parent, ".build-workspaces.lock")

    @contextmanager
    def writer(self) -> Iterator[WorkspaceWriter]:
        """Claim under the same lock as retention/resume, then hold the run lock."""
        with FileLock(self.lifecycle_lock):
            lock = FileLock(self.lock_path)
            lock.__enter__()
        try:
            writer = WorkspaceWriter(self, lock)
            yield writer
        finally:
            lock.__exit__(None, None, None)

    def materialize(self, target: Path, source_identity: str) -> str:
        """Copy the complete tree once. The original source is never linked or mutated."""
        _identity(source_identity, "source_identity")
        if self.replay_id is not None:
            raise WorkspaceError("replay workspaces must be reconstructed by create_replay")
        target = Path(target).resolve(strict=True)
        if (target == self.run_dir or target in self.run_dir.parents
                or self.run_dir in target.parents):
            raise WorkspaceError("target and run directories must be disjoint")
        with self.writer() as writer:
            if safe_path(self.run_dir, self.owner_relative).exists() or self.root.exists():
                raise WorkspaceError("workspace already exists; explicitly verify or restore it")
            source_entries = _scan(target, source=True)
            self.root.mkdir(parents=True)
            _copy_entries(target, self.paths.target, source_entries)
            self.paths.install.mkdir()
            if _scan(target, source=True) != source_entries or _scan(self.paths.target) != source_entries:
                raise WorkspaceError("source changed during materialization")
            entries = writer._capture()
            initial = {"schema": _SCHEMA, "source_identity": source_identity, "entries": entries,
                       "excluded_control_metadata": [".git"]}
            ref = _immutable(self.run_dir, _INPUT, initial)
            owner = {"schema": _SCHEMA, "run_dir": str(self.run_dir), "ownership_id": uuid.uuid4().hex,
                     "disposable": _DISPOSABLE, "input": ref, "source_identity": source_identity,
                     "terminal_ns": None, "holds": {}, "replays": {}, "replay_id": None}
            _atomic(safe_path(self.run_dir, self.owner_relative), owner)
            generation = writer._publish_generation(entries, {}, ref["sha256"])
            writer._write_state({"schema": _SCHEMA, "generation": generation, "attempt": None,
                                 "condition": "clean", "purged": False})
            return generation

    def set_hold(self, name: str, *, held: bool) -> None:
        """C registers external worker/lease/preserve/resume holds before releasing custody."""
        _identity(name, "hold name")
        if type(held) is not bool:
            raise ValueError("held must be a boolean")
        with self.writer() as writer:
            owner = writer._owner()
            if held:
                owner["holds"][name] = True
            else:
                owner["holds"].pop(name, None)
            _atomic(safe_path(self.run_dir, self.owner_relative), owner)

    def mark_terminal(self, *, workers_stopped: bool) -> None:
        """Call only after terminal orchestration status and verified worker/lease cleanup."""
        if workers_stopped is not True:
            raise WorkspaceError("terminal retention requires confirmed worker/lease cleanup")
        with self.writer() as writer:
            owner = writer._owner()
            state = writer.state()
            if state["attempt"] is not None:
                raise WorkspaceError("an unfinished build attempt cannot become retention-eligible")
            if owner["terminal_ns"] is None:
                owner["terminal_ns"] = time.time_ns()
                _atomic(safe_path(self.run_dir, self.owner_relative), owner)


class WorkspaceWriter:
    """Created only by ``BuildWorkspace.writer``; all mutation/reuse is serialized."""

    def __init__(self, workspace: BuildWorkspace, claim: FileLock):
        self.workspace = workspace
        self.run_dir = workspace.run_dir
        self._claim = claim

    def _require_claim(self) -> None:
        if self._claim.stream is None:
            raise WorkspaceError("workspace writer claim has been released")

    @property
    def paths(self) -> WorkspacePaths:
        return self.workspace.paths

    def _owner(self) -> dict[str, Any]:
        self._require_claim()
        owner = _json(safe_path(self.run_dir, self.workspace.owner_relative))
        if (not {"schema", "run_dir", "disposable", "replay_id", "ownership_id",
                 "holds", "replays", "terminal_ns", "source_identity", "input"} <= owner.keys()
                or owner.get("schema") != _SCHEMA or owner.get("run_dir") != str(self.run_dir)
                or owner.get("disposable") != self.workspace.disposable_relative
                or owner.get("replay_id") != self.workspace.replay_id
                or not isinstance(owner.get("ownership_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", owner["ownership_id"])
                or not isinstance(owner.get("holds"), dict)
                or not isinstance(owner.get("replays"), dict)
                or any(not isinstance(key, str) or value is not True
                       for key, value in owner["holds"].items())
                or (owner.get("terminal_ns") is not None
                    and (type(owner["terminal_ns"]) is not int or owner["terminal_ns"] <= 0))):
            raise WorkspaceError(f"malformed workspace ownership record: {self.run_dir}")
        for replay_id, record in owner["replays"].items():
            if self.workspace.replay_id is not None or not isinstance(record, dict):
                raise WorkspaceError("invalid nested replay ownership")
            replay = BuildWorkspace(self.run_dir, replay_id=replay_id)
            if (record.get("disposable") != replay.disposable_relative
                    or not isinstance(record.get("ownership_id"), str)
                    or not re.fullmatch(r"[0-9a-f]{32}", record["ownership_id"])):
                raise WorkspaceError("malformed registered replay ownership")
        try:
            _identity(owner["source_identity"], "source_identity")
            if owner["input"]["path"] != _INPUT:
                raise WorkspaceError("unexpected input snapshot location")
            snapshot = _json(verify_reference(self.run_dir, owner["input"]))
            if (snapshot.get("schema") != _SCHEMA
                    or snapshot.get("source_identity") != owner["source_identity"]):
                raise ReconstructionMiss("input snapshot source binding changed")
        except (KeyError, TypeError, ValueError, OSError) as error:
            raise ReconstructionMiss("input snapshot is missing or changed") from error
        return owner

    def state(self) -> dict[str, Any]:
        self._require_claim()
        state = _json(safe_path(self.run_dir, self.workspace.state_relative))
        if (state.get("schema") != _SCHEMA or state.get("condition") not in {"clean", "tainted", "running"}
                or type(state.get("purged")) is not bool or "attempt" not in state):
            raise ReconstructionMiss("invalid committed workspace state")
        _hash(state.get("generation"))
        if state["attempt"] is not None:
            attempt = state["attempt"]
            if (not isinstance(attempt, dict) or not isinstance(attempt.get("binding"), dict)
                    or not isinstance(attempt.get("attempt_id"), str)):
                raise ReconstructionMiss("invalid uncommitted attempt state")
            try:
                _identity(attempt["attempt_id"], "attempt_id")
                binding = dict(attempt["binding"])
                binding["upstream_products"] = tuple(binding["upstream_products"])
                NodeBinding(**binding)
            except (KeyError, TypeError, ValueError) as error:
                raise ReconstructionMiss("incomplete persisted attempt binding") from error
        if (state["condition"] == "running" and state["attempt"] is None
                or state["condition"] == "clean" and state["attempt"] is not None):
            raise ReconstructionMiss("inconsistent attempt and committed workspace state")
        return state

    def _write_state(self, value: dict[str, Any]) -> None:
        _atomic(safe_path(self.run_dir, self.workspace.state_relative), value)

    def _capture(self) -> dict[str, Any]:
        self._require_claim()
        root = self.workspace.root
        safe_path(self.run_dir, self.workspace.disposable_relative)
        if set(child.name for child in root.iterdir()) != {"target", "install"}:
            raise WorkspaceError("workspace boundary must contain only target and install")
        entries = _scan(root)
        for relative, item in entries.items():
            if item["kind"] == "file":
                ref = put_file(self.run_dir, root / relative)
                if ref["sha256"] != item["sha256"] or ref["size_bytes"] != item["size_bytes"]:
                    raise WorkspaceError(f"file changed during durable publication: {relative}")
        if any(item["kind"] == "file" for item in entries.values()):
            _sync_directory(safe_path(self.run_dir, "data/shared/objects"))
        if _scan(root) != entries:
            raise WorkspaceError("workspace changed during durable capture")
        return entries

    def _publish_generation(self, entries: dict[str, Any], accepted: dict[str, Any],
                            input_identity: str) -> str:
        manifest = {"schema": _SCHEMA, "input_identity": input_identity,
                    "entries": entries, "accepted": accepted}
        identity = canonical_json_sha256(manifest)
        _immutable(self.run_dir, f"artifacts/build/workspace/generations/{identity}.json", manifest)
        return identity

    def committed_generation(self, generation_identity: str | None = None) -> Mapping[str, Any]:
        """Verify durable checkpoint custody without inspecting or changing the mounted tree.

        This is not a mounted-product reuse check. Call ``verify_product`` before
        execution; replay promotion can inspect these defensive-copy producer records
        while the production attempt still holds uncommitted failed mutations.
        """
        return deepcopy(self._generation(generation_identity))

    def _generation(self, identity: str | None = None) -> dict[str, Any]:
        owner = self._owner()
        identity = _hash(identity or self.state()["generation"])
        path = safe_path(self.run_dir, f"artifacts/build/workspace/generations/{identity}.json")
        manifest = _json(path)
        if (canonical_json_sha256(manifest) != identity or manifest.get("schema") != _SCHEMA
                or manifest.get("input_identity") != owner["input"]["sha256"]
                or not isinstance(manifest.get("entries"), dict)
                or not isinstance(manifest.get("accepted"), dict)):
            raise ReconstructionMiss("committed workspace generation is missing or changed")
        self._validate_entries(manifest["entries"])
        accepted_identities = {ref["sha256"] for ref in manifest["accepted"].values()
                               if isinstance(ref, dict) and isinstance(ref.get("sha256"), str)}
        for node, ref in manifest["accepted"].items():
            value = self._record(ref)
            if (value["binding"]["node_id"] != node
                    or value.get("input_identity") != manifest["input_identity"]
                    or value["binding"]["source_identity"] != owner["source_identity"]):
                raise ReconstructionMiss("accepted producer identity mismatch")
            if not set(value["binding"]["upstream_products"]) <= accepted_identities:
                raise ReconstructionMiss("accepted producer upstream products are no longer retained")
            self._verify_entries(value["entries"], manifest["entries"])
        return manifest

    def _validate_entries(self, entries: Mapping[str, Any]) -> None:
        self.validate_retained_entries(self.run_dir, entries)

    @staticmethod
    def validate_retained_entries(run_dir: Path, entries: Mapping[str, Any]) -> None:
        for relative, item in entries.items():
            _relative(relative)
            if relative.split("/")[0] not in {"target", "install"} or not isinstance(item, dict):
                raise ReconstructionMiss("manifest path is outside target/install")
            if (item.get("kind") not in {"file", "directory", "symlink"}
                    or type(item.get("mode")) is not int or not 0 <= item["mode"] <= 0o7777
                    or type(item.get("mtime_ns")) is not int):
                raise ReconstructionMiss(f"invalid filesystem metadata: {relative}")
            parent = str(PurePosixPath(relative).parent)
            if parent != "." and entries.get(parent, {}).get("kind") != "directory":
                raise ReconstructionMiss("manifest traverses non-directory parent")
            if item["kind"] == "file":
                try:
                    digest = _hash(item["sha256"])
                    verify_reference(run_dir, {"path": f"data/shared/objects/{digest}",
                                                    "sha256": digest, "size_bytes": item["size_bytes"]})
                except (KeyError, OSError, TypeError, ValueError) as error:
                    raise ReconstructionMiss(f"retained file is missing or changed: {relative}") from error
            elif item["kind"] == "symlink":
                WorkspaceWriter._link_target(relative, entries)
        if any(entries.get(name, {}).get("kind") != "directory" for name in ("target", "install")):
            raise ReconstructionMiss("manifest lacks target/install roots")

    @staticmethod
    def _link_chain(relative: str, entries: Mapping[str, Any]) -> tuple[str, ...]:
        seen: set[str] = set()
        chain: list[str] = []
        pending = relative.split("/")
        resolved: list[str] = []
        while pending:
            part = pending.pop(0)
            if part in {"", "."}:
                continue
            if part == "..":
                if not resolved:
                    raise ReconstructionMiss("symlink escapes workspace")
                resolved.pop()
                continue
            resolved.append(part)
            path = "/".join(resolved)
            item = entries.get(path)
            if item is None:
                raise ReconstructionMiss(f"symlink target missing: {relative}")
            if item["kind"] == "symlink":
                link = item.get("link")
                if (not isinstance(link, str) or not link or link.startswith("/")
                        or "\\" in link or "\0" in link or path in seen):
                    raise ReconstructionMiss(f"unsafe or cyclic symlink: {relative}")
                seen.add(path)
                chain.append(path)
                resolved.pop()
                pending = link.split("/") + pending
        return (*chain, "/".join(resolved))

    @staticmethod
    def _link_target(relative: str, entries: Mapping[str, Any]) -> str:
        return WorkspaceWriter._link_chain(relative, entries)[-1]

    def _record(self, ref: Mapping[str, Any]) -> dict[str, Any]:
        return self.read_retained_record(self.run_dir, ref)

    @staticmethod
    def read_retained_record(run_dir: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
        try:
            identity = _hash(ref["sha256"])
            if ref["path"] != f"artifacts/build/workspace/products/{identity}.json":
                raise ReconstructionMiss("accepted product reference is not durable")
            value = _json(verify_reference(run_dir, ref))
            if (value.get("schema") != _SCHEMA or not isinstance(value.get("entries"), dict)
                    or not isinstance(value.get("binding"), dict)
                    or not isinstance(value.get("products"), list)):
                raise ReconstructionMiss("invalid accepted product record")
            binding = dict(value["binding"])
            binding["upstream_products"] = tuple(binding["upstream_products"])
            NodeBinding(**binding)
            for spec in value["products"]:
                ProductSpec(**spec)
            return value
        except (KeyError, TypeError, ValueError, OSError) as error:
            raise ReconstructionMiss("accepted product record missing or changed") from error

    @staticmethod
    def _verify_entries(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> None:
        for path, item in expected.items():
            if actual.get(path) != item:
                raise ReconstructionMiss(f"accepted product overwritten or missing: {path}")
            if item["kind"] == "directory" and any(
                    child.startswith(path + "/") and child not in expected for child in actual):
                raise ReconstructionMiss(f"accepted product directory gained unexpected entries: {path}")

    def verify_product(self, record: ProductRecord | Mapping[str, Any], binding: NodeBinding) -> ProductRecord:
        """Verify durable bytes, accepted membership, exact inputs and current mounted state."""
        ref = record.reference if isinstance(record, ProductRecord) else record
        state = self.state()
        if state["condition"] != "clean" or state["purged"]:
            raise ReconstructionMiss("workspace must be restored before product reuse")
        generation = self._generation()
        value = self._record(ref)
        if (value["binding"] != binding.view()
                or generation["accepted"].get(binding.node_id) != dict(ref)):
            raise ReconstructionMiss("accepted product binding changed or is not current")
        mounted = _scan(self.workspace.root)
        self._verify_entries(value["entries"], mounted)
        if mounted != generation["entries"]:
            raise ReconstructionMiss("uncommitted workspace mutations require restore before reuse")
        return ProductRecord(ref["sha256"], dict(ref), value["binding"], value["attempt_id"],
                             tuple(ProductSpec(**item) for item in value["products"]))

    def product_interfaces(self, record: ProductRecord | Mapping[str, Any],
                           binding: NodeBinding) -> tuple[dict[str, Any], ...]:
        """A's readiness projection, pinned to this verified producer's durable record."""
        verified = self.verify_product(record, binding)
        value = self._record(verified.reference)
        committed_entries = self._generation()["entries"]
        interfaces: list[dict[str, Any]] = []
        for spec in verified.products:
            footprint = {path: item for path, item in value["entries"].items()
                         if path == spec.path or path.startswith(spec.path + "/")}
            entry = value["entries"][self._link_target(spec.path, committed_entries)
                                     if value["entries"][spec.path]["kind"] == "symlink" else spec.path]
            digest = entry["sha256"] if entry["kind"] == "file" else canonical_json_sha256(footprint)
            interfaces.append({"producer_build_unit_id": binding.node_id, "product_id": spec.product_id,
                               "kind": spec.kind, "interface": spec.interface, "variant": dict(spec.variant),
                               "role": spec.role, "axes": spec.axes,
                               "path": spec.container_path, "sha256": digest,
                               "topology_id": binding.graph_identity, "recipe_revision": binding.recipe_identity,
                               "workspace_product": dict(verified.reference)})
        return tuple(interfaces)

    def begin_attempt(self, binding: NodeBinding, attempt_id: str, expected_generation: str) -> str:
        """Persist the pre-command boundary. Any unfinished attempt requires explicit restore."""
        _identity(attempt_id, "attempt_id")
        owner = self._owner()
        state = self.state()
        if state["generation"] != expected_generation:
            raise WorkspaceError("workspace generation changed before writer acquisition")
        if state["condition"] != "clean" or state["purged"] or state["attempt"] is not None:
            raise ReconstructionMiss("uncommitted/interrupted attempt or purged workspace requires restore")
        if owner["terminal_ns"] is not None:
            raise WorkspaceError("terminal workspace needs explicit resume before a new attempt")
        generation = self._generation()
        if binding.source_identity != owner["source_identity"]:
            raise ReconstructionMiss("pinned source identity changed")
        if _scan(self.workspace.root) != generation["entries"]:
            state["condition"] = "tainted"
            self._write_state(state)
            raise ReconstructionMiss("uncommitted workspace mutations require restore")
        upstreams = {ref["sha256"]: ref for ref in generation["accepted"].values()}
        for identity in binding.upstream_products:
            if identity not in upstreams:
                raise ReconstructionMiss(f"upstream product is not accepted: {identity}")
            self._record(upstreams[identity])
        if binding.node_id in generation["accepted"]:
            raise WorkspaceError("node already accepted; invalidate its generation before rebuilding")
        intent = {"schema": _SCHEMA, "attempt_id": attempt_id, "binding": binding.view(),
                  "generation": state["generation"], "replay_id": self.workspace.replay_id}
        relative = self._attempt_path(attempt_id, "intent")
        if safe_path(self.run_dir, relative).exists():
            raise WorkspaceError("attempt identity already used; retries require a new attempt identity")
        _immutable(self.run_dir, relative, intent)
        state.update(condition="running", attempt={"attempt_id": attempt_id, "binding": binding.view()})
        self._write_state(state)
        return state["generation"]

    def fail_attempt(self, reason: str) -> None:
        _identity(reason, "failure reason")
        state = self.state()
        if state["attempt"] is None:
            raise WorkspaceError("no unfinished attempt")
        _immutable(self.run_dir, self._attempt_path(state["attempt"]["attempt_id"], "failure"),
                   {"schema": _SCHEMA, "attempt": state["attempt"], "generation": state["generation"],
                    "reason": reason})
        state.update(condition="tainted", failure_reason=reason)
        self._write_state(state)

    def commit(self, products: Sequence[ProductSpec]) -> ProductRecord:
        """Publish durable products first, then atomically accept the entire mutation generation.

        Product declarations must come from the caller's validated output contract.
        This storage layer does not mistake an exit-0 help command for compilation.
        """
        state = self.state()
        if state["condition"] != "running" or state["attempt"] is None:
            raise WorkspaceError("no running attempt to commit")
        if (not products or len({spec.path for spec in products}) != len(products)
                or len({spec.product_id for spec in products}) != len(products)):
            raise WorkspaceError("commit requires unique, verified expected product paths")
        generation = self._generation()
        entries = self._capture()
        accepted = dict(generation["accepted"])
        for ref in accepted.values():
            self._verify_entries(self._record(ref)["entries"], entries)
        selected: dict[str, Any] = {}

        def include(path: str) -> None:
            if path not in entries:
                raise WorkspaceError(f"expected product missing: {path}")
            if path in selected:
                return
            item = entries[path]
            selected[path] = item
            if item["kind"] == "directory":
                for child in entries:
                    if child.startswith(path + "/"):
                        include(child)
            elif item["kind"] == "symlink":
                for target in self._link_chain(path, entries)[1:]:
                    include(target)

        for spec in products:
            include(spec.path)
            resolved = self._link_target(spec.path, entries)
            if not any(item["kind"] == "file" and (path == resolved or path.startswith(resolved + "/"))
                       for path, item in selected.items()):
                raise WorkspaceError(f"expected product has no regular file bytes: {spec.path}")
            verify_native_product(safe_path(self.workspace.root, resolved), spec)
        if not any(item["kind"] == "file" for item in selected.values()):
            raise WorkspaceError("product set contains no regular file bytes")
        attempt = state["attempt"]
        record = {"schema": _SCHEMA, "binding": attempt["binding"], "attempt_id": attempt["attempt_id"],
                  "input_identity": generation["input_identity"], "entries": dict(sorted(selected.items())),
                  "products": [asdict(spec) for spec in products]}
        identity = canonical_json_sha256(record)
        ref = _immutable(self.run_dir, f"artifacts/build/workspace/products/{identity}.json", record)
        accepted[attempt["binding"]["node_id"]] = ref
        committed = self._publish_generation(entries, accepted, generation["input_identity"])
        self._write_state({"schema": _SCHEMA, "generation": committed, "condition": "clean",
                           "attempt": None, "purged": False})
        return ProductRecord(identity, ref, record["binding"], record["attempt_id"], tuple(products))

    def _attempt_path(self, attempt_id: str, event: str) -> str:
        identity = canonical_json_sha256({"attempt_id": attempt_id, "replay_id": self.workspace.replay_id})
        return f"artifacts/build/workspace/attempts/{identity}/{event}.json"

    def invalidate_nodes(self, node_ids: Sequence[str],
                         checkpoints: Sequence[tuple[str, str, str]], *,
                         operation_id: str, expected_generation: str) -> Mapping[str, Any]:
        """Recompose exact invalidations, preserving independent later accepted nodes.

        Checkpoints name every currently accepted node in execution order, with
        that node's durable before/after generation identities. They are provenance,
        not a requirement for surviving transitions to remain globally contiguous.
        No graph closure is inferred here: the caller supplies the invalid closure.
        Missing descendants, overlapping meaningful writes, or undeclared mutations
        require an explicit reconstruction/rebuild decision, never a guessed merge.
        Persist the returned receipt and retained_checkpoints in the caller's ledger.
        Retrying the identical operation after publication is idempotent; an old
        operation cannot overwrite a newer accepted generation or attempt.
        """
        _identity(operation_id, "operation_id")
        state = self.state()
        current = self._generation()
        if (isinstance(node_ids, (str, bytes)) or not node_ids
                or any(not isinstance(node, str) or not node.strip() for node in node_ids)
                or len(set(node_ids)) != len(node_ids)):
            raise ValueError("node_ids must name unique accepted nodes to invalidate")
        invalid = set(node_ids)
        if isinstance(checkpoints, (str, bytes)):
            raise ValueError("checkpoints must contain ordered node/before/after tuples")
        for checkpoint in checkpoints:
            if (not isinstance(checkpoint, (tuple, list)) or len(checkpoint) != 3
                    or not isinstance(checkpoint[0], str)):
                raise ValueError("each checkpoint must contain node_id, before_generation, after_generation")
            _hash(checkpoint[1])
            _hash(checkpoint[2])
        request = {"operation_id": operation_id, "replay_id": self.workspace.replay_id,
                   "node_ids": sorted(invalid), "checkpoints": [list(item) for item in checkpoints],
                   "expected_generation": _hash(expected_generation)}
        operation_key = canonical_json_sha256(
            {"operation_id": operation_id, "replay_id": self.workspace.replay_id})
        operation_path = f"artifacts/build/workspace/invalidations/operations/{operation_key}.json"

        def finish(receipt: dict[str, Any], ref: Mapping[str, Any]) -> Mapping[str, Any]:
            if receipt.get("schema") != _SCHEMA or receipt.get("request") != request:
                raise ReconstructionMiss("invalidation operation identity was used for a different request")
            result = _hash(receipt["after_generation"])
            self._generation(result)
            if state["generation"] == result:
                if state["condition"] != "clean" or state["attempt"] is not None or state["purged"]:
                    raise ReconstructionMiss("completed invalidation has newer uncommitted workspace state")
                if _scan(self.workspace.root) != current["entries"]:
                    raise ReconstructionMiss("completed invalidation has uncommitted workspace mutations")
            elif (state["generation"] == expected_generation
                  and state["attempt"] == receipt["before_attempt"]):
                if (state["condition"] == "clean" and not state["purged"]
                        and _scan(self.workspace.root) != current["entries"]):
                    raise ReconstructionMiss("untracked clean-workspace mutations prevent invalidation retry")
                self.restore(result)
            else:
                raise ReconstructionMiss("invalidation retry is stale against a newer generation or attempt")
            return deepcopy(dict(receipt, reference=dict(ref)))

        index_path = safe_path(self.run_dir, operation_path)
        if index_path.exists():
            index = _json(index_path)
            try:
                ref = index["receipt"]
                if ref["path"] != f"artifacts/build/workspace/invalidations/{_hash(ref['sha256'])}.json":
                    raise ReconstructionMiss("invalidation operation receipt is not durable")
                receipt = _json(verify_reference(self.run_dir, ref))
            except (KeyError, TypeError, ValueError, OSError) as error:
                raise ReconstructionMiss("invalidation operation receipt is missing or changed") from error
            return finish(receipt, ref)
        if state["generation"] != expected_generation:
            raise ReconstructionMiss("invalidation expected generation changed before publication")
        if (state["condition"] == "clean" and not state["purged"]
                and _scan(self.workspace.root) != current["entries"]):
            raise ReconstructionMiss("untracked clean-workspace mutations prevent invalidation")
        if not invalid <= current["accepted"].keys():
            raise ReconstructionMiss("invalidated node is not in the committed accepted generation")
        transitions: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        seen: set[str] = set()
        for checkpoint in checkpoints:
            node, before_id, after_id = checkpoint
            if node in seen or node not in current["accepted"]:
                raise ReconstructionMiss("duplicate or unaccepted checkpoint node")
            seen.add(node)
            before, after = self._generation(_hash(before_id)), self._generation(_hash(after_id))
            if (set(after["accepted"]) - set(before["accepted"]) != {node}
                    or node in before["accepted"]
                    or any(after["accepted"].get(key) != ref for key, ref in before["accepted"].items())
                    or after["accepted"][node] != current["accepted"][node]):
                raise ReconstructionMiss("checkpoint does not prove exactly the accepted node transition")
            transitions.append((node, before, after))
        if seen != set(current["accepted"]):
            raise ReconstructionMiss("checkpoints must cover every currently accepted node exactly once")

        owner = self._owner()
        snapshot = _json(verify_reference(self.run_dir, owner["input"]))
        self._validate_entries(snapshot["entries"])

        def meaningful(item: Mapping[str, Any] | None) -> dict[str, Any] | None:
            if item is None:
                return None
            value = dict(item)
            if value["kind"] == "directory":
                value.pop("mtime_ns")
            return value

        changes: dict[str, dict[str, tuple[Any, Any]]] = {}
        writes: dict[str, set[str]] = {}
        for node, before, after in transitions:
            delta = {path: (before["entries"].get(path), after["entries"].get(path))
                     for path in before["entries"].keys() | after["entries"].keys()
                     if before["entries"].get(path) != after["entries"].get(path)}
            changes[node] = delta
            writes[node] = {path for path, (old, new) in delta.items()
                            if meaningful(old) != meaningful(new)}
        invalid_writes = set().union(*(writes[node] for node in invalid))
        for node in seen - invalid:
            for path in writes[node]:
                for removed in invalid_writes:
                    if path == removed or path.startswith(removed + "/") or removed.startswith(path + "/"):
                        raise ReconstructionMiss(
                            f"overlapping invalidated and retained mutations: {node}:{path}, {removed}")

        def compose(excluded: set[str]) -> tuple[dict[str, Any], dict[str, Any]]:
            entries = deepcopy(snapshot["entries"])
            accepted: dict[str, Any] = {}
            for node, _, after in transitions:
                if node in excluded:
                    continue
                ref = after["accepted"][node]
                record = self._record(ref)
                if not set(record["binding"]["upstream_products"]) <= {
                        item["sha256"] for item in accepted.values()}:
                    raise ReconstructionMiss(f"retained node has missing or unordered upstream products: {node}")
                for path, (old, _) in changes[node].items():
                    if meaningful(entries.get(path)) != meaningful(old):
                        raise ReconstructionMiss(f"unresolvable checkpoint mutation baseline: {node}:{path}")
                for path, (_, new) in changes[node].items():
                    if new is None:
                        entries.pop(path, None)
                    else:
                        entries[path] = deepcopy(new)
                accepted[node] = ref
            self._validate_entries(entries)
            for ref in accepted.values():
                self._verify_entries(self._record(ref)["entries"], entries)
            return entries, accepted

        complete_entries, complete_accepted = compose(set())
        if complete_entries != current["entries"] or complete_accepted != current["accepted"]:
            raise ReconstructionMiss("current generation has mutations outside the supplied checkpoints")
        entries, accepted = compose(invalid)
        result = self._publish_generation(entries, accepted, current["input_identity"])
        self._generation(result)
        receipt = {"schema": _SCHEMA, "invalid_nodes": sorted(invalid),
                   "request": request, "before_generation": state["generation"],
                   "after_generation": result, "before_attempt": state["attempt"], "retained": accepted,
                   "retained_checkpoints": [list(item) for item in checkpoints if item[0] not in invalid]}
        identity = canonical_json_sha256(receipt)
        ref = _immutable(self.run_dir, f"artifacts/build/workspace/invalidations/{identity}.json", receipt)
        _immutable(self.run_dir, operation_path, {"schema": _SCHEMA, "receipt": ref})
        return finish(receipt, ref)

    def restore(self, generation_identity: str | None = None) -> str:
        """Rehydrate all committed mutations, deletions and metadata without running a compiler."""
        state = self.state()
        identity = _hash(generation_identity or state["generation"])
        generation = self._generation(identity)
        # Verify every durable byte before deleting even a tainted workspace.
        if state["attempt"] is not None:
            _immutable(self.run_dir, self._attempt_path(state["attempt"]["attempt_id"], "recovery"),
                       {"schema": _SCHEMA, "attempt": state["attempt"],
                        "abandoned_generation": state["generation"], "restored_generation": identity,
                        "reason": state.get("failure_reason", "interrupted_uncommitted_attempt")})
        state.update(condition="tainted")
        self._write_state(state)
        safe_path(self.run_dir, self.workspace.disposable_relative)
        if self.workspace.root.exists():
            _remove_tree(self.workspace.root)
        self.workspace.root.mkdir(parents=True)
        entries = generation["entries"]
        for relative, item in sorted(entries.items(), key=lambda pair: (pair[0].count("/"), pair[0])):
            path = self.workspace.root / relative
            if item["kind"] == "directory":
                path.mkdir()
            elif item["kind"] == "file":
                source = safe_path(self.run_dir, f"data/shared/objects/{item['sha256']}")
                shutil.copyfile(source, path)
            else:
                path.symlink_to(item["link"])
        _metadata(self.workspace.root, entries)
        if _scan(self.workspace.root) != entries:
            raise ReconstructionMiss("restored workspace does not match the committed generation")
        self._write_state({"schema": _SCHEMA, "generation": identity, "condition": "clean",
                           "attempt": None, "purged": False})
        return identity

    def resume(self) -> str:
        """Acquire with retention serialization; restore a crash/purge, retain explicit holds."""
        state = self.state()
        self.restore()
        owner = self._owner()
        owner["terminal_ns"] = None
        _atomic(safe_path(self.run_dir, self.workspace.owner_relative), owner)
        return state["generation"]

    def create_replay(self, replay_id: str, generation_identity: str | None = None) -> BuildWorkspace:
        """Rehydrate a committed checkpoint, never the dirty production tree.

        Replay metadata and CAS remain in the parent run's durable data/artifacts.
        Only workspace/build-replays/<hash> is registered as disposable.
        """
        if self.workspace.replay_id is not None:
            raise WorkspaceError("nested replay workspaces are not supported")
        owner = self._owner()
        identity = _hash(generation_identity or self.state()["generation"])
        self._generation(identity)
        replay = BuildWorkspace(self.run_dir, replay_id=replay_id)
        if replay_id in owner["replays"] or safe_path(self.run_dir, replay.owner_relative).exists():
            raise WorkspaceError("replay identity already exists")
        with replay.writer() as writer:
            if replay.root.exists():
                raise WorkspaceError("unclaimed replay directory already exists")
            replay_owner = dict(owner, ownership_id=uuid.uuid4().hex,
                                disposable=replay.disposable_relative, terminal_ns=None,
                                holds={}, replays={}, replay_id=replay_id)
            _atomic(safe_path(self.run_dir, replay.owner_relative), replay_owner)
            writer._write_state({"schema": _SCHEMA, "generation": identity, "condition": "tainted",
                                 "attempt": None, "purged": True})
            owner["replays"][replay_id] = {"disposable": replay.disposable_relative,
                                          "ownership_id": replay_owner["ownership_id"]}
            _atomic(safe_path(self.run_dir, self.workspace.owner_relative), owner)
            writer.restore(identity)
        return replay


def sweep_workspaces(runs_dir: Path, policy: BuildWorkspacePolicy) -> RetentionReport:
    """Sweep exact owned fixture/run subdirectories, never the run/evidence itself.

    Each deletion is preceded by a durable inventory and purged-state marker.
    Callers must surface ``failures``; a partially failed sweep is not success.
    """
    root = Path(runs_dir).absolute()
    if root != root.resolve() or not root.is_dir():
        raise WorkspaceError("runs_dir must be an existing nonsymlink canonical directory")
    report = RetentionReport()
    with FileLock(safe_path(root, ".build-workspaces.lock")):
        candidates: list[tuple[int, BuildWorkspace]] = []
        for run in sorted(root.iterdir()):
            if not run.is_dir() or run.is_symlink():
                continue
            try:
                workspace = BuildWorkspace(run)
                if not safe_path(run, _OWNER).exists():
                    continue
                with FileLock(workspace.lock_path) as claim:
                    writer = WorkspaceWriter(workspace, claim)
                    owner = writer._owner()
                    state = writer.state()
                    if owner["terminal_ns"] is not None:
                        candidates.append((owner["terminal_ns"], workspace))
                    else:
                        report.retained[str(workspace.root)] = "active"
            except LockUnavailable:
                report.retained[str(run / _DISPOSABLE)] = "writer_or_resume_claim"
            except (WorkspaceError, ValueError, OSError) as error:
                report.failures[str(run)] = str(error)
        newest = {str(item[1].run_dir) for item in sorted(candidates, key=lambda pair: (
            pair[0], str(pair[1].run_dir)), reverse=True)[:policy.build_workspace_retention_runs]}
        for _, workspace in candidates:
            path = str(workspace.root)
            try:
                with FileLock(workspace.lock_path) as claim:
                    writer = WorkspaceWriter(workspace, claim)
                    owner, state = writer._owner(), writer.state()
                    if policy.build_workspace_retention_runs == 0:
                        report.retained[path] = "retention_disabled"
                    elif str(workspace.run_dir) in newest:
                        report.retained[path] = "newest_terminal"
                    elif owner["holds"]:
                        report.retained[path] = "held:" + ",".join(sorted(owner["holds"]))
                    elif state["attempt"] is not None or state["condition"] != "clean":
                        report.retained[path] = "unfinished_or_tainted"
                    else:
                        with ExitStack() as claims:
                            writers = [writer]
                            replay_block = None
                            for replay_id, registered in owner["replays"].items():
                                replay = BuildWorkspace(workspace.run_dir, replay_id=replay_id)
                                replay_claim = claims.enter_context(FileLock(replay.lock_path))
                                replay_writer = WorkspaceWriter(replay, replay_claim)
                                replay_owner, replay_state = replay_writer._owner(), replay_writer.state()
                                if replay_owner["ownership_id"] != registered["ownership_id"]:
                                    raise WorkspaceError("registered replay ownership changed")
                                if (replay_owner["terminal_ns"] is None or replay_owner["holds"]
                                        or replay_state["attempt"] is not None
                                        or replay_state["condition"] != "clean"):
                                    replay_block = f"active_or_held_replay:{replay_id}"
                                writers.append(replay_writer)
                            if replay_block:
                                report.retained[path] = replay_block
                                continue
                            disposable = []
                            for selected in writers:
                                # Durable accepted references must resolve outside every deletion.
                                selected._generation()
                                selected_workspace = selected.workspace
                                safe_path(selected.run_dir, selected_workspace.disposable_relative)
                                if selected_workspace.root.exists():
                                    disposable.append(selected)
                                elif not selected.state()["purged"]:
                                    raise ReconstructionMiss("owned workspace disappeared without a purge receipt")
                            if not disposable:
                                report.retained[path] = "already_purged"
                                continue
                            inventory = {"schema": _SCHEMA, "ownership_id": owner["ownership_id"],
                                         "generation": state["generation"],
                                         "paths": [item.workspace.disposable_relative for item in disposable],
                                         "status": "deleting", "deleted": []}
                            receipt = safe_path(workspace.run_dir, "data/build/workspace/deletion.json")
                            _atomic(receipt, inventory)
                            for selected in disposable:
                                selected_state = selected.state()
                                selected_state["purged"] = True
                                selected._write_state(selected_state)
                                _remove_tree(selected.workspace.root)
                                removed = selected.workspace.disposable_relative
                                inventory["deleted"].append(removed)
                                _atomic(receipt, inventory)
                                report.deleted.append(str(selected.workspace.root))
                            inventory["status"] = "deleted"
                            _atomic(receipt, inventory)
            except LockUnavailable:
                report.retained[path] = "writer_or_resume_claim"
            except (WorkspaceError, ValueError, OSError) as error:
                report.failures[path] = str(error)
    return report
