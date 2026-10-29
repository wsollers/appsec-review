"""Fresh, invocation-only custody for bounded acceptance fixtures.

The supervisor, not a producer test, publishes a seal after interpreter exit and owned
cleanup. These receipts authenticate bytes; they do not replace production validation.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time
from typing import Any, Iterator

from appsec_review.acceptance.staging import (
    CUSTODY_INPUT_FILE, SeedInputs, StageContext, StageKind,
)


MAX_FILES = 10_000
MAX_ENTRIES = 20_000
MAX_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 64
MAX_RECORD_BYTES = 8 * 1024 * 1024
SEED_SCHEMA = "appsec-review/acceptance-invocation-seed/1"
_DEADLINE: ContextVar[float | None] = ContextVar("acceptance_custody_deadline", default=None)


class CustodyError(ValueError):
    """A missing, changed, redirected, unbounded, or incompatible fixture."""


@contextmanager
def custody_deadline(deadline: float) -> Iterator[None]:
    token = _DEADLINE.set(deadline)
    try:
        _check_deadline()
        yield
        _check_deadline()
    finally:
        _DEADLINE.reset(token)


def _check_deadline() -> None:
    deadline = _DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise CustodyError("custody_deadline_exceeded")


def ordinary_path(path: Path, *, missing: bool = False) -> Path:
    """Check lexical ancestors before resolving, including Windows junctions."""
    path = Path(path)
    if not path.is_absolute():
        raise CustodyError(f"custody_path_not_absolute:{path}")
    for ancestor in (*reversed(path.parents), path):
        _check_deadline()
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError as error:
            if missing:
                continue
            raise CustodyError(f"custody_path_missing:{ancestor}") from error
        if (stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400):
            raise CustodyError(f"custody_redirected_path:{ancestor}")
        if ancestor != path and not stat.S_ISDIR(metadata.st_mode):
            raise CustodyError(f"custody_parent_not_directory:{ancestor}")
        if ancestor == path:
            if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                raise CustodyError(f"custody_not_ordinary:{path}")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise CustodyError(f"custody_hardlinked_file:{path}")
    if path.resolve() != path:
        raise CustodyError(f"custody_noncanonical_path:{path}")
    return path


def _identity(metadata: os.stat_result) -> tuple:
    # Windows 3.13 path stat and descriptor fstat expose different ctime semantics.
    # Compare stable file identity/size/mtime, and always hash the actual bytes.
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
            metadata.st_nlink, metadata.st_mode)


def _file_record(path: Path) -> dict[str, Any]:
    ordinary_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
        raise CustodyError(f"custody_file_not_bounded:{path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise CustodyError(f"custody_file_changed_while_opening:{path}")
        while chunk := stream.read(1024 * 1024):
            _check_deadline()
            size += len(chunk)
            if size > MAX_BYTES:
                raise CustodyError(f"custody_byte_limit:{path}")
            digest.update(chunk)
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise CustodyError(f"custody_file_changed_while_reading:{path}")
    ordinary_path(path)
    if size != before.st_size or _identity(path.stat()) != _identity(before):
        raise CustodyError(f"custody_file_changed_while_reading:{path}")
    return {"size": size, "sha256": digest.hexdigest(), "mode": stat.S_IMODE(before.st_mode)}


def _logical(value: str) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or PurePosixPath(value).is_absolute() or PurePosixPath(value).as_posix() != value
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise CustodyError(f"custody_invalid_logical_path:{value!r}")
    return value


def snapshot_tree(root: Path) -> dict[str, Any]:
    ordinary_path(root)
    if not root.is_dir():
        raise CustodyError("custody_root_not_directory")
    files: dict[str, dict] = {}
    directories: list[str] = []
    pending = [root]
    total = entries = 0
    names: set[str] = set()
    while pending:
        directory = pending.pop()
        _check_deadline()
        ordinary_path(directory)
        with os.scandir(directory) as children:
            for entry in children:
                _check_deadline()
                entries += 1
                if entries > MAX_ENTRIES:
                    raise CustodyError("custody_entry_limit")
                path = directory / entry.name
                relative = _logical(path.relative_to(root).as_posix())
                if len(PurePosixPath(relative).parts) > MAX_DEPTH:
                    raise CustodyError("custody_depth_limit")
                key = relative.casefold() if os.name == "nt" else relative
                if key in names:
                    raise CustodyError("custody_ambiguous_path")
                names.add(key)
                ordinary_path(path)
                if path.is_dir():
                    directories.append(relative)
                    pending.append(path)
                else:
                    if len(files) >= MAX_FILES:
                        raise CustodyError("custody_file_limit")
                    record = _file_record(path)
                    total += record["size"]
                    if total > MAX_BYTES:
                        raise CustodyError("custody_byte_limit")
                    files[relative] = record
    return {"files": dict(sorted(files.items())), "directories": sorted(directories),
            "file_count": len(files), "total_bytes": total}


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise CustodyError(f"custody_duplicate_record_key:{name}")
        value[name] = item
    return value


def _read_record(path: Path) -> dict[str, Any]:
    ordinary_path(path)
    if path.stat().st_size > MAX_RECORD_BYTES:
        raise CustodyError("custody_record_limit")
    try:
        payload = json.loads(path.read_bytes(), object_pairs_hook=_object)
    except (ValueError, UnicodeError) as error:
        raise CustodyError(f"custody_malformed_record:{path}") from error
    if not isinstance(payload, dict):
        raise CustodyError(f"custody_record_not_object:{path}")
    return payload


def _write_record(path: Path, payload: dict[str, Any]) -> str:
    ordinary_path(path, missing=True)
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
               + "\n").encode("utf-8")
    if len(encoded) > MAX_RECORD_BYTES:
        raise CustodyError("custody_record_limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_deadline()
    # Exclusive publication: a previous invocation or torn receipt is never overwritten.
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return _file_record(path)["sha256"]


def _binding(context: StageContext, seed_root: Path) -> dict[str, Any]:
    return {"invocation_id": context.invocation_id, "variant": context.variant,
            "tested_commit": context.tested_commit,
            "source_identities": dict(context.source_identities), "seed_root": str(seed_root)}


def _verify_source_manifest(context: StageContext) -> None:
    expected = context.source_identities.get("source-manifest")
    if expected is not None and _file_record(
            context.workspace_root / "source-identities.json")["sha256"] != expected:
        raise CustodyError("custody_source_manifest_changed")


def capture_inputs(context: StageContext) -> dict[str, Any]:
    """Pin PREPARE's declared immutable paths and declaration itself, using actual bytes."""
    root = context.work_root if context.kind is StageKind.PRODUCER else context.seed_root
    assert root is not None
    _verify_source_manifest(context)
    declaration = _read_record(root / CUSTODY_INPUT_FILE)
    try:
        selected = SeedInputs.from_mapping(declaration)
    except (ValueError, TypeError) as error:
        raise CustodyError("custody_invalid_seed_inputs") from error
    if selected.variant != context.variant:
        raise CustodyError("custody_input_variant_mismatch")
    tree = snapshot_tree(root)
    if len(selected.read_only_paths) > MAX_ENTRIES:
        raise CustodyError("custody_immutable_path_limit")
    paths = tuple(dict.fromkeys((*selected.read_only_paths, CUSTODY_INPUT_FILE)))
    for name in paths:
        if name not in tree["files"] and name not in tree["directories"]:
            raise CustodyError(f"custody_immutable_input_missing:{name}")
    files = {name: record for name, record in tree["files"].items()
             if any(name == path or name.startswith(path + "/") for path in paths)}
    directories = [name for name in tree["directories"]
                   if any(name == path or name.startswith(path + "/") for path in paths)]
    return {"schema": "appsec-review/acceptance-immutable-inputs/1", **_binding(context, root),
            "read_only_paths": list(paths), "files": files, "directories": directories}


def verify_inputs(context: StageContext, expected: dict[str, Any]) -> None:
    if capture_inputs(context) != expected:
        raise CustodyError("custody_immutable_inputs_changed")


def checkpoint_seed(context: StageContext, path: Path) -> str:
    if context.kind is not StageKind.PRODUCER:
        raise CustodyError("custody_checkpoint_requires_producer")
    if not path.is_relative_to(context.workspace_root) or path.is_relative_to(context.work_root):
        raise CustodyError("custody_checkpoint_must_be_outside_seed")
    return _write_record(path, {
        "schema": "appsec-review/acceptance-checkpoint/1", **_binding(context, context.work_root),
        "obligation_id": context.obligation_id, "tree": snapshot_tree(context.work_root)})


def verify_checkpoint(context: StageContext, path: Path, expected_sha256: str) -> None:
    if _file_record(path)["sha256"] != expected_sha256:
        raise CustodyError("custody_checkpoint_identity_changed")
    expected = _read_record(path)
    if (expected.get("schema") != "appsec-review/acceptance-checkpoint/1"
            or any(expected.get(key) != value
                   for key, value in _binding(context, context.work_root).items())
            or expected.get("tree") != snapshot_tree(context.work_root)):
        raise CustodyError("custody_predecessor_tree_changed")


def seal_seed(context: StageContext, manifest_path: Path) -> str:
    if context.kind is not StageKind.PRODUCER:
        raise CustodyError("custody_seal_requires_producer")
    manifest_path = Path(manifest_path)
    if (not manifest_path.is_relative_to(context.workspace_root)
            or manifest_path.is_relative_to(context.work_root)):
        raise CustodyError("custody_manifest_must_be_outside_seed")
    inputs = capture_inputs(context)
    tree = snapshot_tree(context.work_root)
    return _write_record(manifest_path, {
        "schema": SEED_SCHEMA, **_binding(context, context.work_root),
        "producer_obligation": context.obligation_id, "immutable_inputs": inputs, "tree": tree})


def verify_seed(context: StageContext) -> dict[str, Any]:
    if context.kind is not StageKind.CONSUMER:
        raise CustodyError("custody_verify_requires_consumer")
    _verify_source_manifest(context)
    assert context.manifest_path is not None and context.seed_root is not None
    if context.manifest_path.is_relative_to(context.seed_root):
        raise CustodyError("custody_manifest_must_be_outside_seed")
    if _file_record(context.manifest_path)["sha256"] != context.manifest_sha256:
        raise CustodyError("custody_manifest_identity_changed")
    manifest = _read_record(context.manifest_path)
    expected_keys = {"schema", "invocation_id", "variant", "tested_commit", "source_identities",
                     "seed_root", "producer_obligation", "immutable_inputs", "tree"}
    if (set(manifest) != expected_keys or manifest["schema"] != SEED_SCHEMA
            or any(manifest.get(key) != value
                   for key, value in _binding(context, context.seed_root).items())):
        raise CustodyError("custody_manifest_binding_mismatch")
    if manifest["tree"] != snapshot_tree(context.seed_root):
        raise CustodyError("custody_sealed_tree_changed")
    verify_inputs(context, manifest["immutable_inputs"])
    return manifest


def copy_receipt_path(destination: Path) -> Path:
    return destination.with_name(destination.name + ".custody.json")


def _copy_file(source: Path, destination: Path) -> None:
    ordinary_path(source)
    ordinary_path(destination, missing=True)
    with source.open("rb") as reader, destination.open("xb") as writer:
        while chunk := reader.read(1024 * 1024):
            _check_deadline()
            writer.write(chunk)
    # Admission keys, immutable evidence and executable fixtures retain their ordinary
    # permission bits. New writable aliases would change production validation semantics.
    destination.chmod(stat.S_IMODE(source.stat().st_mode))


def materialize_seed(context: StageContext, destination: Path | None = None) -> Path:
    """Make a newly verified ordinary copy, never rewriting frozen absolute references."""
    manifest = verify_seed(context)
    assert context.seed_root is not None
    destination = context.work_root if destination is None else Path(destination)
    if (not destination.is_relative_to(context.work_root)
            or destination.is_relative_to(context.seed_root)
            or context.seed_root.is_relative_to(destination)):
        raise CustodyError("custody_copy_must_be_private")
    ordinary_path(destination, missing=True)
    if destination.exists():
        raise CustodyError("custody_copy_destination_exists")
    receipt = copy_receipt_path(destination)
    ordinary_path(receipt, missing=True)
    if receipt.exists():
        raise CustodyError("custody_copy_receipt_exists")
    started = time.monotonic()
    destination.mkdir(parents=True, exist_ok=False)
    for relative in manifest["tree"]["directories"]:
        _check_deadline()
        (destination / relative).mkdir(parents=True, exist_ok=True)
    for relative in manifest["tree"]["files"]:
        _check_deadline()
        _copy_file(context.seed_root / relative, destination / relative)
    if snapshot_tree(destination) != manifest["tree"]:
        raise CustodyError("custody_copy_bytes_changed")
    # Catch a changing source, too; never bless a copy from an advanced producer tree.
    verify_seed(context)
    _write_record(receipt, {
        "schema": "appsec-review/acceptance-materialization/1",
        **_binding(context, context.seed_root), "obligation_id": context.obligation_id,
        "destination": str(destination), "manifest_sha256": context.manifest_sha256,
        "file_count": manifest["tree"]["file_count"], "copied_bytes": manifest["tree"]["total_bytes"],
        "duration_seconds": time.monotonic() - started, "verified": True})
    return destination
