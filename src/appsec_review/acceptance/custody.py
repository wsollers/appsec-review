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
from uuid import uuid4

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


def _checked_path(path: Path, *, missing: bool = False, producer_alias: bool = False) -> Path:
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
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1 and not producer_alias:
                raise CustodyError(f"custody_hardlinked_file:{path}")
    if path.resolve() != path:
        raise CustodyError(f"custody_noncanonical_path:{path}")
    return path


def ordinary_path(path: Path, *, missing: bool = False) -> Path:
    """Check lexical ancestors and require single-link files, including on Windows."""
    return _checked_path(path, missing=missing)


def _identity(metadata: os.stat_result) -> tuple:
    # Windows 3.13 path stat and descriptor fstat expose different ctime semantics.
    # Compare stable file identity/size/mtime, and always hash the actual bytes.
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
            metadata.st_nlink, metadata.st_mode)


def _read_file_record(path: Path, *, producer_alias: bool = False) -> tuple[dict[str, Any], os.stat_result]:
    _checked_path(path, producer_alias=producer_alias)
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
    _checked_path(path, producer_alias=producer_alias)
    if size != before.st_size or _identity(path.stat()) != _identity(before):
        raise CustodyError(f"custody_file_changed_while_reading:{path}")
    return {"size": size, "sha256": digest.hexdigest(), "mode": stat.S_IMODE(before.st_mode)}, before


def _file_record(path: Path) -> dict[str, Any]:
    return _read_file_record(path)[0]


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


def _declared_input_paths(context: StageContext) -> tuple[str, ...]:
    declaration = _read_record(context.work_root / CUSTODY_INPUT_FILE)
    try:
        selected = SeedInputs.from_mapping(declaration)
    except (ValueError, TypeError) as error:
        raise CustodyError("custody_invalid_seed_inputs") from error
    if selected.variant != context.variant or len(selected.read_only_paths) > MAX_ENTRIES:
        raise CustodyError("custody_input_variant_or_path_limit")
    return tuple(dict.fromkeys((*selected.read_only_paths, CUSTODY_INPUT_FILE)))


def _reserved_input(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    return (
        parts[0] in {"target", "appsec-review.toml", "capacity-overlay.toml", "overlay.toml",
                     "fixture-state.json", CUSTODY_INPUT_FILE, "driver"}
        or parts[:2] == ("data", "target")
        or (len(parts) >= 4 and parts[0] == "runs" and parts[2:4] == ("data", "configuration"))
        or parts[-1].endswith(".custody.json"))


def producer_link_path(context: StageContext, path: Path) -> Path:
    """Only mutable producer publication may temporarily share an inode.

    The built-in source/configuration loci are protected even before PREPARE publishes
    its declaration. Once present, that closed declaration also protects custom loci.
    """
    if context.kind is not StageKind.PRODUCER or not path.is_relative_to(context.work_root):
        raise CustodyError("custody_link_requires_producer_output")
    _checked_path(path, missing=True, producer_alias=True)
    relative = _logical(path.relative_to(context.work_root).as_posix())
    paths = _declared_input_paths(context) if (context.work_root / CUSTODY_INPUT_FILE).exists() else ()
    if _reserved_input(relative) or any(
            relative == item or relative.startswith(item + "/") for item in paths):
        raise CustodyError("custody_link_to_immutable_or_reporting_path")
    return path


def _producer_tree(root: Path) -> tuple[dict[str, Any], dict[str, os.stat_result]]:
    """Inspect aliases without admitting them to an ordinary snapshot or consumer."""
    ordinary_path(root)
    pending = [root]
    files, identities, directories, names = {}, {}, [], set()
    entries = total = 0
    while pending:
        directory = pending.pop()
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
                _checked_path(path, producer_alias=True)
                if path.is_dir():
                    directories.append(relative)
                    pending.append(path)
                    continue
                if len(files) >= MAX_FILES:
                    raise CustodyError("custody_file_limit")
                record, metadata = _read_file_record(path, producer_alias=True)
                if (type(metadata.st_dev) is not int or metadata.st_dev < 0
                        or type(metadata.st_ino) is not int or metadata.st_ino <= 0
                        or type(metadata.st_nlink) is not int or metadata.st_nlink < 1):
                    raise CustodyError(f"custody_publication_identity_unsupported:{relative}")
                total += record["size"]
                if total > MAX_BYTES:
                    raise CustodyError("custody_byte_limit")
                files[relative], identities[relative] = record, metadata
    return {"files": dict(sorted(files.items())), "directories": sorted(directories),
            "file_count": len(files), "total_bytes": total}, identities


def _inputs_from_tree(context: StageContext, tree: dict, paths: tuple[str, ...]) -> dict[str, Any]:
    for name in paths:
        if name not in tree["files"] and name not in tree["directories"]:
            raise CustodyError(f"custody_immutable_input_missing:{name}")
    return {
        "schema": "appsec-review/acceptance-immutable-inputs/1", **_binding(context, context.work_root),
        "read_only_paths": list(paths),
        "files": {name: record for name, record in tree["files"].items()
                  if any(name == path or name.startswith(path + "/") for path in paths)},
        "directories": [name for name in tree["directories"]
                        if any(name == path or name.startswith(path + "/") for path in paths)]}


def _publication_groups(context: StageContext, tree: dict, identities: dict,
                        immutable: tuple[str, ...],
                        groups: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    from appsec_review.storage.shared import NAMED_LAYOUTS, OBJECTS, _binding_path, reference, verify_binding
    from appsec_review.storage.validation import current_validation, validation_scope

    grouped = {}
    for relative, metadata in identities.items():
        grouped.setdefault((metadata.st_dev, metadata.st_ino), []).append(relative)
    groups = [] if groups is None else groups
    for (device, inode), members in sorted(grouped.items()):
        if len(members) == 1 and identities[members[0]].st_nlink == 1:
            continue
        members.sort()
        group = {
            "device": device, "inode": inode, "link_count": identities[members[0]].st_nlink,
            "enumerated_member_count": len(members),
            "observed_link_counts": {name: identities[name].st_nlink for name in members},
            "members": members, "bindings": [], "replaced": [], "eligible": False,
            **tree["files"][members[0]]}
        groups.append(group)
        if any(identities[name].st_nlink != len(members) for name in members):
            raise CustodyError("custody_publication_external_or_unaccounted_alias")
        if any(_reserved_input(name) or any(name == item or name.startswith(item + "/")
                                          for item in immutable) for name in members):
            raise CustodyError("custody_publication_immutable_alias")
        run_ids = {PurePosixPath(name).parts[:2] for name in members}
        if len(run_ids) != 1:
            raise CustodyError("custody_publication_cross_run_alias")
        prefix = next(iter(run_ids))
        if len(prefix) != 2 or prefix[0] != "runs" or prefix[1] == "metadata":
            raise CustodyError("custody_publication_unclassified_alias")
        run_root = context.work_root.joinpath(*prefix)
        group["run_root"] = str(run_root)
        records = [tree["files"][name] for name in members]
        if any(record != records[0] for record in records):
            raise CustodyError("custody_publication_alias_bytes_or_modes_changed")
        record = records[0]
        object_name = f"{OBJECTS}/{record['sha256']}"
        logical = {name: (context.work_root / name).relative_to(run_root).as_posix() for name in members}
        if list(logical.values()).count(object_name) != 1:
            raise CustodyError("custody_publication_requires_exact_byte_object")
        bindings = []
        if current_validation(run_root) is not None:
            raise CustodyError("custody_publication_requires_fresh_validation")
        with validation_scope(run_root):
            for name, relative in logical.items():
                _check_deadline()
                if relative == object_name:
                    continue
                namespaces = [namespace for namespace, layouts in NAMED_LAYOUTS.items()
                              if relative.startswith(layouts)]
                obj = {"path": relative, "sha256": record["sha256"], "size_bytes": record["size"]}
                matches = []
                for namespace in namespaces:
                    binding_path = run_root / _binding_path(namespace, obj)
                    ordinary_path(binding_path, missing=True)
                    if not binding_path.exists():
                        continue
                    binding_ref = reference(run_root, binding_path)
                    value = verify_binding(run_root, binding_ref)
                    if value["namespace"] != namespace or value["object"] != obj:
                        raise CustodyError(f"custody_publication_binding_mismatch:{name}")
                    matches.append(binding_ref)
                # Cell/check layouts share a prefix; the actual published binding
                # must identify one registered namespace, not prefix ordering.
                if len(matches) != 1:
                    raise CustodyError(f"custody_publication_unclassified_or_ambiguous_alias:{name}")
                bindings.extend(matches)
        group.update(bindings=bindings, eligible=True)
    return groups


def _recheck_publication_group(context: StageContext, group: dict, remaining: list[str]) -> None:
    for name in remaining:
        record, metadata = _read_file_record(context.work_root / name, producer_alias=True)
        if ((metadata.st_dev, metadata.st_ino, metadata.st_nlink)
                != (group["device"], group["inode"], len(remaining))
                or record != {key: group[key] for key in ("sha256", "size", "mode")}):
            raise CustodyError("custody_publication_group_changed_before_replacement")


def _detach_publication_member(context: StageContext, group: dict, remaining: list[str], receipt: dict) -> dict:
    path = context.work_root / remaining[0]
    pending = path.with_name(".custody-" + uuid4().hex)
    expected = {key: group[key] for key in ("sha256", "size", "mode")}
    group["pending"] = str(pending)
    _recheck_publication_group(context, group, remaining)
    ordinary_path(pending, missing=True)
    # Both handles close before replacement, also on Windows. No readonly-bit relaxation.
    with path.open("rb") as reader, pending.open("xb") as writer:
        metadata = os.fstat(reader.fileno())
        if (metadata.st_dev, metadata.st_ino, metadata.st_nlink) != (
                group["device"], group["inode"], len(remaining)):
            raise CustodyError("custody_publication_source_handle_changed")
        size = 0
        while chunk := reader.read(1024 * 1024):
            _check_deadline()
            size += len(chunk)
            if size > expected["size"]:
                raise CustodyError("custody_publication_source_grew")
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    pending.chmod(expected["mode"])
    if _file_record(pending) != expected:
        raise CustodyError("custody_publication_copy_changed")
    receipt["verified_copy_files"] += 1
    receipt["verified_copy_bytes"] += size
    _recheck_publication_group(context, group, remaining)
    _check_deadline()
    os.replace(pending, path)
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    actual, metadata = _read_file_record(path)
    if actual != expected or (metadata.st_dev, metadata.st_ino) == (group["device"], group["inode"]):
        raise CustodyError("custody_publication_replacement_changed")
    group.pop("pending")
    return {"path": remaining[0], "device": metadata.st_dev, "inode": metadata.st_ino,
            "link_count": metadata.st_nlink}


def detach_producer_outputs(context: StageContext, receipt_path: Path, *, producer_result: dict,
                            frozen_inputs: dict | None = None) -> dict[str, Any]:
    """Detach only fully accounted registered output aliases after successful owned cleanup.

    A failed or partial operation is never retried or accepted. The strict snapshot APIs
    remain unchanged and must succeed before the supervisor publishes a checkpoint/seal.
    """
    cleanup = producer_result.get("cleanup", {})
    if (context.kind is not StageKind.PRODUCER or producer_result.get("outcome") != "completed"
            or producer_result.get("exit_code") != 0 or cleanup.get("confirmed") is not True
            or cleanup.get("started") is not True or cleanup.get("remaining_processes") != 0
            or cleanup.get("boundary") not in {"windows_job", "linux_process_group"}):
        raise CustodyError("custody_publication_requires_successful_owned_cleanup")
    if (not receipt_path.is_relative_to(context.workspace_root)
            or receipt_path.is_relative_to(context.work_root)):
        raise CustodyError("custody_publication_receipt_must_be_outside_seed")
    started = time.monotonic()
    receipt = {
        "schema": "appsec-review/acceptance-producer-detachment/1",
        **_binding(context, context.work_root), "obligation_id": context.obligation_id,
        "groups": [], "verified_copy_files": 0, "verified_copy_bytes": 0,
        "inspected_files": None, "inspected_bytes": None,
        "replaced_files": 0, "outcome": "failed",
        "cleanup": dict(cleanup)}
    try:
        _check_deadline()
        ordinary_path(receipt_path, missing=True)
        if receipt_path.exists():
            raise CustodyError("custody_publication_receipt_exists")
        _verify_source_manifest(context)
        paths = _declared_input_paths(context)
        tree, identities = _producer_tree(context.work_root)
        receipt.update(inspected_files=tree["file_count"], inspected_bytes=tree["total_bytes"])
        _publication_groups(context, tree, identities, paths, receipt["groups"])
        inputs = _inputs_from_tree(context, tree, paths)
        if frozen_inputs is not None and inputs != frozen_inputs:
            raise CustodyError("custody_immutable_inputs_changed_before_detachment")
        before, before_identities = _producer_tree(context.work_root)
        if (tree != before or any(_identity(before_identities[name]) != _identity(metadata)
                                  for name, metadata in identities.items())):
            raise CustodyError("custody_publication_tree_changed_before_detachment")
        for group in receipt["groups"]:
            remaining = list(group["members"])
            while remaining:
                replaced = _detach_publication_member(context, group, remaining, receipt)
                group["replaced"].append(replaced)
                receipt["replaced_files"] += 1
                remaining.pop(0)
        if snapshot_tree(context.work_root) != tree:
            raise CustodyError("custody_publication_tree_changed_after_detachment")
        verify_inputs(context, inputs)
        _check_deadline()
        receipt["outcome"] = "detached" if receipt["groups"] else "ordinary"
    except BaseException as error:
        receipt["reason"] = f"{type(error).__name__}:{error}"
        raise
    finally:
        receipt["duration_seconds"] = time.monotonic() - started
        # A failure receipt is bounded accounting, not an extension or a usable seed.
        # Its time is still charged by the caller's case/suite clock.
        token = _DEADLINE.set(None) if receipt["outcome"] == "failed" else None
        try:
            _write_record(receipt_path, receipt)
        finally:
            if token is not None:
                _DEADLINE.reset(token)
    return receipt


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
