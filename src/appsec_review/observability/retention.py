"""Fail-closed retention for explicitly sealed, exclusively owned offline artifact stores.

Ordinary run roots are held, never auto-enrolled or migrated. The catalog is an operator
ownership assertion, not job-state authority. Build workspace deletion remains its own API.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Iterator, Mapping, Sequence

from appsec_review.storage import FileLock, atomic_json, canonical_json
from appsec_review.storage.atomic import timed_fsync

CATALOG = "retention-catalog.json"
JOURNAL = "retention-journal.json"
SCHEMA = "appsec-review/retention-plan/1"
_CONTROL = {CATALOG, JOURNAL, ".retention.lock"}
_ROLES = {"artifact", "accepted_receipt", "audit_root", "configuration", "log", "build_workspace"}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _persist_journal(root: Path, value: Mapping[str, Any]) -> None:
    atomic_json(root / JOURNAL, value)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        timed_fsync(descriptor)
    finally:
        os.close(descriptor)


def _relative(value: Any) -> str:
    if (not isinstance(value, str) or "\\" in value or ":" in value
            or str(PurePosixPath(value)) != value or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/")) or len(value.split("/")) < 2):
        raise ValueError("unsafe retention object path")
    return value


@contextmanager
def _parent(root: Path, relative: str) -> Iterator[tuple[int, str]]:
    parts = _relative(relative).split("/")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def _inspect(root: Path, path: str, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    with _parent(root, path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or info.st_mode & 0o022):
                raise ValueError("uncertain retention object ownership")
            if info.st_size > max_bytes:
                raise ValueError("retention object exceeds verification bound")
            digest = hashlib.sha256()
            while data := os.read(fd, 65536):
                digest.update(data)
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("retention object changed while hashing")
            return {"sha256": digest.hexdigest(), "device": info.st_dev, "inode": info.st_ino,
                    "size": info.st_size, "mtime_ns": info.st_mtime_ns}
        finally:
            os.close(fd)


def _catalog(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if os.name != "posix":
        raise ValueError("retention apply requires private POSIX custody")
    if root.is_symlink() or root.resolve() != root.absolute():
        raise ValueError("retention root has symlinked ancestry")
    info = root.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("retention root requires exclusive owner-only permissions")
    path = root / CATALOG
    info_file = path.lstat()
    if (not stat.S_ISREG(info_file.st_mode) or info_file.st_nlink != 1
            or info_file.st_uid != os.getuid() or info_file.st_mode & 0o022
            or info_file.st_size > 4 * 1024 * 1024):
        raise ValueError("invalid or unbounded retention catalog")
    value = json.loads(path.read_bytes())
    if (not isinstance(value, dict) or value.get("schema") != "appsec-review/retention-catalog/1"
            or value.get("custody") != "sealed_offline"
            or not isinstance(value.get("owner"), str) or not value["owner"]
            or not isinstance(value.get("runs"), dict) or not isinstance(value.get("objects"), list)
            or len(value["objects"]) > 10000 or len(value["runs"]) > 1000):
        raise ValueError("unsupported or unbounded retention catalog")
    return value, {"device": info.st_dev, "inode": info.st_ino, "catalog_sha256": _digest(value)}


def plan_retention(root: Path, *, _resume: Mapping[str, Any] | None = None) -> dict[str, Any]:
    root = Path(root).absolute()
    base: dict[str, Any] = {"schema": SCHEMA, "root": str(root), "delete": [], "retained": [],
                            "holds": [], "scope": "sealed_offline_artifact_files_only"}
    try:
        catalog, custody = _catalog(root)
        if (root / JOURNAL).exists() and _resume is None:
            raise ValueError("interrupted_or_completed_deletion_requires_original_plan")
        nodes, snapshots = {}, {}
        roots = set()
        verified_bytes = 0
        for run_id, run in catalog["runs"].items():
            if (not isinstance(run_id, str) or not run_id or "/" in run_id or "\\" in run_id or run_id in {".", ".."}
                    or not isinstance(run, dict) or run.get("state") not in {"terminal", "active", "held"}
                    or not isinstance(run.get("leases"), list) or type(run.get("repair_hold")) is not bool):
                raise ValueError("unknown run root state or ownership")
        for item in catalog["objects"]:
            path = _relative(item["path"])
            if path in nodes or item.get("role") not in _ROLES:
                raise ValueError("duplicate object or unknown retention role")
            owner = item.get("run_id")
            if (owner not in catalog["runs"] or path.split("/")[0] != owner
                    or not isinstance(item.get("references"), list)
                    or type(item.get("retain")) is not bool):
                raise ValueError("unknown object ownership or reference coverage")
            run = catalog["runs"][owner]
            if (not isinstance(run, dict) or run.get("state") not in {"terminal", "active", "held"}
                    or not isinstance(run.get("leases"), list) or type(run.get("repair_hold")) is not bool):
                raise ValueError("unknown run state or holds")
            nodes[path] = item
            deleted = _resume is not None and path in _resume.get("authorized_absence", [])
            try:
                snapshot = _inspect(root, path, max_bytes=min(16 * 1024 * 1024,
                                                            64 * 1024 * 1024 - verified_bytes))
            except FileNotFoundError:
                if not deleted:
                    raise
                snapshot = _resume["snapshots"][path]
            if snapshot["sha256"] != item.get("sha256"):
                raise ValueError("retention object content identity changed")
            snapshots[path] = snapshot
            verified_bytes += snapshot["size"]
            protected_path = path.split("/")[1:3] in [
                ["data", name] for name in ("jobs", "logs", "configuration", "guidance", "orchestration", "build")]
            if (item["retain"] or item["role"] != "artifact" or protected_path or run["state"] != "terminal"
                    or run["leases"] or run["repair_hold"]):
                roots.add(path)
        # A sealed catalog must enumerate every object; unknown files and symlinks hold the store.
        count = 0
        stack = [root]
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    if count > 20000 or entry.is_symlink():
                        raise ValueError("unbounded inventory or symlinked object")
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        info = entry.stat(follow_symlinks=False)
                        if (info.st_mode & 0o022 or info.st_uid != os.getuid()
                                or directory == root and entry.name not in catalog["runs"]):
                            raise ValueError("uncertain directory ownership")
                        stack.append(path)
                    elif path.relative_to(root).as_posix() not in nodes and not (
                        directory == root and entry.name in _CONTROL
                    ):
                        raise ValueError("unregistered object or unknown root")
        for node in nodes.values():
            if any(reference not in nodes for reference in node["references"]):
                raise ValueError("unresolved cross-run reference")
        retained, pending = set(), list(roots)
        while pending:
            path = pending.pop()
            if path not in retained:
                retained.add(path)
                pending.extend(nodes[path]["references"])
        base.update(custody=custody, snapshots=snapshots, retained=sorted(retained),
                    delete=sorted(nodes.keys() - retained))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Failed admission is visible and makes deletion impossible, including legacy roots.
        base["holds"] = [{"reason": type(exc).__name__, "detail": str(exc)}]
    base["plan_id"] = _digest(base)
    return base


def apply_retention(root: Path, plan: Mapping[str, Any], *, apply: bool = False) -> dict[str, Any]:
    if not apply:
        return {"status": "dry_run", "plan": dict(plan)}
    root = Path(root).absolute()
    if (plan.get("schema") != SCHEMA or plan.get("root") != str(root) or plan.get("holds")
            or _digest({key: value for key, value in plan.items() if key != "plan_id"}) != plan.get("plan_id")):
        raise ValueError("invalid or held retention plan")
    _catalog(root)
    lock_path = root / ".retention.lock"
    if lock_path.exists() or lock_path.is_symlink():
        info = lock_path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError("uncertain retention lock ownership")
    with FileLock(lock_path):
        journal_path = root / JOURNAL
        if journal_path.exists():
            info = journal_path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or info.st_mode & 0o022
                    or info.st_size > 4 * 1024 * 1024):
                raise ValueError("uncertain or unbounded retention journal ownership")
            journal = json.loads(journal_path.read_bytes())
            if (journal.get("plan_id") != plan["plan_id"] or not isinstance(journal.get("deleted"), list)
                    or not set(journal["deleted"]) <= set(plan["delete"])
                    or journal.get("pending") not in [None, *plan["delete"]]):
                raise ValueError("retention journal does not match the original plan")
        else:
            journal = {"plan_id": plan["plan_id"], "deleted": [], "pending": None}
        absent = journal["deleted"] + ([journal["pending"]] if journal["pending"] else [])
        current = plan_retention(root, _resume={"authorized_absence": absent, "snapshots": plan["snapshots"]})
        if current != plan:
            raise ValueError("retention ownership, claims, references or files changed since planning")
        for relative in plan["delete"]:
            if relative in journal["deleted"]:
                continue
            journal["pending"] = relative
            _persist_journal(root, journal)
            if _catalog(root)[1] != plan["custody"]:
                raise ValueError("retention claims changed during apply")
            with _parent(root, relative) as (parent, name):
                try:
                    actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    if relative not in absent:
                        raise
                else:
                    expected = plan["snapshots"][relative]
                    if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                        expected["device"], expected["inode"], expected["size"], expected["mtime_ns"]
                    ) or not stat.S_ISREG(actual.st_mode):
                        raise ValueError("retention object replaced during apply")
                    os.unlink(name, dir_fd=parent)
                    timed_fsync(parent)
            journal["deleted"].append(relative)
            journal["pending"] = None
            _persist_journal(root, journal)
        return {"status": "applied", "deleted": journal["deleted"], "plan_id": plan["plan_id"]}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--plan", type=Path, help="Previously saved plan; required for apply")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if args.apply and not args.plan:
        parser.error("--apply requires the exact saved --plan")
    plan = json.loads(args.plan.read_text()) if args.plan else plan_retention(args.root)
    result = apply_retention(args.root, plan, apply=args.apply)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if plan["holds"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
