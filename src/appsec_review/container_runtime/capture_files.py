"""Post-build file evidence derived from captured syscall events.

Nothing here runs during the build. After the traced command exits, file events are resolved to
absolute container paths, using strace's ``-y`` directory annotations when present and otherwise
per-process working directories reconstructed from fork and directory-change events. Paths are
then classified against the container's roots:

* workspace files become workspace-relative and are deduplicated by path. Unchanged copies of the
  accepted target snapshot reuse its SHA-256; everything else is hashed once, after the build.
* files on the read-only image filesystem are identified by image ID plus path, never hashed.
* ephemeral (tmpfs) and virtual (proc/sys/dev) paths are counted, not hashed.

Compiler response files (``@file`` arguments) that a process actually opened are copied into the
capture so their arguments survive the build workspace.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import time
from typing import Any, Iterable, Iterator, Mapping

from appsec_review.storage import canonical_json


INVENTORY_SCHEMA = "appsec-review/build-file-inventory/1"
RESPONSE_FILE_SCHEMA = "appsec-review/build-response-file/1"
_REDACTED = "<redacted"
_FILE_KINDS = frozenset({"file_open", "file_rename", "file_link", "file_unlink"})


@dataclass(frozen=True, slots=True)
class CaptureRoots:
    """How container paths map to host evidence for one captured command."""

    workspace_logical: str
    workspace_host: Path
    capture_logical: str
    image_id: str
    initial_directory: str
    ephemeral: tuple[str, ...] = ("/tmp", "/var/tmp", "/run", "/dev/shm")
    virtual: tuple[str, ...] = ("/proc", "/sys", "/dev")

    def classify(self, path: str) -> tuple[str, str]:
        """Return (root, key): workspace keys are relative; other keys are absolute."""
        def under(root: str) -> bool:
            return path == root or path.startswith(root.rstrip("/") + "/")

        if under(self.capture_logical):
            return "capture", path
        if under(self.workspace_logical):
            relative = path[len(self.workspace_logical):].lstrip("/")
            return ("workspace", relative) if relative else ("workspace-root", path)
        if any(under(root) for root in self.ephemeral):
            return "ephemeral", path
        if any(under(root) for root in self.virtual):
            return "virtual", path
        return "image", path


@dataclass(frozen=True, slots=True)
class ResolvedFileEvent:
    timestamp_ns: int
    ordinal: int
    pid: int
    operation: str  # read | write | read-write | rename-source | rename-target | link-target | unlink
    path: str
    succeeded: bool
    creates: bool = False


def _absolute(path: str, directory: str | None, cwd: str) -> str:
    base = path if path.startswith("/") else posixpath.join(directory or cwd, path)
    normalized = posixpath.normpath(base)
    return "/" + normalized.lstrip("/")


def resolve_file_events(events: Iterable[Mapping[str, Any]], initial_directory: str
                        ) -> tuple[list[ResolvedFileEvent], dict[str, int]]:
    """Resolve file events to absolute paths in global time order.

    Working directories are inherited across forks and updated by successful directory
    changes, so legacy calls without a directory annotation still resolve correctly.
    """
    relevant = sorted(
        (event for event in events
         if event.get("kind") in _FILE_KINDS | {"process_fork", "directory_change"}),
        key=lambda event: (int(event.get("timestamp_ns", 0)), int(event.get("ordinal", 0))))
    cwd: dict[int, str] = {}
    resolved: list[ResolvedFileEvent] = []
    skipped = {"redacted": 0, "truncated": 0}

    def directory_of(pid: int) -> str:
        return cwd.get(pid, initial_directory)

    for event in relevant:
        kind, pid = event["kind"], int(event.get("pid", 0))
        if kind == "process_fork":
            cwd[int(event.get("child_pid", -1))] = directory_of(pid)
            continue
        values = [str(event.get(name, "")) for name in ("path", "source", "target", "directory",
                                                        "resolved", "source_directory",
                                                        "target_directory") if name in event]
        if any(value.startswith(_REDACTED) for value in values):
            skipped["redacted"] += 1
            continue
        if event.get("path_truncated"):
            skipped["truncated"] += 1
            continue
        ok = int(event.get("result", -1)) >= 0
        stamp, ordinal = int(event.get("timestamp_ns", 0)), int(event.get("ordinal", 0))
        if kind == "directory_change":
            if ok:
                cwd[pid] = _absolute(str(event["path"]), event.get("directory"), directory_of(pid))
            continue
        if kind == "file_open":
            path = (str(event["resolved"]) if ok and event.get("resolved") else
                    _absolute(str(event["path"]), event.get("directory"), directory_of(pid)))
            resolved.append(ResolvedFileEvent(stamp, ordinal, pid, str(event.get("access", "read")),
                                              _absolute(path, None, "/"), ok,
                                              bool(event.get("creates", False))))
        elif kind == "file_unlink":
            path = _absolute(str(event["path"]), event.get("directory"), directory_of(pid))
            resolved.append(ResolvedFileEvent(stamp, ordinal, pid, "unlink", path, ok))
        else:
            source = _absolute(str(event["source"]), event.get("source_directory"), directory_of(pid))
            target = _absolute(str(event["target"]), event.get("target_directory"), directory_of(pid))
            if kind == "file_rename":
                resolved.append(ResolvedFileEvent(stamp, ordinal, pid, "rename-source", source, ok))
                resolved.append(ResolvedFileEvent(stamp, ordinal, pid, "rename-target", target, ok, True))
            else:
                resolved.append(ResolvedFileEvent(stamp, ordinal, pid, "link-target", target, ok, True))
    return resolved, skipped


def process_directories(events: Iterable[Mapping[str, Any]], initial_directory: str
                        ) -> dict[tuple[int, int], str]:
    """Map (pid, exec ordinal) to the working directory each successful exec ran in."""
    ordered = sorted((event for event in events
                      if event.get("kind") in {"process_fork", "directory_change", "process_exec"}),
                     key=lambda event: (int(event.get("timestamp_ns", 0)), int(event.get("ordinal", 0))))
    cwd: dict[int, str] = {}
    result: dict[tuple[int, int], str] = {}
    for event in ordered:
        pid = int(event.get("pid", 0))
        current = cwd.get(pid, initial_directory)
        if event["kind"] == "process_fork":
            cwd[int(event.get("child_pid", -1))] = current
        elif event["kind"] == "directory_change":
            path = str(event.get("path", ""))
            if int(event.get("result", -1)) == 0 and not path.startswith(_REDACTED):
                cwd[pid] = _absolute(path, event.get("directory"), current)
        else:
            result[(pid, int(event.get("ordinal", 0)))] = current
    return result


def snapshot_response_files(events: list[Mapping[str, Any]], roots: CaptureRoots,
                            capture_root: Path, *, count_limit: int, bytes_limit: int
                            ) -> tuple[list[dict[str, Any]], list[str]]:
    """Copy ``@file`` arguments that the executing process opened successfully.

    A response file outside the workspace, deleted before the snapshot, or over the size bound is
    named as a gap; its arguments are otherwise lost with the build workspace.
    """
    directories = process_directories(events, roots.initial_directory)
    opened: dict[int, set[str]] = {}
    file_events, _skipped = resolve_file_events(events, roots.initial_directory)
    for item in file_events:
        if item.succeeded and item.operation in {"read", "read-write"}:
            opened.setdefault(item.pid, set()).add(item.path)
    snapshots: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: dict[str, dict[str, Any]] = {}
    destination = capture_root / "response-files"
    for event in events:
        if event.get("kind") != "process_exec" or int(event.get("result", -1)) != 0:
            continue
        pid, ordinal = int(event.get("pid", 0)), int(event.get("ordinal", 0))
        argv = event.get("argv") or []
        for index, argument in enumerate(argv):
            if not isinstance(argument, str) or not argument.startswith("@") or len(argument) < 2:
                continue
            if argument.startswith(_REDACTED) or argument[1:].startswith(_REDACTED):
                continue
            path = _absolute(argument[1:], None, directories.get((pid, ordinal), roots.initial_directory))
            if path not in opened.get(pid, set()):
                continue  # an "@" argument the process never read is not a response file
            reference = {"pid": pid, "exec_ordinal": ordinal, "argv_index": index}
            if path in seen:
                seen[path]["references"].append(reference)
                continue
            root, key = roots.classify(path)
            if root != "workspace":
                gaps.append(f"response file outside the workspace was not retained: {path}")
                continue
            host = roots.workspace_host / Path(*PurePosixPath(key).parts)
            if not host.is_file() or host.is_symlink():
                gaps.append(f"response file was removed before it could be retained: {key}")
                continue
            if host.stat().st_size > bytes_limit:
                gaps.append(f"response file exceeds the {bytes_limit}-byte bound: {key}")
                continue
            if len(snapshots) >= count_limit:
                gaps.append("response file retention limit reached")
                break
            destination.mkdir(exist_ok=True)
            member = destination / f"{len(snapshots) + 1:06d}.rsp"
            shutil.copyfile(host, member)
            member.chmod(0o644)
            entry = {"schema": RESPONSE_FILE_SCHEMA, "path": key,
                     "uri": member.relative_to(capture_root).as_posix(),
                     "references": [reference]}
            seen[path] = entry
            snapshots.append(entry)
    return snapshots, gaps


def _sha256(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def build_file_inventory(events: Iterable[Mapping[str, Any]], roots: CaptureRoots, output: Path, *,
                         snapshot: Mapping[str, Mapping[str, Any]] | None, count_limit: int
                         ) -> dict[str, Any]:
    """Write a deduplicated, hashed inventory of files the build touched, with timing.

    Failed opens (search-path probes) are counted but never listed. A workspace file that was
    modified after a process had read it is flagged per entry and counted, not raised as a
    coverage gap: build systems routinely rewrite files they read (caches, logs). Consumers that
    treat such a file as a translation-unit input must not trust its post-build hash.
    """
    started = time.monotonic()
    resolved, skipped = resolve_file_events(events, roots.initial_directory)
    resolve_seconds = time.monotonic() - started
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    failed = 0
    other: dict[str, int] = {"capture": 0, "virtual": 0, "workspace-root": 0}
    for item in resolved:
        if not item.succeeded:
            failed += 1
            continue
        root, key = roots.classify(item.path)
        if root in other:
            other[root] += 1
            continue
        entry = entries.setdefault((root, key), {
            "root": root, "path": key, "reads": 0, "writes": 0, "created": False,
            "renamed_away": False, "unlinked": False, "first_read_ns": None,
            "last_mutation_ns": None})
        if item.operation in {"read", "read-write"}:
            entry["reads"] += 1
            if entry["first_read_ns"] is None:
                entry["first_read_ns"] = item.timestamp_ns
        if item.operation in {"write", "read-write", "rename-target", "link-target"} or item.creates:
            entry["writes"] += 1
            entry["last_mutation_ns"] = item.timestamp_ns
        if item.creates:
            entry["created"] = True
        if item.operation in {"rename-source", "unlink"}:
            entry["renamed_away" if item.operation == "rename-source" else "unlinked"] = True
            entry["last_mutation_ns"] = item.timestamp_ns

    hash_started = time.monotonic()
    counts = {"unique_paths": len(entries), "failed_opens": failed, "hashed_files": 0,
              "hashed_bytes": 0, "snapshot_reused": 0, "image_files": 0, "ephemeral_files": 0,
              "absent": 0, "directories": 0, "symlinks": 0, "modified_after_read": 0,
              "skipped_redacted": skipped["redacted"], "skipped_truncated": skipped["truncated"],
              **{f"{name.replace('-', '_')}_events": value for name, value in other.items()}}
    gaps: list[str] = []
    written = 0
    capped = False
    with output.open("xb") as stream:
        for (root, key), entry in sorted(entries.items()):
            if written >= count_limit:
                capped = True
                break
            record: dict[str, Any] = {"schema": INVENTORY_SCHEMA, "root": root, "path": key,
                                      "reads": entry["reads"], "writes": entry["writes"],
                                      "created": entry["created"]}
            if root == "image":
                record.update(image_id=roots.image_id, status="immutable")
                counts["image_files"] += 1
            elif root == "ephemeral":
                record["status"] = "ephemeral"
                counts["ephemeral_files"] += 1
            else:
                modified = (entry["first_read_ns"] is not None and entry["last_mutation_ns"] is not None
                            and entry["last_mutation_ns"] > entry["first_read_ns"])
                record["modified_after_read"] = modified
                counts["modified_after_read"] += int(modified)
                host = roots.workspace_host / Path(*PurePosixPath(key).parts)
                known = (snapshot or {}).get(key)
                if host.is_symlink():
                    record["status"] = "symlink"
                    counts["symlinks"] += 1
                elif host.is_dir():
                    record["status"] = "directory"
                    counts["directories"] += 1
                elif not host.is_file():
                    record["status"] = "absent"
                    record["renamed_away"], record["unlinked"] = entry["renamed_away"], entry["unlinked"]
                    counts["absent"] += 1
                elif (known is not None and entry["writes"] == 0 and not entry["created"]
                      and host.stat().st_size == int(known["size_bytes"])):
                    record.update(status="snapshot", sha256=str(known["sha256"]),
                                  size_bytes=int(known["size_bytes"]))
                    counts["snapshot_reused"] += 1
                else:
                    digest, size = _sha256(host)
                    record.update(status="hashed", sha256=digest, size_bytes=size)
                    counts["hashed_files"] += 1
                    counts["hashed_bytes"] += size
            stream.write(canonical_json(record))
            written += 1
    if capped:
        gaps.append("file inventory retention limit reached")
    if skipped["truncated"]:
        gaps.append(f"{skipped['truncated']} file events had truncated paths and were not inventoried")
    finished = time.monotonic()
    return {"counts": {**counts, "retained": written}, "capped": capped, "gaps": gaps,
            "timing_seconds": {"resolve": round(resolve_seconds, 6),
                               "hash": round(finished - hash_started, 6),
                               "total": round(finished - started, 6)}}


def read_events(path: Path) -> Iterator[Mapping[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)
