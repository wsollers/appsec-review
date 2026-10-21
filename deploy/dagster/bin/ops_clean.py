"""Remove disposable test state under ``test/tmp`` and nothing else.

AGENTS.md makes ``test/tmp`` the only disposable tree (pytest base temp, pytest cache, session
scratch). This module deletes entries of that one tree and refuses everything else: it never follows
a symlink out of the tree, never touches ``runs/``, ``data/``, ``targets/``, ``old/``,
``test/acceptance/`` or a git-tracked file, and deletes only with ``--yes``. By default it keeps
entries modified within ``--older-than`` so a concurrent session's fresh state survives.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time


DEFAULT_AGE = "2h"
PROTECTED = ("runs", "data", "targets", "old", "test/acceptance")
DOCKER_CONTAINER_PREFIX = "appsec-review-build-"  # container_runtime/build_executor._container_name
DOCKER_VOLUME_PREFIX = "appsec-codeql-"  # codeql/runtime.py disposable database volume


class CleanRefused(Exception):
    """A safety rule forbids the cleanup."""


@dataclass
class Entry:
    path: Path
    size: int
    newest: float
    action: str  # "delete", "keep" or "skip"
    reason: str = ""


@dataclass
class Plan:
    tmp: Path | None
    entries: list[Entry] = field(default_factory=list)

    def of(self, action: str) -> list[Entry]:
        return [entry for entry in self.entries if entry.action == action]


def parse_age(text: str) -> float:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", text.strip())
    if not match:
        raise ValueError(f"cannot read age {text!r}; use forms like 30m, 2h, 1d or 0")
    return float(match.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def verified_tmp(root: Path) -> Path | None:
    """The real ``test/tmp`` of ``root``; None when absent; refuses any redirected location."""
    root = root.resolve()
    tmp = root / "test" / "tmp"
    if not os.path.lexists(tmp):
        return None
    if tmp.is_symlink() or tmp.resolve() != tmp:
        raise CleanRefused(f"{tmp} resolves to {tmp.resolve()}, outside the repository's test/tmp; refusing")
    for protected in PROTECTED:
        if tmp == root / protected or (root / protected) in tmp.parents:
            raise CleanRefused(f"{tmp} lies inside protected {protected}/; refusing")
    return tmp


def tracked_under(root: Path, tmp: Path) -> set[str]:
    if not (root / ".git").exists():
        return set()
    result = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", "test/tmp"],
                            capture_output=True, text=True, check=False)
    return {item for item in result.stdout.split("\0") if item}


def scan(entry: Path, tmp: Path) -> tuple[int, float, str]:
    """Total bytes, newest mtime, and an escape reason ('' when the entry is self-contained)."""
    size, newest = 0, 0.0
    stack = [entry]
    while stack:
        current = stack.pop()
        info = current.lstat()
        newest = max(newest, info.st_mtime)
        if stat.S_ISLNK(info.st_mode):
            target = Path(os.path.realpath(current))
            if target != tmp and tmp not in target.parents:
                return size, newest, f"symlink {current.relative_to(tmp)} points outside test/tmp ({target})"
            continue
        size += info.st_size
        if stat.S_ISDIR(info.st_mode):
            stack.extend(current.iterdir())
    return size, newest, ""


def plan(root: Path, older_than: float, now: float | None = None) -> Plan:
    tmp = verified_tmp(root)
    result = Plan(tmp)
    if tmp is None:
        return result
    now = time.time() if now is None else now
    tracked = tracked_under(root.resolve(), tmp)
    for path in sorted(tmp.iterdir()):
        if path.is_symlink():
            result.entries.append(Entry(path, 0, 0.0, "skip", "top-level symlink; never followed or removed"))
            continue
        size, newest, escape = scan(path, tmp)
        relative = f"test/tmp/{path.name}"
        if escape:
            result.entries.append(Entry(path, size, newest, "skip", escape))
        elif any(item == relative or item.startswith(relative + "/") for item in tracked):
            result.entries.append(Entry(path, size, newest, "skip", "contains git-tracked files"))
        elif now - newest < older_than:
            result.entries.append(Entry(path, size, newest, "keep", f"modified {_age(now - newest)} ago (< {_age(older_than)})"))
        else:
            result.entries.append(Entry(path, size, newest, "delete", f"idle {_age(now - newest)}"))
    return result


def _age(seconds: float) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds / size:.1f}{unit}"
    return f"{seconds:.0f}s"


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _writable(function, path, _error) -> None:
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
    function(path)


def remove(entry: Entry, tmp: Path) -> None:
    """Delete one planned entry after re-checking it is still a direct, non-symlink child of test/tmp."""
    path = entry.path
    if path.parent != tmp or path.is_symlink() or path.parent.resolve() != tmp:
        raise CleanRefused(f"{path} is no longer a direct child of {tmp}; not deleting")
    if path.is_dir():
        shutil.rmtree(path, onerror=_writable)  # rmtree unlinks symlinks; it never follows them
    else:
        path.unlink()


def docker_listing() -> list[str]:
    """Lines naming disposable containers and volumes; never removes anything."""
    lines = []
    for label, command, prefix in (
            ("container", ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}", "--filter", f"name={DOCKER_CONTAINER_PREFIX}"],
             DOCKER_CONTAINER_PREFIX),
            ("volume", ["docker", "volume", "ls", "--format", "{{.Name}}", "--filter", f"name={DOCKER_VOLUME_PREFIX}"],
             DOCKER_VOLUME_PREFIX)):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            return [f"docker unavailable: {error}"]
        for line in result.stdout.splitlines():
            if line.split("\t")[0].startswith(prefix):
                lines.append(f"{label}: {line.replace(chr(9), '  ')}")
    return lines


def run(args: argparse.Namespace, root: Path) -> int:
    if args.yes and args.dry_run:
        print("error: --yes and --dry-run contradict each other", file=sys.stderr, flush=True)
        return 2
    try:
        older = parse_age(args.older_than)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2
    try:
        result = plan(root, older)
    except CleanRefused as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 3
    tmp_text = (root.resolve() / "test" / "tmp")
    print(f"clean-temp: {tmp_text} (entries idle for at least {args.older_than}); "
          + ("DELETING" if args.yes else "dry run"), flush=True)
    if result.tmp is None:
        print("test/tmp does not exist; nothing to do", flush=True)
    for entry in result.entries:
        verdict = {"delete": "DELETE" if args.yes else "would delete", "keep": "keep", "skip": "SKIP"}[entry.action]
        print(f"  {verdict:<12} {_human(entry.size):>10}  {entry.path.name}  ({entry.reason})", flush=True)
    failures = 0
    removed = result.of("delete")
    if args.yes and result.tmp is not None:
        for entry in removed:
            try:
                remove(entry, result.tmp)
            except (OSError, CleanRefused) as error:
                failures += 1
                print(f"  FAILED       {entry.path.name}: {error}", flush=True)
    freed = sum(entry.size for entry in removed)
    print(f"summary: {len(removed)} {'deleted' if args.yes else 'to delete'} ({_human(freed)}), "
          f"{len(result.of('keep'))} kept (recent), {len(result.of('skip'))} skipped, {failures} failed", flush=True)
    if not args.yes and removed:
        print("nothing was deleted; add --yes to delete the entries above", flush=True)
    print("protected and never touched: " + ", ".join(f"{name}/" for name in PROTECTED) + ", git-tracked files", flush=True)
    if args.docker:
        print("docker (listed only, never removed):", flush=True)
        for line in docker_listing() or ["none matching " + f"{DOCKER_CONTAINER_PREFIX}* containers or {DOCKER_VOLUME_PREFIX}* volumes"]:
            print(f"  {line}", flush=True)
    return 1 if failures else 0


def register(commands, add, root: Path) -> None:
    sub = add("clean-temp", lambda args: run(args, root), "Remove disposable state under test/tmp (dry run unless --yes).",
              dry_run=True, url=False)
    sub.add_argument("--yes", action="store_true", help="actually delete (default is a dry run)")
    sub.add_argument("--older-than", default=DEFAULT_AGE, metavar="AGE",
                     help="only entries idle at least this long: 30m, 2h, 1d, or 0 for all (default %(default)s)")
    sub.add_argument("--docker", action="store_true",
                     help=f"also list (never remove) {DOCKER_CONTAINER_PREFIX}* containers and {DOCKER_VOLUME_PREFIX}* volumes")
