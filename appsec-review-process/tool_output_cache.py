#!/usr/bin/env python3
"""Tool-output cache for pinned B13 tool runs (brief N, TODO "Relaunch tax").

A pinned-tool run (syft, grype, osv-scanner, scancode) is a pure function of the image, the fixed
request (argv, environment, limits, network, mounts) and the bytes it reads.  After a fingerprint
change that did not alter those, re-running it is pure cost: freeciv21 spent 60 min in scancode.
This module keys such a run by content and remembers which verified B13 attempt produced it.

Rules (the security posture of the cache):

- The key is built only from pinned configuration (image digest from the B16 record, argv,
  environment, limits, network, container paths, the B13 boundary hash, the host binding), the run
  and job identity, the run mode, and sha256 digests this module computes itself over the mounted
  bytes (or a snapshot identity the offline registry re-hashed).  Nothing read out of a tool output
  or a target file is ever part of a key: target-controlled content is hashed, never trusted.
- An entry is a pointer, not evidence: it names the B13 attempt and the result/output hashes the
  caller retained when that attempt was verified.  A hit is reused only after the caller re-runs
  the full independent B13 re-verification on that attempt (``dependency_b13_adapters``), and the
  consuming worker re-verifies it again.  A hit that fails re-verification is invalidated and the
  tool runs fresh.
- Only verified outcomes are stored: a complete output, or a TIMEOUT / OOM_KILLED coverage gap
  (the resource limits are part of the key, so a gap is only reused under the same limits).
  Canceled, blocked, tampered and non-zero-exit attempts are never stored.
- The run mode is part of the key: a prod run never reuses an entry a dev run stored.
- Tunable ``tool_output_cache``: ``off``, ``dev`` (default: on only when ``APPSEC_RUN_MODE=dev``),
  ``on`` (both modes; the controller flips prod).

Store: ``data/caches/<namespace>/`` at the repository root (git-ignored; ``APPSEC_CACHE_ROOT``
overrides), one small JSON entry per key, pruned to ``<namespace>_max_entries`` oldest-first and of
entries whose attempt no longer exists.  ``python3 tool_output_cache.py stats|prune|clear``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable

import tunables
from execution_state import atomic_json, digest, now

ROOT = Path(__file__).resolve().parent
NAMESPACE = "tool-output"
ENTRY_SCHEMA = "appsec-review/tool-output-cache-entry/1"
KEY_VERSION = "tool-output-cache/1"
MODES = ("off", "dev", "on")
# Verified gap causes a rerun under the same limits would repeat. A non-zero exit is not cached: it
# can be transient and costs little to retry.
CACHEABLE_GAP_CAUSES = frozenset({"TIMEOUT", "OOM_KILLED"})


class Uncacheable(ValueError):
    """The inputs cannot be keyed safely (a link, a special file): run without the cache."""


def cache_root() -> Path:
    configured = os.environ.get("APPSEC_CACHE_ROOT")
    return Path(configured).resolve() if configured else ROOT.parent / "data" / "caches"


def run_mode() -> str | None:
    import dev_restart
    try:
        return dev_restart.run_mode()
    except ValueError:
        return None


def mode_enabled(setting: Any, mode: str | None) -> bool:
    """``off`` / ``dev`` / ``on`` against the process mode; anything else is off (fail closed)."""
    if setting not in MODES or mode is None:
        return False
    return setting == "on" or (setting == "dev" and mode == "dev")


def enabled(mode: str | None = None) -> bool:
    return mode_enabled(tunables.shared("tool_output_cache"), run_mode() if mode is None else mode)


def tree_digest(root: Path) -> str:
    """sha256 over every directory and regular file beneath ``root`` (relative path, kind, size,
    content hash), computed here.  Any link or special file makes the tree uncacheable."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise Uncacheable(f"{root} is not a real directory")
    rows = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        base = Path(directory)
        for name in dirs:
            if (base / name).is_symlink():
                raise Uncacheable(f"{base / name} is a link")
            rows.append([(base / name).relative_to(root).as_posix(), "d", 0, ""])
        for name in sorted(files):
            path = base / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise Uncacheable(f"{path} is not a regular file")
            content = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    content.update(chunk)
            rows.append([path.relative_to(root).as_posix(), "f", info.st_size, content.hexdigest()])
    rows.sort()
    return "sha256:" + digest(rows)


def key_of(material: dict[str, Any]) -> str:
    return digest({"version": KEY_VERSION, "material": material})


class Store:
    """Small JSON entries named by key under ``cache_root()/namespace``."""

    def __init__(self, namespace: str, schema: str, max_entries_tunable: str,
                 root: Path | None = None) -> None:
        self.namespace, self.schema, self.max_entries_tunable = namespace, schema, max_entries_tunable
        self.directory = (root or cache_root()) / namespace

    def path(self, key: str) -> Path:
        if not isinstance(key, str) or len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("cache key must be 64 lowercase hex characters")
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str, material: dict[str, Any]) -> dict[str, Any] | None:
        """The entry for ``key`` if it is well formed and was stored for exactly ``material``.
        A malformed or mismatched entry is removed and reported as a miss."""
        path = self.path(key)
        if not path.is_file():
            return None
        if path.is_symlink():
            self.invalidate(key, "entry is a link"); return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            self.invalidate(key, "entry is unreadable"); return None
        if (not isinstance(entry, dict) or entry.get("schema") != self.schema or entry.get("key") != key
                or entry.get("material") != material or key_of(entry["material"]) != key):
            self.invalidate(key, "entry does not match its key"); return None
        return entry

    def put(self, key: str, material: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        entry = {**payload, "schema": self.schema, "key": key, "material": material, "created_at": now()}
        atomic_json(self.path(key), entry)
        self.prune()
        return entry

    def invalidate(self, key: str, reason: str) -> None:
        path = self.path(key)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        self._event("invalidate", key=key, reason=reason)

    def _event(self, kind: str, **details: Any) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": now(), "event": kind, **details}, sort_keys=True) + "\n")

    def entries(self) -> list[tuple[Path, dict[str, Any] | None]]:
        found = []
        if not self.directory.is_dir():
            return found
        for path in sorted(self.directory.glob("??/*.json")):
            try:
                found.append((path, json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, UnicodeError, ValueError):
                found.append((path, None))
        return found

    def prune(self, max_entries: int | None = None,
              alive: Callable[[dict[str, Any]], bool] | None = None) -> int:
        """Drop unreadable entries, entries ``alive`` rejects, then the oldest beyond the cap."""
        cap = tunables.shared(self.max_entries_tunable) if max_entries is None else max_entries
        removed, kept = 0, []
        for path, entry in self.entries():
            if entry is None or (alive is not None and not alive(entry)):
                path.unlink(missing_ok=True); removed += 1
            else:
                kept.append((str(entry.get("created_at", "")), path))
        kept.sort()
        for _created, path in kept[:max(0, len(kept) - cap)]:
            path.unlink(missing_ok=True); removed += 1
        if removed:
            self._event("prune", removed=removed)
        return removed

    def clear(self) -> int:
        entries = self.entries()
        for path, _entry in entries:
            path.unlink(missing_ok=True)
        return len(entries)


def store() -> Store:
    return Store(NAMESPACE, ENTRY_SCHEMA, "tool_output_cache_max_entries")


def attempt_alive(entry: dict[str, Any]) -> bool:
    binding = entry.get("b13_attempt")
    root = binding.get("attempt_root") if isinstance(binding, dict) else None
    return isinstance(root, str) and Path(root).is_dir() and not Path(root).is_symlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("stats", "prune", "clear"))
    args = parser.parse_args()
    cache = store()
    if args.command == "stats":
        entries = cache.entries()
        print(json.dumps({"root": str(cache.directory), "entries": len(entries),
                          "setting": tunables.shared("tool_output_cache"), "mode": run_mode(),
                          "enabled": enabled()}, sort_keys=True))
    elif args.command == "prune":
        print(json.dumps({"removed": cache.prune(alive=attempt_alive)}))
    else:
        print(json.dumps({"removed": cache.clear()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
