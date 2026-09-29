"""Read-only, offline binding to the published OSV snapshot (sibling of ``sca_nvd_snapshot.py``).

``resolve_snapshot(data_root, *, max_age, now)`` locates the snapshot ``osv_feed.py`` published under
the OSV publication root, re-hashes every archive against the manifest, enforces the age ceiling,
and returns a ``Resolution``. It returns the directory to mount READ-ONLY for OSV-Scanner
(``mount_dir``, containing ``osv-scanner/<ecosystem>/all.zip``).

Outcomes follow NVD/M4: an over-age snapshot is FAILED (never "OK with a staleness gap"); an absent
snapshot is BLOCKED; an ecosystem the publisher could not fetch is a recorded ``gap`` on an OK
resolution (the scanner reports a coverage gap for it), never a crash.

Like ``sca_nvd_snapshot`` this module deliberately does NOT import ``osv_feed`` or ``execution_state``
(they import network/subprocess machinery): the no-network property is provable by import inspection.
It never writes, fetches, locks or caches.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re

IDENTITY_SCHEMA = "appsec-review/osv-database-identity/1"
POINTER_SCHEMA = "appsec-review/osv-current-pointer/1"
MANIFEST_SCHEMA = "appsec-review/osv-snapshot-manifest/1"
DEFAULT_MAX_AGE = timedelta(seconds=1_209_600)   # 14 days, same as NVD

OK, BLOCKED, FAILED = "OK", "BLOCKED", "FAILED"
REASONS = {
    "VERIFIED_WITHIN_LIMIT": OK,
    "SNAPSHOT_TOO_OLD": FAILED,
    "DATA_ROOT_MISSING": BLOCKED,
    "POINTER_MISSING": BLOCKED,
    "SNAPSHOT_MISSING": BLOCKED,
    "UNSAFE_PATH": FAILED,
    "POINTER_INVALID": FAILED,
    "MANIFEST_INVALID": FAILED,
    "MANIFEST_HASH_MISMATCH": FAILED,
    "SNAPSHOT_ID_MISMATCH": FAILED,
    "ARCHIVE_MISSING": FAILED,
    "ARCHIVE_HASH_MISMATCH": FAILED,
    "INDEX_HASH_MISMATCH": FAILED,
    "TIMESTAMP_IN_FUTURE": FAILED,
    "NO_USABLE_ECOSYSTEM": FAILED,
    "READ_ERROR": FAILED,
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SNAPSHOT_ID = re.compile(r"sha256-[0-9a-f]{16}")
_ECOSYSTEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_MAX_JSON_BYTES = 16 * 1024 * 1024


class _Stop(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason, self.detail = reason, detail


@dataclass(frozen=True)
class Resolution:
    outcome: str
    reason: str
    detail: str
    identity: dict | None
    mount_dir: str | None
    gaps: tuple
    index_path: str | None = None    # verified lookup index, when the publisher built one

    def __post_init__(self):
        if self.outcome not in (OK, BLOCKED, FAILED) or REASONS.get(self.reason) != self.outcome:
            raise ValueError(f"reason {self.reason!r} does not belong to outcome {self.outcome!r}")
        if (self.outcome == OK) != (self.identity is not None) or (self.outcome == OK) != (self.mount_dir is not None):
            raise ValueError("identity and mount_dir are returned only for OK")
        if self.outcome != OK and self.gaps:
            raise ValueError("gaps are reported only on an OK resolution")

    @property
    def usable(self):
        return self.outcome == OK


def _snapshot_id_of(manifest):
    unsigned = {k: v for k, v in manifest.items() if k != "snapshot_id"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return "sha256-" + hashlib.sha256(payload).hexdigest()[:16]


def _utc(value, what):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise _Stop("MANIFEST_INVALID", f"{what} is not a timestamp") from None
    if parsed.tzinfo is None:
        raise _Stop("MANIFEST_INVALID", f"{what} has no offset")
    return parsed.astimezone(timezone.utc)


def _stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _absent(path):
    return not path.is_symlink() and not path.exists()


def _contained(root, path):
    """`path` must be `root` or inside it, with no symlink on any component below root."""
    root, path = Path(root).absolute(), Path(path).absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise _Stop("UNSAFE_PATH", "path escapes the OSV publication root") from None
    probe = root
    for part in relative.parts:
        probe = probe / part
        if probe.is_symlink():
            raise _Stop("UNSAFE_PATH", f"symbolic link inside the OSV publication root: {part}")


def _read_json(path, what):
    try:
        if path.is_symlink() or not path.is_file():
            raise _Stop("POINTER_INVALID" if what == "current.json" else "MANIFEST_INVALID", f"{what} is not a regular file")
        if path.stat().st_size > _MAX_JSON_BYTES:
            raise _Stop("MANIFEST_INVALID", f"{what} is implausibly large")
        data = path.read_bytes()
        return json.loads(data.decode("utf-8")), hashlib.sha256(data).hexdigest()
    except _Stop:
        raise
    except (OSError, ValueError) as exc:
        raise _Stop("READ_ERROR", f"{what} unreadable: {type(exc).__name__}") from None


def _hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_snapshot(data_root, *, max_age=DEFAULT_MAX_AGE, now):
    """Resolve and verify the current OSV snapshot under `data_root` (the directory holding
    `current.json`). `now` is required and never read from the wall clock here."""
    if not isinstance(data_root, (str, os.PathLike)) or not str(data_root):
        raise TypeError("data_root must be a non-empty path")
    if not isinstance(max_age, timedelta):
        raise TypeError("max_age must be a datetime.timedelta")
    if max_age <= timedelta(0):
        raise ValueError("max_age must be greater than zero")
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    now = now.astimezone(timezone.utc)
    root = Path(data_root).absolute()
    try:
        return _resolve(root, max_age, now)
    except _Stop as stop:
        return Resolution(REASONS[stop.reason], stop.reason, stop.detail, None, None, ())


def _resolve(root, max_age, now):
    if _absent(root):
        raise _Stop("DATA_ROOT_MISSING", "the OSV publication root does not exist; the publisher has not run here")
    _contained(root, root)
    pointer_path = root / "current.json"
    if _absent(pointer_path):
        raise _Stop("POINTER_MISSING", "current.json does not exist; no OSV snapshot has been published")
    _contained(root, pointer_path)
    pointer, _ = _read_json(pointer_path, "current.json")
    if (not isinstance(pointer, dict) or pointer.get("schema") != POINTER_SCHEMA or
            not isinstance(pointer.get("snapshot_id"), str) or not _SNAPSHOT_ID.fullmatch(pointer["snapshot_id"]) or
            not isinstance(pointer.get("manifest_sha256"), str) or not _SHA256.fullmatch(pointer["manifest_sha256"])):
        raise _Stop("POINTER_INVALID", "current.json is not a valid OSV pointer")
    directory = root / "snapshots" / pointer["snapshot_id"]
    if _absent(directory):
        raise _Stop("SNAPSHOT_MISSING", "the snapshot named by current.json is not on disk")
    _contained(root, directory)
    manifest, manifest_sha = _read_json(directory / "manifest.json", "manifest.json")
    if manifest_sha != pointer["manifest_sha256"]:
        raise _Stop("MANIFEST_HASH_MISMATCH", "manifest.json does not match the pointer hash")
    if (not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA or
            not isinstance(manifest.get("ecosystems"), dict) or not manifest["ecosystems"]):
        raise _Stop("MANIFEST_INVALID", "manifest.json is not a valid OSV manifest")
    if manifest.get("snapshot_id") != pointer["snapshot_id"] or _snapshot_id_of(manifest) != pointer["snapshot_id"]:
        raise _Stop("SNAPSHOT_ID_MISMATCH", "snapshot identity does not derive from its manifest")
    db = directory / "db"
    ecosystems, gaps, oldest = {}, [], None
    for name, entry in sorted(manifest["ecosystems"].items()):
        if not _ECOSYSTEM.fullmatch(name) or not isinstance(entry, dict):
            raise _Stop("MANIFEST_INVALID", "invalid ecosystem entry")
        if entry.get("status") == "FAILED":
            gaps.append({"ecosystem": name, "reason": str(entry.get("error", "unspecified"))[:300]})
            continue
        if (entry.get("status") not in ("OK", "CARRIED_FORWARD") or not _SHA256.fullmatch(str(entry.get("sha256"))) or
                isinstance(entry.get("size_bytes"), bool) or not isinstance(entry.get("size_bytes"), int)):
            raise _Stop("MANIFEST_INVALID", f"invalid manifest entry for {name}")
        path = db / "osv-scanner" / name / "all.zip"
        if _absent(path):
            raise _Stop("ARCHIVE_MISSING", f"archive for {name} is missing")
        _contained(root, path)
        if not path.is_file() or path.stat().st_size != entry["size_bytes"] or _hash_file(path) != entry["sha256"]:
            raise _Stop("ARCHIVE_HASH_MISMATCH", f"archive for {name} does not match the manifest")
        fetched = _utc(entry.get("fetched_at"), f"{name} fetched_at")
        oldest = fetched if oldest is None or fetched < oldest else oldest
        ecosystems[name] = {"status": entry["status"], "sha256": entry["sha256"], "size_bytes": entry["size_bytes"],
                            "record_count": entry.get("record_count"), "fetched_at": _stamp(fetched)}
    index_path = None
    index = manifest.get("index")
    if isinstance(index, dict) and index.get("status") == "OK":
        candidate = directory / str(index.get("path"))
        if (not _SHA256.fullmatch(str(index.get("sha256"))) or _absent(candidate)):
            raise _Stop("INDEX_HASH_MISMATCH", "the lookup index is missing or its manifest entry is invalid")
        _contained(root, candidate)
        if not candidate.is_file() or candidate.stat().st_size != index.get("size_bytes") or _hash_file(candidate) != index["sha256"]:
            raise _Stop("INDEX_HASH_MISMATCH", "the lookup index does not match the manifest")
        index_path = str(candidate)
    if oldest is None:
        raise _Stop("NO_USABLE_ECOSYSTEM", "the snapshot holds no usable ecosystem archive")
    age = int((now - oldest).total_seconds())
    if age < 0:
        raise _Stop("TIMESTAMP_IN_FUTURE", "the snapshot data timestamp is in the future")
    if age > int(max_age.total_seconds()):
        raise _Stop("SNAPSHOT_TOO_OLD",
                    f"OSV snapshot {pointer['snapshot_id']} is {age} seconds old; the limit is {int(max_age.total_seconds())}")
    identity = {"schema": IDENTITY_SCHEMA, "database_kind": "osv", "snapshot_id": pointer["snapshot_id"],
                "manifest_sha256": manifest_sha, "data_timestamp": _stamp(oldest), "age_seconds": age,
                "max_age_seconds": int(max_age.total_seconds()), "ecosystems": ecosystems,
                "gaps": gaps, "index": "OK" if index_path else "ABSENT", "match_basis": "purl"}
    return Resolution(OK, "VERIFIED_WITHIN_LIMIT",
                      f"snapshot {pointer['snapshot_id']} verified offline; oldest ecosystem data is {age} seconds old"
                      + (f"; {len(gaps)} ecosystem gap(s)" if gaps else ""),
                      identity, str(db), tuple(g["ecosystem"] for g in gaps), index_path)
