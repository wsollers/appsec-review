"""Read-only, offline binding of the SCA job to the published NVD snapshot (ADR-0010 G3, V09).

`resolve_snapshot(data_root, *, max_age, now)` locates the last-good snapshot that
`nvd_feed.py` published under the NVD publication root, re-derives every trusted field from
bytes on disk, and returns the identity record that enters the `02-sca-vulnerability-match`
input fingerprint and is published as `outputs/vulnerability-database-identity.json`.

This module never fetches, never takes or inspects the writer lease, never writes, never
caches, and does not select, wrap or invoke a matcher. It deliberately does NOT import
`nvd_feed` or `execution_state`: both import `socket` (and `urllib` / `subprocess`), and the
no-network claim of this binding is proven by import inspection. The few read-path helpers
(`beneath`, snapshot-id derivation, file hashing) are re-implemented here and pinned to the
publisher's behaviour by parity tests. See docs/sca-nvd-snapshot-binding.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from schema_validate import SchemaStore, validate, validate_document

IDENTITY_SCHEMA = "appsec-review/vulnerability-database-identity/2"
IDENTITY_SCHEMA_FILE = "vulnerability-database-identity.schema.json"
POINTER_SCHEMA_FILE = "nvd-current-pointer.schema.json"
MANIFEST_SCHEMA_FILE = "nvd-snapshot-manifest.schema.json"
PUBLISHER = "appsec-review-process/nvd_feed.py"
MANIFEST_SCHEMA_ID = "appsec-review/nvd-snapshot-manifest/1"
MATCH_BASIS = "cpe"
LIMITATIONS = (
    "NVD is CPE-keyed (ADR-0010 G3): every match made against this database carries match_basis=cpe.",
    "An SBOM component with no CPE mapping is a coverage gap, never 'no known vulnerabilities'.",
    "Reference enrichment only: no product match, reachability, exploitability, severity or finding is established by this record.",
    "Integrity is verified against the publisher's own hashes; the publication root is not signed, so this record does not authenticate the publisher.",
)

OK, BLOCKED, FAILED = "OK", "BLOCKED", "FAILED"
OUTCOMES = (OK, BLOCKED, FAILED)
USABLE = (OK,)


class _NoAgeLimit:
    """The explicit "no age limit" policy (ADR-0010 sub-decision M4). It is a value a caller must
    pass on purpose; `max_age` has no default, so "no limit" can never be reached by omission."""
    __slots__ = ()

    def __repr__(self):
        return "NO_AGE_LIMIT"


NO_AGE_LIMIT = _NoAgeLimit()
AGE_POLICY_NO_LIMIT, AGE_POLICY_WITHIN_LIMIT = "no-limit", "within-limit"
REASONS = {
    "VERIFIED_NO_AGE_LIMIT": OK,
    "VERIFIED_WITHIN_LIMIT": OK,
    "SNAPSHOT_TOO_OLD": FAILED,
    "DATA_ROOT_MISSING": BLOCKED,
    "POINTER_MISSING": BLOCKED,
    "SNAPSHOT_MISSING": BLOCKED,
    "UNSAFE_PATH": FAILED,
    "POINTER_INVALID": FAILED,
    "MANIFEST_MISSING": FAILED,
    "MANIFEST_HASH_MISMATCH": FAILED,
    "MANIFEST_INVALID": FAILED,
    "SNAPSHOT_ID_MISMATCH": FAILED,
    "POINTER_MANIFEST_MISMATCH": FAILED,
    "SNAPSHOT_FILE_SET_MISMATCH": FAILED,
    "CHAIN_INVALID": FAILED,
    "BLOB_MISSING": FAILED,
    "BLOB_SIZE_MISMATCH": FAILED,
    "BLOB_HASH_MISMATCH": FAILED,
    "TIMESTAMP_IN_FUTURE": FAILED,
    "READ_ERROR": FAILED,
}
MAX_POINTER_READS = 3
MAX_CHAIN_LENGTH = 100000
_MAX_JSON_BYTES = 64 * 1024 * 1024
_BLOB_PATH = re.compile(r"blobs/sha256-([0-9a-f]{64})\.json\.gz")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_LAYER_KEYS = {
    "year": {"kind", "year", "source_url", "metadata_url", "source_metadata", "record_count", "blob"},
    "api-last-modified": {"kind", "start", "end", "pages"},
}
_PAGE_KEYS = {"start_index", "record_count", "duplicate_count", "source_url", "blob"}
_BLOB_KEYS = {"path", "sha256", "size_bytes"}
_STORE = SchemaStore()


class _Stop(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason, self.detail = reason, detail


class _Frozen:
    """Mixin: every mutator raises. A copy (copy.deepcopy) is an ordinary mutable structure."""
    def _refuse(self, *args, **kwargs):
        raise TypeError("the identity record inside a Resolution is read-only; deep-copy it to edit a copy")


class _FrozenDict(_Frozen, dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _Frozen._refuse

    def __deepcopy__(self, memo):
        return {key: _thaw(value) for key, value in self.items()}


class _FrozenList(_Frozen, list):
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _Frozen._refuse
    append = extend = insert = pop = remove = clear = sort = reverse = _Frozen._refuse

    def __deepcopy__(self, memo):
        return [_thaw(value) for value in self]


def _freeze(value):
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, dict):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_thaw(item) for item in value]
    return value


class IdentityMismatch(ValueError):
    """A persisted identity record does not describe the snapshot that is on disk now."""


@dataclass(frozen=True)
class Resolution:
    """Outcome of one resolve. `identity` and `fingerprint_component` are non-None if and only if
    the outcome is OK; construction enforces it. `gaps` is reserved and always empty: under
    sub-decision M4 an over-age snapshot is FAILED, not a usable result with a staleness gap."""
    outcome: str
    reason: str
    detail: str
    identity: dict | None
    fingerprint_component: str | None
    gaps: tuple
    pointer_reads: int

    def __post_init__(self):
        if self.outcome not in OUTCOMES or REASONS.get(self.reason) != self.outcome:
            raise ValueError(f"reason {self.reason!r} does not belong to outcome {self.outcome!r}")
        usable = self.outcome in USABLE
        if usable != (self.identity is not None) or usable != (self.fingerprint_component is not None):
            raise ValueError("identity and fingerprint_component are returned only for OK")
        if self.gaps:
            raise ValueError("gaps is reserved and must be empty: an over-age snapshot is FAILED, not a gap")
        if usable:
            # The identity a worker publishes and the component it fingerprints must be the same
            # statement. Bind them here, then make the identity read-only so they stay bound.
            if fingerprint_component(self.identity) != self.fingerprint_component:
                raise ValueError("fingerprint_component does not belong to this identity record")
            expected = "VERIFIED_NO_AGE_LIMIT" if self.identity["age_policy"] == AGE_POLICY_NO_LIMIT else "VERIFIED_WITHIN_LIMIT"
            if self.reason != expected:
                raise ValueError("identity age_policy contradicts the reason")
            object.__setattr__(self, "identity", _freeze(self.identity))

    @property
    def usable(self):
        return self.outcome in USABLE


def beneath(root, path):
    """Same rule as execution_state.beneath: lexically and physically inside root, no link in the
    path or in any ancestor up to and including root."""
    root, path = Path(root).absolute(), Path(path).absolute()
    try:
        path.relative_to(root)
        path.resolve().relative_to(root.resolve())
    except ValueError:
        raise ValueError(f"path escapes owning root: {path}") from None
    for part in [path, *path.parents]:
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()) or (
                part.exists() and getattr(part.lstat(), "st_reparse_tag", 0)):
            raise ValueError(f"linked path forbidden: {part}")
        if part == root:
            break
    return path


def snapshot_id_of(manifest):
    """The publisher's identity rule: sha256 over the canonical manifest without `snapshot_id`,
    truncated to 16 hex digits."""
    unsigned = {key: value for key, value in manifest.items() if key != "snapshot_id"}
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return "sha256-" + hashlib.sha256(payload).hexdigest()[:16]


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _utc(value, what):
    if not isinstance(value, str):
        raise ValueError(f"{what} must be a string timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{what} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _contained(root, path):
    try:
        return beneath(root, path)
    except ValueError as exc:
        raise _Stop("UNSAFE_PATH", str(exc)) from None


def _read_regular(path, what):
    """One open, one read: the bytes that are hashed are the bytes that are parsed."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _Stop("READ_ERROR", f"{what} cannot be opened: {type(exc).__name__}") from None
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise _Stop("READ_ERROR", f"{what} is not a regular file")
        if info.st_size > _MAX_JSON_BYTES:
            raise _Stop("READ_ERROR", f"{what} is larger than {_MAX_JSON_BYTES} bytes")
        return stream.read()


def _parse(data, what, reason):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (ValueError, RecursionError) as exc:
        raise _Stop(reason, f"{what} is not a well-formed JSON document: {exc}") from None
    if not isinstance(value, dict):
        raise _Stop(reason, f"{what} is not a JSON object")
    return value


def _hash_file(path):
    """Returns (sha256, size) from one open descriptor, refusing links and non-regular files."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _blob(value, where):
    if not isinstance(value, dict) or set(value) != _BLOB_KEYS:
        raise _Stop("MANIFEST_INVALID", f"{where}.blob must have exactly the keys {sorted(_BLOB_KEYS)}")
    path, sha, size = value["path"], value["sha256"], value["size_bytes"]
    if not isinstance(sha, str) or not _SHA256.fullmatch(sha):
        raise _Stop("MANIFEST_INVALID", f"{where}.blob.sha256 must be 64 lowercase hex digits")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise _Stop("MANIFEST_INVALID", f"{where}.blob.size_bytes must be a non-negative integer")
    match = _BLOB_PATH.fullmatch(path) if isinstance(path, str) else None
    if not match:
        raise _Stop("UNSAFE_PATH", f"{where}.blob.path must be blobs/sha256-<64 hex>.json.gz relative to the NVD root, got {path!r}")
    if match.group(1) != sha:
        raise _Stop("MANIFEST_INVALID", f"{where}.blob.path is not the content address of {where}.blob.sha256")
    return path, sha, size


def _layer_blobs(manifest, snapshot_id):
    layers = manifest["layers"]
    if manifest["mode"] == "bootstrap" and not layers:
        raise _Stop("MANIFEST_INVALID", f"bootstrap snapshot {snapshot_id} lists no layers")
    expected_kind = "year" if manifest["mode"] == "bootstrap" else "api-last-modified"
    blobs = []
    for index, layer in enumerate(layers):
        where = f"{snapshot_id}.layers[{index}]"
        kind = layer.get("kind")
        if kind != expected_kind:
            raise _Stop("MANIFEST_INVALID", f"{where}.kind must be {expected_kind!r} in a {manifest['mode']} snapshot, got {kind!r}")
        if set(layer) != _LAYER_KEYS[kind]:
            raise _Stop("MANIFEST_INVALID", f"{where} must have exactly the keys {sorted(_LAYER_KEYS[kind])}")
        if kind == "year":
            blobs.append(_blob(layer["blob"], where))
            continue
        pages = layer["pages"]
        if not isinstance(pages, list) or not pages:
            raise _Stop("MANIFEST_INVALID", f"{where}.pages must be a non-empty array")
        for number, page in enumerate(pages):
            page_where = f"{where}.pages[{number}]"
            if not isinstance(page, dict) or set(page) != _PAGE_KEYS:
                raise _Stop("MANIFEST_INVALID", f"{page_where} must have exactly the keys {sorted(_PAGE_KEYS)}")
            blobs.append(_blob(page["blob"], page_where))
    return blobs


def _load_manifest(root, snapshot_id, *, current, expected_sha=None):
    directory = _contained(root, root / "snapshots" / snapshot_id)
    if not directory.exists():
        if current:
            raise _Stop("SNAPSHOT_MISSING", f"current.json names snapshot {snapshot_id} but snapshots/{snapshot_id} does not exist")
        raise _Stop("CHAIN_INVALID", f"parent snapshot {snapshot_id} is missing; the snapshot chain is partial")
    if not directory.is_dir():
        raise _Stop("SNAPSHOT_FILE_SET_MISMATCH", f"snapshots/{snapshot_id} is not a directory")
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        raise _Stop("READ_ERROR", f"snapshots/{snapshot_id} cannot be listed: {type(exc).__name__}") from None
    if "manifest.json" not in names:
        raise _Stop("MANIFEST_MISSING", f"snapshots/{snapshot_id} exists without manifest.json; the snapshot is partial")
    if names != ["manifest.json"]:
        extra = [name for name in names if name != "manifest.json"]
        raise _Stop("SNAPSHOT_FILE_SET_MISMATCH", f"snapshots/{snapshot_id} must contain exactly manifest.json; unexpected entries: {extra}")
    data = _read_regular(_contained(root, directory / "manifest.json"), f"snapshots/{snapshot_id}/manifest.json")
    sha = hashlib.sha256(data).hexdigest()
    if expected_sha is not None and sha != expected_sha:
        raise _Stop("MANIFEST_HASH_MISMATCH", f"sha256 of snapshots/{snapshot_id}/manifest.json is {sha}, current.json records {expected_sha}")
    manifest = _parse(data, f"snapshots/{snapshot_id}/manifest.json", "MANIFEST_INVALID")
    errors = validate(manifest, _STORE.load(MANIFEST_SCHEMA_FILE), _STORE)
    if errors:
        raise _Stop("MANIFEST_INVALID", f"snapshots/{snapshot_id}/manifest.json violates {MANIFEST_SCHEMA_FILE}: {errors[0]}")
    if manifest["snapshot_id"] != snapshot_id:
        raise _Stop("SNAPSHOT_ID_MISMATCH", f"snapshots/{snapshot_id}/manifest.json declares snapshot_id {manifest['snapshot_id']}")
    derived = snapshot_id_of(manifest)
    if derived != snapshot_id:
        raise _Stop("SNAPSHOT_ID_MISMATCH", f"snapshot id derived from the manifest content is {derived}, not {snapshot_id}")
    if isinstance(manifest["record_count"], bool) or manifest["record_count"] < 0:
        raise _Stop("MANIFEST_INVALID", f"{snapshot_id}.record_count must be a non-negative integer")
    try:
        times = {"cursor": _utc(manifest["cursor"], "cursor"), "captured_at": _utc(manifest["captured_at"], "captured_at")}
    except ValueError as exc:
        raise _Stop("MANIFEST_INVALID", f"snapshots/{snapshot_id}/manifest.json: {exc}") from None
    parent = manifest["parent_snapshot_id"]
    if (manifest["mode"] == "bootstrap") != (parent is None):
        raise _Stop("CHAIN_INVALID", f"snapshot {snapshot_id}: a bootstrap snapshot has no parent and an incremental snapshot has one")
    return manifest, sha, times, _layer_blobs(manifest, snapshot_id)


def _verify_once(root, pointer_bytes):
    pointer = _parse(pointer_bytes, "current.json", "POINTER_INVALID")
    errors = validate_document(pointer, POINTER_SCHEMA_FILE, _STORE)
    if errors:
        raise _Stop("POINTER_INVALID", f"current.json violates {POINTER_SCHEMA_FILE}: {errors[0]}")
    try:
        pointer_cursor = _utc(pointer["cursor"], "cursor")
        _utc(pointer["published_at"], "published_at")
    except ValueError as exc:
        raise _Stop("POINTER_INVALID", f"current.json: {exc}") from None

    chain, blobs, seen = [], {}, set()
    snapshot_id, expected_sha, child = pointer["snapshot_id"], pointer["manifest_sha256"], None
    head = None
    while snapshot_id is not None:
        if snapshot_id in seen:
            raise _Stop("CHAIN_INVALID", f"snapshot parent cycle at {snapshot_id}")
        if len(seen) >= MAX_CHAIN_LENGTH:
            raise _Stop("CHAIN_INVALID", f"snapshot chain is longer than {MAX_CHAIN_LENGTH}")
        seen.add(snapshot_id)
        manifest, sha, times, listed = _load_manifest(root, snapshot_id, current=child is None, expected_sha=expected_sha)
        if child is None:
            head = (manifest, sha, times)
            if times["cursor"] != pointer_cursor:
                raise _Stop("POINTER_MANIFEST_MISMATCH", f"current.json cursor {pointer['cursor']} is not the manifest cursor {manifest['cursor']}")
        else:
            start = child["coverage"].get("last_modified_start")
            try:
                continuous = _utc(start, "coverage.last_modified_start") == times["cursor"]
            except ValueError:
                continuous = False
            if not continuous:
                raise _Stop("CHAIN_INVALID", f"snapshot {child['snapshot_id']} does not start at the cursor of its parent {snapshot_id}")
        for path, blob_sha, size in listed:
            if blobs.setdefault(path, (blob_sha, size)) != (blob_sha, size):
                raise _Stop("CHAIN_INVALID", f"{path} is listed with two different sizes in the snapshot chain")
        chain.append({"snapshot_id": snapshot_id, "manifest_sha256": sha})
        child, snapshot_id, expected_sha = manifest, manifest["parent_snapshot_id"], None

    files = []
    for path in sorted(blobs):
        blob_sha, size = blobs[path]
        target = _contained(root, root / path)
        if not target.exists():
            raise _Stop("BLOB_MISSING", f"{path} is listed by the snapshot chain but absent; the snapshot is partial")
        try:
            actual_sha, actual_size = _hash_file(target)
        except OSError as exc:
            raise _Stop("READ_ERROR", f"{path} cannot be read as a regular file: {type(exc).__name__}") from None
        if actual_size != size:
            raise _Stop("BLOB_SIZE_MISMATCH", f"{path} is {actual_size} bytes, the manifest records {size}")
        if actual_sha != blob_sha:
            raise _Stop("BLOB_HASH_MISMATCH", f"sha256 of {path} is {actual_sha}, the manifest records {blob_sha}")
        files.append({"path": path, "sha256": blob_sha, "size_bytes": size})
    return head, chain, files


def _identity(head, chain, files, max_age, now):
    manifest, manifest_sha, times = head
    for name in ("cursor", "captured_at"):
        if times[name] > now:
            raise _Stop("TIMESTAMP_IN_FUTURE", f"manifest {name} {manifest[name]} is later than now {_stamp(now)}; age cannot be established")
    age = int((now - times["cursor"]).total_seconds())
    limit = None if max_age is NO_AGE_LIMIT else int(max_age.total_seconds())
    if limit is not None and age > limit:
        # M4: a job that set a limit gets an error, not a usable result with a gap. No identity and
        # no fingerprint component exist for this outcome, so nothing downstream can proceed on it.
        raise _Stop("SNAPSHOT_TOO_OLD", f"snapshot data is {age} seconds old at {_stamp(now)}, which exceeds the "
                                        f"max_age of {limit} seconds this job set; refresh the snapshot or re-launch "
                                        "with the age policy the engagement intends")
    content = hashlib.sha256(_canonical({"chain": chain, "files": files}).encode()).hexdigest()
    return {
        "schema": IDENTITY_SCHEMA,
        "database_kind": "nvd",
        "feed_id": manifest["feed_id"],
        "feed_schema": manifest["feed_schema"],
        "publisher": PUBLISHER,
        "publisher_manifest_schema": manifest["schema"],
        "snapshot_id": manifest["snapshot_id"],
        "snapshot_mode": manifest["mode"],
        "parent_snapshot_id": manifest["parent_snapshot_id"],
        "chain_snapshot_ids": [entry["snapshot_id"] for entry in chain],
        "manifest_sha256": manifest_sha,
        "content_sha256": content,
        "retrieved_at": _stamp(times["captured_at"]),
        "cursor": _stamp(times["cursor"]),
        "file_count": len(files),
        "total_bytes": sum(entry["size_bytes"] for entry in files),
        "evaluated_at": _stamp(now),
        "age_seconds": age,
        "max_age_seconds": limit,
        "age_policy": AGE_POLICY_NO_LIMIT if limit is None else AGE_POLICY_WITHIN_LIMIT,
        "match_basis": MATCH_BASIS,
        "limitations": list(LIMITATIONS),
    }


def fingerprint_component(identity):
    """Stable input-fingerprint material for the SCA job.

    Includes what changes the meaning of a match result: snapshot id, manifest sha256, the
    full-strength content hash of every verified file, feed schema and match basis. Excludes
    `age_seconds`, `evaluated_at`, `max_age_seconds` and `age_policy`: the clock would invalidate
    reuse on every run, and under sub-decision M4 age is not a property of a usable result at all.
    An over-age snapshot is FAILED before a component exists, so a worker MUST call
    `resolve_snapshot` in preflight BEFORE reuse admission; a cached OK is then never reached with
    a snapshot that exceeds the limit the job set.
    """
    errors = validate_document(identity, IDENTITY_SCHEMA_FILE, _STORE) if isinstance(identity, dict) else ["identity must be an object"]
    if errors:
        raise ValueError(f"identity record violates {IDENTITY_SCHEMA_FILE}: {errors[0]}")
    errors = identity_consistency_errors(identity)
    if errors:
        raise ValueError(f"identity record is inconsistent: {errors[0]}")
    return _canonical({
        "component": "vulnerability-database-identity/2",
        "database_kind": identity["database_kind"],
        "feed_schema": identity["feed_schema"],
        "snapshot_id": identity["snapshot_id"],
        "manifest_sha256": identity["manifest_sha256"],
        "content_sha256": identity["content_sha256"],
        "match_basis": identity["match_basis"],
    })


def identity_consistency_errors(identity):
    """Fields of an identity record that must agree with each other. `age_policy` is not a free
    label: it is `no-limit` exactly when `max_age_seconds` is null, and a `within-limit` record
    whose age exceeds its own limit describes an outcome that is FAILED and never has an identity.
    `age_seconds` is a function of `evaluated_at` and `cursor`. This catches an independently edited
    record. It cannot authenticate one: see `verify_identity`."""
    errors = []
    try:
        evaluated, cursor, retrieved = (_utc(identity[name], name) for name in ("evaluated_at", "cursor", "retrieved_at"))
    except ValueError as exc:
        return [str(exc)]
    if cursor > evaluated or retrieved > evaluated:
        errors.append("cursor and retrieved_at must not be later than evaluated_at")
    if identity["age_seconds"] != int((evaluated - cursor).total_seconds()):
        errors.append("age_seconds must equal evaluated_at minus cursor")
    limit = identity["max_age_seconds"]
    if (identity["age_policy"] == AGE_POLICY_NO_LIMIT) != (limit is None):
        errors.append("age_policy must be 'no-limit' exactly when max_age_seconds is null")
    elif limit is not None:
        if limit <= 0:
            errors.append("max_age_seconds must be greater than zero")
        elif identity["age_seconds"] > limit:
            errors.append("age_seconds exceeds max_age_seconds: that snapshot is SNAPSHOT_TOO_OLD and has no identity")
    if identity["snapshot_id"] not in identity["chain_snapshot_ids"]:
        errors.append("snapshot_id must appear in chain_snapshot_ids")
    return errors


# What a persisted identity asserts about the bytes on disk. Everything else in the record is a
# function of the caller's `now` and `max_age` and is re-derived, never compared.
_SNAPSHOT_BOUND_FIELDS = ("schema", "database_kind", "feed_id", "feed_schema", "publisher",
                          "publisher_manifest_schema", "snapshot_id", "snapshot_mode", "parent_snapshot_id",
                          "chain_snapshot_ids", "manifest_sha256", "content_sha256", "retrieved_at", "cursor",
                          "file_count", "total_bytes", "match_basis", "limitations")


def verify_identity(identity, data_root, *, max_age, now):
    """Check a PERSISTED identity record against the snapshot on disk and return a fresh Resolution.

    A persisted `vulnerability-database-identity.json` is a cache, never an authority: whoever can
    rewrite it can make it self-consistent. So this does not trust it. `data_root`, `max_age` and
    `now` are required; the snapshot is resolved and re-verified from bytes, and the record is
    accepted only if every snapshot-bound field equals the fresh one. Age, the age policy and the
    fingerprint component are taken from the fresh Resolution that is returned, never from the
    record. Raises IdentityMismatch otherwise.
    """
    errors = validate_document(identity, IDENTITY_SCHEMA_FILE, _STORE) if isinstance(identity, dict) else ["identity must be an object"]
    errors = errors or identity_consistency_errors(identity)
    if errors:
        raise IdentityMismatch(f"persisted identity record is invalid: {errors[0]}")
    fresh = resolve_snapshot(data_root, max_age=max_age, now=now)
    if not fresh.usable:
        raise IdentityMismatch(f"the snapshot on disk does not verify now: {fresh.reason}")
    for name in _SNAPSHOT_BOUND_FIELDS:
        if _thaw(identity[name]) != _thaw(fresh.identity[name]):
            raise IdentityMismatch(f"persisted identity field {name!r} does not match the verified snapshot")
    return fresh


def _stopped(stop, reads):
    return Resolution(REASONS[stop.reason], stop.reason, stop.detail, None, None, (), reads)


def resolve_snapshot(data_root, *, max_age, now):
    """Resolve and verify the current NVD snapshot under `data_root` (the NVD publication root,
    the directory that holds `current.json`). All three arguments are required: there is no
    default root, no default age policy (pass NO_AGE_LIMIT to say so), and the wall clock is never read here."""
    if not isinstance(data_root, (str, os.PathLike)) or not str(data_root):
        raise TypeError("data_root must be a non-empty path")
    if max_age is not NO_AGE_LIMIT:
        if not isinstance(max_age, timedelta):
            raise TypeError("max_age must be NO_AGE_LIMIT or a datetime.timedelta; it has no default")
        if max_age <= timedelta(0):
            raise ValueError("max_age must be greater than zero")
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime.datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    root = Path(data_root).absolute()
    reads = 0
    try:
        if not root.is_symlink() and not root.exists():
            raise _Stop("DATA_ROOT_MISSING", "the NVD publication root does not exist; the publisher has not run here")
        _contained(root, root)
        if not root.is_dir():
            raise _Stop("UNSAFE_PATH", "the NVD publication root is not a directory")
        pointer_path = root / "current.json"
        if not pointer_path.is_symlink() and not pointer_path.exists():
            raise _Stop("POINTER_MISSING", "current.json does not exist; no NVD snapshot has been published")
        _contained(root, pointer_path)
        pointer_bytes = _read_regular(pointer_path, "current.json")
        while True:
            reads += 1
            # One generation per pass: everything verified below is reached from these bytes only.
            verified = _verify_once(root, pointer_bytes)
            if not pointer_path.is_symlink() and not pointer_path.exists():
                raise _Stop("POINTER_INVALID", "current.json disappeared while the snapshot was being verified")
            _contained(root, pointer_path)
            latest = _read_regular(pointer_path, "current.json")
            if latest == pointer_bytes or reads >= MAX_POINTER_READS:
                # A fully verified snapshot is immutable, so it stays sound even if the pointer
                # is still moving after the bounded retries; it is never mixed with another.
                break
            pointer_bytes = latest
        identity = _identity(*verified, max_age, now)
    except _Stop as stop:
        return _stopped(stop, reads)
    errors = validate_document(identity, IDENTITY_SCHEMA_FILE, _STORE)
    if errors:
        raise AssertionError(f"resolver built an identity record that violates its schema: {errors[0]}")
    component = fingerprint_component(identity)
    if identity["age_policy"] == AGE_POLICY_NO_LIMIT:
        return Resolution(OK, "VERIFIED_NO_AGE_LIMIT",
                          f"snapshot {identity['snapshot_id']} verified offline; no age limit was set, data is "
                          f"{identity['age_seconds']} seconds old", identity, component, (), reads)
    return Resolution(OK, "VERIFIED_WITHIN_LIMIT",
                      f"snapshot {identity['snapshot_id']} verified offline; data is {identity['age_seconds']} seconds old, "
                      f"within the {identity['max_age_seconds']} second limit this job set", identity, component, (), reads)
