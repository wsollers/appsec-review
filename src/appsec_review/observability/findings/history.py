"""Per-target, cross-run finding history (finding-metrics.md sections 4.2 and 5.6).

A directory store under an operator-supplied root (the design names
``runs/metadata/finding-history/``)::

    <root>/<target_id>/snapshots/<sha256>.json     finding-snapshot/1 documents
    <root>/<target_id>/lifecycles/<sha256>.json    lifecycle documents (lifecycle.classify)

Doctrine:

* Derived state, never evidence. Everything here is rebuildable from accepted run artifacts and
  nothing here is cited by a finding.
* Content-addressed and immutable: a file is named by the digest of its canonical JSON and is
  created exclusively. A file whose name, bytes or content disagree is a tampered store, which is
  an error and never a smaller history.
* Path custody: the target id is a closed pattern, store directories and files are never symbolic
  links, and nothing outside ``<root>/<target_id>`` is read or written.
* Bounded: at most ``MAX_SNAPSHOTS`` snapshots and ``MAX_LIFECYCLES`` lifecycles per target.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.storage import canonical_json, protected_json

from .contracts import HISTORY_SCHEMA, SNAPSHOT_STAGES, LifecycleState, check_snapshot, digest, is_sha256
from .lifecycle import check_lifecycle

MAX_SNAPSHOTS = 512
MAX_LIFECYCLES = 1024
_TARGET = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_KINDS = ("snapshots", "lifecycles")


def _target(target_id: Any) -> str:
    if not isinstance(target_id, str) or not _TARGET.fullmatch(target_id) or ".." in target_id:
        raise ValueError("finding history target_id must match ^[a-z0-9][a-z0-9._-]{0,63}$ without '..'")
    return target_id


def _directory(root: Any, target_id: str, kind: str) -> Path:
    """``<root>/<target_id>/<kind>`` after refusing a symbolic link or non-directory on the way."""
    root = Path(root)
    target = root / _target(target_id)
    directory = target / kind
    for path in (root, target, directory):
        if path.is_symlink():
            raise ValueError(f"finding history directory is a symbolic link: {path}")
        if path.exists() and not path.is_dir():
            raise ValueError(f"finding history directory is not a directory: {path}")
    return directory


def _read(path: Path) -> dict[str, Any]:
    """The document of one store file whose name, bytes and canonical content agree."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"finding history entry is not a regular file: {path}")
    name = path.name.removesuffix(".json")
    if not path.name.endswith(".json") or not is_sha256(name):
        raise ValueError(f"finding history entry is not named by a SHA-256: {path}")
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise ValueError(f"finding history entry is not JSON: {path}") from error
    if hashlib.sha256(raw).hexdigest() != name or not isinstance(document, dict) or canonical_json(document) != raw:
        raise ValueError(f"finding history entry does not match its content address: {path}")
    return document


def _entries(directory: Path, bound: int, unit: str) -> list[Path]:
    if not directory.is_dir():
        return []
    entries = sorted(directory.iterdir())
    if len(entries) > bound:
        raise ValueError(f"finding history holds more than {bound} {unit}: {directory}")
    return entries


def _snapshots(root: Any, target_id: str) -> list[tuple[str, dict[str, Any]]]:
    loaded = []
    for path in _entries(_directory(root, target_id, "snapshots"), MAX_SNAPSHOTS, "snapshots"):
        document = _read(path)
        try:
            check_snapshot(document)
        except ValueError as error:
            raise ValueError(f"finding history entry is not a finding snapshot: {path}") from error
        if document["target_id"] != target_id:
            raise ValueError(f"finding history entry belongs to another target: {path}")
        loaded.append((path.name.removesuffix(".json"), document))
    return loaded


def _lifecycles(root: Any, target_id: str) -> list[tuple[str, dict[str, Any]]]:
    loaded = []
    for path in _entries(_directory(root, target_id, "lifecycles"), MAX_LIFECYCLES, "lifecycles"):
        document = _read(path)
        try:
            check_lifecycle(document)
        except ValueError as error:
            raise ValueError(f"finding history entry is not a lifecycle: {path}") from error
        if document["target_id"] != target_id:
            raise ValueError(f"finding history entry belongs to another target: {path}")
        loaded.append((path.name.removesuffix(".json"), document))
    return loaded


def _publish(directory: Path, document: Mapping[str, Any], identity: str) -> dict[str, str]:
    path = directory / f"{identity}.json"
    if path.is_symlink():
        raise ValueError(f"finding history entry is a symbolic link: {path}")
    try:
        protected_json(path, document)
    except FileExistsError:
        if path.read_bytes() != canonical_json(document):
            raise ValueError(f"finding history identity collision: {path}") from None
        return {"status": "duplicate", "sha256": identity, "path": str(path)}
    return {"status": "published", "sha256": identity, "path": str(path)}


def publish_snapshot(root: Any, snapshot: Mapping[str, Any]) -> dict[str, str]:
    """Store one snapshot under its digest; ``published`` or, for identical content, ``duplicate``.

    A target holds one snapshot per ``(run_id, stage)``: a second, different one is refused, and so
    is a snapshot beyond ``MAX_SNAPSHOTS``.
    """
    snapshot = check_snapshot(snapshot)
    target_id = _target(snapshot["target_id"])
    identity = digest(snapshot)
    stored = _snapshots(root, target_id)
    known = {sha256 for sha256, _ in stored}
    if identity not in known:
        if any((document["run_id"], document["stage"]) == (snapshot["run_id"], snapshot["stage"])
               for _, document in stored):
            raise ValueError("finding history already holds a different snapshot of this run and stage")
        if len(stored) >= MAX_SNAPSHOTS:
            raise ValueError(f"finding history holds the bounded number of snapshots ({MAX_SNAPSHOTS})")
    return _publish(_directory(root, target_id, "snapshots"), snapshot, identity)


def publish_lifecycle(root: Any, target_id: str, lifecycle: Mapping[str, Any]) -> dict[str, str]:
    """Store one lifecycle document under its digest.

    A run pair may hold several (the classification and the one after re-checks were applied); the
    store is bounded to ``MAX_LIFECYCLES``.
    """
    lifecycle = check_lifecycle(lifecycle)
    if lifecycle["target_id"] != _target(target_id):
        raise ValueError("lifecycle belongs to another target")
    identity = digest(lifecycle)
    directory = _directory(root, target_id, "lifecycles")
    entries = _entries(directory, MAX_LIFECYCLES, "lifecycles")
    if len(entries) >= MAX_LIFECYCLES and directory / f"{identity}.json" not in entries:
        raise ValueError(f"finding history holds the bounded number of lifecycles ({MAX_LIFECYCLES})")
    return _publish(directory, lifecycle, identity)


def load_history(root: Any, target_id: str) -> dict[str, Any]:
    """The verified ``finding-history/1`` view of one target; empty when the target has no store.

    Each snapshot row carries ``fingerprints``, the sorted ``exact`` keys of its findings, so
    ``ages`` needs no second read of the store.
    """
    snapshots = [{"sha256": sha256, "run_id": document["run_id"], "stage": document["stage"],
                  "source_revision": document["source_revision"], "finding_count": len(document["findings"]),
                  "fingerprints": sorted({finding["fingerprint"]["exact"] for finding in document["findings"]})}
                 for sha256, document in _snapshots(root, target_id)]
    lifecycles = sorted(_lifecycles(root, target_id),
                        key=lambda item: (item[1]["prior_run_id"], item[1]["current_run_id"], item[0]))
    return {"schema": HISTORY_SCHEMA, "target_id": target_id,
            "snapshots": sorted(snapshots, key=lambda row: (row["stage"], row["run_id"], row["sha256"])),
            "lifecycles": [document for _, document in lifecycles]}


def read_snapshot(root: Any, target_id: str, sha256: str) -> dict[str, Any]:
    """One stored snapshot, verified against its content address, schema and target."""
    if not is_sha256(sha256):
        raise ValueError("a stored snapshot is named by a SHA-256")
    path = _directory(root, target_id, "snapshots") / f"{sha256}.json"
    document = _read(path)
    try:
        check_snapshot(document)
    except ValueError as error:
        raise ValueError(f"finding history entry is not a finding snapshot: {path}") from error
    if document["target_id"] != target_id:
        raise ValueError(f"finding history entry belongs to another target: {path}")
    return document


def _history(history: Any) -> Mapping[str, Any]:
    if (not isinstance(history, Mapping) or history.get("schema") != HISTORY_SCHEMA
            or not isinstance(history.get("snapshots"), list) or not isinstance(history.get("lifecycles"), list)):
        raise ValueError("unsupported finding history schema")
    return history


def previously_fixed(history: Mapping[str, Any]) -> frozenset[str]:
    """``fingerprint_exact`` of every prior row any stored lifecycle records as ``fixed``."""
    return frozenset(row["fingerprint_exact"] for lifecycle in _history(history)["lifecycles"]
                     for row in lifecycle["prior"] if row["state"] == LifecycleState.FIXED.value)


def ages(history: Mapping[str, Any], stage: str = "published") -> dict[str, int]:
    """For each fingerprint ``exact`` key, the number of stored snapshots of ``stage`` holding it."""
    if stage not in SNAPSHOT_STAGES:
        raise ValueError(f"unknown snapshot stage {stage!r}")
    seen: dict[str, int] = {}
    for row in _history(history)["snapshots"]:
        if row["stage"] == stage:
            for key in set(row["fingerprints"]):
                seen[key] = seen.get(key, 0) + 1
    return dict(sorted(seen.items()))


def latest_prior(history: Mapping[str, Any], *, stage: str, before_run_id: str) -> str | None:
    """Digest of the stored ``stage`` snapshot with the greatest ``run_id`` below ``before_run_id``.

    Run ids compare as strings; ``None`` when the history holds no earlier run of that stage.
    """
    if stage not in SNAPSHOT_STAGES:
        raise ValueError(f"unknown snapshot stage {stage!r}")
    if not isinstance(before_run_id, str) or not before_run_id:
        raise ValueError("before_run_id must be a non-empty run id")
    earlier = [(row["run_id"], row["sha256"]) for row in _history(history)["snapshots"]
               if row["stage"] == stage and row["run_id"] < before_run_id]
    return max(earlier)[1] if earlier else None


__all__ = ["MAX_LIFECYCLES", "MAX_SNAPSHOTS", "ages", "latest_prior", "load_history", "previously_fixed",
           "publish_lifecycle", "publish_snapshot", "read_snapshot"]
