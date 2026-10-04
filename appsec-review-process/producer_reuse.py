"""Content-keyed reuse for evidence producers whose request carries per-launch values.

The vendor, dependency and binary CVE producers build their request on every launch (a fresh
``generated_at``, a fresh orchestration attempt) and their envelopes bind the attempt id, so their
own fingerprints can never match across launches. Before any container runs, each route derives a
content record instead: the bytes and hashes it reads, the pinned image records, its own code and
contracts and the bound upstream content by hash, never a Dagster run id, attempt id, timestamp or
per-launch path. ``reuse.json`` beside the accepted pointer remembers which accepted attempt was
produced from which content key; a launch whose key matches, and whose accepted attempt still
verifies, returns that pointer and runs nothing (ADR-0013, resume reuse,
run 20261004T054551Z-357581). The equivalent of ``coordinate_worker_lifecycle``'s reuse check for
routes that publish through their own seams. The record lives outside the immutable attempt, so it
names the attempt by id and envelope hash and is never trusted alone: the accepted pointer, the
attempt tree and the route's own verifier decide. Any mismatch or verification failure re-executes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

import container_execution as ce
from execution_state import (ROOT, Blocked, atomic_json, digest, drop_shared_runtime, file_hash,
                             identifier, read_json, tree_hashes)

SCHEMA = "appsec-review/producer-reuse-record/1.0"
RECORD = "reuse.json"
ACCEPTED_SCHEMA = "appsec-review/accepted-worker-result/1.0"
PUBLISHABLE = {"OK", "OK_WITH_GAPS", "SKIPPED"}


def key(inputs: dict[str, Any]) -> str:
    return "sha256:" + digest(inputs)


def code(names: Iterable[str]) -> dict[str, str | None]:
    """Process-root relative code and contract hashes, without the shared runtime (ADR-0013)."""
    values = {}
    for name in names:
        path = ROOT / name
        values[name] = file_hash(path) if path.is_file() else None
    return drop_shared_runtime(values)


def images(image_ids: Iterable[str], images_dir: Path | None = None) -> dict[str, Any]:
    """The pinned image record identity per image id; an unregistered image is recorded as None."""
    try:
        registry = ce.load_image_registry(images_dir or ce.IMAGES_DIR)
    except ce.ContainerRequestError:
        registry = {}
    return {image_id: ({"digest": registry[image_id].get("digest"),
                        "record_sha256": digest(registry[image_id])} if image_id in registry else None)
            for image_id in sorted(set(image_ids))}


def admit(base: Path, inputs: dict[str, Any], *, run_id: str, job_id: str,
          verify: Callable[[Path, dict[str, Any], dict[str, Any]], None] | None = None
          ) -> dict[str, Any] | None:
    """The accepted pointer when it was published from exactly ``inputs`` and still verifies, else None.

    ``verify(attempt, pointer, record)`` is the route's own publication validator; any exception it
    raises means "re-execute", never "accept"."""
    base = Path(base)
    try:
        record = read_json(base / RECORD)
        pointer = read_json(base / "accepted.json")
        latest = read_json(base / "latest.json")
    except (OSError, ValueError):
        return None
    if (not isinstance(record, dict) or record.get("schema") != SCHEMA or
            record.get("run_id") != run_id or record.get("job_id") != job_id or
            record.get("reuse_key") != key(inputs) or not isinstance(pointer, dict) or
            pointer.get("schema") != ACCEPTED_SCHEMA or pointer.get("run_id") != run_id or
            pointer.get("job") != job_id or pointer.get("status") not in PUBLISHABLE or
            pointer.get("attempt_id") != record.get("attempt_id") or
            pointer.get("envelope_sha256") != record.get("envelope_sha256") or
            not isinstance(latest, dict) or latest.get("attempt_id") != pointer.get("attempt_id")):
        return None
    try:
        attempt = base / "attempts" / identifier(pointer["attempt_id"])
        if (not attempt.is_dir() or attempt.is_symlink() or tree_hashes(attempt) != pointer.get("hashes") or
                file_hash(attempt / "result.json") != pointer["envelope_sha256"]):
            return None
        envelope = read_json(attempt / "result.json")
        if (envelope.get("attempt_id") != pointer["attempt_id"] or envelope.get("acceptance_status") != "CURRENT" or
                envelope.get("execution_status") != pointer["status"]):
            return None
        if verify is not None:
            verify(attempt, pointer, record)
    except (Blocked, OSError, ValueError, KeyError, TypeError):
        return None
    return pointer


def remember(base: Path, inputs: dict[str, Any], pointer: dict[str, Any], *, run_id: str, job_id: str,
             facts: dict[str, Any] | None = None) -> None:
    """Record that the just-published accepted pointer was produced from ``inputs``. ``facts`` are the
    orchestration facts a later verification needs (the producing Dagster run, its observation time).
    A pointer without the common identity fields cannot be admitted later, so nothing is recorded."""
    if not isinstance(pointer, dict) or not {"attempt_id", "envelope_sha256"} <= set(pointer):
        return
    atomic_json(Path(base) / RECORD, {"schema": SCHEMA, "run_id": run_id, "job_id": job_id,
        "reuse_key": key(inputs), "attempt_id": pointer["attempt_id"],
        "envelope_sha256": pointer["envelope_sha256"], "inputs": inputs, **(facts or {})})
