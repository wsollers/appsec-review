"""Hash-verified access to accepted upstream handoffs and their artifacts."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import json
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.storage import file_sha256


def read_json(run_root: Path, identity: Mapping[str, Any]) -> Any:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted artifact identity changed")
    return json.loads(path.read_text(encoding="utf-8"))


def read_lines(run_root: Path, identity: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted artifact identity changed")
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def has_handoff(run_root: Path, job_id: str) -> bool:
    return (run_root / "data" / "jobs" / job_id / "latest.json").is_file()


def accepted_handoff(run_root: Path, job_id: str) -> tuple[Mapping[str, Any], str]:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise ValueError(f"accepted {job_id} handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = read_json(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def producer_entities(run_root: Path, manifest: Mapping[str, Any], *, job: str, kind: str,
                      producer: str | None = None) -> Iterator[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Yield (shard identity, entity payload) for verified shards published by one upstream job."""
    document, _ = load_verified_manifest(run_root, run_root / str(manifest["path"]), str(manifest["sha256"]))
    for shard in document.get("indexes", ()):
        owner = shard.get("producer", {})
        if owner.get("job") != job or (producer is not None and owner.get("producer") != producer):
            continue
        candidate = (run_root / shard["relative_path"]).resolve()
        uri = f"file:{candidate.as_posix()}?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True) as database:
            rows = database.execute(
                "SELECT e.identity, e.payload_json, l.path, l.file_sha256, l.start_byte, l.end_byte, l.start_line, "
                "l.end_line, l.start_column, l.end_column FROM entities e LEFT JOIN locations l "
                "ON l.entity_id = e.identity WHERE e.kind = ? ORDER BY e.identity", (kind,))
            for row in rows:
                payload = json.loads(row[1])
                location = None if row[2] is None else {
                    "path": row[2], "file_sha256": row[3], "start_byte": row[4], "end_byte": row[5],
                    "start_line": row[6], "end_line": row[7], "start_column": row[8], "end_column": row[9]}
                yield shard, {"identity": row[0], "payload": payload, "location": location}
