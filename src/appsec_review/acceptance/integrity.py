"""Check that one attempt's identifiers, hashes and paths are populated and consistent in its own run.

Two drivers of a job (docs/processes/local-dagster-parity.md) may record different run ids, attempt
ids, Dagster ids, hashes and paths; those differences do not fail parity. What must hold on each
side is that every such value is present and correct where it is used:

- the claim, status and handoff name this run, job and attempt, and agree with each other;
- the job's latest pointer names this handoff and its actual hash;
- every artifact the handoff lists, and every path-and-hash reference in the result, resolves
  inside the run to bytes with the recorded hash (and size, where recorded);
- every upstream handoff hash the attempt bound is the one that job accepted in this run, so the
  chain of hashes is consistent from job to job.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import hashlib
import json
from pathlib import Path
from typing import Any

from .diff import Difference


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _references(value: Any, where: str) -> Iterator[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            yield where, value
        for key, child in value.items():
            yield from _references(child, f"{where}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _references(child, f"{where}[{index}]")


def attempt_integrity(job_id: str, run_root: Path, run_id: str, attempt: Path | None,
                      side: str) -> list[Difference]:
    """Integrity problems of ``attempt`` within ``run_root``, labelled with the driver ``side``."""

    problems: list[Difference] = []

    def problem(path: str, expected: Any, actual: Any) -> None:
        problems.append(Difference(job_id, "integrity", f"{side}:{path}", str(expected), str(actual)))

    run_root = Path(run_root).resolve()
    if attempt is None:
        problem("attempt", "an attempt", "<absent>")
        return problems
    documents = {name: _read(attempt / f"{name}.json") for name in ("claim", "status", "handoff")}
    for name, document in documents.items():
        if document is None:
            problem(f"{name}.json", "a readable document", "<absent>")
    claim, status, handoff = documents["claim"] or {}, documents["status"] or {}, documents["handoff"] or {}
    for name, document in documents.items():
        if document is None:
            continue
        for key, expected in (("job_id", job_id), ("attempt_id", attempt.name)) + (
                (("run_id", run_id),) if name != "handoff" else ()):
            if document.get(key) != expected:
                problem(f"{name}.{key}", expected, document.get(key))
    if handoff:
        if handoff.get("status") != "ACCEPTED":
            problem("handoff.status", "ACCEPTED", handoff.get("status"))
        if status and status.get("status") != handoff.get("completion_status"):
            problem("status.status", handoff.get("completion_status"), status.get("status"))
        for key in ("source_fingerprint", "input_identity"):
            if claim and claim.get(key) != handoff.get(key):
                problem(f"handoff.{key}", claim.get(key), handoff.get(key))
        if claim and dict(claim.get("upstream_handoffs") or {}) != dict(handoff.get("upstream_handoff_sha256") or {}):
            problem("handoff.upstream_handoff_sha256", claim.get("upstream_handoffs"),
                    handoff.get("upstream_handoff_sha256"))
        if handoff.get("source_fingerprint") not in {None, "none"} and not claim.get("target_root"):
            problem("claim.target_root", "the target the attempt read", claim.get("target_root"))
        for key in ("implementation_identity", "schema_identity", "validation_identity", "resolved_config_sha256",
                    "job_config_sha256"):
            if not handoff.get(key):
                problem(f"handoff.{key}", "a populated identity", handoff.get(key))
        latest = _read(run_root / "data" / "jobs" / job_id / "latest.json")
        handoff_path = attempt / "handoff.json"
        if latest is None:
            problem("latest.json", "a pointer to the accepted handoff", "<absent>")
        else:
            if (run_root / str(latest.get("handoff_path", ""))).resolve() != handoff_path.resolve():
                problem("latest.json.handoff_path", handoff_path.relative_to(run_root).as_posix(),
                        latest.get("handoff_path"))
            if latest.get("handoff_sha256") != _sha256(handoff_path):
                problem("latest.json.handoff_sha256", _sha256(handoff_path), latest.get("handoff_sha256"))
        for upstream, digest in sorted(dict(handoff.get("upstream_handoff_sha256") or {}).items()):
            pointer = _read(run_root / "data" / "jobs" / upstream / "latest.json")
            if pointer is None or pointer.get("handoff_sha256") != digest:
                problem(f"upstream.{upstream}", digest, (pointer or {}).get("handoff_sha256", "<absent>"))
    references = list(_references(handoff.get("artifacts", []), "handoff.artifacts"))
    references += list(_references(_read(attempt / "result.json") or {}, "result"))
    for where, reference in references:
        relative = str(reference["path"])
        if relative.startswith("/") or relative.startswith("<"):
            continue
        target = (run_root / relative).resolve()
        if run_root not in target.parents or not target.is_file():
            problem(f"{where}.path", "a file inside the run", relative)
            continue
        if _sha256(target) != reference["sha256"]:
            problem(f"{where}.sha256", reference["sha256"], _sha256(target))
        size = reference.get("size_bytes")
        if isinstance(size, int) and size != target.stat().st_size:
            problem(f"{where}.size_bytes", size, target.stat().st_size)
    return problems
