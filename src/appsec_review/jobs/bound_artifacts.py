"""Hash-bound reads of run-owned artifacts for jobs that only project accepted state.

The final publication gate and the final report publication read artifacts that earlier jobs
accepted. Every read goes through :func:`read_bound`, which re-hashes the bytes, so a file changed
after acceptance is an :class:`IntegrityError` and never a quietly different report.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.review.models import IntegrityError
from appsec_review.storage import file_sha256


def artifact_ref(run_root: Path, path: Path) -> dict[str, str]:
    """``{path, sha256}`` of a run-owned file, the path relative to the run root."""
    resolved = Path(path).resolve()
    root = Path(run_root).resolve()
    if root not in resolved.parents:
        raise IntegrityError(f"artifact is outside the run: {path}")
    return {"path": resolved.relative_to(root).as_posix(), "sha256": file_sha256(resolved)}


def resolve_bound(run_root: Path, reference: Mapping[str, Any]) -> Path:
    """The file a reference names, after proving it is a regular run-owned file with that hash."""
    root = Path(run_root).resolve()
    name = reference.get("path")
    digest = reference.get("sha256")
    if not isinstance(name, str) or not isinstance(digest, str):
        raise IntegrityError("artifact reference is malformed")
    path = root / name
    if path.is_symlink():
        raise IntegrityError(f"run-owned artifact is a symbolic link: {name}")
    resolved = path.resolve()
    if root not in resolved.parents or not resolved.is_file():
        raise IntegrityError(f"run-owned artifact is missing or outside the run: {name}")
    if file_sha256(resolved) != digest:
        raise IntegrityError(f"run-owned artifact changed after acceptance: {name}")
    return resolved


def read_bound(run_root: Path, reference: Mapping[str, Any]) -> bytes:
    return resolve_bound(run_root, reference).read_bytes()


def read_bound_json(run_root: Path, reference: Mapping[str, Any]) -> Any:
    try:
        return json.loads(read_bound(run_root, reference).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise IntegrityError(f"run-owned artifact is not valid JSON: {reference.get('path')}") from exc
