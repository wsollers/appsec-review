"""Bounded, manifest-exact, run-owned scratch copies with explicit cleanup."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
from typing import Any

from appsec_review.config.remediation import RemediationBounds
from appsec_review.jobs.job_poc_generation.buildctx import BuildUnit
from appsec_review.jobs.job_remediation_planning.patches import safe_file, relative_path
from appsec_review.review.models import IntegrityError


class WorkspaceLimit(ValueError):
    """A safe scratch copy cannot fit its commissioned resource bounds."""


def materialize(build: BuildUnit, destination: Path, bounds: RemediationBounds, *, run_root: Path) -> None:
    if run_root.resolve() not in build.workspace.resolve().parents:
        raise IntegrityError("accepted remediation source workspace is not run-owned")
    if len(build.workspace_manifest) > bounds.max_workspace_files:
        raise WorkspaceLimit("workspace_file_bound_reached")
    if destination.exists():
        raise IntegrityError("remediation scratch workspace already exists")
    destination.mkdir(parents=True)
    total = 0
    for relative, digest in sorted(build.workspace_manifest.items()):
        relative_path(relative)
        source = safe_file(build.workspace, relative)
        if source.stat().st_size + total > bounds.max_workspace_bytes:
            raise WorkspaceLimit("workspace_byte_bound_reached")
        data = source.read_bytes()
        total += len(data)
        if hashlib.sha256(data).hexdigest() != digest:
            raise IntegrityError(f"accepted workspace bytes changed: {relative}")
        target = safe_file(destination, relative, missing=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def manifest(root: Path, bounds: RemediationBounds) -> dict[str, str]:
    result: dict[str, str] = {}
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise IntegrityError("scratch workspace contains an unexpected symlink or junction")
        if not path.is_file():
            continue
        if len(result) >= bounds.max_workspace_files or total + path.stat().st_size > bounds.max_workspace_bytes:
            raise WorkspaceLimit("scratch_workspace_bound_reached")
        data = path.read_bytes()
        total += len(data)
        result[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    return result


def cleanup(root: Path, run_root: Path) -> dict[str, Any]:
    if run_root.resolve() not in root.resolve().parents or root.name != "scratch":
        raise IntegrityError("cleanup path is not a named attempt-owned remediation scratch directory")
    created = root.exists()
    try:
        if created:
            shutil.rmtree(root)
    except OSError as exc:
        return {"workspace": root.relative_to(run_root).as_posix(), "created": created,
                "removed": False, "error": f"{type(exc).__name__}:{str(exc)[:160]}"}
    return {"workspace": root.relative_to(run_root).as_posix(), "created": created,
            "removed": not root.exists(), "error": None}
