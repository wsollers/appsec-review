"""Bounded, manifest-exact, run-owned scratch copies with explicit cleanup."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
from typing import Any, Mapping

from appsec_review.config.remediation import RemediationBounds
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, BuildUnit, workspace_bytes
from appsec_review.jobs.job_remediation_planning.patches import safe_file, relative_path
from appsec_review.review.models import IntegrityError


class WorkspaceLimit(ValueError):
    """A safe scratch copy cannot fit its commissioned resource bounds."""


def admit_source_context(files: Any, builds: AcceptedBuilds, bounds: RemediationBounds, *,
                         run_root: Path) -> dict[str, BuildUnit]:
    """Re-admit the entire planning context without truncating or rewriting accepted source text."""
    if not isinstance(files, list):
        raise IntegrityError("proposal source context files are malformed")
    if len(files) > bounds.max_source_files:
        raise WorkspaceLimit("source_file_bound_reached")
    admitted: dict[str, BuildUnit] = {}
    total = 0
    for source in files:
        if not isinstance(source, Mapping) or not isinstance(source.get("text"), str):
            raise IntegrityError("proposal source context file is malformed")
        name = relative_path(source.get("path"))
        if name in admitted:
            raise IntegrityError("proposal source context contains duplicate paths")
        try:
            expected = source["text"].encode("utf-8")
        except UnicodeEncodeError as exc:
            raise IntegrityError("proposal source context is not UTF-8") from exc
        limit = min(bounds.max_file_bytes, bounds.max_source_bytes - total)
        if len(expected) > limit:
            raise WorkspaceLimit("source_byte_bound_reached")
        located = builds.locate(name)
        if located.unit is None or located.unit.identity() != source.get("build"):
            raise IntegrityError("proposal source build identity changed")
        build = located.unit
        if run_root.resolve() not in build.workspace.resolve().parents:
            raise IntegrityError("accepted remediation source workspace is not run-owned")
        if build.workspace_manifest.get(name) != source.get("sha256"):
            raise IntegrityError("proposal source hash differs from accepted workspace")
        data = workspace_bytes(build.workspace, build.workspace_manifest, name, byte_limit=limit)
        if data is None:
            raise WorkspaceLimit("source_byte_bound_reached")
        if data != expected:
            raise IntegrityError("proposal source text differs from accepted workspace bytes")
        total += len(data)
        admitted[name] = build
    return admitted


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
        with source.open("rb") as stream:
            data = stream.read(bounds.max_workspace_bytes - total + 1)
        if len(data) + total > bounds.max_workspace_bytes:
            raise WorkspaceLimit("workspace_byte_bound_reached")
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
        with path.open("rb") as stream:
            data = stream.read(bounds.max_workspace_bytes - total + 1)
        if len(data) + total > bounds.max_workspace_bytes:
            raise WorkspaceLimit("scratch_workspace_bound_reached")
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
