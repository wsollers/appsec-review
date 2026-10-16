"""Seed plans for producers that run per project and read the job's pinned input manifest."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from appsec_review.config.seeding import SeededSettings
from appsec_review.retrieval.core import resolve_context_manifest

from .ledger import SeedPlan, extract_seeds
from .record import ProjectScope


def project_scope(case_id: str, mapping: Mapping[str, Any]) -> ProjectScope:
    """One accepted C/C++ project as a seed scope: seeds are project-relative, files are every source."""
    return ProjectScope(case_id, str(mapping["root"]),
                        tuple({"path": str(item["target_path"])} for item in mapping.get("files", ())))


def seed_plan(job: Any, scopes: Sequence[ProjectScope], settings: SeededSettings) -> SeedPlan:
    """Seeds of every scope from the hash-verified observation shards pinned to this job attempt.

    Reads accepted observation indices only; it never scans the target tree and never runs a tool.
    """
    path, sha256 = resolve_context_manifest(job)
    manifests = [{"path": path.relative_to(job.run_root.resolve()).as_posix(), "sha256": sha256}]
    return extract_seeds(job.run_root, manifests, scopes, seed_limit=settings.seed_limit)


MAX_SCAN_BYTES = 1024 * 1024


def source_reader(source_root: Path):
    """``read_text`` for :func:`select_units`: a project-relative file's text, bounded, never a symlink."""
    root = source_root.resolve()

    def read(relative: str) -> str | None:
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file() or path.is_symlink():
            return None
        try:
            return path.read_bytes()[:MAX_SCAN_BYTES].decode("utf-8", errors="replace")
        except OSError:
            return None

    return read
