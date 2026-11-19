"""Seed plans for producers that run per project and read the job's pinned input manifest."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import os
from pathlib import Path
from typing import Any

from appsec_review.config.seeding import SeededSettings
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.storage.shared import safe_path

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


class SourceScanLimit(ValueError):
    """An existing source could not be scanned within the per-file byte limit."""


class SourceScanIncomplete(ValueError):
    """An existing source did not yield its complete observed bytes."""


def source_reader(source_root: Path):
    """Read an accepted source copy without following links or exceeding the per-file byte limit.

    Oversized or incomplete sources are omitted, not parsed as complete prefixes. The selector
    records the read failure as a gap while retaining the file's existence for include search order.
    """
    root = source_root.resolve()

    def read(relative: str) -> str | None:
        try:
            path = safe_path(root, relative)
        except ValueError:
            return None
        try:
            if not path.is_file():
                return None
            gap = (f"include_scan_bytes_limit_reached: {relative} exceeds {MAX_SCAN_BYTES} bytes; "
                   "its transitive includes were not scanned")
            incomplete = (f"include_scan_incomplete: {relative} did not yield its complete observed bytes; "
                          "its transitive includes were not scanned")
            if path.stat().st_size > MAX_SCAN_BYTES:
                raise SourceScanLimit(gap)
            with path.open("rb", buffering=0) as stream:
                size = os.fstat(stream.fileno()).st_size
                if size > MAX_SCAN_BYTES:
                    raise SourceScanLimit(gap)
                data = bytearray()
                while True:
                    remaining = size - len(data)
                    chunk = stream.read(remaining)
                    if not chunk and remaining:
                        raise SourceScanIncomplete(incomplete)
                    data.extend(chunk)
                    if len(data) == size:
                        break
                after = os.fstat(stream.fileno()).st_size
                if after > MAX_SCAN_BYTES:
                    raise SourceScanLimit(gap)
                if after != size:
                    raise SourceScanIncomplete(incomplete)
            return data.decode("utf-8", errors="replace")
        except OSError:
            return None

    return read
