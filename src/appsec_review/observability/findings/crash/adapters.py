"""The pluggable crash-adapter registry and batch ingestion (finding-metrics.md section 7.2, T-072).

One adapter per format, registered by name. An adapter is a pure, bounded function from the bytes
of one file an operator has *already exported* to ``crash-report/1`` records. Nothing here fetches
from a crash service, reads or walks a raw minidump, runs a symbolication tool, opens a file, starts
a process or touches the network; ``publish_evidence`` is the only function that writes, and it
writes the normalized evidence only.

Crash content is untrusted data: it is parsed with the standard library, never evaluated, and never
echoed in an error. The ingestion result carries no file name and no file content: a failed file is
named by its SHA-256 and a closed failure kind. Metric keys are closed vocabularies only (adapter
name, fault class, binding tier).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Any

from appsec_review.storage import canonical_json, protected_json

from ..contracts import CRASH_EVIDENCE_SCHEMA, MAX_CRASH_REPORTS, digest
from .adapter_sanitizer import parse_sanitizer_report
from .adapter_sentry import parse_sentry_event
from .adapter_stackwalk import parse_stackwalk_json
from .records import (ADAPTER_NAME, MAX_INPUT_BYTES, check_evidence, input_digest, normalize_report, review_rank,
                      seen_key)

Adapter = Callable[..., list[dict[str, Any]]]     # (data: bytes, *, roots: Sequence[str]) -> reports

_REGISTRY: dict[str, Adapter] = {}
ADAPTERS: Mapping[str, Adapter] = MappingProxyType(_REGISTRY)


def register(name: str, parse: Adapter) -> None:
    """Register an adapter; a duplicate name, a malformed name or a non-callable is refused."""
    if not isinstance(name, str) or not ADAPTER_NAME.match(name):
        raise ValueError("crash adapter name must match ^[a-z][a-z0-9_]{1,31}$")
    if name in _REGISTRY:
        raise ValueError(f"crash adapter {name} is already registered")
    if not callable(parse):
        raise ValueError("crash adapter must be callable")
    _REGISTRY[name] = parse


register("stackwalk_json", parse_stackwalk_json)
register("sanitizer_report", parse_sanitizer_report)
register("sentry_event", parse_sentry_event)


def parse(adapter_name: str, data: bytes, *, roots: Sequence[str] = ()) -> list[dict[str, Any]]:
    """The normalized reports one registered adapter reads from one file's bytes.

    Raises ``ValueError`` for an unknown adapter (listing the registered names), an input over
    16 MiB, or input the adapter cannot parse. The message never contains input content. Every
    report is re-normalized here and carries the registered adapter name and the SHA-256 of ``data``.
    """
    adapter = _REGISTRY.get(adapter_name) if isinstance(adapter_name, str) else None
    if adapter is None:
        raise ValueError(f"unknown crash adapter; registered: {', '.join(sorted(_REGISTRY))}")
    source = input_digest(data)
    try:
        reports = adapter(bytes(data), roots=tuple(roots))
        if not isinstance(reports, list):
            raise ValueError("crash adapter did not return a list of reports")
        return [normalize_report({**report, "adapter": adapter_name, "source_sha256": source})
                for report in reports]
    except ValueError:
        raise
    except Exception:           # an adapter defect must not surface untrusted content or stop a batch
        raise ValueError("crash input could not be parsed") from None


def _merge(group: list[dict[str, Any]]) -> dict[str, Any]:
    first = [item["first_seen"] for item in group if item["first_seen"] is not None]
    last = [item["last_seen"] for item in group if item["last_seen"] is not None]
    return normalize_report({
        **group[0], "occurrences": sum(item["occurrences"] for item in group),
        "first_seen": min(first + last, key=seen_key) if first or last else None,
        "last_seen": max(first + last, key=seen_key) if first or last else None,
        "gaps": sorted({gap for item in group for gap in item["gaps"]})})


def ingest(sources: Iterable[tuple[str, str, bytes]], *, roots: Sequence[str] = (),
           max_reports: int = MAX_CRASH_REPORTS) -> dict[str, Any]:
    """Parse a batch of exported crash files into one ``crash-evidence/1`` document.

    ``sources`` is a list of ``(adapter_name, file_name, data_bytes)``. The file name is accepted so
    a caller can pass its listing unchanged; it is never read, stored or returned. A file that fails
    does not abort the batch: it is recorded as ``{"file_sha256", "adapter", "error"}`` with ``error``
    one of ``unparseable``, ``too_large`` (over 16 MiB) and ``unknown_adapter``; ``adapter`` is ``None``
    for an unknown adapter, because an unregistered name is caller text. A file whose bytes were
    already seen for the same adapter is counted in ``duplicate_files`` and not parsed again, so a
    file listed twice never doubles an occurrence count.

    Reports with the same ``(adapter, bucket_id)`` merge into one bucket: occurrences are summed,
    first and last seen are widened, gaps are united, and the frames, build and fault of the first
    report in ``source_sha256`` order are kept. More than ``max_reports`` reports before merging (at
    most, and by default, ``MAX_CRASH_REPORTS``) or more than ``MAX_CRASH_REPORTS`` files is a
    ``ValueError``, never a silent subset. ``counts.reports`` counts reports before merging and
    ``counts.buckets`` after; ``sha256`` is the digest of the reports.
    """
    if isinstance(max_reports, bool) or not isinstance(max_reports, int) or not 1 <= max_reports <= MAX_CRASH_REPORTS:
        raise ValueError("max_reports must be between 1 and the bounded number of crash reports")
    if isinstance(sources, (str, bytes, Mapping)):
        raise ValueError("crash sources must be a list of (adapter, file name, bytes)")
    failures: list[dict[str, Any]] = []
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    files = parsed = duplicates = total = 0
    for source in sources:
        if (not isinstance(source, (tuple, list)) or len(source) != 3 or not isinstance(source[0], str)
                or not isinstance(source[1], str) or not isinstance(source[2], (bytes, bytearray))):
            raise ValueError("crash sources must be a list of (adapter, file name, bytes)")
        adapter_name, _, data = source
        files += 1
        if files > MAX_CRASH_REPORTS:
            raise ValueError("crash ingestion exceeds the bounded number of files")
        sha256 = hashlib.sha256(data).hexdigest()
        registered = adapter_name in _REGISTRY
        if (adapter_name if registered else "", sha256) in seen:
            duplicates += 1
            continue
        seen.add((adapter_name if registered else "", sha256))
        if not registered:
            failures.append({"file_sha256": sha256, "adapter": None, "error": "unknown_adapter"})
            continue
        if len(data) > MAX_INPUT_BYTES:
            failures.append({"file_sha256": sha256, "adapter": adapter_name, "error": "too_large"})
            continue
        try:
            reports = parse(adapter_name, data, roots=roots)
        except ValueError:
            failures.append({"file_sha256": sha256, "adapter": adapter_name, "error": "unparseable"})
            continue
        parsed += 1
        total += len(reports)
        if total > max_reports:
            raise ValueError("crash ingestion exceeds the bounded number of reports")
        for report in reports:
            groups.setdefault((adapter_name, report["bucket_id"]), []).append(report)
    merged = [_merge(sorted(group, key=lambda item: item["source_sha256"])) for group in groups.values()]
    merged.sort(key=lambda item: (review_rank(item), item["bucket_id"], item["adapter"]))
    failures.sort(key=lambda item: (item["file_sha256"], item["adapter"] or "", item["error"]))
    return {"schema": CRASH_EVIDENCE_SCHEMA, "reports": merged, "failures": failures,
            "counts": {"files": files, "parsed": parsed, "failed": len(failures), "duplicate_files": duplicates,
                       "reports": total, "buckets": len(merged)},
            "sha256": digest(merged)}


def publish_evidence(directory: Path, evidence: Mapping[str, Any]) -> dict[str, str]:
    """Publish a checked ``crash-evidence/1`` document content-addressed under ``directory``.

    Returns ``{"status": "published" | "duplicate", "sha256", "path"}``; the SHA-256 is of the whole
    document's canonical JSON, which also names the file. An existing file with other bytes is an
    identity collision and a ``ValueError``.
    """
    checked = check_evidence(evidence)
    sha256 = hashlib.sha256(canonical_json(checked)).hexdigest()
    path = Path(directory) / (sha256 + ".json")
    try:
        protected_json(path, checked)
    except FileExistsError:
        if path.read_bytes() != canonical_json(checked):
            raise ValueError("crash evidence identity collision") from None
        return {"status": "duplicate", "sha256": sha256, "path": str(path)}
    return {"status": "published", "sha256": sha256, "path": str(path)}


__all__ = ["ADAPTERS", "Adapter", "ingest", "parse", "publish_evidence", "register"]
