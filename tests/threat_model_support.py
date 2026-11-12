"""In-memory evidence for threat-model unit tests (T-107). No files, no shards, no shared state."""
from __future__ import annotations

from typing import Any, Mapping

from appsec_review.threat_model.contract import EvidenceRecord, InputState, Publication, SourceSpan
from appsec_review.threat_model.view import InputStatus, Page

SHA_A = "a" * 64
SHA_B = "b" * 64


def publication(job: str, output_kind: str, *, index: str | None = "index", shard_id: str | None = "shard",
                sha256: str = SHA_A) -> Publication:
    return Publication(job, output_kind, index, shard_id, sha256)


def span(path: str, start_line: int = 1, end_line: int | None = None, *, file_sha256: str = SHA_B) -> SourceSpan:
    return SourceSpan(path, file_sha256, start_line, end_line if end_line is not None else start_line)


def record(producer: str, output_kind: str, kind: str, entity_id: str, payload: Mapping[str, Any] | None = None, *,
           name: str | None = None, at: SourceSpan | None = None) -> EvidenceRecord:
    return EvidenceRecord(entity_id, kind, name or entity_id, payload or {}, publication(producer, output_kind), at)


class FakeEvidenceView:
    """Literal records keyed by ``(producer, output_kind)``; inputs never added are ``absent``."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], list[EvidenceRecord]] = {}
        self._status: dict[tuple[str, str], InputStatus] = {}
        self._calls: dict[str, list[EvidenceRecord]] = {}
        self.queries: list[tuple[Any, ...]] = []

    def add(self, *records: EvidenceRecord) -> "FakeEvidenceView":
        for item in records:
            key = (item.publication.job, item.publication.output_kind)
            self._records.setdefault(key, []).append(item)
            self._status.setdefault(key, InputStatus(InputState.READ, item.publication.sha256, "complete"))
        return self

    def add_call(self, name: str, *records: EvidenceRecord) -> "FakeEvidenceView":
        self._calls.setdefault(name, []).extend(records)
        for item in records:
            key = (item.publication.job, item.publication.output_kind)
            self._status.setdefault(key, InputStatus(InputState.READ, item.publication.sha256, "complete"))
        return self

    def set_status(self, producer: str, output_kind: str, state: InputState, *, coverage: str | None = None,
                   upstream_gap_count: int = 0) -> "FakeEvidenceView":
        self._status[(producer, output_kind)] = InputStatus(
            state, None if state in {InputState.ABSENT, InputState.DISABLED, InputState.NOT_REGISTERED} else "c" * 64,
            coverage, upstream_gap_count)
        return self

    def input_status(self, producer: str, output_kind: str) -> InputStatus:
        return self._status.get((producer, output_kind), InputStatus(InputState.ABSENT))

    def entities(self, producer: str, output_kind: str, kind: str, *, limit: int) -> Page:
        self.queries.append(("entities", producer, output_kind, kind, limit))
        found = sorted((item for item in self._records.get((producer, output_kind), []) if item.entity_kind == kind),
                       key=lambda item: item.entity_id)
        return Page(tuple(found[:limit]), len(found) > limit)

    def search_calls(self, name: str, *, limit: int) -> Page:
        self.queries.append(("search_calls", name, limit))
        found = sorted(self._calls.get(name, []), key=lambda item: item.entity_id)
        return Page(tuple(found[:limit]), len(found) > limit)
