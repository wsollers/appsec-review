from __future__ import annotations

import hashlib

import pytest

from appsec_review.debug_symbols.contract import SourceSpan
from appsec_review.jobs.job_debug_symbol_indexing.job import _Sources


def _resolver(data: bytes, *, maximum=4096):
    digest = hashlib.sha256(data).hexdigest()
    row = {"identity": "source-1", "path": "src/main.cc", "sha256": digest}
    sources = _Sources.__new__(_Sources)
    sources.maximum = maximum
    sources.cache = {digest: data}
    sources.by_path = {"src/main.cc": [row]}
    sources.by_sha256 = {digest: [row]}
    sources.line_offsets = {}
    sources.line_offset_bytes = 0

    class NoInventoryScan:
        def __iter__(self):
            pytest.fail("source resolution scanned the source inventory")

    sources.rows = NoInventoryScan()
    return sources, row


@pytest.mark.parametrize("data", [
    b"", b"\n", b"a\r\nb\rc\nlast", b"\v\f\x85a", b"last",
])
def test_cached_source_offsets_preserve_byte_line_boundaries(data):
    sources, row = _resolver(data)
    offsets = sources._line_table(row["sha256"], data)
    assert offsets is not None
    assert [data[start:end] for start, end in zip(offsets, offsets[1:])] == data.splitlines(keepends=True)
    assert sources._line_table(row["sha256"], data) is offsets


def test_repeated_source_resolution_uses_indexes_and_cached_line_offsets(monkeypatch):
    data = b"first\r\nsecond\nlast"
    sources, row = _resolver(data)
    span = SourceSpan(r"C:\private\checkout\src\main.cc", 2, 1, row["sha256"], "sha256")
    result, gap = sources.resolve(span)
    assert gap is None
    assert (result["start_byte"], result["end_byte"]) == (7, 14)

    def no_rescan(*_args, **_kwargs):
        pytest.fail("cached source bytes were rescanned for line offsets")

    monkeypatch.setattr("appsec_review.jobs.job_debug_symbol_indexing.job.re.finditer", no_rescan)
    again, gap = sources.resolve(SourceSpan("src/main.cc", 3, 5, row["sha256"], "sha256"))
    assert gap is None
    assert (again["start_byte"], again["end_byte"]) == (14, len(data))
    assert sources.line_offset_bytes <= sources.maximum


@pytest.mark.parametrize("line,column", [(0, 0), (5, 1), (4, 6)])
def test_source_offsets_reject_out_of_range_locations(line, column):
    sources, row = _resolver(b"a\r\nb\rc\nlast")
    if line == 0:
        with pytest.raises(ValueError):
            SourceSpan("src/main.cc", line, column, row["sha256"], "sha256")
        return
    result, gap = sources.resolve(SourceSpan("src/main.cc", line, column, row["sha256"], "sha256"))
    assert result is None and gap == "source_checksum_unverified"


def test_duplicate_checksums_remain_ambiguous():
    sources, row = _resolver(b"line\n")
    sources.by_sha256[row["sha256"]].append({**row, "identity": "source-2", "path": "other.cc"})
    result, gap = sources.resolve(SourceSpan("src/main.cc", 1, 0, row["sha256"], "sha256"))
    assert result is None and gap == "source_checksum_ambiguous"


def test_line_offset_memory_bound_is_an_explicit_gap():
    sources, row = _resolver(b"\n" * 20, maximum=16)
    result, gap = sources.resolve(SourceSpan("src/main.cc", 1, 0, row["sha256"], "sha256"))
    assert result is None and gap == "source_line_offset_bound"
    assert sources.line_offset_bytes == 0
