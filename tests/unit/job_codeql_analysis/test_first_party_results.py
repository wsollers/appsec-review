"""CodeQL query results located in non-first-party files are counted, not published (T-5016)."""
from __future__ import annotations

from appsec_review.jobs.job_codeql_analysis.sarif import scope_first_party
from appsec_review.review.dispositions import SourceDispositions

DISPOSITIONS = SourceDispositions(vendored=("**/third_party/**",), test=("tests/**",))


def _record(path: str | None) -> dict:
    return {"rule_id": "cpp/x", "native_id": path or "unlocated",
            "location": {"path": path} if path is not None else None}


def test_first_party_and_unlocated_results_are_kept_and_the_rest_are_counted_per_disposition() -> None:
    records = [_record("src/request.cpp"), _record("third_party/zlib/gzwrite.c"), _record("tests/t.cpp"),
               _record("third_party/lz4/lib/lz4.c"), _record(None)]
    kept, excluded = scope_first_party(records, DISPOSITIONS)
    assert [record["native_id"] for record in kept] == ["src/request.cpp", "unlocated"]
    assert excluded == {"test": 1, "vendored": 2}


def test_without_configured_dispositions_every_result_is_kept() -> None:
    records = [_record("third_party/zlib/gzwrite.c"), _record("src/a.c")]
    kept, excluded = scope_first_party(records, SourceDispositions())
    assert kept == records and excluded == {}
