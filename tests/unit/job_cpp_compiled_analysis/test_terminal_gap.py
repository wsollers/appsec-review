"""A language build that completed with named gaps is usable for the native producers (T-5016).

On smoke-cpp run 2026-11-14-0005 one low-confidence build-output heuristic gap made the only build unit
BLOCKED_BY_COMPILE, so clangd, the Clang AST and IR producers and SVF had nothing to index.
"""
from __future__ import annotations

from appsec_review.jobs.job_cpp_compiled_analysis.job import _USABLE_BUILD_STATUSES, _terminal_gap

GAP = {"reason": "build-output-heuristic: build/CMakeFiles/x.dir classified per_file by directory name (low)"}


def _receipt(status: str, entries: int = 3) -> dict:
    return {"terminal_status": status, "gaps": [GAP],
            "build_receipt": {"family": "native", "native_compile_database": {"entry_count": entries}}}


def test_completed_with_gaps_is_usable_when_the_compile_database_has_entries() -> None:
    assert "COMPLETED_WITH_GAPS" in _USABLE_BUILD_STATUSES
    assert _terminal_gap(_receipt("COMPLETED_WITH_GAPS")) is None
    assert _terminal_gap(_receipt("SUCCEEDED")) is None


def test_an_empty_capture_backed_compile_database_is_still_a_gap() -> None:
    assert _terminal_gap(_receipt("COMPLETED_WITH_GAPS", entries=0)) == "capture-backed native compile database is empty"


def test_a_failed_build_names_its_first_gap() -> None:
    gap = _terminal_gap(_receipt("FAILED"))
    assert gap and "build-output-heuristic" in gap
    assert _terminal_gap({"terminal_status": "FAILED", "gaps": []}) == "upstream C++ case action did not succeed"
