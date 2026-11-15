"""clangd symbols are admitted first-party first; a vendored exclusion is a count, not a gap (T-5016)."""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from appsec_review.jobs.job_cpp_symbol_index.job import normalize_scope
from appsec_review.retrieval import IndexBuilder
from appsec_review.review.dispositions import SourceDispositions

SYMBOL = ("--- !Symbol\nID:              {id}\nName:            {name}\nScope:           ''\n"
          "Definition:\n  FileURI:         'file:///target/source/{file}'\n  Start:\n"
          "    Line:            0\n    Column:          4\n...\n")


def _run(tmp_path: Path, *, limit: int, dispositions: SourceDispositions | None):
    target = tmp_path / "target"
    (target / "p" / "third_party").mkdir(parents=True)
    (target / "p" / "a.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (target / "p" / "third_party" / "z.c").write_text("int zlib_x() { return 1; }\n", encoding="utf-8")
    entries = {
        "/target/source/a.cpp": {"target_path": "p/a.cpp", "scratch_path": "source/a.cpp",
                                 "sha256": hashlib.sha256((target / "p" / "a.cpp").read_bytes()).hexdigest()},
        "/target/source/third_party/z.c": {"target_path": "p/third_party/z.c", "scratch_path": "source/third_party/z.c",
                                           "sha256": hashlib.sha256((target / "p" / "third_party" / "z.c").read_bytes()).hexdigest()},
    }
    scope = SimpleNamespace(project_id="cpp:p", case_snapshot="d" * 64, accepted_file=entries.get,
                            container_compile_database=lambda: [{"file": path} for path in entries])
    # The vendored symbol comes first in clangd's output; the first-party one must still win the budget.
    text = (SYMBOL.format(id="1111111111111111", name="zlib_x", file="third_party/z.c") +
            SYMBOL.format(id="2222222222222222", name="main", file="a.cpp"))
    run_root = tmp_path / "run"
    (run_root / "raw").mkdir(parents=True)
    (run_root / "raw" / "stdout").write_text(text, encoding="utf-8")
    (run_root / "raw" / "stderr").write_text("[1/2] Processing file /target/source/a.cpp\n"
                                             "[2/2] Processing file /target/source/third_party/z.c\n", encoding="utf-8")
    unit = SimpleNamespace(job=SimpleNamespace(run_root=run_root, target_root=target, source_fingerprint="e" * 64))
    builder = IndexBuilder(run_root / "shard.sqlite", name="analysis", fingerprint="f" * 64,
                           target_snapshot="e" * 64, shard_id="clangd-test")
    counts = normalize_scope(unit, scope, {"timed_out": False, "oom_killed": False, "exit_code": 0,
                                           "stdout_truncated": False, "stdout_path": "raw/stdout",
                                           "stderr_path": "raw/stderr"},
                             {"max_documents_per_scope": 100, "max_symbols_per_scope": limit,
                              "max_relations_per_scope": 100, "locations_per_relation": 1},
                             builder, "clangd-test", dispositions=dispositions)
    return counts, [entity.name for entity in builder.entities]


def test_first_party_symbols_take_the_budget_and_the_vendored_exclusion_is_a_count(tmp_path: Path) -> None:
    counts, names = _run(tmp_path, limit=1, dispositions=SourceDispositions(vendored=("**/third_party/**",)))
    assert names == ["main"] and counts["symbols"] == 1
    assert counts["symbols_by_disposition"] == {"first_party": 1}
    assert counts["excluded_symbols_by_disposition"] == {"vendored": 1}
    assert counts["gaps"] == [] and counts["coverage"] == "complete"


def test_an_excluded_first_party_symbol_is_still_a_gap(tmp_path: Path) -> None:
    counts, names = _run(tmp_path, limit=1, dispositions=None)
    assert len(names) == 1 and counts["excluded_symbols_by_disposition"] == {"first_party": 1}
    assert "clangd symbol limit reached" in counts["gaps"] and counts["coverage"] == "partial"


def test_without_a_limit_every_symbol_is_admitted_with_its_disposition(tmp_path: Path) -> None:
    counts, names = _run(tmp_path, limit=10, dispositions=SourceDispositions(vendored=("**/third_party/**",)))
    assert sorted(names) == ["main", "zlib_x"]
    assert counts["symbols_by_disposition"] == {"first_party": 1, "vendored": 1}
    assert counts["excluded_symbols_by_disposition"] == {} and counts["gaps"] == []
