from __future__ import annotations

from datetime import datetime, timezone
from fractions import Fraction

import pytest

from appsec_review.jobs.job_source_history_analysis import filters, hotspots, lines, signals, symbols, window
from appsec_review.jobs.job_source_history_analysis.settings import FilterRules
from .support import HEAD, PARENT, SOURCE, STAMP, change, node, nodes


RULES = FilterRules(("*.generated.*",), ("*.lock",), ("fixtures/**",), ("docs/**",), ("vendor/**",),
                   ("tests/**",), 0.1)


@pytest.mark.parametrize("anchor,months,expected", [
    ("2024-08-31", 6, "2024-02-29"), ("2023-08-31", 6, "2023-02-28"),
    ("2024-02-29", 12, "2023-02-28"), ("2024-01-15", 6, "2023-07-15"),
])
def test_calendar_window(anchor, months, expected):
    stamp = lambda text: int(datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp())
    assert window.window_start(stamp(anchor), months) == stamp(expected)
    with pytest.raises(ValueError, match="at least one month"):
        window.window_start(stamp(anchor), 0)


def test_normalization_renames_pseudonyms_anomalies_windows_and_bounds():
    def commit(identity, when, path, old=None):
        return {"commit": identity, "parents": [], "author_time": when, "commit_time": when,
                "author_key": "private@" + identity,
                "files": [{"path": path, "renamed_from": old, "added": 1, "deleted": 0, "binary": False}]}
    commits = [commit(HEAD, STAMP, "new", "old"), commit(PARENT, STAMP + 1, "old"),
               commit("c" * 40, STAMP - 400 * signals.DAY, "old")]
    result = signals.normalize(commits, current_paths=["new"], shallow=[PARENT], window_months=6,
                               max_changes=3, bulk_threshold=0)
    assert [item["change_id"] for item in result["changes"]] == [HEAD, PARENT]
    assert result["changes"][1]["files"][0]["current_path"] == "new"
    assert result["changes"][1]["effective_time"] == STAMP
    assert result["changes"][1]["author"] == "author-0002"
    assert result["changes"][0]["bulk"] is True
    assert result["gaps"] == ["shallow_history"] and result["observations"] == ["timestamp_anomaly:1"]
    assert result["walked_change_count"] == 3 and result["author_count"] == 3
    assert signals.normalize(commits, current_paths=[], shallow=[], window_months=None,
                             max_changes=1, bulk_threshold=5)["gaps"] == ["history_window_truncated"]
    assert signals.normalize([], current_paths=[], shallow=[], window_months=6,
                             max_changes=1, bulk_threshold=5) == {
        "changes": [], "anchor_time": None, "window_start": None, "gaps": [], "observations": [],
        "author_count": 0, "walked_change_count": 0}


def test_classification_bases_exact_reverts_and_incomplete_messages():
    changes = [change(), change(PARENT), change("c" * 40), change("d" * 40)]
    labels = signals.classify(changes, {
        HEAD: b'Revert "fix"\nThis reverts commit ' + PARENT.encode(),
        PARENT: b"neutral", "c" * 40: b'Revert "unknown"\nfix: security CVE-2024-12345'},
        {PARENT: {"labels": ["security", "bug"]}}, known_commits=[HEAD, PARENT],
        fix_labels=["BUG"], security_labels=["SECURITY"], formatting_tolerance=0.1,
        incomplete_messages=["c" * 40])
    assert labels[HEAD]["reverts"] == PARENT and labels[HEAD]["revert"] == "exact"
    assert labels[PARENT]["reverted_by"] == HEAD
    assert labels[PARENT]["fix"] == labels[PARENT]["security_fix"] == "github_label"
    assert labels["c" * 40]["revert"] == "heuristic" and labels["c" * 40]["message_complete"] is False
    assert labels["c" * 40]["security_references"] == ["CVE-2024-12345"]
    assert labels["d" * 40]["fix"] is None and labels["d" * 40]["message_complete"] is False
    assert signals.classify_text("neutral", "security CWE-79") == {
        "fix": "heuristic", "security_fix": "heuristic", "security_references": ["CWE-79"]}


@pytest.mark.parametrize("path,pattern,expected", [
    ("a/b/x.py", "*.py", True), ("a/x.py", "a/?.py", True), ("a/b/x.py", "a/*.py", False),
    ("a/b/x.py", "a/**", True), ("x.py", "**/x.py", True), ("a/b/x.py", "a/**/x.py", True),
])
def test_glob_segments(path, pattern, expected):
    assert filters.matches(path, pattern) is expected


def test_exclusions_and_formatting_preserve_precedence_and_zero_churn():
    assert filters.path_exclusion("a.generated.lock", RULES) == {
        "category": "generated", "pattern": "*.generated.*", "rules": filters.FILTER_IDENTITY}
    assert filters.path_exclusion("src/a.py", RULES) is None
    assert filters.is_test_path("tests/a.py", RULES) and not filters.is_test_path("src/a.py", RULES)
    assert filters.formatting_change("style: format", [{"added": 10, "deleted": 9}], 0.1)
    assert not filters.formatting_change("style: format", [{"added": 10, "deleted": 8}], 0.1)
    assert not filters.formatting_change("style: format", [], 0.1)
    assert not filters.formatting_change("feature", [{"added": 10, "deleted": 10}], 0.1)


def test_file_component_metrics_exclusions_and_entropy():
    changes = [change(), change(PARENT, STAMP - signals.DAY, added=3, deleted=0, author="author-0002"),
               change("c" * 40, bulk=True), change("d" * 40)]
    changes[0]["files"] += [
        {"path": path, "current_path": path, "added": 2, "deleted": 0}
        for path in ("tests/a.py", "a.lock", "empty", "orphan")]
    changes[0]["files"].append({"path": "gone", "current_path": None, "added": 100, "deleted": 0})
    eligible = {path: {"line_count": 0 if path == "empty" else 2}
                for path in ("a.py", "tests/a.py", "a.lock", "empty", "orphan")}
    classes = {HEAD: {"fix": True, "security_fix": True, "revert": True},
               PARENT: {"fix": True}, "d" * 40: {"formatting": True}}
    result = signals.compute_signals(changes, classes, {HEAD: {"review_bypass": True}}, eligible=eligible,
                                     roots=[(".", "c")], anchor_time=STAMP, window_months=6, half_life_days=1,
                                     minor_author_share=0.6, fix_interval_days=30, filters=RULES)
    file = result["files"]["a.py"]
    assert (file["churn_lines"], file["change_count"], file["relative_churn"]) == (5, 2, 2.5)
    assert file["recency_weighted_churn"] == 3.5 and file["author_entropy"] == 1
    assert file["minor_author_count"] == 2 and file["top_author_share"] == 0.5
    assert file["repeat_fix_count"] == 1 and file["retouch_interval_median_days"] == 1
    assert file["review_bypass_count"] == file["review_bypass_unresolved_count"] == 1
    assert file["bulk_change_count"] == file["formatting_change_count"] == 1
    assert file["test_touch_share"] == 0.5 and result["files"]["tests/a.py"]["test_touch_share"] is None
    assert result["files"]["empty"]["rank_eligibility"] == "zero_size"
    assert result["files"]["a.lock"]["rank_eligibility"] == "excluded:lockfile"
    assert result["components"]["c"]["change_count"] == 2
    assert result["components"]["c"]["production_to_test_churn_ratio"] == 4.5
    assert signals.entropy([]) == 0 and signals.entropy([1, 1, 2]) == 1.5
    assert signals.component_roots([{"component_id": "root"}, {"root": "a/b", "component_id": "deep"}]) == [
        ("a/b", "deep"), (".", "root")]


def test_co_change_support_tie_breaks_exclusions_and_unknown_ownership():
    pair = change()
    pair["files"] += [{"current_path": "b.py"}, {"current_path": "c.py"}, {"current_path": None}]
    changes = [pair, {**pair, "change_id": PARENT}, {**pair, "bulk": True},
               {**pair, "change_id": "format"}]
    result = signals.co_change(changes, {"format": {"formatting": True}}, eligible=["a.py", "b.py", "c.py"],
                                roots=[("a.py", "a"), ("b.py", "b")], top_k=1, min_support=2)
    assert result["a.py"] == [{"path": "b.py", "support": 2, "confidence": 1.0, "cross_component": True}]
    assert result["c.py"][0]["cross_component"] is None
    assert signals.co_change([pair], {}, eligible=["a.py", "b.py"], roots=[], top_k=2, min_support=2) == {}


def test_hunks_mapping_chains_attribution_and_binary_gaps():
    raw = f"\x01{HEAD}\n@@ -3 +3,0 @@\nBinary files a and b differ\n\x01{PARENT}\n@@ -0,0 +1,2 @@\n".encode()
    parsed = lines.parse_file_history(raw)
    assert parsed == [{"commit": HEAD, "hunks": [[3, 1, 3, 0]], "binary": True},
                      {"commit": PARENT, "hunks": [[0, 0, 1, 2]], "binary": False}]
    for data, message in [(b"orphan", "does not begin"), (f"\x01{HEAD}\n@@ -oops".encode(), "malformed")]:
        with pytest.raises(ValueError, match=message):
            lines.parse_file_history(data)
    assert lines.old_regions([[0, 0, 1, 2]]) == [(1, 1)]
    assert lines.map_span((3, 5), [[2, 2, 2, 1]]) == (2, 4)
    assert lines.map_forward((5, 5), [[[2, 0, 3, 2]], [[1, 1, 1, 0]]]) == (6, 6)
    history = lines.FileLines(parsed, 10)
    assert history.hunks("missing") is None and history.hunks(HEAD) is None
    assert history.chain(PARENT) is None and history.chain(HEAD, PARENT) is None
    assert history.chain("missing") is None
    parsed[0]["binary"] = False
    attributed, gaps = lines.attribute([{"change_id": HEAD}, {"change_id": "missing"}], history,
                                      [{"symbol_id": "f", "own_lines": [[1, 5]]}])
    assert attributed == {"f": [{"change_id": HEAD, "added": 0, "deleted": 1}]} and gaps == ["missing"]
    assert lines.FileLines(parsed, 0).snapshot_regions(HEAD)[0][0] == (1, 1)


@pytest.mark.parametrize("kind", ["overlap", "same-symbol", "distinct", "no-lines", "no-symbols", "incomplete", "late"])
def test_fix_on_fix_distinguishes_proof_absence_and_unavailable(kind):
    later_line = 3 if kind == "overlap" else 8
    history = lines.FileLines([
        {"commit": HEAD, "hunks": [[later_line, 1, later_line, 1]], "binary": False},
        {"commit": PARENT, "hunks": [[3, 1, 3, 1]], "binary": kind == "incomplete"}], 20)
    changes = [{"change_id": HEAD, "effective_time": (31 if kind == "late" else 2) * signals.DAY, "fix": True},
               {"change_id": PARENT, "effective_time": 0, "fix": True}]
    result = lines.fix_on_fix(
        changes, lines=None if kind == "no-lines" else history, lines_reason="line_history_bound_reached",
        symbols=None if kind == "no-symbols" else [{"symbol_id": "f", "own_lines": [[1, 5 if kind == "distinct" else 10]]}],
        symbols_reason="symbol_language_unsupported", interval_days=30)
    if kind in {"overlap", "same-symbol"}:
        assert result["count"] == 1 and result["status"] == "complete"
        assert result["events"][0]["basis"] == ("line_overlap" if kind == "overlap" else "same_function")
        assert result["events"][0]["earlier_change"] == PARENT and result["events"][0]["later_change"] == HEAD
    elif kind in {"distinct", "late"}:
        assert result["count"] == 0 and result["status"] == "complete"
        assert result["candidate_pair_count"] == (0 if kind == "late" else 1)
    else:
        assert result["count"] is None and result["status"] == "unavailable"
        assert result["undetermined"] == [{
            "earlier_change": PARENT, "later_change": HEAD, "interval_days": 2.0,
            "reason": {"no-lines": "line_history_bound_reached", "no-symbols": "symbol_language_unsupported",
                       "incomplete": "line_history_incomplete"}[kind]}]


def test_sii_normalization_missing_metrics_ties_and_tiers():
    weights = dict.fromkeys(("relative_churn", "revision_frequency", "author_entropy", "complexity"), 1)
    population = {f"x{i:02}": {"relative_churn": i, "revision_frequency": i, "author_entropy": 1,
                              "complexity": i, "churn_lines": i, "change_count": i} for i in range(20)}
    population["missing"] = dict.fromkeys(weights)
    score = lambda values: hotspots.score(values, weights=weights, tier_1_share=Fraction(1, 20),
                                           tier_2_share=Fraction(3, 20))
    result = score(population)
    assert result == score(dict(reversed(list(population.items()))))
    assert result["ranked"][0]["key"] == "x19" and result["ranked"][0]["score"] == 75
    assert result["constant_metrics"] == ["author_entropy"]
    assert result["ranked"][-1]["key"] == "x00"
    missing = next(item for item in result["ranked"] if item["key"] == "missing")
    assert missing["weight_coverage"] == 0 and missing["missing_inputs"] == list(weights)
    assert result["tiers"]["tier_1_last_rank"] == 2 and result["tiers"]["tier_2_last_rank"] == 5
    assert score({})["ranked"] == [] and hotspots.tier_bounds(0, Fraction(1, 20), Fraction(3, 20)) == (0, 0)


def test_symbol_extraction_exact_spans_complexity_and_named_gaps():
    record = {"nodes": [*nodes(), node((0, 1), "if_statement", row=1),
                         node((0, 1, 0), "and", named=False, row=1)]}
    result = symbols.extract(record, SOURCE, "Python", "a.py")
    symbol = result["symbols"][0]
    assert symbol["symbol_id"] == "a.py::f" and symbol["own_lines"] == [(1, 2)]
    assert (symbol["cyclomatic_complexity"], symbol["cognitive_complexity"]) == (3, 2)
    assert result["file_complexity"] == {"cyclomatic": 3, "cognitive": 2, "function_count": 1, "gaps": []}
    record.update({"truncated": True, "root_has_error": True})
    record["nodes"].append(node((0, 2), "ERROR", error=True))
    result = symbols.extract(record, SOURCE, "Python", "a.py")
    assert result["status"] == "partial"
    assert result["gaps"] == ["node_limit_reached", "parse_errors_in_span", "parse_errors_present"]
    assert symbols.extract({"nodes": []}, b"", "C", "a.c") == {
        "status": "unavailable", "language": "C", "symbols": [], "gaps": ["no_syntax_tree"], "file_complexity": None}
    assert symbols.tree_sitter_language(None, "a.tsx") is None
    assert symbols.tree_sitter_language("TypeScript", "a.tsx") == "TSX"
    assert symbols.tree_sitter_language("Swift", "a.swift") is None
    assert symbols.tree_sitter_language("Python", "a.py") == "Python"


def test_nested_anonymous_duplicate_symbols_and_preprocessor_complexity():
    record = {"nodes": [node((), "translation_unit"), node((0,), "function_definition"),
                        node((0, 0), "identifier", 4, 5, field="name", end_row=0),
                        node((0, 1), "preproc_if"), node((0, 2), "compound_statement"),
                        node((0, 2, 0), "lambda_expression", row=1),
                        node((0, 2, 0, 0), "if_statement", row=1), node((1,), "function_definition"),
                        node((1, 0), "identifier", 4, 5, field="name", end_row=0),
                        node((1, 1), "case_statement"), node((1, 1, 0), "default", named=False),
                        node((1, 2), "goto_statement")]}
    result = symbols.extract(record, SOURCE, "C", "a.c")
    by_id = {item["symbol_id"]: item for item in result["symbols"]}
    assert set(by_id) == {"a.c::f", "a.c::f.<anonymous:2>", "a.c::f#2"}
    assert by_id["a.c::f"]["own_lines"] == [(1, 1)]
    assert by_id["a.c::f#2"]["cyclomatic_complexity"] == 1
    assert by_id["a.c::f#2"]["cognitive_complexity"] == 1
    assert result["gaps"] == ["preprocessor_branches_not_counted"]
