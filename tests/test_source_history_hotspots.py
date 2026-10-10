from __future__ import annotations

from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.jobs.job_source_history_analysis import load_accepted_history, load_accepted_hotspots
from appsec_review.jobs.job_source_history_analysis.filters import formatting_change, path_exclusion
from appsec_review.jobs.job_source_history_analysis.hotspots import score, tier_bounds
from appsec_review.jobs.job_source_history_analysis.lines import (
    FileLines, attribute, fix_on_fix, map_span, parse_file_history,
)
from appsec_review.jobs.job_source_history_analysis.settings import parse_settings
from appsec_review.jobs.job_source_history_analysis.signals import compute_signals, entropy, normalize
from appsec_review.jobs.job_source_history_analysis.symbols import extract, tree_sitter_language
from appsec_review.jobs.job_source_history_analysis.window import window_start
from appsec_review.retrieval import RetrievalCore

from tests.test_source_history_analysis import (
    DAY, GIT, T0, LocalDocker, build_repository, commit, configured, outputs, run_graph, tree_sitter_nodes, write,
)


ROOT = Path(__file__).parents[1]
pytestmark = pytest.mark.skipif(GIT is None, reason="host git is required to emulate the tool-git image")


def default_settings() -> dict:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return json.loads(json.dumps(document["jobs"]["job_source_history_analysis"]["settings"]))


def conforms(value, schema: dict, root: dict, where: str = "$") -> None:
    """Check the JSON-schema subset the hotspot schema uses: refs, types, consts, enums, and keys."""
    if "$ref" in schema:
        schema = root["$defs"][schema["$ref"].rsplit("/", 1)[1]]
    if "const" in schema:
        assert value == schema["const"], where
    if "enum" in schema:
        assert value in schema["enum"], where
    kinds = schema.get("type")
    if kinds is not None:
        names = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float),
                 "boolean": bool, "null": type(None)}
        assert any(isinstance(value, names[kind]) for kind in ([kinds] if isinstance(kinds, str) else kinds)), where
    if isinstance(value, dict):
        assert set(schema.get("required", ())) <= set(value), (where, set(schema.get("required", ())) - set(value))
        if schema.get("additionalProperties") is False:
            assert set(value) <= set(schema.get("properties", {})), (where, set(value) - set(schema["properties"]))
        for key, child in value.items():
            if key in schema.get("properties", {}):
                conforms(child, schema["properties"][key], root, f"{where}.{key}")
    if isinstance(value, list):
        assert len(value) <= schema.get("maxItems", len(value)), where
        if "items" in schema:
            for index, child in enumerate(value):
                conforms(child, schema["items"], root, f"{where}[{index}]")


def utc(text: str) -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp())


@pytest.mark.parametrize(("anchor", "months", "expected"), [
    ("2024-08-31T12:00:00", 6, "2024-02-29T12:00:00"),
    ("2023-08-31T12:00:00", 6, "2023-02-28T12:00:00"),
    ("2024-02-29T00:00:01", 12, "2023-02-28T00:00:01"),
    ("2024-03-31T23:59:59", 1, "2024-02-29T23:59:59"),
    ("2024-01-15T08:30:00", 6, "2023-07-15T08:30:00"),
    ("2025-05-31T00:00:00", 3, "2025-02-28T00:00:00"),
])
def test_calendar_month_window_clamps_month_ends_and_leap_years(anchor: str, months: int, expected: str) -> None:
    assert window_start(utc(anchor), months) == utc(expected)


def test_window_membership_is_inclusive_at_the_start_and_anchored_to_the_snapshot_commit() -> None:
    anchor = utc("2024-08-31T12:00:00")
    start = utc("2024-02-29T12:00:00")

    def commit_at(name: str, when: int) -> dict:
        return {"commit": name * 40, "parents": [], "author_time": when, "commit_time": when, "author_key": "a",
                "files": [{"path": "a.py", "renamed_from": None, "added": 1, "deleted": 0, "binary": False}]}

    normalized = normalize([commit_at("c", anchor), commit_at("b", start), commit_at("a", start - 1)],
                           current_paths={"a.py": {}}, shallow=(), window_months=6, max_changes=10, bulk_threshold=50)
    assert normalized["window_start"] == start
    assert [item["change_id"][0] for item in normalized["changes"]] == ["c", "b"]


def test_settings_defaults_overrides_and_rejections() -> None:
    settings = default_settings()
    parsed = parse_settings(settings)
    assert (parsed.hotspot_count, parsed.history_window_months, parsed.fix_on_fix_interval_days) == (10, 6, 30)
    assert parsed.sii.tier_1_share == Fraction(1, 20) and parsed.sii.tier_2_share == Fraction(3, 20)
    assert sum(parsed.sii.weights.values()) == pytest.approx(1.0)
    override = parse_settings({**settings, "hotspot_count": 25, "history_window_months": 12,
                               "fix_on_fix": {"interval_days": 14}})
    assert (override.hotspot_count, override.history_window_months, override.fix_on_fix_interval_days) == (25, 12, 14)
    invalid = [
        {"hotspot_count": 0}, {"hotspot_count": 101}, {"hotspot_count": True}, {"history_window_months": 0},
        {"window_days": 365}, {"fix_on_fix": {"interval_days": 13}}, {"fix_on_fix": {"interval_days": 31}},
        {"sii": {**settings["sii"], "weights": {**settings["sii"]["weights"], "churn_lines": 1}}},
        {"sii": {**settings["sii"], "weights": {key: 0 for key in settings["sii"]["weights"]}}},
        {"sii": {**settings["sii"], "tier_2_share": 0.95}}, {"sii": {**settings["sii"], "complexity_metric": "halstead"}},
        {"filters": {**settings["filters"], "generated": ["../escape"]}},
    ]
    for change in invalid:
        with pytest.raises(ValueError):
            parse_settings({**settings, **change})


def test_path_filters_and_formatting_rules_are_explicit() -> None:
    filters = parse_settings(default_settings()).filters
    assert path_exclusion("web/package-lock.json", filters)["category"] == "lockfile"
    assert path_exclusion("api/v1/service_pb2.py", filters)["category"] == "generated"
    assert path_exclusion("tests/fixtures/payload.py", filters)["category"] == "fixture"
    assert path_exclusion("docs/guide.py", filters)["category"] == "documentation"
    assert path_exclusion("src/vendor/lib.c", filters)["category"] == "vendored"
    assert path_exclusion("src/app/auth.py", filters) is None
    balanced = [{"added": 40, "deleted": 41}]
    assert formatting_change("style: apply black", balanced, 0.1)
    assert formatting_change("Reformat sources", balanced, 0.1)
    assert not formatting_change("style: apply black", [{"added": 40, "deleted": 2}], 0.1)
    assert not formatting_change("add login throttling", balanced, 0.1)


def test_file_metrics_separate_churn_ownership_entropy_and_exclusions() -> None:
    filters = parse_settings(default_settings()).filters
    eligible = {"src/a.py": {"line_count": 10}, "tests/test_a.py": {"line_count": 5},
                "package-lock.json": {"line_count": 100}, "src/empty.py": {"line_count": 0}}

    def change(name: str, days: int, author: str, files: dict, *, bulk: bool = False) -> dict:
        return {"change_id": name * 40, "effective_time": T0 + days * DAY, "author": author, "bulk": bulk,
                "files": [{"path": path, "current_path": path, "added": added, "deleted": deleted}
                          for path, (added, deleted) in files.items()]}

    changes = [
        change("d", 30, "author-0001", {"src/a.py": (100, 100)}, bulk=True),
        change("c", 20, "author-0002", {"src/a.py": (5, 5)}),
        change("b", 10, "author-0002", {"src/a.py": (3, 1), "tests/test_a.py": (2, 0),
                                         "package-lock.json": (50, 50), "src/empty.py": (0, 1)}),
        change("a", 0, "author-0001", {"src/a.py": (10, 0)}),
    ]
    classes = {"c" * 40: {"formatting": "heuristic"}, "b" * 40: {"fix": "heuristic"}, "a" * 40: {"fix": "heuristic"}}
    values = compute_signals(changes, classes, {}, eligible=eligible, roots=[(".", "component:0001")],
                             anchor_time=T0 + 30 * DAY, window_months=6, half_life_days=90, minor_author_share=0.05,
                             fix_interval_days=30, filters=filters)
    item = values["files"]["src/a.py"]
    assert (item["lines_added"], item["lines_deleted"], item["churn_lines"]) == (13, 1, 14)
    assert item["relative_churn"] == 1.4 and item["change_count"] == 2 and item["revision_frequency"] == 0.333333
    assert item["author_commit_shares"] == {"author-0001": 0.5, "author-0002": 0.5} and item["author_entropy"] == 1.0
    assert (item["bulk_change_count"], item["formatting_change_count"], item["excluded_churn_lines"]) == (1, 1, 210)
    assert item["repeat_fix_count"] == 1 and item["test_touch_share"] == 0.5
    assert [entry["excluded"] for entry in item["changes"]] == ["bulk", "formatting", None, None]
    assert [(entry["added"], entry["deleted"]) for entry in item["changes"]] == [(100, 100), (5, 5), (3, 1), (10, 0)]
    assert values["files"]["package-lock.json"]["rank_eligibility"] == "excluded:lockfile"
    assert values["files"]["package-lock.json"]["churn_lines"] == 100, "excluded files keep their metrics"
    assert values["files"]["src/empty.py"]["rank_eligibility"] == "zero_size"
    assert values["files"]["tests/test_a.py"]["is_test"] and values["files"]["tests/test_a.py"]["test_touch_share"] is None
    component = values["components"]["component:0001"]
    assert (component["production_churn_lines"], component["test_churn_lines"]) == (15, 2)
    assert component["production_to_test_churn_ratio"] == 7.5
    assert entropy([1, 1, 2]) == 1.5 and entropy([4]) == 0.0


def test_zero_context_hunks_map_regions_through_later_commits() -> None:
    commit_a, commit_b = "a" * 40, "b" * 40
    parsed = parse_file_history(b"\x01" + commit_b.encode() + b"\n\ndiff --git a/x b/x\n@@ -4 +3,0 @@ ctx\n-d\n"
                                b"+@@ -9 +9 @@ looks like a header\n\x01" + commit_a.encode() +
                                b"\n@@ -0,0 +1,3 @@\n+a\n+b\n+c\n")
    assert parsed == [{"commit": commit_b, "hunks": [[4, 1, 3, 0]], "binary": False},
                      {"commit": commit_a, "hunks": [[0, 0, 1, 3]], "binary": False}]
    hunks = [[2, 2, 2, 1], [10, 0, 9, 3]]
    assert map_span((1, 1), hunks) == (1, 1)
    assert map_span((3, 3), hunks) == (2, 2), "a rewritten line maps to its replacement region"
    assert map_span((5, 5), hunks) == (4, 4)
    assert map_span((11, 11), hunks) == (13, 13)
    assert map_span((1, 5), hunks) == (1, 4)
    with pytest.raises(ValueError):
        parse_file_history(b"@@ -1 +1 @@\n")


def _fix_history(later_hunks: list[list[int]]) -> FileLines:
    return FileLines([{"commit": "c" * 40, "hunks": later_hunks, "binary": False},
                      {"commit": "b" * 40, "hunks": [[0, 0, 1, 2]], "binary": False},
                      {"commit": "a" * 40, "hunks": [[3, 1, 3, 1]], "binary": False}], line_total=40)


def _fix_changes(later_days: int = 2) -> list[dict]:
    return [{"change_id": "c" * 40, "effective_time": later_days * DAY, "fix": True},
            {"change_id": "b" * 40, "effective_time": DAY, "fix": False},
            {"change_id": "a" * 40, "effective_time": 0, "fix": True}]


def test_fix_on_fix_matches_shifted_lines_same_function_and_reports_gaps() -> None:
    symbols = [{"symbol_id": "m.py::f", "own_lines": [[1, 30]]}, {"symbol_id": "m.py::g", "own_lines": [[31, 40]]}]
    lines = fix_on_fix(_fix_changes(), lines=_fix_history([[5, 1, 5, 1]]), lines_reason=None, symbols=symbols,
                       symbols_reason=None, interval_days=30)
    assert lines["status"] == "complete" and lines["count"] == 1
    event = lines["events"][0]
    assert event["basis"] == "line_overlap" and event["earlier_region_at_later_parent"] == [5, 5]
    assert (event["earlier_change"], event["later_change"], event["interval_days"]) == ("a" * 40, "c" * 40, 2.0)
    assert event["symbols"] == ["m.py::f"] and event["snapshot_location"] == {"start_line": 5, "end_line": 5}
    function = fix_on_fix(_fix_changes(), lines=_fix_history([[20, 1, 20, 1]]), lines_reason=None, symbols=symbols,
                          symbols_reason=None, interval_days=30)
    assert [item["basis"] for item in function["events"]] == ["same_function"]
    unrelated = fix_on_fix(_fix_changes(), lines=_fix_history([[35, 1, 35, 1]]), lines_reason=None, symbols=symbols,
                           symbols_reason=None, interval_days=30)
    assert unrelated["count"] == 0 and unrelated["status"] == "complete"
    no_symbols = fix_on_fix(_fix_changes(), lines=_fix_history([[20, 1, 20, 1]]), lines_reason=None, symbols=None,
                            symbols_reason="symbol_language_unsupported", interval_days=30)
    assert no_symbols["count"] is None, "an undetermined pair is a gap, never a zero"
    assert no_symbols["undetermined"][0]["reason"] == "symbol_language_unsupported"
    no_lines = fix_on_fix(_fix_changes(), lines=None, lines_reason="line_history_bound_reached", symbols=symbols,
                          symbols_reason=None, interval_days=30)
    assert (no_lines["status"], no_lines["count"]) == ("unavailable", None)
    late = fix_on_fix(_fix_changes(later_days=31), lines=None, lines_reason="x", symbols=None, symbols_reason="y",
                      interval_days=30)
    assert (late["status"], late["count"], late["candidate_pair_count"]) == ("complete", 0, 0)
    incomplete = FileLines([{"commit": "c" * 40, "hunks": [[5, 1, 5, 1]], "binary": False},
                            {"commit": "a" * 40, "hunks": [[3, 1, 3, 1]], "binary": True}], line_total=40)
    assert fix_on_fix(_fix_changes(), lines=incomplete, lines_reason=None, symbols=symbols, symbols_reason=None,
                      interval_days=30)["undetermined"][0]["reason"] == "line_history_incomplete"


SOURCE = b"""def outer(a, b):
    if a and b or a:
        return 1
    elif b:
        for x in a:
            while x:
                pass
    else:
        y = (lambda z: z if z else 0)
    return 2


class Box:
    def size(self):
        return 0
"""


def _record(source: bytes) -> dict:
    nodes = tree_sitter_nodes(source)
    return {"path": "m.py", "status": "SUCCEEDED", "nodes": nodes, "truncated": False, "root_has_error": False}


def test_tree_sitter_symbols_carry_spans_and_distinct_complexities() -> None:
    extracted = extract(_record(SOURCE), SOURCE, "Python", "m.py")
    assert extracted["status"] == "complete"
    symbols = {item["symbol_id"]: item for item in extracted["symbols"]}
    assert set(symbols) == {"m.py::outer", "m.py::outer.<anonymous:9>", "m.py::Box.size"}
    outer = symbols["m.py::outer"]
    assert (outer["start_line"], outer["end_line"], outer["own_lines"]) == (1, 10, [(1, 8), (10, 10)])
    assert (outer["cyclomatic_complexity"], outer["cognitive_complexity"]) == (7, 10)
    lam = symbols["m.py::outer.<anonymous:9>"]
    assert (lam["cyclomatic_complexity"], lam["cognitive_complexity"]) == (2, 1)
    assert (symbols["m.py::Box.size"]["cyclomatic_complexity"], symbols["m.py::Box.size"]["cognitive_complexity"]) == (1, 0)
    assert extracted["file_complexity"] == {"cyclomatic": 10, "cognitive": 11, "function_count": 3, "gaps": []}
    assert SOURCE[outer["start_byte"]:outer["end_byte"]].startswith(b"def outer")
    truncated = extract({**_record(SOURCE), "truncated": True}, SOURCE, "Python", "m.py")
    assert truncated["status"] == "partial" and "node_limit_reached" in truncated["gaps"]
    assert tree_sitter_language("Ruby", "app.rb") is None and tree_sitter_language("TypeScript", "ui/App.tsx") == "TSX"


def test_symbol_attribution_follows_regions_to_innermost_functions() -> None:
    extracted = extract(_record(SOURCE), SOURCE, "Python", "m.py")
    lines = FileLines([{"commit": "b" * 40, "hunks": [[9, 1, 9, 1]], "binary": False},
                       {"commit": "a" * 40, "hunks": [[0, 0, 1, 2], [3, 1, 5, 1]], "binary": False}],
                      line_total=SOURCE.count(b"\n"))
    changes = [{"change_id": "b" * 40}, {"change_id": "a" * 40}, {"change_id": "d" * 40}]
    attributed, unmapped = attribute(changes, lines, extracted["symbols"])
    assert unmapped == ["d" * 40]
    assert attributed["m.py::outer.<anonymous:9>"] == [{"change_id": "b" * 40, "added": 1, "deleted": 1}]
    assert attributed["m.py::outer"] == [{"change_id": "a" * 40, "added": 3, "deleted": 1}]


@pytest.mark.parametrize(("population", "bounds"), [
    (0, (0, 0)), (1, (1, 1)), (3, (1, 1)), (10, (1, 2)), (20, (1, 4)), (21, (2, 5)), (100, (5, 20)), (101, (6, 21)),
])
def test_tier_boundaries_round_up(population: int, bounds: tuple[int, int]) -> None:
    assert tier_bounds(population, Fraction(1, 20), Fraction(3, 20)) == bounds


def test_sii_is_deterministic_bounded_and_explains_missing_and_constant_inputs() -> None:
    weights = parse_settings(default_settings()).sii.weights
    units = {f"f{index:02d}.py": {"relative_churn": index / 10, "revision_frequency": index / 6, "author_entropy": 1.0,
                                  "complexity": index, "churn_lines": index, "change_count": index}
             for index in range(1, 21)}
    units["tie-b.py"] = units["tie-a.py"] = {"relative_churn": 0.0, "revision_frequency": 0.0, "author_entropy": 1.0,
                                             "complexity": None, "churn_lines": 0, "change_count": 0}
    first = score(units, weights=weights, tier_1_share=Fraction(1, 20), tier_2_share=Fraction(3, 20))
    again = score(dict(sorted(units.items(), reverse=True)), weights=weights, tier_1_share=Fraction(1, 20),
                  tier_2_share=Fraction(3, 20))
    assert first == again
    ranked = first["ranked"]
    assert ranked[0]["key"] == "f20.py" and ranked[0]["score"] == 85.0, "constant entropy scores 0 of its weight"
    assert all(0 <= item["score"] <= 100 for item in ranked)
    assert first["constant_metrics"] == ["author_entropy"]
    assert [item["key"] for item in ranked[-2:]] == ["tie-a.py", "tie-b.py"]
    assert ranked[-1]["missing_inputs"] == ["complexity"] and ranked[-1]["weight_coverage"] == 0.75
    assert [item["tier"] for item in ranked].count(1) == 2 and [item["tier"] for item in ranked].count(2) == 3
    single = score({"only.py": units["f01.py"]}, weights=weights, tier_1_share=Fraction(1, 20),
                   tier_2_share=Fraction(3, 20))
    assert single["ranked"][0] | {"inputs": None} == {"key": "only.py", "score": 0.0, "inputs": None,
                                                     "missing_inputs": [], "weight_coverage": 1.0, "rank": 1, "tier": 1}


def test_hotspot_index_is_bounded_queryable_and_excludes_non_code(tmp_path: Path) -> None:
    config = configured(tmp_path, replacements=(("hotspot_count = 10", "hotspot_count = 1"),))
    target = tmp_path / "target"
    build_repository(target)
    write(target, "package-lock.json", '{"lockfileVersion": 3, "packages": {"a": 1, "b": 2}}\n' * 40)
    write(target, "README.md", "# Fixture\n" * 30)
    commit(target, "bump dependencies and docs", T0 + 7 * DAY)
    outcome = run_graph(config, target, LocalDocker())
    run_root = config.runtime.runs_dir / outcome["run_id"]
    history = load_accepted_history(run_root)
    signals = json.loads((run_root / history["ranking"]["signals"]["path"]).read_text(encoding="utf-8"))
    assert signals["files"]["package-lock.json"]["rank_eligibility"] == "excluded:lockfile"
    assert signals["files"]["README.md"]["rank_eligibility"] == "excluded:documentation"
    assert {item["path"] for item in history["ranking"]["files"]}.isdisjoint({"package-lock.json", "README.md"})
    assert history["window"]["months"] == 6 and "first-parent" in history["window"]["revision_semantics"]
    hotspots = load_accepted_hotspots(run_root)
    assert [(item["scope"], item["rank"]) for item in hotspots["entries"]] == [("file", 1), ("symbol", 1)]
    schema = json.loads((ROOT / "docs" / "schemas" / "history-hotspots.schema.json").read_text(encoding="utf-8"))
    conforms({key: value for key, value in hotspots.items() if key != "handoff_sha256"}, schema, schema)
    file_entry, symbol_entry = hotspots["entries"]
    assert file_entry["identity"]["path"] == "app/auth.py" and file_entry["tier"] == 1
    assert symbol_entry["identity"]["symbol_id"] == "app/auth.py::check"
    for entry in hotspots["entries"]:
        assert entry["snapshot"]["target_snapshot"] == history["target_snapshot"]
        assert entry["snapshot"]["snapshot_commit"] == history["sources"]["git"]["snapshot_commit"]
        assert len(entry["source"]["sha256"]) == 64 and len(entry["source"]["blob_id"]) == 40
        assert {"relative_churn", "revision_frequency", "author_entropy", "complexity"} == set(entry["inputs"]["values"])
        assert entry["metrics"]["lines_added"] + entry["metrics"]["lines_deleted"] == entry["metrics"]["churn_lines"]
        assert "signal_unavailable:pull_request_timing:pr_timing_not_acquired" in entry["coverage_gaps"]
        assert "never vulnerability evidence" in entry["authority"]
    assert symbol_entry["location"]["start_line"] == 1 and symbol_entry["metrics"]["cyclomatic_complexity"] == 3
    assert file_entry["metrics"]["fix_on_fix_count"] >= 1
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    found = core.find(kind="hotspot", indexes=("history",))
    assert len(found["results"]) == 2
    symbol = core.find(kind="hotspot", path="app/auth.py", name="app/auth.py::check", indexes=("history",))
    assert symbol["results"][0]["payload"]["tier"] == 1
    rows = {row["area"]: row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]}
    assert rows["history-hotspots"]["status"] in {"complete", "partial"}
    assert rows["pull-request-timing"] == {"area": "pull-request-timing", "status": "unavailable",
                                           "gap": "pr_timing_not_acquired"}
    signal = core.find(kind="history_signal", name="app/auth.py::check", indexes=("history",))
    assert signal["results"][0]["payload"]["change_count"] >= 1


def test_missing_symbol_and_line_coverage_is_a_named_gap_not_zero(tmp_path: Path) -> None:
    config = configured(tmp_path, replacements=(
        ("max_files = 50\nmax_file_bytes = 1048576\n\n[jobs.job_source_history_analysis.settings.symbols]",
         "max_files = 0\nmax_file_bytes = 1048576\n\n[jobs.job_source_history_analysis.settings.symbols]"),))
    target = tmp_path / "target"
    build_repository(target)
    outcome = run_graph(config, target, LocalDocker(tree_sitter_fails=True))
    produced = outputs(outcome)
    assert produced["analyze.symbol_spans"]["dispositions"][0]["reason"] == "tree_sitter_execution_failed"
    assert {"tree_sitter_execution_failed", "line_history_bound_reached", "fix_on_fix_undetermined"} <= \
        set(produced["publish.publish_handoff"]["gaps"])
    assert produced["publish.publish_handoff"]["terminal_status"] == "PARTIAL"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    hotspots = load_accepted_hotspots(run_root)
    assert hotspots["entries"] and {item["scope"] for item in hotspots["entries"]} == {"file"}
    auth = next(item for item in hotspots["entries"] if item["identity"]["path"] == "app/auth.py")
    assert auth["metrics"]["fix_on_fix_count"] is None and auth["metrics"]["fix_on_fix_status"] == "unavailable"
    assert auth["metrics"]["cyclomatic_complexity"] is None
    assert auth["inputs"]["missing_inputs"] == ["complexity"] and auth["inputs"]["weight_coverage"] == 0.75
    assert {"complexity_unavailable:tree_sitter_execution_failed", "fix_on_fix_unavailable",
            "line_history_unavailable:line_history_bound_reached"} <= set(auth["coverage_gaps"])
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = {row["area"]: row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]}
    assert rows["symbol-spans"]["status"] == "partial" and rows["fix-on-fix"]["status"] == "partial"
