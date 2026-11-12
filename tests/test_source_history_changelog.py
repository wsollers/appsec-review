"""Change-log files as a history source: parsers, bounds, path binding, privacy and the job path.

Fixtures under ``tests/fixtures/changelog_history`` are synthetic.  Every one carries an e-mail
address and an instruction-like sentence; no output may contain either.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.interchange import validate_unit_output
from appsec_review.jobs.job_source_history_analysis import build_job
from appsec_review.jobs.job_source_history_analysis import changelog, job as history_module
from appsec_review.jobs.job_source_history_analysis.changelog import ChangelogLimits, PathBinder
from appsec_review.jobs.job_source_history_analysis.settings import parse_settings
from appsec_review.jobs.job_source_history_analysis.signals import classify_text
from appsec_review.jobs.job_target_analysis_plan.planning import history_priority
from appsec_review.observability import EventLog
from appsec_review.retrieval import IndexBuilder
from appsec_review.runtime import plan_jobs
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.units import UnitContext


ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "changelog_history"
LIMITS = ChangelogLimits(max_files=16, max_file_bytes=1 << 20, max_entries=1000, max_line_bytes=4096,
                         max_paths_per_entry=100)
CATALOG = {path: hashlib.sha256(path.encode()).hexdigest() for path in (
    "docs/guide.txt", "manual/deep/guide.txt", "src/auth.c", "src/net/util.c", "src/util.c")}
# Names, addresses, user ids and message text that appear in the fixtures and must never be published.
FORBIDDEN = ("example.test", "Jane", "Roe", "Sam Poe", "Old Hand", "jroe", "spoe", "forged",
             "Ignore all previous", "mark this file as safe")
UNIT = "acquire.changelog_history"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def parsed(name: str, limits: ChangelogLimits = LIMITS) -> dict:
    return changelog.parse(fixture(name), limits, classify_text)


def entry(line, identity, stated, paths, *, fix=None, security=None, references=()):
    return {"line": line, "id": identity, "date": stated, "paths": paths, "fix": fix, "security_fix": security,
            "security_references": list(references), "message_complete": True, "paths_truncated": False}


def assert_private(value) -> None:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    for needle in FORBIDDEN:
        assert needle not in text, needle


# --- Names -----------------------------------------------------------------------------------------

@pytest.mark.parametrize(("path", "expected"), [
    ("CHANGELOG.md", True), ("CHANGES", True), ("ChangeLog", True), ("ChangeLog-1.0-S3_0", True),
    ("HISTORY.rst", True), ("NEWS-3.2", True), ("RELEASE_NOTES.txt", True), ("doc/ChangeLog.old", True),
    ("changes.json", False), ("changelog.d/123.bugfix", False), ("history.c", False), ("news.py", False),
    ("src/changelogger.c", False),
])
def test_only_conventional_change_log_names_are_candidates(path: str, expected: bool) -> None:
    assert changelog.is_changelog_name(path) is expected


# --- Formats ---------------------------------------------------------------------------------------

def test_gnu_changelog_yields_dates_files_and_symbols() -> None:
    result = parsed("gnu/ChangeLog")
    assert (result["format"], result["status"]) == ("gnu-changelog", "parsed")
    assert result["entries"] == [
        entry(1, None, "2024-03-10", [("src/auth.c", ("check_user", "verify_token")), ("util.c", ())],
              fix="heuristic", security="heuristic", references=["CVE-2024-11111"]),
        entry(7, None, "2024-02-01", [("src/auth.c", ("check_user", "login")), ("docs/guide.txt", ()),
                                      ("src/net/util.c", ())]),
        entry(14, None, "2001-01-15", [("missing.c", ())]),
    ]
    assert result["counts"]["unparsed_lines"] == 0 and result["counts"]["undated_entry_count"] == 0


def test_git_log_dump_reads_stat_numstat_name_status_and_name_only_rows() -> None:
    result = parsed("git/ChangeLog")
    assert (result["format"], result["status"]) == ("git-log", "parsed")
    assert result["entries"] == [
        entry(1, "1" * 40, "2024-03-10", [("src/auth.c", ()), ("src/util.c", ())],
              fix="heuristic", security="heuristic", references=["CVE-2024-22222"]),
        entry(12, "2" * 40, "2024-02-01", [("src/net/util.c", ()), (".../deep/guide.txt", ())]),
        entry(23, "3" * 40, "2024-01-15", [("docs/guide.txt", ()), ("assets/logo.png", ()), ("README", ())]),
    ]
    assert result["counts"]["unparsed_lines"] == 0


def test_svn_log_message_line_count_defeats_a_forged_header() -> None:
    result = parsed("svn/ChangeLog")
    assert (result["format"], result["status"]) == ("svn-log", "parsed")
    assert result["entries"] == [
        entry(2, "r42", "2024-03-10", [("/trunk/src/auth.c", ()), ("/trunk/src/util.c", ()),
                                       ("/branches/stable/docs/guide.txt", ()), ("/trunk/gone.c", ())],
              fix="heuristic", security="heuristic"),
        entry(13, "r41", "2024-02-01", []),
    ], "the r99 line is message text, not an entry dated 2030"
    assert result["counts"]["unparsed_lines"] == 0


def test_keep_a_changelog_uses_sections_as_a_closed_classification() -> None:
    result = parsed("keepachangelog/CHANGELOG.md")
    assert (result["format"], result["status"]) == ("keep-a-changelog", "parsed")
    assert result["entries"] == [
        entry(8, None, None, [("src/net/util.c", ())]),
        entry(13, None, "2024-03-10", [("src/auth.c", ())], fix="changelog_section", security="changelog_section"),
        entry(17, None, "2024-03-10", [("docs/guide.txt", ()), ("nothing/here.c", ())], fix="changelog_section"),
        entry(22, None, "2024-02-01", []),
    ]
    assert result["counts"]["undated_entry_count"] == 1 and result["counts"]["prose_lines"] == 1


def test_mixed_and_unrecognised_files_are_named_gaps_with_counts() -> None:
    mixed = parsed("mixed/ChangeLog")
    assert (mixed["format"], mixed["status"]) == ("git-log", "partial")
    assert [item["id"] for item in mixed["entries"]] == ["4" * 40], "the recognised part is kept, nothing is guessed"
    assert changelog.file_gaps("ChangeLog", mixed) == [
        {"gap": "changelog_mixed_format", "path": "ChangeLog", "count": 1, "unit": "lines"}]
    prose = parsed("prose/NEWS")
    assert (prose["format"], prose["status"], prose["entries"]) == (None, "unrecognized", [])
    assert changelog.file_gaps("NEWS", prose) == [
        {"gap": "changelog_format_unrecognized", "path": "NEWS", "count": 4, "unit": "lines"}]
    stray = changelog.parse(b"commit " + b"5" * 40 + b"\n\n    subject\n\nnot a path row at all\n", LIMITS, classify_text)
    assert changelog.file_gaps("ChangeLog", stray) == [
        {"gap": "changelog_unparsed_lines", "path": "ChangeLog", "count": 1, "unit": "lines"}]


def test_invalid_encoding_and_hostile_lines_are_handled_without_guessing() -> None:
    data = (b"commit " + b"6" * 40 + b"\nAuthor: J\xff\xfe <x@example.test>\nDate:   2024-13-45\n\n"
            b"    caf\xe9 fix\n\nM\tsrc/\xff.c\n" + b"(" * 2000 + b"\n")
    result = changelog.parse(data, LIMITS, classify_text)
    assert result["counts"]["undecodable_lines"] == 3 and result["counts"]["unparsed_lines"] == 1
    assert result["entries"][0]["date"] is None, "an impossible date is undated, never repaired"
    assert result["entries"][0]["fix"] == "heuristic"
    nested = changelog.parse(b"2024-01-02  A  <a@example.test>\n\n\t* a.c " + b"(" * 3000 + b": x\n", LIMITS,
                             classify_text)
    assert nested["entries"][0]["paths"] == [("a.c", ())]


# --- Bounds, each at its exact boundary ------------------------------------------------------------

def test_entry_bound_is_exact_and_reports_the_lines_it_did_not_parse() -> None:
    at_bound = parsed("git/ChangeLog", replace(LIMITS, max_entries=3))
    assert at_bound["status"] == "parsed" and at_bound["counts"]["lines_beyond_entry_bound"] == 0
    over = parsed("git/ChangeLog", replace(LIMITS, max_entries=2))
    assert [item["id"] for item in over["entries"]] == ["1" * 40, "2" * 40]
    # The third entry starts at line 23 of 31; lines 23-31 are reported, not parsed.
    assert over["counts"]["lines_beyond_entry_bound"] == 9 and over["status"] == "partial"
    assert changelog.file_gaps("ChangeLog", over) == [
        {"gap": "changelog_entry_bound_reached", "path": "ChangeLog", "count": 9, "unit": "lines"}]


def test_line_length_bound_is_exact_and_an_overlong_line_is_never_interpreted() -> None:
    head = b"commit " + b"7" * 40 + b"\n\n    subject\n\n"
    row = b"M\t" + b"a" * 62
    limits = replace(LIMITS, max_line_bytes=64)
    at_bound = changelog.parse(head + row + b"\n", limits, classify_text)
    assert at_bound["entries"][0]["paths"] == [("a" * 62, ())] and at_bound["counts"]["overlong_lines"] == 0
    over = changelog.parse(head + row + b"a\n", limits, classify_text)
    assert over["entries"][0]["paths"] == [] and over["counts"]["overlong_lines"] == 1
    assert changelog.file_gaps("ChangeLog", over) == [
        {"gap": "changelog_line_too_long", "path": "ChangeLog", "count": 1, "unit": "lines"}]


def test_paths_per_entry_bound_is_exact() -> None:
    at_bound = parsed("svn/ChangeLog", replace(LIMITS, max_paths_per_entry=4))
    assert len(at_bound["entries"][0]["paths"]) == 4 and at_bound["counts"]["entries_paths_truncated"] == 0
    over = parsed("svn/ChangeLog", replace(LIMITS, max_paths_per_entry=3))
    assert len(over["entries"][0]["paths"]) == 3 and over["entries"][0]["paths_truncated"] is True
    assert changelog.file_gaps("ChangeLog", over) == [
        {"gap": "changelog_entry_paths_truncated", "path": "ChangeLog", "count": 1, "unit": "entries"}]


def test_message_text_bound_marks_the_classification_incomplete() -> None:
    body = b"    " + b"x" * 4000 + b"\n"
    data = b"commit " + b"8" * 40 + b"\n\n" + body * 17 + b"    fix CVE-2024-33333\n"
    result = changelog.parse(data, LIMITS, classify_text)
    assert result["entries"][0]["message_complete"] is False and result["entries"][0]["fix"] is None
    assert result["counts"]["messages_truncated"] == 1 and result["status"] == "partial"
    assert changelog.file_gaps("ChangeLog", result) == [
        {"gap": "changelog_message_truncated", "path": "ChangeLog", "count": 1, "unit": "entries"}]


def test_non_ascii_digits_never_reach_int_and_never_raise() -> None:
    # str.isdigit accepts superscript and other Unicode digits that int() rejects.
    assert changelog._svn_header("r1 | a | 2020-01-01 | ² lines") == ("r1", "2020-01-01", None)
    assert changelog._svn_header("r² | a | 2020-01-01 | 1 line") is None
    assert changelog._stated_date("Date: ²²²² Jan 1") is None
    assert changelog._stated_date("٣ Jan ٢٠٢٤") is None
    assert changelog._git_path("²\t²\tsrc/a.c") is None
    # Whole files with such tokens parse without raising; an invalid count or date is simply absent.
    for text, dates in (
            ("r1 | a | 2020-01-01 | ² lines\n\nmessage\n", ["2020-01-01"]),
            ("commit " + "a" * 40 + "\nDate: ²²²² Jan 1\n\n    subject\n\nR²²\told\tnew\n", [None]),
            ("Mon Jan ² 10:00:00 ²²²²  A  <a@example.test>\n\n\t* a.c: x\n", [])):
        result = changelog.parse(text.encode(), LIMITS, classify_text)
        assert [item["date"] for item in result["entries"]] == dates


def test_svn_header_claiming_more_lines_than_exist_is_reported_not_trusted() -> None:
    separator = b"-" * 72 + b"\n"
    data = (separator + b"r2 | a | 2024-03-10 00:00:00 +0000 (x) | 999999 lines\n\nfirst\n" + separator
            + b"r1 | a | 2024-02-01 00:00:00 +0000 (x) | 1 line\n\nswallowed\n" + separator)
    result = changelog.parse(data, LIMITS, classify_text)
    assert [item["id"] for item in result["entries"]] == ["r2"] and result["status"] == "partial"
    assert changelog.file_gaps("ChangeLog", result) == [
        {"gap": "changelog_unparsed_lines", "path": "ChangeLog", "count": 6, "unit": "lines"}]


def test_gnu_symbols_need_a_closed_group_and_scan_once() -> None:
    data = ("2024-01-02  A  <a@example.test>\n\n\t* a.c (Closes: #12\n\t(Unfinished\n\t* b.c " + "()" * 1500
            + " (done): x\n").encode()
    result = changelog.parse(data, LIMITS, classify_text)
    assert result["entries"][0]["paths"] == [("a.c", ()), ("b.c", ("done",))]


# --- Path binding ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "expected"), [
    ("../etc/passwd", ("invalid", None)),
    ("./src/auth.c", ("exact", "src/auth.c")),
    (".../deep/guide.txt", ("suffix", "manual/deep/guide.txt")),
    (".../docs/guide.txt", ("unmatched", None)),
    ("/branches/stable/docs/guide.txt", ("unmatched", None)),
    ("/trunk/project/src/auth.c", ("unmatched", None)),
    ("/tags/v1/src/auth.c", ("unmatched", None)),
    ("/trunk/src/auth.c", ("repository_prefix", "src/auth.c")),
    ("auth.c", ("suffix", "src/auth.c")),
    ("deep/guide.txt", ("suffix", "manual/deep/guide.txt")),
    ("guide.txt", ("ambiguous", None)),
    ("missing.c", ("unmatched", None)),
    ("src/auth.c", ("exact", "src/auth.c")),
    ("util.c", ("ambiguous", None)),
])
def test_paths_bind_only_exactly_or_by_an_unambiguous_suffix(raw: str, expected: tuple) -> None:
    assert PathBinder(CATALOG).bind(raw) == expected


def test_a_source_root_is_tried_before_the_bare_path() -> None:
    binder = PathBinder({"api/src/auth.c": "0", "worker/src/auth.c": "1"}, root="api")
    assert binder.bind("src/auth.c") == ("exact", "api/src/auth.c")
    assert PathBinder({"api/src/auth.c": "0", "worker/src/auth.c": "1"}).bind("src/auth.c") == ("ambiguous", None)


# --- Signals ---------------------------------------------------------------------------------------

def summary(*names: str, months: int = 6, bulk: int = 500) -> dict:
    return changelog.summarize([{"path": name, "parsed": parsed(name)} for name in names], catalog=CATALOG,
                               root=".", window_months=months, bulk_threshold=bulk)


def test_file_signals_count_entries_in_a_window_anchored_to_the_newest_entry() -> None:
    result = summary("gnu/ChangeLog")
    assert result["window"] == {"identity": "appsec-review/history-window/calendar-months-utc/1", "months": 6,
                                "anchor_date": "2024-03-10", "start_date": "2023-09-10",
                                "anchor": "newest dated change-log entry"}
    auth = result["files"]["src/auth.c"]
    assert {key: auth[key] for key in (
        "source", "rank", "change_count", "lifetime_change_count", "fix_change_count", "security_fix_change_count",
        "first_change_date", "last_change_date", "security_references", "symbols")} == {
        "source": "changelog", "rank": 1, "change_count": 2, "lifetime_change_count": 2, "fix_change_count": 1,
        "security_fix_change_count": 1, "first_change_date": "2024-02-01", "last_change_date": "2024-03-10",
        "security_references": ["CVE-2024-11111"], "symbols": ["check_user", "login", "verify_token"]}
    assert auth["evidence"][0] == {"changelog": "gnu/ChangeLog", "line": 1, "date": "2024-03-10"}
    assert result["entries"][0] == {
        "changelog": "gnu/ChangeLog", "line": 1, "id": None, "date": "2024-03-10", "fix": "heuristic",
        "security_fix": "heuristic", "security_references": ["CVE-2024-11111"], "message_complete": True,
        "paths_truncated": False, "paths": ["src/auth.c"],
        "binding_counts": {"exact": 1, "suffix": 0, "repository_prefix": 0},
        "symbols": {"src/auth.c": ["check_user", "verify_token"]}, "unbound_path_count": 1, "bulk": False,
        "in_window": True}
    assert result["ranking"] == ["src/auth.c", "docs/guide.txt", "src/net/util.c"]
    assert result["totals"]["path_mentions"] == {"exact": 4, "suffix": 0, "repository_prefix": 0, "ambiguous": 1,
                                                 "unmatched": 1, "invalid": 0}
    one_month = summary("gnu/ChangeLog", months=1)
    assert one_month["window"]["start_date"] == "2024-02-10"
    assert one_month["files"]["src/auth.c"]["change_count"] == 1
    assert one_month["files"]["src/auth.c"]["lifetime_change_count"] == 2


def test_bulk_entries_and_repeated_entry_ids_are_not_counted_twice() -> None:
    bulk = summary("svn/ChangeLog", bulk=3)
    assert bulk["totals"]["bulk_entry_count"] == 1 and bulk["ranking"] == []
    assert bulk["files"]["src/auth.c"]["bulk_change_count"] == 1
    assert bulk["files"]["src/auth.c"]["lifetime_change_count"] == 0
    twice = changelog.summarize([{"path": name, "parsed": parsed("svn/ChangeLog")} for name in ("a", "b")],
                                catalog=CATALOG, root=".", window_months=6, bulk_threshold=500)
    assert twice["totals"]["duplicate_entry_count"] == 2 and twice["totals"]["entry_count"] == 2
    assert twice["files"]["src/auth.c"]["lifetime_change_count"] == 1


@pytest.mark.parametrize("name", ["git/ChangeLog", "gnu/ChangeLog", "keepachangelog/CHANGELOG.md",
                                  "mixed/ChangeLog", "prose/NEWS", "svn/ChangeLog"])
def test_names_addresses_and_message_text_are_dropped_while_parsing(name: str) -> None:
    for needle in FORBIDDEN[:1] + FORBIDDEN[-2:]:
        assert needle.encode() in fixture(name), "the fixture must carry what the parser has to drop"
    result = parsed(name)
    assert_private(repr(result))
    assert_private(summary(name))


# --- Settings --------------------------------------------------------------------------------------

def history_settings() -> dict:
    return deepcopy(dict(load_config(ROOT / "appsec-review.toml").job("job_source_history_analysis").settings))


def test_default_changelog_settings_are_typed() -> None:
    settings = parse_settings(history_settings())
    assert settings.changelog_enabled is True
    assert settings.changelog == ChangelogLimits(max_files=16, max_file_bytes=16 * 1024 * 1024, max_entries=100_000,
                                                 max_line_bytes=4096, max_paths_per_entry=2000)


@pytest.mark.parametrize(("key", "value"), [
    ("enabled", "yes"), ("enabled", 1), ("max_entries", 0), ("max_entries", 1_000_001), ("max_file_bytes", 1023),
    ("max_file_bytes", 64 * 1024 * 1024 + 1), ("max_files", 0), ("max_files", 257), ("max_files", True),
    ("max_line_bytes", 63), ("max_line_bytes", 65_537), ("max_paths_per_entry", 0),
    ("max_paths_per_entry", 100_001),
])
def test_invalid_changelog_settings_are_rejected(key: str, value) -> None:
    settings = history_settings()
    settings["changelog"][key] = value
    with pytest.raises(ValueError, match="changelog"):
        parse_settings(settings)


@pytest.mark.parametrize(("key", "value"), [
    ("max_entries", 1), ("max_entries", 1_000_000), ("max_file_bytes", 1024), ("max_file_bytes", 64 * 1024 * 1024),
    ("max_files", 1), ("max_files", 256), ("max_line_bytes", 64), ("max_line_bytes", 65_536),
    ("max_paths_per_entry", 1), ("max_paths_per_entry", 100_000),
])
def test_changelog_setting_bounds_are_inclusive(key: str, value: int) -> None:
    settings = history_settings()
    settings["changelog"][key] = value
    assert getattr(parse_settings(settings).changelog, key) == value


def test_missing_or_unknown_changelog_settings_fail_validation() -> None:
    settings = history_settings()
    settings["changelog"]["max_bytes"] = 1
    with pytest.raises(ValueError, match="changelog"):
        parse_settings(settings)
    del settings["changelog"]
    with pytest.raises(ValueError, match="changelog"):
        parse_settings(settings)


# --- The unit, through the real handler ------------------------------------------------------------

def lane(tmp_path: Path, files: dict[str, bytes], *, bounds: dict | None = None, exclusions=(),
         sources: dict[str, str] | None = None) -> tuple[UnitContext, object]:
    """A unit context over a real target tree and the resolve output the handler consumes."""
    target, run = tmp_path / "target", tmp_path / "run"
    inventory = []
    for path, data in sorted(files.items()):
        (target / path).parent.mkdir(parents=True, exist_ok=True)
        (target / path).write_bytes(data)
        inventory.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
                          "language": None})
    config = load_config(ROOT / "appsec-review.toml").job("job_source_history_analysis")
    if bounds:
        config = replace(config, settings={**config.settings, "changelog": {**config.settings["changelog"], **bounds}})
    context = JobContext(
        run_id="fixture", attempt_id="attempt_0001", trigger="test", repository_root=tmp_path, run_root=run,
        attempt_root=run / "attempt", metadata_root=run / "metadata", orchestration={}, config=config,
        events=EventLog(run / "events.jsonl"), target_root=target, source_fingerprint="snapshot")

    def resolved(source_id: str, root: str) -> dict:
        owned = [item for item in inventory if root == "." or item["path"].startswith(root + "/")]
        return {"source": {"source_id": source_id, "root": root},
                "inputs": {"files": owned, "changelog_exclusions": list(exclusions)}}

    first = (resolved(".", ".") if sources is None else
             {"by_source": {key: resolved(key, root) for key, root in sorted(sources.items())}})
    unit = UnitContext(context, UNIT, "acquire", "changelog_history", run / "changelog",
                       {"resolve_sources.resolve_history_source": first})
    handler = next(item.handler for item in build_job().units if item.unit_id == UNIT)
    return unit, handler


def artifact(unit: UnitContext, output: dict) -> dict:
    return json.loads((unit.job.run_root / output["artifact"]["path"]).read_text(encoding="utf-8"))


SOURCES = {path: b"int x;\n" for path in CATALOG}


def every_format(tmp_path: Path) -> tuple[UnitContext, dict]:
    unit, handler = lane(tmp_path, {
        **SOURCES, "ChangeLog": fixture("gnu/ChangeLog"), "CHANGELOG.md": fixture("keepachangelog/CHANGELOG.md"),
        "NEWS": fixture("prose/NEWS"), "history/ChangeLog-git": fixture("git/ChangeLog"),
        "history/ChangeLog-svn": fixture("svn/ChangeLog")})
    return unit, dict(handler(unit))


def test_unit_parses_every_format_and_reports_each_gap_as_a_record(tmp_path: Path) -> None:
    unit, output = every_format(tmp_path)
    validate_unit_output(output, unit_id=UNIT, strict_gaps=True)
    assert output["terminal_status"] == "PARTIAL"
    assert output["formats"] == ["git-log", "gnu-changelog", "keep-a-changelog", "svn-log"]
    assert output["gap_codes"] == ["changelog_format_unrecognized", "changelog_paths_unbound"]
    assert sorted((gap["code"], gap["scope_id"], gap["reason"]) for gap in output["gaps"]) == [
        ("location_unresolved", "source:.",
         "changelog_paths_unbound: source:.: 7 path mentions (ambiguous 1, unmatched 6, invalid 0)"),
        ("parser_error", "NEWS", "changelog_format_unrecognized: NEWS: 4 lines"),
    ]
    document = artifact(unit, output)
    assert document["schema"] == "appsec-review/source-history-changelog/1" and document["source"] == "changelog"
    assert [item["path"] for item in document["changelogs"]] == [
        "CHANGELOG.md", "ChangeLog", "NEWS", "history/ChangeLog-git", "history/ChangeLog-svn"]
    auth = document["files"]["src/auth.c"]
    # Five entries name it: two GNU, one Markdown, one git-log, one svn-log; four of them are security fixes.
    assert (auth["rank"], auth["change_count"], auth["security_fix_change_count"]) == (1, 5, 4)
    assert auth["bindings"] == {"exact": 4, "suffix": 0, "repository_prefix": 1}
    assert document["totals"]["entry_count"] == 12 and document["window"]["anchor_date"] == "2024-03-10"
    assert all(item["source"] == "changelog" for item in document["files"].values())
    assert_private(document)
    assert_private(output)


def test_no_change_log_is_not_applicable_and_disabled_is_policy(tmp_path: Path) -> None:
    unit, handler = lane(tmp_path / "none", SOURCES)
    assert handler(unit) == {"terminal_status": "SKIPPED_NA", "reason": "no_changelog_files", "gaps": []}
    unit, handler = lane(tmp_path / "off", {**SOURCES, "ChangeLog": fixture("gnu/ChangeLog")},
                         bounds={"enabled": False})
    assert handler(unit) == {"terminal_status": "SKIPPED_POLICY", "reason": "changelog_history_disabled", "gaps": []}


def test_a_change_log_the_inventory_left_out_is_a_named_gap(tmp_path: Path) -> None:
    unit, handler = lane(tmp_path, SOURCES, exclusions=[{"path": "ChangeLog", "reason": "file_too_large"}])
    output = handler(unit)
    assert output["terminal_status"] == "PARTIAL" and output["entry_count"] == 0
    assert [(gap["code"], gap["scope_id"], gap["reason"]) for gap in output["gaps"]] == [
        ("input_unavailable", "ChangeLog", "changelog_excluded_from_inventory: ChangeLog: 1 files (file_too_large)")]
    assert not (unit.job.target_root / "ChangeLog").exists(), "an excluded file is never opened"


def test_file_count_bound_is_exact(tmp_path: Path) -> None:
    logs = {name: fixture("gnu/ChangeLog") for name in ("ChangeLog", "a/ChangeLog", "b/ChangeLog")}
    unit, handler = lane(tmp_path / "at", {**SOURCES, **logs}, bounds={"max_files": 3})
    assert handler(unit)["gap_codes"] == ["changelog_paths_unbound"]
    unit, handler = lane(tmp_path / "over", {**SOURCES, **logs}, bounds={"max_files": 2})
    output = handler(unit)
    assert [item["path"] for item in artifact(unit, output)["changelogs"]] == ["ChangeLog", "a/ChangeLog"]
    assert ("truncated", "changelog_file_bound_reached: source:.: 1 files") in [
        (gap["code"], gap["reason"]) for gap in output["gaps"]]


def test_byte_bound_is_exact_and_the_unparsed_bytes_are_counted(tmp_path: Path) -> None:
    data = fixture("git/ChangeLog") + b"\n" * (2048 - len(fixture("git/ChangeLog")))
    unit, handler = lane(tmp_path / "at", {**SOURCES, "ChangeLog": data}, bounds={"max_file_bytes": 2048})
    output = handler(unit)
    assert "changelog_bytes_truncated" not in output["gap_codes"] and output["entry_count"] == 3
    unit, handler = lane(tmp_path / "over", {**SOURCES, "ChangeLog": data + b"commit " + b"9" * 40 + b"\n"},
                         bounds={"max_file_bytes": 2048})
    output = handler(unit)
    record = artifact(unit, output)["changelogs"][0]
    assert (record["size_bytes"], record["parsed_bytes"]) == (2096, 2048) and output["entry_count"] == 3
    assert ("truncated", "changelog_bytes_truncated: ChangeLog: 48 bytes") in [
        (gap["code"], gap["reason"]) for gap in output["gaps"]]


def test_changed_or_escaping_change_log_bytes_fail_the_unit(tmp_path: Path) -> None:
    unit, handler = lane(tmp_path / "changed", {**SOURCES, "ChangeLog": fixture("gnu/ChangeLog")})
    (unit.job.target_root / "ChangeLog").write_bytes(b"edited after the catalog accepted it\n")
    with pytest.raises(ValueError, match="accepted target bytes changed"):
        handler(unit)
    unit, handler = lane(tmp_path / "link", {**SOURCES, "ChangeLog": fixture("gnu/ChangeLog")})
    outside = tmp_path / "outside"
    outside.write_bytes(fixture("gnu/ChangeLog"))
    (unit.job.target_root / "ChangeLog").unlink()
    (unit.job.target_root / "ChangeLog").symlink_to(outside)
    with pytest.raises(ValueError, match="accepted target file is unavailable"):
        handler(unit)


def test_hostile_digits_in_a_change_log_do_not_fail_the_unit(tmp_path: Path) -> None:
    hostile = ("r1 | a | 2020-01-01 | ² lines\nDate: ²²²² Jan 1\n\nmessage\n").encode()
    unit, handler = lane(tmp_path, {**SOURCES, "ChangeLog": hostile, "doc/ChangeLog": fixture("gnu/ChangeLog")})
    output = handler(unit)
    validate_unit_output(output, unit_id=UNIT, strict_gaps=True)
    assert output["terminal_status"] == "PARTIAL" and output["entry_count"] == 4
    assert "²" not in json.dumps(output, ensure_ascii=False)


def test_a_failure_inside_the_unit_is_a_named_gap_without_target_text(tmp_path: Path, monkeypatch) -> None:
    def explode(*args, **kwargs):
        raise RuntimeError("secret target text jane.roe@example.test")

    logs = {"ChangeLog": fixture("gnu/ChangeLog"), "doc/ChangeLog": fixture("svn/ChangeLog")}
    unit, handler = lane(tmp_path / "parser", {**SOURCES, **logs})
    real = changelog.parse
    monkeypatch.setattr(changelog, "parse", lambda data, *rest: explode() if data.startswith(b"2024") else
                        real(data, *rest))
    output = handler(unit)
    validate_unit_output(output, unit_id=UNIT, strict_gaps=True)
    assert ("producer_failed", "ChangeLog", "changelog_parser_failed: ChangeLog: 1 files (RuntimeError)") in [
        (gap["code"], gap["scope_id"], gap["reason"]) for gap in output["gaps"]]
    assert output["formats"] == ["svn-log"], "the other change log is still parsed"
    monkeypatch.setattr(changelog, "parse", real)
    monkeypatch.setattr(changelog, "summarize", explode)
    for sources in (None, {"api": "src", "docs": "docs"}):
        unit, handler = lane(tmp_path / f"unit-{bool(sources)}", {**SOURCES, "src/ChangeLog": fixture("gnu/ChangeLog")},
                             sources=sources)
        output = handler(unit)
        validate_unit_output(output, unit_id=UNIT, strict_gaps=True)
        assert output["terminal_status"] == "PARTIAL"
        assert [(gap["code"], gap["reason"]) for gap in output["gaps"]] == [(
            "producer_failed",
            f"changelog_unit_failed: source:{'api' if sources else '.'}: 1 sources (RuntimeError)")]
        if sources:
            assert output["by_source"]["docs"]["terminal_status"] == "SKIPPED_NA", "one lane never kills another"
        failed = output["by_source"]["api"] if sources else output
        section = history_module.changelog_section(unit.job.run_root, failed, git_ranked=True, git_gaps=[],
                                                   source_id=".", top_n=5)
        assert (section["decision"], section["role"], section["gaps"]) == ("PARTIAL", None, ["changelog_unit_failed"])
        assert_private(output)
        assert "secret" not in json.dumps(output)
        assert "secret" not in (unit.job.run_root / "events.jsonl").read_text(encoding="utf-8")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files regardless of their mode")
def test_an_unreadable_change_log_is_a_gap_and_the_others_are_still_read(tmp_path: Path) -> None:
    unit, handler = lane(tmp_path, {**SOURCES, "ChangeLog": fixture("gnu/ChangeLog"),
                                    "doc/ChangeLog": fixture("svn/ChangeLog")})
    blocked = unit.job.target_root / "ChangeLog"
    blocked.chmod(0)
    try:
        output = handler(unit)
    finally:
        blocked.chmod(0o644)
    validate_unit_output(output, unit_id=UNIT, strict_gaps=True)
    assert ("input_unavailable", "ChangeLog", "changelog_unreadable: ChangeLog: 1 files (PermissionError)") in [
        (gap["code"], gap["scope_id"], gap["reason"]) for gap in output["gaps"]]
    assert output["formats"] == ["svn-log"] and output["entry_count"] == 2


def test_a_change_log_that_ranks_no_file_gets_no_role(tmp_path: Path) -> None:
    dump = b"commit " + b"a" * 40 + b"\nDate:   2024-03-10\n\n    fix: overflow\n"
    unit, handler = lane(tmp_path, {**SOURCES, "ChangeLog": dump})
    output = handler(unit)
    assert (output["terminal_status"], output["entry_count"], output["ranked_file_count"]) == ("SUCCEEDED", 1, 0)
    section = history_module.changelog_section(unit.job.run_root, output, git_ranked=False, git_gaps=[],
                                               source_id=".", top_n=5)
    # Entry counts are published, but nothing here can order files, so a Git-less job stays SKIPPED_NA.
    assert (section["decision"], section["entry_count"], section["role"], section["files"]) == ("SUCCEEDED", 1, None, [])


def test_source_lanes_stay_separate_and_bind_under_their_own_root(tmp_path: Path) -> None:
    unit, handler = lane(tmp_path, {
        "api/src/auth.c": b"int a;\n", "worker/src/auth.c": b"int w;\n",
        "api/ChangeLog": b"2024-03-10  A  <a@example.test>\n\n\t* src/auth.c: Fix crash.\n"},
        sources={"api": "api", "worker": "worker"})
    output = handler(unit)
    validate_unit_output(output, unit_id=UNIT, strict_gaps=True)
    assert output["terminal_status"] == "SUCCEEDED" and output["gaps"] == []
    assert output["by_source"]["worker"] == {"terminal_status": "SKIPPED_NA", "reason": "no_changelog_files",
                                             "gaps": []}
    api = output["by_source"]["api"]
    document = json.loads((unit.job.run_root / api["artifact"]["path"]).read_text(encoding="utf-8"))
    assert list(document["files"]) == ["api/src/auth.c"] and document["files"]["api/src/auth.c"]["fix_change_count"] == 1
    assert "/sources/" in api["artifact"]["path"]


# --- The job: precedence between Git and the change log --------------------------------------------

def test_dag_runs_the_change_log_unit_before_the_index() -> None:
    plan = plan_jobs((build_job(),))
    assert plan.node(f"job_source_history_analysis.{UNIT}").dependencies == (
        "job_source_history_analysis.resolve_sources.resolve_history_source",)
    assert f"job_source_history_analysis.{UNIT}" in plan.node(
        "job_source_history_analysis.publish.index_history").dependencies


def test_change_log_artifact_changes_the_index_fingerprint_only_when_present() -> None:
    settings = history_settings()
    base = {"snapshot": "snapshot", "source_identity": "b" * 64, "settings": settings,
            "ranked": {}, "normalized": {}, "acquired": {}, "github": {}}
    absent = history_module._history_index_fingerprint(**base)
    assert history_module._history_index_fingerprint(**base, changelog={"terminal_status": "SKIPPED_NA"}) == absent
    present = {"artifact": {"path": "artifacts/changelog.json", "sha256": "a" * 64, "size_bytes": 1}}
    first = history_module._history_index_fingerprint(**base, changelog=present)
    present["artifact"]["sha256"] = "d" * 64
    assert len({absent, first, history_module._history_index_fingerprint(**base, changelog=present)}) == 3


@pytest.mark.parametrize(("git_ranked", "git_gaps", "role"), [
    (False, [], "primary"),
    (True, [], "supplement"),
    (True, ["history_not_of_snapshot"], "primary"),
    (True, ["history_window_truncated"], "primary"),
    (True, ["shallow_history", "working_tree_divergent"], "primary"),
    (True, ["working_tree_divergent"], "supplement"),
], ids=["no-git", "complete-git", "unrelated-git", "truncated-git", "shallow-git", "divergent-git"])
def test_git_is_authoritative_while_complete_and_the_change_log_leads_otherwise(
        tmp_path: Path, git_ranked: bool, git_gaps: list[str], role: str) -> None:
    unit, output = every_format(tmp_path)
    section = history_module.changelog_section(unit.job.run_root, output, git_ranked=git_ranked, git_gaps=git_gaps,
                                               source_id=".", top_n=3)
    assert (section["source"], section["role"], section["decision"]) == ("changelog", role, "PARTIAL")
    assert section["gaps"] == ["changelog_format_unrecognized", "changelog_paths_unbound"]
    assert len(section["files"]) == 3, "the published ranking is bounded"
    # Never shaped like, or merged into, a commit-derived rank: no score or churn, and its own labels.
    assert section["files"][0] == {
        "path": "src/auth.c", "sha256": hashlib.sha256(b"int x;\n").hexdigest(), "rank": 1, "change_count": 5,
        "lifetime_change_count": 5, "last_change_date": "2024-03-10", "fix_change_count": 4,
        "security_fix_change_count": 4, "source": "changelog", "role": role, "source_id": "."}
    assert all(item["source"] == "changelog" and item["role"] == role for item in section["files"])
    assert_private(section)


def test_no_change_log_leaves_an_empty_section_without_a_role(tmp_path: Path) -> None:
    skipped = {"terminal_status": "SKIPPED_NA", "reason": "no_changelog_files", "gaps": []}
    for output, reason in ((skipped, "no_changelog_files"), (None, "changelog_unit_not_run")):
        section = history_module.changelog_section(tmp_path, output, git_ranked=False, git_gaps=[], source_id=".",
                                                   top_n=200)
        assert (section["decision"], section["reason"], section["role"], section["files"], section["gaps"]) == (
            "SKIPPED_NA", reason, None, [], [])


def test_index_gets_location_free_change_log_signals_and_a_coverage_row(tmp_path: Path) -> None:
    unit, output = every_format(tmp_path)
    builder = IndexBuilder(tmp_path / "history.sqlite", name="history", fingerprint="f" * 64,
                           target_snapshot="snapshot", shard_id="git-history")
    history_module.index_changelog(builder, unit.job.run_root, output, snapshot="snapshot",
                                   source={"source_id": ".", "root": "."}, top_n=2)
    assert [(item.native_id, item.name, item.payload["source"], item.payload["change_count"], item.location)
            for item in builder.entities] == [("changelog:src/auth.c", "src/auth.c", "changelog", 5, None),
                                              ("changelog:docs/guide.txt", "docs/guide.txt", "changelog", 3, None)]
    assert builder.entities[0].payload["evidence"][0].keys() == {"changelog", "line", "date"}
    assert builder.coverage == [
        ("changelog-history", "partial", "changelog_format_unrecognized; changelog_paths_unbound")]
    assert_private([item.payload for item in builder.entities] + [item.text for item in builder.entities])
    builder.build()
    assert (tmp_path / "history.sqlite").is_file()
    skipped = {"terminal_status": "SKIPPED_NA", "reason": "no_changelog_files", "gaps": []}
    for missing, gap in ((skipped, "no_changelog_files"), (None, "changelog_unit_not_run")):
        empty = IndexBuilder(tmp_path / "empty.sqlite", name="history", fingerprint="e" * 64,
                             target_snapshot="snapshot", shard_id="git-history")
        history_module.index_changelog(empty, unit.job.run_root, missing, snapshot="snapshot", source={}, top_n=2)
        assert (empty.entities, empty.coverage) == ([], [("changelog-history", "unavailable", gap)])


def test_job_validator_requires_the_change_log_task_and_settings(tmp_path: Path) -> None:
    unit, _ = lane(tmp_path, SOURCES)
    history_module._validate(unit.job, None)
    settings = dict(unit.job.config.settings)
    del settings["changelog"]
    with pytest.raises(ValueError, match="changelog"):
        history_module._validate(replace(unit.job, config=replace(unit.job.config, settings=settings)), None)
    assert history_module.TOPOLOGY["acquire"][-1] == "changelog_history"
    assert build_job().strict_gaps is False, "the job is still on the legacy gap list; this unit alone emits records"


def test_plan_projection_drops_change_log_files_the_catalog_does_not_accept() -> None:
    accepted = {"path": "src/auth.c", "sha256": "a" * 64, "rank": 1, "change_count": 2, "lifetime_change_count": 3,
                "last_change_date": "2024-03-10", "fix_change_count": 1, "security_fix_change_count": 1,
                "source": "changelog", "role": "primary", "source_id": "."}
    history = {"ranking": {}, "changelog": {"role": "primary", "identity": changelog.IDENTITY, "files": [
        accepted, {**accepted, "path": "src/gone.c"}, {**accepted, "path": "src/util.c", "sha256": "b" * 64}]}}
    catalog = {"files": [{"path": "src/auth.c", "sha256": "a" * 64}, {"path": "src/util.c", "sha256": "c" * 64}],
               "components": []}
    priority = history_priority(history, catalog)
    assert priority["status"] == "UNAVAILABLE" and priority["files"] == []
    assert priority["changelog"] == {"status": "AVAILABLE", "source": "changelog", "role": "primary",
                                     "identity": changelog.IDENTITY, "reason": None, "files": [accepted]}
    assert history_priority(None, catalog)["changelog"]["status"] == "UNAVAILABLE"
