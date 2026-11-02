"""CASTLE-style detector scoring (docs/reviews/castle-style-detector-scoring.md, decisions 1-3, 6-9, 11).

Expected numbers are computed by hand from paper eq. 1-2 and the design's decisions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import types

import pytest

from appsec_review.acceptance import scoring
from appsec_review.acceptance.funnel import DEFAULT_EXPECTATIONS
from appsec_review.acceptance.scoring import (NO_NEGATIVE_CONTROLS, bonus, load_cwe_match, load_scoring_key,
                                              load_top_list, render_lines, score)
from appsec_review.acceptance.scoring_model import (CWE_MATCH_REFERENCE, SCORING_SCHEMA, EntryKind, Report,
                                                    ReportOutcome)

REPO = Path(scoring.__file__).resolve().parents[3]

# D1 CWE-787 (Table 2 rank 2, B=5) on lines 10 and 14, scope 5..20; C1 its fixed twin, scope 25..40.
# D2 CWE-190 (rank 23, B=1) on lines 8..9; C2 a whole-file control.
# Max = (5+5) + (5+1) + 2*2 = 20; floor = 2*2 = 4.
MINI = """
[corpus]
name = "mini"
tag = "mini-v1"
commit = "0123456789abcdef"

[[defect]]
id = "d1"
cwe = "CWE-0787"
path = "src/a.c"
line = 10
lines = [14, 10]
scope_start = 5
scope_end = 20
pair = "c1"

[[defect]]
id = "d2"
cwe = 190
path = "src/b.c"
line = 8
end_line = 9
scope_start = 1
scope_end = 20

[[control]]
id = "c1"
cwe = "CWE-787"
path = "src/a.c"
line = 30
scope_start = 25
scope_end = 40
pair = "d1"

[[control]]
id = "c2"
path = "src/c.c"
line = 3
scope = "file"
"""


def _key(tmp_path: Path, text: str = MINI, name: str = "key.toml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return load_scoring_key(path)


def _r(producer: str, path: str, line: int, *cwes: str, end: int | None = None, rule: str = "",
       evidence: str = "") -> Report:
    return Report(producer, path, line, end or line, rule or f"r{line}", frozenset(cwes), evidence)


ALPHA = [_r("alpha", "src/a.c", 14, "CWE-787"),  # hit d1 on its second target line
         _r("alpha", "src/a.c", 18, "CWE-787"),  # in d1's scope, 4 lines past 14: off_location
         _r("alpha", "src/b.c", 9, "CWE-190"),  # hit d2
         _r("alpha", "src/c.c", 50, "CWE-476"),  # on control c2
         _r("alpha", "src/a.c", 100, "CWE-787")]  # in no scope: unattributed
BETA = [_r("beta", "src/a.c", 10, "CWE-787"),  # hit d1
        _r("beta", "src/a.c", 30, "CWE-787"),  # on control c1
        _r("beta", "src/b.c", 8)]  # on d2's lines without a CWE
GAMMA = [_r("gamma", "src/c.c", 5, "CWE-121")]  # noise on control c2


def _producer(report, name):
    return next(item for item in report.producers if item.producer == name)


# ---------------------------------------------------------------------------------------- loader

def test_v1_key_loads_unchanged_and_scores_without_controls():
    key = load_scoring_key(REPO / DEFAULT_EXPECTATIONS)
    assert len(key.defects) == 7 and key.controls == ()
    frame = next(entry for entry in key.defects if entry.id == "integer-overflow-frame-size")
    assert frame.lines == (9, 10) and frame.scope == (9, 10) and frame.cwe == "CWE-190"
    assert frame.producers == ("codeql",)
    report = score(key, [_r("codeql", "src/frame.cpp", 10, "CWE-190")])
    assert NO_NEGATIVE_CONTROLS in report.gaps
    codeql = _producer(report, "codeql")
    assert (codeql.tp, codeql.fn, codeql.tn, codeql.accuracy) == (1, 6, None, None)
    # B: 121 -> 0, 416 (8) -> 4, 476 (21) -> 1, 190 (23) -> 1, 134 (12) -> 3, 78 (7) -> 4, 798 (14) -> 3.
    assert (report.max_score, report.floor_score) == (35 + 16, 0)
    assert codeql.castle_score == 5 + 1


def test_mini_key_fields(tmp_path):
    key = _key(tmp_path)
    d1, d2, c1, c2 = key.entries
    assert d1.lines == (10, 14) and d1.scope == (5, 20) and d1.cwe == "CWE-787" and d1.pair == "c1"
    assert d2.lines == (8, 9) and d2.scope == (1, 20) and d2.cwe == "CWE-190"
    assert c1.kind is EntryKind.CONTROL and c2.scope is None and c2.cwe is None


def test_default_scope_is_the_target_lines(tmp_path):
    key = _key(tmp_path, '[[defect]]\nid = "x"\ncwe = "CWE-78"\npath = "a.c"\nlines = [7, 3, 5]\n')
    assert key.entries[0].lines == (3, 5, 7) and key.entries[0].scope == (3, 7)


@pytest.mark.parametrize(("text", "message"), [
    ("[corpus]\nname = 'x'\n", "lists no defects or controls"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 1\n'
     '[[control]]\nid = "x"\npath = "b.c"\nline = 1\n', "repeats the id x"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 1\npair = "y"\n', "pair names no other entry"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 5\nend_line = 4\n', "end_line precedes line"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 5\nscope_start = 1\nscope_end = 10\n'
     '[[control]]\nid = "y"\npath = "a.c"\nline = 12\nscope_start = 10\nscope_end = 20\n', "overlap"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 5\n'
     '[[control]]\nid = "y"\npath = "a.c"\nline = 50\nscope = "file"\n', "file-scope case shares its file"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 5\nscope_start = 6\nscope_end = 10\n',
     "does not contain its lines"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nlines = [5, 12]\nline = 5\nscope_start = 1\nscope_end = 10\n',
     "does not contain its lines"),
    ('[[defect]]\nid = "x"\npath = "a.c"\nline = 5\n', "a defect needs a cwe"),
    ('[[defect]]\nid = "x"\ncwe = "not a cwe"\npath = "a.c"\nline = 5\n', "unrecognised cwe"),
    ('[corpus]\nscored_paths = "p"\n[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "p/a.c"\nline = 5\n', "scored_paths"),
    ('[[defect]]\nid = "x"\ncwe = "CWE-1"\npath = "a.c"\nline = 5\nscope_start = 1\n', "go together"),
])
def test_loader_rejects(tmp_path, text, message):
    with pytest.raises(ValueError, match=message):
        _key(tmp_path, text)


# --------------------------------------------------------------------------------- single producer

def test_single_producer_reproduces_paper_equations(tmp_path):
    report = score(_key(tmp_path), ALPHA)
    assert (report.max_score, report.floor_score) == (20, 4)
    alpha = _producer(report, "alpha")
    # d1: 5 - (2 - 1) + 5 = 9; d2: 5 - 0 + 1 = 6; c1 silent: 2; c2 one report: -1.
    assert alpha.castle_score == 9 + 6 + 2 - 1 == 16
    assert (alpha.tp, alpha.fn, alpha.tn, alpha.fp, alpha.fp_cases, alpha.lenient_tp) == (2, 0, 1, 2, 2, 2)
    assert (alpha.precision, alpha.recall, alpha.accuracy) == (0.5, 1.0, 0.6)  # 2/4, 2/2, 3/5
    assert alpha.outcomes == {"hit": 2, "location_hit_cwe_miss": 0, "location_hit_cwe_unknown": 0,
                              "off_location": 1, "control": 1, "unattributed": 1}
    assert [(item.path, item.start_line) for item in alpha.unattributed] == [("src/a.c", 100)]
    assert NO_NEGATIVE_CONTROLS not in report.gaps
    cases = {case["id"]: case for case in report.as_dict()["cases"]}
    assert cases["d1"]["bonus"] == 5 and cases["d1"]["hit_by"] == ["alpha"]
    assert cases["d1"]["outcomes"] == {"alpha": {"hit": 1, "off_location": 1}}
    assert cases["d1"]["scores"] == {"alpha": 9} and cases["c2"]["scores"] == {"alpha": -1}


def test_outcome_classification_and_tolerance_boundary(tmp_path):
    key = _key(tmp_path, '[[defect]]\nid = "x"\ncwe = "CWE-121"\npath = "a.c"\nline = 20\n'
                         'scope_start = 10\nscope_end = 40\n'
                         '[[control]]\nid = "y"\npath = "a.c"\nline = 60\nscope_start = 50\nscope_end = 70\n')
    reports = [_r("p", "a.c", 20, "CWE-787"),  # accepted for CWE-121 by cwe-match
               _r("p", "a.c", 21, "CWE-476"), _r("p", "a.c", 22), _r("p", "a.c", 23, "CWE-121"),
               _r("p", "a.c", 16, "CWE-121", end=18),  # ends exactly tolerance before line 20
               _r("p", "a.c", 15, "CWE-121", end=17),  # ends tolerance + 1 before
               _r("p", "a.c", 55), _r("p", "a.c", 45), _r("p", "b.c", 1, "CWE-121")]
    report = score(key, reports)
    assert _producer(report, "p").outcomes == {"hit": 2, "location_hit_cwe_miss": 1, "location_hit_cwe_unknown": 1,
                                               "off_location": 2, "control": 1, "unattributed": 2}
    by_line = {case["id"]: case["outcomes"] for case in report.as_dict()["cases"]}
    assert by_line == {"x": {"p": {"hit": 2, "location_hit_cwe_miss": 1, "location_hit_cwe_unknown": 1,
                                   "off_location": 2}}, "y": {"p": {"control": 1}}}
    assert _producer(report, "p").lenient_tp == 1
    tight = score(key, [_r("p", "a.c", 22, "CWE-121"), _r("p", "a.c", 23, "CWE-121")], tolerance=0)
    assert _producer(tight, "p").outcomes["off_location"] == 2


def test_attribution_prefers_containing_scope_then_widened(tmp_path):
    key = _key(tmp_path, '[[defect]]\nid = "x"\ncwe = "CWE-78"\npath = "a.c"\nline = 10\nscope_start = 5\nscope_end = 10\n'
                         '[[control]]\nid = "y"\npath = "a.c"\nline = 12\nscope_start = 12\nscope_end = 20\n')
    report = score(key, [_r("p", "a.c", 11, "CWE-78"), _r("p", "a.c", 12, "CWE-78"), _r("p", "a.c", 1, end=3)])
    cases = {case["id"]: case["outcomes"] for case in report.as_dict()["cases"]}
    # Line 11 is in both widened scopes: the first in line order wins; line 12 lies in y's scope;
    # lines 1..3 start outside every widened scope but overlap x's widened scope 3..12.
    assert cases == {"x": {"p": {"hit": 1, "off_location": 1}}, "y": {"p": {"control": 1}}}


def test_cwe_match_is_one_way(tmp_path):
    table = load_cwe_match()
    assert "CWE-787" in table["CWE-121"] and "CWE-690" in table["CWE-476"]
    assert "CWE-690" not in table  # absent key: accepts only itself
    key = _key(tmp_path, '[[defect]]\nid = "x"\ncwe = "CWE-690"\npath = "a.c"\nline = 5\n'
                         '[[defect]]\nid = "z"\ncwe = "CWE-476"\npath = "b.c"\nline = 5\n')
    report = score(key, [_r("p", "a.c", 5, "CWE-476"), _r("p", "b.c", 5, "CWE-690")])
    cases = {case["id"]: case["outcomes"] for case in report.as_dict()["cases"]}
    assert cases == {"x": {"p": {"location_hit_cwe_miss": 1}}, "z": {"p": {"hit": 1}}}


def test_cwe_match_reference_covers_the_corpus_cwes():
    table = load_cwe_match()
    castle = {22, 78, 89, 125, 134, 190, 253, 327, 362, 369, 401, 415, 416, 476, 522, 617, 628, 674, 761, 770,
              787, 798, 822, 835, 843}
    assert {f"CWE-{n}" for n in castle | {121, 416, 476, 190, 134, 78, 798}} == set(table)
    assert all(cwe in accepted for cwe, accepted in table.items())
    document = json.loads(CWE_MATCH_REFERENCE.read_text(encoding="utf-8"))
    assert all(row["rationale"] for row in document["accepts"].values())


def test_scored_paths_filter_reports(tmp_path):
    key = _key(tmp_path, '[corpus]\nscored_paths = ["proj/case-1"]\n'
                         '[[defect]]\nid = "x"\ncwe = "CWE-78"\npath = "proj/case-1/a.c"\nline = 5\n')
    report = score(key, [_r("p", "proj/case-1/a.c", 5, "CWE-78"), _r("p", "proj/case-1/b.c", 5, "CWE-78"),
                         _r("p", "proj/case-10/a.c", 5, "CWE-78"), _r("p", "proj/case-2/a.c", 5, "CWE-78")])
    p = _producer(report, "p")
    assert (p.reports, p.tp, len(p.unattributed), report.ignored_reports) == (2, 1, 1, 2)
    with pytest.raises(ValueError, match="outside scored_paths"):
        _key(tmp_path, '[corpus]\nscored_paths = ["proj/case-1"]\n'
                       '[[defect]]\nid = "x"\ncwe = "CWE-78"\npath = "proj/case-2/a.c"\nline = 5\n', "other.toml")


def test_reports_with_one_identity_collapse(tmp_path):
    key = _key(tmp_path, '[[defect]]\nid = "x"\ncwe = "CWE-78"\npath = "a.c"\nline = 5\nscope_start = 1\nscope_end = 9\n')
    reports = [_r("p", "a.c", 5, "CWE-77", rule="cmd", evidence="obs-b"),
               _r("p", "a.c", 5, "CWE-20", rule="cmd", evidence="obs-a"),
               _r("p", "a.c", 5, rule="other")]
    report = score(key, reports)
    p = _producer(report, "p")
    # Two distinct identities: one hit (CWE-77 accepted for CWE-78) and one location_hit_cwe_unknown.
    assert (p.reports, p.tp, p.fp, p.castle_score) == (2, 1, 1, 5 - 1 + 4)
    collapsed = scoring._collapse(reports)
    merged = next(item for item in collapsed if item.rule == "cmd")
    assert merged.cwes == {"CWE-20", "CWE-77"} and merged.evidence == "obs-a"


# ------------------------------------------------------------------------------------ combinations

def test_combination_credits_true_positive_once_and_penalties_cumulatively(tmp_path):
    report = score(_key(tmp_path), ALPHA + BETA + GAMMA)
    scores = {item.producer: item.castle_score for item in report.producers}
    # beta: d1 5+5=10, d2 -1, c1 -1, c2 2. gamma: d1 0, d2 0, c1 2, c2 -1.
    assert scores == {"alpha": 16, "beta": 10, "gamma": 1}
    # Full set: d1 both hit, extras alpha 1 + beta 0 -> 5+5-1 = 9; d2 alpha hit, beta 1 extra -> 5+1-1 = 5;
    # c1 beta 1 -> -1; c2 alpha 1 + gamma 1 -> -2.
    assert report.full_set == {"producers": ["alpha", "beta", "gamma"], "castle_score": 11}
    assert [(item["size"], item["producers"], item["castle_score"]) for item in report.best_combinations] == [
        (1, ["alpha"], 16), (2, ["alpha", "gamma"], 15), (3, ["alpha", "beta", "gamma"], 11)]
    # alpha+beta = 12, alpha+gamma = 15, beta+gamma = 7.
    assert report.marginal == {"alpha": 11 - 7, "beta": 11 - 15, "gamma": 11 - 12}
    lines = render_lines(report)
    assert all(line.startswith("   scoring ") for line in lines)
    assert "   scoring marginal gamma=-1 net-negative" in lines and "   scoring marginal alpha=+4" in lines


def test_two_hitters_each_get_one_free_report(tmp_path):
    key = _key(tmp_path)
    both = [_r("alpha", "src/a.c", 10, "CWE-787"), _r("beta", "src/a.c", 14, "CWE-787")]
    report = score(key, both, max_combination=1)
    assert report.as_dict()["cases"][0]["hit_by"] == ["alpha", "beta"]
    # d1 5+5 with no extra; d2 0; c1 2; c2 2.
    assert report.full_set["castle_score"] == 10 + 4
    assert [item["size"] for item in report.best_combinations] == [1]


def test_combination_of_one_producer_equals_its_score(tmp_path):
    report = score(_key(tmp_path), ALPHA)
    assert report.full_set["castle_score"] == _producer(report, "alpha").castle_score == 16
    assert report.marginal == {"alpha": 16 - 4}  # without alpha only the silent floor remains


def test_producers_filter_lists_zero_report_producer(tmp_path):
    report = score(_key(tmp_path), ALPHA + BETA, producers=["Alpha", "delta"])
    assert [item.producer for item in report.producers] == ["alpha", "delta"]
    delta = _producer(report, "delta")
    assert (delta.reports, delta.castle_score, delta.tp, delta.fn, delta.tn, delta.fp) == (0, 4, 0, 2, 2, 0)
    assert (delta.precision, delta.recall, delta.accuracy) == (None, 0.0, 0.5)
    assert [item["producers"] for item in report.best_combinations] == [["alpha"]]
    assert report.marginal["delta"] == 0


def test_reference_comparison_rows(tmp_path):
    reference = {"paper_reference": [
        {"tool": "Alpha", "version": "1.0", "producer": "alpha", "tp": 1, "tn": 2, "fp": 3, "fn": 4, "castle_score": 5},
        {"tool": "Other", "version": "-", "producer": None, "tp": 0, "tn": 0, "fp": 0, "fn": 0, "castle_score": 0}]}
    report = score(_key(tmp_path), ALPHA, reference=reference)
    assert report.as_dict()["reference_comparison"] == [{
        "producer": "alpha",
        "paper": {"tool": "Alpha", "version": "1.0", "tp": 1, "tn": 2, "fp": 3, "fn": 4, "castle_score": 5},
        "ours": {"tp": 2, "tn": 1, "fp": 2, "fn": 0, "castle_score": 16}}]


def test_report_dict_is_json_and_deterministic(tmp_path):
    key = _key(tmp_path)
    first = score(key, ALPHA + BETA + GAMMA, gaps=["review_unavailable: x"]).as_dict()
    second = score(key, list(reversed(ALPHA + BETA + GAMMA)), gaps=["review_unavailable: x"]).as_dict()
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["schema"] == SCORING_SCHEMA and first["gaps"] == ["review_unavailable: x"]
    assert first["corpus"] == {"name": "mini", "tag": "mini-v1", "commit": "0123456789abcdef"}
    assert (first["tolerance"], first["top_list"], first["max_score"], first["floor_score"]) == (
        2, "castle-2025-table2", 20, 4)


# ------------------------------------------------------------------------------------- top lists

def test_top_lists_and_bonus():
    castle = load_top_list("castle-2025-table2")
    assert len(castle) == 18
    assert (bonus("CWE-787", castle), bonus("CWE-190", castle), bonus("CWE-253", castle)) == (5, 1, 0)
    assert (bonus("CWE-125", castle), bonus("CWE-134", castle), bonus("CWE-761", castle)) == (4, 3, 2)
    mitre = load_top_list("mitre-2024")
    assert len(mitre) == 25 and sorted(mitre.values()) == list(range(1, 26))
    assert (mitre["CWE-79"], mitre["CWE-306"], bonus("CWE-369", mitre), bonus("CWE-400", mitre)) == (1, 25, 0, 1)
    with pytest.raises(ValueError, match="unknown top list"):
        load_top_list("nope")


def test_top_list_changes_the_bonus(tmp_path):
    key = _key(tmp_path)
    assert score(key, [], top_list="mitre-2024").max_score == 20  # 787 rank 2 and 190 rank 23 in both lists
    v1 = load_scoring_key(REPO / DEFAULT_EXPECTATIONS)
    # MITRE 2024: 134 is unranked (B 3 -> 0) and 798 is rank 22 (B 3 -> 1); the other five agree.
    assert score(v1, [], top_list="mitre-2024").max_score == 51 - 3 - 2
    with pytest.raises(ValueError):
        score(key, [], top_list="nope")


# ------------------------------------------------------------------------------------------- CLI

def test_cli_json_with_fake_producer_reports(tmp_path, monkeypatch, capsys):
    run = tmp_path / "run"
    (run / "data").mkdir(parents=True)
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"paper_reference": [
        {"tool": "Beta", "version": "2", "producer": "beta", "tp": 9, "tn": 9, "fp": 9, "fn": 9, "castle_score": 99}]}),
        encoding="utf-8")
    key = tmp_path / "key.toml"
    key.write_text(MINI.replace('commit = "0123456789abcdef"',
                                f'commit = "0123456789abcdef"\nreference_lock = "{os.path.relpath(lock, REPO)}"'),
                   encoding="utf-8")
    calls = []

    def reports_from_run(run_root, *, include_review=False):
        calls.append((Path(run_root), include_review))
        return ALPHA + BETA, ["review_unavailable: no accepted final report"]

    fake = types.ModuleType("appsec_review.acceptance.producer_reports")
    fake.reports_from_run = reports_from_run
    monkeypatch.setitem(sys.modules, "appsec_review.acceptance.producer_reports", fake)
    code = scoring.main(["--run", str(run), "--expectations", str(key), "--include-review", "--producers", "alpha,beta",
                         "--max-combination", "2", "--json"])
    assert code == 0 and calls == [(run, True)]
    document = json.loads(capsys.readouterr().out)
    assert document["schema"] == SCORING_SCHEMA
    assert [item["producer"] for item in document["producers"]] == ["alpha", "beta"]
    assert document["full_set"]["castle_score"] == 12
    assert document["gaps"] == ["review_unavailable: no accepted final report"]
    assert [row["paper"]["castle_score"] for row in document["reference_comparison"]] == [99]
    assert scoring.main(["--run", str(run), "--expectations", str(key), "--producers", "gamma"]) == 0
    assert "   scoring gamma castle=4 " in capsys.readouterr().out
    assert scoring.main(["--run", str(tmp_path / "absent"), "--expectations", str(key)]) == 2


def test_report_outcome_vocabulary_is_complete(tmp_path):
    silent = score(_key(tmp_path), [])
    assert silent.as_dict()["producers"] == [] and silent.full_set["castle_score"] == silent.floor_score == 4
    alpha = _producer(score(_key(tmp_path), ALPHA), "alpha")
    assert set(alpha.outcomes) == {item.value for item in ReportOutcome}
