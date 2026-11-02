"""Every committed scoring key loads with the detector-scoring loader and keeps its pairing invariants."""

from __future__ import annotations

import json
from pathlib import Path

from appsec_review.acceptance import producer_reports
from appsec_review.acceptance.funnel import DEFAULT_EXPECTATIONS
from appsec_review.acceptance.scoring import load_scoring_key

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "test" / "acceptance"


def test_default_key_stays_the_v1_key_without_controls():
    key = load_scoring_key(ROOT / DEFAULT_EXPECTATIONS)
    assert key.corpus["tag"] == "cpp-multivuln-v1"
    assert (len(key.defects), len(key.controls)) == (7, 0)


def test_case_094_key_pairs_each_defect_with_one_control():
    key = load_scoring_key(ACCEPTANCE / "appsec-multi-vuln-c094-v1" / "expectations.toml")
    assert key.corpus["tag"] == "appsec-multi-vuln-c094-v1"
    assert key.scored_paths == ("projects/native/case-094",)
    assert (len(key.defects), len(key.controls)) == (7, 7)
    by_id = {entry.id: entry for entry in key.entries}
    for defect in key.defects:
        control = by_id[defect.pair]
        assert control.pair == defect.id and control.cwe == defect.cwe
    assert {d.cwe for d in key.defects} == {"CWE-121", "CWE-416", "CWE-476", "CWE-190", "CWE-134", "CWE-78",
                                            "CWE-798"}


def test_castle_key_is_file_scoped_over_25_cwes():
    key = load_scoring_key(ACCEPTANCE / "castle-c250-v1" / "expectations.toml")
    assert (len(key.defects), len(key.controls)) == (150, 100)
    assert all(entry.scope is None for entry in key.entries)
    assert len({entry.cwe for entry in key.entries}) == 25
    assert key.corpus["reference_lock"] == "data/reference/castle/castle-c250.lock.json"


def test_castle_reference_producers_are_names_the_run_reports_emit():
    lock = json.loads((ROOT / "data" / "reference" / "castle" / "castle-c250.lock.json").read_text("utf-8"))
    named = {row["producer"] for row in lock["paper_reference"]} - {None}
    payloads = {"codeql": {"producer": "codeql"}, "cppcheck": {"tool_id": "tool-cppcheck"},
                "semgrep": {"tool_id": "tool-semgrep"},
                "clang-static-analyzer": {"tool_id": "tool-clang-static-analysis", "scanner": "clang-static-analyzer"}}
    assert named <= set(payloads)
    assert {name: producer_reports.producer_name(payloads[name]) for name in named} == {n: n for n in named}