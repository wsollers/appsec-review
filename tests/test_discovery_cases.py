"""Build discovery cases: test/discovery/cases/<NNN>-<slug>/{tree, expect.json}.

One test per check per case (docs/plans/build-discovery-test-program-2026-11-08.md §2–3). A check
listed in the case's ``pending`` is a strict xfail: it must fail until the behaviour lands, and the
pending entry must be removed when it passes. Everything else is a hard assertion. Fast: discovery
over small committed trees, no Docker, no model, no network.
"""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from appsec_review.acceptance.discovery import CASE_SCHEMA, evaluate_case, pending_refs

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "test" / "discovery" / "cases"
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "discovery-case.schema.json").read_text(encoding="utf-8"))
CASE_DIRS = sorted(path for path in CASES.iterdir() if path.is_dir() and (path / "expect.json").is_file())


def _evaluate_all() -> list[tuple[str, str, bool, str, str | None]]:
    rows = []
    for case_dir in CASE_DIRS:
        expect, checks = evaluate_case(case_dir)
        pending = pending_refs(expect)
        for check in checks:
            rows.append((case_dir.name, check.id, check.ok, check.detail, pending.get(check.id)))
    return rows


_ROWS = _evaluate_all()


def test_there_are_cases_and_each_directory_has_a_tree_and_an_expectation() -> None:
    assert CASE_DIRS, "no discovery cases"
    for path in sorted(CASES.iterdir()):
        if path.is_dir():
            assert (path / "tree").is_dir(), f"{path.name}: missing tree/"
            assert (path / "expect.json").is_file(), f"{path.name}: missing expect.json"
            assert path.name == json.loads((path / "expect.json").read_text(encoding="utf-8"))["case"]


@pytest.mark.parametrize("case_dir", CASE_DIRS, ids=[path.name for path in CASE_DIRS])
def test_expectation_validates_against_the_case_schema(case_dir: Path) -> None:
    expect = json.loads((case_dir / "expect.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(SCHEMA)
    Draft202012Validator(SCHEMA).validate(expect)
    assert expect["schema"] == CASE_SCHEMA
    checks = {check for _case, check, *_rest in _ROWS if _case == case_dir.name}
    for item in expect.get("pending", []):
        assert item["check"] in checks, f"{case_dir.name}: pending names an unknown check {item['check']!r}"


@pytest.mark.parametrize("case,check,ok,detail,pending", _ROWS,
                         ids=[f"{case}::{check}" for case, check, *_rest in _ROWS])
def test_discovery_case_check(case: str, check: str, ok: bool, detail: str, pending: str | None) -> None:
    if pending is not None:
        if ok:
            pytest.fail(f"{case}: {check} now passes; remove its pending entry ({pending})")
        pytest.xfail(f"{case}: {check} pending {pending}: {detail}")
    assert ok, f"{case}: {check}: {detail}"
