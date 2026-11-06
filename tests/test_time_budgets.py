"""Per-test time budgets for the integration and live tiers (tests/time_budgets.py, tests/conftest.py)."""

from __future__ import annotations

from pathlib import Path
import tomllib
from types import SimpleNamespace

import pytest

from tests import conftest, time_budgets


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
BUDGETS = {"integration": 300.0, "live": 1800.0}


def _report(when: str, duration: float, outcome: str = "passed") -> pytest.TestReport:
    return pytest.TestReport("tests/live/test_x.py::test_y", ("tests/live/test_x.py", 1, "test_y"), {},
                             outcome, None, when, duration=duration)


def _marker(*args, **kwargs):
    return SimpleNamespace(args=args, kwargs=kwargs)


@pytest.mark.parametrize(("relative", "tier"), [
    ("integration/test_a.py", "integration"),
    ("integration/signing/test_b.py", "integration"),
    ("live/test_c.py", "live"),
    ("test_live_d.py", "live"),
    ("test_unit.py", None),
    ("review/test_live_nested.py", None),
    ("acceptance/test_e.py", None),
])
def test_tier_follows_the_collection_boundary(relative: str, tier: str | None) -> None:
    assert time_budgets.tier_of(TESTS / relative, TESTS) == tier


def test_pyproject_declares_the_documented_defaults() -> None:
    options = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    declared = {tier: float(options[name]) for tier, name in time_budgets.TIER_INI_OPTIONS.items()}
    assert declared == dict(time_budgets.DEFAULT_TIER_BUDGETS) == BUDGETS


def test_tier_defaults_apply_and_unit_tests_have_none() -> None:
    assert time_budgets.budget_for("n", "integration", None, BUDGETS).seconds == 300.0
    assert time_budgets.budget_for("n", "live", None, BUDGETS).seconds == 1800.0
    assert time_budgets.budget_for("n", None, None, BUDGETS) is None


def test_a_declared_exception_replaces_the_default_and_records_its_reason() -> None:
    budget = time_budgets.budget_for("n", "live", _marker(14400, reason="full review"), BUDGETS)
    assert budget.seconds == 14400 and "full review" in budget.source


@pytest.mark.parametrize("marker", [
    _marker(60),
    _marker(60, reason=" "),
    _marker(reason="no seconds"),
    _marker(0, reason="zero"),
    _marker("soon", reason="not a number"),
    _marker(60, 70, reason="two values"),
], ids=["no-reason", "blank-reason", "no-seconds", "zero", "non-numeric", "two-values"])
def test_an_invalid_declaration_is_a_usage_error(marker) -> None:
    with pytest.raises(pytest.UsageError):
        time_budgets.budget_for("n", "integration", marker, BUDGETS)


def test_ini_values_are_parsed_and_validated() -> None:
    values = {"integration_time_budget_seconds": "120", "live_time_budget_seconds": "900"}
    assert time_budgets.tier_budgets(values.__getitem__) == {"integration": 120.0, "live": 900.0}
    with pytest.raises(pytest.UsageError, match="live_time_budget_seconds"):
        time_budgets.tier_budgets({**values, "live_time_budget_seconds": "-1"}.__getitem__)


def test_setup_and_call_over_budget_fails_the_call_with_both_times() -> None:
    clock = time_budgets.PhaseClock(time_budgets.TimeBudget(10, "live default"))
    clock.observe(_report("setup", 6))
    call = _report("call", 5)
    clock.observe(call)
    assert call.failed and "setup and call took 11.0s, budget 10s (live default)" in str(call.longrepr)


def test_teardown_that_crosses_the_budget_fails_the_teardown() -> None:
    clock = time_budgets.PhaseClock(time_budgets.TimeBudget(10, "d"))
    for when, seconds in (("setup", 2), ("call", 7)):
        report = _report(when, seconds)
        clock.observe(report)
        assert report.passed
    teardown = _report("teardown", 2)
    clock.observe(teardown)
    assert teardown.failed and "setup, call and teardown took 11.0s" in str(teardown.longrepr)


def test_within_budget_skipped_and_already_failed_tests_are_unchanged() -> None:
    within = time_budgets.PhaseClock(time_budgets.TimeBudget(10, "d"))
    call = _report("call", 9.5)
    within.observe(call)
    assert call.passed
    skipped = time_budgets.PhaseClock(time_budgets.TimeBudget(1, "d"))
    skip = _report("setup", 5, "skipped")
    skipped.observe(skip)
    assert skip.skipped
    failed = time_budgets.PhaseClock(time_budgets.TimeBudget(1, "d"))
    failed.observe(_report("call", 5, "failed"))
    teardown = _report("teardown", 5)
    failed.observe(teardown)
    assert teardown.passed


def test_the_report_hook_applies_the_item_budget() -> None:
    item = SimpleNamespace(stash=pytest.Stash())
    item.stash[conftest._PHASE_CLOCK] = time_budgets.PhaseClock(time_budgets.TimeBudget(1, "integration default"))
    hook = conftest.pytest_runtest_makereport(item, None)
    next(hook)
    with pytest.raises(StopIteration) as stopped:
        hook.send(_report("call", 2))
    assert stopped.value.value.failed
    unbudgeted = conftest.pytest_runtest_makereport(SimpleNamespace(stash=pytest.Stash()), None)
    next(unbudgeted)
    with pytest.raises(StopIteration) as untouched:
        unbudgeted.send(_report("call", 2))
    assert untouched.value.value.passed
