from __future__ import annotations

import pytest

from scripts.docs_support import identifier_errors, with_frontmatter


def document(body: str, *, status: str = "current") -> str:
    return with_frontmatter({
        "title": "Fixture", "kind": "architecture", "subsystem": "runtime interchange",
        "status": status, "last reconciled": "a" * 40,
    }, body)


def inventory() -> dict:
    return {"identifiers": {
        "jobs": ["job_fixture"], "tasks": ["step.task"], "datasets": ["output"],
        "schemas": ["fixture/1"], "gaps": ["input_unavailable"],
        "fields_and_functions": ["job_id"],
    }}


def test_current_prose_identifiers_resolve(doc_pages, doc_inventory) -> None:
    errors = []
    for path, text in sorted(doc_pages.items()):
        errors.extend(f"{path}: {error}" for error in identifier_errors(
            text, doc_inventory, planning_registry=path == "docs/TODO.md"))
    assert not errors, "\n".join(errors)


@pytest.mark.parametrize("body", [
    "`job_typo`", "task `step.typo`", "dataset `typo`", "schema `typo/99`",
    "gap cause `typo`",
], ids=["job", "task", "dataset", "schema", "gap"])
def test_unknown_current_identifier_fails(body) -> None:
    assert identifier_errors(document(body), inventory())


def test_declared_fields_and_valid_identifiers_are_not_job_typos() -> None:
    body = "`job_id` and `job_fixture`; task `step.task`; dataset `output`; schema `fixture/1`."
    assert identifier_errors(document(body), inventory()) == []


def test_historical_and_planning_records_preserve_retired_identifiers() -> None:
    assert identifier_errors(document("`job_old`", status="historical"), inventory()) == []
    assert identifier_errors(document("`job_future`"), inventory(), planning_registry=True) == []
    assert identifier_errors(document("`job_future`"), inventory())


def test_historical_passage_does_not_exempt_current_claims() -> None:
    body = "<!-- historical:begin -->`job_old`<!-- historical:end -->\nCurrent: `job_typo`."
    assert identifier_errors(document(body), inventory()) == ["unknown jobs identifier: job_typo"]


@pytest.mark.parametrize("body", [
    "<!-- historical:begin -->`job_old`",
    "<!-- historical:end -->",
    "<!-- historical:begin --><!-- historical:begin --><!-- historical:end --><!-- historical:end -->",
], ids=["unclosed", "unopened", "nested"])
def test_malformed_historical_markers_fail(body) -> None:
    with pytest.raises(ValueError, match="historical markers"):
        identifier_errors(document(body), inventory())


def test_code_examples_are_not_current_prose() -> None:
    assert identifier_errors(document("```text\n`job_example`\n```\n"), inventory()) == []


def test_quoted_historical_markers_do_not_hide_current_claims() -> None:
    body = "`<!-- historical:begin -->` example; current `job_typo`; `<!-- historical:end -->`."
    assert identifier_errors(document(body), inventory()) == ["unknown jobs identifier: job_typo"]


def test_double_backtick_identifiers_are_checked() -> None:
    assert identifier_errors(document("``job_typo``"), inventory()) == ["unknown jobs identifier: job_typo"]
