from __future__ import annotations

from scripts.docs_support import authored_job_errors, with_frontmatter


def page(body: str) -> str:
    return with_frontmatter({
        "title": "Fixture", "kind": "operations", "subsystem": "runtime interchange",
        "status": "current", "jobs": ["job_fixture"], "last reconciled": "a" * 40,
    }, body)


def job() -> dict:
    return {"steps": {"read": {}}, "model_configuration": {}, "specialized_workers": {}}


def complete() -> str:
    return page("""
# Fixture

## Purpose
Read a bounded fixture without claiming target coverage.

<!-- generated:begin job=job_fixture -->
## Declared job contract
Generated content is not an authored explanation.
<!-- generated:end -->

## Process
### `read`
1. Read the accepted fixture and reject a missing identity.

## Dataflow
```mermaid
flowchart LR
  job["job_fixture"] --> result["fixture"]
```

## Gaps
A missing input prevents publication; it is not an empty success.

## Acceptance
1. **A. Inputs:** Compare the input identity with the admitted fixture.
2. **B. Independent comparison:** Compare the returned count with an independent fixture count.
3. **C. Gaps:** Reconcile canonical outcomes with the walk's expected causes.
4. **D. Baseline:** Record the accepted baseline and compare it on the next authorized run.

## Resume and invalidation
A changed fixture identity invalidates reuse.
""")


def test_every_job_has_its_authored_contract(doc_pages, doc_inventory) -> None:
    errors = []
    for job_id in doc_inventory["job_order"]:
        row = doc_inventory["jobs"][job_id]
        errors.extend(f"{row['page']}: {error}"
                      for error in authored_job_errors(doc_pages[row["page"]], job_id, row))
    assert not errors, "\n".join(errors)


def test_generated_sections_cannot_substitute_for_authored_sections() -> None:
    text = page("<!-- generated:begin job=job_fixture -->\n## Purpose\nNot authored.\n<!-- generated:end -->")
    errors = authored_job_errors(text, "job_fixture", job())
    assert "missing authored section: Purpose" in errors
    assert "missing authored section: Acceptance" in errors


def test_complete_page_and_exact_step_coverage() -> None:
    assert authored_job_errors(complete(), "job_fixture", job()) == []
    changed = complete().replace("### `read`", "### `invented`")
    assert "Process must have one exact step heading per configured step" in authored_job_errors(
        changed, "job_fixture", job())


def test_model_backed_page_requires_model_usage_explanation() -> None:
    model_job = {**job(), "model_configuration": {"model": {"model": "fixture"}}}
    assert "missing authored section: Model usage" in authored_job_errors(
        complete(), "job_fixture", model_job)


def test_each_acceptance_check_is_required() -> None:
    text = complete().replace("**B. Independent comparison:**", "**Comparison:**")
    assert "Acceptance must state the charter check: B. Independent comparison" in authored_job_errors(
        text, "job_fixture", job())
