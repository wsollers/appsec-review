"""First-party scoping of the graph producers (T-5016): one source-disposition table per run.

``job_tree_sitter_ast``, ``job_cpp_symbol_index``, ``job_codeql_analysis`` and ``job_code_graph_index``
spend their node, symbol and fact budgets on first-party files first and record every non-first-party
exclusion as a count. They read the T-165 dispositions
(``[jobs.job_inference_security_review.settings.source_dispositions]``, ``review/dispositions.py``);
the loader copies that table into each producer's ``settings.source_dispositions`` unless the producer
names an identical table itself, so a run freezes exactly one classification. A producer table that
differs from the review's fails loading: two disposition tables in one run would make the graph and the
review disagree about what first-party means.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from appsec_review.review.dispositions import SourceDispositions

REVIEW_TABLE = "jobs.job_inference_security_review.settings.source_dispositions"
FIRST_PARTY_SCOPED_JOBS = ("job_codeql_analysis", "job_code_graph_index", "job_cpp_symbol_index",
                           "job_tree_sitter_ast")


def resolve_job_dispositions(job_id: str, value: object, inherited: object) -> dict[str, list[str]]:
    """The resolved ``source_dispositions`` table of one scoped producer (without the rule id)."""
    prefix = f"jobs.{job_id}.settings.source_dispositions"
    review = SourceDispositions.from_mapping(inherited, REVIEW_TABLE) if inherited is not None else None
    if value is not None:
        own = SourceDispositions.from_mapping(value, prefix)
        if review is not None and own != review:
            raise ValueError(f"{prefix} must equal {REVIEW_TABLE}")
        typed = own
    else:
        typed = review if review is not None else SourceDispositions()
    return {key: list(item) for key, item in typed.record().items() if key != "rule"}


def job_dispositions(settings: Mapping[str, Any] | None) -> SourceDispositions:
    """The typed dispositions a scoped producer reads from its frozen job settings."""
    value = (settings or {}).get("source_dispositions") if settings is not None else None
    return SourceDispositions.from_mapping(value, "settings.source_dispositions")


__all__ = ["FIRST_PARTY_SCOPED_JOBS", "REVIEW_TABLE", "job_dispositions", "resolve_job_dispositions"]
