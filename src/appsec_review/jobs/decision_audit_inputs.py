"""Original shard permissions for the gate/dossier audit verifier, not worker retrieval.

These are the indexed source families that ``collect_leads`` can reference in the
protected audit. Declaring their envelopes lets the existing ``selected_handoffs``
closure retain the review's exact admitted upstream pins; declarations alone do not
supply a producer or establish a read.
"""
from __future__ import annotations

from collections.abc import Sequence

from appsec_review.jobs.job_artifact_security_analysis import datasets as _artifact_security
from appsec_review.jobs.job_ci_configuration_analysis import datasets as _ci_configuration
from appsec_review.jobs.job_clang_static_analysis import datasets as _clang_static
from appsec_review.jobs.job_codeql_analysis import datasets as _codeql
from appsec_review.jobs.job_cpp_compiled_analysis import datasets as _cpp_compiled
from appsec_review.jobs.job_evidence_collection import datasets as _evidence_collection
from appsec_review.jobs.job_post_build_security_assessment import datasets as _post_build_security
from appsec_review.jobs.job_review_data_indexing import datasets as _review_data_indexing
from appsec_review.runtime.contracts import InputRequirement, accepted_inputs


# Static imports on purpose: a computed ``import_module`` here would make the implementation identity
# of every job that imports this module depend on the whole shared closure (runtime/release.py walk).
ORIGINAL_AUDIT_SOURCES = (
    ("job_artifact_security_analysis", ("artifact_security_observations",)),
    ("job_ci_configuration_analysis", ("ci_observations",)),
    ("job_clang_static_analysis", ("clang_static_observations",)),
    ("job_codeql_analysis", ("codeql_observations",)),
    ("job_cpp_compiled_analysis", ("infer_observations",)),
    ("job_evidence_collection", ("static_tool_observations",)),
    ("job_post_build_security_assessment", ("build_security",)),
    ("job_review_data_indexing", ("precomputed_products",)),
)
_DATASETS = {
    "job_artifact_security_analysis": _artifact_security.DATASETS,
    "job_ci_configuration_analysis": _ci_configuration.DATASETS,
    "job_clang_static_analysis": _clang_static.DATASETS,
    "job_codeql_analysis": _codeql.DATASETS,
    "job_cpp_compiled_analysis": _cpp_compiled.DATASETS,
    "job_evidence_collection": _evidence_collection.DATASETS,
    "job_post_build_security_assessment": _post_build_security.DATASETS,
    "job_review_data_indexing": _review_data_indexing.DATASETS,
}


def original_audit_source_inputs(existing: Sequence[InputRequirement] = ()) -> tuple[InputRequirement, ...]:
    """Merge a bounded canonical selection, rejecting incompatible duplicate permissions."""
    requirements = list(existing)
    for producer, kinds in ORIGINAL_AUDIT_SOURCES:
        requirements.extend(accepted_inputs(producer, _DATASETS[producer], output_kinds=kinds))
    merged: dict[tuple[str, str, str], InputRequirement] = {}
    for requirement in requirements:
        prior = merged.get(requirement.key)
        if prior is not None and prior != requirement:
            raise ValueError(f"conflicting original audit input: {requirement.producer}/{requirement.output_kind}")
        merged[requirement.key] = requirement
    return tuple(merged.values())


__all__ = ["ORIGINAL_AUDIT_SOURCES", "original_audit_source_inputs"]
