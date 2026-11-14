"""Original shard permissions for the gate/dossier audit verifier, not worker retrieval.

These are the indexed source families that ``collect_leads`` can reference in the
protected audit. Declaring their envelopes lets the existing ``selected_handoffs``
closure retain the review's exact admitted upstream pins; declarations alone do not
supply a producer or establish a read.
"""
from __future__ import annotations

from collections.abc import Sequence
from importlib import import_module

from appsec_review.runtime.contracts import InputRequirement, accepted_inputs


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


def original_audit_source_inputs(existing: Sequence[InputRequirement] = ()) -> tuple[InputRequirement, ...]:
    """Merge a bounded canonical selection, rejecting incompatible duplicate permissions."""
    requirements = list(existing)
    for producer, kinds in ORIGINAL_AUDIT_SOURCES:
        datasets = import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS
        requirements.extend(accepted_inputs(producer, datasets, output_kinds=kinds))
    merged: dict[tuple[str, str, str], InputRequirement] = {}
    for requirement in requirements:
        prior = merged.get(requirement.key)
        if prior is not None and prior != requirement:
            raise ValueError(f"conflicting original audit input: {requirement.producer}/{requirement.output_kind}")
        merged[requirement.key] = requirement
    return tuple(merged.values())


__all__ = ["ORIGINAL_AUDIT_SOURCES", "original_audit_source_inputs"]
