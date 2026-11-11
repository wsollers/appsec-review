"""Which jobs still report free-text gaps. The list only shrinks; a new job must report producer-gap/1."""
from __future__ import annotations

import pytest

from appsec_review.runtime.registry import builtin_registry

# Jobs whose units still emit free-text or ad-hoc gap records. Each entry is debt: converting a job
# means emitting appsec_review.interchange.producer_gap(...) records and setting strict_gaps=True on
# its Job, then deleting it here. Adding a job to this list is not allowed.
LEGACY_FREE_TEXT_GAPS = frozenset({
    "job_artifact_indexing", "job_artifact_security_analysis", "job_binary_evidence_indexing",
    "job_change_context_analysis",
    "job_clang_static_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpg_analysis",
    "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_debug_symbol_indexing",
    "job_dependency_intelligence", "job_document_issue_analysis", "job_dossier_publication",
    "job_evidence_collection", "job_final_publication_gate", "job_final_report_publication",
    "job_inference_security_review", "job_language_build", "job_openvex_export",
    "job_owasp_control_assessment", "job_poc_generation", "job_post_build_security_assessment",
    "job_profile_data", "job_remediation_planning", "job_remediation_validation",
    "job_review_data_indexing", "job_review_package_assembly",
    "job_review_prioritization", "job_sanitizer_build", "job_security_tagging", "job_source_history_analysis",
    "job_svf_alias_analysis", "job_target_analysis_plan", "job_target_catalog",
    "job_test_coverage", "job_tree_sitter_ast",
})


def test_every_registered_job_is_strict_or_explicitly_listed_as_legacy() -> None:
    registry = builtin_registry()
    lenient = {job_id for job_id in registry.job_ids() if not registry.build(job_id).strict_gaps}
    assert lenient == LEGACY_FREE_TEXT_GAPS, (
        f"converted (remove from list): {sorted(LEGACY_FREE_TEXT_GAPS - lenient)}; "
        f"new lenient jobs (not allowed): {sorted(lenient - LEGACY_FREE_TEXT_GAPS)}")


@pytest.mark.parametrize("job_id", sorted({"job_image_pin_verification", "job_model_connectivity",
                                          "job_build_iteration", "job_third_party_data_sync",
                                          "job_build_environment_analysis", "job_ci_configuration_analysis"}))
def test_converted_jobs_reject_free_text_gaps(job_id: str) -> None:
    assert builtin_registry().build(job_id).strict_gaps is True
