from __future__ import annotations

from collections.abc import Callable, Iterable

from appsec_review.runtime.job import Job

JobFactory = Callable[[], Job]


class JobRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, JobFactory] = {}

    def register(self, job_id: str, factory: JobFactory) -> None:
        if job_id in self._factories:
            raise ValueError(f"job already registered: {job_id}")
        self._factories[job_id] = factory

    def build(self, job_id: str) -> Job:
        try:
            job = self._factories[job_id]()
        except KeyError as exc:
            raise KeyError(f"job is not registered: {job_id}") from exc
        if job.job_id != job_id:
            raise ValueError(f"registered job id mismatch: {job.job_id} != {job_id}")
        return job

    def job_ids(self) -> tuple[str, ...]:
        """Return registered semantic job ids in deterministic order."""

        return tuple(sorted(self._factories))

    def require_matches(self, configured: Iterable[str], *, surface: str) -> None:
        """Refuse to run when the configured jobs and the registered jobs differ."""

        registered, configured = set(self._factories), set(configured)
        if registered != configured:
            raise ValueError(
                f"{surface} job/config mismatch: "
                f"missing_config={sorted(registered - configured)}, "
                f"missing_registration={sorted(configured - registered)}"
            )


def builtin_registry() -> JobRegistry:
    from appsec_review.inference import check_models, infer as live_infer
    from appsec_review.inference.recording import recorded
    from appsec_review.jobs.job_model_connectivity import build_job as build_model_connectivity
    from appsec_review.container_runtime.build_executor import _run as run_command
    from appsec_review.jobs.job_image_pin_verification import build_job as build_image_pin_verification
    from appsec_review.jobs.job_target_acquisition import build_job as build_target_acquisition
    from appsec_review.jobs.job_review_intake import build_job as build_intake
    from appsec_review.jobs.job_target_catalog import build_job as build_catalog
    from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan
    from appsec_review.jobs.job_source_history_analysis import build_job as build_source_history
    from appsec_review.jobs.job_change_context_analysis import build_job as build_change_context
    from appsec_review.jobs.job_tree_sitter_ast import build_job as build_tree_sitter_ast
    from appsec_review.jobs.job_project_build import build_job as build_project_build
    from appsec_review.jobs.job_language_build import build_job as build_language_build
    from appsec_review.jobs.job_artifact_indexing import build_job as build_artifact_indexing
    from appsec_review.jobs.job_test_coverage import build_job as build_test_coverage
    from appsec_review.jobs.job_profile_data import build_job as build_profile_data
    from appsec_review.jobs.job_artifact_security_analysis import build_job as build_artifact_security_analysis
    from appsec_review.jobs.job_third_party_data_sync import build_job as build_sync
    from appsec_review.jobs.job_evidence_collection import build_job as build_evidence
    from appsec_review.jobs.job_dependency_intelligence import build_job as build_dependency_intelligence
    from appsec_review.jobs.job_ci_configuration_analysis import build_job as build_ci_configuration_analysis
    from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp_compiled
    from appsec_review.jobs.job_clang_static_analysis import build_job as build_clang_static_analysis
    from appsec_review.jobs.job_svf_alias_analysis import build_job as build_svf_alias_analysis
    from appsec_review.jobs.job_sanitizer_build import build_job as build_sanitizer_build
    from appsec_review.jobs.job_cpp_symbol_index import build_job as build_cpp_symbol_index
    from appsec_review.jobs.job_binary_evidence_indexing import build_job as build_binary_evidence_indexing
    from appsec_review.jobs.job_cpg_analysis import build_job as build_cpg_analysis
    from appsec_review.jobs.job_codeql_analysis.job import build_job as build_codeql_analysis
    from appsec_review.jobs.job_code_graph_index import build_job as build_code_graph_index
    from appsec_review.jobs.job_post_build_security_assessment import build_job as build_post_build_security
    from appsec_review.jobs.job_owasp_control_assessment import build_job as build_owasp_control_assessment
    from appsec_review.jobs.job_security_tagging import build_job as build_security_tagging
    from appsec_review.jobs.job_review_prioritization import build_job as build_review_prioritization
    from appsec_review.jobs.job_review_data_indexing import build_job as build_review_data_indexing
    from appsec_review.jobs.job_review_package_assembly import build_job as build_review_package_assembly
    from appsec_review.jobs.job_document_issue_analysis import build_job as build_document_issue_analysis
    from appsec_review.jobs.job_inference_security_review import build_job as build_inference_review
    from appsec_review.jobs.job_final_publication_gate import build_job as build_final_publication_gate
    from appsec_review.jobs.job_openvex_export.job import build_job as build_openvex_export
    from appsec_review.jobs.job_poc_generation import build_job as build_poc_generation
    from appsec_review.jobs.job_final_report_publication import build_job as build_final_report_publication

    # Parity walks record and replay model responses here (docs/processes/local-dagster-parity.md).
    infer = recorded(live_infer)
    registry = JobRegistry()
    registry.register("job_model_connectivity", lambda: build_model_connectivity(check_models=check_models))
    registry.register("job_image_pin_verification", lambda: build_image_pin_verification(runner=run_command))
    registry.register("job_target_acquisition", build_target_acquisition)
    registry.register("job_review_intake", lambda: build_intake(check_models=check_models))
    registry.register("job_target_catalog", build_catalog)
    registry.register("job_source_history_analysis", build_source_history)
    registry.register("job_change_context_analysis", build_change_context)
    registry.register("job_target_analysis_plan",
                      lambda: build_analysis_plan(infer=infer))
    registry.register("job_tree_sitter_ast", build_tree_sitter_ast)
    registry.register("job_project_build",
                      lambda: build_project_build(infer=infer))
    registry.register("job_language_build", build_language_build)
    registry.register("job_artifact_indexing", build_artifact_indexing)
    registry.register("job_test_coverage", build_test_coverage)
    registry.register("job_profile_data", build_profile_data)
    registry.register("job_artifact_security_analysis", build_artifact_security_analysis)
    registry.register("job_third_party_data_sync", build_sync)
    registry.register("job_evidence_collection", build_evidence)
    registry.register("job_dependency_intelligence", lambda: build_dependency_intelligence(infer=infer))
    registry.register("job_ci_configuration_analysis", build_ci_configuration_analysis)
    registry.register("job_cpp_compiled_analysis", build_cpp_compiled)
    registry.register("job_clang_static_analysis", build_clang_static_analysis)
    registry.register("job_svf_alias_analysis", build_svf_alias_analysis)
    registry.register("job_sanitizer_build", build_sanitizer_build)
    registry.register("job_cpp_symbol_index", build_cpp_symbol_index)
    registry.register("job_binary_evidence_indexing", build_binary_evidence_indexing)
    registry.register("job_cpg_analysis", build_cpg_analysis)
    registry.register("job_codeql_analysis", build_codeql_analysis)
    registry.register("job_code_graph_index", build_code_graph_index)
    registry.register("job_post_build_security_assessment",
                      lambda: build_post_build_security(infer=infer))
    registry.register("job_owasp_control_assessment", build_owasp_control_assessment)
    registry.register("job_security_tagging", build_security_tagging)
    registry.register("job_review_prioritization", build_review_prioritization)
    registry.register("job_review_data_indexing", build_review_data_indexing)
    registry.register("job_review_package_assembly", build_review_package_assembly)
    registry.register("job_document_issue_analysis", build_document_issue_analysis)
    registry.register("job_inference_security_review", lambda: build_inference_review(infer=infer))
    registry.register("job_final_publication_gate", build_final_publication_gate)
    registry.register("job_openvex_export", build_openvex_export)
    registry.register("job_poc_generation", lambda: build_poc_generation(infer=infer))
    registry.register("job_final_report_publication", build_final_report_publication)
    return registry
