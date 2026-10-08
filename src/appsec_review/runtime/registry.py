from __future__ import annotations

from collections.abc import Callable

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


def builtin_registry() -> JobRegistry:
    from appsec_review.inference import ClaudeCliModelClient
    from appsec_review.jobs.job_review_intake import build_job as build_intake
    from appsec_review.jobs.job_target_catalog import build_job as build_catalog
    from appsec_review.jobs.job_target_analysis_plan import build_job as build_analysis_plan
    from appsec_review.jobs.job_third_party_data_sync import build_job as build_sync
    from appsec_review.jobs.job_evidence_collection import build_job as build_evidence
    from appsec_review.jobs.job_ci_configuration_analysis import build_job as build_ci_configuration_analysis
    from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp_compiled
    from appsec_review.jobs.job_post_build_security_assessment import build_job as build_post_build_security
    from appsec_review.jobs.job_owasp_control_assessment import build_job as build_owasp_control_assessment

    registry = JobRegistry()
    registry.register("job_review_intake", build_intake)
    registry.register("job_target_catalog", build_catalog)
    registry.register("job_target_analysis_plan",
                      lambda: build_analysis_plan(model_client=ClaudeCliModelClient()))
    registry.register("job_third_party_data_sync", build_sync)
    registry.register("job_evidence_collection", build_evidence)
    registry.register("job_ci_configuration_analysis", build_ci_configuration_analysis)
    registry.register("job_cpp_compiled_analysis", build_cpp_compiled)
    registry.register("job_post_build_security_assessment", build_post_build_security)
    registry.register("job_owasp_control_assessment", build_owasp_control_assessment)
    return registry
