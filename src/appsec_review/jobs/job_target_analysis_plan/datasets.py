"""Dataset publication declarations for job_target_analysis_plan.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_target_analysis_plan/attempts/*"
CONSUMES = ('job_target_catalog', 'job_source_history_analysis')
DATASETS = (
    indexed("analysis_plan", "plan_acceptance", "analysis_plan", "appsec-review/retrieval-index/2",
            "Accepted components, scanner selections and planned build actions.",
            indexes=("analysis",), prefixes=("target-analysis-plan",),
            route="find/search/trace index=analysis shard=target-analysis-plan", required=True),
    artifact_only("analysis_plan_documents", "plan_acceptance", "analysis_plan",
                  "appsec-review/target-analysis-plan/1", "Catalog summary and accepted analysis plan documents.",
                  artifacts=(_A + "/artifacts/analysis-plan/*.json",),
                  reason="source documents of the analysis-plan shard; accepted recipes carry exact commands",
                  sensitivity="sensitive"),
    protected("planning_model_transcripts", "analysis_decisions", "analysis_plan", "text/plain",
              "Raw model responses for build-recipe proposals.",
              artifacts=(_A + "/steps/analysis_decisions/tasks/resolve_ambiguity/model-response-*.txt",),
              reason="raw model output must never enter retrieval; only validated plan facts are indexed"),
)
