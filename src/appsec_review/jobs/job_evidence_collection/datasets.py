"""Dataset publication declarations for job_evidence_collection.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_evidence_collection/attempts/*"
CONSUMES = ('job_target_catalog', 'job_review_intake', 'job_target_analysis_plan')
DATASETS = (
    indexed("static_tool_observations", "evidence_publication", "scanner_findings",
            "appsec-review/retrieval-index/2",
            "Normalized static-tool observations, one shard per tool, including software inventory and "
            "vulnerability matches.",
            indexes=("observations",),
            route="find/search index=observations; query_precomputed query_set=scanner_correlation"),
    artifact_only("static_tool_evidence", "evidence_publication", "scanner_findings",
                  "appsec-review/static-tool-evidence/2",
                  "Normalized per-tool evidence documents, checkpoints and the evidence handoff.",
                  artifacts=(_A + "/steps/*/tasks/*/evidence.json", _A + "/steps/*/tasks/*/handoff.json",
                             "data/task-checkpoints/job_evidence_collection/**"),
                  reason="same normalized records as the per-tool observation shards"),
    protected("static_tool_io", "source_sast", "scanner_findings", "appsec-review/container-execution/1",
              "Raw scanner output, staged inputs, SBOMs and execution streams.",
              artifacts=(_A + "/steps/*/tasks/*/scratch/**", _A + "/steps/*/tasks/*/inputs/**",
                         _A + "/steps/vulnerability_matching/tasks/osv_scanner_scan/osv-scanner-merged.json"),
              reason="raw scanner output can contain secret matches and unbounded target content"),
)
