"""Dataset publication declarations for job_ci_configuration_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_ci_configuration_analysis/attempts/*"
DATASETS = (
    indexed("ci_observations", "ci_observation_publication", "ci", "appsec-review/retrieval-index/2",
            "Normalized CI observations with provider, workflow, job and step hierarchy.",
            indexes=("observations",), prefixes=("ci_",),
            route="query_ci_configuration; query_precomputed query_set=ci_trust"),
    indexed("ci_findings", "ci_correlation", "ci", "appsec-review/retrieval-index/2",
            "Canonical CI findings correlated across tools.",
            indexes=("evidence",), prefixes=("ci_findings",), route="query_ci_configuration canonical_finding"),
    artifact_only("ci_documents", "ci_coverage", "ci", "appsec-review/ci-configuration-analysis-handoff/1",
                  "CI definitions, classifications, normalized observations, hierarchy and coverage.",
                  artifacts=(_A + "/artifacts/ci/*/*.json",),
                  reason="same redacted records as the CI observation and finding shards"),
    protected("ci_tool_io", "ci_analysis", "ci", "appsec-review/container-execution/1",
              "Raw CI linter output and streams.",
              artifacts=(_A + "/steps/ci_analysis/tasks/*/scratch/**",), reason=RAW),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_target_catalog", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_target_catalog", "target_artifact_inputs",
                         "appsec-review/target-artifact-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "source_files",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "declaration_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "components",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "target_documents",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "build_units",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_target_catalog", "catalog_documents",
                         "appsec-review/target-catalog/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_target_catalog',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
