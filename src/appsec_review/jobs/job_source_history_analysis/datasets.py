"""Dataset publication declarations for job_source_history_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_source_history_analysis/attempts/*"
DATASETS = (
    indexed("history_signals", "publish", "history", "appsec-review/retrieval-index/2",
            "Change, file, symbol and component history signals and SII hotspots with pseudonymous authors, "
            "and separately labelled change-log file signals.",
            indexes=("history",), prefixes=("git-history",),
            route="find/search/trace index=history; query_precomputed query_set=history_context", authority=EvidenceAuthority.ROUTING_CONTEXT),
    artifact_only("history_documents", "publish", "history", "appsec-review/source-history-analysis/2",
                  "Normalized changes, classification, signals, line history, symbol spans, hotspots and "
                  "change-log signals (source: changelog, no names, addresses or message text).",
                  artifacts=(_A + "/steps/*/tasks/*/artifacts/*.json",
                             _A + "/steps/*/tasks/*/sources/*/artifacts/*.json",),
                  reason="normalized inputs of the history shard; full per-change lists exceed retrieval bounds", authority=EvidenceAuthority.ROUTING_CONTEXT),
    protected("raw_git_history", "acquire", "history", "application/octet-stream",
              "Raw git log and commit messages, including author e-mail addresses.",
              artifacts=(_A + "/steps/acquire/tasks/git_history/protected/*",
                         _A + "/steps/acquire/tasks/git_history/sources/*/protected/*",),
              reason="raw author identities and commit message text; only pseudonyms and classifications are indexed", authority=EvidenceAuthority.ROUTING_CONTEXT),
    protected("history_tool_io", "analyze", "history", "appsec-review/container-execution/1",
              "Git and parser container scratch, including blame output and raw patches.",
              artifacts=(_A + "/steps/*/tasks/*/scratch/**",
                         _A + "/steps/*/tasks/*/sources/*/scratch/**",), reason=RAW, authority=EvidenceAuthority.ROUTING_CONTEXT),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_review_intake", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_review_intake", "model_preflight",
                         "appsec-review/model-preflight/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "binary_evidence",
                         "appsec-review/binary-evidence-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "review_intake",
                         "appsec-review/review-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
