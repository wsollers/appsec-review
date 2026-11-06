"""Dataset publication declarations for job_change_context_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_change_context_analysis/attempts/*"
DATASETS = (
    indexed("change_context", "publish", "change_context", "appsec-review/retrieval-index/2",
            "Ranked change-context signals, changes, review units and deployment events.",
            indexes=("history",), prefixes=("change-context",),
            route="query_change_context; query_precomputed query_set=history_context", authority=EvidenceAuthority.ROUTING_CONTEXT),
    artifact_only("change_context_documents", "publish", "change_context",
                  "appsec-review/change-context-analysis/1",
                  "Attribution, change records, unit signals and ranking documents.",
                  artifacts=(_A + "/steps/*/tasks/*/artifacts/*.json",
                             _A + "/steps/*/tasks/*/sources/*/artifacts/*.json",),
                  reason="normalized inputs of the change-context shard; pseudonym maps are never indexed",
                  sensitivity="sensitive", authority=EvidenceAuthority.ROUTING_CONTEXT),
    protected("operator_exports", "load", "change_context", "application/json",
              "Verbatim operator review, deployment and organization exports.",
              artifacts=(_A + "/steps/load/tasks/external_sources/artifacts/inputs/*",
                         _A + "/steps/load/tasks/external_sources/sources/*/artifacts/inputs/*",),
              reason="unredacted operator-supplied records; only normalized bounded facts are indexed", authority=EvidenceAuthority.ROUTING_CONTEXT),
    protected("change_context_tool_io", "attribute", "change_context", "appsec-review/container-execution/1",
              "Git blame and diff container scratch.",
              artifacts=(_A + "/steps/*/tasks/*/scratch/**",
                         _A + "/steps/*/tasks/*/sources/*/scratch/**",), reason=RAW, authority=EvidenceAuthority.ROUTING_CONTEXT),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_source_history_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "history_signals",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "history_documents",
                         "appsec-review/source-history-analysis/2", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "raw_git_history",
                         "application/octet-stream", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_source_history_analysis", "history_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.ROUTING_CONTEXT),
        InputRequirement("job_target_catalog", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
        InputRequirement("job_tree_sitter_ast", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_ast",
                         "appsec-review/tree-sitter-normalizer/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_coverage",
                         "appsec-review/tree-sitter-ast/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_node_shards",
                         "appsec-review/tree-sitter-ast/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "generated_source_backing",
                         "appsec-review/generated-source-backing/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_tree_sitter_ast", "tree_sitter_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    ),
    schedule_after=('job_tree_sitter_ast',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
