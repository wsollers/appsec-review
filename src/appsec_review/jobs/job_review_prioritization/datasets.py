"""Dataset publication declarations for job_review_prioritization.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import EvidenceAuthority
from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_review_prioritization/attempts/*"
DATASETS = (
    indexed("priority_items", "publish", "priority", "appsec-review/retrieval-index/2",
            "Ranked review-priority items, review signals, ordered flow steps and dependency context.",
            indexes=("priority",), route="query_hotspots; find/trace index=priority", required=True, authority=EvidenceAuthority.ROUTING_CONTEXT),
    artifact_only("prioritization_documents", "publish", "priority", "appsec-review/review-prioritization/1",
                  "Syntax facts, dependency graph, semantic evidence and the full ranking.",
                  artifacts=(_A + "/steps/*/tasks/*/artifacts/*.json",),
                  reason="full unselected ranking and per-file syntax facts exceed retrieval bounds; selected "
                         "items are indexed", authority=EvidenceAuthority.ROUTING_CONTEXT),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_codeql_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_predecessor_import",
                         "appsec-review/codeql-predecessor-import/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_graph_export",
                         "appsec-review/codeql-graph-export/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_observations",
                         "appsec-review/codeql-sarif-normalizer/3", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_plan_and_summary",
                         "appsec-review/codeql-analysis-handoff/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_codeql_analysis", "codeql_scope_material",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_evidence",
                         "appsec-review/static-tool-evidence/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "model_preflight",
                         "appsec-review/model-preflight/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "binary_evidence",
                         "appsec-review/binary-evidence-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "review_intake",
                         "appsec-review/review-intake/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    schedule_after=('job_codeql_analysis',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
