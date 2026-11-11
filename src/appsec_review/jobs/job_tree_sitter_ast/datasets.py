"""Dataset publication declarations for job_tree_sitter_ast.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


RAW = "raw tool streams and receipts may contain unredacted target content and host paths"
_A = "data/jobs/job_tree_sitter_ast/attempts/*"
DATASETS = (
    indexed("tree_sitter_ast", "parse", "syntax", "appsec-review/tree-sitter-normalizer/1",
            "Bounded Tree-sitter AST nodes, byte-exact spans, parent relations and unresolved syntax navigation.",
            indexes=("analysis",), route="query_syntax subject=source_file/ast_node; find/trace/search index=analysis kind=ast_node"),
    indexed("tree_sitter_coverage", "acceptance", "syntax", "appsec-review/tree-sitter-ast/1",
            "Per-scope parse dispositions, including unavailable grammars and truncation.",
            indexes=("analysis",), prefixes=("tree-sitter-coverage-",), route="coverage index=analysis"),
    artifact_only("tree_sitter_node_shards", "parse", "syntax", "appsec-review/tree-sitter-ast/1",
                  "JSONL node records and per-scope results backing the AST shards.",
                  artifacts=("data/treesitter/shards/*.jsonl", "data/treesitter/shards/*.json",
                             _A + "/steps/parse/tasks/dynamic_scopes/dynamic/*.json",
                             _A + "/steps/acceptance/tasks/publish_handoff/accepted-tree-sitter-ast.json"),
                  reason="same nodes as the accepted analysis shards; kept for deterministic reuse"),
    artifact_only("generated_source_backing", "load", "syntax", "appsec-review/generated-source-backing/1",
                  "Bounded accepted generated-source provenance; bytes reside in run-owned shared objects.",
                  artifacts=("data/treesitter/sources/*.json",),
                  reason="immutable source custody for AST and downstream resolving spans"),
    protected("tree_sitter_tool_io", "parse", "syntax", "appsec-review/container-execution/1",
              "Parser container requests, raw output and streams.",
              artifacts=("data/treesitter/work/**", "data/treesitter/inputs/**"), reason=RAW),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_language_build", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "topology_refinement_inputs",
                         "appsec-review/build-topology-refinement/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "build_actions",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "jvm_build_actions",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "language_build_receipts",
                         "appsec-review/language-build-handoff/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_language_build", "build_workspaces",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_review_intake", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    schedule_after=('job_language_build',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
