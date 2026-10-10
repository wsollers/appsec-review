"""Dataset publication declarations for job_review_data_indexing.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed


_A = "data/jobs/job_review_data_indexing/attempts/*/steps"
CONSUMES = (
    "job_review_intake", "job_target_catalog", "job_source_history_analysis", "job_target_analysis_plan",
    "job_tree_sitter_ast", "job_project_build", "job_language_build", "job_artifact_indexing",
    "job_artifact_security_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_cpg_analysis",
    "job_evidence_collection", "job_change_context_analysis", "job_codeql_analysis", "job_review_prioritization",
)
DATASETS = (
    artifact_only("accepted_input_summary", "load", "inventory", "appsec-review/review-data-indexing-inputs/1",
                  "Accepted handoffs, restored shards and resolved job topology read by this job.",
                  artifacts=(_A + "/load/tasks/*/accepted-inputs.json",),
                  reason="sanitized summary is indexed as dataset inventory rows"),
    indexed("cross_domain_links", "links", "links", "appsec-review/retrieval-index/2",
            "Typed exact and explicitly ambiguous links between accepted representations.",
            indexes=("links",), prefixes=("links-",), route="trace/find index=links"),
    indexed("precomputed_products", "precompute", "precomputed", "appsec-review/retrieval-index/2",
            "Stage-1 precomputed query sets, one immutable shard per set.",
            indexes=("precomputed",), prefixes=("qs-",), route="query_precomputed; query_observations"),
    artifact_only("derived_checkpoints", "precompute", "precomputed", "appsec-review/derived-shard/1",
                  "Content-addressed reuse checkpoints for derived link and product shards.",
                  artifacts=("data/indexing/checkpoints/**",),
                  reason="reuse bookkeeping; the shards themselves are indexed"),
    artifact_only("fts_image_validation", "fts", "inventory", "appsec-review/sqlite-fts-validation/1",
                  "Sanitized FTS document stream, image-built FTS5 database, container receipts and the "
                  "cross-check receipt from the pinned tool-sqlite-fts image.",
                  artifacts=("data/indexing/fts/**",),
                  reason="validation-only rebuild of already-indexed shard text; the accepted in-process shards "
                         "remain the retrieval authority"),
    artifact_only("dataset_audit_report", "audit", "inventory", "appsec-review/dataset-inventory/1",
                  "Machine-readable inventory rows, audit violations, warnings and repairs.",
                  artifacts=(_A + "/audit/tasks/*/inventory.json",),
                  reason="every row is indexed in the dataset inventory shard"),
    artifact_only("coverage_matrices", "matrix", "inventory", "appsec-review/coverage-matrices/1",
                  "Language, build-unit, producer/consumer and input-source reconciliation matrices.",
                  artifacts=(_A + "/matrix/tasks/*/coverage-matrices.json",),
                  reason="every cell is indexed in the dataset inventory shard"),
    indexed("dataset_inventory", "publish", "inventory", "appsec-review/retrieval-index/2",
            "Accepted dataset inventory, audit status and coverage matrices.",
            indexes=("inventory",), route="query_dataset_inventory", required=True),
)
