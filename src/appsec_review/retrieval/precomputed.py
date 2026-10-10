"""Stable query-set names and payload contract for run-owned computed facts.

Producer jobs are implemented separately. An accepted shard must declare its query set in the
manifest producer identity and publish ``precomputed_fact`` entities with the same set in payload.
The MCP never executes an analyzer or reads a raw CPG/IR artifact to answer these queries.
"""

from __future__ import annotations


FACT_SCHEMA = "appsec-review/precomputed-fact/1"
QUERY_SETS = (
    "symbol_links", "call_graph", "control_flow", "dataflow", "entrypoint_paths",
    "guards_ranges", "sarif_correlation", "ast_ir_cpg_mapping", "hotspot_context",
    "build_provenance", "artifact_inventory", "dependency_advisories", "scanner_correlation",
    "ci_trust", "redacted_secret_exposure", "history_context", "control_evidence",
    "reference_intelligence", "contract_enforcement", "deployment_exposure", "test_intent",
    "review_package",
)
