"""Stable query-set names and payload contract for run-owned computed facts.

Producer jobs are implemented separately. An accepted shard must declare its query set in the
manifest producer identity and publish ``precomputed_fact`` entities with the same set in payload.
The MCP never executes an analyzer or reads a raw CPG/IR artifact to answer these queries.

Code-graph facts are not query sets. The former ``call_graph``, ``control_flow``, ``dataflow``,
``sarif_correlation``, ``ast_ir_cpg_mapping``, ``guards_ranges`` and ``entrypoint_paths`` sets are
retired (docs/architecture/code-graph-precomputation.md, D2 and section 11): graph facts are
first-class entities of the ``graph`` index, read through ``query_code_graph``. A retired name is
rejected as an invalid query set, never answered as an unavailable one.
"""

from __future__ import annotations


FACT_SCHEMA = "appsec-review/precomputed-fact/1"
QUERY_SETS = (
    "symbol_links", "hotspot_context",
    "build_provenance", "artifact_inventory", "dependency_advisories", "scanner_correlation",
    "ci_trust", "redacted_secret_exposure", "history_context", "control_evidence",
    "reference_intelligence", "contract_enforcement", "deployment_exposure", "test_intent",
    "review_package", "document_context",
)
# Retired graph set names, kept only so tests and the indexing job can assert they stay retired.
RETIRED_GRAPH_SETS = (
    "call_graph", "control_flow", "dataflow", "sarif_correlation", "ast_ir_cpg_mapping", "guards_ranges",
    "entrypoint_paths",
)
assert not set(RETIRED_GRAPH_SETS) & set(QUERY_SETS)
