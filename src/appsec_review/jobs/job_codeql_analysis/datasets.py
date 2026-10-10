"""Dataset publication declarations for job_codeql_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_codeql_analysis/attempts/*"
CONSUMES = ('job_target_catalog', 'job_language_build', 'job_artifact_indexing', 'job_cpp_compiled_analysis', 'job_artifact_security_analysis', 'job_post_build_security_assessment', 'job_evidence_collection', 'job_tree_sitter_ast', 'job_cpp_symbol_index', 'job_cpg_analysis', 'job_change_context_analysis')
DATASETS = (
    indexed("codeql_observations", "normalize", "codeql", "appsec-review/codeql-sarif-normalizer/2",
            "CodeQL observations with rule identity, mapped locations and ordered flow steps.",
            indexes=("observations",), prefixes=("codeql-",),
            route="query_codeql; query_hotspots for ordered flow steps"),
    artifact_only("codeql_plan_and_summary", "acceptance", "codeql", "appsec-review/codeql-analysis-handoff/1",
                  "CodeQL plan, extractor inventory and per-scope summary.",
                  artifacts=(_A + "/artifacts/codeql/*.json", _A + "/steps/plan/tasks/inventory/inventory/*.json"),
                  reason="scope dispositions are published as observation-shard coverage"),
    protected("codeql_scope_material", "database", "codeql", "application/octet-stream",
              "CodeQL databases, staged workspaces, raw SARIF, replay commands and execution streams.",
              artifacts=("data/codeql/scopes/**", _A + "/steps/plan/tasks/inventory/inventory/executions/**"),
              reason="databases and raw SARIF are bulky; replay documents hold exact argv and environment"),
)
