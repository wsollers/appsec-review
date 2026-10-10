"""Dataset publication declarations for job_cpg_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_cpg_analysis/attempts/*"
CONSUMES = ('job_cpp_compiled_analysis',)
DATASETS = (
    indexed("cpg_graph_coverage", "generate", "cpg", "appsec-review/retrieval-index/2",
            "Per-scope CPG evidence identity with unavailable graph coverage.",
            indexes=("observations",), prefixes=("joern-",), route="coverage index=observations; find kind=evidence_artifact"),
    indexed("cpg_scope_coverage", "acceptance", "cpg", "appsec-review/cpp-index-coverage/1",
            "Unavailable C/C++ CPG scopes.",
            indexes=("observations",), prefixes=("joern-coverage-",), route="coverage index=observations"),
    artifact_only("cpg_summary", "acceptance", "cpg", "appsec-review/cpg-analysis/1",
                  "CPG generation summary.", artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/*.json",),
                  reason="counts already published as coverage"),
    protected("cpg_binary", "generate", "cpg", "application/octet-stream",
              "Binary Joern code property graphs, compile databases and raw streams.",
              artifacts=("data/code-index/joern/**",),
              reason="binary CPG is not graph coverage; graph extraction stays unavailable until a pinned "
                     "bounded exporter publishes source-mapped nodes and edges"),
)
