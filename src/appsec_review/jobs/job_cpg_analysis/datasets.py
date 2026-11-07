"""Dataset publication declarations for job_cpg_analysis.

Every output kind this job may emit is declared here so the publication audit can account for it.
A declaration is a contract; it is not evidence that the output was produced.
"""

from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_cpg_analysis/attempts/*"
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

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_cpp_compiled_analysis", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE,
                         availability=Availability.REQUIRED, missing=MissingPolicy.REJECT),
        InputRequirement("job_cpp_compiled_analysis", "cpp_build_graph",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "clang_ast",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "llvm_ir",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "infer_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "binary_symbols",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_blocked_branches",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_plan_and_summary",
                         "appsec-review/cpp-compiled-analysis/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_cpp_compiled_analysis", "cpp_case_material",
                         "application/octet-stream", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_observations",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_evidence",
                         "appsec-review/static-tool-evidence/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_evidence_collection", "static_tool_io",
                         "appsec-review/container-execution/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    ),
    schedule_after=('job_cpp_compiled_analysis',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
