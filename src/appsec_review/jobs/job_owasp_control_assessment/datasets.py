"""OWASP publications and the explicit accepted source view its readers use."""
from __future__ import annotations

from appsec_review.runtime.datasets import artifact_only, indexed, protected
from appsec_review.runtime.contracts import (
    DispatchClass, EvidenceAuthority, InputChannel, InputRequirement, JobContract, TargetAccess,
)
from appsec_review.retrieval.index import IndexSelection


_A = "data/jobs/job_owasp_control_assessment/attempts/*"
DATASETS = (
    protected("owasp_model_receipts", "verification", "owasp", "appsec-review/owasp-model-receipt/1",
              "Worker/reviewer proposals, usage and content-bound reuse receipts; not target evidence.",
              artifacts=("data/indexes/owasp/receipts/*.json",),
              reason="model interpretations are not an independent evidence source"),
    indexed("owasp_workbench", "publication", "owasp", "appsec-review/owasp-index-shard/1",
            "Standards, component classifications, applicability, validation work, finding packages and "
            "control results.",
            indexes=("standards", "component-classification", "applicability", "validation-work",
                     "control-result", "finding-package"),
            artifacts=tuple(f"data/indexes/owasp/{family}/**" for family in (
                "standards", "component-classification", "applicability", "validation-work",
                "control-result", "finding-package", "manifests")) + ("data/indexes/owasp/accepted.json",),
            route="query_owasp_workbench; query_precomputed query_set=control_evidence", store="owasp"),
    artifact_only("owasp_documents", "publication", "owasp", "appsec-review/owasp-workbench-result/1",
                  "Workbench source documents and the accepted result.",
                  artifacts=(_A + "/artifacts/owasp-workbench/*.json",),
                  reason="same records as the accepted workbench shards"),
    artifact_only("owasp_control_gaps", "publication", "owasp", "appsec-review/owasp-control-gap/1",
                  "Verified absent or weak OWASP control gaps bound to concrete source/evidence spans.",
                  artifacts=(_A + "/artifacts/owasp-control-gaps/*.json",),
                  reason="curated gap projection of accepted control-result shards"),
)

_INDEX = "appsec-review/retrieval-index/2"
_COVERAGE = "appsec-review/cpp-index-coverage/1"
_EVIDENCE = EvidenceAuthority.PRODUCER_EVIDENCE
_ROUTING = EvidenceAuthority.ROUTING_CONTEXT

# Index families select payloads; output identities separately admit their exact dataset owners.
_SOURCE_INPUTS = {
    "job_artifact_indexing": (
        ("artifacts", "artifact_catalog", _INDEX), ("artifacts", "archive_members", _INDEX),
        ("artifacts", "artifact_relationships", _INDEX)),
    "job_artifact_security_analysis": (("observations", "artifact_security_observations", _INDEX),),
    "job_ci_configuration_analysis": (
        ("observations", "ci_observations", _INDEX), ("evidence", "ci_findings", _INDEX)),
    "job_clang_static_analysis": (
        ("observations", "clang_static_observations", _INDEX),
        ("observations", "clang_static_scope_coverage", _COVERAGE)),
    "job_code_graph_index": (
        ("graph", "code_graph_facts", "appsec-review/graph-fact/1"),
        ("analysis", "alternate_cpg_index", "appsec-review/alternate-cpg/1")),
    "job_codeql_analysis": (("observations", "codeql_observations", "appsec-review/codeql-sarif-normalizer/3"),),
    "job_cpg_analysis": (
        ("observations", "cpg_graph_coverage", _INDEX), ("observations", "cpg_scope_coverage", _COVERAGE)),
    "job_cpp_compiled_analysis": (
        ("build", "cpp_build_graph", _INDEX), ("analysis", "clang_ast", _INDEX),
        ("analysis", "llvm_ir", _INDEX), ("observations", "infer_observations", _INDEX),
        ("compiled", "binary_symbols", _INDEX), ("analysis", "cpp_blocked_branches", _INDEX)),
    "job_cpp_symbol_index": (
        ("analysis", "clangd_symbols", _INDEX), ("analysis", "clangd_coverage", _COVERAGE)),
    "job_dependency_intelligence": (
        ("observations", "native_advisory_observations", _INDEX), ("inventory", "dependency_context", _INDEX)),
    "job_evidence_collection": (("observations", "static_tool_observations", _INDEX),),
    "job_language_build": (("build", "build_actions", _INDEX), ("build", "jvm_build_actions", _INDEX)),
    "job_post_build_security_assessment": (("build_security", "build_security", _INDEX),),
    "job_profile_data": (("analysis", "profile_data", _INDEX),),
    "job_review_prioritization": (("priority", "priority_items", _INDEX),),
    "job_security_tagging": (("tags", "tag_assignments", "appsec-review/tag-assignment/1"),),
    "job_svf_alias_analysis": (
        ("analysis", "svf_alias_sets", _INDEX), ("analysis", "svf_alias_scope_coverage", _COVERAGE)),
    "job_target_analysis_plan": (("analysis", "analysis_plan", _INDEX),),
    "job_target_catalog": (
        ("source", "source_files", _INDEX), ("analysis", "declaration_symbols", _INDEX),
        ("components", "components", _INDEX), ("documents", "target_documents", _INDEX),
        ("build", "build_units", _INDEX)),
    "job_test_coverage": (("analysis", "test_coverage", _INDEX),),
    "job_tree_sitter_ast": (
        ("analysis", "tree_sitter_ast", "appsec-review/tree-sitter-normalizer/1"),
        ("analysis", "tree_sitter_coverage", "appsec-review/tree-sitter-ast/1")),
}
_CUSTODY_INPUTS = (
    ("job_binary_evidence_indexing", "binary_pseudo_c", "appsec-review/binary-source-backing/1"),
    ("job_tree_sitter_ast", "generated_source_backing", "appsec-review/generated-source-backing/1"),
)
SOURCE_SELECTION = IndexSelection(
    tuple((producer, index) for producer, rows in _SOURCE_INPUTS.items() for index, _, _ in rows),
    tuple((producer, output) for producer, output, _ in _CUSTODY_INPUTS),
)
_ROUTING_PRODUCERS = {"job_review_prioritization", "job_security_tagging"}
CONTRACT = JobContract(
    inputs=(
        *(InputRequirement(producer, "handoff", "appsec-review/job-handoff/2",
                           authority=_ROUTING if producer in _ROUTING_PRODUCERS else _EVIDENCE)
          for producer in sorted({*_SOURCE_INPUTS, *(row[0] for row in _CUSTODY_INPUTS)})),
        *(InputRequirement(producer, output, schema,
                           authority=_ROUTING if producer in _ROUTING_PRODUCERS else _EVIDENCE)
          for producer, rows in _SOURCE_INPUTS.items() for _, output, schema in rows),
        *(InputRequirement(producer, output, schema, authority=_EVIDENCE)
          for producer, output, schema in _CUSTODY_INPUTS),
        InputRequirement("job_third_party_data_sync", "feed_snapshot", "appsec-review/public-feed-use/1",
                         channel=InputChannel.EXTERNAL, authority=EvidenceAuthority.REFERENCE),
    ),
    schedule_after=("job_post_build_security_assessment", "job_evidence_collection",
                    "job_artifact_security_analysis", "job_tree_sitter_ast", "job_codeql_analysis",
                    "job_review_prioritization", "job_code_graph_index", "job_security_tagging"),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
