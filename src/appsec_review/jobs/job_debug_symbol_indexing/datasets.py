"""Publication contracts for normalized symbols and protected input references."""
from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_debug_symbol_indexing/attempts/*"
DATASETS = (
    indexed("normalized_symbols", "extract", "symbols", "appsec-review/retrieval-index/2",
            "Build-bound normalized symbols, layouts, inline frames and compilation units.",
            indexes=("debug_symbols",), prefixes=("symbols-",),
            route="query_debug_symbols"),
    artifact_only("symbol_coverage", "extract", "symbols", "appsec-review/debug-symbol-coverage/1",
                  "Artifact-specific coverage and named unavailable symbol families.",
                  artifacts=(_A + "/artifacts/debug-symbols/coverage.json",),
                  reason="coverage rows are also published in the normalized symbol shard",
                  route="query_debug_symbols mode=coverage"),
    artifact_only("target_decision", "decide", "configuration", "appsec-review/debug-symbol-decision/1",
                  "Persisted immutable compiler-target route and its input fingerprint.",
                  artifacts=(_A + "/artifacts/debug-symbols/decision.json",),
                  reason="routing metadata; normalized records are indexed separately"),
    protected("raw_artifact_refs", "extract", "symbols", "appsec-review/debug-symbol-inputs/1",
              "Run-owned binary/debug references and protected raw reader records.",
              artifacts=(_A + "/artifacts/debug-symbols/raw-refs.json",),
              reason="private debug symbols and recorded paths are not raw retrieval outputs"),
    protected("reader_executions", "extract", "symbols", "appsec-review/container-execution/1",
              "Build-image and compatibility-reader receipts, bounded exports and diagnostics.",
              artifacts=(_A + "/artifacts/debug-symbols/executions/**",),
              reason="raw symbol exports, tool diagnostics and execution mounts remain protected"),
    artifact_only("debug_symbol_summary", "acceptance", "symbols", "appsec-review/debug-symbol-indexing/1",
                  "Accepted composite index manifest and coverage summary.",
                  artifacts=(_A + "/artifacts/debug-symbols/accepted-index.json",),
                  reason="summary identities and counts are represented by indexed coverage"),
)

from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, InputRequirement,
    JobContract, MissingPolicy, TargetAccess,
)

CONTRACT = JobContract(
    inputs=(
        InputRequirement("job_artifact_indexing", "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_catalog",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "archive_members",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_relationships",
                         "appsec-review/retrieval-index/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement("job_artifact_indexing", "artifact_index_summary",
                         "appsec-review/artifact-indexing/1", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
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
    ),
    schedule_after=('job_artifact_indexing',),
    dispatch=DispatchClass.REVIEW_GRAPH,
    target_access=TargetAccess.CHECKOUT,
    always_execute=False,
    propagate_handoff=True,
)
CONSUMES = CONTRACT.consumes
