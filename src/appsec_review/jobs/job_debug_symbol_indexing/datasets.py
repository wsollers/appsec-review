"""Publication contracts for normalized symbols and protected input references."""
from appsec_review.runtime.datasets import artifact_only, indexed, protected


_A = "data/jobs/job_debug_symbol_indexing/attempts/*"
CONSUMES = ("job_artifact_indexing", "job_language_build")
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
