"""Exact inputs and complete output ownership for bounded CBMC analysis."""

from appsec_review.jobs.job_cpp_compiled_analysis.datasets import DATASETS as CPP_DATASETS
from appsec_review.jobs.job_evidence_collection.datasets import DATASETS as SAST_DATASETS
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS as CODEQL_DATASETS
from appsec_review.jobs.job_clang_static_analysis.datasets import DATASETS as CLANG_DATASETS
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.runtime.contracts import (
    Availability, JobContract, MissingPolicy, TargetAccess, accepted_inputs,
)
from appsec_review.runtime.datasets import artifact_only, indexed, protected


JOB_ID = "job_cbmc_analysis"
SUMMARY_SCHEMA = "appsec-review/cbmc-summary/1"
_A = "data/jobs/job_cbmc_analysis/attempts/*"
DATASETS = (
    artifact_only("cbmc_plan", "load", "scanner_findings", "appsec-review/cbmc-plan/1",
                  "Deterministic seed and translation-unit selection with explicit omissions.",
                  artifacts=(_A + "/steps/load/tasks/accepted_inputs/plan.json",),
                  reason="selection bookkeeping; result and coverage summaries are indexed"),
    indexed("cbmc_results", "acceptance", "scanner_findings", "appsec-review/retrieval-index/2",
            "Conditional CBMC judgments bound to exact scanner seeds, source hashes and native receipts.",
            indexes=("observations",), prefixes=("cbmc-results-",),
            route="find/search index=observations; review-package bounded_analysis context"),
    indexed("cbmc_coverage", "acceptance", "scanner_findings", "appsec-review/retrieval-index/2",
            "Selection, incomplete-model and resource-bound coverage of CBMC attempts.",
            indexes=("observations",), prefixes=("cbmc-coverage-",), route="coverage index=observations"),
    artifact_only("cbmc_summary", "acceptance", "scanner_findings", SUMMARY_SCHEMA,
                  "Accepted CBMC accounting and exact result/receipt references.",
                  artifacts=(_A + "/steps/acceptance/tasks/publish_handoff/summary.json",),
                  reason="conditional judgments are indexed; this is their publication accounting"),
    protected("cbmc_raw", "analyze", "scanner_findings", "application/octet-stream",
              "Verified source copies, GOTO binaries, native JSON/traces and container receipts.",
              artifacts=(_A + "/artifacts/cbmc/**",),
              reason="native traces and build context are protected; only bounded summaries are indexed"),
)
CONTRACT = JobContract(
    inputs=(
        *accepted_inputs("job_target_catalog", CATALOG_DATASETS, output_kinds=("source_files",)),
        *accepted_inputs("job_cpp_compiled_analysis", CPP_DATASETS,
                         availability=Availability.WHEN_ENABLED, missing=MissingPolicy.REJECT,
                         output_kinds=("cpp_plan_and_summary", "cpp_case_material")),
        *accepted_inputs("job_evidence_collection", SAST_DATASETS,
                         output_kinds=("static_tool_observations",)),
        *accepted_inputs("job_codeql_analysis", CODEQL_DATASETS, output_kinds=("codeql_observations",)),
        *accepted_inputs("job_clang_static_analysis", CLANG_DATASETS,
                         output_kinds=("clang_static_observations",)),
    ),
    target_access=TargetAccess.ACCEPTED_EVIDENCE,
)
