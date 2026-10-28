"""Shared contracts for engineering-signal producer jobs.

The producer implementations deliberately remain independent.  These constants are the small
cross-job contract used by orchestration, review-data indexing, and tests; changing one is a schema
change rather than an implementation detail.
"""
from __future__ import annotations

from enum import StrEnum


CLANG_STATIC_HANDOFF_SCHEMA = "appsec-review/clang-static-analysis-handoff/1"
SVF_ALIAS_HANDOFF_SCHEMA = "appsec-review/svf-alias-analysis-handoff/1"
SANITIZER_BUILD_HANDOFF_SCHEMA = "appsec-review/sanitizer-build-handoff/1"
POC_GENERATION_HANDOFF_SCHEMA = "appsec-review/poc-generation-handoff/2"
POC_GENERATION_SCHEMA = "appsec-review/poc-generation/2"
FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA = "appsec-review/final-publication-gate-handoff/2"
FINAL_PUBLICATION_GATE_SCHEMA = "appsec-review/final-publication-gate/2"
FINAL_REPORT_HANDOFF_SCHEMA = "appsec-review/final-report-handoff/2"
FINAL_REPORT_SCHEMA = "appsec-review/final-report/2"
OPENVEX_EXPORT_HANDOFF_SCHEMA = "appsec-review/openvex-export-handoff/1"
OPENVEX_EXPORT_MANIFEST_SCHEMA = "appsec-review/openvex-export-manifest/1"
OPENVEX_EXPORT_RESULT_SCHEMA = "appsec-review/openvex-export-result/1"
TEST_COVERAGE_HANDOFF_SCHEMA = "appsec-review/test-coverage-handoff/1"
DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA = "appsec-review/dependency-intelligence-handoff/1"
PROFILE_DATA_HANDOFF_SCHEMA = "appsec-review/profile-data-handoff/1"
SCORECARD_RECORD_SCHEMA = "appsec-review/openssf-scorecard-record/1"
NATIVE_DEPENDENCY_CANDIDATE_SCHEMA = "appsec-review/native-dependency-candidate/1"


class CoverageState(StrEnum):
    """Closed producer-coverage vocabulary shared by the new jobs."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class ResolutionBasis(StrEnum):
    """How a dependency-to-repository identity was established."""

    DECLARED = "declared"
    PACKAGE_METADATA = "package_metadata"
    LINKER_EVIDENCE = "linker_evidence"
    MODEL_INFERENCE = "model_inference"
    UNRESOLVED = "unresolved"


class MaximalExposure(StrEnum):
    """Ordered deployment exposure inferred for a dependency or runtime observation."""

    DEV = "DEV"
    DEBUG = "DEBUG"
    QA = "QA"
    PREPROD = "PREPROD"
    PROD = "PROD"
