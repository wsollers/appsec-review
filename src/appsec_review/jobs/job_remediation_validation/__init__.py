"""Remediation validation job package."""

from appsec_review.jobs.job_remediation_validation.job import JOB_ID, build_job
from appsec_review.jobs.job_remediation_validation.static_validator import (
    FilePatchValidation,
    STATIC_PATCH_VALIDATION_SCHEMA,
    SUPPORTED_REMEDIATION_LANGUAGES,
    StaticPatchValidationResult,
    UnifiedDiffApplyError,
    apply_unified_diff_in_memory,
    extract_declared_functions,
    validate_file_remediation_in_memory,
    validate_remediation_patch_set,
    detect_guard_pattern,
    verify_patched_syntax,
)

__all__ = [
    "FilePatchValidation",
    "JOB_ID",
    "STATIC_PATCH_VALIDATION_SCHEMA",
    "SUPPORTED_REMEDIATION_LANGUAGES",
    "StaticPatchValidationResult",
    "UnifiedDiffApplyError",
    "apply_unified_diff_in_memory",
    "build_job",
    "extract_declared_functions",
    "validate_file_remediation_in_memory",
    "validate_remediation_patch_set",
    "detect_guard_pattern",
    "verify_patched_syntax",
]
