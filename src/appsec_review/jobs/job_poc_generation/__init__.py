"""Proof-of-concept unit-test functions for findings the judge agreed are correct (compile-checked, never run)."""

from .job import JOB_ID, build_job
from .poc_execution_gate import (
    GENERATED_CODE_EXECUTION_POLICY,
    POC_EXECUTION_BLOCKED_CODE,
    PocExecutionBlockedByPolicyError,
    enforce_poc_non_execution,
    guard_command_against_poc_execution,
)
from .static_compile_check import (
    POC_COMPILE_CHECK_SCHEMA,
    SUPPORTED_POC_LANGUAGES,
    StaticPocCompileCheckResult,
    detect_poc_language,
    validate_static_poc_harness,
)

__all__ = [
    "GENERATED_CODE_EXECUTION_POLICY",
    "JOB_ID",
    "POC_COMPILE_CHECK_SCHEMA",
    "POC_EXECUTION_BLOCKED_CODE",
    "PocExecutionBlockedByPolicyError",
    "SUPPORTED_POC_LANGUAGES",
    "StaticPocCompileCheckResult",
    "build_job",
    "detect_poc_language",
    "enforce_poc_non_execution",
    "guard_command_against_poc_execution",
    "validate_static_poc_harness",
]
