"""Fail-closed non-execution policy gate for PoC generation (T-175).

Dynamic PoC execution is strictly prohibited until the dedicated sandbox architecture and explicit
operator approval gate in T-175 are ratified. Every settings load, static check, container command
and published handoff passes through this module so no flag, caller or adapter can execute
generated PoC code.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

GENERATED_CODE_EXECUTION_POLICY = "not_performed_by_policy"
POC_EXECUTION_BLOCKED_CODE = "dynamic_poc_execution_prohibited_pending_t175_sandbox_approval"

_FORBIDDEN_EXECUTION_FLAGS = frozenset({
    "execute_poc",
    "dynamic_execution",
    "allow_dynamic_execution",
    "run_generated_code",
    "sandbox_execution",
    "execute_generated_code",
    "enable_poc_execution",
})

_FORBIDDEN_RUNNERS = frozenset({
    "sh", "bash", "zsh", "dash", "ksh", "fish", "powershell", "pwsh", "cmd", "cmd.exe",
    "node", "nodejs", "deno", "bun", "ruby", "bundle", "rspec", "php", "phpunit",
    "pytest", "nosetests", "java", "mvn", "gradle", "gradlew", "dotnet", "cargo", "go", "perl",
})

_COMPILE_ONLY_COMPILERS = frozenset({
    "clang", "clang++", "gcc", "g++", "cc", "c++", "javac", "rustc", "csc",
})

_INSPECTION_TOOLS = frozenset({"nm", "objdump", "readelf", "find"})


class PocExecutionBlockedByPolicyError(RuntimeError, ValueError):
    """Raised whenever any configuration, caller or command attempts dynamic PoC execution."""

    def __init__(self, detail: str = "") -> None:
        message = POC_EXECUTION_BLOCKED_CODE if not detail else f"{POC_EXECUTION_BLOCKED_CODE}: {detail}"
        super().__init__(message)
        self.code = POC_EXECUTION_BLOCKED_CODE


def _check_mapping_for_execution_flags(mapping: Mapping[str, Any], prefix: str = "") -> None:
    for key in _FORBIDDEN_EXECUTION_FLAGS:
        if key in mapping:
            value = mapping[key]
            where = f"{prefix}.{key}" if prefix else key
            raise PocExecutionBlockedByPolicyError(f"{where}={value!r}")
    if "generated_code_execution" in mapping and mapping["generated_code_execution"] != GENERATED_CODE_EXECUTION_POLICY:
        raise PocExecutionBlockedByPolicyError(
            f"generated_code_execution={mapping['generated_code_execution']!r}"
        )
    if "runtime_verified" in mapping and mapping["runtime_verified"] is not False:
        raise PocExecutionBlockedByPolicyError(f"runtime_verified={mapping['runtime_verified']!r}")
    if "execution" in mapping and mapping["execution"] not in (GENERATED_CODE_EXECUTION_POLICY, "never"):
        raise PocExecutionBlockedByPolicyError(f"execution={mapping['execution']!r}")


def enforce_poc_non_execution(
    *,
    generated_code_execution: Any = GENERATED_CODE_EXECUTION_POLICY,
    runtime_verified: Any = False,
    result_id: Any = None,
    execute_poc: Any = False,
    settings_mapping: Mapping[str, Any] | None = None,
    **extra_flags: Any,
) -> dict[str, Any]:
    """Fail closed if any parameter or configuration requests dynamic PoC execution."""
    if extra_flags:
        bad_key, bad_val = next(iter(sorted(extra_flags.items())))
        raise PocExecutionBlockedByPolicyError(f"{bad_key}={bad_val!r}")
    if execute_poc is not False:
        raise PocExecutionBlockedByPolicyError(f"execute_poc={execute_poc!r}")
    if generated_code_execution != GENERATED_CODE_EXECUTION_POLICY:
        raise PocExecutionBlockedByPolicyError(f"generated_code_execution={generated_code_execution!r}")
    if runtime_verified is not False:
        raise PocExecutionBlockedByPolicyError(f"runtime_verified={runtime_verified!r}")
    if result_id is not None:
        raise PocExecutionBlockedByPolicyError(f"result_id={result_id!r}")
    if isinstance(settings_mapping, Mapping):
        _check_mapping_for_execution_flags(settings_mapping)
        for section in ("build", "policy"):
            nested = settings_mapping.get(section)
            if isinstance(nested, Mapping):
                _check_mapping_for_execution_flags(nested, section)
    return {
        "generated_code_execution": GENERATED_CODE_EXECUTION_POLICY,
        "execution": GENERATED_CODE_EXECUTION_POLICY,
        "runtime_verified": False,
        "result_id": None,
    }


def guard_command_against_poc_execution(argv: Sequence[str]) -> None:
    """Refuse any container command vector that could link and run or interpret a generated PoC."""
    if not argv or not all(isinstance(part, str) and part for part in argv):
        raise PocExecutionBlockedByPolicyError("empty or malformed command vector")
    binary = PurePosixPath(argv[0].replace("\\", "/")).name.lower()
    if binary in ("python", "python3"):
        if len(argv) >= 5 and argv[1].endswith("/ast_reduce.py") and "--" in argv and "-fsyntax-only" in argv:
            return
        raise PocExecutionBlockedByPolicyError(f"interpreter execution denied for {argv[0]}")
    if binary in _FORBIDDEN_RUNNERS:
        raise PocExecutionBlockedByPolicyError(f"runtime runner denied: {binary}")
    if binary in _INSPECTION_TOOLS:
        return
    if binary in _COMPILE_ONLY_COMPILERS or any(binary.startswith(f"{n}-") for n in ("clang", "clang++", "gcc", "g++")):
        if "-fsyntax-only" in argv or "-c" in argv or "--emit=metadata" in argv:
            return
        raise PocExecutionBlockedByPolicyError(f"compiler command lacks compile-only flag: {binary}")
    raise PocExecutionBlockedByPolicyError(f"unapproved command binary: {binary}")


__all__ = [
    "GENERATED_CODE_EXECUTION_POLICY",
    "POC_EXECUTION_BLOCKED_CODE",
    "PocExecutionBlockedByPolicyError",
    "enforce_poc_non_execution",
    "guard_command_against_poc_execution",
]
