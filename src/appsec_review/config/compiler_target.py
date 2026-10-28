"""The native compiler family selected for one immutable application run."""
from __future__ import annotations

from enum import Enum


class CompilerTarget(str, Enum):
    CLANG = "clang"
    MSVC = "msvc"


COMPILER_TARGET_TAG = "appsec/compiler_target"
DEFAULT_COMPILER_TARGET = CompilerTarget.CLANG


def compiler_target(value: object) -> CompilerTarget:
    if not isinstance(value, str):
        raise ValueError("compiler_target must be clang or msvc")
    try:
        return CompilerTarget(value)
    except ValueError as exc:
        raise ValueError("compiler_target must be clang or msvc") from exc
