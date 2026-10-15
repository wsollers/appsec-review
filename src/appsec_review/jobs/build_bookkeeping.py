"""Build-system bookkeeping that a workspace diff must not report as a produced artifact.

CMake compiles probe programs while it configures (compiler identification, ABI detection,
``try_compile`` checks), and Cargo keeps fingerprints, incremental caches, dependency-info and
build-script records beside its real outputs. Those files change during a build, so a
before/after workspace diff sees them, but no review question is about them and no captured
tool invocation names most of them as an output. Cataloguing them as produced artifacts only
creates producer mappings that can never resolve.

Every exclusion is counted under a typed reason so the receipt states what was left out and
why. A file is never excluded silently, and real outputs are never matched: a target's objects
live in ``CMakeFiles/<target>.dir/`` and a crate's outputs in ``<profile>/deps/`` (other than
dependency-info) or the profile directory itself.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
import re


SCHEMA = "appsec-review/build-bookkeeping-exclusions/1"
_CMAKE_VERSION = re.compile(r"\d+(?:\.\d+)+(?:-[A-Za-z0-9.]+)?")
_CMAKE_COMPILER_ID = re.compile(r"CompilerId[A-Za-z0-9_]*")
_CMAKE_FIND_PROBE = re.compile(r"Find[A-Za-z0-9_]+")
_CARGO_UNIT_DIRECTORY = re.compile(r"[A-Za-z0-9_.+-]+-[0-9a-f]{16}")
_CARGO_BUILD_SCRIPT_RECORDS = frozenset({"output", "root-output", "stderr", "invoked.timestamp"})


class BookkeepingReason(str, Enum):
    """Why a changed workspace file is build bookkeeping rather than a produced artifact."""

    CMAKE_COMPILER_IDENTIFICATION = "cmake-compiler-identification"
    CMAKE_TRY_COMPILE = "cmake-try-compile"
    CMAKE_FIND_MODULE_PROBE = "cmake-find-module-probe"
    CARGO_FINGERPRINT = "cargo-fingerprint"
    CARGO_INCREMENTAL = "cargo-incremental-cache"
    CARGO_DEPENDENCY_INFO = "cargo-dependency-info"
    CARGO_BUILD_SCRIPT_RECORD = "cargo-build-script-record"


def _cmake_reason(parts: tuple[str, ...]) -> BookkeepingReason | None:
    for index, part in enumerate(parts[:-1]):
        if part != "CMakeFiles":
            continue
        below = parts[index + 1:-1]
        if not below:
            return None  # CMakeFiles/<file> holds configuration state, not probe programs.
        head = below[0]
        if head in {"CMakeScratch", "CMakeTmp"} or any(item.startswith("TryCompile") for item in below):
            return BookkeepingReason.CMAKE_TRY_COMPILE
        if any(_CMAKE_COMPILER_ID.fullmatch(item) for item in below):
            return BookkeepingReason.CMAKE_COMPILER_IDENTIFICATION
        if _CMAKE_VERSION.fullmatch(head):
            # CMakeFiles/<version>/ holds the compiler identification and ABI-detection
            # programs (CMakeDetermineCompilerABI_<LANG>.bin); targets never build there.
            return BookkeepingReason.CMAKE_COMPILER_IDENTIFICATION
        if _CMAKE_FIND_PROBE.fullmatch(head):
            return BookkeepingReason.CMAKE_FIND_MODULE_PROBE
    return None


def _cargo_reason(parts: tuple[str, ...]) -> BookkeepingReason | None:
    name = parts[-1]
    directories = parts[:-1]
    if ".fingerprint" in directories:
        return BookkeepingReason.CARGO_FINGERPRINT
    for index, part in enumerate(directories[:-1]):
        if part == "incremental" and _CARGO_UNIT_DIRECTORY.fullmatch(directories[index + 1]):
            return BookkeepingReason.CARGO_INCREMENTAL
    if PurePosixPath(name).suffix == ".d" and directories and directories[-1] == "deps":
        return BookkeepingReason.CARGO_DEPENDENCY_INFO
    if (name in _CARGO_BUILD_SCRIPT_RECORDS and len(directories) >= 2 and
            directories[-2] == "build" and _CARGO_UNIT_DIRECTORY.fullmatch(directories[-1])):
        return BookkeepingReason.CARGO_BUILD_SCRIPT_RECORD
    return None


def bookkeeping_reason(relative: str | PurePosixPath, *, cargo: bool = False,
                       cargo_profile_directories: frozenset[str] = frozenset()) -> BookkeepingReason | None:
    """Return why a workspace-relative path is build bookkeeping, or ``None`` when it is not.

    CMake probe trees are recognised in every family, because Cargo build scripts and Python,
    PHP, and Node native extensions also drive CMake. Cargo rules apply only when ``cargo`` is
    true. ``cargo_profile_directories`` names the profile directories (those holding a
    ``.fingerprint`` directory) whose top-level ``*.d`` files are Cargo's dependency-info copies.
    """
    parts = PurePosixPath(str(relative).replace("\\", "/")).parts
    if not parts:
        return None
    reason = _cmake_reason(parts)
    if reason is None and cargo:
        reason = _cargo_reason(parts)
        if (reason is None and PurePosixPath(parts[-1]).suffix == ".d" and
                PurePosixPath(*parts[:-1]).as_posix() in cargo_profile_directories):
            reason = BookkeepingReason.CARGO_DEPENDENCY_INFO
    return reason


@dataclass(slots=True)
class BookkeepingExclusions:
    """A typed, bounded tally of the changed files left out of an artifact catalog."""

    counts: Counter = field(default_factory=Counter)
    examples: dict[str, list[str]] = field(default_factory=dict)
    example_limit: int = 5

    def record(self, reason: BookkeepingReason, relative: str) -> None:
        self.counts[reason.value] += 1
        examples = self.examples.setdefault(reason.value, [])
        if len(examples) < self.example_limit:
            examples.append(relative)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def document(self) -> dict[str, object]:
        return {"schema": SCHEMA, "total": self.total,
                "counts": {reason: self.counts[reason] for reason in sorted(self.counts)},
                "examples": {reason: list(self.examples[reason]) for reason in sorted(self.examples)}}


def cargo_profile_directories(workspace: Path) -> frozenset[str]:
    """Workspace-relative Cargo profile directories: those holding a ``.fingerprint`` tree."""
    found: set[str] = set()
    for path in workspace.rglob(".fingerprint"):
        try:
            if path.is_dir() and not path.is_symlink():
                found.add(path.parent.relative_to(workspace).as_posix())
        except OSError:
            continue
    return frozenset(found)
