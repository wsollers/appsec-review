"""Typed configuration and instrumentation-environment construction for ``job_sanitizer_build``.

Everything an operator can tune lives in ``[jobs.job_sanitizer_build.settings]``; nothing here is
a default the job can fall back on. The environment builder is pure so the flag contract is
testable without a container: it turns the accepted recipe's recorded environment plus these
settings into the environment of the instrumented rebuild, and names every way the accepted
recipe would defeat that environment.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any


SANITIZERS = ("address", "undefined")
BUILD_SYSTEMS = ("cmake", "autotools", "meson", "make")
FLAG_VARIABLES = ("CFLAGS", "CXXFLAGS", "LDFLAGS")
_KEYS = frozenset({
    "enabled", "workers", "sanitizers", "extra_flags", "required_evidence", "build_systems",
    "build_environment", "command_timeout_seconds", "output_bytes", "artifact_count_limit", "max_units",
})
_FLAG = re.compile(r"-[A-Za-z0-9][A-Za-z0-9_=,+.:/-]{0,127}")
_ENV_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
# Command-line spellings that pin flags and so mask CFLAGS/CXXFLAGS/LDFLAGS taken from the environment.
_MASKING_ARGUMENTS = (
    (re.compile(r"-DCMAKE_(?:C|CXX|OBJC|OBJCXX)_FLAGS(?::[A-Z]+)?="), "CMake compiler flags cache entry"),
    (re.compile(r"-DCMAKE_(?:EXE|SHARED|MODULE)_LINKER_FLAGS(?::[A-Z]+)?="), "CMake linker flags cache entry"),
    (re.compile(r"-D(?:c|cpp)_(?:args|link_args)="), "Meson compiler or linker arguments option"),
    (re.compile(r"-Db_sanitize="), "Meson sanitizer option"),
    (re.compile(r"(?:C|CXX|LD)FLAGS="), "make or configure flags variable"),
)


@dataclass(frozen=True, slots=True)
class SanitizerBuildSettings:
    enabled: bool
    workers: int
    sanitizers: tuple[str, ...]
    extra_flags: tuple[str, ...]
    required_evidence: tuple[str, ...]
    build_systems: tuple[str, ...]
    build_environment: Mapping[str, str]
    command_timeout_seconds: int
    output_bytes: int
    artifact_count_limit: int
    max_units: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "SanitizerBuildSettings":
        if not isinstance(value, Mapping) or set(value) != _KEYS:
            unknown = sorted(set(value) - _KEYS) if isinstance(value, Mapping) else []
            missing = sorted(_KEYS - set(value)) if isinstance(value, Mapping) else sorted(_KEYS)
            raise ValueError("jobs.job_sanitizer_build.settings must define exactly its documented keys"
                             f" (unknown: {unknown}, missing: {missing})")
        if not isinstance(value["enabled"], bool):
            raise ValueError("jobs.job_sanitizer_build.settings.enabled must be a boolean")
        for key in ("workers", "command_timeout_seconds", "output_bytes", "artifact_count_limit", "max_units"):
            if type(value[key]) is not int or value[key] <= 0:
                raise ValueError(f"jobs.job_sanitizer_build.settings.{key} must be a positive integer")
        sanitizers = _names(value["sanitizers"], "sanitizers", SANITIZERS)
        required = _names(value["required_evidence"], "required_evidence", SANITIZERS)
        if not set(required) <= set(sanitizers):
            raise ValueError("required_evidence must be a subset of sanitizers")
        build_systems = _names(value["build_systems"], "build_systems", BUILD_SYSTEMS)
        flags = value["extra_flags"]
        if (not isinstance(flags, list) or len(flags) > 16 or len(set(flags)) != len(flags) or
                any(not isinstance(item, str) or not _FLAG.fullmatch(item) or "sanitize" in item for item in flags)):
            raise ValueError("extra_flags must be a bounded unique list of option flags that do not select sanitizers")
        environment = value["build_environment"]
        if not isinstance(environment, Mapping) or len(environment) > 16:
            raise ValueError("build_environment must be a bounded table")
        for key, text in environment.items():
            if (not isinstance(key, str) or not _ENV_KEY.fullmatch(key) or _SECRET_KEY.search(key) or
                    key in FLAG_VARIABLES or not isinstance(text, str) or len(text.encode()) > 1024 or "\0" in text):
                raise ValueError(f"build_environment entry is invalid: {key!r}")
        return cls(value["enabled"], value["workers"], sanitizers, tuple(flags), required, build_systems,
                   dict(environment), value["command_timeout_seconds"], value["output_bytes"],
                   value["artifact_count_limit"], value["max_units"])

    @property
    def flags(self) -> tuple[str, ...]:
        """The compile and link flags every instrumented translation unit and link receives."""
        return (f"-fsanitize={','.join(self.sanitizers)}", *self.extra_flags)

    def identity(self) -> dict[str, Any]:
        """The settings that change the bytes of an instrumented build."""
        return {"flags": list(self.flags), "build_environment": dict(sorted(self.build_environment.items())),
                "required_evidence": list(self.required_evidence), "build_systems": list(self.build_systems)}


def _names(value: Any, key: str, allowed: Sequence[str]) -> tuple[str, ...]:
    if (not isinstance(value, list) or not value or len(set(value)) != len(value) or
            any(item not in allowed for item in value)):
        raise ValueError(f"{key} must be a non-empty unique list drawn from {list(allowed)}")
    return tuple(value)


def argument_conflicts(commands: Sequence[Sequence[str]]) -> list[str]:
    """Reasons the accepted command lines would mask or contradict the environment's sanitizer flags."""
    reasons: list[str] = []
    for ordinal, argv in enumerate(commands, 1):
        for argument in argv[1:]:
            label = next((text for pattern, text in _MASKING_ARGUMENTS if pattern.match(argument)), None)
            if argument.startswith("-") and "sanitize" in argument:
                reasons.append(f"command {ordinal} already selects sanitizer flags")
            elif label is not None:
                reasons.append(f"command {ordinal} sets a {label}, which masks the environment flags")
            else:
                continue
            break
    return reasons


def instrumented_environment(settings: SanitizerBuildSettings,
                             recorded: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """Environment of the instrumented rebuild and the conflicts the recorded environment causes.

    The sanitizer flags go first in ``CFLAGS``, ``CXXFLAGS`` and ``LDFLAGS``; flags the accepted
    recipe already set follow them. A recipe that already selects or disables a sanitizer is a
    conflict, and so is any configured build variable the recipe sets to a different value.
    """
    environment = {str(key): str(item) for key, item in recorded.items()}
    conflicts: list[str] = []
    flags = " ".join(settings.flags)
    for key in FLAG_VARIABLES:
        existing = environment.get(key, "").strip()
        if "sanitize" in existing:
            conflicts.append(f"recipe environment {key} already selects sanitizer flags")
        environment[key] = f"{flags} {existing}" if existing else flags
    for key, item in settings.build_environment.items():
        if key in environment and environment[key] != item:
            conflicts.append(f"recipe environment {key} conflicts with the configured build environment")
        else:
            environment[key] = item
    return environment, conflicts
