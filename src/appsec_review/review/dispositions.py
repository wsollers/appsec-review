"""Source dispositions: which accepted source files the review lanes reason over (T-165).

Every accepted source file has exactly one disposition. ``first_party`` is code the target's
developers own and can change; ``vendored``, ``sdk``, ``generated`` and ``test`` name code the
review lanes leave alone. The lead lane, the hunt lane and the hypothesis hunters reason only over
first-party files; a lead located in any other disposition is recorded as not admitted with the
disposition as its reason, never as a coverage gap. Scanners, indexes and the dependency inventory
still cover the whole target: a disposition narrows what the model workers reason about, not what
the run observed.

The disposition is derived from configured target-relative POSIX globs
(``[jobs.job_inference_security_review.settings.source_dispositions]``; glob semantics of
``path_globs.py``). Classes are tested in the fixed order ``vendored``, ``sdk``,
``generated``, ``test``, so a test file inside a vendored tree is ``vendored``. An unmatched path,
and a lead with no location, is ``first_party``: the review never silently drops what it cannot
place. The settings are semantic: they change which leads and units reach the lanes.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Mapping

from appsec_review.path_globs import matches, validate_glob_patterns

DISPOSITION_RULE = "appsec-review/source-disposition/1"
FIRST_PARTY = "first_party"
# Fixed classification order; the first matching class wins.
EXCLUDED_DISPOSITIONS = ("vendored", "sdk", "generated", "test")
DISPOSITIONS = (FIRST_PARTY, *EXCLUDED_DISPOSITIONS)


@dataclass(frozen=True, slots=True)
class SourceDispositions:
    """Glob lists per non-first-party disposition; empty lists make every path first-party."""

    vendored: tuple[str, ...] = ()
    sdk: tuple[str, ...] = ()
    generated: tuple[str, ...] = ()
    test: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in EXCLUDED_DISPOSITIONS:
            object.__setattr__(self, name, validate_glob_patterns(list(getattr(self, name)), f"source_dispositions.{name}"))

    def classify(self, path: str | None) -> str:
        """The disposition of one target-relative path; ``None`` (unlocated) is first-party."""
        if path is None:
            return FIRST_PARTY
        for name in EXCLUDED_DISPOSITIONS:
            if any(matches(path, pattern) for pattern in getattr(self, name)):
                return name
        return FIRST_PARTY

    def matched_pattern(self, path: str) -> tuple[str, str] | None:
        """``(disposition, pattern)`` of the first matching class, for audit records."""
        for name in EXCLUDED_DISPOSITIONS:
            for pattern in getattr(self, name):
                if matches(path, pattern):
                    return name, pattern
        return None

    @property
    def configured(self) -> bool:
        return any(getattr(self, name) for name in EXCLUDED_DISPOSITIONS)

    @classmethod
    def from_mapping(cls, value: object, field: str = "source_dispositions") -> "SourceDispositions":
        """Dispositions from a TOML table; unknown keys are rejected and absent classes stay empty."""
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        known = {item.name for item in fields(cls)}
        unknown = sorted(str(key) for key in set(value) - known)
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        return cls(**{name: validate_glob_patterns(value[name], f"{field}.{name}") for name in value})

    def record(self) -> dict[str, Any]:
        return {"rule": DISPOSITION_RULE, **{name: list(getattr(self, name)) for name in EXCLUDED_DISPOSITIONS}}


__all__ = ["DISPOSITIONS", "DISPOSITION_RULE", "EXCLUDED_DISPOSITIONS", "FIRST_PARTY", "SourceDispositions"]
