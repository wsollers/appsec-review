"""Lead filters: observation rule classes that are never security leads (T-167).

Scanners report style, readability, performance and portability checks beside their security
checks. cppcheck's ``unusedStructMember``, ``variableScope``, ``constVariablePointer``,
``constParameterPointer`` and ``unreadVariable`` family (native severity ``style``) carries no
security signal, yet every such observation became a lead and a hunt-menu entry. A stylistic
rule class names a scanner and the native severities and/or rule-id globs of its non-security
checks; an observation matching a class is a *stylistic non-lead*: it stays in the observations
index and counts toward scanner coverage, and lead collection records it as not admitted with
reason ``stylistic`` instead of making it a lead.

Configured under ``[jobs.job_inference_security_review.settings.lead_filters]`` as an array of
``stylistic`` tables; the settings are semantic. A class matches an observation when its scanner
glob matches the observation's scanner id (``tool-cppcheck``, ``tool-cppcheck:2.14``) and either
the observation's native severity is one of ``native_severities`` (case-insensitive) or its rule
id matches one of the ``rule_ids`` globs. A class names at least one of the two. The filter
decides nothing about severity: a stylistic observation is not "low", it is not a lead.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from fnmatch import fnmatchcase
import re
from typing import Any, Mapping

FILTER_RULE = "appsec-review/stylistic-lead-filter/1"
STYLISTIC = "stylistic"
_SCANNER = re.compile(r"[A-Za-z0-9_.*?:@+-]{1,128}")
_LABEL = re.compile(r"[A-Za-z0-9_ -]{1,64}")
_RULE_GLOB = re.compile(r"[A-Za-z0-9_.*?/:@+\[\]-]{1,256}")
_MAX_CLASSES = 256
_MAX_ITEMS = 1024


def _strings(value: Any, field: str, pattern: re.Pattern[str], bound: int = _MAX_ITEMS) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > bound or not all(
            isinstance(item, str) and pattern.fullmatch(item) for item in value):
        raise ValueError(f"{field} must be a list of at most {bound} non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} repeats a value")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class StylisticRuleClass:
    """One scanner's non-security checks, by native severity label and/or rule-id glob."""

    scanner: str
    native_severities: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.scanner, str) or not _SCANNER.fullmatch(self.scanner):
            raise ValueError(f"lead_filters.stylistic scanner must be a scanner id or glob: {self.scanner!r}")
        object.__setattr__(self, "native_severities", tuple(
            item.strip().lower() for item in _strings(list(self.native_severities), "lead_filters.stylistic."
                                                     "native_severities", _LABEL)))
        object.__setattr__(self, "rule_ids", _strings(list(self.rule_ids), "lead_filters.stylistic.rule_ids",
                                                      _RULE_GLOB))
        if not self.native_severities and not self.rule_ids:
            raise ValueError("lead_filters.stylistic entries name native_severities or rule_ids (or both)")
        if not isinstance(self.reason, str):
            raise ValueError("lead_filters.stylistic reason must be a string")

    def matches(self, scanner: str, native_severity: str | None, rule_id: str) -> bool:
        names = {scanner, scanner.split(":", 1)[0]}
        if not any(fnmatchcase(name, self.scanner) for name in names):
            return False
        label = (native_severity or "").strip().lower()
        if label and label in self.native_severities:
            return True
        return any(fnmatchcase(rule_id, pattern) for pattern in self.rule_ids)

    def record(self) -> dict[str, Any]:
        return {"scanner": self.scanner, "native_severities": list(self.native_severities),
                "rule_ids": list(self.rule_ids), "reason": self.reason}


@dataclass(frozen=True, slots=True)
class LeadFilters:
    stylistic: tuple[StylisticRuleClass, ...] = ()

    def __post_init__(self) -> None:
        if len(self.stylistic) > _MAX_CLASSES or any(not isinstance(item, StylisticRuleClass) for item in self.stylistic):
            raise ValueError(f"lead_filters.stylistic must hold at most {_MAX_CLASSES} rule classes")

    def stylistic_class(self, scanner: str, native_severity: str | None, rule_id: str) -> StylisticRuleClass | None:
        """The first rule class naming the observation as stylistic, or ``None`` (it may be a lead)."""
        return next((item for item in self.stylistic if item.matches(scanner, native_severity, rule_id)), None)

    @classmethod
    def from_mapping(cls, value: object, field: str = "lead_filters") -> "LeadFilters":
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        unknown = sorted(str(key) for key in set(value) - {"stylistic"})
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        rows = value.get("stylistic", [])
        if not isinstance(rows, list):
            raise ValueError(f"{field}.stylistic must be an array of tables")
        classes = []
        known = {item.name for item in fields(StylisticRuleClass)}
        for index, row in enumerate(rows):
            where = f"{field}.stylistic[{index}]"
            if not isinstance(row, Mapping):
                raise ValueError(f"{where} must be a table")
            extra = sorted(str(key) for key in set(row) - known)
            if extra:
                raise ValueError(f"{where} has unknown settings: {', '.join(extra)}")
            if "scanner" not in row:
                raise ValueError(f"{where} is missing settings: scanner")
            try:
                classes.append(StylisticRuleClass(**{key: (tuple(item) if isinstance(item, list) else item)
                                                     for key, item in row.items()}))
            except ValueError as exc:
                raise ValueError(str(exc).replace("lead_filters.stylistic", where, 1)) from exc
        return cls(tuple(classes))

    def record(self) -> dict[str, Any]:
        return {"rule": FILTER_RULE, "stylistic": [item.record() for item in self.stylistic]}


__all__ = ["FILTER_RULE", "STYLISTIC", "LeadFilters", "StylisticRuleClass"]
