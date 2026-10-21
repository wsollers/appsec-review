"""Typed settings and the versioned deterministic rule table of lead severity triage.

``jobs.job_inference_security_review.settings.triage`` holds the switch, the batching and prompt bounds, the
model profile name, and the ``lead-severity-rules/1`` table that decides the clearly decidable leads before any
model call. The table is semantic configuration: it enters the configuration hash, and every triage fingerprint
names its version and content hash, so editing a row invalidates cached triage results.

Light on purpose (no guidance, retrieval or scoring imports): the central configuration parser imports it.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import re
from typing import Any, Mapping

RULE_TABLE_VERSION = "lead-severity-rules/1"
ASSESSABLE = ("critical", "high", "medium", "low", "info")
RULE_BASES = ("rule_semantics", "exposure")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}")
_SCANNER = re.compile(r"\*|[a-z0-9][a-z0-9_.-]{0,63}")
_PROFILE = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_REASON = 200


def scanner_key(scanner: str) -> str:
    """``tool-gitleaks:8.2:adapter-1`` -> ``gitleaks``: the scanner id the table is keyed by."""
    name = str(scanner).split(":", 1)[0].strip().lower()
    return name[5:] if name.startswith("tool-") else name


@dataclass(frozen=True, slots=True)
class TriageRule:
    """One row of ``lead-severity-rules/1``: (scanner, rule id) or CWE -> severity, with its basis and reason.

    ``scanner = "*"`` with a ``cwe`` matches any scanner's lead carrying that rule CWE; a scanner with
    ``rule = "*"`` matches every rule of that scanner. The most specific matching row decides: scanner and
    rule, then scanner alone, then CWE.
    """

    scanner: str
    severity: str
    basis: str
    reason: str
    rule: str = "*"
    cwe: str | None = None

    def __post_init__(self) -> None:
        if not _SCANNER.fullmatch(self.scanner) or self.scanner != self.scanner.lower():
            raise ValueError(f"triage rule scanner is invalid: {self.scanner!r}")
        if self.severity not in ASSESSABLE:
            raise ValueError(f"triage rule severity must be one of: {', '.join(ASSESSABLE)}")
        if self.basis not in RULE_BASES:
            raise ValueError(f"triage rule basis must be one of: {', '.join(RULE_BASES)}")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > MAX_REASON:
            raise ValueError(f"triage rule reason must be 1-{MAX_REASON} characters")
        if not isinstance(self.rule, str) or not self.rule or len(self.rule) > 200:
            raise ValueError("triage rule rule must be a rule id or '*'")
        if self.cwe is not None and not _CWE.fullmatch(self.cwe):
            raise ValueError(f"triage rule cwe is invalid: {self.cwe!r}")
        if self.cwe is None and self.scanner == "*":
            raise ValueError("a triage rule needs a scanner or a CWE")
        if self.cwe is not None and (self.scanner != "*" or self.rule != "*"):
            raise ValueError("a CWE triage rule takes scanner '*' and rule '*'")

    @property
    def key(self) -> str:
        return self.cwe if self.cwe else f"{self.scanner}/{self.rule}"

    def matches(self, scanner: str, rule_id: str, cwes: tuple[str, ...]) -> int:
        """Specificity (3 scanner+rule, 2 scanner, 1 CWE) when the row matches the lead, else 0."""
        if self.cwe is not None:
            return 1 if self.cwe in cwes else 0
        if scanner_key(scanner) != self.scanner:
            return 0
        if self.rule == "*":
            return 2
        return 3 if rule_id.strip().lower() == self.rule.lower() else 0

    def record(self) -> dict[str, Any]:
        return {"key": self.key, "scanner": self.scanner, "rule": self.rule, "cwe": self.cwe,
                "severity": self.severity, "basis": self.basis, "reason": self.reason}


def table_sha256(rules: tuple[TriageRule, ...]) -> str:
    body = {"version": RULE_TABLE_VERSION, "rules": [rule.record() for rule in rules]}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TriageSettings:
    """``settings.triage``. Absent from a configuration means triage is off and no model profile is needed."""

    enabled: bool = False
    batch_size: int = 20
    model_profile: str = "triage"
    max_leads: int = 200
    max_excerpt_lines: int = 24
    max_reason_chars: int = MAX_REASON
    rules: tuple[TriageRule, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("triage.enabled must be a Boolean")
        for name, low, high in (("batch_size", 1, 100), ("max_leads", 0, 100_000), ("max_excerpt_lines", 1, 200),
                                ("max_reason_chars", 20, MAX_REASON)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"triage.{name} must be an integer between {low} and {high}")
        if not isinstance(self.model_profile, str) or not _PROFILE.fullmatch(self.model_profile):
            raise ValueError("triage.model_profile is invalid")
        keys = [rule.key for rule in self.rules]
        if len(set(keys)) != len(keys):
            raise ValueError("triage.rules repeats a (scanner, rule) or CWE row")

    @property
    def table_sha256(self) -> str:
        return table_sha256(self.rules)

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "TriageSettings":
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        known = {item.name for item in fields(cls)}
        unknown = sorted(str(key) for key in set(value) - known)
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        if "enabled" not in value:
            raise ValueError(f"{field} is missing settings: enabled")
        rows = value.get("rules", [])
        if not isinstance(rows, list):
            raise ValueError(f"{field}.rules must be an array of tables")
        rules = []
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise ValueError(f"{field}.rules[{index}] must be a table")
            extra = sorted(str(key) for key in set(row) - {"scanner", "rule", "cwe", "severity", "basis", "reason"})
            if extra:
                raise ValueError(f"{field}.rules[{index}] has unknown settings: {', '.join(extra)}")
            try:
                rules.append(TriageRule(**dict(row)))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{field}.rules[{index}]: {exc}") from exc
        try:
            return cls(**{**{key: item for key, item in value.items() if key != "rules"}, "rules": tuple(rules)})
        except ValueError as exc:
            raise ValueError(f"{field}: {exc}") from exc


__all__ = ["ASSESSABLE", "MAX_REASON", "RULE_BASES", "RULE_TABLE_VERSION", "TriageRule", "TriageSettings",
           "scanner_key", "table_sha256"]
