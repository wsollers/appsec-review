"""Fixture expectation annotations for the SEI CERT rule pack.

A fixture line comment of the form ``// cert: <kind> <rule-id> [engines=<engine>[,<engine>]]``
binds an expectation to the next line that is neither blank nor another annotation. Positive kinds
require a finding of ``rule-id`` that starts on that line; every other kind requires that no
finding of ``rule-id`` starts there. Any finding on a line without a positive expectation for that
rule is an unexpected result.

``unmodeled-exception:<EXCEPTION-ID>`` documents a line that a CERT exception permits but that
the rule cannot recognize syntactically. A finding is expected there and is counted as a known
false positive, so the limitation is tested rather than hidden.

``known-false-negative`` documents a noncompliant line the rule is known to miss (for example a
call hidden behind a macro). It is asserted to be unmatched and is counted as a false negative,
so an engine limitation is visible in every evaluation instead of being hidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

POSITIVE_KINDS = frozenset({"positive", "variant"})
NEGATIVE_KINDS = frozenset({"negative", "near-miss", "safe-alternative", "known-false-negative"})
EXCEPTION_PREFIX = "exception:"
UNMODELED_EXCEPTION_PREFIX = "unmodeled-exception:"
_ANNOTATION = re.compile(
    r"//\s*cert:\s*(?P<kind>[a-z-]+(?::[A-Z0-9-]+)?)\s+(?P<rule>[a-z0-9.\-]+)"
    r"(?:\s+engines=(?P<engines>[a-z,]+))?\s*$"
)
_LOOSE = re.compile(r"//\s*cert:")


@dataclass(frozen=True, slots=True)
class Expectation:
    path: str
    annotation_line: int
    line: int
    kind: str
    rule_id: str
    engines: tuple[str, ...] | None

    @property
    def positive(self) -> bool:
        return self.kind in POSITIVE_KINDS or self.kind.startswith(UNMODELED_EXCEPTION_PREFIX)

    @property
    def exception_id(self) -> str | None:
        for prefix in (EXCEPTION_PREFIX, UNMODELED_EXCEPTION_PREFIX):
            if self.kind.startswith(prefix):
                return self.kind[len(prefix):]
        return None

    def applies_to(self, engine: str) -> bool:
        return self.engines is None or engine in self.engines


def parse_expectations(path: Path, relative: str) -> list[Expectation]:
    """Parse and bind every annotation; malformed or dangling annotations are errors."""
    lines = path.read_text(encoding="utf-8").splitlines()
    expectations: list[Expectation] = []
    pending: list[tuple[int, str, str, tuple[str, ...] | None]] = []
    for number, text in enumerate(lines, start=1):
        stripped = text.strip()
        if _LOOSE.search(stripped):
            match = _ANNOTATION.search(stripped)
            if match is None or not stripped.startswith("//"):
                raise ValueError(f"{relative}:{number}: malformed cert annotation")
            kind = match.group("kind")
            if (kind not in POSITIVE_KINDS | NEGATIVE_KINDS and not kind.startswith(EXCEPTION_PREFIX)
                    and not kind.startswith(UNMODELED_EXCEPTION_PREFIX)):
                raise ValueError(f"{relative}:{number}: unknown expectation kind {kind!r}")
            engines = tuple(match.group("engines").split(",")) if match.group("engines") else None
            pending.append((number, kind, match.group("rule"), engines))
            continue
        if not stripped or not pending:
            continue
        for annotation_line, kind, rule_id, engines in pending:
            expectations.append(Expectation(relative, annotation_line, number, kind, rule_id, engines))
        pending = []
    if pending:
        raise ValueError(f"{relative}:{pending[0][0]}: annotation is not followed by a code line")
    return expectations
