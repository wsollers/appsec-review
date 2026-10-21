"""Producer-specific predicates for a tool observation (``tool-rule-predicates/2``, design R3).

A ``tool_observation`` is direct evidence only for the predicates its *producing rule* names. The
mapping is keyed by lead family, producer (the scanner identity), native rule or query identity and
result kind, never by family alone: a scanner family that includes a path query does not make its
point-in-code results evidence of reachability.

Result kind is ``path`` when the accepted lead carries data-flow steps (``flow_ids``, a SARIF
``codeFlows`` result), else ``point``. Rows are matched in order, the first match wins, and a lead
that matches no row, including every unknown family or rule, gets the narrowest default: no
predicate. (Each family below ends with a catch-all row that names its own narrowest set, usually
``affected_construct`` only.)

| family | producer | rule | result | predicates |
|---|---|---|---|---|
| ``codeql`` | ``codeql`` | any | ``path`` | ``affected_construct``, ``source_to_sink_reachability`` |
| ``codeql`` | ``codeql`` | any | ``point`` | ``affected_construct`` |
| ``source_sast`` | any | any | any | ``affected_construct`` |
| ``artifact_scanner`` | any | any | any | ``affected_construct`` |
| ``dependency_advisory`` | any | any | any | ``affected_construct`` |
| ``ci_rule`` | any | any | any | ``affected_construct``, ``configuration_enables`` |
| ``post_build_hardening`` | any | any | any | ``affected_construct``, ``configuration_enables`` |
| ``owasp_control`` | any | any | any | ``missing_or_ineffective_guard`` |
| anything else | | | | none |

A ``codeql`` lead whose scanner identity is not ``codeql`` matches no codeql row and gets none.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Mapping

from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Predicate

VERSION = "tool-rule-predicates/2"
ANY = "*"
_P = Predicate


@dataclass(frozen=True, slots=True)
class RuleRow:
    family: str
    producer: str            # fnmatch pattern over the scanner identity
    rule: str                # fnmatch pattern over the native rule or query identity
    result: str              # "path", "point" or "*"
    predicates: tuple[Predicate, ...]

    def matches(self, family: str, producer: str, rule: str, result: str) -> bool:
        return (self.family == family and fnmatchcase(producer, self.producer) and fnmatchcase(rule, self.rule)
                and self.result in (ANY, result))


RULES: tuple[RuleRow, ...] = (
    RuleRow("codeql", "codeql", ANY, "path", (_P.AFFECTED_CONSTRUCT, _P.SOURCE_TO_SINK_REACHABILITY)),
    RuleRow("codeql", "codeql", ANY, "point", (_P.AFFECTED_CONSTRUCT,)),
    RuleRow("source_sast", ANY, ANY, ANY, (_P.AFFECTED_CONSTRUCT,)),
    RuleRow("artifact_scanner", ANY, ANY, ANY, (_P.AFFECTED_CONSTRUCT,)),
    RuleRow("dependency_advisory", ANY, ANY, ANY, (_P.AFFECTED_CONSTRUCT,)),
    RuleRow("ci_rule", ANY, ANY, ANY, (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES)),
    RuleRow("post_build_hardening", ANY, ANY, ANY, (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES)),
    RuleRow("owasp_control", ANY, ANY, ANY, (_P.MISSING_OR_INEFFECTIVE_GUARD,)),
)


def result_kind(flow_ids: Any) -> str:
    """``path`` when the lead carries data-flow steps, else ``point``."""
    return "path" if flow_ids else "point"


def predicates_for(family: str, producer: str, rule: str, result: str,
                   rules: tuple[RuleRow, ...] = RULES) -> tuple[Predicate, ...]:
    """The predicates a tool observation is direct for; empty when no row matches."""
    for row in rules:
        if row.matches(str(family), str(producer), str(rule), str(result)):
            return row.predicates
    return ()


def lead_predicates(lead: Mapping[str, Any], rules: tuple[RuleRow, ...] = RULES) -> tuple[Predicate, ...]:
    """The predicates for one lead-menu entry (``review.packages.lead_record``)."""
    return predicates_for(str(lead.get("lead_family", "")), str(lead.get("scanner", "")),
                          str(lead.get("rule_id", "")), result_kind(lead.get("flow_ids")), rules)


def table_record(rules: tuple[RuleRow, ...] = RULES) -> dict[str, Any]:
    return {"version": VERSION,
            "rows": [[row.family, row.producer, row.rule, row.result, [item.value for item in row.predicates]]
                     for row in rules]}


TABLE_SHA256 = sha256_hex(table_record())

__all__ = ["ANY", "RULES", "RuleRow", "TABLE_SHA256", "VERSION", "lead_predicates", "predicates_for",
           "result_kind", "table_record"]
