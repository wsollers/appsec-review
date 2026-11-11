"""Shared contract of the finding-metrics domain (docs/architecture/finding-metrics.md).

Closed vocabularies, the normalized finding record, the immutable finding snapshot and the ratio
helpers every other module of ``observability.findings`` imports. Nothing here reads a run, a
target or a model; adapters that do live in ``run_adapter``.

Doctrine shared by the whole domain:

* An unavailable input is ``None`` with a named reason, never zero.
* Every proportion carries its numerator and denominator; proportions over independent units also
  carry a Wilson interval.
* Labels come from an answer key, a developer outcome, a human audit sample or a crash report.
  A model's dismissal, confidence or agreement is never a label.
* Units are never mixed: observation, lead, claim, finding (root cause), key case, crash bucket.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
import hashlib
import math
import re
from typing import Any

from appsec_review.storage import canonical_json

SNAPSHOT_SCHEMA = "appsec-review/finding-snapshot/1"
METRICS_SCHEMA = "appsec-review/finding-metrics/1"
HISTORY_SCHEMA = "appsec-review/finding-history/1"
LABEL_SET_SCHEMA = "appsec-review/finding-labels/1"
OUTCOME_FILE_SCHEMA = "appsec-review/developer-outcomes/1"
AUDIT_SAMPLE_SCHEMA = "appsec-review/audit-sample/1"
CRASH_REPORT_SCHEMA = "appsec-review/crash-report/1"
CRASH_EVIDENCE_SCHEMA = "appsec-review/crash-evidence/1"
FINGERPRINT_VERSION = "finding-fingerprint/1"

MAX_FINDINGS = 10_000          # per snapshot
MAX_LOCATIONS = 64             # per finding
MAX_CODE_CHARS = 16_000        # per location excerpt
MAX_LEADS = 100_000            # per triage computation
MAX_CRASH_REPORTS = 50_000     # per ingestion
MAX_FRAMES = 128               # per crash report

SEVERITY_BANDS = ("low", "medium", "high", "critical")
ACTIONABLE_BANDS = ("high", "critical")
PUBLISHED_STATES = ("confirmed", "supported")
BUCKETS = ("findings", "verification_backlog", "withheld")
LANES = ("lead", "hunt")
SHIP_BLOCK_STATUSES = ("ship_blocking", "ship_blocking_pending_distinct_verification", "needs_verification",
                       "decision_pending", "not_ship_blocking")
TRIAGE_STAGES = ("red_no_proposal", "blue", "judge", "verifier", "unattributed")


class LifecycleState(StrEnum):
    NEW = "new"
    REGRESSED = "regressed"
    PERSISTING = "persisting"
    NOT_COVERED = "not_covered"
    NOT_REDETECTED = "not_redetected"
    FIX_CANDIDATE = "fix_candidate"
    FIXED = "fixed"
    STILL_PRESENT = "still_present"


class MatchTier(StrEnum):
    EXACT = "exact"
    RELOCATED = "relocated"


class LabelSource(StrEnum):
    """Label sources in descending authority for correctness."""

    ANSWER_KEY = "answer_key"
    DEVELOPER_OUTCOME = "developer_outcome"
    AUDIT_SAMPLE = "audit_sample"
    CRASH = "crash"


LABEL_AUTHORITY = tuple(source.value for source in LabelSource)


class LabelOutcome(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNRESOLVED = "unresolved"


class DeveloperDisposition(StrEnum):
    FIXED = "fixed"
    REJECTED_FALSE = "rejected_false"
    ACCEPTED_RISK = "accepted_risk"
    DUPLICATE = "duplicate"


class AttackerPosition(StrEnum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"
    PEER_TO_PEER = "peer_to_peer"
    HOSTILE_CONTENT = "hostile_content"
    LOCAL = "local"


class Ownership(StrEnum):
    FIRST_PARTY = "first_party"
    ENGINE = "engine"
    MIDDLEWARE = "middleware"


class BuildConfiguration(StrEnum):
    SHIPPING = "shipping"
    DEVELOPMENT = "development"
    EDITOR_OR_TEST = "editor_or_test"


class FaultClass(StrEnum):
    """Deterministic crash fault classes, most review-worthy first. Ordering, never a severity."""

    WRITE_ACCESS_VIOLATION = "write_access_violation"
    EXECUTE_ACCESS_VIOLATION = "execute_access_violation"
    SANITIZER_MEMORY_ERROR = "sanitizer_memory_error"
    HEAP_CORRUPTION = "heap_corruption"
    STACK_COOKIE = "stack_cookie"
    WILD_READ = "wild_read"
    STACK_OVERFLOW = "stack_overflow"
    SANITIZER_UNDEFINED = "sanitizer_undefined"
    SANITIZER_RACE = "sanitizer_race"
    NEAR_NULL_READ = "near_null_read"
    ASSERTION = "assertion"
    ABORT = "abort"
    OUT_OF_MEMORY = "out_of_memory"
    UNKNOWN = "unknown"


FAULT_ORDER = tuple(item.value for item in FaultClass)
MEMORY_SAFETY_FAULTS = frozenset({
    FaultClass.WRITE_ACCESS_VIOLATION.value, FaultClass.EXECUTE_ACCESS_VIOLATION.value,
    FaultClass.SANITIZER_MEMORY_ERROR.value, FaultClass.HEAP_CORRUPTION.value,
    FaultClass.STACK_COOKIE.value, FaultClass.WILD_READ.value})


class BindingTier(StrEnum):
    BUILD_MATCHED = "build_matched"
    REVISION_MATCHED = "revision_matched"
    SYMBOL_MATCHED = "symbol_matched"
    UNBOUND = "unbound"


# Repository-defined weakness families (finding-metrics.md section 4.1). A CWE outside the table is
# its own family. The table groups weaknesses a reviewer may name differently for one root cause;
# it is not a MITRE view and is never used to widen a strict scanner match.
WEAKNESS_FAMILIES: Mapping[str, frozenset[int]] = {
    "memory_safety": frozenset({119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 131, 170, 415, 416, 476, 590,
                                761, 762, 787, 788, 805, 806, 822, 823, 824, 825}),
    "numeric": frozenset({190, 191, 192, 194, 195, 196, 197, 369, 680, 681}),
    "format_string": frozenset({134}),
    "injection": frozenset({74, 77, 78, 79, 80, 88, 89, 90, 91, 94, 95, 96, 917, 943}),
    "path_and_file": frozenset({22, 23, 36, 59, 73, 434}),
    "credentials_and_crypto": frozenset({256, 257, 259, 311, 312, 319, 321, 326, 327, 328, 330, 338, 522, 798, 916}),
    "authorization_and_trust": frozenset({269, 284, 285, 287, 306, 602, 639, 732, 807, 862, 863}),
    "input_and_deserialization": frozenset({20, 502, 611, 1284, 1285}),
    "concurrency": frozenset({362, 364, 366, 367, 667, 833}),
    "resource_management": frozenset({400, 401, 404, 674, 770, 772, 835}),
    "information_exposure": frozenset({200, 201, 209, 532}),
}
_CWE = re.compile(r"^(?:CWE-)?(\d{1,5})$", re.I)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def normalize_cwe(value: Any) -> str | None:
    """``"CWE-<n>"`` for a CWE given as ``"CWE-120"``, ``"cwe-120"``, ``"120"`` or ``120``; else ``None``."""
    if isinstance(value, bool):
        return None
    match = _CWE.match(str(value).strip()) if isinstance(value, (str, int)) else None
    return f"CWE-{int(match.group(1))}" if match else None


def weakness_family(cwe: Any) -> str | None:
    """The family of a CWE: a ``WEAKNESS_FAMILIES`` name, the normalized CWE itself, or ``None``."""
    normalized = normalize_cwe(cwe)
    if normalized is None:
        return None
    number = int(normalized[4:])
    for family in sorted(WEAKNESS_FAMILIES):
        if number in WEAKNESS_FAMILIES[family]:
            return family
    return normalized


def digest(value: Any) -> str:
    """SHA-256 of the repository canonical JSON of ``value``."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256.match(value))


# ------------------------------------------------------------------------------------- ratios

_Z95 = 1.959963984540054


def wilson(numerator: int, denominator: int) -> dict[str, float] | None:
    """The 95% Wilson score interval of a binomial proportion; ``None`` for an empty denominator."""
    if denominator <= 0:
        return None
    p = numerator / denominator
    z2 = _Z95 * _Z95
    centre = (p + z2 / (2 * denominator)) / (1 + z2 / denominator)
    half = (_Z95 * math.sqrt(p * (1 - p) / denominator + z2 / (4 * denominator * denominator))
            / (1 + z2 / denominator))
    return {"low": round(max(0.0, centre - half), 6), "high": round(min(1.0, centre + half), 6), "level": 0.95}


def ratio(numerator: int | None, denominator: int | None, *, reason: str | None = None,
          interval: bool = False) -> dict[str, Any]:
    """A reported proportion. ``status`` is ``measured``, ``empty_denominator`` or ``unavailable``.

    ``interval=True`` adds the Wilson interval; use it only when the denominator counts independent
    units (key cases, sampled leads, findings), never overlapping run pairs.
    """
    available = numerator is not None and denominator is not None
    if available and (isinstance(numerator, bool) or isinstance(denominator, bool)
                      or numerator < 0 or denominator < 0 or numerator > denominator):   # type: ignore[operator]
        raise ValueError(f"invalid proportion {numerator!r}/{denominator!r}")
    measured = available and bool(denominator)
    result: dict[str, Any] = {
        "numerator": numerator, "denominator": denominator,
        "value": round(numerator / denominator, 6) if measured else None,   # type: ignore[operator]
        "status": "measured" if measured else "empty_denominator" if available else "unavailable",
        "reason": None if measured else "zero_denominator" if available else (reason or "input_unavailable"),
    }
    if interval:
        result["interval"] = wilson(numerator, denominator) if measured else None   # type: ignore[arg-type]
    return result


def unavailable(reason: str) -> dict[str, Any]:
    """A whole metric section that could not be computed: never zero, always a named reason."""
    if not reason or not isinstance(reason, str):
        raise ValueError("an unavailable section needs a named reason")
    return {"available": False, "reason": reason}


def counts(values: Iterable[Any], vocabulary: Sequence[str]) -> dict[str, int]:
    """Zero-filled counts over a closed vocabulary plus ``"null"`` for a value not established."""
    table = {name: 0 for name in vocabulary}
    table["null"] = 0
    for value in values:
        key = "null" if value is None else str(value)
        if key not in table:
            raise ValueError(f"value {key!r} is outside the closed vocabulary")
        table[key] += 1
    return table


# ------------------------------------------------------------------------------------ records

_OPTIONAL_ENUMS: Mapping[str, Sequence[str]] = {
    "lane": LANES, "bucket": BUCKETS, "severity": SEVERITY_BANDS, "ship_block_status": SHIP_BLOCK_STATUSES,
    "attacker_position": tuple(item.value for item in AttackerPosition),
    "ownership": tuple(item.value for item in Ownership),
    "build_configuration": tuple(item.value for item in BuildConfiguration),
}
_OPTIONAL_TEXT = ("claim_id", "security_predicate", "source_symbol", "sink_symbol", "component", "owner")
_ACTIONABILITY = ("entry_to_sink_path", "preconditions", "remediation", "remediation_validated")
FINDING_FIELDS = ("finding_id", "state", "weakness_cwe", "locations", "lead_families", "scanner_backed",
                  "duplicates_collapsed", "actionability", "citations", "verification",
                  *_OPTIONAL_ENUMS, *_OPTIONAL_TEXT)


def _text(value: Any, name: str, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or len(value) > 512 or "\n" in value or "\r" in value:
        raise ValueError(f"finding {name} must be a short single-line string")
    return value


def _flag(value: Any, name: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"finding {name} must be a Boolean or null")
    return value


def _count(value: Any, name: str, *, optional: bool = True) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"finding {name} must be a non-negative integer")
    return value


def normalize_path(value: Any) -> str:
    """A canonical target-relative POSIX path; absolute, escaping or Windows-style paths are refused."""
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise ValueError("location path must be a non-empty string")
    if "\\" in value or ":" in value or value.startswith("/") or "\n" in value or "\r" in value:
        raise ValueError(f"location path is not target-relative POSIX: {value!r}")
    parts = [part for part in value.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        raise ValueError(f"location path escapes the target: {value!r}")
    return "/".join(parts)


def normalize_location(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("finding location must be an object")
    start, end = value.get("start_line"), value.get("end_line", value.get("start_line"))
    for line in (start, end):
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ValueError("location lines must be positive integers")
    if end < start:
        raise ValueError("location end_line precedes start_line")
    code = value.get("code")
    if code is not None and (not isinstance(code, str) or len(code) > MAX_CODE_CHARS):
        raise ValueError("location code must be a bounded string or null")
    return {"path": normalize_path(value.get("path")), "start_line": start, "end_line": end,
            "function": _text(value.get("function"), "location function"), "code": code}


def normalize_finding(value: Any) -> dict[str, Any]:
    """Validate and canonicalize one finding record; unknown fields and open vocabularies are refused.

    Required: ``finding_id``, ``state``, ``locations`` (at least one). Everything else defaults to
    ``None`` (not established) or an empty/zero value, so a metric can report it as its own row.
    """
    if not isinstance(value, Mapping):
        raise ValueError("finding record must be an object")
    unknown = sorted(str(key) for key in set(value) - set(FINDING_FIELDS) - {"fingerprint"})
    if unknown:
        raise ValueError(f"finding record has unknown fields: {', '.join(unknown)}")
    locations = value.get("locations")
    if not isinstance(locations, (list, tuple)) or not 1 <= len(locations) <= MAX_LOCATIONS:
        raise ValueError("finding needs between 1 and the bounded number of locations")
    record: dict[str, Any] = {
        "finding_id": _text(value.get("finding_id"), "finding_id", optional=False),
        "state": _text(value.get("state"), "state", optional=False),
        "weakness_cwe": None if value.get("weakness_cwe") is None else normalize_cwe(value["weakness_cwe"]),
        "locations": sorted((normalize_location(item) for item in locations),
                            key=lambda item: (item["path"], item["start_line"], item["end_line"])),
        "lead_families": sorted({_text(item, "lead family", optional=False)   # type: ignore[misc]
                                 for item in value.get("lead_families", ())}),
        "scanner_backed": _flag(value.get("scanner_backed"), "scanner_backed"),
        "duplicates_collapsed": _count(value.get("duplicates_collapsed", 0), "duplicates_collapsed", optional=False),
    }
    if value.get("weakness_cwe") is not None and record["weakness_cwe"] is None:
        raise ValueError(f"finding weakness_cwe is not a CWE: {value['weakness_cwe']!r}")
    for name, vocabulary in _OPTIONAL_ENUMS.items():
        item = value.get(name)
        if item is not None and item not in vocabulary:
            raise ValueError(f"finding {name} {item!r} is outside its closed vocabulary")
        record[name] = item
    for name in _OPTIONAL_TEXT:
        record[name] = _text(value.get(name), name)
    actionability = value.get("actionability") or {}
    citations = value.get("citations") or {}
    verification = value.get("verification") or {}
    for group, allowed in ((actionability, _ACTIONABILITY), (citations, ("total", "unresolved")),
                           (verification, ("verifier_overturned", "distinct_model"))):
        if not isinstance(group, Mapping) or set(group) - set(allowed):
            raise ValueError("finding actionability, citations or verification has unknown fields")
    record["actionability"] = {name: _flag(actionability.get(name), name) for name in _ACTIONABILITY}
    record["citations"] = {name: _count(citations.get(name), f"citations {name}") for name in ("total", "unresolved")}
    total, unresolved = record["citations"]["total"], record["citations"]["unresolved"]
    if total is not None and unresolved is not None and unresolved > total:
        raise ValueError("finding has more unresolved citations than citations")
    record["verification"] = {name: _flag(verification.get(name), name)
                              for name in ("verifier_overturned", "distinct_model")}
    return record


def is_published(finding: Mapping[str, Any]) -> bool:
    """A finding a team would be shown: state confirmed or supported."""
    return finding.get("state") in PUBLISHED_STATES


def is_actionable(finding: Mapping[str, Any]) -> bool:
    """Confirmed and rated high or critical: the unit of actionable yield."""
    return finding.get("state") == "confirmed" and finding.get("severity") in ACTIONABLE_BANDS


# ------------------------------------------------------------------------------------ snapshot

_IDENTITY_HASHES = ("configuration_sha256", "guidance_sha256", "model_sha256")
SNAPSHOT_FIELDS = ("schema", "run_id", "target_id", "source_revision", "stage", *_IDENTITY_HASHES,
                   "reviewed_units", "unreviewed_units", "findings", "gaps")
SNAPSHOT_STAGES = ("candidate", "verified", "published")


def build_snapshot(*, run_id: str, target_id: str, source_revision: str, findings: Iterable[Mapping[str, Any]],
                   fingerprint, stage: str = "published",
                   reviewed_units: Mapping[str, str | None] | None = None,
                   unreviewed_units: Mapping[str, str] | None = None, gaps: Iterable[str] = (),
                   configuration_sha256: str | None = None, guidance_sha256: str | None = None,
                   model_sha256: str | None = None) -> dict[str, Any]:
    """The immutable ``finding-snapshot/1`` of one run at one stage.

    ``fingerprint`` is ``identity.fingerprint`` (injected so this module stays import-free of it).
    ``reviewed_units`` maps the target-relative path of each unit reviewed this run to the SHA-256
    of its content at ``source_revision`` (``None`` when the hash is unknown), or is ``None`` when
    coverage is unknown; ``unreviewed_units`` maps a path to its residual-coverage reason.
    Findings sharing a fingerprint collapse into the first in ``finding_id`` order, which counts
    the others in ``duplicates_collapsed``.
    """
    if stage not in SNAPSHOT_STAGES:
        raise ValueError(f"unknown snapshot stage {stage!r}")
    hashes = {"configuration_sha256": configuration_sha256, "guidance_sha256": guidance_sha256,
              "model_sha256": model_sha256}
    for name, item in hashes.items():
        if item is not None and not is_sha256(item):
            raise ValueError(f"snapshot {name} must be a SHA-256 or null")
    merged: dict[str, dict[str, Any]] = {}
    total = 0
    for raw in sorted((normalize_finding(item) for item in findings), key=lambda item: item["finding_id"]):
        total += 1
        if total > MAX_FINDINGS:
            raise ValueError("snapshot exceeds the bounded number of findings")
        identity = fingerprint(raw)
        first = merged.get(identity["exact"])
        if first is None:
            merged[identity["exact"]] = {**raw, "fingerprint": identity}
        else:
            first["duplicates_collapsed"] += 1 + raw["duplicates_collapsed"]
    ids = [item["finding_id"] for item in merged.values()]
    if len(ids) != len(set(ids)):
        raise ValueError("snapshot repeats a finding_id")
    reviewed: dict[str, str | None] | None = None
    if reviewed_units is not None:
        reviewed = {}
        for path, content in sorted(reviewed_units.items()):
            if content is not None and not is_sha256(content):
                raise ValueError("a reviewed unit's content identity must be a SHA-256 or null")
            reviewed[normalize_path(path)] = content
    return {
        "schema": SNAPSHOT_SCHEMA,
        "run_id": _text(run_id, "run_id", optional=False),
        "target_id": _text(target_id, "target_id", optional=False),
        "source_revision": _text(source_revision, "source_revision", optional=False),
        "stage": stage, **hashes,
        "reviewed_units": reviewed,
        "unreviewed_units": None if unreviewed_units is None else {
            normalize_path(path): _text(reason, "residual coverage reason", optional=False)
            for path, reason in sorted(unreviewed_units.items())},
        "findings": sorted(merged.values(), key=lambda item: item["finding_id"]),
        "gaps": sorted({_text(item, "gap", optional=False) for item in gaps}),   # type: ignore[misc]
    }


def check_snapshot(value: Any) -> dict[str, Any]:
    """A stored snapshot's shape; raises ``ValueError`` for anything that is not ``finding-snapshot/1``."""
    if not isinstance(value, Mapping) or value.get("schema") != SNAPSHOT_SCHEMA:
        raise ValueError("unsupported finding snapshot schema")
    if set(value) != set(SNAPSHOT_FIELDS):
        raise ValueError("finding snapshot has missing or unknown fields")
    if value["stage"] not in SNAPSHOT_STAGES or not isinstance(value["findings"], list):
        raise ValueError("finding snapshot stage or findings are invalid")
    if len(value["findings"]) > MAX_FINDINGS:
        raise ValueError("finding snapshot exceeds the bounded number of findings")
    for finding in value["findings"]:
        identity = finding.get("fingerprint") if isinstance(finding, Mapping) else None
        if (not isinstance(identity, Mapping) or identity.get("version") != FINGERPRINT_VERSION
                or not is_sha256(identity.get("exact")) or not is_sha256(identity.get("relocated"))):
            raise ValueError("finding snapshot holds a finding without a valid fingerprint")
        normalize_finding({key: item for key, item in finding.items() if key != "fingerprint"})
    return dict(value)


__all__ = [
    "ACTIONABLE_BANDS", "AUDIT_SAMPLE_SCHEMA", "AttackerPosition", "BUCKETS", "BindingTier", "BuildConfiguration",
    "CRASH_EVIDENCE_SCHEMA", "CRASH_REPORT_SCHEMA", "DeveloperDisposition", "FAULT_ORDER", "FINDING_FIELDS",
    "FINGERPRINT_VERSION", "FaultClass", "HISTORY_SCHEMA", "LABEL_AUTHORITY", "LABEL_SET_SCHEMA", "LANES",
    "LabelOutcome", "LabelSource", "LifecycleState", "MAX_CODE_CHARS", "MAX_CRASH_REPORTS", "MAX_FINDINGS",
    "MAX_FRAMES", "MAX_LEADS", "MAX_LOCATIONS", "MEMORY_SAFETY_FAULTS", "METRICS_SCHEMA", "MatchTier",
    "OUTCOME_FILE_SCHEMA", "Ownership", "PUBLISHED_STATES", "SEVERITY_BANDS", "SHIP_BLOCK_STATUSES",
    "SNAPSHOT_FIELDS", "SNAPSHOT_SCHEMA", "SNAPSHOT_STAGES", "TRIAGE_STAGES", "WEAKNESS_FAMILIES",
    "build_snapshot", "check_snapshot", "counts", "digest", "is_actionable", "is_published", "is_sha256",
    "normalize_cwe", "normalize_finding", "normalize_location", "normalize_path", "ratio", "unavailable",
    "weakness_family", "wilson",
]
