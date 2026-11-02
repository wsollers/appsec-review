"""Per-producer reports of one run, the scorer's input (docs/reviews/castle-style-detector-scoring.md, decisions 4-5).

Each located tool observation in the run's observation indices becomes one ``Report``; with
``include_review`` the run's accepted final findings are added as producer ``"review"``. Reports are
never deduplicated here: the scorer collapses them by ``Report.identity``. Anything that prevents a
complete extraction is returned as a named gap, never silently dropped.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.acceptance import answer_key
from appsec_review.acceptance.answer_key import _relative
from appsec_review.acceptance.scoring_model import RULE_CWE_REFERENCE, Report, normalize_cwe
from appsec_review.indexing.products import cwe_ids

RULE_CWE_SCHEMA = "appsec-review/rule-cwe/1"
REVIEW_PRODUCER = "review"
GAP_NO_OBSERVATION_INDEX = "no_observation_index"
GAP_REVIEW_UNAVAILABLE = "review_report_unavailable"

_OBSERVATIONS = Path("data") / "indices" / "observations"
_QUERY = ("SELECT e.identity, e.payload_json, l.path, l.start_line, l.end_line "
          "FROM entities e JOIN locations l ON l.entity_id = e.identity "
          "WHERE e.kind = 'tool_observation' ORDER BY e.identity")
# Producer-name fields, most specific first. ``scanner``/``tool`` are decision 5; the rest are where
# evidence collection (``common.scanner``, ``tool_id``) and CodeQL (``producer``) record it.
_PRODUCER_FIELDS = ("scanner", "tool", "tool_id", "scanner_identity", "producer")
_RULE_FIELDS = ("native_rule_id", "rule_id")


def load_rule_cwe(path: Path = RULE_CWE_REFERENCE) -> dict[str, dict[str, frozenset[str]]]:
    """The validated ``producer -> native rule -> CWEs`` fallback table."""

    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: unreadable rule-CWE reference: {error}") from error
    if not isinstance(document, Mapping) or document.get("schema") != RULE_CWE_SCHEMA:
        raise ValueError(f"{path}: schema must be {RULE_CWE_SCHEMA!r}")
    if not isinstance(document.get("source"), str) or not document["source"].strip():
        raise ValueError(f"{path}: a source is required")
    producers = document.get("producers")
    if not isinstance(producers, Mapping):
        raise ValueError(f"{path}: producers must be a mapping")
    table: dict[str, dict[str, frozenset[str]]] = {}
    for producer, rules in producers.items():
        if not producer or producer != producer.strip().lower() or not isinstance(rules, Mapping):
            raise ValueError(f"{path}: producer {producer!r} must be a lowercase name mapping rules")
        table[producer] = {}
        for rule, entry in rules.items():
            if not isinstance(rule, str) or not rule or rule != rule.strip() or not isinstance(entry, Mapping):
                raise ValueError(f"{path}: {producer} rule {rule!r} must be a non-empty id with an entry")
            cwes = entry.get("cwes")
            if (not isinstance(cwes, list) or not cwes
                    or any(not isinstance(cwe, str) or normalize_cwe(cwe) != cwe for cwe in cwes)):
                raise ValueError(f"{path}: {producer} {rule}: cwes must be a non-empty list of normalized CWEs")
            if not isinstance(entry.get("rationale"), str) or not entry["rationale"].strip():
                raise ValueError(f"{path}: {producer} {rule}: a rationale is required")
            table[producer][rule] = frozenset(cwes)
    return table


def producer_name(payload: Mapping[str, Any]) -> str | None:
    """The lowercase producer of an observation payload, without the ``tool-`` image prefix."""

    common = payload.get("common")
    identity = payload.get("tool_identity")
    candidates = [payload.get(name) for name in _PRODUCER_FIELDS[:2]]
    candidates.append(common.get("scanner") if isinstance(common, Mapping) else None)
    candidates.extend(payload.get(name) for name in _PRODUCER_FIELDS[2:])
    candidates.append(identity.get("id") if isinstance(identity, Mapping) else None)
    for value in candidates:
        if isinstance(value, str) and value.strip():
            name = value.strip().lower().removeprefix("tool-")
            if name and name != "unknown":
                return name
    return None


def rule_name(payload: Mapping[str, Any]) -> str:
    common = payload.get("common")
    for value in (*(payload.get(name) for name in _RULE_FIELDS),
                  common.get("rule_id") if isinstance(common, Mapping) else None):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _payload_cwes(payload: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(cwe for cwe in (normalize_cwe(value) for value in cwe_ids(payload)) if cwe)


def _read_shard(path: Path) -> list[tuple[str, str | None, str, int, int | None]]:
    try:
        database = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as error:
        raise ValueError(f"unreadable observation index {path}: {error}") from error
    try:
        return database.execute(_QUERY).fetchall()
    except sqlite3.Error as error:
        raise ValueError(f"unreadable observation index {path}: {error}") from error
    finally:
        database.close()


def _observation_reports(run_root: Path, rule_cwe: Mapping[str, Mapping[str, frozenset[str]]]
                         ) -> tuple[list[Report], list[str]]:
    shards = sorted((run_root / _OBSERVATIONS).glob("**/*.sqlite"))
    if not shards:
        return [], [GAP_NO_OBSERVATION_INDEX]
    reports: list[Report] = []
    without_producer = invalid = 0
    for shard in shards:
        index = shard.relative_to(run_root).as_posix()
        for identity, payload_json, path, start_line, end_line in _read_shard(shard):
            try:
                payload = json.loads(payload_json or "{}")
            except ValueError:
                payload = {}
            payload = payload if isinstance(payload, Mapping) else {}
            producer = producer_name(payload)
            if producer is None:
                without_producer += 1
                continue
            if not isinstance(path, str) or not path or not isinstance(start_line, int) or start_line < 1:
                invalid += 1
                continue
            end = end_line if isinstance(end_line, int) and end_line >= start_line else start_line
            rule = rule_name(payload)
            cwes = _payload_cwes(payload) or rule_cwe.get(producer, {}).get(rule, frozenset())
            reports.append(Report(producer, _relative(path), start_line, end, rule, cwes, f"{index}#{identity}"))
    gaps = []
    if without_producer:
        gaps.append(f"observations_without_producer:{without_producer}")
    if invalid:
        gaps.append(f"observations_without_location:{invalid}")
    return reports, gaps


def _claim_weaknesses(projection: Mapping[str, Any]) -> dict[str, frozenset[str]]:
    claims = projection.get("claims", ())
    rows = list(claims.values()) if isinstance(claims, Mapping) else claims if isinstance(claims, list) else []
    weaknesses = {}
    for row in rows:
        if isinstance(row, Mapping) and isinstance(row.get("claim_id"), str):
            cwe = normalize_cwe(row.get("weakness_cwe"))
            weaknesses[row["claim_id"]] = frozenset({cwe} if cwe else ())
    return weaknesses


def _finding_cwes(finding: Mapping[str, Any], weaknesses: Mapping[str, frozenset[str]]) -> frozenset[str]:
    values: list[Any] = []
    for key in ("cwe", "cwes", "weakness_cwe"):
        value = finding.get(key)
        values.extend(value if isinstance(value, (list, tuple, set, frozenset)) else [value])
    found = frozenset(cwe for cwe in (normalize_cwe(value) for value in values) if cwe)
    return found or weaknesses.get(str(finding.get("claim_id")), frozenset())


def _review_reports(run_root: Path) -> tuple[list[Report], list[str]]:
    """Accepted final findings as producer ``review``; their CWE is the claim's ``weakness_cwe``."""

    try:
        from appsec_review.acceptance.system import accepted_final_report
        from appsec_review.storage.validation import validation_scope

        with validation_scope(run_root):
            findings = answer_key.current_report_findings(run_root)
            weaknesses = _claim_weaknesses(accepted_final_report(run_root)[2]) if findings else {}
    except (ImportError, OSError, RuntimeError, ValueError, LookupError, TypeError, sqlite3.Error):
        # RuntimeError covers IntegrityError/RetrievalGap: no current accepted report to score.
        return [], [GAP_REVIEW_UNAVAILABLE]
    reports = []
    for finding in findings:
        record = finding.get("record", {})
        start = record.get("start_line")
        if not isinstance(record.get("path"), str) or not isinstance(start, int) or start < 1:
            continue
        end = record.get("end_line") if isinstance(record.get("end_line"), int) else start
        reports.append(Report(REVIEW_PRODUCER, _relative(record["path"]), start, max(end, start), "",
                              _finding_cwes(finding, weaknesses), str(finding.get("evidence_id", ""))))
    return reports, []


def reports_from_run(run_root: Path, *, include_review: bool = False) -> tuple[list[Report], list[str]]:
    """Every located report of ``run_root``'s producers, deterministically ordered, and the named gaps."""

    run_root = Path(run_root)
    reports, gaps = _observation_reports(run_root, load_rule_cwe())
    if include_review:
        review, review_gaps = _review_reports(run_root)
        reports.extend(review)
        gaps.extend(review_gaps)
    reports.sort(key=lambda report: (report.producer, report.path, report.start_line, report.rule, report.evidence))
    with_cwe: dict[str, bool] = {}
    for report in reports:
        with_cwe[report.producer] = with_cwe.get(report.producer, False) or bool(report.cwes)
    gaps.extend(f"producer_without_cwe:{producer}" for producer in sorted(with_cwe) if not with_cwe[producer])
    return reports, gaps
