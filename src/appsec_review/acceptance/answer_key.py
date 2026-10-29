"""Evaluate a run's findings against a corpus answer key.

The key (``test/acceptance/<tag>/expectations.toml``) lists the defects seeded in a blind corpus.
Each is *found* when some finding of the run names its file and its reported lines overlap the defect's lines
(``line``, through ``end_line`` when the defect spans several), *missed*
otherwise. A finding that matches no defect is *spurious*; it is reported and never fails the run
(docs/processes/acceptance-and-regression-testing.md, Decision 2). A missed defect is the failure.
``producers`` in the key are a hypothesis: which producers reported each found defect is reported
for information and never gates the result.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import glob
import json
from pathlib import Path
import sqlite3
import tomllib
from typing import Any

LINE_TOLERANCE = 0
_FINDING_KINDS = {"tool_observation"}


@dataclass(frozen=True)
class Defect:
    id: str
    cwe: str
    path: str
    line: int
    summary: str
    producers: tuple[str, ...]
    end_line: int | None = None
    claim_id: str | None = None
    finding_package_id: str | None = None
    state: str = "confirmed"
    bucket: str = "publishable"


@dataclass
class AnswerKeyReport:
    found: dict[str, list[str]] = field(default_factory=dict)  # defect id -> evidence "job: name"
    missed: list[str] = field(default_factory=list)
    spurious: int = 0
    producers_seen: dict[str, list[str]] = field(default_factory=dict)  # defect id -> producers observed
    producers_unseen: dict[str, list[str]] = field(default_factory=dict)  # expected but not observed
    gaps: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.missed or self.gaps)

    def as_dict(self) -> dict[str, Any]:
        return {"found": self.found, "missed": self.missed, "spurious": self.spurious,
                "producers_seen": self.producers_seen, "producers_unseen": self.producers_unseen,
                "gaps": self.gaps}


def load_answer_key(path: Path) -> tuple[dict[str, Any], list[Defect]]:
    document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    defects = [Defect(item["id"], item.get("cwe", ""), item["path"], int(item["line"]), item.get("summary", ""),
                      tuple(item.get("producers", ())),
                      int(item["end_line"]) if "end_line" in item else None,
                      item.get("claim_id"), item.get("finding_package_id"),
                      item.get("state", "confirmed"), item.get("bucket", "publishable"))
               for item in document.get("defect", ())]
    for defect in defects:
        if defect.end_line is not None and defect.end_line < defect.line:
            raise ValueError(f"{defect.id}: end_line precedes line")
    if not defects:
        raise ValueError(f"{path} lists no defects")
    if len({defect.id for defect in defects}) != len(defects):
        raise ValueError(f"{path} repeats a defect id")
    return dict(document.get("corpus", {})), defects


def _relative(path: str) -> str:
    for prefix in ("<target>/", "./"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def _covers(record: Mapping[str, Any], defect: Defect, tolerance: int) -> bool:
    path = record.get("path")
    start = record.get("start_line")
    if not isinstance(path, str) or not isinstance(start, int) or _relative(path) != defect.path:
        return False
    end = record.get("end_line") if isinstance(record.get("end_line"), int) else start
    # The reported lines [start, end] must overlap the defect's lines [line, end_line].
    return start - tolerance <= (defect.end_line or defect.line) and defect.line <= end + tolerance


def _producer(finding: Mapping[str, Any]) -> str:
    unit = str(finding.get("unit", ""))
    for part in (unit, str(finding.get("source", ""))):
        if part:
            return part
    return ""


def evaluate(defects: Iterable[Defect], findings: Iterable[Mapping[str, Any]], *,
             tolerance: int = LINE_TOLERANCE) -> AnswerKeyReport:
    """``findings`` are the ``findings`` entries of normalized job outputs, each with a ``job_id``."""

    defects = list(defects)
    tool_findings = [item for item in findings if (item.get("record") or {}).get("kind") in _FINDING_KINDS]
    report = AnswerKeyReport()
    matched: set[int] = set()
    for defect in defects:
        evidence, seen = [], set()
        for index, item in enumerate(tool_findings):
            record = item["record"]
            if _covers(record, defect, tolerance):
                matched.add(index)
                evidence.append(f"{item.get('job_id', '?')}: {record.get('name', '?')}")
                seen.add(_producer(item).lower())
        if evidence:
            report.found[defect.id] = sorted(set(evidence))
            report.producers_seen[defect.id] = sorted(
                producer for producer in defect.producers if any(producer.lower() in text for text in seen))
            report.producers_unseen[defect.id] = sorted(set(defect.producers) - set(report.producers_seen[defect.id]))
        else:
            report.missed.append(defect.id)
    report.spurious = len(tool_findings) - len(matched)
    return report


def observations_from_run(run_root: Path) -> list[dict[str, Any]]:
    """Every tool observation the run published, with its source location.

    The observation shards under ``data/indices/observations`` are what every consumer of tool results
    reads (graph, tagging, review packages), so they, not a job's summary of them, say what the
    pipeline reported. Each result has the shape ``evaluate`` takes.
    """

    findings = []
    for name in sorted(glob.glob(str(Path(run_root) / "data" / "indices" / "observations" / "**" / "*.sqlite"),
                                 recursive=True)):
        try:
            database = sqlite3.connect(f"file:{name}?mode=ro&immutable=1", uri=True)
            rows = database.execute(
                "SELECT e.name, e.text, e.payload_json, l.path, l.start_line, l.end_line "
                "FROM entities e JOIN locations l ON l.entity_id = e.identity WHERE e.kind = 'tool_observation'"
            ).fetchall()
        except sqlite3.Error:
            continue
        finally:
            try:
                database.close()
            except (NameError, sqlite3.Error):
                pass
        for rule, text, payload_json, path, start_line, end_line in rows:
            try:
                payload = json.loads(payload_json or "{}")
            except ValueError:
                payload = {}
            scanner = str(payload.get("scanner") or payload.get("tool") or "")
            findings.append({"job_id": "observations", "source": "observations",
                             "unit": f"{scanner} {payload.get('native_rule_id') or rule}".strip(),
                             "record": {"kind": "tool_observation", "name": str(rule), "path": path,
                                        "start_line": start_line, "end_line": end_line, "text": str(text)}})
    return findings


def collect_findings(outputs: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The findings of normalized job outputs, each tagged with the job that reported it."""

    return [{**finding, "job_id": output.get("job_id")} for output in outputs for finding in output.get("findings", ())]


def current_report_findings(run_root: Path, *, schema_root: Path | None = None) -> list[dict[str, Any]]:
    """Only accepted final rows with evidence resolving through the current accepted manifest.

    Scanner detection remains available through ``observations_from_run``/``evaluate``. It cannot
    satisfy this outcome oracle: a row must survive review, publication and current-pointer checks.
    """
    from appsec_review.storage.validation import validation_scope

    with validation_scope(Path(run_root)):
        return _current_report_findings(Path(run_root), schema_root)


def _current_report_findings(run_root: Path, schema_root: Path | None) -> list[dict[str, Any]]:
    from appsec_review.acceptance.system import accepted_final_report
    from appsec_review.review.evidence import _content_record
    from appsec_review.review.identity import sha256_hex
    from appsec_review.review.models import IntegrityError

    report, core, projection = accepted_final_report(run_root, schema_root)
    findings = []
    for section in ("findings", "verification_backlog", "withheld"):
        for finding in report[section]:
            relations = {row["relation_id"]: row for row in projection["relations"].get(finding["claim_id"], ())}
            for identity in finding["direct_evidence"]:
                relation = relations.get(identity)
                if (relation is None or relation["claim_id"] != finding["claim_id"]
                        or relation["kind"] != "supports" or not relation["complete"]):
                    raise IntegrityError(f"current finding has no complete supporting relation: {identity}")
                rows = core.find(identity=relation["entity_id"], limit=20)["results"]
                rows = [row for row in rows if f"{row['index']}/{row['shard_id']}" == relation["shard_id"]]
                if len(rows) != 1:
                    raise IntegrityError(f"current finding evidence does not resolve uniquely: {identity}")
                entity = rows[0]
                location = entity.get("location")
                excerpt = None
                if location is not None:
                    excerpts = core.read_excerpt(identity=relation["entity_id"], context_lines=0)["results"]
                    if not excerpts:
                        raise IntegrityError(f"current finding source no longer resolves: {identity}")
                    excerpt = str(excerpts[0]["excerpt"])
                if sha256_hex(_content_record(entity, excerpt)) != relation["content_sha256"]:
                    raise IntegrityError(f"current finding evidence content changed: {identity}")
                if location is None:
                    continue
                findings.append({
                    "job_id": "job_final_report_publication", "unit": _producer(entity["payload"]),
                    "claim_id": finding["claim_id"], "finding_package_id": finding["finding_package_id"],
                    "state": finding["state"], "bucket": finding["bucket"], "evidence_id": identity,
                    "record": {"kind": "accepted_final_finding", "name": finding["finding_package_id"],
                               "path": location["path"], "start_line": location["start_line"],
                               "end_line": location["end_line"]}})
    return findings


def evaluate_current_report(defects: Iterable[Defect], run_root: Path, *,
                            schema_root: Path | None = None, tolerance: int = LINE_TOLERANCE) -> AnswerKeyReport:
    """Evaluate expected final identity/state/bucket, failing closed with named integrity gaps."""
    from appsec_review.review.models import IntegrityError
    from appsec_review.retrieval.core import RetrievalGap, RetrievalIntegrityError

    defects = list(defects)
    report = AnswerKeyReport()
    try:
        findings = current_report_findings(run_root, schema_root=schema_root)
    except (OSError, ValueError, KeyError, IntegrityError, RetrievalGap, RetrievalIntegrityError) as error:
        report.missed = [defect.id for defect in defects]
        report.gaps = [f"current_final_report_unavailable: {error}"]
        return report
    matched = set()
    for defect in defects:
        evidence = []
        for index, item in enumerate(findings):
            if (item["state"] == defect.state and item["bucket"] == defect.bucket
                    and (defect.claim_id is None or item["claim_id"] == defect.claim_id)
                    and (defect.finding_package_id is None or item["finding_package_id"] == defect.finding_package_id)
                    and _covers(item["record"], defect, tolerance)):
                matched.add(index)
                evidence.append(f"{item['finding_package_id']} ({item['state']}/{item['bucket']}): {item['evidence_id']}")
        if evidence:
            report.found[defect.id] = sorted(set(evidence))
        else:
            report.missed.append(defect.id)
    report.spurious = len({item["finding_package_id"] for index, item in enumerate(findings) if index not in matched}
                          - {findings[index]["finding_package_id"] for index in matched})
    return report
