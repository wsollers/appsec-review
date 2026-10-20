"""System-level acceptance of one complete application run.

Per-job parity (docs/processes/local-dagster-parity.md) shows each job behaves the same through
both drivers. This checks the whole run that Dagster produced end to end:

- every job of the graph finished with an accepted handoff, with no job left running or failed;
- every handoff, artifact and path-and-hash reference of every job resolves to the recorded bytes,
  and each job bound the upstream handoffs the run actually accepted (``integrity``);
- the final artifacts exist and are valid: the review packages and the document-issue ledger.

Output comparison against the accepted baselines (``stepwise.py compare``) and the answer-key
matrix (``answer_key``) are separate checks run alongside this one.
"""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json
from pathlib import Path
from typing import Any

from .diff import Difference
from .integrity import attempt_integrity

ACCEPTED = {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
PACKAGE_JOB = "job_review_package_assembly"
LEDGER_JOB = "job_document_issue_analysis"
LEDGER_SCHEMA = Path("docs") / "schemas" / "document-issue-ledger.schema.json"


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _problem(job_id: str, path: str, expected: str, actual: str) -> Difference:
    return Difference(job_id, "integrity", path, expected, actual)


def latest_attempt(run_root: Path, job_id: str) -> tuple[Path | None, dict | None]:
    pointer = _json(run_root / "data" / "jobs" / job_id / "latest.json")
    if not isinstance(pointer, dict) or "handoff_path" not in pointer:
        return None, None
    handoff_path = run_root / str(pointer["handoff_path"])
    handoff = _json(handoff_path)
    return (handoff_path.parent, handoff) if isinstance(handoff, dict) else (None, None)


def run_problems(run_root: Path, run_id: str, job_ids: Iterable[str],
                 target_root: Path | None = None) -> list[Difference]:
    """Every job accepted, and every accepted job's evidence intact."""

    problems: list[Difference] = []
    for job_id in job_ids:
        attempt, handoff = latest_attempt(run_root, job_id)
        if attempt is None or handoff is None:
            problems.append(_problem(job_id, "latest", "an accepted handoff", "<absent>"))
            continue
        if handoff.get("status") != "ACCEPTED" or handoff.get("completion_status") not in ACCEPTED:
            problems.append(_problem(job_id, "handoff.status", "ACCEPTED with SUCCEEDED or COMPLETED_WITH_GAPS",
                                     f"{handoff.get('status')} / {handoff.get('completion_status')}"))
        problems += attempt_integrity(job_id, run_root, run_id, attempt, "system", target_root)
    return problems


def final_artifact_problems(run_root: Path, schema_root: Path) -> list[Difference]:
    """The review packages and the document-issue ledger the run exists to produce."""

    problems: list[Difference] = []
    attempt, _handoff = latest_attempt(run_root, PACKAGE_JOB)
    result = _json(attempt / "result.json") if attempt else None
    publication = ((result or {}).get("outputs") or {}).get("publication.publish_packages")
    if not isinstance(publication, dict):
        problems.append(_problem(PACKAGE_JOB, "publication", "a published package set", "<absent>"))
    else:
        directory = run_root / str(publication.get("package_directory", ""))
        manifest = _json(directory / "manifest.json")
        if not isinstance(manifest, dict):
            problems.append(_problem(PACKAGE_JOB, "manifest.json", "a package manifest", "<absent>"))
        else:
            if not manifest.get("packages"):
                problems.append(_problem(PACKAGE_JOB, "manifest.packages", "at least one package", "none"))
            if manifest.get("content_sha256") != publication.get("content_sha256"):
                problems.append(_problem(PACKAGE_JOB, "manifest.content_sha256",
                                         str(publication.get("content_sha256")), str(manifest.get("content_sha256"))))
            for item in publication.get("artifacts", ()):
                path = run_root / str(item.get("path", ""))
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item.get("sha256"):
                    problems.append(_problem(PACKAGE_JOB, f"artifact {item.get('path')}", "the recorded bytes",
                                             "<absent or changed>"))
    attempt, _handoff = latest_attempt(run_root, LEDGER_JOB)
    result = _json(attempt / "result.json") if attempt else None
    published = ((result or {}).get("outputs") or {}).get("analysis.map_and_adjudicate")
    artifact = (published or {}).get("artifact") if isinstance(published, dict) else None
    ledger = _json(run_root / str(artifact["path"])) if isinstance(artifact, dict) else None
    if not isinstance(ledger, dict):
        problems.append(_problem(LEDGER_JOB, "ledger.json", "a document-issue ledger", "<absent>"))
    else:
        if Path(artifact["path"]).parent.name != ledger.get("content_sha256"):
            problems.append(_problem(LEDGER_JOB, "ledger.content_sha256", Path(artifact["path"]).parent.name,
                                     str(ledger.get("content_sha256"))))
        schema = _json(schema_root / LEDGER_SCHEMA)
        if isinstance(schema, dict):
            from jsonschema import Draft202012Validator

            for error in list(Draft202012Validator(schema).iter_errors(ledger))[:5]:
                problems.append(_problem(LEDGER_JOB, "ledger." + ".".join(str(part) for part in error.path),
                                         "valid against the ledger schema", error.message[:120]))
    return problems
