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
    from appsec_review.indexing.store import accepted_handoff

    published = None
    try:
        accepted = accepted_handoff(run_root, LEDGER_JOB)
        if (accepted is not None and accepted.handoff.get("job_id") == LEDGER_JOB
                and accepted.handoff.get("completion_status") in ACCEPTED):
            published = accepted.handoff.get("outputs", {}).get("analysis.map_and_adjudicate")
            artifact = published.get("artifact") if isinstance(published, dict) else None
            if artifact not in accepted.handoff.get("artifacts", ()):
                raise ValueError("ledger object is not bound to its accepted handoff")
    except (OSError, ValueError, KeyError) as error:
        problems.append(_problem(LEDGER_JOB, "ledger.receipt", "an accepted ledger receipt", str(error)))
        published = None
    artifact = (published or {}).get("artifact") if isinstance(published, dict) else None
    ledger = _json(run_root / str(artifact["path"])) if isinstance(artifact, dict) else None
    if not isinstance(ledger, dict):
        problems.append(_problem(LEDGER_JOB, "ledger.json", "a document-issue ledger", "<absent>"))
    else:
        from appsec_review.retrieval.model import canonical_json as content_json
        from appsec_review.storage import canonical_json
        from appsec_review.storage.shared import verify_reference, verify_receipt

        try:
            path = verify_reference(run_root, artifact)
            body = {key: value for key, value in ledger.items() if key != "content_sha256"}
            if hashlib.sha256(content_json(body)).hexdigest() != ledger.get("content_sha256"):
                raise ValueError("ledger content identity does not match its body")
            receipt = published.get("shared_receipt")
            if receipt is not None and verify_receipt(run_root, receipt)["object"] != artifact:
                raise ValueError("ledger shared receipt names another object")
            if path.read_bytes() != canonical_json(ledger):
                raise ValueError("ledger bytes are not canonical")
        except (OSError, ValueError, KeyError) as error:
            problems.append(_problem(LEDGER_JOB, "ledger.content_sha256", "verified object and receipt references",
                                     str(error)))
        schema = _json(schema_root / LEDGER_SCHEMA)
        if isinstance(schema, dict):
            from jsonschema import Draft202012Validator

            for error in list(Draft202012Validator(schema).iter_errors(ledger))[:5]:
                problems.append(_problem(LEDGER_JOB, "ledger." + ".".join(str(part) for part in error.path),
                                         "valid against the ledger schema", error.message[:120]))
    return problems


def accepted_final_report(run_root: Path, schema_root: Path | None = None) -> tuple[dict, Any, dict]:
    """Resolve the current report, gate, review, projection and accepted evidence.

    Directory scans and historical attempts are deliberately not fallback sources. The report
    must still project the currently accepted review and index set, not just some intact old run.
    """
    from appsec_review.storage.validation import validation_scope

    with validation_scope(Path(run_root)):
        return _accepted_final_report(Path(run_root), schema_root)


def _accepted_final_report(run_root: Path, schema_root: Path | None) -> tuple[dict, Any, dict]:
    from appsec_review.indexing.store import accepted_handoff
    from appsec_review.jobs.bound_artifacts import read_bound_json
    from appsec_review.jobs.job_final_publication_gate.classify import classify, gate_document
    from appsec_review.jobs.job_final_publication_gate.verify import load_accepted_gate, load_accepted_review
    from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
    from appsec_review.retrieval.core import RetrievalCore
    from appsec_review.review.models import IntegrityError

    run_root = Path(run_root).resolve()
    schema_root = Path(schema_root or Path(__file__).resolve().parents[3])

    def published(job_id: str) -> tuple[dict, dict]:
        accepted = accepted_handoff(run_root, job_id)
        if (accepted is None or accepted.handoff.get("job_id") != job_id
                or accepted.handoff.get("completion_status") not in ACCEPTED):
            raise IntegrityError(f"current accepted {job_id} is unavailable")
        output = accepted.handoff["outputs"]["acceptance.publish_handoff"]
        return {"path": accepted.path, "sha256": accepted.sha256}, output

    _report_ref, report_output = published("job_final_report_publication")
    report = read_bound_json(run_root, report_output["artifact"])
    schemas = SchemaSet(schema_root / "docs" / "schemas" / "final-report")
    schemas.validate("final-report", report)
    accepted_gate, gate = load_accepted_gate(run_root, schemas)
    gate_ref = {"path": accepted_gate.path, "sha256": accepted_gate.sha256}
    gate_output = accepted_gate.handoff["outputs"]["acceptance.publish_handoff"]
    verified = load_accepted_review(
        run_root, SchemaSet(schema_root / "docs" / "schemas" / "inference-security-review"),
        max_packages=len(gate["packages"])).document
    certified = {(row["path"], row["sha256"]) for row in gate["bindings"]}
    if not {(row["path"], row["sha256"]) for row in verified["bindings"]} <= certified:
        raise IntegrityError("current gate does not certify every current review binding")
    verified.update(capabilities=gate["capabilities"], attachments=gate["attachments"], bindings=gate["bindings"])
    if gate != gate_document(gate["schema"], verified, classify(verified)):
        raise IntegrityError("current gate does not project the currently accepted review")
    provenance = report["provenance"]
    if (report["run_id"] != run_root.name or gate["run_id"] != run_root.name
            or provenance["gate_handoff"] != gate_ref
            or provenance["review_handoff"] != verified["inputs"]["review_handoff"]
            or provenance["gate_document"] != gate_output["artifact"]
            or any(provenance[key] != gate["review"][key] for key in (
                "accepted_manifest_sha256", "configuration_sha256", "ledger_head_sha256", "ship_block_policy_sha256"))):
        raise IntegrityError("report provenance is not the currently accepted review and gate")
    for name, bucket in (("findings", "publishable"), ("verification_backlog", "verification_backlog"),
                         ("withheld", "withheld")):
        expected = [item for item in gate["packages"] if item["bucket"] == bucket]
        if report[name] != expected:
            raise IntegrityError(f"current report {name} differs from its accepted gate bucket")
    if report["summary"]["package_counts"] != gate["package_counts"]:
        raise IntegrityError("current report package accounting differs from its accepted gate")
    core = RetrievalCore(run_root.parent, run_root.name)
    if core.manifest_sha256 != provenance["accepted_manifest_sha256"]:
        raise IntegrityError("current report does not bind the currently accepted index manifest")
    projection = read_bound_json(run_root, verified["inputs"]["projection"])
    return report, core, projection
