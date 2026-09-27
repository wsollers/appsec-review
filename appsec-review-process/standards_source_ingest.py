#!/usr/bin/env python3
"""Offline, immutable S01 standards-source ingestion.

The worker copies only an explicitly bound subset of the repository's already materialized
OWASP/OpenCRE snapshots into run-owned evidence.  Reference text and mappings are data, never
instructions or proof that a target satisfies a control.  This core is deliberately not wired to
the shared graph or Dagster definitions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, now, read_json
import phase1
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import reference_snapshots
from schema_validate import validate_document

JOB = "02-standards-source-ingest"
CONTRACT = "standards-source-extract"
RESULT = "standards-source.json"
WORKER_KIND = "deterministic_python"
REFERENCE_ROOT = ROOT.parent / "data/reference"
SOURCE_LOCK = REFERENCE_ROOT / "source-lock.json"
BINDING_NAME = "standards-source-binding.json"
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
RECORD_SCHEMAS = {
    "owasp_asvs": "owasp-control-record.schema.json",
    "owasp_masvs": "owasp-control-record.schema.json",
    "owasp_mastg": "owasp-test-record.schema.json",
    "owasp_top_10": "owasp-context-record.schema.json",
    "owasp_api_security_top_10": "owasp-context-record.schema.json",
    "owasp_llm_top_10": "owasp-context-record.schema.json",
    "opencre": "opencre-crosswalk-record.schema.json",
}
CODE_FILES = (
    "standards_source_ingest.py", "reference_snapshots.py", "publish_job_output.py",
    "validate_job_output.py", "worker_result.py",
    "registry/job-templates/02-standards-source-ingest.json",
    "registry/output-contracts/standards-source-extract.json",
    "registry/roles/standards-source-ingestor.json",
    "registry/domains/owasp-application-controls.json",
    "registry/tooling-profiles/standards-source-static-ingest.json",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _hash(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("standards-source-binding.schema.json", "standards-source-extract.schema.json",
                 "standards-source-record.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _permissions() -> list[str]:
    value = read_json(ROOT / "registry/job-templates/02-standards-source-ingest.json").get("permissions")
    if not isinstance(value, list) or not value or len(value) != len(set(value)):
        raise Blocked(f"{JOB}: canonical template permissions are absent or invalid")
    return value


def _intake(run_id: str) -> dict[str, Any]:
    pointer = phase1.accepted(run_id, phase1.JOB, fresh=True)
    if pointer is None or pointer.get("status") != "OK":
        raise Blocked(f"{JOB}: exact accepted intake is required")
    base = phase1.job_root(run_id, phase1.JOB, "whole")
    attempt = base / "attempts" / pointer["attempt_id"]
    source = read_json(attempt / "evidence/source.json")
    intake_result = read_json(attempt / "outputs/intake.json")
    if source.get("fingerprint") != intake_result.get("source_fingerprint"):
        raise Blocked(f"{JOB}: intake source identity mismatch")
    return {
        "job_id": phase1.JOB, "attempt_id": pointer["attempt_id"],
        "fingerprint": pointer["fingerprint"], "source_fingerprint": source["fingerprint"],
        "pointer_sha256": "sha256:" + file_hash(base / "accepted.json"),
    }


def _source_entries() -> dict[str, dict[str, Any]]:
    lock = read_json(SOURCE_LOCK)
    if validate_document(lock, "reference-source-lock.schema.json"):
        raise Blocked(f"{JOB}: source lock fails its schema")
    entries = lock.get("sources", [])
    families = [item.get("family") for item in entries]
    if len(families) != len(set(families)) or any(family not in RECORD_SCHEMAS for family in families):
        raise Blocked(f"{JOB}: source lock has duplicate or unsupported families")
    return {item["family"]: item for item in entries}


def _snapshot_path(family: str, snapshot_id: str) -> Path:
    matches = [path.parent for path in REFERENCE_ROOT.glob("**/manifest.json")
               if path.parent.name == snapshot_id]
    matching = [path for path in matches if read_json(path / "manifest.json").get("family") == family]
    if len(matching) != 1:
        raise Blocked(f"{JOB}: expected exactly one pinned snapshot for {family}/{snapshot_id}")
    return matching[0]


def _verify_snapshot(path: Path) -> dict[str, Any]:
    try:
        return reference_snapshots.verify_snapshot(path)
    except (reference_snapshots.SnapshotError, OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: immutable reference snapshot failed verification") from exc


def _binding(run_id: str) -> dict[str, Any]:
    path = data_path(run_id, "inputs", BINDING_NAME)
    if not path.is_file() or path.is_symlink():
        raise Blocked(f"{JOB}: run-owned {BINDING_NAME} is required")
    value = read_json(path)
    errors = validate_document(value, "standards-source-binding.schema.json")
    if errors or value.get("run_id") != run_id:
        raise Blocked(f"{JOB}: standards source binding is invalid for this run")
    selected = [item["family"] for item in value["selected_snapshots"]]
    unselected = [item["family"] for item in value["unselected_families"]]
    known = set(_source_entries())
    if (len(selected) != len(set(selected)) or len(unselected) != len(set(unselected)) or
            set(selected) & set(unselected) or set(selected) | set(unselected) != known):
        raise Blocked(f"{JOB}: selected and unselected families must partition the pinned source lock")
    return value


def current_inputs(run_id: str) -> dict[str, Any]:
    binding = _binding(run_id)
    intake_binding = _intake(run_id)
    snapshots = []
    lock_entries = _source_entries()
    for selected in sorted(binding["selected_snapshots"], key=lambda item: item["family"]):
        path = _snapshot_path(selected["family"], selected["snapshot_id"])
        manifest = _verify_snapshot(path)
        lock = lock_entries[selected["family"]]
        if (selected["edition"] != manifest["edition"] or
                selected["manifest_sha256"] != "sha256:" + file_hash(path / "manifest.json") or
                lock["edition"] != manifest["edition"] or
                lock["upstream_url"] != manifest["upstream"]["url"] or
                lock["immutable_ref"] != manifest["upstream"]["immutable_ref"] or
                lock["resolved_commit"] != manifest["upstream"]["resolved_commit"] or
                lock.get("tag_object") != manifest["upstream"].get("tag_object") or
                lock["license_identifier"] != manifest["license"]["identifier"] or
                lock["expected_record_count"] != manifest["record_counts"]["records"]):
            raise Blocked(f"{JOB}: {selected['family']} binding, lock, and manifest identity differ")
        snapshots.append({"family": selected["family"], "path": str(path.resolve()),
                          "manifest_sha256": selected["manifest_sha256"],
                          "expected_record_count": lock["expected_record_count"]})
    return {
        "run_id": run_id, "job_id": JOB, "binding": binding,
        "binding_sha256": "sha256:" + file_hash(data_path(run_id, "inputs", BINDING_NAME)),
        "intake": intake_binding, "source_lock_sha256": "sha256:" + file_hash(SOURCE_LOCK),
        "snapshots": snapshots, "code": _code_hashes(),
    }


def _record_id(record: dict[str, Any]) -> str:
    for key in ("control_id", "test_id", "category_id", "record_id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    raise Blocked(f"{JOB}: reference record has no stable identity")


def _safe_record_name(record_id: str) -> str:
    return digest(record_id)[:24] + ".json"


def _load_snapshot(path: Path, expected_manifest_sha256: str,
                   expected_record_count: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _verify_snapshot(path)
    if "sha256:" + file_hash(path / "manifest.json") != expected_manifest_sha256:
        raise Blocked(f"{JOB}: selected snapshot manifest changed")
    catalog = read_json(path / "normalized/catalog.json")
    if (catalog.get("family") != manifest["family"] or catalog.get("edition") != manifest["edition"] or
            catalog.get("snapshot_id") != manifest["snapshot_id"]):
        raise Blocked(f"{JOB}: mixed snapshot catalog identity for {manifest['family']}")
    records = catalog.get("records")
    if (not isinstance(records, list) or len(records) != manifest["record_counts"]["records"] or
            len(records) != expected_record_count):
        raise Blocked(f"{JOB}: missing reference records for {manifest['family']}")
    raw = {item["path"]: item["sha256"] for item in manifest["raw_files"]}
    identities: set[str] = set()
    for record in records:
        errors = validate_document(record, RECORD_SCHEMAS[manifest["family"]])
        if errors:
            raise Blocked(f"{JOB}: invalid record in {manifest['family']}")
        identity = _record_id(record)
        if identity in identities:
            raise Blocked(f"{JOB}: duplicate record id {manifest['family']}/{identity}")
        identities.add(identity)
        source = record.get("source", {})
        if (source.get("snapshot_id") != manifest["snapshot_id"] or
                raw.get(source.get("raw_path")) != source.get("raw_sha256")):
            raise Blocked(f"{JOB}: mixed or stale record lineage for {manifest['family']}/{identity}")
        if record.get("record_type") == "control" and not record.get("text", "").strip():
            raise Blocked(f"{JOB}: control text is missing for {manifest['family']}/{identity}")
    return manifest, sorted(records, key=lambda item: _record_id(item))


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _render(*, run_id: str, attempt_id: str,
            inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bytes]]:
    summaries: list[dict[str, Any]] = []
    index: list[dict[str, Any]] = []
    outputs: dict[str, bytes] = {}
    for selected in inputs["snapshots"]:
        source = Path(selected["path"])
        manifest, records = _load_snapshot(source, selected["manifest_sha256"],
                                           selected["expected_record_count"])
        prefix = PurePosixPath("standards") / manifest["family"] / manifest["snapshot_id"]
        manifest_rel = (prefix / "manifest.json").as_posix()
        license_rel = (prefix / "LICENSE-or-usage.txt").as_posix()
        outputs[manifest_rel] = (source / "manifest.json").read_bytes()
        outputs[license_rel] = (source / "LICENSE-or-usage.txt").read_bytes()
        catalog_hash = next(item["sha256"] for item in manifest["normalized_files"]
                            if item["path"] == "normalized/catalog.json")
        for record in records:
            record_id = _record_id(record)
            relative = (prefix / "records" / _safe_record_name(record_id)).as_posix()
            wrapper = {
                "schema": "appsec-review/standards-source-record/1.0",
                "family": manifest["family"], "edition": manifest["edition"],
                "snapshot_id": manifest["snapshot_id"], "manifest_sha256": selected["manifest_sha256"],
                "license": {"identifier": manifest["license"]["identifier"], "path": license_rel,
                            "sha256": "sha256:" + manifest["license"]["sha256"]},
                "extractor": manifest["extractor"], "record_type": record["record_type"],
                "record_id": record_id, "record_sha256": _hash(record),
                "source": {"catalog_path": "normalized/catalog.json",
                           "catalog_sha256": "sha256:" + catalog_hash,
                           "raw_paths": [record["source"]["raw_path"]]},
                "record": record,
            }
            if validate_document(wrapper, "standards-source-record.schema.json"):
                raise Blocked(f"{JOB}: generated record wrapper is invalid")
            outputs[relative] = _json_bytes(wrapper)
            index.append({"family": manifest["family"], "record_type": record["record_type"],
                          "record_id": record_id, "path": relative,
                          "sha256": "sha256:" + hashlib.sha256(outputs[relative]).hexdigest()})
        summaries.append({
            "family": manifest["family"], "edition": manifest["edition"],
            "snapshot_id": manifest["snapshot_id"], "manifest_path": manifest_rel,
            "manifest_sha256": selected["manifest_sha256"], "license_path": license_rel,
            "license_sha256": "sha256:" + manifest["license"]["sha256"],
            "content_digest": manifest["content_digest"], "extractor": manifest["extractor"],
            "record_count": len(records),
        })
    gaps = [f"unselected-family:{item['family']}:{item['reason']}"
            for item in sorted(inputs["binding"]["unselected_families"], key=lambda item: item["family"])]
    result = {
        "schema": "appsec-review/standards-source-extract/1.0", "run_id": run_id,
        "job_id": JOB, "attempt_id": attempt_id, "status": "OK_WITH_GAPS" if gaps else "OK",
        "source_snapshot_sha256": "sha256:" + inputs["intake"]["source_fingerprint"],
        "source_lock": {"path": "data/reference/source-lock.json", "sha256": inputs["source_lock_sha256"]},
        "snapshots": summaries, "records": index, "coverage_gaps": gaps,
        "claim_boundary": "REFERENCE_MATERIAL_ONLY_NOT_PROOF_OR_COMPLIANCE",
    }
    if validate_document(result, "standards-source-extract.schema.json"):
        raise Blocked(f"{JOB}: generated standards source result is invalid")
    return result, outputs


def materialize(*, run_id: str, attempt_id: str, attempt: Path,
                inputs: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    result, outputs = _render(run_id=run_id, attempt_id=attempt_id, inputs=inputs)
    for relative, content in outputs.items():
        atomic_bytes(attempt / relative, content)
    return result, list(outputs)


def _receipts(run_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = "sha256:" + inputs["intake"]["source_fingerprint"]
    return (
        {"schema": PERMISSION_SCHEMA, "run_id": run_id, "job_id": JOB,
         "source_snapshot_sha256": source, "permissions": _permissions()},
        {"schema": LINEAGE_SCHEMA, "run_id": run_id, "job_id": JOB,
         "source_snapshot_sha256": source, "build_lineage_sha256": None},
    )


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    live = current_inputs(run_id)
    if live != inputs:
        raise Blocked(f"{JOB}: intake, selection, lock, or reference snapshot changed")
    expected, outputs = _render(run_id=run_id, attempt_id=attempt.name, inputs=inputs)
    found = read_json(attempt / RESULT)
    if found != expected:
        raise Blocked(f"{JOB}: result differs from the selected immutable snapshots")
    for relative, content in outputs.items():
        candidate = attempt / relative
        if not candidate.is_file() or candidate.is_symlink() or candidate.read_bytes() != content:
            raise Blocked(f"{JOB}: run-owned standards artifact changed: {relative}")
    permission, lineage = _receipts(run_id, inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: F02 permission or lineage receipt changed")


def run(run_id: str, dagster_run_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]
        result, artifacts = materialize(run_id=run_id, attempt_id=allocation["attempt_id"],
                                        attempt=attempt, inputs=inputs)
        atomic_json(attempt / RESULT, result)
        permission, lineage = _receipts(run_id, inputs)
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        status = {
            "process": JOB, "status": result["status"], "run_id": run_id,
            "dagster_run_id": dagster_run_id, "attempt_id": allocation["attempt_id"],
            "source_snapshot_sha256": result["source_snapshot_sha256"],
            "snapshots": len(result["snapshots"]), "records": len(result["records"]),
            "network": "none", "qualification": "implemented_not_qualified", "ended_at": now(),
        }
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
            worker_kind=WORKER_KIND, output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Pinned {len(result['records'])} immutable OWASP/OpenCRE reference records.",
            status_record=status,
            artifact_paths=[RESULT, "status.json", "permission.json", "lineage.json", *artifacts],
            gaps=result["coverage_gaps"] or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs),
        )

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
        worker_kind=WORKER_KIND, output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/standards_source_ingest.py {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: _hash(value),
        execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job_id": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, inputs: _validate_attempt(run_id, attempt, inputs),
        blocked_summary="Standards source selection or immutable reference validation blocked.",
        failed_summary="Standards source ingest did not publish.",
    )


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    inputs = current_inputs(run_id)
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, _hash(inputs), expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--dagster-run-id", default="standalone")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
