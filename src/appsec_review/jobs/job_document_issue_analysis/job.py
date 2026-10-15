"""Accepted document hunts to bounded, private candidate ledger."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from appsec_review.application_paths import application_asset
from appsec_review.document_issues import SCHEMA, analyze_document_hunts, verify_document_issue_ledger
from appsec_review.indexing.store import accepted_handoff
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from .datasets import CONSUMES, DATASETS


JOB_ID = "job_document_issue_analysis"
# The ledger holds private candidates only; until independent review publishes findings the job's
# coverage is always partial, and this names why so an empty ledger never reads as clean.
UNADJUDICATED_GAP = ("document issue candidates are not adjudicated: finding publication is not "
                     "implemented, so an empty ledger says nothing about target security")


def _schema_path() -> Path:
    return application_asset("docs/schemas/document-issue-ledger.schema.json")


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != ("analysis",) or tuple(context.config.step("analysis").tasks) != ("map_and_adjudicate",):
        raise ValueError("document issue analysis topology differs from central configuration")
    settings = context.config.settings
    if set(settings) != {"max_source_files", "max_source_file_bytes"} or any(
        type(settings[key]) is not int or settings[key] < 1 for key in settings
    ):
        raise ValueError("document issue analysis requires positive bounded source settings")


def _validate_output(unit: UnitContext, result: Mapping[str, Any] | None) -> None:
    if result is None:
        raise ValueError("document issue ledger is unavailable")
    path = (unit.job.run_root / result["artifact"]["path"]).resolve()
    if unit.job.run_root.resolve() not in path.parents or file_sha256(path) != result["artifact"]["sha256"]:
        raise ValueError("document issue ledger receipt failed verification")
    manifest_path, manifest_sha = resolve_context_manifest(unit.job)
    core = RetrievalCore(unit.job.run_root.parent, unit.job.run_id,
                         manifest_sha256=manifest_sha, manifest_path=manifest_path)
    ledger = verify_document_issue_ledger(core, path)
    if ledger["counts"] != result["counts"]:
        raise ValueError("document issue ledger counts differ from receipt")


def build_job() -> Job:
    def analyze(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        manifest_path, manifest_sha = resolve_context_manifest(unit.job)
        core = RetrievalCore(run_root.parent, unit.job.run_id,
                             manifest_sha256=manifest_sha, manifest_path=manifest_path)
        if core.manifest["target_snapshot"] != unit.job.source_fingerprint:
            raise ValueError("document issue analysis target snapshot changed")
        handoff = accepted_handoff(run_root, "job_review_package_assembly")
        if handoff is None:
            raise ValueError("accepted review package handoff is unavailable")
        result_path = (run_root / handoff.handoff["resolving_paths"]["result"]).resolve()
        if run_root.resolve() not in result_path.parents or not any(
            item["path"] == result_path.relative_to(run_root).as_posix()
            and item["sha256"] == file_sha256(result_path) for item in handoff.handoff["artifacts"]
        ):
            raise ValueError("accepted review package result failed verification")
        output = json.loads(result_path.read_text(encoding="utf-8"))["outputs"]["publication.publish_packages"]
        directory = (run_root / output["package_directory"]).resolve()
        if run_root.resolve() not in directory.parents:
            raise ValueError("review package path escapes run")
        if output["accepted_manifest_sha256"] != core.manifest_sha256:
            raise ValueError("review package manifest is not the accepted index set")
        if not any(item["path"] == (directory / "manifest.json").relative_to(run_root).as_posix()
                   and item["sha256"] == file_sha256(directory / "manifest.json")
                   for item in handoff.handoff["artifacts"]):
            raise ValueError("review package manifest is not bound to its accepted handoff")
        ledger = analyze_document_hunts(core, directory,
            max_files=unit.job.config.settings["max_source_files"],
            max_file_bytes=unit.job.config.settings["max_source_file_bytes"])
        schema_path = _schema_path()
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(ledger)
        path = run_root / "data" / "document-issues" / ledger["content_sha256"] / "ledger.json"
        if path.exists():
            from appsec_review.retrieval.model import canonical_json
            if path.read_bytes() != canonical_json(ledger) + b"\n":
                raise ValueError("existing document issue ledger changed bytes")
        else:
            atomic_json(path, ledger)
        artifact = {"path": path.relative_to(run_root).as_posix(),
                    "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
        unit.job.events.write("DOCUMENT_ISSUES_PUBLISHED", **ledger["counts"])
        return {"schema": SCHEMA, "artifact": artifact, "artifacts": [artifact],
                "counts": ledger["counts"],
                "gaps": [UNADJUDICATED_GAP, *(gap["gap_id"] for candidate in ledger["candidates"]
                                              for gap in candidate["coverage_gaps"])],
                "terminal_status": "COMPLETED_WITH_GAPS"}

    units = (Unit("analysis.map_and_adjudicate", analyze, output_validators=(_validate_output,)),)
    sources = [Path(__file__), Path(__file__).with_name("datasets.py"),
               Path(__file__).parents[2] / "document_issues.py",
               _schema_path()]
    identity = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()
    return Job(JOB_ID, "document_issue_analysis", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=identity, validation_identity=identity, units=units,
               datasets=DATASETS, consumes=CONSUMES)
