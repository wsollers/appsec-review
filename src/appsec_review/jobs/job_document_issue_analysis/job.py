"""Accepted document hunts and multi-language API spec drift to bounded candidate artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from appsec_review.application_paths import application_asset
from appsec_review.document_issues import (
    DRIFT_SCHEMA,
    SCHEMA,
    analyze_api_spec_drift,
    analyze_document_hunts,
    verify_document_drift_issues,
    verify_document_issue_inputs,
    verify_document_issue_ledger,
)
from appsec_review.indexing.store import accepted_handoff
from appsec_review.indexing.derive import Derived, fact, publish_derived
from appsec_review.observability.spans import count_work
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import IndexIdentity, load_verified_manifest, write_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, immutable_bytes, put_bytes, reference, verify_reference

from .datasets import CONTRACT, DATASETS


JOB_ID = "job_document_issue_analysis"
UNADJUDICATED_GAP = ("document issue candidates are not adjudicated: finding publication is not "
                     "implemented, so an empty ledger says nothing about target security")
PROJECTION_RULE = "appsec-review/document-navigation/1"


def _publish_projection(unit: UnitContext, core: RetrievalCore, ledger: Mapping[str, Any],
                        drift: Mapping[str, Any], artifact: Mapping[str, Any],
                        drift_artifact: Mapping[str, Any]) -> Mapping[str, Any]:
    """Project bounded navigation records, never claims or adjudicated findings, after package assembly."""
    derived = Derived()
    derived.gap(UNADJUDICATED_GAP)
    for gap in drift["gaps"]:
        derived.gap(gap)
    rows = [("drift", item["drift_id"], item) for item in drift["mismatches"]]
    rows.extend(("mapping", item["candidate_id"], item) for item in ledger["candidates"])
    bound = unit.job.config.settings["max_source_files"]
    ordered = sorted(rows, key=lambda row: (row[0], row[1]))
    if len(ordered) > bound:
        derived.gap(f"document navigation projection truncated: {len(ordered) - bound} records beyond {bound}")
    resolved: dict[str, Mapping[str, Any]] = {}
    shard_hashes = {(name, item.get("shard_id", "default")): item["sha256"]
                    for name, items in core.indexes.items() for item in items}

    def evidence(identity: str) -> Mapping[str, Any]:
        if identity not in resolved:
            found = core.find(identity=identity, indexes=("source", "documents"), limit=2)
            if len(found["results"]) != 1 or found["truncated"]:
                raise ValueError("document navigation source is not uniquely bound to accepted catalog evidence")
            row = found["results"][0]
            resolved[identity] = {"identity": identity, "index": row["index"],
                                  "shard_id": row["shard_id"],
                                  "shard_sha256": shard_hashes[(row["index"], row["shard_id"])],
                                  "location": row.get("location")}
        return resolved[identity]

    for kind, key, item in ordered[:bound]:
        gaps = [UNADJUDICATED_GAP]
        if kind == "drift":
            ids = [value for value in (item["handler_source_id"], item["spec_source_id"]) if value]
            result = dict(item)
            path = item["handler_path"] or item["spec_path"]
            payload = drift_artifact
            summary = item["summary"]
        else:
            ids = sorted({entry["entity_id"] for entry in item["implementation_evidence"]})
            ids.extend(sorted({entry["entity_id"] for entry in item["document_evidence"]
                               if LogicalIdentity.parse(entry["entity_id"]).kind is EntityKind.DOCUMENT_RECORD}))
            result = {name: item[name] for name in ("candidate_id", "package_id", "subject", "mapping_status")}
            result["state"] = "insufficient_evidence"
            result["document_evidence"] = item["document_evidence"][:32]
            if len(item["document_evidence"]) > 32:
                gaps.append(f"document evidence references truncated: {len(item['document_evidence']) - 32} omitted")
            path = next((entry["path"] for entry in item["implementation_evidence"]), None)
            payload = artifact
            summary = "Verify document-to-implementation mapping; no behavior conclusion"
            gaps.extend(gap["reason"] for gap in item["coverage_gaps"])
        if len(ids) > 32:
            gaps.append(f"document navigation source references truncated: {len(ids) - 32} omitted")
        sources = [evidence(identity) for identity in ids[:32]]
        result.update(authority="provisional_navigation_lead", source_evidence=sources,
                      payload_artifact=dict(payload), accepted_manifest_sha256=core.manifest_sha256)
        if path is None:
            derived.gap(f"document mapping {key}: no implementation path; not admitted to a source hunt")
        derived.entities.append(fact(
            core.manifest["target_snapshot"], "document_context", PROJECTION_RULE,
            {"kind": kind, "id": key}, name=f"document {kind}: {summary}", text=summary,
            result=result, basis="provisional document navigation only; independent adjudication required",
            upstream=sources, subject_identity=ids[0] if ids else None, subject_path=path,
            status="partial", gaps=gaps, fact_type=f"document_{kind}"))
    derived.coverage.append(("document_navigation", "partial", "; ".join(derived.gaps[:20])[:1000]))
    published = publish_derived(
        unit.job.run_root, index="precomputed", shard_id="document-issues", job_id=JOB_ID,
        unit_id=unit.unit_id, rule="document_navigation", rule_version=PROJECTION_RULE,
        snapshot=unit.job.source_fingerprint,
        inputs={"ledger": dict(artifact), "drift": dict(drift_artifact),
                "manifest_sha256": core.manifest_sha256, "max_records": bound},
        build=lambda: derived, producer={"query_set": "document_context", "authority": "provisional"})
    manifest_path, manifest_sha = resolve_context_manifest(unit.job)
    path = unit.job.run_root / "data/document-issues" / unit.job.attempt_id / "retrieval-manifest.json"
    identities = [IndexIdentity(**item) for item in core.manifest["indexes"]
                  if item.get("producer", {}).get("job") != JOB_ID]
    identities.append(IndexIdentity(**published["index_identity"]))
    write_manifest(path, run_id=core.run_id, target_snapshot=core.manifest["target_snapshot"],
                   target_root=core.target_root, indexes=identities,
                   upstream_manifests=({"path": manifest_path.relative_to(core.run_root).as_posix(),
                                        "sha256": manifest_sha},))
    return {"index_identity": published["index_identity"],
            "index_manifest": {"path": path.relative_to(core.run_root).as_posix(), "sha256": file_sha256(path)},
            "shard_artifact": reference(core.run_root, core.run_root / published["index_identity"]["relative_path"]),
            "checkpoint": reference(core.run_root, core.run_root / "data/indexing/checkpoints/precomputed/document-issues"
                                    / f"{published['fingerprint']}.json"),
            "gaps": published["gaps"]}


def _schema_path() -> Path:
    return application_asset("docs/schemas/document-issue-ledger.schema.json")


def _drift_schema_path() -> Path:
    return application_asset("docs/schemas/document-issues/document-drift-issue.schema.json")


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
    if "drift_artifact" in result:
        drift_path = (unit.job.run_root / result["drift_artifact"]["path"]).resolve()
        if unit.job.run_root.resolve() not in drift_path.parents or file_sha256(drift_path) != result["drift_artifact"]["sha256"]:
            raise ValueError("document drift report receipt failed verification")
        verify_document_drift_issues(core, drift_path)
    if "index_manifest" in result:
        manifest = result["index_manifest"]
        document, _ = load_verified_manifest(unit.job.run_root, unit.job.run_root / manifest["path"], manifest["sha256"])
        if not any(canonical_json(result["index_identity"]) == canonical_json(item) for item in document["indexes"]):
            raise ValueError("document projection shard is not bound to its manifest")


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
        shared = SharedArtifacts.for_job(unit.job)
        releases = unit.job.review_policy.releases
        implementation_key = JOB_ID if JOB_ID in releases.values else "platform"
        reusable, miss_reason = releases.require(implementation_key, "validation")
        computation = {"accepted_manifest_sha256": core.manifest_sha256,
                       "package_manifest_sha256": file_sha256(directory / "manifest.json"),
                       "settings": dict(unit.job.config.settings),
                       "schema": SCHEMA, "target_snapshot": unit.job.source_fingerprint,
                       "component_releases": {
                           key: releases.values.get(key) for key in (implementation_key, "validation")}}
        fingerprint = hashlib.sha256(canonical_json(computation)).hexdigest()
        hit = shared.lookup("document-issues", fingerprint) if reusable else None
        count_work("cache_hits" if hit is not None else "cache_misses")
        unit.job.events.write("CHECKPOINT_REUSED" if hit is not None else "CHECKPOINT_MISSED",
                              unit_id=unit.unit_id, action="document-issues", fingerprint=fingerprint,
                              reason=None if hit is not None else (miss_reason or "missing"))
        max_files = unit.job.config.settings["max_source_files"]
        max_bytes = unit.job.config.settings["max_source_file_bytes"]
        if hit is None:
            ledger = analyze_document_hunts(core, directory, max_files=max_files, max_file_bytes=max_bytes)
        else:
            value, receipt = hit
            verify_document_issue_inputs(core, directory, max_files=max_files, max_file_bytes=max_bytes)
            ledger = verify_document_issue_ledger(core, verify_reference(run_root, value["object"]))
        schema = json.loads(_schema_path().read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(ledger)
        if hit is None:
            artifact = put_bytes(run_root, canonical_json(ledger))
            receipt = shared.computed("document-issues", fingerprint, artifact, computation=computation)
        else:
            artifact = value["object"]

        drift_report = analyze_api_spec_drift(core, max_files=max_files, max_file_bytes=max_bytes)
        drift_schema = json.loads(_drift_schema_path().read_text(encoding="utf-8"))
        Draft202012Validator(drift_schema).validate(drift_report)
        drift_artifact = immutable_bytes(
            run_root,
            f"data/document-issues/{unit.job.attempt_id}/drift-issues.json",
            canonical_json(drift_report),
        )
        projection = _publish_projection(unit, core, ledger, drift_report, artifact, drift_artifact)

        unit.job.events.write("DOCUMENT_ISSUES_PUBLISHED", **ledger["counts"])
        unit.job.events.write(
            "DOCUMENT_DRIFT_PUBLISHED",
            specs_parsed=drift_report["specs_parsed"],
            handler_mismatches_found=len(drift_report["mismatches"]),
            telemetry=drift_report["telemetry"],
        )
        return {
            "schema": SCHEMA,
            "drift_schema": DRIFT_SCHEMA,
            "artifact": artifact,
            "drift_artifact": drift_artifact,
            "artifacts": [artifact, drift_artifact, projection["shard_artifact"], projection["checkpoint"]],
            "index_identity": projection["index_identity"],
            "index_manifest": projection["index_manifest"],
            "shared_receipt": receipt,
            "reused": hit is not None,
            "counts": ledger["counts"],
            "drift_counts": {
                "specs_parsed": drift_report["specs_parsed"],
                "handlers_scanned": drift_report["handlers_scanned"],
                "mismatches": len(drift_report["mismatches"]),
            },
            "telemetry": drift_report["telemetry"],
            "gaps": [
                UNADJUDICATED_GAP,
                *(gap["gap_id"] for candidate in ledger["candidates"] for gap in candidate["coverage_gaps"]),
                *drift_report["gaps"],
                *projection["gaps"][1:],
            ],
            "terminal_status": "COMPLETED_WITH_GAPS",
        }

    units = (Unit("analysis.map_and_adjudicate", analyze, output_validators=(_validate_output,)),)
    return Job(JOB_ID, "document_issue_analysis", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               units=units,
               datasets=DATASETS, contract=CONTRACT)
