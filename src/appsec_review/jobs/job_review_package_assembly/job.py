"""Publish and verify packages from the final accepted retrieval manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.retrieval.core import RetrievalCore, resolve_context_manifest
from appsec_review.indexing.store import accepted_handoff
from appsec_review.review_packages import publish_review_packages, verify_review_packages
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import file_sha256

from .datasets import CONSUMES, DATASETS


JOB_ID = "job_review_package_assembly"
SCHEMA = "appsec-review/review-package-assembly/1"
TOPOLOGY = {"publication": ("publish_packages",)}


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("review package assembly topology differs from central configuration")
    if tuple(context.config.step("publication").tasks) != TOPOLOGY["publication"]:
        raise ValueError("review package assembly task differs from central configuration")
    page_size = context.config.settings.get("max_page_size")
    if type(page_size) is not int or not 1 <= page_size <= 100:
        raise ValueError("review package max_page_size must be an integer from 1 through 100")


def _core(unit: UnitContext) -> tuple[RetrievalCore, Path, str]:
    from appsec_review.storage.validation import current_validation
    manifest_path, manifest_sha = resolve_context_manifest(unit.job)
    validation = current_validation(unit.job.run_root)
    key = ("package-core", str(manifest_path), manifest_sha)
    if validation is not None and key in validation.records:
        return validation.records[key], manifest_path, manifest_sha
    core = RetrievalCore(unit.job.run_root.parent, unit.job.run_id,
                         manifest_sha256=manifest_sha, manifest_path=manifest_path)
    if validation is not None:
        validation.records[key] = core
    return core, manifest_path, manifest_sha


def _validate_output(unit: UnitContext, result: Mapping[str, Any] | None) -> None:
    if result is None:
        raise ValueError("review package publication result is unavailable")
    core, manifest_path, manifest_sha = _core(unit)
    if manifest_sha != str(result["accepted_manifest_sha256"]):
        raise ValueError("review package publication used a different input manifest")
    directory = (unit.job.run_root / str(result["package_directory"])).resolve()
    manifest = verify_review_packages(core, directory)
    manifest_path = directory / "manifest.json"
    if (manifest["content_sha256"] != result["content_sha256"] or
            file_sha256(manifest_path) != result["manifest_sha256"] or
            manifest["counts"] != result["counts"] or
            len(manifest["coverage_gaps"]) != result["coverage_gap_count"]):
        raise ValueError("review package publication receipt differs from verified output")


def build_job() -> Job:
    def publish(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        core, accepted_path, accepted_sha = _core(unit)
        if core.manifest["target_snapshot"] != unit.job.source_fingerprint:
            raise ValueError("review package target snapshot differs from the graph target")
        handoff = accepted_handoff(run_root, "job_review_data_indexing")
        input_manifest = json.loads(accepted_path.read_text(encoding="utf-8"))
        bound = {(item.get("path"), item.get("sha256"))
                 for item in handoff.handoff.get("artifacts", ())} if handoff is not None else set()
        lineage = {(item.get("path"), item.get("sha256"))
                   for item in input_manifest.get("upstream_manifests", ())}
        if handoff is None or not (bound & (lineage | {
                (accepted_path.relative_to(run_root).as_posix(), accepted_sha)})):
            raise ValueError("review packages require the accepted review-data-indexing manifest")
        directory = publish_review_packages(core, max_page_size=unit.job.config.settings["max_page_size"])
        manifest = verify_review_packages(core, directory)
        gaps = manifest["coverage_gaps"]
        artifacts = [{"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
                      "size_bytes": path.stat().st_size}
                     for path in sorted(directory.glob("*.json"))]
        unit.job.events.write("REVIEW_PACKAGES_PUBLISHED", package_count=len(manifest["packages"]),
                              coverage_gap_count=len(gaps), manifest_sha256=accepted_sha)
        return {"schema": SCHEMA, "accepted_manifest_sha256": accepted_sha,
                "package_directory": directory.relative_to(run_root).as_posix(),
                "content_sha256": manifest["content_sha256"],
                "manifest_sha256": file_sha256(directory / "manifest.json"),
                "artifacts": artifacts,
                "counts": manifest["counts"], "package_count": len(manifest["packages"]),
                "coverage_gap_count": len(gaps), "gaps": [item["gap_id"] for item in gaps],
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    units = (Unit("publication.publish_packages", publish, output_validators=(_validate_output,)),)
    return Job(JOB_ID, "review_package_assembly", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               units=units,
               datasets=DATASETS, consumes=CONSUMES)
