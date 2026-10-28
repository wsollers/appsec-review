"""Isolated source lanes within the history jobs' existing unit topology."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
import hashlib
from pathlib import Path
from typing import Any

from appsec_review.retrieval import IndexIdentity, write_manifest
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


def source_key(source: Mapping[str, Any]) -> str:
    return hashlib.sha256(str(source["source_id"]).encode()).hexdigest()[:16]


def source_identity(source: Mapping[str, Any]) -> dict[str, Any]:
    return {"source_id": source["source_id"]} if source.get("source_id", ".") != "." else {}


def source_of(unit: UnitContext) -> Mapping[str, Any]:
    for name in ("resolve_sources.resolve_history_source", "load.accepted_history"):
        if name in unit.outputs:
            return unit.output(name).get("source", {})
    return {}


def target_path(root: str, path: str) -> str:
    return path if root == "." else f"{root}/{path}"


def map_commits(commits: list[dict[str, Any]], root: str) -> list[dict[str, Any]]:
    if root != ".":
        for commit in commits:
            for entry in commit["files"]:
                entry["path"] = target_path(root, entry["path"])
                if entry.get("renamed_from") is not None:
                    entry["renamed_from"] = target_path(root, entry["renamed_from"])
    return commits


def lane_context(unit: UnitContext, source_id: str) -> UnitContext:
    outputs = {key: value["by_source"][source_id] if "by_source" in value else value
               for key, value in unit.outputs.items()}
    key = hashlib.sha256(source_id.encode()).hexdigest()[:16]
    return replace(unit, outputs=outputs, unit_root=unit.unit_root / "sources" / key)


def per_source(handler: Callable[[UnitContext], Mapping[str, Any]], first_unit: str,
               aggregate: Callable[[UnitContext, Mapping[str, Any]], Mapping[str, Any]] | None = None
               ) -> Callable[[UnitContext], Mapping[str, Any]]:
    def execute(unit: UnitContext) -> Mapping[str, Any]:
        first = unit.outputs.get(first_unit, {})
        if "by_source" not in first:
            return handler(unit)
        results = {}
        for key in first["by_source"]:
            lane = lane_context(unit, key)
            prior_error = next((value for value in lane.outputs.values() if value.get("source_error")), None)
            if prior_error and not unit.unit_id.startswith("publish."):
                results[key] = {**prior_error, "reason": "upstream_source_failed"}
                continue
            try:
                results[key] = dict(handler(lane))
            except (OSError, ValueError, RuntimeError) as exc:
                unit.job.events.write("SOURCE_LANE_FAILED", source_id=key, unit_id=unit.unit_id,
                                      error_type=type(exc).__name__)
                gap = f"source_failed:{unit.unit_id}:{type(exc).__name__}"
                results[key] = {"source_error": True, "terminal_status": "PARTIAL", "gaps": [gap],
                                "eligible": {}, "binding": "unavailable", "young_line_share": {},
                                "dispositions": [{"disposition": "GAP", "reason": gap}]}
                if unit.unit_id.startswith("publish."):
                    # A publication integrity failure must not create an accepted, incomplete manifest.
                    raise
        gaps = sorted({f"{key}:{gap}" for key, value in results.items() for gap in value.get("gaps", ())})
        output = {"by_source": results, "gaps": gaps,
                  "terminal_status": "PARTIAL" if gaps else "SUCCEEDED"}
        dispositions = [item for value in results.values() for item in value.get("dispositions", ())]
        if dispositions:
            output["dispositions"] = dispositions
        return {**output, **aggregate(unit, output)} if aggregate else output
    return execute


def combine_indexes(unit: UnitContext, output: Mapping[str, Any]) -> Mapping[str, Any]:
    upstream_path, upstream_sha = resolve_context_manifest(unit.job)
    upstream, _ = load_verified_manifest(unit.job.run_root, upstream_path, upstream_sha)
    job_id = unit.job.config.job_id
    indexes = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
               for item in upstream["indexes"] if item.get("producer", {}).get("job") != job_id]
    indexes.extend(IndexIdentity(**{**value["index_identity"],
                                    "gaps": tuple(value["index_identity"].get("gaps", ()))})
                   for value in output["by_source"].values())
    path = unit.job.run_root / "data" / "indices" / "manifests" / f"{job_id}-{unit.job.attempt_id}.json"
    write_manifest(path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=(unit.job.target_root or Path()).resolve(), indexes=indexes,
                   upstream_manifests=({"path": upstream_path.relative_to(unit.job.run_root).as_posix(),
                                        "sha256": upstream_sha},))
    digest = file_sha256(path)
    load_verified_manifest(unit.job.run_root, path, digest)
    return {"manifest": {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": digest,
                         "size_bytes": path.stat().st_size}}
