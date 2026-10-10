from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.jobs.job_evidence_collection.job import load_target_catalog
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation,
    index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from .discovery import CATEGORIES, RULESET_IDENTITY, classify_path, merge, needs_probe, probe_content


JOB_ID = "job_design_artifact_discovery"
SHARD_ID = "design_artifacts"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "design_discovery": ("classify_paths", "probe_content"),
    "design_publication": ("build_index", "publish_handoff"),
}
_UNCATALOGED_REASONS = {"binary_excluded", "file_too_large", "inventory_bound_reached"}


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "design" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _read(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity["sha256"]:
        raise ValueError("design discovery artifact identity mismatch")
    return json.loads(path.read_text(encoding="utf-8"))


def _bounds(settings: Mapping[str, Any]) -> tuple[int, int, int, int]:
    values = (int(settings.get("max_artifacts", 20_000)), int(settings.get("max_probe_files", 2_000)),
              int(settings.get("max_probe_bytes", 16_384)), int(settings.get("max_file_bytes", 1_048_576)))
    if not 1 <= values[0] <= 200_000 or not 0 <= values[1] <= 50_000:
        raise ValueError("design discovery count bounds are outside the supported range")
    if not 256 <= values[2] <= 1_048_576 or not 1 <= values[3] <= 16 * 1024 * 1024:
        raise ValueError("design discovery byte bounds are outside the supported range")
    return values


def discover_design_artifacts(files: tuple[Mapping[str, Any], ...],
                              uncataloged: tuple[Mapping[str, Any], ...] = (), *,
                              max_artifacts: int = 20_000) -> tuple[list[dict[str, Any]], list[str]]:
    """Classify cataloged paths, plus uncataloged paths that are only identified by name."""
    found: list[dict[str, Any]] = []
    gaps: list[str] = []
    entries = [(item, True) for item in files] + [(item, False) for item in uncataloged]
    for item, cataloged in entries:
        path = str(item["path"])
        matches = classify_path(path)
        probe = cataloged and needs_probe(path, matches)
        if not matches and not probe:
            continue
        if len(found) >= max_artifacts:
            gaps.append(f"design artifact discovery stopped at configured max_artifacts={max_artifacts}")
            break
        found.append({"path": path, "sha256": item.get("sha256") if cataloged else None,
                      "size_bytes": int(item.get("size_bytes", 0)), "cataloged": cataloged,
                      "uncataloged_reason": None if cataloged else str(item.get("reason")),
                      "path_matches": matches, "probe": probe})
    return sorted(found, key=lambda value: value["path"]), gaps


def _probe(unit: UnitContext, candidates: list[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    _, max_probe_files, max_probe_bytes, max_file_bytes = _bounds(unit.job.config.settings)
    target_root = (unit.job.target_root or Path()).resolve()
    artifacts: list[dict[str, Any]] = []
    gaps: list[str] = []
    probed = 0
    for candidate in candidates:
        content_matches: list[dict[str, Any]] = []
        signals: dict[str, int] = {}
        probe_status = "not_probed"
        if candidate["probe"]:
            source = (target_root / candidate["path"]).resolve()
            if probed >= max_probe_files:
                probe_status = "bound_reached"
            elif target_root not in source.parents or not source.is_file() or source.is_symlink():
                probe_status = "unavailable"
                gaps.append(f"{candidate['path']}: cataloged file is unavailable for content probe")
            elif int(candidate["size_bytes"]) > max_file_bytes:
                probe_status = "too_large"
                gaps.append(f"{candidate['path']}: content probe skipped above max_file_bytes")
            else:
                data = source.read_bytes()
                probed += 1
                if hashlib.sha256(data).hexdigest() != candidate["sha256"]:
                    raise ValueError(f"target file changed after catalog acceptance: {candidate['path']}")
                content_matches, signals = probe_content(candidate["path"], data[:max_probe_bytes])
                probe_status = "probed" if len(data) <= max_probe_bytes else "probed_prefix"
        categories = merge(candidate["path_matches"], content_matches)
        if not categories:
            continue
        if not candidate["cataloged"]:
            gaps.append(f"{candidate['path']}: {categories[0]['category']} identified by name only; "
                        f"content not cataloged ({candidate['uncataloged_reason']})")
        artifacts.append({
            "artifact_id": "dsa:" + hashlib.sha256(canonical_json(
                {"path": candidate["path"], "sha256": candidate["sha256"]})).hexdigest(),
            "path": candidate["path"], "sha256": candidate["sha256"], "size_bytes": candidate["size_bytes"],
            "cataloged": candidate["cataloged"], "categories": categories, "signals": signals,
            "probe_status": probe_status,
        })
    skipped = sum(1 for item in candidates if item["probe"]) - probed
    if probed >= max_probe_files and skipped > 0:
        gaps.append(f"content probe bound max_probe_files={max_probe_files} reached; "
                    f"{skipped} candidates classified by path only")
    return artifacts, gaps


def load_accepted_design_artifacts(run_root: Path) -> dict[str, Any] | None:
    """Return the accepted discovery summary and artifact catalog, or None when never accepted."""
    run_root = Path(run_root)
    pointer_path = run_root / "data" / "jobs" / JOB_ID / "latest.json"
    if not pointer_path.is_file():
        return None
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError("design artifact discovery handoff is not accepted")
    published = handoff.get("outputs", {}).get("design_publication.publish_handoff", {})
    summary = _read(run_root, published.get("artifact", {}))
    if summary.get("schema") != "appsec-review/design-artifact-discovery-handoff/1":
        raise ValueError("design artifact discovery summary schema is unsupported")
    catalog = _read(run_root, summary["design_artifacts"])
    if catalog.get("schema") != "appsec-review/design-artifact-catalog/1":
        raise ValueError("design artifact catalog schema is unsupported")
    return {"handoff_sha256": str(pointer["handoff_sha256"]),
            "source_fingerprint": str(handoff.get("source_fingerprint")),
            "catalog_handoff_sha256": handoff.get("upstream_handoff_sha256", {}).get("job_target_catalog"),
            "summary_artifact": dict(published["artifact"]), "summary": summary,
            "artifacts": list(catalog["artifacts"])}


def _location(unit: UnitContext, artifact: Mapping[str, Any]) -> SourceLocation | None:
    if not artifact["cataloged"]:
        return None
    source = (unit.job.target_root or Path()) / str(artifact["path"])
    data = source.read_bytes()
    lines = max(1, data.count(b"\n") + (0 if data.endswith(b"\n") else 1))
    return SourceLocation(
        target_snapshot=unit.job.source_fingerprint, path=str(artifact["path"]),
        file_sha256=str(artifact["sha256"]), start_byte=0, end_byte=len(data), start_line=1,
        end_line=lines, start_column=1, end_column=1,
        producer_location={"producer": JOB_ID}, mapping_method="whole-cataloged-file", confidence=1.0,
    )


def build_job() -> Job:
    def validate(context, result) -> None:
        if context.target_root is None:
            raise ValueError("design artifact discovery requires a graph-provided target root")
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("design artifact discovery topology does not match central configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"design artifact discovery task order mismatch: {step}")
        _bounds(context.config.settings)
        catalog = load_target_catalog(context.run_root)
        if catalog.source_fingerprint != context.source_fingerprint:
            raise ValueError("design discovery fingerprint does not match the accepted target catalog")

    def classify_handler(unit: UnitContext) -> Mapping[str, Any]:
        catalog = load_target_catalog(unit.job.run_root)
        max_artifacts, _, _, _ = _bounds(unit.job.config.settings)
        uncataloged = tuple(item for item in catalog.gaps if item.get("reason") in _UNCATALOGED_REASONS)
        candidates, gaps = discover_design_artifacts(catalog.files, uncataloged, max_artifacts=max_artifacts)
        document = {"schema": "appsec-review/design-artifact-candidates/1", "ruleset": RULESET_IDENTITY,
                    "candidates": candidates, "gaps": gaps, "catalog_handoff_sha256": catalog.handoff_sha256}
        return {"artifact": _write(unit, "candidates.json", document), "item_count": len(candidates),
                "gaps": gaps}

    def probe_handler(unit: UnitContext) -> Mapping[str, Any]:
        source = unit.output("design_discovery.classify_paths")
        candidates = _read(unit.job.run_root, source["artifact"])["candidates"]
        artifacts, gaps = _probe(unit, candidates)
        gaps = [*source["gaps"], *gaps]
        document = {"schema": "appsec-review/design-artifact-catalog/1", "ruleset": RULESET_IDENTITY,
                    "artifacts": artifacts, "gaps": gaps}
        return {"artifact": _write(unit, "design-artifacts.json", document), "item_count": len(artifacts),
                "gaps": gaps, "terminal_status": "PARTIAL" if gaps else "SUCCEEDED"}

    def index_handler(unit: UnitContext) -> Mapping[str, Any]:
        source = unit.output("design_discovery.probe_content")
        document = _read(unit.job.run_root, source["artifact"])
        fingerprint = index_fingerprint(
            name="analysis", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=[source["artifact"]],
            tool_identity={"ruleset": RULESET_IDENTITY,
                           "config": hashlib.sha256(canonical_json(dict(unit.job.config.settings))).hexdigest()},
            parser_identity="design-artifact-probe/1", normalizer_identity="design-artifact-merge/1",
            mapping_identity="whole-cataloged-file/1",
        )
        path = unit.job.run_root / "data" / "indices" / "analysis" / SHARD_ID / f"{fingerprint}.sqlite"
        if not path.exists():
            builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id=SHARD_ID)
            for artifact in document["artifacts"]:
                identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                  {"design_artifact_id": artifact["artifact_id"]})
                categories = [item["category"] for item in artifact["categories"]]
                subtypes = [item["subtype"] for item in artifact["categories"]]
                payload = {**artifact, "category": categories[0], "subtype": subtypes[0],
                           "category_set": categories, "subtype_set": subtypes}
                builder.add_entity(EntityRecord(
                    identity, artifact["artifact_id"], artifact["path"],
                    " ".join(["design_artifact", artifact["path"], *categories, *subtypes]),
                    payload, _location(unit, artifact)))
            found = {item["category"] for artifact in document["artifacts"] for item in artifact["categories"]}
            for category in CATEGORIES:
                builder.add_coverage(f"design:{category}", "partial" if document["gaps"] else "complete",
                                     "; ".join(document["gaps"][:10]) or None)
            builder.add_coverage("design:absent_categories", "complete",
                                 ", ".join(sorted(set(CATEGORIES) - found)) or None)
            sha256 = builder.build()
        else:
            sha256 = file_sha256(path)
        identity = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha256, fingerprint,
                                 _rel(unit.job.run_root, path), {"job": JOB_ID, "ruleset": RULESET_IDENTITY},
                                 tuple(document["gaps"]), SHARD_ID)
        return {"artifact": _artifact(unit.job.run_root, path), "index_identity": asdict(identity),
                "item_count": len(document["artifacts"]), "gaps": document["gaps"]}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        probed = unit.output("design_discovery.probe_content")
        document = _read(unit.job.run_root, probed["artifact"])
        indexed = unit.output("design_publication.build_index")
        manifest_path, manifest_sha = resolve_accepted_manifest(unit.job.run_root)
        upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
        identities = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                      for item in upstream["indexes"]
                      if not (item["name"] == "analysis" and item.get("shard_id") == SHARD_ID)]
        identities.append(IndexIdentity(**{**indexed["index_identity"],
                                           "gaps": tuple(indexed["index_identity"].get("gaps", ()))}))
        combined = unit.job.run_root / "data" / "indices" / "manifests" / f"design-{unit.job.attempt_id}.json"
        write_manifest(combined, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or Path(), indexes=identities,
                       upstream_manifests=({"path": _rel(unit.job.run_root, manifest_path),
                                            "sha256": manifest_sha},))
        load_verified_manifest(unit.job.run_root, combined, file_sha256(combined))
        counts = Counter(item["category"] for artifact in document["artifacts"] for item in artifact["categories"])
        subtypes = Counter(f"{item['category']}:{item['subtype']}"
                           for artifact in document["artifacts"] for item in artifact["categories"])
        summary = {"schema": "appsec-review/design-artifact-discovery-handoff/1",
                   "target_fingerprint": unit.job.source_fingerprint, "ruleset": RULESET_IDENTITY,
                   "design_artifacts": probed["artifact"], "index_manifest": _artifact(unit.job.run_root, combined),
                   "counts_by_category": {category: counts.get(category, 0) for category in CATEGORIES},
                   "counts_by_subtype": dict(sorted(subtypes.items())),
                   # Absence is a discovery fact about cataloged paths, never evidence of security.
                   "absent_categories": [category for category in CATEGORIES if not counts.get(category)],
                   "gaps": document["gaps"], "security_findings": []}
        return {**summary, "artifact": _write(unit, "handoff.json", summary),
                "terminal_status": "PARTIAL" if summary["gaps"] else "SUCCEEDED"}

    units = (
        Unit("design_discovery.classify_paths", classify_handler),
        Unit("design_discovery.probe_content", probe_handler, ("design_discovery.classify_paths",)),
        Unit("design_publication.build_index", index_handler, ("design_discovery.probe_content",)),
        Unit("design_publication.publish_handoff", publish,
             ("design_discovery.probe_content", "design_publication.build_index")),
    )
    source_files = (Path(__file__), Path(__file__).with_name("discovery.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files)).hexdigest()
    return Job(JOB_ID, "design_artifact_discovery", UnitExecutor(units).execute,
               input_validators=(validate,), schema_identity="appsec-review/design-artifact-discovery-job/1",
               implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               units=units)
