"""Generic, bounded ingestion of test coverage emitted by accepted builds.

This producer never executes target tests and never scans a target or build tree. Candidate files
must be enumerated and hash-bound in an accepted language-build receipt. The accepted artifact
index and target catalog are independently verified before any candidate bytes are opened.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.jobs.engineering_contracts import TEST_COVERAGE_HANDOFF_SCHEMA
from appsec_review.jobs.job_artifact_indexing import load_accepted_artifact_index
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_language_build.node import is_coverage_exchange_path
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from .datasets import CONSUMES, DATASETS
from .parsers import CoverageDocument, CoverageFile, CoverageTotals, parse_coverage


TOPOLOGY = {
    "load": ("accepted_inputs",),
    "normalize": ("coverage",),
    "index": ("coverage",),
    "acceptance": ("publish_handoff",),
}
PARSER_IDENTITY = "appsec-review/test-coverage-parsers/1"
NORMALIZER_IDENTITY = "appsec-review/test-coverage-normalizer/1"
MAPPING_IDENTITY = "appsec-review/test-coverage-source-binding/1"
class CoverageIntegrityError(ValueError):
    """An accepted identity changed or escaped the run boundary."""


@dataclass(frozen=True, slots=True)
class CoverageBounds:
    max_artifacts: int = 256
    max_artifact_bytes: int = 32 * 1024 * 1024
    max_rows_per_artifact: int = 250_000
    max_files_per_artifact: int = 50_000
    max_path_candidates: int = 20

    def __post_init__(self) -> None:
        if any(value < 1 for value in asdict(self).values()):
            raise ValueError("test-coverage bounds must be positive")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CoverageBounds":
        return cls(**{field: int(value[field]) for field in asdict(cls()) if field in value})


def _safe_file(run_root: Path, identity: Mapping[str, Any], label: str) -> Path:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise CoverageIntegrityError(f"{label} is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise CoverageIntegrityError(f"{label} identity changed")
    return path


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[Mapping[str, Any], str]:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise CoverageIntegrityError(f"accepted {job_id} handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = _safe_file(run_root, {
        "path": pointer.get("handoff_path"), "sha256": pointer.get("handoff_sha256")}, f"{job_id} handoff")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != job_id):
        raise CoverageIntegrityError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def _load_catalog_files(run_root: Path) -> tuple[list[Mapping[str, Any]], str, Mapping[str, str]]:
    handoff, handoff_sha = _accepted_handoff(run_root, "job_target_catalog")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    identity = published.get("artifact") if isinstance(published, Mapping) else None
    if not isinstance(identity, Mapping):
        raise CoverageIntegrityError("target catalog publication is unavailable")
    if not any(item.get("path") == identity.get("path") and item.get("sha256") == identity.get("sha256")
               for item in handoff.get("artifacts", ()) if isinstance(item, Mapping)):
        raise CoverageIntegrityError("target catalog publication is not bound to its handoff")
    catalog = json.loads(_safe_file(run_root, identity, "target catalog").read_text(encoding="utf-8"))
    if catalog.get("schema") != "appsec-review/target-catalog/1":
        raise CoverageIntegrityError("target catalog schema is unsupported")
    partition_identity = catalog.get("artifacts", {}).get("repository_discovery.partition_repository")
    if not isinstance(partition_identity, Mapping):
        raise CoverageIntegrityError("target catalog source inventory is unavailable")
    partition = json.loads(_safe_file(run_root, partition_identity, "target source inventory").read_text(encoding="utf-8"))
    files = partition.get("files")
    if not isinstance(files, list):
        raise CoverageIntegrityError("target source inventory is invalid")
    hashes: dict[str, str] = {}
    for item in files:
        if (not isinstance(item, Mapping) or not isinstance(item.get("path"), str) or
                not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))):
            raise CoverageIntegrityError("target source inventory contains an invalid row")
        if item["path"] in hashes:
            raise CoverageIntegrityError("target source inventory contains a duplicate path")
        hashes[item["path"]] = str(item["sha256"])
    return files, handoff_sha, hashes


def _format(path: str, data: bytes) -> str | None:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    prefix = data[:4096].lstrip()
    if name.endswith((".info", ".lcov")) or name == "lcov" or prefix.startswith((b"TN:", b"SF:")):
        return "lcov"
    if prefix.startswith((b"{", b"[")):
        try:
            value = json.loads(data.decode("utf-8-sig", errors="strict"))
        except (UnicodeError, json.JSONDecodeError):
            return "llvm" if name.endswith(".json") else None
        if isinstance(value, Mapping) and isinstance(value.get("data"), list) and "type" in value:
            return "llvm"
        return None
    lowered = prefix.lower()
    if b"<coverage" in lowered:
        return "cobertura"
    if b"<report" in lowered and (b"jacoco" in lowered or name.startswith("jacoco")):
        return "jacoco"
    return None


def _is_candidate(artifact: Mapping[str, Any]) -> bool:
    path = str(artifact.get("workspace_path") or artifact.get("path") or "").replace("\\", "/")
    kind = str(artifact.get("kind", "")).lower()
    return is_coverage_exchange_path(path) or "coverage" in kind


def _normalize_report_path(value: str) -> str:
    raw = value.strip().replace("\\", "/")
    if raw.startswith("file://"):
        raw = raw[7:]
    raw = re.sub(r"^[A-Za-z]:", "", raw).lstrip("/")
    return PurePosixPath(raw).as_posix()


def bind_coverage_paths(
    document: CoverageDocument, catalog_hashes: Mapping[str, str], *, build_root: str = ".",
    max_path_candidates: int = 20,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Bind producer paths to exactly one accepted catalog path and SHA-256 identity."""
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    catalog = sorted(catalog_hashes)
    normalized_root = "" if build_root in {"", "."} else build_root.strip("/").replace("\\", "/")
    for item in document.files:
        normalized = _normalize_report_path(item.source_path)
        direct = [normalized]
        if normalized_root:
            if normalized.startswith(normalized_root + "/"):
                direct.append(normalized[len(normalized_root) + 1:])
            else:
                direct.append(f"{normalized_root}/{normalized}")
        exact = [path for path in direct if path in catalog_hashes]
        matches = sorted(set(exact or [path for path in catalog if (
            normalized == path or normalized.endswith("/" + path) or path.endswith("/" + normalized))]))
        row = {"producer_path": item.source_path, "normalized_path": normalized,
               "format": document.format, "totals": item.totals.as_dict()}
        if len(matches) == 1:
            rows.append({**row, "path": matches[0], "file_sha256": catalog_hashes[matches[0]],
                         "binding": "exact" if matches[0] in exact else "unique-suffix",
                         "binding_candidates": matches})
        elif not matches:
            rows.append({**row, "path": None, "file_sha256": None, "binding": "unresolved",
                         "binding_candidates": []})
            gaps.append(f"unresolved_source_path: {item.source_path}")
        else:
            retained = matches[:max_path_candidates]
            rows.append({**row, "path": None, "file_sha256": None, "binding": "ambiguous",
                         "binding_candidates": retained})
            gaps.append(f"ambiguous_source_path: {item.source_path} matched {len(matches)} catalog paths")
            if len(matches) > max_path_candidates:
                gaps.append(f"path_candidate_truncation: {item.source_path} retained {max_path_candidates} of {len(matches)}")
    return rows, gaps


def ingest_coverage_artifacts(
    run_root: Path, receipts: Sequence[Mapping[str, Any]], catalog_hashes: Mapping[str, str],
    *, bounds: CoverageBounds = CoverageBounds(), applicable_families: Sequence[str] = (),
) -> dict[str, Any]:
    """Normalize only coverage files enumerated by accepted build receipts."""
    allowed = frozenset(applicable_families)
    units: list[dict[str, Any]] = []
    global_gaps: list[str] = []
    for receipt in sorted(receipts, key=lambda item: str(item.get("build_unit_id", ""))):
        build_unit_id = str(receipt.get("build_unit_id", ""))
        family = str(receipt.get("family", ""))
        if allowed and family not in allowed:
            continue
        unit_gaps: list[str] = []
        candidates = [item for item in receipt.get("artifacts", ())
                      if isinstance(item, Mapping) and _is_candidate(item)]
        if len(candidates) > bounds.max_artifacts:
            unit_gaps.append(
                f"artifact_count_truncation: retained {bounds.max_artifacts} of {len(candidates)} coverage artifacts")
            candidates = candidates[:bounds.max_artifacts]
        rows: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for candidate in candidates:
            label = str(candidate.get("workspace_path") or candidate.get("path") or "coverage artifact")
            artifact_origin = candidate.get("artifact_origin", "build-output")
            if artifact_origin not in {"accepted-input", "build-output"}:
                raise CoverageIntegrityError(
                    f"coverage artifact {label} has invalid artifact origin")
            try:
                path = _safe_file(run_root, candidate, f"coverage artifact {label}")
            except CoverageIntegrityError:
                raise
            if path.stat().st_size > bounds.max_artifact_bytes:
                unit_gaps.append(f"artifact_byte_bound: {label} exceeds {bounds.max_artifact_bytes} bytes")
                continue
            data = path.read_bytes()
            format_name = _format(label, data)
            if format_name is None:
                unit_gaps.append(f"unsupported_coverage_format: {label}")
                continue
            try:
                document = parse_coverage(data, format_name, max_rows=bounds.max_rows_per_artifact)
            except ValueError as exc:
                unit_gaps.append(f"malformed_coverage: {label}: {exc}")
                continue
            if len(document.files) > bounds.max_files_per_artifact:
                unit_gaps.append(
                    f"coverage_file_truncation: {label} retained {bounds.max_files_per_artifact} "
                    f"of {len(document.files)} source rows")
                document = CoverageDocument(document.format, document.files[:bounds.max_files_per_artifact], document.gaps)
            bound, binding_gaps = bind_coverage_paths(
                document, catalog_hashes, build_root=str(receipt.get("root", ".")),
                max_path_candidates=bounds.max_path_candidates)
            for row in bound:
                if row.get("path") and row["path"] in seen_paths:
                    unit_gaps.append(f"overlapping_coverage_reports: {row['path']} occurs in multiple artifacts")
                if row.get("path"):
                    seen_paths.add(str(row["path"]))
                rows.append({**row, "artifact_path": candidate.get("path"),
                             "artifact_sha256": candidate.get("sha256"),
                             "artifact_origin": artifact_origin})
            unit_gaps.extend(binding_gaps)
            artifacts.append({"path": candidate.get("path"), "workspace_path": candidate.get("workspace_path"),
                              "sha256": candidate.get("sha256"), "format": format_name,
                              "source_row_count": len(document.files),
                              "artifact_origin": artifact_origin})
        applicable = receipt.get("terminal_status") in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
        if applicable and not candidates:
            unit_gaps.append("missing_applicable_coverage: accepted build receipt has no coverage artifact")
        bound_rows = [row for row in rows if row.get("path")]
        totals = CoverageTotals()
        for row in bound_rows:
            value = row["totals"]
            totals += CoverageTotals(*(int(value[key]) for key in (
                "lines_total", "lines_covered", "branches_total", "branches_covered",
                "functions_total", "functions_covered")))
        units.append({"build_unit_id": build_unit_id, "family": family, "root": receipt.get("root", "."),
                      "artifacts": artifacts, "files": rows, "totals": totals.as_dict(),
                      "gaps": list(dict.fromkeys(unit_gaps)),
                      "coverage_state": "unavailable" if not bound_rows else
                                        "partial" if unit_gaps else "complete"})
        global_gaps.extend(f"{build_unit_id}: {gap}" for gap in unit_gaps)
    return {"units": units, "gaps": list(dict.fromkeys(global_gaps))}


def _artifact(unit: UnitContext, path: Path, value: Any | None = None) -> dict[str, Any]:
    if value is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, value)
    return {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _settings(unit: UnitContext) -> tuple[CoverageBounds, tuple[str, ...]]:
    value = unit.job.config.settings
    bounds_value = value.get("bounds", {})
    if not isinstance(bounds_value, Mapping):
        raise ValueError("test-coverage bounds are invalid")
    families = value.get("applicable_families", ())
    if (not isinstance(families, list) or any(not isinstance(item, str) or not item for item in families) or
            len(families) != len(set(families))):
        raise ValueError("test-coverage applicable families are invalid")
    return CoverageBounds.from_mapping(bounds_value), tuple(families)


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("test-coverage topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"test-coverage task order mismatch: {step}")
    bounds = context.config.settings.get("bounds")
    if not isinstance(bounds, Mapping):
        raise ValueError("test-coverage bounds are required")
    CoverageBounds.from_mapping(bounds)
    for key, expected in (("parser_identity", PARSER_IDENTITY),
                          ("normalizer_identity", NORMALIZER_IDENTITY),
                          ("mapping_identity", MAPPING_IDENTITY)):
        if context.config.settings.get(key) != expected:
            raise ValueError(f"test-coverage {key} is invalid")


def build_job() -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        _files, catalog_handoff_sha, hashes = _load_catalog_files(unit.job.run_root)
        language = load_accepted_language_build(unit.job.run_root)
        artifacts = load_accepted_artifact_index(unit.job.run_root)
        if (language.get("source_fingerprint") != unit.job.source_fingerprint or
                artifacts.get("source_fingerprint") != unit.job.source_fingerprint):
            raise CoverageIntegrityError("coverage inputs disagree with the accepted target snapshot")
        return {"receipts": language.get("receipts", ()), "catalog_hashes": hashes,
                "upstream_handoffs": {
                    "job_target_catalog": catalog_handoff_sha,
                    "job_language_build": language["language_build_handoff_sha256"],
                    "job_artifact_indexing": artifacts["handoff_sha256"],
                }, "upstream_manifest": artifacts["index_manifest"]}

    def normalize(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        bounds, families = _settings(unit)
        return ingest_coverage_artifacts(unit.job.run_root, loaded["receipts"], loaded["catalog_hashes"],
                                         bounds=bounds, applicable_families=families)

    def index(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        normalized = unit.output("normalize.coverage")
        upstream_identity = loaded["upstream_manifest"]
        prior_path = _safe_file(unit.job.run_root, upstream_identity, "artifact-index manifest")
        prior, _ = load_verified_manifest(unit.job.run_root, prior_path, str(upstream_identity["sha256"]))
        existing = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
                    for raw in prior["indexes"] if not (
                        raw["name"] == "analysis" and str(raw.get("shard_id", "")).startswith("test-coverage-"))]
        current: list[IndexIdentity] = []
        for value in normalized["units"]:
            artifacts = [{"build_unit_id": value["build_unit_id"]}, *(
                {"path": item.get("path"), "sha256": item.get("sha256")} for item in value["artifacts"])]
            fingerprint = index_fingerprint(
                name="analysis", target_snapshot=unit.job.source_fingerprint, producer_artifacts=artifacts,
                tool_identity={"producer": "accepted-test-coverage"}, parser_identity=PARSER_IDENTITY,
                normalizer_identity=NORMALIZER_IDENTITY, mapping_identity=MAPPING_IDENTITY,
                upstream_manifests=(str(upstream_identity["sha256"]),))
            shard_id = f"test-coverage-{value['build_unit_id']}"
            path = unit.job.run_root / "data" / "indices" / "analysis" / f"{fingerprint}.sqlite"
            if path.exists():
                sha = file_sha256(path)
            else:
                builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                                       target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
                for row in value["files"]:
                    native = {"build_unit_id": value["build_unit_id"], "artifact_sha256": row["artifact_sha256"],
                              "producer_path": row["producer_path"], "path": row.get("path")}
                    identity = LogicalIdentity.derive(EntityKind.COVERAGE_CELL, unit.job.source_fingerprint, native)
                    name = str(row.get("path") or row["producer_path"])
                    builder.add_entity(EntityRecord(identity, json.dumps(native, sort_keys=True), name,
                        f"test coverage {name}", {**row, "build_unit_id": value["build_unit_id"],
                                                  "family": value["family"]}))
                aggregate_identity = LogicalIdentity.derive(EntityKind.COVERAGE_CELL, unit.job.source_fingerprint,
                    {"build_unit_id": value["build_unit_id"], "aggregate": True})
                builder.add_entity(EntityRecord(aggregate_identity, value["build_unit_id"], value["build_unit_id"],
                    f"test coverage totals for {value['build_unit_id']}",
                    {"build_unit_id": value["build_unit_id"], "family": value["family"],
                     "totals": value["totals"], "coverage_state": value["coverage_state"]}))
                builder.add_coverage(f"test-coverage:{value['build_unit_id']}", value["coverage_state"],
                                     "; ".join(value["gaps"][:10])[:1000] or None)
                sha = builder.build()
            current.append(IndexIdentity(
                "analysis", "appsec-review/retrieval-index/2", sha, fingerprint,
                path.relative_to(unit.job.run_root).as_posix(),
                {"job": "job_test_coverage", "unit": unit.unit_id,
                 "parser_identity": PARSER_IDENTITY, "normalizer_identity": NORMALIZER_IDENTITY,
                 "mapping_identity": MAPPING_IDENTITY}, tuple(value["gaps"]), shard_id))
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"test-coverage-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or unit.job.repository_root,
                       indexes=(*existing, *current), upstream_manifests=(upstream_identity,))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        return {"indexes": [asdict(item) for item in current], "index_manifest": _artifact(unit, manifest_path),
                "gaps": normalized["gaps"]}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        normalized = unit.output("normalize.coverage")
        indexed = unit.output("index.coverage")
        totals = CoverageTotals()
        for value in normalized["units"]:
            raw = value["totals"]
            totals += CoverageTotals(*(int(raw[key]) for key in (
                "lines_total", "lines_covered", "branches_total", "branches_covered",
                "functions_total", "functions_covered")))
        document = {"schema": TEST_COVERAGE_HANDOFF_SCHEMA,
                    "source_fingerprint": unit.job.source_fingerprint,
                    "upstream_handoff_sha256": loaded["upstream_handoffs"],
                    "parser_identity": PARSER_IDENTITY, "normalizer_identity": NORMALIZER_IDENTITY,
                    "mapping_identity": MAPPING_IDENTITY,
                    "build_units": normalized["units"], "totals": totals.as_dict(),
                    "gaps": normalized["gaps"], "index_manifest": indexed["index_manifest"]}
        path = unit.job.attempt_root / "artifacts" / "test-coverage" / "accepted-test-coverage.json"
        artifact = _artifact(unit, path, document)
        return {"schema": TEST_COVERAGE_HANDOFF_SCHEMA, "artifact": artifact,
                "index_manifest": indexed["index_manifest"], "item_count": len(normalized["units"]),
                "gaps": normalized["gaps"], "terminal_status": "COMPLETED_WITH_GAPS" if normalized["gaps"] else
                                                         "SUCCEEDED" if normalized["units"] else "NOT_APPLICABLE"}

    units = (
        Unit("load.accepted_inputs", load),
        Unit("normalize.coverage", normalize, ("load.accepted_inputs",)),
        Unit("index.coverage", index, ("load.accepted_inputs", "normalize.coverage")),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_inputs", "normalize.coverage", "index.coverage")),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes() + Path(__file__).with_name("parsers.py").read_bytes()).hexdigest()
    return Job("job_test_coverage", "test_coverage", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=TEST_COVERAGE_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, consumes=CONSUMES)


def load_accepted_test_coverage(run_root: Path) -> Mapping[str, Any]:
    """Load and verify the immutable accepted coverage document and its full manifest."""
    handoff, handoff_sha = _accepted_handoff(Path(run_root), "job_test_coverage")
    published = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    identity = published.get("artifact") if isinstance(published, Mapping) else None
    manifest = published.get("index_manifest") if isinstance(published, Mapping) else None
    if not isinstance(identity, Mapping) or not isinstance(manifest, Mapping):
        raise CoverageIntegrityError("test-coverage publication is unavailable")
    artifacts = handoff.get("artifacts", ())
    for expected in (identity, manifest):
        if not any(item.get("path") == expected.get("path") and item.get("sha256") == expected.get("sha256")
                   for item in artifacts if isinstance(item, Mapping)):
            raise CoverageIntegrityError("test-coverage publication is not bound to its handoff")
    document = json.loads(_safe_file(Path(run_root), identity, "test-coverage handoff").read_text(encoding="utf-8"))
    if document.get("schema") != TEST_COVERAGE_HANDOFF_SCHEMA:
        raise CoverageIntegrityError("test-coverage handoff schema is unsupported")
    load_verified_manifest(Path(run_root), _safe_file(Path(run_root), manifest, "test-coverage manifest"),
                           str(manifest["sha256"]))
    return {**document, "handoff_sha256": handoff_sha}
