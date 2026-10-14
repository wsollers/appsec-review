"""Generic ingestion of hash-bound, textual execution profiles from accepted builds.

Profile hotness is context only.  It is neither a security finding nor an estimate of defect
probability, and this producer never executes the target or invokes a profile converter.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.jobs.engineering_contracts import PROFILE_DATA_HANDOFF_SCHEMA
from appsec_review.jobs.job_artifact_indexing import load_accepted_artifact_index
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from .datasets import CONSUMES, DATASETS
from .parsers import ProfileDocument, parse_profile


TOPOLOGY = {
    "load": ("accepted_inputs",),
    "normalize": ("profile_data",),
    "index": ("profile_data",),
    "acceptance": ("publish_handoff",),
}
PARSER_IDENTITY = "appsec-review/profile-data-parsers/1"
NORMALIZER_IDENTITY = "appsec-review/profile-data-normalizer/1"
MAPPING_IDENTITY = "appsec-review/profile-data-report-binding/1"
SEMANTICS = "context_only"
_SUPPORTED = frozenset({"folded-stacks", "perf-script", "callgrind", "llvm-sample"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProfileIntegrityError(ValueError):
    """An accepted identity changed, escaped the run, or contradicted its handoff."""


@dataclass(frozen=True, slots=True)
class ProfileBounds:
    max_artifacts: int = 256
    max_artifact_bytes: int = 32 * 1024 * 1024
    max_rows_per_artifact: int = 250_000
    max_line_bytes: int = 64 * 1024
    max_frames_per_sample: int = 256

    def __post_init__(self) -> None:
        if any(value < 1 for value in asdict(self).values()):
            raise ValueError("profile-data bounds must be positive")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProfileBounds":
        return cls(**{field: int(value[field]) for field in asdict(cls()) if field in value})


def _safe_file(run_root: Path, identity: Mapping[str, Any], label: str) -> Path:
    candidate = run_root / str(identity.get("path", ""))
    if candidate.is_symlink():
        raise ProfileIntegrityError(f"{label} is unavailable, a symlink, or outside the run")
    path = candidate.resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ProfileIntegrityError(f"{label} is unavailable, a symlink, or outside the run")
    expected = identity.get("sha256")
    if not isinstance(expected, str) or not _SHA256.fullmatch(expected) or file_sha256(path) != expected:
        raise ProfileIntegrityError(f"{label} identity changed")
    return path


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[Mapping[str, Any], str]:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise ProfileIntegrityError(f"accepted {job_id} handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = _safe_file(run_root, {
        "path": pointer.get("handoff_path"), "sha256": pointer.get("handoff_sha256")}, f"{job_id} handoff")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != job_id):
        raise ProfileIntegrityError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def _load_catalog_identity(run_root: Path) -> tuple[str, str | None]:
    handoff, handoff_sha = _accepted_handoff(run_root, "job_target_catalog")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    identity = published.get("artifact") if isinstance(published, Mapping) else None
    if not isinstance(identity, Mapping) or not any(
            item.get("path") == identity.get("path") and item.get("sha256") == identity.get("sha256")
            for item in handoff.get("artifacts", ()) if isinstance(item, Mapping)):
        raise ProfileIntegrityError("target catalog publication is not bound to its handoff")
    catalog = json.loads(_safe_file(run_root, identity, "target catalog").read_text(encoding="utf-8"))
    if catalog.get("schema") != "appsec-review/target-catalog/1":
        raise ProfileIntegrityError("target catalog schema is unsupported")
    fingerprint = catalog.get("source_fingerprint")
    return handoff_sha, str(fingerprint) if fingerprint is not None else None


def detect_profile_format(path: str, data: bytes, declared_format: str | None = None) -> tuple[str | None, str | None]:
    """Return ``(format, gap)`` without interpreting opaque serialized profile bytes."""
    declared = (declared_format or "").strip().lower()
    if declared:
        if declared in _SUPPORTED:
            return declared, None
        if declared in {"gmon", "pprof", "llvm-raw", "llvm-indexed"}:
            return None, f"unsupported_profile_format: {path}: {declared} requires a pinned converter"
        return None, f"unsupported_profile_format: {path}: {declared}"
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if name == "gmon.out" or name.endswith(".gmon"):
        return None, f"unsupported_profile_format: {path}: opaque gmon"
    if name.endswith((".pprof", ".pb", ".pb.gz")):
        return None, f"unsupported_profile_format: {path}: opaque pprof"
    if name.endswith(".profraw"):
        return None, f"unsupported_profile_format: {path}: opaque LLVM raw profile"
    if name.endswith(".profdata"):
        return None, f"unsupported_profile_format: {path}: opaque LLVM indexed profile"
    try:
        prefix = data[:65536].decode("utf-8-sig", errors="strict")
    except UnicodeError:
        return None, f"unsupported_profile_format: {path}: unrecognized opaque profile"
    matches: list[str] = []
    meaningful = [line for line in prefix.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if name.startswith("callgrind") or any(line.startswith("events:") for line in meaningful):
        matches.append("callgrind")
    if name.endswith((".folded", ".stacks")) or (meaningful and all(
            re.search(r"\S(?:;\S)*\s+[0-9]+\s*$", line) for line in meaningful[:20])):
        matches.append("folded-stacks")
    if name.endswith((".perf-script", ".perf.txt")) or any(
            re.match(r"^\s*.+?\s+\d+(?:/\d+)?\s+(?:\[\d+\]\s+)?[0-9.]+:\s+[^:]+:", line)
            for line in meaningful[:100]):
        matches.append("perf-script")
    if name.endswith((".llvm-sample", ".sample.prof", ".prof")) or any(
            re.match(r"^[^\s:#].*:[0-9]+:[0-9]+(?:\s+.*)?$", line) for line in meaningful[:20]):
        matches.append("llvm-sample")
    matches = list(dict.fromkeys(matches))
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, f"ambiguous_profile_format: {path}: matched {', '.join(sorted(matches))}"
    return None, f"unsupported_profile_format: {path}: unrecognized text profile"


def _candidate(artifact: Mapping[str, Any]) -> bool:
    return artifact.get("kind") == "execution-profile"


def ingest_profile_artifacts(run_root: Path, receipts: Sequence[Mapping[str, Any]], *,
                             bounds: ProfileBounds = ProfileBounds()) -> dict[str, Any]:
    """Normalize profile artifacts listed by accepted build receipts and assign stable hotness ranks."""
    units: list[dict[str, Any]] = []
    global_gaps: list[str] = []
    for receipt in sorted(receipts, key=lambda item: str(item.get("build_unit_id", ""))):
        build_unit_id = str(receipt.get("build_unit_id", ""))
        candidates = sorted((item for item in receipt.get("artifacts", ())
                             if isinstance(item, Mapping) and _candidate(item)),
                            key=lambda item: (str(item.get("path", "")), str(item.get("sha256", ""))))
        gaps: list[str] = []
        if len(candidates) > bounds.max_artifacts:
            gaps.append(f"artifact_count_truncation: retained {bounds.max_artifacts} of {len(candidates)} profiles")
            candidates = candidates[:bounds.max_artifacts]
        if not candidates:
            gaps.append("missing_profile_data: accepted build receipt has no execution-profile artifact")
        reports: list[dict[str, Any]] = []
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in candidates:
            label = str(candidate.get("workspace_path") or candidate.get("path") or "profile artifact")
            origin = candidate.get("artifact_origin", "build-output")
            if origin not in {"accepted-input", "build-output"}:
                raise ProfileIntegrityError(f"profile artifact {label} has invalid artifact origin")
            identity = (str(candidate.get("path", "")), str(candidate.get("sha256", "")))
            if identity in seen:
                gaps.append(f"ambiguous_profile_identity: duplicate accepted artifact {label}")
                continue
            seen.add(identity)
            path = _safe_file(run_root, candidate, f"profile artifact {label}")
            if path.stat().st_size > bounds.max_artifact_bytes:
                gaps.append(f"artifact_byte_bound: {label} exceeds {bounds.max_artifact_bytes} bytes")
                continue
            data = path.read_bytes()
            format_name, format_gap = detect_profile_format(
                label, data, str(candidate.get("profile_format", "")) or None)
            if format_gap:
                gaps.append(format_gap)
            if format_name is None:
                reports.append({"path": candidate.get("path"), "workspace_path": candidate.get("workspace_path"),
                                "sha256": candidate.get("sha256"), "format": None,
                                "artifact_origin": origin, "row_count": 0})
                continue
            try:
                document = parse_profile(data, format_name, max_rows=bounds.max_rows_per_artifact,
                                         max_line_bytes=bounds.max_line_bytes,
                                         max_frames_per_sample=bounds.max_frames_per_sample)
            except ValueError as exc:
                gaps.append(f"malformed_profile: {label}: {exc}")
                continue
            parsed_rows = list(document.rows)
            if len(parsed_rows) > bounds.max_rows_per_artifact:
                gaps.append(f"profile_row_truncation: {label} retained {bounds.max_rows_per_artifact} "
                            f"of {len(parsed_rows)} normalized rows")
                parsed_rows = parsed_rows[:bounds.max_rows_per_artifact]
            gaps.extend(f"{label}: {gap}" for gap in document.gaps)
            report = {"path": candidate.get("path"), "workspace_path": candidate.get("workspace_path"),
                      "sha256": candidate.get("sha256"), "format": document.format,
                      "artifact_origin": origin, "row_count": len(parsed_rows)}
            reports.append(report)
            for item in parsed_rows:
                rows.append({**asdict(item), "build_unit_id": build_unit_id,
                             "report_path": candidate.get("path"), "report_sha256": candidate.get("sha256"),
                             "report_format": document.format, "artifact_origin": origin,
                             "semantics": SEMANTICS, "is_finding": False,
                             "defect_probability": None})
        ordered = sorted(range(len(rows)), key=lambda i: (
            -int(rows[i]["count"]), str(rows[i]["event"]), str(rows[i]["symbol"]),
            str(rows[i].get("module") or ""), str(rows[i].get("source") or ""),
            int(rows[i].get("line") or 0), str(rows[i]["report_sha256"])))
        for rank, index in enumerate(ordered, 1):
            rows[index]["hotness_rank"] = rank
            rows[index]["hotness_population"] = len(rows)
        state = "unavailable" if not rows else "partial" if gaps else "complete"
        unit_value = {"build_unit_id": build_unit_id, "family": receipt.get("family"),
                      "root": receipt.get("root", "."), "reports": reports, "rows": rows,
                      "coverage_state": state, "gaps": list(dict.fromkeys(gaps)),
                      "semantics": SEMANTICS}
        units.append(unit_value)
        global_gaps.extend(f"{build_unit_id}: {gap}" for gap in unit_value["gaps"])
    return {"units": units, "gaps": list(dict.fromkeys(global_gaps)), "semantics": SEMANTICS,
            "interpretation": "hotness is context only, not a finding or defect probability"}


def _artifact(unit: UnitContext, path: Path, value: Any | None = None) -> dict[str, Any]:
    if value is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, value)
    return {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _settings(unit: UnitContext) -> ProfileBounds:
    value = unit.job.config.settings.get("bounds", {})
    if not isinstance(value, Mapping):
        raise ValueError("profile-data bounds are invalid")
    return ProfileBounds.from_mapping(value)


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("profile-data topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"profile-data task order mismatch: {step}")
    bounds = context.config.settings.get("bounds")
    if not isinstance(bounds, Mapping):
        raise ValueError("profile-data bounds are required")
    ProfileBounds.from_mapping(bounds)
    for key, expected in (("parser_identity", PARSER_IDENTITY),
                          ("normalizer_identity", NORMALIZER_IDENTITY),
                          ("mapping_identity", MAPPING_IDENTITY)):
        if context.config.settings.get(key) != expected:
            raise ValueError(f"profile-data {key} is invalid")


def build_job() -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        catalog_handoff_sha, catalog_fingerprint = _load_catalog_identity(unit.job.run_root)
        language = load_accepted_language_build(unit.job.run_root)
        artifacts = load_accepted_artifact_index(unit.job.run_root)
        for value, label in ((language, "language-build"), (artifacts, "artifact-indexing")):
            if value.get("source_fingerprint") != unit.job.source_fingerprint:
                raise ProfileIntegrityError(f"{label} differs from the accepted target snapshot")
        if catalog_fingerprint is not None and catalog_fingerprint != unit.job.source_fingerprint:
            raise ProfileIntegrityError("target catalog differs from the accepted target snapshot")
        return {"receipts": language.get("receipts", ()),
                "upstream_handoffs": {"job_target_catalog": catalog_handoff_sha,
                                      "job_language_build": language["language_build_handoff_sha256"],
                                      "job_artifact_indexing": artifacts["handoff_sha256"]},
                "upstream_manifest": artifacts["index_manifest"]}

    def normalize(unit: UnitContext) -> Mapping[str, Any]:
        return ingest_profile_artifacts(unit.job.run_root, unit.output("load.accepted_inputs")["receipts"],
                                        bounds=_settings(unit))

    def index(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        normalized = unit.output("normalize.profile_data")
        upstream_identity = loaded["upstream_manifest"]
        prior, _ = load_verified_manifest(
            unit.job.run_root, _safe_file(unit.job.run_root, upstream_identity, "artifact-index manifest"),
            str(upstream_identity["sha256"]))
        existing = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
                    for raw in prior["indexes"] if not (
                        raw["name"] == "analysis" and str(raw.get("shard_id", "")).startswith("profile-data-"))]
        current: list[IndexIdentity] = []
        for value in normalized["units"]:
            producer_artifacts = [{"build_unit_id": value["build_unit_id"]}, *(
                {"path": item.get("path"), "sha256": item.get("sha256")} for item in value["reports"])]
            fingerprint = index_fingerprint(
                name="analysis", target_snapshot=unit.job.source_fingerprint,
                producer_artifacts=producer_artifacts, tool_identity={"producer": "accepted-profile-data"},
                parser_identity=PARSER_IDENTITY, normalizer_identity=NORMALIZER_IDENTITY,
                mapping_identity=MAPPING_IDENTITY, upstream_manifests=(str(upstream_identity["sha256"]),))
            shard_id = f"profile-data-{value['build_unit_id']}"
            path = unit.job.run_root / "data" / "indices" / "analysis" / f"{fingerprint}.sqlite"
            if path.exists():
                sha = file_sha256(path)
            else:
                builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                                       target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
                for row in value["rows"]:
                    native = {key: row.get(key) for key in (
                        "build_unit_id", "report_sha256", "symbol", "event", "module", "source", "line")}
                    identity = LogicalIdentity.derive(EntityKind.HOTSPOT, unit.job.source_fingerprint, native)
                    builder.add_entity(EntityRecord(
                        identity, json.dumps(native, sort_keys=True), str(row["symbol"]),
                        f"profile hotspot {row['symbol']} rank {row['hotness_rank']}", row))
                builder.add_coverage(f"profile-data:{value['build_unit_id']}", value["coverage_state"],
                                     "; ".join(value["gaps"][:10])[:1000] or None)
                sha = builder.build()
            current.append(IndexIdentity(
                "analysis", "appsec-review/retrieval-index/2", sha, fingerprint,
                path.relative_to(unit.job.run_root).as_posix(),
                {"job": "job_profile_data", "unit": unit.unit_id, "parser_identity": PARSER_IDENTITY,
                 "normalizer_identity": NORMALIZER_IDENTITY, "mapping_identity": MAPPING_IDENTITY,
                 "semantics": SEMANTICS}, tuple(value["gaps"]), shard_id))
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"profile-data-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or unit.job.repository_root,
                       indexes=(*existing, *current), upstream_manifests=(upstream_identity,))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        return {"indexes": [asdict(item) for item in current], "index_manifest": _artifact(unit, manifest_path),
                "gaps": normalized["gaps"]}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        normalized = unit.output("normalize.profile_data")
        indexed = unit.output("index.profile_data")
        document = {"schema": PROFILE_DATA_HANDOFF_SCHEMA,
                    "source_fingerprint": unit.job.source_fingerprint,
                    "upstream_handoff_sha256": loaded["upstream_handoffs"],
                    "parser_identity": PARSER_IDENTITY, "normalizer_identity": NORMALIZER_IDENTITY,
                    "mapping_identity": MAPPING_IDENTITY, "semantics": SEMANTICS,
                    "interpretation": normalized["interpretation"], "build_units": normalized["units"],
                    "gaps": normalized["gaps"], "index_manifest": indexed["index_manifest"]}
        path = unit.job.attempt_root / "artifacts" / "profile-data" / "accepted-profile-data.json"
        artifact = _artifact(unit, path, document)
        return {"schema": PROFILE_DATA_HANDOFF_SCHEMA, "artifact": artifact,
                "index_manifest": indexed["index_manifest"], "item_count": sum(
                    len(value["rows"]) for value in normalized["units"]), "gaps": normalized["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if normalized["gaps"] else
                                   "SUCCEEDED" if normalized["units"] else "NOT_APPLICABLE"}

    units = (
        Unit("load.accepted_inputs", load),
        Unit("normalize.profile_data", normalize, ("load.accepted_inputs",)),
        Unit("index.profile_data", index, ("load.accepted_inputs", "normalize.profile_data")),
        Unit("acceptance.publish_handoff", publish,
             ("load.accepted_inputs", "normalize.profile_data", "index.profile_data")),
    )
    implementation = hashlib.sha256(
        Path(__file__).read_bytes() + Path(__file__).with_name("parsers.py").read_bytes()).hexdigest()
    return Job("job_profile_data", "profile_data", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=PROFILE_DATA_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, consumes=CONSUMES)


def load_accepted_profile_data(run_root: Path) -> Mapping[str, Any]:
    """Load and integrity-check the accepted profile document and its immutable index manifest."""
    handoff, handoff_sha = _accepted_handoff(Path(run_root), "job_profile_data")
    published = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    identity = published.get("artifact") if isinstance(published, Mapping) else None
    manifest = published.get("index_manifest") if isinstance(published, Mapping) else None
    if not isinstance(identity, Mapping) or not isinstance(manifest, Mapping):
        raise ProfileIntegrityError("profile-data publication is unavailable")
    artifacts = handoff.get("artifacts", ())
    for expected in (identity, manifest):
        if not any(item.get("path") == expected.get("path") and item.get("sha256") == expected.get("sha256")
                   for item in artifacts if isinstance(item, Mapping)):
            raise ProfileIntegrityError("profile-data publication is not bound to its handoff")
    document = json.loads(_safe_file(Path(run_root), identity, "profile-data handoff").read_text(encoding="utf-8"))
    if document.get("schema") != PROFILE_DATA_HANDOFF_SCHEMA or document.get("semantics") != SEMANTICS:
        raise ProfileIntegrityError("profile-data handoff schema or semantics is unsupported")
    load_verified_manifest(Path(run_root), _safe_file(Path(run_root), manifest, "profile-data manifest"),
                           str(manifest["sha256"]))
    return {**document, "handoff_sha256": handoff_sha}
