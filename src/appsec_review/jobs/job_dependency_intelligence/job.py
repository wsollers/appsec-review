"""Generic dependency intelligence producer for declarations, SBOMs, and native links."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.inference import Infer
from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_artifact_indexing import load_accepted_artifact_index
from appsec_review.retrieval import (EntityKind, EntityRecord, IndexBuilder, IndexIdentity,
                                     LogicalIdentity, RelationKind, RelationRecord, index_fingerprint,
                                     SourceLocation, write_manifest)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import safe_path, verify_reference
from appsec_review.observability.spans import operation_span

from .datasets import CONSUMES, DATASETS
from .inference import resolve_with_inference
from .integration import (
    Converter, collect_inputs, native_bounds, publish_sbom, read_native_file, sbom_bounds,
    validate_publication,
)
from .resolution import deduplicate_repositories, normalize_dependencies, repository_identity
from .scorecard import (ScorecardCache, ScorecardCacheError, ScorecardClient, ScorecardError,
                        Transport, https_get)


JOB_ID = "job_dependency_intelligence"
TOPOLOGY = {
    "inputs": ("load_accepted",),
    "resolution": ("detect_dependencies", "infer_repositories"),
    "repositories": ("deduplicate",),
    "scorecards": ("fetch",),
    "publication": ("publish_sbom", "publish_context"),
    "acceptance": ("publish_handoff",),
}
PARSER_IDENTITY = "dependency-intelligence-parser/2"
NORMALIZER_IDENTITY = "dependency-intelligence-normalizer/2"
MAPPING_IDENTITY = "dependency-intelligence-evidence-map/2"


def _index_native_evidence(unit: UnitContext, builder: IndexBuilder, identities: Mapping[str, str],
                           dependencies: list[Mapping[str, Any]], sbom: Mapping[str, Any]) -> None:
    discovery = unit.output("resolution.detect_dependencies")["native_discovery_document"]
    snapshot = unit.job.source_fingerprint
    evidence_entities: dict[str, str] = {}
    seen_artifacts: set[str] = set()
    seen_sources: set[str] = set()

    def artifact_entity(artifact: Mapping[str, Any], name: str) -> str:
        verify_reference(unit.job.run_root, artifact)
        identity = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, snapshot, dict(artifact))
        if identity.value not in seen_artifacts:
            builder.add_entity(EntityRecord(identity, artifact["sha256"], name, name,
                                            {"artifact": dict(artifact), "tool_id": "native-sbom"}))
            seen_artifacts.add(identity.value)
        return identity.value

    for evidence in discovery["evidence"]:
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot,
                                          {"native_evidence_id": evidence["evidence_id"]})
        selector, location, source_id = evidence["selector"], None, None
        if evidence["domain"] == "target" and "start_byte" in selector:
            location = SourceLocation(
                target_snapshot=snapshot, path=evidence["path"], file_sha256=evidence["sha256"],
                start_byte=selector["start_byte"], end_byte=selector["end_byte"],
                start_line=selector["start_line"], end_line=selector["end_line"],
                start_column=1, end_column=1, producer_location=selector,
                mapping_method="native-literal-exact", confidence=1.0,
            )
            source_id = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, snapshot, {
                "native_evidence_id": evidence["evidence_id"],
                "path": evidence["path"], "sha256": evidence["sha256"],
            })
            if source_id.value not in seen_sources:
                builder.add_entity(EntityRecord(
                    source_id, evidence["path"], evidence["path"], evidence["path"],
                    {"path": evidence["path"], "sha256": evidence["sha256"],
                     "source_fingerprint": snapshot, "coverage": "supporting-native-evidence-span"}, location,
                ))
                seen_sources.add(source_id.value)
        builder.add_entity(EntityRecord(identity, evidence["evidence_id"], evidence["kind"],
                                       f"{evidence['kind']} {evidence['value']}", evidence, location))
        evidence_entities[evidence["evidence_id"]] = identity.value
        backing = evidence.get("backing") or evidence["upstream"]
        artifact_id = artifact_entity(backing, "Native dependency evidence")
        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value, artifact_id, True, 1.0))
        if source_id is not None:
            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, identity.value, source_id.value, True, 1.0))
    for dependency in dependencies:
        candidates = dependency.get("native_candidates") or [dependency.get("native_candidate")]
        evidence_ids = {evidence_id for candidate in candidates if isinstance(candidate, Mapping)
                        for evidence_id in candidate.get("evidence_ids", ())}
        for evidence_id in sorted(evidence_ids):
            if evidence_id in evidence_entities:
                builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM,
                    identities[dependency["dependency_id"]], evidence_entities[evidence_id], True, 1.0))
    provenance_id = artifact_entity(sbom["provenance"], "Native SPDX provenance")
    if sbom.get("artifact"):
        spdx_id = artifact_entity(sbom["artifact"], "Enriched SPDX 2.3 inventory")
        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, spdx_id, provenance_id, True, 1.0))
    for area, complete in (
        ("native-source-discovery", not discovery["gaps"]),
        ("source-syft-baseline", sbom.get("baseline") is not None),
        ("native-spdx-publication", sbom["status"] == "SUCCEEDED"),
    ):
        builder.add_coverage(area, "complete" if complete else "partial",
                             None if complete else "inspect native discovery and SPDX publication gaps")


def _safe_read(run_root: Path, identity: Mapping[str, Any], *, max_bytes: int | None = None) -> bytes:
    path = safe_path(run_root, str(identity.get("path", "")))
    if not path.is_file():
        raise ValueError("accepted dependency input is missing or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted dependency input hash changed")
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise ValueError("accepted dependency input exceeds its byte bound")
    if identity.get("size_bytes", path.stat().st_size) != path.stat().st_size:
        raise ValueError("accepted dependency input size changed")
    return path.read_bytes()


def _accepted_job(run_root: Path, job_id: str) -> tuple[dict[str, Any], str]:
    latest = run_root / "data" / "jobs" / job_id / "latest.json"
    if not latest.is_file():
        raise ValueError(f"accepted {job_id} handoff is required")
    pointer = json.loads(latest.read_text(encoding="utf-8"))
    handoff = json.loads(_safe_read(run_root, {"path": pointer.get("handoff_path"),
                                               "sha256": pointer.get("handoff_sha256")}).decode())
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != job_id):
        raise ValueError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def _target_dependencies(run_root: Path) -> tuple[list[dict[str, Any]], str]:
    handoff, sha = _accepted_job(run_root, "job_target_catalog")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    catalog = json.loads(_safe_read(run_root, published.get("artifact", {})).decode())
    identity = catalog.get("artifacts", {}).get("component_discovery.catalog_dependencies", {})
    document = json.loads(_safe_read(run_root, identity).decode())
    if document.get("schema") != "appsec-review/dependency-catalog/1":
        raise ValueError("accepted dependency catalog schema is unsupported")
    return [dict(item) for item in document.get("dependencies", ()) if isinstance(item, Mapping)], sha


def _evidence_packages(run_root: Path) -> tuple[list[dict[str, Any]], str]:
    handoff, sha = _accepted_job(run_root, "job_evidence_collection")
    output = handoff.get("outputs", {}).get("evidence_publication.publish_handoff", {})
    manifest_identity = output.get("index_manifest")
    if not isinstance(manifest_identity, Mapping):
        return [], sha
    path = (run_root / str(manifest_identity.get("path", ""))).resolve()
    manifest, _ = load_verified_manifest(run_root, path, str(manifest_identity.get("sha256", "")))
    records: list[dict[str, Any]] = []
    for shard in manifest.get("indexes", ()):
        if (shard.get("name") != "observations" or
                shard.get("producer", {}).get("producer") != "tool-syft"):
            continue
        database_path = (run_root / str(shard["relative_path"])).resolve()
        uri = f"file:{database_path.as_posix()}?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True) as database:
            for identity, payload_json in database.execute(
                    "SELECT identity, payload_json FROM entities WHERE kind = ?", (EntityKind.TOOL_OBSERVATION.value,)):
                payload = json.loads(payload_json)
                package = payload.get("package")
                if package:
                    records.append({"observation_id": identity, "name": str(package),
                                    "version": payload.get("version"), "purl": payload.get("purl"),
                                    "repository_url": payload.get("repository_url"),
                                    "path": (payload.get("location") or {}).get("path")
                                            if isinstance(payload.get("location"), Mapping) else None})
    return records, sha


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _gap(dependency_id: str, kind: str, detail: str) -> dict[str, Any]:
    return {"dependency_id": dependency_id, "kind": kind, "detail": detail[:4096]}


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("dependency-intelligence topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"dependency-intelligence task order mismatch: {step}")
    settings = context.config.settings
    integers = ("dependency_limit", "repository_limit", "native_candidate_limit", "command_token_limit",
                "metadata_file_limit", "metadata_bytes_per_file", "inference_candidate_bytes")
    if any(type(settings.get(key)) is not int or int(settings[key]) < 1 for key in integers):
        raise ValueError("dependency-intelligence deterministic bounds are invalid")
    native_bounds(settings)
    sbom_bounds(settings)
    if (type(settings.get("sbom_conversion_timeout_seconds")) is not int
            or settings["sbom_conversion_timeout_seconds"] < 1):
        raise ValueError("SPDX conversion timeout must be a positive integer")
    hosts = settings.get("repository_hosts")
    if not isinstance(hosts, list) or not hosts or len(hosts) != len(set(hosts)):
        raise ValueError("dependency-intelligence repository host allowlist is invalid")
    model, scorecard = settings.get("model"), settings.get("scorecard")
    if not isinstance(model, Mapping) or not isinstance(scorecard, Mapping):
        raise ValueError("dependency-intelligence model and Scorecard settings are required")
    required_model = {"enabled", "provider", "model", "reasoning", "max_input_tokens", "max_output_tokens",
                      "timeout_seconds", "retries"}
    required_scorecard = {"base_url", "allowed_hosts", "max_requests", "max_response_bytes",
                          "timeout_seconds", "retries", "cache_root", "cache_max_age_seconds",
                          "cache_lock_timeout_seconds"}
    if not required_model <= set(model) or not required_scorecard <= set(scorecard):
        raise ValueError("dependency-intelligence model or Scorecard settings are incomplete")
    if type(model["enabled"]) is not bool:
        raise ValueError("dependency-intelligence model enabled setting must be boolean")
    for key in ("provider", "model", "reasoning"):
        if not isinstance(model[key], str) or not model[key]:
            raise ValueError(f"dependency-intelligence model {key} is invalid")
    for table, keys in ((model, ("max_input_tokens", "max_output_tokens", "timeout_seconds")),
                        (scorecard, ("max_requests", "max_response_bytes", "timeout_seconds",
                                     "cache_max_age_seconds", "cache_lock_timeout_seconds"))):
        if any(type(table[key]) is not int or table[key] < 1 for key in keys):
            raise ValueError("dependency-intelligence configured bounds are invalid")
    if type(model["retries"]) is not int or not 0 <= model["retries"] <= 5 or \
       type(scorecard["retries"]) is not int or not 0 <= scorecard["retries"] <= 5:
        raise ValueError("dependency-intelligence retry bounds are invalid")
    cache_root = scorecard["cache_root"]
    if (not isinstance(cache_root, str) or not cache_root or Path(cache_root).is_absolute() or
            ".." in Path(cache_root).parts):
        raise ValueError("dependency-intelligence Scorecard cache root must be repository-relative")


def build_job(*, infer: Infer | None = None, scorecard_transport: Transport = https_get,
              syft_converter: Converter | None = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        declared, catalog_sha = _target_dependencies(unit.job.run_root)
        language = load_accepted_language_build(unit.job.run_root)
        packages, evidence_sha = _evidence_packages(unit.job.run_root)
        artifact_index = load_accepted_artifact_index(unit.job.run_root)
        artifact_sha = artifact_index["handoff_sha256"]
        if language.get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("dependency-intelligence target differs from accepted language builds")
        receipts = [dict(item) for item in language.get("receipts", ())]
        native_inputs = collect_inputs(unit, receipts)
        return {**native_inputs, "declared": declared, "packages": packages,
                "receipts": receipts,
                "upstream_handoffs": {"job_target_catalog": catalog_sha,
                                      "job_language_build": language["language_build_handoff_sha256"],
                                      "job_artifact_indexing": artifact_sha,
                                      "job_evidence_collection": evidence_sha},
                "gaps": list(language.get("gaps", ())), "terminal_status": "SUCCEEDED"}

    def detect(unit: UnitContext) -> Mapping[str, Any]:
        from .discovery import discover_native_dependencies
        loaded = unit.output("inputs.load_accepted")
        with operation_span(unit.job.events, "native-sbom.discovery", unit_id=unit.unit_id) as span:
            discovery = discover_native_dependencies(
                source_fingerprint=unit.job.source_fingerprint, files=loaded["native_files"],
                invocations=loaded["native_invocations"], artifacts=loaded["native_artifacts"],
                read_file=lambda record, limit: read_native_file(
                    unit, record, limit, loaded["native_workspace_roots"]),
                bounds=native_bounds(unit.job.config.settings),
            )
            discovery["gaps"].extend(loaded["native_gaps"])
            discovery["coverage"]["configured_exclusions"] = loaded["native_exclusions"]
            discovery["coverage"]["inherited_catalog_gaps"] = loaded["native_catalog_gaps"]
            discovery["source_fingerprint"] = unit.job.source_fingerprint
            if discovery["gaps"]:
                span.status = "COMPLETED_WITH_GAPS"
        path = unit.unit_root / "native-discovery.json"
        if len(canonical_json(discovery)) > unit.job.config.settings["sbom_output_bytes"]:
            raise ValueError("native discovery exceeds its configured publication byte bound")
        atomic_json(path, discovery)
        dependencies, normalization_gaps = normalize_dependencies(
            loaded["declared"], loaded["packages"], discovery["candidates"],
            supported_hosts=tuple(unit.job.config.settings["repository_hosts"]),
            max_dependencies=int(unit.job.config.settings["dependency_limit"]))
        gaps = [*discovery["gaps"], *normalization_gaps]
        return {"dependencies": dependencies, "gaps": gaps,
                "native_discovery": _artifact(unit.job.run_root, path),
                "native_discovery_document": discovery,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def infer_repositories(unit: UnitContext) -> Mapping[str, Any]:
        detected = unit.output("resolution.detect_dependencies")
        dependencies, gaps = [], []
        settings = unit.job.config.settings
        for dependency in detected["dependencies"]:
            resolved, gap = resolve_with_inference(
                dependency, repository_root=unit.job.repository_root, run_root=unit.job.run_root,
                model=settings["model"], supported_hosts=tuple(settings["repository_hosts"]), infer=infer,
                max_candidate_bytes=int(settings["inference_candidate_bytes"]))
            dependencies.append(resolved)
            if gap:
                gaps.append(gap)
            if resolved.get("repository") is None:
                raw = resolved.get("repository_url_observed")
                kind = "unsupported_host" if raw else "unresolved_repository"
                gaps.append(_gap(resolved["dependency_id"], kind,
                                 "repository metadata names an unsupported public host" if raw else
                                 "no supported public repository identity was resolved"))
        return {"dependencies": dependencies, "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def repositories(unit: UnitContext) -> Mapping[str, Any]:
        resolved = unit.output("resolution.infer_repositories")
        values, gaps = deduplicate_repositories(
            resolved["dependencies"], max_repositories=int(unit.job.config.settings["repository_limit"]))
        return {"repositories": values, "dependency_count": len(resolved["dependencies"]),
                "repository_count": len(values), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def scorecards(unit: UnitContext) -> Mapping[str, Any]:
        deduplicated = unit.output("repositories.deduplicate")
        settings = unit.job.config.settings["scorecard"]
        client = ScorecardClient(base_url=str(settings["base_url"]), allowed_hosts=settings["allowed_hosts"],
                                 max_requests=int(settings["max_requests"]),
                                 max_response_bytes=int(settings["max_response_bytes"]),
                                 timeout_seconds=int(settings["timeout_seconds"]), retries=int(settings["retries"]),
                                 transport=scorecard_transport)
        cache = ScorecardCache(unit.job.repository_root / str(settings["cache_root"]),
                               max_age_seconds=int(settings["cache_max_age_seconds"]),
                               max_response_bytes=int(settings["max_response_bytes"]),
                               lock_timeout_seconds=int(settings["cache_lock_timeout_seconds"]))
        records, gaps = [], []
        root = unit.unit_root / "artifacts" / "scorecards"
        cache_hits = 0
        for group in deduplicated["repositories"]:
            repository = group["repository"]
            raw = None
            cache_metadata: dict[str, Any] = {"status": "miss"}
            try:
                raw, cache_metadata = cache.load(repository)
                if raw is not None:
                    record, raw = client.normalize(repository, raw)
                    cache_hits += 1
            except (ScorecardCacheError, ScorecardError) as exc:
                raw = None
                cache_metadata = {"status": "invalid"}
                gaps.extend(_gap(dependency_id, "scorecard_cache_invalid", str(exc))
                            for dependency_id in group["dependency_ids"])
            try:
                if raw is None:
                    record, raw = client.fetch(repository)
                    try:
                        cache_metadata = cache.store(repository, raw)
                    except (OSError, ScorecardCacheError) as exc:
                        cache_metadata = {"status": "write_failed"}
                        gaps.extend(_gap(dependency_id, "scorecard_cache_write_failure", str(exc))
                                    for dependency_id in group["dependency_ids"])
                path = root / f"{group['repository_id']}.json"
                atomic_bytes(path, raw)
                artifact = _artifact(unit.job.run_root, path)
                records.extend({**record, "dependency_id": dependency_id,
                                "repository_id": group["repository_id"], "cache": cache_metadata,
                                "response_artifact": artifact}
                               for dependency_id in group["dependency_ids"])
            except ScorecardError as exc:
                mapping = {"not_found": "scorecard_not_found", "rate_limit": "scorecard_rate_limit",
                           "request_failure": "scorecard_request_failure",
                           "malformed_response": "scorecard_malformed_response", "bounds": "bounds",
                           "unsupported_host": "unsupported_host"}
                scoped_gaps = [_gap(dependency_id, mapping.get(exc.kind, exc.kind), str(exc))
                               for dependency_id in group["dependency_ids"]]
                if exc.response is not None:
                    path = root / f"{group['repository_id']}.error.json"
                    atomic_bytes(path, exc.response.body)
                    artifact = _artifact(unit.job.run_root, path)
                    for gap in scoped_gaps:
                        gap["response_artifact"] = artifact
                        gap["http_status"] = exc.response.status
                        gap["request_url"] = exc.url
                gaps.extend(scoped_gaps)
        return {"records": records, "gaps": gaps, "request_count": client.requests,
                "repository_count": len(deduplicated["repositories"]), "cache_hit_count": cache_hits,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def publish_context(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("inputs.load_accepted")
        resolved = unit.output("resolution.infer_repositories")
        repositories = unit.output("repositories.deduplicate")
        scorecard = unit.output("scorecards.fetch")
        sbom = unit.output("publication.publish_sbom")
        gaps = [*unit.output("resolution.detect_dependencies")["gaps"], *resolved["gaps"],
                *repositories["gaps"], *scorecard["gaps"], *sbom["gaps"]]
        producer_artifacts = [{"job": key, "sha256": value} for key, value in sorted(loaded["upstream_handoffs"].items())]
        fingerprint = index_fingerprint(name="inventory", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=producer_artifacts,
            tool_identity={"scorecard_api": unit.job.config.settings["scorecard"]["base_url"],
                           "native_sbom": sbom["input_fingerprint"],
                           "spdx_sha256": (sbom.get("artifact") or {}).get("sha256")},
            parser_identity=PARSER_IDENTITY, normalizer_identity=NORMALIZER_IDENTITY,
            mapping_identity=MAPPING_IDENTITY)
        path = unit.job.run_root / "data" / "indices" / "inventory" / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="inventory", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint,
                               shard_id="dependency-intelligence")
        identities: dict[str, str] = {}
        gaps_by_dependency: dict[str, list[dict[str, str]]] = {}
        for gap in gaps:
            if isinstance(gap, Mapping) and gap.get("dependency_id"):
                gaps_by_dependency.setdefault(str(gap["dependency_id"]), []).append(dict(gap))
        for dependency in resolved["dependencies"]:
            identity = LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, unit.job.source_fingerprint,
                {key: dependency.get(key) for key in ("dependency_id", "name", "version", "purl", "repository")})
            identities[dependency["dependency_id"]] = identity.value
            scoped = gaps_by_dependency.get(dependency["dependency_id"], [])
            builder.add_entity(EntityRecord(identity, dependency["dependency_id"], dependency["name"],
                f"dependency {dependency['name']} {dependency.get('version') or ''}",
                {**dependency, "gaps": scoped, "scorecard_context_only": True}))
            builder.add_coverage(dependency["dependency_id"], "partial" if scoped else "complete",
                                 scoped[0]["detail"] if scoped else None)
        _index_native_evidence(unit, builder, identities, resolved["dependencies"], sbom)
        for record in scorecard["records"]:
            dependency_identity = identities[record["dependency_id"]]
            identity = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, unit.job.source_fingerprint,
                {"dependency_id": record["dependency_id"], "response_sha256": record["response_artifact"]["sha256"]})
            builder.add_entity(EntityRecord(identity, record["response_artifact"]["sha256"],
                "OpenSSF Scorecard context", f"OpenSSF Scorecard score {record['score']}", record))
            builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                dependency_identity, True, 1.0,
                                                payload={"context_only": True, "security_finding": False}))
        builder.add_coverage("dependency-intelligence", "partial" if gaps else "complete",
                             str(gaps[0])[:4096] if gaps else None)
        sha = builder.build()
        identity = IndexIdentity("inventory", "appsec-review/retrieval-index/2", sha, fingerprint,
                                 path.relative_to(unit.job.run_root).as_posix(),
                                 {"job": JOB_ID, "unit": unit.unit_id},
                                 tuple(str(gap)[:4096] for gap in gaps), "dependency-intelligence")
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / \
                        f"dependency-intelligence-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or unit.job.repository_root, indexes=(identity,))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        return {"index_identity": asdict(identity), "index_manifest": _artifact(unit.job.run_root, manifest_path),
                "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        loaded, resolved = unit.output("inputs.load_accepted"), unit.output("resolution.infer_repositories")
        repositories = unit.output("repositories.deduplicate")
        scorecard, context = unit.output("scorecards.fetch"), unit.output("publication.publish_context")
        sbom = unit.output("publication.publish_sbom")
        document = {"schema": DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA,
                    "source_fingerprint": unit.job.source_fingerprint,
                    "upstream_handoffs": loaded["upstream_handoffs"],
                    "dependencies": resolved["dependencies"], "repositories": repositories["repositories"],
                    "scorecards": scorecard["records"], "scorecard_metrics": {
                        "request_count": scorecard["request_count"],
                        "repository_count": scorecard["repository_count"],
                        "cache_hit_count": scorecard["cache_hit_count"]},
                    "gaps": context["gaps"], "index_identity": context["index_identity"],
                    "index_manifest": context["index_manifest"],
                    "native_discovery": unit.output("resolution.detect_dependencies")["native_discovery"],
                    "sbom": sbom,
                    "security_findings": [], "scorecard_semantics": "review-context-and-red-team-seed-only"}
        path = unit.unit_root / "dependency-intelligence-handoff.json"
        atomic_json(path, document)
        return {"schema": document["schema"], "artifact": _artifact(unit.job.run_root, path),
                "index_manifest": context["index_manifest"], "item_count": len(document["dependencies"]),
                "scorecard_count": len(document["scorecards"]), "gaps": document["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}

    units = (
        Unit("inputs.load_accepted", load),
        Unit("resolution.detect_dependencies", detect, ("inputs.load_accepted",)),
        Unit("resolution.infer_repositories", infer_repositories, ("resolution.detect_dependencies",)),
        Unit("repositories.deduplicate", repositories, ("resolution.infer_repositories",)),
        Unit("scorecards.fetch", scorecards, ("repositories.deduplicate",)),
        Unit("publication.publish_sbom", lambda unit: publish_sbom(unit, syft_converter),
             ("inputs.load_accepted", "resolution.detect_dependencies")),
        Unit("publication.publish_context", publish_context,
             ("inputs.load_accepted", "resolution.detect_dependencies", "resolution.infer_repositories",
              "repositories.deduplicate", "scorecards.fetch", "publication.publish_sbom")),
        Unit("acceptance.publish_handoff", publish_handoff,
             ("inputs.load_accepted", "resolution.infer_repositories", "repositories.deduplicate", "scorecards.fetch",
              "publication.publish_context", "publication.publish_sbom", "resolution.detect_dependencies")),
    )
    implementation = None
    return Job(JOB_ID, "dependency_intelligence", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units, datasets=DATASETS, consumes=CONSUMES)


def load_accepted_dependency_intelligence(run_root: Path) -> Mapping[str, Any]:
    handoff, sha = _accepted_job(Path(run_root), JOB_ID)
    output = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    artifact = output.get("artifact", {})
    if not any(item.get("path") == artifact.get("path") and item.get("sha256") == artifact.get("sha256")
               for item in handoff.get("artifacts", ()) if isinstance(item, Mapping)):
        raise ValueError("dependency-intelligence publication is not bound to its accepted handoff")
    document = json.loads(_safe_read(Path(run_root), artifact).decode())
    if document.get("schema") != DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA:
        raise ValueError("dependency-intelligence publication schema is unsupported")
    manifest_identity = document.get("index_manifest", {})
    if not any(item.get("path") == manifest_identity.get("path") and
               item.get("sha256") == manifest_identity.get("sha256")
               for item in handoff.get("artifacts", ()) if isinstance(item, Mapping)):
        raise ValueError("dependency-intelligence index manifest is not bound to its accepted handoff")
    load_verified_manifest(Path(run_root), Path(run_root) / document["index_manifest"]["path"],
                           document["index_manifest"]["sha256"])
    if "sbom" in document:
        validate_publication(Path(run_root), handoff, document)
    return {**document, "handoff_sha256": sha}


__all__ = ["JOB_ID", "TOPOLOGY", "build_job", "load_accepted_dependency_intelligence"]
