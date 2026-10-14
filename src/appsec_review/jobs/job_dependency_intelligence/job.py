"""Generic dependency intelligence producer for declarations, SBOMs, and native links."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
from typing import Any

from appsec_review.inference import Infer
from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import (EntityKind, EntityRecord, IndexBuilder, IndexIdentity,
                                     LogicalIdentity, RelationKind, RelationRecord, index_fingerprint,
                                     write_manifest)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .datasets import CONSUMES, DATASETS
from .inference import resolve_with_inference
from .native import parse_native_candidates
from .resolution import deduplicate_repositories, normalize_dependencies, repository_identity
from .scorecard import (ScorecardCache, ScorecardCacheError, ScorecardClient, ScorecardError,
                        Transport, https_get)


JOB_ID = "job_dependency_intelligence"
TOPOLOGY = {
    "inputs": ("load_accepted",),
    "resolution": ("detect_dependencies", "infer_repositories"),
    "repositories": ("deduplicate",),
    "scorecards": ("fetch",),
    "publication": ("publish_context",),
    "acceptance": ("publish_handoff",),
}
PARSER_IDENTITY = "dependency-intelligence-parser/1"
NORMALIZER_IDENTITY = "dependency-intelligence-normalizer/1"
MAPPING_IDENTITY = "dependency-intelligence-evidence-map/1"


def _safe_read(run_root: Path, identity: Mapping[str, Any], *, max_bytes: int | None = None) -> bytes:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted dependency input is missing or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted dependency input hash changed")
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise ValueError("accepted dependency input exceeds its byte bound")
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


def _parse_metadata(path: Path, *, limit: int) -> dict[str, str]:
    payload = path.read_bytes()
    if len(payload) > limit:
        raise ValueError("native package metadata exceeds its byte bound")
    text = payload.decode("utf-8")
    fields: dict[str, str] = {}
    for line in text.splitlines()[:10000]:
        match = re.match(r"\s*([A-Za-z][A-Za-z0-9_.-]{0,63})\s*[:=]\s*[\"']?([^\"')#]{1,4096})", line)
        if match and match.group(1).lower() in {"name", "version", "url", "homepage_url", "repository"}:
            key = "URL" if match.group(1).lower() in {"url", "homepage_url", "repository"} else match.group(1).title()
            fields.setdefault(key, match.group(2).strip())
    return fields


def _native_inputs(run_root: Path, receipts: list[Mapping[str, Any]], settings: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    invocations: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    gaps: list[str] = []
    remaining_metadata = int(settings["metadata_file_limit"])
    for receipt in receipts:
        if receipt.get("family") != "native":
            continue
        artifacts.extend(dict(item) for item in receipt.get("artifacts", ()) if isinstance(item, Mapping))
        identity = receipt.get("protected_compile_commands")
        if isinstance(identity, Mapping):
            try:
                document = json.loads(_safe_read(run_root, identity,
                    max_bytes=int(settings["metadata_bytes_per_file"]) * 16).decode())
                if document.get("schema") != "appsec-review/protected-compile-commands/1":
                    raise ValueError("protected native command schema is unsupported")
                invocations.extend(dict(item) for item in document.get("rows", ()) if isinstance(item, Mapping))
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                gaps.append(f"{receipt.get('build_unit_id')}: native compile/link evidence unavailable ({exc})")
        workspace_identity = receipt.get("workspace_manifest")
        workspace = (run_root / str(receipt.get("workspace", ""))).resolve()
        if not isinstance(workspace_identity, Mapping) or run_root.resolve() not in workspace.parents:
            continue
        try:
            manifest = json.loads(_safe_read(run_root, workspace_identity).decode())
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            gaps.append(f"{receipt.get('build_unit_id')}: workspace metadata unavailable ({exc})")
            continue
        for relative, digest in sorted((manifest.get("files") or {}).items()):
            lower = str(relative).lower()
            if not lower.endswith((".pc", "config.cmake", "-config.cmake")):
                continue
            if remaining_metadata <= 0:
                gaps.append(f"native metadata file bound exceeded ({settings['metadata_file_limit']})")
                break
            remaining_metadata -= 1
            path = (workspace / Path(*PurePosixPath(str(relative)).parts)).resolve()
            try:
                if workspace != path and workspace not in path.parents:
                    raise ValueError("metadata path escapes accepted workspace")
                if not path.is_file() or path.is_symlink() or file_sha256(path) != digest:
                    raise ValueError("metadata file identity changed")
                fields = _parse_metadata(path, limit=int(settings["metadata_bytes_per_file"]))
                metadata.append({"path": str(relative), "sha256": digest, "fields": fields})
            except (OSError, UnicodeError, ValueError) as exc:
                gaps.append(f"{relative}: native package metadata unavailable ({exc})")
    candidates, candidate_gaps = parse_native_candidates(
        invocations, artifacts=artifacts, metadata_files=metadata,
        max_candidates=int(settings["native_candidate_limit"]),
        max_tokens_per_command=int(settings["command_token_limit"]))
    return candidates, [*gaps, *candidate_gaps]


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


def build_job(*, infer: Infer | None = None, scorecard_transport: Transport = https_get) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        declared, catalog_sha = _target_dependencies(unit.job.run_root)
        language = load_accepted_language_build(unit.job.run_root)
        packages, evidence_sha = _evidence_packages(unit.job.run_root)
        _artifact_handoff, artifact_sha = _accepted_job(unit.job.run_root, "job_artifact_indexing")
        if language.get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("dependency-intelligence target differs from accepted language builds")
        return {"declared": declared, "packages": packages,
                "receipts": [dict(item) for item in language.get("receipts", ())],
                "upstream_handoffs": {"job_target_catalog": catalog_sha,
                                      "job_language_build": language["language_build_handoff_sha256"],
                                      "job_artifact_indexing": artifact_sha,
                                      "job_evidence_collection": evidence_sha},
                "gaps": list(language.get("gaps", ())), "terminal_status": "SUCCEEDED"}

    def detect(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("inputs.load_accepted")
        native, native_gaps = _native_inputs(unit.job.run_root, loaded["receipts"], unit.job.config.settings)
        dependencies, normalization_gaps = normalize_dependencies(
            loaded["declared"], loaded["packages"], native,
            supported_hosts=tuple(unit.job.config.settings["repository_hosts"]),
            max_dependencies=int(unit.job.config.settings["dependency_limit"]))
        gaps = [*native_gaps, *normalization_gaps]
        return {"dependencies": dependencies, "gaps": gaps,
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
        gaps = [*unit.output("resolution.detect_dependencies")["gaps"], *resolved["gaps"],
                *repositories["gaps"], *scorecard["gaps"]]
        producer_artifacts = [{"job": key, "sha256": value} for key, value in sorted(loaded["upstream_handoffs"].items())]
        fingerprint = index_fingerprint(name="inventory", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=producer_artifacts,
            tool_identity={"scorecard_api": unit.job.config.settings["scorecard"]["base_url"]},
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
                {key: dependency.get(key) for key in ("name", "version", "purl", "repository")})
            identities[dependency["dependency_id"]] = identity.value
            scoped = gaps_by_dependency.get(dependency["dependency_id"], [])
            builder.add_entity(EntityRecord(identity, dependency["dependency_id"], dependency["name"],
                f"dependency {dependency['name']} {dependency.get('version') or ''}",
                {**dependency, "gaps": scoped, "scorecard_context_only": True}))
            builder.add_coverage(dependency["dependency_id"], "partial" if scoped else "complete",
                                 scoped[0]["detail"] if scoped else None)
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
        Unit("publication.publish_context", publish_context,
             ("inputs.load_accepted", "resolution.detect_dependencies", "resolution.infer_repositories",
              "repositories.deduplicate", "scorecards.fetch")),
        Unit("acceptance.publish_handoff", publish_handoff,
             ("inputs.load_accepted", "resolution.infer_repositories", "repositories.deduplicate", "scorecards.fetch",
              "publication.publish_context")),
    )
    implementation = hashlib.sha256(b"".join(Path(__file__).with_name(name).read_bytes() for name in
        ("job.py", "native.py", "resolution.py", "inference.py", "scorecard.py"))).hexdigest()
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
    return {**document, "handoff_sha256": sha}


__all__ = ["JOB_ID", "TOPOLOGY", "build_job", "load_accepted_dependency_intelligence"]
