"""Accepted native evidence custody and bounded SPDX publication."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount, load_catalog
from appsec_review.interchange import decode_handoff
from appsec_review.jobs.job_language_build.native import tool_kind as native_tool_kind
from appsec_review.observability.spans import operation_span
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, protected_json
from appsec_review.storage.shared import put_bytes, reference, safe_path, verify_reference

from .native_sbom_contracts import (
    DISCOVERY_IDENTITY, GAP_KINDS, MERGE_IDENTITY, METRIC_COUNTERS, METRICS_SCHEMA,
    NativeBounds, NativeFile, NativeInputIntegrityError, SbomBounds, SpdxBaseline,
    SpdxValidationError,
)


Converter = Callable[..., SpdxBaseline]


class NativeSbomInfrastructureError(RuntimeError):
    """The conversion runtime failed before reporting a tool disposition."""


def native_bounds(settings: Mapping[str, Any]) -> NativeBounds:
    return NativeBounds(
        candidate_limit=settings["native_candidate_limit"],
        command_token_limit=settings["command_token_limit"],
        file_limit=settings["metadata_file_limit"],
        bytes_per_file=settings["metadata_bytes_per_file"],
        source_bytes_limit=settings["native_source_bytes_limit"],
        root_limit=settings["native_root_limit"],
        evidence_limit=settings["native_evidence_limit"],
        evidence_per_candidate=settings["native_evidence_per_candidate"],
        field_bytes=settings["native_field_bytes"], path_chars=settings["native_path_chars"],
    )


def sbom_bounds(settings: Mapping[str, Any]) -> SbomBounds:
    return SbomBounds(settings["sbom_input_bytes"], settings["sbom_element_limit"],
                      settings["sbom_output_bytes"], settings["native_field_bytes"])


def gap(kind: str, scope: str, detail: str) -> dict[str, Any]:
    if kind not in GAP_KINDS:
        raise ValueError("unsupported native SBOM gap kind")
    return {"kind": kind, "scope": scope, "detail": detail[:4096], "evidence_ids": []}


def member(handoff: Mapping[str, Any], identity: Mapping[str, Any]) -> dict[str, Any]:
    for candidate in handoff.get("artifacts", ()):
        if (isinstance(candidate, Mapping) and candidate.get("path") == identity.get("path")
                and candidate.get("sha256") == identity.get("sha256")):
            if identity.get("size_bytes", candidate.get("size_bytes")) != candidate.get("size_bytes"):
                raise NativeInputIntegrityError("accepted publication size binding changed")
            return dict(candidate)
    raise NativeInputIntegrityError("native input is not bound to its accepted handoff")


def read_json(run_root: Path, identity: Mapping[str, Any], limit: int) -> dict[str, Any]:
    path = verify_reference(run_root, identity)
    if path.stat().st_size > limit:
        raise ValueError("native input JSON exceeds its configured byte bound")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit or hashlib.sha256(payload).hexdigest() != identity["sha256"]:
        raise NativeInputIntegrityError("native JSON changed while reading")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("native input JSON must be an object")
    return value


def accepted_framework(run_root: Path, job_id: str, limit: int) -> tuple[dict[str, Any], dict[str, Any]]:
    pointer_path = safe_path(run_root, f"data/jobs/{job_id}/latest.json")
    if not pointer_path.is_file():
        raise ValueError(f"accepted {job_id} handoff is required")
    if pointer_path.stat().st_size > limit:
        raise ValueError("accepted handoff pointer exceeds its byte bound")
    pointer = json.loads(pointer_path.read_bytes())
    path = safe_path(run_root, str(pointer["handoff_path"]))
    identity = reference(run_root, path, expected_sha256=str(pointer["handoff_sha256"]))
    framework = decode_handoff(read_json(run_root, identity, limit),
                                run_id=run_root.name, job_id=job_id)
    return framework, identity


def collect_inputs(unit: UnitContext, receipts: list[Mapping[str, Any]]) -> dict[str, Any]:
    run_root, settings = unit.job.run_root, unit.job.config.settings
    limit = int(settings["sbom_input_bytes"])
    snapshot = unit.job.source_fingerprint
    frameworks, inputs = {}, []
    for job_id in ("job_target_catalog", "job_language_build", "job_artifact_indexing",
                   "job_evidence_collection"):
        framework, identity = accepted_framework(run_root, job_id, limit)
        if framework.get("source_fingerprint") != snapshot:
            raise NativeInputIntegrityError(f"{job_id} native input snapshot differs")
        frameworks[job_id] = framework
        inputs.append(identity)
    catalog_handoff = frameworks["job_target_catalog"]
    catalog_ref = member(catalog_handoff,
                         catalog_handoff["outputs"]["publish_catalog.publish_handoff"]["artifact"])
    catalog = read_json(run_root, catalog_ref, limit)
    if catalog.get("source_fingerprint") != snapshot:
        raise NativeInputIntegrityError("native catalog snapshot differs")
    partition_ref = member(catalog_handoff,
                           catalog["artifacts"]["repository_discovery.partition_repository"])
    partition = read_json(run_root, partition_ref, limit)
    if (partition.get("schema") != "appsec-review/repository-partition/1"
            or partition.get("source_fingerprint") != snapshot):
        raise NativeInputIntegrityError("native source partition schema/snapshot differs")
    inputs.extend((catalog_ref, partition_ref))
    files = [{
        "domain": "target", "root_id": "target", "path": item["path"],
        "sha256": item["sha256"], "size_bytes": item["size_bytes"],
        "upstream": partition_ref, "backing": None,
    } for item in partition.get("files", ())]
    inherited = [gap("upstream_partial", "target-catalog", str(item))
                 for item in partition.get("gaps", ())]
    exclusions = partition.get("configured_exclusions", [])
    if exclusions:
        inherited.append(gap("upstream_partial", "target-catalog",
                             "catalog exclusions limit native source coverage"))
    commands, artifacts, workspace_roots = [], [], {}
    language_handoff = frameworks["job_language_build"]
    language_ref = member(language_handoff,
                          language_handoff["outputs"]["acceptance.publish_handoff"]["artifact"])
    language = read_json(run_root, language_ref, limit)
    if language.get("source_fingerprint") != snapshot:
        raise NativeInputIntegrityError("native build snapshot differs")
    if canonical_json(receipts) != canonical_json(language.get("receipts", [])):
        raise NativeInputIntegrityError("native receipts differ from accepted language publication")
    inputs.append(language_ref)
    for ordinal, receipt in enumerate(receipts):
        root_id = str(receipt["build_unit_id"])
        workspace = receipt.get("workspace")
        if workspace is not None:
            workspace_roots[root_id] = str(workspace)
            safe_path(run_root, str(workspace))
        protected = receipt.get("protected_compile_commands")
        if isinstance(protected, Mapping):
            protected_ref = member(language_handoff, protected)
            document = read_json(run_root, protected_ref, limit)
            if document.get("schema") != "appsec-review/protected-compile-commands/1":
                raise ValueError("native protected command schema is unsupported")
            inputs.append(protected_ref)
            for index, row in enumerate(document.get("rows", ())):
                argv = row.get("argv")
                if not isinstance(argv, list) or not argv:
                    if receipt.get("family") == "native":
                        inherited.append(gap("unsupported_metadata", root_id,
                                             "accepted native command has no retained argument vector"))
                    continue
                if receipt.get("family") != "native" and native_tool_kind(str(argv[0]), argv) is None:
                    continue
                directory = str(row.get("directory", ".")).replace("\\", "/")
                command_domain, command_root = "workspace", root_id
                for prefix in ("/workspace", "/target"):
                    if directory == prefix or directory.startswith(prefix + "/"):
                        directory = directory[len(prefix):].lstrip("/") or "."
                        if prefix == "/target":
                            command_domain, command_root = "target", "target"
                        break
                if PurePosixPath(directory).is_absolute() or ":" in directory:
                    inherited.append(gap("unmapped_path", root_id,
                                         "protected working directory has no accepted mapping"))
                    continue
                commands.append({
                    **row, "root_id": command_root, "domain": command_domain, "directory": directory,
                    "path_mappings": {
                        "/workspace": {"domain": "workspace", "root_id": root_id, "path": "."},
                        "/target": {"domain": "target", "root_id": "target", "path": "."},
                    },
                    "evidence_source": {"artifact": protected_ref, "json_pointer": f"/rows/{index}"},
                })
        manifest_identity = receipt.get("workspace_manifest")
        if isinstance(manifest_identity, Mapping) and workspace is not None:
            manifest_ref = member(language_handoff, manifest_identity)
            manifest = read_json(run_root, manifest_ref, limit)
            inputs.append(manifest_ref)
            workspace_root = safe_path(run_root, str(workspace))
            for relative, digest in sorted(manifest.get("files", {}).items()):
                path = safe_path(workspace_root, relative)
                files.append({
                    "domain": "workspace", "root_id": root_id, "path": relative, "sha256": digest,
                    "size_bytes": path.stat().st_size if path.is_file() else 0,
                    "upstream": manifest_ref, "backing": None,
                })
        for index, item in enumerate(receipt.get("artifacts", ())):
            artifacts.append({
                **item, "path": item.get("workspace_path") or item.get("path", ""),
                "root_id": root_id, "domain": "workspace",
                "evidence_source": {
                    "artifact": language_ref, "json_pointer": f"/receipts/{ordinal}/artifacts/{index}",
                },
            })
    artifact_handoff = frameworks["job_artifact_indexing"]
    artifact_ref = member(artifact_handoff,
                          artifact_handoff["outputs"]["acceptance.publish_handoff"]["artifact"])
    artifact_document = read_json(run_root, artifact_ref, limit)
    if artifact_document.get("source_fingerprint") != snapshot:
        raise NativeInputIntegrityError("artifact index native snapshot differs")
    inputs.append(artifact_ref)
    for index, item in enumerate(artifact_document.get("target_artifacts", ())):
        artifacts.append({
            **item, "root_id": "target", "domain": "target",
            "evidence_source": {"artifact": artifact_ref, "json_pointer": f"/target_artifacts/{index}"},
        })
    inherited.extend(gap("upstream_partial", "language-build", str(item))
                     for item in language.get("gaps", ()))
    inherited.extend(gap("upstream_partial", "artifact-index", str(item))
                     for item in artifact_document.get("gaps", ()))
    if artifacts:
        inherited.append(gap("artifact_inventory_not_merged", "artifact-index",
                             "artifact filename/loader evidence is included; artifact scanner SBOMs are not merged"))
    syft_handoff = frameworks["job_evidence_collection"]
    scan = syft_handoff.get("outputs", {}).get("software_inventory.syft_scan", {})
    source = None
    if isinstance(scan.get("artifact"), Mapping):
        envelope_ref = member(syft_handoff, scan["artifact"])
        envelope = read_json(run_root, envelope_ref, limit)
        if envelope.get("target_fingerprint") != snapshot:
            raise NativeInputIntegrityError("source Syft evidence snapshot differs")
        inputs.append(envelope_ref)
        source_identity = envelope.get("source_inventory")
        source_path = (source_identity or {}).get("path") or scan.get("scanner_output")
        if scan.get("terminal_status") in {"SUCCEEDED", "PARTIAL", "COMPLETED_WITH_GAPS"} and source_path:
            matching = [item for item in envelope.get("raw_artifacts", ())
                        if item.get("path") == source_path]
            if len(matching) != 1:
                raise NativeInputIntegrityError("source Syft bytes are not bound to accepted evidence")
            source = member(syft_handoff, matching[0])
            if source_identity is not None and dict(source_identity) != source:
                raise NativeInputIntegrityError("source Syft publication identity differs")
            read_json(run_root, source, limit)
            inputs.append(source)
        if envelope.get("exclusions_and_gaps"):
            inherited.append(gap("upstream_partial", "source-syft",
                                 "; ".join(str(item) for item in envelope["exclusions_and_gaps"])[:4096]))
    if source is None:
        inherited.append(gap("input_missing", "source-syft",
                             "accepted source Syft inventory is unavailable; native-only publication"))
    normalized = {}
    for kind, rows in (("commands", commands), ("artifacts", artifacts)):
        normalized[kind] = [
            {**{key: value for key, value in row.items() if key != "evidence_source"},
             "accepted_source": row["evidence_source"]}
            for row in rows
        ]
    normalized_path = unit.unit_root / "protected-native-inputs.json"
    protected_json(normalized_path, {
        "schema": "appsec-review/native-inputs/1", "source_fingerprint": snapshot, **normalized,
    })
    normalized_ref = put_bytes(run_root, normalized_path.read_bytes())
    safe_path(run_root, normalized_ref["path"]).chmod(0o600)
    inputs.append(normalized_ref)
    for kind, rows in (("commands", commands), ("artifacts", artifacts)):
        for index, row in enumerate(rows):
            row["evidence_source"] = {
                "artifact": normalized_ref, "json_pointer": f"/{kind}/{index}",
            }
    created = datetime.fromisoformat(str(catalog_handoff["started_at"]).replace("Z", "+00:00"))
    if created.tzinfo is None:
        raise ValueError("accepted catalog timestamp lacks timezone")
    return {
        "native_files": files, "native_invocations": commands, "native_artifacts": artifacts,
        "native_workspace_roots": workspace_roots, "native_input_identities": inputs,
        "native_gaps": inherited, "native_exclusions": exclusions,
        "native_catalog_gaps": partition.get("gaps", []),
        "native_created": created.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source_syft": source,
    }


def read_native_file(unit: UnitContext, record: NativeFile, limit: int,
                     workspace_roots: Mapping[str, str]) -> bytes:
    try:
        if record["domain"] == "target":
            if unit.job.target_root is None:
                raise ValueError("target source root is unavailable")
            root = unit.job.target_root
        else:
            root = safe_path(unit.job.run_root, workspace_roots[record["root_id"]])
        path = safe_path(root, record["path"])
        if path.stat().st_size != record["size_bytes"]:
            raise NativeInputIntegrityError("native source size changed")
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
        if (len(payload) != record["size_bytes"]
                or hashlib.sha256(payload).hexdigest() != record["sha256"]):
            raise NativeInputIntegrityError("native source bytes changed")
        if record["domain"] == "workspace":
            record["backing"] = put_bytes(unit.job.run_root, payload)
        return payload
    except ValueError as exc:
        if isinstance(exc, NativeInputIntegrityError):
            raise
        raise NativeInputIntegrityError(str(exc)) from exc


def convert_syft(source: Mapping[str, Any], *, unit: UnitContext) -> SpdxBaseline:
    from .sbom import validate_spdx
    root = unit.job.run_root
    try:
        source_path = verify_reference(root, source)
    except ValueError as exc:
        raise NativeInputIntegrityError("source Syft inventory integrity changed") from exc
    settings = unit.job.config.settings
    if source_path.stat().st_size > settings["sbom_input_bytes"]:
        raise ValueError("source Syft inventory exceeds conversion byte bound")
    scope = hashlib.sha256(canonical_json({
        "job": "job_dependency_intelligence", "attempt": unit.job.attempt_id, "unit": unit.unit_id,
    })).hexdigest()[:24]
    # Docker Desktop cannot reliably bind the deeply nested task directory on Windows.
    staging = root / "data" / "native-sbom" / scope
    scratch, empty = staging / "conversion", staging / "target"
    scratch.mkdir(parents=True, exist_ok=True)
    empty.mkdir(parents=True, exist_ok=True)
    payload = source_path.read_bytes()
    if len(payload) != source["size_bytes"] or hashlib.sha256(payload).hexdigest() != source["sha256"]:
        raise NativeInputIntegrityError("source Syft inventory changed while staging")
    staged_source = staging / "syft.json"
    atomic_bytes(staged_source, payload)
    try:
        catalog = load_catalog(unit.job.repository_root)
        tool = catalog.tool("tool-syft")
        tool = replace(tool, timeout_seconds=min(tool.timeout_seconds,
                                                settings["sbom_conversion_timeout_seconds"]))
        catalog = replace(catalog, tools={**catalog.tools, "tool-syft": tool})
        executor = ContainerExecutor(catalog, root)
        image = executor.resolve_image(tool)
        result = executor.execute(ExecutionRequest(
            "tool-syft", (tool.executable, "convert", "/inputs/syft.json",
                          "--output", "spdx-json=/scratch/baseline.spdx.json"),
            empty, scratch, extra_mounts=(Mount(staged_source, "/inputs/syft.json", True),),
            file_size_limit_bytes=settings["sbom_output_bytes"],
        ))
    except (RuntimeError, ValueError, OSError) as exc:
        raise NativeSbomInfrastructureError(f"Syft conversion runtime unavailable: {exc}") from exc
    atomic_json(unit.unit_root / "conversion.json", {
        "input": reference(root, staged_source),
        "execution": reference(root, root / result.receipt_path),
        "stdout": reference(root, root / result.stdout_path),
        "stderr": reference(root, root / result.stderr_path),
    })
    if result.exit_code != 0 or result.timed_out or result.oom_killed or result.file_size_limit_reached:
        raise RuntimeError(f"Syft SPDX conversion failed ({result.terminal_status}, exit={result.exit_code})")
    output = scratch / "baseline.spdx.json"
    output_ref = reference(root, output)
    document = read_json(root, output_ref, settings["sbom_input_bytes"])
    validate_spdx(document, bounds=sbom_bounds(settings))
    destination = unit.unit_root / "baseline.spdx.json"
    atomic_bytes(destination, output.read_bytes())
    return {
        "document": document, "artifact": reference(root, destination), "source_artifact": dict(source),
        "tool_identity": {"tool_id": "tool-syft", "version": tool.version, "image_id": image},
    }


def publish_sbom(unit: UnitContext, converter: Converter | None) -> dict[str, Any]:
    from .sbom import build_spdx, schema_sha256
    loaded, detected = unit.output("inputs.load_accepted"), unit.output("resolution.detect_dependencies")
    discovery = detected["native_discovery_document"]
    settings = unit.job.config.settings
    counters = {name: 0 for name in METRIC_COUNTERS}
    counters.update(discovery["metrics"])
    gaps = list(discovery["gaps"])
    baselines = []
    conversion_status, validation_status = "FAILED", "SUCCEEDED"
    computation = {
        "inputs": loaded["native_input_identities"], "source_fingerprint": unit.job.source_fingerprint,
        "native_bounds": asdict(native_bounds(settings)), "sbom_bounds": asdict(sbom_bounds(settings)),
        "discovery": DISCOVERY_IDENTITY, "merge": MERGE_IDENTITY, "schema_sha256": schema_sha256(),
    }
    baseline_ref = None
    with operation_span(unit.job.events, "native-sbom.publication", unit_id=unit.unit_id) as span:
        source = loaded["source_syft"]
        if source is not None:
            with operation_span(unit.job.events, "native-sbom.conversion", unit_id=unit.unit_id) as conversion_span:
                try:
                    baseline = (converter or convert_syft)(source, unit=unit)
                    try:
                        verify_reference(unit.job.run_root, baseline["artifact"])
                    except (ValueError, KeyError) as exc:
                        raise NativeInputIntegrityError("converter artifact identity changed") from exc
                    if dict(baseline["source_artifact"]) != dict(source):
                        raise NativeInputIntegrityError("converter source identity changed")
                    document = read_json(unit.job.run_root, baseline["artifact"], settings["sbom_input_bytes"])
                    if document != baseline["document"]:
                        raise NativeInputIntegrityError("converter document differs from retained bytes")
                    baselines.append(baseline)
                    baseline_ref = baseline["artifact"]
                    conversion_status = "SUCCEEDED"
                except (NativeInputIntegrityError, NativeSbomInfrastructureError):
                    raise
                except (RuntimeError, ValueError, OSError) as exc:
                    conversion_span.status = "FAILED"
                    gaps.append(gap("sbom_conversion_failed", "source-syft",
                                    f"{type(exc).__name__}: {exc}"))
        fingerprint = hashlib.sha256(canonical_json({
            **computation, "converter": [dict(item["tool_identity"]) for item in baselines],
            "conversion_status": conversion_status,
        })).hexdigest()
        artifact = None
        try:
            result = build_spdx(
                source_fingerprint=unit.job.source_fingerprint, created=loaded["native_created"],
                baselines=baselines, discovery=discovery,
                input_identities=loaded["native_input_identities"], bounds=sbom_bounds(settings),
            )
            gaps.extend(result["gaps"])
            counters.update(result["metrics"])
            document_path = unit.unit_root / "enriched.spdx.json"
            atomic_json(document_path, result["document"])
            artifact = reference(unit.job.run_root, document_path)
            counters["output_bytes"] = artifact["size_bytes"]
            provenance = dict(result["provenance"])
            fingerprint = provenance["input_fingerprint"]
        except SpdxValidationError as exc:
            validation_status = "FAILED"
            gaps.append(gap("sbom_validation_failed", "spdx-publication", str(exc)))
            provenance = {
                "schema": "appsec-review/native-sbom-provenance/1",
                "source_fingerprint": unit.job.source_fingerprint, "packages": [],
                "input_fingerprint": fingerprint,
                "input_identities": loaded["native_input_identities"], "gaps": gaps,
            }
        unique_gaps = {canonical_json(item): item for item in gaps}
        gaps = [unique_gaps[key] for key in sorted(unique_gaps)]
        status = "FAILED" if artifact is None else "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"
        span.status = status
        provenance_path = unit.unit_root / "native-sbom-provenance.json"
        atomic_json(provenance_path, provenance)
        metrics = {
            "schema": METRICS_SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
            "run_id": unit.job.run_id, "job_id": "job_dependency_intelligence",
            "attempt_id": unit.job.attempt_id, "unit_id": unit.unit_id, "status": status,
            "discovery_status": "COMPLETED_WITH_GAPS" if discovery["gaps"] else "SUCCEEDED",
            "conversion_status": conversion_status, "validation_status": validation_status,
            "input_fingerprint": fingerprint, "sbom_sha256": artifact["sha256"] if artifact else None,
            "counters": counters, "gaps_by_kind": dict(sorted(Counter(item["kind"] for item in gaps).items())),
        }
        metrics_path = unit.unit_root / "native-sbom-metrics.json"
        atomic_json(metrics_path, metrics)
        metrics_ref = reference(unit.job.run_root, metrics_path)
        conversion_path = unit.unit_root / "conversion.json"
        conversion = (json.loads(conversion_path.read_bytes()) if conversion_path.is_file() else None)
        unit.job.events.write("NATIVE_SBOM_RESULT", unit_id=unit.unit_id,
                              metrics_receipt=metrics_ref, input_fingerprint=fingerprint)
        return {
            "format": "spdx-json", "spec_version": "2.3", "status": status,
            "artifact": artifact, "baseline": baseline_ref,
            "conversion": conversion,
            "provenance": reference(unit.job.run_root, provenance_path), "metrics": metrics_ref,
            "input_fingerprint": fingerprint, "schema_sha256": schema_sha256(),
            "bounds": asdict(sbom_bounds(settings)), "gaps": gaps,
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps or status == "FAILED" else "SUCCEEDED",
        }


def validate_publication(run_root: Path, framework: Mapping[str, Any],
                         document: Mapping[str, Any]) -> None:
    from .sbom import schema_sha256, validate_spdx
    sbom = document["sbom"]
    if (sbom.get("format") != "spdx-json" or sbom.get("spec_version") != "2.3"
            or sbom.get("schema_sha256") != schema_sha256()):
        raise ValueError("accepted native SPDX standard/schema identity changed")
    bounds = SbomBounds(**sbom["bounds"])
    discovery = read_json(run_root, member(framework, document["native_discovery"]),
                          bounds.output_bytes)
    if (discovery.get("schema") != "appsec-review/native-discovery/1"
            or discovery.get("source_fingerprint") != document["source_fingerprint"]):
        raise NativeInputIntegrityError("accepted native discovery snapshot changed")
    evidence_ids = {item["evidence_id"] for item in discovery["evidence"]}
    from .native_sbom_contracts import evidence_identity
    for evidence in discovery["evidence"]:
        if (evidence["evidence_id"] != evidence_identity(evidence)
                or evidence["source_fingerprint"] != document["source_fingerprint"]):
            raise NativeInputIntegrityError("accepted native evidence identity changed")
        verify_reference(run_root, member(framework, evidence["upstream"]))
        if evidence.get("backing"):
            verify_reference(run_root, member(framework, evidence["backing"]))
    for candidate in discovery["candidates"]:
        if not set(candidate["evidence_ids"]) <= evidence_ids:
            raise NativeInputIntegrityError("accepted native candidate evidence is unresolved")
    provenance = read_json(run_root, member(framework, sbom["provenance"]), bounds.output_bytes)
    if provenance.get("schema") != "appsec-review/native-sbom-provenance/1":
        raise ValueError("accepted native SPDX provenance schema changed")
    if (provenance.get("source_fingerprint") != document["source_fingerprint"]
            or provenance.get("input_fingerprint") != sbom["input_fingerprint"]):
        raise NativeInputIntegrityError("accepted native SPDX provenance snapshot/input changed")
    for identity in (sbom.get("conversion") or {}).values():
        verify_reference(run_root, member(framework, identity))
    metrics = read_json(run_root, member(framework, sbom["metrics"]), bounds.output_bytes)
    if (metrics.get("schema") != METRICS_SCHEMA or metrics.get("status") != sbom["status"]
            or metrics.get("input_fingerprint") != sbom["input_fingerprint"]
            or metrics.get("source_fingerprint") != document["source_fingerprint"]
            or set(metrics.get("counters", {})) != set(METRIC_COUNTERS)
            or any(type(value) is not int or value < 0 for value in metrics["counters"].values())):
        raise ValueError("accepted native SPDX metrics binding changed")
    if sbom.get("baseline"):
        validate_spdx(read_json(run_root, member(framework, sbom["baseline"]), bounds.input_bytes),
                      bounds=bounds)
    if sbom.get("artifact"):
        identity = member(framework, sbom["artifact"])
        spdx = read_json(run_root, identity, bounds.output_bytes)
        validate_spdx(spdx, bounds=bounds)
        package_ids = {item["SPDXID"] for item in spdx.get("packages", ())}
        if set(provenance.get("packages", {})) != package_ids:
            raise NativeInputIntegrityError("accepted SPDX package provenance is incomplete")
        candidate_ids = {item["candidate_id"] for item in discovery["candidates"]}
        for package in provenance["packages"].values():
            if (not set(package.get("evidence_ids", ())) <= evidence_ids
                    or not set(package.get("native_candidate_ids", ())) <= candidate_ids):
                raise NativeInputIntegrityError("accepted SPDX provenance evidence is unresolved")
            for baseline in package.get("baseline_packages", ()):
                verify_reference(run_root, member(framework, baseline["artifact"]))
                verify_reference(run_root, member(framework, baseline["source_artifact"]))
        if (sbom["status"] not in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
                or metrics["sbom_sha256"] != identity["sha256"]
                or metrics["counters"]["output_bytes"] != identity["size_bytes"]):
            raise ValueError("accepted native SPDX publication status/hash changed")
    elif sbom["status"] != "FAILED" or metrics["sbom_sha256"] is not None:
        raise ValueError("accepted native SPDX publication has no standard document")
