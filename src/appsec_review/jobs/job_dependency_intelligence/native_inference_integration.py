"""Job boundaries for curated, evidence-bound native SBOM enrichment."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, fields
import hashlib
import time
from typing import Any

from appsec_review.inference import Infer
from appsec_review.observability.spans import operation_span
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage.shared import reference, verify_reference

from .integration import member, read_native_file
from .native_inference_contracts import (
    INFERENCE_COUNTERS, INFERENCE_METRICS_SCHEMA, NativeInferenceBounds,
)
from .native_sbom_contracts import GAP_KINDS


INFERENCE_UNITS = ("resolution.curate_components", "resolution.investigate_components")


def inference_bounds(settings: Mapping[str, Any]) -> NativeInferenceBounds:
    config = settings["native_inference"]
    if not isinstance(config, Mapping) or type(config.get("enabled")) is not bool:
        raise ValueError("native inference requires an explicit enabled setting")
    expected = {field.name for field in fields(NativeInferenceBounds)}
    if set(config) != expected | {"enabled"}:
        raise ValueError("native inference settings do not match the typed bounds")
    return NativeInferenceBounds(**{name: config[name] for name in expected})


def _publish(unit: UnitContext, result: Mapping[str, Any], proposer: Any,
             *, started: float, input_document: Mapping[str, Any]) -> dict[str, Any]:
    if len(canonical_json(result)) > unit.job.config.settings["sbom_output_bytes"]:
        raise ValueError("native inference result exceeds the publication byte bound")
    result_path = unit.unit_root / "native-inference.json"
    atomic_json(result_path, result)
    result_ref = reference(unit.job.run_root, result_path)
    discovery_path = unit.unit_root / "native-discovery.json"
    atomic_json(discovery_path, result["discovery"])
    discovery_ref = reference(unit.job.run_root, discovery_path)
    counters = dict.fromkeys(INFERENCE_COUNTERS, 0)
    for source in (result["metrics"], proposer.metrics if proposer is not None else {}):
        if not set(source) <= set(counters):
            raise ValueError("native inference returned unsupported counters")
        for name, value in source.items():
            if type(value) is not int or value < 0:
                raise ValueError("native inference counters must be nonnegative integers")
            counters[name] += value
    artifacts = list(proposer.artifacts) if proposer is not None else []
    for artifact in artifacts:
        verify_reference(unit.job.run_root, artifact)
    manifest_path = unit.unit_root / "model-artifacts.json"
    atomic_json(manifest_path, {"schema": "appsec-review/native-inference-artifacts/1",
                               "artifacts": artifacts})
    manifest_ref = reference(unit.job.run_root, manifest_path)
    gaps = list(result["gaps"])
    status = "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"
    fingerprint = hashlib.sha256(canonical_json({
        "input": input_document, "bounds": asdict(inference_bounds(unit.job.config.settings)),
        "model": unit.job.config.settings["model"],
        "guidance": proposer.guidance_hashes if proposer is not None else [],
        "result": result_ref,
    })).hexdigest()
    receipt = {
        "schema": INFERENCE_METRICS_SCHEMA, "run_id": unit.job.run_id,
        "job_id": "job_dependency_intelligence", "attempt_id": unit.job.attempt_id,
        "unit_id": unit.unit_id, "source_fingerprint": unit.job.source_fingerprint,
        "input_fingerprint": fingerprint, "status": status, "counters": counters,
        "duration_ms": (time.monotonic() - started) * 1000,
        "usage_complete": counters["unknown_usage_calls"] == 0,
        "gaps_by_kind": dict(sorted(Counter(item["kind"] for item in gaps).items())),
        "result": result_ref, "discovery": discovery_ref, "model_artifacts": manifest_ref,
    }
    metrics_path = unit.unit_root / "native-inference-metrics.json"
    atomic_json(metrics_path, receipt)
    metrics_ref = reference(unit.job.run_root, metrics_path)
    unit.job.events.write("NATIVE_INFERENCE_RESULT", unit_id=unit.unit_id,
                          metrics_receipt=metrics_ref, input_fingerprint=fingerprint)
    return {
        "artifact": result_ref, "native_discovery": discovery_ref,
        "native_discovery_document": result["discovery"], "inference_metrics": metrics_ref,
        "model_artifacts": [manifest_ref, *artifacts], "input_fingerprint": fingerprint,
        "gaps": gaps, "terminal_status": status,
    }


def run_native_inference(unit: UnitContext, infer: Infer | None, *, investigate: bool) -> dict[str, Any]:
    from .curation import curate_native_components
    from .investigation import investigate_native_metadata
    from .native_inference_runtime import make_proposer

    loaded = unit.output("inputs.load_accepted")
    previous = unit.output("resolution.curate_components" if investigate else
                           "resolution.detect_dependencies")
    discovery = previous["native_discovery_document"]
    settings = unit.job.config.settings
    bounds = inference_bounds(settings)
    enabled = settings["native_inference"]["enabled"] and settings["model"]["enabled"]
    proposer = (make_proposer(
        repository_root=unit.job.repository_root, run_root=unit.job.run_root,
        model=settings["model"], infer=infer, bounds=bounds,
        events=unit.job.events, unit_id=unit.unit_id,
    ) if enabled and infer is not None else None)
    started = time.monotonic()
    operation = "native-sbom.metadata" if investigate else "native-sbom.curation"
    with operation_span(unit.job.events, operation, unit_id=unit.unit_id) as span:
        if investigate:
            result = investigate_native_metadata(
                discovery, loaded["native_files"], propose=proposer, bounds=bounds,
                read_file=lambda record, limit: read_native_file(
                    unit, record, limit, loaded["native_workspace_roots"]),
            )
        else:
            result = curate_native_components(discovery, loaded["native_files"],
                                               propose=proposer, bounds=bounds)
        if result["gaps"]:
            span.status = "COMPLETED_WITH_GAPS"
        return _publish(unit, result, proposer, started=started, input_document=discovery)


def validate_inference_receipt(run_root, identity: Mapping[str, Any], *,
                               source_fingerprint: str, unit_id: str | None = None,
                               attempt_id: str | None = None) -> dict[str, Any]:
    import json
    import math

    path = verify_reference(run_root, identity)
    if path.stat().st_size > 65536:
        raise ValueError("native inference metrics exceed their byte bound")
    receipt = json.loads(path.read_bytes())
    if (not isinstance(receipt, dict) or receipt.get("schema") != INFERENCE_METRICS_SCHEMA
            or receipt.get("run_id") != run_root.name
            or receipt.get("job_id") != "job_dependency_intelligence"
            or receipt.get("unit_id") not in INFERENCE_UNITS
            or receipt.get("source_fingerprint") != source_fingerprint
            or (unit_id is not None and receipt["unit_id"] != unit_id)
            or (attempt_id is not None and receipt.get("attempt_id") != attempt_id)):
        raise ValueError("native inference metrics provenance changed")
    if (receipt.get("status") not in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
            or not isinstance(receipt.get("input_fingerprint"), str)
            or len(receipt["input_fingerprint"]) != 64
            or any(char not in "0123456789abcdef" for char in receipt["input_fingerprint"])):
        raise ValueError("native inference metrics disposition/fingerprint is invalid")
    counters = receipt.get("counters")
    if (not isinstance(counters, dict) or set(counters) != set(INFERENCE_COUNTERS)
            or any(type(value) is not int or value < 0 for value in counters.values())
            or counters["unknown_usage_calls"] > counters["model_calls"]
            or counters["model_failures"] > counters["model_calls"]):
        raise ValueError("native inference metrics counters are invalid")
    duration = receipt.get("duration_ms")
    if (type(duration) not in {int, float} or not math.isfinite(duration) or duration < 0
            or type(receipt.get("usage_complete")) is not bool
            or receipt["usage_complete"] != (counters["unknown_usage_calls"] == 0)):
        raise ValueError("native inference timing/usage accounting is invalid")
    gaps = receipt.get("gaps_by_kind")
    if (not isinstance(gaps, dict)
            or any(key not in GAP_KINDS or type(value) is not int or value < 1
                   for key, value in gaps.items())
            or (receipt["status"] == "SUCCEEDED") != (not gaps)):
        raise ValueError("native inference coverage accounting is invalid")
    for artifact in (receipt["result"], receipt["discovery"], receipt["model_artifacts"]):
        verify_reference(run_root, artifact)
    manifest_path = verify_reference(run_root, receipt["model_artifacts"])
    if manifest_path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("native inference artifact manifest exceeds its bound")
    manifest = json.loads(manifest_path.read_bytes())
    if (not isinstance(manifest, dict)
            or manifest.get("schema") != "appsec-review/native-inference-artifacts/1"
            or not isinstance(manifest.get("artifacts"), list)
            or any(not isinstance(item, dict) for item in manifest["artifacts"])):
        raise ValueError("native inference artifact manifest schema changed")
    for artifact in manifest["artifacts"]:
        verify_reference(run_root, artifact)
    return receipt


def validate_inference_publication(run_root, framework: Mapping[str, Any],
                                  document: Mapping[str, Any]) -> None:
    import json

    identities = document["sbom"]["inference_metrics"]
    if not isinstance(identities, list) or len(identities) != len(INFERENCE_UNITS):
        raise ValueError("accepted native inference metrics are incomplete")
    for unit_id, identity in zip(INFERENCE_UNITS, identities, strict=True):
        receipt = validate_inference_receipt(
            run_root, member(framework, identity),
            source_fingerprint=document["source_fingerprint"], unit_id=unit_id,
            attempt_id=framework["attempt_id"])
        for artifact in (receipt["result"], receipt["discovery"], receipt["model_artifacts"]):
            member(framework, artifact)
        manifest_path = verify_reference(run_root, receipt["model_artifacts"])
        for artifact in json.loads(manifest_path.read_bytes())["artifacts"]:
            member(framework, artifact)
        result_name = "native_curation" if unit_id == INFERENCE_UNITS[0] else "native_metadata"
        if receipt["result"] != document[result_name]:
            raise ValueError("accepted native inference result binding changed")
        if unit_id == INFERENCE_UNITS[1] and receipt["discovery"] != document["native_discovery"]:
            raise ValueError("accepted native inference discovery binding changed")
    for name in ("raw_native_discovery", "native_curation", "native_metadata"):
        verify_reference(run_root, member(framework, document[name]))
