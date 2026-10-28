"""Byte-verified job interchange accounting, independent of job-specific result schemas.

Execution comes from task receipts. Only explicitly declared producer status and gap
fields contribute coverage; nested tool payloads and narrative text have no authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.interchange import (
    ArtifactReference, CoverageDisposition, CoverageSummary, ExecutionStatus, GapCode,
    OUTCOMES_SCHEMA, ProducerGap, UnitOutcome, artifact_reference_from_mapping,
    classify_producer_status, decode_handoff, gap_id,
)
from appsec_review.runtime.datasets import read_dataset_contract
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import reference, safe_path, verify_reference
from appsec_review.storage.validation import validation_operation


_COVERAGE_ALIASES = {
    "COMPLETE": "complete", "PARTIAL": "partial", "UNAVAILABLE": "unavailable",
    "NOT_APPLICABLE": "not_applicable", "SKIPPED_NA": "not_applicable",
    "SKIPPED_POLICY": "skipped_policy", "CONFIGURED_DISABLED": "skipped_policy",
}
_DETERMINISTIC_FAILURES = {"INVALID_COMPILE_DATABASE", "BLOCKED_BY_COMPILE"}
_KNOWN_STATUSES = {
    "SUCCEEDED", "COMPLETE", "COMPLETED", "FAILED", "GAP", "BLOCKED", "BLOCKED_BY_COMPILE",
    "INVALID_COMPILE_DATABASE", "UNAVAILABLE", "TIMED_OUT", "TIMEOUT", "OOM_KILLED",
    "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY", "CONFIGURED_DISABLED",
    "PARTIAL", "COMPLETED_WITH_GAPS", "DEGRADED",
}
_REFERENCE_FIELD = re.compile(r"(?:.*_)?(?:artifact|artifacts|reference|references|receipt|receipts)$")
_REFERENCE_FIELDS = {
    "index_manifest", "outcomes", "input_manifest", "object", "dependencies", "evidence_refs",
    "native_output", "native_outputs",
}
_SOURCE_DATA_FIELDS = {
    "files", "source_files", "source_metrics", "artifact_candidates", "source_inventory",
    "sources", "input_files", "source_inputs", "native_files", "file_inventory", "payload", "records", "findings", "raw",
}


def _read(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    artifact_reference_from_mapping(ref)
    value = json.loads(verify_reference(root, ref).read_bytes())
    if not isinstance(value, dict):
        raise ValueError("handoff accounting document must be an object")
    return value


def collect_artifacts(root: Path, *values: Any) -> list[dict[str, Any]]:
    """Resolve every declared artifact reference, never silently drop a missing path."""
    artifacts: dict[str, dict[str, Any]] = {}
    source_layers: list[Mapping[str, Any]] | None = None

    def collect(value: Any, *, declared: bool = False, source_data: bool = False) -> None:
        nonlocal source_layers
        if isinstance(value, Mapping):
            if ("path" in value or "run_path" in value) and "sha256" in value:
                relative = value.get("run_path", value.get("path"))
                # Intake records external configuration identity, not permission to
                # open that source. Only an exact frozen layer can use this shape.
                if "run_path" not in value and isinstance(relative, str) and Path(relative).is_absolute():
                    if source_layers is None:
                        manifest = json.loads(safe_path(root, "data/configuration/manifest.json").read_bytes())
                        source_layers = manifest["sources"]
                    if value in source_layers:
                        return
                # Source inventories also have path/hash/size fields. Those are
                # not run artifacts; artifact fields and the run's data namespace are.
                if "run_path" in value or declared or (
                        not source_data and isinstance(relative, str) and relative.startswith("data/")):
                    path = safe_path(root, relative)
                    ref = reference(root, path, expected_sha256=value["sha256"])
                    if "size_bytes" in value and (
                            type(value["size_bytes"]) is not int or value["size_bytes"] != ref["size_bytes"]):
                        raise ValueError("result artifact size mismatch")
                    previous = artifacts.setdefault(ref["path"], ref)
                    if previous != ref:
                        raise ValueError("result artifact has conflicting identities")
            for name, child in value.items():
                collect(child, declared=name in _REFERENCE_FIELDS or _REFERENCE_FIELD.fullmatch(name) is not None,
                        source_data=source_data or name in _SOURCE_DATA_FIELDS)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect(child, declared=declared, source_data=source_data)

    for value in values:
        collect(value, declared=True)
    return list(artifacts.values())


def _gap(unit_id: str | None, code: str, reason: str, *, retryable: bool = False,
         scope_id: str | None = None, refs: tuple[ArtifactReference, ...] = ()) -> ProducerGap:
    identity = {"unit_id": unit_id, "scope_id": scope_id, "code": code, "reason": reason}
    return ProducerGap(gap_id(identity), code, unit_id, scope_id, reason, retryable, refs)


def _declared_gap(value: Any, unit_id: str, refs: tuple[ArtifactReference, ...]) -> ProducerGap:
    if isinstance(value, Mapping) and value.get("schema") == "appsec-review/producer-gap/1":
        fields = {"schema", "gap_id", "code", "unit_id", "scope_id", "reason", "retryable", "evidence_refs"}
        if set(value) != fields or not isinstance(value["evidence_refs"], list):
            raise ValueError("invalid declared producer gap")
        gap = ProducerGap(**{**value, "evidence_refs": tuple(
            artifact_reference_from_mapping(ref) for ref in value["evidence_refs"])})
        if gap.unit_id not in {None, unit_id}:
            raise ValueError("declared producer gap belongs to another unit")
        return gap
    if isinstance(value, str) and value.strip():
        reason, scope = value, None
    elif isinstance(value, Mapping) and value:
        reason = canonical_json(value).decode("utf-8").strip()
        scope = value.get("scope_id")
        if scope is not None and not isinstance(scope, str):
            raise ValueError("invalid producer gap scope")
    else:
        raise ValueError("producer gaps must be nonempty text or structured records")
    return _gap(unit_id, GapCode.PRODUCER_REPORTED_GAP, reason, scope_id=scope, refs=refs)


def _coverage(status: str | None, explicit: Any = None, *, has_gaps: bool = False) -> CoverageSummary:
    if explicit is not None:
        explicit = _COVERAGE_ALIASES.get(explicit, explicit) if isinstance(explicit, str) else explicit
        if explicit not in set(CoverageDisposition):
            return CoverageSummary(CoverageDisposition.UNAVAILABLE, int(has_gaps), False)
    summary = classify_producer_status(status, coverage_disposition=explicit, has_gaps=has_gaps)
    return CoverageSummary(summary.disposition, summary.gap_count,
                           summary.retry_required and status not in _DETERMINISTIC_FAILURES)


def _summarize(units: Sequence[UnitOutcome], gaps: Sequence[ProducerGap]) -> CoverageSummary:
    dispositions = {unit.coverage_disposition for unit in units}
    if not units or dispositions == {CoverageDisposition.UNAVAILABLE}:
        disposition = CoverageDisposition.UNAVAILABLE
    elif dispositions <= {CoverageDisposition.NOT_APPLICABLE, CoverageDisposition.SKIPPED_POLICY}:
        disposition = (CoverageDisposition.SKIPPED_POLICY
                       if CoverageDisposition.SKIPPED_POLICY in dispositions else CoverageDisposition.NOT_APPLICABLE)
    elif gaps or dispositions & {CoverageDisposition.UNAVAILABLE, CoverageDisposition.PARTIAL}:
        disposition = CoverageDisposition.PARTIAL
    else:
        disposition = CoverageDisposition.COMPLETE
    return CoverageSummary(disposition, len(gaps), any(gap.retryable for gap in gaps))


def execution_status(outcomes: Mapping[str, Any]) -> str:
    statuses = {unit["execution_status"] for unit in outcomes["units"]}
    if ExecutionStatus.FAILED in statuses:
        return ExecutionStatus.FAILED
    if not statuses or statuses == {ExecutionStatus.SKIPPED}:
        return ExecutionStatus.SKIPPED
    return ExecutionStatus.SUCCEEDED


def frozen_job_config_sha256(document: Mapping[str, Any], job_id: str) -> str:
    """Reconstruct the job hash from the frozen resolved configuration, not live code."""
    from appsec_review.config.loader import _build_capture
    job = document["jobs"][job_id]
    capture = _build_capture(document["build_capture"])
    override = job.get("settings", {}).get("build_capture")
    if override is not None:
        capture = _build_capture(override, base=capture)
    value = {
        "job_id": job_id, "name": str(job.get("name", "")), "workers": int(job.get("workers", 1)),
        "settings": job.get("settings", {}), "build_capture": asdict(capture),
        "steps": {
            step_id: {"workers": int(step.get("workers", 1)), "settings": step.get("settings", {}),
                      "tasks": {task_id: {"workers": int(task.get("workers", 1)),
                                          "settings": task.get("settings", {})}
                                for task_id, task in step.get("tasks", {}).items()}}
            for step_id, step in job.get("steps", {}).items()
        },
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _producer_outcome(unit_id: str, state: ExecutionStatus, result: Mapping[str, Any],
                      result_ref: ArtifactReference | None, status_ref: ArtifactReference
                      ) -> tuple[UnitOutcome, dict[str, ProducerGap]]:
    refs = tuple(ref for ref in (result_ref, status_ref) if ref is not None)
    declared: dict[str, ProducerGap] = {}
    raw_gaps = result.get("gaps", [])
    if not isinstance(raw_gaps, list):
        raise ValueError("declared producer gaps must be an array")
    for raw in raw_gaps:
        gap = _declared_gap(raw, unit_id, refs)
        if gap.gap_id in declared and declared[gap.gap_id] != gap:
            raise ValueError("conflicting producer gap identities")
        declared[gap.gap_id] = gap
    status = result.get("terminal_status")
    if status is not None and (not isinstance(status, str) or not status.strip()):
        raise ValueError("producer terminal status must be nonempty text")
    dispositions = result.get("dispositions", [])
    if not isinstance(dispositions, list):
        raise ValueError("producer dispositions must be an array")
    summaries = []
    statuses = [(status, result.get("coverage_disposition"), None)]
    for disposition in dispositions:
        if not isinstance(disposition, Mapping):
            raise ValueError("producer disposition must be a record")
        producer = disposition.get("terminal_status")
        if producer is None:
            producer = disposition.get("disposition")
        if producer is not None and not isinstance(producer, str):
            raise ValueError("producer disposition status must be text")
        scope = disposition.get("scope_id")
        statuses.append((producer, disposition.get("coverage_disposition"), scope))
    for producer, explicit, scope in statuses:
        summary = _coverage(producer, explicit, has_gaps=bool(declared))
        summaries.append(summary)
        unknown = ((producer is not None and producer not in _KNOWN_STATUSES)
                   or (explicit is not None and _COVERAGE_ALIASES.get(explicit, explicit)
                       not in set(CoverageDisposition)))
        if (unknown or summary.disposition == CoverageDisposition.UNAVAILABLE
                or (summary.disposition == CoverageDisposition.PARTIAL and not declared)):
            code = (GapCode.UNKNOWN_PRODUCER_STATUS if unknown else
                    GapCode.PRODUCER_FAILED if summary.retry_required or producer in _DETERMINISTIC_FAILURES
                    else GapCode.PRODUCER_REPORTED_GAP)
            # Preserve native status verbatim in accounting, never in telemetry labels.
            reason = f"producer status: {producer}; coverage disposition: {explicit}"
            gap = _gap(unit_id, code, reason, retryable=summary.retry_required, scope_id=scope, refs=refs)
            declared[gap.gap_id] = gap
    if state is not ExecutionStatus.SUCCEEDED:
        gap = _gap(unit_id, GapCode.PRODUCER_FAILED if state is ExecutionStatus.FAILED else
                   GapCode.PRODUCER_BLOCKED, f"task execution: {state}", retryable=True, refs=refs)
        declared[gap.gap_id] = gap
    coverage = {item.disposition for item in summaries}
    if state is not ExecutionStatus.SUCCEEDED or summaries[0].disposition == CoverageDisposition.UNAVAILABLE:
        disposition = CoverageDisposition.UNAVAILABLE
    elif CoverageDisposition.UNAVAILABLE in coverage:
        disposition = CoverageDisposition.PARTIAL
    elif CoverageDisposition.PARTIAL in coverage or declared:
        disposition = CoverageDisposition.PARTIAL
    elif coverage <= {CoverageDisposition.NOT_APPLICABLE, CoverageDisposition.SKIPPED_POLICY}:
        disposition = (CoverageDisposition.SKIPPED_POLICY if CoverageDisposition.SKIPPED_POLICY in coverage
                       else CoverageDisposition.NOT_APPLICABLE)
    else:
        disposition = CoverageDisposition.COMPLETE
    return UnitOutcome(unit_id, state, status, disposition, result_ref, status_ref, tuple(sorted(declared))), declared


def build_outcomes(root: Path, *, run_id: str, job_id: str, attempt_id: str, target_snapshot: str,
                   unit_ids: Sequence[str], diagnostic: bool = False) -> dict[str, Any]:
    units: list[UnitOutcome] = []
    gaps: dict[str, ProducerGap] = {}
    for unit_id in unit_ids:
        parts = unit_id.split(".")
        if len(parts) != 2 or any(not part or not part.replace("_", "a").isalnum() for part in parts):
            raise ValueError("invalid outcome unit identity")
        step, task = parts
        base = f"data/jobs/{job_id}/attempts/{attempt_id}/steps/{step}/tasks/{task}"
        try:
            status_ref = artifact_reference_from_mapping(reference(root, safe_path(root, base + "/status.json")))
            receipt = _read(root, status_ref.as_dict())
            state = ExecutionStatus(receipt["status"])
            if (receipt.get("unit_id") != unit_id or receipt.get("step_id") != step
                    or receipt.get("task_id") != task):
                raise ValueError("unit terminal receipt identity mismatch")
            result_ref = None
            result: dict[str, Any] = {}
            if state is ExecutionStatus.SUCCEEDED:
                result_ref = artifact_reference_from_mapping(reference(
                    root, safe_path(root, base + "/result.json"), expected_sha256=receipt["result_sha256"]))
                result = _read(root, result_ref.as_dict())
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if not diagnostic:
                raise ValueError(f"unit terminal receipt is missing or unsafe: {unit_id}") from exc
            gap = _gap(unit_id, GapCode.INPUT_UNAVAILABLE, "verified terminal receipt unavailable", retryable=True)
            gaps[gap.gap_id] = gap
            continue
        try:
            unit, declared = _producer_outcome(unit_id, state, result, result_ref, status_ref)
            for gap in declared.values():
                for evidence in gap.evidence_refs:
                    verify_reference(root, evidence.as_dict())
        except (OSError, ValueError, KeyError, TypeError):
            if not diagnostic:
                raise
            refs = tuple(ref for ref in (result_ref, status_ref) if ref is not None)
            gap = _gap(unit_id, GapCode.UNKNOWN_PRODUCER_STATUS, "invalid producer accounting declaration", refs=refs)
            status = result.get("terminal_status")
            native_status = status if isinstance(status, str) and status.strip() and "\x00" not in status else None
            unit = UnitOutcome(unit_id, state, native_status, CoverageDisposition.UNAVAILABLE,
                               result_ref, status_ref, (gap.gap_id,))
            declared = {gap.gap_id: gap}
        units.append(unit)
        for identity, gap in declared.items():
            if identity in gaps and gaps[identity] != gap:
                raise ValueError("conflicting producer gap identities")
            gaps[identity] = gap
    ordered_gaps = [gaps[key] for key in sorted(gaps)]
    return {"schema": OUTCOMES_SCHEMA, "run_id": run_id, "job_id": job_id, "attempt_id": attempt_id,
            "target_snapshot": target_snapshot, "units": [unit.as_dict() for unit in units],
            "gaps": [gap.as_dict() for gap in ordered_gaps],
            "coverage": _summarize(units, ordered_gaps).as_dict()}


@validation_operation
def verify_outcomes(root: Path, handoff: Mapping[str, Any]) -> dict[str, Any]:
    handoff = decode_handoff(handoff, run_id=root.name, accepted_only=False)
    document = _read(root, handoff["outcomes"])
    fields = {"schema", "run_id", "job_id", "attempt_id", "target_snapshot", "units", "gaps", "coverage"}
    if set(document) != fields or document["schema"] != OUTCOMES_SCHEMA:
        raise ValueError("unsupported job outcomes document")
    for name in ("run_id", "job_id", "attempt_id", "target_snapshot"):
        if document[name] != handoff[name]:
            raise ValueError("outcomes identity differs from handoff")
    if not isinstance(document["units"], list) or not isinstance(document["gaps"], list):
        raise ValueError("outcomes must contain unit and gap arrays")
    pinned = {ref["path"]: ref for ref in handoff["artifacts"]}
    for ref in collect_artifacts(root, document):
        if pinned.get(ref["path"]) != ref:
            raise ValueError("outcomes reference is not bound in handoff artifacts")
    claim_ref = pinned.get(handoff["resolving_paths"]["attempt"] + "/claim.json")
    if claim_ref is None:
        raise ValueError("handoff does not bind its attempt claim")
    claim = _read(root, claim_ref)
    unit_ids = claim.get("unit_ids", [unit["unit_id"] for unit in document["units"]])
    if (not isinstance(unit_ids, list) or any(not isinstance(unit, str) for unit in unit_ids)
            or len(unit_ids) != len(set(unit_ids))):
        raise ValueError("invalid pinned unit topology")
    expected = build_outcomes(root, run_id=root.name, job_id=handoff["job_id"], attempt_id=handoff["attempt_id"],
                              target_snapshot=handoff["target_snapshot"], unit_ids=unit_ids,
                              diagnostic=handoff["status"] == "REJECTED")
    if canonical_json(document) != canonical_json(expected):
        raise ValueError("outcomes differ from verified task receipts and producer declarations")
    if document["coverage"] != handoff["coverage"] or execution_status(document) != handoff["execution_status"]:
        raise ValueError("handoff coverage or execution differs from outcomes")
    return document


@validation_operation
def verify_handoff_integrity(root: Path, handoff: Mapping[str, Any], *,
                             accepted_only: bool = True) -> dict[str, Any]:
    handoff = decode_handoff(handoff, run_id=root.name, accepted_only=accepted_only)
    pinned = {ref["path"]: ref for ref in handoff["artifacts"]}
    for ref in pinned.values():
        verify_reference(root, ref)
    attempt = f"data/jobs/{handoff['job_id']}/attempts/{handoff['attempt_id']}"
    if handoff["resolving_paths"]["attempt"] != attempt:
        raise ValueError("handoff attempt path identity mismatch")
    claim_ref = pinned.get(attempt + "/claim.json")
    if claim_ref is None:
        raise ValueError("handoff does not bind its attempt claim")
    claim = _read(root, claim_ref)
    for name in ("run_id", "job_id", "attempt_id", "source_fingerprint", "resolved_config_sha256",
                 "input_identity"):
        if claim.get(name) != handoff[name]:
            raise ValueError(f"handoff differs from attempt claim: {name}")
    if claim.get("attempt_path") != attempt:
        raise ValueError("handoff differs from claim attempt path")
    if claim.get("upstream_handoffs", {}) != handoff["upstream_handoff_sha256"]:
        raise ValueError("handoff differs from claimed upstream handoffs")
    if claim.get("job_config_sha256", handoff["job_config_sha256"]) != handoff["job_config_sha256"]:
        raise ValueError("handoff differs from claimed job configuration")
    identities = claim.get("component_identities")
    if identities is not None and any(handoff[name] != identities[key] for name, key in (
            ("implementation_identity", "implementation"), ("schema_identity", "schema"),
            ("validation_identity", "validation"))):
        raise ValueError("handoff differs from claimed component identities")
    read_dataset_contract(claim["dataset_contract"], handoff["job_id"])
    if claim["dataset_contract"]["sha256"] != handoff["dataset_contract_sha256"]:
        raise ValueError("handoff differs from pinned dataset contract")
    manifest = handoff["input_manifest"]
    if ((manifest["path"] if manifest else None) != claim.get("input_manifest_path")
            or (manifest["sha256"] if manifest else None) != claim.get("input_manifest_sha256")):
        raise ValueError("handoff differs from claimed input manifest")
    config_manifest = json.loads(safe_path(root, "data/configuration/manifest.json").read_bytes())
    config_ref = reference(root, safe_path(root, "data/configuration/resolved.json"),
                           expected_sha256=handoff["resolved_config_sha256"])
    if config_manifest.get("resolved_sha256") != config_ref["sha256"]:
        raise ValueError("handoff differs from frozen configuration")
    frozen = _read(root, config_ref)
    if frozen_job_config_sha256(frozen, handoff["job_id"]) != handoff["job_config_sha256"]:
        raise ValueError("handoff job configuration differs from frozen configuration")
    if handoff["target_snapshot"] != claim.get("evidence_target_snapshot", handoff["source_fingerprint"]):
        raise ValueError("handoff differs from effective evidence identity")
    if manifest is not None:
        from appsec_review.retrieval.index import load_verified_manifest
        document, _ = load_verified_manifest(root, verify_reference(root, manifest), manifest["sha256"])
        if document["run_id"] != root.name or document["target_snapshot"] != handoff["target_snapshot"]:
            raise ValueError("input manifest target or run identity mismatch")
    if handoff["status"] == "ACCEPTED":
        result_path = handoff["resolving_paths"].get("result")
        if result_path != attempt + "/result.json" or result_path not in pinned:
            raise ValueError("accepted handoff does not bind its result")
        result = _read(root, pinned[result_path])
        if result.get("status") != handoff["completion_status"]:
            raise ValueError("handoff completion differs from its result")
        for unit_id, output in handoff["outputs"].items():
            native = result.get("outputs", {}).get(unit_id)
            if not isinstance(output, Mapping) or not isinstance(native, Mapping) or any(
                    key not in native or native[key] != value for key, value in output.items()):
                raise ValueError("handoff output differs from its result")
        for ref in collect_artifacts(root, result):
            if pinned.get(ref["path"]) != ref:
                raise ValueError("result reference is not bound in handoff artifacts")
        verify_required_outputs(root, handoff, claim, result)
    if handoff["outcomes"] is not None:
        verify_outcomes(root, handoff)
    from appsec_review.observability.spans import count_work
    count_work("handoff_validations")
    return handoff


def verify_required_outputs(root: Path, handoff: Mapping[str, Any], claim: Mapping[str, Any],
                            result: Mapping[str, Any]) -> None:
    """Required output claims are satisfied by this attempt, never inherited inventory."""
    _, declarations = read_dataset_contract(claim["dataset_contract"], handoff["job_id"])
    required = [declaration for declaration in declarations if declaration.required]
    from appsec_review.indexing.inventory import compile_glob
    from appsec_review.retrieval.index import MANIFEST_SCHEMA, load_verified_manifest
    from appsec_review.storage.shared import attempt_artifacts, verify_receipt
    attempt = handoff["resolving_paths"]["attempt"]
    emitted = collect_artifacts(root, result.get("outputs", {}))
    owned = {ref["path"] for ref in emitted if ref["path"].startswith(attempt + "/")}
    computed_shards: set[tuple[str, str]] = set()
    for ref in attempt_artifacts(root, safe_path(root, attempt)):
        if ref["path"].startswith(attempt + "/shared/"):
            receipt = verify_receipt(root, ref)
            if receipt["mode"] == "computed":
                owned.update(item["path"] for item in (receipt["object"], *receipt["dependencies"]))
                if receipt["namespace"] in {"index-shard", "owasp-shard"}:
                    computed_shards.add((receipt["object"]["path"], receipt["object"]["sha256"]))
    candidates = []
    direct = set()
    for output in result.get("outputs", {}).values():
        if not isinstance(output, Mapping):
            continue
        identity = output.get("index_identity")
        if isinstance(identity, Mapping):
            direct.add((identity.get("relative_path"), identity.get("sha256")))
        raw = output.get("index_manifest")
        if isinstance(raw, Mapping):
            path = verify_reference(root, next(ref for ref in emitted if ref["path"] == raw["path"]))
            document = json.loads(path.read_bytes())
            if document.get("schema") == MANIFEST_SCHEMA:
                verified, _ = load_verified_manifest(root, path, raw["sha256"])
                if verified["run_id"] != root.name or verified["target_snapshot"] != handoff["target_snapshot"]:
                    raise ValueError("output manifest target or run identity mismatch")
                candidates.extend(verified["indexes"])
    if not required:
        return
    for declaration in required:
        matched_artifact = any(compile_glob(pattern).fullmatch(path) for pattern in declaration.artifacts
                               for path in owned)
        matched_shard = any(
            raw.get("producer", {}).get("job") == handoff["job_id"]
            and str(raw.get("producer", {}).get("unit", "")).split(".")[0] == declaration.step
            and declaration.claims_shard(raw.get("name", ""), raw.get("shard_id", "default"))
            and (raw.get("relative_path"), raw.get("sha256")) in direct | computed_shards
            for raw in candidates)
        if not matched_artifact and not matched_shard:
            raise ValueError(f"required dataset output missing: {declaration.output_kind}")
