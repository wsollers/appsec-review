from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import time
from typing import Any

from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity, load_accepted_artifact_index
from appsec_review.retrieval import (EntityKind, EntityRecord, IndexBuilder, IndexIdentity,
    LogicalIdentity, RelationKind, RelationRecord, index_fingerprint, write_manifest)
from appsec_review.retrieval.index import INDEX_SCHEMA, load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .formats import ArchiveLimits, builtin_observation, classify
from .scanners import ADAPTERS, ContainerScannerRunner


SCHEMA = "appsec-review/artifact-security-analysis/1"
OBSERVATION_SCHEMA = "appsec-review/artifact-security-observation/1"
PARSER_IDENTITY = "appsec-review/artifact-security-parsers/1"
NORMALIZER_IDENTITY = "appsec-review/artifact-security-normalizer/1"
CAPABILITIES = ("inventory", "native", "jvm", "packages", "wasm", "spotbugs", "blint", "syft", "grype", "osv")
TOPOLOGY = {
    "load": ("accepted_artifacts",),
    "analyze": CAPABILITIES,
    "index": ("observations",),
    "acceptance": ("publish_handoff",),
}

ScannerRunner = Callable[[str, Path, Mapping[str, Any], int, int], Mapping[str, Any]]


class FrameworkIntegrityError(ValueError):
    """An accepted identity or immutable run-owned artifact changed."""


def _identity(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _safe_file(run_root: Path, identity: Mapping[str, Any]) -> Path:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise FrameworkIntegrityError("accepted produced artifact path is invalid")
    if file_sha256(path) != identity.get("sha256") or (
            identity.get("size_bytes") is not None and path.stat().st_size != identity.get("size_bytes")):
        raise FrameworkIntegrityError("accepted produced artifact identity changed")
    return path


def _accepted_artifacts(run_root: Path) -> dict[str, Any]:
    accepted = load_accepted_language_build(run_root)
    indexed = load_accepted_artifact_index(run_root)
    if indexed.get("language_build_handoff_sha256") != accepted.get("language_build_handoff_sha256"):
        raise FrameworkIntegrityError("artifact-indexing handoff does not bind the accepted language-build handoff")
    if indexed.get("source_fingerprint") != accepted.get("source_fingerprint"):
        raise FrameworkIntegrityError("artifact-indexing target snapshot differs from language-build")
    raw_manifest = indexed.get("index_manifest")
    if not isinstance(raw_manifest, Mapping):
        raise FrameworkIntegrityError("accepted artifact-indexing manifest is unavailable")
    manifest_path = _safe_file(run_root, raw_manifest)
    manifest, _ = load_verified_manifest(run_root, manifest_path, str(raw_manifest["sha256"]))
    if not any(item.get("name") == "artifacts" for item in manifest.get("indexes", ())):
        raise FrameworkIntegrityError("accepted artifact-indexing manifest has no artifacts shard")
    artifact_index = {"path": manifest_path.relative_to(run_root).as_posix(),
                      "sha256": str(raw_manifest["sha256"]),
                      "handoff_sha256": indexed["handoff_sha256"]}
    artifacts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for receipt in accepted.get("receipts", ()):
        if not isinstance(receipt, Mapping):
            raise FrameworkIntegrityError("language-build receipt is invalid")
        producer = {key: receipt.get(key) for key in ("build_unit_id", "family", "fingerprint",
                    "executor_identity", "capture_identity", "image")}
        for raw in receipt.get("artifacts", ()):
            if not isinstance(raw, Mapping):
                raise FrameworkIntegrityError("language-build artifact identity is invalid")
            path = _safe_file(run_root, raw)
            key = (str(raw.get("sha256", "")), str(raw.get("path", "")))
            if key in seen:
                continue
            seen.add(key)
            canonical = canonical_artifact_identity(str(accepted["source_fingerprint"]),
                                                    str(receipt.get("build_unit_id", "")), raw)
            artifacts.append({**dict(raw), "producer": producer, "canonical_identity": canonical.value,
                              "artifact_id": "artifact-" + hashlib.sha256(canonical_json(key)).hexdigest()[:24],
                              "verified_path": path.relative_to(run_root).as_posix()})
    artifacts.sort(key=lambda item: item["artifact_id"])
    return {"source_fingerprint": accepted.get("source_fingerprint"),
            "language_build_handoff_sha256": accepted["language_build_handoff_sha256"],
            "artifact_index": artifact_index, "artifacts": artifacts,
            "producer_gaps": list(accepted.get("gaps", ())) }


def _applicable(capability: str, classification: Mapping[str, Any]) -> bool:
    family, fmt = classification.get("family"), classification.get("format")
    if capability == "inventory": return True
    if capability == "native": return family in {"native", "dotnet"}
    if capability == "jvm": return family == "jvm"
    if capability == "spotbugs": return family == "jvm"
    if capability == "wasm": return family == "wasm"
    if capability == "packages": return bool(classification.get("container")) or family in {"node", "python", "php"}
    if capability == "blint": return family in {"native", "dotnet", "jvm", "wasm", "python", "node", "php"}
    if capability == "syft": return True
    if capability in {"grype", "osv"}: return True
    return False


def _stream(unit: UnitContext, root: Path, name: str, data: bytes, limit: int, tail: int) -> dict[str, Any]:
    truncated = len(data) > limit
    captured = data[:limit]
    path = root / name
    atomic_bytes(path, captured)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    tail_data = data[-tail:] if tail and len(data) > len(captured) else b""
    tail_identity = None
    if tail_data:
        tail_path = root / (name + ".tail")
        atomic_bytes(tail_path, tail_data)
        try:
            tail_path.chmod(0o600)
        except OSError:
            pass
        tail_identity = _identity(unit.job.run_root, tail_path)
    return {**_identity(unit.job.run_root, path), "byte_count": len(data),
            "captured_bytes": len(captured), "limit_bytes": limit, "truncated": truncated,
            "tail": tail_identity}


def _scan_one(unit: UnitContext, artifact: Mapping[str, Any], capability: str,
              runner: ScannerRunner | None) -> dict[str, Any]:
    settings = unit.job.config.settings
    limits = ArchiveLimits(int(settings["archive_member_limit"]), int(settings["archive_expanded_bytes"]),
                           int(settings["archive_member_bytes"]), int(settings["archive_ratio_limit"]),
                           int(settings["archive_depth_limit"]))
    path = _safe_file(unit.job.run_root, artifact)
    classification = classify(path, artifact)
    scanner_identity = (str(settings.get("scanner_identities", {}).get(capability, "unavailable")) +
                        (":" + ADAPTERS[capability].identity if capability in ADAPTERS else "")
                        if capability not in {"inventory", "native", "jvm", "packages", "wasm"}
                        else f"builtin-{capability}/1")
    identity_provider = getattr(runner, "identity", None)
    resolved_tool_identity = (identity_provider(capability, artifact)
                              if capability in ADAPTERS and callable(identity_provider) else {})
    if not isinstance(resolved_tool_identity, Mapping):
        raise FrameworkIntegrityError("scanner identity provider returned an invalid identity")
    fingerprint = hashlib.sha256(canonical_json({"schema": OBSERVATION_SCHEMA,
        "artifact_sha256": artifact["sha256"],
        "artifact_identity": artifact["canonical_identity"], "format": classification,
        "producer": artifact["producer"], "language_build_handoff": unit.output("load.accepted_artifacts")["language_build_handoff_sha256"],
        "artifact_index": unit.output("load.accepted_artifacts")["artifact_index"]["sha256"],
        "scanner": scanner_identity, "resolved_tool_identity": resolved_tool_identity,
        "parser": PARSER_IDENTITY, "normalizer": NORMALIZER_IDENTITY,
        "configuration": {key: settings[key] for key in sorted(settings) if key != "scanner_identities"}})).hexdigest()
    checkpoint = unit.job.run_root / "data" / "artifact-security" / "shards" / capability / fingerprint / "result.json"
    if checkpoint.is_file():
        prior = json.loads(checkpoint.read_text(encoding="utf-8"))
        if prior.get("fingerprint") != fingerprint:
            raise FrameworkIntegrityError("artifact-security checkpoint fingerprint changed")
        for identity in prior.get("raw_artifacts", ()):
            _safe_file(unit.job.run_root, identity)
        return {**prior, "reused": True}
    root = unit.job.attempt_root / "artifacts" / "asa" / artifact["artifact_id"][-12:] / capability
    root.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    observation: Mapping[str, Any] = {}
    gaps: list[str] = []
    stdout = b""
    stderr = b""
    exit_code: int | None = 0
    timed_out = False
    execution_receipt: Mapping[str, Any] | None = None
    tool_identity: Mapping[str, Any] = (dict(resolved_tool_identity) if resolved_tool_identity else
        {"scanner": scanner_identity, "rules": scanner_identity, "image": None})
    try:
        if capability in {"inventory", "native", "jvm", "packages", "wasm"}:
            observation, gaps = builtin_observation(path, classification, capability, limits)
            stdout = canonical_json(observation)
        elif runner is None:
            exit_code = None
            gaps = [f"{capability} scanner unavailable: no pinned executor configured"]
            stderr = gaps[0].encode()
        else:
            raw = runner(capability, path, artifact, int(settings["timeout_seconds"]), int(settings["stream_limit_bytes"]))
            stdout, stderr = bytes(raw.get("stdout", b"")), bytes(raw.get("stderr", b""))
            exit_code, timed_out = raw.get("exit_code"), bool(raw.get("timed_out", False))
            supplied = raw.get("observation")
            observation = (supplied if isinstance(supplied, Mapping) else
                           ADAPTERS[capability].parse(stdout))
            tool_identity = raw.get("tool_identity", tool_identity)
            receipt_value = raw.get("execution_receipt")
            execution_receipt = receipt_value if isinstance(receipt_value, Mapping) else None
            if resolved_tool_identity and dict(tool_identity) != dict(resolved_tool_identity):
                raise FrameworkIntegrityError("executed scanner identity differs from fingerprinted identity")
            if timed_out: gaps.append(f"{capability} scanner timed out")
            elif exit_code not in ADAPTERS[capability].accepted_exit_codes:
                gaps.append(f"{capability} scanner exited {exit_code}")
            if raw.get("truncated"): gaps.append(f"{capability} scanner output was truncated")
    except FrameworkIntegrityError:
        raise
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        exit_code = None
        gaps.append(f"{capability} scanner parse or execution failure: {type(exc).__name__}: {exc}")
        stderr = str(exc).encode("utf-8", errors="replace")
    stream_limit, tail = int(settings["stream_limit_bytes"]), int(settings["diagnostic_tail_bytes"])
    stdout_identity = _stream(unit, root, "stdout.bin", stdout, stream_limit, tail)
    stderr_identity = _stream(unit, root, "stderr.bin", stderr, stream_limit, tail)
    result = {"schema": OBSERVATION_SCHEMA, "fingerprint": fingerprint,
        "artifact_id": artifact["artifact_id"], "artifact": {key: artifact.get(key) for key in
            ("path", "workspace_path", "sha256", "size_bytes", "kind", "build_unit_id", "canonical_identity")},
        "classification": classification, "capability": capability, "scanner_identity": scanner_identity,
        "tool_identity": tool_identity, "parser_identity": PARSER_IDENTITY,
        "normalizer_identity": NORMALIZER_IDENTITY, "attempt_identity": hashlib.sha256(canonical_json({
            "run": unit.job.run_id, "attempt": unit.job.attempt_id, "artifact": artifact["artifact_id"],
            "capability": capability})).hexdigest(),
        "observation": observation, "gaps": gaps, "exit_code": exit_code, "timed_out": timed_out,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "raw_artifacts": [stdout_identity, stderr_identity], "execution_receipt": execution_receipt,
        "reused": False,
        "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(checkpoint, result)
    return result


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("artifact-security topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"artifact-security task order mismatch: {step}")
    required = {"timeout_seconds", "stream_limit_bytes", "diagnostic_tail_bytes", "archive_member_limit",
                "archive_expanded_bytes", "archive_member_bytes", "archive_ratio_limit", "archive_depth_limit",
                "scanner_identities"}
    if not required <= set(context.config.settings):
        raise ValueError("artifact-security settings are incomplete")
    if any(type(context.config.settings[key]) is not int or context.config.settings[key] < 1
           for key in required - {"scanner_identities"}):
        raise ValueError("artifact-security bounds must be positive integers")
    if not isinstance(context.config.settings["scanner_identities"], Mapping):
        raise ValueError("artifact-security scanner identities must be a table")


def load_accepted_artifact_security_analysis(run_root: Path) -> Mapping[str, Any]:
    pointer_path = run_root / "data" / "jobs" / "job_artifact_security_analysis" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted artifact-security-analysis handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = json.loads(_safe_file(run_root, {"path": pointer.get("handoff_path"),
                                              "sha256": pointer.get("handoff_sha256")}).read_text(encoding="utf-8"))
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or handoff.get("job_id") != "job_artifact_security_analysis":
        raise ValueError("artifact-security-analysis handoff is not accepted")
    identity = handoff.get("outputs", {}).get("acceptance.publish_handoff", {}).get("artifact")
    if not isinstance(identity, Mapping): raise ValueError("artifact-security publication is unavailable")
    if not any(item.get("path") == identity.get("path") and item.get("sha256") == identity.get("sha256")
               for item in handoff.get("artifacts", ())):
        raise FrameworkIntegrityError("artifact-security publication is not bound to its handoff")
    document = json.loads(_safe_file(run_root, identity).read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA: raise ValueError("artifact-security publication schema is unsupported")
    return {**document, "handoff_sha256": pointer["handoff_sha256"]}


def build_job(*, scanner_runner: ScannerRunner | None = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted = _accepted_artifacts(unit.job.run_root)
        if accepted["source_fingerprint"] != unit.job.source_fingerprint:
            raise FrameworkIntegrityError("artifact-security target snapshot differs from language-build")
        return {**accepted, "artifact_count": len(accepted["artifacts"]), "terminal_status": "SUCCEEDED"}

    def analyze(capability: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            loaded = unit.output("load.accepted_artifacts")
            if capability == "grype" and unit.job.tools.disable_grype:
                gap = "Grype artifact coverage was configured disabled by tools.disable_grype"
                unit.job.events.write("TOOL_CONFIGURED_DISABLED", unit_id=unit.unit_id,
                                      tool_id="tool-grype", disposition="CONFIGURED_DISABLED",
                                      gap_count=1, gaps=[gap], checkpoint_reused=False)
                return {"capability": capability, "observations": [], "observation_count": 0,
                        "gaps": [gap], "coverage_disposition": "CONFIGURED_DISABLED",
                        "terminal_status": "NOT_APPLICABLE"}
            effective_runner = scanner_runner or (ContainerScannerRunner(
                unit.job.repository_root, unit.job.run_root, unit.unit_root) if capability in ADAPTERS else None)
            observations, gaps = [], []
            for artifact in loaded["artifacts"]:
                path = _safe_file(unit.job.run_root, artifact)
                classification = classify(path, artifact)
                if not _applicable(capability, classification):
                    continue
                result = _scan_one(unit, artifact, capability, effective_runner)
                observations.append(result)
                gaps.extend(f"{artifact['artifact_id']}: {gap}" for gap in result["gaps"])
            return {"capability": capability, "observations": observations,
                    "observation_count": len(observations), "gaps": gaps,
                    "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED" if observations else "NOT_APPLICABLE"}
        return handler

    def index(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_artifacts")
        observations = [row for capability in CAPABILITIES
                        for row in unit.output(f"analyze.{capability}")["observations"]]
        producer = [{"sha256": item["fingerprint"]} for item in observations]
        fingerprint = index_fingerprint(name="observations", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=producer, tool_identity={"job": "job_artifact_security_analysis"},
            parser_identity=PARSER_IDENTITY, normalizer_identity=NORMALIZER_IDENTITY,
            mapping_identity="exact-run-artifact/1", upstream_manifests=[loaded["artifact_index"]["sha256"]])
        path = unit.job.run_root / "data" / "indices" / "observations" / f"artifact-security-{fingerprint}.sqlite"
        gaps = [gap for capability in CAPABILITIES for gap in unit.output(f"analyze.{capability}")["gaps"]]
        if not path.is_file():
            builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id="artifact-security")
            artifact_entities: dict[str, str] = {}
            for row in observations:
                artifact = row["artifact"]
                artifact_id = LogicalIdentity.parse(str(artifact["canonical_identity"]))
                if artifact_id.value not in artifact_entities:
                    artifact_entities[artifact_id.value] = artifact_id.value
                    builder.add_entity(EntityRecord(artifact_id, artifact["sha256"],
                        PurePosixPath(str(artifact.get("workspace_path") or artifact["path"])).name,
                        f"produced artifact {row['classification']['format']}", artifact))
                observation_id = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, unit.job.source_fingerprint,
                    {"fingerprint": row["fingerprint"]})
                builder.add_entity(EntityRecord(observation_id, row["fingerprint"], row["capability"],
                    f"{row['capability']} observation for {row['classification']['format']}",
                    {key: row[key] for key in ("artifact", "classification", "capability", "scanner_identity",
                                                "tool_identity", "observation", "gaps", "raw_artifacts",
                                                "attempt_identity", "exit_code", "timed_out", "duration_ms")} |
                    {"evidence_identities": [{"relative_path": raw["path"], "sha256": raw["sha256"],
                        "byte_count": raw["byte_count"], "captured_bytes": raw["captured_bytes"],
                        "truncated": raw["truncated"]} for raw in row["raw_artifacts"]],
                     "execution_receipt_identity": row.get("execution_receipt")}))
                builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, observation_id.value,
                                                     artifact_id.value, True, 1.0))
            builder.add_coverage("produced-artifact-security", "partial" if gaps else "complete",
                                 gaps[0] if gaps else None)
            sha = builder.build()
        else:
            sha = file_sha256(path)
        identity = IndexIdentity("observations", INDEX_SCHEMA, sha, fingerprint,
            path.relative_to(unit.job.run_root).as_posix(), {"job": "job_artifact_security_analysis"},
            tuple(gaps[:1000]), "artifact-security")
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"artifact-security-{fingerprint}.json"
        if not manifest_path.is_file():
            write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                target_root=unit.job.target_root or unit.job.repository_root, indexes=[identity],
                upstream_manifests=[loaded["artifact_index"]])
        manifest = _identity(unit.job.run_root, manifest_path)
        load_verified_manifest(unit.job.run_root, manifest_path, manifest["sha256"])
        return {"index_identity": asdict(identity), "index_manifest": manifest,
                "observation_count": len(observations), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, indexed = unit.output("load.accepted_artifacts"), unit.output("index.observations")
        capabilities = {capability: {key: unit.output(f"analyze.{capability}")[key]
                        for key in ("observation_count", "gaps", "terminal_status")} for capability in CAPABILITIES}
        document = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
            "language_build_handoff_sha256": loaded["language_build_handoff_sha256"],
            "artifact_index": loaded["artifact_index"], "artifact_count": loaded["artifact_count"],
            "observation_count": indexed["observation_count"], "capabilities": capabilities,
            "producer_gaps": loaded["producer_gaps"], "gaps": indexed["gaps"],
            "index_manifest": indexed["index_manifest"]}
        path = unit.job.attempt_root / "artifacts" / "artifact-security" / "accepted-analysis.json"
        atomic_json(path, document)
        return {"artifact": _identity(unit.job.run_root, path), "index_manifest": indexed["index_manifest"],
                "artifact_count": loaded["artifact_count"], "observation_count": indexed["observation_count"],
                "gaps": indexed["gaps"], "terminal_status": "COMPLETED_WITH_GAPS" if indexed["gaps"] else "SUCCEEDED"}

    analyze_units = tuple(Unit(f"analyze.{capability}", analyze(capability), ("load.accepted_artifacts",))
                          for capability in CAPABILITIES)
    index_dependencies = tuple(f"analyze.{capability}" for capability in CAPABILITIES)
    units = (Unit("load.accepted_artifacts", load), *analyze_units,
             Unit("index.observations", index, index_dependencies),
             Unit("acceptance.publish_handoff", publish, ("index.observations",)))
    implementation = hashlib.sha256(Path(__file__).read_bytes() + Path(__file__).with_name("formats.py").read_bytes() +
                                    Path(__file__).with_name("scanners.py").read_bytes()).hexdigest()
    return Job("job_artifact_security_analysis", "artifact_security_analysis", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation, units=units)
