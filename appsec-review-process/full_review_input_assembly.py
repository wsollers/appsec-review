#!/usr/bin/env python3
"""Derive, assemble, and dispatch exact full-review analysis requests.

The derivation seam starts with the accepted component map.  It only selects analyses justified by
that map and by input classes actually present in the immutable run; absent classes are retained as
explicit ``SKIPPED_NA`` rows.  Assembly and dispatch remain separate callable seams so orchestration
can inspect the hash-bound request bundle before invoking any worker.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

import bounded_transform_orchestration
from bounded_analysis_workers import load_accepted
from bounded_transform_orchestration import REQUEST_SCHEMA as BOUNDED_SCHEMA, FACADES
from dependency_orchestration import (REQUEST_SCHEMA as DEPENDENCY_SCHEMA,
                                      JOBS as DEPENDENCY_JOBS, _PAYLOAD_KEYS, _TOOL_KEYS)
from execution_state import Blocked, atomic_json, digest, file_hash, identifier, read_json, tree_hashes
import intake
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from vendor_evidence_orchestration import REQUEST_SCHEMA as VENDOR_SCHEMA, WORKERS
import vendor_evidence_orchestration
import dependency_orchestration
from worker_result import artifact_records, terminal_envelope, validate_worker_result

JOB = "02-full-review-input-assembly"
CONTRACT = "full-review-input-assembly"
RESULT = "full-review-input-assembly.json"
PLAN_SCHEMA = "appsec-review/full-review-input-plan/1.0"
RESULT_SCHEMA = "appsec-review/full-review-input-assembly/1.0"
HASH = "sha256:"

_PLAN_KEYS = {"schema", "run_id", "source_generation", "generated_at", "accepted_sources", "launches"}
_SOURCE_KEYS = {"alias", "pointer_path", "job_id", "contract", "artifact", "artifact_schema",
                "generation_pointer"}
_LAUNCH_KEYS = {
    "bounded": {"adapter", "job_id", "upstream", "payload"},
    "vendor": {"adapter", "job_id", "source_root"},
    "dependency": {"adapter", "job_id", "payload", "tool"},
}

COMPONENT_SOURCE = {
    "job_id": "01-component-characterization", "contract": "component-map",
    "artifact": "component-purpose-map.json", "artifact_schema": "component-purpose-map.schema.json",
    "generation_pointer": "/source_snapshot_sha256",
}
NATIVE_SUFFIXES = {".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
                   ".m": "objective-c", ".mm": "objective-cpp"}
MOBILE_MARKERS = {"androidmanifest.xml", "build.gradle", "build.gradle.kts", "info.plist",
                  "podfile", "project.pbxproj"}
DEPENDENCY_SOURCES = {
    "02-sbom-inventory": ("sbom-inventory", "outputs/sbom-manifest.json", "sbom-inventory.schema.json"),
    "02-sca-vulnerability-match": ("sca-vulnerability-match", "outputs/sca-vulnerability-match.json",
                                    "sca-vulnerability-match.schema.json"),
    "02-license-scan": ("license-inventory", "outputs/license-inventory.json", "license-inventory.schema.json"),
}


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise Blocked(f"full review input assembly: {label} shape is not closed")
    return value


def _relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise Blocked(f"full review input assembly: {label} must be a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked(f"full review input assembly: {label} must be a normalized relative path")
    return path


def _owned(run_root: Path, value: Any, label: str, *, kind: str | None = None) -> Path:
    relative = _relative(value, label)
    candidate = run_root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(run_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"full review input assembly: {label} is not a run-owned path") from exc
    if candidate.is_symlink() or (kind == "file" and not candidate.is_file()) or (
            kind == "directory" and not candidate.is_dir()):
        raise Blocked(f"full review input assembly: {label} has the wrong path kind")
    return candidate.absolute()


def _pointer(document: Any, pointer: Any, label: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise Blocked(f"full review input assembly: {label} must be an absolute JSON pointer")
    current = document
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise Blocked(f"full review input assembly: {label} does not resolve")
    return current


def _source_files(root: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise Blocked("full review input assembly: source tree contains a symbolic link")
        if path.is_file():
            rows[path.relative_to(root).as_posix()] = HASH + file_hash(path)
    return rows


def _resolve(value: Any, *, run_root: Path, sources: dict[str, dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_resolve(item, run_root=run_root, sources=sources) for item in value]
    if not isinstance(value, dict):
        return value
    keys = set(value)
    if keys == {"$accepted", "pointer"}:
        alias = value["$accepted"]
        if alias not in sources:
            raise Blocked("full review input assembly: accepted source alias is unknown")
        return _resolve(_pointer(sources[alias]["document"], value["pointer"], f"{alias} value"),
                        run_root=run_root, sources=sources)
    if keys == {"$metadata", "field"}:
        alias, field = value["$metadata"], value["field"]
        if alias not in sources or field not in sources[alias]["binding"]:
            raise Blocked("full review input assembly: accepted metadata reference is unknown")
        return sources[alias]["binding"][field]
    if keys == {"$binding"}:
        alias = value["$binding"]
        if alias not in sources:
            raise Blocked("full review input assembly: binding source alias is unknown")
        source, binding = sources[alias], sources[alias]["binding"]
        artifact_path = source["pointer"].parent / "attempts" / binding["attempt_id"] / binding["artifact_path"]
        return {"attempt_id": binding["attempt_id"], "path": str(artifact_path.absolute()),
                "sha256": binding["artifact_sha256"], "accepted_path": str(source["pointer"].absolute())}
    if keys == {"$run_path", "kind"}:
        if value["kind"] not in {"file", "directory"}:
            raise Blocked("full review input assembly: run path kind is invalid")
        return str(_owned(run_root, value["$run_path"], "resolved run path", kind=value["kind"]))
    if keys == {"$source_files"}:
        root = _owned(run_root, value["$source_files"], "source file root", kind="directory")
        return _source_files(root)
    if any(isinstance(key, str) and key.startswith("$") for key in keys):
        raise Blocked("full review input assembly: resolver expression is not closed")
    return {key: _resolve(item, run_root=run_root, sources=sources) for key, item in value.items()}


def _referenced_aliases(value: Any) -> set[str]:
    if isinstance(value, list):
        return set().union(*(_referenced_aliases(item) for item in value), set())
    if not isinstance(value, dict):
        return set()
    aliases = {value[key] for key in ("$accepted", "$metadata", "$binding")
               if key in value and isinstance(value[key], str)}
    return aliases | set().union(*(_referenced_aliases(item) for item in value.values()), set())


def _component_source_current(document: dict[str, Any], run_root: Path) -> None:
    """Bind the component map to the current target rather than conflating two generations.

    Component characterization records the checkout fingerprint.  Adapter requests intentionally
    record the artifact-manifest hash.  Both are required and they are not interchangeable.
    """
    manifest = read_json(run_root / "inputs/artifact-manifest.json")
    target = manifest.get("target") if isinstance(manifest, dict) else None
    value = target.get("repo_path") if isinstance(target, dict) else None
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked("full review input assembly: manifest target is unavailable")
    identity = intake.source_identity(str(path.resolve()))
    if document.get("source_snapshot_sha256") != HASH + identity["fingerprint"]:
        raise Blocked("full review input assembly: component map is stale for the staged target")


def _load_dependency_source(pointer: Path, *, run_id: str, spec: dict[str, Any]
                            ) -> tuple[dict[str, Any], dict[str, Any]]:
    """Revalidate the dependency worker's older accepted-pointer dialect without trusting it."""
    accepted = read_json(pointer)
    required = {"schema", "run_id", "job", "attempt_id", "status", "fingerprint",
                "envelope_path", "envelope_sha256"}
    if (not isinstance(accepted, dict) or set(accepted) != required or
            accepted.get("schema") != ACCEPTED_SCHEMA or accepted.get("run_id") != run_id or
            accepted.get("job") != spec["job_id"] or accepted.get("status") not in {"OK", "OK_WITH_GAPS"} or
            accepted.get("envelope_path") != "result.json"):
        raise Blocked("full review input assembly: dependency accepted pointer is invalid")
    attempt = pointer.parent / "attempts" / identifier(accepted["attempt_id"])
    envelope_path = attempt / "result.json"
    if (attempt.is_symlink() or not attempt.is_dir() or envelope_path.is_symlink() or
            not envelope_path.is_file() or file_hash(envelope_path) != accepted["envelope_sha256"]):
        raise Blocked("full review input assembly: dependency accepted attempt changed")
    envelope = read_json(envelope_path)
    if (validate_worker_result(envelope) or envelope.get("run_id") != run_id or
            envelope.get("job_id") != spec["job_id"] or envelope.get("attempt_id") != accepted["attempt_id"] or
            envelope.get("input_fingerprint") != accepted["fingerprint"] or
            envelope.get("output_contract") != spec["contract"] or envelope.get("acceptance_status") != "CURRENT"):
        raise Blocked("full review input assembly: dependency accepted envelope is invalid")
    artifacts = {row.get("path"): row for row in envelope.get("artifacts", []) if isinstance(row, dict)}
    artifact = spec["artifact"]
    if artifact not in artifacts or len(artifacts) != len(envelope.get("artifacts", [])):
        raise Blocked("full review input assembly: dependency accepted artifact is absent")
    for relative, row in artifacts.items():
        path = attempt.joinpath(*PurePosixPath(relative).parts)
        try:
            path.resolve(strict=True).relative_to(attempt.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise Blocked("full review input assembly: dependency artifact escapes attempt") from exc
        if path.is_symlink() or not path.is_file() or file_hash(path) != row.get("sha256"):
            raise Blocked("full review input assembly: dependency artifact changed")
    document = read_json(attempt / artifact)
    errors = validate_document(document, spec["artifact_schema"])
    if errors:
        raise Blocked("full review input assembly: dependency artifact schema failed: " + errors[0])
    return document, {"job_id": spec["job_id"], "attempt_id": accepted["attempt_id"],
        "artifact_path": artifact, "artifact_sha256": HASH + file_hash(attempt / artifact),
        "accepted_pointer_sha256": HASH + file_hash(pointer)}


def _component_citation(component: dict[str, Any], index: int, target: Path) -> tuple[str, dict[str, Any]]:
    locations = component.get("representative_locations")
    relative = locations[0] if isinstance(locations, list) and locations else ""
    source = target / relative
    if (not relative or source.is_symlink() or not source.is_file() or
            source.resolve().parent != target.resolve() and target.resolve() not in source.resolve().parents):
        raise Blocked("full review input assembly: component representative source is unavailable")
    source_sha = HASH + file_hash(source)
    citation = {
        "citation_id": "component-" + digest({"component": component["component_id"],
                                                "path": relative, "sha256": source_sha})[:20],
        "artifact_path": relative, "artifact_sha256": source_sha,
        "locator": relative, "observed_fact": {
            "$accepted": "component-map", "pointer": f"/functional_components/{index}/observed_purpose"},
    }
    return source_sha, citation


def derive_plan(component_pointer: Path, run_root: Path, plan_path: Path, *, run_id: str,
                generated_at: str) -> dict[str, Any]:
    """Derive the applicable first-wave plan from the accepted component map and staged inputs."""
    run_root, component_pointer, plan_path = Path(run_root), Path(component_pointer), Path(plan_path)
    identifier(run_id)
    try:
        component_pointer.resolve(strict=True).relative_to(run_root.resolve(strict=True))
        plan_path.resolve(strict=False).relative_to(run_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked("full review input assembly: derivation paths must be run-owned") from exc
    document, _ = load_accepted(component_pointer, run_id=run_id, **{
        key: COMPONENT_SOURCE[key] for key in ("job_id", "contract", "artifact")},
        schema=COMPONENT_SOURCE["artifact_schema"])
    _component_source_current(document, run_root)
    manifest = run_root / "inputs/artifact-manifest.json"
    generation = HASH + file_hash(manifest)
    target_value = read_json(manifest).get("target", {}).get("repo_path")
    target = Path(target_value).resolve()
    try:
        target_relative = target.relative_to(run_root.resolve()).as_posix()
    except ValueError as exc:
        raise Blocked("full review input assembly: staged target must be run-owned for dispatch") from exc
    source_spec = {"alias": "component-map",
        "pointer_path": component_pointer.relative_to(run_root).as_posix(), **COMPONENT_SOURCE}
    source_specs = [source_spec]
    available: dict[str, str] = {}
    for job_id, (contract, artifact, artifact_schema) in DEPENDENCY_SOURCES.items():
        pointer = run_root / "data/jobs" / job_id / "accepted.json"
        if not pointer.is_file() or pointer.is_symlink():
            continue
        alias = {"02-sbom-inventory": "sbom", "02-sca-vulnerability-match": "sca",
                 "02-license-scan": "license"}[job_id]
        spec = {"alias": alias, "pointer_path": pointer.relative_to(run_root).as_posix(),
                "job_id": job_id, "contract": contract, "artifact": artifact,
                "artifact_schema": artifact_schema, "generation_pointer": "/source_snapshot_sha256"}
        document_value, _ = _load_dependency_source(pointer, run_id=run_id, spec=spec)
        if document_value.get("source_snapshot_sha256") != generation:
            raise Blocked("full review input assembly: current dependency source has mixed generation")
        source_specs.append(spec)
        available[job_id] = alias
    launches: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    native_units, fuzz_targets = [], []
    for index, component in enumerate(document["functional_components"]):
        locations = component.get("representative_locations", [])
        relative = locations[0] if locations else ""
        suffix = Path(relative).suffix.lower()
        lanes = set(component.get("downstream_lanes", []))
        if suffix in NATIVE_SUFFIXES and ("05-native-memory" in lanes or "02-native-build" in lanes):
            source_sha, citation = _component_citation(component, index, target)
            native_units.append({"unit_id": component["component_id"], "language": NATIVE_SUFFIXES[suffix],
                "path": relative, "source_sha256": source_sha, "signals": [],
                "coverage": ["component-routed-static-triage"], "citations": [citation]})
        if "13-fuzz-target-triage" in lanes:
            fuzz_targets.append({"target_id": "component-" + component["component_id"],
                "component_id": component["component_id"],
                "entrypoint": component.get("search_terms", ["unknown"])[0], "input_model": "unknown",
                "buildable": False, "deterministic": False, "isolation": "unknown",
                "blockers": ["entrypoint and harness feasibility require independent confirmation"],
                "citation_ids": [{"$accepted": "component-map",
                                  "pointer": f"/functional_components/{index}/component_id"}]})
    if native_units:
        launches.append({"adapter": "bounded", "job_id": "05-native-memory",
                         "upstream": ["component-map"], "payload": {"units": native_units}})
    else:
        skipped.append({"job_id": "05-native-memory", "status": "SKIPPED_NA",
                        "reason": "component map contains no routed native source unit"})
    if fuzz_targets:
        launches.append({"adapter": "bounded", "job_id": "13-fuzz-target-triage",
                         "upstream": ["component-map"], "payload": {"targets": fuzz_targets}})
    else:
        skipped.append({"job_id": "13-fuzz-target-triage", "status": "SKIPPED_NA",
                        "reason": "component map routes no component to fuzz-target triage"})

    launches.append({"adapter": "vendor", "job_id": "02-secrets-inventory",
                     "source_root": {"$run_path": target_relative, "kind": "directory"}})
    names = {path.name.lower() for path in target.rglob("*") if path.is_file() and not path.is_symlink()}
    iac_present = any(path.suffix.lower() in {".tf", ".tfvars"} or
                      (path.suffix.lower() in {".yaml", ".yml"} and
                       any(token in path.as_posix().lower() for token in ("deploy", "k8s", "helm", "terraform")))
                      for path in target.rglob("*") if path.is_file() and not path.is_symlink())
    if iac_present:
        launches.append({"adapter": "vendor", "job_id": "02-iac-config-scan",
                         "source_root": {"$run_path": target_relative, "kind": "directory"}})
    else:
        skipped.append({"job_id": "02-iac-config-scan", "status": "SKIPPED_NA",
                        "reason": "no IaC input class is present in the staged target"})
    if names & MOBILE_MARKERS:
        launches.append({"adapter": "vendor", "job_id": "02-mobile-sast",
                         "source_root": {"$run_path": target_relative, "kind": "directory"}})
    else:
        skipped.append({"job_id": "02-mobile-sast", "status": "SKIPPED_NA",
                        "reason": "no mobile project marker is present in the staged target"})
    if any(path.name == "index.json" or path.suffix.lower() in {".tar", ".oci"}
           for path in (run_root / "inputs").rglob("*") if path.is_file() and not path.is_symlink()):
        launches.append({"adapter": "vendor", "job_id": "02-container-image-inventory",
                         "source_root": {"$run_path": "inputs", "kind": "directory"}})
    else:
        skipped.append({"job_id": "02-container-image-inventory", "status": "SKIPPED_NA",
                        "reason": "no container image or OCI layout is staged"})
    if "02-sbom-inventory" not in available:
        launches.append({"adapter": "dependency", "job_id": "02-sbom-inventory",
                         "payload": {"source_files": {"$source_files": target_relative}},
                         "tool": {"target_path": {"$run_path": target_relative, "kind": "directory"}}})
        skipped.extend([
            {"job_id": "02-sca-vulnerability-match", "status": "SKIPPED_NA",
             "reason": "requires the accepted SBOM produced by this first-wave dispatch"},
            {"job_id": "02-license-scan", "status": "SKIPPED_NA",
             "reason": "requires the accepted SBOM produced by this first-wave dispatch"},
        ])
    else:
        sbom_binding = {"$binding": "sbom"}
        if "02-license-scan" not in available:
            launches.append({"adapter": "dependency", "job_id": "02-license-scan",
                             "payload": {"sbom": sbom_binding, "source_files": {"$source_files": target_relative}},
                             "tool": {"target_path": {"$run_path": target_relative, "kind": "directory"}}})
        registry = os.environ.get("APPSEC_REVIEW_VULN_SNAPSHOT_REGISTRY")
        max_age = os.environ.get("APPSEC_REVIEW_VULN_MAX_AGE_SECONDS")
        if "02-sca-vulnerability-match" in available:
            pass
        elif registry and max_age and max_age.isdigit() and Path(registry).is_absolute() and Path(registry).is_dir():
            _, sbom_accepted = _load_dependency_source(
                run_root / "data/jobs/02-sbom-inventory/accepted.json", run_id=run_id,
                spec=next(spec for spec in source_specs if spec["alias"] == "sbom"))
            sbom_path = (run_root / "data/jobs/02-sbom-inventory/attempts" /
                         sbom_accepted["attempt_id"] /
                         "outputs/sbom-manifest.json")
            launches.append({"adapter": "dependency", "job_id": "02-sca-vulnerability-match",
                             "payload": {"sbom": sbom_binding},
                             "tool": {"sbom_root": str(sbom_path.parent), "snapshot_registry": registry,
                                      "max_database_age_seconds": int(max_age)}})
        else:
            skipped.append({"job_id": "02-sca-vulnerability-match", "status": "SKIPPED_NA",
                            "reason": "offline snapshot registry and explicit age ceiling are not configured"})
    lifecycle_reference = run_root / "inputs/dependency-lifecycle-reference-table.json"
    reference_age = os.environ.get("APPSEC_REVIEW_LIFECYCLE_MAX_AGE_DAYS")
    if ("02-sbom-inventory" in available and "02-license-scan" in available and
            lifecycle_reference.is_file() and not lifecycle_reference.is_symlink() and
            reference_age and reference_age.isdigit()):
        launches.append({"adapter": "dependency", "job_id": "02-dependency-lifecycle",
            "payload": {"sbom": {"$binding": "sbom"}, "license": {"$binding": "license"},
                        "reference_table": {"$run_path": "inputs/dependency-lifecycle-reference-table.json",
                                            "kind": "file"},
                        "reference_table_sha256": HASH + file_hash(lifecycle_reference),
                        "max_reference_age_days": int(reference_age)}, "tool": {}})
    else:
        skipped.append({"job_id": "02-dependency-lifecycle", "status": "SKIPPED_NA",
                        "reason": "requires accepted SBOM, license, staged lifecycle reference, and explicit age ceiling"})
    reachability_evidence = run_root / "inputs/cve-reachability-evidence.json"
    if ("02-sca-vulnerability-match" in available and reachability_evidence.is_file() and
            not reachability_evidence.is_symlink()):
        launches.append({"adapter": "dependency", "job_id": "06-cve-reachability",
            "payload": {"sca": {"$binding": "sca"},
                        "reachability_evidence": {"$run_path": "inputs/cve-reachability-evidence.json",
                                                  "kind": "file"},
                        "reachability_evidence_sha256": HASH + file_hash(reachability_evidence)}, "tool": {}})
    else:
        skipped.append({"job_id": "06-cve-reachability", "status": "SKIPPED_NA",
                        "reason": "requires accepted SCA and staged reachability evidence"})
    skipped.append({"job_id": "02-binary-hardening", "status": "SKIPPED_NA",
                    "reason": "requires an accepted built-binary projection"})
    plan = {"schema": PLAN_SCHEMA, "run_id": run_id, "source_generation": generation,
            "generated_at": generated_at, "accepted_sources": source_specs,
            "launches": sorted(launches, key=lambda row: row["job_id"]),
            "skipped": sorted(skipped, key=lambda row: row["job_id"])}
    errors = validate_document(plan, "full-review-input-plan.schema.json")
    if errors:
        raise Blocked("full review input assembly: derived plan schema failed: " + errors[0])
    if plan_path.exists() or plan_path.is_symlink():
        raise Blocked("full review input assembly: derived plan path already exists")
    atomic_json(plan_path, plan)
    return plan


def _load_sources(plan: dict[str, Any], run_root: Path) -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for raw in plan["accepted_sources"]:
        source = _closed(raw, _SOURCE_KEYS, "accepted source")
        alias = source["alias"]
        if not isinstance(alias, str) or not alias or alias in sources:
            raise Blocked("full review input assembly: accepted source aliases must be unique")
        pointer = _owned(run_root, source["pointer_path"], f"{alias} accepted pointer", kind="file")
        if source["job_id"] in DEPENDENCY_SOURCES:
            document, binding = _load_dependency_source(pointer, run_id=plan["run_id"], spec=source)
        else:
            document, binding = load_accepted(pointer, run_id=plan["run_id"], job_id=source["job_id"],
                contract=source["contract"], artifact=source["artifact"], schema=source["artifact_schema"])
        if source["job_id"] == COMPONENT_SOURCE["job_id"]:
            _component_source_current(document, run_root)
        elif _pointer(document, source["generation_pointer"], f"{alias} source generation") != plan["source_generation"]:
            raise Blocked("full review input assembly: accepted sources contain a stale or mixed generation")
        sources[alias] = {"document": document, "binding": binding, "pointer": pointer, "spec": source}
    return sources


def _bounded(raw: dict[str, Any], plan: dict[str, Any], sources: dict[str, dict[str, Any]], run_root: Path) -> dict[str, Any]:
    job = raw["job_id"]
    if job not in FACADES or not isinstance(raw["upstream"], list) or not raw["upstream"]:
        raise Blocked("full review input assembly: bounded launch job or upstream is invalid")
    upstream = []
    for alias in raw["upstream"]:
        if alias not in sources:
            raise Blocked("full review input assembly: bounded upstream alias is unknown")
        source = sources[alias]
        spec = source["spec"]
        upstream.append({"pointer_path": str(source["pointer"].absolute()), "job_id": spec["job_id"],
                         "contract": spec["contract"], "artifact": spec["artifact"],
                         "schema": spec["artifact_schema"]})
    payload = _resolve(raw["payload"], run_root=run_root, sources=sources)
    payload_aliases = _referenced_aliases(raw["payload"])
    if not payload_aliases or not payload_aliases.issubset(set(raw["upstream"])):
        raise Blocked("full review input assembly: bounded payload must derive from its accepted upstream")
    expected_key = FACADES[job][2]
    if not isinstance(payload, dict) or set(payload) != {expected_key} or not isinstance(payload[expected_key], list):
        raise Blocked(f"full review input assembly: bounded payload must contain only {expected_key}")
    return {"schema": BOUNDED_SCHEMA, "run_id": plan["run_id"], "job_id": job,
            "source_generation": plan["source_generation"], "upstream": upstream, "payload": payload}


def _vendor(raw: dict[str, Any], plan: dict[str, Any], sources: dict[str, dict[str, Any]], run_root: Path) -> dict[str, Any]:
    job = raw["job_id"]
    if job not in WORKERS:
        raise Blocked("full review input assembly: vendor launch job is invalid")
    source_root = _resolve(raw["source_root"], run_root=run_root, sources=sources)
    if not isinstance(source_root, str):
        raise Blocked("full review input assembly: vendor source root did not resolve to a path")
    return {"schema": VENDOR_SCHEMA, "run_id": plan["run_id"], "job_id": job,
            "source_generation": plan["source_generation"], "generated_at": plan["generated_at"],
            "source_root": source_root}


def _dependency(raw: dict[str, Any], plan: dict[str, Any], sources: dict[str, dict[str, Any]], run_root: Path) -> dict[str, Any]:
    job = raw["job_id"]
    if job not in DEPENDENCY_JOBS:
        raise Blocked("full review input assembly: dependency launch job is invalid")
    kind = DEPENDENCY_JOBS[job]
    if kind != "sbom" and not _referenced_aliases(raw["payload"]):
        raise Blocked("full review input assembly: downstream dependency payload must bind accepted evidence")
    payload = _resolve(raw["payload"], run_root=run_root, sources=sources)
    tool = _resolve(raw["tool"], run_root=run_root, sources=sources)
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS[kind]:
        raise Blocked("full review input assembly: dependency payload shape is not closed")
    if not isinstance(tool, dict) or set(tool) != _TOOL_KEYS[kind]:
        raise Blocked("full review input assembly: dependency tool shape is not closed")
    return {"schema": DEPENDENCY_SCHEMA, "run_id": plan["run_id"], "job_id": job,
            "source_generation": plan["source_generation"], "generated_at": plan["generated_at"],
            "payload": payload, "tool": tool}


def assemble(plan_path: Path, run_root: Path, output_root: Path, *, attempt_id: str,
             started_at: str, finished_at: str) -> dict[str, Any]:
    """Build and accept one immutable bundle of exact orchestration requests."""
    run_root, output_root, plan_path = Path(run_root), Path(output_root), Path(plan_path)
    if not run_root.is_absolute() or not run_root.is_dir() or run_root.is_symlink():
        raise Blocked("full review input assembly: run root must be an absolute real directory")
    try:
        plan_path.resolve(strict=True).relative_to(run_root.resolve(strict=True))
        output_root.resolve(strict=False).relative_to(run_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked("full review input assembly: plan and output must be run-owned") from exc
    if plan_path.is_symlink() or not plan_path.is_file() or output_root.is_symlink():
        raise Blocked("full review input assembly: plan or output path is unsafe")
    plan = read_json(plan_path)
    if not isinstance(plan, dict) or set(plan) not in (_PLAN_KEYS, _PLAN_KEYS | {"skipped"}):
        raise Blocked("full review input assembly: plan shape is not closed")
    if plan["schema"] != PLAN_SCHEMA or not isinstance(plan["accepted_sources"], list) or not isinstance(plan["launches"], list):
        raise Blocked("full review input assembly: plan identity or collections are invalid")
    identifier(plan["run_id"])
    identifier(attempt_id)
    plan_errors = validate_document(plan, "full-review-input-plan.schema.json")
    if plan_errors:
        raise Blocked("full review input assembly: plan schema failed: " + plan_errors[0])
    manifest = _owned(run_root, "inputs/artifact-manifest.json", "artifact manifest", kind="file")
    generation = HASH + file_hash(manifest)
    if plan["source_generation"] != generation:
        raise Blocked("full review input assembly: plan source generation is stale")
    sources = _load_sources(plan, run_root)
    attempt = output_root / "attempts" / attempt_id
    fingerprint = HASH + digest({"plan": plan, "source_bindings": {key: row["binding"] for key, row in sources.items()}})
    if attempt.exists():
        raise Blocked("full review input assembly: immutable attempt already exists")
    (attempt / "requests").mkdir(parents=True)
    builders = {"bounded": _bounded, "vendor": _vendor, "dependency": _dependency}
    request_rows, paths, seen = [], [], set()
    for raw in plan["launches"]:
        if not isinstance(raw, dict) or raw.get("adapter") not in _LAUNCH_KEYS:
            raise Blocked("full review input assembly: launch adapter is invalid")
        adapter = raw["adapter"]
        _closed(raw, _LAUNCH_KEYS[adapter], "launch")
        job = raw["job_id"]
        if not isinstance(job, str) or job in seen:
            raise Blocked("full review input assembly: launch job identities must be unique")
        seen.add(job)
        request = builders[adapter](raw, plan, sources, run_root)
        relative = f"requests/{job}.json"
        atomic_json(attempt / relative, request)
        paths.append(relative)
        aliases = sorted(_referenced_aliases(raw) |
                         {value for value in raw.get("upstream", []) if isinstance(value, str)})
        request_rows.append({"job_id": job, "adapter": adapter, "path": relative,
                             "sha256": HASH + file_hash(attempt / relative), "accepted_source_aliases": aliases})
    if not request_rows:
        raise Blocked("full review input assembly: at least one launch request is required")
    accepted = [{"alias": alias, **row["binding"]} for alias, row in sorted(sources.items())]
    result = {"schema": RESULT_SCHEMA, "run_id": plan["run_id"], "job_id": JOB,
              "attempt_id": attempt_id, "source_generation": generation,
              "plan_sha256": HASH + file_hash(plan_path), "accepted_sources": accepted,
              "requests": sorted(request_rows, key=lambda row: row["job_id"]),
              "skipped": plan.get("skipped", [])}
    errors = validate_document(result, "full-review-input-assembly.schema.json")
    if errors:
        raise Blocked("full review input assembly: result schema failed: " + errors[0])
    atomic_json(attempt / RESULT, result)
    atomic_json(attempt / "status.json", {"process": JOB, "status": "OK", "requests": len(request_rows),
                "accepted_sources": len(accepted), "qualification": "accepted_nominal_happy_path"})
    paths += [RESULT, "status.json"]
    envelope = terminal_envelope(run_id=plan["run_id"], job_id=JOB, attempt_id=attempt_id,
        worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
        input_fingerprint=fingerprint, output_contract=CONTRACT, started_at=started_at,
        finished_at=finished_at, summary="assembled exact accepted-source analysis launch requests",
        artifacts=artifact_records(attempt, paths))
    if validate_worker_result(envelope):
        raise Blocked("full review input assembly: common envelope is invalid")
    atomic_json(attempt / "result.json", envelope)
    atomic_json(output_root / "latest.json", {"attempt_id": attempt_id, "updated_at": finished_at})
    atomic_json(output_root / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK",
        "run_id": plan["run_id"], "job": JOB, "attempt_id": attempt_id, "fingerprint": fingerprint,
        "envelope_path": "result.json", "envelope_sha256": file_hash(attempt / "result.json"),
        "hashes": tree_hashes(attempt), "accepted_at": finished_at})
    return result


def validate(output_root: Path) -> dict[str, Any]:
    """Revalidate the currently accepted immutable assembly attempt."""
    output_root = Path(output_root)
    accepted = read_json(output_root / "accepted.json")
    attempt_id = identifier(accepted.get("attempt_id", ""))
    attempt = output_root / "attempts" / attempt_id
    envelope = read_json(attempt / "result.json")
    errors = validate_worker_result(envelope)
    if errors:
        raise Blocked("full review input assembly: common envelope is invalid: " + errors[0])
    if accepted.get("envelope_sha256") != file_hash(attempt / "result.json"):
        raise Blocked("full review input assembly: accepted envelope hash is stale")
    result = read_json(attempt / RESULT)
    schema_errors = validate_document(result, "full-review-input-assembly.schema.json")
    if schema_errors:
        raise Blocked("full review input assembly: result schema failed: " + schema_errors[0])
    for request in result.get("requests", []):
        path = attempt / request["path"]
        if not path.is_file() or request["sha256"] != HASH + file_hash(path):
            raise Blocked("full review input assembly: request artifact is missing or changed")
    return result


def _dispatch_one(adapter: str, job_id: str, request_path: Path, run_root: Path,
                  attempt_id: str, dagster_run_id: str) -> Any:
    run_id = run_root.name
    if adapter == "bounded":
        output = run_root / "data/jobs" / job_id
        return bounded_transform_orchestration.execute(job_id=job_id, run_id=run_id,
            input_path=str(request_path), output_root=str(output), attempt_id=attempt_id)
    if adapter == "vendor":
        output = run_root / "data/jobs" / job_id / "whole"
        return vendor_evidence_orchestration.execute(job_id=job_id, run_id=run_id,
            dagster_run_id=dagster_run_id, input_path=str(request_path), output_root=str(output),
            attempt_root=str(output / "attempts" / attempt_id),
            execution_root=str(output / "executions" / attempt_id))
    if adapter == "dependency":
        output = run_root / "data/jobs"
        attempt = output / job_id / "orchestration-attempts" / attempt_id
        return dependency_orchestration.execute(job_id=job_id, run_id=run_id,
            input_path=str(request_path), output_root=str(output), attempt_root=str(attempt))
    raise Blocked("full review dispatch: unknown adapter")


def dispatch(assembly_root: Path, run_root: Path, dispatch_root: Path, *, attempt_id: str,
             dagster_run_id: str, started_at: str, finished_at: str,
             executor: Any = None) -> dict[str, Any]:
    """Invoke every emitted request and retain an exact result collection.

    ``executor`` is a qualification seam with the same arguments as ``_dispatch_one``.  Production
    callers omit it and use the already-qualified public orchestration adapters.
    """
    assembly_root, run_root, dispatch_root = Path(assembly_root), Path(run_root), Path(dispatch_root)
    identifier(attempt_id); identifier(dagster_run_id)
    try:
        assembly_root.resolve(strict=True).relative_to(run_root.resolve(strict=True))
        dispatch_root.resolve(strict=False).relative_to(run_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked("full review dispatch: paths must be run-owned") from exc
    attempt = dispatch_root / "attempts" / attempt_id
    if dispatch_root.is_symlink() or attempt.exists():
        raise Blocked("full review dispatch: immutable attempt already exists")
    assembly = validate(assembly_root)
    assembly_attempt = assembly_root / "attempts" / assembly["attempt_id"]
    (attempt / "results").mkdir(parents=True)
    runner = executor or _dispatch_one
    rows, paths = [], []
    for row in assembly["requests"]:
        request_path = assembly_attempt / row["path"]
        worker_attempt_id = ("full-" + attempt_id[:96] + "-" + digest(row["job_id"])[:8])[:119]
        value = runner(row["adapter"], row["job_id"], request_path, run_root,
                       worker_attempt_id, dagster_run_id)
        relative = "results/" + row["job_id"] + ".json"
        atomic_json(attempt / relative, value)
        paths.append(relative)
        rows.append({"job_id": row["job_id"], "adapter": row["adapter"], "status": "CURRENT",
                     "request_sha256": row["sha256"], "result_path": relative,
                     "result_sha256": HASH + file_hash(attempt / relative)})
    result = {"schema": "appsec-review/full-review-dispatch/1.0", "run_id": assembly["run_id"],
              "job_id": "02-full-review-input-dispatch", "attempt_id": attempt_id,
              "source_generation": assembly["source_generation"],
              "assembly_attempt_id": assembly["attempt_id"],
              "assembly_sha256": HASH + file_hash(assembly_attempt / RESULT),
              "results": sorted(rows, key=lambda row: row["job_id"]), "skipped": assembly["skipped"]}
    errors = validate_document(result, "full-review-dispatch.schema.json")
    if errors:
        raise Blocked("full review dispatch: result schema failed: " + errors[0])
    atomic_json(attempt / "full-review-dispatch.json", result)
    atomic_json(attempt / "status.json", {"process": "02-full-review-input-dispatch", "status": "OK",
                "dispatched": len(rows), "skipped_na": len(assembly["skipped"])})
    paths += ["full-review-dispatch.json", "status.json"]
    fingerprint = HASH + digest({"assembly": result["assembly_sha256"], "requests": assembly["requests"]})
    envelope = terminal_envelope(run_id=assembly["run_id"], job_id="02-full-review-input-dispatch",
        attempt_id=attempt_id, worker_kind="deterministic_python", execution_status="OK",
        acceptance_status="CURRENT", input_fingerprint=fingerprint,
        output_contract="full-review-dispatch", started_at=started_at, finished_at=finished_at,
        summary="dispatched every applicable derived full-review request",
        artifacts=artifact_records(attempt, paths),
        gaps=[row["job_id"] + ": " + row["reason"] for row in assembly["skipped"]])
    errors = validate_worker_result(envelope)
    if errors:
        raise Blocked("full review dispatch: common envelope is invalid: " + errors[0])
    atomic_json(attempt / "result.json", envelope)
    atomic_json(dispatch_root / "latest.json", {"attempt_id": attempt_id, "updated_at": finished_at})
    atomic_json(dispatch_root / "accepted.json", {"schema": ACCEPTED_SCHEMA, "status": "OK",
        "run_id": assembly["run_id"], "job": "02-full-review-input-dispatch", "attempt_id": attempt_id,
        "fingerprint": fingerprint, "envelope_path": "result.json",
        "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
        "accepted_at": finished_at})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--component-pointer", type=Path)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--dispatch-root", type=Path)
    parser.add_argument("--dagster-run-id")
    args = parser.parse_args()
    if bool(args.plan) == bool(args.component_pointer):
        parser.error("exactly one of --plan or --component-pointer is required")
    plan = args.plan
    if args.component_pointer:
        plan = args.run_root / "inputs" / "derived-full-review-plan.json"
        derive_plan(args.component_pointer, args.run_root, plan, run_id=args.run_root.name,
                    generated_at=args.started_at)
    assemble(plan, args.run_root, args.output_root, attempt_id=args.attempt_id,
             started_at=args.started_at, finished_at=args.finished_at)
    if args.dispatch_root:
        if not args.dagster_run_id:
            parser.error("--dagster-run-id is required with --dispatch-root")
        dispatch(args.output_root, args.run_root, args.dispatch_root, attempt_id=args.attempt_id,
                 dagster_run_id=args.dagster_run_id, started_at=args.started_at,
                 finished_at=args.finished_at)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
