"""Construct immutable, run-owned inputs for dependency and vendor evidence jobs.

The constructor is deliberately not a scanner.  It validates the current accepted intake,
copies only the regular files attested by that intake into a content-addressed source projection,
binds accepted upstream worker generations, and writes the closed request consumed by the existing
orchestration adapters.  Applicability remains in the scanner worker so its accepted probe receipt
is the authority for ``SKIPPED``; this module never guesses a successful or negative result.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Any

import dependency_snapshot_registry as snapshots
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, identifier, read_json, run_path
import intake
import phase1
import reference_snapshots
from schema_validate import validate_document
from worker_result import validate_worker_result
import vendor_evidence_workers as vendor_workers
import registry_paths

CONTROL = "automatic-evidence-input-control.json"
CONTROL_SCHEMA = "appsec-review/automatic-evidence-input-control/1"
SOURCE_SCHEMA = "appsec-review/automatic-source-projection/1"
SOURCE_BINDING_KEYS = {
    "intake_attempt_id", "intake_pointer_sha256", "source_record_sha256",
    "source_fingerprint", "source_revision", "projection_manifest_sha256",
}
VENDOR_JOBS = {
    "02-secrets-inventory", "02-iac-config-scan",
    "02-container-image-inventory", "02-mobile-sast",
}
DEPENDENCY_JOBS = {
    "02-sbom-inventory", "02-sca-vulnerability-match",
    "02-license-scan", "02-dependency-lifecycle",
}
ALL_JOBS = VENDOR_JOBS | DEPENDENCY_JOBS
RESULTS = {
    "02-build-index": "build-index.json",
    "02-native-build": "native-build.json",
    "02-sbom-inventory": "outputs/sbom-manifest.json",
    "02-sca-vulnerability-match": "outputs/sca-vulnerability-match.json",
    "02-license-scan": "outputs/license-inventory.json",
}
STANDARDS_BINDING = "standards-source-binding.json"
REFERENCE_SOURCE_LOCK = ROOT.parent / "data" / "reference" / "source-lock.json"
REFERENCE_ROOT = ROOT.parent / "data" / "reference"


def _sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def _timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Blocked("automatic evidence inputs: generated_at must be a UTC second timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Blocked("automatic evidence inputs: generated_at is invalid") from exc
    if parsed.microsecond:
        raise Blocked("automatic evidence inputs: generated_at must have second precision")
    return value


def _manifest(run_id: str) -> tuple[Path, dict[str, Any], str]:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file() or path.is_symlink():
        raise Blocked("automatic evidence inputs: staged artifact manifest is required")
    value = read_json(path)
    if value.get("run_id") != run_id or not isinstance(value.get("intake_config"), dict):
        raise Blocked("automatic evidence inputs: staged artifact manifest identity is invalid")
    return path, value, _sha(path)


def _permissions(manifest: dict[str, Any], job_id: str) -> list[str]:
    configured = manifest["intake_config"].get("permissions")
    template = read_json(registry_paths.template(job_id))
    required = template.get("permissions")
    if (not isinstance(configured, list) or any(not isinstance(item, str) for item in configured) or
            not isinstance(required, list) or any(not isinstance(item, str) for item in required)):
        raise Blocked("automatic evidence inputs: permission declarations are invalid")
    missing = sorted(set(required) - set(configured))
    if missing:
        raise Blocked("automatic evidence inputs: missing staged permission(s): " + ", ".join(missing))
    return required


def _accepted_source(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    pointer = phase1.accepted(run_id, fresh=True)
    if not isinstance(pointer, dict) or pointer.get("status") != "OK":
        raise Blocked("automatic evidence inputs: current accepted intake is required")
    base = data_path(run_id, "jobs", "00-intake", "whole")
    pointer_path = base / "accepted.json"
    attempt = base / "attempts" / identifier(pointer.get("attempt_id"))
    source_path = attempt / "evidence" / "source.json"
    if not pointer_path.is_file() or not source_path.is_file() or source_path.is_symlink():
        raise Blocked("automatic evidence inputs: accepted intake source record is absent")
    source = read_json(source_path)
    current = intake.source_identity(source.get("target", ""))
    if current != source:
        raise Blocked("automatic evidence inputs: accepted source checkout changed")
    return pointer_path, pointer, source


def _source_files(source: dict[str, Any]) -> dict[str, str]:
    values = {}
    for relative, record in source.get("files", {}).items():
        if not isinstance(record, dict) or record.get("kind") != "file":
            continue
        pure = PurePosixPath(relative)
        if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
            raise Blocked("automatic evidence inputs: accepted source record has an unsafe path")
        value = record.get("sha256")
        if not isinstance(value, str) or len(value) != 64:
            raise Blocked("automatic evidence inputs: accepted source record has an invalid hash")
        values[pure.as_posix()] = "sha256:" + value
    return values


def _projection_manifest(run_id: str, pointer_path: Path, pointer: dict[str, Any],
                         source_path: Path, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SOURCE_SCHEMA, "run_id": run_id,
        "intake_attempt_id": pointer["attempt_id"],
        "intake_pointer_sha256": _sha(pointer_path),
        "source_record_sha256": _sha(source_path),
        "source_fingerprint": source["fingerprint"], "source_revision": source["revision"],
        "files": _source_files(source),
        "unavailable": source.get("unavailable", []),
    }


def _validate_projection(root: Path, expected: dict[str, Any]) -> Path:
    manifest_path = root / "projection.json"
    tree = root / "tree"
    if not manifest_path.is_file() or manifest_path.is_symlink() or read_json(manifest_path) != expected:
        raise Blocked("automatic evidence inputs: source projection manifest changed")
    expected_paths = set()
    for relative, wanted in expected["files"].items():
        path = tree.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file() or path.is_symlink() or _sha(path) != wanted:
            raise Blocked("automatic evidence inputs: source projection bytes changed")
        expected_paths.add(path.resolve())
    actual = {path.resolve() for path in tree.rglob("*") if path.is_file()}
    if actual != expected_paths:
        raise Blocked("automatic evidence inputs: source projection contains undeclared files")
    return tree


def source_projection(run_id: str) -> tuple[Path, dict[str, Any], dict[str, str]]:
    """Return the immutable source tree, its lineage binding and exact source-file hashes."""
    pointer_path, pointer, source = _accepted_source(run_id)
    source_path = (data_path(run_id, "jobs", "00-intake", "whole", "attempts",
                             pointer["attempt_id"], "evidence", "source.json"))
    expected = _projection_manifest(run_id, pointer_path, pointer, source_path, source)
    # The immutable projection binds both source bytes and the accepted intake lineage.  A later
    # full_review may legitimately republish an equivalent intake (for example after a definition
    # reload), so the source fingerprint alone is not a unique generation identity.
    projection_id = "source-" + source["fingerprint"][:24] + "-" + digest(expected)[:24]
    base = data_path(run_id, "automatic-inputs", "source")
    destination = base / projection_id
    if destination.exists():
        tree = _validate_projection(destination, expected)
    else:
        base.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".source-", dir=base))
        try:
            tree = staging / "tree"; tree.mkdir()
            target = Path(source["target"])
            for relative, wanted in expected["files"].items():
                original = target.joinpath(*PurePosixPath(relative).parts)
                output = tree.joinpath(*PurePosixPath(relative).parts)
                if not original.is_file() or original.is_symlink() or _sha(original) != wanted:
                    raise Blocked("automatic evidence inputs: source changed while projecting")
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, output)
                if _sha(output) != wanted:
                    raise Blocked("automatic evidence inputs: projected source copy differs")
            atomic_json(staging / "projection.json", expected)
            if intake.source_identity(source["target"]) != source:
                raise Blocked("automatic evidence inputs: source changed during projection")
            try:
                os.replace(staging, destination)
            except FileExistsError:
                # Parallel fan-out jobs can construct the same generation concurrently.  Keep the
                # first immutable winner and validate it below; a different winner remains fatal.
                shutil.rmtree(staging)
        finally:
            if staging.exists(): shutil.rmtree(staging)
        tree = _validate_projection(destination, expected)
    projection_path = destination / "projection.json"
    binding = {key: expected[key] for key in SOURCE_BINDING_KEYS - {"projection_manifest_sha256"}}
    binding["projection_manifest_sha256"] = _sha(projection_path)
    return tree, binding, expected["files"]


def validate_source_projection(run_id: str, tree: Path, binding: dict[str, Any]) -> dict[str, Any]:
    """Re-derive the accepted projection and reject stale/cross-run request bindings."""
    expected_tree, expected_binding, files = source_projection(run_id)
    if set(binding) != SOURCE_BINDING_KEYS or binding != expected_binding or Path(tree).resolve() != expected_tree.resolve():
        raise Blocked("automatic evidence inputs: source projection lineage is stale or mismatched")
    return {"binding": expected_binding, "files": files}


def _control(run_id: str) -> dict[str, Any]:
    path = data_path(run_id, "controls", CONTROL)
    if not path.is_file() or path.is_symlink():
        raise Blocked("automatic evidence inputs: offline evidence control is required")
    value = read_json(path)
    if value.get("schema") != CONTROL_SCHEMA or validate_document(value, "automatic-evidence-input-control.schema.json"):
        raise Blocked("automatic evidence inputs: offline evidence control is invalid")
    return value


def _accepted_binding(run_id: str, job_id: str, jobs: Path | None = None) -> tuple[dict[str, str], Path]:
    result_rel = RESULTS[job_id]
    base = (jobs / job_id) if jobs is not None else data_path(run_id, "jobs", job_id)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked(f"automatic evidence inputs: accepted {job_id} is required")
    pointer = read_json(pointer_path)
    attempt_id = pointer.get("attempt_id")
    attempt = base / "attempts" / identifier(attempt_id)
    result = attempt.joinpath(*PurePosixPath(result_rel).parts)
    envelope_path = attempt / "result.json"
    if (pointer.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            pointer.get("run_id") != run_id or pointer.get("job") != job_id or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            not result.is_file() or result.is_symlink() or not envelope_path.is_file()):
        raise Blocked(f"automatic evidence inputs: accepted {job_id} pointer is invalid")
    envelope = read_json(envelope_path)
    if (validate_worker_result(envelope) or envelope.get("attempt_id") != attempt_id or
            envelope.get("input_fingerprint") != pointer.get("fingerprint") or
            envelope.get("execution_status") != pointer.get("status") or
            envelope.get("acceptance_status") != "CURRENT" or
            file_hash(envelope_path) != pointer.get("envelope_sha256") or
            not any(item.get("path") == result_rel and item.get("sha256") == file_hash(result)
                    for item in envelope.get("artifacts", []) if isinstance(item, dict))):
        raise Blocked(f"automatic evidence inputs: accepted {job_id} envelope is invalid")
    return {"attempt_id": attempt_id, "path": str(result), "sha256": _sha(result),
            "accepted_path": str(pointer_path)}, attempt / "outputs"


def _native_build_binding(run_id: str, jobs: Path | None = None) -> dict[str, str] | None:
    """P37: the SBOM's optional 02-native-build edge: the accepted binding, ``{"skipped": reason}`` for a
    skipped build (no gap), or None when no accepted build exists (P42: a crashed or BLOCKED build does not
    hold the SBOM, which records ``native-build-not-published``). ``jobs``: the run's jobs root (assembly)."""
    jobs = jobs if jobs is not None else data_path(run_id, "jobs")
    pointer_path = jobs / "02-native-build" / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None
    pointer = read_json(pointer_path)
    if pointer.get("status") == "SKIPPED":
        envelope = jobs / "02-native-build" / "attempts" / identifier(pointer.get("attempt_id")) / "result.json"
        reason = read_json(envelope).get("skip_reason") if envelope.is_file() else None
        return {"skipped": str(reason or "skipped")}
    if pointer.get("status") not in {"OK", "OK_WITH_GAPS"}:
        return None
    return _accepted_binding(run_id, "02-native-build", jobs)[0]


def _reference_table(run_id: str, control: dict[str, Any]) -> tuple[Path, str]:
    configured = Path(control["dependency_lifecycle"]["reference_table_path"])
    if not configured.is_absolute() or not configured.is_file() or configured.is_symlink():
        raise Blocked("automatic evidence inputs: lifecycle reference table is absent or linked")
    value = read_json(configured)
    if validate_document(value, "dependency-lifecycle-reference-table.schema.json"):
        raise Blocked("automatic evidence inputs: lifecycle reference table is invalid")
    wanted = _sha(configured)
    destination = data_path(run_id, "automatic-inputs", "reference", wanted[7:] + ".json")
    if destination.exists():
        if destination.is_symlink() or _sha(destination) != wanted:
            raise Blocked("automatic evidence inputs: imported lifecycle reference changed")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name("." + destination.name + ".tmp")
        shutil.copyfile(configured, temporary)
        if _sha(temporary) != wanted: raise Blocked("automatic evidence inputs: lifecycle reference changed during import")
        os.replace(temporary, destination)
    return destination, wanted


def _write_request(path: Path, request: dict[str, Any]) -> None:
    if path.exists():
        if path.is_symlink() or read_json(path) != request:
            raise Blocked("automatic evidence inputs: existing request has different inputs")
        return
    atomic_json(path, request)


def _reference_snapshot(family: str, edition: str) -> tuple[Path, dict[str, Any]]:
    matches = []
    for path in REFERENCE_ROOT.glob("**/manifest.json"):
        value = read_json(path)
        if value.get("family") == family and value.get("edition") == edition:
            matches.append((path, value))
    if len(matches) != 1:
        raise Blocked(f"automatic evidence inputs: expected one offline snapshot for {family}/{edition}")
    return matches[0]


# P18: why a deselected family is not applicable; published as N/A by 02-standards-source-ingest.
NOT_APPLICABLE_REASONS = {
    "owasp_masvs": "No Android or iOS project markers in the accepted intake source inventory.",
    "owasp_mastg": "No Android or iOS project markers in the accepted intake source inventory.",
    "owasp_api_security_top_10": "No OpenAPI or Swagger definition in the accepted intake source inventory.",
    "owasp_llm_top_10": "No LLM SDK or framework paths (openai, anthropic, langchain, llamaindex) in the accepted intake source inventory.",
    "disa_gpos_srg": "The general-purpose operating system SRG covers OS configuration; a source review routes application controls to the ASD STIG instead.",
}


def _standards_selection(source: dict[str, Any]) -> dict[str, bool]:
    paths = {str(path).lower() for path, value in source.get("files", {}).items()
             if isinstance(value, dict) and value.get("kind") == "file"}
    mobile = any(path.endswith(("androidmanifest.xml", ".xcodeproj/project.pbxproj", ".xcworkspace"))
                 or "/ios/" in f"/{path}" or "/android/" in f"/{path}" for path in paths)
    api = any(path.endswith(("openapi.json", "openapi.yaml", "openapi.yml", "swagger.json",
                             "swagger.yaml", "swagger.yml")) for path in paths)
    llm = any(any(token in path for token in ("openai", "anthropic", "langchain", "llamaindex"))
              for path in paths)
    return {"owasp_asvs": True, "owasp_masvs": mobile, "owasp_mastg": mobile,
            "owasp_top_10": True, "owasp_api_security_top_10": api,
            "owasp_llm_top_10": llm, "opencre": True, "disa_asd_stig": True,
            "disa_gpos_srg": False}


def prepare_standards_binding(run_id: str) -> Path:
    """Create the immutable run-owned standards selection from accepted source facts."""
    run_id = identifier(run_id)
    _pointer_path, _pointer, source = _accepted_source(run_id)
    lock = read_json(REFERENCE_SOURCE_LOCK)
    if validate_document(lock, "reference-source-lock.schema.json"):
        raise Blocked("automatic evidence inputs: reference source lock is invalid")
    try:
        reference_snapshots.validate_source_lock_semantics(lock)
    except reference_snapshots.SnapshotError as exc:
        raise Blocked("automatic evidence inputs: reference source provenance is invalid") from exc
    decisions = _standards_selection(source)
    known = {item["family"] for item in lock["sources"]}
    if known != set(decisions):
        raise Blocked("automatic evidence inputs: standards applicability rules do not cover source lock")
    selected, unselected = [], []
    for entry in sorted(lock["sources"], key=lambda item: item["family"]):
        family = entry["family"]
        if decisions[family]:
            manifest_path, manifest = _reference_snapshot(family, entry["edition"])
            selected.append({"family": family, "edition": entry["edition"],
                "snapshot_id": manifest["snapshot_id"],
                "manifest_sha256": _sha(manifest_path),
                "selection_basis": "Automatic applicability routing from the accepted intake source inventory; reference material only, not an approval or compliance decision."})
        else:
            unselected.append({"family": family, "reason": NOT_APPLICABLE_REASONS.get(family,
                "Accepted intake source paths contain no target evidence for this specialized standards family.")})
    binding = {"schema": "appsec-review/standards-source-binding/1.0", "run_id": run_id,
               "selected_snapshots": selected, "unselected_families": unselected}
    if validate_document(binding, "standards-source-binding.schema.json"):
        raise Blocked("automatic evidence inputs: generated standards binding is invalid")
    path = data_path(run_id, "inputs", STANDARDS_BINDING)
    if path.exists():
        if path.is_symlink() or read_json(path) != binding:
            raise Blocked("automatic evidence inputs: existing standards binding differs from accepted source")
    else:
        atomic_json(path, binding)
    return path


def prepare(run_id: str, job_id: str, dagster_run_id: str, *, generated_at: str | None = None) -> dict[str, str]:
    """Create a closed request and return the exact kwargs for the orchestration adapter."""
    run_id, dagster_run_id = identifier(run_id), identifier(dagster_run_id)
    if job_id not in ALL_JOBS:
        raise Blocked("automatic evidence inputs: unsupported lifecycle job")
    manifest_path, manifest, generation = _manifest(run_id)
    permissions = _permissions(manifest, job_id)
    source, source_binding, source_files = source_projection(run_id)
    attempt_id = "auto-" + digest({"dagster_run_id": dagster_run_id, "job_id": job_id})[:24]
    request_path = data_path(run_id, "jobs", job_id, "automatic-inputs", attempt_id + ".json")
    if generated_at is None and request_path.is_file() and not request_path.is_symlink():
        generated_at = read_json(request_path).get("generated_at")
    stamp = _timestamp(generated_at)

    if job_id in VENDOR_JOBS:
        source_root = run_path(run_id) / "inputs" if job_id == "02-container-image-inventory" else source
        probe = vendor_workers.probe(job_id, source_root)
        applicable = any(probe["candidates"].values()) or job_id == "02-secrets-inventory"
        applicability = {"decision": "EXECUTE" if applicable else "SKIPPED_NA",
            "skip_reason": None if applicable else vendor_workers.SKIP,
            "probe_sha256": "sha256:" + digest(probe), "probe": probe}
        request = {"schema": "appsec-review/vendor-evidence-orchestration-request/1.1",
            "run_id": run_id, "job_id": job_id, "source_generation": generation,
            "generated_at": stamp, "source_root": str(source_root), "source_binding": source_binding,
            "applicability": applicability}
        base = data_path(run_id, "jobs", job_id, "whole")
        result = {"input_path": str(request_path), "output_root": str(base),
            "attempt_root": str(base / "attempts" / attempt_id),
            "execution_root": str(base / "executions" / attempt_id)}
    else:
        payload: dict[str, Any]; tool: dict[str, Any]
        if job_id == "02-sbom-inventory":
            build_index, _ = _accepted_binding(run_id, "02-build-index")
            payload = {"source_files": source_files, "build_index": build_index,
                       "native_build": _native_build_binding(run_id)}
            tool = {"target_path": str(source)}
        elif job_id == "02-sca-vulnerability-match":
            control = _control(run_id); sbom, sbom_root = _accepted_binding(run_id, "02-sbom-inventory")
            registry = Path(control["offline_snapshots"]["registry_path"])
            max_age = control["offline_snapshots"]["max_database_age_seconds"]
            now = datetime.fromisoformat(stamp[:-1] + "+00:00")
            try:
                resolved_snapshots = [snapshots.resolve(kind, registry, max_age_seconds=max_age, now=now)
                                      for kind in sorted(snapshots.KINDS)]
            except (snapshots.SnapshotBlocked, snapshots.SnapshotInvalid, snapshots.SnapshotStale) as exc:
                raise Blocked(f"automatic evidence inputs: offline snapshot validation failed: {exc}") from exc
            payload = {"sbom": sbom}
            tool = {"sbom_root": str(sbom_root), "snapshot_registry": str(registry.resolve()),
                    "max_database_age_seconds": max_age,
                    "snapshot_identities": [{key: item[key] for key in
                        ("database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp")}
                        for item in resolved_snapshots]}
        elif job_id == "02-license-scan":
            sbom, _ = _accepted_binding(run_id, "02-sbom-inventory")
            payload, tool = {"sbom": sbom, "source_files": source_files}, {"target_path": str(source)}
        else:
            control = _control(run_id); sbom, _ = _accepted_binding(run_id, "02-sbom-inventory")
            license_binding, _ = _accepted_binding(run_id, "02-license-scan")
            table, table_sha = _reference_table(run_id, control)
            payload = {"sbom": sbom, "license": license_binding, "reference_table": str(table),
                       "reference_table_sha256": table_sha,
                       "max_reference_age_days": control["dependency_lifecycle"]["max_reference_age_days"]}
            tool = {}
        request = {"schema": "appsec-review/dependency-orchestration-request/1.1",
            "run_id": run_id, "job_id": job_id, "source_generation": generation,
            "generated_at": stamp, "source_binding": source_binding, "payload": payload, "tool": tool}
        jobs = data_path(run_id, "jobs")
        result = {"input_path": str(request_path), "output_root": str(jobs),
            "attempt_root": str(jobs / job_id / "orchestration-attempts" / attempt_id)}
    request_path.parent.mkdir(parents=True, exist_ok=True)
    _write_request(request_path, request)
    atomic_json(request_path.with_suffix(".receipt.json"), {
        "schema": "appsec-review/automatic-evidence-input-receipt/1", "run_id": run_id,
        "job_id": job_id, "dagster_run_id": dagster_run_id,
        "source_generation": generation, "artifact_manifest_sha256": _sha(manifest_path),
        "source_binding": source_binding, "permissions": permissions,
        "request_sha256": _sha(request_path), "orchestration": result,
    })
    return result


__all__ = ["ALL_JOBS", "CONTROL", "prepare", "prepare_standards_binding", "source_projection",
           "validate_source_projection"]
