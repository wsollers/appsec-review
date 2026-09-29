"""Deterministic, fail-closed core for the planned 02-evidence-assembly barrier.

This module consumes one explicit supplied generation rooted at ``supply_root``::

    assembly-supply.json
    terminal-instances.json
    producers/<job>/accepted.json
    producers/<job>/latest.json
    producers/<job>/attempts/<attempt>/result.json

Every producer artifact, including ``permission.json``, remains below its immutable attempt.  A
complete assembly copies only envelope-declared, hash-verified artifacts into its own attempt and
publishes their assembly-relative identities in ``intel-manifest.json``.  Missing producers can be
rendered for diagnostics, but can never pass the publication preflight.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import shutil
from typing import Any

import pool_rendezvous as pr
from execution_state import (ROOT, Blocked, atomic_bytes, data_path, digest, file_hash, identifier,
                             now, read_json, tree_hashes)
from publish_job_output import (ACCEPTED_SCHEMA, coordinate_worker_lifecycle,
                                record_terminal_current, validate_published)
from schema_validate import validate_document
from worker_result import validate_worker_result

JOB = "02-evidence-assembly"
CONTRACT = "pregather"
WORKER_KIND = "join_controller"
RESULT = "intel-manifest.json"
SUPPLY = "assembly-supply.json"
TERMINAL = "terminal-instances.json"
GRAPH = ROOT / "job-graph.json"
SCHEMA = "appsec-review/intel-manifest/1.0"
SUPPLY_SCHEMA = "appsec-review/evidence-assembly-supply/1.0"
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
CODE_FILES = (
    "evidence_assembly.py", "execution_state.py", "publish_job_output.py",
    "validate_job_output.py", "worker_result.py", "pool_rendezvous.py", "pool_specification.py",
    "worker_adapters.py", "container_execution.py", "persona_invocation.py",
    "registry/job-templates/02-evidence-assembly.json",
    "registry/output-contracts/pregather.json", "personas/roles/evidence-assembler/role.json",
    "registry/domains/evidence-assembly.json",
    "registry/tooling-profiles/hash-bound-evidence-assembly.json",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _hash(value: Any) -> str:
    return "sha256:" + digest(value)


def manifest_sha256(value: dict[str, Any]) -> str:
    return _hash({key: item for key, item in value.items() if key != "manifest_sha256"})


def serialize(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _real_directory(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: {label} must be an absolute real directory")
    return path.resolve()


def _relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise Blocked(f"{JOB}: {label} must be a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise Blocked(f"{JOB}: {label} is not a normalized relative path")
    return path


def _owned_file(base: Path, relative: PurePosixPath, label: str) -> Path:
    path = base.joinpath(*relative.parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(base.resolve())
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: {label} does not resolve beneath its immutable attempt") from exc
    cursor = base
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise Blocked(f"{JOB}: {label} traverses a symbolic link")
    if not path.is_file():
        raise Blocked(f"{JOB}: {label} is not a regular file")
    return path


def _graph() -> tuple[list[dict[str, Any]], str]:
    value = read_json(GRAPH)
    node = value.get("jobs", {}).get(JOB, {})
    dependencies = node.get("dependencies")
    if (node.get("implemented") is not True or node.get("join_policy", {}).get("mode") !=
            "all-required-terminal-accepted" or not isinstance(dependencies, list)):
        raise Blocked(f"{JOB}: graph must describe the implemented fail-closed barrier")
    return dependencies, "sha256:" + file_hash(GRAPH)


def _terminal(pool_root: Path, *, expected_spec: Any, context: Any,
              rendezvous_parent: Path, run_id: str) -> tuple[dict[str, Any], Path, str]:
    """Load C02's authority: re-derived expansion, requests and adapter results, never its self-hash."""
    try:
        verified = pr.load_verified_manifest(pool_root, expected_spec=expected_spec, context=context,
                                             rendezvous_parent=rendezvous_parent)
    except pr.RendezvousError as exc:
        raise Blocked(f"{JOB}: terminal-instance generation did not re-verify ({exc})") from exc
    value = pr.thaw(verified.manifest)
    if value.get("run_id") != run_id or value.get("job_id") != JOB:
        raise Blocked(f"{JOB}: verified terminal-instance generation belongs to another run/job")
    path = pr.rendezvous_root(verified.plan, rendezvous_parent) / pr.MANIFEST_FILE
    return value, path, "sha256:" + file_hash(path)


def _producer(supply_root: Path, run_id: str, source: str, edge: dict[str, Any],
              binding: dict[str, Any], terminal_by_id: dict[str, dict[str, Any]]) -> tuple[dict, list]:
    job = edge["job"]
    if binding["source_snapshot_sha256"] != source:
        raise Blocked(f"{JOB}: {job} belongs to a different source snapshot")
    # Direct core callers created before the dual-identity supply contract necessarily use the
    # canonical identity for their producer receipts. Schema-validated supplies always carry the
    # explicit field; this fallback preserves that narrow core API without inventing an alias.
    producer_source = binding.get("producer_source_snapshot_sha256", source)
    producer_root = supply_root / "producers" / job
    if not producer_root.is_dir() or producer_root.is_symlink():
        raise Blocked(f"{JOB}: {job} producer root is absent or not a real directory")
    pointer_path = _owned_file(producer_root, PurePosixPath("accepted.json"),
                               f"{job} accepted pointer")
    pointer = read_json(pointer_path)
    latest = read_json(_owned_file(producer_root, PurePosixPath("latest.json"),
                                   f"{job} latest pointer"))
    required_pointer = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                        "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if pointer.get("status") == "SKIPPED":
        required_pointer.add("reason")
    if (set(pointer) != required_pointer or pointer.get("schema") != ACCEPTED_SCHEMA or
            pointer.get("envelope_path") != "result.json" or pointer.get("run_id") != run_id or
            pointer.get("job") != job or latest.get("attempt_id") != pointer.get("attempt_id")):
        raise Blocked(f"{JOB}: {job} accepted/latest pointer identity is stale or incomplete")
    try:
        attempt_id = identifier(pointer["attempt_id"])
    except ValueError as exc:
        raise Blocked(f"{JOB}: {job} accepted pointer has an invalid attempt id") from exc
    attempt = producer_root / "attempts" / attempt_id
    if not attempt.is_dir() or attempt.is_symlink() or tree_hashes(attempt) != pointer["hashes"]:
        raise Blocked(f"{JOB}: {job} immutable attempt tree does not match its accepted pointer")
    envelope_path = _owned_file(attempt, _relative(pointer["envelope_path"], "envelope_path"),
                                f"{job} envelope")
    if file_hash(envelope_path) != pointer["envelope_sha256"]:
        raise Blocked(f"{JOB}: {job} accepted envelope hash changed")
    envelope = read_json(envelope_path)
    allowed_skips = set(edge.get("allowed_skip_reasons", []))
    errors = validate_worker_result(envelope, allowed_skip_reasons=allowed_skips)
    if errors:
        raise Blocked(f"{JOB}: {job} envelope is invalid ({len(errors)} errors)")
    if (envelope.get("run_id") != run_id or envelope.get("job_id") != job or
            envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("acceptance_status") != "CURRENT" or
            envelope.get("output_contract") != edge["contract"]):
        raise Blocked(f"{JOB}: {job} envelope/pointer/edge identity mismatch")
    if envelope["execution_status"] == "SKIPPED" and pointer["reason"] != envelope["skip_reason"]:
        raise Blocked(f"{JOB}: {job} accepted pointer skip reason differs from its envelope")
    if envelope["execution_status"] not in {"OK", "OK_WITH_GAPS", "SKIPPED"}:
        raise Blocked(f"{JOB}: {job} is not an accepted terminal producer")

    terminal_ids = binding["terminal_instance_ids"]
    for instance_id in terminal_ids:
        instance = terminal_by_id.get(instance_id)
        if (instance is None or instance.get("state") != "succeeded" or
                instance.get("group_id") != job.removeprefix("02-")[:40]):
            raise Blocked(f"{JOB}: {job} references an absent or unsuccessful terminal instance")

    artifacts, copies, seen_artifacts = [], [], set()
    for artifact in envelope["artifacts"]:
        relative = _relative(artifact.get("path"), f"{job} artifact path")
        if relative.as_posix() in seen_artifacts:
            raise Blocked(f"{JOB}: {job} envelope repeats an artifact path")
        seen_artifacts.add(relative.as_posix())
        source_path = _owned_file(attempt, relative, f"{job} artifact")
        if file_hash(source_path) != artifact.get("sha256"):
            raise Blocked(f"{JOB}: {job} artifact hash changed: {relative.as_posix()}")
        output = PurePosixPath("evidence", job, pointer["attempt_id"], *relative.parts)
        artifacts.append({"producer_job_id": job, "producer_attempt_id": pointer["attempt_id"],
            "producer_path": relative.as_posix(), "path": output.as_posix(),
            "sha256": "sha256:" + artifact["sha256"], "media_type": artifact["media_type"]})
        copies.append((source_path, output.as_posix()))
    permission = next((item for item in artifacts if item["producer_path"] == "permission.json"), None)
    if permission is None:
        raise Blocked(f"{JOB}: {job} envelope does not publish permission.json")
    permission_value = read_json(attempt / "permission.json")
    expected_permission = {"schema": PERMISSION_SCHEMA, "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": producer_source, "permissions": binding["permissions"]}
    if permission_value != expected_permission:
        raise Blocked(f"{JOB}: {job} permission receipt does not match its generation binding")
    lineage = next((item for item in artifacts if item["producer_path"] == "lineage.json"), None)
    if lineage is None:
        raise Blocked(f"{JOB}: {job} envelope does not publish lineage.json")
    lineage_value = read_json(attempt / "lineage.json")
    expected_lineage = {"schema": LINEAGE_SCHEMA, "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": producer_source,
        "build_lineage_sha256": binding["build_lineage_sha256"]}
    if lineage_value != expected_lineage:
        raise Blocked(f"{JOB}: {job} lineage receipt does not match its generation binding")
    disposition = "authorized-skip" if envelope["execution_status"] == "SKIPPED" else "accepted"
    entry = {"job_id": job, "contract": edge["contract"], "disposition": disposition,
        "attempt_id": pointer["attempt_id"], "input_fingerprint": pointer["fingerprint"],
        "execution_status": envelope["execution_status"],
        "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
        "envelope_sha256": "sha256:" + pointer["envelope_sha256"],
        "source_snapshot_sha256": source,
        "producer_source_snapshot_sha256": producer_source,
        "build_lineage_sha256": binding["build_lineage_sha256"],
        "terminal_instance_ids": list(terminal_ids), "permissions": list(binding["permissions"]),
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
        "gaps": list(envelope["gaps"]), "skip_reason": envelope["skip_reason"]}
    return entry, copies


def inspect_supply(supply_root: Path, *, run_id: str, source_snapshot_sha256: str,
                   pool_root: Path, expected_spec: Any, context: Any, rendezvous_parent: Path
                   ) -> tuple[dict[str, Any], list[tuple[Path, str]]]:
    """Return the deterministic candidate manifest and copy plan; never writes."""
    supply_root = _real_directory(supply_root, "supply_root")
    supply = read_json(_owned_file(supply_root, PurePosixPath(SUPPLY), "assembly supply"))
    errors = validate_document(supply, "evidence-assembly-supply.schema.json")
    if errors:
        raise Blocked(f"{JOB}: assembly supply schema failed ({len(errors)} errors)")
    if supply["run_id"] != run_id or supply["source_snapshot_sha256"] != source_snapshot_sha256:
        raise Blocked(f"{JOB}: supply run/source identity mismatch")
    terminal, terminal_path, terminal_file_sha = _terminal(
        pool_root, expected_spec=expected_spec, context=context,
        rendezvous_parent=rendezvous_parent, run_id=run_id)
    dependencies, graph_sha = _graph()
    bindings = {item["job_id"]: item for item in supply["producers"]}
    if len(bindings) != len(supply["producers"]):
        raise Blocked(f"{JOB}: duplicate producer binding")
    expected_jobs = [edge["job"] for edge in dependencies]
    if set(bindings) - set(expected_jobs):
        raise Blocked(f"{JOB}: supply contains a producer outside the graph join")
    terminal_by_id = {item["instance_id"]: item for item in terminal["instances"]}
    claimed: set[str] = set()
    producers, copies, gaps = [], [(terminal_path, TERMINAL)], []
    for edge in dependencies:
        job = edge["job"]
        binding = bindings.get(job)
        if binding is None:
            producers.append({"job_id": job, "contract": edge["contract"], "disposition": "missing",
                "attempt_id": None, "input_fingerprint": None, "execution_status": None,
                "accepted_pointer_sha256": None, "envelope_sha256": None,
                "source_snapshot_sha256": None,
                "producer_source_snapshot_sha256": None,
                "build_lineage_sha256": None, "terminal_instance_ids": [], "permissions": [],
                "artifacts": [], "gaps": [], "skip_reason": None})
            gaps.append({"producer_job_id": job, "kind": "missing-producer",
                         "detail": "Required producer has no supplied accepted terminal envelope."})
            continue
        overlap = claimed.intersection(binding["terminal_instance_ids"])
        if overlap:
            raise Blocked(f"{JOB}: terminal instance is claimed by more than one producer")
        claimed.update(binding["terminal_instance_ids"])
        entry, producer_copies = _producer(supply_root, run_id, source_snapshot_sha256, edge,
                                            binding, terminal_by_id)
        producers.append(entry); copies.extend(producer_copies)
        if entry["disposition"] == "authorized-skip":
            gaps.append({"producer_job_id": job, "kind": "authorized-skip",
                         "detail": f"Producer was explicitly skipped: {entry['skip_reason']}."})
        gaps.extend({"producer_job_id": job, "kind": "producer-gap", "detail": detail}
                    for detail in entry["gaps"])
    if claimed != set(terminal_by_id):
        gaps.append({"producer_job_id": JOB, "kind": "producer-gap",
                     "detail": "Terminal manifest contains unclaimed producer instances."})
    complete = (not any(item["disposition"] == "missing" for item in producers)
                and claimed == set(terminal_by_id) and terminal["outcome"] == "COMPLETE")
    generation = {"source_snapshot_sha256": source_snapshot_sha256,
        "terminal_manifest_sha256": terminal["manifest_sha256"],
        "producer_envelopes": [(item["job_id"], item["accepted_pointer_sha256"],
                                 item["envelope_sha256"],
                                 item["producer_source_snapshot_sha256"],
                                 item["build_lineage_sha256"]) for item in producers]}
    manifest = {"schema": SCHEMA, "run_id": run_id,
        "source_snapshot_sha256": source_snapshot_sha256,
        "assembly_status": "COMPLETE" if complete else "INCOMPLETE",
        "generation": {"generation_sha256": _hash(generation), "graph_sha256": graph_sha,
                       "terminal_manifest_sha256": terminal["manifest_sha256"]},
        "terminal_instances": {"path": TERMINAL, "sha256": terminal_file_sha,
            "manifest_sha256": terminal["manifest_sha256"], "outcome": terminal["outcome"],
            "counts": terminal["counts"]},
        "producers": producers, "coverage_gaps": gaps}
    manifest["manifest_sha256"] = manifest_sha256(manifest)
    schema_errors = validate_document(manifest, "intel-manifest.schema.json")
    if schema_errors:
        raise Blocked(f"{JOB}: derived intel manifest schema failed ({len(schema_errors)} errors)")
    return manifest, copies


def _code_hashes() -> dict[str, str]:
    result = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("intel-manifest.schema.json", "intel-manifest-producer.schema.json",
                 "intel-manifest-artifact.schema.json", "intel-manifest-gap.schema.json",
                 "evidence-assembly-supply.schema.json",
                 "pool-rendezvous-manifest.schema.json", "worker-result-envelope.schema.json"):
        result["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    result["job-graph.json"] = file_hash(GRAPH)
    return result


def current_inputs(run_id: str, supply_root: Path, source_snapshot_sha256: str, *,
                   pool_root: Path, expected_spec: Any, context: Any,
                   rendezvous_parent: Path) -> dict[str, Any]:
    supply_root = _real_directory(supply_root, "supply_root")
    pool_root = _real_directory(pool_root, "pool_root")
    rendezvous_parent = _real_directory(rendezvous_parent, "rendezvous_parent")
    terminal, terminal_path, terminal_file_sha = _terminal(
        pool_root, expected_spec=expected_spec, context=context,
        rendezvous_parent=rendezvous_parent, run_id=run_id)
    return {"run_id": run_id, "job": JOB, "supply_root": str(supply_root),
            "source_snapshot_sha256": source_snapshot_sha256,
            "supply_hashes": tree_hashes(supply_root), "pool_root": str(pool_root),
            "pool_hashes": tree_hashes(pool_root), "rendezvous_parent": str(rendezvous_parent),
            "rendezvous_hashes": tree_hashes(rendezvous_parent),
            "expected_spec_sha256": _hash(expected_spec),
            "terminal_manifest_sha256": terminal["manifest_sha256"],
            "terminal_file_sha256": terminal_file_sha,
            "terminal_path": str(terminal_path), "code": _code_hashes()}


def _derive_from_record(record: dict[str, Any], *, expected_spec: Any, context: Any):
    supply_root = Path(record["supply_root"])
    pool_root = Path(record["pool_root"])
    rendezvous_parent = Path(record["rendezvous_parent"])
    if (_hash(expected_spec) != record["expected_spec_sha256"] or
            tree_hashes(supply_root) != record["supply_hashes"] or
            tree_hashes(pool_root) != record["pool_hashes"] or
            tree_hashes(rendezvous_parent) != record["rendezvous_hashes"]):
        raise Blocked(f"{JOB}: supplied generation changed after inputs were recorded")
    return inspect_supply(supply_root, run_id=record["run_id"],
                          source_snapshot_sha256=record["source_snapshot_sha256"],
                          pool_root=pool_root, expected_spec=expected_spec, context=context,
                          rendezvous_parent=rendezvous_parent)


def _validate_attempt(attempt: Path, record: dict[str, Any], *, expected_spec: Any,
                      context: Any) -> None:
    if read_json(attempt / "inputs.json") != record:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    expected, _copies = _derive_from_record(record, expected_spec=expected_spec, context=context)
    found = read_json(attempt / RESULT)
    if found != expected or found["manifest_sha256"] != manifest_sha256(found):
        raise Blocked(f"{JOB}: intel manifest is stale or changed")
    terminal_path = _owned_file(attempt, PurePosixPath(TERMINAL), "assembled terminal manifest")
    if "sha256:" + file_hash(terminal_path) != found["terminal_instances"]["sha256"]:
        raise Blocked(f"{JOB}: assembled terminal manifest hash changed")
    for producer in found["producers"]:
        for artifact in producer["artifacts"]:
            path = _owned_file(attempt, _relative(artifact["path"], "assembled artifact path"),
                               "assembled producer artifact")
            if "sha256:" + file_hash(path) != artifact["sha256"]:
                raise Blocked(f"{JOB}: assembled producer artifact hash changed")


def run(run_id: str, dagster_id: str, *, supply_root: Path, source_snapshot_sha256: str,
        pool_root: Path, expected_spec: Any, context: Any, rendezvous_parent: Path,
        force: bool = False) -> dict[str, Any]:
    """Nominal worker entry point; deliberately has no graph/Dagster binding yet."""
    base = root(run_id)
    resume = (f"evidence_assembly.run({run_id!r}, <dagster-id>, supply_root=<path>, "
              "source_snapshot_sha256=<hash>, pool_root=<path>, expected_spec=<spec>, "
              "context=<PoolContext>, rendezvous_parent=<path>)")

    def derive():
        record = current_inputs(run_id, supply_root, source_snapshot_sha256, pool_root=pool_root,
            expected_spec=expected_spec, context=context, rendezvous_parent=rendezvous_parent)
        manifest, _copies = _derive_from_record(record, expected_spec=expected_spec, context=context)
        if manifest["assembly_status"] != "COMPLETE":
            missing = [item["job_id"] for item in manifest["producers"]
                       if item["disposition"] == "missing"]
            raise Blocked(f"{JOB}: early publication refused; missing producers: {', '.join(missing)}")
        return record

    def execute(allocation, record, fingerprint):
        attempt = allocation["attempt"]
        manifest, copies = _derive_from_record(record, expected_spec=expected_spec, context=context)
        for source, relative in copies:
            target = attempt.joinpath(*PurePosixPath(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        atomic_bytes(attempt / RESULT, serialize(manifest))
        if record["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed during assembly")
        status = {"process": "02-evidence-pregather", "status": "OK_WITH_GAPS" if manifest["coverage_gaps"] else "OK",
            "run_id": run_id, "job": JOB, "attempt_id": allocation["attempt_id"],
            "dagster_run_id": dagster_id, "source_snapshot_sha256": source_snapshot_sha256,
            "generation_sha256": manifest["generation"]["generation_sha256"],
            "producers": len(manifest["producers"]), "permissions": ["read-run-data", "write-run-data"],
            "started_at": allocation["started_at"], "ended_at": now()}
        artifact_paths = [RESULT, TERMINAL, "status.json"] + [artifact["path"]
            for producer in manifest["producers"] for artifact in producer["artifacts"]]
        gaps = [item["detail"] for item in manifest["coverage_gaps"]]
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_id, worker_kind=WORKER_KIND, output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status="OK_WITH_GAPS" if gaps else "OK",
            summary=f"Assembled {len(manifest['producers'])} terminal producer records without executing target content.",
            status_record=status, artifact_paths=artifact_paths, gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(
                path, record, expected_spec=expected_spec, context=context))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind=WORKER_KIND, output_contract=CONTRACT, resume_command=resume,
        derive_inputs=derive, fingerprint_inputs=lambda value: _hash(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(
            attempt, record, expected_spec=expected_spec, context=context),
        blocked_summary="Evidence assembly preflight refused incomplete, stale, or corrupt producers.",
        failed_summary="Evidence assembly did not publish.")


def validate(run_id: str, *, supply_root: Path, source_snapshot_sha256: str,
             pool_root: Path, expected_spec: Any, context: Any, rendezvous_parent: Path,
             pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    record = current_inputs(run_id, supply_root, source_snapshot_sha256, pool_root=pool_root,
        expected_spec=expected_spec, context=context, rendezvous_parent=rendezvous_parent)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _envelope = validate_published(base, pointer, _hash(record),
        expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(attempt, record, expected_spec=expected_spec, context=context)
    return attempt


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
