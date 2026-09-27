#!/usr/bin/env python3
"""Construct an evidence-assembly supply from accepted run-owned producers.

The F02 assembly core deliberately consumes a closed, immutable supply directory.  This module
provides the missing construction boundary: it discovers no shared scratch data and accepts no
hand-authored producer list.  Instead it derives the exact producer denominator from the job
graph, re-verifies the C01/C02 terminal generation, validates every current common-envelope
producer and its permission/lineage receipts, and copies that generation into a new run-owned
supply directory.

Construction is fail-closed and publish-once.  The final directory appears only after the staged
copy itself passes :func:`evidence_assembly.inspect_supply`; a failed construction leaves no
candidate that a later assembly could mistake for accepted input.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import uuid
from typing import Any

import evidence_assembly as assembly
from execution_state import Blocked, atomic_json, file_hash, read_json, tree_hashes
import pool_rendezvous as rendezvous
from publish_job_output import ACCEPTED_SCHEMA
from worker_result import validate_worker_result

SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _real_directory(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{assembly.JOB}: {label} must be an absolute real directory")
    return path.resolve()


def _beneath(root: Path, path: Path, label: str, *, must_exist: bool = True) -> Path:
    lexical = Path(os.path.abspath(path))
    try:
        relative = lexical.relative_to(root)
        cursor = root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("symbolic-link component")
        resolved = lexical.resolve(strict=must_exist)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise Blocked(f"{assembly.JOB}: {label} is not run-owned") from exc
    return resolved


def _no_links(root: Path, label: str) -> None:
    if root.is_symlink():
        raise Blocked(f"{assembly.JOB}: {label} is symbolic-linked")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise Blocked(f"{assembly.JOB}: {label} contains a symbolic link")


def _dependencies() -> list[dict[str, Any]]:
    graph = read_json(assembly.GRAPH)
    node = graph.get("jobs", {}).get(assembly.JOB)
    dependencies = node.get("dependencies") if isinstance(node, dict) else None
    if (not isinstance(dependencies, list) or
            node.get("join_policy", {}).get("mode") != "all-required-terminal-accepted"):
        raise Blocked(f"{assembly.JOB}: graph does not define the required rendezvous")
    jobs = [edge.get("job") for edge in dependencies if isinstance(edge, dict)]
    if len(jobs) != len(dependencies) or len(jobs) != len(set(jobs)):
        raise Blocked(f"{assembly.JOB}: graph producer denominator is invalid")
    return dependencies


def _pointer_shape(pointer: Any) -> set[str]:
    keys = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
            "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if isinstance(pointer, dict) and pointer.get("status") == "SKIPPED":
        keys.add("reason")
    return keys


def _generation_identities(run_root: Path, run_id: str,
                           source_snapshot_sha256: str) -> tuple[str, str]:
    """Verify the two source identities legitimately used by current producers.

    The canonical identity is the target-tree fingerprint recorded by intake.  Some later,
    permission-bound workers intentionally bind their receipts to the exact staged artifact
    manifest instead.  That alias is valid only for the current manifest bytes and is never
    substituted for the canonical identity in the assembly output.
    """
    manifest_path = _beneath(
        run_root, run_root / "inputs" / "artifact-manifest.json", "artifact manifest")
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{assembly.JOB}: current artifact manifest is absent")
    manifest = read_json(manifest_path)
    identity = manifest.get("source_identity") if isinstance(manifest, dict) else None
    fingerprint = identity.get("fingerprint") if isinstance(identity, dict) else None
    if (not isinstance(manifest, dict) or manifest.get("run_id") != run_id or
            not isinstance(fingerprint, str) or
            not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or
            source_snapshot_sha256 != "sha256:" + fingerprint):
        raise Blocked(f"{assembly.JOB}: canonical source identity is not current")
    return source_snapshot_sha256, "sha256:" + file_hash(manifest_path)


def _producer_root(run_root: Path, job: str) -> Path:
    base = _beneath(run_root, run_root / "data" / "jobs" / job, f"{job} producer namespace")
    candidates = []
    for candidate in (base, base / "whole"):
        accepted = candidate / "accepted.json"
        latest = candidate / "latest.json"
        if accepted.exists() or latest.exists():
            if (not candidate.is_dir() or candidate.is_symlink() or not accepted.is_file() or
                    accepted.is_symlink() or not latest.is_file() or latest.is_symlink()):
                raise Blocked(f"{assembly.JOB}: {job} has an incomplete accepted producer root")
            candidates.append(_beneath(run_root, candidate, f"{job} accepted producer root"))
    if len(candidates) != 1:
        detail = "ambiguous" if candidates else "absent"
        raise Blocked(f"{assembly.JOB}: {job} accepted producer root is {detail}")
    return candidates[0]


def _producer_binding(run_root: Path, run_id: str, source_snapshot_sha256: str,
                      edge: dict[str, Any], instance_ids: list[str]
                      ) -> tuple[dict[str, Any], dict[str, Any]]:
    job = edge["job"]
    canonical_source, manifest_source = _generation_identities(
        run_root, run_id, source_snapshot_sha256)
    producer = _producer_root(run_root, job)
    pointer_path, latest_path = producer / "accepted.json", producer / "latest.json"
    if (not pointer_path.is_file() or pointer_path.is_symlink() or
            not latest_path.is_file() or latest_path.is_symlink()):
        raise Blocked(f"{assembly.JOB}: {job} has no current accepted/latest pointers")
    pointer, latest = read_json(pointer_path), read_json(latest_path)
    if (not isinstance(pointer, dict) or set(pointer) != _pointer_shape(pointer) or
            pointer.get("schema") != ACCEPTED_SCHEMA or pointer.get("run_id") != run_id or
            pointer.get("job") != job or pointer.get("envelope_path") != "result.json" or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS", "SKIPPED"} or
            latest.get("attempt_id") != pointer.get("attempt_id")):
        raise Blocked(f"{assembly.JOB}: {job} does not expose one current common-envelope result")
    attempt_id = pointer["attempt_id"]
    if not isinstance(attempt_id, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", attempt_id):
        raise Blocked(f"{assembly.JOB}: {job} accepted attempt id is invalid")
    attempt = _beneath(producer, producer / "attempts" / attempt_id, f"{job} accepted attempt")
    if not attempt.is_dir() or attempt.is_symlink():
        raise Blocked(f"{assembly.JOB}: {job} accepted attempt is not a real directory")
    _no_links(attempt, f"{job} accepted attempt")
    if tree_hashes(attempt) != pointer.get("hashes"):
        raise Blocked(f"{assembly.JOB}: {job} accepted attempt tree changed")
    envelope_path = attempt / "result.json"
    if (not envelope_path.is_file() or envelope_path.is_symlink() or
            file_hash(envelope_path) != pointer.get("envelope_sha256")):
        raise Blocked(f"{assembly.JOB}: {job} accepted envelope changed")
    envelope = read_json(envelope_path)
    allowed = set(edge.get("allowed_skip_reasons", []))
    errors = validate_worker_result(envelope, allowed_skip_reasons=allowed)
    if errors:
        raise Blocked(f"{assembly.JOB}: {job} common envelope is invalid ({len(errors)} errors)")
    if (envelope.get("run_id") != run_id or envelope.get("job_id") != job or
            envelope.get("attempt_id") != attempt_id or
            envelope.get("input_fingerprint") != pointer.get("fingerprint") or
            envelope.get("execution_status") != pointer.get("status") or
            envelope.get("acceptance_status") != "CURRENT" or
            envelope.get("output_contract") != edge.get("contract")):
        raise Blocked(f"{assembly.JOB}: {job} envelope identity does not match the graph/pointer")
    if envelope["execution_status"] == "SKIPPED" and (
            pointer.get("reason") != envelope.get("skip_reason") or
            envelope.get("skip_reason") not in allowed):
        raise Blocked(f"{assembly.JOB}: {job} skip receipt is not authorized by its graph edge")

    artifacts = {item.get("path"): item for item in envelope.get("artifacts", [])
                 if isinstance(item, dict)}
    if len(artifacts) != len(envelope.get("artifacts", [])):
        raise Blocked(f"{assembly.JOB}: {job} repeats an artifact path")
    for required in ("permission.json", "lineage.json"):
        item = artifacts.get(required)
        path = attempt / required
        if (item is None or not path.is_file() or path.is_symlink() or
                item.get("sha256") != file_hash(path)):
            raise Blocked(f"{assembly.JOB}: {job} does not publish an intact {required}")
    permission, lineage = read_json(attempt / "permission.json"), read_json(attempt / "lineage.json")
    permission_source = permission.get("source_snapshot_sha256")
    lineage_source = lineage.get("source_snapshot_sha256")
    if (permission.get("schema") != assembly.PERMISSION_SCHEMA or
            permission.get("run_id") != run_id or permission.get("job_id") != job or
            permission_source not in {canonical_source, manifest_source} or
            not isinstance(permission.get("permissions"), list) or
            not permission["permissions"] or len(permission["permissions"]) != len(set(permission["permissions"]))):
        raise Blocked(f"{assembly.JOB}: {job} permission receipt is stale or invalid")
    build = lineage.get("build_lineage_sha256")
    if (lineage.get("schema") != assembly.LINEAGE_SCHEMA or lineage.get("run_id") != run_id or
            lineage.get("job_id") != job or
            lineage_source != permission_source or
            (build is not None and (not isinstance(build, str) or not SHA256.fullmatch(build)))):
        raise Blocked(f"{assembly.JOB}: {job} lineage receipt is stale or invalid")
    if permission_source == manifest_source and permission_source != canonical_source and build is None:
        raise Blocked(f"{assembly.JOB}: {job} manifest-bound source alias lacks build lineage")
    binding = {"job_id": job, "source_snapshot_sha256": canonical_source,
        "producer_source_snapshot_sha256": permission_source,
        "build_lineage_sha256": build, "permissions": permission["permissions"],
        "terminal_instance_ids": instance_ids}
    source = {"job_id": job, "root": producer, "attempt_id": attempt_id,
        "accepted_sha256": file_hash(pointer_path), "latest_sha256": file_hash(latest_path),
        "attempt_hashes": pointer["hashes"]}
    return source, binding


def derive_plan(run_root: Path, *, run_id: str, source_snapshot_sha256: str,
                pool_root: Path, expected_spec: Any, context: Any,
                rendezvous_parent: Path) -> dict[str, Any]:
    """Return a validated copy plan without writing any supply content."""
    run_root = _real_directory(run_root, "run_root")
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._-]*", run_id):
        raise Blocked(f"{assembly.JOB}: run id is invalid")
    if not isinstance(source_snapshot_sha256, str) or not SHA256.fullmatch(source_snapshot_sha256):
        raise Blocked(f"{assembly.JOB}: source snapshot identity is invalid")
    try:
        verified = rendezvous.load_verified_manifest(
            pool_root, expected_spec=expected_spec, context=context,
            rendezvous_parent=rendezvous_parent)
    except rendezvous.RendezvousError as exc:
        raise Blocked(f"{assembly.JOB}: C01/C02 terminal generation did not verify ({exc})") from exc
    terminal = rendezvous.thaw(verified.manifest)
    if (terminal.get("run_id") != run_id or terminal.get("job_id") != assembly.JOB or
            terminal.get("outcome") != "COMPLETE"):
        raise Blocked(f"{assembly.JOB}: C01/C02 terminal generation is not complete for this run/job")
    instances_by_group: dict[str, list[str]] = {}
    for instance in terminal.get("instances", []):
        if instance.get("state") != "succeeded":
            raise Blocked(f"{assembly.JOB}: C02 contains a non-successful terminal instance")
        instances_by_group.setdefault(instance.get("group_id"), []).append(instance.get("instance_id"))

    dependencies = _dependencies()
    expected_groups = {edge["job"][3:][:40] for edge in dependencies}
    if (len(expected_groups) != len(dependencies) or set(instances_by_group) != expected_groups or
            any(not values for values in instances_by_group.values())):
        raise Blocked(f"{assembly.JOB}: C01/C02 groups do not equal the graph producer denominator")
    producers, bindings = [], []
    for edge in dependencies:
        group = edge["job"][3:][:40]
        producer, binding = _producer_binding(
            run_root, run_id, source_snapshot_sha256, edge, sorted(instances_by_group[group]))
        producers.append(producer)
        bindings.append(binding)
    return {"run_root": run_root, "terminal": terminal, "producers": producers,
            "supply": {"schema": assembly.SUPPLY_SCHEMA, "run_id": run_id,
                "source_snapshot_sha256": source_snapshot_sha256, "producers": bindings}}


def stage_supply(run_root: Path, output_root: Path, *, run_id: str,
                 source_snapshot_sha256: str, pool_root: Path, expected_spec: Any,
                 context: Any, rendezvous_parent: Path) -> Path:
    """Create one verified, immutable, run-owned supply directory and return it."""
    plan = derive_plan(run_root, run_id=run_id, source_snapshot_sha256=source_snapshot_sha256,
        pool_root=pool_root, expected_spec=expected_spec, context=context,
        rendezvous_parent=rendezvous_parent)
    run_root = plan["run_root"]
    output_root = Path(output_root)
    _beneath(run_root, output_root, "supply output", must_exist=False)
    if os.path.lexists(output_root):
        raise Blocked(f"{assembly.JOB}: supply output already exists")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_root.parent / ("." + output_root.name + ".staging-" + uuid.uuid4().hex)
    try:
        temporary.mkdir(mode=0o700)
        for producer in plan["producers"]:
            job, source = producer["job_id"], producer["root"]
            if (file_hash(source / "accepted.json") != producer["accepted_sha256"] or
                    file_hash(source / "latest.json") != producer["latest_sha256"] or
                    tree_hashes(source / "attempts" / producer["attempt_id"]) !=
                    producer["attempt_hashes"]):
                raise Blocked(f"{assembly.JOB}: {job} changed after supply derivation")
            destination = temporary / "producers" / job
            destination.mkdir(parents=True)
            shutil.copy2(source / "accepted.json", destination / "accepted.json", follow_symlinks=False)
            shutil.copy2(source / "latest.json", destination / "latest.json", follow_symlinks=False)
            source_attempt = source / "attempts" / producer["attempt_id"]
            destination_attempt = destination / "attempts" / producer["attempt_id"]
            # Preserve a link instead of following it if the source is raced after preflight;
            # _no_links then rejects the staged generation without reading through that link.
            shutil.copytree(source_attempt, destination_attempt, symlinks=True)
            _no_links(destination_attempt, f"staged {job} accepted attempt")
            if (file_hash(destination / "accepted.json") != producer["accepted_sha256"] or
                    file_hash(destination / "latest.json") != producer["latest_sha256"] or
                    tree_hashes(destination_attempt) != producer["attempt_hashes"]):
                raise Blocked(f"{assembly.JOB}: {job} changed while its supply copy was staged")
        atomic_json(temporary / assembly.SUPPLY, plan["supply"])
        # The assembly's own verifier is the final authority over the staged bytes.  This also
        # proves the copied terminal bindings and receipts, rather than trusting this constructor.
        manifest, _copies = assembly.inspect_supply(
            temporary, run_id=run_id, source_snapshot_sha256=source_snapshot_sha256,
            pool_root=pool_root, expected_spec=expected_spec, context=context,
            rendezvous_parent=rendezvous_parent)
        if manifest.get("assembly_status") != "COMPLETE":
            raise Blocked(f"{assembly.JOB}: staged supply did not derive a complete manifest")
        os.replace(temporary, output_root)
        return output_root
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
