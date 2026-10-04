"""Config-driven orchestration for dependency evidence and CVE reachability jobs.

The adapter owns no scanner logic.  It binds explicit run-owned inputs to the public B13
adapters, supplies only verified offline database snapshots, and then calls the dependency
worker's immutable publication seam.  Snapshot synchronization deliberately lives elsewhere.

The 02 dependency jobs are reused by content before any B13 container runs (``reuse_inputs``,
``producer_reuse``): their requests carry a per-launch ``generated_at`` and orchestration attempt and
bind upstreams by attempt, so the worker's own request fingerprint changes on every launch.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import dependency_b13_adapters as b13
import dependency_workers as workers
import automatic_evidence_inputs as automatic_inputs
from execution_state import Blocked, atomic_json, beneath, data_path, file_hash, identifier, read_json, run_path
import producer_reuse
import registry_paths

REQUEST_SCHEMA = "appsec-review/dependency-orchestration-request/1.1"
LEGACY_REQUEST_SCHEMA = "appsec-review/dependency-orchestration-request/1.0"
JOBS = {
    "02-sbom-inventory": "sbom",
    "02-sca-vulnerability-match": "sca",
    "02-license-scan": "license",
    "02-dependency-lifecycle": "lifecycle",
    "06-cve-reachability": "reachability",
}
_REQUEST_KEYS = {"schema", "run_id", "job_id", "source_generation", "generated_at",
                 "source_binding", "payload", "tool"}
_LEGACY_REQUEST_KEYS = {"schema", "run_id", "job_id", "source_generation", "generated_at", "payload", "tool"}
_PAYLOAD_KEYS = {
    "sbom": {"source_files", "build_index"},
    "sca": {"sbom"},
    "license": {"sbom", "source_files"},
    "lifecycle": {"sbom", "license", "reference_table", "reference_table_sha256", "max_reference_age_days"},
    "reachability": {"sca", "reachability_evidence", "reachability_evidence_sha256"},
}
# P37: the SBOM's optional 02-native-build edge; requests built before it (or by the full-review assembly) omit it.
# P43: likewise the optional 02-iac-config-scan base-image inventory.
_OPTIONAL_PAYLOAD_KEYS = {"sbom": {"native_build", "base_image_inventory"}}
_OPTIONAL_BINDINGS = {"native_build", "base_image_inventory"}  # None (absent) or {"skipped": reason} bind no file
_TOOL_KEYS = {
    "sbom": {"target_path"},
    "sca": {"sbom_root", "snapshot_registry", "max_database_age_seconds", "snapshot_identities"},
    "license": {"target_path"},
    "lifecycle": set(),
    "reachability": set(),
}
_LEGACY_TOOL_KEYS = {**_TOOL_KEYS,
    "sca": {"sbom_root", "snapshot_registry", "max_database_age_seconds"}}
REUSABLE = {"sbom", "sca", "license", "lifecycle"}       # the 02 producers 02-evidence-assembly joins
_PATH_KEYS = {"target_path", "sbom_root", "snapshot_registry", "reference_table", "reachability_evidence"}
CODE_FILES = ("dependency_orchestration.py", "dependency_workers.py", "dependency_b13_adapters.py",
              "automatic_evidence_inputs.py", "producer_reuse.py")


def _content(value: Any) -> Any:
    """An upstream binding by its content hash, never its attempt id or path; skips stay as they are."""
    if isinstance(value, dict) and "sha256" in value and "path" in value:
        return {"sha256": value["sha256"]}
    return value


def reuse_inputs(kind: str, job_id: str, run_id: str, request: dict[str, Any], generation: str) -> dict[str, Any]:
    """What the job's evidence is a function of: request content, upstream content by hash, the pinned
    image records, its own code and contracts. Never ``generated_at``, an attempt id or a path."""
    binding = request.get("source_binding") if isinstance(request.get("source_binding"), dict) else {}
    contract = workers.JOBS[kind][1]
    return {"job_id": job_id, "run_id": run_id, "source_generation": generation, "schema": request.get("schema"),
        "source": {"fingerprint": binding.get("source_fingerprint"), "revision": binding.get("source_revision")},
        "payload": {key: _content(value) for key, value in request["payload"].items() if key not in _PATH_KEYS},
        "tool": {key: value for key, value in request["tool"].items() if key not in _PATH_KEYS},
        "images": producer_reuse.images(spec["image"] for spec in b13.SPECS.values() if spec["job"] == job_id),
        "code": producer_reuse.code(CODE_FILES + (registry_paths.contract_rel(contract),
                                                  registry_paths.template_rel(job_id)))}


def _still_current(kind: str, request: dict[str, Any]) -> None:
    """A reused result must still pass the age ceilings at this launch's clock (else re-execute)."""
    now = datetime.fromisoformat(request["generated_at"].replace("Z", "+00:00"))
    if kind == "sca":
        ceiling = request["tool"]["max_database_age_seconds"]
        for identity in request["tool"].get("snapshot_identities") or []:
            age = (now - datetime.fromisoformat(identity["data_timestamp"].replace("Z", "+00:00"))).total_seconds()
            if age < 0 or age > ceiling:
                raise Blocked("dependency orchestration: reused vulnerability database is out of its age ceiling")
    elif kind == "lifecycle":
        table = json.loads(Path(request["payload"]["reference_table"]).read_text(encoding="utf-8"))
        age = (now.date() - datetime.fromisoformat(table["as_of"]).date()).days
        if age < 0 or age > request["payload"]["max_reference_age_days"]:
            raise Blocked("dependency orchestration: reused lifecycle reference table is out of its age ceiling")


def _owned(value: Any, owner: Path, label: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not value:
        raise Blocked(f"dependency orchestration: {label} path is required")
    path = Path(value).absolute()
    try:
        path = beneath(owner, path)
    except ValueError as exc:
        raise Blocked(f"dependency orchestration: {label} path is not run-owned") from exc
    present = path.is_dir() if directory else path.is_file()
    if not present or path.is_symlink():
        raise Blocked(f"dependency orchestration: {label} is absent or linked")
    return path


def _offline_registry(value: Any) -> Path:
    if not isinstance(value, str) or not value:
        raise Blocked("dependency orchestration: offline snapshot registry is required")
    configured = Path(value)
    if not configured.is_absolute() or not configured.is_dir() or configured.is_symlink():
        raise Blocked("dependency orchestration: offline snapshot registry is absent or linked")
    return configured.resolve()


def _binding_paths(payload: dict[str, Any], owner: Path, kind: str) -> None:
    for key in ("build_index", "native_build", "base_image_inventory", "sbom", "license", "sca"):
        if key not in payload or (key in _OPTIONAL_BINDINGS and (payload[key] is None or set(payload[key]) == {"skipped"})):
            continue
        binding = payload[key]
        if not isinstance(binding, dict):
            raise Blocked(f"dependency orchestration: {key} binding is invalid")
        _owned(binding.get("path"), owner, key)
        _owned(binding.get("accepted_path"), owner, key + " accepted pointer")
    if kind == "lifecycle":
        _owned(payload.get("reference_table"), owner, "reference table")
    if kind == "reachability":
        _owned(payload.get("reachability_evidence"), owner, "reachability evidence")


def _osv_applicability(sbom_binding: dict[str, Any]) -> dict[str, Any]:
    """Derive OSV Scanner's accepted input class from the exact bound SBOM.

    OSV Scanner's CycloneDX path can only identify components carrying package URLs.  A present
    SBOM with zero such components is therefore a per-tool non-applicability result, not a reason
    to skip Grype or the enclosing SCA lifecycle job.
    """
    path = Path(sbom_binding["path"])
    expected = sbom_binding.get("sha256")
    if expected != "sha256:" + file_hash(path):
        raise Blocked("dependency orchestration: SBOM changed before OSV applicability evaluation")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise Blocked("dependency orchestration: SBOM is unreadable for OSV applicability evaluation") from None
    components = document.get("components") if isinstance(document, dict) else None
    if not isinstance(components, list) or any(not isinstance(item, dict) for item in components):
        raise Blocked("dependency orchestration: SBOM components are invalid for OSV applicability evaluation")
    refs = sorted(item.get("component_id") for item in components if isinstance(item.get("purl"), str) and item["purl"])
    if any(not isinstance(ref, str) for ref in refs):
        raise Blocked("dependency orchestration: purl-bearing SBOM component lacks an identity")
    return {"decision": "EXECUTE" if refs else "SKIPPED_NA",
            "reason": None if refs else "no-purl-bearing-components",
            "examined_component_count": len(components), "purl_component_count": len(refs),
            "purl_component_refs": refs}


def _canonical_attempt(value: str, owner: Path, job_id: str) -> Path:
    path = Path(value).absolute()
    expected_parent = data_path(owner.name, "jobs", job_id, "orchestration-attempts").absolute()
    if path.parent != expected_parent:
        raise Blocked("dependency orchestration: attempt root is not the canonical run-owned path")
    identifier(path.name)
    try:
        beneath(owner, path.parent)
    except ValueError as exc:
        raise Blocked("dependency orchestration: attempt root is not run-owned") from exc
    return path


def _reuse_or_prepare(attempt: Path, request_path: Path) -> Path | None:
    resolved = attempt / "worker-request.json"
    metadata = attempt / "orchestration-input.json"
    if not attempt.exists():
        attempt.mkdir(parents=True)
        atomic_json(metadata, {"input_path": str(request_path), "input_sha256": "sha256:" + file_hash(request_path)})
        return None
    if attempt.is_symlink() or not attempt.is_dir() or not resolved.is_file() or resolved.is_symlink():
        raise Blocked("dependency orchestration: incomplete prior orchestration attempt")
    try:
        recorded = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Blocked("dependency orchestration: prior input identity is unreadable") from None
    if recorded != {"input_path": str(request_path), "input_sha256": "sha256:" + file_hash(request_path)}:
        raise Blocked("dependency orchestration: orchestration attempt input changed")
    return resolved


def execute(*, job_id: str, run_id: str, input_path: str, output_root: str,
            attempt_root: str) -> dict[str, Any]:
    """Run one dependency job from closed config and explicit paths."""
    if job_id not in JOBS:
        raise Blocked("dependency orchestration: unknown lifecycle job")
    run_id = identifier(run_id)
    owner = run_path(run_id).absolute()
    request_path = _owned(input_path, owner, "input request")
    expected_output = data_path(run_id, "jobs").absolute()
    selected_output = Path(output_root).absolute()
    try:
        selected_output = beneath(owner, selected_output)
    except ValueError as exc:
        raise Blocked("dependency orchestration: output root is not run-owned") from exc
    if selected_output != expected_output:
        raise Blocked("dependency orchestration: output root is not the canonical jobs root")
    attempt = _canonical_attempt(attempt_root, owner, job_id)

    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise Blocked("dependency orchestration: input request is unreadable") from None
    legacy = (isinstance(request, dict) and set(request) == _LEGACY_REQUEST_KEYS and
              request.get("schema") == LEGACY_REQUEST_SCHEMA)
    if not isinstance(request, dict) or (set(request) != _REQUEST_KEYS and not legacy):
        raise Blocked("dependency orchestration: request shape is not closed")
    if ((request.get("schema") != REQUEST_SCHEMA and not legacy) or request.get("run_id") != run_id or
            request.get("job_id") != job_id):
        raise Blocked("dependency orchestration: request identity is invalid")
    manifest = owner / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise Blocked("dependency orchestration: run artifact manifest is unavailable")
    generation = "sha256:" + file_hash(manifest)
    if request.get("source_generation") != generation:
        raise Blocked("dependency orchestration: request source generation is stale")
    source_tree = None
    if not legacy:
        source_tree, _binding, _files = automatic_inputs.source_projection(run_id)
        automatic_inputs.validate_source_projection(run_id, source_tree, request.get("source_binding"))

    kind = JOBS[job_id]
    payload, tool = request.get("payload"), request.get("tool")
    optional = _OPTIONAL_PAYLOAD_KEYS.get(kind, set())
    if not isinstance(payload, dict) or set(payload) - optional != _PAYLOAD_KEYS[kind]:
        raise Blocked("dependency orchestration: worker payload shape is not closed")
    expected_tool_keys = _LEGACY_TOOL_KEYS[kind] if legacy else _TOOL_KEYS[kind]
    if not isinstance(tool, dict) or set(tool) != expected_tool_keys:
        raise Blocked("dependency orchestration: tool config shape is not closed")
    _binding_paths(payload, owner, kind)

    job_root = selected_output / job_id
    content = reuse_inputs(kind, job_id, run_id, request, generation) if kind in REUSABLE and not legacy else None
    if content is not None:
        reused = producer_reuse.admit(job_root, content, run_id=run_id, job_id=job_id,
                                      verify=lambda _attempt, _pointer, _record: _still_current(kind, request))
        if reused is not None:
            return read_json(job_root / "attempts" / reused["attempt_id"] / "result.json")

    def remember(envelope: dict[str, Any]) -> dict[str, Any]:
        pointer_path = job_root / "accepted.json"
        if content is not None and pointer_path.is_file() and not pointer_path.is_symlink():
            pointer = read_json(pointer_path)
            if isinstance(pointer, dict) and pointer.get("attempt_id") == envelope.get("attempt_id"):
                producer_reuse.remember(job_root, content, pointer, run_id=run_id, job_id=job_id)
        return envelope

    resolved = _reuse_or_prepare(attempt, request_path)
    if resolved is not None:
        return remember(workers.run(kind, resolved))

    worker_request = {"run_id": run_id, "source_snapshot_sha256": generation,
                      "generated_at": request["generated_at"], "output_root": str(selected_output), **payload}
    try:
        if kind in {"sbom", "license"}:
            target = _owned(tool["target_path"], owner, "target", directory=True)
            if not legacy and target.resolve() != source_tree.resolve():
                raise Blocked("dependency orchestration: target differs from the accepted source projection")
            adapter_kind = "syft" if kind == "sbom" else "scancode"
            b13_root = attempt / "b13" / adapter_kind
            b13_root.mkdir(parents=True)
            result = b13.execute(adapter_kind, run_id=run_id,
                adapter_attempt_id=attempt.name + "-" + adapter_kind,
                source_snapshot_sha256=generation, attempt_root=b13_root, target=target)
            worker_request["b13_attempt"] = result["b13_attempt"]
        elif kind == "sca":
            sbom_root = _owned(tool["sbom_root"], owner, "SBOM root", directory=True)
            if Path(payload["sbom"]["path"]).parent.resolve() != sbom_root.resolve():
                raise Blocked("dependency orchestration: SBOM root differs from the accepted SBOM binding")
            registry = _offline_registry(tool["snapshot_registry"])
            max_age = tool["max_database_age_seconds"]
            if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
                raise Blocked("dependency orchestration: explicit non-negative database age ceiling is required")
            expected_by_kind = None
            if not legacy:
                expected_identities = tool["snapshot_identities"]
                if (not isinstance(expected_identities, list) or len(expected_identities) != 2 or
                        any(not isinstance(item, dict) for item in expected_identities)):
                    raise Blocked("dependency orchestration: exact offline snapshot identities are required")
                expected_by_kind = {item.get("database_kind"): item for item in expected_identities}
                if set(expected_by_kind) != {"grype-db", "osv"}:
                    raise Blocked("dependency orchestration: offline snapshot identities are incomplete")
            applicability = _osv_applicability(payload["sbom"])
            identities = []
            for adapter_kind in ("grype", "osv"):
                b13_root = attempt / "b13" / adapter_kind
                if adapter_kind == "osv" and applicability["decision"] == "SKIPPED_NA":
                    result = b13.resolve_registered_snapshot("osv", snapshot_registry=registry,
                        max_age_seconds=max_age,
                        now=datetime.fromisoformat(request["generated_at"].replace("Z", "+00:00")))
                else:
                    b13_root.mkdir(parents=True)
                    result = b13.execute_registered(adapter_kind, snapshot_registry=registry,
                        max_age_seconds=max_age, run_id=run_id,
                        adapter_attempt_id=attempt.name + "-" + adapter_kind,
                        source_snapshot_sha256=generation, attempt_root=b13_root, sbom_root=sbom_root)
                    worker_request[("osv_" if adapter_kind == "osv" else "") + "b13_attempt"] = result["b13_attempt"]
                if expected_by_kind is not None and result["database"] != expected_by_kind.get(result["database"].get("database_kind")):
                    raise Blocked("dependency orchestration: offline snapshot changed after input construction")
                identities.append(result["database"])
            worker_request.update(databases=identities, max_database_age_seconds=max_age,
                                  osv_applicability=applicability)
        resolved = attempt / "worker-request.json"
        atomic_json(resolved, worker_request)
        return remember(workers.run(kind, resolved))
    except (b13.AdapterBlocked, workers.WorkerBlocked) as exc:
        raise Blocked(str(exc)) from exc
