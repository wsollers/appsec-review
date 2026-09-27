"""Nominal, deterministic core for ``02-native-sast``.

The worker consumes one exact accepted ``02-native-build`` publication and runs the pinned
``audit-native`` image through B13.  It emits evidence leads only.  Live Dagster wiring,
reuse/recovery hardening and qualification intentionally remain integration work.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import threading
from typing import Any

import container_execution as ce
from execution_state import (Blocked, ROOT, atomic_json, data_path, digest, file_hash, now,
                             read_json)
import native_sast_adapters as adapters
import permission_capabilities as pc
from publish_job_output import (ACCEPTED_SCHEMA, coordinate_worker_lifecycle,
                                record_terminal_current, validate_published)
from schema_validate import validate_document

JOB = "02-native-sast"
UPSTREAM_JOB = "02-native-build"
CONTRACT = "native-sast"
RESULT = "native-sast.json"
RECEIPTS = "b13-receipts.json"
SUMMARY = "native-sast-summary.md"
SCHEMA = "appsec-review/native-sast/1"
PERMISSION_SCHEMA = "appsec-review/producer-permission-receipt/1.0"
LINEAGE_SCHEMA = "appsec-review/producer-lineage-receipt/1.0"
PERMISSIONS = ["read-run-data", "write-run-data", "execute-container-static-analysis"]
IMAGE_ID = "audit-native"
CONFIG = ROOT.parent / "data" / "native-sast" / "config-v1.json"
TOOLS = ("clang-tidy", "cppcheck", "clang-static-analyzer")
CODE_FILES = (
    "native_sast.py", "native_sast_adapters.py", "container_execution.py",
    "permission_capabilities.py", "publish_job_output.py", "validate_job_output.py",
    "registry/output-contracts/native-sast.json",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash(path: Path) -> str:
    return "sha256:" + file_hash(path)


def _source_tree_identity(target: Path) -> str:
    """Hash the actual post-build checkout bytes, excluding mutable Git administration data."""
    records: dict[str, dict[str, str]] = {}
    for current, dirs, files in os.walk(target, topdown=True, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(files):
            path = Path(current, name)
            relative = path.relative_to(target).as_posix()
            if path.is_symlink():
                records[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                records[relative] = {"kind": "file", "sha256": _hash(path)}
            else:
                raise Blocked(f"{JOB}: checkout contains a special file: {relative}")
    return "sha256:" + digest(records)


def _verify_source_tree(inputs: dict[str, Any]) -> None:
    target = Path(inputs["target_path"])
    if _source_tree_identity(target) != inputs.get("source_tree_sha256"):
        raise Blocked(f"{JOB}: post-build checkout bytes changed")


def _owned(root_path: Path, relative: str, label: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise Blocked(f"{JOB}: {label} path is not normalized")
    root_path = root_path.resolve()
    candidate = root_path.joinpath(*pure.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root_path)
    except (OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: {label} does not resolve beneath its immutable attempt") from exc
    relative_parts = candidate.relative_to(root_path).parts
    cursor = root_path
    has_symlink = False
    for part in relative_parts:
        cursor = cursor / part
        if cursor.is_symlink():
            has_symlink = True
            break
    if not resolved.is_file() or has_symlink:
        raise Blocked(f"{JOB}: {label} is not a regular file")
    return resolved


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values["data/native-sast/config-v1.json"] = file_hash(CONFIG)
    for name in ("native-sast.schema.json", "native-sast-upstream.schema.json",
                 "native-sast-unit.schema.json", "native-sast-tool.schema.json",
                 "native-sast-lead.schema.json", "native-sast-artifact.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _strict_pointer(pointer: dict[str, Any], run_id: str) -> None:
    expected = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if (set(pointer) != expected or pointer.get("schema") != ACCEPTED_SCHEMA or
            pointer.get("status") != "OK" or pointer.get("run_id") != run_id or
            pointer.get("job") != UPSTREAM_JOB or pointer.get("envelope_path") != "result.json"):
        raise Blocked(f"{JOB}: native-build pointer is not the exact accepted common shape")


def load_native_build(native_build_root: Path, *, run_id: str,
                      expected_fingerprint: str) -> dict[str, Any]:
    """Revalidate E02 and return the lineage plus exact compile databases used by E03."""
    native_build_root = native_build_root.resolve()
    pointer_path = _owned(native_build_root, "accepted.json", "native-build pointer")
    pointer = read_json(pointer_path)
    _strict_pointer(pointer, run_id)
    if pointer["fingerprint"] != expected_fingerprint:
        raise Blocked(f"{JOB}: native-build fingerprint differs from the caller-held identity")
    attempt, envelope = validate_published(
        native_build_root, pointer, expected_fingerprint,
        expected_run_id=run_id, expected_job_id=UPSTREAM_JOB)
    result_path = _owned(attempt, "native-build.json", "native-build result")
    result = read_json(result_path)
    if validate_document(result, "native-build.schema.json"):
        raise Blocked(f"{JOB}: native-build result schema failed")
    inputs = read_json(_owned(attempt, "inputs.json", "native-build inputs"))
    if (inputs.get("run_id") != run_id or inputs.get("job") != UPSTREAM_JOB or
            inputs.get("source_revision") != result.get("source_revision")):
        raise Blocked(f"{JOB}: native-build input/result lineage mismatch")
    source_snapshot = inputs.get("source_snapshot_sha256")
    target_value = inputs.get("target_path")
    if (not isinstance(source_snapshot, str) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", source_snapshot) or
            not isinstance(target_value, str)):
        raise Blocked(f"{JOB}: native-build lacks source lineage")
    target = Path(target_value)
    if not target.is_absolute() or not target.is_dir() or target.is_symlink():
        raise Blocked(f"{JOB}: native-build target is no longer a real checkout directory")
    artifact_hashes = {item.get("path"): "sha256:" + item.get("sha256", "")
                       for item in envelope["artifacts"]}
    units = []
    unit_ids: set[str] = set()
    for unit in result["units"]:
        if unit["unit_id"] in unit_ids:
            raise Blocked(f"{JOB}: native-build repeats a unit identity")
        unit_ids.add(unit["unit_id"])
        db_record = unit["compile_database"]
        db = _owned(attempt, db_record["path"], f"{unit['unit_id']} compile database")
        if (_hash(db) != db_record["sha256"] or artifact_hashes.get(db_record["path"]) != db_record["sha256"]):
            raise Blocked(f"{JOB}: native-build compile database hash/contract mismatch")
        raw = read_json(db)
        if len(raw) != db_record["entries"]:
            raise Blocked(f"{JOB}: native-build compile database entry count changed")
        try:
            adapted, unsupported = adapters.adapt_compile_database(raw)
        except adapters.AdapterError as exc:
            raise Blocked(f"{JOB}: native-build compile database rejected ({exc})") from exc
        sources = {}
        for entry in adapted:
            relative = entry["file"][len(adapters.WORKSPACE_PREFIX):]
            source = _owned(target, relative, f"translation unit {relative}")
            sources[relative] = _hash(source)
        commands_sha = "sha256:" + digest(unit["commands"])
        variant_id = "locked-" + digest({"unit_id": unit["unit_id"],
            "image_id": unit["image_id"], "image_digest": unit["image_digest"],
            "commands_sha256": commands_sha})[:16]
        units.append({"unit_id": unit["unit_id"], "build_variant": {
                          "variant_id": variant_id, "source": "accepted-native-build-unit",
                          "image_id": unit["image_id"], "image_digest": unit["image_digest"],
                          "commands_sha256": commands_sha},
                      "compile_database": {"path": db_record["path"],
                          "sha256": db_record["sha256"], "entries": db_record["entries"],
                          "adapted_path": f"adapted-inputs/{digest(unit['unit_id'])[:16]}/compile_commands.json",
                          "adapted_sha256": adapters.canonical_sha(adapted)},
                      "adapted": adapted, "unsupported": unsupported, "sources": sources})
    checkout_sha256 = _source_tree_identity(target.resolve())
    return {"attempt": attempt, "pointer": pointer, "envelope": envelope, "result": result,
            "inputs": inputs, "target": target.resolve(), "units": units,
            "binding": {"job_id": UPSTREAM_JOB, "attempt_id": pointer["attempt_id"],
                "fingerprint": pointer["fingerprint"], "pointer_sha256": _hash(pointer_path),
                "envelope_sha256": "sha256:" + pointer["envelope_sha256"],
                "result_sha256": _hash(result_path), "source_revision": result["source_revision"]},
            "source_snapshot_sha256": source_snapshot,
            "source_tree_sha256": checkout_sha256}


def current_inputs(run_id: str, *, native_build_root: Path,
                   native_build_fingerprint: str) -> dict[str, Any]:
    upstream = load_native_build(native_build_root, run_id=run_id,
                                 expected_fingerprint=native_build_fingerprint)
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    if IMAGE_ID not in registry:
        raise Blocked(f"{JOB}: {IMAGE_ID} has no current B16 record")
    config = read_json(CONFIG)
    return {"run_id": run_id, "job": JOB,
        "source_snapshot_sha256": upstream["source_snapshot_sha256"],
        "source_tree_sha256": upstream["source_tree_sha256"],
        "target_path": str(upstream["target"]), "native_build_root": str(Path(native_build_root).resolve()),
        "native_build": upstream["binding"],
        "units": [{key: value for key, value in unit.items() if key != "adapted"}
                  | {"adapted": unit["adapted"]} for unit in upstream["units"]],
        "image": registry[IMAGE_ID], "config": config,
        "config_sha256": _hash(CONFIG), "boundary_sha256": ce.boundary_sha256(),
        "code": _code_hashes()}


def _permission(run_id: str, source: str, at: str) -> dict[str, Any]:
    requirement = {"schema": "appsec-review/permission-requirement/1.0",
                   "job_id": JOB, "capabilities": []}
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": []}
    decision = pc.evaluate(requirement, [], context)
    pc.require_granted(decision, requirement=requirement, grants=[], context=context)
    return {"requirement": requirement, "grants": [], "decision": decision}


def _runtime(source: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=[], clock=_utc_now, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _request(run_id: str, adapter_id: str, inputs: dict[str, Any], unit: dict[str, Any],
             database_root: Path, tool_group: str) -> dict[str, Any]:
    db = f"/inputs/native-sast/{digest(unit['unit_id'])[:16]}/compile_commands.json"
    config = inputs["config"]
    if tool_group == "clang-cppcheck":
        argv = ["/opt/scripts/run_native_sast.py", "--compile-commands", db,
                "--out", "/scratch/native-sast", "--jobs", "1",
                "--timeout", str(config["timeout_seconds"]), "--checks", config["clang_tidy_checks"]]
    elif tool_group == "csa":
        argv = ["/opt/scripts/run_csa.py", "--compile-commands", db,
                "--out", "/scratch/csa", "--jobs", "1",
                "--timeout", str(config["timeout_seconds"]), "--no-codechecker"]
    else:  # pragma: no cover - closed internal call set
        raise ValueError(tool_group)
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB,
        "attempt_id": adapter_id,
        "image": {"image_id": inputs["image"]["image_id"], "digest": inputs["image"]["digest"]},
        "argv": argv,
        "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"},
                        {"name": "NO_COLOR", "value": "1"}],
        "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"},
                          {"host_path": str(database_root), "container_path": "/inputs/native-sast"}],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": _permission(run_id, inputs["source_snapshot_sha256"], _utc_now()),
        "limits": {"timeout_seconds": config["container_timeout_seconds"],
            "memory_bytes": 4 * 1024 * 1024 * 1024, "cpu_millis": 2000, "pids": 512,
            "tmpfs_bytes": 256 * 1024 * 1024, "stdout_limit_bytes": 1024 * 1024,
            "stderr_limit_bytes": 1024 * 1024}}


def _raw(path: Path, attempt: Path) -> dict[str, Any]:
    return {"path": path.relative_to(attempt).as_posix(), "sha256": _hash(path)}


def normalize_unit(unit: dict[str, Any], *, target: Path, attempt: Path,
                   clang_trial: Path, csa_trial: Path, inputs: dict[str, Any]) -> dict[str, Any]:
    clang_raw = read_json(clang_trial / "scratch/native-sast/findings-clang-tidy.json")
    native_manifest = read_json(clang_trial / "scratch/native-sast/native-sast-manifest.json")
    cpp_path = clang_trial / "scratch/native-sast/cppcheck.xml"
    csa_raw = read_json(csa_trial / "scratch/csa/findings-csa.json")
    csa_summary = read_json(csa_trial / "scratch/csa/csa-summary.json")
    raw_leads = (adapters.clang_tidy_leads(clang_raw, unit_id=unit["unit_id"], target=target) +
                 adapters.cppcheck_leads(cpp_path.read_text(encoding="utf-8"),
                                         unit_id=unit["unit_id"], target=target) +
                 adapters.csa_leads(csa_raw, unit_id=unit["unit_id"], target=target))
    by_id: dict[str, dict[str, Any]] = {}
    for lead in raw_leads:
        prior = by_id.setdefault(lead["lead_id"], lead)
        if prior != lead:
            raise adapters.AdapterError("native-SAST lead identity collision")
    leads = list(by_id.values())
    leads.sort(key=lambda item: (item["path"], item["start_line"], item["tool_id"], item["rule_id"]))
    supported = len(unit["adapted"])
    gaps = [f"unsupported-translation-unit:{path}" for path in unit["unsupported"]]
    tidy_failed = int(native_manifest["clang_tidy"]["files_nonzero_exit"])
    cpp_exit = int(native_manifest["cppcheck"]["exit_code"])
    csa_failed = int(csa_summary["tu_error"]) + int(csa_summary["tu_timeout"])
    if tidy_failed:
        gaps.append(f"clang-tidy-tool-error:{tidy_failed}-translation-units")
    if cpp_exit:
        gaps.append(f"cppcheck-tool-error:exit-{cpp_exit}")
    if csa_failed:
        gaps.append(f"clang-static-analyzer-tool-error:{csa_failed}-translation-units")
    config = inputs["config"]
    image = inputs["image"]
    tools = [
        {"tool_id": "clang-tidy", "tool": "clang-tidy", "version": config["tools"]["clang-tidy"],
         "image_id": image["image_id"], "image_digest": image["digest"],
         "config_sha256": inputs["config_sha256"], "status": "PARTIAL" if tidy_failed else "COMPLETE",
         "translation_units": supported, "analyzed_units": supported - tidy_failed,
         "records": len([x for x in leads if x["tool_id"] == "clang-tidy"]),
         "raw_evidence": [_raw(clang_trial / "scratch/native-sast/findings-clang-tidy.json", attempt),
                          _raw(clang_trial / "scratch/native-sast/clang-tidy.log", attempt)]},
        {"tool_id": "cppcheck", "tool": "cppcheck", "version": config["tools"]["cppcheck"],
         "image_id": image["image_id"], "image_digest": image["digest"],
         "config_sha256": inputs["config_sha256"], "status": "ERROR" if cpp_exit else "COMPLETE",
         "translation_units": supported, "analyzed_units": 0 if cpp_exit else supported,
         "records": len([x for x in leads if x["tool_id"] == "cppcheck"]),
         "raw_evidence": [_raw(cpp_path, attempt)]},
        {"tool_id": "clang-static-analyzer", "tool": "clang-static-analyzer",
         "version": config["tools"]["clang-static-analyzer"],
         "image_id": image["image_id"], "image_digest": image["digest"],
         "config_sha256": inputs["config_sha256"], "status": "PARTIAL" if csa_failed else "COMPLETE",
         "translation_units": supported, "analyzed_units": supported - csa_failed,
         "records": len([x for x in leads if x["tool_id"] == "clang-static-analyzer"]),
         "raw_evidence": [_raw(csa_trial / "scratch/csa/findings-csa.json", attempt),
                          _raw(csa_trial / "scratch/csa/csa-summary.json", attempt)]},
    ]
    return {"unit_id": unit["unit_id"], "build_variant": unit["build_variant"],
            "compile_database": unit["compile_database"], "tools": tools,
            "leads": leads, "coverage_gaps": sorted(gaps)}


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    if (inputs.get("code") != _code_hashes() or inputs.get("config") != read_json(CONFIG) or
            inputs.get("config_sha256") != _hash(CONFIG)):
        raise Blocked(f"{JOB}: implementation or analyzer configuration changed")
    _verify_source_tree(inputs)
    upstream = load_native_build(Path(inputs["native_build_root"]), run_id=run_id,
                                 expected_fingerprint=inputs["native_build"]["fingerprint"])
    if upstream["binding"] != inputs["native_build"] or upstream["units"] != inputs["units"]:
        raise Blocked(f"{JOB}: native-build publication, compile database, or source bytes changed")
    if upstream["source_tree_sha256"] != inputs["source_tree_sha256"]:
        raise Blocked(f"{JOB}: post-build checkout bytes changed")
    for unit in inputs["units"]:
        adapted_path = _owned(attempt, unit["compile_database"]["adapted_path"],
                              f"{unit['unit_id']} adapted compile database")
        if (read_json(adapted_path) != unit["adapted"] or
                _hash(adapted_path) != unit["compile_database"]["adapted_sha256"]):
            raise Blocked(f"{JOB}: adapted compile database changed")
    result = read_json(attempt / RESULT)
    if validate_document(result, "native-sast.schema.json"):
        raise Blocked(f"{JOB}: native-SAST result schema failed")
    if (result["source_snapshot_sha256"] != inputs["source_snapshot_sha256"] or
            result["native_build"] != inputs["native_build"]):
        raise Blocked(f"{JOB}: result lineage differs from the accepted native build")
    permission = {"schema": PERMISSION_SCHEMA, "run_id": run_id, "job_id": JOB,
        "source_snapshot_sha256": inputs["source_snapshot_sha256"], "permissions": PERMISSIONS}
    lineage = {"schema": LINEAGE_SCHEMA, "run_id": run_id, "job_id": JOB,
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "build_lineage_sha256": "sha256:" + digest(inputs["native_build"])}
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: evidence-assembly permission or lineage receipt changed")
    receipt = read_json(attempt / RECEIPTS)
    if not isinstance(receipt, list) or len(receipt) != 2 * len(inputs["units"]):
        raise Blocked(f"{JOB}: B13 receipt set is incomplete")
    runtime = _runtime(inputs["source_snapshot_sha256"])
    trials: dict[tuple[str, str], Path] = {}
    for item in receipt:
        trial = attempt / item["trial_path"]
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        errors = ce.verify_container_result(trial, run_id=run_id, job_id=JOB,
            attempt_id=item["adapter_attempt_id"], request=request, images_dir=runtime.images_dir,
            expected_result_sha256=item["expected_result_sha256"], **_host(runtime))
        if errors:
            raise Blocked(f"{JOB}: B13 evidence failed re-verification ({len(errors)} errors)")
        key = (item.get("unit_id"), item.get("tool_group"))
        if key in trials or key[0] not in {unit["unit_id"] for unit in inputs["units"]} or key[1] not in {"clang-cppcheck", "csa"}:
            raise Blocked(f"{JOB}: B13 receipt identity is duplicate or unknown")
        trials[key] = trial
    try:
        expected_units = [normalize_unit(unit, target=Path(inputs["target_path"]), attempt=attempt,
            clang_trial=trials[(unit["unit_id"], "clang-cppcheck")],
            csa_trial=trials[(unit["unit_id"], "csa")], inputs=inputs)
            for unit in inputs["units"]]
    except (KeyError, OSError, ValueError) as exc:
        raise Blocked(f"{JOB}: normalized raw evidence cannot be re-derived ({exc})") from exc
    expected_gaps = sorted(gap for unit in expected_units for gap in unit["coverage_gaps"])
    expected = {"schema": SCHEMA, "run_id": run_id, "job_id": JOB,
        "attempt_id": attempt.name, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "native_build": inputs["native_build"], "status": "OK_WITH_GAPS" if expected_gaps else "OK",
        "units": expected_units, "coverage_gaps": expected_gaps}
    if result != expected:
        raise Blocked(f"{JOB}: normalized result differs from its immutable raw analyzer evidence")


def run(run_id: str, dagster_id: str, *, native_build_root: Path,
        native_build_fingerprint: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = (f"native_sast.run({run_id!r}, <dagster-id>, native_build_root=<path>, "
              "native_build_fingerprint=<sha256>)")

    def derive() -> dict[str, Any]:
        return current_inputs(run_id, native_build_root=native_build_root,
                              native_build_fingerprint=native_build_fingerprint)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str):
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        database_root = attempt / "adapted-inputs"
        units_by_id = {unit["unit_id"]: unit for unit in inputs["units"]}
        for unit in inputs["units"]:
            folder = database_root / digest(unit["unit_id"])[:16]
            folder.mkdir(parents=True)
            atomic_json(folder / "compile_commands.json", unit["adapted"])
        receipts, normalized = [], []
        for ordinal, unit in enumerate(inputs["units"]):
            trials = {}
            for group in ("clang-cppcheck", "csa"):
                adapter_id = f"n{ordinal}-{group}"
                trial = attempt / "tools" / digest(unit["unit_id"])[:16] / group
                trial.mkdir(parents=True)
                runtime = _runtime(inputs["source_snapshot_sha256"])
                request = _request(run_id, adapter_id, inputs, unit, database_root, group)
                terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB,
                    attempt_id=adapter_id, attempt_root=trial, request=request)
                expected = terminal["result_sha256"]
                ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                    request=request, images_dir=runtime.images_dir,
                    expected_result_sha256=expected, **_host(runtime))
                if terminal["execution_status"] != "OK":
                    raise RuntimeError(f"{JOB}: {group} adapter ended {terminal['execution_status']}")
                receipts.append({"unit_id": unit["unit_id"], "tool_group": group,
                    "adapter_attempt_id": adapter_id, "trial_path": trial.relative_to(attempt).as_posix(),
                    "expected_result_sha256": expected})
                trials[group] = trial
            normalized.append(normalize_unit(units_by_id[unit["unit_id"]],
                target=Path(inputs["target_path"]), attempt=attempt,
                clang_trial=trials["clang-cppcheck"], csa_trial=trials["csa"], inputs=inputs))
        gaps = sorted(gap for unit in normalized for gap in unit["coverage_gaps"])
        result = {"schema": SCHEMA, "run_id": run_id, "job_id": JOB,
            "attempt_id": allocation["attempt_id"],
            "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "native_build": inputs["native_build"],
            "status": "OK_WITH_GAPS" if gaps else "OK", "units": normalized,
            "coverage_gaps": gaps}
        atomic_json(attempt / RESULT, result)
        atomic_json(attempt / RECEIPTS, receipts)
        atomic_json(attempt / "permission.json", {"schema": PERMISSION_SCHEMA, "run_id": run_id,
            "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "permissions": PERMISSIONS})
        atomic_json(attempt / "lineage.json", {"schema": LINEAGE_SCHEMA, "run_id": run_id,
            "job_id": JOB, "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "build_lineage_sha256": "sha256:" + digest(inputs["native_build"])})
        (attempt / SUMMARY).write_text(
            "# Native SAST\n\n" +
            f"- Units: {len(normalized)}\n- Evidence leads: {sum(len(x['leads']) for x in normalized)}\n"
            f"- Coverage gaps: {len(gaps)}\n- Qualification: nominal core only.\n", encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id,
            "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
            "source_snapshot_sha256": inputs["source_snapshot_sha256"],
            "native_build_attempt_id": inputs["native_build"]["attempt_id"],
            "build_variants": sorted(x["build_variant"]["variant_id"] for x in normalized),
            "tools_run": list(TOOLS), "leads": sum(len(x["leads"]) for x in normalized),
            "network": "none", "qualification": "implemented_not_qualified", "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        artifacts = [RESULT, RECEIPTS, SUMMARY, "status.json", "permission.json", "lineage.json"]
        artifacts.extend(unit["compile_database"]["adapted_path"] for unit in inputs["units"])
        for item in receipts:
            trial = attempt / item["trial_path"]
            for path in sorted(trial.rglob("*")):
                if path.is_file():
                    artifacts.append(path.relative_to(attempt).as_posix())
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_id, worker_kind="pinned_container", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=result["status"],
            summary=f"Three pinned native analyzers produced {status['leads']} evidence lead(s).",
            status_record=status, artifact_paths=artifacts, gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB,
        dagster_run_id=dagster_id, worker_kind="pinned_container", output_contract=CONTRACT,
        resume_command=resume, derive_inputs=derive,
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, record:
            _validate_attempt(run_id, attempt, record),
        blocked_summary="Native SAST preflight rejected missing, stale, or mismatched build evidence.",
        failed_summary="Native SAST did not publish.")


def validate(run_id: str, *, native_build_root: Path, native_build_fingerprint: str,
             pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    inputs = current_inputs(run_id, native_build_root=native_build_root,
                            native_build_fingerprint=native_build_fingerprint)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
        expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, inputs)
    return attempt
