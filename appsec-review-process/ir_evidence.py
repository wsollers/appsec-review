"""Nominal E04/E05 LLVM IR evidence workers.

The workers preserve exact accepted-attempt lineage and publish compiler-derived evidence only.
They do not assert vulnerabilities, severity, reachability, or runtime behavior.  Container/Dagster
binding and recovery qualification remain integration work.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
import shlex
from typing import Any, Protocol

from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path, tree_hashes
import intake
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
from worker_result import validate_worker_result

NATIVE_JOB = "02-native-build"
JOBS = {
    "02-ir-capture": ("ir-capture.json", "ir-capture.schema.json", "ir-capture"),
    "02-ir-link": ("ir-link.json", "ir-link.schema.json", "ir-link"),
    "02-ir-facts": ("ir-facts.json", "ir-facts.schema.json", "ir-facts"),
}
PERMISSIONS = {"02-ir-capture": ["read-source", "write-run-data"],
               "02-ir-link": ["read-run-data", "write-run-data"],
               "02-ir-facts": ["read-run-data", "write-run-data"]}
PROHIBITED = {"finding", "findings", "severity", "vulnerability", "verdict", "runtime_state"}
TOOLCHAIN_FACTORY = None  # serialized integration binds the pinned B13 adapter


def _sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def _relative(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Blocked("IR evidence path is not normalized and relative")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise Blocked("IR evidence path is not normalized and relative")
    path = root.joinpath(*pure.parts)
    if path.is_symlink():
        raise Blocked("IR evidence path is a symbolic link")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise Blocked("IR evidence path escapes its attempt") from exc
    return path


def _accepted(run_id: str, job: str, artifact: str, schema: str,
              contract: str | None = None) -> tuple[Path, dict, dict]:
    base = data_path(run_id, "jobs", job)
    pointer_path = base / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked(f"{job}: accepted pointer is required")
    pointer = read_json(pointer_path)
    expected_pointer = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                        "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    latest_path = base / "latest.json"
    latest = read_json(latest_path) if latest_path.is_file() and not latest_path.is_symlink() else {}
    if (set(pointer) != expected_pointer or
            pointer.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            pointer.get("run_id") != run_id or pointer.get("job") != job or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            latest.get("attempt_id") != pointer.get("attempt_id")):
        raise Blocked(f"{job}: pointer is not a current accepted result")
    attempt = base / "attempts" / str(pointer.get("attempt_id", ""))
    envelope = attempt / str(pointer.get("envelope_path", ""))
    if (not attempt.is_dir() or attempt.is_symlink() or not envelope.is_file() or
            file_hash(envelope) != pointer.get("envelope_sha256") or
            tree_hashes(attempt) != pointer.get("hashes")):
        raise Blocked(f"{job}: accepted attempt or envelope changed")
    env = read_json(envelope)
    if (validate_worker_result(env) or env.get("schema") != "appsec-review/worker-result-envelope/1.0" or
            env.get("run_id") != run_id or env.get("attempt_id") != pointer["attempt_id"] or
            env.get("job_id") != job or env.get("acceptance_status") != "CURRENT" or
            env.get("execution_status") != pointer["status"] or
            env.get("input_fingerprint") != pointer.get("fingerprint") or
            pointer.get("envelope_path") != "result.json" or
            (contract is not None and env.get("output_contract") != contract)):
        raise Blocked(f"{job}: terminal envelope is invalid")
    published = {item["path"]: item["sha256"] for item in env["artifacts"]}
    for relative, expected in published.items():
        candidate = _relative(attempt, relative)
        if not candidate.is_file() or candidate.is_symlink() or file_hash(candidate) != expected:
            raise Blocked(f"{job}: accepted artifact changed: {relative}")
    result_path = _relative(attempt, artifact)
    if not result_path.is_file() or published.get(artifact) != file_hash(result_path):
        raise Blocked(f"{job}: {artifact} is not hash-bound by the accepted envelope")
    result = read_json(result_path)
    if validate_document(result, schema):
        raise Blocked(f"{job}: {artifact} fails its canonical schema")
    return attempt, result, {"job_id": job, "attempt_id": pointer["attempt_id"],
        "accepted_pointer_sha256": _sha(pointer_path), "envelope_sha256": _sha(envelope),
        "result_sha256": _sha(result_path), "input_fingerprint": pointer["fingerprint"]}


def _target(run_id: str) -> tuple[Path, str, str, str | None]:
    manifest = run_path(run_id) / "inputs/artifact-manifest.json"
    value = read_json(manifest).get("target", {}).get("repo_path") if manifest.is_file() else None
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked("IR capture requires an absolute real staged target")
    resolved = path.resolve(); identity = intake.source_identity(str(resolved))
    return resolved, _sha(manifest), "sha256:" + identity["fingerprint"], identity.get("revision")


def _require_current_source(run_id: str, value: dict[str, Any]) -> Path:
    target, snapshot, checkout, revision = _target(run_id)
    if (value.get("source_snapshot_sha256") != snapshot or
            value.get("checkout_identity_sha256") != checkout or
            (revision is not None and value.get("source_revision") != revision)):
        raise Blocked("IR evidence source/checkout generation is stale")
    return target


def _variant(unit: dict, entries: list[dict]) -> str:
    return "sha256:" + digest({"unit_id": unit["unit_id"], "image_id": unit["image_id"],
        "image_digest": unit["image_digest"], "compile_database": unit["compile_database"],
        "entries": entries})


def _source_path(target: Path, value: str) -> tuple[str, Path]:
    normalized = value.replace("\\", "/")
    prefix = "/scratch/src/"
    relative = normalized[len(prefix):] if normalized.startswith(prefix) else normalized
    path = _relative(target, relative)
    if not path.is_file():
        raise Blocked(f"compile entry source is missing: {relative}")
    return PurePosixPath(relative).as_posix(), path


class IrToolchain(Protocol):
    image_id: str
    image_digest: str
    toolchain_sha256: str
    def compile(self, argv: list[str], source: Path, destination: Path) -> int: ...
    def link(self, modules: list[Path], destination: Path) -> int: ...
    def disassemble(self, module: Path) -> str: ...


def _capture_argv(words: list[str], relative: str, module_path: str) -> list[str]:
    """Preserve accepted compile semantics while replacing only compiler/source/output actions."""
    result: list[str] = []
    skip = False
    source_forms = {relative, "/scratch/src/" + relative}
    for index, word in enumerate(words[1:]):
        if skip:
            skip = False; continue
        if word == "-o":
            skip = True; continue
        if word in {"-c", "-emit-llvm"} or word in source_forms:
            continue
        if word.startswith("/scratch/src/"):
            word = word.removeprefix("/scratch/src/")
        result.append(word)
    return [words[0], *result, "-emit-llvm", "-g", "-c", relative, "-o", module_path]


def capture(run_id: str, output: Path, *, toolchain: IrToolchain) -> dict:
    native_attempt, native, lineage = _accepted(
        run_id, NATIVE_JOB, "native-build.json", "native-build.schema.json", "native-build")
    target, source_snapshot, checkout_identity, revision = _target(run_id); modules=[]; gaps=[]; variants=[]
    native_inputs = read_json(native_attempt / "inputs.json")
    if native_inputs.get("source_snapshot_sha256") != source_snapshot:
        raise Blocked("native build source snapshot is stale")
    if revision is not None and native["source_revision"] != revision:
        raise Blocked("native build revision differs from the checkout")
    for unit in sorted(native["units"], key=lambda item: item["unit_id"]):
        db_path = _relative(native_attempt, unit["compile_database"]["path"])
        if not db_path.is_file() or _sha(db_path) != unit["compile_database"]["sha256"]:
            raise Blocked("native compile database is stale")
        entries = read_json(db_path)
        if not isinstance(entries, list) or len(entries) != unit["compile_database"]["entries"]:
            raise Blocked("native compile database entry count changed")
        variant = _variant(unit, entries); variants.append({"unit_id": unit["unit_id"],
            "variant_sha256": variant, "compile_database_sha256": _sha(db_path),
            "image_id": unit["image_id"], "image_digest": unit["image_digest"],
            "toolchain_sha256": toolchain.toolchain_sha256})
        if (toolchain.image_id != unit["image_id"] or toolchain.image_digest != unit["image_digest"]):
            raise Blocked("IR capture toolchain is not the accepted native-build image")
        for index, entry in enumerate(entries):
            words = entry.get("arguments") or shlex.split(entry.get("command", ""))
            if not words:
                gaps.append({"unit_id": unit["unit_id"], "compile_index": index,
                             "reason": "compile-entry-has-no-argv"}); continue
            relative, source = _source_path(target, entry.get("file", ""))
            module_id = "bc_" + digest({"unit": unit["unit_id"], "index": index,
                                         "source": relative, "variant": variant})[:16]
            destination = output / "modules" / f"{module_id}.bc"; destination.parent.mkdir(parents=True, exist_ok=True)
            logical_argv = _capture_argv(words, relative, f"modules/{module_id}.bc")
            if toolchain.compile(logical_argv, source, destination):
                gaps.append({"unit_id": unit["unit_id"], "compile_index": index,
                    "source_path": relative, "reason": "bitcode-capture-failed"}); continue
            if not destination.is_file() or destination.read_bytes()[:4] != b"BC\xc0\xde":
                raise RuntimeError("IR capture produced malformed LLVM bitcode")
            modules.append({"module_id": module_id, "unit_id": unit["unit_id"],
                "compile_index": index, "source_path": relative, "source_sha256": _sha(source),
                "compiler": words[0], "compiler_argv": logical_argv,
                "compiler_argv_sha256": "sha256:" + digest(logical_argv),
                "toolchain_sha256": toolchain.toolchain_sha256,
                "variant_sha256": variant, "path": destination.relative_to(output).as_posix(),
                "sha256": _sha(destination), "size_bytes": destination.stat().st_size})
    status = "OK" if modules and not gaps else "OK_WITH_GAPS"
    result = {"schema": "appsec-review/ir-capture/1", "run_id": run_id,
        "source_revision": native["source_revision"], "source_snapshot_sha256": source_snapshot,
        "checkout_identity_sha256": checkout_identity,
        "native_build": lineage,
        "variants": variants, "status": status, "modules": modules, "coverage_gaps": gaps}
    if validate_document(result, "ir-capture.schema.json"):
        raise RuntimeError("derived IR capture result is invalid")
    return result


def _verify_artifact(attempt: Path, record: dict, magic: bytes | None = None) -> Path:
    path = _relative(attempt, record["path"])
    if not path.is_file() or _sha(path) != record["sha256"]:
        raise Blocked("IR artifact hash changed")
    if magic is not None and path.read_bytes()[:len(magic)] != magic:
        raise Blocked("IR artifact is malformed")
    return path


def link(run_id: str, output: Path, *, toolchain: IrToolchain) -> dict:
    capture_attempt, captured, lineage = _accepted(
        run_id, "02-ir-capture", "ir-capture.json", "ir-capture.schema.json", "ir-capture")
    _require_current_source(run_id, captured)
    if not captured["modules"]:
        raise Blocked("IR link refuses zero captured modules")
    variants = {item["variant_sha256"] for item in captured["modules"]}
    toolchains = {item["toolchain_sha256"] for item in captured["modules"]}
    images = {(item["image_id"], item["image_digest"]) for item in captured["variants"]}
    if len(variants) != 1 or len(toolchains) != 1 or len(images) != 1:
        raise Blocked("IR link refuses mixed variants, toolchains, or native images")
    image_id, image_digest = next(iter(images))
    if ((toolchain.image_id, toolchain.image_digest) != (image_id, image_digest) or
            toolchain.toolchain_sha256 != next(iter(toolchains))):
        raise Blocked("IR link toolchain differs from capture")
    paths = [_verify_artifact(capture_attempt, item, b"BC\xc0\xde") for item in captured["modules"]]
    linked = output / "linked" / "application.bc"; linked.parent.mkdir(parents=True, exist_ok=True)
    if toolchain.link(paths, linked) or not linked.is_file() or linked.read_bytes()[:4] != b"BC\xc0\xde":
        raise RuntimeError("LLVM module link failed or produced malformed bitcode")
    result = {"schema": "appsec-review/ir-link/1", "run_id": run_id,
        "source_revision": captured["source_revision"],
        "source_snapshot_sha256": captured["source_snapshot_sha256"],
        "checkout_identity_sha256": captured["checkout_identity_sha256"], "capture": lineage,
        "variant_sha256": next(iter(variants)), "toolchain_sha256": next(iter(toolchains)),
        "image_id": image_id, "image_digest": image_digest,
        "module_set_sha256": "sha256:" + digest([(x["module_id"], x["sha256"]) for x in captured["modules"]]),
        "status": "OK_WITH_GAPS" if captured["coverage_gaps"] else "OK",
        "linked_module": {"path": linked.relative_to(output).as_posix(), "sha256": _sha(linked),
                          "size_bytes": linked.stat().st_size,
                          "input_module_ids": [x["module_id"] for x in captured["modules"]]},
        "sources": [{"module_id": x["module_id"], "path": x["source_path"],
                     "sha256": x["source_sha256"]} for x in captured["modules"]],
        "coverage_gaps": captured["coverage_gaps"]}
    if validate_document(result, "ir-link.schema.json"):
        raise RuntimeError("derived IR link result is invalid")
    return result


def facts(run_id: str, output: Path, *, toolchain: IrToolchain) -> dict:
    link_attempt, linked, lineage = _accepted(run_id, "02-ir-link", "ir-link.json", "ir-link.schema.json", "ir-link")
    _require_current_source(run_id, linked)
    if (toolchain.toolchain_sha256 != linked["toolchain_sha256"] or
            toolchain.image_id != linked["image_id"] or toolchain.image_digest != linked["image_digest"]):
        raise Blocked("IR facts toolchain differs from link")
    module = _verify_artifact(link_attempt, linked["linked_module"], b"BC\xc0\xde")
    try:
        ir_text = toolchain.disassemble(module)
    except Exception as exc:
        raise RuntimeError("linked LLVM module cannot be decoded")
    records=[]; debug_locations=[]
    current_function = None
    for line_number, line in enumerate(ir_text.splitlines(), 1):
        definition = re.search(r"^define\b.*@([^ (]+)\(", line)
        if definition: current_function = definition.group(1)
        if line.strip() == "}": current_function = None
        location = re.search(r"!(\d+) = !DILocation\(line: (\d+), column: (\d+)", line)
        if location:
            debug_locations.append({"debug_location_id": location.group(1),
                                    "source_line": int(location.group(2)),
                                    "source_column": int(location.group(3))})
        kind = ("pointer-arithmetic" if "getelementptr" in line else
                "memory-read" if re.search(r"\bload\b", line) else
                "memory-write" if re.search(r"\bstore\b", line) else
                "memory-intrinsic" if "llvm.mem" in line else None)
        if kind:
            records.append({"fact_id": "fact_" + digest({"line": line_number, "text": line.strip()})[:16],
                "kind": kind, "ir_line": line_number,
                "function": current_function, "module_id": linked["linked_module"]["path"],
                "debug_location_id": (re.search(r"!dbg !(\d+)", line).group(1)
                                      if re.search(r"!dbg !(\d+)", line) else None)})
    result = {"schema": "appsec-review/ir-facts/1", "run_id": run_id,
        "source_revision": linked["source_revision"],
        "source_snapshot_sha256": linked["source_snapshot_sha256"],
        "checkout_identity_sha256": linked["checkout_identity_sha256"], "link": lineage,
        "linked_module_sha256": linked["linked_module"]["sha256"],
        "variant_sha256": linked["variant_sha256"], "toolchain_sha256": linked["toolchain_sha256"],
        "image_id": linked["image_id"], "image_digest": linked["image_digest"],
        "sources": linked["sources"], "status": linked["status"],
        "debug_locations": debug_locations, "facts": records,
        "coverage_gaps": linked["coverage_gaps"]}
    if any(key in json.dumps(result).lower() for key in PROHIBITED):
        raise RuntimeError("IR facts attempted a prohibited verdict promotion")
    if validate_document(result, "ir-facts.schema.json"):
        raise RuntimeError("derived IR facts result is invalid")
    return result


def _code_hashes(job: str) -> dict[str, str]:
    wrapper = job.replace("02-", "").replace("-", "_") + ".py"
    result = {name: file_hash(ROOT / name) for name in (
        "ir_evidence.py", wrapper, "publish_job_output.py", "worker_result.py", "validate_job_output.py",
        f"registry/job-templates/{job}.json",
        f"registry/output-contracts/{JOBS[job][2]}.json")}
    consumed = {"02-ir-capture": "native-build.schema.json",
                "02-ir-link": "ir-capture.schema.json",
                "02-ir-facts": "ir-link.schema.json"}[job]
    for name in (JOBS[job][1], consumed, "ir-upstream-lineage.schema.json"):
        result["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return result


def current_inputs(run_id: str, job: str) -> dict[str, Any]:
    if job == "02-ir-capture":
        attempt, result, lineage = _accepted(run_id, NATIVE_JOB, "native-build.json", "native-build.schema.json")
        target, source, checkout, revision = _target(run_id)
        detail = {"upstream": lineage, "source_snapshot_sha256": source,
                  "checkout_identity_sha256": checkout, "source_revision": revision,
                  "target_path": str(target), "native_result_sha256": lineage["result_sha256"],
                  "compile_databases": [(unit["unit_id"], unit["compile_database"]["sha256"])
                                        for unit in result["units"]]}
    elif job == "02-ir-link":
        attempt, result, lineage = _accepted(run_id, "02-ir-capture", "ir-capture.json", "ir-capture.schema.json")
        _require_current_source(run_id, result)
        detail = {"upstream": lineage, "source_snapshot_sha256": result["source_snapshot_sha256"],
                  "modules": [(item["module_id"], item["sha256"]) for item in result["modules"]]}
    elif job == "02-ir-facts":
        attempt, result, lineage = _accepted(run_id, "02-ir-link", "ir-link.json", "ir-link.schema.json")
        _require_current_source(run_id, result)
        detail = {"upstream": lineage, "source_snapshot_sha256": result["source_snapshot_sha256"],
                  "linked_module_sha256": result["linked_module"]["sha256"]}
    else:
        raise ValueError(job)
    detail["build_lineage_sha256"] = "sha256:" + digest({
        "job": job, "source_snapshot_sha256": detail["source_snapshot_sha256"],
        "upstream": detail["upstream"]})
    return {"run_id": run_id, "job": job, **detail, "code": _code_hashes(job)}


def _producer_receipts(run_id: str, job: str, inputs: dict[str, Any]) -> tuple[dict, dict]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "permissions": PERMISSIONS[job]}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": run_id, "job_id": job,
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "build_lineage_sha256": inputs["build_lineage_sha256"]}
    return permission, lineage


def _validate_attempt(job: str, attempt: Path, inputs: dict[str, Any] | None = None) -> None:
    result_name, schema, _contract = JOBS[job]
    result = read_json(attempt / result_name)
    if validate_document(result, schema):
        raise Blocked(f"{job}: result schema validation failed")
    if job == "02-ir-capture":
        for item in result["modules"]:
            _verify_artifact(attempt, item, b"BC\xc0\xde")
    elif job == "02-ir-link":
        _verify_artifact(attempt, result["linked_module"], b"BC\xc0\xde")
    elif any(key in json.dumps(result).lower() for key in PROHIBITED):
        raise Blocked(f"{job}: result contains prohibited verdict language")
    if inputs is not None:
        expected = _producer_receipts(inputs["run_id"], job, inputs)
        if (read_json(attempt / "permission.json"), read_json(attempt / "lineage.json")) != expected:
            raise Blocked(f"{job}: F02 permission/lineage receipts changed")


def run_job(run_id: str, dagster_id: str, job: str, force: bool = False) -> dict[str, Any]:
    result_name, _schema, contract = JOBS[job]; base = data_path(run_id, "jobs", job)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if current_inputs(run_id, job) != inputs:
            raise Blocked(f"{job}: upstream or implementation changed before execution")
        attempt = allocation["attempt"]
        if TOOLCHAIN_FACTORY is None:
            raise Blocked(f"{job}: pinned B13 IR toolchain adapter is not integrated")
        toolchain = TOOLCHAIN_FACTORY(job, inputs, attempt)
        result = (capture(run_id, attempt, toolchain=toolchain) if job == "02-ir-capture" else
                  link(run_id, attempt, toolchain=toolchain) if job == "02-ir-link" else
                  facts(run_id, attempt, toolchain=toolchain))
        atomic_json(attempt / result_name, result)
        permission_receipt, lineage_receipt = _producer_receipts(run_id, job, inputs)
        atomic_json(attempt / "permission.json", permission_receipt)
        atomic_json(attempt / "lineage.json", lineage_receipt)
        (attempt / f"{contract}-summary.md").write_text(
            f"# {job}\n\n- status: {result['status']}\n- coverage gaps: {len(result['coverage_gaps'])}\n",
            encoding="utf-8")
        count_key = "modules" if job != "02-ir-facts" else "facts"
        count = (len(result["modules"]) if job == "02-ir-capture" else
                 len(result["linked_module"]["input_module_ids"]) if job == "02-ir-link" else
                 len(result["facts"]))
        status = {"process": job, "status": result["status"], count_key: count,
                  "coverage_gaps": len(result["coverage_gaps"]),
                  "qualification": "implemented_not_qualified", "run_id": run_id,
                  "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
                  "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        artifacts = [result_name, f"{contract}-summary.md", "status.json", "permission.json", "lineage.json"]
        if job == "02-ir-capture": artifacts.extend(item["path"] for item in result["modules"])
        elif job == "02-ir-link": artifacts.append(result["linked_module"]["path"])
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job,
            dagster_run_id=dagster_id, worker_kind="deterministic_python", output_contract=contract,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=result["status"], summary=f"Published nominal {job} evidence.",
            status_record=status, artifact_paths=artifacts,
            pre_envelope_validate=lambda path, _status: _validate_attempt(job, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job,
        dagster_run_id=dagster_id, worker_kind="deterministic_python", output_contract=contract,
        resume_command=f"integration required for {job}", derive_inputs=lambda: current_inputs(run_id, job),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(job)},
        force=force, post_validate=lambda attempt, _envelope, record: _validate_attempt(job, attempt, record),
        blocked_summary=f"{job} preflight did not complete.", failed_summary=f"{job} did not publish.")


def validate(run_id: str, job: str, pointer: dict[str, Any] | None = None) -> Path:
    base = data_path(run_id, "jobs", job); inputs = current_inputs(run_id, job)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=job)
    _validate_attempt(job, attempt, inputs); return attempt
