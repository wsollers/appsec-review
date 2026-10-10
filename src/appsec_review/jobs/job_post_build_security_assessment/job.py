from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import shlex
import time
from typing import Any

from appsec_review.jobs.cpp_index_scopes import load_accepted_cpp
from appsec_review.inference import Infer, ModelRequest
from appsec_review.observability import PipelineLog, emit_model_event
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .assessment import (
    GUIDANCE_IDENTITY, NORMALIZER_VERSION, PARSER_VERSION, PROVENANCE_SCHEMA, RULE_VERSION,
    INFERENCE_PROPOSAL_SCHEMA, SCHEMA, command_fingerprint, deterministic_checks, inspect_binary,
    normalize_action, shard_fingerprint, validate_inference,
)

PROJECT_TASKS = ("native_units",)
TOPOLOGY = {
    "load": ("accepted_cpp_build",),
    "provenance": PROJECT_TASKS,
    "inspection": PROJECT_TASKS,
    "deterministic": PROJECT_TASKS,
    "inference": PROJECT_TASKS,
    "index": PROJECT_TASKS,
    "publication": ("publish_handoff",),
}


def _artifact(run_root: Path, path: Path, value: Any | None = None) -> dict[str, Any]:
    if value is not None:
        atomic_json(path, value)
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _read_json_artifact(run_root: Path, identity: Mapping[str, Any]) -> Any:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted upstream artifact identity changed")
    return json.loads(path.read_text(encoding="utf-8"))


def _case_root(unit: UnitContext, case_id: str) -> Path:
    root = (unit.job.run_root / "data" / "cpp" / "projects" / case_id).resolve()
    if unit.job.run_root.resolve() not in root.parents:
        raise ValueError("case root escapes the run")
    return root


def _display(case_id: str) -> str:
    return case_id


def _stage_case(unit: UnitContext, stage: str, case_id: str) -> Mapping[str, Any]:
    value = unit.output(f"{stage}.native_units").get("projects", {}).get(case_id)
    if not isinstance(value, Mapping):
        raise ValueError(f"post-build {stage} output is unavailable for {case_id}")
    return value


def _raw_rows(root: Path) -> list[Mapping[str, Any]]:
    candidates = (root / "build" / "compile_commands.json", root / "source" / "compile_commands.json")
    path = next((item for item in candidates if item.is_file() and not item.is_symlink()), None)
    if path is None or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("bounded raw compile database is unavailable")
    rows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or len(rows) > 4096 or any(not isinstance(item, Mapping) for item in rows):
        raise ValueError("raw compile database is invalid")
    return rows


def _link_rows(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((root / "build").rglob("link.txt"))[:4096]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:100]:
            if line.strip():
                rows.append({"command": line, "directory": str(path.parent), "origin": path.relative_to(root).as_posix()})
    return rows


def _argv(row: Mapping[str, Any]) -> list[str]:
    if isinstance(row.get("argv"), list):
        return [str(item) for item in row["argv"]]
    if isinstance(row.get("arguments"), list):
        return [str(item) for item in row["arguments"]]
    return shlex.split(str(row.get("command", "")), posix=True)


def _case_catalog(unit: UnitContext, case_id: str) -> Mapping[str, Any]:
    cases = unit.output("load.accepted_cpp_build")["cases"]
    value = cases.get(case_id)
    if not isinstance(value, Mapping):
        raise ValueError(f"accepted C++ catalog is unavailable for {case_id}")
    return value


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("post-build security topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"post-build security task order mismatch: {step}")
    settings = context.config.settings
    model = settings.get("model")
    required = {"enabled", "provider", "model", "reasoning", "max_input_tokens",
                "max_output_tokens", "timeout_seconds", "retries"}
    if not isinstance(model, Mapping) or not required <= set(model):
        raise ValueError("post-build model settings are incomplete")
    if type(model["enabled"]) is not bool:
        raise ValueError("post-build model enabled setting must be boolean")
    for key in ("max_input_tokens", "max_output_tokens", "timeout_seconds"):
        if type(model[key]) is not int or model[key] < 1:
            raise ValueError(f"post-build model bound is invalid: {key}")
    if type(model["retries"]) is not int or not 0 <= model["retries"] <= 5:
        raise ValueError("post-build model retries must be between zero and five")


def build_job(*, infer: Infer | None = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted = load_accepted_cpp(unit.job.run_root)
        if accepted["handoff"].get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("post-build target snapshot differs from accepted build")
        cases = {}
        catalogs = accepted["result"].get("outputs", {}).get("catalog.projects", {}).get("projects", {})
        for case_id, catalog in catalogs.items():
            if catalog.get("terminal_status") in {"SUCCEEDED", "NOT_APPLICABLE"}:
                cases[case_id] = dict(catalog)
            else:
                cases[case_id] = {"terminal_status": catalog.get("terminal_status", "UNAVAILABLE"),
                                  "gaps": list(catalog.get("gaps", ())) or ["accepted build catalog is unavailable"]}
        unit.job.events.write("BUILD_SECURITY_ACCEPTED_BUILD_LOADED",
                              upstream_handoff_sha256=accepted["handoff_sha256"], case_count=len(cases))
        return {"schema": SCHEMA, "cases": cases, "upstream_handoff_sha256": accepted["handoff_sha256"],
                "upstream_manifest": accepted["manifest"], "terminal_status": "SUCCEEDED"}

    def aggregate(factory):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            projects = {}
            for case_id in sorted(unit.output("load.accepted_cpp_build")["cases"]):
                project_root = unit.unit_root / ("p-" + hashlib.sha256(case_id.encode()).hexdigest()[:12])
                project_root.mkdir(parents=True, exist_ok=True)
                child = UnitContext(unit.job, unit.unit_id, unit.step_id, case_id,
                                    project_root, unit.outputs)
                projects[case_id] = factory(case_id)(child)
            gaps = [gap for value in projects.values() for gap in value.get("gaps", ())]
            return {"projects": projects, "project_count": len(projects), "gaps": gaps,
                    "terminal_status": "COMPLETED_WITH_GAPS" if gaps else
                    "SUCCEEDED" if projects else "NOT_APPLICABLE"}
        return handler

    def provenance(case_id: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            catalog = _case_catalog(unit, case_id)
            if catalog.get("terminal_status") == "NOT_APPLICABLE":
                document = {"schema": PROVENANCE_SCHEMA, "case_id": _display(case_id),
                            "actions": [], "artifacts": [], "relationships_exact": False, "gaps": []}
                return {**document, "artifact": _artifact(unit.job.run_root,
                        unit.unit_root / "build-command-provenance.json", document),
                        "terminal_status": "NOT_APPLICABLE"}
            if catalog.get("terminal_status") != "SUCCEEDED":
                gaps = list(catalog.get("gaps", ())) or ["accepted build catalog is unavailable"]
                return {"case_id": _display(case_id), "actions": [], "artifacts": [], "gaps": gaps,
                        "terminal_status": "COMPLETED_WITH_GAPS"}
            root = _case_root(unit, case_id)
            rows, gaps, generic_protected = [], [], None
            build_receipt = catalog.get("build_receipt", {})
            if isinstance(build_receipt, Mapping) and isinstance(
                    build_receipt.get("protected_compile_commands"), Mapping):
                try:
                    generic_protected = dict(build_receipt["protected_compile_commands"])
                    protected_document = _read_json_artifact(unit.job.run_root, generic_protected)
                    if (protected_document.get("schema") != "appsec-review/protected-compile-commands/1" or
                            not isinstance(protected_document.get("rows"), list)):
                        raise ValueError("generic build command provenance schema is unsupported")
                    rows.extend(protected_document["rows"])
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    gaps.append(f"generic build action provenance unavailable: {type(exc).__name__}")
                    generic_protected = None
            if generic_protected is None:
                try:
                    rows.extend(_raw_rows(root))
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    gaps.append(f"compile action provenance unavailable: {type(exc).__name__}")
                links = _link_rows(root)
                rows.extend(links)
                if not links:
                    gaps.append("exact linker/archiver provenance was not emitted by this build system")
            if rows:
                gaps.append("per-action environment was not emitted; only sanitized empty facts are retained")
            protected = root / "build-security" / "protected-commands"
            if generic_protected is None:
                protected.mkdir(parents=True, exist_ok=True)
            actions = []
            mapping = catalog.get("mapping", {})
            profile = str(catalog.get("profile") or mapping.get("build_system") or "unknown")
            build_execution = build_receipt if isinstance(build_receipt, Mapping) else {}
            execution_identity = build_execution.get("execution") if isinstance(build_execution, Mapping) else None
            try:
                execution = (_read_json_artifact(unit.job.run_root, execution_identity)
                             if isinstance(execution_identity, Mapping) else {})
            except (OSError, ValueError, json.JSONDecodeError):
                execution = {}
                gaps.append("accepted build execution receipt is unavailable")
            roots = {str(root): f"<run>/data/cpp/projects/{case_id}",
                     str(root / "source"): str(mapping.get("root", case_id))}
            for index, row in enumerate(rows):
                argv = _argv(row)
                if not argv:
                    gaps.append(f"build action {index} had no parseable argv")
                    continue
                action_id = hashlib.sha256(canonical_json({"case": case_id, "index": index, "argv": argv})).hexdigest()
                exact_argv = isinstance(row.get("argv"), list) or isinstance(row.get("arguments"), list)
                if generic_protected is not None:
                    protected_artifact = generic_protected
                    protected_value = {"argv_source": "generic-build-protected-argv"}
                else:
                    protected_path = protected / f"{action_id[:24]}.json"
                    protected_value = {"schema": "appsec-review/protected-build-command/1", "argv": argv,
                                       "argv_source": "arguments" if exact_argv else "parsed-command",
                                       "original_command": (None if exact_argv else str(row.get("command", ""))),
                                       "directory": row.get("directory"), "origin": row.get("origin"),
                                       "environment": {}, "access": "run-owned-protected"}
                    protected_artifact = _artifact(unit.job.run_root, protected_path, protected_value)
                    protected_path.chmod(0o600)
                has_action_timing = all(row.get(key) is not None for key in ("start", "end", "exit_status"))
                timed_row = {**dict(row), "start": row.get("start", execution.get("started_at")),
                             "end": row.get("end", execution.get("completed_at")),
                             "exit_status": row.get("exit_status", execution.get("exit_code")),
                             "arguments": argv}
                normalized = normalize_action(timed_row, action_id=action_id, run_id=unit.job.run_id,
                    target_snapshot=unit.job.source_fingerprint,
                    project=str(mapping.get("root", case_id)),
                    build_root=f"data/cpp/projects/{case_id}/build", configuration="accepted-recipe",
                    producer={"job": "job_language_build", "task": "execute.native"},
                    toolchain={"executable": PurePosixPath(argv[0].replace("\\", "/")).name,
                               "tool_id": "generic-native-build",
                               "tool_version": str(build_receipt.get("image", {}).get("image_tag", "unknown")),
                               "image_id": str(catalog.get("image_id", execution.get("image_id", "unknown"))),
                               "image_digest": str(execution.get("image_digest", catalog.get("image_id", "unknown")))},
                    protected_artifact=protected_artifact, roots=roots)
                normalized["timing_granularity"] = "action" if has_action_timing else "build-invocation"
                normalized["argv_source"] = protected_value["argv_source"]
                if not exact_argv:
                    gaps.append(f"exact argv unavailable for command-only action {action_id}; protected command text was retained")
                if not has_action_timing:
                    gaps.append(f"per-action timing/exit status unavailable for {action_id}")
                discovered = []
                for declared in normalized["declared_inputs"]:
                    declared_path = Path(str(declared))
                    candidates = [] if declared_path.is_absolute() else [root / "build" / declared_path,
                                                                          root / "source" / declared_path]
                    match = next((value.resolve() for value in candidates if value.is_file() and not value.is_symlink()), None)
                    if match is not None and root in match.parents:
                        discovered.append({"path": match.relative_to(root).as_posix(),
                                           "sha256": file_sha256(match), "size_bytes": match.stat().st_size})
                normalized["discovered_inputs"] = discovered
                actions.append({**normalized, "command_fingerprint": command_fingerprint(normalized)})
            artifacts = []
            for item in catalog.get("outputs", ()):
                candidate = (root / str(item.get("path", ""))).resolve()
                if root not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
                    gaps.append(f"cataloged artifact unavailable: {PurePosixPath(str(item.get('path', 'unknown'))).name}")
                    continue
                actual = file_sha256(candidate)
                if actual != item.get("sha256"):
                    gaps.append(f"cataloged artifact hash mismatch: {PurePosixPath(str(item.get('path'))).name}")
                    continue
                artifact_id = hashlib.sha256(canonical_json({"case": case_id, "path": item["path"], "sha256": actual})).hexdigest()
                artifacts.append({**dict(item), "artifact_id": artifact_id,
                                  "run_path": candidate.relative_to(unit.job.run_root).as_posix()})
            supported_suffixes = {".o", ".obj", ".a", ".lib", ".so", ".dylib", ".dll", ".exe",
                                  ".bc", ".map", ".linkmap", ".debug", ".pdb"}
            known_paths = {str(item["run_path"]) for item in artifacts}
            build_root = root / "build"
            for candidate in (sorted(build_root.rglob("*")) if build_root.is_dir() else ()):
                if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > 512 * 1024 * 1024:
                    continue
                prefix = candidate.read_bytes()[:8]
                supported_magic = prefix.startswith((b"\x7fELF", b"MZ", b"!<arch>\n", b"!<thin>\n", b"BC\xc0\xde")) or prefix[:4] in {
                    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
                if candidate.suffix.lower() not in supported_suffixes and not supported_magic:
                    continue
                run_path = candidate.relative_to(unit.job.run_root).as_posix()
                if run_path in known_paths:
                    continue
                sha = file_sha256(candidate)
                artifact_id = hashlib.sha256(canonical_json({"case": case_id,
                    "path": candidate.relative_to(root).as_posix(), "sha256": sha})).hexdigest()
                artifacts.append({"path": candidate.relative_to(root).as_posix(), "kind": "discovered",
                                  "sha256": sha, "size_bytes": candidate.stat().st_size,
                                  "artifact_id": artifact_id, "run_path": run_path})
                known_paths.add(run_path)
            by_output = {PurePosixPath(value).name: action for action in actions for value in action.get("outputs", ())}
            related_artifacts: set[str] = set()
            for artifact in artifacts:
                producer = by_output.get(PurePosixPath(str(artifact["path"])).name)
                if producer:
                    producer["linked_artifact_ids"] = sorted(set([*producer["linked_artifact_ids"], artifact["artifact_id"]]))
                    producer["output_hashes"][artifact["artifact_id"]] = artifact["sha256"]
                    related_artifacts.add(artifact["artifact_id"])
                else:
                    gaps.append(f"no exact producing action resolved for {PurePosixPath(str(artifact['path'])).name}")
            for action in actions:
                action["command_fingerprint"] = command_fingerprint(action)
            document = {"schema": PROVENANCE_SCHEMA, "case_id": _display(case_id), "actions": actions,
                        "artifacts": artifacts,
                        "relationships_exact": len(related_artifacts) == len(artifacts),
                        "relationship_count": len(related_artifacts), "gaps": list(dict.fromkeys(gaps))}
            artifact = _artifact(unit.job.run_root, unit.unit_root / "build-command-provenance.json", document)
            unit.job.events.write("BUILD_COMMAND_PROVENANCE_CAPTURED", case_id=_display(case_id),
                                  action_count=len(actions), artifact_count=len(artifacts), gap_count=len(document["gaps"]))
            return {**document, "artifact": artifact,
                    "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}
        return handler

    def inspection(case_id: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            provenance_value = _stage_case(unit, "provenance", case_id)
            if provenance_value.get("terminal_status") == "NOT_APPLICABLE":
                document = {"schema": "appsec-review/binary-inspection-set/1",
                            "case_id": _display(case_id), "records": [], "gaps": []}
                return {**document, "artifact": _artifact(unit.job.run_root,
                        unit.unit_root / "binary-inspections.json", document),
                        "terminal_status": "NOT_APPLICABLE"}
            records, gaps = [], list(provenance_value.get("gaps", ()))
            pinned_records: dict[str, Mapping[str, Any]] = {}
            pinned_path = _case_root(unit, case_id) / "analysis" / "binary" / "records.json"
            try:
                if pinned_path.is_file() and not pinned_path.is_symlink() and pinned_path.stat().st_size <= 64 * 1024 * 1024:
                    raw_records = json.loads(pinned_path.read_text(encoding="utf-8"))
                    if isinstance(raw_records, list):
                        pinned_records = {str(item.get("sha256")): item for item in raw_records[:100000]
                                          if isinstance(item, Mapping) and item.get("sha256")}
            except (OSError, ValueError, json.JSONDecodeError):
                gaps.append("pinned native binary-tool output was invalid")
            for artifact in provenance_value.get("artifacts", ()):
                path = (unit.job.run_root / artifact["run_path"]).resolve()
                record = {**inspect_binary(path), "artifact_id": artifact["artifact_id"],
                          "run_path": artifact["run_path"], "catalog_kind": artifact.get("kind")}
                pinned = pinned_records.get(str(record["sha256"]))
                if pinned is not None:
                    pinned_symbols = pinned.get("symbols", ()) if isinstance(pinned.get("symbols"), list) else ()
                    record["pinned_tool_observation"] = {
                        "tool": "tool-native-cpp:1.0.0/nm+readelf",
                        "record_sha256": hashlib.sha256(canonical_json(pinned)).hexdigest(),
                        "symbol_count": len(pinned_symbols),
                        "metadata_sha256": hashlib.sha256(str(pinned.get("metadata", "")).encode()).hexdigest(),
                    }
                    record["symbols"] = {**dict(record.get("symbols", {})),
                                         "defined_names": [str(line).split(" ", 1)[0][:4096]
                                                           for line in pinned_symbols[:10000]]}
                elif record.get("format") == "ELF":
                    record.setdefault("gaps", []).append("pinned nm/readelf observation was unavailable for this ELF artifact")
                records.append(record)
                gaps.extend(f"{PurePosixPath(artifact['run_path']).name}: {gap}" for gap in record.get("gaps", ()))
            document = {"schema": "appsec-review/binary-inspection-set/1", "case_id": _display(case_id),
                        "records": records, "gaps": list(dict.fromkeys(gaps))}
            artifact = _artifact(unit.job.run_root, unit.unit_root / "binary-inspections.json", document)
            unit.job.events.write("BUILD_ARTIFACTS_INSPECTED", case_id=_display(case_id),
                                  inspected_count=len(records), unsupported_count=sum(
                                      item.get("format") in {"unsupported", "malformed"} for item in records),
                                  truncated_count=sum(any(word in str(gap).lower() for word in ("bound", "truncat"))
                                                      for item in records for gap in item.get("gaps", ())),
                                  gap_count=len(document["gaps"]))
            return {**document, "artifact": artifact,
                    "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}
        return handler

    def deterministic(case_id: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            provenance_value = _stage_case(unit, "provenance", case_id)
            inspection_value = _stage_case(unit, "inspection", case_id)
            if provenance_value.get("terminal_status") == "NOT_APPLICABLE":
                document = {"schema": "appsec-review/build-security-deterministic-results/1",
                            "case_id": _display(case_id), "rule_version": RULE_VERSION, "checks": [],
                            "counts": {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0}, "gaps": []}
                return {**document, "artifact": _artifact(unit.job.run_root,
                        unit.unit_root / "deterministic-results.json", document),
                        "terminal_status": "NOT_APPLICABLE"}
            checks = deterministic_checks(provenance_value.get("actions", ()), inspection_value.get("records", ()))
            unknown = sum(item["status"] == "UNKNOWN" for item in checks)
            failed = sum(item["status"] == "FAIL" for item in checks)
            gaps = list(dict.fromkeys([*provenance_value.get("gaps", ()), *inspection_value.get("gaps", ()),
                                      *( [f"{unknown} applicable deterministic checks remain unknown"] if unknown else [])]))
            document = {"schema": "appsec-review/build-security-deterministic-results/1",
                        "case_id": _display(case_id), "rule_version": RULE_VERSION,
                        "checks": checks, "counts": {status.lower(): sum(item["status"] == status for item in checks)
                                                     for status in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")},
                        "gaps": gaps}
            artifact = _artifact(unit.job.run_root, unit.unit_root / "deterministic-results.json", document)
            unit.job.events.write("BUILD_SECURITY_CHECKS_COMPLETED", case_id=_display(case_id),
                                  check_count=len(checks), failed_count=failed, unknown_count=unknown,
                                  gap_count=len(gaps))
            return {**document, "artifact": artifact,
                    "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}
        return handler

    def inference(case_id: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            provenance_value = _stage_case(unit, "provenance", case_id)
            inspection_value = _stage_case(unit, "inspection", case_id)
            deterministic_value = _stage_case(unit, "deterministic", case_id)
            settings = unit.job.config.settings["model"]
            guidance_path = unit.job.repository_root / "skills" / "post-build-security-assessment" / "SKILL.md"
            guidance = guidance_path.read_text(encoding="utf-8") if guidance_path.is_file() else GUIDANCE_IDENTITY
            guidance_sha = hashlib.sha256(guidance.encode()).hexdigest()
            bundle = unit.job.run_root / "data" / "guidance" / guidance_sha
            atomic_bytes(bundle / "SKILL.md", guidance.encode())
            model_identity = {"provider": str(settings["provider"]), "model": str(settings["model"]),
                              "reasoning": str(settings["reasoning"]), "guidance_sha256": guidance_sha}
            atomic_json(bundle / "model-identity.json", model_identity)
            if provenance_value.get("terminal_status") == "NOT_APPLICABLE":
                document = {"schema": "appsec-review/build-security-inference/1",
                            "case_id": _display(case_id), "model_identity": model_identity,
                            "request_sha256": hashlib.sha256(canonical_json({"case": case_id,
                                "status": "NOT_APPLICABLE"})).hexdigest(), "model_calls": 0,
                            "observations": [], "rejections": [], "confirmed_count": 0,
                            "refuted_count": 0, "unvalidated_count": 0, "gaps": []}
                return {**document, "artifact": _artifact(unit.job.run_root,
                        unit.unit_root / "inference-results.json", document),
                        "terminal_status": "NOT_APPLICABLE"}
            actions = [{key: value.get(key) for key in ("project", "build_root", "configuration", "build_action_id",
                        "compile_unit_id", "linked_artifact_ids", "classification", "toolchain", "argv", "declared_inputs",
                        "discovered_inputs", "outputs", "producer")} for value in provenance_value.get("actions", ())]
            records = [{key: value.get(key) for key in ("artifact_id", "sha256", "format", "kind", "architecture", "bits",
                        "headers", "sections", "imports", "exports", "relocations", "interpreter", "rpath", "runpath",
                        "dependencies", "archive_members", "build_id", "debug", "symbols", "hardening", "gaps")}
                       for value in inspection_value.get("records", ())]
            request = {"schema": "appsec-review/build-security-inference-request/1", "guidance": GUIDANCE_IDENTITY,
                       "case_id": _display(case_id), "topology": {"actions": len(actions), "artifacts": len(records)},
                       "actions": actions, "artifacts": records, "deterministic_results": deterministic_value["checks"],
                       "rules": ["missing data is a gap, never a clean result", "cite only supplied evidence ids",
                                 "model output remains an observation until deterministic validation"]}
            encoded = canonical_json(request)
            gaps: list[str] = []
            if len(encoded) > int(settings["max_input_tokens"]) * 4:
                gaps.append("structured build-security inference request exceeded its configured input budget")
                result = {"observations": [], "rejections": [], "confirmed_count": 0,
                          "refuted_count": 0, "unvalidated_count": 0}
                calls = 0
            elif not settings["enabled"]:
                gaps.append("build-security inference model is disabled; deterministic results remain authoritative")
                result = {"observations": [], "rejections": [], "confirmed_count": 0,
                          "refuted_count": 0, "unvalidated_count": 0}
                calls = 0
            elif infer is None:
                gaps.append("build-security inference model is unavailable; deterministic results remain authoritative")
                result = {"observations": [], "rejections": [], "confirmed_count": 0,
                          "refuted_count": 0, "unvalidated_count": 0}
                calls = 0
            else:
                request_sha = hashlib.sha256(encoded).hexdigest()
                model_request = ModelRequest(
                    schema=INFERENCE_PROPOSAL_SCHEMA, persona="", role="", guidance=guidance, summary=request,
                    allowed_scanners=(), allowed_build_systems=(), allowed_components=(), allowed_paths=(),
                    allowed_build_units=(), provider=str(settings["provider"]), model=str(settings["model"]),
                    reasoning=str(settings["reasoning"]), max_input_tokens=int(settings["max_input_tokens"]),
                    max_output_tokens=int(settings["max_output_tokens"]))
                known = {str(item.get("build_action_id")) for item in actions} | {
                    str(item.get("compile_unit_id")) for item in actions if item.get("compile_unit_id")} | {
                    str(item.get("artifact_id")) for item in records} | {str(item.get("sha256")) for item in records}
                calls, proposal = 0, None
                last_error: Exception | None = None
                for retry in range(int(settings["retries"]) + 1):
                    calls += 1
                    invocation = hashlib.sha256(f"{unit.job.run_id}:{case_id}:{retry}:{request_sha}".encode()).hexdigest()
                    emit_model_event(PipelineLog(unit.job.run_root), event_type="MODEL_CALL_STARTED",
                        run_id=unit.job.run_id, invocation_id=invocation, provider=str(settings["provider"]),
                        model=str(settings["model"]), reasoning_level=str(settings["reasoning"]),
                        guidance_bundle_sha256=guidance_sha, request_sha256=request_sha, retry_count=retry,
                        job_id="job_post_build_security_assessment", attempt_id=unit.job.attempt_id,
                        case_id=_display(case_id))
                    started = time.monotonic()
                    try:
                        proposal = infer(model_request, timeout_seconds=int(settings["timeout_seconds"]))
                        if ((proposal.output_tokens or 0) > int(settings["max_output_tokens"]) or
                                len(canonical_json(proposal.proposal)) > int(settings["max_output_tokens"]) * 4):
                            raise ValueError("build-security inference output exceeded configured budget")
                        result = validate_inference(proposal.proposal, checks=deterministic_value["checks"], evidence_ids=known)
                        emit_model_event(PipelineLog(unit.job.run_root), event_type="MODEL_CALL_COMPLETED",
                            run_id=unit.job.run_id, invocation_id=invocation, provider=str(settings["provider"]),
                            model=str(settings["model"]), reasoning_level=str(settings["reasoning"]),
                            guidance_bundle_sha256=guidance_sha, request_sha256=request_sha,
                            terminal_status="ACCEPTED", duration_ms=int((time.monotonic() - started) * 1000),
                            retry_count=retry, input_tokens=proposal.input_tokens, output_tokens=proposal.output_tokens,
                            cache_tokens=proposal.cache_tokens, job_id="job_post_build_security_assessment",
                            attempt_id=unit.job.attempt_id, case_id=_display(case_id))
                        break
                    except Exception as exc:
                        last_error = exc
                        emit_model_event(PipelineLog(unit.job.run_root), event_type="MODEL_CALL_COMPLETED",
                            run_id=unit.job.run_id, invocation_id=invocation, provider=str(settings["provider"]),
                            model=str(settings["model"]), reasoning_level=str(settings["reasoning"]),
                            guidance_bundle_sha256=guidance_sha, request_sha256=request_sha,
                            terminal_status="FAILED", duration_ms=int((time.monotonic() - started) * 1000),
                            retry_count=retry, error_class=type(exc).__name__, job_id="job_post_build_security_assessment",
                            attempt_id=unit.job.attempt_id, case_id=_display(case_id))
                else:
                    gaps.append(f"build-security inference failed after bounded retries ({type(last_error).__name__})")
                    result = {"observations": [], "rejections": [], "confirmed_count": 0,
                              "refuted_count": 0, "unvalidated_count": 0}
            if result.get("rejections"):
                gaps.append(f"{len(result['rejections'])} inference observations were rejected during evidence validation")
            document = {"schema": "appsec-review/build-security-inference/1", "case_id": _display(case_id),
                        "model_identity": model_identity, "request_sha256": hashlib.sha256(encoded).hexdigest(),
                        "model_calls": calls, **result, "gaps": gaps}
            artifact = _artifact(unit.job.run_root, unit.unit_root / "inference-results.json", document)
            unit.job.events.write("BUILD_SECURITY_INFERENCE_COMPLETED", case_id=_display(case_id), model_calls=calls,
                                  observation_count=len(result["observations"]), confirmed_count=result["confirmed_count"],
                                  refuted_count=result["refuted_count"], gap_count=len(gaps))
            return {**document, "artifact": artifact,
                    "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}
        return handler

    def index_case(case_id: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            provenance_value = _stage_case(unit, "provenance", case_id)
            inspection_value = _stage_case(unit, "inspection", case_id)
            deterministic_value = _stage_case(unit, "deterministic", case_id)
            inference_value = _stage_case(unit, "inference", case_id)
            upstream = unit.output("load.accepted_cpp_build")["upstream_manifest"]
            artifacts = [provenance_value.get("artifact", {}), inspection_value.get("artifact", {}),
                         deterministic_value.get("artifact", {}), inference_value.get("artifact", {})]
            fingerprint = shard_fingerprint(command_artifacts=[item.get("protected_argv_artifact", {})
                for item in provenance_value.get("actions", ())],
                binary_hashes=[item["sha256"] for item in inspection_value.get("records", ())],
                tool_identity={"parser": PARSER_VERSION, "normalizer": NORMALIZER_VERSION,
                               "images": sorted({str(item.get("toolchain", {}).get("image_digest"))
                                                 for item in provenance_value.get("actions", ())}),
                               "tools": sorted({str(item.get("toolchain", {}).get("tool_version"))
                                                for item in provenance_value.get("actions", ())}),
                               "executables": sorted({str(item.get("toolchain", {}).get("executable"))
                                                      for item in provenance_value.get("actions", ())})},
                model_identity=inference_value["model_identity"], upstream_manifest_sha256=upstream["sha256"])
            shard_id = f"build-security-{case_id}"
            path = unit.job.run_root / "data" / "indices" / "build_security" / f"{fingerprint}-{shard_id}.sqlite"
            reused = path.exists()
            if not reused:
                path.parent.mkdir(parents=True, exist_ok=True)
                builder = IndexBuilder(path, name="build_security", fingerprint=fingerprint,
                                       target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
                action_ids: dict[str, str] = {}
                compile_ids: dict[str, str] = {}
                source_ids: dict[str, str] = {}
                for action in provenance_value.get("actions", ()):
                    identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                        {"case": case_id, "action": action["build_action_id"], "fingerprint": action["command_fingerprint"]})
                    action_ids[action["build_action_id"]] = identity.value
                    payload = {**dict(action), "shard": shard_id, "producer": "job_post_build_security_assessment"}
                    builder.add_entity(EntityRecord(identity, action["build_action_id"], action["build_action_id"],
                        " ".join(action.get("argv", ())), payload))
                    if action.get("compile_unit_id"):
                        compile_id = LogicalIdentity.derive(EntityKind.COMPILE_UNIT, unit.job.source_fingerprint,
                            {"case": case_id, "compile_unit": action["compile_unit_id"]})
                        compile_ids[action["compile_unit_id"]] = compile_id.value
                        builder.add_entity(EntityRecord(compile_id, action["compile_unit_id"],
                            PurePosixPath(str(action.get("declared_inputs", ["compile-unit"])[0])).name,
                            "compile unit", {"project": action["project"], "build_root": action["build_root"],
                            "configuration": action["configuration"], "compile_unit": action["compile_unit_id"],
                            "producer": action["producer"], "shard": shard_id}))
                        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, compile_id.value,
                                                           identity.value, True, 1.0))
                binary_ids: dict[str, str] = {}
                binary_names: dict[str, str] = {}
                dependency_ids: set[str] = set()
                for record in inspection_value.get("records", ()):
                    kind = {"object": EntityKind.OBJECT_FILE, "archive": EntityKind.LIBRARY,
                            "shared_library": EntityKind.LIBRARY, "pie_executable": EntityKind.EXECUTABLE,
                            "dll": EntityKind.LIBRARY,
                            "dylib": EntityKind.LIBRARY, "executable": EntityKind.EXECUTABLE}.get(
                                str(record.get("kind")), EntityKind.EVIDENCE_ARTIFACT)
                    identity = LogicalIdentity.derive(kind, unit.job.source_fingerprint,
                        {"case": case_id, "artifact": record["artifact_id"], "sha256": record["sha256"]})
                    binary_ids[record["artifact_id"]] = identity.value
                    binary_names[PurePosixPath(str(record["run_path"])).name] = identity.value
                    builder.add_entity(EntityRecord(identity, record["artifact_id"],
                        PurePosixPath(str(record["run_path"])).name, f"{record['format']} {record['kind']}",
                        {**dict(record), "project": case_id,
                         "build_root": f"data/cpp/projects/{case_id}/build",
                         "configuration": "RelWithDebInfo", "linked_artifact": record["artifact_id"],
                         "producer": "job_cpp_compiled_analysis", "shard": shard_id}))
                    for member in record.get("archive_members", ()):
                        member_id = LogicalIdentity.derive(EntityKind.OBJECT_FILE, unit.job.source_fingerprint,
                            {"archive": record["sha256"], "member": member.get("name"),
                             "size": member.get("size"), "index": member.get("index")})
                        builder.add_entity(EntityRecord(member_id, str(member.get("name")), str(member.get("name")),
                            "archive member", {"archive": record["artifact_id"], "member": dict(member),
                            "project": case_id, "shard": shard_id}))
                        builder.add_relation(RelationRecord(RelationKind.CONTAINS, identity.value,
                                                           member_id.value, True, 1.0))
                    for dependency in record.get("dependencies", ()):
                        dependency_id = LogicalIdentity.derive(EntityKind.LIBRARY, unit.job.source_fingerprint,
                            {"loader_dependency": dependency, "platform": record.get("format")})
                        if dependency_id.value not in dependency_ids:
                            dependency_ids.add(dependency_id.value)
                            builder.add_entity(EntityRecord(dependency_id, str(dependency), str(dependency),
                                "loader dependency", {"dependency": dependency, "producer": "binary-loader-metadata",
                                "project": case_id, "shard": shard_id}))
                        builder.add_relation(RelationRecord(RelationKind.DEPENDS_ON, identity.value,
                                                           dependency_id.value, True, 1.0))
                for action in provenance_value.get("actions", ()):
                    source = compile_ids.get(str(action.get("compile_unit_id"))) or action_ids[action["build_action_id"]]
                    for artifact_id in action.get("linked_artifact_ids", ()):
                        if artifact_id in binary_ids:
                            relation = RelationKind.COMPILES_TO if action.get("classification") == "compiler" else RelationKind.LINKS_INTO
                            builder.add_relation(RelationRecord(relation, source, binary_ids[artifact_id], True, 1.0))
                            output_id = binary_ids[artifact_id]
                            for input_path in action.get("declared_inputs", ()):
                                input_name = PurePosixPath(str(input_path)).name
                                if action.get("classification") == "compiler" and PurePosixPath(str(input_path)).suffix.lower() in {
                                    ".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".s", ".asm"}:
                                    if str(input_path) not in source_ids:
                                        source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                            {"path": input_path, "compile_unit": action.get("compile_unit_id")})
                                        source_ids[str(input_path)] = source_id.value
                                        builder.add_entity(EntityRecord(source_id, str(input_path), input_name,
                                            "compiled source", {"path": input_path, "project": action["project"],
                                            "build_root": action["build_root"], "configuration": action["configuration"],
                                            "producer": action["producer"], "shard": shard_id}))
                                    builder.add_relation(RelationRecord(RelationKind.COMPILES_TO,
                                        source_ids[str(input_path)], output_id, True, 1.0))
                                elif input_name in binary_names:
                                    builder.add_relation(RelationRecord(RelationKind.LINKS_INTO,
                                        binary_names[input_name], output_id, True, 1.0))
                evidence_entities = {**action_ids,
                    **{str(record["sha256"]): binary_ids[record["artifact_id"]]
                       for record in inspection_value.get("records", ()) if record["artifact_id"] in binary_ids}}
                first_action = next(iter(provenance_value.get("actions", ())), {})
                common_scope = {"project": first_action.get("project", case_id),
                                "build_root": first_action.get("build_root", f"data/cpp/projects/{case_id}/build"),
                                "configuration": first_action.get("configuration", "RelWithDebInfo"),
                                "shard": shard_id}
                for check in deterministic_value.get("checks", ()):
                    check_identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, unit.job.source_fingerprint,
                        {"case": case_id, "rule_version": RULE_VERSION, "check": check.get("check_id"),
                         "scope": check.get("scope")})
                    builder.add_entity(EntityRecord(check_identity,
                        f"deterministic:{check.get('check_id')}:{check.get('scope')}",
                        str(check.get("check_id")), f"{check.get('status')} {check.get('rationale')}",
                        {**dict(check), **common_scope, "producer": "deterministic-build-security-rules"}))
                    for evidence_id in check.get("evidence", ()):
                        if str(evidence_id) in evidence_entities:
                            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT,
                                check_identity.value, evidence_entities[str(evidence_id)], True, 1.0))
                for observation in inference_value.get("observations", ()):
                    identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, unit.job.source_fingerprint,
                        {"case": case_id, "observation": observation["observation_id"]})
                    builder.add_entity(EntityRecord(identity, observation["observation_id"],
                        observation["check_id"], observation["claim"], {**dict(observation), "project": case_id,
                        "configuration": "RelWithDebInfo", "producer": "bounded_inference", "shard": shard_id}))
                    for evidence_id in observation.get("evidence_ids", ()):
                        if str(evidence_id) in evidence_entities:
                            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT,
                                identity.value, evidence_entities[str(evidence_id)], True, 1.0))
                gaps = list(dict.fromkeys([*provenance_value.get("gaps", ()), *inspection_value.get("gaps", ()),
                                          *deterministic_value.get("gaps", ()), *inference_value.get("gaps", ())]))
                builder.add_coverage("post-build-security", "partial" if gaps else "complete", "; ".join(gaps[:20]) or None)
                sha = builder.build()
            else:
                sha = file_sha256(path)
                gaps = list(dict.fromkeys([*provenance_value.get("gaps", ()), *inspection_value.get("gaps", ()),
                                          *deterministic_value.get("gaps", ()), *inference_value.get("gaps", ())]))
            identity = IndexIdentity("build_security", "appsec-review/retrieval-index/2", sha, fingerprint,
                path.relative_to(unit.job.run_root).as_posix(),
                {"job": "job_post_build_security_assessment", "unit": unit.unit_id,
                 "rule_version": RULE_VERSION, "parser_version": PARSER_VERSION,
                 "normalizer_version": NORMALIZER_VERSION, "guidance_identity": GUIDANCE_IDENTITY},
                tuple(gaps), shard_id)
            unit.job.events.write("BUILD_SECURITY_SHARD_PUBLISHED", case_id=_display(case_id),
                                  shard=shard_id, fingerprint=fingerprint, reused=reused,
                                  resumption_count=int(reused), gap_count=len(gaps))
            return {"index_identity": asdict(identity), "index_reused": reused,
                    "artifact": _artifact(unit.job.run_root, path), "source_artifacts": artifacts,
                    "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}
        return handler

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        upstream = unit.output("load.accepted_cpp_build")["upstream_manifest"]
        manifest_path = (unit.job.run_root / upstream["path"]).resolve()
        manifest_sha = str(upstream["sha256"])
        manifest, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
        existing = [IndexIdentity(**{**value, "gaps": tuple(value.get("gaps", ()))})
                    for value in manifest["indexes"] if value["name"] != "build_security"]
        indexed = unit.output("index.native_units")["projects"]
        current = [IndexIdentity(**{**value["index_identity"],
                                    "gaps": tuple(value["index_identity"].get("gaps", ()))})
                   for value in indexed.values()]
        destination = unit.job.run_root / "data" / "indices" / "manifests" / f"build-security-{unit.job.attempt_id}.json"
        write_manifest(destination, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
            target_root=unit.job.target_root or Path(), indexes=(*existing, *current),
            upstream_manifests=({"path": manifest_path.relative_to(unit.job.run_root).as_posix(), "sha256": manifest_sha},))
        load_verified_manifest(unit.job.run_root, destination, file_sha256(destination))
        gaps = list(dict.fromkeys(item for value in indexed.values() for item in value.get("gaps", ())))
        summary = {"schema": SCHEMA, "case_count": len(indexed), "shard_count": len(current),
                   "gaps": gaps, "rule_version": RULE_VERSION, "parser_version": PARSER_VERSION,
                   "normalizer_version": NORMALIZER_VERSION}
        summary_artifact = _artifact(unit.job.run_root, unit.unit_root / "post-build-security-summary.json", summary)
        unit.job.events.write("POST_BUILD_SECURITY_ASSESSMENT_COMPLETED", case_count=len(indexed),
                              shard_count=len(current), gap_count=len(gaps))
        return {"schema": SCHEMA, "artifact": summary_artifact,
                "index_manifest": _artifact(unit.job.run_root, destination), "item_count": len(current),
                "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    units: list[Unit] = [Unit("load.accepted_cpp_build", load)]
    units.append(Unit("provenance.native_units", aggregate(provenance), ("load.accepted_cpp_build",)))
    units.append(Unit("inspection.native_units", aggregate(inspection), ("provenance.native_units",)))
    units.append(Unit("deterministic.native_units", aggregate(deterministic),
                      ("provenance.native_units", "inspection.native_units")))
    units.append(Unit("inference.native_units", aggregate(inference),
                      ("provenance.native_units", "inspection.native_units", "deterministic.native_units")))
    units.append(Unit("index.native_units", aggregate(index_case),
                      ("load.accepted_cpp_build", "provenance.native_units", "inspection.native_units",
                       "deterministic.native_units", "inference.native_units")))
    units.append(Unit("publication.publish_handoff", publish, ("index.native_units",)))
    values = tuple(units)
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
                                    Path(__file__).with_name("assessment.py").read_bytes()).hexdigest()
    return Job("job_post_build_security_assessment", "post_build_security_assessment",
               UnitExecutor(values).execute, input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation, units=values)
