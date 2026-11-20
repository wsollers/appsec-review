from __future__ import annotations

from appsec_review.interchange import bounded_gap_messages

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import shlex
import shutil
import time
from typing import Any
import zipfile

from appsec_review.jobs.cpp_index_scopes import load_accepted_cpp
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.build_outcome import build_succeeded
from appsec_review.jobs.job_project_build.enforcement import gap_text
from appsec_review.inference import Infer, ModelRequest
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .assessment import (
    GUIDANCE_IDENTITY, NORMALIZER_VERSION, PARSER_VERSION, PROVENANCE_SCHEMA, RULE_VERSION,
    INFERENCE_PROPOSAL_SCHEMA, INFERENCE_RESPONSE_SCHEMA, SCHEMA, command_fingerprint,
    deterministic_checks, discover_io, has_unexpanded_response_file, inspect_binary,
    normalize_action, shard_fingerprint, validate_inference,
)
from appsec_review.jobs.job_post_build_security_assessment.datasets import CONTRACT, DATASETS

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
                # A command file's location is not evidence of its invocation directory.
                rows.append({"command": line, "origin": path.relative_to(root).as_posix()})
    return rows


def _case_path(value: str, directory: Any, *, root: Path, run_root: Path,
               catalog: Mapping[str, Any]) -> Path | None:
    """Resolve only captured cwd paths and the accepted workspace-to-case copy mapping."""
    value = value.replace("\\", "/")
    if not PurePosixPath(value).is_absolute():
        if not isinstance(directory, str) or not directory:
            return None
        value = posixpath.join(directory.replace("\\", "/"), value)
    receipt, mapping = catalog.get("build_receipt", {}), catalog.get("mapping", {})
    aliases = [(root.as_posix(), root)]
    workspace = receipt.get("workspace")
    if isinstance(workspace, str) and workspace and not PurePosixPath(workspace).is_absolute():
        recipe = receipt.get("recipe", {})
        for relative, local in ((recipe.get("build_dir", mapping.get("build_dir")), root / "build"),
                                (mapping.get("source_dir", mapping.get("root")), root / "source")):
            if not isinstance(relative, str) or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts:
                continue
            for prefix in ("/workspace", (run_root / workspace).as_posix()):
                aliases.append((posixpath.normpath(posixpath.join(prefix, relative)), local))
        if not PurePosixPath(value).is_absolute():
            value = posixpath.join("/workspace", value)
    normalized = posixpath.normpath(value)
    for prefix, destination in sorted(aliases, key=lambda pair: -len(pair[0])):
        if normalized == prefix or normalized.startswith(prefix + "/"):
            candidate = destination / normalized[len(prefix):].lstrip("/")
            if candidate.is_symlink():
                return None
            resolved = candidate.resolve()
            return resolved if root == resolved or root in resolved.parents else None
    return None


def _argv(row: Mapping[str, Any]) -> list[str]:
    if isinstance(row.get("argv"), list):
        return [str(item) for item in row["argv"]]
    if isinstance(row.get("arguments"), list):
        return [str(item) for item in row["arguments"]]
    return shlex.split(str(row.get("command", "")), posix=True)


_BINARY_MAGICS = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                  b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
_ARCHIVE_MEMBER_SUFFIXES = (".so", ".pyd", ".dylib", ".dll", ".node")
_ARCHIVE_MEMBER_LIMIT = 256


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4).startswith(_BINARY_MAGICS)
    except OSError:
        return False


_PE_CLR_DIRECTORY = 14  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR


def _is_managed_pe(path: Path) -> bool:
    """A PE image with a CLR runtime header holds .NET IL, not native code to harden-check.

    Native AOT output has no CLR header and stays a family case. A truncated or malformed header is
    not proven managed, so the file is still inspected.
    """
    try:
        with path.open("rb") as stream:
            dos = stream.read(64)
            if len(dos) < 64 or not dos.startswith(b"MZ"):
                return False
            stream.seek(int.from_bytes(dos[0x3C:0x40], "little"))
            header = stream.read(24 + 240)
    except OSError:
        return False
    if len(header) < 26 or header[:4] != b"PE\0\0":
        return False
    optional = header[24:]
    magic = int.from_bytes(optional[:2], "little")
    if magic not in (0x10B, 0x20B):
        return False
    count_at, directories_at = (92, 96) if magic == 0x10B else (108, 112)
    entry = directories_at + _PE_CLR_DIRECTORY * 8
    if len(optional) < entry + 8 or int.from_bytes(optional[count_at:count_at + 4], "little") <= _PE_CLR_DIRECTORY:
        return False
    rva, size = optional[entry:entry + 4], optional[entry + 4:entry + 8]
    return int.from_bytes(rva, "little") != 0 and int.from_bytes(size, "little") != 0


def family_build_cases(language: Mapping[str, Any], run_root: Path) -> dict[str, dict[str, Any]]:
    """Accepted non-native builds whose produced binaries need ELF/PE/Mach-O inspection.

    Native units and mixed units whose own build compiled ``native_components`` reach this job
    through the C/C++ lane, with their captured compile flags. Every other successful build
    (Go and Rust executables, .NET native AOT output, prebuilt extension modules inside wheels)
    is a family case judged by its family's documented hardening expectations.
    Managed .NET assemblies (PE images with a CLR runtime header) carry IL, not native code, and
    are not family-case artifacts.
    """
    cases: dict[str, dict[str, Any]] = {}
    for receipt in language.get("receipts", ()):
        family = str(receipt.get("family") or receipt.get("source_family") or "")
        database = receipt.get("native_compile_database")
        # Products-exist question. Provenance gaps do not remove admitted binaries from inspection.
        if (not build_succeeded(receipt) or receipt.get("terminal_status") not in {
                "SUCCEEDED", "COMPLETED_WITH_GAPS"} or family in {"", "native"} or
                (isinstance(database, Mapping) and int(database.get("entry_count", 0)) > 0)):
            continue
        if receipt.get("terminal_status") != "SUCCEEDED" and receipt.get("artifacts"):
            from appsec_review.jobs.job_artifact_indexing.job import _validate_receipts
            # Newly admitted partial receipts must satisfy the same manifest/custody boundary
            # as artifact indexing; rejected_artifacts are never candidate inputs.
            _validate_receipts(run_root, str(language.get("source_fingerprint", "")), [receipt])
        artifacts = []
        for item in receipt.get("artifacts", ()):
            path = (run_root / str(item.get("path", ""))).resolve()
            if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
                continue
            if (_is_binary(path) and not _is_managed_pe(path)) or str(item.get("kind")) == "wheel":
                artifacts.append({key: item[key] for key in ("path", "sha256", "size_bytes", "kind")
                                  if key in item})
        if artifacts:
            case_id = f"family-{receipt['build_unit_id']}"
            cases[case_id] = {"terminal_status": receipt["terminal_status"], "source": "language-build",
                              "family": family, "build_unit_id": receipt["build_unit_id"],
                              "root": receipt.get("root"), "artifacts": artifacts,
                              "gaps": [gap_text(gap) for gap in receipt.get("gaps", ())],
                              "image_id": str(receipt.get("image", {}).get("image_id", "unknown"))}
    return cases


def _family_provenance(unit: UnitContext, case_id: str, catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Artifacts of a family build: verified receipt binaries plus binary members of wheels."""
    artifacts, gaps = [], [gap_text(gap) for gap in catalog.get("gaps", ())]
    for item in catalog.get("artifacts", ()):
        path = (unit.job.run_root / str(item["path"])).resolve()
        if (unit.job.run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink() or
                file_sha256(path) != item.get("sha256")):
            gaps.append(f"accepted build artifact identity changed: {PurePosixPath(str(item['path'])).name}")
            continue
        if item.get("kind") != "wheel":
            artifacts.append({"path": PurePosixPath(str(item["path"])).name, "kind": item.get("kind"),
                              "sha256": item["sha256"], "size_bytes": path.stat().st_size,
                              "artifact_id": hashlib.sha256(canonical_json({
                                  "case": case_id, "path": item["path"], "sha256": item["sha256"]})).hexdigest(),
                              "run_path": path.relative_to(unit.job.run_root).as_posix()})
            continue
        try:
            with zipfile.ZipFile(path) as archive:
                members = [info for info in archive.infolist()
                           if not info.is_dir() and info.filename.lower().endswith(_ARCHIVE_MEMBER_SUFFIXES)]
                if len(members) > _ARCHIVE_MEMBER_LIMIT:
                    gaps.append(f"{path.name}: binary member bound reached; later members were not inspected")
                for ordinal, info in enumerate(members[:_ARCHIVE_MEMBER_LIMIT]):
                    if info.file_size > 512 * 1024 * 1024:
                        gaps.append(f"{path.name}: member exceeds the inspection byte bound")
                        continue
                    target = unit.unit_root / "archive-members" / item["sha256"][:16] / f"{ordinal:04d}.bin"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("wb") as sink:
                        shutil.copyfileobj(source, sink)
                    digest = file_sha256(target)
                    artifacts.append({"path": PurePosixPath(info.filename).name, "kind": "archive-member",
                                      "sha256": digest, "size_bytes": target.stat().st_size,
                                      "archive": {"path": item["path"], "sha256": item["sha256"],
                                                  "member": info.filename[:4096]},
                                      "artifact_id": hashlib.sha256(canonical_json({
                                          "case": case_id, "archive": item["sha256"],
                                          "member": info.filename, "sha256": digest})).hexdigest(),
                                      "run_path": target.relative_to(unit.job.run_root).as_posix()})
        except (OSError, zipfile.BadZipFile) as exc:
            gaps.append(f"{path.name}: package archive could not be inspected ({type(exc).__name__})")
    document = {"schema": PROVENANCE_SCHEMA, "case_id": _display(case_id), "family": catalog["family"],
                "actions": [], "artifacts": artifacts, "relationships_exact": False,
                "relationship_count": 0,
                "action_source": "no captured C/C++ compiles; family hardening expectations apply",
                "gaps": list(dict.fromkeys(gaps))}
    artifact = _artifact(unit.job.run_root, unit.unit_root / "build-command-provenance.json", document)
    unit.job.events.write("BUILD_COMMAND_PROVENANCE_CAPTURED", case_id=_display(case_id),
                          action_count=0, artifact_count=len(artifacts), gap_count=len(document["gaps"]))
    return {**document, "artifact": artifact,
            "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}


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
        # Every other family's accepted binaries (Go, Rust, .NET AOT, wheel extension members).
        # The C/C++ lane is downstream of job_language_build, so its accepted handoff exists in a
        # real run; read it through its own integrity-checked pointer.
        load_gaps: list[str] = []
        from appsec_review.runtime.consume import has_accepted_upstream
        if has_accepted_upstream(unit.job.run_root, "job_language_build"):
            language = load_accepted_language_build(unit.job.run_root)
            cases.update(family_build_cases(language, unit.job.run_root))
            load_gaps.extend(gap_text(gap) for gap in language.get("gaps", ()))
            load_gaps.extend(gap_text(gap) for receipt in language.get("receipts", ())
                             for gap in receipt.get("gaps", ()))
        else:
            load_gaps.append("accepted language-build handoff is unavailable; non-native family binaries "
                             "were not inspected")
        unit.job.events.write("BUILD_SECURITY_ACCEPTED_BUILD_LOADED",
                              upstream_handoff_sha256=accepted["handoff_sha256"], case_count=len(cases))
        return {"schema": SCHEMA, "cases": cases, "upstream_handoff_sha256": accepted["handoff_sha256"],
                "upstream_manifest": accepted["manifest"], "gaps": load_gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if load_gaps else "SUCCEEDED"}

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
            if catalog.get("source") == "language-build":
                return _family_provenance(unit, case_id, catalog)
            if catalog.get("terminal_status") == "NOT_APPLICABLE":
                document = {"schema": PROVENANCE_SCHEMA, "case_id": _display(case_id),
                            "actions": [], "artifacts": [], "relationships_exact": False, "gaps": []}
                return {**document, "artifact": _artifact(unit.job.run_root,
                        unit.unit_root / "build-command-provenance.json", document),
                        "terminal_status": "NOT_APPLICABLE"}
            if catalog.get("terminal_status") != "SUCCEEDED":
                gaps = list(catalog.get("gaps", ())) or ["accepted build catalog is unavailable"]
                # A build that did not succeed upstream still publishes its (empty) provenance
                # document: later stages bind every stage output by its artifact hash.
                document = {"schema": PROVENANCE_SCHEMA, "case_id": _display(case_id),
                            "actions": [], "artifacts": [], "relationships_exact": False, "gaps": gaps}
                return {**document, "artifact": _artifact(unit.job.run_root,
                        unit.unit_root / "build-command-provenance.json", document),
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
                action_id = hashlib.sha256(canonical_json({"case": case_id, "index": index, "argv": argv,
                                                          "directory": row.get("directory")})).hexdigest()
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
                if normalized["classification"] == "unknown":
                    gaps.append(f"compiler/tool identity could not be classified for {action_id}")
                if has_unexpanded_response_file(argv):
                    gaps.append(f"unexpanded response file leaves effective flags unknown for {action_id}")
                if not row.get("directory"):
                    gaps.append(f"working directory unavailable for {action_id}; relative paths are unresolved")
                inputs, outputs = discover_io(argv, working_directory=str(row.get("directory") or ""))
                if isinstance(row.get("output"), str) and row["output"] not in outputs:
                    outputs.append(row["output"])
                discovered = []
                for declared in inputs:
                    match = _case_path(declared, row.get("directory"), root=root,
                                       run_root=unit.job.run_root, catalog=catalog)
                    if match is not None and match.is_file():
                        discovered.append({"path": match.relative_to(root).as_posix(),
                                           "sha256": file_sha256(match), "size_bytes": match.stat().st_size})
                normalized["discovered_inputs"] = discovered
                normalized["resolved_outputs"] = sorted({
                    match.relative_to(root).as_posix() for output in outputs
                    if (match := _case_path(output, row.get("directory"), root=root,
                                           run_root=unit.job.run_root, catalog=catalog)) is not None})
                actions.append({**normalized, "command_fingerprint": command_fingerprint(normalized)})
            artifacts = []
            cataloged_paths: set[Path] = set()
            for item in catalog.get("outputs", ()):
                candidate = (root / str(item.get("path", ""))).resolve()
                cataloged_paths.add(candidate)
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
                if candidate.resolve() in cataloged_paths:
                    continue
                with candidate.open("rb") as stream:
                    prefix = stream.read(8)
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
            by_output: dict[str, list[dict[str, Any]]] = {}
            for action in actions:
                if action["classification"] not in {"compiler", "linker", "linker_driver", "archiver", "librarian"}:
                    continue
                for output in action["resolved_outputs"]:
                    by_output.setdefault(output, []).append(action)
            related_artifacts: set[str] = set()
            for artifact in artifacts:
                artifact_path = (unit.job.run_root / artifact["run_path"]).relative_to(root).as_posix()
                producers = by_output.get(artifact_path, [])
                if len(producers) == 1:
                    producer = producers[0]
                    producer["linked_artifact_ids"] = sorted(set([*producer["linked_artifact_ids"], artifact["artifact_id"]]))
                    producer["output_hashes"][artifact["artifact_id"]] = artifact["sha256"]
                    related_artifacts.add(artifact["artifact_id"])
                else:
                    gaps.append(f"no exact producing action resolved for {PurePosixPath(str(artifact['path'])).name}")
            for action in actions:
                action["input_artifact_ids"] = sorted({
                    artifact["artifact_id"] for artifact in artifacts
                    for item in action["discovered_inputs"]
                    if (unit.job.run_root / artifact["run_path"]).relative_to(root).as_posix() == item["path"]
                    and artifact["sha256"] == item["sha256"]})
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
                if record["sha256"] != artifact["sha256"]:
                    gaps.append(f"accepted artifact hash changed before inspection: {path.name}")
                    continue
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
            catalog = _case_catalog(unit, case_id)
            family = str(catalog.get("family") or catalog.get("mapping", {}).get("family") or "native")
            checks = deterministic_checks(provenance_value.get("actions", ()), inspection_value.get("records", ()),
                                          family=family)
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
            from appsec_review.guidance.workers import publish_worker_guidance
            model_identity = {"provider": str(settings["provider"]), "model": str(settings["model"]),
                              "reasoning": str(settings["reasoning"])}
            guidance, guidance_sha = publish_worker_guidance(
                unit.job.repository_root, unit.job.run_root, "post_build", model=settings)
            model_identity["guidance_sha256"] = guidance_sha
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
                        "working_directory", "discovered_inputs", "input_artifact_ids", "resolved_outputs",
                        "outputs", "output_hashes", "producer")} for value in provenance_value.get("actions", ())]
            records = [{key: value.get(key) for key in ("artifact_id", "sha256", "format", "kind", "architecture", "bits",
                        "headers", "sections", "imports", "exports", "relocations", "interpreter", "rpath", "runpath",
                        "dependencies", "archive_members", "build_id", "debug", "symbols", "hardening", "gaps")}
                       for value in inspection_value.get("records", ())]
            request = {"schema": "appsec-review/build-security-inference-request/1", "guidance": GUIDANCE_IDENTITY,
                       "response_schema": INFERENCE_RESPONSE_SCHEMA,
                       "case_id": _display(case_id), "topology": {"actions": len(actions), "artifacts": len(records)},
                       "actions": actions, "artifacts": records, "deterministic_results": deterministic_value["checks"],
                       "guidance_bundle_sha256": guidance_sha,
                       "artifact_admission": {"datasets": [
                           {"name": name, "producer": "job_post_build_security_assessment",
                            "accepted_sha256": value["artifact"]["sha256"]}
                           for name, value in (("actions", provenance_value), ("artifacts", inspection_value),
                                               ("deterministic_results", deterministic_value))]},
                       "coverage_gaps": list(dict.fromkeys([
                           *provenance_value.get("gaps", ()), *inspection_value.get("gaps", ()),
                           *deterministic_value.get("gaps", ())]))}
            encoded = canonical_json(request)
            gaps: list[str] = []
            if not actions and not records:
                # Nothing was built for this case (the upstream gaps are already in the request's
                # coverage_gaps and in the earlier stages): there is no evidence a model could cite.
                gaps.append("no build actions or binary artifacts are available; build-security inference was not run")
                result = {"observations": [], "rejections": [], "confirmed_count": 0,
                          "refuted_count": 0, "unvalidated_count": 0}
                calls = 0
            elif len(encoded) > int(settings["max_input_tokens"]) * 4:
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
                from appsec_review.inference.errors import (
                    ExecutionLimit, ModelOutputError, ProviderError, failure_category,
                )
                from appsec_review.inference.execution import CallContext, Execution, RetryPolicy
                import subprocess
                model_request = ModelRequest(
                    schema=INFERENCE_PROPOSAL_SCHEMA, persona="build_supply_chain",
                    role="build_security_assessor", guidance=guidance, summary=request,
                    allowed_scanners=(), allowed_build_systems=(), allowed_components=(), allowed_paths=(),
                    allowed_build_units=(), provider=str(settings["provider"]), model=str(settings["model"]),
                    reasoning=str(settings["reasoning"]), max_input_tokens=int(settings["max_input_tokens"]),
                    max_output_tokens=int(settings["max_output_tokens"]))
                known = {str(item.get("build_action_id")) for item in actions} | {
                    str(item.get("compile_unit_id")) for item in actions if item.get("compile_unit_id")} | {
                    str(item.get("artifact_id")) for item in records} | {str(item.get("sha256")) for item in records}
                aliases = {str(item["compile_unit_id"]): str(item["build_action_id"])
                           for item in actions if item.get("compile_unit_id")}
                aliases.update({str(item["artifact_id"]): str(item["sha256"]) for item in records})
                calls, proposal = 0, None
                last_error: Exception | None = None
                policy = RetryPolicy(int(settings["retries"]) + 1, True, True, True)
                engine = Execution(timeout_seconds=int(settings["timeout_seconds"]), max_calls=policy.attempts,
                    max_response_bytes=int(settings["max_output_tokens"]) * 4,
                    guidance_sha256=guidance_sha,
                    context=CallContext(unit.job.run_root, unit.job.run_id,
                                        "job_post_build_security_assessment", unit.job.attempt_id,
                                        "inference", _display(case_id), case_id=_display(case_id)))
                retry_reason = None
                accepted = False
                for attempt in range(1, policy.attempts + 1):
                    try:
                        proposal = engine.call(infer, model_request, timeout_seconds=int(settings["timeout_seconds"]),
                                               retry_count=attempt - 1, retry_reason=retry_reason)
                        try:
                            result = validate_inference(proposal.proposal, checks=deterministic_value["checks"],
                                                        evidence_ids=known, evidence_aliases=aliases)
                        except ValueError as exc:
                            raise ModelOutputError(str(exc)) from exc
                        accepted = True
                        break
                    except (ModelOutputError, ProviderError, TimeoutError, subprocess.TimeoutExpired, ExecutionLimit) as exc:
                        last_error = exc
                        try:
                            retry = engine.retry(attempt, exc, policy)
                        except ExecutionLimit:
                            retry = False
                        if not retry:
                            break
                        retry_reason = failure_category(exc).value
                    finally:
                        calls = engine.calls
                if not accepted:
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
            stage_hashes = {}
            for stage, value in (("provenance", provenance_value), ("inspection", inspection_value),
                                 ("deterministic", deterministic_value), ("inference", inference_value)):
                document = _read_json_artifact(unit.job.run_root, value["artifact"])
                if document != {key: item for key, item in value.items() if key not in {"artifact", "terminal_status"}}:
                    raise ValueError(f"{stage} stage content differs from its immutable artifact")
                stage_hashes[stage] = value["artifact"]["sha256"]
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
                model_identity=inference_value["model_identity"], upstream_manifest_sha256=upstream["sha256"],
                stage_hashes=stage_hashes, semantic_inputs={
                    "target_snapshot": unit.job.source_fingerprint,
                    "family": _case_catalog(unit, case_id).get("family") or
                              _case_catalog(unit, case_id).get("mapping", {}).get("family") or "native",
                    "model_settings": dict(unit.job.config.settings["model"]),
                })
            shard_id = f"build-security-{case_id}"
            shard_suffix = hashlib.sha256(shard_id.encode()).hexdigest()[:16]
            path = (unit.job.run_root / "data" / "indices" / "build_security" /
                    f"{fingerprint}-{shard_suffix}.sqlite")
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
                binary_paths: dict[str, str] = {}
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
                    run_path = PurePosixPath(str(record["run_path"])).as_posix()
                    if binary_paths.setdefault(run_path, identity.value) != identity.value:
                        raise ValueError(f"multiple inspected binaries resolve to {run_path}")
                    builder.add_entity(EntityRecord(identity, record["artifact_id"],
                        PurePosixPath(str(record["run_path"])).name, f"{record.get('format', 'unsupported')} {record.get('kind', 'unknown')}",
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
                            for item in action.get("discovered_inputs", ()):
                                input_path = item["path"]
                                input_name = PurePosixPath(input_path).name
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
                            for input_artifact in action.get("input_artifact_ids", ()):
                                input_id = binary_ids.get(input_artifact)
                                if input_id is not None and input_id != output_id:
                                    builder.add_relation(RelationRecord(RelationKind.LINKS_INTO,
                                        input_id, output_id, True, 1.0))
                evidence_entities = {**action_ids, **compile_ids, **binary_ids}
                hash_entities: dict[str, set[str]] = {}
                for record in inspection_value.get("records", ()):
                    hash_entities.setdefault(record["sha256"], set()).add(binary_ids[record["artifact_id"]])
                evidence_entities.update({sha: next(iter(ids)) for sha, ids in hash_entities.items() if len(ids) == 1})

                def evidence_entity(evidence_id: str, scope: str) -> str | None:
                    subject = evidence_entities.get(scope)
                    if subject in hash_entities.get(evidence_id, ()):
                        return subject
                    return evidence_entities.get(evidence_id)

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
                        endpoint = evidence_entity(str(evidence_id), str(check.get("scope")))
                        if endpoint:
                            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT,
                                check_identity.value, endpoint, True, 1.0))
                for observation in inference_value.get("observations", ()):
                    identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, unit.job.source_fingerprint,
                        {"case": case_id, "observation": observation["observation_id"]})
                    builder.add_entity(EntityRecord(identity, observation["observation_id"],
                        observation["check_id"], observation["claim"], {**dict(observation), "project": case_id,
                        "configuration": "RelWithDebInfo", "producer": "bounded_inference", "shard": shard_id}))
                    for evidence_id in observation.get("evidence_ids", ()):
                        endpoint = evidence_entity(str(evidence_id), str(observation.get("scope")))
                        if endpoint:
                            builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT,
                                identity.value, endpoint, True, 1.0))
                gaps = list(dict.fromkeys([*provenance_value.get("gaps", ()), *inspection_value.get("gaps", ()),
                                          *deterministic_value.get("gaps", ()), *inference_value.get("gaps", ())]))
                builder.add_coverage("post-build-security", "partial" if gaps else "complete",
                                     "; ".join(bounded_gap_messages(gaps, 20)) or None)
                sha = builder.build()
            else:
                sha = IndexBuilder(path, name="build_security", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint,
                                   shard_id=shard_id).attest_existing()
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
    implementation = None
    return Job("job_post_build_security_assessment", "post_build_security_assessment",
               UnitExecutor(values).execute, input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation, units=values,
               datasets=DATASETS, contract=CONTRACT)
