from __future__ import annotations

from appsec_review.interchange import bounded_gap_messages

from collections.abc import Mapping
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
from typing import Any
from appsec_review import seeding
from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.jobs.cpp_index_scopes import container_compile_database, project_prefix, workspace_root
from appsec_review.jobs.build_bookkeeping import bookkeeping_reason
from appsec_review.jobs.build_outcome import build_succeeded
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.jobs.job_language_build.native_components import (
    compile_commands as native_component_compile_commands,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256, protected_json, tool_input_json
from appsec_review.jobs.job_cpp_compiled_analysis.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_cpp_compiled_analysis import seeded

SCHEMA = "appsec-review/cpp-compiled-analysis/2"
PROJECT_TASKS = ("projects",)
BRANCHES = ("compiled", "ast", "ir", "infer", "binary")
AST_NODE_LIMIT = 20000
AST_CALLABLE_KINDS = frozenset({"FunctionDecl", "CXXMethodDecl", "CXXConversionDecl",
                               "CXXConstructorDecl", "CXXDestructorDecl"})
AST_ENTITY_KINDS = AST_CALLABLE_KINDS | {"VarDecl", "RecordDecl", "CallExpr", "DeclRefExpr",
                                        "FieldDecl", "ParmVarDecl", "TypedefDecl"}
BRANCH_IDENTITY = {"compiled": "cpp-compiled-index/4", "ast": "clang-ast/7",
                   "ir": "llvm-ir/4",
                   "infer": "infer-cpp-adapter/2",
                   "binary": "elf-symbols/3"}


def _project_key(root: PurePosixPath) -> str:
    return "project-" + hashlib.sha256(root.as_posix().encode()).hexdigest()[:16]


def _case_root(unit: UnitContext, case_id: str) -> Path:
    return unit.job.run_root / "data" / "cpp" / "attempts" / unit.job.attempt_id / "projects" / case_id


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _json_artifact(unit: UnitContext, path: Path, value: Any, *, immutable: bool = False) -> dict[str, Any]:
    if immutable:
        digest = hashlib.sha256(canonical_json(value)).hexdigest()
        path = path.with_name(f"{path.stem}-{digest}{path.suffix}")
        if path.exists():
            if path.is_symlink() or file_sha256(path) != digest:
                raise ValueError("immutable C++ artifact changed")
        else:
            protected_json(path, value)
    else:
        atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


# A language build that completed with named gaps (build-output classification heuristics, an unrecognised
# compiler probe) still materialised a workspace and an exact command set; its gaps travel with the case. On
# smoke-cpp run 2026-11-14-0005 a single low-confidence build-output heuristic gap made the only build unit
# BLOCKED_BY_COMPILE, so clangd, the Clang AST/IR producers and SVF indexed nothing (T-5016). The CodeQL
# planner applies the same rule (planning.py _USABLE_BUILD_STATUSES).
_USABLE_BUILD_STATUSES = frozenset({"SUCCEEDED", "NOT_APPLICABLE", "COMPLETED_WITH_GAPS"})


def _terminal_gap(output: Mapping[str, Any]) -> str | None:
    if output.get("terminal_status") in _USABLE_BUILD_STATUSES:
        receipt = output.get("build_receipt", output)
        database = receipt.get("native_compile_database")
        if receipt.get("family") == "native" and isinstance(database, Mapping) and database.get("entry_count") == 0:
            return "capture-backed native compile database is empty"
        return None
    gaps = output.get("gaps", ())
    from appsec_review.jobs.job_project_build.enforcement import gap_text
    return gap_text(gaps[0]) if gaps else "upstream C++ case action did not succeed"


def _checkpoint_identity(unit: UnitContext, case_id: str, stage: str, values: Mapping[str, Any],
                         *, tool_id: str = "tool-native-cpp") -> str:
    from appsec_review.config.assurance import ReviewPolicy
    policy = getattr(unit.job, "review_policy", ReviewPolicy())
    tool = load_catalog(unit.job.repository_root).tool(tool_id) if (
        unit.job.repository_root / "containers" / "catalog.toml").is_file() else None
    tool_identity = ({"tag": tool.tag, "version": tool.version,
                      "expected_image_id": tool.expected_image_id} if tool else
                     {"injected_executor": True})
    return hashlib.sha256(canonical_json({"schema": "appsec-review/cpp-checkpoint/1",
        "project": case_id, "stage": stage,
        "tool": tool_identity, "values": values,
        "releases": {key: policy.releases.values.get(key) for key in ("platform", "validation", tool_id)}
        })).hexdigest()


def _load_checkpoint(unit: UnitContext, case_id: str, stage: str, identity: str) -> Mapping[str, Any] | None:
    from appsec_review.config.assurance import ReviewPolicy
    policy = getattr(unit.job, "review_policy", ReviewPolicy())
    tool_id = "tool-infer" if stage == "branch-infer" else "tool-native-cpp"
    reusable, reason = policy.releases.require("platform", "validation", tool_id)
    if not reusable:
        unit.job.events.write("CHECKPOINT_MISSED", scope_id=case_id, action=stage, reason=reason)
        return None
    path = _case_root(unit, case_id) / "checkpoints" / f"{stage}.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if document.get("identity") != identity or not isinstance(document.get("result"), Mapping):
        return None
    result = dict(document["result"])
    def intact(value: Any) -> bool:
        if isinstance(value, Mapping):
            if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                artifact = unit.job.run_root / value["path"]
                if (artifact.is_symlink() or unit.job.run_root.resolve() not in artifact.resolve().parents
                        or not artifact.is_file() or file_sha256(artifact) != value["sha256"]):
                    return False
            return True
        return all(intact(item) for item in value) if isinstance(value, list) else True

    if not all(intact(value) for key, value in result.items() if key == "evidence" or isinstance(value, Mapping)):
        return None
    if result.get("checkpointable") is False or (
            result.get("terminal_status") != "SUCCEEDED" and result.get("checkpointable") is not True):
        return None
    return {**result, "checkpoint_reused": True}


def _save_checkpoint(unit: UnitContext, case_id: str, stage: str, identity: str,
                     result: Mapping[str, Any]) -> None:
    if result.get("checkpointable") is False or (
            result.get("terminal_status") != "SUCCEEDED" and result.get("checkpointable") is not True):
        return
    atomic_json(_case_root(unit, case_id) / "checkpoints" / f"{stage}.json",
                {"schema": "appsec-review/cpp-checkpoint/1", "identity": identity,
                 "project_key": case_id, "stage": stage, "result": dict(result)})


def _run_tool(unit: UnitContext, case_id: str, argv: tuple[str, ...], executor_factory=None,
              label: str = "") -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    executor = (executor_factory(unit) if executor_factory is not None else
                ContainerExecutor(load_catalog(unit.job.repository_root), unit.job.run_root))
    result = executor.execute(ExecutionRequest(
        tool_id="tool-native-cpp", argv=("/opt/appsec/native.py", *argv),
        target_root=unit.job.target_root or unit.job.repository_root, scratch_root=root,
    ))
    receipt = root / "execution.json"
    retained = unit.unit_root / f"{case_id}-{label or argv[0]}-{file_sha256(receipt)}-execution.json"
    retained.parent.mkdir(parents=True, exist_ok=True)
    if retained.exists():
        if retained.is_symlink() or file_sha256(retained) != file_sha256(receipt):
            raise ValueError("retained compiler execution changed")
    else:
        shutil.copyfile(receipt, retained)
    evidence = [_artifact(unit.job.run_root, retained)]
    for stream in ("stdout", "stderr"):
        source = unit.job.run_root / getattr(result, f"{stream}_path")
        digest = file_sha256(source)
        destination = root / "evidence" / "execution" / f"{digest}-{stream}.bin"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copyfile(source, destination)
        elif destination.is_symlink() or file_sha256(destination) != digest:
            raise ValueError("retained compiler stream changed")
        evidence.append({**_artifact(unit.job.run_root, destination),
                         "original_path": source.relative_to(unit.job.run_root).as_posix()})
    mode = "binary" if argv[0] == "symbols" else argv[0]
    atomic_json(root / "analysis" / mode / "execution-evidence.json", {"artifacts": evidence})
    return {"execution": _artifact(unit.job.run_root, retained), "exit_code": result.exit_code,
            "timed_out": result.timed_out, "oom_killed": result.oom_killed,
            "image_id": result.image_id, "image_digest": result.image_digest,
            "argv_identity": result.argv_identity}


def _infer_compile_database(catalog: Mapping[str, Any]) -> list[dict[str, Any]]:
    return container_compile_database(catalog["mapping"]["root"], catalog["compile_commands"])


def _run_infer(unit: UnitContext, case_id: str, catalog: Mapping[str, Any],
               executor_factory=None) -> Mapping[str, Any]:
    case_root = _case_root(unit, case_id)
    scratch = case_root / "analysis" / "infer-run"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    compile_database = scratch / "compile_commands.json"
    tool_input_json(compile_database, _infer_compile_database(catalog))
    tool_catalog = (load_catalog(unit.job.repository_root) if
                    (unit.job.repository_root / "containers" / "catalog.toml").is_file() else None)
    executor = (executor_factory(unit) if executor_factory is not None else
                ContainerExecutor(tool_catalog, unit.job.run_root))
    result = executor.execute(ExecutionRequest(
        tool_id="tool-infer",
        argv=("/opt/infer/bin/infer", "run", "--no-progress-bar", "--jobs", "2", "--results-dir",
              "/scratch/infer-out", "--compilation-database", "/scratch/compile_commands.json"),
        target_root=case_root, scratch_root=scratch, memory="4g",
    ))
    retained = unit.unit_root / f"{case_id}-infer-execution.json"
    retained.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(scratch / "execution.json", retained)
    report_path = scratch / "infer-out" / "report.json"
    value = {"execution": _artifact(unit.job.run_root, retained),
             "compile_database": _artifact(unit.job.run_root, compile_database),
             "tool_version": tool_catalog.tool("tool-infer").version if tool_catalog else "injected",
             "exit_code": result.exit_code, "timed_out": result.timed_out,
             "oom_killed": result.oom_killed, "image_id": result.image_id,
             "image_digest": result.image_digest, "argv_identity": result.argv_identity}
    if report_path.is_file() and not report_path.is_symlink():
        value["report"] = _artifact(unit.job.run_root, report_path)
    return value


def _source_files(root: Path) -> list[Path]:
    return [path for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()]


def _raw_compile_db(root: Path) -> Path:
    values = [root / "build" / "compile_commands.json", root / "source" / "compile_commands.json"]
    for path in values:
        if path.is_file() and not path.is_symlink():
            return path
    raise ValueError("build completed without compile_commands.json")


def _mapped_path(value: str, case_root: Path, target_root: str) -> str:
    normalized = value.replace("\\", "/")
    source = (case_root / "source").as_posix()
    if normalized == "/scratch/source" or normalized == source:
        return project_prefix(target_root).rstrip("/") or "."
    for prefix in ("/scratch/source/", source + "/"):
        if normalized.startswith(prefix):
            return project_prefix(target_root) + normalized[len(prefix):]
    return normalized


def _raw_arguments(row: Mapping[str, Any]) -> list[str]:
    raw = row.get("arguments")
    if not isinstance(raw, list):
        command = row.get("command")
        if not isinstance(command, str) or len(command) > 131072:
            raise ValueError("compile command must use bounded command or arguments form")
        raw = shlex.split(command)
    if not raw or len(raw) > 2048 or any(not isinstance(value, str) or "\x00" in value for value in raw):
        raise ValueError("compile command arguments are invalid")
    return list(raw)


def _compile_path(value: str, root: Path, mapping: Mapping[str, Any], *, directory: str = "",
                  source_only: bool = False) -> str:
    source_dir = workspace_root(str(mapping.get("source_dir", mapping["root"])))
    build_dir = workspace_root(str(mapping.get("build_dir", project_prefix(mapping["root"]) + "build")))
    value = value.replace("\\", "/")
    if not value.startswith("/"):
        cwd = directory.replace("\\", "/")
        if not cwd.startswith("/"):
            cwd = posixpath.join(source_dir, cwd)
        value = posixpath.join(cwd or source_dir, value)
    value = posixpath.normpath(value)
    aliases = [(root.as_posix() + "/source", "/scratch/source"), (source_dir, "/scratch/source")]
    if not source_only:
        aliases = [(root.as_posix() + "/build", "/scratch/build"), (build_dir, "/scratch/build"), *aliases]
    for prefix, destination in sorted(aliases, key=lambda pair: -len(pair[0])):
        if value == prefix or value.startswith(prefix + "/"):
            return destination + value[len(prefix):]
    return value


def _sanitize_arguments(row: Mapping[str, Any], case_root: Path, source_path: str,
                        target_root: str = "", *, mapping: Mapping[str, Any] | None = None) -> list[str]:
    raw = _raw_arguments(row)
    compiler = "clang++-18" if PurePosixPath(source_path).suffix.lower() in {".cc", ".cpp", ".cxx", ".c++", ".mm"} else "clang-18"
    result = [compiler]
    skip_next = False
    context = mapping or {"root": target_root}
    path_flags = ("-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-I", "--sysroot")
    paired = {*path_flags, "-x", "--target"}
    drop_paired = {"-o", "-MF", "-MT", "-MQ", "-MJ"}
    for value in raw[1:]:
        if skip_next:
            skip_next = False
            continue
        if value in drop_paired:
            skip_next = True
            continue
        if value in {"-c", "-M", "-MM", "-MD", "-MMD", "-MP"}:
            continue
        if value in paired:
            result.append(value)
            continue
        if result[-1] in paired:
            result.append(_compile_path(value, case_root, context, directory=str(row.get("directory", "")))
                          if result[-1] in path_flags else value)
            continue
        flag = next((flag for flag in path_flags if value.startswith(flag) and len(value) > len(flag)), None)
        if flag:
            separator = "=" if value[len(flag):].startswith("=") else ""
            result.append(flag + separator + _compile_path(value[len(flag) + len(separator):],
                          case_root, context, directory=str(row.get("directory", ""))))
            continue
        if value.startswith(("-D", "-U", "-std=", "-f", "-m", "-W", "--target=")):
            result.append(value)
    result.append(source_path)
    return result


def _output_path(row: Mapping[str, Any], root: Path, target_root: str = "",
                 *, mapping: Mapping[str, Any] | None = None) -> str | None:
    raw = _raw_arguments(row)
    value = row.get("output") if isinstance(row.get("output"), str) else None
    if value is None:
        for index, argument in enumerate(raw[:-1]):
            if argument == "-o":
                value = raw[index + 1]
                break
    if not value:
        return None
    normalized = _compile_path(value, root, mapping or {"root": target_root},
                               directory=str(row.get("directory", "")))
    if normalized == "/scratch/build":
        return "build"
    if normalized.startswith("/scratch/build/"):
        return "build/" + normalized[len("/scratch/build/"):]
    return None


def normalize_link_commands(value: Any, outputs: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Retain only bounded link edges between cataloged build artifacts."""
    if not isinstance(value, list) or len(value) > 4096:
        return []
    known = {str(item["path"]) for item in outputs}
    result = []
    for item in value:
        if not isinstance(item, Mapping) or str(item.get("output_path")) not in known:
            continue
        inputs = sorted({str(path) for path in item.get("input_paths", ()) if str(path) in known
                         and str(path) != str(item["output_path"])})
        if not inputs:
            continue
        result.append({"output_path": str(item["output_path"]), "input_paths": inputs,
                       "receipt": str(item.get("receipt", "")),
                       "command_sha256": str(item.get("command_sha256", ""))})
    return result


def _accepted_links(unit: UnitContext, receipt: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[str]]:
    identity = receipt.get("link_database")
    if not isinstance(identity, Mapping):
        return [], ["accepted link database is unavailable"]
    path = unit.job.run_root / str(identity.get("path", ""))
    if (path.is_symlink() or unit.job.run_root.resolve() not in path.resolve().parents or not path.is_file()
            or file_sha256(path) != identity.get("sha256")):
        raise ValueError("accepted link database identity changed")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("accepted link database exceeds bound")
    rows = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(rows, list) or len(rows) > 4096 or
            identity.get("relationship_count") != len(rows) or any(
                not isinstance(row, Mapping) or not isinstance(row.get("output_path"), str) or
                not isinstance(row.get("input_paths"), list) or
                any(not isinstance(value, str) for value in row["input_paths"]) for row in rows)):
        raise ValueError("accepted link database shape/count is invalid")
    return rows, []


def _tu_identity(mapping: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json({
        "schema": "appsec-review/cpp-translation-unit/1",
        "project_id": mapping["project_id"], "case_snapshot": mapping["case_snapshot"],
        "target_path": row["target_path"], "source_sha256": row["source_sha256"],
        "command_sha256": row["command_sha256"],
    })).hexdigest()


def normalize_compile_db(root: Path, mapping: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw_path = _raw_compile_db(root)
    if raw_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("compile database exceeds the 16 MiB bound")
    rows = json.loads(raw_path.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows or len(rows) > 4096:
        raise ValueError("compile database must contain 1..4096 entries")
    target_root = str(mapping["root"])
    result = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or not isinstance(row.get("file"), str):
            raise ValueError("compile database row is malformed")
        raw_arguments = list(row.get("arguments") or shlex.split(str(row.get("command", ""))))
        if "-cc1" in raw_arguments:
            continue
        if not isinstance(row.get("directory"), str) or not row["directory"].replace("\\", "/").startswith("/"):
            raise ValueError("compile directory has no accepted absolute identity")
        directory = _compile_path(str(row.get("directory", "")), root, mapping)
        if not any(directory == prefix or directory.startswith(prefix + "/")
                   for prefix in ("/scratch/source", "/scratch/build")):
            raise ValueError(f"compile directory is outside accepted source/build context: {row.get('directory')}")
        scratch_source = _compile_path(row["file"], root, mapping, directory=str(row.get("directory", "")),
                                       source_only=True)
        matches = [item for item in mapping.get("files", ()) if scratch_source == "/scratch/" + item["scratch_path"]]
        if len(matches) != 1:
            raise ValueError(f"compile database source is not in the accepted case mapping: {row['file']}")
        source_record = matches[0]
        target_path = source_record["target_path"]
        arguments = _sanitize_arguments(row, root, scratch_source, target_root, mapping=mapping)
        result.append({"project_key": mapping["project_key"], "index": index, "directory": directory,
                       "file": scratch_source, "target_path": target_path, "arguments": arguments,
                       "source_sha256": source_record["sha256"],
                       "output_path": _output_path(row, root, target_root, mapping=mapping),
                       "command_sha256": hashlib.sha256(canonical_json({
                           "arguments": arguments, "directory": directory})).hexdigest()})
        result[-1]["compile_unit_id"] = _tu_identity(mapping, result[-1])
    return sorted(result, key=lambda item: (item["target_path"], item["command_sha256"]))


def _restore_replay_commands(unit: UnitContext, case_id: str, catalog: Mapping[str, Any]) -> None:
    """Recreate tool staging only from the accepted, hash-bound command artifact."""
    identity = catalog["compile_database"]
    path = unit.job.run_root / str(identity.get("path", ""))
    if (path.is_symlink() or unit.job.run_root.resolve() not in path.resolve().parents
            or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024):
        raise ValueError("accepted compile database is unavailable or unsafe")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != identity.get("sha256"):
        raise ValueError("accepted compile database identity changed")
    commands = json.loads(data)
    if not isinstance(commands, list) or len(commands) > 4096 or commands != catalog["compile_commands"]:
        raise ValueError("accepted compile database command context changed")
    destination = _case_root(unit, case_id) / "normalized-compile-commands.json"
    # Historical catalogs can pin this same file. Verify their bytes, never rewrite their authority.
    if destination.resolve() != path.resolve():
        tool_input_json(destination, commands)


_MISSING_HEADER = (
    re.compile(r"fatal error: '([^'\n]{1,512})' file not found"),
    re.compile(r"fatal error: ([^:\n]{1,512}): No such file or directory"),
)


def replay_failures(root: Path, mode: str, commands: list[Mapping[str, Any]]) -> dict[int, str] | None:
    """Name each translation unit the AST or IR replay could not compile, from its bounded receipt.

    A header the replay image does not carry is named as such, so a missing include path is a
    visible gap rather than an empty index. Returns ``None`` when the receipt is unusable.
    """
    from appsec_review.runtime import execution_safety as safety
    path = root / "analysis" / mode / "receipt.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
        safety.fail("required replay receipt is missing or unsafe", action=f"compiled.{mode}")
        return None
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        safety.retain_failure(f"compiled.{mode}", exc)
        safety.fail("required replay receipt is malformed", action=f"compiled.{mode}")
        return None
    if not isinstance(records, list) or len(records) != len(commands):
        safety.fail("replay receipt does not cover its commands", action=f"compiled.{mode}")
        return None
    failures: dict[int, str] = {}
    for index, (record, command) in enumerate(zip(records, commands)):
        if (not isinstance(record, Mapping) or type(record.get("index")) is not int or record["index"] != index
                or ("source" in record and "file" in command and record["source"] != command["file"])):
            safety.fail("replay receipt command identity is invalid", action=f"compiled.{mode}")
            return None
        if record.get("output_truncated"):
            failures[index] = f"{command['target_path']}: {mode} replay output was truncated"
            continue
        if type(record.get("exit_code")) is int and record["exit_code"] == 0 and not record.get("timeout"):
            continue
        stderr = str(record.get("stderr", ""))[:8192]
        prefix = f"{command['target_path']}: {mode} replay"
        missing = next((match.group(1) for pattern in _MISSING_HEADER
                        for match in [pattern.search(stderr)] if match), None)
        if record.get("timeout"):
            failures[index] = f"{prefix} timed out"
        elif missing is not None:
            failures[index] = (f"{prefix} header not found in tool-native-cpp: {missing} "
                               "(an include path the build image had is absent from the replay image)")
        else:
            first = next((line.strip() for line in stderr.splitlines() if "error" in line), "")
            failures[index] = f"{prefix} failed with exit {record.get('exit_code')}" + (
                f": {first[:512]}" if first else "")
    if failures:
        safety.fail("replay contains failed compilation commands", action=f"compiled.{mode}")
    return failures


def _location(snapshot: str, target: Path, path: str, line: int = 1, column: int = 1,
              *, ambiguous: bool = False, method: str = "exact-path") -> SourceLocation:
    file_path = target / Path(*PurePosixPath(path).parts)
    data = file_path.read_bytes()
    safe_line = max(1, line)
    return SourceLocation(snapshot, path, hashlib.sha256(data).hexdigest(), 0, len(data), safe_line,
                          safe_line, max(1, column), max(1, column),
                          {"path": path, "line": safe_line, "column": max(1, column)},
                          method, 0.5 if ambiguous else 1.0, ambiguous)


def _new_builder(unit: UnitContext, name: str, case_id: str, branch: str,
                 artifacts: list[Mapping[str, Any]], gaps: list[str], tool: Mapping[str, Any],
                 scope_snapshot: str):
    evidence = []
    root = _case_root(unit, case_id)
    modes = ("ir", "cfg") if branch == "ir" else (branch,) if branch in {"ast", "binary"} else ()
    for mode in modes:
        paths = sorted((root / "analysis" / mode).glob("*"))
        paths += [root / f"replay-{mode}.json"]
        for source in paths:
            if not source.is_file() or source.is_symlink() or source.stat().st_size > 64 * 1024 * 1024:
                continue
            digest = file_sha256(source)
            retained = root / "evidence" / mode / f"{digest}-{source.name}"
            retained.parent.mkdir(parents=True, exist_ok=True)
            if not retained.exists():
                shutil.copyfile(source, retained)
            elif file_sha256(retained) != digest:
                raise ValueError("retained compiler evidence changed")
            evidence.append(_artifact(unit.job.run_root, retained))
            if source.name == "execution-evidence.json":
                evidence.extend(json.loads(source.read_text(encoding="utf-8"))["artifacts"])
    fingerprint = index_fingerprint(name=name, target_snapshot=scope_snapshot,
        producer_artifacts=[*artifacts, *evidence], tool_identity=tool,
        parser_identity=BRANCH_IDENTITY[branch],
        normalizer_identity=f"cpp-{branch}-normalizer/4", mapping_identity="cpp-source-mapping/4")
    shard = f"cpp-{case_id}-{branch}"
    physical_shard = hashlib.sha256(shard.encode()).hexdigest()[:16]
    path = unit.job.run_root / "data" / "indices" / name / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}-{physical_shard}.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    builder.cpp_evidence = evidence
    return builder, path, fingerprint, shard


def _finish_index(unit: UnitContext, builder: IndexBuilder, path: Path, fingerprint: str,
                  shard: str, name: str, branch: str, gaps: list[str],
                  seeded: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    # Outcomes and late parse/location gaps are semantic inputs too. A retry must not select an
    # earlier shard merely because the executor's receipt and compile command did not change.
    fingerprint = hashlib.sha256(canonical_json({
        "inputs": fingerprint, "entities": [asdict(item) for item in builder.entities],
        "relations": [asdict(item) for item in builder.relations],
        "coverage": builder.coverage, "gaps": gaps,
    })).hexdigest()
    path = path.with_name(f"{fingerprint}-{hashlib.sha256(shard.encode()).hexdigest()[:16]}.sqlite")
    builder.path, builder.fingerprint = path, fingerprint
    sha, reused = builder.build_or_reuse()
    producer: dict[str, Any] = {"job": "job_cpp_compiled_analysis", "unit": unit.unit_id, "branch": branch}
    if seeded is not None:
        producer["seeded"] = dict(seeded)
    identity = IndexIdentity(name, "appsec-review/retrieval-index/2", sha, fingerprint,
                             path.relative_to(unit.job.run_root).as_posix(),
                             producer, tuple(gaps), shard)
    return {"index_identity": asdict(identity), "index_reused": reused,
            "artifact": _artifact(unit.job.run_root, path), "gaps": gaps,
            "evidence": builder.cpp_evidence,
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}


def _build_entities(unit: UnitContext, case_id: str, catalog: Mapping[str, Any]) -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    mapping = catalog["mapping"]
    commands = catalog["compile_commands"]
    artifacts = [catalog["compile_database"], catalog["artifact_catalog"], catalog["link_database"]]
    builder, path, fingerprint, shard = _new_builder(unit, "build", case_id, "compiled", artifacts, [],
        {"compiler_image": catalog["image_id"], "compiler": "clang-18"}, mapping["case_snapshot"])
    project = LogicalIdentity.derive(EntityKind.PROJECT, mapping["case_snapshot"],
                                     {"project_id": mapping["project_id"], "root": mapping["root"]})
    builder.add_entity(EntityRecord(project, mapping["project_id"], mapping["display_name"],
                                    mapping["root"], {**mapping, "shard_id": shard}))
    action = LogicalIdentity.derive(EntityKind.BUILD_ACTION, mapping["case_snapshot"],
                                    {"project_id": mapping["project_id"],
                                     "case_snapshot": mapping["case_snapshot"],
                                     "profile": mapping["build_system"]})
    builder.add_entity(EntityRecord(action, case_id, mapping["display_name"],
                                    f"{mapping['build_system']} build action",
                                    {**mapping, "shard_id": shard}))
    builder.add_relation(RelationRecord(RelationKind.CONTAINS, project.value, action.value, True, 1.0))
    source_entities: dict[str, str] = {}
    for record in mapping["files"]:
        source = LogicalIdentity.derive(EntityKind.SOURCE_FILE, mapping["case_snapshot"],
                                        {"project_id": mapping["project_id"],
                                         "path": record["target_path"], "sha256": record["sha256"]})
        source_entities[record["target_path"]] = source.value
        builder.add_entity(EntityRecord(source, record["target_path"],
                                        PurePosixPath(record["target_path"]).name,
                                        record["target_path"],
                                        {**record, "project_id": mapping["project_id"], "shard_id": shard},
                                        _location(unit.job.source_fingerprint, unit.job.target_root or Path(),
                                                  record["target_path"])))
        builder.add_relation(RelationRecord(RelationKind.CONTAINS, project.value, source.value, True, 1.0))
    compile_entities: dict[str, str] = {}
    for row in commands:
        compile_id = LogicalIdentity.derive(EntityKind.COMPILE_UNIT, mapping["case_snapshot"],
                                            {"compile_unit_id": row["compile_unit_id"]})
        compile_entities[row["compile_unit_id"]] = compile_id.value
        builder.add_entity(EntityRecord(compile_id, row["command_sha256"], row["target_path"],
                                        " ".join(row["arguments"]),
                                        {**row, "project_id": mapping["project_id"], "shard_id": shard},
                                        _location(unit.job.source_fingerprint,
                                                  unit.job.target_root or Path(), row["target_path"])))
        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, compile_id.value, action.value, True, 1.0))
        source_id = source_entities.get(row["target_path"])
        if source_id is not None:
            builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM,
                                                compile_id.value, source_id, True, 1.0))
    output_entities: dict[str, str] = {}
    for item in catalog["outputs"]:
        kind = {"object": EntityKind.OBJECT_FILE, "library": EntityKind.LIBRARY,
                "executable": EntityKind.EXECUTABLE}[item["kind"]]
        identity = LogicalIdentity.derive(kind, mapping["case_snapshot"],
                                          {"project_id": mapping["project_id"], "path": item["path"],
                                           "sha256": item["sha256"]})
        output_entities[item["path"]] = identity.value
        builder.add_entity(EntityRecord(identity, item["path"], PurePosixPath(item["path"]).name,
                                        item["kind"], {**item, "project_id": mapping["project_id"],
                                                              "artifact_id": identity.value,
                                                              "shard_id": shard}))
    related = 0
    for row in commands:
        output_id = output_entities.get(str(row.get("output_path")))
        if output_id is not None:
            builder.add_relation(RelationRecord(RelationKind.COMPILES_TO,
                compile_entities[row["compile_unit_id"]], output_id, True, 1.0,
                payload={"mapping": "compile-database-output"}))
            related += 1
    for receipt in catalog.get("link_commands", ()):
        output_id = output_entities.get(str(receipt.get("output_path")))
        if output_id is None:
            continue
        for input_path in receipt.get("input_paths", ()):
            input_id = output_entities.get(str(input_path))
            if input_id is not None:
                builder.add_relation(RelationRecord(RelationKind.LINKS_INTO, input_id, output_id,
                    True, 1.0, payload={"mapping": "captured-link-command"}))
                related += 1
    gaps = list(catalog.get("gaps", ()))
    if not related:
        gaps.append("no exact compile-output or captured link relation was available")
    builder.add_coverage("compile-and-link", "partial" if gaps else "complete", "; ".join(gaps) or None)
    return _finish_index(unit, builder, path, fingerprint, shard, "build", "compiled",
                         gaps)


def _walk_ast(value: Any, *, limit: int | None = 20000):
    stack = [value]
    count = 0
    while stack and (limit is None or count < limit):
        item = stack.pop()
        if not isinstance(item, Mapping):
            continue
        count += 1
        yield item
        children = item.get("inner", ())
        if isinstance(children, list):
            stack.extend(reversed(children))


def _load_ast_document(path: Path) -> Mapping[str, Any]:
    if path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Clang AST output is unsafe or over bound")
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    documents: list[Mapping[str, Any]] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, Mapping):
            raise ValueError("Clang AST record is not an object")
        if not isinstance(value.get("kind"), str) or not value["kind"]:
            raise ValueError("Clang AST record has no node kind")
        documents.append(value)
        if len(documents) > 4096:
            raise ValueError("Clang AST declaration count exceeds bound")
    if not documents:
        raise ValueError("Clang AST output is empty")
    if len(documents) == 1:
        return documents[0]
    return {"kind": "TranslationUnitDecl", "inner": documents}


def _callee_decl(node: Mapping[str, Any]) -> Any:
    """The declaration a call or reference names. Clang nests a call's callee under ``inner``."""
    declaration = node.get("referencedDecl") or node.get("referencedMemberDecl")
    if declaration is not None or str(node.get("kind", "")) != "CallExpr":
        return declaration
    frontier = [node]
    for _ in range(4):
        following = []
        for value in frontier:
            for child in value.get("inner", ()) if isinstance(value.get("inner"), list) else ():
                if not isinstance(child, Mapping):
                    continue
                found = child.get("referencedDecl") or child.get("referencedMemberDecl")
                if found is not None:
                    return found
                following.append(child)
        frontier = following
    return None


class _AstLocations:
    """Resolve Clang's dump-order file elision, never ``includedFrom`` or a TU fallback.

    Offsets and columns are byte positions in the original accepted file, not decoded text.
    Macro spelling/expansion alternatives remain raw evidence rather than one invented location.
    """

    def __init__(self, unit: UnitContext, mapping: Mapping[str, Any], command: Mapping[str, Any]):
        self.snapshot = unit.job.source_fingerprint
        self.target = unit.job.target_root or Path()
        self.command = command
        self.files = mapping["files"]
        self.current_file: str | None = None
        self.last_file: str | None = None
        self.node_files: list[str | None] = []
        self.cache: dict[str, tuple[Mapping[str, Any], bytes] | None] = {}

    def _source(self, raw: str) -> tuple[Mapping[str, Any], bytes] | None:
        path = posixpath.normpath(raw if raw.startswith("/") else
                                 posixpath.join(str(self.command["directory"]), raw))
        if path not in self.cache:
            matches = [row for row in self.files if path == "/scratch/" + row["scratch_path"]]
            result = None
            if len(matches) == 1:
                row = matches[0]
                source = self.target / row["target_path"]
                try:
                    if not source.is_symlink() and source.resolve().is_relative_to(self.target.resolve()):
                        data = source.read_bytes()
                        if hashlib.sha256(data).hexdigest() == row["sha256"]:
                            result = (row, data)
                except OSError:
                    pass
            self.cache[path] = result
        return self.cache[path]

    def _advance_ast_file(self, point: Any) -> bool:
        """Advance the stream and retain each node-local provenance branch, including unknowns."""
        if not isinstance(point, Mapping):
            self.current_file = None
            self.node_files.append(None)
            return False
        macro = "spellingLoc" in point or "expansionLoc" in point
        # JSONNodeDumper writes spelling before expansion; either can elide its filename.
        emitted = (point.get("spellingLoc"), point.get("expansionLoc")) if macro else (point,)
        if macro and any(key in point for key in ("file", "offset", "line", "col", "tokLen")):
            self.node_files.append(None)  # Conflicting macro and bare-location forms.
        for bare in emitted:
            if not isinstance(bare, Mapping):
                self.current_file = None
                self.node_files.append(None)
                continue
            if "file" in bare:
                filename = bare["file"]
                self.current_file = (filename if isinstance(filename, str) and filename
                                     and "\x00" not in filename else None)
            positioned = "offset" in bare or ("line" in bare and "col" in bare)
            valid = positioned and all(
                type(bare[key]) is int and bare[key] >= minimum
                for key, minimum in (("offset", 0), ("line", 1), ("col", 1), ("tokLen", 0))
                if key in bare)
            valid = valid and not ("spellingLoc" in bare or "expansionLoc" in bare)
            self.node_files.append(self.current_file if valid else None)
        return macro

    def wholly_foreign(self, accepted_paths: set[str]) -> bool:
        """Only known foreign branches permit exclusion; the stream's final filename is not ownership."""
        if not self.node_files:
            return False
        for raw in self.node_files:
            if raw is None:
                return False
            if not raw.startswith("/"):
                directory = self.command.get("directory")
                if not isinstance(directory, str) or not directory.startswith("/") or "\x00" in directory:
                    return False
                raw = posixpath.join(directory, raw)
            if posixpath.normpath(raw) in accepted_paths:
                return False
        return True

    def resolve(self, node: Mapping[str, Any]) -> tuple[SourceLocation | None, str | None]:
        loc = node.get("loc") if isinstance(node.get("loc"), Mapping) else {}
        span = node.get("range") if isinstance(node.get("range"), Mapping) else {}
        begin = span.get("begin") if isinstance(span.get("begin"), Mapping) else {}
        selected = loc or begin
        points = [(node.get("loc"), "loc" in node, selected is loc),
                  (span.get("begin"), "range" in node, selected is begin),
                  (span.get("end"), "range" in node, False)]
        selected_file = None
        macro = False
        self.node_files = []
        for point, relevant, is_selected in points:
            if not relevant:
                continue
            point_macro = self._advance_ast_file(point)
            macro |= point_macro
            if is_selected:
                selected_file = None if point_macro else self.current_file
        self.last_file = selected_file
        if macro:
            return None, "macro spelling/expansion location is ambiguous"
        if not selected or not selected_file:
            return None, "source file or position is absent"
        source = self._source(selected_file)
        if source is None:
            return None, "source file is unmapped, ambiguous or its accepted bytes changed"
        row, data = source

        def integer(key: str, minimum: int) -> int | None:
            value = selected.get(key)
            return value if type(value) is int and value >= minimum else None

        offset, line, column = integer("offset", 0), integer("line", 1), integer("col", 1)
        if any(key in selected and value is None for key, value in
               (("offset", offset), ("line", line), ("col", column))):
            return None, "invalid source coordinates"
        if offset is None:
            if line is None or column is None:
                return None, "source line/column and byte offset are incomplete"
            lines = data.splitlines(keepends=True)
            if not 1 <= line <= len(lines) or column > len(lines[line - 1].rstrip(b"\r\n")) + 1:
                return None, "source line/column lies outside accepted bytes"
            offset = sum(map(len, lines[:line - 1])) + column - 1
        if offset > len(data):
            return None, "source byte offset lies outside accepted bytes"
        actual_line = data.count(b"\n", 0, offset) + 1
        actual_column = offset - data.rfind(b"\n", 0, offset)
        if (line is not None and line != actual_line) or (column is not None and column != actual_column):
            return None, "source line/column conflicts with byte offset"
        token = integer("tokLen", 0)
        if "tokLen" in selected and token is None:
            return None, "invalid source token length"
        stop = offset + (token or 0)
        if stop > len(data):
            return None, "source token lies outside accepted bytes"
        last = max(offset, stop - 1)
        producer = {"loc": dict(loc), "range": dict(span), "resolved_file": selected_file,
                    "compile_unit_id": self.command["compile_unit_id"]}
        return SourceLocation(self.snapshot, row["target_path"], row["sha256"], offset, stop,
                              actual_line, data.count(b"\n", 0, last) + 1, actual_column,
                              last - data.rfind(b"\n", 0, last), producer,
                              "clang-source-position", 1.0), None


def _ast_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any], execution: Mapping[str, Any],
               failures: Mapping[int, str] | None = None) -> Mapping[str, Any]:
    gaps: list[str] = []
    failures = dict(failures or {})
    builder, path, fingerprint, shard = _new_builder(unit, "analysis", case_id, "ast",
        [execution["execution"], catalog["compile_database"]], gaps,
        {"tool": "clang-18", "image": execution["image_id"], "callee_decl": 1},
        catalog["mapping"]["case_snapshot"])
    count = _add_ast_entities(unit, case_id, catalog, failures, builder, shard, gaps)
    builder.add_coverage("clang-ast", "partial" if gaps else "complete",
                         "; ".join(bounded_gap_messages(gaps, 10)) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "analysis", "ast", gaps))
    result.update(entity_count=count, checkpointable=not failures)
    return result


def _add_ast_entities(unit: UnitContext, case_id: str, catalog: Mapping[str, Any],
                      failures: dict[int, str], builder: IndexBuilder, shard: str,
                      gaps: list[str], parsed_units: dict[int, set[str]] | None = None,
                      bounded_units: set[int] | None = None) -> int:
    root = _case_root(unit, case_id)
    count = 0
    seen_entities: set[str] = set()
    for index, command in enumerate(catalog["compile_commands"]):
        if index in failures:
            gaps.append(failures[index])
            continue
        ast_path = root / "analysis" / "ast" / f"tu-{index:04d}.json"
        try:
            document = _load_ast_document(ast_path)
        except (OSError, ValueError, UnicodeDecodeError):
            from appsec_review.runtime import execution_safety as safety
            safety.fail("Clang AST output is unavailable or malformed", action="cpp.ast")
            failures[index] = f"{command['target_path']}: Clang AST output unavailable or invalid"
            gaps.append(failures[index])
            continue
        if parsed_units is not None:
            parsed_units[index] = set()
        locations = _AstLocations(unit, catalog["mapping"], command)
        admitted = set(command.get("ast_linkages", ()))
        excluded: set[int] = set()
        location_gaps: set[str] = set()
        accepted_paths = {"/scratch/" + row["scratch_path"] for row in catalog["mapping"]["files"]}
        retained = filtered = 0
        for node in _walk_ast(document, limit=None):
            location, location_gap = locations.resolve(node)
            if id(node) in excluded:
                continue
            if admitted and node.get("kind") in AST_CALLABLE_KINDS:
                linkage = node.get("mangledName")
                if linkage and linkage not in admitted:
                    excluded.update(id(child) for child in _walk_ast(node))
                    continue
                elif not linkage:
                    location_gaps.add("function linkage is absent; neighborhood membership is unresolved")
            kind = str(node.get("kind", ""))
            if kind not in AST_ENTITY_KINDS:
                continue
            if not command.get("ast_filters") and locations.wholly_foreign(accepted_paths):
                filtered += 1
                continue
            if retained >= AST_NODE_LIMIT:
                gaps.append(f"ast_truncated: {command['target_path']}: node detail cut at {AST_NODE_LIMIT}")
                if bounded_units is not None:
                    bounded_units.add(index)
                break
            retained += 1
            if parsed_units is not None and kind in AST_CALLABLE_KINDS:
                linkage = node.get("mangledName")
                if isinstance(linkage, str) and linkage:
                    parsed_units[index].add(linkage)
            declared = _callee_decl(node)
            name = str(node.get("name") or (declared.get("name") if isinstance(declared, Mapping) else None) or kind)
            if location_gap:
                location_gaps.add(location_gap)
            line = location.start_line if location else None
            column = location.start_column if location else None
            native = str(node.get("id") or hashlib.sha256(canonical_json({
                "tu": command["compile_unit_id"], "ordinal": count, "kind": kind,
                "line": line, "column": column, "node": node,
            })).hexdigest())
            identity = LogicalIdentity.derive(EntityKind.AST_NODE, catalog["mapping"]["case_snapshot"],
                {"compile_unit_id": command["compile_unit_id"], "native": native, "kind": kind,
                 "line": line, "column": column})
            if identity.value in seen_entities:
                continue
            seen_entities.add(identity.value)
            builder.add_entity(EntityRecord(identity, native, name, f"{kind} {name}",
                {"kind": kind, "type": node.get("type"), "referenced_decl": _callee_decl(node),
                 "mangled_name": node.get("mangledName"),
                 "clang_location": {"loc": node.get("loc"), "range": node.get("range")},
                 "location_gap": location_gap,
                 "project_id": catalog["mapping"]["project_id"],
                 "compile_unit_id": command["compile_unit_id"], "shard_id": shard},
                location))
            count += 1
        if filtered:
            gaps.append(f"ast_source_filtered: {command['target_path']}: {filtered} nodes outside accepted sources")
        gaps.extend(f"ast_location_unresolved: {command['target_path']} "
                    f"({command['compile_unit_id']}): {message}" for message in sorted(location_gaps))
    return count


def _ir_source(unit: UnitContext, mapping: Mapping[str, Any], command: Mapping[str, Any], function):
    """Admit debug paths through the accepted mapping and bytes, not a TU/display-name fallback."""
    relative = function.path
    raw = relative if relative.startswith("/") else posixpath.join("/scratch/source", relative)
    resolver = _AstLocations(unit, mapping, command)
    source = resolver._source(raw)
    if source is None:
        return False, None, f"ir_source_unresolved: {function.linkage_name}: {relative}"
    location, gap = resolver.resolve({"loc": {"file": raw, "line": function.start_line, "col": 1}})
    if location is not None:
        location = replace(location, mapping_method="ir-debug-info")
    return True, location, f"ir_location_unresolved: {function.linkage_name}: {gap}" if gap else None


def _read_ir_module(path: Path, *, block_limit: int):
    from .llvm_ir import IrModule, parse_module
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return IrModule((), unparsed=("LLVM IR text is unreadable",))
    return parse_module(text, block_limit=block_limit)


def _ir_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any], execution: Mapping[str, Any],
              failures: Mapping[int, str] | None = None, *, cfgs=None, cfg_gaps=(),
              block_limit: int = 4000) -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    gaps: list[str] = list(cfg_gaps)
    failures = dict(failures or {})
    commands, mapping = catalog["compile_commands"], catalog["mapping"]
    parsed, locations = [], {}
    for index, command in enumerate(commands):
        if index in failures:
            gaps.append(failures[index])
            continue
        ir_path = root / "analysis" / "ir" / f"tu-{index:04d}.ll"
        if not ir_path.is_file() or ir_path.is_symlink() or ir_path.stat().st_size > seeded.MAX_IR_BYTES:
            failures[index] = f"{command['target_path']}: LLVM IR output unavailable or over bound"
            gaps.append(failures[index])
            continue
        module = _read_ir_module(ir_path, block_limit=block_limit)
        if module.unparsed:
            failures[index] = f"{command['target_path']}: LLVM IR could not be fully parsed: " + "; ".join(module.unparsed[:10])
            gaps.append(failures[index])
        for fn in module.functions:
            admitted, location, gap = _ir_source(unit, mapping, command, fn)
            if gap:
                gaps.append(gap)
            if admitted:
                parsed.append((index, fn))
                locations[(index, fn.linkage_name)] = location
            if fn.truncated:
                gaps.append(f"export_truncated: {fn.linkage_name} flow detail: {', '.join(fn.truncated)}")
    cfgs = cfgs or {}
    source_cfg, ambiguous_cfg, missing_cfg = seeded._match_cfgs(
        parsed, {(pos, fn.linkage_name) for pos, fn in parsed}, cfgs)
    if source_cfg:
        gaps.append(seeded.NO_BLOCK_LINES_GAP)
    if ambiguous_cfg:
        gaps.append("source_cfg_ambiguous: " + ", ".join(ambiguous_cfg[:20]))
    if missing_cfg:
        gaps.append("source_cfg_unmatched: " + ", ".join(missing_cfg[:20]))
    builder, path, fingerprint, shard = _new_builder(unit, "analysis", case_id, "ir",
        [execution["execution"], catalog["compile_database"]], gaps,
        {"tool": "clang-18-llvm-ir", "image": execution["image_id"], "block_limit": block_limit},
        mapping["case_snapshot"])
    entities, external = {}, {}
    for index, fn in parsed:
        command = commands[index]
        identity = LogicalIdentity.derive(EntityKind.IR_ENTITY, mapping["case_snapshot"], {
            "compile_unit_id": command["compile_unit_id"], "function": fn.linkage_name,
            "definition_line": fn.start_line})
        entities[(index, fn.linkage_name)] = identity.value
        if not fn.internal:
            external.setdefault(fn.linkage_name, []).append(identity.value)
        builder.add_entity(EntityRecord(identity, f"{index}:{fn.linkage_name}", fn.name,
            f"define {fn.linkage_name}", {
                "kind": "function", "linkage_name": fn.linkage_name, "internal": fn.internal,
                "flow": fn.flow(), "seeded": False, "project_id": mapping["project_id"],
                "compile_unit_id": command["compile_unit_id"], "shard_id": shard,
                **({"source_cfg": source_cfg[(index, fn.linkage_name)].to_payload()}
                   if (index, fn.linkage_name) in source_cfg else {}),
            }, locations[(index, fn.linkage_name)]))
    call_edges = 0
    seen_calls: set[tuple[str, str]] = set()
    ambiguous_names: set[str] = set()
    for index, fn in parsed:
        caller = entities[(index, fn.linkage_name)]
        for call in fn.calls:
            local = entities.get((index, call.callee_linkage))
            resolved = [local] if local else external.get(call.callee_linkage, ())
            if len(resolved) == 1:
                edge = (caller, resolved[0])
                if edge not in seen_calls:
                    seen_calls.add(edge)
                    builder.add_relation(RelationRecord(RelationKind.CALLS, caller, resolved[0], True, 1.0,
                        payload={"mapping": "unique-ir-definition", "line": call.line,
                                 "callee_linkage": call.callee_linkage}))
                    call_edges += 1
            elif len(resolved) > 1:
                ambiguous_names.add(call.callee_linkage)
    if ambiguous_names:
        gaps.append("ambiguous cross-translation-unit IR callees were not related: " +
                    ", ".join(sorted(ambiguous_names)[:20]))
    builder.add_coverage("llvm-ir", "partial" if gaps else "complete",
                         "; ".join(bounded_gap_messages(gaps, 10)) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "analysis", "ir", gaps))
    result.update(entity_count=len(entities), basic_block_count=sum(len(fn.blocks) for _, fn in parsed),
                  instruction_count=sum(fn.instruction_count for _, fn in parsed),
                  call_edge_count=call_edges, source_cfg_count=len(source_cfg),
                  checkpointable=not failures and not cfg_gaps and not missing_cfg)
    return result


def _bounded_infer_report(path: Path) -> list[Mapping[str, Any]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Infer report is missing, linked, or exceeds 64 MiB")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or len(value) > 100000 or any(
            not isinstance(item, Mapping) for item in value):
        raise ValueError("Infer report must be a bounded list of objects")
    return value


def _infer_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any],
                 execution: Mapping[str, Any]) -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    report_path = root / "analysis" / "infer-run" / "infer-out" / "report.json"
    log_path = root / "analysis" / "infer-run" / "infer-out" / "logs"
    gaps: list[str] = []
    if execution.get("timed_out"):
        gaps.append("Infer timed out before coverage could be established")
    elif execution.get("oom_killed"):
        gaps.append("Infer was OOM-killed before coverage could be established")
    elif execution.get("exit_code") != 0:
        gaps.append(f"Infer exited with status {execution.get('exit_code')}")
    try:
        records = _bounded_infer_report(report_path)
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        from appsec_review.runtime import execution_safety as safety
        safety.fail(f"Infer output is invalid: {type(exc).__name__}", action="cpp.infer")
        records = []
        gaps.append(f"Infer report unavailable or invalid: {exc}")

    captured_count = None
    if log_path.is_file() and not log_path.is_symlink() and log_path.stat().st_size <= 16 * 1024 * 1024:
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        matches = re.findall(r"Found ([0-9]+) source files? to analyze", log_text)
        if matches:
            captured_count = int(matches[-1])
    expected_count = len({str(item["target_path"]) for item in catalog["compile_commands"]})
    if captured_count is None:
        gaps.append("Infer capture count was unavailable")
    elif captured_count != expected_count:
        gaps.append(f"Infer captured {captured_count} of {expected_count} source files")

    artifacts = [execution["execution"], execution["compile_database"], catalog["compile_database"]]
    if isinstance(execution.get("report"), Mapping):
        artifacts.append(execution["report"])
    if log_path.is_file() and not log_path.is_symlink():
        artifacts.append(_artifact(unit.job.run_root, log_path))
    builder, path, fingerprint, shard = _new_builder(
        unit, "observations", case_id, "infer", artifacts, gaps,
        {"tool": "infer", "version": execution["tool_version"], "adapter": BRANCH_IDENTITY["infer"],
         "image": execution["image_id"],
         "image_digest": execution["image_digest"]}, catalog["mapping"]["case_snapshot"])

    by_relative = {
        str(item["scratch_path"])[len("source/"):]: item
        for item in catalog["mapping"].get("files", ())
        if str(item.get("scratch_path", "")).startswith("source/")
    }
    count = 0
    for ordinal, record in enumerate(records):
        raw_path = str(record.get("file", "")).replace("\\", "/")
        relative = raw_path.removeprefix("/target/")
        relative = relative[len("source/"):] if relative.startswith("source/") else ""
        source = by_relative.get(relative)
        if source is None:
            gaps.append(f"Infer observation path did not resolve to accepted source: {raw_path[:512]}")
            continue
        target_path = str(source["target_path"])
        target_file = (unit.job.target_root or Path()) / Path(*PurePosixPath(target_path).parts)
        if not target_file.is_file() or target_file.is_symlink() or file_sha256(target_file) != source["sha256"]:
            raise ValueError(f"Infer observation source changed after accepted mapping: {target_path}")
        line = int(record.get("line", 1)) if str(record.get("line", "1")).isdigit() else 1
        column = int(record.get("column", 1)) if str(record.get("column", "1")).isdigit() else 1
        bug_type = str(record.get("bug_type") or "INFER_OBSERVATION")[:256]
        qualifier = str(record.get("qualifier") or bug_type)[:16384]
        native = str(record.get("key") or record.get("hash") or f"{bug_type}:{ordinal}")[:2048]
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION,
            catalog["mapping"]["case_snapshot"], {"project_id": catalog["mapping"]["project_id"],
            "tool": "infer", "bug_type": bug_type, "path": target_path, "line": line,
            "column": column, "native": native})
        trace = []
        for step in record.get("bug_trace", ())[:100] if isinstance(record.get("bug_trace"), list) else ():
            if isinstance(step, Mapping):
                trace.append({"line": step.get("line_number"), "column": step.get("column_number"),
                              "description": str(step.get("description", ""))[:4096]})
        builder.add_entity(EntityRecord(identity, native, bug_type, qualifier,
            {"tool": "infer", "tool_version": execution["tool_version"], "rule_id": bug_type,
             "severity": str(record.get("severity") or "UNKNOWN")[:64],
             "category": str(record.get("category") or "")[:256],
             "procedure": str(record.get("procedure") or "")[:2048],
             "project_id": catalog["mapping"]["project_id"], "target_path": target_path,
             "source_sha256": source["sha256"], "trace": trace, "shard_id": shard},
            _location(unit.job.source_fingerprint, unit.job.target_root or Path(),
                      target_path, line, column)))
        count += 1
    unique_gaps = list(dict.fromkeys(gaps))
    builder.add_coverage("infer", "partial" if unique_gaps else "complete",
                         "; ".join(bounded_gap_messages(unique_gaps, 10)) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard,
                                "observations", "infer", unique_gaps))
    result.update(observation_count=count, expected_source_files=expected_count,
                  captured_source_files=captured_count)
    return result


def _binary_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any], execution: Mapping[str, Any]) -> Mapping[str, Any]:
    records_path = _case_root(unit, case_id) / "analysis" / "binary" / "records.json"
    gaps = []
    try:
        if records_path.is_symlink() or records_path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("binary record set is unsafe or over bound")
        records = json.loads(records_path.read_text(encoding="utf-8"))
        if not isinstance(records, list) or any(not isinstance(item, Mapping) for item in records):
            raise ValueError("binary record set is not a list of objects")
    except (OSError, ValueError, UnicodeDecodeError):
        from appsec_review.runtime import execution_safety as safety
        safety.fail("binary analysis output is unavailable or malformed", action="cpp.binary")
        records, gaps = [], ["binary/symbol analysis produced no valid bounded record set"]
    if execution.get("exit_code", 0) != 0:
        gaps.append(f"binary inspection exited with status {execution['exit_code']}")
    expected = {item["path"]: item for item in catalog.get("outputs", ())}
    observed = set()
    if len(records) > 4096:
        gaps.append("binary record set truncated at 4096 artifacts")
    builder, path, fingerprint, shard = _new_builder(unit, "compiled", case_id, "binary",
        [execution["execution"], catalog["artifact_catalog"]], gaps,
        {"tool": "binutils-2.42", "image": execution["image_id"]}, catalog["mapping"]["case_snapshot"])
    symbols = 0
    seen_entities: set[str] = set()
    for record_index, record in enumerate(records[:4096]):
        if (not isinstance(record.get("path"), str) or not isinstance(record.get("sha256"), str)
                or not isinstance(record.get("symbols"), list) or
                any(not isinstance(line, str) for line in record["symbols"])):
            gaps.append(f"binary record {record_index} has an invalid artifact or symbol shape")
            continue
        if record["path"] not in expected and bookkeeping_reason(record["path"]) is not None:
            continue
        if expected and (record["path"] not in expected or
                         record["sha256"] != expected[record["path"]]["sha256"]):
            gaps.append(f"binary record is not an accepted artifact: {record['path']}")
            continue
        observed.add(record["path"])
        tools = record.get("tools")
        if "tools" in record or execution.get("exit_code") != 0 or not isinstance(record.get("metadata"), str):
            for tool in ("nm", "readelf"):
                receipt = tools.get(tool) if isinstance(tools, Mapping) else None
                if not isinstance(receipt, Mapping):
                    gaps.append(f"{record['path']}: {tool} outcome unavailable")
                    continue
                if type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0 or receipt.get("timeout"):
                    gaps.append(f"{record['path']}: {tool} failed with exit {receipt.get('exit_code')}: "
                                f"{str(receipt.get('stderr', ''))[:512]}")
                if receipt.get("output_truncated") or receipt.get("stderr_truncated"):
                    gaps.append(f"{record['path']}: {tool} output truncated")
        if len(record["symbols"]) > 10000:
            gaps.append(f"{record['path']}: symbols truncated at 10000")
        kind = {"object": EntityKind.OBJECT_FILE, "library": EntityKind.LIBRARY,
                "executable": EntityKind.EXECUTABLE}.get(record.get("kind"), EntityKind.EVIDENCE_ARTIFACT)
        artifact = LogicalIdentity.derive(kind, catalog["mapping"]["case_snapshot"],
                                          {"project_id": catalog["mapping"]["project_id"],
                                           "path": record.get("path"),
                                           "sha256": record.get("sha256")})
        if artifact.value in seen_entities:
            continue
        seen_entities.add(artifact.value)
        builder.add_entity(EntityRecord(artifact, str(record.get("path")),
                                        PurePosixPath(str(record.get("path"))).name,
                                        str(record.get("metadata", ""))[:131072],
                                        {**record, "project_id": catalog["mapping"]["project_id"],
                                                   "artifact_id": artifact.value, "shard_id": shard}))
        for symbol_index, line in enumerate(record.get("symbols", ())[:10000]):
            name = str(line).split(" ", 1)[0]
            symbol = LogicalIdentity.derive(EntityKind.SYMBOL, catalog["mapping"]["case_snapshot"],
                                             {"artifact_id": artifact.value, "native": line,
                                              "ordinal": symbol_index})
            if symbol.value in seen_entities:
                continue
            seen_entities.add(symbol.value)
            builder.add_entity(EntityRecord(symbol, str(line), name, str(line),
                                            {"mapping": "native-symbol-table", "exact": True,
                                             "project_id": catalog["mapping"]["project_id"],
                                             "artifact_id": artifact.value, "shard_id": shard}))
            builder.add_relation(RelationRecord(RelationKind.CONTAINS, artifact.value, symbol.value, True, 1.0))
            symbols += 1
    if set(expected) - observed:
        gaps.append("binary inspection omitted accepted artifacts: " + ", ".join(sorted(set(expected) - observed)[:20]))
    builder.add_coverage("symbols-and-hardening", "partial" if gaps else "complete", "; ".join(gaps) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "compiled", "binary", gaps))
    result.update(entity_count=len(observed), symbol_count=symbols, checkpointable=not gaps)
    return result


def _validate_config(context, _result) -> None:
    expected_steps = ("plan", "prepare", "catalog", *BRANCHES, "acceptance")
    if tuple(context.config.steps) != expected_steps:
        raise ValueError("C++ compiled-analysis topology does not match central configuration")
    if tuple(context.config.step("plan").tasks) != ("accepted_cpp_plan",):
        raise ValueError("C++ plan task configuration is invalid")
    for step in ("prepare", "catalog", *BRANCHES):
        if tuple(context.config.step(step).tasks) != PROJECT_TASKS:
            raise ValueError(f"C/C++ project task configuration mismatch: {step}")
    if tuple(context.config.step("acceptance").tasks) != ("publish_handoff",):
        raise ValueError("C++ acceptance task configuration is invalid")


def native_analysis_actions(accepted: Mapping[str, Any], target_root: Path) -> list[dict[str, Any]]:
    """Select every accepted build whose C/C++ compiles the native analysis lane replays.

    Native units qualify by family. Any other family qualifies when its single execution
    capture recorded compiles of the unit's ``native_components`` (node-gyp, phpize,
    setuptools, clang --target=wasm32); those compiles are the project's compile database.
    """
    actions = []
    target = target_root.resolve(strict=True)
    for receipt in accepted["receipts"]:
        # Native units, and any family build whose native_components compiled C/C++ under
        # its single execution capture (node-gyp, phpize, setuptools, clang wasm32).
        component_database = receipt.get("native_compile_database")
        mixed = (isinstance(component_database, Mapping) and
                 int(component_database.get("entry_count", 0)) > 0 and
                 build_succeeded(receipt))
        if receipt.get("family") != "native" and not mixed:
            continue
        if receipt.get("family") == "native" and receipt.get("workspace") and not isinstance(component_database, Mapping):
            raise ValueError("accepted native build lacks a capture-backed compile database")
        root = PurePosixPath(str(receipt.get("root", "")))
        if root.is_absolute() or ".." in root.parts:
            raise ValueError("accepted native build root is invalid")
        source = (target / Path(*root.parts)).resolve(strict=True)
        if (source != target and target not in source.parents) or not source.is_dir():
            raise ValueError(f"accepted C/C++ project escapes the target: {root}")
        native_sources = [path for path in source.rglob("*") if path.is_file() and not path.is_symlink()
                          and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}]
        if not native_sources:
            continue
        actions.append({"root": root.as_posix(), "build_system": receipt.get("build_system"),
                        "build_unit_id": receipt["build_unit_id"], "receipt": dict(receipt),
                        "language_build_handoff_sha256": accepted["language_build_handoff_sha256"],
                        "project_key": str(receipt["build_unit_id"]),
                        "project_id": f"cpp:{root.as_posix()}",
                        "family": str(receipt.get("family", "native")),
                        "native_components": [dict(item) for item in receipt.get("native_components", ())],
                        "compile_database_origin": ("captured-native-components" if isinstance(
                            component_database, Mapping) else "unavailable"),
                        "source_count": len(native_sources)})
    return actions


def unbuilt_native_gap(receipt: Mapping[str, Any], root: str) -> str:
    """Name a planned C/C++ unit that has no build: the unit, the upstream failure, the failing job."""
    upstream = receipt.get("upstream_failure")
    if isinstance(upstream, Mapping):
        job_id, status = upstream.get("job_id"), upstream.get("terminal_status")
        reason = upstream.get("reason")
    else:
        job_id, status = "job_language_build", receipt.get("terminal_status")
        from appsec_review.jobs.job_project_build.enforcement import gap_text
        gaps = [gap_text(value) for value in receipt.get("gaps", ()) if value]
        reason = gaps[0] if gaps else "no reason recorded"
    return (f"{receipt.get('build_unit_id')} ({root}): C/C++ analysis unavailable because the native "
            f"build failed upstream in {job_id} ({status}): {reason}")


def _unbuilt_project(unit: UnitContext, action: Mapping[str, Any]) -> dict[str, Any]:
    """A planned C/C++ project with no build workspace, kept as a blocked project with its gap."""
    receipt = action["receipt"]
    relative = PurePosixPath(str(action["root"]))
    target_source = (unit.job.target_root or Path()).resolve() / Path(*relative.parts)
    files = []
    for path in _source_files(target_source):
        if ".git" in path.relative_to(target_source).parts:
            continue
        relative_file = path.relative_to(target_source).as_posix()
        files.append({"target_path": project_prefix(str(action["root"])) + relative_file,
                      "scratch_path": None, "sha256": file_sha256(path)})
    mapping = {"schema": "appsec-review/cpp-source-mapping/3", "project_key": str(action["project_key"]),
               "project_id": action["project_id"], "display_name": relative.name,
               "build_system": action.get("build_system"), "root": action["root"],
               "case_snapshot": hashlib.sha256(canonical_json(files)).hexdigest(), "files": files,
               "language_build_fingerprint": receipt.get("fingerprint"),
               "language_build_handoff_sha256": action["language_build_handoff_sha256"],
               "family": action.get("family", "native"),
               "native_components": list(action.get("native_components", ())),
               "compile_database_origin": action.get("compile_database_origin", "build-system")}
    gap = unbuilt_native_gap(receipt, str(action["root"]))
    unit.job.events.write("CPP_BUILD_PROJECT_UNBUILT", project_key=str(action["project_key"]),
                          project_id=action["project_id"], build_system=action.get("build_system"))
    return {"mapping": mapping, "artifact": None, "project_key": str(action["project_key"]),
            "profile": action.get("build_system"), "build_receipt": dict(receipt),
            "terminal_status": "BLOCKED", "gaps": [gap]}


def _implementation_files() -> tuple[Path, ...]:
    here = Path(__file__).parent
    return (Path(__file__), here / "seeded.py", here / "llvm_ir.py", here / "clang_cfg.py",
            here.parent / "cpp_index_scopes.py", *seeding.implementation_sources())


def build_job(*, executor_factory=None) -> Job:

    def plan(unit: UnitContext) -> Mapping[str, Any]:
        accepted = load_accepted_language_build(unit.job.run_root)
        if accepted.get("source_fingerprint") != unit.job.source_fingerprint:
            raise ValueError("C++ analysis target snapshot differs from accepted language build")
        target = (unit.job.target_root or Path()).resolve(strict=True)
        actions = native_analysis_actions(accepted, target)
        keys = [str(item["project_key"]) for item in actions]
        if len(set(keys)) != len(keys):
            raise ValueError("accepted C/C++ project identities are not unique")
        actions.sort(key=lambda item: (str(item["root"]), str(item["build_system"])))
        counts = {profile: sum(item["build_system"] == profile for item in actions)
                  for profile in ("cmake", "make", "autotools", "msbuild")}
        if not actions:
            document = {"schema": SCHEMA, "lane": "cpp", "project_count": 0,
                        "topology": {"cmake": 0, "make": 0, "autotools": 0, "msbuild": 0}, "actions": [],
                        "source_fingerprint": unit.job.source_fingerprint}
            artifact = _json_artifact(unit, unit.unit_root / "accepted-cpp-plan.json", document)
            return {"artifact": artifact, "plan": document, "terminal_status": "NOT_APPLICABLE",
                    "gaps": []}
        document = {"schema": SCHEMA, "lane": "cpp", "project_count": len(actions),
                    "topology": counts, "actions": actions,
                    "source_fingerprint": unit.job.source_fingerprint}
        artifact = _json_artifact(unit, unit.unit_root / "accepted-cpp-plan.json", document)
        return {"artifact": artifact, "plan": document, "terminal_status": "SUCCEEDED"}

    def prepare(unit: UnitContext) -> Mapping[str, Any]:
        actions = unit.output("plan.accepted_cpp_plan")["plan"]["actions"]
        projects = {}
        for action in actions:
            project_key = str(action["project_key"])
            receipt = action["receipt"]
            case_root = _case_root(unit, project_key)
            for name in ("source", "build", "analysis", "checkpoints"):
                if (case_root / name).exists():
                    shutil.rmtree(case_root / name)
            if receipt.get("terminal_status") != "SUCCEEDED" and not receipt.get("workspace"):
                # The unit was planned but never built (upstream project build or language build
                # failed before a workspace existed): keep it as a named, blocked project.
                projects[project_key] = _unbuilt_project(unit, action)
                continue
            workspace = (unit.job.run_root / str(receipt.get("workspace", ""))).resolve()
            if unit.job.run_root.resolve() not in workspace.parents or not workspace.is_dir() or workspace.is_symlink():
                raise ValueError("accepted native build workspace is unavailable or outside the run")
            manifest_identity = receipt.get("workspace_manifest")
            if not isinstance(manifest_identity, Mapping):
                raise ValueError("accepted native build does not bind its workspace manifest")
            manifest_path = (unit.job.run_root / str(manifest_identity.get("path", ""))).resolve()
            if (unit.job.run_root.resolve() not in manifest_path.parents or not manifest_path.is_file() or
                    manifest_path.is_symlink() or file_sha256(manifest_path) != manifest_identity.get("sha256")):
                raise ValueError("accepted native build workspace manifest identity changed")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_files = manifest.get("files") if manifest.get("schema") == "appsec-review/build-workspace-manifest/1" else None
            if not isinstance(expected_files, Mapping):
                raise ValueError("accepted native build workspace manifest is invalid")
            actual_paths = {path.relative_to(workspace).as_posix() for path in workspace.rglob("*")
                            if path.is_file() and not path.is_symlink()}
            if actual_paths != set(expected_files):
                raise ValueError("accepted native build workspace file set changed")
            for relative_file, digest in expected_files.items():
                logical = PurePosixPath(str(relative_file))
                path = (workspace / Path(*logical.parts)).resolve()
                if (workspace != path and workspace not in path.parents) or not path.is_file() or path.is_symlink():
                    raise ValueError("accepted native build workspace manifest contains an invalid path")
                if file_sha256(path) != digest:
                    raise ValueError("accepted native build workspace content changed")
            for identity in receipt.get("artifacts", ()):
                path = (unit.job.run_root / str(identity.get("path", ""))).resolve()
                if (unit.job.run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink() or
                        file_sha256(path) != identity.get("sha256")):
                    raise ValueError("accepted native build artifact identity changed")
            relative = PurePosixPath(str(action["root"]))
            target_source = (unit.job.target_root or Path()).resolve() / Path(*relative.parts)
            source = case_root / "source"
            shutil.copytree(target_source, source, symlinks=True,
                            ignore=shutil.ignore_patterns(".git", ".hg", ".svn"))
            build_relative = PurePosixPath(str(receipt["recipe"]["build_dir"]))
            built = workspace / Path(*build_relative.parts)
            build = case_root / "build"
            if built.is_dir() and not built.is_symlink():
                shutil.copytree(built, build)
            else:
                build.mkdir(parents=True)
            for staged_path in (build, *build.rglob("*")):
                if staged_path.is_symlink():
                    continue
                try:
                    if staged_path.is_dir():
                        staged_path.chmod(0o755)
                    elif staged_path.is_file():
                        mode = staged_path.stat().st_mode
                        staged_path.chmod(0o755 if (mode & 0o100) else 0o644)
                except OSError:
                    pass
            if action.get("compile_database_origin") == "captured-native-components":
                identity = receipt["native_compile_database"]
                database = (unit.job.run_root / str(identity.get("path", ""))).resolve()
                if (unit.job.run_root.resolve() not in database.parents or not database.is_file() or
                        database.is_symlink() or file_sha256(database) != identity.get("sha256")):
                    raise ValueError("accepted native component compile database identity changed")
                rows = native_component_compile_commands(json.loads(database.read_text(encoding="utf-8")))
                # The family build's captured compiles are this project's compile database.
                (build / "compile_commands.json").write_text(json.dumps(rows), encoding="utf-8")
            files = []
            for path in _source_files(source):
                relative_file = path.relative_to(source).as_posix()
                original = target_source / Path(*PurePosixPath(relative_file).parts)
                if not original.is_file() or original.is_symlink() or file_sha256(original) != file_sha256(path):
                    raise ValueError("accepted native source mapping changed")
                files.append({"target_path": project_prefix(str(action["root"])) + relative_file,
                              "scratch_path": f"source/{relative_file}", "sha256": file_sha256(path)})
            build_files = [{"scratch_path": path.relative_to(case_root).as_posix(), "sha256": file_sha256(path)}
                           for path in _source_files(build)]
            context = {"source_dir": str(action["root"]), "build_dir": build_relative.as_posix()}
            mapping = {"schema": "appsec-review/cpp-source-mapping/4", "project_key": project_key,
                       "project_id": action["project_id"], "display_name": relative.name,
                       "build_system": action.get("build_system"), "root": action["root"],
                       "case_snapshot": hashlib.sha256(canonical_json({
                           "files": files, "build_files": build_files, **context})).hexdigest(),
                       "files": files, "build_files": build_files, **context,
                       "language_build_fingerprint": receipt.get("fingerprint"),
                       "language_build_handoff_sha256": action["language_build_handoff_sha256"],
                       "family": action.get("family", "native"),
                       "native_components": list(action.get("native_components", ())),
                       "compile_database_origin": action.get("compile_database_origin", "build-system")}
            artifact = _json_artifact(unit, _case_root(unit, project_key) / "source-mapping.json", mapping,
                                      immutable=True)
            projects[project_key] = {"mapping": mapping, "artifact": artifact,
                                     "project_key": project_key, "profile": action["build_system"],
                                     "build_receipt": receipt, "terminal_status": receipt.get("terminal_status"),
                                     "gaps": list(receipt.get("gaps", ()))}
            unit.job.events.write("CPP_BUILD_PROJECT_PREPARED", project_key=project_key,
                                  project_id=mapping["project_id"], source_count=len(mapping["files"]),
                                  build_system=action["build_system"])
        gaps = [gap for project in projects.values() if project.get("terminal_status") != "SUCCEEDED"
                for gap in project.get("gaps", ())]
        return {"projects": projects, "project_count": len(projects), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED" if projects else "NOT_APPLICABLE"}

    def catalog(unit: UnitContext) -> Mapping[str, Any]:
        projects = {}
        prepared = unit.output("prepare.projects")["projects"]
        for case_id, compiled in prepared.items():
            gap = _terminal_gap(compiled)
            mapping = prepared[case_id]["mapping"]
            if gap:
                projects[case_id] = {"project_key": case_id, "mapping": mapping, "gaps": [gap],
                                     "terminal_status": "BLOCKED_BY_COMPILE"}
                continue
            candidate_links, link_gaps = _accepted_links(unit, compiled["build_receipt"])
            candidate_links = [
                row for row in candidate_links
                if bookkeeping_reason(str(row.get("output_path", ""))) is None
                and all(bookkeeping_reason(str(src)) is None for src in row.get("input_paths", ()))
            ]
            identity = _checkpoint_identity(unit, case_id, "catalog",
                                            {"language_build": compiled["build_receipt"]["fingerprint"],
                                             "mapping": prepared[case_id]["artifact"]["sha256"],
                                             "accepted_compile": compiled["build_receipt"].get("native_compile_database"),
                                             "accepted_links": compiled["build_receipt"].get("link_database"),
                                             "normalizer": "native-compile-link-normalizer/5"})
            reused = _load_checkpoint(unit, case_id, "catalog", identity)
            if reused is not None:
                _restore_replay_commands(unit, case_id, reused)
                projects[case_id] = reused
                continue
            root = _case_root(unit, case_id)
            try:
                commands = normalize_compile_db(root, mapping)
                # tool-native-cpp reads this as the application uid for the AST and IR replays.
                normalized = root / "normalized-compile-commands.json"
                tool_input_json(normalized, commands)
                compile_artifact = _json_artifact(unit, root / "compile-commands.json", commands, immutable=True)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                from appsec_review.runtime import execution_safety as safety
                safety.fail(f"produced compile database is invalid: {type(exc).__name__}", action="cpp.catalog")
                projects[case_id] = {"project_key": case_id, "mapping": mapping,
                    "gaps": [f"{case_id} compile database invalid: {type(exc).__name__}: {exc}"],
                    "terminal_status": "INVALID_COMPILE_DATABASE"}
                continue
            outputs = []
            for path in sorted((root / "build").rglob("*")):
                if not path.is_file() or path.is_symlink() or path.name == "compile_commands.json":
                    continue
                if bookkeeping_reason(path.relative_to(root).as_posix()) is not None:
                    continue
                magic = path.read_bytes()[:4]
                kind = "object" if path.suffix == ".o" else "library" if path.suffix in {".a", ".so"} else (
                    "executable" if magic == b"\x7fELF" else None)
                if kind:
                    outputs.append({"path": path.relative_to(root).as_posix(), "kind": kind,
                                    "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
            link_commands = normalize_link_commands(candidate_links, outputs)
            if len(link_commands) != len(candidate_links):
                link_gaps.append("accepted link relationships could not all resolve to retained build artifacts")
            expected_edges = {(row["output_path"], source) for row in candidate_links for source in row["input_paths"]}
            retained_edges = {(row["output_path"], source) for row in link_commands for source in row["input_paths"]}
            missing_edges = sorted(expected_edges - retained_edges)
            if missing_edges:
                link_gaps.append(f"{len(missing_edges)} accepted link relationship(s) unavailable: " +
                                 "; ".join(f"{source} -> {output}" for output, source in missing_edges[:20]))
            output_artifact = _json_artifact(unit, root / "artifact-catalog.json", outputs, immutable=True)
            link_artifact = _json_artifact(unit, root / "normalized-link-commands.json", link_commands, immutable=True)
            result = {"project_key": case_id, "mapping": mapping, "compile_commands": commands,
                      "compile_database": compile_artifact, "artifact_catalog": output_artifact,
                      "link_database": link_artifact, "link_commands": link_commands,
                      "outputs": outputs, "image_id": compiled["build_receipt"]["image"]["image_id"],
                      "build_receipt": compiled["build_receipt"], "gaps": link_gaps,
                      "checkpointable": not link_gaps,
                      "terminal_status": "SUCCEEDED",
                      "counts": {"compile_units": len(commands), "objects": sum(x["kind"] == "object" for x in outputs),
                                 "libraries": sum(x["kind"] == "library" for x in outputs),
                                 "executables": sum(x["kind"] == "executable" for x in outputs)}}
            _save_checkpoint(unit, case_id, "catalog", identity, result)
            projects[case_id] = result
        gaps = [gap for result in projects.values() for gap in result.get("gaps", ())]
        return {"projects": projects, "project_count": len(projects), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else ("SUCCEEDED" if projects else "NOT_APPLICABLE")}

    def branch(name: str):
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            projects = {}
            all_projects = unit.output("catalog.projects")["projects"]
            seeded_settings = seeded.settings_of(unit) if name in {"ir", "ast"} else None
            seed_plan = None
            if seeded_settings is not None and seeded_settings.seeded:
                buildable = {case_id: value for case_id, value in all_projects.items() if not _terminal_gap(value)}
                seed_plan = seeded.plan_for(unit, buildable, seeded_settings) if buildable else None
            ir_projects = unit.output("ir.projects")["projects"] if name == "ast" and seed_plan is not None else {}
            for case_id, cataloged in all_projects.items():
                gap = _terminal_gap(cataloged)
                if gap:
                    builder, path, fingerprint, shard = _new_builder(unit,
                        "analysis",
                        case_id, name, [], [gap], {"tool": name, "status": "blocked-by-build"},
                        cataloged["mapping"]["case_snapshot"])
                    builder.add_coverage(name, "unavailable", gap)
                    projects[case_id] = _finish_index(unit, builder, path, fingerprint, shard,
                                                      builder.name, name, [gap])
                    continue
                if name in {"ast", "ir"}:
                    _restore_replay_commands(unit, case_id, cataloged)
                identity_values = {
                    "compile_database": cataloged["compile_database"]["sha256"],
                    "branch_identity": BRANCH_IDENTITY[name],
                    "mapping": cataloged["mapping"],
                }
                if seeded_settings is not None:
                    identity_values["settings"] = asdict(seeded_settings)
                if name == "ast":
                    identity_values["node_limit"] = AST_NODE_LIMIT
                if name != "infer":
                    identity_values.update({
                        "artifact_catalog": cataloged["artifact_catalog"]["sha256"],
                        "link_database": cataloged["link_database"]["sha256"],
                    })
                if seed_plan is not None:
                    identity_values.update(seeded.identity_values(
                        seeded_settings, seed_plan.for_scope(case_id),
                        **({"ir": ir_projects.get(case_id, {}).get("handoff_sha256")} if name == "ast" else {})))
                identity = _checkpoint_identity(
                    unit, case_id, f"branch-{name}", identity_values,
                    tool_id="tool-infer" if name == "infer" else "tool-native-cpp")
                reused = _load_checkpoint(unit, case_id, f"branch-{name}", identity)
                if reused is not None:
                    projects[case_id] = reused
                    continue
                if seed_plan is not None:
                    result = (seeded.ir_result(unit, case_id, cataloged, seeded_settings, seed_plan, executor_factory)
                              if name == "ir" else
                              seeded.ast_result(unit, case_id, cataloged, seeded_settings, seed_plan,
                                                ir_projects.get(case_id), executor_factory))
                elif name == "compiled":
                    result = _build_entities(unit, case_id, cataloged)
                elif name == "infer":
                    execution = _run_infer(unit, case_id, cataloged, executor_factory)
                    result = _infer_index(unit, case_id, cataloged, execution)
                else:
                    tool_mode = "symbols" if name == "binary" else name
                    if name in {"ast", "ir"}:
                        seeded.clear_replay(unit, case_id, name)   # a stale seeded subset must never be replayed
                    execution = _run_tool(unit, case_id, (tool_mode,), executor_factory)
                    from appsec_review.runtime import execution_safety as safety
                    safety.failed_result(execution["timed_out"] or execution["oom_killed"]
                                         or execution["exit_code"] != 0,
                                         f"{case_id} {name} execution failed", action=f"cpp.{name}")
                    tool_gap = (None if execution["exit_code"] == 0 else
                                f"{case_id} {name} failed with exit {execution['exit_code']}")
                    if execution["timed_out"] or execution["oom_killed"]:
                        tool_gap = f"{case_id} {name} {'timed out' if execution['timed_out'] else 'ran out of memory'}"
                    elif name == "binary" and execution["exit_code"] == 2:
                        tool_gap = None  # The bounded per-artifact receipts describe partial inspection.
                    failures: dict[int, str] | None = None
                    if name in {"ast", "ir"} and not execution["timed_out"] and not execution["oom_killed"]:
                        failures = replay_failures(_case_root(unit, case_id), name,
                                                   cataloged["compile_commands"])
                        # The driver exits 2 when some units failed: index the others and name
                        # each failed unit, instead of discarding the whole branch.
                        if execution["exit_code"] == 2 and failures:
                            tool_gap = None
                        elif tool_gap and failures:
                            tool_gap += "; " + "; ".join(list(failures.values())[:5])
                        if failures is None:
                            tool_gap = f"{case_id} {name} replay receipt unusable"
                    if tool_gap:
                        builder, path, fingerprint, shard = _new_builder(
                            unit, "compiled" if name == "binary" else "analysis", case_id, name,
                            [execution["execution"]], [tool_gap],
                            {"tool": name, "image": execution["image_id"]},
                            cataloged["mapping"]["case_snapshot"])
                        builder.add_coverage(name, "unavailable", tool_gap)
                        result = _finish_index(unit, builder, path, fingerprint, shard,
                                               builder.name, name, [tool_gap])
                    elif name == "ast":
                        result = _ast_index(unit, case_id, cataloged, execution, failures)
                    elif name == "ir":
                        from .llvm_ir import MAX_BLOCKS
                        flow_settings = replace(seeded_settings, block_limit=seeded_settings.block_limit or MAX_BLOCKS)
                        cfg_gaps = []
                        cfgs, _, _ = seeded._source_cfgs(unit, case_id, _case_root(unit, case_id),
                            cataloged["compile_commands"], flow_settings, executor_factory, cfg_gaps)
                        result = _ir_index(unit, case_id, cataloged, execution, failures, cfgs=cfgs,
                                           cfg_gaps=cfg_gaps, block_limit=flow_settings.block_limit)
                    else:
                        result = _binary_index(unit, case_id, cataloged, execution)
                _save_checkpoint(unit, case_id, f"branch-{name}", identity, result)
                projects[case_id] = result
            gaps = [gap for result in projects.values() for gap in result.get("gaps", ())]
            return {"projects": projects, "project_count": len(projects), "branch": name, "gaps": gaps,
                    "terminal_status": "COMPLETED_WITH_GAPS" if gaps else ("SUCCEEDED" if projects else "NOT_APPLICABLE")}
        return handler

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        manifest_path, manifest_sha = resolve_context_manifest(unit.job)
        upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
        prior_identities = [IndexIdentity(**{**value, "gaps": tuple(value.get("gaps", ()))})
                            for value in upstream["indexes"]
                            if value.get("producer", {}).get("job") != "job_cpp_compiled_analysis"]
        current_identities: list[IndexIdentity] = []
        gaps, dispositions = [], {}
        handoff_dispositions = []
        for name in BRANCHES:
            for case_id, output in unit.output(f"{name}.projects")["projects"].items():
                identity = output.get("index_identity")
                if isinstance(identity, Mapping):
                    current_identities.append(IndexIdentity(**{**identity, "gaps": tuple(identity.get("gaps", ())) }))
                gaps.extend(str(item) for item in output.get("gaps", ()))
                status = output.get("terminal_status", "UNKNOWN")
                dispositions[f"{case_id}:{name}"] = status
                disposition = {"project_key": case_id, "branch": name, "terminal_status": status}
                if status not in {"SUCCEEDED", "NOT_APPLICABLE"} and output.get("checkpointable") is not True:
                    disposition["disposition"] = "GAP"
                handoff_dispositions.append(disposition)
        current_keys = {(item.name, item.shard_id) for item in current_identities}
        identities = [item for item in prior_identities if (item.name, item.shard_id) not in current_keys]
        identities.extend(current_identities)
        destination = unit.job.run_root / "data" / "indices" / "manifests" / f"cpp-compiled-{unit.job.attempt_id}.json"
        write_manifest(destination, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or Path(), indexes=identities,
                       upstream_manifests=({"path": manifest_path.relative_to(unit.job.run_root).as_posix(),
                                            "sha256": manifest_sha},))
        load_verified_manifest(unit.job.run_root, destination, file_sha256(destination))
        unique_gaps = list(dict.fromkeys(gaps))
        project_count = unit.output("plan.accepted_cpp_plan")["plan"]["project_count"]
        summary = {"schema": SCHEMA, "project_count": project_count, "branch_count": len(BRANCHES),
                   "physical_shard_count": len(identities), "gaps": unique_gaps,
                   "dispositions": dispositions}
        summary_artifact = _json_artifact(unit, unit.unit_root / "cpp-compiled-summary.json", summary)
        unit.job.events.write("CPP_COMPILED_ANALYSIS_COMPLETED", project_count=project_count,
                              shard_count=len(identities), gap_count=len(unique_gaps))
        return {"schema": SCHEMA, "artifact": summary_artifact,
                "index_manifest": _artifact(unit.job.run_root, destination),
                "item_count": len(identities), "gaps": unique_gaps, "dispositions": handoff_dispositions,
                "terminal_status": "COMPLETED_WITH_GAPS" if unique_gaps else "SUCCEEDED"}

    units: list[Unit] = [Unit("plan.accepted_cpp_plan", plan)]
    units.append(Unit("prepare.projects", prepare, ("plan.accepted_cpp_plan",)))
    units.append(Unit("catalog.projects", catalog, ("prepare.projects",)))
    # The seeded AST replays the translation units that define the seeded IR neighborhood, so it
    # runs after the IR; the central step order (BRANCHES) is unchanged.
    for name in ("compiled", "ir", "ast", "infer", "binary"):
        dependencies_of = ("catalog.projects", "ir.projects") if name == "ast" else ("catalog.projects",)
        units.append(Unit(f"{name}.projects", branch(name), dependencies_of))
    dependencies = tuple(f"{name}.projects" for name in BRANCHES)
    units.append(Unit("acceptance.publish_handoff", publish, dependencies))
    values = tuple(units)
    implementation = None
    return Job("job_cpp_compiled_analysis", "cpp_compiled_analysis", UnitExecutor(values).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=values,
               datasets=DATASETS, contract=CONTRACT)
