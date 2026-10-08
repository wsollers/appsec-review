from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256


SCHEMA = "appsec-review/cpp-compiled-analysis/2"
PROJECT_TASKS = ("projects",)
BRANCHES = ("compiled", "ast", "ir", "infer", "codeql", "joern", "binary")
BRANCH_IDENTITY = {"compiled": "cpp-compiled-index/2", "ast": "clang-ast/2",
                   "ir": "llvm-ir/2", "codeql": "codeql-cpp-adapter/2",
                   "infer": "infer-cpp-adapter/1", "joern": "joern-c2cpg-adapter/2",
                   "binary": "elf-symbols/2"}
PROFILE_BY_MARKER = {"CMakeLists.txt": "cmake", "Makefile": "make", "configure.ac": "autotools",
                     ".vcxproj": "msbuild"}
MSBUILD_GAP = (
    "UNAVAILABLE: the accepted project requires MSBuild, which is not present in the pinned "
    "Linux native-analysis image; no compiled MSBuild coverage is claimed."
)
CODEQL_GAP = (
    "BLOCKED: CodeQL C/C++ assets and an applicable user/environment entitlement were not supplied; "
    "no database or query suite was executed and no CodeQL coverage is claimed."
)
JOERN_GAP = (
    "BLOCKED: a hash-pinned Joern/c2cpg distribution with reviewed license provenance is not "
    "available in the tool catalog; no CPG coverage is claimed."
)


def _project_key(root: PurePosixPath) -> str:
    return "project-" + hashlib.sha256(root.as_posix().encode()).hexdigest()[:16]


def _case_root(unit: UnitContext, case_id: str) -> Path:
    return unit.job.run_root / "data" / "cpp" / "projects" / case_id


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _json_artifact(unit: UnitContext, path: Path, value: Any) -> dict[str, Any]:
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _terminal_gap(output: Mapping[str, Any]) -> str | None:
    if output.get("terminal_status") in {"SUCCEEDED", "NOT_APPLICABLE"}:
        return None
    gaps = output.get("gaps", ())
    return str(gaps[0]) if gaps else "upstream C++ case action did not succeed"


def _checkpoint_identity(unit: UnitContext, case_id: str, stage: str, values: Mapping[str, Any],
                         *, tool_id: str = "tool-native-cpp") -> str:
    tool = load_catalog(unit.job.repository_root).tool(tool_id) if (
        unit.job.repository_root / "containers" / "catalog.toml").is_file() else None
    tool_identity = ({"tag": tool.tag, "version": tool.version,
                      "expected_image_id": tool.expected_image_id,
                      "manifest_sha256": file_sha256(tool.manifest_path)} if tool else
                     {"injected_executor": True})
    return hashlib.sha256(canonical_json({"schema": "appsec-review/cpp-checkpoint/1",
        "project": case_id, "stage": stage,
        "tool": tool_identity, "values": values})).hexdigest()


def _load_checkpoint(unit: UnitContext, case_id: str, stage: str, identity: str) -> Mapping[str, Any] | None:
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
    for value in result.values():
        if isinstance(value, Mapping) and isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            artifact = (unit.job.run_root / value["path"]).resolve()
            if unit.job.run_root.resolve() not in artifact.parents or not artifact.is_file() or file_sha256(artifact) != value["sha256"]:
                return None
    if result.get("terminal_status") != "SUCCEEDED":
        return None
    return {**result, "checkpoint_reused": True}


def _save_checkpoint(unit: UnitContext, case_id: str, stage: str, identity: str,
                     result: Mapping[str, Any]) -> None:
    if result.get("terminal_status") != "SUCCEEDED":
        return
    atomic_json(_case_root(unit, case_id) / "checkpoints" / f"{stage}.json",
                {"schema": "appsec-review/cpp-checkpoint/1", "identity": identity,
                 "project_key": case_id, "stage": stage, "result": dict(result)})


def _run_tool(unit: UnitContext, case_id: str, argv: tuple[str, ...], executor_factory=None) -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    executor = (executor_factory(unit) if executor_factory is not None else
                ContainerExecutor(load_catalog(unit.job.repository_root), unit.job.run_root))
    result = executor.execute(ExecutionRequest(
        tool_id="tool-native-cpp", argv=("/opt/appsec/native.py", *argv),
        target_root=unit.job.target_root or unit.job.repository_root, scratch_root=root,
    ))
    receipt = root / "execution.json"
    retained = unit.unit_root / f"{case_id}-execution.json"
    retained.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(receipt, retained)
    return {"execution": _artifact(unit.job.run_root, retained), "exit_code": result.exit_code,
            "timed_out": result.timed_out, "oom_killed": result.oom_killed,
            "image_id": result.image_id, "image_digest": result.image_digest,
            "argv_identity": result.argv_identity}


def _infer_compile_database(catalog: Mapping[str, Any]) -> list[dict[str, Any]]:
    mapping = catalog["mapping"]
    root = str(mapping["root"]).rstrip("/") + "/"
    rows = []
    for command in catalog["compile_commands"]:
        target_path = str(command["target_path"])
        if not target_path.startswith(root):
            raise ValueError("Infer compile unit is outside the accepted project root")
        relative = target_path[len(root):]
        source = "/target/source/" + relative
        arguments = []
        for index, value in enumerate(command["arguments"]):
            rewritten = str(value).replace("/scratch/source", "/target/source").replace(
                "/scratch/build", "/target/build")
            if index == 0:
                rewritten = "clang++" if PurePosixPath(relative).suffix.lower() in {
                    ".cc", ".cpp", ".cxx", ".c++", ".mm"
                } else "clang"
            arguments.append(rewritten)
        rows.append({"directory": "/target/source", "file": source, "arguments": arguments})
    return rows


def _run_infer(unit: UnitContext, case_id: str, catalog: Mapping[str, Any],
               executor_factory=None) -> Mapping[str, Any]:
    case_root = _case_root(unit, case_id)
    scratch = case_root / "analysis" / "infer-run"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    compile_database = scratch / "compile_commands.json"
    atomic_json(compile_database, _infer_compile_database(catalog))
    tool_catalog = (load_catalog(unit.job.repository_root) if
                    (unit.job.repository_root / "containers" / "catalog.toml").is_file() else None)
    executor = (executor_factory(unit) if executor_factory is not None else
                ContainerExecutor(tool_catalog, unit.job.run_root))
    result = executor.execute(ExecutionRequest(
        tool_id="tool-infer",
        argv=("/opt/infer/bin/infer", "run", "--no-progress-bar", "--jobs", "2", "--results-dir",
              "/scratch/infer-out", "--compilation-database", "/scratch/compile_commands.json"),
        target_root=case_root, scratch_root=scratch,
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


def _safe_copy_case(unit: UnitContext, case_id: str, action: Mapping[str, Any]) -> Mapping[str, Any]:
    target = (unit.job.target_root or Path()).resolve(strict=True)
    relative = PurePosixPath(str(action["root"]))
    if not relative.parts or relative.parts[0] != "projects" or _project_key(relative) != case_id:
        raise ValueError(f"accepted C/C++ project identity mismatch for {case_id}")
    source = (target / Path(*relative.parts)).resolve(strict=True)
    if target not in source.parents or not source.is_dir():
        raise ValueError("accepted C/C++ project root escapes the target")
    destination = _case_root(unit, case_id) / "source"
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, symlinks=False, ignore=shutil.ignore_patterns(".git", "build"))
    mapping = []
    for path in _source_files(destination):
        relative_file = path.relative_to(destination).as_posix()
        original = source / Path(*PurePosixPath(relative_file).parts)
        if not original.is_file() or original.is_symlink():
            raise ValueError("copied source mapping is not a regular accepted file")
        source_sha = file_sha256(original)
        if file_sha256(path) != source_sha:
            raise ValueError("run-owned source copy differs from accepted target source")
        mapping.append({"target_path": f"{action['root']}/{relative_file}",
                        "scratch_path": f"source/{relative_file}", "sha256": source_sha})
    case_snapshot = hashlib.sha256(canonical_json(mapping)).hexdigest()
    return {"schema": "appsec-review/cpp-source-mapping/2", "project_key": case_id,
            "project_id": f"cpp:{relative.as_posix()}", "display_name": relative.name,
            "build_system": action["build_system"],
            "root": action["root"], "case_snapshot": case_snapshot, "files": mapping}


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
        return target_root
    for prefix in ("/scratch/source/", source + "/"):
        if normalized.startswith(prefix):
            return target_root.rstrip("/") + "/" + normalized[len(prefix):]
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


def _sanitize_arguments(row: Mapping[str, Any], case_root: Path, source_path: str) -> list[str]:
    raw = _raw_arguments(row)
    compiler = "clang++-18" if PurePosixPath(source_path).suffix.lower() in {".cc", ".cpp", ".cxx", ".c++", ".mm"} else "clang-18"
    result = [compiler]
    skip_next = False
    source_seen = False
    paired = {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-x", "--target"}
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
        mapped = value.replace(str(case_root).replace("\\", "/"), "/scratch")
        if value in paired:
            result.append(value)
            continue
        if result[-1] in paired:
            result.append(mapped)
            continue
        if mapped == source_path:
            source_seen = True
            continue
        if mapped.startswith(("-D", "-U", "-I", "-std=", "-f", "-m", "-W", "--sysroot=", "--target=")):
            result.append(mapped)
    result.append(source_path)
    return result


def _output_path(row: Mapping[str, Any], root: Path) -> str | None:
    raw = _raw_arguments(row)
    value = row.get("output") if isinstance(row.get("output"), str) else None
    if value is None:
        for index, argument in enumerate(raw[:-1]):
            if argument == "-o":
                value = raw[index + 1]
                break
    if not value:
        return None
    normalized = value.replace("\\", "/")
    directory = str(row.get("directory", "")).replace("\\", "/")
    if not normalized.startswith("/") and not re.match(r"^[A-Za-z]:/", normalized):
        normalized = posixpath.normpath(posixpath.join(directory, normalized))
    prefixes = ((root / "build").as_posix(), "/scratch/build")
    for prefix in prefixes:
        if normalized == prefix:
            return "build"
        if normalized.startswith(prefix + "/"):
            return "build/" + normalized[len(prefix) + 1:]
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
        target_path = _mapped_path(str(row["file"]), root, target_root)
        if not target_path.startswith(target_root.rstrip("/") + "/"):
            normalized_file = str(row["file"]).replace("\\", "/")
            matches = [item for item in mapping.get("files", ())
                       if normalized_file.endswith("/" + str(item["scratch_path"])[len("source/"):])]
            if len(matches) != 1:
                raise ValueError(f"compile database path does not resolve uniquely: {row['file']}")
            target_path = str(matches[0]["target_path"])
        scratch_source = "/scratch/source/" + target_path[len(target_root.rstrip("/") + "/"):]
        arguments = _sanitize_arguments(row, root, scratch_source)
        source_record = next((item for item in mapping.get("files", ())
                              if item.get("target_path") == target_path), None)
        if source_record is None:
            raise ValueError(f"compile database source is not in the accepted case mapping: {target_path}")
        result.append({"project_key": mapping["project_key"], "index": index, "directory": "/scratch/source",
                       "file": scratch_source, "target_path": target_path, "arguments": arguments,
                       "source_sha256": source_record["sha256"], "output_path": _output_path(row, root),
                       "command_sha256": hashlib.sha256(canonical_json(arguments)).hexdigest()})
        result[-1]["compile_unit_id"] = _tu_identity(mapping, result[-1])
    return sorted(result, key=lambda item: (item["target_path"], item["command_sha256"]))


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
    fingerprint = index_fingerprint(name=name, target_snapshot=scope_snapshot,
        producer_artifacts=artifacts, tool_identity=tool, parser_identity=f"cpp-{branch}-parser/2",
        normalizer_identity=f"cpp-{branch}-normalizer/3", mapping_identity="cpp-source-mapping/2")
    shard = f"cpp-{case_id}-{branch}"
    path = unit.job.run_root / "data" / "indices" / name / f"{fingerprint}-{shard}.sqlite"
    return IndexBuilder(path, name=name, fingerprint=fingerprint,
                        target_snapshot=unit.job.source_fingerprint, shard_id=shard), path, fingerprint, shard


def _finish_index(unit: UnitContext, builder: IndexBuilder, path: Path, fingerprint: str,
                  shard: str, name: str, branch: str, gaps: list[str]) -> Mapping[str, Any]:
    reused = path.exists()
    sha = file_sha256(path) if reused else builder.build()
    identity = IndexIdentity(name, "appsec-review/retrieval-index/1", sha, fingerprint,
                             path.relative_to(unit.job.run_root).as_posix(),
                             {"job": "job_cpp_compiled_analysis", "unit": unit.unit_id,
                              "branch": branch}, tuple(gaps), shard)
    return {"index_identity": asdict(identity), "index_reused": reused,
            "artifact": _artifact(unit.job.run_root, path), "gaps": gaps,
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
    coverage_gap = None if related else "no exact compile-output or captured link relation was available"
    builder.add_coverage("compile-and-link", "complete" if coverage_gap is None else "partial", coverage_gap)
    return _finish_index(unit, builder, path, fingerprint, shard, "build", "compiled", [])


def _walk_ast(value: Any, *, limit: int = 20000):
    stack = [value]
    count = 0
    while stack and count < limit:
        item = stack.pop()
        if not isinstance(item, Mapping):
            continue
        count += 1
        yield item
        children = item.get("inner", ())
        if isinstance(children, list):
            stack.extend(reversed(children))


def _load_ast_document(path: Path) -> Mapping[str, Any]:
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
        documents.append(value)
        if len(documents) > 4096:
            raise ValueError("Clang AST declaration count exceeds bound")
    if not documents:
        raise ValueError("Clang AST output is empty")
    if len(documents) == 1:
        return documents[0]
    return {"kind": "TranslationUnitDecl", "inner": documents}


def _ast_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any], execution: Mapping[str, Any]) -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    gaps: list[str] = []
    builder, path, fingerprint, shard = _new_builder(unit, "analysis", case_id, "ast",
        [execution["execution"], catalog["compile_database"]], gaps,
        {"tool": "clang-18", "image": execution["image_id"]}, catalog["mapping"]["case_snapshot"])
    count = 0
    seen_entities: set[str] = set()
    for index, command in enumerate(catalog["compile_commands"]):
        ast_path = root / "analysis" / "ast" / f"tu-{index:04d}.json"
        try:
            document = _load_ast_document(ast_path)
        except (OSError, ValueError, UnicodeDecodeError):
            gaps.append(f"{command['target_path']}: Clang AST output unavailable or invalid")
            continue
        for node in _walk_ast(document):
            kind = str(node.get("kind", ""))
            if kind not in {"FunctionDecl", "CXXMethodDecl", "VarDecl", "RecordDecl", "CallExpr",
                            "DeclRefExpr", "FieldDecl", "ParmVarDecl", "TypedefDecl"}:
                continue
            name = str(node.get("name") or node.get("referencedDecl", {}).get("name") or kind)
            loc = node.get("loc", {}) if isinstance(node.get("loc"), Mapping) else {}
            line = int(loc.get("line", 1)) if str(loc.get("line", "1")).isdigit() else 1
            column = int(loc.get("col", 1)) if str(loc.get("col", "1")).isdigit() else 1
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
                {"kind": kind, "type": node.get("type"), "referenced_decl": node.get("referencedDecl"),
                 "project_id": catalog["mapping"]["project_id"],
                 "compile_unit_id": command["compile_unit_id"], "shard_id": shard},
                _location(unit.job.source_fingerprint, unit.job.target_root or Path(),
                          command["target_path"], line, column)))
            count += 1
    builder.add_coverage("clang-ast", "partial" if gaps else "complete", "; ".join(gaps[:10]) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "analysis", "ast", gaps))
    result["entity_count"] = count
    return result


_IR_ENTITY = re.compile(r"^define\s+.*?@(?P<name>[^\s(]+)\(")
_IR_CALL = re.compile(r"\bcall\b.*?@(?P<name>[^\s(]+)\(")


def _ir_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any], execution: Mapping[str, Any]) -> Mapping[str, Any]:
    root = _case_root(unit, case_id)
    gaps: list[str] = []
    builder, path, fingerprint, shard = _new_builder(unit, "analysis", case_id, "ir",
        [execution["execution"], catalog["compile_database"]], gaps,
        {"tool": "clang-18-llvm-ir", "image": execution["image_id"]},
        catalog["mapping"]["case_snapshot"])
    entities: dict[str, list[tuple[str, str]]] = {}
    pending_calls: list[tuple[str, str, str]] = []
    count = blocks = instructions = 0
    for index, command in enumerate(catalog["compile_commands"]):
        ir_path = root / "analysis" / "ir" / f"tu-{index:04d}.ll"
        if not ir_path.is_file() or ir_path.stat().st_size > 64 * 1024 * 1024:
            gaps.append(f"{command['target_path']}: LLVM IR output unavailable or over bound")
            continue
        current: str | None = None
        for line_number, line in enumerate(ir_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            match = _IR_ENTITY.match(line)
            if match:
                name = match.group("name")
                identity = LogicalIdentity.derive(EntityKind.IR_ENTITY, catalog["mapping"]["case_snapshot"],
                    {"compile_unit_id": command["compile_unit_id"], "function": name,
                     "definition_line": line_number})
                builder.add_entity(EntityRecord(identity, f"{index}:{name}", name, line[:8192],
                    {"kind": "function", "ir_line": line_number,
                     "project_id": catalog["mapping"]["project_id"],
                     "compile_unit_id": command["compile_unit_id"], "shard_id": shard},
                    _location(unit.job.source_fingerprint, unit.job.target_root or Path(),
                              command["target_path"], ambiguous=True, method="debug-or-tu-fallback")))
                entities.setdefault(name, []).append((command["compile_unit_id"], identity.value))
                current = identity.value
                count += 1
            elif current and line.endswith(":"):
                blocks += 1
            elif current and line.startswith("  "):
                instructions += 1
                call = _IR_CALL.search(line)
                if call:
                    pending_calls.append((current, call.group("name"), command["compile_unit_id"]))
    call_edges = 0
    seen_calls: set[tuple[str, str]] = set()
    ambiguous_names: set[str] = set()
    for caller, callee_name, caller_tu in pending_calls:
        candidates = entities.get(callee_name, ())
        local = [identity for tu, identity in candidates if tu == caller_tu]
        resolved = local if len(local) == 1 else [identity for _, identity in candidates]
        if len(resolved) == 1:
            edge = (caller, resolved[0])
            if edge not in seen_calls:
                seen_calls.add(edge)
                builder.add_relation(RelationRecord(RelationKind.CALLS, caller, resolved[0], True, 1.0,
                                                    payload={"mapping": "unique-ir-definition"}))
                call_edges += 1
        elif len(resolved) > 1:
            ambiguous_names.add(callee_name)
    if ambiguous_names:
        gaps.append("ambiguous cross-translation-unit IR callees were not related: " +
                    ", ".join(sorted(ambiguous_names)[:20]))
    builder.add_coverage("llvm-ir", "partial" if gaps else "complete", "; ".join(gaps[:10]) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "analysis", "ir", gaps))
    result.update(entity_count=count, basic_block_count=blocks, instruction_count=instructions,
                  call_edge_count=call_edges)
    return result


def _blocked_index(unit: UnitContext, case_id: str, branch: str, catalog: Mapping[str, Any], gap: str) -> Mapping[str, Any]:
    builder, path, fingerprint, shard = _new_builder(unit, "observations", case_id, branch,
        [catalog["compile_database"]], [gap], {"tool": branch, "availability": "blocked"},
        catalog["mapping"]["case_snapshot"])
    identity = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, catalog["mapping"]["case_snapshot"],
                                      {"case": case_id, "producer": branch, "status": "BLOCKED"})
    builder.add_entity(EntityRecord(identity, f"{branch}:{case_id}", branch,
                                    gap, {"status": "BLOCKED", "observation_count": 0}))
    builder.add_coverage(branch, "unavailable", gap)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "observations", branch, [gap]))
    result["observation_count"] = 0
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
        {"tool": "infer", "version": execution["tool_version"], "image": execution["image_id"],
         "image_digest": execution["image_digest"]}, catalog["mapping"]["case_snapshot"])

    by_relative = {
        str(item["scratch_path"])[len("source/"):]: item
        for item in catalog["mapping"].get("files", ())
        if str(item.get("scratch_path", "")).startswith("source/")
    }
    count = 0
    for ordinal, record in enumerate(records):
        raw_path = str(record.get("file", "")).replace("\\", "/")
        relative = raw_path[len("/target/source/"):] if raw_path.startswith("/target/source/") else ""
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
                         "; ".join(unique_gaps[:10]) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard,
                                "observations", "infer", unique_gaps))
    result.update(observation_count=count, expected_source_files=expected_count,
                  captured_source_files=captured_count)
    return result


def _binary_index(unit: UnitContext, case_id: str, catalog: Mapping[str, Any], execution: Mapping[str, Any]) -> Mapping[str, Any]:
    records_path = _case_root(unit, case_id) / "analysis" / "binary" / "records.json"
    gaps = []
    try:
        records = json.loads(records_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        records, gaps = [], ["binary/symbol analysis produced no valid bounded record set"]
    builder, path, fingerprint, shard = _new_builder(unit, "compiled", case_id, "binary",
        [execution["execution"], catalog["artifact_catalog"]], gaps,
        {"tool": "binutils-2.42", "image": execution["image_id"]}, catalog["mapping"]["case_snapshot"])
    symbols = 0
    seen_entities: set[str] = set()
    for record_index, record in enumerate(records[:4096]):
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
    builder.add_coverage("symbols-and-hardening", "partial" if gaps else "complete", "; ".join(gaps) or None)
    result = dict(_finish_index(unit, builder, path, fingerprint, shard, "compiled", "binary", gaps))
    result.update(entity_count=len(records), symbol_count=symbols)
    return result


def _validate_config(context, _result) -> None:
    expected_steps = ("plan", "prepare", "configure", "compile", "catalog", *BRANCHES, "acceptance")
    if tuple(context.config.steps) != expected_steps:
        raise ValueError("C++ compiled-analysis topology does not match central configuration")
    if tuple(context.config.step("plan").tasks) != ("accepted_cpp_plan",):
        raise ValueError("C++ plan task configuration is invalid")
    for step in ("prepare", "configure", "compile", "catalog", *BRANCHES):
        if tuple(context.config.step(step).tasks) != PROJECT_TASKS:
            raise ValueError(f"C/C++ project task configuration mismatch: {step}")
    if tuple(context.config.step("acceptance").tasks) != ("publish_handoff",):
        raise ValueError("C++ acceptance task configuration is invalid")


def build_job(*, executor_factory=None) -> Job:

    def plan(unit: UnitContext) -> Mapping[str, Any]:
        accepted = load_accepted_plan(unit.job.run_root)
        actions = []
        target = (unit.job.target_root or Path()).resolve(strict=True)
        for action in accepted["build_topology"]["build_actions"]:
            root = PurePosixPath(str(action.get("root", "")))
            if (not root.parts or root.parts[0] != "projects" or
                    action.get("build_system") not in {"cmake", "make", "autotools", "msbuild"}):
                continue
            source = (target / Path(*root.parts)).resolve(strict=True)
            if target not in source.parents or not source.is_dir():
                raise ValueError(f"accepted C/C++ project escapes the target: {root}")
            native_sources = [path for path in source.rglob("*") if path.is_file() and not path.is_symlink()
                              and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}]
            if not native_sources:
                continue
            actions.append({**dict(action), "project_key": _project_key(root),
                            "project_id": f"cpp:{root.as_posix()}",
                            "source_count": len(native_sources)})
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
            mapping = _safe_copy_case(unit, project_key, action)
            artifact = _json_artifact(unit, _case_root(unit, project_key) / "source-mapping.json", mapping)
            projects[project_key] = {"mapping": mapping, "artifact": artifact,
                                     "project_key": project_key, "profile": action["build_system"],
                                     "terminal_status": "SUCCEEDED", "gaps": []}
            unit.job.events.write("CPP_BUILD_PROJECT_PREPARED", project_key=project_key,
                                  project_id=mapping["project_id"], source_count=len(mapping["files"]),
                                  build_system=action["build_system"])
        return {"projects": projects, "project_count": len(projects),
                "terminal_status": "SUCCEEDED" if projects else "NOT_APPLICABLE", "gaps": []}

    def configure(unit: UnitContext) -> Mapping[str, Any]:
        projects = {}
        for case_id, source in unit.output("prepare.projects")["projects"].items():
            if source["profile"] == "msbuild":
                projects[case_id] = {"project_key": case_id, "profile": "msbuild",
                                     "gaps": [MSBUILD_GAP], "terminal_status": "UNAVAILABLE"}
                continue
            identity = _checkpoint_identity(unit, case_id, "configure",
                                            {"source_mapping": source["artifact"]["sha256"],
                                             "profile": source["profile"]})
            reused = _load_checkpoint(unit, case_id, "configure", identity)
            if reused is not None:
                projects[case_id] = reused
                continue
            execution = _run_tool(unit, case_id, ("configure", str(source["profile"])), executor_factory)
            gap = None if execution["exit_code"] == 0 else f"{case_id} configure failed with exit {execution['exit_code']}"
            unit.job.events.write("CPP_BUILD_PROJECT_CONFIGURED", project_key=case_id,
                                  terminal_status="SUCCEEDED" if gap is None else "FAILED_AS_GAP",
                                  image_id=execution["image_id"])
            result = {**execution, "project_key": case_id, "profile": source["profile"],
                      "gaps": [gap] if gap else [], "terminal_status": "SUCCEEDED" if gap is None else "FAILED_AS_GAP"}
            _save_checkpoint(unit, case_id, "configure", identity, result)
            projects[case_id] = result
        gaps = [gap for result in projects.values() for gap in result.get("gaps", ())]
        return {"projects": projects, "project_count": len(projects), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else ("SUCCEEDED" if projects else "NOT_APPLICABLE")}

    def compile_projects(unit: UnitContext) -> Mapping[str, Any]:
        projects = {}
        for case_id, configured in unit.output("configure.projects")["projects"].items():
            gap = _terminal_gap(configured)
            if gap:
                projects[case_id] = {"project_key": case_id, "profile": configured.get("profile"),
                                     "gaps": [gap], "terminal_status": "BLOCKED_BY_CONFIGURE"}
                continue
            identity = _checkpoint_identity(unit, case_id, "compile",
                                            {"configure_execution": configured["execution"]["sha256"],
                                             "profile": configured["profile"]})
            reused = _load_checkpoint(unit, case_id, "compile", identity)
            if reused is not None:
                projects[case_id] = reused
                continue
            execution = _run_tool(unit, case_id, ("compile", str(configured["profile"])), executor_factory)
            gap = None if execution["exit_code"] == 0 else f"{case_id} compile failed with exit {execution['exit_code']}"
            unit.job.events.write("CPP_BUILD_PROJECT_COMPILED", project_key=case_id,
                                  terminal_status="SUCCEEDED" if gap is None else "FAILED_AS_GAP",
                                  image_id=execution["image_id"])
            result = {**execution, "project_key": case_id, "profile": configured["profile"],
                      "gaps": [gap] if gap else [], "terminal_status": "SUCCEEDED" if gap is None else "FAILED_AS_GAP"}
            _save_checkpoint(unit, case_id, "compile", identity, result)
            projects[case_id] = result
        gaps = [gap for result in projects.values() for gap in result.get("gaps", ())]
        return {"projects": projects, "project_count": len(projects), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else ("SUCCEEDED" if projects else "NOT_APPLICABLE")}

    def catalog(unit: UnitContext) -> Mapping[str, Any]:
        projects = {}
        prepared = unit.output("prepare.projects")["projects"]
        for case_id, compiled in unit.output("compile.projects")["projects"].items():
            gap = _terminal_gap(compiled)
            mapping = prepared[case_id]["mapping"]
            if gap:
                projects[case_id] = {"project_key": case_id, "mapping": mapping, "gaps": [gap],
                                     "terminal_status": "BLOCKED_BY_COMPILE"}
                continue
            identity = _checkpoint_identity(unit, case_id, "catalog",
                                            {"compile_execution": compiled["execution"]["sha256"],
                                             "mapping": prepared[case_id]["artifact"]["sha256"],
                                             "link_normalizer": "native-link-normalizer/2"})
            reused = _load_checkpoint(unit, case_id, "catalog", identity)
            if reused is not None:
                projects[case_id] = reused
                continue
            root = _case_root(unit, case_id)
            try:
                commands = normalize_compile_db(root, mapping)
                compile_artifact = _json_artifact(unit, root / "normalized-compile-commands.json", commands)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                projects[case_id] = {"project_key": case_id, "mapping": mapping,
                    "gaps": [f"{case_id} compile database invalid: {type(exc).__name__}: {exc}"],
                    "terminal_status": "INVALID_COMPILE_DATABASE"}
                continue
            outputs = []
            for path in sorted((root / "build").rglob("*")):
                if not path.is_file() or path.is_symlink() or path.name == "compile_commands.json":
                    continue
                magic = path.read_bytes()[:4]
                kind = "object" if path.suffix == ".o" else "library" if path.suffix in {".a", ".so"} else (
                    "executable" if magic == b"\x7fELF" else None)
                if kind:
                    outputs.append({"path": path.relative_to(root).as_posix(), "kind": kind,
                                    "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
            links_path = root / "build" / "link-commands.json"
            link_commands = []
            if links_path.is_file() and not links_path.is_symlink() and links_path.stat().st_size <= 4 * 1024 * 1024:
                candidate_links = json.loads(links_path.read_text(encoding="utf-8"))
                link_commands = normalize_link_commands(candidate_links, outputs)
            output_artifact = _json_artifact(unit, root / "artifact-catalog.json", outputs)
            link_artifact = _json_artifact(unit, root / "normalized-link-commands.json", link_commands)
            result = {"project_key": case_id, "mapping": mapping, "compile_commands": commands,
                      "compile_database": compile_artifact, "artifact_catalog": output_artifact,
                      "link_database": link_artifact, "link_commands": link_commands,
                      "outputs": outputs, "image_id": compiled["image_id"], "gaps": [],
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
            for case_id, cataloged in unit.output("catalog.projects")["projects"].items():
                gap = _terminal_gap(cataloged)
                if gap:
                    builder, path, fingerprint, shard = _new_builder(unit,
                        "observations" if name in {"codeql", "joern"} else "analysis",
                        case_id, name, [], [gap], {"tool": name, "status": "blocked-by-build"},
                        cataloged["mapping"]["case_snapshot"])
                    builder.add_coverage(name, "unavailable", gap)
                    projects[case_id] = _finish_index(unit, builder, path, fingerprint, shard,
                                                      builder.name, name, [gap])
                    continue
                identity_values = {
                    "compile_database": cataloged["compile_database"]["sha256"],
                    "branch_identity": BRANCH_IDENTITY[name],
                }
                if name != "infer":
                    identity_values.update({
                        "artifact_catalog": cataloged["artifact_catalog"]["sha256"],
                        "link_database": cataloged["link_database"]["sha256"],
                    })
                identity = _checkpoint_identity(
                    unit, case_id, f"branch-{name}", identity_values,
                    tool_id="tool-infer" if name == "infer" else "tool-native-cpp")
                reused = _load_checkpoint(unit, case_id, f"branch-{name}", identity)
                if reused is not None:
                    projects[case_id] = reused
                    continue
                if name == "compiled":
                    result = _build_entities(unit, case_id, cataloged)
                elif name == "infer":
                    execution = _run_infer(unit, case_id, cataloged, executor_factory)
                    result = _infer_index(unit, case_id, cataloged, execution)
                elif name == "codeql":
                    result = _blocked_index(unit, case_id, name, cataloged, CODEQL_GAP)
                elif name == "joern":
                    result = _blocked_index(unit, case_id, name, cataloged, JOERN_GAP)
                else:
                    tool_mode = "symbols" if name == "binary" else name
                    execution = _run_tool(unit, case_id, (tool_mode,), executor_factory)
                    tool_gap = (None if execution["exit_code"] == 0 else
                                f"{case_id} {name} failed with exit {execution['exit_code']}")
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
                        result = _ast_index(unit, case_id, cataloged, execution)
                    elif name == "ir":
                        result = _ir_index(unit, case_id, cataloged, execution)
                    else:
                        result = _binary_index(unit, case_id, cataloged, execution)
                _save_checkpoint(unit, case_id, f"branch-{name}", identity, result)
                projects[case_id] = result
            gaps = [gap for result in projects.values() for gap in result.get("gaps", ())]
            return {"projects": projects, "project_count": len(projects), "branch": name, "gaps": gaps,
                    "terminal_status": "COMPLETED_WITH_GAPS" if gaps else ("SUCCEEDED" if projects else "NOT_APPLICABLE")}
        return handler

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        manifest_path, manifest_sha = resolve_accepted_manifest(unit.job.run_root)
        upstream, _ = load_verified_manifest(unit.job.run_root, manifest_path, manifest_sha)
        prior_identities = [IndexIdentity(**{**value, "gaps": tuple(value.get("gaps", ()))})
                            for value in upstream["indexes"]]
        current_identities: list[IndexIdentity] = []
        gaps, dispositions = [], {}
        for name in BRANCHES:
            for case_id, output in unit.output(f"{name}.projects")["projects"].items():
                identity = output.get("index_identity")
                if isinstance(identity, Mapping):
                    current_identities.append(IndexIdentity(**{**identity, "gaps": tuple(identity.get("gaps", ())) }))
                gaps.extend(str(item) for item in output.get("gaps", ()))
                dispositions[f"{case_id}:{name}"] = output.get("terminal_status", "UNKNOWN")
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
                "item_count": len(identities), "gaps": unique_gaps, "dispositions": dispositions,
                "terminal_status": "COMPLETED_WITH_GAPS" if unique_gaps else "SUCCEEDED"}

    units: list[Unit] = [Unit("plan.accepted_cpp_plan", plan)]
    units.append(Unit("prepare.projects", prepare, ("plan.accepted_cpp_plan",)))
    units.append(Unit("configure.projects", configure, ("prepare.projects",)))
    units.append(Unit("compile.projects", compile_projects, ("configure.projects",)))
    units.append(Unit("catalog.projects", catalog, ("compile.projects", "prepare.projects")))
    for name in BRANCHES:
        units.append(Unit(f"{name}.projects", branch(name), ("catalog.projects",)))
    dependencies = tuple(f"{name}.projects" for name in BRANCHES)
    units.append(Unit("acceptance.publish_handoff", publish, dependencies))
    values = tuple(units)
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
                                    (b"injected-executor" if executor_factory else b"container-executor")).hexdigest()
    return Job("job_cpp_compiled_analysis", "cpp_compiled_analysis", UnitExecutor(values).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=values)
