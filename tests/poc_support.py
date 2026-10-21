"""Shared support for the ``job_poc_generation`` tests: settings, a relay build unit and a recording fake executor.

The fake executor stands in for ``BuildContainerExecutor``: it answers the AST, syntax, object and ``nm``
commands from scripted data, writes the object files a real compiler would, and records every argv so a
test can assert the job never links an executable, never names a file the build produced as a command and
never runs anything but the compiler, the AST reducer and ``nm``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tomllib
from types import SimpleNamespace
from typing import Any, Callable, Mapping, Sequence

from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, BuildUnit, CompileCommand
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings
from tests.fixtures.poc_generation import relay

ROOT = Path(__file__).parents[1]
TARGET = Path.home() / "projects" / "appsec-review" / "targets" / "cpp-multivuln"
FIXTURES = Path(__file__).parent / "fixtures" / "poc_generation"
PROJECT_SYMBOL = "_ZN5relay12parse_headerEPKhmRNS_6HeaderE"
OBJECTS = ("build/CMakeFiles/relay.dir/src/packet.cpp.o", "build/CMakeFiles/relay.dir/src/main.cpp.o")


def settings_table() -> dict[str, Any]:
    return tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["jobs"]["job_poc_generation"][
        "settings"]


def settings(**overrides: Any) -> PocGenerationSettings:
    table = settings_table()
    for key, value in overrides.items():
        table[key] = value
    return PocGenerationSettings.from_mapping(table)


def manifest_of(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()}


def command(source: str = "src/packet.cpp") -> CompileCommand:
    return CompileCommand(relay.PACKET_ARGV, source, "cxx", ".", "exact")


def relay_unit(workspace: Path, manifest: Mapping[str, str], *, objects: Sequence[str] = OBJECTS,
               image_id: str = "sha256:" + "a" * 64, tag: str = "audit-buildenv-cpp:local",
               compile_command: CompileCommand | None = None) -> BuildUnit:
    return BuildUnit(
        "build-unit-" + "1" * 20, "cmake", ".", "f" * 64, workspace, dict(manifest),
        hashlib.sha256(json.dumps(dict(manifest), sort_keys=True).encode()).hexdigest(), tag, image_id, "10001:10001",
        compile_command or command(), tuple(objects), ())


def relay_workspace(destination: Path, *, with_objects: bool = True) -> tuple[Path, dict[str, str]]:
    """A copy of the cpp-multivuln source with placeholder object files, and the manifest of every file."""
    if destination.exists():
        shutil.rmtree(destination)
    # The whole cpp-multivuln target when this host has it; otherwise the two files the reproducer needs.
    shutil.copytree(TARGET if TARGET.is_dir() else FIXTURES / "relay_source", destination)
    if with_objects:
        for relative in OBJECTS:
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELF placeholder " + relative.encode())
    return destination, manifest_of(destination)


def builds(unit: BuildUnit, *, byte_limit: int = 10**9) -> AcceptedBuilds:
    """An ``AcceptedBuilds`` whose lookup always finds ``unit`` (only its workspace copy is used)."""
    found = AcceptedBuilds(unit.workspace.parent, loader=lambda _root: {"receipts": []})
    found.locate = lambda path: SimpleNamespace(unit=unit, reason="", code="found")  # type: ignore[method-assign]
    return found


def without_ids(value: Any) -> Any:
    """``value`` without clang's per-run node ids (``id``, ``typeAliasDeclId`` and the ids inside references)."""
    if isinstance(value, dict):
        return {key: without_ids(item) for key, item in value.items()
                if key not in {"id", "typeAliasDeclId", "referencedMemberDecl"}}
    if isinstance(value, list):
        return [without_ids(item) for item in value]
    return value


def ast_document(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "ast" / f"{name}.json").read_text(encoding="utf-8"))


NM_UNDEFINED = f"{PROJECT_SYMBOL} U\nmemset U\n__asan_init U\n__ubsan_handle_type_mismatch_v1 U\n__gmon_start__ w\n"
NM_PROJECT = f"{PROJECT_SYMBOL} T 0000000000000000 0000000000000040\nmain T 0000000000000000 0000000000000010\n"
NM_RUNTIME = "memset T 0000000000000000 0000000000000010\nmemcpy T 0000000000000000 0000000000000010\n"


class FakeExecutor:
    """A recording stand-in for the build container executor."""

    def __init__(self, ast: Callable[[str], Mapping[str, Any]] | Mapping[str, Any] | None = None, *,
                 undefined: str = NM_UNDEFINED, project: str = NM_PROJECT, runtime: str = NM_RUNTIME,
                 fail: Mapping[str, int] | None = None, unavailable: bool = False) -> None:
        self.ast = ast
        self.undefined, self.project, self.runtime = undefined, project, runtime
        self.fail = dict(fail or {})
        self.unavailable = unavailable
        self.calls: list[dict[str, Any]] = []
        self.produced: set[str] = set()
        self.resolved = 0

    def resolve(self) -> None:
        self.resolved += 1
        if self.unavailable:
            raise RuntimeError("build image is unavailable: native")

    def execute(self, argv: Sequence[str], *, workspace: Path, working_directory: str,
                environment: Mapping[str, str]) -> Any:
        command = tuple(argv)
        self.calls.append({"argv": command, "workspace": workspace, "working_directory": working_directory,
                           "environment": dict(environment)})
        stdout, stderr, code = b"", b"", 0
        if command[0] == "python3":
            source = Path(workspace) / command[command.index("--source") + 1].removeprefix("/workspace/")
            document = self.ast(source.read_text(encoding="utf-8")) if callable(self.ast) else self.ast
            stdout = json.dumps(document).encode() if document is not None else b""
        elif command[0] == "nm":
            if "-u" in command:
                stdout = self.undefined.encode()
            elif "-D" in command and "-g" not in command:
                stdout = self.runtime.encode()
            else:
                stdout = self.project.encode()
        elif "-o" in command:
            target = Path(workspace) / command[command.index("-o") + 1].removeprefix("/workspace/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"\x7fELF object " + hashlib.sha256(" ".join(command).encode()).digest())
            self.produced.add(command[command.index("-o") + 1])
        label = next((key for key in self.fail if key in " ".join(command)), None)
        if label is not None:
            code, stderr = self.fail[label], b"poc.cpp:3:3: error: use of undeclared identifier 'x'\n"
        return SimpleNamespace(exit_code=code, timed_out=False, stdout=stdout, stderr=stderr,
                               stdout_bytes=len(stdout), stderr_bytes=len(stderr))

    # -- invariants every test of the compile path asserts ----------------------------------------------
    def assert_nothing_is_linked_or_run(self) -> None:
        produced = {item.removeprefix("/workspace/") for item in self.produced}
        assert self.calls, "the executor was never used"
        for call in self.calls:
            argv = call["argv"]
            assert argv[0] in {"python3", "nm"} or PurePosixName(argv[0]) in {"clang", "clang++", "gcc", "g++", "cc", "c++"}, argv[0]
            assert argv[0].removeprefix("/workspace/") not in produced, "a produced file was named as the command"
            assert not any(item.startswith("./") for item in argv), argv
            if "-o" in argv:
                assert argv[argv.index("-o") + 1].endswith(".o"), "an output that is not an object file"
            if argv[0] not in {"python3", "nm"}:
                assert "-c" in argv or "-fsyntax-only" in argv, "a compiler command that could link"
            assert "-fuse-ld" not in " ".join(argv) and "-shared" not in argv and "-static" not in argv


def PurePosixName(value: str) -> str:
    return value.rsplit("/", 1)[-1]


SOURCE_NAMES = ("config", "diag", "frame", "log", "main", "packet", "session")


def accepted_run(root: Path, *, objects: bool = True, compile_rows: bool = True, terminal: str = "SUCCEEDED",
                 family: str = "native", build_dir: str = "build") -> SimpleNamespace:
    """A run directory holding one accepted native build unit in the shape ``job_language_build`` leaves.

    ``accepted`` is what ``load_accepted_language_build`` would return: the receipt set with the workspace,
    its manifest, the protected compile database, the image and the produced objects.
    """
    run_root = root / "run"
    unit_id = "build-unit-" + "1" * 20
    base = run_root / "data" / "build" / "native" / "units" / unit_id
    workspace, manifest = relay_workspace(base / "workspace", with_objects=objects)
    manifest_path = base / "workspace-manifest.json"
    manifest_path.write_text(json.dumps({"build_unit_id": unit_id, "files": manifest}), encoding="utf-8")
    rows = []
    for name in SOURCE_NAMES:
        argv = ["/usr/bin/clang++", "-I/workspace/include", "-O2", "-g", "-DNDEBUG", "-std=c++17", "-Wall", "-Wextra",
                "-MD", "-MT", f"CMakeFiles/relay.dir/src/{name}.cpp.o", "-MF", f"CMakeFiles/relay.dir/src/{name}.cpp.o.d",
                "-o", f"CMakeFiles/relay.dir/src/{name}.cpp.o", "-c", f"/workspace/src/{name}.cpp"]
        for compiler in ("/capture/wrappers/clang++", "/usr/bin/clang++"):
            rows.append({"argv": [compiler, *argv[1:]], "tool": "clang++", "tool_kind": "compiler",
                         "inputs": [{"workspace_path": f"src/{name}.cpp"}], "outputs": []})
    rows.append({"argv": ["/usr/bin/cmake", "--build", "build"], "tool": "cmake", "tool_kind": "build-driver",
                 "inputs": [], "outputs": []})
    database = base / "protected-commands" / "compile-database-attempt_0001.json"
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_text(json.dumps({"schema": "appsec-review/protected-compile-commands/1",
                                    "rows": rows if compile_rows else []}), encoding="utf-8")

    def ref(path: Path) -> dict[str, str]:
        return {"path": path.relative_to(run_root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    artifacts = [{"kind": "object", "workspace_path": relative, "path": (workspace / relative).relative_to(
        run_root).as_posix(), "sha256": manifest[relative]} for relative in OBJECTS if relative in manifest]
    artifacts.append({"kind": "executable", "workspace_path": "build/relay", "path": "x", "sha256": "0" * 64})
    receipt = {
        "build_unit_id": unit_id, "family": family, "terminal_status": terminal, "build_system": "cmake", "root": ".",
        "fingerprint": "f" * 64, "workspace": workspace.relative_to(run_root).as_posix(),
        "workspace_manifest": ref(manifest_path), "protected_compile_commands": ref(database),
        "image": {"image_tag": "audit-buildenv-cpp:local", "image_id": "sha256:" + "a" * 64, "user": "10001:10001"},
        "recipe": {"build_dir": build_dir}, "artifacts": artifacts}
    accepted = {"schema": "appsec-review/language-build-handoff/1", "receipts": [receipt],
                "language_build_handoff_sha256": "9" * 64}
    return SimpleNamespace(run_root=run_root, accepted=accepted, receipt=receipt, unit_id=unit_id,
                           workspace=workspace, manifest=manifest, database=database, manifest_path=manifest_path)
