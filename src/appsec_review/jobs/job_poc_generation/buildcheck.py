"""The compiler side of a PoC candidate: the AST parse for the validators, then the compile check.

Everything here runs the build image's tools through an injected executor (the production one is
``BuildContainerExecutor`` with no network) in a hash-verified copy of the accepted workspace. The
commands are derived from the exact compiler invocation the accepted build captured for the sink's
translation unit: the project's own include paths, defines and standard are kept, and what would
write dependency files, plugins or an executable is dropped. Nothing is linked and nothing is run:

* the only outputs are ``-fsyntax-only`` results and two object files (``-c``), which are hashed and
  then discarded with the scratch copy;
* the symbols the object needs come from ``nm -P -u`` and are checked against ``nm`` listings of the
  project's accepted objects and of a closed list of runtime libraries;
* no derived command names an input that the build produced, and none writes an executable.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import time
from typing import Any, Protocol

from appsec_review.indexing.build_facts import classify_command

from .ast_reduce import SCHEMA as AST_SCHEMA
from .buildctx import CONTAINER_ROOT, AcceptedBuilds, BuildUnit
from .settings import PocGenerationSettings
from .statuses import ARTIFACT_GENERATED, COMPILE_FAILED, COMPILE_VERIFIED

COMPILE_SCHEMA = "appsec-review/poc-compile/1"
REDUCER = Path(__file__).with_name("ast_reduce.py")
DIAGNOSTIC_BYTES = 4000
DROP_FLAGS = frozenset({"-c", "-MD", "-MMD", "-MP", "-M", "-MM", "-E", "-S", "-fsyntax-only", "-save-temps",
                        "-emit-pch", "-Werror", "-pedantic-errors", "-fcolor-diagnostics", "-fdiagnostics-color"})
DROP_WITH_VALUE = frozenset({"-o", "-MF", "-MT", "-MQ", "-MJ", "-include-pch"})
DROP_PREFIXES = ("-fplugin=", "-fpass-plugin=", "-Werror=", "-fdiagnostics-color=", "-MF", "-MT", "-MQ", "-MJ")
PLUGIN_XCLANG = frozenset({"-load", "-plugin", "-add-plugin", "-plugin-arg"})
AST_VALUE_FLAGS = frozenset({"-I", "-isystem", "-iquote", "-idirafter", "-include", "-x"})
AST_ATTACHED = re.compile(r"^(?:-I.+|-isystem.+|-iquote.+|-idirafter.+|-D.+|-U.+|-std=.+|-stdlib=.+|"
                          r"-f(?:no-)?(?:exceptions|rtti|char8-type|signed-char|unsigned-char|ms-extensions)|"
                          r"-fcxx-modules|-fno-cxx-modules|-m(?:32|64))$")


class Executor(Protocol):
    def execute(self, argv: Sequence[str], *, workspace: Path, working_directory: str,
                environment: Mapping[str, str]) -> Any: ...


@dataclass(frozen=True, slots=True)
class Names:
    """Where the candidate's files live in the scratch workspace (and so under ``/workspace``)."""

    directory: str
    source: str            # file name of the PoC translation unit
    reducer: str = "ast_reduce.py"
    object_file: str = "poc.o"
    sanitized_object: str = "poc_san.o"

    def container(self, name: str) -> str:
        return f"{CONTAINER_ROOT}/{self.directory}/{name}"


def derive(argv: Sequence[str], source: str, mode: str, names: Names, settings: PocGenerationSettings
           ) -> tuple[list[str], list[str]]:
    """The PoC command for ``mode`` (syntax, object, sanitized) from the captured compiler command.

    Returns the argv and the project flags that were dropped (they are recorded in compile.json).
    """
    container_source = f"{CONTAINER_ROOT}/{source}"
    out: list[str] = [argv[0]]
    dropped: list[str] = []
    index = 1
    while index < len(argv):
        item = argv[index]
        following = argv[index + 1] if index + 1 < len(argv) else None
        if item in DROP_WITH_VALUE:
            dropped.append(item)
            index += 2
            continue
        if item == "-Xclang" and following in PLUGIN_XCLANG:
            dropped.append(f"{item} {following}")
            index += 4 if following in {"-load", "-plugin", "-add-plugin"} else 2
            continue
        if item in DROP_FLAGS or item.startswith(DROP_PREFIXES):
            dropped.append(item)
            index += 1
            continue
        if item == container_source or (not item.startswith("-") and item.endswith(tuple(
                (".c", ".cc", ".cpp", ".cxx", ".c++"))) and PurePosixPath(item).name == PurePosixPath(source).name):
            dropped.append("<translation unit>")
            index += 1
            continue
        if mode in {"object", "sanitized"} and (item.startswith("-O") or re.fullmatch(r"-g[0-9a-z-]*", item)):
            dropped.append(item)
            index += 1
            continue
        if mode == "sanitized" and (item.startswith("-fsanitize") or item.startswith("-fno-sanitize")):
            dropped.append(item)
            index += 1
            continue
        out.append(item)
        index += 1
    poc = names.container(names.source)
    if mode == "syntax":
        out += ["-fsyntax-only", poc]
    elif mode == "object":
        out += [*settings.build.debug_flags, "-c", "-o", names.container(names.object_file), poc]
    elif mode == "sanitized":
        out += [*settings.build.debug_flags, *settings.build.sanitizer_flags, "-c", "-o",
                names.container(names.sanitized_object), poc]
    else:
        raise ValueError(f"unknown PoC compile mode: {mode}")
    return out, dropped


def derive_ast(argv: Sequence[str], language: str, names: Names, settings: PocGenerationSettings) -> list[str]:
    """The AST command: the in-image reducer around clang, keeping only the flags that shape parsing."""
    recorded = PurePosixPath(argv[0]).name
    compiler = argv[0] if recorded.startswith("clang") else settings.build.ast_compilers[language]
    kept: list[str] = []
    index = 1
    while index < len(argv):
        item = argv[index]
        if item in AST_VALUE_FLAGS and index + 1 < len(argv):
            kept += [item, argv[index + 1]]
            index += 2
            continue
        if AST_ATTACHED.match(item):
            kept.append(item)
        index += 1
    return ["python3", names.container(names.reducer), "--source", names.container(names.source),
            "--project-root", CONTAINER_ROOT, "--", compiler, *kept, "-fsyntax-only", "-Xclang", "-ast-dump=json",
            names.container(names.source)]


def render(argv: Sequence[str], visible: Sequence[str] = ()) -> list[str]:
    """A safe display form of a command: classified tokens, redacted values shown as placeholders.

    ``visible`` are arguments the job itself chose (tool names, its own paths); they are shown as they are.
    Everything else is the project's flags: logical paths, allowlisted values only.
    """
    shown = set(visible)
    result = []
    for original, token in zip(argv, classify_command(list(argv), target_prefixes=(CONTAINER_ROOT,)), strict=True):
        value = token.get("safe_value")
        if original in shown:
            result.append(original)
        elif value is None:
            result.append("<redacted>")
        elif token["kind"] in {"include_path", "library_path"} and original[:2] in {"-I", "-L"}:
            result.append(original[:2] + str(value))
        else:
            result.append(str(value))
    return result


def diagnostics(stderr: bytes, names: Names, limit: int = DIAGNOSTIC_BYTES) -> list[str]:
    text = stderr.decode("utf-8", "replace").replace(f"{CONTAINER_ROOT}/{names.directory}/", "")
    text = text.replace(f"{CONTAINER_ROOT}/", "")
    return [line[:300] for line in text.splitlines() if line.strip()][: max(1, limit // 100)]


@dataclass(slots=True)
class Step:
    name: str
    argv: list[str]
    working_directory: str
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.exit_code == 0

    def visible(self, names: Names) -> set[str]:
        """Arguments the job chose itself: tool names, its scratch paths, the reducer's compiler, system libraries."""
        chosen = {self.argv[0], "python3", "nm", "-ast-dump=json"}
        chosen |= {item for item in self.argv if item.startswith(f"{CONTAINER_ROOT}/{names.directory}/")}
        if self.argv[0] == "python3" and "--" in self.argv:
            chosen.add(self.argv[self.argv.index("--") + 1])
        if self.argv[0] == "nm":
            chosen |= {item for item in self.argv if item.startswith(("/lib/", "/usr/lib/"))}
        return chosen

    def record(self, names: Names) -> dict[str, Any]:
        return {"name": self.name, "command": render(self.argv, tuple(self.visible(names))),
                "command_sha256": hashlib.sha256(
                    json.dumps(self.argv).encode()).hexdigest(), "working_directory": self.working_directory,
                "exit_code": self.exit_code, "timed_out": self.timed_out, "duration_ms": self.duration_ms,
                "diagnostics": diagnostics(self.stderr, names) if self.error is None else [self.error[:300]]}


def run_step(executor: Executor, name: str, argv: Sequence[str], workspace: Path, working_directory: str
             ) -> Step:
    step = Step(name, list(argv), working_directory)
    started = time.monotonic()
    try:
        outcome = executor.execute(tuple(argv), workspace=workspace, working_directory=working_directory,
                                   environment={})
    except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
        step.error = f"{type(exc).__name__}: {exc}"
        return step
    finally:
        step.duration_ms = int((time.monotonic() - started) * 1000)
    step.exit_code, step.timed_out = outcome.exit_code, bool(outcome.timed_out)
    step.stdout, step.stderr = outcome.stdout, outcome.stderr
    return step


# -- nm ------------------------------------------------------------------------------------------------


def parse_nm(text: str) -> list[tuple[str, str]]:
    """``(name, type)`` rows of ``nm -P`` output; archive and file header lines are skipped."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or line.rstrip().endswith(":") or len(parts[1]) != 1:
            continue
        rows.append((parts[0].split("@", 1)[0], parts[1]))     # drop a symbol version such as memset@@GLIBC_2.2.5
    return rows


def resolve_symbols(undefined: Sequence[tuple[str, str]], project: set[str], runtime: set[str],
                    prefixes: Sequence[str]) -> dict[str, Any]:
    """Classify every required undefined symbol as project, runtime-library or unresolved."""
    required = sorted({name for name, kind in undefined if kind == "U"})
    weak = sorted({name for name, kind in undefined if kind in {"w", "v"}})
    by_project = [name for name in required if name in project]
    by_runtime = [name for name in required if name not in project and (name in runtime
                                                                          or name.startswith(tuple(prefixes)))]
    unresolved = [name for name in required if name not in set(by_project) | set(by_runtime)]
    return {"undefined": required, "resolved_by_project": by_project, "resolved_by_runtime": by_runtime,
            "weak": weak, "unresolved": unresolved}


# -- the phases ------------------------------------------------------------------------------------------


@dataclass(slots=True)
class Scratch:
    root: Path
    names: Names


def prepare(builds: AcceptedBuilds, unit: BuildUnit, parent: Path, *, name: str, poc_text: str,
            settings: PocGenerationSettings) -> Scratch:
    """Copy the verified accepted workspace into ``parent/<name>`` and put the PoC file beside the reducer."""
    root = Path(parent) / name
    if root.exists():
        shutil.rmtree(root)
    builds.materialize(unit, root, byte_limit=settings.build.workspace_bytes_limit)
    directory = settings.build.scratch_directory
    suffix = ".c" if unit.command.language == "c" else ".cpp"
    names = Names(directory, f"poc{suffix}")
    folder = root / directory
    if folder.exists():
        raise ValueError("the accepted workspace already holds the PoC scratch directory")
    folder.mkdir()
    (folder / names.source).write_text(poc_text, encoding="utf-8")
    (folder / names.reducer).write_bytes(REDUCER.read_bytes())
    return Scratch(root, names)


def reduced_ast(step: Step) -> tuple[dict[str, Any] | None, str]:
    """The reducer's document, or ``None`` with the reason the AST could not be read."""
    if step.error:
        return None, f"the AST step could not run: {step.error[:200]}"
    if step.timed_out:
        return None, "the AST step timed out"
    try:
        document = json.loads(step.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, f"the AST step produced no document (exit {step.exit_code})"
    if not isinstance(document, dict) or document.get("schema") != AST_SCHEMA:
        return None, "the AST step produced an unsupported document"
    return document, ""


def ast_step(executor: Executor, unit: BuildUnit, scratch: Scratch, settings: PocGenerationSettings) -> Step:
    command = derive_ast(unit.command.argv, unit.command.language, scratch.names, settings)
    return run_step(executor, "ast", command, scratch.root, unit.command.working_directory)


@dataclass(slots=True)
class BuildOutcome:
    status: str
    reason: str
    record: dict[str, Any]
    gaps: list[str] = field(default_factory=list)


def check_build(executor: Executor, builds: AcceptedBuilds, unit: BuildUnit, scratch: Scratch,
                settings: PocGenerationSettings, *, claim_id: str) -> BuildOutcome:
    """Syntax check, plain and sanitizer objects, then the undefined-symbol check; nothing is linked or run."""
    names, cwd = scratch.names, unit.command.working_directory
    steps: list[Step] = []
    dropped: dict[str, list[str]] = {}
    gaps: list[str] = list(unit.gaps)
    objects: dict[str, dict[str, Any]] = {}
    symbols: dict[str, Any] | None = None

    def finish(status: str, reason: str) -> BuildOutcome:
        record = {
            "schema": COMPILE_SCHEMA, "claim_id": claim_id, "status": status, "reason": reason[:300],
            "execution_policy": "nothing is linked into an executable and nothing is run",
            "build_unit": unit.identity(), "image": {"tag": unit.image_tag, "image_id": unit.image_id},
            "translation_unit": {"source": unit.command.source, "language": unit.command.language,
                                 "basis": unit.command.basis, "working_directory": cwd,
                                 "compiler": PurePosixPath(unit.command.argv[0]).name,
                                 "command_sha256": unit.command.sha256, "dropped_flags": dropped},
            "steps": [step.record(names) for step in steps], "objects": objects, "symbol_check": symbols,
            "settings_sha256": settings.settings_sha256(), "gaps": list(dict.fromkeys(gaps))}
        return BuildOutcome(status, reason, record, record["gaps"])

    for mode, label in (("syntax", "syntax"), ("object", "object"), ("sanitized", "sanitized_object")):
        argv, drops = derive(unit.command.argv, unit.command.source, mode, names, settings)
        dropped[label] = sorted(set(drops))
        step = run_step(executor, label, argv, scratch.root, cwd)
        steps.append(step)
        if step.error:
            gaps.append(f"the build image could not run {label}: {step.error[:160]}")
            return finish(ARTIFACT_GENERATED, f"the build image is unavailable ({label})")
        if not step.ok:
            reason = "timed out" if step.timed_out else f"exited {step.exit_code}"
            return finish(COMPILE_FAILED, f"the generated code does not build: {label} {reason}")
        if mode != "syntax":
            produced = scratch.root / names.directory / (names.object_file if mode == "object"
                                                           else names.sanitized_object)
            if not produced.is_file():
                return finish(COMPILE_FAILED, f"{label} produced no object file")
            objects[label] = {"sha256": hashlib.sha256(produced.read_bytes()).hexdigest(),
                              "size_bytes": produced.stat().st_size}
    poc_object = f"{names.directory}/{names.object_file}"
    undefined = run_step(executor, "undefined_symbols", ["nm", "-P", "-u", names.container(names.object_file)],
                         scratch.root, cwd)
    steps.append(undefined)
    if not undefined.ok:
        gaps.append("the undefined symbols of the object could not be read")
        return finish(ARTIFACT_GENERATED, "symbols could not be read from the object")
    required = parse_nm(undefined.stdout.decode("utf-8", "replace"))
    project: set[str] = set()
    for label, flag, files in (("project_symbols", "-g", unit.objects), ("project_shared_symbols", "-D", unit.shared_libraries)):
        if not files:
            continue
        for chunk_start in range(0, min(len(files), settings.build.object_limit), 256):
            chunk = [f"{CONTAINER_ROOT}/{item}" for item in files[chunk_start:chunk_start + 256]]
            step = run_step(executor, label, ["nm", "-P", flag, "--defined-only", *chunk], scratch.root, cwd)
            steps.append(step)
            if step.error or step.timed_out:
                gaps.append(f"project symbols could not be read ({label})")
                continue
            project.update(name for name, kind in parse_nm(step.stdout.decode("utf-8", "replace"))
                           if kind not in {"U", "w", "v"})
    if len(unit.objects) + len(unit.shared_libraries) > settings.build.object_limit:
        gaps.append(f"only the first {settings.build.object_limit} accepted outputs were read for symbols")
    runtime: set[str] = set()
    libraries = run_step(executor, "runtime_symbols",
                         ["nm", "-P", "-D", "--defined-only", *settings.build.runtime_libraries], scratch.root, cwd)
    steps.append(libraries)
    unavailable: list[str] = []
    if libraries.error or libraries.timed_out:
        gaps.append("the runtime library symbols could not be read")
    else:
        runtime.update(name for name, kind in parse_nm(libraries.stdout.decode("utf-8", "replace"))
                       if kind not in {"U", "w", "v"})
        unavailable = [library for library in settings.build.runtime_libraries
                       if library in libraries.stderr.decode("utf-8", "replace")]
    symbols = resolve_symbols(required, project, runtime, settings.build.runtime_symbol_prefixes)
    symbols["unavailable_runtime_libraries"] = unavailable
    symbols["project_symbol_count"] = len(project)
    symbols["runtime_symbol_count"] = len(runtime)
    del poc_object
    if not project:
        gaps.append("no project symbols were available, so the undefined symbols could not be resolved")
        return finish(ARTIFACT_GENERATED, "the project's accepted objects could not be read")
    if not runtime:
        gaps.append("no runtime library symbols were available, so the undefined symbols could not be resolved")
        return finish(ARTIFACT_GENERATED, "the runtime libraries could not be read")
    if symbols["unresolved"]:
        return finish(COMPILE_FAILED, "the object needs symbols that neither the project nor the runtime defines: "
                      + ", ".join(symbols["unresolved"][:5]))
    return finish(COMPILE_VERIFIED, "the functions compile against the project and every symbol they need resolves")


__all__ = ["BuildOutcome", "Names", "Scratch", "Step", "ast_step", "check_build", "derive", "derive_ast", "parse_nm",
           "prepare", "reduced_ast", "render", "resolve_symbols", "run_step"]
