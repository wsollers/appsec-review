"""Shared command planning and immediate source/cwd custody for production and detached replay."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
from typing import Any

from appsec_review.jobs.build_discovery import ensure_declared_build_dir, recipe_execution_cwd


@dataclass(frozen=True, slots=True)
class _CommandPlan:
    argv: tuple[str, ...]
    cwd: str
    drivers: tuple[str, ...] = ()
    make_directory: str | None = None
    cmake_build: str | None = None
    directories: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()


def _plan(recipe: Mapping[str, Any], phase: str, argv: Sequence[str], *,
          normalized: bool = False) -> _CommandPlan:
    from appsec_review.jobs.job_project_build.job import _normalized_argv
    cwd = recipe_execution_cwd(recipe, phase)
    if not argv:
        raise ValueError("recipe command is empty")
    tool = PurePosixPath(argv[0]).name
    command = list(argv if normalized or "execution_cwd" in recipe or tool in {"cmake", "make", "gmake"}
                   else _normalized_argv(recipe, list(argv)))
    command[0] = argv[0]
    source, build = str(recipe["source_dir"]), recipe.get("build_dir")

    def operand(value: str, base: str, *, rebase: bool = True) -> tuple[str, str]:
        if rebase and not normalized and source != "." and (value == source or value.startswith(source + "/")):
            value = posixpath.relpath(value, base)
        logical = posixpath.normpath(posixpath.join(base, value))
        if (PurePosixPath(logical).is_absolute() or ".." in PurePosixPath(logical).parts
                or "\\" in value or "\0" in value):
            raise ValueError("driver operand escaped the verified workspace")
        return value, logical

    if tool == "cmake":
        paths = {}
        index = 1
        while index < len(command):
            value = command[index]
            if value in {"-S", "-B", "--build"}:
                if value in paths or index + 1 == len(command):
                    raise ValueError("ambiguous CMake source/build operands")
                command[index + 1], paths[value] = operand(command[index + 1], cwd)
                index += 2
                continue
            if value.startswith(("-S", "-B")) and len(value) > 2:
                option = value[:2]
                if option in paths or value[2] == "=":
                    raise ValueError("ambiguous CMake source/build operands")
                adjusted, paths[option] = operand(value[2:], cwd)
                command[index] = option + adjusted
            elif value.startswith(("--preset", "--workflow", "--install", "--build=", "-P", "-E")):
                raise ValueError("unsupported CMake driver authority; use explicit source/build operands")
            elif value == "--":
                break
            elif value in {"--target", "-t"}:
                while index + 1 < len(command) and not command[index + 1].startswith("-"):
                    index += 1
            elif value in {"-G", "-A", "-T", "-D", "-U", "-C",
                           "--parallel", "-j", "--config"}:
                if index + 1 < len(command) and not command[index + 1].startswith("-"):
                    index += 1
            elif not value.startswith("-"):
                raise ValueError("unsupported positional CMake source/build operand")
            index += 1
        cmake_build = None
        if "--build" in paths:
            if phase != "build" or set(paths) != {"--build"} or paths["--build"] != build:
                raise ValueError("CMake build directory differs from declared build authority")
            cmake_build = str(build)
        elif paths.get("-S", cwd) != source or paths.get("-B", cwd) != build:
            raise ValueError("CMake configure selects the wrong accepted source/build directory")
        return _CommandPlan(tuple(command), cwd,
            ((PurePosixPath(source) / "CMakeLists.txt").as_posix(),), cmake_build=cmake_build,
            directories=tuple(paths.values()))
    if tool in {"make", "gmake"}:
        directories, makefiles = [], []
        index = 1
        while index < len(command):
            value = command[index]
            if value == "--":
                break
            if value in {"-C", "--directory", "-f", "--file", "--makefile"}:
                if index + 1 == len(command):
                    raise ValueError("Make driver operand is missing")
                (directories if value in {"-C", "--directory"} else makefiles).append((index + 1, ""))
                index += 2
                continue
            for prefix, destination in (("--directory=", directories), ("--file=", makefiles),
                                        ("--makefile=", makefiles), ("-C", directories), ("-f", makefiles)):
                if value.startswith(prefix) and len(value) > len(prefix):
                    destination.append((index, prefix))
                    break
            else:
                if value.startswith("-") and any(letter in value[1:] for letter in ("C", "f")):
                    raise ValueError("unsupported combined Make driver options")
            index += 1
        effective = cwd
        required = []
        for index, prefix in directories:
            value, effective = operand(command[index][len(prefix):], effective)
            command[index] = prefix + value
            required.append(effective)
        if effective not in {source, build}:
            raise ValueError("Make directory differs from accepted source/build authority")
        drivers = []
        for index, prefix in makefiles:
            value, relative = operand(command[index][len(prefix):], effective)
            command[index] = prefix + value
            drivers.append(relative)
        return _CommandPlan(tuple(command), cwd, tuple(drivers),
                            None if makefiles else effective, directories=tuple(required))
    if "execution_cwd" in recipe and cwd != source and tool in {"clang", "clang++", "gcc", "g++"}:
        drivers, outputs = [], []
        index = 1
        while index < len(command):
            value = command[index]
            if value in {"-o", "-target", "--target"}:
                if index + 1 == len(command):
                    raise ValueError("compiler option operand is missing")
                if value == "-o":
                    _, output = operand(command[index + 1], cwd, rebase=False)
                    if not (output == source or output.startswith(source.rstrip("/") + "/")
                            or source == "."):
                        raise ValueError("compiler output escaped its accepted unit")
                    outputs.append(output)
                index += 2
                continue
            if not value.startswith("-") and PurePosixPath(value).suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}:
                _, path = operand(value, cwd, rebase=False)
                drivers.append(path)
            index += 1
        if not drivers:
            raise ValueError("changed compiler cwd requires accepted translation-unit source evidence")
        return _CommandPlan(tuple(command), cwd, tuple(drivers), outputs=tuple(outputs))
    if "execution_cwd" in recipe and cwd != source:
        raise ValueError("changed execution cwd is unsupported for this driver; use a validated native driver")
    return _CommandPlan(tuple(command), cwd)


def normalize_recipe_command(recipe: Mapping[str, Any], phase: str,
                             argv: Sequence[str]) -> tuple[tuple[str, ...], str]:
    """Pure command plan: rebase recognized path operands, never native target/flag values."""
    plan = _plan(recipe, phase, argv)
    return plan.argv, plan.cwd


def prepare_recipe_command(workspace: Path, validation_unit: Mapping[str, Any],
                           recipe: Mapping[str, Any], phase: str, argv: Sequence[str], *,
                           normalized: bool = False) -> tuple[tuple[str, ...], str]:
    """Recheck actual source/driver and cwd custody immediately before every command launch."""
    plan = _plan(recipe, phase, argv, normalized=normalized)
    if str(recipe["source_dir"]) != str(validation_unit["root"]):
        raise ValueError("execution source differs from the accepted unit root")
    ensure_declared_build_dir(workspace, recipe)
    root = workspace.resolve(strict=True)

    def contained(relative: str, *, exists: bool = True) -> Path:
        logical = PurePosixPath(relative)
        if logical.is_absolute() or ".." in logical.parts:
            raise ValueError("driver operand escaped the verified workspace")
        current = root
        for component in logical.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("recipe execution path traverses a symlink")
        resolved = current.resolve(strict=exists)
        if not resolved.is_relative_to(root):
            raise ValueError("recipe execution path escaped the verified workspace")
        return resolved

    if workspace.is_symlink() or not contained(plan.cwd).is_dir():
        raise ValueError("recipe execution cwd is not a verified workspace directory")
    documents = {str(item["path"]): item for item in
                 validation_unit.get("descriptor_package", {}).get("documents", ())}
    source, build = str(recipe["source_dir"]), recipe.get("build_dir")
    if (plan.cwd != source and not (build and (plan.cwd == build or plan.cwd.startswith(build + "/")))
            and not any(str(PurePosixPath(path).parent) == plan.cwd for path in documents)):
        raise ValueError("execution cwd lacks accepted source or declared build-directory evidence")
    for relative in plan.directories:
        if not contained(relative).is_dir():
            raise ValueError("native driver does not resolve a verified directory")
    for relative in plan.outputs:
        contained(relative, exists=False)
    drivers = plan.drivers
    if plan.make_directory is not None:
        candidates = [(PurePosixPath(plan.make_directory) / name).as_posix()
                      for name in ("GNUmakefile", "makefile", "Makefile")]
        driver = next((path for path in candidates if contained(path, exists=False).exists()), None)
        if driver is None:
            raise ValueError("Make default driver is absent")
        drivers = (driver,)
    for relative in drivers:
        document, path = documents.get(relative), contained(relative)
        if (document is None or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != document.get("sha256")):
            raise ValueError("native driver is not the unchanged accepted source descriptor")
    if plan.cmake_build is not None:
        cache = contained(plan.cmake_build) / "CMakeCache.txt"
        if cache.is_symlink():
            raise ValueError("CMake cache traverses a symlink")
        if cache.is_file():
            homes = [line.partition("=")[2] for line in cache.read_text(errors="strict").splitlines()
                     if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")]
            if homes and homes != ["/workspace/" + source if source != "." else "/workspace"]:
                raise ValueError("CMake cache selects a different accepted source")
    return plan.argv, plan.cwd
