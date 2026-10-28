"""Conservative, nonexecuting native compiler replay over caller-verified workspace copies.

Only an accepted translation unit is checked; no build system, linker, generated test or PoC is
invoked. The caller owns workspace/hash verification, patch policy (including tool configuration
changes), protected diagnostic retention and an offline executor pinned to the accepted image.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any

from appsec_review.jobs.job_poc_generation.buildctx import BuildUnit
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json


class UnsafeCompile(ValueError):
    """The accepted command cannot be replayed inside the syntax-only safety boundary."""


_COMPILERS = frozenset({"/usr/bin/clang", "/usr/bin/clang++", "/usr/bin/gcc", "/usr/bin/g++"})
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
_INCLUDES = ("-isystem", "-iquote", "-idirafter", "-I")
_DISCARD = frozenset({"-c", "-fsyntax-only", "-MD", "-MMD", "-MP", "-MG", "-M", "-MM"})
_OUTPUTS = ("-MF", "-MT", "-MQ", "-MJ", "-o")
_LANGUAGES = {".c": "c", ".cc": "cxx", ".cpp": "cxx", ".cxx": "cxx", ".c++": "cxx"}
_STANDARD = re.compile(
    r"-std=(?:(?:c|gnu)(?:89|90|99|9x|11|1x|17|18|2x|23)|"
    r"(?:c|gnu)\+\+(?:98|03|0x|11|1y|14|1z|17|2a|20|2b|23|2c|26)|"
    r"iso9899:(?:1990|199409|1999|2011|2017|2018|2024))")
_DEFINE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\((?:(?:[A-Za-z_][A-Za-z0-9_]*|\.\.\.)"
    r"(?:,(?:[A-Za-z_][A-Za-z0-9_]*|\.\.\.))*)?\))?(?:=.*)?")
_UNDEFINE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WARNING = re.compile(r"-W(?:[a-z][a-z0-9-]*)(?:=(?:[a-z][a-z0-9-]*|[0-9]+))?")
_OPTIMIZATION = re.compile(r"-O(?:[0-3sgz]|fast)?")
_DEBUG = re.compile(r"-g(?:[0-3]|gdb[0-3]?)?")
_SIMPLE = frozenset({
    "-ansi", "-pedantic", "-pedantic-errors", "-pthread", "-m32", "-m64",
    "-fPIC", "-fpic", "-fPIE", "-fpie", "-fno-pic", "-fno-pie",
    "-fexceptions", "-fno-exceptions", "-frtti", "-fno-rtti",
    "-fsigned-char", "-funsigned-char", "-fshort-wchar", "-fshort-enums",
    "-fchar8_t", "-fno-char8_t", "-fchar8-type", "-fno-char8-type",
    "-fms-extensions", "-fms-compatibility", "-fno-ms-extensions", "-fno-ms-compatibility",
    "-fstrict-aliasing", "-fno-strict-aliasing", "-fwrapv", "-fno-wrapv",
    "-fno-strict-overflow", "-fno-builtin",
})


def _text(value: str) -> None:
    if (not isinstance(value, str) or not value or len(value) > 8192
            or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF
                   for char in value)):
        raise UnsafeCompile("compiler argument is empty, oversized or contains control characters")


def _relative(value: str, *, directory: bool = False) -> str:
    _text(value)
    if directory and value == ".":
        return value
    parts = value.split("/")
    if (value.startswith(("/", "-", "@")) or "\\" in value or ":" in value
            or any(part in {"", ".", ".."} for part in parts)):
        raise UnsafeCompile("source and working directory must be canonical workspace-relative paths")
    return value


def _workspace_path(value: str, working_directory: str) -> str:
    """Resolve container paths lexically; the caller separately verifies filesystem provenance."""
    _text(value)
    if value.startswith(("-", "@", "=")) or "\\" in value or ":" in value or "//" in value:
        raise UnsafeCompile("compiler path is not a workspace path")
    if value == "/workspace" or value.startswith("/workspace/"):
        parts: list[str] = []
        components = value[len("/workspace"):].split("/")
    elif value.startswith("/"):
        raise UnsafeCompile("compiler path is outside the workspace")
    else:
        parts = [] if working_directory == "." else working_directory.split("/")
        components = value.split("/")
    for component in components:
        if component in {"", "."}:
            continue
        if component == "..":
            if not parts:
                raise UnsafeCompile("compiler path escapes the workspace")
            parts.pop()
        else:
            parts.append(component)
    return "/workspace" + ("/" + "/".join(parts) if parts else "")


def compile_argv(build: BuildUnit) -> tuple[str, ...]:
    """Derive a single syntax check, refusing unclassified or executable-tool-loading options.

    Clang's implicit driver configurations are explicitly disabled. GCC has no equivalent
    target-owned default driver config: explicit specs, plugin and tool-search flags are all
    refused, rather than passing an unsupported ``-fno-plugins`` option.
    """
    command = build.command
    if not isinstance(build.image_id, str) or not _IMAGE.fullmatch(build.image_id):
        raise UnsafeCompile("native replay requires an immutable accepted image id")
    argv = command.argv
    if (not isinstance(argv, (tuple, list)) or not argv or len(argv) > 1024
            or any(not isinstance(item, str) for item in argv)):
        raise UnsafeCompile("accepted compiler argv is invalid")
    for item in argv:
        _text(item)
    if sum(map(len, argv)) > 65536:
        raise UnsafeCompile("accepted compiler argv exceeds the replay bound")
    if argv[0] not in _COMPILERS:
        raise UnsafeCompile("compiler is not an allowed absolute native compiler")
    source = _relative(command.source)
    working_directory = _relative(command.working_directory, directory=True)
    if (command.language not in {"c", "cxx"}
            or _LANGUAGES.get(PurePosixPath(source).suffix) != command.language):
        raise UnsafeCompile("accepted source is not a matching C or C++ translation unit")
    expected_source = "/workspace/" + source
    kept: list[str] = []
    seen_source = False
    index = 1
    while index < len(argv):
        item = argv[index]
        if item.startswith("@"):
            raise UnsafeCompile("response files are not replayed")
        if item in _DISCARD:
            index += 1
            continue
        if item == "--no-default-config" and argv[0] in {"/usr/bin/clang", "/usr/bin/clang++"}:
            index += 1
            continue
        prefix = next((flag for flag in (*_INCLUDES, *_OUTPUTS, "-D", "-U", "-x")
                       if item.startswith(flag)), None)
        if prefix is not None:
            paired = item == prefix
            if paired and index + 1 == len(argv):
                raise UnsafeCompile("compiler option lacks its argument")
            value = argv[index + 1] if paired else item[len(prefix):]
            _text(value)
            if prefix in _INCLUDES:
                value = _workspace_path(value, working_directory)
            elif prefix in _OUTPUTS:
                if _workspace_path(value, working_directory) == expected_source:
                    raise UnsafeCompile("compiler output would overwrite the accepted source")
                index += 2 if paired else 1
                continue
            elif prefix in {"-D", "-U"}:
                pattern = _DEFINE if prefix == "-D" else _UNDEFINE
                if len(value) > 4096 or not pattern.fullmatch(value):
                    raise UnsafeCompile("compiler macro is not a bounded definition or identifier")
            elif value != ("c" if command.language == "c" else "c++"):
                raise UnsafeCompile("compiler language override differs from the accepted source")
            kept.extend((prefix, value) if paired else (prefix + value,))
            index += 2 if paired else 1
            continue
        if not item.startswith("-"):
            if seen_source or _workspace_path(item, working_directory) != expected_source:
                raise UnsafeCompile("compiler command contains an unexpected input")
            seen_source = True
        elif (item in _SIMPLE or _STANDARD.fullmatch(item) or _OPTIMIZATION.fullmatch(item)
              or _DEBUG.fullmatch(item)
              or (_WARNING.fullmatch(item) and item not in {"-Wa", "-Wp", "-Wl"})):
            kept.append(item)
        else:
            raise UnsafeCompile("compiler option is not allowlisted for syntax-only replay")
        index += 1
    if not seen_source:
        raise UnsafeCompile("compiler command does not name its accepted source")
    guards = ("--no-default-config",) if argv[0] in {"/usr/bin/clang", "/usr/bin/clang++"} else ()
    return (argv[0], "-fsyntax-only", *guards, *kept, expected_source)


def _excerpt(data: bytes, limit: int) -> str:
    # Replacement characters must not expand an invalid UTF-8 byte stream past the byte bound.
    return data[:limit].decode("utf-8", "replace").encode("utf-8")[:limit].decode("utf-8", "ignore")


def _record(exit_code: int | None, timed_out: bool, stdout: bytes, stderr: bytes,
            limit: int) -> dict[str, Any]:
    return {
        "exit_code": exit_code, "timed_out": timed_out,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout": _excerpt(stdout, limit), "stderr": _excerpt(stderr, limit),
    }


def _timeout_bytes(value: bytes | str | None) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value or b""


def compare_build(build: BuildUnit, baseline: Path, patched: Path, executor: Any, *,
                  output_bytes: int) -> dict[str, Any]:
    """Check baseline first, then the patch, without treating a broken baseline as success.

    Hashes cover the executor-returned diagnostic streams before display truncation; the caller
    retains those streams as protected artifacts. Unexpected/programming and integrity failures
    propagate rather than being recast as an ordinary unavailable compiler.
    """
    if type(output_bytes) is not int or output_bytes < 0:
        raise ValueError("output_bytes must be a nonnegative integer")
    result: dict[str, Any] = {
        "status": "unsafe", "reason": "",
        "tool": {"image_id": build.image_id, "compiler": None, "command_sha256": None},
        "baseline": None, "patched": None,
    }
    try:
        argv = compile_argv(build)
    except UnsafeCompile as exc:
        result["reason"] = str(exc)
        return result
    result["tool"].update(compiler=argv[0],
                          command_sha256=hashlib.sha256(canonical_json(list(argv))).hexdigest())
    try:
        executor.resolve()
    except IntegrityError:
        raise
    except (RuntimeError, OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        result.update(status="unavailable", reason=f"compiler image unavailable ({type(exc).__name__})")
        return result
    for name, workspace in (("baseline", baseline), ("patched", patched)):
        try:
            outcome = executor.execute(argv, workspace=workspace,
                                       working_directory=build.command.working_directory, environment={})
            record = _record(outcome.exit_code, bool(outcome.timed_out), outcome.stdout, outcome.stderr,
                             output_bytes)
        except IntegrityError:
            raise
        except subprocess.TimeoutExpired as exc:
            record = _record(None, True, _timeout_bytes(exc.stdout), _timeout_bytes(exc.stderr), output_bytes)
        except TimeoutError:
            record = _record(None, True, b"", b"", output_bytes)
        except (RuntimeError, OSError) as exc:
            result.update(status="unavailable", reason=f"{name} compiler unavailable ({type(exc).__name__})")
            return result
        result[name] = record
        if record["timed_out"] or record["exit_code"] != 0:
            result.update(status=f"{name}_failed", reason=f"{name} syntax-only compile did not succeed")
            return result
    result.update(status="passed", reason="baseline and patched syntax-only compile checks passed")
    return result


__all__ = ["UnsafeCompile", "compare_build", "compile_argv"]
