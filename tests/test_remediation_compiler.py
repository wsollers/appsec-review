from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime.build_executor import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.job_poc_generation.buildctx import BuildUnit, CompileCommand
from appsec_review.jobs.job_remediation_validation.compiler import UnsafeCompile, compare_build, compile_argv
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json


IMAGE_ID = "sha256:" + "a" * 64


def build_unit(*args: str, compiler: str = "/usr/bin/clang", source: str = "src/main.c",
               working_directory: str = ".", language: str = "c") -> BuildUnit:
    command = CompileCommand((compiler, *args), source, language, working_directory, "exact")
    return BuildUnit("native-unit", "make", ".", "receipt", Path("unused"), {source: "a" * 64},
                     "b" * 64, "build-native:local", IMAGE_ID, "10001:10001", command, (), ())


def outcome(code: int | None = 0, *, timed_out: bool = False, stdout: bytes = b"stdout",
            stderr: bytes = b"stderr") -> SimpleNamespace:
    return SimpleNamespace(exit_code=code, timed_out=timed_out, stdout=stdout, stderr=stderr)


class RecordingExecutor:
    def __init__(self, *outcomes, resolve_error: Exception | None = None):
        self.outcomes = list(outcomes) or [outcome(), outcome()]
        self.resolve_error = resolve_error
        self.calls: list[tuple] = []

    def resolve(self):
        self.calls.append(("resolve",))
        if self.resolve_error is not None:
            raise self.resolve_error

    def execute(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        result = self.outcomes.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.mark.parametrize("compiler", ["/usr/bin/clang", "/usr/bin/clang++", "/usr/bin/gcc", "/usr/bin/g++"])
def test_replay_is_one_absolute_compiler_and_one_accepted_source(compiler):
    build = build_unit("-c", "/workspace/src/main.c", "-o", "main.o", compiler=compiler)
    guards = ("--no-default-config",) if "clang" in compiler else ()
    assert compile_argv(build) == (compiler, "-fsyntax-only", *guards, "/workspace/src/main.c")


def test_preserves_only_classified_flags_and_normalizes_workspace_includes():
    build = build_unit("-I/workspace/include", "-I", "../include", "-iquote", ".",
                       "-isystem../vendor", "-idirafter", "/workspace/late",
                       "-D", "VALUE=1", "-UMACRO", '-DTEXT="$(touch marker); -Xclang -load"',
                       "-DF(x,y)=((x)+(y))", "-std=c11", "-O2", "-Wall", "-Wno-unused-parameter",
                       "-Werror=implicit-function-declaration", "-Wframe-larger-than=512", "-pedantic",
                       "-g3", "-fPIC", "-fno-strict-aliasing", "-x", "c",
                       "-c", "../src/main.c", working_directory="build")
    assert compile_argv(build) == (
        "/usr/bin/clang", "-fsyntax-only", "--no-default-config",
        "-I/workspace/include", "-I", "/workspace/include", "-iquote", "/workspace/build",
        "-isystem/workspace/vendor", "-idirafter", "/workspace/late", "-D", "VALUE=1", "-UMACRO",
        '-DTEXT="$(touch marker); -Xclang -load"', "-DF(x,y)=((x)+(y))", "-std=c11", "-O2",
        "-Wall", "-Wno-unused-parameter", "-Werror=implicit-function-declaration",
        "-Wframe-larger-than=512", "-pedantic", "-g3", "-fPIC", "-fno-strict-aliasing", "-x", "c",
        "/workspace/src/main.c",
    )


def test_strips_both_separate_and_attached_outputs_and_dependencies():
    build = build_unit("-c", "src/main.c", "-o/workspace/build/main.o", "-MD", "-MMD", "-MP",
                       "-MF", "build/main.d", "-MTbuild/main.o", "-MQ", "build/main.o",
                       "-MJbuild/command.json", "-fsyntax-only", "--no-default-config")
    assert compile_argv(build) == (
        "/usr/bin/clang", "-fsyntax-only", "--no-default-config", "/workspace/src/main.c")


@pytest.mark.parametrize("source,language,standard", [
    ("src/a.cpp", "cxx", "c++20"), ("src/a.c++", "cxx", "gnu++2b"), ("src/a.c", "c", "gnu11"),
])
def test_matches_supported_source_and_language(source, language, standard):
    build = build_unit("-std=" + standard, "-c", source, source=source, language=language)
    assert compile_argv(build)[-2:] == ("-std=" + standard, "/workspace/" + source)


@pytest.mark.parametrize("compiler", [
    "clang", "gcc", "cc", "c++", "/bin/clang", "/workspace/clang", "/usr/bin/clang-18",
    "/usr/bin/../bin/clang", "make", "cmake", "ninja", "sh", "bash", "python3",
])
def test_refuses_shells_build_systems_wrappers_and_unpinned_compiler_paths(compiler):
    with pytest.raises(UnsafeCompile):
        compile_argv(build_unit("-c", "src/main.c", compiler=compiler))


@pytest.mark.parametrize("image", ["", "build:latest", "sha256:abc", "sha256:" + "A" * 64,
                                   "sha256:" + "a" * 63, IMAGE_ID + "\n"])
def test_refuses_mutable_or_malformed_image_identity(image):
    with pytest.raises(UnsafeCompile):
        compile_argv(replace(build_unit("-c", "src/main.c"), image_id=image))


@pytest.mark.parametrize("flags", [
    ("@options.rsp",), ("@/workspace/options.rsp",), ("-Xclang", "-load", "/workspace/plugin.so"),
    ("-Xpreprocessor", "-include", "/workspace/config.h"), ("-B", "/workspace/bin"),
    ("-B/workspace/bin",), ("-specs=/workspace/specs",), ("--specs=/workspace/specs",),
    ("-fplugin=/workspace/plugin.so",), ("-fplugin-arg-test-key=value",),
    ("-fpass-plugin=/workspace/plugin.so",), ("-load", "/workspace/plugin.so"),
    ("-plugin", "plugin"), ("-wrapper", "/workspace/driver"), ("-cc1",), ("-cc1as",),
    ("-Wp,-include,/workspace/injected.h",), ("-Wa,--help",), ("-Wl,-plugin,/workspace/plugin.so",),
    ("-Wp",), ("-Wa",), ("-Wl",), ("--config=/workspace/clang.cfg",),
    ("--config-system-dir=/workspace",), ("--config-user-dir=/workspace",),
    ("-resource-dir=/workspace",), ("--gcc-toolchain=/workspace",),
    ("--sysroot=/workspace",), ("-isysroot", "/workspace"), ("-I-",),
    ("-include", "config.h"), ("-imacros", "config.h"), ("-include-pch", "config.pch"),
    ("-ivfsoverlay", "vfs.yaml"), ("-fmodules",), ("-fmodules-ts",),
    ("-fmodule-file=/workspace/module.pcm",), ("-fmodule-mapper=|/workspace/mapper",),
    ("-flto",), ("-fprofile-use",), ("-fprofile-instr-generate",),
    ("-ftime-trace",), ("-fdiagnostics-file=/workspace/diagnostics",), ("-save-temps",),
    ("-dumpdir", "/workspace"), ("-aux-info", "aux"), ("-S",), ("-E",),
    ("-lfoo",), ("-L/workspace/lib",), ("-shared",), ("-Wunknown=/workspace/file",),
    ("-std=@options.rsp",), ("-O2;touch marker",), ("-march=native",), ("--",),
])
def test_refuses_tool_loading_preprocessor_forwarding_writes_and_unknown_flags(flags):
    with pytest.raises(UnsafeCompile):
        compile_argv(build_unit(*flags, "-c", "src/main.c"))


@pytest.mark.parametrize("flags", [
    ("-I/etc",), ("-I", "/workspace-evil/include"), ("-iquote", "/workspace/../../etc"),
    ("-isystem", "../../etc"), ("-idirafter", "\\workspace\\include"),
    ("-I", "C:\\includes"), ("-I", "@options.rsp"), ("-I", "=/usr/include"),
    ("-I", "//workspace/include"), ("-o", "/outside/object.o"),
    ("-o", "../escape.o"), ("-MF", "/outside/deps"), ("-MF../../escape",),
    ("-MT", "/outside/target"), ("-MQ", "@/workspace/response"), ("-o", "/workspace/src/main.c"),
    ("-o", "-c"), ("-D", "@response"), ("-D", "BAD NAME=1"), ("-U", "MACRO=1"),
    ("-x", "assembler-with-cpp"), ("-x", "c++"), ("-DVALUE=x\n-o file",),
    ("-DVALUE=\0",), ("-DVALUE=" + "a" * 4097,), ("-I" + "a" * 8193,),
])
def test_refuses_escaping_paths_malformed_macros_and_language_overrides(flags):
    with pytest.raises(UnsafeCompile):
        compile_argv(build_unit(*flags, "-c", "src/main.c"))


@pytest.mark.parametrize("flag", ["-I", "-isystem", "-iquote", "-idirafter", "-D", "-U",
                                 "-x", "-o", "-MF", "-MT", "-MQ", "-MJ"])
def test_refuses_missing_option_values(flag):
    with pytest.raises(UnsafeCompile):
        compile_argv(build_unit("-c", "src/main.c", flag))


@pytest.mark.parametrize("inputs", [
    (), ("src/different.c",), ("/outside/main.c",), ("../src/main.c",),
    ("src/main.c", "other.c"), ("src/main.c", "src/main.c"), ("src/main.c", "object.o"),
    ("src/main.c", "/workspace/src/other.c"), ("@src/main.c",),
])
def test_refuses_missing_mismatched_and_extra_compiler_inputs(inputs):
    with pytest.raises(UnsafeCompile):
        compile_argv(build_unit("-c", *inputs))


@pytest.mark.parametrize("field,value", [
    ("source", "/workspace/src/main.c"), ("source", "../main.c"), ("source", "src/../main.c"),
    ("source", "src\\main.c"), ("source", "src/main.h"), ("source", "src//main.c"),
    ("source", "-main.c"), ("working_directory", "/workspace"), ("working_directory", "../build"),
    ("working_directory", "build/.."), ("working_directory", "build\\nested"),
    ("language", "assembler"), ("language", None),
])
def test_refuses_unsafe_or_inconsistent_source_metadata(field, value):
    build = build_unit("-c", "src/main.c")
    with pytest.raises(UnsafeCompile):
        compile_argv(replace(build, command=replace(build.command, **{field: value})))


def test_refuses_argument_count_and_total_length_overruns():
    for flags in (("-Wall",) * 1024, ("-DVALUE=" + "a" * 4000,) * 20):
        with pytest.raises(UnsafeCompile):
            compile_argv(build_unit(*flags, "-c", "src/main.c"))


def test_compare_records_identical_baseline_first_commands_and_bounded_protected_diagnostics(tmp_path):
    build = build_unit("-Iinclude", "-c", "../src/main.c", working_directory="build")
    stdout = b"A" * 32
    stderr = b"\xff" * 32
    executor = RecordingExecutor(outcome(stdout=stdout, stderr=stderr), outcome())
    baseline, patched = tmp_path / "baseline", tmp_path / "patched"
    result = compare_build(build, baseline, patched, executor, output_bytes=8)
    assert result["status"] == "passed"
    assert set(result) == {"status", "reason", "tool", "baseline", "patched"}
    argv = compile_argv(build)
    assert executor.calls == [
        ("resolve",),
        (argv, {"workspace": baseline, "working_directory": "build", "environment": {}}),
        (argv, {"workspace": patched, "working_directory": "build", "environment": {}}),
    ]
    assert result["tool"] == {
        "compiler": "/usr/bin/clang", "image_id": IMAGE_ID,
        "command_sha256": hashlib.sha256(canonical_json(list(argv))).hexdigest(),
    }
    assert result["baseline"] == {
        "exit_code": 0, "timed_out": False, "stdout": "A" * 8, "stderr": "\ufffd" * 2,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    assert len(result["baseline"]["stderr"].encode()) <= 8
    assert not (tmp_path / "marker").exists()


@pytest.mark.parametrize("failed", [outcome(1), outcome(None), outcome(0, timed_out=True),
                                    outcome(None, timed_out=True)])
def test_baseline_failure_is_never_success_and_never_runs_patch(tmp_path, failed):
    executor = RecordingExecutor(failed)
    result = compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=32)
    assert result["status"] == "baseline_failed"
    assert result["baseline"]["exit_code"] == failed.exit_code
    assert result["patched"] is None
    assert len(executor.calls) == 2


@pytest.mark.parametrize("failed", [outcome(2), outcome(None), outcome(0, timed_out=True)])
def test_patched_failure_is_not_relabelled_as_baseline_or_success(tmp_path, failed):
    executor = RecordingExecutor(outcome(), failed)
    result = compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=32)
    assert result["status"] == "patched_failed"
    assert result["baseline"]["exit_code"] == 0
    assert result["patched"]["exit_code"] == failed.exit_code
    assert len(executor.calls) == 3


def test_unsafe_compile_never_resolves_or_executes_an_image(tmp_path):
    executor = RecordingExecutor()
    result = compare_build(build_unit("-fplugin=evil", "-c", "src/main.c"),
                           tmp_path, tmp_path, executor, output_bytes=32)
    assert result["status"] == "unsafe"
    assert result["baseline"] is result["patched"] is None
    assert executor.calls == []


@pytest.mark.parametrize("error", [RuntimeError("unavailable"), OSError("unavailable"), TimeoutError(),
                                   subprocess.TimeoutExpired("inspect", 10)])
def test_resolve_availability_errors_are_explicit(tmp_path, error):
    executor = RecordingExecutor(resolve_error=error)
    result = compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=32)
    assert result["status"] == "unavailable"
    assert result["baseline"] is result["patched"] is None
    assert executor.calls == [("resolve",)]


@pytest.mark.parametrize("stage", ["baseline", "patched"])
@pytest.mark.parametrize("error", [RuntimeError("unavailable"), OSError("unavailable")])
def test_execute_availability_errors_preserve_completed_baseline(tmp_path, error, stage):
    executor = RecordingExecutor(*([outcome()] if stage == "patched" else []), error)
    result = compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=32)
    assert result["status"] == "unavailable"
    assert (result["baseline"] is not None) == (stage == "patched")
    assert result["patched"] is None


@pytest.mark.parametrize("stage", ["baseline", "patched"])
@pytest.mark.parametrize("error", [
    TimeoutError(), subprocess.TimeoutExpired("compiler", 10, output=b"partial", stderr=b"timeout"),
])
def test_execute_timeout_is_a_failed_check_with_partial_diagnostics(tmp_path, error, stage):
    executor = RecordingExecutor(*([outcome()] if stage == "patched" else []), error)
    result = compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=32)
    assert result["status"] == stage + "_failed"
    assert result[stage]["timed_out"] is True
    assert result[stage]["exit_code"] is None
    if isinstance(error, subprocess.TimeoutExpired):
        assert result[stage]["stdout"] == "partial"
        assert result[stage]["stderr_sha256"] == hashlib.sha256(b"timeout").hexdigest()


@pytest.mark.parametrize("stage", ["resolve", "baseline", "patched"])
@pytest.mark.parametrize("error", [IntegrityError("tampered"), ValueError("configuration error"),
                                   TypeError("programming error")])
def test_integrity_configuration_and_programming_errors_are_not_swallowed(tmp_path, stage, error):
    executor = (RecordingExecutor(resolve_error=error) if stage == "resolve"
                else RecordingExecutor(*([outcome()] if stage == "patched" else []), error))
    with pytest.raises(type(error), match=str(error)):
        compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=32)


def test_zero_diagnostic_limit_keeps_hashes_and_no_text(tmp_path):
    result = compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path,
                           RecordingExecutor(), output_bytes=0)
    assert result["baseline"]["stdout"] == result["baseline"]["stderr"] == ""
    assert result["baseline"]["stdout_sha256"] == hashlib.sha256(b"stdout").hexdigest()


@pytest.mark.parametrize("limit", [-1, True, "32"])
def test_invalid_output_limit_fails_before_executor_activity(tmp_path, limit):
    executor = RecordingExecutor()
    with pytest.raises(ValueError):
        compare_build(build_unit("-c", "src/main.c"), tmp_path, tmp_path, executor, output_bytes=limit)
    assert executor.calls == []


def test_production_executor_docker_argv_has_no_shell_linker_runtime_or_output(tmp_path):
    calls = []

    def runner(argv, timeout):
        calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, IMAGE_ID.encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        return 0, b"checked", b"", False

    baseline, patched = tmp_path / "baseline", tmp_path / "patched"
    for workspace in (baseline, patched):
        (workspace / "build").mkdir(parents=True)
    profile = BuildProfile("native", "build-native:local", IMAGE_ID, "10001:10001")
    executor = BuildContainerExecutor(profile, timeout_seconds=30, output_bytes=64, runner=runner,
                                      network="none")
    build = build_unit("-DNAME=$(touch marker)", "-c", "../src/main.c", "-o", "main.o",
                       working_directory="build")
    result = compare_build(build, baseline, patched, executor, output_bytes=64)
    assert result["status"] == "passed"
    commands = [argv for argv in calls if argv[:2] == ("docker", "run")]
    assert len(commands) == 2
    for command in commands:
        assert command[command.index("--entrypoint") + 1:] == (
            "/usr/bin/clang", IMAGE_ID, "-fsyntax-only", "--no-default-config",
            "-DNAME=$(touch marker)", "/workspace/src/main.c",
        )
        assert command[command.index("--network") + 1] == "none"
        assert command[command.index("--workdir") + 1] == "/workspace/build"
        assert "--read-only" in command
        assert "--cap-drop" in command and "no-new-privileges" in command
        assert not {"sh", "bash", "make", "cmake", "ninja", "ld", "-c", "-o"} & set(command)
        assert not any(token.startswith(("LD_PRELOAD=", "GCC_EXEC_PREFIX=", "COMPILER_PATH="))
                       for token in command)
    assert str(baseline) in commands[0][commands[0].index("--mount") + 1]
    assert str(patched) in commands[1][commands[1].index("--mount") + 1]
    assert not any(workspace.joinpath("build", "marker").exists() for workspace in (baseline, patched))
