"""Code-level unit tests for ``job_sanitizer_build.settings`` and ``evidence``."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tomllib

import pytest

from appsec_review.jobs.job_language_build import elf
from appsec_review.jobs.job_sanitizer_build import JOB_ID, build_job
from appsec_review.jobs.job_sanitizer_build.evidence import (
    any_referenced,
    referenced,
    runtime_evidence,
)
from appsec_review.jobs.job_sanitizer_build.settings import (
    SanitizerBuildSettings,
    argument_conflicts,
    instrumented_environment,
)
from tests.sanitizer_support import ET_REL, elf_with_symbols, instrumented_elf


ROOT = Path(__file__).resolve().parents[3]
SETTINGS = {
    "enabled": True,
    "workers": 1,
    "sanitizers": ["address", "undefined"],
    "extra_flags": ["-fno-omit-frame-pointer", "-g", "-O1"],
    "required_evidence": ["address"],
    "build_systems": ["cmake", "autotools", "meson", "make"],
    "build_environment": {"ASAN_OPTIONS": "detect_leaks=0"},
    "command_timeout_seconds": 60,
    "output_bytes": 1_000_000,
    "artifact_count_limit": 100,
    "max_units": 4,
}


def _settings(**overrides) -> SanitizerBuildSettings:
    return SanitizerBuildSettings.from_mapping({**deepcopy(SETTINGS), **overrides})


def test_shipped_configuration_is_valid_and_declares_the_job() -> None:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    job = document["jobs"][JOB_ID]
    settings = SanitizerBuildSettings.from_mapping(job["settings"])
    assert settings.enabled and settings.sanitizers == ("address", "undefined")
    assert settings.flags == ("-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1")
    assert settings.identity()["required_evidence"] == list(settings.required_evidence)
    assert tuple(job["steps"]) == ("load", "build", "acceptance")
    assert {unit.unit_id for unit in build_job().units} == {
        "load.accepted_native",
        "build.units",
        "acceptance.publish_handoff",
    }


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"enabled": "yes"}, "enabled must be a boolean"),
        ({"workers": 0}, "workers must be a positive integer"),
        ({"max_units": True}, "max_units must be a positive integer"),
        ({"sanitizers": []}, "sanitizers must be a non-empty"),
        ({"sanitizers": ["address", "thread"]}, "sanitizers must be a non-empty"),
        ({"sanitizers": ["address", "address"]}, "sanitizers must be a non-empty"),
        ({"sanitizers": ["address"], "required_evidence": ["undefined"]}, "subset of sanitizers"),
        ({"build_systems": ["gradle"]}, "build_systems must be a non-empty"),
        ({"extra_flags": ["-fno-sanitize=address"]}, "extra_flags"),
        ({"extra_flags": ["-g -O0"]}, "extra_flags"),
        ({"build_environment": "bad"}, "build_environment must be a bounded table"),
        ({"build_environment": {f"K{i}": "v" for i in range(17)}}, "build_environment must be a bounded table"),
        ({"build_environment": {"CXXFLAGS": "-O0"}}, "build_environment entry is invalid"),
        ({"build_environment": {"API_TOKEN": "x"}}, "build_environment entry is invalid"),
        ({"build_environment": {"lower": "x"}}, "build_environment entry is invalid"),
        ({"build_environment": {"OK_KEY": "a\x00b"}}, "build_environment entry is invalid"),
    ],
    ids=[
        "enabled-str",
        "workers-zero",
        "max-units-bool",
        "sanitizers-empty",
        "sanitizers-thread",
        "sanitizers-dup",
        "required-not-subset",
        "build-systems-gradle",
        "extra-flags-sanitize",
        "extra-flags-space",
        "env-not-mapping",
        "env-too-many",
        "env-cxxflags",
        "env-secret-key",
        "env-lowercase",
        "env-nul-byte",
    ],
)
def test_invalid_settings_are_rejected(override, message) -> None:
    with pytest.raises(ValueError, match=message):
        _settings(**override)


def test_unknown_and_missing_settings_are_rejected() -> None:
    with pytest.raises(ValueError, match="exactly its documented keys"):
        SanitizerBuildSettings.from_mapping("not-a-mapping")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exactly its documented keys"):
        SanitizerBuildSettings.from_mapping({**SETTINGS, "surprise": 1})
    with pytest.raises(ValueError, match="exactly its documented keys"):
        SanitizerBuildSettings.from_mapping({key: value for key, value in SETTINGS.items() if key != "workers"})


def test_single_sanitizer_configuration_changes_the_flags() -> None:
    settings = _settings(sanitizers=["address"], required_evidence=["address"], extra_flags=[])
    assert settings.flags == ("-fsanitize=address",)


def test_environment_places_sanitizer_flags_first_and_keeps_recipe_flags() -> None:
    environment, conflicts = instrumented_environment(
        _settings(), {"CFLAGS": "-Wall", "ASAN_OPTIONS": "detect_leaks=0", "OTHER": "kept"}
    )
    flags = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    assert conflicts == []
    assert environment["CFLAGS"] == f"{flags} -Wall"
    assert environment["CXXFLAGS"] == environment["LDFLAGS"] == flags
    assert environment["ASAN_OPTIONS"] == "detect_leaks=0" and environment["OTHER"] == "kept"


@pytest.mark.parametrize(
    "recorded",
    [
        {"CXXFLAGS": "-fsanitize=thread"},
        {"LDFLAGS": "-fno-sanitize=undefined"},
        {"ASAN_OPTIONS": "detect_leaks=1"},
    ],
    ids=["cxxflags-sanitize", "ldflags-fno-sanitize", "asan-options-conflict"],
)
def test_recipe_environment_that_contradicts_the_flags_is_a_conflict(recorded) -> None:
    _environment, conflicts = instrumented_environment(_settings(), recorded)
    assert len(conflicts) == 1


@pytest.mark.parametrize(
    "argv",
    [
        ["cmake", "-S", ".", "-B", "build", "-DCMAKE_CXX_FLAGS=-O0"],
        ["cmake", "-S", ".", "-DCMAKE_C_FLAGS:STRING=-O0"],
        ["cmake", "-DCMAKE_EXE_LINKER_FLAGS=-static"],
        ["cmake", "-DCMAKE_CXX_FLAGS=-fsanitize=thread"],
        ["make", "CXXFLAGS=-O3"],
        ["./configure", "CFLAGS=-g"],
        ["meson", "setup", "build", "-Db_sanitize=thread"],
        ["meson", "setup", "build", "-Dc_args=-O0"],
        ["gcc", "-fsanitize=address", "-c", "x.c"],
    ],
    ids=[
        "cmake-cxx",
        "cmake-c-typed",
        "cmake-linker",
        "cmake-sanitize",
        "make-cxxflags",
        "configure-cflags",
        "meson-sanitize",
        "meson-c-args",
        "gcc-fsanitize",
    ],
)
def test_command_lines_that_mask_the_environment_flags_are_conflicts(argv) -> None:
    assert len(argument_conflicts([["true"], argv])) == 1


@pytest.mark.parametrize(("assignment", "conflicting"), [
    ("CMAKE_CXX_FLAGS:STRING=-O0 -Wall", True),
    ("CMAKE_EXE_LINKER_FLAGS=-static", True),
    ("CMAKE_C_FLAGS=-fno-sanitize=address", True),
    ("CMAKE_BUILD_TYPE=RelWithDebInfo", False),
    ("CMAKE_CXX_FLAGS_DEBUG=-O0", False),
    ("FEATURE_LABEL=CMAKE_CXX_FLAGS=-O0", False),
], ids=["typed-compiler", "linker", "sanitizer", "build-type", "debug-flags", "ordinary-value"])
def test_split_cmake_definitions_match_joined_policy_without_mutating_argv(assignment, conflicting) -> None:
    prefix = ["/usr/bin/cmake", "-S", ".", "-B", "build"]
    split, joined = [*prefix, "-D", assignment], [*prefix, "-D" + assignment]
    original = deepcopy(split)
    expected = argument_conflicts([["make", "-j2"], joined])
    assert bool(expected) == conflicting
    assert argument_conflicts([["make", "-j2"], split]) == expected
    assert split == original
    if conflicting:
        assert expected[0].startswith("command 2 ")


@pytest.mark.parametrize(
    "argv",
    [
        ["cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
        ["cmake", "-DCMAKE_CXX_FLAGS_DEBUG=-O0"],
        ["cmake", "--build", "build", "--parallel", "2"],
        ["make", "-j2"],
    ],
    ids=["cmake-config", "cmake-debug-flags", "cmake-build", "make-j2"],
)
def test_ordinary_command_lines_are_not_conflicts(argv) -> None:
    assert argument_conflicts([argv]) == []


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_symbol_reader_separates_defined_and_undefined_names(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "x.o",
        elf_with_symbols(ET_REL, defined=("main", "__asan_runtime_probe"), undefined=("__asan_init", "puts")),
    )
    facts = elf.symbol_names(path, ("__asan_",))
    assert facts["tables"] == [".symtab"]
    assert facts["defined"] == ["__asan_runtime_probe"] and facts["undefined"] == ["__asan_init"]


def test_instrumented_and_plain_objects_are_told_apart(tmp_path: Path) -> None:
    on = runtime_evidence(_write(tmp_path, "on.o", instrumented_elf(ET_REL)), "object")
    off = runtime_evidence(_write(tmp_path, "off.o", elf_with_symbols(ET_REL, undefined=("puts",))), "object")
    assert on["evidence_status"] == off["evidence_status"] == "resolved"
    assert on["sanitizers"]["address"]["runtime_referenced"] is True
    assert on["sanitizers"]["address"]["imports_runtime"] is True
    assert "__asan_init" in on["sanitizers"]["address"]["symbols"]
    assert on["sanitizers"]["undefined"]["runtime_referenced"] is True
    assert referenced(on, ("address", "undefined")) is True
    assert any_referenced(on) is True
    assert off["sanitizers"]["address"]["runtime_referenced"] is False
    assert off["sanitizers"]["undefined"]["runtime_referenced"] is False
    assert referenced(off, ("address",)) is False
    assert any_referenced(off) is False


def test_a_stripped_or_malformed_file_proves_nothing_either_way(tmp_path: Path) -> None:
    stripped = runtime_evidence(_write(tmp_path, "s", instrumented_elf(symbol_tables=False)), "executable")
    assert stripped["evidence_status"] == "no_symbol_tables"
    assert stripped["sanitizers"]["address"]["runtime_referenced"] is False
    broken = runtime_evidence(_write(tmp_path, "b", b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 20), "executable")
    assert broken["evidence_status"] == "unparsed" and "error" in broken
    assert runtime_evidence(tmp_path / "libx.a", "static-library")["evidence_status"] == "not_inspected"


def test_a_named_sanitizer_runtime_library_counts_as_linked(tmp_path: Path, monkeypatch) -> None:
    path = _write(tmp_path, "app", elf_with_symbols(undefined=("puts",)))
    monkeypatch.setattr(elf, "loader_facts", lambda _path: {"needed": ["libasan.so.8", "libc.so.6"]})
    evidence = runtime_evidence(path, "executable")
    assert evidence["sanitizers"]["address"]["runtime_libraries"] == ["libasan.so.8"]
    assert evidence["sanitizers"]["address"]["runtime_referenced"] is True
    assert evidence["sanitizers"]["undefined"]["runtime_referenced"] is False
