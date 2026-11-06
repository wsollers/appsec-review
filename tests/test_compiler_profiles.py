from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from appsec_review.container_runtime import compiler_profiles as cp
from appsec_review.container_runtime.build_executor import BuildProfile
from appsec_review.container_runtime.native_commands import NativeRun, parse_native_command
from appsec_review.signing.core import SignatureVerificationError
from appsec_review.signing.images import DisabledImageVerifier

# Explicitly synthetic transcripts shaped like the default builder images. Recorded probe output
# from real images replaces them once a probe has been run against the pinned images.
IMAGE = "sha256:" + "a" * 64
OTHER_IMAGE = "sha256:" + "b" * 64

CPP = """@@collector appsec-review/compiler-probe/1
@@env CC
|clang
@@env CXX
|clang++
@@env PATH
|/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
@@tool cc
|/usr/bin/cc
@@link cc
|/usr/bin/cc
|/etc/alternatives/cc
@@link cc
|/etc/alternatives/cc
|/usr/bin/clang
@@link cc
|/usr/bin/clang
|../lib/llvm-18/bin/clang
@@real cc
|/usr/lib/llvm-18/bin/clang
@@tool clang
|/usr/bin/clang
@@link clang
|/usr/bin/clang
|../lib/llvm-18/bin/clang
@@real clang
|/usr/lib/llvm-18/bin/clang
@@tool gcc
|/usr/bin/gcc
@@link gcc
|/usr/bin/gcc
|gcc-13
@@link gcc
|/usr/bin/gcc-13
|x86_64-linux-gnu-gcc-13
@@real gcc
|/usr/bin/x86_64-linux-gnu-gcc-13
@@probe clang.dumpmachine 0
|x86_64-pc-linux-gnu
@@probe clang.version 0
|Ubuntu clang version 18.1.3 (1ubuntu1)
|Target: x86_64-pc-linux-gnu
@@probe gcc.dumpmachine 0
|x86_64-linux-gnu
@@probe gcc.version 0
|gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
@@copy clang 0
@@copy gcc 0
@@end
"""

RUST = """@@collector appsec-review/compiler-probe/1
@@env PATH
|/opt/rust/bin:/usr/bin:/bin
@@tool rustc
|/opt/rust/bin/rustc
@@real rustc
|/opt/rust/bin/rustc
@@tool cargo
|/opt/rust/bin/cargo
@@real cargo
|/opt/rust/bin/cargo
@@probe rustc.version 0
|rustc 1.90.0 (1159e78c4 2025-09-14)
|binary: rustc
|host: x86_64-unknown-linux-gnu
|release: 1.90.0
|LLVM version: 20.1.8
@@targets
|wasm32-unknown-unknown
|wasm32-wasip1
|x86_64-unknown-linux-gnu
@@probe cargo.version 0
|cargo 1.90.0 (840b83a10 2025-07-30)
@@copy rustc 0
@@copy cargo 0
@@end
"""

GO = """@@collector appsec-review/compiler-probe/1
@@env GOFLAGS
|-mod=readonly
@@tool go
|/usr/bin/go
@@link go
|/usr/bin/go
|../lib/go-1.23/bin/go
@@real go
|/usr/lib/go-1.23/bin/go
@@probe go.version 0
|go version go1.23.4 linux/amd64
@@probe go.env 0
|{
|\t"CC": "gcc",
|\t"CGO_ENABLED": "1",
|\t"CXX": "g++",
|\t"GOARCH": "amd64",
|\t"GOOS": "linux",
|\t"GOROOT": "/usr/lib/go-1.23"
|}
@@copy go 0
@@end
"""

EMPTY = "@@collector appsec-review/compiler-probe/1\n@@env PATH\n|/usr/bin:/bin\n@@end\n"


def _elf(name: str, *, machine: int = 62, e_type: int = 3, entry: int = 0x1000,
         load: bool = True) -> bytes:
    """A structurally valid, inert ELF64 little-endian image: one PT_LOAD covering its entry.

    It is never executed; its only code bytes are the driver name.
    """
    payload = name.encode() * 8
    count = 1 if load else 0
    size = 64 + 56 * count + len(payload)
    header = (b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, entry, 64, 0, 0, 64, 56, count, 64, 0, 0))
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, 0x2000, 0x1000) if load else b""
    return header + program + payload


_FORMAT = {"class": "elf64", "machine": "x86_64", "type": "dyn"}


def _executables(drivers, machine: str = "x86_64") -> dict:
    return {driver: {"sha256": hashlib.sha256(_elf(driver)).hexdigest(),
                     "format": {**_FORMAT, "machine": machine}} for driver in drivers}


def _records(text: str, image: str = IMAGE, *, machine: str = "x86_64", signature: str = "verified") -> dict:
    transcript = cp.parse_probe_transcript(text.encode())
    return cp.build_profile_records(transcript, image_digest=image,
                                    executables=_executables(transcript.copies, machine),
                                    transcript_sha256=hashlib.sha256(text.encode()).hexdigest(),
                                    image_signature=signature)


def test_cpp_image_profiles_record_closure_targets_and_environment():
    records = _records(CPP)
    assert sorted(records) == ["clang", "gcc"]
    clang = records["clang"]
    assert clang["schema"] == "appsec-review/static-compiler-profile/2"
    assert clang["executable"] == "/usr/lib/llvm-18/bin/clang"
    assert clang["invocation_names"] == ["cc", "clang"]
    assert clang["wrapper_closure"] == [{"path": "/usr/bin/clang", "target": "../lib/llvm-18/bin/clang"}]
    assert clang["driver_semantics"] == "clang-target/1"
    assert clang["default_target"] == "x86_64-pc-linux-gnu"
    assert clang["target_axes"] == {"os": "linux", "isa": "x86_64", "abi": "gnu"}
    assert clang["image_env"]["CC"] == "clang" and clang["image_env"]["CXX"] == "clang++"
    assert clang["compiler_sha256"] == hashlib.sha256(_elf("clang")).hexdigest()
    assert clang["executable_format"] == _FORMAT
    assert set(clang["probe"]["outputs"]) == {"clang.dumpmachine", "clang.version"}
    assert clang["probe"]["script_sha256"] == hashlib.sha256(cp.PROBE_SCRIPT.encode()).hexdigest()
    assert clang["provenance"] == {"origin": "image-probe/1", "collector_version": "1",
                                   "image_identity": "docker-image-id/1", "image_signature": "verified"}
    gcc = records["gcc"]
    assert gcc["invocation_names"] == ["gcc"]
    assert [hop["target"] for hop in gcc["wrapper_closure"]] == ["gcc-13", "x86_64-linux-gnu-gcc-13"]
    assert gcc["driver_semantics"] == "gcc-default/1" and gcc["default_target"] == "x86_64-linux-gnu"


def test_rust_image_profiles_list_installed_targets_for_rustc_and_cargo():
    records = _records(RUST)
    assert sorted(records) == ["cargo", "rustc"]
    for driver in ("rustc", "cargo"):
        assert records[driver]["default_target"] == "x86_64-unknown-linux-gnu"
        assert records[driver]["supported_targets"] == [
            "wasm32-unknown-unknown", "wasm32-wasip1", "x86_64-unknown-linux-gnu"]
    assert records["rustc"]["driver_facts"] == {"release": "1.90.0"}
    assert records["cargo"]["driver_semantics"] == "cargo-rustc/1"


def test_go_image_profile_reads_platform_and_cgo_from_go_env():
    go = _records(GO)["go"]
    assert go["default_target"] == "linux/amd64"
    assert go["target_axes"] == {"os": "linux", "isa": "x86_64", "abi": None}
    assert go["driver_facts"] == {"cgo_enabled": True, "cc": "gcc", "cxx": "g++", "goroot": "/usr/lib/go-1.23"}
    assert go["image_env"] == {"GOFLAGS": "-mod=readonly"}


def test_image_without_compiler_drivers_is_an_empty_probed_set():
    assert _records(EMPTY) == {}
    assert cp.profile_set(IMAGE, {}) == {"schema": cp.SET_SCHEMA, "images": {IMAGE: {}}}


@pytest.mark.parametrize("mutation,message", [
    (lambda text: text.replace("@@end\n", ""), "end marker"),
    (lambda text: text.replace("|clang\n", "clang\n", 1), "unrecognised"),
    (lambda text: text.replace("@@env CXX", "@@env CC"), "environment"),
    (lambda text: text.replace("@@env CXX", "@@env SECRET"), "unrecognised|environment"),
    (lambda text: text.replace("|/etc/alternatives/cc\n@@link cc\n|/etc/alternatives/cc",
                               "|/etc/alternatives/cc\n@@link cc\n|/etc/other"), "discontinuous"),
    (lambda text: text.replace("@@real gcc\n|/usr/bin/x86_64-linux-gnu-gcc-13\n", "@@unresolved gcc\n"),
     "could not be resolved"),
    (lambda text: text.replace("@@real clang\n|/usr/lib/llvm-18/bin/clang",
                               "@@real clang\n|/usr/lib/llvm-17/bin/clang"), "normalized symlink chain"),
    (lambda text: text.replace("@@real gcc\n|/usr/bin/x86_64-linux-gnu-gcc-13",
                               "@@real gcc\n|/usr/bin/gcc-13"), "normalized symlink chain"),
    (lambda text: text.replace("@@probe gcc.version 0\n|gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0\n",
                               "@@overflow gcc.version\n"), "exceeded its bound"),
    (lambda text: text.replace("@@probe clang.dumpmachine 0", "@@probe clang.dumpmachine 1"), "failed"),
    (lambda text: text.replace("|x86_64-pc-linux-gnu\n@@probe clang.version",
                               "|x86_64-pc-linux-gnu\n|i686-pc-linux-gnu\n@@probe clang.version"),
     "exactly one target"),
    (lambda text: text.replace("|x86_64-linux-gnu\n", "|not a triple\n"), "exactly one target"),
    (lambda text: text.replace("|x86_64-linux-gnu\n", "|mips-unknown-plan9\n"), "recognised platform"),
    (lambda text: text.replace("@@copy gcc 0\n", ""), "do not match"),
    (lambda text: text.replace("@@copy gcc 0\n", "@@copy gcc 0\n@@copy gcc 0\n"), "repeated copy"),
    (lambda text: text.replace("@@probe gcc.version 0\n|gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0\n", ""),
     "do not match"),
    (lambda text: text + "@@end\n", "end marker"),
    (lambda text: text.replace("\n", "\r\n"), "LF"),
], ids=["truncated", "bare-payload", "duplicate-env", "unknown-env", "chain-gap", "unresolved",
        "real-off-chain", "real-short-of-chain", "overflow", "probe-failed", "two-triples",
        "bad-triple", "unknown-platform", "copy-missing", "copy-repeated", "probe-missing",
        "trailing-data", "crlf"])
def test_malformed_transcripts_fail_closed(mutation, message):
    with pytest.raises(cp.CompilerProfileError, match=message):
        _records(mutation(CPP))


def test_unlinked_tool_real_path_must_equal_its_normalized_path():
    with pytest.raises(cp.CompilerProfileError, match="normalized symlink chain"):
        _records(RUST.replace("@@real cargo\n|/opt/rust/bin/cargo", "@@real cargo\n|/opt/rust/bin/rustc"))


@pytest.mark.parametrize("mutation,message", [
    (lambda text: text.replace("|host: x86_64-unknown-linux-gnu\n", ""), "host triple"),
    (lambda text: text.replace("|x86_64-unknown-linux-gnu\n@@probe cargo", "@@probe cargo"), "exclude the host"),
    (lambda text: text.replace("|binary: rustc\n", "|binary: rustc\n|binary: other\n"), "unexpected field"),
    (lambda text: text.replace("@@targets\n|wasm32-unknown-unknown\n|wasm32-wasip1\n"
                               "|x86_64-unknown-linux-gnu\n", ""), "do not match"),
    (lambda text: text.replace("@@targets\n", "@@targets\n" + "".join(
        f"|t{index}-unknown-none\n" for index in range(cp.MAX_RUST_TARGETS))), "rust target"),
], ids=["no-host", "host-not-installed", "repeated-field", "targets-missing", "too-many-targets"])
def test_malformed_rust_facts_fail_closed(mutation, message):
    with pytest.raises(cp.CompilerProfileError, match=message):
        _records(mutation(RUST))


@pytest.mark.parametrize("mutation,message", [
    (lambda text: text.replace(',\n|\t"GOROOT": "/usr/lib/go-1.23"', ""), "exactly the requested"),
    (lambda text: text.replace('"CGO_ENABLED": "1"', '"CGO_ENABLED": "yes"'), "cgo"),
    (lambda text: text.replace("|}\n", ""), "not JSON"),
    (lambda text: text.replace('|\t"GOOS": "linux",', '|\t"GOOS": "windows",\n|\t"GOOS": "linux",'),
     "repeats a key"),
    (lambda text: text.replace('"GOROOT": "/usr/lib/go-1.23"', '"GOROOT": "relative"'), "driver facts"),
], ids=["missing-key", "bad-cgo", "bad-json", "duplicate-key", "relative-goroot"])
def test_malformed_go_facts_fail_closed(mutation, message):
    with pytest.raises(cp.CompilerProfileError, match=message):
        _records(mutation(GO))


def test_transcript_size_line_and_encoding_bounds():
    with pytest.raises(cp.CompilerProfileError, match="size bound"):
        cp.parse_probe_transcript(b"|" * (cp.MAX_TRANSCRIPT_BYTES + 1))
    with pytest.raises(cp.CompilerProfileError, match="line bounds"):
        cp.parse_probe_transcript(CPP.replace("|clang\n", "|" + "c" * cp.MAX_LINE_BYTES + "\n").encode())
    with pytest.raises(cp.CompilerProfileError, match="UTF-8"):
        cp.parse_probe_transcript(CPP.encode().replace(b"|clang\n", b"|\xff\n"))


def _set(record: dict, path: tuple, value) -> dict:
    changed = copy.deepcopy(record)
    target = changed
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return changed


_TAMPERED = [
    ("compiler_sha256",), "B" * 64, ("driver_semantics",), "gcc-default/1",
    ("invocation_names",), ["clang", "cc"], ("invocation_names",), [1, "clang"],
    ("invocation_names",), [["clang"]], ("image_env",), {"SECRET": "x"}, ("image_env",), {"CC": 1},
    ("provenance",), {"origin": "explicitly-synthetic"}, ("provenance", "image_signature"), "maybe",
    ("extra",), True, ("supported_targets",), ["aarch64-linux-gnu"], ("supported_targets",), [1],
    ("target_axes",), {"os": "not-an-os"}, ("target_axes",), None, ("target_axes", "isa"), "arm64",
    ("default_target",), 5, ("default_target",), "aarch64-linux-gnu",
    ("version",), "", ("driver_facts",), {"release": "18"}, ("driver_facts",), [],
    ("executable",), "/usr/lib/llvm-18/bin/../bin/clang", ("executable",), "/usr/bin/clang",
    ("executable",), 7, ("wrapper_closure",), [{"path": "/usr/bin/clang", "target": "clang-17"}],
    ("wrapper_closure",), [{"path": 1, "target": "x"}], ("wrapper_closure",), "none",
    ("executable_format",), {**_FORMAT, "machine": "mips"},
    ("executable_format",), {**_FORMAT, "class": "elf32"}, ("executable_format",), {**_FORMAT, "type": "rel"},
    ("probe", "outputs", "clang.dumpmachine"), {"exit_code": 1, "sha256": "bogus"},
    ("probe", "outputs", "clang.dumpmachine"), {"exit_code": 1, "sha256": "c" * 64},
    ("probe", "outputs", "clang.dumpmachine"), {"exit_code": True, "sha256": "c" * 64},
    ("probe", "outputs", "clang.dumpmachine"), {"exit_code": 0, "sha256": hashlib.sha256(b"").hexdigest()},
    ("probe", "outputs", "clang.dumpmachine"), {"exit_code": 0, "sha256": "c" * 64, "extra": 1},
    ("probe", "outputs", "clang.dumpmachine"), ["exit_code", 0], ("probe", "outputs"), [],
    ("probe", "script_sha256"), "d" * 64, ("probe",), None,
]
_TAMPER_CASES = list(zip(_TAMPERED[::2], _TAMPERED[1::2]))


@pytest.mark.parametrize("path,value", _TAMPER_CASES, ids=[f"t{index:02d}" for index in range(len(_TAMPER_CASES))])
def test_validation_rejects_tampered_clang_records_with_profile_error(path, value):
    with pytest.raises(cp.CompilerProfileError):
        cp.validate_profile(_set(_records(CPP)["clang"], path, value))


@pytest.mark.parametrize("driver,path,value", [
    ("rustc", ("driver_facts",), {}), ("rustc", ("driver_facts", "release"), 1),
    ("rustc", ("supported_targets",), ["wasm32-wasip1"]),
    ("rustc", ("executable_format", "machine"), "arm64"), ("cargo", ("driver_facts",), {"release": "1"}),
    ("cargo", ("version",), "rustc 1.90.0"),
    ("go", ("driver_facts", "cgo_enabled"), "1"), ("go", ("driver_facts", "cgo_enabled"), 1),
    ("go", ("default_target",), "linux-amd64"), ("go", ("target_axes", "abi"), "gnu"),
    ("go", ("supported_targets",), ["linux/amd64", "linux/arm64"]),
], ids=["rustc-no-release", "rustc-release-type", "rustc-host-unsupported", "rustc-machine",
        "cargo-facts", "cargo-version", "go-cgo-text", "go-cgo-int", "go-target-form", "go-axes",
        "go-supported"])
def test_validation_enforces_per_driver_semantics(driver, path, value):
    records = {**_records(RUST), **_records(GO)}
    cp.validate_profile(records[driver])
    with pytest.raises(cp.CompilerProfileError):
        cp.validate_profile(_set(records[driver], path, value))


def test_rust_host_must_match_the_copied_executable_machine():
    with pytest.raises(cp.CompilerProfileError, match="rust host"):
        _records(RUST, machine="arm64")


def test_mixed_executable_machines_in_one_image_fail_closed():
    transcript = cp.parse_probe_transcript(CPP.encode())
    executables = _executables(transcript.copies)
    executables["gcc"]["format"] = {**_FORMAT, "machine": "arm64"}
    with pytest.raises(cp.CompilerProfileError, match="more than one ELF"):
        cp.build_profile_records(transcript, image_digest=IMAGE, executables=executables,
                                 transcript_sha256="c" * 64, image_signature="verified")


@pytest.mark.parametrize("field,value", [
    ("machine", []), ("machine", {}), ("class", {}), ("class", ["elf64"]), ("type", []), ("type", None),
], ids=["machine-list", "machine-dict", "class-dict", "class-list", "type-list", "type-none"])
def test_malformed_nested_executable_format_raises_profile_error(field, value):
    record = _set(_records(CPP)["clang"], ("executable_format", field), value)
    with pytest.raises(cp.CompilerProfileError, match="executable format is invalid"):
        cp.validate_profile(record)
    with pytest.raises(cp.CompilerProfileError, match="executable format is invalid"):
        cp.profile_set(IMAGE, {"clang": record})


def test_persisted_set_rejects_individually_valid_records_with_mixed_executable_formats():
    records = _records(CPP)
    arm_gcc = _records(CPP, machine="arm64")["gcc"]
    cp.validate_profile(records["clang"])
    cp.validate_profile(arm_gcc)
    with pytest.raises(cp.CompilerProfileError, match="mixes executable ELF"):
        cp.profile_set(IMAGE, {"clang": records["clang"], "gcc": arm_gcc})
    persisted = {"schema": cp.SET_SCHEMA, "images": {IMAGE: {"clang": records["clang"], "gcc": arm_gcc}}}
    with pytest.raises(cp.CompilerProfileError, match="mixes executable ELF"):
        cp.merge_profile_sets([persisted])


def test_set_consistency_does_not_tie_cross_compiler_targets_to_the_host_machine():
    cross = CPP.replace("@@probe clang.dumpmachine 0\n|x86_64-pc-linux-gnu",
                        "@@probe clang.dumpmachine 0\n|aarch64-unknown-linux-gnu")
    records = _records(cross)
    assert records["clang"]["target_axes"]["isa"] == "arm64"
    assert records["clang"]["executable_format"]["machine"] == "x86_64"
    persisted = cp.profile_set(IMAGE, records)
    assert cp.merge_profile_sets([persisted])["images"][IMAGE]["clang"]["default_target"] == (
        "aarch64-unknown-linux-gnu")


def test_validation_rejects_ambiguous_and_malformed_sets():
    records = _records(CPP)
    with pytest.raises(cp.CompilerProfileError, match="does not match"):
        cp.profile_set(OTHER_IMAGE, records)
    with pytest.raises(cp.CompilerProfileError, match="does not match"):
        cp.profile_set(IMAGE, {"gcc": records["clang"]})
    with pytest.raises(cp.CompilerProfileError, match="mixes image signature"):
        cp.profile_set(IMAGE, {"clang": records["clang"],
                               "gcc": _set(records["gcc"], ("provenance", "image_signature"), "not-enforced")})
    for bad in (["clang"], None, {1: records["clang"]}, {"clang": "record"}):
        with pytest.raises(cp.CompilerProfileError):
            cp.profile_set(IMAGE, bad)
    for bad in ({"schema": cp.SET_SCHEMA, "images": [IMAGE]}, {"schema": cp.SET_SCHEMA, "images": {1: {}}},
                {"schema": cp.SET_SCHEMA, "images": {IMAGE: []}}, {"schema": cp.SET_SCHEMA}, [IMAGE]):
        with pytest.raises(cp.CompilerProfileError):
            cp.merge_profile_sets([bad])
    one = cp.profile_set(IMAGE, records)
    two = cp.profile_set(OTHER_IMAGE, _records(GO, OTHER_IMAGE))
    assert sorted(cp.merge_profile_sets([two, one])["images"]) == [IMAGE, OTHER_IMAGE]
    with pytest.raises(cp.CompilerProfileError, match="more than one"):
        cp.merge_profile_sets([one, one])


@pytest.mark.parametrize("data,message", [
    (b"\x7fELF", "structurally valid"),
    (b"\x7fELF" + b"clang" * 12, "structurally valid"),
    (_elf("clang")[:40], "structurally valid"),
    (_elf("clang")[:100], "structurally valid"),
    (_elf("clang", e_type=1), "executable or shared-executable"),
    (_elf("clang", machine=40), "unsupported ELF machine"),
    (_elf("clang", entry=0x9000), "entry point"),
    (_elf("clang", load=False), "entry point"),
    (b"#!/bin/sh\nexec clang-18 \"$@\"\n", "script wrapper"),
], ids=["magic-only", "magic-garbage", "truncated-header", "truncated-program", "relocatable",
        "machine", "entry-outside", "no-load", "script"])
def test_copied_executable_must_be_a_structurally_valid_elf_executable(tmp_path, data, message):
    (tmp_path / "clang").write_bytes(data)
    with pytest.raises(cp.CompilerProfileError, match=message):
        cp.hash_copied_executables(tmp_path, ["clang"])


def test_copied_executable_facts_for_valid_elf(tmp_path):
    (tmp_path / "clang").write_bytes(_elf("clang"))
    (tmp_path / "go").write_bytes(_elf("go", e_type=2, machine=183))
    assert cp.hash_copied_executables(tmp_path, ["clang", "go"]) == {
        "clang": {"sha256": hashlib.sha256(_elf("clang")).hexdigest(), "format": _FORMAT},
        "go": {"sha256": hashlib.sha256(_elf("go", e_type=2, machine=183)).hexdigest(),
               "format": {"class": "elf64", "machine": "arm64", "type": "exec"}}}


class Verifier:
    def __init__(self, error: Exception | None = None, *, enforced: object = True) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.error = error
        if enforced is not None:
            self.enforced = enforced

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        self.calls.append((image_id, reference))
        if self.error is not None:
            raise self.error


class Engine:
    """Fake docker boundary: answers inspect and rm, and for run writes the copied executables."""

    def __init__(self, transcript: str | bytes, *, image_id: str = IMAGE, copies: dict[str, bytes] | None = None,
                 timed_out: bool = False, run_error: BaseException | None = None,
                 remove: tuple | BaseException = (0, b"", b"", False)) -> None:
        self.transcript = transcript if isinstance(transcript, bytes) else transcript.encode()
        self.image_id = image_id
        self.copies = copies
        self.timed_out = timed_out
        self.run_error = run_error
        self.remove = remove
        self.calls: list[tuple[str, ...]] = []
        self.output_dirs: list[Path] = []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, (self.image_id + "\n").encode(), b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            if isinstance(self.remove, BaseException):
                raise self.remove
            return self.remove
        assert argv[:2] == ("docker", "run")
        mount = argv[argv.index("--mount") + 1]
        source = Path(mount.split(",")[1].removeprefix("src="))
        self.output_dirs.append(source)
        copies = self.copies
        if copies is None:
            copies = {driver: _elf(driver) for driver in cp.parse_probe_transcript(self.transcript).copies}
        for name, data in copies.items():
            (source / name).write_bytes(data)
        if self.run_error is not None:
            raise self.run_error
        if self.timed_out:
            return None, b"", b"", True
        return 0, self.transcript, b"", False

    def container(self) -> str:
        run = next(call for call in self.calls if call[:2] == ("docker", "run"))
        return run[run.index("--name") + 1]


def _profile() -> BuildProfile:
    return BuildProfile("cpp", "appsec-review/buildenv-cpp:test", IMAGE, "10001:10001")


def test_collector_runs_one_isolated_native_protocol_probe_and_hashes_copied_bytes(tmp_path):
    engine = Engine(CPP)
    verifier = Verifier()
    result = cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=verifier)
    assert verifier.calls == [(IMAGE, "appsec-review/buildenv-cpp:test")]
    assert [call[:3] for call in engine.calls] == [
        ("docker", "image", "inspect"), ("docker", "run", "--rm"), ("docker", "rm", "--force")]
    assert engine.calls[2][3] == engine.container()
    run = engine.calls[1]
    parsed = parse_native_command(run)
    assert isinstance(parsed, NativeRun)
    assert parsed.image_id == IMAGE and parsed.network == "none" and parsed.executable == "/bin/sh"
    assert [(mount.target, mount.read_only) for mount in parsed.mounts] == [("/out", False)]
    assert parsed.arguments == ("-c", cp.PROBE_SCRIPT, "compiler-probe", "/out")
    records = result["images"][IMAGE]
    assert records["clang"]["compiler_sha256"] == hashlib.sha256(_elf("clang")).hexdigest()
    assert records["clang"]["probe"]["transcript_sha256"] == hashlib.sha256(CPP.encode()).hexdigest()
    assert records["clang"]["provenance"]["image_signature"] == "verified"
    assert not engine.output_dirs[0].exists()
    assert list(tmp_path.iterdir()) == []


def test_collector_accepts_already_removed_container(tmp_path):
    engine = Engine(CPP, remove=(1, b"", b"Error: No such container: x\n", False))
    result = cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    assert sorted(result["images"][IMAGE]) == ["clang", "gcc"]
    assert list(tmp_path.iterdir()) == []


def test_collector_records_disabled_signature_policy_as_not_enforced(tmp_path):
    engine = Engine(CPP)
    result = cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine,
                                          image_verifier=DisabledImageVerifier())
    for record in result["images"][IMAGE].values():
        assert record["provenance"]["image_identity"] == "docker-image-id/1"
        assert record["provenance"]["image_signature"] == "not-enforced"


@pytest.mark.parametrize("enforced", [True, False], ids=["enforced", "not-enforced"])
def test_collector_refuses_derived_image_rather_than_claim_its_signature(tmp_path, enforced):
    # The executor verifies only a derived image's base; no record may present that as the
    # derived digest's own signature, so step 1 refuses before any Docker call or verification.
    derived = BuildProfile("cpp", "appsec-review/buildenv-cpp:derived", IMAGE, "10001:10001",
                           derived_from_image_id=OTHER_IMAGE)
    engine = Engine(CPP)
    verifier = Verifier(enforced=enforced)
    with pytest.raises(cp.CompilerProfileError, match="derived image cpp is not supported"):
        cp.collect_compiler_profiles(derived, scratch=tmp_path, runner=engine, image_verifier=verifier)
    assert engine.calls == [] and verifier.calls == []
    assert list(tmp_path.iterdir()) == []


def test_collector_refuses_verifier_without_declared_enforcement_before_any_docker_call(tmp_path):
    engine = Engine(CPP)
    with pytest.raises(cp.CompilerProfileError, match="declare whether it enforces"):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine,
                                     image_verifier=Verifier(enforced=None))
    assert engine.calls == []


def test_collector_refuses_identity_mismatch_before_any_run(tmp_path):
    engine = Engine(CPP, image_id=OTHER_IMAGE)
    with pytest.raises(ValueError, match="identity changed"):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    assert [call[:2] for call in engine.calls] == [("docker", "image")]


def test_collector_stops_when_configured_signature_verifier_refuses(tmp_path):
    engine = Engine(CPP)
    with pytest.raises(SignatureVerificationError):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine,
                                     image_verifier=Verifier(SignatureVerificationError("unsigned")))
    assert [call[:2] for call in engine.calls] == [("docker", "image")]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("engine_options,error,message", [
    ({"timed_out": True}, cp.CompilerProfileError, "timed out"),
    ({"run_error": RuntimeError("engine connection lost")}, RuntimeError, "connection lost"),
    ({"run_error": KeyboardInterrupt("operator stop")}, KeyboardInterrupt, "operator stop"),
], ids=["timeout", "runner-raised", "interrupted"])
def test_collector_reconciles_probe_container_before_removing_output(tmp_path, engine_options, error, message):
    engine = Engine(CPP, **engine_options)
    with pytest.raises(error, match=message):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    assert engine.calls[-1] == ("docker", "rm", "--force", engine.container())
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("engine_options,cause", [
    ({"timed_out": True, "remove": (1, b"", b"permission denied\n", False)}, type(None)),
    ({"timed_out": True, "remove": (None, b"", b"", True)}, type(None)),
    ({"run_error": RuntimeError("engine connection lost"), "remove": OSError("broker gone")}, OSError),
    ({"remove": (125, b"", b"daemon error\n", False)}, type(None)),
], ids=["timeout-refused", "timeout-rm-timed-out", "raised-rm-raised", "success-rm-failed"])
def test_unconfirmed_cleanup_is_surfaced_and_preserves_probe_output(tmp_path, engine_options, cause):
    engine = Engine(CPP, **engine_options)
    with pytest.raises(cp.CompilerProfileError, match="cleanup is unconfirmed") as raised:
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    assert type(raised.value.__cause__) is cause
    if "run_error" in engine_options:
        assert isinstance(raised.value.__context__, OSError)
        assert isinstance(raised.value.__context__.__context__, RuntimeError)
    [output] = engine.output_dirs
    assert str(output) in str(raised.value)
    assert sorted(os.listdir(output)) == ["clang", "gcc"]


@pytest.mark.parametrize("copies,message", [
    ({"clang": b"#!/bin/sh\nexec clang-18 \"$@\"\n", "gcc": _elf("gcc")}, "script wrapper"),
    ({"clang": b"MZ\x90\x00 not elf", "gcc": _elf("gcc")}, "ELF"),
    ({"clang": b"\x7fELF", "gcc": _elf("gcc")}, "structurally valid"),
    ({"clang": _elf("clang")}, "do not match"),
    ({"clang": _elf("clang"), "gcc": _elf("gcc"), "extra": _elf("extra")}, "do not match"),
], ids=["script", "not-elf", "magic-only", "missing", "extra"])
def test_collector_rejects_untrustworthy_copied_executables(tmp_path, copies, message):
    engine = Engine(CPP, copies=copies)
    with pytest.raises(cp.CompilerProfileError, match=message):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    assert list(tmp_path.iterdir()) == []


def test_collector_rejects_symlinked_copy(tmp_path):
    class LinkingEngine(Engine):
        def __call__(self, argv, timeout):
            result = super().__call__(argv, timeout)
            if tuple(argv[:2]) == ("docker", "run"):
                target = self.output_dirs[-1] / "gcc"
                target.unlink()
                target.symlink_to(self.output_dirs[-1] / "clang")
            return result

    with pytest.raises(cp.CompilerProfileError, match="regular file"):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=LinkingEngine(CPP),
                                     image_verifier=Verifier())


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def _probe_sandbox(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    tools, utilities, out, work = (tmp_path / name for name in ("tools", "utilities", "out", "work"))
    for directory in (tools, utilities, out, work):
        directory.mkdir()
    for utility in ("printenv", "readlink", "cp", "head", "wc"):
        (utilities / utility).symlink_to(shutil.which(utility))
    environment = {"PATH": f"{tools}:{utilities}", "HOME": str(tmp_path), "TMPDIR": str(work)}
    return tools, out, environment


def _run_probe(out: Path, environment: dict[str, str]) -> bytes:
    completed = subprocess.run(["/bin/sh", "-c", cp.PROBE_SCRIPT, "compiler-probe", str(out)],
                               env=environment, capture_output=True, timeout=10, check=True)
    return completed.stdout


def test_real_probe_script_output_parses_and_script_wrappers_fail_closed(tmp_path):
    tools, out, environment = _probe_sandbox(tmp_path)
    sysroot = tmp_path / "sysroot"
    for target in ("x86_64-unknown-linux-gnu", "wasm32-wasip1"):
        (sysroot / "lib" / "rustlib" / target / "lib").mkdir(parents=True)
    _stub(tools, "clang-18", 'case "$1" in -dumpmachine) echo x86_64-pc-linux-gnu ;;'
                             ' --version) echo "clang version 18.1.3"; echo "Target: x86_64-pc-linux-gnu" ;; esac\n')
    (tools / "clang").symlink_to("clang-18")
    (tools / "cc").symlink_to("clang")
    _stub(tools, "rustc", 'case "$1" in -vV) printf "rustc 1.90.0 (x 2025-09-14)\\nhost: '
                          'x86_64-unknown-linux-gnu\\nrelease: 1.90.0\\n" ;;'
                          f' --print) echo {sysroot} ;; esac\n')
    _stub(tools, "go", 'case "$1" in version) echo "go version go1.23.4 linux/amd64" ;;'
                       ' env) printf \'{\\n\\t"CC": "gcc",\\n\\t"CGO_ENABLED": "0",\\n\\t"CXX": "g++",'
                       '\\n\\t"GOARCH": "arm64",\\n\\t"GOOS": "linux",\\n\\t"GOROOT": "/go"\\n}\\n\' ;; esac\n')
    stdout = _run_probe(out, {**environment, "CC": "clang"})
    transcript = cp.parse_probe_transcript(stdout)
    assert sorted(transcript.tools) == ["cc", "clang", "go", "rustc"]
    assert transcript.tools["cc"]["links"] == [(f"{tools}/cc", "clang"), (f"{tools}/clang", "clang-18")]
    assert transcript.tools["cc"]["real"] == transcript.tools["clang"]["real"] == f"{tools}/clang-18"
    assert transcript.env == {"CC": "clang", "PATH": environment["PATH"]}
    assert transcript.rust_targets == ("wasm32-wasip1", "x86_64-unknown-linux-gnu")
    assert transcript.copies == {"clang": 0, "go": 0, "rustc": 0}
    assert transcript.probes["clang.version"] == (0, ("clang version 18.1.3", "Target: x86_64-pc-linux-gnu"))
    assert json.loads("\n".join(transcript.probes["go.env"][1]))["GOARCH"] == "arm64"
    assert sorted(os.listdir(out)) == ["clang", "go", "rustc"]
    with pytest.raises(cp.CompilerProfileError, match="script wrapper"):
        cp.hash_copied_executables(out, transcript.copies)
    records = cp.build_profile_records(
        transcript, image_digest=IMAGE, transcript_sha256=hashlib.sha256(stdout).hexdigest(),
        executables=_executables(transcript.copies), image_signature="not-enforced")
    assert records["clang"]["invocation_names"] == ["cc", "clang"]
    assert records["go"]["target_axes"]["isa"] == "arm64"


def _gcc_stub(tools: Path, version_body: str) -> None:
    _stub(tools, "gcc", f'case "$1" in -dumpmachine) echo x86_64-linux-gnu ;; --version) {version_body} ;; esac\n')


@pytest.mark.parametrize("version_body", [
    'i=0; while [ $i -lt 257 ]; do echo "gcc line $i"; i=$((i + 1)); done',
    'i=0; while [ $i -lt 256 ]; do echo "gcc line $i"; i=$((i + 1)); done; printf tail',
    'i=0; while [ $i -lt 1100 ]; do printf "%064d" 0; i=$((i + 1)); done; echo',
], ids=["257-lines", "unterminated-257th-line", "bytes"])
def test_real_probe_script_reports_overflow_and_collection_rejects_it(tmp_path, version_body):
    tools, out, environment = _probe_sandbox(tmp_path)
    _gcc_stub(tools, version_body)
    stdout = _run_probe(out, environment)
    assert b"@@overflow gcc.version\n" in stdout and b"gcc line 255" not in stdout
    with pytest.raises(cp.CompilerProfileError, match="gcc.version exceeded its bound"):
        cp.parse_probe_transcript(stdout)
    engine = Engine(stdout, copies={"gcc": _elf("gcc")})
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with pytest.raises(cp.CompilerProfileError, match="exceeded its bound"):
        cp.collect_compiler_profiles(_profile(), scratch=scratch, runner=engine, image_verifier=Verifier())
    assert list(scratch.iterdir()) == []


def test_real_probe_script_keeps_output_at_its_line_bound(tmp_path):
    tools, out, environment = _probe_sandbox(tmp_path)
    _gcc_stub(tools, 'echo "gcc (stub) 13.3.0"; i=1; while [ $i -lt 256 ]; do echo "line $i"; i=$((i + 1)); done')
    transcript = cp.parse_probe_transcript(_run_probe(out, environment))
    code, lines = transcript.probes["gcc.version"]
    assert code == 0 and len(lines) == cp.MAX_PROBE_LINES and lines[-1] == "line 255"
