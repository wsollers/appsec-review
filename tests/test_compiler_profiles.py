from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.container_runtime import compiler_profiles as cp
from appsec_review.container_runtime.build_executor import BuildProfile
from appsec_review.container_runtime.native_commands import NativeRun, parse_native_command
from appsec_review.signing.core import SignatureVerificationError

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


def _elf(name: str) -> bytes:
    return b"\x7fELF" + name.encode() * 8


def _records(text: str, image: str = IMAGE) -> dict:
    transcript = cp.parse_probe_transcript(text.encode())
    hashes = {driver: hashlib.sha256(_elf(driver)).hexdigest() for driver in transcript.copies}
    return cp.build_profile_records(transcript, image_digest=image, executable_hashes=hashes,
                                    transcript_sha256=hashlib.sha256(text.encode()).hexdigest())


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
    assert set(clang["probe"]["outputs"]) == {"clang.dumpmachine", "clang.version"}
    assert clang["probe"]["script_sha256"] == hashlib.sha256(cp.PROBE_SCRIPT.encode()).hexdigest()
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
    (lambda text: text.replace("@@probe clang.dumpmachine 0", "@@probe clang.dumpmachine 1"), "failed"),
    (lambda text: text.replace("|x86_64-pc-linux-gnu\n@@probe clang.version",
                               "|x86_64-pc-linux-gnu\n|i686-pc-linux-gnu\n@@probe clang.version"),
     "exactly one target"),
    (lambda text: text.replace("|x86_64-linux-gnu\n", "|not a triple\n"), "exactly one target"),
    (lambda text: text.replace("@@copy gcc 0\n", ""), "do not match"),
    (lambda text: text.replace("@@copy gcc 0\n", "@@copy gcc 0\n@@copy gcc 0\n"), "repeated copy"),
    (lambda text: text.replace("@@probe gcc.version 0\n|gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0\n", ""),
     "do not match"),
    (lambda text: text + "@@end\n", "end marker"),
    (lambda text: text.replace("\n", "\r\n"), "LF"),
], ids=["truncated", "bare-payload", "duplicate-env", "unknown-env", "chain-gap", "unresolved",
        "probe-failed", "two-triples", "bad-triple", "copy-missing", "copy-repeated",
        "probe-missing", "trailing-data", "crlf"])
def test_malformed_transcripts_fail_closed(mutation, message):
    with pytest.raises(cp.CompilerProfileError, match=message):
        _records(mutation(CPP))


@pytest.mark.parametrize("mutation,message", [
    (lambda text: text.replace("|host: x86_64-unknown-linux-gnu\n", ""), "host triple"),
    (lambda text: text.replace("|x86_64-unknown-linux-gnu\n@@probe cargo", "@@probe cargo"), "exclude the host"),
    (lambda text: text.replace("|binary: rustc\n", "|binary: rustc\n|binary: other\n"), "unexpected field"),
    (lambda text: text.replace("@@targets\n|wasm32-unknown-unknown\n|wasm32-wasip1\n"
                               "|x86_64-unknown-linux-gnu\n", ""), "do not match"),
], ids=["no-host", "host-not-installed", "repeated-field", "targets-missing"])
def test_malformed_rust_facts_fail_closed(mutation, message):
    with pytest.raises(cp.CompilerProfileError, match=message):
        _records(mutation(RUST))


@pytest.mark.parametrize("mutation,message", [
    (lambda text: text.replace(',\n|\t"GOROOT": "/usr/lib/go-1.23"', ""), "exactly the requested"),
    (lambda text: text.replace('"CGO_ENABLED": "1"', '"CGO_ENABLED": "yes"'), "cgo"),
    (lambda text: text.replace("|}\n", ""), "not JSON"),
], ids=["missing-key", "bad-cgo", "bad-json"])
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


def test_validation_rejects_tampered_records_and_ambiguous_sets():
    records = _records(CPP)
    for change in ({"compiler_sha256": "B" * 64}, {"driver_semantics": "gcc-default/1"},
                   {"invocation_names": ["clang", "cc"]}, {"image_env": {"SECRET": "x"}},
                   {"provenance": {"origin": "explicitly-synthetic"}}, {"extra": True},
                   {"supported_targets": ["aarch64-linux-gnu"]}):
        with pytest.raises(cp.CompilerProfileError):
            cp.validate_profile({**records["clang"], **change})
    with pytest.raises(cp.CompilerProfileError, match="does not match"):
        cp.profile_set(OTHER_IMAGE, records)
    with pytest.raises(cp.CompilerProfileError, match="does not match"):
        cp.profile_set(IMAGE, {"gcc": records["clang"]})
    one = cp.profile_set(IMAGE, records)
    two = cp.profile_set(OTHER_IMAGE, _records(GO, OTHER_IMAGE))
    assert sorted(cp.merge_profile_sets([two, one])["images"]) == [IMAGE, OTHER_IMAGE]
    with pytest.raises(cp.CompilerProfileError, match="more than one"):
        cp.merge_profile_sets([one, one])


class Verifier:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.error = error

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        self.calls.append((image_id, reference))
        if self.error is not None:
            raise self.error


class Engine:
    """Fake docker boundary: answers inspect, and for run writes the image's copied executables."""

    def __init__(self, transcript: str, *, image_id: str = IMAGE, copies: dict[str, bytes] | None = None,
                 timed_out: bool = False) -> None:
        self.transcript = transcript.encode()
        self.image_id = image_id
        self.copies = copies
        self.timed_out = timed_out
        self.calls: list[tuple[str, ...]] = []
        self.output_dirs: list[Path] = []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, (self.image_id + "\n").encode(), b"", False
        if argv[:3] == ("docker", "rm", "--force"):
            return 0, b"", b"", False
        assert argv[:2] == ("docker", "run")
        mount = argv[argv.index("--mount") + 1]
        source = Path(mount.split(",")[1].removeprefix("src="))
        self.output_dirs.append(source)
        if self.timed_out:
            return None, b"", b"", True
        transcript = cp.parse_probe_transcript(self.transcript)
        for name, data in (self.copies or {driver: _elf(driver) for driver in transcript.copies}).items():
            (source / name).write_bytes(data)
        return 0, self.transcript, b"", False


def _profile() -> BuildProfile:
    return BuildProfile("cpp", "appsec-review/buildenv-cpp:test", IMAGE, "10001:10001")


def test_collector_runs_one_isolated_native_protocol_probe_and_hashes_copied_bytes(tmp_path):
    engine = Engine(CPP)
    verifier = Verifier()
    result = cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=verifier)
    assert verifier.calls == [(IMAGE, "appsec-review/buildenv-cpp:test")]
    assert [call[:2] for call in engine.calls] == [("docker", "image"), ("docker", "run")]
    run = engine.calls[1]
    parsed = parse_native_command(run)
    assert isinstance(parsed, NativeRun)
    assert parsed.image_id == IMAGE and parsed.network == "none" and parsed.executable == "/bin/sh"
    assert [(mount.target, mount.read_only) for mount in parsed.mounts] == [("/out", False)]
    assert parsed.arguments == ("-c", cp.PROBE_SCRIPT, "compiler-probe", "/out")
    records = result["images"][IMAGE]
    assert records["clang"]["compiler_sha256"] == hashlib.sha256(_elf("clang")).hexdigest()
    assert records["clang"]["probe"]["transcript_sha256"] == hashlib.sha256(CPP.encode()).hexdigest()
    assert not engine.output_dirs[0].exists()
    assert list(tmp_path.iterdir()) == []


def test_collector_refuses_identity_mismatch_before_any_run(tmp_path):
    engine = Engine(CPP, image_id=OTHER_IMAGE)
    with pytest.raises(ValueError, match="identity changed"):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    assert [call[:2] for call in engine.calls] == [("docker", "image")]


def test_collector_refuses_unsigned_image_before_any_run(tmp_path):
    engine = Engine(CPP)
    with pytest.raises(SignatureVerificationError):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine,
                                     image_verifier=Verifier(SignatureVerificationError("unsigned")))
    assert [call[:2] for call in engine.calls] == [("docker", "image")]


def test_collector_removes_timed_out_probe_container_and_scratch(tmp_path):
    engine = Engine(CPP, timed_out=True)
    with pytest.raises(cp.CompilerProfileError, match="timed out"):
        cp.collect_compiler_profiles(_profile(), scratch=tmp_path, runner=engine, image_verifier=Verifier())
    run = engine.calls[1]
    assert engine.calls[2] == ("docker", "rm", "--force", run[run.index("--name") + 1])
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("copies,message", [
    ({"clang": b"#!/bin/sh\nexec clang-18 \"$@\"\n", "gcc": _elf("gcc")}, "script wrapper"),
    ({"clang": b"MZ\x90\x00 not elf", "gcc": _elf("gcc")}, "ELF"),
    ({"clang": _elf("clang")}, "do not match"),
    ({"clang": _elf("clang"), "gcc": _elf("gcc"), "extra": _elf("extra")}, "do not match"),
], ids=["script", "not-elf", "missing", "extra"])
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


def test_real_probe_script_output_parses_and_script_wrappers_fail_closed(tmp_path):
    tools, utilities, out, sysroot = (tmp_path / name for name in ("tools", "utilities", "out", "sysroot"))
    for directory in (tools, utilities, out):
        directory.mkdir()
    for target in ("x86_64-unknown-linux-gnu", "wasm32-wasip1"):
        (sysroot / "lib" / "rustlib" / target / "lib").mkdir(parents=True)
    for utility in ("printenv", "readlink", "cp", "head"):
        (utilities / utility).symlink_to(shutil.which(utility))
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
    environment = {"PATH": f"{tools}:{utilities}", "HOME": str(tmp_path), "CC": "clang"}
    completed = subprocess.run(["/bin/sh", "-c", cp.PROBE_SCRIPT, "compiler-probe", str(out)],
                               env=environment, capture_output=True, timeout=10, check=True)
    transcript = cp.parse_probe_transcript(completed.stdout)
    assert sorted(transcript.tools) == ["cc", "clang", "go", "rustc"]
    assert transcript.tools["cc"]["links"] == [(f"{tools}/cc", "clang"), (f"{tools}/clang", "clang-18")]
    assert transcript.tools["cc"]["real"] == transcript.tools["clang"]["real"] == f"{tools}/clang-18"
    assert transcript.env == {"CC": "clang", "PATH": f"{tools}:{utilities}"}
    assert transcript.rust_targets == ("wasm32-wasip1", "x86_64-unknown-linux-gnu")
    assert transcript.copies == {"clang": 0, "go": 0, "rustc": 0}
    assert json.loads("\n".join(transcript.probes["go.env"][1]))["GOARCH"] == "arm64"
    assert sorted(os.listdir(out)) == ["clang", "go", "rustc"]
    with pytest.raises(cp.CompilerProfileError, match="script wrapper"):
        cp.hash_copied_executables(out, transcript.copies)
    records = cp.build_profile_records(
        transcript, image_digest=IMAGE, transcript_sha256=hashlib.sha256(completed.stdout).hexdigest(),
        executable_hashes={name: "c" * 64 for name in transcript.copies})
    assert records["clang"]["invocation_names"] == ["cc", "clang"]
    assert records["go"]["target_axes"]["isa"] == "arm64"
