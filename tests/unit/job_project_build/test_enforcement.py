"""job_project_build.enforcement: gap scoping, target-switch parsing and capture-wrapper
recognition, the pure parts of captured native target evidence."""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime import compiler_profiles as cp
from appsec_review.jobs.build_topology import _digest
from appsec_review.jobs.job_project_build.enforcement import (
    _capture_wrapper_invocation, _profile_for, _targets, captured_enforcement, gap_text,
    scoped_gaps, unique_gaps, validate_enforcement,
)
from appsec_review.storage import file_sha256

DEFAULTS = {"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None, "deployment": None,
            "device_kind": None, "hardware_generation": None}


# --- gaps ------------------------------------------------------------------------------------------

def test_gap_text_reads_a_record_reason_or_the_raw_value() -> None:
    assert gap_text({"schema": "producer-gap/1", "reason": "r"}) == "r"
    assert gap_text("plain") == "plain" and gap_text(7) == "7"


def test_unique_gaps_deduplicates_by_canonical_content_and_keeps_first_order() -> None:
    first = {"reason": "a", "scope_id": "x"}
    assert unique_gaps([first, {"scope_id": "x", "reason": "a"}, "b", "b", first]) == [first, "b"]


def test_scoped_gaps_wrap_text_as_producer_gaps_scoped_to_the_build_unit_or_the_unit() -> None:
    record = {"schema": "producer-gap/1", "reason": "already typed", "scope_id": "keep"}
    gaps = scoped_gaps(["build-unit-abc: recipe unavailable", "image build timed out", record,
                        "image build timed out"], "image.native")
    assert gaps[2] is record and len(gaps) == 3
    assert [(gap["scope_id"], gap["reason"]) for gap in gaps[:2]] == [
        ("build-unit-abc", "build-unit-abc: recipe unavailable"), ("image.native", "image build timed out")]
    assert all(gap["schema"] == "appsec-review/producer-gap/1" and gap["code"] == "producer_reported_gap"
               for gap in gaps[:2])
    explicit = scoped_gaps(["build-unit-abc: x"], "image.native", "forced")
    assert explicit[0]["scope_id"] == "forced"


# --- _targets --------------------------------------------------------------------------------------

def test_targets_default_to_the_profile_axes_without_switches() -> None:
    flags, axes, malformed = _targets(["clang", "-c", "main.c"], DEFAULTS)
    assert flags == [] and malformed is False
    assert axes == [{"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None, "deployment": None,
                     "device_kind": None, "hardware_generation": None}]


@pytest.mark.parametrize(("argv", "flags", "axes"), [
    (["clang", "--target=aarch64-unknown-linux-gnu", "-c", "a.c"], [["--target=aarch64-unknown-linux-gnu"]],
     [{"os": "linux", "isa": "arm64", "abi": "gnu"}]),
    (["clang", "-target", "i686-w64-mingw32", "a.c"], [["-target", "i686-w64-mingw32"]],
     [{"os": "windows", "isa": "x86", "abi": None}]),
    (["gcc", "-m32", "a.c"], [["-m32"]], [{"os": "linux", "isa": "x86", "abi": "gnu"}]),
    (["gcc", "-m64", "-m32", "a.c"], [["-m64"], ["-m32"]],
     [{"os": "linux", "isa": "x86", "abi": "gnu"}, {"os": "linux", "isa": "x86_64", "abi": "gnu"}]),
], ids=["target-equals", "target-split", "m32", "both-bitness"])
def test_targets_follow_explicit_switches(argv, flags, axes) -> None:
    got_flags, got_axes, malformed = _targets(argv, DEFAULTS)
    assert got_flags == flags and malformed is False
    assert [{key: value[key] for key in ("os", "isa", "abi")} for value in got_axes] == axes
    assert all(set(value) == set(DEFAULTS) for value in got_axes)


@pytest.mark.parametrize("argv", [
    ["clang", "a.c", "--target"],
    ["clang", "@response.rsp"],
    ["clang", "--target=aarch64-unknown-linux-gnu", "-m32", "a.c"],
], ids=["dangling-target", "response-file", "bitness-on-arm"])
def test_targets_flag_malformed_or_contradictory_switches(argv) -> None:
    assert _targets(argv, DEFAULTS)[2] is True


# --- _capture_wrapper_invocation ----------------------------------------------------------------

def test_direct_wrapper_and_python_tool_wrapper_frames_are_unwrapped() -> None:
    assert _capture_wrapper_invocation("/capture/wrappers/cc", ["cc", "-c", "a.c"]) == ("cc", ["-c", "a.c"])
    assert _capture_wrapper_invocation("/usr/bin/python3", ["python3", "/capture/tool-wrapper.py", "ld", "-o", "a"]) \
        == ("ld", ["-o", "a"])
    assert _capture_wrapper_invocation("/usr/bin/cc", ["cc", "-c", "a.c"]) is None
    assert _capture_wrapper_invocation("/usr/bin/python3", ["python3", "setup.py"]) is None


@pytest.mark.parametrize(("command", "expected"), [
    ("/capture/wrappers/c++ -o app main.o", ("c++", ["-o", "app", "main.o"])),
    (": && /capture/wrappers/c++ -o app main.o && :", ("c++", ["-o", "app", "main.o"])),
    ("/capture/wrappers/c++ -o 'my app' main.o", ("c++", ["-o", "my app", "main.o"])),
    ("/usr/bin/c++ -o app main.o", None),
    ("/capture/wrappers/c++ -o app && rm -rf /", None),
    ("/capture/wrappers/c++ -o $OUT main.o", None),
    ("/capture/wrappers/c++ -o `pwd`/app", None),
    ("/capture/wrappers/c++ -o app | tee log", None),
    ("", None),
    ("/capture/wrappers/c++ -o 'unterminated", None),
], ids=["plain", "ninja-guards", "quoted", "not-wrapper", "chained", "expansion", "backtick", "pipe", "empty",
        "unbalanced"])
def test_shell_frames_are_unwrapped_only_for_a_single_safe_wrapper_command(command, expected) -> None:
    assert _capture_wrapper_invocation("/bin/sh", ["sh", "-c", command]) == expected


def test_shell_frames_need_exactly_the_dash_c_shape() -> None:
    assert _capture_wrapper_invocation("/bin/sh", ["sh", "/capture/wrappers/cc"]) is None
    assert _capture_wrapper_invocation("/bin/bash", ["bash", "-c", "/capture/wrappers/cc -c a.c"]) is None


# --- _profile_for, captured_enforcement, validate_enforcement -----------------------------------

IMAGE_ID = "sha256:" + "a" * 64
_CPP_TRANSCRIPT = """@@collector appsec-review/compiler-probe/1
@@env CC
|clang
@@env PATH
|/usr/bin:/bin
@@tool cc
|/usr/bin/cc
@@link cc
|/usr/bin/cc
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
@@probe clang.dumpmachine 0
|x86_64-pc-linux-gnu
@@probe clang.version 0
|Ubuntu clang version 18.1.3
@@copy clang 0
@@end
"""


def _elf_bytes(name: str = "app", *, machine: int = 62, e_type: int = 2) -> bytes:
    payload = name.encode() * 8
    size = 64 + 56 + len(payload)
    header = (b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
              + struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, 0x1000, 64, 0, 0, 64, 56, 1, 64, 0, 0))
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, size, 0x2000, 0x1000)
    return header + program + payload


def _compiler_profile_set(image_id: str = IMAGE_ID) -> dict:
    transcript = cp.parse_probe_transcript(_CPP_TRANSCRIPT.encode())
    executables = {
        "clang": {
            "sha256": hashlib.sha256(_elf_bytes("clang", e_type=3)).hexdigest(),
            "format": {"class": "elf64", "machine": "x86_64", "type": "dyn"},
        }
    }
    records = cp.build_profile_records(
        transcript, image_digest=image_id, executables=executables,
        transcript_sha256=hashlib.sha256(_CPP_TRANSCRIPT.encode()).hexdigest(),
        image_signature="verified",
    )
    return cp.profile_set(image_id, records)


def _fake_capture(events: list[dict], *, image_id: str = IMAGE_ID, gaps: tuple[str, ...] = (),
                  capture_envp: bool = True):
    return SimpleNamespace(
        document={"collector": {"image_id": image_id}, "limits": {"capture_envp": capture_envp}},
        gaps=gaps,
        identity={"path": "data/build/probes/u/capture.json", "sha256": "c" * 64, "size_bytes": 128},
        events=lambda: list(events),
    )


def _dispatch_and_bound() -> tuple[dict, dict]:
    dispatch = {
        "build_unit_id": "build-unit-" + "1" * 16,
        "source_fingerprint": "f" * 40,
        "build_variant": {
            "configuration": "RelWithDebInfo", "target_arch": "x86_64", "execution_role": "target",
            "linkage": "dynamic", "toolchain": "clang", "abi": "gnu",
        },
        "image": {"image_id": IMAGE_ID},
        "recipe": {"source_dir": ".", "build_dir": "build", "configure_commands": [], "build_commands": []},
    }
    bound = {
        "selection": {
            "selection_id": "2" * 64,
            "required_axes": {
                "os": "linux", "isa": "x86_64", "abi": "gnu",
                "sdk": None, "deployment": None, "device_kind": None, "hardware_generation": None,
            },
        },
        "operations": [{"operation_id": "3" * 64, "kind": "native_compile"}],
        "enforcement": [{"catalog_bundle_identity": "4" * 64}],
    }
    return dispatch, bound


def test_profile_for_matches_only_image_owned_recorded_paths() -> None:
    profiles = _compiler_profile_set()
    records = profiles["images"][IMAGE_ID]
    assert _profile_for("/usr/lib/llvm-18/bin/clang", records) is records["clang"]
    assert _profile_for("/usr/bin/cc", records) is records["clang"]
    assert _profile_for("/workspace/clang", records) is None
    assert _profile_for("/usr/bin/unknown-cc", records) is None


def test_captured_enforcement_proves_compatible_native_target_and_validates_artifacts(tmp_path: Path) -> None:
    profiles = _compiler_profile_set()
    dispatch, bound = _dispatch_and_bound()
    bin_path = tmp_path / "data" / "build" / "probes" / "app"
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path.write_bytes(_elf_bytes("app", machine=62, e_type=2))
    doc_path = tmp_path / "data" / "build" / "probes" / "notes.jar"
    doc_path.write_bytes(b"PK\x03\x04")
    artifacts = [
        {"kind": "executable", "path": "data/build/probes/app",
         "workspace_path": "build/app", "sha256": file_sha256(bin_path)},
        {"kind": "jar", "path": "data/build/probes/notes.jar",
         "workspace_path": "build/notes.jar", "sha256": file_sha256(doc_path)},
    ]
    events = [
        {"ordinal": 1, "pid": 10, "kind": "process_exec", "result": 0,
         "executable": "/capture/wrappers/clang", "argv": ["clang", "-c", "main.c", "-o", "main.o"]},
        {"ordinal": 2, "pid": 11, "kind": "process_exec", "result": 0,
         "executable": "/usr/lib/llvm-18/bin/clang", "argv": ["clang", "-c", "main.c", "-o", "main.o"]},
        {"ordinal": 3, "pid": 12, "kind": "process_exec", "result": 0,
         "executable": "/usr/lib/llvm-18/bin/clang", "argv": ["clang", "--version"]},
        {"ordinal": 4, "pid": 13, "kind": "process_exec", "result": 0,
         "executable": "/usr/bin/echo", "argv": ["echo", "ok"]},
        {"ordinal": 5, "pid": 14, "kind": "file_open", "result": 0},
    ]
    proof, gaps = captured_enforcement(
        captures=[(1, _fake_capture(events))], dispatch=dispatch, bound=bound,
        profiles=profiles, policy=None, run_root=tmp_path, artifacts=artifacts,
    )
    assert proof["status"] == "proven" and gaps == []
    assert proof["proven_axes"]["isa"] == "x86_64" and proof["proven_axes"]["os"] == "linux"
    assert proof["closure_manifest"]["translation_units"] == ["/workspace/main.c"]
    assert len(proof["closure_manifest"]["native_artifacts"]) == 1

    # Tampered artifact sha256 fails closed before target check
    bin_path.write_bytes(_elf_bytes("tampered", machine=62, e_type=2))
    with pytest.raises(ValueError, match="native artifact changed before target enforcement"):
        captured_enforcement(
            captures=[(1, _fake_capture(events))], dispatch=dispatch, bound=bound,
            profiles=profiles, policy=None, run_root=tmp_path, artifacts=artifacts,
        )

    # Cross-target artifact (arm64 ELF when x86_64 was proven) is recorded as cross_target_not_permitted
    bin_path.write_bytes(_elf_bytes("arm64", machine=183, e_type=2))
    artifacts[0]["sha256"] = file_sha256(bin_path)
    rejected_proof, rejected_gaps = captured_enforcement(
        captures=[(1, _fake_capture(events))], dispatch=dispatch, bound=bound,
        profiles=profiles, policy=None, run_root=tmp_path, artifacts=artifacts,
    )
    assert rejected_proof["status"] == "unknown"
    assert rejected_proof["unresolved_inputs"] == ["cross_target_not_permitted"]
    assert "rejection" in rejected_proof["closure_manifest"]["native_artifacts"][0]
    assert [g["reason"] for g in rejected_gaps] == ["cross_target_not_permitted"]


def test_captured_enforcement_covers_empty_incomplete_mixed_cross_target_and_image_mismatch(tmp_path: Path) -> None:
    profiles = _compiler_profile_set()
    dispatch, bound = _dispatch_and_bound()

    # Different pinned image raises immediately
    with pytest.raises(ValueError, match="execution capture belongs to a different pinned image"):
        captured_enforcement(
            captures=[(1, _fake_capture([], image_id="sha256:" + "b" * 64))],
            dispatch=dispatch, bound=bound, profiles=profiles, policy=None, run_root=tmp_path, artifacts=(),
        )

    # Empty capture records capture_empty
    empty_proof, empty_gaps = captured_enforcement(
        captures=[(1, _fake_capture([]))], dispatch=dispatch, bound=bound,
        profiles=profiles, policy=None, run_root=tmp_path, artifacts=(),
    )
    assert empty_proof["status"] == "unknown"
    assert empty_proof["unresolved_inputs"] == ["capture_empty"] and len(empty_gaps) == 1
    # An empty capture says nothing about the build's target: provenance, not a failed build.
    assert (empty_gaps[0]["code"], empty_gaps[0]["reason"]) == ("provenance_unavailable", "capture_empty")

    # Incomplete capture + unknown compiler + mixed targets
    mixed_events = [
        {"ordinal": 1, "pid": 10, "kind": "process_exec", "result": 0, "executable": None, "argv": []},
        {"ordinal": 2, "pid": 11, "kind": "process_exec", "result": 0,
         "executable": "/usr/lib/llvm-18/bin/clang", "argv": ["clang", "-c", "a.c", "-o", "a.o"]},
        {"ordinal": 3, "pid": 12, "kind": "process_exec", "result": 0,
         "executable": "/opt/custom/mycc", "argv": ["mycc", "--target=aarch64-unknown-linux-gnu", "-c", "b.c", "-o", "b.o"]},
    ]
    mixed_proof, _ = captured_enforcement(
        captures=[(1, _fake_capture(mixed_events, capture_envp=False))],
        dispatch=dispatch, bound=bound, profiles=profiles, policy=None, run_root=tmp_path, artifacts=(),
    )
    assert mixed_proof["status"] == "unknown"
    assert set(mixed_proof["unresolved_inputs"]) == {"mixed_targets_in_capture", "unknown_compiler_in_capture"}

    # Required-axes mismatch (e.g. required arm64 while proven x86_64) -> cross_target_not_permitted
    arm_bound = {**bound, "selection": {**bound["selection"], "required_axes": {
        **bound["selection"]["required_axes"], "isa": "arm64"}}}
    single_events = [
        {"ordinal": 1, "pid": 10, "kind": "process_exec", "result": 0,
         "executable": "/usr/lib/llvm-18/bin/clang", "argv": ["clang", "-c", "a.c", "-o", "a.o"]},
    ]
    cross_proof, _ = captured_enforcement(
        captures=[(1, _fake_capture(single_events))], dispatch=dispatch, bound=arm_bound,
        profiles=profiles, policy=None, run_root=tmp_path, artifacts=(),
    )
    assert cross_proof["unresolved_inputs"] == ["cross_target_not_permitted"]


def test_validate_enforcement_rejects_tampered_mismatched_and_unproven_closures(tmp_path: Path) -> None:
    profiles = _compiler_profile_set()
    dispatch, bound = _dispatch_and_bound()
    events = [
        {"ordinal": 1, "pid": 10, "kind": "process_exec", "result": 0,
         "executable": "/usr/lib/llvm-18/bin/clang", "argv": ["clang", "-c", "a.c", "-o", "a.o"]},
    ]
    proof, _ = captured_enforcement(
        captures=[(1, _fake_capture(events))], dispatch=dispatch, bound=bound,
        profiles=profiles, policy=None, run_root=tmp_path, artifacts=(),
    )
    validate_enforcement(proof, dispatch=dispatch)

    with pytest.raises(ValueError, match="captured native enforcement identity is invalid"):
        validate_enforcement({**proof, "enforcement_id": "0" * 64})

    other_dispatch = {**dispatch, "source_fingerprint": "e" * 40}
    with pytest.raises(ValueError, match="belongs to a different build"):
        validate_enforcement(proof, dispatch=other_dispatch)

    bad_closure = {
        **proof,
        "closure_manifest": {**proof["closure_manifest"], "translation_units": []},
    }
    bad_closure["enforcement_id"] = _digest({k: v for k, v in bad_closure.items() if k != "enforcement_id"})
    with pytest.raises(ValueError, match="does not prove one compatible target"):
        validate_enforcement(bad_closure)
