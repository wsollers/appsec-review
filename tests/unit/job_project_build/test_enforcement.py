"""job_project_build.enforcement: gap scoping, target-switch parsing and capture-wrapper
recognition, the pure parts of captured native target evidence."""
from __future__ import annotations

import pytest

from appsec_review.jobs.job_project_build.enforcement import (
    _capture_wrapper_invocation, _targets, gap_text, scoped_gaps, unique_gaps,
)

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
