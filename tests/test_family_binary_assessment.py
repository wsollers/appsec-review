"""Every family's binaries reach inspection, each with its own hardening expectations.

Inspection records are synthetic headers (as in test_post_build_security_assessment.py) or a
minimal loader-readable ELF; no target code is built or run.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from appsec_review.jobs.job_cpp_compiled_analysis.job import native_analysis_actions
from appsec_review.jobs.job_language_build import native_components
from appsec_review.jobs.job_post_build_security_assessment.assessment import (
    deterministic_checks, family_expectations, inspect_binary,
)
from appsec_review.jobs.job_post_build_security_assessment.hardening import (
    ELF_CHECKS, FAMILY_EXPECTATIONS, PE_CHECKS, Expectation,
)
from appsec_review.jobs.job_post_build_security_assessment.job import family_build_cases
from tests.capture_fakes import minimal_elf


def _elf(kind: str, **hardening) -> dict:
    return {"format": "ELF", "kind": kind, "sha256": "e" * 64, "artifact_id": "a" * 64,
            "hardening": {"pie": None, "relro": None, "now": None, "nx_stack": None,
                          "control_flow": None, "stack_canary": None, "fortify": None, **hardening}}


def _by_id(checks: list[dict]) -> dict[str, dict]:
    return {item["check_id"]: item for item in checks}


def test_every_family_expectation_names_its_source_and_never_invents_a_pass() -> None:
    for family, table in FAMILY_EXPECTATIONS.items():
        assert table.family == family and not table.flags_driven
        for check_id, value in table.checks.items():
            assert check_id in {*ELF_CHECKS, *PE_CHECKS}
            assert value.reason and value.source


def test_go_defaults_are_not_findings_but_a_required_property_still_fails() -> None:
    # A default Go linux/amd64 executable: non-PIE, no RELRO, no canary, no fortify.
    checks = _by_id(deterministic_checks([], [_elf("executable", pie=False, relro=False, now=None,
                                                    nx_stack=True)], family="go"))
    for check_id in ("elf.pie", "elf.relro", "elf.now", "elf.stack_canary", "elf.fortify", "elf.control_flow"):
        assert checks[check_id]["status"] == "NOT_APPLICABLE", check_id
        assert checks[check_id]["expectation"]["value"] == "not_offered"
        assert "Go" in checks[check_id]["rationale"]
    assert checks["elf.nx_stack"]["status"] == "PASS"
    executable_stack = _by_id(deterministic_checks([], [_elf("executable", nx_stack=False)], family="go"))
    assert executable_stack["elf.nx_stack"]["status"] == "FAIL"


def test_rust_requires_pie_and_full_relro_but_not_c_protections() -> None:
    good = _by_id(deterministic_checks([], [_elf("pie_executable", pie=True, relro=True, now=True,
                                                 nx_stack=True)], family="rust"))
    assert {good[key]["status"] for key in ("elf.pie", "elf.relro", "elf.now", "elf.nx_stack")} == {"PASS"}
    assert good["elf.stack_canary"]["status"] == "NOT_APPLICABLE"
    assert good["elf.fortify"]["status"] == "NOT_APPLICABLE"
    regressed = _by_id(deterministic_checks([], [_elf("executable", pie=False, relro=False)], family="rust"))
    assert regressed["elf.pie"]["status"] == "FAIL" and regressed["elf.relro"]["status"] == "FAIL"


def test_dotnet_aot_pe_defaults_and_unknown_elf_defaults() -> None:
    pe = {"format": "PE/COFF", "kind": "executable", "bits": 64, "sha256": "p" * 64, "artifact_id": "b" * 64,
          "hardening": {"dynamic_base": True, "nx_compat": True, "high_entropy_va": False,
                        "guard_cf": False, "safe_seh": None, "gs": None}}
    checks = _by_id(deterministic_checks([], [pe], family="dotnet"))
    assert checks["pe.dynamic_base"]["status"] == "PASS"
    assert checks["pe.high_entropy_va"]["status"] == "FAIL"
    assert checks["pe.guard_cf"]["status"] == "NOT_APPLICABLE"  # opt-in: unknown, not a finding
    assert checks["pe.gs"]["status"] == "NOT_APPLICABLE"
    elf = _by_id(deterministic_checks([], [_elf("pie_executable", pie=False)], family="dotnet"))
    assert all(elf[check]["status"] == "NOT_APPLICABLE" and elf[check]["expectation"]["value"] == "unknown"
               for check in ("elf.pie", "elf.relro", "elf.now", "elf.stack_canary"))


def test_unlisted_family_without_captured_flags_assumes_nothing() -> None:
    checks = deterministic_checks([], [_elf("executable", pie=False, nx_stack=False)], family="zig")
    assert {item["status"] for item in checks} == {"NOT_APPLICABLE"}


@pytest.mark.parametrize("family", ["native", "node", "python", "php"])
def test_flag_driven_families_keep_native_requested_versus_actual_checks(family: str) -> None:
    action = {"classification": "compiler", "build_action_id": "c1", "project": "p",
              "argv": ["cc", "-fstack-protector-strong", "-O2", "-D_FORTIFY_SOURCE=2", "-fPIE", "-c", "x.c"]}
    assert family_expectations(family, True) is None
    checks = deterministic_checks([action], [_elf("executable", pie=False, nx_stack=True)], family=family)
    by_id = _by_id(checks)
    assert by_id["gnu.stack_protector"]["status"] == "PASS"
    assert by_id["elf.pie"]["status"] == "FAIL" and "expectation" not in by_id["elf.pie"]
    assert by_id["command_binary.pie_mismatch"]["status"] == "FAIL"


def _receipt(run_root: Path, family: str, unit: str, files: dict[str, bytes], *, kinds: dict[str, str],
             database: int = 0, status: str = "SUCCEEDED") -> dict:
    artifacts = []
    for name, data in files.items():
        path = run_root / "data" / "build" / family / unit / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        artifacts.append({"path": path.relative_to(run_root).as_posix(),
                          "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
                          "kind": kinds[name]})
    value = {"build_unit_id": unit, "family": family, "root": f"svc/{unit}", "terminal_status": status,
             "artifacts": artifacts, "image": {"image_id": "sha256:" + "1" * 64}}
    if database:
        value["native_compile_database"] = {"entry_count": database}
    return value


def test_family_cases_cover_go_rust_dotnet_and_wheel_members_but_not_native_lane_units(tmp_path: Path) -> None:
    elf = minimal_elf()
    wheel = tmp_path / "w.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pkg/_speed.cpython-312-x86_64-linux-gnu.so", elf)
        archive.writestr("pkg/__init__.py", "")
    receipts = [
        _receipt(tmp_path, "go", "build-unit-go1", {"svc": elf, "go.sum": b"x"},
                 kinds={"svc": "executable", "go.sum": "package-metadata"}),
        _receipt(tmp_path, "rust", "build-unit-rs1", {"tool": elf}, kinds={"tool": "executable"}),
        _receipt(tmp_path, "dotnet", "build-unit-dn1", {"app.exe": b"MZ" + bytes(62)}, kinds={"app.exe": "executable"}),
        _receipt(tmp_path, "python", "build-unit-py1", {"pkg.whl": wheel.read_bytes()}, kinds={"pkg.whl": "wheel"}),
        # A mixed unit whose captured C compiles route it through the C/C++ lane instead.
        _receipt(tmp_path, "php", "build-unit-php1", {"ext.so": elf}, kinds={"ext.so": "native-extension"},
                 database=2),
        _receipt(tmp_path, "native", "build-unit-c1", {"a.out": elf}, kinds={"a.out": "executable"}),
        _receipt(tmp_path, "go", "build-unit-go2", {"svc": elf}, kinds={"svc": "executable"}, status="FAILED"),
        _receipt(tmp_path, "java", "build-unit-j1", {"a.jar": b"PK\x03\x04"}, kinds={"a.jar": "jar"}),
    ]
    cases = family_build_cases({"receipts": receipts}, tmp_path)
    assert {case["family"]: [item["kind"] for item in case["artifacts"]] for case in cases.values()} == {
        "go": ["executable"], "rust": ["executable"], "dotnet": ["executable"], "python": ["wheel"]}
    assert set(cases) == {"family-build-unit-go1", "family-build-unit-rs1", "family-build-unit-dn1",
                          "family-build-unit-py1"}
    record = inspect_binary(tmp_path / cases["family-build-unit-go1"]["artifacts"][0]["path"])
    assert record["format"] == "ELF" and record["executed"] is False


class _Capture:
    def __init__(self, events: list[dict]) -> None:
        self._events = events
        self.identity = {"sha256": "c" * 64}

    def events(self):
        return iter(self._events)


def test_captured_family_compiles_become_a_compile_database_and_native_analysis_input(tmp_path: Path) -> None:
    """A synthetic repository with two C-extension packages; nothing here is review-target specific."""
    workspace = tmp_path / "workspace"
    for relative in ("pkgs/a/src/a.c", "pkgs/a/src/b.c", "pkgs/b/ext/c.c"):
        (workspace / relative).parent.mkdir(parents=True, exist_ok=True)
        (workspace / relative).write_text("int f(void){return 0;}\n", encoding="utf-8")
    events = [
        {"kind": "process_exec", "pid": 1, "ordinal": 1, "timestamp_ns": 1, "result": 0,
         "executable": "/usr/bin/python3.12", "argv": ["python", "-m", "pip", "wheel", "."]},
        {"kind": "process_fork", "pid": 1, "child_pid": 2, "ordinal": 2, "timestamp_ns": 2},
        {"kind": "process_exec", "pid": 2, "ordinal": 3, "timestamp_ns": 3, "result": 0,
         "executable": "/usr/bin/x86_64-linux-gnu-gcc-13",
         "argv": ["x86_64-linux-gnu-gcc", "-fstack-protector-strong", "-O2", "-I/usr/include/python3.12",
                  "-c", "src/a.c", "-o", "build/temp/src/a.o"]},
        # The capture wrapper launcher in a writable root is never a compile record.
        {"kind": "process_exec", "pid": 3, "ordinal": 4, "timestamp_ns": 4, "result": 0,
         "executable": "/capture/wrappers/gcc", "argv": ["gcc", "-c", "src/b.c"]},
        {"kind": "process_exec", "pid": 4, "ordinal": 5, "timestamp_ns": 5, "result": 0,
         "executable": "/usr/lib/llvm-18/bin/clang", "argv": ["clang", "-cc1", "-emit-obj", "src/b.c"]},
        {"kind": "process_exec", "pid": 5, "ordinal": 6, "timestamp_ns": 6, "result": 0,
         "executable": "/usr/bin/x86_64-linux-gnu-gcc-13",
         "argv": ["x86_64-linux-gnu-gcc", "-shared", "build/temp/src/a.o", "-o", "a.so"]},
    ]
    dispatch = {"build_unit_id": "build-unit-" + "a" * 20, "family": "python", "root": "pkgs/a",
                "recipe": {"source_dir": "pkgs/a"},
                "native_components": [{"path": "pkgs/a/src/a.c", "sha256": "0" * 64, "size_bytes": 1},
                                      {"path": "pkgs/a/src/b.c", "sha256": "0" * 64, "size_bytes": 1}]}
    unit_root = tmp_path / "run" / "data" / "build" / "python" / "units" / dispatch["build_unit_id"]
    unit_root.mkdir(parents=True)
    identity, gaps = native_components.publish(unit_root, tmp_path / "run", dispatch=dispatch,
                                               workspace=workspace, captures=[(1, _Capture(events))])
    assert identity is not None and identity["entry_count"] == 1 and identity["family"] == "python"
    # b.c was never compiled by the family build: a named gap, not silent coverage.
    assert gaps == ["native component sources were not observed in a captured compile: pkgs/a/src/b.c"]
    document = json.loads((tmp_path / "run" / identity["path"]).read_text(encoding="utf-8"))
    rows = native_components.compile_commands(document)
    assert rows == [{"directory": "/workspace/pkgs/a", "file": "/workspace/pkgs/a/src/a.c",
                     "arguments": events[2]["argv"], "output": "build/temp/src/a.o"}]

    target = tmp_path / "target"
    for relative in ("pkgs/a/src/a.c", "pkgs/b/ext/c.c", "tools/cli/main.c"):
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text("int x;\n", encoding="utf-8")
    language = {"language_build_handoff_sha256": "f" * 64, "receipts": [
        {"build_unit_id": dispatch["build_unit_id"], "family": "python", "root": "pkgs/a",
         "build_system": "python", "terminal_status": "SUCCEEDED",
         "native_components": dispatch["native_components"], "native_compile_database": identity},
        # A second package whose build captured no compile is not a native analysis input.
        {"build_unit_id": "build-unit-" + "b" * 20, "family": "python", "root": "pkgs/b",
         "build_system": "python", "terminal_status": "SUCCEEDED",
         "native_compile_database": {**identity, "entry_count": 0}},
        {"build_unit_id": "build-unit-" + "c" * 20, "family": "native", "root": "tools/cli",
         "build_system": "direct-native", "terminal_status": "SUCCEEDED"},
    ]}
    actions = {item["root"]: item for item in native_analysis_actions(language, target)}
    assert set(actions) == {"pkgs/a", "tools/cli"}
    assert actions["pkgs/a"]["family"] == "python"
    assert actions["pkgs/a"]["compile_database_origin"] == "captured-native-components"
    assert actions["tools/cli"]["compile_database_origin"] == "build-system"


def _pe(*, managed: bool, pe32_plus: bool = True) -> bytes:
    """Minimal PE image; ``managed`` sets the CLR runtime header (data directory 14)."""
    dos = bytearray(64)
    dos[:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    optional = bytearray(240 if pe32_plus else 224)
    optional[:2] = (0x20B if pe32_plus else 0x10B).to_bytes(2, "little")
    count_at, directories_at = (108, 112) if pe32_plus else (92, 96)
    optional[count_at:count_at + 4] = (16).to_bytes(4, "little")
    if managed:
        entry = directories_at + 14 * 8
        optional[entry:entry + 8] = (0x2008).to_bytes(4, "little") + (72).to_bytes(4, "little")
    coff = bytearray(20)
    coff[16:18] = len(optional).to_bytes(2, "little")
    return bytes(dos) + b"PE\0\0" + bytes(coff) + bytes(optional)


def test_managed_dotnet_assemblies_are_not_family_cases_but_native_aot_pe_is(tmp_path: Path) -> None:
    receipts = [
        _receipt(tmp_path, "dotnet", "build-unit-il", {"App.dll": _pe(managed=True),
                                                       "Lib.dll": _pe(managed=True, pe32_plus=False)},
                 kinds={"App.dll": "assembly", "Lib.dll": "assembly"}),
        _receipt(tmp_path, "dotnet", "build-unit-aot", {"app.exe": _pe(managed=False), "App.dll": _pe(managed=True)},
                 kinds={"app.exe": "executable", "App.dll": "assembly"}),
    ]
    cases = family_build_cases({"receipts": receipts}, tmp_path)
    assert set(cases) == {"family-build-unit-aot"}
    assert [item["kind"] for item in cases["family-build-unit-aot"]["artifacts"]] == ["executable"]
