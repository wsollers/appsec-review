"""Per-family binary hardening expectations.

A C/C++ build states what it asked for in its captured compile and link flags, so the native
checks compare the requested posture with the linked binary. Go, Rust and .NET native AOT builds
emit no C flags; their binaries follow documented toolchain defaults instead. This table records
those defaults so that a protection a toolchain does not offer is never reported as a missing
protection.

Each expectation is one of:

* ``required``: the toolchain enables it by default; the observed value decides PASS or FAIL.
* ``not_offered``: the toolchain does not provide it by default for this output; the check is
  NOT_APPLICABLE with the documented reason.
* ``unknown``: no documented default is established here; the check is NOT_APPLICABLE with that
  reason. It is never a PASS and never a finding.

Mixed units (node-gyp, phpize, setuptools) are not listed: their C parts are judged by the flags
captured from their own compiles, exactly like a native unit.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType


EXPECTATIONS_VERSION = "build-security-family-expectations/1"


class Expectation(str, Enum):
    REQUIRED = "required"
    NOT_OFFERED = "not_offered"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CheckExpectation:
    expectation: Expectation
    reason: str
    source: str


@dataclass(frozen=True, slots=True)
class FamilyExpectations:
    family: str
    toolchain: str
    flags_driven: bool
    checks: Mapping[str, CheckExpectation]

    def for_check(self, check_id: str) -> CheckExpectation:
        return self.checks.get(check_id, CheckExpectation(
            Expectation.UNKNOWN, f"no documented {self.toolchain} default for {check_id}",
            "appsec-review family expectation table"))


ELF_CHECKS = ("elf.pie", "elf.relro", "elf.now", "elf.nx_stack", "elf.control_flow",
              "elf.stack_canary", "elf.fortify")
PE_CHECKS = ("pe.dynamic_base", "pe.nx_compat", "pe.high_entropy_va", "pe.guard_cf",
             "pe.safe_seh", "pe.gs")

_GO_LINK = "https://pkg.go.dev/cmd/go#hdr-Build_modes and https://pkg.go.dev/cmd/link"
_GO_SPEC = "Go is memory-safe without C stack protectors; cmd/go (go help buildmode)"
_RUST = ("rustc target spec x86_64-unknown-linux-gnu: position_independent_executables=true, "
         "relro_level=Full (https://doc.rust-lang.org/rustc/codegen-options/index.html#relro-level)")
_RUST_SP = "https://doc.rust-lang.org/rustc/exploit-mitigations.html (stack smashing protection is off by default)"
_ILC = ("https://learn.microsoft.com/dotnet/core/deploying/native-aot/ (ILCompiler links with the "
        "platform linker; its hardening defaults are not documented per property)")


def _table(values: Mapping[str, tuple[Expectation, str, str]]) -> Mapping[str, CheckExpectation]:
    return MappingProxyType({key: CheckExpectation(*value) for key, value in values.items()})


FAMILY_EXPECTATIONS: Mapping[str, FamilyExpectations] = MappingProxyType({
    "go": FamilyExpectations("go", "Go gc toolchain (linux/amd64)", False, _table({
        "elf.pie": (Expectation.NOT_OFFERED,
                    "the default -buildmode=exe links a non-PIE executable on linux/amd64; PIE needs -buildmode=pie",
                    _GO_LINK),
        "elf.relro": (Expectation.NOT_OFFERED,
                      "the internal linker emits no RELRO segment for a default non-PIE executable", _GO_LINK),
        "elf.now": (Expectation.NOT_OFFERED,
                    "a default Go executable is statically resolved; immediate binding is not a linker option",
                    _GO_LINK),
        "elf.nx_stack": (Expectation.REQUIRED, "the Go linker always emits a non-executable PT_GNU_STACK",
                         _GO_LINK),
        "elf.control_flow": (Expectation.NOT_OFFERED, "the gc compiler emits no CET/IBT notes", _GO_SPEC),
        "elf.stack_canary": (Expectation.NOT_OFFERED,
                             "pure Go uses checked growable stacks, not C stack canaries", _GO_SPEC),
        "elf.fortify": (Expectation.NOT_OFFERED, "pure Go does not call fortified libc routines", _GO_SPEC),
    })),
    "rust": FamilyExpectations("rust", "rustc (x86_64-unknown-linux-gnu)", False, _table({
        "elf.pie": (Expectation.REQUIRED, "rustc links PIE executables by default on this target", _RUST),
        "elf.relro": (Expectation.REQUIRED, "rustc requests full RELRO by default on this target", _RUST),
        "elf.now": (Expectation.REQUIRED, "full RELRO implies immediate binding (-z now)", _RUST),
        "elf.nx_stack": (Expectation.REQUIRED, "rustc links a non-executable stack", _RUST),
        "elf.control_flow": (Expectation.NOT_OFFERED,
                             "control-flow protection needs the unstable -Z cf-protection option", _RUST_SP),
        "elf.stack_canary": (Expectation.NOT_OFFERED,
                             "stack smashing protection is off by default (-Z stack-protector)", _RUST_SP),
        "elf.fortify": (Expectation.NOT_OFFERED, "Rust code does not use _FORTIFY_SOURCE libc wrappers",
                        _RUST_SP),
    })),
    "dotnet": FamilyExpectations("dotnet", ".NET ILCompiler native AOT", False, _table({
        **{check: (Expectation.UNKNOWN, "ILCompiler does not document this ELF default", _ILC)
           for check in ELF_CHECKS},
        "pe.dynamic_base": (Expectation.REQUIRED, "the MSVC linker used by ILCompiler sets /DYNAMICBASE by default",
                            "https://learn.microsoft.com/cpp/build/reference/dynamicbase"),
        "pe.nx_compat": (Expectation.REQUIRED, "the MSVC linker sets /NXCOMPAT by default",
                         "https://learn.microsoft.com/cpp/build/reference/nxcompat"),
        "pe.high_entropy_va": (Expectation.REQUIRED, "the MSVC linker sets /HIGHENTROPYVA by default for x64",
                               "https://learn.microsoft.com/cpp/build/reference/highentropyva"),
        "pe.guard_cf": (Expectation.UNKNOWN, "Control Flow Guard is opt-in for native AOT", _ILC),
        "pe.safe_seh": (Expectation.NOT_OFFERED, "SafeSEH applies only to 32-bit images", _ILC),
        "pe.gs": (Expectation.NOT_OFFERED, "/GS is a C/C++ compiler option; managed code is compiled by ILC",
                  _ILC),
    })),
})


def expectations_for(family: str) -> FamilyExpectations | None:
    """The documented defaults of a family toolchain; ``None`` means captured flags decide."""
    return FAMILY_EXPECTATIONS.get(family)


def unknown_family(family: str) -> FamilyExpectations:
    """A family without a captured C build and without a documented table: nothing is assumed."""
    return FamilyExpectations(family, f"{family} toolchain", False, MappingProxyType({}))
