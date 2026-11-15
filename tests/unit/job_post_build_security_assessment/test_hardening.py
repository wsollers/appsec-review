from __future__ import annotations

import pytest

from appsec_review.jobs.job_post_build_security_assessment.assessment import family_expectations
from appsec_review.jobs.job_post_build_security_assessment.hardening import (
    ELF_CHECKS,
    EXPECTATIONS_VERSION,
    FAMILY_EXPECTATIONS,
    PE_CHECKS,
    CheckExpectation,
    Expectation,
    FamilyExpectations,
    expectations_for,
    unknown_family,
)


def test_hardening_tables_and_fallback_lookup() -> None:
    assert EXPECTATIONS_VERSION == "build-security-family-expectations/1"
    assert sorted(FAMILY_EXPECTATIONS) == ["dotnet", "go", "rust"]

    for family_name, table in sorted(FAMILY_EXPECTATIONS.items()):
        assert isinstance(table, FamilyExpectations)
        assert table.family == family_name
        assert table.flags_driven is False
        for check_id, spec in sorted(table.checks.items()):
            assert check_id in {*ELF_CHECKS, *PE_CHECKS}
            assert isinstance(spec, CheckExpectation)
            assert isinstance(spec.expectation, Expectation)
            assert spec.reason and spec.source

    go_table = expectations_for("go")
    assert go_table is not None
    assert go_table.for_check("elf.nx_stack").expectation is Expectation.REQUIRED
    assert go_table.for_check("elf.pie").expectation is Expectation.NOT_OFFERED
    missing = go_table.for_check("pe.dynamic_base")
    assert missing.expectation is Expectation.UNKNOWN
    assert "no documented" in missing.reason
    assert missing.source == "appsec-review family expectation table"

    assert expectations_for("zig") is None
    zig = unknown_family("zig")
    assert zig.family == "zig"
    assert zig.toolchain == "zig toolchain"
    assert zig.flags_driven is False
    assert dict(zig.checks) == {}
    assert zig.for_check("elf.pie").expectation is Expectation.UNKNOWN


@pytest.mark.parametrize(
    ("family", "has_compiles", "expected_family"),
    [
        ("native", False, None),
        ("native", True, None),
        ("node", True, None),
        ("python", True, None),
        ("php", True, None),
        ("wasm", True, None),
        ("python", False, "python"),
        ("node", False, "node"),
        ("go", False, "go"),
        ("go", True, "go"),
        ("rust", False, "rust"),
        ("dotnet", False, "dotnet"),
        ("zig", False, "zig"),
    ],
)
def test_family_expectations_selector(
    family: str,
    has_compiles: bool,
    expected_family: str | None,
) -> None:
    selected = family_expectations(family, has_compiles)
    if expected_family is None:
        assert selected is None
    else:
        assert selected is not None
        assert selected.family == expected_family
