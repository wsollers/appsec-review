import copy

import pytest

from appsec_review.config.build_selection import AXES, SCHEMA, parse_build_selection


def _rule(selectors, axes):
    return {"selectors": selectors, "axes": axes, "provenance": "synthetic-inline-intent"}


def _policy(rules):
    return parse_build_selection({"schema": SCHEMA, "policy_id": "inline/1",
                                  "ambiguity_policy": "block", "rules": rules})


def test_exact_unit_selection_overrides_family_without_rewriting_source_facts():
    unit = {"build_unit_id": "chosen", "root": ".", "build_system": "cmake"}
    policy = _policy([_rule({"build_system": "cmake"}, {"os": "linux", "isa": "x86_64"}),
                      _rule({"build_unit_id": "chosen"}, {"os": "windows", "isa": "x86_64"})])
    selected = policy.select(unit)
    assert selected["required_axes"]["os"] == "windows"
    assert set(selected["required_axes"]) == set(AXES)
    assert "os" not in unit
    assert selected["required_axes"]["hardware_generation"] is None


def test_equal_specificity_conflict_blocks_and_never_chooses_a_default():
    policy = _policy([_rule({"build_unit_id": "chosen"}, {"os": "linux"}),
                      _rule({"build_unit_id": "chosen"}, {"os": "windows"})])
    selected = policy.select({"build_unit_id": "chosen"})
    assert selected["status"] == "ambiguous"
    assert selected["required_axes"]["os"] is None
    assert selected["reasons"] == ["selection_ambiguous:os"]


def test_32bit_selection_is_blocked_but_observed_declaration_is_preserved():
    unit = {"build_unit_id": "chosen", "observed_arch": "x86"}
    selected = _policy([_rule({"build_unit_id": "chosen"}, {"isa": "x86"})]).select(unit)
    assert "32bit_selection_forbidden" in selected["reasons"]
    assert unit["observed_arch"] == "x86"


def test_unknown_policy_fields_fail_closed():
    with pytest.raises(ValueError, match="unsupported"):
        parse_build_selection({"schema": SCHEMA, "policy_id": "inline/1",
                               "ambiguity_policy": "default", "rules": []})


@pytest.mark.parametrize("alias,expected", [
    ("amd64", "x86_64"), ("x64", "x86_64"), ("aarch64", "arm64"), ("arm64-v8a", "arm64"),
])
def test_selection_uses_canonical_64bit_aliases(alias, expected):
    selected = _policy([_rule({"build_unit_id": "chosen"}, {"isa": alias})]).select({"build_unit_id": "chosen"})
    assert selected["required_axes"]["isa"] == expected
    assert "32bit_selection_forbidden" not in selected["reasons"]


@pytest.mark.parametrize("alias", ["i386", "i686", "arm32", "armeabi-v7a"])
def test_every_recognized_native_32bit_alias_remains_unselectable(alias):
    selected = _policy([_rule({"build_unit_id": "chosen"}, {"isa": alias})]).select({"build_unit_id": "chosen"})
    assert "32bit_selection_forbidden" in selected["reasons"]


def test_wasm32_is_allowed_by_default_and_recorded_in_policy_identity():
    policy = _policy([_rule({"build_unit_id": "chosen"}, {"isa": "wasm32"})])
    selected = policy.select({"build_unit_id": "chosen"})
    assert policy.view()["allowed_32bit_isas"] == ["wasm32"]
    assert selected["required_axes"]["isa"] == "wasm32"
    assert selected["reasons"] == [] and selected["status"] == "selected"


def test_empty_exemption_list_forbids_wasm32_and_changes_policy_identity():
    rules = [_rule({"build_unit_id": "chosen"}, {"isa": "wasm32"})]
    strict = parse_build_selection({"schema": SCHEMA, "policy_id": "inline/1", "ambiguity_policy": "block",
                                    "allowed_32bit_isas": [], "rules": rules})
    assert "32bit_selection_forbidden" in strict.select({"build_unit_id": "chosen"})["reasons"]
    assert strict.sha256 != _policy(rules).sha256


def test_exemption_list_canonicalizes_aliases_and_round_trips_through_view():
    policy = parse_build_selection({"schema": SCHEMA, "policy_id": "inline/1", "ambiguity_policy": "block",
                                    "allowed_32bit_isas": ["i686", "wasm32"],
                                    "rules": [_rule({"build_unit_id": "chosen"}, {"isa": "x86"})]})
    assert policy.allowed_32bit_isas == ("wasm32", "x86")
    assert "32bit_selection_forbidden" not in policy.select({"build_unit_id": "chosen"})["reasons"]
    assert parse_build_selection(policy.view()) == policy


@pytest.mark.parametrize("allowed", [["x86_64"], ["invented"], "wasm32", [1]])
def test_exemption_list_accepts_only_recognized_32bit_isas(allowed):
    with pytest.raises(ValueError, match="allowed_32bit_isas"):
        parse_build_selection({"schema": SCHEMA, "policy_id": "inline/1", "ambiguity_policy": "block",
                               "allowed_32bit_isas": allowed, "rules": []})


def test_unrecognized_isa_does_not_create_an_unbounded_policy_escape():
    with pytest.raises(ValueError, match="ISA"):
        _policy([_rule({"build_unit_id": "chosen"}, {"isa": "invented-hardware"})])


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_declared_mobile_scope_does_not_invent_device_or_hardware_policy(platform):
    selected = _policy([_rule({"declared_platform": platform}, {"os": platform})]).select(
        {"build_unit_id": "mobile", "build_system": "cmake", "declared_platform": platform})
    assert selected["required_axes"]["os"] == platform
    for axis in ("isa", "sdk", "deployment", "device_kind", "hardware_generation"):
        assert selected["required_axes"][axis] is None


@pytest.mark.parametrize("system,platform", [
    ("msbuild", "windows"), ("vcbuild", "windows"),
    ("make", "linux"), ("autotools", "linux"), ("cmake", "linux"),
])
def test_missing_policy_retains_only_confirmed_legacy_defaults(system, platform):
    policy = parse_build_selection(None)
    assert {rule["selectors"]["build_system"] for rule in policy.rules} == {
        "msbuild", "vcbuild", "make", "autotools", "cmake"}
    selected = policy.select({"build_unit_id": "legacy", "build_system": system})
    assert selected["status"] == "selected"
    assert selected["required_axes"]["os"] == platform
    assert selected["required_axes"]["isa"] == "x86_64"
    assert selected["reasons"] == []


@pytest.mark.parametrize("system,declared_platform", [
    ("dotnet", None), ("direct-native", None), ("go", None),
    ("cargo", None), ("rustc", None), ("gradle", "android"), ("xcode", "ios"),
])
def test_missing_policy_leaves_other_build_systems_unbound(system, declared_platform):
    unit = {"build_unit_id": "unbound", "build_system": system,
            "declared_platform": declared_platform, "observed_arch": "x86"}
    original = copy.deepcopy(unit)
    selected = parse_build_selection(None).select(unit)
    assert selected["reasons"] == ["selection_unbound"]
    assert all(value is None for value in selected["required_axes"].values())
    assert selected["status"] != "selected"
    assert unit == original


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_explicit_go_selection_preserves_observed_source_facts(platform):
    unit = {"build_unit_id": "explicit-go", "build_system": "go", "family": "go",
            "build_variant": {"target_arch": None}, "descriptor_facts": {"declared_os": None}}
    original = copy.deepcopy(unit)
    selected = _policy([_rule({"build_unit_id": unit["build_unit_id"]},
                              {"os": platform, "isa": "x86_64"})]).select(unit)
    assert selected["status"] == "selected"
    assert selected["required_axes"]["os"] == platform
    assert selected["required_axes"]["isa"] == "x86_64"
    assert selected["reasons"] == []
    assert unit == original
