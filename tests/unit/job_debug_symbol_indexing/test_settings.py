"""The closed, bounded settings the job parses, and the build-image identity it accepts from a
language-build receipt."""
from __future__ import annotations

import pytest

from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.execution import SymbolIntegrityError, build_image_identity

BUILD_IMAGE = "sha256:" + "d" * 64


@pytest.mark.parametrize("settings", [
    {"unknown": True}, {"compiler_target": "gcc"}, {"max_artifacts": 0}, {"max_artifacts": 4097},
    {"enabled": "true"}, {"reader": {"max_records": True}},
    {"reader": {"timeout_seconds": float("inf")}}, {"reader": {"unknown": 1}},
    {"reader": {"max_records": 10**400}}, {"reader": {"max_records": 1000001}}, {"reader": {"max_depth": 0}},
    {"reader": {"tools": {"llvm_dwarfdump": {"path": "tool"}}}},
], ids=lambda value: next(iter(value)) + ":" + str(next(iter(value.values())))[:24])
def test_settings_are_bounded_and_closed(settings) -> None:
    with pytest.raises(ValueError):
        parse_debug_symbol_settings(settings)


def test_host_path_settings_are_rejected_instead_of_ignored() -> None:
    with pytest.raises(ValueError, match="unknown debug-symbol reader settings"):
        parse_debug_symbol_settings({"reader": {"tools": {
            "llvm_dwarfdump": {"path": "C:\\approved\\llvm-dwarfdump.exe", "sha256": "a" * 64}}}})


def test_settings_defaults_match_the_shipped_reader_bounds() -> None:
    settings = parse_debug_symbol_settings({})
    assert settings == {"enabled": True, "max_artifacts": 128, "compiler_target": "clang",
                        "reader": {"max_input_bytes": 536870912, "max_output_bytes": 16777216,
                                   "max_records": 100000, "max_depth": 128, "timeout_seconds": 120}}
    assert parse_debug_symbol_settings({"compiler_target": "msvc", "reader": {"timeout_seconds": 2.5}})["reader"][
        "timeout_seconds"] == 2.5
    assert parse_debug_symbol_settings({"enabled": False})["enabled"] is False


@pytest.mark.parametrize("image", [
    None, {}, {"image_id": "mutable:tag", "user": "10001:10001"},
    {"image_id": BUILD_IMAGE, "user": "0:0"}, {"image_id": BUILD_IMAGE},
    {"image_id": BUILD_IMAGE.upper(), "user": "10001:10001"},
], ids=["none", "empty", "tag", "root", "no-user", "upper"])
def test_unpinned_or_root_build_identity_is_rejected(image) -> None:
    with pytest.raises(SymbolIntegrityError):
        build_image_identity(image)


def test_build_identity_keeps_only_the_pinned_image_and_its_unprivileged_user() -> None:
    assert build_image_identity({"image_id": BUILD_IMAGE, "user": "10001:10001", "image_tag": "x"}) == {
        "image_id": BUILD_IMAGE, "user": "10001:10001"}
