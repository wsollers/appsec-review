from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from tools.quality.config import GateError, checked_file, load_config, relative_path, unit_selector
from tools.quality.selection import changed_paths, parse_changes, select_tests
from tests.quality.support import git, repository, write


def test_changed_paths_include_rename_delete_and_untracked(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    write(root, "src/appsec_review/removed.py", "value = 1\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Before changes")
    (root / "src/appsec_review/removed.py").unlink()
    git(root, "mv", "src/appsec_review/runtime/contract.py", "src/appsec_review/runtime/renamed.py")
    write(root, "src/appsec_review/untracked.py", "value = 2\n")
    assert changed_paths(root, "HEAD", 10) == (
        "src/appsec_review/removed.py", "src/appsec_review/runtime/contract.py",
        "src/appsec_review/runtime/renamed.py", "src/appsec_review/untracked.py",
    )


@pytest.mark.parametrize("text", ["M\0", "M\0a.py", "R100\0old.py\0", "U\0a.py\0", "Z\0a.py\0"])
def test_malformed_or_unresolved_git_output_fails(text: str) -> None:
    with pytest.raises(GateError, match="git-output"):
        parse_changes(text)


def test_nul_paths_preserve_spaces_and_copy_sides() -> None:
    assert parse_changes("R100\0old name.py\0new name.py\0C80\0a.py\0b.py\0") == (
        "a.py", "b.py", "new name.py", "old name.py",
    )
    assert parse_changes("") == ()


@pytest.mark.parametrize("path", ["../outside", "/outside", "a/../b", "a\\b", "-flag", "a\nb", "tests/a.py::case"])
def test_noncanonical_paths_fail(path: str) -> None:
    with pytest.raises(GateError):
        relative_path(path)


@pytest.mark.parametrize("path", [
    "tests", "tests/integration/test_offline.py", "tests/acceptance/test_small.py",
    "tests/live/test_fixture.py", "tests/test_live_model.py", "tests/test_image_build.py",
    "tests/test_real_model.py", "tests/test_feature_integration.py",
])
def test_manual_or_broad_test_selectors_are_rejected(path: str) -> None:
    with pytest.raises(GateError):
        unit_selector(path)


def test_selection_has_explicit_bounded_fallback(tmp_path: Path) -> None:
    config = load_config(repository(tmp_path / "repo"))
    for paths in ((), ("docs/readme.md",), ("tools/quality/new.py",), ("README.md",)):
        assert select_tests(config, paths).tests == config.unit_tests
    for paths in (("pyproject.toml",), ("src/appsec_review/storage/atomic.py",),
                  ("brand-new-language.unknown",), ("tests/test_new.py",)):
        selection = select_tests(config, paths)
        assert selection.tests == config.unit_tests + config.contract_tests
        assert selection.reasons
    assert "unmapped path" in select_tests(config, ("unmapped",)).reasons[0]
    assert select_tests(config, (), full=True).tests == config.unit_tests + config.contract_tests
    with pytest.raises(GateError, match="no-tests"):
        select_tests(replace(config, unit_tests=()), ())


@pytest.mark.parametrize(("old", "new"), [
    ("version = 1\n", "version = 99\n"),
    ("timeout_seconds = 120", "timeout_seconds = true"),
    ("timeout_seconds = 120", "timeout_seconds = 0"),
    ('"B602"', '"B999"'),
    ('unit_tests = ["tests/test_fixture.py"]', 'unit_tests = []'),
    ('unit_tests = ["tests/test_fixture.py"]', 'unit_tests = ["tests/live/test_fixture.py"]'),
    ('source_roots = ["src/appsec_review", "tools/quality"]', 'source_roots = ["absent"]'),
    ('[tool.appsec-quality]', '[tool.appsec-quality]\nunknown_key = 1'),
])
def test_configuration_rejects_invalid_values(tmp_path: Path, old: str, new: str) -> None:
    root = repository(tmp_path / "repo")
    path = root / "pyproject.toml"
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")
    with pytest.raises(GateError):
        load_config(root)


def test_missing_required_selector_and_malformed_toml_fail(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    (root / "tests/test_fixture.py").unlink()
    with pytest.raises(GateError, match="missing-input"):
        load_config(root)
    write(root, "pyproject.toml", "invalid [\n")
    with pytest.raises(GateError, match="configuration"):
        load_config(root)


def test_outside_symlink_is_not_a_required_input(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    outside = write(tmp_path, "outside.py", "value = 1\n")
    (root / "tests/link.py").symlink_to(outside)
    with pytest.raises(GateError, match="missing-input"):
        checked_file(root, "tests/link.py")


def test_baseline_initialization_cannot_follow_an_external_parent(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    (root / "quality/baseline.json").unlink()
    (root / "quality").rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "quality").symlink_to(outside, target_is_directory=True)
    with pytest.raises(GateError, match="baseline must remain inside"):
        load_config(root)
    assert not (outside / "baseline.json").exists()


def test_missing_base_fails_instead_of_selecting_nothing(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    with pytest.raises(GateError, match="tool-failure"):
        changed_paths(root, "does-not-exist", 10)
