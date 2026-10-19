from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.config.exclusions import ExclusionRule, PathExclusions, job_exclusions
from appsec_review.jobs.cataloging import inventory, source_fingerprint

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(("pattern", "path", "expected"), [
    (".gitignore", ".gitignore", True),
    (".gitignore", "sub/dir/.gitignore", True),
    (".gitignore", "src/gitignore.cpp", False),
    ("*.md", "docs/guide.md", True),
    ("*.md", "src/main.cpp", False),
    ("fixtures", "tests/fixtures/case.cpp", True),
    ("fixtures", "tests/fixtures.cpp", False),
    ("fixtures/", "tests/fixtures/case.cpp", True),
    ("fixtures/", "fixtures", False),
    ("docs/api/", "docs/api/index.md", True),
    ("docs/api/", "other/docs/api/index.md", False),
    ("src/*.cpp", "src/main.cpp", True),
    ("src/*.cpp", "lib/src/main.cpp", False),
    ("third_party/vendored/**", "third_party/vendored/a/b.c", True),
    ("third_party/vendored", "third_party/vendored/a/b.c", True),
    ("third_party/vendored", "third_party/other/b.c", False),
])
def test_pattern_semantics(pattern: str, path: str, expected: bool) -> None:
    assert ExclusionRule(pattern, "global").matches(path) is expected


def test_folder_rules_prune_whole_directories() -> None:
    rules = PathExclusions((ExclusionRule("fixtures/", "global"), ExclusionRule("docs/api/", "global")))
    assert rules.match_directory("tests/fixtures") is not None
    assert rules.match_directory("docs/api") is not None
    assert rules.match_directory("docs") is None


@pytest.mark.parametrize(("value", "message"), [
    ({"patterns": "x"}, "list of strings"),
    ({"patterns": [""]}, "non-empty"),
    ({"patterns": [" x"]}, "surrounding space"),
    ({"patterns": ["/abs"]}, "target-relative"),
    ({"patterns": ["a/../b"]}, "target-relative"),
    ({"patterns": ["a\\b"]}, "target-relative"),
    ({"patterns": ["x", "x"]}, "repeats"),
    ({"patterns": ["x"], "paths": []}, "only a patterns list"),
])
def test_invalid_patterns_fail(value: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        job_exclusions("job_target_catalog", {"exclusions": value}, ())


def test_job_level_patterns_are_refused_where_a_job_cannot_honour_them() -> None:
    with pytest.raises(ValueError, match="not supported"):
        job_exclusions("job_codeql_analysis", {"exclusions": {"patterns": ["x"]}}, ())
    with pytest.raises(ValueError, match="repeats global"):
        job_exclusions("job_target_catalog", {"exclusions": {"patterns": [".gitignore"]}}, (".gitignore",))


def _config(tmp_path: Path, *, global_patterns: list[str], catalog_patterns: list[str]) -> Path:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    current = '[exclusions]\npatterns = [".gitignore"]\n'
    assert current in text
    text = text.replace(current, f"[exclusions]\npatterns = {json.dumps(global_patterns)}\n")
    text += f"\n[jobs.job_target_catalog.exclusions]\npatterns = {json.dumps(catalog_patterns)}\n"
    path = tmp_path / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_config_resolves_global_then_job_patterns_and_freezes_them(tmp_path: Path) -> None:
    config = load_config(_config(tmp_path, global_patterns=[".gitignore"], catalog_patterns=["docs/"]))

    assert [rule.as_dict() for rule in config.job("job_target_catalog").exclusions.rules] == [
        {"pattern": ".gitignore", "scope": "global"}, {"pattern": "docs/", "scope": "job_target_catalog"}]
    assert [rule.pattern for rule in config.job("job_codeql_analysis").exclusions.rules] == [".gitignore"]
    resolved = json.loads(config.resolved_json)
    assert resolved["exclusions"] == {"patterns": [".gitignore"]}
    assert resolved["jobs"]["job_target_catalog"]["exclusions"] == {"patterns": ["docs/"]}
    baseline = load_config(_config(tmp_path, global_patterns=[], catalog_patterns=[]))
    assert baseline.resolved_sha256 != config.resolved_sha256


def test_inventory_leaves_excluded_paths_out_and_lists_each_once(tmp_path: Path) -> None:
    target = tmp_path / "target"
    for relative in (".gitignore", "src/main.cpp", "include/api.hpp", "docs/api/index.md", "docs/readme.md"):
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_text("text\n", encoding="utf-8")
    fingerprint = source_fingerprint(target)
    exclusions = PathExclusions((ExclusionRule(".gitignore", "global"),
                                 ExclusionRule("docs/api/", "job_target_catalog")))

    snapshot = inventory(target, exclusions=exclusions)

    assert [item["path"] for item in snapshot["files"]] == ["docs/readme.md", "include/api.hpp", "src/main.cpp"]
    assert snapshot["configured_exclusions"] == [
        {"path": ".gitignore", "pattern": ".gitignore", "scope": "global"},
        {"path": "docs/api/", "pattern": "docs/api/", "scope": "job_target_catalog"}]
    assert not any(gap["path"] in {".gitignore", "docs/api"} for gap in snapshot["gaps"])
    # Exclusions narrow analysis, never the target's identity.
    assert source_fingerprint(target) == fingerprint
    assert inventory(target)["configured_exclusions"] == []
