from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from appsec_review.config import load_config
from appsec_review.config.build_outputs import (
    BuildOutputPolicy, parse_build_outputs, reject_misplaced,
)

ROOT = Path(__file__).parents[1]
_BLOCK = re.compile(r"\n\[build_outputs\]\n.*?(?=\n\[runtime\]\n)", re.S)


def _config(tmp_path: Path, block: str = "", *, extra: str = "") -> Path:
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    assert _BLOCK.search(text)
    text = _BLOCK.sub(lambda _match: "\n" + block, text) + extra
    path = tmp_path / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _shipped() -> BuildOutputPolicy:
    policy = load_config(ROOT / "appsec-review.toml").job("job_language_build").build_outputs
    assert policy is not None
    return policy


def test_shipped_defaults_reach_exactly_the_three_build_jobs() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    policy = _shipped()
    assert [rule.name for rule in policy.exclusions] == ["cmake-fetchcontent-subbuild", "node-bundler-cache"]
    assert policy.heuristic_min_confidence == "medium"
    for job_id in ("job_project_build", "job_sanitizer_build"):
        if job_id in config.jobs:
            assert config.job(job_id).build_outputs == policy
    assert config.job("job_target_catalog").build_outputs is None
    resolved = json.loads(config.resolved_json)
    assert resolved["build_outputs"] == policy.view()


def test_shipped_fetchcontent_rule_is_native_only_and_matches_subbuild_directories() -> None:
    policy = _shipped()
    native = [(rule.pattern, exclusion.name) for rule, exclusion in policy.rules_for("native")]
    assert native == [("*-subbuild/", "cmake-fetchcontent-subbuild")]
    rule = policy.rules_for("native")[0][0]
    assert rule.matches_directory("build/_deps/fmt-subbuild")
    assert rule.matches("build/_deps/fmt-subbuild/CMakeLists.txt")
    assert not rule.matches_directory("build/_deps/fmt-build")
    assert not rule.matches("build/_deps/fmt-src/include/fmt/core.h")


@pytest.mark.parametrize(("path", "expected"), [
    ("node_modules/.cache/babel-loader/a.json", True),
    ("node_modules/.vite/deps/react.js", True),
    ("packages/web/node_modules/.cache/terser/x", True),
    ("apps/a/b/node_modules/.vite/deps/_metadata.json", True),
    (".vite/deps/react.js", False),
    ("web/.vite/deps/react.js", False),
    ("node_modules/react/index.js", False),
    ("packages/web/node_modules/react/cjs/react.production.js", False),
    ("node_modules/.package-lock.json", False),
    ("src/.cache/x.js", False),
])
def test_shipped_node_bundler_cache_rule_matches_root_and_nested_caches_only(path: str, expected: bool) -> None:
    rules = _shipped().rules_for("node")
    assert {exclusion.name for _rule, exclusion in rules} == {"node-bundler-cache"}
    assert any(rule.matches(path) for rule, _exclusion in rules) is expected


def test_node_bundler_cache_rule_prunes_cache_directories_but_not_node_modules() -> None:
    rules = [rule for rule, _exclusion in _shipped().rules_for("node")]
    for directory in ("node_modules/.cache", "node_modules/.vite", "packages/web/node_modules/.vite"):
        assert any(rule.matches_directory(directory) for rule in rules), directory
    for directory in ("node_modules", ".vite", "packages/web/node_modules", "node_modules/react"):
        assert not any(rule.matches_directory(directory) for rule in rules), directory


def test_families_filter_rules_and_an_omitted_list_applies_to_every_family() -> None:
    policy = parse_build_outputs({"exclusions": [
        {"name": "everywhere", "reason": "all", "patterns": ["gen-out/"]},
        {"name": "rust-only", "reason": "rust", "patterns": ["target/tmp/"], "families": ["rust"]},
    ]})
    assert [exclusion.name for _rule, exclusion in policy.rules_for("native")] == ["everywhere"]
    assert [exclusion.name for _rule, exclusion in policy.rules_for("rust")] == ["everywhere", "rust-only"]
    assert all(rule.scope == "build_outputs" for rule, _exclusion in policy.rules_for("rust"))


def test_absent_table_gives_defaults_without_rules() -> None:
    policy = parse_build_outputs(None)
    assert policy == BuildOutputPolicy()
    assert policy.exclusions == ()
    assert policy.discovery.max_layout_roots == 512 and policy.discovery.cmake_file_api is True


def test_identity_is_stable_and_changes_with_any_policy_field() -> None:
    value = {"heuristic_min_confidence": "high", "discovery": {"max_kept_per_root": 8},
             "exclusions": [{"name": "a", "reason": "r", "patterns": ["x/"]}]}
    first = parse_build_outputs(value)
    assert first.identity == parse_build_outputs(json.loads(json.dumps(value))).identity
    assert len(first.identity) == 64
    changed = [
        {**value, "heuristic_min_confidence": "low"},
        {**value, "discovery": {"max_kept_per_root": 9}},
        {**value, "exclusions": [{"name": "a", "reason": "r", "patterns": ["y/"]}]},
        {**value, "exclusions": [{"name": "b", "reason": "r", "patterns": ["x/"]}]},
        {**value, "exclusions": [{"name": "a", "reason": "r", "patterns": ["x/"], "families": ["native"]}]},
    ]
    for other in changed:
        assert parse_build_outputs(other).identity != first.identity, other


@pytest.mark.parametrize(("value", "message"), [
    ([], "must be a table"),
    ({"heuristics": "medium"}, "unknown keys: heuristics"),
    ({"heuristic_min_confidence": "fact"}, "heuristic_min_confidence"),
    ({"discovery": {"max_roots": 1}}, "discovery has unknown keys"),
    ({"discovery": {"max_layout_roots": 0}}, "positive integer"),
    ({"discovery": {"max_layout_roots": True}}, "positive integer"),
    ({"discovery": {"cmake_file_api": "yes"}}, "boolean"),
    ({"exclusions": {"name": "a"}}, "array of tables"),
    ({"exclusions": [{"name": "A b", "reason": "r", "patterns": ["x"]}]}, r"name must match"),
    ({"exclusions": [{"name": "a", "reason": " ", "patterns": ["x"]}]}, "reason"),
    ({"exclusions": [{"name": "a", "reason": "r"}]}, "patterns is required"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": []}]}, "at least one pattern"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["/abs/"]}]}, "target-relative"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["a/../b"]}]}, "target-relative"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["x", "x"]}]}, "repeats"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["x"], "families": ["cobol"]}]}, "families"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["x"], "families": ["go", "go"]}]},
     "repeats a family"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["x"], "scope": "global"}]}, "unknown keys: scope"),
    ({"exclusions": [{"name": "a", "reason": "r", "patterns": ["x"]},
                     {"name": "a", "reason": "s", "patterns": ["y"]}]}, "repeats names: a"),
])
def test_invalid_policies_fail(value: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_build_outputs(value)


def test_pattern_errors_name_the_offending_rule() -> None:
    with pytest.raises(ValueError, match=r"build_outputs\.exclusions\[1\]\.patterns"):
        parse_build_outputs({"exclusions": [{"name": "a", "reason": "r", "patterns": ["x"]},
                                            {"name": "b", "reason": "r", "patterns": [""]}]})


def test_job_level_build_output_tables_fail_rather_than_being_ignored(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="top-level table"):
        reject_misplaced("job_language_build", {"build_outputs": {}})
    with pytest.raises(ValueError, match="top-level table"):
        reject_misplaced("job_project_build", {"settings": {"build_outputs": {}}})
    reject_misplaced("job_language_build", {"settings": {"artifact_count_limit": 1}})
    path = _config(tmp_path, '[build_outputs]\nheuristic_min_confidence = "high"\n',
                   extra='\n[jobs.job_language_build.build_outputs]\nheuristic_min_confidence = "low"\n')
    with pytest.raises(ValueError, match="jobs.job_language_build.build_outputs is not supported"):
        load_config(path)


def test_build_jobs_still_refuse_job_level_path_exclusions(tmp_path: Path) -> None:
    path = _config(tmp_path, extra='\n[jobs.job_language_build.exclusions]\npatterns = ["build/"]\n')
    with pytest.raises(ValueError, match="not supported"):
        load_config(path)


def test_a_configured_table_is_resolved_into_the_frozen_configuration(tmp_path: Path) -> None:
    block = ('[build_outputs]\nheuristic_min_confidence = "off"\n\n'
             '[[build_outputs.exclusions]]\nname = "vendored-out"\nreason = "vendored prebuilt output"\n'
             'patterns = ["third_party/prebuilt/"]\n')
    config = load_config(_config(tmp_path, block))
    policy = config.job("job_language_build").build_outputs
    assert policy is not None and policy.heuristic_min_confidence == "off"
    assert [exclusion.name for exclusion in policy.exclusions] == ["vendored-out"]
    assert json.loads(config.resolved_json)["build_outputs"]["exclusions"] == [
        {"name": "vendored-out", "reason": "vendored prebuilt output", "patterns": ["third_party/prebuilt/"]}]
    assert policy.identity != _shipped().identity
