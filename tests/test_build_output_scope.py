"""Build-output dispositions: the per-tree recorder and the pruning walk the cataloguers share."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from appsec_review.config.build_outputs import BuildOutputDiscovery, BuildOutputPolicy, parse_build_outputs
from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions
from appsec_review.jobs.build_output_scope import (
    SCHEMA, BuildOutputDispositions, conflict_gap, heuristic_gap, summarized_content_gap,
)
from appsec_review.jobs.job_language_build import job as language_build_job
from appsec_review.jobs.job_language_build.job import _catalog, _snapshot
from tests.test_build_output_mapping import _cmake_project, _elf, _write

FETCHCONTENT = parse_build_outputs({"exclusions": [{
    "name": "cmake-fetchcontent-subbuild", "reason": "FetchContent download sub-builds",
    "patterns": ["*-subbuild/"], "families": ["native"]}]})


def _fact(dispositions: BuildOutputDispositions, root: str, disposition: str, **extra) -> bool:
    values = {"basis": "build-system-fact", "name": "cmake-fetchcontent", "reason": "fetched dependency",
              "confidence": "fact", "evidence_ref": "build/CMakeCache.txt", **extra}
    return dispositions.classify_tree(root, disposition=disposition, **values)


def _fetchcontent_workspace(workspace: Path) -> None:
    _write(workspace, "build/CMakeFiles/app.dir/main.c.o", _elf(1))
    _write(workspace, "build/app", _elf(3, interpreter=True))
    _write(workspace, "build/_deps/fmt-src/include/fmt/core.h", "#pragma once\n")
    _write(workspace, "build/_deps/fmt-src/src/format.cc", "int f() { return 1; }\n")
    _write(workspace, "build/_deps/fmt-build/CMakeFiles/fmt.dir/src/format.cc.o", _elf(1))
    _write(workspace, "build/_deps/fmt-build/libfmt.a", b"!<arch>\nmember")
    _write(workspace, "build/_deps/fmt-subbuild/CMakeLists.txt", "project(fmt-populate)\n")
    _write(workspace, "build/_deps/fmt-subbuild/fmt-populate-prefix/src/stamp.o", _elf(1))


def _classified(policy: BuildOutputPolicy | None = None) -> BuildOutputDispositions:
    dispositions = BuildOutputDispositions(policy if policy is not None else FETCHCONTENT, family="native")
    assert _fact(dispositions, "build/_deps/fmt-src", "supply_chain", scope_role="build_dependency")
    assert _fact(dispositions, "build/_deps/fmt-build", "supply_chain", scope_role="build_dependency",
                 keep_linked=True)
    return dispositions


def test_catalog_lists_target_rows_and_keeps_only_dependency_libraries(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _fetchcontent_workspace(workspace)
    dispositions = _classified()

    artifacts, gaps = _catalog(tmp_path, workspace, {}, 100, "unit", "native", dispositions=dispositions)

    rows = {row["workspace_path"]: row for row in artifacts}
    assert set(rows) == {"build/CMakeFiles/app.dir/main.c.o", "build/app", "build/_deps/fmt-build/libfmt.a"}
    kept = rows["build/_deps/fmt-build/libfmt.a"]
    assert (kept["scope_role"], kept["analysis_lane"], kept["build_output_root"]) == (
        "build_dependency", "supply_chain", "build/_deps/fmt-build")
    assert rows["build/app"]["analysis_lane"] == "target"
    assert not any("subbuild" in gap or "fmt-src" in gap for gap in gaps)

    document = dispositions.document()
    assert document["schema"] == SCHEMA and document["policy_identity"] == FETCHCONTENT.identity
    assert document["configured_exclusions"] == [{
        "path": "build/_deps/fmt-subbuild", "name": "cmake-fetchcontent-subbuild", "pattern": "*-subbuild/",
        "scope": "build_outputs", "files": 2}]
    roots = {root["root"]: root for root in document["roots"]}
    assert roots["build/_deps/fmt-src"]["files"] == 2 and roots["build/_deps/fmt-src"]["kept"] == []
    assert roots["build/_deps/fmt-build"]["kept"] == ["build/_deps/fmt-build/libfmt.a"]
    assert dispositions.summary() == {
        "supply_chain_trees": 2, "excluded_trees": 1, "excluded_files": 5, "kept_rows": 1,
        "heuristic_dispositions": 0, "conflicts": 0, "layout_sources_read": 0}


def test_pruned_trees_are_never_hashed_and_the_catalog_stays_a_manifest_subset(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    _fetchcontent_workspace(workspace)
    manifest = _snapshot(workspace, 1000)
    assert "build/_deps/fmt-src/src/format.cc" in manifest
    assert "build/_deps/fmt-subbuild/fmt-populate-prefix/src/stamp.o" in manifest
    hashed: list[str] = []
    real = language_build_job.file_sha256

    def counting(path: Path) -> str:
        hashed.append(Path(path).relative_to(workspace).as_posix())
        return real(path)

    monkeypatch.setattr(language_build_job, "file_sha256", counting)
    artifacts, _gaps = _catalog(tmp_path, workspace, {}, 100, "unit", "native", dispositions=_classified())

    assert sorted(hashed) == sorted(row["workspace_path"] for row in artifacts)
    assert not any("fmt-src" in path or "fmt-subbuild" in path or "fmt.dir" in path for path in hashed)
    assert {row["workspace_path"] for row in artifacts} <= set(manifest)
    assert all(manifest[row["workspace_path"]] == row["sha256"] for row in artifacts)


def test_deepest_registered_root_governs_and_a_per_file_root_carves_out_target_content(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "third_party/dep/lib.o", _elf(1))
    _write(workspace, "third_party/dep/generated/ours.o", _elf(1))
    dispositions = BuildOutputDispositions(family="native")
    _fact(dispositions, "third_party/dep", "supply_chain", scope_role="build_dependency")
    _fact(dispositions, "third_party/dep/generated", "per_file")

    walked = dict(dispositions.walk(workspace))

    assert list(walked) == ["third_party/dep/generated/ours.o"]
    decision = walked["third_party/dep/generated/ours.o"]
    assert (decision.root, decision.disposition, decision.kept) == ("third_party/dep/generated", "per_file", False)


def test_explicit_keep_paths_are_yielded_and_unlisted_files_stay_counted(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "out/dep/libdep.so", _elf(3))
    _write(workspace, "out/dep/manifest.json", "{}")
    _write(workspace, "out/dep/notes.txt", "x")
    dispositions = BuildOutputDispositions(family="native")
    _fact(dispositions, "out/dep", "supply_chain", scope_role="shipped_dependency", keep=["out/dep/manifest.json"])

    walked = dict(dispositions.walk(workspace))

    assert list(walked) == ["out/dep/manifest.json"]
    assert walked["out/dep/manifest.json"].scope_role == "shipped_dependency"
    assert dispositions.roots()[0]["files"] == 3


def test_configured_exclusion_wins_over_every_root_beneath_it_and_is_never_a_gap(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "build/_deps/x-subbuild/inner/lib.a", b"!<arch>\n")
    _write(workspace, "build/_deps/x-subbuild/top.o", _elf(1))
    dispositions = BuildOutputDispositions(FETCHCONTENT, family="native")
    _fact(dispositions, "build/_deps/x-subbuild/inner", "supply_chain", scope_role="build_dependency",
          keep_linked=True)

    assert list(dispositions.walk(workspace)) == []
    assert dispositions.document()["configured_exclusions"] == [{
        "path": "build/_deps/x-subbuild", "name": "cmake-fetchcontent-subbuild", "pattern": "*-subbuild/",
        "scope": "build_outputs", "files": 2}]
    assert dispositions.named_gaps() == []


def test_configured_file_rule_applies_inside_classified_trees(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "dep/libdep.a", b"!<arch>\n")
    _write(workspace, "dep/libdep.debug.a", b"!<arch>\n")
    policy = parse_build_outputs({"exclusions": [
        {"name": "debug-archives", "reason": "debug copies", "patterns": ["*.debug.a"]}]})
    dispositions = BuildOutputDispositions(policy, family="native")
    _fact(dispositions, "dep", "supply_chain", scope_role="build_dependency", keep_linked=True)

    assert [path for path, _decision in dispositions.walk(workspace)] == ["dep/libdep.a"]
    assert dispositions.document()["configured_exclusions"] == [{
        "path": "dep/libdep.debug.a", "name": "debug-archives", "pattern": "*.debug.a",
        "scope": "build_outputs", "files": 1}]


def test_rules_for_other_families_do_not_apply(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "build/_deps/x-subbuild/a.o", _elf(1))
    dispositions = BuildOutputDispositions(FETCHCONTENT, family="rust")
    assert [path for path, _decision in dispositions.walk(workspace)] == ["build/_deps/x-subbuild/a.o"]


def test_bookkeeping_projection_is_unchanged(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _cmake_project(workspace)
    exclusions = BookkeepingExclusions()
    dispositions = BuildOutputDispositions(family="native", bookkeeping=exclusions)

    _catalog(tmp_path, workspace, {}, 100, "unit", "native", exclusions, dispositions=dispositions)

    assert exclusions.total == 8
    assert dispositions.document()["bookkeeping"] == exclusions.document()


def test_fact_disagreement_leaves_the_root_per_file_and_names_a_conflict(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "vendor/dep/libdep.a", b"!<arch>\n")
    dispositions = BuildOutputDispositions(family="native")
    _fact(dispositions, "vendor/dep", "supply_chain", scope_role="build_dependency")
    dispositions.classify_tree("vendor/dep", disposition="evidence", basis="execution-capture",
                               name="capture", reason="installed by build", confidence="fact")

    assert [path for path, _decision in dispositions.walk(workspace)] == ["vendor/dep/libdep.a"]
    assert dispositions.conflicts == ("vendor/dep",)
    assert dispositions.named_gaps() == [conflict_gap("vendor/dep")]
    assert dispositions.roots()[0]["disposition"] == "per_file"


def test_a_higher_ranked_basis_replaces_a_lower_one_without_conflict() -> None:
    dispositions = BuildOutputDispositions(family="native")
    dispositions.classify_tree("deps/x", disposition="supply_chain", basis="heuristic", name="deps-dir",
                               reason="directory name", confidence="high", scope_role="build_dependency")
    _fact(dispositions, "deps/x", "excluded")
    assert dispositions.roots()[0]["disposition"] == "excluded"
    assert dispositions.roots()[0]["basis"] == "build-system-fact"
    dispositions.classify_tree("deps/x", disposition="supply_chain", basis="heuristic", name="deps-dir",
                               reason="directory name", confidence="high")
    assert dispositions.roots()[0]["disposition"] == "excluded"
    assert dispositions.conflicts == ()


@pytest.mark.parametrize(("threshold", "confidence", "expected"), [
    ("medium", "low", "per_file"), ("medium", "medium", "supply_chain"),
    ("high", "medium", "per_file"), ("low", "low", "supply_chain"), ("off", "high", "per_file"),
])
def test_heuristics_below_the_threshold_stay_per_file(threshold: str, confidence: str, expected: str) -> None:
    dispositions = BuildOutputDispositions(parse_build_outputs({"heuristic_min_confidence": threshold}))
    dispositions.classify_tree("third_party/x", disposition="supply_chain", basis="heuristic", name="vendor-dir",
                               reason="directory name", confidence=confidence, scope_role="build_dependency")
    root = dispositions.roots()[0]
    assert (root["disposition"], root["confidence"], root["basis"]) == (expected, confidence, "heuristic")
    assert dispositions.summary()["heuristic_dispositions"] == 1


def test_kept_rows_and_registered_roots_are_bounded_with_named_gaps(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for name in ("a", "b", "c"):
        _write(workspace, f"dep/lib{name}.a", b"!<arch>\n")
    policy = BuildOutputPolicy(discovery=BuildOutputDiscovery(max_kept_per_root=2, max_layout_roots=1))
    dispositions = BuildOutputDispositions(policy, family="native")
    assert _fact(dispositions, "dep", "supply_chain", scope_role="build_dependency", keep_linked=True)
    assert not _fact(dispositions, "other", "excluded")

    assert [path for path, _decision in dispositions.walk(workspace)] == ["dep/liba.a", "dep/libb.a"]
    gaps = dispositions.named_gaps()
    assert gaps[0].startswith("build-output-kept-bound-exceeded: dep kept 2 linked files; 1 more")
    assert gaps[1].startswith("build-output-root-bound-exceeded: 1 roots")


def _npm_package(dispositions: BuildOutputDispositions, prefix: str, package: str) -> bool:
    return dispositions.classify_tree(
        f"{prefix}/{package}", disposition="supply_chain", basis="installer-record",
        name="npm-installed-package", reason="verified npm package", confidence="fact",
        evidence_ref=f"{prefix}/.package-lock.json", scope_role="build_dependency", bound_group=prefix)


def test_one_npm_installer_prefix_counts_once_against_max_layout_roots() -> None:
    dispositions = BuildOutputDispositions(BuildOutputPolicy(), family="node")
    assert all(_npm_package(dispositions, "node_modules", f"pkg-{index:04d}") for index in range(1200))
    # The prefix used one of the 512; the other layout roots keep the remaining 511.
    assert all(_fact(dispositions, f"other/{index}", "excluded") for index in range(511))
    assert not _fact(dispositions, "other/overrun", "excluded")
    assert not _npm_package(dispositions, "web/node_modules", "react")
    assert _npm_package(dispositions, "node_modules", "late-package")
    assert len([root for root in dispositions.roots() if root["name"] == "npm-installed-package"]) == 1201
    assert dispositions.named_gaps() == [
        "build-output-root-bound-exceeded: 2 roots beyond max_layout_roots stay per-file target content"]


def test_grouped_npm_packages_are_all_classified_without_root_bound_gaps(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for prefix in ("node_modules", "web/node_modules"):
        for index in range(3):
            _write(workspace, f"{prefix}/pkg-{index}/index.js", "module.exports = 1;\n")
    _write(workspace, "web/src/app.js", "export default 1;\n")
    policy = BuildOutputPolicy(discovery=BuildOutputDiscovery(max_layout_roots=2))
    dispositions = BuildOutputDispositions(policy, family="node")
    assert all(_npm_package(dispositions, prefix, f"pkg-{index}")
               for prefix in ("node_modules", "web/node_modules") for index in range(3))

    assert [path for path, _decision in dispositions.walk(workspace)] == ["web/src/app.js"]
    roots = dispositions.roots()
    assert len(roots) == 6 and all(root["files"] == 1 for root in roots)
    assert {root["bound_group"] for root in roots} == {"node_modules", "web/node_modules"}
    assert dispositions.named_gaps() == []
    assert "bound_group" not in _classified().roots()[0]


def test_bound_group_must_contain_its_root() -> None:
    with pytest.raises(ValueError, match="outside its bound group"):
        BuildOutputDispositions().classify_tree(
            "web/node_modules/react", disposition="supply_chain", basis="installer-record", name="npm",
            reason="r", confidence="fact", bound_group="node_modules")


def test_sanitizer_replay_preserves_bound_groups() -> None:
    from appsec_review.jobs.job_sanitizer_build.job import _dispositions

    original = BuildOutputDispositions(BuildOutputPolicy(), family="node")
    for index in range(3):
        _npm_package(original, "node_modules", f"pkg-{index}")
    policy = BuildOutputPolicy(discovery=BuildOutputDiscovery(max_layout_roots=1))
    replayed = _dispositions({"build_output_dispositions": original.document()}, policy, BookkeepingExclusions())
    assert [root["bound_group"] for root in replayed.roots()] == ["node_modules"] * 3
    assert replayed.named_gaps() == []


def test_walk_skips_symlinks_and_restarts_counts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "dep/a.o", _elf(1))
    _write(workspace, "outside/b.o", _elf(1))
    try:
        os.symlink(workspace / "outside", workspace / "dep" / "link")
    except OSError:
        pytest.skip("symlinks are unavailable")
    dispositions = BuildOutputDispositions(family="native")
    _fact(dispositions, "dep", "excluded")
    for _attempt in range(2):
        assert [path for path, _decision in dispositions.walk(workspace)] == ["outside/b.o"]
        assert dispositions.roots()[0]["files"] == 1


@pytest.mark.parametrize("root", ["", "/abs", "a/../b", "./a"])
def test_roots_must_be_workspace_relative(root: str) -> None:
    with pytest.raises(ValueError, match="workspace-relative"):
        _fact(BuildOutputDispositions(), root, "excluded")


def test_scope_roles_and_enums_are_validated() -> None:
    with pytest.raises(ValueError):
        _fact(BuildOutputDispositions(), "x", "supply_chain", scope_role="not-a-role")
    with pytest.raises(ValueError):
        _fact(BuildOutputDispositions(), "x", "dropped")


def test_gap_formatters() -> None:
    assert summarized_content_gap(3, "FetchContent dependencies", 120, 4096, "build/CMakeCache.txt",
                                  "supply-chain") == (
        "dependency-content-summarized: 3 FetchContent dependencies (120 files, 4096 bytes) recorded by "
        "build/CMakeCache.txt routed to supply-chain review; per-file target review not performed")
    assert heuristic_gap("third_party/x", "supply_chain", "medium") == (
        "build-output-heuristic: third_party/x classified supply_chain by directory name (medium)")
