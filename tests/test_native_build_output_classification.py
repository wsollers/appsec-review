"""Native build-output classification inside the generic language build (design chunk D)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config.build_outputs import BuildOutputPolicy, parse_build_outputs
from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions
from appsec_review.jobs.build_output_scope import BuildOutputDispositions
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import job as language_build_job, native_outputs
from appsec_review.jobs.job_language_build.job import _catalog, _fingerprint
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256
from tests.capture_fakes import minimal_elf, simulated_executor
from tests.test_build_output_mapping import _elf, _write
from tests.test_language_build import _accepted_project, _fixture
from tests.test_native_layout import _meson

POLICY = parse_build_outputs({"exclusions": [{
    "name": "cmake-fetchcontent-subbuild", "reason": "FetchContent download sub-builds",
    "patterns": ["*-subbuild/"], "families": ["native"]}]})
_SUMMARIZED = "dependency-content-summarized:"
# Keys aggregate_run_metrics sums into throughput totals; the classification event must avoid them.
_SUMMED = {"file_count", "artifact_count", "size_bytes", "processed_bytes", "gap_count", "disposition"}


def _cache(source: str, build: str) -> str:
    return (f"FETCHCONTENT_BASE_DIR:PATH={build}/_deps\n"
            f"CMAKE_HOME_DIRECTORY:INTERNAL={source}\nCMAKE_CACHEFILE_DIR:INTERNAL={build}\n"
            f"app_SOURCE_DIR:STATIC={source}\napp_BINARY_DIR:STATIC={build}\napp_IS_TOP_LEVEL:STATIC=ON\n"
            f"fmt_SOURCE_DIR:STATIC={build}/_deps/fmt-src\nfmt_BINARY_DIR:STATIC={build}/_deps/fmt-build\n"
            "fmt_IS_TOP_LEVEL:STATIC=OFF\n")


def _fetchcontent_build(workspace: Path, prefix: str = "") -> None:
    """What a configured and built CMake FetchContent project leaves in its workspace."""
    build = f"{prefix}build"
    logical = "/workspace" + (f"/{prefix.rstrip('/')}" if prefix else "")
    _write(workspace, f"{build}/CMakeCache.txt", _cache(logical, f"{logical}/build"))
    _write(workspace, f"{build}/_deps/fmt-src/include/fmt/core.h", "#pragma once\n")
    _write(workspace, f"{build}/_deps/fmt-src/src/format.cc", "int f() { return 1; }\n")
    _write(workspace, f"{build}/_deps/fmt-build/CMakeFiles/fmt.dir/src/format.cc.o", _elf(1))
    _write(workspace, f"{build}/_deps/fmt-build/libfmt.a", b"!<arch>\nmember")
    _write(workspace, f"{build}/_deps/fmt-subbuild/CMakeLists.txt", "project(fmt-populate)\n")
    _write(workspace, f"{build}/_deps/fmt-subbuild/fmt-populate-prefix/src/stamp.o", _elf(1))
    _write(workspace, f"{build}/CMakeFiles/app.dir/main.cpp.o", _elf(1))
    _write(workspace, f"{build}/app", minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))


def _before(workspace: Path, *paths: str) -> dict[str, str]:
    return {path: file_sha256(workspace / path) for path in paths}


def _classify(workspace: Path, before: dict[str, str], *, policy: BuildOutputPolicy = POLICY,
              build_dir: str = "build", build_system: str = "cmake", capture_complete: bool = True):
    dispositions = BuildOutputDispositions(policy, family="native", bookkeeping=BookkeepingExclusions())
    classification = native_outputs.register(
        dispositions, workspace, build_dir=build_dir, source_dir=".", build_system=build_system,
        preexisting_files=before, captures=[], rows=[], capture_complete=capture_complete)
    artifacts, gaps = _catalog(workspace.parent, workspace, before, 100, "unit", "native",
                               dispositions=dispositions, tagged_outputs=classification.tagged_outputs)
    return dispositions, classification, {row["workspace_path"]: row for row in artifacts}, [
        *gaps, *native_outputs.gaps(dispositions), *classification.gaps]


def test_fetchcontent_trees_leave_only_target_rows_and_one_summarized_gap(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "CMakeLists.txt", "project(app)\n")
    _write(workspace, "main.cpp", "int main() { return 0; }\n")
    _fetchcontent_build(workspace)
    hashed: list[str] = []
    real = language_build_job.file_sha256
    monkeypatch.setattr(language_build_job, "file_sha256",
                        lambda path: hashed.append(path.relative_to(workspace).as_posix()) or real(path))

    dispositions, _classification, rows, gaps = _classify(
        workspace, _before(workspace, "CMakeLists.txt", "main.cpp"))

    target = {path for path, row in rows.items() if row["analysis_lane"] != "supply_chain"}
    assert target == {"build/CMakeFiles/app.dir/main.cpp.o", "build/app"}
    assert rows["build/_deps/fmt-build/libfmt.a"]["analysis_lane"] == "supply_chain"
    assert rows["build/_deps/fmt-build/libfmt.a"]["scope_role"] == "build_dependency"
    assert not any(path.startswith("build/_deps/fmt-src/") for path in hashed)
    document = dispositions.document()
    by_root = {root["root"]: root for root in document["roots"]}
    assert set(by_root) == {"build/_deps/fmt-build", "build/_deps/fmt-src"}
    assert (by_root["build/_deps/fmt-src"]["disposition"], by_root["build/_deps/fmt-src"]["files"]) == (
        "supply_chain", 2)
    assert by_root["build/_deps/fmt-src"]["evidence_ref"] == "build/CMakeCache.txt#fmt_SOURCE_DIR"
    assert [(item["path"], item["name"], item["scope"]) for item in document["configured_exclusions"]] == [
        ("build/_deps/fmt-subbuild", "cmake-fetchcontent-subbuild", "build_outputs")]
    assert not any("fmt-subbuild" in gap for gap in gaps)
    (summarized,) = [gap for gap in gaps if gap.startswith(_SUMMARIZED)]
    total = by_root["build/_deps/fmt-src"]["bytes"] + by_root["build/_deps/fmt-build"]["bytes"]
    assert f"1 native dependency (4 files, {total} bytes)" in summarized
    assert "build/CMakeCache.txt" in summarized and "supply_chain" in summarized
    assert [source["kind"] for source in document["layout_sources"]] == ["cmake-cache"]


def test_meson_wrap_subproject_is_supply_chain(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _meson(workspace)
    _write(workspace, "builddir/app", minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))

    dispositions, _classification, rows, gaps = _classify(
        workspace, {},
        build_dir="builddir", build_system="meson")

    assert rows["builddir/subprojects/zlib-1.3.1/libz.a"]["analysis_lane"] == "supply_chain"
    assert rows["builddir/app"]["analysis_lane"] == "target"
    assert {root["root"]: root["disposition"] for root in dispositions.roots()} == {
        "subprojects/zlib-1.3.1": "supply_chain", "builddir/subprojects/zlib-1.3.1": "supply_chain"}
    assert sum(gap.startswith(_SUMMARIZED) for gap in gaps) == 1


def test_committed_meson_subproject_stays_target(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _meson(workspace)

    dispositions, _classification, rows, gaps = _classify(
        workspace, _before(workspace, "subprojects/zlib-1.3.1/meson.build"),
        build_dir="builddir", build_system="meson")

    library = rows["builddir/subprojects/zlib-1.3.1/libz.a"]
    assert library["analysis_lane"] == "target" and "build_output_root" not in library
    assert {root["disposition"] for root in dispositions.roots()} == {"per_file"}
    assert not any(gap.startswith(_SUMMARIZED) for gap in gaps)


def test_heuristic_medium_reclassifies_and_low_only_annotates(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _write(workspace, "CMakeLists.txt", "project(app)\n")
    _write(workspace, "third_party/foo/CMakeLists.txt", "project(foo)\n")
    _write(workspace, "third_party/foo/libfoo.a", b"!<arch>\nfoo")
    _write(workspace, "third_party/bar/bar.c", "int bar;\n")
    _write(workspace, "third_party/bar/libbar.a", b"!<arch>\nbar")

    dispositions, _classification, rows, gaps = _classify(workspace, _before(workspace, "CMakeLists.txt"))

    by_root = {root["root"]: root for root in dispositions.roots()}
    assert (by_root["third_party/foo"]["disposition"], by_root["third_party/foo"]["confidence"]) == (
        "supply_chain", "medium")
    assert (by_root["third_party/bar"]["disposition"], by_root["third_party/bar"]["confidence"]) == (
        "per_file", "low")
    assert rows["third_party/foo/libfoo.a"]["analysis_lane"] == "supply_chain"
    assert rows["third_party/bar/libbar.a"]["analysis_lane"] == "target"
    assert "third_party/bar/bar.c" in rows  # per-file content is still catalogued
    assert "build-output-heuristic: third_party/foo classified supply_chain by directory name (medium)" in gaps
    assert "build-output-heuristic: third_party/bar classified per_file by directory name (low)" in gaps


def test_root_bound_overrun_is_a_gap_and_the_rest_stays_per_file(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _fetchcontent_build(workspace)
    policy = parse_build_outputs({**POLICY.view(), "discovery": {"max_layout_roots": 1}})

    dispositions, _classification, rows, gaps = _classify(workspace, {}, policy=policy)

    assert [root["root"] for root in dispositions.roots()] == ["build/_deps/fmt-build"]
    assert "build/_deps/fmt-src/src/format.cc" in rows  # fell back to per-file cataloguing
    assert rows["build/_deps/fmt-src/src/format.cc"]["analysis_lane"] != "supply_chain"
    assert any(gap.startswith("build-output-root-bound-exceeded: 1 roots") for gap in gaps)


def test_layout_source_byte_overrun_is_a_gap_and_classifies_nothing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _fetchcontent_build(workspace)
    policy = parse_build_outputs({**POLICY.view(), "discovery": {"max_layout_source_bytes": 16}})

    dispositions, _classification, rows, gaps = _classify(workspace, {}, policy=policy)

    assert not any(root["basis"] != "heuristic" for root in dispositions.roots())
    assert any(gap.startswith("build-output-layout-source-bound-exceeded: build/CMakeCache.txt") for gap in gaps)
    assert "build/_deps/fmt-build/libfmt.a" in rows


def test_incomplete_capture_is_a_gap_but_layout_facts_still_apply(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _fetchcontent_build(workspace)

    dispositions, _classification, _rows, gaps = _classify(workspace, {}, capture_complete=False)

    assert any(gap.startswith("build-output-capture-incomplete:") for gap in gaps)
    assert "build/_deps/fmt-src" in {root["root"] for root in dispositions.roots()}


def test_dependency_outputs_in_mixed_directories_are_tagged_and_loaded_libraries_promoted() -> None:
    rows = [
        {"workspace_path": "build/app", "kind": "executable", "loader_dependencies": ["libfmt.so.10"]},
        {"workspace_path": "build/libmixed.a", "kind": "static-library"},
        {"workspace_path": "build/libfmt.so.10", "kind": "shared-library", "scope_role": "build_dependency",
         "loader_soname": "libfmt.so.10"},
        {"workspace_path": "build/libunused.so", "kind": "shared-library", "scope_role": "build_dependency"},
    ]

    native_outputs.tag_and_promote(rows, {"build/libmixed.a", "build/app.o"})

    assert rows[1]["scope_role"] == "build_dependency"
    assert rows[1]["build_output_tag"] == "dependency-sourced-output"
    assert "scope_role" not in rows[0]
    expected = native_outputs.RUNTIME_DEPENDENCY or "build_dependency"
    assert rows[2]["scope_role"] == expected
    assert rows[3]["scope_role"] == "build_dependency"


def test_build_outputs_policy_changes_the_language_build_fingerprint() -> None:
    dispatch = {"source_fingerprint": "1" * 64, "recipe_identity": "2" * 64, "family": "native",
                "probe_identity": "3" * 64,
                "image": {"dependency_hashes": ["4" * 64], "image_id": "sha256:" + "5" * 64}}
    accepted = {"project_build_handoff_sha256": "6" * 64}
    settings = {"command_timeout_seconds": 1, "output_bytes": 2, "artifact_count_limit": 3,
                "build_capture": {"mode": "required"}, "compiler_artifact_collection_mode": "required",
                "compiler_artifact_collection_overrides": {}, "native": {}}
    baseline = _fingerprint(dispatch, accepted, settings, build_outputs=POLICY)
    for changed in ({**POLICY.view(), "heuristic_min_confidence": "high"},
                    {**POLICY.view(), "discovery": {"cmake_file_api": False}},
                    {**POLICY.view(), "exclusions": []}):
        assert _fingerprint(dispatch, accepted, settings, build_outputs=parse_build_outputs(changed)) != baseline
    assert _fingerprint(dispatch, accepted, settings, build_outputs=parse_build_outputs(POLICY.view())) == baseline


def _fetchcontent_executor(profile):
    def behavior(command, workspace, working_directory, environment, simulation):
        simulation.exec("/usr/bin/cmake", command)
        simulation.tool_call("cmake", command[1:], executable="/usr/bin/cmake")
        if "--build" in command:
            _fetchcontent_build(workspace, f"{working_directory}/")
            source = f"/workspace/{working_directory}/main.cpp"
            obj = f"/workspace/{working_directory}/build/CMakeFiles/app.dir/main.cpp.o"
            _write(workspace, f"{working_directory}/build/compile_commands.json", json.dumps([{
                "directory": f"/workspace/{working_directory}/build", "file": source,
                "arguments": ["clang++", "-c", source, "-o", obj], "output": obj}]))
            compiler = ("clang++", "-c", source, "-o", obj)
            simulation.exec("/usr/bin/clang++", compiler)
            simulation.tool_call("clang++", compiler[1:], executable="/usr/bin/clang++")
            linker = ("clang++", obj, f"/workspace/{working_directory}/build/_deps/fmt-build/libfmt.a",
                      "-o", f"/workspace/{working_directory}/build/app")
            simulation.exec("/usr/bin/clang++", linker)
            simulation.tool_call("clang++", linker[1:], executable="/usr/bin/clang++")
        return 0, b"ok", b""

    return simulated_executor(profile, behavior)


def test_language_build_receipt_classifies_a_fetchcontent_build(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])

    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: _fetchcontent_executor(profile))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)

    run_root = config.runtime.runs_dir / run_id
    (receipt,) = load_accepted_language_build(run_root)["receipts"]
    assert receipt["terminal_status"] == "SUCCEEDED"
    rows = {row["workspace_path"]: row for row in receipt["artifacts"]}
    assert {path for path, row in rows.items()
            if row["kind"] in {"object", "executable"} and row["analysis_lane"] != "supply_chain"} == {
        "native/build/CMakeFiles/app.dir/main.cpp.o", "native/build/app"}
    assert rows["native/build/_deps/fmt-build/libfmt.a"]["analysis_lane"] == "supply_chain"
    assert not any("/_deps/fmt-src/" in path or "/_deps/fmt-subbuild/" in path for path in rows)
    document = receipt["build_output_dispositions"]
    assert document["schema"] == "appsec-review/build-output-dispositions/1"
    assert {root["root"] for root in document["roots"]} == {
        "native/build/_deps/fmt-build", "native/build/_deps/fmt-src"}
    assert [item["path"] for item in document["configured_exclusions"]] == ["native/build/_deps/fmt-subbuild"]
    assert sum(gap.startswith(_SUMMARIZED) for gap in receipt["gaps"]) == 1
    assert not any("fmt-subbuild" in gap for gap in receipt["gaps"])
    query = "native/build/.cmake/api/v1/query/client-appsec-review/query.json"
    assert receipt["prepared_inputs"][0]["path"] == query
    assert any(gap.startswith("cmake-file-api-reply-missing:") for gap in receipt["gaps"])
    manifest = json.loads((run_root / receipt["workspace_manifest"]["path"]).read_text(encoding="utf-8"))
    assert {query, "native/build/_deps/fmt-src/src/format.cc",
            "native/build/_deps/fmt-subbuild/CMakeLists.txt"} <= set(manifest["files"])
    records = [json.loads(line) for line in (run_root / "data" / "logs" / "pipeline.jsonl").read_text(
        encoding="utf-8").splitlines()]
    (classified,) = [record.get("details", record) for record in records
                     if record["event_type"] == "BUILD_OUTPUT_CLASSIFIED"]
    assert classified["supply_chain_trees"] == 2 and classified["target_rows"] == 1  # app; objects take the evidence lane
    assert not _SUMMED & set(classified)
    (completed,) = [record["details"] for record in records
                    if record["event_type"] == "OPERATION_COMPLETED"
                    and record["details"].get("operation_id") == "unit.execute"
                    and record["details"].get("unit_id") == classified["unit_id"]]
    assert completed["phases"]["build.output_classify"]["count"] == 1
