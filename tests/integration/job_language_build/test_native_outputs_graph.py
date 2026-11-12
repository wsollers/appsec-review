"""job_language_build native FetchContent build-output classification through GraphRunner.

The pre-walk whole-graph suite, moved out of the unit path by T-113: the case runs the intake,
catalog, plan, project-build and language-build jobs with fake executors. It is an integration
test pending replacement by the code-level tests in tests/unit/job_language_build/ and runs only
when named explicitly (``scripts/run-tests.sh --allow-heavy -- <file>``).
"""

from __future__ import annotations

import json
from pathlib import Path

from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.runtime import GraphRunner
from tests.capture_fakes import simulated_executor
from tests.integration.job_language_build.test_language_build_graph import _accepted_project, _fixture
from tests.unit.job_language_build.test_native_outputs import _fetchcontent_build, _write

# Keys aggregate_run_metrics sums into throughput totals; the classification event must avoid them.
_SUMMED = {"file_count", "artifact_count", "size_bytes", "processed_bytes", "gap_count", "disposition"}
_SUMMARIZED = "dependency-content-summarized:"



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
