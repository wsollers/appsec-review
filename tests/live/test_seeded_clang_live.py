"""Opt-in live checks for seeded Clang neighborhoods (docs/architecture/seeded-neighborhoods.md section 12).

Skipped unless ``APPSEC_LIVE_SEEDED_CLANG=1``.

* ``test_live_compiler_flow_matches_the_recording`` needs ``clang++-18`` on PATH. It re-emits LLVM IR for the
  12-unit fixture with the real compiler, parses it with the production parser and requires the flow summary
  (blocks, edges, calls, dominators) to match what the offline suite pins from the recording.
* ``TestContainers`` needs a Docker daemon and the built images ``tool-native-cpp`` (pinned),
  ``tool-clang-static-analysis`` and ``tool-joern``. It runs the production seeded handlers through the real
  ``ContainerExecutor`` on the same fixture and requires every stage to stay inside the two seeded units.
  Counts the operator should expect are recorded in docs/architecture/seeded-neighborhoods.md section 12; a
  stage that cannot run is a named failure here, never a pass.
"""
from __future__ import annotations

import os
from pathlib import Path
import json
import shutil
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_cpp_compiled_analysis import llvm_ir
from tests import seeded_clang_support as sc

LIVE = os.environ.get("APPSEC_LIVE_SEEDED_CLANG") == "1"
REPOSITORY = Path(__file__).resolve().parents[2]
IMAGES = ("tool-native-cpp", "tool-clang-static-analysis", "tool-joern")
needs_compiler = pytest.mark.skipif(
    not LIVE or shutil.which("clang++-18") is None,
    reason="set APPSEC_LIVE_SEEDED_CLANG=1 with clang++-18 installed to run the live compiler check")


def _live_module(tmp_path: Path, stem: str) -> llvm_ir.IrModule:
    out = tmp_path / f"{stem}.ll"
    subprocess.run(["clang++-18", f"-ffile-prefix-map={sc.PROJECT}=/scratch/source", f"-I{sc.PROJECT}/include",
                    "-std=c++17", "-emit-llvm", "-S", "-g", "-O0", "-o", str(out), str(sc.PROJECT / "src" / f"{stem}.cpp")],
                   check=True, capture_output=True, cwd=sc.PROJECT)
    return llvm_ir.parse_module(out.read_text(encoding="utf-8").replace(str(sc.PROJECT), "/scratch/source"))


@needs_compiler
@pytest.mark.parametrize("stem", ["util", "net", "parse"])
def test_live_compiler_flow_matches_the_recording(tmp_path: Path, stem: str) -> None:
    recorded = llvm_ir.parse_module((sc.RECORDED / "ir" / f"{stem}.ll").read_text(encoding="utf-8"))
    live = _live_module(tmp_path, stem)
    assert [(f.name, f.path, f.start_line, f.flow()) for f in live.functions] == [
        (f.name, f.path, f.start_line, f.flow()) for f in recorded.functions]


# ---- the real tool containers ---------------------------------------------------------------------------------


def _images_missing() -> str:
    if shutil.which("docker") is None:
        return "docker is not installed"
    from appsec_review.container_runtime import load_catalog

    catalog = load_catalog(REPOSITORY)
    for tool_id in IMAGES:
        tag = catalog.tool(tool_id).tag
        if subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode:
            return f"image {tag} is not built"
    return ""


UNITS = ("src/net.cpp", "src/util.cpp")


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    """Run the seeded IR/AST/CFG, Clang-Tidy/CSA and c2cpg/joern-export handlers once through real containers."""
    if not LIVE:
        pytest.skip("set APPSEC_LIVE_SEEDED_CLANG=1 to run the real tool containers")
    if (reason := _images_missing()):
        pytest.fail(reason)
    from appsec_review.jobs import cpp_seeded
    from appsec_review.jobs.job_clang_static_analysis import job as static_job, seeded as static_seeded
    from appsec_review.jobs.job_cpg_analysis import job as cpg_job, seeded as cpg_seeded
    from appsec_review.jobs.job_cpp_compiled_analysis import build_job

    staged = sc.stage(tmp_path_factory.mktemp("seeded-live"))
    staged.repository = REPOSITORY            # the real catalog, so ContainerExecutor starts the real images
    compiled = {unit.unit_id: unit for unit in build_job().units}

    def native(name: str, **outputs):
        outputs.setdefault("catalog.projects", {"projects": {sc.CASE: staged.cataloged}})
        unit = staged.unit(f"{name}.projects", outputs)
        return compiled[f"{name}.projects"].handler(unit)

    ir = native("ir")
    ast = native("ast", **{"ir.projects": ir})
    scope = sc.index_scope(staged)
    hood = {"result": {"outputs": {"ir.projects": ir}}}

    unit = staged.unit("analyze.scopes", {}, job_id="job_clang_static_analysis")
    unit.job.config.settings.update({**sc.STATIC_SETTINGS, "max_output_bytes": 16 << 20,
                                     "clang_tidy_checks": ["clang-analyzer-*", "bugprone-*", "cert-*"],
                                     "clang_analyzer_checkers": ["core", "cplusplus", "security", "unix"]})
    settings = static_seeded.settings_of(unit)
    plan = static_seeded.plan_for(unit, [scope], settings)
    static = static_job._analyze_scope(unit, scope, None, static_seeded.Run(
        settings, plan, plan.for_scope(sc.CASE), static_seeded.neighborhood_of(hood, sc.CASE)))

    unit = staged.unit("generate.scopes", {}, job_id="job_cpg_analysis")
    unit.job.config.settings.update({**sc.CPG_SETTINGS, "max_cpg_bytes": 2 << 30})
    settings = cpp_seeded.settings_of(unit)
    plan = cpp_seeded.plan_for(unit, [scope], settings)
    cpg = cpg_job._generate(unit, scope, None, cpg_seeded.Run(settings, plan, plan.for_scope(sc.CASE)))
    result = SimpleNamespace(staged=staged, ir=ir["projects"][sc.CASE], ast=ast["projects"][sc.CASE], static=static, cpg=cpg)
    print("\nSEEDED-LIVE", json.dumps(_numbers(result), sort_keys=True))
    return result


def _numbers(live) -> dict:
    """What an operator records in docs/architecture/seeded-neighborhoods.md section 12."""
    observations = _entities(live, live.static["index_identity"]["relative_path"], "tool_observation")
    functions = _entities(live, live.cpg["index_identity"]["relative_path"], "ast_node")
    return {"ir_functions": len(_entities(live, live.ir["artifact"]["path"], "ir_entity")),
            "ir_call_edges": live.ir["call_edge_count"], "ast_status": live.ast["terminal_status"],
            "diagnostics": {scanner: sum(1 for _, p in observations if p["scanner"] == scanner)
                            for scanner in sorted({p["scanner"] for _, p in observations})},
            "cpg_functions": len(functions), "cpg_gaps": sorted(live.cpg["gaps"]),
            "static_gaps": sorted(live.static["gaps"]), "ir_gaps": sorted(live.ir["gaps"])}


def _entities(live, relative_path: str, kind: str) -> list[tuple[str, dict]]:
    path = live.staged.run_root / relative_path
    return [(row[3], json.loads(row[5])) for row in sqlite3.connect(path).execute(
        "select * from entities where kind = ?", (kind,))]


class TestContainers:
    def test_native_cpp_replays_only_the_seeded_units_and_publishes_flow_and_source_cfg(self, live) -> None:
        ir, ast = live.ir, live.ast
        assert ir["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"} and ast["terminal_status"] in {
            "SUCCEEDED", "COMPLETED_WITH_GAPS"}
        assert ir["index_identity"]["producer"]["seeded"]["resolved_seed_count"] == 2
        flows = {name: payload for name, payload in _entities(live, ir["artifact"]["path"], "ir_entity")}
        assert {"copy_field", "handle_packet", "checked_len", "log_event", "clamp_len"} <= set(flows)
        copy = flows["copy_field"]
        assert copy["seeded"] is True and copy["flow"]["blocks"] and copy["flow"]["dominators"]
        assert copy["source_cfg"]["blocks"], "the clang -cfg replay produced no source blocks"
        assert ir["call_edge_count"] == 4, "the live IR must give the same call edges as the recording"
        assert not any(gap.startswith("source_cfg_unavailable") for gap in ir["gaps"]), ir["gaps"]

    def test_clang_tidy_and_the_static_analyzer_run_over_the_seeded_units_only(self, live) -> None:
        result = live.static
        assert result["analyzed_units"] == [f"unit:{name}" for name in UNITS]
        assert result["index_identity"]["producer"]["seeded"]["resolved_seed_count"] == 2
        observations = _entities(live, result["index_identity"]["relative_path"], "tool_observation")
        assert {payload["scanner"] for _, payload in observations} <= {"clang-tidy", "clang-static-analyzer"}
        assert {payload["path"] for _, payload in observations} <= {f"proj/{name}" for name in UNITS}
        assert not any(gap.endswith("unavailable") or "tool/image unavailable" in gap for gap in result["gaps"])

    def test_joern_builds_a_seeded_cpg_and_exports_bounded_function_rows(self, live) -> None:
        result = live.cpg
        assert result["cpg"] is not None, result["gaps"]
        assert result["analyzed_files"] == list(UNITS)
        assert result["cpg_export"] is not None, result["gaps"]
        rows = dict(_entities(live, result["index_identity"]["relative_path"], "ast_node"))
        assert {"handle_packet", "copy_field", "clamp_len", "checked_len"} <= set(rows)
        copy = rows["copy_field"]
        assert copy["path"] == "src/util.cpp" and any(call["name"] == "memcpy" for call in copy["calls"])
        assert any(item["condition"] for item in copy["branches"])
        assert any("cpg_no_cfg_edges" in gap for gap in result["gaps"])


BAD_SOURCE = """#include <string.h>
#include <stdlib.h>
void copy(char *dst, const char *src) {
  char small[4];
  strcpy(small, src);
  strncpy(dst, src, 8);
}
int deref(int flag) {
  int *p = nullptr;
  if (flag) return *p;
  return 0;
}
"""


@pytest.mark.skipif(not LIVE, reason="set APPSEC_LIVE_SEEDED_CLANG=1 to run the real tool containers")
def test_real_analyzer_diagnostics_use_check_ids_the_graph_sink_table_recognizes(tmp_path: Path) -> None:
    """The reviewed check table must name checks the real tools emit; the fixture project itself is clean."""
    if (reason := _images_missing()):
        pytest.fail(reason)
    from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
    from appsec_review.graph.analyzers import sink_class_of
    from appsec_review.jobs.job_clang_static_analysis.job import _engine_argv

    case, run_root = tmp_path / "case", tmp_path / "run"
    (case / "source" / "src").mkdir(parents=True)
    (case / "source" / "src" / "bad.cpp").write_text(BAD_SOURCE, encoding="utf-8")
    executor = ContainerExecutor(load_catalog(REPOSITORY), run_root)
    settings = {"max_diagnostics_per_scope": 1000, "clang_tidy_checks": ["clang-analyzer-*", "bugprone-*", "cert-*"],
                "clang_analyzer_checkers": ["core", "cplusplus", "security", "unix"]}
    found: dict[str, list[dict]] = {}
    for engine in ("clang-tidy", "clang-static-analyzer"):
        scratch = run_root / engine
        scratch.mkdir(parents=True)
        (scratch / "compile_commands.json").write_text(json.dumps([{
            "directory": "/target/source", "file": "/target/source/src/bad.cpp",
            "arguments": ["clang++", "-std=c++17", "-c", "/target/source/src/bad.cpp"]}]), encoding="utf-8")
        result = executor.execute(ExecutionRequest(tool_id="tool-clang-static-analysis", argv=_engine_argv(engine, settings),
                                                   target_root=case, scratch_root=scratch))
        assert result.exit_code in {0, 1}, f"{engine} exited with {result.exit_code}"
        document = json.loads((scratch / ("tidy.json" if engine == "clang-tidy" else "analyze.json")).read_text())
        assert document["engine"] == engine and document["units"] and document["units"][0]["exit_code"] in {0, 1}
        found[engine] = document["diagnostics"]
    checks = {item["rule_id"] for items in found.values() for item in items}
    print("\nSEEDED-LIVE-CHECKS", json.dumps({key: sorted({item["rule_id"] for item in value}) for key, value in found.items()}))
    assert checks, "the real tools reported nothing for a file with an obvious unbounded strcpy and null dereference"
    assert any(sink_class_of(check) is not None for check in checks), sorted(checks)
