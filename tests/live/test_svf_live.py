"""Live tier for the SVF points-to producer (docs/architecture/svf-alias-producer.md, operator-run).

Skipped unless the pinned ``tool-svf`` image is present locally with the catalog's image id. With it,
``job_svf_alias_analysis`` runs end to end through the real ``ContainerExecutor`` and catalog policy
(no network, read-only root, non-root, 1 GiB, 600 s) against:

1. the synthetic fixture (``containers/fixtures/svf``), whose real output must still match the
   recorded documents the offline tests replay, so recordings cannot silently drift from the image;
2. ``linux-calibration``, a small multi-vulnerability C/C++ project copied from the
   ``appsec-multi-vuln`` target: a static archive and a shared library linked into two executables,
   one source compiled twice with different definitions, a function-pointer dispatch and a
   mismatched ``new[]``/``delete``.

Both runs then feed the SVF shard to the real cross-check over CodeQL-shaped facts.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from appsec_review.container_runtime import load_catalog
from appsec_review.graph import contract as c
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.svf_crosscheck import function_tail, read_svf, svf_cross_check
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.job_svf_alias_analysis.job import _analyze_scope
from appsec_review.storage import file_sha256
from tests.fixtures.graph.secondary.builder import SCOPE, SNAPSHOT, payload, span
from tests.fixtures.svf.builder import LINK_COMMANDS, RECORDED, SETTINGS, scope, unit


ROOT = Path(__file__).parents[2]
PROJECT = ROOT / "tests" / "fixtures" / "svf" / "linux-calibration"
PROJECT_ROOT = "projects/native/linux-calibration"
LIVE_SETTINGS = {**SETTINGS, "max_sites": 20000, "max_pts_size": 256, "max_indirect_calls": 2000,
                 "max_targets_per_call": 64, "module_timeout_seconds": 300, "andersen_time_limit_seconds": 240,
                 "compile_timeout_seconds": 120, "link_timeout_seconds": 120}


@pytest.fixture(scope="module")
def svf_image() -> None:
    if sys.platform != "win32" and shutil.which("docker") is None:
        pytest.skip("docker is unavailable")
    expected = load_catalog(ROOT).tool("tool-svf").expected_image_id
    try:
        actual = subprocess.run(["docker", "image", "inspect", "appsec-review/tool-svf:3.3.0", "--format", "{{.Id}}"],
                                capture_output=True, text=True, timeout=60, check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker is unavailable")
    if not actual:
        pytest.skip("the pinned tool-svf image is not built locally")
    if actual != expected:
        pytest.skip(f"local tool-svf image {actual} differs from the catalog pin {expected}")


def _run_root(tmp_path_factory, name: str) -> Path:
    # Run roots sit directly under the base temp: Docker Desktop rejects deep bind-mount sources.
    return tmp_path_factory.getbasetemp() / name


def _entities(run_root: Path, result) -> list[dict]:
    shard = dict(result["index_identity"])
    return list(ShardSet(run_root, [shard]).entities([shard]))


def _sources(scope_value: IndexScope) -> dict[str, SourceFile]:
    return {str(item["target_path"]): SourceFile.from_bytes(
        (scope_value.case_root / item["scratch_path"]).read_bytes()) for item in scope_value.files}


def _call_fact(sources, path: str, needle: str, callee: str, dispatch: str) -> c.GraphFact:
    location = span(sources, path, needle)
    caller = "asr:symbol:" + "2" * 64
    identity = c.fact_identity(c.Family.CALL_SITE, SNAPSHOT, {
        "scope_id": SCOPE["scope_id"], "caller_symbol": caller, "path": path, "start_byte": location.start_byte,
        "end_byte": location.end_byte, "callee_name": callee})
    result = {"caller": {"symbol": caller, "display": "caller"},
              "callee": {"symbol": None, "display": callee, "dispatch": dispatch, "candidate_count": 1},
              "argument_count": 1, "in_loop": False}
    return c.GraphFact(identity, callee, payload(c.Family.CALL_SITE, result), location)


def _project_scope(run_root: Path) -> tuple[IndexScope, list[dict]]:
    case_root = run_root / "data" / "cpp" / "projects" / "case-calibration"
    files, by_relative = [], {}
    for path in sorted(PROJECT.rglob("*")):
        if not path.is_file() or path.name == "NOTICE.md":
            continue
        relative = path.relative_to(PROJECT).as_posix()
        target = case_root / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        item = {"target_path": f"{PROJECT_ROOT}/{relative}", "scratch_path": f"source/{relative}",
                "sha256": file_sha256(target)}
        files.append(item)
        by_relative[relative] = item
    common = ["-Wall", "-Wextra", "-fPIC", "-I/scratch/source/include"]

    def command(relative: str, obj: str, *extra: str) -> dict:
        driver = "clang" if relative.endswith(".c") else "clang++"
        standard = "-std=c17" if relative.endswith(".c") else "-std=c++20"
        return {"target_path": f"{PROJECT_ROOT}/{relative}", "output_path": f"build/{obj}",
                "arguments": [driver, standard, *common, *extra, "-c", f"/scratch/source/{relative}",
                              "-o", f"/scratch/build/{obj}"]}

    commands = [
        command("src/profile.cpp", "profile_alpha.o", "-DCALIBRATION_PROFILE=1", "-DCALIBRATION_PROFILE_NAME=profile_alpha"),
        command("src/profile.cpp", "profile_beta.o", "-DCALIBRATION_PROFILE=2", "-DCALIBRATION_PROFILE_NAME=profile_beta"),
        command("src/storage.cpp", "storage.o"),
        command("src/sequences.cpp", "sequences.o"),
        command("src/coordination.cpp", "coordination.o", "-pthread"),
        command("src/platform.c", "platform.o"),
        command("app/observer_a.cpp", "observer_a.o"),
        command("app/observer_b.cpp", "observer_b.o"),
    ]
    links = [
        {"output_path": "build/libfoundation.a",
         "input_paths": ["build/storage.o", "build/sequences.o", "build/profile_alpha.o", "build/profile_beta.o"]},
        {"output_path": "build/libcoordination.so", "input_paths": ["build/coordination.o", "build/platform.o"]},
        {"output_path": "build/observer_a",
         "input_paths": ["build/observer_a.o", "build/libfoundation.a", "build/libcoordination.so"]},
        {"output_path": "build/observer_b",
         "input_paths": ["build/observer_b.o", "build/libcoordination.so", "build/libfoundation.a"]},
    ]
    database = case_root / "build" / "normalized-compile-commands.json"
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_text(json.dumps(commands), encoding="utf-8")
    value = IndexScope(
        scope_id="cpp-scope-calibration", case_id="case-calibration", project_id="cpp:linux-calibration",
        root=PROJECT_ROOT, case_snapshot="b" * 64, case_root=case_root, files=tuple(files),
        compile_commands=tuple(commands),
        compile_database={"path": database.relative_to(run_root).as_posix(), "sha256": file_sha256(database),
                          "size_bytes": database.stat().st_size},
        _by_relative=by_relative,
    )
    return value, links


def test_synthetic_fixture_runs_live_and_matches_its_recording(svf_image, tmp_path_factory) -> None:
    run_root = _run_root(tmp_path_factory, "svf-synthetic")
    accepted = scope(run_root)
    result = _analyze_scope(unit(run_root, LIVE_SETTINGS, repository_root=ROOT), accepted, LINK_COMMANDS, None)
    assert result["counts"]["analyzed"] == 2, result["gaps"]
    assert result["execution"]["image_id"] == load_catalog(ROOT).tool("tool-svf").expected_image_id

    scratch = run_root / "data" / "svf" / accepted.scope_id / "run"
    live = json.loads((scratch / "result.json").read_text(encoding="utf-8"))
    by_kind = {item["kind"]: item for item in live["modules"]}
    for kind, recorded in (("link", "m-app"), ("translation_unit", "m-plugin")):
        actual = json.loads((scratch / by_kind[kind]["output"]).read_text(encoding="utf-8"))
        expected = json.loads((RECORDED / "modules" / recorded / "alias.json").read_text(encoding="utf-8"))
        assert actual["module"] == expected["module"]
        assert actual["indirect_calls"] == expected["indirect_calls"]
        assert [(s["file"], s["line"], s["column"], s["role"], s["operand"], len(s["points_to"]),
                 s["incomplete_reasons"]) for s in actual["sites"]] == \
               [(s["file"], s["line"], s["column"], s["role"], s["operand"], len(s["points_to"]),
                 s["incomplete_reasons"]) for s in expected["sites"]]

    sources = _sources(accepted)
    shard = dict(result["index_identity"])
    svf = read_svf(ShardSet(run_root, [shard]), shard)
    call = "commands[index].handler(buffer, input)"
    facts = [_call_fact(sources, "native/callbacks.c", call, "copy_handler", "function_pointer_resolved"),
             _call_fact(sources, "native/callbacks.c", call, "unused_handler", "function_pointer_resolved")]
    checked = svf_cross_check(facts, [svf], target_snapshot=SNAPSHOT, scope=SCOPE)
    states = {fact.payload["result"]["callee"]["display"]: fact.payload["cross_check"]["state"]
              for fact in checked.facts}
    assert states == {"copy_handler": "agree", "unused_handler": "disagree"}


def test_multivuln_cpp_project_links_archives_and_resolves_its_function_pointer(svf_image, tmp_path_factory) -> None:
    run_root = _run_root(tmp_path_factory, "svf-calibration")
    accepted, links = _project_scope(run_root)
    result = _analyze_scope(unit(run_root, LIVE_SETTINGS, repository_root=ROOT), accepted, links, None)
    plan = {item["label"]: item for item in result["plan"]["modules"]}
    # The archive is folded into both executables; the shared library is its own module.
    assert set(plan) == {"build/libcoordination.so", "build/observer_a", "build/observer_b"}
    assert plan["build/observer_a"]["compile_indexes"] == [0, 1, 2, 3, 6]
    assert result["counts"]["analyzed"] == 3, result["gaps"]
    # The executables call only modeled or non-capturing externals; the shared library starts threads
    # and throws, whose runtime functions retain pointers, so it stays open-world.
    assert result["counts"]["closed_world"] == 2, result
    assert not any("did not produce bitcode" in gap for gap in result["gaps"]), result["gaps"]

    entities = _entities(run_root, result)
    sequences = f"{PROJECT_ROOT}/src/sequences.cpp"
    calls = [row for row in entities if row["kind"] == "indirect_call_targets" and row["location"]["path"] == sequences]
    assert calls, "the Selector dispatch in indirect_shape must be exported"
    for row in calls:
        targets = {function_tail(target["demangled"]) for target in row["payload"]["targets"]}
        assert targets == {"select_four", "select_four_checked"}, row["payload"]["targets"]
    assert {row["payload"]["module_label"] for row in calls} == {"build/observer_a", "build/observer_b"}

    deletes = [row for row in entities if row["kind"] == "points_to_set" and row["location"]["path"] == sequences
               and str(row["payload"].get("callee", "")).startswith("_ZdlPv")]
    assert deletes and all(row["payload"]["points_to"] for row in deletes), \
        "the scalar delete of the new[] allocation must carry its heap object"
    heap = {key for row in deletes for key in row["payload"]["points_to"]}
    assert all(row["payload"]["objects"][key]["kind"] == "heap" for row in deletes for key in row["payload"]["points_to"])
    assert heap

    # The object index pairs the array allocation with its scalar free from the records alone.
    allocation = [row["payload"] for row in entities if row["kind"] == "memory_object"
                  and row["payload"]["object_key"] in heap]
    assert allocation, "the new[] allocation must have a memory_object record"
    for item in allocation:
        assert item["allocator"] == "_Znam" and item["allocator_demangled"].startswith("operator new[]")
        frees = [a for a in item["accessors"] if a["class"] == "free"]
        assert frees and all(a["callee"].startswith("_ZdlPv") for a in frees)
        assert item["accessors"][0]["class"] == "free" and item["complete"] is True
    assert result["counts"]["memory_objects"] > 0

    sources = _sources(accepted)
    shard = dict(result["index_identity"])
    svf = read_svf(ShardSet(run_root, [shard]), shard)
    facts = [_call_fact(sources, sequences, "selector(index)", "select_four_checked", "function_pointer_resolved"),
             _call_fact(sources, sequences, "selector(index)", "<unresolved>", "unresolved_indirect")]
    checked = svf_cross_check(facts, [svf], target_snapshot=SNAPSHOT, scope=SCOPE)
    resolved = next(f for f in checked.facts if f.identity == facts[0].identity)
    entry = next(item for item in resolved.payload["cross_check"]["producers"] if item["name"] == "svf")
    assert entry["state"] == "agree", entry
    secondary = sorted(function_tail(f.payload["result"]["callee"]["display"])
                       for f in checked.facts if f.payload["producer"]["name"] == "svf")
    assert secondary == ["select_four", "select_four_checked"]

    report = {"counts": result["counts"], "gaps": result["gaps"],
              "modules": {label: item["open_world_reasons"] for label, item in plan.items()}}
    (run_root / "svf-acceptance.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
