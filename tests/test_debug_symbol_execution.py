from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sys

import pytest

from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor
from appsec_review.debug_symbols import _container_export as driver
from appsec_review.debug_symbols import execution
from appsec_review.jobs.job_debug_symbol_indexing import build_job, load_accepted_debug_symbols
from appsec_review.storage import atomic_json, file_sha256
from tests.test_debug_symbol_indexing import _seed
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "debug_symbols"
BUILD_IMAGE = "sha256:" + "d" * 64


class Engine:
    def __init__(self, output, *, build_exit=0, build_missing=False, substitute_image=False,
                 fallback_missing=False):
        self.output = output
        self.build_exit = build_exit
        self.build_missing = build_missing
        self.substitute_image = substitute_image
        self.fallback_missing = fallback_missing
        self.runs = []

    def __call__(self, argv, timeout):
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            image = argv[3]
            if image == BUILD_IMAGE and self.build_missing:
                return CommandOutcome(1, b"", b"not present")
            if image != BUILD_IMAGE and self.fallback_missing:
                return CommandOutcome(1, b"", b"not present")
            if image == BUILD_IMAGE and self.substitute_image:
                image = "sha256:" + "e" * 64
            return CommandOutcome(0, image.encode(), b"")
        assert tuple(argv[:2]) == ("docker", "run")
        self.runs.append(tuple(argv))
        image = argv[argv.index("--entrypoint") + 2]
        if image == BUILD_IMAGE and self.build_exit:
            return CommandOutcome(self.build_exit, b"", b"")
        for value in argv:
            if value.startswith("type=bind,src=") and ",dst=/scratch" in value:
                scratch = Path(value.split("src=", 1)[1].split(",dst=", 1)[0])
                (scratch / "export.bin").write_bytes(self.output)
        return CommandOutcome(0, b"", b"")


@pytest.fixture
def catalog(monkeypatch):
    original = load_catalog(ROOT)
    tool = original.tool("tool-native-cpp")
    tool = replace(tool, additional_executables=(*tool.additional_executables, "/usr/bin/python3"))
    value = replace(original, tools={**original.tools, tool.tool_id: tool})
    monkeypatch.setattr(execution, "load_catalog", lambda _: value)
    return value


def _run(tmp_path, monkeypatch, catalog, target="clang", *, produced=True, fixture=None,
         **engine_options):
    binary = "tiny.elf" if target == "clang" else (fixture or "tiny") + ".exe"
    output = "tiny.dwarf.txt" if target == "clang" else (fixture or "tiny") + ".pdb.yaml"
    context, _, _ = _seed(
        tmp_path, target, produced=produced, debug=target == "msvc",
        binary_bytes=(FIXTURES / binary).read_bytes(),
        debug_bytes=(FIXTURES / ((fixture or "tiny") + ".pdb")).read_bytes()
        if target == "msvc" else None,
    )
    context = replace(context, repository_root=ROOT)
    engine = Engine((FIXTURES / output).read_bytes(), **engine_options)
    monkeypatch.setattr("appsec_review.debug_symbols.readers._tool",
                        lambda *_: pytest.fail("production used a host executable"))
    factory = lambda image_catalog, run_root: ContainerExecutor(image_catalog, run_root, runner=engine)
    result = build_job(executor_factory=factory).execute(context)
    if "acceptance.publish_handoff" in result["outputs"]:
        output = result["outputs"]["acceptance.publish_handoff"]
        handoff = context.attempt_root / "handoff.json"
        write_fixture_handoff(context.run_root, handoff, {
            "status": "ACCEPTED",
            "job_id": context.config.job_id, "outputs": {"acceptance.publish_handoff": output},
            "artifacts": [output["artifact"], output["index_manifest"]]})
        atomic_json(context.run_root / "data" / "jobs" / context.config.job_id / "latest.json", {
            "handoff_path": handoff.relative_to(context.run_root).as_posix(),
            "handoff_sha256": file_sha256(handoff)})
    return context, result, engine


@pytest.mark.parametrize("target", ["clang", "msvc"])
def test_real_reader_contract_uses_exact_accepted_build_image(tmp_path, monkeypatch, catalog, target):
    context, result, engine = _run(tmp_path, monkeypatch, catalog, target)
    assert result["failed_units"] == []
    assert result["outputs"]["acceptance.publish_handoff"]["item_count"] > 0
    assert len(engine.runs) == 1
    argv = engine.runs[0]
    assert argv[argv.index("--entrypoint") + 1:argv.index("--entrypoint") + 3] == (
        "/usr/bin/python3", BUILD_IMAGE)
    assert argv[argv.index("--entrypoint") + 3:argv.index("--entrypoint") + 6] == (
        "-I", "-S", "-B")
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv and "--cap-drop" in argv
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--ulimit") + 1] == "fsize=16777217:16777217"
    mounts = [value for value in argv if value.startswith("type=bind,src=")]
    assert sum(",readonly" not in value for value in mounts) == 1
    assert any(",dst=/target,readonly" in value for value in mounts)
    assert any(",dst=/opt/appsec/debug-symbol-export.py,readonly" in value for value in mounts)
    summary = load_accepted_debug_symbols(context.run_root)
    raw = json.loads((context.run_root / summary["reader_evidence"]["path"]).read_text())
    attempt = raw["artifacts"][0]["reader_executions"][0]
    assert attempt["image_id"] == BUILD_IMAGE and attempt["environment"] == "build"
    assert attempt["outcome"] == "succeeded"
    assert (context.run_root / attempt["execution"]["path"]).is_file()
    events = context.events.path.read_text()
    assert "DEBUG_SYMBOL_READER_COMPLETED" in events
    assert "private-program" not in events


@pytest.mark.parametrize("options,reason", [
    ({"build_exit": 42}, "tool_unavailable"),
    ({"build_exit": 127}, "tool_unavailable"),
    ({"build_exit": 125}, "image_incompatible"),
    ({"build_missing": True}, "image_unavailable"),
])
def test_legacy_or_incompatible_build_image_uses_pinned_managed_reader(
        tmp_path, monkeypatch, catalog, options, reason):
    context, result, engine = _run(tmp_path, monkeypatch, catalog, **options)
    assert result["failed_units"] == []
    assert result["outputs"]["acceptance.publish_handoff"]["item_count"] > 0
    assert engine.runs[-1][engine.runs[-1].index("--entrypoint") + 2] == (
        catalog.tool("tool-native-cpp").expected_image_id)
    assert "DEBUG_SYMBOL_READER_FALLBACK" in context.events.path.read_text()
    assert reason in context.events.path.read_text()


@pytest.mark.parametrize("target", ["clang", "msvc"])
def test_prebuilt_artifacts_need_no_host_tool_settings(tmp_path, monkeypatch, catalog, target):
    context, result, engine = _run(tmp_path, monkeypatch, catalog, target, produced=False)
    assert result["failed_units"] == []
    assert result["outputs"]["acceptance.publish_handoff"]["item_count"] > 0
    assert len(engine.runs) == 1
    assert BUILD_IMAGE not in engine.runs[0]


def test_container_image_substitution_is_fatal_not_a_fallback(tmp_path, monkeypatch, catalog):
    _, result, engine = _run(tmp_path, monkeypatch, catalog, substitute_image=True)
    assert result["failed_units"] == ["extract.clang_dwarf"]
    assert "acceptance.publish_handoff" not in result["outputs"]
    assert engine.runs == []


def test_missing_managed_reader_is_unavailable_not_empty_success(tmp_path, monkeypatch, catalog):
    context, result, _ = _run(
        tmp_path, monkeypatch, catalog, build_exit=42, fallback_missing=True)
    assert result["status"] == "COMPLETED_WITH_GAPS"
    output = result["outputs"]["acceptance.publish_handoff"]
    assert output["item_count"] == 0
    assert "image_unavailable" in " ".join(output["gaps"])
    assert "DEBUG_SYMBOL_ARTIFACT_FAILED" in context.events.path.read_text()


@pytest.mark.parametrize("code,gap", [(43, "tool_failed"), (44, "tool_timeout"), (45, "output_limit")])
def test_export_failures_are_explicit_and_do_not_change_environments(
        tmp_path, monkeypatch, catalog, code, gap):
    _, result, engine = _run(tmp_path, monkeypatch, catalog, build_exit=code)
    assert result["status"] == "COMPLETED_WITH_GAPS"
    assert gap in " ".join(result["outputs"]["acceptance.publish_handoff"]["gaps"])
    assert result["outputs"]["acceptance.publish_handoff"]["item_count"] == 0
    assert len(engine.runs) == 1


def test_execution_receipts_are_hash_bound_to_accepted_symbols(tmp_path, monkeypatch, catalog):
    context, _, _ = _run(tmp_path, monkeypatch, catalog)
    summary = load_accepted_debug_symbols(context.run_root)
    raw = json.loads((context.run_root / summary["reader_evidence"]["path"]).read_text())
    receipt = raw["artifacts"][0]["reader_executions"][0]["execution"]
    (context.run_root / receipt["path"]).write_text("{}")
    with pytest.raises(ValueError, match="integrity"):
        load_accepted_debug_symbols(context.run_root)


def test_managed_image_and_launcher_are_resume_inputs(monkeypatch, catalog):
    first = execution.execution_plan(ROOT)
    tool = catalog.tool("tool-native-cpp")
    changed = replace(catalog, tools={**catalog.tools, tool.tool_id:
                                    replace(tool, expected_image_id="sha256:" + "f" * 64)})
    monkeypatch.setattr(execution, "load_catalog", lambda _: changed)
    second = execution.execution_plan(ROOT)
    assert first != second
    assert len(first["launcher_sha256"]) == 64


@pytest.mark.parametrize("fixture", ["msvc-tiny", "msvc-inline"])
def test_genuine_msvc_artifacts_flow_through_image_exporter(tmp_path, monkeypatch, catalog, fixture):
    _, result, engine = _run(tmp_path, monkeypatch, catalog, "msvc", fixture=fixture)
    assert result["failed_units"] == []
    assert result["outputs"]["acceptance.publish_handoff"]["item_count"] > 0
    assert len(engine.runs) == 1


@pytest.mark.parametrize("image", [
    None, {}, {"image_id": "mutable:tag", "user": "10001:10001"},
    {"image_id": BUILD_IMAGE, "user": "0:0"},
])
def test_unpinned_or_root_build_identity_is_rejected(image):
    with pytest.raises(execution.SymbolIntegrityError):
        execution.build_image_identity(image)


def test_host_path_settings_are_rejected_instead_of_ignored():
    from appsec_review.config.debug_symbols import parse_debug_symbol_settings
    with pytest.raises(ValueError, match="unknown debug-symbol reader settings"):
        parse_debug_symbol_settings({"reader": {"tools": {
            "llvm_dwarfdump": {"path": "C:\\approved\\llvm-dwarfdump.exe", "sha256": "a" * 64}}}})


def test_resume_identity_changes_when_managed_reader_image_changes(monkeypatch, catalog):
    job = build_job()
    before = job.probe_input_identity(None)
    tool = catalog.tool("tool-native-cpp")
    changed = replace(catalog, tools={**catalog.tools, tool.tool_id:
                                    replace(tool, expected_image_id="sha256:" + "f" * 64)})
    monkeypatch.setattr(execution, "load_catalog", lambda _: changed)
    assert job.probe_input_identity(None) != before


def test_fresh_execution_attempts_cannot_alias_previous_receipt_shards(
        tmp_path, monkeypatch, catalog):
    context, first, engine = _run(tmp_path, monkeypatch, catalog)
    next_root = context.attempt_root.with_name("attempt_0002")
    next_root.mkdir()
    context = replace(context, attempt_id="attempt_0002", attempt_root=next_root)
    factory = lambda image_catalog, run_root: ContainerExecutor(image_catalog, run_root, runner=engine)
    second = build_job(executor_factory=factory).execute(context)
    assert second["failed_units"] == []
    initial = first["outputs"]["extract.clang_dwarf"]["indexes"][0]
    latest = second["outputs"]["extract.clang_dwarf"]["indexes"][0]
    assert initial["fingerprint"] != latest["fingerprint"]
    assert initial["relative_path"] != latest["relative_path"]


def test_runtime_failures_are_not_misclassified_as_missing_images(tmp_path, monkeypatch, catalog):
    context, _, _ = _seed(tmp_path, binary_bytes=(FIXTURES / "tiny.elf").read_bytes(), produced=True)
    context = replace(context, repository_root=ROOT)

    class BrokenExecutor(ContainerExecutor):
        def execute(self, request):
            raise RuntimeError("private admission failure")

    result = build_job(executor_factory=BrokenExecutor).execute(context)
    assert result["status"] == "COMPLETED_WITH_GAPS"
    assert "reader_failed: RuntimeError" in " ".join(
        result["outputs"]["acceptance.publish_handoff"]["gaps"])
    assert "DEBUG_SYMBOL_READER_FALLBACK" not in context.events.path.read_text()


@pytest.mark.parametrize("script,maximum,timeout,code", [
    ("print('metadata')", 100, 5, 0),
    ("raise SystemExit(1)", 100, 5, 43),
    ("import time; time.sleep(2)", 100, 0.02, 44),
    ("print('x' * 100)", 16, 5, 45),
])
def test_bounded_export_driver(tmp_path, monkeypatch, script, maximum, timeout, code):
    tool = tmp_path / "fake_reader.py"
    tool.write_text(script)
    monkeypatch.setitem(driver.TOOLS, "llvm_dwarfdump", sys.executable)
    monkeypatch.setitem(driver.ARGUMENTS, "llvm_dwarfdump", (str(tool),))
    result = driver.export("llvm_dwarfdump", tmp_path / "input", tmp_path / "export.bin",
                           maximum, timeout)
    assert result == code


def test_export_driver_never_searches_path(tmp_path, monkeypatch):
    monkeypatch.setitem(driver.TOOLS, "llvm_dwarfdump", str(tmp_path / "not-installed"))
    assert driver.export("llvm_dwarfdump", tmp_path / "input", tmp_path / "export.bin", 100, 2) == 42
