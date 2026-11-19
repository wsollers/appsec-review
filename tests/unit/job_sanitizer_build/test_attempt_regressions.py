"""Offline attempt, source-copy and catalog regressions; only the build boundary is simulated."""
from __future__ import annotations

from copy import copy
import json
from pathlib import Path
import subprocess
from types import MappingProxyType

import pytest

from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_sanitizer_build import JOB_ID, build_job
from appsec_review.jobs.job_sanitizer_build import job as sanitizer_job
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.handoff import collect_artifacts
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.sanitizer_support import DockerFake, instrumented_elf
from .test_handlers import _doctored, _never_started, _settings, _synthetic_fixture


def _publish_input(ctx, receipts):
    root = ctx.job.run_root
    document = root / "data" / "language_build" / "receipts.json"
    atomic_json(document, {
        "schema": "appsec-review/language-build-handoff/2",
        "source_fingerprint": ctx.job.source_fingerprint, "receipts": receipts,
    })
    handoff = root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001" / "handoff.json"
    write_fixture_handoff(root, handoff, {"job_id": "job_language_build", "outputs": {
        "acceptance.publish_handoff": {"artifact": sanitizer_job._artifact(root, document)},
    }}, target_snapshot=ctx.job.source_fingerprint)
    return file_sha256(handoff)


def _run_handlers(ctx, upstream, factory, *, attempt="attempt_0001"):
    job = build_job(executor_factory=factory)
    context = copy(ctx.job)
    context.attempt_id = attempt
    outputs = {}
    with upstream_scope(context.run_root, JOB_ID, {"job_language_build": upstream}, contract=job.contract):
        for unit in job.units:
            step, task = unit.unit_id.split(".")
            root = context.run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt / "steps" / step / "tasks" / task
            root.mkdir(parents=True, exist_ok=True)
            outputs[unit.unit_id] = unit.handler(UnitContext(
                context, unit.unit_id, step, task, root, MappingProxyType(outputs)))
    published = outputs["acceptance.publish_handoff"]
    summary = json.loads((context.run_root / published["artifact"]["path"]).read_bytes())
    return published, summary


@pytest.mark.parametrize("second_fails", [True, False], ids=["failed-replacement", "successful-replacement"])
def test_fresh_attempt_preserves_published_evidence(tmp_path: Path, second_fails: bool) -> None:
    _, _, _, root, receipt, ctx = _synthetic_fixture(tmp_path)
    upstream = _publish_input(ctx, [receipt])
    published, summary = _run_handlers(ctx, upstream, lambda _u, p: DockerFake(p).executor())
    assert published["terminal_status"] == "SUCCEEDED"
    references = collect_artifacts(root, published, summary)
    original = {ref["path"]: (root / ref["path"]).read_bytes() for ref in references}
    old_workspace = root / summary["units"][0]["workspace"]
    old_files = sanitizer_job._snapshot(old_workspace, 100)

    second, second_summary = _run_handlers(
        ctx, upstream, lambda _u, p: DockerFake(p, fail_ordinal=1 if second_fails else None).executor(),
        attempt="attempt_0002")
    assert second["terminal_status"] == ("COMPLETED_WITH_GAPS" if second_fails else "SUCCEEDED")
    assert collect_artifacts(root, published, summary) == references
    assert {path: (root / path).read_bytes() for path in original} == original
    assert sanitizer_job._snapshot(old_workspace, 100) == old_files
    assert summary["units"][0]["workspace"] != second_summary["units"][0]["workspace"]


def test_same_attempt_cannot_replace_its_existing_workspace(tmp_path: Path) -> None:
    _, _, _, root, receipt, ctx = _synthetic_fixture(tmp_path)
    first = sanitizer_job._build_unit(ctx, receipt, _settings(), lambda _u, p: DockerFake(p).executor())
    references = collect_artifacts(root, first)
    result = sanitizer_job._build_unit(ctx, receipt, _settings(), _never_started)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert "already exists" in result["gaps"][0]
    assert collect_artifacts(root, first) == references


@pytest.mark.parametrize("build_dir", ["native/build", "native", "."],
                         ids=["out-of-source", "in-source", "workspace-root"])
def test_fresh_copy_removes_cmake_state_without_dropping_build_sources(tmp_path: Path, build_dir: str) -> None:
    _, target, _, root, receipt, ctx = _synthetic_fixture(tmp_path)
    if build_dir == ".":
        receipt["root"] = "."
        receipt["recipe"]["source_dir"] = "."
        (target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    receipt["recipe"]["build_dir"] = build_dir
    relative_build = Path(build_dir).relative_to(Path(receipt["root"])).as_posix()
    configure = ["cmake", "-S", ".", "-B", relative_build]
    build = ["cmake", "--build", relative_build]
    for index, argv in enumerate((configure, build)):
        receipt = _doctored(root, receipt, index, lambda doc, argv=argv: doc.update(
            argv=argv, working_directory=receipt["root"]))
        receipt["commands"][index]["working_directory"] = receipt["root"]
    receipt["recipe"].update(configure_commands=[configure], build_commands=[build])
    cache_root = target / build_dir
    controls = {
        "native/build/kept.cpp": b"int kept() { return 7; }\n",
        "native/tools/build/kept.cmake": b"set(KEPT ON)\n",
        "native/fixtures/CMakeCache.txt": b"example fixture, not this recipe's cache\n",
        "native/vendor/lib.c": b"int vendor() { return 1; }\n",
    }
    for relative, content in controls.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    stale = ("CMakeCache.txt", "CMakeFiles/3.28.3/CMakeCXXCompiler.cmake",
             "CMakeFiles/sample.dir/main.cpp.o", ".ninja_deps", ".ninja_log")
    for relative in stale:
        path = cache_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"stale compiler configuration or build state\n")
    receipt["recipe"]["dependency_files"] = ["shared/header.h"]
    (target / "shared").mkdir()
    (target / "shared/header.h").write_bytes(b"#define ACCEPTED 1\n")
    ctx.job.source_fingerprint = source_fingerprint(target)
    original = sanitizer_job._snapshot(target, 100)

    class CleanSourceBuild(DockerFake):
        def _build(self, source, environment):
            assert "-fsanitize=address,undefined" in environment["CXXFLAGS"]
            output = source / relative_build / "fresh-app"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(instrumented_elf())

        def __call__(self, argv, timeout):
            if tuple(argv[:2]) == ("docker", "run"):
                mount = argv[argv.index("--mount") + 1]
                workspace = Path(dict(part.split("=", 1) for part in mount.split(",") if "=" in part)["src"])
                if not self.runs:
                    for relative in stale:
                        assert not (workspace / build_dir / relative).exists(), relative
                    for relative, content in controls.items():
                        assert (workspace / relative).read_bytes() == content
                    assert (workspace / "shared/header.h").read_bytes() == b"#define ACCEPTED 1\n"
                    assert not (workspace / ".git").exists()
            return super().__call__(argv, timeout)

    result = sanitizer_job._build_unit(ctx, receipt, _settings(), lambda _u, p: CleanSourceBuild(p).executor())
    assert result["terminal_status"] == "SUCCEEDED"
    assert source_fingerprint(target) == ctx.job.source_fingerprint
    assert sanitizer_job._snapshot(target, 100) == original
    manifest = json.loads((root / result["workspace_manifest"]["path"]).read_bytes())
    for relative, content in controls.items():
        assert (root / result["workspace"] / relative).read_bytes() == content
        assert manifest["files"][relative] == file_sha256(target / relative)


@pytest.mark.parametrize("count", [1, 2, 3], ids=["below", "equal", "over"])
def test_output_limit_requires_an_additional_eligible_artifact(tmp_path: Path, count: int) -> None:
    _, target, _, root, receipt, ctx = _synthetic_fixture(tmp_path, settings_override={"artifact_count_limit": 2})
    prebuilt = target / "native" / "z-prebuilt"
    prebuilt.write_bytes(instrumented_elf())
    ctx.job.source_fingerprint = source_fingerprint(target)
    upstream = _publish_input(ctx, [receipt])

    class BoundedBuild(DockerFake):
        def _build(self, source, environment):
            assert "-fsanitize=address,undefined" in environment["CXXFLAGS"]
            build = source / "build"
            build.mkdir(exist_ok=True)
            for index in range(count):
                (build / f"app-{index}").write_bytes(instrumented_elf())
            probe = source / "z-probes/CMakeFiles/3.28.3/CompilerIdCXX"
            probe.mkdir(parents=True)
            (probe / "a.out").write_bytes(instrumented_elf())
            (source / "zz-not-an-artifact.txt").write_text("not eligible\n", encoding="utf-8")

    published, summary = _run_handlers(ctx, upstream, lambda _u, p: BoundedBuild(p).executor())
    unit = summary["units"][0]
    assert len(unit["outputs"]) == min(count, 2)
    assert published["counts"]["instrumented_outputs"] == min(count, 2)
    assert published["counts"]["instrumented_units"] == int(count <= 2)
    assert published["counts"]["gap_count"] == int(count > 2)
    assert published["terminal_status"] == ("COMPLETED_WITH_GAPS" if count > 2 else "SUCCEEDED")
    assert unit["gaps"] == (
        ["instrumented output catalog truncated at the configured count bound"] if count > 2 else [])
    assert collect_artifacts(root, published, summary)


@pytest.mark.parametrize("split", [False, True], ids=["joined", "split"])
def test_cmake_masking_assignment_is_rejected_before_build(tmp_path: Path, split: bool) -> None:
    _, _, _, root, receipt, ctx = _synthetic_fixture(tmp_path)
    assignment = "CMAKE_CXX_FLAGS:STRING=-O0"
    masked = _doctored(root, receipt, 0, lambda doc: doc["argv"].extend(
        ["-D", assignment] if split else ["-D" + assignment]))
    result = sanitizer_job._build_unit(ctx, masked, _settings(), _never_started)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert "command 1 sets a CMake compiler flags cache entry" in result["gaps"][0]
    assert result["workspace"] is None
