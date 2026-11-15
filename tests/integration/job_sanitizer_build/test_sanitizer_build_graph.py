"""job_sanitizer_build: ASan/UBSan rebuild of accepted native units, proven from the produced ELF.

The language build runs for real with its own fakes; the sanitizer rebuild then runs through the
real ``BuildContainerExecutor`` over a fake Docker CLI (``tests/sanitizer_support.py``), so the
executor's environment and mount handling are exercised. Nothing here executes a produced file.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import shutil
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildProfile
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import elf
from appsec_review.jobs.job_sanitizer_build import JOB_ID, build_job
from appsec_review.jobs.job_sanitizer_build import job as sanitizer_job
from appsec_review.jobs.job_sanitizer_build.datasets import CONSUMES, DATASETS
from appsec_review.jobs.job_sanitizer_build.evidence import runtime_evidence
from appsec_review.jobs.job_sanitizer_build.settings import (
    SanitizerBuildSettings, argument_conflicts, instrumented_environment,
)
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime import GraphRunner, UnitContext
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import canonical_json, file_sha256
from tests.sanitizer_support import (
    ET_REL, DockerFake, elf_with_symbols, instrumented_elf,
)
from tests.integration.job_language_build.test_language_build_graph import (
    ImageResolver, NativeExecutor, NativeRecipeModel, _fixture, native_language_executor,
)
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).resolve().parents[3]
SETTINGS = {
    "enabled": True, "workers": 1, "sanitizers": ["address", "undefined"],
    "extra_flags": ["-fno-omit-frame-pointer", "-g", "-O1"], "required_evidence": ["address"],
    "build_systems": ["cmake", "autotools", "meson", "make"],
    "build_environment": {"ASAN_OPTIONS": "detect_leaks=0"},
    "command_timeout_seconds": 60, "output_bytes": 1_000_000, "artifact_count_limit": 100, "max_units": 4,
}


def _settings(**overrides) -> SanitizerBuildSettings:
    return SanitizerBuildSettings.from_mapping({**deepcopy(SETTINGS), **overrides})


# --------------------------------------------------------------------------- accepted native build


def _accepted(base: Path):
    config, target = _fixture(base)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
                                    build_plan(infer=NativeRecipeModel().complete)]).run(
        target_root=target, source_fingerprint=fingerprint)
    project = build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, NativeExecutor([])),
                             image_resolver_factory=lambda unit: ImageResolver(target))
    GraphRunner(config, [project]).run(target_root=target, source_fingerprint=fingerprint,
                                       run_id=upstream["run_id"])
    run_id = upstream["run_id"]
    GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: native_language_executor(profile, []))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    return base, fingerprint, run_id


@pytest.fixture(scope="module")
def accepted_base(tmp_path_factory):
    """One accepted native language build, built once; every test works on its own copy."""
    return _accepted(tmp_path_factory.mktemp("accepted"))


def _clone(accepted_base, tmp_path: Path):
    base, fingerprint, run_id = accepted_base
    root = tmp_path / "copy"
    shutil.copytree(base, root, symlinks=True)
    return load_config(root / "appsec-review.toml"), root / "target", fingerprint, run_id


def _sanitize(accepted_base, tmp_path: Path, *, mode: str = "honor_env", fail_ordinal: int | None = None):
    config, target, fingerprint, run_id = _clone(accepted_base, tmp_path)
    fakes: list[DockerFake] = []

    def factory(unit, profile: BuildProfile):
        fake = DockerFake(profile, mode=mode, fail_ordinal=fail_ordinal)
        fakes.append(fake)
        return fake.executor()

    outcome = GraphRunner(config, [build_job(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    return config, outcome, config.runtime.runs_dir / run_id, fakes


def _summary(outcome, run_root: Path) -> dict:
    job = outcome["jobs"][JOB_ID]
    result = json.loads((Path(job["attempt_root"]) / "result.json").read_text(encoding="utf-8"))
    artifact = result["outputs"]["acceptance.publish_handoff"]["artifact"]
    assert file_sha256(run_root / artifact["path"]) == artifact["sha256"]
    return json.loads((run_root / artifact["path"]).read_text(encoding="utf-8"))


def test_sanitizer_rebuild_publishes_a_hash_bound_instrumented_catalog(accepted_base, tmp_path: Path) -> None:
    _config, outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path)
    assert outcome["status"] == "SUCCEEDED"
    summary = _summary(outcome, run_root)
    assert summary["schema"] == "appsec-review/sanitizer-build-handoff/1"
    assert summary["gaps"] == [] and summary["counts"]["instrumented_units"] == 1
    assert "no produced binary was loaded or executed" in summary["execution_policy"]
    unit = summary["units"][0]
    assert unit["terminal_status"] == "SUCCEEDED" and unit["instrumented"] is True
    assert unit["flags"] == ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"]
    assert unit["workspace"] == f"data/sanitizer/{unit['build_unit_id']}/workspace"
    by_path = {item["workspace_path"]: item for item in unit["outputs"]}
    assert set(by_path) == {"native/build/sample", "native/build/CMakeFiles/sample.dir/main.cpp.o"}
    executable = by_path["native/build/sample"]
    assert executable["kind"] == "executable" and executable["instrumented"] is True
    assert file_sha256(run_root / executable["path"]) == executable["sha256"]
    assert executable["evidence"]["sanitizers"]["address"]["runtime_referenced"] is True
    assert executable["evidence"]["sanitizers"]["undefined"]["runtime_referenced"] is True
    # The control: the normal build's file at the same path was read and does not reference the runtime.
    assert not executable["baseline"]["runtime_referenced"]
    assert unit["excluded_bookkeeping"]["counts"] == {"cmake-compiler-identification": 1}
    assert unit["build_output_dispositions"]["schema"] == "appsec-review/build-output-dispositions/1"
    assert unit["build_output_dispositions"]["bookkeeping"] == unit["excluded_bookkeeping"]
    assert summary["build_outputs_policy"] == unit["build_output_dispositions"]["policy_identity"]
    assert unit["outputs_sha256"]
    for command in unit["commands"]:
        assert file_sha256(run_root / command["stdout"]["path"]) == command["stdout"]["sha256"]
    assert file_sha256(run_root / unit["workspace_manifest"]["path"]) == unit["workspace_manifest"]["sha256"]
    assert file_sha256(run_root / unit["replay"]["path"]) == unit["replay"]["sha256"]


def test_rebuild_replays_the_accepted_commands_with_the_flags_in_the_environment(
        accepted_base, tmp_path: Path) -> None:
    _config, outcome, _run_root, fakes = _sanitize(accepted_base, tmp_path)
    assert outcome["status"] == "SUCCEEDED"
    runs = fakes[0].runs
    assert [run["command"] for run in runs] == [
        ("cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
         "-DCMAKE_BUILD_TYPE=RelWithDebInfo"),
        ("cmake", "--build", "build", "--parallel", "2")]
    assert {run["workdir"] for run in runs} == {"native"}
    flags = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    for run in runs:
        for variable in ("CFLAGS", "CXXFLAGS", "LDFLAGS"):
            assert run["environment"][variable] == flags
        assert run["environment"]["ASAN_OPTIONS"] == "detect_leaks=0"
        docker = run["docker"]
        assert "--cap-drop" in docker and docker[docker.index("--cap-drop") + 1] == "ALL"
        assert docker[docker.index("--user") + 1].split(":")[0] != "0"  # never root
        assert "no-new-privileges" in docker and "--read-only" in docker


def test_only_build_tools_run_and_never_a_produced_binary(accepted_base, tmp_path: Path) -> None:
    _config, _outcome, run_root, fakes = _sanitize(accepted_base, tmp_path)
    produced = {path.name for path in (run_root / "data" / "sanitizer").rglob("*") if path.is_file()}
    assert "sample" in produced  # the instrumented binary exists but was only ever read
    for run in fakes[0].runs:
        assert Path(run["command"][0]).name == "cmake"
        assert not ({Path(argument).name for argument in run["command"]} & {"sample", "main.cpp.o", "a.out"})


def test_normal_build_tree_and_downstream_consumers_are_untouched(accepted_base, tmp_path: Path) -> None:
    config, target, fingerprint, run_id = _clone(accepted_base, tmp_path)
    run_root = config.runtime.runs_dir / run_id
    accepted = load_accepted_language_build(run_root)
    normal = run_root / accepted["receipts"][0]["workspace"]

    def tree() -> dict[str, str]:
        return {path.relative_to(normal).as_posix(): file_sha256(path) for path in normal.rglob("*")
                if path.is_file()}

    before = tree()
    outcome = GraphRunner(config, [build_job(
        executor_factory=lambda unit, profile: DockerFake(profile).executor())]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "SUCCEEDED"
    assert tree() == before
    assert load_accepted_language_build(run_root)["language_build_handoff_sha256"] == \
        accepted["language_build_handoff_sha256"]
    assert normal.parts[-4:-1] == ("native", "units", accepted["receipts"][0]["build_unit_id"])
    assert (run_root / "data" / "sanitizer" / accepted["receipts"][0]["build_unit_id"] / "workspace").is_dir()


def test_every_file_the_job_writes_is_claimed_by_a_dataset_declaration(accepted_base, tmp_path: Path) -> None:
    config, _outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path)
    steps = tuple(config.job(JOB_ID).steps)
    claims = runtime_claims({JOB_ID: steps}) + [Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS]
    tree = scan_run_tree(run_root, FileClaims(claims), max_files=1_000_000)
    mine = [path for path in tree.unaccounted if path.startswith(("data/sanitizer", f"data/jobs/{JOB_ID}"))]
    assert mine == []
    kinds = {key[2] for key in tree.groups if key[0] == JOB_ID}
    assert {"sanitizer_build_summary", "sanitizer_build_workspaces"} <= kinds


# --------------------------------------------------------------------------- named gaps


def _only_unit(outcome, run_root: Path) -> tuple[dict, dict]:
    summary = _summary(outcome, run_root)
    return summary, summary["units"][0]


def test_flags_the_build_ignored_are_a_gap_not_a_clean_result(accepted_base, tmp_path: Path) -> None:
    _config, outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path, mode="ignore_env")
    summary, unit = _only_unit(outcome, run_root)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert unit["terminal_status"] == "COMPLETED_WITH_GAPS" and unit["instrumented"] is False
    assert any("no address sanitizer runtime reference" in gap and "the build did not take the flags" in gap
               for gap in unit["gaps"])
    assert all(output["instrumented"] is False for output in unit["outputs"])
    assert summary["counts"]["instrumented_units"] == 0 and summary["counts"]["instrumented_outputs"] == 0
    assert any(gap.startswith(unit["build_unit_id"]) for gap in summary["gaps"])


def test_a_stripped_instrumented_binary_cannot_be_proven(accepted_base, tmp_path: Path) -> None:
    _config, outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path, mode="stripped")
    _summary_doc, unit = _only_unit(outcome, run_root)
    assert outcome["status"] == "COMPLETED_WITH_GAPS" and unit["instrumented"] is False
    assert any("no symbol tables" in gap for gap in unit["gaps"])


def test_a_build_that_produces_no_binaries_is_a_gap(accepted_base, tmp_path: Path) -> None:
    _config, outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path, mode="no_binaries")
    _summary_doc, unit = _only_unit(outcome, run_root)
    assert outcome["status"] == "COMPLETED_WITH_GAPS" and unit["outputs"] == []
    assert any("produced no native objects" in gap for gap in unit["gaps"])


def test_a_failed_instrumented_build_is_a_failed_unit_with_a_named_gap(accepted_base, tmp_path: Path) -> None:
    _config, outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path, fail_ordinal=2)
    summary, unit = _only_unit(outcome, run_root)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert unit["terminal_status"] == "FAILED" and unit["instrumented"] is False and unit["outputs"] == []
    assert unit["gaps"] == ["instrumented build command 2 exited 2"]
    assert [item["exit_code"] for item in unit["commands"]] == [0, 2]
    assert summary["counts"]["instrumented_outputs"] == 0


def test_a_missing_sanitizer_runtime_in_the_build_image_is_named(accepted_base, tmp_path: Path) -> None:
    _config, outcome, run_root, _fakes = _sanitize(accepted_base, tmp_path, mode="missing_runtime", fail_ordinal=2)
    _summary_doc, unit = _only_unit(outcome, run_root)
    assert unit["terminal_status"] == "FAILED"
    assert unit["gaps"] == ["instrumented build command 2 exited 1; the build image lacks the sanitizer runtime "
                            "libclang_rt.asan-x86_64.a"]
