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
from tests.test_language_build import (
    ImageResolver, NativeExecutor, NativeRecipeModel, _fixture, native_language_executor,
)
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[1]
SETTINGS = {
    "enabled": True, "workers": 1, "sanitizers": ["address", "undefined"],
    "extra_flags": ["-fno-omit-frame-pointer", "-g", "-O1"], "required_evidence": ["address"],
    "build_systems": ["cmake", "autotools", "meson", "make"],
    "build_environment": {"ASAN_OPTIONS": "detect_leaks=0"},
    "command_timeout_seconds": 60, "output_bytes": 1_000_000, "artifact_count_limit": 100, "max_units": 4,
}


def _settings(**overrides) -> SanitizerBuildSettings:
    return SanitizerBuildSettings.from_mapping({**deepcopy(SETTINGS), **overrides})


# --------------------------------------------------------------------------- configuration


def test_shipped_configuration_is_valid_and_declares_the_job() -> None:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    job = document["jobs"][JOB_ID]
    settings = SanitizerBuildSettings.from_mapping(job["settings"])
    assert settings.enabled and settings.sanitizers == ("address", "undefined")
    assert settings.flags == ("-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1")
    assert tuple(job["steps"]) == ("load", "build", "acceptance")
    assert {unit.unit_id for unit in build_job().units} == {
        "load.accepted_native", "build.units", "acceptance.publish_handoff"}


@pytest.mark.parametrize(("override", "message"), [
    ({"enabled": "yes"}, "enabled must be a boolean"),
    ({"workers": 0}, "workers must be a positive integer"),
    ({"max_units": True}, "max_units must be a positive integer"),
    ({"sanitizers": []}, "sanitizers must be a non-empty"),
    ({"sanitizers": ["address", "thread"]}, "sanitizers must be a non-empty"),
    ({"sanitizers": ["address", "address"]}, "sanitizers must be a non-empty"),
    ({"sanitizers": ["address"], "required_evidence": ["undefined"]}, "subset of sanitizers"),
    ({"build_systems": ["gradle"]}, "build_systems must be a non-empty"),
    ({"extra_flags": ["-fno-sanitize=address"]}, "extra_flags"),
    ({"extra_flags": ["-g -O0"]}, "extra_flags"),
    ({"build_environment": {"CXXFLAGS": "-O0"}}, "build_environment entry is invalid"),
    ({"build_environment": {"API_TOKEN": "x"}}, "build_environment entry is invalid"),
    ({"build_environment": {"lower": "x"}}, "build_environment entry is invalid"),
], ids=lambda value: str(value)[:40])
def test_invalid_settings_are_rejected(override, message) -> None:
    with pytest.raises(ValueError, match=message):
        _settings(**override)


def test_unknown_and_missing_settings_are_rejected() -> None:
    with pytest.raises(ValueError, match="exactly its documented keys"):
        SanitizerBuildSettings.from_mapping({**SETTINGS, "surprise": 1})
    with pytest.raises(ValueError, match="exactly its documented keys"):
        SanitizerBuildSettings.from_mapping({key: value for key, value in SETTINGS.items() if key != "workers"})


def test_single_sanitizer_configuration_changes_the_flags() -> None:
    settings = _settings(sanitizers=["address"], required_evidence=["address"], extra_flags=[])
    assert settings.flags == ("-fsanitize=address",)


# --------------------------------------------------------------------------- flag and environment construction


def test_environment_places_sanitizer_flags_first_and_keeps_recipe_flags() -> None:
    environment, conflicts = instrumented_environment(
        _settings(), {"CFLAGS": "-Wall", "OTHER": "kept"})
    flags = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    assert conflicts == []
    assert environment["CFLAGS"] == f"{flags} -Wall"
    assert environment["CXXFLAGS"] == environment["LDFLAGS"] == flags
    assert environment["ASAN_OPTIONS"] == "detect_leaks=0" and environment["OTHER"] == "kept"


@pytest.mark.parametrize("recorded", [
    {"CXXFLAGS": "-fsanitize=thread"}, {"LDFLAGS": "-fno-sanitize=undefined"},
    {"ASAN_OPTIONS": "detect_leaks=1"},
])
def test_recipe_environment_that_contradicts_the_flags_is_a_conflict(recorded) -> None:
    _environment, conflicts = instrumented_environment(_settings(), recorded)
    assert len(conflicts) == 1


@pytest.mark.parametrize("argv", [
    ["cmake", "-S", ".", "-B", "build", "-DCMAKE_CXX_FLAGS=-O0"],
    ["cmake", "-S", ".", "-DCMAKE_C_FLAGS:STRING=-O0"],
    ["cmake", "-DCMAKE_EXE_LINKER_FLAGS=-static"],
    ["cmake", "-DCMAKE_CXX_FLAGS=-fsanitize=thread"],
    ["make", "CXXFLAGS=-O3"],
    ["./configure", "CFLAGS=-g"],
    ["meson", "setup", "build", "-Db_sanitize=thread"],
    ["meson", "setup", "build", "-Dc_args=-O0"],
    ["gcc", "-fsanitize=address", "-c", "x.c"],
])
def test_command_lines_that_mask_the_environment_flags_are_conflicts(argv) -> None:
    assert len(argument_conflicts([["true"], argv])) == 1


@pytest.mark.parametrize("argv", [
    ["cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
    ["cmake", "-DCMAKE_CXX_FLAGS_DEBUG=-O0"],
    ["cmake", "--build", "build", "--parallel", "2"],
    ["make", "-j2"],
])
def test_ordinary_command_lines_are_not_conflicts(argv) -> None:
    assert argument_conflicts([argv]) == []


# --------------------------------------------------------------------------- ELF evidence


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_symbol_reader_separates_defined_and_undefined_names(tmp_path: Path) -> None:
    path = _write(tmp_path, "x.o", elf_with_symbols(ET_REL, defined=("main", "__asan_runtime_probe"),
                                                    undefined=("__asan_init", "puts")))
    facts = elf.symbol_names(path, ("__asan_",))
    assert facts["tables"] == [".symtab"]
    assert facts["defined"] == ["__asan_runtime_probe"] and facts["undefined"] == ["__asan_init"]


def test_instrumented_and_plain_objects_are_told_apart(tmp_path: Path) -> None:
    on = runtime_evidence(_write(tmp_path, "on.o", instrumented_elf(ET_REL)), "object")
    off = runtime_evidence(_write(tmp_path, "off.o", elf_with_symbols(ET_REL, undefined=("puts",))), "object")
    assert on["evidence_status"] == off["evidence_status"] == "resolved"
    assert on["sanitizers"]["address"]["runtime_referenced"] is True
    assert on["sanitizers"]["address"]["imports_runtime"] is True
    assert "__asan_init" in on["sanitizers"]["address"]["symbols"]
    assert on["sanitizers"]["undefined"]["runtime_referenced"] is True
    assert off["sanitizers"]["address"]["runtime_referenced"] is False
    assert off["sanitizers"]["undefined"]["runtime_referenced"] is False


def test_a_stripped_or_malformed_file_proves_nothing_either_way(tmp_path: Path) -> None:
    stripped = runtime_evidence(_write(tmp_path, "s", instrumented_elf(symbol_tables=False)), "executable")
    assert stripped["evidence_status"] == "no_symbol_tables"
    assert stripped["sanitizers"]["address"]["runtime_referenced"] is False
    broken = runtime_evidence(_write(tmp_path, "b", b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 20), "executable")
    assert broken["evidence_status"] == "unparsed" and "error" in broken
    assert runtime_evidence(tmp_path / "libx.a", "static-library")["evidence_status"] == "not_inspected"


def test_a_named_sanitizer_runtime_library_counts_as_linked(tmp_path: Path, monkeypatch) -> None:
    path = _write(tmp_path, "app", elf_with_symbols(undefined=("puts",)))
    monkeypatch.setattr(elf, "loader_facts", lambda _path: {"needed": ["libasan.so.8", "libc.so.6"]})
    evidence = runtime_evidence(path, "executable")
    assert evidence["sanitizers"]["address"]["runtime_libraries"] == ["libasan.so.8"]
    assert evidence["sanitizers"]["address"]["runtime_referenced"] is True
    assert evidence["sanitizers"]["undefined"]["runtime_referenced"] is False


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


# --------------------------------------------------------------------------- accepted-recipe conflicts


def _doctored(run_root: Path, receipt: dict, index: int, change) -> dict:
    """The receipt with command ``index``'s protected argv rewritten, hash-consistently."""
    receipt = deepcopy(receipt)
    command = receipt["commands"][index]
    path = run_root / command["protected_argv"]["path"]
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    rewritten = path.with_name("doctored-" + path.name)
    rewritten.write_text(json.dumps(document), encoding="utf-8")
    command["protected_argv"] = {"path": rewritten.relative_to(run_root).as_posix(), "sha256": file_sha256(rewritten)}
    command["argv_sha256"] = hashlib.sha256(canonical_json(document["argv"])).hexdigest()
    return receipt


def _unit_context(run_root: Path, config, target: Path, fingerprint: str, outputs=None,
                  settings: dict | None = None) -> UnitContext:
    job_config = SimpleNamespace(settings=settings or deepcopy(SETTINGS), steps=config.job(JOB_ID).steps,
                                 step=config.job(JOB_ID).step)
    events = SimpleNamespace(write=lambda *args, **kwargs: None)
    job = SimpleNamespace(run_root=run_root, target_root=target, source_fingerprint=fingerprint,
                          config=job_config, events=events, attempt_id="attempt_0001")
    unit_root = run_root / "unit"
    unit_root.mkdir(exist_ok=True)
    return UnitContext(job, "build.units", "build", "units", unit_root, MappingProxyType(outputs or {}))


def _receipt_context(accepted_base, tmp_path: Path):
    config, target, fingerprint, run_id = _clone(accepted_base, tmp_path)
    run_root = config.runtime.runs_dir / run_id
    receipt = load_accepted_language_build(run_root)["receipts"][0]
    return run_root, receipt, _unit_context(run_root, config, target, fingerprint)


def _never_started(_unit, _profile):
    raise AssertionError("no container may be started for a unit that cannot be instrumented")


@pytest.mark.parametrize("extra", [["-DCMAKE_CXX_FLAGS=-O0"], ["-DCMAKE_EXE_LINKER_FLAGS=-static"],
                                   ["-DCMAKE_CXX_FLAGS=-fsanitize=thread"]])
def test_recipe_flags_that_mask_the_environment_are_a_gap_and_nothing_is_built(
        accepted_base, tmp_path: Path, extra) -> None:
    run_root, receipt, context = _receipt_context(accepted_base, tmp_path)
    doctored = _doctored(run_root, receipt, 0, lambda document: document["argv"].extend(extra))
    unit = sanitizer_job._build_unit(context, doctored, _settings(), _never_started)
    assert unit["terminal_status"] == "COMPLETED_WITH_GAPS" and unit["instrumented"] is False
    assert len(unit["gaps"]) == 1 and "cannot be injected through the environment" in unit["gaps"][0]
    assert not (run_root / "data" / "sanitizer" / unit["build_unit_id"]).exists()


def test_recipe_environment_that_contradicts_the_flags_is_a_gap(accepted_base, tmp_path: Path) -> None:
    run_root, receipt, context = _receipt_context(accepted_base, tmp_path)
    doctored = _doctored(run_root, receipt, 1, lambda document: document["environment"].update(
        CXXFLAGS="-fsanitize=thread"))
    unit = sanitizer_job._build_unit(context, doctored, _settings(), _never_started)
    assert unit["gaps"] == ["sanitizer flags cannot be injected through the environment: "
                            "recipe environment CXXFLAGS already selects sanitizer flags"]


def test_recipe_flags_in_the_environment_follow_the_sanitizer_flags(accepted_base, tmp_path: Path) -> None:
    run_root, receipt, context = _receipt_context(accepted_base, tmp_path)
    doctored = _doctored(run_root, receipt, 0, lambda document: document["environment"].update(CFLAGS="-Wall"))
    fakes: list[DockerFake] = []

    def factory(_unit, profile):
        fakes.append(DockerFake(profile))
        return fakes[0].executor()

    unit = sanitizer_job._build_unit(context, doctored, _settings(), factory)
    assert unit["terminal_status"] == "SUCCEEDED"
    assert fakes[0].runs[0]["environment"]["CFLAGS"] == \
        "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -Wall"
    assert fakes[0].runs[1]["environment"]["CFLAGS"] == "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"


def test_unsupported_build_system_and_unreplayable_units_are_gaps(accepted_base, tmp_path: Path) -> None:
    run_root, receipt, context = _receipt_context(accepted_base, tmp_path)
    unsupported = sanitizer_job._build_unit(context, receipt, _settings(build_systems=["meson"]), _never_started)
    assert unsupported["gaps"] == ["build system 'cmake' is not enabled for sanitizer rebuilds (configured: meson)"]
    assert unsupported["terminal_status"] == "COMPLETED_WITH_GAPS" and unsupported["workspace"] is None

    stripped = deepcopy(receipt)
    for command in stripped["commands"]:
        command.pop("protected_argv")
    assert sanitizer_job._build_unit(context, stripped, _settings(), _never_started)["gaps"] == [
        "not replayable: accepted build command lacks its protected argv"]

    incomplete = deepcopy(receipt)
    incomplete["commands"] = incomplete["commands"][:1]
    assert sanitizer_job._build_unit(context, incomplete, _settings(), _never_started)["gaps"] == [
        "not replayable: accepted build command set is incomplete"]

    failed = {**deepcopy(receipt), "terminal_status": "FAILED"}
    assert "did not succeed" in sanitizer_job._build_unit(context, failed, _settings(), _never_started)["gaps"][0]


def test_a_changed_protected_command_is_an_integrity_failure(accepted_base, tmp_path: Path) -> None:
    run_root, receipt, _context = _receipt_context(accepted_base, tmp_path)
    path = run_root / receipt["commands"][0]["protected_argv"]["path"]
    path.chmod(0o644)
    path.write_text(path.read_text(encoding="utf-8").replace("cmake", "cmakE"), encoding="utf-8")
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="identity changed"):
        sanitizer_job._replay(run_root, receipt)


def test_a_redacted_command_cannot_be_replayed(accepted_base, tmp_path: Path) -> None:
    run_root, receipt, _context = _receipt_context(accepted_base, tmp_path)
    doctored = _doctored(run_root, receipt, 0, lambda document: document.update(
        argv=["<redacted: secret scan disposition>"]))
    commands, error = sanitizer_job._replay(run_root, doctored)
    assert commands is None and "redacted by the secret scan" in error


# --------------------------------------------------------------------------- planning


def _accepted_document(*receipts) -> dict:
    return {"source_fingerprint": "f" * 64, "language_build_handoff_sha256": "a" * 64,
            "receipts": list(receipts)}


def _receipt(build_unit_id: str, family: str = "native") -> dict:
    return {"build_unit_id": build_unit_id, "family": family, "root": build_unit_id, "build_system": "cmake",
            "fingerprint": build_unit_id[-4:] * 16}


def test_only_native_units_are_planned_and_other_families_are_not_applicable(tmp_path: Path, monkeypatch) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    document = _accepted_document(_receipt("build-unit-b"), _receipt("build-unit-a"),
                                  _receipt("build-unit-n", "node"), _receipt("build-unit-c"))
    monkeypatch.setattr(sanitizer_job, "load_accepted_language_build", lambda _root: document)
    context = _unit_context(tmp_path, config, tmp_path, "f" * 64, settings={**deepcopy(SETTINGS), "max_units": 2})
    loaded = build_job().units[0].handler(context)
    assert [item["build_unit_id"] for item in loaded["planned"]] == ["build-unit-a", "build-unit-b"]
    assert [item["build_unit_id"] for item in loaded["omitted"]] == ["build-unit-c"]
    assert [(item["build_unit_id"], item["disposition"]) for item in loaded["not_applicable"]] == [
        ("build-unit-n", "SKIPPED_NA")]


def test_a_different_target_snapshot_stops_the_job(tmp_path: Path, monkeypatch) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    monkeypatch.setattr(sanitizer_job, "load_accepted_language_build",
                        lambda _root: {**_accepted_document(), "source_fingerprint": "0" * 64})
    with pytest.raises(sanitizer_job.FrameworkIntegrityError, match="snapshot differs"):
        build_job().units[0].handler(_unit_context(tmp_path, config, tmp_path, "f" * 64))


def test_no_native_units_is_not_applicable_and_omitted_units_are_gaps(tmp_path: Path, monkeypatch) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    build = build_job().units[1].handler
    empty = {"upstream": {"language_build_handoff_sha256": "a" * 64}, "planned": [], "omitted": [],
             "not_applicable": []}
    monkeypatch.setattr(sanitizer_job, "load_accepted_language_build", lambda _root: _accepted_document())
    context = _unit_context(tmp_path, config, tmp_path, "f" * 64, {"load.accepted_native": empty})
    assert build(context)["terminal_status"] == "NOT_APPLICABLE"
    bounded = {**empty, "omitted": [{"build_unit_id": "build-unit-c"}]}
    context = _unit_context(tmp_path, config, tmp_path, "f" * 64, {"load.accepted_native": bounded})
    result = build(context)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["gaps"] == ["build-unit-c: unit bound of 4 reached; this native build unit was not rebuilt"]


# --------------------------------------------------------------------------- topology and registry


def test_topology_places_the_job_after_language_build_with_one_terminal_job() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    jobs = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    assert jobs[JOB_ID]["dependencies"] == ["job_language_build"]
    assert "job_language_build" in jobs[JOB_ID]["upstream_handoffs"]
    depended = {dependency for item in jobs.values() for dependency in item["dependencies"]}
    assert set(jobs) - depended == {"job_document_issue_analysis"}  # exactly one terminal job
    consumers = [job_id for job_id, item in jobs.items() if JOB_ID in item["dependencies"]]
    assert consumers == ["job_review_data_indexing"]
    for sibling in ("job_cpp_compiled_analysis", "job_codeql_analysis", "job_clang_static_analysis",
                    "job_post_build_security_assessment", "job_security_tagging"):
        assert JOB_ID not in jobs[sibling]["upstream_handoffs"]


def test_only_the_dataset_inventory_declares_the_job_as_consumed() -> None:
    import importlib
    declaring = []
    for job_id in builtin_registry().job_ids():
        try:
            module = importlib.import_module(f"appsec_review.jobs.{job_id}.datasets")
        except ModuleNotFoundError:
            continue
        if JOB_ID in getattr(module, "CONSUMES", ()):
            declaring.append(job_id)
    assert declaring == ["job_review_data_indexing"]
    assert CONSUMES == ("job_language_build",)


def test_disabled_job_is_transparent_to_topology() -> None:
    from appsec_review.orchestration.topology import wave1_dependencies
    registered = {job_id for job_id in builtin_registry().job_ids()
                  if job_id not in {JOB_ID, "job_third_party_data_sync", "job_inference_security_review"}}
    dependencies = wave1_dependencies(registered)
    assert JOB_ID not in dependencies
    assert all(JOB_ID not in values for values in dependencies.values())


def test_dataset_declarations_are_protected_or_artifact_only_never_indexed() -> None:
    assert {item.output_kind: item.disposition for item in DATASETS} == {
        "sanitizer_build_summary": "artifact_only", "sanitizer_build_workspaces": "protected"}
    protected = next(item for item in DATASETS if item.disposition == "protected")
    assert protected.artifacts == ("data/sanitizer/**",) and protected.sensitivity == "sensitive"


def test_a_workspace_too_large_for_a_manifest_is_a_gap_not_a_crash(
        accepted_base, tmp_path: Path, monkeypatch) -> None:
    run_root, receipt, context = _receipt_context(accepted_base, tmp_path)
    real, calls = sanitizer_job._snapshot, []

    def snapshot(root, limit):
        calls.append(root)
        if len(calls) == 2:  # the pre-build snapshot is the first call; the manifest is the second
            raise ValueError("language-build workspace file-count bound exceeded")
        return real(root, limit)

    monkeypatch.setattr(sanitizer_job, "_snapshot", snapshot)
    unit = sanitizer_job._build_unit(context, receipt, _settings(),
                                     lambda _unit, profile: DockerFake(profile).executor())
    assert unit["terminal_status"] == "COMPLETED_WITH_GAPS" and unit["instrumented"] is False
    assert "workspace_manifest" not in unit
    assert unit["gaps"] == ["the instrumented workspace exceeds the file bound, so it has no manifest: "
                            "language-build workspace file-count bound exceeded"]
