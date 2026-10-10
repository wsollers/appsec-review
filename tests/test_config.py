import copy
import hashlib
import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config import (
    BuildCaptureConfig, CodeQLAnalysisSettings, CodeQLExecutionMode, LanguageBuildSettings,
    ProcessingMode, load_config,
)
from appsec_review.config.codeql import parse_codeql_settings
from appsec_review.config.loader import _build_capture, _processing_mode
from appsec_review.runtime.resume import job_config_sha256


ROOT = Path(__file__).parents[1]


def _variant(tmp_path: Path, *replacements: tuple[str, str], suffix: str = ""):
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    for old, new in replacements:
        assert old in source
        source = source.replace(old, new, 1)
    path = tmp_path / "appsec-review.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source + suffix, encoding="utf-8")
    return load_config(path)


def test_default_config_declares_midnight_nvd_schedule() -> None:
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    job = config.job("job_third_party_data_sync")

    assert job.name == "third_party_data_sync"
    assert job.workers == 3
    assert job.schedule is not None
    assert job.schedule.enabled is True
    assert job.schedule.cron == "0 0 * * *"
    assert job.schedule.timezone == "UTC"
    assert config.runtime.metadata_dir == config.runtime.runs_dir / "metadata"
    assert config.tools.disable_grype is True
    assert config.build_capture == BuildCaptureConfig(
        "ptrace", 100000, 256, 16384, True, 1024, 131072,
        ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NODE_AUTH_TOKEN", "NUGET_AUTH_TOKEN",
         "PIP_INDEX_URL"), 4096, 10000, 1000)
    assert config.job("job_project_build").build_capture.event_count_limit == 250000
    assert config.job("job_language_build").build_capture.event_count_limit == 250000
    assert config.job("job_codeql_analysis").build_capture == config.build_capture
    assert set(job.steps) == {"nvd_sync", "osv_sync", "mitre_sync", "cve_bin_tool_db_build"}
    assert tuple(job.step("nvd_sync").tasks) == ("fetch", "process", "publish")
    assert tuple(job.step("osv_sync").tasks) == ("fetch", "index", "publish")
    assert tuple(job.step("mitre_sync").tasks) == ("fetch", "normalize", "publish")
    assert tuple(job.step("cve_bin_tool_db_build").tasks) == ("resolve_nvd_snapshot", "build", "publish")
    assert job.step("osv_sync").settings["ecosystems"] == ["PyPI"]
    assert job.step("mitre_sync").settings["source_selections"] == ["enterprise_attack", "capec", "cwe"]


def test_configuration_accepts_a_file_uri() -> None:
    path = Path(__file__).parents[1] / "appsec-review.toml"
    assert load_config(path.as_uri()).source_sha256 == load_config(path).source_sha256


def test_global_grype_policy_is_strictly_typed(tmp_path: Path) -> None:
    source = (Path(__file__).parents[1] / "appsec-review.toml").read_text(encoding="utf-8")
    path = tmp_path / "appsec-review.toml"
    path.write_text(source.replace("disable_grype = true", 'disable_grype = "true"'), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a Boolean"):
        load_config(path)


def test_language_build_has_typed_rust_limits_and_policy() -> None:
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    settings = config.job("job_language_build").typed_settings
    assert isinstance(settings, LanguageBuildSettings)
    assert settings.rust.toolchain == "stable"
    assert settings.rust.offline is False
    assert settings.go.offline is False
    assert settings.node.network == "allowed" and settings.node.require_lockfile is False
    assert settings.python.offline is False and settings.python.require_locked_dependencies is False
    assert settings.dotnet.require_locked_restore is False
    assert settings.rust.locked is False
    assert settings.rust.diagnostic_tail_bytes == 32768


def test_codeql_analysis_has_typed_cross_language_policy() -> None:
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    settings = config.job("job_codeql_analysis").typed_settings
    assert isinstance(settings, CodeQLAnalysisSettings)
    assert set(settings.languages) == {
        "actions", "cpp", "csharp", "go", "java", "javascript", "python", "rust"}
    assert settings.languages["java"].source_languages == ("Java", "Kotlin")
    assert settings.execution_mode is CodeQLExecutionMode.AUTO
    assert settings.languages["rust"].mode is CodeQLExecutionMode.SOURCE
    assert settings.languages["cpp"].mode is CodeQLExecutionMode.BUILD
    assert settings.languages["cpp"].query_suite == "codeql-suites/cpp-code-scanning.qls"
    assert [item.query_id for item in settings.languages["cpp"].custom_queries] == ["cert-cpp"]
    assert settings.retention == "run-owned"


@pytest.mark.parametrize("mode", list(ProcessingMode))
def test_every_build_capture_mode_is_typed(mode: ProcessingMode, tmp_path: Path) -> None:
    config = _variant(tmp_path, ('mode = "required"', f'mode = "{mode.value}"'))
    assert config.build_capture.mode is mode
    assert config.job("job_project_build").build_capture.mode is mode


def test_build_capture_job_override_is_bounded_and_inherits_other_limits(tmp_path: Path) -> None:
    config = _variant(tmp_path, (
        "[jobs.job_language_build.settings.build_capture]\nevent_count_limit = 250000",
        "[jobs.job_language_build.settings.build_capture]\nmode = \"auto\"\nevent_count_limit = 250000",
    ))
    capture = config.job("job_language_build").build_capture
    assert capture.mode is ProcessingMode.AUTO
    assert capture.event_count_limit == 250000
    assert config.job("job_project_build").build_capture.mode is ProcessingMode.REQUIRED


def test_processing_mode_defaults_are_explicit_when_omitted(tmp_path: Path) -> None:
    config = _variant(tmp_path,
        ('mode = "required"\n', ''),
        ('compiler_artifact_collection_mode = "required"\n', ''),
        ('execution_mode = "auto"\n', ''))
    assert config.build_capture.mode is ProcessingMode.REQUIRED
    assert config.job("job_language_build").typed_settings.compiler_artifact_collection_mode is (
        ProcessingMode.REQUIRED)
    assert config.job("job_codeql_analysis").typed_settings.execution_mode is (
        CodeQLExecutionMode.AUTO)
    resolved = json.loads(config.resolved_json)
    assert resolved["build_capture"]["mode"] == "required"
    assert resolved["jobs"]["job_language_build"]["settings"][
        "compiler_artifact_collection_mode"] == "required"
    assert resolved["jobs"]["job_codeql_analysis"]["settings"]["execution_mode"] == "auto"


@pytest.mark.parametrize("mode", list(ProcessingMode))
def test_every_compiler_artifact_mode_is_typed(mode: ProcessingMode, tmp_path: Path) -> None:
    config = _variant(tmp_path, (
        'compiler_artifact_collection_mode = "required"',
        f'compiler_artifact_collection_mode = "{mode.value}"',
    ))
    settings = config.job("job_language_build").typed_settings
    assert settings.compiler_artifact_collection_mode is mode
    assert settings.compiler_artifact_mode("node") is mode


@pytest.mark.parametrize("mode", list(ProcessingMode))
def test_every_compiler_artifact_language_override_is_typed(
        mode: ProcessingMode, tmp_path: Path) -> None:
    config = _variant(tmp_path, ('native = "required"', f'native = "{mode.value}"'))
    settings = config.job("job_language_build").typed_settings
    assert settings.compiler_artifact_mode("native") is mode
    assert settings.compiler_artifact_mode("go") is ProcessingMode.REQUIRED


@pytest.mark.parametrize("mode", list(CodeQLExecutionMode))
def test_every_codeql_default_execution_mode_is_typed(
        mode: CodeQLExecutionMode, tmp_path: Path) -> None:
    enabled = "false" if mode is CodeQLExecutionMode.DISABLED else "true"
    config = _variant(tmp_path, (
        'enabled = true\nexecution_mode = "auto"',
        f'enabled = {enabled}\nexecution_mode = "{mode.value}"',
    ))
    assert config.job("job_codeql_analysis").typed_settings.execution_mode is mode


@pytest.mark.parametrize("mode", list(CodeQLExecutionMode))
def test_every_codeql_language_override_is_typed(
        mode: CodeQLExecutionMode, tmp_path: Path) -> None:
    enabled = "false" if mode is CodeQLExecutionMode.DISABLED else "true"
    config = _variant(tmp_path, (
        '[jobs.job_codeql_analysis.settings.languages.cpp]\nenabled = true\nmode = "build"',
        f'[jobs.job_codeql_analysis.settings.languages.cpp]\nenabled = {enabled}\nmode = "{mode.value}"',
    ))
    assert config.job("job_codeql_analysis").typed_settings.languages["cpp"].mode is mode


def test_codeql_language_without_override_inherits_typed_default(tmp_path: Path) -> None:
    config = _variant(tmp_path,
        ('execution_mode = "auto"', 'execution_mode = "source"'),
        ('enabled = true\nmode = "build"', 'enabled = true'))
    assert config.job("job_codeql_analysis").typed_settings.languages[
        "cpp"].mode is CodeQLExecutionMode.SOURCE


@pytest.mark.parametrize("bad", ['"REQUIRED"', '"requried"', "1", "true"])
def test_processing_modes_reject_unknown_case_and_wrong_types(
        bad: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="required, auto, disabled"):
        _variant(tmp_path, ('mode = "required"', f"mode = {bad}"))
    with pytest.raises(ValueError, match="required, auto, disabled"):
        _variant(tmp_path, (
            'compiler_artifact_collection_mode = "required"',
            f"compiler_artifact_collection_mode = {bad}",
        ))


@pytest.mark.parametrize("bad", ['"BUILD"', '"manualx"', "1", "true"])
def test_codeql_modes_reject_unknown_case_and_wrong_types(bad: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="build, source, auto, disabled"):
        _variant(tmp_path, ('execution_mode = "auto"', f"execution_mode = {bad}"))
    with pytest.raises(ValueError, match="build, source, auto, disabled"):
        _variant(tmp_path, ('mode = "build"', f"mode = {bad}"))


def test_processing_modes_reject_null_and_malformed_values() -> None:
    base = load_config(ROOT / "appsec-review.toml").build_capture
    with pytest.raises(ValueError, match="required, auto, disabled"):
        _processing_mode(None, "mode")
    with pytest.raises(ValueError, match="required, auto, disabled"):
        _build_capture({"mode": {"value": "required"}}, base=base)

    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    codeql = raw["jobs"]["job_codeql_analysis"]["settings"]
    for field, value in (("execution_mode", None), ("execution_mode", {"value": "auto"})):
        malformed = copy.deepcopy(codeql)
        malformed[field] = value
        with pytest.raises(ValueError, match="build, source, auto, disabled"):
            parse_codeql_settings(malformed)


def test_mode_override_targets_and_duplicate_definitions_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown settings"):
        _variant(tmp_path / "typo", (
            'compiler_artifact_collection_mode = "required"',
            'compiler_artifact_collecton_mode = "required"'))
    with pytest.raises(ValueError, match="must be a table"):
        _variant(tmp_path / "malformed", (
            '[jobs.job_language_build.settings.compiler_artifact_collection_overrides]\n'
            'native = "required"\ngo = "required"\ndotnet = "required"\nrust = "required"',
            'compiler_artifact_collection_overrides = "required"'))
    with pytest.raises(ValueError, match="unknown compiler-artifact override targets"):
        _variant(tmp_path, ('rust = "required"', 'rust = "required"\nruby = "auto"'))
    with pytest.raises(ValueError, match="not a supported override target"):
        _variant(tmp_path, suffix=(
            "\n[jobs.job_review_intake.settings.build_capture]\nmode = \"auto\"\n"))
    with pytest.raises(ValueError, match="unknown CodeQL language override target"):
        _variant(tmp_path, suffix=(
            "\n[jobs.job_codeql_analysis.settings.languages.ruby]\nmode = \"source\"\n"))
    with pytest.raises(tomllib.TOMLDecodeError):
        _variant(tmp_path, ('mode = "required"', 'mode = "required"\nmode = "auto"'))


def test_codeql_legacy_modes_normalize_one_way_and_reject_ambiguous_enablement() -> None:
    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    value = raw["jobs"]["job_codeql_analysis"]["settings"]
    legacy = copy.deepcopy(value)
    legacy["languages"]["cpp"]["mode"] = "manual"
    legacy["languages"]["python"]["mode"] = "none"
    parsed = parse_codeql_settings(legacy)
    assert parsed.languages["cpp"].mode is CodeQLExecutionMode.BUILD
    assert parsed.languages["python"].mode is CodeQLExecutionMode.SOURCE

    ambiguous = copy.deepcopy(value)
    ambiguous["languages"]["cpp"].update(enabled=False, mode="build")
    with pytest.raises(ValueError, match="conflict"):
        parse_codeql_settings(ambiguous)
    ambiguous = copy.deepcopy(value)
    ambiguous.update(enabled=True, execution_mode="disabled")
    with pytest.raises(ValueError, match="conflict"):
        parse_codeql_settings(ambiguous)


def test_resolved_serialization_is_canonical_and_mode_hashes_are_consequential(
        tmp_path: Path) -> None:
    baseline = load_config(ROOT / "appsec-review.toml")
    identical = _variant(tmp_path)
    assert identical.resolved_json == baseline.resolved_json
    assert identical.resolved_sha256 == hashlib.sha256(identical.resolved_json).hexdigest()
    document = json.loads(baseline.resolved_json)
    assert document["build_capture"]["mode"] == "required"
    assert document["jobs"]["job_language_build"]["settings"][
        "compiler_artifact_collection_overrides"]["native"] == "required"
    assert document["jobs"]["job_codeql_analysis"]["settings"]["languages"]["cpp"][
        "mode"] == "build"

    variants = (
        _variant(tmp_path / "capture", ('mode = "required"', 'mode = "auto"')),
        _variant(tmp_path / "artifacts", (
            'compiler_artifact_collection_mode = "required"',
            'compiler_artifact_collection_mode = "auto"')),
        _variant(tmp_path / "codeql", ('execution_mode = "auto"', 'execution_mode = "source"')),
    )
    assert len({baseline.resolved_sha256, *(item.resolved_sha256 for item in variants)}) == 4
    assert job_config_sha256(baseline, "job_project_build") != job_config_sha256(
        variants[0], "job_project_build")
    assert job_config_sha256(baseline, "job_language_build") != job_config_sha256(
        variants[1], "job_language_build")
    assert job_config_sha256(baseline, "job_codeql_analysis") != job_config_sha256(
        variants[2], "job_codeql_analysis")

    overrides = (
        _variant(tmp_path / "capture-override", (
            "[jobs.job_language_build.settings.build_capture]\nevent_count_limit = 250000",
            "[jobs.job_language_build.settings.build_capture]\nmode = \"auto\"\n"
            "event_count_limit = 250000")),
        _variant(tmp_path / "artifact-override", (
            'native = "required"', 'native = "auto"')),
        _variant(tmp_path / "codeql-override", (
            'mode = "build"', 'mode = "source"')),
    )
    assert all(item.resolved_sha256 != baseline.resolved_sha256 for item in overrides)
    assert job_config_sha256(baseline, "job_language_build") != job_config_sha256(
        overrides[0], "job_language_build")
    assert job_config_sha256(baseline, "job_language_build") != job_config_sha256(
        overrides[1], "job_language_build")
    assert job_config_sha256(baseline, "job_codeql_analysis") != job_config_sha256(
        overrides[2], "job_codeql_analysis")

    legacy = _variant(tmp_path / "legacy", ('mode = "build"', 'mode = "manual"'))
    assert legacy.resolved_json == baseline.resolved_json
    assert b'"manual"' not in legacy.resolved_json


def test_verified_language_defaults_remain_required_and_codeql_capable() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    language = config.job("job_language_build").typed_settings
    assert config.job("job_project_build").build_capture.mode is ProcessingMode.REQUIRED
    assert config.job("job_language_build").build_capture.mode is ProcessingMode.REQUIRED
    assert {name: language.compiler_artifact_mode(name) for name in
            ("native", "dotnet", "rust", "go")} == {
        name: ProcessingMode.REQUIRED for name in ("native", "dotnet", "rust", "go")}
    codeql = config.job("job_codeql_analysis").typed_settings
    assert {name: codeql.languages[name].mode for name in ("cpp", "csharp", "go")} == {
        name: CodeQLExecutionMode.BUILD for name in ("cpp", "csharp", "go")}
    assert codeql.languages["rust"].mode is CodeQLExecutionMode.SOURCE
