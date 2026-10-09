from pathlib import Path

import pytest

from appsec_review.config import CodeQLAnalysisSettings, LanguageBuildSettings, load_config


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
    assert settings.rust.offline is True
    assert settings.rust.locked is False
    assert settings.rust.diagnostic_tail_bytes == 32768


def test_codeql_analysis_has_typed_cross_language_policy() -> None:
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    settings = config.job("job_codeql_analysis").typed_settings
    assert isinstance(settings, CodeQLAnalysisSettings)
    assert set(settings.languages) == {
        "actions", "cpp", "csharp", "go", "java", "javascript", "python", "rust"}
    assert settings.languages["java"].source_languages == ("Java", "Kotlin")
    assert settings.languages["rust"].mode == "none"
    assert settings.languages["cpp"].query_suite == "codeql-suites/cpp-code-scanning.qls"
    assert [item.query_id for item in settings.languages["cpp"].custom_queries] == ["cert-cpp"]
    assert settings.retention == "run-owned"
