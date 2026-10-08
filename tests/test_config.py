from pathlib import Path

from appsec_review.config import load_config


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
    assert set(job.steps) == {"nvd_sync", "osv_sync", "mitre_sync", "cve_bin_tool_db_build"}
    assert tuple(job.step("nvd_sync").tasks) == ("fetch", "process", "publish")
    assert tuple(job.step("osv_sync").tasks) == ("fetch", "index", "publish")
    assert tuple(job.step("mitre_sync").tasks) == ("fetch", "normalize", "publish")
    assert tuple(job.step("cve_bin_tool_db_build").tasks) == ("resolve_nvd_snapshot", "build", "publish")
    assert job.step("osv_sync").settings["ecosystems"] == ["PyPI"]
    assert job.step("mitre_sync").settings["source_selections"] == ["enterprise_attack", "capec", "cwe"]
