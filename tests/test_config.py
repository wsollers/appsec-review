from pathlib import Path

from appsec_review.config import load_config


def test_default_config_declares_midnight_nvd_schedule() -> None:
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    job = config.job("job_third_party_data_sync")

    assert job.name == "third_party_data_sync"
    assert job.workers == 1
    assert job.schedule is not None
    assert job.schedule.enabled is True
    assert job.schedule.cron == "0 0 * * *"
    assert job.schedule.timezone == "UTC"
    step = job.step("nvd_sync")
    assert set(step.tasks) == {"fetch", "process", "build"}
