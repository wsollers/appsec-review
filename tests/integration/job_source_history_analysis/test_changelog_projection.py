"""Pre-walk suite pending replacement: the history-to-analysis-plan consumer boundary."""
from appsec_review.jobs.job_source_history_analysis import changelog
from appsec_review.jobs.job_target_analysis_plan.planning import history_priority


def test_plan_projection_drops_change_log_files_the_catalog_does_not_accept() -> None:
    accepted = {"path": "src/auth.c", "sha256": "a" * 64, "rank": 1, "change_count": 2, "lifetime_change_count": 3,
                "last_change_date": "2024-03-10", "fix_change_count": 1, "security_fix_change_count": 1,
                "source": "changelog", "role": "primary", "source_id": "."}
    history = {"ranking": {}, "changelog": {"role": "primary", "identity": changelog.IDENTITY, "files": [
        accepted, {**accepted, "path": "src/gone.c"}, {**accepted, "path": "src/util.c", "sha256": "b" * 64}]}}
    catalog = {"files": [{"path": "src/auth.c", "sha256": "a" * 64}, {"path": "src/util.c", "sha256": "c" * 64}],
               "components": []}
    priority = history_priority(history, catalog)
    assert priority["status"] == "UNAVAILABLE" and priority["files"] == []
    assert priority["changelog"] == {"status": "AVAILABLE", "source": "changelog", "role": "primary",
                                     "identity": changelog.IDENTITY, "reason": None, "files": [accepted]}
    assert history_priority(None, catalog)["changelog"]["status"] == "UNAVAILABLE"
