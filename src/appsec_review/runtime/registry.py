from __future__ import annotations

from collections.abc import Callable

from appsec_review.runtime.job import Job

JobFactory = Callable[[], Job]


class JobRegistry:
    def __init__(self) -> None:
        self._factories: dict[str, JobFactory] = {}

    def register(self, job_id: str, factory: JobFactory) -> None:
        if job_id in self._factories:
            raise ValueError(f"job already registered: {job_id}")
        self._factories[job_id] = factory

    def build(self, job_id: str) -> Job:
        try:
            job = self._factories[job_id]()
        except KeyError as exc:
            raise KeyError(f"job is not registered: {job_id}") from exc
        if job.job_id != job_id:
            raise ValueError(f"registered job id mismatch: {job.job_id} != {job_id}")
        return job

    def job_ids(self) -> tuple[str, ...]:
        """Return registered semantic job ids in deterministic order."""

        return tuple(sorted(self._factories))


def builtin_registry() -> JobRegistry:
    from appsec_review.jobs.job_third_party_data_sync import build_job

    registry = JobRegistry()
    registry.register("job_third_party_data_sync", build_job)
    return registry
