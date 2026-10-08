from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
import os
from typing import Any

from appsec_review.jobs.job_0001_nvd_sync.feed import NvdClient, NvdPublisher
from appsec_review.jobs.job_0001_nvd_sync.models import NvdSettings
from appsec_review.runtime.job import Job, JobContext


def _settings(context: JobContext) -> NvdSettings:
    return NvdSettings.from_mapping(context.repository_root, context.config.settings)


def validate_input(context: JobContext, result: Mapping[str, Any] | None) -> None:
    settings = _settings(context)
    data_root = (context.repository_root / "data").resolve()
    if settings.feed_root != data_root and data_root not in settings.feed_root.parents:
        raise ValueError("NVD feed_root must be inside the repository data directory")


def build_job(
    *,
    client: NvdClient | None = None,
    clock: Callable[[], datetime] | None = None,
    pause: Callable[[float], None] | None = None,
) -> Job:
    def handler(context: JobContext) -> Mapping[str, Any]:
        settings = _settings(context)
        arguments: dict[str, Any] = {"client": client}
        if clock is not None:
            arguments["clock"] = clock
        if pause is not None:
            arguments["pause"] = pause
        publisher = NvdPublisher(settings, **arguments)
        api_key = os.environ.get(settings.api_key_env)
        pointer = publisher.sync(f"{context.run_id}/{context.attempt_id}", api_key)
        verification = publisher.verify()
        return {
            "schema": "appsec-review/job-result/nvd-sync/1",
            "feed": pointer,
            "verification": verification,
            "limitations": [
                "NVD data is reference enrichment and does not independently establish a finding."
            ],
        }

    def validate_output(context: JobContext, result: Mapping[str, Any] | None) -> None:
        if result is None or result.get("schema") != "appsec-review/job-result/nvd-sync/1":
            raise ValueError("NVD job returned an invalid result schema")
        settings = _settings(context)
        publisher = NvdPublisher(settings, client=client)
        verified = publisher.verify()
        if verified != result.get("verification"):
            raise ValueError("NVD verification changed before publication")

    return Job(
        job_id="job_0001",
        name="nvd_sync",
        handler=handler,
        input_validators=(validate_input,),
        output_validators=(validate_output,),
    )
