from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
import os
from pathlib import Path
from typing import Any

from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader, publish_metadata, stamp
from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as cve_db
from appsec_review.jobs.job_third_party_data_sync.steps.mitre_sync import feed as mitre_feed
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdClient, NvdPublisher
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv_feed
from appsec_review.runtime import Job, JobContext, Unit, UnitContext, UnitExecutor


TOPOLOGY = {
    "nvd_sync": ("fetch", "process", "publish"),
    "osv_sync": ("fetch", "index", "publish"),
    "mitre_sync": ("fetch", "normalize", "publish"),
    "cve_bin_tool_db_build": ("resolve_nvd_snapshot", "build", "publish"),
}


def _nvd(context: JobContext) -> NvdSettings:
    return NvdSettings.from_mapping(context.repository_root, context.config.step("nvd_sync").settings)


def _osv(context: JobContext) -> osv_feed.OsvSettings:
    return osv_feed.OsvSettings.from_mapping(context.repository_root, context.config.step("osv_sync").settings)


def _mitre(context: JobContext) -> mitre_feed.MitreSettings:
    return mitre_feed.MitreSettings.from_mapping(context.repository_root, context.config.step("mitre_sync").settings)


def _cve(context: JobContext) -> cve_db.CveBinToolSettings:
    return cve_db.CveBinToolSettings.from_mapping(
        context.repository_root, context.config.step("cve_bin_tool_db_build").settings
    )


def _inside(root: Path, path: Path, label: str) -> None:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"{label} must be inside {resolved_root}")


def validate_input(context: JobContext, result: Mapping[str, Any] | None) -> None:
    if set(context.config.steps) != set(TOPOLOGY):
        raise ValueError(f"third-party sync steps must be exactly {sorted(TOPOLOGY)}")
    for step_id, task_ids in TOPOLOGY.items():
        step = context.config.step(step_id)
        if tuple(step.tasks) != task_ids:
            raise ValueError(f"{step_id} tasks must be ordered exactly as {list(task_ids)}")
    data_root = (context.repository_root / "data").resolve()
    for label, path in (("NVD feed_root", _nvd(context).feed_root), ("OSV feed_root", _osv(context).feed_root),
                        ("MITRE feed_root", _mitre(context).feed_root),
                        ("cve-bin-tool feed_root", _cve(context).feed_root)):
        _inside(data_root, path, label)
    _inside(context.run_root.parent, context.metadata_root, "metadata_root")


def _publisher(context: JobContext, client: NvdClient | None, clock: Callable[[], datetime] | None,
               pause: Callable[[float], None] | None) -> NvdPublisher:
    arguments: dict[str, Any] = {"client": client}
    if clock is not None:
        arguments["clock"] = clock
    if pause is not None:
        arguments["pause"] = pause
    return NvdPublisher(_nvd(context), **arguments)


def _schema(expected: str):
    def validate(context: UnitContext, result: Mapping[str, Any] | None) -> None:
        if result is None or result.get("schema") != expected:
            raise ValueError(f"{context.unit_id} returned an invalid result schema")
    return validate


def build_job(
    *,
    client: NvdClient | None = None,
    clock: Callable[[], datetime] | None = None,
    pause: Callable[[float], None] | None = None,
    osv_downloader: HttpDownloader | None = None,
    mitre_downloader: HttpDownloader | None = None,
    cve_runner: Callable[[cve_db.CveBinToolSettings, Path, Path], Mapping[str, str]] | None = None,
) -> Job:
    def nvd_fetch(unit: UnitContext) -> Mapping[str, Any]:
        publisher = _publisher(unit.job, client, clock, pause)
        pointer = publisher.sync(f"{unit.job.run_id}/{unit.job.attempt_id}", os.environ.get(publisher.settings.api_key_env))
        return {"schema": "appsec-review/nvd-fetch/1", **pointer}

    def nvd_process(unit: UnitContext) -> Mapping[str, Any]:
        expected = unit.output("nvd_sync.fetch")
        verified = _publisher(unit.job, client, clock, pause).verify()
        if verified["snapshot_id"] != expected["snapshot_id"]:
            raise ValueError("NVD current snapshot changed between fetch and process")
        return {"schema": "appsec-review/nvd-process/1", **verified,
                "manifest_sha256": expected["manifest_sha256"]}

    def nvd_publish(unit: UnitContext) -> Mapping[str, Any]:
        identity = dict(unit.output("nvd_sync.process"))
        path = publish_metadata(unit.job.metadata_root, "feeds", "nvd", {
            "schema": "appsec-review/global-feed-metadata/1", "feed_id": "nvd", "updated_at": stamp(),
            "run_id": unit.job.run_id, "attempt_id": unit.job.attempt_id, "identity": identity,
        })
        return {"schema": "appsec-review/nvd-publication/1", "identity": identity, "metadata_path": str(path)}

    def osv_fetch(unit: UnitContext) -> Mapping[str, Any]:
        return osv_feed.fetch(_osv(unit.job), unit.unit_root / "work", osv_downloader)

    def osv_index(unit: UnitContext) -> Mapping[str, Any]:
        return osv_feed.index(_osv(unit.job), unit.output("osv_sync.fetch"), unit.unit_root / "work")

    def osv_publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _osv(unit.job)
        pointer = osv_feed.publish(settings, unit.output("osv_sync.fetch"), unit.output("osv_sync.index"))
        identity = osv_feed.verify(settings)
        path = publish_metadata(unit.job.metadata_root, "feeds", "osv", {
            "schema": "appsec-review/global-feed-metadata/1", "feed_id": "osv", "updated_at": stamp(),
            "run_id": unit.job.run_id, "attempt_id": unit.job.attempt_id, "pointer": pointer, "identity": identity,
        })
        return {"schema": "appsec-review/osv-publication/1", "pointer": pointer, "identity": identity,
                "metadata_path": str(path)}

    def mitre_fetch(unit: UnitContext) -> Mapping[str, Any]:
        return mitre_feed.fetch(_mitre(unit.job), unit.unit_root / "work", mitre_downloader)

    def mitre_normalize(unit: UnitContext) -> Mapping[str, Any]:
        return mitre_feed.normalize(_mitre(unit.job), unit.output("mitre_sync.fetch"), unit.unit_root / "work")

    def mitre_publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _mitre(unit.job)
        pointer = mitre_feed.publish(settings, unit.output("mitre_sync.fetch"), unit.output("mitre_sync.normalize"))
        identity = mitre_feed.verify(settings)
        path = publish_metadata(unit.job.metadata_root, "feeds", "mitre", {
            "schema": "appsec-review/global-feed-metadata/1", "feed_id": "mitre", "updated_at": stamp(),
            "run_id": unit.job.run_id, "attempt_id": unit.job.attempt_id, "pointer": pointer, "identity": identity,
        })
        return {"schema": "appsec-review/mitre-publication/1", "pointer": pointer, "identity": identity,
                "metadata_path": str(path)}

    def cve_resolve(unit: UnitContext) -> Mapping[str, Any]:
        nvd_identity = unit.output("nvd_sync.publish")["identity"]
        return cve_db.resolve_nvd_snapshot(_nvd(unit.job).feed_root, nvd_identity)

    def cve_build(unit: UnitContext) -> Mapping[str, Any]:
        return cve_db.build(_cve(unit.job), unit.output("cve_bin_tool_db_build.resolve_nvd_snapshot"),
                            unit.unit_root / "work", cve_runner)

    def cve_publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _cve(unit.job)
        built = unit.output("cve_bin_tool_db_build.build")
        pointer = cve_db.publish(settings, built)
        identity = cve_db.verify(settings, unit.output("cve_bin_tool_db_build.resolve_nvd_snapshot"))
        path = publish_metadata(unit.job.metadata_root, "feeds", "cve-bin-tool", {
            "schema": "appsec-review/global-feed-metadata/1", "feed_id": "cve-bin-tool", "updated_at": stamp(),
            "run_id": unit.job.run_id, "attempt_id": unit.job.attempt_id, "pointer": pointer, "identity": identity,
        })
        return {"schema": "appsec-review/cve-bin-tool-publication/1", "pointer": pointer, "identity": identity,
                "metadata_path": str(path)}

    units = (
        Unit("nvd_sync.fetch", nvd_fetch, output_validators=(_schema("appsec-review/nvd-current-pointer/1"),)),
        Unit("osv_sync.fetch", osv_fetch, output_validators=(_schema("appsec-review/osv-fetch/1"),)),
        Unit("mitre_sync.fetch", mitre_fetch, output_validators=(_schema("appsec-review/mitre-fetch/1"),)),
        Unit("nvd_sync.process", nvd_process, ("nvd_sync.fetch",),
             output_validators=(_schema("appsec-review/nvd-process/1"),)),
        Unit("osv_sync.index", osv_index, ("osv_sync.fetch",),
             output_validators=(_schema("appsec-review/osv-index/1"),)),
        Unit("mitre_sync.normalize", mitre_normalize, ("mitre_sync.fetch",),
             output_validators=(_schema("appsec-review/mitre-normalize/1"),)),
        Unit("nvd_sync.publish", nvd_publish, ("nvd_sync.process",),
             output_validators=(_schema("appsec-review/nvd-publication/1"),)),
        Unit("osv_sync.publish", osv_publish, ("osv_sync.index",),
             output_validators=(_schema("appsec-review/osv-publication/1"),)),
        Unit("mitre_sync.publish", mitre_publish, ("mitre_sync.normalize",),
             output_validators=(_schema("appsec-review/mitre-publication/1"),)),
        Unit("cve_bin_tool_db_build.resolve_nvd_snapshot", cve_resolve, ("nvd_sync.publish",),
             output_validators=(_schema("appsec-review/resolved-nvd-snapshot/1"),)),
        Unit("cve_bin_tool_db_build.build", cve_build, ("cve_bin_tool_db_build.resolve_nvd_snapshot",),
             output_validators=(_schema("appsec-review/cve-bin-tool-build/1"),)),
        Unit("cve_bin_tool_db_build.publish", cve_publish, ("cve_bin_tool_db_build.build",),
             output_validators=(_schema("appsec-review/cve-bin-tool-publication/1"),)),
    )
    executor = UnitExecutor(units)

    def handler(context: JobContext) -> Mapping[str, Any]:
        result = executor.execute(context)
        result = {**result, "schema": "appsec-review/job-result/third-party-data-sync/1"}
        publish_metadata(context.metadata_root, "jobs", "job_third_party_data_sync", {
            "schema": "appsec-review/global-job-metadata/1", "job_id": "job_third_party_data_sync",
            "updated_at": stamp(), "run_id": context.run_id, "attempt_id": context.attempt_id,
            "trigger": context.trigger, "status": result["status"], "steps": result["steps"],
            "failed_units": result["failed_units"], "skipped_units": result["skipped_units"],
        })
        return result

    def validate_output(context: JobContext, result: Mapping[str, Any] | None) -> None:
        if result is None or result.get("schema") != "appsec-review/job-result/third-party-data-sync/1":
            raise ValueError("third-party data sync returned an invalid result schema")
        if set(result.get("units", {})) != {unit.unit_id for unit in units}:
            raise ValueError("third-party data sync omitted unit receipts")

    return Job("job_third_party_data_sync", "third_party_data_sync", handler, (validate_input,), (validate_output,))
