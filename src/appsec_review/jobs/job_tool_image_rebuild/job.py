"""Mandatory rebuild of the catalog's container tool images before review intake.

The job drives the deterministic builder ``containers/build.py`` through an injectable runner so
tests never reach Docker. Any image that does not build, any builder failure and any unreadable
builder summary fails the job, and with it the run: a missing tool image is never a recorded gap.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import json
import logging
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import tomllib
from typing import Any

from appsec_review.config.tool_image_rebuild import (
    ToolImageRebuildSettings, parse_tool_image_rebuild_settings,
)
from appsec_review.jobs.cataloging import write_json
from appsec_review.jobs.job_tool_image_rebuild.datasets import CONSUMES, DATASETS
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.runtime.selection import resolved_job_is_enabled


LOGGER = logging.getLogger(__name__)
PLAN_SCHEMA = "appsec-review/tool-image-plan/1"
REBUILD_SCHEMA = "appsec-review/tool-image-rebuild/1"
RECEIPT_SCHEMA = "appsec-review/tool-image-receipt/1"
FAILURE_SCHEMA = "appsec-review/tool-image-rebuild-failure/1"
BUILDER_SUMMARY_SCHEMA = "appsec-review/container-build-summary/1"
CATALOG = Path("containers") / "catalog.toml"
BUILDER = Path("containers") / "build.py"
# Builder output kept beside the receipts; the builder's own per-image logs stay where it wrote them.
CAPTURED_OUTPUT_BYTES = 1024 * 1024
# Setting pairs that pin an image tag to an exact image ID in enabled jobs' configuration.
PIN_PAIRS = (("tag", "image_id"), ("source_image_tag", "source_image_id"))
TOPOLOGY = {
    "selection": ("resolve_images",),
    "build": ("build_images",),
    "publication": ("publish_handoff",),
}

# run_builder(argv, *, cwd, timeout_seconds) -> {"returncode": int | None, "stdout": str,
# "stderr": str, "timed_out": bool}
BuilderRunner = Callable[..., Mapping[str, Any]]


def run_builder(argv: Sequence[str], *, cwd: Path, timeout_seconds: int) -> Mapping[str, Any]:
    """Run the builder in its own process group so a timeout also stops its docker builds."""

    process = subprocess.Popen(list(argv), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace", start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return {"returncode": process.returncode, "stdout": stdout or "", "stderr": stderr or "",
                "timed_out": False}
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.kill()
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        return {"returncode": process.returncode, "stdout": stdout or "", "stderr": stderr or "",
                "timed_out": True}


def settings_of(config) -> ToolImageRebuildSettings:
    return parse_tool_image_rebuild_settings(config.settings)


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("tool image rebuild topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"tool image rebuild task order mismatch: {step}")
    settings_of(context.config)


def dependency_order(requested: Sequence[str], by_id: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Return the builder's dependency-first order: every image after all of its dependencies."""

    ordered: list[str] = []
    visiting: set[str] = set()

    def visit(image_id: str) -> None:
        if image_id in ordered:
            return
        if image_id in visiting:
            raise ValueError(f"tool image dependency cycle at {image_id}")
        item = by_id.get(image_id)
        if item is None:
            raise ValueError(f"unknown tool image: {image_id}")
        if item.get("state") != "enabled":
            raise ValueError(f"tool image {image_id} is {item.get('state')}, not enabled")
        visiting.add(image_id)
        for dependency in item.get("dependencies", []):
            visit(dependency)
        visiting.remove(image_id)
        ordered.append(image_id)

    for image_id in requested:
        visit(image_id)
    return ordered


def configured_pins(catalog_images: Sequence[Mapping[str, Any]],
                    document: Mapping[str, Any]) -> list[dict[str, str]]:
    """Every exact image-ID pin a rebuild could invalidate: catalog pins and enabled jobs' settings."""

    pins: list[dict[str, str]] = []
    for item in catalog_images:
        if isinstance(item.get("tag"), str) and isinstance(item.get("image_id"), str):
            pins.append({"source": f"{CATALOG.as_posix()} images.{item['id']}.image_id",
                         "tag": item["tag"], "image_id": item["image_id"]})

    def walk(value: object, path: str) -> None:
        if not isinstance(value, Mapping):
            return
        for tag_key, id_key in PIN_PAIRS:
            if isinstance(value.get(tag_key), str) and isinstance(value.get(id_key), str):
                pins.append({"source": f"{path}.{id_key}", "tag": value[tag_key], "image_id": value[id_key]})
        for key, child in value.items():
            walk(child, f"{path}.{key}")

    for job_id, job in sorted(dict(document.get("jobs") or {}).items()):
        if isinstance(job, Mapping) and resolved_job_is_enabled(job_id, job):
            walk(job.get("settings") or {}, f"jobs.{job_id}.settings")
    return pins


def _tail(text: str, limit: int) -> str:
    data = text.encode("utf-8", errors="replace")
    if len(data) <= limit:
        return text
    return "[...truncated...]\n" + data[-limit:].decode("utf-8", errors="replace")


def _file_tail(path: Path, limit: int) -> str:
    try:
        with path.open("rb") as stream:
            size = stream.seek(0, os.SEEK_END)
            stream.seek(max(0, size - limit))
            data = stream.read(limit)
    except OSError as exc:
        return f"<build log unavailable: {type(exc).__name__}: {exc}>"
    prefix = "[...truncated...]\n" if size > limit else ""
    return prefix + data.decode("utf-8", errors="replace")


def _inside(root: Path, value: str) -> Path | None:
    path = Path(value)
    resolved = (path if path.is_absolute() else root / path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def _summary_location(stdout: str) -> str | None:
    lines = [line.strip() for line in stdout.splitlines() if line.strip().startswith("summary=")]
    return lines[-1].removeprefix("summary=") if lines else None


def build_job(*, run_builder: BuilderRunner | None = None) -> Job:
    def resolve_images(unit: UnitContext) -> Mapping[str, Any]:
        settings = settings_of(unit.job.config)
        root = unit.job.repository_root
        catalog_path, builder_path = root / CATALOG, root / BUILDER
        for path in (catalog_path, builder_path):
            if not path.is_file():
                raise FileNotFoundError(f"tool image rebuild requires {path.relative_to(root).as_posix()}")
        catalog_bytes = catalog_path.read_bytes()
        images = tomllib.loads(catalog_bytes.decode("utf-8")).get("images", [])
        by_id = {str(item["id"]): item for item in images}
        enabled = [str(item["id"]) for item in images if item.get("state") == "enabled"]
        requested = list(settings.images) or enabled
        if not requested:
            raise ValueError("tool image rebuild selected no enabled catalog image")
        ordered = dependency_order(requested, by_id)
        frozen = unit.job.run_root / "data" / "configuration" / "appsec-review.toml"
        rebuilt_tags = {by_id[image_id].get("tag") for image_id in ordered}
        pins = [pin for pin in configured_pins(images, tomllib.loads(frozen.read_text(encoding="utf-8")))
                if pin["tag"] in rebuilt_tags]
        document = {
            "schema": PLAN_SCHEMA,
            "catalog": {"path": CATALOG.as_posix(), "sha256": hashlib.sha256(catalog_bytes).hexdigest()},
            "builder": {"path": BUILDER.as_posix(),
                        "sha256": hashlib.sha256(builder_path.read_bytes()).hexdigest()},
            "selection": "configured" if settings.images else "all_enabled",
            "requested": requested,
            "ordered": [{"id": image_id, "tag": by_id[image_id].get("tag"),
                         "kind": by_id[image_id].get("kind"),
                         "dependencies": list(by_id[image_id].get("dependencies", []))}
                        for image_id in ordered],
            "pins": pins,
            "settings": {"parallelism": settings.parallelism,
                         "image_timeout_seconds": settings.image_timeout_seconds,
                         "total_timeout_seconds": settings.total_timeout_seconds,
                         "continue_on_error": settings.continue_on_error,
                         "log_tail_bytes": settings.log_tail_bytes,
                         "pin_mismatch": settings.pin_mismatch},
        }
        path = unit.unit_root / "tool-image-plan.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        return {"schema": PLAN_SCHEMA, "artifact": identity, "requested": requested,
                "ordered": document["ordered"], "pins": pins, "image_count": len(ordered)}

    def build_images(unit: UnitContext) -> Mapping[str, Any]:
        if run_builder is None:
            raise RuntimeError("tool image builder is not wired into this job instance")
        settings = settings_of(unit.job.config)
        plan = unit.output("selection.resolve_images")
        root = unit.job.repository_root
        ordered = [dict(item) for item in plan["ordered"]]
        argv = [sys.executable, str(root / BUILDER), "build", *plan["requested"],
                "--jobs", str(settings.parallelism),
                "--timeout-seconds", str(settings.image_timeout_seconds)]
        if settings.continue_on_error:
            argv.append("--continue-on-error")
        command = shlex.join(argv)
        unit.job.events.write("TOOL_IMAGE_REBUILD_STARTED", unit_id=unit.unit_id,
                              image_count=len(ordered), command=command)
        started = time.monotonic()
        try:
            outcome = dict(run_builder(argv, cwd=root, timeout_seconds=settings.total_timeout_seconds))
        except Exception as exc:  # the failure is reported below with the command that raised it
            outcome = {"returncode": None, "stdout": "", "stderr": f"{type(exc).__name__}: {exc}",
                       "timed_out": False}
        duration = round(time.monotonic() - started, 3)
        stdout, stderr = str(outcome.get("stdout") or ""), str(outcome.get("stderr") or "")
        returncode = outcome.get("returncode")
        for name, text in (("builder-stdout.log", stdout), ("builder-stderr.log", stderr)):
            (unit.unit_root / name).write_text(_tail(text, CAPTURED_OUTPUT_BYTES), encoding="utf-8")

        failures: list[dict[str, Any]] = []
        if outcome.get("timed_out"):
            failures.append({"image_id": None, "status": "timed_out",
                             "error": f"builder exceeded total_timeout_seconds={settings.total_timeout_seconds}"})
        location = _summary_location(stdout)
        summary_path = _inside(root, location) if location else None
        summary: Mapping[str, Any] | None = None
        summary_identity = None
        if summary_path is None:
            failures.append({"image_id": None, "status": "no_summary",
                             "error": "builder reported no summary inside the repository"})
        else:
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                if summary.get("schema") != BUILDER_SUMMARY_SCHEMA:
                    raise ValueError(f"unexpected builder summary schema {summary.get('schema')!r}")
                summary_identity = write_json(unit.unit_root / "builder-summary.json", summary)
                summary_identity["path"] = (unit.unit_root / "builder-summary.json").relative_to(
                    unit.job.run_root).as_posix()
                summary_identity["source"] = summary_path.relative_to(root.resolve()).as_posix()
            except (OSError, ValueError, AttributeError) as exc:
                failures.append({"image_id": None, "status": "unreadable_summary",
                                 "error": f"{type(exc).__name__}: {exc}"})
                summary = None
        results = {str(item.get("id")): dict(item) for item in (summary or {}).get("results", [])}
        if summary is not None and [str(item.get("id")) for item in summary.get("results", [])] != [
                item["id"] for item in ordered]:
            failures.append({"image_id": None, "status": "order_mismatch",
                             "error": "builder results do not match the catalog dependency order"})
        if summary is not None:
            for item in ordered:
                result = results.get(item["id"])
                if result is None:
                    failures.append({"image_id": item["id"], "status": "missing",
                                     "error": "builder reported no result"})
                elif result.get("status") != "passed" or not str(result.get("digest") or "").startswith(
                        "sha256:"):
                    log_path = _inside(root, str(result["build_log"])) if result.get("build_log") else None
                    failures.append({
                        "image_id": item["id"], "tag": item["tag"], "status": str(result.get("status")),
                        "error": str(result.get("error") or "built image digest is missing"),
                        "build_log": result.get("build_log"), "fetch_log": result.get("fetch_log"),
                        "build_log_tail": (_file_tail(log_path, settings.log_tail_bytes)
                                           if log_path is not None else None),
                    })
        if returncode != 0 and not outcome.get("timed_out"):
            failures.append({"image_id": None, "status": "builder_failed",
                             "error": f"builder exited {returncode}"})

        if failures:
            failure_path = unit.unit_root / "tool-image-rebuild-failure.json"
            document = {
                "schema": FAILURE_SCHEMA, "command": argv, "exit_status": returncode,
                "timed_out": bool(outcome.get("timed_out")), "duration_seconds": duration,
                "builder_summary": location, "failures": failures,
                "stderr_tail": _tail(stderr, settings.log_tail_bytes),
                "stdout_tail": _tail(stdout, settings.log_tail_bytes),
            }
            write_json(failure_path, document)
            record = failure_path.relative_to(unit.job.run_root).as_posix()
            image_failures = [item for item in failures if item["image_id"]]
            failed_ids = [item["image_id"] for item in image_failures]
            unit.job.events.write("TOOL_IMAGE_REBUILD_FAILED", unit_id=unit.unit_id,
                                  failed_images=failed_ids, exit_status=returncode,
                                  timed_out=bool(outcome.get("timed_out")), command=command,
                                  builder_summary=location, failure_record=record,
                                  stderr_tail=_tail(stderr, min(settings.log_tail_bytes, 4096)))
            lines = [
                "tool image rebuild failed; the review run cannot continue without its tool images",
                "failed images: " + (", ".join(
                    f"{item['image_id']} ({item['status']}: {item['error']}"
                    + (f"; build log {item['build_log']})" if item.get("build_log") else ")")
                    for item in image_failures) or "none reported"),
                *[f"builder: {item['status']}: {item['error']}" for item in failures if not item["image_id"]],
                f"exit status: {returncode}",
                f"command: {command}",
                f"builder summary: {location}",
                f"failure record: {failure_path}",
                "stderr tail:", _tail(stderr, settings.log_tail_bytes) or "<empty>",
                "stdout tail:", _tail(stdout, settings.log_tail_bytes) or "<empty>",
            ]
            for item in image_failures:
                if item.get("build_log_tail"):
                    lines += [f"{item['image_id']} build log tail ({item['build_log']}):", item["build_log_tail"]]
            message = "\n".join(lines)
            LOGGER.error("%s", message)
            raise RuntimeError(message)

        digests = {str(results[item["id"]].get("tag") or item["tag"]): results[item["id"]]["digest"]
                   for item in ordered}
        pins = [{**pin, "rebuilt_image_id": digests[pin["tag"]],
                 "status": "matched" if digests[pin["tag"]] == pin["image_id"] else "mismatched"}
                for pin in plan.get("pins", []) if pin["tag"] in digests]
        mismatches = [pin for pin in pins if pin["status"] == "mismatched"]
        receipts = []
        for position, item in enumerate(ordered):
            result = results[item["id"]]
            receipt = {
                "schema": RECEIPT_SCHEMA, "image_id": item["id"], "tag": result.get("tag") or item["tag"],
                "kind": item["kind"], "order": position, "dependencies": item["dependencies"],
                "image_digest": result["digest"], "duration_seconds": result.get("duration_seconds"),
                "build_log": result.get("build_log"), "fetch_log": result.get("fetch_log"),
                "dockerfile_sha256": result.get("dockerfile_sha256"),
                "assets_lock_sha256": result.get("assets_lock_sha256"),
                "base_identity": result.get("base_identity"),
                "builder_run_id": (summary or {}).get("run_id"),
                "pins": [pin for pin in pins if pin["tag"] == (result.get("tag") or item["tag"])],
            }
            path = unit.unit_root / "receipts" / f"{item['id']}.json"
            identity = write_json(path, receipt)
            identity["path"] = path.relative_to(unit.job.run_root).as_posix()
            receipts.append({"image_id": item["id"], "tag": receipt["tag"],
                             "image_digest": receipt["image_digest"], "receipt": identity})
        document = {"schema": REBUILD_SCHEMA, "command": argv, "exit_status": returncode,
                    "duration_seconds": duration, "builder_summary": summary_identity,
                    "plan": plan["artifact"], "images": receipts, "pins": pins,
                    "pin_mismatch": settings.pin_mismatch}
        path = unit.unit_root / "tool-image-rebuild.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        if mismatches:
            stale = [f"{pin['source']} pins {pin['tag']} to {pin['image_id']} but the rebuild produced "
                     f"{pin['rebuilt_image_id']}" for pin in mismatches]
            event = ("TOOL_IMAGE_PIN_CHECK_FAILED" if settings.pin_mismatch == "fail"
                     else "TOOL_IMAGE_PIN_MISMATCH")
            unit.job.events.write(event, unit_id=unit.unit_id, mismatches=mismatches, record=identity["path"])
            if settings.pin_mismatch == "fail":
                message = "\n".join([
                    "rebuilt tool images no longer match their configured pins; update each pin to the "
                    "rebuilt image ID (or make the build reproducible) before the review can continue",
                    *stale, f"rebuild record: {path}"])
                LOGGER.error("%s", message)
                raise RuntimeError(message)
            LOGGER.warning("%s", "; ".join(stale))
        unit.job.events.write("TOOL_IMAGE_REBUILD_COMPLETED", unit_id=unit.unit_id,
                              image_count=len(receipts), duration_ms=int(duration * 1000))
        return {"schema": REBUILD_SCHEMA, "artifact": identity, "image_count": len(receipts),
                "images": [{key: item[key] for key in ("image_id", "tag", "image_digest")}
                           for item in receipts], "pin_mismatches": mismatches}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        built = unit.output("build.build_images")
        document = {"schema": REBUILD_SCHEMA, "artifact": built["artifact"], "images": built["images"],
                    "pin_mismatches": built["pin_mismatches"]}
        path = unit.unit_root / "tool-image-rebuild-handoff.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        return {"schema": REBUILD_SCHEMA, "artifact": identity, "image_count": built["image_count"],
                "images": built["images"], "pin_mismatches": built["pin_mismatches"], "gaps": []}

    units = (
        Unit("selection.resolve_images", resolve_images),
        Unit("build.build_images", build_images, ("selection.resolve_images",)),
        Unit("publication.publish_handoff", publish_handoff, ("build.build_images",)),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
                                    (b"image-builder" if run_builder else b"no-image-builder")).hexdigest()
    return Job(
        "job_tool_image_rebuild", "tool_image_rebuild", UnitExecutor(units).execute,
        input_validators=(_validate,), schema_identity="appsec-review/tool-image-rebuild-job/1",
        implementation_identity=implementation, validation_identity=implementation,
        units=units, datasets=DATASETS, consumes=CONSUMES,
        always_execute=True, propagate_handoff=False,
    )
