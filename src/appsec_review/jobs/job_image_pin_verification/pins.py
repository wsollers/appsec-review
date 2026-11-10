"""Image selection and verification, and atomic publication of host-local bindings."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import re
import tomllib
from typing import Any

from appsec_review.config.host_pins import (
    HostPins, IMAGE_ID, configuration_image_settings, host_pins_path, image_settings,
    parse_host_pins, serialize_host_pins,
)
from appsec_review.container_runtime.build_executor import Runner
from appsec_review.runtime.selection import resolved_job_is_enabled


CATALOG = Path("containers") / "catalog.toml"
CATALOG_PREFIX = f"{CATALOG.as_posix()} images."
INSPECT_TIMEOUT_SECONDS = 60
_ABSENT = re.compile(r"no such (image|object)", re.IGNORECASE)
PASSING = frozenset({"matched", "present"})


class PinUpdateError(ValueError):
    """Host image bindings cannot be updated safely."""


def configured_pins(catalog_images: Sequence[Mapping[str, Any]],
                    document: Mapping[str, Any]) -> list[dict[str, Any]]:
    pins: list[dict[str, Any]] = []
    for item in catalog_images:
        if (item.get("state") != "enabled" or not isinstance(item.get("tag"), str)
                or item.get("manual") is True):
            continue
        image_id = item.get("image_id")
        pins.append({"source": f"{CATALOG_PREFIX}{item['id']}.image_id", "tag": item["tag"],
                     "image_id": image_id if isinstance(image_id, str) else None})
    for job_id, job in sorted(dict(document.get("jobs") or {}).items()):
        if isinstance(job, Mapping) and resolved_job_is_enabled(job_id, job):
            for source, settings, id_key, tag in image_settings(
                    dict(job), f"jobs.{job_id}"):
                image_id = settings.get(id_key)
                if isinstance(image_id, str):
                    pins.append({"source": source, "tag": tag, "image_id": image_id})
    report = document.get("reporting", {}).get("telemetry_report", {})
    if report.get("enabled") is True and report.get("render_pdf") is True:
        for source, settings, id_key, tag in image_settings(report, "reporting.telemetry_report"):
            pins.append({"source": source, "tag": tag, "image_id": settings[id_key]})
    return pins


def inspect_image(runner: Runner, tag: str) -> dict[str, Any]:
    argv = ("docker", "image", "inspect", tag, "--format", "{{.Id}}")
    try:
        code, stdout, stderr, timed_out = runner(argv, INSPECT_TIMEOUT_SECONDS)
    except OSError as exc:
        return {"resolved_image_id": None, "state": "inspect_failed", "detail": f"{type(exc).__name__}: {exc}"}
    out = stdout.decode("utf-8", "replace").strip()
    err = stderr.decode("utf-8", "replace").strip()
    if timed_out:
        return {"resolved_image_id": None, "state": "inspect_failed",
                "detail": f"docker image inspect timed out after {INSPECT_TIMEOUT_SECONDS}s"}
    if code == 0 and IMAGE_ID.fullmatch(out):
        return {"resolved_image_id": out, "state": "present", "detail": ""}
    if code != 0 and _ABSENT.search(err):
        return {"resolved_image_id": None, "state": "missing", "detail": err[-512:]}
    return {"resolved_image_id": None, "state": "inspect_failed",
            "detail": f"docker image inspect exited {code}: {(err or out)[-512:]}"}


def verify_pins(pins: Sequence[Mapping[str, Any]], runner: Runner) -> list[dict[str, Any]]:
    resolved: dict[str, dict[str, Any]] = {}
    results = []
    for pin in pins:
        tag = str(pin["tag"])
        if tag not in resolved:
            resolved[tag] = inspect_image(runner, tag)
        local = resolved[tag]
        if local["state"] != "present":
            status = local["state"]
        elif pin.get("image_id") is None:
            status = "present"
        else:
            status = "matched" if local["resolved_image_id"] == pin["image_id"] else "mismatched"
        results.append({"source": pin["source"], "tag": tag, "image_id": pin.get("image_id"),
                        "resolved_image_id": local["resolved_image_id"], "status": status,
                        "detail": local["detail"]})
    return results


def describe(result: Mapping[str, Any]) -> str:
    if result["status"] == "missing":
        resolved = "missing"
    elif result["status"] == "inspect_failed":
        resolved = f"not inspectable ({result['detail']})"
    else:
        resolved = str(result["resolved_image_id"])
    return (f"{result['source']}: tag {result['tag']} pinned {result['image_id'] or '<unpinned>'} "
            f"resolved {resolved}")


def update_pins(*, config_path: Path, catalog_path: Path, write: bool, runner: Runner,
                profile: str | None = None, host_path: Path | None = None) -> dict[str, Any]:
    """Inspect recipe tags, validate the complete effective configuration, then publish one host file."""
    from appsec_review.config.loader import load_config
    from appsec_review.storage import atomic_bytes

    path = host_path or host_pins_path(config_path.parent)
    try:
        config_bytes, catalog_bytes = config_path.read_bytes(), catalog_path.read_bytes()
        document = tomllib.loads(config_bytes.decode("utf-8"))
        images = tomllib.loads(catalog_bytes.decode("utf-8")).get("images", [])
        original = path.read_bytes() if path.exists() else None
        previous = parse_host_pins(original) if original is not None else {
            "images": {}, "preinstalled_runtimes": []}
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PinUpdateError(f"cannot read the pins: {type(exc).__name__}: {exc}") from exc
    tags = {item["tag"] for item in images if item.get("state") == "enabled"}
    tags.update(tag for _, _, _, tag in configuration_image_settings(document))
    pins = [{"source": f"host-pins.images[{json.dumps(tag)}]", "tag": tag,
             "image_id": previous["images"].get(tag)} for tag in sorted(tags)]
    results = verify_pins(pins, runner)
    failures = [describe(row) for row in results if row["status"] in {"missing", "inspect_failed"}]
    bindings = {row["tag"]: row["resolved_image_id"] for row in results
                if row["resolved_image_id"] is not None}
    edits = [{"tag": row["tag"], "old": row["image_id"], "new": row["resolved_image_id"]}
             for row in results if row["image_id"] != row["resolved_image_id"]]
    report: dict[str, Any] = {"written": False, "checked": len(results), "host_file": str(path),
                              "edits": edits, "failures": failures}
    if failures:
        return report
    content = serialize_host_pins(bindings, previous["preinstalled_runtimes"])
    candidate = HostPins(path, content)
    try:
        config = load_config(config_path, profile=profile, host_pins=candidate)
    except (OSError, ValueError, KeyError) as exc:
        raise PinUpdateError(f"host pins do not load through the typed configuration: {exc}; "
                             "no files changed") from exc
    codeql = config.job("job_codeql_analysis").typed_settings
    for runtime in codeql.preinstalled_runtimes:
        for image_id in (runtime.build_image_id, runtime.runtime_image_id):
            result = inspect_image(runner, image_id)
            if result["resolved_image_id"] != image_id:
                raise PinUpdateError(f"declared preinstalled image is not available: {image_id}; "
                                     "correct its host declaration; no files changed")
    if write:
        if (config_path.read_bytes() != config_bytes or catalog_path.read_bytes() != catalog_bytes
                or (path.read_bytes() if path.exists() else None) != original):
            raise PinUpdateError("image binding inputs changed during inspection; no files changed")
        if content != original:
            atomic_bytes(path, content)
        report["written"] = True
    report["sha256"] = candidate.sha256
    return report
