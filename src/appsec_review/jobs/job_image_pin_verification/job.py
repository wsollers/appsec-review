"""Pre-intake gate: every image the review depends on resolves to exactly its pinned image.

The job builds nothing. Images are built and re-pinned on the host by the operator
(``containers/build.py build``, then ``appsec-review update-image-pins``). The gate reads
``containers/catalog.toml`` and the run's frozen configuration, runs ``docker image inspect`` for each
tag through an injectable command runner (tests never reach Docker), and fails the run naming every
missing image, moved tag and uninspectable tag. A missing or mismatched tool image is never a
recorded gap.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import logging
from pathlib import Path
import tomllib
from typing import Any

from appsec_review.config.image_pin_verification import (
    ImagePinVerificationSettings, parse_image_pin_verification_settings,
)
from appsec_review.container_runtime.build_executor import Runner
from appsec_review.jobs.cataloging import write_json
from appsec_review.jobs.job_image_pin_verification.datasets import CONSUMES, DATASETS
from appsec_review.jobs.job_image_pin_verification.pins import (
    CATALOG, PASSING, configured_pins, describe, verify_pins,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor


LOGGER = logging.getLogger(__name__)
JOB_ID = "job_image_pin_verification"
PLAN_SCHEMA = "appsec-review/image-pin-plan/1"
VERIFICATION_SCHEMA = "appsec-review/image-pin-verification/1"
RECORD_NAME = "image-pin-verification.json"
HANDOFF_NAME = "image-pin-verification-handoff.json"
TOPOLOGY = {
    "selection": ("resolve_pins",),
    "verification": ("inspect_images",),
    "publication": ("publish_handoff",),
}


def settings_of(config) -> ImagePinVerificationSettings:
    return parse_image_pin_verification_settings(config.settings)


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("image pin verification topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"image pin verification task order mismatch: {step}")
    settings_of(context.config)


def _identity(unit: UnitContext, path: Path, document: Mapping[str, Any]) -> dict[str, Any]:
    identity = write_json(path, document)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def build_job(*, runner: Runner | None = None) -> Job:
    def resolve_pins(unit: UnitContext) -> Mapping[str, Any]:
        settings_of(unit.job.config)
        catalog_path = unit.job.repository_root / CATALOG
        if not catalog_path.is_file():
            raise FileNotFoundError(f"image pin verification requires {CATALOG.as_posix()}")
        catalog_bytes = catalog_path.read_bytes()
        images = tomllib.loads(catalog_bytes.decode("utf-8")).get("images", [])
        frozen = unit.job.run_root / "data" / "configuration" / "appsec-review.toml"
        frozen_bytes = frozen.read_bytes()
        pins = configured_pins(images, tomllib.loads(frozen_bytes.decode("utf-8")))
        if not pins:
            raise ValueError("image pin verification found no enabled catalog image or configured pin")
        document = {
            "schema": PLAN_SCHEMA,
            "catalog": {"path": CATALOG.as_posix(),
                        "release_id": unit.job.review_policy.releases.values.get("platform")},
            "configuration": {"path": frozen.relative_to(unit.job.run_root).as_posix(),
                              "sha256": hashlib.sha256(frozen_bytes).hexdigest()},
            "pins": pins,
        }
        identity = _identity(unit, unit.unit_root / "image-pin-plan.json", document)
        return {"schema": PLAN_SCHEMA, "artifact": identity, "pins": pins, "pin_count": len(pins)}

    def inspect_images(unit: UnitContext) -> Mapping[str, Any]:
        if runner is None:
            raise RuntimeError("image inspection runner is not wired into this job instance")
        plan = unit.output("selection.resolve_pins")
        pins = [dict(pin) for pin in plan["pins"]]
        unit.job.events.write("IMAGE_PIN_VERIFICATION_STARTED", unit_id=unit.unit_id, pin_count=len(pins))
        results = verify_pins(pins, runner)
        failures = [item for item in results if item["status"] not in PASSING]
        document = {"schema": VERIFICATION_SCHEMA, "plan": plan["artifact"],
                    "status": "FAILED" if failures else "PASSED", "pins": results}
        identity = _identity(unit, unit.unit_root / RECORD_NAME, document)
        if failures:
            lines = [describe(item) for item in failures]
            unit.job.events.write("IMAGE_PIN_VERIFICATION_FAILED", unit_id=unit.unit_id,
                                  failures=failures, record=identity["path"])
            message = "\n".join([
                f"image pin verification failed: {len(failures)} of {len(results)} image pins do not "
                "resolve on the local daemon to their pinned image; rebuild and re-pin on the host "
                "(docs/operations/image-pin-verification.md) before the review can continue",
                *lines, f"verification record: {unit.unit_root / RECORD_NAME}"])
            LOGGER.error("%s", message)
            raise RuntimeError(message)
        unit.job.events.write("IMAGE_PIN_VERIFICATION_COMPLETED", unit_id=unit.unit_id,
                              pin_count=len(results))
        return {"schema": VERIFICATION_SCHEMA, "artifact": identity, "pin_count": len(results),
                "images": [{key: item[key] for key in ("source", "tag", "image_id", "resolved_image_id",
                                                       "status")} for item in results]}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        verified = unit.output("verification.inspect_images")
        document = {"schema": VERIFICATION_SCHEMA, "artifact": verified["artifact"],
                    "images": verified["images"]}
        identity = _identity(unit, unit.unit_root / HANDOFF_NAME, document)
        return {"schema": VERIFICATION_SCHEMA, "artifact": identity, "pin_count": verified["pin_count"],
                "images": verified["images"], "gaps": []}

    units = (
        Unit("selection.resolve_pins", resolve_pins),
        Unit("verification.inspect_images", inspect_images, ("selection.resolve_pins",)),
        Unit("publication.publish_handoff", publish_handoff, ("verification.inspect_images",)),
    )
    implementation = None
    return Job(
        JOB_ID, "image_pin_verification", UnitExecutor(units).execute,
        input_validators=(_validate,), schema_identity="appsec-review/image-pin-verification-job/1",
        implementation_identity=implementation, validation_identity=implementation,
        units=units, datasets=DATASETS, consumes=CONSUMES,
        always_execute=True, propagate_handoff=False,
    )
