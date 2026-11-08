"""The live model-connectivity gate: the first job of every graph dispatch.

Every configured provider/model pair is asked for availability once, with a tool-disabled request,
before any target is read. A pair named only by a disabled job or a disabled model setting is
*checked but not required*: when it does not answer, the attempt publishes with a retryable
``producer-gap/1`` record instead of blocking the review. An unavailable *required* model fails the
attempt (the graph stops here and ``resume`` retries the gate). ``model-connectivity.json`` keeps
every answer, the required/not-required split and the gap records.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from appsec_review.jobs.cataloging import write_json
from appsec_review.jobs.job_review_intake.job import (
    PREFLIGHT_SCHEMA, required_models, resolved_configuration, verify_configured_models)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.jobs.job_model_connectivity.datasets import CONTRACT, DATASETS


ModelCheck = Callable[..., Mapping[str, Any]]
JOB_ID = "job_model_connectivity"
TOPOLOGY = {
    "connectivity": ("resolve_models", "verify_models"),
    "publication": ("publish_handoff",),
}
MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS = 1, 600


class ModelConnectivityBlocked(RuntimeError):
    """A required model did not answer; the review cannot start."""


def _pairs(items: list[Mapping[str, Any]]) -> set[tuple[str, str]]:
    return {(str(item["provider"]), str(item["model"])) for item in items}


def build_job(*, check_models: ModelCheck | None = None) -> Job:
    def validate(context, _result) -> None:
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("model connectivity topology does not match configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"model connectivity task order mismatch: {step}")
        timeout = context.config.settings.get("timeout_seconds")
        if type(timeout) is not int or not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError("model connectivity timeout is invalid")
        if check_models is None:
            # Refused at claim time: a gate that cannot ask the question must not start a review.
            raise ValueError("model connectivity check is not wired into this job instance")

    def resolve_models(unit: UnitContext) -> Mapping[str, Any]:
        required, not_required = required_models(resolved_configuration(unit.job.run_root))
        return {"required": required, "not_required": not_required,
                "model_count": len(_pairs(required)),
                "not_required_count": len(_pairs(not_required) - _pairs(required))}

    def verify_models(unit: UnitContext) -> Mapping[str, Any]:
        resolved = unit.output("connectivity.resolve_models")
        assert check_models is not None  # validate() refused the claim otherwise
        document = verify_configured_models(
            check_models, resolved["required"], resolved["not_required"],
            timeout_seconds=int(unit.job.config.settings["timeout_seconds"]), unit_id=unit.unit_id)
        path = unit.unit_root / "model-connectivity.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        unit.job.events.write(
            "MODEL_CONNECTIVITY_COMPLETED", unit_id=unit.unit_id,
            provider_count=len(document["providers"]),
            model_count=sum(len(report.get("models", {})) for report in document["providers"].values()),
            unavailable_count=len(document["unavailable"]),
            unavailable_not_required_count=len(document["unavailable_not_required"]),
        )
        if document["unavailable"]:
            raise ModelConnectivityBlocked("model connectivity blocked the review: " + "; ".join(
                f"{item['provider']}/{item['model']} ({item['detail']})"
                for item in document["unavailable"]))
        verified = sorted(f"{provider}/{name}" for provider, report in document["providers"].items()
                          for name in report.get("models", {}) if report["models"][name].get("available") is True)
        return {"schema": PREFLIGHT_SCHEMA, "artifact": identity,
                "providers": sorted(document["providers"]), "verified": verified,
                "not_required": sorted(f"{item['provider']}/{item['model']}" for item in resolved["not_required"]),
                "unavailable_not_required": sorted(f"{item['provider']}/{item['model']}"
                                                   for item in document["unavailable_not_required"]),
                "gaps": document["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        verified = unit.output("connectivity.verify_models")
        document = {"schema": PREFLIGHT_SCHEMA, "artifact": verified["artifact"],
                    "providers": verified["providers"], "verified": verified["verified"],
                    "not_required": verified["not_required"],
                    "unavailable_not_required": verified["unavailable_not_required"]}
        path = unit.unit_root / "model-connectivity-handoff.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        # The gap records stay on the unit that observed them (connectivity.verify_models); the
        # runner aggregates them into the attempt's outcomes. Publication itself has none.
        return {"schema": PREFLIGHT_SCHEMA, "artifact": identity,
                "verified": verified["verified"], "not_required": verified["not_required"],
                "unavailable_not_required": verified["unavailable_not_required"],
                "terminal_status": "SUCCEEDED", "gaps": []}

    units = (
        Unit("connectivity.resolve_models", resolve_models),
        Unit("connectivity.verify_models", verify_models, ("connectivity.resolve_models",)),
        Unit("publication.publish_handoff", publish_handoff, ("connectivity.verify_models",)),
    )
    implementation = None
    return Job(
        JOB_ID, "model_connectivity", UnitExecutor(units).execute,
        input_validators=(validate,), schema_identity="appsec-review/model-connectivity-job/2",
        implementation_identity=implementation, validation_identity=implementation,
        units=units, datasets=DATASETS, contract=CONTRACT,
        always_execute=True, propagate_handoff=False, strict_gaps=True,
    )
