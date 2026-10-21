from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
from pathlib import Path
from typing import Any

from appsec_review.jobs.cataloging import write_json
from appsec_review.jobs.job_review_intake.job import PREFLIGHT_SCHEMA, configured_models, resolved_configuration
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.jobs.job_model_connectivity.datasets import CONSUMES, DATASETS


ModelCheck = Callable[..., Mapping[str, Any]]
TOPOLOGY = {
    "connectivity": ("resolve_models", "verify_models"),
    "publication": ("publish_handoff",),
}


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("model connectivity topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"model connectivity task order mismatch: {step}")
    timeout = context.config.settings.get("timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise ValueError("model connectivity timeout is invalid")


def build_job(*, check_models: ModelCheck | None = None) -> Job:
    def resolve_models(unit: UnitContext) -> Mapping[str, Any]:
        required = configured_models(resolved_configuration(unit.job.run_root))
        return {"required": required,
                "model_count": len({(item["provider"], item["model"]) for item in required})}

    def verify_models(unit: UnitContext) -> Mapping[str, Any]:
        required = unit.output("connectivity.resolve_models")["required"]
        document: dict[str, Any] = {"schema": PREFLIGHT_SCHEMA, "required": required,
                                    "providers": {}, "unavailable": []}
        if check_models is None:
            raise RuntimeError("model connectivity check is not wired into this job instance")
        timeout = int(unit.job.config.settings["timeout_seconds"])
        for provider in sorted({item["provider"] for item in required}):
            names = sorted({item["model"] for item in required if item["provider"] == provider})
            report = dict(check_models(provider, names, timeout_seconds=timeout))
            document["providers"][provider] = report
            for name in names:
                entry = report.get("models", {}).get(name, {})
                if entry.get("available") is not True:
                    document["unavailable"].append({
                        "provider": provider, "model": name,
                        "detail": str(entry.get("detail") or report.get("error") or "not reported"),
                        "jobs": sorted({item["job_id"] for item in required
                                        if (item["provider"], item["model"]) == (provider, name)}),
                    })
        path = unit.unit_root / "model-connectivity.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        unit.job.events.write(
            "MODEL_CONNECTIVITY_COMPLETED", unit_id=unit.unit_id,
            provider_count=len(document["providers"]),
            model_count=sum(len(report.get("models", {})) for report in document["providers"].values()),
            unavailable_count=len(document["unavailable"]),
        )
        if document["unavailable"]:
            raise RuntimeError("model connectivity blocked the review: " + "; ".join(
                f"{item['provider']}/{item['model']} ({item['detail']})"
                for item in document["unavailable"]))
        return {"schema": PREFLIGHT_SCHEMA, "artifact": identity,
                "providers": sorted(document["providers"]),
                "verified": sorted(f"{provider}/{name}"
                                   for provider, report in document["providers"].items()
                                   for name in report.get("models", {}))}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        verified = unit.output("connectivity.verify_models")
        document = {"schema": PREFLIGHT_SCHEMA, "artifact": verified["artifact"],
                    "providers": verified["providers"], "verified": verified["verified"]}
        path = unit.unit_root / "model-connectivity-handoff.json"
        identity = write_json(path, document)
        identity["path"] = path.relative_to(unit.job.run_root).as_posix()
        return {"schema": PREFLIGHT_SCHEMA, "artifact": identity,
                "verified": verified["verified"], "gaps": []}

    units = (
        Unit("connectivity.resolve_models", resolve_models),
        Unit("connectivity.verify_models", verify_models, ("connectivity.resolve_models",)),
        Unit("publication.publish_handoff", publish_handoff, ("connectivity.verify_models",)),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
                                    (b"model-check" if check_models else b"no-model-check")).hexdigest()
    return Job(
        "job_model_connectivity", "model_connectivity", UnitExecutor(units).execute,
        input_validators=(_validate,), schema_identity="appsec-review/model-connectivity-job/1",
        implementation_identity=implementation, validation_identity=implementation,
        units=units, datasets=DATASETS, consumes=CONSUMES,
        always_execute=True, propagate_handoff=False,
    )
