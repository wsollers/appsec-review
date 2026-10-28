"""Pre-intake gate: acquire (or re-verify) every component of the requested review system.

A review *system* may be composed of several source-control components (Git by default, Perforce, or
code-review exports). ``start --system <id>`` (or ``APPSEC_REVIEW_SYSTEM`` for any driver) names the
configured ``[[target_acquisition.systems]]`` entry. This gate acquires its components concurrently,
bounded by ``target_acquisition.max_parallel_components``, into ``targets/<system>/<component>/`` and
records the composed ``targets/<system>`` root that intake fingerprints and discovery reads once.

A component whose checkout and record already exist is only re-verified, so a resumed run never
fetches or edits a checkout. A failed component is a named gap and the system is ``PARTIAL``; when no
component is available the gate fails the run. Without a requested system the gate records
``NOT_REQUESTED`` and changes nothing. Credentials come only from the environment variables the
configuration names and never reach an artifact.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import re
import tomllib
from typing import Any

from appsec_review.config.target_acquisition import parse_target_acquisition
from appsec_review.jobs.cataloging import write_json
from appsec_review.jobs.job_target_acquisition.datasets import CONSUMES, DATASETS
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor


JOB_ID = "job_target_acquisition"
SCHEMA = "appsec-review/target-acquisition-job/1"
PLAN_NAME = "target-acquisition-plan.json"
RESULT_NAME = "target-acquisition-result.json"
MANIFEST_NAME = "system-manifest.json"
HANDOFF_NAME = "target-acquisition-handoff.json"
TOPOLOGY = {
    "selection": ("resolve_system",),
    "acquisition": ("acquire_components",),
    "publication": ("publish_handoff",),
}
_SYSTEM_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("target acquisition topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"target acquisition task order mismatch: {step}")
    unknown = set(context.config.settings) - {"enabled"}
    if unknown:
        raise ValueError("jobs.job_target_acquisition.settings has unknown keys: " + ", ".join(sorted(unknown)))


def requested_system(environ: Mapping[str, str] | None = None) -> str | None:
    from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT
    value = (os.environ if environ is None else environ).get(SYSTEM_ENVIRONMENT, "")
    if not value:
        return None
    if not _SYSTEM_ID.fullmatch(value):
        raise ValueError(f"{SYSTEM_ENVIRONMENT} is not a valid system id")
    return value


def _identity(unit: UnitContext, path: Path, document: Mapping[str, Any]) -> dict[str, Any]:
    identity = write_json(path, document)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _settings(unit: UnitContext):
    frozen = unit.job.run_root / "data" / "configuration" / "appsec-review.toml"
    data = frozen.read_bytes()
    document = tomllib.loads(data.decode("utf-8"))
    settings = parse_target_acquisition(document.get("target_acquisition"), unit.job.repository_root)
    return settings, {"path": frozen.relative_to(unit.job.run_root).as_posix(),
                      "sha256": hashlib.sha256(data).hexdigest()}


def build_job(*, environ: Mapping[str, str] | None = None, fetcher_factory=None) -> Job:
    def resolve_system(unit: UnitContext) -> Mapping[str, Any]:
        system_id = requested_system(environ)
        settings, configuration = _settings(unit)
        document: dict[str, Any] = {"schema": SCHEMA, "configuration": configuration, "requested": False,
                                    "system_id": system_id}
        if system_id is not None:
            try:
                system = settings.system(system_id)
            except KeyError:
                raise ValueError(f"requested system is not configured under [[target_acquisition.systems]]: "
                                 f"{system_id}") from None
            system_root = (unit.job.repository_root / settings.targets_dir / system_id).resolve()
            if unit.job.target_root is not None and unit.job.target_root.resolve() != system_root:
                raise ValueError("the review target is not the composed root of the requested system")
            document.update({
                "requested": True, "spec": system.spec(),
                "target_path": f"{settings.targets_dir}/{system_id}",
                "max_parallel_components": min(settings.max_parallel_components, len(system.components)),
            })
        identity = _identity(unit, unit.unit_root / PLAN_NAME, document)
        return {"schema": SCHEMA, "artifact": identity, "requested": document["requested"],
                "system_id": system_id}

    def acquire_components(unit: UnitContext) -> Mapping[str, Any]:
        plan = unit.output("selection.resolve_system")
        if not plan["requested"]:
            document = {"schema": SCHEMA, "status": "NOT_REQUESTED", "plan": plan["artifact"]}
            return {"schema": SCHEMA, "status": "NOT_REQUESTED",
                    "artifact": _identity(unit, unit.unit_root / RESULT_NAME, document), "gaps": []}
        from appsec_review.target_acquisition.acquire import acquire_system, system_paths
        settings, _configuration = _settings(unit)
        system = settings.system(plan["system_id"])
        unit.job.events.write("TARGET_ACQUISITION_STARTED", unit_id=unit.unit_id, system_id=system.system_id,
                              components=[item.target_id for item in system.components])
        result = acquire_system(repository_root=unit.job.repository_root, settings=settings, system=system,
                                environ=environ, fetcher_factory=fetcher_factory)
        components = {component_id: {key: value.get(key) for key in (
            "status", "action", "acquisition_id", "target_path", "manifest", "manifest_sha256", "tree_sha256",
            "error", "failure_record")} for component_id, value in result.get("components", {}).items()}
        document = {"schema": SCHEMA, "plan": plan["artifact"], "system_id": system.system_id,
                    "status": result["status"], "acquisition_id": result.get("acquisition_id"),
                    "target_path": result.get("target_path"), "manifest": result.get("manifest"),
                    "manifest_sha256": result.get("manifest_sha256"), "tree_sha256": result.get("tree_sha256"),
                    "components": components, "gaps": result.get("gaps", []), "error": result.get("error")}
        identity = _identity(unit, unit.unit_root / RESULT_NAME, document)
        manifest_identity = None
        _system_root, records = system_paths(unit.job.repository_root, settings, system.system_id)
        manifest_path = records / "manifest.json"
        if result.get("manifest") and manifest_path.is_file():
            copy = unit.unit_root / MANIFEST_NAME
            data = manifest_path.read_bytes()
            if hashlib.sha256(data).hexdigest() != result.get("manifest_sha256"):
                raise RuntimeError("the system manifest changed while it was being recorded")
            copy.write_bytes(data)
            manifest_identity = {"name": MANIFEST_NAME, "sha256": result["manifest_sha256"],
                                 "path": copy.relative_to(unit.job.run_root).as_posix()}
        if result["status"] not in {"COMPLETE", "PARTIAL"}:
            unit.job.events.write("TARGET_ACQUISITION_FAILED", unit_id=unit.unit_id, system_id=system.system_id,
                                  status=result["status"], record=identity["path"])
            failures = [f"{component_id}: {value.get('status')}: {value.get('error')}"
                        for component_id, value in components.items() if value.get("error")]
            raise RuntimeError("\n".join([
                f"target acquisition of system {system.system_id} is {result['status']}: "
                f"{result.get('error') or 'no component is available'}", *failures,
                f"acquisition record: {unit.unit_root / RESULT_NAME}"]))
        unit.job.events.write("TARGET_ACQUISITION_COMPLETED", unit_id=unit.unit_id, system_id=system.system_id,
                              status=result["status"], gap_count=len(document["gaps"]))
        return {"schema": SCHEMA, "status": result["status"], "artifact": identity,
                "manifest": manifest_identity, "system_id": system.system_id,
                "acquisition_id": result.get("acquisition_id"), "tree_sha256": result.get("tree_sha256"),
                "target_path": result.get("target_path"), "components": components, "gaps": document["gaps"]}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        acquired = unit.output("acquisition.acquire_components")
        document = {key: acquired.get(key) for key in (
            "schema", "status", "artifact", "manifest", "system_id", "acquisition_id", "tree_sha256",
            "target_path", "components", "gaps")}
        identity = _identity(unit, unit.unit_root / HANDOFF_NAME, document)
        return {**document, "artifact": identity, "result": acquired["artifact"],
                "gaps": list(acquired.get("gaps") or [])}

    units = (
        Unit("selection.resolve_system", resolve_system),
        Unit("acquisition.acquire_components", acquire_components, ("selection.resolve_system",)),
        Unit("publication.publish_handoff", publish_handoff, ("acquisition.acquire_components",)),
    )
    return Job(
        JOB_ID, "target_acquisition", UnitExecutor(units).execute,
        input_validators=(_validate,), schema_identity=SCHEMA, units=units, datasets=DATASETS,
        consumes=CONSUMES, always_execute=True, propagate_handoff=False,
    )
