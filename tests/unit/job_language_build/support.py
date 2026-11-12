"""Shared fakes for the job_language_build unit tier: a run root with a verified resolved
configuration, a unit context over the shipped job configuration, and small accepted dispatches.
Nothing here runs a job, a container or a model."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.jobs.job_language_build.job import build_job

ROOT = Path(__file__).resolve().parents[3]
FAMILIES = ("native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm")
SOURCE_FINGERPRINT = "f" * 64
HANDOFF_SHA = "6" * 64
RELEASES = {"platform": "fixture-platform", "build_toolchain": "fixture-build", "validation": "fixture-validation"}


def units(**kwargs) -> dict[str, Any]:
    return {unit.unit_id: unit for unit in build_job(**kwargs).units}


def real_job():
    return load_config(ROOT / "appsec-review.toml").job("job_language_build")


class Events:
    def __init__(self) -> None:
        self.written: list[tuple[str, dict[str, Any]]] = []

    def write(self, event: str, **fields: Any) -> None:
        self.written.append((event, fields))


def write_resolved_configuration(run_root: Path, document: dict[str, Any] | None = None) -> str:
    """The run-owned immutable configuration every handler resolves its identity from."""
    configuration = run_root / "data" / "configuration"
    configuration.mkdir(parents=True, exist_ok=True)
    resolved = configuration / "resolved.json"
    resolved.write_text(json.dumps(document or {"tools": {"enable_swift": False}}, sort_keys=True), encoding="utf-8")
    identity = hashlib.sha256(resolved.read_bytes()).hexdigest()
    (configuration / "manifest.json").write_text(json.dumps({"resolved_sha256": identity}), encoding="utf-8")
    return identity


def job_context(tmp_path: Path, **overrides: Any) -> SimpleNamespace:
    run_root = tmp_path / "run"
    write_resolved_configuration(run_root)
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    fields = {"run_id": "2026-11-12-0001", "attempt_id": "attempt_0001", "run_root": run_root,
              "attempt_root": run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_0001",
              "metadata_root": tmp_path / "metadata", "target_root": target,
              "source_fingerprint": SOURCE_FINGERPRINT, "config": real_job(),
              "review_policy": SimpleNamespace(releases=ComponentReleases(dict(RELEASES))),
              "events": Events()}
    fields.update(overrides)
    return SimpleNamespace(**fields)


def unit_context(tmp_path: Path, unit_id: str, outputs: dict[str, Any] | None = None,
                 **job_overrides: Any) -> SimpleNamespace:
    outputs = dict(outputs or {})
    step_id, task_id = unit_id.split(".")
    return SimpleNamespace(job=job_context(tmp_path, **job_overrides), unit_id=unit_id, step_id=step_id,
                           task_id=task_id, unit_root=tmp_path / "unit" / unit_id, outputs=outputs,
                           output=lambda key: outputs[key])


def dispatch(build_unit_id: str, family: str = "native", *, root: str = ".", build_system: str = "cmake",
             dependencies: tuple[str, ...] = (), complete_inventory: bool = True,
             expected_outputs: tuple[str, ...] = ("build",), commands=None) -> dict[str, Any]:
    """An accepted build dispatch as job_project_build hands it over, after _dispatches validated it."""
    documents = ([{"path": f"{root}/CMakeLists.txt".lstrip("./") or "CMakeLists.txt", "sha256": "a" * 64,
                   "content": "project(x)"}] if complete_inventory else [])
    return {"workflow": "lang_jobflow_build", "build_unit_id": build_unit_id, "family": family, "root": root,
            "build_system": build_system, "source_fingerprint": SOURCE_FINGERPRINT,
            "recipe_identity": "2" * 64, "probe_identity": "3" * 64,
            "image": {"image_id": "sha256:" + "5" * 64, "dependency_hashes": {}},
            "recipe": {"source_dir": root, "build_dir": f"{root}/build" if root != "." else "build",
                       "configure_commands": [], "build_commands": commands or [["cmake", "--build", "build"]],
                       "expected_outputs": list(expected_outputs)},
            "build_dependencies": list(dependencies),
            "descriptor_package": {"documents": documents, "gaps": [], "inventory": []}}


def accepted(*dispatches: dict[str, Any], probe_receipts=(), execution_mode: str = "legacy") -> dict[str, Any]:
    probes = list(probe_receipts) or [
        {"build_unit_id": item["build_unit_id"], "family": item["family"], "root": item["root"],
         "build_system": item["build_system"], "terminal_status": "SUCCEEDED", "gaps": []}
        for item in dispatches]
    return {"schema": "appsec-review/project-build-dispatch/3", "execution_mode": execution_mode,
            "source_fingerprint": SOURCE_FINGERPRINT, "project_build_handoff_sha256": HANDOFF_SHA,
            "build_dispatches": list(dispatches), "probe_receipts": probes,
            "execution_graph": {"edges": []}, "images": {}}
