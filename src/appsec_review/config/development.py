"""Development-only, per-job input overrides.

``[[jobs.<job>.development.input_overrides]]`` maps one already-declared upstream data artifact to an
edited copy under ``data/development/input-overrides/<job>/``. The table is accepted only from the
layer of an explicitly selected development profile (``DEVELOPMENT_PROFILES``); the base recipe, a
capacity overlay and every other profile reject it. Resolution, snapshotting and reads live in
``appsec_review.runtime.job`` (``Job.resolve_development_inputs`` / ``JobContext.input_file``).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping

DEVELOPMENT_PROFILES: tuple[str, ...] = (
    "copilot-dev", "copilot-dev-astra-6.2", "copilot-dev-gemini", "wsollers1-dev")
OVERRIDE_DIRECTORY = "data/development/input-overrides"
_JOB = re.compile(r"job_[a-z][a-z0-9_]*")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")
_FIELDS = ("producer", "output_kind", "artifact", "replacement")
# Control records and signing material are never data inputs, whatever a glob would admit.
_CONTROL_NAMES = frozenset({
    "claim.json", "handoff.json", "status.json", "result.json", "latest.json", "published.json",
    "outcomes.json", "failure-finalized.json", "rejected-handoff.json", "rejected-outcomes.json",
    "checkpoint.json", "lifecycle.json", "manifest.json", "current.json"})
_EXECUTABLE_SUFFIXES = frozenset({
    ".py", ".pyc", ".so", ".dll", ".dylib", ".exe", ".sh", ".bash", ".bat", ".cmd", ".ps1",
    ".jar", ".class", ".sig", ".pem", ".key", ".crt"})
_CONTROL_PREFIXES = ("data/configuration/", "data/recovery/", "data/guidance/", "data/inputs/")


@dataclass(frozen=True, slots=True)
class InputOverride:
    producer: str
    output_kind: str
    # Run-relative path of the producer's accepted artifact being replaced.
    artifact: str
    # Repository-relative path of the operator's edited copy.
    replacement: str

    def view(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in _FIELDS}


@dataclass(frozen=True, slots=True)
class JobDevelopment:
    input_overrides: tuple[InputOverride, ...]

    def view(self) -> dict[str, Any]:
        return {"input_overrides": [item.view() for item in self.input_overrides]}


def _relative(value: object, field: str) -> str:
    path = PurePosixPath(value) if isinstance(value, str) else None
    if (path is None or not value or path.is_absolute() or "\\" in value or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)):
        raise ValueError(f"{field} must be a canonical relative path")
    if path.suffix.lower() in _EXECUTABLE_SUFFIXES:
        raise ValueError(f"{field} names executable code or signing material, not a data input")
    return value


def parse_job_development(job_id: str, value: object) -> JobDevelopment:
    label = f"jobs.{job_id}.development"
    if not isinstance(value, Mapping) or set(value) != {"input_overrides"}:
        raise ValueError(f"{label} must define exactly input_overrides")
    rows = value["input_overrides"]
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{label}.input_overrides must be a non-empty array of tables")
    overrides: list[InputOverride] = []
    for index, row in enumerate(rows):
        field = f"{label}.input_overrides[{index}]"
        if not isinstance(row, Mapping) or set(row) != set(_FIELDS):
            raise ValueError(f"{field} must define exactly {list(_FIELDS)}")
        if not all(isinstance(row[name], str) for name in _FIELDS):
            raise ValueError(f"{field} values must be strings")
        if not _JOB.fullmatch(row["producer"]) or row["producer"] == job_id:
            raise ValueError(f"{field}.producer must name another job")
        if not _NAME.fullmatch(row["output_kind"]) or row["output_kind"] == "handoff":
            raise ValueError(f"{field}.output_kind must name a declared data output, not the handoff envelope")
        artifact = _relative(row["artifact"], f"{field}.artifact")
        if (not artifact.startswith("data/") or artifact.startswith(_CONTROL_PREFIXES)
                or PurePosixPath(artifact).name in _CONTROL_NAMES):
            raise ValueError(f"{field}.artifact must be a run data artifact, not a control or signing record")
        replacement = _relative(row["replacement"], f"{field}.replacement")
        if not replacement.startswith(f"{OVERRIDE_DIRECTORY}/{job_id}/"):
            raise ValueError(f"{field}.replacement must be under {OVERRIDE_DIRECTORY}/{job_id}/")
        overrides.append(InputOverride(row["producer"], row["output_kind"], artifact, replacement))
    if len({item.artifact for item in overrides}) != len(overrides):
        raise ValueError(f"{label}.input_overrides repeats an artifact")
    return JobDevelopment(tuple(overrides))


def split_profile_development(document: object) -> tuple[Any, dict[str, Any]]:
    """Separate ``jobs.*.development`` from a profile so the closed model allowlist still applies."""
    if not isinstance(document, Mapping) or not isinstance(document.get("jobs"), Mapping):
        return document, {}
    remainder = copy.deepcopy(dict(document))
    found: dict[str, Any] = {}
    for job_id in list(remainder["jobs"]):
        job = remainder["jobs"][job_id]
        if isinstance(job, dict) and "development" in job:
            found[job_id] = job.pop("development")
            if not job:
                del remainder["jobs"][job_id]
    if not remainder["jobs"]:
        del remainder["jobs"]
    return remainder, found


def reject_development(document: Mapping[str, Any], layer: str) -> None:
    jobs = document.get("jobs")
    named = sorted(job_id for job_id, job in (jobs.items() if isinstance(jobs, Mapping) else ())
                   if isinstance(job, Mapping) and "development" in job)
    if named:
        raise ValueError(f"jobs.{named[0]}.development is not allowed in {layer}; put it in an explicitly "
                         f"selected development profile ({', '.join(DEVELOPMENT_PROFILES)})")


def _without_development(document: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(document))
    for job in (value.get("jobs") or {}).values():
        if isinstance(job, dict):
            job.pop("development", None)
    profile = value.get("configuration_profile")
    if isinstance(profile, dict):
        profile["document"] = split_profile_development(profile.get("document", {}))[0]
        profile["keys"] = [key for key in profile.get("keys", []) if ".development." not in str(key)]
        profile.pop("sha256", None)
    return value


def development_only_change(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    """Whether two resolved configurations differ only in development input overrides."""
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))  # noqa: E731
    return canonical(_without_development(before)) == canonical(_without_development(after))
