"""Small run-owned identity reads; never rebuild topology from the current registry."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from uuid import UUID

from appsec_review.observability.model_metrics import label
from appsec_review.runtime.selection import resolved_job_is_enabled
from appsec_review.reporting.telemetry.inputs import RUN_TERMINALS
from appsec_review.storage import canonical_json

GRAPH_SCHEMA = "appsec-review/run-graph/1"
MAX_JSON_BYTES = 8 * 1024 * 1024


def observation_epoch(events: Sequence[Mapping[str, Any]]) -> tuple[int, int]:
    """Current execution boundary and the earliest graph selection that can belong to it."""
    epoch = graph_floor = last_sequence = selection = 0
    dispatch = graph_identity = None
    terminal = False
    for event in events:
        kind, details, sequence = event["event_type"], event["details"], event["sequence"]
        if kind == "RUN_GRAPH_SNAPSHOT":
            identity = details.get("graph_reference", {}).get("sha256")
            candidate_dispatch = details.get("dagster_run_id")
            if (not epoch or terminal or identity != graph_identity
                    or candidate_dispatch != dispatch):
                epoch = graph_floor = sequence
                terminal = False
            selection, graph_identity, dispatch = sequence, identity, candidate_dispatch
        elif kind == "RUN_STARTED":
            # Dagster may admit inputs between selection and its first RUN_STARTED.
            graph_floor = selection if selection and (selection == epoch or selection == last_sequence) else sequence
            epoch, terminal = sequence, False
        elif kind in RUN_TERMINALS:
            terminal = (not dispatch or details.get("dagster_run_id") == dispatch
                        or details.get("dagster_run_id") is None and event.get("orchestrator") != "dagster")
        last_sequence = sequence
    return epoch, graph_floor


def read_json(root: Path, relative: str, *, limit: int = MAX_JSON_BYTES,
              expected: str | None = None) -> tuple[dict[str, Any], str]:
    path = root / relative
    if path.is_symlink() or root.resolve() not in path.resolve().parents:
        raise ValueError("run artifact escapes root")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("run artifact exceeds read bound")
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None and digest != expected:
        raise ValueError("run artifact hash mismatch")
    try:
        value = json.loads(data)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("invalid run artifact encoding or nesting") from exc
    if not isinstance(value, dict):
        raise ValueError("run artifact must be an object")
    return value, digest


def validate_graph(value: Mapping[str, Any], *, run_id: str, config_sha256: str) -> None:
    if (value.get("schema") != GRAPH_SCHEMA or value.get("run_id") != run_id
            or value.get("resolved_config_sha256") != config_sha256):
        raise ValueError("run graph provenance mismatch")
    if (set(value) != {"schema", "run_id", "resolved_config_sha256", "dagster_run_id",
                      "profile", "source_sha256", "jobs", "partial_jobs"}
            or not re.fullmatch(r"[a-f0-9]{64}", config_sha256)
            or (value["source_sha256"] is not None and (
                not isinstance(value["source_sha256"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", value["source_sha256"])))
            or (value["profile"] is not None and (
                not isinstance(value["profile"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["profile"])))):
        raise ValueError("invalid run graph identity fields")
    if value["dagster_run_id"] is not None:
        if not isinstance(value["dagster_run_id"], str):
            raise ValueError("invalid Dagster graph identity")
        UUID(value["dagster_run_id"])
    jobs = value.get("jobs")
    if not isinstance(jobs, dict) or not 1 <= len(jobs) <= 200:
        raise ValueError("run graph job bound")
    partial = value["partial_jobs"]
    if (not isinstance(partial, list) or not all(isinstance(job, str) and job in jobs for job in partial)
            or len(set(partial)) != len(partial)):
        raise ValueError("invalid partial job selection")
    for job, parents in jobs.items():
        if (not isinstance(job, str) or not re.fullmatch(r"job_[a-z0-9_]{1,120}", job)
                or not isinstance(parents, list)
                or not all(isinstance(parent, str) and parent in jobs and parent != job for parent in parents)
                or len(parents) != len(set(parents))):
            raise ValueError("invalid run graph dependencies")
    visited: set[str] = set()
    while len(visited) < len(jobs):
        ready = {job for job, parents in jobs.items() if job not in visited and set(parents) <= visited}
        if not ready:
            raise ValueError("run graph has a cycle")
        visited.update(ready)


def _reference(root: Path, ref: Any) -> tuple[dict[str, Any], str]:
    if (not isinstance(ref, dict) or not isinstance(ref.get("path"), str)
            or not isinstance(ref.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", ref["sha256"])):
        raise ValueError("invalid run artifact reference")
    return read_json(root, ref["path"], expected=ref["sha256"])


def freeze_run_graph(run_root: Path, jobs: Mapping[str, Sequence[str]], *,
                     config_sha256: str, dagster_run_id: str | None = None,
                     profile: str | None = None, source_sha256: str | None = None,
                     partial_jobs: Sequence[str] = ()) -> dict[str, Any]:
    """Called by the graph owner at launch, never by the read-only monitor."""
    from appsec_review.storage.shared import immutable_bytes

    value = {"schema": GRAPH_SCHEMA, "run_id": run_root.name, "resolved_config_sha256": config_sha256,
             "dagster_run_id": dagster_run_id, "profile": profile, "source_sha256": source_sha256,
             "partial_jobs": sorted(partial_jobs),
             "jobs": {job: sorted(parents) for job, parents in sorted(jobs.items())}}
    validate_graph(value, run_id=run_root.name, config_sha256=config_sha256)
    payload = canonical_json(value)
    digest = hashlib.sha256(payload).hexdigest()
    return dict(immutable_bytes(run_root, f"data/configuration/graphs/{digest}.json", payload))


def record_graph_selection(config: Any, run_root: Path, jobs: Mapping[str, Sequence[str]], *,
                           dagster_run_id: str | None = None,
                           partial_jobs: Sequence[str] = ()) -> dict[str, Any]:
    """Persist exact driver selection, with no current-registry reconstruction or target reads."""
    from appsec_review.observability.events import PipelineLog
    from appsec_review.runtime.release import load_release

    release = load_release(config.runtime.repository_root)
    ref = freeze_run_graph(run_root, jobs, config_sha256=config.resolved_sha256, profile=config.profile,
                           source_sha256=release["sha256"] if release else None,
                           dagster_run_id=dagster_run_id, partial_jobs=partial_jobs)
    PipelineLog(run_root).write("RUN_GRAPH_SNAPSHOT", run_id=run_root.name,
                               orchestrator="dagster" if dagster_run_id else "application",
                               details={"graph_reference": ref, "dagster_run_id": dagster_run_id})
    return ref


def frozen_inputs(root: Path, events: Sequence[Mapping[str, Any]], *, max_rows: int = 8) -> dict[str, Any]:
    gaps: list[str] = []
    config: dict[str, Any] = {}
    config_sha = None
    profile = None
    try:
        manifest, _ = read_json(root, "data/configuration/manifest.json")
        expected = manifest.get("resolved_sha256")
        if (manifest.get("schema") != "appsec-review/run-configuration/2"
                or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)):
            raise ValueError("invalid frozen configuration manifest")
        config, config_sha = read_json(root, "data/configuration/resolved.json", expected=expected)
        profile = label(manifest.get("selection", {}).get("profile"))
    except (OSError, ValueError, TypeError, AttributeError):
        gaps.append("frozen_configuration_unavailable_or_invalid")
    enabled = []
    models: set[tuple[str, str]] = set()

    def walk(value: Any, depth: int = 0) -> None:
        if not isinstance(value, dict) or depth > 20:
            return
        if isinstance(value.get("provider"), str) and isinstance(value.get("model"), str):
            models.add((label(value["provider"]), label(value["model"])))
        for nested in value.values():
            walk(nested, depth + 1)

    try:
        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict) or len(jobs) > 200:
            raise ValueError("invalid frozen jobs")
        for job, settings in jobs.items():
            if not isinstance(settings, dict):
                raise ValueError("invalid frozen job")
            if resolved_job_is_enabled(job, settings):
                enabled.append(job)
                walk(settings.get("settings"))
    except (ValueError, TypeError, AttributeError):
        gaps.append("frozen_job_configuration_invalid")
        enabled, models = [], set()
    graph = None
    graph_sha = None
    _, graph_floor = observation_epoch(events)
    latest_graph = next((event for event in reversed(events) if event["sequence"] >= graph_floor
                         and (event["event_type"] == "RUN_GRAPH_SNAPSHOT"
                              or event["event_type"] == "GRAPH_STARTED"
                              and event["details"].get("graph_reference"))), None)
    try:
        ref = latest_graph["details"]["graph_reference"] if latest_graph else None
        if not isinstance(ref, dict) or config_sha is None:
            raise ValueError("no frozen actual graph")
        graph, graph_sha = _reference(root, ref)
        validate_graph(graph, run_id=root.name, config_sha256=config_sha)
        if not set(graph["jobs"]) <= set(enabled):
            raise ValueError("run graph disagrees with enabled configuration")
        if graph["partial_jobs"]:
            graph, graph_sha = None, None
            gaps.append("partial_job_op_selection_has_no_whole_job_denominator")
    except (OSError, ValueError, TypeError, KeyError):
        graph, graph_sha = None, None
        gaps.append("actual_run_graph_unavailable_or_invalid")
    source_sha = None
    try:
        binding, _ = read_json(root, "data/recovery/current.json")
        if binding.get("schema") != "appsec-review/implementation-binding/1":
            raise ValueError("invalid implementation binding")
        ref = binding["release"]
        release, _ = _reference(root, ref)
        from appsec_review.runtime.release import validate_release
        release = validate_release(release)
        if release["sha256"] != binding["release_sha256"]:
            raise ValueError("source identity mismatch")
        source_sha = release["sha256"]
    except (OSError, ValueError, TypeError, KeyError):
        gaps.append("frozen_source_identity_unavailable_or_invalid")
    if graph and ((graph["profile"] is not None and label(graph["profile"]) != profile)
                  or graph["source_sha256"] != source_sha):
        graph, graph_sha = None, None
        gaps.append("graph_source_or_profile_identity_mismatch")
    return {
        "profile": profile, "configuration_sha256": config_sha, "source_sha256": source_sha,
        "configured_models": [{"provider": provider, "model": model}
                              for provider, model in sorted(models)[:max_rows]],
        "omitted_configured_models": max(0, len(models) - max_rows),
        "configured_enabled_jobs": len(enabled) if config_sha else None,
        "graph": graph, "graph_sha256": graph_sha, "gaps": gaps,
    }
