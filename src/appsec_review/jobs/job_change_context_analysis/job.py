from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from appsec_review.container_runtime import ContainerExecutor, load_catalog
from appsec_review.jobs.job_source_history_analysis import load_accepted_history
from appsec_review.jobs.job_source_history_analysis import signals as history_signals
from appsec_review.jobs.job_source_history_analysis.git import GitRunner, parse_log
from appsec_review.jobs.job_source_history_analysis.sources import GitSource
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from . import metrics as change_metrics
from .attribution import (
    ATTRIBUTION_IDENTITY, function_spans, innermost_function, parse_blame_commits, parse_blame_lines,
    parse_old_hunks,
)
from .settings import ChangeContextSettings, parse_settings
from .sources import (
    deployments_from_export, identity_hash, load_export, normalize_review_record, organization_from_export,
    review_records_from_export,
)


SCHEMA = "appsec-review/change-context-analysis/1"
PRODUCER = "job_change_context_analysis"
SHARD_ID = "change-context"
AUTHORITY = "change-context priorities order review work; they are never vulnerability findings or evidence"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "load": ("accepted_history", "external_sources"),
    "attribute": ("line_attribution", "fix_on_fix"),
    "analyze": ("change_signals", "unit_signals", "rank"),
    "publish": ("index_change_context", "publish_handoff"),
}
SKIPPED = {"SKIPPED_NA", "SKIPPED_POLICY"}
ExecutorFactory = Callable[[UnitContext], ContainerExecutor]


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _write(unit: UnitContext, name: str, value: Any) -> dict[str, Any]:
    path = unit.unit_root / "artifacts" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return _artifact(unit.job.run_root, path)


def _read_bytes(run_root: Path, identity: Mapping[str, Any]) -> bytes:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity.get("sha256"):
        raise ValueError("change context artifact identity mismatch")
    return path.read_bytes()


def _read(run_root: Path, identity: Mapping[str, Any]) -> Any:
    return json.loads(_read_bytes(run_root, identity).decode("utf-8"))


def _accepted_handoff(run_root: Path, job_id: str, *, required: bool) -> tuple[Mapping[str, Any], str] | None:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file():
        if required:
            raise ValueError(f"accepted {job_id} handoff is required")
        return None
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def _accepted_outputs(run_root: Path, handoff: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the full unit outputs of an accepted attempt, verified through its handoff."""
    result_path = str(handoff["resolving_paths"]["result"])
    entry = next((item for item in handoff.get("artifacts", ()) if item.get("path") == result_path), None)
    if entry is None:
        raise ValueError("accepted handoff does not pin its result")
    return _read(run_root, entry)["outputs"]


def _resolved_job_settings(run_root: Path, job_id: str) -> Mapping[str, Any]:
    """Read another job's settings from the run-owned, hash-verified resolved configuration."""
    destination = run_root / "data" / "configuration"
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    resolved = _read(run_root, {"path": _rel(run_root, destination / "resolved.json"),
                                "sha256": manifest["resolved_sha256"]})
    return resolved["jobs"][job_id]["settings"]


def _load_catalog(run_root: Path) -> dict[str, Any]:
    accepted = _accepted_handoff(run_root, "job_target_catalog", required=True)
    assert accepted is not None
    catalog = _read(run_root, accepted[0]["outputs"]["publish_catalog.publish_handoff"]["artifact"])
    if catalog.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("change context catalog schema is unsupported")
    components = _read(run_root, catalog["artifacts"]["component_discovery.catalog_components"])
    return {"source_fingerprint": catalog["source_fingerprint"], "catalog_handoff_sha256": accepted[1],
            "components": [{"component_id": item["component_id"], "root": item.get("root") or "."}
                           for item in components.get("components", ())]}


def _settings(context) -> ChangeContextSettings:
    return parse_settings(context.config.settings)


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("change context topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"change context task order mismatch: {step}")
    settings = _settings(context)
    for pattern in (*settings.test_association.test_patterns, *settings.test_association.contract_patterns):
        change_metrics.glob_regex(pattern)


def _status(gaps: list[str]) -> str:
    return "PARTIAL" if gaps else "SUCCEEDED"


def _source_status(gaps: list[str], available: bool) -> str:
    return "unavailable" if not available else "partial" if gaps else "complete"


def build_job(*, executor_factory: ExecutorFactory | None = None) -> Job:
    def factory(unit: UnitContext) -> ContainerExecutor:
        return executor_factory(unit) if executor_factory is not None else ContainerExecutor(
            load_catalog(unit.job.repository_root), unit.job.run_root)

    def history(unit: UnitContext) -> Mapping[str, Any]:
        return unit.output("load.accepted_history")

    def git_source(unit: UnitContext) -> GitSource | None:
        value = history(unit).get("git")
        if not value or value.get("decision") != "SUCCEEDED":
            return None
        return GitSource(**{**value, "shallow": tuple(value["shallow"]), "observations": tuple(value["observations"])})

    def runner(unit: UnitContext) -> GitRunner:
        source = git_source(unit)
        assert source is not None
        return GitRunner(factory(unit), unit.job.target_root or Path(), unit.unit_root / "scratch", source)

    def load_history(unit: UnitContext) -> Mapping[str, Any]:
        _settings(unit.job)
        run_root = unit.job.run_root
        catalog = _load_catalog(run_root)
        if catalog["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted catalog")
        accepted = _accepted_handoff(run_root, "job_source_history_analysis", required=True)
        assert accepted is not None
        handoff, handoff_sha = accepted
        document = load_accepted_history(run_root)
        assert document is not None
        outputs = _accepted_outputs(run_root, handoff)
        git = dict(outputs["resolve_sources.resolve_history_source"]["git"])
        normalized = outputs["acquire.normalize_changes"]
        base = {"history_handoff_sha256": handoff_sha, "history_identity": document["history_identity"],
                "history_gaps": list(document.get("gaps", ())), "git": git,
                "components": catalog["components"], "catalog_handoff_sha256": catalog["catalog_handoff_sha256"],
                "snapshot_commit": git.get("snapshot_commit")}
        if git["decision"] != "SUCCEEDED" or "artifact" not in normalized:
            reason = git.get("reason") if git["decision"] != "SUCCEEDED" else "no_bound_history"
            unit.job.events.write("CHANGE_CONTEXT_HISTORY_UNAVAILABLE", reason=reason)
            return {**base, "available": False, "reason": reason, "gaps": [], "terminal_status": "SKIPPED_NA"}
        eligible = outputs["resolve_sources.bind_snapshot"]["eligible"]
        history_settings = _resolved_job_settings(run_root, "job_source_history_analysis")
        raw_log = outputs["acquire.git_history"]["raw_log"]
        commits = parse_log(_read_bytes(run_root, raw_log))
        walked = int(normalized["walked_change_count"])
        lifetime = history_signals.normalize(
            commits[:walked], current_paths=eligible, shallow=(), window_days=1_000_000, max_changes=walked,
            bulk_threshold=int(history_settings["bulk_change_file_threshold"]))
        ordinals: dict[str, str] = {}
        for commit in commits[:walked]:
            ordinals.setdefault(str(commit["author_key"]), f"author-{len(ordinals) + 1:04d}")
        roots = history_signals.component_roots(catalog["components"])
        files: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        components: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for change in lifetime["changes"]:
            if change["bulk"]:
                continue
            touched = {entry["current_path"] for entry in change["files"] if entry.get("current_path") in eligible}
            for path in touched:
                files[path][change["author"]] += 1
            for component in {change_metrics.component_of(path, roots) for path in touched} - {None}:
                components[str(component)][change["author"]] += 1
        gaps = []
        if len(commits) > walked:
            gaps.append("lifetime_history_truncated")
        if git.get("shallow"):
            gaps.append("lifetime_history_shallow")
        lifetime_doc = {
            "schema": "appsec-review/change-context-lifetime/1", "walked_change_count": walked,
            "first_commit_time": int(commits[walked - 1]["commit_time"]) if walked else None,
            "files": {path: dict(sorted(value.items())) for path, value in sorted(files.items())},
            "components": {key: dict(sorted(value.items())) for key, value in sorted(components.items())},
            # Pseudonymous keys for organization matching only; never indexed.
            "identities": {ordinal: identity_hash(email) for email, ordinal in sorted(ordinals.items(), key=lambda i: i[1])},
            "gaps": gaps,
        }
        rank_output = outputs.get("analyze.rank", {})
        return {**base, "available": True, "eligible": eligible, "changes": normalized["artifact"],
                "classification": outputs["analyze.classify_changes"].get("artifact"),
                "classification_gaps": list(outputs["analyze.classify_changes"].get("gaps", ())),
                "github": outputs["acquire.github_enrichment"].get("artifact"),
                "github_status": outputs["acquire.github_enrichment"].get("terminal_status"),
                "github_reason": outputs["acquire.github_enrichment"].get("reason"),
                "github_gaps": list(outputs["acquire.github_enrichment"].get("gaps", ())),
                "history_signals": rank_output.get("artifact"), "lifetime": _write(unit, "lifetime.json", lifetime_doc),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def external(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = history(unit)
        repository, target = unit.job.repository_root, unit.job.target_root
        sources: dict[str, Any] = {}
        raw_copies: dict[str, Any] = {}

        def keep(name: str, data: bytes | None) -> None:
            if data is not None:
                path = unit.unit_root / "artifacts" / "inputs" / f"{name}.json"
                atomic_bytes(path, data)
                raw_copies[name] = _artifact(unit.job.run_root, path)

        review_source = settings.review.source
        reviews, review_gaps = None, []
        if review_source == "none":
            review_gaps = ["review_records_disabled"]
        elif review_source == "export":
            document, data, review_gaps = load_export(repository, target, settings.review.export, "review")
            keep("review", data)
            if document is not None:
                reviews, review_gaps = review_records_from_export(document)
                reviews = reviews if not review_gaps else None
        elif not loaded.get("available"):
            review_gaps = ["review_records_unavailable:no_git_history"]
        elif loaded.get("github") is None:
            review_gaps = [f"review_records_unavailable:{loaded.get('github_reason') or 'github_enrichment_missing'}"]
        else:
            facts = _read(unit.job.run_root, loaded["github"])["facts"]
            reviews = {commit: normalize_review_record(value) for commit, value in sorted(facts.items())}
            review_gaps = [f"review_records_partial:{gap}" for gap in loaded.get("github_gaps", ())]
        sources["review"] = {"source": review_source, "status": _source_status(review_gaps, reviews is not None),
                             "gaps": sorted(set(review_gaps)), "record_count": len(reviews or {})}
        deployments, deployment_gaps = None, []
        document, data, deployment_gaps = load_export(repository, target, settings.deployments.export, "deployment")
        keep("deployment", data)
        if document is not None:
            deployments, deployment_gaps = deployments_from_export(document, settings.deployments.environments)
        sources["deployment"] = {"status": _source_status(deployment_gaps, deployments is not None),
                                 "gaps": deployment_gaps, "event_count": len((deployments or {}).get("events", ())),
                                 "environments": list(settings.deployments.environments)}
        organization, organization_gaps = None, []
        document, data, organization_gaps = load_export(repository, target, settings.organization, "organization")
        keep("organization", data)
        if document is not None:
            organization, organization_gaps = organization_from_export(document)
        sources["organization"] = {"status": _source_status(organization_gaps, organization is not None),
                                   "gaps": organization_gaps, "member_count": len((organization or {}).get("members", {}))}
        zone_name, zone_gaps = settings.schedule.time_zone, []
        if not zone_name:
            zone_gaps = ["time_zone_not_configured"]
        else:
            try:
                ZoneInfo(zone_name)
            except (ZoneInfoNotFoundError, ValueError):
                zone_gaps = ["time_zone_database_unavailable"]
        sources["schedule"] = {"status": "unavailable" if zone_gaps else "complete", "gaps": zone_gaps,
                               "time_zone": zone_name or None}
        sources["test_association"] = {"status": "complete" if settings.test_association.enabled else "unavailable",
                                       "gaps": [] if settings.test_association.enabled else ["test_association_disabled"]}
        document = {"schema": "appsec-review/change-context-sources/1", "sources": sources,
                    "reviews": reviews, "deployments": deployments, "organization": organization}
        gaps = sorted({gap for value in sources.values() for gap in value["gaps"]})
        unit.job.events.write("CHANGE_CONTEXT_SOURCES_LOADED",
                              **{f"{name}_status": value["status"] for name, value in sources.items()})
        return {"artifact": _write(unit, "external-sources.json", document), "raw_exports": raw_copies,
                "sources": sources, "gaps": gaps, "terminal_status": _status(gaps)}

    def attribute_lines(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = history(unit)
        if not loaded.get("available"):
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "reason": "no_bound_history"}
        run_root = unit.job.run_root
        eligible = loaded["eligible"]
        ranking = _read(run_root, loaded["history_signals"])["files"] if loaded.get("history_signals") else {}
        candidates = sorted((path for path, value in ranking.items()
                             if eligible.get(path, {}).get("exact") and
                             int(eligible[path]["size_bytes"]) <= settings.ownership.line_attribution_max_file_bytes),
                            key=lambda path: (-int(ranking[path]["churn_lines"]), path))
        limit = settings.ownership.line_attribution_max_files
        gaps = ["line_attribution_bound_reached"] if len(candidates) > limit else []
        selected = candidates[:limit]
        tree = _accepted_handoff(run_root, "job_tree_sitter_ast", required=False)
        spans: dict[str, list[dict[str, Any]]] = {}
        unreliable: dict[str, str] = {}
        if tree is None:
            gaps.append("function_spans_unavailable:tree_sitter_not_accepted")
            unreliable = {path: "function_spans_unavailable" for path in selected}
        elif selected:
            accepted_tree = _read(run_root, tree[0]["outputs"]["acceptance.publish_handoff"]["artifact"])
            if accepted_tree.get("target_snapshot") != unit.job.source_fingerprint:
                raise ValueError("Tree-sitter snapshot does not match the change context target")
            lines: list[bytes] = []
            for value in accepted_tree.get("dispositions", ()):
                if isinstance(value, Mapping) and isinstance(value.get("artifact"), Mapping):
                    lines.extend(_read_bytes(run_root, value["artifact"]).splitlines())
            spans, unreliable = function_spans(lines, {path: eligible[path]["sha256"] for path in selected},
                                               unit.job.target_root or Path())
            if unreliable:
                gaps.append("function_mapping_unreliable")
        lifetime = _read(run_root, loaded["lifetime"])
        ordinal_of = {value: key for key, value in lifetime["identities"].items()}
        extra: dict[str, str] = {}
        files: dict[str, Any] = {}
        failures = 0
        git = runner(unit) if selected else None
        for index, path in enumerate(selected):
            assert git is not None
            run = git.run(f"attr-blame-{index:05d}", ("blame", "--porcelain", "-w", "--no-progress", "HEAD", "--", path))
            if run.exit_code != 0 or run.timed_out or run.truncated:
                failures += 1
                continue
            blamed = parse_blame_lines(run.stdout)

            def author(email: str) -> str:
                key = identity_hash(email)
                if key not in ordinal_of:
                    extra.setdefault(key, f"author-x{len(extra) + 1:04d}")
                    return extra[key]
                return ordinal_of[key]

            line_authors: dict[str, int] = defaultdict(int)
            functions: dict[str, dict[str, Any]] = {}
            for number, (commit, email) in enumerate(blamed, 1):
                who = author(email)
                line_authors[who] += 1
                span = innermost_function(spans.get(path, []), number) if path not in unreliable else None
                if span is None:
                    continue
                key = f"{path}#{span['start_line']}-{span['end_line']}:{span['type']}"
                item = functions.setdefault(key, {**span, "key": key, "commits": defaultdict(int),
                                                  "line_authors": defaultdict(int)})
                item["commits"][commit] += 1
                item["line_authors"][who] += 1
            files[path] = {"line_count": len(blamed), "line_authors": dict(sorted(line_authors.items())),
                           "function_mapping": "unreliable" if path in unreliable else "surviving-line",
                           "unreliable_reason": unreliable.get(path),
                           "functions": [{**value, "commits": dict(sorted(value["commits"].items())),
                                          "line_authors": dict(sorted(value["line_authors"].items()))}
                                         for _, value in sorted(functions.items())]}
        if failures:
            gaps.append("line_attribution_execution_failed")
        document = {"schema": "appsec-review/change-context-attribution/1", "method": ATTRIBUTION_IDENTITY,
                    "files": files, "unreliable": dict(sorted(unreliable.items())),
                    "unmapped_identities": dict(sorted(extra.items()))}
        return {"artifact": _write(unit, "attribution.json", document), "attributed_file_count": len(files),
                "function_count": sum(len(value["functions"]) for value in files.values()),
                "candidate_count": len(candidates), "gaps": sorted(set(gaps)), "terminal_status": _status(gaps)}

    def fix_on_fix(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = history(unit)
        if not loaded.get("available") or loaded.get("classification") is None:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "status": "unavailable", "reason": "no_bound_history"}
        limit = settings.repeated_repairs.fix_on_fix_max_checks
        if limit == 0:
            return {"terminal_status": "SKIPPED_POLICY", "gaps": ["fix_on_fix_disabled"], "status": "unavailable"}
        run_root = unit.job.run_root
        changes = _read(run_root, loaded["changes"])["changes"]
        classes = _read(run_root, loaded["classification"])["classes"]
        eligible = loaded["eligible"]
        fixes = {change_id for change_id, value in classes.items() if value.get("fix")}
        candidates = []
        for change in changes:
            if change["change_id"] not in fixes or change["bulk"] or not change["parents"]:
                continue
            for entry in change["files"]:
                if entry.get("current_path") in eligible and int(entry["deleted"]) > 0 and not entry["binary"]:
                    candidates.append((int(change["position"]), entry["current_path"], change, entry))
        candidates.sort(key=lambda item: (item[0], item[1]))
        gaps = ["fix_on_fix_bound_reached"] if len(candidates) > limit else []
        events: list[dict[str, Any]] = []
        unclassified = failures = 0
        git = runner(unit) if candidates[:limit] else None
        for index, (_, current, change, entry) in enumerate(candidates[:limit]):
            assert git is not None
            parent, commit = str(change["parents"][0]), str(change["change_id"])
            before = entry.get("renamed_from") or entry["path"]
            paths = (before, entry["path"]) if before != entry["path"] else (entry["path"],)
            diff = git.run(f"fof-diff-{index:05d}", ("diff", "-U0", "--no-ext-diff", "--no-textconv", "--no-color",
                                                     "-M", parent, commit, "--", *paths))
            if diff.exit_code != 0 or diff.timed_out or diff.truncated:
                failures += 1
                continue
            hunks = parse_old_hunks(diff.stdout)[:200]
            if not hunks:
                continue
            ranges = tuple(item for start, count in hunks for item in ("-L", f"{start},+{count}"))
            blame = git.run(f"fof-blame-{index:05d}", ("blame", "--porcelain", "-w", "--no-progress", *ranges,
                                                       parent, "--", before))
            if blame.exit_code != 0 or blame.timed_out or blame.truncated:
                failures += 1
                continue
            prior: dict[str, int] = defaultdict(int)
            for origin in parse_blame_commits(blame.stdout):
                if origin in fixes and origin != commit:
                    prior[origin] += 1
                elif origin not in classes:
                    unclassified += 1
            for origin, count in sorted(prior.items()):
                events.append({"fix_change": commit, "prior_fix_change": origin, "path": current, "line_count": count,
                               "basis": "exact_line_blame_at_parent"})
        if failures:
            gaps.append("fix_on_fix_execution_failed")
        document = {"schema": "appsec-review/change-context-fix-on-fix/1", "events": events,
                    "checked": min(len(candidates), limit), "candidate_count": len(candidates),
                    "prior_lines_outside_window": unclassified}
        return {"artifact": _write(unit, "fix-on-fix.json", document), "event_count": len(events),
                "status": "partial" if gaps else "available", "gaps": gaps, "terminal_status": _status(gaps)}

    def change_signals(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = history(unit)
        if not loaded.get("available"):
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "change_count": 0}
        run_root = unit.job.run_root
        changes_doc = _read(run_root, loaded["changes"])
        classes = _read(run_root, loaded["classification"])["classes"] if loaded.get("classification") else {}
        sources = _read(run_root, unit.output("load.external_sources")["artifact"])
        zone = None
        if sources["sources"]["schedule"]["status"] == "complete":
            zone = ZoneInfo(settings.schedule.time_zone)
        roots = history_signals.component_roots(loaded["components"])
        records, gaps = change_metrics.change_records(
            changes_doc["changes"], classes, reviews=sources["reviews"], deployments=sources["deployments"],
            walked=list(changes_doc["walked_commits"]), zone=zone, roots=roots, settings=settings)
        missing = sum(1 for value in records.values() if value["review"]["status"] == "missing")
        if sources["reviews"] is not None and missing:
            gaps.append("review_records_missing_for_changes")
        document = {"schema": "appsec-review/change-context-changes/1", "rules": change_metrics.RULES_IDENTITY,
                    "snapshot_commit": loaded["snapshot_commit"], "time_zone": settings.schedule.time_zone or None,
                    "changes": records}
        return {"artifact": _write(unit, "change-records.json", document), "change_count": len(records),
                "flag_counts": {
                    "sprawling": sum(1 for value in records.values() if value["sprawl"]["sprawling"]),
                    "off_hours": sum(1 for value in records.values() if value["schedule"].get("off_hours")),
                    "pre_deployment": sum(1 for value in records.values() if value["deployment"].get("pre_deployment")),
                    "unapproved_mainline": sum(1 for value in records.values() if value["review"].get("unapproved_mainline")),
                    "untested_production": sum(1 for value in records.values() if value["tests"].get("untested_production")),
                }, "gaps": sorted(set(gaps)), "terminal_status": _status(gaps)}

    def unit_signals(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = history(unit)
        produced = unit.output("analyze.change_signals")
        if "artifact" not in produced:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        run_root = unit.job.run_root
        records = _read(run_root, produced["artifact"])["changes"]
        changes = _read(run_root, loaded["changes"])["changes"]
        sources = _read(run_root, unit.output("load.external_sources")["artifact"])
        lifetime = _read(run_root, loaded["lifetime"])
        organization = sources["organization"]
        identities = lifetime["identities"]
        eligible = loaded["eligible"]
        roots = history_signals.component_roots(loaded["components"])
        classification_status = "partial" if loaded["classification_gaps"] else "available"
        owner_status = "partial" if lifetime["gaps"] else "available"
        fof_output = unit.output("attribute.fix_on_fix")
        fof_status = fof_output.get("status", "unavailable")
        fof_events = _read(run_root, fof_output["artifact"])["events"] if "artifact" in fof_output else []
        fof_by_file: dict[str, int] = defaultdict(int)
        fof_by_component: dict[str, int] = defaultdict(int)
        for event in fof_events:
            fof_by_file[event["path"]] += 1
            component = change_metrics.component_of(event["path"], roots)
            if component is not None:
                fof_by_component[component] += 1
        by_file: dict[str, list[str]] = defaultdict(list)
        by_component: dict[str, list[str]] = defaultdict(list)
        for change in changes:
            for entry in change["files"]:
                path = entry.get("current_path")
                if path in eligible:
                    by_file[path].append(change["change_id"])
                    component = change_metrics.component_of(path, roots)
                    if component is not None:
                        by_component[component].append(change["change_id"])
        bus = settings.ownership.bus_factor_share
        files, components, functions = {}, {}, {}
        for path in sorted(by_file):
            owner = change_metrics.ownership(lifetime["files"].get(path, {}), bus)
            value = change_metrics.aggregate(
                by_file[path], records, fix_events=fof_by_file.get(path, 0), fix_on_fix_status=fof_status,
                owner=owner, owner_status=owner_status, organization=organization, identity_of=identities,
                classification_status=classification_status, settings=settings)
            files[path] = {"scope": "file", "key": path, "path": path, "file_sha256": eligible[path]["sha256"],
                           "binding": "exact" if eligible[path]["exact"] else "divergent",
                           "component_id": change_metrics.component_of(path, roots), **value}
        for component_id in sorted(by_component):
            owner = change_metrics.ownership(lifetime["components"].get(component_id, {}), bus)
            value = change_metrics.aggregate(
                by_component[component_id], records, fix_events=fof_by_component.get(component_id, 0),
                fix_on_fix_status=fof_status, owner=owner, owner_status=owner_status, organization=organization,
                identity_of=identities, classification_status=classification_status, settings=settings)
            components[component_id] = {"scope": "component", "key": component_id, "component_id": component_id, **value}
        attribution_output = unit.output("attribute.line_attribution")
        if "artifact" in attribution_output:
            attribution = _read(run_root, attribution_output["artifact"])
            for path, value in sorted(attribution["files"].items()):
                for function in value["functions"]:
                    attributed = [commit for commit in function["commits"] if commit in records]
                    if not attributed:
                        continue
                    owner = change_metrics.ownership(function["line_authors"], bus)
                    aggregated = change_metrics.aggregate(
                        attributed, records, fix_events=None, fix_on_fix_status="unavailable", owner=owner,
                        owner_status="available", organization=organization, identity_of=identities,
                        classification_status=classification_status, settings=settings)
                    aggregated["details"]["ownership"]["basis"] = "surviving_line_authorship"
                    functions[function["key"]] = {
                        "scope": "function", "key": function["key"], "path": path,
                        "file_sha256": eligible[path]["sha256"],
                        "component_id": change_metrics.component_of(path, roots),
                        "function": {key: function[key] for key in ("name", "type", "start_line", "end_line", "identity")},
                        "location": function["location"], "attribution": "surviving-line", **aggregated}
            for item in files.values():
                blamed = attribution["files"].get(item["path"])
                if blamed is not None:
                    item["details"]["ownership"]["surviving_line_ownership"] = change_metrics.ownership(
                        blamed["line_authors"], bus)
        history_files = (_read(run_root, loaded["history_signals"]) if loaded.get("history_signals") else {})
        for key, item in files.items():
            attention = history_files.get("files", {}).get(key, {}).get("attention")
            item["history_hotspot"] = attention and {"rank": attention["rank"], "score": attention["score"]}
        for key, item in components.items():
            attention = history_files.get("components", {}).get(key, {}).get("attention")
            item["history_hotspot"] = attention and {"rank": attention["rank"], "score": attention["score"]}
        document = {"schema": "appsec-review/change-context-units/1", "files": files, "functions": functions,
                    "components": components}
        return {"artifact": _write(unit, "units.json", document), "file_count": len(files),
                "function_count": len(functions), "component_count": len(components),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def rank(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        produced = unit.output("analyze.unit_signals")
        if "artifact" not in produced:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        document = _read(unit.job.run_root, produced["artifact"])
        rankings = {}
        for scope in ("files", "functions", "components"):
            ranked = change_metrics.rank(document[scope], settings.priority_weights)
            for item in ranked:
                document[scope][item["key"]]["priority"] = {key: item[key] for key in
                                                            ("rank", "score", "coverage", "normalized", "missing_signals")}
            rankings[scope] = [item["key"] for item in ranked]
        result = {"schema": "appsec-review/change-context-signals/1", "priority": change_metrics.PRIORITY_IDENTITY,
                  "rules": change_metrics.RULES_IDENTITY, "weights": dict(settings.priority_weights),
                  "authority": AUTHORITY, **document, "rankings": rankings}
        return {"artifact": _write(unit, "signals.json", result),
                "ranked": {scope: len(value) for scope, value in rankings.items()}, "gaps": [], "terminal_status": "SUCCEEDED"}

    def all_gaps(unit: UnitContext) -> list[str]:
        gaps: list[str] = []
        for unit_id in ("load.accepted_history", "load.external_sources", "attribute.line_attribution",
                        "attribute.fix_on_fix", "analyze.change_signals"):
            gaps.extend(unit.output(unit_id).get("gaps", ()))
        if not history(unit).get("available"):
            gaps.append(f"git_history_unavailable:{history(unit).get('reason')}")
        return sorted(set(gaps))

    def coverage_rows(unit: UnitContext) -> list[tuple[str, str, str | None]]:
        loaded = history(unit)
        sources = unit.output("load.external_sources")["sources"]
        available = bool(loaded.get("available"))
        rows = [("git-change-context",
                 "unavailable" if not available else "partial" if loaded.get("gaps") or loaded.get("classification_gaps") else "complete",
                 "; ".join([*loaded.get("gaps", ()), *loaded.get("classification_gaps", ())]) or
                 (None if available else str(loaded.get("reason"))))]
        for name, area in (("review", "review-records"), ("deployment", "deployment-events"),
                           ("schedule", "off-hours-schedule"), ("test_association", "test-association"),
                           ("organization", "organization-membership")):
            value = sources[name]
            status = value["status"] if available else "unavailable"
            rows.append((area, status, "; ".join(value["gaps"]) or (None if available else "no_git_history")))
        attribution = unit.output("attribute.line_attribution")
        rows.append(("function-attribution",
                     "unavailable" if "artifact" not in attribution or not attribution.get("function_count") else
                     "partial" if attribution["gaps"] else "complete",
                     "; ".join(attribution.get("gaps", ())) or attribution.get("reason") or
                     (None if attribution.get("function_count") else "no_functions_attributed")))
        fof = unit.output("attribute.fix_on_fix")
        rows.append(("fix-on-fix", "unavailable" if "artifact" not in fof else "partial" if fof["gaps"] else "complete",
                     "; ".join(fof.get("gaps", ())) or fof.get("reason")))
        return rows

    def index(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        snapshot = unit.job.source_fingerprint
        run_root = unit.job.run_root
        loaded = history(unit)
        ranked = unit.output("analyze.rank")
        signals_doc = _read(run_root, ranked["artifact"]) if "artifact" in ranked else None
        records = (_read(run_root, unit.output("analyze.change_signals")["artifact"])["changes"]
                   if "artifact" in unit.output("analyze.change_signals") else {})
        sources_doc = _read(run_root, unit.output("load.external_sources")["artifact"])
        gaps = all_gaps(unit)
        producer_artifacts = [value["artifact"] for value in (ranked, unit.output("analyze.change_signals"),
                                                              unit.output("load.external_sources")) if "artifact" in value]
        fingerprint = index_fingerprint(
            name="history", target_snapshot=snapshot, producer_artifacts=producer_artifacts,
            tool_identity={"history_handoff": loaded["history_handoff_sha256"], "rules": change_metrics.RULES_IDENTITY,
                           "priority": change_metrics.PRIORITY_IDENTITY, "attribution": ATTRIBUTION_IDENTITY,
                           "config": hashlib.sha256(canonical_json(dict(unit.job.config.settings))).hexdigest()},
            parser_identity="change-context-records/1", normalizer_identity=change_metrics.TEST_ASSOCIATION_IDENTITY,
            mapping_identity="git-blob-binding+tree-sitter-span/1")
        path = run_root / "data" / "indices" / "history" / SHARD_ID / f"{fingerprint}.sqlite"
        eligible = loaded.get("eligible", {})
        if not path.exists():
            builder = IndexBuilder(path, name="history", fingerprint=fingerprint, target_snapshot=snapshot, shard_id=SHARD_ID)
            change_ids: dict[str, str] = {}
            review_ids: dict[str, str] = {}
            deployment_ids: dict[str, str] = {}
            deployments = {item["deployment_id"]: item for item in (sources_doc.get("deployments") or {}).get("events", ())}

            def change_entity(change_id: str) -> str:
                if change_id in change_ids:
                    return change_ids[change_id]
                record = records[change_id]
                identity = LogicalIdentity.derive(EntityKind.CHANGE, snapshot, {"vcs": "git", "change_id": change_id})
                change_ids[change_id] = identity.value
                flags = [name for name, value in (
                    ("sprawling", record["sprawl"]["sprawling"]), ("off_hours", record["schedule"].get("off_hours")),
                    ("pre_deployment", record["deployment"].get("pre_deployment")),
                    ("unapproved_mainline", record["review"].get("unapproved_mainline")),
                    ("stale_approval", record["review"].get("stale_approval")),
                    ("fast_review", record["review"].get("fast_approval") or record["review"].get("fast_merge")),
                    ("untested_production", record["tests"].get("untested_production"))) if value]
                payload = {**record, "producer": PRODUCER, "rules": change_metrics.RULES_IDENTITY,
                           "snapshot_commit": loaded["snapshot_commit"], "flags": flags}
                builder.add_entity(EntityRecord(identity, change_id, change_id[:12],
                                                " ".join(["change context change", change_id, *flags]), payload))
                review = (record["facts"].get("review_record") or {})
                if review.get("pull_request"):
                    number = int(review["pull_request"])
                    if number not in review_ids:
                        review_identity = LogicalIdentity.derive(EntityKind.REVIEW_UNIT, snapshot,
                                                                 {"system": settings.review.source, "pull_request": number})
                        review_ids[number] = review_identity.value
                        builder.add_entity(EntityRecord(review_identity, f"pr:{number}", f"pull request {number}",
                                                        f"review unit pull request {number}",
                                                        {**review, "producer": PRODUCER, "source": settings.review.source}))
                    builder.add_relation(RelationRecord(RelationKind.SUPPORTS, review_ids[number], identity.value, True, 1.0))
                deployment_id = record["deployment"].get("deployment_id")
                if deployment_id in deployments:
                    if deployment_id not in deployment_ids:
                        deployment_identity = LogicalIdentity.derive(EntityKind.DEPLOYMENT_EVENT, snapshot,
                                                                     {"deployment_id": deployment_id})
                        deployment_ids[deployment_id] = deployment_identity.value
                        builder.add_entity(EntityRecord(deployment_identity, deployment_id, deployment_id,
                                                        f"deployment event {deployments[deployment_id]['environment']}",
                                                        {**deployments[deployment_id], "producer": PRODUCER}))
                    builder.add_relation(RelationRecord(RelationKind.SUPPORTS, deployment_ids[deployment_id],
                                                        identity.value, True, 1.0, payload={"relation": "shipped"}))
                return identity.value

            unit_ids: dict[tuple[str, str], str] = {}
            limits = {"files": settings.ranking_top_files, "functions": settings.ranking_top_functions,
                      "components": settings.ranking_top_components}
            for scope, limit in limits.items():
                for key in (signals_doc or {}).get("rankings", {}).get(scope, [])[:limit]:
                    value = signals_doc[scope][key]
                    location = None
                    if scope == "files":
                        facts = eligible[key]
                        location = SourceLocation(
                            target_snapshot=snapshot, path=key, file_sha256=facts["sha256"], start_byte=0,
                            end_byte=int(facts["size_bytes"]), start_line=1, end_line=int(facts["span_lines"]),
                            start_column=1, end_column=1, producer_location={"vcs": "git", "scope": "file"},
                            mapping_method="git-blob-binding" if facts["exact"] else "git-path-binding",
                            confidence=1.0 if facts["exact"] else 0.5, ambiguous=not facts["exact"])
                    elif scope == "functions":
                        span = value["location"]
                        location = SourceLocation(
                            target_snapshot=snapshot, path=value["path"], file_sha256=value["file_sha256"],
                            start_byte=int(span["start_byte"]), end_byte=int(span["end_byte"]),
                            start_line=int(span["start_line"]), end_line=int(span["end_line"]),
                            start_column=int(span["start_column"]), end_column=int(span["end_column"]),
                            producer_location={"tree_sitter_node": value["function"]["identity"],
                                               "attribution": "surviving-line"},
                            mapping_method="tree-sitter-span+git-blame", confidence=1.0)
                    native = {"files": {"scope": "file", "path": key}, "components": {"scope": "component", "component_id": key},
                              "functions": {"scope": "function", "path": value.get("path"), "file_sha256": value.get("file_sha256"),
                                            "start_line": (value.get("function") or {}).get("start_line"),
                                            "end_line": (value.get("function") or {}).get("end_line"),
                                            "type": (value.get("function") or {}).get("type")}}[scope]
                    identity = LogicalIdentity.derive(EntityKind.CHANGE_CONTEXT_SIGNAL, snapshot, native)
                    unit_ids[(scope, key)] = identity.value
                    flags = sorted(name for name, metric in value["metrics"].items() if metric)
                    name = (value.get("function") or {}).get("name") or key
                    payload = {key_: value[key_] for key_ in value if key_ != "location"}
                    payload.update({"producer": PRODUCER, "rules": change_metrics.RULES_IDENTITY,
                                    "priority_identity": change_metrics.PRIORITY_IDENTITY, "authority": AUTHORITY,
                                    "snapshot_commit": loaded["snapshot_commit"], "rank": value["priority"]["rank"],
                                    "score": value["priority"]["score"]})
                    text = (f"change context {value['scope']} {name} rank {value['priority']['rank']} "
                            f"score {value['priority']['score']} " + " ".join(flags))
                    builder.add_entity(EntityRecord(identity, f"{value['scope']}:{key}", name, text, payload, location))
                    for change_id in value["supporting_changes"]:
                        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                            change_entity(change_id), True, 1.0))
            for (scope, key), identity in unit_ids.items():
                value = signals_doc[scope][key]
                if scope == "files" and ("components", value.get("component_id")) in unit_ids:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, unit_ids[("components", value["component_id"])],
                                                        identity, True, 1.0))
                if scope == "functions" and ("files", value["path"]) in unit_ids:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, unit_ids[("files", value["path"])],
                                                        identity, True, 1.0))
            for area, status, gap in coverage_rows(unit):
                builder.add_coverage(area, status, gap)
            builder.build()
        identity = IndexIdentity("history", "appsec-review/retrieval-index/2", file_sha256(path), fingerprint,
                                 _rel(run_root, path), {"job": PRODUCER, "vcs": "git"}, tuple(gaps), SHARD_ID)
        upstream_path, upstream_sha = resolve_accepted_manifest(run_root)
        upstream, _ = load_verified_manifest(run_root, upstream_path, upstream_sha)
        base = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in upstream["indexes"]
                if item.get("producer", {}).get("job") != PRODUCER]
        manifest_path = run_root / "data" / "indices" / "manifests" / f"change-context-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=snapshot,
                       target_root=(unit.job.target_root or Path()).resolve(), indexes=[*base, identity],
                       upstream_manifests=({"path": _rel(run_root, upstream_path), "sha256": upstream_sha},))
        load_verified_manifest(run_root, manifest_path, file_sha256(manifest_path))
        return {"index_identity": asdict(identity), "manifest": _artifact(run_root, manifest_path),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        loaded = history(unit)
        ranked = unit.output("analyze.rank")
        signals_doc = _read(unit.job.run_root, ranked["artifact"]) if "artifact" in ranked else {}
        gaps = all_gaps(unit)
        limits = {"files": settings.ranking_top_files, "functions": settings.ranking_top_functions,
                  "components": settings.ranking_top_components}
        top = {scope: [{"key": key, "rank": signals_doc[scope][key]["priority"]["rank"],
                        "score": signals_doc[scope][key]["priority"]["score"],
                        "coverage": signals_doc[scope][key]["priority"]["coverage"],
                        "path": signals_doc[scope][key].get("path"),
                        "component_id": signals_doc[scope][key].get("component_id"),
                        "file_sha256": signals_doc[scope][key].get("file_sha256")}
                       for key in signals_doc.get("rankings", {}).get(scope, [])[:limit]]
               for scope, limit in limits.items()}
        document = {
            "schema": SCHEMA, "target_snapshot": unit.job.source_fingerprint, "authority": AUTHORITY,
            "history_handoff_sha256": loaded["history_handoff_sha256"], "history_identity": loaded["history_identity"],
            "snapshot_commit": loaded.get("snapshot_commit"),
            "sources": unit.output("load.external_sources")["sources"],
            "raw_exports": unit.output("load.external_sources")["raw_exports"],
            "rules": {"change": change_metrics.RULES_IDENTITY, "tests": change_metrics.TEST_ASSOCIATION_IDENTITY,
                      "attribution": ATTRIBUTION_IDENTITY, "priority": change_metrics.PRIORITY_IDENTITY},
            "priority": {"weights": dict(settings.priority_weights), "top": top, "signals": ranked.get("artifact")},
            "coverage": [{"area": area, "status": status, "gap": gap} for area, status, gap in coverage_rows(unit)],
            "gaps": gaps, "index_manifest": unit.output("publish.index_change_context")["manifest"],
        }
        artifact = _write(unit, "change-context.json", document)
        unit.job.events.write("CHANGE_CONTEXT_COMPLETED", ranked_file_count=len(top["files"]),
                              ranked_function_count=len(top["functions"]),
                              ranked_component_count=len(top["components"]), gap_count=len(gaps))
        terminal = "SKIPPED_NA" if not loaded.get("available") else _status(gaps)
        output = {"schema": SCHEMA, "artifact": artifact, "index_manifest": document["index_manifest"],
                  "item_count": sum(len(value) for value in top.values()), "gaps": gaps, "terminal_status": terminal}
        retriable = [{"disposition": "GAP", "reason": gap} for gap in gaps if gap.endswith("_execution_failed")]
        if retriable:
            output["dispositions"] = retriable
        return output

    units = (
        Unit("load.accepted_history", load_history),
        Unit("load.external_sources", external, ("load.accepted_history",)),
        Unit("attribute.line_attribution", attribute_lines, ("load.accepted_history",)),
        Unit("attribute.fix_on_fix", fix_on_fix, ("load.accepted_history",)),
        Unit("analyze.change_signals", change_signals, ("load.external_sources",)),
        Unit("analyze.unit_signals", unit_signals, ("analyze.change_signals", "attribute.line_attribution",
                                                     "attribute.fix_on_fix")),
        Unit("analyze.rank", rank, ("analyze.unit_signals",)),
        Unit("publish.index_change_context", index, ("analyze.rank",)),
        Unit("publish.publish_handoff", publish, ("publish.index_change_context",)),
    )
    sources = sorted(Path(__file__).parent.glob("*.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sources) +
                                    (b"custom-executor" if executor_factory else b"container-only")).hexdigest()
    return Job(PRODUCER, "change_context_analysis", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units)
