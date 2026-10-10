from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from . import signals as history_signals
from .filters import FILTER_IDENTITY, FORMATTING_IDENTITY
from .git import ARGV_VERSION, TOOL_ID, GitRunner, parse_blame, parse_log, parse_messages, parse_tree
from .github import GitHubClient, GitHubSettings, Transport, enrich
from .hotspots import SII_IDENTITY, TRANSFORMS, score as sii_score
from .lines import FIX_ON_FIX_IDENTITY, LINE_HISTORY_IDENTITY, FileLines, attribute, fix_on_fix, parse_file_history
from .settings import HistorySettings, parse_settings
from .sources import GitSource, blob_id, history_identity, resolve_git_source
from .symbols import COMPLEXITY_IDENTITY, SYMBOL_IDENTITY, extract, tree_sitter_language
from .window import WINDOW_IDENTITY


SCHEMA = "appsec-review/source-history-analysis/2"
HOTSPOT_SCHEMA = "appsec-review/history-hotspots/1"
HOTSPOT_ENTRY_SCHEMA = "appsec-review/history-hotspot/1"
TREE_SITTER_TOOL = "tool-tree-sitter"
AUTHORITY = "history signals and hotspot scores prioritize review; they are never vulnerability evidence"
REVISION_SEMANTICS = ("change_count counts distinct first-parent commits on the mainline; a merged pull request "
                      "counts once as its merge commit, and individual commits on merged branches are not counted")
# Signals that need data this lane does not acquire.  They are reported as gaps, never inferred.
UNAVAILABLE_SIGNALS = {
    "pull_request_timing": "pr_timing_not_acquired",
    "deployment_timing": "deployment_timing_not_acquired",
}
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "resolve_sources": ("resolve_history_source", "bind_snapshot"),
    "acquire": ("git_history", "normalize_changes", "github_enrichment"),
    "analyze": ("classify_changes", "compute_signals", "blame_age", "co_change", "line_history", "symbol_spans",
                "fix_on_fix", "symbol_signals", "rank"),
    "publish": ("index_history", "publish_handoff"),
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


def _read(run_root: Path, identity: Mapping[str, Any]) -> Any:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity.get("sha256"):
        raise ValueError("source history artifact identity mismatch")
    return json.loads(path.read_text(encoding="utf-8"))


def _read_bytes(run_root: Path, identity: Mapping[str, Any]) -> bytes:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != identity.get("sha256"):
        raise ValueError("source history raw artifact identity mismatch")
    return path.read_bytes()


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[Mapping[str, Any], str]:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file():
        raise ValueError(f"accepted {job_id} handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def _load_inputs(run_root: Path) -> dict[str, Any]:
    intake_handoff, _ = _accepted_handoff(run_root, "job_review_intake")
    catalog_handoff, catalog_sha = _accepted_handoff(run_root, "job_target_catalog")
    intake = _read(run_root, intake_handoff["outputs"]["publish_intake.publish_handoff"]["artifact"])
    catalog = _read(run_root, catalog_handoff["outputs"]["publish_catalog.publish_handoff"]["artifact"])
    if intake.get("schema") != "appsec-review/review-intake/1" or catalog.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("source history inputs use unsupported schemas")
    if catalog.get("source_fingerprint") != intake.get("fingerprint", {}).get("sha256"):
        raise ValueError("target snapshot and catalog identities disagree")
    artifacts = catalog["artifacts"]
    partition = _read(run_root, artifacts["repository_discovery.partition_repository"])
    components = _read(run_root, artifacts["component_discovery.catalog_components"])
    return {"source_fingerprint": catalog["source_fingerprint"], "catalog_handoff_sha256": catalog_sha,
            "files": [{**{key: item[key] for key in ("path", "sha256", "size_bytes")}, "language": item.get("language")}
                      for item in partition.get("files", ())],
            "components": [{"component_id": item["component_id"], "root": item.get("root") or "."}
                           for item in components.get("components", ())]}


def load_accepted_history(run_root: Path) -> Mapping[str, Any] | None:
    """Return the accepted history document, or ``None`` when the job has not run in this graph."""
    if not (Path(run_root) / "data" / "jobs" / "job_source_history_analysis" / "latest.json").is_file():
        return None
    handoff, handoff_sha = _accepted_handoff(Path(run_root), "job_source_history_analysis")
    document = _read(Path(run_root), handoff["outputs"]["publish.publish_handoff"]["artifact"])
    if document.get("schema") != SCHEMA:
        raise ValueError("accepted source history schema is unsupported")
    return {**document, "handoff_sha256": handoff_sha}


def load_accepted_hotspots(run_root: Path) -> Mapping[str, Any] | None:
    """Return the accepted, hash-verified hotspot index, or ``None`` when history is not in this graph.

    Consumers read this bounded index (or query ``kind="hotspot"`` in the ``history`` retrieval
    index) instead of rescanning Git or the target tree.
    """
    history = load_accepted_history(run_root)
    if history is None:
        return None
    identity = history.get("hotspots", {}).get("artifact")
    if identity is None:
        return {"schema": HOTSPOT_SCHEMA, "status": "unavailable", "reason": history["sources"]["git"]["reason"],
                "entries": [], "handoff_sha256": history["handoff_sha256"]}
    document = _read(Path(run_root), identity)
    if document.get("schema") != HOTSPOT_SCHEMA or document.get("target_snapshot") != history["target_snapshot"]:
        raise ValueError("accepted hotspot index identity is unsupported or stale")
    return {**document, "handoff_sha256": history["handoff_sha256"]}


def _settings(context) -> HistorySettings:
    return parse_settings(context.config.settings)


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("source history topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"source history task order mismatch: {step}")
    _settings(context)


def _status(gaps: list[str]) -> str:
    return "PARTIAL" if gaps else "SUCCEEDED"


def _ranking_candidates(files: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Rank-eligible files, most churn first; the order every bounded per-file step uses."""
    return sorted((path for path, value in files.items() if value["rank_eligibility"] == "eligible"),
                  key=lambda path: (-int(files[path]["churn_lines"]), path))


def _reason(status: str) -> str:
    return status.split(":", 1)[1] if ":" in status else status


def build_job(*, executor_factory: ExecutorFactory | None = None,
              github_transport: Transport | None = None) -> Job:
    def factory(unit: UnitContext) -> ContainerExecutor:
        return executor_factory(unit) if executor_factory is not None else ContainerExecutor(
            load_catalog(unit.job.repository_root), unit.job.run_root)

    def source_of(unit: UnitContext) -> GitSource:
        value = dict(unit.output("resolve_sources.resolve_history_source")["git"])
        value["shallow"] = tuple(value["shallow"])
        value["observations"] = tuple(value["observations"])
        return GitSource(**value)

    def git_ready(unit: UnitContext) -> bool:
        binding = unit.output("resolve_sources.bind_snapshot")
        return binding["terminal_status"] not in SKIPPED and bool(binding.get("eligible"))

    def runner(unit: UnitContext) -> GitRunner:
        return GitRunner(factory(unit), unit.job.target_root or Path(), unit.unit_root / "scratch", source_of(unit))

    def eligible_of(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
        return unit.output("resolve_sources.bind_snapshot")["eligible"]

    def resolve(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        inputs = _load_inputs(unit.job.run_root)
        if inputs["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted catalog")
        target = unit.job.target_root
        if not settings.git_enabled:
            git = GitSource("SKIPPED_POLICY", "git_history_disabled")
        elif target is None:
            git = GitSource("SKIPPED_NA", "no_target")
        else:
            try:
                git = resolve_git_source(target)
            except (OSError, ValueError) as exc:
                git = GitSource("GAP", f"git_metadata_unreadable:{type(exc).__name__}")
        github = ("SKIPPED_POLICY", "github_enrichment_disabled") if not settings.github["enabled"] else (
            ("PENDING", "awaiting_git_history") if git.decision == "SUCCEEDED" else ("SKIPPED_NA", "no_git_history"))
        unit.job.events.write("SOURCE_HISTORY_RESOLVED", git_decision=git.decision, git_reason=git.reason,
                              github_decision=github[0])
        gaps = [git.reason] if git.decision == "GAP" else []
        return {"identity": history_identity(target), "git": git.as_dict(),
                "github": {"decision": github[0], "reason": github[1]}, "inputs": inputs,
                "gaps": gaps, "terminal_status": git.decision if git.decision in SKIPPED else _status(gaps)}

    def bind(unit: UnitContext) -> Mapping[str, Any]:
        resolved = unit.output("resolve_sources.resolve_history_source")
        source = source_of(unit)
        if source.decision != "SUCCEEDED":
            terminal = source.decision if source.decision in SKIPPED else "PARTIAL"
            return {"binding": "not_applicable", "eligible": {}, "gaps": list(resolved["gaps"]),
                    "terminal_status": terminal}
        git = runner(unit)
        tree_run = git.tree()
        if tree_run.exit_code != 0 or tree_run.timed_out:
            return {"binding": "unavailable", "eligible": {}, "gaps": ["git_execution_failed:ls-tree"],
                    "executions": [tree_run.execution], "terminal_status": "PARTIAL",
                    "dispositions": [{"disposition": "GAP", "reason": "git_execution_failed"}]}
        tree = parse_tree(tree_run.stdout)
        target = (unit.job.target_root or Path()).resolve()
        eligible: dict[str, dict[str, Any]] = {}
        divergent: list[str] = []
        untracked: list[str] = []
        matched = 0
        for item in resolved["inputs"]["files"]:
            path = str(item["path"])
            data = (target / path).read_bytes()
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError(f"accepted target bytes changed: {path}")
            entry = tree.get(path)
            if entry is None or entry["type"] != "blob":
                untracked.append(path)
                continue
            exact = blob_id(data, source.object_format) == entry["oid"]
            matched += exact
            if not exact:
                divergent.append(path)
            eligible[path] = {"sha256": item["sha256"], "size_bytes": len(data), "exact": exact,
                              "blob_id": entry["oid"], "language": item.get("language"),
                              "line_count": sum(1 for line in data.splitlines() if line.strip()),
                              "span_lines": max(1, data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1))}
        gaps: list[str] = []
        if tree_run.truncated:
            gaps.append("tree_listing_truncated")
        submodules = sorted(path for path, entry in tree.items() if entry["type"] == "commit")
        if submodules:
            gaps.append("submodule_history_not_followed")
        if resolved["inputs"]["files"] and not matched:
            binding = "unrelated"
            gaps.append("history_not_of_snapshot")
            eligible = {}
        else:
            binding = "exact" if not divergent and not untracked else "partial"
        if divergent:
            gaps.append("working_tree_divergent")
        if untracked:
            gaps.append("untracked_path")
        document = {"schema": "appsec-review/source-history-binding/1", "binding": binding,
                    "snapshot_commit": source.snapshot_commit, "object_format": source.object_format,
                    "divergent_paths": divergent, "untracked_paths": untracked, "submodule_paths": submodules,
                    "tree_entry_count": len(tree), "matched_count": matched}
        return {"binding": binding, "eligible": eligible, "artifact": _write(unit, "binding.json", document),
                "gaps": sorted(set(gaps)), "executions": [tree_run.execution],
                "counts": {"divergent_count": len(divergent), "untracked_count": len(untracked),
                           "matched_count": matched, "submodule_count": len(submodules)},
                "terminal_status": _status(gaps)}

    def acquire(unit: UnitContext) -> Mapping[str, Any]:
        if not git_ready(unit):
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "reason": "no_bound_history"}
        settings = _settings(unit.job)
        git = runner(unit)
        count = settings.max_changes + 1
        log_run, message_run = git.log(count), git.messages(count)
        executions = [log_run.execution, message_run.execution]
        failed = [name for name, run in (("log", log_run), ("messages", message_run))
                  if run.exit_code != 0 or run.timed_out or run.output is None]
        if failed:
            return {"terminal_status": "PARTIAL", "gaps": [f"git_execution_failed:{name}" for name in failed],
                    "executions": executions, "dispositions": [{"disposition": "GAP", "reason": "git_execution_failed"}]}
        raw = unit.unit_root / "protected"
        atomic_bytes(raw / "log.bin", log_run.output or b"")
        atomic_bytes(raw / "messages.bin", message_run.output or b"")
        return {"raw_log": _artifact(unit.job.run_root, raw / "log.bin"),
                "raw_messages": _artifact(unit.job.run_root, raw / "messages.bin"),
                "executions": executions, "image_id": log_run.execution["image_id"],
                "argv_version": ARGV_VERSION, "gaps": [], "terminal_status": "SUCCEEDED"}

    def normalize(unit: UnitContext) -> Mapping[str, Any]:
        acquired = unit.output("acquire.git_history")
        if "raw_log" not in acquired:
            return {"terminal_status": acquired["terminal_status"], "gaps": list(acquired["gaps"]), "change_count": 0}
        settings = _settings(unit.job)
        commits = parse_log(_read_bytes(unit.job.run_root, acquired["raw_log"]))
        normalized = history_signals.normalize(
            commits, current_paths=eligible_of(unit), shallow=source_of(unit).shallow,
            window_months=settings.history_window_months, max_changes=settings.max_changes,
            bulk_threshold=settings.bulk_change_file_threshold)
        walked = [str(item["commit"]) for item in commits[:settings.max_changes]]
        document = {"schema": "appsec-review/source-history-changes/2", "normalizer": history_signals.NORMALIZER_IDENTITY,
                    "window": WINDOW_IDENTITY, "anchor_time": normalized["anchor_time"],
                    "window_start": normalized.get("window_start"), "walked_commits": walked,
                    "changes": normalized["changes"]}
        return {"artifact": _write(unit, "changes.json", document), "change_count": len(normalized["changes"]),
                "walked_change_count": normalized["walked_change_count"], "anchor_time": normalized["anchor_time"],
                "window_start": normalized.get("window_start"),
                "author_count": normalized["author_count"], "observations": normalized["observations"],
                "gaps": normalized["gaps"], "terminal_status": _status(normalized["gaps"])}

    def github_enrichment(unit: UnitContext) -> Mapping[str, Any]:
        resolved = unit.output("resolve_sources.resolve_history_source")["github"]
        normalized = unit.output("acquire.normalize_changes")
        if resolved["decision"] in SKIPPED:
            return {"terminal_status": resolved["decision"], "reason": resolved["reason"], "gaps": [], "facts_count": 0}
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "reason": "no_git_history", "gaps": [], "facts_count": 0}
        configured = _settings(unit.job).github
        settings = GitHubSettings(str(configured["api_base"]), str(configured["repository"]),
                                  os.environ.get(str(configured["token_env"])) or None,
                                  int(configured["max_requests"]), int(configured["timeout_seconds"]))
        changes = _read(unit.job.run_root, normalized["artifact"])["changes"]
        result = enrich(GitHubClient(settings, github_transport), str(source_of(unit).snapshot_commit),
                        [str(item["change_id"]) for item in changes])
        document = {"schema": "appsec-review/source-history-github/1", "repository": settings.repository,
                    "api_base": settings.api_base, **result}
        output = {"artifact": _write(unit, "github-enrichment.json", document), "facts_count": len(result["facts"]),
                  "requests": result["requests"], "gaps": list(result["gaps"]),
                  "terminal_status": _status(list(result["gaps"]))}
        if result["retriable"]:
            output["dispositions"] = [{"disposition": "GAP", "reason": "github_enrichment_retriable"}]
        unit.job.events.write("SOURCE_HISTORY_GITHUB_ENRICHED", facts_count=len(result["facts"]),
                              requests=result["requests"], gap_count=len(result["gaps"]))
        return output

    def github_facts(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
        output = unit.output("acquire.github_enrichment")
        return _read(unit.job.run_root, output["artifact"])["facts"] if "artifact" in output else {}

    def classes_of(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
        output = unit.output("analyze.classify_changes")
        return _read(unit.job.run_root, output["artifact"])["classes"] if "artifact" in output else {}

    def classify(unit: UnitContext) -> Mapping[str, Any]:
        normalized = unit.output("acquire.normalize_changes")
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        settings = _settings(unit.job)
        changes = _read(unit.job.run_root, normalized["artifact"])
        messages, gaps = parse_messages(
            _read_bytes(unit.job.run_root, unit.output("acquire.git_history")["raw_messages"]),
            changes["walked_commits"])
        classes = history_signals.classify(
            changes["changes"], messages, github_facts(unit), known_commits=changes["walked_commits"],
            fix_labels=settings.fix_labels, security_labels=settings.security_labels,
            formatting_tolerance=settings.filters.formatting_balance_tolerance)
        counts = {key: sum(1 for value in classes.values() if value.get(key))
                  for key in ("fix", "security_fix", "revert", "formatting")}
        document = {"schema": "appsec-review/source-history-classification/2",
                    "rules": history_signals.RULES_IDENTITY, "formatting_rules": FORMATTING_IDENTITY, "classes": classes}
        return {"artifact": _write(unit, "classification.json", document), "counts": counts,
                "gaps": gaps, "terminal_status": _status(gaps)}

    def compute(unit: UnitContext) -> Mapping[str, Any]:
        normalized = unit.output("acquire.normalize_changes")
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "files": {}, "components": {}}
        settings = _settings(unit.job)
        changes = _read(unit.job.run_root, normalized["artifact"])
        roots = history_signals.component_roots(
            unit.output("resolve_sources.resolve_history_source")["inputs"]["components"])
        values = history_signals.compute_signals(
            changes["changes"], classes_of(unit), github_facts(unit), eligible=eligible_of(unit), roots=roots,
            anchor_time=changes["anchor_time"], window_months=settings.history_window_months,
            half_life_days=settings.recency_half_life_days, minor_author_share=settings.minor_author_share,
            fix_interval_days=settings.fix_on_fix_interval_days, filters=settings.filters)
        excluded: dict[str, int] = {}
        for value in values["files"].values():
            if value["rank_eligibility"] != "eligible":
                excluded[value["rank_eligibility"]] = excluded.get(value["rank_eligibility"], 0) + 1
        return {"artifact": _write(unit, "raw-signals.json", values), "file_count": len(values["files"]),
                "component_count": len(values["components"]), "rank_exclusions": dict(sorted(excluded.items())),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def file_signals(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
        return _read(unit.job.run_root, unit.output("analyze.compute_signals")["artifact"])["files"]

    def blame(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "young_line_share": {}}
        settings = _settings(unit.job)
        files = file_signals(unit)
        eligible = eligible_of(unit)
        candidates = [path for path in _ranking_candidates(files)
                      if eligible[path]["exact"] and eligible[path]["size_bytes"] <= settings.blame_max_file_bytes]
        limit = settings.blame_max_files
        gaps = ["blame_bound_reached"] if len(candidates) > limit else []
        threshold = int(unit.output("acquire.normalize_changes")["anchor_time"]) - settings.young_line_days * history_signals.DAY
        shares: dict[str, float] = {}
        failures = 0
        selected = candidates[:limit]
        git = runner(unit) if selected else None
        for index, path in enumerate(selected):
            assert git is not None
            run = git.blame(index, path)
            if run.exit_code != 0 or run.timed_out or run.truncated:
                failures += 1
                continue
            times = parse_blame(run.stdout)
            if times:
                shares[path] = round(sum(1 for value in times if value >= threshold) / len(times), 6)
        if failures:
            gaps.append("blame_execution_failed")
        return {"young_line_share": dict(sorted(shares.items())), "blamed_file_count": len(shares),
                "candidate_count": len(candidates), "gaps": gaps, "terminal_status": _status(gaps)}

    def coupling(unit: UnitContext) -> Mapping[str, Any]:
        normalized = unit.output("acquire.normalize_changes")
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "partners": {}}
        settings = _settings(unit.job)
        partners = history_signals.co_change(
            _read(unit.job.run_root, normalized["artifact"])["changes"], classes_of(unit),
            eligible=eligible_of(unit),
            roots=history_signals.component_roots(
                unit.output("resolve_sources.resolve_history_source")["inputs"]["components"]),
            top_k=settings.co_change_top_k, min_support=settings.co_change_min_support)
        return {"artifact": _write(unit, "co-change.json", partners), "file_count": len(partners),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def line_history(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        settings = _settings(unit.job)
        eligible = eligible_of(unit)
        statuses: dict[str, str] = {}
        candidates = []
        for path in _ranking_candidates(file_signals(unit)):
            if not eligible[path]["exact"]:
                statuses[path] = "unavailable:working_tree_divergent"
            elif eligible[path]["size_bytes"] > settings.line_history_max_file_bytes:
                statuses[path] = "unavailable:line_history_file_too_large"
            else:
                candidates.append(path)
        for path in candidates[settings.line_history_max_files:]:
            statuses[path] = "unavailable:line_history_bound_reached"
        selected = candidates[:settings.line_history_max_files]
        histories: dict[str, list[dict[str, Any]]] = {}
        git = runner(unit) if selected else None
        failed = False
        for index, path in enumerate(selected):
            assert git is not None
            run = git.file_history(index, path, settings.max_changes)
            if run.exit_code != 0 or run.timed_out:
                statuses[path] = "unavailable:git_execution_failed"
                failed = True
            elif run.truncated:
                statuses[path] = "unavailable:line_history_truncated"
            else:
                try:
                    histories[path] = parse_file_history(run.stdout)
                    statuses[path] = "complete"
                except ValueError:
                    statuses[path] = "unavailable:line_history_unparseable"
        gaps = sorted({f"line_history:{_reason(value)}" if _reason(value) == "git_execution_failed" else _reason(value)
                       for value in statuses.values() if value != "complete"} - {"working_tree_divergent"})
        document = {"schema": "appsec-review/source-history-lines/1", "identity": LINE_HISTORY_IDENTITY,
                    "statuses": dict(sorted(statuses.items())), "files": dict(sorted(histories.items()))}
        output = {"artifact": _write(unit, "line-history.json", document), "file_count": len(histories),
                  "gaps": gaps, "terminal_status": _status(gaps)}
        if failed:
            output["dispositions"] = [{"disposition": "GAP", "reason": "git_execution_failed"}]
        return output

    def symbol_spans(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        settings = _settings(unit.job)
        eligible = eligible_of(unit)
        ranked = _ranking_candidates(file_signals(unit))
        statuses: dict[str, str] = {}
        results: dict[str, dict[str, Any]] = {}
        output: dict[str, Any] = {}

        def finish(gaps: list[str], terminal: str | None = None) -> Mapping[str, Any]:
            document = {"schema": "appsec-review/source-history-symbols/1", "identity": SYMBOL_IDENTITY,
                        "complexity_rules": COMPLEXITY_IDENTITY, "statuses": dict(sorted(statuses.items())),
                        "files": dict(sorted(results.items()))}
            return {**output, "artifact": _write(unit, "symbols.json", document), "file_count": len(results),
                    "gaps": gaps, "terminal_status": terminal or _status(gaps)}

        if not settings.symbols_enabled:
            statuses.update({path: "unavailable:symbol_spans_disabled" for path in ranked})
            return finish(["symbol_spans_disabled"] if ranked else [])
        languages: dict[str, str] = {}
        candidates = []
        for path in ranked:
            language = tree_sitter_language(eligible[path].get("language"), path)
            if not eligible[path]["exact"]:
                statuses[path] = "unavailable:working_tree_divergent"
            elif language is None:
                statuses[path] = "unavailable:symbol_language_unsupported"
            elif eligible[path]["size_bytes"] > settings.symbols_max_file_bytes:
                statuses[path] = "unavailable:symbol_file_too_large"
            else:
                languages[path] = language
                candidates.append(path)
        for path in candidates[settings.symbols_max_files:]:
            statuses[path] = "unavailable:symbol_spans_bound_reached"
        selected = candidates[:settings.symbols_max_files]
        if selected:
            from appsec_review.jobs.job_tree_sitter_ast.job import _grammar_locks
            from appsec_review.jobs.job_tree_sitter_ast.scope_execution import _validate_container_output
            try:
                locks, asset_lock = _grammar_locks(unit.job.repository_root)
                executor = factory(unit)
                image_id = executor.resolve_image(executor.catalog.tool(TREE_SITTER_TOOL))
            except (KeyError, OSError, RuntimeError, ValueError):
                statuses.update({path: "unavailable:tree_sitter_unavailable" for path in selected})
                output["dispositions"] = [{"disposition": "GAP", "reason": "tree_sitter_unavailable"}]
                selected = []
            groups: dict[str, list[str]] = {}
            for path in selected:
                if languages[path] in locks:
                    groups.setdefault(languages[path], []).append(path)
                else:
                    statuses[path] = "unavailable:symbol_language_unsupported"
            target = (unit.job.target_root or Path()).resolve()
            for language, paths in sorted(groups.items()):
                scratch = unit.unit_root / "scratch" / "tree-sitter" / re.sub(r"[^a-z0-9]+", "-", language.lower())
                scratch.mkdir(parents=True, exist_ok=True)
                request = {"schema": "appsec-review/tree-sitter-request/1", "scope_id": f"history-{language}",
                           "language": language, "max_nodes": settings.symbols_max_nodes_per_file,
                           "max_scope_nodes": settings.symbols_max_nodes_per_file * len(paths),
                           "max_file_bytes": settings.symbols_max_file_bytes,
                           "files": [{"path": path, "sha256": eligible[path]["sha256"]} for path in paths]}
                request_path = scratch / "request.json"
                atomic_json(request_path, request)
                # The parser runs as a different non-root UID: it may read the request and create its output.
                request_path.chmod(0o444)
                scratch.chmod(0o733)
                try:
                    execution = executor.execute(ExecutionRequest(
                        TREE_SITTER_TOOL, ("/opt/appsec/parser.py", "parse", "--request", "/scratch/request.json",
                                           "--output", "/scratch/output.json"),
                        unit.job.target_root or Path(), scratch, working_directory="/scratch"))
                except (OSError, RuntimeError, ValueError):
                    execution = None
                output_path = scratch / "output.json"
                if (execution is None or execution.exit_code != 0 or execution.timed_out or execution.oom_killed
                        or not output_path.is_file()):
                    statuses.update({path: "unavailable:tree_sitter_execution_failed" for path in paths})
                    output["dispositions"] = [{"disposition": "GAP", "reason": "tree_sitter_execution_failed"}]
                    continue
                container_output = json.loads(output_path.read_text(encoding="utf-8"))
                _validate_container_output(container_output, scope=None, grammar=locks[language],
                                           asset_lock=asset_lock, image_id=image_id,
                                           execution_image_id=execution.image_id)
                if container_output.get("scope_id") != request["scope_id"] or container_output.get("language") != language:
                    raise ValueError("Tree-sitter output scope identity mismatch")
                seen: set[str] = set()
                for record in container_output.get("records", ()):
                    path = str(record.get("path"))
                    if path not in paths or path in seen or record.get("sha256") != eligible[path]["sha256"]:
                        raise ValueError("Tree-sitter output names an unrequested path or a changed source hash")
                    seen.add(path)
                    if record.get("status") == "TRUNCATED":
                        statuses[path] = "unavailable:symbol_file_truncated"
                        continue
                    source = (target / path).read_bytes()
                    if hashlib.sha256(source).hexdigest() != eligible[path]["sha256"]:
                        raise ValueError(f"accepted target bytes changed: {path}")
                    results[path] = extract(record, source, language, path)
                    statuses[path] = results[path]["status"]
                for path in sorted(set(paths) - seen):
                    statuses[path] = "unavailable:tree_sitter_omitted_file"
        gaps = sorted({_reason(value) for value in statuses.values() if value.startswith("unavailable:")} -
                      {"working_tree_divergent"} |
                      {gap for value in results.values() for gap in value["gaps"]})
        return finish(gaps)

    def lines_of(unit: UnitContext) -> tuple[Mapping[str, str], Mapping[str, Any]]:
        output = unit.output("analyze.line_history")
        if "artifact" not in output:
            return {}, {}
        document = _read(unit.job.run_root, output["artifact"])
        return document["statuses"], document["files"]

    def symbols_of(unit: UnitContext) -> tuple[Mapping[str, str], Mapping[str, Any]]:
        output = unit.output("analyze.symbol_spans")
        if "artifact" not in output:
            return {}, {}
        document = _read(unit.job.run_root, output["artifact"])
        return document["statuses"], document["files"]

    def file_lines(path: str, statuses: Mapping[str, str], histories: Mapping[str, Any],
                   eligible: Mapping[str, Mapping[str, Any]]) -> FileLines | None:
        if statuses.get(path) != "complete":
            return None
        return FileLines(histories[path], int(eligible[path]["span_lines"]))

    def fix_detection(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        settings = _settings(unit.job)
        eligible = eligible_of(unit)
        files = file_signals(unit)
        line_statuses, histories = lines_of(unit)
        symbol_statuses, symbol_files = symbols_of(unit)
        results: dict[str, dict[str, Any]] = {}
        for path in _ranking_candidates(files):
            changes = [change for change in files[path]["changes"] if not change["excluded"]]
            if sum(1 for change in changes if change["fix"]) < 2:
                continue
            available = path in symbol_files and symbol_files[path]["status"] != "unavailable"
            results[path] = fix_on_fix(
                changes, lines=file_lines(path, line_statuses, histories, eligible),
                lines_reason=_reason(line_statuses.get(path, "unavailable:line_history_unavailable")),
                symbols=symbol_files[path]["symbols"] if available else None,
                symbols_reason=_reason(symbol_statuses.get(path, "unavailable:symbol_spans_unavailable")),
                interval_days=settings.fix_on_fix_interval_days)
        gaps = ["fix_on_fix_undetermined"] if any(value["undetermined"] for value in results.values()) else []
        document = {"schema": "appsec-review/source-history-fix-on-fix/1", "rules": FIX_ON_FIX_IDENTITY,
                    "interval_days": settings.fix_on_fix_interval_days, "files": dict(sorted(results.items()))}
        return {"artifact": _write(unit, "fix-on-fix.json", document),
                "event_count": sum(len(value["events"]) for value in results.values()),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def symbol_signals(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        settings = _settings(unit.job)
        eligible = eligible_of(unit)
        files = file_signals(unit)
        line_statuses, histories = lines_of(unit)
        _, symbol_files = symbols_of(unit)
        fixes = _read(unit.job.run_root, unit.output("analyze.fix_on_fix")["artifact"])["files"]
        symbols: dict[str, dict[str, Any]] = {}
        incomplete: dict[str, list[str]] = {}
        for path in _ranking_candidates(files):
            extracted = symbol_files.get(path)
            lines = file_lines(path, line_statuses, histories, eligible)
            if extracted is None or extracted["status"] == "unavailable" or lines is None:
                continue
            changes = {change["change_id"]: change for change in files[path]["changes"] if not change["excluded"]}
            attributed, unmapped = attribute(list(changes.values()), lines, extracted["symbols"])
            if unmapped:
                incomplete[path] = unmapped
            events = fixes.get(path, {}).get("events", ())
            for symbol in extracted["symbols"]:
                records = attributed.get(symbol["symbol_id"], [])
                if not records:
                    continue
                authors: dict[str, int] = {}
                for record in records:
                    author = changes[record["change_id"]]["author"]
                    authors[author] = authors.get(author, 0) + 1
                added = sum(record["added"] for record in records)
                deleted = sum(record["deleted"] for record in records)
                lines_count = int(symbol["nonblank_lines"])
                symbols[symbol["symbol_id"]] = {
                    **{key: symbol[key] for key in ("symbol_id", "qualified_name", "name", "kind", "language",
                                                    "start_line", "end_line", "start_column", "end_column",
                                                    "start_byte", "end_byte", "cyclomatic_complexity",
                                                    "cognitive_complexity", "complexity_gaps")},
                    "path": path, "component_id": files[path]["component_id"], "nonblank_lines": lines_count,
                    "change_count": len(records),
                    "revision_frequency": round(len(records) / settings.history_window_months, 6),
                    "lines_added": added, "lines_deleted": deleted, "churn_lines": added + deleted,
                    "relative_churn": round((added + deleted) / lines_count, 6) if lines_count else None,
                    "author_count": len(authors),
                    "author_commit_shares": {key: round(value / len(records), 6) for key, value in sorted(authors.items())},
                    "author_entropy": round(history_signals.entropy(authors.values()), 6),
                    "fix_change_count": sum(1 for record in records if changes[record["change_id"]]["fix"]),
                    "fix_on_fix_count": sum(1 for event in events if symbol["symbol_id"] in event.get("symbols", ())),
                    "last_change_time": max(changes[record["change_id"]]["effective_time"] for record in records),
                    "changes": records, "attribution": "hunk-region-to-innermost-symbol",
                    "attribution_gaps": ["symbol_attribution_incomplete"] if unmapped else [],
                }
        gaps = ["symbol_attribution_incomplete"] if incomplete else []
        document = {"schema": "appsec-review/source-history-symbol-signals/1", "symbols": dict(sorted(symbols.items())),
                    "unmapped_changes": dict(sorted(incomplete.items()))}
        return {"artifact": _write(unit, "symbol-signals.json", document), "symbol_count": len(symbols),
                "gaps": gaps, "terminal_status": _status(gaps)}

    history_units = ("resolve_sources.resolve_history_source", "resolve_sources.bind_snapshot", "acquire.git_history",
                     "acquire.normalize_changes", "acquire.github_enrichment", "analyze.classify_changes",
                     "analyze.blame_age")
    analysis_units = ("analyze.line_history", "analyze.symbol_spans", "analyze.fix_on_fix", "analyze.symbol_signals")

    def gaps_and_observations(unit: UnitContext, *, history_only: bool = False) -> tuple[list[str], list[str]]:
        gaps: list[str] = []
        for unit_id in history_units if history_only else (*history_units, *analysis_units):
            gaps.extend(unit.output(unit_id).get("gaps", ()))
        observations = [*source_of(unit).observations,
                        *unit.output("acquire.normalize_changes").get("observations", ())]
        return sorted(set(gaps)), sorted(set(observations))

    def rank(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "files": [], "components": []}
        settings = _settings(unit.job)
        sii = settings.sii
        metric = sii.complexity_metric
        values = _read(unit.job.run_root, computed["artifact"])
        eligible = eligible_of(unit)
        shares = unit.output("analyze.blame_age")["young_line_share"]
        partners = _read(unit.job.run_root, unit.output("analyze.co_change")["artifact"])
        line_statuses, _ = lines_of(unit)
        symbol_statuses, symbol_files = symbols_of(unit)
        fixes = _read(unit.job.run_root, unit.output("analyze.fix_on_fix")["artifact"])["files"]
        symbols = _read(unit.job.run_root, unit.output("analyze.symbol_signals")["artifact"])["symbols"]
        github = unit.output("acquire.github_enrichment")
        normalized = unit.output("acquire.normalize_changes")
        history_gaps = [*normalized.get("gaps", ()), *unit.output("analyze.classify_changes").get("gaps", ())]
        unavailable = [f"{name}:{reason}" for name, reason in sorted(UNAVAILABLE_SIGNALS.items())]
        if github["terminal_status"] in SKIPPED:
            unavailable.append(f"review_bypass:{github.get('reason')}")
        files: dict[str, dict[str, Any]] = {}
        for path, value in values["files"].items():
            extracted = symbol_files.get(path)
            complexity = extracted.get("file_complexity") if extracted else None
            fix = fixes.get(path)
            if fix is None:
                fix = {"status": "complete", "count": 0, "events": [], "undetermined": [], "candidate_pair_count": 0}
            files[path] = {
                **value, "young_line_share": shares.get(path), "co_change_partners": partners.get(path, []),
                "line_history_status": line_statuses.get(path, "not_requested"),
                "symbol_status": symbol_statuses.get(path, "not_requested"),
                "cyclomatic_complexity": complexity["cyclomatic"] if complexity else None,
                "cognitive_complexity": complexity["cognitive"] if complexity else None,
                "function_count": complexity["function_count"] if complexity else None,
                "complexity_gaps": complexity["gaps"] if complexity else [],
                "fix_on_fix_count": fix["count"], "fix_on_fix_status": fix["status"],
                "fix_on_fix_events": fix["events"], "fix_on_fix_undetermined": fix["undetermined"],
            }

        def coverage_gaps(path: str, symbol: Mapping[str, Any] | None = None) -> list[str]:
            item = files[path]
            gaps = list(history_gaps)
            if not eligible[path]["exact"]:
                gaps.append("working_tree_divergent")
            if item["line_history_status"] != "complete":
                gaps.append(f"line_history_unavailable:{_reason(item['line_history_status'])}")
            if item["cyclomatic_complexity"] is None:
                gaps.append(f"complexity_unavailable:{_reason(item['symbol_status'])}")
            gaps.extend(f"complexity:{gap}" for gap in item["complexity_gaps"])
            if item["fix_on_fix_status"] != "complete":
                gaps.append(f"fix_on_fix_{item['fix_on_fix_status']}")
            if item["young_line_share"] is None:
                gaps.append("young_line_share_unavailable")
            if symbol is not None:
                gaps.extend(f"complexity:{gap}" for gap in symbol["complexity_gaps"])
                gaps.extend(symbol["attribution_gaps"])
            gaps.extend(f"signal_unavailable:{entry}" for entry in unavailable)
            return sorted(set(gaps))

        population = {path: {"relative_churn": item["relative_churn"], "revision_frequency": item["revision_frequency"],
                             "author_entropy": item["author_entropy"], "complexity": item[f"{metric}_complexity"],
                             "churn_lines": item["churn_lines"], "change_count": item["change_count"]}
                      for path, item in files.items() if item["rank_eligibility"] == "eligible"}
        weights = dict(sii.weights)
        file_scores = sii_score(population, weights=weights, tier_1_share=sii.tier_1_share, tier_2_share=sii.tier_2_share)
        for item in file_scores["ranked"]:
            files[item["key"]]["sii"] = {key: item[key] for key in ("rank", "tier", "score", "inputs", "missing_inputs",
                                                                     "weight_coverage")}
        symbol_population = {key: {"relative_churn": item["relative_churn"],
                                   "revision_frequency": item["revision_frequency"],
                                   "author_entropy": item["author_entropy"], "complexity": item[f"{metric}_complexity"],
                                   "churn_lines": item["churn_lines"], "change_count": item["change_count"]}
                             for key, item in symbols.items() if item["nonblank_lines"] > 0}
        symbol_scores = sii_score(symbol_population, weights=weights, tier_1_share=sii.tier_1_share,
                                  tier_2_share=sii.tier_2_share)
        for item in symbol_scores["ranked"]:
            symbols[item["key"]]["sii"] = {key: item[key] for key in ("rank", "tier", "score", "inputs",
                                                                       "missing_inputs", "weight_coverage")}
        # A component's priority is its highest-scoring ranked file.
        components = dict(values["components"])
        best: dict[str, float] = {}
        for item in file_scores["ranked"]:
            component_id = files[item["key"]]["component_id"]
            if component_id in components and component_id not in best:
                best[component_id] = item["score"]
        component_order = sorted(best, key=lambda key: (-best[key], -int(components[key]["churn_lines"]),
                                                        -int(components[key]["change_count"]), key))
        for position, key in enumerate(component_order, 1):
            components[key]["priority"] = {"rank": position, "score": best[key], "basis": "max_file_sii"}
        window = {"identity": WINDOW_IDENTITY, "months": settings.history_window_months,
                  "start_time": normalized.get("window_start"), "anchor_time": normalized.get("anchor_time"),
                  "anchor": "mainline snapshot commit committer time"}
        sii_metadata = {"identity": SII_IDENTITY, "weights": weights, "complexity_metric": metric,
                        "transforms": TRANSFORMS, "tie_break": ["score desc", "churn_lines desc",
                                                                "change_count desc", "identity asc"]}

        def metadata(scores: Mapping[str, Any]) -> dict[str, Any]:
            return {key: value for key, value in scores.items() if key != "ranked"}

        document = {"schema": "appsec-review/source-history-signals/2", "sii": sii_metadata, "window": window,
                    "revision_semantics": REVISION_SEMANTICS, "filters": FILTER_IDENTITY,
                    "file_population": metadata(file_scores), "symbol_population": metadata(symbol_scores),
                    "files": files, "components": components, "symbols": symbols,
                    "file_ranking": [item["key"] for item in file_scores["ranked"]],
                    "component_ranking": component_order,
                    "symbol_ranking": [item["key"] for item in symbol_scores["ranked"]],
                    "unavailable_signals": unavailable}
        signals_artifact = _write(unit, "signals.json", document)
        snapshot = {"target_snapshot": unit.job.source_fingerprint, "snapshot_commit": source_of(unit).snapshot_commit,
                    "object_format": source_of(unit).object_format}

        def scalar(item: Mapping[str, Any]) -> dict[str, Any]:
            return {key: value for key, value in item.items()
                    if key not in {"changes", "sii", "recent_changes", "fix_on_fix_events"}}

        def entry(scope: str, key: str, item: Mapping[str, Any], scores: Mapping[str, Any]) -> dict[str, Any]:
            path = str(item["path"])
            facts = eligible[path]
            if scope == "file":
                location = {"start_line": 1, "end_line": int(facts["span_lines"]), "start_byte": 0,
                            "end_byte": int(facts["size_bytes"]), "start_column": 1, "end_column": 1,
                            "mapping_method": "git-blob-binding" if facts["exact"] else "git-path-binding",
                            "exact": bool(facts["exact"])}
                identity = {"path": path, "symbol_id": None, "component_id": item["component_id"]}
                gaps = coverage_gaps(path)
            else:
                location = {key_: item[key_] for key_ in ("start_line", "end_line", "start_byte", "end_byte",
                                                          "start_column", "end_column")}
                location.update({"mapping_method": "tree-sitter-byte-and-point-exact", "exact": True})
                identity = {"path": path, "symbol_id": key, "qualified_name": item["qualified_name"],
                            "kind": item["kind"], "component_id": item["component_id"]}
                gaps = coverage_gaps(path, item)
            changes = list(item["changes"])
            return {"schema": HOTSPOT_ENTRY_SCHEMA, "scope": scope, "identity": identity,
                    "rank": item["sii"]["rank"], "tier": item["sii"]["tier"], "score": item["sii"]["score"],
                    "sii": SII_IDENTITY, "metrics": scalar(item), "changes": changes[:100],
                    "changes_truncated": len(changes) > 100,
                    "fix_on_fix_events": item.get("fix_on_fix_events", [])[:20],
                    "inputs": {"values": item["sii"]["inputs"], "missing_inputs": item["sii"]["missing_inputs"],
                               "weight_coverage": item["sii"]["weight_coverage"],
                               "normalization": scores["normalization"], "constant_metrics": scores["constant_metrics"],
                               "weights": weights, "complexity_metric": metric, "population": scores["population"],
                               "tiers": scores["tiers"]},
                    "snapshot": snapshot, "source": {"path": path, "sha256": facts["sha256"], "blob_id": facts["blob_id"]},
                    "location": location, "window": window, "coverage_gaps": gaps, "authority": AUTHORITY}

        top_n = settings.hotspot_count
        entries = [entry("file", item["key"], files[item["key"]], file_scores) for item in file_scores["ranked"][:top_n]]
        entries += [entry("symbol", item["key"], symbols[item["key"]], symbol_scores)
                    for item in symbol_scores["ranked"][:top_n]]
        hotspots = {"schema": HOTSPOT_SCHEMA, "target_snapshot": unit.job.source_fingerprint, "snapshot": snapshot,
                    "sii": sii_metadata, "window": window, "hotspot_count": top_n,
                    "selection": "top hotspot_count ranked files and top hotspot_count ranked symbols",
                    "revision_semantics": REVISION_SEMANTICS, "authority": AUTHORITY,
                    "populations": {"file": metadata(file_scores), "symbol": metadata(symbol_scores)},
                    "exclusions": computed.get("rank_exclusions", {}), "unavailable_signals": unavailable,
                    "signals": signals_artifact, "entries": entries}
        return {"artifact": signals_artifact, "hotspots": _write(unit, "hotspots.json", hotspots),
                "ranked_file_count": file_scores["population"], "ranked_symbol_count": symbol_scores["population"],
                "ranked_component_count": len(component_order), "hotspot_entry_count": len(entries),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def index(unit: UnitContext) -> Mapping[str, Any]:
        snapshot = unit.job.source_fingerprint
        resolved = unit.output("resolve_sources.resolve_history_source")
        ranked = unit.output("analyze.rank")
        gaps, observations = gaps_and_observations(unit)
        history_gaps, _ = gaps_and_observations(unit, history_only=True)
        signals_doc = _read(unit.job.run_root, ranked["artifact"]) if "artifact" in ranked else None
        hotspots_doc = _read(unit.job.run_root, ranked["hotspots"]) if "hotspots" in ranked else None
        normalized = unit.output("acquire.normalize_changes")
        changes_doc = _read(unit.job.run_root, normalized["artifact"]) if "artifact" in normalized else {"changes": []}
        classes = classes_of(unit)
        producer_artifacts = [value[key] for value, key in ((ranked, "artifact"), (ranked, "hotspots"),
                                                            (normalized, "artifact")) if key in value]
        fingerprint = index_fingerprint(
            name="history", target_snapshot=snapshot, producer_artifacts=producer_artifacts,
            tool_identity={"history_identity": resolved["identity"], "rules": history_signals.RULES_IDENTITY,
                           "ranking": SII_IDENTITY, "symbols": SYMBOL_IDENTITY, "complexity": COMPLEXITY_IDENTITY,
                           "argv": ARGV_VERSION,
                           "config": hashlib.sha256(canonical_json(dict(unit.job.config.settings))).hexdigest()},
            parser_identity="git-log-numstat-z/1+git-log-u0/1", normalizer_identity=history_signals.NORMALIZER_IDENTITY,
            mapping_identity="git-blob-binding/1+tree-sitter-spans/1")
        shard_id = "git-history"
        path = unit.job.run_root / "data" / "indices" / "history" / shard_id / f"{fingerprint}.sqlite"
        eligible = eligible_of(unit)
        target = (unit.job.target_root or Path()).resolve()

        def file_location(file_path: str, scope: str) -> SourceLocation:
            facts = eligible[file_path]
            return SourceLocation(
                target_snapshot=snapshot, path=file_path, file_sha256=facts["sha256"], start_byte=0,
                end_byte=int(facts["size_bytes"]), start_line=1, end_line=int(facts["span_lines"]),
                start_column=1, end_column=1, producer_location={"vcs": "git", "scope": scope},
                mapping_method="git-blob-binding" if facts["exact"] else "git-path-binding",
                confidence=1.0 if facts["exact"] else 0.5, ambiguous=not facts["exact"])

        def symbol_location(value: Mapping[str, Any], scope: str) -> SourceLocation:
            return SourceLocation(
                target_snapshot=snapshot, path=str(value["path"]), file_sha256=eligible[value["path"]]["sha256"],
                start_byte=int(value["start_byte"]), end_byte=int(value["end_byte"]),
                start_line=int(value["start_line"]), end_line=int(value["end_line"]),
                start_column=int(value["start_column"]), end_column=int(value["end_column"]),
                producer_location={"vcs": "git", "scope": scope, "symbol_id": value["symbol_id"]},
                mapping_method="tree-sitter-byte-and-point-exact", confidence=1.0)

        if not path.exists():
            builder = IndexBuilder(path, name="history", fingerprint=fingerprint, target_snapshot=snapshot,
                                   shard_id=shard_id)
            change_ids: dict[str, str] = {}
            relevant = {change_id for value in (signals_doc or {}).get("files", {}).values()
                        for change_id in value["recent_changes"]}
            for change in changes_doc["changes"]:
                if change["change_id"] not in relevant:
                    continue
                identity = LogicalIdentity.derive(EntityKind.CHANGE, snapshot, {"vcs": "git", "change_id": change["change_id"]})
                change_ids[change["change_id"]] = identity.value
                label = classes.get(change["change_id"], {})
                payload = {"vcs": "git", "change_id": change["change_id"], "commit_time": change["commit_time"],
                           "author": change["author"], "file_count": change["file_count"], "bulk": change["bulk"],
                           "classification": label}
                text = " ".join(["change", change["change_id"],
                                 *(key for key in ("fix", "security_fix", "revert", "formatting") if label.get(key)),
                                 *label.get("security_references", ())])
                builder.add_entity(EntityRecord(identity, change["change_id"], change["change_id"][:12], text, payload))
            components: dict[str, str] = {}
            for component_id, value in sorted((signals_doc or {}).get("components", {}).items()):
                identity = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, snapshot,
                                                  {"scope": "component", "component_id": component_id})
                components[component_id] = identity.value
                builder.add_entity(EntityRecord(identity, f"component:{component_id}", component_id,
                    f"history component {component_id} churn {value['churn_lines']} changes {value['change_count']}", value))
            file_ids: dict[str, str] = {}
            for file_path, value in sorted((signals_doc or {}).get("files", {}).items()):
                identity = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, snapshot, {"scope": "file", "path": file_path})
                file_ids[file_path] = identity.value
                rank_text = (f"sii rank {value['sii']['rank']} tier {value['sii']['tier']}" if value.get("sii")
                             else value["rank_eligibility"])
                payload = {key: item for key, item in value.items() if key != "changes"}
                builder.add_entity(EntityRecord(identity, f"file:{file_path}", file_path,
                    f"history file {file_path} {rank_text} churn {value['churn_lines']} changes {value['change_count']}",
                    payload, file_location(file_path, "file")))
                for change_id in value["recent_changes"]:
                    if change_id in change_ids:
                        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                            change_ids[change_id], True, 1.0))
                if value.get("component_id") in components:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, components[value["component_id"]],
                                                        identity.value, True, 1.0))
            symbol_ids: dict[str, str] = {}
            for symbol_id, value in sorted((signals_doc or {}).get("symbols", {}).items()):
                identity = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, snapshot,
                                                  {"scope": "symbol", "symbol_id": symbol_id})
                symbol_ids[symbol_id] = identity.value
                builder.add_entity(EntityRecord(identity, f"symbol:{symbol_id}", symbol_id,
                    f"history symbol {value['qualified_name']} in {value['path']} churn {value['churn_lines']} "
                    f"changes {value['change_count']}", value, symbol_location(value, "symbol")))
                if value["path"] in file_ids:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, file_ids[value["path"]],
                                                        identity.value, True, 1.0))
            for item in (hotspots_doc or {}).get("entries", ()):
                key = item["identity"]["symbol_id"] or item["identity"]["path"]
                identity = LogicalIdentity.derive(EntityKind.HOTSPOT, snapshot, {
                    "scope": item["scope"], "key": key, "sii": SII_IDENTITY, "window_months": item["window"]["months"]})
                location = (file_location(item["identity"]["path"], "hotspot") if item["scope"] == "file"
                            else symbol_location((signals_doc or {})["symbols"][key], "hotspot"))
                builder.add_entity(EntityRecord(identity, f"hotspot:{item['scope']}:{key}", key,
                    f"hotspot {item['scope']} {key} tier {item['tier']} rank {item['rank']} sii {item['score']}",
                    item, location))
                source = file_ids.get(key) if item["scope"] == "file" else symbol_ids.get(key)
                if source is not None:
                    builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value, source, True, 1.0))
            git_status = resolved["git"]["decision"]
            status = ("unavailable" if git_status != "SUCCEEDED" or signals_doc is None
                      else "partial" if history_gaps else "complete")
            builder.add_coverage("git-history", status, "; ".join([*history_gaps, *observations][:20]) or
                                 (resolved["git"]["reason"] if status == "unavailable" else None))
            github = unit.output("acquire.github_enrichment")
            builder.add_coverage("github-enrichment",
                                 "complete" if github["terminal_status"] == "SUCCEEDED" else
                                 "partial" if "artifact" in github else "unavailable",
                                 "; ".join(github.get("gaps", ())) or github.get("reason"))
            for area, unit_id in (("line-history", "analyze.line_history"), ("symbol-spans", "analyze.symbol_spans"),
                                  ("fix-on-fix", "analyze.fix_on_fix")):
                output = unit.output(unit_id)
                area_status = ("unavailable" if "artifact" not in output else
                               "partial" if output.get("gaps") else "complete")
                builder.add_coverage(area, area_status, "; ".join(output.get("gaps", ())[:20]) or
                                     (resolved["git"]["reason"] if area_status == "unavailable" else None))
            builder.add_coverage("history-hotspots", "unavailable" if hotspots_doc is None else
                                 "partial" if gaps else "complete",
                                 resolved["git"]["reason"] if hotspots_doc is None else ("; ".join(gaps[:20]) or None))
            for name, reason in sorted(UNAVAILABLE_SIGNALS.items()):
                builder.add_coverage(name.replace("_", "-"), "unavailable", reason)
            builder.build()
        identity = IndexIdentity("history", "appsec-review/retrieval-index/2", file_sha256(path), fingerprint,
                                 _rel(unit.job.run_root, path), {"job": "job_source_history_analysis", "vcs": "git"},
                                 tuple(gaps), shard_id)
        upstream_path, upstream_sha = resolve_accepted_manifest(unit.job.run_root)
        upstream, _ = load_verified_manifest(unit.job.run_root, upstream_path, upstream_sha)
        base = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in upstream["indexes"]
                if item.get("producer", {}).get("job") != "job_source_history_analysis"]
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"source-history-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=snapshot, target_root=target,
                       indexes=[*base, identity],
                       upstream_manifests=({"path": _rel(unit.job.run_root, upstream_path), "sha256": upstream_sha},))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        return {"index_identity": asdict(identity), "manifest": _artifact(unit.job.run_root, manifest_path),
                "gaps": gaps, "terminal_status": _status(gaps)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        resolved = unit.output("resolve_sources.resolve_history_source")
        if resolved["identity"] != history_identity(unit.job.target_root):
            raise ValueError("target history changed during source history analysis")
        settings = _settings(unit.job)
        gaps, observations = gaps_and_observations(unit)
        ranked = unit.output("analyze.rank")
        signals_doc = _read(unit.job.run_root, ranked["artifact"]) if "artifact" in ranked else {}
        hotspots_doc = _read(unit.job.run_root, ranked["hotspots"]) if "hotspots" in ranked else None
        eligible = eligible_of(unit)
        files = signals_doc.get("files", {})
        components = signals_doc.get("components", {})
        file_ranking = [{"path": path, "sha256": eligible[path]["sha256"], "rank": files[path]["sii"]["rank"],
                         "tier": files[path]["sii"]["tier"], "score": files[path]["sii"]["score"],
                         "churn_lines": files[path]["churn_lines"], "change_count": files[path]["change_count"],
                         "component_id": files[path]["component_id"]}
                        for path in signals_doc.get("file_ranking", [])[:settings.ranking_top_n]]
        component_ranking = [{"component_id": key, "rank": components[key]["priority"]["rank"],
                              "score": components[key]["priority"]["score"],
                              "churn_lines": components[key]["churn_lines"],
                              "change_count": components[key]["change_count"]}
                             for key in signals_doc.get("component_ranking", [])]
        git = resolved["git"]
        normalized = unit.output("acquire.normalize_changes")
        decision = git["decision"] if git["decision"] != "SUCCEEDED" or not gaps else "SUCCEEDED"
        document = {
            "schema": SCHEMA, "target_snapshot": unit.job.source_fingerprint, "history_identity": resolved["identity"],
            "authority": AUTHORITY,
            "sources": {"git": {key: git[key] for key in ("decision", "reason", "object_format", "mainline_ref",
                                                          "snapshot_commit", "head_commit")},
                        "github": {"decision": unit.output("acquire.github_enrichment")["terminal_status"],
                                   "reason": unit.output("acquire.github_enrichment").get("reason")}},
            "binding": unit.output("resolve_sources.bind_snapshot")["binding"],
            "window": {"identity": WINDOW_IDENTITY, "months": settings.history_window_months,
                       "start_time": normalized.get("window_start"), "anchor_time": normalized.get("anchor_time"),
                       "change_count": normalized.get("change_count", 0), "revision_semantics": REVISION_SEMANTICS},
            "ranking": {"identity": SII_IDENTITY, "weights": dict(settings.sii.weights),
                        "complexity_metric": settings.sii.complexity_metric,
                        "files": file_ranking, "components": component_ranking, "signals": ranked.get("artifact")},
            "hotspots": {"schema": HOTSPOT_SCHEMA, "hotspot_count": settings.hotspot_count,
                         "artifact": ranked.get("hotspots"),
                         "entries": [{key: item[key] for key in ("scope", "rank", "tier", "score")} |
                                     {"path": item["identity"]["path"], "symbol_id": item["identity"]["symbol_id"]}
                                     for item in (hotspots_doc or {}).get("entries", ())]},
            "unavailable_signals": dict(sorted(UNAVAILABLE_SIGNALS.items())),
            "rules": history_signals.RULES_IDENTITY, "gaps": gaps, "observations": observations,
            "index_manifest": unit.output("publish.index_history")["manifest"], "decision": decision,
        }
        artifact = _write(unit, "source-history.json", document)
        unit.job.events.write("SOURCE_HISTORY_COMPLETED", ranked_file_count=len(signals_doc.get("file_ranking", [])),
                              ranked_component_count=len(component_ranking), gap_count=len(gaps),
                              hotspot_entry_count=len(document["hotspots"]["entries"]))
        output = {"schema": SCHEMA, "artifact": artifact, "index_manifest": document["index_manifest"],
                  "item_count": len(files), "gaps": gaps,
                  "terminal_status": git["decision"] if git["decision"] in SKIPPED else _status(gaps)}
        retriable = [item for unit_id in ("resolve_sources.bind_snapshot", "acquire.git_history", "acquire.github_enrichment",
                                          "analyze.line_history", "analyze.symbol_spans")
                     for item in unit.output(unit_id).get("dispositions", ())]
        if retriable:
            output["dispositions"] = retriable
        return output

    units = (
        Unit("resolve_sources.resolve_history_source", resolve),
        Unit("resolve_sources.bind_snapshot", bind, ("resolve_sources.resolve_history_source",)),
        Unit("acquire.git_history", acquire, ("resolve_sources.bind_snapshot",)),
        Unit("acquire.normalize_changes", normalize, ("acquire.git_history",)),
        Unit("acquire.github_enrichment", github_enrichment, ("acquire.normalize_changes",)),
        Unit("analyze.classify_changes", classify, ("acquire.normalize_changes", "acquire.github_enrichment")),
        Unit("analyze.compute_signals", compute, ("analyze.classify_changes",)),
        Unit("analyze.blame_age", blame, ("analyze.compute_signals",)),
        Unit("analyze.co_change", coupling, ("analyze.classify_changes",)),
        Unit("analyze.line_history", line_history, ("analyze.compute_signals",)),
        Unit("analyze.symbol_spans", symbol_spans, ("analyze.compute_signals",)),
        Unit("analyze.fix_on_fix", fix_detection, ("analyze.line_history", "analyze.symbol_spans")),
        Unit("analyze.symbol_signals", symbol_signals, ("analyze.fix_on_fix",)),
        Unit("analyze.rank", rank, ("analyze.blame_age", "analyze.co_change", "analyze.symbol_signals")),
        Unit("publish.index_history", index, ("analyze.rank",)),
        Unit("publish.publish_handoff", publish, ("publish.index_history",)),
    )
    sources = sorted(Path(__file__).parent.glob("*.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sources) +
                                    (b"custom-executor" if executor_factory else b"container-only") +
                                    (b"custom-transport" if github_transport else b"https-transport")).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        identities = {}
        for tool_id in (TOOL_ID, TREE_SITTER_TOOL):
            try:
                tool = load_catalog(root).tool(tool_id)
                identities[tool_id] = {"tag": tool.tag, "manifest": file_sha256(tool.manifest_path)}
            except (KeyError, OSError, ValueError):
                identities[tool_id] = "UNAVAILABLE"
        return hashlib.sha256(canonical_json(identities)).hexdigest()

    return Job("job_source_history_analysis", "source_history_analysis", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=SCHEMA, implementation_identity=implementation,
               runtime_identity=runtime_identity, units=units, input_identity=history_identity)
