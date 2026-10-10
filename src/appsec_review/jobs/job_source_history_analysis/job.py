from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, load_catalog
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from . import signals as history_signals
from .git import (
    ARGV_VERSION, CHUNK_BYTES, LIMIT_RANGES, PARSER_IDENTITY, TOOL_ID, GitLimits, GitRunner, HistoryBoundError,
    parse_blame, parse_log_stream, parse_messages_stream, parse_tree,
)
from .github import GitHubClient, GitHubSettings, Transport, enrich
from .sources import GitSource, blob_id, history_identity, resolve_git_source


SCHEMA = "appsec-review/source-history-analysis/1"
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    "resolve_sources": ("resolve_history_source", "bind_snapshot"),
    "acquire": ("git_history", "normalize_changes", "github_enrichment"),
    "analyze": ("classify_changes", "compute_signals", "blame_age", "co_change", "rank"),
    "publish": ("index_history", "publish_handoff"),
}
SETTINGS = {
    "window_days": (1, 3650), "max_changes": (1, 200_000), "bulk_change_file_threshold": (1, 100_000),
    "recency_half_life_days": (1, 3650), "young_line_days": (1, 3650), "co_change_top_k": (1, 100),
    "co_change_min_support": (1, 10_000), "blame_max_files": (0, 10_000),
    "blame_max_file_bytes": (1, 16 * 1024 * 1024), "ranking_top_n": (1, 10_000),
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


class _VerifiedReader:
    """Bounded chunk reads over a retained raw artifact whose SHA-256 is checked as it is consumed."""

    def __init__(self, run_root: Path, identity: Mapping[str, Any]):
        candidate = run_root / str(identity.get("path", ""))
        path = candidate.resolve()
        if (run_root.resolve() not in path.parents or candidate.is_symlink() or not path.is_file()
                or path.stat().st_size != identity.get("size_bytes")):
            raise ValueError("source history raw artifact identity mismatch")
        self.expected = identity.get("sha256")
        self.digest = hashlib.sha256()
        self.stream = path.open("rb")

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > CHUNK_BYTES:
            raise ValueError("source history raw artifacts are read in bounded chunks only")
        data = self.stream.read(size)
        self.digest.update(data)
        return data

    def finish(self) -> None:
        try:
            for chunk in iter(lambda: self.stream.read(CHUNK_BYTES), b""):
                self.digest.update(chunk)
        finally:
            self.stream.close()
        if self.digest.hexdigest() != self.expected:
            raise ValueError("source history raw artifact identity mismatch")


@contextmanager
def _verified_stream(run_root: Path, identity: Mapping[str, Any]) -> Iterator[_VerifiedReader]:
    """Yield a chunked reader; the artifact hash is verified over every byte when the block exits."""
    reader = _VerifiedReader(run_root, identity)
    try:
        yield reader
    finally:
        reader.finish()


def _retain(run_root: Path, source: Path, destination: Path, limit: int) -> dict[str, Any]:
    """Stream a completed producer output into protected storage, hashing it without loading it."""
    if source.is_symlink() or not source.is_file():
        raise ValueError("git output is not a regular run-owned file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    digest, size = hashlib.sha256(), 0
    with source.open("rb") as reader, temporary.open("wb") as writer:
        for chunk in iter(lambda: reader.read(CHUNK_BYTES), b""):
            size += len(chunk)
            if size > limit:
                writer.close()
                temporary.unlink()
                raise HistoryBoundError("git_output_limit_reached")
            digest.update(chunk)
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    os.replace(temporary, destination)
    source.unlink()
    retained = _artifact(run_root, destination)
    if retained["sha256"] != digest.hexdigest() or retained["size_bytes"] != size:
        raise ValueError("retained git output changed while it was stored")
    return retained


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
            "files": [{key: item[key] for key in ("path", "sha256", "size_bytes")} for item in partition.get("files", ())],
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


def _settings(context) -> Mapping[str, Any]:
    settings = context.config.settings
    for key, (low, high) in SETTINGS.items():
        if type(settings.get(key)) is not int or not low <= settings[key] <= high:
            raise ValueError(f"source history setting is invalid: {key}")
    share = settings.get("minor_author_share")
    if not isinstance(share, (int, float)) or isinstance(share, bool) or not 0 < float(share) < 1:
        raise ValueError("source history setting is invalid: minor_author_share")
    for key in ("fix_labels", "security_labels"):
        values = settings.get(key)
        if not isinstance(values, list) or not all(isinstance(item, str) and 0 < len(item) <= 64 for item in values):
            raise ValueError(f"source history setting is invalid: {key}")
    weights = settings.get("ranking_weights")
    if not isinstance(weights, Mapping) or not weights:
        raise ValueError("source history ranking weights are required")
    for key, value in weights.items():
        if key not in history_signals.FILE_SIGNALS:
            raise ValueError(f"unknown source history ranking signal: {key}")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError(f"source history ranking weight is invalid: {key}")
    if not any(float(value) > 0 for value in weights.values()):
        raise ValueError("source history ranking needs at least one positive weight")
    git = settings.get("git")
    if not isinstance(git, Mapping) or set(git) != {"enabled", *LIMIT_RANGES} or type(git["enabled"]) is not bool:
        raise ValueError("source history git settings are invalid")
    GitLimits.from_settings(git)
    github = settings.get("github")
    required = {"enabled", "api_base", "repository", "token_env", "max_requests", "timeout_seconds",
                "per_page", "max_pages", "max_records"}
    if not isinstance(github, Mapping) or set(github) != required or type(github["enabled"]) is not bool:
        raise ValueError("source history github settings are invalid")
    if github["enabled"]:
        _github_settings(github, None)
        if not isinstance(github["token_env"], str) or not github["token_env"].isidentifier():
            raise ValueError("source history github token_env must name an environment variable")
    return settings


def _github_settings(github: Mapping[str, Any], token: str | None) -> GitHubSettings:
    return GitHubSettings(str(github["api_base"]), str(github["repository"]), token,
                          int(github["max_requests"]), int(github["timeout_seconds"]),
                          github["per_page"], github["max_pages"], github["max_records"])


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("source history topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"source history task order mismatch: {step}")
    _settings(context)


def _status(gaps: list[str]) -> str:
    return "PARTIAL" if gaps else "SUCCEEDED"


def _limits(unit: UnitContext) -> GitLimits:
    return GitLimits.from_settings(unit.job.config.settings["git"])


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
        return GitRunner(factory(unit), unit.job.target_root or Path(), unit.unit_root / "scratch", source_of(unit),
                         _limits(unit))

    def resolve(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit.job)
        inputs = _load_inputs(unit.job.run_root)
        if inputs["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted catalog")
        target = unit.job.target_root
        if not settings["git"]["enabled"]:
            git = GitSource("SKIPPED_POLICY", "git_history_disabled")
        elif target is None:
            git = GitSource("SKIPPED_NA", "no_target")
        else:
            try:
                git = resolve_git_source(target)
            except (OSError, ValueError) as exc:
                git = GitSource("GAP", f"git_metadata_unreadable:{type(exc).__name__}")
        github = ("SKIPPED_POLICY", "github_enrichment_disabled") if not settings["github"]["enabled"] else (
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
        settings = unit.job.config.settings
        limits = _limits(unit)
        git = runner(unit)
        count = int(settings["max_changes"]) + 1
        runs = (("log", git.log(count)), ("messages", git.messages(count)))
        executions = [run.execution for _, run in runs]
        limited = [name for name, run in runs if run.output_limit_reached]
        failed = [name for name, run in runs if name not in limited and
                  (run.exit_code != 0 or run.timed_out or run.output is None)]
        if limited or failed:
            # Partial output is never history: discard every producer file from this attempt.
            for _, run in runs:
                if run.output is not None:
                    run.output.unlink(missing_ok=True)
        if limited:
            unit.job.events.write("SOURCE_HISTORY_RESOURCE_LIMIT_REACHED", producers=limited,
                                  max_output_bytes=limits.max_output_bytes)
            return {"terminal_status": "PARTIAL", "executions": executions, "resource_limits": limits.as_dict(),
                    "resource_limit": {"disposition": "LIMIT_REACHED", "mechanism": "RLIMIT_FSIZE",
                                       "producers": limited, "partial_output": "discarded"},
                    "gaps": sorted([f"git_output_limit_reached:{name}" for name in limited] +
                                   [f"git_execution_failed:{name}" for name in failed])}
        if failed:
            return {"terminal_status": "PARTIAL", "gaps": [f"git_execution_failed:{name}" for name in failed],
                    "executions": executions, "dispositions": [{"disposition": "GAP", "reason": "git_execution_failed"}]}
        source = source_of(unit)
        raw = unit.unit_root / "protected"
        retained: dict[str, dict[str, Any]] = {}
        for name, run in runs:
            assert run.output is not None
            try:
                artifact = _retain(unit.job.run_root, run.output, raw / f"{name}.bin", limits.max_output_bytes)
            except HistoryBoundError as exc:
                return {"terminal_status": "PARTIAL", "gaps": [f"{exc.gap}:{name}"], "executions": executions,
                        "resource_limits": limits.as_dict()}
            retained[name] = {**artifact, "execution": {
                "status": "COMPLETED", "exit_code": run.exit_code, "image_id": run.execution["image_id"],
                "argv_identity": run.execution["argv_identity"],
                "file_size_limit_bytes": run.execution["file_size_limit_bytes"],
                "receipt": _artifact(unit.job.run_root, unit.job.run_root / run.execution["receipt_path"])},
                "source": {"snapshot_commit": source.snapshot_commit, "object_format": source.object_format,
                           "history_identity": unit.output("resolve_sources.resolve_history_source")["identity"]}}
        return {"raw_log": retained["log"], "raw_messages": retained["messages"],
                "executions": executions, "image_id": runs[0][1].execution["image_id"],
                "argv_version": ARGV_VERSION, "parser": PARSER_IDENTITY, "resource_limits": limits.as_dict(),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def normalize(unit: UnitContext) -> Mapping[str, Any]:
        acquired = unit.output("acquire.git_history")
        if "raw_log" not in acquired:
            return {"terminal_status": acquired["terminal_status"], "gaps": list(acquired["gaps"]), "change_count": 0}
        settings = unit.job.config.settings
        limits = _limits(unit)
        try:
            with _verified_stream(unit.job.run_root, acquired["raw_log"]) as stream:
                commits = parse_log_stream(stream, max_record_bytes=limits.max_record_bytes,
                                           max_changed_paths=limits.max_changed_paths)
        except HistoryBoundError as exc:
            # A bounded record means the history is incomplete; no change may be derived from it.
            unit.job.events.write("SOURCE_HISTORY_RESOURCE_LIMIT_REACHED", producers=["log"], bound=exc.gap)
            return {"terminal_status": "PARTIAL", "gaps": [exc.gap], "change_count": 0,
                    "resource_limits": limits.as_dict(),
                    "resource_limit": {"disposition": "LIMIT_REACHED", "mechanism": "bounded-record-parser",
                                       "producers": ["log"], "partial_output": "rejected"}}
        eligible = unit.output("resolve_sources.bind_snapshot")["eligible"]
        normalized = history_signals.normalize(
            commits, current_paths=eligible, shallow=source_of(unit).shallow,
            window_days=int(settings["window_days"]), max_changes=int(settings["max_changes"]),
            bulk_threshold=int(settings["bulk_change_file_threshold"]))
        walked = [str(item["commit"]) for item in commits[:int(settings["max_changes"])]]
        document = {"schema": "appsec-review/source-history-changes/1", "normalizer": history_signals.NORMALIZER_IDENTITY,
                    "anchor_time": normalized["anchor_time"], "window_start": normalized.get("window_start"),
                    "walked_commits": walked, "changes": normalized["changes"]}
        return {"artifact": _write(unit, "changes.json", document), "change_count": len(normalized["changes"]),
                "walked_change_count": normalized["walked_change_count"], "anchor_time": normalized["anchor_time"],
                "author_count": normalized["author_count"], "observations": normalized["observations"],
                "gaps": normalized["gaps"], "terminal_status": _status(normalized["gaps"])}

    def github_enrichment(unit: UnitContext) -> Mapping[str, Any]:
        resolved = unit.output("resolve_sources.resolve_history_source")["github"]
        normalized = unit.output("acquire.normalize_changes")
        if resolved["decision"] in SKIPPED:
            return {"terminal_status": resolved["decision"], "reason": resolved["reason"], "gaps": [], "facts_count": 0}
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "reason": "no_git_history", "gaps": [], "facts_count": 0}
        configured = unit.job.config.settings["github"]
        settings = _github_settings(configured, os.environ.get(str(configured["token_env"])) or None)
        changes = _read(unit.job.run_root, normalized["artifact"])["changes"]
        result = enrich(GitHubClient(settings, github_transport), str(source_of(unit).snapshot_commit),
                        [str(item["change_id"]) for item in changes])
        document = {"schema": "appsec-review/source-history-github/1", "repository": settings.repository,
                    "api_base": settings.api_base, **result}
        output = {"artifact": _write(unit, "github-enrichment.json", document), "facts_count": len(result["facts"]),
                  "indeterminate_count": result["indeterminate_count"], "pagination": result["pagination"],
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

    def classify(unit: UnitContext) -> Mapping[str, Any]:
        normalized = unit.output("acquire.normalize_changes")
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "gaps": []}
        settings = unit.job.config.settings
        changes = _read(unit.job.run_root, normalized["artifact"])
        with _verified_stream(unit.job.run_root, unit.output("acquire.git_history")["raw_messages"]) as stream:
            messages, gaps, oversized = parse_messages_stream(
                stream, changes["walked_commits"], max_message_bytes=_limits(unit).max_message_bytes)
        classes = history_signals.classify(
            changes["changes"], messages, github_facts(unit), known_commits=changes["walked_commits"],
            fix_labels=settings["fix_labels"], security_labels=settings["security_labels"],
            incomplete_messages=oversized)
        counts = {key: sum(1 for value in classes.values() if value.get(key)) for key in ("fix", "security_fix", "revert")}
        counts["message_incomplete"] = sum(1 for value in classes.values() if not value["message_complete"])
        document = {"schema": "appsec-review/source-history-classification/2",
                    "rules": history_signals.RULES_IDENTITY, "parser": PARSER_IDENTITY,
                    "max_message_bytes": _limits(unit).max_message_bytes, "classes": classes}
        return {"artifact": _write(unit, "classification.json", document), "counts": counts,
                "gaps": gaps, "terminal_status": _status(gaps)}

    def compute(unit: UnitContext) -> Mapping[str, Any]:
        normalized = unit.output("acquire.normalize_changes")
        if "artifact" not in normalized:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "files": {}, "components": {}}
        settings = unit.job.config.settings
        changes = _read(unit.job.run_root, normalized["artifact"])
        classes = _read(unit.job.run_root, unit.output("analyze.classify_changes")["artifact"])["classes"]
        roots = history_signals.component_roots(
            unit.output("resolve_sources.resolve_history_source")["inputs"]["components"])
        values = history_signals.compute_signals(
            changes["changes"], classes, github_facts(unit),
            eligible=unit.output("resolve_sources.bind_snapshot")["eligible"], roots=roots,
            anchor_time=changes["anchor_time"], half_life_days=int(settings["recency_half_life_days"]),
            minor_author_share=float(settings["minor_author_share"]))
        return {"artifact": _write(unit, "raw-signals.json", values), "file_count": len(values["files"]),
                "component_count": len(values["components"]), "gaps": [], "terminal_status": "SUCCEEDED"}

    def blame(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "young_line_share": {}}
        settings = unit.job.config.settings
        files = _read(unit.job.run_root, computed["artifact"])["files"]
        eligible = unit.output("resolve_sources.bind_snapshot")["eligible"]
        candidates = sorted((path for path, value in files.items()
                             if eligible[path]["exact"] and eligible[path]["size_bytes"] <= int(settings["blame_max_file_bytes"])),
                            key=lambda path: (-int(files[path]["churn_lines"]), path))
        limit = int(settings["blame_max_files"])
        gaps = ["blame_bound_reached"] if len(candidates) > limit else []
        anchor = int(unit.output("acquire.normalize_changes")["anchor_time"])
        threshold = anchor - int(settings["young_line_days"]) * history_signals.DAY
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
        settings = unit.job.config.settings
        partners = history_signals.co_change(
            _read(unit.job.run_root, normalized["artifact"])["changes"],
            eligible=unit.output("resolve_sources.bind_snapshot")["eligible"],
            roots=history_signals.component_roots(
                unit.output("resolve_sources.resolve_history_source")["inputs"]["components"]),
            top_k=int(settings["co_change_top_k"]), min_support=int(settings["co_change_min_support"]))
        return {"artifact": _write(unit, "co-change.json", partners), "file_count": len(partners),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def rank(unit: UnitContext) -> Mapping[str, Any]:
        computed = unit.output("analyze.compute_signals")
        if "artifact" not in computed:
            return {"terminal_status": "SKIPPED_NA", "gaps": [], "files": [], "components": []}
        settings = unit.job.config.settings
        values = _read(unit.job.run_root, computed["artifact"])
        shares = unit.output("analyze.blame_age")["young_line_share"]
        partners = _read(unit.job.run_root, unit.output("analyze.co_change")["artifact"])
        files = {path: {**value, "young_line_share": shares.get(path), "co_change_partners": partners.get(path, [])}
                 for path, value in values["files"].items()}
        weights = dict(settings["ranking_weights"])
        file_ranks = history_signals.rank(files, weights, signals=history_signals.FILE_SIGNALS)
        component_ranks = history_signals.rank(values["components"], weights, signals=history_signals.COMPONENT_SIGNALS)
        for item in file_ranks:
            files[item["key"]]["attention"] = {k: item[k] for k in ("rank", "score", "percentiles")}
        components = dict(values["components"])
        for item in component_ranks:
            components[item["key"]]["attention"] = {k: item[k] for k in ("rank", "score", "percentiles")}
        document = {"schema": "appsec-review/source-history-signals/1", "ranking": history_signals.RANKING_IDENTITY,
                    "weights": weights, "files": files, "components": components,
                    "file_ranking": [item["key"] for item in file_ranks],
                    "component_ranking": [item["key"] for item in component_ranks]}
        return {"artifact": _write(unit, "signals.json", document), "ranked_file_count": len(file_ranks),
                "ranked_component_count": len(component_ranks), "gaps": [], "terminal_status": "SUCCEEDED"}

    def gaps_and_observations(unit: UnitContext) -> tuple[list[str], list[str]]:
        gaps: list[str] = []
        for unit_id in ("resolve_sources.resolve_history_source", "resolve_sources.bind_snapshot", "acquire.git_history",
                        "acquire.normalize_changes", "acquire.github_enrichment", "analyze.classify_changes",
                        "analyze.blame_age"):
            gaps.extend(unit.output(unit_id).get("gaps", ()))
        observations = [*source_of(unit).observations,
                        *unit.output("acquire.normalize_changes").get("observations", ())]
        return sorted(set(gaps)), sorted(set(observations))

    def index(unit: UnitContext) -> Mapping[str, Any]:
        snapshot = unit.job.source_fingerprint
        resolved = unit.output("resolve_sources.resolve_history_source")
        ranked = unit.output("analyze.rank")
        gaps, observations = gaps_and_observations(unit)
        signals_doc = _read(unit.job.run_root, ranked["artifact"]) if "artifact" in ranked else None
        normalized = unit.output("acquire.normalize_changes")
        changes_doc = _read(unit.job.run_root, normalized["artifact"]) if "artifact" in normalized else {"changes": []}
        classes = (_read(unit.job.run_root, unit.output("analyze.classify_changes")["artifact"])["classes"]
                   if "artifact" in unit.output("analyze.classify_changes") else {})
        acquired = unit.output("acquire.git_history")
        github_output = unit.output("acquire.github_enrichment")
        producer_artifacts = [value["artifact"] for value in (ranked, normalized, github_output) if "artifact" in value]
        producer_artifacts += [{key: acquired[name][key] for key in ("path", "sha256", "size_bytes")}
                               for name in ("raw_log", "raw_messages") if name in acquired]
        fingerprint = index_fingerprint(
            name="history", target_snapshot=snapshot, producer_artifacts=producer_artifacts,
            tool_identity={"history_identity": resolved["identity"], "rules": history_signals.RULES_IDENTITY,
                           "ranking": history_signals.RANKING_IDENTITY, "argv": ARGV_VERSION,
                           "image": acquired.get("image_id"), "git_limits": _limits(unit).as_dict(),
                           "config": hashlib.sha256(canonical_json(dict(unit.job.config.settings))).hexdigest()},
            parser_identity=PARSER_IDENTITY, normalizer_identity=history_signals.NORMALIZER_IDENTITY,
            mapping_identity="git-blob-binding/1")
        shard_id = "git-history"
        path = unit.job.run_root / "data" / "indices" / "history" / shard_id / f"{fingerprint}.sqlite"
        eligible = unit.output("resolve_sources.bind_snapshot")["eligible"]
        target = (unit.job.target_root or Path()).resolve()
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
                text = " ".join(["change", change["change_id"], *(key for key in ("fix", "security_fix", "revert") if label.get(key)),
                                 *label.get("security_references", ())])
                builder.add_entity(EntityRecord(identity, change["change_id"], change["change_id"][:12], text, payload))
            components: dict[str, str] = {}
            for component_id, value in sorted((signals_doc or {}).get("components", {}).items()):
                identity = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, snapshot,
                                                  {"scope": "component", "component_id": component_id})
                components[component_id] = identity.value
                builder.add_entity(EntityRecord(identity, f"component:{component_id}", component_id,
                    f"history component {component_id} churn {value['churn_lines']} changes {value['change_count']}", value))
            for file_path, value in sorted((signals_doc or {}).get("files", {}).items()):
                identity = LogicalIdentity.derive(EntityKind.HISTORY_SIGNAL, snapshot, {"scope": "file", "path": file_path})
                facts = eligible[file_path]
                location = SourceLocation(
                    target_snapshot=snapshot, path=file_path, file_sha256=facts["sha256"], start_byte=0,
                    end_byte=int(facts["size_bytes"]), start_line=1, end_line=int(facts["span_lines"]),
                    start_column=1, end_column=1, producer_location={"vcs": "git", "scope": "file"},
                    mapping_method="git-blob-binding" if facts["exact"] else "git-path-binding",
                    confidence=1.0 if facts["exact"] else 0.5, ambiguous=not facts["exact"])
                rank_text = f"rank {value['attention']['rank']}" if value.get("attention") else "unranked"
                builder.add_entity(EntityRecord(identity, f"file:{file_path}", file_path,
                    f"history file {file_path} {rank_text} churn {value['churn_lines']} changes {value['change_count']}",
                    value, location))
                for change_id in value["recent_changes"]:
                    if change_id in change_ids:
                        builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, identity.value,
                                                            change_ids[change_id], True, 1.0))
                if value.get("component_id") in components:
                    builder.add_relation(RelationRecord(RelationKind.CONTAINS, components[value["component_id"]],
                                                        identity.value, True, 1.0))
            git_status = resolved["git"]["decision"]
            status = ("unavailable" if git_status != "SUCCEEDED" or signals_doc is None
                      else "partial" if gaps else "complete")
            builder.add_coverage("git-history", status, "; ".join([*gaps, *observations][:20]) or
                                 (resolved["git"]["reason"] if status == "unavailable" else None))
            github = unit.output("acquire.github_enrichment")
            builder.add_coverage("github-enrichment",
                                 "complete" if github["terminal_status"] == "SUCCEEDED" else
                                 "partial" if "artifact" in github else "unavailable",
                                 "; ".join(github.get("gaps", ())) or github.get("reason"))
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
        settings = unit.job.config.settings
        gaps, observations = gaps_and_observations(unit)
        ranked = unit.output("analyze.rank")
        signals_doc = _read(unit.job.run_root, ranked["artifact"]) if "artifact" in ranked else {}
        top_n = int(settings["ranking_top_n"])
        eligible = unit.output("resolve_sources.bind_snapshot")["eligible"]
        files = signals_doc.get("files", {})
        components = signals_doc.get("components", {})
        file_ranking = [{"path": path, "sha256": eligible[path]["sha256"], "rank": files[path]["attention"]["rank"],
                         "score": files[path]["attention"]["score"], "churn_lines": files[path]["churn_lines"],
                         "change_count": files[path]["change_count"], "component_id": files[path]["component_id"]}
                        for path in signals_doc.get("file_ranking", [])[:top_n]]
        component_ranking = [{"component_id": key, "rank": components[key]["attention"]["rank"],
                              "score": components[key]["attention"]["score"],
                              "churn_lines": components[key]["churn_lines"],
                              "change_count": components[key]["change_count"]}
                             for key in signals_doc.get("component_ranking", [])]
        git = resolved["git"]
        decision = git["decision"] if git["decision"] != "SUCCEEDED" or not gaps else "SUCCEEDED"
        document = {
            "schema": SCHEMA, "target_snapshot": unit.job.source_fingerprint, "history_identity": resolved["identity"],
            "authority": "history signals prioritize review; they are never vulnerability evidence",
            "sources": {"git": {key: git[key] for key in ("decision", "reason", "object_format", "mainline_ref",
                                                          "snapshot_commit", "head_commit")},
                        "github": {"decision": unit.output("acquire.github_enrichment")["terminal_status"],
                                   "reason": unit.output("acquire.github_enrichment").get("reason")}},
            "binding": unit.output("resolve_sources.bind_snapshot")["binding"],
            "window": {"days": settings["window_days"], "anchor_time": unit.output("acquire.normalize_changes").get("anchor_time"),
                       "change_count": unit.output("acquire.normalize_changes").get("change_count", 0)},
            "ranking": {"identity": history_signals.RANKING_IDENTITY, "weights": dict(settings["ranking_weights"]),
                        "files": file_ranking, "components": component_ranking,
                        "signals": ranked.get("artifact")},
            "rules": history_signals.RULES_IDENTITY, "gaps": gaps, "observations": observations,
            "index_manifest": unit.output("publish.index_history")["manifest"], "decision": decision,
        }
        artifact = _write(unit, "source-history.json", document)
        unit.job.events.write("SOURCE_HISTORY_COMPLETED", ranked_file_count=len(signals_doc.get("file_ranking", [])),
                              ranked_component_count=len(component_ranking), gap_count=len(gaps))
        output = {"schema": SCHEMA, "artifact": artifact, "index_manifest": document["index_manifest"],
                  "item_count": len(files), "gaps": gaps,
                  "terminal_status": git["decision"] if git["decision"] in SKIPPED else _status(gaps)}
        retriable = [item for unit_id in ("resolve_sources.bind_snapshot", "acquire.git_history", "acquire.github_enrichment")
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
        Unit("analyze.co_change", coupling, ("acquire.normalize_changes",)),
        Unit("analyze.rank", rank, ("analyze.compute_signals", "analyze.blame_age", "analyze.co_change")),
        Unit("publish.index_history", index, ("analyze.rank",)),
        Unit("publish.publish_handoff", publish, ("publish.index_history",)),
    )
    sources = sorted(Path(__file__).parent.glob("*.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sources) +
                                    (b"custom-executor" if executor_factory else b"container-only") +
                                    (b"custom-transport" if github_transport else b"https-transport")).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        try:
            tool = load_catalog(root).tool(TOOL_ID)
            return hashlib.sha256(canonical_json({"tag": tool.tag, "manifest": file_sha256(tool.manifest_path)})).hexdigest()
        except (KeyError, OSError, ValueError):
            return f"{TOOL_ID}:UNAVAILABLE"

    return Job("job_source_history_analysis", "source_history_analysis", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=SCHEMA, implementation_identity=implementation,
               runtime_identity=runtime_identity, units=units, input_identity=history_identity)
