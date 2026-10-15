"""Dataset inventory and publication-completeness audit for one review run.

The inventory is derived from four independent observations of a run: the job registry and
resolved configuration (what could run), dataset declarations (what each job promises), accepted
handoffs and index manifests (what was formally published), and the run-owned ``data/`` tree (what
is actually on disk). The audit compares them. Missing, skipped or failed outputs become scoped
``unavailable`` rows; an output nobody declared is a violation, never a silent success.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from appsec_review.indexing.store import AcceptedHandoff, digest, shard_key, shard_summary
from appsec_review.runtime.datasets import METADATA_ROUTE, DatasetDeclaration
from appsec_review.storage import file_sha256


ROW_SCHEMA = "appsec-review/dataset-inventory-row/1"
INVENTORY_SCHEMA = "appsec-review/dataset-inventory/1"
AUDIT_SCHEMA = "appsec-review/dataset-audit/1"
RUNTIME = "runtime"
_STATE_ORDER = {"complete": 0, "partial": 1, "stale": 2, "unavailable": 3}
_OK_STATUSES = {"SUCCEEDED", "PARTIAL", "COMPLETED_WITH_GAPS"}
_TRUNCATION = re.compile(r"(?i)truncat|bound reached|limit reached|over bound|exceed")


def compile_glob(pattern: str) -> re.Pattern[str]:
    """Translate a run-relative glob: ``*`` stays inside one segment, ``**`` crosses segments."""
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(parts))


@dataclass(frozen=True, slots=True)
class Claim:
    """One dataset that may own run-owned files."""

    job_id: str
    step: str
    output_kind: str
    declaration: DatasetDeclaration

    @property
    def key(self) -> tuple[str, str, str]:
        return self.job_id, self.step, self.output_kind


def _runtime_declaration(output_kind: str, step: str, family: str, schema: str, description: str,
                         patterns: tuple[str, ...], reason: str, *, sensitivity: str = "internal",
                         disposition: str = "artifact_only") -> DatasetDeclaration:
    return DatasetDeclaration(output_kind, step, family, schema, sensitivity, disposition, description,
                              artifacts=patterns, query_route=METADATA_ROUTE, reason=reason)


def runtime_claims(job_steps: Mapping[str, Sequence[str]]) -> list[Claim]:
    """Datasets written by the job runtime itself for every configured job and step."""
    claims: list[Claim] = []
    for job_id, steps in sorted(job_steps.items()):
        base = f"data/jobs/{job_id}"
        claims.append(Claim(job_id, "lifecycle", "attempt_receipts", _runtime_declaration(
            "attempt_receipts", "lifecycle", "execution_receipts", "appsec-review/job-handoff/1",
            "Attempt claims, status, results, handoffs, event logs and the attempt's pinned retrieval "
            "input manifest.",
            (f"{base}/latest.json", f"{base}/attempts/*/claim.json", f"{base}/attempts/*/status.json",
             f"{base}/attempts/*/result.json", f"{base}/attempts/*/handoff.json", f"{base}/attempts/*/logs/**",
             # Written by the runner (materialize_attempt_input_manifest) when an attempt inherits
             # more than one upstream index lineage; it merges manifests and adds no shards.
             f"{base}/attempts/*/inputs/retrieval-manifest.json"),
            "unit results may embed exact recipes, host paths and unredacted records; only status, counts "
            "and hashes are published", sensitivity="sensitive", disposition="protected")))
        for step in steps:
            root = f"{base}/attempts/*/steps/{step}"
            claims.append(Claim(job_id, step, "step_receipts", _runtime_declaration(
                "step_receipts", step, "execution_receipts", "appsec-review/unit-execution/2",
                "Per-task status, result receipts and task event logs of one configured step.",
                (f"{root}/lifecycle.json", f"{root}/lifecycle.lock", f"{root}/tasks/*/status.json",
                 f"{root}/tasks/*/result.json", f"{root}/tasks/*/traceback.txt", f"{root}/tasks/*/logs/**"),
                "unit results may embed exact recipes, host paths and unredacted records; only status, counts "
                "and hashes are published", sensitivity="sensitive", disposition="protected")))
    run_level = (
        ("run_configuration", "configuration", "appsec-review/run-configuration/2",
         "Run-bound source and resolved configuration.", ("data/configuration/**",),
         "configuration is hash-pinned per run; enabled lanes are visible as inventory rows", "internal",
         "artifact_only"),
        ("run_telemetry", "execution_receipts", "appsec-review/telemetry-event/1",
         "Run-wide structured log, metrics, locks and orchestration receipts.",
         ("data/logs/**", "data/telemetry/**", "data/orchestration/**", "data/resume.lock"),
         "operational telemetry, not review evidence; durations and statuses are inventory metadata", "internal",
         "artifact_only"),
        ("model_guidance", "configuration", "appsec-review/guidance-bundle/1",
         "Hash-pinned model guidance bundles used by inference steps.", ("data/guidance/**",),
         "prompt and guidance text must never enter retrieval; only bundle hashes are published", "sensitive",
         "protected"),
        ("operator_inputs", "configuration", "application/json",
         "Operator-supplied run-owned input fixtures.", ("data/inputs/**",),
         "unvalidated operator-supplied material; consumers index only validated facts", "sensitive", "protected"),
        ("index_manifests", "inventory", "appsec-review/index-manifest/1",
         "Accepted-index pointer and every published index manifest.",
         ("data/indices/accepted.json", "data/indices/manifests/**"),
         "manifests are the authority boundary, read through the accepted pointer rather than indexed",
         "internal", "artifact_only"),
    )
    for kind, family, schema, description, patterns, reason, sensitivity, disposition in run_level:
        claims.append(Claim(RUNTIME, "run", kind, _runtime_declaration(
            kind, "run", family, schema, description, patterns, reason, sensitivity=sensitivity,
            disposition=disposition)))
    return claims


@dataclass(slots=True)
class FileGroup:
    count: int = 0
    size_bytes: int = 0
    listing: Any = field(default_factory=hashlib.sha256)

    def add(self, relative: str, size: int) -> None:
        self.count += 1
        self.size_bytes += size
        self.listing.update(f"{relative}\0{size}\n".encode())

    def as_dict(self) -> dict[str, Any]:
        return {"file_count": self.count, "size_bytes": self.size_bytes,
                "listing_sha256": self.listing.hexdigest() if self.count else None}


@dataclass(slots=True)
class RunTree:
    groups: dict[tuple[str, str, str], FileGroup]
    shard_files: dict[str, int]
    unaccounted: list[str]
    unaccounted_count: int
    file_count: int
    truncated: bool
    scan_errors: list[str]


class FileClaims:
    """Match run-relative paths to the dataset that owns them; runtime receipts win over jobs."""

    def __init__(self, claims: Iterable[Claim]):
        self.files: list[tuple[re.Pattern[str], Claim]] = []
        self.trees: list[tuple[re.Pattern[str], Claim]] = []
        for claim in claims:
            for pattern in claim.declaration.artifacts:
                if pattern.endswith("/**"):
                    self.trees.append((compile_glob(pattern[:-3]), claim))
                    self.files.append((compile_glob(pattern), claim))
                else:
                    self.files.append((compile_glob(pattern), claim))

    def tree(self, directory: str) -> Claim | None:
        return next((claim for pattern, claim in self.trees if pattern.fullmatch(directory)), None)

    def file(self, path: str) -> Claim | None:
        return next((claim for pattern, claim in self.files if pattern.fullmatch(path)), None)


def scan_run_tree(run_root: Path, claims: FileClaims, *, max_files: int, sample_limit: int = 50) -> RunTree:
    """Enumerate the run-owned ``data/`` tree in deterministic order without reading file content."""
    groups: dict[tuple[str, str, str], FileGroup] = {}
    shard_files: dict[str, int] = {}
    unaccounted: list[str] = []
    scan_errors: list[str] = []
    state = {"files": 0, "unaccounted": 0, "truncated": False}
    root = Path(run_root)

    def visit(directory: Path, relative: str, owner: Claim | None) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            scan_errors.append(f"{relative}: {type(exc).__name__}")
            return
        for entry in entries:
            if state["truncated"]:
                return
            path = f"{relative}/{entry.name}"
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError as exc:
                scan_errors.append(f"{path}: {type(exc).__name__}")
                continue
            if is_dir:
                visit(Path(entry.path), path, owner or claims.tree(path))
                continue
            state["files"] += 1
            if state["files"] > max_files:
                state["truncated"] = True
                return
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError as exc:
                scan_errors.append(f"{path}: {type(exc).__name__}")
                continue
            claim = owner or claims.file(path)
            if claim is not None:
                groups.setdefault(claim.key, FileGroup()).add(path, size)
            elif path.startswith("data/indices/"):
                shard_files[path] = size
            else:
                state["unaccounted"] += 1
                if len(unaccounted) < sample_limit:
                    unaccounted.append(path)

    data = root / "data"
    if data.is_dir():
        visit(data, "data", None)
    else:
        scan_errors.append("data: missing_run_data_directory")
    return RunTree(groups, shard_files, unaccounted, state["unaccounted"], min(state["files"], max_files),
                   bool(state["truncated"]), scan_errors)


def dataset_id(run_id: str, job_id: str, step: str, scope: str, output_kind: str) -> str:
    return "ds:" + digest({"run": run_id, "job": job_id, "step": step, "scope": scope, "kind": output_kind})


def _status_class(job_ran: bool, statuses: Sequence[str]) -> tuple[str, str]:
    if not job_ran:
        return "not_run", "job has no accepted handoff in this run (disabled or outside the executed graph)"
    upper = [value.upper() for value in statuses]
    if any("TIMEOUT" in value or "TIMED_OUT" in value for value in upper):
        return "timed_out", "producing step timed out"
    if any(value in {"FAILED", "BLOCKED", "GAP", "UNAVAILABLE", "BLOCKED_BY_COMPILE", "INVALID_COMPILE_DATABASE"}
           for value in upper):
        return "failed", "producing step reported " + ", ".join(sorted(set(statuses)))
    if any(value == "SKIPPED_POLICY" for value in upper):
        return "disabled", "producing step was skipped by configured policy"
    if any(value in {"NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED"} for value in upper):
        return "skipped", "producing step was not applicable to this target"
    return "not_emitted", "producing step completed without emitting this optional output"


def _shard_coverage(summary: Mapping[str, Any], shard: Mapping[str, Any]) -> dict[str, Any]:
    rows = summary["coverage"]
    state = max((row["status"] for row in rows), key=lambda value: _STATE_ORDER.get(value, 1), default=None)
    gaps = [str(row["gap"])[:300] for row in rows if row["gap"] and row["status"] != "complete"]
    gaps.extend(str(gap)[:300] for gap in shard.get("gaps", ()))
    gaps = list(dict.fromkeys(gaps))
    if state is None:
        state, reason = "partial", "shard publishes no coverage row"
    elif state == "complete" and gaps:
        state, reason = "partial", gaps[0]
    else:
        reason = gaps[0] if gaps and state != "complete" else None
    return {"state": state, "reason": reason, "gaps": gaps[:10], "gap_count": len(gaps),
            "truncation_count": sum(1 for gap in gaps if _TRUNCATION.search(gap)),
            "areas": {name: sum(1 for row in rows if row["status"] == name) for name in _STATE_ORDER}}


def _producer(handoff: AcceptedHandoff | None) -> dict[str, Any]:
    if handoff is None:
        return {"attempt_id": None, "handoff_sha256": None}
    value = handoff.handoff
    return {"attempt_id": value.get("attempt_id"), "handoff_sha256": handoff.sha256,
            "completion_status": value.get("completion_status"),
            "implementation_identity": value.get("implementation_identity"),
            "schema_identity": value.get("schema_identity"),
            "job_config_sha256": value.get("job_config_sha256")}


@dataclass(slots=True)
class InventoryInputs:
    run_root: Path
    run_id: str
    target_snapshot: str
    job_steps: Mapping[str, Sequence[str]]
    declarations: Mapping[str, Sequence[DatasetDeclaration]]
    consumes: Mapping[str, Sequence[str]]
    handoffs: Mapping[str, AcceptedHandoff | None]
    unit_statuses: Mapping[str, Mapping[str, str]]
    shards: Sequence[Mapping[str, Any]]
    restored_shards: Sequence[Mapping[str, Any]] = ()
    shard_conflicts: Sequence[str] = ()
    max_files: int = 500_000


def _owasp_shards(run_root: Path) -> tuple[list[Mapping[str, Any]], str | None]:
    pointer_path = run_root / "data" / "indexes" / "owasp" / "accepted.json"
    if not pointer_path.is_file():
        return [], None
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    manifest_path = (run_root / str(pointer.get("manifest_path", ""))).resolve()
    if run_root.resolve() not in manifest_path.parents or not manifest_path.is_file():
        raise ValueError("accepted OWASP workbench manifest is unavailable")
    if file_sha256(manifest_path) != pointer.get("manifest_sha256"):
        raise ValueError("accepted OWASP workbench manifest identity changed")
    return list(json.loads(manifest_path.read_text(encoding="utf-8")).get("shards", ())), \
        str(pointer.get("manifest_sha256"))


def build_inventory(inputs: InventoryInputs) -> dict[str, Any]:
    """Return inventory rows plus audit violations, warnings and repairs for one run."""
    run_root = inputs.run_root
    violations: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    def violate(code: str, job_id: str, subject: str, detail: str) -> None:
        violations.append({"code": code, "job_id": job_id, "subject": subject[:512], "detail": detail[:1024]})

    def warn(code: str, job_id: str, subject: str, detail: str) -> None:
        warnings.append({"code": code, "job_id": job_id, "subject": subject[:512], "detail": detail[:1024]})

    claims = runtime_claims(inputs.job_steps)
    for job_id, declarations in sorted(inputs.declarations.items()):
        steps = inputs.job_steps.get(job_id, ())
        for declaration in declarations:
            if declaration.step not in steps:
                violate("unknown_step", job_id, declaration.output_kind,
                        f"declared step {declaration.step} is not in the resolved configuration")
            claims.append(Claim(job_id, declaration.step, declaration.output_kind, declaration))
    file_claims = FileClaims(claims)
    tree = scan_run_tree(run_root, file_claims, max_files=inputs.max_files)
    if tree.truncated:
        violate("run_tree_truncated", RUNTIME, "data",
                f"run tree enumeration stopped at {inputs.max_files} files; publication completeness is unknown")
    for error in tree.scan_errors:
        violate("run_tree_unreadable", RUNTIME, error, "run-owned files could not be enumerated")

    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def add_row(job_id: str, declaration: DatasetDeclaration, scope: str, **values: Any) -> dict[str, Any]:
        identity = dataset_id(inputs.run_id, job_id, declaration.step, scope, declaration.output_kind)
        if identity in seen_ids:
            violate("duplicate_dataset_id", job_id, declaration.output_kind, f"duplicate scope {scope}")
        seen_ids.add(identity)
        disposition = values.pop("disposition", declaration.disposition)
        row = {
            "schema": ROW_SCHEMA, "dataset_id": identity, "run_id": inputs.run_id, "job_id": job_id,
            "step": declaration.step, "output_kind": declaration.output_kind, "scope": scope,
            "family": declaration.family, "description": declaration.description,
            "dataset_schema": declaration.schema, "target_snapshot": inputs.target_snapshot,
            "sensitivity": declaration.sensitivity, "declared_disposition": declaration.disposition,
            "disposition": disposition, "query_route": declaration.query_route,
            "exception_reason": declaration.reason, "store": declaration.store,
            "producer": {"job": job_id, **_producer(inputs.handoffs.get(job_id))},
            "index": None, "artifacts": None, "record_count": None, "relation_count": None, **values,
        }
        rows.append(row)
        return row

    known_jobs = set(inputs.job_steps)
    claimed_shard_paths: set[str] = set()
    emitted: dict[tuple[str, str], int] = {}
    for shard in sorted(inputs.shards, key=shard_key):
        name, shard_id = shard_key(shard)
        job_id = str(shard.get("producer", {}).get("job") or "")
        claimed_shard_paths.add(str(shard["relative_path"]))
        if job_id not in known_jobs:
            violate("shard_without_registered_producer", job_id or RUNTIME, f"{name}/{shard_id}",
                    "accepted shard does not name a registered, configured producer job")
            continue
        scored = sorted(((item.claims_shard(name, shard_id), item) for item in inputs.declarations.get(job_id, ())
                         if item.store == "retrieval"), key=lambda pair: -pair[0])
        scored = [pair for pair in scored if pair[0] > 0]
        if not scored:
            violate("undeclared_shard", job_id, f"{name}/{shard_id}",
                    "emitted index shard is not claimed by any dataset declaration of its producer")
            continue
        if len(scored) > 1 and scored[0][0] == scored[1][0]:
            violate("ambiguous_shard_claim", job_id, f"{name}/{shard_id}",
                    f"claimed equally by {scored[0][1].output_kind} and {scored[1][1].output_kind}")
            continue
        declaration = scored[0][1]
        summary = shard_summary(run_root, shard)
        if not summary["counts_agree"]:
            violate("shard_counts_disagree", job_id, f"{name}/{shard_id}",
                    "entity or relation counts differ from the shard's recorded kind counts")
        coverage = _shard_coverage(summary, shard)
        producer = shard.get("producer", {})
        add_row(job_id, declaration, shard_id,
                disposition="unavailable" if coverage["state"] == "unavailable" else "indexed",
                index={"name": name, "shard_id": shard_id, "sha256": shard["sha256"],
                       "fingerprint": shard["fingerprint"], "schema": shard["schema"],
                       "entity_kinds": summary["entity_kinds"], "relation_kinds": summary["relation_kinds"]},
                record_count=summary["entity_count"], relation_count=summary["relation_count"],
                language=producer.get("language"), build_unit=producer.get("scope_id"),
                query_set=producer.get("query_set"), coverage=coverage)
        emitted[(job_id, declaration.output_kind)] = emitted.get((job_id, declaration.output_kind), 0) + 1

    owasp_shards, owasp_manifest = _owasp_shards(run_root)
    for job_id, declarations in sorted(inputs.declarations.items()):
        for declaration in (item for item in declarations if item.store == "owasp"):
            by_family: dict[str, list[Mapping[str, Any]]] = {}
            for shard in owasp_shards:
                by_family.setdefault(str(shard.get("family")), []).append(shard)
            for family, members in sorted(by_family.items()):
                if family not in declaration.indexes:
                    violate("undeclared_shard", job_id, f"owasp/{family}", "workbench family is not declared")
                    continue
                gaps = [str(gap)[:300] for shard in members for gap in shard.get("gaps", ())]
                add_row(job_id, declaration, family,
                        index={"name": f"owasp/{family}", "shard_id": family, "manifest_sha256": owasp_manifest,
                               "sha256": digest(sorted(str(item.get("sha256")) for item in members)),
                               "shard_count": len(members)},
                        record_count=sum(int(item.get("record_count", 0)) for item in members),
                        coverage={"state": "partial" if gaps else "complete", "reason": gaps[0] if gaps else None,
                                  "gaps": gaps[:10], "gap_count": len(gaps), "truncation_count": 0})
                emitted[(job_id, declaration.output_kind)] = emitted.get((job_id, declaration.output_kind), 0) + 1

    # Handoff artifacts must be claimed by a declaration, a runtime receipt or an accepted shard.
    artifact_refs: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for job_id, handoff in sorted(inputs.handoffs.items()):
        if handoff is None:
            continue
        fingerprint = handoff.handoff.get("source_fingerprint")
        if fingerprint not in {inputs.target_snapshot, "none", None}:
            violate("snapshot_mismatch", job_id, handoff.path,
                    "accepted handoff is bound to a different target snapshot")
        if not inputs.declarations.get(job_id):
            violate("undeclared_job", job_id, job_id, "job published a handoff but declares no datasets")
        for artifact in handoff.handoff.get("artifacts", ()):
            path = str(artifact.get("path", ""))
            candidate = (run_root / path).resolve()
            if run_root.resolve() not in candidate.parents or not candidate.is_file():
                violate("dangling_artifact", job_id, path, "handoff artifact is missing from the run")
                continue
            if file_sha256(candidate) != artifact.get("sha256"):
                violate("artifact_hash_mismatch", job_id, path, "handoff artifact content changed")
                continue
            if path in claimed_shard_paths:
                continue
            claim = file_claims.file(path)
            if claim is None:
                if path.startswith("data/indices/"):
                    continue  # a superseded or unpublished shard file, reported below
                violate("unaccounted_handoff_artifact", job_id, path,
                        "published artifact is not claimed by any dataset declaration")
                continue
            refs = artifact_refs.setdefault(claim.key, [])
            if len(refs) < 5:
                refs.append({"reference": path, "sha256": str(artifact.get("sha256"))})

    for claim in claims:
        declaration = claim.declaration
        if declaration.disposition == "indexed" and not declaration.artifacts:
            continue
        group = tree.groups.get(claim.key)
        if group is None:
            continue
        if declaration.disposition == "indexed":
            continue  # backing files of an indexed dataset are accounted by its shard rows
        add_row(claim.job_id, declaration, "run",
                artifacts={**group.as_dict(), "references": artifact_refs.get(claim.key, [])},
                coverage={"state": "complete", "reason": None, "gaps": [], "gap_count": 0, "truncation_count": 0})
        emitted[(claim.job_id, declaration.output_kind)] = 1

    for claim in claims:
        declaration = claim.declaration
        if (claim.job_id, declaration.output_kind) in emitted or claim.job_id == RUNTIME:
            continue
        if claim.key in tree.groups:
            continue
        ran = inputs.handoffs.get(claim.job_id) is not None
        statuses = [status for unit, status in inputs.unit_statuses.get(claim.job_id, {}).items()
                    if unit.split(".")[0] == declaration.step]
        status_class, reason = _status_class(ran, statuses)
        if declaration.required and ran and status_class == "not_emitted":
            violate("missing_required_output", claim.job_id, declaration.output_kind,
                    "required dataset was not emitted by a completed job")
        add_row(claim.job_id, declaration, "run", disposition="unavailable",
                coverage={"state": "unavailable", "reason": reason, "status_class": status_class, "gaps": [reason],
                          "gap_count": 1, "truncation_count": 0})

    if tree.unaccounted_count:
        for path in tree.unaccounted:
            violate("unaccounted_file", RUNTIME, path, "run-owned file is not claimed by any dataset declaration")
    unreferenced = sorted(path for path in tree.shard_files if path not in claimed_shard_paths)
    if unreferenced:
        warn("unreferenced_index_files", RUNTIME, "data/indices",
             f"{len(unreferenced)} index file(s) are outside the accepted set (superseded attempts, locks or "
             f"unpublished shards); first: {', '.join(unreferenced[:3])}")
    for conflict in inputs.shard_conflicts:
        violate("shard_conflict", RUNTIME, conflict, "two producers published different content for one shard")
    for row in rows:
        if row["disposition"] == "indexed" and not row["query_route"]:
            violate("indexed_without_route", row["job_id"], row["output_kind"], "indexed dataset has no query route")
        if row["disposition"] in {"artifact_only", "protected"} and not row["exception_reason"]:
            violate("exception_without_reason", row["job_id"], row["output_kind"], "missing exception reason")
    for job_id, upstream in sorted(inputs.consumes.items()):
        if inputs.handoffs.get(job_id) is None:
            continue
        for consumed in upstream:
            if consumed in known_jobs and inputs.handoffs.get(consumed) is None:
                warn("upstream_not_run", job_id, consumed, "a consumed upstream job has no accepted handoff")

    repairs = [{"code": "restored_dropped_shard", "job_id": str(shard.get("producer", {}).get("job")),
                "subject": "/".join(shard_key(shard)),
                "detail": "shard was published by its producer but absent from the previously accepted set"}
               for shard in sorted(inputs.restored_shards, key=shard_key)]
    rows.sort(key=lambda row: (row["job_id"], row["step"], row["output_kind"], row["scope"]))
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
    return {
        "schema": INVENTORY_SCHEMA, "run_id": inputs.run_id, "target_snapshot": inputs.target_snapshot,
        "rows": rows, "disposition_counts": dict(sorted(counts.items())),
        "run_tree": {"file_count": tree.file_count, "truncated": tree.truncated,
                     "scan_errors": tree.scan_errors[:50],
                     "unaccounted_count": tree.unaccounted_count, "unreferenced_index_files": len(unreferenced)},
        "audit": {"schema": AUDIT_SCHEMA, "status": "FAILED" if violations else "PASSED",
                  "violations": violations, "warnings": warnings, "repairs": repairs},
    }
