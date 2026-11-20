"""Accepted dataset inventory, cross-domain links and stage-1 precomputed products.

The job runs after every producer in the review graph. It reads only the accepted retrieval
manifest, accepted handoffs and hash-verified run-owned artifacts; it never parses raw scanner
output, IR or a CPG and never executes target code. It restores shards that an upstream manifest
rewrite dropped, publishes typed link shards and one immutable shard per stage-1 query set, audits
every upstream dataset against its registered declaration, and publishes the
inventory as an indexed, queryable dataset. An audit violation blocks index acceptance; the audit
report remains on disk as run-owned evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
from typing import Any

from appsec_review import osv_matching
from appsec_review.indexing import input_matrix, matrix, products
from appsec_review.indexing import fts_worker
from appsec_review.indexing.derive import Derived, publish_derived
from appsec_review.storage.shared import SharedArtifacts
from appsec_review.indexing.inventory import InventoryInputs, accepted_owasp_publication, build_inventory, dataset_id
from appsec_review.indexing.links import LINK_RULES, LinkContext, rule_versions
from appsec_review.indexing.build_facts import build_command_facts, capture_events
from appsec_review.indexing.metrics import build_metric_vectors
from appsec_review.indexing.products_base import AcceptedShards, merge_product, to_derived
from appsec_review.indexing.sast import build_scanner_correlation
from appsec_review.indexing.store import AcceptedHandoff, ShardSet, accepted_handoff, as_identity, digest, \
    handoff_manifests, shard_key
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest, write_manifest
from appsec_review.retrieval.model import EntityKind, EntityRecord, LogicalIdentity
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor, resolved_job_is_enabled
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.storage import atomic_json, file_sha256

from .datasets import CONTRACT, DATASETS


JOB_ID = "job_review_data_indexing"
SCHEMA = "appsec-review/review-data-indexing/1"
INVENTORY_RULE = "appsec-review/dataset-inventory-index/2"
PRODUCT_SETS = ("build_provenance", "artifact_inventory", "dependency_advisories", "scanner_correlation",
                "ci_trust", "history_context", "control_evidence", "reference_intelligence", "symbol_links",
                "document_context", "threat_boundaries")
TOPOLOGY = {"load": ("accepted_inputs",), "links": ("cross_domain",), "precompute": PRODUCT_SETS,
            "fts": ("image_validation",), "audit": ("inventory",), "matrix": ("coverage",),
            "publish": ("inventory_index",)}
Providers = Callable[[], tuple[tuple[str, ...], Mapping[str, Sequence[Any]], Mapping[str, Sequence[str]]]]
def downstream_jobs() -> frozenset[str]:
    return frozenset(name for name, _ in input_matrix.downstream_consumers(JOB_ID))


def __getattr__(name: str):
    if name == "DOWNSTREAM_JOBS":
        return downstream_jobs()
    raise AttributeError(name)


def registry_providers() -> tuple[tuple[str, ...], dict[str, tuple[Any, ...]], dict[str, tuple[str, ...]]]:
    """All registered file owners, their datasets, and consumed upstream jobs."""
    from appsec_review.runtime.registry import builtin_registry
    registry = builtin_registry()
    job_ids = registry.job_ids()
    declarations: dict[str, tuple[Any, ...]] = {}
    consumes: dict[str, tuple[str, ...]] = {}
    for job_id in job_ids:
        job = registry.build(job_id)
        declarations[job_id] = job.datasets
        consumes[job_id] = job.consumes
    return job_ids, declarations, consumes


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _read(run_root: Path, reference: Mapping[str, Any]) -> Any:
    path = (run_root / str(reference["path"])).resolve()
    if run_root.resolve() not in path.parents or file_sha256(path) != reference["sha256"]:
        raise ValueError(f"run-owned artifact changed after acceptance: {reference['path']}")
    return json.loads(path.read_text(encoding="utf-8"))


def _bound_composed_product(derived: Derived, query_set: str, maximum: int) -> Derived:
    # Base facts retain their deterministic priority; supplemental facts use merge_product's order.
    unique = {}
    for record in derived.entities:
        unique.setdefault(record.identity.value, record)
    derived.entities = list(unique.values())[:maximum]
    kept = {record.identity.value for record in derived.entities}
    omitted = set(unique) - kept
    derived.counts["facts"] = len(kept)
    derived.counts["composed_candidate_facts"] = len(unique)
    derived.counts["omitted_facts"] = len(omitted)
    if omitted:
        before = len(derived.relations)
        derived.relations = [edge for edge in derived.relations
                             if edge.source_id not in omitted and edge.target_id not in omitted]
        derived.counts["omitted_relations"] = before - len(derived.relations)
        reason = f"truncated: {len(omitted)} composed {query_set} fact(s) exceeded the final bound of {maximum}"
        derived.gap(reason)
        derived.coverage.append((f"{query_set}:composition", "partial", reason))
    return derived


def _resolved_document(run_root: Path) -> dict[str, Any]:
    configuration = run_root / "data" / "configuration"
    manifest = json.loads((configuration / "manifest.json").read_text(encoding="utf-8"))
    if file_sha256(configuration / "resolved.json") != manifest.get("resolved_sha256"):
        raise ValueError("run-owned resolved configuration hash mismatch")
    return json.loads((configuration / "resolved.json").read_text(encoding="utf-8"))


def _resolved_steps(run_root: Path, *, include_disabled: bool = False) -> dict[str, list[str]]:
    configuration = run_root / "data" / "configuration"
    manifest = json.loads((configuration / "manifest.json").read_text(encoding="utf-8"))
    if file_sha256(configuration / "resolved.json") != manifest.get("resolved_sha256"):
        raise ValueError("run-owned resolved configuration hash mismatch")
    document = json.loads((configuration / "resolved.json").read_text(encoding="utf-8"))
    return {job_id: list((value.get("steps") or {}).keys())
            for job_id, value in sorted((document.get("jobs") or {}).items())
            if include_disabled or resolved_job_is_enabled(job_id, value)}


FEED_STEPS = {"nvd": "nvd_sync", "osv": "osv_sync", "mitre": "mitre_sync", "cve-bin-tool": "cve_bin_tool_db_build",
              "kev": "kev_sync", "epss": "epss_sync"}
# The index file each feed's snapshot manifest must hash for the feed to be pinned as queryable.
FEED_INDEXES = {"nvd": "index/nvd.sqlite", "osv": "index/osv.sqlite", "mitre": "index/mitre.sqlite",
                "kev": "index/kev.sqlite", "epss": "index/epss.sqlite"}


def feed_pins(repository_root: Path, resolved: Mapping[str, Any], max_age_days: int,
              now: datetime | None = None,
              max_age_overrides: Mapping[str, int] | None = None) -> dict[str, dict[str, Any]]:
    """Pin each global reference feed's verified current snapshot into this run's inputs.

    A feed whose ``current.json``, manifest or any manifest-hashed file (including its
    ``index/*.sqlite``) fails verification is ``unavailable``; one older than its freshness bound
    (``max_age_overrides[feed]`` or ``max_age_days``) is pinned with ``stale: true``.
    """
    from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
    steps = ((resolved.get("jobs") or {}).get("job_third_party_data_sync") or {}).get("steps") or {}
    instant = now or datetime.now(timezone.utc)
    pins: dict[str, dict[str, Any]] = {}
    for feed, step in FEED_STEPS.items():
        configured = ((steps.get(step) or {}).get("settings") or {}).get("feed_root")
        if not configured:
            pins[feed] = {"feed_id": feed, "status": "unavailable", "reason": "feed root is not configured"}
            continue
        root = Path(str(configured))
        root = root if root.is_absolute() else (repository_root / root).resolve()
        try:
            verified = verify_current(root, feed)
            pointer = json.loads((root / "current.json").read_text(encoding="utf-8"))
            manifest = json.loads((Path(verified["directory"]) / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            pins[feed] = {"feed_id": feed, "status": "unavailable",
                          "reason": f"no verified current snapshot ({type(exc).__name__})"}
            continue
        index = FEED_INDEXES.get(feed)
        if index is not None and index not in (manifest.get("files") or {}):
            pins[feed] = {"feed_id": feed, "status": "unavailable",
                          "reason": f"the verified snapshot publishes no {index}"}
            continue
        bound = int((max_age_overrides or {}).get(feed, max_age_days))
        published = str(pointer.get("published_at") or "")
        try:
            age = (instant - datetime.fromisoformat(published.replace("Z", "+00:00"))).days
        except ValueError:
            age = None
        pins[feed] = {"feed_id": feed, "status": "pinned", "snapshot_id": verified["snapshot_id"],
                      "manifest_sha256": verified["manifest_sha256"], "directory": verified["directory"],
                      "published_at": published, "stale": age is None or age > bound, "max_age_days": bound,
                      **({"provenance": verified["provenance"]} if "provenance" in verified else {}),
                      "files": {logical: (entry.get("sha256") if isinstance(entry, Mapping) else entry)
                                for logical, entry in (manifest.get("files") or {}).items()}}
    return pins


def owasp_status(run_root: Path) -> dict[str, Any]:
    return accepted_owasp_publication(run_root, accepted_handoff(run_root, "job_owasp_control_assessment"))


def threat_model_status(run_root: Path) -> dict[str, Any]:
    """Load and hash-verify accepted job_threat_model_generation artifacts when present."""
    accepted = accepted_handoff(run_root, "job_threat_model_generation")
    if accepted is None:
        return {"status": "unavailable", "reason": "job_threat_model_generation has no accepted handoff in this run"}
    outputs = accepted.handoff.get("outputs") or {}
    pub_out = outputs.get("publication.publish_handoff") or {}
    named_artifacts = dict(pub_out.get("artifacts") or {})
    top_artifacts = {Path(str(ref.get("path", ""))).name: ref
                     for ref in (accepted.handoff.get("artifacts") or ())
                     if isinstance(ref, Mapping) and isinstance(ref.get("path"), str)}
    from appsec_review.runtime.inputs import observe_output
    loaded: dict[str, Any] = {}
    kind_map = {
        "dfd": ("dfd.json", "generated_dfd"),
        "threat_model": ("threat-model.json", "generated_threat_model"),
        "result": ("result.json", "threat_model_documents"),
    }
    for key, (filename, output_kind) in kind_map.items():
        ref = named_artifacts.get(filename) or top_artifacts.get(filename)
        if not isinstance(ref, Mapping) or not isinstance(ref.get("path"), str) or not isinstance(ref.get("sha256"), str):
            continue
        data = _read(run_root, ref)
        observe_output(run_root, "job_threat_model_generation", output_kind,
                       {"path": ref["path"], "sha256": ref["sha256"]})
        loaded[key] = data
    if not loaded.get("dfd") and not loaded.get("threat_model"):
        return {"status": "unavailable", "reason": "job_threat_model_generation handoff carries no dfd.json or threat-model.json"}
    raw_gaps = (loaded.get("result") or {}).get("gaps") or ()
    gap_summaries = [
        str(g.get("summary") or g.get("detail") or g.get("code") or g) if isinstance(g, Mapping) else str(g)
        for g in raw_gaps
    ]
    return {
        "status": "accepted",
        "handoff_sha256": accepted.sha256,
        "dfd": loaded.get("dfd") or {},
        "threat_model": loaded.get("threat_model") or {},
        "counts": dict((loaded.get("result") or {}).get("counts") or pub_out.get("counts") or {}),
        "gaps": gap_summaries,
    }


def sanitizer_status(run_root: Path, snapshot: str, *, disabled: bool = False) -> dict[str, Any]:
    """Read only the admitted summary, never the protected build tree or a floating handoff."""
    from appsec_review.jobs.engineering_contracts import SANITIZER_BUILD_HANDOFF_SCHEMA
    from appsec_review.runtime.inputs import observe_output
    from appsec_review.storage.shared import safe_path

    job_id = "job_sanitizer_build"
    if disabled:
        return {"status": "disabled", "reason": "sanitizer build is disabled in this run"}
    accepted = accepted_handoff(run_root, job_id)
    if accepted is None:
        return {"status": "unavailable", "reason": "no admitted sanitizer build handoff"}
    handoff = accepted.handoff
    if handoff["source_fingerprint"] != snapshot or handoff["target_snapshot"] != snapshot:
        raise ValueError("sanitizer summary target snapshot differs from indexing")
    reference = (handoff["outputs"].get("acceptance.publish_handoff") or {}).get("artifact")
    if not isinstance(reference, Mapping):
        return {"status": "unavailable", "reason": "accepted sanitizer handoff has no summary artifact"}
    path = safe_path(run_root, reference["path"])
    if (safe_path(run_root, accepted.path).parent not in path.parents
            or not any(ref["path"] == reference["path"] and ref["sha256"] == reference["sha256"]
                       for ref in handoff["artifacts"])):
        raise ValueError("sanitizer summary is not pinned to its accepted attempt")
    observe_output(run_root, job_id, "sanitizer_build_summary", reference)
    summary = _read(run_root, reference)
    if summary.get("schema") != SANITIZER_BUILD_HANDOFF_SCHEMA:
        raise ValueError("sanitizer summary schema mismatch")
    identity = {"run_id": handoff["run_id"], "attempt_id": handoff["attempt_id"],
                "source_fingerprint": snapshot}
    for key, value in identity.items():
        if key in summary and summary[key] != value:
            raise ValueError(f"sanitizer summary {key} mismatch")
    language_hash = (summary.get("upstream") or {}).get("language_build_handoff_sha256")
    if language_hash != handoff["upstream_handoff_sha256"].get("job_language_build"):
        raise ValueError("sanitizer summary language-build lineage mismatch")
    units = [item for key in ("units", "omitted_units", "not_applicable_units")
             for item in summary.get(key, ())]
    ids = [item.get("build_unit_id") for item in units]
    if any(not isinstance(value, str) or not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("sanitizer summary has invalid or duplicate build units")
    return {"status": "accepted", **identity, "handoff_sha256": accepted.sha256,
            "summary_reference": dict(reference), "language_build_handoff_sha256": language_hash,
            "summary": summary}


def _unit_statuses(run_root: Path, handoff: AcceptedHandoff) -> dict[str, str]:
    attempt = (run_root / handoff.path).parent
    statuses: dict[str, str] = {}
    for status_path in sorted(attempt.glob("steps/*/tasks/*/status.json")):
        task, step = status_path.parent.name, status_path.parent.parent.parent.name
        status = str(json.loads(status_path.read_text(encoding="utf-8")).get("status", "UNKNOWN"))
        result_path = status_path.with_name("result.json")
        if result_path.is_file():
            try:
                terminal = json.loads(result_path.read_text(encoding="utf-8")).get("terminal_status")
            except ValueError:
                terminal = None
            if isinstance(terminal, str):
                status = terminal
        statuses[f"{step}.{task}"] = status
    return statuses


def reconcile_shards(run_root: Path, accepted: Sequence[Mapping[str, Any]],
                     handoffs: Mapping[str, AcceptedHandoff | None]) -> tuple[list[dict], list[dict], list[str]]:
    """Restore shards a producer published but a later manifest rewrite dropped; report conflicts."""
    by_key = {shard_key(item): item for item in accepted}
    restored: dict[tuple[str, str], dict[str, Any]] = {}
    conflicts: list[str] = []
    for job_id, handoff in sorted(handoffs.items()):
        if handoff is None:
            continue
        for manifest in handoff_manifests(run_root, handoff.handoff):
            for shard in manifest["document"].get("indexes", ()):
                if shard.get("producer", {}).get("job") != job_id:
                    continue
                key = shard_key(shard)
                present = by_key.get(key) or restored.get(key)
                if present is None:
                    restored[key] = dict(shard)
                elif present["sha256"] != shard["sha256"] and present.get("producer", {}).get("job") == job_id:
                    conflicts.append(f"{key[0]}/{key[1]}: {job_id} handoff manifest and accepted set disagree")
    return [dict(item) for item in accepted], [restored[key] for key in sorted(restored)], sorted(set(conflicts))


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("review-data-indexing topology does not match central configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"review-data-indexing task configuration mismatch: {step}")


def build_job(*, providers: Providers = registry_providers,
              executor_factory: Callable[[UnitContext], Any] | None = None) -> Job:
    def settings_of(unit: UnitContext) -> Mapping[str, Any]:
        return unit.job.config.settings

    def inputs_of(unit: UnitContext) -> dict[str, Any]:
        return _read(unit.job.run_root, unit.output("load.accepted_inputs")["artifact"])

    def shard_view(unit: UnitContext) -> tuple[dict[str, Any], AcceptedShards]:
        document = inputs_of(unit)
        return document, AcceptedShards(unit.job.run_root, [*document["shards"], *document["restored_shards"]],
                                        document["target_snapshot"])

    def load(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        manifest_path, manifest_sha = resolve_context_manifest(unit.job)
        manifest, _ = load_verified_manifest(run_root, manifest_path, manifest_sha)
        if manifest.get("target_snapshot") != unit.job.source_fingerprint:
            raise ValueError("accepted index snapshot differs from the graph target snapshot")
        job_ids, declarations, consumes = providers()
        registered_jobs = job_ids
        file_job_steps = {job_id: steps for job_id, steps in _resolved_steps(
            run_root, include_disabled=True).items() if job_id in job_ids}
        resolved_jobs = (_resolved_document(run_root).get("jobs") or {})
        disabled = {job_id for job_id, value in resolved_jobs.items()
                    if not resolved_job_is_enabled(job_id, value)}
        from appsec_review.runtime.contracts import DispatchClass
        from appsec_review.runtime.registry import builtin_contracts
        contracts = builtin_contracts()
        active = {name for name in _resolved_steps(run_root)
                  if name not in contracts or contracts[name].dispatch is DispatchClass.REVIEW_GRAPH} - downstream_jobs()
        job_ids = tuple(job_id for job_id in job_ids if job_id in active)
        declarations = {job_id: values for job_id, values in declarations.items() if job_id in active}
        consumes = {job_id: tuple(upstream for upstream in values if upstream in active)
                    for job_id, values in consumes.items() if job_id in active}
        handoffs = {job_id: accepted_handoff(run_root, job_id) for job_id in job_ids if job_id != JOB_ID}
        accepted, restored, conflicts = reconcile_shards(run_root, manifest["indexes"], handoffs)
        for shard in restored:
            candidate = (run_root / str(shard["relative_path"])).resolve()
            if run_root.resolve() not in candidate.parents or file_sha256(candidate) != shard["sha256"]:
                raise ValueError(f"restored shard failed verification: {'/'.join(shard_key(shard))}")
        job_steps = {job_id: steps for job_id, steps in _resolved_steps(run_root).items()
                     if job_id in active}
        feeds = feed_pins(unit.job.repository_root, _resolved_document(run_root),
                          int(settings_of(unit)["feed_max_age_days"]),
                          max_age_overrides={str(key): int(value) for key, value in dict(
                              settings_of(unit).get("feed_max_age_days_overrides") or {}).items()})
        mismatch = sorted(set(job_ids) ^ set(job_steps))
        document = {
            "schema": "appsec-review/review-data-indexing-inputs/2", "target_snapshot": manifest["target_snapshot"],
            "accepted_manifest": {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": manifest_sha},
            "shards": accepted, "restored_shards": restored, "shard_conflicts": conflicts,
            "registry_jobs": list(job_ids), "registry_configuration_mismatch": mismatch, "job_steps": job_steps,
            "registered_jobs": list(registered_jobs),
            "dispatch_classes": {name: contracts[name].dispatch.value for name in registered_jobs
                                 if name in contracts},
            "file_job_steps": file_job_steps,
            "disabled_jobs": sorted(disabled),
            "declarations": {job_id: [item.output_kind for item in values] for job_id, values in declarations.items()},
            "consumes": {job_id: list(values) for job_id, values in consumes.items()},
            "handoffs": {job_id: None if value is None else {
                "sha256": value.sha256, "path": value.path, "attempt_id": value.handoff.get("attempt_id"),
                "completion_status": value.handoff.get("completion_status")} for job_id, value in handoffs.items()},
            "feeds": feeds, "owasp": owasp_status(run_root), "threat_model": threat_model_status(run_root),
            "sanitizer": sanitizer_status(run_root, manifest["target_snapshot"],
                                           disabled="job_sanitizer_build" in disabled),
            "unit_statuses": {job_id: _unit_statuses(run_root, value) for job_id, value in handoffs.items()
                              if value is not None},
        }
        path = unit.unit_root / "accepted-inputs.json"
        atomic_json(path, document)
        unit.job.events.write("DATASET_INPUTS_LOADED", shard_count=len(accepted), restored_count=len(restored),
                              conflict_count=len(conflicts), job_count=len(job_ids))
        gaps = [f"restored dropped shard {'/'.join(shard_key(item))}" for item in restored]
        return {"artifact": _artifact(run_root, path), "shard_count": len(accepted), "restored": len(restored),
                "gaps": gaps, "terminal_status": "SUCCEEDED"}

    def links(unit: UnitContext) -> Mapping[str, Any]:
        document, view = shard_view(unit)
        settings = settings_of(unit)
        versions = rule_versions(dict(settings.get("rule_versions", {})))
        context = LinkContext(document["target_snapshot"], view.store, int(settings["max_links_per_rule"]))
        published = []
        for rule in LINK_RULES:
            selected = rule.select(view.store)
            published.append(publish_derived(
                unit.job.run_root, index="links", shard_id="links-" + rule.family.replace("_", "-"), job_id=JOB_ID,
                unit_id=unit.unit_id, rule=rule.family, rule_version=versions[rule.family],
                snapshot=document["target_snapshot"],
                inputs={"shards": ShardSet.identities(selected), "max_links": context.max_links,
                        "link_budget_rule": "emitted-relations/2"},
                build=lambda rule=rule, selected=selected: rule.build(context, selected),
                producer={"link_family": rule.family}, shared=SharedArtifacts.for_job(unit.job)))
        gaps = [f"links/{item['rule']}: {gap}" for item in published for gap in item["gaps"]]
        return {"links": published, "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    def precompute(query_set: str) -> Callable[[UnitContext], Mapping[str, Any]]:
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            document, view = shard_view(unit)
            settings = settings_of(unit)
            run_root, snapshot = unit.job.run_root, document["target_snapshot"]
            rule = products.product_rule(query_set)
            version = str(dict(settings.get("rule_versions", {})).get(query_set, rule.version))
            max_facts = int(settings["max_facts_per_product"])
            link_identities = {item["rule"]: item["index_identity"] for item in unit.output("links.cross_domain")["links"]}
            store = ShardSet(run_root, [*view.shards, *link_identities.values()])
            osv_version_matching = osv_matching.parse_mode(
                settings.get("osv_version_matching", "disabled"), f"jobs.{JOB_ID}.settings.osv_version_matching")
            tm_doc = document.get("threat_model") or {}
            context = products.ProductContext(
                run_root, snapshot, store, {family: link_identities[family] for family in rule.links
                                            if family in link_identities},
                {feed: document["feeds"].get(feed, {"status": "unavailable", "reason": "feed is not configured"})
                 for feed in rule.feeds}, document["owasp"] if rule.owasp else {}, max_facts, version,
                osv_version_matching, threat_model=tm_doc if rule.threat_model else {})
            selected = rule.select(store)
            inputs: dict[str, Any] = {
                "shards": ShardSet.identities(selected), "max_facts": max_facts,
                "gap_summary_rule": "counted-gaps/1",
                "links": {family: link_identities[family]["sha256"] for family in rule.links if family in link_identities},
                "feeds": {feed: {key: document["feeds"].get(feed, {}).get(key) for key in ("status", "manifest_sha256",
                                                                                           "stale")}
                          for feed in rule.feeds},
                "owasp": document["owasp"].get("manifest_sha256") if rule.owasp else None}
            if rule.threat_model:
                inputs["threat_model"] = tm_doc.get("handoff_sha256")
                inputs["projection_rule"] = "counted-boundary-detail/2"
            if query_set == "dependency_advisories" and osv_version_matching != "disabled":
                # Only a non-default mode enters the reuse identity, so default checkpoints keep theirs.
                inputs["osv_version_matching"] = {"mode": osv_version_matching, "matcher": osv_matching.SCHEMA}
            build: Callable[[], Derived]
            if query_set == "scanner_correlation":
                syntax, syntax_reference = None, None
                prioritization = accepted_handoff(run_root, "job_review_prioritization")
                if prioritization is not None:
                    syntax_reference = (prioritization.handoff.get("outputs", {}).get("extract.syntax_metrics")
                                        or {}).get("artifact")
                if isinstance(syntax_reference, Mapping):
                    syntax = _read(run_root, syntax_reference)
                evidence = accepted_handoff(run_root, "job_evidence_collection")
                from appsec_review.indexing.sast import scanner_handoff_payload
                scanner = scanner_handoff_payload(run_root, evidence.handoff) if evidence else None
                dispositions = list((scanner or {}).get("dispositions") or [])
                scanner_gaps = tuple(scanner.get("gaps") or ()) if scanner is not None else (
                    "accepted scanner domain handoff unavailable; scanner dispositions are unknown",)
                inputs.update(sast_shards=ShardSet.identities([*view.select("observations"), *view.select("priority")]),
                              syntax_sha256=(syntax_reference or {}).get("sha256"), dispositions=digest(dispositions),
                              scanner_gaps=scanner_gaps,
                              menu_partition_size=int(settings["menu_partition_size"]))
                build = lambda: to_derived(build_scanner_correlation(
                    view, syntax, dispositions, settings, version, scanner_gaps=scanner_gaps), snapshot, max_facts)
            elif query_set == "history_context":
                inputs["metric_shards"] = ShardSet.identities([*view.select("history"), *view.select("priority")])
                inputs["composition_rule"] = "final-fact-budget/1"

                def build() -> Derived:
                    return _bound_composed_product(merge_product(
                        rule.build(context, selected), build_metric_vectors(view), snapshot,
                        area="history_context:metric_vectors"), query_set, max_facts)
            elif query_set == "build_provenance":
                inputs["composition_rule"] = "final-fact-budget/1"
                handoffs = {job_id: accepted_handoff(run_root, job_id) for job_id in ("job_language_build", "job_project_build")}
                inputs.update(command_shards=ShardSet.identities([*view.select("build", job="job_language_build"),
                                                                  *view.select("artifacts")]),
                              captures=sorted(capture_events(run_root, handoffs)),
                              max_build_exec_events=int(settings["max_build_exec_events"]),
                              max_commands_per_action=int(settings["max_commands_per_action"]))

                def build() -> Derived:
                    return _bound_composed_product(merge_product(rule.build(context, selected), build_command_facts(
                        view, run_root, handoffs, max_events=int(settings["max_build_exec_events"]),
                        max_commands=int(settings["max_commands_per_action"])), snapshot,
                        area="build_provenance:command_facts"), query_set, max_facts)
            else:
                build = lambda: rule.build(context, selected)
            published = publish_derived(run_root, index="precomputed", shard_id=f"qs-{query_set}", job_id=JOB_ID,
                                        unit_id=unit.unit_id, rule=query_set, rule_version=version, snapshot=snapshot,
                                        inputs=inputs, build=build, producer={"query_set": query_set},
                                        shared=SharedArtifacts.for_job(unit.job))
            status = {"SUCCEEDED": "complete", "UNAVAILABLE": "unavailable"}.get(published["terminal_status"], "partial")
            unit.job.events.write("PRECOMPUTED_PRODUCT_PUBLISHED", query_set=query_set, status=status,
                                  fact_count=published["counts"].get("entities", 0), reused=published["reused"],
                                  gap_count=len(published["gaps"]),
                                  owasp_manifest_sha256=inputs["owasp"], unit_id=unit.unit_id)
            return {"query_set": query_set, "rule_version": version, "status": status,
                    "fact_count": published["counts"].get("entities", 0), "reused": published["reused"],
                    "counts": published["counts"], "gaps": published["gaps"], "index_identity": published["index_identity"],
                    "terminal_status": "SUCCEEDED" if status == "complete" else "COMPLETED_WITH_GAPS"}
        return handler
    def image_validation(unit: UnitContext) -> Mapping[str, Any]:
        """Rebuild this job's published shard text with the pinned FTS5 image and cross-check it."""
        from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
        settings = settings_of(unit)
        run_root = unit.job.run_root
        mode = str(settings["fts_image_validation"])
        shards = [item["index_identity"] for item in unit.output("links.cross_domain")["links"]]
        shards.extend(unit.output(f"precompute.{name}")["index_identity"] for name in PRODUCT_SETS)
        expected, catalog_gap = None, None
        if mode != "disabled":
            try:
                expected = load_catalog(unit.job.repository_root).tool(fts_worker.TOOL_ID).expected_image_id
            except (KeyError, ValueError, OSError) as exc:
                catalog_gap = f"{fts_worker.TOOL_ID} is not an enabled catalog image: {exc}"
            if expected is None and catalog_gap is None:
                catalog_gap = f"{fts_worker.TOOL_ID} has no pinned image id in the container catalog"

        def factory() -> Any:
            if catalog_gap is not None:
                raise RuntimeError(catalog_gap)
            return executor_factory(unit) if executor_factory else ContainerExecutor(
                load_catalog(unit.job.repository_root), run_root)

        receipt = fts_worker.validate_shards(
            run_root, run_root / "data" / "indexing" / "fts" / unit.job.attempt_id, shards, mode=mode,
            expected_image_id=expected, executor_factory=factory, request_type=ExecutionRequest,
            max_records=int(settings["fts_max_records"]), max_input_bytes=int(settings["fts_max_input_bytes"]),
            max_text_bytes=int(settings["fts_max_text_bytes"]))
        unit.job.events.write("FTS_IMAGE_VALIDATION_COMPLETED", status=receipt["status"],
                              record_count=receipt.get("record_count"), image_id=receipt.get("image_id"))
        return {"artifact": receipt["receipt"], "summary": fts_worker.receipt_summary(receipt),
                "gaps": list(receipt["gaps"]),
                "terminal_status": "SUCCEEDED" if receipt["status"] == "verified" and not receipt["gaps"]
                else "COMPLETED_WITH_GAPS"}

    def audit(unit: UnitContext) -> Mapping[str, Any]:
        document = inputs_of(unit)
        settings = settings_of(unit)
        run_root = unit.job.run_root
        _job_ids, declarations, consumes = providers()
        file_job_steps = document["file_job_steps"]
        file_declarations = {job_id: values for job_id, values in declarations.items() if job_id in file_job_steps}
        active = set(document["registry_jobs"])
        declarations = {job_id: values for job_id, values in declarations.items() if job_id in active}
        consumes = {job_id: tuple(upstream for upstream in values if upstream in active)
                    for job_id, values in consumes.items() if job_id in active}
        handoffs = {job_id: accepted_handoff(run_root, job_id) for job_id in document["registry_jobs"] if job_id != JOB_ID}
        inventory = build_inventory(InventoryInputs(
            run_root=run_root, run_id=unit.job.run_id, target_snapshot=document["target_snapshot"],
            job_steps=document["job_steps"], declarations=declarations, consumes=consumes, handoffs=handoffs,
            unit_statuses=document["unit_statuses"], shards=[*document["shards"], *document["restored_shards"]],
            restored_shards=document["restored_shards"], shard_conflicts=document["shard_conflicts"],
            max_files=int(settings["max_run_files"]),
            managed_publications=unit.job.review_policy.mode.value == "first_party_managed",
            file_job_steps=file_job_steps, file_declarations=file_declarations))
        violations = inventory["audit"]["violations"]
        for job_id in document["registry_configuration_mismatch"]:
            violations.append({"code": "registry_configuration_mismatch", "job_id": job_id, "subject": job_id,
                               "detail": "job is registered but not configured, or configured but not registered"})
        for job_id in document["registry_jobs"]:
            if not declarations.get(job_id):
                violations.append({"code": "undeclared_job", "job_id": job_id, "subject": job_id,
                                   "detail": "registered job declares no datasets"})
        inventory["audit"]["status"] = "FAILED" if violations else "PASSED"
        path = unit.unit_root / "inventory.json"
        atomic_json(path, inventory)
        unit.job.events.write("DATASET_AUDIT_COMPLETED", status=inventory["audit"]["status"],
                              violation_count=len(violations), warning_count=len(inventory["audit"]["warnings"]),
                              unaccounted_file_count=inventory["run_tree"]["unaccounted_count"],
                              row_count=len(inventory["rows"]))
        if violations:
            codes = sorted({item["code"] for item in violations})
            raise ValueError(f"dataset publication audit failed ({len(violations)} reported violations: "
                             f"{', '.join(codes)}; {inventory['run_tree']['unaccounted_count']} unaccounted files); "
                             f"report retained at {path.relative_to(run_root).as_posix()}")
        warnings = [f"{item['code']}: {item['detail']}" for item in inventory["audit"]["warnings"]]
        return {"artifact": _artifact(run_root, path), "row_count": len(inventory["rows"]),
                "audit_status": inventory["audit"]["status"], "violation_count": len(violations),
                "gaps": warnings[:50], "terminal_status": "COMPLETED_WITH_GAPS" if violations or warnings else "SUCCEEDED"}

    def coverage(unit: UnitContext) -> Mapping[str, Any]:
        document, view = shard_view(unit)
        inventory = _read(unit.job.run_root, unit.output("audit.inventory")["artifact"])
        lead_counts = unit.output("precompute.scanner_correlation").get("counts", {})
        leads: dict[str, int] = {}
        for key, value in lead_counts.items():
            if key.startswith("lead_language:"):
                language = matrix.canonical_language(key.split(":", 1)[1])
                leads[language] = leads.get(language, 0) + int(value)
        product_status = {name: {"status": unit.output(f"precompute.{name}")["status"],
                                 "gaps": unit.output(f"precompute.{name}")["gaps"][:10]} for name in PRODUCT_SETS}
        jobs = [{"job_id": job_id, "status": "self" if job_id == JOB_ID else
                 "accepted" if document["handoffs"].get(job_id) else "not_executed"}
                for job_id in document["registry_jobs"]]
        reconciled, discrepancies = input_matrix.reconcile(
            document["registered_jobs"], jobs, inventory["rows"], product_status, JOB_ID,
            disabled_jobs=document.get("disabled_jobs", ()))
        from appsec_review.runtime.inputs import read_input_observations
        consumer_handoffs = {job_id: accepted_handoff(unit.job.run_root, job_id)
                             for job_id in document["registry_jobs"] if job_id != JOB_ID}
        matrices = {"schema": "appsec-review/coverage-matrices/2", "target_snapshot": document["target_snapshot"],
                    "languages": matrix.language_matrix(
                        view.store, leads, enable_swift=unit.job.tools.enable_swift),
                    "build_units": matrix.build_unit_matrix(
                        view.store, codeql_handoff=consumer_handoffs.get("job_codeql_analysis"),
                        target_snapshot=document["target_snapshot"]),
                    "producer_consumer": matrix.producer_consumer_matrix(
                        jobs, document["consumes"], handoffs=consumer_handoffs,
                        observations={name: read_input_observations(unit.job.run_root, value.handoff)
                                      for name, value in consumer_handoffs.items() if value is not None}),
                    "input_sources": reconciled, "input_source_discrepancies": discrepancies,
                    "query_sets": product_status}
        matrices["graph_follow_up"] = graph_follow_up(matrices["languages"])
        path = unit.unit_root / "coverage-matrices.json"
        atomic_json(path, matrices)
        return {"artifact": _artifact(unit.job.run_root, path), "language_count": len(matrices["languages"]),
                "build_unit_count": len(matrices["build_units"]), "gaps": discrepancies,
                "terminal_status": "COMPLETED_WITH_GAPS" if discrepancies else "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        run_root = unit.job.run_root
        document = inputs_of(unit)
        snapshot = document["target_snapshot"]
        inventory = _read(run_root, unit.output("audit.inventory")["artifact"])
        matrices = _read(run_root, unit.output("matrix.coverage")["artifact"])
        product_outputs = [unit.output(f"precompute.{name}") for name in PRODUCT_SETS]
        link_outputs = unit.output("links.cross_domain")["links"]
        fts_summary = unit.output("fts.image_validation")["summary"]
        readiness = products.sanitizer_readiness(
            snapshot, document.get("sanitizer") or {}, int(settings_of(unit)["max_facts_per_product"]))
        completed_self_artifacts = {"accepted_input_summary", "derived_checkpoints", "fts_image_validation"}
        rows = [row for row in inventory["rows"] if row["job_id"] != JOB_ID or
                (row["output_kind"] in completed_self_artifacts and row["disposition"] != "unavailable")]
        rows += _self_rows(unit.job.run_id, snapshot, product_outputs, link_outputs,
                           {"dataset_audit_report": unit.output("audit.inventory")["artifact"],
                            "coverage_matrices": unit.output("matrix.coverage")["artifact"]})

        def build() -> Derived:
            derived = Derived(entities=list(readiness.entities), coverage=list(readiness.coverage),
                              gaps=list(readiness.gaps))
            for row in rows:
                identity = LogicalIdentity.derive(EntityKind.DATASET, snapshot, {"dataset_id": row["dataset_id"]})
                coverage_state = (row.get("coverage") or {}).get("state")
                derived.entities.append(EntityRecord(
                    identity, row["dataset_id"], f"{row['job_id']}/{row['step']}/{row['output_kind']}",
                    f"dataset {row['job_id']} {row['step']} {row['output_kind']} {row['family']} "
                    f"{row['disposition']} {coverage_state}", {**row, "record_type": "dataset",
                                                                "coverage_state": coverage_state}))
            audit_entity = LogicalIdentity.derive(EntityKind.DATASET_AUDIT, snapshot, {"audit": "publication"})
            derived.entities.append(EntityRecord(
                audit_entity, "dataset-audit", "dataset publication audit",
                f"dataset audit {inventory['audit']['status']}",
                {"record_type": "audit", **{key: inventory["audit"][key] for key in ("schema", "status")},
                 "violations": inventory["audit"]["violations"][:200],
                 "warnings": inventory["audit"]["warnings"][:200], "repairs": inventory["audit"]["repairs"][:200],
                 "disposition_counts": inventory["disposition_counts"], "run_tree": inventory["run_tree"]}))
            cells = [*matrices["languages"], *matrices["build_units"], *matrices["producer_consumer"],
                     *({"cell_type": "input_source", **item} for item in matrices["input_sources"]),
                     *({"cell_type": "query_set", "query_set": name, **value}
                       for name, value in matrices["query_sets"].items()),
                     *({"cell_type": "graph_follow_up", **item} for item in matrices["graph_follow_up"]),
                     {**fts_summary, "cell_type": "fts_validation", "query_set": "fts_image_validation"}]
            for cell in cells:
                key = {name: cell.get(name) for name in ("cell_type", "language", "build_unit_id", "consumer",
                                                         "producer", "source", "query_set")}
                identity = LogicalIdentity.derive(EntityKind.COVERAGE_CELL, snapshot, key)
                label = " ".join(str(value) for value in key.values() if value)
                derived.entities.append(EntityRecord(identity, label[:256], label[:256], f"coverage {label}",
                                                     {"record_type": "coverage_cell", **cell}))
            unavailable = sum(1 for row in rows if row["disposition"] == "unavailable")
            derived.coverage.append(("dataset-inventory", "partial" if unavailable else "complete",
                                     f"{unavailable} declared dataset(s) unavailable" if unavailable else None))
            derived.coverage.append(("dataset-audit", "complete" if inventory["audit"]["status"] == "PASSED"
                                     else "partial", None if inventory["audit"]["status"] == "PASSED"
                                     else f"{len(inventory['audit']['violations'])} audit violation(s)"))
            derived.coverage.append(("fts-image-validation", "complete" if fts_summary["status"] == "verified"
                                     and not fts_summary["gaps"] else "partial", "; ".join(fts_summary["gaps"] or [])[:1000] or None))
            if matrices["input_source_discrepancies"]:
                derived.gap("input-source matrix discrepancies: " + "; ".join(matrices["input_source_discrepancies"][:5]))
            return derived

        published = publish_derived(
            run_root, index="inventory", shard_id="dataset-inventory", job_id=JOB_ID, unit_id=unit.unit_id,
            rule="dataset_inventory", rule_version=INVENTORY_RULE, snapshot=snapshot,
            inputs={"inventory": digest(rows), "audit": digest(inventory["audit"]), "matrices": digest(matrices),
                    "fts": digest(fts_summary), "sanitizer": digest(document.get("sanitizer")),
                    "sanitizer_projection": "per-unit-readiness/1",
                    "max_readiness_facts": int(settings_of(unit)["max_facts_per_product"])},
            build=build, shared=SharedArtifacts.for_job(unit.job))
        manifest_reference = document["accepted_manifest"]
        upstream, _ = load_verified_manifest(run_root, run_root / manifest_reference["path"], manifest_reference["sha256"])
        indexes = [as_identity(item) for item in upstream["indexes"] if item.get("producer", {}).get("job") != JOB_ID]
        indexes.extend(as_identity(item) for item in document["restored_shards"])
        indexes.extend(as_identity(item["index_identity"]) for item in [*link_outputs, *product_outputs])
        indexes.append(as_identity(published["index_identity"]))
        manifest_path = run_root / "data" / "indices" / "manifests" / f"review-data-indexing-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=snapshot,
                       target_root=Path(upstream["target_root"]), indexes=indexes,
                       upstream_manifests=(manifest_reference,))
        load_verified_manifest(run_root, manifest_path, file_sha256(manifest_path))
        summary = {"schema": SCHEMA, "audit_status": inventory["audit"]["status"],
                   "sanitizer_readiness": dict(readiness.counts),
                   "fts_image_validation": fts_summary, "rows": len(rows), "restored_shards": len(document["restored_shards"]),
                   "products": {item["query_set"]: {key: item[key] for key in ("status", "fact_count", "reused")}
                                for item in product_outputs},
                   "links": {item["rule"]: {"terminal_status": item["terminal_status"], "reused": item["reused"]}
                             for item in link_outputs}}
        unit.job.events.write("DATASET_INVENTORY_PUBLISHED", row_count=len(rows),
                              product_count=len(product_outputs), audit_status=inventory["audit"]["status"])
        unit.job.events.write(
            "INDEXING_TELEMETRY_RECORDED",
            unit_id=unit.unit_id,
            metrics={
                "indexing.shards_built": len(link_outputs) + len(product_outputs) + 1,
                "indexing.entities_indexed": sum(int(item.get("fact_count", 0)) for item in product_outputs) + len(rows),
                "indexing.threat_boundaries_indexed": next(
                    (int(item.get("fact_count", 0)) for item in product_outputs if item["query_set"] == "threat_boundaries"),
                    0,
                ),
                "build_security.sanitizer_readiness_indexed": len(readiness.entities),
            },
        )
        gaps = [*readiness.gaps, *(f"{item['query_set']}: {item['status']}"
                                 for item in product_outputs if item["status"] != "complete")]
        return {"schema": SCHEMA, "index_manifest": _artifact(run_root, manifest_path),
                "index_identity": published["index_identity"], "item_count": len(rows), "summary": summary,
                "gaps": gaps, "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    units: list[Unit] = [Unit("load.accepted_inputs", load), Unit("links.cross_domain", links, ("load.accepted_inputs",))]
    product_units = tuple(f"precompute.{name}" for name in PRODUCT_SETS)
    units.extend(Unit(unit_id, precompute(name), ("load.accepted_inputs", "links.cross_domain"))
                 for unit_id, name in zip(product_units, PRODUCT_SETS))
    units.append(Unit("fts.image_validation", image_validation, ("links.cross_domain", *product_units)))
    units.append(Unit("audit.inventory", audit, ("load.accepted_inputs", "links.cross_domain", *product_units,
                                                 "fts.image_validation")))
    units.append(Unit("matrix.coverage", coverage, ("load.accepted_inputs", "audit.inventory", *product_units)))
    units.append(Unit("publish.inventory_index", publish,
                      ("load.accepted_inputs", "links.cross_domain", *product_units, "fts.image_validation",
                       "audit.inventory", "matrix.coverage")))
    return Job(JOB_ID, "review_data_indexing", UnitExecutor(tuple(units)).execute, input_validators=(_validate,),
               schema_identity=SCHEMA, units=tuple(units),
               datasets=DATASETS, contract=CONTRACT, external_input_identity=feed_input_identity)


# Query sets this job does not produce: the stage-3 compositions over accepted graph families and
# the sets whose producer is planned. Graph facts themselves are not query sets (they are the
# ``graph`` index of job_code_graph_index), so the retired graph set names never appear here.
GRAPH_FOLLOW_UP = (
    ("hotspot_context", "stage-3 composition of priority items with accepted graph families"),
    ("review_package", "stage-3 package composition over accepted indices, including graph families"),
    ("redacted_secret_exposure", "secret-scanner sink joins"),
    ("contract_enforcement", "interface-contract producer (planned)"),
    ("deployment_exposure", "deployment-topology producer (planned)"),
    ("test_intent", "assertion semantics and negative-case links beyond document_context"),
)
GRAPH_DEPENDENT = frozenset({"hotspot_context", "review_package"})
FOLLOW_UP_STATUS = "pending_follow_up"


def graph_follow_up(languages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Follow-up rows; graph-dependent sets carry the accepted ``code_graph`` lane states."""
    by_state: dict[str, list[str]] = {"complete": [], "partial": [], "unavailable": []}
    for row in languages:
        state = str(row.get("lanes", {}).get("code_graph", {}).get("state", "unavailable"))
        by_state.setdefault(state, []).append(str(row.get("language")))
    accepted = sorted(by_state["complete"] + by_state["partial"])
    rows = []
    for name, reason in GRAPH_FOLLOW_UP:
        item: dict[str, Any] = {"query_set": name, "status": FOLLOW_UP_STATUS, "missing_prerequisite": reason}
        if name in GRAPH_DEPENDENT:
            item["graph_coverage"] = {state: sorted(values) for state, values in sorted(by_state.items())}
            if not accepted:
                item["missing_prerequisite"] = (f"{reason}; no language has accepted graph coverage "
                                                f"({matrix.GRAPH_JOB} not run, unregistered or unavailable)")
        rows.append(item)
    return rows


def _self_rows(run_id: str, snapshot: str, product_outputs: Sequence[Mapping[str, Any]],
               link_outputs: Sequence[Mapping[str, Any]],
               completed_artifacts: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Inventory rows for this job's own indexed outputs, which exist only after its units ran."""
    declarations = {item.output_kind: item for item in DATASETS}
    rows: list[dict[str, Any]] = []

    def row(kind: str, scope: str, identity: Mapping[str, Any], state: str, gaps: Sequence[str],
            query_set: str | None = None) -> dict[str, Any]:
        declaration = declarations[kind]
        return {"schema": "appsec-review/dataset-inventory-row/1",
                "dataset_id": dataset_id(run_id, JOB_ID, declaration.step, scope, kind), "run_id": run_id,
                "job_id": JOB_ID, "step": declaration.step, "output_kind": kind, "scope": scope,
                "family": declaration.family, "description": declaration.description,
                "dataset_schema": declaration.schema, "target_snapshot": snapshot,
                "sensitivity": declaration.sensitivity, "declared_disposition": declaration.disposition,
                "disposition": "unavailable" if state == "unavailable" else declaration.disposition,
                "query_route": declaration.query_route, "exception_reason": declaration.reason,
                "store": declaration.store, "producer": {"job": JOB_ID},
                "index": {"name": identity["name"], "shard_id": identity["shard_id"], "sha256": identity["sha256"],
                          "fingerprint": identity["fingerprint"], "schema": identity["schema"]},
                "artifacts": None, "record_count": None, "relation_count": None, "query_set": query_set,
                "coverage": {"state": state, "reason": gaps[0] if gaps else None, "gaps": list(gaps)[:10],
                             "gap_count": len(gaps), "truncation_count": 0}}

    for item in product_outputs:
        rows.append(row("precomputed_products", item["query_set"], item["index_identity"], item["status"],
                        item["gaps"], item["query_set"]))
    for item in link_outputs:
        state = {"SUCCEEDED": "complete", "UNAVAILABLE": "unavailable"}.get(item["terminal_status"], "partial")
        rows.append(row("cross_domain_links", item["rule"], item["index_identity"], state, item["gaps"]))

    for kind, reference in sorted(completed_artifacts.items()):
        declaration = declarations[kind]
        rows.append({"schema": "appsec-review/dataset-inventory-row/1",
                     "dataset_id": dataset_id(run_id, JOB_ID, declaration.step, "run", kind),
                     "run_id": run_id, "job_id": JOB_ID, "step": declaration.step,
                     "output_kind": kind, "scope": "run", "family": declaration.family,
                     "description": declaration.description, "dataset_schema": declaration.schema,
                     "target_snapshot": snapshot, "sensitivity": declaration.sensitivity,
                     "declared_disposition": declaration.disposition, "disposition": declaration.disposition,
                     "query_route": declaration.query_route, "exception_reason": declaration.reason,
                     "store": declaration.store, "producer": {"job": JOB_ID}, "index": None,
                     "artifacts": {"file_count": 1, "size_bytes": reference.get("size_bytes"),
                                   "references": [{"reference": reference["path"],
                                                   "sha256": reference["sha256"]}]},
                     "record_count": None, "relation_count": None,
                     "coverage": {"state": "complete", "reason": None, "gaps": [],
                                  "gap_count": 0, "truncation_count": 0}})

    # A shard cannot contain its own SHA-256 without a recursive hash. Its accepted manifest
    # supplies the content hash, and the row names the exact shard identity to resolve there.
    declaration = declarations["dataset_inventory"]
    rows.append({"schema": "appsec-review/dataset-inventory-row/1",
                 "dataset_id": dataset_id(run_id, JOB_ID, declaration.step, "self", "dataset_inventory"),
                 "run_id": run_id, "job_id": JOB_ID, "step": declaration.step,
                 "output_kind": "dataset_inventory", "scope": "self", "family": declaration.family,
                 "description": declaration.description, "dataset_schema": declaration.schema,
                 "target_snapshot": snapshot, "sensitivity": declaration.sensitivity,
                 "declared_disposition": declaration.disposition, "disposition": "indexed",
                 "query_route": declaration.query_route, "exception_reason": "self hash resolves through accepted manifest",
                 "store": declaration.store, "producer": {"job": JOB_ID},
                 "index": {"name": "inventory", "shard_id": "dataset-inventory",
                           "hash_resolution": "accepted_manifest"},
                 "artifacts": None, "record_count": None, "relation_count": None,
                 "coverage": {"state": "complete", "reason": None, "gaps": [],
                              "gap_count": 0, "truncation_count": 0}})
    return rows
