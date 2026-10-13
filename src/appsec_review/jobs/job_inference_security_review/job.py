"""``job_inference_security_review``: the slice 1 visible units of design R1.

Units, in dependency order: ``scope.accept_manifest``, ``scope.assemble_scope``,
``packages.assemble_lead_packages``, ``packages.assemble_hunt_packages``, ``lead_review.teams``,
``hunt_review.teams``, ``merge.claims``, ``adjudicate.apply_policy``, ``scoring.score_claims``,
``completeness.audit``, ``publication.publish_claim_ledger``, ``publication.publish_handoff``.
The two lane units depend only on their own package unit, so Dagster runs them in parallel; actual
model concurrency is the run-wide review-team semaphore. Ordinary failures become typed gaps and a
``DEGRADED`` handoff; only :class:`IntegrityError` fails a unit and blocks publication.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

from appsec_review.config.inference_review import (
    JOB_ID, InferenceSecurityReviewSettings, semantic_settings_sha256,
)
from appsec_review.graph.contract import ADMISSIBILITY_RULE as GRAPH_FACT_ADMISSIBILITY_RULE, FACT_PREDICATES_RULE
from appsec_review.guidance import load_persona_covers, load_registry
from appsec_review.guidance.coverage import crosswalk_tags
from appsec_review.guidance.routing import unit_sources
from appsec_review.indexing.store import open_shard
from appsec_review.jobs.job_security_tagging.crosswalk import load_crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import load_vocabulary
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review import obligations
from appsec_review.review.budget import JobBudget
from appsec_review.review.claims import normalize_cwe
from appsec_review.review.identity import sha256_hex
from appsec_review.review.ledger import LedgerWriter, project
from appsec_review.review.models import IntegrityError, Lane, Predicate
from appsec_review.review.packages import (
    ASSEMBLY_RULE, PackageSettings, assemble_packages, publish_packages, verify_package_manifest,
)
from appsec_review.review.references import load_cwe_reference
from appsec_review.review.scoring.cwe_impact import ImpactCatalog
from appsec_review.review.scope import AcceptedScope, accept_manifest
from appsec_review.review.teams import ReviewTeamSemaphore
from appsec_review.review.scoring.evidence_source import AcceptedEvidenceSource
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from . import stages
from .datasets import CONSUMES, DATASETS
from .schemas import SchemaSet, SCHEMA_DIRECTORY
from .teams import PackageWork, ReviewContext, lane_failure, run_lane

SCHEMA = "appsec-review/inference-security-review/1"
TOPOLOGY = {"scope": ("accept_manifest", "assemble_scope"),
            "packages": ("assemble_lead_packages", "assemble_hunt_packages"),
            "lead_review": ("teams",), "hunt_review": ("teams",), "merge": ("claims",),
            "adjudicate": ("apply_policy",), "scoring": ("score_claims",), "completeness": ("audit",),
            "publication": ("publish_claim_ledger", "publish_handoff")}
LEDGER_UNITS = ("lead_review.teams", "hunt_review.teams", "adjudicate.apply_policy", "scoring.score_claims",
                "completeness.audit")
TAXONOMY = Path("data") / "reference" / "taxonomy"
RULE_PREDICATES_VERSION = "tool-rule-predicates/1"
# The predicates a producing rule's versioned mapping names for its own tool observation (design R3).
# A tool observation is direct evidence only for these; every other predicate treats it as indirect.
TOOL_RULE_PREDICATES: Mapping[str, tuple[Predicate, ...]] = {
    "source_sast": (Predicate.AFFECTED_CONSTRUCT,),
    "codeql": (Predicate.AFFECTED_CONSTRUCT, Predicate.SOURCE_TO_SINK_REACHABILITY),
    "artifact_scanner": (Predicate.AFFECTED_CONSTRUCT,),
    "dependency_advisory": (Predicate.AFFECTED_CONSTRUCT,),
    "ci_rule": (Predicate.AFFECTED_CONSTRUCT, Predicate.CONFIGURATION_ENABLES),
    "post_build_hardening": (Predicate.AFFECTED_CONSTRUCT, Predicate.CONFIGURATION_ENABLES),
    "owasp_control": (Predicate.MISSING_OR_INEFFECTIVE_GUARD,),
}
# Ground truth and target-owned agent guidance are never readable: a manifest naming an evaluator
# root fails startup, and target guidance files are removed from every capability's entity scope.
EVALUATOR_ROOTS = ("appsec-multi-vuln-guide",)
TARGET_GUIDANCE = re.compile(
    r"(?i)(^|/)(agents\.md|claude\.md|gemini\.md|\.cursorrules|\.windsurfrules|\.clinerules|"
    r"copilot-instructions\.md)$|(^|/)\.cursor/rules/|(^|/)\.github/instructions/")

InferFactory = Callable[[], Callable[..., Any]]


def _default_infer():
    from appsec_review.inference import infer
    return infer


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": Path(path).resolve().relative_to(run_root.resolve()).as_posix(), "sha256": file_sha256(path),
            "size_bytes": Path(path).stat().st_size}


def _read(run_root: Path, reference: Mapping[str, Any]) -> Any:
    path = (run_root / str(reference["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != reference["sha256"]:
        raise IntegrityError(f"run-owned artifact changed after acceptance: {reference['path']}")
    return json.loads(path.read_text(encoding="utf-8"))


def _write(unit: UnitContext, name: str, document: Any) -> dict[str, Any]:
    path = unit.unit_root / name
    atomic_json(path, document)
    return _artifact(unit.job.run_root, path)


def _settings(unit: UnitContext) -> InferenceSecurityReviewSettings:
    settings = unit.job.config.typed_settings
    if not isinstance(settings, InferenceSecurityReviewSettings):
        raise ValueError("job_inference_security_review settings are not typed")
    return settings


def _status(gaps: Sequence[Any]) -> str:
    return "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"


def _check_isolation(scope: AcceptedScope) -> None:
    """Startup validator: no accepted input may name an evaluator root (design rule 4)."""
    manifest = json.loads(scope.manifest_path.read_text(encoding="utf-8"))
    texts = [str(manifest.get("target_root", "")), *(str(shard.get("relative_path", "")) for shard in scope.shards),
             *(item.path for item in scope.source_files)]
    for text in texts:
        parts = {part.lower() for part in PurePosixPath(text.replace("\\", "/")).parts}
        if any(root in parts for root in EVALUATOR_ROOTS):
            raise IntegrityError("accepted inputs name an evaluator root; review inputs must never reach it")


def _scope(unit: UnitContext) -> AcceptedScope:
    scope = accept_manifest(unit.job.run_root)
    pinned = unit.output("scope.accept_manifest")["manifest_sha256"] if unit.unit_id != "scope.accept_manifest" else None
    if pinned is not None and scope.manifest_sha256 != pinned:
        raise IntegrityError("accepted manifest changed during the review attempt")
    _check_isolation(scope)
    return scope


def _excluded(scope: AcceptedScope) -> set[str]:
    return {item.identity for item in scope.source_files if TARGET_GUIDANCE.search(item.path)
            or any(root in item.path.lower().split("/") for root in EVALUATOR_ROOTS)}


def _membership(scope: AcceptedScope, entities: set[str]) -> dict[str, set[str]]:
    """Accepted shards (name/shard@sha256) holding each entity as a row or a relation endpoint."""
    found: dict[str, set[str]] = defaultdict(set)
    ordered = sorted(entities)
    for shard in scope.shards:
        label = f"{shard['name']}/{shard.get('shard_id', 'default')}@{shard['sha256']}"
        with open_shard(scope.run_root, shard) as database:
            for offset in range(0, len(ordered), 400):
                chunk = ordered[offset:offset + 400]
                marks = ",".join("?" for _ in chunk)
                for (identity,) in database.execute(f"SELECT identity FROM entities WHERE identity IN ({marks})", chunk):
                    found[identity].add(label)
                for row in database.execute(f"SELECT source_id, target_id FROM relations WHERE source_id IN ({marks}) "
                                            f"OR target_id IN ({marks})", [*chunk, *chunk]):
                    for identity in row:
                        if identity in entities:
                            found[identity].add(label)
    return found


def _taxonomy(repository_root: Path):
    root = repository_root / TAXONOMY
    vocabulary = load_vocabulary(root / "vocabulary.json", file_sha256(root / "vocabulary.json"))
    crosswalk = load_crosswalk(root / "crosswalk.json", file_sha256(root / "crosswalk.json"), vocabulary)
    return vocabulary, crosswalk


def run_sources(query_sets: Iterable[str]) -> tuple[str, ...]:
    """Hunt-strategy data sources available to every unit of the run.

    Only ``control_evidence`` is run-wide (``owasp_workbench``). Sink facts and the entry-point
    catalog are per unit: :func:`available_sources` adds them from the package's accepted graph
    families. Symbol links unlock no strategy.
    """
    return ("owasp_workbench",) if "control_evidence" in set(query_sets) else ()


def available_sources(query_sets: Iterable[str], graph_families: Iterable[str]) -> tuple[str, ...]:
    """``source_sink_facts`` when the unit's scope has an accepted ``sink_site`` family and
    ``entry_point_catalog`` when it has an accepted ``entry_point`` family, plus the run sources."""
    return unit_sources(run_sources(query_sets), graph_families)


# Rule versions that decide which evidence a cell's citations may satisfy; part of every package's
# reuse basis so a change to graph admissibility invalidates reuse of the cells it affects.
EVIDENCE_RULES = {"rule_predicates": RULE_PREDICATES_VERSION,
                  "admissibility": obligations.ADMISSIBILITY_RULES_VERSION,
                  "graph_fact_predicates": FACT_PREDICATES_RULE,
                  "graph_fact_admissibility": GRAPH_FACT_ADMISSIBILITY_RULE,
                  "obligation_policy_sha256": obligations.POLICY_SHA256}


def package_works(run_root: Path, packages_doc: Mapping[str, Any]) -> list[PackageWork]:
    """The lane's verified packages as team work items."""
    works = []
    for record in packages_doc["packages"]:
        path = Path(run_root) / record["path"]
        if not path.is_file() or file_sha256(path) != record["sha256"]:
            raise IntegrityError(f"review package changed after assembly: {record['package_id']}")
        works.append(PackageWork(record["package_id"], Lane(record["lane"]), record["sha256"],
                                 json.loads(path.read_text(encoding="utf-8")), tuple(record["rank"]),
                                 record["basis"], tuple(record["entities"]), record["unit_key"]))
    return works


def review_context(*, run_root: Path, run_id: str, attempt_root: Path, repository_root: Path,
                   settings: InferenceSecurityReviewSettings, infer: Callable[..., Any], manifest_sha256: str,
                   packages_doc: Mapping[str, Any], scope_out: Mapping[str, Any]) -> ReviewContext:
    """Everything a lane needs: pinned retrieval core, guidance inputs, budget, semaphore, policy."""
    root = Path(repository_root)
    vocabulary, crosswalk = _taxonomy(root)
    registry = load_registry(root)
    core = RetrievalCore(Path(run_root).parent, run_id, manifest_sha256=manifest_sha256)
    query_sets = set(_read(Path(run_root), scope_out["artifact"])["query_sets"])
    return ReviewContext(
        run_root=Path(run_root), run_id=run_id, repository_root=root, settings=settings, core=core, infer=infer,
        receipts_root=Path(run_root) / "data" / "jobs" / JOB_ID / "cells",
        budget=JobBudget(Path(attempt_root) / "budget", settings.budgets),
        semaphore=ReviewTeamSemaphore.for_run(Path(run_root), settings.teams.review_teams),
        vocabulary=vocabulary, crosswalk=crosswalk, covers=load_persona_covers(root, registry),
        role_tools={name: tuple(value.get("tools", ())) for name, value in registry["roles"].items()},
        schemas=SchemaSet(root / SCHEMA_DIRECTORY),
        accepted_cwe_ids=frozenset(packages_doc["accepted_cwe_ids"]),
        rule_predicates={key: tuple(Predicate(item) for item in values)
                         for key, values in packages_doc["rule_predicates"].items()},
        source_languages=dict(scope_out["source_languages"]),
        build_unit_languages={key: tuple(value) for key, value in scope_out["build_unit_languages"].items()},
        index_names=tuple(sorted({str(shard["name"]) for shard in core.manifest["indexes"]})),
        available_sources=run_sources(query_sets),
        max_page_size=settings.packages.max_page_size, max_depth=settings.packages.max_depth)


def build_job(*, infer: Callable[..., Any] | None = None, repository_root: Path | None = None) -> Job:
    """Build the job; ``infer`` and ``repository_root`` are injectable for acceptance tests."""

    def repo(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root).resolve()

    def job_data(unit: UnitContext) -> Path:
        return unit.job.run_root / "data" / "jobs" / JOB_ID

    # scope --------------------------------------------------------------------------------------
    def accept(unit: UnitContext) -> Mapping[str, Any]:
        scope = _scope(unit)
        document = {"schema": "appsec-review/inference-review-accepted-scope/1", "run_id": scope.run_id,
                    "manifest_sha256": scope.manifest_sha256, "target_snapshot": scope.target_snapshot,
                    "manifest_path": scope.manifest_path.relative_to(unit.job.run_root.resolve()).as_posix(),
                    "shards": [{"name": str(shard["name"]), "shard_id": str(shard.get("shard_id", "default")),
                                "sha256": str(shard["sha256"])} for shard in scope.shards]}
        unit.job.events.write("INFERENCE_REVIEW_SCOPE_ACCEPTED", manifest_sha256=scope.manifest_sha256,
                              shard_count=len(scope.shards))
        return {"artifact": _write(unit, "accepted-scope.json", document), "manifest_sha256": scope.manifest_sha256,
                "shard_count": len(scope.shards), "gaps": [], "terminal_status": "SUCCEEDED"}

    def assemble_scope(unit: UnitContext) -> Mapping[str, Any]:
        scope = _scope(unit)
        evidence_map = scope.evidence_map()
        gaps = [f"{gap.producer}:{gap.scope}: {gap.state}" for gap in scope.gaps]
        return {"artifact": _write(unit, "evidence-map.json", evidence_map),
                "evidence_map_sha256": sha256_hex(evidence_map),
                "components": sorted(item.identity for item in scope.components),
                "source_languages": {item.identity: item.language for item in scope.source_files if item.language},
                "build_unit_languages": {item.build_unit_id: list(item.languages) for item in scope.build_units},
                "scope_gaps": [gap.record() for gap in scope.gaps], "gaps": gaps[:200],
                "terminal_status": _status(gaps)}

    # packages -----------------------------------------------------------------------------------
    def assemble(lane: Lane) -> Callable[[UnitContext], Mapping[str, Any]]:
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            scope = _scope(unit)
            settings = _settings(unit)
            # Claim CWEs validate against the run-pinned MITRE CWE catalog; an unpinned, mismatched or
            # stale catalog falls back to the rule/crosswalk CWE set with a recorded coverage gap.
            reference = load_cwe_reference(unit.job.run_root)
            assembly = assemble_packages(scope, PackageSettings.from_review_settings(settings),
                                         cwe_reference=reference)
            manifest_path = publish_packages(assembly, unit.unit_root / "assembly")
            excluded = _excluded(scope)
            mine = [package for package in assembly.packages if package.lane == lane.value]
            entities = {package.package_id: tuple(sorted(set(package.document()["retrieval"]["entity_ids"]) - excluded))
                        for package in mine}
            membership = _membership(scope, {item for values in entities.values() for item in values})
            positions = {unit_row["unit_key"]: unit_row["position"] for unit_row in assembly.manifest["units"]}
            leads = [lead for package in assembly.packages for lead in package.document()["lead_menu"]]
            fallback = {normalize_cwe(cwe) for lead in leads for cwe in lead.get("rule_cwe", ())}
            _vocabulary, crosswalk = _taxonomy(repo(unit))
            fallback |= {normalize_cwe(tag.split(":", 1)[1]) for tag in crosswalk_tags(crosswalk)
                         if tag.startswith("cwe:")}
            reference = reference.with_fallback(frozenset(item for item in fallback if item))
            cwe_ids = set(reference.accepted_ids)
            records = []
            for package in mine:
                document = package.document()
                if lane is Lane.LEAD:
                    rank = (0 if document["lead_menu"][0]["reported_severity"] == "critical" else 1, package.package_id)
                else:
                    rank = (int(positions[package.unit_key]), package.package_id)
                sanitized = {key: value for key, value in document.items()
                             if key not in {"package_id", "manifest_sha256", "input_fingerprint", "run_id"}}
                shards = sorted({label for identity in entities[package.package_id]
                                 for label in membership.get(identity, ())})
                basis = sha256_hex({"package": sanitized, "shards": shards, "assembly": ASSEMBLY_RULE,
                                    **EVIDENCE_RULES})
                records.append({"package_id": package.package_id, "kind": package.kind, "lane": lane.value,
                                "sha256": package.sha256, "unit_key": package.unit_key, "rank": list(rank),
                                "basis": basis, "dependency_shards": shards,
                                "entities": list(entities[package.package_id]),
                                "path": (manifest_path.parent / "packages" / f"{package.package_id}.json")
                                .resolve().relative_to(unit.job.run_root.resolve()).as_posix()})
            document = {
                "schema": "appsec-review/inference-review-lane-packages/1", "lane": lane.value,
                "package_manifest": _artifact(unit.job.run_root, manifest_path),
                "package_manifest_content_sha256": assembly.manifest["content_sha256"],
                "lane_counts": {item.value: sum(1 for package in assembly.packages if package.lane == item.value)
                                for item in Lane},
                "packages": sorted(records, key=lambda item: (item["rank"], item["package_id"])),
                "accepted_cwe_ids": sorted(item for item in cwe_ids if item),
                "cwe_reference": reference.record(),
                "rule_predicates": {lead["observation_id"]: [item.value for item in
                                                             TOOL_RULE_PREDICATES.get(lead["lead_family"], ())]
                                    for lead in sorted(leads, key=lambda item: item["observation_id"])},
                "units": [{"unit_key": row["unit_key"], "position": row["position"], "hunted": row["hunted"]}
                          for row in assembly.manifest["units"]],
            }
            gaps = [f"{gap.producer}:{gap.scope}: {gap.state}" for gap in assembly.gaps]
            if reference.gap:
                gaps.insert(0, f"cwe_reference: {reference.gap}; claim CWEs validate against the "
                               f"{len(cwe_ids)} rule/crosswalk CWE ids only")
            unit.job.events.write("INFERENCE_REVIEW_PACKAGES_ASSEMBLED", lane=lane.value, package_count=len(records))
            return {"artifact": _write(unit, f"{lane.value}-packages.json", document),
                    "package_count": len(records), "gaps": gaps[:200], "terminal_status": _status(gaps)}
        return handler

    # lanes --------------------------------------------------------------------------------------
    def review(lane: Lane) -> Callable[[UnitContext], Mapping[str, Any]]:
        def handler(unit: UnitContext) -> Mapping[str, Any]:
            run_root = unit.job.run_root
            settings = _settings(unit)
            packages_doc = _read(run_root, unit.output(f"packages.assemble_{lane.value}_packages")["artifact"])
            scope_out = unit.output("scope.assemble_scope")
            works = package_works(run_root, packages_doc)
            ledger_path = unit.unit_root / "ledger.jsonl"
            other = Lane.HUNT if lane is Lane.LEAD else Lane.LEAD
            try:
                ctx = review_context(
                    run_root=run_root, run_id=unit.job.run_id, attempt_root=unit.job.attempt_root,
                    repository_root=repo(unit), settings=settings, infer=infer or _default_infer(),
                    manifest_sha256=unit.output("scope.accept_manifest")["manifest_sha256"],
                    packages_doc=packages_doc, scope_out=scope_out)
                document = run_lane(ctx, lane, works, other_lane_count=int(packages_doc["lane_counts"][other.value]),
                                    ledger_path=ledger_path, stream=unit.unit_id,
                                    signal_dir=unit.job.attempt_root / "lanes")
            except IntegrityError:
                raise
            except Exception as exc:  # an entire lane failing is an ordinary, accounted gap
                if ledger_path.exists():
                    ledger_path.unlink()
                document = lane_failure(lane, works, f"{type(exc).__name__}", ledger_path, unit.unit_id)
                unit.job.events.write("INFERENCE_REVIEW_LANE_FAILED", lane=lane.value, error_type=type(exc).__name__)
            document["ledger_shard"]["path"] = _artifact(run_root, ledger_path)["path"]
            gaps = [f"{lane.value}: {document['counts'].get('gaps', 0)} gaps"] if document["counts"].get("gaps") else []
            unit.job.events.write("INFERENCE_REVIEW_LANE_COMPLETED", lane=lane.value, **{
                key: value for key, value in document["counts"].items()})
            return {"artifact": _write(unit, "lane.json", document),
                    "ledger_shard": _artifact(run_root, ledger_path), "counts": document["counts"],
                    "gaps": gaps, "terminal_status": _status(gaps)}
        return handler

    def lane_documents(unit: UnitContext) -> list[Mapping[str, Any]]:
        return [_read(unit.job.run_root, unit.output(f"{lane}_review.teams")["artifact"]) for lane in ("lead", "hunt")]

    def shard_paths(unit: UnitContext, units: Sequence[str]) -> list[Path]:
        paths = []
        for unit_id in units:
            reference = unit.output(unit_id)["ledger_shard"]
            path = (unit.job.run_root / reference["path"]).resolve()
            if file_sha256(path) != reference["sha256"]:
                raise IntegrityError(f"ledger shard changed after its unit sealed it: {unit_id}")
            paths.append(path)
        return paths

    def merge(unit: UnitContext) -> Mapping[str, Any]:
        lanes = lane_documents(unit)
        entities = {}
        for lane in ("lead", "hunt"):
            document = _read(unit.job.run_root, unit.output(f"packages.assemble_{lane}_packages")["artifact"])
            entities.update({item["package_id"]: item["entities"] for item in document["packages"]})
        merged = stages.merge_claims(lanes, shard_paths(unit, LEDGER_UNITS[:2]), entities,
                                     unit.output("scope.assemble_scope")["components"])
        return {"artifact": _write(unit, "merge.json", merged), "claim_count": len(merged["claims"]),
                "duplicate_proposal_count": sum(sum(item.values()) for item in merged["duplicate_proposals"].values()),
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def adjudicate_unit(unit: UnitContext) -> Mapping[str, Any]:
        merged = _read(unit.job.run_root, unit.output("merge.claims")["artifact"])
        projection = project(stages.merge_verified(shard_paths(unit, LEDGER_UNITS[:2])).events)
        if projection.head != merged["ledger_head_sha256"]:
            raise IntegrityError("lane ledger changed between merge and adjudication")
        ledger_path = unit.unit_root / "ledger.jsonl"
        document = stages.apply_policy(merged, projection, ledger_path, unit.unit_id)
        return {"artifact": _write(unit, "adjudications.json", document),
                "ledger_shard": _artifact(unit.job.run_root, ledger_path), "states": document["states"],
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def score(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        adjudications = _read(unit.job.run_root, unit.output("adjudicate.apply_policy")["artifact"])
        projection = project(stages.merge_verified(shard_paths(unit, LEDGER_UNITS[:3])).events)
        ledger_path = unit.unit_root / "ledger.jsonl"
        merged = _read(unit.job.run_root, unit.output("merge.claims")["artifact"])
        documents = {}
        for lane in ("lead", "hunt"):
            packages_doc = _read(unit.job.run_root, unit.output(f"packages.assemble_{lane}_packages")["artifact"])
            documents.update({work.package_id: work.document for work in package_works(unit.job.run_root,
                                                                                     packages_doc)})
        scope = _scope(unit)
        # Factors are derived only from accepted, re-resolved evidence and accepted tags.
        evidence = AcceptedEvidenceSource(
            RetrievalCore(Path(unit.job.run_root).parent, scope.run_id,
                          manifest_sha256=scope.manifest_sha256), scope)
        # impact_class is derived from the run-pinned MITRE CWE catalog (decision 11); an unpinned or
        # mismatched catalog derives nothing, and a stale one derives with the stale gap recorded.
        catalog = ImpactCatalog.from_reference(load_cwe_reference(unit.job.run_root))
        document = stages.score_claims(adjudications["adjudications"], projection,
                                       settings.scoring.cwe_impact_overrides, unit.unit_root / "scores", ledger_path,
                                       unit.unit_id, SchemaSet(repo(unit) / SCHEMA_DIRECTORY),
                                       references=stages.claim_references(merged, documents),
                                       scoring=settings.scoring, evidence=evidence, cwe_catalog=catalog)
        gaps: list[str] = []
        return {"artifact": _write(unit, "scores.json", document),
                "ledger_shard": _artifact(unit.job.run_root, ledger_path), "score_count": len(document["scores"]),
                "gaps": gaps, "terminal_status": "SUCCEEDED"}

    def completeness(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        lanes = lane_documents(unit)
        packages = _read(unit.job.run_root, unit.output("packages.assemble_hunt_packages")["artifact"])
        ledger_path = unit.unit_root / "ledger.jsonl"
        writer = LedgerWriter(ledger_path, unit.unit_id)
        for gap in stages.completeness_gaps(packages["units"], unit.output("scope.assemble_scope")["scope_gaps"],
                                            packages.get("cwe_reference")):
            writer.record_gap(gap)
        writer.seal()
        paths = shard_paths(unit, LEDGER_UNITS[:4]) + [ledger_path]
        accounting, projection, merged = stages.audit(lanes, paths, settings.lanes.incomplete_gap_ratio)
        matrix = stages.coverage_matrix(lanes[1], packages["units"])
        matrix_ref = _write(unit, "coverage-matrix.json", matrix)
        document = {"schema": "appsec-review/inference-review-completeness/1", "ledger_head_sha256": merged.head,
                    "projection_sha256": projection.sha256(), "accounting": accounting.to_json(),
                    "status": stages.handoff_status(accounting), "coverage_matrix": matrix_ref}
        gaps = ([f"review_incomplete: gap ratio {accounting.gap_ratio:.3f}"] if accounting.review_incomplete else []) + (
            [f"accounting violation: {gap.reason}" for gap in accounting.violations])
        return {"artifact": _write(unit, "completeness.json", document),
                "ledger_shard": _artifact(unit.job.run_root, ledger_path), "status": document["status"],
                "review_incomplete": accounting.review_incomplete, "gaps": gaps[:50],
                "terminal_status": "SUCCEEDED" if document["status"] == "COMPLETE" else "COMPLETED_WITH_GAPS"}

    # publication --------------------------------------------------------------------------------
    def publish_ledger(unit: UnitContext) -> Mapping[str, Any]:
        _scope(unit)                                     # re-verifies every accepted shard from bytes
        for lane in ("lead", "hunt"):
            document = _read(unit.job.run_root, unit.output(f"packages.assemble_{lane}_packages")["artifact"])
            reference = document["package_manifest"]
            verify_package_manifest(unit.job.run_root / reference["path"])
            _read(unit.job.run_root, reference)
        completeness_doc = _read(unit.job.run_root, unit.output("completeness.audit")["artifact"])
        merged = stages.merge_verified(shard_paths(unit, LEDGER_UNITS))
        projection = project(merged.events)
        if merged.head != completeness_doc["ledger_head_sha256"] or projection.sha256() != completeness_doc[
                "projection_sha256"]:
            raise IntegrityError("claim ledger changed between completeness audit and publication")
        checked = stages.verify_receipts(projection, job_data(unit) / "cells")
        head = stages.write_ledger(merged, projection, unit.unit_root)
        return {"artifact": _write(unit, "ledger-head-receipt.json", {**head, "receipts_verified": checked}),
                "ledger": _artifact(unit.job.run_root, unit.unit_root / "claim-ledger.jsonl"),
                "projection": _artifact(unit.job.run_root, unit.unit_root / "projection.json"),
                "ledger_head_sha256": merged.head, "gaps": [], "terminal_status": "SUCCEEDED"}

    def publish_handoff(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        schemas = SchemaSet(repo(unit) / SCHEMA_DIRECTORY)
        ledger_out = unit.output("publication.publish_claim_ledger")
        ledger_file = unit.job.run_root / ledger_out["ledger"]["path"]
        if file_sha256(ledger_file) != ledger_out["ledger"]["sha256"]:
            raise IntegrityError("published claim ledger changed before the handoff")
        paths = shard_paths(unit, LEDGER_UNITS)
        accounting, projection, merged = stages.audit(lane_documents(unit), paths, settings.lanes.incomplete_gap_ratio)
        if ledger_file.read_bytes() != b"".join(canonical_json(event) for event in merged.events):
            raise IntegrityError("published claim ledger does not revalidate from its shards")
        completeness_doc = _read(unit.job.run_root, unit.output("completeness.audit")["artifact"])
        if accounting.to_json() != completeness_doc["accounting"]:
            raise IntegrityError("claim accounting is not deterministic between audit and publication")
        adjudications = _read(unit.job.run_root, unit.output("adjudicate.apply_policy")["artifact"])["adjudications"]
        merged_doc = _read(unit.job.run_root, unit.output("merge.claims")["artifact"])
        scores = _read(unit.job.run_root, unit.output("scoring.score_claims")["artifact"])["scores"]
        accepted = _read(unit.job.run_root, unit.output("scope.accept_manifest")["artifact"])
        findings = stages.finding_packages(projection, adjudications, merged_doc, scores,
                                           manifest_sha256=accepted["manifest_sha256"],
                                           out_dir=unit.unit_root / "findings", schemas=schemas)
        hunt_packages = _read(unit.job.run_root, unit.output("packages.assemble_hunt_packages")["artifact"])
        matrix_ref = completeness_doc["coverage_matrix"]
        matrix = _read(unit.job.run_root, matrix_ref)
        handoff = stages.build_handoff(
            run_id=unit.job.run_id, manifest_sha256=accepted["manifest_sha256"],
            configuration_sha256=semantic_settings_sha256(settings), projection=projection, accounting=accounting,
            shards=stages.shard_records(unit.job.run_root, paths), findings=findings, scores=scores,
            package_manifest_sha256=hunt_packages["package_manifest_content_sha256"],
            coverage={"path": matrix_ref["path"], "sha256": matrix_ref["sha256"], "rows": len(matrix["rows"])},
            possible=merged_doc["possible_duplicates"], schemas=schemas)
        artifact = _write(unit, "inference-review-handoff.json", handoff)
        gaps = [f"status {handoff['status']}"] if handoff["status"] != "COMPLETE" else []
        if accounting.review_incomplete:
            gaps.append("review_incomplete: no consumer may present this review as complete")
        unit.job.events.write("INFERENCE_REVIEW_PUBLISHED", status=handoff["status"],
                              review_incomplete=accounting.review_incomplete, claim_count=accounting.claims_total,
                              finding_count=len(findings), ledger_head_sha256=projection.head)
        return {"schema": SCHEMA, "artifact": artifact, "status": handoff["status"],
                "review_incomplete": accounting.review_incomplete, "ledger_head_sha256": projection.head,
                "item_count": accounting.claims_total, "gaps": gaps,
                "terminal_status": "SUCCEEDED" if handoff["status"] == "COMPLETE" else "COMPLETED_WITH_GAPS"}

    units = (
        Unit("scope.accept_manifest", accept),
        Unit("scope.assemble_scope", assemble_scope, ("scope.accept_manifest",)),
        Unit("packages.assemble_lead_packages", assemble(Lane.LEAD), ("scope.assemble_scope",)),
        Unit("packages.assemble_hunt_packages", assemble(Lane.HUNT), ("scope.assemble_scope",)),
        Unit("lead_review.teams", review(Lane.LEAD), ("packages.assemble_lead_packages",)),
        Unit("hunt_review.teams", review(Lane.HUNT), ("packages.assemble_hunt_packages",)),
        Unit("merge.claims", merge, ("lead_review.teams", "hunt_review.teams")),
        Unit("adjudicate.apply_policy", adjudicate_unit, ("merge.claims",)),
        Unit("scoring.score_claims", score, ("adjudicate.apply_policy",)),
        Unit("completeness.audit", completeness, ("scoring.score_claims",)),
        Unit("publication.publish_claim_ledger", publish_ledger, ("completeness.audit",)),
        Unit("publication.publish_handoff", publish_handoff, ("publication.publish_claim_ledger",)),
    )
    sources = sorted(Path(__file__).parent.glob("*.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sources)).hexdigest()

    def validate(context, _result) -> None:
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("inference security review topology does not match configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"inference security review task order mismatch: {step}")
        if not isinstance(context.config.typed_settings, InferenceSecurityReviewSettings):
            raise ValueError("job_inference_security_review settings are not typed")

    return Job(JOB_ID, "inference_security_review", UnitExecutor(units).execute, input_validators=(validate,),
               schema_identity=SCHEMA, implementation_identity=implementation, units=units,
               datasets=DATASETS, consumes=CONSUMES)
