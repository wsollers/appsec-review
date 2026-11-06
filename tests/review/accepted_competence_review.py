"""Small accepted-review producer chain for remediation admission units.

Scanner observations, proposed model claims and finite verifier outcomes are synthetic inputs.
Scope/package assembly, R5 adjudication, ledger projection, findings, accounting and acceptance
are production code. No JobRunner, live model, target build or acceptance-tier test is executed.
"""
import json
from typing import Any

from appsec_review.config.remediation import RemediationBounds
from appsec_review.indexing.store import as_identity
from appsec_review.jobs.accepted_review import REVIEW_SCHEMA
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_remediation_planning.inputs import load_review
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationRecord,
    RelationKind as IndexRelationKind, RetrievalCore, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.identity import make_id
from appsec_review.review.ledger import LedgerWriter, project
from appsec_review.review.models import (
    Admissibility, CellRecord, CellStatus, Claim, EvidenceRelation, Lane, Predicate, RelationKind,
    Role, SecurityPredicate,
)
from appsec_review.review.obligations import required_predicates_for
from appsec_review.review.packages import PackageSettings, assemble_packages, publish_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.review.test_prompt_competence import Corpus, ROOT, SETTINGS


def _observation_manifest(corpus: Corpus) -> None:
    core, root = corpus.core, corpus.core.run_root
    source = core.find(identity=corpus.labels["S1"], limit=1)["results"][0]["location"]
    source_file = core.find(kind="source_file", name=source["path"], limit=1)["results"][0]["identity"]
    snapshot = core.manifest["target_snapshot"]
    fingerprint = index_fingerprint(
        name="observations", target_snapshot=snapshot,
        producer_artifacts=[{"sha256": source["file_sha256"]}],
        tool_identity={"tool": "f08-synthetic-scanner", "version": "1"},
        parser_identity="f08-observation/1", normalizer_identity="retrieval/2", mapping_identity="exact-source/1")
    path = root / "data" / "indices" / "observations" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint, target_snapshot=snapshot)
    observation = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"case": "f08-native"})
    text = (core.target_root / source["path"]).read_text()
    lines = text.splitlines(keepends=True)
    start = len("".join(lines[:2]).encode())
    location = SourceLocation(
        snapshot, source["path"], source["file_sha256"], start, start + len(lines[2].encode()),
        3, 3, 1, len(lines[2].rstrip()) + 1, {"producer": "f08-synthetic-scanner"}, "fixture-exact", 1.0)
    builder.add_entity(EntityRecord(
        observation, "f08-copy", "f08-copy", "Synthetic unchecked destination copy",
        {"tool_id": "tool-semgrep", "native_rule_id": "f08-copy", "category": "source_sast",
         "native_severity": "HIGH", "message": "Synthetic unchecked destination copy",
         "rule_mapping": {"cwe": ["CWE-787"]}, "language": "C"}, location))
    builder.add_relation(RelationRecord(IndexRelationKind.OBSERVED_AT, observation.value, source_file, True, 1.0))
    builder.add_coverage("source_sast", "complete")
    digest = builder.build()
    manifest = root / "data" / "indices" / "manifests" / "remediation-corpus.json"
    write_manifest(
        manifest, run_id=root.name, target_snapshot=snapshot, target_root=core.target_root,
        indexes=[*(as_identity(row) for row in core.manifest["indexes"]),
                 IndexIdentity("observations", "appsec-review/retrieval-index/2", digest, fingerprint,
                               path.relative_to(root).as_posix(),
                               {"job": "job_evidence_collection", "producer": "tool-semgrep"}, ())])
    reference = artifact_ref(root, manifest)
    handoff = root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0002" / "handoff.json"
    write_fixture_handoff(root, handoff, {"job_id": "fixture", "outputs": {
        "fixture.index": {"index_manifest": reference}}})
    atomic_json(root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": root.name,
        "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": reference["path"], "manifest_sha256": reference["sha256"]})
    corpus.core = RetrievalCore(root.parent, root.name)


def publish_review(corpus: Corpus, bounds: RemediationBounds, *,
                   independent: bool = True, candidates: int = 1) -> dict[str, Any]:
    _observation_manifest(corpus)
    root = corpus.core.run_root
    directory = root / "data" / "f08-review"
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    scope = accept_manifest(root)
    assembly = assemble_packages(scope, PackageSettings(hunt_max_units=0))
    manifest = publish_packages(assembly, directory / "packages")
    [package] = [item for item in assembly.packages if item.kind == "finding_lead"]
    outputs = {}

    def publish(name: str, document: Any) -> dict[str, str]:
        path = directory / name
        atomic_json(path, document)
        return artifact_ref(root, path)

    outputs["scope.accept_manifest"] = {"artifact": publish("scope.json", {
        "manifest_path": scope.manifest_path.relative_to(root).as_posix(),
        "manifest_sha256": scope.manifest_sha256})}
    for lane in ("lead", "hunt"):
        outputs[f"packages.assemble_{lane}_packages"] = {"artifact": publish(f"{lane}-packages.json", {
            "package_manifest": artifact_ref(root, manifest),
            "package_manifest_content_sha256": assembly.manifest["content_sha256"],
            "packages": [artifact_ref(root, manifest.parent / "packages" / f"{item.package_id}.json")
                         for item in assembly.packages if item.lane == lane]})}

    writer = LedgerWriter(directory / "model-events.jsonl", "lead_review.teams")
    for gap in scope.gaps:
        writer.record_gap(gap.to_gap())
    metadata = {"independence": {}, "verifier_gaps": {}, "scope_entities": {}}
    expected_cells = {}
    sources = tuple(corpus.labels.values())
    for number in range(candidates):
        claim_id = make_id("claim", 1, {"affected": sources, "fixture_candidate": number})
        cell_ids = {role: make_id("cell", 1, {"claim": claim_id, "role": role.value}) for role in (
            Role.RED_TEAM_ANALYST, Role.INDEPENDENT_VERIFIER)}
        claim = Claim(
            claim_id, Lane.LEAD, package.package_id, sources, "CWE-787", SecurityPredicate.MEMORY_CORRUPTION,
            ("attacker_controls_request_field",), "Synthetic destination copy violates its capacity.",
            origin_cell_ids=(cell_ids[Role.RED_TEAM_ANALYST],))
        writer.propose_claim(claim)
        for role, cell_id in cell_ids.items():
            request = {"synthetic": True, "role": role.value, "claim_id": claim_id}
            receipt = publish(f"cells/{cell_id}.json", request)
            writer.cell_terminal(CellRecord(
                cell_id, Lane.LEAD, package.package_id, role, "memory_safety_native", "cpp_native_service",
                "blind_verifier" if role is Role.INDEPENDENT_VERIFIER else "lead_red_preconditions",
                claim_id, CellStatus.SUCCEEDED, 1, (), receipt["sha256"]))
            expected_cells[cell_id] = Lane.LEAD
        for predicate in sorted(required_predicates_for(claim), key=lambda item: item.value):
            identity = corpus.labels["S2" if predicate is Predicate.ATTACKER_INPUT_CONTROL else "S1"]
            excerpt = corpus.core.read_excerpt(identity=identity, context_lines=0)
            reference = publish(f"evidence/{claim_id}-{predicate.value}.json", excerpt)
            location = corpus.core.find(identity=identity, limit=1)["results"][0]["location"]
            writer.add_relation(EvidenceRelation(
                make_id("evidence_relation", 1, {"claim": claim_id, "predicate": predicate.value}),
                claim_id, predicate, RelationKind.SUPPORTS, identity, "source_span", Admissibility.DIRECT,
                "default", location["file_sha256"],
                f"{location['path']}:{location['start_line']}-{location['end_line']}", True,
                cell_ids[Role.INDEPENDENT_VERIFIER], reference["sha256"]))
        metadata["independence"][claim_id] = [{
            "independent": independent, "review_id": make_id("review", 1, {"claim": claim_id}),
            "provider_distinct": False, "verifier_model_distinct": False}]
        metadata["scope_entities"][claim_id] = sources
    writer.seal()
    initial = stages.merge_verified([writer.path])
    decision_path = directory / "adjudications.jsonl"
    decisions = stages.apply_policy(metadata, project(initial.events), decision_path, "adjudicate.apply_policy")
    merged = stages.merge_verified([writer.path, decision_path])
    projection = project(merged.events)
    stages.write_ledger(merged, projection, directory / "ledger")
    outputs["publication.publish_claim_ledger"] = {"artifact": artifact_ref(root, directory / "ledger/ledger-head.json")}
    findings = stages.finding_packages(
        projection, decisions["adjudications"], metadata, (), manifest_sha256=scope.manifest_sha256,
        out_dir=directory / "findings", schemas=schemas)
    outputs["scoring.score_claims"] = {"artifact": publish("scores/score-set.json", {"scores": []})}
    coverage = stages.coverage_matrix({}, assembly.manifest["units"])
    coverage_ref = {**publish("coverage.json", coverage), "rows": len(coverage["rows"])}
    chains = publish("chains.json", {
        "schema": "appsec-review/attack-chain-manifest/1", "run_id": root.name, "items": [], "gaps": [],
        "accounting": dict.fromkeys(("proposed", "admitted", "assessed", "capped", "rejected", "deduplicated",
                                    "seeds_received", "seeds_rejected"), 0),
        "exploration": {"expanded": 0, "limit": 1, "frontier": [], "frontier_truncated": False}})
    finding = json.loads((directory / "findings" / findings[0]["file"]).read_text())
    accounting = exact_accounting(projection, expected_cells, {package.package_id: Lane.LEAD},
                                  incomplete_gap_ratio=SETTINGS.lanes.incomplete_gap_ratio)
    handoff = stages.build_handoff(
        run_id=root.name, manifest_sha256=scope.manifest_sha256,
        configuration_sha256=file_sha256(root / "data/configuration/resolved.json"),
        projection=projection, accounting=accounting,
        shards=stages.shard_records(root, [writer.path, decision_path]), findings=findings, scores=(),
        package_manifest_sha256=assembly.manifest["content_sha256"],
        lead_package_manifest_sha256=assembly.manifest["content_sha256"], coverage=coverage_ref,
        possible=(), schemas=schemas, ship_block_policy_sha256=finding["ship_block"]["policy_sha256"],
        verification=SETTINGS.verifier_distinctness(), attack_chain_manifest=chains)
    outputs["publication.publish_handoff"] = {
        "schema": REVIEW_SCHEMA, "artifact": publish("review-handoff.json", handoff)}
    job_handoff = root / "data/jobs/job_inference_security_review/attempts/attempt_0001/handoff.json"
    write_fixture_handoff(root, job_handoff, {"job_id": "job_inference_security_review", "outputs": outputs},
                          target_snapshot=scope.target_snapshot)
    atomic_json(root / "data/jobs/job_inference_security_review/latest.json", {
        "handoff_path": job_handoff.relative_to(root).as_posix(), "handoff_sha256": file_sha256(job_handoff)})
    return load_review(root, ROOT, bounds)
