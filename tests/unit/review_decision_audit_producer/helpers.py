"""Accepted fixture bytes built with the actual ledger, adjudicator and finding publisher."""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.audit import AuditInputs, publish_decision_audit
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review import obligations
from appsec_review.review.cells import RECEIPT_SCHEMA, _RECEIPT_KEYS
from appsec_review.review.claims import normalize_claim
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.projection import (
    Document, PROJECTION_POLICY_VERSION, ProjectionInputs, link, policy_sha256, project,
)
from appsec_review.review.decision_audit.publication import audit_directory
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import Lead, LeadCollection
from appsec_review.review.ledger import LedgerWriter, project as ledger_project
from appsec_review.review.models import (
    Admissibility, CellRecord, CellStatus, EvidenceRelation, JudgeVerdict, JudgeVerdictValue,
    Lane, Predicate, RelationKind, Role,
)
from appsec_review.review.scope import AcceptedScope
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[3]
ATTEMPT = "data/jobs/job_inference_security_review/attempts/attempt-1"
CELLS = "data/jobs/job_inference_security_review/cells"
ENTITY = "asr:source_span:" + "a" * 64


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


RED, BLUE, VERIFIER, JUDGE = (f"cell-{digest(role)}" for role in ("red", "blue", "verifier", "judge"))


def document(root, path, value):
    data = canonical_json(value)
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return Document(c.SourceRef("run-1", path, hashlib.sha256(data).hexdigest(), link(), (c.EvidenceUse.READ,)), value)


def reference(doc):
    return {"path": doc.source.path, "sha256": doc.source.sha256}


@dataclass
class Fixture:
    root: Path
    settings: DecisionAuditSettings
    inputs: ProjectionInputs
    refs: AuditInputs
    scope: AcceptedScope
    findings: list

    @property
    def attempt(self):
        return self.root / ATTEMPT

    @property
    def directory(self):
        return audit_directory(self.root, self.attempt, self.inputs.origin)

    def project(self):
        return project(self.inputs, settings=self.settings, directory=self.directory)

    def publish(self):
        return publish_decision_audit(run_root=self.root, attempt_root=self.attempt, origin=self.inputs.origin,
                                      scope=self.scope, collection=self.inputs.collection,
                                      inputs=self.refs, settings=self.settings).manifest


def fixture(tmp_path, *, state="confirmed", red_status=CellStatus.SUCCEEDED, verifier_status=CellStatus.SUCCEEDED,
            capture=True, duplicate=False, relation_count=0, settings=None, receipt_change=None,
            unrelated_support=False):
    root = tmp_path / "run-1"
    settings = settings or DecisionAuditSettings(enabled=True)
    raw_source = document(root, "data/indices/observations.json", {"record": "accepted original observation"})
    shard = {"name": "observations", "shard_id": "scanner", "sha256": raw_source.source.sha256,
             "relative_path": raw_source.source.path}
    accepted = document(root, "data/indices/manifest.json", {"run_id": "run-1", "target_snapshot": "snapshot-1",
                                                           "shards": [shard]})
    scope = AcceptedScope("run-1", root, root / accepted.source.path, accepted.source.sha256,
                          "snapshot-1", (shard,), (), (), (), (), {}, ())
    claim = normalize_claim(lane=Lane.LEAD, package_id="package-1", affected_entities=(ENTITY,),
                            weakness_cwe="CWE-120", security_predicate="memory_corruption",
                            preconditions=(), statement="private target statement must never enter audit",
                            accepted_cwe_ids={"CWE-120"}, origin_cell_ids=(RED,)).claim
    claim_id = claim.claim_id
    required = obligations.required_predicates_for(claim)
    proposals = [{"local_id": "p1", "source_lead_ids": ["lead-1"]}] + (
        [{"local_id": "p2", "source_lead_ids": ["lead-1"]}] if duplicate else [])
    red_result = {"schema": "appsec-review/red-discovery-result/1",
                  "lead_accounting": [{"observation_id": "lead-1", "outcome": "proposal",
                                       "reason": "developed into a proposal", "proposal_ids": [p["local_id"] for p in proposals],
                                       "gap_ids": []},
                                      {"observation_id": "lead-3", "outcome": "no_proposal",
                                       "reason": "guard is present; password=secret", "proposal_ids": [], "gap_ids": []}],
                  "proposals": proposals}
    receipts, cells = {}, []
    for cell_id, role, status in (
            (RED, Role.RED_TEAM_ANALYST, red_status),
            (BLUE, Role.BLUE_TEAM_REFUTER, CellStatus.SUCCEEDED),
            (VERIFIER, Role.INDEPENDENT_VERIFIER, verifier_status),
            (JUDGE, Role.ADJUDICATION_JUDGE, CellStatus.SUCCEEDED)):
        if status != CellStatus.NOT_LAUNCHED:
            result = red_result if cell_id == RED else {"proposed_relations": []}
            receipt = dict.fromkeys(_RECEIPT_KEYS)
            receipt.update(schema=RECEIPT_SCHEMA, cell_id=cell_id, attempt=1, attempt_id=f"{cell_id}/attempt-1",
                           status=status.value, seen_identities=[ENTITY], result=result if status == CellStatus.SUCCEEDED else None,
                           result_sha256=sha256_hex(result) if status == CellStatus.SUCCEEDED else None,
                           provider="provider", model="model", reason="worker stopped" if status != CellStatus.SUCCEEDED else None)
            if cell_id == RED and receipt_change:
                receipt.update(receipt_change)
            receipts[cell_id] = document(root, f"{CELLS}/{cell_id}/attempt-1.json", receipt)
        cells.append(CellRecord(cell_id, Lane.LEAD, "package-1", role, "general", "native", "task",
                                claim_id if cell_id != RED else None, status,
                                0 if status == CellStatus.NOT_LAUNCHED else 1, (),
                                receipts[cell_id].source.sha256 if cell_id in receipts else None))
    relations = []
    for cell in cells[:3]:
        if cell.status != CellStatus.SUCCEEDED or cell.role == Role.BLUE_TEAM_REFUTER:
            continue
        for predicate in sorted(required):
            if state == "unresolved" or (state == "supported" and predicate != Predicate.AFFECTED_CONSTRUCT):
                continue
            if predicate == Predicate.AFFECTED_CONSTRUCT and (
                    state == "contradicted" or (state == "conflicted" and cell.cell_id == VERIFIER)):
                continue
            relations.append(EvidenceRelation(
                f"evrel-{digest(cell.cell_id + predicate)}", claim_id, predicate, RelationKind.SUPPORTS, ENTITY,
                "source_span", Admissibility.DIRECT, "observations/scanner", digest("evidence"), "line-1", True,
                cell.cell_id, cell.receipt_sha256))
    for i in range(relation_count):
        relations.append(replace(relations[0], relation_id=f"evrel-{digest(str(i))}"))
    for predicate, kind, admissibility, cell_id, provenance in (
            (Predicate.AFFECTED_CONSTRUCT, RelationKind.QUALIFIES, Admissibility.DIRECT, BLUE, None),
            (Predicate.AFFECTED_CONSTRUCT, RelationKind.CONTRADICTS, Admissibility.ANALYST_ASSESSED, BLUE, None),
            (Predicate.AFFECTED_CONSTRUCT, RelationKind.CONTRADICTS, Admissibility.DIRECT, JUDGE, "adjudication_judge")):
        relations.append(EvidenceRelation(f"evrel-{digest(cell_id + kind)}", claim_id, predicate, kind, ENTITY,
                                          "source_span", admissibility, "observations/scanner", digest("evidence"),
                                          "line-1", True, cell_id, receipts[cell_id].source.sha256, provenance=provenance))
    if state in ("conflicted", "contradicted"):
        relations.append(replace(relations[-2], relation_id=f"evrel-{digest('conflict')}",
                                 admissibility=Admissibility.DIRECT))
    if unrelated_support:
        relations.append(EvidenceRelation(f"evrel-{digest('optional-support')}", claim_id, Predicate.SECURITY_IMPACT,
            RelationKind.SUPPORTS, ENTITY, "source_span", Admissibility.DIRECT, "observations/scanner",
            digest("evidence"), "line-1", True, BLUE, receipts[BLUE].source.sha256))
    writer = LedgerWriter(root / ATTEMPT / "lead-ledger.jsonl", "lead_review.teams")
    writer.propose_claim(claim)
    for relation in relations:
        writer.add_relation(relation)
    for cell in cells:
        writer.cell_terminal(cell)
    writer.judge_verdict(JudgeVerdict(f"judge-{digest('judge')}", claim_id, JudgeVerdictValue.BLUE_CORRECT,
                                    (), "judge disagrees; token=ghp_SUPERSECRET", JUDGE, False))
    writer.seal()
    initial = ledger_project(writer.events)
    request_check = document(root, f"{CELLS}/{VERIFIER}/independence-attempt-1.json", {
        "schema": "appsec-review/verifier-request-check/1", "cell_id": VERIFIER, "attempt": 1,
        "markers_sha256": digest("markers"), "request_sha256s": [digest("request")], "contains_forbidden_marker": False})
    independent = state == "confirmed" and verifier_status == CellStatus.SUCCEEDED
    independence = {"verifier_cell_id": VERIFIER, "independent": independent, "provider_distinct": False,
                    "verifier_model_distinct": False, "review_id": "review-" + digest("review") if verifier_status == CellStatus.SUCCEEDED else None,
                    "gap_ids": [], "status": verifier_status.value}
    if capture and verifier_status == CellStatus.SUCCEEDED:
        independence["audit"] = {"schema": "appsec-review/verifier-structure-capture/1",
                                 "actor_distinct": True, "conversation_fresh": True, "prior_response_absent": True,
                                 "shared_actor_cache_absent": True, "request_markers_absent": True,
                                 "request_check": reference(request_check)}
    merged = {"independence": {claim_id: [independence]}, "verifier_gaps": {},
              "scope_entities": {claim_id: [] if state == "out_of_scope" else [ENTITY]}, "claim_rounds": {claim_id: 0}}
    adjudication_path = root / ATTEMPT / "adjudication-ledger.jsonl"
    decisions = stages.apply_policy(merged, initial, adjudication_path, "adjudicate.apply_policy")
    combined = stages.merge_verified([writer.path, adjudication_path])
    projection = ledger_project(combined.events)
    projection_doc = document(root, f"{ATTEMPT}/projection.json", projection.to_json())
    ledger_path = root / ATTEMPT / "claim-ledger.jsonl"
    ledger_bytes = b"".join(canonical_json(event) for event in combined.events)
    ledger_path.write_bytes(ledger_bytes)
    adjudications = document(root, f"{ATTEMPT}/adjudications.json", decisions)
    scores = document(root, f"{ATTEMPT}/scores.json", {"schema": "appsec-review/inference-review-scores/3", "scores": []})
    handoff_path = f"{ATTEMPT}/publication/inference-review-handoff.json"
    findings = stages.finding_packages(projection, decisions["adjudications"], merged, [],
                                      manifest_sha256=scope.manifest_sha256,
                                      out_dir=root / ATTEMPT / "publication/findings",
                                      schemas=SchemaSet(ROOT / SCHEMA_DIRECTORY))
    finding_docs = tuple(Document(c.SourceRef("run-1", f"{ATTEMPT}/publication/findings/{f['file']}", f["sha256"],
                                             link(), (c.EvidenceUse.READ,)),
                                  json.loads((root / ATTEMPT / "publication/findings" / f["file"]).read_bytes()))
                         for f in findings)
    package = document(root, f"{ATTEMPT}/package.json", {
        "schema": "appsec-review/review-package/7",
        "package_id": "package-1", "scope": {"component_id": "component-1", "build_unit_id": "build-1",
                                           "operation": {"operation_id": "operation-1"}},
        "lead_menu": [{"observation_id": "lead-1"}, {"observation_id": "lead-3"}]})
    admission = [{"lead_id": identity, "status": "not_admitted" if identity == "lead-2" else "admitted",
                  "effective_severity": "low" if identity == "lead-2" else "high", "reasons": [],
                  "residual_coverage": "outside_admission_policy" if identity == "lead-2" else "review_pending"}
                 for identity in ("lead-1", "lead-2", "lead-3")]
    sets = []
    for lane in ("lead", "hunt"):
        manifest_body = {"schema": "appsec-review/review-package-manifest/1", "run_id": "run-1",
                         "manifest_sha256": scope.manifest_sha256, "admission": admission}
        manifest = document(root, f"{ATTEMPT}/{lane}-manifest.json", {
            **manifest_body, "content_sha256": sha256_hex(manifest_body)})
        sets.append(document(root, f"{ATTEMPT}/{lane}-packages.json", {
            "schema": "appsec-review/inference-review-lane-packages/1", "lane": lane,
            "package_manifest": reference(manifest), "package_manifest_content_sha256": manifest.value["content_sha256"],
            "admission": admission, "packages": [{**reference(package), "package_id": "package-1"}] if lane == "lead" else []}))
    lane_body = {"schema": "appsec-review/inference-review-lane/1", "lane": "lead",
                 "expected_cells": {cell.cell_id: "lead" for cell in cells}, "independence": {claim_id: [independence]},
                 "capabilities": [{"cell_id": cell.cell_id, "round": 0} for cell in cells]}
    if capture:
        lane_body["proposal_audit"] = {"schema": "appsec-review/proposal-membership-capture/1", "items": [
            {"package_id": "package-1", "cell_id": RED, "round": 0, "proposal_ref": proposal["local_id"],
             "claim_id": claim_id, "decision": "admitted", "reason": None,
             "receipt_sha256": cells[0].receipt_sha256} for proposal in proposals if red_status == CellStatus.SUCCEEDED]}
    lanes = (document(root, f"{ATTEMPT}/lane.json", lane_body),)
    triage = document(root, f"{ATTEMPT}/triage.json", {
        "schema": "appsec-review/lead-triage/1",
        "enabled": True, "leads": [{"lead_id": "lead-2", "assessed": {"reason": "class-level routing only"}}]})
    handoff = document(root, handoff_path, {
        "schema": "appsec-review/inference-review-handoff/3", "run_id": "run-1",
        "accepted_manifest_sha256": scope.manifest_sha256, "ledger_head_sha256": projection.head,
        "projection_sha256": projection.sha256(), "configuration_sha256": digest("semantic"),
        "package_manifest_sha256": sets[1].value["package_manifest_content_sha256"],
        "lead_package_manifest_sha256": sets[0].value["package_manifest_content_sha256"],
        "finding_packages": [{"finding_package_id": f["finding_package_id"], "sha256": f["sha256"]} for f in findings]})
    collection = LeadCollection(tuple(
        Lead(identity, "source_sast", "scanner", "rule", "low" if identity == "lead-2" else "high",
             "low" if identity == "lead-2" else "high", "native", "never copied prose", ("CWE-120",),
             "file.c", 1, True, "observations", "scanner", shard["sha256"])
        for identity in ("lead-1", "lead-2", "lead-3")), (), {"source_sast": True}, None)
    origin = c.Origin("run-1", "attempt-1", "snapshot-1", scope.manifest_sha256, handoff.source.sha256,
                      projection.head, projection.sha256(), sets[1].value["package_manifest_content_sha256"],
                      c.HashLink(sets[0].value["package_manifest_content_sha256"], None), digest("full-config"),
                      c.HashLink(None, c.AbsenceReason.LEGACY_UNRECORDED),
                      c.HashLink(None, c.AbsenceReason.LEGACY_UNRECORDED),
                      PROJECTION_POLICY_VERSION, policy_sha256(settings))
    inputs = ProjectionInputs(origin, projection, projection_doc, lanes, tuple(sets), (package,),
                              adjudications, scores, finding_docs, triage, receipts,
                              {VERIFIER: request_check} if capture and verifier_status == CellStatus.SUCCEEDED else {},
                              collection, {lead.observation_id: raw_source.ref(lead.observation_id)
                                           for lead in collection.leads}, {})
    refs = AuditInputs(reference(handoff), {"path": ledger_path.relative_to(root).as_posix(),
                                         "sha256": hashlib.sha256(ledger_bytes).hexdigest()},
                       reference(projection_doc), tuple(reference(doc) for doc in lanes),
                       tuple(reference(doc) for doc in sets), reference(adjudications), reference(scores),
                       reference(triage), {})
    return Fixture(root, settings, inputs, refs, scope, findings)
