from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
from pathlib import Path
import tomllib

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.metadata import POLICY_VERSION
from appsec_review.review.decision_audit.metadata import build_publication
from appsec_review.review.decision_audit.reader import REVIEW_JOB, expected_origin, verify_decision_audit
from appsec_review.review.models import Admissibility, CellStatus, Predicate, RelationKind, Role
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from appsec_review.runtime.datasets import EvidenceAuthority, artifact_only, dataset_contract, protected
from tests.handoff_fixture import write_fixture_handoff


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def link(value: str | None = None) -> c.Link:
    return c.Link(value, None if value else c.AbsenceReason.NOT_APPLICABLE)


def check(value: bool | None) -> c.Check:
    return c.Check(value, None if value is not None else c.AbsenceReason.LEGACY_UNRECORDED)


class Fixture:
    """Tiny immutable files and a real common accepted envelope; never executes a job."""

    def __init__(self, base: Path, *, settings: DecisionAuditSettings | None = None, receipt_changes=None,
                 scores=False, chain_cell=False, cell_package="package-1", proposal=False, proposal_count=1,
                 discovery_results=None, capture_items=None, other_claim=False, discovery_status="succeeded",
                 qualification_cell="blue-1", second_proposal_package="original-red-2", config_padding_bytes=0):
        self.root = base.resolve() / "run-1"
        self.attempt = f"data/jobs/{REVIEW_JOB}/attempts/attempt_0001"
        self.audit_root = self.attempt + "/artifacts/decision-audit"
        self.settings = settings or DecisionAuditSettings(enabled=True)
        self.artifacts = {}
        self.declare_audit = True
        self.config = {"jobs": {REVIEW_JOB: {"settings": {"decision_audit": asdict(self.settings)},
                                          "steps": {}, "workers": 1, "name": REVIEW_JOB}}}
        self.config["build_capture"] = tomllib.loads(
            (Path(__file__).resolve().parents[3] / "appsec-review.toml").read_text())["build_capture"]
        if config_padding_bytes:
            self.config["fixture_padding"] = "x" * config_padding_bytes
        config_ref = self.write("data/configuration/resolved.json", self.config, pin=False)
        self.write("data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]}, pin=False)
        self.policy = {"version": POLICY_VERSION, "settings": asdict(self.settings),
                       "sha256": digest(canonical_json({"version": POLICY_VERSION,
                                                       "settings": asdict(self.settings)}).decode())}
        self.manifest_ref = self.write("data/indices/manifests/accepted.json",
                                      {"run_id": self.root.name, "target_snapshot": "target-1", "indexes": []})
        self.scope = {"run_id": self.root.name, "target_snapshot": "target-1",
                      "manifest_path": self.manifest_ref["path"], "manifest_sha256": self.manifest_ref["sha256"],
                      "shards": []}
        self.scope_ref = self.write(self.attempt + "/steps/scope/scope.json", self.scope)
        self.claim = {"claim_id": "claim-1", "package_id": "package-1", "state": "confirmed",
                      "statement": "accepted synthetic statement", "weakness_cwe": "CWE-20",
                      "security_predicate": "memory_corruption", "preconditions": [], "state_history": []}
        self.receipt_ref = self.write(f"data/jobs/{REVIEW_JOB}/cells/cell-1/attempt-1.json", {
            "schema": "appsec-review/cell-attempt-receipt/1", "cell_id": "cell-1", "attempt": 1,
            "status": "succeeded", "seen_identities": ["entity-support"],
            "result": {"raw_private_payload": "DO_NOT_COPY_PRIVATE_WORKER_DICTIONARY"}, **(receipt_changes or {})})
        cells = {"cell-1": Role.INDEPENDENT_VERIFIER, "judge-1": Role.ADJUDICATION_JUDGE,
                 "blue-1": Role.BLUE_TEAM_REFUTER}
        if chain_cell:
            cells["chain-1"] = Role.INDEPENDENT_VERIFIER
        if proposal:
            cells["red-1"] = Role.RED_TEAM_ANALYST
            if proposal_count == 2:
                cells["red-2"] = Role.RED_TEAM_ANALYST
        self.projection = {"schema": "appsec-review/claim-projection/1", "ledger_head_sha256": digest("ledger"),
                           "claims": [self.claim], "relations": {"claim-1": []},
                           "cells": {key: [{"cell_id": key, "claim_id": "claim-1", "package_id": "package-1",
                                            "role": role.value, "receipt_sha256": None, "attempts": 1,
                                            "status": "succeeded"}] for key, role in cells.items()},
                           "judge_verdicts": {"claim-1": [{"verdict_id": "judge-verdict-1", "verdict": "blue_correct"}]}}
        if other_claim:
            self.projection["claims"].append({**self.claim, "claim_id": "claim-2",
                                               "package_id": "package-2", "state": "proposed"})
            self.projection["relations"]["claim-2"] = []
        if chain_cell:
            self.projection["cells"]["chain-1"][0].update(claim_id=None, package_id="chain-package")
        if proposal:
            self.proposal_receipt = self.write(f"data/jobs/{REVIEW_JOB}/cells/red-1/attempt-1.json", {
                "schema": "appsec-review/cell-attempt-receipt/1", "cell_id": "red-1", "attempt": 1,
                "status": discovery_status, "seen_identities": [],
                "result": discovery_results[0] if discovery_results is not None else {
                    "proposals": [{"local_id": "p1"}], "raw_private_payload": "ORIGINAL_PRIVATE_PROPOSAL"}})
            self.projection["cells"]["red-1"][0].update(
                claim_id=None, package_id="original-red-package", receipt_sha256=self.proposal_receipt["sha256"],
                status=discovery_status)
            if proposal_count == 2:
                self.second_proposal_receipt = self.write(f"data/jobs/{REVIEW_JOB}/cells/red-2/attempt-1.json", {
                    "schema": "appsec-review/cell-attempt-receipt/1", "cell_id": "red-2", "attempt": 1,
                    "status": "succeeded", "seen_identities": [],
                    "result": discovery_results[1] if discovery_results is not None else {"proposals": [{"local_id": "p1"}]}})
                self.projection["cells"]["red-2"][0].update(claim_id=None, package_id=second_proposal_package,
                    receipt_sha256=self.second_proposal_receipt["sha256"])
        self.projection["cells"]["cell-1"][0]["receipt_sha256"] = self.receipt_ref["sha256"]
        self.projection["cells"]["cell-1"][0]["package_id"] = cell_package
        for identity, cell, kind in (("support", "cell-1", RelationKind.SUPPORTS),
                                      ("dissent", "judge-1", RelationKind.CONTRADICTS),
                                      ("qualification", qualification_cell, RelationKind.QUALIFIES)):
            self.projection["relations"]["claim-1"].append({
                "relation_id": identity, "claim_id": "claim-1", "predicate": Predicate.AFFECTED_CONSTRUCT.value,
                "kind": kind.value, "producing_cell_id": cell, "admissibility": "direct", "complete": True,
                "entity_id": "entity-" + identity, "entity_kind": "source_file", "content_sha256": digest(identity),
                "retrieval_receipt_sha256": self.receipt_ref["sha256"] if identity == "support"
                else digest("receipt-" + identity), "locator": f"example/{identity}.c:1",
                "shard_id": "default"})
        self.projection_ref = self.write(self.attempt + "/steps/publication/ledger/projection.json", self.projection)
        self.adjudications = {"adjudications": [{
            "adjudication_id": "adjudication-1", "claim_id": "claim-1", "state": "confirmed",
            "deciding_row": c.DecidingRow.CONFIRMED.value,
            "counted_relation_ids": ["support"], "predicates": [{"predicate": Predicate.AFFECTED_CONSTRUCT.value,
                                                               "required": True}]}]}
        self.adjudication_ref = self.write(self.attempt + "/steps/adjudicate/decisions.json", self.adjudications)
        self.scoring_ref = self.write(self.attempt + "/steps/scoring/scores.json", {"scores": [
            {"score_id": "score-1", "claim_id": "claim-1"}] if scores else []})
        self.finding = {"claim_id": "claim-1", "finding_package_id": "finding-1", "adjudication_id": "adjudication-1",
                        "state": "confirmed", "scores": ["score-1"] if scores else [], "missing_predicates": [],
                        "direct_evidence": ["support"],
                        "analyst_assessed_evidence": [], "gap_ids": [], "title": "Synthetic finding", "lane": "lead",
                        "ship_block": {"policy": "ship-block-policy/1", "status": "not_ship_blocking",
                                       "technical_severity": "medium"}}
        self.finding_ref = self.write(self.attempt + "/steps/publication/handoff/findings/finding-1.json", self.finding)
        self.review = {"run_id": self.root.name, "accepted_manifest_sha256": self.scope["manifest_sha256"],
                       "configuration_sha256": digest("semantic-settings"), "ledger_head_sha256": digest("ledger"),
                       "projection_sha256": digest(canonical_json(self.projection).decode()),
                       "package_manifest_sha256": digest("packages"), "lead_package_manifest_sha256": digest("leads")}
        self.review_ref = self.write(self.attempt + "/steps/publication/handoff/review.json", self.review)
        self.published = {"schema": "appsec-review/inference-security-review/1", "artifact": self.review_ref}
        self.outputs = {"publication.publish_handoff": self.published,
                        "scope.accept_manifest": {"artifact": self.scope_ref},
                        "scoring.score_claims": {"artifact": self.scoring_ref},
                        "adjudicate.apply_policy": {"artifact": self.adjudication_ref}}
        self.independence = {"verifier_cell_id": "cell-1", "independent": False,
                             "provider_distinct": False, "verifier_model_distinct": False, "status": "succeeded"}
        self.lane = {"independence": {"claim-1": [self.independence]}}
        if proposal:
            self.capture = {"package_id": "original-red-package", "cell_id": "red-1", "round": 1,
                            "proposal_ref": "p1", "claim_id": "claim-1", "decision": "admitted", "reason": None,
                            "receipt_sha256": self.proposal_receipt["sha256"]}
            self.lane["proposal_audit"] = {"schema": "appsec-review/proposal-membership-capture/1",
                                           "items": [self.capture]}
            if proposal_count == 2:
                self.lane["proposal_audit"]["items"].append({
                    **self.capture, "cell_id": "red-2", "package_id": second_proposal_package,
                    "receipt_sha256": self.second_proposal_receipt["sha256"]})
            if capture_items is not None:
                captures = []
                for item in capture_items:
                    cell = self.projection["cells"][item["cell_id"]][0]
                    captures.append({**self.capture, **item, "package_id": cell["package_id"],
                                     "receipt_sha256": cell["receipt_sha256"]})
                self.lane["proposal_audit"]["items"] = captures
        self.lane_ref = self.write(self.attempt + "/steps/lead_review/lane.json", self.lane)
        self.outputs["lead_review.teams"] = {"artifact": self.lane_ref}
        origin_anchor = {"run_id": self.root.name, "attempt_id": "attempt_0001", "target_snapshot": "target-1",
                         "resolved_config_sha256": file_sha256(self.root / "data/configuration/resolved.json")}
        self.origin = expected_origin(handoff=origin_anchor, published=self.published,
                                      review=self.review, scope=self.scope, policy=self.policy)
        self.subject = c.Subject(link(), link(), link("claim-1"), link("adjudication-1"),
                                 link("finding-1"), link(cell_package), link(), link(), link(),
                                 link("cell-1"), c.Round(1, None))
        future = c.OptionalSources((), c.AbsenceReason.NOT_COMMISSIONED)
        self.context = c.Context(self.origin, self.subject, (self.source(self.projection_ref, "claim-1"),),
                                 (), (), (), c.FutureReferences(future, future, future),
                                 c.Explanation('A redacted "literal-secret" explanation.', None, link()), ())
        self.relations = tuple(c.RelationRef(
            row["relation_id"], "claim-1", Predicate(row["predicate"]), RelationKind(row["kind"]),
            row["producing_cell_id"], cells[row["producing_cell_id"]], Admissibility.DIRECT,
            row["relation_id"] == "support", None if row["relation_id"] == "support" else
            c.NoncountedReason.JUDGE_NONDECIDING if row["relation_id"] == "dissent" else c.NoncountedReason.QUALIFYING,
            self.source(self.projection_ref, row["relation_id"])) for row in self.projection["relations"]["claim-1"])
        self.decision = c.DecisionRecord(
            replace(self.context, subject=replace(self.subject, lead_id=link("lead-1"))),
            c.Stage.ADMISSION, "admitted", link(), c.OptionalSource(None, c.AbsenceReason.NOT_APPLICABLE),
            c.ReasonCode.ADMISSION_POLICY, c.BasisStatus.EXISTING_POLICY, None, c.AbsenceReason.NOT_APPLICABLE,
            (), (Predicate.AFFECTED_CONSTRUCT,), ())
        self.verification = c.VerificationRecord(
            replace(self.context, relations=(self.relations[0],)), CellStatus.SUCCEEDED,
            c.OptionalSource(self.source(self.receipt_ref, "cell-1"), None),
            c.Blindness(check(None), check(None), check(None), check(None),
                        c.OptionalSource(None, c.AbsenceReason.LEGACY_UNRECORDED), check(None)),
            c.Diversity(check(False), check(False), c.Link(None, c.AbsenceReason.UNKNOWN_MODEL_REVISION)),
            (c.PredicateCoverage(Predicate.AFFECTED_CONSTRUCT, True, (self.source(self.receipt_ref, "cell-1"),),
                                 ("support",), (), (), c.SupportCoverage.SUPPORTED, None),),
            c.EvidenceOverlap((), (), check(None)), check(False), check(False))
        self.basis = c.DecisionBasisRecord(
            replace(self.context, subject=replace(self.subject, package_id=link("package-1")),
                    relations=self.relations), self.source(self.projection_ref, "claim-1"),
            self.source(self.finding_ref, "finding-1"), self.source(self.adjudication_ref, "adjudication-1"),
            (c.RecordRef.of(self.decision),), c.OptionalRecord(c.RecordRef.of(self.verification), None),
            (Predicate.AFFECTED_CONSTRUCT,), (), (self.source(self.projection_ref, "judge-verdict-1"),),
            (self.source(self.scoring_ref, "score-1"),) if scores else ())
        self.products = (self.decision, self.verification, self.basis)
        self.publish()

    def source(self, ref, identity):
        return c.SourceRef(self.root.name, ref["path"], ref["sha256"], link(identity), (c.EvidenceUse.READ,))

    def write(self, name, value, *, pin=True):
        path = self.root / name
        if isinstance(value, bytes):
            atomic_bytes(path, value)
        else:
            atomic_json(path, value)
        ref = artifact_ref(self.root, path)
        if pin:
            self.artifacts[name] = ref
        return ref

    def publish(self, products=None, *, continuations=None, reason=None, legacy=False, mutate_manifest=None,
                mutate_metadata=None):
        products = self.products if products is None else products
        groups = {}
        for row in products:
            groups.setdefault(c.RecordRef.of(row).kind, []).append(row)
        shards = []
        for kind, rows in groups.items():
            path = self.audit_root + "/" + kind.value + "/0001.jsonl"
            self.write(path, b"".join(c.canonical_bytes(row) for row in rows))
            shards.append(c.make_shard(path, rows))
        for path, data in (continuations or {}).items():
            self.write(path, data)
        coverage = tuple(c.CoverageCount(pop, count, count, 0, 0, None) for pop in c.Population
                         for count in (sum(row.record_count for row in shards if row.kind == pop),))
        manifest = c.AuditManifest(self.origin, tuple(shards), coverage)
        path = self.audit_root + "/manifest.json"
        document = manifest.to_dict()
        if mutate_manifest:
            mutate_manifest(document)
        self.write(path, document)
        self.reference = c.ManifestRef.of(path, manifest)
        metadata = {"schema": "appsec-review/review-audit-publication/1", "origin": self.origin.to_dict(),
                    "status": "available" if reason is None else "unavailable",
                    "manifest": self.reference.to_dict() if reason is None else None,
                    "unavailable_reason": reason, "policy": self.policy}
        if mutate_metadata:
            mutate_metadata(metadata)
        metadata_ref = self.write(self.audit_root + "/publication.json", metadata)
        self.published.pop("metadata_path", None)
        self.declare_audit = not legacy
        if not legacy:
            self.published["metadata_path"] = metadata_ref["path"]
        self.accept()
        return manifest

    def accept(self):
        handoff = self.root / self.attempt / "handoff.json"
        declarations = (*source_declarations(self.attempt),
                        *(audit_declarations(self.attempt) if self.declare_audit else ()))
        atomic_json(handoff.parent / "claim.json", {
            "dataset_contract": dataset_contract(REVIEW_JOB, ("publication", "scope", "adjudicate", "lead_review"),
                                                  declarations)})
        # The fixture republisher changes only this test's synthetic accepted input.
        (handoff.parent / "result.json").unlink(missing_ok=True)
        write_fixture_handoff(self.root, handoff, {"job_id": REVIEW_JOB, "target_snapshot": "target-1",
                                                 "outputs": self.outputs, "artifacts": list(self.artifacts.values())})
        atomic_json(handoff.parent.parent.parent / "latest.json",
                    {"handoff_path": handoff.relative_to(self.root).as_posix(), "handoff_sha256": file_sha256(handoff)})

    def load(self):
        accepted = accepted_handoff(self.root, REVIEW_JOB)
        published = accepted.handoff["outputs"]["publication.publish_handoff"]
        return verify_decision_audit(
            self.root, accepted=accepted, published=published,
            review=read_bound_json(self.root, published["artifact"]),
            scope=read_bound_json(self.root, accepted.handoff["outputs"]["scope.accept_manifest"]["artifact"]),
            projection=read_bound_json(self.root, self.projection_ref), projection_ref=self.projection_ref,
            findings=((self.finding_ref, read_bound_json(self.root, self.finding_ref)),))

    def dossier(self):
        return {"run_id": self.root.name, "kind": "confirmed_finding",
                "finding": {**self.finding, **self.finding_ref}, "claim": self.claim,
                "relations": self.projection["relations"]["claim-1"],
                "provenance": {"review_handoff": self.review_ref, "projection": self.projection_ref,
                               "ledger_head_sha256": self.origin.ledger_head_sha256}}


def audit_declarations(attempt):
    base = attempt + "/artifacts/decision-audit/"
    return tuple(protected(kind, "publication", "inference_review", schema, "Synthetic protected audit",
                           artifacts=(base + pattern,), reason="operator only", authority=EvidenceAuthority.OPERATIONAL)
                 for kind, schema, pattern in (
                     ("review_audit_metadata", "appsec-review/review-audit-publication/1", "publication.json"),
                     ("review_decision_audit", c.MANIFEST_SCHEMA, "manifest.json"),
                     ("review_decisions", c.DECISION_SCHEMA, "decision/*.jsonl"),
                     ("review_verification_coverage", c.VERIFICATION_SCHEMA, "verification_coverage/*.jsonl"),
                     ("review_decision_bases", c.BASIS_SCHEMA, "decision_basis/*.jsonl"),
                     ("review_audit_continuations", "application/x-ndjson", "continuations/**/*.jsonl")))


def source_declarations(attempt):
    return (
        artifact_only("accepted_scope", "scope", "inference_review", "appsec-review/inference-review-accepted-scope/1",
                      "Synthetic accepted scope", artifacts=(attempt + "/steps/scope/**",), reason="fixture",
                      authority=EvidenceAuthority.ROUTING_CONTEXT),
        artifact_only("claim_ledger", "publication", "inference_review", "appsec-review/ledger-event/1",
                      "Synthetic ledger", artifacts=(attempt + "/steps/publication/ledger/**",
                                                     attempt + "/steps/adjudicate/**"), reason="fixture"),
        artifact_only("scores_and_findings", "publication", "inference_review", "appsec-review/finding-package/2",
                      "Synthetic findings", artifacts=(attempt + "/steps/publication/handoff/**",
                                                       attempt + "/steps/scoring/**"), reason="fixture"),
        protected("review_cells", "lead_review", "inference_review", "appsec-review/cell-attempt-receipt/1",
                  "Synthetic cells", artifacts=(f"data/jobs/{REVIEW_JOB}/cells/**",
                                                 attempt + "/steps/lead_review/**"), reason="fixture",
                  authority=EvidenceAuthority.PROVISIONAL),
    )


def continued_verifier(fixture, relation=None):
    rows = (relation or fixture.relations[0],)
    path = fixture.audit_root + "/continuations/relations/0001.jsonl"
    ref = c.make_continuation(c.ReferenceField.RELATIONS, path, rows, origin=fixture.origin,
                              claim_id=link("claim-1"))
    verifier = replace(fixture.verification, context=replace(fixture.verification.context,
                       relations=(), continuations=(ref,)))
    basis = replace(fixture.basis, verification=c.OptionalRecord(c.RecordRef.of(verifier), None))
    data = c.reference_bytes(ref.field, rows, origin=fixture.origin, claim_id=link("claim-1"))
    return (fixture.decision, verifier, basis), {path: data}


def rebind_manifest(fixture, manifest):
    path = fixture.audit_root + "/manifest.json"
    fixture.write(path, c.canonical_bytes(manifest))
    fixture.reference = c.ManifestRef.of(path, manifest)
    fixture.write(fixture.audit_root + "/publication.json",
                  build_publication(fixture.origin, settings=fixture.settings, manifest=fixture.reference))
    fixture.accept()
