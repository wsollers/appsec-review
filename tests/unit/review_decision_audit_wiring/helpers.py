"""Inert immutable input fixtures for individual handler and identity boundaries."""
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace
import tomllib

from appsec_review.config import JobConfig
from appsec_review.config.inference_review import (
    DecisionAuditSettings, parse_inference_review_settings, semantic_settings_sha256,
)
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.review import ship_block
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.metadata import policy_document
from appsec_review.review.decision_audit.reader import AcceptedAudit, ReadReceipt
from appsec_review.review.identity import sha256_hex
from appsec_review.review.scope import AcceptedScope
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.storage import canonical_json, file_sha256

ROOT = Path(__file__).resolve().parents[3]
REVIEW_JOB = "job_inference_security_review"
ATTEMPT = f"data/jobs/{REVIEW_JOB}/attempts/attempt_0001"
AUDIT_DIR = ATTEMPT + "/artifacts/decision-audit"
HASH = sha256_hex("synthetic")


def put(root, path, value):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value if isinstance(value, bytes) else canonical_json(value))
    return {"path": path, "sha256": file_sha256(target)}


def events():
    rows = []
    return SimpleNamespace(rows=rows, write=lambda event, **fields: rows.append((event, fields)))


def context_fixture(tmp_path, *, enabled=True, absent=False):
    root = tmp_path / "run-wiring"
    settings = deepcopy(tomllib.loads((ROOT / "appsec-review.toml").read_text())["jobs"][REVIEW_JOB]["settings"])
    if absent:
        settings.pop("decision_audit")
    else:
        settings["decision_audit"] = asdict(DecisionAuditSettings(enabled=enabled))
    typed = parse_inference_review_settings(settings)
    config = JobConfig(REVIEW_JOB, "inference_security_review", 1, None, settings, {}, typed)
    frozen = {"jobs": {REVIEW_JOB: {"settings": settings}}, "runtime": {"fixture": "full frozen identity"}}
    config_ref = put(root, "data/configuration/resolved.json", frozen)
    put(root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
    manifest_ref = put(root, "data/indices/scope.json", {"run_id": root.name, "target_snapshot": HASH})
    scope = AcceptedScope(root.name, root, root / manifest_ref["path"], manifest_ref["sha256"], HASH,
                          (), (), (), (), (), {}, ())
    claim = {
        "schema": "appsec-review/attempt-claim/1", "run_id": root.name, "job_id": REVIEW_JOB,
        "attempt_id": "attempt_0001", "attempt_path": ATTEMPT, "repository_root": str(ROOT),
        "source_fingerprint": HASH, "evidence_target_snapshot": HASH, "upstream_handoffs": {},
        "input_manifest_path": manifest_ref["path"], "input_manifest_sha256": manifest_ref["sha256"],
        "resolved_config_sha256": config_ref["sha256"],
    }
    put(root, ATTEMPT + "/claim.json", claim)
    accepted = {"schema": "appsec-review/inference-review-accepted-scope/1", "run_id": root.name,
                "target_snapshot": HASH, "manifest_path": manifest_ref["path"],
                "manifest_sha256": manifest_ref["sha256"], "shards": []}
    scope_ref = put(root, ATTEMPT + "/steps/scope/tasks/accept_manifest/accepted-scope.json", accepted)
    projection_ref = put(root, ATTEMPT + "/steps/publication/tasks/publish_claim_ledger/projection.json",
                         {"schema": "appsec-review/claim-projection/1", "ledger_head_sha256": HASH})
    ledger_ref = put(root, ATTEMPT + "/steps/publication/tasks/publish_claim_ledger/claim-ledger.jsonl", b"")
    handoff = {
        "schema": "appsec-review/inference-review-handoff/3", "run_id": root.name, "status": "COMPLETE",
        "configuration_sha256": semantic_settings_sha256(typed), "accepted_manifest_sha256": scope.manifest_sha256,
        "ledger_head_sha256": HASH, "projection_sha256": projection_ref["sha256"],
        "package_manifest_sha256": sha256_hex("hunt"), "lead_package_manifest_sha256": sha256_hex("lead"),
    }
    handoff_ref = put(root, ATTEMPT + "/steps/publication/tasks/publish_handoff/inference-review-handoff.json", handoff)
    outputs = {
        "scope.accept_manifest": {"artifact": scope_ref, "manifest_sha256": scope.manifest_sha256},
        "publication.publish_claim_ledger": {
            "ledger": ledger_ref, "projection": projection_ref, "ledger_head_sha256": HASH},
    }
    for lane in ("lead", "hunt"):
        outputs[f"packages.assemble_{lane}_packages"] = {"artifact": put(
            root, ATTEMPT + f"/steps/packages/tasks/assemble_{lane}_packages/manifest.json",
            {"schema": "appsec-review/inference-review-lane-packages/1", "lane": lane,
             "package_manifest_content_sha256": sha256_hex(lane), "packages": []})}
    job = JobContext(root.name, "attempt_0001", "unit-fixture", ROOT, root, root / ATTEMPT, root / "metadata",
                     {}, config, events(), source_fingerprint=HASH, evidence_target_snapshot=HASH,
                     input_manifest_path=scope.manifest_path, input_manifest_sha256=scope.manifest_sha256)
    unit = UnitContext(job, "publication.publish_handoff", "publication", "publish_handoff",
                       root / ATTEMPT / "steps/publication/tasks/publish_handoff", outputs)
    return SimpleNamespace(root=root, scope=scope, unit=unit, config_ref=config_ref, claim=claim,
                           frozen=frozen, scope_document=accepted, handoff=handoff, handoff_ref=handoff_ref,
                           outputs=outputs, settings=typed.decision_audit)


def audit_fixture(*, reason=None, partial=None, handoff_sha256=HASH, reads=()):
    settings = DecisionAuditSettings(enabled=reason not in {"disabled", "legacy_unrecorded"})
    policy = policy_document(settings)
    origin = c.Origin("run-wiring", "attempt_0001", HASH, HASH, HASH, HASH, HASH, HASH,
                      c.HashLink(HASH, None), HASH, c.HashLink(None, c.AbsenceReason.NOT_PRODUCED),
                      c.HashLink(None, c.AbsenceReason.NOT_PRODUCED), policy["version"], policy["sha256"])
    manifest = None
    reference = None
    if reason is None:
        coverage = tuple((partial or {}).get(population, c.CoverageCount(population, 0, 0, 0, 0, None))
                         for population in c.Population)
        manifest = c.AuditManifest(origin, (), coverage)
        reference = c.ManifestRef.of(AUDIT_DIR + "/manifest.json", manifest)
    return AcceptedAudit(reference, manifest, (), (), tuple(reads), settings, handoff_sha256, reason)


def package(index, state):
    def identity(prefix):
        return f"{prefix}-{sha256_hex(str(index))}"

    score_id = identity("score")
    return {
        "finding_package_id": identity("finding"), "path": f"data/findings/{index}.json", "sha256": HASH,
        "claim_id": identity("claim"), "adjudication_id": identity("adjudication"), "lane": "hunt", "state": state,
        "label": "confirmed" if state == "confirmed" else "not_independently_confirmed",
        "title": f"Synthetic finding {index}",
        "ship_block": {
            "policy": "ship-block-policy/1", "policy_sha256": HASH,
            "status": "ship_blocking" if state == "confirmed" else "needs_verification",
            "reasons": [], "technical_severity": "high", "technical_severity_score_id": score_id,
            "technical_severity_floor": "high", "technical_severity_ceiling": "high", "missing_factors": [],
            "distinct_verification_required": True, "verifier_model_distinct": True,
        },
        "independence": {"independent": True, "provider_distinct": True, "verifier_model_distinct": True,
                         "judge_model_distinct": None},
        "judge_verdict": None, "verification_review_id": identity("review"),
        "direct_evidence": [identity("evrel")], "analyst_assessed_evidence": [],
        "missing_predicates": [], "gap_ids": [], "poc": None, "attack_chains": [],
        "scores": [{
            "score_id": score_id, "sha256": HASH,
            "provider": {"id": "fixture", "interface": "score/1", "implementation": "synthetic"},
            "native": {"nomenclature": None, "rating": None, "score": None},
            "technical_severity": {"scale": "fixture/1", "rating": "high", "value": 8},
            "exploitability_confidence": None, "environmental_business_impact": None, "remediation_priority": None,
            "missing_factors": [],
            "severity_assessment": {"assessment": "complete", "severity_floor": "high",
                                    "severity_ceiling": "high", "unresolved_factors": []},
        }],
    }


def verified_document():
    packages = [package(0, "confirmed"), package(1, "supported")]
    capabilities = {name: capability(False) for name in (
        "poc_generation", "attack_chains", "remediation_planning", "remediation_validation", "dossiers")}
    block = ship_block.summarize({"lane": row["lane"], "status": row["ship_block"]["status"]} for row in packages)
    return {
        "run_id": "run-wiring",
        "review": {"status": "COMPLETE", "review_incomplete": False,
                   **{key: HASH for key in ("accepted_manifest_sha256", "configuration_sha256",
                      "ledger_head_sha256", "projection_sha256", "ship_block_policy_sha256",
                      "package_manifest_sha256", "lead_package_manifest_sha256")}},
        "inputs": {name: {"path": f"data/{name}.json", "sha256": HASH} for name in (
            "job_handoff", "review_handoff", "claim_ledger", "projection", "coverage_matrix")},
        "accounting": {"outcome": "COMPLETE", "review_incomplete": False, "incomplete_gap_ratio": .1,
                       "gap_ratio": 0, "claims_total": 2, "duplicate_proposals": 0,
                       "claims_by_state": {"confirmed": 1, "supported": 1}, "gaps_by_class": {}},
        "lanes": [], "ship_block": {"policy": "ship-block-policy/1", "policy_sha256": HASH, **block},
        "verification": {"require_distinct_model_for_ship_blocking": True, "distinct": True, "warning": None},
        "coverage": {"rows": 1, "summary": {"reviewed": 1}, "statement": "Synthetic coverage"},
        "partition": {"confirmed": [packages[0]["finding_package_id"]], "supported": [packages[1]["finding_package_id"]]},
        "possible_duplicate_pairs": 0, "packages": packages, "capabilities": capabilities,
        "attachments": {name: [] for name in capabilities}, "gap_ids": [],
        "bindings": [{"path": "data/job_handoff.json", "sha256": HASH}],
    }


def gate_fixture(tmp_path, *, reason=None):
    root = tmp_path / "run-wiring"
    doc = verified_document()
    for name in doc["inputs"]:
        doc["inputs"][name] = put(root, f"data/{name}.json", {})
    doc["bindings"] = list(doc["inputs"].values())
    audit_refs = [put(root, AUDIT_DIR + "/" + name, {"private": "do not publish raw rows"})
                  for name in ("publication.json", "manifest.json", "decision/shard-0001.jsonl",
                               "continuations/refs.jsonl", "source.json")]
    doc["bindings"].extend(audit_refs)
    config_ref = put(root, "data/configuration/resolved.json", {"jobs": {}})
    put(root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
    audit_reads = list(audit_refs)
    if reason != "legacy_unrecorded":
        doc["bindings"].append(config_ref)
        audit_reads.append(config_ref)
    audit = audit_fixture(reason=reason, handoff_sha256=doc["inputs"]["job_handoff"]["sha256"],
                          reads=tuple(ReadReceipt(ref["path"], ref["sha256"], (root / ref["path"]).stat().st_size)
                                      for ref in audit_reads))
    config = JobConfig("job_final_publication_gate", "final_publication_gate", 1, None,
                       {"enabled": True, "max_packages": 10}, {})
    attempt = root / "data/jobs/job_final_publication_gate/attempts/attempt_0001"
    job = JobContext(root.name, "attempt_0001", "unit-fixture", ROOT, root, attempt, root / "metadata",
                     {}, config, events(), upstream_handoffs={REVIEW_JOB: audit.accepted_handoff_sha256})

    def unit(name, outputs=None):
        step, task = name.split(".")
        return UnitContext(job, name, step, task, attempt / "steps" / step / "tasks" / task, outputs or {})

    return SimpleNamespace(root=root, document=doc, audit=audit, audit_refs=audit_refs, job=job, unit=unit,
                           config_ref=config_ref)


def change_json(root, reference, **changes):
    document = json.loads((root / reference["path"]).read_bytes())
    return put(root, reference["path"], {**document, **changes})
