"""Small hash-bound disk inputs with one explicit authoritative-review test double.

These are not a scripted review chain or evidence of real review acceptance. The gate
classifier, current-pointer reader, configuration verifier and empty index-manifest
verifier run normally; only the expensive ledger/package review authority is replaced.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import tomllib
from typing import Any

import pytest

from appsec_review.config.inference_review import parse_inference_review_settings, semantic_settings_sha256
from appsec_review.jobs.accepted_review import VerifiedReview
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as classifier
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.jobs.job_openvex_export import contracts as c, inputs
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.retrieval.model import canonical_json as index_canonical_json
from appsec_review.review.ship_block import policy_sha256

from tests.openvex_support import ROOT, enabled_settings, make_verified_inputs


class AcceptedInputDisk:
    """Synthetic accepted records on disk; ``authority`` is a separate verified-boundary double."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch, *,
                 buckets: tuple[str, ...] = ("publishable",), settings: OpenVexExportSettings | None = None,
                 acquisition: str | None = None) -> None:
        self.root = root / "run-openvex-inputs"
        self.root.mkdir()
        self.settings = settings or enabled_settings()
        config = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
        review_settings = config["jobs"][inputs.REVIEW_JOB]["settings"]
        self.resolved = {
            "jobs": {inputs.REVIEW_JOB: {"settings": review_settings},
                     inputs.GATE_JOB: {"settings": {"enabled": True, "max_packages": 10000}},
                     c.JOB_ID: {"settings": self.settings.to_mapping()}},
            "configuration_profile": {"name": "dev", "path": None},
        }
        self.config_ref = self.put("data/configuration/resolved.json", self.resolved)
        self.config_manifest_ref = self.put("data/configuration/manifest.json",
                                             {"resolved_sha256": self.config_ref["sha256"], "sources": []})
        typed = parse_inference_review_settings(review_settings)
        semantic = semantic_settings_sha256(typed)
        policy = policy_sha256(typed.ship_block, typed.verification.require_distinct_model_for_ship_blocking)
        self.snapshot = c.json_sha256("accepted snapshot only, never current target")
        manifest = {
            "schema": "appsec-review/index-manifest/1", "run_id": self.root.name,
            "target_snapshot": self.snapshot, "target_root": "DO-NOT-ACCESS-TARGET",
            "indexes": [], "upstream_manifests": [],
        }
        self.manifest_ref = self.put("data/indices/original-manifest.json", {
            **manifest, "content_sha256": hashlib.sha256(index_canonical_json(manifest)).hexdigest(),
        })
        self.scope = {
            "schema": "appsec-review/inference-review-accepted-scope/1", "run_id": self.root.name,
            "target_snapshot": self.snapshot, "manifest_path": self.manifest_ref["path"],
            "manifest_sha256": self.manifest_ref["sha256"], "shards": [],
        }
        self.scope_ref = self.put("data/review/scope.json", self.scope)
        self.authority = c.json_body(make_verified_inputs(buckets, settings=self.settings).gate)
        # This is the verified-review input of the real classifier, not an accepted gate.
        self.authority.pop("schema")
        self.authority["run_id"] = self.root.name
        self.authority["lanes"] = []
        self.authority["possible_duplicate_pairs"] = 0
        self.authority["partition"] = {
            "confirmed": [row["finding_package_id"] for row in self.authority["packages"] if row["state"] == "confirmed"],
            "supported": [row["finding_package_id"] for row in self.authority["packages"] if row["state"] == "supported"],
        }
        self.authority["review"].update({
            "accepted_manifest_sha256": self.manifest_ref["sha256"],
            "configuration_sha256": semantic, "ship_block_policy_sha256": policy,
        })
        self.authority["ship_block"]["policy_sha256"] = policy
        self.lane_refs: dict[str, dict[str, str]] = {}
        self.lane_manifest_refs: dict[str, dict[str, str]] = {}
        self.lane_package_refs: dict[str, dict[str, str]] = {}
        for lane in ("lead", "hunt"):
            package = {"kind": lane, "synthetic": True}
            package_id = f"{lane}-{c.json_sha256(package)}"
            package_ref = self.put(f"data/review/{lane}/packages/{package_id}.json",
                                   {"package_id": package_id, **package})
            self.lane_package_refs[lane] = package_ref
            manifest = self.content_hash({"schema": "appsec-review/review-package-manifest/1",
                                           "packages": [{"package_id": package_id, "sha256": package_ref["sha256"]}]})
            reference = self.put(f"data/review/{lane}/package-manifest.json", manifest)
            self.lane_manifest_refs[lane] = reference
            self.lane_refs[lane] = self.put(f"data/review/{lane}/lane.json", {
                "package_manifest": reference, "package_manifest_content_sha256": manifest["content_sha256"],
                "packages": [package_ref],
            })
            self.authority["review"]["lead_package_manifest_sha256" if lane == "lead"
                                     else "package_manifest_sha256"] = manifest["content_sha256"]
        relations = {}
        for row in self.authority["packages"]:
            relations[row["claim_id"]] = [
                {"relation_id": identity, "claim_id": row["claim_id"]}
                for identity in (*row["direct_evidence"], *row["analyst_assessed_evidence"])
            ]
        self.projection = {
            "schema": "appsec-review/claim-projection/1", "ledger_head_sha256": c.json_sha256("head"),
            "claims": [], "relations": relations, "gaps": [], "cells": {}, "evidence_requests": [],
        }
        self.projection_ref = self.put("data/review/ledger/projection.json", self.projection)
        self.ledger_ref = self.put("data/review/ledger/claim-ledger.jsonl", b'{"synthetic":"ledger"}\n')
        self.receipt_ref = self.put("data/review/ledger/head.json", {
            "schema": "appsec-review/claim-ledger-head/1",
            "ledger_head_sha256": self.projection["ledger_head_sha256"],
            "ledger_sha256": self.ledger_ref["sha256"], "projection_sha256": self.projection_ref["sha256"],
            "projection_file_sha256": self.projection_ref["sha256"],
        })
        self.coverage_ref = self.put("data/review/coverage.json",
                                      {"rows": [], "summary": {}, "statement": "Synthetic coverage"})
        self.chain_manifest = {
            "schema": "appsec-review/attack-chain-manifest/1", "run_id": self.root.name,
            "items": [], "gaps": [],
            "accounting": {key: 0 for key in ("proposed", "admitted", "assessed", "capped", "rejected",
                                             "deduplicated", "seeds_received", "seeds_rejected")},
            "exploration": {"expanded": 0, "limit": 1, "frontier": [], "frontier_truncated": False},
        }
        self.chain_manifest_ref = self.put("data/review/chains/manifest.json", self.chain_manifest)
        self.authority["capabilities"]["attack_chains"]["summary"] = self.chain_manifest_ref
        self.authority["review"].update({
            "ledger_head_sha256": self.projection["ledger_head_sha256"],
            "projection_sha256": self.projection_ref["sha256"],
        })
        finding_refs, score_refs = [], []
        for row in self.authority["packages"]:
            row["ship_block"]["policy_sha256"] = policy
            for score in row["scores"]:
                reference = self.put(f"data/review/scoring/scores/{score['score_id']}.json",
                                       {**{key: value for key, value in score.items() if key != "sha256"},
                                        "claim_id": row["claim_id"]})
                score["sha256"] = reference["sha256"]
                score_refs.append({"score_id": score["score_id"], "sha256": reference["sha256"]})
            reference = self.put(f"data/review/findings/{row['finding_package_id']}.json",
                                   {"finding_package_id": row["finding_package_id"], "claim_id": row["claim_id"],
                                    "state": row["state"]})
            row.update(reference)
            finding_refs.append({"finding_package_id": row["finding_package_id"], "sha256": reference["sha256"]})
        self.review = {
            "schema": "appsec-review/inference-review-handoff/3",
            "run_id": self.root.name, "accepted_manifest_sha256": self.manifest_ref["sha256"],
            "finding_packages": finding_refs, "score_packages": score_refs, "shards": [],
            "coverage_matrix": self.coverage_ref, "attack_chain_manifest": self.chain_manifest_ref,
        }
        self.review_ref = self.put("data/review/review.json", self.review)
        self.review_handoff = self.handoff(inputs.REVIEW_JOB, {
            "publication.publish_handoff": {"schema": "appsec-review/inference-security-review/1",
                                            "artifact": self.review_ref},
            "scope.accept_manifest": {"artifact": self.scope_ref},
            **{f"packages.assemble_{lane}_packages": {"artifact": ref} for lane, ref in self.lane_refs.items()},
            "publication.publish_claim_ledger": {"artifact": self.receipt_ref},
            "scoring.score_claims": {"artifact": self.put("data/review/scoring/score-set.json", {"synthetic": True})},
        })
        self.review_job_ref = self.publish(inputs.REVIEW_JOB, self.review_handoff)
        self.authority["inputs"] = {
            "job_handoff": self.review_job_ref, "review_handoff": self.review_ref,
            "projection": self.projection_ref, "claim_ledger": self.ledger_ref, "coverage_matrix": self.coverage_ref,
        }
        bound = [*self.authority["inputs"].values(), self.receipt_ref, self.scope_ref, self.config_ref,
                 *self.lane_refs.values(), *self.lane_manifest_refs.values(), *self.lane_package_refs.values(),
                 self.chain_manifest_ref]
        for row in self.authority["packages"]:
            bound.append({"path": row["path"], "sha256": row["sha256"]})
        for reference in score_refs:
            bound.append({"path": f"data/review/scoring/scores/{reference['score_id']}.json",
                          "sha256": reference["sha256"]})
        self.authority["bindings"] = sorted(bound, key=lambda ref: ref["path"])
        self.publish_gate()
        self.calls: list[str] = []

        def verify_review(run_root: Path, schemas: Any, *, max_packages: int) -> VerifiedReview:
            assert run_root == self.root
            assert schemas.directory == ROOT / "docs" / "schemas" / "inference-security-review"
            assert max_packages == self.settings.max_packages
            self.calls.append("load_accepted_review")
            document = deepcopy(self.authority)
            for name in ("capabilities", "attachments", "status", "package_counts", "buckets", "limitations"):
                document.pop(name)
            document["bindings"] = [ref for ref in document["bindings"] if ref != self.config_ref]
            document["packages"] = [{key: value for key, value in row.items()
                                     if key not in {"bucket", "withheld_reasons"}}
                                    for row in document["packages"]]
            return VerifiedReview(document)

        monkeypatch.setattr(inputs, "load_accepted_review", verify_review)
        if acquisition is not None:
            self.add_acquisition(acquisition)

    @staticmethod
    def content_hash(value: dict[str, Any]) -> dict[str, Any]:
        return {**value, "content_sha256": c.json_sha256(value)}

    def put(self, name: str, body: Any) -> dict[str, str]:
        payload = body if isinstance(body, bytes) else c.canonical_bytes(body)
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return {"path": name, "sha256": hashlib.sha256(payload).hexdigest()}

    def handoff(self, job: str, outputs: dict[str, Any]) -> dict[str, Any]:
        return {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "job_id": job,
                "outputs": outputs, "resolved_config_sha256": self.config_ref["sha256"],
                "completed_at": "2026-10-28T10:00:00-04:00"}

    def publish(self, job: str, handoff: dict[str, Any]) -> dict[str, str]:
        reference = self.put(f"data/jobs/{job}/attempts/one/handoff.json", handoff)
        self.put(f"data/jobs/{job}/latest.json",
                 {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
        return reference

    def publish_gate(self, gate: dict[str, Any] | None = None) -> None:
        self.gate = gate if gate is not None else classifier.gate_document(
            FINAL_PUBLICATION_GATE_SCHEMA, self.authority, classifier.classify(self.authority))
        self.gate_ref = self.put("data/gate/gate.json", self.gate)
        self.gate_handoff = self.handoff(inputs.GATE_JOB, {"acceptance.publish_handoff": {
            "schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, "artifact": self.gate_ref,
            "item_count": len(self.gate["packages"]),
        }})
        self.gate_handoff["upstream_handoff_sha256"] = {inputs.REVIEW_JOB: self.review_job_ref["sha256"]}
        self.gate_job_ref = self.publish(inputs.GATE_JOB, self.gate_handoff)

    def refresh_review(self) -> None:
        self.review_ref = self.put(self.review_ref["path"], self.review)
        self.review_handoff["outputs"]["publication.publish_handoff"]["artifact"] = self.review_ref
        self.review_job_ref = self.publish(inputs.REVIEW_JOB, self.review_handoff)
        self.authority["inputs"].update({"job_handoff": self.review_job_ref, "review_handoff": self.review_ref})
        updated = {ref["path"]: ref for ref in self.authority["inputs"].values()}
        self.authority["bindings"] = [updated.get(ref["path"], ref) for ref in self.authority["bindings"]]
        self.publish_gate()

    def add_certified_chain(self) -> dict[str, str]:
        """Synthetic certificate bytes only; the review-authority double stands in for chain policy."""
        claims = [row["claim_id"] for row in self.authority["packages"][:2]]
        if len(claims) != 2:
            raise ValueError("the synthetic chain needs two findings")
        chain_id = "chain-" + c.json_sha256(claims)
        reference = self.put("data/review/chains/chain.json", {"synthetic": "certified chain", "run_id": self.root.name})
        item = {"chain_id": chain_id, "status": "qualified_supported", "component_claim_ids": claims,
                "artifact": reference, "limitations": ["Synthetic manual limitation"], "disposition": "assessed"}
        self.chain_manifest["items"] = [item]
        self.chain_manifest["accounting"].update({"proposed": 1, "admitted": 1, "assessed": 1})
        self.chain_manifest_ref = self.put(self.chain_manifest_ref["path"], self.chain_manifest)
        self.review["attack_chain_manifest"] = self.chain_manifest_ref
        self.authority["capabilities"]["attack_chains"] = capability(
            True, summary=self.chain_manifest_ref, count=1, gaps=1)
        self.authority["attachments"]["attack_chains"] = [
            {key: value for key, value in item.items() if key != "limitations"} | {"gap_count": 1}]
        for row in self.authority["packages"][:2]:
            row["attack_chains"] = [chain_id]
        self.authority["bindings"] = [
            self.chain_manifest_ref if ref["path"] == self.chain_manifest_ref["path"] else ref
            for ref in self.authority["bindings"]]
        self.authority["bindings"].append(reference)
        self.authority["bindings"].sort(key=lambda ref: ref["path"])
        self.refresh_review()
        return reference

    def add_acquisition(self, repository: str, *, tree_matches: bool = True) -> None:
        identity = {"kind": "git", "commit": "b" * 40, "tree": "c" * 40, "object_format": "sha1", "submodules": []}
        acquisition = {
            "schema": "appsec-review/target-acquisition/1", "acquisition_id": "example@1234",
            "identity": identity, "identity_sha256": c.json_sha256(identity), "status": "COMPLETE",
            "spec": {"kind": "git", "url": repository, "commit": identity["commit"]}, "tree": {
                "sha256": self.snapshot if tree_matches else c.json_sha256("older acquired snapshot")}, "gaps": [],
        }
        self.acquisition_ref = self.put("data/intake/acquisition.json", acquisition)
        record = {key: acquisition[key] for key in ("schema", "identity", "identity_sha256", "acquisition_id", "status")}
        record.update({"manifest": self.acquisition_ref["path"], "manifest_sha256": self.acquisition_ref["sha256"],
                       "tree_matches": tree_matches, "gaps": []})
        self.intake_ref = self.put("data/intake/intake.json", {
            "schema": "appsec-review/review-intake/1",
            "fingerprint": {"sha256": self.snapshot, "acquisition": record},
        })
        self.intake_handoff = self.handoff(inputs.INTAKE_JOB, {"publish_intake.publish_handoff": {
            "artifact": self.intake_ref,
        }})
        self.publish(inputs.INTAKE_JOB, self.intake_handoff)

    def verify(self) -> c.VerifiedInputs:
        return inputs.verify_inputs(self.root, self.settings, ROOT)
