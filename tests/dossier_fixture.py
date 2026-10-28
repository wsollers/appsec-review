"""Reproducible, harmless seeded dossier for unit tests and real PDF design review.

Generate run-owned samples with:
python -m tests.dossier_fixture --run runs/dossier-synthetic-sample --image-id sha256:...
All finding and compile dispositions are seeded test data, not claims about a real target.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.completion_contracts import nonexecution_assurance
from appsec_review.jobs.job_dossier_publication.settings import DossierPublicationSettings
from appsec_review.reporting.dossier_render import render_dossier
from appsec_review.reporting.dossiers import build_dossier
from appsec_review.storage import atomic_bytes, atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_IMAGE_ID = "sha256:1dd77c969bba00168bc3128e5ee8290328dd06c09ecd4d845618c3c6336530e4"


def settings(**overrides) -> DossierPublicationSettings:
    return DossierPublicationSettings.from_mapping({
        "enabled": True, "render_pdf": True, "max_packages": 10000, "max_dossiers": 20000,
        "max_artifact_bytes": 16777216, "max_source_excerpts": 4, "max_evidence_rows": 24,
        "max_text_chars": 1800, "max_code_lines": 40, "max_code_chars": 4000,
        "image_tag": "appsec-review/tool-report-latex:1.0.0", "image_id": SAMPLE_IMAGE_ID,
        "render_timeout_seconds": 600, **overrides})


def seed(root: Path) -> dict:
    """Only accepted-style, harmless synthetic evidence; never a model transcript."""
    data = root / "data" / "seed"
    data.mkdir(parents=True, exist_ok=True)
    source = ("// Synthetic in-memory documentation; not an exploit.\n"
              "bool documented_scope_gate(bool scope_present) {\n"
              "    return scope_present;\n"
              "}\n"
              "bool safe_negative_control() { return documented_scope_gate(true); }\n")
    atomic_bytes(data / "functions.cpp", source.encode())
    atomic_json(data / "compile.json", {"status": "compile_verified", "fixture": True,
                                       "notice": "Seeded unit-test disposition, not an actual target compilation.",
                                       **nonexecution_assurance()})
    finding = {
        "finding_package_id": "finding-" + "a" * 64, "sha256": "a" * 64, "claim_id": "claim-" + "b" * 64,
        "title": "Synthetic document finding: preserve the access invariant",
        "state": "confirmed", "lane": "lead", "adjudication_id": "adjudication-" + "c" * 64,
        "direct_evidence": ["evrel-" + "d" * 64], "analyst_assessed_evidence": [],
        "missing_predicates": [], "gap_ids": [],
        "ship_block": {"policy": "ship-block-policy/1", "status": "not_ship_blocking", "technical_severity": "medium"},
        "scores": [{"score_id": "score-" + "e" * 64, "sha256": "e" * 64,
                    "provider": {"id": "application_risk_matrix/3"},
                    "technical_severity": {"scale": "application", "rating": "medium", "value": 2},
                    "exploitability_confidence": {"scale": "evidence", "rating": "limited", "value": None},
                    "environmental_business_impact": None, "remediation_priority": None,
                    "missing_factors": ["deployed_configuration"]}],
        "attack_chains": [],
    }
    atomic_json(data / "finding.json", finding)
    finding.update(artifact_ref(root, data / "finding.json"))
    claim = {"claim_id": finding["claim_id"], "state": "confirmed", "package_id": "synthetic-document",
             "statement": "The seeded document states an access invariant without its corresponding enforcement "
                          "requirement. This is a synthetic review fixture, not a vulnerability in a real project.",
             "weakness_cwe": "CWE-862", "security_predicate": "authz_bypass",
             "preconditions": ["synthetic_fixture_only"]}
    relations = [{"relation_id": finding["direct_evidence"][0], "claim_id": finding["claim_id"],
                  "predicate": "missing_or_ineffective_guard", "kind": "supports", "admissibility": "direct",
                  "entity_id": "asr:source_file:" + "f" * 64, "entity_kind": "source_file",
                  "content_sha256": "f" * 64, "locator": "design/access-policy.md:12-15",
                  "shard_id": "synthetic", "retrieval_receipt_sha256": "1" * 64, "complete": True}]
    document = ("# Access invariant (synthetic)\nOnly scoped records may be returned.\n"
                "Enforcement linkage: missing in this seeded document.\nNo deployment was tested.")
    atomic_bytes(data / "document.md", document.encode())
    excerpts = [{"identity": relations[0]["entity_id"],
                 "location": {"path": "design/access-policy.md", "source_id": "asr:source_file:" + "f" * 64,
                              "file_sha256": file_sha256(data / "document.md")},
                 "excerpt_start_line": 12, "excerpt_end_line": 15,
                 "excerpt": document}]
    poc = {"claim_id": finding["claim_id"], "finding": {key: finding[key] for key in (
        "claim_id", "finding_package_id", "sha256")}, "status": "compile_verified",
        "reason": "Seeded compile-only unit-test outcome. No real target compilation is asserted.",
        "description": "Harmless in-memory scope predicate with a safe negative control. Never run.",
        **nonexecution_assurance(),
        "files": {"source": artifact_ref(root, data / "functions.cpp"),
                  "compile": artifact_ref(root, data / "compile.json")}}
    atomic_json(data / "projection.json", {"synthetic": True, "claims": [claim], "relations": relations})
    atomic_json(data / "review.json", {"synthetic": True, "notice": "Seeded unit-test data; not a real accepted run.",
                                     "finding_artifact": artifact_ref(root, data / "finding.json"),
                                     "projection": artifact_ref(root, data / "projection.json")})
    atomic_json(data / "configuration.json", {"synthetic": True, "execution": "not_performed_by_policy"})
    provenance = {"ledger_head_sha256": file_sha256(data / "projection.json"),
                  "configuration_sha256": file_sha256(data / "configuration.json"),
                  "finding_artifact": artifact_ref(root, data / "finding.json"),
                  "projection": artifact_ref(root, data / "projection.json"),
                  "review_handoff": artifact_ref(root, data / "review.json")}
    return {"run_id": root.name, "finding": finding, "claim": claim, "relations": relations,
            "excerpts": excerpts, "poc": poc, "poc_source": source, "provenance": provenance,
            "remediation": [{"stage": "Planning", "status": "proposal_generated",
                             "reason": "Seeded proposal: document the enforcement invariant and its safe checks.",
                             "violated_invariant": "Every returned record must be scoped.",
                             "corrected_invariant": "Document and trace the scope check before record selection.",
                             "compatibility_effects": ["No runtime change is performed by this documentation fixture."],
                             "residual_risks": ["Deployment evidence remains unavailable."],
                             "regression_spec": {"safety_assertion": "Only harmless in-memory synthetic data is used."}},
                            {"stage": "Validation", "status": "static_checked",
                             "reason": "Seeded static-check disposition only; not a fix confirmation."}],
            "gaps": ["synthetic_fixture_only: findings and compile dispositions are seeded unit-test data",
                     "deployment_evidence_unavailable: no deployed system or real data was accessed"]}


def make_model(root: Path, kind: str = "confirmed_finding", **overrides) -> dict:
    return build_dossier(kind=kind, **{**seed(root), **overrides})


def render_sample(root: Path, *, image_id: str = SAMPLE_IMAGE_ID) -> list[dict]:
    records = []
    for kind in ("confirmed_finding", "poc"):
        model = make_model(root, kind)
        records.append(render_dossier(root, root / "data" / "sample" / kind, model,
                                      settings=settings(image_id=image_id), repository_root=ROOT))
    atomic_json(root / "data" / "sample" / "manifest.json", {"synthetic": True, "items": records})
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    for item in render_sample(args.run.resolve(), image_id=args.image_id):
        print(item["status"], item["files"]["latex"]["path"], (item["files"]["pdf"] or {}).get("path"))
