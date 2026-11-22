"""Tiny producer/gate/report seams; no compiler, container, model or target execution."""
from __future__ import annotations

from copy import deepcopy

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.jobs.job_final_report_publication import build_job
from appsec_review.jobs.job_final_report_publication.pdf import bind_dossiers, render_executive_latex, template_dir
from appsec_review.jobs.job_final_report_publication.render import render_markdown
from appsec_review.jobs.job_final_report_publication.report import build_report
from appsec_review.reporting.executive_report import executive_document, render_executive_html
from appsec_review.reporting.latex import escape_latex, render_latex
from appsec_review.reporting.model import Box, Fields
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_bytes, atomic_json
from tests.unit.job_final_report_publication.test_job_units import (
    EXCERPT, ROOT, _setup_run, run_units,
)
from tests.unit.review_decision_audit_wiring.helpers import verified_document


@pytest.mark.parametrize("format", ["html", "latex"])
def test_each_chain_keeps_its_accepted_status_when_aggregate_counts_are_unchanged(format):
    verified = verified_document()
    members = [row["claim_id"] for row in verified["packages"]]
    chains = [
        {"chain_id": "chain-" + marker * 64, "status": status, "component_claim_ids": members,
         "artifact": {"path": f"data/chain-{marker}.json", "sha256": marker * 64},
         "gap_count": 0, "disposition": "SUCCEEDED"}
        for marker, status in (("a", "confirmed"), ("b", "qualified_supported"))
    ]
    manifest = {"path": "data/chains.json", "sha256": "c" * 64}
    verified["capabilities"]["attack_chains"] = capability(True, summary=manifest, count=2)
    verified["bindings"].extend([manifest, *(row["artifact"] for row in chains)])
    reports, rendered = [], []
    for swapped in (False, True):
        accepted = deepcopy(chains)
        if swapped:
            accepted[0]["status"], accepted[1]["status"] = accepted[1]["status"], accepted[0]["status"]
        verified["attachments"]["attack_chains"] = accepted
        gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, gate_classify.classify(verified))
        report = build_report(
            gate, gate_handoff={"path": "data/gate-handoff.json", "sha256": "d" * 64},
            gate_document={"path": "data/gate.json", "sha256": "e" * 64},
            chain_manifest_items=[{**row, "composed_severity": "high"} for row in accepted],
        )
        original = deepcopy(report)
        text = (render_executive_html(report) if format == "html" else
                render_executive_latex(report, (), template_dir(ROOT)).decode())
        for row in accepted:
            if format == "html":
                card = text.split("Chain " + row["chain_id"], 1)[1].split("</section>", 1)[0]
                expected = f"<dt>Accepted chain status</dt><dd>{row['status']}</dd>"
            else:
                title = r"\technicalsubheading{" + escape_latex("Chain " + row["chain_id"]) + "}"
                card = text.split(title, 1)[1].split(r"\technicalsubheading", 1)[0]
                expected = r"\technicalfield{Accepted chain status}{" + escape_latex(row["status"]) + "}"
            assert expected in card
        assert report == original
        reports.append(report)
        rendered.append(text)
    assert reports[0]["attack_chains"]["status_counts"] == reports[1]["attack_chains"]["status_counts"]
    assert reports[0]["attack_chains"]["reason"] == reports[1]["attack_chains"]["reason"]
    assert rendered[0] != rendered[1]


@pytest.mark.parametrize("severity", ["critical", "low"])
def test_certified_composed_severity_survives_all_report_formats(severity):
    verified = verified_document()
    members = [row["claim_id"] for row in verified["packages"]]
    chain = {
        "chain_id": "chain-" + "c" * 64, "status": "qualified_supported",
        "component_claim_ids": members,
        "artifact": {"path": "data/chain.json", "sha256": "d" * 64},
        "gap_count": 0, "disposition": "SUCCEEDED",
    }
    verified["attachments"]["attack_chains"] = [chain]
    gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, gate_classify.classify(verified))
    report = build_report(
        gate, gate_handoff={"path": "data/gate-handoff.json", "sha256": "a" * 64},
        gate_document={"path": "data/gate.json", "sha256": "b" * 64},
        chain_manifest_items=[{**chain, "composed_severity": severity}],
    )
    assert report["attack_chain_cards"][0]["composed_severity"] == severity
    before = deepcopy(report)
    document = executive_document(report)
    box = next(block for block in document.blocks if isinstance(block, Box)
               and block.title == "Chain " + chain["chain_id"])
    fields = {row.label: row.value for item in box.items if isinstance(item, Fields) for row in item.rows}
    assert fields["Composed severity"] == severity
    assert fields["Recorded chain gaps"] == "0"
    assert f"composed severity `{severity}`" in render_markdown(report, evidence_ids=8, gap_ids=16)
    assert f"composed severity {severity}" in render_executive_html(report)
    assert f"composed severity {severity}" in render_latex(document, ROOT / "containers" / "report" / "latex" / "template")
    assert report == before

    legacy = deepcopy(report)
    del legacy["attack_chain_cards"]
    assert "composed severity unrated" in render_executive_html(legacy)
    empty = {**report, "attack_chain_cards": []}
    assert not any(isinstance(block, Box) and block.title == box.title
                   for block in executive_document(empty).blocks)


def test_html_and_latex_share_certified_narratives_without_protected_payloads(tmp_path, monkeypatch):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    outputs = run_units(fx, build_job(executor_factory=lambda *_: pytest.fail("PDF disabled")))
    publication = outputs["acceptance.publish_handoff"]
    html = read_bound(fx.root, publication["html"]).decode()
    tex = read_bound(fx.root, publication["pdf"]["latex"]).decode()
    assert fx.dossier["statement"] in html
    assert "1 of 1 gate-certified dossier documents" in html
    assert "1 of 1 gate{-}certified dossier documents" in tex
    assert "src/parser.c" in html and "lines 40-52" in html
    for protected in (EXCERPT, "SECRET_EXCERPT", "codebox"):
        assert protected not in html and protected not in tex
    assert "0 of 0 gate-certified" not in html
    assert publication["pdf"]["state"] == "not_rendered"

    report = read_bound_json(fx.root, publication["artifact"])
    unloaded = render_executive_html(report)
    assert "0 of 1 gate-certified dossier documents" in unloaded
    assert "not loaded" in unloaded
    assert "dossier was not available" not in unloaded

    absent = deepcopy(report)
    absent["dossiers"]["items"] = []
    assert "0 of 0 gate-certified dossier documents" in render_executive_html(absent)
    assert "dossier was not available" in render_executive_html(absent)


@pytest.mark.parametrize("phase", ["report.render", "report.render_pdf"])
@pytest.mark.parametrize("damage", ["changed", "missing"])
def test_claimed_dossier_tampering_fails_before_either_renderer(tmp_path, monkeypatch, phase, damage):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    built = build_job(executor_factory=lambda *_: pytest.fail("PDF disabled"))
    outputs = {}
    for unit in built.units[:2]:
        outputs[unit.unit_id] = unit.handler(fx.unit(unit.unit_id, outputs))
    reference = fx.verified["attachments"]["dossiers"][0]["files"]["json"]
    path = fx.root / reference["path"]
    if damage == "changed":
        atomic_bytes(path, b'{"changed":true}')
    else:
        path.unlink()
    handler = next(unit for unit in built.units if unit.unit_id == phase)
    with pytest.raises(IntegrityError, match="changed after acceptance|missing"):
        handler.handler(fx.unit(phase, outputs))
    report = read_bound_json(fx.root, outputs["report.assemble"]["artifact"])
    with pytest.raises(IntegrityError, match="changed after acceptance|missing"):
        bind_dossiers(fx.root, report, fx.gate["bindings"])


@pytest.mark.parametrize("field,value", [
    ("schema", "unsupported/1"), ("dossier_id", "another-dossier"),
    ("finding", {}), ("kind", "poc"), ("run_id", "another-run"), ("visibility", "public"),
], ids=["schema", "dossier", "finding", "kind", "run", "visibility"])
def test_hash_bound_dossier_must_match_certified_identity(tmp_path, monkeypatch, field, value):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    report = build_report(fx.gate, gate_handoff={"path": fx.accepted.path, "sha256": fx.accepted.sha256},
                          gate_document=fx.gate_ref)
    path = fx.root / report["dossiers"]["items"][0]["files"]["json"]["path"]
    atomic_json(path, {**fx.dossier, field: value})
    ref = artifact_ref(fx.root, path)
    report["dossiers"]["items"][0]["files"]["json"] = ref
    with pytest.raises(IntegrityError, match="unsupported schema|certified identity"):
        bind_dossiers(fx.root, report, [ref])
