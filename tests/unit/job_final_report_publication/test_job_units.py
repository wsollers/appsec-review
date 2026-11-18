"""Unit tests for job_final_report_publication handlers, integrity checks, and dataset file custody."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import JobConfig
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound, read_bound_json
from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
    FINAL_REPORT_HANDOFF_SCHEMA, FINAL_REPORT_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.jobs.job_final_publication_gate import verify as gate_verify
from appsec_review.jobs.job_final_report_publication import JOB_ID, build_job
from appsec_review.jobs.job_final_report_publication import job as report_job
from appsec_review.jobs.job_final_report_publication.datasets import DATASETS
from appsec_review.jobs.job_final_report_publication.pdf import RECEIPT_SCHEMA, bind_dossiers
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from tests.unit.review_decision_audit_wiring.helpers import events, put, verified_document

ROOT = Path(__file__).resolve().parents[3]
GATE_JOB = "job_final_publication_gate"
ATTEMPT = f"data/jobs/{JOB_ID}/attempts/attempt_0001"
IMAGE_TAG = "appsec-review/tool-report-latex:1.0.0"
IMAGE_ID = "sha256:" + "ab" * 32
PDF = b"%PDF-1.5\n" + b"synthetic executive report " * 4 + b"\n%%EOF\n"
EXCERPT = "SECRET_EXCERPT_memcpy(buf, input, length);"


def fake_executor(seen: list, *, render_status: int = 0, pdf: bytes | None = PDF, timed_out: bool = False):
    """A ContainerExecutor whose docker runner writes a PDF into the scratch mount instead of running an image."""

    class FixtureExecutor(ContainerExecutor):
        def _docker_bind_source(self, path):
            return path

    def factory(catalog, root):
        def runner(argv, timeout):
            seen.append(tuple(argv))
            if argv[1:3] == ("image", "inspect"):
                return CommandOutcome(0, IMAGE_ID.encode(), b"")
            if "run" in argv:
                mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
                spec = next(item for item in mounts if "dst=/scratch" in item)
                scratch = Path(spec.split("src=", 1)[1].split(",dst=")[0])
                if pdf is not None:
                    (scratch / "report.pdf").write_bytes(pdf)
                (scratch / "report.log").write_bytes(b"xelatex log\n")
                (scratch / "report.pdfinfo.txt").write_bytes(b"Pages: 3\n")
            return CommandOutcome(render_status, b"renderer output", b"renderer diagnostic", timed_out=timed_out)
        return FixtureExecutor(catalog, root, runner=runner)
    return factory


def dossier_for(finding: dict[str, Any], run_id: str) -> dict[str, Any]:
    binding = {key: finding[key] for key in ("claim_id", "finding_package_id", "sha256")}
    return {
        "schema": DOSSIER_SCHEMA, "dossier_id": "dossier-" + sha256_hex(finding["claim_id"]), "run_id": run_id,
        "kind": "confirmed_finding", "finding": binding, "visibility": "protected_developer",
        "title": finding["title"], "state": finding["state"], "lane": finding["lane"],
        "statement": "An attacker-controlled length reaches a fixed-size copy without a bound check.",
        "weakness_cwe": "CWE-120", "security_predicate": "memory_corruption", "preconditions": [],
        "ship_block": {"policy": "ship-block-policy/1", "status": "ship_blocking", "technical_severity": "high"},
        "missing_predicates": [], "evidence": [], "scores": [], "chains": [],
        "sources": [{"path": "src/parser.c", "start_line": 40, "end_line": 52, "excerpt": EXCERPT}],
        "poc": None, "remediation": [], "notices": [], "gaps": [], "truncations": [], "provenance": {},
    }


def _setup_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    degraded: bool = False,
    profile: dict[str, Any] | None = None,
    render_pdf: bool = True,
    dossier: bool = False,
) -> SimpleNamespace:
    root = tmp_path / "run-report"
    verified = verified_document()
    verified["run_id"] = root.name
    for name in verified["inputs"]:
        verified["inputs"][name] = put(root, f"data/{name}.json", {"input": name})
    verified["bindings"] = list(verified["inputs"].values())
    dossier_document = None
    if dossier:
        # One gate-certified confirmed-finding dossier: its JSON, LaTeX and receipt are bound by the gate.
        dossier_document = dossier_for(verified["packages"][0], root.name)
        base = "data/jobs/job_dossier_publication/attempts/attempt_0001/steps/dossiers/tasks/create/d1"
        files = {"json": put(root, f"{base}/dossier.json", dossier_document),
                 "latex": put(root, f"{base}/dossier.tex", b"\\documentclass{appsec-report}\n"),
                 "pdf": None, "receipt": put(root, f"{base}/receipt.json", {"status": "latex_only"})}
        verified["attachments"]["dossiers"] = [{
            "dossier_id": dossier_document["dossier_id"], "kind": "confirmed_finding",
            "finding": dossier_document["finding"], "status": "latex_only", "files": files, "gap_ids": []}]
        handoff = put(root, "data/jobs/job_dossier_publication/attempts/attempt_0001/handoff.json", {"job": "dossiers"})
        summary = put(root, "data/jobs/job_dossier_publication/attempts/attempt_0001/summary.json", {"items": 1})
        verified["capabilities"]["dossiers"] = capability(True, handoff=handoff, summary=summary, count=1)
        verified["bindings"] += [handoff, summary, files["json"], files["latex"], files["receipt"]]
    if degraded:
        verified["review"]["status"] = "DEGRADED"
        verified["accounting"]["outcome"] = "DEGRADED"

    resolved_payload: dict[str, Any] = {"jobs": {}}
    if profile is not None:
        resolved_payload["configuration_profile"] = profile
    config_ref = put(root, "data/configuration/resolved.json", resolved_payload)
    put(root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
    verified["bindings"].append(config_ref)

    classification = gate_classify.classify(verified)
    gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, classification)
    gate_path = root / "data/jobs/job_final_publication_gate/attempts/attempt_0001/steps/acceptance/tasks/publish_handoff/final-publication-gate.json"
    atomic_json(gate_path, gate)
    gate_ref = artifact_ref(root, gate_path)

    published = {
        "schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
        "artifact": gate_ref,
        "item_count": gate["package_counts"]["total"],
    }
    handoff_payload = {
        "job_id": GATE_JOB,
        "outputs": {"acceptance.publish_handoff": published},
    }
    handoff_ref = put(
        root,
        "data/jobs/job_final_publication_gate/attempts/attempt_0001/handoff.json",
        handoff_payload,
    )
    accepted = AcceptedHandoff(GATE_JOB, handoff_payload, handoff_ref["sha256"], handoff_ref["path"])
    monkeypatch.setattr(
        gate_verify,
        "accepted_handoff",
        lambda _run_root, job_id: accepted if job_id == GATE_JOB else None,
    )

    settings = {"enabled": True, "markdown_evidence_ids": 8, "markdown_gap_ids": 16, "render_pdf": render_pdf,
                "image_tag": IMAGE_TAG, "image_id": IMAGE_ID, "render_timeout_seconds": 600, "max_pdf_bytes": 16777216}
    config = JobConfig(JOB_ID, "final_report_publication", 1, None, settings, {})
    ev = events()
    job_ctx = JobContext(
        root.name,
        "attempt_0001",
        "unit-fixture",
        ROOT,
        root,
        root / ATTEMPT,
        root / "metadata",
        {},
        config,
        ev,
        upstream_handoffs={GATE_JOB: accepted.sha256},
    )

    def unit(unit_id: str, outputs: dict[str, Any] | None = None) -> UnitContext:
        step, task = unit_id.split(".")
        return UnitContext(
            job_ctx,
            unit_id,
            step,
            task,
            root / ATTEMPT / "steps" / step / "tasks" / task,
            outputs or {},
        )

    return SimpleNamespace(
        root=root,
        gate=gate,
        gate_path=gate_path,
        gate_ref=gate_ref,
        accepted=accepted,
        job_ctx=job_ctx,
        events=ev,
        unit=unit,
        verified=verified,
        dossier=dossier_document,
    )


def run_units(fx: SimpleNamespace, built: Any) -> dict[str, Any]:
    outputs: dict[str, Any] = {}
    for u in built.units:
        outputs[u.unit_id] = u.handler(fx.unit(u.unit_id, outputs))
    return outputs


def test_units_execute_clean_and_gapped_flows_and_claim_every_written_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path / "clean", monkeypatch, degraded=False, profile=None)
    seen: list = []
    built = build_job(executor_factory=fake_executor(seen))  # default repository_root=None -> unit.job.repository_root
    outputs = run_units(fx, built)

    loaded = outputs["load.accepted_gate"]
    assert loaded["terminal_status"] == "SUCCEEDED"
    assert loaded["gaps"] == []
    assert loaded["gate_handoff"] == {"path": fx.accepted.path, "sha256": fx.accepted.sha256}
    assert loaded["gate_document"] == fx.gate_ref
    assert loaded["gate_status"] == "PUBLISHABLE"
    assert loaded["review_status"] == "COMPLETE"

    assembled = outputs["report.assemble"]
    rendered = outputs["report.render"]
    published = outputs["acceptance.publish_handoff"]
    assert rendered["settings"] == {"markdown_evidence_ids": 8, "markdown_gap_ids": 16}
    assert published["schema"] == FINAL_REPORT_HANDOFF_SCHEMA
    assert published["report_schema"] == FINAL_REPORT_SCHEMA
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert published["gaps"] == assembled["gaps"]
    assert len(assembled["gaps"]) == 1
    assert "sarif_record_omitted:" in assembled["gaps"][0]["reason"]
    assert published["item_count"] == 2
    assert published["poc_handoff"] is None

    report_doc = read_bound_json(fx.root, published["artifact"])
    assert report_doc["provenance"]["configuration_profile"] == {"name": "dev", "sha256": None}
    assert report_doc["renderers"]["pdf"]["state"] == "not_rendered"   # assembled before the PDF exists
    event_names = [name for name, _fields in fx.events.rows]
    assert event_names == ["FINAL_REPORT_ASSEMBLED", "FINAL_REPORT_PDF_RENDERED", "FINAL_REPORT_PUBLISHED"]

    # The executive PDF: rendered through the container once, with the template and inputs mounted read-only.
    pdf_out = outputs["report.render_pdf"]
    assert pdf_out["status"] == "rendered" and pdf_out["gaps"] == [] and pdf_out["terminal_status"] == "SUCCEEDED"
    assert pdf_out["settings"] == {"render_pdf": True, "image_tag": IMAGE_TAG, "image_id": IMAGE_ID,
                                   "render_timeout_seconds": 600, "max_pdf_bytes": 16777216}
    command = next(argv for argv in seen if "run" in argv)
    assert IMAGE_ID in command and any("SOURCE_DATE_EPOCH" in arg for arg in command)
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--mount"]
    assert all(",readonly" in item for item in mounts if "dst=/scratch" not in item)
    assert any("dst=/template" in item for item in mounts) and any("dst=/input" in item for item in mounts)
    files = pdf_out["files"]
    assert read_bound(fx.root, files["pdf"]) == PDF
    assert files["latex"]["path"].endswith("steps/report/tasks/render_pdf/final-report.tex")
    receipt = read_bound_json(fx.root, files["receipt"])
    assert receipt["schema"] == RECEIPT_SCHEMA and receipt["status"] == "rendered"
    assert receipt["pdf_sha256"] == files["pdf"]["sha256"] and receipt["tex_sha256"] == files["latex"]["sha256"]
    assert receipt["report"] == assembled["artifact"] and receipt["source_date_epoch"] == 0
    assert receipt["tool"]["image_id"] == IMAGE_ID and receipt["execution"] is not None
    assert receipt["dossiers"] == {"certified": 0, "read": 0, "unavailable": []}
    unit_dir = fx.root / ATTEMPT / "steps/report/tasks/render_pdf"
    assert sorted(p.name for p in unit_dir.iterdir()) == [
        "container-execution.json", "container-stderr.bin", "container-stdout.bin", "final-report.pdf",
        "final-report.tex", "receipt.json", "report.log", "report.pdfinfo.txt"]
    assert published["pdf"] == {"state": "rendered", "reason": receipt["reason"], "file": files["pdf"],
                                "sha256": files["pdf"]["sha256"], "latex": files["latex"], "receipt": files["receipt"]}
    tex = (fx.root / files["latex"]["path"]).read_text(encoding="utf-8")
    assert "Executive security review report" in tex and "Synthetic finding 0" in tex

    # Verify every file written under data/jobs/job_final_report_publication is claimed by DATASETS.
    claims = runtime_claims({JOB_ID: ("load", "report", "acceptance")}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    tree = scan_run_tree(fx.root, FileClaims(claims), max_files=10_000)
    unaccounted = [p for p in tree.unaccounted if p.startswith(f"data/jobs/{JOB_ID}")]
    assert unaccounted == []

    # Gapped flow with explicit prod configuration_profile produces COMPLETED_WITH_GAPS and gap summaries.
    prod_sha = sha256_hex("prod-profile")
    fx_gap = _setup_run(
        tmp_path / "gapped",
        monkeypatch,
        degraded=True,
        profile={"name": "prod", "sha256": prod_sha},
    )
    built_explicit = build_job(repository_root=ROOT, executor_factory=fake_executor([], render_status=1, pdf=None))
    gap_outputs = run_units(fx_gap, built_explicit)

    pub_gap = gap_outputs["acceptance.publish_handoff"]
    assert pub_gap["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any(gap.startswith("review_degraded:") for gap in pub_gap["gaps"])
    assert not any("not_run" in gap for gap in pub_gap["gaps"])
    gap_report = read_bound_json(fx_gap.root, pub_gap["artifact"])
    assert gap_report["provenance"]["configuration_profile"] == {"name": "prod", "sha256": prod_sha}
    # A failed render keeps the LaTeX, the logs and a named gap; no PDF is invented.
    pdf_gap = gap_outputs["report.render_pdf"]
    assert pdf_gap["status"] == "render_failed" and pdf_gap["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert pdf_gap["files"]["pdf"] is None and pdf_gap["pdf_sha256"] is None
    assert pdf_gap["gaps"] == ["final_report_pdf_render_failed: COMPLETED, exit=1"]
    assert "final_report_pdf_render_failed: COMPLETED, exit=1" in pub_gap["gaps"]
    assert pub_gap["pdf"]["state"] == "render_failed" and pub_gap["pdf"]["file"] is None
    gap_dir = fx_gap.root / ATTEMPT / "steps/report/tasks/render_pdf"
    assert not (gap_dir / "final-report.pdf").exists() and (gap_dir / "final-report.tex").is_file()
    assert (gap_dir / "report.log").is_file() and not (gap_dir / "scratch").exists()
    claims = runtime_claims({JOB_ID: ("load", "report", "acceptance")}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    tree = scan_run_tree(fx_gap.root, FileClaims(claims), max_files=10_000)
    assert [p for p in tree.unaccounted if p.startswith(f"data/jobs/{JOB_ID}")] == []


def test_assemble_render_and_publish_integrity_guards_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path, monkeypatch)
    built = build_job(executor_factory=fake_executor([]))
    loaded = built.units[0].handler(fx.unit("load.accepted_gate"))
    assembled = built.units[1].handler(fx.unit("report.assemble", {"load.accepted_gate": loaded}))
    rendered = built.units[2].handler(
        fx.unit("report.render", {"load.accepted_gate": loaded, "report.assemble": assembled})
    )
    pdf = built.units[3].handler(
        fx.unit("report.render_pdf", {"load.accepted_gate": loaded, "report.assemble": assembled})
    )
    all_outputs = {
        "load.accepted_gate": loaded,
        "report.assemble": assembled,
        "report.render": rendered,
        "report.render_pdf": pdf,
    }
    publish = built.units[4]

    # 1. Schema error in _check is rejected with IntegrityError.
    bad_schemas = SimpleNamespace(errors=lambda _name, _doc: ["bad field one", "bad field two"])
    with pytest.raises(IntegrityError, match="final-report does not satisfy its schema: bad field one"):
        report_job._check(bad_schemas, "final-report", {})  # type: ignore[arg-type]

    # 2. Non-deterministic render_markdown is rejected during report.render.
    calls = iter(["first pass\n", "second pass\n"])
    with monkeypatch.context() as mp:
        mp.setattr(report_job, "render_markdown", lambda *_a, **_kw: next(calls))
        with pytest.raises(IntegrityError, match="report rendering is not deterministic"):
            built.units[2].handler(fx.unit("report.render", {"report.assemble": assembled}))

    # 3. Markdown bytes that match their artifact_ref sha256 (forged re-pin) but not final-report.json fail publish.
    md_path = fx.root / rendered["artifact"]["path"]
    original_md = md_path.read_bytes()
    atomic_bytes(md_path, original_md + b"\nforged trailing line\n")
    forged_rendered = {**rendered, "artifact": artifact_ref(fx.root, md_path)}
    with pytest.raises(IntegrityError, match="final-report.md is not the rendering of final-report.json"):
        publish.handler(
            fx.unit("acceptance.publish_handoff", {**all_outputs, "report.render": forged_rendered})
        )
    atomic_bytes(md_path, original_md)

    # 4. Report JSON whose provenance.gate_handoff disagrees with load.accepted_gate fails publish,
    #    even when final-report.md was deterministically rendered from that forged JSON and re-pinned.
    json_path = fx.root / assembled["artifact"]["path"]
    original_report = read_bound_json(fx.root, assembled["artifact"])
    forged_report = deepcopy(original_report)
    forged_report["provenance"]["gate_handoff"] = {"path": "data/other-gate.json", "sha256": "b" * 64}
    atomic_json(json_path, forged_report)
    forged_md = report_job.render_markdown(forged_report, evidence_ids=8, gap_ids=16).encode("utf-8")
    atomic_bytes(md_path, forged_md)
    forged_outputs = {
        "load.accepted_gate": loaded,
        "report.assemble": {**assembled, "artifact": artifact_ref(fx.root, json_path)},
        "report.render": {**rendered, "artifact": artifact_ref(fx.root, md_path)},
        "report.render_pdf": pdf,
    }
    with pytest.raises(IntegrityError, match="final report is not bound to the accepted gate handoff"):
        publish.handler(fx.unit("acceptance.publish_handoff", forged_outputs))

    # Restore valid JSON/MD, then tamper a gate-bound input file: publish re-verifies gate bindings.
    atomic_json(json_path, original_report)
    atomic_bytes(md_path, original_md)
    bound_input = fx.root / fx.verified["inputs"]["claim_ledger"]["path"]
    bound_input.write_bytes(b"tampered after gate acceptance")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        publish.handler(fx.unit("acceptance.publish_handoff", all_outputs))
    atomic_bytes(bound_input, canonical_json({"input": "claim_ledger"}))

    # 6. The executive PDF files are re-proved: a re-pinned LaTeX that is not the rendering of the JSON plus the
    #    bound dossiers, a receipt that hashes other bytes, and a PDF published without a rendered receipt all fail.
    tex_path = fx.root / pdf["files"]["latex"]["path"]
    original_tex = tex_path.read_bytes()
    atomic_bytes(tex_path, original_tex.replace(b"Executive security review report", b"Edited report"))
    forged_pdf = {**pdf, "files": {**pdf["files"], "latex": artifact_ref(fx.root, tex_path)}}
    with pytest.raises(IntegrityError, match="final-report.tex is not the rendering"):
        publish.handler(fx.unit("acceptance.publish_handoff", {**all_outputs, "report.render_pdf": forged_pdf}))
    atomic_bytes(tex_path, original_tex)
    receipt_path = fx.root / pdf["files"]["receipt"]["path"]
    original_receipt = receipt_path.read_bytes()
    forged_receipt = {**read_bound_json(fx.root, pdf["files"]["receipt"]), "pdf_sha256": "c" * 64}
    atomic_json(receipt_path, forged_receipt)
    forged_pdf = {**pdf, "files": {**pdf["files"], "receipt": artifact_ref(fx.root, receipt_path)}}
    with pytest.raises(IntegrityError, match="without the PDF it hashes"):
        publish.handler(fx.unit("acceptance.publish_handoff", {**all_outputs, "report.render_pdf": forged_pdf}))
    atomic_json(receipt_path, {**forged_receipt, "pdf_sha256": None, "status": "render_failed",
                               "files": {**forged_receipt["files"], "pdf": None}})
    forged_pdf = {**pdf, "files": {**pdf["files"], "receipt": artifact_ref(fx.root, receipt_path)}}
    with pytest.raises(IntegrityError, match="published without a rendered receipt"):
        publish.handler(fx.unit("acceptance.publish_handoff", {**all_outputs, "report.render_pdf": forged_pdf}))
    atomic_bytes(receipt_path, original_receipt)
    pdf_path = fx.root / pdf["files"]["pdf"]["path"]
    atomic_bytes(pdf_path, b"%PDF-1.5 truncated without a trailer")
    forged_receipt = {**read_bound_json(fx.root, pdf["files"]["receipt"]), "pdf_sha256": file_sha256(pdf_path)}
    atomic_json(receipt_path, forged_receipt)
    forged_pdf = {**pdf, "files": {**pdf["files"], "pdf": artifact_ref(fx.root, pdf_path),
                                   "receipt": artifact_ref(fx.root, receipt_path)}}
    with pytest.raises(IntegrityError, match="not a valid PDF"):
        publish.handler(fx.unit("acceptance.publish_handoff", {**all_outputs, "report.render_pdf": forged_pdf}))

    # 5. Missing/corrupt configuration manifest fails _configuration_profile closed.
    (fx.root / "data/configuration/manifest.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="resolved configuration manifest is unavailable"):
        report_job._configuration_profile(fx.root)


def test_render_pdf_disabled_by_policy_keeps_latex_and_names_the_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path, monkeypatch, render_pdf=False)
    outputs = run_units(fx, build_job(executor_factory=lambda *a: pytest.fail("render_pdf = false must not render")))
    pdf = outputs["report.render_pdf"]
    assert pdf["status"] == "not_rendered" and pdf["files"]["pdf"] is None
    assert pdf["gaps"] == ["final_report_pdf_disabled_by_policy"] and pdf["terminal_status"] == "COMPLETED_WITH_GAPS"
    receipt = read_bound_json(fx.root, pdf["files"]["receipt"])
    assert receipt["status"] == "not_rendered" and receipt["execution"] is None and "version" not in receipt["tool"]
    assert (fx.root / pdf["files"]["latex"]["path"]).is_file()
    published = outputs["acceptance.publish_handoff"]
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert published["gaps"] == ["final_report_pdf_disabled_by_policy", *outputs["report.assemble"]["gaps"]]
    assert published["pdf"]["state"] == "not_rendered" and "disabled by policy" in published["pdf"]["reason"]
    unit_dir = fx.root / ATTEMPT / "steps/report/tasks/render_pdf"
    assert sorted(p.name for p in unit_dir.iterdir()) == ["final-report.tex", "receipt.json"]


def test_sarif_publication_uses_only_certified_findings_and_reproves_bytes(tmp_path, monkeypatch):
    fx = _setup_run(tmp_path, monkeypatch, dossier=True, render_pdf=False)
    built = build_job(executor_factory=lambda *a: pytest.fail("PDF disabled"))
    outputs = run_units(fx, built)
    published = outputs["acceptance.publish_handoff"]
    sarif = read_bound_json(fx.root, published["sarif"])
    results = sarif["runs"][0]["results"]
    assert len(results) == 1  # Supported backlog is not exported as a confirmed finding.
    assert results[0]["properties"]["finding_id"] == fx.dossier["finding"]["finding_package_id"]
    assert results[0]["properties"]["reachability"] == "unknown"
    assert results[0]["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "src/parser.c"}, "region": {"startLine": 40, "endLine": 52}}
    assert EXCERPT not in read_bound(fx.root, published["sarif"]).decode()
    assert read_bound_json(fx.root, published["sarif_result"])["gaps"] == []
    path = fx.root / published["sarif"]["path"]
    sarif["runs"][0]["results"][0]["level"] = "note"
    atomic_json(path, sarif)
    outputs["report.assemble"]["sarif"] = artifact_ref(fx.root, path)
    with pytest.raises(IntegrityError, match="SARIF does not match"):
        built.units[-1].handler(fx.unit("acceptance.publish_handoff", outputs))


def test_bound_dossier_narrative_reaches_the_pdf_source_without_its_excerpt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path, monkeypatch, dossier=True)
    outputs = run_units(fx, build_job(executor_factory=fake_executor([])))
    pdf = outputs["report.render_pdf"]
    assert pdf["status"] == "rendered" and pdf["gaps"] == []
    receipt = read_bound_json(fx.root, pdf["files"]["receipt"])
    assert receipt["dossiers"] == {"certified": 1, "read": 1, "unavailable": []}
    tex = (fx.root / pdf["files"]["latex"]["path"]).read_text(encoding="utf-8")
    assert "attacker{-}controlled length reaches a fixed{-}size copy" in tex
    assert "lines 40{-}52" in tex and "CWE{-}120" in tex and "memory corruption" in tex
    assert EXCERPT not in tex and "SECRET_EXCERPT" not in tex
    assert outputs["acceptance.publish_handoff"]["terminal_status"] == "SUCCEEDED"


def test_tampered_dossier_is_a_named_gap_and_an_unbound_one_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path / "tampered", monkeypatch, dossier=True)
    built = build_job(executor_factory=fake_executor([]))
    loaded = built.units[0].handler(fx.unit("load.accepted_gate"))
    assembled = built.units[1].handler(fx.unit("report.assemble", {"load.accepted_gate": loaded}))
    rendered = built.units[2].handler(fx.unit("report.render", {"report.assemble": assembled}))
    json_ref = fx.verified["attachments"]["dossiers"][0]["files"]["json"]
    tampered = {**fx.dossier, "statement": "edited after the gate accepted it"}
    atomic_json(fx.root / json_ref["path"], tampered)
    # The gate's own binding check (publish) would also reject this; the PDF unit records it as a named gap
    # instead of printing the changed narrative, and the report still renders.
    pdf = built.units[3].handler(fx.unit("report.render_pdf", {"load.accepted_gate": loaded, "report.assemble": assembled}))
    assert pdf["status"] == "rendered"
    assert pdf["gaps"] == [f"executive_dossier_unavailable: {fx.dossier['dossier_id']}: run-owned artifact changed "
                           f"after acceptance: {json_ref['path']}"]
    receipt = read_bound_json(fx.root, pdf["files"]["receipt"])
    assert receipt["dossiers"] == {"certified": 1, "read": 0, "unavailable": [fx.dossier["dossier_id"]]}
    tex = (fx.root / pdf["files"]["latex"]["path"]).read_text(encoding="utf-8")
    assert "edited after the gate accepted it" not in tex and "dossier was not available to this report" in tex
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        built.units[4].handler(fx.unit("acceptance.publish_handoff", {
            "load.accepted_gate": loaded, "report.assemble": assembled, "report.render": rendered,
            "report.render_pdf": pdf}))

    # A dossier reference outside the gate's binding set is never read: the binder fails closed before the read.
    atomic_json(fx.root / json_ref["path"], fx.dossier)
    report = read_bound_json(fx.root, assembled["artifact"])
    with pytest.raises(IntegrityError, match="is not bound by the accepted gate"):
        bind_dossiers(fx.root, report, [])
    assert bind_dossiers(fx.root, report, read_bound_json(fx.root, loaded["gate_document"])["bindings"])[0].document == fx.dossier
