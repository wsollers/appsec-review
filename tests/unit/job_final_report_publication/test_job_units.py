"""Unit tests for job_final_report_publication handlers, integrity checks, and dataset file custody."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import JobConfig
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
    FINAL_REPORT_HANDOFF_SCHEMA, FINAL_REPORT_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate import verify as gate_verify
from appsec_review.jobs.job_final_report_publication import JOB_ID, build_job
from appsec_review.jobs.job_final_report_publication import job as report_job
from appsec_review.jobs.job_final_report_publication.datasets import DATASETS
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.storage import atomic_bytes, atomic_json, file_sha256
from tests.unit.review_decision_audit_wiring.helpers import events, put, verified_document

ROOT = Path(__file__).resolve().parents[3]
GATE_JOB = "job_final_publication_gate"
ATTEMPT = f"data/jobs/{JOB_ID}/attempts/attempt_0001"


def _setup_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    degraded: bool = False,
    profile: dict[str, Any] | None = None,
) -> SimpleNamespace:
    root = tmp_path / "run-report"
    verified = verified_document()
    verified["run_id"] = root.name
    for name in verified["inputs"]:
        verified["inputs"][name] = put(root, f"data/{name}.json", {"input": name})
    verified["bindings"] = list(verified["inputs"].values())
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

    settings = {"enabled": True, "markdown_evidence_ids": 8, "markdown_gap_ids": 16}
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
    )


def test_units_execute_clean_and_gapped_flows_and_claim_every_written_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path / "clean", monkeypatch, degraded=False, profile=None)
    built = build_job()  # exercises default repository_root=None -> unit.job.repository_root
    outputs: dict[str, Any] = {}
    for u in built.units:
        outputs[u.unit_id] = u.handler(fx.unit(u.unit_id, outputs))

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
    assert published["terminal_status"] == "SUCCEEDED"
    assert published["gaps"] == []
    assert published["item_count"] == 2
    assert published["poc_handoff"] is None

    report_doc = read_bound_json(fx.root, published["artifact"])
    assert report_doc["provenance"]["configuration_profile"] == {"name": "dev", "sha256": None}
    event_names = [name for name, _fields in fx.events.rows]
    assert event_names == ["FINAL_REPORT_ASSEMBLED", "FINAL_REPORT_PUBLISHED"]

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
    built_explicit = build_job(repository_root=ROOT)
    gap_outputs: dict[str, Any] = {}
    for u in built_explicit.units:
        gap_outputs[u.unit_id] = u.handler(fx_gap.unit(u.unit_id, gap_outputs))

    pub_gap = gap_outputs["acceptance.publish_handoff"]
    assert pub_gap["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any(gap.startswith("review_degraded:") for gap in pub_gap["gaps"])
    assert not any("not_run" in gap for gap in pub_gap["gaps"])
    gap_report = read_bound_json(fx_gap.root, pub_gap["artifact"])
    assert gap_report["provenance"]["configuration_profile"] == {"name": "prod", "sha256": prod_sha}


def test_assemble_render_and_publish_integrity_guards_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = _setup_run(tmp_path, monkeypatch)
    built = build_job()
    loaded = built.units[0].handler(fx.unit("load.accepted_gate"))
    assembled = built.units[1].handler(fx.unit("report.assemble", {"load.accepted_gate": loaded}))
    rendered = built.units[2].handler(
        fx.unit("report.render", {"load.accepted_gate": loaded, "report.assemble": assembled})
    )
    all_outputs = {
        "load.accepted_gate": loaded,
        "report.assemble": assembled,
        "report.render": rendered,
    }

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
        built.units[3].handler(
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
    }
    with pytest.raises(IntegrityError, match="final report is not bound to the accepted gate handoff"):
        built.units[3].handler(fx.unit("acceptance.publish_handoff", forged_outputs))

    # Restore valid JSON/MD, then tamper a gate-bound input file: publish re-verifies gate bindings.
    atomic_json(json_path, original_report)
    atomic_bytes(md_path, original_md)
    bound_input = fx.root / fx.verified["inputs"]["claim_ledger"]["path"]
    bound_input.write_bytes(b"tampered after gate acceptance")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        built.units[3].handler(fx.unit("acceptance.publish_handoff", all_outputs))

    # 5. Missing/corrupt configuration manifest fails _configuration_profile closed.
    (fx.root / "data/configuration/manifest.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="resolved configuration manifest is unavailable"):
        report_job._configuration_profile(fx.root)
