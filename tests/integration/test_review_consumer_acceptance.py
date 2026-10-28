"""Small real-run consumer chains; only the external model boundary is scripted."""
from __future__ import annotations

from dataclasses import asdict
from html import escape
import json
from pathlib import Path
import time

from appsec_review.inference import ModelResult
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.job_inference_security_review import build_job
from appsec_review.reporting import Limits, load_document, render_html, render_latex
from appsec_review.reporting.model import Box, Fields, Para, Stats, Table
from appsec_review.reporting.text import tex, tex_mono
from appsec_review.review.lead_triage import RESULT_SCHEMA
from appsec_review.review.ledger import merge_shards, project
from appsec_review.storage import file_sha256
from appsec_review.storage.validation import validation_scope
from tests.final_report_support import Chain, GATE, REPORT, environment, gate_job, job_tables, report_job, run_job
from tests.fixtures.inference_review.acceptance import JOB, write_config, write_overlay
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.fixtures.inference_review.fake_infer import ScriptedInfer


ROOT = Path(__file__).resolve().parents[2]
OMIT = ("opengrep", "codeql", "osv", "priority", "history", "tags", "scanner_correlation",
        "dependency_advisories", "gitleaks")
REASON = "The bounded source excerpt needs high-priority review; exploitability remains unverified."
QUESTION = "Which accepted workflow configuration enables untrusted checkout execution?"
FOREIGN = "asr:source_file:" + "f" * 64


class ConsumerInfer(ScriptedInfer):
    def __init__(self, ids, trace: Path, *, referrals: bool, foreign_first: bool):
        super().__init__({"ids": ids})
        self.trace = trace
        self.referrals = referrals
        self.foreign_first = foreign_first
        self.calls = []

    def __call__(self, request, *, timeout_seconds):
        if request.role == "lead_triager":
            result = ModelResult({"schema": RESULT_SCHEMA, "items": [
                {"lead_id": row["lead_id"], "severity": "high", "basis": "code_context", "reason": REASON}
                for row in request.task_input["findings"]
            ]}, 100, 30)
        else:
            result = super().__call__(request, timeout_seconds=timeout_seconds)
            if self.referrals and request.role in {"red_team_analyst", "blue_team_refuter"}:
                body = result.proposal["result"]
                anchors = [self.ids["ci_high"]]
                if self.foreign_first and request.role == "red_team_analyst" and not request.repair_errors:
                    anchors = [FOREIGN]
                referral = {"predicate": "configuration_enables", "requested_kind": "configuration",
                            "anchors": anchors, "question": QUESTION, "specialist": "ci_cd_pipeline"}
                if request.role == "red_team_analyst":
                    for claim in body["claims"]:
                        claim["evidence_requests"] = [referral]
                else:
                    body["evidence_requests"] = [referral]
        with self.lock:
            self.calls.append(request)
            with self.trace.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"request": asdict(request), "proposal": result.proposal},
                                        sort_keys=True) + "\n")
        return result


def _review(lane, name: str, *, ci: bool, rounds: int, foreign_first: bool = False):
    base = lane.require_owned_path(lane.root / name)
    base.mkdir()
    run_id = "2026-10-28-" + {"triage": "0301", "publication": "0302", "cutoff": "0303"}[name]
    run_root = lane.runs_dir / run_id
    run_root.mkdir()
    config = write_config(
        run_root, lane.runs_dir,
        overrides={"budget_team_packages": 1, "hunt_max_units": 1, "max_rounds": rounds,
                   "red_per_team": 1, "blue_per_team": 1, "verifier_per_team": 1},
        extra=job_tables("job_third_party_data_sync") + job_tables("job_review_data_indexing")
              + job_tables(GATE) + job_tables(REPORT))
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(base, 1))}
    # The fixture producer freezes framework /2 configuration before publishing its handoff.
    with environment(env):
        fixture = build_accepted_index_set(
            base / "fixture", run_id=run_id, runs_dir=lane.runs_dir,
            omit=OMIT + (("semgrep", "components", "build", "reference_intelligence") if ci else ("ci",)),
            omit_feeds=("osv", "nvd", "kev", "epss") + (("mitre",) if ci else ()))
    assert fixture.runs_dir == lane.runs_dir
    (fixture.run_root / "data" / "jobs" / JOB / "cells").mkdir(parents=True, exist_ok=True)
    infer = ConsumerInfer(fixture.ids, base / "model-turns.jsonl",
                          referrals=ci, foreign_first=foreign_first)
    chain = Chain(base, fixture, config, env)
    accepted = json.loads((fixture.run_root / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
    with lane.span(name + ".review"):
        chain.review = run_job(config, build_job(infer=infer, repository_root=ROOT), fixture.run_id,
                               {"job_review_data_indexing": accepted["handoff_sha256"]}, env)
    return chain, infer


def _lane(chain):
    return chain.read(JOB, "lead_review.teams", "lane.json")


def _projection(chain):
    handoff = chain.read(JOB, "publication.publish_handoff", "inference-review-handoff.json")
    paths = [chain.run_root / item["path"] for item in handoff["shards"]]
    events = merge_shards(paths).events
    return handoff, project(events), events


def _finished(lane, case: str, started: float, *, budget: int = 60):
    elapsed = time.monotonic() - started
    lane.emit("ACCEPTANCE_CASE_FINISHED", case=case, duration_seconds=elapsed, case_budget_seconds=budget)
    assert elapsed < budget, f"{case} exceeded its acceptance case budget: {elapsed:.2f}s"


def test_triage_assessment_orders_admits_and_binds_real_review_handoff(acceptance_workspace):
    lane = acceptance_workspace
    started = time.monotonic()
    with lane.span("consumer.triage"):
        chain, infer = _review(lane, "triage", ci=False, rounds=1)
        triage = chain.read(JOB, "triage.lead_severity", "lead-triage.json")
        unknown = chain.fixture.ids["sast_unknown"]
        row = next(item for item in triage["leads"] if item["lead_id"] == unknown)
        assert row["assessed"]["value"] == "high" and row["assessed"]["reason"] == REASON
        assert row["assessed"]["source"] == "model_triage"
        assert triage["counts"]["unknown_leads"] == triage["counts"]["model_triage"] == 1
        calls = [call for call in infer.calls if call.role == "lead_triager"]
        assert len(calls) == 1 and calls[0].task_input["findings"][0]["excerpt"]

        packages = chain.read(JOB, "packages.assemble_lead_packages", "lead-packages.json")
        menus = {item["package_id"]: json.loads((chain.run_root / item["path"]).read_text(
            encoding="utf-8"))["lead_menu"][0] for item in packages["packages"]}
        assessed_id = next(key for key, menu in menus.items() if menu["observation_id"] == unknown)
        menu = menus[assessed_id]
        assert menu["reported_severity"] == "unknown"
        assert menu["admission_reasons"] == ["assessed_severity"]
        assert menu["severity_record"]["assessed"] == row["assessed"]
        assert menu["severity_record"]["effective"] == {"value": "high", "from": "assessed"}
        first = packages["packages"][0]
        assert menus[first["package_id"]]["observation_id"] == chain.fixture.ids["sast_critical"]
        assert first["rank"][0] == 0
        assert next(item for item in packages["packages"] if item["package_id"] == assessed_id)["rank"][0] == 1
        assert _lane(chain)["launched"] == [first["package_id"]]
        medium = next(item for item in packages["admission"]
                      if item["lead_id"] == chain.fixture.ids["sast_medium"])
        assert medium["status"] == "not_admitted"

        handoff, projection, _events = _projection(chain)
        binding = handoff["lead_severity_triage"]["artifact"]
        path = chain.run_root / binding["path"]
        assert path == chain.unit_file(JOB, "triage.lead_severity", "lead-triage.json")
        assert file_sha256(path) == binding["sha256"]
        assert handoff["lead_severity_triage"]["model_calls"] == 1
        assert all(view.claim.state.value != "confirmed" for view in projection.claims.values())
    _finished(lane, "consumer-triage", started, budget=120)


def test_authentic_publication_renders_counts_states_gaps_and_provenance(acceptance_workspace):
    lane = acceptance_workspace
    started = time.monotonic()
    with lane.span("consumer.publication-rendering"):
        chain, _infer = _review(lane, "publication", ci=True, rounds=1)
        rounds = next(iter(_lane(chain)["rounds"].values()))
        assert len(rounds) == 1 and rounds[0]["stop_reason"] == "max_rounds"
        handoff, projection, _events = _projection(chain)
        assert len(projection.claims) == 1
        assert any(gap.reason == "unresolved_specialist_referral:ci_cd_pipeline" for gap in projection.gaps)
        assert any(gap.reason == "follow_up_cutoff:max_rounds" for gap in projection.gaps)

        with lane.span("consumer.publication"):
            run_job(chain.config, gate_job(), chain.fixture.run_id, chain.upstream(JOB), chain.env)
            published = run_job(chain.config, report_job(), chain.fixture.run_id, chain.upstream(GATE), chain.env)
            assert chain.pointer_sha(REPORT) == published["handoff_sha256"]
            report = read_bound_json(
                chain.run_root, published["handoff"]["outputs"]["acceptance.publish_handoff"]["artifact"])
            gate = read_bound_json(
                chain.run_root, chain.handoff(GATE)["outputs"]["acceptance.publish_handoff"]["artifact"])
            with validation_scope(chain.run_root):
                document = load_document(chain.run_root, limits=Limits(rows=32))
            html, latex = render_html(document), render_latex(document)
        counts = report["summary"]["package_counts"]
        assert counts == {"total": 1, "publishable": 1, "verification_backlog": 0, "withheld": 0, "exact": True}
        assert counts == gate["package_counts"]
        for section, bucket in (("findings", "publishable"), ("verification_backlog", "verification_backlog"),
                                ("withheld", "withheld")):
            assert report[section] == [item for item in gate["packages"] if item["bucket"] == bucket]
        assert len(report["findings"]) == 1 and not report["verification_backlog"] and not report["withheld"]
        assert report["findings"][0]["state"] == "confirmed"
        assert document.ledger_head == handoff["ledger_head_sha256"]
        assert document.status_badge == report["status"]["review"]
        boxes = [block for block in document.blocks if isinstance(block, Box)]
        findings = [box for box in boxes if box.meta == "Confirmed findings"]
        assert len(findings) == counts["publishable"] and findings[0].badges == ("confirmed",)
        accounting = next(box for box in boxes if box.title == "Accounting")
        table = next(item for item in accounting.items if isinstance(item, Table)
                     and item.headers == ("claim state", "count"))
        assert [(row[0].text, row[1].text) for row in table.rows] == [("confirmed", "1")]
        stats = {stat.label: stat.value for block in document.blocks if isinstance(block, Stats) for stat in block.items}
        assert stats["Claims"] == "1"
        assert stats["Review"] == report["status"]["review"]
        assert '<div class="k">Claims</div><div class="v">1</div>' in html
        assert r"\statcard{Claims}{1}" in latex
        assert 'data-state="confirmed"' in html and r"\badge{confirmed}{CONFIRMED}" in latex
        provenance = next(box for box in boxes if box.title == "Provenance")
        fields = {row.label: row.value for item in provenance.items if isinstance(item, Fields) for row in item.rows}
        for label, key in (("ledger head", "ledger_head_sha256"), ("accepted manifest", "accepted_manifest_sha256"),
                           ("configuration", "configuration_sha256")):
            value = report["provenance"][key]
            assert fields[label] == value and value in html and tex_mono(value) in latex
        assert report["provenance"]["gate_handoff"]["sha256"] == chain.pointer_sha(GATE)
        assert report["limitations"] and not report["status"]["review_complete"]
        assert any("model recording" in gap for gap in document.named_gaps)
        assert "Artifacts this report could not read" in html
        assert tex("Artifacts this report could not read") in latex
        for limitation in report["limitations"]:
            box = next(box for box in boxes if box.title == limitation["limitation_id"])
            assert any(isinstance(item, Para) and item.text == limitation["statement"] for item in box.items)
            assert escape(limitation["statement"], quote=True) in html
            assert tex(limitation["statement"]) in latex
        assert escape(document.run_id) in html and tex_mono(document.run_id) in latex
        assert render_html(document) == html
        assert render_latex(document) == latex
        (chain.base / "report.html").write_text(html, encoding="utf-8")
        (chain.base / "report.tex").write_text(latex, encoding="utf-8")
    _finished(lane, "consumer-publication-rendering", started, budget=120)


def test_worker_referral_deduplicates_next_round_after_foreign_repair(acceptance_workspace):
    lane = acceptance_workspace
    started = time.monotonic()
    with lane.span("consumer.referral-convergence"):
        chain, infer = _review(lane, "cutoff", ci=True, rounds=3, foreign_first=True)
        reds = [call for call in infer.calls if call.role == "red_team_analyst"]
        assert len(reds) == 4 and len({call.cell_id for call in reds}) == 2
        repaired = [call for call in reds if call.repair_errors]
        assert len(repaired) == 2
        assert all(any("unresolved anchors" in error and FOREIGN in error for error in call.repair_errors)
                   for call in repaired)
        assert {call.task_input["input"]["round"] for call in reds} == {0, 1}
        assert reds[0].task_input["input"]["evidence_requests"] == []
        requests = repaired[1].task_input["input"]["evidence_requests"]
        assert len(requests) == 1
        referral = requests[0]
        assert referral["question"] == QUESTION and referral["specialist"] == "ci_cd_pipeline"
        assert referral["predicate"] == "configuration_enables"
        assert referral["requested_kind"] == "configuration"
        package = repaired[1].task_input["input"]["package"]
        assert referral["anchors"] == [package["leads"][0]["label"]]
        assert package["leads"][0]["ref"] == chain.fixture.ids["ci_high"]
        assert repaired[1].task_input["input"]["known_claims"][0]["state"] == "confirmed"
        rounds = next(iter(_lane(chain)["rounds"].values()))
        assert [row["round"] for row in rounds] == [0, 1]
        assert rounds[-1]["stop_reason"] == "stable"
        assert rounds[0]["state_sha256"] == rounds[1]["state_sha256"]
        _handoff, projection, events = _projection(chain)
        origins = [event["body"] for event in events
                   if event["kind"] == "evidence_request_opened" and event["body"]["round"] == 0]
        assert len({request["origin_cell_id"] for request in origins}) >= 2
        assert all(request["anchors"] == [chain.fixture.ids["ci_high"]] for request in origins)
        assert projection.evidence_requests
        assert all(FOREIGN not in request.anchors for request in projection.evidence_requests.values())
        assert all(request.anchors == (chain.fixture.ids["ci_high"],)
                   for request in projection.evidence_requests.values())
        assert not any(gap.reason == "follow_up_cutoff:max_rounds" for gap in projection.gaps)
        assert any(gap.reason == "unresolved_specialist_referral:ci_cd_pipeline" for gap in projection.gaps)
        assert len(projection.claims) == 1
    _finished(lane, "consumer-referral-convergence", started, budget=120)
