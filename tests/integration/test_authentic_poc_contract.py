"""Authentic producer/consumer seams: no edited handoffs or substitute schemas."""
from __future__ import annotations

from pathlib import Path
import json
import os

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.config.inference_review import PocCandidateSettings
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.inputs import verify_inputs
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError
from tests.final_report_support import GATE, REPORT, Chain, job_tables, run_job, gate_job, report_job
from tests.fixtures.inference_review.acceptance import JOB, write_config, write_overlay
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.poc_chain import poc_tables

ROOT = Path(__file__).resolve().parents[2]
ENTRY = "asr:entry_point:" + "a" * 64
HOP = "asr:call_site:" + "b" * 64


def acceptance_lane(name: str) -> LaneWorkspace:
    return LaneWorkspace.create(Path(os.environ.get("APPSEC_ACCEPTANCE_ROOT", ROOT)), name)


def attach_call_chain(fixture):
    """Direct p(s) -> strcpy flow and absent guard over the fixture's real bytes."""
    from appsec_review.graph.contract import Family
    from appsec_review.retrieval import EntityKind, EntityRecord, LogicalIdentity
    from tests.review.test_graph_admissibility import SCOPE_ID, graph_entity, results_for
    from tests.review.test_packages_graph_context import PARSE, SNAPSHOT, _location, _span
    from tests.review.test_packages_memory_context import _publish

    def symbol(name, needle):
        return EntityRecord(
            LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"qualified_name": name, "scope_id": SCOPE_ID}),
            name, name, f"function {name}", {
                "producer": "codeql-export", "scope": {"scope_id": SCOPE_ID, "build_unit_id": "native-main"},
                "kind": "function", "qualified_name": name, "exact": True, "gaps": []},
            _location(fixture, PARSE, needle))

    p = symbol("p", "p(char")
    location = _location(fixture, PARSE, "strcpy(b, s)")
    sink = graph_entity(
        Family.SINK_SITE, {**_span(location), "sink_class": "memory_write", "argument_index": 7},
        {**results_for(Family.SINK_SITE), "enclosing_function": {"symbol": p.identity.value, "display": "p"},
         "api": {"display": "strcpy"}}, location, snapshot=SNAPSHOT)
    location = _location(fixture, PARSE, "strcpy(b, s)")
    call = graph_entity(
        Family.CALL_SITE, {**_span(location), "caller_symbol": p.identity.value, "callee_name": "strcpy"},
        {"caller": {"symbol": p.identity.value, "display": "p"},
         "callee": {"symbol": None, "display": "strcpy", "dispatch": "external_undefined", "candidate_count": 0}},
        location, snapshot=SNAPSHOT)
    location = _location(fixture, PARSE, "char *s")
    entry = graph_entity(
        Family.ENTRY_POINT, {**_span(location), "source_class": "remote"},
        {**results_for(Family.ENTRY_POINT, "remote"),
         "enclosing_function": {"symbol": p.identity.value, "display": "p"}}, location, snapshot=SNAPSHOT)
    location = _location(fixture, PARSE, "strcpy(b, s)")
    flow = graph_entity(
        Family.DATAFLOW_PATH, {"source_identity": entry.identity.value, "sink_identity": sink.identity.value,
                               "step_locations_sha256": "1" * 64},
        {**results_for(Family.DATAFLOW_PATH, sink=sink.identity.value, entry=entry.identity.value),
         "enclosing_function": {"symbol": p.identity.value, "display": "p"}}, location, snapshot=SNAPSHOT)
    guard = graph_entity(
        Family.GUARD_FACT, {**_span(location), "sink_identity": sink.identity.value},
        {**results_for(Family.GUARD_FACT, sink=sink.identity.value),
         "enclosing_function": {"symbol": p.identity.value, "display": "p"}}, location, snapshot=SNAPSHOT)
    _publish(fixture, [
        ("graph", "authentic-symbols", {"job": "job_code_graph_index", "build_unit_id": "native-main"},
         [p], [], ("graph:native:symbols", "complete", None)),
        ("graph", "authentic-facts", {"job": "job_code_graph_index", "build_unit_id": "native-main"},
         [sink, call, entry, flow, guard], [], ("graph:native:facts", "complete", None))])
    return entry.identity.value, call.identity.value


class BasisInfer(ScriptedInfer):
    """Only the external model boundary is scripted; eligibility stays application-owned."""

    def __call__(self, request, *, timeout_seconds):
        if self.scenario.get("benign") and request.role in {"red_team_analyst", "hypothesis_hunter"}:
            from tests.fixtures.inference_review.red import red_result
            return self._final(red_result(request.task_input))
        answer = super().__call__(request, timeout_seconds=timeout_seconds)
        if request.role == "red_team_analyst":
            neighborhood = request.task_input["input"]["package"]["neighborhood"]
            chain = neighborhood["chain"]
            result = answer.proposal.get("result", {})
            for claim in result.get("claims", ()):
                if claim["id"] == "c1" and chain["entries"]:
                    entry = chain["entries"][0]["label"]
                    claim.setdefault("support", {}).setdefault("attacker_input_control", []).append(entry)
                    for predicate, section in (("source_to_sink_reachability", "flows"),
                                               ("missing_or_ineffective_guard", "guards")):
                        claim["support"][predicate] = [row["label"] for row in neighborhood[section]]
                    if not self.scenario.get("basis", True):
                        continue
                    claim["poc_basis"] = {
                        "entry": [entry], "path": [item["label"] for item in
                                                 (chain["hops"] or neighborhood["callees"])],
                        "trigger": [{"field": "s", "where": "p", "constraint": "greater than 8",
                                     "why": "p copies into an eight-byte destination"}],
                        "input_format": "request field", "preconditions": ["attacker_controls_request_field"],
                        "expected_observation": "an out-of-bounds write", "unknowns": []}
        if self.scenario.get("trace"):
            with self.lock:
                with Path(self.scenario["trace"]).open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"role": request.role, "task": request.task_input.get("task"),
                                             "proposal": answer.proposal}) + "\n")
        return answer


def authentic_chain(lane: LaneWorkspace, *, basis=True, benign=False, blocked=False, ci_only=False):
    omit = ("opengrep", "codeql", "osv", "priority", "history", "tags", "scanner_correlation",
            "dependency_advisories", "gitleaks")
    fixture = build_accepted_index_set(lane.root, omit=omit + (("semgrep",) if ci_only else ("ci",)),
                                       omit_feeds=("osv", "nvd", "kev", "epss"))
    assert fixture.runs_dir == lane.runs_dir
    if not ci_only:
        attach_call_chain(fixture)
    (fixture.run_root / "data" / "jobs" / JOB / "cells").mkdir(parents=True, exist_ok=True)
    config = write_config(
        lane.root, lane.runs_dir,
        overrides={"budget_team_packages": 1, "hunt_max_units": 1, "max_rounds": 1,
                   "red_per_team": 1, "blue_per_team": 1, "verifier_per_team": 1},
        extra=job_tables("job_third_party_data_sync") + job_tables(GATE) + job_tables(REPORT)
              + poc_tables(max_candidates=2))
    env = {"APPSEC_REVIEW_CONFIG_OVERLAY": str(write_overlay(lane.root, 1))}
    infer = BasisInfer({"ids": fixture.ids, "basis": basis, "benign": benign,
                        "trace": str(lane.root / "scripted-turns.jsonl"),
                        **({"fail_roles": ["red_team_analyst", "hypothesis_hunter"]} if blocked else {})})
    from appsec_review.jobs.job_inference_security_review import build_job

    chain = Chain(lane.root, fixture, config, env)
    with lane.span("review"):
        run_job(config, build_job(infer=infer, repository_root=ROOT), fixture.run_id, env=env)
    with lane.span("gate"):
        run_job(config, gate_job(), fixture.run_id, chain.upstream(JOB), env)
    return chain


@pytest.fixture(scope="module")
def authentic():
    lane = acceptance_lane("authentic-poc-contract")
    with lane.span("chain"):
        chain = authentic_chain(lane)
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="authentic-review-gate")
    return lane, chain


def verified(chain):
    return verify_inputs(
        chain.run_root, review_schemas=SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review"),
        gate_schemas=SchemaSet(ROOT / "docs" / "schemas" / "final-report"))


def test_current_review_producer_is_read_by_poc_consumer() -> None:
    claim = "claim-" + "1" * 64
    basis = {
        "entry": [ENTRY], "path": [HOP],
        "trigger": [{"field": "name", "where": "input", "constraint": "greater than 8",
                     "why": "the destination has eight bytes"}],
        "input_format": "request field", "preconditions": ["attacker_controls_request_field"],
        "expected_observation": "an out-of-bounds write", "unknowns": [],
    }
    produced = stages.poc_candidates(
        [{"claim_id": claim, "state": "supported", "judge_verdict": "red_correct",
          "technical_severity": "high", "finding_package_id": "finding-" + "2" * 64,
          "sha256": "3" * 64, "direct_evidence": ["evrel-" + "4" * 64]}],
        [{"claim_id": claim, "package_id": "finding_lead-" + "5" * 64,
          "cell_id": "cell-" + "6" * 64, "poc_basis": basis}],
        PocCandidateSettings())
    assert len(produced) == 1
    [candidate] = parse_candidates(produced)
    assert candidate.poc_basis.record() == basis
    assert candidate.state == "supported"


def test_real_review_gate_and_poc_planning_use_authoritative_contracts(authentic):
    from appsec_review.jobs.job_poc_generation import build_job
    from appsec_review.jobs.job_poc_generation.brief import build_brief
    from appsec_review.jobs.job_poc_generation.inputs import load_package, retrieval_core, sink_of
    from appsec_review.review.package_view import ViewLimits, build_view
    from tests import poc_support

    lane, chain = authentic
    inputs = verified(chain)
    assert inputs.candidates
    from appsec_review.jobs.bound_artifacts import read_bound_json
    handoff = chain.handoff(JOB)
    documents = [read_bound_json(chain.run_root, handoff["outputs"][f"{name}_review.teams"]["artifact"])
                 for name in ("lead", "hunt")]
    assert sum(len(document["launched"]) for document in documents) <= 2
    assert all(len(rounds) <= 1 for document in documents for rounds in document["rounds"].values())
    for candidate in inputs.candidates:
        assert candidate.state in {"supported", "confirmed"}
        assert candidate.judge_verdict == "red_correct"
        assert candidate.evidence_refs == tuple(inputs.findings[candidate.finding_package_id]["direct_evidence"])
        package = load_package(chain.run_root, inputs, candidate.package_id)
        view = build_view(package, retrieval_core(chain.run_root, inputs), ViewLimits())
        brief = build_brief(
            candidate, finding=inputs.findings[candidate.finding_package_id], package=package,
            view=view, sink=sink_of(package), unit=None, headers=None, settings=poc_support.settings())
        assert not any(gap.startswith("poc_basis label") for gap in brief.gaps)
        assert set(candidate.poc_basis.entry + candidate.poc_basis.path) <= set(brief.document["poc_basis_labels"])

    def forbidden(*args, **kwargs):
        raise AssertionError("no model or compiler may be dispatched by the planning lane")

    job = build_job(infer=forbidden, executor_factory=forbidden, repository_root=ROOT)
    with lane.span("poc-planning"):
        outcome = run_job(chain.config, job, chain.fixture.run_id, chain.upstream(GATE), chain.env)
    assert outcome["completion_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    summary = chain.read("job_poc_generation", "publish.publish_handoff", "poc-generation.json")
    assert summary["counts"]["candidates"] == len(inputs.candidates)
    assert all(row["status"] == "not_applicable" for row in summary["candidates"])
    assert all("accepted language build" in row["reason"] for row in summary["candidates"])
    assert summary["execution_policy"] == "nothing is linked into an executable and nothing is run"
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="eligible-no-build", candidates=len(inputs.candidates))


def test_authentic_empty_candidates_are_not_a_missing_field():
    lane = acceptance_lane("authentic-poc-empty")
    with lane.span("chain"):
        chain = authentic_chain(lane, basis=False)
        inputs = verified(chain)
        assert inputs.candidates == ()
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="legitimate-empty")


def test_corrupt_review_is_rejected_before_dispatch(authentic):
    lane, chain = authentic
    inputs = verified(chain)
    path = chain.run_root / inputs.review_handoff["path"]
    original = path.read_bytes()
    try:
        path.write_bytes(original + b" ")
        with lane.span("corruption"):
            with pytest.raises((IntegrityError, ValueError), match="changed|integrity|provenance"):
                verified(chain)
    finally:
        path.write_bytes(original)
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="corrupt-before-dispatch")
