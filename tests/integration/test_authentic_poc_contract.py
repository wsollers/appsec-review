"""Authentic producer/consumer seams: no edited handoffs or substitute schemas."""
from __future__ import annotations

from pathlib import Path
import hashlib
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
from appsec_review.storage.validation import validation_scope
from tests.acceptance_review_stages import (
    consumer_chain, fresh_chain, prepare_chain, run_gate, run_poc_planning, run_review,
)
from tests.fixtures.inference_review.acceptance import JOB
from tests.fixtures.inference_review.fake_infer import ScriptedInfer

ROOT = Path(__file__).resolve().parents[2]
ENTRY = "asr:entry_point:" + "a" * 64
HOP = "asr:call_site:" + "b" * 64


def acceptance_lane(name: str) -> LaneWorkspace:
    return LaneWorkspace.create(Path(os.environ.get("APPSEC_ACCEPTANCE_ROOT", ROOT)), name)


def attach_call_chain(fixture):
    """Direct p(s) -> strcpy flow and absent guard over the fixture's real bytes."""
    from appsec_review.graph.contract import Family
    from appsec_review.retrieval import (
        EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord,
    )
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
        Family.GUARD_FACT, {"sink_identity": sink.identity.value, "condition_path": PARSE,
                           "condition_start_byte": location.start_byte,
                           "condition_end_byte": location.end_byte},
        {**results_for(Family.GUARD_FACT, sink=sink.identity.value),
         "enclosing_function": {"symbol": p.identity.value, "display": "p"}}, location, snapshot=SNAPSHOT)
    tag = EntityRecord(
        LogicalIdentity.derive(EntityKind.TAG_ASSIGNMENT, SNAPSHOT, {"assignment": "recorded-public-surface"}),
        "recorded-public-surface", "surface:entry:http-public", "recorded public entry context",
        {"tag": "surface:entry:http-public", "basis": "declared",
         "subject": {"logical_id": fixture.ids[PARSE], "component_id": "component:0002"}}, location)
    lead = EntityRecord(
        LogicalIdentity.parse(fixture.ids["sast_critical"]), "sast_critical", "c.strcpy", "c.strcpy tool-semgrep",
        {"tool_id": "tool-semgrep", "native_rule_id": "c.strcpy", "category": "source_sast",
         "native_severity": "CRITICAL", "message": "c.strcpy lead", "rule_mapping": {"cwe": ["CWE-120"]},
         "language": "C"}, location)
    _publish(fixture, [
        ("observations", "authentic-lead", {"job": "job_evidence_collection", "producer": "tool-semgrep"},
         [lead], [RelationRecord(RelationKind.OBSERVED_AT, lead.identity.value, fixture.ids[PARSE], True, 1.0)],
         ("authentic-lead", "complete", None)),
        ("graph", "authentic-facts", {"job": "job_code_graph_index", "build_unit_id": "native-main"},
         [p, sink, call, entry, flow, guard], [], ("graph:native:facts", "complete", None)),
        ("tags", "authentic-surface-tags", {"job": "job_security_tagging", "family": "surface_data"},
         [tag], [], ("recorded-public-surface", "complete", None))])
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


def authentic_chain(lane: LaneWorkspace, *, basis=True, benign=False, blocked=False, ci_only=False,
                    publish_gate=True):
    options = dict(basis=basis, benign=benign, blocked=blocked, ci_only=ci_only)
    chain = prepare_chain(lane, **options)
    run_review(lane, chain, **options)
    if publish_gate:
        run_gate(lane, chain)
    return chain


@pytest.fixture(scope="module")
def authentic():
    staged = consumer_chain("native-positive")
    if staged is not None:
        return staged
    lane = acceptance_lane("authentic-poc-contract")
    with lane.span("chain"):
        chain = authentic_chain(lane, publish_gate=False)
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="authentic-review-gate")
    return lane, chain


def verified(chain):
    with validation_scope(chain.run_root):
        return verify_inputs(
            chain.run_root, review_schemas=SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review"))


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


def assert_poc_candidates(lane, chain):
    from appsec_review.jobs.job_poc_generation.brief import build_brief
    from appsec_review.jobs.job_poc_generation.inputs import load_package, retrieval_core, sink_of
    from appsec_review.review.package_view import ViewLimits, build_view
    from tests import poc_support

    from appsec_review.jobs.bound_artifacts import read_bound_json
    with lane.span("verify-poc-contract"), validation_scope(chain.run_root):
        inputs = verified(chain)
        assert len(inputs.candidates) == 1
        handoff = chain.handoff(JOB)
        documents = [read_bound_json(chain.run_root, handoff["outputs"][f"{name}_review.teams"]["artifact"])
                     for name in ("lead", "hunt")]
        assert sum(len(document["launched"]) for document in documents) == 1
        assert all(len(rounds) <= 1 for document in documents for rounds in document["rounds"].values())
        for candidate in inputs.candidates:
            assert candidate.state in {"supported", "confirmed"}
            assert candidate.judge_verdict == "red_correct"
            finding = inputs.findings[candidate.finding_package_id]
            assert finding["ship_block"]["technical_severity"] in {"high", "critical"}
            assert candidate.evidence_refs == tuple(finding["direct_evidence"])
            package = load_package(chain.run_root, inputs, candidate.package_id)
            view = build_view(package, retrieval_core(chain.run_root, inputs), ViewLimits())
            brief = build_brief(
                candidate, finding=finding, package=package,
                view=view, sink=sink_of(package), unit=None, headers=None, settings=poc_support.settings())
            assert not any(gap.startswith("poc_basis label") for gap in brief.gaps)
            assert set(candidate.poc_basis.entry + candidate.poc_basis.path) <= set(brief.document["poc_basis_labels"])
    return inputs


def assert_poc_output(chain, candidates):
    from appsec_review.indexing.store import accepted_handoff
    from appsec_review.jobs.bound_artifacts import read_bound_json

    with validation_scope(chain.run_root):
        accepted = accepted_handoff(chain.run_root, "job_poc_generation")
        assert accepted is not None
        assert accepted.handoff["upstream_handoff_sha256"][JOB] == chain.pointer_sha(JOB)
        summary = read_bound_json(
            chain.run_root, accepted.handoff["outputs"]["publish.publish_handoff"]["artifact"])
        SchemaSet(ROOT / "docs" / "schemas" / "poc-generation").validate("poc-generation", summary)
        assert summary["counts"]["candidates"] == candidates
        assert all(row["status"] == "not_applicable" for row in summary["candidates"])
        assert all("accepted language build" in row["reason"] for row in summary["candidates"])
        assert summary["execution_policy"] == "nothing is linked into an executable and nothing is run"


def test_real_review_and_poc_planning_use_authoritative_contracts(authentic):
    from appsec_review.acceptance.staging import stage_context

    lane, chain = authentic
    if stage_context() is None:
        candidate_count = run_poc_planning(lane, chain)
    else:
        inputs = assert_poc_candidates(lane, chain)
        candidate_count = len(inputs.candidates)
        assert_poc_output(chain, candidate_count)
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="eligible-no-build", candidates=candidate_count)


def test_authentic_empty_candidates_are_not_a_missing_field():
    staged = consumer_chain("native-empty")
    if staged is None:
        lane = acceptance_lane("authentic-poc-empty")
        with lane.span("chain"):
            chain = authentic_chain(lane, basis=False, publish_gate=False)
    else:
        lane, chain = staged
    with lane.span("verify-empty"):
        inputs = verified(chain)
        assert inputs.candidates == ()
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="legitimate-empty")


def test_corrupt_review_is_rejected_before_dispatch(authentic):
    lane, chain = authentic
    chain = fresh_chain(chain, "corrupt-review")
    inputs = verified(chain)
    path = chain.run_root / inputs.review_handoff["path"]
    original = path.read_bytes()
    changed = original + b" "
    path.write_bytes(changed)
    with lane.span("corruption"):
        with pytest.raises((IntegrityError, ValueError), match="changed|integrity|provenance"):
            verified(chain)
    lane.emit("ACCEPTANCE_MUTATION_VALIDATED", vector="review-handoff",
              run_root=str(chain.run_root), path=path.relative_to(chain.run_root).as_posix(),
              before_sha256=hashlib.sha256(original).hexdigest(),
              after_sha256=hashlib.sha256(changed).hexdigest(),
              validator="verify_inputs", outcome="rejected")
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="corrupt-before-dispatch")
