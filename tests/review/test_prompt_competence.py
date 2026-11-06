"""Scripted cell regressions; no model quality or live-provider claims."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.guidance import verify_bundle
from appsec_review.inference import ModelResult
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore,
    RetrievalLimits, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import RetrievalIntegrityError
from appsec_review.retrieval.model import normalize_relative_path
from appsec_review.review.capability import CellCapability
from appsec_review.review.competence import LIMITATION, ROLE, run_competence_case
from appsec_review.review.evaluation import OUTCOMES, load_cases, score
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import CellStatus, GapClass, IntegrityError, Role
from appsec_review.review.package_view import PackageView
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "review_guidance"
CASES = load_cases(FIXTURES / "competence_cases.json")
SCRIPTS = json.loads((FIXTURES / "competence_scripts.json").read_text(encoding="utf-8"))
SETTINGS = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
RUN_ID = "2026-11-06-0001"
OUTSIDE = "asr:evidence_artifact:" + "f" * 64
PRIVATE = "privateoutside_only_not_cell_evidence"


@dataclass
class Corpus:
    core: RetrievalCore
    capability: CellCapability
    view: PackageView
    labels: dict[str, str]


def accepted_corpus(directory: Path, case: dict[str, Any], *, page_size: int = 10,
                    max_turns: int = 6, max_queries: int = 8,
                    max_result_bytes: int = 16384, excerpt_bytes: int = 65536,
                    role: Role = ROLE, source_files: bool = False) -> Corpus:
    """A real accepted synthetic producer, shared with the opt-in manual acceptance entrypoint."""
    run_root = directory / "runs" / RUN_ID
    target = directory / "source"
    target.mkdir(parents=True)
    snapshot = "target-sha256:" + sha256_hex(case["sources"])
    fingerprint = index_fingerprint(
        name="source", target_snapshot=snapshot,
        producer_artifacts=[{"sha256": sha256_hex(case["sources"])}],
        tool_identity={"tool": "competence-synthetic-producer", "version": "1"},
        parser_identity="competence-source-files/1" if source_files else "competence-source/1",
        normalizer_identity="retrieval/2",
        mapping_identity="exact-source/1")
    path = run_root / "data" / "indices" / "source" / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="source", fingerprint=fingerprint, target_snapshot=snapshot)
    labels = {}
    for source in case["sources"]:
        file = target / normalize_relative_path(source["path"])
        file.parent.mkdir(parents=True, exist_ok=True)
        text = "\n" * (source["start_line"] - 1) + source["text"]
        file.write_text(text, encoding="utf-8")
        identity = LogicalIdentity.derive(
            EntityKind.SOURCE_SPAN, snapshot, {"path": source["path"], "sha256": file_sha256(file)})
        labels[source["label"]] = identity.value
        location = SourceLocation(
            snapshot, source["path"], file_sha256(file), 0, len(text.encode()),
            source["start_line"], source["start_line"] + len(source["text"].splitlines()) - 1,
            1, 1, {"producer": "competence-synthetic-producer"}, "fixture-exact", 1.0)
        builder.add_entity(EntityRecord(identity, source["path"], source["path"], source["text"], {}, location))
        if source_files:
            file_identity = LogicalIdentity.derive(
                EntityKind.SOURCE_FILE, snapshot, {"path": source["path"], "sha256": file_sha256(file)})
            builder.add_entity(EntityRecord(
                file_identity, source["path"], source["path"], source["text"],
                {"path": source["path"], "language": "C"}, location))
    lead = None
    if role is Role.RED_TEAM_ANALYST:
        lead = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"question": case["question"]})
        builder.add_entity(EntityRecord(lead, "fixture-lead", "fixture lead", case["question"], {}))
    builder.add_entity(EntityRecord(LogicalIdentity.parse(OUTSIDE), "outside", PRIVATE, PRIVATE, {}))
    gaps = tuple(case.get("coverage_gaps", ()))
    builder.add_coverage("source", "partial" if gaps else "complete", "; ".join(gaps) or None)
    digest = builder.build()
    manifest = run_root / "data" / "indices" / "manifests" / "corpus.json"
    write_manifest(
        manifest, run_id=RUN_ID, target_snapshot=snapshot, target_root=target,
        indexes=[IndexIdentity("source", "appsec-review/retrieval-index/2", digest, fingerprint,
                               path.relative_to(run_root).as_posix(),
                               {"tool": "competence-synthetic-producer", "version": "1"}, gaps)])
    reference = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest),
                 "size_bytes": manifest.stat().st_size}
    handoff = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    write_fixture_handoff(run_root, handoff, {
        "job_id": "fixture", "artifacts": [reference],
        "outputs": {"fixture.index": {"index_manifest": reference}},
    })
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff),
        "manifest_path": reference["path"], "manifest_sha256": reference["sha256"],
    })
    core = RetrievalCore(directory / "runs", RUN_ID,
                         limits=RetrievalLimits(max_excerpt_bytes=excerpt_bytes))
    package = {
        "question": case["question"], "affected": [{
            "label": "A1", "identity": labels["S1"],
            "location": {"path": case["sources"][0]["path"], "line": case["sources"][0]["start_line"]}}],
        "retrieval_hint": {"kind": "source_span", "index": "source"},
        "coverage_gaps": list(gaps),
    }
    view = PackageView(
        document=package, labels={"A1": labels["S1"], **({"L1": lead.value} if lead else {})},
        files={"gaps.jsonl": tuple({"reason": gap} for gap in gaps)},
        locator_paths=frozenset(source["path"] for source in case["sources"]),
        lead_refs=(lead.value,) if lead else (),
        packaged_refs=frozenset({labels["S1"], *([lead.value] if lead else [])}))
    if lead:
        package["leads"] = [{"label": "L1", "summary": case["question"]}]
    capability = CellCapability.issue(
        run_id=RUN_ID, manifest_sha256=core.manifest_sha256,
        package_id="competence-" + sha256_hex(package), package_sha256=sha256_hex(package), role=role, round=0,
        tools=("find", "read_excerpt"), indexes=("source", "artifacts"),
        entities=(*labels.values(), *([lead.value] if lead else [])), max_queries=max_queries, max_turns=max_turns,
        page_size=page_size, max_depth=2, max_result_bytes=max_result_bytes)
    return Corpus(core, capability, view, labels)


def returned_rows(request) -> list[dict[str, Any]]:
    return [row for turn in request.transcript if turn["from"] == "application"
            for response in turn["responses"] for row in response.get("results", [])]


class ScriptedTransport:
    """Only model I/O is scripted. Requests consume real application cursors, labels and excerpts."""

    def __init__(self, case: dict[str, Any], script: str, *, answer: str | None = None):
        self.case = case
        self.steps = list(SCRIPTS["scripts"][script])
        self.answer = answer or case["expected"]
        self.calls = 0

    def __call__(self, request, *, timeout_seconds):
        assert timeout_seconds > 0
        step = self.steps[self.calls]
        self.calls += 1
        rows = returned_rows(request)
        parameters = {"kind": "source_span", "indexes": ["source"]}
        if step in {"find_source", "find_first_page", "find_next_page"}:
            if step in {"find_first_page", "find_next_page"}:
                parameters["limit"] = 1
            if step == "find_next_page":
                parameters["cursor"] = request.transcript[-1]["responses"][0]["next_cursor"]
                assert parameters["cursor"]
            requests = [{"tool": "find", "parameters": parameters}]
        elif step == "read_returned":
            refs = list(dict.fromkeys(row["identity"] for row in rows))
            assert refs
            requests = [{"tool": "read_excerpt", "parameters": {"identity": ref, "context_lines": 0}}
                        for ref in refs]
        elif step == "deny_untrusted_shell":
            requests = [{"tool": "shell", "parameters": {"command": "read privateoutside"}}]
        elif step == "find_missing_artifact":
            requests = [{"tool": "find", "parameters": {"kind": "evidence_artifact", "indexes": ["artifacts"]}}]
        else:
            result = deepcopy(SCRIPTS["answers"]["abstain" if step == "truncated_answer" else self.answer])
            citations = list(dict.fromkeys(row["label"] for row in rows))
            if step == "wrong_label_answer":
                citations = ["Q999"]
            elif step == "wrong_identity_answer":
                citations = [OUTSIDE]
            elif step == "path_citation_answer":
                citations = ["frame.cpp:4"]
            elif step == "invalid_anchor_answer":
                result = deepcopy(SCRIPTS["answers"]["abstain"])
                result["evidence_requests"][0]["anchors"] = ["Q999"]
            if step == "truncated_answer":
                result["per_predicate"]["missing_or_ineffective_guard"]["missing"] = [
                    "The excerpt was truncated before the decisive guard; retrieve the omitted source."]
            result["per_predicate"]["missing_or_ineffective_guard"]["cites"] = citations
            return ModelResult({"action": "final", "result": result}, input_tokens=80, output_tokens=20)
        return ModelResult({"action": "retrieve", "requests": requests}, input_tokens=80, output_tokens=20)


def execute(directory, case, script="retrieve_then_resolve", *, corpus=None, settings=SETTINGS, **limits):
    corpus = corpus or accepted_corpus(directory, case, **limits)
    transport = ScriptedTransport(case, script)
    result = run_competence_case(
        ROOT, case, settings, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment",
        transport=transport)
    assert transport.calls == len(transport.steps)
    return corpus, result


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_real_multiturn_corpus_resolves_with_grounded_scripted_answers(tmp_path, case):
    corpus, result = execute(tmp_path, case)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.row["status"] == "completed" and result.row["correct"]
    assert result.row["decision"] == case["expected"]
    assert result.row["execution"] == "scripted" and result.row["limitation"] == LIMITATION
    assert result.outcome.counts["turns"] == 3
    assert result.outcome.counts["queries"] == 1 + len(case["sources"])
    assert result.outcome.counts["denials"] == 0
    assert result.row["manifest_sha256"] == corpus.core.manifest_sha256
    assert result.row["settings_sha256"] == sha256_hex(SETTINGS.as_document())
    assert result.row["model"]["model"] == SETTINGS.profile_for(ROLE).model
    assert all(request.provider == SETTINGS.profile_for(ROLE).provider for request in result.requests)
    assert not any("excerpt" in row for row in returned_rows(result.requests[1]))
    excerpts = [row for row in returned_rows(result.requests[-1]) if "excerpt" in row]
    assert {row["identity"] for row in excerpts} == set(corpus.labels.values())
    for row in excerpts:
        assert row["location"]["file_sha256"] == file_sha256(corpus.core.target_root / row["location"]["path"])
    initial = json.dumps(result.requests[0].task_input)
    assert all(f'"{field}"' not in initial for field in ("expected", "decisive_labels", "family"))
    assert all(source["text"] not in initial for source in case["sources"])
    receipt = json.loads(result.outcome.receipt_paths[0].read_text())
    assert not any(source["text"] in json.dumps(receipt) for source in case["sources"])
    assert all(request.guidance_bundle_sha256 == result.row["guidance_sha256"] for request in result.requests)
    bundle_path = corpus.core.run_root / "data" / "guidance" / result.row["guidance_sha256"] / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    verify_bundle(bundle)
    assert bundle["sections"][0]["name"] == "governing_rules"
    assert any(section["name"] == "procedures" and section["items"] for section in bundle["sections"])
    catalog = result.requests[0].task_input["turn_protocol"]["tool_catalog"]
    assert {tool["name"] for tool in catalog} == set(corpus.capability.tools)


def test_real_cursor_paging_retains_source_identity_and_remaining_budget(tmp_path):
    corpus, result = execute(tmp_path, CASES[0], "paging", page_size=1, max_turns=4, max_queries=4)
    assert result.row["correct"] and result.outcome.counts["turns"] == 4
    applications = [request.transcript[-1] for request in result.requests[1:]]
    first, second = (application["responses"][0] for application in applications[:2])
    assert first["next_cursor"] and second["next_cursor"] is None
    assert first["results"][0]["identity"] != second["results"][0]["identity"]
    assert {first["results"][0]["identity"], second["results"][0]["identity"]} == set(corpus.labels.values())
    assert [item["remaining_queries"] for item in applications] == [3, 2, 0]
    assert [item["remaining_turns"] for item in applications] == [3, 2, 1]
    assert [item["final_required"] for item in applications] == [False, False, True]
    assert result.outcome.counts["queries"] == 4


def test_denial_recovery_never_executes_unlisted_tool_and_costs_a_query(tmp_path):
    _, result = execute(tmp_path, CASES[1], "denial_recovery")
    assert result.row["correct"] and result.row["decision"] == "safe"
    response = result.requests[1].transcript[-1]["responses"][0]
    assert response["status"] == "denied" and response["code"] == "unknown_tool"
    assert response["counted_as_query"] and response["corrected"]["use_one_of"]
    assert "shell" not in response["corrected"]["use_one_of"]
    assert result.outcome.counts["denials"] == 1 and result.outcome.counts["queries"] == 4
    assert result.outcome.gaps == ()
    assert result.outcome.security_events[0]["denial_code"] == "unknown_tool"
    assert "read privateoutside" not in json.dumps(result.outcome.security_events)


def test_misleading_source_is_retrieved_as_data_and_does_not_change_authority(tmp_path):
    _, result = execute(tmp_path, CASES[1])
    prompt = result.requests[0].guidance_text
    assert "MISLEADING_UNTRUSTED" not in prompt
    assert "MISLEADING_UNTRUSTED" in json.dumps(result.requests[-1].transcript)
    assert "shell" not in result.requests[-1].task_input["capability"]["tools"]
    assert result.row["decision"] == "safe" and result.row["unsupported"] == 0
    assert all(request.guidance_text == prompt for request in result.requests)


def test_missing_accepted_artifact_is_a_named_gap_not_a_safety_claim(tmp_path):
    _, result = execute(tmp_path, CASES[-1], "missing_artifact")
    response = result.requests[1].transcript[-1]["responses"][0]
    assert response["status"] == "ok" and response["results"] == []
    assert response["coverage_gaps"] == ["artifacts index is unavailable"]
    assert result.row["correct"] and result.row["decision"] == "abstain"
    assert result.row["named_gap"] and result.row["conclusions"] == 0
    assert result.outcome.result["evidence_requests"][0]["anchors"]
    source_response = result.requests[2].transcript[-1]["responses"][0]
    assert any("overlay" in gap for gap in source_response["coverage_gaps"])


@pytest.mark.parametrize("script", ["wrong_label", "wrong_identity"])
def test_wrong_citations_are_dropped_by_real_expander_and_never_score_as_grounded(tmp_path, script):
    _, result = execute(tmp_path, CASES[0], script)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.outcome.result["citations"] == {}
    assert result.outcome.result["proposed_relations"] == []
    assert not result.row["correct"] and not result.row["grounded"] and result.row["unsupported"] == 1
    receipt = json.loads(result.outcome.receipt_paths[0].read_text())
    assert any("does not resolve" in item for item in receipt["feedback"])
    assert any("recorded as unresolved" in item for item in receipt["feedback"])


def test_unresolved_evidence_request_anchor_is_rejected_not_silently_scored(tmp_path):
    _, result = execute(tmp_path, CASES[2], "invalid_anchor")
    assert result.outcome.record.status is CellStatus.INVALID
    assert result.row["status"] == "invalid"
    assert result.outcome.gaps[0].gap_class is GapClass.SCHEMA_ERROR
    assert result.outcome.result is None


def test_same_denial_twice_ends_without_claiming_abstention(tmp_path):
    _, result = execute(tmp_path, CASES[0], "repeated_denial")
    assert result.outcome.record.status is CellStatus.INVALID
    assert result.outcome.gaps[0].gap_class is GapClass.AUTHORITY_ERROR
    assert result.outcome.counts["denials"] == 2 and result.outcome.counts["queries"] == 2
    assert result.row["status"] == "invalid" and "decision" not in result.row
    assert score(CASES[:1], [result.row], ROLE.value)["gaps"] == 1


def test_final_turn_is_enforced_by_cell_not_fixture(tmp_path):
    _, result = execute(tmp_path, CASES[0], "final_turn_ignored", max_turns=2)
    assert result.requests[1].transcript[-1]["final_required"]
    assert result.outcome.record.status is CellStatus.TIMED_OUT
    assert result.outcome.gaps[0].gap_class is GapClass.BUDGET_GAP
    assert result.outcome.gaps[0].reason == "cap_reached_without_final"
    assert result.outcome.counts["queries"] == 1
    assert result.outcome.result is None and result.row["status"] == "invalid"


def test_excerpt_truncation_is_explicit_and_cannot_establish_fixture_resolution(tmp_path):
    _, result = execute(tmp_path, CASES[1], "truncated_excerpt", excerpt_bytes=24)
    excerpts = [row for row in returned_rows(result.requests[-1]) if "excerpt" in row]
    assert excerpts and all(row["excerpt_truncated"] for row in excerpts)
    assert all(len(row["excerpt"].encode()) <= 24 for row in excerpts)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.row["decision"] == "abstain" and result.row["named_gap"]
    assert not result.row["correct"]


def test_response_byte_truncation_is_not_an_empty_clean_result(tmp_path):
    corpus = accepted_corpus(tmp_path, CASES[0], max_result_bytes=256, max_turns=2)
    calls = []

    def scripted(request, *, timeout_seconds):
        calls.append(request)
        if not request.transcript:
            return ModelResult({"action": "retrieve", "requests": [
                {"tool": "find", "parameters": {"kind": "source_span"}}]})
        response = request.transcript[-1]["responses"][0]
        assert response["truncated"] and response["results"] == [] and response["next_cursor"] is None
        return ModelResult({"action": "final", "result": SCRIPTS["answers"]["abstain"]})

    result = run_competence_case(
        ROOT, CASES[0], SETTINGS, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment", transport=scripted)
    assert len(calls) == 2 and result.row["decision"] == "abstain" and not result.row["correct"]
    assert result.row["input_tokens"] is None and result.row["output_tokens"] is None
    assert score(CASES[:1], [result.row], ROLE.value)["tokens_per_correct_resolution"] is None


def test_find_cannot_export_other_package_rows_or_grant_their_identity(tmp_path):
    corpus = accepted_corpus(tmp_path, CASES[0], max_turns=3)
    requests = []

    def scripted(request, *, timeout_seconds):
        requests.append(request)
        if len(requests) == 1:
            proposal = {"action": "retrieve", "requests": [
                {"tool": "find", "parameters": {"name": PRIVATE}}]}
        elif len(requests) == 2:
            response = request.transcript[-1]["responses"][0]
            assert response["results"] == [] and response["withheld_out_of_scope"] == 1
            proposal = {"action": "retrieve", "requests": [
                {"tool": "read_excerpt", "parameters": {"identity": OUTSIDE}}]}
        else:
            assert request.transcript[-1]["responses"][0]["code"] == "entity_out_of_scope"
            proposal = {"action": "final", "result": SCRIPTS["answers"]["abstain"]}
        return ModelResult(proposal)

    result = run_competence_case(
        ROOT, CASES[0], SETTINGS, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment", transport=scripted)
    assert result.outcome.counts["denials"] == 1
    assert result.row["decision"] == "abstain" and not result.row["correct"]


def test_model_and_corpus_failures_do_not_bypass_opt_in_or_identity_binding(tmp_path):
    corpus = accepted_corpus(tmp_path, CASES[0])
    kwargs = dict(core=corpus.core, capability=corpus.capability, view=corpus.view,
                  source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment")
    with pytest.raises(ValueError, match="live"):
        run_competence_case(ROOT, CASES[0], SETTINGS, **kwargs)
    assert not kwargs["output"].exists()
    wrong = replace(corpus.capability, manifest_sha256="0" * 64)
    with pytest.raises(IntegrityError, match="hash check"):
        run_competence_case(ROOT, CASES[0], SETTINGS, **{**kwargs, "capability": wrong},
                            transport=ScriptedTransport(CASES[0], "retrieve_then_resolve"))
    accepted = corpus.core.run_root / "data" / "indices" / "accepted.json"
    pointer = json.loads(accepted.read_text())
    pointer["manifest_sha256"] = "0" * 64
    atomic_json(accepted, pointer)
    with pytest.raises(RetrievalIntegrityError, match="bound"):
        RetrievalCore(tmp_path / "runs", RUN_ID)


def test_all_domains_have_controls_and_incomplete_cases_without_quality_claims():
    families = {case["family"] for case in CASES}
    assert families == {"native_capacity", "object_authorization", "deployed_configuration"}
    for family in families:
        assert {case["expected"] for case in CASES if case["family"] == family} == OUTCOMES
    assert "never live" in SCRIPTS["limitation"]
    assert all(case.get("coverage_gaps") for case in CASES if case["expected"] == "abstain")


def test_job_turn_budget_stops_real_loop_without_a_second_transport_call(tmp_path):
    corpus = accepted_corpus(tmp_path, CASES[0])
    settings = replace(SETTINGS, budgets=replace(SETTINGS.budgets, max_model_turns=1))
    transport = ScriptedTransport(CASES[0], "retrieve_then_resolve")
    result = run_competence_case(
        ROOT, CASES[0], settings, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment", transport=transport)
    assert transport.calls == 1
    assert result.outcome.record.status is CellStatus.TIMED_OUT
    assert result.outcome.gaps[0].gap_class is GapClass.BUDGET_GAP
    assert result.row["status"] == "invalid"
    budget = json.loads((corpus.core.run_root / "data" / "jobs" / "job_inference_security_review"
                         / "budget" / "budget.json").read_text())
    assert budget["model_turns"] == 1 and budget["retrieval_queries"] == 1


def test_path_citations_fail_the_real_compact_schema(tmp_path):
    _, result = execute(tmp_path, CASES[0], "path_citation")
    assert result.outcome.record.status is CellStatus.INVALID
    assert result.outcome.gaps[0].gap_class is GapClass.SCHEMA_ERROR
    assert result.row["status"] == "invalid"
    assert result.outcome.result is None


def test_grounded_false_positive_is_still_an_unsupported_conclusion(tmp_path):
    case = CASES[1]
    corpus = accepted_corpus(tmp_path, case)
    transport = ScriptedTransport(case, "retrieve_then_resolve", answer="vulnerable")
    result = run_competence_case(
        ROOT, case, SETTINGS, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment", transport=transport)
    assert result.row["grounded"] and result.row["decision"] == "vulnerable"
    assert not result.row["correct"] and result.row["unsupported"] == 1
    assert score([case], [result.row], ROLE.value)["unsupported_conclusion_rate"]["value"] == 1


def test_empty_abstention_is_not_a_justified_resolution(tmp_path):
    case = CASES[2]
    corpus = accepted_corpus(tmp_path, case)
    scripted = ScriptedTransport(case, "retrieve_then_resolve")

    def transport(request, *, timeout_seconds):
        answer = scripted(request, timeout_seconds=timeout_seconds)
        if answer.proposal["action"] == "final":
            result = answer.proposal["result"]
            result.pop("evidence_requests")
            result["per_predicate"]["missing_or_ineffective_guard"].pop("missing")
        return answer

    result = run_competence_case(
        ROOT, case, SETTINGS, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment", transport=transport)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.row["decision"] == "abstain" and not result.row["named_gap"] and not result.row["correct"]


def test_failed_transport_usage_is_not_reported_as_complete(tmp_path):
    case = CASES[0]
    corpus = accepted_corpus(tmp_path, case)
    scripted = ScriptedTransport(case, "retrieve_then_resolve")

    def transport(request, *, timeout_seconds):
        if request.transcript:
            raise TimeoutError("scripted provider boundary failure")
        return scripted(request, timeout_seconds=timeout_seconds)

    result = run_competence_case(
        ROOT, case, SETTINGS, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment", transport=transport)
    assert result.outcome.record.status is CellStatus.TIMED_OUT
    assert result.row["status"] == "invalid"
    assert result.row["input_tokens"] is None and result.row["output_tokens"] is None
    assert not score([case], [result.row], ROLE.value)["usage_complete"]
