"""The adjudication judge: shuffle, selection, presentation, expansion, scheduling, ledger and the PoC gate.

The pure parts (``review.judge``, ``review.compact.expand_judge``) are tested directly; the scheduling, request
blindness, ledger events and R5 invariance run the real review team with the scripted ``Infer`` double of
``tests.fixtures.inference_review.fake_infer`` (no model).
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType

import pytest

from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.job import package_works
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import run_lane, run_team
from appsec_review.config.inference_review import JudgeSettings, PocCandidateSettings
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.compact import deshuffle, expand_judge
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.judge import (
    SideInput, blue_side, present, red_affirms, red_side, scrub, selected, side_assignment,
)
from appsec_review.review.labels import LabelTable
from appsec_review.review.ledger import EventKind, merge_shards, project
from appsec_review.review.models import (
    CellStatus, ClaimState, GapClass, JudgeVerdict, JudgeVerdictValue, Lane, Role,
)
from appsec_review.review.package_view import PackageView
from tests.fixtures.inference_review.acceptance import ROOT
from tests.fixtures.inference_review.fake_infer import ScriptedInfer
from tests.review.test_team_handler import Recording, prepared  # noqa: F401  (the shared review fixture)

SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
MANIFEST = "7" * 64
CLAIM = "claim-" + "1" * 64
K1, S1, G2, X9 = ("asr:sink_site:" + "1" * 64, "asr:source_span:" + "2" * 64, "asr:guard_fact:" + "3" * 64,
                  "asr:tool_observation:" + "9" * 64)


def ref(kind: str, digit: str) -> str:
    return f"asr:{kind}:{digit * 64}"


# ------------------------------------------------------------------------------------------------ shuffle


def test_side_a_is_chosen_by_the_low_bit_of_the_documented_digest() -> None:
    seen = set()
    for number in range(64):
        claim = f"claim-{number:064x}"
        digest = hashlib.sha256((MANIFEST + claim + "judge-order").encode()).digest()
        expected = "red" if digest[-1] & 1 == 0 else "blue"
        assignment = side_assignment(MANIFEST, claim)
        assert assignment["A"] == expected and assignment == side_assignment(MANIFEST, claim)
        assert assignment["B"] == ("blue" if expected == "red" else "red")
        seen.add(assignment["A"])
    assert seen == {"red", "blue"}                                             # unrelated to role
    # A further judge of the same claim gets its own order; the first keeps exactly the documented tag.
    later = {side_assignment(MANIFEST, CLAIM, index)["A"] for index in range(1, 12)}
    assert later == {"red", "blue"} and side_assignment(MANIFEST, CLAIM, 0) == side_assignment(MANIFEST, CLAIM)
    # A different accepted manifest reshuffles.
    assert {side_assignment(str(number) * 64, CLAIM)["A"] for number in range(10)} == {"red", "blue"}


# ------------------------------------------------------------------------------------------------ selection


@pytest.mark.parametrize("when, red, blues, expected", [
    ("all", True, ["supports", "supports"], True),
    ("all", False, ["contradicts", "contradicts"], False),                      # red affirmed nothing: no judge
    ("disagreement", True, ["supports", "supports"], False),                    # blue agrees with red
    ("disagreement", True, ["contradicts", "supports"], True),
    ("disagreement", True, ["qualifies", "qualifies"], True),
    ("disagreement", True, ["unresolved", "unresolved"], True),                 # a predicate left unresolved
    ("disagreement", True, ["supports", None], True),                           # no answer is not agreement
    ("disagreement", True, ["supports", "supports", "qualifies"], True),
    ("disagreement", False, ["contradicts", "contradicts"], False),
])
def test_when_selects_the_claims_a_judge_sees(when, red, blues, expected) -> None:
    assert selected(when, red_affirmed=red, blue_dispositions=blues) is expected


def test_blue_against_blue_is_a_disagreement_even_when_both_oppose_red() -> None:
    assert selected("disagreement", red_affirmed=True, blue_dispositions=["contradicts", "contradicts"]) is True
    assert selected("disagreement", red_affirmed=True, blue_dispositions=["supports", "supports"]) is False
    with pytest.raises(ValueError):
        selected("sometimes", red_affirmed=True, blue_dispositions=[])


def test_the_two_sides_are_read_from_the_expanded_results() -> None:
    red = red_side([({"statement": "memcpy overflows the name", "evidence_ids": ["e1"], "counterevidence_ids": ["e2"]},
                     {"evidence_refs": [{"local_id": "e1", "predicate": "affected_construct", "entity_id": K1},
                                        {"local_id": "e2", "predicate": "missing_or_ineffective_guard",
                                         "entity_id": G2}]})])
    assert red_affirms(red) and red.stance == "supports"
    assert red.predicates == {"affected_construct": ("supports", [K1]),
                              "missing_or_ineffective_guard": ("qualifies", [G2])}
    only_counter = red_side([({"statement": "s", "evidence_ids": [], "counterevidence_ids": ["e2"]},
                              {"evidence_refs": [{"local_id": "e2", "predicate": "affected_construct",
                                                  "entity_id": K1}]})])
    assert not red_affirms(only_counter)
    side, dispositions = blue_side([
        {"disposition": "contradicts", "rationale": "guard", "proposed_relations": [
            {"predicate": "missing_or_ineffective_guard", "kind": "contradicts", "entity_id": G2, "rationale": "x"}]},
        {"disposition": "unresolved", "rationale": "nothing", "proposed_relations": []}, None])
    assert dispositions == ["contradicts", "unresolved", None] and side.stance == "contradicts"
    assert side.predicates == {"missing_or_ineffective_guard": ("contradicts", [G2])} and side.why == "guard | nothing"
    empty, _ = blue_side([None, None])
    assert empty.stance == "unresolved" and "no answer" in empty.why


# ------------------------------------------------------------------------------------------------ presentation


def view(**labels: str) -> PackageView:
    return PackageView(document={}, labels=dict(labels), files={}, locator_paths=frozenset(), lead_refs=(),
                       packaged_refs=frozenset(labels.values()))


def test_a_judge_sees_package_labels_unchanged_and_re_presented_rows_under_j_labels() -> None:
    red = SideInput("supports", {"affected_construct": ("supports", [K1, X9]),
                                 "missing_or_ineffective_guard": ("qualifies", [G2])}, "red reason")
    blue = SideInput("contradicts", {"missing_or_ineffective_guard": ("contradicts", [G2, S1])}, "blue reason")
    shown = present({"red": red, "blue": blue}, {"A": "blue", "B": "red"}, view(K1=K1, G2=G2), max_why=600,
                    max_rows=12, describe=lambda identity: f"resolved {identity[-4:]}")
    # Side A is blue here; K1 and G2 keep their package labels, S1 and X9 are new rows under J labels.
    assert shown.sides["A"]["stance"] == "contradicts" and shown.sides["B"]["stance"] == "supports"
    assert shown.sides["A"]["per_predicate"]["missing_or_ineffective_guard"] == {
        "stance": "contradicts", "cites": ["G2", "J1"]}
    assert shown.sides["B"]["per_predicate"]["affected_construct"] == {"stance": "supports", "cites": ["K1", "J2"]}
    assert shown.cited_rows == {"J1": {"ref": S1, "summary": f"resolved {S1[-4:]}"},
                                "J2": {"ref": X9, "summary": f"resolved {X9[-4:]}"}}
    assert shown.rows == (S1, X9) and shown.view.labels["J1"] == S1 and shown.view.labels["K1"] == K1
    again = present({"red": red, "blue": blue}, {"A": "blue", "B": "red"}, view(K1=K1, G2=G2), max_why=600,
                    max_rows=12, describe=lambda identity: f"resolved {identity[-4:]}")
    assert again.sides == shown.sides and again.cited_rows == shown.cited_rows


def test_each_side_is_bounded_and_every_omission_is_named() -> None:
    cites = [ref("guard_fact", f"{number:x}") for number in range(14)]
    red = SideInput("supports", {"affected_construct": ("supports", cites[:8]),
                                 "attacker_input_control": ("supports", cites[8:])}, "r" * 700)
    blue = SideInput("qualifies", {}, "b" * 10)
    shown = present({"red": red, "blue": blue}, {"A": "red", "B": "blue"}, view(), max_why=600, max_rows=12)
    side = shown.sides["A"]
    kept = {label for entry in side["per_predicate"].values() for label in entry["cites"]}
    assert len(kept) == 12 and shown.sides["A"]["omitted"]["cited_rows"] == 2
    assert len(side["why"]) == 600 and side["why"].endswith("…") and side["omitted"]["why_characters"] == 101
    assert "omitted" not in shown.sides["B"] and shown.omitted == {"A": side["omitted"], "B": {}}
    assert len(shown.cited_rows) == 12


def test_identifying_terms_are_removed_from_a_sides_reason() -> None:
    text, count = scrub("the Red_Team_Analyst and blue_control agree; actor-123", ["red_team_analyst", "blue_control"])
    assert text == "the [removed] and [removed] agree; actor-123" and count == 2
    red = SideInput("supports", {}, "written by red_team_analyst")
    shown = present({"red": red, "blue": SideInput()}, {"A": "red", "B": "blue"}, view(), max_why=600, max_rows=12,
                    markers=["red_team_analyst"])
    assert shown.sides["A"]["why"] == "written by [removed]" and shown.sides["A"]["omitted"] == {
        "removed_identifying_terms": 1}


# ------------------------------------------------------------------------------------------------ expansion


def expand(compact: dict, side_map: dict[str, str], labels: dict[str, str] | None = None):
    table = LabelTable(labels if labels is not None else {"K1": K1, "G2": G2, "S1": S1, "J1": X9})
    return expand_judge(compact, table, claim_id=CLAIM, side_map=side_map, schema_errors=SCHEMAS.errors)


@pytest.mark.parametrize("side_map", [{"A": "red", "B": "blue"}, {"A": "blue", "B": "red"}])
def test_the_application_de_shuffles_every_verdict_through_the_stored_map(side_map) -> None:
    red_letter = "A" if side_map["A"] == "red" else "B"
    blue_letter = "B" if red_letter == "A" else "A"
    cases = {red_letter: "red_correct", blue_letter: "blue_correct", "both": "partly", "neither": "neither"}
    for choice, expected in cases.items():
        expansion = expand({"verdict": choice, "per_predicate": {"affected_construct": {"verdict": choice,
                                                                                         "cites": ["K1", "S1"]}},
                            "reason": "because"}, side_map)
        assert expansion.errors == [], expansion.errors
        result = expansion.result
        assert result["verdict"] == expected and result["per_predicate"]["affected_construct"] == {
            "verdict": expected, "cites": [K1, S1]}
        assert result["claim_id"] == CLAIM and "A" not in json.dumps(result) and SCHEMAS.errors("judge-result", result) == []
    unresolved = expand({"verdict": "unresolved", "per_predicate": {}, "reason": "unclear"}, side_map).result
    assert unresolved["verdict"] == "unresolved" and unresolved["per_predicate"] == {}
    assert deshuffle("A", {"A": "blue", "B": "red"}) == "blue_correct" and deshuffle("both", side_map) == "partly"


def test_a_verdict_naming_a_side_without_a_resolvable_citation_is_unresolved_with_feedback() -> None:
    side_map = {"A": "red", "B": "blue"}
    nothing = expand({"verdict": "B", "per_predicate": {"affected_construct": {"verdict": "B", "cites": []}},
                      "reason": "B sounds more sure"}, side_map)
    assert nothing.result["verdict"] == "unresolved"
    assert nothing.result["per_predicate"]["affected_construct"] == {"verdict": "unresolved", "cites": []}
    assert any("no resolvable citation" in item for item in nothing.feedback)
    foreign = expand({"verdict": "A", "per_predicate": {"affected_construct": {"verdict": "A", "cites": ["Q9", "J7"]}},
                      "reason": "r"}, side_map)                 # labels this cell never received
    assert foreign.result["verdict"] == "unresolved" and len(foreign.feedback) >= 3
    partial = expand({"verdict": "A", "per_predicate": {
        "affected_construct": {"verdict": "A", "cites": ["K1"]},
        "missing_or_ineffective_guard": {"verdict": "B", "cites": ["Q9"]}}, "reason": "r"}, side_map)
    assert partial.result["verdict"] == "red_correct"           # one decided predicate still stands
    assert partial.result["per_predicate"]["missing_or_ineffective_guard"]["verdict"] == "unresolved"
    assert partial.result["citations"] == {"affected_construct": [K1]}


def test_an_answer_that_names_a_role_or_breaks_the_closed_shape_is_rejected() -> None:
    side_map = {"A": "red", "B": "blue"}
    for compact in ({"verdict": "red_team_analyst", "per_predicate": {}, "reason": "r"},
                    {"verdict": "red_correct", "per_predicate": {}, "reason": "r"},
                    {"verdict": "A", "per_predicate": {}},
                    {"verdict": "A", "per_predicate": {"made_up": {"verdict": "A", "cites": ["K1"]}}, "reason": "r"},
                    {"verdict": "A", "per_predicate": {}, "reason": "r", "state": "confirmed"}):
        expansion = expand(compact, side_map)
        assert expansion.result is None and expansion.errors, compact


# ------------------------------------------------------------------------------------------------ the review team


def judge_changes(prepared, *, model: str | None = "claude-judge-model", **changes):
    """Context overrides: the judge on its own model profile (so red and blue names can be checked) and changes."""
    settings = prepared.settings
    models, profile = dict(settings.models), "default"
    if model is not None:
        models["judge"] = replace(settings.models["default"], model=model)
        profile = "judge"
    judge = replace(settings.roles[Role.ADJUDICATION_JUDGE], model_profile=profile, **changes)
    return {"models": MappingProxyType(models), "roles": MappingProxyType({**settings.roles,
                                                                           Role.ADJUDICATION_JUDGE: judge})}


def judge_cells(result):
    return [record for record in result.cells if record.role is Role.ADJUDICATION_JUDGE]


def test_the_checked_in_configuration_enables_the_judge_for_every_affirmed_claim(prepared) -> None:
    judge = prepared.settings.judge
    assert isinstance(judge, JudgeSettings) and judge.when == "all" and judge.judges_per_claim == 1
    assert (judge.max_why_chars, judge.max_cited_rows_per_side) == (600, 12)
    assert prepared.settings.roles[Role.ADJUDICATION_JUDGE].require_distinct_from_roles == (
        Role.HYPOTHESIS_HUNTER, Role.RED_TEAM_ANALYST, Role.BLUE_TEAM_REFUTER)


def test_a_judge_runs_after_red_and_blue_with_a_stored_map_and_a_request_that_names_no_side(prepared) -> None:
    recording = Recording(prepared.infer)
    result = run_team(prepared.context(recording, **judge_changes(prepared)), prepared.work("lead", "sast_critical"),
                      launch=True)
    [record] = judge_cells(result)
    assert record.status is CellStatus.SUCCEEDED and record.persona == "generalist" and record.claim_id
    [claim] = result.claims
    expected_map = side_assignment(result.capabilities[0]["manifest_sha256"], claim.claim_id)
    assert dict(record.side_map) == expected_map
    [verdict] = result.judge_verdicts
    assert verdict.verdict is JudgeVerdictValue.RED_CORRECT and verdict.cell_id == record.cell_id
    assert verdict.judge_model_distinct is True                          # claude-judge-model differs from the others
    # The order of requests: the judge is asked after every red and blue request.
    order = [item.role for item in recording.requests]
    assert order.index("adjudication_judge") > max(i for i, role in enumerate(order) if role == "blue_team_refuter")
    # The request is the labelled package, the claim and two sides; the sides carry stances and labels.
    [request, *_] = recording.by_role("adjudication_judge")
    payload = request.task_input["input"]
    assert set(payload["sides"]) == {"A", "B"} and "cited_rows" in payload and payload["claim"]["statement"]
    affirming = [letter for letter, side in payload["sides"].items() if side["stance"] == "supports"]
    assert [expected_map[letter] for letter in affirming] == ["red"]
    # Role-blind: no role, task, persona, actor, cell or model name of red or blue, and no side-to-role map.
    markers = {"red_team_analyst", "hypothesis_hunter", "blue_team_refuter", "blue_control", "blue_reachability",
               "lead_red_stack", "lead_red_preconditions", "lead_red_failure_modes", "claude-haiku-5-5"}
    for item in result.cells:
        if item.role is not Role.ADJUDICATION_JUDGE and item.role is not Role.INDEPENDENT_VERIFIER:
            markers |= {item.cell_id, make_id("actor", 1, {"cell_id": item.cell_id})}
            markers |= {item.persona} if "_" in item.persona else set()
    for stored in recording.by_role("adjudication_judge"):
        text = json.dumps(asdict(stored), sort_keys=True, default=str)
        leaked = sorted(marker for marker in markers if marker in text)
        assert leaked == [], leaked
        assert not re.search(r"\b(?:red|blue)\b", stored.guidance_text, re.IGNORECASE)
        assert "side_map" not in text and '"role": "red"' not in text and '"role": "blue"' not in text
    assert stored.model == "claude-judge-model"
    checks = sorted(Path(prepared.fixture.run_root).rglob("judge-request-check-*.json"))
    assert checks and json.loads(checks[-1].read_text())["contains_forbidden_marker"] is False


def test_both_assignments_de_shuffle_to_the_same_red_correct_verdict_in_real_cells(prepared) -> None:
    firsts = set()
    for number, key in enumerate(("sast_critical", "sast_high", "codeql_high")):
        result = run_team(prepared.context(prepared.infer, attempt=str(number)), prepared.work("lead", key),
                          launch=True)
        for record in judge_cells(result):
            firsts.add(dict(record.side_map)["A"])
            verdict = next(item for item in result.judge_verdicts if item.cell_id == record.cell_id)
            assert verdict.verdict is JudgeVerdictValue.RED_CORRECT
    assert firsts == {"red", "blue"}                                      # both orders occurred


@pytest.mark.parametrize("mode, expected", [
    ("blue", JudgeVerdictValue.BLUE_CORRECT), ("both", JudgeVerdictValue.PARTLY),
    ("neither", JudgeVerdictValue.NEITHER), ("unresolved", JudgeVerdictValue.UNRESOLVED),
    ("uncited", JudgeVerdictValue.UNRESOLVED)])
def test_every_verdict_is_recorded_and_an_uncited_side_becomes_unresolved(prepared, mode, expected) -> None:
    infer = ScriptedInfer({"ids": prepared.fixture.ids, "judge": mode})
    # Only codeql_high has a blue side that cites anything, which siding with blue needs.
    lead = "codeql_high" if mode == "blue" else "sast_critical"
    result = run_team(prepared.context(infer, attempt=mode), prepared.work("lead", lead), launch=True)
    [verdict] = result.judge_verdicts
    assert verdict.verdict is expected
    provenance = [item for item in result.relations if item.provenance is not None]
    if mode in ("neither", "unresolved", "uncited"):
        assert provenance == []                                            # nothing decided, nothing recorded
    if mode == "blue":
        assert provenance and {item.kind.value for item in provenance} <= {"contradicts", "qualifies"}
    if mode == "both":
        assert {item.claim_id for item in provenance} <= {verdict.claim_id}
    if mode == "uncited":
        [record] = judge_cells(result)
        receipt = next(prepared.fixture.run_root.rglob(f"{record.cell_id}/attempt-*.json"))
        compact = json.loads(receipt.read_text())["compact_result"]
        assert compact["verdict"] in ("A", "B")                         # what the model wrote stays in the receipt


def test_judge_relations_carry_provenance_and_follow_the_admissibility_rules(prepared) -> None:
    result = run_team(prepared.context(prepared.infer), prepared.work("lead", "sast_critical"), launch=True)
    [record] = judge_cells(result)
    judged = [item for item in result.relations if item.producing_cell_id == record.cell_id]
    assert judged and {item.provenance for item in judged} == {"adjudication_judge"}
    for relation in judged:
        direct = relation.complete and relation.admissibility.value in ("direct", "direct_for_mapped_predicate")
        assert relation.kind.value == ("supports" if direct else "qualifies")
        assert relation.relation_id.startswith("evrel-")
    assert all(item.provenance is None for item in result.relations if item.producing_cell_id != record.cell_id)
    blue = run_team(prepared.context(ScriptedInfer({"ids": prepared.fixture.ids, "judge": "blue"}), attempt="b",
                                     **judge_changes(prepared, model="claude-judge-b")),
                    prepared.work("lead", "codeql_high"), launch=True)
    cell = judge_cells(blue)[0]
    siding = [item for item in blue.relations if item.producing_cell_id == cell.cell_id]
    assert siding and {item.kind.value for item in siding} <= {"contradicts", "qualifies"}
    assert all(item.kind.value == "qualifies" for item in siding if not item.complete
               or item.admissibility.value == "indirect")


@pytest.mark.parametrize("when, answers, judged", [
    ("disagreement", lambda task: "supports", 1),                 # invalid blue support is not agreement
    ("disagreement", lambda task: "contradicts", 1),                                         # blue opposes red
    ("disagreement", lambda task: "supports" if task == "blue_control" else "qualifies", 1), # invalid plus qualification
    ("disagreement", lambda task: "unresolved", 1),                                          # a predicate left open
    ("all", lambda task: "supports", 1)])                         # all judges even invalid blue output
def test_when_selects_judge_cells_in_a_real_team(prepared, when, answers, judged) -> None:
    class Scripted(ScriptedInfer):
        def _blue(self, payload):
            stance = answers(payload["task"])
            if stance == "unresolved":
                return self._final({"stance": stance, "why": "scripted blue answer for the selection test"})
            return self._final({"stance": stance, "predicate": "affected_construct",
                                "cites": [self.ids["unit:native-main"]], "why": "scripted blue answer"})

    result = run_team(prepared.context(Scripted({"ids": prepared.fixture.ids}), **judge_changes(
        prepared, model=None, when=when)), prepared.work("lead", "sast_critical"), launch=True)
    assert len(judge_cells(result)) == judged
    [entry] = result.judging.values()
    assert entry["selected"] is bool(judged)
    if not judged:
        assert entry["reason"] == "no_disagreement" and result.judge_verdicts == []


def test_judges_per_claim_adds_cells_with_their_own_order_and_a_disabled_judge_adds_none(prepared) -> None:
    two = run_team(prepared.context(prepared.infer, attempt="two", **judge_changes(prepared, model=None,
                                                                                     judges_per_claim=2)),
                   prepared.work("lead", "sast_critical"), launch=True)
    assert len(judge_cells(two)) == 2 and len({item.cell_id for item in judge_cells(two)}) == 2
    assert len(two.judge_verdicts) == 2
    off = run_team(prepared.context(prepared.infer, attempt="off", **judge_changes(prepared, model=None,
                                                                                     enabled=False)),
                   prepared.work("lead", "sast_critical"), launch=True)
    assert judge_cells(off) == [] and off.judge_verdicts == [] and off.judging == {}


def test_a_failed_judge_is_a_named_gap_with_one_terminal_record_and_no_verdict(prepared) -> None:
    infer = ScriptedInfer({"ids": prepared.fixture.ids, "fail_roles": ["adjudication_judge"]})
    result = run_team(prepared.context(infer, attempt="down"), prepared.work("lead", "sast_critical"), launch=True)
    [record] = judge_cells(result)
    assert record.status is CellStatus.FAILED and record.gap_ids and record.side_map is not None
    assert result.judge_verdicts == [] and not any(item.provenance for item in result.relations)
    assert any(gap.gap_class is GapClass.WORKER_GAP and gap.subject_id == record.cell_id for gap in result.gaps)
    # The claim is still reviewed, adjudicated and publishable without a verdict.
    assert len(result.claims) == 1


def test_a_reused_judge_cell_is_not_asked_again(prepared) -> None:
    first = run_team(prepared.context(prepared.infer), prepared.work("lead", "sast_critical"), launch=True)
    recording = Recording(prepared.infer)
    again = run_team(prepared.context(recording, attempt="b"), prepared.work("lead", "sast_critical"), launch=True)
    assert not recording.requests and again.judge_verdicts == first.judge_verdicts
    assert again.cells == first.cells and again.relations == first.relations


# ------------------------------------------------------------------------------------------------ ledger and R5


def run_lead(prepared, infer, name: str, **changes):
    ctx = prepared.context(infer, lane="lead", attempt=name, **changes)
    shards = prepared.tmp / name
    works = package_works(prepared.fixture.run_root, prepared.documents("lead"))
    document = run_lane(ctx, Lane.LEAD, works, other_lane_count=2, ledger_path=shards / "lead.jsonl",
                        stream="lead_review.teams", signal_dir=prepared.tmp / "lanes" / name)
    return document, shards / "lead.jsonl", works


def adjudicate_lane(prepared, document, ledger, works, name: str):
    merged = stages.merge_claims([document], [ledger], {work.package_id: work.entities for work in works}, [])
    projection = project(stages.merge_verified([ledger]).events)
    shard = prepared.tmp / name / "adjudication.jsonl"
    return stages.apply_policy(merged, projection, shard, "adjudicate.apply_policy"), projection


def test_the_ledger_records_judge_verdicts_and_relations_and_accounts_for_every_judge_cell(prepared) -> None:
    document, ledger, works = run_lead(prepared, prepared.infer, "ledger")
    events = [json.loads(line) for line in ledger.read_text().splitlines()]
    verdict_events = [event for event in events if event["kind"] == EventKind.JUDGE_VERDICT.value]
    assert len(verdict_events) == sum(1 for entry in document["judging"].values() if entry.get("selected"))
    body = verdict_events[0]["body"]["verdict"]
    assert set(body) == {"verdict_id", "claim_id", "verdict", "per_predicate", "citations", "reason", "cell_id",
                         "judge_model_distinct"} and verdict_events[0]["subject_id"] == body["verdict_id"]
    projection = project(merge_shards([ledger]).events)
    assert sum(len(items) for items in projection.judge_verdicts.values()) == len(verdict_events)
    judge_records = [item for items in projection.cells.values() for item in items
                     if item.role is Role.ADJUDICATION_JUDGE]
    assert len(judge_records) == len(verdict_events) and all(item.side_map for item in judge_records)
    relations = [item for items in projection.relations.values() for item in items if item.provenance]
    assert relations and {item.provenance for item in relations} == {"adjudication_judge"}
    expected_cells = {key: Lane(value) for key, value in document["expected_cells"].items()}
    assert {item.cell_id for item in judge_records} <= set(expected_cells)
    accounting = exact_accounting(projection, expected_cells, {key: Lane(value) for key, value in
                                                               document["packages"].items()}, incomplete_gap_ratio=0.5)
    assert {gap.reason for gap in accounting.violations} == {"claim_not_final"}
    summary = accounting.to_json()["judge_verdicts"]
    assert sum(summary["by_outcome"].values()) == len(verdict_events)
    assert summary["model_distinct"] + summary["not_model_distinct"] == len(verdict_events)
    assert all(SCHEMAS.errors("ledger-event", event) == [] for event in events)
    assert all(SCHEMAS.errors("cell-record", event["body"]["cell"]) == []
               for event in events if event["kind"] == "cell_terminal")


def test_r5_outcomes_are_unchanged_with_and_without_a_judge_for_the_same_inputs(prepared) -> None:
    results = {}
    for name, infer, changes in (
            ("off", prepared.infer, judge_changes(prepared, model=None, enabled=False)),
            ("red", prepared.infer, judge_changes(prepared, model="claude-judge-red")),
            ("blue", ScriptedInfer({"ids": prepared.fixture.ids, "judge": "blue"}),
             judge_changes(prepared, model="claude-judge-blue")),
            ("neither", ScriptedInfer({"ids": prepared.fixture.ids, "judge": "neither"}),
             judge_changes(prepared, model="claude-judge-neither"))):
        document, ledger, works = run_lead(prepared, infer, name, **changes)
        adjudications, projection = adjudicate_lane(prepared, document, ledger, works, name)
        results[name] = (adjudications["adjudications"], adjudications["states"], projection)
    baseline = results["off"]
    assert baseline[1] and any(state in baseline[1] for state in ("confirmed", "supported", "contradicted"))
    def outcome(records):
        # A failed cell is run again in a later attempt of the same run and so names a new terminal gap id; that
        # is unrelated to the judge, so the gap ids (and the adjudication id that covers them) are left out.
        return [{key: value for key, value in record.items() if key not in ("adjudication_id", "gap_ids")}
                for record in records]

    for name in ("red", "blue", "neither"):
        assert outcome(results[name][0]) == outcome(baseline[0]), name   # every state, row, predicate and counted id
        assert results[name][1] == baseline[1], name
    assert not results["off"][2].judge_verdicts and results["blue"][2].judge_verdicts
    # Counted relations never include a judge's, even when the judge sided with blue on direct rows.
    counted = {rid for record in results["blue"][0] for rid in record["counted_relation_ids"]}
    judge_ids = {item.relation_id for items in results["blue"][2].relations.values() for item in items
                 if item.provenance}
    assert judge_ids and not counted & judge_ids


# ------------------------------------------------------------------------------------------------ findings and PoC


def finding(claim: str, *, state="confirmed", verdict="red_correct", rating="high", number="1") -> dict:
    return {"claim_id": claim, "state": state, "judge_verdict": verdict, "technical_severity": rating,
            "finding_package_id": "finding-" + number * 64, "sha256": number * 64,
            "direct_evidence": ["evrel-" + number * 64]}


BRIEF = {"entry": [ref("entry_point", "a")], "path": [ref("call_site", "b")], "trigger": [],
         "input_format": "x", "preconditions": [], "expected_observation": "y", "unknowns": []}


def briefs(claim: str, poc_basis: dict | None = None, cell: str = "cell-" + "1" * 64) -> list[dict]:
    return [{"claim_id": claim, "package_id": "pkg", "lane": "lead", "cell_id": cell, "poc_basis": poc_basis or BRIEF}]


def test_poc_candidates_need_all_four_conditions() -> None:
    settings = PocCandidateSettings()
    claim = "claim-" + "1" * 64
    [entry] = stages.poc_candidates([finding(claim)], briefs(claim), settings)
    assert entry == {"claim_id": claim, "package_id": "pkg", "state": "confirmed", "judge_verdict": "red_correct",
                     "poc_basis": {"sha256": sha256_hex(BRIEF), "brief": BRIEF},
                     "finding_package": {"finding_package_id": "finding-" + "1" * 64, "sha256": "1" * 64},
                     "evidence_refs": ["evrel-" + "1" * 64]}
    assert stages.poc_candidates([finding(claim, state="supported")], briefs(claim), settings)       # 1: supported counts
    assert stages.poc_candidates([finding(claim, verdict="blue_correct")], briefs(claim), settings) == []   # 2
    assert stages.poc_candidates([finding(claim, verdict=None)], briefs(claim), settings) == []
    assert stages.poc_candidates([finding(claim)], [], settings) == []                              # 3: no poc_basis
    assert stages.poc_candidates([finding(claim)], briefs(claim, {**BRIEF, "entry": []}), settings) == []
    assert stages.poc_candidates([finding(claim)], briefs(claim, {**BRIEF, "path": []}), settings) == []
    assert stages.poc_candidates([finding(claim, rating="low")], briefs(claim), settings) == []      # 4: policy
    assert stages.poc_candidates([finding(claim, rating=None)], briefs(claim), settings) == []


def test_partly_and_the_policy_ratings_are_configurable() -> None:
    claim = "claim-" + "1" * 64
    partly = finding(claim, verdict="partly")
    assert stages.poc_candidates([partly], briefs(claim), PocCandidateSettings()) == []
    assert stages.poc_candidates([partly], briefs(claim), PocCandidateSettings(accept_partly=True))
    low = finding(claim, rating="low")
    assert stages.poc_candidates([low], briefs(claim), PocCandidateSettings(risk_ratings=("low", "high")))
    assert stages.poc_candidates([finding(claim, rating="critical")], briefs(claim),
                                 PocCandidateSettings(risk_ratings=("low",))) == []


def test_poc_candidates_are_deterministic_and_pick_the_first_resolved_brief() -> None:
    first, second = "claim-" + "1" * 64, "claim-" + "2" * 64
    unresolved = {**BRIEF, "entry": []}
    found = stages.poc_candidates(
        [finding(second, number="2"), finding(first)],
        briefs(second, cell="cell-" + "9" * 64) + briefs(first, unresolved, "cell-" + "0" * 64)
        + briefs(first, BRIEF, "cell-" + "5" * 64), PocCandidateSettings())
    assert [item["claim_id"] for item in found] == [first, second]
    assert found[0]["poc_basis"]["brief"] == BRIEF


def test_a_finding_package_carries_the_judge_verdict_beside_its_state() -> None:
    def verdict(number: str, value: JudgeVerdictValue) -> JudgeVerdict:
        return JudgeVerdict("judge-" + number * 64, "claim-" + "1" * 64, value, (), "because", "cell-" + number * 64,
                            number == "1")

    assert stages.finding_judge([]) is None
    one = stages.finding_judge([verdict("1", JudgeVerdictValue.RED_CORRECT)])
    assert one["verdict"] == "red_correct" and one["disagrees_with_state"] is False
    blue = stages.finding_judge([verdict("1", JudgeVerdictValue.BLUE_CORRECT)])
    assert blue["verdict"] == "blue_correct" and blue["disagrees_with_state"] is True      # never hidden
    split = stages.finding_judge([verdict("1", JudgeVerdictValue.RED_CORRECT), verdict("2", JudgeVerdictValue.NEITHER)])
    assert split["verdict"] == "unresolved" and len(split["judges"]) == 2
    schema = json.loads((ROOT / "docs/schemas/inference-security-review/common.schema.json").read_text())
    assert "finding_judge_verdict" in schema["$defs"]
