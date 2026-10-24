from __future__ import annotations

import json
from pathlib import Path
import random

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.ledger import (
    EventKind, EvidenceRequestOutcome, LEGAL_TRANSITIONS, LedgerWriter, check_transition, merge_shards, project,
    verify_chain,
)
from appsec_review.review.models import (
    Admissibility, CellRecord, CellStatus, Claim, ClaimState, EvidenceRelation, Gap, GapClass, IntegrityError,
    Lane, Predicate, RelationKind, Role,
)

S = ClaimState


def entity(name: str) -> str:
    return f"asr:source_span:{sha256_hex(name)}"


def claim(name: str, lane: Lane = Lane.LEAD, package: str = "package-a", cells: tuple[str, ...] = ()) -> Claim:
    entities = (entity(name),)
    return Claim(make_id("claim", 1, {"entities": entities, "cwe": "CWE-120"}), lane, package, entities, "CWE-120",
                 "memory_corruption", ("attacker_controls_request_field",), f"statement {name}",
                 origin_cell_ids=cells)


def cell(name: str, lane: Lane = Lane.LEAD, status: CellStatus = CellStatus.SUCCEEDED, package: str = "package-a",
         claim_id: str | None = None) -> CellRecord:
    gaps = () if status is CellStatus.SUCCEEDED else (gap(f"cell-{name}").gap_id,)
    return CellRecord(cell_id(name), lane, package, Role.BLUE_TEAM_REFUTER, "memory_safety_native",
                      "cpp_rpc_service", "blue_control", claim_id, status,
                      0 if status is CellStatus.NOT_LAUNCHED else 1, gaps, sha256_hex(name))


def cell_id(name: str) -> str:
    return make_id("cell", 1, {"name": name})


def gap(subject: str, gap_class: GapClass = GapClass.WORKER_GAP) -> Gap:
    return Gap(make_id("gap", 1, {"gap_class": gap_class.value, "subject_id": subject, "predicate": None,
                                  "round": 0}), gap_class, subject, "bounded reason")


def relation(target: Claim, name: str, kind: RelationKind = RelationKind.SUPPORTS) -> EvidenceRelation:
    return EvidenceRelation(make_id("evidence_relation", 1, {"claim": target.claim_id, "name": name}),
                            target.claim_id, Predicate.AFFECTED_CONSTRUCT, kind, entity(name), "source_span",
                            Admissibility.DIRECT, "shard-1", sha256_hex(name), "src/a.c:10-12", True,
                            cell_id(name), sha256_hex(f"receipt {name}"))


def request_id(name: str) -> str:
    return make_id("evidence_request", 1, {"name": name})


def write_sample(root: Path) -> tuple[list[Path], dict[str, Claim]]:
    """Two lane units and one adjudication unit; returns shard paths and the claims."""
    a, b, c = claim("a"), claim("b", Lane.HUNT, "package-h"), claim("c")
    lead = LedgerWriter(root / "lead.jsonl", "lead_review.teams")
    lead.propose_claim(a)
    lead.propose_claim(c)
    lead.add_relation(relation(a, "r1"))
    lead.add_relation(relation(c, "r2", RelationKind.CONTRADICTS))
    lead.open_request(request_id("q1"), a.claim_id, Predicate.SECURITY_IMPACT, "source_span")
    lead.cell_terminal(cell("lead-1", claim_id=a.claim_id))
    lead.cell_terminal(cell("lead-2", status=CellStatus.FAILED))
    lead.record_gap(gap(cell_id("lead-2")))
    hunt = LedgerWriter(root / "hunt.jsonl", "hunt_review.teams")
    hunt.propose_claim(b)
    hunt.cell_terminal(cell("hunt-1", Lane.HUNT, package="package-h"))
    adjudicate = LedgerWriter(root / "adjudicate.jsonl", "adjudicate.apply_policy")
    adjudicate.transition(a.claim_id, S.PROPOSED, S.SUPPORTED, reason="r5 rule 6")
    adjudicate.transition(a.claim_id, S.SUPPORTED, S.CONFIRMED, reason="r5 rule 5")
    adjudicate.transition(c.claim_id, S.PROPOSED, S.CONTRADICTED, reason="r5 rule 4")
    adjudicate.mark_duplicate(b.claim_id, a.claim_id, reason="equal identity")
    adjudicate.close_request(request_id("q1"), a.claim_id, EvidenceRequestOutcome.SATISFIED, reason="resolved")
    for writer in (lead, hunt, adjudicate):
        writer.seal()
    return [lead.path, hunt.path, adjudicate.path], {"a": a, "b": b, "c": c}


def test_writer_seals_verifiable_chain(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    events = verify_chain(paths[0])
    assert [event["sequence"] for event in events] == list(range(len(events)))
    assert events[0]["prev_event_sha256"] is None
    assert all(event["event_id"].startswith("event-") for event in events)
    assert verify_chain(paths[0], expected_head=sha256_hex(events[-1])) == events


def test_request_question_and_specialist_survive_ledger_projection(tmp_path: Path) -> None:
    target = claim("request")
    writer = LedgerWriter(tmp_path / "requests.jsonl", "review")
    writer.propose_claim(target)
    writer.open_request(request_id("details"), target.claim_id, Predicate.CONFIGURATION_ENABLES,
                        "configuration", anchors=target.affected_entities, question="Which overlay is deployed?",
                        specialist="cloud_container_deployment")
    writer.seal()
    view = project(verify_chain(writer.path))
    request = view.evidence_requests[request_id("details")]
    assert request.anchors == target.affected_entities
    assert request.question == "Which overlay is deployed?"
    assert request.specialist == "cloud_container_deployment"
    assert view.to_json()["evidence_requests"][0]["question"] == request.question


def test_request_identity_cannot_be_reused_for_a_different_question(tmp_path: Path) -> None:
    target = claim("request")
    writer = LedgerWriter(tmp_path / "requests.jsonl", "review")
    writer.propose_claim(target)
    for question in ("Which overlay is deployed?", "Who owns this record?"):
        writer.open_request(request_id("collision"), target.claim_id, Predicate.CONFIGURATION_ENABLES,
                            "configuration", question=question)
    writer.seal()
    with pytest.raises(IntegrityError, match="question or scope"):
        project(verify_chain(writer.path))


def test_seal_is_immutable(tmp_path: Path) -> None:
    writer = LedgerWriter(tmp_path / "s.jsonl", "unit")
    writer.propose_claim(claim("a"))
    writer.seal()
    with pytest.raises(IntegrityError):
        writer.propose_claim(claim("b"))
    other = LedgerWriter(tmp_path / "s.jsonl", "unit")
    other.propose_claim(claim("b"))
    with pytest.raises(IntegrityError):
        other.seal()
    same = LedgerWriter(tmp_path / "s.jsonl", "unit")
    same.propose_claim(claim("a"))
    assert same.seal().event_count == 1


def test_edit_byte_is_detected(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    raw = paths[0].read_bytes()
    index = raw.index(b"statement a")
    paths[0].write_bytes(raw[:index] + b"S" + raw[index + 1:])
    with pytest.raises(IntegrityError):
        verify_chain(paths[0])


def test_reencoded_line_is_detected(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    lines = paths[0].read_bytes().splitlines(keepends=True)
    lines[1] = (json.dumps(json.loads(lines[1]), indent=1).replace("\n", "") + "\n").encode()
    paths[0].write_bytes(b"".join(lines))
    with pytest.raises(IntegrityError):
        verify_chain(paths[0])


@pytest.mark.parametrize("mutation", ["drop_middle", "drop_first", "reorder", "duplicate"])
def test_structural_tamper_is_detected(tmp_path: Path, mutation: str) -> None:
    paths, _ = write_sample(tmp_path)
    lines = paths[0].read_bytes().splitlines(keepends=True)
    if mutation == "drop_middle":
        del lines[2]
    elif mutation == "drop_first":
        del lines[0]
    elif mutation == "reorder":
        lines[1], lines[2] = lines[2], lines[1]
    else:
        lines.insert(2, lines[1])
    paths[0].write_bytes(b"".join(lines))
    with pytest.raises(IntegrityError):
        verify_chain(paths[0])
    with pytest.raises(IntegrityError):
        merge_shards(paths)


def test_dropped_tail_is_detected_against_expected_head(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    head = sha256_hex(verify_chain(paths[0])[-1])
    lines = paths[0].read_bytes().splitlines(keepends=True)
    paths[0].write_bytes(b"".join(lines[:-1]))
    verify_chain(paths[0])
    with pytest.raises(IntegrityError):
        verify_chain(paths[0], expected_head=head)


def test_forged_identity_with_consistent_chain_is_detected(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    event = json.loads(paths[1].read_bytes().splitlines()[0])
    event["body"]["claim"]["statement"] = "forged"
    from appsec_review.storage.atomic import canonical_json
    paths[1].write_bytes(canonical_json(event))
    with pytest.raises(IntegrityError):
        verify_chain(paths[1])


def test_stream_in_two_shards_is_rejected(tmp_path: Path) -> None:
    first = LedgerWriter(tmp_path / "1.jsonl", "unit")
    first.propose_claim(claim("a"))
    second = LedgerWriter(tmp_path / "2.jsonl", "unit")
    second.propose_claim(claim("b"))
    with pytest.raises(IntegrityError):
        merge_shards([first.seal() and first.path, second.seal() and second.path])


def test_merge_order_and_projection(tmp_path: Path) -> None:
    paths, claims = write_sample(tmp_path)
    merged = merge_shards(paths)
    assert merged.head == merge_shards(list(reversed(paths))).head
    assert merged.events[0]["kind"] == "gap_recorded"  # events without a claim sort first
    projection = project(merged.events)
    assert projection.head == merged.head
    assert projection == project(reversed(merged.events))
    a, b, c = (claims[name].claim_id for name in "abc")
    assert projection.claims[a].claim.state is S.CONFIRMED
    assert [(change.from_state, change.to_state) for change in projection.claims[a].history] == [
        (S.PROPOSED, S.SUPPORTED), (S.SUPPORTED, S.CONFIRMED)]
    assert projection.claims[b].claim.state is S.DUPLICATE and projection.claims[b].claim.duplicate_of == a
    assert projection.claims[c].claim.state is S.CONTRADICTED
    assert [item.kind for item in projection.relations[c]] == [RelationKind.CONTRADICTS]
    assert projection.evidence_requests[request_id("q1")].outcomes == (EvidenceRequestOutcome.SATISFIED,)
    assert len(projection.cells) == 3 and len(projection.gaps) == 1
    assert projection.sha256() == project(merged.events).sha256()


def test_same_claim_from_two_packages_merges_origins(tmp_path: Path) -> None:
    lead = LedgerWriter(tmp_path / "l.jsonl", "lead")
    lead.propose_claim(claim("a", cells=(cell_id("x"),)))
    hunt = LedgerWriter(tmp_path / "h.jsonl", "hunt")
    hunt.propose_claim(claim("a", Lane.HUNT, "package-h", cells=(cell_id("y"),)))
    lead.seal(), hunt.seal()
    view = project(merge_shards([hunt.path, lead.path]).events).claims[claim("a").claim_id]
    assert view.claim.lane is Lane.LEAD and view.claim.package_id == "package-a"
    assert view.claim.origin_cell_ids == tuple(sorted((cell_id("x"), cell_id("y"))))
    assert len(view.proposal_sha256s) == 2


def test_identity_collision_is_integrity_error(tmp_path: Path) -> None:
    writer = LedgerWriter(tmp_path / "l.jsonl", "lead")
    original = claim("a")
    writer.propose_claim(original)
    writer.propose_claim(Claim(original.claim_id, Lane.LEAD, "package-a", original.affected_entities, "CWE-787",
                               original.security_predicate, original.preconditions, "other"))
    with pytest.raises(IntegrityError):
        project(writer.events)


def test_legal_transitions_match_lifecycle_diagram() -> None:
    edges = {(source, target) for source, targets in LEGAL_TRANSITIONS.items() for target in targets}
    assert edges == {
        (S.PROPOSED, S.DUPLICATE), (S.PROPOSED, S.OUT_OF_SCOPE), (S.PROPOSED, S.COVERAGE_GAP),
        (S.PROPOSED, S.CONTRADICTED), (S.PROPOSED, S.INSUFFICIENT_EVIDENCE), (S.PROPOSED, S.SUPPORTED),
        (S.SUPPORTED, S.CONFIRMED), (S.SUPPORTED, S.CONTRADICTED), (S.SUPPORTED, S.NOT_REACHABLE),
        (S.SUPPORTED, S.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION), (S.SUPPORTED, S.INSUFFICIENT_EVIDENCE),
        (S.CONFIRMED, S.SUPPORTED), (S.CONFIRMED, S.CONTRADICTED), (S.CONFIRMED, S.NOT_REACHABLE),
        (S.CONFIRMED, S.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION)}


@pytest.mark.parametrize("source,target", [
    (S.PROPOSED, S.CONFIRMED), (S.CONTRADICTED, S.SUPPORTED), (S.INSUFFICIENT_EVIDENCE, S.CONFIRMED),
    (S.PROPOSED, S.NOT_REACHABLE), (S.DUPLICATE, S.SUPPORTED), (S.CONFIRMED, S.PROPOSED)])
def test_illegal_transition_is_rejected(tmp_path: Path, source: ClaimState, target: ClaimState) -> None:
    with pytest.raises(IntegrityError):
        check_transition(source, target)
    writer = LedgerWriter(tmp_path / "w.jsonl", "unit")
    with pytest.raises(IntegrityError):
        writer.transition(claim("a").claim_id, source, target, reason="x")


def _forged_transition(tmp_path: Path, steps: list[tuple[ClaimState, ClaimState]]) -> list[dict]:
    """Bypass the writer's guard by appending raw events, as a tampering producer would."""
    writer = LedgerWriter(tmp_path / "w.jsonl", "unit")
    target = claim("a")
    writer.propose_claim(target)
    for source, to_state in steps:
        writer.append(EventKind.STATE_TRANSITION, target.claim_id, {
            "from_state": source.value, "to_state": to_state.value, "reason": "x", "round": 0,
            "adjudication_id": None})
    return list(writer.events)


@pytest.mark.parametrize("steps", [
    [(S.PROPOSED, S.CONFIRMED)],
    [(S.SUPPORTED, S.CONFIRMED)],
    [(S.PROPOSED, S.SUPPORTED), (S.PROPOSED, S.CONTRADICTED)],
    [(S.PROPOSED, S.CONTRADICTED), (S.CONTRADICTED, S.SUPPORTED)],
    [(S.PROPOSED, S.DUPLICATE)],
])
def test_projection_rejects_illegal_history(tmp_path: Path, steps: list[tuple[ClaimState, ClaimState]]) -> None:
    with pytest.raises(IntegrityError):
        project(_forged_transition(tmp_path, steps))


def test_projection_rejects_dangling_records(tmp_path: Path) -> None:
    writer = LedgerWriter(tmp_path / "w.jsonl", "unit")
    writer.transition(claim("a").claim_id, S.PROPOSED, S.SUPPORTED, reason="x")
    with pytest.raises(IntegrityError):
        project(writer.events)
    writer = LedgerWriter(tmp_path / "v.jsonl", "unit")
    writer.add_relation(relation(claim("a"), "r"))
    with pytest.raises(IntegrityError):
        project(writer.events)


def test_duplicate_cannot_transition_further(tmp_path: Path) -> None:
    writer = LedgerWriter(tmp_path / "w.jsonl", "unit")
    a, b = claim("a"), claim("b")
    writer.propose_claim(a)
    writer.propose_claim(b)
    writer.mark_duplicate(b.claim_id, a.claim_id, reason="same")
    writer.append(EventKind.STATE_TRANSITION, b.claim_id, {
        "from_state": "duplicate", "to_state": "supported", "reason": "x", "round": 0, "adjudication_id": None})
    with pytest.raises(IntegrityError):
        project(writer.events)


def test_round_orders_transitions(tmp_path: Path) -> None:
    writer = LedgerWriter(tmp_path / "w.jsonl", "unit")
    a = claim("a")
    writer.propose_claim(a)
    writer.transition(a.claim_id, S.CONFIRMED, S.SUPPORTED, reason="invalidated", round=1)
    writer.transition(a.claim_id, S.SUPPORTED, S.CONFIRMED, reason="r5", round=0)
    writer.transition(a.claim_id, S.PROPOSED, S.SUPPORTED, reason="r5", round=0)
    view = project(writer.events).claims[a.claim_id]
    assert view.claim.state is S.SUPPORTED
    assert [change.round for change in view.history] == [0, 0, 1]


# Property: shard enumeration order and the order in which units append independent events never
# change the merged head or the projection.

_NAMES = [f"c{index}" for index in range(6)]
_FINALS = [S.CONTRADICTED, S.INSUFFICIENT_EVIDENCE, S.OUT_OF_SCOPE, None]


@st.composite
def ledgers(draw):
    names = draw(st.lists(st.sampled_from(_NAMES), min_size=1, max_size=6, unique=True))
    plan = []
    for name in names:
        target = claim(name, draw(st.sampled_from(list(Lane))))
        unit = draw(st.integers(0, 2))
        items = [(unit, "propose", target), (unit, "relation", relation(target, f"{name}-r")),
                 (unit, "cell", cell(f"{name}-cell", target.lane, claim_id=target.claim_id))]
        final = draw(st.sampled_from(_FINALS + ["confirm"]))
        adjudicator = 3
        if final == "confirm":
            items += [(adjudicator, "transition", (target.claim_id, S.PROPOSED, S.SUPPORTED)),
                      (adjudicator, "transition", (target.claim_id, S.SUPPORTED, S.CONFIRMED))]
        elif final is not None:
            items.append((adjudicator, "transition", (target.claim_id, S.PROPOSED, final)))
        plan += items
    return plan, draw(st.randoms(use_true_random=False))


def _write(root: Path, plan, rng: random.Random, shuffle: bool) -> list[Path]:
    units: dict[int, list] = {}
    for unit, action, value in plan:
        units.setdefault(unit, []).append((action, value))
    paths = []
    for unit, items in sorted(units.items()):
        items = list(items)
        if shuffle:
            rng.shuffle(items)
        writer = LedgerWriter(root / f"unit-{unit}.jsonl", f"unit-{unit}")
        for action, value in items:
            if action == "propose":
                writer.propose_claim(value)
            elif action == "relation":
                writer.add_relation(value)
            elif action == "cell":
                writer.cell_terminal(value)
            else:
                writer.transition(*value, reason="policy")
        writer.seal()
        paths.append(writer.path)
    if shuffle:
        rng.shuffle(paths)
    return paths


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(ledgers())
def test_merge_is_order_independent(tmp_path_factory, data) -> None:
    plan, rng = data
    baseline_root, shuffled_root = tmp_path_factory.mktemp("base"), tmp_path_factory.mktemp("shuffled")
    baseline = merge_shards(_write(baseline_root, plan, rng, shuffle=False))
    shuffled = merge_shards(_write(shuffled_root, plan, rng, shuffle=True))
    assert baseline.head == shuffled.head
    first, second = project(baseline.events), project(shuffled.events)
    assert first.to_json() == second.to_json()
    proposed = {value.claim_id for _, action, value in plan if action == "propose"}
    assert set(first.claims) == proposed
