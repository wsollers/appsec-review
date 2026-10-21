"""R3 ``evidence-admissibility/3``: a dominating guard or range contradicts ``missing_or_ineffective_guard`` only
when the exported facts show it bounds the destination (``graph.bounds``), and only for blue, verifier or judge.

Includes the regression for the cpp-multivuln ``src/packet.cpp`` overflow (``char name[16]``), built from the
live-verified guard rows of lines 8 and 13.
"""
from __future__ import annotations

from typing import Any

import pytest

from appsec_review.graph.contract import Family
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.evidence import GUARD_CONTRADICTION_ROLES, resolve_relation, satisfies
from appsec_review.review.ledger import relation_from_json, relation_json
from appsec_review.review.models import EvidenceRelation, Gap, Predicate, RelationKind
from tests.review.test_graph_admissibility import (
    CELL, CLAIM, RECEIPT, RUN_ID, accepted_graph_run, graph_entity,
)

GUARD = Predicate.MISSING_OR_INEFFECTIVE_GUARD


def operand(role: str, kind: str, value: Any = None, text: str | None = None) -> dict[str, Any]:
    return {"role": role, "kind": kind, "value": value, "text": text, "location": None}


def guard_result(sink: str, operator: str, lhs: dict, rhs: dict, *, polarity: str = "false_branch",
                 constrains: Any = True, capacity: int | None = 16, state: str = "dominating") -> dict[str, Any]:
    return {"sink": {"sink_site": sink, "sink_class": "memory_write"}, "guard_state": state, "polarity": polarity,
            "condition": None, "constrains_sink_operand": constrains,
            "comparison": {"operator": operator, "bound_display": "x", "operands": [lhs, rhs]},
            "destination": {"object_bytes": capacity}}


def range_result(sink: str, upper: Any, *, bits: int = 16) -> dict[str, Any]:
    return {"sink": {"sink_site": sink, "sink_class": "memory_write"}, "operand_index": 2,
            "applicability": "integral", "type": {"display": f"uint{bits}_t", "signed": False, "bits": bits},
            "interval": {"lower": 0, "upper": upper}, "conversions": [], "sign_change": False}


def extras(ids, add, condition, sink_span, call) -> None:
    sink = ids["sink"]
    n, size = operand("lhs", "variable", None, "n"), operand("lhs", "variable", None, "size")
    sixteen, sixty_four = operand("rhs", "constant", 16, "16"), operand("rhs", "constant", 64, "64")
    sizeof16 = operand("rhs", "sizeof", 16, "sizeof(out.name)")
    guards = {
        "g_gt16": guard_result(sink, ">", n, sixteen),                                  # if (n > 16) return;
        "g_gt64": guard_result(sink, ">", n, sixty_four),                               # if (n > 64) return;
        "g_ge_sizeof": guard_result(sink, ">=", n, sizeof16),                           # if (n >= sizeof) return;
        "g_eq16": guard_result(sink, "==", n, sixteen, polarity="true_branch"),
        "g_16_lt_n": guard_result(sink, "<", operand("lhs", "constant", 16, "16"), operand("rhs", "variable", None, "n")),
        # packet.cpp line 13: if (size < 4u + out.length) return -1;  (live-verified row)
        "g_packet13": guard_result(sink, "<", size, operand("rhs", "other", None, "4u + out.length"),
                                   constrains="unknown"),
        # packet.cpp line 8: if (size < 4) return -1;  (live-verified row)
        "g_packet8": guard_result(sink, "<", size, operand("rhs", "constant", 4, "4"), constrains=False),
        "g_unknown_capacity": guard_result(sink, ">", n, sixteen, capacity=None),
        "g_non_dominating": guard_result(sink, ">", n, sixteen, state="non_dominating"),
    }
    for index, (key, result) in enumerate(guards.items()):
        add(key, graph_entity(Family.GUARD_FACT, {
            "sink_identity": sink, "condition_path": "src/copy.c",
            "condition_start_byte": condition.start_byte + index + 1, "condition_end_byte": condition.end_byte}, result,
            condition))
    add("r_16", graph_entity(Family.RANGE_FACT, {"sink_identity": sink, "operand_index": 3},
                             range_result(sink, 16, bits=8), sink_span))
    add("r_u16", graph_entity(Family.RANGE_FACT, {"sink_identity": sink, "operand_index": 4},
                              range_result(sink, 65535), sink_span))
    add("r_unknown", graph_entity(Family.RANGE_FACT, {"sink_identity": sink, "operand_index": 5},
                                  range_result(sink, "unknown"), sink_span))
    # A second sink whose guards record no destination size: its range has no capacity to be compared with.
    other = graph_entity(Family.SINK_SITE, {"path": "src/copy.c", "start_byte": call.start_byte + 1,
                                            "end_byte": call.end_byte, "sink_class": "memory_write",
                                            "argument_index": 1},
                         {"sink_class": "memory_write", "cwe_family": "CWE-787", "argument_index": 1}, call)
    add("sink2", other)
    add("g_sink2", graph_entity(Family.GUARD_FACT, {
        "sink_identity": ids["sink2"], "condition_path": "src/copy.c", "condition_start_byte": condition.start_byte,
        "condition_end_byte": condition.end_byte}, guard_result(ids["sink2"], ">", n, sixteen, capacity=None),
        condition))
    add("r_sink2", graph_entity(Family.RANGE_FACT, {"sink_identity": ids["sink2"], "operand_index": 2},
                                range_result(ids["sink2"], 8, bits=8), sink_span))


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    runs, ids = accepted_graph_run(tmp_path_factory.mktemp("guard-bounds"), extras)
    return RetrievalCore(runs, RUN_ID), ids


def cite(core, entity_id, *, kind=RelationKind.CONTRADICTS, role="blue_team_refuter") -> EvidenceRelation:
    found = resolve_relation(core, claim_id=CLAIM, predicate=GUARD, kind=kind, entity_id=entity_id,
                             producing_cell_id=CELL, retrieval_receipt_sha256=RECEIPT, role=role)
    assert isinstance(found, EvidenceRelation), found if isinstance(found, Gap) else None
    return found


PROVEN = ["g_gt16", "g_ge_sizeof", "g_eq16", "g_16_lt_n", "r_16"]
NOT_PROVEN = ["g_gt64", "g_packet13", "g_packet8", "g_unknown_capacity", "g_non_dominating", "r_u16", "r_unknown",
              "r_sink2"]


@pytest.mark.parametrize("key", PROVEN)
@pytest.mark.parametrize("role", sorted(GUARD_CONTRADICTION_ROLES))
def test_a_fact_shown_to_bound_the_destination_contradicts_for_blue_verifier_and_judge(run, key, role) -> None:
    core, ids = run
    relation = cite(core, ids[key], role=role)
    assert relation.kind is RelationKind.CONTRADICTS and relation.reason is None and satisfies(relation)


@pytest.mark.parametrize("key", PROVEN)
@pytest.mark.parametrize("role", ["red_team_analyst", "hypothesis_hunter", "independent_scorer", None])
def test_other_roles_never_contradict_even_a_bounding_fact(run, key, role) -> None:
    core, ids = run
    relation = cite(core, ids[key], role=role)
    assert relation.kind is RelationKind.QUALIFIES and relation.reason.startswith("contradiction_role_not_permitted")
    assert relation.admissibility.value == "direct_for_mapped_predicate"


@pytest.mark.parametrize("key", NOT_PROVEN)
@pytest.mark.parametrize("role", sorted(GUARD_CONTRADICTION_ROLES))
def test_a_fact_not_shown_to_bound_the_destination_only_qualifies(run, key, role) -> None:
    core, ids = run
    relation = cite(core, ids[key], role=role)
    assert relation.kind is RelationKind.QUALIFIES
    assert relation.reason.startswith("guard_not_shown_to_bound_destination:") and len(relation.reason) <= 200


@pytest.mark.parametrize("key", PROVEN + NOT_PROVEN)
@pytest.mark.parametrize("kind", [RelationKind.SUPPORTS, RelationKind.QUALIFIES])
def test_supports_and_qualifies_are_recorded_as_cited(run, key, kind) -> None:
    core, ids = run
    relation = cite(core, ids[key], kind=kind)
    assert relation.kind is kind and relation.reason is None


def test_the_reason_changes_the_relation_identity_and_survives_the_ledger_round_trip(run) -> None:
    core, ids = run
    qualified = cite(core, ids["g_packet13"])
    again = cite(core, ids["g_packet13"])
    assert qualified.relation_id == again.relation_id
    assert cite(core, ids["g_packet13"], kind=RelationKind.QUALIFIES).relation_id != qualified.relation_id
    restored = relation_from_json(relation_json(qualified))
    assert restored == qualified and restored.reason == qualified.reason


def test_the_range_destination_comes_from_the_guard_facts_of_the_same_sink(run) -> None:
    core, ids = run
    assert cite(core, ids["r_16"]).kind is RelationKind.CONTRADICTS
    sink2 = cite(core, ids["r_sink2"])                       # upper bound 8, but its sink records no object size
    assert sink2.kind is RelationKind.QUALIFIES and "destination object size is unknown" in sink2.reason


def test_packet_cpp_overflow_is_not_refuted_by_its_size_guards(run) -> None:
    """cpp-multivuln src/packet.cpp:16, ``memcpy(out.name, data + 4, out.length)`` into ``char name[16]``.

    Line 13 ``if (size < 4u + out.length) return -1;`` compares the input size with the length field: the sink
    operand is not identified (``unknown``), the other operand is not a constant, and the 16-byte capacity is never
    the bound. Line 8 ``if (size < 4) return -1;`` does not involve the sink operand. Blue citing either as a
    contradiction gets a qualification, so ``missing_or_ineffective_guard`` is not refuted.
    """
    core, ids = run
    for key in ("g_packet13", "g_packet8"):
        for role in sorted(GUARD_CONTRADICTION_ROLES):
            relation = cite(core, ids[key], role=role)
            assert relation.kind is RelationKind.QUALIFIES, (key, role)
            assert relation.reason.startswith("guard_not_shown_to_bound_destination:")
    assert "constrains_sink_operand" in cite(core, ids["g_packet13"]).reason
    # The same facts remain citable as support that the guard is ineffective.
    assert cite(core, ids["g_packet13"], kind=RelationKind.SUPPORTS).kind is RelationKind.SUPPORTS
    # And a guard that does bound the 16-byte destination does refute.
    assert cite(core, ids["g_gt16"]).kind is RelationKind.CONTRADICTS
