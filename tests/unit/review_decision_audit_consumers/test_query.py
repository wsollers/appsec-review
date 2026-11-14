from __future__ import annotations

import base64
from dataclasses import replace

import pytest

from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.query import Query, Template, execute
from appsec_review.review.models import Predicate, Role
from appsec_review.storage import canonical_json

from .helpers import Fixture, continued_verifier, link


@pytest.mark.parametrize("query,expected", [
    (Query(Template.LEAD_TRACE, lead_id="lead-1"), 1),
    (Query(Template.LEAD_TRACE, lead_id="foreign"), 0),
    (Query(Template.CLAIM_BASIS, claim_id="claim-1"), 1),
    (Query(Template.CLAIM_BASIS, claim_id="foreign"), 0),
    (Query(Template.VERIFICATION_COVERAGE), 1),
    (Query(Template.VERIFICATION_COVERAGE, claim_id="claim-1", predicate=Predicate.AFFECTED_CONSTRUCT), 1),
    (Query(Template.VERIFICATION_COVERAGE, predicate=Predicate.ATTACKER_INPUT_CONTROL), 0),
    (Query(Template.POPULATION), 3),
    (Query(Template.POPULATION, stage=c.Stage.ADMISSION), 1),
    (Query(Template.POPULATION, stage=c.Stage.PUBLICATION), 0),
    (Query(Template.POPULATION, role=Role.ADJUDICATION_JUDGE), 0),
    (Query(Template.POPULATION, role=Role.INDEPENDENT_VERIFIER), 1),
    (Query(Template.POPULATION, role=Role.HYPOTHESIS_HUNTER), 0),
], ids=["lead", "unknown-lead", "basis", "unknown-claim", "verifiers", "predicate", "uncovered-predicate",
        "population", "stage", "unknown-stage", "judge", "verifier-role", "hunter"])
def test_closed_templates_apply_exact_filters(tmp_path, query, expected):
    audit = Fixture(tmp_path).load()
    result = execute(audit, query)
    assert result["total"] == result["returned"] == expected
    assert result["next_cursor"] is None
    assert "literal-secret" not in canonical_json(result).decode()
    assert result["coverage"] == [row.to_dict() for row in audit.manifest.coverage]
    assert all(row["record_id"] in {record.record_id for record in audit.records} for row in result["records"])


def test_deterministic_order_pages_and_cursor_identity(tmp_path):
    fixture = Fixture(tmp_path)
    audit = fixture.load()
    query = Query(Template.POPULATION)
    all_rows = execute(audit, query)["records"]
    pages = []
    cursor = None
    for offset in range(3):
        page = execute(audit, query, limit=1, cursor=cursor)
        assert page["offset"] == offset and page["total"] == 3
        pages.extend(page["records"])
        cursor = page["next_cursor"]
    assert cursor is None and pages == all_rows
    assert execute(replace(audit, records=tuple(reversed(audit.records))), query)["records"] == all_rows
    cursor = execute(audit, query, limit=1)["next_cursor"]
    for changed, other, size in (
        (replace(audit, accepted_handoff_sha256="b" * 64), query, 1),
        (replace(audit, reference=replace(audit.reference, sha256="c" * 64)), query, 1),
        (audit, Query(Template.LEAD_TRACE, lead_id="lead-1"), 1), (audit, query, 2)):
        with pytest.raises(ValueError, match="cursor"):
            execute(changed, other, limit=size, cursor=cursor)


@pytest.mark.parametrize("value", [0, -1, True, 201, 1.5, "2"])
def test_page_limit_is_typed_and_bounded(tmp_path, value):
    with pytest.raises(ValueError, match="limit"):
        execute(Fixture(tmp_path).load(), Query(Template.POPULATION), limit=value)


@pytest.mark.parametrize("cursor", ["!", "x" * 513, base64.b64encode(b"[]").decode(),
                                   base64.b64encode(b"not-json").decode(),
                                   base64.b64encode(b'{"identity": "foreign", "offset": true}').decode()],
                         ids=["invalid-base64", "too-long", "array", "invalid-json", "foreign"])
def test_cursor_is_closed_bounded_and_not_a_sql_or_path_channel(tmp_path, cursor):
    with pytest.raises(ValueError, match="cursor"):
        execute(Fixture(tmp_path).load(), Query(Template.POPULATION), limit=1, cursor=cursor)


@pytest.mark.parametrize("kwargs", [
    {"template": "sql"}, {"template": None}, {"template": "lead_trace"},
    {"template": "claim_basis"}, {"template": "population", "claim_id": "claim"},
    {"template": "claim_basis", "claim_id": "claim", "stage": "admission"},
    {"template": "lead_trace", "lead_id": ""}, {"template": "lead_trace", "lead_id": "a\nb"},
    {"template": "lead_trace", "lead_id": "x" * 201}, {"template": "lead_trace", "lead_id": True},
    {"template": "population", "role": "operator"}, {"template": "population", "role": "admin"},
], ids=["sql", "null", "lead-required", "claim-required", "extra-claim", "extra-stage",
        "empty", "control", "long", "bool", "operator-not-role", "admin-not-role"])
def test_queries_are_closed_and_roles_are_only_attribution(kwargs):
    with pytest.raises(ValueError):
        Query(**kwargs)


def test_unavailable_query_never_claims_zero_complete_results(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.publish(legacy=True)
    result = execute(fixture.load(), Query(Template.POPULATION))
    assert result["available"] is False
    assert result["unavailable_reason"] == "legacy_unrecorded"
    assert result["total"] is result["coverage"] is None
    with pytest.raises(ValueError, match="unavailable"):
        execute(fixture.load(), Query(Template.POPULATION), cursor="anything")


def test_continuations_are_verified_before_query_and_omissions_are_explicit(tmp_path):
    fixture = Fixture(tmp_path)
    products, payloads = continued_verifier(fixture)
    fixture.publish(products, continuations=payloads)
    result = execute(fixture.load(), Query(Template.VERIFICATION_COVERAGE))
    assert result["omissions"] == [{"record_id": products[1].record_id,
                                    "reason": "verified_reference_continuations_not_expanded", "references": 1}]
    assert result["records"][0]["context"]["relations"] == []


def test_judge_dissent_never_becomes_verification_support(tmp_path):
    fixture = Fixture(tmp_path)
    result = execute(fixture.load(), Query(Template.CLAIM_BASIS, claim_id="claim-1"))
    relations = {row["relation_id"]: row for row in result["records"][0]["context"]["relations"]}
    assert relations["dissent"]["actor_role"] == Role.ADJUDICATION_JUDGE
    assert relations["dissent"]["kind"] == "contradicts" and relations["dissent"]["counted"] is False
    verification = execute(fixture.load(), Query(Template.VERIFICATION_COVERAGE))["records"][0]
    assert verification["predicates"][0]["supporting_relation_ids"] == ["support"]
    assert verification["confirmation_eligible"]["value"] is False


def test_role_population_uses_producing_actor_not_deciding_or_citation_roles(tmp_path):
    fixture = Fixture(tmp_path)
    decision = replace(fixture.decision, stage=c.Stage.ADJUDICATION, outcome="confirmed",
                       context=replace(fixture.context, relations=fixture.relations),
                       deciding_row=c.DecidingRow.CONFIRMED, deciding_row_absence_reason=None,
                       deciding_actor_roles=c.deciding_roles(c.DecidingRow.CONFIRMED,
                                                             fixture.decision.required_predicates, fixture.relations))
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),))
    fixture.publish((decision, fixture.verification, basis))
    result = execute(fixture.load(), Query(Template.POPULATION, role=Role.INDEPENDENT_VERIFIER))
    assert [row["source_schema"] for row in result["records"]] == [c.VERIFICATION_SCHEMA]
    executed = replace(fixture.decision, stage=c.Stage.CELL_EXECUTION, outcome="succeeded",
                       actor_role=Role.INDEPENDENT_VERIFIER, actor_role_absence_reason=None)
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(executed),))
    fixture.publish((executed, fixture.verification, basis))
    result = execute(fixture.load(), Query(Template.POPULATION, stage=c.Stage.CELL_EXECUTION,
                                          role=Role.INDEPENDENT_VERIFIER))
    assert [row["record_id"] for row in result["records"]] == [executed.record_id]


def test_query_redacts_original_narrative_but_keeps_exact_resolving_citations(tmp_path):
    fixture = Fixture(tmp_path)
    original = "synthetic-token-abcdef0123456789abcdef0123456789"
    decision = replace(fixture.decision, original_outcome=link(original))
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),))
    fixture.publish((decision, fixture.verification, basis))
    result = execute(fixture.load(), Query(Template.POPULATION, stage=c.Stage.ADMISSION))
    document = result["records"][0]
    assert original not in canonical_json(document).decode()
    assert document["view"] == "redacted_operator_projection" and "schema" not in document
    assert document["source_record"] == c.RecordRef.of(decision).to_dict()
    assert document["record_id"] == decision.record_id
    assert document["context"]["sources"][0]["sha256"] == fixture.projection_ref["sha256"]
    assert document["context"]["sources"][0]["path"] == fixture.projection_ref["path"]
