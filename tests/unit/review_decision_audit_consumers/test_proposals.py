from dataclasses import replace

import pytest

from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.query import Query, Template, execute
from appsec_review.review.models import IntegrityError, Role

from .helpers import Fixture, digest, link


def proposal_products(fixture, *, legacy=False):
    claim = c.Link(None, c.AbsenceReason.LEGACY_UNRECORDED) if legacy else link("claim-1")
    subject = replace(fixture.subject, cell_id=link("red-1"), package_id=link("original-red-package"),
                      claim_id=claim, lead_id=link(), proposal_ref=link("p1"),
                      adjudication_id=link(), finding_package_id=link())
    source = fixture.source(fixture.proposal_receipt, "p1")
    context = replace(fixture.context, subject=subject, origin_proposals=(source,),
                      sources=(fixture.source(fixture.proposal_receipt, "red-1"),),
                      gap_ids=("audit:original_proposal_membership_unrecorded",) if legacy else ())
    proposal = replace(fixture.decision, context=context, stage=c.Stage.RED_DISCOVERY, outcome="proposed",
                       cell_receipt=c.OptionalSource(fixture.source(fixture.proposal_receipt, "red-1"), None),
                       actor_role=Role.RED_TEAM_ANALYST, actor_role_absence_reason=None)
    decisions = (c.RecordRef.of(fixture.decision),) if legacy else (
        c.RecordRef.of(fixture.decision), c.RecordRef.of(proposal))
    basis = replace(fixture.basis, decisions=decisions,
                    context=replace(fixture.basis.context, origin_proposals=() if legacy else (source,)))
    return fixture.decision, fixture.verification, basis, proposal


def update_lane(fixture):
    fixture.lane_ref = fixture.write(fixture.lane_ref["path"], fixture.lane)
    fixture.outputs["lead_review.teams"] = {"artifact": fixture.lane_ref}


def test_original_receipt_local_proposal_membership_is_not_reconstructed_or_renamed(tmp_path):
    fixture = Fixture(tmp_path, proposal=True)
    products = proposal_products(fixture)
    fixture.publish(products)
    audit = fixture.load()
    assert audit.basis("claim-1").context.origin_proposals[0].record_id.value == "p1"
    result = execute(audit, Query(Template.POPULATION, stage=c.Stage.RED_DISCOVERY))
    assert result["total"] == 1
    subject = result["records"][0]["context"]["subject"]
    assert subject["proposal_ref"]["value"] == "p1" and subject["claim_id"]["value"] == "claim-1"
    assert subject["package_id"]["value"] == "original-red-package"
    assert "ORIGINAL_PRIVATE_PROPOSAL" not in str(result)


def test_historical_proposal_is_named_unknown_membership_not_a_fabricated_claim(tmp_path):
    fixture = Fixture(tmp_path, proposal=True)
    fixture.lane.pop("proposal_audit")
    update_lane(fixture)
    products = proposal_products(fixture, legacy=True)
    fixture.publish(products)
    audit = fixture.load()
    assert audit.basis("claim-1").context.origin_proposals == ()
    result = execute(audit, Query(Template.POPULATION, stage=c.Stage.RED_DISCOVERY))["records"][0]
    assert result["context"]["subject"]["claim_id"] == {"value": None, "absence_reason": "legacy_unrecorded"}
    assert result["context"]["gap_ids"] == ["audit:original_proposal_membership_unrecorded"]
    invalid = replace(products[-1], context=replace(products[-1].context, gap_ids=()))
    fixture.publish((*products[:-1], invalid))
    with pytest.raises(IntegrityError, match="no exact original claim membership"):
        fixture.load()


@pytest.mark.parametrize("field,value", [
    ("claim_id", "foreign"), ("package_id", "foreign"), ("round", 2),
    ("proposal_ref", "another"), ("receipt_sha256", digest("foreign")),
], ids=["claim", "package", "round", "local-id", "receipt"])
def test_capture_cannot_move_a_proposal_to_another_claim_cell_round_or_package(tmp_path, field, value):
    fixture = Fixture(tmp_path, proposal=True)
    fixture.capture[field] = value
    update_lane(fixture)
    fixture.publish(proposal_products(fixture))
    with pytest.raises(IntegrityError, match="member|terminal receipt"):
        fixture.load()


@pytest.mark.parametrize("mutation", ["schema", "extra", "type", "duplicate"])
def test_proposal_capture_is_versioned_closed_and_unambiguous(tmp_path, mutation):
    fixture = Fixture(tmp_path, proposal=True)
    capture = fixture.lane["proposal_audit"]
    if mutation == "schema":
        capture["schema"] = "foreign"
    elif mutation == "extra":
        fixture.capture["unknown"] = True
    elif mutation == "type":
        fixture.capture["cell_id"] = {}
    else:
        capture["items"].append(dict(fixture.capture))
    update_lane(fixture)
    fixture.publish(proposal_products(fixture))
    with pytest.raises(IntegrityError, match="proposal capture"):
        fixture.load()


def test_origin_proposal_reference_cannot_name_another_local_id_or_receipt(tmp_path):
    fixture = Fixture(tmp_path, proposal=True)
    products = list(proposal_products(fixture))
    for source in (fixture.source(fixture.proposal_receipt, "foreign-local-id"),
                   fixture.source(fixture.projection_ref, "p1")):
        basis = replace(products[2], context=replace(products[2].context, origin_proposals=(source,)))
        fixture.publish((*products[:2], basis, products[3]))
        with pytest.raises(IntegrityError, match="proposal identity|accepted cell receipt"):
            fixture.load()


def test_continued_original_proposals_have_the_same_membership_checks(tmp_path):
    fixture = Fixture(tmp_path, proposal=True)
    products = list(proposal_products(fixture))
    source = fixture.source(fixture.proposal_receipt, "p1")
    path = fixture.audit_root + "/continuations/origins/0001.jsonl"
    continuation = c.make_continuation(c.ReferenceField.ORIGIN_PROPOSALS, path, (source,),
                                       origin=fixture.origin, claim_id=link("claim-1"))
    basis = replace(products[2], context=replace(products[2].context, origin_proposals=(),
                                                continuations=(continuation,)))
    fixture.publish((*products[:2], basis, products[3]), continuations={
        path: c.reference_bytes(continuation.field, (source,), origin=fixture.origin, claim_id=link("claim-1"))})
    assert fixture.load().basis("claim-1") == basis


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
def test_same_original_local_id_in_different_receipts_keeps_both_origins(tmp_path, continued):
    fixture = Fixture(tmp_path, proposal=True, proposal_count=2)
    products = proposal_products(fixture)
    source = fixture.source(fixture.second_proposal_receipt, "p1")
    subject = replace(products[3].context.subject, cell_id=link("red-2"), package_id=link("original-red-2"))
    second = replace(products[3], context=replace(
        products[3].context, subject=subject, origin_proposals=(source,),
        sources=(fixture.source(fixture.second_proposal_receipt, "red-2"),)),
        cell_receipt=c.OptionalSource(fixture.source(fixture.second_proposal_receipt, "red-2"), None))
    origins = (*products[2].context.origin_proposals, source)
    context = replace(products[2].context, origin_proposals=origins)
    payloads = {}
    if continued:
        path = fixture.audit_root + "/continuations/origins/0001.jsonl"
        ref = c.make_continuation(c.ReferenceField.ORIGIN_PROPOSALS, path, origins,
                                  origin=fixture.origin, claim_id=link("claim-1"))
        context = replace(context, origin_proposals=(), continuations=(ref,))
        payloads[path] = c.reference_bytes(ref.field, origins, origin=fixture.origin, claim_id=link("claim-1"))
    basis = replace(products[2], context=context, decisions=(*products[2].decisions, c.RecordRef.of(second)))
    fixture.publish((*products[:2], basis, products[3], second), continuations=payloads)
    audit = fixture.load()
    result = execute(audit, Query(Template.POPULATION, stage=c.Stage.RED_DISCOVERY))
    assert result["total"] == 2
    assert {row["context"]["subject"]["proposal_ref"]["value"] for row in result["records"]} == {"p1"}
    assert {row["context"]["subject"]["cell_id"]["value"] for row in result["records"]} == {"red-1", "red-2"}
    assert audit.basis("claim-1") == basis
