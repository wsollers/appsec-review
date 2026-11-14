from dataclasses import replace

import pytest

from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.query import Query, Template, execute
from appsec_review.review.models import IntegrityError, Role

from .helpers import Fixture, link


def two_cells(tmp_path):
    results = (
        {"proposals": [], "lead_accounting": [
            {"observation_id": "lead-shared", "outcome": "no_proposal", "proposal_ids": [], "gap_ids": []}]},
        {"proposals": [{"local_id": "p1", "source_lead_ids": ["lead-shared"]}], "lead_accounting": [
            {"observation_id": "lead-shared", "outcome": "proposal", "proposal_ids": ["p1"], "gap_ids": []}]},
    )
    fixture = Fixture(tmp_path, proposal=True, proposal_count=2, discovery_results=results,
                      second_proposal_package="original-red-package",
                      capture_items=[{"cell_id": "red-2", "proposal_ref": "p1", "claim_id": "claim-1"}])
    a = fixture.source(fixture.proposal_receipt, "lead-shared")
    b = fixture.source(fixture.second_proposal_receipt, "lead-shared")
    origin = fixture.source(fixture.second_proposal_receipt, "p1")
    subject = replace(fixture.subject, lead_id=link("lead-shared"), cell_id=link("red-1"),
                      package_id=link("original-red-package"), claim_id=link(), adjudication_id=link(),
                      finding_package_id=link())
    context = replace(fixture.context, subject=subject, sources=(a,))
    root = replace(fixture.decision, context=context, stage=c.Stage.RED_DISCOVERY, outcome="explicit_no_claim",
                   original_outcome=link("no_proposal"), basis_status=c.BasisStatus.NARRATIVE_ONLY,
                   reason_code=c.ReasonCode.RECORDED_DECISION, required_predicates=(),
                   actor_role=Role.RED_TEAM_ANALYST, actor_role_absence_reason=None,
                   cell_receipt=c.OptionalSource(fixture.source(fixture.proposal_receipt, "red-1"), None))
    canonical = replace(fixture.decision, context=fixture.context)
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(canonical),),
                    context=replace(fixture.basis.context, origin_proposals=(origin,)))
    return fixture, root, a, b, origin, canonical, basis


def publish(fixture, root, canonical, basis, *, continued):
    payloads = {}
    if continued:
        path = fixture.audit_root + "/continuations/known-cell/sources.jsonl"
        ref = c.make_continuation(c.ReferenceField.SOURCES, path, root.context.sources,
                                  origin=fixture.origin, claim_id=root.context.subject.claim_id)
        payloads[path] = c.reference_bytes(ref.field, root.context.sources, origin=fixture.origin,
                                          claim_id=root.context.subject.claim_id)
        root = replace(root, context=replace(root.context, continuations=(ref,),
            sources=(fixture.source(fixture.projection_ref, "red-1"),)))
    fixture.publish((canonical, fixture.verification, basis, root), continuations=payloads)
    return fixture.load()


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
@pytest.mark.parametrize("explicit_receipt", [False, True], ids=["sources-only", "explicit-receipt"])
def test_known_cell_cannot_adopt_another_cells_proposals_for_the_same_lead_and_package(
        tmp_path, continued, explicit_receipt):
    fixture, root, a, b, origin, canonical, basis = two_cells(tmp_path)
    assert fixture.projection["cells"]["red-1"][0]["package_id"] == \
        fixture.projection["cells"]["red-2"][0]["package_id"]
    if not explicit_receipt:
        root = replace(root, cell_receipt=c.OptionalSource(None, c.AbsenceReason.LEGACY_UNRECORDED))
    audit = publish(fixture, root, canonical, basis, continued=continued)
    result = execute(audit, Query(Template.LEAD_TRACE, lead_id="lead-shared"))
    assert result["total"] == 1 and result["records"][0]["outcome"] == "explicit_no_claim"
    assert result["trace"]["matched_proposals"] == 0
    borrowed = replace(root, context=replace(root.context, sources=(a, b), origin_proposals=(origin,),
                                              gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="different known cell"):
        publish(fixture, borrowed, canonical, basis, continued=continued)


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
def test_unknown_cell_can_use_only_the_complete_union_of_explicit_receipt_sources(tmp_path, continued):
    fixture, root, a, b, origin, canonical, basis = two_cells(tmp_path)
    root = replace(root, outcome="proposed", original_outcome=link("proposal"),
                   cell_receipt=c.OptionalSource(None, c.AbsenceReason.NOT_APPLICABLE),
                   context=replace(root.context, subject=replace(root.context.subject, cell_id=link()),
                                   sources=(a, b), origin_proposals=(origin,)))
    audit = publish(fixture, root, canonical, basis, continued=continued)
    result = execute(audit, Query(Template.LEAD_TRACE, lead_id="lead-shared"))
    assert result["total"] == 4
    assert result["trace"] == {"matched_proposals": 1, "matched_claims": 1, "unavailable_membership_records": 0}
    omitted = replace(root, context=replace(root.context, origin_proposals=(),
                                            gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="origin set omits"):
        publish(fixture, omitted, canonical, basis, continued=continued)
