from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.query import Query, Template, execute
from appsec_review.review.models import IntegrityError, Role
from appsec_review.observability.findings.cli import main

from .helpers import Fixture, link


def discovery_results():
    proposals = [
        {"local_id": "p1", "source_lead_ids": ["lead-A"]},
        {"local_id": "shared", "source_lead_ids": ["lead-A", "lead-B"]},
        {"local_id": "sibling", "source_lead_ids": ["lead-B"]},
        {"local_id": "capped", "source_lead_ids": ["lead-A"]},
        {"local_id": "rejected", "source_lead_ids": ["lead-A"]},
    ]
    return (
        {"proposals": proposals, "lead_accounting": [
            {"observation_id": "lead-A", "outcome": "proposal",
             "proposal_ids": ["p1", "shared", "capped", "rejected"], "gap_ids": []},
            {"observation_id": "lead-B", "outcome": "proposal", "proposal_ids": ["shared", "sibling"], "gap_ids": []},
            {"observation_id": "lead-zero", "outcome": "no_proposal", "proposal_ids": [], "gap_ids": []}]},
        {"proposals": [{"local_id": "p1", "source_lead_ids": ["lead-C"]},
                       {"local_id": "other", "source_lead_ids": ["lead-C"]}],
         "lead_accounting": [{"observation_id": "lead-C", "outcome": "proposal",
                             "proposal_ids": ["p1", "other"], "gap_ids": []}]},
    )


def trace_case(tmp_path, *, change_source=None):
    results = discovery_results()
    if change_source is not None:
        change_source(results)
    captures = [{"cell_id": "red-1", "proposal_ref": identity, "claim_id": claim,
                 "decision": decision, "reason": reason} for identity, claim, decision, reason in (
                     ("p1", "claim-1", "admitted", None), ("shared", "claim-1", "admitted", None),
                     ("sibling", "claim-1", "admitted", None),
                     ("capped", None, "over_cap", "max_active_claims"),
                     ("rejected", None, "rejected", "unresolvable_citation"))]
    captures.extend((
        {"cell_id": "red-2", "proposal_ref": "p1", "claim_id": None, "decision": "rejected", "reason": "closed_vocabulary"},
        {"cell_id": "red-2", "proposal_ref": "other", "claim_id": "claim-1", "decision": "admitted", "reason": None}))
    fixture = Fixture(tmp_path, proposal=True, proposal_count=2, discovery_results=results,
                      capture_items=captures, other_claim=True)
    receipt_refs = {"red-1": fixture.proposal_receipt, "red-2": fixture.second_proposal_receipt}
    sources = {(cell, row["local_id"]): fixture.source(receipt_refs[cell], row["local_id"])
               for cell, result in zip(("red-1", "red-2"), results, strict=True)
               for row in result["proposals"]}
    proposal_rows = []
    for capture in fixture.lane["proposal_audit"]["items"]:
        cell, local = capture["cell_id"], capture["proposal_ref"]
        source = sources[(cell, local)]
        claim = link(capture["claim_id"]) if capture["claim_id"] else c.Link(None, c.AbsenceReason.PRE_CLAIM)
        subject = replace(fixture.subject, cell_id=link(cell), package_id=link(capture["package_id"]),
                          lead_id=link(), proposal_ref=link(local), claim_id=claim,
                          finding_package_id=link(), adjudication_id=link())
        context = replace(fixture.context, subject=subject, origin_proposals=(source,),
                          sources=(fixture.source(receipt_refs[cell], cell),))
        proposed = replace(fixture.decision, context=context, stage=c.Stage.RED_DISCOVERY, outcome="proposed",
                           reason_code=c.ReasonCode.RECORDED_DECISION, basis_status=c.BasisStatus.NARRATIVE_ONLY,
                           actor_role=Role.RED_TEAM_ANALYST, actor_role_absence_reason=None,
                           cell_receipt=c.OptionalSource(fixture.source(receipt_refs[cell], cell), None))
        stage, outcome = ((c.Stage.CLAIM_CAP, "capped") if capture["decision"] == "over_cap" else
                          (c.Stage.PROPOSAL_NORMALIZATION, "rejected" if capture["decision"] == "rejected" else "normalized"))
        proposal_rows.extend((proposed, replace(proposed, stage=stage, outcome=outcome,
                                                basis_status=c.BasisStatus.EXISTING_POLICY)))
    roots = {}
    for lead, cell, result in (("lead-A", "red-1", results[0]), ("lead-B", "red-1", results[0]),
                               ("lead-zero", "red-1", results[0]), ("lead-C", "red-2", results[1])):
        # This is the known original lead invocation, not a reconstruction from sibling proposals.
        entries = result.get("lead_accounting")
        entry = next((row for row in entries if isinstance(row, dict) and row.get("observation_id") == lead), {}) \
            if isinstance(entries, list) else {}
        ids = entry.get("proposal_ids")
        recorded = isinstance(ids, list)
        origins = tuple(sources[(cell, local)] for local in dict.fromkeys(ids)
                        if (cell, local) in sources) if recorded else ()
        subject = replace(fixture.subject, cell_id=link(cell), lead_id=link(lead), proposal_ref=link(),
                          claim_id=link(), finding_package_id=link(), adjudication_id=link(),
                          package_id=link(fixture.projection["cells"][cell][0]["package_id"]))
        context = replace(fixture.context, subject=subject, origin_proposals=origins,
                          sources=(fixture.source(receipt_refs[cell], lead),),
                          gap_ids=() if recorded else ("audit:lead_proposal_membership_unrecorded",))
        roots[lead] = replace(fixture.decision, context=context, stage=c.Stage.RED_DISCOVERY,
                              outcome="explicit_no_claim" if recorded and not ids else "proposed",
                              reason_code=c.ReasonCode.RECORDED_DECISION, basis_status=c.BasisStatus.NARRATIVE_ONLY,
                              actor_role=Role.RED_TEAM_ANALYST, actor_role_absence_reason=None,
                              cell_receipt=c.OptionalSource(fixture.source(receipt_refs[cell], cell), None))
    canonical = replace(fixture.decision, context=fixture.context)
    other = replace(fixture.decision, context=replace(fixture.context, subject=replace(
        fixture.subject, claim_id=link("claim-2"), package_id=link("package-2"), cell_id=link(),
        adjudication_id=link(), finding_package_id=link())))
    origins = tuple(sources[(row["cell_id"], row["proposal_ref"])]
                    for row in fixture.lane["proposal_audit"]["items"] if row["claim_id"] == "claim-1")
    return SimpleNamespace(fixture=fixture, roots=roots, proposals=tuple(proposal_rows), sources=sources,
                           canonical=canonical, other=other, origins=origins)


def publish_trace(case, *, continued=False):
    fixture = case.fixture
    payloads = dict(getattr(case, "extra_payloads", {}))

    def continue_origins(record, name):
        origins = record.context.origin_proposals
        path = fixture.audit_root + "/continuations/lineage/" + name + ".jsonl"
        ref = c.make_continuation(c.ReferenceField.ORIGIN_PROPOSALS, path, origins, origin=fixture.origin,
                                  claim_id=record.context.subject.claim_id)
        payloads[path] = c.reference_bytes(ref.field, origins, origin=fixture.origin,
                                           claim_id=record.context.subject.claim_id)
        return replace(record, context=replace(record.context, origin_proposals=(),
                                                continuations=(*record.context.continuations, ref)))

    roots = [continue_origins(row, lead) if continued and row.context.origin_proposals else row
             for lead, row in sorted(case.roots.items())]
    proposals = [continue_origins(row, "proposal-" + str(index)) if continued else row
                 for index, row in enumerate(case.proposals)]
    decisions = [case.canonical, case.other, *roots, *proposals]
    basis = replace(fixture.basis, context=replace(fixture.basis.context, origin_proposals=case.origins),
                    decisions=tuple(c.RecordRef.of(row) for row in decisions
                                    if row.context.subject.claim_id.value == "claim-1"))
    if continued:
        basis = continue_origins(basis, "basis")
    products = (*decisions, fixture.verification, basis)
    fixture.publish(products, continuations=payloads)
    return fixture.load()


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
@pytest.mark.parametrize("lead,total,proposals", [
    ("lead-A", 12, {("red-1", "p1"), ("red-1", "shared"), ("red-1", "capped"), ("red-1", "rejected")}),
    ("lead-B", 8, {("red-1", "shared"), ("red-1", "sibling")}),
    ("lead-C", 8, {("red-2", "p1"), ("red-2", "other")}),
], ids=["many-outcomes", "shared-proposal", "same-local-id"])
def test_lead_trace_joins_exact_original_proposals_then_canonical_outcomes(tmp_path, continued, lead, total, proposals):
    case = trace_case(tmp_path)
    audit = publish_trace(case, continued=continued)
    assert all(row.context.subject.lead_id.value is None for row in
               (*case.proposals, case.canonical, case.other, case.fixture.verification, audit.basis("claim-1")))
    result = execute(audit, Query(Template.LEAD_TRACE, lead_id=lead))
    assert result["total"] == total
    actual = {(row["context"]["subject"]["cell_id"]["value"], row["context"]["subject"]["proposal_ref"]["value"])
              for row in result["records"] if row["context"]["subject"]["proposal_ref"]["value"] is not None}
    assert actual == proposals
    assert {row["source_schema"] for row in result["records"]} == {c.DECISION_SCHEMA, c.VERIFICATION_SCHEMA, c.BASIS_SCHEMA}
    assert case.canonical.record_id in {row["record_id"] for row in result["records"]}
    assert case.other.record_id not in {row["record_id"] for row in result["records"]}
    assert {row["context"]["subject"]["lead_id"]["value"] for row in result["records"]} == {None, lead}
    if lead == "lead-A":
        assert {"capped", "rejected", "normalized"} <= {row.get("outcome") for row in result["records"]}
    assert result["trace"] == {"matched_proposals": len(proposals), "matched_claims": 1,
                               "unavailable_membership_records": 0}


def test_lead_trace_pages_and_cursors_bind_the_exact_many_to_many_query(tmp_path):
    audit = publish_trace(trace_case(tmp_path), continued=True)
    query = Query(Template.LEAD_TRACE, lead_id="lead-A")
    full = execute(audit, query)
    page = execute(audit, query, limit=2)
    first_cursor = page["next_cursor"]
    records = list(page["records"])
    while page["next_cursor"] is not None:
        page = execute(audit, query, limit=2, cursor=page["next_cursor"])
        assert page["trace"] == full["trace"]
        records.extend(page["records"])
    assert records == full["records"]
    with pytest.raises(ValueError, match="cursor"):
        execute(audit, Query(Template.LEAD_TRACE, lead_id="lead-B"), limit=2, cursor=first_cursor)


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
@pytest.mark.parametrize("mutation", ["sibling", "omit-one", "omit-all", "foreign-receipt"])
def test_lead_semantic_complete_origin_set_rejects_substitutions_and_omissions(tmp_path, continued, mutation):
    case = trace_case(tmp_path)
    root = case.roots["lead-A"]
    origins = root.context.origin_proposals
    if mutation == "sibling":
        origins = tuple(case.sources[("red-1", "sibling")] if row.record_id.value == "p1" else row for row in origins)
    elif mutation == "foreign-receipt":
        origins = tuple(case.sources[("red-2", "p1")] if row.record_id.value == "p1" else row for row in origins)
    elif mutation == "omit-one":
        origins = origins[:-1]
    else:
        origins = ()
    case.roots["lead-A"] = replace(root, context=replace(root.context, origin_proposals=origins))
    assert case.roots["lead-A"].context.subject.claim_id.value is None
    with pytest.raises(IntegrityError, match="origin set omits or substitutes"):
        publish_trace(case, continued=continued)


@pytest.mark.parametrize("mutation", ["forward", "reverse", "unknown", "duplicate-lead",
                                     "duplicate-proposal", "bad-proposal-ids", "bad-source-leads"])
def test_original_accounting_and_source_lead_ids_must_agree(tmp_path, mutation):
    def change(results):
        result = results[0]
        if mutation == "forward":
            result["proposals"][0]["source_lead_ids"] = ["lead-B"]
        elif mutation == "reverse":
            result["lead_accounting"][0]["proposal_ids"].remove("p1")
        elif mutation == "unknown":
            result["lead_accounting"][0]["proposal_ids"].append("missing")
        elif mutation == "duplicate-lead":
            result["lead_accounting"].append(dict(result["lead_accounting"][0]))
        elif mutation == "duplicate-proposal":
            result["lead_accounting"][0]["proposal_ids"].append("p1")
        elif mutation == "bad-proposal-ids":
            result["lead_accounting"][0]["proposal_ids"] = "p1"
        else:
            result["proposals"][0]["source_lead_ids"] = None

    case = trace_case(tmp_path, change_source=change)
    if mutation == "duplicate-proposal":
        root = case.roots["lead-A"]
        case.roots["lead-A"] = replace(root, context=replace(root.context, origin_proposals=tuple(
            {row.record_id.value: row for row in root.context.origin_proposals}.values())))
    with pytest.raises(IntegrityError, match="lead accounting|membership is malformed|source leads|ambiguous"):
        publish_trace(case)


@pytest.mark.parametrize("missing", ["accounting", "proposal-ids"])
def test_historical_membership_absence_is_explicit_not_a_same_cell_join(tmp_path, missing):
    def change(results):
        if missing == "accounting":
            results[0].pop("lead_accounting")
        else:
            results[0]["lead_accounting"][0].pop("proposal_ids")

    case = trace_case(tmp_path, change_source=change)
    audit = publish_trace(case)
    result = execute(audit, Query(Template.LEAD_TRACE, lead_id="lead-A"))
    assert result["total"] == 1
    assert result["records"][0]["context"]["gap_ids"] == ["audit:lead_proposal_membership_unrecorded"]
    assert result["trace"] == {"matched_proposals": 0, "matched_claims": 0, "unavailable_membership_records": 1}
    assert {"reason": "lead_proposal_membership_unavailable", "records": 1} in result["omissions"]
    root = case.roots["lead-A"]
    case.roots["lead-A"] = replace(root, context=replace(root.context, gap_ids=()))
    with pytest.raises(IntegrityError, match="explicit omission"):
        publish_trace(case)


def test_known_no_proposal_is_distinct_from_unrecorded_membership(tmp_path):
    result = execute(publish_trace(trace_case(tmp_path)), Query(Template.LEAD_TRACE, lead_id="lead-zero"))
    assert result["total"] == 1 and result["records"][0]["outcome"] == "explicit_no_claim"
    assert result["trace"] == {"matched_proposals": 0, "matched_claims": 0, "unavailable_membership_records": 0}
    assert result["omissions"] == []


@pytest.mark.parametrize("lead", ["lead-A", "lead-C"], ids=["recorded-source", "sibling-substitution"])
def test_proposal_specific_lead_attribution_uses_original_accounting(tmp_path, lead):
    case = trace_case(tmp_path)
    rows = list(case.proposals)
    index = next(index for index, row in enumerate(rows)
                 if row.context.subject.cell_id.value == "red-1"
                 and row.context.subject.proposal_ref.value == "shared")
    row = rows[index]
    rows[index] = replace(row, context=replace(row.context, subject=replace(row.context.subject, lead_id=link(lead))))
    case.proposals = tuple(rows)
    if lead == "lead-C":
        with pytest.raises(IntegrityError, match="lead is absent|does not belong"):
            publish_trace(case)
    else:
        audit = publish_trace(case)
        assert execute(audit, Query(Template.LEAD_TRACE, lead_id=lead))["total"] == 12


def test_missing_recorded_membership_never_accepts_inferred_origin_refs(tmp_path):
    case = trace_case(tmp_path, change_source=lambda results: results[0].pop("lead_accounting"))
    root = case.roots["lead-A"]
    case.roots["lead-A"] = replace(root, context=replace(root.context, origin_proposals=(case.sources[("red-1", "p1")],)))
    with pytest.raises(IntegrityError, match="no inferred origins"):
        publish_trace(case)


def test_lost_historical_cell_identity_is_unavailable_not_reconstructed_from_current_cells(tmp_path):
    case = trace_case(tmp_path)
    root = case.roots["lead-A"]
    case.roots["lead-A"] = replace(root, cell_receipt=c.OptionalSource(None, c.AbsenceReason.LEGACY_UNRECORDED),
        context=replace(root.context, subject=replace(root.context.subject, cell_id=c.Link(None, c.AbsenceReason.LEGACY_UNRECORDED)),
                        sources=(case.fixture.source(case.fixture.projection_ref, "red-1"),),
                        origin_proposals=(), gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    result = execute(publish_trace(case), Query(Template.LEAD_TRACE, lead_id="lead-A"))
    assert result["total"] == 1 and result["trace"]["matched_claims"] == 0
    assert result["trace"]["unavailable_membership_records"] == 1


def test_lead_semantic_row_cannot_borrow_a_non_discovery_cell_to_claim_absence(tmp_path):
    case = trace_case(tmp_path)
    root = case.roots["lead-A"]
    case.roots["lead-A"] = replace(root, actor_role=None, actor_role_absence_reason=c.AbsenceReason.LEGACY_UNRECORDED,
        cell_receipt=c.OptionalSource(case.fixture.source(case.fixture.receipt_ref, "cell-1"), None),
        context=replace(root.context, subject=replace(root.context.subject, cell_id=link("cell-1"), package_id=link("package-1")),
                        origin_proposals=(), gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="does not name a discovery cell"):
        publish_trace(case)


def test_operator_cli_returns_downstream_claim_outcomes_without_direct_lead_ids(tmp_path, monkeypatch, capsys):
    case = trace_case(tmp_path)
    audit = publish_trace(case, continued=True)
    monkeypatch.setattr("appsec_review.review.decision_audit.reader.load_decision_audit", lambda _: audit)
    assert main(["decision-audit", "--run", str(case.fixture.root), "--template", "lead_trace",
                 "--lead-id", "lead-A", "--limit", "20"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["total"] == 12
    assert {row["source_schema"] for row in document["records"]} == {c.DECISION_SCHEMA, c.VERIFICATION_SCHEMA, c.BASIS_SCHEMA}
    assert document["trace"]["matched_claims"] == 1


def source_only_lead(case, source, continued_source):
    root = case.roots["lead-A"]
    context = replace(root.context, subject=replace(root.context.subject,
                      cell_id=c.Link(None, c.AbsenceReason.LEGACY_UNRECORDED)),
                      sources=(source,))
    if continued_source:
        path = case.fixture.audit_root + "/continuations/lineage/lead-source.jsonl"
        ref = c.make_continuation(c.ReferenceField.SOURCES, path, context.sources,
                                  origin=case.fixture.origin, claim_id=context.subject.claim_id)
        case.extra_payloads = {path: c.reference_bytes(ref.field, context.sources, origin=case.fixture.origin,
                                                     claim_id=context.subject.claim_id)}
        context = replace(context, sources=(case.fixture.source(case.fixture.projection_ref, "red-1"),),
                          continuations=(ref,))
    root = replace(root, context=context, cell_receipt=c.OptionalSource(None, c.AbsenceReason.LEGACY_UNRECORDED))
    return root


@pytest.mark.parametrize("continued_source", [False, True], ids=["source-inline", "source-continued"])
@pytest.mark.parametrize("locator", ["red-1", "lead-A"], ids=["cell-locator", "producer-lead-locator"])
@pytest.mark.parametrize("mutation", ["omit-one", "omit-all", "sibling", "other-receipt"])
def test_recorded_source_receipt_prevents_omission_when_cell_display_fields_are_absent(
        tmp_path, continued_source, locator, mutation):
    case = trace_case(tmp_path)
    root = source_only_lead(case, case.fixture.source(case.fixture.proposal_receipt, locator), continued_source)
    case.roots["lead-A"] = root
    result = execute(publish_trace(case, continued=True), Query(Template.LEAD_TRACE, lead_id="lead-A"))
    assert result["total"] == 12 and result["trace"]["unavailable_membership_records"] == 0
    origins = root.context.origin_proposals
    if mutation == "omit-one":
        origins = origins[:-1]
    elif mutation == "omit-all":
        origins = ()
    else:
        substitute = case.sources[("red-1", "sibling") if mutation == "sibling" else ("red-2", "p1")]
        origins = tuple(substitute if row.record_id.value == "p1" else row for row in origins)
    case.roots["lead-A"] = replace(root, context=replace(
        root.context, origin_proposals=origins, gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="origin set omits"):
        publish_trace(case, continued=True)


@pytest.mark.parametrize("continued_source", [False, True], ids=["source-inline", "source-continued"])
@pytest.mark.parametrize("locator", ["lead-B", "red-2", "p1", None],
                         ids=["sibling-lead", "foreign-cell", "proposal-not-lead", "absent-locator"])
def test_receipt_locator_cannot_substitute_a_sibling_or_hide_available_membership(
        tmp_path, continued_source, locator):
    case = trace_case(tmp_path)
    root = source_only_lead(case, case.fixture.source(case.fixture.proposal_receipt, locator), continued_source)
    case.roots["lead-A"] = replace(root, context=replace(
        root.context, origin_proposals=(), gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="receipt locator"):
        publish_trace(case, continued=True)


@pytest.mark.parametrize("continued_source", [False, True], ids=["source-inline", "source-continued"])
def test_lead_addressed_source_must_still_be_an_accepted_discovery_receipt(tmp_path, continued_source):
    case = trace_case(tmp_path)
    root = source_only_lead(case, case.fixture.source(case.fixture.receipt_ref, "lead-A"), continued_source)
    case.roots["lead-A"] = replace(root, context=replace(
        root.context, origin_proposals=(), gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="receipt source is not a discovery"):
        publish_trace(case, continued=True)


@pytest.mark.parametrize("continued_source", [False, True], ids=["source-inline", "source-continued"])
def test_identical_lookalike_file_is_not_an_original_receipt_binding(tmp_path, continued_source):
    case = trace_case(tmp_path)
    fixture = case.fixture
    copied = fixture.write(fixture.attempt + "/steps/lead_review/lookalike.json",
                           (fixture.root / fixture.proposal_receipt["path"]).read_bytes())
    assert copied["sha256"] == fixture.proposal_receipt["sha256"]
    root = source_only_lead(case, fixture.source(copied, "lead-A"), continued_source)
    case.roots["lead-A"] = replace(root, context=replace(
        root.context, gap_ids=("audit:lead_proposal_membership_unrecorded",)))
    with pytest.raises(IntegrityError, match="origin set omits"):
        publish_trace(case, continued=True)
    case.roots["lead-A"] = replace(root, context=replace(
        root.context, origin_proposals=(fixture.source(copied, "p1"),)))
    with pytest.raises(IntegrityError, match="accepted cell receipt"):
        publish_trace(case, continued=True)


@pytest.mark.parametrize("continued_source", [False, True], ids=["source-inline", "source-continued"])
def test_lead_addressed_historical_receipt_without_recorded_membership_stays_unavailable(tmp_path, continued_source):
    case = trace_case(tmp_path, change_source=lambda results: results[0].pop("lead_accounting"))
    root = source_only_lead(case, case.fixture.source(case.fixture.proposal_receipt, "lead-A"), continued_source)
    case.roots["lead-A"] = root
    result = execute(publish_trace(case, continued=True), Query(Template.LEAD_TRACE, lead_id="lead-A"))
    assert result["total"] == 1
    assert result["trace"] == {"matched_proposals": 0, "matched_claims": 0, "unavailable_membership_records": 1}
    assert result["records"][0]["context"]["gap_ids"] == ["audit:lead_proposal_membership_unrecorded"]
    assert {"reason": "lead_proposal_membership_unavailable", "records": 1} in result["omissions"]
    case.roots["lead-A"] = replace(root, context=replace(root.context, gap_ids=()))
    with pytest.raises(IntegrityError, match="explicit omission"):
        publish_trace(case, continued=True)


def test_recorded_accounting_remains_usable_when_optional_source_lead_ids_were_not_recorded(tmp_path):
    case = trace_case(tmp_path, change_source=lambda results: results[0]["proposals"][0].pop("source_lead_ids"))
    result = execute(publish_trace(case), Query(Template.LEAD_TRACE, lead_id="lead-A"))
    assert result["total"] == 12 and result["trace"]["matched_proposals"] == 4


@pytest.mark.parametrize("result,available", [
    (None, False),
    ("not an object", None),
    ({"lead_accounting": {}}, None),
    ({"lead_accounting": [{"observation_id": "lead-A", "proposal_ids": []}], "proposals": {}}, None),
], ids=["failed-no-result", "malformed-result", "malformed-accounting", "malformed-proposals"])
def test_absent_failed_cell_detail_is_not_confused_with_malformed_recorded_detail(tmp_path, result, available):
    fixture = Fixture(tmp_path, proposal=True, discovery_results=(result,), capture_items=[], discovery_status="failed")
    subject = replace(fixture.subject, lead_id=link("lead-A"), cell_id=link("red-1"),
                      claim_id=link(), adjudication_id=link(), finding_package_id=link(),
                      package_id=link("original-red-package"))
    root = replace(fixture.decision, stage=c.Stage.RED_DISCOVERY, outcome="invalid",
                   reason_code=c.ReasonCode.INVALID_OUTPUT, basis_status=c.BasisStatus.UNSTATED,
                   actor_role=Role.RED_TEAM_ANALYST, actor_role_absence_reason=None,
                   context=replace(fixture.context, subject=subject, gap_ids=("audit:cell_failed",)),
                   cell_receipt=c.OptionalSource(fixture.source(fixture.proposal_receipt, "red-1"), None))
    fixture.publish((root,))
    if available is None:
        with pytest.raises(IntegrityError, match="malformed"):
            fixture.load()
    else:
        response = execute(fixture.load(), Query(Template.LEAD_TRACE, lead_id="lead-A"))
        assert response["trace"]["unavailable_membership_records"] == 1
        assert response["records"][0]["context"]["gap_ids"] == ["audit:cell_failed"]
