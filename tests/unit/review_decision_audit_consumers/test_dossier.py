from dataclasses import replace

import pytest

from appsec_review.jobs.job_dossier_publication.job import _excerpts
from appsec_review.reporting.dossiers import DossierLimits, audit_relation_ids, build_dossier, dossier_document
from appsec_review.reporting.latex import render_latex
from appsec_review.review.models import IntegrityError
from appsec_review.review.decision_audit import contracts as c
from appsec_review.storage import canonical_json
from tests.dossier_fixture import settings

from .helpers import Fixture


def test_protected_basis_preserves_public_claim_evidence_and_scoring(tmp_path):
    fixture = Fixture(tmp_path)
    audit = fixture.load()
    before = build_dossier(**fixture.dossier())
    after = build_dossier(**fixture.dossier(), decision_audit=audit)
    assert "decision_basis" not in before
    assert "Protected decision basis" not in render_latex(dossier_document(before))
    assert {key: value for key, value in after.items() if key != "decision_basis"} == before
    basis = after["decision_basis"]
    assert basis["available"] and basis["record_id"] == fixture.basis.record_id
    assert {row["relation_id"] for row in after["evidence"]} == {"support"}
    assert {row["relation_id"] for row in basis["relations"]} == {"support", "dissent", "qualification"}
    assert next(row for row in basis["relations"] if row["relation_id"] == "dissent")[
        "counted_by_existing_policy"] is False
    assert "literal-secret" not in canonical_json(after).decode()
    rendered = render_latex(dossier_document(after))
    assert "Protected decision basis" in rendered
    assert "dissent" in rendered and "qualification" in rendered
    assert "nondeciding" in rendered


@pytest.mark.parametrize("field,value", [("sha256", "a" * 64), ("path", "foreign.json"),
                                        ("adjudication_id", "foreign"), ("finding_package_id", "foreign")],
                         ids=["hash", "path", "adjudication", "finding"])
def test_dossier_binding_cannot_mix_findings(tmp_path, field, value):
    fixture = Fixture(tmp_path)
    document = fixture.dossier()
    document["finding"][field] = value
    with pytest.raises(IntegrityError, match="another accepted finding"):
        build_dossier(**document, decision_audit=fixture.load())


@pytest.mark.parametrize("field", ["ledger_head_sha256", "review_handoff", "projection"])
def test_dossier_binding_cannot_mix_ledger_or_review(tmp_path, field):
    fixture = Fixture(tmp_path)
    document = fixture.dossier()
    document["provenance"][field] = "foreign" if field == "ledger_head_sha256" else {"sha256": "a" * 64}
    with pytest.raises(IntegrityError, match="ledger and review"):
        build_dossier(**document, decision_audit=fixture.load())


def test_dossier_missing_basis_and_bounded_relation_omissions(tmp_path):
    fixture = Fixture(tmp_path)
    audit = fixture.load()
    absent = replace(audit, records=tuple(row for row in audit.records if row != fixture.basis))
    assert audit_relation_ids(absent, fixture.dossier()["finding"]) == frozenset()
    missing = build_dossier(**fixture.dossier(), decision_audit=absent)
    assert missing["decision_basis"]["reason"] == "decision_basis_not_emitted"
    assert "Decision basis unavailable" in render_latex(dossier_document(missing))
    limited = build_dossier(**fixture.dossier(), decision_audit=audit, limits=DossierLimits(evidence_rows=1))
    assert len(limited["decision_basis"]["relations"]) == 1
    assert any(row["field"] == "decision_basis.relations" and row["omitted"] == 2 for row in limited["truncations"])


def test_dossier_refuses_relation_not_in_accepted_projection(tmp_path):
    fixture = Fixture(tmp_path)
    document = fixture.dossier()
    document["relations"] = document["relations"][:1]
    with pytest.raises(IntegrityError, match="absent"):
        build_dossier(**document, decision_audit=fixture.load())


def test_additional_excerpts_use_only_original_evidence_and_existing_caps(tmp_path):
    fixture = Fixture(tmp_path)
    audit = fixture.load()
    calls = []

    class Core:
        def read_excerpt(self, *, identity, context_lines):
            calls.append((identity, context_lines))
            return {"results": [{"identity": identity, "excerpt": 'password = "private-value"'}], "truncated": False}

    document = fixture.dossier()
    rows, gaps = _excerpts(Core(), document["relations"], document["finding"], settings(max_source_excerpts=2),
                           audit_relations=audit_relation_ids(audit, document["finding"]))
    assert calls == [("entity-support", 2), ("entity-dissent", 2)]
    assert len(rows) == 2 and gaps == ["source_excerpt_cap: 1 cited identities omitted"]
    built = build_dossier(**document, decision_audit=audit, excerpts=rows)
    assert "private-value" not in canonical_json(built).decode()
    assert len(built["evidence"]) == 1
    with pytest.raises(IntegrityError, match="unaccepted"):
        _excerpts(Core(), document["relations"], document["finding"], settings(),
                  audit_relations=frozenset({"foreign"}))


def test_no_audit_keeps_historical_excerpt_selection(tmp_path):
    fixture = Fixture(tmp_path)
    calls = []

    class Core:
        def read_excerpt(self, *, identity, context_lines):
            calls.append(identity)
            return {"results": [], "truncated": True}

    document = fixture.dossier()
    _, gaps = _excerpts(Core(), document["relations"], document["finding"], settings())
    assert calls == ["entity-support"]
    assert len(gaps) == 2


def test_verification_absence_and_explanation_bounds_remain_explicit(tmp_path):
    fixture = Fixture(tmp_path)
    decision = replace(fixture.decision, context=replace(fixture.context, explanation=c.Explanation(
        "explanation " * 100, None, fixture.context.explanation.redaction_reason)))
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),),
                    verification=c.OptionalRecord(None, c.AbsenceReason.NOT_PRODUCED))
    fixture.publish((decision, basis))
    result = build_dossier(**fixture.dossier(), decision_audit=fixture.load(), limits=DossierLimits(text_chars=100))
    assert result["decision_basis"]["verification"] is None
    assert result["decision_basis"]["verification_absence_reason"] == "not_produced"
    assert any(row["field"] == "decision_basis.explanation" for row in result["truncations"])
    assert "Unavailable:" in render_latex(dossier_document(result))
    fixture.publish(legacy=True)
    result = build_dossier(**fixture.dossier(), decision_audit=fixture.load())
    assert result["decision_basis"]["reason"] == "legacy_unrecorded"
