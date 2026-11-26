"""The OpenVEX contract declares every decision-audit and original-source input the gate declares."""
from __future__ import annotations

from appsec_review.jobs.decision_audit_inputs import ORIGINAL_AUDIT_SOURCES
from appsec_review.jobs.job_final_publication_gate.datasets import CONTRACT as GATE
from appsec_review.jobs.job_openvex_export.datasets import CONTRACT as OPENVEX

AUDIT_KINDS = {"review_audit_metadata", "review_decision_audit", "review_decisions",
               "review_verification_coverage", "review_decision_bases", "review_audit_continuations"}


def test_openvex_declares_the_gates_decision_audit_inputs() -> None:
    """The export loads the accepted review with include_decision_audit=True, as the gate does, so the typed
    contract must admit the same producer outputs; an undeclared read fails the unit at runtime."""
    gate = {(row.producer, row.output_kind): row for row in GATE.inputs if row.output_kind in AUDIT_KINDS}
    openvex = {(row.producer, row.output_kind): row for row in OPENVEX.inputs if row.output_kind in AUDIT_KINDS}
    assert set(gate) == set(openvex) == {("job_inference_security_review", kind) for kind in AUDIT_KINDS}
    for key, row in gate.items():
        mirror = openvex[key]
        assert (mirror.schema, mirror.authority, mirror.availability, mirror.missing, mirror.channel) == (
            row.schema, row.authority, row.availability, row.missing, row.channel)


def test_openvex_declares_original_audit_source_inputs_matching_gate() -> None:
    """verify_decision_audit re-verifies original producer shards; OpenVEX must declare ORIGINAL_AUDIT_SOURCES."""
    expected = {(producer, kind) for producer, kinds in ORIGINAL_AUDIT_SOURCES for kind in ("handoff", *kinds)}
    gate = {(row.producer, row.output_kind): row for row in GATE.inputs if (row.producer, row.output_kind) in expected}
    openvex = {(row.producer, row.output_kind): row for row in OPENVEX.inputs if (row.producer, row.output_kind) in expected}
    assert set(gate) == set(openvex) == expected
    for key, row in gate.items():
        assert openvex[key] == row
