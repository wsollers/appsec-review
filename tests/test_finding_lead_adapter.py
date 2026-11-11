"""Lead records with stage attribution derived from a run's verified review documents (T-077).

The run fixtures are the hash-bound ones of ``tests/test_triage_reduction_metrics.py``, read through
the real ``triage_reduction.load_verified_documents``. That fixture writes claims without evidence
relations, cell records or state history, so the tests that need them set those tables on the
verified projection in memory, in the shapes ``review.ledger`` projects (``claim_json`` plus
``state_history``, ``relation_json``, ``cell_json``, ``judge_verdict_json``).
"""
from __future__ import annotations

from collections import Counter
import copy
import hashlib
from pathlib import Path

import pytest

from appsec_review.acceptance.scoring_model import EntryKind, KeyEntry, ScoringKey
from appsec_review.observability import triage_reduction
from appsec_review.observability.findings import lead_adapter as adapter, triage
from appsec_review.observability.findings.contracts import TRIAGE_STAGES
from appsec_review.observability.findings.lead_adapter import LeadDocuments, claim_removal_stage, lead_records
from appsec_review.storage import canonical_json
from tests.test_triage_reduction_metrics import Claim, Lead, Scenario, build_run, mixed

ROW = "adjudication-rules/1:r4_direct_contradiction"
REACH, GUARD, CONFIG = "source_to_sink_reachability", "missing_or_ineffective_guard", "configuration_enables"
BLUE, VERIFIER, JUDGE, RED = "blue_team_refuter", "independent_verifier", "adjudication_judge", "red_team_analyst"


def claim(claim_id="C1", state="contradicted", *, row=ROW, **changes):
    document = {"schema": "appsec-review/review-claim/1", "claim_id": claim_id, "lane": "lead", "package_id": "pkg",
                "affected_entities": [], "weakness_cwe": "CWE-121", "security_predicate": "memory_corruption",
                "preconditions": ["attacker_has_network_access"], "statement": "prose that is never read",
                "state": state, "duplicate_of": None, "origin_cell_ids": ["red-1"],
                "state_history": [] if row is None else [
                    {"from_state": "proposed", "to_state": state, "round": 0, "reason": row,
                     "event_content_sha256": "e" * 64, "adjudication_id": "adjudication-" + "a" * 64}]}
    return {**document, **changes}


def relation(cell_id, predicate=REACH, *, kind="contradicts", claim_id="C1", complete=True, admissibility="direct",
             provenance=None):
    document = {"relation_id": f"rel-{cell_id}-{predicate}-{kind}", "claim_id": claim_id, "predicate": predicate,
                "kind": kind, "entity_id": "asr:symbol:x", "entity_kind": "symbol", "admissibility": admissibility,
                "shard_id": "graph/default", "content_sha256": "f" * 64, "locator": "src/a.c:1", "complete": complete,
                "producing_cell_id": cell_id, "retrieval_receipt_sha256": None, "reason": None}
    return {**document, **({"provenance": provenance} if provenance else {})}


def cells(**roles):
    return {cell_id: [{"cell_id": cell_id, "lane": "lead", "package_id": "pkg", "role": role, "persona": None,
                       "stack_profile": None, "task": "task", "claim_id": "C1", "status": "succeeded", "attempts": 1,
                       "gap_ids": [], "receipt_sha256": "9" * 64}] for cell_id, role in roles.items()}


CELLS = cells(blue=BLUE, verifier=VERIFIER, judge=JUDGE, red=RED)


@pytest.mark.parametrize(("relations", "expected"), [
    ([relation("blue")], ("blue", None)),
    ([relation("verifier")], ("verifier", None)),
    ([relation("verifier"), relation("blue", GUARD)], ("blue", None)),
    ([relation("judge", provenance="adjudication_judge")], ("unattributed", "no_counted_contradiction")),
    ([relation("blue", CONFIG)], ("unattributed", "no_counted_contradiction")),
    ([relation("blue"), relation("red", kind="supports")], ("unattributed", "no_counted_contradiction")),
    ([relation("blue", complete=False)], ("unattributed", "no_counted_contradiction")),
    ([relation("blue", admissibility="analyst_assessed")], ("unattributed", "no_counted_contradiction")),
    ([relation("blue", kind="qualifies")], ("unattributed", "no_counted_contradiction")),
    ([], ("unattributed", "no_counted_contradiction")),
    ([relation("ghost")], ("unattributed", "producer_role_unknown")),
    ([relation("red")], ("unattributed", "producer_role_unknown")),
], ids=["blue", "verifier", "both-names-blue", "judge-not-counted", "predicate-not-required", "also-supported",
        "incomplete", "not-direct", "qualifies", "no-relation", "unknown-cell", "red-cell"])
def test_a_dismissed_claim_takes_the_stage_of_its_counted_contradiction(relations, expected):
    assert claim_removal_stage(claim(), relations, CELLS) == expected


def test_a_configuration_scoped_claim_requires_the_configuration_predicate():
    scoped = claim(state="not_exploitable_in_observed_configuration", preconditions=["feature_flag_enabled"])
    assert claim_removal_stage(scoped, [relation("verifier", CONFIG)], CELLS) == ("verifier", None)


@pytest.mark.parametrize(("document", "reason"), [
    (claim(state="out_of_scope", row="adjudication-rules/1:r2_out_of_scope"), "out_of_scope_policy"),
    (claim(row=None), "deciding_row_not_recorded"),
    (claim(row="adjudication-rules/1:r7_insufficient_evidence"), "deciding_row_not_recorded"),
    (claim(state="not_reachable", state_history=[{"to_state": "contradicted", "reason": ROW}]),
     "deciding_row_not_recorded"),
    (claim(preconditions=["not a precondition"]), "claim_unreadable"),
    ({key: value for key, value in claim().items() if key != "affected_entities"}, "claim_unreadable"),
], ids=["scope-policy", "no-history", "other-row", "history-of-another-state", "bad-precondition", "missing-field"])
def test_what_the_projection_does_not_record_is_unattributed_with_its_reason(document, reason):
    assert reason in adapter.UNATTRIBUTED_REASONS
    assert claim_removal_stage(document, [relation("blue")], CELLS) == ("unattributed", reason)


def test_a_claim_that_was_not_dismissed_is_refused():
    with pytest.raises(ValueError, match="not in a dismissing state"):
        claim_removal_stage(claim(state="supported"), [], CELLS)


# ------------------------------------------------------------------------------ records from a run

def verified(tmp_path: Path, scenario: Scenario) -> dict:
    documents, code = triage_reduction.load_verified_documents(build_run(tmp_path, scenario))
    assert code is None
    return documents


def with_facts(documents: dict, *, relations=None, cell_roles=None, rows=None) -> dict:
    """The verified documents with projection tables the hash-bound fixture does not write."""
    documents = copy.deepcopy(documents)
    projection = documents["projection"]["document"]
    for item in projection["claims"]:
        full = claim(item["claim_id"], item["state"], row=(rows or {}).get(item["claim_id"], ROW))
        item.update({key: value for key, value in full.items() if key not in item or key == "state_history"})
    projection["relations"] = relations or {}
    projection["cells"] = {**projection["cells"], **cells(**(cell_roles or {}))}
    return documents


def test_every_disposition_and_stage_agrees_with_the_triage_reduction_section(tmp_path):
    scenario = mixed()
    scenario.leads += [Lead("L8", outcome="proposal"), Lead("L9", outcome="proposal")]
    scenario.claims += [Claim("C8", "out_of_scope", lead="L8"), Claim("C9", "contradicted", lead="L9")]
    run_root = build_run(tmp_path, scenario)
    documents, _ = triage_reduction.load_verified_documents(run_root)
    documents = with_facts(
        documents, cell_roles={"b1": BLUE, "v1": VERIFIER, "j1": JUDGE},
        relations={"C3": [relation("b1", claim_id="C3")], "C6": [relation("v1", claim_id="C6")],
                   "C9": [relation("j1", claim_id="C9", provenance="adjudication_judge")]})
    before = copy.deepcopy(documents)

    records, gaps = lead_records(LeadDocuments(documents, None))

    assert documents == before, "the verified documents are never mutated"
    by_id = {record["lead_id"]: record for record in records}
    assert [record["lead_id"] for record in records] == sorted(by_id)
    assert {lead_id: (row["disposition"], row["removed_stage"]) for lead_id, row in by_id.items()} == {
        "L1": ("survived_confirmed", None), "L2": ("survived_supported", None),
        "L3": ("dismissed_by_adjudication", "blue"), "L4": ("no_claim_raised", "red_no_proposal"),
        "L5": ("survived_confirmed", None),                 # its duplicate claim resolves to the confirmed C1
        "L6": ("dismissed_by_adjudication", "verifier"), "L7": ("unresolved", None),
        "L8": ("dismissed_by_adjudication", "unattributed"), "L9": ("dismissed_by_adjudication", "unattributed"),
        "N1": (None, None), "N2": (None, None), "N3": (None, None)}
    assert {row["removed_stage"] for row in records if row["removed_stage"]} <= set(TRIAGE_STAGES)
    assert by_id["N1"] == {"lead_id": "N1", "admitted": False, "disposition": None, "removed_stage": None,
                           "family": None, "scanner": None, "control_id": None}
    assert (by_id["L3"]["family"], by_id["L3"]["scanner"]) == ("sca", "osv")
    assert all(set(record) == set(triage.LEAD_FIELDS) for record in records)
    # a judge that sided with blue did not remove the lead: its relations are never counted
    assert gaps == ["dismissal_unattributed:no_counted_contradiction:1", "dismissal_unattributed:out_of_scope_policy:1"]

    section = triage_reduction.triage_reduction_metrics(run_root)
    admitted = [record for record in records if record["admitted"]]
    assert dict(Counter(record["disposition"] for record in admitted)) == {
        name: count for name, count in section["admitted_dispositions"].items() if count}
    assert len(admitted) == section["leads"]["admitted"]
    assert len(records) - len(admitted) == section["leads"]["not_admitted"]
    for field, table in (("family", section["by_family"]), ("scanner", section["by_scanner"])):
        for name, row in table.items():
            group = Counter(record["disposition"] for record in admitted if record[field] == name)
            assert {key: row[key] for key in triage_reduction.DISPOSITIONS} == {
                key: group.get(key, 0) for key in triage_reduction.DISPOSITIONS}
    # the records are exactly what the labelled triage metric validates
    assert triage.effectiveness(records, {})["admitted"] == section["leads"]["admitted"]


def test_a_dismissal_through_a_duplicate_chain_takes_the_canonical_claims_stage(tmp_path):
    scenario = Scenario(
        leads=[Lead("L1", outcome="proposal"), Lead("L2", outcome="proposal"), Lead("L3", outcome="proposal")],
        claims=[Claim("C1", "duplicate", lead="L1", duplicate_of="C2"), Claim("C2", "duplicate", duplicate_of="C3",
                                                                              lane="hunt"),
                Claim("C3", "not_reachable", lane="hunt"),
                Claim("C4", "contradicted", lead="L2"), Claim("C5", "contradicted", lead="L2"),
                Claim("C6", "contradicted", lead="L3"), Claim("C7", "duplicate", lead="L3", duplicate_of="C6")])
    documents = with_facts(
        verified(tmp_path, scenario), cell_roles={"b1": BLUE, "v1": VERIFIER},
        relations={"C3": [relation("v1", claim_id="C3")], "C4": [relation("b1", claim_id="C4")],
                   "C5": [relation("v1", claim_id="C5")], "C6": [relation("b1", GUARD, claim_id="C6")]})

    records, gaps = lead_records(LeadDocuments(documents, None))

    assert {record["lead_id"]: record["removed_stage"] for record in records} == {
        "L1": "verifier",          # C1 -> C2 -> C3, dismissed by the verifier's contradiction
        "L2": "unattributed",      # its two claims were dismissed by different stages
        "L3": "blue"}              # a claim and its own duplicate are one canonical claim
    assert gaps == ["dismissal_unattributed:claims_disagree:1"]


def test_integrity_gaps_of_the_accounting_are_named_and_unlinked_leads_have_no_family(tmp_path):
    scenario = Scenario(leads=[Lead("L1", packaged=False), Lead("L2", outcome="proposal")],
                        claims=[Claim("C2", "duplicate", lead="L2", duplicate_of="missing")])
    records, gaps = lead_records(LeadDocuments(verified(tmp_path, scenario), None, ("lead_locations_unavailable:x",)))

    assert [(row["lead_id"], row["disposition"], row["family"], row["scanner"]) for row in records] == [
        ("L1", "unresolved", None, None), ("L2", "unresolved", "sast", "semgrep")]
    assert gaps == ["lead_accounting_gap:duplicate_unresolved", "lead_accounting_gap:lead_package_unlinked",
                    "lead_locations_unavailable:x"]


def test_a_dismissed_claim_missing_from_the_projection_document_is_unattributed(tmp_path):
    documents = verified(tmp_path, Scenario(leads=[Lead("L1", outcome="proposal")],
                                            claims=[Claim("C1", "contradicted", lead="L1")]))
    documents = copy.deepcopy(documents)
    documents["projection"]["document"] = None

    records, gaps = lead_records(LeadDocuments(documents))

    assert records[0]["removed_stage"] == "unattributed"
    assert gaps == ["dismissal_unattributed:claim_unreadable:1"]


def test_unavailable_documents_are_null_records_with_a_named_gap_never_an_empty_list():
    assert lead_records(LeadDocuments(None)) == (None, ["lead_documents_unavailable"])
    assert lead_records(LeadDocuments(None, None, ("lead_documents_unavailable:lane_document_unavailable",))) == (
        None, ["lead_documents_unavailable:lane_document_unavailable"])


def test_the_lead_bound_is_enforced(tmp_path, monkeypatch):
    documents = verified(tmp_path, Scenario(leads=[Lead("L1", outcome="no_proposal"),
                                                   Lead("L2", outcome="no_proposal")]))
    monkeypatch.setattr(adapter, "MAX_LEADS", 1)
    with pytest.raises(ValueError, match="bounded number"):
        lead_records(LeadDocuments(documents))
    with pytest.raises(ValueError, match="bounded number"):
        adapter.label_leads_from_key(KEY, {"L1": at("net/parse.c", 5), "L2": at("net/parse.c", 6)})


def test_the_public_wrappers_leave_the_section_bytes_unchanged(tmp_path):
    """Pins the section the pre-refactor module (commit 20b3ed52) produced for these fixtures.

    When the public wrappers were added the whole section was compared byte for byte with that
    module on these and six more of the existing fixtures; the digests keep the result. ``sources``
    is left out: its handoff hash follows the repository configuration, not this module.
    """
    scenarios = {
        "mixed": (mixed(), "30921b0eef52fffb7a9fba71c604cbd17e4618552ee39a0f6de607e64f2f7af1"),
        "gaps": (Scenario(leads=[Lead("L1", outcome="no_proposal"), Lead("L2", outcome=None)],
                          leads_by_outcome={"proposal": 0, "no_proposal": 2, "blocked": 0, "unaccounted": 0},
                          review_incomplete=True), "658e12540d675f1409122aa7c93f03dee4173899daf2bf95d9fbf15e9c1ccdab"),
    }
    for name, (scenario, digest) in scenarios.items():
        section = triage_reduction.triage_reduction_metrics(build_run(tmp_path / name, scenario))
        body = {key: value for key, value in section.items() if key != "sources"}
        assert hashlib.sha256(canonical_json(body)).hexdigest() == digest, name


# ----------------------------------------------------------------------------------------- loader

def test_the_loader_names_the_first_unverifiable_document(tmp_path):
    documents = adapter.load_lead_documents(tmp_path / "runs" / "absent")
    assert documents == LeadDocuments(None, None, ("lead_documents_unavailable:review_handoff_unavailable",))


def test_the_loader_reads_the_verified_documents_and_names_missing_locations(tmp_path):
    run_root = build_run(tmp_path, Scenario(leads=[Lead("L1", outcome="no_proposal")]))

    documents = adapter.load_lead_documents(run_root)

    # the fixture run has no accepted index set, so lead locations are a named gap, not an empty map
    assert documents.locations is None
    assert documents.gaps == ("lead_locations_unavailable:accepted_index_unreadable",)
    assert lead_records(documents)[0] == [
        {"lead_id": "L1", "admitted": True, "disposition": "no_claim_raised", "removed_stage": "red_no_proposal",
         "family": "sast", "scanner": "semgrep", "control_id": None}]


# ----------------------------------------------------------------------------------------- labels

def entry(entry_id, kind, path, scope=(1, 40)):
    return KeyEntry(id=entry_id, kind=kind, path=path, cwe="CWE-121" if kind is EntryKind.DEFECT else None,
                    lines=(scope[0] + 5 if scope else 10,), scope=scope)


KEY = ScoringKey(corpus={"name": "unit"}, entries=(
    entry("d1", EntryKind.DEFECT, "net/parse.c"), entry("c2", EntryKind.CONTROL, "net/safe.c"),
    entry("c1", EntryKind.CONTROL, "net/safe.c", None), entry("c3", EntryKind.CONTROL, "net/parse.c", (30, 60))))


def at(path, start, end=None):
    return {"path": path, "start_line": start, "end_line": end or start}


def test_leads_are_labelled_from_the_key_by_location_only():
    locations = {"defect": at("net/parse.c", 12), "control": at("net/safe.c", 20), "whole-file": at("net/safe.c", 99),
                 "both": at("net/parse.c", 35, 45), "outside": at("net/parse.c", 70), "other": at("net/other.c", 12)}
    before = copy.deepcopy(locations)

    labels, controls = adapter.label_leads_from_key(KEY, locations)

    assert locations == before
    answer = {"source": "answer_key", "expected_severity": None, "disposition": None}
    assert labels == {"both": {"outcome": "true", **answer}, "control": {"outcome": "false", **answer},
                      "defect": {"outcome": "true", **answer}, "whole-file": {"outcome": "false", **answer}}
    # a lead inside a defect scope is a defect lead even where a control overlaps; several controls: first by id
    assert controls == {"control": "c1", "whole-file": "c1"}


@pytest.mark.parametrize(("locations", "message"), [
    ([], "must map a lead id"),
    ({"L1": at("/abs/parse.c", 1)}, "not target-relative"),
    ({"L1": {"path": "net/parse.c", "start_line": 0}}, "positive integers"),
    ({"L1": "net/parse.c:3"}, "must be an object"),
    ({"": at("net/parse.c", 1)}, "non-empty string"),
], ids=["not-a-map", "absolute-path", "line-zero", "not-an-object", "empty-id"])
def test_unusable_lead_locations_are_refused(locations, message):
    with pytest.raises(ValueError, match=message):
        adapter.label_leads_from_key(KEY, locations)


def test_an_answer_key_must_be_a_scoring_key():
    with pytest.raises(ValueError, match="ScoringKey"):
        adapter.label_leads_from_key({"entries": []}, {"L1": at("net/parse.c", 1)})


def test_with_controls_copies_records_and_refuses_unknown_fields():
    records = [{"lead_id": "L1", "admitted": False, "disposition": None, "removed_stage": None, "family": None,
                "scanner": None, "control_id": None}]
    assert adapter.with_controls(records, {"L1": "c1", "L9": "c2"})[0]["control_id"] == "c1"
    assert records[0]["control_id"] is None
    with pytest.raises(ValueError, match="unknown fields: note"):
        adapter.with_controls([{**records[0], "note": "x"}], {})


# ------------------------------------------------------------------------------------ run to inputs

def test_leads_and_labels_from_a_run_feed_the_paired_retention_and_removal(tmp_path):
    scenario = Scenario(
        leads=[Lead("L1", outcome="proposal"), Lead("L2", outcome="proposal"), Lead("L3", outcome="no_proposal"),
               Lead("L4", outcome="proposal"), Lead("L5", outcome="proposal"), Lead("N1", admitted=False)],
        claims=[Claim("C1", "confirmed", lead="L1"), Claim("C2", "contradicted", lead="L2"),
                Claim("C4", "contradicted", lead="L4"), Claim("C5", "supported", lead="L5")])
    documents = with_facts(verified(tmp_path, scenario), cell_roles={"b1": BLUE, "v1": VERIFIER},
                           relations={"C2": [relation("v1", claim_id="C2")], "C4": [relation("b1", claim_id="C4")]})
    locations = {"L1": at("net/parse.c", 10), "L2": at("net/parse.c", 20), "L3": at("net/parse.c", 25),
                 "L4": at("net/safe.c", 10), "L5": at("net/safe.c", 12), "N1": at("net/parse.c", 5),
                 "stray": at("net/parse.c", 6)}
    calls = []

    def loader(run_root):
        calls.append(run_root)
        return LeadDocuments(documents, locations, ("leads_without_location:0",))

    derived = adapter.leads_from_run(tmp_path / "runs" / "r1", key=KEY, loader=loader)

    assert calls == [tmp_path / "runs" / "r1"] and derived["gaps"] == ["leads_without_location:0"]
    assert "stray" not in derived["labels"], "a location without a lead record labels nothing"
    assert {row["lead_id"]: row["control_id"] for row in derived["leads"]} == {
        "L1": None, "L2": None, "L3": None, "L4": "c1", "L5": "c1", "N1": None}
    result = triage.effectiveness(derived["leads"], derived["labels"])
    assert (result["true_lead_retention"]["numerator"], result["true_lead_retention"]["denominator"]) == (1, 3)
    assert (result["false_lead_removal"]["numerator"], result["false_lead_removal"]["denominator"]) == (1, 2)
    assert result["true_leads_removed_by_stage"] == {**dict.fromkeys(TRIAGE_STAGES, 0), "verifier": 1,
                                                    "red_no_proposal": 1}
    assert result["false_leads_removed_by_stage"] == {**dict.fromkeys(TRIAGE_STAGES, 0), "blue": 1}
    assert result["control_false_positive_rate"]["value"] == 1.0 and result["true_leads_not_admitted"] == 1


def test_without_a_key_or_without_locations_there_are_no_labels():
    triage_documents = {"manifest": {"admission": [("L1", "not_admitted", "outside_admission_policy")],
                                     "lead_packages": {}},
                        "lane": {"lead_accounting": {}, "proposals": {}},
                        "projection": {"claims": {}, "cell_packages": {}, "document": {}}}
    unlabelled = adapter.leads_from_run(Path("r1"), loader=lambda _: LeadDocuments(triage_documents, {}))
    assert unlabelled["labels"] is None and unlabelled["gaps"] == [] and len(unlabelled["leads"]) == 1
    unlocated = adapter.leads_from_run(Path("r1"), key=KEY, loader=lambda _: LeadDocuments(triage_documents, None))
    assert unlocated["labels"] is None and unlocated["gaps"] == ["lead_locations_unavailable"]
    assert adapter.leads_from_run(Path("r1"), key=KEY, loader=lambda _: LeadDocuments(None)) == {
        "leads": None, "labels": None, "gaps": ["lead_documents_unavailable"]}
