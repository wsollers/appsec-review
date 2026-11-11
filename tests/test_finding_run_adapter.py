"""The adapter from an accepted run's documents to a finding snapshot (finding-metrics.md sections 3, 5.1).

The documents below have the shape of the real final report package rows
(``jobs.accepted_review.project_finding`` plus the gate's ``bucket``) and of the claim projection
(``review.ledger.claim_json``). Reading a real run is the integration test's job; the read boundary
here is the injected loader.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.observability.findings import run_adapter as adapter
from appsec_review.observability.findings.contracts import check_snapshot
from appsec_review.observability.findings.run_adapter import RunDocuments, findings_from_documents

CODE = "char b[8];\nstrcpy(b, p);\n"


def package(finding_id, claim_id, *, lane="lead", state="confirmed", severity="high", status="ship_blocking",
            judge=None, review_id="review-1", missing=(), distinct=True):
    return {"finding_package_id": finding_id, "claim_id": claim_id, "lane": lane, "state": state,
            "ship_block": {"status": status, "technical_severity": severity, "verifier_model_distinct": distinct,
                           "distinct_verification_required": True, "reasons": []},
            "judge_verdict": judge, "verification_review_id": review_id, "direct_evidence": ["rel-1"],
            "missing_predicates": list(missing), "gap_ids": [], "scores": [], "poc": None, "attack_chains": []}


def claim(claim_id, *, cwe="CWE-121", state="confirmed", duplicate_of=None, preconditions=("network_reachable",)):
    return {"claim_id": claim_id, "lane": "lead", "package_id": "pkg", "affected_entities": [],
            "weakness_cwe": cwe, "security_predicate": "memory_corruption", "preconditions": list(preconditions),
            "statement": "prose that never reaches a record", "state": state, "duplicate_of": duplicate_of,
            "origin_cell_ids": []}


def location(path="src/net/parse.c", start=10, end=11, code=CODE):
    return {"path": path, "start_line": start, "end_line": end, "function": None, "code": code}


def documents(*, report=None, claims=None, located=None, observations=(), identities=None, gaps=()):
    report = report or {"findings": [package("F1", "c1")], "verification_backlog": [], "withheld": []}
    located = located if located is not None else {
        "F1": {"locations": [location()], "citations": {"total": 1, "unresolved": 0}}}
    return RunDocuments(report=report, projection={"claims": claims if claims is not None else [claim("c1")]},
                        located=located, observations=observations, identities=identities or {}, gaps=tuple(gaps))


def test_a_report_package_becomes_one_finding_record():
    records, gaps = findings_from_documents(documents())
    assert gaps == []
    record = records[0]
    assert (record["finding_id"], record["claim_id"], record["lane"], record["state"], record["bucket"]) == (
        "F1", "c1", "lead", "confirmed", "findings")
    assert (record["weakness_cwe"], record["security_predicate"]) == ("CWE-121", "memory_corruption")
    assert (record["severity"], record["ship_block_status"]) == ("high", "ship_blocking")
    assert record["locations"] == [location()]
    assert record["citations"] == {"total": 1, "unresolved": 0}
    assert "statement" not in record and "prose" not in json.dumps(record)


def test_every_bucket_is_carried_and_records_are_ordered_by_finding_id():
    report = {"findings": [package("F2", "c2")],
              "verification_backlog": [package("F1", "c1", state="supported", status="needs_verification")],
              "withheld": [package("F3", "c3", severity=None, status="decision_pending")]}
    located = {name: {"locations": [location(start=line)], "citations": {"total": 1, "unresolved": 0}}
               for name, line in (("F1", 10), ("F2", 20), ("F3", 30))}
    records, _ = findings_from_documents(documents(report=report, located=located,
                                                   claims=[claim("c1"), claim("c2"), claim("c3")]))
    assert [(item["finding_id"], item["bucket"], item["severity"]) for item in records] == [
        ("F1", "verification_backlog", "high"), ("F2", "findings", "high"), ("F3", "withheld", None)]


def test_a_finding_without_a_resolved_location_is_a_named_gap_never_a_guess():
    report = {"findings": [package("F1", "c1"), package("F2", "c2")], "verification_backlog": [], "withheld": []}
    located = {"F1": {"locations": [location()], "citations": {"total": 1, "unresolved": 0}},
               "F2": {"locations": [], "citations": {"total": 2, "unresolved": 2}}}
    records, gaps = findings_from_documents(documents(report=report, located=located,
                                                      claims=[claim("c1"), claim("c2")]))
    assert [item["finding_id"] for item in records] == ["F1"]
    assert gaps == ["citation_unresolved:2", "finding_without_resolved_location:1"]


def test_unresolved_citations_are_counted_on_the_record_and_as_a_gap():
    located = {"F1": {"locations": [location()], "citations": {"total": 3, "unresolved": 1}}}
    records, gaps = findings_from_documents(documents(located=located))
    assert records[0]["citations"] == {"total": 3, "unresolved": 1} and gaps == ["citation_unresolved:1"]


@pytest.mark.parametrize("lane, observations, expected", [
    ("hunt", None, None),                                      # no observation index: unknown, not independent
    ("hunt", [], False),                                       # index present, nothing there
    ("hunt", [("src/net/parse.c", 13, 13)], True),             # exactly tolerance lines after the location
    ("hunt", [("src/net/parse.c", 14, 14)], False),            # tolerance + 1
    ("hunt", [("src/net/parse.c", 1, 8)], True),               # ends exactly tolerance lines before
    ("hunt", [("src/net/parse.c", 1, 7)], False),
    ("hunt", [("src/other.c", 10, 11)], False),                # another file
    ("lead", None, True),                                      # lane A is scanner-derived by construction
], ids=["hunt-unknown", "hunt-empty", "after-edge", "after-miss", "before-edge", "before-miss", "other-file",
        "lead"])
def test_scanner_backing_of_a_finding(lane, observations, expected):
    report = {"findings": [package("F1", "c1", lane=lane)], "verification_backlog": [], "withheld": []}
    records, gaps = findings_from_documents(documents(report=report, observations=observations))
    assert records[0]["scanner_backed"] is expected
    assert ("scanner_observations_unavailable" in gaps) is (observations is None)


def test_duplicate_claims_are_counted_on_the_claim_their_chain_ends_at():
    claims = [claim("c1"), claim("d1", state="duplicate", duplicate_of="d2"),
              claim("d2", state="duplicate", duplicate_of="c1"),
              claim("loop-a", state="duplicate", duplicate_of="loop-b"),
              claim("loop-b", state="duplicate", duplicate_of="loop-a"),
              claim("dangling", state="duplicate", duplicate_of="absent")]
    records, _ = findings_from_documents(documents(claims=claims))
    assert records[0]["duplicates_collapsed"] == 2          # broken and cyclic chains credit nothing


def test_actionability_and_verification_are_read_not_inferred():
    plain = findings_from_documents(documents())[0][0]
    assert plain["actionability"] == {"entry_to_sink_path": True, "preconditions": True, "remediation": None,
                                      "remediation_validated": None}
    assert plain["verification"] == {"verifier_overturned": None, "distinct_model": True}
    report = {"findings": [package("F1", "c1", missing=["source_to_sink_reachability"], review_id=None,
                                   judge={"verdict": "blue", "disagrees_with_state": True, "verdict_ids": []})],
              "verification_backlog": [], "withheld": []}
    other = findings_from_documents(documents(report=report, claims=[claim("c1", preconditions=())]))[0][0]
    assert other["actionability"]["entry_to_sink_path"] is False
    assert other["actionability"]["preconditions"] is None      # none stated is not "has no preconditions"
    assert other["verification"] == {"verifier_overturned": True, "distinct_model": None}


def test_a_package_whose_claim_is_absent_from_the_projection_keeps_null_weakness_and_names_the_gap():
    records, gaps = findings_from_documents(documents(claims=[]))
    assert records[0]["weakness_cwe"] is None and gaps == ["finding_claim_missing_from_projection:1"]


def test_locations_beyond_the_bound_are_truncated_with_a_gap():
    many = [location(start=line, end=line) for line in range(1, 66)]
    records, gaps = findings_from_documents(documents(
        located={"F1": {"locations": many, "citations": {"total": 65, "unresolved": 0}}}))
    assert len(records[0]["locations"]) == 64 and gaps == ["finding_locations_truncated:1"]
    exact = findings_from_documents(documents(
        located={"F1": {"locations": many[:64], "citations": {"total": 64, "unresolved": 0}}}))
    assert len(exact[0][0]["locations"]) == 64 and exact[1] == []


def test_loader_gaps_are_preserved():
    assert findings_from_documents(documents(gaps=["upstream_gap"]))[1] == ["upstream_gap"]


# --------------------------------------------------------------------------------- snapshot

def test_snapshot_from_run_binds_identities_and_names_missing_coverage(tmp_path):
    identities = {"configuration_sha256": "a" * 64, "guidance_sha256": "b" * 64, "model_sha256": None}
    calls = []

    def loader(run_root):
        calls.append(run_root)
        return documents(identities=identities)

    built = adapter.snapshot_from_run(tmp_path / "run-7", target_id="game", source_revision="c" * 40, loader=loader)
    assert calls == [tmp_path / "run-7"]
    assert check_snapshot(built) == built
    assert (built["run_id"], built["target_id"], built["source_revision"], built["stage"]) == (
        "run-7", "game", "c" * 40, "published")
    assert (built["configuration_sha256"], built["guidance_sha256"], built["model_sha256"]) == (
        "a" * 64, "b" * 64, None)
    assert built["reviewed_units"] is None and built["gaps"] == ["reviewed_units_not_supplied"]
    assert built["findings"][0]["fingerprint"]["basis"] == "code"


def test_snapshot_from_run_takes_supplied_coverage_and_annotation(tmp_path):
    def annotate(record):
        return {**record, "ownership": "engine", "component": "netcode"}

    plain = adapter.snapshot_from_run(tmp_path / "run-7", target_id="game", source_revision="c" * 40,
                                      loader=lambda _: documents())
    built = adapter.snapshot_from_run(
        tmp_path / "run-7", target_id="game", source_revision="c" * 40, loader=lambda _: documents(),
        reviewed_units={"src/net/parse.c": "d" * 64}, unreviewed_units={"src/x.c": "not_built"}, annotate=annotate)
    assert built["gaps"] == [] and built["reviewed_units"] == {"src/net/parse.c": "d" * 64}
    assert built["findings"][0]["ownership"] == "engine" and built["findings"][0]["component"] == "netcode"
    # Slice dimensions are not part of a finding's identity.
    assert built["findings"][0]["fingerprint"] == plain["findings"][0]["fingerprint"]


def test_snapshot_from_run_lets_a_loader_failure_surface(tmp_path):
    def loader(_run_root):
        raise RuntimeError("current accepted report is unavailable")

    with pytest.raises(RuntimeError, match="unavailable"):
        adapter.snapshot_from_run(tmp_path / "run-7", target_id="game", source_revision="c" * 40, loader=loader)


# -------------------------------------------------------------------------------- identities

def _write_configuration(run, resolved):
    configuration = run / "data" / "configuration"
    configuration.mkdir(parents=True)
    payload = json.dumps(resolved).encode()
    (configuration / "resolved.json").write_bytes(payload)
    (configuration / "manifest.json").write_text(
        json.dumps({"resolved_sha256": hashlib.sha256(payload).hexdigest()}), encoding="utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_run_identities_are_null_for_a_run_that_recorded_nothing(tmp_path):
    assert adapter.run_identities(tmp_path / "absent") == {
        "configuration_sha256": None, "guidance_sha256": None, "model_sha256": None}


def test_run_identities_read_the_frozen_configuration_guidance_and_models(tmp_path):
    run = tmp_path / "run-1"
    resolved = {"jobs": {"job_inference_security_review": {"settings": {
        "red": {"provider": "anthropic", "model": "model-a"},
        "off": {"provider": "anthropic", "model": "model-b", "enabled": False}}}}}
    digest = _write_configuration(run, resolved)
    (run / "data" / "guidance" / ("e" * 64)).mkdir(parents=True)
    (run / "data" / "guidance" / "scratch").mkdir()
    identities = adapter.run_identities(run)
    assert identities["configuration_sha256"] == digest
    assert identities["guidance_sha256"] is not None and identities["model_sha256"] is not None
    # The model identity follows the enabled models only.
    other = tmp_path / "run-2"
    resolved["jobs"]["job_inference_security_review"]["settings"]["off"]["model"] = "model-c"
    _write_configuration(other, resolved)
    assert adapter.run_identities(other)["model_sha256"] == identities["model_sha256"]
    third = tmp_path / "run-3"
    resolved["jobs"]["job_inference_security_review"]["settings"]["red"]["model"] = "model-z"
    _write_configuration(third, resolved)
    assert adapter.run_identities(third)["model_sha256"] != identities["model_sha256"]


def test_a_configuration_that_no_longer_matches_its_manifest_is_no_identity(tmp_path):
    run = tmp_path / "run-1"
    _write_configuration(run, {"jobs": {}})
    (run / "data" / "configuration" / "resolved.json").write_bytes(b'{"jobs": {"changed": {}}}')
    identities = adapter.run_identities(run)
    assert identities["configuration_sha256"] is None and identities["model_sha256"] is None
