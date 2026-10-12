from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
import pytest
from referencing import Registry, Resource

from appsec_review.retrieval.model import EntityKind
from appsec_review.review import models
from appsec_review.review.accounting import PoolOutcome, exact_accounting
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.ledger import EventKind, EvidenceRequestOutcome, merge_shards, project
from tests.review.test_ledger import cell_id, entity, write_sample

ROOT = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "inference-security-review"
NAMES = ("common", "ledger-event", "claim", "evidence-relation", "cell-record", "gap", "worker-turn", "red-result",
         "blue-result", "verifier-result", "adjudication", "score-package", "finding-package", "handoff")
SCHEMAS = {name: json.loads((ROOT / f"{name}.schema.json").read_text()) for name in NAMES}
REGISTRY = Registry().with_resources(
    (schema["$id"], Resource.from_contents(schema)) for schema in SCHEMAS.values())
DEFS = SCHEMAS["common"]["$defs"]


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(SCHEMAS[name], registry=REGISTRY)


def valid(name: str, document: object) -> bool:
    return validator(name).is_valid(document)


def ident(kind: str, name: str = "x") -> str:
    return make_id(kind, 1, {"name": name})


SHA = sha256_hex("x")


def test_schema_set_is_exactly_the_contract_set() -> None:
    assert {path.name for path in ROOT.glob("*.schema.json")} == {f"{name}.schema.json" for name in NAMES}


@pytest.mark.parametrize("name", NAMES)
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    schema = SCHEMAS[name]
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith(f"/inference-security-review/{name}.schema.json")


def _objects(node: object):
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            yield node
        for value in node.values():
            yield from _objects(value)
    elif isinstance(node, list):
        for value in node:
            yield from _objects(value)


def _refs(node: object):
    if isinstance(node, dict):
        if "$ref" in node:
            yield node["$ref"]
        for value in node.values():
            yield from _refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _refs(value)


@pytest.mark.parametrize("name", NAMES)
def test_objects_closed_strings_and_arrays_bounded(name: str) -> None:
    schema = SCHEMAS[name]
    for node in _objects(schema):
        assert node["additionalProperties"] is False
    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "string":
                assert {"maxLength", "pattern", "enum", "const"} & set(node), node
            if node.get("type") == "array":
                assert "maxItems" in node, node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(schema)
    for ref in _refs(schema):
        target, _, pointer = ref.partition("#")
        assert not target.startswith(("http", "/")), ref
        document = SCHEMAS[target.removesuffix(".schema.json")] if target else schema
        for part in filter(None, pointer.split("/")):
            document = document[part]


@pytest.mark.parametrize("definition,enum", [
    ("lane", models.Lane), ("role", models.Role), ("blue_task", models.BlueTask),
    ("hunt_strategy", models.HuntStrategy), ("claim_state", models.ClaimState), ("predicate", models.Predicate),
    ("relation_kind", models.RelationKind), ("admissibility", models.Admissibility),
    ("cell_status", models.CellStatus), ("gap_class", models.GapClass), ("event_kind", EventKind),
    ("evidence_request_outcome", EvidenceRequestOutcome), ("pool_outcome", PoolOutcome),
    ("entity_kind", EntityKind)])
def test_enums_match_python_contract(definition: str, enum) -> None:
    assert DEFS[definition]["enum"] == [member.value for member in enum]


def test_derived_vocabularies_are_subsets() -> None:
    assert set(DEFS["evidence_relation_kind"]["enum"]) <= set(DEFS["relation_kind"]["enum"])
    assert set(DEFS["predicate_citations"]["properties"]) == {member.value for member in models.Predicate}
    for count in ("claims_by_state", "cells_by_status", "gaps_by_class"):
        assert DEFS[count]["required"] == list(DEFS[count]["properties"])
    verifier = SCHEMAS["verifier-result"]["properties"]["proposed_disposition"]["enum"]
    assert set(verifier) <= set(DEFS["claim_state"]["enum"])
    assert set(SCHEMAS["adjudication"]["properties"]["new_state"]["$ref"].split("/")[-1:]) == {"claim_state"}


def test_ledger_events_and_projection_records_validate(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    merged = merge_shards(paths)
    events = validator("ledger-event")
    for event in merged.events:
        events.validate(event)
    projection = project(merged.events)
    for record in projection.to_json()["claims"]:
        validator("claim").validate(record)
    tampered = copy.deepcopy(next(event for event in merged.events if event["kind"] == "claim_proposed"))
    tampered["body"]["claim"]["state"] = "confirmed"
    assert not events.is_valid(tampered)
    tampered = copy.deepcopy(merged.events[0])
    tampered["kind"] = "claim_proposed"
    assert not events.is_valid(tampered)


def _claim() -> dict:
    """Design "Schema sketches" claim example, adapted to the final field names."""
    return {
        "schema": "appsec-review/claim/1", "claim_id": ident("claim"), "lane": "lead", "package_id": "package-1",
        "state": "confirmed",
        "statement": "A bounded request path reaches a fixed-size copy without a length guard.",
        "affected_entities": [entity("span")], "weakness_cwe": "CWE-120",
        "security_predicate": "memory_corruption", "preconditions": ["attacker_controls_request_field"],
        "duplicate_of": None, "origin_cell_ids": [cell_id("red")],
        "proof_obligations": [
            {"predicate": "source_to_sink_reachability", "status": "satisfied", "evidence": [ident("evidence_relation", "51")]},
            {"predicate": "missing_or_ineffective_guard", "status": "satisfied", "evidence": [ident("evidence_relation", "c2")]}],
        "relations": {"supports": [ident("evidence_relation", "51"), ident("evidence_relation", "c2")],
                      "contradicts": [], "qualifies": []},
        "verification_review_id": ident("review"),
        "round_history": [ident("adjudication", "a1"), ident("adjudication", "b4")],
    }


def _score() -> dict:
    return {
        "schema": "appsec-review/score-package/2", "score_id": ident("score"), "claim_id": ident("claim"),
        "adjudication_id": ident("adjudication"),
        "provider": {"id": "cvss_v4", "interface": "appsec-review/scoring-provider/1", "implementation": "first-compatible/1"},
        "provider_config_sha256": SHA, "policy_sha256": SHA,
        "native": {"nomenclature": "CVSS-B", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                   "score": 9.3, "rating": "CRITICAL"},
        "native_result_sha256": SHA,
        "technical_severity": {"scale": "cvss_v4", "rating": "CRITICAL", "value": 9.3},
        "exploitability_confidence": {"scale": "evidence_confidence/1", "rating": "high"},
        "environmental_business_impact": None, "remediation_priority": None,
        "assumptions": ["deployed route matches accepted configuration shard"],
        "missing_factors": ["business_asset_criticality"],
        "evidence_relations": [ident("evidence_relation", "51"), ident("evidence_relation", "c2")],
        "factor_citations": [{"factor": "taint_path", "evidence_relations": [ident("evidence_relation", "c2")],
                              "entities": ["asr:dataflow_path:" + SHA], "tag_assignments": [], "references": []}],
        "factors": [{"factor": "taint_path", "scale": "score-factors/1:taint_path", "value": "graph_dataflow_path",
                     "detail": {"entity_kind": ["dataflow_path"]}}],
        "missing_factor_reasons": [{"factor": "business_asset_criticality", "reason": "no deployment data"}],
        "limitations": [], "scorer": ident("actor", "scorer"),
        "input_fingerprint": SHA, "overrides": [],
    }


def test_score_package_2_rejects_version_1_and_malformed_factors() -> None:
    assert not valid("score-package", {**_score(), "schema": "appsec-review/score-package/1"})
    factor = _score()["factors"][0]
    assert not valid("score-package", {**_score(), "factors": [{**factor, "detail": {"entity_kind": "dataflow_path"}}]})
    assert not valid("score-package", {**_score(), "factors": [{**factor, "points": 3}]})
    citation = _score()["factor_citations"][0]
    assert not valid("score-package", {**_score(), "factor_citations": [{**citation, "evidence_relations": ["x"]}]})
    assert not valid("score-package", {**_score(), "missing_factor_reasons": [{"factor": "threat"}]})


def _finding() -> dict:
    return {
        "schema": "appsec-review/finding-package/1", "finding_package_id": ident("finding_package"),
        "claim_id": ident("claim"), "state": "confirmed", "label": "confirmed",
        "title": "Unbounded copy on the accepted request path", "adjudication_id": ident("adjudication"),
        "direct_evidence": [ident("evidence_relation", "51"), ident("evidence_relation", "c2")],
        "verification_review_id": ident("review"), "scores": [ident("score"), ident("score", "matrix")],
        "poc": {"status": "verification_succeeded", "result_id": "pocresult-" + SHA},
        "attack_chains": ["chain-" + SHA], "remediation_inputs": {"safe_regression_artifact": "regression-" + SHA},
        "independence": {"independent": True, "provider_distinct": False},
        "gaps": [ident("gap")], "provenance": {"run_manifest_sha256": SHA, "ledger_head_sha256": SHA},
    }


@pytest.mark.parametrize("name,build", [("claim", _claim), ("score-package", _score), ("finding-package", _finding)])
def test_design_examples_validate_and_extra_fields_are_rejected(name: str, build) -> None:
    document = build()
    validator(name).validate(document)
    assert not valid(name, {**document, "extra": True})
    missing = dict(document)
    missing.pop(next(key for key in SCHEMAS[name]["required"] if key != "schema"))
    assert not valid(name, missing)


def test_claim_and_finding_conditionals() -> None:
    assert not valid("claim", {**_claim(), "state": "duplicate"})
    assert valid("claim", {**_claim(), "state": "duplicate", "duplicate_of": ident("claim", "other")})
    assert not valid("claim", {**_claim(), "state": "severe"})
    assert not valid("claim", {**_claim(), "weakness_cwe": "120"})
    assert not valid("finding-package", {**_finding(), "label": "not_independently_confirmed"})
    assert valid("finding-package", {**_finding(), "state": "supported", "label": "not_independently_confirmed",
                                     "verification_review_id": None})
    assert not valid("finding-package", {**_finding(), "verification_review_id": None})


def _citations() -> dict:
    return {"affected_construct": [entity("span")], "source_to_sink_reachability": [entity("trace")]}


def _red() -> dict:
    return {"schema": "appsec-review/red-result/1", "claims": [{
        "claim_ref": "c1", "affected_entities": [entity("span")], "weakness_cwe": "CWE-120",
        "security_predicate": "memory_corruption", "preconditions": ["attacker_controls_request_field"],
        "statement": "copy without bound", "citations": _citations(),
        "proposed_relations": [{"predicate": "affected_construct", "kind": "supports", "entity_id": entity("span"),
                                "rationale": "the copy"}],
        "evidence_requests": [{"predicate": "configuration_enables", "requested_kind": "build_action",
                               "anchors": [entity("span")], "question": "is the guard compiled in?"}]}]}


def test_red_result_cannot_set_state_or_severity() -> None:
    validator("red-result").validate(_red())
    for forbidden in ("state", "severity", "confirmed", "priority", "exploitability"):
        document = _red()
        document["claims"][0][forbidden] = "confirmed"
        assert not valid("red-result", document)
    document = _red()
    document["claims"][0]["citations"]["not_a_predicate"] = []
    assert not valid("red-result", document)
    document = _red()
    document["claims"][0]["citations"]["affected_construct"] = ["src/a.c"]
    assert not valid("red-result", document)


def test_blue_verifier_and_adjudication_results() -> None:
    common = {"claim_id": ident("claim"), "citations": _citations(), "proposed_relations": [],
              "evidence_requests": [], "rationale": "bounded"}
    blue = {"schema": "appsec-review/blue-result/1", **common, "task": "blue_control", "disposition": "contradicts"}
    validator("blue-result").validate(blue)
    assert not valid("blue-result", {**blue, "task": "blue_everything"})
    assert not valid("blue-result", {**blue, "state": "contradicted"})
    verifier = {"schema": "appsec-review/verifier-result/1", **common, "proposed_disposition": "confirmed"}
    validator("verifier-result").validate(verifier)
    assert not valid("verifier-result", {**verifier, "proposed_disposition": "duplicate"})
    assert not valid("verifier-result", {**verifier, "red_actor_id": ident("actor")})
    adjudication = {
        "schema": "appsec-review/adjudication/1", "adjudication_id": ident("adjudication"), "claim_id": ident("claim"),
        "round": 0, "prior_state": "proposed", "new_state": "supported", "rule": "supported", "duplicate_of": None,
        "predicates": [{"predicate": "affected_construct", "required": True, "status": "supported",
                        "support": [ident("evidence_relation")], "contradict": []}],
        "independence": {"verifier_actor_id": ident("actor"), "independent": False, "provider_distinct": False,
                         "reasons": ["no_independent_support"]},
        "gap_ids": [], "policy_sha256": SHA}
    validator("adjudication").validate(adjudication)
    assert not valid("adjudication", {**adjudication, "rule": "majority_vote"})


def test_worker_turn_retrieve_or_final() -> None:
    turn = validator("worker-turn")
    turn.validate({"action": "retrieve", "requests": [
        {"tool": "search", "params": {"query": "memcpy", "limit": 10}},
        {"tool": "read_excerpt", "params": {"identity": entity("span"), "context_lines": 3}}]})
    turn.validate({"action": "final", "result": _red()})
    for bad in (
        {"action": "retrieve", "requests": []},
        {"action": "retrieve", "requests": [{"tool": "shell", "params": {"cmd": "ls"}}]},
        {"action": "retrieve", "requests": [{"tool": "search", "params": {"query": "x", "path": "/etc"}}]},
        {"action": "retrieve", "requests": [{"tool": "read_excerpt", "params": {}}]},
        {"action": "final", "result": {}, "requests": []},
        {"action": "think"},
    ):
        assert not turn.is_valid(bad), bad


def test_cell_record_and_gap() -> None:
    record = {"schema": "appsec-review/cell-record/1", "cell_id": cell_id("c"), "lane": "hunt",
              "package_id": "package-h", "role": "hypothesis_hunter", "persona": "memory_safety_native",
              "stack_profile": "cpp_rpc_service", "task": "sink_up", "claim_id": None, "status": "succeeded",
              "attempts": 1, "gap_ids": [], "receipt_sha256": SHA}
    validator("cell-record").validate(record)
    assert not valid("cell-record", {**record, "status": "failed"})
    assert valid("cell-record", {**record, "status": "failed", "gap_ids": [ident("gap")]})
    assert not valid("cell-record", {**record, "status": "not_launched", "gap_ids": [ident("gap")]})
    assert valid("cell-record", {**record, "status": "not_launched", "attempts": 0, "gap_ids": [ident("gap")]})
    gap = {"schema": "appsec-review/gap/1", "gap_id": ident("gap"), "gap_class": "budget_gap",
           "subject_id": "package-h", "reason": "below_hunt_cutoff", "predicate": None, "round": 0}
    validator("gap").validate(gap)
    assert not valid("gap", {**gap, "gap_class": "clean"})


def test_handoff_accepts_exact_accounting_only(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    projection = project(merge_shards(paths).events)
    expected = {cell_id("lead-1"): models.Lane.LEAD, cell_id("lead-2"): models.Lane.LEAD,
                cell_id("hunt-1"): models.Lane.HUNT}
    accounting = exact_accounting(projection, expected, {"package-a": models.Lane.LEAD, "package-h": models.Lane.HUNT},
                                  incomplete_gap_ratio=0.25)
    handoff = {
        "schema": "appsec-review/inference-review-handoff/1", "run_id": "run-1", "accepted_manifest_sha256": SHA,
        "status": "DEGRADED",
        "configuration_sha256": SHA, "ledger_head_sha256": projection.head, "projection_sha256": projection.sha256(),
        "accounting": accounting.to_json(), "shards": [{"path": "data/ledger/lead.jsonl", "schema":
                                                         "appsec-review/ledger-event/1", "sha256": SHA, "rows": 8}],
        "finding_packages": [], "score_packages": [], "gap_ids": [gap.gap_id for gap in projection.gaps]}
    assert accounting.exact and accounting.review_incomplete
    validator("handoff").validate(handoff)
    broken = exact_accounting(projection, {}, {}, incomplete_gap_ratio=0.25)
    assert not broken.exact
    with pytest.raises(ValidationError):
        validator("handoff").validate({**handoff, "accounting": broken.to_json()})
    assert not valid("handoff", {**handoff, "shards": [{"path": "../escape", "schema": "x", "sha256": SHA, "rows": 1}]})
    assert not valid("handoff", {**handoff, "status": "CLEAN"})
    assert accounting.to_json()["duplicate_proposals"] == 0
    assert all("duplicate_proposals" in lane for lane in accounting.to_json()["lanes"])
