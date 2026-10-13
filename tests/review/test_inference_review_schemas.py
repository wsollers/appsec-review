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
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.ship_block import ShipBlockStatus
from tests.review.test_ledger import cell_id, entity, write_sample

ROOT = Path(__file__).resolve().parents[2] / "docs" / "schemas" / "inference-security-review"
NAMES = ("common", "ledger-event", "claim", "evidence-relation", "cell-record", "gap", "worker-turn",
         "red-discovery-result", "blue-result", "verifier-result", "adjudication", "score-package", "finding-package", "handoff")
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
    ("security_predicate", models.SecurityPredicate),
    ("evidence_request_outcome", EvidenceRequestOutcome), ("pool_outcome", PoolOutcome),
    ("entity_kind", EntityKind), ("ship_block_status", ShipBlockStatus)])
def test_enums_match_python_contract(definition: str, enum) -> None:
    assert DEFS[definition]["enum"] == [member.value for member in enum]


def test_security_predicate_fields_use_the_closed_vocabulary() -> None:
    reference = "common.schema.json#/$defs/security_predicate"
    assert SCHEMAS["claim"]["properties"]["security_predicate"] == {"$ref": reference}
    proposal = SCHEMAS["red-discovery-result"]["$defs"]["proposal"]["properties"]
    assert proposal["security_predicate"] == {"$ref": reference}
    assert "red-result.schema.json" not in {path.name for path in ROOT.glob("*.schema.json")}
    assert models.SECURITY_PREDICATES_VERSION == "security-predicates/1"
    assert set(models.SECURITY_PREDICATE_CWE_ROLLUP.values()) <= set(models.SecurityPredicate)
    assert models.SecurityPredicate.OTHER not in set(models.SECURITY_PREDICATE_CWE_ROLLUP.values())


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


def _ship_block(status: str = "ship_blocking", state: str = "confirmed") -> dict:
    return {
        "policy": "ship-block-policy/1", "policy_sha256": SHA, "status": status,
        "conditions": {"claim_confirmed": state == "confirmed", "claim_supported": state == "supported",
                       "technical_severity_qualifies": True, "dependency_finding": False,
                       "kev_dependency_qualifies": False, "distinct_verification_required": True,
                       "verifier_model_distinct": True},
        "reasons": ["technical_severity_high"],
        "inputs": {"claim_state": state, "lead_families": ["codeql"], "kev_listed": None,
                   "verifier_model_distinct": True,
                   "technical_severity": {"provider": "application_risk_matrix/2", "rating": "high",
                                          "score_id": ident("score", "matrix")}},
        "citations": {"adjudication_id": ident("adjudication"), "score_ids": [ident("score", "matrix")],
                      "verification_review_id": ident("review")},
        "displayed_context": {"decides": False, "non_deciding_scores": [ident("score")],
                              "reference_cvss": [{"cve_id": "CVE-2026-0001", "version": "3.1",
                                                  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                  "base_score": 9.8}]},
    }


def _finding() -> dict:
    return {
        "schema": "appsec-review/finding-package/2", "finding_package_id": ident("finding_package"),
        "claim_id": ident("claim"), "lane": "lead", "state": "confirmed", "label": "confirmed",
        "title": "Unbounded copy on the accepted request path", "adjudication_id": ident("adjudication"),
        "direct_evidence": [ident("evidence_relation", "51"), ident("evidence_relation", "c2")],
        "missing_predicates": [],
        "verification_review_id": ident("review"), "scores": [ident("score"), ident("score", "matrix")],
        "poc": {"status": "verification_succeeded", "result_id": "pocresult-" + SHA},
        "attack_chains": ["chain-" + SHA], "remediation_inputs": {"safe_regression_artifact": "regression-" + SHA},
        "independence": {"independent": True, "provider_distinct": False, "verifier_model_distinct": True},
        "ship_block": _ship_block(),
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
    supported = {**_finding(), "state": "supported", "label": "not_independently_confirmed",
                 "verification_review_id": None, "missing_predicates": ["source_to_sink_reachability"],
                 "ship_block": _ship_block("needs_verification", "supported")}
    assert valid("finding-package", supported)
    assert not valid("finding-package", {**_finding(), "verification_review_id": None})


@pytest.mark.parametrize("state,status,ok", [
    ("confirmed", "ship_blocking", True),
    ("confirmed", "ship_blocking_pending_distinct_verification", True),
    ("confirmed", "not_ship_blocking", True),
    ("confirmed", "needs_verification", False),
    ("supported", "needs_verification", True),
    ("supported", "not_ship_blocking", True),
    ("supported", "ship_blocking", False),
    ("supported", "ship_blocking_pending_distinct_verification", False),
])
def test_finding_ship_block_status_matches_the_claim_state(state: str, status: str, ok: bool) -> None:
    document = {**_finding(), "state": state, "ship_block": _ship_block(status, state)}
    if state == "supported":
        document.update(label="not_independently_confirmed", verification_review_id=None)
    assert valid("finding-package", document) is ok
    # The job's closed validator agrees with jsonschema on the ship-block conditionals.
    assert (not SchemaSet(ROOT).errors("finding-package", document)) is ok


def test_finding_ship_block_record_is_closed_and_never_lets_cvss_decide() -> None:
    assert not valid("finding-package", {**_finding(), "ship_block": {**_ship_block(), "policy": "ship-block-policy/2"}})
    displayed = {**_ship_block()["displayed_context"], "decides": True}
    assert not valid("finding-package", {**_finding(), "ship_block": {**_ship_block(), "displayed_context": displayed}})
    inputs = copy.deepcopy(_ship_block()["inputs"])
    inputs["technical_severity"]["provider"] = "cvss_v4"
    assert not valid("finding-package", {**_finding(), "ship_block": {**_ship_block(), "inputs": inputs}})
    independence = {"independent": True, "provider_distinct": False}
    assert not valid("finding-package", {**_finding(), "independence": independence})
    assert not valid("finding-package", {**_finding(), "missing_predicates": ["security_impact"]})   # confirmed
    assert not valid("finding-package", {**_finding(), "schema": "appsec-review/finding-package/1"})


def _citations() -> dict:
    return {"affected_construct": [entity("span")], "source_to_sink_reachability": [entity("trace")]}


def _red() -> dict:
    return {
        "schema": "appsec-review/red-discovery-result/1", "package": {"basis_sha256": SHA},
        "role": "red_team_analyst", "round_id": "0", "result_status": "completed",
        "lead_accounting": [{"observation_id": entity("lead"), "outcome": "proposal", "proposal_ids": ["c1"],
                             "gap_ids": [], "reason": "developed"}],
        "proposals": [{
            "local_id": "c1", "source_lead_ids": [entity("lead")], "affected_entities": [entity("span")],
            "statement": "copy without bound", "mechanism": "strcpy into a fixed buffer",
            "weakness": {"namespace": "CWE", "id": "CWE-120"}, "security_predicate": "memory_corruption",
            "attacker_entry": {"entity_id": None, "control": "request field",
                               "preconditions": ["attacker_controls_request_field"]},
            "trigger": "send a long field", "suspected_consequence": "stack overwrite", "assumptions": [],
            "evidence_ids": ["e1"], "counterevidence_ids": [], "obligation_ids": [], "taint_path_ids": []}],
        "proof_obligations": [], "taint_paths": [], "chain_seeds": [],
        "evidence_refs": [{"local_id": "e1", "entity_id": entity("span"), "shard_id": None, "shard_sha256": None,
                           "relation": "supports", "predicate": "affected_construct",
                           "locator": {"kind": "unresolved", "reason": "re-resolved by the validator"}}],
        "evidence_requests": [{"local_id": "r1", "proposal_id": "c1", "predicate": "configuration_enables",
                               "requested_kind": "build_provenance", "scope_entity_ids": [entity("span")],
                               "reason": "is the guard compiled in?"}],
        "gaps": []}


def test_red_discovery_result_cannot_set_state_or_severity() -> None:
    validator("red-discovery-result").validate(_red())
    for forbidden in ("state", "severity", "confirmed", "priority", "exploitability"):
        document = _red()
        document["proposals"][0][forbidden] = "confirmed"
        assert not valid("red-discovery-result", document)
    for field, value in (("security_predicate", "unbounded_copy"), ("weakness", {"namespace": "CWE", "id": "120"})):
        document = _red()
        document["proposals"][0][field] = value
        assert not valid("red-discovery-result", document)
    document = _red()
    document["evidence_refs"][0]["predicate"] = "reachability"
    assert not valid("red-discovery-result", document)
    document = _red()
    document["proposals"][0]["affected_entities"] = ["src/a.c"]
    assert not valid("red-discovery-result", document)
    document = _red()
    document["package"]["run_id"] = "run-1"
    assert not valid("red-discovery-result", document)


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


def _handoff_review_fields(intake=(), backlog=()) -> dict:
    from appsec_review.jobs.job_inference_security_review.datasets import PLANNED_CONSUMERS
    from appsec_review.review.ship_block import summarize

    rows = [*intake, *backlog]
    return {"remediation_intake": list(intake), "verification_backlog": list(backlog),
            "ship_block": {**summarize({"lane": row["lane"], "status": row["ship_block_status"]} for row in rows),
                           "policy_sha256": SHA},
            "verification": {"require_distinct_model_for_ship_blocking": True,
                             "verifier": {"provider": "claude-cli", "model": "claude-haiku-5-5"},
                             "red": {role: {"provider": "claude-cli", "model": "claude-haiku-5-5"}
                                     for role in ("hypothesis_hunter", "red_team_analyst")},
                             "distinct": False, "warning": "same model"},
            "planned_consumers": [dict(item) for item in PLANNED_CONSUMERS]}


def test_handoff_partitions_remediation_intake_from_the_verification_backlog(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    projection = project(merge_shards(paths).events)
    expected = {cell_id("lead-1"): models.Lane.LEAD, cell_id("lead-2"): models.Lane.LEAD,
                cell_id("hunt-1"): models.Lane.HUNT}
    accounting = exact_accounting(projection, expected, {"package-a": models.Lane.LEAD, "package-h": models.Lane.HUNT},
                                  incomplete_gap_ratio=0.25)
    confirmed = {"finding_package_id": ident("finding_package", "c"), "sha256": SHA, "claim_id": ident("claim", "c"),
                 "lane": "lead", "ship_block_status": "ship_blocking_pending_distinct_verification"}
    supported = {"finding_package_id": ident("finding_package", "s"), "sha256": SHA, "claim_id": ident("claim", "s"),
                 "lane": "hunt", "ship_block_status": "needs_verification", "label": "unconfirmed",
                 "missing_predicates": ["source_to_sink_reachability"], "gap_ids": [ident("gap")]}
    handoff = {
        "schema": "appsec-review/inference-review-handoff/2", "run_id": "run-1", "accepted_manifest_sha256": SHA,
        "status": "DEGRADED", "configuration_sha256": SHA, "ledger_head_sha256": projection.head,
        "projection_sha256": projection.sha256(), "accounting": accounting.to_json(), "shards": [],
        "finding_packages": [{"finding_package_id": item["finding_package_id"], "sha256": SHA}
                             for item in (confirmed, supported)],
        "score_packages": [], "gap_ids": [gap.gap_id for gap in projection.gaps],
        **_handoff_review_fields([confirmed], [supported])}
    validator("handoff").validate(handoff)
    assert SchemaSet(ROOT).errors("handoff", handoff) == []
    assert handoff["ship_block"]["by_lane"]["hunt"]["needs_verification"] == 1
    # A supported package can never enter remediation intake, nor a confirmed one the backlog.
    assert not valid("handoff", {**handoff, "remediation_intake": [{**confirmed, "ship_block_status":
                                                                    "needs_verification"}]})
    assert not valid("handoff", {**handoff, "verification_backlog": [{**supported, "label": "confirmed"}]})
    assert not valid("handoff", {**handoff, "verification_backlog": [{**supported, "ship_block_status":
                                                                      "ship_blocking"}]})
    consumers = [{**item, "job_id": "job_remediation"} for item in handoff["planned_consumers"]]
    assert not valid("handoff", {**handoff, "planned_consumers": consumers})
    assert not valid("handoff", {key: value for key, value in handoff.items() if key != "remediation_intake"})
    assert not valid("handoff", {**handoff, "schema": "appsec-review/inference-review-handoff/1"})


def test_handoff_accepts_exact_accounting_only(tmp_path: Path) -> None:
    paths, _ = write_sample(tmp_path)
    projection = project(merge_shards(paths).events)
    expected = {cell_id("lead-1"): models.Lane.LEAD, cell_id("lead-2"): models.Lane.LEAD,
                cell_id("hunt-1"): models.Lane.HUNT}
    accounting = exact_accounting(projection, expected, {"package-a": models.Lane.LEAD, "package-h": models.Lane.HUNT},
                                  incomplete_gap_ratio=0.25)
    handoff = {
        "schema": "appsec-review/inference-review-handoff/2", "run_id": "run-1", "accepted_manifest_sha256": SHA,
        "status": "DEGRADED",
        "configuration_sha256": SHA, "ledger_head_sha256": projection.head, "projection_sha256": projection.sha256(),
        "accounting": accounting.to_json(), "shards": [{"path": "data/ledger/lead.jsonl", "schema":
                                                         "appsec-review/ledger-event/1", "sha256": SHA, "rows": 8}],
        "finding_packages": [], "score_packages": [], "gap_ids": [gap.gap_id for gap in projection.gaps],
        **_handoff_review_fields()}
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
