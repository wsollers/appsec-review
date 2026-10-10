"""Structural contract for untrusted red-pool proposals."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest


SCHEMA_PATH = (Path(__file__).parents[1] / "docs" / "schemas" /
               "inference-security-review" / "red-discovery-result.schema.json")
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
LEAD = "asr:tool_observation:" + "1" * 64
SOURCE = "asr:source_file:" + "2" * 64


def _result() -> dict:
    return {
        "schema": "appsec-review/red-discovery-result/1",
        "package": {"run_id": "2026-10-10-0001", "manifest_sha256": "a" * 64,
                    "package_id": "hunt-example", "package_sha256": "b" * 64},
        "role": "red_team_analyst", "round_id": "1", "result_status": "partial",
        "lead_accounting": [{"observation_id": LEAD, "outcome": "proposal",
                             "proposal_ids": ["proposal1"], "gap_ids": [],
                             "reason": "A bounded path merits independent review"}],
        "proposals": [{"local_id": "proposal1", "source_lead_ids": [LEAD],
                       "affected_entities": [SOURCE],
                       "statement": "A request value may reach a security-sensitive operation",
                       "mechanism": "unchecked value propagation",
                       "security_predicate": "untrusted value reaches the operation without an effective guard",
                       "attacker_entry": {"entity_id": SOURCE, "control": "request field",
                                          "preconditions": ["route is enabled"]},
                       "trigger": "invoke the accepted request path",
                       "suspected_consequence": "unauthorized state change",
                       "assumptions": ["deployment selects this build unit"],
                       "evidence_ids": ["ev1"], "counterevidence_ids": [],
                       "obligation_ids": ["ob1"], "taint_path_ids": ["path1"]}],
        "proof_obligations": [{"local_id": "ob1", "proposal_id": "proposal1",
                               "predicate": "guard_state", "question": "Is the guard effective?",
                               "candidate_evidence_ids": ["ev1"]}],
        "taint_paths": [{"local_id": "path1", "proposal_id": "proposal1",
                         "source_node": "source1", "sink_node": "sink1", "basis": "partial",
                         "nodes": [{"local_id": "source1", "role": "source", "entity_id": SOURCE,
                                    "description": "request value"},
                                   {"local_id": "sink1", "role": "sink", "entity_id": SOURCE,
                                    "description": "sensitive operation"}],
                         "edges": [{"from_node": "source1", "to_node": "sink1", "kind": "data",
                                    "basis": "analyst_hypothesis", "evidence_ids": ["ev1"],
                                    "open_question": "Confirm the intermediate call"}],
                         "gap_ids": ["gap1"]}],
        "chain_seeds": [{"local_id": "chain1", "objective": "reach protected state",
                         "steps": [{"local_id": "step1", "description": "control request value",
                                    "proposal_id": "proposal1", "prerequisite": "route reachable",
                                    "resulting_state": "value accepted", "entity_ids": [SOURCE]},
                                   {"local_id": "step2", "description": "invoke operation",
                                    "proposal_id": None, "prerequisite": "value reaches operation",
                                    "resulting_state": "protected state may change", "entity_ids": [SOURCE]}],
                         "links": [{"from_step": "step1", "to_step": "step2",
                                    "continuity_dimensions": ["identity", "temporal"],
                                    "evidence_ids": ["ev1"],
                                    "open_questions": ["Does the same value reach step 2?"]}],
                         "gap_ids": ["gap1"]}],
        "evidence_refs": [{"local_id": "ev1", "entity_id": SOURCE, "shard_id": "source-default",
                           "shard_sha256": "c" * 64, "relation": "nominates",
                           "predicate": "request value reaches the operation",
                           "locator": {"kind": "source_line", "path": "src/handler.c",
                                       "file_sha256": "d" * 64, "start_line": 10, "end_line": 12}}],
        "evidence_requests": [{"local_id": "request1", "proposal_id": "proposal1",
                               "predicate": "effective guard state", "requested_kind": "compiled_view",
                               "scope_entity_ids": [SOURCE], "reason": "Inspect expanded guard"}],
        "gaps": [{"local_id": "gap1", "kind": "unresolved", "scope": "source-to-sink path",
                  "reason": "intermediate call is not mapped"}]
    }


def test_red_result_schema_accepts_typed_proposal_and_path() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    VALIDATOR.validate(_result())


@pytest.mark.parametrize("mutate", [
    lambda value: value["proposals"][0].update({"state": "confirmed"}),
    lambda value: value["proposals"][0].update({"technical_severity": "critical"}),
    lambda value: value["chain_seeds"][0].update({"attack_chain_id": "chain-invented"}),
    lambda value: value["taint_paths"][0]["edges"][0].pop("basis"),
    lambda value: value["evidence_refs"][0]["locator"].update({"raw_source": "secret"}),
])
def test_red_result_schema_rejects_premature_conclusions_and_unbounded_content(mutate) -> None:
    result = deepcopy(_result())
    mutate(result)
    assert not VALIDATOR.is_valid(result)
