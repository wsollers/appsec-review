"""A3: bounded feedback -> accepted evidence -> publication/reproducibility.

AUTHORED - NOT RUN. R4/R6/R8/R11/R12: fake only the model/byte-reader boundary,
not proposal validation, evidence custody, planner merge, cache or accepted reader.
"""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json

import pytest

from appsec_review.config import PlanningFeedbackSettings
from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.jobs.build_topology import compile_build_topology
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PROPOSAL_SCHEMA, bounded_feedback, deterministic_plan, evidence_catalog,
    merge_proposal, summarize_catalog, validate_plan,
)
from appsec_review.storage import canonical_json
from tests.integration.test_build_topology_catalog_planner_publication import (
    SHARED_SOURCE, final_proposal, offline_reporting, run_pipeline,
)
from tests.integration.test_build_topology_consumers_recovery import native_action


NOTE = b"explicit synthetic additive input: retain exact CRLF bytes\r\n"


def feedback_inputs():
    unit = native_action()
    recipe = copy.deepcopy(unit["recipe"])
    unit["recipe"] = None
    texts = {doc["path"]: doc["content"].encode() for doc in unit["descriptor_package"]["documents"]}
    texts["extra.h"] = b"typedef unsigned long independent_word;\r\n"
    files = [{"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
             for path, raw in texts.items()]
    catalog = {
        "source_fingerprint": "independent-feedback-source", "catalog_handoff_sha256": "c" * 64,
        "files": files, "components": [], "projects": [], "build_files": [],
        "build_units": [unit], "gaps": [], "accepted_artifacts": [], "compile_databases": [],
    }
    request = ModelRequest(
        schema=PROPOSAL_SCHEMA, persona="synthetic acceptance viewpoint",
        role="bounded recipe proposer", guidance="synthetic proposal/3 test input",
        summary={"build_units": [unit]}, allowed_scanners=(), allowed_build_systems=("cmake",),
        allowed_components=(), allowed_paths=tuple(texts),
        allowed_build_units=(unit["build_unit_id"],), allowed_image_profiles=("native",),
        provider="offline-scripted", model="independent-acceptance/1", reasoning="low",
        max_input_tokens=32000, max_output_tokens=16000)
    final = {"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
             "build_recipes": [recipe], "hints": [], "abstentions": []}
    item = next(item for item in files if item["path"] == "extra.h")
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
        "path": item["path"], "sha256": item["sha256"], "reason": "exact independently offered source",
    }]}
    return catalog, request, final, need, texts


def feedback(tmp_path, responses, *, identity=None, read=None, request_change=None):
    catalog, request, _final, _need, texts = feedback_inputs()
    if request_change is not None:
        request = request_change(request)
    replies = iter(responses)
    calls = []

    def infer(current, *, timeout_seconds):
        assert 0 < timeout_seconds <= 300
        calls.append(current)
        reply = next(replies)
        if isinstance(reply, Exception):
            raise reply
        return ModelResult(reply)

    result = bounded_feedback(
        infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
        read_document=read or (lambda item, bound: texts[item["path"]][:bound + 1]),
        cache_root=tmp_path / "cache",
        identity=identity if identity is not None else {
            "environment": "ABSENT", "profiles": None, "rules": "independent-rules/1"})
    return result, calls


def test_real_feedback_round_publishes_exact_additive_bytes_and_preserves_dependency_graph(tmp_path):
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        if len(calls) == 1:
            offered = next(item for item in request.summary["evidence_inventory"]
                           if item["path"] == "server/note.txt")
            return ModelResult({
                "schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
                    "path": offered["path"], "sha256": offered["sha256"],
                    "reason": "resolve exact accepted additional source",
                }],
            })
        assert request.summary["evidence"] == [{
            "path": "server/note.txt", "sha256": hashlib.sha256(NOTE).hexdigest(),
            "content": NOTE.decode(),
        }]
        return ModelResult(final_proposal(request))

    _config, _target, _runner, _result, root, plan = run_pipeline(
        tmp_path, {**SHARED_SOURCE, "server/note.txt": NOTE}, infer=infer)
    assert len(calls) == 2 and plan["feedback"][0]["calls"] == 2
    assert plan["feedback"][0]["metrics"]["evidence_bytes"] == len(NOTE)
    assert plan["planning_evidence"] == [{
        "path": "server/note.txt", "sha256": hashlib.sha256(NOTE).hexdigest(), "content": NOTE.decode(),
    }]
    graph = plan["build_topology"]["executable_graph"]
    roots = {node["build_unit_id"]: node["root"] for node in graph["nodes"]}
    assert {(roots[e["producer_build_unit_id"]], roots[e["consumer_build_unit_id"]])
            for e in graph["edges"]} == {("shared", "server"), ("shared", "client")}
    pointer = json.loads((root / "data/jobs/job_target_analysis_plan/latest.json").read_bytes())
    claim = json.loads((root / pointer["handoff_path"]).with_name("claim.json").read_bytes())
    launch = json.loads(claim["orchestration"]["build_environment_contract"])
    assert launch == {key: plan["build_environment"][key] for key in launch}
    assert plan["build_environment"]["mode"] == "NOT_RUN"
    assert load_accepted_plan(root) == plan


def test_completed_feedback_cache_replays_identical_result_without_model_or_source_read(tmp_path):
    catalog, _request, final, need, texts = feedback_inputs()
    first, calls = feedback(tmp_path, [need, final])
    assert first["status"] == "ACCEPTED" and len(calls) == 2
    assert calls[-1].summary["evidence"] == first["documents"]
    again, replay_calls = feedback(
        tmp_path, [], read=lambda *_: pytest.fail("accepted cache does not reread target source"))
    assert again["cache_hit"] and again["calls"] == 0 and replay_calls == []
    assert first["proposal"] == again["proposal"] and first["documents"] == again["documents"]
    assert first["documents"][0]["content"].encode() == texts["extra.h"]
    original = copy.deepcopy(catalog)
    augmented = evidence_catalog(catalog, first["documents"])
    plan = deterministic_plan(augmented, summarize_catalog(
        augmented, max_items=100, max_bytes=65536, sample_per_prefix=10))
    plan["planning_evidence"] = first["documents"]
    merged = merge_proposal(plan, first["proposal"], augmented)
    validate_plan(merged, catalog)
    assert merged["build_topology"]["executable_graph"] == compile_build_topology(
        augmented["build_units"], source_fingerprint=catalog["source_fingerprint"])
    assert catalog == original


@pytest.mark.parametrize("axis", ["environment", "profiles", "rules"])
def test_changed_feedback_identity_misses_cache_and_does_not_consume_a_private_case(tmp_path, axis):
    _catalog, _request, final, _need, _texts = feedback_inputs()
    first, _calls = feedback(tmp_path, [final])
    identity = {"environment": "ABSENT", "profiles": None, "rules": "independent-rules/1"}
    identity[axis] = "independent-new-identity"
    second, calls = feedback(tmp_path, [final], identity=identity)
    assert not second["cache_hit"] and len(calls) == 1
    assert first["cache_key"] != second["cache_key"]


@pytest.mark.parametrize("mutation", ["foreign_path", "wrong_hash", "executable_request", "unoffered_path"])
def test_invalid_or_unoffered_evidence_is_repaired_without_reading_it(tmp_path, mutation):
    _catalog, _request, final, need, _texts = feedback_inputs()
    change_request = None
    if mutation == "foreign_path":
        need["requests"][0]["path"] = "../outside"
    elif mutation == "wrong_hash":
        need["requests"][0]["sha256"] = "f" * 64
    elif mutation == "executable_request":
        need["requests"][0]["command"] = ["execute", "untrusted-target"]
    else:
        change_request = lambda request: replace(
            request, allowed_paths=tuple(path for path in request.allowed_paths if path != "extra.h"))
    result, calls = feedback(
        tmp_path, [need, final], request_change=change_request,
        read=lambda *_: pytest.fail("rejected evidence cannot reach the source reader"))
    assert len(calls) == 2 and calls[1].repair_errors
    assert result["status"] == "ACCEPTED" and result["documents"] == []


@pytest.mark.parametrize("outcome", ["abstain", "timeout", "malformed"])
def test_partial_or_exhausted_feedback_names_gap_and_never_populates_complete_cache(tmp_path, outcome):
    _catalog, _request, final, _need, _texts = feedback_inputs()
    if outcome == "abstain":
        reply = {**final, "build_recipes": [], "abstentions": [{
            "build_unit_id": final["build_recipes"][0]["build_unit_id"],
            "reason": "selected toolchain source is not captured",
        }]}
    elif outcome == "timeout":
        reply = TimeoutError("synthetic model deadline")
    else:
        reply = {"schema": PROPOSAL_SCHEMA, "action": "final"}
    result, calls = feedback(tmp_path, [reply] * 4)
    assert result["status"] == ("PARTIAL" if outcome == "abstain" else "BUDGET_EXCEEDED")
    assert len(calls) == result["calls"] == (1 if outcome == "abstain" else 4)
    assert result["gap"] and not list((tmp_path / "cache").glob("*.json"))


def test_corrupt_completed_cache_changed_source_and_unexpected_bug_remain_hard_failures(tmp_path):
    _catalog, _request, final, need, _texts = feedback_inputs()
    result, _calls = feedback(tmp_path, [final])
    cache = tmp_path / "cache" / (result["cache_key"] + ".json")
    cache.write_bytes(b"{}")
    with pytest.raises(ValueError, match="cache identity"):
        feedback(tmp_path, [])
    with pytest.raises(ValueError, match="source identity changed"):
        feedback(tmp_path / "changed-source", [need], read=lambda *_: b"not accepted bytes")
    with pytest.raises(RuntimeError, match="independent unexpected provider bug"):
        feedback(tmp_path / "provider-bug", [RuntimeError("independent unexpected provider bug")])


def test_feedback_documents_change_source_evidence_not_model_authority_or_original_catalog(tmp_path):
    catalog, _request, final, need, _texts = feedback_inputs()
    original = canonical_json(catalog)
    result, _calls = feedback(tmp_path, [need, final])
    augmented = evidence_catalog(catalog, result["documents"])
    graph = compile_build_topology(augmented["build_units"], source_fingerprint=catalog["source_fingerprint"])
    before = canonical_json(graph)
    for hints in ([], graph["facts"], graph["facts"][:1], list(reversed(graph["facts"]))):
        assert canonical_json(compile_build_topology(
            augmented["build_units"], source_fingerprint=catalog["source_fingerprint"], hints=hints)) == before
    assert canonical_json(catalog) == original
    assert any(document["path"] == "extra.h"
               for document in augmented["build_units"][0]["descriptor_package"]["documents"])
