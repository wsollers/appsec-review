"""Manual integration tier: accepted producer -> retrieval -> family-specific prompt/card.

No live provider is needed. These composition/admission checks are deliberately separate from
units; they do not claim a complete build, confirmed finding, or successful remediation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.guidance.cards import review_admission, review_tool_catalog
from appsec_review.guidance.compose import compose_bundle, pin_bundle, render_prompt
from appsec_review.guidance.workers import publish_worker_guidance
from appsec_review.inference import ModelRequest, ReviewModelRequest
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import NativeInferenceBounds
from appsec_review.jobs.job_dependency_intelligence.native_inference_runtime import NativeProposer
from appsec_review.jobs.job_remediation_planning.model import guidance
from appsec_review.jobs.job_security_tagging.crosswalk import load_crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import load_vocabulary
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.capability import Authorized, AuthorityDenied, CellCapability
from appsec_review.storage import file_sha256
from tests.fixtures.inference_review.builder import build_accepted_index_set

ROOT = Path(__file__).resolve().parents[2]
MODEL = {"enabled": True, "provider": "offline", "model": "fixture", "reasoning": "high",
         "max_input_tokens": 32000, "max_output_tokens": 4000, "timeout_seconds": 10, "retries": 0}


@pytest.fixture
def admitted(tmp_path):
    fixture = build_accepted_index_set(tmp_path / "accepted")
    core = RetrievalCore(fixture.runs_dir, fixture.run_id)
    identity = fixture.ids["native/src/parse.c"]
    capability = CellCapability.issue(
        run_id=fixture.run_id, manifest_sha256=core.manifest_sha256, package_id="bounded-source",
        package_sha256="a" * 64, role="hypothesis_hunter", round=0, tools=("find", "read_excerpt"),
        indexes=("source",), entities=(identity,), max_queries=2, max_turns=3, page_size=5,
        max_depth=2, max_result_bytes=4096)
    decision = capability.authorize({"tool": "read_excerpt", "parameters": {"identity": identity}})
    assert isinstance(decision, Authorized)
    response = core.read_excerpt(**decision.parameters)
    assert response["results"] and not response["truncated"]
    source, error = core.read_source_lines(identity=identity)
    assert error is None and source
    assert isinstance(capability.authorize({"tool": "read_excerpt", "parameters": {
        "identity": fixture.ids["svc/api/handler.py"]}}), AuthorityDenied)
    return fixture, core, capability, source


@pytest.mark.parametrize("family", ["review", "dependency", "build", "remediation"])
def test_accepted_shard_retrieval_reaches_only_the_selected_worker_card(admitted, family):
    fixture, core, capability, source = admitted
    path = source["location"]["path"]
    sha = source["location"]["file_sha256"]
    assert path == "native/src/parse.c"
    assert sha == file_sha256(fixture.target / path)
    if family == "review":
        taxonomy = ROOT / "data" / "reference" / "taxonomy"
        vocabulary = load_vocabulary(taxonomy / "vocabulary.json", file_sha256(taxonomy / "vocabulary.json"))
        crosswalk = load_crosswalk(taxonomy / "crosswalk.json", file_sha256(taxonomy / "crosswalk.json"), vocabulary)
        bundle = compose_bundle(ROOT, role="hypothesis_hunter", persona="memory_safety_native",
            stack="cpp_native_service", task="sink_up", task_input={},
            capability={"granted_tools": list(capability.tools)}, vocabulary=vocabulary, crosswalk=crosswalk)
        pin_bundle(fixture.run_root, bundle)
        request = ReviewModelRequest("appsec-review/worker-turn/1", "hypothesis_hunter",
            "memory_safety_native", "cpp_native_service", bundle["sha256"], render_prompt(bundle),
            {"capability": capability.public_view(), "artifact_admission": review_admission(core, capability),
             "turn_protocol": {"tool_catalog": review_tool_catalog(capability.tools)}}, (),
            "offline", "fixture", "high", 32000, 4000)
    elif family == "dependency":
        proposer = NativeProposer(repository_root=ROOT, run_root=fixture.run_root, model=MODEL,
                                 infer=lambda *_a, **_k: pytest.fail("no provider dispatch"),
                                 bounds=NativeInferenceBounds())
        request, _, _ = proposer._request("metadata", {
            "candidate_id": "candidate-local", "files": [{"path": path, "sha256": sha,
                "lines": [{"line": index, "text": line} for index, line in enumerate(source["lines"], 1)]}]})
    elif family == "build":
        text, identity = publish_worker_guidance(ROOT, fixture.run_root, "build_planning",
                                                 family="native", model=MODEL, build_system="make")
        request = ModelRequest("appsec-review/target-analysis-proposal/3", "devops_engineer",
            "build_engineer_native", text,
            {"guidance_bundle_sha256": identity, "build_units": [{"build_unit_id": "native-main"}],
             "evidence_inventory": [{"path": path, "sha256": sha}], "feedback_limits": {"max_documents": 1}},
            (), ("make",), (), (path,), ("native-main",), "offline", "fixture", "high", 32000, 4000)
    else:
        text, identity = guidance(ROOT, fixture.run_root, "remediation_reviewer",
                                  job_id="job_remediation_validation")
        request = ReviewModelRequest("appsec-review/worker-turn/1", "remediation_reviewer", "", "",
            identity, text, {"task": {"source_files": [{"path": path, "sha256": sha,
                "text": "\n".join(source["lines"])}], "accepted_evidence": []}}, (),
            "offline", "fixture", "high", 32000, 4000)
        assert request.capability_artifact_card["datasets"][0]["availability"] == "not_supplied"
    card = request.capability_artifact_card
    assert card["guidance_bundle_sha256"]
    assert "svc/api/handler.py" not in json.dumps(card)
    assert "strcpy" not in json.dumps(card)
    if family != "review":
        assert card["scope"]["paths"] == [path]
    assert card["coverage"]["absence_is_not_evidence"] is True


def test_changed_accepted_source_is_not_relabelled_as_available(admitted):
    fixture, core, capability, _ = admitted
    (fixture.target / "native/src/parse.c").write_text("changed after acceptance\n")
    source, error = core.read_source_lines(identity=capability.entities[0])
    assert source is None and error
