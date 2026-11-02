"""Functional tests for the real proposer with only the external Infer boundary faked."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.guidance.compose import GOVERNING_PATH, load_registry
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.inference import ModelOutputError, ModelResult
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import (
    CURATION_SCHEMA, METADATA_SCHEMA, PLAN_SCHEMA, NativeInferenceBounds, NativeInferenceError,
)
from appsec_review.jobs.job_dependency_intelligence.native_inference_runtime import (
    NativeProposer, make_proposer,
)
from appsec_review.observability.events import EventLog
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[1]
MODEL = {
    "enabled": True, "provider": "claude-cli", "model": "configured-model", "reasoning": "high",
    "max_input_tokens": 32768, "max_output_tokens": 8192, "timeout_seconds": 19, "retries": 0,
}
SCHEMAS = {"curate": CURATION_SCHEMA, "plan": PLAN_SCHEMA, "metadata": METADATA_SCHEMA}
METRICS = {"model_calls", "model_failures", "input_tokens", "output_tokens", "cache_tokens", "unknown_usage_calls"}


class FakeInfer:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, request, *, timeout_seconds):
        self.calls.append((request, timeout_seconds))
        if self.results:
            result = self.results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return ModelResult({"schema": request.schema}, input_tokens=11, output_tokens=7, cache_tokens=0)


def proposer(tmp_path, *, fake=None, model=None, bounds=None, root=ROOT, unit_id=None, events=None):
    return make_proposer(
        repository_root=root, run_root=tmp_path / "run", model=MODEL if model is None else model,
        infer=FakeInfer() if fake is None else fake, bounds=bounds or NativeInferenceBounds(),
        unit_id=unit_id, events=events,
    )


def documents(instance, name):
    return [json.loads((instance.run_root / ref["path"]).read_bytes())
            for ref in instance.artifacts if Path(ref["path"]).name == f"{name}.json"]


def copied_repository(tmp_path):
    root = tmp_path / "repository"
    shutil.copytree(ROOT / "pipeline", root / "pipeline")
    destination = root / "docs" / "schemas" / "retrieval-mcp-tools.json"
    destination.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "docs" / "schemas" / destination.name, destination)
    return root


@pytest.mark.parametrize("stage", SCHEMAS)
def test_routes_stage_schema_and_central_settings_without_tools(tmp_path, stage):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake)
    payload = {"candidate_id": "candidate-a", "files": ["vendor/sdk/include/version.h"]}
    answer = instance(stage, payload)
    request, timeout = fake.calls[0]
    assert isinstance(instance, NativeProposer)
    assert answer == {"schema": SCHEMAS[stage]}
    assert request.schema == SCHEMAS[stage]
    assert request.persona == "native_dependency_analyst" and request.role == "native_sbom_investigator"
    assert request.summary == {"stage": stage, "payload": payload,
                               "guidance_bundle_sha256": instance.guidance_hashes[0]}
    assert request.provider == MODEL["provider"] and request.model == MODEL["model"]
    assert request.reasoning == MODEL["reasoning"]
    assert request.max_input_tokens == MODEL["max_input_tokens"]
    assert request.max_output_tokens == MODEL["max_output_tokens"] and timeout == MODEL["timeout_seconds"]
    assert (request.allowed_scanners, request.allowed_build_systems, request.allowed_components,
            request.allowed_paths, request.allowed_build_units, request.allowed_image_profiles) == ((),) * 6
    assert request.repair_errors == () and request.prior_response is None


def test_guidance_is_exact_registered_pinned_and_shared_rules_occur_once(tmp_path):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake)
    for stage in SCHEMAS:
        instance(stage, {})
    assert len(instance.guidance_hashes) == 2
    assert fake.calls[1][0].guidance == fake.calls[2][0].guidance
    registry = load_registry(ROOT)
    skill = load_runtime_skill(ROOT, "native-sbom-investigation", job_id="job_dependency_intelligence")
    for digest in instance.guidance_hashes:
        directory = instance.run_root / "data" / "guidance" / digest
        manifest_bytes = (directory / "bundle.json").read_bytes()
        assert hashlib.sha256(manifest_bytes).hexdigest() == digest
        manifest = json.loads(manifest_bytes)
        assert manifest["registry_version"] == registry["version"]
        assert manifest["role_record"] == registry["roles"]["native_sbom_investigator"]
        assert manifest["persona_record"] == registry["personas"]["native_dependency_analyst"]
        assert manifest["files"]["skill.md"]["path"] == skill.path
        assert manifest["files"]["skill.md"]["sha256"] == skill.sha256
        for name, ref in manifest["files"].items():
            pinned = (directory / name).read_bytes()
            assert pinned == (ROOT / ref["path"]).read_bytes()
            assert hashlib.sha256(pinned).hexdigest() == ref["sha256"]
            assert len(pinned) == ref["size_bytes"]
    rules = (ROOT / GOVERNING_PATH).read_bytes().decode("utf-8")
    for request, _ in fake.calls:
        assert request.guidance.count(rules) == 1
        assert ".claude" not in request.guidance and ".agents" not in request.guidance
        assert "Repository Agent Guidance" not in request.guidance


def test_guidance_snapshot_does_not_change_after_source_edits_even_for_unused_stage(tmp_path):
    root = copied_repository(tmp_path)
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake, root=root)
    instance("curate", {})
    path = root / "pipeline" / "guidance" / "tasks" / "dependency-intelligence" / "native_metadata_investigation.md"
    path.write_text(path.read_text() + "\nSOURCE CHANGED AFTER FIRST CALL\n")
    instance("plan", {})
    instance("metadata", {})
    assert "SOURCE CHANGED" not in fake.calls[1][0].guidance
    assert fake.calls[1][0].guidance == fake.calls[2][0].guidance


def test_guidance_pin_tampering_fails_before_another_model_call(tmp_path):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake)
    instance("curate", {})
    path = instance.run_root / "data" / "guidance" / instance.guidance_hashes[0] / "role.md"
    path.write_text("changed bytes")
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {})
    assert caught.value.kind == "unavailable"
    assert len(fake.calls) == 1


@pytest.mark.parametrize("mutation", ["unregistered", "unauthorized", "development", "conflict"])
def test_guidance_registration_separation_and_conflicts_are_enforced(tmp_path, mutation):
    root = copied_repository(tmp_path)
    path = root / "pipeline" / "guidance" / "registry.json"
    registry = json.loads(path.read_bytes())
    if mutation == "unregistered":
        del registry["runtime_skills"]["native-sbom-investigation"]
    elif mutation == "unauthorized":
        registry["runtime_skills"]["native-sbom-investigation"]["jobs"] = ["job_project_build"]
    elif mutation == "development":
        registry["runtime_skills"]["native-sbom-investigation"]["path"] = ".claude/skills/docs-sync/SKILL.md"
    else:
        role = root / "pipeline" / "prompt-fragments" / "roles" / "native_sbom_investigator.md"
        role.write_text(role.read_text() + "\ngranted_tools: read_everything\n")
    path.write_bytes(canonical_json(registry))
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake, root=root)
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {})
    assert caught.value.kind == "unavailable"
    assert not fake.calls and not instance.metrics["model_calls"]


@pytest.mark.parametrize("model,transport", [
    ({**MODEL, "enabled": False}, FakeInfer()),
    (MODEL, None),
    ({key: value for key, value in MODEL.items() if key != "provider"}, FakeInfer()),
    ({**MODEL, "retries": -1}, FakeInfer()),
    ({**MODEL, "max_output_tokens": True}, FakeInfer()),
])
def test_disabled_missing_or_invalid_central_model_is_explicit_unavailable(tmp_path, model, transport):
    events = EventLog(tmp_path / "events.jsonl")
    instance = make_proposer(repository_root=ROOT, run_root=tmp_path / "run", model=model, infer=transport,
                             bounds=NativeInferenceBounds(), events=events, unit_id="dependency.unit")
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {})
    assert caught.value.kind == "unavailable"
    assert instance.metrics == dict.fromkeys(METRICS, 0)
    assert instance.artifacts == []
    event = json.loads(events.path.read_text().splitlines()[-1])
    assert event["event"] == "NATIVE_INFERENCE_FAILED" and event["kind"] == "unavailable"
    assert event["unit_id"] == "dependency.unit"


@pytest.mark.parametrize("payload,bounds", [
    ({"value": "a" * 65}, replace(NativeInferenceBounds(), field_bytes=64)),
    ({"value": "x" * 1000}, replace(NativeInferenceBounds(), max_payload_bytes=100)),
    ({"candidates": [{}, {}]}, replace(NativeInferenceBounds(), batch_candidates=1)),
    ({"input_records": [{}, {}]}, replace(NativeInferenceBounds(), batch_candidates=1)),
    ({"input_records": 2}, replace(NativeInferenceBounds(), batch_candidates=1)),
    ({"value": float("inf")}, NativeInferenceBounds()),
    ({1: "not-a-json-key"}, NativeInferenceBounds()),
])
def test_payload_bounds_fail_before_dispatch_without_truncating(tmp_path, payload, bounds):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake, bounds=bounds)
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", payload)
    assert caught.value.kind == "bounds"
    assert not fake.calls and instance.metrics["model_calls"] == 0


def test_summary_and_complete_request_token_bounds_are_enforced(tmp_path):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake, bounds=replace(NativeInferenceBounds(), max_payload_bytes=100))
    with pytest.raises(NativeInferenceError, match="summary"):
        instance("curate", {})
    instance = proposer(tmp_path, fake=fake, model={**MODEL, "max_input_tokens": 1})
    with pytest.raises(NativeInferenceError, match="token-derived"):
        instance("curate", {})
    assert not fake.calls


def test_string_field_bound_counts_utf8_bytes_and_accepts_exact_boundary(tmp_path):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake, bounds=replace(NativeInferenceBounds(), field_bytes=64))
    instance("curate", {"value": "\u00e9" * 32})
    assert fake.calls[0][0].summary["payload"]["value"] == "\u00e9" * 32
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {"value": "\u00e9" * 33})
    assert caught.value.kind == "bounds" and len(fake.calls) == 1


def test_exact_input_budget_boundary_includes_repair_and_guidance(tmp_path):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake)
    instance("curate", {})
    size = len(canonical_json(asdict(fake.calls[0][0])))
    tokens = (size + 3) // 4
    at_boundary = proposer(tmp_path / "boundary", model={**MODEL, "max_input_tokens": tokens})
    # Changing the limit's digit width is part of the serialized request.
    while True:
        request, _, _ = at_boundary._request("curate", {})
        needed = (len(canonical_json(asdict(request))) + 3) // 4
        if tokens == needed:
            break
        tokens = needed
        at_boundary.model["max_input_tokens"] = tokens
    assert at_boundary("curate", {})["schema"] == CURATION_SCHEMA
    below = proposer(tmp_path / "below", model={**MODEL, "max_input_tokens": tokens - 1})
    with pytest.raises(NativeInferenceError, match="token-derived"):
        below("curate", {})


@pytest.mark.parametrize("result,kind", [
    (ModelResult({"schema": PLAN_SCHEMA}), "invalid_output"),
    (ModelResult({}), "invalid_output"),
    (ModelResult(["not", "an", "object"]), "invalid_output"),
    (ModelResult({"schema": CURATION_SCHEMA, "value": "a" * 65}), "bounds"),
    (ModelResult({"schema": CURATION_SCHEMA, "value": float("nan")}), "invalid_output"),
    ({"proposal": {"schema": CURATION_SCHEMA}}, "invalid_output"),
])
def test_invalid_output_is_not_success_and_preserves_attempt(tmp_path, result, kind):
    fake = FakeInfer(result)
    instance = proposer(tmp_path, fake=fake, bounds=replace(NativeInferenceBounds(), field_bytes=64))
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {})
    assert caught.value.kind == kind
    assert instance.metrics["model_calls"] == instance.metrics["model_failures"] == 1
    assert documents(instance, "attempt")[0]["status"] == "FAILED"
    assert documents(instance, "attempt")[0]["error"]["kind"] == kind
    assert len(instance.artifacts) == 3


@pytest.mark.parametrize("raw", [False, True])
@pytest.mark.parametrize("limit_source", ["tokens", "payload"])
def test_output_byte_bound_preserves_hash_and_size_without_accepting_oversize(tmp_path, raw, limit_source):
    value = {"schema": CURATION_SCHEMA, "values": ["a" * 40] * 25}
    encoded = canonical_json(value)
    result = ModelResult({"schema": CURATION_SCHEMA} if raw else value,
                         raw_response=encoded.decode() if raw else None,
                         served_model="actual-model", served_provider="actual-provider")
    instance = proposer(
        tmp_path, fake=FakeInfer(result),
        model={**MODEL, "max_output_tokens": 64 if limit_source == "tokens" else 8192},
        bounds=replace(NativeInferenceBounds(), max_payload_bytes=512)
        if limit_source == "payload" else NativeInferenceBounds(),
    )
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {})
    assert caught.value.kind == "bounds"
    response = documents(instance, "response")[0]
    prefix = "raw_response" if raw else "proposal"
    assert response[f"{prefix}_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert response[f"{prefix}_size_bytes"] == len(encoded)
    assert response[f"{prefix}_omitted"] is True
    assert response["served_model"] == "actual-model"
    assert response["served_provider"] == "actual-provider"


@pytest.mark.parametrize("failure", [
    RuntimeError("transport broke"),
    TimeoutError("deadline"),
    subprocess.TimeoutExpired("fake-model", 19),
    ModelOutputError("malformed external model JSON"),
    ValueError("provider reasoning is unavailable"),
])
def test_central_retries_preserve_errors_and_do_not_recount_usage(tmp_path, failure):
    fake = FakeInfer(failure, ModelResult({"schema": CURATION_SCHEMA, "stats": {"input_tokens": 999999}},
                                        input_tokens=23, output_tokens=5, cache_tokens=3))
    instance = proposer(tmp_path, fake=fake, model={**MODEL, "retries": 1})
    instance("curate", {})
    assert len(fake.calls) == 2
    assert fake.calls[1][0].repair_errors == (f"{type(failure).__name__}: {failure}",)
    assert fake.calls[1][0].prior_response is None
    assert instance.metrics == {"model_calls": 2, "model_failures": 1, "input_tokens": 23,
                                "output_tokens": 5, "cache_tokens": 3, "unknown_usage_calls": 1}
    receipts = documents(instance, "attempt")
    assert [receipt["status"] for receipt in receipts] == ["FAILED", "SUCCEEDED"]
    assert receipts[0]["error"]["type"] == type(failure).__name__
    assert receipts[0]["error"]["message"] == str(failure)
    assert receipts[0]["usage"] == dict.fromkeys(("input_tokens", "output_tokens", "cache_tokens"))


def test_exhausted_model_error_retains_original_cause_and_attempts(tmp_path):
    failure = OSError("external transport unavailable")
    fake = FakeInfer(RuntimeError("first error"), failure)
    instance = proposer(tmp_path, fake=fake, model={**MODEL, "retries": 1})
    with pytest.raises(NativeInferenceError) as caught:
        instance("metadata", {})
    assert caught.value.kind == "model_failure" and caught.value.__cause__ is failure
    assert instance.metrics["model_calls"] == instance.metrics["model_failures"] == 2
    assert instance.metrics["unknown_usage_calls"] == 2
    assert [item["error"]["message"] for item in documents(instance, "attempt")] == [
        "first error", "external transport unavailable"]


def test_transport_parse_failure_keeps_bounded_raw_error_evidence(tmp_path):
    failure = ModelOutputError("no schema-bearing JSON")
    failure.raw_response = "original malformed response"
    instance = proposer(tmp_path, fake=FakeInfer(failure))
    with pytest.raises(NativeInferenceError):
        instance("plan", {})
    response = documents(instance, "response")[0]
    assert response["raw_response_excerpt"] == failure.raw_response
    assert response["raw_response_sha256"] == hashlib.sha256(failure.raw_response.encode()).hexdigest()
    assert response["raw_response_size_bytes"] == len(failure.raw_response.encode())
    assert response["raw_response_omitted"] is False


def test_execution_safety_stops_after_first_failure_but_keeps_attempt(tmp_path, monkeypatch):
    from appsec_review.runtime import execution_safety as safety

    def stop(reason, **kwargs):
        raise safety.ReviewStopped(reason)

    monkeypatch.setattr(safety, "active", lambda: True)
    monkeypatch.setattr(safety, "fail", stop)
    fake = FakeInfer(RuntimeError("first-error policy"))
    instance = proposer(tmp_path, fake=fake, model={**MODEL, "retries": 3})
    with pytest.raises(safety.ReviewStopped):
        instance("curate", {})
    assert len(fake.calls) == 1
    assert documents(instance, "attempt")[0]["status"] == "FAILED"
    assert instance.metrics["unknown_usage_calls"] == 1


def test_schema_retry_counts_each_returned_usage_once(tmp_path):
    fake = FakeInfer(ModelResult({"schema": "wrong"}, input_tokens=4, output_tokens=2, cache_tokens=1),
                     ModelResult({"schema": CURATION_SCHEMA}, input_tokens=7, output_tokens=3, cache_tokens=0))
    instance = proposer(tmp_path, fake=fake, model={**MODEL, "retries": 1})
    instance("curate", {})
    assert instance.metrics == {"model_calls": 2, "model_failures": 1, "input_tokens": 11,
                                "output_tokens": 5, "cache_tokens": 1, "unknown_usage_calls": 0}
    assert documents(instance, "response")[0]["proposal"] == {"schema": "wrong"}


def test_missing_partial_zero_and_invalid_usage_remain_distinguishable(tmp_path):
    fake = FakeInfer(
        ModelResult({"schema": CURATION_SCHEMA}),
        ModelResult({"schema": CURATION_SCHEMA}, input_tokens=0, output_tokens=0, cache_tokens=0),
        ModelResult({"schema": CURATION_SCHEMA}, input_tokens=8, cache_tokens=2),
        ModelResult({"schema": CURATION_SCHEMA}, input_tokens=-1, output_tokens=True, cache_tokens=1),
    )
    instance = proposer(tmp_path, fake=fake)
    for _ in range(4):
        instance("curate", {})
    assert instance.metrics == {"model_calls": 4, "model_failures": 0, "input_tokens": 8,
                                "output_tokens": 0, "cache_tokens": 3, "unknown_usage_calls": 3}
    usage = [item["usage"] for item in documents(instance, "attempt")]
    assert usage[0] == {"input_tokens": None, "output_tokens": None, "cache_tokens": None}
    assert usage[1] == {"input_tokens": 0, "output_tokens": 0, "cache_tokens": 0}
    assert usage[2]["output_tokens"] is None
    assert usage[3] == {"input_tokens": None, "output_tokens": None, "cache_tokens": 1}


def test_call_bound_includes_retries_and_prevents_extra_dispatch(tmp_path):
    fake = FakeInfer(RuntimeError("failed"))
    instance = proposer(tmp_path, fake=fake, model={**MODEL, "retries": 8},
                        bounds=replace(NativeInferenceBounds(), max_calls=1))
    with pytest.raises(NativeInferenceError) as caught:
        instance("curate", {})
    assert caught.value.kind == "bounds"
    assert len(fake.calls) == 1 and len(documents(instance, "attempt")) == 1
    with pytest.raises(NativeInferenceError, match="call bound"):
        instance("metadata", {})
    assert len(fake.calls) == 1


def test_persisted_receipts_exact_hashes_served_identity_and_collision_safe_scope(tmp_path):
    result = ModelResult({"schema": CURATION_SCHEMA}, raw_response='{"schema":"example raw envelope"}',
                         served_model="served-revision", served_provider="served-service")
    fake = FakeInfer(result)
    instance = proposer(tmp_path, fake=fake, unit_id="../../escaped\\scope")
    instance("curate", {"candidates": [{"candidate_id": "a"}]})
    assert len(instance.artifacts) == 3
    for ref in instance.artifacts:
        path = instance.run_root / ref["path"]
        raw = path.read_bytes()
        assert path.resolve().is_relative_to((instance.run_root / "data" / "native-inference").resolve())
        assert len(raw) == ref["size_bytes"] and hashlib.sha256(raw).hexdigest() == ref["sha256"]
        assert "../" not in ref["path"] and "\\" not in ref["path"]
    response = documents(instance, "response")[0]
    assert response["raw_response"] == result.raw_response
    assert response["served_model"] == result.served_model
    assert response["served_provider"] == result.served_provider
    receipt = documents(instance, "attempt")[0]
    assert receipt["request"] == instance.artifacts[0] and receipt["response"] == instance.artifacts[1]
    original_id = receipt["request_id"]
    second = proposer(tmp_path, unit_id="../../escaped\\scope")
    second("curate", {"candidates": [{"candidate_id": "a"}]})
    assert documents(second, "attempt")[0]["request_id"] == original_id
    assert second.artifacts[0]["path"] != instance.artifacts[0]["path"]
    assert Path(second.artifacts[0]["path"]).parent.name == "attempt-000002"


def test_request_ids_change_for_payload_guidance_model_and_stage(tmp_path):
    instance = proposer(tmp_path)
    base = instance._request("curate", {})[1]
    assert instance._request("curate", {"different": True})[1] != base
    assert instance._request("plan", {})[1] != base
    changed = proposer(tmp_path / "model", model={**MODEL, "reasoning": "low"})
    assert changed._request("curate", {})[1] != base
    root = copied_repository(tmp_path)
    task = root / "pipeline" / "guidance" / "tasks" / "dependency-intelligence" / "native_component_curation.md"
    task.write_text(task.read_text() + "\nInspect distribution context.\n")
    changed = proposer(tmp_path / "guidance", root=root)
    assert changed._request("curate", {})[1] != base


def test_payload_and_model_inputs_are_snapshotted_without_modifying_caller(tmp_path):
    payload = {"candidates": [{"candidate_id": "a"}]}
    model = dict(MODEL)
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake, model=model)
    model["model"] = "changed"
    instance("curate", payload)
    payload["candidates"][0]["candidate_id"] = "changed"
    assert fake.calls[0][0].model == MODEL["model"]
    assert fake.calls[0][0].summary["payload"]["candidates"][0]["candidate_id"] == "a"


def test_stage_error_is_explicit_without_model_or_evidence_reads(tmp_path):
    fake = FakeInfer()
    instance = proposer(tmp_path, fake=fake)
    with pytest.raises(NativeInferenceError) as caught:
        instance("retrieve", {"path": "/not/read/by/transport"})
    assert caught.value.kind == "invalid_output" and not fake.calls
