from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from appsec_review.guidance.compose import load_registry
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
from appsec_review.jobs.job_dependency_intelligence import (
    HttpResponse, ScorecardClient, ScorecardError, apply_model_resolution, build_job,
    load_accepted_dependency_intelligence, normalize_dependencies, parse_native_candidates,
)
from appsec_review.jobs.job_dependency_intelligence.inference import resolve_with_inference
from appsec_review.inference import ModelResult
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity
from appsec_review.retrieval.index import write_manifest
from appsec_review.storage import atomic_json, file_sha256


def test_native_detection_covers_link_loader_and_metadata_and_deduplicates() -> None:
    candidates, gaps = parse_native_candidates(
        [{"command_id": "cmd-1", "argv": ["clang++", "main.o", "-lz", "-Wl,-lssl", "/opt/lib/libcurl.a"],
          "argv_sha256": "a" * 64},
         {"command_id": "cmd-2", "argv": ["ld", "-l", "z"], "argv_sha256": "b" * 64}],
        artifacts=[{"sha256": "c" * 64, "loader_dependencies": ["libssl.so.3", "libz.so.1"]}],
        metadata_files=[{"path": "lib/pkgconfig/zlib.pc", "sha256": "d" * 64,
                         "fields": {"Name": "z", "Version": "1.3", "URL": "https://github.com/madler/zlib"}}],
    )
    assert gaps == []
    by_name = {item["native_name"].casefold(): item for item in candidates}
    assert set(by_name) == {"curl", "ssl", "z"}
    assert len(by_name["z"]["observations"]) == 4
    assert by_name["z"]["metadata"]["repository_url"] == "https://github.com/madler/zlib"
    assert {row["kind"] for row in by_name["ssl"]["observations"]} == {
        "linker_forwarded_flag", "loader_needed"}


def test_native_detection_records_command_bounds() -> None:
    candidates, gaps = parse_native_candidates(
        [{"argv": ["cc", "-lfoo", "-lbar"]}], max_tokens_per_command=2, max_candidates=10)
    assert [item["native_name"] for item in candidates] == ["foo"]
    assert gaps == ["native invocation 0 exceeds command token bound (2)"]


def test_normalization_prefers_package_repository_metadata_and_deduplicates() -> None:
    dependencies, gaps = normalize_dependencies(
        [{"name": "zlib", "constraint": "1.3", "source": "package.json"}],
        [{"name": "zlib", "version": "1.3", "repository_url": "https://github.com/madler/zlib.git",
          "observation_id": "sbom:1"},
         {"name": "openssl", "version": "3.0", "observation_id": "sbom:2"}],
        [], supported_hosts=("github.com",), max_dependencies=10)
    assert gaps == []
    zlib = next(item for item in dependencies if item["name"] == "zlib")
    assert zlib["repository"]["url"] == "https://github.com/madler/zlib"
    assert zlib["resolution_basis"] == "package_metadata"
    assert zlib["exact_repository_identity"] is True
    assert len(dependencies) == 2


def test_model_resolution_is_validated_and_never_exact() -> None:
    native = {"candidate_id": "native-dependency-a", "native_name": "mystery",
              "observations": [{"command_id": "cmd-1", "kind": "link_flag", "value": "-lmystery"}]}
    dependency = {"dependency_id": "dependency-a", "name": "mystery", "repository": None,
                  "observations": [{"evidence_id": "native:1"}], "native_candidate": native}
    proposal = {"schema": "appsec-review/native-dependency-resolution-proposal/1",
                "candidate_id": "native-dependency-a",
                "repository": {"host": "github.com", "owner": "example", "name": "mystery",
                               "url": "https://github.com/example/mystery"},
                "confidence": .72, "evidence_refs": ["cmd-1"], "rationale": "name and link evidence agree"}
    resolved = apply_model_resolution(dependency, proposal, supported_hosts=("github.com",))
    assert resolved["resolution_basis"] == "model_inference"
    assert resolved["exact_repository_identity"] is False
    assert resolved["resolution_confidence"] == .72
    with pytest.raises(ValueError, match="outside the candidate"):
        apply_model_resolution(dependency, {**proposal, "evidence_refs": ["invented"]},
                               supported_hosts=("github.com",))
    with pytest.raises(ValueError, match="between 0 and 0.95"):
        apply_model_resolution(dependency, {**proposal, "confidence": 1.0},
                               supported_hosts=("github.com",))


def test_native_inference_is_injectable_and_pins_registered_guidance(tmp_path: Path) -> None:
    candidate = {"candidate_id": "native-dependency-a", "native_name": "mystery",
                 "observations": [{"command_id": "cmd-1", "kind": "link_flag", "value": "-lmystery"}]}
    dependency = {"dependency_id": "dependency-a", "name": "mystery", "repository": None,
                  "observations": [{"evidence_id": "native:1"}], "native_candidate": candidate}
    seen = []
    def fake_infer(request, *, timeout_seconds: int) -> ModelResult:
        seen.append((request, timeout_seconds))
        return ModelResult({"schema": "appsec-review/native-dependency-resolution-proposal/1",
            "candidate_id": "native-dependency-a",
            "repository": {"host": "github.com", "owner": "example", "name": "mystery",
                           "url": "https://github.com/example/mystery"},
            "confidence": .6, "evidence_refs": ["cmd-1"], "rationale": "bounded evidence"})
    model = {"enabled": True, "provider": "fake", "model": "fake", "reasoning": "low",
             "max_input_tokens": 10000, "max_output_tokens": 1000, "timeout_seconds": 7, "retries": 0}
    resolved, gap = resolve_with_inference(dependency, repository_root=Path(__file__).parents[1],
        run_root=tmp_path, model=model, supported_hosts=("github.com",), infer=fake_infer,
        max_candidate_bytes=10000)
    assert gap is None and resolved["exact_repository_identity"] is False
    assert seen[0][0].persona == "dependency_repository_investigator" and seen[0][1] == 7
    assert list((tmp_path / "data/guidance").iterdir())


def test_scorecard_success_retains_exact_bytes_and_context_semantics() -> None:
    raw = json.dumps({"score": 7.4, "date": "2026-01-01", "commit": "abc",
                      "checks": [{"name": "Maintained", "score": 8, "reason": "recent"}]}).encode()
    calls = []
    def transport(url: str, **kwargs) -> HttpResponse:
        calls.append((url, kwargs))
        return HttpResponse(200, raw, {})
    client = ScorecardClient(base_url="https://api.securityscorecards.dev",
        allowed_hosts=("api.securityscorecards.dev",), max_requests=2, max_response_bytes=4096,
        timeout_seconds=3, retries=0, transport=transport)
    record, response = client.fetch({"host": "github.com", "owner": "ossf", "name": "scorecard"})
    assert response == raw
    assert record["context_only"] is True and record["security_finding"] is False
    assert record["score"] == 7.4
    assert calls[0][0].endswith("/projects/github.com/ossf/scorecard")


@pytest.mark.parametrize("status,kind", [(404, "not_found"), (429, "rate_limit"), (503, "request_failure")])
def test_scorecard_missing_rate_limit_and_failure_are_typed(status: int, kind: str) -> None:
    client = ScorecardClient(base_url="https://api.securityscorecards.dev",
        allowed_hosts=("api.securityscorecards.dev",), max_requests=1, max_response_bytes=4096,
        timeout_seconds=3, retries=0, transport=lambda *_args, **_kwargs: HttpResponse(status, b"{}", {}))
    with pytest.raises(ScorecardError) as caught:
        client.fetch({"host": "github.com", "owner": "o", "name": "r"})
    assert caught.value.kind == kind


def test_scorecard_malformed_and_request_bounds_are_typed() -> None:
    malformed = ScorecardClient(base_url="https://api.securityscorecards.dev",
        allowed_hosts=("api.securityscorecards.dev",), max_requests=1, max_response_bytes=4096,
        timeout_seconds=3, retries=0, transport=lambda *_args, **_kwargs: HttpResponse(200, b"[]", {}))
    with pytest.raises(ScorecardError) as caught:
        malformed.fetch({"host": "github.com", "owner": "o", "name": "r"})
    assert caught.value.kind == "malformed_response"
    assert caught.value.response is not None and caught.value.response.body == b"[]"
    with pytest.raises(ScorecardError) as caught:
        malformed.fetch({"host": "github.com", "owner": "o", "name": "r"})
    assert caught.value.kind == "bounds"


def test_guidance_and_job_public_api_are_registered() -> None:
    root = Path(__file__).parents[1]
    registry = load_registry(root)
    assert registry["roles"]["native_dependency_resolver"]["responsibility"]
    assert registry["personas"]["dependency_repository_investigator"]["viewpoint"]
    skill = load_runtime_skill(root, "native-dependency-resolution", job_id="job_dependency_intelligence")
    assert skill.name == "native-dependency-resolution"
    job = build_job()
    assert job.consumes == ("job_target_catalog", "job_language_build", "job_artifact_indexing",
                            "job_evidence_collection")
    assert {item.output_kind for item in job.datasets} == {
        "dependency_context", "scorecard_responses", "dependency_intelligence_handoff"}


def test_accepted_publication_verifies_handoff_index_and_hashes(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    snapshot = "f" * 64
    fingerprint = "e" * 64
    index_path = run_root / "data/indices/inventory/dependencies.sqlite"
    builder = IndexBuilder(index_path, name="inventory", fingerprint=fingerprint,
                           target_snapshot=snapshot, shard_id="dependency-intelligence")
    identity = LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, snapshot, {"name": "zlib"})
    builder.add_entity(EntityRecord(identity, "dependency-zlib", "zlib", "dependency zlib", {}))
    builder.add_coverage("dependency-zlib", "complete")
    index_sha = builder.build()
    index = IndexIdentity("inventory", "appsec-review/retrieval-index/2", index_sha, fingerprint,
                          index_path.relative_to(run_root).as_posix(),
                          {"job": "job_dependency_intelligence"}, (), "dependency-intelligence")
    manifest_path = run_root / "data/indices/manifests/dependency.json"
    write_manifest(manifest_path, run_id="run", target_snapshot=snapshot, target_root=tmp_path,
                   indexes=(index,))
    manifest_identity = {"path": manifest_path.relative_to(run_root).as_posix(),
                         "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    document = {"schema": DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA, "source_fingerprint": snapshot,
                "upstream_handoffs": {}, "dependencies": [], "scorecards": [], "gaps": [],
                "index_identity": asdict(index), "index_manifest": manifest_identity,
                "security_findings": [], "scorecard_semantics": "review-context-and-red-team-seed-only"}
    published = run_root / "published.json"
    atomic_json(published, document)
    artifact = {"path": published.relative_to(run_root).as_posix(), "sha256": file_sha256(published),
                "size_bytes": published.stat().st_size}
    framework = run_root / "framework-handoff.json"
    atomic_json(framework, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                            "job_id": "job_dependency_intelligence",
                            "outputs": {"acceptance.publish_handoff": {"artifact": artifact}},
                            "artifacts": [artifact, manifest_identity]})
    latest = run_root / "data/jobs/job_dependency_intelligence/latest.json"
    atomic_json(latest, {"handoff_path": framework.relative_to(run_root).as_posix(),
                         "handoff_sha256": file_sha256(framework)})
    loaded = load_accepted_dependency_intelligence(run_root)
    assert loaded["schema"] == DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
    index_path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="index integrity mismatch"):
        load_accepted_dependency_intelligence(run_root)
