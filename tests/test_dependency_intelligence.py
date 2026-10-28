from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.guidance.compose import load_registry
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
from appsec_review.jobs.job_dependency_intelligence import (
    HttpResponse, ScorecardCache, ScorecardCacheError, ScorecardClient, ScorecardError,
    apply_model_resolution, build_job, deduplicate_repositories, infer_maximal_exposure,
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


def test_native_detection_retains_structured_and_explicit_debug_build_context() -> None:
    candidates, gaps = parse_native_candidates([
        {"command_id": "cmd-1", "argv": ["clang", "-g", "main.o", "-lexample"]},
        {"command_id": "cmd-2", "argv": ["link", "x.obj", "example.lib"],
         "configuration": "preproduction"},
    ])
    assert gaps == []
    assert {item["configuration"] for item in candidates[0]["observations"]} == {
        "debug", "preproduction"}


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


def test_repository_deduplication_groups_dependency_fanout_before_requests() -> None:
    repositories, gaps = deduplicate_repositories([
        {"dependency_id": "dependency-a", "repository": {
            "host": "github.com", "owner": "OpenSSF", "name": "Scorecard",
            "url": "https://github.com/OpenSSF/Scorecard"}},
        {"dependency_id": "dependency-b", "repository": {
            "host": "GITHUB.COM", "owner": "openssf", "name": "scorecard",
            "url": "https://github.com/openssf/scorecard"}},
        {"dependency_id": "dependency-c", "repository": None},
    ], max_repositories=10)
    assert gaps == []
    assert len(repositories) == 1
    assert repositories[0]["dependency_ids"] == ["dependency-a", "dependency-b"]


def test_repository_deduplication_records_bound_per_affected_dependency() -> None:
    repositories, gaps = deduplicate_repositories([
        {"dependency_id": f"dependency-{name}", "repository": {
            "host": "github.com", "owner": "example", "name": name,
            "url": f"https://github.com/example/{name}"}}
        for name in ("a", "b")
    ], max_repositories=1)
    assert len(repositories) == 1
    assert gaps == [{"dependency_id": "dependency-b", "kind": "repository_bound",
                     "detail": "repository deduplication bound exceeded (1)"}]


@pytest.mark.parametrize(("field", "value", "expected"), [
    ("location", "devDependencies", "DEV"),
    ("configuration", "Debug", "DEBUG"),
    ("scope", "integration-test", "QA"),
    ("environment", "staging", "PREPROD"),
    ("usage", "runtime", "PROD"),
])
def test_exposure_classifier_covers_the_closed_ordered_vocabulary(
        field: str, value: str, expected: str) -> None:
    evidence = infer_maximal_exposure({field: value, "observation_id": "obs-1"}, "declared")
    assert {item["exposure"] for item in evidence} == {expected}
    assert all(item["evidence_id"] == "obs-1" for item in evidence)


def test_normalization_retains_conflicting_exposure_and_chooses_maximum() -> None:
    dependencies, gaps = normalize_dependencies(
        [
            {"name": "example", "constraint": "1", "location": "devDependencies",
             "observation_id": "manifest-dev"},
            {"name": "example", "constraint": "1", "scope": "qa",
             "observation_id": "manifest-qa"},
            {"name": "example", "constraint": "1", "environment": "preproduction",
             "observation_id": "manifest-preprod"},
        ], [], [], supported_hosts=("github.com",), max_dependencies=10)
    assert gaps == []
    dependency = dependencies[0]
    assert dependency["maximal_exposure"] == "PREPROD"
    assert dependency["exposure_inference_basis"] == "maximum-observed-evidence"
    assert {item["exposure"] for item in dependency["exposure_evidence"]} == {
        "DEV", "QA", "PREPROD"}
    assert {item["evidence_id"] for item in dependency["exposure_evidence"]} == {
        "manifest-dev", "manifest-qa", "manifest-preprod"}


def test_unknown_exposure_conservatively_defaults_to_prod() -> None:
    dependencies, gaps = normalize_dependencies(
        [{"name": "example", "constraint": "1", "source": "package.json"}], [], [],
        supported_hosts=("github.com",), max_dependencies=10)
    assert gaps == []
    assert dependencies[0]["maximal_exposure"] == "PROD"
    assert dependencies[0]["exposure_inference_basis"] == "conservative-default"
    assert dependencies[0]["exposure_evidence"] == []


def test_exposure_evidence_is_deduplicated_with_dependency_observations() -> None:
    record = {"name": "example", "constraint": "1", "scope": "test",
              "observation_id": "same-observation"}
    dependencies, gaps = normalize_dependencies(
        [record, dict(record)], [], [], supported_hosts=("github.com",), max_dependencies=10)
    assert gaps == []
    assert len(dependencies[0]["observations"]) == 1
    assert len(dependencies[0]["exposure_evidence"]) == 1
    assert dependencies[0]["maximal_exposure"] == "QA"


def test_native_loader_and_configuration_evidence_conflict_and_propagate() -> None:
    native = {"candidate_id": "native-dependency-a", "native_name": "example",
              "observations": [
                  {"command_id": "cmd-1", "kind": "link_flag", "configuration": "debug"},
                  {"artifact_sha256": "a" * 64, "kind": "loader_needed", "value": "libexample.so"},
              ]}
    (dependency,), gaps = normalize_dependencies(
        [], [], [native], supported_hosts=("github.com",), max_dependencies=10)
    assert gaps == [] and dependency["maximal_exposure"] == "PROD"
    assert {item["basis"] for item in dependency["exposure_evidence"]} == {
        "native-build-configuration", "runtime-loader"}
    proposal = {"schema": "appsec-review/native-dependency-resolution-proposal/1",
                "candidate_id": "native-dependency-a",
                "repository": {"host": "github.com", "owner": "example", "name": "example",
                               "url": "https://github.com/example/example"},
                "confidence": .7, "evidence_refs": ["cmd-1"], "rationale": "bounded evidence"}
    resolved = apply_model_resolution(dependency, proposal, supported_hosts=("github.com",))
    assert resolved["maximal_exposure"] == dependency["maximal_exposure"]
    assert resolved["exposure_evidence"] == dependency["exposure_evidence"]


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


def test_scorecard_cache_reuses_fresh_exact_bytes_and_expires_by_tunable_age(tmp_path: Path) -> None:
    instant = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    now = [instant]
    cache = ScorecardCache(tmp_path / "cache", max_age_seconds=3600, max_response_bytes=4096,
                           clock=lambda: now[0])
    repository = {"host": "github.com", "owner": "ossf", "name": "scorecard"}
    raw = json.dumps({"score": 8, "checks": []}).encode()
    stored = cache.store(repository, raw)
    assert stored["status"] == "refresh"
    payload, hit = cache.load(repository)
    assert payload == raw and hit["status"] == "hit" and hit["age_seconds"] == 0
    client = ScorecardClient(base_url="https://api.securityscorecards.dev",
        allowed_hosts=("api.securityscorecards.dev",), max_requests=1, max_response_bytes=4096,
        timeout_seconds=3, retries=0,
        transport=lambda *_args, **_kwargs: pytest.fail("fresh cache must avoid HTTP"))
    record, normalized_raw = client.normalize(repository, payload)
    assert record["score"] == 8 and normalized_raw == raw and client.requests == 0
    now[0] += timedelta(seconds=3601)
    payload, stale = cache.load(repository)
    assert payload is None and stale["status"] == "stale" and stale["age_seconds"] == 3601


def test_scorecard_cache_rejects_tampered_content_addressed_blob(tmp_path: Path) -> None:
    cache = ScorecardCache(tmp_path / "cache", max_age_seconds=3600, max_response_bytes=4096)
    repository = {"host": "github.com", "owner": "ossf", "name": "scorecard"}
    stored = cache.store(repository, b'{"score":8,"checks":[]}')
    blob = next((tmp_path / "cache" / "blobs").iterdir())
    blob.write_bytes(b"changed")
    with pytest.raises(ScorecardCacheError, match="invalid Scorecard cache entry"):
        cache.load(repository)
    assert stored["response_sha256"] != file_sha256(blob)


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
    assert [unit.unit_id for unit in job.units][2:5] == [
        "resolution.infer_repositories", "repositories.deduplicate", "scorecards.fetch"]
    assert job.consumes == ("job_target_catalog", "job_language_build", "job_artifact_indexing",
                            "job_evidence_collection")
    assert {item.output_kind for item in job.datasets} == {
        "dependency_context", "scorecard_responses", "dependency_intelligence_handoff",
        "native_discovery", "native_spdx", "native_sbom_provenance", "native_sbom_metrics"}


def test_accepted_publication_verifies_handoff_index_and_hashes(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    snapshot = "f" * 64
    fingerprint = "e" * 64
    index_path = run_root / "data/indices/inventory/dependencies.sqlite"
    builder = IndexBuilder(index_path, name="inventory", fingerprint=fingerprint,
                           target_snapshot=snapshot, shard_id="dependency-intelligence")
    identity = LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, snapshot, {"name": "zlib"})
    exposure = {"dependency_id": "dependency-zlib", "name": "zlib", "maximal_exposure": "QA",
                "exposure_inference_basis": "maximum-observed-evidence",
                "exposure_evidence": [{"exposure": "QA", "basis": "structured-scope",
                                       "source": "declared", "evidence_id": "manifest-1",
                                       "field": "scope", "value": "test", "matched_term": "test"}]}
    builder.add_entity(EntityRecord(identity, "dependency-zlib", "zlib", "dependency zlib", exposure))
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
                "upstream_handoffs": {}, "dependencies": [exposure], "scorecards": [], "gaps": [],
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
    assert loaded["dependencies"][0]["maximal_exposure"] == "QA"
    with sqlite3.connect(index_path) as database:
        payload = json.loads(database.execute(
            "SELECT payload_json FROM entities WHERE native_id = 'dependency-zlib'").fetchone()[0])
    assert payload["maximal_exposure"] == "QA"
    assert payload["exposure_evidence"] == exposure["exposure_evidence"]
    index_path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="index integrity mismatch"):
        load_accepted_dependency_intelligence(run_root)
