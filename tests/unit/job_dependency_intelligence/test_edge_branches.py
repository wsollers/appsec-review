"""Focused edge-case and error-branch unit tests for job_dependency_intelligence."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
import math
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ExecutionLimit, ModelOutputError
from appsec_review.jobs.job_dependency_intelligence.curation import (
    _Curation, curate_native_components,
)
from appsec_review.jobs.job_dependency_intelligence.discovery import (
    _domain, _pointer, _reference, _text, discover_native_dependencies,
)
from appsec_review.jobs.job_dependency_intelligence.inference import (
    PROPOSAL_SCHEMA, ResolutionBudget, resolve_with_inference,
)
from appsec_review.jobs.job_dependency_intelligence.integration import (
    collect_inputs, validate_publication,
)
from appsec_review.jobs.job_dependency_intelligence.investigation import (
    investigate_native_metadata,
)
from appsec_review.jobs.job_dependency_intelligence.native import parse_native_candidates
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import (
    CURATION_SCHEMA, INFERENCE_COUNTERS, INFERENCE_METRICS_SCHEMA, NativeInferenceBounds, Propose,
)
from appsec_review.jobs.job_dependency_intelligence.native_inference_integration import (
    _publish as publish_inference_unit, inference_bounds, validate_inference_receipt,
)
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
    DISCOVERY_SCHEMA, NativeBounds, NativeInputIntegrityError, SbomBounds, evidence_identity,
)
from appsec_review.jobs.job_dependency_intelligence.resolution import (
    apply_model_resolution, deduplicate_repositories, infer_maximal_exposure,
    normalize_dependencies, repository_identity,
)
from appsec_review.jobs.job_dependency_intelligence.scorecard import (
    HttpResponse, ScorecardCache, ScorecardCacheError, ScorecardClient, ScorecardError,
    https_get, repository_cache_key,
)
from appsec_review.runtime import UnitContext
from appsec_review.runtime import execution_safety as safety
from appsec_review.storage import LockUnavailable, atomic_bytes, atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import reference

from tests.unit.job_dependency_intelligence.test_job_graph import (
    CREATED, ROOT, SNAPSHOT, _converter, _framework, _make_job_context, _owner_scope,
    _publish_result_as_handoff, _seed_upstreams, _write,
)
from appsec_review.jobs.job_dependency_intelligence import build_job


def test_contracts_bounds_and_protocol_branches() -> None:
    with pytest.raises(ValueError, match="must be a positive integer"):
        NativeBounds(0, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    with pytest.raises(ValueError, match="must be a positive integer"):
        SbomBounds(0, 1, 1, 1)
    with pytest.raises(ValueError, match="must be a positive integer"):
        NativeInferenceBounds(max_calls=0)
    assert Propose.__call__(None, "curate", {}) is None  # type: ignore[arg-type]


def test_inference_budget_reuse_bounds_and_retry_exhaustion(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        ResolutionBudget(0)

    run_root = tmp_path / "run"
    run_root.mkdir()
    model = {
        "enabled": True, "provider": "openai", "model": "gpt-test", "reasoning": "low",
        "max_input_tokens": 8000, "max_output_tokens": 1000, "timeout_seconds": 5, "retries": 1,
    }
    cand1 = {"candidate_id": "cand-1", "native_name": "foo", "observations": [{"evidence_id": "ev-1"}]}
    dep1 = {
        "dependency_id": "dep-1", "name": "foo", "repository": None,
        "observations": [{"evidence_id": "ev-1"}], "native_candidate": cand1,
    }
    dep1_dup = {**dep1, "dependency_id": "dep-1b"}

    # Disabled & missing transport
    _, g_dis = resolve_with_inference(
        dep1, repository_root=ROOT, run_root=run_root,
        model={**model, "enabled": False}, supported_hosts=("github.com",),
        infer=None, max_candidate_bytes=4096,
    )
    assert g_dis and g_dis["kind"] == "model_unavailable"

    _, g_none = resolve_with_inference(
        dep1, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=None, max_candidate_bytes=4096,
    )
    assert g_none and g_none["kind"] == "model_unavailable"

    # Candidate byte bound & token-derived byte bound
    _, g_bytes = resolve_with_inference(
        dep1, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=lambda _r, timeout_seconds: None, max_candidate_bytes=4,  # type: ignore[return-value]
    )
    assert g_bytes and g_bytes["kind"] == "bounds"

    _, g_tok = resolve_with_inference(
        dep1, repository_root=ROOT, run_root=run_root,
        model={**model, "max_input_tokens": 1}, supported_hosts=("github.com",),
        infer=lambda _r, timeout_seconds: None, max_candidate_bytes=4096,  # type: ignore[return-value]
    )
    assert g_tok and g_tok["kind"] == "bounds"

    # Invalid proposal triggers ValueError -> ModelOutputError -> retry -> failure recorded in budget
    calls = {"n": 0}

    def bad_infer(req, timeout_seconds: int):
        calls["n"] += 1
        return ModelResult({"schema": "wrong"})

    budget = ResolutionBudget(1)
    _, g_fail = resolve_with_inference(
        dep1, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=bad_infer, max_candidate_bytes=4096, budget=budget,
    )
    assert g_fail and g_fail["kind"] == "model_failure" and calls["n"] == 2
    assert budget.exhausted

    # Identical candidate set reuses cached gap without calling infer again
    _, g_reused = resolve_with_inference(
        dep1_dup, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=bad_infer, max_candidate_bytes=4096, budget=budget,
    )
    assert g_reused and "already asked" in g_reused["detail"] and calls["n"] == 2

    # Different candidate set after budget exhausted hits model_failure_bound
    dep2 = {
        "dependency_id": "dep-2", "name": "bar", "repository": None,
        "observations": [{"evidence_id": "ev-2"}],
        "native_candidate": {"candidate_id": "cand-2", "native_name": "bar", "observations": [{"evidence_id": "ev-2"}]},
    }
    _, g_bound = resolve_with_inference(
        dep2, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=bad_infer, max_candidate_bytes=4096, budget=budget,
    )
    assert g_bound and g_bound["kind"] == "model_failure_bound"

    # Proposal reuse & ExecutionLimit on retry
    good_budget = ResolutionBudget(2)
    good_proposal = {
        "schema": PROPOSAL_SCHEMA,
        "candidate_id": "cand-1",
        "repository": {"host": "github.com", "owner": "org", "name": "foo", "url": "https://github.com/org/foo"},
        "confidence": 0.8,
        "evidence_refs": ["ev-1"],
        "rationale": "matched",
    }
    res_ok, g_ok = resolve_with_inference(
        dep1, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=lambda _r, timeout_seconds: ModelResult(good_proposal),
        max_candidate_bytes=4096, budget=good_budget,
    )
    assert g_ok is None and res_ok["repository"]["owner"] == "org"
    res_reused, g_reused_ok = resolve_with_inference(
        dep1_dup, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=bad_infer, max_candidate_bytes=4096, budget=good_budget,
    )
    assert g_reused_ok is None and res_reused["repository"]["owner"] == "org"

    # ExecutionLimit raised inside engine.retry breaks cleanly
    def exec_limit_infer(_r, timeout_seconds: int):
        raise ExecutionLimit("budget hit")

    _, g_lim = resolve_with_inference(
        dep2, repository_root=ROOT, run_root=run_root,
        model=model, supported_hosts=("github.com",),
        infer=exec_limit_infer, max_candidate_bytes=4096,
    )
    assert g_lim and g_lim["kind"] == "model_failure"


def test_scorecard_transport_cache_and_client_edge_branches(tmp_path: Path, monkeypatch) -> None:
    # https_get branches via monkeypatched build_opener
    state: dict[str, Any] = {"mode": "ok", "redirect_checked": False}

    class FakeResp:
        status = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, body: bytes):
            self._io = BytesIO(body)

        def read(self, n: int) -> bytes:
            return self._io.read(n)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_build_opener(*handlers):
        for h in handlers:
            if hasattr(h, "redirect_request"):
                assert h.redirect_request(None, None, 302, "Found", {}, "https://x") is None
                state["redirect_checked"] = True

        class Opener:
            def open(self, req, timeout=5):
                if state["mode"] == "ok":
                    return FakeResp(b'{"ok":1}')
                if state["mode"] == "big":
                    return FakeResp(b"x" * 20)
                if state["mode"] == "http404":
                    raise HTTPError(req.full_url, 404, "Not Found", {"X-Err": "1"}, BytesIO(b"nope"))
                raise HTTPError(req.full_url, 500, "Boom", {}, BytesIO(b"y" * 20))

        return Opener()

    monkeypatch.setattr("appsec_review.jobs.job_dependency_intelligence.scorecard.build_opener", fake_build_opener)
    r_ok = https_get("https://api.securityscorecards.dev/projects/github.com/o/r", timeout_seconds=2, max_bytes=16)
    assert r_ok.status == 200 and state["redirect_checked"]
    state["mode"] = "big"
    with pytest.raises(ValueError, match="response byte bound exceeded"):
        https_get("https://api.securityscorecards.dev/projects/github.com/o/r", timeout_seconds=2, max_bytes=5)
    state["mode"] = "http404"
    r_404 = https_get("https://api.securityscorecards.dev/projects/github.com/o/r", timeout_seconds=2, max_bytes=16)
    assert r_404.status == 404
    state["mode"] = "http_big"
    with pytest.raises(ValueError, match="response byte bound exceeded"):
        https_get("https://api.securityscorecards.dev/projects/github.com/o/r", timeout_seconds=2, max_bytes=5)

    # _repository_parts & ScorecardCache validation / corruption branches
    with pytest.raises(ScorecardError):
        repository_cache_key({"host": "github.com", "owner": "../bad", "name": "r"})
    with pytest.raises(ValueError, match="positive integers"):
        ScorecardCache(tmp_path / "c", max_age_seconds=0, max_response_bytes=10)

    now = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
    clock_box = {"now": now}
    cache = ScorecardCache(tmp_path / "cache", max_age_seconds=60, max_response_bytes=128,
                           clock=lambda: clock_box["now"])
    repo = {"host": "github.com", "owner": "org", "name": "pkg"}
    key = repository_cache_key(repo)
    ptr = cache.root / "entries" / f"{key}.json"

    with pytest.raises(ScorecardCacheError, match="exceeds cache byte bound"):
        cache.store(repo, b"z" * 200)

    stored = cache.store(repo, b'{"score": 7.0, "checks": []}')
    assert stored["status"] == "refresh"
    # Second store hits existing valid blob branch
    assert cache.store(repo, b'{"score": 7.0, "checks": []}')["status"] == "refresh"

    # Stale branch
    clock_box["now"] = now + timedelta(seconds=120)
    raw_stale, meta_stale = cache.load(repo)
    assert raw_stale is None and meta_stale["status"] == "stale"
    clock_box["now"] = now

    # Future timestamp, naive timestamp, schema mismatch, missing response, outside blob, size mismatch, hash mismatch
    orig_ptr = json.loads(ptr.read_text())
    for mutated in (
        {**orig_ptr, "schema": "bad"},
        {**orig_ptr, "fetched_at": "2026-10-28T12:00:00"},
        {**orig_ptr, "fetched_at": "2026-10-28T13:00:00Z"},
        {**orig_ptr, "response": None},
        {**orig_ptr, "response": {**orig_ptr["response"], "path": "../outside.json"}},
        {**orig_ptr, "response": {**orig_ptr["response"], "size_bytes": 999}},
        {**orig_ptr, "response": {**orig_ptr["response"], "sha256": "0" * 64}},
    ):
        atomic_json(ptr, mutated)
        with pytest.raises(ScorecardCacheError):
            cache.load(repo)

    # Oversized pointer
    ptr.write_bytes(b" " * 70000)
    with pytest.raises(ScorecardCacheError):
        cache.load(repo)

    # Corrupted existing blob on store & LockUnavailable on store
    blob_path = cache.root / orig_ptr["response"]["path"]
    blob_path.write_bytes(b"corrupted")
    with pytest.raises(ScorecardCacheError, match="blob mismatch"):
        cache.store(repo, b'{"score": 7.0, "checks": []}')
    blob_path.unlink()

    def raise_lock(*_a, **_kw):
        raise LockUnavailable("locked")

    monkeypatch.setattr("appsec_review.jobs.job_dependency_intelligence.scorecard.bounded_file_lock", raise_lock)
    with pytest.raises(ScorecardCacheError, match="lock timed out"):
        cache.store(repo, b'{"score": 7.0, "checks": []}')

    # ScorecardClient constructor & fetch/normalize branches
    for kwargs in (
        {"base_url": "http://api.securityscorecards.dev", "allowed_hosts": ["api.securityscorecards.dev"],
         "max_requests": 1, "max_response_bytes": 100, "timeout_seconds": 1, "retries": 0},
        {"base_url": "https://api.securityscorecards.dev:8443?q=1", "allowed_hosts": ["api.securityscorecards.dev"],
         "max_requests": 1, "max_response_bytes": 100, "timeout_seconds": 1, "retries": 0},
        {"base_url": "https://api.securityscorecards.dev", "allowed_hosts": ["api.securityscorecards.dev"],
         "max_requests": -1, "max_response_bytes": 100, "timeout_seconds": 1, "retries": 0},
        {"base_url": "https://api.securityscorecards.dev", "allowed_hosts": ["api.securityscorecards.dev"],
         "max_requests": 1, "max_response_bytes": 100, "timeout_seconds": 1, "retries": 6},
    ):
        with pytest.raises(ValueError):
            ScorecardClient(**kwargs)  # type: ignore[arg-type]

    sleeps: list[float] = []
    seq = iter([
        URLError("temp"),
        HttpResponse(429, b"rate", {}),
        HttpResponse(503, b"busy", {}),
        HttpResponse(200, b'{"score": 9.0, "checks": []}', {}),
    ])

    def retry_transport(url: str, *, timeout_seconds: int, max_bytes: int) -> HttpResponse:
        item = next(seq)
        if isinstance(item, Exception):
            raise item
        return item

    client = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=4, max_response_bytes=4096, timeout_seconds=2, retries=3,
        transport=retry_transport, sleeper=sleeps.append,
    )
    norm, _ = client.fetch(repo)
    assert norm["score"] == 9.0 and len(sleeps) == 3
    with pytest.raises(ScorecardError, match="request bound exhausted"):
        client.fetch(repo)

    # Exhausting max_requests mid-retry, rate_limit terminal, HTTP 400 terminal, bounds error, and safety.active()
    c_mid = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=1, max_response_bytes=4096, timeout_seconds=2, retries=2,
        transport=lambda _u, timeout_seconds, max_bytes: HttpResponse(429, b"rl", {}),
        sleeper=lambda _s: None,
    )
    with pytest.raises(ScorecardError, match="request bound exhausted"):
        c_mid.fetch(repo)

    c_rl = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=5, max_response_bytes=4096, timeout_seconds=2, retries=0,
        transport=lambda _u, timeout_seconds, max_bytes: HttpResponse(429, b"rl", {}),
    )
    with pytest.raises(ScorecardError) as exc_rl:
        c_rl.fetch(repo)
    assert exc_rl.value.kind == "rate_limit"

    c_400 = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=5, max_response_bytes=4096, timeout_seconds=2, retries=0,
        transport=lambda _u, timeout_seconds, max_bytes: HttpResponse(400, b"bad", {}),
    )
    with pytest.raises(ScorecardError) as exc_400:
        c_400.fetch(repo)
    assert exc_400.value.kind == "request_failure"

    c_bnd = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=5, max_response_bytes=4096, timeout_seconds=2, retries=0,
        transport=lambda _u, timeout_seconds, max_bytes: (_ for _ in ()).throw(ValueError("response byte bound exceeded")),
    )
    with pytest.raises(ScorecardError) as exc_bnd:
        c_bnd.fetch(repo)
    assert exc_bnd.value.kind == "bounds"

    c_bad_norm = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=5, max_response_bytes=64, timeout_seconds=2, retries=0,
        transport=lambda _u, timeout_seconds, max_bytes: HttpResponse(200, b"not-json", {}),
    )
    with pytest.raises(ScorecardError, match="not UTF-8 JSON"):
        c_bad_norm.fetch(repo)

    for bad_payload in (
        b"x" * 100,
        b"\xff\xfe",
        b"[1, 2]",
        b'{"score": true, "checks": []}',
        b'{"score": 5.0, "checks": "no"}',
    ):
        with pytest.raises(ScorecardError):
            c_bad_norm.normalize(repo, bad_payload)

    many_checks = json.dumps({"score": 5.0, "checks": [{"name": "c", "score": 1} for _ in range(1001)]}).encode()
    c_large = ScorecardClient(
        base_url="https://api.securityscorecards.dev", allowed_hosts=["api.securityscorecards.dev"],
        max_requests=5, max_response_bytes=1_000_000, timeout_seconds=2, retries=0,
    )
    with pytest.raises(ScorecardError, match="check count bound"):
        c_large.normalize(repo, many_checks)


def test_native_and_resolution_edge_branches() -> None:
    invocations = [
        {"argv": "not-a-sequence"},
        {
            "command_id": "cmd-1",
            "target": "app",
            "argv": [
                "clang", "-g2", "--configuration", "Debug", "-DCMAKE_BUILD_TYPE=Debug",
                "-L", "/usr/lib", "-l", "z", "-l", "bad name!",
                "-framework", "CoreFoundation", "-l:libssl.so.3",
                "-Wl,-lcrypto,-l,pthread", "/opt/lib/libcurl.a", "--extra",
            ],
        },
        {"argv": ["clang", "-lm"]},
    ]
    candidates, gaps = parse_native_candidates(
        invocations,
        artifacts=[{"sha256": "a" * 64, "loader_dependencies": ["libxml2.so.2"], "loader_soname": "libapp.so.1"}],
        metadata_files=[
            {"path": "notes.txt", "fields": {"Name": "ignored"}},
            {"path": "cmake/FooConfig.cmake", "sha256": "b" * 64,
             "fields": {"Name": "FooConfig", "Version": "2.0", "URL": "https://github.com/org/foo"}},
        ],
        max_candidates=20,
        max_tokens_per_command=16,
    )
    assert any("no argv" in g for g in gaps)
    assert any("exceeds command token bound" in g for g in gaps)
    names = {c["native_name"].casefold() for c in candidates}
    assert {"z", "corefoundation", "ssl", "crypto", "pthread", "xml2", "app", "foo"} <= names

    _, bound_gaps = parse_native_candidates(
        [{"argv": ["cc", "-lz"]}, {"argv": ["cc", "-lm"]}], max_candidates=1
    )
    assert any("candidate bound exceeded" in g for g in bound_gaps)

    # repository_identity & deduplicate_repositories
    assert repository_identity("", supported_hosts=["github.com"]) is None
    assert repository_identity("https://github.com/org/repo\x00", supported_hosts=["github.com"]) is None
    assert repository_identity("git@github.com:org/repo.git", supported_hosts=["github.com"]) == {
        "host": "github.com", "owner": "org", "name": "repo", "url": "https://github.com/org/repo",
    }
    assert repository_identity("git+https://github.com/org/repo.git", supported_hosts=["github.com"]) is not None
    assert repository_identity("https://user@github.com/org/repo", supported_hosts=["github.com"]) is None
    assert repository_identity("https://github.com/onlyowner", supported_hosts=["github.com"]) is None
    assert repository_identity("https://github.com/bad!owner/repo", supported_hosts=["github.com"]) is None

    with pytest.raises(ValueError, match="positive integer"):
        deduplicate_repositories([], max_repositories=0)
    dedup, d_gaps = deduplicate_repositories(
        [
            {"dependency_id": "d0", "repository": None},
            {"dependency_id": "d0b", "repository": {"host": "github.com", "owner": "", "name": "x"}},
            {"dependency_id": "d1", "repository": {"host": "github.com", "owner": "a", "name": "one"}},
            {"dependency_id": "d2", "repository": {"host": "github.com", "owner": "b", "name": "two"}},
        ],
        max_repositories=1,
    )
    assert len(dedup) == 1 and d_gaps and d_gaps[0]["kind"] == "repository_bound"

    # Exposure & normalize_dependencies
    exp = infer_maximal_exposure(
        {
            "scope": True,
            "observations": [
                "not-a-mapping",
                {"kind": "loader_needed", "command_id": "c1", "configuration": "devDependencies"},
            ],
        },
        "native",
    )
    assert any(e["basis"] == "runtime-loader" for e in exp)

    deps, n_gaps = normalize_dependencies(
        declared=[
            {"name": ""},
            {"name": "alpha", "purl": "pkg:pypi/alpha@1.0"},
            {"name": "alpha", "version": "1.0", "purl": "pkg:pypi/alpha@1.0",
             "repository_url": "https://github.com/org/alpha"},
        ],
        packages=[{"package": "beta", "purl": "pkg:npm/beta", "repository_url": "https://internal.corp/b"}],
        native=[{
            "candidate_id": "nc-1", "native_name": "gamma", "root_id": "target", "package_root": "vendor/gamma",
            "release": {"status": "corroborated", "value": "3.1", "evidence_ids": ["e1"]},
            "observations": [{"evidence_id": "e1"}],
        }],
        supported_hosts=["github.com"],
        max_dependencies=2,
    )
    assert len(deps) == 2
    assert any("no usable identity" in g for g in n_gaps)
    assert any("dependency bound exceeded" in g for g in n_gaps)

    # apply_model_resolution negative checks
    base_dep = {
        "dependency_id": "dep-g", "name": "gamma",
        "observations": ["skip", {"evidence_id": "e1"}],
        "native_candidate": {"candidate_id": "nc-1", "observations": ["skip", {"command_id": "cmd-1"}]},
    }
    with pytest.raises(ValueError, match="no native candidate"):
        apply_model_resolution({"dependency_id": "x"}, {}, supported_hosts=["github.com"])
    for bad_prop, msg in (
        ({"schema": "bad"}, "schema or candidate"),
        ({"schema": PROPOSAL_SCHEMA, "candidate_id": "nc-1", "repository": None}, "absent or unsupported"),
        ({"schema": PROPOSAL_SCHEMA, "candidate_id": "nc-1",
          "repository": {"host": "github.com", "owner": "WRONG", "name": "g", "url": "https://github.com/o/g"}},
         "inconsistent"),
        ({"schema": PROPOSAL_SCHEMA, "candidate_id": "nc-1",
          "repository": {"host": "github.com", "owner": "o", "name": "g", "url": "https://github.com/o/g"},
          "evidence_refs": ["unowned"]},
         "outside the candidate"),
        ({"schema": PROPOSAL_SCHEMA, "candidate_id": "nc-1",
          "repository": {"host": "github.com", "owner": "o", "name": "g", "url": "https://github.com/o/g"},
          "evidence_refs": ["cmd-1"], "confidence": True},
         "between 0 and 0.95"),
    ):
        with pytest.raises(ValueError, match=msg):
            apply_model_resolution(base_dep, bad_prop, supported_hosts=["github.com"])


def test_native_inference_integration_and_publication_validation_branches(tmp_path: Path) -> None:
    target = tmp_path / "target"
    ctx, run_root, _ = _make_job_context(tmp_path, target_root=target)
    _seed_upstreams(run_root, target)
    ctx_no_inf = replace(
        ctx,
        config=replace(
            ctx.config,
            settings={**ctx.config.settings, "native_inference": {**ctx.config.settings["native_inference"], "enabled": False}},
        ),
    )

    with pytest.raises(ValueError, match="explicit enabled setting"):
        inference_bounds({"native_inference": {"enabled": "yes"}})
    with pytest.raises(ValueError, match="do not match the typed bounds"):
        inference_bounds({"native_inference": {"enabled": True}})

    unit_root = ctx.attempt_root / "steps" / "resolution" / "tasks" / "curate_components"
    unit_root.mkdir(parents=True, exist_ok=True)
    small_ctx = replace(ctx, config=replace(ctx.config, settings={**ctx.config.settings, "sbom_output_bytes": 10}))
    small_unit = UnitContext(small_ctx, "resolution.curate_components", "resolution", "curate_components", unit_root, {})
    with pytest.raises(ValueError, match="exceeds the publication byte bound"):
        publish_inference_unit(
            small_unit, {"discovery": {}, "metrics": {}, "gaps": []}, None, started=0.0, input_document={}
        )

    normal_unit = UnitContext(ctx, "resolution.curate_components", "resolution", "curate_components", unit_root, {})
    with pytest.raises(ValueError, match="unsupported counters"):
        publish_inference_unit(
            normal_unit, {"discovery": {}, "metrics": {"bogus": 1}, "gaps": []}, None, started=0.0, input_document={}
        )
    with pytest.raises(ValueError, match="nonnegative integers"):
        publish_inference_unit(
            normal_unit, {"discovery": {}, "metrics": {"model_calls": -1}, "gaps": []}, None, started=0.0, input_document={}
        )

    # Execute full job to obtain a valid published handoff & receipts, then exercise tamper/negative branches
    job = build_job(
        infer=lambda _r, timeout_seconds: ModelResult({
            "schema": PROPOSAL_SCHEMA, "candidate_id": "none", "repository": None,
            "confidence": 0, "evidence_refs": [], "rationale": "n",
        }),
        scorecard_transport=lambda _u, timeout_seconds, max_bytes: HttpResponse(404, b"{}", {}),
        syft_converter=_converter,
    )
    with _owner_scope(ctx_no_inf):
        result = job.handler(ctx_no_inf)
    h_path = _publish_result_as_handoff(ctx_no_inf, result)
    framework = json.loads(h_path.read_bytes())
    pub_ref = framework["outputs"]["acceptance.publish_handoff"]["artifact"]
    pub_doc = json.loads((run_root / pub_ref["path"]).read_bytes())
    validate_publication(run_root, framework, pub_doc)

    # validate_inference_receipt negative checks
    rcpt_ref = pub_doc["sbom"]["inference_metrics"][0]
    rcpt_doc = json.loads((run_root / rcpt_ref["path"]).read_bytes())
    big_rcpt = run_root / "big-rcpt.json"
    big_rcpt.write_bytes(b" " * 70000)
    with pytest.raises(ValueError, match="exceed their byte bound"):
        validate_inference_receipt(run_root, reference(run_root, big_rcpt), source_fingerprint=SNAPSHOT)

    for bad_rcpt, match in (
        ({**rcpt_doc, "status": "BOGUS"}, "disposition/fingerprint"),
        ({**rcpt_doc, "counters": {**rcpt_doc["counters"], "unknown_usage_calls": 5}}, "counters are invalid"),
        ({**rcpt_doc, "duration_ms": -1}, "timing/usage accounting"),
        ({**rcpt_doc, "status": "SUCCEEDED", "gaps_by_kind": {"bounds": 1}}, "coverage accounting"),
    ):
        p = _write(run_root, "bad-inf-rcpt.json", bad_rcpt)
        with pytest.raises(ValueError, match=match):
            validate_inference_receipt(run_root, p, source_fingerprint=SNAPSHOT)

    bad_manifest = _write(run_root, "bad-manifest.json", {"schema": "wrong"})
    p_bad_man = _write(run_root, "rcpt-bad-man.json", {**rcpt_doc, "model_artifacts": bad_manifest})
    with pytest.raises(ValueError, match="manifest schema changed"):
        validate_inference_receipt(run_root, p_bad_man, source_fingerprint=SNAPSHOT)

    # validate_publication negative checks
    with pytest.raises(ValueError, match="standard/schema identity"):
        validate_publication(run_root, framework, {**pub_doc, "sbom": {**pub_doc["sbom"], "format": "cyclonedx"}})

    bad_disc = _write(run_root, "bad-disc.json", {"schema": "wrong", "source_fingerprint": SNAPSHOT})
    with pytest.raises(NativeInputIntegrityError, match="discovery snapshot changed"):
        validate_publication(
            run_root, {**framework, "artifacts": [*framework["artifacts"], bad_disc]},
            {**pub_doc, "native_discovery": bad_disc},
        )

    bad_prov = _write(run_root, "bad-prov.json", {"schema": "wrong"})
    with pytest.raises(ValueError, match="provenance schema changed"):
        validate_publication(
            run_root, {**framework, "artifacts": [*framework["artifacts"], bad_prov]},
            {**pub_doc, "sbom": {**pub_doc["sbom"], "provenance": bad_prov}},
        )

    bad_unity = _write(run_root, "bad-unity.json", {"schema": "wrong", "source_fingerprint": SNAPSHOT})
    with pytest.raises(NativeInputIntegrityError, match="Unity inventory schema/snapshot"):
        validate_publication(
            run_root, {**framework, "artifacts": [*framework["artifacts"], bad_unity]},
            {**pub_doc, "unity_inventory": bad_unity},
        )

    bad_metrics = _write(run_root, "bad-metrics.json", {"schema": "wrong"})
    with pytest.raises(ValueError, match="metrics binding changed"):
        validate_publication(
            run_root, {**framework, "artifacts": [*framework["artifacts"], bad_metrics]},
            {**pub_doc, "sbom": {**pub_doc["sbom"], "metrics": bad_metrics}},
        )

    orig_metrics = json.loads((run_root / pub_doc["sbom"]["metrics"]["path"]).read_bytes())
    m_bad_sha = _write(run_root, "m-bad-sha.json", {**orig_metrics, "sbom_sha256": "0" * 64})
    with pytest.raises(ValueError, match="status/hash changed"):
        validate_publication(
            run_root, {**framework, "artifacts": [*framework["artifacts"], m_bad_sha]},
            {**pub_doc, "sbom": {**pub_doc["sbom"], "metrics": m_bad_sha}},
        )

    m_no_doc = _write(run_root, "m-no-doc.json", {**orig_metrics, "status": "SUCCEEDED", "sbom_sha256": None})
    with pytest.raises(ValueError, match="no standard document"):
        validate_publication(
            run_root, {**framework, "artifacts": [*framework["artifacts"], m_no_doc]},
            {**pub_doc, "sbom": {**pub_doc["sbom"], "artifact": None, "status": "SUCCEEDED", "metrics": m_no_doc}},
        )

    # collect_inputs snapshot/schema mismatch branches
    load_unit = UnitContext(ctx_no_inf, "inputs.load_accepted", "inputs", "load_accepted", unit_root, {})
    with pytest.raises(NativeInputIntegrityError, match="receipts differ"):
        collect_inputs(load_unit, [{"build_unit_id": "unexpected"}])


def test_curation_discovery_and_investigation_validation_branches(tmp_path: Path) -> None:
    bounds = NativeBounds(10, 10, 2, 64, 96, 10, 50, 20, 128, 128)
    inf_bounds = NativeInferenceBounds(
        batch_candidates=4, max_payload_bytes=4096, max_calls=8,
        component_limit=1, group_limit=4, files_per_root=4,
        bytes_per_file=1024, source_bytes_limit=4096, field_bytes=64,
    )
    upstream_ref = {"path": "data/part.json", "sha256": "a" * 64, "size_bytes": 10}

    # discovery helper checks
    with pytest.raises(ValueError):
        _text("bad\x01", "lbl")
    with pytest.raises(ValueError):
        _reference("not-a-map")
    with pytest.raises(ValueError):
        _reference({"path": "a", "sha256": "short", "size_bytes": 1})
    with pytest.raises(ValueError):
        _reference({"path": "a", "sha256": "a" * 64, "size_bytes": -1})
    with pytest.raises(ValueError):
        _domain({"domain": "cloud"})
    with pytest.raises(ValueError):
        _pointer("no-slash")
    with pytest.raises(ValueError):
        _pointer("/bad~2escape")

    # discover_native_dependencies input validation errors
    with pytest.raises(ValueError):
        discover_native_dependencies(source_fingerprint=SNAPSHOT, files=[], invocations=[], artifacts=[],
                                     read_file="no", bounds=bounds)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        discover_native_dependencies(source_fingerprint=SNAPSHOT, files="bad", invocations=[], artifacts=[],  # type: ignore[arg-type]
                                     read_file=lambda _f, _l: b"", bounds=bounds)
    for bad_files, exc_type in (
        (["not-map"], ValueError),
        ([{"root_id": "target", "path": "a.h", "sha256": "a" * 64, "size_bytes": 1, "upstream": upstream_ref, "backing": None}], ValueError),
        ([{"domain": "target", "root_id": "target", "path": "a.h", "sha256": "a" * 64, "size_bytes": 1, "upstream": upstream_ref}], ValueError),
        ([{"domain": "workspace", "root_id": "w", "path": "a.h", "sha256": "a" * 64, "size_bytes": 1,
           "upstream": upstream_ref, "backing": {"path": "b", "sha256": "b" * 64, "size_bytes": 1}}], NativeInputIntegrityError),
    ):
        with pytest.raises(exc_type):
            discover_native_dependencies(source_fingerprint=SNAPSHOT, files=bad_files, invocations=[], artifacts=[],  # type: ignore[arg-type]
                                         read_file=lambda _f, _l: b"", bounds=bounds)

    ev_src = {"artifact": upstream_ref, "json_pointer": "/rows/0"}
    for bad_inv, exc_type in (
        (["not-map"], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": []}], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc\x00"]}], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "argv_sha256": "0" * 64}], NativeInputIntegrityError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "expanded_argv": []}], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "expanded_argv": ["cc"], "expanded_argv_sha256": "0" * 64}], NativeInputIntegrityError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "path_mappings": "bad"}], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "path_mappings": {"rel/path": "."}}], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "path_mappings": {"/abs": 123}}], ValueError),
        ([{"root_id": "target", "evidence_source": ev_src, "argv": ["cc"], "path_mappings": {"/abs": {"root_id": "t", "path": "."}}}], ValueError),
    ):
        with pytest.raises(exc_type):
            discover_native_dependencies(source_fingerprint=SNAPSHOT, files=[], invocations=bad_inv, artifacts=[],  # type: ignore[arg-type]
                                         read_file=lambda _f, _l: b"", bounds=bounds)

    for bad_art in (
        ["not-map"],
        [{"root_id": "target", "evidence_source": ev_src, "path": "a.so", "sha256": "bad"}],
        [{"root_id": "target", "evidence_source": ev_src, "path": "a.so", "loader_dependencies": "bad"}],
        [{"root_id": "target", "evidence_source": ev_src, "path": "a.so", "loader_soname": 123}],
    ):
        with pytest.raises(ValueError):
            discover_native_dependencies(source_fingerprint=SNAPSHOT, files=[], invocations=[], artifacts=bad_art,  # type: ignore[arg-type]
                                         read_file=lambda _f, _l: b"", bounds=bounds)

    # Exercise discovery command response file, unmapped paths, escaping '..', file omissions, and read OSError
    f_payloads = {
        "pkg/README": b"Package: pkg\nVersion: 1.0.0\n",
        "pkg/big.cmake": b"#" * 80,
        "pkg/a.pc": b"Name: pkg\nVersion: 1.0.0\n",
        "pkg/b.pc": b"Name: pkg\nVersion: 1.0.0\n",
        "pkg/err.pc": b"Name: pkg\n",
    }
    disc_files = [
        {
            "domain": "target", "root_id": "target", "path": p,
            "sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b),
            "upstream": upstream_ref, "backing": None,
        }
        for p, b in f_payloads.items()
    ]
    cmd = {
        "root_id": "target", "domain": "target", "directory": ".",
        "argv": ["cc", "@args.rsp", "-I/unmapped/inc", "-I../escape", "-Ipkg", "-c", "main.c"],
        "path_mappings": {"/target": "."},
        "evidence_source": ev_src,
    }

    def reader(rec: dict[str, Any], _lim: int) -> bytes:
        if rec["path"].endswith("err.pc"):
            raise OSError("disk error")
        return f_payloads[rec["path"]]

    disc = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=disc_files, invocations=[cmd], artifacts=[],
        read_file=reader, bounds=NativeBounds(10, 4, 2, 64, 70, 10, 50, 20, 256, 256),
    )
    assert disc["metrics"]["commands_truncated"] == 1
    gap_kinds = {g["kind"] for g in disc["gaps"]}
    assert {"unsupported_response_file", "unmapped_path"} <= gap_kinds

    # Curation validation & conflict branches
    full_disc = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=disc_files[:1],
        invocations=[{"root_id": "target", "domain": "target", "directory": ".",
                      "argv": ["cc", "-Ipkg", "-lpkg", "-lpkg2"], "evidence_source": ev_src}],
        artifacts=[], read_file=lambda r, _l: f_payloads[r["path"]],
        bounds=NativeBounds(10, 20, 10, 1024, 4096, 10, 50, 20, 256, 256),
    )
    with pytest.raises(ValueError):
        curate_native_components(full_disc, disc_files[:1], propose="bad", bounds=inf_bounds)  # type: ignore[arg-type]
    with pytest.raises(NativeInputIntegrityError):
        _Curation({**full_disc, "schema": "bad"}, [], inf_bounds)
    with pytest.raises(ValueError):
        _Curation(full_disc, "bad", inf_bounds)  # type: ignore[arg-type]

    curator = _Curation(deepcopy(full_disc), disc_files[:1], inf_bounds)
    cids = sorted(curator.sources)
    for bad_p in (
        "not-map",
        {"x": math.nan},
        {"schema": CURATION_SCHEMA, "input_records": len(cids), "libraries": [], "sdk_groups": [],
         "rejected_candidate_ids": [], "uncertain_candidate_ids": [], "extra": 1},
        {"schema": "bad", "input_records": len(cids), "libraries": [], "sdk_groups": [],
         "rejected_candidate_ids": [], "uncertain_candidate_ids": []},
        {"schema": CURATION_SCHEMA, "input_records": len(cids), "libraries": [], "sdk_groups": [],
         "rejected_candidate_ids": [cids[0]], "uncertain_candidate_ids": [cids[0]]},
        {"schema": CURATION_SCHEMA, "input_records": len(cids), "libraries": "bad", "sdk_groups": [],
         "rejected_candidate_ids": [], "uncertain_candidate_ids": []},
        {"schema": CURATION_SCHEMA, "input_records": len(cids), "libraries": [{}], "sdk_groups": [],
         "rejected_candidate_ids": [], "uncertain_candidate_ids": []},
    ):
        with pytest.raises(Exception):
            curator.validate(bad_p, cids)

    # Investigation manifests (pyproject.toml, Cargo.toml, Info.plist) + unsubstantiated PURL demotion
    inv_payloads = {
        "pkg/pyproject.toml": b'[project]\nname = "My_Pkg"\nversion = "1.2.3"\nlicense = "MIT"\n',
        "pkg2/Cargo.toml": b'[package]\nname = "pkg2"\nversion = "0.4.0"\nrepository = "https://github.com/o/pkg2"\n',
        "Foo.framework/Info.plist": (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<plist version="1.0"><dict>'
            b'<key>CFBundleIdentifier</key><string>org.example.Foo</string>'
            b'<key>CFBundleShortVersionString</key><string>2.1.0</string>'
            b'</dict></plist>\n'
        ),
    }
    inv_files = [
        {
            "domain": "target", "root_id": "target", "path": p,
            "sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b),
            "upstream": upstream_ref, "backing": None,
        }
        for p, b in inv_payloads.items()
    ]
    inv_disc = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=inv_files,
        invocations=[{
            "root_id": "target", "domain": "target", "directory": ".",
            "argv": ["cc", "-Ipkg", "-lmy_pkg", "-Ipkg2", "-lpkg2", "-IFoo.framework", "-framework", "Foo"],
            "evidence_source": ev_src,
        }],
        artifacts=[], read_file=lambda r, _l: inv_payloads[r["path"]],
        bounds=NativeBounds(20, 30, 20, 4096, 16384, 20, 100, 40, 512, 512),
    )
    # Inject an unsubstantiated purl on one candidate + an oversized native_name candidate
    inv_disc["candidates"][0]["purl"] = "pkg:generic/unsubstantiated@9.9.9"
    with pytest.raises(ValueError):
        investigate_native_metadata(inv_disc, "bad", read_file=lambda r, _l: b"", propose=None, bounds=inf_bounds)  # type: ignore[arg-type]

    def plan_all(stage: str, payload: Any) -> dict[str, Any]:
        if stage == "plan":
            return {
                "schema": payload["schema"],
                "candidate_id": payload["candidate_id"],
                "files": list(payload["available_files"]),
                "version_patterns": [],
            }
        first_file = payload["files"][0]
        return {
            "schema": payload["schema"],
            "candidate_id": payload["candidate_id"],
            "claims": [
                {
                    "field": "version",
                    "value": "2.1.0",
                    "citations": [{"path": first_file["path"], "start_line": 1, "end_line": len(first_file["lines"])}],
                },
            ],
        }

    inv_res = investigate_native_metadata(
        deepcopy(inv_disc), inv_files,
        read_file=lambda r, _l: inv_payloads[r["path"]],
        propose=plan_all,
        bounds=NativeInferenceBounds(component_limit=3, field_bytes=256),
    )
    assert any("unsubstantiated or inconsistent existing PURL" in g["detail"] for g in inv_res["gaps"])
    inv_bounded = investigate_native_metadata(
        deepcopy(inv_disc), inv_files,
        read_file=lambda r, _l: inv_payloads[r["path"]],
        propose=plan_all,
        bounds=NativeInferenceBounds(component_limit=1, field_bytes=256),
    )
    assert inv_bounded["metrics"]["omitted_candidates"] >= 1


def test_remaining_module_branch_thresholds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import appsec_review.jobs.job_dependency_intelligence.integration as integ_mod

    upstream_ref = {"path": "data/part.json", "sha256": "a" * 64, "size_bytes": 10}
    ev_src = {"artifact": upstream_ref, "json_pointer": "/rows/0"}
    bounds = NativeBounds(20, 30, 10, 2048, 8192, 20, 100, 40, 256, 256)
    inf_bounds = NativeInferenceBounds(component_limit=6, field_bytes=256)

    # 1. discovery.py mapped_path & fact branches (empty path, string prefix map, '..' pop, ':' in part, invalid pkg name)
    map_cmd = {
        "root_id": "target", "domain": "target", "directory": ".",
        "argv": [
            "cc",
            "-I", "",
            "-I/srcroot/sub",
            "-Isub/../clean",
            "-Ibad:colon",
            "-lbad!name",
            "-Ipkg", "-lpkg_a", "-lpkg_b",
        ],
        "path_mappings": {"/srcroot": "mapped"},
        "evidence_source": ev_src,
    }
    pkg_bytes = b"Name: pkg_a\nVersion: 1.0.0\n"
    pkg_files = [{
        "domain": "target", "root_id": "target", "path": "pkg/pkg_a.pc",
        "sha256": hashlib.sha256(pkg_bytes).hexdigest(), "size_bytes": len(pkg_bytes),
        "upstream": upstream_ref, "backing": None,
    }]
    disc = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=pkg_files, invocations=[map_cmd], artifacts=[],
        read_file=lambda _r, _l: pkg_bytes, bounds=bounds,
    )
    assert any(g["kind"] == "unmapped_path" for g in disc["gaps"])
    assert any(g["kind"] == "unsupported_metadata" for g in disc["gaps"])

    # 2. curation.py _validate_inputs error branches & duplicate effective component merge + conflicts
    with pytest.raises(NativeInputIntegrityError, match="conflicting accepted native file"):
        _Curation(deepcopy(disc), [pkg_files[0], {**pkg_files[0], "size_bytes": 999}], inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="Unbound or changed native evidence"):
        bad_ev = deepcopy(disc)
        bad_ev["evidence"][0]["evidence_id"] = "native-evidence-" + "0" * 64
        _Curation(bad_ev, pkg_files, inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="differs from accepted catalog"):
        _Curation(
            deepcopy(disc),
            [{**pkg_files[0], "sha256": "b" * 64}],
            inf_bounds,
        )
    with pytest.raises(NativeInputIntegrityError, match="mixes source fingerprints"):
        mix_fp = deepcopy(disc)
        mix_fp["source_fingerprint"] = "sha256:" + "9" * 64
        _Curation(mix_fp, pkg_files, inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="Conflicting native candidate ID"):
        dup_cand = deepcopy(disc)
        dup_cand["candidates"].append({**dup_cand["candidates"][0], "native_name": "other"})
        _Curation(dup_cand, pkg_files, inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="Unknown native claim status"):
        bad_st = deepcopy(disc)
        bad_st["candidates"][0]["release"]["status"] = "bogus"
        _Curation(bad_st, pkg_files, inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="Unsupported corroborated native claim"):
        bad_cor = deepcopy(disc)
        bad_cor["candidates"][0]["release"] = {"value": "", "status": "corroborated", "evidence_ids": [], "alternatives": []}
        _Curation(bad_cor, pkg_files, inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="Unknown native evidence reference"):
        bad_ref = deepcopy(disc)
        bad_ref["candidates"][0]["evidence_ids"].append("native-evidence-" + "f" * 64)
        _Curation(bad_ref, pkg_files, inf_bounds)
    with pytest.raises(NativeInputIntegrityError, match="Unknown native gap evidence reference"):
        bad_gap = deepcopy(disc)
        bad_gap["gaps"].append({"kind": "bounds", "scope": "s", "detail": "d", "evidence_ids": ["native-evidence-" + "e" * 64]})
        _Curation(bad_gap, pkg_files, inf_bounds)

    # Merge two candidates in same locality into same component_id ("pkg_a") with conflicted claims
    merge_disc = deepcopy(disc)
    ev_id = merge_disc["evidence"][0]["evidence_id"]
    c0, c1 = merge_disc["candidates"][0], merge_disc["candidates"][1]
    c0["package_root"] = c1["package_root"] = "pkg"
    c0["native_name"] = "pkg_a"
    c1["native_name"] = "pkg_a"
    c0["identity"] = {"value": "pkg_a", "status": "corroborated", "evidence_ids": [ev_id], "alternatives": []}
    c1["identity"] = {"value": "pkg_alt", "status": "corroborated", "evidence_ids": [ev_id], "alternatives": []}
    c0["release"] = {"value": "1.0.0", "status": "corroborated", "evidence_ids": [ev_id], "alternatives": []}
    c1["release"] = {"value": "2.0.0", "status": "corroborated", "evidence_ids": [ev_id], "alternatives": []}
    c0["upstream"] = {"value": "https://github.com/o/a", "status": "corroborated", "evidence_ids": [ev_id], "alternatives": []}
    c1["upstream"] = {"value": "https://github.com/o/b", "status": "corroborated", "evidence_ids": [ev_id], "alternatives": []}
    c0["metadata"]["version"] = "1.0.0"
    c0["metadata"]["repository_url"] = "https://github.com/o/a"
    curator = _Curation(merge_disc, pkg_files, inf_bounds)
    curator.make_context(c0["candidate_id"])
    curator.make_context(c1["candidate_id"])
    curator.add_component("pkg_a", "library", [c0["candidate_id"]], ["pkg/pkg_a.pc"], "curated")
    curator.add_component("pkg_a", "sdk-component", [c1["candidate_id"]], ["pkg/pkg_a.pc"], "fallback", conservative=True)
    cur_gaps = {g["kind"] for g in curator.gaps}
    assert {"identity_conflict", "version_conflict", "repository_conflict"} <= cur_gaps

    # 3. investigation.py plist edge cases + supplier / download_location / license_declared claim validation
    plist_payloads = {
        "A.framework/Info.plist": b'<!DOCTYPE plist [<!ENTITY x "y">]><plist version="1.0"><dict/></plist>',
        "B.framework/Info.plist": b'<notplist/>',
        "C.framework/Info.plist": b'<plist version="1.0"><dict><key>only_key</key></dict></plist>',
        "D.framework/Info.plist": (
            b'<plist version="1.0"><dict>'
            b'<key>CFBundleName</key><string>Mismatch</string>'
            b'<key>CFBundleIdentifier</key><string>org.example.D</string>'
            b'<key>CFBundleShortVersionString</key><string>1.0.0</string>'
            b'</dict></plist>'
        ),
    }
    p_files = [
        {
            "domain": "target", "root_id": "target", "path": p,
            "sha256": hashlib.sha256(b).hexdigest(), "size_bytes": len(b),
            "upstream": upstream_ref, "backing": None,
        }
        for p, b in plist_payloads.items()
    ]
    p_disc = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=p_files,
        invocations=[{
            "root_id": "target", "domain": "target", "directory": ".",
            "argv": [
                "cc",
                "-IA.framework", "-framework", "A",
                "-IB.framework", "-framework", "B",
                "-IC.framework", "-framework", "C",
                "-ID.framework", "-framework", "D",
            ],
            "evidence_source": ev_src,
        }],
        artifacts=[], read_file=lambda r, _l: plist_payloads[r["path"]], bounds=bounds,
    )

    def propose_extra_fields(stage: str, payload: Any) -> dict[str, Any]:
        if stage == "plan":
            return {
                "schema": payload["schema"], "candidate_id": payload["candidate_id"],
                "files": list(payload["available_files"]), "version_patterns": [],
            }
        f0 = payload["files"][0]
        cite = [{"path": f0["path"], "start_line": 1, "end_line": len(f0["lines"])}]
        return {
            "schema": payload["schema"], "candidate_id": payload["candidate_id"],
            "claims": [
                {"field": "supplier", "value": "Organization: Example", "citations": cite},
                {"field": "download_location", "value": "https://example.com/a.tar.gz", "citations": cite},
                {"field": "license_declared", "value": "NOASSERTION", "citations": cite},
                {"field": "purl", "value": "pkg:generic/a@1.0.0", "citations": cite},
            ],
        }

    p_inv = investigate_native_metadata(
        p_disc, p_files, read_file=lambda r, _l: plist_payloads[r["path"]],
        propose=propose_extra_fields, bounds=inf_bounds,
    )
    assert len(p_inv["findings"]) >= 4

    # 4. integration.py collect_inputs edge branches via monkeypatched accepted_framework
    run_root = tmp_path / "integ-collect"
    (run_root / "ws" / "u1").mkdir(parents=True)
    (run_root / "ws" / "u1" / "gen.h").write_bytes(b"#define V 1\n")
    gen_sha = hashlib.sha256(b"#define V 1\n").hexdigest()

    part_ref = _write(run_root, "data/cat/partition.json", {
        "schema": "appsec-review/repository-partition/1",
        "source_fingerprint": SNAPSHOT,
        "files": [],
        "gaps": ["cat-gap"],
        "configured_exclusions": ["vendor/**"],
    })
    cat_ref = _write(run_root, "data/cat/catalog.json", {
        "source_fingerprint": SNAPSHOT,
        "artifacts": {"repository_discovery.partition_repository": part_ref},
    })
    prot_ref = _write(run_root, "data/lang/protected.json", {
        "schema": "appsec-review/protected-compile-commands/1",
        "rows": [
            {"argv": []},
            {"argv": ["cc", "-c", "a.c"], "directory": "/target/sub"},
            {"argv": ["cc", "-c", "b.c"], "directory": "/unmapped/abs"},
        ],
    })
    prot_jvm_ref = _write(run_root, "data/lang/protected_jvm.json", {
        "schema": "appsec-review/protected-compile-commands/1",
        "rows": [{"argv": ["javac", "Main.java"], "directory": "/workspace"}],
    })
    ws_man_ref = _write(run_root, "data/lang/ws_manifest.json", {"files": {"gen.h": gen_sha}})
    receipts = [
        {
            "build_unit_id": "u1", "family": "native", "workspace": "ws/u1",
            "protected_compile_commands": prot_ref, "workspace_manifest": ws_man_ref,
            "artifacts": [{"workspace_path": "libfoo.so"}],
        },
        {
            "build_unit_id": "u2", "family": "jvm",
            "protected_compile_commands": prot_jvm_ref, "artifacts": [],
        },
    ]
    lang_ref = _write(run_root, "data/lang/pub.json", {
        "source_fingerprint": SNAPSHOT, "receipts": receipts, "gaps": ["lang-gap"],
    })
    art_ref = _write(run_root, "data/art/pub.json", {
        "source_fingerprint": SNAPSHOT,
        "target_artifacts": [{"path": "bin/prebuilt.so"}],
        "gaps": ["art-gap"],
    })
    syft_raw_ref = _write(run_root, "data/ev/syft-raw.json", {"artifacts": [], "source": {"type": "directory", "target": "."}})
    syft_env_ref = _write(run_root, "data/ev/syft-env.json", {
        "target_fingerprint": SNAPSHOT,
        "source_inventory": syft_raw_ref,
        "raw_artifacts": [syft_raw_ref],
        "exclusions_and_gaps": ["syft-gap"],
    })

    from appsec_review.config.loader import load_config

    (run_root / "unit").mkdir(parents=True)
    (run_root / "target").mkdir(parents=True)
    fake_handoffs = {
        "job_target_catalog": {
            "source_fingerprint": SNAPSHOT,
            "started_at": "2026-01-01T00:00:00Z",
            "outputs": {"publish_catalog.publish_handoff": {"artifact": cat_ref}},
            "artifacts": [cat_ref, part_ref],
        },
        "job_language_build": {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"acceptance.publish_handoff": {"artifact": lang_ref}},
            "artifacts": [lang_ref, prot_ref, prot_jvm_ref, ws_man_ref],
        },
        "job_artifact_indexing": {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"acceptance.publish_handoff": {"artifact": art_ref}},
            "artifacts": [art_ref],
        },
        "job_evidence_collection": {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"software_inventory.syft_scan": {"terminal_status": "COMPLETED_WITH_GAPS", "artifact": syft_env_ref}},
            "artifacts": [syft_env_ref, syft_raw_ref],
        },
    }
    monkeypatch.setattr(
        integ_mod,
        "accepted_framework",
        lambda _rr, jid, _lim: (fake_handoffs[jid], _write(run_root, f"handoffs/{jid}.json", fake_handoffs[jid])),
    )
    job_cfg = load_config(ROOT / "appsec-review.toml").jobs["job_dependency_intelligence"]
    dummy_unit = type("U", (), {
        "unit_root": run_root / "unit",
        "job": type("J", (), {
            "run_root": run_root,
            "target_root": run_root / "target",
            "source_fingerprint": SNAPSHOT,
            "config": job_cfg,
        })(),
    })()
    collected = integ_mod.collect_inputs(dummy_unit, receipts)  # type: ignore[arg-type]
    assert len(collected["native_invocations"]) == 1
    assert len(collected["native_artifacts"]) == 2
    inh_kinds = {g["kind"] for g in collected["native_gaps"]}
    assert {"upstream_partial", "unsupported_metadata", "unmapped_path", "artifact_inventory_not_merged"} <= inh_kinds
    fake_handoffs["job_target_catalog"]["started_at"] = "2026-01-01T00:00:00"
    (run_root / "unit2").mkdir(parents=True)
    dummy_unit.unit_root = run_root / "unit2"  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="lacks timezone"):
        integ_mod.collect_inputs(dummy_unit, receipts)  # type: ignore[arg-type]
    fake_handoffs["job_target_catalog"]["started_at"] = "2026-01-01T00:00:00Z"

    arr_ref = _write(run_root, "data/arr.json", [1, 2, 3])
    with pytest.raises(ValueError, match="must be an object"):
        integ_mod.read_json(run_root, arr_ref, 1024)

    other_fp = "sha256:" + "9" * 64
    bad_cat = _write(run_root, "data/cat/bad_cat.json", {"source_fingerprint": other_fp, "artifacts": {}})
    bad_part = _write(run_root, "data/cat/bad_part.json", {"schema": "bad", "source_fingerprint": SNAPSHOT})
    cat_for_bad_part = _write(run_root, "data/cat/cat_bp.json", {
        "source_fingerprint": SNAPSHOT,
        "artifacts": {"repository_discovery.partition_repository": bad_part},
    })
    bad_lang = _write(run_root, "data/lang/bad_pub.json", {"source_fingerprint": other_fp, "receipts": receipts})
    bad_prot = _write(run_root, "data/lang/bad_prot.json", {"schema": "bad", "rows": []})
    bad_prot_receipts = [{**receipts[0], "protected_compile_commands": bad_prot}]
    lang_for_bad_prot = _write(run_root, "data/lang/pub_bp.json", {"source_fingerprint": SNAPSHOT, "receipts": bad_prot_receipts})
    bad_art_doc = _write(run_root, "data/art/bad_pub.json", {"source_fingerprint": other_fp})
    bad_syft_fp = _write(run_root, "data/ev/bad_fp.json", {"target_fingerprint": other_fp})
    bad_syft_unb = _write(run_root, "data/ev/bad_unb.json", {
        "target_fingerprint": SNAPSHOT, "source_inventory": syft_raw_ref, "raw_artifacts": [],
    })
    bad_syft_id = _write(run_root, "data/ev/bad_id.json", {
        "target_fingerprint": SNAPSHOT,
        "source_inventory": {**syft_raw_ref, "size_bytes": 999},
        "raw_artifacts": [syft_raw_ref],
    })

    for override_job, override_handoff, call_receipts, exc_cls in (
        ("job_target_catalog", {**fake_handoffs["job_target_catalog"], "source_fingerprint": other_fp}, receipts, NativeInputIntegrityError),
        ("job_target_catalog", {
            "source_fingerprint": SNAPSHOT, "started_at": "2026-01-01T00:00:00Z",
            "outputs": {"publish_catalog.publish_handoff": {"artifact": bad_cat}},
            "artifacts": [bad_cat],
        }, receipts, NativeInputIntegrityError),
        ("job_target_catalog", {
            "source_fingerprint": SNAPSHOT, "started_at": "2026-01-01T00:00:00Z",
            "outputs": {"publish_catalog.publish_handoff": {"artifact": cat_for_bad_part}},
            "artifacts": [cat_for_bad_part, bad_part],
        }, receipts, NativeInputIntegrityError),
        ("job_language_build", {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"acceptance.publish_handoff": {"artifact": bad_lang}},
            "artifacts": [bad_lang],
        }, receipts, NativeInputIntegrityError),
        ("job_language_build", {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"acceptance.publish_handoff": {"artifact": lang_for_bad_prot}},
            "artifacts": [lang_for_bad_prot, bad_prot, ws_man_ref],
        }, bad_prot_receipts, ValueError),
        ("job_artifact_indexing", {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"acceptance.publish_handoff": {"artifact": bad_art_doc}},
            "artifacts": [bad_art_doc],
        }, receipts, NativeInputIntegrityError),
        ("job_evidence_collection", {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"software_inventory.syft_scan": {"terminal_status": "SUCCEEDED", "artifact": bad_syft_fp}},
            "artifacts": [bad_syft_fp],
        }, receipts, NativeInputIntegrityError),
        ("job_evidence_collection", {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"software_inventory.syft_scan": {"terminal_status": "SUCCEEDED", "artifact": bad_syft_unb}},
            "artifacts": [bad_syft_unb],
        }, receipts, NativeInputIntegrityError),
        ("job_evidence_collection", {
            "source_fingerprint": SNAPSHOT,
            "outputs": {"software_inventory.syft_scan": {"terminal_status": "SUCCEEDED", "artifact": bad_syft_id}},
            "artifacts": [bad_syft_id, syft_raw_ref],
        }, receipts, NativeInputIntegrityError),
    ):
        patched = {**fake_handoffs, override_job: override_handoff}
        monkeypatch.setattr(
            integ_mod,
            "accepted_framework",
            lambda _rr, jid, _lim, _p=patched: (_p[jid], _write(run_root, f"handoffs/{jid}-chk.json", _p[jid])),
        )
        with pytest.raises(exc_cls):
            integ_mod.collect_inputs(dummy_unit, call_receipts)  # type: ignore[arg-type]


def test_collect_inputs_honors_working_directory_and_filters_cmake_probes_wrappers_and_unmodified_copies(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    ctx, run_root, _ = _make_job_context(tmp_path, target_root=target)
    zlib_bytes = b'#define ZLIB_VERSION "1.2.11"\n'
    ws_dir = run_root / "data/workspaces/u1"
    (ws_dir / "third_party/zlib").mkdir(parents=True, exist_ok=True)
    (ws_dir / "third_party/zlib/zlib.h").write_bytes(zlib_bytes)
    (ws_dir / "build/CMakeFiles").mkdir(parents=True, exist_ok=True)
    (ws_dir / "build/CMakeFiles/TargetDirectories.txt").write_bytes(b"internal\n")
    (ws_dir / "build/generated").mkdir(parents=True, exist_ok=True)
    gen_bytes = b"#define GEN_CFG 1\n"
    (ws_dir / "build/generated/config.h").write_bytes(gen_bytes)
    (ws_dir / "build/libsmoke_zlib.a").write_bytes(b"!<arch>\n")
    (ws_dir / "build/smoke_server").write_bytes(b"\x7fELF")

    ws_manifest = _write(
        run_root,
        "ws-manifest.json",
        {
            "schema": "appsec-review/workspace-manifest/1",
            "files": {
                "third_party/zlib/zlib.h": file_sha256(ws_dir / "third_party/zlib/zlib.h"),
                "build/CMakeFiles/TargetDirectories.txt": file_sha256(
                    ws_dir / "build/CMakeFiles/TargetDirectories.txt"
                ),
                "build/generated/config.h": file_sha256(ws_dir / "build/generated/config.h"),
                "build/libsmoke_zlib.a": file_sha256(ws_dir / "build/libsmoke_zlib.a"),
            },
        },
    )
    protected = _write(
        run_root,
        "protected-commands.json",
        {
            "schema": "appsec-review/protected-compile-commands/1",
            "rows": [
                {
                    "working_directory": "build",
                    "tool_kind": "build-driver",
                    "argv": ["/usr/bin/cmake", "-S", "/workspace", "-B", "/workspace/build"],
                },
                {
                    "working_directory": "build/CMakeFiles/CMakeScratch/TryCompile-abc",
                    "tool_kind": "compiler",
                    "argv": ["/usr/bin/cc", "-c", "testCCompiler.c", "-o", "testCCompiler.c.o"],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "compiler",
                    "argv": ["/usr/bin/cc", "-dumpmachine"],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "compiler",
                    "argv": ["/capture/wrappers/cc", "-I/workspace/third_party/zlib", "-c", "adler32.c"],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "compiler",
                    "argv": ["/usr/lib/gcc/x86_64-linux-gnu/13/cc1", "-quiet", "adler32.c"],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "compiler",
                    "argv": [
                        "/usr/bin/cc",
                        "-I/workspace/third_party/zlib",
                        "-c",
                        "/workspace/third_party/zlib/adler32.c",
                        "-o",
                        "CMakeFiles/smoke_zlib.dir/third_party/zlib/adler32.c.o",
                    ],
                    "outputs": [{"workspace_path": "build/CMakeFiles/smoke_zlib.dir/third_party/zlib/adler32.c.o"}],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "archiver",
                    "argv": ["/usr/bin/ar", "qc", "libsmoke_zlib.a", "adler32.c.o"],
                    "outputs": [{"workspace_path": "build/libsmoke_zlib.a"}],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "linker-driver",
                    "argv": ["/usr/bin/c++", "main.cpp.o", "libsmoke_zlib.a", "-o", "smoke_server"],
                    "outputs": [{"workspace_path": "build/smoke_server"}],
                },
                {
                    "working_directory": "build",
                    "tool_kind": "linker",
                    "argv": ["/usr/bin/ld", "-dynamic-linker", "/lib64/ld-linux-x86-64.so.2", "-o", "smoke_server"],
                    "outputs": [{"workspace_path": "build/smoke_server"}],
                },
            ],
        },
    )
    receipts = [
        {
            "family": "native",
            "build_unit_id": "u1",
            "workspace": ws_dir.relative_to(run_root).as_posix(),
            "workspace_manifest": ws_manifest,
            "protected_compile_commands": protected,
            "artifacts": [
                {
                    "path": (ws_dir / "build/libsmoke_zlib.a").relative_to(run_root).as_posix(),
                    "workspace_path": "build/libsmoke_zlib.a",
                    "sha256": file_sha256(ws_dir / "build/libsmoke_zlib.a"),
                    "kind": "static-library",
                    "artifact_origin": "build-output",
                },
                {
                    "path": (ws_dir / "build/smoke_server").relative_to(run_root).as_posix(),
                    "workspace_path": "build/smoke_server",
                    "sha256": file_sha256(ws_dir / "build/smoke_server"),
                    "kind": "executable",
                    "artifact_origin": "build-output",
                    "loader_dependencies": ["libc.so.6", "libcrypto.so.3"],
                },
            ],
        }
    ]
    _seed_upstreams(
        run_root,
        target,
        files={"third_party/zlib/zlib.h": zlib_bytes},
        receipts=receipts,
        receipt_extra_artifacts=[ws_manifest, protected],
    )
    unit = SimpleNamespace(job=ctx, unit_root=ctx.attempt_root / "scratch")
    unit.unit_root.mkdir(parents=True, exist_ok=True)
    collected = collect_inputs(unit, receipts)  # type: ignore[arg-type]

    invocations = collected["native_invocations"]
    assert len(invocations) == 2
    assert [row["tool_kind"] for row in invocations] == ["compiler", "linker-driver"]
    assert all(row["directory"] == "build" for row in invocations)
    assert all("build/libsmoke_zlib.a" in row.get("build_outputs", ()) for row in invocations)

    ws_files = [f["path"] for f in collected["native_files"] if f["domain"] == "workspace"]
    assert ws_files == ["build/generated/config.h"]

    ws_artifacts = [a for a in collected["native_artifacts"] if a["root_id"] == "u1"]
    assert [a["path"] for a in ws_artifacts] == ["build/smoke_server"]
    assert ws_artifacts[0]["build_output"] is True
