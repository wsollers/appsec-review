"""Focused unit regressions for Epoch-3 job_inference_security_review repairs (seq=09..12)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
import threading
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.job_inference_security_review import teams as team_handler
from appsec_review.jobs.job_inference_security_review.datasets import CONTRACT as REVIEW_CONTRACT
from appsec_review.jobs.job_inference_security_review import job as review_job_mod
from appsec_review.jobs.job_inference_security_review.job import (
    JOB_ID,
    ReviewTeamSemaphore,
)
from appsec_review.jobs.job_inference_security_review.teams import PackageWork
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    RetrievalCore,
    RetrievalGap,
    write_manifest,
)
from appsec_review.retrieval.core import RetrievalIntegrityError
from appsec_review.review.budget import JobBudget
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.lead_triage import finding_input
from appsec_review.review.lead_triage_settings import TriageSettings
from appsec_review.review.models import GapClass, IntegrityError, Lane, Role
from appsec_review.review.packages import _evidence
from appsec_review.review.references import accepted_feed_pins, load_cwe_reference
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime import inputs as runtime_inputs
from appsec_review.runtime.consume import upstream_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.acceptance import JOB, ROOT
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.review_decision_audit_consumers.source_permission_fixture import POST_BUILD, SourceRun


def _common_payload_with_exec_ref(exec_path: str) -> dict[str, object]:
    digest = "ab" * 32
    return {
        "schema": "appsec-review/observation/1",
        "observation_class": "source_sast",
        "record_kind": "finding",
        "scanner": "clang-static-analyzer",
        "rule_id": "core.DivideZero",
        "reported_severity": {"value": "high", "native": "warning", "basis": "adapter", "rule": "core.DivideZero"},
        "gap_ids": [],
        "payload_schema": "appsec-review/clang-static-output/1",
        "evidence_refs": [
            {
                "schema": "appsec-review/native-result-reference/1",
                "parser_identity": "clang-static-adapter/5",
                "complete": True,
                "artifact": {"path": f"data/shared/objects/{digest}", "sha256": digest, "size_bytes": 3},
                "selector": {"kind": "json_pointer", "value": "/diagnostics/0"},
                "execution_reference": {"path": exec_path, "sha256": digest, "size_bytes": 3},
                "retention_receipt": {
                    "path": f"data/jobs/job_clang_static_analysis/attempts/attempt_0001/shared/native-output/{digest}.json",
                    "sha256": digest,
                    "size_bytes": 3,
                },
            }
        ],
    }


def test_seq09_review_grant_memoizes_population_and_isolates_caller_mutation(monkeypatch) -> None:
    assert getattr(review_job_mod, '_REVIEW_RETRIEVAL_LIMITS', None) is not None and review_job_mod._REVIEW_RETRIEVAL_LIMITS.timeout_ms == 10_000

    calls: list[tuple[str, ...]] = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def fake_review_population(core, indexes, *, job_id):
        assert job_id == JOB_ID
        with lock:
            calls.append(tuple(indexes))
        return {
            "counts_by_kind": {"source_file": 4},
            "counts_by_index": {name: 2 for name in indexes},
            "binary": {"known_row_count": 0},
        }

    monkeypatch.setattr(team_handler, "review_population", fake_review_population)
    monkeypatch.setattr(team_handler, "populated_review_tools", lambda candidates, indexes, pop: tuple(candidates))

    settings = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    ctx = object.__new__(team_handler.ReviewContext)
    ctx.core = object()
    ctx.settings = settings
    ctx.role_tools = {Role.RED_TEAM_ANALYST.value: ("read_source",)}
    ctx._populations = {}
    ctx._lock = threading.Lock()

    def worker(order: tuple[str, ...]):
        barrier.wait(timeout=5)
        _candidates, _tools, pop = ctx.review_grant(Role.RED_TEAM_ANALYST, order)
        pop["counts_by_kind"]["source_file"] = 999
        return pop

    orders = [
        ("observations", "code_graph"),
        ("code_graph", "observations", "observations"),
        ("observations", "code_graph"),
        ("code_graph", "observations"),
        ("observations", "code_graph"),
        ("code_graph", "observations"),
    ]
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(worker, orders))

    assert calls == [("code_graph", "observations")]
    _c, _t, clean = ctx.review_grant(Role.RED_TEAM_ANALYST, ("observations", "code_graph"))
    assert clean["counts_by_kind"]["source_file"] == 4


def test_seq09_run_team_contains_pre_cell_retrieval_gap_and_propagates_integrity_error(
    tmp_path: Path, monkeypatch
) -> None:
    settings = load_config(ROOT / "appsec-review.toml").job(JOB).typed_settings
    ctx = object.__new__(team_handler.ReviewContext)
    ctx.run_root = None
    ctx.settings = settings
    ctx.budget = JobBudget(tmp_path / "budget", settings.budgets)
    ctx.semaphore = SimpleNamespace(acquire=lambda _lane: nullcontext())

    pkg_gap = PackageWork(
        package_id="pkg-gap",
        lane=Lane.LEAD,
        unit_key="src/request.cpp",
        rank=(1, "pkg-gap"),
        sha256="11" * 32,
        basis="22" * 32,
        document={"lead_menu": [{"observation_id": "obs-1"}]},
        entities=("ent-1",),
    )
    pkg_integrity = PackageWork(
        package_id="pkg-integrity",
        lane=Lane.LEAD,
        unit_key="src/session.cpp",
        rank=(2, "pkg-integrity"),
        sha256="33" * 32,
        basis="44" * 32,
        document={"lead_menu": [{"observation_id": "obs-2"}]},
        entities=("ent-2",),
    )

    def fake_route(_ctx, work: PackageWork):
        if work.package_id == "pkg-gap":
            raise RetrievalGap("dataset inventory execution-time budget exceeded")
        raise IntegrityError("corrupt guidance pin")

    monkeypatch.setattr(team_handler, "route", fake_route)

    gap_result = team_handler.run_team(ctx, pkg_gap, launch=True)
    assert gap_result.package_id == "pkg-gap"
    assert [g.gap_class for g in gap_result.gaps] == [GapClass.WORKER_GAP]
    assert gap_result.gaps[0].reason == "team failure: RetrievalGap"

    with pytest.raises(IntegrityError, match="corrupt guidance pin"):
        team_handler.run_team(ctx, pkg_integrity, launch=True)


def test_seq09_observe_shard_caches_provenance_and_still_detects_byte_tampering(
    tmp_path: Path, monkeypatch
) -> None:
    run = SourceRun(tmp_path)
    built = run.source(POST_BUILD)
    shard_dict = asdict(built.shard)
    review_cfg = load_config(ROOT / "appsec-review.toml").job(JOB_ID)

    owner_calls = 0
    real_owner = runtime_inputs.input_shard_owner

    def counting_owner(root: Path, shard):
        nonlocal owner_calls
        owner_calls += 1
        return real_owner(root, shard)

    monkeypatch.setattr(runtime_inputs, "input_shard_owner", counting_owner)

    pins = {POST_BUILD[0]: built.accepted.sha256}
    read_ctx = SimpleNamespace(
        config=review_cfg,
        contract=REVIEW_CONTRACT,
        run_root=run.root,
        upstream_handoffs=pins,
        optional_prior_handoffs={},
    )
    with pytest.raises(ValueError, match="input contract violation: consumed shard bytes changed"):
        with runtime_inputs.input_read_scope(read_ctx) as reads:
            runtime_inputs.observe_shard(run.root, shard_dict)
            runtime_inputs.observe_shard(run.root, shard_dict)
            assert owner_calls == 1
            assert len(reads.records) >= 1

            shard_file = run.root / built.shard.relative_path
            raw = bytearray(shard_file.read_bytes())
            raw[-1] ^= 0xFF
            shard_file.write_bytes(bytes(raw))
            with pytest.raises(ValueError, match="consumed shard bytes changed"):
                runtime_inputs.observe_shard(run.root, shard_dict)


@pytest.mark.parametrize(
    ("label", "exec_path"),
    [
        (
            "clang_tidy_attempt",
            f"data/clang-static/cpp-scope-1/attempts/attempt_0002/{'ab' * 32}/execution-0001/tidy/execution.json",
        ),
        (
            "clang_analyze_attempt",
            f"data/clang-static/cpp-scope-1/attempts/attempt_0002/{'cd' * 32}/execution-0002/analyze/execution.json",
        ),
        (
            "artifact_security_nested",
            "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/steps/analyze/tasks/"
            "trivy/containers/smoke-image/0123456789abcdef/execution.json",
        ),
        (
            "codeql_attempt_isolated",
            "data/codeql/attempts/attempt_0002/scopes/codeql-unit-1/queries/cpp/executions/query/receipt.json",
        ),
        (
            "cbmc_execution",
            "data/jobs/job_cbmc_analysis/attempts/attempt_0003/artifacts/cbmc/executions/00020/execution.json",
        ),
    ],
    ids=lambda item: item if "_" in item and "/" not in item else None,
)
def test_seq10_safe_common_admits_attempt_isolated_execution_references(label: str, exec_path: str) -> None:
    payload = {"common": _common_payload_with_exec_ref(exec_path)}
    cleaned = RetrievalCore._safe_payload(payload)
    assert cleaned["common"]["evidence_refs"][0]["execution_reference"]["path"] == exec_path


@pytest.mark.parametrize(
    ("label", "bad_path"),
    [
        ("cbmc_outside_artifacts", "data/jobs/job_cbmc_analysis/attempts/attempt_0003/steps/run/execution.json"),
        ("clang_nonhex_digest", "data/clang-static/s1/attempts/attempt_0002/nothex/execution-0001/tidy/execution.json"),
        ("artifact_sec_upper_hex", "data/jobs/job_artifact_security_analysis/attempts/attempt_0001/steps/analyze/tasks/t/containers/c/ABCDEF/execution.json"),
    ],
    ids=lambda item: item if "_" in item and "/" not in item else None,
)
def test_seq10_safe_common_rejects_unscoped_execution_references(label: str, bad_path: str) -> None:
    payload = {"common": _common_payload_with_exec_ref(bad_path)}
    with pytest.raises(RetrievalIntegrityError, match="outside its allowed namespace"):
        RetrievalCore._safe_payload(payload)


def test_seq11_accepted_feed_pins_resolves_downstream_index_updater_and_checks_lineage(tmp_path: Path) -> None:
    built = build_accepted_index_set(tmp_path)
    accepted_ptr_path = built.run_root / "data" / "indices" / "accepted.json"
    original_ptr = accepted_ptr_path.read_text(encoding="utf-8")
    import json

    ptr_doc = json.loads(original_ptr)
    indexing_sha = ptr_doc["handoff_sha256"]

    doc_job = "job_document_issue_analysis"
    doc_attempt = built.run_root / "data" / "jobs" / doc_job / "attempts" / "attempt_0001"
    doc_handoff = write_fixture_handoff(
        built.run_root,
        doc_attempt / "handoff.json",
        {
            "job_id": doc_job,
            "target_snapshot": built.snapshot,
            "source_fingerprint": built.snapshot,
            "outputs": {"publish.index_set": {"index_manifest": {"path": ptr_doc["manifest_path"], "sha256": ptr_doc["manifest_sha256"]}}},
            "artifacts": [],
            "upstream_handoff_sha256": {"job_review_data_indexing": indexing_sha},
        },
    )
    atomic_json(
        doc_attempt.parent.parent / "latest.json",
        {"handoff_path": doc_handoff.relative_to(built.run_root).as_posix(), "handoff_sha256": file_sha256(doc_handoff)},
    )
    atomic_json(
        accepted_ptr_path,
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": built.run_id,
            "handoff_path": doc_handoff.relative_to(built.run_root).as_posix(),
            "handoff_sha256": file_sha256(doc_handoff),
            "manifest_path": ptr_doc["manifest_path"],
            "manifest_sha256": ptr_doc["manifest_sha256"],
        },
    )

    ref = load_cwe_reference(built.run_root)
    assert ref.source == "mitre_catalog"
    assert ref.gap is None
    assert ref.lookup("CWE-120") is not None

    # Lineage mismatch must fail closed with a named gap rather than silently trusting mismatched pins.
    bad_handoff = write_fixture_handoff(
        built.run_root,
        doc_attempt / "handoff-bad.json",
        {
            "job_id": doc_job,
            "target_snapshot": built.snapshot,
            "source_fingerprint": built.snapshot,
            "outputs": {},
            "artifacts": [],
            "upstream_handoff_sha256": {"job_review_data_indexing": "f" * 64},
        },
    )
    atomic_json(
        accepted_ptr_path,
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": built.run_id,
            "handoff_path": bad_handoff.relative_to(built.run_root).as_posix(),
            "handoff_sha256": file_sha256(bad_handoff),
            "manifest_path": ptr_doc["manifest_path"],
            "manifest_sha256": ptr_doc["manifest_sha256"],
        },
    )
    with pytest.raises(RetrievalIntegrityError, match="does not match the accepted index lineage"):
        accepted_feed_pins(built.run_root)


def test_seq12_post_build_hardening_leads_bind_executable_and_render_triage_context(tmp_path: Path) -> None:
    run_root = tmp_path / "runs" / "hardening-run"
    target = "snapshot-hardening"
    shard_path = run_root / "data" / "indices" / "build_security" / "shard.sqlite"

    exe_id = LogicalIdentity.derive(EntityKind.EXECUTABLE, target, {"artifact": "smoke_server"})
    obs_id = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, target, {"check": "elf.now", "artifact": "smoke_server"})

    builder = IndexBuilder(shard_path, name="build_security", fingerprint="b" * 64, target_snapshot=target, shard_id="bs-1")
    builder.add_entity(
        EntityRecord(
            exe_id,
            "smoke_server",
            "smoke_server",
            "ELF pie_executable",
            {"format": "ELF", "hardening": {"now": False, "pie": True}, "build_root": "data/cpp/build"},
        )
    )
    builder.add_entity(
        EntityRecord(
            obs_id,
            "elf.now",
            "elf.now",
            "FAIL observed ELF now",
            {
                "producer": "deterministic-build-security-rules",
                "check_id": "elf.now",
                "status": "FAIL",
                "rationale": "observed ELF now",
                "build_root": "data/cpp/build",
            },
        )
    )
    builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, obs_id.value, exe_id.value, True, 1.0))
    builder.add_coverage("build_security", "complete", None)
    shard = IndexIdentity(
        "build_security",
        "appsec-review/retrieval-index/2",
        builder.build(),
        "b" * 64,
        shard_path.relative_to(run_root).as_posix(),
        {"job": "job_post_build_security_assessment", "unit": "assess.binary"},
        (),
        "bs-1",
    )
    manifest_path = run_root / "data" / "indices" / "manifest.json"
    target_dir = tmp_path / "target"
    target_dir.mkdir(parents=True, exist_ok=True)
    write_manifest(manifest_path, run_id=run_root.name, target_snapshot=target, target_root=target_dir, indexes=(shard,))
    handoff_path = write_fixture_handoff(
        run_root,
        run_root / "data" / "jobs" / "job_review_data_indexing" / "attempts" / "attempt_0001" / "handoff.json",
        {
            "job_id": "job_review_data_indexing",
            "target_snapshot": target,
            "source_fingerprint": target,
            "outputs": {"publish.inventory_index": {"index_manifest": artifact_ref(run_root, manifest_path)}},
            "artifacts": [artifact_ref(run_root, manifest_path), artifact_ref(run_root, shard_path)],
            "upstream_handoff_sha256": {},
        },
    )
    atomic_json(
        run_root / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": run_root.name,
            "handoff_path": handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": file_sha256(handoff_path),
            "manifest_path": manifest_path.relative_to(run_root).as_posix(),
            "manifest_sha256": file_sha256(manifest_path),
        },
    )

    scope = accept_manifest(run_root)
    leads = collect_leads(scope).leads
    hardening_leads = [lead for lead in leads if lead.family == "post_build_hardening"]
    assert len(hardening_leads) == 1
    lead = hardening_leads[0]
    assert lead.related == ((exe_id.value, "artifact"),)
    assert lead.message == (
        "post-build hardening check elf.now FAILED on ELF executable smoke_server "
        "(now=false; observed ELF now; build_root=data/cpp/build)"
    )

    evidence = _evidence(lead)
    assert evidence["resolution"] == "run_artifact"

    item = finding_input(
        lead,
        settings=TriageSettings(enabled=True),
        reader=lambda _lead: (None, None),
        reference=None,
        impact=None,
    )
    assert item["excerpt_unavailable"] == (
        "compiled binary hardening observation (no source line applies; rate by rule_semantics)"
    )
    assert "smoke_server" in item["message"]
    assert "now=false" in item["message"]
