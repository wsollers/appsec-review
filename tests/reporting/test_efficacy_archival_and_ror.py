"""Unit tests for [reporting.efficacy_report], target identity, archival, RoR reporting, and hooks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, fields
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import EfficacyReportSettings, load_config, parse_efficacy_report
from appsec_review.observability.findings import history
from appsec_review.observability.findings.target_identity import normalize_target_id, resolve_target_identity
from appsec_review.reporting import efficacy_finalize
from appsec_review.reporting.__main__ import main as reporting_main
from appsec_review.reporting.efficacy_finalize import finalize_efficacy_report, run_efficacy_finalization
from appsec_review.reporting.html import render_html
from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.run_over_run_report import (
    JSON_NAME,
    LATEST_JSON_NAME,
    LATEST_MD_NAME,
    MD_NAME,
    PDF_NAME,
    RECEIPT_NAME,
    RECEIPT_SCHEMA,
    SCHEMA,
    TEX_NAME,
    archive_target_run,
    build_run_over_run_document,
    build_run_over_run_report,
    render_run_over_run_markdown,
    write_run_over_run_outputs,
)
from appsec_review.reporting.smoke_score import DOSSIER_JOB, GATE_JOB, GRAPH_JOB, REPORT_JOB, REVIEW_JOB

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "containers" / "report" / "latex" / "template"
ATTEMPT = "attempt_0001"
FAKE_PDF = b"%PDF-1.5\nfixture-ror-efficacy\n%%EOF\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, value: Any) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    return {"path": None, "sha256": _sha(raw), "size_bytes": len(raw)}


@dataclass
class _FakeExecResult:
    exit_code: int = 0
    timed_out: bool = False
    oom_killed: bool = False
    file_size_limit_reached: bool = False
    terminal_status: str = "SUCCEEDED"
    image_id: str = "sha256:" + "8" * 64


def _fake_executor_factory(seen: list[Any], *, pdf_bytes: bytes = FAKE_PDF):
    class FakeExecutor:
        def __init__(self, catalog: Any, root: Path) -> None:
            self.catalog = catalog
            self.root = root

        def execute(self, request: Any) -> _FakeExecResult:
            seen.append(request)
            (request.scratch_root / "report.pdf").write_bytes(pdf_bytes)
            (request.scratch_root / "report.log").write_bytes(b"This is LuaHBTeX\n")
            (request.scratch_root / "report.pdfinfo.txt").write_bytes(b"Pages:          3\n")
            return _FakeExecResult()

    return FakeExecutor


def _handoff(run: Path, job: str, outputs: dict[str, str], *, steps: tuple[str, ...] = ("publish",), extra: dict[str, Any] | None = None) -> Path:
    attempt = run / "data" / "jobs" / job / "attempts" / ATTEMPT
    outcomes_ref = _write_json(
        attempt / "outcomes.json",
        {"schema": "appsec-review/job-outcomes/1", "job_id": job, "attempt_id": ATTEMPT, "gaps": []},
    )
    outcomes_ref["path"] = f"data/jobs/{job}/attempts/{ATTEMPT}/outcomes.json"
    body = {
        "schema": "appsec-review/job-handoff/2",
        "job_id": job,
        "attempt_id": ATTEMPT,
        "status": "ACCEPTED",
        "completion_status": "SUCCEEDED",
        "execution_status": "SUCCEEDED",
        "terminal_status": "succeeded",
        "started_at": "2026-11-27T02:00:00+00:00",
        "completed_at": "2026-11-27T02:02:00+00:00",
        "coverage": {"disposition": "complete", "gap_count": 0},
        "outcomes": outcomes_ref,
        "outputs": {u: {"terminal_status": st} for u, st in outputs.items()},
        **(extra or {}),
    }
    ref = _write_json(attempt / "handoff.json", body)
    _write_json(
        run / "data" / "jobs" / job / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": ATTEMPT,
            "handoff_path": f"data/jobs/{job}/attempts/{ATTEMPT}/handoff.json",
            "handoff_sha256": ref["sha256"],
        },
    )
    for step in steps:
        _write_json(
            attempt / "steps" / step / "lifecycle.json",
            {
                "step_id": step,
                "status": "SUCCEEDED",
                "duration_ms": 50,
                "started_at": "2026-11-27T02:00:00+00:00",
                "completed_at": "2026-11-27T02:01:00+00:00",
            },
        )
    return attempt


def _write_source_shard(path: Path, snapshot: str, files: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript(
        """
        PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;
        CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE entities(identity TEXT PRIMARY KEY, kind TEXT NOT NULL, native_id TEXT NOT NULL,
            name TEXT NOT NULL, text TEXT NOT NULL, payload_json TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE locations(location_id TEXT NOT NULL, entity_id TEXT PRIMARY KEY, target_snapshot TEXT NOT NULL,
            path TEXT NOT NULL, file_sha256 TEXT NOT NULL, start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
            start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, start_column INTEGER NOT NULL,
            end_column INTEGER NOT NULL, producer_location_json TEXT NOT NULL, mapping_method TEXT NOT NULL,
            confidence REAL NOT NULL, ambiguous INTEGER NOT NULL) WITHOUT ROWID;
        CREATE TABLE relations(relation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT NOT NULL,
            target_id TEXT NOT NULL, exact INTEGER NOT NULL, confidence REAL NOT NULL, ambiguity TEXT,
            payload_json TEXT NOT NULL) WITHOUT ROWID;
        CREATE TABLE coverage(area TEXT NOT NULL, status TEXT NOT NULL, gap TEXT, PRIMARY KEY(area, status, gap));
        """
    )
    for idx, (f_path, file_sha) in enumerate(sorted(files.items()), start=1):
        eid = f"asr:source_file:{idx:02d}" + "a1" * 31
        con.execute("INSERT INTO entities VALUES (?,?,?,?,?,?)", (eid, "source_file", f_path, f_path, "", json.dumps({"language": "C", "sha256": file_sha})))
        con.execute(
            "INSERT INTO locations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"loc:{idx}", eid, snapshot, f_path, file_sha, 0, 1, 1, 100, 1, 1, "{}", "fixture-exact", 1.0, 0),
        )
    con.execute("INSERT INTO coverage VALUES ('fixture', 'complete', NULL)")
    con.execute("INSERT INTO metadata VALUES ('target_snapshot', ?)", (snapshot,))
    con.commit()
    con.close()


def _build_synthetic_run(
    runs_dir: Path,
    run_id: str,
    *,
    repo: str = "acme/target-alpha",
    commit: str = "1" * 40,
    findings_spec: list[tuple[str, str, int, str, str, str]],
    file_hashes: dict[str, str] | None = None,
    include_gate: bool = True,
) -> Path:
    """Build a fast synthetic run with findings_spec = [(fid, path, line, cwe, severity, lane), ...]."""
    run = runs_dir / run_id
    snapshot = _sha(f"{repo}:{commit}".encode())
    files = file_hashes or {"src/a.c": "a" * 64, "src/b.c": "b" * 64, "src/c.c": "c" * 64}

    _write_json(
        run / "data" / "configuration" / "resolved.json",
        {
            "reporting": {"efficacy_report": {"enabled": True, "render_pdf": False}},
            "jobs": {
                REVIEW_JOB: {
                    "name": REVIEW_JOB,
                    "settings": {
                        "source_dispositions": {"vendored": ["**/third_party/**"], "test": ["**/tests/**"]},
                        "budgets": {"max_output_tokens": 500000, "max_model_turns": 500},
                    },
                }
            },
        },
    )
    binding_rel = f"data/jobs/job_source_history_analysis/attempts/{ATTEMPT}/binding.json"
    binding_ref = _write_json(
        run / binding_rel,
        {"schema": "appsec-review/source-history-binding/1", "snapshot_commit": commit, "source": {"github_repository": repo}},
    )
    binding_ref["path"] = binding_rel
    _handoff(run, "job_source_history_analysis", {"bind.publish": "SUCCEEDED"}, extra={"artifacts": [binding_ref]})

    src_rel = "data/indices/source/src.sqlite"
    _write_source_shard(run / src_rel, snapshot, files)
    manifest_ref = _write_json(
        run / "data" / "indices" / "manifests" / "tags.json",
        {
            "schema": "appsec-review/retrieval-index/2",
            "run_id": run_id,
            "target_snapshot": snapshot,
            "indexes": [
                {
                    "name": "source",
                    "shard_id": "default",
                    "relative_path": src_rel,
                    "sha256": _sha((run / src_rel).read_bytes()),
                    "fingerprint": "f" * 64,
                    "producer": {"job": "job_target_catalog"},
                    "gaps": [],
                    "schema": "appsec-review/retrieval-index/2",
                }
            ],
        },
    )
    _write_json(
        run / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": run_id,
            "manifest_path": "data/indices/manifests/tags.json",
            "manifest_sha256": manifest_ref["sha256"],
            "handoff_path": f"data/jobs/job_security_tagging/attempts/{ATTEMPT}/handoff.json",
            "handoff_sha256": "0" * 64,
        },
    )
    _handoff(run, "job_security_tagging", {"publication.publish_handoff": "SUCCEEDED"})
    _handoff(run, "job_review_prioritization", {"prioritize.score": "SUCCEEDED"})
    _handoff(run, GRAPH_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("acceptance",))

    rev_attempt = _handoff(
        run,
        REVIEW_JOB,
        {"packages.assemble_lead_packages": "SUCCEEDED", "publication.publish_handoff": "SUCCEEDED"},
        steps=("packages", "publication"),
    )
    assembly = rev_attempt / "steps" / "packages" / "tasks" / "assemble_lead_packages" / "assembly"
    source_ids = [f"asr:source_file:{idx:02d}" + "a1" * 31 for idx in range(1, len(files) + 1)]
    unit_doc = {"schema": "appsec-review/package-unit-context/2", "unit_key": "unit-1", "scope": {"component_id": "comp:1", "source_ids": source_ids}}
    unit_raw = json.dumps(unit_doc, sort_keys=True).encode("utf-8")
    unit_sha = _sha(unit_raw)
    (assembly / "unit-context").mkdir(parents=True, exist_ok=True)
    (assembly / "unit-context" / f"{unit_sha}.json").write_bytes(unit_raw)

    _write_json(assembly / "packages" / "finding_lead-1.json", {"package_id": "finding_lead-1", "kind": "finding_lead", "lane": "lead", "lead_menu": [], "scope": {"source_ids": source_ids}, "unit_context": None})
    _write_json(assembly / "packages" / "hunt-1.json", {"package_id": "hunt-1", "kind": "hunt", "lane": "hunt", "lead_menu": [], "scope": {}, "unit_context": {"schema": unit_doc["schema"], "path": f"unit-context/{unit_sha}.json", "sha256": unit_sha}})
    _write_json(
        assembly / "package-manifest.json",
        {
            "schema": "appsec-review/review-package-manifest/1",
            "run_id": run_id,
            "admission": [],
            "packages": [
                {"package_id": "finding_lead-1", "kind": "finding_lead", "lane": "lead", "unit_key": None},
                {"package_id": "hunt-1", "kind": "hunt", "lane": "hunt", "unit_key": "unit-1"},
            ],
            "units": [{"unit_key": "unit-1", "source_ids": source_ids, "hunted": True, "package_ids": ["hunt-1"]}],
            "counts": {"dispositions": {"files": {"first_party": len(files)}}},
        },
    )

    claims = []
    relations = []
    proposal_packages: dict[str, list[str]] = {}
    gate_packages = []
    report_findings = []
    for idx, (fid, f_path, line, cwe, sev, lane) in enumerate(findings_spec, start=1):
        cid = f"claim-{fid}"
        pkg_id = "hunt-1" if lane == "hunt" else "finding_lead-1"
        claims.append({"claim_id": cid, "lane": lane, "package_id": pkg_id, "state": "confirmed", "weakness_cwe": cwe, "affected_entities": [], "state_history": []})
        relations.append(
            {
                "relation_id": f"rel-{idx}",
                "claim_id": cid,
                "entity_id": "asr:call_site:" + f"{idx:02d}" * 32,
                "entity_kind": "call_site",
                "kind": "supports",
                "predicate": "affected_construct",
                "locator": f"{f_path}:{line}-{line}#b0-1@{snapshot}",
            }
        )
        proposal_packages[cid] = [pkg_id]
        _write_json(
            rev_attempt / "steps" / "publication" / "tasks" / "publish_handoff" / "findings" / f"{fid}.json",
            {"schema": "appsec-review/finding-package/2", "finding_package_id": fid, "claim_id": cid, "state": "confirmed", "technical_severity": sev, "title": f"Issue {fid}"},
        )
        gate_packages.append({"finding_package_id": fid, "claim_id": cid, "state": "confirmed", "bucket": "publishable", "severity": sev})
        report_findings.append({"finding_package_id": fid, "claim_id": cid})

    _write_json(
        rev_attempt / "steps" / "publication" / "tasks" / "publish_claim_ledger" / "projection.json",
        {"schema": "appsec-review/claim-projection/1", "ledger_head_sha256": "2" * 64, "claims": claims, "relations": relations, "cells": {"c-hunt": [{"cell_id": "c-hunt", "lane": "hunt", "package_id": "hunt-1", "role": "hypothesis_hunter", "status": "succeeded"}]}, "gaps": [], "evidence_requests": [], "judge_verdicts": {}},
    )
    _write_json(rev_attempt / "steps" / "merge" / "tasks" / "claims" / "merge.json", {"proposal_packages": proposal_packages})
    _handoff(run, DOSSIER_JOB, {"dossiers.create": "SUCCEEDED"}, steps=("dossiers",))

    if include_gate:
        gate_attempt = _handoff(run, GATE_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("acceptance",))
        _write_json(
            gate_attempt / "steps" / "acceptance" / "tasks" / "publish_handoff" / "final-publication-gate.json",
            {"schema": "appsec-review/final-publication-gate/2", "run_id": run_id, "packages": gate_packages},
        )
        rep_attempt = _handoff(run, REPORT_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("report",))
        _write_json(
            rep_attempt / "steps" / "report" / "tasks" / "build" / "final-report.json",
            {"schema": "appsec-review/final-report/2", "run_id": run_id, "findings": report_findings},
        )
    return run


def test_efficacy_report_config_defaults_roundtrip_and_validation(tmp_path: Path) -> None:
    defaults = EfficacyReportSettings()
    assert parse_efficacy_report(None) == defaults
    assert parse_efficacy_report({}) == defaults
    field_names = {f.name for f in fields(EfficacyReportSettings)}
    assert "image_id" not in field_names and "image_tag" not in field_names

    cfg = load_config(ROOT / "appsec-review.toml")
    assert cfg.efficacy_report == defaults
    resolved_eff = json.loads(cfg.resolved_json)["reporting"]["efficacy_report"]
    assert parse_efficacy_report(resolved_eff) == defaults

    custom = parse_efficacy_report(
        {
            "enabled": False,
            "render_pdf": False,
            "auto_smoke_score": False,
            "history_dir": "custom/history",
            "smoke_guide_dir": "custom/guide",
            "timeout_seconds": 120,
            "max_tex_bytes": 1_048_576,
            "max_pdf_bytes": 2_097_152,
        }
    )
    assert custom.enabled is False
    assert custom.render_pdf is False
    assert custom.auto_smoke_score is False
    assert custom.history_dir == "custom/history"
    assert custom.timeout_seconds == 120

    with pytest.raises(ValueError):
        parse_efficacy_report({"enabled": "yes"})
    with pytest.raises(ValueError):
        parse_efficacy_report({"timeout_seconds": 0})
    with pytest.raises(ValueError):
        parse_efficacy_report({"max_tex_bytes": -5})
    with pytest.raises(ValueError):
        parse_efficacy_report({"unknown_option": True})


def test_resolve_target_identity_precedence_and_normalization(tmp_path: Path) -> None:
    assert history._TARGET.fullmatch(normalize_target_id("My Org/Strange__Repo!!Name"))

    # 1. Resolved from job_source_history_analysis -> binding.json
    run1 = tmp_path / "2026-11-27-0001"
    hist_att = _handoff(run1, "job_source_history_analysis", {"bind.publish": "SUCCEEDED"})
    _write_json(
        hist_att / "binding.json",
        {
            "schema": "appsec-review/source-history-binding/1",
            "snapshot_commit": "bededb650d0c576e27b0041e9f675040b9a7bd97",
            "source": {"github_repository": "wsollers/appsec-review-smoke-cpp"},
        },
    )
    id1 = resolve_target_identity(run1, repository_root=tmp_path)
    assert id1.target_id == "appsec-review-smoke-cpp"
    assert id1.source_revision == "bededb650d0c576e27b0041e9f675040b9a7bd97"
    assert id1.repository == "wsollers/appsec-review-smoke-cpp"
    assert history._TARGET.fullmatch(id1.target_id)

    # 2. Fallback to job_review_intake -> handoff.json source_fingerprint
    run2 = tmp_path / "2026-11-27-0002"
    fp = "ab" * 32
    _handoff(run2, "job_review_intake", {"intake.publish": "SUCCEEDED"}, extra={"source_fingerprint": fp})
    id2 = resolve_target_identity(run2, repository_root=tmp_path)
    assert id2.target_id == f"target-{fp[:16]}"
    assert id2.source_revision == fp
    assert history._TARGET.fullmatch(id2.target_id)

    # 3. Empty run falls back deterministically
    run3 = tmp_path / "2026-11-27-0003"
    (run3 / "data").mkdir(parents=True)
    id3 = resolve_target_identity(run3, repository_root=tmp_path)
    assert id3.target_id == "unknown-target"
    assert id3.source_revision == "unknown-revision"
    assert history._TARGET.fullmatch(id3.target_id)


def test_incomplete_run_without_publication_gate_skips_cleanly(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    history_root = tmp_path / "history"
    incomplete = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0001",
        findings_spec=[("F1", "src/a.c", 10, "CWE-78", "high", "lead")],
        include_gate=False,
    )
    res = archive_target_run(incomplete, history_root=history_root, repository_root=tmp_path)
    assert res["status"] == "skipped_incomplete_run"
    assert not history_root.exists()

    called: list[Any] = []
    assert (
        finalize_efficacy_report(
            incomplete,
            EfficacyReportSettings(history_dir=str(history_root)),
            runs_dir=runs_dir,
            repository_root=tmp_path,
            renderer=lambda *a, **kw: called.append((a, kw)) or {"status": "rendered"},
        )
        is None
    )
    assert called == []


def test_strict_target_isolation_and_idempotent_rearchival(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    history_root = tmp_path / "history"

    alpha_1 = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0001",
        repo="acme/target-alpha",
        commit="1" * 40,
        findings_spec=[("FA1", "src/a.c", 10, "CWE-78", "critical", "lead")],
    )
    alpha_2 = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0002",
        repo="acme/target-alpha",
        commit="2" * 40,
        findings_spec=[
            ("FA1", "src/a.c", 10, "CWE-78", "critical", "lead"),
            ("FA2", "src/b.c", 22, "CWE-287", "high", "hunt"),
        ],
    )
    beta_1 = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0003",
        repo="acme/target-beta",
        commit="3" * 40,
        findings_spec=[("FB1", "src/c.c", 44, "CWE-416", "medium", "hunt")],
    )

    r_a1 = archive_target_run(alpha_1, history_root=history_root, repository_root=tmp_path)
    r_a2 = archive_target_run(alpha_2, history_root=history_root, repository_root=tmp_path)
    r_b1 = archive_target_run(beta_1, history_root=history_root, repository_root=tmp_path)

    assert r_a1["status"] == "published"
    assert r_a2["status"] == "published"
    assert r_b1["status"] == "published"

    # Re-archiving alpha_2 is 100% idempotent (uses cached scorecard, no duplicate snapshot)
    r_a2_repeat = archive_target_run(alpha_2, history_root=history_root, repository_root=tmp_path)
    assert r_a2_repeat["status"] == "already_archived"
    assert len(history.load_history(history_root, "target-alpha")["snapshots"]) == 2
    assert len(history.load_history(history_root, "target-beta")["snapshots"]) == 1

    ror_alpha = build_run_over_run_report(target_id="target-alpha", history_root=history_root, runs_dir=runs_dir)
    ror_beta = build_run_over_run_report(target_id="target-beta", history_root=history_root, runs_dir=runs_dir)

    assert ror_alpha["schema"] == SCHEMA
    assert ror_alpha["cohort_size"] == 2
    assert [r["run_id"] for r in ror_alpha["per_run_series"]] == ["2026-11-27-0001", "2026-11-27-0002"]

    assert ror_beta["cohort_size"] == 1
    assert [r["run_id"] for r in ror_beta["per_run_series"]] == ["2026-11-27-0003"]


def test_multi_run_lifecycle_transitions_jaccard_rendering_and_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from appsec_review.observability.findings import coverage_adapter
    from appsec_review.observability.findings.coverage_adapter import CoverageDocuments

    runs_dir = tmp_path / "runs"
    history_root = tmp_path / "history"
    run_hashes = {
        "2026-11-27-0011": {"src/a.c": "a1" * 32, "src/b.c": "b1" * 32, "src/c.c": "c1" * 32},
        "2026-11-27-0012": {"src/a.c": "a1" * 32, "src/b.c": "b2" * 32, "src/c.c": "c1" * 32},
        "2026-11-27-0013": {"src/a.c": "a1" * 32, "src/b.c": "b3" * 32, "src/c.c": "c1" * 32},
    }

    def _cov_docs(run_path: Path) -> CoverageDocuments:
        fh = run_hashes[Path(run_path).name]
        sids = [f"asr:source_file:{p}" for p in sorted(fh)]
        return CoverageDocuments(
            catalog={f"asr:source_file:{p}": {"path": p, "sha256": h, "built": True} for p, h in fh.items()},
            packages=[{"package_id": "hunt-1", "source_ids": sids}],
            cells={"c-1": [{"cell_id": "c-1", "lane": "hunt", "package_id": "hunt-1", "role": sorted(coverage_adapter.RED_ROLES)[0], "status": "succeeded"}]},
            units=[{"unit_key": "unit-1", "hunted": True}],
            tags=[],
        )

    monkeypatch.setitem(coverage_adapter.coverage_from_run.__kwdefaults__, "loader", _cov_docs)

    # Run 1: F-PERSIST (a.c:10) + F-TRANS (b.c:20)
    r1 = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0011",
        repo="acme/target-alpha",
        commit="1" * 40,
        findings_spec=[
            ("F-PERSIST", "src/a.c", 10, "CWE-78", "critical", "lead"),
            ("F-TRANS", "src/b.c", 20, "CWE-89", "high", "lead"),
        ],
        file_hashes={"src/a.c": "a1" * 32, "src/b.c": "b1" * 32, "src/c.c": "c1" * 32},
    )
    # Run 2: F-PERSIST stays, F-TRANS disappears after b.c changes (fix_candidate -> fixed), F-NEW appears
    r2 = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0012",
        repo="acme/target-alpha",
        commit="2" * 40,
        findings_spec=[
            ("F-PERSIST", "src/a.c", 10, "CWE-78", "critical", "lead"),
            ("F-NEW", "src/c.c", 30, "CWE-416", "medium", "hunt"),
        ],
        file_hashes={"src/a.c": "a1" * 32, "src/b.c": "b2" * 32, "src/c.c": "c1" * 32},
    )
    # Run 3: F-PERSIST + F-NEW persist, and F-TRANS reappears at b.c:20 -> regressed!
    r3 = _build_synthetic_run(
        runs_dir,
        "2026-11-27-0013",
        repo="acme/target-alpha",
        commit="3" * 40,
        findings_spec=[
            ("F-PERSIST", "src/a.c", 10, "CWE-78", "critical", "lead"),
            ("F-NEW", "src/c.c", 30, "CWE-416", "medium", "hunt"),
            ("F-TRANS", "src/b.c", 20, "CWE-89", "high", "lead"),
        ],
        file_hashes={"src/a.c": "a1" * 32, "src/b.c": "b3" * 32, "src/c.c": "c1" * 32},
    )

    archive_target_run(r1, history_root=history_root, repository_root=tmp_path)
    archive_target_run(r2, history_root=history_root, repository_root=tmp_path)
    seen: list[Any] = []
    settings = EfficacyReportSettings(
        enabled=True,
        render_pdf=True,
        auto_smoke_score=True,
        history_dir=str(history_root),
        smoke_guide_dir=str(tmp_path / "no-smoke-guide"),
    )
    res3 = run_efficacy_finalization(
        r3,
        settings,
        runs_dir=runs_dir,
        repository_root=ROOT,
        executor_factory=_fake_executor_factory(seen),
    )

    assert res3["status"] == "rendered"
    assert res3["cohort_size"] == 3
    assert len(seen) == 1

    ror = res3["ror_payload"]
    s1, s2, s3 = ror["per_run_series"]
    assert s1["lifecycle"]["new"] == 2 and s1["jaccard_stability_vs_prior"] is None
    assert s2["lifecycle"]["persisting"] == 1
    assert s2["lifecycle"]["new"] == 1
    assert s2["lifecycle"]["fixed"] == 1
    assert s2["jaccard_stability_vs_prior"] == pytest.approx(1 / 3, abs=1e-3)
    assert s3["lifecycle"]["persisting"] == 2
    assert s3["lifecycle"]["regressed"] == 1
    assert s3["jaccard_stability_vs_prior"] == pytest.approx(2 / 3, abs=1e-3)

    md = render_run_over_run_markdown(ror)
    assert "Run-over-Run" in md and "2026-11-27-0013" in md
    doc = build_run_over_run_document(ror)
    assert r"\documentclass" in render_latex(doc, TEMPLATE)
    assert "2026-11-27-0013" in render_html(doc)

    eff_dir = r3 / "data" / "efficacy"
    assert (eff_dir / JSON_NAME).is_file()
    assert (eff_dir / MD_NAME).is_file()
    assert (eff_dir / TEX_NAME).is_file()
    assert (eff_dir / PDF_NAME).read_bytes() == FAKE_PDF
    receipt = json.loads((eff_dir / RECEIPT_NAME).read_text(encoding="utf-8"))
    assert receipt["schema"] == RECEIPT_SCHEMA and receipt["status"] == "rendered"
    assert (history_root / "target-alpha" / LATEST_JSON_NAME).is_file()
    assert (history_root / "target-alpha" / LATEST_MD_NAME).is_file()

    # CLI subcommand `efficacy --format md --out <dir>` exports cleanly without Docker
    export_dir = tmp_path / "cli-export"
    _write_json(
        r3 / "data" / "configuration" / "resolved.json",
        {
            "reporting": {
                "efficacy_report": {
                    "enabled": True,
                    "render_pdf": False,
                    "auto_smoke_score": True,
                    "history_dir": str(history_root),
                    "smoke_guide_dir": str(tmp_path / "no-smoke-guide"),
                }
            },
            "jobs": {
                REVIEW_JOB: {
                    "name": REVIEW_JOB,
                    "settings": {
                        "source_dispositions": {"vendored": ["**/third_party/**"], "test": ["**/tests/**"]},
                        "budgets": {"max_output_tokens": 500000, "max_model_turns": 500},
                    },
                }
            },
        },
    )
    code = reporting_main(
        ["efficacy", "--run", "2026-11-27-0013", "--runs-dir", str(runs_dir), "--format", "md", "--out", str(export_dir)]
    )
    assert code == 0
    cli_out = json.loads(capsys.readouterr().out)
    assert cli_out["status"] == "latex_only"
    assert (export_dir / MD_NAME).is_file()
    assert (export_dir / JSON_NAME).is_file()


def test_dagster_complete_and_graph_runner_hook_ordering_and_error_safety(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # 1. Verify AST invariant in adapter.py: write_run_metrics -> finalize_telemetry_report -> finalize_efficacy_report
    tree = ast.parse((ROOT / "src/appsec_review/orchestration/dagster/adapter.py").read_text(encoding="utf-8"))
    complete = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "complete")
    body = [ast.unparse(stmt) for stmt in complete.body]
    metrics_idx = body.index("write_run_metrics(run_root)")
    assert body[metrics_idx + 1] == (
        "finalize_telemetry_report(run_root, config.telemetry_report, repository_root=config.runtime.repository_root)"
    )
    assert body[metrics_idx + 2] == (
        "finalize_efficacy_report(run_root, config.efficacy_report, runs_dir=config.runtime.runs_dir, repository_root=config.runtime.repository_root)"
    )

    # 2. Verify GraphRunner._finish() calls write_run_metrics -> finalize_telemetry_report -> finalize_efficacy_report
    from appsec_review.runtime import graph as graph_mod
    import appsec_review.jobs.build_iterations as bi_mod
    import appsec_review.reporting.telemetry_finalize as tf_mod

    order: list[str] = []
    monkeypatch.setattr(bi_mod, "finish_build_workspaces", lambda *_a, **_k: order.append("workspaces"))
    monkeypatch.setattr(graph_mod, "write_run_metrics", lambda *_a, **_k: order.append("metrics"))
    monkeypatch.setattr(tf_mod, "finalize_telemetry_report", lambda *_a, **_k: order.append("telemetry"))
    monkeypatch.setattr(efficacy_finalize, "finalize_efficacy_report", lambda *_a, **_k: order.append("efficacy"))

    dummy_runner = SimpleNamespace(
        config=SimpleNamespace(
            build_workspaces=SimpleNamespace(),
            telemetry_report=SimpleNamespace(),
            efficacy_report=EfficacyReportSettings(),
            runtime=SimpleNamespace(runs_dir=tmp_path / "runs", repository_root=tmp_path),
        )
    )
    graph_mod.GraphRunner._finish(dummy_runner, tmp_path / "runs" / "2026-11-27-0001")
    assert order == ["workspaces", "metrics", "telemetry", "efficacy"]

    # 3. Verify finalize_efficacy_report swallows unexpected renderer exceptions, redacts detail, and never writes pipeline.jsonl
    run_ok = _build_synthetic_run(
        tmp_path / "runs2",
        "2026-11-27-0099",
        findings_spec=[("F1", "src/a.c", 10, "CWE-78", "high", "lead")],
    )

    def _boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("sensitive internal token")

    with caplog.at_level(logging.WARNING, logger=efficacy_finalize.__name__):
        out = finalize_efficacy_report(run_ok, EfficacyReportSettings(), renderer=_boom)
    assert out is None
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "2026-11-27-0099" in msg and "RuntimeError" in msg and "sensitive internal token" not in msg
    assert not (run_ok / "data" / "logs" / "pipeline.jsonl").exists()
