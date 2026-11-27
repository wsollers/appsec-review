"""Unit tests for blind-safe smoke-target effectiveness and SAST-vs-Hunter attribution."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from appsec_review.reporting.html import render_html
from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.smoke_effectiveness import (
    RECEIPT_NAME,
    RECEIPT_SCHEMA,
    SCHEMA,
    build_smoke_effectiveness,
    build_smoke_effectiveness_document,
    discover_matching_smoke_key,
    render_smoke_effectiveness_markdown,
    write_smoke_effectiveness_outputs,
)
from appsec_review.reporting.smoke_score import DOSSIER_JOB, GATE_JOB, GRAPH_JOB, REPORT_JOB, REVIEW_JOB

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "containers" / "report" / "latex" / "template"
SNAPSHOT = "b" * 64
COMMIT_SHA = "bededb650d0c576e27b0041e9f675040b9a7bd97"
ATTEMPT = "attempt_0001"
FAKE_PDF = b"%PDF-1.5\nfixture-smoke-effectiveness\n%%EOF\n"

REQ, AUTH, CRYPTO, UTIL, EXTRA, ZLIB = (
    "src/request.cpp",
    "src/auth.cpp",
    "src/crypto.cpp",
    "src/util.c",
    "src/extra.cpp",
    "third_party/zlib/inflate.c",
)
IDS = {
    REQ: "asr:source_file:" + "11" * 32,
    AUTH: "asr:source_file:" + "12" * 32,
    CRYPTO: "asr:source_file:" + "13" * 32,
    UTIL: "asr:source_file:" + "14" * 32,
    EXTRA: "asr:source_file:" + "15" * 32,
    ZLIB: "asr:source_file:" + "16" * 32,
    "obs-sast-1": "asr:tool_observation:" + "21" * 32,
    "obs-both": "asr:tool_observation:" + "22" * 32,
    "obs-fp-1": "asr:tool_observation:" + "23" * 32,
    "obs-dep-1": "asr:tool_observation:" + "24" * 32,
    "dep-zlib": "asr:dependency_package:" + "31" * 32,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, value: Any) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    return {"path": None, "sha256": _sha(raw), "size_bytes": len(raw)}


def _write_shard(path: Path, rows: list[tuple[Any, ...]]) -> None:
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
    for identity, kind, native_id, name, payload, location in rows:
        con.execute("INSERT INTO entities VALUES (?,?,?,?,?,?)", (identity, kind, native_id, name, "", json.dumps(payload)))
        if location is not None:
            file_path, start, end = location
            con.execute(
                "INSERT INTO locations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"loc:{_sha(identity.encode())}", identity, SNAPSHOT, file_path, _sha(file_path.encode()),
                 0, 1, start, end, 1, 1, "{}", "fixture-exact", 1.0, 0),
            )
    con.execute("INSERT INTO coverage VALUES ('fixture', 'complete', NULL)")
    con.execute("INSERT INTO metadata VALUES ('target_snapshot', ?)", (SNAPSHOT,))
    con.commit()
    con.close()


def _handoff(run: Path, job: str, outputs: dict[str, str], *, steps: tuple[str, ...] = ("publish",)) -> Path:
    attempt = run / "data" / "jobs" / job / "attempts" / ATTEMPT
    outcomes_ref = _write_json(
        attempt / "outcomes.json",
        {"schema": "appsec-review/job-outcomes/1", "job_id": job, "attempt_id": ATTEMPT, "gaps": []},
    )
    outcomes_ref["path"] = f"data/jobs/{job}/attempts/{ATTEMPT}/outcomes.json"
    ref = _write_json(
        attempt / "handoff.json",
        {
            "schema": "appsec-review/job-handoff/2",
            "job_id": job,
            "attempt_id": ATTEMPT,
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "execution_status": "SUCCEEDED",
            "terminal_status": "succeeded",
            "started_at": "2026-11-27T01:00:00+00:00",
            "completed_at": "2026-11-27T01:02:00+00:00",
            "coverage": {"disposition": "complete", "gap_count": 0},
            "outcomes": outcomes_ref,
            "outputs": {u: {"terminal_status": st} for u, st in outputs.items()},
        },
    )
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
                "duration_ms": 100,
                "started_at": "2026-11-27T01:00:00+00:00",
                "completed_at": "2026-11-27T01:01:00+00:00",
            },
        )
    return attempt


def _obs_payload(scanner: str, rule_id: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": "appsec-review/observation/1",
        "common": {"scanner": scanner, "rule_id": rule_id, "observation_class": "source_sast", "reported_severity": {"value": "high"}},
        **(extra or {}),
    }


@dataclass
class _FakeExecResult:
    exit_code: int = 0
    timed_out: bool = False
    oom_killed: bool = False
    file_size_limit_reached: bool = False
    terminal_status: str = "SUCCEEDED"
    image_id: str = "sha256:" + "9" * 64


def _fake_executor_factory(seen: list[Any], *, pdf_bytes: bytes = FAKE_PDF):
    class FakeExecutor:
        def __init__(self, catalog: Any, root: Path) -> None:
            self.catalog = catalog
            self.root = root

        def execute(self, request: Any) -> _FakeExecResult:
            seen.append(request)
            (request.scratch_root / "report.pdf").write_bytes(pdf_bytes)
            (request.scratch_root / "report.log").write_bytes(b"This is LuaHBTeX\n")
            (request.scratch_root / "report.pdfinfo.txt").write_bytes(b"Pages:          2\n")
            return _FakeExecResult()

    return FakeExecutor


def _build_effectiveness_fixture(tmp_path: Path, *, include_false_alarm: bool = False) -> tuple[Path, Path]:
    run = tmp_path / "runs" / "2026-11-27-0001"
    data = run / "data"
    _write_json(
        data / "configuration" / "resolved.json",
        {
            "jobs": {
                REVIEW_JOB: {
                    "name": REVIEW_JOB,
                    "settings": {
                        "source_dispositions": {"vendored": ["**/third_party/**"], "test": ["**/tests/**"]},
                        "budgets": {"max_output_tokens": 1000000, "max_model_turns": 2000},
                    },
                }
            }
        },
    )
    hist_attempt = _handoff(run, "job_source_history_analysis", {"bind.publish": "SUCCEEDED"})
    _write_json(
        hist_attempt / "binding.json",
        {
            "schema": "appsec-review/source-history-binding/1",
            "snapshot_commit": COMMIT_SHA,
            "source": {"github_repository": "wsollers/appsec-review-smoke-cpp"},
        },
    )

    shards: list[dict[str, Any]] = []

    def add_shard(name: str, shard_id: str, rel: str, rows: list[tuple[Any, ...]], producer: dict[str, Any]) -> None:
        _write_shard(run / rel, rows)
        shards.append(
            {
                "name": name,
                "shard_id": shard_id,
                "relative_path": rel,
                "sha256": _sha((run / rel).read_bytes()),
                "fingerprint": "f" * 64,
                "producer": producer,
                "gaps": [],
                "schema": "appsec-review/retrieval-index/2",
            }
        )

    add_shard(
        "source",
        "default",
        "data/indices/source/src.sqlite",
        [
            (IDS[REQ], "source_file", REQ, REQ, {"language": "C++"}, (REQ, 1, 220)),
            (IDS[AUTH], "source_file", AUTH, AUTH, {"language": "C++"}, (AUTH, 1, 120)),
            (IDS[CRYPTO], "source_file", CRYPTO, CRYPTO, {"language": "C++"}, (CRYPTO, 1, 120)),
            (IDS[UTIL], "source_file", UTIL, UTIL, {"language": "C"}, (UTIL, 1, 80)),
            (IDS[EXTRA], "source_file", EXTRA, EXTRA, {"language": "C++"}, (EXTRA, 1, 40)),
            (IDS[ZLIB], "source_file", ZLIB, ZLIB, {"language": "C"}, (ZLIB, 1, 400)),
        ],
        {"job": "job_target_catalog"},
    )
    add_shard(
        "tags",
        "facets",
        "data/indices/tags/facets.sqlite",
        [
            (
                "asr:tag_assignment:" + "41" * 32,
                "tag_assignment",
                "tag:1",
                "role:request-handler",
                {"tag": "role:request-handler", "namespace": "role", "subject": {"kind": "source_file", "path": REQ}},
                (REQ, 1, 220),
            )
        ],
        {"job": "job_security_tagging", "family": "code_facts"},
    )
    add_shard(
        "observations",
        "semgrep",
        "data/indices/observations/semgrep.sqlite",
        [
            (IDS["obs-sast-1"], "tool_observation", "ev-1", "cpp-popen", _obs_payload("tool-semgrep", "rules.cpp-cmdi"), (REQ, 120, 120)),
            (IDS["obs-both"], "tool_observation", "ev-2", "cpp-fmt", _obs_payload("tool-codeql", "cpp/tainted-format-string"), (REQ, 160, 160)),
            (IDS["obs-fp-1"], "tool_observation", "ev-3", "cpp-copy-trap", _obs_payload("tool-semgrep", "rules.cpp-bounded-copy"), (UTIL, 20, 20)),
        ],
        {"job": "job_evidence_collection", "producer": "tool-semgrep"},
    )
    add_shard(
        "observations",
        "osv",
        "data/indices/observations/osv.sqlite",
        [
            (
                IDS["obs-dep-1"],
                "tool_observation",
                "ev-4",
                "CVE-2018-25032",
                _obs_payload(
                    "tool-osv-scanner",
                    "CVE-2018-25032",
                    {
                        "common": {
                            "scanner": "tool-osv-scanner",
                            "rule_id": "CVE-2018-25032",
                            "observation_class": "dependency_advisory",
                            "reported_severity": {"value": "high"},
                        },
                        "advisory": {"id": "CVE-2018-25032", "aliases": ["GHSA-jc36-42cf-vqwj"], "package": "zlib", "version": "1.2.11"},
                    },
                ),
                None,
            )
        ],
        {"job": "job_evidence_collection", "producer": "tool-osv-scanner"},
    )
    add_shard(
        "inventory",
        "deps",
        "data/indices/inventory/inv.sqlite",
        [(IDS["dep-zlib"], "dependency_package", "dep-1", "zlib", {"name": "zlib", "version": "1.2.11"}, None)],
        {"job": "job_dependency_intelligence"},
    )

    manifest_ref = _write_json(
        data / "indices" / "manifests" / "tags.json",
        {"schema": "appsec-review/retrieval-index/2", "run_id": run.name, "target_snapshot": SNAPSHOT, "indexes": shards},
    )
    _write_json(
        data / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": run.name,
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
    unit_doc = {
        "schema": "appsec-review/package-unit-context/2",
        "unit_key": "unit-1",
        "scope": {"component_id": "comp:1", "source_ids": [IDS[REQ], IDS[AUTH], IDS[CRYPTO], IDS[UTIL], IDS[EXTRA]]},
    }
    unit_raw = json.dumps(unit_doc, sort_keys=True).encode("utf-8")
    unit_sha = _sha(unit_raw)
    (assembly / "unit-context").mkdir(parents=True, exist_ok=True)
    (assembly / "unit-context" / f"{unit_sha}.json").write_bytes(unit_raw)

    packages = {
        "finding_lead-1": {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": IDS["obs-sast-1"], "lead_family": "source_sast", "scanner": "tool-semgrep"}], "scope": {"source_ids": [IDS[REQ]]}, "unit_context": None},
        "finding_lead-2": {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": IDS["obs-both"], "lead_family": "source_sast", "scanner": "tool-codeql"}], "scope": {"source_ids": [IDS[REQ]]}, "unit_context": None},
        "finding_lead-3": {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": IDS["obs-fp-1"], "lead_family": "source_sast", "scanner": "tool-semgrep"}], "scope": {"source_ids": [IDS[UTIL]]}, "unit_context": None},
        "finding_lead-4": {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": IDS["obs-dep-1"], "lead_family": "dependency_advisory", "scanner": "tool-osv-scanner"}], "scope": {"source_ids": []}, "unit_context": None},
        "hunt-1": {"kind": "hunt", "lane": "hunt", "lead_menu": [], "scope": {}, "unit_context": {"schema": unit_doc["schema"], "path": f"unit-context/{unit_sha}.json", "sha256": unit_sha}},
    }
    for pid, body in packages.items():
        _write_json(assembly / "packages" / f"{pid}.json", {**body, "package_id": pid})

    _write_json(
        assembly / "package-manifest.json",
        {
            "schema": "appsec-review/review-package-manifest/1",
            "run_id": run.name,
            "admission": [
                {"lead_id": IDS["obs-sast-1"], "status": "admitted", "effective_severity": "high"},
                {"lead_id": IDS["obs-both"], "status": "admitted", "effective_severity": "high"},
                {"lead_id": IDS["obs-fp-1"], "status": "admitted", "effective_severity": "medium"},
                {"lead_id": IDS["obs-dep-1"], "status": "admitted", "effective_severity": "high"},
            ],
            "packages": [{"package_id": pid, "kind": body["kind"], "lane": body["lane"], "unit_key": None} for pid, body in packages.items()],
            "units": [{"unit_key": "unit-1", "source_ids": [IDS[REQ], IDS[AUTH], IDS[CRYPTO], IDS[UTIL], IDS[EXTRA]], "hunted": True, "package_ids": ["hunt-1"]}],
            "counts": {"dispositions": {"files": {"first_party": 5, "vendored": 1}}},
        },
    )

    def _rel(cid: str, idx: int, path_str: str, line: int) -> dict[str, Any]:
        return {
            "relation_id": f"rel-{cid}-{idx}",
            "claim_id": cid,
            "entity_id": "asr:call_site:" + f"{idx:02d}" * 32,
            "entity_kind": "call_site",
            "kind": "supports",
            "predicate": "affected_construct",
            "locator": f"{path_str}:{line}-{line}#b0-1@{SNAPSHOT}",
        }

    claims = [
        {"claim_id": "claim-sast", "lane": "lead", "package_id": "finding_lead-1", "state": "confirmed", "weakness_cwe": "CWE-78", "affected_entities": [IDS["obs-sast-1"]], "state_history": []},
        {"claim_id": "claim-hunt", "lane": "hunt", "package_id": "hunt-1", "state": "confirmed", "weakness_cwe": "CWE-287", "affected_entities": [], "state_history": []},
        {"claim_id": "claim-both-sast", "lane": "lead", "package_id": "finding_lead-2", "state": "confirmed", "weakness_cwe": "CWE-134", "affected_entities": [IDS["obs-both"]], "state_history": []},
        {"claim_id": "claim-both-hunt", "lane": "hunt", "package_id": "hunt-1", "state": "confirmed", "weakness_cwe": "CWE-134", "affected_entities": [], "state_history": []},
        {"claim_id": "claim-dep", "lane": "lead", "package_id": "finding_lead-4", "state": "confirmed", "weakness_cwe": "CWE-787", "affected_entities": [IDS["obs-dep-1"]], "state_history": []},
        {"claim_id": "claim-fp-refuted", "lane": "lead", "package_id": "finding_lead-3", "state": "contradicted", "weakness_cwe": "CWE-120", "affected_entities": [IDS["obs-fp-1"]], "state_history": []},
        {"claim_id": "claim-bonus", "lane": "hunt", "package_id": "hunt-1", "state": "confirmed", "weakness_cwe": "CWE-416", "affected_entities": [], "state_history": []},
    ]
    relations = [
        _rel("claim-sast", 1, REQ, 120),
        _rel("claim-hunt", 2, AUTH, 45),
        _rel("claim-both-sast", 3, REQ, 160),
        _rel("claim-both-hunt", 4, REQ, 161),
        _rel("claim-fp-refuted", 5, UTIL, 20),
        _rel("claim-bonus", 6, EXTRA, 14),
    ]
    proposal_packages = {
        "claim-sast": ["finding_lead-1"],
        "claim-hunt": ["hunt-1"],
        "claim-both-sast": ["finding_lead-2"],
        "claim-both-hunt": ["hunt-1"],
        "claim-dep": ["finding_lead-4"],
        "claim-fp-refuted": ["finding_lead-3"],
        "claim-bonus": ["hunt-1"],
    }
    published_pairs = [
        ("fp-sast", "claim-sast", "critical"),
        ("fp-hunt", "claim-hunt", "high"),
        ("fp-both-sast", "claim-both-sast", "high"),
        ("fp-both-hunt", "claim-both-hunt", "high"),
        ("fp-dep", "claim-dep", "high"),
        ("fp-bonus", "claim-bonus", "medium"),
    ]
    if include_false_alarm:
        claims.append({"claim_id": "claim-false-alarm", "lane": "hunt", "package_id": "hunt-1", "state": "confirmed", "weakness_cwe": "CWE-120", "affected_entities": [], "state_history": []})
        relations.append(_rel("claim-false-alarm", 7, UTIL, 50))
        proposal_packages["claim-false-alarm"] = ["hunt-1"]
        published_pairs.append(("fp-false-alarm", "claim-false-alarm", "medium"))

    _write_json(
        rev_attempt / "steps" / "publication" / "tasks" / "publish_claim_ledger" / "projection.json",
        {
            "schema": "appsec-review/claim-projection/1",
            "ledger_head_sha256": "1" * 64,
            "claims": claims,
            "relations": relations,
            "cells": {},
            "gaps": [],
            "evidence_requests": [],
            "judge_verdicts": {"claim-fp-refuted": [{"verdict_id": "j-fp", "claim_id": "claim-fp-refuted", "verdict": "blue_correct", "cell_id": "c-j"}]},
        },
    )
    _write_json(rev_attempt / "steps" / "merge" / "tasks" / "claims" / "merge.json", {"proposal_packages": proposal_packages})

    gate_packages = []
    report_findings = []
    for fid, cid, sev in published_pairs:
        _write_json(
            rev_attempt / "steps" / "publication" / "tasks" / "publish_handoff" / "findings" / f"{fid}.json",
            {"schema": "appsec-review/finding-package/2", "finding_package_id": fid, "claim_id": cid, "state": "confirmed", "technical_severity": sev, "title": f"Confirmed issue for {cid}"},
        )
        gate_packages.append({"finding_package_id": fid, "claim_id": cid, "state": "confirmed", "bucket": "publishable", "severity": sev})
        report_findings.append({"finding_package_id": fid, "claim_id": cid})

    _handoff(run, DOSSIER_JOB, {"dossiers.create": "SUCCEEDED"}, steps=("dossiers",))
    gate_attempt = _handoff(run, GATE_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("acceptance",))
    _write_json(
        gate_attempt / "steps" / "acceptance" / "tasks" / "publish_handoff" / "final-publication-gate.json",
        {"schema": "appsec-review/final-publication-gate/2", "run_id": run.name, "packages": gate_packages},
    )
    rep_attempt = _handoff(run, REPORT_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("report",))
    _write_json(
        rep_attempt / "steps" / "report" / "tasks" / "build" / "final-report.json",
        {
            "schema": "appsec-review/final-report/2",
            "run_id": run.name,
            "findings": report_findings,
            "poc_outcomes": {"items": [{"finding": {"claim_id": "claim-sast"}, "status": "verified"}]},
            "remediation_validation": {
                "items": [
                    {"finding": {"claim_id": "claim-sast"}, "status": "build_checked"},
                    {"finding": {"claim_id": "claim-hunt"}, "status": "build_checked"},
                ]
            },
        },
    )

    planted = [
        {"class": "true_positive_code", "id": "TP-SAST", "cwe": "CWE-78", "axis": "injection", "real_severity": "critical", "title": "Command injection", "file": REQ, "function": "run_cmd", "span": {"start_line": 120, "end_line": 120}, "expected_disposition": "reported"},
        {"class": "true_positive_code", "id": "TP-HUNT", "cwe": "CWE-287", "axis": "access_control", "real_severity": "high", "title": "Auth bypass", "file": AUTH, "function": "check_token", "span": {"start_line": 45, "end_line": 45}, "expected_disposition": "reported"},
        {"class": "true_positive_code", "id": "TP-BOTH", "cwe": "CWE-134", "axis": "injection", "real_severity": "high", "title": "Format string", "file": REQ, "function": "log_req", "span": {"start_line": 160, "end_line": 162}, "expected_disposition": "reported"},
        {"class": "true_positive_code", "id": "TP-MISS", "cwe": "CWE-327", "axis": "cryptography", "real_severity": "medium", "title": "Weak cipher", "file": CRYPTO, "function": "encrypt_block", "span": {"start_line": 88, "end_line": 90}, "expected_disposition": "reported"},
        {"class": "true_positive_dependency", "id": "TP-DEP", "package": "zlib", "version": "1.2.11", "ecosystem": "vendored-c", "osv": "GHSA-jc36-42cf-vqwj", "cve": "CVE-2018-25032", "axis": "supply_chain", "location": "third_party/zlib", "expected_disposition": "reported"},
        {"class": "false_positive", "id": "FP-1", "axis": "memory_safety", "file": UTIL, "function": "safe_copy", "span": {"start_line": 20, "end_line": 20}, "flagged_by": ["rules.cpp-bounded-copy"], "expected_disposition": "squelched"},
    ]
    if include_false_alarm:
        planted.append({"class": "false_positive", "id": "FP-2", "axis": "memory_safety", "file": UTIL, "function": "other_safe_copy", "span": {"start_line": 50, "end_line": 50}, "flagged_by": [], "expected_disposition": "squelched"})

    key_path = tmp_path / "external-smoke-keys" / "cpp" / "answer-key.json"
    _write_json(
        key_path,
        {
            "schema": "appsec-review/smoke-answer-key/1",
            "version": "1.1.0",
            "language": "cpp",
            "tag": "v1.1.0",
            "commit": COMMIT_SHA,
            "repository": "https://github.com/wsollers/appsec-review-smoke-cpp",
            "chains": [],
            "planted": planted,
        },
    )
    return run, key_path



def test_discover_matching_smoke_key_by_commit_and_slug(tmp_path: Path) -> None:
    _run, key_path = _build_effectiveness_fixture(tmp_path)
    guide_root = key_path.parents[1]

    assert discover_matching_smoke_key(
        guide_root, repository=None, target_id="other-name", snapshot_commit=COMMIT_SHA
    ) == key_path.resolve()
    assert discover_matching_smoke_key(
        guide_root, repository=None, target_id="other-name", snapshot_commit=COMMIT_SHA[:12]
    ) == key_path.resolve()
    assert discover_matching_smoke_key(
        guide_root, repository="wsollers/appsec-review-smoke-cpp", target_id="appsec-review-smoke-cpp", snapshot_commit=None
    ) == key_path.resolve()
    assert discover_matching_smoke_key(
        guide_root, repository="wsollers/appsec-review-smoke-cpp", target_id="appsec-review-smoke-cpp", snapshot_commit="deadbeef" * 5
    ) is None
    assert discover_matching_smoke_key(
        guide_root, repository="acme/customer-portal", target_id="customer-portal", snapshot_commit="12345678" * 5
    ) is None
    assert discover_matching_smoke_key(
        tmp_path / "missing-guide-dir", repository="wsollers/appsec-review-smoke-cpp", target_id="appsec-review-smoke-cpp", snapshot_commit=COMMIT_SHA
    ) is None


def test_sast_vs_hunter_attribution_and_planted_reconciliation(tmp_path: Path) -> None:
    run, key_path = _build_effectiveness_fixture(tmp_path)
    payload = build_smoke_effectiveness(run, key_path=key_path)

    assert payload["schema"] == SCHEMA
    assert payload["keyed_smoke_target"] is True
    assert payload["answer_key"]["repository_slug"] == "appsec-review-smoke-cpp"
    assert len(payload["answer_key"]["answer_key_sha256"]) == 64

    lanes = payload["lane_attribution"]
    assert lanes["confirmed_from_sast_lane"] == 3
    assert lanes["confirmed_from_hunter_lane"] == 3
    assert lanes["both_lanes_count"] == 1
    assert lanes["hunter_only_count"] == 2
    assert lanes["sast_only_count"] == 1
    assert lanes["dependency_scanner_count"] == 1

    recs_by_claim = {r["claim_id"]: r for r in payload["adjudicated_findings"]}
    assert recs_by_claim["claim-sast"]["poc_status"] == "verified"
    assert recs_by_claim["claim-sast"]["remediation_validation_status"] == "build_checked"
    assert recs_by_claim["claim-hunt"]["remediation_validation_status"] == "build_checked"

    keyed = payload["keyed"]
    assert keyed is not None
    by_pos = {p["id"]: p for p in keyed["planted_positives"]}
    assert by_pos["TP-SAST"]["reconciliation"] == "MATCHED" and by_pos["TP-SAST"]["attribution_lane"] == "sast_only"
    assert by_pos["TP-HUNT"]["reconciliation"] == "MATCHED" and by_pos["TP-HUNT"]["attribution_lane"] == "hunter_only"
    assert by_pos["TP-BOTH"]["reconciliation"] == "MATCHED" and by_pos["TP-BOTH"]["attribution_lane"] == "both_lanes"
    assert by_pos["TP-MISS"]["reconciliation"] == "MISSED" and by_pos["TP-MISS"]["attribution_lane"] == "missed"
    assert by_pos["TP-DEP"]["reconciliation"] == "MATCHED" and by_pos["TP-DEP"]["attribution_lane"] == "dependency_scanner"

    by_neg = {n["id"]: n for n in keyed["planted_negatives"]}
    assert by_neg["FP-1"]["reconciliation"] == "CLEANLY_REJECTED"
    assert by_neg["FP-1"]["raw_sast_hit"] is True
    assert by_neg["FP-1"]["suppression_mechanism"] == "verifier_or_judge_refuted"

    bonus = keyed["unplanted_code_findings"]
    assert len(bonus) == 1
    assert bonus[0]["finding_id"] == "fp-bonus"
    assert bonus[0]["location"] == f"{EXTRA}:14"
    assert bonus[0]["lane"] == "Hunter"

    hl = keyed["headline_metrics"]
    assert hl["code_tp_matched"] == 3 and hl["code_tp_total"] == 4
    assert hl["code_tp_recall"] == pytest.approx(0.75)
    assert hl["sast_only_code_recall"] == pytest.approx(0.50)
    assert hl["hunter_only_code_recall"] == pytest.approx(0.50)
    assert hl["combined_sast_hunter_recall"] == pytest.approx(0.75)
    assert hl["vendored_cve_recall"] == pytest.approx(1.0)
    assert hl["planted_fp_trap_rejection_rate"] == pytest.approx(1.0)
    assert hl["precision"] == pytest.approx(1.0)


def test_non_smoke_run_skips_ground_truth_and_preserves_lane_attribution(tmp_path: Path) -> None:
    run, _key_path = _build_effectiveness_fixture(tmp_path)
    payload = build_smoke_effectiveness(run, key_path=None)

    assert payload["schema"] == SCHEMA
    assert payload["keyed_smoke_target"] is False
    assert payload["answer_key"] is None
    assert payload["keyed"] is None
    assert payload["lane_attribution"]["both_lanes_count"] == 1


def test_false_alarm_on_planted_negative_reduces_precision_and_rejection_rate(tmp_path: Path) -> None:
    run, key_path = _build_effectiveness_fixture(tmp_path, include_false_alarm=True)
    payload = build_smoke_effectiveness(run, key_path=key_path)
    keyed = payload["keyed"]
    assert keyed is not None
    by_neg = {n["id"]: n for n in keyed["planted_negatives"]}
    assert by_neg["FP-1"]["reconciliation"] == "CLEANLY_REJECTED"
    assert by_neg["FP-2"]["reconciliation"] == "FALSE_ALARM"

    hl = keyed["headline_metrics"]
    assert hl["planted_negatives_total"] == 2
    assert hl["false_alarms"] == 1
    assert hl["planted_fp_trap_rejection_rate"] == pytest.approx(0.5)
    assert hl["precision"] == pytest.approx(0.8)


def test_markdown_latex_and_pdf_receipt_rendering(tmp_path: Path) -> None:
    run, key_path = _build_effectiveness_fixture(tmp_path)
    payload = build_smoke_effectiveness(run, key_path=key_path)
    md = render_smoke_effectiveness_markdown(payload)
    assert "## SAST vs Autonomous Hunter Attribution" in md
    assert "## Planted Positives Reconciliation" in md
    assert "TP-HUNT" in md and "Hunter only" in md

    doc = build_smoke_effectiveness_document(payload)
    tex = render_latex(doc, TEMPLATE)
    html = render_html(doc)
    assert "Smoke" in tex and "TP{-}HUNT" in tex
    assert "Smoke" in html

    seen: list[Any] = []
    receipt = write_smoke_effectiveness_outputs(
        run,
        payload,
        render_tex_and_pdf=True,
        render_pdf=True,
        repository_root=ROOT,
        executor_factory=_fake_executor_factory(seen),
    )
    assert receipt is not None
    assert receipt["schema"] == RECEIPT_SCHEMA
    assert receipt["status"] == "rendered"
    assert len(seen) == 1
    ver = run / "data" / "verification"
    assert (ver / "smoke-effectiveness.json").is_file()
    assert (ver / "smoke-effectiveness.md").is_file()
    assert (ver / "smoke-effectiveness.tex").is_file()
    assert (ver / "smoke-effectiveness.pdf").read_bytes() == FAKE_PDF
    assert (ver / RECEIPT_NAME).is_file()


def test_blind_target_isolation_in_effectiveness_outputs(tmp_path: Path) -> None:
    from tests.test_blind_target_isolation import leaked_evaluator_material

    run, key_path = _build_effectiveness_fixture(tmp_path)
    payload = build_smoke_effectiveness(run, key_path=key_path)
    seen: list[Any] = []
    write_smoke_effectiveness_outputs(
        run,
        payload,
        render_tex_and_pdf=True,
        render_pdf=False,
        repository_root=ROOT,
        executor_factory=_fake_executor_factory(seen),
    )
    assert leaked_evaluator_material(tmp_path / "runs") == []
    raw_guide_str = str(key_path.parent)
    ver = run / "data" / "verification"
    for fname in ("smoke-effectiveness.json", "smoke-effectiveness.md", "smoke-effectiveness.tex"):
        content = (ver / fname).read_text(encoding="utf-8")
        assert raw_guide_str not in content
