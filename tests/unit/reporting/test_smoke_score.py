"""The smoke-run verification harness (T-5019) over a synthetic run tree and a synthetic answer key.

Nothing here touches a real run or the real answer key: the run tree is built in ``tmp_path`` with the
published shapes the scorer reads (accepted index shards, ``latest.json`` handoffs, the review assembly,
the claim projection, finding packages, the gate and report documents, the graph scorecard, model receipts
and the budget ledger), and the key is written from the schema in ``answer-key-schema.md``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.reporting import smoke_score
from appsec_review.reporting.smoke_score import (
    SCHEMA, SmokeScoreError, load_answer_key, main, render_summary, score_run, validate_document, write_outputs,
)

SNAPSHOT = "7" * 64
REVIEW = smoke_score.REVIEW_JOB
ATTEMPT = "attempt_0001"
REQUEST, UTIL, VENDORED, EXTRA = "src/request.cpp", "src/util.c", "third_party/zlib/inflate.c", "src/extra.cpp"
ID = {
    REQUEST: "asr:source_file:" + "a" * 64, UTIL: "asr:source_file:" + "b" * 64, VENDORED: "asr:source_file:" + "c" * 64,
    "README.md": "asr:source_file:" + "d" * 64, EXTRA: "asr:source_file:" + "e" * 64,
    "obs-tp": "asr:tool_observation:" + "1" * 64, "obs-fp": "asr:tool_observation:" + "2" * 64,
    "obs-vendored": "asr:tool_observation:" + "3" * 64, "obs-dep": "asr:tool_observation:" + "4" * 64,
    "obs-other": "asr:tool_observation:" + "5" * 64, "dep-zlib": "asr:dependency_package:" + "6" * 64,
    "path-ok": "asr:dataflow_path:" + "8" * 64, "path-unclassified": "asr:dataflow_path:" + "9" * 64,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: Path, value) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, sort_keys=True).encode()
    path.write_bytes(data)
    return {"path": None, "sha256": _sha(data), "size_bytes": len(data)}


def _shard(path: Path, rows, coverage=(("fixture", "complete", None),)) -> None:
    """``rows``: (identity, kind, native_id, name, payload, location|None); location = (path, start, end)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript("""
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
    """)
    for identity, kind, native_id, name, payload, location in rows:
        con.execute("INSERT INTO entities VALUES (?,?,?,?,?,?)", (identity, kind, native_id, name, "", json.dumps(payload)))
        if location is not None:
            file, start, end = location
            con.execute("INSERT INTO locations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (f"loc:{_sha(identity.encode())}", identity, SNAPSHOT, file, _sha(file.encode()), 0, 1, start, end,
                         1, 1, "{}", "fixture-exact", 1.0, 0))
    con.executemany("INSERT INTO coverage VALUES (?,?,?)", list(coverage))
    con.execute("INSERT INTO metadata VALUES (?,?)", ("target_snapshot", SNAPSHOT))
    con.commit()
    con.close()


def _observation(scanner: str, rule: str, extra=None) -> dict:
    return {"schema": "appsec-review/observation/1", "common": {"scanner": scanner, "rule_id": rule,
            "observation_class": "source_sast", "reported_severity": {"value": "high"}}, **(extra or {})}


def _dataflow(sink_class: str, eligible: bool) -> dict:
    return {"family": "dataflow_path", "admissibility": {"direct_eligible": eligible, "rule": "graph-fact-admissibility/1",
            "ineligibility_reasons": [] if eligible else ["unclassified_sink"]},
            "result": {"sink": {"sink_class": sink_class, "cwe_family": None}, "source": {"source_class": "network_input"}}}


def _handoff(run: Path, job: str, outputs: dict, *, gaps=(), completion="SUCCEEDED", steps=("load", "publish")) -> None:
    attempt = run / "data" / "jobs" / job / "attempts" / ATTEMPT
    outcomes = {"schema": "appsec-review/job-outcomes/1", "job_id": job, "attempt_id": ATTEMPT,
                "gaps": [{"schema": "appsec-review/producer-gap/1", "code": code, "reason": reason} for code, reason in gaps]}
    outcomes_ref = _write(attempt / "outcomes.json", outcomes)
    outcomes_ref["path"] = f"data/jobs/{job}/attempts/{ATTEMPT}/outcomes.json"
    handoff = {"schema": "appsec-review/job-handoff/2", "job_id": job, "attempt_id": ATTEMPT, "status": "ACCEPTED",
               "completion_status": completion, "execution_status": "SUCCEEDED",
               "started_at": "2026-11-14T21:57:15.939770+00:00", "completed_at": "2026-11-14T21:58:51.128245+00:00",
               "coverage": {"disposition": "partial" if gaps else "complete", "gap_count": len(gaps)},
               "outcomes": outcomes_ref, "outputs": {unit: {"terminal_status": status} for unit, status in outputs.items()}}
    ref = _write(attempt / "handoff.json", handoff)
    _write(run / "data" / "jobs" / job / "latest.json", {"schema": "appsec-review/latest-handoff/1", "attempt_id": ATTEMPT,
           "handoff_path": f"data/jobs/{job}/attempts/{ATTEMPT}/handoff.json", "handoff_sha256": ref["sha256"]})
    for index, step in enumerate(steps):
        _write(attempt / "steps" / step / "lifecycle.json", {"step_id": step, "status": "SUCCEEDED", "duration_ms": 400 + index,
               "started_at": "2026-11-14T21:57:16+00:00", "completed_at": "2026-11-14T21:57:17+00:00"})
        _write(attempt / "steps" / step / "tasks" / "work" / "status.json", {"schema": "appsec-review/task-receipt/1",
               "status": "SUCCEEDED", "started_at": "2026-11-14T21:57:16+00:00", "completed_at": "2026-11-14T21:57:18+00:00"})


def build_run(root: Path, *, facets=True, graph=True, review=True, graph_job=True, scorecard=True, report=True,
              extra_first_party=False, unit_overlap=False, util_facets=True, admit_vendored=False,
              classified_ineligible=False, duplicate_function=False, unknown_terminal=False) -> Path:
    run = root / "runs" / "2026-11-14-9999"
    data = run / "data"
    _write(data / "configuration" / "resolved.json", {"jobs": {REVIEW: {"name": REVIEW, "settings": {
        "source_dispositions": {"vendored": ["**/third_party/**"], "test": ["**/tests/**"]},
        "budgets": {"max_output_tokens": 6000000, "max_model_turns": 12000}}}}})
    indices = data / "indices"
    shards = []

    def add(name, shard_id, relative, rows, producer, coverage=(("fixture", "complete", None),)):
        _shard(run / relative, rows, coverage)
        shards.append({"name": name, "shard_id": shard_id, "relative_path": relative, "sha256": _sha((run / relative).read_bytes()),
                       "fingerprint": "f" * 64, "producer": producer, "gaps": [], "schema": "appsec-review/retrieval-index/2"})

    sources = [(ID[REQUEST], "source_file", REQUEST, REQUEST, {"language": "C++"}, (REQUEST, 1, 200)),
               (ID[UTIL], "source_file", UTIL, UTIL, {"language": "C"}, (UTIL, 1, 60)),
               (ID[VENDORED], "source_file", VENDORED, VENDORED, {"language": "C"}, (VENDORED, 1, 900)),
               (ID["README.md"], "source_file", "README.md", "README.md", {"language": None}, ("README.md", 1, 1))]
    if extra_first_party:
        sources.append((ID[EXTRA], "source_file", EXTRA, EXTRA, {"language": "C++"}, (EXTRA, 1, 20)))
    add("source", "default", "data/indices/source/src.sqlite", sources, {"job": "job_target_catalog"})
    if facets:
        rows = [("asr:tag_assignment:" + "a1" * 32, "tag_assignment", "tag:1", "role:request-handler",
                 {"tag": "role:request-handler", "namespace": "role", "subject": {"kind": "source_file", "path": REQUEST}}, (REQUEST, 1, 200)),
                ("asr:tag_assignment:" + "a2" * 32, "tag_assignment", "tag:2", "exposure:network",
                 {"tag": "exposure:network", "namespace": "exposure", "subject": {"kind": "source_file", "path": REQUEST}}, (REQUEST, 1, 200)),
                ("asr:tag_assignment:" + "a4" * 32, "tag_assignment", "tag:4", "func:exec:unmanaged-memory",
                 {"tag": "func:exec:unmanaged-memory", "namespace": "func", "subject": {"kind": "source_file", "path": UTIL}}, (UTIL, 1, 60))]
        if extra_first_party:
            rows.append(("asr:tag_assignment:" + "a5" * 32, "tag_assignment", "tag:5", "role:helper",
                         {"tag": "role:helper", "namespace": "role", "subject": {"kind": "source_file", "path": EXTRA}}, (EXTRA, 1, 20)))
        if util_facets:
            rows.append(("asr:tag_assignment:" + "a3" * 32, "tag_assignment", "tag:3", "mechanism:buffer-copy",
                         {"tag": "mechanism:buffer-copy", "namespace": "mechanism", "subject": {"kind": "source_file", "path": UTIL}}, (UTIL, 1, 60)))
        add("tags", "facets", "data/indices/tags/facets/facets.sqlite", rows, {"job": "job_security_tagging", "family": "code_facts"})
    add("observations", "semgrep", "data/indices/observations/semgrep/s.sqlite", [
        (ID["obs-tp"], "tool_observation", "evidence-1", "cpp-popen", _observation("tool-semgrep", "rules.cpp-command-injection"), (REQUEST, 137, 137)),
        (ID["obs-fp"], "tool_observation", "evidence-2", "cpp-copy", _observation("tool-semgrep", "appsec-review.review-signal.sink.cpp-copy-length-not-bounded"), (UTIL, 20, 20)),
        (ID["obs-vendored"], "tool_observation", "evidence-3", "cpp-copy", _observation("tool-semgrep", "rules.cpp-memcpy"), (VENDORED, 10, 10)),
        (ID["obs-other"], "tool_observation", "evidence-5", "cpp-other", _observation("tool-semgrep", "rules.cpp-other"), (REQUEST, 80, 80)),
    ], {"job": "job_evidence_collection", "producer": "tool-semgrep"})
    add("observations", "grype", "data/indices/observations/grype/g.sqlite", [
        (ID["obs-dep"], "tool_observation", "evidence-4", "CVE-2018-25032", _observation(
            "tool-grype", "CVE-2018-25032", {"advisory": {"id": "CVE-2018-25032", "aliases": ["GHSA-jc36-42cf-vqwj"], "package": "zlib", "version": "1.2.11"}}),
         None),
    ], {"job": "job_evidence_collection", "producer": "tool-grype"})
    add("inventory", "dependency-intelligence", "data/indices/inventory/inv.sqlite", [
        (ID["dep-zlib"], "dependency_package", "dependency-1", "zlib", {"name": "zlib", "version": "1.2.11"}, None),
    ], {"job": "job_dependency_intelligence"})
    if graph:
        add("graph", "graph-scope-1-dataflow_path", "data/indices/graph/dataflow/d.sqlite", [
            (ID["path-ok"], "dataflow_path", ID["path-ok"], "recv -> popen [command_execution]",
             _dataflow("command_execution", not classified_ineligible), (REQUEST, 137, 137)),
            (ID["path-unclassified"], "dataflow_path", ID["path-unclassified"], "fread -> send [unclassified]",
             _dataflow("unclassified", False), (REQUEST, 127, 127)),
        ], {"job": "job_code_graph_index", "family": "dataflow_path", "scope_id": "scope-1"})
    manifest = {"schema": "appsec-review/retrieval-index/2", "run_id": run.name, "target_snapshot": SNAPSHOT, "indexes": shards}
    manifest_ref = _write(indices / "manifests" / "tags-attempt_0001.json", manifest)
    _write(indices / "accepted.json", {"schema": "appsec-review/accepted-index-set/1", "run_id": run.name,
           "manifest_path": "data/indices/manifests/tags-attempt_0001.json", "manifest_sha256": manifest_ref["sha256"],
           "handoff_path": f"data/jobs/job_security_tagging/attempts/{ATTEMPT}/handoff.json", "handoff_sha256": "0" * 64})

    _handoff(run, "job_security_tagging", {"collection.source_facts": "SUCCEEDED", "publication.publish_handoff": "SUCCEEDED"},
             gaps=(("producer_reported_gap", "collation:no_graph_facts"),), completion="COMPLETED_WITH_GAPS")
    _handoff(run, "job_review_prioritization", {"prioritize.score": "SUCCEEDED"})
    priority_attempt = data / "jobs" / "job_review_prioritization" / "attempts" / ATTEMPT
    _write(priority_attempt / "steps" / "prioritize" / "tasks" / "score" / "artifacts" / "priority.json", {
        "schema": "appsec-review/review-prioritization/1", "population": "run",
        "files": [{"path": REQUEST, "rank": 1, "share_above_threshold": {"10": 0.5, "15": 0.25}},
                  {"path": UTIL, "rank": 2, "share_above_threshold": {"10": 0.0, "15": 0.0}}],
        "functions": [{"path": REQUEST, "name": "handle_request", "rank": 1, "features": {"cyclomatic": 36}},
                      {"path": UTIL, "name": "frame_fill", "rank": 2, "features": {"cyclomatic": 3}}]})
    _write(priority_attempt / "steps" / "extract" / "tasks" / "syntax_metrics" / "artifacts" / "syntax-facts.json", {
        "schema": "appsec-review/syntax-facts/1", "files": {REQUEST: {"path": REQUEST, "units": [
            {"name": "handle_request", "start_line": 100, "end_line": 164, "cyclomatic": 36},
            {"name": "run_tool", "start_line": 40, "end_line": 60, "cyclomatic": 4}]}}})
    if graph_job:
        _handoff(run, smoke_score.GRAPH_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("acceptance",))
        if scorecard:
            functions = [{"path": REQUEST, "name": "handle_request", "line": 100, "symbol": "s1", "calls": {"total": 2}, "producers": []},
                         {"path": REQUEST, "name": "run_tool", "line": 40, "symbol": "s2", "calls": {"total": 1}, "producers": []},
                         {"path": UTIL, "name": "frame_fill", "line": 15, "symbol": "s3", "calls": {"total": 0}, "producers": []}]
            if duplicate_function:
                functions.append(dict(functions[0]))
            _write(data / "jobs" / smoke_score.GRAPH_JOB / "attempts" / ATTEMPT / "steps" / "acceptance" / "tasks" / "publish_handoff"
                   / "graph-quality-scorecard.json", {"schema": "appsec-review/graph-quality-scorecard/1", "run_id": run.name,
                   "totals": {"first_party_functions": 3, "paths": 2, "paths_eligible": 1},
                   "scopes": [{"scope_id": "scope-1", "functions": functions, "paths": []}]})
    if review:
        _review(run, admit_vendored=admit_vendored, unit_overlap=unit_overlap, unknown_terminal=unknown_terminal)
        _handoff(run, smoke_score.GATE_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("acceptance",))
        _write(data / "jobs" / smoke_score.GATE_JOB / "attempts" / ATTEMPT / "steps" / "acceptance" / "tasks" / "publish_handoff"
               / "final-publication-gate.json", {"schema": "appsec-review/final-publication-gate/2", "run_id": run.name, "packages": [
                   {"finding_package_id": "finding_package-1", "claim_id": "claim-1", "state": "confirmed", "bucket": "publishable"},
                   {"finding_package_id": "finding_package-3", "claim_id": "claim-3", "state": "confirmed", "bucket": "publishable"},
                   {"finding_package_id": "finding_package-4", "claim_id": "claim-4", "state": "supported", "bucket": "publishable"}]})
        if report:
            _handoff(run, smoke_score.REPORT_JOB, {"acceptance.publish_handoff": "SUCCEEDED"}, steps=("report",))
            _write(data / "jobs" / smoke_score.REPORT_JOB / "attempts" / ATTEMPT / "steps" / "report" / "tasks" / "build" / "final-report.json",
                   {"schema": "appsec-review/final-report/2", "run_id": run.name, "findings": [
                       {"finding_package_id": "finding_package-1", "claim_id": "claim-1"},
                       {"finding_package_id": "finding_package-3", "claim_id": "claim-3"},
                       {"finding_package_id": "finding_package-4", "claim_id": "claim-4"}]})
    receipts = data / "inference-executions" / ("0" * 64)
    for index, (job, status, tokens) in enumerate(((REVIEW, "SUCCEEDED", 1200), (REVIEW, "FAILED", None),
                                                   ("job_dependency_intelligence", "SUCCEEDED", 300))):
        _write(receipts / f"exec-{index}" / "000001.json", {"schema": "appsec-review/model-execution-receipt/1", "job_id": job,
               "status": status, "elapsed_ms": 1000 + index, "requested_model": "claude-haiku-5-5",
               "usage": {"input_tokens": tokens, "output_tokens": (tokens or 0) // 2 if tokens else None, "cache_tokens": None}})
    if review:
        _write(data / "jobs" / REVIEW / "budget" / "budget.json", {"schema": "appsec-review/inference-review-budget/2",
               "limits": {"max_model_turns": 12000, "max_input_tokens": 60000000, "max_output_tokens": 6000000, "max_retrieval_queries": 40000},
               "model_turns": 2, "input_tokens": 1200, "output_tokens": 600, "retrieval_queries": 3, "exhausted": None,
               "team_packages": {"lead": 2, "hunt": 1}})
    return run


def _review(run: Path, *, admit_vendored: bool, unit_overlap: bool, unknown_terminal: bool) -> None:
    attempt = run / "data" / "jobs" / REVIEW / "attempts" / ATTEMPT
    _handoff(run, REVIEW, {"packages.assemble_lead_packages": "SUCCEEDED",
                           "publication.publish_handoff": "WEIRD" if unknown_terminal else "SUCCEEDED"}, steps=("packages", "publication"))
    assembly = attempt / "steps" / "packages" / "tasks" / "assemble_lead_packages" / "assembly"
    unit_doc = {"schema": "appsec-review/package-unit-context/2", "unit_key": "unit-1",
                "scope": {"component_id": "component:0001", "source_ids": [ID[REQUEST], ID[UTIL]]}}
    unit_bytes = json.dumps(unit_doc, sort_keys=True).encode()
    unit_sha = _sha(unit_bytes)
    (assembly / "unit-context").mkdir(parents=True)
    (assembly / "unit-context" / f"{unit_sha}.json").write_bytes(unit_bytes)
    packages = {
        "finding_lead-1": {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": ID["obs-tp"], "lead_family": "source_sast",
                           "scanner": "tool-semgrep"}], "scope": {"source_ids": [ID[REQUEST]]}, "unit_context": None},
        "finding_lead-2": {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": ID["obs-dep"], "lead_family": "dependency_advisory",
                           "scanner": "tool-grype"}], "scope": {"source_ids": []}, "unit_context": None},
        "hunt-1": {"kind": "hunt", "lane": "hunt", "lead_menu": [{"observation_id": ID["obs-fp"]}], "scope": {},
                   "unit_context": {"schema": unit_doc["schema"], "path": f"unit-context/{unit_sha}.json", "sha256": unit_sha}},
    }
    if admit_vendored:
        packages["finding_lead-3"] = {"kind": "finding_lead", "lane": "lead", "lead_menu": [{"observation_id": ID["obs-vendored"]}],
                                     "scope": {"source_ids": [ID[VENDORED]]}, "unit_context": None}
    for package_id, body in packages.items():
        _write(assembly / "packages" / f"{package_id}.json", {**body, "package_id": package_id})
    units = [{"unit_key": "unit-1", "source_ids": [ID[REQUEST], ID[UTIL]], "hunted": True, "package_ids": ["hunt-1"]}]
    if unit_overlap:
        units.append({"unit_key": "unit-2", "source_ids": [ID[UTIL]], "hunted": False, "package_ids": []})
    _write(assembly / "package-manifest.json", {
        "schema": "appsec-review/review-package-manifest/1", "run_id": run.name,
        "admission": [{"lead_id": ID["obs-tp"], "status": "admitted", "effective_severity": "high"},
                      {"lead_id": ID["obs-fp"], "status": "admitted", "effective_severity": "high"},
                      {"lead_id": ID["obs-dep"], "status": "admitted", "effective_severity": "critical"},
                      {"lead_id": ID["obs-vendored"], "status": "admitted" if admit_vendored else "not_admitted",
                       "effective_severity": "high", **({} if admit_vendored else {"exclusion": "vendored"})}],
        "packages": [{"package_id": package_id, "kind": body["kind"], "lane": body["lane"], "unit_key": None}
                     for package_id, body in packages.items()],
        "units": units, "counts": {"dispositions": {"files": {"first_party": 2, "vendored": 1}}}})
    claims = [
        {"claim_id": "claim-1", "lane": "lead", "package_id": "finding_lead-1", "state": "confirmed", "weakness_cwe": "CWE-78",
         "affected_entities": [ID["obs-tp"]], "state_history": []},
        {"claim_id": "claim-2", "lane": "hunt", "package_id": "hunt-1", "state": "contradicted", "weakness_cwe": "CWE-120",
         "affected_entities": [ID["obs-fp"]], "state_history": []},
        {"claim_id": "claim-3", "lane": "lead", "package_id": "finding_lead-2", "state": "confirmed", "weakness_cwe": "CWE-787",
         "affected_entities": [ID["obs-dep"]], "state_history": []},
        {"claim_id": "claim-4", "lane": "hunt", "package_id": "hunt-1", "state": "supported", "weakness_cwe": "CWE-20",
         "affected_entities": [ID["obs-other"]], "state_history": []},
    ]
    _write(attempt / "steps" / "publication" / "tasks" / "publish_claim_ledger" / "projection.json", {
        "schema": "appsec-review/claim-projection/1", "ledger_head_sha256": "1" * 64, "claims": claims,
        "relations": {"claim-1": [{"relation_id": "evrel-1", "claim_id": "claim-1", "entity_id": ID[REQUEST], "kind": "supports"}]},
        "cells": {}, "gaps": [], "evidence_requests": [],
        "judge_verdicts": {"claim-1": [{"verdict_id": "judge-1", "claim_id": "claim-1", "verdict": "red_correct", "cell_id": "cell-j1"}],
                           "claim-2": [{"verdict_id": "judge-2", "claim_id": "claim-2", "verdict": "blue_correct", "cell_id": "cell-j2"}]}})
    _write(attempt / "steps" / "merge" / "tasks" / "claims" / "merge.json", {
        "proposal_packages": {"claim-1": ["finding_lead-1"], "claim-2": ["hunt-1"], "claim-3": ["finding_lead-2"], "claim-4": ["hunt-1"]}})
    for number, claim in (("1", "claim-1"), ("3", "claim-3"), ("4", "claim-4")):
        _write(attempt / "steps" / "publication" / "tasks" / "publish_handoff" / "findings" / f"finding_package-{number}.json",
               {"schema": "appsec-review/finding-package/2", "finding_package_id": f"finding_package-{number}", "claim_id": claim,
                "state": "confirmed" if number != "4" else "supported"})


def answer_key(root: Path, *, tp_file: str = REQUEST) -> Path:
    key = {
        "schema": "appsec-review/smoke-answer-key/1", "language": "cpp", "tag": "v1.0.0", "commit": "0" * 40,
        "repository": "https://example.invalid/smoke", "planted": [
            {"class": "true_positive_code", "id": "TP-C1", "cwe": "CWE-78", "title": "command injection through the EXEC verb",
             "file": tp_file, "function": "handle_request", "span": {"start_line": 137, "end_line": 137},
             "expected_disposition": "reported"},
            {"class": "fixed_code", "id": "FX-C1", "cwe": "CWE-78", "title": "command injection in run_tool", "file": REQUEST,
             "function": "run_tool", "introduced_span": {"start_line": 0, "end_line": 0}, "expected_disposition": "reported-as-fixed"},
            {"class": "false_positive", "id": "FP-1", "file": UTIL, "function": "frame_fill", "span": {"start_line": 20, "end_line": 20},
             "flagged_by": ["appsec-review.review-signal.sink.cpp-copy-length-not-bounded"], "expected_disposition": "squelched"},
            {"class": "true_positive_dependency", "id": "TP-D1", "package": "zlib", "version": "1.2.11", "ecosystem": "vendored-c",
             "osv": "GHSA-jc36-42cf-vqwj", "cve": "CVE-2018-25032", "location": "third_party/zlib", "expected_disposition": "reported"},
            {"class": "fixed_dependency", "id": "FX-D1", "package": "cjson", "ecosystem": "vendored-c", "vulnerable_version": "1.7.16",
             "fixed_version": "1.7.17", "osv": "CVE-2023-50472", "cve": "CVE-2023-50472", "expected_disposition": "reported-as-fixed"},
        ],
        "complexity": {"file": REQUEST, "function": "handle_request", "cyclomatic": 36, "holds": "TP-C1", "expected_top_rank": True,
                       "cyclomatic_high_risk_share_above_zero": True},
    }
    path = root / "answer-key.json"
    _write(path, key)
    return path


def _checks(document) -> dict[str, dict]:
    return {check["check_id"]: check for check in document["structural_checks"]}


def _items(document) -> dict[str, dict]:
    return {item["id"]: item for item in document["keyed"]["items"]}


def test_keyed_scoring_reports_every_planted_item_and_the_metrics(tmp_path) -> None:
    run = build_run(tmp_path)
    document = score_run(run, load_answer_key(answer_key(tmp_path)))
    items = _items(document)
    tp = items["TP-C1"]
    assert tp["outcome"] == "hit" and tp["reported"] and tp["in_accepted_scope"] and tp["disposition"] == "first_party"
    assert tp["facets"] == ["exposure:network", "role:request-handler"]
    assert [(lead["family"], lead["scanner"], lead["admission"]) for lead in tp["leads"]] == [("source_sast", "tool-semgrep", "admitted")]
    assert [(p["package_id"], p["lane"], p["via"]) for p in tp["packages"]] == [("finding_lead-1", "lead", "lead"), ("hunt-1", "hunt", "unit")]
    assert [c["claim_id"] for c in tp["claims"]] == ["claim-1"]
    assert [v["verdict"] for v in tp["judge_verdicts"]] == ["red_correct"]
    assert tp["finding_packages"][0]["bucket"] == "publishable"
    assert [(line["path"], line["start_line"]) for line in tp["citing_lines"]] == [(REQUEST, 137)]  # never the whole file
    fixed = items["FX-C1"]
    assert fixed["match_basis"] == "function" and fixed["span"] == {"start_line": 40, "end_line": 60}
    assert fixed["outcome"] == "hit" and fixed["observed_disposition"] == "in_hunt_unit_only" and fixed["leads"] == []
    fp = items["FP-1"]
    assert fp["outcome"] == "hit" and fp["outcome_reason"] == "refuted by 1 claim(s)" and fp["judge_verdicts"][0]["verdict"] == "blue_correct"
    dep = items["TP-D1"]
    assert dep["match_basis"] == "identifier" and dep["in_accepted_scope"] is None
    assert dep["outcome"] == "hit" and dep["dependency_rows"] == [ID["dep-zlib"]] and dep["leads"][0]["family"] == "dependency_advisory"
    assert items["FX-D1"]["outcome"] == "hit" and items["FX-D1"]["observed_disposition"] == "not_observed"
    metrics = document["keyed"]["metrics"]
    assert metrics["reported_findings"] == 3 and metrics["reported_findings_matching_planted_true_positives"] == 2
    assert metrics["reported_findings_unmatched"] == 1 and metrics["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert metrics["recall"] == 1.0 and metrics["by_class"]["false_positive"]["squelch_rate"] == 1.0
    complexity = document["keyed"]["complexity"]
    assert complexity["observed_cyclomatic"] == 36 and complexity["function_rank"] == 1 and complexity["top_rank"] is True
    assert complexity["share_above_threshold_positive"] is True
    assert document["answer_key"]["planted"] == 5 and document["answer_key"]["language"] == "cpp"


def test_items_match_by_path_and_span_never_by_title(tmp_path) -> None:
    run = build_run(tmp_path)
    document = score_run(run, load_answer_key(answer_key(tmp_path, tp_file="src/other.cpp")))
    moved = _items(document)["TP-C1"]
    assert moved["leads"] == [] and moved["claims"] == [] and moved["outcome"] == "miss"
    assert moved["in_accepted_scope"] is False and moved["observed_disposition"] == "not_observed"


def test_structural_checks_pass_on_the_synthetic_run(tmp_path) -> None:
    document = score_run(build_run(tmp_path))
    checks = _checks(document)
    assert {check_id: check["status"] for check_id, check in checks.items()} == {check_id: "pass" for check_id in smoke_score.CHECK_IDS}
    assert checks["units_cover_first_party_once"]["counts"]["first_party_code_files"] == 2
    assert checks["first_party_files_have_facets"]["counts"] == {"facet_tags": 3, "first_party_code_files": 2, "with_facets": 2, "without_facets": 0}
    assert checks["classified_sink_paths_eligible"]["counts"] == {"classified_eligible": 1, "classified_sink": 1, "paths": 2, "unclassified_sink": 1}
    assert checks["scorecard_lists_first_party_functions_once"]["counts"]["functions"] == 3
    assert checks["jobs_terminal_status_tabulated"]["counts"]["declared_gaps"] == 1
    assert checks["jobs_terminal_status_tabulated"]["counts"]["units_without_terminal_status"] == 0
    assert document["keyed"] is None and document["check_counts"] == {"pass": 6}
    jobs = {job["job_id"]: job for job in document["jobs"]}
    assert jobs["job_security_tagging"]["gaps_by_code"] == {"producer_reported_gap": 1}
    assert jobs["job_security_tagging"]["duration_seconds"] == pytest.approx(95.188, abs=0.01)
    assert jobs["job_security_tagging"]["steps"][0] == {"step_id": "load", "status": "SUCCEEDED", "duration_ms": 400}
    calls = document["model_calls"]
    assert calls["receipts"] == 3 and calls["by_job"][REVIEW] == {"calls": 2, "succeeded": 1, "failed": 1, "elapsed_ms": 2001,
                                                                  "input_tokens": 1200, "output_tokens": 600, "usage_unavailable": 1}
    assert calls["review_budget"]["usage"]["model_turns"] == 2 and calls["review_budget"]["limits"]["max_model_turns"] == 12000


DEFECTS = sorted([
    ("extra_first_party", "units_cover_first_party_once", EXTRA),
    ("unit_overlap", "units_cover_first_party_once", f"{UTIL} x2"),
    ("admit_vendored", "no_lead_outside_first_party", "vendored"),
    ("classified_ineligible", "classified_sink_paths_eligible", "command_execution"),
    ("duplicate_function", "scorecard_lists_first_party_functions_once", "listed 2 times"),
    ("unknown_terminal", "jobs_terminal_status_tabulated", "'WEIRD'"),
])


@pytest.mark.parametrize("defect", DEFECTS, ids=[item[0] for item in DEFECTS])
def test_each_structural_check_fails_on_the_defect_it_guards(tmp_path, defect) -> None:
    option, check_id, offender = defect
    document = score_run(build_run(tmp_path, **{option: True}))
    checks = _checks(document)
    assert checks[check_id]["status"] == "fail", checks[check_id]
    assert any(offender in item for item in checks[check_id]["offenders"]), checks[check_id]["offenders"]
    assert all(check["status"] == "pass" for other, check in checks.items() if other != check_id)


def test_facets_missing_for_one_file_fails_the_facet_check(tmp_path) -> None:
    checks = _checks(score_run(build_run(tmp_path, util_facets=False)))
    assert checks["first_party_files_have_facets"]["status"] == "fail"
    assert checks["first_party_files_have_facets"]["offenders"] == [UTIL]


def test_scorecard_absent_after_the_graph_job_ran_is_a_failure(tmp_path) -> None:
    checks = _checks(score_run(build_run(tmp_path, scorecard=False)))
    assert checks["scorecard_lists_first_party_functions_once"]["status"] == "fail"
    assert "published no graph-quality-scorecard.json" in checks["scorecard_lists_first_party_functions_once"]["summary"]


def test_checks_are_not_applicable_when_their_dataset_was_not_published(tmp_path) -> None:
    document = score_run(build_run(tmp_path, facets=False, graph=False, review=False, graph_job=False),
                         load_answer_key(answer_key(tmp_path)))
    checks = _checks(document)
    assert {check_id: check["status"] for check_id, check in checks.items()} == {
        "units_cover_first_party_once": "not_applicable", "first_party_files_have_facets": "not_applicable",
        "no_lead_outside_first_party": "not_applicable", "classified_sink_paths_eligible": "not_applicable",
        "scorecard_lists_first_party_functions_once": "not_applicable", "jobs_terminal_status_tabulated": "pass"}
    assert document["check_counts"] == {"not_applicable": 5, "pass": 1}
    items = _items(document)
    assert {item["outcome"] for item in items.values()} == {"not_evaluable"}
    assert items["TP-C1"]["leads"][0]["admission"] == "no_review" and items["TP-C1"]["facets_available"] is False
    assert document["keyed"]["publication_available"] == {"review_assembly": False, "claim_projection": False, "finding_packages": False,
                                                          "gate": False, "report": False, "facets": False}
    assert document["keyed"]["metrics"]["precision"] is None and document["keyed"]["metrics"]["recall"] is None


def test_without_a_report_planted_items_are_not_evaluable(tmp_path) -> None:
    document = score_run(build_run(tmp_path, report=False), load_answer_key(answer_key(tmp_path)))
    items = _items(document)
    assert items["TP-C1"]["outcome"] == "not_evaluable"
    assert items["TP-C1"]["observed_disposition"] == "finding_not_reported"
    assert items["TP-C1"]["finding_packages"][0]["bucket"] == "publishable"
    assert document["keyed"]["metrics"]["report_available"] is False


def test_output_is_deterministic_validates_and_touches_only_the_verification_directory(tmp_path) -> None:
    run = build_run(tmp_path)
    key = load_answer_key(answer_key(tmp_path))
    before = sorted(path.relative_to(run).as_posix() for path in run.rglob("*") if path.is_file())
    first = score_run(run, key, key_path=tmp_path / "answer-key.json")
    second = score_run(run, key, key_path=tmp_path / "answer-key.json")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    validate_document(first)
    assert first["schema"] == SCHEMA and first["run_id"] == run.name
    summary = render_summary(first)
    json_path, text_path = write_outputs(run, first, summary)
    assert json_path == run / "data" / "verification" / "smoke-score.json" and text_path.read_text(encoding="utf-8") == summary
    after = sorted(path.relative_to(run).as_posix() for path in run.rglob("*") if path.is_file())
    assert sorted(set(after) - set(before)) == ["data/verification/smoke-score.json", "data/verification/smoke-score.txt"]
    assert json.loads(json_path.read_text(encoding="utf-8")) == first
    assert len(summary.splitlines()) <= 50 and "TP-C1" in summary and "precision=0.6667" in summary
    assert "data/indices/source/src.sqlite" in first["evidence_paths"]
    with pytest.raises(SmokeScoreError, match="violates its schema"):
        validate_document({**first, "unexpected": 1})


def test_main_writes_the_documents_and_refuses_a_file_that_is_not_the_key(tmp_path, capsys) -> None:
    run = build_run(tmp_path)
    assert main(["--run", str(run), "--answer-key", str(answer_key(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"Smoke score ({SCHEMA}) run {run.name}") and "written:" in out
    assert (run / "data" / "verification" / "smoke-score.txt").is_file()
    not_a_key = tmp_path / "other.json"
    not_a_key.write_text("{}", encoding="utf-8")
    assert main(["--run", str(run), "--answer-key", str(not_a_key)]) == 2
    assert "is not appsec-review/smoke-answer-key/1" in capsys.readouterr().err
    assert main(["--run", str(tmp_path / "missing"), "--quiet"]) == 2
