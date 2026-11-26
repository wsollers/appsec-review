"""Unit tests for the read-only live run dossier HTML report and stdlib HTTP server."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from appsec_review.jobs.completion_contracts import DOSSIER_PUBLICATION_SCHEMA, DOSSIER_SCHEMA
from appsec_review.observability.events import PipelineLog
from appsec_review.observability.monitor_inputs import freeze_run_graph
from appsec_review.reporting.live_report import (
    collect_live_report_data,
    create_live_report_server,
    main,
    render_live_report_html,
)
from appsec_review.runtime.release import digest
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.reporting.fixture import RUN_ID as FIXTURE_RUN_ID, build_fixture

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "live-run-report.py"
NOW = datetime(2026, 11, 26, 7, 0, tzinfo=timezone.utc)
DAGSTER_UUID = "46fdbbd2-e405-4791-9e09-52214b39bf31"
HOSTILE = '<script>alert("xss")</script><img src=x onerror=alert(1)> & " \' ` \\write18{id}'


def _dir_snapshot(root: Path) -> dict[str, tuple[int, str]]:
    snap: dict[str, tuple[int, str]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            snap[rel] = (path.stat().st_size, file_sha256(path))
    return snap


def _emit(run_dir: Path, kind: str, offset_s: int, *, job: str = "-", attempt: str = "-", **details: object) -> None:
    details.setdefault("dagster_run_id", DAGSTER_UUID)
    log = PipelineLog(run_dir)
    log.write(
        kind,
        run_id=run_dir.name,
        job_id=job,
        attempt_id=attempt,
        orchestrator="dagster",
        details=details,
    )
    records, _ = log.read()
    records[-1]["timestamp"] = (NOW - timedelta(seconds=300) + timedelta(seconds=offset_s)).isoformat()
    log.path.write_bytes(b"".join(canonical_json(r) for r in records))


def _build_monitored_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    jobs = ("job_review_intake", "job_target_catalog", "job_inference_security_review", "job_final_report_publication")
    config = {"jobs": {j: {"settings": {"enabled": True, "model": "gpt-6.2-astra", "provider": "copilot-sdk"}} for j in jobs}}
    cfg_bytes = canonical_json(config)
    cfg_sha = hashlib.sha256(cfg_bytes).hexdigest()
    cfg_dir = run_dir / "data" / "configuration"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "resolved.json").write_bytes(cfg_bytes)
    atomic_json(cfg_dir / "manifest.json", {
        "schema": "appsec-review/run-configuration/2",
        "resolved_sha256": cfg_sha,
        "selection": {"profile": "copilot-dev-astra-6.2"},
    })
    release = {
        "schema": "appsec-review/implementation-release/1",
        "dependency_manifest": "a" * 64,
        "files": {},
        "jobs": {j: {"implementation": "b" * 64, "validation": "c" * 64} for j in jobs},
        "scripts_sha256": "d" * 64,
        "environment_requirements": [],
    }
    release["sha256"] = digest(release)
    rel_bytes = canonical_json(release)
    (cfg_dir / "release.json").write_bytes(rel_bytes)
    atomic_json(run_dir / "data" / "recovery" / "current.json", {
        "schema": "appsec-review/implementation-binding/1",
        "release_sha256": release["sha256"],
        "release": {"path": "data/configuration/release.json", "sha256": hashlib.sha256(rel_bytes).hexdigest()},
    })
    deps = {
        "job_review_intake": [],
        "job_target_catalog": ["job_review_intake"],
        "job_inference_security_review": ["job_target_catalog"],
        "job_final_report_publication": ["job_inference_security_review"],
    }
    _emit(run_dir, "RUN_STARTED", 0)
    graph_ref = freeze_run_graph(
        run_dir,
        deps,
        config_sha256=cfg_sha,
        dagster_run_id=DAGSTER_UUID,
        profile="copilot-dev-astra-6.2",
        source_sha256=release["sha256"],
    )
    _emit(run_dir, "GRAPH_STARTED", 1, graph_reference=graph_ref)
    _emit(run_dir, "JOB_STARTED", 2, job="job_review_intake", attempt="attempt_0001")
    _emit(run_dir, "JOB_SUCCEEDED", 12, job="job_review_intake", attempt="attempt_0001")
    _emit(run_dir, "JOB_STARTED", 15, job="job_target_catalog", attempt="attempt_0001")
    _emit(run_dir, "JOB_COMPLETED_WITH_GAPS", 35, job="job_target_catalog", attempt="attempt_0001")
    _emit(run_dir, "JOB_STARTED", 40, job="job_inference_security_review", attempt="attempt_0001")
    _emit(
        run_dir,
        "TASK_STARTED",
        45,
        job="job_inference_security_review",
        attempt="attempt_0001",
        unit_id="lead_review.teams",
    )
    for idx, latency in enumerate((1200, 4800), start=1):
        call_info = {
            "model_invocation_id": f"inv-{idx}",
            "provider": "copilot-sdk",
            "model": "gpt-6.2-astra",
            "role": "red_team_analyst",
            "retry_count": idx - 1,
            "execution_mode": "inference",
        }
        _emit(run_dir, "MODEL_CALL_STARTED", 50 + idx * 5, job="job_inference_security_review", attempt="attempt_0001", **call_info)
        _emit(
            run_dir,
            "MODEL_CALL_COMPLETED",
            52 + idx * 5,
            job="job_inference_security_review",
            attempt="attempt_0001",
            terminal_status="SUCCEEDED",
            call_latency_ms=latency,
            queue_delay_ms=15,
            duration_ms=latency + 15,
            input_tokens=2500,
            output_tokens=600,
            cache_tokens=100,
            reasoning_tokens=None,
            **call_info,
        )


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _write_accepted_handoff(run_dir: Path, job_id: str, outputs: dict[str, object], status: str = "SUCCEEDED") -> None:
    from appsec_review.interchange import HANDOFF_SCHEMA, OUTCOMES_SCHEMA, handoff_input_projection, input_set_sha256

    attempt_dir = run_dir / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    outcomes_path = attempt_dir / "outcomes.json"
    atomic_json(outcomes_path, {"schema": OUTCOMES_SCHEMA, "units": []})
    outcomes_ref = {
        "path": outcomes_path.relative_to(run_dir).as_posix(),
        "sha256": file_sha256(outcomes_path),
        "size_bytes": outcomes_path.stat().st_size,
    }
    handoff_doc: dict[str, object] = {
        "schema": HANDOFF_SCHEMA,
        "run_id": run_dir.name,
        "job_id": job_id,
        "attempt_id": "attempt_0001",
        "status": "ACCEPTED",
        "completion_status": status,
        "execution_status": "SUCCEEDED",
        "started_at": (NOW - timedelta(seconds=240)).isoformat(),
        "completed_at": (NOW - timedelta(seconds=180)).isoformat(),
        "outputs": outputs,
        "artifacts": [outcomes_ref],
        "upstream_handoff_sha256": {},
        "resolved_config_sha256": _sha(f"cfg-{job_id}"),
        "job_config_sha256": _sha(f"jcfg-{job_id}"),
        "source_fingerprint": _sha("src-fp"),
        "target_snapshot": _sha("target-snap"),
        "implementation_identity": _sha("impl-id"),
        "schema_identity": _sha("schema-id"),
        "validation_identity": _sha("val-id"),
        "tool_identity": {},
        "input_identity": {},
        "input_manifest": None,
        "dataset_contract_sha256": _sha(f"ds-{job_id}"),
        "coverage": {"disposition": "complete", "gap_count": 0, "retry_required": False},
        "outcomes": outcomes_ref,
        "resolving_paths": {},
    }
    handoff_doc["input_set_sha256"] = input_set_sha256(handoff_input_projection(handoff_doc))
    handoff_path = attempt_dir / "handoff.json"
    atomic_json(handoff_path, handoff_doc)
    atomic_json(run_dir / "data" / "jobs" / job_id / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": handoff_path.relative_to(run_dir).as_posix(),
        "handoff_sha256": file_sha256(handoff_path),
    })


def _make_finding_row(
    fid: str,
    title: str,
    *,
    severity: str,
    state: str = "confirmed",
    ship_status: str = "ship_blocking",
    confidence: str = "high",
) -> dict[str, object]:
    return {
        "finding_package_id": fid,
        "claim_id": f"claim-{fid}",
        "title": title,
        "state": state,
        "label": state,
        "lane": "lead",
        "ship_block": {
            "status": ship_status,
            "technical_severity": severity,
            "reasons": [],
            "missing_factors": [],
        },
        "independence": {"independent": state == "confirmed"},
        "direct_evidence": [f"ev-{fid}-1"],
        "analyst_assessed_evidence": [],
        "missing_predicates": [] if state == "confirmed" else ["attacker_input_control"],
        "scores": [{
            "technical_severity": {"scale": "qualitative", "rating": severity, "value": None},
            "exploitability_confidence": {"scale": "qualitative", "rating": confidence, "value": None},
        }],
        "poc": {"status": "compiled", "result_id": f"poc-{fid}"},
        "attack_chains": [],
    }


def test_non_empty_findings_top_n_ranking_stats_nested_dossier_and_escaping(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "2026-11-26-0001"
    _build_monitored_run(run_dir)

    report_path = (
        run_dir / "data" / "jobs" / "job_final_report_publication" / "attempts" / "attempt_0001"
        / "steps" / "publish" / "tasks" / "publish_report" / "final-report.json"
    )
    atomic_json(report_path, {
        "schema": "appsec-review/final-report/4",
        "run_id": run_dir.name,
        "status": {"review": "COMPLETE", "publication": "COMPLETE", "review_complete": True},
        "findings": [
            _make_finding_row("fp-med", "Medium buffer check issue", severity="medium", ship_status="non_blocking"),
            _make_finding_row("fp-crit", f"Critical RCE in parser {HOSTILE}", severity="critical", ship_status="ship_blocking"),
            _make_finding_row("fp-high", "High SQL injection in query builder", severity="high", ship_status="ship_blocking"),
        ],
        "verification_backlog": [
            _make_finding_row("fp-low-sup", "Supported low integer cast", severity="low", state="supported", ship_status="non_blocking"),
        ],
        "withheld": [],
    })

    before = _dir_snapshot(run_dir)
    data = collect_live_report_data(run_dir, top_n=2, now=NOW)
    html = render_live_report_html(data, refresh_seconds=300)
    after = _dir_snapshot(run_dir)

    assert before == after, "live report collection and rendering must never mutate run_dir"
    assert data.total_findings == 4
    assert data.confirmed_findings == 3 and data.supported_findings == 1
    assert [f.finding_package_id for f in data.findings] == ["fp-crit", "fp-high"]

    assert '<meta http-equiv="refresh" content="300">' in html
    assert 'data-empty-findings="true"' not in html
    assert 'data-stat="# findings"' in html
    assert '<div class="v">4</div>' in html
    assert "3 confirmed ? 1 supported" in html
    assert "Showing top 2 of 4 (top-n=2)" in html
    assert "2 omitted" in html

    # Performance metrics & nested dossier disclosure
    assert "5m 00s" in html
    assert "lead_review.teams" in html
    assert "6.2k" in html  # (2500 + 600) * 2 = 6200 tokens
    assert "1.2 s / 4.8 s" in html
    assert html.count('<details class="box finding-dossier"') == 2
    assert '<details class="inner"' in html
    assert "High SQL injection in query builder" in html
    assert "Medium buffer check issue" not in html
    assert "Supported low integer cast" not in html

    # Strict HTML escaping of hostile target/model text
    assert "<script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html


def test_zero_findings_renders_slanted_diagonal_na_watermark(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "2026-11-26-0002"
    _build_monitored_run(run_dir)

    before = _dir_snapshot(run_dir)
    data = collect_live_report_data(run_dir, top_n=5, now=NOW)
    html = render_live_report_html(data, refresh_seconds=300)
    after = _dir_snapshot(run_dir)

    assert before == after
    assert data.total_findings == 0
    assert data.findings == ()
    assert '<meta http-equiv="refresh" content="300">' in html
    assert 'data-empty-findings="true"' in html
    assert 'class="na-watermark-svg"' in html
    assert "rotate(-22)" in html
    assert ">N/A</text>" in html
    assert "NO FINDINGS RECORDED" in html
    assert "never evidence that the target is clean" in html


def test_published_dossier_and_midflight_ledger_sources(tmp_path: Path) -> None:
    # 1a. Reporting fixture with final-report.json + ledger enrichment
    full_fixture = build_fixture(tmp_path / "fixture_runs")
    fixture_before = _dir_snapshot(full_fixture)
    fx_data = collect_live_report_data(full_fixture, top_n=5, now=NOW)
    fx_html = render_live_report_html(fx_data, refresh_seconds=300)
    assert _dir_snapshot(full_fixture) == fixture_before
    assert fx_data.findings_source == "final_report"
    assert fx_data.total_findings == 1
    assert fx_data.findings[0].cwe == "CWE-190"
    assert "<script>" not in fx_html

    # 1b. Mid-flight ledger fallback when final_report_publication has not run yet
    ledger_run = build_fixture(tmp_path / "ledger_runs")
    for p in sorted((ledger_run / "data" / "jobs" / "job_final_report_publication").rglob("*"), reverse=True):
        if p.is_file():
            p.unlink()
        elif p.is_dir():
            p.rmdir()
    (ledger_run / "data" / "jobs" / "job_final_report_publication").rmdir()
    ledger_before = _dir_snapshot(ledger_run)
    ledger_data = collect_live_report_data(ledger_run, top_n=5, now=NOW)
    ledger_html = render_live_report_html(ledger_data, refresh_seconds=300)
    assert _dir_snapshot(ledger_run) == ledger_before
    assert ledger_data.findings_source == "in_progress_ledger"
    assert ledger_data.total_findings == 1
    assert ledger_data.findings[0].cwe == "CWE-190"
    assert "<script>" not in ledger_html

    # 2. Accepted dossier_publication source with source excerpt & remediation
    dossier_run = tmp_path / "dossier_runs" / "2026-11-26-0003"
    _build_monitored_run(dossier_run)
    dossier_path = (
        dossier_run / "data" / "jobs" / "job_dossier_publication" / "attempts" / "attempt_0001"
        / "steps" / "dossiers" / "tasks" / "create" / "item_0001" / "dossier.json"
    )
    atomic_json(dossier_path, {
        "schema": DOSSIER_SCHEMA,
        "dossier_id": "dossier-0001",
        "kind": "finding",
        "visibility": "protected",
        "run_id": dossier_run.name,
        "finding_package_id": "fp-0001",
        "claim_id": "claim-0001",
        "title": "Heap overflow in packet frame decoder",
        "state": "confirmed",
        "weakness_cwe": "CWE-122",
        "security_predicate": "memory_corruption",
        "statement": "Unbounded memcpy length from packet header into heap buffer.",
        "classification": {"cwe": "CWE-122", "owasp": ["A03:2021"]},
        "ship_block": {"status": "ship_blocking", "technical_severity": "critical"},
        "independence": {"independent": True},
        "preconditions": ["network_packet_input"],
        "evidence": [{
            "relation_id": "rel-1",
            "predicate": "affected_construct",
            "kind": "supports",
            "admissibility": "direct",
            "locator": "src/decoder.cpp:142",
            "entity_id": "asr:ast_node:1",
        }],
        "sources": [{
            "entity_id": "asr:ast_node:1",
            "location": {"path": "src/decoder.cpp", "start_line": 140, "end_line": 145},
            "excerpt": "memcpy(buf, pkt->payload, pkt->len);",
        }],
        "remediation": [{
            "stage": "Planning",
            "status": "succeeded",
            "corrected_invariant": "Validate pkt->len <= buf_cap before memcpy.",
        }],
        "gaps": [],
    })
    manifest_path = dossier_path.parent.parent / "dossiers.json"
    atomic_json(manifest_path, {
        "schema": DOSSIER_PUBLICATION_SCHEMA,
        "run_id": dossier_run.name,
        "items": [{
            "dossier_id": "dossier-0001",
            "files": {"json": {"path": dossier_path.relative_to(dossier_run).as_posix(), "sha256": file_sha256(dossier_path)}},
        }],
    })
    _write_accepted_handoff(
        dossier_run,
        "job_dossier_publication",
        {"acceptance.publish_handoff": {"artifact": {"path": manifest_path.relative_to(dossier_run).as_posix(), "sha256": file_sha256(manifest_path)}}},
    )

    dos_data = collect_live_report_data(dossier_run, top_n=5, now=NOW)
    dos_html = render_live_report_html(dos_data, refresh_seconds=300)
    assert dos_data.findings_source == "dossier_publication"
    assert dos_data.total_findings == 1
    assert "Heap overflow in packet frame decoder" in dos_html
    assert "src/decoder.cpp:140-145" in dos_html
    assert "memcpy(buf, pkt-&gt;payload, pkt-&gt;len);" in dos_html
    assert "Validate pkt-&gt;len &lt;= buf_cap before memcpy." in dos_html


def test_http_server_serves_html_and_healthz_without_mutating_run(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "2026-11-26-0004"
    _build_monitored_run(run_dir)
    before = _dir_snapshot(run_dir)

    server = create_live_report_server(run_dir, host="127.0.0.1", port=0, top_n=3, refresh_seconds=300, quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    base_url = f"http://{host}:{port}"
    try:
        with urlopen(f"{base_url}/", timeout=5) as resp:
            assert resp.status == 200
            assert "text/html" in resp.headers.get("Content-Type", "")
            assert "no-store" in resp.headers.get("Cache-Control", "")
            body = resp.read().decode("utf-8")
            assert '<meta http-equiv="refresh" content="300">' in body
            assert 'data-empty-findings="true"' in body

        with urlopen(f"{base_url}/runs/{run_dir.name}?top_n=1&refresh=60", timeout=5) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert '<meta http-equiv="refresh" content="60">' in body
            assert "Top 1 findings" in body

        head_req = Request(f"{base_url}/", method="HEAD")
        with urlopen(head_req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.read() == b""

        with urlopen(f"{base_url}/healthz", timeout=5) as resp:
            assert resp.status == 200
            health = json.loads(resp.read().decode("utf-8"))
            assert health["ok"] is True
            assert health["run_id"] == run_dir.name
            assert health["findings_count"] == 0
            assert health["refresh_seconds"] == 300

        with pytest.raises(HTTPError) as bad_query:
            urlopen(f"{base_url}/?top_n=0", timeout=5)
        assert bad_query.value.code == 400
        bad_query.value.close()

        with pytest.raises(HTTPError) as missing:
            urlopen(f"{base_url}/no-such-route", timeout=5)
        assert missing.value.code == 404
        missing.value.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert _dir_snapshot(run_dir) == before


def test_cli_export_and_argument_validation(tmp_path: Path) -> None:
    runs_root = tmp_path / "runs"
    run_dir = runs_root / "2026-11-26-0005"
    _build_monitored_run(run_dir)
    out_html = tmp_path / "exported" / "live.html"

    rc = main([
        "--runs-root", str(runs_root),
        "--run-id", "2026-11-26-0005",
        "--top-n", "5",
        "--refresh-seconds", "300",
        "--export-html", str(out_html),
    ])
    assert rc == 0
    rendered = out_html.read_text(encoding="utf-8")
    assert rendered.startswith("<!doctype html>")
    assert "2026-11-26-0005" in rendered

    # Refuses writing inside the run directory
    assert main(["--run", str(run_dir), "--export-html", str(run_dir / "inside.html")]) == 2
    assert not (run_dir / "inside.html").exists()

    # Invalid parameters exit 2
    assert main(["--run", str(run_dir), "--top-n", "0"]) == 2
    assert main(["--run", str(run_dir), "--refresh-seconds", "-5"]) == 2
    assert main(["--runs-root", str(runs_root), "--run-id", "missing-run"]) == 2

    # Standalone script --help works
    helped = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, timeout=30)
    assert helped.returncode == 0
    assert "--refresh-seconds" in helped.stdout and "--top-n" in helped.stdout
