"""Unit tests for Candidate A, Candidate B, and Candidate C executive reports."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any

import pytest

from appsec_review.reporting import (
    CANDIDATE_IDS,
    CANDIDATE_LABELS,
    CANDIDATE_TITLES,
    build_executive_candidate_document,
    normalize_candidate_id,
    render_executive_candidate_html,
    render_executive_candidate_latex,
    render_executive_candidate_markdown,
    render_executive_candidates,
)
from appsec_review.reporting.__main__ import _parser, main as reporting_cli_main
from appsec_review.reporting.executive_candidates import assert_candidate_output_clean
from appsec_review.reporting.model import (
    BarChart,
    Box,
    Code,
    Document,
    FlowDiagram,
    Heading,
    IdList,
    RadarChart,
    Stats,
    Table,
)
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError

ROOT = Path(__file__).resolve().parents[3]
RAW_EXCERPT = "RAW_SOURCE_CODE_EXCERPT_memcpy(dst_buf, attacker_payload, untrusted_len);"

FORBIDDEN_PERSONA_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bCISO\b", re.IGNORECASE),
    re.compile(r"\bBoard\b", re.IGNORECASE),
    re.compile(r"\bVP\b", re.IGNORECASE),
    re.compile(r"VP\s+Engineering", re.IGNORECASE),
    re.compile(r"Audit\s+Sign[- ]Off", re.IGNORECASE),
    re.compile(r"Chief\s+Information\s+Security\s+Officer", re.IGNORECASE),
    re.compile(r"Board\s+of\s+Directors", re.IGNORECASE),
)


def _sample_final_report(*, finding_count: int = 6, with_radar: bool = True) -> dict[str, Any]:
    severities = ("critical", "high", "high", "medium", "medium", "low")
    cwes = ("CWE-787", "CWE-89", "CWE-22", "CWE-79", "CWE-287", "CWE-400")
    files = (
        "src/net/frame_decoder.c",
        "src/net/frame_decoder.c",
        "src/storage/archive_extract.c",
        "src/http/template_view.py",
        "src/auth/token_verifier.py",
        "src/worker/batch_queue.py",
    )
    domains = (
        "memory_safety",
        "injection",
        "input_validation",
        "injection",
        "authentication",
        "availability",
    )
    findings: list[dict[str, Any]] = []
    remediation_items: list[dict[str, Any]] = []
    poc_items: list[dict[str, Any]] = []
    roadmap: list[dict[str, Any]] = []
    for idx in range(finding_count):
        sev = severities[idx % len(severities)]
        cwe = cwes[idx % len(cwes)]
        fpath = files[idx % len(files)]
        dom = domains[idx % len(domains)]
        pkg_id = f"pkg-{sha256_hex(f'pkg-{idx}')}"
        claim_id = f"claim-{sha256_hex(f'claim-{idx}')}"
        ev_ids = [f"ev-{sha256_hex(f'ev-{idx}-{j}')}" for j in range(18)]
        rem_status = "build_checked" if idx % 3 == 0 else ("patch_synthesized" if idx % 3 == 1 else "rejected")
        findings.append(
            {
                "finding_package_id": pkg_id,
                "claim_id": claim_id,
                "state": "confirmed",
                "severity": sev,
                "title": f"Unchecked boundary condition #{idx + 1} in {fpath.split('/')[-1]}",
                "cwe": cwe,
                "security_domain": dom,
                "violated_invariant": f"Untrusted input length reaches sink #{idx + 1} without bounds validation.",
                "primary_location": {
                    "path": fpath,
                    "start_line": 40 + idx * 10,
                    "end_line": 48 + idx * 10,
                },
                "locations": [
                    {
                        "path": fpath,
                        "start_line": 40 + idx * 10,
                        "end_line": 48 + idx * 10,
                    }
                ],
                "evidence_ids": ev_ids,
                "direct_evidence": ev_ids[:10],
                "analyst_assessed_evidence": ev_ids[10:],
                "remediation": {
                    "status": rem_status,
                    "validation_tier": "build_checked" if rem_status == "build_checked" else "static_only",
                },
            }
        )
        remediation_items.append(
            {
                "finding_package_id": pkg_id,
                "claim_id": claim_id,
                "status": rem_status,
                "disposition": rem_status,
            }
        )
        roadmap.append(
            {
                "priority_rank": idx + 1,
                "finding_package_id": pkg_id,
                "claim_id": claim_id,
                "severity": sev,
                "remediation_tier": rem_status,
                "disposition": "immediate_patch" if sev in ("critical", "high") else "scheduled_patch",
            }
        )
        if idx < 2:
            poc_items.append(
                {
                    "finding_package_id": pkg_id,
                    "claim_id": claim_id,
                    "status": "generated",
                    "execution_policy": "not_executed",
                }
            )

    backlog = [
        {
            "finding_package_id": f"pkg-{sha256_hex('backlog-0')}",
            "claim_id": f"claim-{sha256_hex('backlog-0')}",
            "state": "supported",
            "severity": "medium",
            "title": "Unconfirmed header canonicalization path under proxy forwarding",
            "cwe": "CWE-444",
            "security_domain": "input_validation",
            "primary_location": {"path": "src/http/proxy_headers.py", "start_line": 88, "end_line": 96},
            "qualification_reason": "Requires live upstream proxy header normalization check",
        }
    ]
    gap_ids = [f"gap-{sha256_hex(f'gap-{i}')}" for i in range(45)]
    named_gaps = [
        {
            "gap_id": gap_ids[i],
            "category": "codeql_extraction" if i < 25 else ("dynamic_harness" if i < 38 else "sca_reachability"),
            "affected_scope": "job_codeql_analysis" if i < 25 else ("job_poc_generation" if i < 38 else "job_sca_reachability"),
            "statement": "Scoped coverage limitation recorded by producer.",
        }
        for i in range(len(gap_ids))
    ]
    report: dict[str, Any] = {
        "schema": "appsec-review/final-report/4",
        "run_id": "run-candidate-unit-001",
        "target_snapshot": sha256_hex("snapshot-001"),
        "status": {
            "publication": "PUBLISHABLE_WITH_GAPS",
            "review_status": "DEGRADED",
            "review_complete": False,
        },
        "provenance": {
            "ledger_head_sha256": sha256_hex("ledger-head"),
            "configuration_profile": {"name": "smoke", "sha256": sha256_hex("profile")},
        },
        "summary": {
            "package_counts": {
                "total": finding_count + len(backlog) + 2,
                "publishable": finding_count,
                "verification_backlog": len(backlog),
                "withheld": 2,
                "refuted": 1,
            }
        },
        "executive_posture": {
            "release_readiness": "HOLD_PENDING_CRITICAL_FIXES",
            "chain_elevated_findings_count": 1,
            "reachable_supply_chain_advisories_count": 0,
            "reachable_supply_chain_gap_reasons": [],
        },
        "findings": findings,
        "verification_backlog": backlog,
        "withheld": [
            {"finding_package_id": f"pkg-{sha256_hex('withheld-0')}", "reason": "insufficient_direct_evidence"},
            {"finding_package_id": f"pkg-{sha256_hex('withheld-1')}", "reason": "refuted_by_verifier"},
        ],
        "remediation": {"status": "available", "items": remediation_items},
        "remediation_roadmap": roadmap,
        "poc": {"status": "available", "items": poc_items},
        "dossiers": {"status": "none_available", "items": []},
        "attack_chains": {"status": "none_available", "items": []},
        "limitations": [
            {
                "limitation_id": "codeql_partial_coverage",
                "kind": "gap",
                "count": 25,
                "statement": "CodeQL C++ database skipped optional vendor targets.",
            },
            {
                "limitation_id": "poc_execution_disabled",
                "kind": "policy",
                "count": 2,
                "statement": "Generated PoCs were retained as static harnesses without target execution.",
            },
        ],
        "gap_ids": gap_ids,
        "named_coverage_gaps": named_gaps,
    }
    if with_radar:
        report["radar_tracker"] = {
            "schema": "appsec-review/security-radar-tracker/2",
            "axes": [
                {"axis_id": "memory_safety", "label": "Memory Safety", "posture_score": 38, "verified_coverage": 82, "confirmed_findings": 2},
                {"axis_id": "injection", "label": "Injection", "posture_score": 52, "verified_coverage": 88, "confirmed_findings": 2},
                {"axis_id": "authentication", "label": "Authentication", "posture_score": 74, "verified_coverage": 90, "confirmed_findings": 1},
                {"axis_id": "input_validation", "label": "Input Validation", "posture_score": 61, "verified_coverage": 79, "confirmed_findings": 1},
                {"axis_id": "availability", "label": "Availability", "posture_score": 78, "verified_coverage": 85, "confirmed_findings": 1},
            ],
            "coverage_confidence": {"verified_axes": 5, "gap_axes": 1, "confidence_score": 0.84, "gap_reasons": []},
        }
    return report


def _sample_dossiers(report: dict[str, Any]) -> list[dict[str, Any]]:
    top = report["findings"][0]
    second = report["findings"][1]
    return [
        {
            "dossier_id": f"dossier-{sha256_hex('d0')[:12]}",
            "finding": {
                "finding_package_id": top["finding_package_id"],
                "claim_id": top["claim_id"],
                "severity": top["severity"],
            },
            "claim": {
                "claim_id": top["claim_id"],
                "weakness_cwe": top["cwe"],
                "statement": top["violated_invariant"],
            },
            "excerpts": [
                {
                    "location": {"path": "src/net/frame_decoder.c"},
                    "excerpt_start_line": 40,
                    "excerpt_end_line": 48,
                    "excerpt": RAW_EXCERPT,
                }
            ],
            "taint_path_timeline": [
                {
                    "step": 1,
                    "stage": "source",
                    "location": {"path": "src/net/socket_reader.c", "start_line": 19},
                    "symbol": "read_network_frame",
                    "assessment": "Reads attacker-controlled 32-bit frame length header",
                    "excerpt": RAW_EXCERPT,
                },
                {
                    "step": 2,
                    "stage": "propagation",
                    "location": {"path": "src/net/frame_decoder.c", "start_line": 34},
                    "symbol": "parse_payload_slice",
                    "assessment": "Forwards unchecked length into fixed stack buffer copy",
                    "excerpt": RAW_EXCERPT,
                },
                {
                    "step": 3,
                    "stage": "sink",
                    "location": {"path": "src/net/frame_decoder.c", "start_line": 44},
                    "symbol": "copy_frame_bytes",
                    "assessment": "Writes past 256-byte stack frame buffer",
                    "excerpt": RAW_EXCERPT,
                },
            ],
        },
        {
            "dossier_id": f"dossier-{sha256_hex('d1')[:12]}",
            "finding": {
                "finding_package_id": second["finding_package_id"],
                "claim_id": second["claim_id"],
                "severity": second["severity"],
            },
            "excerpts": [{"excerpt": RAW_EXCERPT}],
            "taint_path_timeline": [],
        },
    ]


def test_executive_candidates_strict_neutral_naming_and_zero_persona_labels() -> None:
    assert CANDIDATE_IDS == ("a", "b", "c")
    assert CANDIDATE_LABELS == {"a": "Candidate A", "b": "Candidate B", "c": "Candidate C"}
    assert CANDIDATE_TITLES == {
        "a": "Executive Security Review \u2014 Candidate A",
        "b": "Executive Security Review \u2014 Candidate B",
        "c": "Executive Security Review \u2014 Candidate C",
    }
    assert normalize_candidate_id("A") == "a"
    assert normalize_candidate_id("Candidate B") == "b"
    assert normalize_candidate_id("candidate-c") == "c"
    with pytest.raises(ValueError, match="unsupported executive candidate"):
        normalize_candidate_id("d")

    report = _sample_final_report()
    dossiers = _sample_dossiers(report)
    rendered = render_executive_candidates(report, dossiers=dossiers)
    assert tuple(rendered) == ("a", "b", "c")

    help_text = _parser().format_help()
    render_sub = next(
        action.choices["render"].format_help()
        for action in _parser()._actions
        if getattr(action, "choices", None) and "render" in action.choices
    )
    module_source = (ROOT / "src" / "appsec_review" / "reporting" / "executive_candidates.py").read_text("utf-8")

    for cid in CANDIDATE_IDS:
        bundle = rendered[cid]
        assert bundle.document.title == CANDIDATE_TITLES[cid]
        assert CANDIDATE_TITLES[cid] in bundle.markdown
        assert CANDIDATE_LABELS[cid] in bundle.html
        for fmt_name, text in (("md", bundle.markdown), ("html", bundle.html), ("tex", bundle.latex)):
            for pattern in FORBIDDEN_PERSONA_PATTERNS:
                assert not pattern.search(text), f"forbidden persona label {pattern.pattern!r} leaked in candidate {cid} {fmt_name}"

    for surface_name, surface_text in (("cli-help", help_text + "\n" + render_sub), ("module-source", module_source)):
        for pattern in FORBIDDEN_PERSONA_PATTERNS:
            assert not pattern.search(surface_text), f"forbidden persona label {pattern.pattern!r} found in {surface_name}"


def test_executive_candidates_distinct_visual_layouts_both_with_and_without_dossiers() -> None:
    report = _sample_final_report(finding_count=14, with_radar=True)
    dossiers = _sample_dossiers(report)

    standalone = render_executive_candidates(report)
    enriched = render_executive_candidates(report, dossiers=dossiers)
    again = render_executive_candidates(deepcopy(report), dossiers=deepcopy(dossiers))

    for cid in CANDIDATE_IDS:
        assert enriched[cid].markdown == again[cid].markdown
        assert enriched[cid].html == again[cid].html
        assert enriched[cid].latex == again[cid].latex
        # Concise ~4-9 page budget even on 14 findings + 45 coverage gaps:
        assert len(enriched[cid].markdown.splitlines()) < 320

    assert len({standalone[cid].markdown for cid in CANDIDATE_IDS}) == 3
    assert len({standalone[cid].html for cid in CANDIDATE_IDS}) == 3
    assert len({standalone[cid].latex for cid in CANDIDATE_IDS}) == 3

    def _sections(doc: Document) -> list[list[object]]:
        grouped: list[list[object]] = []
        for block in doc.blocks:
            if isinstance(block, Heading) and block.level == 1:
                grouped.append([])
            elif grouped:
                grouped[-1].append(block)
        return grouped

    def _tables(blocks: list[object]) -> list[Table]:
        out: list[Table] = []
        for block in blocks:
            if isinstance(block, Table):
                out.append(block)
            elif isinstance(block, Box):
                out.extend(item for item in block.items if isinstance(item, Table))
        return out

    for cid in CANDIDATE_IDS:
        doc = enriched[cid].document
        assert isinstance(doc, Document)
        for block in doc.blocks:
            assert not isinstance(block, (Code, IdList))
            if isinstance(block, Box):
                for item in block.items:
                    assert not isinstance(item, (Code, IdList))

    # Candidate A: Compact Posture & Priority Action Brief
    secs_a = _sections(enriched["a"].document)
    assert len(secs_a) == 5
    assert any(isinstance(b, Box) for b in secs_a[0])
    grid_a = next(b for b in secs_a[0] if isinstance(b, Stats))
    assert len(grid_a.items) == 6
    assert any(isinstance(b, BarChart) for b in secs_a[1])
    assert any(isinstance(b, RadarChart) for b in secs_a[1])
    assert len(_tables(secs_a[2])) == 1
    flows_a = [b for b in secs_a[3] if isinstance(b, FlowDiagram)]
    assert len(flows_a) == 1 and len(flows_a[0].nodes) >= 3
    assert len(_tables(secs_a[4])) == 1
    # Standalone Candidate A without dossiers still synthesizes a crisp 4-node FlowDiagram:
    standalone_flows_a = [b for b in _sections(standalone["a"].document)[3] if isinstance(b, FlowDiagram)]
    assert len(standalone_flows_a) == 1 and len(standalone_flows_a[0].nodes) == 4
    # Candidate A without radar axes falls back to domain BarChart:
    no_radar_a = build_executive_candidate_document("a", _sample_final_report(finding_count=2, with_radar=False))
    charts_no_radar = [b for b in _sections(no_radar_a)[1] if isinstance(b, BarChart)]
    assert len(charts_no_radar) == 2

    # Candidate B: Visual Triage & Remediation Matrix
    secs_b = _sections(enriched["b"].document)
    assert len(secs_b) == 5
    assert any(isinstance(b, Box) for b in secs_b[0])
    grid_b = next(b for b in secs_b[0] if isinstance(b, Stats))
    assert len(grid_b.items) == 6
    assert len([b for b in secs_b[1] if isinstance(b, BarChart)]) == 2
    assert len(_tables(secs_b[2])) == 2
    flows_b = [b for b in secs_b[3] if isinstance(b, FlowDiagram)]
    assert len(flows_b) == 3
    assert len(_tables(secs_b[4])) == 1

    # Candidate C: Assurance Funnel & Coverage Summary
    secs_c = _sections(enriched["c"].document)
    assert len(secs_c) == 5
    assert any(isinstance(b, Box) for b in secs_c[0])
    grid_c = next(b for b in secs_c[0] if isinstance(b, Stats))
    assert len(grid_c.items) == 6
    assert len([b for b in secs_c[1] if isinstance(b, BarChart)]) == 2
    assert len(_tables(secs_c[2])) == 2
    flows_c = [b for b in secs_c[3] if isinstance(b, FlowDiagram)]
    assert len(flows_c) == 1
    assert any(isinstance(b, BarChart) for b in secs_c[4])
    assert len(_tables(secs_c[4])) == 1


def test_executive_candidates_never_emit_source_excerpts_evidence_piles_or_redaction_markers() -> None:
    report = _sample_final_report(finding_count=12)
    report["findings"][0]["title"] = "Buffer overflow <redacted:24 chars> in frame_decoder\x00"
    report["findings"][0]["violated_invariant"] = (
        "Header token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U "
        "and <redacted:12 chars> reach sink."
    )
    dossiers = _sample_dossiers(report)

    sample_ev_id = report["findings"][0]["evidence_ids"][0]
    sample_gap_id = report["gap_ids"][0]

    rendered = render_executive_candidates(report, dossiers=dossiers)
    for cid, bundle in rendered.items():
        for fmt_name, text in (("md", bundle.markdown), ("html", bundle.html), ("tex", bundle.latex)):
            assert RAW_EXCERPT not in text, f"raw source excerpt leaked in candidate {cid} {fmt_name}"
            assert "RAW_SOURCE_CODE_EXCERPT" not in text
            assert "memcpy(dst_buf" not in text
            assert sample_ev_id not in text, f"raw evidence ID dump leaked in candidate {cid} {fmt_name}"
            assert sample_gap_id not in text, f"raw gap hash dump leaked in candidate {cid} {fmt_name}"
            assert "<redacted:" not in text.lower()
            assert "\x00" not in text
            assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in text

    with pytest.raises(IntegrityError, match="redaction marker"):
        assert_candidate_output_clean("leaked <redacted:14 chars> marker", label="unit-test")


def test_reporting_cli_candidate_flag_writes_requested_candidates_and_preserves_legacy_validation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    report = _sample_final_report(finding_count=4)
    input_dir = tmp_path / "standalone-report"
    input_dir.mkdir()
    (input_dir / "final-report.json").write_text(json.dumps(report), encoding="utf-8")

    out_none = tmp_path / "out-none"
    rc_missing_fmt = reporting_cli_main(["render", "--run", str(input_dir), "--out", str(out_none)])
    assert rc_missing_fmt == 2
    assert "--format is required when --candidate is none" in capsys.readouterr().err

    out_single = tmp_path / "out-b"
    rc_single = reporting_cli_main(
        ["render", "--run", str(input_dir), "--output-dir", str(out_single), "--candidate", "b"]
    )
    assert rc_single == 0
    payload_single = json.loads(capsys.readouterr().out.strip())
    assert payload_single["files"] == [
        "executive-report-candidate-b.md",
        "executive-report-candidate-b.html",
        "executive-report-candidate-b.tex",
    ]
    assert sorted(p.name for p in out_single.iterdir()) == sorted(payload_single["files"])

    out_all = tmp_path / "out-all"
    rc_all = reporting_cli_main(
        ["render", "--run", str(input_dir), "--out", str(out_all), "--candidate", "all"]
    )
    assert rc_all == 0
    payload_all = json.loads(capsys.readouterr().out.strip())
    expected_all = [
        f"executive-report-candidate-{cid}.{ext}"
        for cid in ("a", "b", "c")
        for ext in ("md", "html", "tex")
    ]
    assert payload_all["files"] == expected_all
    for fname in expected_all:
        assert (out_all / fname).is_file() and (out_all / fname).stat().st_size > 100
