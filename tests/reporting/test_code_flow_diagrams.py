"""Focused unit tests for FlowDiagram model, HTML/LaTeX/Markdown renderers, and code_flow."""

from __future__ import annotations

import json
import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from appsec_review.reporting.code_flow import (
    build_dossier_flow_diagram,
    export_exe_viewer_flow,
    to_dot,
    to_mermaid,
    to_standalone_svg,
)
from appsec_review.reporting.dossier_render import render_dossier_html, render_dossier_markdown
from appsec_review.reporting.dossiers import DOSSIER_SCHEMA, dossier_document
from appsec_review.reporting.html import render_flow_svg, render_html
from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.model import Document, FlowDiagram, FlowEdge, FlowNode, Heading


def _sample_diagram(*, node_count: int = 4, orientation: str = "LR") -> FlowDiagram:
    roles = ("entry", "hop", "guard", "sink", "callee", "hop")
    nodes = tuple(
        FlowNode(
            node_id=f"n{i + 1}",
            label=f"step_{i + 1} <unsafe & raw>",
            role="sink" if i == node_count - 1 else roles[i % len(roles)],  # type: ignore[arg-type]
            location=f"src/request.cpp:{100 + i * 10}",
            detail=f'popen(cmd_{i}, "r"); // $100% #tag',
        )
        for i in range(node_count)
    )
    edges = tuple(
        FlowEdge(
            source=f"n{i + 1}",
            target=f"n{i + 2}",
            label="unchecked & tainted" if i == 0 else f"hop_{i + 1}",
            style="dashed" if nodes[i].role == "guard" else "solid",
        )
        for i in range(node_count - 1)
    )
    return FlowDiagram(
        nodes=nodes,
        edges=edges,
        caption="Static path from recv() to popen() <escaped>.",
        lane_badge="SAST + Hunter",
        orientation=orientation,  # type: ignore[arg-type]
    )


def _minimal_dossier(
    *,
    lane: str = "hunt",
    scanners: list[str] | None = None,
    cwe: str = "CWE-78",
    predicate: str = "arbitrary_command_execution",
    path_rows: list[dict[str, str]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    sources: list[dict[str, Any]] | None = None,
    finding_family: str | None = None,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": DOSSIER_SCHEMA,
        "dossier_id": "dossier-" + "a" * 64,
        "run_id": "2026-11-27-0001",
        "renderer": "dossier/1",
        "kind": "confirmed_finding",
        "visibility": "protected_developer",
        "finding": {"claim_id": "claim-" + "1" * 64, "finding_package_id": "finding-" + "2" * 64, "sha256": "3" * 64},
        "title": f"command_injection ({cwe})",
        "state": "confirmed",
        "lane": lane,
        "statement": "Untrusted socket input reaches popen() without shell quoting.",
        "weakness_cwe": cwe,
        "security_predicate": predicate,
        "preconditions": ["Client can send a TOOL line over TCP."],
        "ship_block": {
            "policy": "confirmed_high_confidence",
            "status": "block",
            "technical_severity": "HIGH",
        },
        "missing_predicates": [],
        "classification_badge": {
            "reachability_badge": "entry_reachable",
            "owasp_2025": "A05:2025",
            "radar_domain_id": "input_output_execution",
            "radar_domain_label": "Input / Output & Execution",
            "resolution_tier": "exact_ast",
            "corroborating_scanners": scanners if scanners is not None else ["codeql"],
        },
        "taint_path_timeline": [],
        "finding_path_rows": path_rows
        if path_rows is not None
        else [
            {
                "stage": "1. Source",
                "assessment": "src/request.cpp:169 in serve_once: socket read",
                "references": "C1",
            },
            {
                "stage": "2. Call",
                "assessment": "src/request.cpp:95 in handle_request: dispatch verb",
                "references": "C2",
            },
            {
                "stage": "3. Guard",
                "assessment": "src/request.cpp:134 in handle_request: prefix check only",
                "references": "C3",
            },
            {
                "stage": "4. Sink",
                "assessment": "src/request.cpp:137 in handle_request: shell command execution",
                "references": "C4",
            },
        ],
        "adjudication_summary": {
            "verifier_posture": "confirmed",
            "counted_direct_citations": ["evrel-1"],
            "analyst_assessed_citations": [],
            "exploitability_basis": "Direct command string interpolation.",
            "guard_bypass_summary": "strchr check permits metacharacters.",
            "resolving_citations": [],
        },
        "poc_harness_summary": {},
        "remediation_guide": {},
        "evidence": evidence
        if evidence is not None
        else [
            {
                "relation_id": "evrel-1",
                "entity_id": "asr:ast_node:1",
                "entity_kind": "ast_node",
                "kind": "supports",
                "predicate": "attacker_input_control",
                "locator": "src/request.cpp:169-169#b1-10@" + "1" * 64,
                "content_sha256": "2" * 64,
                "admissibility": "counted_direct",
                "strength": "direct",
                "complete": True,
                "shard_id": "s1",
                "retrieval_receipt_sha256": "3" * 64,
            },
            {
                "relation_id": "evrel-2",
                "entity_id": "asr:ast_node:2",
                "entity_kind": "sink_site",
                "kind": "supports",
                "predicate": "affected_construct",
                "locator": "src/request.cpp:137-137#b20-40@" + "1" * 64,
                "content_sha256": "4" * 64,
                "admissibility": "counted_direct",
                "strength": "direct",
                "complete": True,
                "shard_id": "s1",
                "retrieval_receipt_sha256": "3" * 64,
            },
        ],
        "sources": sources
        if sources is not None
        else [
            {
                "path": "src/request.cpp",
                "start_line": 94,
                "end_line": 140,
                "excerpt": "\n".join(
                    [
                        "// request handler",
                        "int handle_request(char *line, size_t len, int sock, Session *session) {",
                        *[f"  // filler {ln}" for ln in range(96, 134)],
                        '  if (strncmp(arg, "ping ", 5) == 0) {',
                        "    char cmd[256];",
                        '    snprintf(cmd, sizeof(cmd), "/bin/ping -c 1 %s", arg + 5);',
                        '    FILE *fp = popen(cmd, "r");',
                        "    if (fp) pclose(fp);",
                        "  }",
                        "}",
                    ]
                ),
                "entity_id": "asr:ast_node:2",
                "file_sha256": "1" * 64,
                "mapping_ambiguous": 0,
                "mapping_confidence": 1.0,
                "mapping_method": "exact",
                "source_id": "src-1",
                "target_snapshot": "snap",
                "upstream_truncated": False,
            },
            {
                "path": "src/request.cpp",
                "start_line": 167,
                "end_line": 176,
                "excerpt": "\n".join(
                    [
                        "int serve_once(int sock) {",
                        "  char line[1024];",
                        "  ssize_t n = recv(sock, line, sizeof(line) - 1, 0);",
                        "  if (n <= 0) return -1;",
                        "  line[n] = '\\0';",
                        "  return handle_request(line, (size_t)n, sock, nullptr);",
                        "}",
                    ]
                ),
                "entity_id": "asr:ast_node:1",
                "file_sha256": "1" * 64,
                "mapping_ambiguous": 0,
                "mapping_confidence": 1.0,
                "mapping_method": "exact",
                "source_id": "src-2",
                "target_snapshot": "snap",
                "upstream_truncated": False,
            },
        ],
        "scores": {},
        "chains": [],
        "poc": None,
        "remediation": [],
        "notices": ["Protected developer artifact."],
        "gaps": [],
        "truncations": [],
        "provenance": {"ledger_head_sha256": "f" * 64},
    }
    if finding_family is not None:
        base["finding_family"] = finding_family
    return base


def test_flow_diagram_model_validation() -> None:
    with pytest.raises(ValueError, match="at least one node"):
        FlowDiagram(nodes=(), edges=())

    n1 = FlowNode(node_id="n1", label="source", role="source")
    with pytest.raises(ValueError, match="distinct"):
        FlowDiagram(nodes=(n1, FlowNode(node_id="n1", label="sink", role="sink")), edges=())

    with pytest.raises(ValueError, match="does not reference"):
        FlowDiagram(
            nodes=(n1,),
            edges=(FlowEdge(source="n1", target="missing"),),
        )


def test_html_and_standalone_svg_escape_and_wrap_rows() -> None:
    diag = _sample_diagram(node_count=6, orientation="LR")
    doc = Document(
        title="Flow Test",
        subtitle="Sub",
        run_id="run-1",
        status_badge="confirmed",
        status_tone="confirmed",
        ledger_head="0" * 64,
        source_date_epoch=0,
        blocks=(Heading(1, "Flow", "flow"), diag),
    )
    rendered_html = render_html(doc)
    assert '<svg xmlns="http://www.w3.org/2000/svg" role="img"' in rendered_html
    assert "SAST + Hunter" in rendered_html
    assert "<unsafe>" not in rendered_html
    assert "&lt;unsafe &amp; raw&gt;" in rendered_html
    assert "https://" not in rendered_html and "http://cdn" not in rendered_html

    standalone = to_standalone_svg(diag)
    root = ET.fromstring(standalone)
    assert root.tag.endswith("svg")
    assert root.attrib["role"] == "img"
    node_groups = [el for el in root.iter() if el.attrib.get("class") == "flow-node"]
    assert len(node_groups) == 6

    td_svg = render_flow_svg(_sample_diagram(node_count=3, orientation="TD"), standalone=True)
    td_root = ET.fromstring(td_svg)
    assert int(td_root.attrib["height"]) > int(td_root.attrib["width"]) // 2


def test_latex_renders_pure_tikz_with_escaped_specials() -> None:
    diag = _sample_diagram(node_count=4, orientation="TD")
    # Include a non-adjacent back/branch edge to exercise orthogonal side-routing too.
    diag_with_jump = FlowDiagram(
        nodes=diag.nodes,
        edges=(*diag.edges, FlowEdge(source="n2", target="n4", label="bypass", style="dashed")),
        caption=diag.caption,
        lane_badge=diag.lane_badge,
        orientation="TD",
    )
    doc = Document(
        title="LaTeX Flow",
        subtitle="Sub",
        run_id="run-1",
        status_badge="confirmed",
        status_tone="confirmed",
        ledger_head="0" * 64,
        source_date_epoch=0,
        blocks=(Heading(1, "Flow", "flow"), diag_with_jump),
    )
    tex_out = render_latex(doc)
    assert r"\begin{tikzpicture}[x=1mm,y=1mm]" in tex_out
    assert r"\end{tikzpicture}" in tex_out
    assert "feedback-accent" in tex_out and "dashed" in tex_out
    assert "claim-accent" in tex_out
    assert r"\$" in tex_out and r"\%" in tex_out and r"\#" in tex_out
    assert " // $100%" not in tex_out
    assert max(len(line.encode("utf-8")) for line in tex_out.splitlines()) < 4096


def test_markdown_and_dot_exporters_escape_metacharacters() -> None:
    dossier = _minimal_dossier()
    md = render_dossier_markdown(dossier)
    assert "```mermaid" in md
    assert "flowchart LR" in md
    assert "classDef role_sink" in md
    assert "| Step | Role | Location | Operation |" in md
    assert "**Verification lane**: ` SAST + Hunter `" in md

    diag = _sample_diagram(node_count=4)
    mermaid = to_mermaid(diag)
    assert "&lt;unsafe &amp; raw&gt;" in mermaid
    dot = to_dot(diag)
    assert "digraph CodeFlow {" in dot
    assert 'style="rounded,filled,dashed"' in dot


def test_build_dossier_flow_diagram_handles_sast_sca_and_redaction() -> None:
    dossier = _minimal_dossier(lane="hunt", scanners=["codeql"])
    diag = build_dossier_flow_diagram(dossier)
    assert diag is not None
    assert diag.lane_badge == "SAST + Hunter"
    assert diag.nodes[0].role in {"source", "entry"}
    assert diag.nodes[-1].role == "sink"
    assert sum(1 for n in diag.nodes if n.role == "sink") == 1
    assert any("popen" in n.detail for n in diag.nodes)

    # Pure SCA advisory without code hop returns None.
    sca_only = _minimal_dossier(
        lane="lead",
        scanners=["osv-scanner"],
        cwe="CWE-1395",
        finding_family="sca",
        path_rows=[],
        evidence=[
            {
                "relation_id": "evrel-sca",
                "entity_id": "asr:pkg:1",
                "entity_kind": "dependency_advisory",
                "kind": "supports",
                "predicate": "vulnerable_dependency",
                "locator": "Cargo.lock:12-18#zlib@1.2.11",
                "content_sha256": "5" * 64,
                "admissibility": "counted_direct",
                "strength": "direct",
                "complete": True,
                "shard_id": "s1",
                "retrieval_receipt_sha256": "6" * 64,
            }
        ],
        sources=[
            {
                "path": "Cargo.lock",
                "start_line": 12,
                "end_line": 18,
                "excerpt": 'name = "zlib"\nversion = "1.2.11"\n',
                "entity_id": "asr:pkg:1",
                "file_sha256": "7" * 64,
                "mapping_ambiguous": 0,
                "mapping_confidence": 1.0,
                "mapping_method": "exact",
                "source_id": "s-lock",
                "target_snapshot": "snap",
                "upstream_truncated": False,
            }
        ],
    )
    assert build_dossier_flow_diagram(sca_only) is None
    sca_doc = dossier_document(sca_only)
    assert not any(isinstance(b, FlowDiagram) for b in sca_doc.blocks)

    # Reachable SCA advisory with call site builds Manifest -> Vulnerable package -> Reachable call.
    sca_reach = dict(sca_only)
    sca_reach["evidence"] = [
        *sca_only["evidence"],
        {
            "relation_id": "evrel-call",
            "entity_id": "asr:ast_node:99",
            "entity_kind": "sink_site",
            "kind": "supports",
            "predicate": "affected_construct",
            "locator": "src/compress.cpp:42-42#b1-20@" + "8" * 64,
            "content_sha256": "9" * 64,
            "admissibility": "counted_direct",
            "strength": "direct",
            "complete": True,
            "shard_id": "s1",
            "retrieval_receipt_sha256": "6" * 64,
        },
    ]
    sca_reach["sources"] = [
        *sca_only["sources"],
        {
            "path": "src/compress.cpp",
            "start_line": 40,
            "end_line": 44,
            "excerpt": "int inflate_buf(z_stream *s) {\n  return inflate(s, Z_NO_FLUSH);\n}\n",
            "entity_id": "asr:ast_node:99",
            "file_sha256": "8" * 64,
            "mapping_ambiguous": 0,
            "mapping_confidence": 1.0,
            "mapping_method": "exact",
            "source_id": "s-code",
            "target_snapshot": "snap",
            "upstream_truncated": False,
        },
    ]
    sca_diag = build_dossier_flow_diagram(sca_reach)
    assert sca_diag is not None
    assert [n.role for n in sca_diag.nodes] == ["source", "callee", "sink"]

    # Secret-bearing CWE-798 source line must never leak raw token into FlowDiagram.
    raw_token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    secret_dossier = _minimal_dossier(
        cwe="CWE-798",
        predicate="hardcoded_secret",
        path_rows=[],
        evidence=[
            {
                "relation_id": "evrel-sec1",
                "entity_id": "asr:ast_node:s1",
                "entity_kind": "ast_node",
                "kind": "supports",
                "predicate": "affected_construct",
                "locator": "src/auth.cpp:14-14#b1-50@" + "a" * 64,
                "content_sha256": "b" * 64,
                "admissibility": "counted_direct",
                "strength": "direct",
                "complete": True,
                "shard_id": "s1",
                "retrieval_receipt_sha256": "c" * 64,
            }
        ],
        sources=[
            {
                "path": "src/auth.cpp",
                "start_line": 10,
                "end_line": 16,
                "excerpt": (
                    "int login_client(const char *user) {\n"
                    "  if (!user) return -1;\n"
                    "  const char *hdr = user;\n"
                    "  if (hdr[0] == '\\0') return -2;\n"
                    f'  const char *api_token = "{raw_token}";\n'
                    "  return send_token(api_token);\n"
                    "}\n"
                ),
                "entity_id": "asr:ast_node:s1",
                "file_sha256": "a" * 64,
                "mapping_ambiguous": 0,
                "mapping_confidence": 1.0,
                "mapping_method": "exact",
                "source_id": "s-sec",
                "target_snapshot": "snap",
                "upstream_truncated": False,
            }
        ],
    )
    sec_diag = build_dossier_flow_diagram(secret_dossier)
    assert sec_diag is not None
    assert all(raw_token not in (n.label + n.detail) for n in sec_diag.nodes)
    assert raw_token not in to_standalone_svg(sec_diag)
    assert raw_token not in to_mermaid(sec_diag)
    assert raw_token not in to_dot(sec_diag)


def test_export_exe_viewer_flow_cli_contract(tmp_path: Path) -> None:
    fake_viewer = tmp_path / "fake_exe_viewer.sh"
    fake_viewer.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'out=""\n'
        'fmt=""\n'
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    --output) out="$2"; shift 2 ;;\n'
        '    --graph-format) fmt="$2"; shift 2 ;;\n'
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        'if [[ "$fmt" == "svg" ]]; then\n'
        '  printf \'<svg xmlns="http://www.w3.org/2000/svg"></svg>\\n\' > "$out"\n'
        'elif [[ "$fmt" == "json" ]]; then\n'
        '  printf \'{"kind":"cfg","nodes":[],"edges":[]}\\n\' > "$out"\n'
        "else\n"
        '  printf \'digraph G {}\\n\' > "$out"\n'
        "fi\n",
        encoding="utf-8",
    )
    os.chmod(fake_viewer, os.stat(fake_viewer).st_mode | stat.S_IXUSR)

    fake_bin = tmp_path / "smoke_server"
    fake_bin.write_bytes(b"\x7fELF")

    with pytest.raises(ValueError, match="symbol"):
        export_exe_viewer_flow(
            fake_viewer, fake_bin, kind="cfg", symbol=None, output_path=tmp_path / "x.svg"
        )

    svg_out = export_exe_viewer_flow(
        fake_viewer,
        fake_bin,
        kind="cfg",
        symbol="handle_request",
        output_path=tmp_path / "nested" / "cfg.svg",
        fmt="svg",
    )
    assert svg_out.is_file()
    assert "<svg" in svg_out.read_text(encoding="utf-8")

    json_out = export_exe_viewer_flow(
        fake_viewer,
        fake_bin,
        kind="entry",
        output_path=tmp_path / "entry.json",
        fmt="json",
    )
    assert json.loads(json_out.read_text(encoding="utf-8"))["kind"] == "cfg"
