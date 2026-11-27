"""Deterministic Detailed Finding Report builder and multi-format renderers.

Pairs each gate-certified defect from ``job_final_publication_gate`` with three
deterministic ``FlowDiagram`` projections:
- ``3a``: Source-Level Taint & Invariant Flow (gate-bound dossier flow + invariant fallback)
- ``3b``: Call-Fanout Slice (streaming ``job_code_graph_index`` ``alternate_cpg`` + ``exe_viewer`` + structural fallback)
- ``3c``: Function Control-Flow Graph (streaming intra-procedural ``cfg_block`` slice + ``exe_viewer`` + CFG fallback)
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import html
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Literal, Mapping, Sequence

from appsec_review.jobs.engineering_contracts import DETAILED_FINDING_REPORT_SCHEMA
from appsec_review.reporting.code_flow import (
    build_dossier_flow_diagram,
    role_title,
    to_dot,
    to_mermaid,
    to_standalone_svg,
)
from appsec_review.reporting.html import render_html
from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.model import (
    FLOW_NODE_ROLES,
    Block,
    Box,
    Bullets,
    Cell,
    Document,
    Field,
    Fields,
    FlowDiagram,
    FlowEdge,
    FlowEdgeStyle,
    FlowNode,
    FlowNodeRole,
    FlowOrientation,
    Heading,
    PageBreak,
    Para,
    Stat,
    Stats,
    Table,
)
from appsec_review.reporting.tokens import BoxKind
from appsec_review.review.models import IntegrityError
from appsec_review.review.secret_redaction import redact_code_secrets, redact_prose_secrets
from appsec_review.storage import atomic_bytes

RENDERER_ID = "appsec-review-detailed-finding-report/1"
SOURCE_DATE_EPOCH = 0

render_svg_flow_diagram = to_standalone_svg
render_mermaid_flowchart = to_mermaid
render_graphviz_dot = to_dot
render_html_report = render_html
render_latex_report = render_latex

DIAGRAM_FILE_STEMS: dict[str, str] = {
    "3a": "3a-source-taint-flow",
    "3b": "3b-call-fanout-slice",
    "3c": "3c-control-flow-graph",
}
DIAGRAM_TITLES: dict[str, str] = {
    "3a": "3a — Source-Level Taint & Invariant Flow",
    "3b": "3b — Call-Fanout Slice",
    "3c": "3c — Function Control-Flow Graph",
}

_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNSPECIFIED": 5,
}
_REDACT_MARKER_RE = re.compile(
    r"(?:<redacted:\d+\s+chars>|&lt;redacted:\d+\s+chars&gt;)",
    re.IGNORECASE,
)
_SLUG_INVALID_RE = re.compile(r"[^a-z0-9._-]+")
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_INTER_EDGE_KINDS = frozenset({"CALLS", "REFERENCES", "FN_TO_SINK", "ENTRYPOINT_TO_FN"})
_INTRA_EDGE_KINDS = frozenset({"CFG", "FLOWS_TO", "GUARDS", "DEF_USE", "TAINT_STEP"})
_SINK_CALLEE_HINTS = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "vsprintf",
    "system", "popen", "execve", "execl", "execvp", "fopen", "open", "eval",
    "query", "execute", "raw", "deserialize", "loads", "unmarshal", "free",
})
_GUARD_CALLEE_HINTS = frozenset({
    "validate", "sanitize", "check", "verify", "authorize", "authenticate", "assert", "assertd",
})


def _norm_path(raw: Any) -> str:
    text = str(raw or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.lstrip("/")
    if not text:
        return ""
    return PurePosixPath(text).as_posix()


def sanitize_report_text(value: Any, *, code: bool = False, single_line: bool = True, max_len: int = 512) -> str:
    """Redact credential literals and normalize any ``<redacted:N chars>`` markers to ``[REDACTED]``."""
    text = "" if value is None else str(value)
    if not text:
        return ""
    if code:
        text = redact_code_secrets(text)
    text = redact_prose_secrets(text)
    text = _REDACT_MARKER_RE.sub("[REDACTED]", text)
    if single_line:
        text = " ".join(text.replace("\r", " ").replace("\n", " ").split())
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(text) > max_len:
        if max_len <= 3:
            return text[:max_len]
        return text[: max_len - 3].rstrip() + "..."
    return text


def assert_no_redaction_markers(text: str, *, artifact_name: str) -> None:
    """Fail closed if any internal ``<redacted:...>`` placeholder survived sanitization."""
    lowered = text.lower()
    if "<redacted:" in lowered or "&lt;redacted:" in lowered:
        raise IntegrityError(f"unnormalized <redacted:> marker leaked into {artifact_name}")


def sanitize_flow_diagram(diagram: FlowDiagram) -> FlowDiagram:
    """Return a copy of ``diagram`` with every label, location, detail, edge and caption sanitized."""
    nodes = tuple(
        FlowNode(
            node_id=sanitize_report_text(node.node_id, max_len=96) or f"n{idx}",
            label=sanitize_report_text(node.label, code=True, max_len=240) or f"Step {idx + 1}",
            role=node.role,
            location=sanitize_report_text(node.location, code=True, max_len=240),
            detail=sanitize_report_text(node.detail, code=True, max_len=240),
        )
        for idx, node in enumerate(diagram.nodes)
    )
    edges = tuple(
        FlowEdge(
            source=sanitize_report_text(edge.source, max_len=96),
            target=sanitize_report_text(edge.target, max_len=96),
            label=sanitize_report_text(edge.label, code=True, max_len=160),
            style=edge.style,
        )
        for edge in diagram.edges
    )
    caption = sanitize_report_text(diagram.caption, max_len=512) if diagram.caption else None
    lane_badge = sanitize_report_text(diagram.lane_badge, max_len=96) if diagram.lane_badge else None
    return FlowDiagram(
        nodes=nodes,
        edges=edges,
        caption=caption,
        lane_badge=lane_badge,
        orientation=diagram.orientation,
    )


def _diagram_to_bundle(
    kind: Literal["3a", "3b", "3c"],
    diagram: FlowDiagram,
    *,
    provenance: str,
    defect_slug: str,
) -> dict[str, Any]:
    stem = DIAGRAM_FILE_STEMS[kind]
    base = f"diagrams/{defect_slug}/{stem}"
    return {
        "kind": kind,
        "title": DIAGRAM_TITLES[kind],
        "provenance": provenance,
        "orientation": diagram.orientation,
        "caption": diagram.caption or "",
        "lane_badge": diagram.lane_badge,
        "nodes": [
            {
                "node_id": node.node_id,
                "label": node.label,
                "role": node.role,
                "location": node.location,
                "detail": node.detail,
            }
            for node in diagram.nodes
        ],
        "edges": [
            {
                "source": edge.source,
                "target": edge.target,
                "label": edge.label,
                "style": edge.style,
            }
            for edge in diagram.edges
        ],
        "relative_paths": {
            "svg": f"{base}.svg",
            "mermaid": f"{base}.mmd",
            "dot": f"{base}.dot",
        },
    }


def diagram_from_bundle(bundle: Mapping[str, Any]) -> FlowDiagram:
    """Rehydrate a deterministic :class:`FlowDiagram` from a validated ``detailed-finding-report.json`` bundle."""
    nodes = tuple(
        FlowNode(
            node_id=str(row["node_id"]),
            label=str(row["label"]),
            role=row["role"],
            location=str(row.get("location") or ""),
            detail=str(row.get("detail") or ""),
        )
        for row in bundle["nodes"]
    )
    edges = tuple(
        FlowEdge(
            source=str(row["source"]),
            target=str(row["target"]),
            label=str(row.get("label") or ""),
            style=row.get("style", "solid"),
        )
        for row in bundle.get("edges", ())
    )
    return sanitize_flow_diagram(
        FlowDiagram(
            nodes=nodes,
            edges=edges,
            caption=str(bundle.get("caption") or "") or None,
            lane_badge=bundle.get("lane_badge"),
            orientation=bundle.get("orientation", "LR"),
        )
    )


def _exe_node_role(raw_node: Mapping[str, Any], *, index: int, kind: str) -> FlowNodeRole:
    raw_role = str(raw_node.get("role") or raw_node.get("kind") or raw_node.get("type") or "").strip().lower()
    if raw_role in FLOW_NODE_ROLES:
        return raw_role  # type: ignore[return-value]
    if raw_role in {"caller", "incoming", "input"}:
        return "source"
    if raw_role in {"start", "entrypoint", "entry_block", "root"}:
        return "entry"
    if raw_role in {"branch", "cond", "condition", "loop", "loop_header", "check"}:
        return "guard"
    if raw_role in {"focal", "target", "vulnerable", "vuln", "defect", "crash"}:
        return "sink"
    if raw_role in {"outgoing", "call", "import", "plt"}:
        return "callee"
    if raw_node.get("is_focal") or raw_node.get("focal") or raw_node.get("is_sink"):
        return "sink"
    if index == 0 and kind == "cfg":
        return "entry"
    return "hop"


def flow_diagram_from_exe_viewer_json(
    payload: Mapping[str, Any],
    kind: Literal["fanout", "cfg"] = "fanout",
    *,
    max_nodes: int = 14,
) -> FlowDiagram:
    """Convert ``peelf_viewer --headless <bin> --graph fanout|cfg --graph-format json`` into a ``FlowDiagram``."""
    if kind not in {"fanout", "cfg"}:
        raise ValueError(f"exe_viewer graph kind must be 'fanout' or 'cfg', got {kind!r}")
    if not isinstance(payload, Mapping):
        raise ValueError("exe_viewer graph payload must be a mapping")
    raw_nodes = payload.get("nodes")
    raw_edges = payload.get("edges", ())
    if not isinstance(raw_nodes, Sequence) or isinstance(raw_nodes, (str, bytes)) or not raw_nodes:
        raise ValueError("exe_viewer graph payload requires a non-empty 'nodes' list")
    if not isinstance(raw_edges, Sequence) or isinstance(raw_edges, (str, bytes)):
        raise ValueError("exe_viewer graph 'edges' must be a sequence")

    limit = max(1, int(max_nodes))
    parsed_nodes: list[tuple[int, int, FlowNode]] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(raw_nodes):
        if not isinstance(item, Mapping):
            continue
        raw_id = str(item.get("node_id") or item.get("id") or item.get("address") or item.get("addr") or f"n{idx}").strip()
        node_id = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw_id) or f"n{idx}"
        if node_id in seen_ids:
            node_id = f"{node_id}_{idx}"
        seen_ids.add(node_id)
        role = _exe_node_role(item, index=idx, kind=kind)
        label = str(
            item.get("label")
            or item.get("symbol")
            or item.get("name")
            or item.get("disasm")
            or raw_id
        )
        location = str(item.get("location") or item.get("address") or item.get("addr") or item.get("offset") or "")
        detail = str(item.get("detail") or item.get("guard") or item.get("summary") or item.get("instruction") or "")
        priority = 0 if role == "sink" else (1 if role in {"entry", "guard"} else 2)
        parsed_nodes.append((priority, idx, FlowNode(node_id=node_id, label=label, role=role, location=location, detail=detail)))

    if not parsed_nodes:
        raise ValueError("exe_viewer graph contained no valid node objects")

    if len(parsed_nodes) > limit:
        chosen = sorted(parsed_nodes, key=lambda row: (row[0], row[1]))[:limit]
        chosen.sort(key=lambda row: row[1])
    else:
        chosen = parsed_nodes

    nodes = tuple(row[2] for row in chosen)
    allowed_ids = {node.node_id for node in nodes}
    edges: list[FlowEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for item in raw_edges:
        if not isinstance(item, Mapping):
            continue
        raw_src = str(item.get("source") or item.get("src") or item.get("from") or "").strip()
        raw_dst = str(item.get("target") or item.get("dst") or item.get("to") or "").strip()
        src = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw_src)
        dst = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw_dst)
        if src not in allowed_ids or dst not in allowed_ids or src == dst:
            continue
        edge_label = str(item.get("label") or item.get("branch") or item.get("kind") or "")
        raw_style = str(item.get("style") or "").lower()
        style: FlowEdgeStyle = (
            "dashed"
            if raw_style == "dashed" or any(tok in edge_label.lower() for tok in ("false", "indirect", "back"))
            else "solid"
        )
        key = (src, dst, edge_label)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append(FlowEdge(source=src, target=dst, label=edge_label, style=style))

    orientation: FlowOrientation = "LR" if kind == "fanout" else "TD"
    caption = str(
        payload.get("caption")
        or (
            "Binary call-fanout neighborhood extracted from exe_viewer JSON."
            if kind == "fanout"
            else "Intra-procedural binary basic-block CFG extracted from exe_viewer JSON."
        )
    )
    return sanitize_flow_diagram(
        FlowDiagram(
            nodes=nodes,
            edges=tuple(edges),
            caption=caption,
            lane_badge="exe_viewer",
            orientation=orientation,
        )
    )


@dataclass(slots=True)
class _FunctionRecord:
    function_id: str
    name: str
    qualified_name: str
    path: str
    start_line: int
    end_line: int
    eff_start_line: int
    eff_end_line: int
    is_entrypoint: bool = False
    sink_class: str = ""
    node_kind: str = "function"


@dataclass(slots=True)
class CpgSliceIndex:
    """Bounded in-memory neighborhood extracted from ``cpg-nodes.jsonl`` and ``cpg-edges.jsonl``."""

    functions: dict[str, _FunctionRecord] = field(default_factory=dict)
    blocks_by_fn: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    incoming_fn_edges: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    outgoing_fn_edges: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    intra_block_edges: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    defect_to_fn: dict[str, str] = field(default_factory=dict)


def _node_display_name(node: Mapping[str, Any]) -> str:
    qname = str(node.get("qualified_name") or "").strip()
    name = str(node.get("name") or "").strip()
    if qname and "::" in qname and node.get("node_kind") == "cfg_block":
        return qname.split("::", 1)[0]
    return qname or name or str(node.get("node_id") or "anonymous")


def stream_cpg_slice_index(
    nodes_path: Path,
    edges_path: Path,
    defect_queries: Sequence[Mapping[str, Any]],
) -> CpgSliceIndex:
    """Stream ``cpg-nodes.jsonl`` and ``cpg-edges.jsonl`` in bounded memory for ``defect_queries``."""
    index = CpgSliceIndex()
    target_paths = {_norm_path(q.get("path")) for q in defect_queries if _norm_path(q.get("path"))}
    if not target_paths or not nodes_path.is_file():
        return index

    fn_candidates_by_path: dict[str, list[str]] = {}
    with nodes_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            row = json.loads(line)
            if not isinstance(row, Mapping):
                continue
            path = _norm_path(row.get("path") or (row.get("location") or {}).get("path"))
            if path not in target_paths:
                continue
            kind = str(row.get("node_kind") or "")
            start_line = int(row.get("start_line") or 0)
            end_line = int(row.get("end_line") or start_line)
            if kind == "function":
                fn_id = str(row.get("function_id") or row.get("node_id") or row.get("id") or "")
                if not fn_id:
                    continue
                existing = index.functions.get(fn_id)
                name = str(row.get("name") or row.get("symbol_name") or row.get("qualified_name") or fn_id)
                qname = str(row.get("qualified_name") or row.get("symbol_name") or name)
                if existing is None:
                    index.functions[fn_id] = _FunctionRecord(
                        function_id=fn_id,
                        name=name,
                        qualified_name=qname,
                        path=path,
                        start_line=start_line,
                        end_line=end_line,
                        eff_start_line=start_line,
                        eff_end_line=end_line,
                        is_entrypoint=bool(row.get("is_entrypoint")),
                        sink_class=str(row.get("sink_class") or ""),
                        node_kind="function",
                    )
                    fn_candidates_by_path.setdefault(path, []).append(fn_id)
                else:
                    existing.name = existing.name or name
                    existing.qualified_name = existing.qualified_name or qname
                    if start_line > 0:
                        existing.eff_start_line = min(existing.eff_start_line or start_line, start_line)
                    if end_line > 0:
                        existing.eff_end_line = max(existing.eff_end_line, end_line)
            elif kind == "cfg_block":
                fn_id = str(row.get("function_id") or "")
                if not fn_id:
                    continue
                blk = {
                    "node_id": str(row.get("node_id") or row.get("id") or ""),
                    "function_id": fn_id,
                    "path": path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "block_kind": str(row.get("block_kind") or row.get("kind") or "statement"),
                    "name": str(row.get("name") or "statement"),
                    "qualified_name": str(row.get("qualified_name") or ""),
                    "calls": [str(c) for c in (row.get("calls") or ()) if c],
                    "defs": [str(d) for d in (row.get("defs") or ()) if d],
                    "uses": [str(u) for u in (row.get("uses") or ()) if u],
                    "guard_expression": str(row.get("guard_expression") or ""),
                    "guard_polarity": str(row.get("guard_polarity") or ""),
                    "guard_dominators": list(row.get("guard_dominators") or ()),
                    "sink_class": str(row.get("sink_class") or ""),
                    "is_entrypoint": bool(row.get("is_entrypoint")),
                }
                index.blocks_by_fn.setdefault(fn_id, []).append(blk)
                rec = index.functions.get(fn_id)
                if rec is None:
                    inferred_name = _node_display_name(row)
                    index.functions[fn_id] = _FunctionRecord(
                        function_id=fn_id,
                        name=inferred_name,
                        qualified_name=inferred_name,
                        path=path,
                        start_line=start_line,
                        end_line=end_line,
                        eff_start_line=start_line,
                        eff_end_line=end_line,
                        is_entrypoint=bool(row.get("is_entrypoint")),
                        node_kind="function",
                    )
                    fn_candidates_by_path.setdefault(path, []).append(fn_id)
                else:
                    if start_line > 0:
                        rec.eff_start_line = min(rec.eff_start_line or start_line, start_line)
                    if end_line > 0:
                        rec.eff_end_line = max(rec.eff_end_line, end_line)

    focal_fn_ids: set[str] = set()
    for query in defect_queries:
        key = str(query["key"])
        qpath = _norm_path(query.get("path"))
        qstart = int(query.get("start_line") or 0)
        qend = int(query.get("end_line") or qstart)
        hint = str(query.get("symbol_hint") or "").strip()
        fn_ids = fn_candidates_by_path.get(qpath, [])
        if not fn_ids:
            continue
        chosen_fn: str | None = None
        if qstart > 0:
            spanning: list[tuple[int, int, str]] = []
            for fn_id in fn_ids:
                rec = index.functions[fn_id]
                if rec.eff_start_line <= qend and qstart <= rec.eff_end_line:
                    span = max(0, rec.eff_end_line - rec.eff_start_line)
                    exact_hit = 0 if (rec.eff_start_line <= qstart <= rec.eff_end_line) else 1
                    spanning.append((exact_hit, span, fn_id))
            if spanning:
                spanning.sort()
                chosen_fn = spanning[0][2]
        if chosen_fn is None and hint:
            hint_base = hint.split("(")[0].split("::")[-1].strip()
            for fn_id in sorted(fn_ids):
                rec = index.functions[fn_id]
                if rec.name == hint or rec.qualified_name == hint or rec.name == hint_base:
                    chosen_fn = fn_id
                    break
        if chosen_fn is not None:
            index.defect_to_fn[key] = chosen_fn
            focal_fn_ids.add(chosen_fn)

    index.blocks_by_fn = {
        fn_id: sorted(
            index.blocks_by_fn.get(fn_id, ()),
            key=lambda b: (int(b["start_line"]), int(b["end_line"]), str(b["node_id"])),
        )
        for fn_id in focal_fn_ids
    }
    blk_to_fn: dict[str, str] = {
        blk["node_id"]: fn_id
        for fn_id, blks in index.blocks_by_fn.items()
        for blk in blks
        if blk["node_id"]
    }

    if not focal_fn_ids or not edges_path.is_file():
        return index

    neighbor_ids: set[str] = set()
    with edges_path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            row = json.loads(line)
            if not isinstance(row, Mapping):
                continue
            src = str(row.get("source_id") or row.get("source") or "")
            dst = str(row.get("target_id") or row.get("target") or "")
            edge_kind = str(row.get("edge_kind") or "")
            if not src or not dst:
                continue
            if edge_kind in _INTER_EDGE_KINDS:
                if dst in focal_fn_ids and src != dst:
                    compact = {
                        "source_id": src,
                        "target_id": dst,
                        "edge_kind": edge_kind,
                        "edge_subtype": str(row.get("edge_subtype") or ""),
                        "callee_name": str(row.get("callee_name") or ""),
                        "line": int(row.get("line") or 0),
                        "path": _norm_path(row.get("path")),
                    }
                    index.incoming_fn_edges.setdefault(dst, []).append(compact)
                    if src not in index.functions:
                        neighbor_ids.add(src)
                if src in focal_fn_ids and src != dst:
                    compact = {
                        "source_id": src,
                        "target_id": dst,
                        "edge_kind": edge_kind,
                        "edge_subtype": str(row.get("edge_subtype") or ""),
                        "callee_name": str(row.get("callee_name") or ""),
                        "line": int(row.get("line") or 0),
                        "path": _norm_path(row.get("path")),
                    }
                    index.outgoing_fn_edges.setdefault(src, []).append(compact)
                    if dst not in index.functions:
                        neighbor_ids.add(dst)
            elif edge_kind in _INTRA_EDGE_KINDS:
                fn_src = blk_to_fn.get(src)
                fn_dst = blk_to_fn.get(dst)
                if fn_src is not None and fn_src == fn_dst and src != dst:
                    index.intra_block_edges.setdefault(fn_src, []).append({
                        "source_id": src,
                        "target_id": dst,
                        "edge_kind": edge_kind,
                        "edge_subtype": str(row.get("edge_subtype") or ""),
                        "variable": str(row.get("variable") or ""),
                        "line": int(row.get("line") or 0),
                    })

    if neighbor_ids:
        with nodes_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if not isinstance(row, Mapping):
                    continue
                nid = str(row.get("node_id") or row.get("function_id") or "")
                if nid not in neighbor_ids or nid in index.functions:
                    continue
                path = _norm_path(row.get("path") or (row.get("location") or {}).get("path"))
                sline = int(row.get("start_line") or 0)
                eline = int(row.get("end_line") or sline)
                name = str(row.get("name") or row.get("qualified_name") or nid)
                qname = str(row.get("qualified_name") or name)
                index.functions[nid] = _FunctionRecord(
                    function_id=nid,
                    name=name,
                    qualified_name=qname,
                    path=path,
                    start_line=sline,
                    end_line=eline,
                    eff_start_line=sline,
                    eff_end_line=eline,
                    is_entrypoint=bool(row.get("is_entrypoint")),
                    sink_class=str(row.get("sink_class") or ""),
                    node_kind=str(row.get("node_kind") or "function"),
                )
                if neighbor_ids.issubset(index.functions.keys()):
                    break

    return index

def _extract_severity(package: Mapping[str, Any], dossier: Mapping[str, Any]) -> tuple[str, int]:
    candidates: list[Any] = [
        package.get("severity"),
        (package.get("ship_block") or {}).get("technical_severity")
        if isinstance(package.get("ship_block"), Mapping) else None,
        (dossier.get("classification_badge") or {}).get("severity")
        if isinstance(dossier.get("classification_badge"), Mapping) else None,
        dossier.get("severity"),
    ]
    scores = package.get("scores")
    if isinstance(scores, Sequence) and not isinstance(scores, (str, bytes)) and scores:
        first = scores[0]
        if isinstance(first, Mapping):
            tech = first.get("technical_severity")
            if isinstance(tech, Mapping):
                candidates.append(tech.get("rating"))
    for raw in candidates:
        if isinstance(raw, str) and raw.strip():
            norm = raw.strip().upper()
            if norm in _SEVERITY_ORDER:
                return norm, _SEVERITY_ORDER[norm]
    return "UNSPECIFIED", _SEVERITY_ORDER["UNSPECIFIED"]


def _extract_cwe(package: Mapping[str, Any], dossier: Mapping[str, Any], title: str) -> str:
    for candidate in (dossier.get("weakness_cwe"), dossier.get("cwe"), package.get("cwe"), title):
        if isinstance(candidate, str) and candidate.strip():
            match = _CWE_RE.search(candidate)
            if match:
                return match.group(0).upper()
    return "UNSPECIFIED"


def _extract_domain(package: Mapping[str, Any], dossier: Mapping[str, Any]) -> str:
    badge = dossier.get("classification_badge")
    if isinstance(badge, Mapping):
        for key in ("radar_domain_label", "radar_domain_id"):
            val = badge.get(key)
            if isinstance(val, str) and val.strip():
                return sanitize_report_text(val, max_len=120)
    for key in ("domain", "security_predicate", "lane"):
        val = dossier.get(key) or package.get(key)
        if isinstance(val, str) and val.strip():
            return sanitize_report_text(val, max_len=120)
    return "application_security"


def _extract_primary_location(dossier: Mapping[str, Any]) -> tuple[str, int, int, str]:
    primary = dossier.get("primary_location")
    if isinstance(primary, Mapping) and primary.get("path"):
        path = _norm_path(primary.get("path"))
        sline = max(0, int(primary.get("start_line") or primary.get("line") or 0))
        eline = max(sline, int(primary.get("end_line") or sline))
        sym = str(primary.get("symbol") or primary.get("function") or "")
        return path or "unspecified", sline, eline, sym

    for list_key in ("finding_path_rows", "taint_path_timeline", "sources", "locations"):
        rows = dossier.get(list_key)
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)) or not rows:
            continue
        selected_row: Mapping[str, Any] | None = None
        for row in rows:
            if isinstance(row, Mapping) and str(row.get("role") or "").lower() == "sink" and row.get("path"):
                selected_row = row
                break
        if selected_row is None:
            for row in rows:
                if isinstance(row, Mapping) and row.get("path"):
                    selected_row = row
                    break
        if selected_row is not None:
            path = _norm_path(selected_row.get("path"))
            sline = max(0, int(selected_row.get("start_line") or selected_row.get("line") or 0))
            eline = max(sline, int(selected_row.get("end_line") or sline))
            sym = str(selected_row.get("symbol") or selected_row.get("function") or selected_row.get("operation") or "")
            if path:
                return path, sline, eline, sym

    evidence = dossier.get("evidence")
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes)):
        for row in evidence:
            if not isinstance(row, Mapping):
                continue
            loc = row.get("locator") if isinstance(row.get("locator"), Mapping) else row
            if isinstance(loc, Mapping) and loc.get("path"):
                path = _norm_path(loc.get("path"))
                sline = max(0, int(loc.get("start_line") or loc.get("line") or 0))
                eline = max(sline, int(loc.get("end_line") or sline))
                sym = str(loc.get("symbol") or "")
                if path:
                    return path, sline, eline, sym

    return "unspecified", 0, 0, ""


def _format_location_display(path: str, start_line: int, end_line: int) -> str:
    if start_line <= 0:
        return path
    return f"{path}:{start_line}-{end_line}" if end_line > start_line else f"{path}:{start_line}"


def _extract_violated_invariant(dossier: Mapping[str, Any]) -> str:
    for key in ("violated_invariant", "statement"):
        val = dossier.get(key)
        if isinstance(val, str) and val.strip():
            return sanitize_report_text(val, code=True, max_len=600)
    guide = dossier.get("remediation_guide")
    if isinstance(guide, Mapping):
        steps = guide.get("concrete_fix_steps")
        if isinstance(steps, Sequence) and not isinstance(steps, (str, bytes)) and steps:
            first = str(steps[0] or "").strip()
            if first:
                return sanitize_report_text(first, code=True, max_len=600)
    pred = dossier.get("security_predicate")
    if isinstance(pred, str) and pred.strip():
        return sanitize_report_text(f"Security predicate violated: {pred}", max_len=300)
    return "Unspecified security invariant violation"


def _extract_remediation_status(
    finding_package_id: str,
    dossier: Mapping[str, Any],
    rem_val_by_pkg: Mapping[str, Mapping[str, Any]],
    rem_plan_by_pkg: Mapping[str, Mapping[str, Any]],
) -> tuple[str, str]:
    val_row = rem_val_by_pkg.get(finding_package_id)
    if isinstance(val_row, Mapping) and val_row.get("status"):
        status = sanitize_report_text(val_row["status"], max_len=80)
    else:
        rem = dossier.get("remediation")
        if isinstance(rem, Mapping) and rem.get("status"):
            status = sanitize_report_text(rem["status"], max_len=80)
        elif isinstance(rem, Sequence) and not isinstance(rem, (str, bytes)) and rem:
            first = rem[0]
            status = sanitize_report_text(
                (first.get("validation_status") or first.get("status") or "proposal_recorded")
                if isinstance(first, Mapping) else "proposal_recorded",
                max_len=80,
            )
        elif finding_package_id in rem_plan_by_pkg:
            status = sanitize_report_text(rem_plan_by_pkg[finding_package_id].get("status") or "proposal_generated", max_len=80)
        else:
            status = "not_validated"

    summary = ""
    guide = dossier.get("remediation_guide")
    if isinstance(guide, Mapping):
        steps = guide.get("concrete_fix_steps")
        if isinstance(steps, Sequence) and not isinstance(steps, (str, bytes)) and steps:
            summary = sanitize_report_text(steps[0], code=True, max_len=160)
    return status, summary


def _extract_poc_status(
    finding_package_id: str,
    claim_id: str,
    package: Mapping[str, Any],
    dossier: Mapping[str, Any],
    poc_by_pkg: Mapping[str, Mapping[str, Any]],
    poc_by_claim: Mapping[str, Mapping[str, Any]],
) -> str:
    row = poc_by_pkg.get(finding_package_id) or poc_by_claim.get(claim_id)
    if isinstance(row, Mapping) and row.get("status"):
        return sanitize_report_text(row["status"], max_len=80)
    if isinstance(package.get("poc"), Mapping) and package["poc"].get("status"):
        return sanitize_report_text(package["poc"]["status"], max_len=80)
    poc = dossier.get("poc")
    if isinstance(poc, Mapping) and poc.get("status"):
        return sanitize_report_text(poc["status"], max_len=80)
    harness = dossier.get("poc_harness_summary")
    if isinstance(harness, Mapping) and harness.get("compile_status"):
        return sanitize_report_text(harness["compile_status"], max_len=80)
    return "not_available"


def _make_defect_slug(finding_id: str, title: str, used: set[str]) -> str:
    short_id = finding_id
    for prefix in ("finding-", "claim-", "pkg-"):
        if short_id.startswith(prefix) and len(short_id) > len(prefix) + 12:
            short_id = f"{prefix}{short_id[len(prefix):len(prefix) + 12]}"
            break
    title_part = _SLUG_INVALID_RE.sub("-", title.lower()).strip("-._")[:36].strip("-._")
    id_part = _SLUG_INVALID_RE.sub("-", short_id.lower()).strip("-._")[:44].strip("-._")
    candidate = f"{id_part}-{title_part}".strip("-._") if title_part else id_part
    if not candidate or not candidate[0].isalnum():
        candidate = "defect-" + hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:12]
    candidate = candidate[:88].rstrip("-._")
    slug = candidate
    suffix = 2
    while slug in used:
        slug = f"{candidate[:80]}-{suffix}"
        suffix += 1
    used.add(slug)
    return slug


def build_diagram_3a(
    dossier: Mapping[str, Any],
    *,
    title: str,
    cwe: str,
    enclosing_symbol: str,
    primary_display: str,
    violated_invariant: str,
    remediation_status: str,
    remediation_summary: str,
) -> tuple[FlowDiagram, str]:
    built = build_dossier_flow_diagram(dossier)
    if built is not None and len(built.nodes) >= 2:
        sanitized = sanitize_flow_diagram(built)
        caption = sanitized.caption or (
            f"Source-level taint and invariant propagation for {title} ({cwe}) at {primary_display}."
        )
        return (
            sanitize_flow_diagram(
                FlowDiagram(
                    nodes=sanitized.nodes,
                    edges=sanitized.edges,
                    caption=caption,
                    lane_badge=sanitized.lane_badge or "dossier_taint_flow",
                    orientation=sanitized.orientation,
                )
            ),
            "dossier_flow_diagram",
        )

    sources = dossier.get("sources")
    secondary_loc = primary_display
    if isinstance(sources, Sequence) and not isinstance(sources, (str, bytes)) and len(sources) >= 2:
        first_src = sources[0]
        if isinstance(first_src, Mapping) and first_src.get("path"):
            sp = _norm_path(first_src.get("path"))
            sl = int(first_src.get("start_line") or 0)
            el = int(first_src.get("end_line") or sl)
            cand = _format_location_display(sp, sl, el)
            if cand != primary_display:
                secondary_loc = cand

    preconds = dossier.get("preconditions")
    precond_detail = "Reachable execution path enters enclosing scope"
    if isinstance(preconds, Sequence) and not isinstance(preconds, (str, bytes)) and preconds:
        precond_detail = sanitize_report_text(preconds[0], code=True, max_len=140) or precond_detail

    nodes: list[FlowNode] = [
        FlowNode("n_entry", f"Scope Entry: {enclosing_symbol}", "entry", secondary_loc, precond_detail),
        FlowNode("n_sink", f"Vulnerable Operation ({cwe})", "sink", primary_display, title),
        FlowNode("n_invariant", "Violated Security Invariant", "guard", primary_display, violated_invariant),
    ]
    edges: list[FlowEdge] = [
        FlowEdge("n_entry", "n_sink", "reaches", "solid"),
        FlowEdge("n_sink", "n_invariant", "violates", "dashed"),
    ]
    if remediation_summary or remediation_status not in {"not_validated", "not_available", "none"}:
        nodes.append(
            FlowNode(
                "n_remediation",
                f"Remediation ({remediation_status})",
                "callee",
                primary_display,
                remediation_summary or f"Validation status: {remediation_status}",
            )
        )
        edges.append(FlowEdge("n_invariant", "n_remediation", "remediated by", "solid"))

    return (
        sanitize_flow_diagram(
            FlowDiagram(
                nodes=tuple(nodes),
                edges=tuple(edges),
                caption=f"Source-level invariant and defect context synthesized from gate-bound dossier ({primary_display}).",
                lane_badge="dossier_invariant",
                orientation="LR",
            )
        ),
        "dossier_invariant_fallback",
    )

def _callee_role(name: str, edge_kind: str, sink_class: str) -> FlowNodeRole:
    if edge_kind == "FN_TO_SINK" or sink_class:
        return "sink"
    low = name.lower().split("::")[-1]
    if low in _SINK_CALLEE_HINTS or any(low.endswith("_" + s) for s in _SINK_CALLEE_HINTS):
        return "sink"
    if low in _GUARD_CALLEE_HINTS or any(tok in low for tok in ("check", "valid", "verify", "sanitize", "guard")):
        return "guard"
    return "callee"


def build_diagram_3b(
    *,
    finding_key: str,
    cpg_index: CpgSliceIndex,
    cpg_status: str,
    exe_fanout_payload: Mapping[str, Any] | None,
    domain: str,
    primary_path: str,
    primary_start_line: int,
    primary_display: str,
    enclosing_symbol: str,
    cwe: str,
    title: str,
    max_nodes: int = 12,
) -> tuple[FlowDiagram, str, str | None, str]:
    limit = max(3, int(max_nodes))
    if exe_fanout_payload is not None:
        return (
            flow_diagram_from_exe_viewer_json(exe_fanout_payload, kind="fanout", max_nodes=limit),
            "exe_viewer_fanout",
            None,
            enclosing_symbol,
        )

    fn_id = cpg_index.defect_to_fn.get(finding_key)
    if fn_id is not None and fn_id in cpg_index.functions:
        focal_fn = cpg_index.functions[fn_id]
        resolved_sym = focal_fn.qualified_name or focal_fn.name or enclosing_symbol
        focal_loc = _format_location_display(focal_fn.path, focal_fn.eff_start_line, focal_fn.eff_end_line)
        focal_node = FlowNode("fn_focal", resolved_sym, "sink", focal_loc, f"Defect @ {primary_display} ({cwe})")

        caller_entries: dict[str, tuple[str, FlowNodeRole, str, str]] = {}
        for edge in cpg_index.incoming_fn_edges.get(fn_id, ()):
            src_id = edge["source_id"]
            rec = cpg_index.functions.get(src_id)
            label = (rec.qualified_name or rec.name) if rec else src_id
            loc = _format_location_display(rec.path, rec.eff_start_line, rec.eff_end_line) if rec and rec.path else (
                _format_location_display(edge["path"], edge["line"], edge["line"]) if edge["path"] else ""
            )
            role: FlowNodeRole = (
                "entry"
                if edge["edge_kind"] == "ENTRYPOINT_TO_FN" or (rec and rec.is_entrypoint)
                else "source"
            )
            edge_lbl = "entry" if role == "entry" else ("calls" if edge["edge_kind"] == "CALLS" else "refs")
            caller_entries.setdefault(label, (label, role, loc, edge_lbl))

        callee_entries: dict[str, tuple[str, FlowNodeRole, str, str]] = {}
        for edge in cpg_index.outgoing_fn_edges.get(fn_id, ()):
            dst_id = edge["target_id"]
            rec = cpg_index.functions.get(dst_id)
            label = edge["callee_name"] or ((rec.qualified_name or rec.name) if rec else dst_id)
            loc = _format_location_display(rec.path, rec.eff_start_line, rec.eff_end_line) if rec and rec.path else (
                _format_location_display(focal_fn.path, edge["line"], edge["line"]) if edge["line"] > 0 else ""
            )
            role = _callee_role(label, edge["edge_kind"], rec.sink_class if rec else "")
            edge_lbl = "sink" if edge["edge_kind"] == "FN_TO_SINK" else (
                "calls" if edge["edge_kind"] == "CALLS" else "refs"
            )
            if label != resolved_sym:
                callee_entries.setdefault(label, (label, role, loc, edge_lbl))

        for blk in cpg_index.blocks_by_fn.get(fn_id, ()):
            blk_loc = _format_location_display(blk["path"], int(blk["start_line"]), int(blk["end_line"]))
            for callee_name in blk.get("calls", ()):
                if callee_name and callee_name != resolved_sym and callee_name not in callee_entries:
                    role = _callee_role(callee_name, "CALLS", str(blk.get("sink_class") or ""))
                    callee_entries[callee_name] = (callee_name, role, blk_loc, "calls")

        sorted_callers = [caller_entries[k] for k in sorted(caller_entries)]
        sorted_callees = [callee_entries[k] for k in sorted(callee_entries)]

        budget = limit - 1
        half = budget // 2
        if len(sorted_callers) <= half:
            take_callers = len(sorted_callers)
            take_callees = min(len(sorted_callees), budget - take_callers)
        elif len(sorted_callees) <= budget - half:
            take_callees = len(sorted_callees)
            take_callers = min(len(sorted_callers), budget - take_callees)
        else:
            take_callers = half
            take_callees = budget - half

        nodes: list[FlowNode] = []
        edges: list[FlowEdge] = []
        for idx, (lbl, role, loc, edge_lbl) in enumerate(sorted_callers[:take_callers]):
            nid = f"caller_{idx}"
            nodes.append(FlowNode(nid, lbl, role, loc, "Incoming caller"))
            edges.append(FlowEdge(nid, "fn_focal", edge_lbl, "solid"))

        if not sorted_callers and not sorted_callees:
            mod_name = PurePosixPath(focal_fn.path).name or focal_fn.path
            nodes.append(
                FlowNode(
                    "module_scope",
                    f"Module: {mod_name}",
                    "entry" if focal_fn.is_entrypoint else "source",
                    focal_fn.path,
                    "Enclosing translation unit",
                )
            )
            edges.append(FlowEdge("module_scope", "fn_focal", "defines", "solid"))

        nodes.append(focal_node)
        for idx, (lbl, role, loc, edge_lbl) in enumerate(sorted_callees[:take_callees]):
            nid = f"callee_{idx}"
            nodes.append(FlowNode(nid, lbl, role, loc, "Outgoing callee"))
            edges.append(FlowEdge("fn_focal", nid, edge_lbl, "solid"))

        caption = (
            f"Call-fanout neighborhood around {resolved_sym} ({focal_loc}) from accepted alternate_cpg "
            f"({take_callers} caller(s), {take_callees} callee(s))."
        )
        return (
            sanitize_flow_diagram(FlowDiagram(tuple(nodes), tuple(edges), caption, "alternate_cpg", "LR")),
            "alternate_cpg_call_fanout",
            None,
            resolved_sym,
        )

    file_name = PurePosixPath(primary_path).name if primary_path and primary_path != "unspecified" else primary_path
    parent_mod = str(PurePosixPath(primary_path).parent) if "/" in primary_path else domain
    reason_note = (
        f"3b fallback (dossier_structural_fallback): job_code_graph_index alternate_cpg was {cpg_status}."
        if cpg_status == "UNAVAILABLE"
        else f"3b fallback (dossier_structural_fallback): no CPG function node spanned {primary_display}."
    )
    fallback = sanitize_flow_diagram(
        FlowDiagram(
            nodes=(
                FlowNode("ctx_component", f"Domain: {domain}", "entry", parent_mod, "Component / review domain"),
                FlowNode("ctx_file", f"File: {file_name}", "hop", primary_path, f"Scope: {enclosing_symbol}"),
                FlowNode("ctx_sink", f"{enclosing_symbol} ({cwe})", "sink", primary_display, title),
            ),
            edges=(
                FlowEdge("ctx_component", "ctx_file", "contains", "solid"),
                FlowEdge("ctx_file", "ctx_sink", "defect site", "solid"),
            ),
            caption=f"Structural call-context fallback from gate-bound dossier ({reason_note})",
            lane_badge="dossier_structural_fallback",
            orientation="LR",
        )
    )
    return fallback, "dossier_structural_fallback", reason_note, enclosing_symbol


def _block_label_and_detail(blk: Mapping[str, Any], *, is_entry: bool, is_focal: bool, cwe: str) -> tuple[str, FlowNodeRole, str]:
    bkind = str(blk.get("block_kind") or "statement")
    guard = str(blk.get("guard_expression") or "").strip()
    calls = list(blk.get("calls") or ())
    defs = list(blk.get("defs") or ())
    sline = int(blk.get("start_line") or 0)
    if is_focal:
        call_txt = f"calls {', '.join(calls[:2])}" if calls else str(blk.get("name") or bkind)
        detail = f"{call_txt} ({cwe})" if not guard else f"if {guard} | {call_txt} ({cwe})"
        return f"Vulnerable {bkind} @ L{sline}", "sink", detail
    if bkind in {"branch", "loop_header"} or guard:
        prefix = "loop" if bkind == "loop_header" else "branch"
        label = f"{prefix}: {guard}" if guard else f"{prefix} @ L{sline}"
        return label, "guard", str(blk.get("guard_polarity") or "branch guard")
    if is_entry:
        detail = f"calls {', '.join(calls[:2])}" if calls else (f"defs {', '.join(defs[:2])}" if defs else bkind)
        return f"Function Entry @ L{sline}", "entry", detail
    if calls:
        label = f"call {', '.join(calls[:2])}"
    elif defs:
        label = f"def {', '.join(defs[:2])}"
    else:
        label = f"{blk.get('name') or bkind} @ L{sline}"
    return label, "hop", bkind


def build_diagram_3c(
    *,
    finding_key: str,
    cpg_index: CpgSliceIndex,
    cpg_status: str,
    exe_cfg_payload: Mapping[str, Any] | None,
    primary_path: str,
    primary_start_line: int,
    primary_end_line: int,
    primary_display: str,
    enclosing_symbol: str,
    cwe: str,
    violated_invariant: str,
    dossier: Mapping[str, Any],
    max_nodes: int = 14,
) -> tuple[FlowDiagram, str, str | None]:
    limit = max(3, int(max_nodes))
    if exe_cfg_payload is not None:
        return (
            flow_diagram_from_exe_viewer_json(exe_cfg_payload, kind="cfg", max_nodes=limit),
            "exe_viewer_cfg",
            None,
        )

    fn_id = cpg_index.defect_to_fn.get(finding_key)
    blocks = cpg_index.blocks_by_fn.get(fn_id, []) if fn_id else []
    if fn_id is not None and blocks:
        blk_by_id = {b["node_id"]: (idx, b) for idx, b in enumerate(blocks)}
        target_line = primary_start_line if primary_start_line > 0 else int(blocks[-1]["start_line"])

        focal_idx = min(
            range(len(blocks)),
            key=lambda i: (
                0 if int(blocks[i]["start_line"]) <= max(target_line, primary_end_line)
                and target_line <= int(blocks[i]["end_line"]) else 1,
                abs(int(blocks[i]["start_line"]) - target_line),
                int(blocks[i]["end_line"]) - int(blocks[i]["start_line"]),
                i,
            ),
        )
        focal_blk = blocks[focal_idx]

        must_keep: list[int] = [0, focal_idx]
        for dom in focal_blk.get("guard_dominators", ()):
            if isinstance(dom, Mapping):
                dom_id = str(dom.get("node_id") or "")
                if dom_id in blk_by_id:
                    must_keep.append(blk_by_id[dom_id][0])
        if focal_idx + 1 < len(blocks):
            must_keep.append(focal_idx + 1)
        if len(blocks) - 1 not in must_keep and len(set(must_keep)) < limit:
            if str(blocks[-1].get("block_kind") or "") == "return" or focal_idx + 2 == len(blocks):
                must_keep.append(len(blocks) - 1)

        selected_indices: set[int] = set()
        for idx in must_keep:
            if len(selected_indices) < limit:
                selected_indices.add(idx)

        radius = 1
        while len(selected_indices) < min(limit, len(blocks)) and (focal_idx - radius >= 0 or focal_idx + radius < len(blocks)):
            if focal_idx - radius >= 0 and len(selected_indices) < limit:
                selected_indices.add(focal_idx - radius)
            if focal_idx + radius < len(blocks) and len(selected_indices) < limit:
                selected_indices.add(focal_idx + radius)
            radius += 1

        ordered_indices = sorted(selected_indices)
        id_map = {blocks[idx]["node_id"]: f"bb_{pos}" for pos, idx in enumerate(ordered_indices)}

        nodes: list[FlowNode] = []
        for pos, idx in enumerate(ordered_indices):
            blk = blocks[idx]
            label, role, detail = _block_label_and_detail(
                blk,
                is_entry=(idx == 0 and idx != focal_idx),
                is_focal=(idx == focal_idx),
                cwe=cwe,
            )
            loc = _format_location_display(blk["path"], int(blk["start_line"]), int(blk["end_line"]))
            nodes.append(FlowNode(f"bb_{pos}", label, role, loc, detail))

        edges: list[FlowEdge] = []
        seen_pairs: set[tuple[str, str]] = set()
        outgoing_has_cfg: set[str] = set()

        for raw_edge in cpg_index.intra_block_edges.get(fn_id, ()):
            src_bb = id_map.get(raw_edge["source_id"])
            dst_bb = id_map.get(raw_edge["target_id"])
            if not src_bb or not dst_bb or src_bb == dst_bb:
                continue
            ekind = raw_edge["edge_kind"]
            esub = raw_edge["edge_subtype"]
            if ekind == "GUARDS":
                lbl = "false" if "false" in esub else ("true" if "true" in esub else "guards")
                style: FlowEdgeStyle = "dashed" if "false" in esub else "solid"
                outgoing_has_cfg.add(src_bb)
            elif ekind in {"CFG", "FLOWS_TO"}:
                lbl = esub if esub and esub not in {"cfg", "next"} else ""
                style = "dashed" if "false" in esub else "solid"
                outgoing_has_cfg.add(src_bb)
            elif ekind == "DEF_USE":
                var = raw_edge["variable"]
                lbl = f"def-use: {var}" if var else "def-use"
                style = "dashed"
            else:
                lbl = ekind.lower()
                style = "solid"
            if (src_bb, dst_bb) not in seen_pairs:
                seen_pairs.add((src_bb, dst_bb))
                edges.append(FlowEdge(src_bb, dst_bb, lbl, style))

        for pos in range(len(ordered_indices) - 1):
            src_bb = f"bb_{pos}"
            dst_bb = f"bb_{pos + 1}"
            if (src_bb, dst_bb) in seen_pairs or (dst_bb, src_bb) in seen_pairs:
                continue
            gap_blocks = ordered_indices[pos + 1] - ordered_indices[pos] - 1
            src_blk = blocks[ordered_indices[pos]]
            if src_bb in outgoing_has_cfg and str(src_blk.get("block_kind") or "") == "return":
                continue
            lbl = f"... +{gap_blocks} blk" if gap_blocks > 0 else "fallthrough"
            style = "dashed" if gap_blocks > 0 else "solid"
            seen_pairs.add((src_bb, dst_bb))
            edges.append(FlowEdge(src_bb, dst_bb, lbl, style))

        fn_rec = cpg_index.functions[fn_id]
        fn_name = fn_rec.qualified_name or fn_rec.name or enclosing_symbol
        caption = (
            f"Intra-procedural CFG slice for {fn_name} centered on {primary_display} "
            f"({len(nodes)} of {len(blocks)} basic blocks)."
        )
        return (
            sanitize_flow_diagram(FlowDiagram(tuple(nodes), tuple(edges), caption, "alternate_cpg_cfg", "TD")),
            "alternate_cpg_cfg",
            None,
        )

    preconds = dossier.get("preconditions")
    guard_detail = "Missing or insufficient guard before vulnerable operation"
    if isinstance(preconds, Sequence) and not isinstance(preconds, (str, bytes)) and preconds:
        guard_detail = sanitize_report_text(preconds[0], code=True, max_len=140) or guard_detail
    reason_note = (
        f"3c fallback (dossier_cfg_fallback): job_code_graph_index alternate_cpg was {cpg_status}."
        if cpg_status == "UNAVAILABLE"
        else f"3c fallback (dossier_cfg_fallback): no intra-procedural CPG basic blocks for {primary_display}."
    )
    fallback = sanitize_flow_diagram(
        FlowDiagram(
            nodes=(
                FlowNode("cfg_entry", f"Entry: {enclosing_symbol}", "entry", primary_path, "Function / file entry state"),
                FlowNode("cfg_guard", "Precondition / Guard State", "guard", primary_display, guard_detail),
                FlowNode("cfg_sink", f"Vulnerable Statement ({cwe})", "sink", primary_display, violated_invariant),
            ),
            edges=(
                FlowEdge("cfg_entry", "cfg_guard", "enters", "solid"),
                FlowEdge("cfg_guard", "cfg_sink", "unguarded path", "dashed"),
            ),
            caption=f"Intra-location control summary fallback from gate-bound dossier ({reason_note})",
            lane_badge="dossier_cfg_fallback",
            orientation="TD",
        )
    )
    return fallback, "dossier_cfg_fallback", reason_note

def build_detailed_finding_report(
    gate: Mapping[str, Any],
    bound_dossiers: Mapping[str, tuple[Mapping[str, Any], Mapping[str, str]]],
    *,
    gate_handoff: Mapping[str, str],
    gate_document: Mapping[str, str],
    configuration_profile: Mapping[str, Any],
    code_graph_handoff: Mapping[str, str] | None = None,
    alternate_cpg_summary: Mapping[str, str] | None = None,
    code_graph_status: str = "UNAVAILABLE",
    cpg_nodes_path: Path | None = None,
    cpg_edges_path: Path | None = None,
    include_backlog: bool = False,
    max_fanout_nodes: int = 12,
    max_cfg_nodes: int = 14,
    exe_viewer_graphs: Mapping[str, Mapping[str, Any]] | None = None,
    extra_limitations: Sequence[Mapping[str, str]] = (),
) -> tuple[dict[str, Any], dict[str, dict[str, FlowDiagram]]]:
    packages_by_id = {
        str(pkg["finding_package_id"]): pkg
        for pkg in gate.get("packages", ())
        if isinstance(pkg, Mapping) and pkg.get("finding_package_id")
    }
    buckets = gate.get("buckets") or {}
    publishable_ids = [
        str(pid) for pid in (buckets.get("publishable") or [
            p["finding_package_id"] for p in gate.get("packages", ())
            if isinstance(p, Mapping) and p.get("bucket") == "publishable"
        ])
        if str(pid) in packages_by_id
    ]
    backlog_ids = [
        str(pid) for pid in (buckets.get("verification_backlog") or [
            p["finding_package_id"] for p in gate.get("packages", ())
            if isinstance(p, Mapping) and p.get("bucket") == "verification_backlog"
        ])
        if include_backlog and str(pid) in packages_by_id and str(pid) in bound_dossiers
    ]

    attachments = gate.get("attachments") or {}
    rem_val_by_pkg = {
        str((row.get("finding") or {}).get("finding_package_id") or row.get("finding_package_id") or ""): row
        for row in (attachments.get("remediation_validation") or ())
        if isinstance(row, Mapping)
    }
    rem_plan_by_pkg = {
        str((row.get("finding") or {}).get("finding_package_id") or row.get("finding_package_id") or ""): row
        for row in (attachments.get("remediation_planning") or ())
        if isinstance(row, Mapping)
    }
    poc_by_pkg = {
        str(row.get("finding_package_id") or ""): row
        for row in (attachments.get("poc_generation") or ())
        if isinstance(row, Mapping) and row.get("finding_package_id")
    }
    poc_by_claim = {
        str(row.get("claim_id") or ""): row
        for row in (attachments.get("poc_generation") or ())
        if isinstance(row, Mapping) and row.get("claim_id")
    }

    synthesized_limitations: list[dict[str, str]] = []
    selected_rows: list[tuple[str, str, Mapping[str, Any], Mapping[str, Any], Mapping[str, str]]] = []
    for section, id_list in (("publishable", publishable_ids), ("backlog", backlog_ids)):
        for pkg_id in id_list:
            if pkg_id not in bound_dossiers:
                if section != "publishable":
                    continue
                pkg_row = packages_by_id[pkg_id]
                dossier_doc = {
                    "dossier_id": "dossier-00000000" + hashlib.sha256(pkg_id.encode("utf-8")).hexdigest()[:56],
                    "finding": dict(pkg_row),
                    "claim": {
                        "claim_id": pkg_row.get("claim_id") or pkg_id,
                        "state": pkg_row.get("state") or "confirmed",
                        "statement": pkg_row.get("summary") or pkg_row.get("title") or "Gate-certified defect without bound dossier.",
                        "weakness_cwe": pkg_row.get("weakness_cwe") or pkg_row.get("cwe"),
                        "security_predicate": pkg_row.get("security_predicate") or pkg_row.get("domain") or "security_defect",
                    },
                    "excerpts": list(pkg_row.get("excerpts") or ()),
                }
                dossier_ref = {"path": str(gate_document["path"]), "sha256": str(gate_document["sha256"])}
                synthesized_limitations.append({
                    "code": "dossier_unavailable_for_publishable_defect",
                    "reason": f"Publishable package {pkg_id} has no bound dossier in gate attachments; rendered from certified gate package metadata.",
                })
                selected_rows.append((section, pkg_id, pkg_row, dossier_doc, dossier_ref))
                continue
            dossier_doc, dossier_ref = bound_dossiers[pkg_id]
            selected_rows.append((section, pkg_id, packages_by_id[pkg_id], dossier_doc, dossier_ref))

    cpg_queries: list[dict[str, Any]] = []
    prelim_locs: dict[str, tuple[str, int, int, str]] = {}
    for _section, pkg_id, _pkg, dossier_doc, _ref in selected_rows:
        loc_tuple = _extract_primary_location(dossier_doc)
        prelim_locs[pkg_id] = loc_tuple
        cpg_queries.append({
            "key": pkg_id,
            "path": loc_tuple[0],
            "start_line": loc_tuple[1],
            "end_line": loc_tuple[2],
            "symbol_hint": loc_tuple[3],
        })

    if cpg_nodes_path is not None and cpg_edges_path is not None:
        cpg_index = stream_cpg_slice_index(cpg_nodes_path, cpg_edges_path, cpg_queries)
    else:
        cpg_index = CpgSliceIndex()

    used_slugs: set[str] = set()
    diagrams_by_slug: dict[str, dict[str, FlowDiagram]] = {}
    publishable_entries: list[dict[str, Any]] = []
    backlog_entries: list[dict[str, Any]] = []

    cpg_fanout_ok = 0
    cpg_cfg_ok = 0
    fallback_fanout = 0
    fallback_cfg = 0

    def _sort_key(item: tuple[str, str, Mapping[str, Any], Mapping[str, Any], Mapping[str, str]]) -> tuple[int, str, str]:
        _sec, pkg_id, pkg, dossier_doc, _ref = item
        _sev, sev_rank = _extract_severity(pkg, dossier_doc)
        finding_id = str(pkg.get("claim_id") or (dossier_doc.get("finding") or {}).get("claim_id") or pkg_id)
        return (sev_rank, finding_id, pkg_id)

    for section in ("publishable", "backlog"):
        section_items = sorted([r for r in selected_rows if r[0] == section], key=_sort_key)
        for _sec, pkg_id, pkg, dossier_doc, dossier_ref in section_items:
            finding_id = sanitize_report_text(
                pkg.get("claim_id") or (dossier_doc.get("finding") or {}).get("claim_id") or pkg_id,
                max_len=128,
            )
            title = sanitize_report_text(
                dossier_doc.get("title") or pkg.get("title") or finding_id,
                code=True,
                max_len=256,
            )
            severity, severity_rank = _extract_severity(pkg, dossier_doc)
            raw_state = str(pkg.get("state") or dossier_doc.get("state") or ("confirmed" if section == "publishable" else "supported")).lower()
            disposition = "confirmed" if raw_state == "confirmed" else "supported"
            cwe = _extract_cwe(pkg, dossier_doc, title)
            domain = _extract_domain(pkg, dossier_doc)
            p_path, p_start, p_end, sym_hint = prelim_locs[pkg_id]
            p_path_clean = sanitize_report_text(p_path, code=True, max_len=512) or "unspecified"
            p_display = _format_location_display(p_path_clean, p_start, p_end)
            enclosing_sym = sanitize_report_text(sym_hint or "<file-scope>", code=True, max_len=180) or "<file-scope>"
            violated_invariant = _extract_violated_invariant(dossier_doc)
            rem_status, rem_summary = _extract_remediation_status(pkg_id, dossier_doc, rem_val_by_pkg, rem_plan_by_pkg)
            poc_status = _extract_poc_status(pkg_id, finding_id, pkg, dossier_doc, poc_by_pkg, poc_by_claim)

            slug = _make_defect_slug(finding_id, title, used_slugs)
            exe_entry: Mapping[str, Any] = {}
            if exe_viewer_graphs:
                exe_entry = (
                    exe_viewer_graphs.get(pkg_id)
                    or exe_viewer_graphs.get(finding_id)
                    or exe_viewer_graphs.get(slug)
                    or {}
                )
            exe_fanout = exe_entry.get("fanout") if isinstance(exe_entry, Mapping) else None
            exe_cfg = exe_entry.get("cfg") if isinstance(exe_entry, Mapping) else None

            diag_3b, prov_3b, note_3b, resolved_sym = build_diagram_3b(
                finding_key=pkg_id,
                cpg_index=cpg_index,
                cpg_status=code_graph_status,
                exe_fanout_payload=exe_fanout if isinstance(exe_fanout, Mapping) else None,
                domain=domain,
                primary_path=p_path_clean,
                primary_start_line=p_start,
                primary_display=p_display,
                enclosing_symbol=enclosing_sym,
                cwe=cwe,
                title=title,
                max_nodes=max_fanout_nodes,
            )
            enclosing_sym = sanitize_report_text(resolved_sym, code=True, max_len=180) or enclosing_sym

            diag_3a, prov_3a = build_diagram_3a(
                dossier_doc,
                title=title,
                cwe=cwe,
                enclosing_symbol=enclosing_sym,
                primary_display=p_display,
                violated_invariant=violated_invariant,
                remediation_status=rem_status,
                remediation_summary=rem_summary,
            )

            diag_3c, prov_3c, note_3c = build_diagram_3c(
                finding_key=pkg_id,
                cpg_index=cpg_index,
                cpg_status=code_graph_status,
                exe_cfg_payload=exe_cfg if isinstance(exe_cfg, Mapping) else None,
                primary_path=p_path_clean,
                primary_start_line=p_start,
                primary_end_line=p_end,
                primary_display=p_display,
                enclosing_symbol=enclosing_sym,
                cwe=cwe,
                violated_invariant=violated_invariant,
                dossier=dossier_doc,
                max_nodes=max_cfg_nodes,
            )

            if prov_3b in {"alternate_cpg_call_fanout", "exe_viewer_fanout"}:
                cpg_fanout_ok += 1
            else:
                fallback_fanout += 1
            if prov_3c in {"alternate_cpg_cfg", "exe_viewer_cfg"}:
                cpg_cfg_ok += 1
            else:
                fallback_cfg += 1

            notes: list[str] = []
            if prov_3a == "dossier_invariant_fallback":
                notes.append("3a synthesized from gate-bound dossier location and violated invariant (sparse taint hops).")
            if note_3b:
                notes.append(sanitize_report_text(note_3b, max_len=400))
            if note_3c:
                notes.append(sanitize_report_text(note_3c, max_len=400))

            diagrams_by_slug[slug] = {"3a": diag_3a, "3b": diag_3b, "3c": diag_3c}
            entry = {
                "finding_package_id": sanitize_report_text(pkg_id, max_len=128),
                "finding_id": finding_id,
                "defect_slug": slug,
                "section": section,
                "title": title,
                "severity": severity,
                "severity_rank": severity_rank,
                "disposition": disposition,
                "cwe": cwe,
                "domain": domain,
                "primary_location": {
                    "path": p_path_clean,
                    "start_line": p_start,
                    "end_line": p_end,
                    "display": p_display,
                },
                "enclosing_symbol": enclosing_sym,
                "violated_invariant": violated_invariant,
                "remediation_validation_status": rem_status,
                "poc_status": poc_status,
                "dossier": {
                    "dossier_id": sanitize_report_text(dossier_doc.get("dossier_id") or slug, max_len=128),
                    "artifact": {"path": str(dossier_ref["path"]), "sha256": str(dossier_ref["sha256"])},
                },
                "diagram_provenance": {"3a": prov_3a, "3b": prov_3b, "3c": prov_3c, "notes": notes},
                "diagrams": {
                    "3a": _diagram_to_bundle("3a", diag_3a, provenance=prov_3a, defect_slug=slug),
                    "3b": _diagram_to_bundle("3b", diag_3b, provenance=prov_3b, defect_slug=slug),
                    "3c": _diagram_to_bundle("3c", diag_3c, provenance=prov_3c, defect_slug=slug),
                },
            }
            if section == "publishable":
                publishable_entries.append(entry)
            else:
                backlog_entries.append(entry)

    limitations: list[dict[str, str]] = []
    seen_lim: set[tuple[str, str]] = set()
    for item in (*synthesized_limitations, *extra_limitations, *(gate.get("limitations") or ())):
        if not isinstance(item, Mapping):
            continue
        code = sanitize_report_text(item.get("code") or item.get("kind") or "limitation", max_len=96) or "limitation"
        reason = sanitize_report_text(item.get("reason") or item.get("summary") or item.get("description") or code, max_len=800)
        if reason and (code, reason) not in seen_lim:
            seen_lim.add((code, reason))
            limitations.append({"code": code, "reason": reason})

    total_defects = len(publishable_entries) + len(backlog_entries)
    report = {
        "schema": DETAILED_FINDING_REPORT_SCHEMA,
        "run_id": str(gate["run_id"]),
        "provenance": {
            "gate_handoff": {"path": str(gate_handoff["path"]), "sha256": str(gate_handoff["sha256"])},
            "gate_document": {"path": str(gate_document["path"]), "sha256": str(gate_document["sha256"])},
            "code_graph_handoff": (
                {"path": str(code_graph_handoff["path"]), "sha256": str(code_graph_handoff["sha256"])}
                if code_graph_handoff is not None else None
            ),
            "alternate_cpg_summary": (
                {"path": str(alternate_cpg_summary["path"]), "sha256": str(alternate_cpg_summary["sha256"])}
                if alternate_cpg_summary is not None else None
            ),
            "configuration_profile": {
                "name": str(configuration_profile.get("name") or "dev"),
                "sha256": configuration_profile.get("sha256"),
            },
            "renderer": RENDERER_ID,
        },
        "status": {
            "gate_status": str(gate.get("status") or "UNKNOWN"),
            "review_status": str((gate.get("review") or {}).get("status") or "UNKNOWN"),
            "code_graph_status": str(code_graph_status),
            "include_backlog": bool(include_backlog),
        },
        "summary": {
            "publishable_defect_count": len(publishable_entries),
            "backlog_defect_count": len(backlog_entries),
            "total_defect_count": total_defects,
            "diagram_count": total_defects * 3,
            "cpg_fanout_resolved_count": cpg_fanout_ok,
            "cpg_cfg_resolved_count": cpg_cfg_ok,
            "fallback_fanout_count": fallback_fanout,
            "fallback_cfg_count": fallback_cfg,
        },
        "defects": publishable_entries,
        "backlog_defects": backlog_entries,
        "limitations": limitations,
    }
    assert_no_redaction_markers(json.dumps(report, sort_keys=True), artifact_name="detailed-finding-report.json")
    return report, diagrams_by_slug

def diagrams_from_report(report: Mapping[str, Any]) -> dict[str, dict[str, FlowDiagram]]:
    """Rehydrate all ``(3a, 3b, 3c)`` ``FlowDiagram`` instances directly from ``detailed-finding-report.json``."""
    out: dict[str, dict[str, FlowDiagram]] = {}
    for row in (*(report.get("defects") or ()), *(report.get("backlog_defects") or ())):
        slug = str(row["defect_slug"])
        bundles = row["diagrams"]
        out[slug] = {
            "3a": diagram_from_bundle(bundles["3a"]),
            "3b": diagram_from_bundle(bundles["3b"]),
            "3c": diagram_from_bundle(bundles["3c"]),
        }
    return out


def write_defect_diagram_files(
    report: Mapping[str, Any],
    output_dir: Path,
    *,
    diagrams_by_slug: Mapping[str, Mapping[str, FlowDiagram]] | None = None,
) -> list[dict[str, Any]]:
    """Write standalone ``.svg``, ``.mmd``, and ``.dot`` files under ``output_dir/diagrams/<defect_slug>/``."""
    resolved_diagrams = diagrams_by_slug if diagrams_by_slug is not None else diagrams_from_report(report)
    written: list[dict[str, Any]] = []
    for row in (*(report.get("defects") or ()), *(report.get("backlog_defects") or ())):
        slug = str(row["defect_slug"])
        for kind in ("3a", "3b", "3c"):
            bundle = row["diagrams"][kind]
            diagram = resolved_diagrams[slug][kind]
            rel_paths = bundle["relative_paths"]
            svg_text = render_svg_flow_diagram(diagram)
            mmd_text = render_mermaid_flowchart(diagram)
            dot_text = render_graphviz_dot(diagram)
            for ext_name, content in (("svg", svg_text), ("mermaid", mmd_text), ("dot", dot_text)):
                rel = str(rel_paths[ext_name])
                assert_no_redaction_markers(content, artifact_name=rel)
                dest = output_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                atomic_bytes(dest, content.encode("utf-8"))
            written.append({
                "defect_slug": slug,
                "diagram": kind,
                "svg_path": output_dir / str(rel_paths["svg"]),
                "mermaid_path": output_dir / str(rel_paths["mermaid"]),
                "dot_path": output_dir / str(rel_paths["dot"]),
            })
    return written


def _md_escape(value: Any) -> str:
    text = sanitize_report_text(value, max_len=600)
    return html.escape(text, quote=False).replace("|", "\\|")


def render_detailed_markdown(report: Mapping[str, Any]) -> str:
    """Render ``detailed-finding-report.md`` with relative Markdown image embeds to standalone SVGs."""
    summary = report["summary"]
    status = report["status"]
    prov = report["provenance"]
    lines: list[str] = [
        f"# Detailed Finding Report — `{report['run_id']}`",
        "",
        f"- **Schema**: `{report['schema']}`",
        f"- **Gate Status**: `{status['gate_status']}` (review: `{status['review_status']}`, code graph: `{status['code_graph_status']}`)",
        f"- **Gate Handoff**: `{prov['gate_handoff']['sha256']}`",
        f"- **Publishable Confirmed Defects**: `{summary['publishable_defect_count']}`",
        f"- **Backlog Supported Defects Included**: `{summary['backlog_defect_count']}` (`include_backlog={str(status['include_backlog']).lower()}`)",
        f"- **Total Diagrams Rendered (`3a` + `3b` + `3c`)**: `{summary['diagram_count']}`",
        "",
    ]

    all_defects = [*(report.get("defects") or ()), *(report.get("backlog_defects") or ())]
    if all_defects:
        lines.extend([
            "## Certified Defect Index",
            "",
            "| # | Section | Severity | Disposition | CWE | Title | Primary Location | Enclosing Symbol |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ])
        for idx, defect in enumerate(all_defects, start=1):
            lines.append(
                f"| {idx} | `{defect['section']}` | **{defect['severity']}** | `{defect['disposition']}` | "
                f"`{_md_escape(defect['cwe'])}` | {_md_escape(defect['title'])} | "
                f"`{_md_escape(defect['primary_location']['display'])}` | `{_md_escape(defect['enclosing_symbol'])}` |"
            )
        lines.append("")
    else:
        lines.extend([
            "## Certified Defect Index",
            "",
            "_No gate-certified defects matched the configured publication scope._",
            "",
        ])

    limitations = report.get("limitations") or ()
    if limitations:
        lines.extend(["## Coverage Gaps & Limitations", ""])
        for lim in limitations:
            lines.append(f"- **`{_md_escape(lim['code'])}`**: {_md_escape(lim['reason'])}")
        lines.append("")

    def _emit_section(heading: str, items: Sequence[Mapping[str, Any]]) -> None:
        if not items:
            return
        lines.extend([f"## {heading}", ""])
        for idx, defect in enumerate(items, start=1):
            dprov = defect["diagram_provenance"]
            lines.extend([
                f"### {idx}. [{defect['severity']}] {_md_escape(defect['title'])}",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| **Finding ID** | `{_md_escape(defect['finding_id'])}` |",
                f"| **Finding Package ID** | `{_md_escape(defect['finding_package_id'])}` |",
                f"| **Disposition** | `{defect['disposition']}` |",
                f"| **Severity** | `{defect['severity']}` |",
                f"| **CWE** | `{_md_escape(defect['cwe'])}` |",
                f"| **Domain** | {_md_escape(defect['domain'])} |",
                f"| **Primary Location** | `{_md_escape(defect['primary_location']['display'])}` |",
                f"| **Enclosing Symbol** | `{_md_escape(defect['enclosing_symbol'])}` |",
                f"| **Remediation Validation** | `{_md_escape(defect['remediation_validation_status'])}` |",
                f"| **PoC Status** | `{_md_escape(defect['poc_status'])}` |",
                f"| **Diagram Provenance (`3a` / `3b` / `3c`)** | `{dprov['3a']}` / `{dprov['3b']}` / `{dprov['3c']}` |",
                "",
                f"**Violated Invariant**: {_md_escape(defect['violated_invariant'])}",
                "",
            ])
            if dprov.get("notes"):
                for note in dprov["notes"]:
                    lines.append(f"> **Provenance Note**: {_md_escape(note)}")
                lines.append("")

            for kind in ("3a", "3b", "3c"):
                bundle = defect["diagrams"][kind]
                svg_rel = bundle["relative_paths"]["svg"]
                mmd_rel = bundle["relative_paths"]["mermaid"]
                dot_rel = bundle["relative_paths"]["dot"]
                lines.extend([
                    f"#### {bundle['title']}",
                    "",
                    f"![{bundle['title']}]({svg_rel})",
                    "",
                    f"*{_md_escape(bundle['caption'])}*  ",
                    f"Provenance: `{bundle['provenance']}` | Graph sources: [`{mmd_rel}`]({mmd_rel}), [`{dot_rel}`]({dot_rel})",
                    "",
                    "| Node | Role | Location | Detail |",
                    "| --- | --- | --- | --- |",
                ])
                for node in bundle["nodes"]:
                    lines.append(
                        f"| {_md_escape(node['label'])} | `{role_title(node['role'])}` | "
                        f"`{_md_escape(node['location'] or '-')}` | {_md_escape(node['detail'] or '-')} |"
                    )
                lines.append("")

    _emit_section("Publishable Confirmed Defects", report.get("defects") or ())
    _emit_section("Verification Backlog Supported Defects", report.get("backlog_defects") or ())

    markdown = "\n".join(lines).rstrip() + "\n"
    assert_no_redaction_markers(markdown, artifact_name="detailed-finding-report.md")
    return markdown


def build_report_document(
    report: Mapping[str, Any],
    *,
    diagrams_by_slug: Mapping[str, Mapping[str, FlowDiagram]] | None = None,
) -> Document:
    """Build a renderer-neutral :class:`Document` for HTML (inline SVG) and LaTeX/PDF (vector TikZ)."""
    resolved = diagrams_by_slug if diagrams_by_slug is not None else diagrams_from_report(report)
    summary = report["summary"]
    status = report["status"]
    prov = report["provenance"]

    gate_status = str(status["gate_status"])
    status_badge = "COMPLETE" if gate_status == "PASS" and not report.get("limitations") else "DEGRADED"
    status_tone = "confirmed" if status_badge == "COMPLETE" else "gap"

    blocks: list[Block] = [
        Heading(
            level=1,
            text="Executive Defect & Diagram Summary",
            anchor="summary",
            subtitle="Every gate-certified defect paired with 3a taint/invariant, 3b call-fanout, and 3c CFG diagrams.",
        ),
        Stats(
            items=(
                Stat("Publishable Defects", str(summary["publishable_defect_count"]), "confirmed"),
                Stat("Backlog Defects", str(summary["backlog_defect_count"]), "supported"),
                Stat("Diagrams (3a/3b/3c)", str(summary["diagram_count"]), "neutral"),
                Stat("CPG Fanout Slices", str(summary["cpg_fanout_resolved_count"]), "neutral"),
                Stat("CPG CFGs", str(summary["cpg_cfg_resolved_count"]), "neutral"),
            )
        ),
    ]

    all_defects = [*(report.get("defects") or ()), *(report.get("backlog_defects") or ())]
    if all_defects:
        table_rows = tuple(
            (
                Cell(str(defect["severity"]), badge=str(defect["disposition"]), badge_label=str(defect["severity"])),
                Cell(str(defect["cwe"]), mono=True),
                Cell(str(defect["title"])),
                Cell(str(defect["primary_location"]["display"]), mono=True),
                Cell(str(defect["enclosing_symbol"]), mono=True),
            )
            for defect in all_defects
        )
        blocks.append(
            Box(
                kind=BoxKind.EVIDENCE,
                title="Certified Defect Index",
                meta=f"{len(all_defects)} defect(s)",
                items=(
                    Table(
                        headers=("Severity", "CWE", "Defect", "Primary Location", "Symbol"),
                        rows=table_rows,
                        widths=(0.14, 0.12, 0.30, 0.24, 0.20),
                    ),
                ),
            )
        )
    else:
        blocks.append(
            Box(
                kind=BoxKind.PROVENANCE,
                title="Certified Defect Index",
                items=(Para("No gate-certified defects matched the configured publication scope."),),
            )
        )

    limitations = report.get("limitations") or ()
    if limitations:
        blocks.append(
            Box(
                kind=BoxKind.GAP,
                title="Coverage Gaps & Provenance Limitations",
                meta=f"{len(limitations)} item(s)",
                items=(Bullets(items=tuple(f"[{lim['code']}] {lim['reason']}" for lim in limitations[:32])),),
            )
        )

    def _append_defect_blocks(section_title: str, anchor_prefix: str, items: Sequence[Mapping[str, Any]]) -> None:
        if not items:
            return
        blocks.append(Heading(level=1, text=section_title, anchor=anchor_prefix, new_page=True))
        for idx, defect in enumerate(items, start=1):
            slug = str(defect["defect_slug"])
            dprov = defect["diagram_provenance"]
            if idx > 1:
                blocks.append(PageBreak())
            blocks.append(
                Heading(
                    level=2,
                    text=f"{idx}. [{defect['severity']}] {defect['title']}",
                    anchor=f"{anchor_prefix}-{slug}",
                    subtitle=f"{defect['cwe']} — {defect['primary_location']['display']} ({defect['enclosing_symbol']})",
                )
            )
            meta_items: list[Any] = [
                Fields(
                    rows=(
                        Field("Finding ID", str(defect["finding_id"]), mono=True),
                        Field("Package ID", str(defect["finding_package_id"]), mono=True),
                        Field("Disposition", str(defect["disposition"]), badge=str(defect["disposition"])),
                        Field("Severity", str(defect["severity"])),
                        Field("CWE", str(defect["cwe"]), mono=True),
                        Field("Domain", str(defect["domain"])),
                        Field("Primary Location", str(defect["primary_location"]["display"]), mono=True),
                        Field("Enclosing Symbol", str(defect["enclosing_symbol"]), mono=True),
                        Field("Remediation Validation", str(defect["remediation_validation_status"]), mono=True),
                        Field("PoC Status", str(defect["poc_status"]), mono=True),
                        Field("Diagram Provenance", f"3a={dprov['3a']}, 3b={dprov['3b']}, 3c={dprov['3c']}", mono=True),
                    )
                ),
                Para(f"Violated Invariant: {defect['violated_invariant']}"),
            ]
            if dprov.get("notes"):
                meta_items.append(Bullets(items=tuple(str(n) for n in dprov["notes"])))
            blocks.append(
                Box(
                    kind=BoxKind.CLAIM if defect["section"] == "publishable" else BoxKind.EVIDENCE,
                    title="Defect Metadata & Invariant Summary",
                    meta=str(defect["dossier"]["dossier_id"]),
                    items=tuple(meta_items),
                )
            )
            for kind in ("3a", "3b", "3c"):
                bundle = defect["diagrams"][kind]
                blocks.append(
                    Heading(
                        level=3,
                        text=str(bundle["title"]),
                        anchor=f"{anchor_prefix}-{slug}-{kind}",
                        subtitle=f"Provenance: {bundle['provenance']}",
                    )
                )
                blocks.append(resolved[slug][kind])

    _append_defect_blocks("Publishable Confirmed Defects", "publishable", report.get("defects") or ())
    _append_defect_blocks("Verification Backlog Supported Defects", "backlog", report.get("backlog_defects") or ())

    return Document(
        title="Detailed Finding Report",
        run_id=str(report["run_id"]),
        subtitle="Gate-certified defects with 3a source taint/invariant, 3b call-fanout, and 3c CFG visual diagrams",
        status_badge=status_badge,
        status_tone=status_tone,
        source_date_epoch=SOURCE_DATE_EPOCH,
        ledger_head=str(prov["gate_handoff"]["sha256"]),
        blocks=tuple(blocks),
        named_gaps=tuple(f"{lim['code']}: {lim['reason']}" for lim in limitations[:24]),
        renderer=RENDERER_ID,
        head_label="gate handoff",
    )


def render_detailed_html(
    report: Mapping[str, Any],
    *,
    diagrams_by_slug: Mapping[str, Mapping[str, FlowDiagram]] | None = None,
) -> str:
    """Render self-contained ``detailed-finding-report.html`` with inline ``<svg>`` diagrams."""
    html_text = render_html(build_report_document(report, diagrams_by_slug=diagrams_by_slug))
    assert_no_redaction_markers(html_text, artifact_name="detailed-finding-report.html")
    return html_text


def render_detailed_latex(
    report: Mapping[str, Any],
    template_dir: Path | None = None,
    *,
    diagrams_by_slug: Mapping[str, Mapping[str, FlowDiagram]] | None = None,
) -> bytes:
    """Render ``detailed-finding-report.tex`` with crisp vector TikZ diagrams."""
    tex_text = render_latex(build_report_document(report, diagrams_by_slug=diagrams_by_slug), template_dir=template_dir)
    assert_no_redaction_markers(tex_text, artifact_name="detailed-finding-report.tex")
    return tex_text.encode("utf-8")


__all__ = [
    "CpgSliceIndex",
    "DIAGRAM_FILE_STEMS",
    "DIAGRAM_TITLES",
    "RENDERER_ID",
    "SOURCE_DATE_EPOCH",
    "assert_no_redaction_markers",
    "build_detailed_finding_report",
    "build_diagram_3a",
    "build_diagram_3b",
    "build_diagram_3c",
    "build_report_document",
    "diagram_from_bundle",
    "diagrams_from_report",
    "flow_diagram_from_exe_viewer_json",
    "render_detailed_html",
    "render_detailed_latex",
    "render_detailed_markdown",
    "render_graphviz_dot",
    "render_html_report",
    "render_latex_report",
    "render_mermaid_flowchart",
    "render_svg_flow_diagram",
    "sanitize_flow_diagram",
    "sanitize_report_text",
    "stream_cpg_slice_index",
    "write_defect_diagram_files",
]