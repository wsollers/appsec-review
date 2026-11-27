"""Deterministic source-to-sink and binary code-flow diagram construction and export."""

from __future__ import annotations

import html
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

from appsec_review.reporting.model import (
    FlowDiagram,
    FlowEdge,
    FlowEdgeStyle,
    FlowNode,
    FlowNodeRole,
)
from appsec_review.reporting.text import clean
from appsec_review.review.secret_redaction import (
    redact_code_secrets,
    redact_prose_secrets,
    redact_source_line,
)
from appsec_review.reporting.tokens import BoxKind, NEUTRALS, STYLE_BY_KIND

_MAX_FLOW_NODES = 8
_NUMBERED_STAGE_RE = re.compile(r"^\s*(?P<num>\d+)\.\s*(?P<kind>[A-Za-z_]+)\s*$")
_ASSESSMENT_LOC_RE = re.compile(
    r"^(?:(?P<fn>[^\s@]+)\s+at\s+)?(?P<path>[^:\s]+):(?P<start>\d+)(?:-(?P<end>\d+))?\s*$"
)
_LOCATOR_RE = re.compile(
    r"^(?P<path>[^:#]+):(?P<start>\d+)(?:-(?P<end>\d+))?(?:#(?P<anchor>.*))?$"
)
_C_FUNC_DEF_RE = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?"
    r"(?:(?:static|inline|virtual|explicit|constexpr|extern|const|unsigned|signed|struct|class|enum)\s+)*"
    r"[A-Za-z_~][A-Za-z0-9_:<>,\s\*&]*?\b(?P<fn>[A-Za-z_~][A-Za-z0-9_:]*)\s*\([^;]*$"
)
_SCRIPT_FUNC_DEF_RE = re.compile(
    r"^\s*(?:async\s+def|def|func|fn|function)\s+(?P<fn>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_CONTROL_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "return", "sizeof", "alignof", "delete"}
)
_DOC_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc"})
_MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "requirements.txt",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "pyproject.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
        "packages.lock.json",
    }
)
_SECRET_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-320", "CWE-522"})
_SECRET_TERMS = ("secret", "credential", "api_key", "private_key", "hardcoded_password", "hardcoded_key")

_SOURCE_HINT_RE = re.compile(
    r"\b(?:recv|recvfrom|recvmsg|read|fread|fgets|getline|getenv|accept|scanf|sscanf|fscanf|"
    r"request|req|query|params|body|argv|stdin|cin)\b"
)
_GUARD_HINT_RE = re.compile(
    r"\b(?:if|switch|assert|check|verify|validate|sanitize|allowlist|whitelist|bounds)\b|"
    r"(?:<=|>=|==|!=|<|>)"
)
_SINK_HINT_RE = re.compile(
    r"\b(?:popen|system|execl|execle|execlp|execv|execve|execvp|ShellExecute|CreateProcess|"
    r"fprintf|printf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|syslog|"
    r"memcpy|memmove|strcpy|strncpy|strcat|strncat|gets|"
    r"malloc|calloc|realloc|free|delete|"
    r"fopen|open|unlink|remove|rename|chmod|"
    r"eval|exec|query|execute|raw|send|write)\b"
)

_ROLE_BOX_KIND: Mapping[FlowNodeRole, BoxKind] = {
    "entry": BoxKind.RESULT,
    "source": BoxKind.EVIDENCE,
    "hop": BoxKind.REQUEST,
    "callee": BoxKind.PROVENANCE,
    "guard": BoxKind.FEEDBACK,
    "sink": BoxKind.CLAIM,
}

_ROLE_TITLES: Mapping[FlowNodeRole, str] = {
    "entry": "ENTRY",
    "source": "SOURCE",
    "hop": "HOP",
    "callee": "CALLEE",
    "guard": "GUARD",
    "sink": "SINK",
}

_ROLE_ORDER: Mapping[FlowNodeRole, int] = {
    "entry": 0,
    "source": 1,
    "callee": 2,
    "hop": 3,
    "guard": 4,
    "sink": 5,
}


def role_box_kind(role: FlowNodeRole) -> BoxKind:
    """Map a flow node role onto the central reporting token palette."""
    return _ROLE_BOX_KIND.get(role, BoxKind.REQUEST)


def role_title(role: FlowNodeRole) -> str:
    """Short uppercase badge title for a flow node role."""
    return _ROLE_TITLES.get(role, "HOP")


@dataclass(frozen=True, slots=True)
class _FunctionSpan:
    path: str
    start_line: int
    end_line: int
    name: str


class _SourceIndex:
    """Line-accurate lookup over resolving source excerpts already embedded in a dossier."""

    def __init__(self, sources: Sequence[Mapping[str, Any]]) -> None:
        self._lines: dict[tuple[str, int], str] = {}
        self._spans_by_path: dict[str, list[tuple[int, int]]] = {}
        self._functions: list[_FunctionSpan] = []

        for src in sources:
            if not isinstance(src, Mapping):
                continue
            path = str(src.get("path") or "").strip()
            start = _as_int(src.get("start_line"))
            end = _as_int(src.get("end_line"))
            excerpt = str(src.get("excerpt") or "")
            if not path or start is None or start < 1 or not excerpt:
                continue
            raw_lines = excerpt.splitlines()
            actual_end = end if end is not None and end >= start else start + len(raw_lines) - 1
            self._spans_by_path.setdefault(path, []).append((start, actual_end))
            for idx, line_text in enumerate(raw_lines):
                line_no = start + idx
                self._lines.setdefault((path, line_no), line_text)
            self._extract_functions(path, start, raw_lines)

    def _extract_functions(self, path: str, start_line: int, raw_lines: Sequence[str]) -> None:
        pending_fn: tuple[int, str] | None = None
        brace_depth = 0
        active_fn: tuple[int, str, int] | None = None

        for idx, raw in enumerate(raw_lines):
            line_no = start_line + idx
            stripped = raw.strip()
            if active_fn is None:
                m_script = _SCRIPT_FUNC_DEF_RE.match(raw)
                if m_script:
                    fn_name = m_script.group("fn")
                    self._functions.append(
                        _FunctionSpan(path=path, start_line=line_no, end_line=start_line + len(raw_lines) - 1, name=fn_name)
                    )
                else:
                    m_c = _C_FUNC_DEF_RE.match(raw)
                    if m_c and m_c.group("fn") not in _CONTROL_KEYWORDS and not stripped.endswith(";"):
                        fn_name = m_c.group("fn").split("::")[-1]
                        if "{" in raw:
                            brace_depth = raw.count("{") - raw.count("}")
                            if brace_depth > 0:
                                active_fn = (line_no, fn_name, brace_depth)
                            else:
                                self._functions.append(
                                    _FunctionSpan(path=path, start_line=line_no, end_line=line_no, name=fn_name)
                                )
                        else:
                            pending_fn = (line_no, fn_name)
                    elif pending_fn is not None:
                        if ";" in stripped and "{" not in stripped:
                            pending_fn = None
                        elif "{" in stripped:
                            brace_depth = raw.count("{") - raw.count("}")
                            if brace_depth > 0:
                                active_fn = (pending_fn[0], pending_fn[1], brace_depth)
                            pending_fn = None
            else:
                brace_depth += raw.count("{") - raw.count("}")
                if brace_depth <= 0:
                    self._functions.append(
                        _FunctionSpan(path=path, start_line=active_fn[0], end_line=line_no, name=active_fn[1])
                    )
                    active_fn = None
                    brace_depth = 0

        if active_fn is not None:
            self._functions.append(
                _FunctionSpan(
                    path=path,
                    start_line=active_fn[0],
                    end_line=start_line + len(raw_lines) - 1,
                    name=active_fn[1],
                )
            )

    def line(self, path: str, line_no: int) -> str:
        return self._lines.get((path, line_no), "").strip()

    def range_lines(self, path: str, start_line: int, end_line: int) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for line_no in range(start_line, end_line + 1):
            if (path, line_no) in self._lines:
                out.append((line_no, self._lines[(path, line_no)].strip()))
        return out

    def enclosing_excerpt_range(self, path: str, line_no: int) -> tuple[int, int] | None:
        for start, end in self._spans_by_path.get(path, ()):
            if start <= line_no <= end:
                return (start, end)
        return None

    def function_at(self, path: str, line_no: int) -> str:
        best: _FunctionSpan | None = None
        for fn in self._functions:
            if fn.path == path and fn.start_line <= line_no <= fn.end_line:
                if best is None or (fn.end_line - fn.start_line) <= (best.end_line - best.start_line):
                    best = fn
        return best.name if best is not None else ""

    def function_header_line(self, path: str, line_no: int) -> int | None:
        best: _FunctionSpan | None = None
        for fn in self._functions:
            if fn.path == path and fn.start_line <= line_no <= fn.end_line:
                if best is None or (fn.end_line - fn.start_line) <= (best.end_line - best.start_line):
                    best = fn
        return best.start_line if best is not None else None


@dataclass(slots=True)
class _CandidateSite:
    path: str
    line: int
    end_line: int
    role: FlowNodeRole
    fn_name: str
    detail: str
    predicate: str = ""


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _is_doc_path(path: str) -> bool:
    p = Path(path.replace("\\", "/"))
    return p.suffix.lower() in _DOC_SUFFIXES


def _is_manifest_path(path: str) -> bool:
    p = Path(path.replace("\\", "/"))
    name = p.name.lower()
    if name in _MANIFEST_NAMES:
        return True
    return name.endswith((".csproj", ".fsproj", ".vbproj", ".nuspec", ".lock"))


def _is_secret_dossier(dossier: Mapping[str, Any]) -> bool:
    cwe = str(dossier.get("weakness_cwe") or "").strip().upper()
    if cwe in _SECRET_CWES:
        return True
    pred = str(dossier.get("security_predicate") or "").strip().lower()
    title = str(dossier.get("title") or "").strip().lower()
    hay = f"{pred} {title}"
    return any(term in hay for term in _SECRET_TERMS)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(1, limit - 3)].rstrip() + "..."


def _sanitize_code(text: str, *, secret_context: bool, limit: int = 68) -> str:
    if not text:
        return ""
    raw = re.sub(r"\s+", " ", text.strip())
    redacted = (
        redact_source_line(raw, assignments=True, backticks=True)
        if secret_context
        else redact_code_secrets(raw, secret_context=False)
    )
    return _truncate(clean(redacted), limit)


def _sanitize_label(text: str, *, secret_context: bool, limit: int = 44) -> str:
    if not text:
        return ""
    raw = re.sub(r"\s+", " ", text.strip())
    redacted = redact_prose_secrets(raw, secret_context=secret_context)
    return _truncate(clean(redacted), limit)


def _infer_lane_badge(dossier: Mapping[str, Any]) -> str | None:
    lanes: set[str] = set()
    family = str(dossier.get("finding_family") or "").lower()
    if family == "sca":
        lanes.add("SCA")
    dossier_lane = str(dossier.get("lane") or "").strip().lower()
    if dossier_lane in {"hunt", "hunter"}:
        lanes.add("Hunter")
    elif dossier_lane in {"lead", "sast"}:
        lanes.add("SAST")
    badge_meta = dossier.get("classification_badge")
    if isinstance(badge_meta, Mapping):
        for scanner in badge_meta.get("corroborating_scanners") or ():
            sc = str(scanner or "").strip().lower()
            if not sc:
                continue
            if "hunt" in sc:
                lanes.add("Hunter")
            elif any(tok in sc for tok in ("osv", "trivy", "sca", "sbom", "grype")):
                lanes.add("SCA")
            else:
                lanes.add("SAST")
    for ev in dossier.get("evidence") or ():
        if not isinstance(ev, Mapping):
            continue
        producer = str(ev.get("producer_job") or "").lower()
        ev_id = str(ev.get("evidence_id") or "").lower()
        kind = str(ev.get("entity_kind") or "").lower()
        if "sast" in producer or "codeql" in producer or "semgrep" in producer or kind == "dataflow_path":
            lanes.add("SAST")
        if (
            "hunter" in producer
            or "audit" in producer
            or "challenge" in producer
            or "adjudicat" in producer
            or ev_id.startswith("ev:hunter")
        ):
            lanes.add("Hunter")
        if "sca" in producer or "osv" in producer or "trivy" in producer or "sbom" in producer:
            lanes.add("SCA")
    if not lanes:
        for row in dossier.get("finding_path_rows") or ():
            if isinstance(row, Mapping) and _NUMBERED_STAGE_RE.match(str(row.get("stage") or "")):
                lanes.add("SAST")
                break
    if "SAST" in lanes and "Hunter" in lanes:
        return "SAST + Hunter"
    if "SAST" in lanes and "SCA" in lanes:
        return "SCA + SAST"
    if "SAST" in lanes:
        return "SAST"
    if "Hunter" in lanes:
        return "Hunter"
    if "SCA" in lanes:
        return "SCA"
    return None


def _short_location(path: str, line: int, end_line: int | None = None) -> str:
    norm = path.replace("\\", "/").lstrip("./")
    if end_line is not None and end_line > line:
        return f"{norm}:{line}-{end_line}"
    return f"{norm}:{line}"


def _node_label(role: FlowNodeRole, fn_name: str, path: str, fallback: str = "") -> str:
    if fn_name:
        if role == "entry":
            return f"{fn_name}() entry"
        if role == "source":
            return f"{fn_name}() input"
        if role == "guard":
            return f"{fn_name}() check"
        if role == "sink":
            return f"{fn_name}() sink"
        return f"{fn_name}()"
    if fallback:
        return fallback
    stem = Path(path.replace("\\", "/")).name or path
    return f"{stem} ({role})"


def _select_bounded_indices(roles: Sequence[FlowNodeRole], limit: int = _MAX_FLOW_NODES) -> list[int]:
    total = len(roles)
    if total <= limit:
        return list(range(total))
    must_keep: set[int] = {0, total - 1}
    for idx, role in enumerate(roles):
        if role in {"entry", "source", "guard", "sink", "callee"} and len(must_keep) < limit:
            must_keep.add(idx)
    remaining = limit - len(must_keep)
    if remaining > 0:
        pool = [idx for idx in range(1, total - 1) if idx not in must_keep]
        if pool:
            step = max(1, len(pool) / (remaining + 1))
            for k in range(1, remaining + 1):
                pick = pool[min(len(pool) - 1, int(round(k * step)) - 1)]
                must_keep.add(pick)
    return sorted(must_keep)[:limit]


def _edge_for_pair(
    prev_node: FlowNode,
    next_node: FlowNode,
    *,
    prev_fn: str,
    next_fn: str,
    default_style: FlowEdgeStyle,
) -> FlowEdge:
    style: FlowEdgeStyle = default_style
    if prev_node.role == "guard":
        label = "non-constraining check"
        style = "dashed"
    elif next_node.role == "guard":
        label = "reaches check"
    elif prev_fn and next_fn and prev_fn != next_fn:
        label = f"calls {next_fn}()"
    elif prev_node.role in {"entry", "source"} and next_node.role == "sink":
        label = "tainted to sink"
    elif prev_node.role in {"entry", "source"}:
        label = "tainted input"
    elif next_node.role == "sink":
        label = "reaches sink"
    elif next_node.role == "callee":
        label = "calls"
    else:
        label = "propagates" if default_style == "solid" else "cited hop"
    return FlowEdge(source=prev_node.node_id, target=next_node.node_id, label=label, style=style)


def _stage_to_role(stage_kind: str, *, index: int, is_last: bool) -> FlowNodeRole:
    lowered = stage_kind.lower()
    if is_last or lowered == "sink":
        return "sink"
    if lowered == "entry":
        return "entry"
    if index == 0 or lowered == "source":
        return "source"
    if lowered in {"guard", "sanitizer", "barrier", "check"}:
        return "guard"
    if lowered in {"call", "callee", "enter"}:
        return "callee"
    return "hop"


def _build_from_path_rows(
    dossier: Mapping[str, Any],
    source_index: _SourceIndex,
    *,
    secret_context: bool,
) -> FlowDiagram | None:
    rows = dossier.get("finding_path_rows") or ()
    if not isinstance(rows, Sequence):
        return None

    first_group: list[tuple[str, str]] = []
    started = False
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        stage = str(row.get("stage") or "").strip()
        assessment = str(row.get("assessment") or "").strip()
        m_stage = _NUMBERED_STAGE_RE.match(stage)
        if m_stage:
            num = int(m_stage.group("num"))
            if started and num == 1 and len(first_group) >= 2:
                break
            started = True
            first_group.append((m_stage.group("kind"), assessment))
        elif started and stage.lower().startswith("cited static path") and len(first_group) >= 2:
            break

    if len(first_group) < 2:
        return None

    parsed_steps: list[_CandidateSite] = []
    for idx, (stage_kind, assessment) in enumerate(first_group):
        m_loc = _ASSESSMENT_LOC_RE.match(assessment)
        if not m_loc:
            continue
        path = m_loc.group("path")
        if _is_doc_path(path):
            continue
        start_line = int(m_loc.group("start"))
        end_line = int(m_loc.group("end") or start_line)
        fn_name = (m_loc.group("fn") or "").strip() or source_index.function_at(path, start_line)
        role = _stage_to_role(stage_kind, index=idx, is_last=(idx == len(first_group) - 1))
        snippet = source_index.line(path, start_line)
        parsed_steps.append(
            _CandidateSite(
                path=path,
                line=start_line,
                end_line=end_line,
                role=role,
                fn_name=fn_name,
                detail=snippet,
            )
        )

    if len(parsed_steps) < 2:
        return None

    deduped: list[_CandidateSite] = []
    seen_index: dict[tuple[str, int], int] = {}
    for idx, step in enumerate(parsed_steps):
        key = (step.path, step.line)
        if key in seen_index:
            prev_idx = seen_index[key]
            existing = deduped[prev_idx]
            if idx == len(parsed_steps) - 1 or _ROLE_ORDER[step.role] > _ROLE_ORDER[existing.role]:
                existing.role = "sink" if idx == len(parsed_steps) - 1 else step.role
            continue
        seen_index[key] = len(deduped)
        deduped.append(step)

    if len(deduped) >= 2:
        deduped[-1].role = "sink"
        if deduped[0].role not in {"entry", "source"}:
            deduped[0].role = "source"

    sink_site = deduped[-1]
    existing_keys = {(s.path, s.line) for s in deduped}
    for ev in dossier.get("evidence") or ():
        if not isinstance(ev, Mapping):
            continue
        if str(ev.get("relation") or "supports") == "contradicts":
            continue
        pred = str(ev.get("predicate") or "")
        kind = str(ev.get("entity_kind") or "")
        if kind != "guard_fact" and pred != "missing_or_ineffective_guard":
            continue
        m_loc = _LOCATOR_RE.match(str(ev.get("locator") or "").strip())
        if not m_loc:
            continue
        g_path = m_loc.group("path")
        g_start = int(m_loc.group("start"))
        g_end = int(m_loc.group("end") or g_start)
        if g_path != sink_site.path or (g_end - g_start) > 4 or (g_path, g_start) in existing_keys:
            continue
        g_fn = source_index.function_at(g_path, g_start) or sink_site.fn_name
        if sink_site.fn_name and g_fn and g_fn != sink_site.fn_name:
            continue
        guard_candidate = _CandidateSite(
            path=g_path,
            line=g_start,
            end_line=g_end,
            role="guard",
            fn_name=g_fn,
            detail=source_index.line(g_path, g_start),
            predicate=pred,
        )
        insert_pos = len(deduped) - 1
        for pos in range(len(deduped) - 1):
            if deduped[pos].path == g_path and deduped[pos].fn_name == g_fn and deduped[pos].line > g_start:
                insert_pos = pos
                break
        deduped.insert(insert_pos, guard_candidate)
        break

    if len(deduped) < 2:
        return None

    keep_indices = _select_bounded_indices([s.role for s in deduped], _MAX_FLOW_NODES)
    chosen = [deduped[i] for i in keep_indices]
    return _finalize_diagram(
        chosen,
        dossier=dossier,
        secret_context=secret_context,
        default_edge_style="solid",
        caption="Producer-verified static source-to-sink path.",
    )


def _pinpoint_line_in_span(
    source_index: _SourceIndex,
    path: str,
    start_line: int,
    end_line: int,
    role: FlowNodeRole,
) -> tuple[int, str]:
    lines = source_index.range_lines(path, start_line, end_line)
    if not lines:
        return (start_line, "")
    if start_line == end_line or len(lines) == 1:
        return lines[0]

    pattern_by_role = {
        "entry": _SOURCE_HINT_RE,
        "source": _SOURCE_HINT_RE,
        "guard": _GUARD_HINT_RE,
        "sink": _SINK_HINT_RE,
    }.get(role)

    if pattern_by_role is not None:
        candidates = [
            (ln, txt)
            for ln, txt in lines
            if txt and not txt.startswith(("//", "/*", "*", "#")) and pattern_by_role.search(txt)
        ]
        if candidates:
            return candidates[-1] if role == "sink" else candidates[0]

    for ln, txt in lines:
        if txt and txt not in {"{", "}", "};"} and not txt.startswith(("//", "/*", "*")):
            return (ln, txt)
    return lines[0]


def _predicate_to_role(predicate: str, entity_kind: str) -> FlowNodeRole:
    kind = entity_kind.lower()
    pred = predicate.lower()
    if kind == "entry_point":
        return "entry"
    if kind == "guard_fact" or pred == "missing_or_ineffective_guard":
        return "guard"
    if kind == "sink_site" or pred in {"affected_construct", "security_impact"}:
        return "sink"
    if pred == "attacker_input_control":
        return "source"
    if kind == "symbol" and pred == "source_to_sink_reachability":
        return "callee"
    return "hop"


def _build_sca_reachable_diagram(
    dossier: Mapping[str, Any],
    manifest_sites: Sequence[_CandidateSite],
    code_sites: Sequence[_CandidateSite],
    *,
    secret_context: bool,
) -> FlowDiagram | None:
    if not manifest_sites or not code_sites:
        return None
    manifest = manifest_sites[0]
    call_site = next((s for s in code_sites if s.role == "sink"), code_sites[-1])
    pkg_detail = ""
    for ev in dossier.get("evidence") or ():
        if not isinstance(ev, Mapping):
            continue
        if str(ev.get("entity_kind") or "") in {"dependency_advisory", "package_lock"}:
            anchor = str(ev.get("locator") or "").split("#", 1)
            if len(anchor) == 2 and anchor[1]:
                pkg_detail = anchor[1]
                break
    cwe = str(dossier.get("weakness_cwe") or "vulnerable dependency").strip()
    nodes = (
        FlowNode(
            node_id="n1",
            label=_sanitize_label(f"Manifest ({Path(manifest.path).name})", secret_context=secret_context),
            role="source",
            location=_short_location(manifest.path, manifest.line, manifest.end_line),
            detail=_sanitize_code(manifest.detail or "dependency declaration", secret_context=secret_context),
        ),
        FlowNode(
            node_id="n2",
            label=_sanitize_label("Vulnerable package", secret_context=secret_context),
            role="callee",
            location=_short_location(manifest.path, manifest.line),
            detail=_sanitize_code(pkg_detail or cwe, secret_context=secret_context),
        ),
        FlowNode(
            node_id="n3",
            label=_sanitize_label(
                _node_label("sink", call_site.fn_name, call_site.path, "Reachable call"),
                secret_context=secret_context,
            ),
            role="sink",
            location=_short_location(call_site.path, call_site.line),
            detail=_sanitize_code(call_site.detail, secret_context=secret_context),
        ),
    )
    edges = (
        FlowEdge(source="n1", target="n2", label="locks package", style="solid"),
        FlowEdge(source="n2", target="n3", label="reachable call", style="dashed"),
    )
    return FlowDiagram(
        nodes=nodes,
        edges=edges,
        caption="Dependency manifest to reachable call-site projection.",
        lane_badge=_infer_lane_badge(dossier) or "SCA",
        orientation="LR",
    )


def _expand_single_excerpt_flow(
    primary: _CandidateSite,
    source_index: _SourceIndex,
) -> list[_CandidateSite]:
    span = source_index.enclosing_excerpt_range(primary.path, primary.line)
    if span is None:
        return [primary]
    lines = source_index.range_lines(primary.path, span[0], span[1])
    if len(lines) < 2:
        return [primary]

    fn_name = primary.fn_name or source_index.function_at(primary.path, primary.line)
    header_line = source_index.function_header_line(primary.path, primary.line)
    expanded: list[_CandidateSite] = []

    if header_line is not None and header_line != primary.line:
        expanded.append(
            _CandidateSite(
                path=primary.path,
                line=header_line,
                end_line=header_line,
                role="source",
                fn_name=fn_name,
                detail=source_index.line(primary.path, header_line),
            )
        )
    else:
        src_ln, src_txt = _pinpoint_line_in_span(source_index, primary.path, span[0], primary.line, "source")
        if src_ln != primary.line and src_txt:
            expanded.append(
                _CandidateSite(
                    path=primary.path,
                    line=src_ln,
                    end_line=src_ln,
                    role="source",
                    fn_name=fn_name,
                    detail=src_txt,
                )
            )

    for ln, txt in lines:
        if ln <= (expanded[0].line if expanded else span[0]) or ln >= primary.line:
            continue
        if txt and not txt.startswith(("//", "/*", "*")) and _GUARD_HINT_RE.search(txt):
            expanded.append(
                _CandidateSite(
                    path=primary.path,
                    line=ln,
                    end_line=ln,
                    role="guard",
                    fn_name=fn_name,
                    detail=txt,
                )
            )
            break

    primary_copy = _CandidateSite(
        path=primary.path,
        line=primary.line,
        end_line=primary.end_line,
        role="sink",
        fn_name=fn_name,
        detail=primary.detail or source_index.line(primary.path, primary.line),
        predicate=primary.predicate,
    )
    expanded.append(primary_copy)
    return expanded


def _build_from_evidence_and_sources(
    dossier: Mapping[str, Any],
    source_index: _SourceIndex,
    *,
    secret_context: bool,
) -> FlowDiagram | None:
    raw_spans: list[tuple[str, int, int, FlowNodeRole, str]] = []
    manifest_sites: list[_CandidateSite] = []

    for ev in dossier.get("evidence") or ():
        if not isinstance(ev, Mapping):
            continue
        if str(ev.get("relation") or "supports") == "contradicts":
            continue
        locator = str(ev.get("locator") or "").strip()
        m_loc = _LOCATOR_RE.match(locator)
        if not m_loc:
            continue
        path = m_loc.group("path").strip()
        if not path or _is_doc_path(path):
            continue
        start_line = int(m_loc.group("start"))
        end_line = int(m_loc.group("end") or start_line)
        if start_line < 1:
            continue
        pred = str(ev.get("predicate") or "")
        kind = str(ev.get("entity_kind") or "")
        if _is_manifest_path(path) or kind in {"dependency_advisory", "package_lock"}:
            manifest_sites.append(
                _CandidateSite(
                    path=path,
                    line=start_line,
                    end_line=end_line,
                    role="source",
                    fn_name="",
                    detail=source_index.line(path, start_line),
                    predicate=pred,
                )
            )
            continue
        role = _predicate_to_role(pred, kind)
        raw_spans.append((path, start_line, end_line, role, pred))

    if not raw_spans:
        for src in dossier.get("sources") or ():
            if not isinstance(src, Mapping):
                continue
            path = str(src.get("path") or "").strip()
            start_line = _as_int(src.get("start_line"))
            end_line = _as_int(src.get("end_line"))
            if not path or start_line is None or start_line < 1 or _is_doc_path(path):
                continue
            if _is_manifest_path(path):
                manifest_sites.append(
                    _CandidateSite(
                        path=path,
                        line=start_line,
                        end_line=end_line or start_line,
                        role="source",
                        fn_name="",
                        detail=source_index.line(path, start_line),
                    )
                )
                continue
            raw_spans.append((path, start_line, end_line or start_line, "sink", "affected_construct"))

    if not raw_spans:
        return None

    filtered_spans: list[tuple[str, int, int, FlowNodeRole, str]] = []
    for idx, (path, start, end, role, pred) in enumerate(raw_spans):
        width = end - start
        if width >= 5:
            has_narrower = any(
                j != idx
                and p2 == path
                and s2 >= start
                and e2 <= end
                and (e2 - s2) < width
                and (r2 == role or (role in {"hop", "callee"}))
                for j, (p2, s2, e2, r2, _) in enumerate(raw_spans)
            )
            if has_narrower:
                continue
        filtered_spans.append((path, start, end, role, pred))

    code_sites: list[_CandidateSite] = []
    for path, start, end, role, pred in filtered_spans:
        pin_line, snippet = _pinpoint_line_in_span(source_index, path, start, end, role)
        fn_name = source_index.function_at(path, pin_line) or source_index.function_at(path, start)
        code_sites.append(
            _CandidateSite(
                path=path,
                line=pin_line,
                end_line=pin_line if end > start else end,
                role=role,
                fn_name=fn_name,
                detail=snippet,
                predicate=pred,
            )
        )

    if manifest_sites and str(dossier.get("finding_family") or "").lower() == "sca":
        return _build_sca_reachable_diagram(
            dossier, manifest_sites, code_sites, secret_context=secret_context
        )
    if manifest_sites and not code_sites:
        return None

    by_key: dict[tuple[str, int], _CandidateSite] = {}
    role_priority: Mapping[FlowNodeRole, int] = {
        "sink": 5,
        "guard": 4,
        "entry": 3,
        "source": 3,
        "callee": 2,
        "hop": 1,
    }
    for site in code_sites:
        key = (site.path, site.line)
        existing = by_key.get(key)
        if existing is None or role_priority[site.role] > role_priority[existing.role]:
            by_key[key] = site

    unique_sites = list(by_key.values())
    if len(unique_sites) == 1:
        unique_sites = _expand_single_excerpt_flow(unique_sites[0], source_index)

    if len(unique_sites) < 2:
        return None

    fn_groups: dict[tuple[str, str], list[_CandidateSite]] = {}
    for site in unique_sites:
        group_key = (site.path, site.fn_name or f"@line:{site.line}")
        fn_groups.setdefault(group_key, []).append(site)

    ordered_groups = sorted(
        fn_groups.items(),
        key=lambda item: (
            min(_ROLE_ORDER[s.role] for s in item[1]),
            max(_ROLE_ORDER[s.role] for s in item[1]),
            item[0][0],
            min(s.line for s in item[1]),
        ),
    )

    ordered_sites: list[_CandidateSite] = []
    for _, group in ordered_groups:
        non_sinks = sorted((s for s in group if s.role != "sink"), key=lambda s: (s.line, _ROLE_ORDER[s.role]))
        sinks = sorted((s for s in group if s.role == "sink"), key=lambda s: s.line)
        ordered_sites.extend(non_sinks)
        ordered_sites.extend(sinks)

    if ordered_sites[0].role not in {"entry", "source"}:
        ordered_sites[0].role = "source"
    if ordered_sites[-1].role != "sink":
        ordered_sites[-1].role = "sink"

    keep_indices = _select_bounded_indices([s.role for s in ordered_sites], _MAX_FLOW_NODES)
    chosen = [ordered_sites[i] for i in keep_indices]
    return _finalize_diagram(
        chosen,
        dossier=dossier,
        secret_context=secret_context,
        default_edge_style="dashed",
        caption="Cited static evidence flow (dashed connectors link cited spans across predicates).",
    )


def _finalize_diagram(
    sites: Sequence[_CandidateSite],
    *,
    dossier: Mapping[str, Any],
    secret_context: bool,
    default_edge_style: FlowEdgeStyle,
    caption: str,
) -> FlowDiagram:
    nodes: list[FlowNode] = []
    fn_names: list[str] = []
    total_sites = len(sites)
    for idx, site in enumerate(sites, start=1):
        node_id = f"n{idx}"
        eff_role: FlowNodeRole = site.role
        if idx < total_sites and eff_role == "sink":
            prev_fn = sites[idx - 2].fn_name if idx >= 2 else ""
            eff_role = "callee" if (site.fn_name and site.fn_name != prev_fn) else "hop"
        elif idx > 1 and eff_role == "entry":
            eff_role = "source" if sites[0].role == "entry" else "hop"
        raw_label = _node_label(eff_role, site.fn_name, site.path)
        nodes.append(
            FlowNode(
                node_id=node_id,
                label=_sanitize_label(raw_label, secret_context=secret_context),
                role=eff_role,
                location=_short_location(site.path, site.line, site.end_line),
                detail=_sanitize_code(site.detail, secret_context=secret_context),
            )
        )
        fn_names.append(site.fn_name)

    edges: list[FlowEdge] = []
    for idx in range(len(nodes) - 1):
        edges.append(
            _edge_for_pair(
                nodes[idx],
                nodes[idx + 1],
                prev_fn=fn_names[idx],
                next_fn=fn_names[idx + 1],
                default_style=default_edge_style,
            )
        )

    orientation: Literal["LR", "TD"] = "LR" if len(nodes) <= 6 else "TD"
    return FlowDiagram(
        nodes=tuple(nodes),
        edges=tuple(edges),
        caption=_sanitize_label(caption, secret_context=secret_context, limit=120),
        lane_badge=_infer_lane_badge(dossier),
        orientation=orientation,
    )


def build_dossier_flow_diagram(dossier: Mapping[str, Any]) -> FlowDiagram | None:
    """Deterministically build a grounded FlowDiagram for a code finding dossier."""
    if not isinstance(dossier, Mapping):
        return None
    secret_context = _is_secret_dossier(dossier)
    raw_sources = dossier.get("sources") or ()
    sources = [s for s in raw_sources if isinstance(s, Mapping)] if isinstance(raw_sources, Sequence) else []
    source_index = _SourceIndex(sources)

    from_path_rows = _build_from_path_rows(dossier, source_index, secret_context=secret_context)
    if from_path_rows is not None:
        return from_path_rows

    return _build_from_evidence_and_sources(dossier, source_index, secret_context=secret_context)


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def to_dot(diagram: FlowDiagram) -> str:
    """Render a FlowDiagram to deterministic Graphviz DOT syntax."""
    neutrals = dict(NEUTRALS)
    rankdir = "LR" if diagram.orientation == "LR" else "TB"
    lines: list[str] = [
        "digraph CodeFlow {",
        f"  rankdir={rankdir};",
        '  graph [fontname="Helvetica", bgcolor="transparent", pad="0.2", nodesep="0.35", ranksep="0.55"];',
        f'  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, color="#{neutrals["rule"]}", fontcolor="#{neutrals["ink"]}"];',
        f'  edge [fontname="Helvetica", fontsize=9, color="#{neutrals["muted"]}", fontcolor="#{neutrals["muted"]}"];',
    ]
    if diagram.caption:
        lines.append(f'  label="{_dot_escape(diagram.caption)}";')
        lines.append('  labelloc="b";')

    for node in diagram.nodes:
        style = STYLE_BY_KIND[role_box_kind(node.role)]
        parts = [f"[{role_title(node.role)}] {node.label}"]
        if node.location:
            parts.append(node.location)
        if node.detail:
            parts.append(node.detail)
        label_str = "\\n".join(_dot_escape(p) for p in parts if p)
        node_style = "rounded,filled,dashed" if node.role == "guard" else "rounded,filled"
        lines.append(
            f'  "{_dot_escape(node.node_id)}" [label="{label_str}", '
            f'style="{node_style}", color="#{style.accent}", fillcolor="#{style.fill}"];'
        )

    for edge in diagram.edges:
        attrs = [f'style="{edge.style}"']
        if edge.label:
            attrs.append(f'label="{_dot_escape(edge.label)}"')
        lines.append(
            f'  "{_dot_escape(edge.source)}" -> "{_dot_escape(edge.target)}" [{", ".join(attrs)}];'
        )

    lines.append("}")
    return "\n".join(lines) + "\n"


def _mermaid_id(raw_id: str, index: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", raw_id)
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"f_{index}_{cleaned}"
    if cleaned.lower() in {"end", "subgraph", "graph", "flowchart", "classdef", "class", "style", "click"}:
        cleaned = f"node_{cleaned}"
    return cleaned


def _mermaid_escape(text: str) -> str:
    safe = html.escape(text, quote=True)
    return (
        safe.replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("{", "&#123;")
        .replace("}", "&#125;")
        .replace("(", "&#40;")
        .replace(")", "&#41;")
        .replace("|", "&#124;")
        .replace("`", "&#96;")
    )


def to_mermaid(diagram: FlowDiagram) -> str:
    """Render a FlowDiagram as a deterministic Mermaid flowchart definition."""
    neutrals = dict(NEUTRALS)
    direction = "LR" if diagram.orientation == "LR" else "TD"
    lines: list[str] = [f"flowchart {direction}"]
    id_map: dict[str, str] = {}
    used_roles: list[FlowNodeRole] = []

    for idx, node in enumerate(diagram.nodes, start=1):
        m_id = _mermaid_id(node.node_id, idx)
        id_map[node.node_id] = m_id
        if node.role not in used_roles:
            used_roles.append(node.role)
        parts = [f"{role_title(node.role)}: {_mermaid_escape(node.label)}"]
        if node.location:
            parts.append(_mermaid_escape(node.location))
        if node.detail:
            parts.append(_mermaid_escape(node.detail))
        joined = "<br/>".join(parts)
        lines.append(f'    {m_id}["{joined}"]')

    for edge in diagram.edges:
        src = id_map[edge.source]
        dst = id_map[edge.target]
        arrow = "-.->" if edge.style == "dashed" else "-->"
        if edge.label:
            lbl = _mermaid_escape(edge.label)
            arrow_expr = f"-. {lbl} .->" if edge.style == "dashed" else f"-- {lbl} -->"
            lines.append(f"    {src} {arrow_expr} {dst}")
        else:
            lines.append(f"    {src} {arrow} {dst}")

    for role in used_roles:
        style = STYLE_BY_KIND[role_box_kind(role)]
        dash = ",stroke-dasharray: 4 3" if role == "guard" else ""
        lines.append(
            f"    classDef role_{role} fill:#{style.fill},stroke:#{style.accent},"
            f"color:#{neutrals['ink']},stroke-width:1.5px{dash};"
        )
    for node in diagram.nodes:
        lines.append(f"    class {id_map[node.node_id]} role_{node.role};")

    return "\n".join(lines)


def to_standalone_svg(diagram: FlowDiagram) -> str:
    """Render a FlowDiagram to a standalone XML/SVG string with zero external dependencies."""
    from appsec_review.reporting.html import render_flow_svg

    return render_flow_svg(diagram, standalone=True)


def export_exe_viewer_flow(
    exe_viewer_bin: Path,
    binary_path: Path,
    *,
    kind: Literal["entry", "fanout", "cfg"] = "cfg",
    symbol: str | None = None,
    output_path: Path,
    fmt: Literal["dot", "svg", "json"] = "svg",
    timeout_seconds: int = 30,
) -> Path:
    """Export a binary call/CFG flow graph using `exe_viewer --headless --graph`."""
    if kind not in {"entry", "fanout", "cfg"}:
        raise ValueError(f"unsupported exe_viewer graph kind: {kind!r}")
    if fmt not in {"dot", "svg", "json"}:
        raise ValueError(f"unsupported exe_viewer graph format: {fmt!r}")
    if kind in {"fanout", "cfg"} and (symbol is None or not symbol.strip()):
        raise ValueError(f"symbol is required when kind={kind!r}")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    exe_path = Path(exe_viewer_bin)
    bin_path = Path(binary_path)
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd: list[str] = [
        str(exe_path),
        "--headless",
        str(bin_path),
        "--graph",
        kind,
    ]
    if symbol is not None and symbol.strip():
        cmd.extend(["--symbol", symbol.strip()])
    cmd.extend(["--graph-format", fmt, "--output", str(out_path)])

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(
            f"exe_viewer headless graph export failed (exit {completed.returncode}): {stderr}"
        )
    if not out_path.is_file():
        raise RuntimeError(f"exe_viewer exited 0 but did not write {out_path}")
    return out_path


__all__ = [
    "build_dossier_flow_diagram",
    "export_exe_viewer_flow",
    "role_box_kind",
    "role_title",
    "to_dot",
    "to_mermaid",
    "to_standalone_svg",
]
