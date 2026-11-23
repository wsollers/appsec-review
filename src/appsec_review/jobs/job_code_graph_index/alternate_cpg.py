"""Universal multi-language Alternate CPG & inter-procedural CFG synthesis (T-169).

Synthesizes a deterministic Code Property Graph (``appsec-review/alternate-cpg/1``)
across all 9 target languages (``cpp``, ``java``, ``javascript``, ``python``,
``ruby``, ``go``, ``csharp``, ``rust``, ``php``) without Joern or SVF:

1. **Dual-seeded fusion**: merges Tree-sitter AST declarations, calls, and
   intra-procedural CFGs/guard dominators with CodeQL semantic graph facts
   (``call_site``, ``dataflow_path``, ``entry_point``, ``sink_site``, ``guard_fact``),
   CodeQL SARIF ``codeFlows``, C/C++ ``clangd`` symbol/call indices, target catalog
   declarations/symbol references, and framework/prioritization entrypoints.
2. **Syntactic fallback**: when CodeQL or ``clangd`` is absent or partial for a
   language, scope, or file, synthesizes inter-procedural ``CALLS``,
   ``ARG_TO_PARAM``, intra-procedural ``DEF_USE``, entrypoint links, and sink sites
   directly from Tree-sitter CFGs and symbol declarations, tagging every edge and
   path with ``resolution_tier``.
3. **Inter-procedural reachability & slicing**: provides deterministic cycle-safe
   path search (default ``max_hops = 10``, configurable 1..16) preserving
   intermediate ``guard_dominators`` along every hop, plus bounded backward and
   forward CPG program slicing.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import heapq
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from appsec_review.indexing.store import ShardSet, open_shard
from appsec_review.graph.correlate import _flow_groups
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.runtime.inputs import observe_output, observe_shard
from appsec_review.storage.shared import safe_path
from appsec_review.retrieval import INDEX_SCHEMA, IndexBuilder, IndexIdentity
from appsec_review.retrieval.model import (
    EntityKind,
    EntityRecord,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    SourceLocation,
    canonical_json,
    normalize_relative_path,
    sanitize_producer_data,
)
from appsec_review.storage import atomic_bytes, atomic_json, file_sha256

ALTERNATE_CPG_SCHEMA = "appsec-review/alternate-cpg/1"
ALTERNATE_CPG_SHARD_ID = "alternate-cpg"
MAX_PATH_STATES = 1024
MAX_PATH_FRONTIER = 1024
MAX_TRAVERSAL_EDGES = 16384

SUPPORTED_LANGUAGES: tuple[str, ...] = (
    "cpp",
    "java",
    "javascript",
    "python",
    "ruby",
    "go",
    "csharp",
    "rust",
    "php",
)

RESOLUTION_TIERS: tuple[str, ...] = (
    "codeql_semantic",
    "clangd_semantic",
    "hybrid_fused",
    "syntactic_fallback",
)
_TIER_RANK: dict[str, int] = {
    "hybrid_fused": 0,
    "codeql_semantic": 1,
    "clangd_semantic": 2,
    "syntactic_fallback": 3,
}

CPG_NODE_KINDS: tuple[str, ...] = (
    "function",
    "symbol",
    "cfg_block",
    "call_site",
    "entrypoint",
    "sink",
)

CPG_EDGE_KINDS: tuple[str, ...] = (
    "CALLS",
    "REFERENCES",
    "FLOWS_TO",
    "GUARDS",
    "DEF_USE",
    "ARG_TO_PARAM",
    "TAINT_STEP",
    "ENTRYPOINT_TO_FN",
    "FN_TO_SINK",
)

_LANG_ALIASES: dict[str, str] = {
    "c": "cpp",
    "c++": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
    "c/c++": "cpp",
    "objective-c": "cpp",
    "java": "java",
    "kotlin": "java",
    "java/kotlin": "java",
    "javascript": "javascript",
    "typescript": "javascript",
    "tsx": "javascript",
    "jsx": "javascript",
    "js": "javascript",
    "ts": "javascript",
    "javascript/typescript": "javascript",
    "python": "python",
    "py": "python",
    "ruby": "ruby",
    "rb": "ruby",
    "go": "go",
    "golang": "go",
    "csharp": "csharp",
    "c#": "csharp",
    "cs": "csharp",
    "rust": "rust",
    "rs": "rust",
    "php": "php",
}

_EXT_LANG: dict[str, str] = {
    ".c": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".kt": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".py": "python",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "csharp",
    ".rs": "rust",
    ".php": "php",
}

_SINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "command_injection",
        re.compile(
            r"(?:^|[.:>])(?:system|popen|execve|execvp|execl|execlp|execSync|spawnSync|"
            r"shell_exec|passthru|proc_open|capture3|Popen|Start|Command::new)$"
            r"|(?:Runtime\.getRuntime\(\)\.exec|os\.system|subprocess\.(?:run|call|Popen)|"
            r"Process\.Start|child_process\.(?:exec|execSync|spawn)|exec\.Command(?:Context)?)",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_injection",
        re.compile(
            r"(?:^|[.:>])(?:execute|executemany|executeQuery|executeUpdate|createNativeQuery|"
            r"ExecuteSqlRaw|FromSqlRaw|mysqli_query|pg_query|sql_query|QueryRow|Raw)$"
            r"|(?:\bdb\.(?:query|exec|raw)|cursor\.execute)",
            re.IGNORECASE,
        ),
    ),
    (
        "memory_safety",
        re.compile(
            r"(?:^|[.:>])(?:memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|vsprintf|"
            r"gets|copy_nonoverlapping|write_unaligned)$",
        ),
    ),
    (
        "deserialization",
        re.compile(
            r"(?:pickle\.loads|yaml\.(?:load|unsafe_load)|Marshal\.load|unserialize|"
            r"readObject|BinaryFormatter\.Deserialize|DeserializeObject|\beval\b)",
        ),
    ),
    (
        "path_traversal",
        re.compile(
            r"(?:^|[.:>])(?:fopen|readFile|readFileSync|writeFile|writeFileSync|"
            r"ReadAllText|ReadAllBytes|WriteAllText|read_to_string|file_get_contents|"
            r"file_put_contents|send_file)$|(?:os\.(?:Open|ReadFile|WriteFile)|File\.(?:Open|ReadAllText))",
        ),
    ),
    (
        "ssrf",
        re.compile(
            r"(?:requests\.(?:get|post|put|request)|urllib\.request\.urlopen|"
            r"http\.(?:Get|Post|Do)|HttpClient\.(?:GetAsync|PostAsync|SendAsync)|"
            r"axios\.(?:get|post|request)|curl_exec|\bfetch\b)",
        ),
    ),
    (
        "xss_or_template",
        re.compile(
            r"(?:render_template_string|mark_safe|Html\.Raw|dangerouslySetInnerHTML)",
        ),
    ),
)

_ENTRYPOINT_NAME_RE = re.compile(
    r"(?:^main$|^ServeHTTP$|^do(?:Get|Post|Put|Delete|Patch)$|"
    r"^(?:handle|on|serve|dispatch|process|route|api_|endpoint_)[A-Za-z0-9_]*|"
    r"[A-Za-z0-9_]*(?:Handler|Endpoint|Action|Controller|Route|View|Webhook)$)"
)
_ENTRYPOINT_PATH_RE = re.compile(
    r"(?:^|/)(?:routes?|controllers?|handlers?|views?|endpoints?|api|cmd|web|http|rpc|server)(?:/|_|\.|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AlternateCpgSettings:
    enabled: bool = True
    max_hops: int = 10
    max_precomputed_paths: int = 200
    max_slice_depth: int = 8

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> "AlternateCpgSettings":
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise ValueError("jobs.job_code_graph_index.settings.alternate_cpg must be a table")
        allowed = {"enabled", "max_hops", "max_precomputed_paths", "max_slice_depth"}
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ValueError(
                "jobs.job_code_graph_index.settings.alternate_cpg has unknown keys: "
                + ", ".join(unknown)
            )
        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("alternate_cpg.enabled must be a boolean")
        max_hops = raw.get("max_hops", 10)
        if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= 16:
            raise ValueError("alternate_cpg.max_hops must be an integer between 1 and 16")
        max_paths = raw.get("max_precomputed_paths", 200)
        if isinstance(max_paths, bool) or not isinstance(max_paths, int) or not 1 <= max_paths <= 2000:
            raise ValueError("alternate_cpg.max_precomputed_paths must be an integer between 1 and 2000")
        max_slice = raw.get("max_slice_depth", 8)
        if isinstance(max_slice, bool) or not isinstance(max_slice, int) or not 1 <= max_slice <= 16:
            raise ValueError("alternate_cpg.max_slice_depth must be an integer between 1 and 16")
        return cls(
            enabled=enabled,
            max_hops=max_hops,
            max_precomputed_paths=max_paths,
            max_slice_depth=max_slice,
        )


def _cpg_digest(prefix: str, payload: Mapping[str, Any]) -> str:
    return f"{prefix}:" + hashlib.sha256(canonical_json(payload)).hexdigest()[:24]


def _evidence(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else row
    evidence = {"identity": row.get("identity") or row.get("relation_id"), **{
        key: payload[key] for key in (
            "producer", "exact", "coverage_status", "cross_check", "admissibility", "scope",
            "kind", "signature", "qualified_name", "linkage", "translation_unit", "translation_unit_id",
            "source_identity", "build_unit_id", "project_id", "gaps",
            "query_identity", "rule_id", "scope_id", "translation_scope_id",
            "upstream", "authority",
        ) if key in payload}}
    if row.get("accepted_shard"):
        evidence["accepted_shard"] = dict(row["accepted_shard"])
    if isinstance(payload.get("result"), Mapping):
        evidence["result"] = {key: value for key, value in payload["result"].items()
                              if key in {"caller", "callee", "source", "sink", "argument_count", "in_loop"}}
    return evidence


def _producer(row: Mapping[str, Any]) -> str:
    value = _evidence(row).get("producer", {})
    name = value.get("name", "") if isinstance(value, Mapping) else str(value)
    return "codeql" if name == "codeql-export" else name or "unattributed"


def _exact_evidence(evidence: Mapping[str, Any]) -> bool:
    admission = evidence.get("admissibility", {})
    return (evidence.get("exact") is True
            and evidence.get("coverage_status", "complete") == "complete"
            and (evidence.get("cross_check") or {}).get("state", "not_covered") in {"agree", "not_covered"}
            and admission.get("direct_eligible", True) is True)


def _source_location(location: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(location)
    if "producer_location_json" in result:
        result["producer_location"] = json.loads(result.pop("producer_location_json") or "{}")
    result["ambiguous"] = bool(result.get("ambiguous", False))
    return result


def _located_entities(shards: ShardSet, *, kinds: Sequence[str] = ()) -> Iterable[dict[str, Any]]:
    """Keep the original location provenance omitted by the generic row projection."""
    for shard in shards.shards:
        sql = ("SELECT l.entity_id, l.target_snapshot, l.producer_location_json FROM locations l "
               "JOIN entities e ON e.identity=l.entity_id")
        if kinds:
            sql += " WHERE e.kind IN (" + ",".join("?" for _ in kinds) + ")"
        with open_shard(shards.run_root, shard) as database:
            native = {row["entity_id"]: {
                "target_snapshot": row["target_snapshot"],
                "producer_location": json.loads(row["producer_location_json"]),
            } for row in database.execute(sql, tuple(kinds))}
        for row in shards.entities((shard,), kinds=kinds):
            if row["location"] is not None:
                row["location"].update(native[row["identity"]])
            row["accepted_shard"] = {"name": shard["name"], "shard_id": shard.get("shard_id", "default"),
                                     "sha256": shard["sha256"]}
            yield row


def _relations_with_provenance(shards: ShardSet) -> Iterable[dict[str, Any]]:
    for shard in shards.shards:
        with open_shard(shards.run_root, shard) as database:
            for record in database.execute(
                "SELECT relation_id, kind, source_id, target_id, exact, confidence, ambiguity, payload_json "
                "FROM relations ORDER BY relation_id"
            ):
                row = dict(record)
                row["payload"] = json.loads(row.pop("payload_json"))
                row["exact"] = bool(row["exact"])
                row["accepted_shard"] = {"name": shard["name"], "shard_id": shard.get("shard_id", "default"),
                                         "sha256": shard["sha256"]}
                yield row


def _cfg_location(record: Mapping[str, Any], snapshot: str) -> dict[str, Any] | None:
    if not re.fullmatch(r"[0-9a-f]{64}", str(record.get("file_sha256") or "")):
        return None
    return {
        "target_snapshot": snapshot, "path": record["path"], "file_sha256": record["file_sha256"],
        "start_byte": int(record.get("start_byte") or 0), "end_byte": int(record.get("end_byte") or 0),
        "start_line": int(record.get("start_line") or 1), "end_line": int(record.get("end_line") or 1),
        "start_column": 1, "end_column": 1, "confidence": 0.75, "ambiguous": True,
        "mapping_method": "tree-sitter-cfg-byte-span-columns-unavailable",
        "producer_location": {**dict(record.get("producer_location") or {}),
                              "source_identity": record.get("source_identity"),
                              "function_id": record.get("function_id"), "ast_identity": record.get("ast_identity")},
    }


def _safe_rel_path(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        return "unknown"
    cleaned = raw.strip().replace("\\", "/").lstrip("/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    try:
        return normalize_relative_path(cleaned)
    except ValueError:
        parts = [p for p in cleaned.split("/") if p not in {"", ".", ".."}]
        return "/".join(parts) if parts else "unknown"


def canonical_cpg_language(language: Any, path: str = "") -> str:
    text = str(language or "").strip().lower()
    if text in _LANG_ALIASES:
        return _LANG_ALIASES[text]
    if path and path != "unknown":
        suffix = Path(path).suffix.lower()
        if suffix in _EXT_LANG:
            return _EXT_LANG[suffix]
    return "unknown"


def _simple_symbol(name: Any) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    if "(" in raw:
        raw = raw.split("(", 1)[0].strip()
    for sep in ("::", "->", ".", "/", "\\"):
        if sep in raw:
            raw = raw.rsplit(sep, 1)[-1].strip()
    return raw.lstrip("*&!")


def classify_syntactic_sink(callee_name: str, language: str = "") -> str | None:
    text = str(callee_name or "").strip()
    if not text:
        return None
    for sink_class, pattern in _SINK_PATTERNS:
        if pattern.search(text):
            return sink_class
    simple = _simple_symbol(text)
    if language == "python" and simple in {"open", "eval", "exec"}:
        return "path_traversal" if simple == "open" else "command_injection"
    if language == "php" and simple in {"eval", "include", "require", "include_once", "require_once"}:
        return "command_injection" if simple == "eval" else "path_traversal"
    return None


def is_syntactic_entrypoint(
    name: str,
    qualified_name: str = "",
    path: str = "",
    decorators_or_text: str = "",
) -> bool:
    simple = _simple_symbol(name)
    if not simple:
        return False
    if _ENTRYPOINT_NAME_RE.search(simple):
        return True
    if qualified_name and _ENTRYPOINT_NAME_RE.search(qualified_name):
        return True
    if decorators_or_text and re.search(
        r"(?:@(?:app|router|bp|blueprint|GetMapping|PostMapping|PutMapping|DeleteMapping|"
        r"RequestMapping|RestController|Controller|api_view)|"
        r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|Route|ApiController)\]|"
        r"#\[(?:get|post|put|delete|route)\b|Route::(?:get|post|put|delete|any))",
        decorators_or_text,
    ):
        return True
    if path and _ENTRYPOINT_PATH_RE.search(path) and not simple.startswith("_"):
        if re.search(
            r"(?:^(?:get|post|put|delete|patch|index|show|create|update|destroy|list|search|login|logout|register|upload|download|webhook|callback|dispatch|process|serve)(?:_|$|[A-Z]))",
            simple,
        ):
            return True
    return False


def _merge_tier(producers: Iterable[str]) -> str:
    pset = set(producers)
    has_codeql = "codeql" in pset
    has_clangd = "clangd" in pset
    has_ts = "tree_sitter" in pset or "syntactic" in pset
    if (has_codeql or has_clangd) and (has_ts or (has_codeql and has_clangd)):
        return "hybrid_fused"
    if has_codeql:
        return "codeql_semantic"
    if has_clangd:
        return "clangd_semantic"
    return "syntactic_fallback"


def _combine_path_tiers(tiers: Iterable[str]) -> str:
    tset = {t for t in tiers if t in _TIER_RANK}
    if not tset:
        return "syntactic_fallback"
    if len(tset) == 1:
        return next(iter(tset))
    return "hybrid_fused"


def _clean_guard_dom(dom: Mapping[str, Any], default_path: str = "", fn_name: str = "") -> dict[str, Any]:
    branch = str(dom.get("branch") or dom.get("branch_arm") or "true_branch")
    if branch == "true":
        branch = "true_branch"
    elif branch == "false":
        branch = "false_branch"
    elif branch not in {"true_branch", "false_branch", "guards"}:
        branch = "guards"
    polarity = str(dom.get("guard_polarity") or "general_condition")
    if polarity not in {
        "null_check",
        "bounds_check",
        "auth_or_role_check",
        "error_return_guard",
        "sanitization_guard",
        "general_condition",
    }:
        polarity = "general_condition"
    out: dict[str, Any] = {
        "node_id": str(dom.get("node_id") or dom.get("branch_node_id") or "guard"),
        "branch": branch,
        "guard_expression": str(dom.get("guard_expression") or "")[:240],
        "guard_polarity": polarity,
    }
    path_val = dom.get("path") or dom.get("file_path") or default_path
    if isinstance(path_val, str) and path_val and path_val != "unknown":
        out["path"] = _safe_rel_path(path_val)
    line_val = dom.get("line") if isinstance(dom.get("line"), int) else dom.get("start_line")
    if isinstance(line_val, int) and line_val >= 1:
        out["line"] = line_val
    fn_val = dom.get("function_name") or fn_name
    if isinstance(fn_val, str) and fn_val:
        out["function_name"] = fn_val
    return out


def _build_intra_def_use_edges(
    fn_node: Mapping[str, Any],
    blocks: Sequence[Mapping[str, Any]],
    cfg_edges: Sequence[Mapping[str, Any]],
    tier: str,
    producers: Sequence[str],
) -> list[dict[str, Any]]:
    """Synthesize intra-procedural DEF_USE edges along forward CFG reachability."""
    if not blocks:
        return []
    by_id = {str(b["node_id"]): b for b in blocks}
    adj: dict[str, list[str]] = defaultdict(list)
    for edge in cfg_edges:
        src = str(edge.get("source_id") or "")
        dst = str(edge.get("target_id") or "")
        if src in by_id and dst in by_id:
            adj[src].append(dst)
    for src in adj:
        adj[src] = sorted(set(adj[src]))

    entry_blocks = [str(b["node_id"]) for b in blocks if b.get("block_kind") == "entry"]
    entry_id = entry_blocks[0] if entry_blocks else str(blocks[0]["node_id"])
    params = [str(p) for p in fn_node.get("parameters", ()) if str(p)]

    def_sources: list[tuple[str, str]] = []
    seen_defs: set[tuple[str, str]] = set()
    for param in params:
        if (entry_id, param) not in seen_defs:
            seen_defs.add((entry_id, param))
            def_sources.append((entry_id, param))
    for blk in blocks:
        bid = str(blk["node_id"])
        for var in blk.get("defs", ()):
            vname = str(var)
            if vname and (bid, vname) not in seen_defs:
                seen_defs.add((bid, vname))
                def_sources.append((bid, vname))

    out: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for def_bid, var in def_sources:
        queue: deque[str] = deque(adj.get(def_bid, ()))
        visited: set[str] = set()
        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)
            cblk = by_id[curr]
            uses = {str(u) for u in cblk.get("uses", ())}
            defs = {str(d) for d in cblk.get("defs", ())}
            if var in uses and (def_bid, curr, var) not in seen_edges:
                seen_edges.add((def_bid, curr, var))
                edge_id = _cpg_digest(
                    "cpg:edge",
                    {"kind": "DEF_USE", "src": def_bid, "dst": curr, "var": var},
                )
                out.append(
                    {
                        "schema": ALTERNATE_CPG_SCHEMA,
                        "record_type": "cpg_edge",
                        "edge_id": edge_id,
                        "edge_kind": "DEF_USE",
                        "edge_subtype": "intra_def_use",
                        "source_id": def_bid,
                        "target_id": curr,
                        "language": fn_node["language"],
                        "path": fn_node["path"],
                        "line": int(cblk.get("start_line") or fn_node["start_line"]),
                        "variable": var,
                        "callee_name": None,
                        "resolution_tier": tier,
                        "guard_dominators": list(cblk.get("guard_dominators", ())),
                        "producers": list(producers),
                    }
                )
            if var in defs and curr != def_bid:
                continue
            for nxt in adj.get(curr, ()):
                if nxt not in visited:
                    queue.append(nxt)
    return out


def synthesize_alternate_cpg(
    *,
    tree_sitter_files: Sequence[Mapping[str, Any]] = (),
    codeql_facts: Sequence[Mapping[str, Any]] = (),
    codeql_relations: Sequence[Mapping[str, Any]] = (),
    sarif_observations: Sequence[Mapping[str, Any]] = (),
    clangd_symbols: Sequence[Mapping[str, Any]] = (),
    clangd_relations: Sequence[Mapping[str, Any]] = (),
    symbol_declarations: Sequence[Mapping[str, Any]] = (),
    symbol_references: Sequence[Mapping[str, Any]] = (),
    route_entrypoints: Sequence[Mapping[str, Any]] = (),
    run_id: str = "offline",
    target_snapshot: str = "0" * 64,
    settings: AlternateCpgSettings | None = None,
) -> dict[str, Any]:
    """Build the universal Alternate CPG across all 9 target languages."""
    cfg = settings or AlternateCpgSettings()
    if not cfg.enabled:
        return {
            "schema": ALTERNATE_CPG_SCHEMA, "run_id": run_id, "target_snapshot": target_snapshot,
            "max_hops": cfg.max_hops, "max_slice_depth": cfg.max_slice_depth,
            "settings": asdict(cfg),
            "nodes": [], "edges": [], "paths": [], "languages": [], "resolution_breakdown": {},
            "counts": {key: 0 for key in ("alternate_cpg_nodes", "alternate_cpg_edges", "semantic_edges_count",
                                        "syntactic_fallback_edges_count", "entrypoints_linked",
                                        "reachable_sink_paths_precomputed")},
            "gaps": ["alternate_cpg_disabled: disabled by configuration"],
        }
    gaps: list[str] = []
    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges_by_id: dict[str, dict[str, Any]] = {}

    fns_by_path_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    fns_by_lang_qname: dict[tuple[str, str], list[str]] = defaultdict(list)
    fns_by_lang_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    fns_by_name: dict[str, list[str]] = defaultdict(list)
    external_id_to_fn: dict[str, str] = {}
    fn_blocks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fn_entry_block: dict[str, str] = {}

    def _register_function(
        *,
        name: str,
        qualified_name: str,
        path: str,
        start_line: int,
        end_line: int,
        language: str,
        producer: str,
        parameters: Sequence[str] = (),
        external_id: str | None = None,
        decorators_text: str = "",
        location: Mapping[str, Any] | None = None,
        evidence: Mapping[str, Any] | None = None,
        node_kind: str = "function",
    ) -> str:
        norm_path = _safe_rel_path(path)
        lang = canonical_cpg_language(language, norm_path)
        simple = _simple_symbol(name) or str(name or "anonymous")
        qname = str(qualified_name or simple)
        s_line = max(1, int(start_line or 1))
        e_line = max(s_line, int(end_line or s_line))

        for existing_id in fns_by_path_name.get((norm_path, simple), ()):
            existing = nodes_by_id[existing_id]
            ex_s, ex_e = int(existing["start_line"]), int(existing["end_line"])
            same_external = external_id and external_id_to_fn.get(external_id) == existing_id
            same_span = (location and existing.get("location") and
                         all(location.get(key) == existing["location"].get(key)
                             for key in ("file_sha256", "start_byte", "end_byte", "start_column", "end_column")))
            same_qualifiers = not evidence or not existing.get("evidence") or all(
                evidence.get(key) == existing["evidence"][0].get(key)
                for key in ("signature", "linkage", "translation_unit", "translation_unit_id", "scope", "build_unit_id"))
            if same_external or (
                node_kind == existing["node_kind"] and qname == existing["qualified_name"]
                and ex_s == s_line and ex_e == e_line and same_qualifiers
                and (same_span or (not location and not existing.get("location")))
                and (not external_id or not existing.get("evidence") or
                     existing["evidence"][0].get("identity") in (None, external_id))
            ):
                if producer not in existing["producers"]:
                    existing["producers"] = sorted({*existing["producers"], producer})
                existing["resolution_tier"] = _merge_tier(existing["producers"])
                existing["start_line"] = min(ex_s, s_line)
                existing["end_line"] = max(ex_e, e_line)
                if parameters and not existing["parameters"]:
                    existing["parameters"] = [str(p) for p in parameters if str(p)]
                if qname and existing["qualified_name"] == existing["name"] and qname != simple:
                    existing["qualified_name"] = qname
                    if existing_id not in fns_by_lang_qname[(lang, qname)]:
                        fns_by_lang_qname[(lang, qname)].append(existing_id)
                if is_syntactic_entrypoint(simple, qname, norm_path, decorators_text):
                    existing["is_entrypoint"] = True
                    if "syntactic_entrypoint" not in existing["entrypoint_sources"]:
                        existing["entrypoint_sources"] = sorted(
                            {*existing["entrypoint_sources"], "syntactic_entrypoint"}
                        )
                if external_id:
                    external_id_to_fn[external_id] = existing_id
                if evidence and dict(evidence) not in existing["evidence"]:
                    existing["evidence"].append(dict(evidence))
                return existing_id

        fn_id = _cpg_digest(
            "cpg:fn",
            {"path": norm_path, "qualified_name": qname, "start_line": s_line, "end_line": e_line,
             "lang": lang, "location": location, "evidence": evidence, "kind": node_kind},
        )
        if fn_id in nodes_by_id:
            existing = nodes_by_id[fn_id]
            existing["producers"] = sorted({*existing["producers"], producer})
            existing["resolution_tier"] = _merge_tier(existing["producers"])
            if external_id:
                external_id_to_fn[external_id] = fn_id
            return fn_id

        ep_flag = node_kind == "function" and is_syntactic_entrypoint(simple, qname, norm_path, decorators_text)
        node = {
            "schema": ALTERNATE_CPG_SCHEMA,
            "record_type": "cpg_node",
            "node_id": fn_id,
            "node_kind": node_kind,
            "name": simple,
            "qualified_name": qname,
            "language": lang,
            "path": norm_path,
            "start_line": s_line,
            "end_line": e_line,
            "function_id": fn_id if node_kind == "function" else None,
            "block_kind": None,
            "guard_expression": None,
            "guard_polarity": None,
            "guard_dominators": [],
            "parameters": [str(p) for p in parameters if str(p)],
            "calls": [],
            "defs": [str(p) for p in parameters if str(p)],
            "uses": [],
            "is_entrypoint": ep_flag,
            "entrypoint_sources": ["syntactic_entrypoint"] if ep_flag else [],
            "sink_class": None,
            "resolution_tier": _merge_tier([producer]),
            "producers": [producer],
            "location": dict(location) if location else None,
            "evidence": [dict(evidence)] if evidence else [],
        }
        nodes_by_id[fn_id] = node
        if node_kind == "function":
            fns_by_path_name[(norm_path, simple)].append(fn_id)
            fns_by_lang_qname[(lang, qname)].append(fn_id)
            fns_by_lang_name[(lang, simple)].append(fn_id)
            fns_by_name[simple].append(fn_id)
        if external_id:
            external_id_to_fn[external_id] = fn_id
        return fn_id

    def _add_edge(
        *,
        edge_kind: str,
        source_id: str,
        target_id: str,
        language: str,
        producer: str,
        edge_subtype: str | None = None,
        path: str | None = None,
        line: int | None = None,
        variable: str | None = None,
        callee_name: str | None = None,
        guard_dominators: Sequence[Mapping[str, Any]] = (),
        location: Mapping[str, Any] | None = None,
        occurrence: str | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> str:
        key_payload: dict[str, Any] = {
            "kind": edge_kind,
            "subtype": edge_subtype or "",
            "src": source_id,
            "dst": target_id,
            "var": variable or "",
            "line": int(line or 0),
            "path": path, "location": location, "occurrence": occurrence,
        }
        edge_id = _cpg_digest("cpg:edge", key_payload)
        cleaned_doms = [
            _clean_guard_dom(d, default_path=path or "")
            for d in guard_dominators
            if isinstance(d, Mapping)
        ]
        if edge_id in edges_by_id:
            existing = edges_by_id[edge_id]
            existing["producers"] = sorted({*existing["producers"], producer})
            existing["resolution_tier"] = _merge_tier(existing["producers"])
            if evidence and dict(evidence) not in existing["evidence"]:
                existing["evidence"].append(dict(evidence))
            existing["exact"] = edge_kind in {"CALLS", "REFERENCES"} and bool(existing["evidence"]) and all(
                _exact_evidence(e) for e in existing["evidence"])
            if cleaned_doms:
                seen_g = {(g["node_id"], g["branch"]) for g in existing["guard_dominators"]}
                for dom in cleaned_doms:
                    if (dom["node_id"], dom["branch"]) not in seen_g:
                        seen_g.add((dom["node_id"], dom["branch"]))
                        existing["guard_dominators"].append(dom)
            return edge_id
        norm_p = _safe_rel_path(path) if path else None
        if norm_p == "unknown":
            norm_p = None
        edges_by_id[edge_id] = {
            "schema": ALTERNATE_CPG_SCHEMA,
            "record_type": "cpg_edge",
            "edge_id": edge_id,
            "edge_kind": edge_kind,
            "edge_subtype": edge_subtype,
            "source_id": source_id,
            "target_id": target_id,
            "language": canonical_cpg_language(language, norm_p or ""),
            "path": norm_p,
            "line": int(line) if isinstance(line, int) and line >= 1 else None,
            "variable": variable,
            "callee_name": callee_name,
            "resolution_tier": _merge_tier([producer]),
            "guard_dominators": cleaned_doms,
            "producers": [producer],
            "location": dict(location) if location else None,
            "occurrence": occurrence,
            "evidence": [dict(evidence)] if evidence else [],
            "exact": edge_kind in {"CALLS", "REFERENCES"} and bool(evidence) and _exact_evidence(evidence),
        }
        return edge_id

    ts_cfg_node_map: dict[str, str] = {}
    pending_ts_calls: list[dict[str, Any]] = []
    for ts_file in tree_sitter_files:
        if hasattr(ts_file, "functions") and hasattr(ts_file, "path") and not isinstance(ts_file, Mapping):
            ts_file = {
                "path": getattr(ts_file, "path", "unknown"),
                "language": getattr(ts_file, "language", "unknown"),
                "functions": [
                    {
                        "function_id": fn.function_id,
                        "name": fn.function_name,
                        "qualified_name": fn.qualified_name,
                        "start_line": fn.start_line,
                        "end_line": fn.end_line,
                        "parameters": list(fn.parameters),
                        "location": _cfg_location(fn.to_summary(), target_snapshot),
                        "evidence": {"producer": "tree_sitter", "identity": fn.function_id,
                                     "source_identity": fn.source_identity},
                    }
                    for fn in getattr(ts_file, "functions", ())
                ],
                "cfg_nodes": [n.to_jsonl_record() for fn in getattr(ts_file, "functions", ()) for n in getattr(fn, "nodes", ())],
                "cfg_edges": [e.to_jsonl_record() for fn in getattr(ts_file, "functions", ()) for e in getattr(fn, "edges", ())],
            }
        fpath = _safe_rel_path(ts_file.get("path"))
        flang = canonical_cpg_language(ts_file.get("language"), fpath)
        ts_fn_to_cpg: dict[str, str] = {}
        route_lines = {
            int(rc["start_line"])
            for rc in ts_file.get("route_candidates", ())
            if isinstance(rc, Mapping) and isinstance(rc.get("start_line"), int)
        }
        for fn in ts_file.get("functions", ()):
            if not isinstance(fn, Mapping):
                continue
            s_line = int(fn.get("start_line") or 1)
            e_line = int(fn.get("end_line") or s_line)
            dec_text = str(fn.get("decorators") or fn.get("signature") or "")
            if any(s_line - 3 <= rl <= e_line for rl in route_lines):
                dec_text = dec_text + " @app.route"
            cpg_fn_id = _register_function(
                name=str(fn.get("name") or "anonymous"),
                qualified_name=str(fn.get("qualified_name") or fn.get("name") or "anonymous"),
                path=fpath,
                start_line=s_line,
                end_line=e_line,
                language=flang,
                producer="tree_sitter",
                parameters=[str(p) for p in fn.get("parameters", ()) if str(p)],
                external_id=str(fn.get("function_id")) if fn.get("function_id") else None,
                decorators_text=dec_text,
                location=fn.get("location"),
                evidence=fn.get("evidence"),
            )
            if fn.get("function_id"):
                ts_fn_to_cpg[str(fn["function_id"])] = cpg_fn_id

        raw_nodes = [n for n in ts_file.get("cfg_nodes", ()) if isinstance(n, Mapping)]
        raw_edges = [e for e in ts_file.get("cfg_edges", ()) if isinstance(e, Mapping)]
        blocks_by_fn: dict[str, list[dict[str, Any]]] = defaultdict(list)
        edges_by_fn: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for raw_n in raw_nodes:
            orig_fn_id = str(raw_n.get("function_id") or "")
            cpg_fn_id = ts_fn_to_cpg.get(orig_fn_id) or _register_function(
                name=str(raw_n.get("function_name") or "anonymous"),
                qualified_name=str(raw_n.get("function_name") or "anonymous"),
                path=fpath,
                start_line=int(raw_n.get("start_line") or 1),
                end_line=int(raw_n.get("end_line") or raw_n.get("start_line") or 1),
                language=flang,
                producer="tree_sitter",
            )
            if orig_fn_id:
                ts_fn_to_cpg[orig_fn_id] = cpg_fn_id
            orig_nid = str(raw_n.get("node_id") or "")
            cpg_nid = _cpg_digest(
                "cpg:blk",
                {"fn": cpg_fn_id, "orig": orig_nid, "line": int(raw_n.get("start_line") or 1)},
            )
            ts_cfg_node_map[orig_nid] = cpg_nid
            fn_obj = nodes_by_id[cpg_fn_id]
            doms = [
                _clean_guard_dom(
                    {
                        **d,
                        "node_id": ts_cfg_node_map.get(
                            str(d.get("node_id") or d.get("branch_node_id") or ""),
                            str(d.get("node_id") or d.get("branch_node_id") or "guard"),
                        ),
                    },
                    default_path=fpath,
                    fn_name=fn_obj["name"],
                )
                for d in raw_n.get("guard_dominators", ())
                if isinstance(d, Mapping)
            ]
            calls_list = [str(c) for c in raw_n.get("calls", ()) if str(c)]
            defs_list = [str(d) for d in raw_n.get("defs", ()) if str(d)]
            uses_list = [str(u) for u in raw_n.get("uses", ()) if str(u)]
            raw_bkind = str(raw_n.get("block_kind") or raw_n.get("kind") or "statement")
            sline_b = max(1, int(raw_n.get("start_line") or fn_obj["start_line"]))
            eline_b = max(sline_b, int(raw_n.get("end_line") or sline_b))
            fn_obj["end_line"] = max(int(fn_obj["end_line"]), eline_b)
            if raw_bkind == "entry" and defs_list and not fn_obj["parameters"]:
                fn_obj["parameters"] = list(defs_list)
            blk_node = {
                "schema": ALTERNATE_CPG_SCHEMA,
                "record_type": "cpg_node",
                "node_id": cpg_nid,
                "node_kind": "cfg_block",
                "name": str(raw_n.get("statement_type") or raw_n.get("ast_type") or raw_bkind or "block"),
                "qualified_name": f"{fn_obj['qualified_name']}::{raw_bkind or 'stmt'}@{sline_b}",
                "language": flang,
                "path": fpath,
                "start_line": sline_b,
                "end_line": eline_b,
                "function_id": cpg_fn_id,
                "block_kind": raw_bkind,
                "guard_expression": raw_n.get("guard_expression"),
                "guard_polarity": raw_n.get("guard_polarity"),
                "guard_dominators": doms,
                "parameters": [],
                "calls": calls_list,
                "defs": defs_list,
                "uses": uses_list,
                "is_entrypoint": False,
                "entrypoint_sources": [],
                "sink_class": None,
                "resolution_tier": "syntactic_fallback",
                "producers": ["tree_sitter"],
                "location": _cfg_location(raw_n, target_snapshot),
            }
            nodes_by_id[cpg_nid] = blk_node
            fn_blocks[cpg_fn_id].append(blk_node)
            blocks_by_fn[cpg_fn_id].append(blk_node)
            if blk_node["block_kind"] == "entry" and cpg_fn_id not in fn_entry_block:
                fn_entry_block[cpg_fn_id] = cpg_nid
            fn_obj["calls"] = sorted({*fn_obj["calls"], *calls_list})
            fn_obj["uses"] = sorted({*fn_obj["uses"], *uses_list})
            fn_obj["defs"] = sorted({*fn_obj["defs"], *defs_list})
            for callee in calls_list:
                pending_ts_calls.append(
                    {
                        "caller_fn_id": cpg_fn_id,
                        "block_id": cpg_nid,
                        "callee_name": callee,
                        "path": fpath,
                        "line": sline_b,
                        "language": flang,
                        "guard_dominators": doms,
                        "uses": uses_list,
                        "location": _cfg_location(raw_n, target_snapshot),
                    }
                )

        for cpg_fn_id, blks in blocks_by_fn.items():
            for blk in blks:
                for dom in blk["guard_dominators"]:
                    if dom["node_id"] in ts_cfg_node_map:
                        dom["node_id"] = ts_cfg_node_map[dom["node_id"]]
                    if dom["node_id"] in nodes_by_id and dom["node_id"] != blk["node_id"]:
                        _add_edge(
                            edge_kind="GUARDS",
                            source_id=dom["node_id"],
                            target_id=blk["node_id"],
                            language=flang,
                            producer="tree_sitter",
                            edge_subtype=dom["branch"],
                            path=fpath,
                            line=dom.get("line") or blk["start_line"],
                            guard_dominators=[dom],
                        )

        for raw_e in raw_edges:
            src_cpg = ts_cfg_node_map.get(str(raw_e.get("source_id") or raw_e.get("source_node_id") or ""))
            dst_cpg = ts_cfg_node_map.get(str(raw_e.get("target_id") or raw_e.get("target_node_id") or ""))
            if not src_cpg or not dst_cpg:
                continue
            ekind = str(raw_e.get("edge_kind") or "unconditional")
            _add_edge(
                edge_kind="FLOWS_TO",
                source_id=src_cpg,
                target_id=dst_cpg,
                language=flang,
                producer="tree_sitter",
                edge_subtype=ekind,
                path=fpath,
                line=nodes_by_id[src_cpg]["start_line"],
            )
            cpg_fn_id = nodes_by_id[src_cpg]["function_id"]
            if cpg_fn_id:
                edges_by_fn[cpg_fn_id].append(
                    {"source_id": src_cpg, "target_id": dst_cpg, "edge_kind": ekind}
                )

        for cpg_fn_id, blks in blocks_by_fn.items():
            fn_obj = nodes_by_id[cpg_fn_id]
            for du_edge in _build_intra_def_use_edges(
                fn_obj, blks, edges_by_fn.get(cpg_fn_id, ()), "syntactic_fallback", ("tree_sitter",)
            ):
                edges_by_id[du_edge["edge_id"]] = du_edge

        if not raw_nodes:
            for call_rec in ts_file.get("calls", ()):
                if not isinstance(call_rec, Mapping):
                    continue
                cline = int(call_rec.get("start_line") or call_rec.get("line") or 1)
                cname = str(call_rec.get("name") or call_rec.get("callee") or "")
                if not cname:
                    continue
                for fid, fn_n in nodes_by_id.items():
                    if fn_n["node_kind"] == "function" and fn_n["path"] == fpath and fn_n["start_line"] <= cline <= fn_n["end_line"]:
                        pending_ts_calls.append(
                            {
                                "caller_fn_id": fid,
                                "block_id": None,
                                "callee_name": cname,
                                "path": fpath,
                                "line": cline,
                                "language": flang,
                                "guard_dominators": [],
                                "uses": [],
                                "location": call_rec.get("location"),
                                "occurrence": call_rec.get("identity"),
                            }
                        )
                        break

    for sym in symbol_declarations:
        if not isinstance(sym, Mapping):
            continue
        payload = sym.get("payload") if isinstance(sym.get("payload"), Mapping) else sym
        skind = str(payload.get("symbol_kind") or payload.get("kind") or "function").lower()
        if skind not in {"function", "method", "constructor", "procedure", "func", "def", "fn", "symbol"}:
            continue
        loc = sym.get("location") if isinstance(sym.get("location"), Mapping) else payload
        spath = _safe_rel_path(loc.get("path") or sym.get("path"))
        sname = str(sym.get("name") or payload.get("name") or "")
        if spath == "unknown" or not sname:
            continue
        sline = int(loc.get("start_line") or sym.get("start_line") or 1)
        eline = int(loc.get("end_line") or sym.get("end_line") or sline)
        _register_function(
            name=sname,
            qualified_name=str(payload.get("qualified_name") or sname),
            path=spath,
            start_line=sline,
            end_line=eline,
            language=str(payload.get("language") or sym.get("language") or ""),
            producer="syntactic",
            external_id=str(sym.get("identity")) if sym.get("identity") else None,
            location=loc if loc.get("file_sha256") else None,
            evidence=_evidence(sym),
        )

    def _enclosing_fn_and_guards(path: str, line: int) -> tuple[str | None, list[dict[str, Any]], str | None]:
        norm_p = _safe_rel_path(path)
        best_fn: str | None = None
        best_span = 10**9
        tied_functions = False
        for fid, node in nodes_by_id.items():
            if node["node_kind"] != "function" or node["path"] != norm_p:
                continue
            if node["start_line"] <= line <= node["end_line"]:
                span = node["end_line"] - node["start_line"]
                if span < best_span:
                    best_span = span
                    best_fn = fid
                    tied_functions = False
                elif span == best_span:
                    tied_functions = True
        if best_fn is None:
            return None, [], None
        if tied_functions:
            gaps.append(f"ambiguous_enclosing_function: {norm_p}:{line}")
            return None, [], None
        best_blk: dict[str, Any] | None = None
        best_blk_span = 10**9
        tied_blocks = False
        for blk in fn_blocks.get(best_fn, ()):
            if blk["start_line"] <= line <= blk["end_line"]:
                bspan = blk["end_line"] - blk["start_line"]
                if bspan < best_blk_span:
                    best_blk_span = bspan
                    best_blk = blk
                    tied_blocks = False
                elif bspan == best_blk_span:
                    tied_blocks = True
        if best_blk is not None and not tied_blocks:
            return best_fn, list(best_blk.get("guard_dominators", ())), best_blk["node_id"]
        if tied_blocks:
            gaps.append(f"ambiguous_guard_context: {norm_p}:{line}")
        return best_fn, [], None

    for csym in clangd_symbols:
        if not isinstance(csym, Mapping):
            continue
        payload = csym.get("payload") if isinstance(csym.get("payload"), Mapping) else csym
        loc = csym.get("location") if isinstance(csym.get("location"), Mapping) else payload
        cpath = _safe_rel_path(loc.get("path") or csym.get("path"))
        cname = str(csym.get("name") or payload.get("name") or "")
        if cpath == "unknown" or not cname:
            continue
        sline = int(loc.get("start_line") or csym.get("start_line") or 1)
        eline = int(loc.get("end_line") or csym.get("end_line") or sline)
        _register_function(
            name=cname,
            qualified_name=str(payload.get("qualified_name") or cname),
            path=cpath,
            start_line=sline,
            end_line=eline,
            language="cpp",
            producer="clangd",
            external_id=str(csym.get("identity") or csym.get("symbol_id") or ""),
            location=loc if loc.get("file_sha256") else None,
            evidence=_evidence(csym),
            node_kind="function" if str(payload.get("kind") or "").lower() in {
                "function", "method", "staticmethod", "instancemethod", "classmethod", "constructor",
                "destructor", "conversionfunction",
            } else "symbol",
        )

    semantic_call_pairs: set[tuple[str, str]] = set()
    for crel in clangd_relations:
        if not isinstance(crel, Mapping) or str(crel.get("kind") or "") not in {"CALLS", "REFERENCES"}:
            continue
        src_fn = external_id_to_fn.get(str(crel.get("source_id") or ""))
        dst_fn = external_id_to_fn.get(str(crel.get("target_id") or ""))
        if src_fn and dst_fn:
            rpayload = crel.get("payload") if isinstance(crel.get("payload"), Mapping) else {}
            kind = str(crel["kind"])
            if kind == "CALLS" and any(nodes_by_id[n]["node_kind"] != "function" for n in (src_fn, dst_fn)):
                gaps.append(f"clangd_noncallable_target: {crel.get('relation_id')}")
                kind = "REFERENCES"
            locations = list(rpayload.get("locations") or ())
            if not locations and rpayload.get("line"):
                locations = [{"path": nodes_by_id[src_fn]["path"], "line": rpayload["line"]}]
            if int(rpayload.get("occurrences") or len(locations)) > len(locations) or not locations:
                gaps.append(f"clangd_occurrences_unavailable: {crel.get('relation_id')}")
            for index, occurrence_loc in enumerate(locations or [None]):
                cline = int(occurrence_loc.get("line") or 0) if occurrence_loc else None
                cpath = str(occurrence_loc.get("path") or nodes_by_id[src_fn]["path"]) if occurrence_loc else None
                _add_edge(
                    edge_kind=kind, source_id=src_fn, target_id=dst_fn, language="cpp", producer="clangd",
                    edge_subtype="clangd_call" if kind == "CALLS" else "clangd_reference",
                    path=cpath, line=cline, callee_name=nodes_by_id[dst_fn]["name"],
                    location=occurrence_loc, occurrence=f"{crel.get('relation_id')}:{index}",
                    evidence={**_evidence(crel), "exact": bool(crel.get("exact")) and bool(occurrence_loc),
                              "ambiguity": crel.get("ambiguity")},
                )
            if kind == "CALLS":
                semantic_call_pairs.add((src_fn, dst_fn))

    codeql_entity_by_id: dict[str, Mapping[str, Any]] = {}
    for fact in codeql_facts:
        if not isinstance(fact, Mapping):
            continue
        fid = str(fact.get("identity") or fact.get("fact_id") or "")
        if fid:
            codeql_entity_by_id[fid] = fact
        if str(fact.get("kind") or fact.get("family") or "") != "symbol":
            continue
        payload = fact.get("payload") if isinstance(fact.get("payload"), Mapping) else fact
        loc = fact.get("location") if isinstance(fact.get("location"), Mapping) else (
            payload.get("location") if isinstance(payload.get("location"), Mapping) else payload
        )
        fpath = _safe_rel_path(loc.get("path") or fact.get("path"))
        sname = str(fact.get("name") or payload.get("name") or "")
        if sname and fpath != "unknown":
            sline = int(loc.get("start_line") or fact.get("start_line") or 1)
            eline = int(loc.get("end_line") or fact.get("end_line") or sline)
            scope_blk = payload.get("scope") if isinstance(payload.get("scope"), Mapping) else {}
            flang = canonical_cpg_language(
                scope_blk.get("language") or payload.get("language") or fact.get("language"), fpath
            )
            _register_function(
                name=sname,
                qualified_name=str(payload.get("qualified_name") or sname),
                path=fpath,
                start_line=sline,
                end_line=eline,
                language=flang,
                producer=_producer(fact),
                external_id=fid or None,
                location=loc if loc.get("file_sha256") else None,
                evidence=_evidence(fact),
                node_kind="function" if str(payload.get("kind", "function")).lower() in {
                    "function", "method", "constructor", "destructor",
                } else "symbol",
            )

    semantic_sink_locs: set[tuple[str, int, str]] = set()
    handled_calls: set[str] = set()
    for fact in codeql_facts:
        if not isinstance(fact, Mapping):
            continue
        fid = str(fact.get("identity") or fact.get("fact_id") or "")
        kind = str(fact.get("kind") or fact.get("family") or "")
        if kind == "symbol":
            continue
        payload = fact.get("payload") if isinstance(fact.get("payload"), Mapping) else fact
        result_blk = payload.get("result") if isinstance(payload.get("result"), Mapping) else payload
        loc = fact.get("location") if isinstance(fact.get("location"), Mapping) else (
            payload.get("location") if isinstance(payload.get("location"), Mapping) else payload
        )
        fpath = _safe_rel_path(loc.get("path") or fact.get("path"))
        sline = int(loc.get("start_line") or fact.get("start_line") or 1)
        scope_blk = payload.get("scope") if isinstance(payload.get("scope"), Mapping) else {}
        flang = canonical_cpg_language(
            scope_blk.get("language") or payload.get("language") or fact.get("language"), fpath
        )

        fact_producer = _producer(fact)
        fact_evidence = _evidence(fact)
        if kind == "entry_point" and fpath != "unknown":
            enc_fn, _, _ = _enclosing_fn_and_guards(fpath, sline)
            if enc_fn is None and (fact.get("name") or result_blk.get("handler")):
                enc_fn = _register_function(
                    name=str(result_blk.get("handler") or fact.get("name") or "entrypoint"),
                    qualified_name=str(result_blk.get("handler") or fact.get("name") or "entrypoint"),
                    path=fpath,
                    start_line=sline,
                    end_line=sline,
                    language=flang,
                    producer=fact_producer,
                    location=loc if loc.get("file_sha256") else None,
                    evidence=fact_evidence,
                )
            ep_id = _cpg_digest("cpg:ep", {"path": fpath, "line": sline, "name": str(fact.get("name") or "entry")})
            nodes_by_id[ep_id] = {
                "schema": ALTERNATE_CPG_SCHEMA,
                "record_type": "cpg_node",
                "node_id": ep_id,
                "node_kind": "entrypoint",
                "name": str(fact.get("name") or result_blk.get("source_class") or "entry_point"),
                "qualified_name": f"{fpath}:{sline}",
                "language": flang,
                "path": fpath,
                "start_line": sline,
                "end_line": sline,
                "function_id": enc_fn,
                "block_kind": None,
                "guard_expression": None,
                "guard_polarity": None,
                "guard_dominators": [],
                "parameters": [],
                "calls": [],
                "defs": [],
                "uses": [],
                "is_entrypoint": True,
                "entrypoint_sources": ["codeql_entry_point"],
                "sink_class": None,
                "resolution_tier": _merge_tier([fact_producer]),
                "producers": [fact_producer],
                "location": loc if loc.get("file_sha256") else None,
                "evidence": [fact_evidence],
            }
            if enc_fn:
                fn_n = nodes_by_id[enc_fn]
                fn_n["is_entrypoint"] = True
                fn_n["entrypoint_sources"] = sorted({*fn_n["entrypoint_sources"], "codeql_entry_point"})
                _add_edge(
                    edge_kind="ENTRYPOINT_TO_FN",
                    source_id=ep_id,
                    target_id=enc_fn,
                    language=flang,
                    producer=fact_producer,
                    path=fpath,
                    line=sline,
                    evidence=fact_evidence,
                )
        elif kind == "sink_site" and fpath != "unknown":
            enc_fn, doms, blk_id = _enclosing_fn_and_guards(fpath, sline)
            sclass = str(result_blk.get("sink_class") or payload.get("sink_class") or "generic_sink")
            sname = str(fact.get("name") or result_blk.get("callee") or sclass)
            sink_id = _cpg_digest("cpg:sink", {"path": fpath, "line": sline, "class": sclass, "name": sname})
            prods = [fact_producer, "tree_sitter"] if blk_id else [fact_producer]
            nodes_by_id[sink_id] = {
                "schema": ALTERNATE_CPG_SCHEMA,
                "record_type": "cpg_node",
                "node_id": sink_id,
                "node_kind": "sink",
                "name": sname,
                "qualified_name": f"{fpath}:{sline}:{sname}",
                "language": flang,
                "path": fpath,
                "start_line": sline,
                "end_line": sline,
                "function_id": enc_fn,
                "block_kind": None,
                "guard_expression": None,
                "guard_polarity": None,
                "guard_dominators": doms,
                "parameters": [],
                "calls": [],
                "defs": [],
                "uses": [],
                "is_entrypoint": False,
                "entrypoint_sources": [],
                "sink_class": sclass,
                "resolution_tier": _merge_tier(prods),
                "producers": prods,
                "location": loc if loc.get("file_sha256") else None,
                "evidence": [fact_evidence],
            }
            if fid:
                external_id_to_fn[fid] = sink_id
            semantic_sink_locs.add((fpath, sline, _simple_symbol(sname)))
            if enc_fn:
                for p in prods:
                    _add_edge(
                        edge_kind="FN_TO_SINK",
                        source_id=enc_fn,
                        target_id=sink_id,
                        language=flang,
                        producer=p,
                        path=fpath,
                        line=sline,
                        callee_name=sname,
                        guard_dominators=doms,
                        evidence=fact_evidence,
                        occurrence=fid or None,
                        location=loc if loc.get("file_sha256") else None,
                    )
            if blk_id:
                _add_edge(
                    edge_kind="FLOWS_TO",
                    source_id=blk_id,
                    target_id=sink_id,
                    language=flang,
                    producer=fact_producer,
                    edge_subtype="sink_invocation",
                    path=fpath,
                    line=sline,
                    guard_dominators=doms,
                    evidence=fact_evidence,
                )
        elif kind == "call_site" and fpath != "unknown":
            caller = result_blk.get("caller") if isinstance(result_blk.get("caller"), Mapping) else {}
            callee = result_blk.get("callee") if isinstance(result_blk.get("callee"), Mapping) else {}
            caller_fn = external_id_to_fn.get(str(caller.get("symbol") or result_blk.get("caller_id")
                                                   or payload.get("caller_id") or ""))
            if caller_fn is None:
                caller_fn, doms, _ = _enclosing_fn_and_guards(fpath, sline)
            else:
                _, doms, _ = _enclosing_fn_and_guards(fpath, sline)
            callee_fn = external_id_to_fn.get(str(callee.get("symbol") or result_blk.get("callee_id")
                                                   or payload.get("callee_id") or ""))
            callee_name = str(callee.get("display") or (result_blk.get("callee") if not callee else "")
                              or payload.get("callee_name") or fact.get("name") or "")
            if callee_fn is None and callee_name:
                tpath = _safe_rel_path(result_blk.get("target_path") or payload.get("target_path") or "")
                tline = int(result_blk.get("target_line") or payload.get("target_line") or 0)
                if tpath != "unknown" and tline >= 1:
                    existing = [n for n in fns_by_path_name.get((tpath, _simple_symbol(callee_name)), ())
                                if nodes_by_id[n]["start_line"] == tline]
                    callee_fn = existing[0] if len(existing) == 1 else _register_function(
                        name=callee_name,
                        qualified_name=callee_name,
                        path=tpath,
                        start_line=tline,
                        end_line=tline,
                        language=flang,
                        producer=_producer(fact),
                    )
                else:
                    cands = fns_by_path_name.get((fpath, _simple_symbol(callee_name))) or fns_by_lang_name.get(
                        (flang, _simple_symbol(callee_name)), []
                    )
                    if len(cands) == 1 and not callee:
                        callee_fn = cands[0]
                    elif len(cands) > 1:
                        gaps.append(f"ambiguous_call_target: {fid or f'{fpath}:{sline}'}")
            if caller_fn and callee_fn and all(
                nodes_by_id[n]["node_kind"] == "function" for n in (caller_fn, callee_fn)
            ):
                _add_edge(
                    edge_kind="CALLS",
                    source_id=caller_fn,
                    target_id=callee_fn,
                    language=flang,
                    producer=_producer(fact),
                    edge_subtype="codeql_call",
                    path=fpath,
                    line=sline,
                    callee_name=nodes_by_id[callee_fn]["name"],
                    guard_dominators=doms,
                    location=loc if loc.get("file_sha256") else None,
                    occurrence=fid or None,
                    evidence=_evidence(fact),
                )
                semantic_call_pairs.add((caller_fn, callee_fn))
            else:
                unresolved_id = _cpg_digest("cpg:call", {"identity": fid, "location": loc,
                                                         "path": fpath, "line": sline})
                nodes_by_id[unresolved_id] = {
                    "schema": ALTERNATE_CPG_SCHEMA, "record_type": "cpg_node",
                    "node_id": unresolved_id, "node_kind": "call_site", "name": callee_name,
                    "qualified_name": callee_name, "language": flang, "path": fpath,
                    "start_line": sline, "end_line": int(loc.get("end_line") or sline),
                    "function_id": caller_fn, "resolution_tier": _merge_tier([fact_producer]),
                    "producers": [fact_producer], "evidence": [fact_evidence],
                    "location": loc if loc.get("file_sha256") else None,
                    "guard_dominators": doms, "is_entrypoint": False,
                }
                gaps.append(f"unresolved_call_context: {fid or f'{fpath}:{sline}'}")
                if caller_fn:
                    _add_edge(
                        edge_kind="REFERENCES", edge_subtype="unresolved_call_context",
                        source_id=caller_fn, target_id=unresolved_id, language=flang,
                        producer=fact_producer, path=fpath, line=sline,
                        location=loc if loc.get("file_sha256") else None,
                        occurrence=fid or None, evidence={**fact_evidence, "exact": False},
                    )
            if fid:
                handled_calls.add(fid)
        elif kind == "dataflow_path":
            steps = result_blk.get("steps") or payload.get("steps") or ()
            prev_fn: str | None = None
            for step in steps:
                if not isinstance(step, Mapping):
                    continue
                sloc = step.get("location") if isinstance(step.get("location"), Mapping) else step
                spath = _safe_rel_path(sloc.get("path"))
                s_ln = int(sloc.get("start_line") or sloc.get("line") or 0)
                if spath == "unknown" or s_ln < 1:
                    gaps.append(f"dataflow_unmapped_step: {fid}:{step.get('n')}")
                    prev_fn = None
                    continue
                step_fn, doms, _ = _enclosing_fn_and_guards(spath, s_ln)
                if prev_fn and step_fn and prev_fn != step_fn:
                    _add_edge(
                        edge_kind="TAINT_STEP",
                        source_id=prev_fn,
                        target_id=step_fn,
                        language=flang,
                        producer=_producer(fact),
                        edge_subtype="codeql_dataflow",
                        path=spath,
                        line=s_ln,
                        guard_dominators=doms,
                        location=sloc,
                        occurrence=f"{fid}:{step.get('n')}",
                        evidence=_evidence(fact),
                    )
                if step_fn:
                    prev_fn = step_fn
                else:
                    gaps.append(f"dataflow_unmapped_step: {fid}:{step.get('n')}")
                    prev_fn = None

    callsite_callers: dict[str, list[str]] = defaultdict(list)
    callsite_targets: dict[str, list[str]] = defaultdict(list)
    for rel in codeql_relations:
        if not isinstance(rel, Mapping):
            continue
        rkind, src_id, dst_id = str(rel.get("kind") or ""), str(rel.get("source_id") or ""), str(rel.get("target_id") or "")
        if src_id in handled_calls or dst_id in handled_calls:
            continue
        if rkind == "CONTAINS" and src_id in external_id_to_fn:
            callsite_callers[dst_id].append(external_id_to_fn[src_id])
        elif rkind == "CALLS":
            if src_id in external_id_to_fn and dst_id in external_id_to_fn:
                s_fn, d_fn = external_id_to_fn[src_id], external_id_to_fn[dst_id]
                if (
                    s_fn != d_fn
                    and nodes_by_id.get(s_fn, {}).get("node_kind") == "function"
                    and nodes_by_id.get(d_fn, {}).get("node_kind") == "function"
                ):
                    gaps.append(f"call_occurrence_unavailable: {rel.get('relation_id')}")
                    _add_edge(
                        edge_kind="CALLS",
                        source_id=s_fn,
                        target_id=d_fn,
                        language=nodes_by_id[s_fn]["language"],
                        producer=_producer(rel),
                        edge_subtype="codeql_call",
                        callee_name=nodes_by_id[d_fn]["name"],
                        evidence={**_evidence(rel), "exact": False},
                    )
                    semantic_call_pairs.add((s_fn, d_fn))
            elif dst_id in external_id_to_fn:
                callsite_targets[src_id].append(external_id_to_fn[dst_id])

    for cs_id, targets in callsite_targets.items():
        cs_fact = codeql_entity_by_id.get(cs_id, {})
        cs_loc = cs_fact.get("location") if isinstance(cs_fact.get("location"), Mapping) else {}
        cs_path = _safe_rel_path(cs_loc.get("path"))
        cs_line = int(cs_loc.get("start_line") or 1)
        callers = callsite_callers.get(cs_id) or []
        if not callers and cs_path != "unknown":
            enc, _, _ = _enclosing_fn_and_guards(cs_path, cs_line)
            if enc:
                callers = [enc]
        _, doms, _ = _enclosing_fn_and_guards(cs_path, cs_line) if cs_path != "unknown" else (None, [], None)
        for c_fn in callers:
            for t_fn in targets:
                if c_fn != t_fn and nodes_by_id.get(t_fn, {}).get("node_kind") == "function":
                    _add_edge(
                        edge_kind="CALLS",
                        source_id=c_fn,
                        target_id=t_fn,
                        language=nodes_by_id[c_fn]["language"],
                        producer=_producer(cs_fact),
                        edge_subtype="codeql_call",
                        path=cs_path if cs_path != "unknown" else nodes_by_id[c_fn]["path"],
                        line=cs_line,
                        callee_name=nodes_by_id[t_fn]["name"],
                        guard_dominators=doms,
                        location=cs_loc if cs_loc.get("file_sha256") else None,
                        occurrence=cs_id,
                        evidence=_evidence(cs_fact),
                    )
                    semantic_call_pairs.add((c_fn, t_fn))

    for obs in sarif_observations:
        if not isinstance(obs, Mapping):
            continue
        payload = obs.get("payload") if isinstance(obs.get("payload"), Mapping) else obs
        groups, unindexed = _flow_groups(payload)
        if unindexed:
            gaps.append(f"sarif_unindexed_steps: {obs.get('identity')}: {unindexed}")
        flows = [{"steps": steps} for _, steps in sorted(groups.items())]
        if not payload.get("flows"):
            flows = list(payload.get("code_flows") or ())
        for flow_index, flow in enumerate(flows):
            steps = (
                flow.get("steps")
                if isinstance(flow, Mapping)
                else (flow if isinstance(flow, Sequence) and not isinstance(flow, (str, bytes)) else ())
            )
            prev_fn: str | None = None
            for step in steps or ():
                if not isinstance(step, Mapping):
                    continue
                sloc = step.get("location") if isinstance(step.get("location"), Mapping) else step
                spath = _safe_rel_path(sloc.get("path"))
                sline = int(sloc.get("start_line") or sloc.get("line") or 0)
                if spath == "unknown" or sline < 1:
                    gaps.append(f"sarif_unmapped_step: {obs.get('identity')}:{flow_index}")
                    prev_fn = None
                    continue
                step_fn, doms, _ = _enclosing_fn_and_guards(spath, sline)
                if prev_fn and step_fn and prev_fn != step_fn:
                    _add_edge(
                        edge_kind="TAINT_STEP",
                        source_id=prev_fn,
                        target_id=step_fn,
                        language=nodes_by_id[step_fn]["language"],
                        producer="codeql",
                        edge_subtype="sarif_code_flow",
                        path=spath,
                        line=sline,
                        guard_dominators=doms,
                        location=sloc,
                        occurrence=f"{obs.get('identity')}:{flow_index}:{step.get('ordinal')}",
                        evidence={"identity": obs.get("identity"), "producer": "codeql-sarif",
                                  "exact": False},
                    )
                if step_fn:
                    prev_fn = step_fn
                else:
                    gaps.append(f"sarif_unmapped_step: {obs.get('identity')}:{flow_index}:{sline}")
                    prev_fn = None

    for route in route_entrypoints:
        if not isinstance(route, Mapping):
            continue
        payload = route.get("payload") if isinstance(route.get("payload"), Mapping) else route
        loc = route.get("location") if isinstance(route.get("location"), Mapping) else payload
        rpath = _safe_rel_path(loc.get("path") or route.get("path"))
        rline = int(loc.get("start_line") or route.get("line") or route.get("start_line") or 1)
        hname = str(
            payload.get("handler_name")
            or payload.get("handler")
            or payload.get("symbol")
            or route.get("name")
            or "route_handler"
        )
        rlabel = str(payload.get("route") or payload.get("uri") or route.get("name") or hname)
        rlang = canonical_cpg_language(payload.get("language") or route.get("language"), rpath)
        target_fn: str | None = None
        if rpath != "unknown":
            target_fn, _, _ = _enclosing_fn_and_guards(rpath, rline)
            if target_fn is None:
                cands = fns_by_path_name.get((rpath, _simple_symbol(hname)), [])
                if cands:
                    target_fn = cands[0]
        if target_fn is None and _simple_symbol(hname):
            cands = fns_by_lang_name.get((rlang, _simple_symbol(hname))) or fns_by_name.get(
                _simple_symbol(hname), []
            )
            if cands:
                target_fn = cands[0]
        if target_fn is not None:
            fn_n = nodes_by_id[target_fn]
            fn_n["is_entrypoint"] = True
            fn_n["entrypoint_sources"] = sorted({*fn_n["entrypoint_sources"], "framework_route"})
            ep_id = _cpg_digest(
                "cpg:ep", {"route": rlabel, "target": target_fn, "path": fn_n["path"], "line": rline}
            )
            nodes_by_id[ep_id] = {
                "schema": ALTERNATE_CPG_SCHEMA,
                "record_type": "cpg_node",
                "node_id": ep_id,
                "node_kind": "entrypoint",
                "name": rlabel,
                "qualified_name": f"{rlabel}->{fn_n['qualified_name']}",
                "language": fn_n["language"],
                "path": fn_n["path"],
                "start_line": fn_n["start_line"],
                "end_line": fn_n["start_line"],
                "function_id": target_fn,
                "block_kind": None,
                "guard_expression": None,
                "guard_polarity": None,
                "guard_dominators": [],
                "parameters": [],
                "calls": [],
                "defs": [],
                "uses": [],
                "is_entrypoint": True,
                "entrypoint_sources": ["framework_route"],
                "sink_class": None,
                "resolution_tier": fn_n["resolution_tier"],
                "producers": list(fn_n["producers"]),
            }
            _add_edge(
                edge_kind="ENTRYPOINT_TO_FN",
                source_id=ep_id,
                target_id=target_fn,
                language=fn_n["language"],
                producer=fn_n["producers"][0],
                path=fn_n["path"],
                line=fn_n["start_line"],
            )

    linked_ep_fns = {
        e["target_id"] for e in edges_by_id.values() if e["edge_kind"] == "ENTRYPOINT_TO_FN"
    }
    for fid, fn_n in list(nodes_by_id.items()):
        if fn_n["node_kind"] == "function" and fn_n["is_entrypoint"] and fid not in linked_ep_fns:
            ep_id = _cpg_digest(
                "cpg:ep", {"fn": fid, "path": fn_n["path"], "line": fn_n["start_line"]}
            )
            nodes_by_id[ep_id] = {
                "schema": ALTERNATE_CPG_SCHEMA,
                "record_type": "cpg_node",
                "node_id": ep_id,
                "node_kind": "entrypoint",
                "name": fn_n["name"],
                "qualified_name": fn_n["qualified_name"],
                "language": fn_n["language"],
                "path": fn_n["path"],
                "start_line": fn_n["start_line"],
                "end_line": fn_n["start_line"],
                "function_id": fid,
                "block_kind": None,
                "guard_expression": None,
                "guard_polarity": None,
                "guard_dominators": [],
                "parameters": [],
                "calls": [],
                "defs": [],
                "uses": [],
                "is_entrypoint": True,
                "entrypoint_sources": list(fn_n["entrypoint_sources"]) or ["syntactic_entrypoint"],
                "sink_class": None,
                "resolution_tier": fn_n["resolution_tier"],
                "producers": list(fn_n["producers"]),
            }
            _add_edge(
                edge_kind="ENTRYPOINT_TO_FN",
                source_id=ep_id,
                target_id=fid,
                language=fn_n["language"],
                producer=fn_n["producers"][0],
                path=fn_n["path"],
                line=fn_n["start_line"],
            )

    symref_targets: dict[tuple[str, int, str], list[str]] = defaultdict(list)
    for sref in symbol_references:
        if not isinstance(sref, Mapping):
            continue
        cpath = _safe_rel_path(sref.get("caller_path") or sref.get("path"))
        cline = int(sref.get("caller_line") or sref.get("line") or 0)
        cname = _simple_symbol(sref.get("callee_name") or sref.get("name"))
        tpath = _safe_rel_path(sref.get("target_path"))
        tline = int(sref.get("target_line") or 0)
        if cpath != "unknown" and cline >= 1 and cname and tpath != "unknown":
            cands = fns_by_path_name.get((tpath, cname), [])
            if not cands and tline >= 1:
                enc, _, _ = _enclosing_fn_and_guards(tpath, tline)
                if enc:
                    cands = [enc]
            for cid in cands:
                if cid not in symref_targets[(cpath, cline, cname)]:
                    symref_targets[(cpath, cline, cname)].append(cid)

    def source_guards(dominators: Sequence[Mapping[str, Any]]) -> dict[bytes, dict[str, Any]]:
        result = {}
        for dominator in dominators:
            guard = dict(dominator)
            block = nodes_by_id.get(str(guard["node_id"]), {})
            native = (block.get("location") or {}).get("producer_location") or {}
            if native.get("ast_identity"):
                guard["node_id"] = native["ast_identity"]
            result[canonical_json(guard)] = guard
        return result

    for call_item in pending_ts_calls:
        caller_fn = call_item["caller_fn_id"]
        blk_id = call_item["block_id"]
        raw_callee = call_item["callee_name"]
        simple_callee = _simple_symbol(raw_callee)
        cpath = call_item["path"]
        cline = int(call_item["line"])
        clang = call_item["language"]
        doms = call_item["guard_dominators"]
        if not simple_callee:
            continue

        targets: list[str] = []
        if (cpath, cline, simple_callee) in symref_targets:
            targets = list(symref_targets[(cpath, cline, simple_callee)])
        elif (cpath, simple_callee) in fns_by_path_name:
            targets = [fid for fid in fns_by_path_name[(cpath, simple_callee)] if fid != caller_fn]
        if not targets and (clang, raw_callee) in fns_by_lang_qname:
            targets = [fid for fid in fns_by_lang_qname[(clang, raw_callee)] if fid != caller_fn]
        if not targets and (clang, simple_callee) in fns_by_lang_name:
            cands = [fid for fid in fns_by_lang_name[(clang, simple_callee)] if fid != caller_fn]
            if len(cands) <= 4:
                targets = sorted(cands, key=lambda fid: (nodes_by_id[fid]["path"], nodes_by_id[fid]["start_line"]))
            else:
                gaps.append(f"syntactic_call_candidates_omitted: {cpath}:{cline}: {len(cands)} candidates")

        if targets:
            if len(targets) > 1:
                gaps.append(f"ambiguous_syntactic_call: {cpath}:{cline}: {len(targets)} candidates")
            if len(targets) > 4:
                gaps.append(f"syntactic_call_candidates_omitted: {cpath}:{cline}: {len(targets) - 4}")
            for tgt_fn in sorted(targets)[:4]:
                upgraded = False
                for ex_edge in edges_by_id.values():
                    if (
                        ex_edge["edge_kind"] == "CALLS"
                        and ex_edge["source_id"] == caller_fn
                        and ex_edge["target_id"] == tgt_fn
                        and ex_edge["path"] == cpath
                        and ex_edge["line"] == cline
                        and ex_edge.get("occurrence") == (call_item.get("occurrence") or blk_id)
                    ):
                        ex_edge["producers"] = sorted({*ex_edge["producers"], "tree_sitter"})
                        ex_edge["resolution_tier"] = _merge_tier(ex_edge["producers"])
                        if doms:
                            seen_g = {(g["node_id"], g["branch"]) for g in ex_edge["guard_dominators"]}
                            for d in doms:
                                cd = _clean_guard_dom(d, default_path=cpath)
                                if (cd["node_id"], cd["branch"]) not in seen_g:
                                    seen_g.add((cd["node_id"], cd["branch"]))
                                    ex_edge["guard_dominators"].append(cd)
                        upgraded = True
                if not upgraded:
                    _add_edge(
                        edge_kind="CALLS",
                        source_id=caller_fn,
                        target_id=tgt_fn,
                        language=clang,
                        producer="tree_sitter",
                        edge_subtype="syntactic_call",
                        path=cpath,
                        line=cline,
                        callee_name=nodes_by_id[tgt_fn]["name"],
                        guard_dominators=doms,
                        location=call_item.get("location"),
                        occurrence=call_item.get("occurrence") or blk_id,
                    )
                callee_params = nodes_by_id[tgt_fn].get("parameters", ())
                if callee_params and (call_item["uses"] or nodes_by_id[caller_fn].get("parameters")):
                    src_data_node = blk_id or caller_fn
                    dst_data_node = fn_entry_block.get(tgt_fn, tgt_fn)
                    prod = "tree_sitter"
                    _add_edge(
                        edge_kind="ARG_TO_PARAM",
                        source_id=src_data_node,
                        target_id=dst_data_node,
                        language=clang,
                        producer=prod,
                        edge_subtype="arg_to_param",
                        path=cpath,
                        line=cline,
                        variable=str(callee_params[0]),
                        callee_name=nodes_by_id[tgt_fn]["name"],
                        guard_dominators=doms,
                    )
                    if prod == "codeql":
                        _add_edge(
                            edge_kind="ARG_TO_PARAM",
                            source_id=src_data_node,
                            target_id=dst_data_node,
                            language=clang,
                            producer="tree_sitter",
                            edge_subtype="arg_to_param",
                            path=cpath,
                            line=cline,
                            variable=str(callee_params[0]),
                            callee_name=nodes_by_id[tgt_fn]["name"],
                            guard_dominators=doms,
                        )

        sink_class = classify_syntactic_sink(raw_callee, clang)
        if sink_class and (cpath, cline, simple_callee) not in semantic_sink_locs:
            sink_id = _cpg_digest(
                "cpg:sink", {"path": cpath, "line": cline, "class": sink_class, "name": raw_callee,
                             "location": call_item.get("location")}
            )
            common_guards = source_guards(doms)
            if sink_id not in nodes_by_id:
                nodes_by_id[sink_id] = {
                    "schema": ALTERNATE_CPG_SCHEMA,
                    "record_type": "cpg_node",
                    "node_id": sink_id,
                    "node_kind": "sink",
                    "name": raw_callee,
                    "qualified_name": f"{cpath}:{cline}:{raw_callee}",
                    "language": clang,
                    "path": cpath,
                    "start_line": cline,
                    "end_line": cline,
                    "function_id": caller_fn,
                    "block_kind": None,
                    "guard_expression": None,
                    "guard_polarity": None,
                    "guard_dominators": [common_guards[key] for key in sorted(common_guards)],
                    "parameters": [],
                    "calls": [],
                    "defs": [],
                    "uses": list(call_item["uses"]),
                    "is_entrypoint": False,
                    "entrypoint_sources": [],
                    "sink_class": sink_class,
                    "resolution_tier": "syntactic_fallback",
                    "producers": ["tree_sitter"],
                    "location": call_item.get("location"),
                }
            else:
                # One source occurrence can execute in several finally contexts. Its
                # aggregate guards must hold in every context, not merely one of them.
                prior = {canonical_json(guard): guard for guard in nodes_by_id[sink_id]["guard_dominators"]}
                nodes_by_id[sink_id]["guard_dominators"] = [
                    prior[key] for key in sorted(prior.keys() & common_guards.keys())]
            _add_edge(
                edge_kind="FN_TO_SINK",
                source_id=caller_fn,
                target_id=sink_id,
                language=clang,
                producer="tree_sitter",
                path=cpath,
                line=cline,
                callee_name=raw_callee,
                guard_dominators=doms,
                occurrence=call_item.get("occurrence") or blk_id,
                location=call_item.get("location"),
            )
            if blk_id:
                _add_edge(
                    edge_kind="FLOWS_TO",
                    source_id=blk_id,
                    target_id=sink_id,
                    language=clang,
                    producer="tree_sitter",
                    edge_subtype="sink_invocation",
                    path=cpath,
                    line=cline,
                    guard_dominators=doms,
                    occurrence=call_item.get("occurrence") or blk_id,
                    location=call_item.get("location"),
                )

    sorted_nodes = [nodes_by_id[nid] for nid in sorted(nodes_by_id)]
    sorted_edges = [edges_by_id[eid] for eid in sorted(edges_by_id)]
    cpg_base: dict[str, Any] = {
        "schema": ALTERNATE_CPG_SCHEMA,
        "run_id": run_id,
        "target_snapshot": target_snapshot,
        "max_hops": cfg.max_hops,
        "max_slice_depth": cfg.max_slice_depth,
        "settings": asdict(cfg),
        "nodes": sorted_nodes,
        "edges": sorted_edges,
    }
    has_entrypoints = any(n["node_kind"] == "function" and n["is_entrypoint"] for n in sorted_nodes)
    traversal: dict[str, Any] = {}
    precomputed_paths = find_interprocedural_paths(
        cpg_base,
        entrypoint_only=has_entrypoints,
        max_hops=cfg.max_hops,
        max_paths=cfg.max_precomputed_paths,
        diagnostics=traversal,
    )
    cpg_base["paths"] = precomputed_paths
    cpg_base["gaps"] = list(dict.fromkeys([*gaps, *traversal.get("gaps", ())]))
    cpg_base["traversal"] = traversal

    resolution_breakdown: dict[str, int] = {tier: 0 for tier in RESOLUTION_TIERS}
    for edge in sorted_edges:
        resolution_breakdown[edge["resolution_tier"]] = (
            resolution_breakdown.get(edge["resolution_tier"], 0) + 1
        )
    semantic_edges = sum(
        count for tier, count in resolution_breakdown.items() if tier != "syntactic_fallback"
    )
    syntactic_edges = resolution_breakdown.get("syntactic_fallback", 0)
    entrypoints_linked = sum(
        1 for n in sorted_nodes if n["node_kind"] == "function" and n["is_entrypoint"]
    )
    languages = sorted({n["language"] for n in sorted_nodes if n["language"] != "unknown"})
    cpg_base["languages"] = languages
    cpg_base["counts"] = {
        "alternate_cpg_nodes": len(sorted_nodes),
        "alternate_cpg_edges": len(sorted_edges),
        "semantic_edges_count": semantic_edges,
        "syntactic_fallback_edges_count": syntactic_edges,
        "entrypoints_linked": entrypoints_linked,
        "reachable_sink_paths_precomputed": len(precomputed_paths),
    }
    cpg_base["resolution_breakdown"] = resolution_breakdown
    return cpg_base


def _match_node_query(node: Mapping[str, Any], query: str) -> bool:
    if (
        node["node_id"] == query
        or node.get("logical_id") == query
        or node["name"] == query
        or node.get("qualified_name") == query
    ):
        return True
    if _simple_symbol(node["name"]) == _simple_symbol(query) and _simple_symbol(query):
        return True
    return False


def find_interprocedural_paths(
    cpg: Mapping[str, Any],
    *,
    source: str | None = None,
    sink: str | None = None,
    sink_class: str | None = None,
    entrypoint_only: bool = False,
    language: str | None = None,
    max_hops: int = 10,
    max_paths: int = 50,
    diagnostics: dict[str, Any] | None = None,
    check_deadline: Callable[[], None] | None = None,
) -> list[dict[str, Any]]:
    """Deterministic, cycle-safe bounded inter-procedural call+dataflow path finder."""
    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= 16:
        raise ValueError("max_hops must be an integer between 1 and 16")
    if isinstance(max_paths, bool) or not isinstance(max_paths, int) or max_paths < 1:
        raise ValueError("max_paths must be >= 1")
    cuts: dict[str, int] = defaultdict(int)
    stats = diagnostics if diagnostics is not None else {}
    stats.update(visited_states=0, inspected_edges=0, cuts={}, gaps=[], truncated=False)

    nodes = {str(n["node_id"]): n for n in cpg.get("nodes", ()) if isinstance(n, Mapping)}
    if not nodes:
        return []
    lang_filter = canonical_cpg_language(language) if language else None

    inter_kinds = {"CALLS", "TAINT_STEP", "FN_TO_SINK", "ENTRYPOINT_TO_FN"}
    adj: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for edge in cpg.get("edges", ()):
        if check_deadline:
            check_deadline()
        if not isinstance(edge, Mapping) or edge.get("edge_kind") not in inter_kinds:
            continue
        src_id = str(edge.get("source_id") or "")
        dst_id = str(edge.get("target_id") or "")
        if src_id in nodes and dst_id in nodes:
            adj[src_id].append(edge)

    for src_id, edge_list in adj.items():
        edge_list.sort(
            key=lambda e: (
                _TIER_RANK.get(str(e.get("resolution_tier")), 9),
                str(nodes[str(e["target_id"])].get("path") or ""),
                int(e.get("line") or nodes[str(e["target_id"])].get("start_line") or 0),
                str(e["target_id"]),
                str(e.get("edge_kind") or ""),
            )
        )

    start_ids: list[str] = []
    for nid in sorted(nodes):
        n = nodes[nid]
        if lang_filter and n.get("language") != lang_filter:
            continue
        if source is not None:
            if _match_node_query(n, source) and n["node_kind"] in {"function", "entrypoint"}:
                start_ids.append(nid)
        elif entrypoint_only:
            if n["node_kind"] == "function" and n.get("is_entrypoint"):
                start_ids.append(nid)
        else:
            if n["node_kind"] == "function":
                start_ids.append(nid)

    target_ids: set[str] = set()
    for nid, n in nodes.items():
        if lang_filter and n.get("language") != lang_filter:
            continue
        if sink_class is not None and n.get("sink_class") != sink_class:
            continue
        if sink is not None:
            if _match_node_query(n, sink) and n["node_kind"] in {"sink", "function"}:
                target_ids.add(nid)
        else:
            if n["node_kind"] == "sink":
                target_ids.add(nid)

    if not start_ids or not target_ids:
        return []

    results: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, ...]] = set()
    queue: deque[tuple[str, frozenset[str], tuple[str, ...], tuple[Mapping[str, Any], ...], int]] = deque()
    for sid in sorted(
        start_ids,
        key=lambda i: (str(nodes[i].get("path") or ""), int(nodes[i].get("start_line") or 0), i),
    ):
        if len(queue) >= MAX_PATH_FRONTIER:
            cuts["frontier_limit"] += 1
            continue
        queue.append((sid, frozenset({sid}), (sid,), (), 0))

    while queue and len(results) < max_paths:
        if check_deadline:
            check_deadline()
        if stats["visited_states"] >= MAX_PATH_STATES:
            cuts["work_limit"] += len(queue)
            break
        stats["visited_states"] += 1
        curr_id, visited, node_chain, edge_chain, call_hops = queue.popleft()
        if edge_chain and curr_id in target_ids:
            signature = tuple(str(e.get("edge_id")) for e in edge_chain)
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                start_node = nodes[node_chain[0]]
                end_node = nodes[curr_id]
                hops_out: list[dict[str, Any]] = []
                doms_out: list[dict[str, Any]] = []
                seen_doms: set[tuple[str, str]] = set()
                tiers: list[str] = []
                for idx, edge in enumerate(edge_chain):
                    s_n = nodes[str(edge["source_id"])]
                    t_n = nodes[str(edge["target_id"])]
                    etier = str(edge.get("resolution_tier") or "syntactic_fallback")
                    tiers.append(etier)
                    hops_out.append(
                        {
                            "step_index": idx,
                            "source_id": str(edge["source_id"]),
                            "source_name": str(s_n.get("name") or ""),
                            "target_id": str(edge["target_id"]),
                            "target_name": str(t_n.get("name") or ""),
                            "edge_kind": str(edge.get("edge_kind") or "CALLS"),
                            "resolution_tier": etier,
                            "path": edge.get("path") or s_n.get("path"),
                            "line": edge.get("line") or s_n.get("start_line"),
                            "edge_id": edge.get("edge_id"),
                            "exact": bool(edge.get("exact")),
                            "evidence": list(edge.get("evidence", ())),
                            "guard_dominators": list(edge.get("guard_dominators", ())),
                        }
                    )
                    for dom in edge.get("guard_dominators", ()):
                        if isinstance(dom, Mapping):
                            cd = _clean_guard_dom(
                                dom,
                                default_path=str(s_n.get("path") or ""),
                                fn_name=str(s_n.get("name") or ""),
                            )
                            key = (cd["node_id"], cd["branch"])
                            if key not in seen_doms:
                                seen_doms.add(key)
                                doms_out.append(cd)
                polarities = sorted({d["guard_polarity"] for d in doms_out})
                ep_linked = bool(
                    start_node.get("is_entrypoint") or start_node.get("node_kind") == "entrypoint"
                )
                path_id = _cpg_digest("cpg:path", {"chain": list(node_chain), "edges": list(signature)})
                results.append(
                    {
                        "schema": ALTERNATE_CPG_SCHEMA,
                        "record_type": "cpg_path",
                        "path_id": path_id,
                        "source_id": node_chain[0],
                        "source_name": str(start_node.get("name") or ""),
                        "sink_id": curr_id,
                        "sink_name": str(end_node.get("name") or ""),
                        "sink_class": end_node.get("sink_class"),
                        "language": str(start_node.get("language") or end_node.get("language") or "unknown"),
                        "hop_count": len(hops_out),
                        "entrypoint_linked": ep_linked,
                        "resolution_tier": _combine_path_tiers(tiers),
                        "guard_polarities": polarities,
                        "guard_dominators": doms_out,
                        "hops": hops_out,
                        "exact": all(bool(edge.get("exact")) for edge in edge_chain),
                    }
                )
            if nodes[curr_id]["node_kind"] == "sink":
                continue

        for edge in adj.get(curr_id, ()):
            if check_deadline:
                check_deadline()
            if stats["inspected_edges"] >= MAX_TRAVERSAL_EDGES:
                cuts["edge_work_limit"] += 1
                break
            stats["inspected_edges"] += 1
            nxt_id = str(edge["target_id"])
            if nxt_id in visited:
                continue
            ekind = str(edge.get("edge_kind") or "CALLS")
            next_call_hops = call_hops + (0 if ekind in {"ENTRYPOINT_TO_FN", "FN_TO_SINK"} else 1)
            if next_call_hops > max_hops or len(edge_chain) + 1 > 16:
                cuts["hop_limit"] += 1
                continue
            if len(queue) >= MAX_PATH_FRONTIER:
                cuts["frontier_limit"] += 1
                continue
            queue.append(
                (
                    nxt_id,
                    visited | {nxt_id},
                    (*node_chain, nxt_id),
                    (*edge_chain, edge),
                    next_call_hops,
                )
            )

    if queue and len(results) >= max_paths:
        cuts["path_limit"] += len(queue)
    stats.update(cuts=dict(cuts), truncated=bool(cuts),
                 gaps=[f"alternate_cpg_{kind}: {count} unexamined traversal branches"
                       for kind, count in sorted(cuts.items())])
    return results


def compute_cpg_slice(
    cpg: Mapping[str, Any],
    *,
    criterion_node_id: str | None = None,
    path: str | None = None,
    line: int | None = None,
    function_name: str | None = None,
    direction: str = "backward",
    max_depth: int = 8,
    edge_kinds: Sequence[str] | None = None,
    max_nodes: int = 100,
    check_deadline: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Compute a deterministic backward or forward program slice over Alternate CPG."""
    if direction not in {"backward", "forward"}:
        raise ValueError("direction must be 'backward' or 'forward'")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= 16:
        raise ValueError("max_depth must be an integer between 1 and 16")
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
        raise ValueError("max_nodes must be >= 1")
    max_depth = min(max_depth, int(cpg.get("max_slice_depth", 16)))

    allowed_kinds = set(edge_kinds) if edge_kinds else set(CPG_EDGE_KINDS)
    unknown_kinds = sorted(allowed_kinds - set(CPG_EDGE_KINDS))
    if unknown_kinds:
        raise ValueError("unknown edge_kinds: " + ", ".join(unknown_kinds))

    nodes = {str(n["node_id"]): n for n in cpg.get("nodes", ()) if isinstance(n, Mapping)}
    norm_p = _safe_rel_path(path) if path else None
    node_order = sorted(nodes, key=lambda nid: (
        str(nodes[nid].get("path") or ""), int(nodes[nid].get("start_line") or 0), nid))
    node_rank = {nid: rank for rank, nid in enumerate(node_order)}

    seeds: list[str] = []
    for nid in node_order:
        n = nodes[nid]
        if criterion_node_id is not None:
            if _match_node_query(n, criterion_node_id):
                seeds.append(nid)
            continue
        if norm_p and norm_p != "unknown" and n.get("path") != norm_p:
            continue
        if function_name and not (
            _match_node_query(n, function_name)
            or (n.get("function_id") in nodes and _match_node_query(nodes[str(n["function_id"])], function_name))
        ):
            continue
        if line is not None and not (int(n.get("start_line") or 0) <= line <= int(n.get("end_line") or 0)):
            continue
        if norm_p or function_name or line is not None:
            seeds.append(nid)

    if line is not None and any(nodes[s]["node_kind"] in {"sink", "cfg_block"} for s in seeds):
        fine = [s for s in seeds if nodes[s]["node_kind"] in {"sink", "cfg_block"}]
        enc_fns = {
            str(nodes[s]["function_id"])
            for s in fine
            if nodes[s].get("function_id") and str(nodes[s]["function_id"]) in nodes
        }
        seeds = sorted(set(fine) | enc_fns)

    if not seeds:
        return {
            "direction": direction,
            "criterion_ids": [],
            "nodes": [],
            "edges": [],
            "guard_dominators": [],
            "resolution_tiers": [],
            "truncated": False,
        }

    adj: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for edge in cpg.get("edges", ()):
        if check_deadline:
            check_deadline()
        if not isinstance(edge, Mapping) or edge.get("edge_kind") not in allowed_kinds:
            continue
        src, dst = str(edge.get("source_id") or ""), str(edge.get("target_id") or "")
        if src in nodes and dst in nodes:
            adj[src if direction == "forward" else dst].append(edge)

    if "CALLS" in allowed_kinds:
        for nid, n in nodes.items():
            fn_id = str(n.get("function_id") or "")
            if n["node_kind"] == "cfg_block" and fn_id and fn_id in nodes and fn_id != nid:
                bridge = {
                    "edge_id": f"bridge:{fn_id}:{nid}",
                    "edge_kind": "FLOWS_TO",
                    "edge_subtype": "function_entry_bridge",
                    "source_id": fn_id,
                    "target_id": nid,
                    "resolution_tier": str(nodes[fn_id].get("resolution_tier") or "syntactic_fallback"),
                    "guard_dominators": [],
                }
                if direction == "backward" and n.get("block_kind") == "entry":
                    adj[nid].append(bridge)
                elif direction == "forward" and n.get("block_kind") == "entry":
                    adj[fn_id].append(bridge)

    for key in adj:
        adj[key].sort(
            key=lambda e: (str(e.get("edge_kind") or ""), str(e.get("source_id") or ""), str(e.get("target_id") or ""))
        )

    distances: dict[str, int] = {}
    via_edge_kind: dict[str, str] = {}
    via_tier: dict[str, str] = {}
    observed_edges: dict[str, Mapping[str, Any]] = {}
    cuts: dict[str, int] = defaultdict(int)
    if len(seeds) > max_nodes:
        cuts["seed_limit"] = len(seeds) - max_nodes
    seeds = sorted(seeds, key=node_rank.__getitem__)[:max_nodes]
    for sid in seeds:
        distances[sid] = 0
        via_edge_kind[sid] = "criterion"
        via_tier[sid] = str(nodes[sid].get("resolution_tier") or "syntactic_fallback")

    inspected_edges = 0
    frontier = list(seeds)
    dist = 0
    while frontier:
        remaining = max_nodes - len(distances)
        candidates: dict[str, Mapping[str, Any]] = {}
        candidate_heap: list[tuple[int, str]] = []
        # Complete a breadth layer before admitting its location-ordered prefix.
        # The bounded heap keeps later pages from inserting earlier results.
        for curr in frontier:
            if check_deadline:
                check_deadline()
            for edge in adj.get(curr, ()):
                if check_deadline:
                    check_deadline()
                if inspected_edges >= MAX_TRAVERSAL_EDGES:
                    cuts["edge_work_limit"] += 1
                    break
                inspected_edges += 1
                neighbor = str(edge["target_id"] if direction == "forward" else edge["source_id"])
                if dist >= max_depth:
                    if neighbor not in distances:
                        cuts["depth_limit"] += 1
                    continue
                eid = str(edge.get("edge_id") or "")
                if not eid.startswith("bridge:"):
                    observed_edges.setdefault(eid, edge)
                if neighbor in distances or neighbor in candidates:
                    continue
                if not remaining:
                    cuts["node_limit"] += 1
                elif len(candidates) < remaining:
                    candidates[neighbor] = edge
                    heapq.heappush(candidate_heap, (-node_rank[neighbor], neighbor))
                else:
                    if node_rank[neighbor] < -candidate_heap[0][0]:
                        _, omitted = heapq.heapreplace(candidate_heap, (-node_rank[neighbor], neighbor))
                        del candidates[omitted]
                        candidates[neighbor] = edge
                    cuts["node_limit"] += 1
            if cuts.get("edge_work_limit"):
                break
        frontier = sorted(candidates, key=node_rank.__getitem__)
        for nid in frontier:
            edge = candidates[nid]
            distances[nid] = dist + 1
            via_edge_kind[nid] = str(edge.get("edge_kind") or "FLOWS_TO")
            via_tier[nid] = str(edge.get("resolution_tier") or "syntactic_fallback")
        if cuts.get("edge_work_limit"):
            break
        dist += 1

    ordered_ids = sorted(
        distances,
        key=lambda nid: (
            distances[nid],
            str(nodes[nid].get("path") or ""),
            int(nodes[nid].get("start_line") or 0),
            nid,
        ),
    )
    slice_nodes: list[dict[str, Any]] = []
    doms_out: list[dict[str, Any]] = []
    seen_doms: set[tuple[str, str]] = set()
    tiers_seen: set[str] = set()
    for nid in ordered_ids:
        n = nodes[nid]
        tier = via_tier[nid]
        tiers_seen.add(tier)
        for dom in n.get("guard_dominators", ()):
            if isinstance(dom, Mapping):
                cd = _clean_guard_dom(dom, default_path=str(n.get("path") or ""))
                if (cd["node_id"], cd["branch"]) not in seen_doms:
                    seen_doms.add((cd["node_id"], cd["branch"]))
                    doms_out.append(cd)
        slice_nodes.append(
            {
                **n,
                "distance": distances[nid],
                "via_edge_kind": via_edge_kind[nid],
                "slice_resolution_tier": tier,
            }
        )

    return {
        "direction": direction,
        "criterion_ids": seeds,
        "nodes": slice_nodes,
        "edges": [dict(edge) for edge in observed_edges.values()
                  if str(edge["source_id"]) in distances and str(edge["target_id"]) in distances],
        "guard_dominators": doms_out,
        "resolution_tiers": sorted(tiers_seen),
        "truncated": any(cuts.values()),
        "cuts": {kind: count for kind, count in cuts.items() if count},
        "gaps": [f"alternate_cpg_{kind}: {count} unexamined slice branches"
                 for kind, count in sorted(cuts.items()) if count],
    }


_NODE_ENTITY_KIND: dict[str, EntityKind] = {
    "function": EntityKind.SYMBOL,
    "symbol": EntityKind.SYMBOL,
    "cfg_block": EntityKind.AST_NODE,
    "call_site": EntityKind.CALL_SITE,
    "entrypoint": EntityKind.ENTRY_POINT,
    "sink": EntityKind.SINK_SITE,
}

_EDGE_RELATION_KIND: dict[str, RelationKind] = {
    "CALLS": RelationKind.CALLS,
    "REFERENCES": RelationKind.REFERENCES,
    "FLOWS_TO": RelationKind.FLOWS_TO,
    "GUARDS": RelationKind.GUARDS,
    "DEF_USE": RelationKind.FLOWS_TO,
    "ARG_TO_PARAM": RelationKind.FLOWS_TO,
    "TAINT_STEP": RelationKind.FLOWS_TO,
    "ENTRYPOINT_TO_FN": RelationKind.FLOWS_TO,
    "FN_TO_SINK": RelationKind.FLOWS_TO,
}


def _cfg_bytes(run_root: Path, identity: Mapping[str, Any]) -> bytes:
    path = safe_path(run_root, identity["path"])
    data = path.read_bytes()
    if (hashlib.sha256(data).hexdigest() != identity.get("sha256")
            or len(data) != identity.get("size_bytes", len(data))):
        raise IntegrityError("accepted Tree-sitter CFG artifact identity mismatch")
    return data


def _accepted_cfg(
    run_root: Path, ts_shards: Sequence[Mapping[str, Any]], target_snapshot: str,
    gaps: list[str],
) -> list[tuple[bytes, bytes]]:
    """Resolve CFG references from the admitted producer, never from a directory layout."""
    accepted = accepted_upstream(run_root, "job_tree_sitter_ast", required=False)
    if accepted is None:
        if ts_shards:
            raise IntegrityError("Tree-sitter shards have no admitted producer")
        gaps.append("tree_sitter_cfg_unavailable: no admitted Tree-sitter producer")
        return []
    if accepted.handoff["target_snapshot"] != target_snapshot:
        raise IntegrityError("Tree-sitter CFG producer target snapshot mismatch")
    gaps.extend(
        f"tree_sitter_cfg_partial: {gap}"
        for output in accepted.handoff["outputs"].values() if isinstance(output, Mapping)
        for gap in output.get("gaps", ())
    )
    # The runner projects unit outputs; dispositions live in the accepted summary artifact.
    output = accepted.handoff["outputs"].get("acceptance.publish_handoff")
    reference = output.get("artifact") if isinstance(output, Mapping) else None
    if not isinstance(reference, Mapping):
        raise IntegrityError("accepted Tree-sitter summary reference is missing")
    attempt = accepted.handoff["resolving_paths"]["attempt"]
    expected_path = f"{attempt}/steps/acceptance/tasks/publish_handoff/accepted-tree-sitter-ast.json"
    if (accepted.path != f"{attempt}/handoff.json" or reference.get("path") != expected_path
            or not any(item["path"] == reference["path"] and item["sha256"] == reference.get("sha256")
                       for item in accepted.handoff["artifacts"])):
        raise IntegrityError("accepted Tree-sitter summary is not bound to the producer attempt")
    observe_output(run_root, "job_tree_sitter_ast", "tree_sitter_acceptance", reference)
    summary = json.loads(_cfg_bytes(run_root, reference))
    if (not isinstance(summary, Mapping) or summary.get("schema") != "appsec-review/tree-sitter-ast/1"
            or summary.get("target_snapshot") != target_snapshot):
        raise IntegrityError("accepted Tree-sitter summary schema or target snapshot mismatch")
    dispositions = summary.get("dispositions")
    if (not isinstance(dispositions, list)
            or any(not isinstance(item, Mapping) or not isinstance(item.get("scope_id"), str)
                   or not item["scope_id"]
                   or ("index_identity" in item and not isinstance(item["index_identity"], Mapping))
                   for item in dispositions)):
        raise IntegrityError("accepted Tree-sitter summary dispositions are malformed or missing")
    dispositions = [item for item in dispositions if "index_identity" in item]
    result = []
    selected = [s for s in ts_shards if not str(s.get("shard_id", "")).startswith("tree-sitter-coverage-")]
    if not selected:
        gaps.append("tree_sitter_cfg_unavailable: no admitted Tree-sitter scope shards")
    for shard in selected:
        matches = [item for item in dispositions if item["index_identity"] == shard]
        if not matches:
            raise IntegrityError("Tree-sitter CFG shard is not in the admitted producer")
        record = matches[0]
        if any(item != record for item in matches):
            raise IntegrityError("conflicting Tree-sitter CFG scope records")
        observe_shard(run_root, shard)
        shard_path = safe_path(run_root, shard["relative_path"])
        if file_sha256(shard_path) != shard["sha256"]:
            raise IntegrityError("accepted Tree-sitter shard identity mismatch")
        refs = record.get("cfg_artifacts")
        if not isinstance(refs, Mapping):
            gaps.append(f"tree_sitter_cfg_unavailable: {record['scope_id']} has no accepted CFG artifacts")
            continue
        if set(refs) != {"manifest", "nodes", "edges"}:
            raise IntegrityError("accepted Tree-sitter CFG artifacts are incomplete")
        for identity in refs.values():
            observe_output(run_root, "job_tree_sitter_ast", "tree_sitter_cfg", identity)
        manifest = json.loads(_cfg_bytes(run_root, refs["manifest"]))
        if (manifest.get("schema") != "appsec-review/tree-sitter-cfg/1"
                or manifest.get("scope_id") != record["scope_id"]
                or manifest.get("target_snapshot") != target_snapshot
                or manifest.get("nodes_artifact") != refs["nodes"]
                or manifest.get("edges_artifact") != refs["edges"]):
            raise IntegrityError("accepted Tree-sitter CFG scope or artifact binding mismatch")
        nodes, edges = _cfg_bytes(run_root, refs["nodes"]), _cfg_bytes(run_root, refs["edges"])
        result.append((nodes, edges))
    return result


def _extract_tree_sitter_files(
    run_root: Path,
    ts_shards: Sequence[Mapping[str, Any]],
    *, target_snapshot: str, gaps: list[str],
) -> list[dict[str, Any]]:
    """Load only the admitted scope CFG artifacts and verified analysis shards."""
    from appsec_review.jobs.job_tree_sitter_ast.cfg import FUNCTION_NODE_TYPES

    by_path: dict[str, dict[str, Any]] = {}

    cfg_records = _accepted_cfg(run_root, ts_shards, target_snapshot, gaps)
    if cfg_records:
        for nodes_data, edges_data in cfg_records:
            for line in nodes_data.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                fpath = _safe_rel_path(rec.get("path"))
                flang = canonical_cpg_language(rec.get("language"), fpath)
                entry = by_path.setdefault(
                    fpath,
                    {
                        "path": fpath,
                        "language": flang,
                        "functions": [],
                        "cfg_nodes": [],
                        "cfg_edges": [],
                        "calls": [],
                        "route_candidates": [],
                        "_fn_seen": set(),
                    },
                )
                entry["cfg_nodes"].append(rec)
                fn_id = str(rec.get("function_id") or "")
                if fn_id and fn_id not in entry["_fn_seen"]:
                    entry["_fn_seen"].add(fn_id)
                    entry["functions"].append(
                        {
                            "function_id": fn_id,
                            "name": str(rec.get("function_name") or "anonymous"),
                            "qualified_name": str(rec.get("function_name") or "anonymous"),
                            "start_line": int(rec.get("start_line") or 1),
                            "end_line": int(rec.get("end_line") or rec.get("start_line") or 1),
                            "parameters": list(rec.get("defs", ())) if (rec.get("block_kind") or rec.get("kind")) == "entry" else [],
                            "location": _cfg_location(rec, target_snapshot),
                            "evidence": {"producer": "tree_sitter", "identity": fn_id,
                                         "source_identity": rec.get("source_identity")},
                        }
                    )
                for fn_item in entry["functions"]:
                    if fn_item["function_id"] == fn_id:
                        fn_item["start_line"] = min(fn_item["start_line"], int(rec.get("start_line") or 1))
                        fn_item["end_line"] = max(fn_item["end_line"], int(rec.get("end_line") or 1))
                        loc = fn_item.get("location")
                        if loc:
                            loc.update(start_line=fn_item["start_line"], end_line=fn_item["end_line"],
                                       start_byte=min(loc["start_byte"], int(rec.get("start_byte") or 0)),
                                       end_byte=max(loc["end_byte"], int(rec.get("end_byte") or 0)))
                if (rec.get("block_kind") or rec.get("kind")) == "entry" and rec.get("defs"):
                    for fn_item in entry["functions"]:
                        if fn_item["function_id"] == fn_id and not fn_item["parameters"]:
                            fn_item["parameters"] = list(rec.get("defs", ()))
            if edges_data:
                for line in edges_data.decode("utf-8").splitlines():
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    fpath = _safe_rel_path(rec.get("path"))
                    if fpath in by_path:
                        by_path[fpath]["cfg_edges"].append(rec)

    # 2. Enrich / fallback from accepted job_tree_sitter_ast SQLite analysis shards.
    if ts_shards:
        shard_set = ShardSet(run_root, [s for s in ts_shards if not str(s.get("shard_id", "")).startswith("tree-sitter-coverage-")])
        for ent in _located_entities(shard_set, kinds=("ast_node",)):
            payload = ent.get("payload") if isinstance(ent.get("payload"), Mapping) else {}
            loc = ent.get("location") if isinstance(ent.get("location"), Mapping) else {}
            fpath = _safe_rel_path(loc.get("path") or payload.get("path"))
            if fpath == "unknown":
                continue
            flang = canonical_cpg_language(payload.get("language"), fpath)
            entry = by_path.setdefault(
                fpath,
                {
                    "path": fpath,
                    "language": flang,
                    "functions": [],
                    "cfg_nodes": [],
                    "cfg_edges": [],
                    "calls": [],
                    "route_candidates": [],
                    "_fn_seen": set(),
                },
            )
            syntax = payload.get("syntax") if isinstance(payload.get("syntax"), Mapping) else {}
            cfg_blk = payload.get("cfg") if isinstance(payload.get("cfg"), Mapping) else {}
            native_type = str(payload.get("grammar_native_type") or "")
            ntype = ("function" if cfg_blk.get("function_id") or native_type in FUNCTION_NODE_TYPES.get(flang, ())
                     else str(syntax.get("category") or ""))
            if not ntype:
                ntype = str(payload.get("grammar_native_type") or "")
            written_name = str(cfg_blk.get("function_name") or syntax.get("written_name")
                               or payload.get("name") or "")
            native = loc.get("producer_location") or {}
            entry["_source_native"] = {key: native[key] for key in ("source_domain", "source_backing")
                                        if key in native}
            sline = int(loc.get("start_line") or payload.get("start_line") or 1)
            eline = int(loc.get("end_line") or payload.get("end_line") or sline)
            if ntype in {"function", "function_definition", "function_declaration", "method_declaration"}:
                fn_id = str(cfg_blk.get("function_id") or ent.get("identity") or f"{fpath}:{sline}")
                if fn_id not in entry["_fn_seen"]:
                    entry["_fn_seen"].add(fn_id)
                    entry["functions"].append(
                        {
                            "function_id": fn_id,
                            "name": written_name or "anonymous",
                            "qualified_name": str(cfg_blk.get("qualified_name") or written_name or "anonymous"),
                            "start_line": sline,
                            "end_line": eline,
                            "parameters": list(cfg_blk.get("parameters") or payload.get("parameters") or ()),
                            "signature": str(payload.get("signature") or ""),
                            "location": _source_location(loc),
                            "evidence": _evidence(ent),
                        }
                    )
                else:
                    for fn_item in entry["functions"]:
                        if fn_item["function_id"] == fn_id:
                            fn_item["start_line"] = min(int(fn_item["start_line"]), sline)
                            fn_item["end_line"] = max(int(fn_item["end_line"]), eline)
                            if cfg_blk.get("parameters") and not fn_item["parameters"]:
                                fn_item["parameters"] = list(cfg_blk["parameters"])
                            fn_item["location"] = _source_location(loc)
                            fn_item["evidence"] = _evidence(ent)
                existing_nodes = {str(n.get("node_id")) for n in entry["cfg_nodes"]}
                if payload.get("cfg_nodes"):
                    for cn in payload.get("cfg_nodes", ()):
                        if str(cn.get("node_id")) in existing_nodes:
                            continue
                        if isinstance(cn, Mapping):
                            entry["cfg_nodes"].append({**cn, "function_id": fn_id, "path": fpath, "language": flang})
                    existing_edges = {str(e.get("edge_id")) for e in entry["cfg_edges"]}
                    for ce in payload.get("cfg_edges", ()):
                        if isinstance(ce, Mapping) and str(ce.get("edge_id")) not in existing_edges:
                            entry["cfg_edges"].append({**ce, "function_id": fn_id, "path": fpath, "language": flang})
                gaps.extend(str(gap) for gap in cfg_blk.get("gaps", ()))
                if cfg_blk.get("truncated"):
                    gaps.append(f"tree_sitter_cfg_partial: {fpath}:{sline}: truncated")
            elif ntype in {"call", "call_expression", "method_invocation", "invocation_expression"}:
                entry["calls"].append(
                    {"name": written_name, "start_line": sline, "identity": ent["identity"],
                     "location": _source_location(loc)}
                )
            elif ntype == "route_candidate":
                entry["route_candidates"].append({"name": str(ent.get("name") or ""), "start_line": sline})

    out: list[dict[str, Any]] = []
    for fpath in sorted(by_path):
        rec = dict(by_path[fpath])
        rec.pop("_fn_seen", None)
        native = rec.pop("_source_native", {})
        for block in rec["cfg_nodes"]:
            if native:
                block["producer_location"] = {**dict(block.get("producer_location") or {}), **native}
        out.append(rec)
    return out


def build_run_alternate_cpg(
    run_root: Path,
    *,
    run_id: str,
    target_snapshot: str,
    upstream_shards: Sequence[Mapping[str, Any]],
    graph_shards: Sequence[Mapping[str, Any]],
    settings: AlternateCpgSettings | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Harvest accepted shards from a run and synthesize the universal Alternate CPG."""
    if settings is not None and not settings.enabled:
        return synthesize_alternate_cpg(run_id=run_id, target_snapshot=target_snapshot, settings=settings), {}
    ts_shards = [s for s in upstream_shards if (s.get("producer") or {}).get("job") == "job_tree_sitter_ast"]
    cat_shards = [
        s
        for s in upstream_shards
        if (s.get("producer") or {}).get("job") == "job_target_catalog" and s.get("name") == "source"
    ]
    clangd_shards = [
        s for s in upstream_shards if (s.get("producer") or {}).get("job") == "job_cpp_symbol_index"
    ]
    obs_shards = [
        s
        for s in upstream_shards
        if (s.get("producer") or {}).get("job") == "job_codeql_analysis" and s.get("name") == "observations"
    ]
    prio_shards = [
        s for s in upstream_shards if (s.get("producer") or {}).get("job") == "job_review_prioritization"
    ]
    gaps: list[str] = []
    ts_files = _extract_tree_sitter_files(run_root, ts_shards, target_snapshot=target_snapshot, gaps=gaps)

    file_shas: dict[str, str] = {}
    symbol_decls: list[Mapping[str, Any]] = []
    if cat_shards:
        cat_set = ShardSet(run_root, cat_shards)
        for sf in _located_entities(cat_set, kinds=("source_file",)):
            loc = sf.get("location") if isinstance(sf.get("location"), Mapping) else {}
            p = _safe_rel_path(loc.get("path") or sf.get("name"))
            sha = str(loc.get("file_sha256") or (sf.get("payload") or {}).get("sha256") or "")
            if p != "unknown" and re.fullmatch(r"[0-9a-f]{64}", sha):
                file_shas[p] = sha
        symbol_decls.extend(_located_entities(cat_set, kinds=("symbol",)))

    clangd_syms: list[Mapping[str, Any]] = []
    clangd_rels: list[Mapping[str, Any]] = []
    if clangd_shards:
        cl_set = ShardSet(run_root, clangd_shards)
        clangd_syms.extend(_located_entities(cl_set, kinds=("symbol",)))
        clangd_rels.extend(_relations_with_provenance(cl_set))

    sarif_obs: list[Mapping[str, Any]] = []
    if obs_shards:
        ob_set = ShardSet(run_root, obs_shards)
        sarif_obs.extend(_located_entities(ob_set, kinds=("tool_observation",)))

    routes: list[Mapping[str, Any]] = []
    if prio_shards:
        pr_set = ShardSet(run_root, prio_shards)
        routes.extend(_located_entities(pr_set, kinds=("review_signal", "priority_item")))
    fact_shards = [
        s
        for s in graph_shards
        if (s.get("producer") or {}).get("kind") not in {"codeql_database", "producer_neighborhood"}
    ]
    cql_facts: list[Mapping[str, Any]] = []
    cql_rels: list[Mapping[str, Any]] = []
    if fact_shards:
        g_set = ShardSet(run_root, fact_shards)
        cql_facts.extend(_located_entities(g_set))
        cql_rels.extend(_relations_with_provenance(g_set))

    for row in [*clangd_syms, *cql_facts, *symbol_decls, *routes, *sarif_obs]:
        loc = row.get("location") or {}
        path, sha = loc.get("path"), loc.get("file_sha256")
        if path and sha:
            if path in file_shas and file_shas[path] != sha:
                raise IntegrityError(f"alternate CPG conflicting accepted source identity: {path}")
            file_shas[path] = sha
    for file in ts_files:
        for fn in file.get("functions", ()):
            loc = fn.get("location") or {}
            path, sha = loc.get("path"), loc.get("file_sha256")
            if path and sha:
                if path in file_shas and file_shas[path] != sha:
                    raise IntegrityError(f"alternate CPG conflicting accepted source identity: {path}")
                file_shas[path] = sha

    cpg = synthesize_alternate_cpg(
        tree_sitter_files=ts_files,
        codeql_facts=cql_facts,
        codeql_relations=cql_rels,
        sarif_observations=sarif_obs,
        clangd_symbols=clangd_syms,
        clangd_relations=clangd_rels,
        symbol_declarations=symbol_decls,
        route_entrypoints=routes,
        run_id=run_id,
        target_snapshot=target_snapshot,
        settings=settings,
    )
    cpg["gaps"] = list(dict.fromkeys([*gaps, *cpg.get("gaps", ())]))
    return cpg, file_shas


def publish_alternate_cpg(
    run_root: Path,
    unit_root: Path,
    cpg: Mapping[str, Any],
    *,
    job_id: str,
    unit_id: str,
    file_shas: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], IndexIdentity]:
    """Write portable Alternate CPG JSONL/JSON artifacts and the indexed SQLite shard."""
    snapshot = str(cpg.get("target_snapshot") or "").strip() or ("0" * 64)
    shas = file_shas or {}
    gaps = list(cpg.get("gaps", ()))
    fingerprint = hashlib.sha256(canonical_json({
        "schema": INDEX_SCHEMA, "index": "analysis", "shard_id": ALTERNATE_CPG_SHARD_ID,
        "graph": cpg, "file_shas": dict(shas),
    })).hexdigest()

    out_dir = run_root / "data" / "code-graph" / "alternate-cpg" / fingerprint
    out_dir.mkdir(parents=True, exist_ok=True)
    nodes_path = out_dir / "cpg-nodes.jsonl"
    edges_path = out_dir / "cpg-edges.jsonl"
    paths_path = out_dir / "cpg-paths.jsonl"

    def record_payload(name: str, record: Any, label: str) -> tuple[dict[str, Any], bool]:
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if sanitize_producer_data(encoded) == encoded:
            return {name + "_json": encoded}, False
        # An opaque JSON string is subject to the index's string limit/redaction. Use
        # structured producer data rather than storing truncated, unparseable JSON.
        bounded = sanitize_producer_data({name: record})[name]
        limited = bounded != record
        if limited:
            gaps.append(f"alternate_cpg_projection_limited: {label}; full record retained in JSONL")
            for item in bounded if isinstance(bounded, list) else [bounded]:
                if isinstance(item, dict) and "exact" in item:
                    item["exact"] = False
        return {name: bounded}, limited

    node_logical_ids: dict[str, LogicalIdentity] = {}
    enriched_nodes: list[dict[str, Any]] = []
    entity_records: list[EntityRecord] = []

    for raw_n in cpg.get("nodes", ()):
        n = dict(raw_n)
        ekind = _NODE_ENTITY_KIND.get(str(n["node_kind"]), EntityKind.AST_NODE)
        lid = LogicalIdentity.derive(ekind, snapshot, {"cpg_node_id": str(n["node_id"])})
        node_logical_ids[str(n["node_id"])] = lid
        n["logical_id"] = lid.value
        enriched_nodes.append(n)

        npath = str(n.get("path") or "unknown")
        loc_obj: SourceLocation | None = None
        if npath != "unknown":
            try:
                rel_p = normalize_relative_path(npath)
                original = n.get("location") or {}
                fsha = original.get("file_sha256") or shas.get(rel_p)
                if not fsha:
                    raise ValueError("source_identity_unavailable")
                if original.get("file_sha256") and shas.get(rel_p, fsha) != fsha:
                    raise IntegrityError(f"alternate CPG conflicting source identity: {rel_p}")
                sline = max(1, int(n.get("start_line") or 1))
                eline = max(sline, int(n.get("end_line") or sline))
                location_data = dict(
                    target_snapshot=snapshot,
                    path=rel_p,
                    file_sha256=fsha,
                    start_byte=0,
                    end_byte=0,
                    start_line=sline,
                    end_line=eline,
                    start_column=1,
                    end_column=1,
                    producer_location={"node_id": str(n["node_id"])},
                    mapping_method="alternate-cpg-line-only",
                    confidence=0.5,
                    ambiguous=True,
                )
                location_data.update({k: v for k, v in _source_location(original).items()
                                      if k in SourceLocation.__dataclass_fields__})
                loc_obj = SourceLocation(**location_data)
                if not original:
                    gaps.append(f"source_span_unavailable: {npath}:{sline}: line-only alternate projection")
            except ValueError as exc:
                loc_obj = None
                gaps.append(f"source_identity_unavailable: {npath}:{n.get('start_line')}: {exc}")

        node_payload, _ = record_payload("cpg_node", n, str(n["node_id"]))
        payload = {
            "schema": ALTERNATE_CPG_SCHEMA,
            "cpg_record": "cpg_node",
            "node_id": n["node_id"],
            "node_kind": n["node_kind"],
            "language": n["language"],
            "path": npath,
            "file_path": npath,
            "start_line": n["start_line"],
            "end_line": n["end_line"],
            "function_id": n.get("function_id"),
            "block_kind": n.get("block_kind"),
            "guard_polarity": n.get("guard_polarity"),
            "sink_class": n.get("sink_class"),
            "is_entrypoint": n.get("is_entrypoint", False),
            "resolution_tier": n["resolution_tier"],
            **node_payload,
            "cpg_settings": {"max_slice_depth": int(cpg.get("max_slice_depth", 8)),
                             "max_hops": int(cpg.get("max_hops", 10))},
        }
        search_text = f"{n['node_kind']} {n['name']} {n.get('qualified_name', '')} {n['language']} {npath}"
        entity_records.append(
            EntityRecord(
                identity=lid,
                native_id=str(n["node_id"]),
                name=str(n["name"]),
                text=search_text[:512],
                payload=payload,
                location=loc_obj,
            )
        )

    # Group edges by (RelationKind, src_logical, dst_logical) so RelationRecord.relation_id never collides.
    grouped_edges: dict[tuple[RelationKind, str, str], list[dict[str, Any]]] = defaultdict(list)
    raw_edges = [dict(e) for e in cpg.get("edges", ())]
    for edge in raw_edges:
        src_lid = node_logical_ids.get(str(edge["source_id"]))
        dst_lid = node_logical_ids.get(str(edge["target_id"]))
        if src_lid is None or dst_lid is None:
            continue
        rkind = _EDGE_RELATION_KIND.get(str(edge["edge_kind"]), RelationKind.FLOWS_TO)
        grouped_edges[(rkind, src_lid.value, dst_lid.value)].append(edge)

    relation_records: list[RelationRecord] = []
    for (rkind, src_val, dst_val), elist in sorted(grouped_edges.items(), key=lambda kv: (kv[0][0].value, kv[0][1], kv[0][2])):
        elist.sort(key=lambda e: str(e["edge_id"]))
        best_tier = min((str(e["resolution_tier"]) for e in elist), key=lambda t: _TIER_RANK.get(t, 9))
        edge_payload, limited = record_payload("cpg_edges", elist, f"{src_val}->{dst_val}")
        exact = not limited and all(bool(edge.get("exact")) for edge in elist)
        relation_records.append(
            RelationRecord(
                kind=rkind,
                source_id=src_val,
                target_id=dst_val,
                exact=exact,
                confidence=0.95 if exact else 0.70,
                ambiguity=None if exact else "alternate_context_only: inexact, disputed, or unverified projection",
                payload={
                    "schema": ALTERNATE_CPG_SCHEMA,
                    "cpg_edge_kind": elist[0]["edge_kind"],
                    "resolution_tier": best_tier,
                    **edge_payload,
                },
            )
        )

    raw_paths = [dict(p) for p in cpg.get("paths", ())]
    for prec in raw_paths:
        plid = LogicalIdentity.derive(
            EntityKind.DATAFLOW_PATH, snapshot, {"cpg_path_id": str(prec["path_id"])}
        )
        path_payload, _ = record_payload("cpg_path", prec, str(prec["path_id"]))
        entity_records.append(
            EntityRecord(
                identity=plid,
                native_id=str(prec["path_id"]),
                name=f"{prec.get('source_name', '')}->{prec.get('sink_name', '')}",
                text=f"cpg_path {prec.get('source_name', '')} {prec.get('sink_name', '')} {prec.get('sink_class') or ''}",
                payload={
                    "schema": ALTERNATE_CPG_SCHEMA,
                    "cpg_record": "cpg_path",
                    "path_id": prec["path_id"],
                    "hop_count": prec["hop_count"],
                    "resolution_tier": prec["resolution_tier"],
                    "entrypoint_linked": prec["entrypoint_linked"],
                    "sink_class": prec.get("sink_class"),
                    **path_payload,
                },
                location=None,
            )
        )

    atomic_bytes(
        nodes_path,
        "".join(json.dumps(n, sort_keys=True) + "\n" for n in enriched_nodes).encode("utf-8"),
    )
    atomic_bytes(
        edges_path,
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in raw_edges).encode("utf-8"),
    )
    atomic_bytes(
        paths_path,
        "".join(json.dumps(p, sort_keys=True) + "\n" for p in raw_paths).encode("utf-8"),
    )

    shard_path = run_root / "data" / "indices" / "analysis" / ALTERNATE_CPG_SHARD_ID / f"{fingerprint}.sqlite"
    builder = IndexBuilder(
        shard_path,
        name="analysis",
        fingerprint=fingerprint,
        target_snapshot=snapshot,
        shard_id=ALTERNATE_CPG_SHARD_ID,
    )
    seen_ent: set[str] = set()
    for ent in sorted(entity_records, key=lambda item: item.identity.value):
        if ent.identity.value not in seen_ent:
            seen_ent.add(ent.identity.value)
            builder.add_entity(ent)
    seen_rel: set[str] = set()
    for rel in sorted(relation_records, key=lambda item: item.relation_id):
        if rel.relation_id not in seen_rel:
            seen_rel.add(rel.relation_id)
            builder.add_relation(rel)
    gaps = tuple(dict.fromkeys(gaps))
    builder.add_coverage("alternate_cpg", "partial" if gaps else "complete", "; ".join(gaps) or None)
    shard_sha = builder.build()

    shard_identity = IndexIdentity(
        "analysis",
        INDEX_SCHEMA,
        shard_sha,
        fingerprint,
        shard_path.relative_to(run_root).as_posix(),
        {
            "job": job_id,
            "unit": unit_id,
            "kind": "alternate_cpg",
            "schema": ALTERNATE_CPG_SCHEMA,
        },
        gaps,
        ALTERNATE_CPG_SHARD_ID,
    )

    summary_doc = {
        "schema": ALTERNATE_CPG_SCHEMA,
        "record_type": "alternate_cpg_summary",
        "run_id": str(cpg.get("run_id") or "offline"),
        "target_snapshot": snapshot,
        "languages": list(cpg.get("languages", ())),
        "max_hops": int(cpg.get("max_hops") or 10),
        "counts": dict(cpg.get("counts", {})),
        "resolution_breakdown": dict(cpg.get("resolution_breakdown", {})),
        "gaps": list(gaps),
        "max_slice_depth": int(cpg.get("max_slice_depth", 8)),
        "traversal": dict(cpg.get("traversal", {})),
        "artifacts": {
            "nodes": nodes_path.relative_to(run_root).as_posix(),
            "edges": edges_path.relative_to(run_root).as_posix(),
            "paths": paths_path.relative_to(run_root).as_posix(),
            "shard": shard_path.relative_to(run_root).as_posix(),
        },
    }
    summary_path = unit_root / "alternate-cpg-summary.json"
    atomic_json(summary_path, summary_doc)
    return summary_doc, shard_identity


def load_cpg_from_sqlite(database: sqlite3.Connection, *,
                         check_deadline: Callable[[], None] | None = None) -> dict[str, Any]:
    """Reconstruct the Alternate CPG graph from an opened ``alternate-cpg`` SQLite shard."""
    nodes: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    settings: dict[str, int] = {}
    for row in database.execute("SELECT identity, payload_json FROM entities ORDER BY identity"):
        if check_deadline:
            check_deadline()
        payload = json.loads(row["payload_json"])
        rec_type = payload.get("cpg_record")
        if rec_type == "cpg_node" and (isinstance(payload.get("cpg_node_json"), str)
                                       or isinstance(payload.get("cpg_node"), Mapping)):
            node = (dict(payload["cpg_node"]) if isinstance(payload.get("cpg_node"), Mapping)
                    else json.loads(payload["cpg_node_json"]))
            node.setdefault("logical_id", row["identity"])
            limits = payload.get("cpg_settings", {})
            for key, value in limits.items():
                settings[key] = min(settings.get(key, int(value)), int(value))
            nodes.append(node)
        elif rec_type == "cpg_path" and (isinstance(payload.get("cpg_path_json"), str)
                                         or isinstance(payload.get("cpg_path"), Mapping)):
            paths.append(dict(payload["cpg_path"]) if isinstance(payload.get("cpg_path"), Mapping)
                         else json.loads(payload["cpg_path_json"]))

    edges: list[dict[str, Any]] = []
    for row in database.execute("SELECT payload_json FROM relations ORDER BY relation_id"):
        if check_deadline:
            check_deadline()
        if not row["payload_json"]:
            continue
        payload = json.loads(row["payload_json"])
        if isinstance(payload.get("cpg_edges_json"), str) or isinstance(payload.get("cpg_edges"), list):
            records = payload["cpg_edges"] if isinstance(payload.get("cpg_edges"), list) else json.loads(
                payload["cpg_edges_json"])
            for edge in records:
                edge.setdefault("exact", False)
                edge.setdefault("evidence", [])
                edges.append(edge)

    nodes.sort(key=lambda n: str(n["node_id"]))
    edges.sort(key=lambda e: str(e["edge_id"]))
    paths.sort(key=lambda p: str(p["path_id"]))
    return {"schema": ALTERNATE_CPG_SCHEMA, "nodes": nodes, "edges": edges, "paths": paths, **settings}
