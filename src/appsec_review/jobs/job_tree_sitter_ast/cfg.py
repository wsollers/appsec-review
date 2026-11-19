"""Universal deterministic intra-procedural Tree-sitter CFG and branch guard polarity synthesizer (T-168).

Operates in pure Python over extracted Tree-sitter CST node arrays (``ordinal_path`` + byte/point spans)
or nested/summarized syntax trees across all 9 target language families:
C/C++ (``c``, ``cpp``), Java (``java``), JavaScript/TypeScript (``javascript``, ``typescript``, ``tsx``),
Python (``python``), Ruby (``ruby``), Go (``go``), C# (``csharp``), Rust (``rust``), and PHP (``php``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.storage import atomic_bytes, atomic_json, file_sha256

CFG_SCHEMA = "appsec-review/tree-sitter-cfg/1"
CFG_BUILDER_IDENTITY = "appsec-review/tree-sitter-cfg-builder/1"

EDGE_KINDS = (
    "entry",
    "true_branch",
    "false_branch",
    "unconditional",
    "loop_back",
    "break_edge",
    "continue_edge",
    "return_exit",
    "exception_edge",
    "fallthrough",
)

GUARD_POLARITIES = (
    "null_check",
    "bounds_check",
    "auth_or_role_check",
    "error_return_guard",
    "sanitization_guard",
    "general_condition",
)

LANGUAGE_GRAMMAR_ALIASES: dict[str, str] = {
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "c/c++": "cpp",
    "java": "java",
    "javascript": "javascript",
    "js": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "tsx": "tsx",
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
    "kotlin": "kotlin",
}

CANONICAL_CFG_LANGUAGE: dict[str, str] = {
    "c": "cpp",
    "cpp": "cpp",
    "java": "java",
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx": "typescript",
    "python": "python",
    "ruby": "ruby",
    "go": "go",
    "csharp": "csharp",
    "rust": "rust",
    "php": "php",
    "kotlin": "kotlin",
}

FUNCTION_NODE_TYPES: dict[str, frozenset[str]] = {
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition", "lambda_expression"}),
    "java": frozenset({"method_declaration", "constructor_declaration", "compact_constructor_declaration"}),
    "javascript": frozenset({
        "function_declaration", "function_expression", "arrow_function",
        "method_definition", "generator_function_declaration",
    }),
    "typescript": frozenset({
        "function_declaration", "function_expression", "arrow_function",
        "method_definition", "generator_function_declaration",
    }),
    "tsx": frozenset({
        "function_declaration", "function_expression", "arrow_function",
        "method_definition", "generator_function_declaration",
    }),
    "python": frozenset({"function_definition", "async_function_definition"}),
    "ruby": frozenset({"method", "singleton_method"}),
    "go": frozenset({"function_declaration", "method_declaration", "func_literal"}),
    "csharp": frozenset({"method_declaration", "constructor_declaration", "local_function_statement"}),
    "rust": frozenset({"function_item", "closure_expression"}),
    "php": frozenset({"function_definition", "method_declaration", "anonymous_function", "arrow_function"}),
    "kotlin": frozenset({"function_declaration"}),
}

CALL_NODE_TYPES: frozenset[str] = frozenset({
    "call_expression", "new_expression", "invocation_expression", "object_creation_expression",
    "method_invocation", "call", "function_call_expression", "member_call_expression",
    "scoped_call_expression", "macro_invocation",
})

IDENTIFIER_TYPES: frozenset[str] = frozenset({
    "identifier", "simple_identifier", "field_identifier", "property_identifier",
    "variable_name", "name", "shorthand_property_identifier",
})

BLOCK_WRAPPER_TYPES: frozenset[str] = frozenset({
    "compound_statement", "block", "statement_block", "body_statement", "declaration_list",
    "do_block", "then", "else", "else_clause", "consequence", "alternative",
    "switch_body", "switch_block", "match_block", "enum_body", "program", "module",
    "translation_unit", "source_file", "compilation_unit",
})

IF_TYPES: frozenset[str] = frozenset({
    "if_statement", "if_expression", "if", "unless", "elif_clause", "elsif", "else_if_clause",
    "conditional_expression", "ternary_expression",
})

SWITCH_TYPES: frozenset[str] = frozenset({
    "switch_statement", "switch_expression", "expression_switch_statement",
    "type_switch_statement", "match_statement", "match_expression", "case",
})

CASE_CLAUSE_TYPES: frozenset[str] = frozenset({
    "case_statement", "switch_section", "switch_block_statement_group", "switch_rule",
    "switch_case", "switch_default", "expression_case", "default_case", "type_case",
    "case_clause", "match_arm", "conditional_arm", "when",
})

LOOP_TYPES: frozenset[str] = frozenset({
    "while_statement", "while_expression", "while", "until", "do_statement",
    "for_statement", "for_in_statement", "for_range_loop", "enhanced_for_statement",
    "foreach_statement", "for_expression", "loop_expression", "for",
})

RETURN_TYPES: frozenset[str] = frozenset({"return_statement", "return_expression", "return"})
BREAK_TYPES: frozenset[str] = frozenset({"break_statement", "break_expression", "break"})
CONTINUE_TYPES: frozenset[str] = frozenset({"continue_statement", "continue_expression", "next"})
THROW_TYPES: frozenset[str] = frozenset({"throw_statement", "throw_expression", "raise_statement"})
TRY_TYPES: frozenset[str] = frozenset({"try_statement", "try_with_resources_statement", "begin"})
CATCH_TYPES: frozenset[str] = frozenset({"catch_clause", "except_clause", "rescue"})
FINALLY_TYPES: frozenset[str] = frozenset({"finally_clause", "ensure"})
FALLTHROUGH_STMT_TYPES: frozenset[str] = frozenset({"fallthrough_statement"})

ASSIGNMENT_TYPES: frozenset[str] = frozenset({
    "assignment_expression", "assignment", "augmented_assignment", "augmented_assignment_expression",
    "variable_declarator", "init_declarator", "short_var_declaration", "var_spec",
    "let_declaration", "local_variable_declaration", "parameter", "formal_parameter",
    "required_parameter", "optional_parameter", "simple_parameter",
})

STATEMENT_IGNORE_TYPES: frozenset[str] = frozenset({
    "comment", "line_comment", "block_comment", "{", "}", "(", ")", ";", ":", ",",
    "modifiers", "annotation", "marker_annotation", "attribute_list",
})

MAX_STATEMENT_TEXT_CHARS = 240
MAX_GUARD_EXPR_CHARS = 240
MAX_CFG_NODES_PER_FUNCTION = 2048


def cfg_builder_identity() -> dict[str, str | int]:
    return {"algorithm": CFG_BUILDER_IDENTITY, "max_nodes_per_function": MAX_CFG_NODES_PER_FUNCTION}


class _CfgLimitReached(Exception):
    pass


@dataclass
class _Transfer:
    source: str
    kind: str
    target: str | list[str]
    finally_depth: int


_AUTH_RE = re.compile(
    r"\b("
    r"is_authenticated|isauthenticated|authenticated|is_authorized|isauthorized|"
    r"has_role|hasrole|isinrole|is_in_role|check_role|checkrole|require_role|require_auth|has_authority|hasauthority|has_permission|haspermission|"
    r"check_permission|checkpermission|can_access|canaccess|authorize|check_auth|checkauth|"
    r"is_admin|isadmin|verify_token|verifytoken|validate_token|validatetoken|"
    r"verify_jwt|verifyjwt|check_csrf|verify_csrf|csrf_valid|session_valid|"
    r"securitycontext|claimsprincipal|user\.is_staff|user\.is_superuser|"
    r"req\.user|ctx\.user|current_user|\.role\b|roles\b|permissions\b"
    r")",
    re.IGNORECASE,
)

_SANITIZE_RE = re.compile(
    r"\b("
    r"sanitize|sanitise|escape|html_escape|htmlescape|htmlspecialchars|htmlentities|addslashes|escapeshellarg|escapeshellcmd|real_escape_string|pg_escape_string|dompurify|encode_for_html|shell_escape|sql_escape|"
    r"is_valid|isvalid|validate|validator|allowlist|whitelist|allowed_|safe_|"
    r"fullmatch|pattern\.matches|regexp\.match|preg_match|ctype_alnum|ctype_digit|"
    r"filter_var|filepath\.clean|path\.normalize|startswith|starts_with|hasprefix|has_prefix|"
    r"isinstance|number\.isinteger|number\.issafeinteger|tryparse|int\.tryparse"
    r")",
    re.IGNORECASE,
)

_ERROR_GUARD_RE = re.compile(
    r"("
    r"\berr\s*(!=|==)\s*nil\b|\berror\s*(!=|==)\s*nil\b|"
    r"\.is_err\s*\(|\.is_ok\s*\(|"
    r"\bFAILED\s*\(|\bSUCCEEDED\s*\(|"
    r"\b(rc|ret|rv|status|err|errno|hr|res)\s*(!=\s*0|<\s*0|>=\s*0|==\s*0|!=\s*ok\b)|"
    r"!\s*ok\b"
    r")",
    re.IGNORECASE,
)

_NULL_CHECK_RE = re.compile(
    r"("
    r"(!=|==|===|!==)\s*(null|nullptr|nil|none|undefined|intptr\.zero)\b|"
    r"\b(null|nullptr|nil|none|undefined)\s*(!=|==|===|!==)|"
    r"\bis\s+not\s+none\b|\bis\s+none\b|\bis\s+not\s+null\b|\bis\s+null\b|"
    r"\.nil\?|\.is_none\s*\(|\.is_some\s*\(|\.ispresent\s*\(|\.isempty\s*\(|"
    r"\bisset\s*\(|\bempty\s*\(|"
    r"\bsome\s*\(|\bnone\b"
    r")",
    re.IGNORECASE,
)

_BOUNDS_OP_RE = re.compile(
    r"(<=|>=|<|>|\b(len|length|size|sizeof|count|cap|capacity|max|min|limit|bound|offset|index|idx)\b)",
    re.IGNORECASE,
)

_ROUTE_HINT_RE = re.compile(
    r"(@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete|patch)\b|"
    r"@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\b|"
    r"\[(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\b|"
    r"#\[(?:get|post|put|delete|patch|route)\b|"
    r"\b(?:http\.HandleFunc|mux\.Handle|r\.(?:GET|POST|PUT|DELETE|PATCH)|"
    r"app\.(?:get|post|put|delete|patch|use)|router\.(?:get|post|put|delete|patch)|"
    r"Route::(?:get|post|put|delete|patch|any))\b)",
    re.IGNORECASE,
)

_IDENT_TOKEN_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_STOP_IDENTIFIERS = frozenset({
    "if", "else", "elif", "elsif", "unless", "while", "for", "in", "return", "true", "false",
    "null", "nullptr", "nil", "None", "none", "undefined", "and", "or", "not", "is", "new",
    "sizeof", "isset", "empty", "Some", "Ok", "Err", "let", "var", "const", "mut",
})


def normalize_grammar_name(language_or_grammar: str) -> str:
    key = str(language_or_grammar or "").strip().lower()
    return LANGUAGE_GRAMMAR_ALIASES.get(key, key)


def classify_guard_polarity(
    condition_text: str,
    *,
    early_exit: bool = False,
    language: str = "",
) -> tuple[str, str, list[str]]:
    """Classify a branch guard condition into one of the 6 canonical polarities."""
    cleaned = " ".join((condition_text or "").strip().split())
    if len(cleaned) > MAX_GUARD_EXPR_CHARS:
        cleaned = cleaned[:MAX_GUARD_EXPR_CHARS]
    identifiers = sorted({
        tok for tok in _IDENT_TOKEN_RE.findall(cleaned)
        if tok not in _STOP_IDENTIFIERS and tok.lower() not in _STOP_IDENTIFIERS
    })[:16]
    if not cleaned:
        return ("error_return_guard" if early_exit else "general_condition"), "", identifiers

    if _AUTH_RE.search(cleaned):
        return "auth_or_role_check", cleaned, identifiers
    if _SANITIZE_RE.search(cleaned):
        return "sanitization_guard", cleaned, identifiers
    if _ERROR_GUARD_RE.search(cleaned):
        return "error_return_guard", cleaned, identifiers
    if _NULL_CHECK_RE.search(cleaned):
        return "null_check", cleaned, identifiers
    if re.fullmatch(r"!\s*[A-Za-z_$][A-Za-z0-9_$.*->]*", cleaned):
        ident_lower = identifiers[0].lower() if identifiers else ""
        if ident_lower in {"err", "error", "ok", "valid", "success"} or (early_exit and ident_lower in {"res", "ret", "status"}):
            return "error_return_guard", cleaned, identifiers
        return "null_check", cleaned, identifiers
    if _BOUNDS_OP_RE.search(cleaned) and any(op in cleaned for op in ("<", ">", "<=", ">=")):
        return "bounds_check", cleaned, identifiers
    if early_exit and any(tok.lower() in {"err", "error", "fail", "failed", "invalid", "bad"} for tok in identifiers):
        return "error_return_guard", cleaned, identifiers
    return "general_condition", cleaned, identifiers


def flatten_syntax_tree(
    tree_or_nodes: Any,
    source_bytes: bytes | str | None = None,
) -> tuple[list[dict[str, Any]], bytes]:
    """Normalize either a flat CST node sequence or a nested AST dict/Node into flat ordinal nodes + bytes."""
    if isinstance(source_bytes, str):
        raw_bytes = source_bytes.encode("utf-8")
    elif isinstance(source_bytes, (bytes, bytearray)):
        raw_bytes = bytes(source_bytes)
    else:
        raw_bytes = b""

    if isinstance(tree_or_nodes, Sequence) and not isinstance(tree_or_nodes, (bytes, bytearray, str)):
        items = list(tree_or_nodes)
        if not items:
            return [], raw_bytes
        if isinstance(items[0], Mapping) and "ordinal_path" in items[0] and "children" not in items[0]:
            normalized = []
            for item in items:
                start_pt = list(item.get("start_point") or [max(0, int(item.get("start_line", 1)) - 1), 0])
                end_pt = list(item.get("end_point") or [max(0, int(item.get("end_line", start_pt[0] + 1)) - 1), 0])
                normalized.append({
                    "ordinal_path": [int(x) for x in item["ordinal_path"]],
                    "field": item.get("field"),
                    "type": str(item["type"]),
                    "named": bool(item.get("named", True)),
                    "missing": bool(item.get("missing", False)),
                    "start_byte": int(item.get("start_byte", 0)),
                    "end_byte": int(item.get("end_byte", 0)),
                    "start_point": start_pt,
                    "end_point": end_pt,
                    "text": item.get("text"),
                })
            return normalized, raw_bytes

    root_obj = getattr(tree_or_nodes, "root_node", tree_or_nodes)
    chunks: list[bytes] = []
    synthesized_offsets = len(raw_bytes) == 0
    cursor_byte = 0
    flat: list[dict[str, Any]] = []

    def visit(node: Any, ordinal: tuple[int, ...], field_name: str | None, line_hint: int) -> tuple[int, int, int, int]:
        nonlocal cursor_byte
        if isinstance(node, Mapping):
            ntype = str(node.get("type", "unknown"))
            field_val = node.get("field", field_name)
            named = bool(node.get("named", True))
            missing = bool(node.get("missing", False))
            children = list(node.get("children") or ())
            node_text = node.get("text")
            sb = node.get("start_byte")
            eb = node.get("end_byte")
            sl = int(node.get("start_line", line_hint))
            el = int(node.get("end_line", sl))
        else:
            ntype = str(getattr(node, "type", "unknown"))
            field_val = field_name
            named = bool(getattr(node, "is_named", True))
            missing = bool(getattr(node, "is_missing", False))
            raw_children = list(getattr(node, "children", ()) or ())
            children = []
            for idx, ch in enumerate(raw_children):
                ch_field = node.field_name_for_child(idx) if hasattr(node, "field_name_for_child") else None
                children.append((ch, ch_field))
            node_text = None
            sb = getattr(node, "start_byte", None)
            eb = getattr(node, "end_byte", None)
            sp = getattr(node, "start_point", (line_hint - 1, 0))
            ep = getattr(node, "end_point", sp)
            sl, el = int(sp[0]) + 1, int(ep[0]) + 1

        idx_pos = len(flat)
        flat.append({})
        child_starts: list[int] = []
        child_ends: list[int] = []
        cur_line = sl
        for c_idx, child_entry in enumerate(children):
            if isinstance(child_entry, tuple) and len(child_entry) == 2 and not isinstance(child_entry[0], (int, str)):
                ch_node, ch_field = child_entry
            else:
                ch_node, ch_field = child_entry, (child_entry.get("field") if isinstance(child_entry, Mapping) else None)
            csb, ceb, csl, cel = visit(ch_node, (*ordinal, c_idx), ch_field, cur_line)
            child_starts.append(csb)
            child_ends.append(ceb)
            cur_line = max(cur_line, cel)

        if synthesized_offsets:
            if isinstance(node_text, str) and not children:
                encoded = node_text.encode("utf-8")
                start_b = cursor_byte
                chunks.append(encoded + b" ")
                cursor_byte += len(encoded) + 1
                end_b = start_b + len(encoded)
            elif child_starts:
                start_b = child_starts[0]
                end_b = child_ends[-1]
            else:
                encoded = (str(node_text) if node_text is not None else "").encode("utf-8")
                start_b = cursor_byte
                chunks.append(encoded + b" ")
                cursor_byte += len(encoded) + 1
                end_b = start_b + len(encoded)
        else:
            start_b = int(sb if sb is not None else (child_starts[0] if child_starts else 0))
            end_b = int(eb if eb is not None else (child_ends[-1] if child_ends else start_b))

        end_line_final = max(el, cur_line)
        flat[idx_pos] = {
            "ordinal_path": list(ordinal),
            "field": field_val,
            "type": ntype,
            "named": named,
            "missing": missing,
            "start_byte": start_b,
            "end_byte": end_b,
            "start_point": [max(0, sl - 1), 0],
            "end_point": [max(0, end_line_final - 1), 0],
            "text": node_text if isinstance(node_text, str) else None,
        }
        return start_b, end_b, sl, end_line_final

    visit(root_obj, (), None, 1)
    if synthesized_offsets:
        raw_bytes = b"".join(chunks)
    return flat, raw_bytes


@dataclass(frozen=True)
class GuardDominator:
    branch_node_id: str
    branch_ast_identity: str | None
    branch_arm: str
    guard_expression: str
    guard_polarity: str
    guarded_identifiers: tuple[str, ...]
    start_line: int
    end_line: int
    early_exit: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "branch_node_id": self.branch_node_id,
            "branch_ast_identity": self.branch_ast_identity,
            "branch_arm": self.branch_arm,
            "guard_expression": self.guard_expression,
            "guard_polarity": self.guard_polarity,
            "guarded_identifiers": list(self.guarded_identifiers),
            "start_line": self.start_line,
            "end_line": self.end_line,
            "early_exit": self.early_exit,
        }


@dataclass
class CfgNode:
    node_id: str
    function_id: str
    function_name: str
    kind: str
    ast_type: str
    language: str
    source_identity: str
    path: str
    file_sha256: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    ordinal_path: tuple[int, ...] = ()
    ast_identity: str | None = None
    statement_text: str = ""
    guard_expression: str | None = None
    guard_polarity: str | None = None
    guarded_identifiers: tuple[str, ...] = ()
    early_exit: bool = False
    calls: tuple[str, ...] = ()
    defs: tuple[str, ...] = ()
    uses: tuple[str, ...] = ()
    guard_dominators: tuple[GuardDominator, ...] = ()

    def to_jsonl_record(self) -> dict[str, Any]:
        return {
            "schema": CFG_SCHEMA,
            "record_type": "cfg_node",
            "node_id": self.node_id,
            "ast_identity": self.ast_identity,
            "function_id": self.function_id,
            "function_name": self.function_name,
            "kind": self.kind,
            "ast_type": self.ast_type,
            "language": self.language,
            "source_identity": self.source_identity,
            "path": self.path,
            "file_sha256": self.file_sha256,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "ordinal_path": list(self.ordinal_path),
            "statement_text": self.statement_text,
            "guard_expression": self.guard_expression,
            "guard_polarity": self.guard_polarity,
            "calls": list(self.calls),
            "defs": list(self.defs),
            "uses": list(self.uses),
            "guard_dominators": [g.to_dict() for g in self.guard_dominators],
        }


@dataclass(frozen=True)
class CfgEdge:
    edge_id: str
    function_id: str
    source_node_id: str
    target_node_id: str
    edge_kind: str
    language: str
    source_identity: str
    path: str
    guard_expression: str | None = None
    guard_polarity: str | None = None

    def to_jsonl_record(self) -> dict[str, Any]:
        return {
            "schema": CFG_SCHEMA,
            "record_type": "cfg_edge",
            "edge_id": self.edge_id,
            "function_id": self.function_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_kind": self.edge_kind,
            "language": self.language,
            "source_identity": self.source_identity,
            "path": self.path,
            "guard_expression": self.guard_expression,
            "guard_polarity": self.guard_polarity,
        }


@dataclass
class FunctionCfg:
    function_id: str
    ast_identity: str | None
    function_name: str
    qualified_name: str
    language: str
    grammar: str
    source_identity: str
    path: str
    file_sha256: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    ordinal_path: tuple[int, ...]
    entry_node_id: str
    exit_node_id: str
    nodes: list[CfgNode]
    edges: list[CfgEdge]
    dominators: dict[str, tuple[str, ...]] = field(default_factory=dict)
    ordinal_to_node_id: dict[tuple[int, ...], str] = field(default_factory=dict)
    ordinal_guard_dominators: dict[tuple[int, ...], tuple[GuardDominator, ...]] = field(default_factory=dict)
    parameters: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()
    is_entrypoint_candidate: bool = False
    entrypoint_route: str | None = None
    truncated: bool = False
    unmodeled_constructs: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()

    @property
    def guard_count(self) -> int:
        return sum(1 for node in self.nodes if node.guard_polarity is not None)

    def to_summary(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "ast_identity": self.ast_identity,
            "function_name": self.function_name,
            "qualified_name": self.qualified_name,
            "language": self.language,
            "source_identity": self.source_identity,
            "path": self.path,
            "file_sha256": self.file_sha256,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "entry_node_id": self.entry_node_id,
            "exit_node_id": self.exit_node_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "guard_count": self.guard_count,
            "parameters": list(self.parameters),
            "decorators": list(self.decorators),
            "is_entrypoint_candidate": self.is_entrypoint_candidate,
            "entrypoint_route": self.entrypoint_route,
            "coverage_status": "partial" if self.gaps else "complete",
            "truncated": self.truncated,
            "unmodeled_constructs": list(self.unmodeled_constructs),
            "gaps": list(self.gaps),
        }

    def to_entity_payload(self) -> dict[str, Any]:
        return {
            "schema": CFG_SCHEMA,
            **self.to_summary(),
            "nodes": [node.to_jsonl_record() for node in self.nodes],
            "edges": [edge.to_jsonl_record() for edge in self.edges],
        }


@dataclass
class FileCfgResult:
    path: str
    language: str
    grammar: str
    source_identity: str
    file_sha256: str
    functions: list[FunctionCfg]

    @property
    def total_nodes(self) -> int:
        return sum(len(fn.nodes) for fn in self.functions)

    @property
    def total_edges(self) -> int:
        return sum(len(fn.edges) for fn in self.functions)

    @property
    def total_guards(self) -> int:
        return sum(fn.guard_count for fn in self.functions)


def compute_dominators(entry_id: str, node_ids: Sequence[str], edges: Sequence[CfgEdge]) -> dict[str, set[str]]:
    """Compute iterative dataflow dominators ``dom[n]`` from ``entry_id``."""
    all_nodes = list(dict.fromkeys(node_ids))
    preds: dict[str, list[str]] = {nid: [] for nid in all_nodes}
    succs: dict[str, list[str]] = {nid: [] for nid in all_nodes}
    for edge in edges:
        if edge.source_node_id in preds and edge.target_node_id in preds:
            preds[edge.target_node_id].append(edge.source_node_id)
            succs[edge.source_node_id].append(edge.target_node_id)

    reachable: list[str] = []
    seen: set[str] = set()
    stack = [entry_id]
    while stack:
        cur = stack.pop()
        if cur in seen or cur not in succs:
            continue
        seen.add(cur)
        reachable.append(cur)
        for nxt in reversed(succs[cur]):
            if nxt not in seen:
                stack.append(nxt)

    reach_set = set(reachable)
    dom: dict[str, set[str]] = {entry_id: {entry_id}}
    for nid in reachable:
        if nid != entry_id:
            dom[nid] = set(reach_set)

    changed = True
    while changed:
        changed = False
        for nid in reachable:
            if nid == entry_id:
                continue
            valid_preds = [p for p in preds[nid] if p in dom]
            if not valid_preds:
                new_dom = {nid}
            else:
                inter = set(dom[valid_preds[0]])
                for p in valid_preds[1:]:
                    inter &= dom[p]
                new_dom = {nid} | inter
            if new_dom != dom[nid]:
                dom[nid] = new_dom
                changed = True

    for nid in all_nodes:
        dom.setdefault(nid, {nid})
    return dom


def compute_guard_dominators(
    entry_id: str,
    exit_id: str,
    nodes: Sequence[CfgNode],
    edges: Sequence[CfgEdge],
    dominators: Mapping[str, set[str]],
) -> dict[str, tuple[GuardDominator, ...]]:
    """Compute ordered branch guards that strictly control-dominate each node."""
    by_id = {n.node_id: n for n in nodes}
    node_order = {n.node_id: idx for idx, n in enumerate(nodes)}
    forward_adj: dict[str, list[CfgEdge]] = {n.node_id: [] for n in nodes}
    for edge in edges:
        if edge.edge_kind == "loop_back":
            continue
        if edge.source_node_id in forward_adj:
            forward_adj[edge.source_node_id].append(edge)

    branch_arms: dict[str, list[CfgEdge]] = {}
    for node in nodes:
        if node.guard_polarity is None:
            continue
        arms = [
            e for e in forward_adj.get(node.node_id, ())
            if e.edge_kind in {"true_branch", "false_branch"}
        ]
        if arms:
            branch_arms[node.node_id] = arms

    arm_reach: dict[tuple[str, str], set[str]] = {}
    for b_id, arms in branch_arms.items():
        for arm in arms:
            key = (b_id, arm.edge_kind)
            visited = arm_reach.setdefault(key, set())
            queue = [arm.target_node_id]
            while queue:
                cur = queue.pop()
                if cur in visited or cur == b_id or cur == exit_id:
                    continue
                visited.add(cur)
                for nxt_edge in forward_adj.get(cur, ()):
                    if nxt_edge.target_node_id not in visited:
                        queue.append(nxt_edge.target_node_id)

    result: dict[str, tuple[GuardDominator, ...]] = {}
    for node in nodes:
        nid = node.node_id
        if nid in {entry_id, exit_id}:
            result[nid] = ()
            continue
        strict_doms = sorted(
            (d for d in dominators.get(nid, set()) if d != nid and d in branch_arms),
            key=lambda d: node_order.get(d, 0),
        )
        guards: list[GuardDominator] = []
        for b_id in strict_doms:
            b_node = by_id[b_id]
            reaching_arms = [
                arm_kind for arm_kind in ("true_branch", "false_branch")
                if nid in arm_reach.get((b_id, arm_kind), set())
            ]
            if len(reaching_arms) == 1:
                guards.append(
                    GuardDominator(
                        branch_node_id=b_id,
                        branch_ast_identity=b_node.ast_identity,
                        branch_arm=reaching_arms[0],
                        guard_expression=b_node.guard_expression or "",
                        guard_polarity=b_node.guard_polarity or "general_condition",
                        guarded_identifiers=b_node.guarded_identifiers,
                        start_line=b_node.start_line,
                        end_line=b_node.end_line,
                        early_exit=b_node.early_exit,
                    )
                )
        result[nid] = tuple(guards)
    return result


def synthesize_file_cfg(
    nodes_or_tree: Any,
    source_bytes: bytes | str | None = None,
    *,
    language: str,
    path: str = "<memory>",
    file_sha256: str = "0" * 64,
    source_identity: str = "asr:source_file:memory",
    ast_identities: Mapping[tuple[int, ...], str] | None = None,
) -> FileCfgResult:
    """Build deterministic intra-procedural CFGs and guard polarities for all functions in one file."""
    grammar = normalize_grammar_name(language)
    canonical_lang = CANONICAL_CFG_LANGUAGE.get(grammar, grammar)
    flat_nodes, raw_bytes = flatten_syntax_tree(nodes_or_tree, source_bytes)
    if not flat_nodes:
        return FileCfgResult(path, canonical_lang, grammar, source_identity, file_sha256, [])

    by_ordinal: dict[tuple[int, ...], dict[str, Any]] = {
        tuple(int(v) for v in item["ordinal_path"]): item for item in flat_nodes
    }
    children: dict[tuple[int, ...], list[dict[str, Any]]] = {}
    for ordinal, item in sorted(by_ordinal.items()):
        if ordinal:
            children.setdefault(ordinal[:-1], []).append(item)

    ast_id_map = dict(ast_identities or {})

    def slice_text(node: Mapping[str, Any], max_chars: int = MAX_STATEMENT_TEXT_CHARS) -> str:
        explicit = node.get("text")
        if isinstance(explicit, str) and explicit.strip():
            txt = " ".join(explicit.strip().split())
            return txt[:max_chars]
        sb, eb = int(node.get("start_byte", 0)), int(node.get("end_byte", 0))
        if 0 <= sb <= eb <= len(raw_bytes) and eb > sb:
            txt = " ".join(raw_bytes[sb:eb].decode("utf-8", errors="replace").strip().split())
            return txt[:max_chars]
        return str(node.get("type", ""))[:max_chars]

    def subtree_ordinals(root_ord: tuple[int, ...], stop_functions: set[tuple[int, ...]]) -> list[tuple[int, ...]]:
        out: list[tuple[int, ...]] = []
        stack = [root_ord]
        while stack:
            cur = stack.pop()
            if cur != root_ord and cur in stop_functions:
                continue
            out.append(cur)
            for ch in reversed(children.get(cur, ())):
                stack.append(tuple(int(v) for v in ch["ordinal_path"]))
        return out

    fn_types = FUNCTION_NODE_TYPES.get(grammar, frozenset())
    fn_ordinals = sorted(
        ord_path for ord_path, item in by_ordinal.items()
        if str(item["type"]) in fn_types
    )
    fn_ordinal_set = set(fn_ordinals)

    def extract_function_name_and_meta(
        fn_ord: tuple[int, ...],
    ) -> tuple[str, str, tuple[str, ...], tuple[str, ...], bool, str | None]:
        fn_node = by_ordinal[fn_ord]
        name = ""
        probe = fn_ord
        for _ in range(8):
            ch_list = children.get(probe, ())
            named_child = next(
                (c for f in ("name", "declarator", "property", "field") for c in ch_list if c.get("field") == f),
                None,
            )
            if named_child is None:
                id_child = next((c for c in ch_list if c["type"] in IDENTIFIER_TYPES), None)
                if id_child is not None:
                    name = slice_text(id_child, 128)
                break
            if named_child["type"] in IDENTIFIER_TYPES:
                name = slice_text(named_child, 128)
                break
            probe = tuple(int(v) for v in named_child["ordinal_path"])
        if not name:
            line_no = int(fn_node["start_point"][0]) + 1
            name = f"<anonymous@{line_no}>"

        qualifiers: list[str] = []
        for depth in range(1, len(fn_ord)):
            anc_ord = fn_ord[:depth]
            anc = by_ordinal.get(anc_ord)
            if anc is None:
                continue
            atype = str(anc["type"])
            if atype in {
                "class_declaration", "class_definition", "class_specifier", "class",
                "module", "namespace_definition", "namespace_declaration", "impl_item",
                "interface_declaration", "struct_specifier", "struct_item",
            }:
                anc_id = next(
                    (c for c in children.get(anc_ord, ()) if c.get("field") in {"name", "type"} or c["type"] in IDENTIFIER_TYPES | {"type_identifier", "constant"}),
                    None,
                )
                if anc_id is not None:
                    qtxt = slice_text(anc_id, 80)
                    if qtxt:
                        qualifiers.append(qtxt)
        qualified = "::".join([*qualifiers, name]) if qualifiers else name

        params: list[str] = []
        for ch in children.get(fn_ord, ()):
            if ch.get("field") in {"parameters", "formal_parameters", "parameter_list"} or "parameter" in str(ch["type"]):
                for ord_p in subtree_ordinals(tuple(int(v) for v in ch["ordinal_path"]), fn_ordinal_set):
                    pnode = by_ordinal[ord_p]
                    if pnode["type"] in IDENTIFIER_TYPES and len(params) < 16:
                        ptxt = slice_text(pnode, 64)
                        if ptxt and ptxt not in params and ptxt != name:
                            params.append(ptxt)

        decorators: list[str] = []
        check_ords = [fn_ord]
        if fn_ord:
            parent = by_ordinal.get(fn_ord[:-1])
            if parent and str(parent["type"]) in {"decorated_definition", "export_statement", "declaration"}:
                check_ords.append(fn_ord[:-1])
        if fn_ord:
            siblings = children.get(fn_ord[:-1], ())
            pos = next((i for i, s in enumerate(siblings) if tuple(int(v) for v in s["ordinal_path"]) == fn_ord), -1)
            for back in range(max(0, pos - 3), pos):
                sib = siblings[back]
                if any(k in str(sib["type"]) for k in ("attribute", "decorator", "annotation")):
                    decorators.append(slice_text(sib, 160))
        for cord in check_ords:
            for ch in children.get(cord, ()):
                ctype = str(ch["type"])
                if any(k in ctype for k in ("decorator", "annotation", "attribute", "modifiers")):
                    dtxt = slice_text(ch, 160)
                    if dtxt and dtxt not in decorators:
                        decorators.append(dtxt)

        joined_meta = " ".join(decorators) + " " + name
        is_entry = bool(_ROUTE_HINT_RE.search(joined_meta)) or name in {
            "main", "ServeHTTP", "doGet", "doPost", "doPut", "doDelete", "handle", "handler",
        }
        route_str = decorators[0] if (decorators and _ROUTE_HINT_RE.search(" ".join(decorators))) else None
        return name, qualified, tuple(params), tuple(decorators[:8]), is_entry, route_str

    def extract_calls_defs_uses(
        stmt_ord: tuple[int, ...],
        stop_ords: set[tuple[int, ...]],
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        calls: list[str] = []
        defs: list[str] = []
        uses: list[str] = []
        def_ords: set[tuple[int, ...]] = set()
        sub_ords = subtree_ordinals(stmt_ord, fn_ordinal_set | stop_ords)
        for ord_cur in sub_ords:
            item = by_ordinal[ord_cur]
            itype = str(item["type"])
            if itype in CALL_NODE_TYPES:
                ch_list = children.get(ord_cur, ())
                callee = next(
                    (c for f in ("function", "name", "method", "member", "constructor") for c in ch_list if c.get("field") == f),
                    None,
                )
                if callee is None and ch_list:
                    callee = next((c for c in ch_list if c.get("named", True)), ch_list[0])
                if callee is not None:
                    cname = slice_text(callee, 96).split("(")[0].strip()
                    if cname and cname not in calls and len(calls) < 16:
                        calls.append(cname)
            elif itype in ASSIGNMENT_TYPES:
                ch_list = children.get(ord_cur, ())
                lhs = next(
                    (c for f in ("left", "name", "declarator", "pattern") for c in ch_list if c.get("field") == f),
                    None,
                )
                if lhs is None and ch_list:
                    lhs = next((c for c in ch_list if c["type"] in IDENTIFIER_TYPES), None)
                if lhs is not None:
                    lhs_ord = tuple(int(v) for v in lhs["ordinal_path"])
                    for id_ord in subtree_ordinals(lhs_ord, fn_ordinal_set):
                        if by_ordinal[id_ord]["type"] in IDENTIFIER_TYPES:
                            def_ords.add(id_ord)
                            dname = slice_text(by_ordinal[id_ord], 64)
                            if dname and dname not in _STOP_IDENTIFIERS and dname not in defs and len(defs) < 16:
                                defs.append(dname)
        for ord_cur in sub_ords:
            if ord_cur in def_ords:
                continue
            item = by_ordinal[ord_cur]
            if str(item["type"]) in IDENTIFIER_TYPES:
                uname = slice_text(item, 64)
                if uname and uname not in _STOP_IDENTIFIERS and uname not in calls and uname not in uses and len(uses) < 24:
                    uses.append(uname)
        return tuple(calls), tuple(defs), tuple(uses)

    functions_out: list[FunctionCfg] = []

    for fn_ord in fn_ordinals:
        fn_raw = by_ordinal[fn_ord]
        fn_name, qualified_name, params, decorators, is_entry, route_str = extract_function_name_and_meta(fn_ord)
        fn_start_line = int(fn_raw["start_point"][0]) + 1
        fn_end_line = int(fn_raw["end_point"][0]) + 1
        fn_sb = int(fn_raw["start_byte"])
        fn_eb = int(fn_raw["end_byte"])
        fn_hash = hashlib.sha256(
            f"{source_identity}:{path}:{fn_ord}:{fn_name}:{fn_sb}:{fn_eb}".encode("utf-8")
        ).hexdigest()[:20]
        fn_id = f"cfgfn:{fn_hash}"
        fn_ast_id = ast_id_map.get(fn_ord)

        nodes_acc: list[CfgNode] = []
        edges_acc: list[CfgEdge] = []
        seen_edges: set[tuple[str, str, str]] = set()
        ord_to_block: dict[tuple[int, ...], str] = {}
        cfg_gaps: set[str] = set()
        unmodeled: set[str] = set()
        truncated = False

        def note_unmodeled(root: tuple[int, ...], stop: set[tuple[int, ...]] | None = None) -> None:
            control_types = IF_TYPES | LOOP_TYPES | SWITCH_TYPES | TRY_TYPES | RETURN_TYPES | BREAK_TYPES | CONTINUE_TYPES | THROW_TYPES
            for sub in subtree_ordinals(root, fn_ordinal_set | (stop or set())):
                if not by_ordinal[sub].get("named", True):
                    continue
                typ = str(by_ordinal[sub]["type"])
                if typ in {"goto_statement", "labeled_statement"} or (sub != root and typ in control_types):
                    unmodeled.add(typ)
                    cfg_gaps.add(f"cfg_unmodeled_construct:{typ}")

        def make_node(
            kind: str,
            ast_node: Mapping[str, Any],
            *,
            stmt_text: str = "",
            guard_expr: str | None = None,
            guard_pol: str | None = None,
            guarded_ids: tuple[str, ...] = (),
            early_exit: bool = False,
            calls: tuple[str, ...] = (),
            defs: tuple[str, ...] = (),
            uses: tuple[str, ...] = (),
            suffix: str = "",
        ) -> CfgNode:
            idx = len(nodes_acc)
            if idx >= MAX_CFG_NODES_PER_FUNCTION:
                raise _CfgLimitReached
            ord_t = tuple(int(v) for v in ast_node["ordinal_path"])
            nid = f"{fn_id}:n{idx}{suffix}"
            sl = int(ast_node["start_point"][0]) + 1
            el = max(sl, int(ast_node["end_point"][0]) + 1)
            sb = int(ast_node["start_byte"])
            eb = max(sb, int(ast_node["end_byte"]))
            cnode = CfgNode(
                node_id=nid,
                function_id=fn_id,
                function_name=fn_name,
                kind=kind,
                ast_type=str(ast_node["type"]),
                language=canonical_lang,
                source_identity=source_identity,
                path=path,
                file_sha256=file_sha256,
                start_line=sl,
                end_line=el,
                start_byte=sb,
                end_byte=eb,
                ordinal_path=ord_t,
                ast_identity=ast_id_map.get(ord_t),
                statement_text=stmt_text,
                guard_expression=guard_expr,
                guard_polarity=guard_pol,
                guarded_identifiers=guarded_ids,
                early_exit=early_exit,
                calls=calls,
                defs=defs,
                uses=uses,
            )
            nodes_acc.append(cnode)
            if ord_t and kind not in {"entry", "exit"}:
                ord_to_block.setdefault(ord_t, nid)
            return cnode

        def add_edge(
            src_id: str,
            dst_id: str,
            edge_kind: str,
            *,
            guard_expr: str | None = None,
            guard_pol: str | None = None,
        ) -> None:
            key = (src_id, dst_id, edge_kind)
            if key in seen_edges:
                return
            seen_edges.add(key)
            eid = f"{fn_id}:e{len(edges_acc)}"
            edges_acc.append(
                CfgEdge(
                    edge_id=eid,
                    function_id=fn_id,
                    source_node_id=src_id,
                    target_node_id=dst_id,
                    edge_kind=edge_kind,
                    language=canonical_lang,
                    source_identity=source_identity,
                    path=path,
                    guard_expression=guard_expr,
                    guard_polarity=guard_pol,
                )
            )

        entry_node = make_node("entry", fn_raw, stmt_text=f"ENTRY {qualified_name}", defs=params, suffix=":entry")
        exit_node = make_node("exit", fn_raw, stmt_text=f"EXIT {qualified_name}", suffix=":exit")

        fn_children = children.get(fn_ord, ())
        body_child = next((c for c in fn_children if c.get("field") == "body"), None)
        if body_child is None:
            body_child = next((c for c in fn_children if str(c["type"]) in BLOCK_WRAPPER_TYPES), None)
        if body_child is None and fn_children:
            body_child = fn_children[-1]

        break_fixups: list[tuple[list[str], int]] = []
        loop_headers: list[tuple[str, int]] = []
        catch_targets: list[tuple[list[str], int]] = []
        finalizers: list[list[_Transfer]] = []

        def transfer(source: str, kind: str, target: str | list[str], depth: int) -> None:
            if len(finalizers) > depth:
                finalizers[-1].append(_Transfer(source, kind, target, depth))
            elif isinstance(target, list):
                target.append(source)
            else:
                add_edge(source, target, kind)

        def exceptional(source: str) -> None:
            targets, depth = catch_targets[-1] if catch_targets else ([exit_node.node_id], 0)
            for target in targets:
                transfer(source, "exception_edge", target, depth)

        def executable_wrapper(ord_path: tuple[int, ...]) -> tuple[int, ...] | None:
            if grammar != "rust" or by_ordinal[ord_path]["type"] != "expression_statement":
                return None
            named = [c for c in children.get(ord_path, ())
                     if c.get("named", True) and str(c["type"]) not in STATEMENT_IGNORE_TYPES]
            if len(named) == 1 and str(named[0]["type"]) in (
                IF_TYPES | LOOP_TYPES | SWITCH_TYPES | RETURN_TYPES | BREAK_TYPES | CONTINUE_TYPES | BLOCK_WRAPPER_TYPES
            ):
                return tuple(int(v) for v in named[0]["ordinal_path"])
            return None

        def subtree_has_always_exit(target_ord: tuple[int, ...]) -> bool:
            wrapped = executable_wrapper(target_ord)
            if wrapped is not None:
                return subtree_has_always_exit(wrapped)
            node = by_ordinal[target_ord]
            ntype = str(node["type"])
            if ntype in RETURN_TYPES | THROW_TYPES | BREAK_TYPES | CONTINUE_TYPES:
                return True
            if ntype in BLOCK_WRAPPER_TYPES:
                named_stmts = [
                    c for c in children.get(target_ord, ())
                    if c.get("named", True) and str(c["type"]) not in STATEMENT_IGNORE_TYPES
                ]
                if named_stmts:
                    last_ord = tuple(int(v) for v in named_stmts[-1]["ordinal_path"])
                    return subtree_has_always_exit(last_ord)
            return False

        def build_seq(
            stmts: Sequence[dict[str, Any]],
            incoming: list[tuple[str, str, str | None, str | None]],
        ) -> list[tuple[str, str, str | None, str | None]]:
            cur = list(incoming)
            for stmt in stmts:
                if not cur:
                    break
                cur = build_stmt(tuple(int(v) for v in stmt["ordinal_path"]), cur)
            return cur

        def connect_incoming(
            incoming: Sequence[tuple[str, str, str | None, str | None]],
            target_id: str,
        ) -> None:
            for src_id, ekind, gexpr, gpol in incoming:
                add_edge(src_id, target_id, ekind, guard_expr=gexpr, guard_pol=gpol)

        def condition_child_of(ord_path: tuple[int, ...]) -> dict[str, Any] | None:
            ch_list = children.get(ord_path, ())
            cond = next(
                (c for f in ("condition", "value", "subject", "test", "left") for c in ch_list if c.get("field") == f),
                None,
            )
            if cond is not None:
                return None if cond.get("missing") else cond
            for c in ch_list:
                ctype = str(c["type"])
                if (
                    c.get("named", True)
                    and not c.get("missing")
                    and ctype not in BLOCK_WRAPPER_TYPES | CASE_CLAUSE_TYPES | CATCH_TYPES | FINALLY_TYPES | STATEMENT_IGNORE_TYPES
                    and ctype not in IF_TYPES
                    and c.get("field") not in {"body", "consequence", "alternative", "label"}
                ):
                    return c
            return None

        def build_stmt(
            stmt_ord: tuple[int, ...],
            incoming: list[tuple[str, str, str | None, str | None]],
        ) -> list[tuple[str, str, str | None, str | None]]:
            if stmt_ord != fn_ord and stmt_ord in fn_ordinal_set:
                return incoming
            node = by_ordinal[stmt_ord]
            ntype = str(node["type"])
            if not node.get("named", True) or ntype in STATEMENT_IGNORE_TYPES:
                return incoming
            wrapped = executable_wrapper(stmt_ord)
            if wrapped is not None:
                return build_stmt(wrapped, incoming)

            if ntype in BLOCK_WRAPPER_TYPES:
                inner = [
                    c for c in children.get(stmt_ord, ())
                    if c.get("named", True) and str(c["type"]) not in STATEMENT_IGNORE_TYPES
                ]
                return build_seq(inner, incoming)

            if ntype in IF_TYPES:
                ch_list = children.get(stmt_ord, ())
                cond_node = condition_child_of(stmt_ord)
                cond_text = slice_text(cond_node, MAX_GUARD_EXPR_CHARS) if cond_node is not None else None
                cons = next((c for f in ("consequence", "body", "then") for c in ch_list if c.get("field") == f), None)
                alt = next((c for f in ("alternative", "else") for c in ch_list if c.get("field") == f), None)
                if cons is None:
                    blocks = [
                        c for c in ch_list
                        if c is not cond_node and c.get("named", True) and str(c["type"]) not in STATEMENT_IGNORE_TYPES
                    ]
                    if blocks:
                        cons = blocks[0]
                    if len(blocks) > 1 and alt is None:
                        alt = blocks[1]

                cons_ord = tuple(int(v) for v in cons["ordinal_path"]) if cons is not None else None
                early_exit = subtree_has_always_exit(cons_ord) if cons_ord is not None else False
                if cond_text is None:
                    cfg_gaps.add(f"cfg_missing_condition:{ntype}")
                    polarity, norm_expr, guarded_ids = None, None, []
                else:
                    polarity, norm_expr, guarded_ids = classify_guard_polarity(
                        cond_text, early_exit=early_exit, language=canonical_lang
                    )
                stop_sub: set[tuple[int, ...]] = set()
                if cons_ord is not None:
                    stop_sub.add(cons_ord)
                if alt is not None:
                    stop_sub.add(tuple(int(v) for v in alt["ordinal_path"]))
                b_calls, b_defs, b_uses = extract_calls_defs_uses(stmt_ord, stop_sub)
                note_unmodeled(stmt_ord, stop_sub)
                b_node = make_node(
                    "branch",
                    node,
                    stmt_text=f"if ({norm_expr})" if ntype != "unless" else f"unless ({norm_expr})",
                    guard_expr=norm_expr,
                    guard_pol=polarity,
                    guarded_ids=tuple(guarded_ids),
                    early_exit=early_exit,
                    calls=b_calls,
                    defs=b_defs,
                    uses=b_uses,
                )
                connect_incoming(incoming, b_node.node_id)
                if (catch_targets or finalizers) and b_calls:
                    exceptional(b_node.node_id)

                is_unless = ntype == "unless"
                cons_edge = "false_branch" if is_unless else "true_branch"
                alt_edge = "true_branch" if is_unless else "false_branch"

                out_tails: list[tuple[str, str, str | None, str | None]] = []
                if cons_ord is not None:
                    cons_tails = build_stmt(cons_ord, [(b_node.node_id, cons_edge, norm_expr, polarity)])
                    out_tails.extend(cons_tails)
                else:
                    out_tails.append((b_node.node_id, cons_edge, norm_expr, polarity))

                if alt is not None:
                    alt_ord = tuple(int(v) for v in alt["ordinal_path"])
                    alt_tails = build_stmt(alt_ord, [(b_node.node_id, alt_edge, norm_expr, polarity)])
                    out_tails.extend(alt_tails)
                else:
                    out_tails.append((b_node.node_id, alt_edge, norm_expr, polarity))
                return out_tails

            if ntype in SWITCH_TYPES:
                cond_node = condition_child_of(stmt_ord)
                if cond_node is None:
                    cfg_gaps.add(f"cfg_missing_condition:{ntype}")
                    polarity, norm_expr, guarded_ids = None, None, []
                else:
                    cond_text = slice_text(cond_node, MAX_GUARD_EXPR_CHARS)
                    polarity, norm_expr, guarded_ids = classify_guard_polarity(cond_text, language=canonical_lang)
                sw_node = make_node(
                    "switch",
                    node,
                    stmt_text=f"switch ({norm_expr})",
                    guard_expr=norm_expr,
                    guard_pol=polarity,
                    guarded_ids=tuple(guarded_ids),
                )
                connect_incoming(incoming, sw_node.node_id)

                case_nodes: list[dict[str, Any]] = []
                for ch in children.get(stmt_ord, ()):
                    ctype = str(ch["type"])
                    if ctype in CASE_CLAUSE_TYPES:
                        case_nodes.append(ch)
                    elif ctype in BLOCK_WRAPPER_TYPES:
                        for gch in children.get(tuple(int(v) for v in ch["ordinal_path"]), ()):
                            if str(gch["type"]) in CASE_CLAUSE_TYPES:
                                case_nodes.append(gch)

                break_fixups_here: list[str] = []
                # Rust match does not bind break; it targets an enclosing loop.
                binds_break = grammar != "rust"
                if binds_break:
                    break_fixups.append((break_fixups_here, len(finalizers)))
                out_tails = []
                allows_implicit_fallthrough = canonical_lang in {"cpp", "java", "javascript", "typescript", "php"}
                prev_fallthrough_sources: list[str] = []
                has_default = False

                for case_item in case_nodes:
                    c_ord = tuple(int(v) for v in case_item["ordinal_path"])
                    c_txt = slice_text(case_item, 120)
                    is_default = (
                        "default" in str(case_item["type"])
                        or c_txt.startswith("default")
                        or c_txt.startswith("_ =>")
                        or c_txt.startswith("case _")
                    )
                    if is_default:
                        has_default = True
                    arm_edge = "false_branch" if is_default else "true_branch"
                    case_in: list[tuple[str, str, str | None, str | None]] = [(sw_node.node_id, arm_edge, norm_expr, polarity)]
                    for ft_src in prev_fallthrough_sources:
                        case_in.append((ft_src, "fallthrough", None, None))
                    prev_fallthrough_sources = []

                    case_stmts = [
                        c for c in children.get(c_ord, ())
                        if c.get("named", True)
                        and str(c["type"]) not in STATEMENT_IGNORE_TYPES
                        and (c.get("field") == "value" if grammar == "rust"
                             else c.get("field") not in {"value", "pattern"})
                    ]
                    if grammar == "rust":
                        for sub in subtree_ordinals(c_ord, fn_ordinal_set):
                            if by_ordinal[sub].get("field") == "condition":
                                unmodeled.add("match_guard")
                                cfg_gaps.add("cfg_unmodeled_construct:match_guard")
                    if not case_stmts:
                        c_hdr = make_node("statement", case_item, stmt_text=c_txt[:120])
                        connect_incoming(case_in, c_hdr.node_id)
                        case_tails = [(c_hdr.node_id, "unconditional", None, None)]
                    else:
                        case_tails = build_seq(case_stmts, case_in)

                    explicit_ft = any(
                        str(by_ordinal[sub]["type"]) in FALLTHROUGH_STMT_TYPES
                        for sub in subtree_ordinals(c_ord, fn_ordinal_set)
                    )
                    if explicit_ft or allows_implicit_fallthrough:
                        prev_fallthrough_sources = [src_id for src_id, _, _, _ in case_tails]
                    else:
                        out_tails.extend(case_tails)

                if binds_break:
                    break_fixups.pop()
                for src_id in prev_fallthrough_sources:
                    out_tails.append((src_id, "unconditional", None, None))
                for brk_src in break_fixups_here:
                    out_tails.append((brk_src, "break_edge", None, None))
                if not has_default:
                    out_tails.append((sw_node.node_id, "false_branch", norm_expr, polarity))
                return out_tails

            if ntype in LOOP_TYPES:
                cond_node = condition_child_of(stmt_ord)
                is_unconditional_loop = ntype == "loop_expression"
                is_post_test = ntype == "do_statement"
                cond_text = "" if is_unconditional_loop else (
                    slice_text(cond_node, MAX_GUARD_EXPR_CHARS) if cond_node is not None else None
                )
                if cond_text is None:
                    cfg_gaps.add(f"cfg_missing_condition:{ntype}")
                polarity, norm_expr, guarded_ids = (
                    (None, None, [])
                    if is_unconditional_loop or cond_text is None
                    else classify_guard_polarity(cond_text, language=canonical_lang)
                )
                body_child_loop = next(
                    (c for f in ("body", "consequence") for c in children.get(stmt_ord, ()) if c.get("field") == f),
                    None,
                )
                if body_child_loop is None:
                    ch_blocks = [c for c in children.get(stmt_ord, ()) if str(c["type"]) in BLOCK_WRAPPER_TYPES]
                    if ch_blocks:
                        body_child_loop = ch_blocks[-1]
                stop_loop = {tuple(int(v) for v in body_child_loop["ordinal_path"])} if body_child_loop is not None else set()
                l_calls, l_defs, l_uses = extract_calls_defs_uses(stmt_ord, stop_loop)
                note_unmodeled(stmt_ord, stop_loop)
                loop_node = make_node(
                    "loop_header",
                    node,
                    stmt_text=f"loop ({norm_expr or 'unconditional'})",
                    guard_expr=norm_expr,
                    guard_pol=polarity,
                    guarded_ids=tuple(guarded_ids),
                    calls=l_calls,
                    defs=l_defs,
                    uses=l_uses,
                )
                if not is_post_test:
                    connect_incoming(incoming, loop_node.node_id)
                if (catch_targets or finalizers) and l_calls:
                    exceptional(loop_node.node_id)

                loop_breaks: list[str] = []
                break_fixups.append((loop_breaks, len(finalizers)))
                loop_headers.append((loop_node.node_id, len(finalizers)))

                enter_edge = "unconditional" if is_unconditional_loop else ("false_branch" if ntype == "until" else "true_branch")
                exit_edge = "true_branch" if ntype == "until" else "false_branch"
                if body_child_loop is not None:
                    b_ord = tuple(int(v) for v in body_child_loop["ordinal_path"])
                    body_in = [(loop_node.node_id, enter_edge, norm_expr, polarity)]
                    if is_post_test:
                        body_entry = make_node("statement", body_child_loop, stmt_text="do body")
                        connect_incoming(incoming, body_entry.node_id)
                        connect_incoming(body_in, body_entry.node_id)
                        body_in = [(body_entry.node_id, "unconditional", None, None)]
                    body_tails = build_stmt(b_ord, body_in)
                    if not is_post_test and any(tail[1] in {"true_branch", "false_branch"} for tail in body_tails):
                        latch = make_node("statement", body_child_loop, stmt_text="loop latch")
                        connect_incoming(body_tails, latch.node_id)
                        add_edge(latch.node_id, loop_node.node_id, "loop_back")
                    else:
                        connect_incoming(
                            [(src, ekind if is_post_test else "loop_back", expr, pol)
                             for src, ekind, expr, pol in body_tails],
                            loop_node.node_id,
                        )
                else:
                    if is_post_test:
                        connect_incoming(incoming, loop_node.node_id)
                    add_edge(loop_node.node_id, loop_node.node_id, "loop_back")

                loop_headers.pop()
                break_fixups.pop()

                out_tails = []
                if not is_unconditional_loop:
                    out_tails.append((loop_node.node_id, exit_edge, norm_expr, polarity))
                for brk_src in loop_breaks:
                    out_tails.append((brk_src, "break_edge", None, None))
                return out_tails

            if ntype in TRY_TYPES:
                ch_list = children.get(stmt_ord, ())
                try_body = next((c for c in ch_list if c.get("field") == "body"), None)
                catches = [c for c in ch_list if str(c["type"]) in CATCH_TYPES]
                finallies = [c for c in ch_list if str(c["type"]) in FINALLY_TYPES]
                if try_body is None:
                    non_handlers = [
                        c for c in ch_list
                        if c.get("named", True)
                        and str(c["type"]) not in CATCH_TYPES | FINALLY_TYPES | STATEMENT_IGNORE_TYPES
                    ]
                    try_body = non_handlers[0] if non_handlers else None

                try_hdr = make_node("try_header", node, stmt_text="try")
                connect_incoming(incoming, try_hdr.node_id)

                catch_hdr_nodes: list[tuple[CfgNode, dict[str, Any]]] = []
                for c_item in catches:
                    chdr = make_node("catch_handler", c_item, stmt_text=slice_text(c_item, 100))
                    catch_hdr_nodes.append((chdr, c_item))

                pending: list[_Transfer] = []
                if finallies:
                    finalizers.append(pending)
                handler_ids = [chdr.node_id for chdr, _ in catch_hdr_nodes]
                if handler_ids:
                    catch_targets.append((handler_ids, len(finalizers)))
                # Calls are not the only throwing expressions (property access,
                # division, etc.). Preserve the region's conservative escape.
                exceptional(try_hdr.node_id)

                normal_tails: list[tuple[str, str, str | None, str | None]] = []
                if try_body is not None:
                    if isinstance(try_body, Mapping) and str(try_body["type"]) in BLOCK_WRAPPER_TYPES:
                        normal_tails.extend(
                            build_stmt(
                                tuple(int(v) for v in try_body["ordinal_path"]),
                                [(try_hdr.node_id, "unconditional", None, None)],
                            )
                        )
                    else:
                        try_stmts = [
                            c for c in ch_list
                            if c.get("named", True)
                            and str(c["type"]) not in CATCH_TYPES | FINALLY_TYPES | STATEMENT_IGNORE_TYPES
                        ]
                        normal_tails.extend(build_seq(try_stmts, [(try_hdr.node_id, "unconditional", None, None)]))
                else:
                    normal_tails.append((try_hdr.node_id, "unconditional", None, None))
                if handler_ids:
                    catch_targets.pop()

                for chdr, c_item in catch_hdr_nodes:
                    c_ord = tuple(int(v) for v in c_item["ordinal_path"])
                    c_body = next(
                        (c for c in children.get(c_ord, ()) if c.get("field") == "body" or str(c["type"]) in BLOCK_WRAPPER_TYPES),
                        None,
                    )
                    if c_body is not None:
                        normal_tails.extend(
                            build_stmt(
                                tuple(int(v) for v in c_body["ordinal_path"]),
                                [(chdr.node_id, "unconditional", None, None)],
                            )
                        )
                    else:
                        normal_tails.append((chdr.node_id, "unconditional", None, None))

                if finallies:
                    finalizers.pop()
                    fin_item = finallies[0]
                    fin_ord = tuple(int(v) for v in fin_item["ordinal_path"])
                    fin_body = next((c for c in children.get(fin_ord, ()) if str(c["type"]) in BLOCK_WRAPPER_TYPES), None)

                    def cleanup(tails: list[tuple[str, str, str | None, str | None]]) -> list[tuple[str, str, str | None, str | None]]:
                        if not tails:
                            return []
                        fin_hdr = make_node("finally_block", fin_item, stmt_text="finally")
                        connect_incoming(tails, fin_hdr.node_id)
                        fin_in = [(fin_hdr.node_id, "unconditional", None, None)]
                        if fin_body is not None:
                            return build_stmt(tuple(int(v) for v in fin_body["ordinal_path"]), fin_in)
                        cfg_gaps.add("cfg_missing_finally_body")
                        return fin_in

                    # A separate cleanup copy preserves each continuation's destination.
                    # Sharing one exit would allow return -> normal continuation cross-edges.
                    resumed_normal = cleanup(normal_tails)
                    for completion in pending:
                        incoming_kind = "exception_edge" if completion.kind == "exception_edge" else "unconditional"
                        resumed = cleanup([(completion.source, incoming_kind, None, None)])
                        for src, ekind, expr, pol in resumed:
                            if ekind in {"true_branch", "false_branch"}:
                                resume_node = make_node("statement", fin_item, stmt_text="resume completion")
                                connect_incoming([(src, ekind, expr, pol)], resume_node.node_id)
                                src = resume_node.node_id
                            transfer(src, completion.kind, completion.target, completion.finally_depth)
                    return resumed_normal
                return normal_tails

            if ntype in RETURN_TYPES:
                note_unmodeled(stmt_ord)
                rcalls, rdefs, ruses = extract_calls_defs_uses(stmt_ord, set())
                rnode = make_node("return", node, stmt_text=slice_text(node), calls=rcalls, defs=rdefs, uses=ruses)
                connect_incoming(incoming, rnode.node_id)
                if (catch_targets or finalizers) and rcalls:
                    exceptional(rnode.node_id)
                transfer(rnode.node_id, "return_exit", exit_node.node_id, 0)
                return []

            if ntype in BREAK_TYPES:
                note_unmodeled(stmt_ord)
                labeled = any(c.get("field") == "label" or c["type"] == "label"
                              for c in children.get(stmt_ord, ()))
                if labeled:
                    unmodeled.add("labeled_break")
                    cfg_gaps.add("cfg_unmodeled_construct:labeled_break")
                bnode = make_node("jump", node, stmt_text=slice_text(node))
                connect_incoming(incoming, bnode.node_id)
                if labeled:
                    return []
                if break_fixups:
                    targets, depth = break_fixups[-1]
                    transfer(bnode.node_id, "break_edge", targets, depth)
                else:
                    transfer(bnode.node_id, "break_edge", exit_node.node_id, 0)
                return []

            if ntype in CONTINUE_TYPES:
                if any(c.get("field") == "label" or c["type"] == "label" for c in children.get(stmt_ord, ())):
                    unmodeled.add("labeled_continue")
                    cfg_gaps.add("cfg_unmodeled_construct:labeled_continue")
                    cnode = make_node("jump", node, stmt_text=slice_text(node))
                    connect_incoming(incoming, cnode.node_id)
                    return []
                cnode = make_node("jump", node, stmt_text=slice_text(node))
                connect_incoming(incoming, cnode.node_id)
                if loop_headers:
                    target, depth = loop_headers[-1]
                    transfer(cnode.node_id, "continue_edge", target, depth)
                else:
                    transfer(cnode.node_id, "continue_edge", exit_node.node_id, 0)
                return []

            if ntype in FALLTHROUGH_STMT_TYPES:
                fnode = make_node("jump", node, stmt_text="fallthrough")
                connect_incoming(incoming, fnode.node_id)
                return [(fnode.node_id, "fallthrough", None, None)]

            note_unmodeled(stmt_ord)
            scalls, sdefs, suses = extract_calls_defs_uses(stmt_ord, set())
            is_throw_call = any(c in {"raise", "panic", "panic!", "abort", "throw"} for c in scalls)
            if ntype in THROW_TYPES or is_throw_call:
                tnode = make_node("throw", node, stmt_text=slice_text(node), calls=scalls, defs=sdefs, uses=suses)
                connect_incoming(incoming, tnode.node_id)
                exceptional(tnode.node_id)
                return []

            snode = make_node("statement", node, stmt_text=slice_text(node), calls=scalls, defs=sdefs, uses=suses)
            connect_incoming(incoming, snode.node_id)
            if (catch_targets or finalizers) and scalls:
                exceptional(snode.node_id)
            has_rust_try = grammar == "rust" and any(
                str(by_ordinal[sub]["type"]) == "try_expression"
                for sub in subtree_ordinals(stmt_ord, fn_ordinal_set)
            )
            if has_rust_try:
                add_edge(snode.node_id, exit_node.node_id, "exception_edge")
            return [(snode.node_id, "unconditional", None, None)]

        try:
            if body_child is not None:
                body_ord = tuple(int(v) for v in body_child["ordinal_path"])
                tails = build_stmt(body_ord, [(entry_node.node_id, "entry", None, None)])
                for tail_src, ekind, gexpr, gpol in tails:
                    final_kind = "unconditional" if ekind == "entry" else ekind
                    add_edge(tail_src, exit_node.node_id, final_kind, guard_expr=gexpr, guard_pol=gpol)
            else:
                cfg_gaps.add("cfg_missing_function_body")
                add_edge(entry_node.node_id, exit_node.node_id, "entry")
        except _CfgLimitReached:
            truncated = True
            cfg_gaps.add("cfg_node_limit_reached")

        dom_map = compute_dominators(
            entry_node.node_id, [n.node_id for n in nodes_acc], edges_acc
        )
        guard_dom_map = {} if cfg_gaps else compute_guard_dominators(
            entry_node.node_id, exit_node.node_id, nodes_acc, edges_acc, dom_map
        )
        for n in nodes_acc:
            n.guard_dominators = guard_dom_map.get(n.node_id, ())

        # A repeated finally ordinal has several execution contexts. Only common
        # guards may be attributed to the source occurrence, never one copy's arm.
        ordinal_guards: dict[tuple[int, ...], set[GuardDominator]] = {}
        contextual_ordinals: set[tuple[int, ...]] = set()
        for n in nodes_acc:
            if n.kind in {"entry", "exit"}:
                continue
            if n.ordinal_path in ordinal_guards:
                contextual_ordinals.add(n.ordinal_path)
                ordinal_guards[n.ordinal_path].intersection_update(n.guard_dominators)
            else:
                ordinal_guards[n.ordinal_path] = set(n.guard_dominators)
        fn_sub_ords = subtree_ordinals(fn_ord, fn_ordinal_set)
        ord_guards: dict[tuple[int, ...], tuple[GuardDominator, ...]] = {}
        ord_blocks_full: dict[tuple[int, ...], str] = {}
        for sub_ord in fn_sub_ords:
            probe = sub_ord
            matched_block: str | None = None
            while len(probe) >= len(fn_ord):
                if probe in ord_to_block:
                    matched_block = ord_to_block[probe]
                    break
                if not probe:
                    break
                probe = probe[:-1]
            if matched_block is not None:
                if probe not in contextual_ordinals:
                    ord_blocks_full[sub_ord] = matched_block
                ord_guards[sub_ord] = tuple(g for g in guard_dom_map.get(matched_block, ())
                                            if g in ordinal_guards.get(probe, set()))

        functions_out.append(
            FunctionCfg(
                function_id=fn_id,
                ast_identity=fn_ast_id,
                function_name=fn_name,
                qualified_name=qualified_name,
                language=canonical_lang,
                grammar=grammar,
                source_identity=source_identity,
                path=path,
                file_sha256=file_sha256,
                start_line=fn_start_line,
                end_line=fn_end_line,
                start_byte=fn_sb,
                end_byte=fn_eb,
                ordinal_path=fn_ord,
                entry_node_id=entry_node.node_id,
                exit_node_id=exit_node.node_id,
                nodes=nodes_acc,
                edges=edges_acc,
                dominators={k: tuple(sorted(v)) for k, v in sorted(dom_map.items())},
                ordinal_to_node_id=ord_blocks_full,
                ordinal_guard_dominators=ord_guards,
                parameters=params,
                decorators=decorators,
                is_entrypoint_candidate=is_entry,
                entrypoint_route=route_str,
                truncated=truncated,
                unmodeled_constructs=tuple(sorted(unmodeled)),
                gaps=tuple(sorted(cfg_gaps)),
            )
        )

    functions_out.sort(key=lambda fn: (fn.path, fn.start_byte, fn.end_byte, fn.function_id))
    return FileCfgResult(
        path=path,
        language=canonical_lang,
        grammar=grammar,
        source_identity=source_identity,
        file_sha256=file_sha256,
        functions=functions_out,
    )


def write_scope_cfg_artifacts(
    *,
    run_root: Path,
    cfg_dir: Path,
    scope_id: str,
    language: str,
    grammar: str,
    target_snapshot: str,
    file_results: Sequence[FileCfgResult],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Write ``cfg-nodes.jsonl``, ``cfg-edges.jsonl``, and ``cfg-manifest.json`` under ``cfg_dir``."""
    cfg_dir.mkdir(parents=True, exist_ok=True)
    nodes_path = cfg_dir / "cfg-nodes.jsonl"
    edges_path = cfg_dir / "cfg-edges.jsonl"
    manifest_path = cfg_dir / "cfg-manifest.json"

    node_lines: list[bytes] = []
    edge_lines: list[bytes] = []
    fn_summaries: list[dict[str, Any]] = []
    langs: set[str] = set()

    ordered_files = sorted(file_results, key=lambda r: r.path)
    for fres in ordered_files:
        if fres.functions:
            langs.add(fres.language)
        for fn in fres.functions:
            fn_summaries.append(fn.to_summary())
            for cnode in fn.nodes:
                node_lines.append(
                    json.dumps(cnode.to_jsonl_record(), sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
                )
            for cedge in fn.edges:
                edge_lines.append(
                    json.dumps(cedge.to_jsonl_record(), sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
                )

    atomic_bytes(nodes_path, b"".join(node_lines))
    atomic_bytes(edges_path, b"".join(edge_lines))

    def _ref(p: Path) -> dict[str, Any]:
        return {
            "path": p.relative_to(run_root).as_posix(),
            "sha256": file_sha256(p),
            "size_bytes": p.stat().st_size,
        }

    nodes_ref = _ref(nodes_path)
    edges_ref = _ref(edges_path)
    guards_count = sum(int(item["guard_count"]) for item in fn_summaries)
    counts = {
        "cfg_functions_built": len(fn_summaries),
        "cfg_nodes_emitted": len(node_lines),
        "cfg_edges_emitted": len(edge_lines),
        "cfg_guards_classified": guards_count,
        "cfg_languages": sorted(langs),
        "cfg_partial_functions": sum(bool(item["gaps"]) for item in fn_summaries),
        "cfg_truncated_functions": sum(item["truncated"] for item in fn_summaries),
        "cfg_unmodeled_constructs": sum(len(item["unmodeled_constructs"]) for item in fn_summaries),
    }
    manifest_doc = {
        "schema": CFG_SCHEMA,
        "record_type": "cfg_manifest",
        "scope_id": scope_id,
        "language": language,
        "grammar": grammar,
        "target_snapshot": target_snapshot,
        "counts": counts,
        "nodes_artifact": nodes_ref,
        "edges_artifact": edges_ref,
        "functions": fn_summaries,
    }
    atomic_json(manifest_path, manifest_doc)
    manifest_ref = _ref(manifest_path)
    return {
        "manifest": manifest_ref,
        "nodes": nodes_ref,
        "edges": edges_ref,
    }, counts
