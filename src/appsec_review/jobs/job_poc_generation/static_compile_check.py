"""Unified 9-language static compile-only PoC harness validator (T-174).

Validates generated PoC harnesses across ``cpp``, ``java``, ``javascript``, ``python``, ``ruby``,
``go``, ``csharp``, ``rust`` and ``php`` without executing untrusted or generated code, emitting
``appsec-review/poc-compile-check/1`` records.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Any, Sequence

from appsec_review.jobs.job_poc_generation.poc_execution_gate import (
    GENERATED_CODE_EXECUTION_POLICY,
    enforce_poc_non_execution,
)

POC_COMPILE_CHECK_SCHEMA = "appsec-review/poc-compile-check/1"
SUPPORTED_POC_LANGUAGES: tuple[str, ...] = (
    "cpp", "java", "javascript", "python", "ruby", "go", "csharp", "rust", "php",
)

_LANGUAGE_ALIASES: dict[str, str] = {
    "c": "cpp", "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "c++": "cpp",
    "java": "java",
    "js": "javascript", "javascript": "javascript", "ts": "javascript", "typescript": "javascript",
    "py": "python", "python": "python",
    "rb": "ruby", "ruby": "ruby",
    "go": "go", "golang": "go",
    "cs": "csharp", "csharp": "csharp", "c#": "csharp",
    "rs": "rust", "rust": "rust",
    "php": "php",
}

_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".java": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".py": "python", ".rb": "ruby", ".go": "go", ".cs": "csharp", ".rs": "rust", ".php": "php",
}

_CLOSING_TO_OPENING = {")": "(", "]": "[", "}": "{"}
_OPENING_DELIMITERS = frozenset(_CLOSING_TO_OPENING.values())

_STUB_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("todo_marker", re.compile(r"\b(?:TODO|FIXME|XXX|TBD)\b")),  # T-175
    ("not_implemented", re.compile(r"\b(?:NotImplementedError|UnsupportedOperationException|NotImplementedException)\b")),
    ("rust_todo_macro", re.compile(r"\b(?:todo|unimplemented)\s*!")),
)

_PROHIBITED_PRIMITIVES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell_system", re.compile(r"(?<![.\w])(?:system|popen|execl|execle|execlp|execv|execve|execvp|fork)\s*\(")),
    ("python_subprocess", re.compile(r"\b(?:os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_output|check_call))\s*\(")),
    ("java_process_exec", re.compile(r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(")),
    ("js_child_process", re.compile(r"\b(?:child_process|execSync|spawnSync|execFileSync)\b")),
    ("ruby_shell_exec", re.compile(r"\b(?:Kernel\.system|Open3\.(?:capture2|capture3|popen3)|IO\.popen)\b")),
    ("go_os_exec", re.compile(r"\bexec\.Command(?:Context)?\s*\(")),
    ("csharp_process_start", re.compile(r"\bProcess\.Start\s*\(")),
    ("rust_process_command", re.compile(r"\b(?:std::)?process::Command::new\s*\(")),
    ("php_shell_exec", re.compile(r"\b(?:shell_exec|proc_open|passthru|pcntl_exec)\s*\(")),
    ("live_network_socket", re.compile(
        r"\b(?:socket\.connect|urllib\.request\.urlopen|requests\.(?:get|post|put|delete|request)|"
        r"Net::HTTP\.start|http\.(?:Get|Post|NewRequest)|TcpStream::connect|curl_exec|fsockopen)\b"
    )),
    ("external_network_url", re.compile(r"https?://(?!(?:127\.0\.0\.1|localhost|\[::1\])\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("destructive_fs", re.compile(
        r"\b(?:shutil\.rmtree|os\.remove|os\.unlink|FileUtils\.rm_rf|fs\.(?:rmSync|rmdirSync|unlinkSync)|"
        r"std::fs::(?:remove_dir_all|remove_file)|Directory\.Delete)\b"
    )),
)

_STANDALONE_MAIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "cpp": re.compile(r"\b(?:int|void)\s+main\s*\("),
    "java": re.compile(r"\bstatic\s+void\s+main\s*\("),
    "javascript": re.compile(r"\bprocess\.exit\s*\("),
    "python": re.compile(r"__name__\s*==\s*['\"]__main__['\"]"),
    "ruby": re.compile(r"__FILE__\s*==\s*\$0\b"),
    "go": re.compile(r"\bfunc\s+main\s*\(\s*\)"),
    "csharp": re.compile(r"\bstatic\s+(?:async\s+)?(?:void|int|Task(?:<int>)?)\s+Main\s*\("),
    "rust": re.compile(r"\bfn\s+main\s*\(\s*\)"),
    "php": re.compile(r"\b\$argv\b"),
}

_ENTRYPOINT_PATTERNS: dict[str, re.Pattern[str]] = {
    "cpp": re.compile(r"\b(?:void|int|bool|auto)\s+(poc_[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)\s*\(|\bTEST(?:_F)?\s*\(\s*[A-Za-z0-9_]+\s*,\s*([A-Za-z0-9_]+)\s*\)"),
    "java": re.compile(r"(?:@Test\b[\s\S]{0,120}?\bvoid\s+([A-Za-z0-9_]+)\s*\(|\bvoid\s+(poc_[A-Za-z0-9_]+|test[A-Za-z0-9_]*)\s*\()"),
    "javascript": re.compile(r"(?:\b(?:async\s+)?function\s+(poc_[A-Za-z0-9_]+|test[A-Za-z0-9_]*)\s*\(|\b(?:const|let|var)\s+(poc_[A-Za-z0-9_]+|test[A-Za-z0-9_]*)\s*=|\b(?:test|it)\s*\(\s*['\"`]([^'\"`]+)['\"`])"),
    "python": re.compile(r"\bdef\s+(poc_[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)\s*\("),
    "ruby": re.compile(r"(?:\bdef\s+(poc_[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)\b|\bit\s+['\"]([^'\"]+)['\"])"),
    "go": re.compile(r"\bfunc\s+(Test[A-Za-z0-9_]+|poc_[A-Za-z0-9_]+)\s*\("),
    "csharp": re.compile(r"(?:\[(?:Fact|Test|Theory)\][\s\S]{0,160}?\b(?:void|Task)\s+([A-Za-z0-9_]+)\s*\(|\b(?:void|Task)\s+(Poc[A-Za-z0-9_]*|poc_[A-Za-z0-9_]+|Test[A-Za-z0-9_]*)\s*\()"),
    "rust": re.compile(r"(?:#\[(?:tokio::)?test\][\s\S]{0,120}?\bfn\s+([A-Za-z0-9_]+)\s*\(|\bfn\s+(poc_[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)\s*\()"),
    "php": re.compile(r"\bfunction\s+(poc_[A-Za-z0-9_]+|test[A-Za-z0-9_]*)\s*\("),
}

_ASSERTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "cpp": re.compile(r"\b(?:assert|static_assert|EXPECT_[A-Z0-9_]+|ASSERT_[A-Z0-9_]+|REQUIRE|CHECK)\s*\("),
    "java": re.compile(r"\b(?:assert\b|assertEquals|assertTrue|assertFalse|assertThrows|assertNotNull|Assertions\.[A-Za-z0-9_]+)\b"),
    "javascript": re.compile(r"\b(?:assert(?:\.[A-Za-z0-9_]+)?|expect)\s*\("),
    "python": re.compile(r"\b(?:assert\b|pytest\.raises|self\.assert[A-Za-z0-9_]+)"),
    "ruby": re.compile(r"\b(?:assert(?:_[a-z0-9_]+)?|refute(?:_[a-z0-9_]+)?|expect|raise_error)\b"),
    "go": re.compile(r"\b(?:t\.(?:Fatal|Fatalf|Error|Errorf|Fail|FailNow)|require\.[A-Za-z0-9_]+|assert\.[A-Za-z0-9_]+)\b"),
    "csharp": re.compile(r"\b(?:Assert\.[A-Za-z0-9_]+|Debug\.Assert|FluentAssertions)\b"),
    "rust": re.compile(r"\b(?:assert!|assert_eq!|assert_ne!|matches!|#\[should_panic)"),
    "php": re.compile(r"(?:\$(?:this->)?assert[A-Za-z0-9_]*\s*\(|\bassert\s*\(|\bexpectException\s*\()"),
}

_IMPORT_VALIDATORS: dict[str, tuple[re.Pattern[str], re.Pattern[str]]] = {
    "cpp": (re.compile(r"^\s*#\s*include\b"), re.compile(r"^\s*#\s*include\s*(?:<[^>\n]+>|\"[^\"\n]+\")\s*$")),
    "java": (re.compile(r"^\s*import\b"), re.compile(r"^\s*import\s+(?:static\s+)?[A-Za-z_][\w.*]*\s*;\s*$")),
    "javascript": (re.compile(r"^\s*import\b"), re.compile(r"^\s*import\s+.+;?\s*$")),
    "python": (re.compile(r"^\s*(?:import|from)\b"), re.compile(r"^\s*(?:import\s+[A-Za-z_][\w.,\s]*|from\s+[A-Za-z_.][\w.]*\s+import\s+.+)$")),
    "ruby": (re.compile(r"^\s*require(?:_relative)?\b"), re.compile(r"^\s*require(?:_relative)?\s*(?:\(\s*)?['\"][^'\"]+['\"]\s*\)?\s*$")),
    "go": (re.compile(r"^\s*package\b"), re.compile(r"^\s*package\s+[A-Za-z_][A-Za-z0-9_]*\s*$")),
    "csharp": (re.compile(r"^\s*using\b"), re.compile(r"^\s*using\s+(?:static\s+)?[A-Za-z_][\w.= ]*\s*;\s*$")),
    "rust": (re.compile(r"^\s*use\b"), re.compile(r"^\s*use\s+[A-Za-z_:][\w:*{},\s]*;\s*$")),
    "php": (re.compile(r"^\s*use\b"), re.compile(r"^\s*use\s+[A-Za-z_\\][\w\\,{}\s]*;\s*$")),
}

_RUBY_OPENERS = re.compile(
    r"(?:^\s*|\s*;\s*)(?:def|class|module|begin|case|while|until|for|if|unless)\b|\bdo(?:\s*\|[^|]*\|)?(?=\s*$)",
    re.MULTILINE,
)
_RUBY_CLOSERS = re.compile(r"\bend\b")


@dataclass(frozen=True)
class StaticPocCompileCheckResult:
    """Result of static compile-only verification for one PoC harness."""

    language: str
    status: str
    syntax_valid: bool
    imports_valid: bool
    harness_entrypoint_valid: bool
    assertion_present: bool
    target_symbol_referenced: bool
    stub_free: bool
    declared_entrypoints: tuple[str, ...]
    matched_target_symbols: tuple[str, ...]
    prohibited_primitives: tuple[str, ...]
    violations: tuple[dict[str, str], ...]
    claim_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "compile_verified"

    def record(self) -> dict[str, Any]:
        enforce_poc_non_execution()
        return {
            "schema": POC_COMPILE_CHECK_SCHEMA,
            "claim_id": self.claim_id,
            "language": self.language,
            "status": self.status,
            "syntax_valid": self.syntax_valid,
            "imports_valid": self.imports_valid,
            "harness_entrypoint_valid": self.harness_entrypoint_valid,
            "assertion_present": self.assertion_present,
            "target_symbol_referenced": self.target_symbol_referenced,
            "stub_free": self.stub_free,
            "declared_entrypoints": list(self.declared_entrypoints),
            "matched_target_symbols": list(self.matched_target_symbols),
            "prohibited_primitives": list(self.prohibited_primitives),
            "violations": [dict(item) for item in self.violations],
            "generated_code_execution": GENERATED_CODE_EXECUTION_POLICY,
            "runtime_verified": False,
        }


def detect_poc_language(path_or_language: str) -> str | None:
    """Normalize a language tag or source file path into one of the 9 supported languages."""
    raw = (path_or_language or "").strip().lower()
    if not raw:
        return None
    if raw in _LANGUAGE_ALIASES:
        return _LANGUAGE_ALIASES[raw]
    return _EXTENSION_TO_LANGUAGE.get(PurePosixPath(raw.replace("\\", "/")).suffix.lower())


def scan_lexical_structure(source_text: str, language: str) -> tuple[bool, str | None, str, str]:
    """Strip comments/strings while checking balanced delimiters and literal closure."""
    n = len(source_text)
    i = 0
    line = 1
    stack: list[tuple[str, int]] = []
    stripped_chars: list[str] = []
    no_comment_chars: list[str] = []

    slash_comments = language in {"cpp", "java", "javascript", "go", "csharp", "rust", "php"}
    hash_comments = language in {"python", "ruby", "php"}
    backtick_strings = language in {"javascript", "go"}

    while i < n:
        ch = source_text[i]
        nxt = source_text[i + 1] if i + 1 < n else ""

        if ch == "\n":
            line += 1
            stripped_chars.append("\n")
            no_comment_chars.append("\n")
            i += 1
            continue
        if slash_comments and ch == "/" and nxt == "/":
            while i < n and source_text[i] != "\n":
                i += 1
            continue
        if slash_comments and ch == "/" and nxt == "*":
            start_line = line
            i += 2
            closed = False
            while i < n:
                if source_text[i] == "\n":
                    line += 1
                    stripped_chars.append("\n")
                    no_comment_chars.append("\n")
                elif source_text[i] == "*" and i + 1 < n and source_text[i + 1] == "/":
                    i += 2
                    closed = True
                    break
                i += 1
            if not closed:
                return False, f"unclosed block comment starting on line {start_line}", "", ""
            continue
        if hash_comments and ch == "#" and not (language == "php" and nxt == "["):
            while i < n and source_text[i] != "\n":
                i += 1
            continue
        if language == "python" and source_text[i:i + 3] in ('"""', "'''"):
            quote3 = source_text[i:i + 3]
            start_line = line
            no_comment_chars.append(quote3)
            stripped_chars.append('""')
            i += 3
            closed = False
            while i < n:
                if source_text[i:i + 3] == quote3:
                    no_comment_chars.append(quote3)
                    i += 3
                    closed = True
                    break
                if source_text[i] == "\\":
                    no_comment_chars.append(source_text[i:i + 2])
                    if i + 1 < n and source_text[i + 1] == "\n":
                        line += 1
                        stripped_chars.append("\n")
                    i += 2
                    continue
                if source_text[i] == "\n":
                    line += 1
                    stripped_chars.append("\n")
                no_comment_chars.append(source_text[i])
                i += 1
            if not closed:
                return False, f"unclosed triple-quoted string starting on line {start_line}", "", ""
            continue
        if language == "rust" and ch == "'":
            if i + 2 < n and source_text[i + 1] != "\\" and source_text[i + 2] == "'":
                no_comment_chars.append(source_text[i:i + 3])
                stripped_chars.append("''")
                i += 3
                continue
            if i + 3 < n and source_text[i + 1] == "\\" and source_text[i + 3] == "'":
                no_comment_chars.append(source_text[i:i + 4])
                stripped_chars.append("''")
                i += 4
                continue
            stripped_chars.append(ch)
            no_comment_chars.append(ch)
            i += 1
            continue
        if ch in ('"', "'") or (backtick_strings and ch == "`"):
            quote = ch
            start_line = line
            stripped_chars.append(quote)
            no_comment_chars.append(quote)
            i += 1
            closed = False
            allow_multiline = quote == "`" or language in {"php", "ruby"}
            while i < n:
                cur = source_text[i]
                if cur == "\\" and quote != "`":
                    no_comment_chars.append(source_text[i:i + 2])
                    if i + 1 < n and source_text[i + 1] == "\n":
                        line += 1
                        stripped_chars.append("\n")
                    i += 2
                    continue
                if cur == quote:
                    stripped_chars.append(quote)
                    no_comment_chars.append(quote)
                    i += 1
                    closed = True
                    break
                if cur == "\n":
                    if not allow_multiline:
                        return False, f"unterminated string literal on line {start_line}", "", ""
                    line += 1
                    stripped_chars.append("\n")
                no_comment_chars.append(cur)
                i += 1
            if not closed:
                return False, f"unclosed string literal starting on line {start_line}", "", ""
            continue

        if ch in _OPENING_DELIMITERS:
            stack.append((ch, line))
        elif ch in _CLOSING_TO_OPENING:
            expected = _CLOSING_TO_OPENING[ch]
            if not stack or stack[-1][0] != expected:
                return False, f"unmatched closing delimiter '{ch}' on line {line}", "", ""
            stack.pop()
        stripped_chars.append(ch)
        no_comment_chars.append(ch)
        i += 1

    if stack:
        opener, open_line = stack[-1]
        return False, f"unclosed delimiter '{opener}' from line {open_line}", "", ""

    stripped = "".join(stripped_chars)
    no_comments = "".join(no_comment_chars)
    if language == "ruby":
        opens = len(_RUBY_OPENERS.findall(stripped))
        closes = len(_RUBY_CLOSERS.findall(stripped))
        if opens != closes:
            return False, f"unbalanced Ruby block keywords (openers={opens}, end={closes})", stripped, no_comments
    if language == "php" and "<?php" not in source_text and "function " not in stripped and "class " not in stripped:
        return False, "PHP source must declare <?php or a function/class definition", stripped, no_comments
    if language == "go" and not re.search(r"^\s*package\s+[A-Za-z_][A-Za-z0-9_]*\b", stripped, re.MULTILINE):
        return False, "Go source must declare a package clause", stripped, no_comments
    return True, None, stripped, no_comments


def _python_ast_check(source_text: str) -> tuple[bool, str | None, list[str], bool]:
    try:
        tree = ast.parse(source_text)
    except SyntaxError as exc:
        return False, f"Python syntax error on line {exc.lineno}: {exc.msg}", [], True
    entrypoints: list[str] = []
    stub_free = True
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith(("poc_", "test_")):
                entrypoints.append(node.name)
            non_doc_stmts = [
                stmt for stmt in node.body
                if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str))
            ]
            if not non_doc_stmts or all(isinstance(stmt, ast.Pass) for stmt in non_doc_stmts):
                stub_free = False
    return True, None, entrypoints, stub_free


def _extract_entrypoints(stripped_code: str, language: str) -> list[str]:
    found: list[str] = []
    for match in _ENTRYPOINT_PATTERNS[language].finditer(stripped_code):
        for group in match.groups():
            if group and group not in found:
                found.append(group)
                break
    return found


def _validate_imports(no_comment_code: str, language: str) -> tuple[bool, str | None]:
    prefix_re, valid_re = _IMPORT_VALIDATORS[language]
    for line_no, line in enumerate(no_comment_code.splitlines(), start=1):
        if prefix_re.search(line):
            if ("{" in line and "}" not in line) or ("(" in line and ")" not in line):
                continue
            if valid_re.search(line) is None:
                return False, f"malformed {language} import/header directive on line {line_no}"
    return True, None


def _normalize_symbol_token(raw: str) -> list[str]:
    cleaned = raw.strip()
    if not cleaned:
        return []
    candidates = [cleaned]
    for sep in ("::", ".", "->", "/", "#"):
        if sep in cleaned:
            tail = cleaned.rsplit(sep, 1)[-1].strip("()")
            if tail and tail not in candidates:
                candidates.append(tail)
    return [item for item in candidates if len(item) >= 2]


def validate_static_poc_harness(
    source_text: str,
    *,
    language: str,
    target_symbols: Sequence[str] = (),
    claim_id: str | None = None,
    allow_standalone_main: bool = False,
) -> StaticPocCompileCheckResult:
    """Validate a PoC harness across any of the 9 supported target languages without executing it."""
    enforce_poc_non_execution()
    canonical_lang = detect_poc_language(language)
    if canonical_lang is None or canonical_lang not in SUPPORTED_POC_LANGUAGES:
        raise ValueError(f"unsupported PoC validation language: {language!r}")

    violations: list[dict[str, str]] = []
    if not isinstance(source_text, str) or not source_text.strip():
        violations.append({"rule": "empty_source", "detail": "PoC harness source is empty"})
        return StaticPocCompileCheckResult(
            language=canonical_lang, status="compile_failed", syntax_valid=False, imports_valid=False,
            harness_entrypoint_valid=False, assertion_present=False, target_symbol_referenced=False,
            stub_free=False, declared_entrypoints=(), matched_target_symbols=(),
            prohibited_primitives=(), violations=tuple(violations), claim_id=claim_id,
        )

    if "\x00" in source_text or "<<<<<<<" in source_text:
        violations.append({"rule": "corrupt_markers", "detail": "PoC source contains NUL bytes or merge markers"})

    lex_ok, lex_err, stripped_code, no_comment_code = scan_lexical_structure(source_text, canonical_lang)
    syntax_valid = lex_ok
    if not lex_ok and lex_err:
        violations.append({"rule": "syntax_structure", "detail": lex_err})

    py_entrypoints: list[str] = []
    py_stub_free = True
    if canonical_lang == "python" and lex_ok:
        py_ok, py_err, py_entrypoints, py_stub_free = _python_ast_check(source_text)
        syntax_valid = syntax_valid and py_ok
        if not py_ok and py_err:
            violations.append({"rule": "python_ast", "detail": py_err})

    check_text = no_comment_code if lex_ok else source_text
    code_only = stripped_code if lex_ok else source_text

    imports_valid, import_err = _validate_imports(check_text, canonical_lang)
    if not imports_valid and import_err:
        violations.append({"rule": "imports", "detail": import_err})

    entrypoints = py_entrypoints if (canonical_lang == "python" and py_entrypoints) else _extract_entrypoints(check_text, canonical_lang)
    has_forbidden_main = (not allow_standalone_main) and (_STANDALONE_MAIN_PATTERNS[canonical_lang].search(check_text) is not None)
    if has_forbidden_main:
        violations.append({"rule": "standalone_entrypoint", "detail": f"{canonical_lang} PoC defines a standalone main/autorun entrypoint"})
    if not entrypoints:
        violations.append({"rule": "harness_entrypoint", "detail": f"{canonical_lang} PoC lacks a poc_* or test_* harness entrypoint"})
    harness_entrypoint_valid = bool(entrypoints) and not has_forbidden_main

    has_assertion = _ASSERTION_PATTERNS[canonical_lang].search(check_text) is not None
    has_paired_controls = len([name for name in entrypoints if name.lower().startswith("poc_")]) >= 2
    assertion_present = has_assertion or has_paired_controls
    if not assertion_present:
        violations.append({
            "rule": "assertion_marker",
            "detail": f"{canonical_lang} PoC must include an explicit assertion/oracle check or paired poc_* control functions",
        })

    stub_free = py_stub_free
    for stub_name, stub_re in _STUB_PATTERNS:
        if stub_re.search(source_text):
            stub_free = False
            violations.append({"rule": "stub_placeholder", "detail": f"PoC contains placeholder marker ({stub_name})"})
            break
    if canonical_lang != "python" and entrypoints and re.search(r"\{\s*\}", code_only):
        stub_free = False
        violations.append({"rule": "stub_placeholder", "detail": "PoC contains an empty function/block body"})

    matched_symbols: list[str] = []
    cleaned_targets = [sym for sym in target_symbols if isinstance(sym, str) and sym.strip()]
    if cleaned_targets:
        for raw_sym in cleaned_targets:
            for token in _normalize_symbol_token(raw_sym):
                if token in check_text:
                    if raw_sym not in matched_symbols:
                        matched_symbols.append(raw_sym)
                    break
        target_symbol_referenced = bool(matched_symbols)
        if not target_symbol_referenced:
            violations.append({
                "rule": "target_symbol_missing",
                "detail": f"PoC does not reference any expected target symbol/route: {', '.join(cleaned_targets[:4])}",
            })
    else:
        target_symbol_referenced = True

    prohibited_hits: list[str] = []
    for prim_name, prim_re in _PROHIBITED_PRIMITIVES:
        if prim_re.search(check_text):
            prohibited_hits.append(prim_name)
            violations.append({
                "rule": "prohibited_primitive",
                "detail": f"PoC uses prohibited network/shell/filesystem primitive: {prim_name}",
            })

    if prohibited_hits or has_forbidden_main:
        status = "policy_denied"
    elif syntax_valid and imports_valid and harness_entrypoint_valid and assertion_present and target_symbol_referenced and stub_free and not violations:
        status = "compile_verified"
    else:
        status = "compile_failed"

    return StaticPocCompileCheckResult(
        language=canonical_lang,
        status=status,
        syntax_valid=syntax_valid,
        imports_valid=imports_valid,
        harness_entrypoint_valid=harness_entrypoint_valid,
        assertion_present=assertion_present,
        target_symbol_referenced=target_symbol_referenced,
        stub_free=stub_free,
        declared_entrypoints=tuple(entrypoints[:32]),
        matched_target_symbols=tuple(matched_symbols[:32]),
        prohibited_primitives=tuple(prohibited_hits[:32]),
        violations=tuple(violations[:32]),
        claim_id=claim_id,
    )


__all__ = [
    "POC_COMPILE_CHECK_SCHEMA",
    "SUPPORTED_POC_LANGUAGES",
    "StaticPocCompileCheckResult",
    "detect_poc_language",
    "scan_lexical_structure",
    "validate_static_poc_harness",
]
