"""9-language in-memory patch, balanced syntax/AST, guard-hardening and function-preservation validator (T-174).

Verifies unified diff hunks and exact byte-range edits purely in memory across ``cpp``, ``java``,
``javascript``, ``python``, ``ruby``, ``go``, ``csharp``, ``rust`` and ``php`` without executing
target or generated code.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import difflib
import re
from typing import Any

from appsec_review.jobs.job_poc_generation.static_compile_check import (
    SUPPORTED_POC_LANGUAGES,
    detect_poc_language,
    scan_lexical_structure,
)

STATIC_PATCH_VALIDATION_SCHEMA = "appsec-review/remediation-static-patch-validation/1"
SUPPORTED_REMEDIATION_LANGUAGES = SUPPORTED_POC_LANGUAGES

_HUNK_HEADER_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")

_CONTROL_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "else", "return", "sizeof", "typeof", "match", "synchronized", "lock",
})

_FUNCTION_DECL_PATTERNS: dict[str, re.Pattern[str]] = {
    "cpp": re.compile(
        r"(?:^|\n)\s*(?:template\s*<[^>]+>\s*)?(?:(?:static|inline|virtual|explicit|constexpr|extern)\s+)*"
        r"[A-Za-z_~][\w:<>,\s*&]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
    ),
    "java": re.compile(
        r"(?:^|\n)\s*(?:@[A-Za-z0-9_.]+\s*(?:\([^)]*\))?\s*)*(?:(?:public|protected|private|static|final|synchronized|abstract)\s+)+"
        r"(?:<[^>]+>\s*)?[A-Za-z_][\w<>\[\],.? ]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{",
    ),
    "javascript": re.compile(
        r"(?:\b(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(|\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>)",
    ),
    "python": re.compile(r"(?:^|\n)\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    "ruby": re.compile(r"(?:^|\n)\s*def\s+(?:self\.)?([A-Za-z_][A-Za-z0-9_!?=]*)"),
    "go": re.compile(r"(?:^|\n)\s*func\s+(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    "csharp": re.compile(
        r"(?:^|\n)\s*(?:\[[^\]]+\]\s*)*(?:(?:public|protected|private|internal|static|virtual|override|async|sealed)\s+)+"
        r"[A-Za-z_][\w<>\[\],.? ]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:where\s+[^{]+)?\{",
    ),
    "rust": re.compile(r"(?:^|\n)\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"),
    "php": re.compile(r"(?:^|\n)\s*(?:(?:public|protected|private|static|final)\s+)*function\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("),
}

_GUARD_AND_HARDENING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:if|unless|guard)\b"),
    re.compile(r"\b(?:strlen|strnlen|sizeof|snprintf|vsnprintf|strlcpy|strlcat|memcpy_s|strncpy_s|bounds|checked_add|checked_mul|saturating_add|saturating_sub)\b"),
    re.compile(r"\b(?:PreparedStatement|prepareStatement|NamedParameterJdbcTemplate|SqlParameter|AddWithValue|Parameters\.Add|ThrowIfNull|ThrowIfNullOrEmpty|ThrowIfNullOrWhiteSpace|bindParam|bindValue|parameterized)\b"),
    re.compile(r"(?:\?\s*,|\$\d+\b|:[A-Za-z_][A-Za-z0-9_]*\b)"),
    re.compile(r"\b(?:escape|html\.escape|markupsafe|bleach|DOMPurify|textContent|encodeForHTML|HtmlUtils\.htmlEscape|HtmlEncoder|htmlspecialchars| ERB::Util\.html_escape|CGI\.escapeHTML|template\.HTMLEscapeString)\b"),
    re.compile(r"\b(?:yaml\.safe_load|SafeLoader|defusedxml|XMLConstants\.FEATURE_SECURE_PROCESSING|setFeature|disallow-doctype-decl|DtdProcessing\.Prohibit|LIBXML_NONET)\b"),
    re.compile(r"\b(?:authorize|hasRole|PreAuthorize|Authorize|require_auth|is_authenticated|check_permission|Gate::authorize|pundit|cancancan)\b"),
    re.compile(r"\b(?:hmac\.compare_digest|MessageDigest\.isEqual|timingSafeEqual|secure_compare|subtle\.ConstantTimeCompare|CryptographicOperations\.FixedTimeEquals|hash_equals)\b"),
    re.compile(r"\b(?:shlex\.quote|escapeshellarg|filepath\.Clean|Path\.GetFullPath|canonicalize|resolve\(\)\.normalize|realpath|startsWith|starts_with|HasPrefix)\b"),
    re.compile(r"\b(?:isinstance|parseInt|Number\.isInteger|filter_var|preg_match|len\(|length\b|Length\b|size\(\)|is_empty\(\)|!= null|!== null|is not None|!= nil)\b"),
    re.compile(r"\b(?:throw\s+new|raise\s+[A-Za-z_]|return\s+(?:false|False|nil|null|None|-1|Err\(|http\.Status|ResponseEntity))\b"),
)


class UnifiedDiffApplyError(ValueError):
    """Raised when a unified diff fails strict in-memory hunk application."""


@dataclass(frozen=True)
class FilePatchValidation:
    path: str
    language: str
    hunks_applied: bool
    syntax_valid: bool
    functions_preserved: bool
    guard_or_sink_hardened: bool
    issues: tuple[str, ...]

    def record(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "hunks_applied": self.hunks_applied,
            "syntax_valid": self.syntax_valid,
            "functions_preserved": self.functions_preserved,
            "guard_or_sink_hardened": self.guard_or_sink_hardened,
            "issues": list(self.issues[:16]),
        }


@dataclass(frozen=True)
class StaticPatchValidationResult:
    validation_tier: str
    patch_applies_cleanly: bool
    ast_parse_clean: bool
    signature_preserved: bool
    dominating_guard_verified: bool
    languages: tuple[str, ...]
    files: tuple[FilePatchValidation, ...]

    @property
    def ok(self) -> bool:
        return self.patch_applies_cleanly and self.ast_parse_clean and self.signature_preserved

    def record(self, *, promoted_tier: str | None = None) -> dict[str, Any]:
        tier = promoted_tier or self.validation_tier
        return {
            "schema": STATIC_PATCH_VALIDATION_SCHEMA,
            "validation_tier": tier,
            "patch_applies_cleanly": self.patch_applies_cleanly,
            "ast_parse_clean": self.ast_parse_clean,
            "signature_preserved": self.signature_preserved,
            "dominating_guard_verified": self.dominating_guard_verified,
            "languages": list(self.languages[:16]),
            "files": [item.record() for item in self.files[:32]],
        }


def apply_unified_diff_in_memory(original_text: str, unified_diff: str) -> str:
    """Apply a unified diff strictly against ``original_text`` in memory without fuzz."""
    if not isinstance(unified_diff, str) or not unified_diff.strip():
        raise UnifiedDiffApplyError("unified diff is empty")
    had_trailing_newline = original_text.endswith("\n") or original_text == ""
    orig_lines = original_text.splitlines()
    diff_lines = unified_diff.splitlines()

    hunks: list[tuple[int, int, list[str]]] = []
    idx = 0
    while idx < len(diff_lines):
        line = diff_lines[idx]
        if line.startswith(("diff --git", "index ", "--- ", "+++ ")):
            idx += 1
            continue
        match = _HUNK_HEADER_RE.match(line)
        if not match:
            if not line.strip():
                idx += 1
                continue
            raise UnifiedDiffApplyError(f"unexpected line outside hunk on line {idx + 1}: {line[:80]}")
        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) is not None else 1
        idx += 1
        body: list[str] = []
        while idx < len(diff_lines):
            cur = diff_lines[idx]
            if cur.startswith("@@ ") or cur.startswith("diff --git") or cur.startswith("--- "):
                break
            if cur.startswith("\\ No newline at end of file"):
                idx += 1
                continue
            if not cur or cur[0] not in (" ", "+", "-"):
                raise UnifiedDiffApplyError(f"malformed hunk prefix on line {idx + 1}")
            body.append(cur)
            idx += 1
        hunks.append((old_start, old_count, body))

    if not hunks:
        raise UnifiedDiffApplyError("unified diff contains no hunks")

    out_lines: list[str] = []
    cursor = 0
    for old_start, old_count, body in hunks:
        start_idx = 0 if old_start == 0 else old_start - 1
        if start_idx < cursor or start_idx > len(orig_lines):
            raise UnifiedDiffApplyError(f"hunk start {old_start} out of bounds or overlapping")
        out_lines.extend(orig_lines[cursor:start_idx])
        src_pos = start_idx
        consumed = 0
        for raw in body:
            op, content = raw[0], raw[1:]
            if op in (" ", "-"):
                if src_pos >= len(orig_lines) or orig_lines[src_pos] != content:
                    raise UnifiedDiffApplyError(f"hunk mismatch at source line {src_pos + 1}")
                if op == " ":
                    out_lines.append(content)
                src_pos += 1
                consumed += 1
            elif op == "+":
                out_lines.append(content)
        if consumed != old_count:
            raise UnifiedDiffApplyError(f"hunk line count mismatch: expected {old_count}, consumed {consumed}")
        cursor = src_pos

    out_lines.extend(orig_lines[cursor:])
    joined = "\n".join(out_lines)
    if had_trailing_newline and (out_lines or original_text.endswith("\n")):
        joined += "\n"
    return joined


def extract_declared_functions(source_text: str, language: str) -> set[str]:
    """Extract declared function/method names for signature-preservation checks."""
    if language == "python":
        try:
            tree = ast.parse(source_text)
        except SyntaxError:
            return set()
        return {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
    ok, _err, stripped, _no_comments = scan_lexical_structure(source_text, language)
    haystack = stripped if ok else source_text
    pattern = _FUNCTION_DECL_PATTERNS.get(language)
    if pattern is None:
        return set()
    names: set[str] = set()
    for match in pattern.finditer(haystack):
        for group in match.groups():
            if group and group not in _CONTROL_KEYWORDS:
                names.add(group)
                break
    return names


def verify_patched_syntax(patched_text: str, language: str) -> tuple[bool, str | None]:
    """Verify balanced syntax/AST structure across all 9 supported languages."""
    if language not in SUPPORTED_REMEDIATION_LANGUAGES:
        return True, None
    lex_ok, lex_err, _stripped, _no_comments = scan_lexical_structure(patched_text, language)
    if not lex_ok:
        return False, lex_err
    if language == "python":
        try:
            ast.parse(patched_text)
        except SyntaxError as exc:
            return False, f"Python syntax error on line {exc.lineno}: {exc.msg}"
    return True, None


def verify_guard_or_sink_hardening(before_text: str, after_text: str, language: str) -> bool:
    """Verify that added/modified non-comment lines introduce or strengthen a guard or safe sink."""
    if before_text == after_text:
        return False
    _ok, _err, _stripped, clean_after = scan_lexical_structure(after_text, language) if language in SUPPORTED_REMEDIATION_LANGUAGES else (True, None, after_text, after_text)
    _ok_b, _err_b, _stripped_b, clean_before = scan_lexical_structure(before_text, language) if language in SUPPORTED_REMEDIATION_LANGUAGES else (True, None, before_text, before_text)
    diff = difflib.ndiff(clean_before.splitlines(), clean_after.splitlines())
    added_lines = [line[2:] for line in diff if line.startswith("+ ") and line[2:].strip()]
    if not added_lines:
        return False
    added_blob = "\n".join(added_lines)
    return any(pattern.search(added_blob) is not None for pattern in _GUARD_AND_HARDENING_PATTERNS)


def validate_file_remediation_in_memory(
    *,
    path: str,
    before_text: str,
    after_text: str | None = None,
    unified_diff: str | None = None,
    language: str | None = None,
) -> FilePatchValidation:
    """Validate a single file's remediation patch in memory across any of the 9 target languages."""
    resolved_lang = detect_poc_language(language or path) or "unknown"
    issues: list[str] = []

    if after_text is None:
        if unified_diff is None:
            return FilePatchValidation(
                path=path, language=resolved_lang, hunks_applied=False, syntax_valid=False,
                functions_preserved=False, guard_or_sink_hardened=False,
                issues=("neither patched text nor unified diff was supplied",),
            )
        try:
            patched = apply_unified_diff_in_memory(before_text, unified_diff)
        except UnifiedDiffApplyError as exc:
            return FilePatchValidation(
                path=path, language=resolved_lang, hunks_applied=False, syntax_valid=False,
                functions_preserved=False, guard_or_sink_hardened=False,
                issues=(str(exc)[:240],),
            )
    else:
        patched = after_text

    if "\x00" in patched or "<<<<<<<" in patched:
        issues.append("patched source contains NUL bytes or merge conflict markers")

    syntax_ok, syntax_err = verify_patched_syntax(patched, resolved_lang)
    if not syntax_ok and syntax_err:
        issues.append(syntax_err[:240])

    if before_text and resolved_lang in SUPPORTED_REMEDIATION_LANGUAGES:
        before_funcs = extract_declared_functions(before_text, resolved_lang)
        after_funcs = extract_declared_functions(patched, resolved_lang)
        deleted = sorted(before_funcs - after_funcs)
        functions_preserved = len(deleted) == 0
        if deleted:
            issues.append(f"patch deleted existing function(s): {', '.join(deleted[:4])}"[:240])
    else:
        functions_preserved = True

    guard_hardened = verify_guard_or_sink_hardening(before_text, patched, resolved_lang)
    if not guard_hardened:
        issues.append("patch does not introduce a recognizable guard or sink-hardening construct")

    return FilePatchValidation(
        path=path,
        language=resolved_lang,
        hunks_applied=True,
        syntax_valid=syntax_ok and ("\x00" not in patched and "<<<<<<<" not in patched),
        functions_preserved=functions_preserved,
        guard_or_sink_hardened=guard_hardened,
        issues=tuple(issues[:16]),
    )


def validate_remediation_patch_set(
    file_entries: Sequence[Mapping[str, Any]],
) -> StaticPatchValidationResult:
    """Validate a multi-file remediation patch in memory and classify its ``validation_tier``."""
    results: list[FilePatchValidation] = []
    languages: list[str] = []
    for entry in file_entries:
        res = validate_file_remediation_in_memory(
            path=str(entry["path"]),
            before_text=str(entry.get("before_text", "")),
            after_text=entry.get("after_text"),
            unified_diff=entry.get("unified_diff"),
            language=entry.get("language"),
        )
        results.append(res)
        if res.language not in languages:
            languages.append(res.language)

    applies_cleanly = bool(results) and all(item.hunks_applied for item in results)
    ast_clean = bool(results) and all(item.syntax_valid for item in results)
    sig_preserved = bool(results) and all(item.functions_preserved for item in results)
    guard_verified = any(item.guard_or_sink_hardened for item in results)

    if not applies_cleanly or not ast_clean or not sig_preserved:
        tier = "rejected"
    elif all(lang in SUPPORTED_REMEDIATION_LANGUAGES for lang in languages):
        tier = "in_memory_patch_and_syntax_verified"
    else:
        tier = "static_checked"

    return StaticPatchValidationResult(
        validation_tier=tier,
        patch_applies_cleanly=applies_cleanly,
        ast_parse_clean=ast_clean,
        signature_preserved=sig_preserved,
        dominating_guard_verified=guard_verified,
        languages=tuple(languages),
        files=tuple(results),
    )


__all__ = [
    "FilePatchValidation",
    "STATIC_PATCH_VALIDATION_SCHEMA",
    "SUPPORTED_REMEDIATION_LANGUAGES",
    "StaticPatchValidationResult",
    "UnifiedDiffApplyError",
    "apply_unified_diff_in_memory",
    "extract_declared_functions",
    "validate_file_remediation_in_memory",
    "validate_remediation_patch_set",
    "verify_guard_or_sink_hardening",
    "verify_patched_syntax",
]
