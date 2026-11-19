"""In-memory patch and lexical checks, with Python-only AST parsing (T-174).

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

STATIC_PATCH_VALIDATION_SCHEMA = "appsec-review/remediation-static-patch-validation/2"
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
    hunks_applied: bool | None
    lexical_check_passed: bool | None
    syntax_valid: bool | None
    function_names_preserved: bool | None
    guard_pattern_detected: bool
    issues: tuple[str, ...]

    def record(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "hunks_applied": self.hunks_applied,
            "lexical_check_passed": self.lexical_check_passed,
            "syntax_valid": self.syntax_valid,
            "parser": "python_ast" if self.syntax_valid is not None else None,
            "function_names_preserved": self.function_names_preserved,
            "guard_pattern_detected": self.guard_pattern_detected,
            "issues": list(self.issues[:16]),
        }


@dataclass(frozen=True)
class StaticPatchValidationResult:
    validation_tier: str
    patch_applies_cleanly: bool | None
    lexical_checks_passed: bool | None
    syntax_valid: bool | None
    function_names_preserved: bool | None
    guard_pattern_detected: bool
    languages: tuple[str, ...]
    files: tuple[FilePatchValidation, ...]

    @property
    def ok(self) -> bool:
        return bool(self.files) and self.validation_tier != "rejected"

    def record(self) -> dict[str, Any]:
        return {
            "schema": STATIC_PATCH_VALIDATION_SCHEMA,
            "validation_tier": self.validation_tier,
            "patch_applies_cleanly": self.patch_applies_cleanly,
            "lexical_checks_passed": self.lexical_checks_passed,
            "syntax_valid": self.syntax_valid,
            "function_names_preserved": self.function_names_preserved,
            "guard_pattern_detected": self.guard_pattern_detected,
            "languages": list(self.languages[:16]),
            "files": [item.record() for item in self.files[:32]],
            "runtime_verified": False,
            "limitations": [
                "Only Python is AST parsed; other supported languages receive lexical checks, not syntax verification.",
                "Function-name retention does not verify signatures, behavior or preservation of all declarations.",
                "Guard patterns do not prove dominance, sink hardening or remediation correctness.",
                "Supplied patched text does not establish patch applicability; only supplied diff hunks are applied here.",
                "No compiler or target code was run.",
            ],
        }


def apply_unified_diff_in_memory(original_text: str, unified_diff: str) -> str:
    """Apply a unified diff strictly against ``original_text`` in memory without fuzz."""
    if not isinstance(unified_diff, str) or not unified_diff.strip():
        raise UnifiedDiffApplyError("unified diff is empty")
    orig_lines = original_text.splitlines(keepends=True)
    diff_lines = unified_diff.splitlines(keepends=True)

    hunks: list[tuple[int, int, int, int, list[str]]] = []
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
        new_start = int(match.group(3))
        new_count = int(match.group(4)) if match.group(4) is not None else 1
        if (old_count and not old_start) or (new_count and not new_start):
            raise UnifiedDiffApplyError("nonempty hunk ranges must start at line one or later")
        idx += 1
        body: list[str] = []
        consumed = produced = 0
        while idx < len(diff_lines):
            cur = diff_lines[idx]
            if not cur.endswith("\n"):
                raise UnifiedDiffApplyError(f"truncated hunk record on line {idx + 1}")
            if cur.rstrip("\r\n") == "\\ No newline at end of file":
                if not body or not body[-1].endswith("\n"):
                    raise UnifiedDiffApplyError("orphaned or repeated no-newline marker")
                body[-1] = body[-1].removesuffix("\n").removesuffix("\r")
                idx += 1
                continue
            if consumed == old_count and produced == new_count:
                break
            if not cur or cur[0] not in (" ", "+", "-"):
                raise UnifiedDiffApplyError(f"malformed hunk prefix on line {idx + 1}")
            body.append(cur)
            consumed += cur[0] in (" ", "-")
            produced += cur[0] in (" ", "+")
            if consumed > old_count or produced > new_count:
                raise UnifiedDiffApplyError("hunk line count exceeds its declared range")
            idx += 1
        if consumed != old_count or produced != new_count:
            raise UnifiedDiffApplyError("hunk line count differs from its declared old/new range")
        hunks.append((old_start, old_count, new_start, new_count, body))

    if not hunks:
        raise UnifiedDiffApplyError("unified diff contains no hunks")

    out_lines: list[str] = []
    cursor = 0
    for old_start, old_count, new_start, new_count, body in hunks:
        # An empty range is anchored *after* its line; a nonempty one begins on it.
        start_idx = old_start if old_count == 0 else old_start - 1
        if start_idx < cursor or start_idx > len(orig_lines):
            raise UnifiedDiffApplyError(f"hunk start {old_start} out of bounds or overlapping")
        out_lines.extend(orig_lines[cursor:start_idx])
        new_idx = new_start if new_count == 0 else new_start - 1
        if new_idx != len(out_lines):
            raise UnifiedDiffApplyError("hunk new range does not match the output position")
        src_pos = start_idx
        for raw in body:
            op, content = raw[0], raw[1:]
            if op in (" ", "-"):
                if src_pos >= len(orig_lines) or orig_lines[src_pos] != content:
                    raise UnifiedDiffApplyError(f"hunk mismatch at source line {src_pos + 1}")
                if op == " ":
                    out_lines.append(content)
                src_pos += 1
            elif op == "+":
                out_lines.append(content)
        cursor = src_pos

    out_lines.extend(orig_lines[cursor:])
    if any(not line.endswith("\n") for line in out_lines[:-1]):
        raise UnifiedDiffApplyError("no-newline line is not the final output line")
    return "".join(out_lines)


def extract_declared_functions(source_text: str, language: str) -> set[str]:
    """Extract Python AST names or regex-matched names; signatures are not compared."""
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


def verify_patched_syntax(patched_text: str, language: str) -> tuple[bool | None, str | None]:
    """Parse Python without importing it; other languages have no commissioned parser here."""
    if language == "python":
        try:
            ast.parse(patched_text)
        except SyntaxError as exc:
            return False, f"Python syntax error on line {exc.lineno}: {exc.msg}"
        return True, None
    return None, None


def detect_guard_pattern(before_text: str, after_text: str, language: str) -> bool:
    """Match guard-like text in added lines; this is not control-flow or semantic analysis."""
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
                path=path, language=resolved_lang, hunks_applied=False, lexical_check_passed=None,
                syntax_valid=None, function_names_preserved=None, guard_pattern_detected=False,
                issues=("neither patched text nor unified diff was supplied",),
            )
        try:
            patched = apply_unified_diff_in_memory(before_text, unified_diff)
        except UnifiedDiffApplyError as exc:
            return FilePatchValidation(
                path=path, language=resolved_lang, hunks_applied=False, lexical_check_passed=None,
                syntax_valid=None, function_names_preserved=None, guard_pattern_detected=False,
                issues=(str(exc)[:240],),
            )
    else:
        patched = after_text

    if "\x00" in patched or "<<<<<<<" in patched:
        issues.append("patched source contains NUL bytes or merge conflict markers")

    lexical_ok, lexical_err = None, None
    if resolved_lang in SUPPORTED_REMEDIATION_LANGUAGES:
        lexical_ok, lexical_err, _, _ = scan_lexical_structure(patched, resolved_lang)
    if lexical_err:
        issues.append(lexical_err[:240])
    syntax_ok, syntax_err = verify_patched_syntax(patched, resolved_lang)
    if syntax_err:
        issues.append(syntax_err[:240])

    if before_text and resolved_lang in SUPPORTED_REMEDIATION_LANGUAGES:
        before_funcs = extract_declared_functions(before_text, resolved_lang)
        after_funcs = extract_declared_functions(patched, resolved_lang)
        deleted = sorted(before_funcs - after_funcs)
        functions_preserved = len(deleted) == 0
        if deleted:
            issues.append(f"patch deleted existing function(s): {', '.join(deleted[:4])}"[:240])
    else:
        functions_preserved = None

    guard_hardened = detect_guard_pattern(before_text, patched, resolved_lang)
    if not guard_hardened:
        issues.append("no added guard or sink-hardening text pattern was detected")

    return FilePatchValidation(
        path=path,
        language=resolved_lang,
        hunks_applied=True if after_text is None else None,
        lexical_check_passed=False if "\x00" in patched or "<<<<<<<" in patched else lexical_ok,
        syntax_valid=syntax_ok,
        function_names_preserved=functions_preserved,
        guard_pattern_detected=guard_hardened,
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

    def checked_all(values: Sequence[bool | None]) -> bool | None:
        if False in values:
            return False
        return True if values and all(value is True for value in values) else None

    applies_cleanly = checked_all([item.hunks_applied for item in results])
    lexical_passed = checked_all([item.lexical_check_passed for item in results])
    syntax_valid = checked_all([item.syntax_valid for item in results])
    names_preserved = checked_all([item.function_names_preserved for item in results])
    guard_detected = any(item.guard_pattern_detected for item in results)

    if not results or any(value is False for value in (
            applies_cleanly, lexical_passed, syntax_valid, names_preserved)):
        tier = "rejected"
    else:
        tier = "static_checked"

    return StaticPatchValidationResult(
        validation_tier=tier,
        patch_applies_cleanly=applies_cleanly,
        lexical_checks_passed=lexical_passed,
        syntax_valid=syntax_valid,
        function_names_preserved=names_preserved,
        guard_pattern_detected=guard_detected,
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
    "detect_guard_pattern",
    "verify_patched_syntax",
]
