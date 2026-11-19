"""T-5172: numeric apostrophes and the exported (not live job) unified-diff path."""
from __future__ import annotations

import pytest

from appsec_review.jobs.job_poc_generation.static_compile_check import (
    scan_lexical_structure, validate_static_poc_harness,
)
from appsec_review.jobs.job_remediation_validation.static_validator import (
    UnifiedDiffApplyError, apply_unified_diff_in_memory, validate_remediation_patch_set,
)


@pytest.mark.parametrize("number", ["1'000", "0xDEAD'BEEF", "0b1010'0101", "07'55",
                                  "1.25'00e1'0", ".1'25", "0x1'a.fp+1'0"])
def test_cpp_numeric_separators_are_not_character_literals(number):
    before = f"long read(int n) {{ long limit = {number}; return n; }}\n"
    after = before.replace("return n;", "if (n < 0) return -1; return n;")
    result = validate_remediation_patch_set([{"path": "read.cpp", "before_text": before, "after_text": after}])
    assert result.ok and result.lexical_checks_passed
    assert result.function_names_preserved and result.guard_pattern_detected
    assert result.syntax_valid is None and result.record()["runtime_verified"] is False


@pytest.mark.parametrize("literal", ["'7'", "L'7'", "u'7'", r"'\''", r"'\\'"])
def test_cpp_character_literals_remain_stripped(literal):
    source = f"void poc_control() {{ auto c = {literal}; assert(c); }}\n"
    ok, error, stripped, no_comments = scan_lexical_structure(source, "cpp")
    assert ok, error
    assert literal in no_comments
    assert stripped.endswith("; assert(c); }\n")
    assert "'7'" not in stripped


@pytest.mark.parametrize("tail", ["auto c = '7;", 'auto s = "unterminated;', "/* unclosed", "if (1) {"],
                         ids=["character", "string", "comment", "delimiter"])
def test_numeric_separator_does_not_hide_unclosed_literals_comments_or_delimiters(tail):
    ok, error, _, _ = scan_lexical_structure(f"long n = 1'000;\n{tail}", "cpp")
    assert not ok and error


def test_numeric_separator_does_not_hide_prohibited_calls_or_expose_comment_calls():
    source = 'void poc_control() { long n = 1\'000; assert(n); system("inert"); }\n'
    assert "shell_system" in validate_static_poc_harness(source, language="cpp").prohibited_primitives
    safe = source.replace('system("inert");', '/* system("inert"); */ auto c = \'7\';')
    result = validate_static_poc_harness(safe, language="cpp")
    assert result.ok and not result.prohibited_primitives


@pytest.mark.parametrize("old_start,new_start,expected", [
    (0, 1, "x\na\nb\n"), (1, 2, "a\nx\nb\n"), (2, 3, "a\nb\nx\n"),
], ids=["first", "middle", "last"])
def test_zero_context_insertions_use_empty_range_anchor(old_start, new_start, expected):
    diff = f"@@ -{old_start},0 +{new_start},1 @@\n+x\n"
    assert apply_unified_diff_in_memory("a\nb\n", diff) == expected


@pytest.mark.parametrize("diff", [
    "@@ -1 +1,99 @@\n-a\n+x\n",
    "@@ -1,2 +1 @@\n-a\n+x\n",
    "@@ -1 +2 @@\n-a\n+x\n",
    "@@ -0,1 +1 @@\n-a\n+x\n",
    "@@ -3,0 +4 @@\n+x\n",
    "@@ -1 +1 @@\n-wrong\n+x\n",
    "@@ -1 +1 @@\n-a\n+x\n@@ -1 +2 @@\n-a\n+y\n",
    "@@ -1 +1 @@\n?bad\n",
], ids=["new-count", "old-count", "new-start", "zero-nonempty-start", "out-of-bounds",
        "context-mismatch", "overlap", "prefix"])
def test_malformed_counts_coordinates_and_context_are_refused(diff):
    with pytest.raises(UnifiedDiffApplyError):
        apply_unified_diff_in_memory("a\nb\n", diff)


@pytest.mark.parametrize("before,diff,after", [
    ("", "@@ -0,0 +1 @@\n+x\n", "x\n"),
    ("a\n", "@@ -1 +0,0 @@\n-a\n", ""),
    ("a", "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+x\n", "x\n"),
    ("a\n", "@@ -1 +1 @@\n-a\n+x\n\\ No newline at end of file\n", "x"),
    ("a", "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+x\n\\ No newline at end of file\n", "x"),
    ("a\r\nb\r\n", "@@ -1,2 +1,2 @@\n a\r\n-b\r\n+x\r\n", "a\r\nx\r\n"),
    ("a\nb\nc\n", "@@ -1,0 +2 @@\n+x\n@@ -3 +4 @@\n-c\n+y\n", "a\nx\nb\ny\n"),
    ("-- old\n", "@@ -1 +1 @@\n--- old\n+new\n", "new\n"),
], ids=["empty", "delete-all", "add-final-newline", "remove-final-newline", "keep-no-newline",
        "crlf", "multiple-hunks", "header-like-body"])
def test_unified_diff_preserves_exact_line_endings_and_both_ranges(before, diff, after):
    assert apply_unified_diff_in_memory(before, diff) == after


@pytest.mark.parametrize("diff", [
    "@@ -1 +1 @@\n\\ No newline at end of file\n-a\n+x\n",
    "@@ -1 +1 @@\n-a\n+x\n\\ No newline at end of file\n\\ No newline at end of file\n",
    "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+x\n",
    "@@ -1,0 +2 @@\n+x\n\\ No newline at end of file\n",
], ids=["orphan", "duplicate", "old-newline-mismatch", "nonfinal"])
def test_invalid_no_newline_markers_are_refused(diff):
    with pytest.raises(UnifiedDiffApplyError):
        apply_unified_diff_in_memory("a\nb\n", diff)


@pytest.mark.parametrize("before,diff", [
    ("a\n", "@@ -1 +1 @@\n-a\n+b"),
    ("a", "@@ -1 +1 @@\n a"),
    ("a", "@@ -1 +0,0 @@\n-a"),
    ("a\r\n", "@@ -1 +1 @@\n-a\r\n+b\r"),
], ids=["addition", "context", "deletion", "crlf-addition"])
def test_truncated_hunk_records_are_not_implicit_no_newline_markers(before, diff):
    with pytest.raises(UnifiedDiffApplyError, match="truncated hunk record"):
        apply_unified_diff_in_memory(before, diff)
