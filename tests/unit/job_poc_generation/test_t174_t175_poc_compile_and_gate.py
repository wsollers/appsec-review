"""Focused T-174 and T-175 unit tests for 9-language static PoC compile checks and strict non-execution gate."""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
import pytest
from referencing import Registry, Resource

from appsec_review.jobs.job_poc_generation import (
    GENERATED_CODE_EXECUTION_POLICY,
    POC_COMPILE_CHECK_SCHEMA,
    POC_EXECUTION_BLOCKED_CODE,
    PocExecutionBlockedByPolicyError,
    SUPPORTED_POC_LANGUAGES,
    detect_poc_language,
    enforce_poc_non_execution,
    guard_command_against_poc_execution,
    validate_static_poc_harness,
)
from appsec_review.jobs.job_poc_generation.settings import PocGenerationSettings

ROOT = Path(__file__).resolve().parents[3]
CLAIM_ID = "claim-" + "a" * 64


def _schema_validator() -> Draft202012Validator:
    schema_dir = ROOT / "docs" / "schemas" / "poc-generation"
    docs = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in sorted(schema_dir.glob("*.schema.json"))}
    registry = Registry().with_resources((doc["$id"], Resource.from_contents(doc)) for doc in docs.values())
    return Draft202012Validator(docs["poc-compile-check.schema.json"], registry=registry)


VALID_HARNESSES: dict[str, tuple[str, str]] = {
    "cpp": (
        "tests/poc_overflow.cpp",
        '#include <cassert>\n#include "parser.hpp"\n\nvoid poc_overflow() {\n    int rc = parse_frame("AAAA");\n    assert(rc < 0);\n}\n',
    ),
    "java": (
        "src/test/java/PocSqlTest.java",
        'import org.junit.jupiter.api.Test;\nimport static org.junit.jupiter.api.Assertions.assertEquals;\n\nclass PocSqlTest {\n    @Test\n    void pocSqlInjection() {\n        int status = parse_frame("OR 1=1");\n        assertEquals(400, status);\n    }\n}\n',
    ),
    "javascript": (
        "test/poc_xss.test.js",
        'const assert = require("node:assert");\nconst { parse_frame } = require("../src/frame");\n\ntest("poc xss guard", () => {\n    const out = parse_frame("<svg onload=1>");\n    expect(out).not.toContain("<svg");\n});\n',
    ),
    "python": (
        "tests/test_poc_sqli.py",
        'import pytest\nfrom app.parser import parse_frame\n\ndef test_poc_sqli():\n    res = parse_frame("OR 1=1")\n    assert res is not None\n',
    ),
    "ruby": (
        "spec/poc_deser_spec.rb",
        'require "rspec"\nrequire_relative "../lib/frame"\n\nRSpec.describe "PoC" do\n  it "reproduces parse_frame issue" do\n    res = parse_frame("bad_payload")\n    expect(res).to eq(:rejected)\n  end\nend\n',
    ),
    "go": (
        "internal/frame/poc_test.go",
        'package frame\n\nimport "testing"\n\nfunc TestPocParseFrame(t *testing.T) {\n    err := parse_frame("../../../etc/passwd")\n    if err == nil {\n        t.Fatalf("expected error from parse_frame")\n    }\n}\n',
    ),
    "csharp": (
        "Tests/PocFrameTests.cs",
        'using Xunit;\n\npublic class PocFrameTests {\n    [Fact]\n    public void PocParseFrame() {\n        var res = FrameParser.parse_frame("bad");\n        Assert.False(res.IsAllowed);\n    }\n}\n',
    ),
    "rust": (
        "tests/poc_frame.rs",
        'use crate::parser::parse_frame;\n\n#[test]\nfn poc_parse_frame_bounds() {\n    let res = parse_frame(b"\\xff\\xff");\n    assert!(res.is_err());\n}\n',
    ),
    "php": (
        "tests/PocFrameTest.php",
        '<?php\nuse PHPUnit\\Framework\\TestCase;\n\nfinal class PocFrameTest extends TestCase {\n    public function testPocParseFrame(): void {\n        $res = parse_frame("../secret");\n        $this->assertFalse($res);\n    }\n}\n',
    ),
}


@pytest.mark.parametrize("language", sorted(VALID_HARNESSES))
def test_nine_language_static_poc_compile_validator_accepts_valid_harnesses(language: str) -> None:
    assert set(SUPPORTED_POC_LANGUAGES) == set(VALID_HARNESSES)
    rel_path, source_text = VALID_HARNESSES[language]
    assert detect_poc_language(rel_path) == language
    res = validate_static_poc_harness(
        source_text,
        language=language,
        target_symbols=["parse_frame"],
        claim_id=CLAIM_ID,
    )
    assert res.ok is True, (language, res.violations)
    assert res.status == "static_checked"
    assert res.lexical_check_passed is True
    assert res.syntax_valid is (True if language == "python" else None)
    assert res.import_patterns_valid is True
    assert res.harness_entrypoint_detected is True
    assert res.oracle_or_control_pattern_detected is True
    assert res.target_symbol_text_present is True
    assert res.stub_patterns_absent is True
    assert res.prohibited_primitives == ()

    record = res.record()
    assert record["schema"] == POC_COMPILE_CHECK_SCHEMA
    assert record["generated_code_execution"] == "not_performed_by_policy"
    assert record["runtime_verified"] is False
    assert record["compiler_verified"] is False
    assert record["limitations"]
    _schema_validator().validate(record)


def test_static_poc_validator_rejects_broken_syntax_missing_target_and_prohibited_primitives() -> None:
    bad_syntax = validate_static_poc_harness(
        "#[test]\nfn poc_broken() {\n    let x = parse_frame(1);\n    assert_eq!(x, 0);\n",
        language="rust",
        target_symbols=["parse_frame"],
        claim_id=CLAIM_ID,
    )
    assert bad_syntax.ok is False
    assert bad_syntax.lexical_check_passed is False
    assert bad_syntax.syntax_valid is None

    missing_target = validate_static_poc_harness(
        "import pytest\ndef test_poc():\n    assert 1 + 1 == 2\n",
        language="python",
        target_symbols=["parse_frame"],
        claim_id=CLAIM_ID,
    )
    assert missing_target.ok is False
    assert missing_target.target_symbol_text_present is False

    prohibited = validate_static_poc_harness(
        'const assert = require("assert");\nconst cp = require("child_process");\ntest("poc", () => { parse_frame("x"); cp.execSync("id"); assert.ok(true); });\n',
        language="javascript",
        target_symbols=["parse_frame"],
        claim_id=CLAIM_ID,
    )
    assert prohibited.ok is False
    assert len(prohibited.prohibited_primitives) >= 1


def test_balanced_nonsense_is_not_compiler_or_parser_verification() -> None:
    res = validate_static_poc_harness(
        "void poc_bad() { this is not C++; assert(parse_frame(1)); }\n",
        language="cpp", target_symbols=["parse_frame"],
    )
    assert res.ok
    record = res.record()
    assert record["status"] == "static_checked"
    assert record["syntax_valid"] is None
    assert record["parser"] is None
    assert record["compiler_verified"] is False
    assert record["runtime_verified"] is False
    _schema_validator().validate(record)
    with pytest.raises(ValidationError):
        _schema_validator().validate({**record, "syntax_valid": True})


def test_python_parser_rejects_balanced_invalid_syntax_without_importing_target(tmp_path: Path) -> None:
    bad = validate_static_poc_harness(
        "def test_poc():\n    assert parse_frame(1) === 1\n", language="python",
    )
    assert bad.lexical_check_passed
    assert bad.syntax_valid is False
    assert not bad.ok
    marker = tmp_path / "must-not-execute"
    source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\ndef test_poc():\n    assert parse_frame(1)\n"
    parsed = validate_static_poc_harness(source, language="python", target_symbols=["parse_frame"])
    assert parsed.syntax_valid is True
    assert not marker.exists()


def test_t175_strict_poc_non_execution_gate_blocks_all_execution_attempts() -> None:
    assert GENERATED_CODE_EXECUTION_POLICY == "not_performed_by_policy"
    assert POC_EXECUTION_BLOCKED_CODE == "dynamic_poc_execution_prohibited_pending_t175_sandbox_approval"
    policy_state = enforce_poc_non_execution()
    assert policy_state["generated_code_execution"] == "not_performed_by_policy"
    assert policy_state["runtime_verified"] is False

    for bad_kwargs in (
        {"execute_poc": True},
        {"allow_execution": True},
        {"run_poc": True},
        {"sandbox_execute": True},
        {"dynamic_execution": True},
        {"generated_code_execution": "sandbox_executed"},
        {"runtime_verified": True},
        {"result_id": "pocres-123"},
        {"settings_mapping": {"execute_poc": True}},
        {"settings_mapping": {"policy": {"dynamic_execution": True}}},
    ):
        with pytest.raises(PocExecutionBlockedByPolicyError, match=POC_EXECUTION_BLOCKED_CODE):
            enforce_poc_non_execution(**bad_kwargs)

    base_raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["jobs"]["job_poc_generation"]["settings"]
    ok_cfg = PocGenerationSettings.from_mapping(base_raw)
    assert ok_cfg.enabled is True

    with pytest.raises(PocExecutionBlockedByPolicyError, match=POC_EXECUTION_BLOCKED_CODE):
        PocGenerationSettings.from_mapping({**base_raw, "execute_poc": True})

    for blocked_cmd in (
        ["pytest", "tests/test_poc.py"],
        ["python3", "-c", "import poc"],
        ["python3", "-m", "py_compile", "poc.py"],
        ["go", "test", "./..."],
        ["cargo", "test", "--no-run"],
        ["mvn", "test"],
        ["dotnet", "test"],
        ["node", "--check", "poc.js"],
        ["ruby", "-c", "poc.rb"],
        ["php", "-l", "poc.php"],
        ["g++", "poc.cpp", "-o", "poc"],
    ):
        with pytest.raises(PocExecutionBlockedByPolicyError, match=POC_EXECUTION_BLOCKED_CODE):
            guard_command_against_poc_execution(blocked_cmd)

    for compile_only_cmd in (
        ["g++", "-fsyntax-only", "poc.cpp"],
        ["clang++", "-c", "poc.cpp", "-o", "poc.o"],
        ["javac", "-c", "PocTest.java"],
        ["rustc", "--emit=metadata", "poc.rs"],
        ["nm", "poc.o"],
    ):
        guard_command_against_poc_execution(compile_only_cmd)
