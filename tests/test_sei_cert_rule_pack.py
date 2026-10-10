"""SEI CERT rule pack: static validation, rejection cases, and cross-engine execution.

Engine tests need Semgrep CE and OpenGrep at the versions pinned in rules/sei-cert/pack.json,
located through APPSEC_REVIEW_SEMGREP / APPSEC_REVIEW_OPENGREP or PATH. They skip with an explicit
reason when an engine is unavailable; a skipped engine test is a coverage gap, not a pass.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

pytest.importorskip("yaml", reason="the SEI CERT rule pack needs the 'rulepacks' extra (PyYAML)")

from appsec_review.rulepacks.sei_cert import engines
from appsec_review.rulepacks.sei_cert.evaluate import evaluate, score_rule, verify_evaluation
from appsec_review.rulepacks.sei_cert.fixtures import parse_expectations
from appsec_review.rulepacks.sei_cert.pack import PACK_ROOT, load_pack, verify_lock, write_lock
from appsec_review.rulepacks.sei_cert.report import render
from appsec_review.rulepacks.sei_cert.sources import build_source_index
from appsec_review.rulepacks.sei_cert.validate import (
    ANALYSIS_CLASSES, CONFIDENCE, EXCEPTION_HANDLING, STATUSES, validate,
)

ROOT = Path(__file__).parents[1]
PACK = load_pack()
RULE_IDS = sorted(rule.rule_id for rule in PACK.rules)


# Static validation ---------------------------------------------------------------------------

def test_pack_validates_without_engines() -> None:
    assert validate() == []


def test_every_official_rule_has_exactly_one_status() -> None:
    index_keys = {entry["key"] for entry in PACK.index["entries"]}
    mapped = [entry["key"] for mapping in PACK.mappings.values() for entry in mapping["rules"]]
    assert sorted(mapped) == sorted(index_keys)
    assert {entry["status"] for entry in PACK.entries.values()} <= set(STATUSES)
    assert len(index_keys) == 412


def test_schema_vocabularies_match_the_validator() -> None:
    schemas = ROOT / "docs" / "schemas"
    mapping = json.loads((schemas / "sei-cert-mapping.schema.json").read_text(encoding="utf-8"))
    entry = mapping["$defs"]["entry"]["properties"]
    assert tuple(entry["status"]["enum"]) == STATUSES
    assert tuple(entry["analysis_class"]["enum"]) == ANALYSIS_CLASSES
    assert tuple(entry["confidence"]["enum"]) == CONFIDENCE
    assert tuple(entry["exceptions"]["items"]["properties"]["handling"]["enum"]) == EXCEPTION_HANDLING
    manifest = json.loads((schemas / "sei-cert-rule-pack.schema.json").read_text(encoding="utf-8"))
    assert tuple(manifest["properties"]["statuses"]["const"]) == STATUSES
    for entry_doc in PACK.entries.values():
        assert set(entry_doc) <= set(entry), sorted(set(entry_doc) - set(entry))


def test_coverage_report_is_current() -> None:
    assert (PACK_ROOT / "COVERAGE.md").read_text(encoding="utf-8") == render(PACK)


def test_implemented_rules_are_partial_unless_complete() -> None:
    supported = sorted(entry["id"] for entry in PACK.entries.values() if entry["status"] == "SUPPORTED")
    assert supported == ["DCL50-CPP", "ERR52-CPP", "ERR61-CPP", "MSC30-C", "MSC50-CPP"]


def test_migrated_gap_rules_carry_corrected_cert_mappings() -> None:
    rules = PACK.rules_by_id()
    assert rules["appsec-review.sei-cert.cpp.mem51-cpp.array-new-scalar-delete"].metadata["cert"] == "MEM51-CPP"
    assert rules["appsec-review.sei-cert.cpp.exp54-cpp.escaping-reference-to-local"].metadata["cert"] == "EXP54-CPP"
    assert rules["appsec-review.sei-cert.c.con31-c.destroy-locked-mutex"].document["languages"] == ["c"]
    cpp_cert_coverage = json.loads((ROOT / "rules/cpp-cert/coverage.json").read_text(encoding="utf-8"))
    referenced = {rule_id for item in cpp_cert_coverage["priorities"] for rule_id in item["semgrep"]}
    assert referenced <= set(rules)


@pytest.fixture()
def pack_copy(tmp_path: Path) -> Path:
    destination = tmp_path / "sei-cert"
    shutil.copytree(PACK_ROOT, destination)
    assert validate(destination) == []
    return destination


def _rewrite(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _errors_after(root: Path, relock: bool = True) -> str:
    if relock:
        write_lock(root)
    return "\n".join(validate(root))


def test_rejects_duplicate_rule_ids(pack_copy: Path) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", "id: appsec-review.sei-cert.c.msc30-c.rand-call",
             "id: appsec-review.sei-cert.c.env33-c.command-processor-call")
    assert "duplicate rule id appsec-review.sei-cert.c.env33-c.command-processor-call" in _errors_after(pack_copy)


def test_rejects_unknown_cert_identifier(pack_copy: Path) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", "cert: MSC30-C", "cert: MSC99-C")
    assert "unknown CERT identifier 'MSC99-C'" in _errors_after(pack_copy)


def test_rejects_missing_mapping_status(pack_copy: Path) -> None:
    mapping = json.loads((pack_copy / "mappings/c.json").read_text(encoding="utf-8"))
    mapping["rules"] = [entry for entry in mapping["rules"] if entry["key"] != "ARR30-C"]
    (pack_copy / "mappings/c.json").write_text(json.dumps(mapping), encoding="utf-8")
    assert "official CERT rule ARR30-C has no mapping status" in _errors_after(pack_copy)


def test_rejects_wrong_or_missing_official_url(pack_copy: Path) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", "miscellaneous-msc/msc30-c", "miscellaneous-msc/msc31-c")
    assert "cert_url does not match the official URL" in _errors_after(pack_copy)


def test_rejects_unsupported_language(pack_copy: Path) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", "languages: [c]", "languages: [rust]")
    assert "are not supported for the c standard" in _errors_after(pack_copy)


def test_rejects_c_rule_applied_to_cpp_when_cert_says_it_does_not_apply(pack_copy: Path) -> None:
    source = pack_copy / "rules/c/con31-c.yml"
    _rewrite(source, "id: appsec-review.sei-cert.c.con31-c", "id: appsec-review.sei-cert.cpp.con31-c")
    _rewrite(source, "languages: [c]", "languages: [cpp]")
    _rewrite(source, "source_language: c", "source_language: cpp")
    assert "does not list CON31-C as applying to C++" in _errors_after(pack_copy)


@pytest.mark.parametrize(("old", "new", "message"), [
    ("severity: WARNING", "severity: CRITICAL", "invalid severity"),
    ("confidence: HIGH", "confidence: CERTAIN", "invalid confidence"),
])
def test_rejects_invalid_severity_and_confidence(pack_copy: Path, old: str, new: str, message: str) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", old, new)
    assert message in _errors_after(pack_copy)


def test_rejects_rule_without_positive_or_negative_fixtures(pack_copy: Path) -> None:
    fixture = pack_copy / "fixtures/c/msc30-c.c"
    text = fixture.read_text(encoding="utf-8")
    text = text.replace("// cert: positive ", "// cert: variant ").replace("// cert: negative ", "// cert: near-miss ")
    text = text.replace("// cert: safe-alternative ", "// cert: near-miss ")
    fixture.write_text(text, encoding="utf-8")
    errors = _errors_after(pack_copy)
    assert "msc30-c.rand-call: missing fixture cases: positive, negative" in errors


def test_rejects_fixtures_that_do_not_resolve(pack_copy: Path) -> None:
    mapping_path = pack_copy / "mappings/c.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    entry = next(item for item in mapping["rules"] if item["id"] == "MSC30-C")
    entry["implementation"]["fixtures"].append("fixtures/c/missing.c")
    mapping_path.write_text(json.dumps(mapping), encoding="utf-8")
    errors = _errors_after(pack_copy)
    assert "fixture fixtures/c/missing.c does not resolve" in errors


def test_rejects_unsafe_paths(pack_copy: Path) -> None:
    mapping_path = pack_copy / "mappings/c.json"
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    entry = next(item for item in mapping["rules"] if item["id"] == "MSC30-C")
    entry["implementation"]["fixtures"].append("../../etc/passwd")
    mapping_path.write_text(json.dumps(mapping), encoding="utf-8")
    assert "unsafe path: '../../etc/passwd'" in _errors_after(pack_copy)


def test_rejects_full_support_claim_for_tested_subset(pack_copy: Path) -> None:
    _rewrite(pack_copy / "fixtures/c/msc30-c.c", "// cert: near-miss", "// cert: known-false-negative")
    assert "MSC30-C: SUPPORTED conflicts with a known-false-negative fixture" in _errors_after(pack_copy)


def test_rejects_unexplained_engine_specific_expectation(pack_copy: Path) -> None:
    _rewrite(pack_copy / "fixtures/c/msc30-c.c",
             "// cert: positive appsec-review.sei-cert.c.msc30-c.rand-call",
             "// cert: positive appsec-review.sei-cert.c.msc30-c.rand-call engines=semgrep")
    assert "engine-specific expectation is not explained" in _errors_after(pack_copy)


@pytest.mark.parametrize(("content", "message"), [
    ("rules:\n  - id: [unclosed\n", "malformed YAML"),
    ("rules:\n  - id: a\n    id: b\n", "duplicate key 'id'"),
    ("rules:\n  - &base\n    id: a\n  - *base\n", "anchors and aliases are not portable"),
])
def test_rejects_malformed_or_nonportable_yaml(pack_copy: Path, content: str, message: str) -> None:
    (pack_copy / "rules/c/msc30-c.yml").write_text(content, encoding="utf-8")
    assert message in _errors_after(pack_copy)


@pytest.mark.parametrize(("addition", "message"), [
    ("    fix: srand(0)\n", "key 'fix' is not allowed"),
    ("    pattern-not-regex-everything: x\n", "unknown rule key"),
])
def test_rejects_autofix_and_nonportable_keys(pack_copy: Path, addition: str, message: str) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", "    pattern: rand()\n", "    pattern: rand()\n" + addition)
    assert message in _errors_after(pack_copy)


def test_rejects_unexpected_generated_output(pack_copy: Path) -> None:
    (pack_copy / "fixtures/c/semgrep-output.json").write_text("{}", encoding="utf-8")
    errors = _errors_after(pack_copy, relock=False)
    assert "unexpected file not recorded in pack.lock.json: fixtures/c/semgrep-output.json" in errors


def test_rejects_changed_locked_rule(pack_copy: Path) -> None:
    _rewrite(pack_copy / "rules/c/msc30-c.yml", "pattern: rand()", "pattern: rand(...)")
    assert "locked file changed: rules/c/msc30-c.yml" in verify_lock(pack_copy)


# Fixture annotations, normalization, and scoring ---------------------------------------------

@pytest.mark.parametrize(("source", "message"), [
    ("// cert: positive\nint x;\n", "malformed cert annotation"),
    ("// cert: maybe appsec-review.sei-cert.c.msc30-c.rand-call\nint x;\n", "unknown expectation kind"),
    ("int x;\n// cert: positive appsec-review.sei-cert.c.msc30-c.rand-call\n", "not followed by a code line"),
])
def test_annotation_parser_rejects_bad_annotations(tmp_path: Path, source: str, message: str) -> None:
    path = tmp_path / "bad.c"
    path.write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        parse_expectations(path, "bad.c")


def test_annotations_bind_to_the_next_code_line(tmp_path: Path) -> None:
    path = tmp_path / "ok.c"
    path.write_text("// cert: positive r.one\n// cert: variant r.two\n\nint x;\n", encoding="utf-8")
    bound = parse_expectations(path, "ok.c")
    assert [(item.rule_id, item.line) for item in bound] == [("r.one", 4), ("r.two", 4)]


def test_normalization_preserves_engine_errors_and_skips_as_gaps(tmp_path: Path) -> None:
    document = {
        "results": [{"check_id": "rules.sei-cert.rules.c.appsec-review.sei-cert.c.msc30-c.rand-call",
                     "path": "a.c", "start": {"line": 3}, "end": {"line": 3},
                     "extra": {"message": "MSC30-C:  rand", "severity": "WARNING", "lines": "requires login",
                               "metadata": {"cert": "MSC30-C"}}}],
        "errors": [{"level": "warn", "path": "b.c", "message": "Syntax error"}],
        "paths": {"scanned": ["a.c"], "skipped": [{"path": "c.c", "reason": "exceeded_size_limit"}]},
    }
    findings, gaps, scanned = engines.normalize("semgrep", document, tmp_path)
    assert findings[0].rule_id == "appsec-review.sei-cert.c.msc30-c.rand-call"
    assert findings[0].message == "MSC30-C: rand" and findings[0].cert == "MSC30-C"
    assert gaps == ["semgrep reported warn for b.c: Syntax error", "semgrep skipped c.c: exceeded_size_limit"]
    assert scanned == ["a.c"]


def test_missing_engine_is_a_named_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APPSEC_REVIEW_OPENGREP", str(tmp_path / "absent"))
    run = engines.run_engine("opengrep", [], ["x.c"], cwd=tmp_path, output_dir=tmp_path / "out")
    assert not run.succeeded and run.gaps == ["opengrep executable is not available"]


def test_scoring_counts_known_limits_without_hiding_them(tmp_path: Path) -> None:
    path = tmp_path / "f.c"
    path.write_text("// cert: positive r\na();\n// cert: known-false-negative r\nb();\n"
                    "// cert: unmodeled-exception:X-EX1 r\nc();\n// cert: near-miss r\nd();\n", encoding="utf-8")
    expectations = parse_expectations(path, "f.c")
    finding = lambda line: engines.Finding("semgrep", "r", "f.c", line, line, "m", "INFO", None)
    scored = score_rule("r", expectations, [finding(2), finding(6)], "semgrep")
    assert scored["failures"] == []
    assert scored["metrics"] | {} == {"true_positives": 1, "false_negatives": 0, "known_false_negatives": 1,
                                      "false_positives": 0, "known_false_positives": 1,
                                      "expected_exclusions": 1, "violated_exclusions": 0}
    noisy = score_rule("r", expectations, [finding(2), finding(6), finding(8), finding(4)], "semgrep")
    assert any("reported near-miss" in item for item in noisy["failures"])
    assert any("now detected" in item for item in noisy["failures"])


# Official source extraction ------------------------------------------------------------------

def _page(path: Path, tags: list[str], heading: str, body: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tag_block = "".join(f" - {tag}\n" for tag in tags)
    path.write_text(f"---\ntags: \n{tag_block}---\n# {heading}\n\n{body}\n", encoding="utf-8")


def test_source_index_extracts_metadata_without_prose(tmp_path: Path) -> None:
    checkout = tmp_path / "standards"
    content = checkout / "content"
    _page(content / "4.sei-cert-c-coding-standard/03.rules/07.environment-env/5.env33-c.md",
          ["rule", "cwe-78"], "ENV33-C. Do not call system()",
          "Prose that must not be copied.\n\n## Exceptions\n\n**ENV33-C-EX1:** allowed.\n**ENV33-EX1** alias.\n"
          "See **ERR34-C-EX9** elsewhere.\n\n## Related Guidelines\n\n"
          "[CWE-88](https://cwe.mitre.org/data/definitions/88.html)\n")
    _page(content / "4.sei-cert-c-coding-standard/03.rules/07.environment-env/1.index.md", ["rule-list"], "Environment (ENV)")
    _page(content / "4.sei-cert-c-coding-standard/03.rules/08.recommendation.md", ["recommendation"], "ENV01-C. Not a rule")
    _page(content / "5.sei-cert-cpp-coding-standard/3.rules/02.misc-msc/1.index.md", ["rule-list"], "Misc",
          "The following rules from the SEI CERT C Coding Standard also apply in C++:\n\n"
          "-   [ENV33-C. Do not call system()](/sei-cert-c-coding-standard/rules/environment-env/env33-c)\n")
    _page(content / "5.sei-cert-cpp-coding-standard/3.rules/02.misc-msc/2.msc50-cpp.md", ["rule"],
          "MSC50-CPP. Do not use std::rand()")
    _page(content / "6.sei-cert-oracle-coding-standard-for-java/3.rules/05.err/2.err07-j.md", ["rule"],
          "ERR07-J. Do not throw RuntimeException")
    for category in ("01.miscellaneous-msc/2.drd25-a.md", "02.cryptography-crp/2.drd25-b.md"):
        _page(content / "3.android-secure-coding-standard/3.rules" / category, ["rule"], "DRD25. Duplicate id")
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
                    "commit", "-q", "-m", "fixture"], check=True)
    index = build_source_index(checkout, retrieved="2026-10-10")
    entries = {entry["key"]: entry for entry in index["entries"]}
    assert sorted(entries) == ["DRD25@CRP", "DRD25@MSC", "ENV33-C", "ERR07-J", "MSC50-CPP"]
    env33 = entries["ENV33-C"]
    assert env33["url"].endswith("/sei-cert-c-coding-standard/rules/environment-env/env33-c")
    assert env33["cwe"] == ["CWE-78", "CWE-88"]
    assert env33["exceptions"] == ["ENV33-C-EX1"]
    assert env33["applies_to_cpp"] is True
    assert entries["DRD25@CRP"]["source_identifier_conflict"] is True
    assert "Prose that must not be copied" not in json.dumps(index)


# Cross-engine execution ----------------------------------------------------------------------

def _require_engines() -> None:
    for engine in engines.ENGINES:
        executable = engines.locate(engine)
        if executable is None:
            pytest.skip(f"{engine} is unavailable; cross-engine execution is an explicit coverage gap")
        version = engines.engine_version(engine, executable, ROOT / "test/tmp/sei-cert-engine-home" / engine)
        pinned = PACK.manifest["engines"][engine]["version"]
        if version != pinned:
            pytest.skip(f"{engine} {version} is not the pinned {pinned}; execution evidence would not apply")


@pytest.fixture(scope="module")
def evaluation(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    _require_engines()
    output = tmp_path_factory.mktemp("sei-cert-evaluation")
    return output, evaluate(output)


@pytest.mark.parametrize("rule_id", RULE_IDS)
@pytest.mark.parametrize("engine", engines.ENGINES)
def test_rule_matches_fixture_expectations(evaluation: tuple[Path, dict], engine: str, rule_id: str) -> None:
    result = evaluation[1]["rules"][rule_id]["engines"][engine]
    assert result["failures"] == []
    assert result["metrics"]["true_positives"] >= 2  # a positive and a syntactic variant
    assert result["metrics"]["expected_exclusions"] >= 2  # a negative and a near miss


def test_engines_execute_cleanly_and_agree(evaluation: tuple[Path, dict]) -> None:
    result = evaluation[1]
    for engine, data in result["engines"].items():
        assert data["succeeded"], result["fixtures"]["runs"][engine]["gaps"]
        assert data["version"] == PACK.manifest["engines"][engine]["version"]
    assert result["differential"]["agree"], result["differential"]["only_in"]
    for run in result["fixtures"]["runs"].values():
        assert sorted(run["scanned"]) == result["fixtures"]["files"]
        for finding in run["findings"]:
            assert finding["cert"] and finding["message"].startswith(finding["cert"].split("-")[0][:3])


def test_evaluation_passes_and_is_hash_verifiable(evaluation: tuple[Path, dict]) -> None:
    output, result = evaluation
    assert result["failures"] == []
    assert result["status"] == "PASSED"
    assert verify_evaluation(output) == []
    (output / "evaluation.json").write_text("{}", encoding="utf-8")
    assert verify_evaluation(output) == ["artifact changed: evaluation.json"]


def test_multivuln_findings_resolve_to_source_lines(evaluation: tuple[Path, dict]) -> None:
    multivuln = evaluation[1]["multivuln"]
    if multivuln["status"] == "NOT_RUN":
        pytest.skip(f"multivuln evaluation was not run: {multivuln['gap']}")
    assert multivuln["status"] == "PASSED", multivuln["failures"]
    assert multivuln["differential"]["agree"]
    expected = {(item["rule_id"], item["path"], item["line"]) for item in PACK.multivuln["expected_findings"]}
    for data in multivuln["engines"].values():
        findings = data["run"]["findings"]
        assert {(f["rule_id"], f["path"], f["start_line"]) for f in findings} == expected
        assert all(f["line_resolves"] and f["start_line_text"] and len(f["source_sha256"]) == 64 for f in findings)
