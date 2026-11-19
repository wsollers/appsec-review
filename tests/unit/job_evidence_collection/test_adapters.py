"""Code-level unit tests for all 20 static tool adapters in adapters.py."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import pytest

from appsec_review.jobs.job_evidence_collection.adapters import (
    ADAPTERS,
    Applicability,
    ScanCatalog,
    _collect_blint,
    _gosec_args,
    _json,
    _list_records,
    _trivy_stderr_gaps,
    adapter_registry,
    checkov_unreported_inputs,
    semgrep_rule_languages,
    semgrep_unscanned_inputs,
)
from .support import EMPTY_REPORTS


def _cat(
    *paths: str,
    languages: dict[str, str | None] | None = None,
    artifacts: tuple[dict[str, object], ...] = (),
    target_root: Path | None = None,
    compile_commands: tuple[dict[str, object], ...] = (),
) -> ScanCatalog:
    langs = languages or {}
    files = tuple(
        {
            "path": path,
            "language": langs.get(path),
            "sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
        }
        for path in paths
    )
    return ScanCatalog("f" * 64, "h" * 64, files, (), artifacts, target_root, compile_commands)


def test_every_registered_adapter_has_applicability_argv_exit_parser_and_fixture_manifest(monkeypatch) -> None:
    def forbidden(value):
        raise AssertionError("supplied adapter source must not be fingerprinted")

    monkeypatch.setattr(inspect, "getsource", forbidden)
    registry = adapter_registry()
    assert len(registry) == 20 and set(registry) == set(ADAPTERS)
    catalog = _cat(
        "main.py",
        "main.go",
        "app.php",
        "run.sh",
        "MainActivity.java",
        "native.cpp",
        "Dockerfile",
        "main.tf",
        ".github/workflows/ci.yml",
        "package-lock.json",
        "build/App.class",
        artifacts=(
            {"path": "bin/libapp.so", "kind": "elf"},
            {"path": "build/app.jar", "kind": "jar"},
        ),
    )
    for adapter in registry.values():
        selection = adapter.applicability(catalog)
        assert selection.applicable and selection.reason and selection.coverage_kind
        argv = adapter.argv(f"/bin/{adapter.tool_id}", selection)
        assert argv[0] == f"/bin/{adapter.tool_id}"
        assert adapter.accepted_exit_codes
        payload = (
            b"<BugCollection/>"
            if adapter.tool_id == "tool-spotbugs"
            else b"<results><errors/></results>"
            if adapter.tool_id == "tool-cppcheck"
            else json.dumps(EMPTY_REPORTS[adapter.tool_id]).encode()
        )
        assert isinstance(adapter.parse(payload), list)
        assert adapter.adapter_identity == "undeclared"
        assert adapter.parser_identity == (
            "syft-package-observations/2" if adapter.tool_id == "tool-syft" else "undeclared"
        )

    manifest_path = Path(__file__).resolve().parents[3] / "containers" / "fixtures" / "static-tool-cases.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert set(document["cases"]) == set(registry)


def test_low_level_decoders_semgrep_languages_and_list_records_edge_cases(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="scanner output is empty"):
        _json(b"   ")
    with pytest.raises(json.JSONDecodeError):
        _json(b"{not-json")

    rule_a = tmp_path / "a.yml"
    rule_a.write_text("rules:\n  - id: r1\n    languages: [python, javascript]\n", encoding="utf-8")
    rule_b = tmp_path / "b.yml"
    rule_b.write_text("rules:\n  - id: r2\n    languages:\n      - go\n      - c\n", encoding="utf-8")
    langs = semgrep_rule_languages([rule_a, rule_b])
    assert langs == frozenset({"python", "javascript", "go", "c"})
    assert semgrep_rule_languages([tmp_path / "missing.yml"]) is None

    unscanned_gaps, unscanned_na = semgrep_unscanned_inputs(
        json.dumps({"paths": {"scanned": ["/target/a.py"], "skipped": []}}).encode("utf-8"),
        ("a.py", "b.py", "c.rb"),
        langs,
        lambda p: p.removeprefix("/target/"),
    )
    assert len(unscanned_gaps) == 1 and "b.py" in unscanned_gaps[0]
    assert len(unscanned_na) == 1 and unscanned_na[0][0] == "c.rb"

    missing_scanned, _ = semgrep_unscanned_inputs(b"{}", ("a.py",), langs, lambda p: p)
    assert "did not report scanned paths" in missing_scanned[0]

    # _list_records supports both list and {"findings": [...]} shapes
    list_doc = json.dumps({
        "findings": [{
            "id": "unpinned-uses",
            "severity": "High",
            "description": "unpinned action",
            "file": ".github/workflows/ci.yml",
            "line": 9,
            "endLine": 10,
        }]
    }).encode("utf-8")
    (ziz_rec,) = ADAPTERS["tool-zizmor"].parse(list_doc)
    assert ziz_rec["rule_id"] == "unpinned-uses"
    assert ziz_rec["path"] == ".github/workflows/ci.yml" and ziz_rec["start_line"] == 9
    with pytest.raises(ValueError, match="requires results"):
        _list_records(b"{}", "configuration")


def test_gitleaks_semgrep_opengrep_gosec_and_mobsfscan_adapters() -> None:
    # gitleaks
    assert not ADAPTERS["tool-gitleaks"].applicability(_cat()).applicable
    (gl,) = ADAPTERS["tool-gitleaks"].parse(
        json.dumps([{
            "RuleID": "generic-api-key",
            "Description": "Secret-named literal",
            "StartLine": 6,
            "EndLine": 7,
            "File": "/target/src/config.cpp",
            "Secret": "REDACTED",
        }]).encode()
    )
    assert (gl["path"], gl["start_line"], gl["end_line"], gl["severity"]) == ("/target/src/config.cpp", 6, 7, "UNKNOWN")

    # semgrep + opengrep applicability, gaps, and rule_mapping
    empty_cat = _cat("README.md")
    assert not ADAPTERS["tool-semgrep"].applicability(empty_cat).applicable
    assert not ADAPTERS["tool-opengrep"].applicability(empty_cat).applicable

    mixed_cat = _cat("App.kt", "main.cpp", "Main.java", "script.rb")
    sg_sel = ADAPTERS["tool-semgrep"].applicability(mixed_cat)
    assert sg_sel.applicable and "script.rb" in sg_sel.files
    og_sel = ADAPTERS["tool-opengrep"].applicability(mixed_cat)
    assert og_sel.files == ("Main.java", "main.cpp")
    assert any("Kotlin" in gap for gap in og_sel.gaps)

    sg_payload = json.dumps({
        "results": [
            {
                "check_id": "rules-sei-cert.c.appsec-review.sei-cert.c.msc30-c.rand-call",
                "path": "main.cpp",
                "start": {"line": 2},
                "end": {"line": 2},
                "extra": {"message": "MSC30-C", "severity": "WARNING", "metadata": {"cert": "MSC30-C"}},
            },
            {
                "check_id": "appsec-review.python-eval",
                "path": "m.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "eval", "severity": "ERROR"},
            },
        ],
        "errors": [{"level": "error", "rule_id": "bad-rule", "message": "Rule parse error"}],
        "paths": {"skipped": [{"path": "big.c", "reason": "exceeded_size_limit"}]},
    }).encode()
    for tool_id in ("tool-semgrep", "tool-opengrep"):
        recs = ADAPTERS[tool_id].parse(sg_payload)
        assert recs[0]["rule_id"] == "appsec-review.sei-cert.c.msc30-c.rand-call"
        assert recs[0]["rule_mapping"] == {"cert": "MSC30-C"}
        assert "rule_mapping" not in recs[1]
        assert [r["coverage_gap"] for r in recs if r.get("gap_only")] == [
            "engine reported error for bad-rule: Rule parse error",
            "engine skipped big.c: exceeded_size_limit",
        ]

    # gosec package-dir argv & line-range parsing
    go_sel = ADAPTERS["tool-gosec"].applicability(_cat("main.go", "pkg/sub/util.go"))
    go_argv = _gosec_args("/bin/gosec", go_sel)
    assert go_argv[-2:] == ("/target", "/target/pkg/sub")
    (gs,) = ADAPTERS["tool-gosec"].parse(
        json.dumps({
            "Issues": [{
                "rule_id": "G204",
                "severity": "HIGH",
                "details": "Subprocess launched",
                "file": "/target/pkg/sub/util.go",
                "line": "15-18",
            }]
        }).encode()
    )
    assert (gs["rule_id"], gs["start_line"], gs["end_line"]) == ("G204", "15-18", 1)

    # mobsfscan applicability & parser
    assert not ADAPTERS["tool-mobsfscan"].applicability(_cat("main.py")).applicable
    mobile_cat = _cat("src/MainActivity.kt")
    mob_sel = ADAPTERS["tool-mobsfscan"].applicability(mobile_cat)
    assert mob_sel.applicable
    (mob,) = ADAPTERS["tool-mobsfscan"].parse(
        json.dumps({
            "results": {
                "android_kotlin_webview": {
                    "metadata": {"severity": "WARNING", "description": "Insecure WebView"},
                    "files": [{"file_path": "/target/src/MainActivity.kt", "match_lines": [10, 14]}],
                }
            }
        }).encode()
    )
    assert (mob["rule_id"], mob["start_line"], mob["end_line"]) == ("android_kotlin_webview", 10, 14)


def test_cppcheck_compile_database_validation_and_pmd_shellcheck_php_spotbugs_parsers(tmp_path: Path) -> None:
    # Cppcheck compile_commands edge cases: multiple DBs, broken JSON, outside directory, missing source
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.cpp").write_text("int main(){}\n", encoding="utf-8")
    multi_cat = _cat(
        "compile_commands.json",
        "sub/compile_commands.json",
        "src/a.cpp",
        target_root=tmp_path,
        compile_commands=({"path": "compile_commands.json"}, {"path": "sub/compile_commands.json"}),
    )
    multi_sel = ADAPTERS["tool-cppcheck"].applicability(multi_cat)
    assert multi_sel.coverage_kind == "cpp_source_without_build_context"
    assert any("multiple compile_commands.json" in g for g in multi_sel.gaps)

    # Outside directory falls back to source mode or is filtered during prerequisite sanitization
    (tmp_path / "compile_commands.json").write_text("not-json", encoding="utf-8")
    outside_cat = _cat(
        "compile_commands.json",
        "src/a.cpp",
        target_root=tmp_path,
        compile_commands=({"path": "compile_commands.json"},),
    )
    outside_sel = ADAPTERS["tool-cppcheck"].applicability(outside_cat)
    assert outside_sel.coverage_kind == "cpp_source_without_build_context"
    assert any("invalid or exceeded" in g for g in outside_sel.gaps)

    # Valid compile DB accepted
    (tmp_path / "compile_commands.json").write_text(
        json.dumps([{"directory": str(tmp_path), "file": "src/a.cpp", "command": "c++ -c src/a.cpp"}]),
        encoding="utf-8",
    )
    ok_sel = ADAPTERS["tool-cppcheck"].applicability(outside_cat)
    assert ok_sel.coverage_kind == "cpp_compile_database"
    assert "--project=/inputs/compile_commands.json" in ADAPTERS["tool-cppcheck"].argv("/bin/cppcheck", ok_sel)

    # Unsafe parent path rejected in argv
    with pytest.raises(ValueError, match="catalog path is unsafe"):
        ADAPTERS["tool-cppcheck"].argv(
            "/bin/cppcheck",
            Applicability(True, "x", ("../escape.cpp",), "cpp_source_without_build_context"),
        )

    # Cppcheck XML parser separates findings from missingIncludeSystem coverage gaps
    cpp_records = ADAPTERS["tool-cppcheck"].parse(
        b"<results><errors>"
        b"<error id='nullPointer' severity='error' msg='null deref'><location file='/target/src/a.cpp' line='4'/></error>"
        b"<error id='missingIncludeSystem' severity='information' msg='no header'><location file='/target/src/a.cpp' line='1'/></error>"
        b"<error id='deallocuse' severity='error' msg='used after free' cwe='416'><location file='/target/src/a.cpp' line='9'/></error>"
        b"</errors></results>"
    )
    assert cpp_records[0]["rule_id"] == "nullPointer" and "rule_mapping" not in cpp_records[0]
    assert cpp_records[1]["gap_only"] is True
    # The raw ``cwe`` attribute reaches the lead as rule_mapping.cwe so correlation and routing can use it.
    assert cpp_records[2]["rule_mapping"] == {"cwe": "CWE-416"}

    # PMD processingErrors -> gap_only; configurationErrors -> raises ValueError
    pmd_records = ADAPTERS["tool-pmd"].parse(
        json.dumps({
            "files": [{
                "filename": "/target/Main.java",
                "violations": [{"rule": "R1", "description": "desc", "priority": 4, "beginline": 2, "endline": 3}],
                "processingErrors": [{"msg": "Lexical error"}],
            }],
            "configurationErrors": [],
        }).encode()
    )
    assert pmd_records[0]["severity"] == "LOW"
    assert pmd_records[1]["gap_only"] is True and "PMD could not process" in pmd_records[1]["coverage_gap"]
    with pytest.raises(ValueError, match="tool-pmd output parser failed: ValueError"):
        ADAPTERS["tool-pmd"].parse(json.dumps({"files": [], "configurationErrors": [{"msg": "bad"}]}).encode())

    # ShellCheck list form + SC1071 non-shell classification
    sc_records = ADAPTERS["tool-shellcheck"].parse(
        json.dumps([
            {"file": "/target/build.bat", "line": 1, "endLine": 1, "level": "error", "code": 1071, "message": "not sh"},
            {"file": "/target/run.sh", "line": 3, "endLine": 3, "level": "warning", "code": 2086, "message": "quote"},
        ]).encode()
    )
    assert sc_records[0]["not_applicable_input"] == "/target/build.bat"
    assert sc_records[1]["rule_id"] == 2086

    # phpcs, phpstan, psalm, spotbugs
    (phpcs_rec,) = ADAPTERS["tool-phpcs"].parse(
        json.dumps({
            "files": {"/target/app.php": {"messages": [{"source": "Squiz.PHP.Eval", "type": "ERROR", "message": "eval", "line": 8}]}}
        }).encode()
    )
    assert phpcs_rec["rule_id"] == "Squiz.PHP.Eval" and phpcs_rec["start_line"] == 8

    (phpstan_rec,) = ADAPTERS["tool-phpstan"].parse(
        json.dumps({
            "files": {"/target/app.php": {"messages": [{"identifier": "argument.type", "message": "bad arg", "line": 11}]}}
        }).encode()
    )
    assert phpstan_rec["rule_id"] == "argument.type"

    (psalm_rec,) = ADAPTERS["tool-psalm"].parse(
        json.dumps([{
            "id": "TaintedHtml",
            "severity": "error",
            "message": "tainted",
            "file": "/target/app.php",
            "line": 5,
        }]).encode()
    )
    assert psalm_rec["rule_id"] == "TaintedHtml" and psalm_rec["start_line"] == 5

    # SpotBugs applicability (source-only Java is not applicable; .class is applicable)
    java_src_only = ADAPTERS["tool-spotbugs"].applicability(_cat("src/Main.java"))
    assert not java_src_only.applicable
    # SpotBugs applicability
    sb_records = ADAPTERS["tool-spotbugs"].parse(
        b"<BugCollection><BugInstance type='SQL_INJECTION' priority='1' category='SECURITY'>"
        b"<LongMessage>sql</LongMessage><SourceLine sourcepath='src/Main.java' start='12' end='14'/>"
        b"</BugInstance></BugCollection>"
    )
    assert (sb_records[0]["rule_id"], sb_records[0]["severity"], sb_records[0]["start_line"]) == (
        "SQL_INJECTION",
        "1",
        "12",
    )


def test_syft_osv_grype_hadolint_checkov_trivy_and_blint_adapters(tmp_path: Path) -> None:
    # Syft retains package version, purl, language, type, and location selector
    (syft_rec,) = ADAPTERS["tool-syft"].parse(
        json.dumps({
            "artifacts": [{
                "name": "express",
                "version": "4.18.2",
                "type": "npm",
                "purl": "pkg:npm/express@4.18.2",
                "language": "javascript",
                "locations": [{"path": "/target/package-lock.json"}],
            }]
        }).encode()
    )
    assert (syft_rec["package"], syft_rec["version"], syft_rec["purl"], syft_rec["path"]) == (
        "express",
        "4.18.2",
        "pkg:npm/express@4.18.2",
        "/target/package-lock.json",
    )

    # OSV-Scanner parses advisory + UNKNOWN default severity (advisory DB lookup happens downstream)
    (osv_rec,) = ADAPTERS["tool-osv-scanner"].parse(
        json.dumps({
            "results": [{
                "source": {"path": "/target/package-lock.json"},
                "packages": [{
                    "package": {"name": "lodash"},
                    "vulnerabilities": [{
                        "id": "GHSA-1111",
                        "summary": "prototype pollution",
                    }],
                }],
            }]
        }).encode()
    )
    assert (osv_rec["advisory"], osv_rec["package"], osv_rec["severity"]) == ("GHSA-1111", "lodash", "UNKNOWN")

    # Grype
    (grype_rec,) = ADAPTERS["tool-grype"].parse(
        json.dumps({
            "matches": [{"artifact": {"name": "openssl"}, "vulnerability": {"id": "CVE-2024-0001", "severity": "Critical"}}]
        }).encode()
    )
    assert grype_rec["advisory"] == "CVE-2024-0001" and grype_rec["severity"] == "Critical"

    # Hadolint
    (hado_rec,) = ADAPTERS["tool-hadolint"].parse(
        json.dumps([{"code": "DL3008", "level": "warning", "message": "pin apt", "file": "/target/Dockerfile", "line": 3}]).encode()
    )
    assert hado_rec["rule_id"] == "DL3008"

    # Checkov applicability, unreported inputs, and parse errors
    ckv_adapter = ADAPTERS["tool-checkov"]
    planned = Applicability(
        True,
        "planned",
        ("CMakePresets.json", "Dockerfile", "infra/main.tf", "sub/deep/main.tf"),
        "checkov_typed_configuration",
    )
    ckv_argv = ckv_adapter.argv("/opt/checkov", planned)
    assert "--framework" not in ckv_argv
    ckv_report = json.dumps([
        {
            "check_type": "dockerfile",
            "results": {
                "passed_checks": [{"check_id": "CKV_1", "file_path": "/target/Dockerfile", "file_line_range": [1, 2]}],
                "failed_checks": [],
            },
        },
        {
            "check_type": "terraform",
            "results": {
                "passed_checks": [{"check_id": "CKV_2", "file_path": "/infra/main.tf", "file_line_range": [1, 2]}],
                "failed_checks": [{
                    "check_id": "CKV_3",
                    "check_name": "bad tf",
                    "severity": "HIGH",
                    "file_path": "/sub/deep/main.tf",
                    "file_line_range": [3, 5],
                }],
            },
        },
    ]).encode()
    assert checkov_unreported_inputs(ckv_report, planned.files) == ["CMakePresets.json"]
    with pytest.raises(ValueError, match="requires results"):
        checkov_unreported_inputs(b'{"passed":0}', planned.files)
    ckv_parsed = ckv_adapter.parse(ckv_report)
    assert len(ckv_parsed) == 1 and ckv_parsed[0]["rule_id"] == "CKV_3"

    broken_ckv = json.dumps({"check_type": "cloudformation", "results": {"parsing_errors": ["/../target/bad.yaml"]}}).encode()
    assert checkov_unreported_inputs(broken_ckv, ("bad.yaml",)) == []
    assert ckv_adapter.parse(broken_ckv)[0]["gap_only"] is True

    # Trivy misconfigurations + stderr_gaps
    trivy_records = ADAPTERS["tool-trivy"].parse(
        json.dumps({
            "Results": [{
                "Target": "Dockerfile",
                "Misconfigurations": [{
                    "ID": "DS002",
                    "Severity": "HIGH",
                    "Message": "root user",
                    "CauseMetadata": {"StartLine": 1, "EndLine": 1},
                }],
            }]
        }).encode()
    )
    assert [r["rule_id"] for r in trivy_records] == ["DS002"]
    assert _trivy_stderr_gaps(b"ok\n") == []
    assert len(_trivy_stderr_gaps(b"WARN failed to download checks bundle\n")) == 1

    # Blint collector + parser + applicability
    assert not ADAPTERS["tool-blint"].applicability(_cat("main.py")).applicable
    blint_sel = ADAPTERS["tool-blint"].applicability(
        _cat("main.py", artifacts=({"path": "bin/libapp.so", "artifact_kind": "built"},))
    )
    assert blint_sel.applicable and blint_sel.files == ("bin/libapp.so",)

    scratch = tmp_path / "blint-scratch"
    scratch.mkdir()
    _collect_blint(scratch)
    empty_blint = ADAPTERS["tool-blint"].parse((scratch / "blint-report.json").read_bytes())
    assert any("no per-binary analysis report" in r.get("coverage_gap", "") for r in empty_blint)

    (scratch / "libapp.so-metadata.json").write_text(
        '{"file_path": "/target/bin/libapp.so", "has_nx": false}', encoding="utf-8"
    )
    (scratch / "reviews.json").write_text('{"reviews": [{"exe_name": "/target/bin/libapp.so"}]}', encoding="utf-8")
    (scratch / "findings.json").write_text(
        json.dumps({"findings": [{"id": "BLINT-1", "severity": "high", "title": "nx disabled", "filename": "/target/bin/libapp.so"}]}),
        encoding="utf-8",
    )
    _collect_blint(scratch)
    blint_recs = ADAPTERS["tool-blint"].parse((scratch / "blint-report.json").read_bytes())
    assert [r["rule_id"] for r in blint_recs] == ["BLINT-1"]

    truncated_blint = ADAPTERS["tool-blint"].parse(
        json.dumps({"findings": [], "analyzed": [{"report": "a-metadata.json"}], "truncated": True}).encode()
    )
    assert any("truncated" in r.get("coverage_gap", "") for r in truncated_blint)


def test_safe_catalog_file_cppcheck_and_semgrep_skip_edge_branches(tmp_path: Path) -> None:
    from appsec_review.jobs.job_evidence_collection.adapters import _safe_catalog_file

    target = tmp_path / "t"
    target.mkdir()
    (target / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (target / "compile_commands.json").write_text("{not-json", encoding="utf-8")

    no_root_cat = _cat("main.c", target_root=None)
    assert _safe_catalog_file(no_root_cat, "main.c", limit=1024) is None

    rooted_cat = _cat(
        "main.c",
        target_root=target,
        compile_commands=({"path": "compile_commands.json"},),
    )
    assert _safe_catalog_file(rooted_cat, "/abs/path.c", limit=1024) is None
    assert _safe_catalog_file(rooted_cat, "../escape.c", limit=1024) is None
    assert _safe_catalog_file(rooted_cat, "missing.c", limit=1024) is None
    assert _safe_catalog_file(rooted_cat, "main.c", limit=2) is None
    assert _safe_catalog_file(rooted_cat, "main.c", limit=1024) is not None

    invalid_cc = ADAPTERS["tool-cppcheck"].applicability(rooted_cat)
    assert invalid_cc.applicable and any("invalid or exceeded" in g for g in invalid_cc.gaps)

    ambig_cat = _cat(
        "main.c",
        target_root=target,
        compile_commands=({"path": "a/compile_commands.json"}, {"path": "b/compile_commands.json"}),
    )
    ambig_cc = ADAPTERS["tool-cppcheck"].applicability(ambig_cat)
    assert ambig_cc.applicable and any("multiple compile_commands.json" in g for g in ambig_cc.gaps)

    semgrep_skip = ADAPTERS["tool-semgrep"].parse(
        json.dumps({
            "results": [],
            "errors": [{"level": "warn", "path": "/target/a.py", "message": "parse err"}],
            "paths": {
                "skipped": [
                    {"path": "/target/big.py", "reason": "max_target_bytes"},
                ]
            },
        }).encode()
    )
    assert len(semgrep_skip) == 2
    assert all(r.get("gap_only") is True for r in semgrep_skip)

