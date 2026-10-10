from __future__ import annotations

import json

import pytest
from pathlib import Path

from appsec_review.jobs.job_evidence_collection.adapters import ScanCatalog, adapter_registry
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope
from appsec_review.jobs.cataloging import inventory, source_fingerprint


def fixture_catalog() -> ScanCatalog:
    paths = [
        ("main.py", "Python"), ("main.go", "Go"), ("app.php", "PHP"), ("run.sh", "Shell"),
        ("MainActivity.java", "Java"), ("native.cpp", "C++"), ("Dockerfile", None), ("main.tf", None),
        (".github/workflows/ci.yml", None), ("package-lock.json", None),
    ]
    return ScanCatalog("fingerprint", "handoff", tuple(
        {"path": path, "language": language, "sha256": str(index) * 64}
        for index, (path, language) in enumerate(paths, 1)), (), ())


def test_every_enabled_adapter_has_applicability_argv_exit_parser_and_limitations() -> None:
    registry = adapter_registry()
    assert len(registry) == 20
    catalog = fixture_catalog()
    for adapter in registry.values():
        selection = adapter.applicability(catalog)
        assert selection.reason and selection.coverage_kind
        if selection.applicable:
            argv = adapter.argv(f"/bin/{adapter.tool_id}", selection)
            assert argv[0] == f"/bin/{adapter.tool_id}"
            assert adapter.accepted_exit_codes
        payload = (b"<BugCollection/>" if adapter.tool_id == "tool-spotbugs" else
                   b"<results><errors/></results>" if adapter.tool_id == "tool-cppcheck" else b"{}")
        assert isinstance(adapter.parse(payload), list)
        assert len(adapter.parser_identity) == 64


def test_functional_fixture_manifest_has_every_enabled_tool() -> None:
    path = Path(__file__).parents[1] / "containers" / "fixtures" / "static-tool-cases.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert set(document["cases"]) == set(adapter_registry())
    for value in document["cases"].values():
        assert (path.parent / value["positive"]).is_file()


def test_tool_specific_parsers_preserve_native_ids_locations_and_packages() -> None:
    registry = adapter_registry()
    semgrep = registry["tool-semgrep"].parse(json.dumps({"results": [{"check_id": "SG-1", "path": "main.py",
        "start": {"line": 3}, "end": {"line": 4}, "extra": {"message": "bad", "severity": "ERROR"}}]}).encode())
    assert semgrep[0]["rule_id"] == "SG-1" and semgrep[0]["start_line"] == 3
    grype = registry["tool-grype"].parse(json.dumps({"matches": [{"artifact": {"name": "pkg", "id": "p1"},
        "vulnerability": {"id": "CVE-1", "severity": "High"}}]}).encode())
    assert grype[0]["package"] == "pkg" and grype[0]["advisory"] == "CVE-1"
    shellcheck = registry["tool-shellcheck"].parse(json.dumps({"comments": [{
        "file": "run.sh", "line": 3, "endLine": 3, "level": "warning",
        "code": 2086, "message": "Double quote to prevent globbing",
    }]}).encode())
    assert shellcheck[0]["rule_id"] == 2086 and shellcheck[0]["path"] == "run.sh"


def test_evidence_redacts_secret_values_bounds_records_and_rejects_uncataloged_locations(tmp_path) -> None:
    raw = tmp_path / "raw.json"
    raw.write_text("{}", encoding="utf-8")
    envelope = build_envelope(
        tool={"id": "tool-gitleaks"}, target_fingerprint="fp",
        applicability={"applicable": True}, coverage_scope={"paths": ["leak.txt"]}, gaps=(),
        raw_artifacts=(raw,), parser_identity="parser",
        observations=({"rule_id": "secret", "message": "token=abcd", "path": "outside.txt",
                       "line": 1, "secret": "abcd"},), cataloged_paths=("leak.txt",),
        terminal_status="SUCCEEDED", run_root=tmp_path,
    )
    record = envelope["records"][0]
    assert "abcd" not in json.dumps(record)
    assert record["location"] is None and record["artifact_evidence"]
    assert record["evidence_id"].startswith("evidence-")


def test_evidence_collapses_exact_duplicates_but_preserves_distinct_observations(tmp_path) -> None:
    raw = tmp_path / "raw.json"
    raw.write_text("{}", encoding="utf-8")
    common = {"rule_id": "rule-1", "message": "same location", "path": "main.py", "start_line": 4}
    envelope = build_envelope(
        tool={"id": "tool-semgrep"}, target_fingerprint="fp",
        applicability={"applicable": True}, coverage_scope={"paths": ["main.py"]}, gaps=(),
        raw_artifacts=(raw,), parser_identity="parser",
        observations=({**common, "severity": "HIGH"}, {**common, "severity": "HIGH"},
                      {**common, "severity": "LOW"}),
        cataloged_paths=("main.py",), terminal_status="SUCCEEDED", run_root=tmp_path,
    )
    assert envelope["record_count"] == 2
    assert len({record["evidence_id"] for record in envelope["records"]}) == 2


def test_checkov_typed_multi_vuln_scope_includes_supported_families_not_arbitrary_yaml() -> None:
    target = Path(__file__).parents[1] / "targets" / "appsec-multi-vuln"
    snapshot = inventory(target)
    catalog = ScanCatalog(source_fingerprint(target), "a" * 64, tuple(snapshot["files"]), (), (), target)
    adapter = adapter_registry()["tool-checkov"]
    selected = adapter.applicability(catalog)
    assert selected.applicable
    assert {"dockerfile", "github_actions"} <= set(selected.families)
    assert "projects/python/case-078/config.yaml" not in selected.files
    assert any(path.endswith("Dockerfile") for path in selected.families["dockerfile"])
    assert set(selected.families["github_actions"]) == {
        ".github/workflows/ci.yml", ".github/workflows/codeql.yml", ".github/workflows/verify.yml"}
    argv = adapter.argv("/opt/tool/bin/checkov", selected)
    assert "--framework" in argv and "dockerfile" in argv and "github_actions" in argv
    assert any("structural evidence" in gap for gap in selected.gaps)


def test_sei_cert_engines_share_the_pack_and_keep_engine_diagnostics_as_gaps() -> None:
    registry = adapter_registry()
    catalog = fixture_catalog()
    semgrep = registry["tool-semgrep"]
    opengrep = registry["tool-opengrep"]
    semgrep_argv = semgrep.argv("/bin/semgrep", semgrep.applicability(catalog))
    assert semgrep_argv[semgrep_argv.index("/rules-sei-cert") - 1] == "--config"
    selection = opengrep.applicability(catalog)
    assert selection.files == ("MainActivity.java", "native.cpp")
    argv = opengrep.argv("/bin/opengrep", selection)
    assert "--config" in argv and "/rules-sei-cert" in argv and "/rules/security.yml" not in argv
    assert any("not CERT conformance" in item for item in opengrep.limitations)
    kotlin = ScanCatalog("fp", "h", ({"path": "App.kt", "sha256": "1" * 64}, {"path": "a.c", "sha256": "2" * 64}), (), ())
    assert any("Kotlin" in gap for gap in opengrep.applicability(kotlin).gaps)
    payload = json.dumps({
        "results": [{"check_id": "rules-sei-cert.c.appsec-review.sei-cert.c.msc30-c.rand-call", "path": "a.c",
                     "start": {"line": 2}, "end": {"line": 2},
                     "extra": {"message": "MSC30-C", "severity": "WARNING", "metadata": {"cert": "MSC30-C"}}},
                    {"check_id": "appsec-review.python-dangerous-eval", "path": "m.py", "start": {"line": 1},
                     "end": {"line": 1}, "extra": {"message": "eval", "severity": "ERROR"}}],
        "errors": [{"level": "error", "rule_id": "bad-rule", "message": "Rule parse error"}],
        "paths": {"skipped": [{"path": "big.c", "reason": "exceeded_size_limit"}]},
    }).encode()
    for adapter in (semgrep, opengrep):
        records = adapter.parse(payload)
        assert records[0]["rule_id"] == "appsec-review.sei-cert.c.msc30-c.rand-call"
        assert records[0]["rule_mapping"] == {"cert": "MSC30-C"}
        assert "rule_mapping" not in records[1]
        gaps = [record["coverage_gap"] for record in records if record.get("gap_only")]
        assert gaps == ["engine reported error for bad-rule: Rule parse error",
                        "engine skipped big.c: exceeded_size_limit"]
