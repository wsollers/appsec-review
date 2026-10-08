from __future__ import annotations

import json

import pytest
from pathlib import Path

from appsec_review.jobs.job_evidence_collection.adapters import ScanCatalog, adapter_registry
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope


def fixture_catalog() -> ScanCatalog:
    paths = [
        ("main.py", "Python"), ("main.go", "Go"), ("app.php", "PHP"), ("run.sh", "Shell"),
        ("MainActivity.java", "Java"), ("Dockerfile", None), ("main.tf", None),
        (".github/workflows/ci.yml", None), ("package-lock.json", None),
    ]
    return ScanCatalog("fingerprint", "handoff", tuple(
        {"path": path, "language": language, "sha256": str(index) * 64}
        for index, (path, language) in enumerate(paths, 1)), (), ())


def test_every_enabled_adapter_has_applicability_argv_exit_parser_and_limitations() -> None:
    registry = adapter_registry()
    assert len(registry) == 17
    catalog = fixture_catalog()
    for adapter in registry.values():
        selection = adapter.applicability(catalog)
        assert selection.reason and selection.coverage_kind
        if selection.applicable:
            argv = adapter.argv(f"/bin/{adapter.tool_id}", selection)
            assert argv[0] == f"/bin/{adapter.tool_id}"
            assert adapter.accepted_exit_codes
        payload = b"<BugCollection/>" if adapter.tool_id == "tool-spotbugs" else b"{}"
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
