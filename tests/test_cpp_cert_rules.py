from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).parents[1]
BUNDLE = ROOT / "rules" / "cpp-cert"
SEMGREP_IMAGE = "appsec-review/tool-semgrep:1.178.0"


def _coverage() -> dict:
    return json.loads((BUNDLE / "coverage.json").read_text(encoding="utf-8"))


def _semgrep_ids() -> set[str]:
    text = (BUNDLE / "semgrep" / "cpp-cert-gap-rules.yml").read_text(encoding="utf-8")
    return set(re.findall(r"^\s*- id: (appsec-review\.cpp-cert\.[a-z0-9-]+)$", text, re.MULTILINE))


def _canonical_finding_ids(document: dict) -> set[str]:
    prefix = "appsec-review.cpp-cert."
    found: set[str] = set()
    for finding in document["results"]:
        check_id = finding["check_id"]
        assert prefix in check_id
        found.add(check_id[check_id.index(prefix):])
    return found


def _semgrep_rule_blocks() -> dict[str, str]:
    text = (BUNDLE / "semgrep" / "cpp-cert-gap-rules.yml").read_text(encoding="utf-8")
    blocks: dict[str, str] = {}
    for block in re.split(r"(?=^  - id: )", text, flags=re.MULTILINE):
        match = re.search(r"^  - id: (appsec-review\.cpp-cert\.[a-z0-9-]+)$", block, re.MULTILINE)
        if match:
            blocks[match.group(1)] = block
    return blocks


def test_locked_bundle_and_crosswalk_verify_offline() -> None:
    result = subprocess.run(
        [sys.executable, str(BUNDLE / "verify_bundle.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "117 CodeQL queries" in result.stdout
    assert "7 local Semgrep rules" in result.stdout


def test_codeql_pack_is_pinned_and_has_a_default_suite() -> None:
    pack = (BUNDLE / "codeql" / "cert" / "qlpack.yml").read_text(encoding="utf-8")
    dependency_lock = (BUNDLE / "codeql" / "cert" / "codeql-pack.lock.yml").read_text(
        encoding="utf-8"
    )
    assert "name: codeql/cert-cpp-coding-standards" in pack
    assert "version: 2.62.0" in pack
    assert "license: MIT" in pack
    assert "codeql/cpp-all: 5.0.0" in pack
    assert "codeql/common-cpp-coding-standards: '*'" in pack
    assert "codeql/cpp-all:\n    version: 5.0.0" in dependency_lock
    assert (BUNDLE / "codeql" / "cert" / "codeql-suites" / "cert-cpp-default.qls").is_file()


def test_priority_crosswalk_resolves_rules_and_mapping_evidence() -> None:
    coverage = _coverage()
    mapping_files = {
        "clang-tidy": BUNDLE / "mappings" / "codechecker" / "clang-tidy.json",
        "clangsa": BUNDLE / "mappings" / "codechecker" / "clangsa.json",
        "cppcheck": BUNDLE / "mappings" / "codechecker" / "cppcheck.json",
    }
    mapping_text = {name: path.read_text(encoding="utf-8").lower() for name, path in mapping_files.items()}
    guideline = (BUNDLE / "mappings" / "codechecker" / "sei-cert-cpp.yaml").read_text(
        encoding="utf-8"
    ).lower()
    local_ids = _semgrep_ids()
    local_blocks = _semgrep_rule_blocks()

    certs: set[str] = set()
    referenced_local: set[str] = set()
    for item in coverage["priorities"]:
        assert item["cert"] not in certs
        certs.add(item["cert"])
        canonical = item["cert"].lower()
        assert f"rule_id: {canonical}" in guideline
        for query in item["codeql"]:
            assert (BUNDLE / query).is_file()
        for engine in item["mapping_evidence"]:
            assert f"sei-cert-cpp:{canonical}" in mapping_text[engine]
        referenced_local.update(item["semgrep"])

        evidence = "\n".join(
            (BUNDLE / query).with_suffix(".md").read_text(encoding="utf-8")
            for query in item["codeql"]
        )
        evidence += "\n" + "\n".join(local_blocks[rule_id] for rule_id in item["semgrep"])
        evidence_cwes = {f"CWE-{number}" for number in re.findall(r"CWE[- ]([0-9]+)", evidence)}
        assert set(item["cwe"]).issubset(evidence_cwes)

    assert referenced_local == local_ids
    assert len(local_ids) == coverage["inventory"]["local_semgrep_rules"]


def _docker_with_semgrep_image() -> bool:
    if not shutil.which("docker"):
        return False
    check = subprocess.run(
        ["docker", "image", "inspect", SEMGREP_IMAGE],
        capture_output=True,
        timeout=15,
        check=False,
    )
    return check.returncode == 0


def test_semgrep_rules_hit_positive_fixture_and_not_clean_fixture() -> None:
    if not _docker_with_semgrep_image():
        pytest.skip(f"pinned local image is unavailable: {SEMGREP_IMAGE}")

    mount = f"{BUNDLE.resolve()}:/rules:ro"
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "-e", "SEMGREP_SEND_METRICS=off", "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
        "-v", mount, SEMGREP_IMAGE, "/opt/tool/bin/semgrep", "scan",
        "--disable-version-check", "--metrics", "off", "--json", "--quiet",
        "--config", "/rules/semgrep/cpp-cert-gap-rules.yml", "/rules/tests/semgrep",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["errors"] == []
    assert _canonical_finding_ids(document) == _semgrep_ids()
    assert len(document["results"]) == len(_semgrep_ids())
    assert all(finding["path"].endswith("positive.cpp") for finding in document["results"])


def test_opengrep_parity_when_pinned_executable_is_available() -> None:
    executable = shutil.which("opengrep")
    if executable is None:
        pytest.skip("no pinned OpenGrep executable is available; parity remains a named coverage gap")
    result = subprocess.run(
        [
            executable, "scan", "--json", "--config",
            str(BUNDLE / "semgrep" / "cpp-cert-gap-rules.yml"),
            str(BUNDLE / "tests" / "semgrep"),
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert _canonical_finding_ids(document) == _semgrep_ids()
    assert all(finding["path"].endswith("positive.cpp") for finding in document["results"])
