from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).parents[1]
BUNDLE = ROOT / "rules" / "cpp-cert"
# The Semgrep/OpenGrep rules this crosswalk references live in the SEI CERT rule pack.
PACK = ROOT / "rules" / "sei-cert"
SEMGREP_IMAGE = "appsec-review/tool-semgrep:1.178.0"


def _coverage() -> dict:
    return json.loads((BUNDLE / "coverage.json").read_text(encoding="utf-8"))


def _semgrep_ids() -> set[str]:
    """Pack rule IDs referenced by the crosswalk."""
    return {rule_id for item in _coverage()["priorities"] for rule_id in item["semgrep"]}


def _canonical_finding_ids(document: dict) -> set[str]:
    prefix = "appsec-review.sei-cert."
    found: set[str] = set()
    for finding in document["results"]:
        check_id = finding["check_id"]
        assert prefix in check_id
        found.add(check_id[check_id.index(prefix):])
    return found


def _semgrep_rule_blocks() -> dict[str, str]:
    blocks: dict[str, str] = {}
    for path in sorted((PACK / "rules" / "cpp").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for block in re.split(r"(?=^  - id: )", text, flags=re.MULTILINE):
            match = re.search(r"^  - id: (appsec-review\.sei-cert\.cpp\.[a-z0-9.-]+)$", block, re.MULTILINE)
            if match:
                blocks[match.group(1)] = block
    return blocks


def _referenced_rule_files() -> list[str]:
    return sorted({f"rules/cpp/{rule_id.split('.')[3]}.yml" for rule_id in _semgrep_ids()})


def _referenced_fixtures() -> list[str]:
    return sorted({f"fixtures/cpp/{rule_id.split('.')[3]}.cpp" for rule_id in _semgrep_ids()})


def _expected_positive_lines() -> set[tuple[str, int]]:
    """(rule id, fixture line) pairs annotated as positive or variant in the pack fixtures."""
    expected: set[tuple[str, int]] = set()
    for relative in _referenced_fixtures():
        lines = (PACK / relative).read_text(encoding="utf-8").splitlines()
        pending: list[str] = []
        for number, line in enumerate(lines, start=1):
            match = re.match(r"\s*//\s*cert:\s*(positive|variant)\s+(\S+)", line)
            if match:
                pending.append(match.group(2))
            elif re.match(r"\s*//\s*cert:", line) or not line.strip():
                continue
            else:
                expected.update((rule_id, number) for rule_id in pending if rule_id in _semgrep_ids())
                pending = []
    return expected


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
    assert f"{len(_semgrep_ids())} SEI CERT pack rules" in result.stdout


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
    source_index = json.loads((PACK / "sources" / "cert-source-index.json").read_text(encoding="utf-8"))
    official_cwe = {entry["id"]: entry["cwe"] for entry in source_index["entries"]}

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
        # The official CERT page's CWE identifiers, as recorded in the SEI CERT source index.
        evidence += "\n" + " ".join(official_cwe.get(item["cert"], []))
        evidence_cwes = {f"CWE-{number}" for number in re.findall(r"CWE[- ]([0-9]+)", evidence)}
        assert set(item["cwe"]).issubset(evidence_cwes)

    assert referenced_local <= set(local_blocks)
    assert len(local_ids) == coverage["inventory"]["sei_cert_pack_rules"]


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


def _referenced_findings(document: dict) -> set[tuple[str, int]]:
    return {(rule_id, finding["start"]["line"])
            for finding in document["results"]
            if (rule_id := next(iter(_canonical_finding_ids({"results": [finding]})))) in _semgrep_ids()}


def test_semgrep_rules_hit_positive_fixture_and_not_clean_fixture() -> None:
    if not _docker_with_semgrep_image():
        pytest.skip(f"pinned local image is unavailable: {SEMGREP_IMAGE}")

    mount = f"{PACK.resolve()}:/pack:ro"
    command = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "-e", "SEMGREP_SEND_METRICS=off", "-e", "SEMGREP_ENABLE_VERSION_CHECK=0",
        "-v", mount, SEMGREP_IMAGE, "/opt/tool/bin/semgrep", "scan",
        "--disable-version-check", "--metrics", "off", "--json", "--quiet",
        *[argument for relative in _referenced_rule_files() for argument in ("--config", f"/pack/{relative}")],
        *[f"/pack/{relative}" for relative in _referenced_fixtures()],
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["errors"] == []
    assert _canonical_finding_ids(document) >= _semgrep_ids()
    assert _referenced_findings(document) == _expected_positive_lines()


def test_opengrep_parity_when_pinned_executable_is_available() -> None:
    executable = os.environ.get("APPSEC_REVIEW_OPENGREP") or shutil.which("opengrep")
    if executable is None or not Path(executable).is_file():
        pytest.skip("no pinned OpenGrep executable is available; parity remains a named coverage gap")
    # OpenGrep aborts at start-up when XDG_CONFIG_HOME does not exist.
    (ROOT / "test" / "tmp" / "opengrep-home" / ".config").mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            executable, "scan", "--json", "--disable-version-check",
            *[argument for relative in _referenced_rule_files() for argument in ("--config", str(PACK / relative))],
            *[str(PACK / relative) for relative in _referenced_fixtures()],
        ],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
        env={**os.environ, "HOME": str(ROOT / "test" / "tmp" / "opengrep-home"),
             "XDG_CONFIG_HOME": str(ROOT / "test" / "tmp" / "opengrep-home" / ".config")},
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["errors"] == []
    assert _canonical_finding_ids(document) >= _semgrep_ids()
    assert _referenced_findings(document) == _expected_positive_lines()
