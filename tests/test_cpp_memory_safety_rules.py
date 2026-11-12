"""C/C++ memory-safety review signals and the generic secret rule.

The dataflow tools stay silent on an overrun that is possible rather than provable; these rules are the
cheap idiom layer that turns such code into a review lead (docs/operations/cpp-memory-safety-detection.md).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).parents[1]
SEMGREP = ROOT / "rules" / "semgrep"
GITLEAKS = ROOT / "rules" / "gitleaks"
FIXTURES = ROOT / "tests" / "fixtures" / "semgrep" / "cpp-memory-safety"
NEW_RULES = {"cpp-copy-length-not-bounded", "cpp-narrow-size-product", "cpp-allocation-size-from-narrow-product"}
SEMGREP_IMAGE = "appsec-review/tool-semgrep:1.178.0"
OPENGREP_IMAGE = "appsec-review/tool-opengrep:1.30.2"
GITLEAKS_IMAGE = "appsec-review/tool-gitleaks:8.30.1"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_semgrep_bundle_lock_matches_the_rule_files() -> None:
    lock = json.loads((SEMGREP / "rules.lock.json").read_text(encoding="utf-8"))
    for name, entry in lock["files"].items():
        assert _sha(SEMGREP / name) == entry["sha256"], f"{name} changed without updating rules.lock.json"


def test_the_gitleaks_bundle_lock_matches_its_rule_file() -> None:
    lock = json.loads((GITLEAKS / "rules.lock.json").read_text(encoding="utf-8"))
    assert lock["schema"] == "appsec-review/rule-bundle-lock/1"
    assert _sha(GITLEAKS / "generic-secrets.toml") == lock["files"]["generic-secrets.toml"]["sha256"]


def test_the_new_signals_are_sinks_for_c_and_cpp_and_only_leads() -> None:
    text = (SEMGREP / "review-signals.yml").read_text(encoding="utf-8")
    blocks = {block.splitlines()[0].strip(): block for block in re.split(r"\n  - id: ", "\n" + text)[1:]}
    names = {rule.rsplit(".", 1)[-1]: rule for rule in blocks}
    assert NEW_RULES <= set(names)
    for name in NEW_RULES:
        rule_id = names[name]
        assert rule_id == f"appsec-review.review-signal.sink.{name}"  # the category job_review_prioritization reads
        assert re.search(r"languages:\s*\[c, cpp\]", blocks[rule_id])
        assert "severity: INFO" in blocks[rule_id]  # a lead, never a finding


def test_the_registry_covers_both_bundles() -> None:
    import tomllib

    packs = {pack["id"]: pack for pack in tomllib.loads((ROOT / "rules" / "registry.toml").read_text())["packs"]}
    assert packs["semgrep-security"]["path"] == "rules/semgrep"
    assert packs["gitleaks-generic-secrets"]["path"] == "rules/gitleaks"
    assert packs["gitleaks-generic-secrets"]["engine"] == "gitleaks"


@pytest.mark.parametrize("line, hit", [
    ('const char relay_api_key[] = "rk_7f3c9a1e5b2d8f40c6a9e3b1d7f5c2a8";', True),
    ('static const char *auth_token = "tk_9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a";', True),
    ('const char *name = "hello world, plain text";', False),
    ('const char key[] = "short";', False),
    ('int api_key_length = 32;', False),
])
def test_the_widened_generic_api_key_pattern_matches_named_secret_literals_only(line: str, hit: bool) -> None:
    regex = re.search(r"regex = '''(.+)'''", (GITLEAKS / "generic-secrets.toml").read_text(encoding="utf-8")).group(1)
    assert bool(re.search(regex, line)) is hit
