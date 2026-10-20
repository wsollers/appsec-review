"""The [banned_functions] table, the rule file generated from it, and what the engines report.

Microsoft's SDL ``banned.h`` names are listed in ``appsec-review.toml``; ``rules/semgrep/banned-functions.yml``
is generated from them (docs/operations/cpp-memory-safety-detection.md).
"""

from __future__ import annotations

import json
from pathlib import Path
import random
import shutil
import subprocess
import tomllib

import pytest

from appsec_review.config.banned_functions import BannedFunctions, parse_banned_functions
from appsec_review.rulepacks import banned_functions as generator

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "semgrep" / "banned-functions"
RULE_PREFIX = generator.RULE_PREFIX
SEMGREP_IMAGE = "appsec-review/tool-semgrep:1.178.0"
OPENGREP_IMAGE = "appsec-review/tool-opengrep:1.30.2"


def _table() -> dict:
    return tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["banned_functions"]


@pytest.mark.parametrize("value, message", [
    ("nope", "must be a table"),
    ({"hihg": []}, "unknown settings: hihg"),
    ({"high": "strcpy"}, "high must be a list"),
    ({"high": ["str cpy"]}, "not C identifiers"),
    ({"high": ["1abc"]}, "not C identifiers"),
    ({"high": ["gets", "gets"]}, "repeats names: gets"),
    ({"high": ["gets"], "warning": ["gets"]}, "both tiers: gets"),
    ({"source": 3}, "source must be a string"),
])
def test_the_table_is_validated(value, message) -> None:
    with pytest.raises(ValueError, match=message):
        parse_banned_functions(value)


def test_an_absent_table_means_no_rules_and_a_valid_one_round_trips() -> None:
    assert parse_banned_functions(None) == BannedFunctions()
    parsed = parse_banned_functions({"high": ["gets"], "warning": ["strlen"], "source": "s"})
    assert (parsed.high, parsed.warning, parsed.source) == (("gets",), ("strlen",), "s")
    assert parsed.as_record()["high"] == ["gets"]


def test_the_repository_table_is_microsofts_list_in_two_disjoint_tiers() -> None:
    parsed = parse_banned_functions(_table())
    assert set(parsed.high).isdisjoint(parsed.warning)
    assert {"strcpy", "strcat", "sprintf", "gets", "sscanf", "CopyMemory", "_itoa"} <= set(parsed.high)
    assert {"strncpy", "strlen", "alloca", "strtok", "PathAppend"} <= set(parsed.warning)
    assert len(parsed.high) + len(parsed.warning) >= 150
    # Microsoft's list does not ban memcpy: it is a review-tier lead, and the unbounded-copy-length rule in
    # review-signals.yml covers an attacker-sized copy separately.
    assert "memcpy" not in parsed.high + parsed.warning
    assert {"malloc", "calloc", "realloc", "memcpy", "memcmp", "strcmp", "printf"} <= set(parsed.review)
    assert parsed.source.endswith("Banned.h") and parsed.retrieved


def test_rendering_is_deterministic_and_ignores_list_order() -> None:
    parsed = parse_banned_functions(_table())
    shuffled = BannedFunctions(
        high=tuple(random.Random(1).sample(parsed.high, len(parsed.high))),
        warning=tuple(random.Random(2).sample(parsed.warning, len(parsed.warning))),
        review=tuple(random.Random(3).sample(parsed.review, len(parsed.review))),
        source=parsed.source)
    assert generator.render_rules(parsed) == generator.render_rules(shuffled)
    text = generator.render_rules(parsed)
    assert all(f"id: {RULE_PREFIX}{tier}" in text for tier in ("high", "warning", "review"))
    assert "severity: ERROR" in text and "severity: WARNING" in text and "severity: INFO" in text
    assert generator.render_rules(BannedFunctions()).rstrip().endswith("rules: []")  # an empty table makes no rules


def test_the_committed_rule_file_and_lock_match_the_table() -> None:
    assert generator.check(ROOT) == []


def test_drift_between_the_table_and_the_rule_file_is_reported(tmp_path) -> None:
    for relative in (generator.CONFIG, generator.RULES, generator.LOCK):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, tmp_path / relative)
    assert generator.check(tmp_path) == []

    rules = tmp_path / generator.RULES
    rules.write_text(rules.read_text(encoding="utf-8").replace("gets|", "", 1), encoding="utf-8")
    assert any("does not match [banned_functions]" in item for item in generator.check(tmp_path))
    generator.write(tmp_path)
    assert generator.check(tmp_path) == []

    config = tmp_path / generator.CONFIG
    config.write_text(config.read_text(encoding="utf-8").replace('"strcpy",', '"strcpy", "gmtime",', 1), encoding="utf-8")
    assert any("does not match [banned_functions]" in item for item in generator.check(tmp_path))


def test_a_rule_id_is_a_prioritization_sink_signal() -> None:
    from appsec_review.jobs.job_review_prioritization.semantic import SEMGREP_CATEGORIES, SEMGREP_MARKER

    assert RULE_PREFIX.startswith(SEMGREP_MARKER)
    assert RULE_PREFIX[len(SEMGREP_MARKER):].split(".")[0] in SEMGREP_CATEGORIES


def _docker_ready(*images: str) -> bool:
    if shutil.which("docker") is None:
        return False
    return all(subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
               for image in images)


def _scan(image: str, entrypoint: str, extra: list[str], target: Path) -> list[tuple[str, int, str, str]]:
    rules = ROOT / "rules" / "semgrep"
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", "1000:1000", "--cap-drop", "ALL",
               "--tmpfs", "/tmp:rw,size=256m", "-e", "HOME=/tmp", "-v", f"{target}:/target:ro",
               "-v", f"{rules}:/rules:ro", "--entrypoint", entrypoint, image,
               "scan", "--disable-version-check", *extra, "--config", "/rules/banned-functions.yml", "--json",
               "--quiet", "/target"]
    document = json.loads(subprocess.run(command, capture_output=True, text=True, timeout=300, check=False).stdout)
    assert not document.get("errors"), document["errors"][:2]
    return sorted((Path(item["path"]).name, item["start"]["line"], item["check_id"].rsplit("-", 1)[-1],
                   item["extra"]["severity"]) for item in document["results"])


@pytest.mark.skipif(not _docker_ready(SEMGREP_IMAGE, OPENGREP_IMAGE), reason="Semgrep and Opengrep images are not built")
@pytest.mark.parametrize("image, entrypoint, extra", [
    (SEMGREP_IMAGE, "/opt/tool/bin/semgrep", ["--metrics", "off"]),
    (OPENGREP_IMAGE, "/opt/tool/opengrep/opengrep.bin", []),
])
def test_both_engines_report_banned_calls_at_their_tier_and_nothing_else(image, entrypoint, extra, tmp_path) -> None:
    target = tmp_path / "target"
    shutil.copytree(FIXTURES, target)  # outside tests/, which Semgrep skips by default
    severity = {"high": "ERROR", "warning": "WARNING", "review": "INFO"}
    expected = sorted(("vulnerable.cpp", number, text.split("EXPECT ")[1].strip(), severity[text.split("EXPECT ")[1].strip()])
                      for number, text in enumerate((FIXTURES / "vulnerable.cpp").read_text(encoding="utf-8").splitlines(), 1)
                      if "EXPECT " in text)
    assert len(expected) == 14
    assert _scan(image, entrypoint, extra, target) == expected
