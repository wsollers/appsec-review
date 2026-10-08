from __future__ import annotations

import json
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "targets" / "appsec-multi-vuln"
LOCK = ROOT / "docs" / "reviews" / "native-evaluator-guide.lock.json"

ANSWER_MARKER = re.compile(
    r"(?:cwe[-_ ]?\d+|vulnerab(?:le|ility)|exploit|answer[-_ ]?key|"
    r"ground[-_ ]?truth|oracle|expected[-_ ]?findings?|remediation)",
    re.IGNORECASE,
)
TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".md", ".txt", ".json",
    ".yaml", ".yml", ".toml", ".xml", ".sh", ".ps1", ".cmake",
}


def target_owned_files() -> list[Path]:
    files = []
    for path in TARGET.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(TARGET)
        if ".git" in relative.parts or "third_party" in relative.parts:
            continue
        files.append(path)
    return files


def test_target_paths_and_prose_do_not_expose_evaluator_answers() -> None:
    failures: list[str] = []
    for path in target_owned_files():
        relative = path.relative_to(TARGET).as_posix()
        if ANSWER_MARKER.search(relative):
            failures.append(f"path:{relative}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
            "CMakeLists.txt", "Dockerfile", "Jenkinsfile", "Makefile",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if ANSWER_MARKER.search(text):
            failures.append(f"content:{relative}")
    assert not failures, "answer-bearing target material: " + ", ".join(failures)


def test_guide_lock_contains_identity_only() -> None:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock["schema"] == "appsec-review/evaluator-guide-lock/1"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["guide"]["commit"])
    assert re.fullmatch(r"[0-9a-f]{64}", lock["guide"]["oracle_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", lock["guide"]["provenance_sha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", lock["guide"]["observed_run_sha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", lock["target"]["commit"])
    assert set(lock["guide"]) == {
        "repository", "commit", "oracle_sha256", "provenance_sha256", "observed_run_sha256",
    }
    assert set(lock["target"]) == {"repository", "commit"}


def test_evaluator_guide_is_outside_target_and_run_roots() -> None:
    guide = Path(
        os.environ.get("APPSEC_EVALUATOR_GUIDE", ROOT.parent / "appsec-multi-vuln-guide")
    ).resolve()
    target = TARGET.resolve()
    runs = (ROOT / "runs").resolve()
    assert guide != target and guide not in target.parents and target not in guide.parents
    assert guide != runs and guide not in runs.parents and runs not in guide.parents

    forbidden = ("appsec-multi-vuln-guide", "native-ground-truth", "native-provenance")
    leaked: list[str] = []
    for path in runs.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".toml", ".md"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        if any(value in text for value in forbidden):
            leaked.append(path.relative_to(runs).as_posix())
    assert not leaked, "evaluator material leaked into run artifacts: " + ", ".join(leaked)
