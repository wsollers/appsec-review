from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest


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
    assert lock["schema"] == "appsec-review/evaluator-guide-lock/2"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["guide"]["commit"])
    assert re.fullmatch(r"[0-9a-f]{40}", lock["target"]["commit"])
    assert set(lock["guide"]) == {"repository", "commit"}
    assert set(lock["target"]) == {"repository", "commit"}


EVALUATOR_MARKERS = ("appsec-multi-vuln-guide", "native-ground-truth", "native-provenance")


def leaked_evaluator_material(runs: Path) -> list[str]:
    leaked: list[str] = []
    for path in runs.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl", ".toml", ".md"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        if any(value in text for value in EVALUATOR_MARKERS):
            leaked.append(path.relative_to(runs).as_posix())
    return sorted(leaked)


def test_evaluator_guide_is_outside_target_and_run_roots() -> None:
    guide = Path(
        os.environ.get("APPSEC_EVALUATOR_GUIDE", ROOT.parent / "appsec-multi-vuln-guide")
    ).resolve()
    target = TARGET.resolve()
    runs = (ROOT / "runs").resolve()
    assert guide != target and guide not in target.parents and target not in guide.parents
    assert guide != runs and guide not in runs.parents and runs not in guide.parents


def test_leak_scan_flags_evaluator_material_in_a_fixture_run(tmp_path: Path) -> None:
    run = tmp_path / "runs" / "2026-10-27-0001" / "data"
    (run / "configuration").mkdir(parents=True)
    (run / "configuration" / "resolved.toml").write_text('target = "targets/appsec-multi-vuln"\n', encoding="utf-8")
    (run / "findings.jsonl").write_text('{"id": "f-1", "summary": "bounded claim"}\n', encoding="utf-8")
    (run / "notes.bin").write_text("native-ground-truth", encoding="utf-8")
    runs = tmp_path / "runs"
    assert leaked_evaluator_material(runs) == []

    (run / "report.md").write_text("See ../appsec-multi-vuln-guide/answers\n", encoding="utf-8")
    (run / "evidence.json").write_text('{"source": "Native-Provenance"}\n', encoding="utf-8")
    assert leaked_evaluator_material(runs) == [
        "2026-10-27-0001/data/evidence.json", "2026-10-27-0001/data/report.md"]


def test_existing_run_artifacts_do_not_contain_evaluator_material() -> None:
    runs = (ROOT / "runs").resolve()
    if not any(path.is_file() and path.name != ".gitignore" for path in runs.rglob("*")):
        pytest.skip("no run artifacts in this checkout to scan")
    leaked = leaked_evaluator_material(runs)
    assert not leaked, "evaluator material leaked into run artifacts: " + ", ".join(leaked)
