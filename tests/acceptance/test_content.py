from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

from appsec_review.acceptance.content import content_differences
from appsec_review.acceptance.normalize import Masks

RUN = "2026-10-19-0001"


def _masks(root: str) -> Masks:
    return Masks.for_run(RUN, runs_roots=[f"{root}/runs"], repository_roots=[root],
                         target_roots=[f"{root}/targets/relay"])


def _artifact(run_root: Path, relative: str) -> dict:
    path = run_root / relative
    return {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _side(tmp_path: Path, name: str, root: str, *, rows: list[tuple], document: dict) -> tuple[Path, dict]:
    run_root = tmp_path / name / "runs" / RUN
    (run_root / "data" / "indices").mkdir(parents=True)
    database = sqlite3.connect(run_root / "data" / "indices" / "source.sqlite")
    database.execute("CREATE TABLE files (path TEXT, line INTEGER)")
    database.executemany("INSERT INTO files VALUES (?, ?)", [(f"{root}/targets/relay/{path}", line)
                                                             for path, line in rows])
    database.commit()
    database.close()
    (run_root / "data" / "catalog.json").write_text(json.dumps(
        {"target": f"{root}/targets/relay", **document}), encoding="utf-8")
    (run_root / "data" / "result.json").write_text(json.dumps({"driver": name}), encoding="utf-8")
    handoff = {"resolving_paths": {"result": "data/result.json"},
               "artifacts": [_artifact(run_root, relative) for relative in (
                   "data/indices/source.sqlite", "data/catalog.json", "data/result.json")]}
    return run_root, handoff


def _compare(dagster, local, dagster_root="/opt/app", local_root="/home/user/checkout"):
    return content_differences("job_target_catalog", dagster[0], dagster[1], _masks(dagster_root),
                               local[0], local[1], _masks(local_root))


def test_same_content_in_each_environment_spelling_matches(tmp_path: Path) -> None:
    rows = [("src/main.cpp", 1), ("src/packet.cpp", 16)]
    dagster = _side(tmp_path, "dagster", "/opt/app", rows=rows, document={"files": 2})
    local = _side(tmp_path, "local", "/home/user/checkout", rows=list(reversed(rows)), document={"files": 2})

    assert dagster[1]["artifacts"][0]["sha256"] != local[1]["artifacts"][0]["sha256"]
    assert _compare(dagster, local) == []


def test_a_differing_row_and_field_are_reported(tmp_path: Path) -> None:
    dagster = _side(tmp_path, "dagster", "/opt/app", rows=[("src/main.cpp", 1)], document={"files": 2})
    local = _side(tmp_path, "local", "/home/user/checkout", rows=[("src/main.cpp", 2)], document={"files": 3})

    differences = {(item.path, item.expected, item.actual) for item in _compare(dagster, local)}
    assert ("data/catalog.json.files", "2", "3") in differences
    assert ("data/indices/source.sqlite#files", '["<target>/src/main.cpp",1]', "<absent>") in differences
    assert ("data/indices/source.sqlite#files", "<absent>", '["<target>/src/main.cpp",2]') in differences


def test_a_path_in_the_other_environments_spelling_is_reported(tmp_path: Path) -> None:
    dagster = _side(tmp_path, "dagster", "/home/user/checkout", rows=[("src/main.cpp", 1)], document={})
    local = _side(tmp_path, "local", "/home/user/checkout", rows=[("src/main.cpp", 1)], document={})

    paths = {item.path for item in _compare(dagster, local)}
    assert {"data/indices/source.sqlite#files", "data/catalog.json.target"} <= paths


def test_an_artifact_published_by_one_side_only_is_reported(tmp_path: Path) -> None:
    dagster = _side(tmp_path, "dagster", "/opt/app", rows=[], document={})
    local = _side(tmp_path, "local", "/home/user/checkout", rows=[], document={})
    local[1]["artifacts"] = [item for item in local[1]["artifacts"] if item["path"] != "data/catalog.json"]

    assert [(item.path, item.expected, item.actual) for item in _compare(dagster, local)] == [
        ("data/catalog.json", "<artifact>", "<absent>")]


def _with_binary(side: tuple[Path, dict], content: bytes) -> None:
    run_root, handoff = side
    (run_root / "data" / "tool.o").write_bytes(content)
    handoff["artifacts"].append(_artifact(run_root, "data/tool.o"))


def test_identical_binary_artifacts_match_and_different_ones_are_reported(tmp_path: Path) -> None:
    dagster = _side(tmp_path, "dagster", "/opt/app", rows=[], document={})
    local = _side(tmp_path, "local", "/home/user/checkout", rows=[], document={})
    _with_binary(dagster, b"\x7fELF\xff\xfe")
    _with_binary(local, b"\x7fELF\xff\xfe")
    assert _compare(dagster, local) == []

    (local[0] / "data" / "tool.o").write_bytes(b"\x7fELF\xff\xfd")
    assert [(item.path, item.actual) for item in _compare(dagster, local)] == [
        ("data/tool.o", "<different bytes>")]


def _packages(tmp_path: Path, name: str, root: str, documents: list[dict], digests: list[str]) -> tuple[Path, dict]:
    run_root = tmp_path / name / "runs" / RUN
    artifacts = []
    for document, digest in zip(documents, digests):
        relative = f"data/review-packages/{digest * 64}/finding_lead-{digest * 64}.json"
        path = run_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({**document, "target": f"{root}/targets/relay"}), encoding="utf-8")
        artifacts.append(_artifact(run_root, relative))
    return run_root, {"artifacts": artifacts}


def test_artifacts_sharing_a_masked_path_are_paired_by_content_not_by_hash_order(tmp_path: Path) -> None:
    first, second, third = {"lead": "a", "n": 1}, {"lead": "b", "n": 2}, {"lead": "c", "n": 3}
    # The sides name the same three packages with different hashes, so hash order pairs them wrongly.
    dagster = _packages(tmp_path, "dagster", "/opt/app", [first, second, third], ["1", "5", "9"])
    local = _packages(tmp_path, "local", "/home/user/checkout", [third, first, second], ["2", "3", "4"])
    assert _compare(dagster, local) == []

    changed = _packages(tmp_path, "changed", "/home/user/checkout", [third, {**first, "n": 99}, second], ["2", "3", "4"])
    differences = _compare(dagster, changed)
    assert [(item.path.rsplit(".", 1)[-1], item.expected, item.actual) for item in differences] == [("n", "1", "99")]

    fewer = _packages(tmp_path, "fewer", "/home/user/checkout", [third, second], ["2", "4"])
    assert [(item.expected, item.actual) for item in _compare(dagster, fewer)] == [("<artifact>", "<absent>")]
