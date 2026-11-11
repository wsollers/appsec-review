"""Asset-class exclusions and the central inventory file bound (Freeciv walk, 2026-11-11)."""
from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from appsec_review.config import load_config
from appsec_review.config.exclusions import (
    INVENTORY_FILE_BYTES_DEFAULT, NEVER_ASSET_SUFFIXES, ExclusionRule, PathExclusions, asset_class_rules,
    inventory_max_file_bytes,
)
from appsec_review.jobs.cataloging import Bounds, inventory, source_fingerprint

ROOT = Path(__file__).parents[1]
SHIPPED = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))


def _classes(*classes: tuple[str, list[str]]) -> dict:
    return {"exclusions": {"asset_classes": [
        {"name": name, "reason": "fixture", "suffixes": suffixes} for name, suffixes in classes]}}


def _rules(*classes: tuple[str, list[str]]) -> PathExclusions:
    return PathExclusions(asset_class_rules(_classes(*classes)))


@pytest.mark.parametrize(("path", "expected"), [
    ("data/tiles/hills.png", "raster-image"),
    ("data/tiles/HILLS.PNG", "raster-image"),          # case-insensitive
    ("Logo.Png", "raster-image"),
    ("data/scenarios/europe.sav", "game-save"),
    ("data/scenarios/europe.sav.gz", "game-save"),      # compound suffix
    ("data/scenarios/EUROPE.SAV.GZ", "game-save"),
    ("data/tiles/hills.pngx", None),                    # near miss: longer extension
    ("data/tiles/png", None),                           # near miss: no dot
    ("data/tiles/hills.png.in", None),                  # near miss: a template of the asset
    ("data/europe.sav.tar", None),
    ("png/loader.c", None),                             # a folder name is never an asset
    ("docs/art.png/readme.txt", None),
])
def test_asset_suffix_matching(path: str, expected: str | None) -> None:
    exclusions = _rules(("raster-image", [".png"]), ("game-save", [".sav", ".sav.gz"]))
    rule = exclusions.match(path)
    assert (rule.asset_class if rule else None) == expected
    # An asset class names files; it never prunes a directory.
    assert exclusions.match_directory(path) is None
    if rule is not None:
        assert rule.as_dict() == {"pattern": rule.pattern, "scope": "global", "asset_class": expected}


@pytest.mark.parametrize(("document", "message"), [
    ({"exclusions": {"asset_classes": {"name": "x"}}}, "array of tables"),
    (_classes(("Raster", [".png"])), "kebab identifier"),
    (_classes(("a", [".png"]), ("a", [".jpg"])), "kebab identifier"),
    ({"exclusions": {"asset_classes": [{"name": "a", "suffixes": [".png"]}]}}, "exactly name, reason and suffixes"),
    ({"exclusions": {"asset_classes": [{"name": "a", "reason": " ", "suffixes": [".png"]}]}}, "reason must say"),
    (_classes(("a", [])), "non-empty list"),
    (_classes(("a", ["png"])), "file-name suffixes"),
    (_classes(("a", [".PNG"])), "file-name suffixes"),
    (_classes(("a", ["*.png"])), "file-name suffixes"),
    (_classes(("a", ["art/.png"])), "file-name suffixes"),
    (_classes(("a", [".png"]), ("b", [".png"])), "repeats .png"),
    (_classes(("a", [".obj"])), "may not exclude .obj"),
    (_classes(("a", [".svg"])), "may not exclude .svg"),
    (_classes(("a", [".zip"])), "may not exclude .zip"),
    (_classes(("a", [".lua"])), "may not exclude .lua"),
], ids=["not-array", "bad-name", "repeated-name", "missing-reason", "blank-reason", "no-suffix", "no-dot",
        "upper-case", "glob", "path", "repeated-suffix", "object", "svg", "archive", "script"])
def test_invalid_asset_classes_fail_at_load(document: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        asset_class_rules(document)


def test_shipped_asset_classes_exclude_no_code_carrying_suffix() -> None:
    rules = asset_class_rules(SHIPPED)
    suffixes = {rule.pattern[1:] for rule in rules}
    assert {rule.asset_class for rule in rules} == {
        "art-source", "raster-image", "video", "audio", "font", "game-save"}
    assert {".blend", ".png", ".mp4", ".ogg", ".ttf", ".sav", ".sav.gz"} <= suffixes
    assert not suffixes & NEVER_ASSET_SUFFIXES
    # Every job carries the asset rules after the path patterns, whichever files it selects.
    config = load_config(ROOT / "appsec-review.toml")
    for job_id in ("job_review_intake", "job_target_catalog", "job_codeql_analysis"):
        carried = config.job(job_id).exclusions.rules
        assert [rule for rule in carried if rule.asset_class is not None] == list(rules)
        assert carried[0] == ExclusionRule(".gitignore", "global")
    assert json.loads(config.resolved_json)["exclusions"]["asset_classes"] == SHIPPED["exclusions"]["asset_classes"]


def test_inventory_counts_excluded_assets_by_class_and_keeps_source_and_descriptors(tmp_path: Path) -> None:
    target = tmp_path / "target"
    contents = {
        "src/main.c": b"int main(void) { return 0; }\n", "src/sprite.pngx": b"not an image\n",
        "CMakeLists.txt": b"project(x)\n", "Makefile.am": b"SUBDIRS = src\n", "configure.ac": b"AC_INIT\n",
        "data/hills.png": b"\x89PNG\0\0binary", "data/ICON.PNG": b"\x89PNG\0more", "data/logo.svg": b"<svg/>\n",
        "data/music.ogg": b"OggS\0", "data/start.sav": b"[savefile]\n", "data/start.sav.gz": b"\x1f\x8b\0",
        "data/pack.tar.gz": b"\x1f\x8b\0archive", "tools/shape.obj": b"\0object",
    }
    for relative, content in contents.items():
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_bytes(content)
    fingerprint = source_fingerprint(target)
    exclusions = _rules(("raster-image", [".png"]), ("audio", [".ogg"]), ("game-save", [".sav", ".sav.gz"]))

    snapshot = inventory(target, exclusions=exclusions)

    excluded = {"data/hills.png": "raster-image", "data/ICON.PNG": "raster-image", "data/music.ogg": "audio",
                "data/start.sav": "game-save", "data/start.sav.gz": "game-save"}
    assert {item["path"]: item["asset_class"] for item in snapshot["configured_exclusions"]} == excluded
    assert snapshot["excluded_assets"]["classes"] == {
        "audio": {"files": 1, "bytes": len(contents["data/music.ogg"])},
        "game-save": {"files": 2, "bytes": len(contents["data/start.sav"]) + len(contents["data/start.sav.gz"])},
        "raster-image": {"files": 2, "bytes": len(contents["data/hills.png"]) + len(contents["data/ICON.PNG"])}}
    assert snapshot["excluded_assets"]["files"] == 5
    assert snapshot["excluded_assets"]["bytes"] == sum(len(contents[path]) for path in excluded)
    # A policy exclusion is not a coverage gap, and it is not an artifact candidate either.
    assert snapshot["gaps"] == []
    kept = {item["path"] for item in snapshot["files"]} | {item["path"] for item in snapshot["artifact_candidates"]}
    assert kept == set(contents) - set(excluded)
    assert snapshot["file_discovery"]["file_paths_examined"] == len(contents)
    assert snapshot["file_discovery"]["descriptors_matched"] == snapshot["file_discovery"]["descriptors_retained"] >= 3
    assert [item["path"] for item in snapshot["source_metrics"]] == ["src/main.c"]
    # Exclusions narrow analysis, never the target's identity.
    assert source_fingerprint(target) == fingerprint
    assert inventory(target)["excluded_assets"] == {
        "policy": snapshot["excluded_assets"]["policy"], "classes": {}, "files": 0, "bytes": 0}


def test_inventory_file_bound_is_one_central_setting(tmp_path: Path) -> None:
    assert inventory_max_file_bytes({}) == INVENTORY_FILE_BYTES_DEFAULT == Bounds().max_file_bytes
    assert inventory_max_file_bytes(SHIPPED) == 12 * 1024 * 1024
    config = load_config(ROOT / "appsec-review.toml")
    assert {config.job(job_id).inventory_max_file_bytes for job_id in config.jobs} == {12 * 1024 * 1024}
    for bad in ({"inventory": {}}, {"inventory": {"max_file_bytes": 0}}, {"inventory": {"max_file_bytes": "1"}},
                {"inventory": {"max_file_bytes": 64 * 1024 * 1024 + 1}},
                {"inventory": {"max_file_bytes": 1, "max_files": 2}}):
        with pytest.raises(ValueError, match="inventory"):
            inventory_max_file_bytes(bad)

    target = tmp_path / "target"
    target.mkdir()
    (target / "small.po").write_bytes(b"m" * 100)
    (target / "large.po").write_bytes(b"m" * 300)
    bounded = inventory(target, Bounds(max_file_bytes=200))
    assert [item["path"] for item in bounded["files"]] == ["small.po"]
    assert bounded["gaps"] == [{"path": "large.po", "reason": "file_too_large"}]
    raised = inventory(target, Bounds(max_file_bytes=300))
    assert [item["path"] for item in raised["files"]] == ["large.po", "small.po"] and raised["gaps"] == []
