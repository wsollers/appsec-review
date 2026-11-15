"""Build discovery reads real-size build descriptors and names the ones it cannot read."""
from __future__ import annotations

import hashlib
from pathlib import Path

from appsec_review.jobs.build_discovery import discover_build_inventory
from appsec_review.jobs.job_target_catalog.job import (
    BUILD_DESCRIPTOR_READ_BYTES, descriptor_reader, unread_descriptor_gaps,
)

MESON = "project('game', 'c')\nexecutable('game-server', 'server/main.c')\n"


def _target(tmp_path: Path, files: dict[str, str]) -> tuple[Path, list[dict]]:
    target = tmp_path / "target"
    records = []
    for relative, text in sorted(files.items()):
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        raw = path.read_bytes()
        records.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
                        "language": "C" if relative.endswith(".c") else None})
    return target, records


def _discover(target: Path, records: list[dict], **reader):
    read_text, changed, unread = descriptor_reader(target, {item["path"]: item for item in records}, **reader)
    inventory = discover_build_inventory(records, read_text=read_text)
    assert changed == []
    return inventory, unread


def test_a_build_descriptor_larger_than_64_kib_is_read_and_yields_its_build_points(tmp_path: Path) -> None:
    # The root meson.build of a real project is large: Freeciv's is 124 KiB.
    padding = "".join(f"# option {index}: {'x' * 60}\n" for index in range(1800))
    files = {"meson.build": MESON + padding, "server/main.c": "int main(void) { return 0; }\n"}
    assert 64 * 1024 < len(files["meson.build"]) < BUILD_DESCRIPTOR_READ_BYTES
    target, records = _target(tmp_path, files)

    inventory, unread = _discover(target, records)

    assert unread == {} and unread_descriptor_gaps(unread) == []
    (unit,) = inventory["units"]
    assert unit["build_system"] == "meson" and unit["root"] == "."
    assert [point["name"] for point in unit["build_points"]] == ["game-server"]
    assert inventory["demoted_markers"] == [] and inventory["orphaned_sources"] == []


def test_a_build_descriptor_over_the_read_bound_is_a_named_gap_not_a_descriptor_without_a_build(tmp_path: Path) -> None:
    files = {"meson.build": MESON, "server/main.c": "int main(void) { return 0; }\n", "notes.txt": "x" * 200}
    target, records = _target(tmp_path, files)
    size = len(files["meson.build"])

    inventory, unread = _discover(target, records, limit=size - 1)

    # Unread, the descriptor yields no build point; that is recorded as unknown, by name and size.
    assert unread == {"meson.build": size}
    assert unread_descriptor_gaps(unread, limit=size - 1) == [
        f"build descriptor not read: meson.build: {size} bytes exceeds the {size - 1}-byte read bound; "
        "its build points and driven directories are unknown"]
    assert not [unit for unit in inventory["units"] if unit["build_points"]]
    # A large file that is not a build descriptor is not a build-discovery gap.
    assert unread_descriptor_gaps({"notes.txt": 10 ** 7}) == []
