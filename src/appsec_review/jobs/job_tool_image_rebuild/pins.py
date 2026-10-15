"""Rewrite stale image-ID pins from a run's tool-image rebuild record.

``job_tool_image_rebuild`` records every configured pin whose tag it rebuilt, with the pinned ID, the
rebuilt ID and ``matched``/``mismatched``. This module turns the mismatched pins of one run into
exact, line-level edits of ``containers/catalog.toml`` and the central configuration. It never
reformats either file: each edit replaces one quoted image ID on the one line that owns the pin, and
the edited document is re-parsed to prove that exactly the planned values changed. A pin that cannot
be located unambiguously is reported for manual editing instead of guessed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import tomllib
from typing import Any


RECORD_NAME = "tool-image-rebuild.json"
CATALOG_PREFIX = "containers/catalog.toml images."
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")

# inspect(tag) -> the local image ID for that tag, or None when it is absent.
ImageInspector = Callable[[str], "str | None"]


class PinUpdateError(ValueError):
    """The rebuild record or a configuration file cannot be updated safely."""


@dataclass(frozen=True, slots=True)
class PinEdit:
    source: str
    file: str
    tag: str
    old: str
    new: str
    line: int | None
    status: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "file": self.file, "tag": self.tag, "old": self.old, "new": self.new,
                "line": self.line, "status": self.status, "detail": self.detail}


def docker_inspector(tag: str) -> str | None:
    completed = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", tag],
                               capture_output=True, text=True, timeout=60, check=False)
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and IMAGE_ID.match(value) else None


def find_record(runs_dir: Path, run_id: str) -> Path:
    """The rebuild record of the run's latest attempt."""

    root = runs_dir / run_id / "data" / "jobs" / "job_tool_image_rebuild"
    records = sorted(root.glob(f"attempts/*/steps/*/tasks/*/{RECORD_NAME}"))
    if not records:
        raise PinUpdateError(f"run {run_id} has no tool-image rebuild record under {root}")
    return records[-1]


def mismatched_pins(record: Mapping[str, Any]) -> list[dict[str, str]]:
    pins = []
    for pin in record.get("pins") or ():
        if pin.get("status") != "mismatched":
            continue
        for key in ("image_id", "rebuilt_image_id"):
            if not IMAGE_ID.match(str(pin.get(key))):
                raise PinUpdateError(f"rebuild record pin {pin.get('source')!r} has an invalid {key}")
        pins.append({key: str(pin[key]) for key in ("source", "tag", "image_id", "rebuilt_image_id")})
    return pins


def _headers(lines: Sequence[str]) -> list[tuple[int, str]]:
    found = []
    for index, line in enumerate(lines):
        match = HEADER.match(line)
        if match:
            found.append((index, ".".join(part.strip().strip('"') for part in match.group(1).split("."))))
    return found


def _assignment(line: str, key: str, old: str) -> bool:
    return re.match(rf'^\s*{re.escape(key)}\s*=\s*"{re.escape(old)}"\s*(?:#.*)?$', line) is not None


def _catalog_line(lines: Sequence[str], image: str, key: str, old: str) -> int | None:
    headers = _headers(lines)
    for position, (start, name) in enumerate(headers):
        if name != "images":
            continue
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        block = range(start + 1, end)
        if any(re.match(rf'^\s*id\s*=\s*"{re.escape(image)}"\s*(?:#.*)?$', lines[i]) for i in block):
            matches = [i for i in block if _assignment(lines[i], key, old)]
            return matches[0] if len(matches) == 1 else None
    return None


def _settings_line(lines: Sequence[str], path: Sequence[str], old: str) -> int | None:
    """Locate ``path[-1] = "old"`` in the table named by the longest matching header prefix."""

    headers = _headers(lines)
    for cut in range(len(path) - 1, 0, -1):
        table, remainder = ".".join(path[:cut]), ".".join(path[cut:])
        for position, (start, name) in enumerate(headers):
            if name != table:
                continue
            end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
            matches = [i for i in range(start + 1, end) if _assignment(lines[i], remainder, old)]
            if len(matches) == 1:
                return matches[0]
    return None


def _lookup(document: Mapping[str, Any], path: Sequence[str]) -> Any:
    value: Any = document
    for key in path:
        if not isinstance(value, Mapping) or key not in value:
            return None
        value = value[key]
    return value


def _catalog_value(document: Mapping[str, Any], image: str, key: str) -> Any:
    for item in document.get("images") or ():
        if item.get("id") == image:
            return item.get(key)
    return None


def plan_updates(record: Mapping[str, Any], *, config_path: Path, catalog_path: Path,
                 inspect: ImageInspector | None = docker_inspector) -> list[PinEdit]:
    """Plan one edit per mismatched pin; ``inspect=None`` skips the local-image check."""

    texts = {path: path.read_text(encoding="utf-8").splitlines(keepends=True)
             for path in (config_path, catalog_path)}
    edits = []
    for pin in mismatched_pins(record):
        source, tag, old, new = pin["source"], pin["tag"], pin["image_id"], pin["rebuilt_image_id"]
        if source.startswith(CATALOG_PREFIX):
            file = catalog_path
            image, _, key = source[len(CATALOG_PREFIX):].rpartition(".")
            line = _catalog_line(texts[file], image, key, old) if image and key else None
        else:
            file = config_path
            line = _settings_line(texts[file], source.split("."), old)
        status, detail = "planned", ""
        if inspect is not None:
            local = inspect(tag)
            if local != new:
                status = "refused"
                detail = (f"local image {tag} is {local or 'absent'}, not the rebuilt {new}; "
                          "rebuild it or pass --no-image-check")
        if status == "planned" and line is None:
            status, detail = "manual", "the pin's line could not be located unambiguously; edit it by hand"
        edits.append(PinEdit(source, file.as_posix(), tag, old, new, None if line is None else line + 1, status,
                             detail))
    return edits


def apply_updates(edits: Sequence[PinEdit], *, config_path: Path, catalog_path: Path) -> None:
    """Apply planned edits and prove by re-parsing that exactly those values changed."""

    by_file: dict[Path, list[PinEdit]] = {}
    for edit in edits:
        if edit.status == "planned":
            by_file.setdefault(Path(edit.file), []).append(edit)
    for path, changes in by_file.items():
        original = path.read_text(encoding="utf-8")
        before = tomllib.loads(original)
        lines = original.splitlines(keepends=True)
        for edit in changes:
            index = int(edit.line) - 1
            if lines[index].count(f'"{edit.old}"') != 1:
                raise PinUpdateError(f"{path}:{edit.line} no longer holds {edit.old}")
            lines[index] = lines[index].replace(f'"{edit.old}"', f'"{edit.new}"')
        updated = "".join(lines)
        after = tomllib.loads(updated)
        expected = json.loads(json.dumps(before))
        for edit in changes:
            if path == catalog_path:
                image, _, key = edit.source[len(CATALOG_PREFIX):].rpartition(".")
                if _catalog_value(after, image, key) != edit.new:
                    raise PinUpdateError(f"{edit.source} did not change to {edit.new}")
                for item in expected["images"]:
                    if item.get("id") == image:
                        item[key] = edit.new
            else:
                keys = edit.source.split(".")
                if _lookup(after, keys) != edit.new:
                    raise PinUpdateError(f"{edit.source} did not change to {edit.new}")
                parent = _lookup(expected, keys[:-1])
                parent[keys[-1]] = edit.new
        if json.loads(json.dumps(after)) != expected:
            raise PinUpdateError(f"{path}: the edit changed values other than the planned pins")
        path.write_text(updated, encoding="utf-8")


def update_pins(*, runs_dir: Path, run_id: str, config_path: Path, catalog_path: Path, write: bool,
                inspect: ImageInspector | None = docker_inspector) -> dict[str, Any]:
    record_path = find_record(runs_dir, run_id)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    edits = plan_updates(record, config_path=config_path, catalog_path=catalog_path, inspect=inspect)
    if write:
        apply_updates(edits, config_path=config_path, catalog_path=catalog_path)
    rows = [{**edit.as_dict(), "status": "applied" if write and edit.status == "planned" else edit.status}
            for edit in edits]
    return {"run_id": run_id, "record": record_path.as_posix(), "written": write, "edits": rows}
