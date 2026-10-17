"""Configured image-ID pins, their local resolution, and the host-side re-pin edit.

One collection of pins serves both the pre-intake gate (``job_image_pin_verification``) and the
operator's ``appsec-review update-image-pins`` command:

* every enabled image in ``containers/catalog.toml`` (its ``image_id`` when pinned; an unpinned
  enabled image must still be present);
* every enabled job's ``tag``/``image_id`` pair (the ``job_project_build`` profiles) and
  ``source_image_tag``/``source_image_id`` pair (CodeQL's source image).

Resolution runs only ``docker image inspect`` through the injectable command runner, so tests never
reach Docker. Re-pinning turns each pin whose tag now resolves to a different local image into an
exact, line-level edit of the catalog or the central configuration. It never reformats either file:
each edit replaces one quoted image ID on the one line that owns the pin, and the edited document is
re-parsed to prove that exactly the planned values changed. A pin that cannot be located
unambiguously is reported for manual editing instead of guessed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import json
from pathlib import Path
import re
import tomllib
from typing import Any

from appsec_review.container_runtime.build_executor import Runner
from appsec_review.runtime.selection import resolved_job_is_enabled


CATALOG = Path("containers") / "catalog.toml"
CATALOG_PREFIX = f"{CATALOG.as_posix()} images."
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
# Setting pairs that pin an image tag to an exact image ID in enabled jobs' configuration.
PIN_PAIRS = (("tag", "image_id"), ("source_image_tag", "source_image_id"))
INSPECT_TIMEOUT_SECONDS = 60
# docker's message for an absent reference; any other failure is an inspection error, not "missing".
_ABSENT = re.compile(r"no such (image|object)", re.IGNORECASE)


class PinUpdateError(ValueError):
    """A configuration file cannot be updated safely."""


def configured_pins(catalog_images: Sequence[Mapping[str, Any]],
                    document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every image the review depends on: enabled catalog images and enabled jobs' exact pins.

    ``image_id`` is ``None`` for an enabled catalog image that carries no pin; it must be present.
    """

    pins: list[dict[str, Any]] = []
    for item in catalog_images:
        if item.get("state") != "enabled" or not isinstance(item.get("tag"), str):
            continue
        image_id = item.get("image_id")
        pins.append({"source": f"{CATALOG_PREFIX}{item['id']}.image_id", "tag": item["tag"],
                     "image_id": image_id if isinstance(image_id, str) else None})

    def walk(value: object, path: str) -> None:
        if not isinstance(value, Mapping):
            return
        for tag_key, id_key in PIN_PAIRS:
            if isinstance(value.get(tag_key), str) and isinstance(value.get(id_key), str):
                pins.append({"source": f"{path}.{id_key}", "tag": value[tag_key], "image_id": value[id_key]})
        for key, child in value.items():
            walk(child, f"{path}.{key}")

    for job_id, job in sorted(dict(document.get("jobs") or {}).items()):
        if isinstance(job, Mapping) and resolved_job_is_enabled(job_id, job):
            walk(job.get("settings") or {}, f"jobs.{job_id}.settings")
    return pins


def inspect_image(runner: Runner, tag: str) -> dict[str, Any]:
    """Resolve one tag on the local daemon: ``{"resolved_image_id", "state", "detail"}``.

    ``state`` is ``present``, ``missing`` (docker reports no such image) or ``inspect_failed``.
    """

    argv = ("docker", "image", "inspect", tag, "--format", "{{.Id}}")
    try:
        code, stdout, stderr, timed_out = runner(argv, INSPECT_TIMEOUT_SECONDS)
    except OSError as exc:
        return {"resolved_image_id": None, "state": "inspect_failed", "detail": f"{type(exc).__name__}: {exc}"}
    out = stdout.decode("utf-8", "replace").strip()
    err = stderr.decode("utf-8", "replace").strip()
    if timed_out:
        return {"resolved_image_id": None, "state": "inspect_failed",
                "detail": f"docker image inspect timed out after {INSPECT_TIMEOUT_SECONDS}s"}
    if code == 0 and IMAGE_ID.match(out):
        return {"resolved_image_id": out, "state": "present", "detail": ""}
    if code != 0 and _ABSENT.search(err):
        return {"resolved_image_id": None, "state": "missing", "detail": err[-512:]}
    return {"resolved_image_id": None, "state": "inspect_failed",
            "detail": f"docker image inspect exited {code}: {(err or out)[-512:]}"}


def verify_pins(pins: Sequence[Mapping[str, Any]], runner: Runner) -> list[dict[str, Any]]:
    """Resolve every pin's tag once and classify it.

    Status is ``matched`` (resolves to the pinned ID), ``present`` (unpinned catalog image exists),
    ``mismatched`` (the tag moved), ``missing`` or ``inspect_failed``. Only the first two pass.
    """

    resolved: dict[str, dict[str, Any]] = {}
    results = []
    for pin in pins:
        tag = str(pin["tag"])
        if tag not in resolved:
            resolved[tag] = inspect_image(runner, tag)
        local = resolved[tag]
        if local["state"] != "present":
            status = local["state"]
        elif pin.get("image_id") is None:
            status = "present"
        else:
            status = "matched" if local["resolved_image_id"] == pin["image_id"] else "mismatched"
        results.append({"source": pin["source"], "tag": tag, "image_id": pin.get("image_id"),
                        "resolved_image_id": local["resolved_image_id"], "status": status,
                        "detail": local["detail"]})
    return results


PASSING = frozenset({"matched", "present"})


def describe(result: Mapping[str, Any]) -> str:
    """One line naming the pin, its tag, the pinned ID and what the tag resolved to."""

    if result["status"] == "missing":
        resolved = "missing"
    elif result["status"] == "inspect_failed":
        resolved = f"not inspectable ({result['detail']})"
    else:
        resolved = str(result["resolved_image_id"])
    return (f"{result['source']}: tag {result['tag']} pinned {result['image_id'] or '<unpinned>'} "
            f"resolved {resolved}")


# ---------------------------------------------------------------- host-side re-pin


@dataclass(frozen=True, slots=True)
class PinEdit:
    source: str
    file: str
    tag: str
    old: str | None
    new: str | None
    line: int | None
    status: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "file": self.file, "tag": self.tag, "old": self.old, "new": self.new,
                "line": self.line, "status": self.status, "detail": self.detail}


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


def plan_updates(results: Sequence[Mapping[str, Any]], *, config_path: Path,
                 catalog_path: Path) -> list[PinEdit]:
    """Plan one edit per pinned tag that resolves locally to a different image.

    A pinned tag that is missing or cannot be inspected is ``unresolved``: there is nothing to pin.
    Unpinned catalog images are never given a pin here; that is a reviewed edit.
    """

    texts = {path: path.read_text(encoding="utf-8").splitlines(keepends=True)
             for path in (config_path, catalog_path)}
    edits = []
    for result in results:
        old, new = result.get("image_id"), result.get("resolved_image_id")
        if old is None or result["status"] in PASSING:
            continue
        source, tag = str(result["source"]), str(result["tag"])
        file = catalog_path if source.startswith(CATALOG_PREFIX) else config_path
        if result["status"] != "mismatched" or not IMAGE_ID.match(str(new)):
            edits.append(PinEdit(source, file.as_posix(), tag, old, None, None, "unresolved", describe(result)))
            continue
        if file == catalog_path:
            image, _, key = source[len(CATALOG_PREFIX):].rpartition(".")
            line = _catalog_line(texts[file], image, key, old) if image and key else None
        else:
            line = _settings_line(texts[file], source.split("."), old)
        if line is None:
            edits.append(PinEdit(source, file.as_posix(), tag, old, new, None, "manual",
                                 "the pin's line could not be located unambiguously; edit it by hand"))
        else:
            edits.append(PinEdit(source, file.as_posix(), tag, old, new, line + 1, "planned"))
    return edits


def apply_updates(edits: Sequence[PinEdit], *, config_path: Path, catalog_path: Path) -> None:
    """Apply planned edits and prove by re-parsing that exactly those values changed."""

    by_file: dict[Path, list[PinEdit]] = {}
    for edit in edits:
        if edit.status == "planned":
            by_file.setdefault(Path(edit.file), []).append(edit)
    for path, changes in by_file.items():
        original = path.read_bytes().decode("utf-8")
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
        path.write_bytes(updated.encode("utf-8"))


def update_pins(*, config_path: Path, catalog_path: Path, write: bool, runner: Runner) -> dict[str, Any]:
    """Re-pin every configured pin to the image its tag resolves to on the local daemon."""

    try:
        document = tomllib.loads(config_path.read_text(encoding="utf-8"))
        images = tomllib.loads(catalog_path.read_text(encoding="utf-8")).get("images", [])
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PinUpdateError(f"cannot read the pins: {type(exc).__name__}: {exc}") from exc
    results = verify_pins(configured_pins(images, document), runner)
    edits = plan_updates(results, config_path=config_path, catalog_path=catalog_path)
    if write:
        apply_updates(edits, config_path=config_path, catalog_path=catalog_path)
    rows = [{**edit.as_dict(), "status": "applied" if write and edit.status == "planned" else edit.status}
            for edit in edits]
    return {"written": write, "checked": len(results),
            "unpinned_missing": [describe(item) for item in results
                                 if item["image_id"] is None and item["status"] not in PASSING],
            "edits": rows}
