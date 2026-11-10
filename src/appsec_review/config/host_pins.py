"""Host-owned image observations, applied before typed configuration validation."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib
from typing import Any


HOST_PINS_PATH = Path("deploy/dagster/host-pins.toml")
HOST_PINS_ENV = "APPSEC_REVIEW_HOST_PINS"
HOST_PINS_SCHEMA = "appsec-review/host-pins/1"
HOST_PINS_LAYER = "host-pins"
PIN_PAIRS = (("tag", "image_id"), ("image_tag", "image_id"),
             ("source_image_tag", "source_image_id"))
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class HostPins:
    path: Path
    content: bytes

    def __post_init__(self) -> None:
        parse_host_pins(self.content)

    @property
    def document(self) -> dict[str, Any]:
        return parse_host_pins(self.content)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def record(self) -> dict[str, Any]:
        return {"layer": HOST_PINS_LAYER, "sha256": self.sha256,
                "document": dict(self.document)}


def host_pins_path(root: Path, explicit: str | Path | None = None) -> Path:
    value = explicit if explicit is not None else os.environ.get(HOST_PINS_ENV)
    if value is not None:
        if not str(value).strip():
            raise ValueError(f"{HOST_PINS_ENV} must name a host-pins file")
        path = Path(value)
        return path if path.is_absolute() else root / path
    return root / HOST_PINS_PATH


def parse_host_pins(content: bytes) -> dict[str, Any]:
    if len(content) > MAX_BYTES:
        raise ValueError("host pins exceed the 1 MiB bound")
    document = tomllib.loads(content.decode("utf-8"))
    if set(document) != {"schema", "images", "preinstalled_runtimes"}:
        raise ValueError("host pins require exactly schema, images and preinstalled_runtimes")
    if document["schema"] != HOST_PINS_SCHEMA:
        raise ValueError("unsupported host-pins schema")
    images = document["images"]
    if not isinstance(images, dict) or not images or len(images) > 1024:
        raise ValueError("host pins require 1 to 1024 image bindings")
    for tag, image_id in images.items():
        if (not tag or len(tag) > 512 or any(char.isspace() for char in tag)
                or not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)):
            raise ValueError(f"invalid host image binding: {tag!r}")
    from .codeql import _preinstalled_runtimes
    _preinstalled_runtimes(document["preinstalled_runtimes"])
    return document


def load_host_pins(root: Path, explicit: str | Path | None = None) -> HostPins:
    path = host_pins_path(root, explicit)
    try:
        with path.open("rb") as stream:
            content = stream.read(MAX_BYTES + 1)
    except FileNotFoundError as exc:
        raise ValueError(f"host pins are missing: {path}; run update-image-pins --write") from exc
    return HostPins(path, content)


def image_settings(value: object, path: str = "jobs") -> Iterator[tuple[str, dict[str, Any], str, str]]:
    """Yield the existing image-tag setting pairs, including step settings."""
    if isinstance(value, dict):
        for tag_key, id_key in PIN_PAIRS:
            tag = value.get(tag_key)
            if isinstance(tag, str):
                yield f"{path}.{id_key}", value, id_key, tag
        for key, child in value.items():
            if key != "preinstalled_runtimes":
                yield from image_settings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from image_settings(child, f"{path}[{index}]")


def apply_host_pins(document: dict[str, Any], pins: HostPins) -> None:
    images = pins.document["images"]
    for source, settings, id_key, tag in configuration_image_settings(document):
        if tag not in images:
            raise ValueError(f"host pins have no binding for {source}: {tag}")
        if id_key in settings and settings[id_key] != images[tag]:
            raise ValueError(f"{source} conflicts with the host binding for {tag}")
        settings[id_key] = images[tag]
    codeql = document.get("jobs", {}).get("job_codeql_analysis", {}).get("settings")
    if isinstance(codeql, dict):
        if "preinstalled_runtimes" in codeql:
            raise ValueError("CodeQL preinstalled_runtimes belong in host-pins.toml")
        codeql["preinstalled_runtimes"] = pins.document["preinstalled_runtimes"]
    document["configuration_host_pins"] = pins.record()


def configuration_image_settings(
        document: Mapping[str, Any]) -> Iterator[tuple[str, dict[str, Any], str, str]]:
    yield from image_settings(document.get("jobs", {}))
    yield from image_settings(document.get("reporting", {}), "reporting")


def bound_catalog_images(images: list[dict[str, Any]],
                         document: Mapping[str, Any]) -> list[dict[str, Any]]:
    record = document.get("configuration_host_pins")
    if not isinstance(record, Mapping) or not isinstance(record.get("document"), Mapping):
        raise ValueError("resolved configuration has no frozen host image bindings")
    bindings = record["document"].get("images")
    if not isinstance(bindings, Mapping):
        raise ValueError("resolved configuration has invalid host image bindings")
    result = []
    for image in images:
        value = dict(image)
        if image.get("state") == "enabled" and image.get("manual") is not True:
            tag = image.get("tag")
            if tag not in bindings:
                raise ValueError(f"host pins have no binding for catalog image {image.get('id')}: {tag}")
            value["image_id"] = bindings[tag]
        result.append(value)
    return result


def serialize_host_pins(images: Mapping[str, str],
                        preinstalled_runtimes: list[dict[str, Any]]) -> bytes:
    lines = [f"schema = {json.dumps(HOST_PINS_SCHEMA)}"]
    if not preinstalled_runtimes:
        lines.append("preinstalled_runtimes = []")
    lines.extend(["", "[images]"])
    lines.extend(f"{json.dumps(tag)} = {json.dumps(image_id)}"
                 for tag, image_id in sorted(images.items()))
    for runtime in preinstalled_runtimes:
        lines.extend(["", "[[preinstalled_runtimes]]"])
        lines.extend(f"{key} = {json.dumps(value)}" for key, value in sorted(runtime.items()))
    content = ("\n".join(lines) + "\n").encode()
    parse_host_pins(content)
    return content
