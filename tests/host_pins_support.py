"""Inert image bindings for offline tests; no host inventory or Docker calls."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tomllib

from appsec_review.config.host_pins import configuration_image_settings, serialize_host_pins


ROOT = Path(__file__).resolve().parents[1]


def fixture_bindings() -> dict[str, str]:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text())
    catalog = tomllib.loads((ROOT / "containers/catalog.toml").read_text())
    tags = {entry["tag"] for entry in catalog["images"] if entry.get("state") == "enabled"}
    tags.update(tag for _, _, _, tag in configuration_image_settings(document))
    return {tag: "sha256:" + hashlib.sha256(tag.encode()).hexdigest() for tag in sorted(tags)}


def fixture_preinstalled() -> list[dict[str, str]]:
    images = fixture_bindings()
    releases = tomllib.loads((ROOT / "appsec-review.toml").read_text())["review_policy"]["releases"]
    source = images["audit-codeql:custom-2.27.0"]
    return [
        {"source_image_id": source, "build_image_id": build_image,
         "runtime_image_id": "sha256:" + digit * 64, "runtime_user": "1000:1000",
         "codeql_release_id": releases["codeql"], "runner_release_id": releases["codeql_runner"],
         "runner_source": "application"}
        for build_image, digit in ((source, "a"), (images["audit-buildenv-cpp:local"], "b"))]


def write_host_pins(path: Path, *, images: dict[str, str] | None = None,
                    runtimes: list[dict] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(serialize_host_pins(
        fixture_bindings() if images is None else images, [] if runtimes is None else runtimes))
    return path
