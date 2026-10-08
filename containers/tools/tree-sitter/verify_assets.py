"""Fail image assembly unless every offline wheel and grammar matches the tracked lock."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _verify(path: Path, expected_hash: str, expected_bytes: int) -> None:
    payload = path.read_bytes()
    if len(payload) != expected_bytes or hashlib.sha256(payload).hexdigest() != expected_hash:
        raise SystemExit(f"offline asset identity mismatch: {path.name}")


def main() -> None:
    lock = json.loads(Path("/opt/assets/assets.lock.json").read_text(encoding="utf-8"))
    expected_wheels = {lock["tree_sitter"]["artifact"], lock["language_pack"]["artifact"]}
    actual_wheels = {path.name for path in Path("/opt/assets/wheels").glob("*.whl")}
    if actual_wheels != expected_wheels:
        raise SystemExit("offline wheel inventory does not exactly match the asset lock")
    for identity in (lock["tree_sitter"], lock["language_pack"]):
        _verify(Path("/opt/assets/wheels") / identity["artifact"],
                identity["wheel_sha256"], identity["wheel_bytes"])
    expected_parsers = {grammar["artifact"] for grammar in lock["grammars"]}
    actual_parsers = {path.name for path in Path("/opt/grammars").glob("*.so")}
    if actual_parsers != expected_parsers:
        raise SystemExit("offline grammar inventory does not exactly match the asset lock")
    for grammar in lock["grammars"]:
        _verify(Path("/opt/grammars") / grammar["artifact"], grammar["sha256"], grammar["bytes"])


if __name__ == "__main__":
    main()
