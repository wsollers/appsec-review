"""Inert deployment inputs; helpers admit bytes but do not fake extraction."""

from __future__ import annotations

import hashlib
from pathlib import Path

from appsec_review.deployment import SourceDocument


FIXTURES = Path(__file__).parent / "fixtures" / "deployment"
SNAPSHOT = "synthetic-target-snapshot"


def document(text: str | bytes, format: str = "compose", path: str = "compose.yaml", **kwargs) -> SourceDocument:
    data = text.encode() if isinstance(text, str) else text
    return SourceDocument(path, data, hashlib.sha256(data).hexdigest(), format,
                          kwargs.pop("deployment", "customer"), **kwargs)


def fixture(name: str, format: str, **kwargs) -> SourceDocument:
    return document((FIXTURES / name).read_bytes(), format, name, **kwargs)
