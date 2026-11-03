"""Pinned JSON schemas for documents the review stage builds at run time.

``review-package-view.schema.json`` covers the model-facing package view (``package_view.build_view``) and
``review-package-manifest.schema.json`` the package manifest (``packages.assemble_packages`` and
``verify_package_manifest``). A document that violates its schema is an ``IntegrityError``: it blocks
publication and is never converted into a gap.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
import json
from pathlib import Path
import sysconfig
from typing import Any

from jsonschema import Draft202012Validator

from appsec_review.application_paths import application_asset
from appsec_review.review.models import IntegrityError

VIEW_SCHEMA_FILE = "review-package-view.schema.json"
MANIFEST_SCHEMA_FILE = "review-package-manifest.schema.json"
_KNOWN = frozenset({VIEW_SCHEMA_FILE, MANIFEST_SCHEMA_FILE})


def schema_path(name: str) -> Path:
    """The source checkout's (or application root's) schema first, then the wheel's ``share/`` copy."""
    if name not in _KNOWN:
        raise ValueError(f"unknown review schema: {name}")
    try:
        return application_asset(f"docs/schemas/{name}")
    except FileNotFoundError:
        pass
    installed = Path(sysconfig.get_path("data")) / "share" / "appsec-review" / "schemas" / name
    if installed.is_file():
        return installed
    raise FileNotFoundError(f"review schema is unavailable: {name}")


@lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    schema = json.loads(schema_path(name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate(name: str, document: Mapping[str, Any], what: str) -> None:
    """Raise ``IntegrityError`` naming the first violations of ``name`` in ``document``."""
    errors = sorted(validator(name).iter_errors(document), key=lambda error: list(map(str, error.absolute_path)))
    if errors:
        detail = "; ".join(f"/{'/'.join(map(str, error.absolute_path))}: {error.message[:200]}" for error in errors[:3])
        raise IntegrityError(f"{what} violates {name} ({len(errors)} error(s)): {detail}")


__all__ = ["MANIFEST_SCHEMA_FILE", "VIEW_SCHEMA_FILE", "schema_path", "validate", "validator"]
