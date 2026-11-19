"""Versioned private format references; the public dossier file map stays unchanged."""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from appsec_review.jobs.bound_artifacts import read_bound
from appsec_review.review.models import IntegrityError

LEGACY_RECEIPT_SCHEMA = "appsec-review/dossier-rendering-receipt/1"
RECEIPT_SCHEMA = "appsec-review/dossier-rendering-receipt/2"
FORMAT_UNLOADED = "Rendering receipt not loaded; Markdown/HTML certification is unknown."
FORMAT_LEGACY = "Legacy receipt /1: Markdown/HTML were not certified; no sidecars were discovered."


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    path = (Path(__file__).resolve().parents[3] / "docs" / "schemas" / "dossier"
            / "dossier-rendering-receipt-v2.schema.json")
    schema = json.loads(path.read_bytes())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def receipt_formats(receipt: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    """Return only explicit current references; a legacy receipt certifies neither new format."""
    if not isinstance(receipt, Mapping):
        raise IntegrityError("dossier rendering receipt must be an object")
    if receipt.get("schema") == LEGACY_RECEIPT_SCHEMA:
        if "additional_formats" in receipt:
            raise IntegrityError("legacy dossier receipt cannot claim additional format certification")
        return {}
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise IntegrityError("unsupported dossier rendering receipt schema")
    error = next(_validator().iter_errors(receipt), None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "$"
        raise IntegrityError(f"dossier rendering receipt does not satisfy its closed schema at {path} ({error.validator})")
    return {name: dict(ref) for name, ref in receipt["additional_formats"].items()}


def verify_additional_formats(root: Path, receipt: Mapping[str, Any], *,
                              bound: set[tuple[str, str]] | None = None,
                              dossier: Mapping[str, Any] | None = None) -> dict[str, dict[str, str]]:
    formats = receipt_formats(receipt)
    expected = None
    if formats and dossier is not None:
        from .dossier_render import render_dossier_html, render_dossier_markdown
        expected = {"markdown": render_dossier_markdown(dossier).encode("utf-8"),
                    "html": render_dossier_html(dossier).encode("utf-8")}
    for name, ref in formats.items():
        if bound is not None and (ref["path"], ref["sha256"]) not in bound:
            raise IntegrityError(f"dossier {name} is not bound by the accepted gate")
        data = read_bound(root, ref)
        if expected is not None and data != expected[name]:
            raise IntegrityError(f"dossier {name} is not the rendering of its published JSON")
    return formats
