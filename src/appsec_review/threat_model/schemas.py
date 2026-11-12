"""Closed JSON Schemas of the four documents the threat-model job publishes (T-107).

``docs/schemas/threat-model/`` holds one self-contained draft 2020-12 schema per document. A document
is the plain JSON form, ``json.loads(contract.canonical(document))``: objects are ``dict``, arrays
are ``list``. ``validate_document`` picks the schema by the document's ``schema`` id and raises
``ValueError`` naming the first violation and its JSON path.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from appsec_review.application_paths import application_asset
from appsec_review.threat_model.contract import DFD_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA, THREAT_MODEL_SCHEMA

SCHEMA_DIRECTORY = "docs/schemas/threat-model"
SCHEMA_FILES: Mapping[str, str] = {
    DFD_SCHEMA: "generated-dfd.schema.json",
    THREAT_MODEL_SCHEMA: "generated-threat-model.schema.json",
    EVIDENCE_SCHEMA: "generated-model-evidence.schema.json",
    RESULT_SCHEMA: "threat-model-generation.schema.json",
}


def schema_path(schema_id: str) -> Path:
    """The schema file of one published document, in the source checkout or application root."""
    if not isinstance(schema_id, str) or schema_id not in SCHEMA_FILES:
        raise ValueError(f"unknown threat-model document schema: {schema_id!r}")
    return application_asset(f"{SCHEMA_DIRECTORY}/{SCHEMA_FILES[schema_id]}")


@lru_cache(maxsize=None)
def validator(schema_id: str) -> Draft202012Validator:
    """The validator of one schema; each file is read and checked once per process."""
    schema = json.loads(schema_path(schema_id).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_document(document: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` naming the first violation of the schema ``document["schema"]`` selects."""
    if not isinstance(document, Mapping):
        raise ValueError("a threat-model document must be a JSON object")
    schema_id = document.get("schema")
    checker = validator(schema_id) if isinstance(schema_id, str) else None
    if checker is None:
        raise ValueError(f"unknown threat-model document schema: {schema_id!r}")
    errors = sorted(checker.iter_errors(document), key=lambda error: (error.json_path, error.message))
    if errors:
        first = errors[0]
        raise ValueError(f"{schema_id} document violates its schema at {first.json_path}: {first.message[:300]}"
                         f" ({len(errors)} violation(s))")


__all__ = ["SCHEMA_DIRECTORY", "SCHEMA_FILES", "schema_path", "validate_document", "validator"]
