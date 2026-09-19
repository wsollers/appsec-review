#!/usr/bin/env python3
"""Small, dependency-free JSON-Schema-subset validator for the schemas/ directory.

Added 2026-09-19 as the "define schemas, place them centrally, write/wire in/test the schema
validators" first step (see claude project TODO -- the common finding/evidence/interjob-transfer
format effort). Deliberately not a dependency on the third-party `jsonschema` pip package: nothing
else in appsec-review-process/*.py takes an external dependency, and this project has a track
record of hand-rolling a real, robust parser instead of trusting a generic library to do exactly
what's needed (see review_cli.py's own budget-table markdown parser, added after a regex-based
guess silently dropped the `full` tier -- bug #2 in the harness doc).

Supports the subset actually used by schemas/*.schema.json: type (incl. a list of types for
nullable fields), required, properties, additionalProperties, enum, const, pattern, items,
minItems, and $ref (resolved against sibling files in the same schemas/ directory, one level --
no remote $ref, no $ref chains through $defs, since none of our schemas need that yet).

classification/classification_taxonomy cross-checking against verdict-taxonomies.json is NOT
expressible as plain JSON Schema (it depends on a sibling field's value) and is handled by
`check_finding_taxonomy()` below, called explicitly wherever a finding is validated.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"


class SchemaStore:
    """Loads every schemas/*.schema.json once and resolves $ref by filename."""

    def __init__(self, schemas_dir: Path = SCHEMAS_DIR) -> None:
        self.dir = schemas_dir
        self._cache: dict[str, dict] = {}

    def load(self, name: str) -> dict:
        name = name.split("#", 1)[0]
        if name not in self._cache:
            path = self.dir / name
            if not path.exists():
                raise FileNotFoundError(f"schema not found: {path}")
            self._cache[name] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[name]

    def taxonomies(self) -> dict:
        return json.loads((self.dir / "verdict-taxonomies.json").read_text(encoding="utf-8"))


_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "number": (int, float),
    "integer": int,
    "null": type(None),
}


def _check_type(value: Any, type_spec: Any) -> bool:
    types = type_spec if isinstance(type_spec, list) else [type_spec]
    for t in types:
        py_t = _TYPE_MAP.get(t)
        if py_t is None:
            continue
        # bool is a subclass of int in Python; only accept bool for "boolean" and int for "integer"/"number"
        if t == "boolean" and isinstance(value, bool):
            return True
        if t in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, py_t):
            return True
    return False


def validate(instance: Any, schema: dict, store: SchemaStore, path: str = "$") -> list[str]:
    """Returns a list of human-readable error strings. Empty list means valid."""
    errors: list[str] = []

    if "$ref" in schema:
        ref_schema = store.load(schema["$ref"])
        return validate(instance, ref_schema, store, path)

    if "const" in schema:
        if instance != schema["const"]:
            errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
        return errors

    if "type" in schema and not _check_type(instance, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']!r}, got {type(instance).__name__}")
        return errors  # further checks would be noise once the base type is wrong

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")

    if isinstance(instance, str) and "pattern" in schema:
        if not re.match(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match pattern {schema['pattern']!r}")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        props = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                errors.extend(validate(value, props[key], store, f"{path}.{key}"))
            elif schema.get("additionalProperties", True) is False:
                errors.append(f"{path}: unexpected property {key!r} (additionalProperties: false)")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: has {len(instance)} items, minItems is {schema['minItems']}")
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], store, f"{path}[{i}]"))

    return errors


def validate_document(instance: Any, schema_name: str, store: SchemaStore | None = None) -> list[str]:
    store = store or SchemaStore()
    schema = store.load(schema_name)
    return validate(instance, schema, store, path="$")


def check_finding_taxonomy(finding: dict, store: SchemaStore | None = None) -> list[str]:
    """Cross-field check plain JSON Schema can't express: classification must be a member of
    verdict-taxonomies.json's list for the finding's own classification_taxonomy."""
    store = store or SchemaStore()
    errors: list[str] = []
    taxonomy_key = finding.get("classification_taxonomy")
    classification = finding.get("classification")
    if taxonomy_key is None or classification is None:
        return errors  # base schema validation already flags missing required fields
    taxonomies = store.taxonomies().get("taxonomies", {})
    if taxonomy_key not in taxonomies:
        errors.append(
            f"classification_taxonomy {taxonomy_key!r} is not registered in verdict-taxonomies.json"
        )
        return errors
    allowed = taxonomies[taxonomy_key].get("values", [])
    if classification not in allowed:
        errors.append(
            f"classification {classification!r} is not a member of taxonomy "
            f"{taxonomy_key!r} (allowed: {allowed})"
        )
    return errors


def validate_lane_status(instance: dict, store: SchemaStore | None = None) -> tuple[list[str], list[str]]:
    """Validates a status.json against lane-status.schema.json.

    Returns (errors, warnings). findings[]/artifacts_read[] are validated for real shape when
    present, but their *absence* is only a warning right now -- existing lanes (00-09, 13, 15)
    predate this schema and are not expected to already populate it. Flip that to an error once
    lanes are migrated to author findings[] as the single source of truth (see lane-status
    schema's own description for why).
    """
    store = store or SchemaStore()
    errors = validate_document(instance, "lane-status.schema.json", store)
    warnings: list[str] = []

    raw_findings = instance.get("findings")
    if raw_findings is None:
        warnings.append("status.json has no findings[] yet -- not migrated to the common finding format")
    elif not isinstance(raw_findings, list):
        errors.append(
            f"$.findings: is not an array (found {type(raw_findings).__name__}) -- "
            "base schema check above already reports the type mismatch; not walking it for "
            "taxonomy cross-checks. Note: existing lane data may use a richer shape here "
            "(e.g. 05-native-memory's {\"reviewed\": [...]}) that a flat findings[] migration "
            "needs to account for, not just relax."
        )
    else:
        for i, finding in enumerate(raw_findings):
            if not isinstance(finding, dict):
                continue  # base schema validation (validate_document) already reported this
            tax_errors = check_finding_taxonomy(finding, store)
            errors.extend(f"$.findings[{i}]: {e}" for e in tax_errors)

    if "artifacts_read" not in instance:
        warnings.append("status.json has no artifacts_read[] yet -- not migrated to evidence-citation format")

    return errors, warnings
