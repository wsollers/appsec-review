#!/usr/bin/env python3
"""Small, dependency-free JSON Schema (Draft 2020-12) validator for the schemas/ directory.

Added 2026-09-19 as the "define schemas, place them centrally, write/wire in/test the schema
validators" first step (see claude project TODO -- the common finding/evidence/interjob-transfer
format effort). Deliberately not a dependency on the third-party `jsonschema` pip package: nothing
else in appsec-review-process/*.py takes an external dependency, and this project has a track
record of hand-rolling a real, robust parser instead of trusting a generic library to do exactly
what's needed (see review_cli.py's own budget-table markdown parser, added after a regex-based
guess silently dropped the `full` tier -- bug #2 in the harness doc).

Keyword coverage (brief L): every keyword is either an assertion/applicator in
``SUPPORTED_KEYWORDS``, an annotation in ``ANNOTATION_KEYWORDS`` (no effect on validity), or
rejected: a schema node carrying any other keyword raises ``UnsupportedSchema`` instead of being
silently ignored. ``schema_keyword_lint.py`` lists the keywords the repo's schemas use against
these sets. ``format`` is asserted, and only the formats in ``FORMAT_CHECKERS`` are accepted.

Three deliberate dialect points, all kept from the original subset so no schema changes meaning:
``pattern`` uses Python ``re`` syntax (the schemas use ``\\Z``) and is matched with ``re.match``
(anchored at the start of the string); ``$ref`` resolves a bare file name against schemas/ (or a
sub-directory such as ``common/``), ``file#/json/pointer`` inside that file, and ``#/json/pointer``
inside the document being validated. Remote references are rejected. ``const`` and ``enum`` use
Python equality, so ``0`` satisfies ``const: false`` (``uniqueItems`` uses JSON equality).

classification/classification_taxonomy cross-checking against verdict-taxonomies.json is NOT
expressible as plain JSON Schema (it depends on a sibling field's value) and is handled by
`check_finding_taxonomy()` below, called explicitly wherever a finding is validated.
"""
from __future__ import annotations

import datetime
import functools
import json
import re
from pathlib import Path
from typing import Any

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"
# The persona and role schemas live with the records they describe (appsec-review-process/personas/).
FOLDER_SCHEMAS = {name: Path(__file__).resolve().parent / "personas" / name
                  for name in ("persona.schema.json", "role.schema.json")}


class SchemaStore:
    """Loads every schemas/*.schema.json once and resolves $ref by filename."""

    def __init__(self, schemas_dir: Path = SCHEMAS_DIR) -> None:
        self.dir = schemas_dir
        self._cache: dict[str, dict] = {}

    def load(self, name: str) -> dict:
        name = name.split("#", 1)[0]
        if name not in self._cache:
            path = self.dir / name
            if not path.exists() and name in FOLDER_SCHEMAS:
                path = FOLDER_SCHEMAS[name]
            if not path.exists():
                raise FileNotFoundError(f"schema not found: {path}")
            self._cache[name] = json.loads(path.read_text(encoding="utf-8"))
        return self._cache[name]

    def taxonomies(self) -> dict:
        return json.loads((self.dir / "verdict-taxonomies.json").read_text(encoding="utf-8"))


# Assertion and applicator keywords this validator implements.
SUPPORTED_KEYWORDS = frozenset({
    "$ref", "type", "enum", "const",
    "properties", "patternProperties", "additionalProperties", "required", "propertyNames",
    "minProperties", "maxProperties", "dependentRequired",
    "items", "prefixItems", "minItems", "maxItems", "uniqueItems", "contains", "minContains",
    "maxContains",
    "minLength", "maxLength", "pattern", "format",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
})
# Keywords with no effect on validity. $defs/definitions are containers reached through $ref.
ANNOTATION_KEYWORDS = frozenset({
    "$schema", "$id", "$comment", "$defs", "definitions", "title", "description", "default",
    "examples", "deprecated", "readOnly", "writeOnly", "contentMediaType", "contentEncoding",
})


class UnsupportedSchema(ValueError):
    """A schema uses a keyword, format or $ref this validator does not implement."""


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
            raise UnsupportedSchema(f"unknown type {t!r}")
        # bool is a subclass of int in Python; only accept bool for "boolean" and int for "integer"/"number"
        if t == "boolean" and isinstance(value, bool):
            return True
        if t in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, py_t):
            return True
    return False


def _json_key(value: Any) -> Any:
    """A hashable key under which two values are equal exactly when JSON says they are
    (1 == 1.0, but true != 1; object key order does not matter)."""
    if isinstance(value, bool) or value is None:
        return ("lit", value)
    if isinstance(value, (int, float)):
        return ("num", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, list):
        return ("arr", tuple(_json_key(v) for v in value))
    if isinstance(value, dict):
        return ("obj", tuple(sorted((k, _json_key(v)) for k, v in value.items())))
    return ("other", repr(value))


def json_equal(left: Any, right: Any) -> bool:
    return _json_key(left) == _json_key(right)


_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?"
                      r"([Zz]|[+-](\d{2}):(\d{2}))\Z")


def _is_date(year: int, month: int, day: int) -> bool:
    try:
        datetime.date(year, month, day)
        return True
    except ValueError:
        return False


def _format_date_time(value: str) -> bool:
    m = _RFC3339.match(value)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if not _is_date(year, month, day) or hour > 23 or minute > 59 or second > 60:
        return False
    return m.group(9) is None or (int(m.group(9)) <= 23 and int(m.group(10)) <= 59)


def _format_date(value: str) -> bool:
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})\Z", value)
    return bool(m) and _is_date(*(int(g) for g in m.groups()))


FORMAT_CHECKERS = {"date-time": _format_date_time, "date": _format_date}


def check_format(name: str, value: str) -> bool:
    checker = FORMAT_CHECKERS.get(name)
    if checker is None:
        raise UnsupportedSchema(f"unsupported format {name!r}")
    return checker(value)


@functools.lru_cache(maxsize=4096)
def _regex(pattern: str) -> re.Pattern:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise UnsupportedSchema(f"pattern {pattern!r} does not compile: {exc}") from None


def _pointer(document: Any, fragment: str, ref: str) -> Any:
    node = document
    if fragment in ("", "/"):
        return node
    if not fragment.startswith("/"):
        raise UnsupportedSchema(f"$ref {ref!r}: only JSON-pointer fragments are supported")
    for token in fragment[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            raise UnsupportedSchema(f"$ref {ref!r} does not resolve")
    return node


def resolve_ref(ref: str, root: Any, store: "SchemaStore") -> tuple[Any, Any]:
    """Returns (schema node, the root document it belongs to)."""
    if "://" in ref or ref.startswith("/"):
        raise UnsupportedSchema(f"remote or absolute $ref {ref!r} is not supported")
    file_part, _, fragment = ref.partition("#")
    document = store.load(file_part) if file_part else root
    if document is None:
        raise UnsupportedSchema(f"local $ref {ref!r} with no enclosing schema document")
    return _pointer(document, fragment, ref), document


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate(instance: Any, schema: Any, store: SchemaStore, path: str = "$",
             root: Any = None) -> list[str]:
    """Returns a list of human-readable error strings. Empty list means valid.

    ``root`` is the schema document local ``#/...`` references resolve against; it defaults to
    ``schema`` itself. Raises ``UnsupportedSchema`` for a keyword, format or reference outside
    SUPPORTED_KEYWORDS / ANNOTATION_KEYWORDS / FORMAT_CHECKERS."""
    if schema is True:
        return []
    if schema is False:
        return [f"{path}: no value is allowed here (schema false)"]
    if not isinstance(schema, dict):
        raise UnsupportedSchema(f"{path}: schema node is {type(schema).__name__}, not an object")
    if root is None:
        root = schema
    unknown = set(schema) - SUPPORTED_KEYWORDS - ANNOTATION_KEYWORDS
    if unknown:
        raise UnsupportedSchema(f"{path}: unsupported schema keyword(s) {sorted(unknown)}")

    errors: list[str] = []

    if "$ref" in schema:
        target, target_root = resolve_ref(schema["$ref"], root, store)
        errors.extend(validate(instance, target, store, path, target_root))

    # const/enum keep Python equality (0 == false, 1 == true), as the original subset did: three
    # tests (owasp_dispatch, evidence_index_metrics, pool_rendezvous) pin the later, named check
    # that rejects a number for a boolean. JSON equality (json_equal) is an owner decision (TODO L).
    if "const" in schema:
        if instance != schema["const"]:
            errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
        return errors

    if "type" in schema and not _check_type(instance, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']!r}, got {type(instance).__name__}")
        return errors  # further checks would be noise once the base type is wrong

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")

    pattern = _regex(schema["pattern"]) if "pattern" in schema else None  # compiles for any instance
    if isinstance(instance, str):
        if pattern is not None and not pattern.match(instance):
            errors.append(f"{path}: {instance!r} does not match pattern {schema['pattern']!r}")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: length {len(instance)} is below minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: length {len(instance)} is above maxLength {schema['maxLength']}")
        if "format" in schema and not check_format(schema["format"], instance):
            errors.append(f"{path}: {instance!r} is not a valid {schema['format']}")
    elif "format" in schema:
        check_format(schema["format"], "")  # an unknown format is rejected for any instance

    if _number(instance):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance!r} is below minimum {schema['minimum']!r}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance!r} is above maximum {schema['maximum']!r}")
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            errors.append(f"{path}: {instance!r} is not above exclusiveMinimum "
                          f"{schema['exclusiveMinimum']!r}")
        if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
            errors.append(f"{path}: {instance!r} is not below exclusiveMaximum "
                          f"{schema['exclusiveMaximum']!r}")
        if "multipleOf" in schema:
            quotient = instance / schema["multipleOf"]
            if not float(quotient).is_integer():
                errors.append(f"{path}: {instance!r} is not a multiple of {schema['multipleOf']!r}")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")
        for key, needed in schema.get("dependentRequired", {}).items():
            if key in instance:
                for other in needed:
                    if other not in instance:
                        errors.append(f"{path}: property {key!r} requires property {other!r}")
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            errors.append(f"{path}: has {len(instance)} properties, minProperties is "
                          f"{schema['minProperties']}")
        if "maxProperties" in schema and len(instance) > schema["maxProperties"]:
            errors.append(f"{path}: has {len(instance)} properties, maxProperties is "
                          f"{schema['maxProperties']}")
        props = schema.get("properties", {})
        pattern_props = schema.get("patternProperties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            matched = False
            if key in props:
                matched = True
                errors.extend(validate(value, props[key], store, f"{path}.{key}", root))
            for pattern, sub in pattern_props.items():
                if _regex(pattern).search(key):
                    matched = True
                    errors.extend(validate(value, sub, store, f"{path}.{key}", root))
            if matched:
                continue
            if additional is False:
                errors.append(f"{path}: unexpected property {key!r} (additionalProperties: false)")
            elif additional is not True:
                errors.extend(validate(value, additional, store, f"{path}.{key}", root))
        if "propertyNames" in schema:
            for key in instance:
                errors.extend(validate(key, schema["propertyNames"], store,
                                       f"{path}[property name {key!r}]", root))

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: has {len(instance)} items, minItems is {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: has {len(instance)} items, maxItems is {schema['maxItems']}")
        if schema.get("uniqueItems") is True:
            seen: set = set()
            for i, item in enumerate(instance):
                key = _json_key(item)
                if key in seen:
                    errors.append(f"{path}[{i}]: duplicate item (uniqueItems: true)")
                seen.add(key)
        prefix = schema.get("prefixItems", [])
        for i, sub in enumerate(prefix[:len(instance)]):
            errors.extend(validate(instance[i], sub, store, f"{path}[{i}]", root))
        if "items" in schema:
            if isinstance(schema["items"], list):
                raise UnsupportedSchema(f"{path}: array-form items is not Draft 2020-12; use prefixItems")
            for i, item in enumerate(instance[len(prefix):], start=len(prefix)):
                errors.extend(validate(item, schema["items"], store, f"{path}[{i}]", root))
        if "contains" in schema:
            hits = sum(1 for item in instance
                       if not validate(item, schema["contains"], store, path, root))
            low = schema.get("minContains", 1)
            if hits < low:
                errors.append(f"{path}: {hits} item(s) match contains, at least {low} required")
            if "maxContains" in schema and hits > schema["maxContains"]:
                errors.append(f"{path}: {hits} item(s) match contains, at most "
                              f"{schema['maxContains']} allowed")

    for sub in schema.get("allOf", []):
        errors.extend(validate(instance, sub, store, path, root))
    if "anyOf" in schema:
        branches = [validate(instance, sub, store, path, root) for sub in schema["anyOf"]]
        if all(branches):
            errors.append(f"{path}: matches none of anyOf: " +
                          " | ".join("; ".join(b[:3]) for b in branches))
    if "oneOf" in schema:
        branches = [validate(instance, sub, store, path, root) for sub in schema["oneOf"]]
        passing = sum(1 for b in branches if not b)
        if passing == 0:
            errors.append(f"{path}: matches none of oneOf: " +
                          " | ".join("; ".join(b[:3]) for b in branches))
        elif passing > 1:
            errors.append(f"{path}: matches {passing} branches of oneOf, exactly one allowed")
    if "not" in schema and not validate(instance, schema["not"], store, path, root):
        errors.append(f"{path}: must not match the 'not' schema")
    if "if" in schema:
        if not validate(instance, schema["if"], store, path, root):
            if "then" in schema:
                errors.extend(validate(instance, schema["then"], store, path, root))
        elif "else" in schema:
            errors.extend(validate(instance, schema["else"], store, path, root))

    return errors


def validate_document(instance: Any, schema_name: str, store: SchemaStore | None = None) -> list[str]:
    """Validates against ``name.schema.json`` or ``name.schema.json#/json/pointer``."""
    store = store or SchemaStore()
    schema, root = resolve_ref(schema_name, None, store)
    return validate(instance, schema, store, path="$", root=root)


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
