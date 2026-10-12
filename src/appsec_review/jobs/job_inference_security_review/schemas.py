"""Closed JSON-schema subset validator for the inference-review contract schemas.

The runtime has no ``jsonschema`` dependency, so the job validates worker results and its handoff
against ``docs/schemas/inference-security-review/`` with this small draft 2020-12 subset. An
unsupported keyword is an error, never silently ignored, so a schema change that needs a new
keyword fails loudly. The test suite cross-checks this validator against ``jsonschema``.
"""
from __future__ import annotations

from functools import lru_cache
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping

SCHEMA_DIRECTORY = Path("docs") / "schemas" / "inference-security-review"
_ANNOTATIONS = frozenset({"$schema", "$id", "$defs", "title", "description", "format"})
_SUPPORTED = _ANNOTATIONS | frozenset({
    "$ref", "type", "properties", "required", "additionalProperties", "const", "enum", "pattern",
    "minLength", "maxLength", "minimum", "maximum", "items", "minItems", "maxItems", "uniqueItems",
    "oneOf", "allOf", "not", "if", "then", "else"})
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool}


class SchemaSet:
    """Every ``*.schema.json`` of one directory, addressed by file name."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.documents = {path.name: json.loads(path.read_text(encoding="utf-8"))
                          for path in sorted(self.directory.glob("*.schema.json"))}
        if "common.schema.json" not in self.documents:
            raise ValueError(f"schema set is incomplete: {self.directory}")

    def errors(self, name: str, value: Any, *, limit: int = 20) -> list[str]:
        document = self.documents[f"{name}.schema.json"]
        found: list[str] = []
        self._check(value, document, document, "$", found, limit)
        return found

    def validate(self, name: str, value: Any) -> None:
        errors = self.errors(name, value)
        if errors:
            raise ValueError(f"{name} does not satisfy its schema: {'; '.join(errors[:5])}")

    def _resolve(self, reference: str, document: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        target, _, pointer = reference.partition("#")
        root = self.documents[target] if target else document
        node: Any = root
        for part in [item for item in pointer.split("/") if item]:
            node = node[part]
        return node, root

    def _check(self, value: Any, schema: Mapping[str, Any], document: Mapping[str, Any], where: str,
               found: list[str], limit: int) -> None:
        if len(found) >= limit:
            return
        unknown = set(schema) - _SUPPORTED
        if unknown:
            raise ValueError(f"schema keyword is not supported by the closed validator: {sorted(unknown)}")

        def fail(message: str) -> None:
            found.append(f"{where}: {message}")

        if "$ref" in schema:
            target, root = self._resolve(schema["$ref"], document)
            self._check(value, target, root, where, found, limit)
        if "type" in schema:
            kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(value, kind) for kind in kinds):
                fail(f"expected {'/'.join(kinds)}")
                return
        if "const" in schema and not _equal(value, schema["const"]):
            fail("does not equal the constant")
        if "enum" in schema and not any(_equal(value, item) for item in schema["enum"]):
            fail("is not in the closed set")
        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", math.inf):
                fail("string length out of bounds")
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                fail("does not match the declared pattern")
        if _is_type(value, "number"):
            if "minimum" in schema and value < schema["minimum"]:
                fail("below minimum")
            if "maximum" in schema and value > schema["maximum"]:
                fail("above maximum")
        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", math.inf):
                fail("array length out of bounds")
            if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
                fail("array items are not unique")
            if "items" in schema:
                for index, item in enumerate(value):
                    self._check(item, schema["items"], document, f"{where}[{index}]", found, limit)
        if isinstance(value, dict):
            for key in schema.get("required", ()):
                if key not in value:
                    fail(f"missing required property {key}")
            properties = schema.get("properties", {})
            for key, item in value.items():
                if key in properties:
                    self._check(item, properties[key], document, f"{where}.{key}", found, limit)
                elif schema.get("additionalProperties") is False:
                    fail(f"unexpected property {str(key)[:64]}")
                elif isinstance(schema.get("additionalProperties"), Mapping):
                    self._check(item, schema["additionalProperties"], document, f"{where}.{key}", found, limit)
        if "allOf" in schema:
            for branch in schema["allOf"]:
                self._check(value, branch, document, where, found, limit)
        if "oneOf" in schema:
            matches = sum(1 for branch in schema["oneOf"] if not self._branch_errors(value, branch, document))
            if matches != 1:
                fail(f"matches {matches} oneOf branches, expected exactly one")
        if "not" in schema and not self._branch_errors(value, schema["not"], document):
            fail("matches a forbidden schema")
        if "if" in schema:
            branch = "then" if not self._branch_errors(value, schema["if"], document) else "else"
            if branch in schema:
                self._check(value, schema[branch], document, where, found, limit)

    def _branch_errors(self, value: Any, schema: Mapping[str, Any], document: Mapping[str, Any]) -> list[str]:
        found: list[str] = []
        self._check(value, schema, document, "$", found, 1)
        return found


def _is_type(value: Any, kind: str) -> bool:
    if kind == "null":
        return value is None
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    expected = _TYPES.get(kind)
    if expected is None:
        raise ValueError(f"unsupported schema type: {kind}")
    return isinstance(value, expected)


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


@lru_cache(maxsize=8)
def schema_set(repository_root: str) -> SchemaSet:
    return SchemaSet(Path(repository_root) / SCHEMA_DIRECTORY)
