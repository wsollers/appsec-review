#!/usr/bin/env python3
"""List the JSON Schema keywords the repo's schemas use against what schema_validate supports.

Brief L: the dependency-free validator must implement, or explicitly reject, every keyword the
schemas use; nothing may be silently ignored. This lint walks every schema node (through
properties, $defs, items, allOf/anyOf/oneOf, if/then/else and the other applicators) of
schemas/**/*.schema.json and the persona/role schemas, and fails when a node uses:

* a keyword outside ``SUPPORTED_KEYWORDS`` and ``ANNOTATION_KEYWORDS``;
* a ``format`` outside ``FORMAT_CHECKERS``;
* a ``$ref`` that does not resolve, or a ``pattern`` that does not compile.

``python3 schema_keyword_lint.py`` prints the table and exits 1 on any problem.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

from schema_validate import (ANNOTATION_KEYWORDS, FOLDER_SCHEMAS, FORMAT_CHECKERS, SCHEMAS_DIR,
                             SUPPORTED_KEYWORDS, SchemaStore, UnsupportedSchema, resolve_ref)

_SCHEMA_MAPS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
_SCHEMA_LISTS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SCHEMA_VALUES = ("additionalProperties", "items", "contains", "not", "if", "then", "else",
                  "propertyNames", "unevaluatedProperties", "unevaluatedItems",
                  "additionalItems")


def schema_files(schemas_dir: Path = SCHEMAS_DIR) -> list[tuple[str, Path]]:
    """(store name, path) of every schema file the validator can load."""
    files = [(path.relative_to(schemas_dir).as_posix(), path)
             for path in sorted(schemas_dir.rglob("*.schema.json"))]
    return files + sorted(FOLDER_SCHEMAS.items())


def nodes(schema: Any, where: str = "#") -> Iterator[tuple[str, dict]]:
    """Every schema object under ``schema`` with its JSON-pointer location."""
    if not isinstance(schema, dict):
        return
    yield where, schema
    for key in _SCHEMA_MAPS:
        if isinstance(schema.get(key), dict):
            for name, sub in schema[key].items():
                yield from nodes(sub, f"{where}/{key}/{name}")
    for key in _SCHEMA_LISTS:
        if isinstance(schema.get(key), list):
            for index, sub in enumerate(schema[key]):
                yield from nodes(sub, f"{where}/{key}/{index}")
    for key in _SCHEMA_VALUES:
        value = schema.get(key)
        if isinstance(value, list):
            for index, sub in enumerate(value):
                yield from nodes(sub, f"{where}/{key}/{index}")
        else:
            yield from nodes(value, f"{where}/{key}")


def survey(schemas_dir: Path = SCHEMAS_DIR) -> dict[str, Any]:
    """{"used": Counter(keyword), "files": {keyword: set(file)}, "problems": [str]}."""
    store = SchemaStore(schemas_dir)
    used: Counter = Counter()
    files: dict[str, set[str]] = defaultdict(set)
    problems: list[str] = []
    for name, path in schema_files(schemas_dir):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append(f"{name}: unreadable: {exc}")
            continue
        for where, node in nodes(document):
            for keyword in node:
                used[keyword] += 1
                files[keyword].add(name)
                if keyword not in SUPPORTED_KEYWORDS and keyword not in ANNOTATION_KEYWORDS:
                    problems.append(f"{name}{where}: unsupported keyword {keyword!r}")
            if "format" in node and node["format"] not in FORMAT_CHECKERS:
                problems.append(f"{name}{where}: unsupported format {node['format']!r}")
            if isinstance(node.get("pattern"), str):
                try:
                    re.compile(node["pattern"])
                except re.error as exc:
                    problems.append(f"{name}{where}: pattern does not compile: {exc}")
            if isinstance(node.get("$ref"), str):
                ref = node["$ref"]
                try:
                    resolve_ref(ref, document, store)
                except (UnsupportedSchema, OSError, ValueError) as exc:
                    problems.append(f"{name}{where}: $ref {ref!r}: {exc}")
    return {"used": used, "files": files, "problems": problems}


def report(result: dict[str, Any]) -> str:
    lines = ["keyword                 uses  files  status"]
    for keyword, count in sorted(result["used"].items(), key=lambda kv: (-kv[1], kv[0])):
        status = ("supported" if keyword in SUPPORTED_KEYWORDS else
                  "annotation" if keyword in ANNOTATION_KEYWORDS else "UNSUPPORTED")
        lines.append(f"{keyword:<22} {count:>5}  {len(result['files'][keyword]):>5}  {status}")
    unused = sorted(SUPPORTED_KEYWORDS - set(result["used"]))
    lines.append("supported but unused: " + (", ".join(unused) or "-"))
    lines += [f"PROBLEM {p}" for p in result["problems"]]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    result = survey()
    print(report(result))
    return 1 if result["problems"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
