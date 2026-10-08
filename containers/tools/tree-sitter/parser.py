#!/usr/local/bin/python
"""Narrow deterministic Tree-sitter container entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from tree_sitter_language_pack import PackConfig, configure, get_parser


TOOL_VERSION = "1.0.0"
RUNTIME_VERSION = "0.26.0"
PACK_VERSION = "1.12.5"
NORMALIZER_SCHEMA = "appsec-review/tree-sitter-normalizer/1"
LANGUAGES = {
    "C": "c", "C++": "cpp", "C/C++": "cpp", "Rust": "rust", "Go": "go",
    "Java": "java", "JavaScript": "javascript", "TypeScript": "typescript",
    "TSX": "tsx", "C#": "csharp", "Python": "python", "PHP": "php",
}


def _safe_target(path: str) -> Path:
    raw = PurePosixPath(path)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError("source path is not canonical and target-relative")
    target = Path("/target").resolve()
    candidate = (target / Path(*raw.parts)).resolve(strict=True)
    if target not in candidate.parents or not candidate.is_file():
        raise ValueError("source path escapes the read-only target")
    return candidate


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _node(node: Any, ordinal_path: tuple[int, ...], field: str | None) -> dict[str, Any]:
    return {
        "ordinal_path": list(ordinal_path), "field": field, "type": node.type,
        "named": bool(node.is_named), "error": bool(node.is_error),
        "missing": bool(node.is_missing), "extra": bool(node.is_extra),
        "has_error": bool(node.has_error), "start_byte": node.start_byte,
        "end_byte": node.end_byte, "start_point": list(node.start_point),
        "end_point": list(node.end_point),
    }


def parse(request_path: Path, output_path: Path) -> None:
    request = json.loads(request_path.read_text(encoding="utf-8"))
    if request.get("schema") != "appsec-review/tree-sitter-request/1":
        raise ValueError("unsupported request schema")
    language = str(request["language"])
    grammar = LANGUAGES.get(language)
    if grammar is None:
        raise ValueError(f"unsupported language: {language}")
    maximum_nodes = int(request["max_nodes"])
    maximum_scope_nodes = int(request["max_scope_nodes"])
    maximum_bytes = int(request["max_file_bytes"])
    if min(maximum_nodes, maximum_scope_nodes, maximum_bytes) < 1:
        raise ValueError("parser bounds must be positive")
    configure(PackConfig(cache_dir="/opt/grammars"))
    parser = get_parser(grammar)
    records: list[dict[str, Any]] = []
    scope_nodes = 0
    for item in request["files"]:
        relative = str(item["path"])
        source = _safe_target(relative)
        payload = source.read_bytes()
        actual = _digest(payload)
        if actual != item["sha256"]:
            raise ValueError(f"accepted source hash changed: {relative}")
        if len(payload) > maximum_bytes:
            records.append({"kind": "file", "path": relative, "status": "TRUNCATED",
                            "reason": "file_byte_limit", "sha256": actual, "bytes": len(payload)})
            continue
        tree = parser.parse(payload)
        if scope_nodes >= maximum_scope_nodes:
            records.append({"kind": "file", "path": relative, "status": "TRUNCATED",
                            "reason": "scope_node_limit", "sha256": actual, "bytes": len(payload)})
            continue
        stack: list[tuple[Any, tuple[int, ...], str | None]] = [(tree.root_node, (), None)]
        nodes: list[dict[str, Any]] = []
        truncated = False
        while stack:
            node, ordinal_path, field = stack.pop()
            if len(nodes) >= maximum_nodes or scope_nodes + len(nodes) >= maximum_scope_nodes:
                truncated = True
                break
            nodes.append(_node(node, ordinal_path, field))
            children = list(node.children)
            for index in range(len(children) - 1, -1, -1):
                stack.append((children[index], (*ordinal_path, index), node.field_name_for_child(index)))
        records.append({
            "kind": "file", "path": relative, "status": "PARTIAL" if truncated else "SUCCEEDED",
            "sha256": actual, "bytes": len(payload), "grammar": grammar,
            "root_has_error": bool(tree.root_node.has_error), "node_count": len(nodes),
            "truncated": truncated, "nodes": nodes,
        })
        scope_nodes += len(nodes)
    document = {
        "schema": "appsec-review/tree-sitter-container-output/1",
        "tool": {"id": "tool-tree-sitter", "version": TOOL_VERSION,
                 "tree_sitter": RUNTIME_VERSION, "language_pack": PACK_VERSION,
                 "normalizer_schema": NORMALIZER_SCHEMA,
                 "architecture": os.uname().machine},
        "scope_id": request["scope_id"], "language": language, "records": records,
    }
    output_path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> None:
    cli = argparse.ArgumentParser()
    sub = cli.add_subparsers(dest="command", required=True)
    sub.add_parser("version")
    run = sub.add_parser("parse")
    run.add_argument("--request", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    if args.command == "version":
        print(json.dumps({"tool": "appsec-tree-sitter", "version": TOOL_VERSION,
                          "tree_sitter": RUNTIME_VERSION, "language_pack": PACK_VERSION}, sort_keys=True))
    else:
        parse(args.request, args.output)


if __name__ == "__main__":
    main()
