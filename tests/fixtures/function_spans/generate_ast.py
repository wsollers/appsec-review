"""Regenerate ``ast-golden.json.gz`` from ``source/`` with the locked Tree-sitter parser.

The golden file is a generated view: never edit it by hand. It records exactly what the locked
``tool-tree-sitter`` container emits for each per-language function-span fixture, so the span tests can
replay real grammar output without Docker. Run it in an environment that has the pinned
``tree-sitter==0.26.0`` and ``tree-sitter-language-pack==1.12.5`` wheels installed:

    python tests/fixtures/function_spans/generate_ast.py

Fixture markers (inside comments): ``BEGIN:<id>`` on a named function's first line, ``END:<id>`` on its
last line, ``ANCHOR:<id>`` on a line whose enclosing named function is ``<id>`` (``ANCHOR:none`` when no
named function encloses it). Lambdas, closures and anonymous blocks belong to their enclosing function.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source"
GOLDEN = HERE / "ast-golden.json.gz"
PARSER = HERE.parents[2] / "containers" / "tools" / "tree-sitter" / "parser.py"
SCHEMA = "appsec-review/test-tree-sitter-golden/1"
# Suffix -> (catalog language, grammar), mirroring the container's LANGUAGES table. Swift has no grammar in
# the locked pack, so its fixture exercises only the text rules.
GRAMMARS = {".c": ("C", "c"), ".cpp": ("C++", "cpp"), ".cs": ("C#", "csharp"), ".go": ("Go", "go"),
            ".java": ("Java", "java"), ".js": ("JavaScript", "javascript"), ".ts": ("TypeScript", "typescript"),
            ".tsx": ("TSX", "tsx"), ".kt": ("Kotlin", "kotlin"), ".php": ("PHP", "php"),
            ".ps1": ("PowerShell", "powershell"), ".py": ("Python", "python"), ".rb": ("Ruby", "ruby"),
            ".rs": ("Rust", "rust"), ".sh": ("Shell", "bash")}


def _container_module() -> Any:
    spec = importlib.util.spec_from_file_location("appsec_tree_sitter_container", PARSER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the Tree-sitter container parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_records(root: Path = SOURCE) -> dict[str, Any]:
    """Return container-equivalent file records for every fixture source file under ``root``."""
    container = _container_module()
    files: dict[str, Any] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        found = GRAMMARS.get(path.suffix)
        if found is None:
            continue
        language, grammar = found
        if container.LANGUAGES.get(language) != grammar:
            raise RuntimeError(f"{path.suffix} grammar differs from the container's LANGUAGES table")
        relative = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        tree = container.get_parser(grammar).parse(payload)
        stack = [(tree.root_node, (), None)]
        nodes = []
        while stack:
            node, ordinal_path, field = stack.pop()
            nodes.append(container._node(node, ordinal_path, field))
            children = list(node.children)
            for index in range(len(children) - 1, -1, -1):
                stack.append((children[index], (*ordinal_path, index), node.field_name_for_child(index)))
        files[relative] = {"sha256": hashlib.sha256(payload).hexdigest(), "language": language,
                           "grammar": grammar, "root_has_error": bool(tree.root_node.has_error),
                           "nodes": nodes}
    return {"schema": SCHEMA, "tool": {"tree_sitter": container.RUNTIME_VERSION,
                                       "language_pack": container.PACK_VERSION}, "files": files}


def main() -> int:
    document = parse_records()
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    GOLDEN.write_bytes(gzip.compress(payload, mtime=0))
    print(f"wrote {GOLDEN.relative_to(HERE.parents[2])} ({len(document['files'])} files)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
