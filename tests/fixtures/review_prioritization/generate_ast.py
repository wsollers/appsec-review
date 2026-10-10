"""Regenerate ``ast-golden.json.gz`` from ``target/`` with the locked Tree-sitter parser.

The golden file is a generated view: never edit it by hand.  It records exactly what the locked
``tool-tree-sitter`` container emits for each fixture file, so the review-prioritization tests can
replay real grammar output without Docker.  Run it in an environment that has the pinned
``tree-sitter==0.26.0`` and ``tree-sitter-language-pack==1.12.5`` wheels installed:

    python tests/fixtures/review_prioritization/generate_ast.py

``tests/test_review_prioritization.py`` re-parses the fixtures and compares against the golden when
those wheels are importable, and always verifies that the golden still matches the fixture bytes.
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
TARGET = HERE / "target"
GOLDEN = HERE / "ast-golden.json.gz"
PARSER = HERE.parents[2] / "containers" / "tools" / "tree-sitter" / "parser.py"
SCHEMA = "appsec-review/test-tree-sitter-golden/1"
# Catalog language -> grammar, mirroring the container's LANGUAGES table and scope routing.
GRAMMARS = {".c": "c", ".h": "cpp", ".cpp": "cpp", ".java": "java", ".cs": "csharp", ".go": "go",
            ".js": "javascript", ".ts": "typescript", ".tsx": "tsx", ".rs": "rust", ".php": "php"}


def _container_module() -> Any:
    spec = importlib.util.spec_from_file_location("appsec_tree_sitter_container", PARSER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the Tree-sitter container parser")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_records() -> dict[str, Any]:
    """Return container-equivalent file records for every fixture source file."""
    container = _container_module()
    files: dict[str, Any] = {}
    for path in sorted(item for item in TARGET.rglob("*") if item.is_file()):
        grammar = GRAMMARS.get(path.suffix)
        if grammar is None:
            continue
        relative = path.relative_to(TARGET).as_posix()
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
        files[relative] = {"sha256": hashlib.sha256(payload).hexdigest(), "grammar": grammar,
                           "root_has_error": bool(tree.root_node.has_error), "nodes": nodes}
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
