"""Re-record the end-to-end slicing fixture (manual; needs Docker and the pinned Tree-sitter wheels).

Usage: ``python tests/fixtures/slicing_end_to_end/record.py``. The sources are the SVF fixture
``containers/fixtures/svf/source`` (``native/guard.c`` and ``native/main.c``), whose real ``tool-svf`` output
is already recorded under ``tests/fixtures/svf/recorded``. This script records the other two compiler and
syntax inputs for the same bytes:

* ``ir/<stem>.ll``: clang-18 ``-emit-llvm -S -g -O0`` in the locked native toolchain image, compiled from
  ``/scratch/source`` so debug-info paths are ``native/<file>`` exactly as the compiled-analysis job sees them.
* ``ast.json.gz``: the locked ``tool-tree-sitter`` parser's node records (the container's own ``_node``),
  through ``tests/fixtures/function_spans/generate_ast.py``.

Both are generated views: never edit them by hand.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "containers" / "fixtures" / "svf" / "source"
FILES = ("guard.c", "main.c")
IMAGE = "appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1"


def record_ir() -> None:
    (HERE / "ir").mkdir(exist_ok=True)
    for name in FILES:
        done = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "-v", f"{SOURCE}:/scratch/source/native:ro",
             "-w", "/scratch/source", IMAGE, "clang-18", "-emit-llvm", "-S", "-g", "-O0", "-o", "-",
             f"native/{name}"], capture_output=True, check=True)
        (HERE / "ir" / f"{Path(name).stem}.ll").write_bytes(done.stdout)


def record_ast() -> None:
    sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "function_spans"))
    from generate_ast import parse_records

    document = parse_records(SOURCE)
    document["files"] = {f"native/{name}": document["files"][name] for name in FILES}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    (HERE / "ast.json.gz").write_bytes(gzip.compress(payload, mtime=0))


if __name__ == "__main__":
    record_ir()
    record_ast()
