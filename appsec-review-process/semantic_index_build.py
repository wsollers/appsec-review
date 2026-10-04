#!/usr/bin/env python3
"""In-container LanceDB builder for ``02-semantic-recall-index`` (moved from the legacy
``images/audit-static*/scripts/build_semantic_index.py``; ``query_semantic_index.py``'s search is
``LanceStore.search`` here and ``semantic_recall_index.query`` on the host).

Runs inside the pinned image that carries lancedb + fastembed (``image_id`` tunable of the job), in the
B13 boundary: network none, read-only mounts only. It never chunks or reads source itself: the host
worker (``semantic_recall_index.py``) cuts one chunk per accepted code-index function span, redacts
it, caps it at ``MAX_CHUNK_CHARS`` and stages the plan (``plan.jsonl``) beside this script. This
script embeds each chunk with the preseeded model mounted at ``--model`` (``specific_model_path``:
fastembed never downloads), writes locator rows (no text) to the LanceDB table ``chunks`` batch by
batch, and writes a stats file the host checks: row count, plan hash, and the hash of the model tree
it actually loaded.

Kept from the legacy builder (its incident notes, 2026-09-08): batches stream straight into LanceDB
(no whole-run vector accumulator: EASTL climbed toward Docker's memory limit), and no chunk exceeds
``MAX_CHUNK_CHARS``: ONNX Runtime pads every sequence in a batch to the longest one and self-attention
costs ~batch_size * length^2, so a few 5-27K-char generated chunks (fsh-server's ControllerHtml.cs
"TableRaw" renderers) in one batch of 64 spiked one slice to 28.57 GB / 2337% CPU. The cap is applied
by the host when it cuts the plan; it truncates only the embedded text, never the locator span.
The legacy start-line chunk heuristic and the LanceDB FTS index are gone: chunk bounds are exact
function spans, and SQLite FTS5 (``02-evidence-index``) stays the lexical authority.

Stdlib only at import time (lancedb and fastembed are imported where used) and Python 3.10 safe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

MAX_CHUNK_CHARS = 4000
TABLE = "chunks"
MODEL_FILES = ("onnx/model.onnx", "config.json", "special_tokens_map.json", "tokenizer.json", "tokenizer_config.json")
COLUMNS = ("row_id", "file", "start_line", "end_line", "symbol", "language")

Embedder = Callable[[list], list]


def _file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def _digest(value: Any) -> str:
    """``execution_state.digest`` (kept identical: the host compares the two)."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def model_files(model_dir: Path) -> dict[str, str]:
    """{relative path: sha256} of the model's pinned files; a missing or symlinked file raises."""
    model_dir = Path(model_dir)
    values = {}
    for name in MODEL_FILES:
        path = model_dir / name
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(f"model file missing: {name}")
        values[name] = _file_sha256(path)
    return values


def model_sha256(model_dir: Path) -> str:
    return "sha256:" + _digest(model_files(model_dir))


def tree_sha256(root: Path) -> str:
    """sha256 over every regular file of a directory tree (relative path + content hash)."""
    root = Path(root)
    rows = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(current, name)
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"index tree carries a non-regular file: {path.relative_to(root)}")
            rows.append([path.relative_to(root).as_posix(), _file_sha256(path)])
    return "sha256:" + _digest(sorted(rows))


def plan_line(row: dict[str, Any]) -> bytes:
    """One plan row as staged and hashed (the host writes ``plan.jsonl`` with this; ``build`` hashes it)."""
    return (json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def read_plan(path: Path) -> Iterator[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def fastembed_embedder(model_dir: Path, model_id: str, cache_dir: Path | None = None) -> Embedder:
    """The pinned model loaded from ``model_dir`` only (``specific_model_path``; nothing is downloaded)."""
    from fastembed import TextEmbedding
    kwargs: dict[str, Any] = {"model_name": model_id, "specific_model_path": str(model_dir), "local_files_only": True}
    if cache_dir is not None:
        kwargs["cache_dir"] = str(cache_dir)
    model = TextEmbedding(**kwargs)
    return lambda texts: [[float(x) for x in vector] for vector in model.embed(list(texts))]


class LanceStore:
    """The LanceDB table ``chunks``: locator columns plus the vector, no source text."""

    def __init__(self, path: Path, table: str = TABLE):
        self.path, self.table = Path(path), table

    def write(self, batches: Iterable[list[dict[str, Any]]]) -> int:
        import lancedb
        self.path.mkdir(parents=True, exist_ok=True)
        db = lancedb.connect(str(self.path))
        table = None
        for rows in batches:
            if table is None:
                table = db.create_table(self.table, data=rows, mode="overwrite")
            else:
                table.add(rows)
        return 0 if table is None else table.count_rows()

    def search(self, vector: list[float], limit: int) -> list[dict[str, Any]]:
        import lancedb
        query = lancedb.connect(str(self.path)).open_table(self.table).search(vector)
        query = query.distance_type("cosine") if hasattr(query, "distance_type") else query.metric("cosine")
        return [{"row_id": int(row["row_id"]), "distance": float(row["_distance"])}
                for row in query.limit(limit).to_list()]


def build(plan: Iterable[dict[str, Any]], embedder: Embedder, store: Any, batch_size: int) -> dict[str, Any]:
    """Embed every plan row in batches of ``batch_size`` and stream the rows into ``store``."""
    if batch_size < 1:
        raise ValueError("batch size must be positive")
    plan_hash, counted, dims = hashlib.sha256(), [0], set()

    def batches() -> Iterator[list[dict[str, Any]]]:
        pending: list[dict[str, Any]] = []
        for row in plan:
            plan_hash.update(plan_line(row))
            if len(row["text"]) > MAX_CHUNK_CHARS:
                raise ValueError(f"plan row {row['row_id']} exceeds {MAX_CHUNK_CHARS} chars")
            pending.append(row)
            if len(pending) == batch_size:
                yield embed(pending); pending = []
        if pending:
            yield embed(pending)

    def embed(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        vectors = embedder([row["text"] for row in rows])
        if len(vectors) != len(rows):
            raise ValueError("embedder returned a different number of vectors")
        out = []
        for row, vector in zip(rows, vectors):
            dims.add(len(vector))
            out.append({**{key: row[key] for key in COLUMNS}, "vector": [float(x) for x in vector]})
        counted[0] += len(out)
        if counted[0] % (batch_size * 50) < batch_size:
            print(f"  embedded and wrote {counted[0]} chunk(s)...", file=sys.stderr)
        return out

    rows = store.write(batches())
    if len(dims) > 1:
        raise ValueError(f"embedder returned vectors of several dimensions: {sorted(dims)}")
    return {"rows": rows, "embedded": counted[0], "plan_sha256": "sha256:" + plan_hash.hexdigest(),
            "vector_dim": dims.pop() if dims else None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("build", help="embed a staged plan into a LanceDB table")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--model", type=Path, required=True, help="preseeded model directory (read-only mount)")
    run.add_argument("--model-id", required=True)
    run.add_argument("--out", type=Path, required=True, help="LanceDB directory to create")
    run.add_argument("--stats", type=Path, required=True)
    run.add_argument("--batch-size", type=int, default=8)
    args = parser.parse_args(argv)
    loaded = model_sha256(args.model)
    embedder = fastembed_embedder(args.model, args.model_id, Path(os.environ.get("XDG_CACHE_HOME", "/tmp")) / "fastembed")
    stats = build(read_plan(args.plan), embedder, LanceStore(args.out), args.batch_size)
    stats.update(model_sha256=loaded, model_id=args.model_id, table=TABLE)
    args.stats.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"semantic index: {stats['rows']} row(s), dim {stats['vector_dim']}", file=sys.stderr)
    return 0 if stats["rows"] == stats["embedded"] and stats["rows"] > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
