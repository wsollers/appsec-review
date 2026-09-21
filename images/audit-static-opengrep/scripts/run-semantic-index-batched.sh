#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run-semantic-index-batched.sh REPO SYMBOL_INDEX_DIR OUT_DIR" >&2
  exit 2
fi

repo=$1
symbol_index=$2
out_dir=$3

batch_size=${SEMANTIC_INDEX_BATCH_SIZE:-1}
slice_limit=${SEMANTIC_INDEX_SLICE_LIMIT:-0}
table=${SEMANTIC_INDEX_TABLE:-chunks}
model=${SEMANTIC_INDEX_MODEL:-}
start=${SEMANTIC_INDEX_START:-0}

if ! [[ "$batch_size" =~ ^[0-9]+$ && "$batch_size" -ge 1 ]]; then
  echo "SEMANTIC_INDEX_BATCH_SIZE must be a positive integer, got '$batch_size'" >&2
  exit 2
fi
if ! [[ "$slice_limit" =~ ^[0-9]+$ ]]; then
  echo "SEMANTIC_INDEX_SLICE_LIMIT must be a non-negative integer, got '$slice_limit'" >&2
  exit 2
fi
if ! [[ "$start" =~ ^[0-9]+$ ]]; then
  echo "SEMANTIC_INDEX_START must be a non-negative integer, got '$start'" >&2
  exit 2
fi

mkdir -p "$out_dir"

while :; do
  if [[ "$slice_limit" -eq 0 ]]; then
    echo "semantic-index slice start=$start limit=all batch-size=$batch_size" >&2
  else
    echo "semantic-index slice start=$start limit=$slice_limit batch-size=$batch_size" >&2
  fi

  args=(
    "$repo"
    "$symbol_index"
    -o "$out_dir"
    --batch-size "$batch_size"
    --start "$start"
    --table "$table"
  )
  if [[ "$slice_limit" -gt 0 ]]; then
    args+=(--limit "$slice_limit")
  fi
  if [[ -n "$model" ]]; then
    args+=(--model "$model")
  fi

  python3 /opt/scripts/build_semantic_index.py "${args[@]}"

  if [[ ! -s "$out_dir/index.json" ]]; then
    echo "semantic-index did not write $out_dir/index.json" >&2
    exit 1
  fi

  read -r complete next_start total_chunks < <(
    python3 - "$out_dir/index.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
processed = data.get("slice_processed") or [0, 0]
print(
    "1" if data.get("complete") else "0",
    int(processed[1]),
    int(data.get("total_chunks_available") or 0),
)
PY
  )

  if [[ "$complete" == "1" ]]; then
    echo "semantic-index complete: $total_chunks chunks indexed" >&2
    break
  fi
  if [[ "$next_start" -le "$start" ]]; then
    echo "semantic-index made no forward progress at start=$start" >&2
    exit 1
  fi

  start=$next_start
done
