#!/usr/bin/env bash
#   images/audit-native/run.sh . - ./scratch -- bash /workspace/images/audit-native/ir-facts/build.sh /scratch/ir-facts-build
set -euo pipefail
B=${1:?build dir}; SRC=$(cd "$(dirname "$0")" && pwd)
cmake -S "$SRC" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" 2>&1 | tail -2
cmake --build "$B" -j"$(nproc)" 2>&1 | grep -E "error|Linking|ir-facts" | head -30
ls -la "$B/ir-facts" && echo "BUILD OK"
