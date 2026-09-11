#!/usr/bin/env bash
# build.sh — compile svf-taint inside audit-native (SVF_DIR/LLVM_DIR/Z3_DIR are set there).
#   images/audit-native/run.sh . - ./scratch -- bash /workspace/images/audit-native/svf-taint/build.sh /scratch/svf-taint-build
# The binary lands in <builddir>/svf-taint. Once it compiles cleanly, bake this into the
# Dockerfile as a layer after SVF so it ships in the image.
set -euo pipefail
B=${1:?build dir}; SRC=$(cd "$(dirname "$0")" && pwd)
cmake -S "$SRC" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR="$LLVM_DIR/lib/cmake/llvm" -DSVF_DIR="$SVF_DIR" -DZ3_DIR="$Z3_DIR" 2>&1 | tail -5
cmake --build "$B" -j"$(nproc)" 2>&1 | grep -E "error|warning: unused|Linking|svf-taint" | head -40
ls -la "$B/svf-taint" && echo "BUILD OK"
