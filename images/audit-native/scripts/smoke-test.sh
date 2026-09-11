#!/usr/bin/env bash
# smoke-test.sh — prove the image can compile a trivial Win32 TU against the
# mounted MSVC headers, emit LLVM bitcode, and run SVF + CSA + Joern on it.
# Runs inside audit-native with network off. Writes only to /scratch.
set -euo pipefail
MSVC=${MSVC_ROOT:-/msvc}
OUT=/scratch/smoke; mkdir -p "$OUT"; cd "$OUT"
COMPAT=${TOOLSET_COMPAT:-19.44}
TARGET=${TARGET:-x86_64-pc-windows-msvc}

cat > hello.cpp <<'CPP'
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
struct Msg { unsigned short len; char body[64]; };
static int parse(const unsigned char* p, size_t n) {
    if (n < 2) return -1;
    Msg m; m.len = *(const unsigned short*)p;
    memcpy(m.body, p + 2, m.len);          // unchecked length: CSA/SVF must see this
    return m.body[0];
}
int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    unsigned char buf[4] = {0xff, 0x00, 'a', 'b'};
    std::string s("smoke");
    printf("%s %d\n", s.c_str(), parse(buf, sizeof buf));
    return 0;
}
CPP

echo "== 1. clang-cl syntax-only against $MSVC"
if [ -d "$MSVC/crt/include" ]; then
  MSVC_FLAGS=(-imsvc "$MSVC/crt/include" -imsvc "$MSVC/sdk/include/ucrt" -imsvc "$MSVC/sdk/include/um" -imsvc "$MSVC/sdk/include/shared")
elif [ -d "$MSVC/VC" ]; then
  MSVC_FLAGS=(/winsysroot "$MSVC")
else
  MSVC_FLAGS=()
fi
if [ ${#MSVC_FLAGS[@]} -gt 0 ]; then
  clang-cl /c /nologo --target=$TARGET -fms-compatibility-version=$COMPAT "${MSVC_FLAGS[@]}" -fsyntax-only hello.cpp
  echo "   ok"
  echo "== 2. emit LLVM bitcode"
  clang-cl /c /nologo --target=$TARGET -fms-compatibility-version=$COMPAT "${MSVC_FLAGS[@]}" \
      -emit-llvm -g -O0 -Xclang -disable-O0-optnone /Fohello.bc hello.cpp
  llvm-dis hello.bc -o hello.ll && grep -q 'define' hello.ll && echo "   ok ($(wc -l < hello.ll) lines IR)"
  echo "== 3. SVF Andersen points-to on the bitcode"
  wpa -ander -stat=false hello.bc > wpa.log 2>&1 && echo "   ok" || { echo "   wpa failed:"; tail -5 wpa.log; }
  echo "== 4. Clang Static Analyzer"
  clang-cl /c /nologo --target=$TARGET -fms-compatibility-version=$COMPAT "${MSVC_FLAGS[@]}" \
      --analyze -Xclang -analyzer-output=text hello.cpp > csa.log 2>&1 || true
  grep -c "warning:" csa.log | xargs echo "   CSA warnings:"
else
  echo "   /msvc not populated (no crt/include or VC/): skipping clang-cl steps. Run scripts/fetch-msvc-xwin.sh on a networked host."
fi

echo "== 5. Joern parse (no build needed)"
joern-parse hello.cpp --output hello.cpg.bin > joern.log 2>&1 && [ -s hello.cpg.bin ] && echo "   ok ($(stat -c%s hello.cpg.bin) bytes)"
echo "== 6. cppcheck"
cppcheck --quiet --error-exitcode=0 --enable=warning hello.cpp 2>&1 | head -3 || true
echo "== 7. tool versions"
{ clang-cl --version | head -1; clang-tidy --version | grep -m1 version; cppcheck --version; joern --version 2>/dev/null | head -1 || echo "joern $(basename $(readlink -f /opt/joern-cli))"; CodeChecker version 2>/dev/null | grep -m1 -i "base package" || true; xwin --version; } | tee versions.txt
echo "smoke test complete -> $OUT"
