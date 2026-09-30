#!/usr/bin/env bash
# smoke_reverse_tools.sh IMAGE_ID            (inside the image)
# smoke_reverse_tools.sh --docker IMAGE_ID   (from the repo root on the host)
#
# Proves Ghidra and x64dbg (under Wine) in audit-binary-analysis and audit-native. With --docker the
# image runs inside its own boundary wrapper, the repository mounted read-only at /workspace and
# scratch/reverse-smoke/IMAGE writable at /scratch, no network:
#
#   audit-binary-analysis: images/audit-buildenv-common/run.sh audit-binary-analysis:local . SCRATCH -- ...
#   audit-native:          images/audit-native/run.sh . - SCRATCH -- ...
#
# Checks: pinned Ghidra and JDK versions; ghidra-analyzeHeadless imports and analyzes a hello ELF built
# from images/test/binary/hello.c (exit 0, non-empty project); wine --version; the per-uid Wine prefix
# (wrapper --prepare runs wineboot); the pinned hashes of the x64dbg executables; x64dbg and x32dbg
# headless start and exit on "exit" within 60 s; x96dbg picks the right arch for a PE32 and a PE32+.
# One line per check: PASS, FAIL or INFO. Exit status 1 if any check FAILs.
set -uo pipefail

if [ "${1:-}" = "--docker" ]; then
  image=${2:?usage: $0 --docker IMAGE_ID}
  repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  scratch="$repo/scratch/reverse-smoke/$image"
  mkdir -p "$scratch"
  tag=${SMOKE_IMAGE_TAG:-$image:local}
  echo "INFO image-size                         $(docker image inspect -f '{{.Size}}' "$tag" | awk '{printf "%.0f MB", $1/1000000}') ($tag)"
  case "$image" in
    audit-binary-analysis)
      exec bash "$repo/images/audit-buildenv-common/run.sh" "$tag" "$repo" "$scratch" -- \
        bash /workspace/scripts/smoke_reverse_tools.sh "$image" ;;
    audit-native)
      AUDIT_NATIVE_IMAGE=$tag exec bash "$repo/images/audit-native/run.sh" "$repo" - "$scratch" -- \
        bash /workspace/scripts/smoke_reverse_tools.sh "$image" ;;
    *) echo "unknown image id: $image" >&2; exit 2 ;;
  esac
fi

image=${1:?usage: $0 IMAGE_ID | --docker IMAGE_ID}
REPO=${SMOKE_REPO:-/workspace}
OUT=${SMOKE_OUT:-/scratch/reverse-smoke}
failures=0
report() {  # STATUS NAME DETAIL
  printf '%-4s %-34s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && failures=$((failures + 1))
  return 0
}

case "$image" in
  audit-binary-analysis) wine_want="wine-8.0 (Debian 8.0~repack-4)"; jdk=/opt/java ;;
  audit-native) wine_want="wine-9.0 (Ubuntu 9.0~repack-4build3)"; jdk=/opt/ghidra-jdk ;;
  *) echo "unknown image id: $image" >&2; exit 2 ;;
esac
rm -rf "$OUT"; mkdir -p "$OUT"
export HOME=${HOME:-/tmp/home}
echo "== $image reverse-engineering tools smoke ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

# --- Ghidra ------------------------------------------------------------------------------------
version=$(sed -n 's/^application.version=//p' /opt/ghidra/Ghidra/application.properties 2>/dev/null)
if [ "$version" = 12.1.3 ]; then report PASS ghidra-version "$version"
else report FAIL ghidra-version "application.version '$version' (want 12.1.3)"; fi
java_version=$("$jdk/bin/java" -version 2>&1 | grep -v "^Picked up" | head -1)
case "$java_version" in
  *'"21.0.12"'*) report PASS ghidra-jdk "$jdk: $java_version" ;;
  *) report FAIL ghidra-jdk "$jdk: '$java_version' (want 21.0.12)" ;;
esac
if gcc -g -O0 "$REPO/images/test/binary/hello.c" -o "$OUT/hello" 2>"$OUT/gcc.log"; then
  mkdir -p "$OUT/ghidra"
  timeout 900 ghidra-analyzeHeadless "$OUT/ghidra" smoke -import "$OUT/hello" >"$OUT/ghidra.log" 2>&1
  status=$?
  if [ "$status" -eq 0 ] && [ -f "$OUT/ghidra/smoke.gpr" ] && [ -n "$(find "$OUT/ghidra/smoke.rep" -type f 2>/dev/null | head -1)" ] \
       && grep -q "Analysis succeeded" "$OUT/ghidra.log"; then
    report PASS ghidra-analyzeHeadless "hello imported and analyzed ($(du -sk "$OUT/ghidra" | cut -f1) KB project)"
  else report FAIL ghidra-analyzeHeadless "exit $status; see $OUT/ghidra.log"; fi
else
  report FAIL ghidra-analyzeHeadless "gcc could not build hello: $(tail -1 "$OUT/gcc.log")"
fi

# --- Wine and x64dbg ---------------------------------------------------------------------------
wine_version=$(timeout 60 wine --version 2>&1)
if [ "$wine_version" = "$wine_want" ]; then report PASS wine-version "$wine_version"
else report FAIL wine-version "'$wine_version' (want '$wine_want')"; fi
export X64DBG_RUNTIME_DIR="$OUT/x64dbg-runtime"
if prefix=$(timeout 180 x64dbg --prepare 2>"$OUT/prepare.log") && [ -f "$prefix/system.reg" ]; then
  report PASS wine-prefix "$prefix (wineboot ok)"
else report FAIL wine-prefix "see $OUT/prepare.log"; fi
report INFO x64dbg-version "$(x64dbg --version 2>&1)"
while read -r want file; do
  got=$(sha256sum "/opt/x64dbg/release/$file" 2>/dev/null | cut -d' ' -f1)
  if [ "$got" = "$want" ]; then report PASS "sha256:$file" "${got:0:16}..."
  else report FAIL "sha256:$file" "'${got:-missing}' (want $want)"; fi
done <<'HASHES'
7473d96b13c350643fc8f471a2e840494f8ab771b35e3e316ebf8a66660df158 x96dbg.exe
68d6afc2cc5a5bfd74a1b4066c0651254661355a0e384524cd1a8772adb95092 x64/x64dbg.exe
822028f0755dba773e445eaf57fdb3dba84c9550ac7bdad2afa449912b5fba41 x32/x32dbg.exe
44ece2d8f81c1acbf4c85b45fe89e11875f0e1a0d2ba0c8c8c1a56bf85164268 x64/headless.exe
28e05e36462a74e5561c45377d417058c2c6a3cf0f27bb0bda1f47ee1763de65 x32/headless.exe
HASHES
for tool in x64dbg x32dbg; do
  printf 'exit\n' | timeout 60 "$tool" >"$OUT/$tool-headless.log" 2>&1
  status=$?
  if [ "$status" -eq 0 ] && grep -q "entering command loop" "$OUT/$tool-headless.log"; then
    report PASS "$tool-headless" "started, command loop, exit 0"
  else report FAIL "$tool-headless" "exit $status (124 = hung); see $OUT/$tool-headless.log"; fi
done
which64=$(x96dbg --which /opt/x64dbg/release/x64/x64dbg.exe 2>&1)
which32=$(x96dbg --which /opt/x64dbg/release/x32/x32dbg.exe 2>&1)
if [ "$which64" = x64 ] && [ "$which32" = x32 ]; then report PASS x96dbg-arch "PE32+ -> x64, PE32 -> x32"
else report FAIL x96dbg-arch "got '$which64' and '$which32'"; fi

echo "== $image: $failures failure(s); logs under $OUT"
[ "$failures" -eq 0 ]
