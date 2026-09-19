#!/usr/bin/env bash
# Evidence-first PE/ELF/debug-symbol triage helper.
set -euo pipefail

TARGET=${1:?usage: analyze-binary <file> [output-dir]}
OUT=${2:-"/scratch/binary-analysis/$(basename "$TARGET")"}
mkdir -p "$OUT"

sha256sum "$TARGET" > "$OUT/sha256.txt"
file "$TARGET" > "$OUT/file.txt"
strings -a -n 6 "$TARGET" > "$OUT/strings.txt" || true
objdump -x "$TARGET" > "$OUT/objdump-x.txt" 2>&1 || true
objdump -d "$TARGET" > "$OUT/objdump-disassembly.txt" 2>&1 || true
nm -an "$TARGET" > "$OUT/nm-symbols.txt" 2>&1 || true
readelf -aW "$TARGET" > "$OUT/readelf-all.txt" 2>&1 || true
eu-readelf -a "$TARGET" > "$OUT/eu-readelf-all.txt" 2>&1 || true
dwarfdump "$TARGET" > "$OUT/dwarfdump.txt" 2>&1 || true
pahole "$TARGET" > "$OUT/pahole.txt" 2>&1 || true
scanelf -a "$TARGET" > "$OUT/scanelf.txt" 2>&1 || true
checksec --file="$TARGET" > "$OUT/checksec.txt" 2>&1 || true
binwalk "$TARGET" > "$OUT/binwalk.txt" 2>&1 || true
retdec-fileinfo "$TARGET" > "$OUT/retdec-fileinfo.txt" 2>&1 || true
ssdeep "$TARGET" > "$OUT/ssdeep.txt" 2>&1 || true
tlsh -f "$TARGET" > "$OUT/tlsh.txt" 2>&1 || true
diec -j "$TARGET" > "$OUT/die.json" 2>&1 || diec "$TARGET" > "$OUT/die.txt" 2>&1 || true
llvm-readobj --file-headers --sections --symbols --relocations "$TARGET" > "$OUT/llvm-readobj.txt" 2>&1 || true
llvm-objdump -d --syms "$TARGET" > "$OUT/llvm-objdump.txt" 2>&1 || true
/opt/binary-analysis-venv/bin/capa -q "$TARGET" > "$OUT/capa.txt" 2>&1 || true
binary-summary "$TARGET" > "$OUT/summary.json"

if [ -n "${YARA_RULES:-}" ]; then
  yara --print-meta --print-strings "$YARA_RULES" "$TARGET" > "$OUT/yara-matches.txt" 2>&1 || true
fi

if [ "${RUN_GHIDRA:-0}" = "1" ]; then
  mkdir -p "$OUT/ghidra-project"
  ghidra-analyzeHeadless "$OUT/ghidra-project" binary-analysis \
    -import "$TARGET" \
    -overwrite \
    -analysisTimeoutPerFile "${GHIDRA_TIMEOUT_SECONDS:-120}" \
    > "$OUT/ghidra-headless.txt" 2>&1 || true
fi

if [ "${RUN_ANGR:-0}" = "1" ]; then
  angr-summary "$TARGET" > "$OUT/angr-cfg-summary.json" 2> "$OUT/angr-cfg-summary.stderr" || true
fi

if [ "${RUN_FLOSS:-0}" = "1" ]; then
  floss --json "$TARGET" > "$OUT/floss.json" 2> "$OUT/floss.stderr" || true
fi

if [ "${RUN_RETDEC:-0}" = "1" ]; then
  mkdir -p "$OUT/retdec"
  retdec-decompiler "$TARGET" \
    --output "$OUT/retdec/decompiled.c" \
    > "$OUT/retdec-decompiler.txt" 2>&1 || true
fi

if [ "${RUN_CWE_CHECKER:-0}" = "1" ]; then
  cwe_checker "$TARGET" > "$OUT/cwe-checker.txt" 2>&1 || true
fi

if [ "${RUN_SBOM_TOOLS:-0}" = "1" ]; then
  syft "$TARGET" -o syft-json > "$OUT/syft.json" 2> "$OUT/syft.stderr" || true
  syft "$TARGET" -o cyclonedx-json > "$OUT/sbom.cdx.json" 2> "$OUT/sbom.cdx.stderr" || true
  grype "$TARGET" -o json > "$OUT/grype.json" 2> "$OUT/grype.stderr" || true
  trivy fs --scanners vuln,secret --format json --output "$OUT/trivy.json" "$TARGET" > "$OUT/trivy.stdout" 2> "$OUT/trivy.stderr" || true
fi

if [ "${RUN_JADX:-0}" = "1" ]; then
  mkdir -p "$OUT/jadx"
  jadx --show-bad-code --output-dir "$OUT/jadx" "$TARGET" > "$OUT/jadx.txt" 2>&1 || true
fi

if [ "${RUN_ILSPY:-0}" = "1" ]; then
  mkdir -p "$OUT/ilspy"
  ilspycmd -p -o "$OUT/ilspy" "$TARGET" > "$OUT/ilspycmd.txt" 2>&1 || true
fi

cat <<EOF
binary analysis complete
target: $TARGET
output: $OUT
EOF
