#!/usr/bin/env bash
# smoke-test.sh — prove the audit-codeql image works before pointing it at a target.
#   AUDIT_NATIVE_IMAGE=audit-codeql:local images/audit-native/run.sh . - ./scratch -- /opt/scripts/smoke-test.sh
set -euo pipefail
OUT=/scratch/codeql-smoke; rm -rf "$OUT"; mkdir -p "$OUT/src"; cd "$OUT"
echo "== 1. CLI";        codeql version | head -1
echo "== 2. languages"; codeql resolve languages | tr '\n' ' '; echo
echo "== 3. packs";     codeql resolve qlpacks | grep -E "codeql/(cpp|javascript|python)-queries" | head -3
echo "== 4. license basis: ${CODEQL_LICENSE_BASIS:-UNSET}"
cat > src/smoke.cpp <<'CPP'
#include <string.h>
#include <stdio.h>
unsigned char table[16];
unsigned char lookup(FILE* f) {
    unsigned char in[8]; fread(in, 1, sizeof in, f);
    char buf[8]; strcpy(buf, (char*)in);          // security-extended: unbounded write
    return table[in[0]];                          // tainted index
}
CPP
echo "== 5. database create (cpp, build-mode none)"
codeql database create db --language=cpp --source-root=src --build-mode=none > create.log 2>&1 && echo "   ok"
echo "== 6. analyze security-extended"
codeql database analyze db codeql/cpp-queries:codeql-suites/cpp-security-extended.qls --format=sarif-latest --output=smoke.sarif > analyze.log 2>&1
N=$(python3 -c "import json; print(sum(len(r['results']) for r in json.load(open('smoke.sarif'))['runs']))")
echo "   findings: $N"
python3 -c "import json; [print('   ', r['ruleId'], '|', r['message']['text'][:70]) for r in json.load(open('smoke.sarif'))['runs'][0]['results']]"
[ "$N" -ge 1 ] || { echo "FAIL: security-extended found nothing on a planted strcpy/tainted index"; exit 1; }
echo "smoke test complete -> $OUT"
