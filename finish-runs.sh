#!/usr/bin/env bash
# finish-runs.sh — complete the open L3 runs on Notepad++ and push.
#   ./finish-runs.sh            # everything
#   ./finish-runs.sh ctu        # only that step (steps: sync build ctu eh svf record push)
set -euo pipefail
cd "$(dirname "$0")"
LOG=runs/finish-$(date +%Y%m%d-%H%M).log; mkdir -p runs
exec > >(tee -a "$LOG") 2>&1
step() { echo; echo "################ [$1] $(date +%T)"; }
NPP6=$HOME/projects/npp-8.5.6; NPP7=$HOME/projects/npp-8.5.7
R6="images/audit-native/run.sh $NPP6 ./msvc ./scratch-npp --"
R7="images/audit-native/run.sh $NPP7 ./msvc ./scratch-npp857 --"
CVE='Utf8_16|uchardet|Buffer\.cpp'
MEM=$(( $(free -g | awk '/^Mem/{print $2}') - 4 ))g
want() { [ $# -eq 0 ] || [[ " $* " == *" $STEP "* ]]; }
STEP=sync;  if want "$@"; then step "sync: install next.zip contents if present"
  Z=$(ls -t ~/Downloads/next*.zip 2>/dev/null | head -1 || true)
  if [ -n "$Z" ]; then rm -rf /tmp/next && unzip -qo "$Z" -d /tmp/next
    cp /tmp/next/next/run_csa.py /tmp/next/next/taint-win32.yaml images/audit-native/scripts/
    cp /tmp/next/next/README.md images/audit-native/README.md
    cp /tmp/next/next/notepad-plus-plus-8.5.6.md validation/
    mkdir -p images/audit-native/svf-taint && cp /tmp/next/next/svf-taint/* images/audit-native/svf-taint/
    S=$(ls -t ~/Downloads/svf-taint*.cpp 2>/dev/null | head -1 || true); [ -n "$S" ] && cp "$S" images/audit-native/svf-taint/svf-taint.cpp
  fi
  echo "run_csa --ctu: $(grep -c -- '--ctu' images/audit-native/scripts/run_csa.py)  taint yaml: $(test -f images/audit-native/scripts/taint-win32.yaml && echo yes || echo NO)"
  echo "svf-taint ptr-only: $(grep -c ptr-only images/audit-native/svf-taint/svf-taint.cpp 2>/dev/null || echo 0)  validation record: $(test -f validation/notepad-plus-plus-8.5.6.md && echo yes || echo NO)"
fi
STEP=build; if want "$@"; then step "build image"
  docker build -q -t audit-native:local images/audit-native
fi
STEP=ctu;   if want "$@"; then step "CSA cross-TU + Win32 taint on CVE TUs, both versions"
  for V in 8.5.6:scratch-npp 8.5.7:scratch-npp857; do ver=${V%%:*}; scr=${V##*:}
    rm -rf $scr/csa-ctu
    images/audit-native/run.sh $HOME/projects/npp-$ver ./msvc ./$scr -- /opt/scripts/run_csa.py \
      --compile-commands /scratch/compile_commands.json --out /scratch/csa-ctu --filter "$CVE" --alpha --ctu
    echo "--- findings v$ver:"
    python3 -c "
import json; [print('  ', f['checker'], f['file'].split('/')[-1]+':'+str(f['line']), '|', f['message'][:100]) for f in json.load(open('$scr/csa-ctu/findings-csa.json'))]"
  done
  echo "--- diff:"
  python3 images/audit-native/scripts/diff_findings.py --before scratch-npp/csa-ctu/findings-csa.json \
    --after scratch-npp857/csa-ctu/findings-csa.json --filter "$CVE" --out scratch-npp857/cve-diff-ctu.json
fi
STEP=eh;    if want "$@"; then step "funclet EH instructions in the linked module (SVF assertion hypothesis)"
  $R6 bash -c 'llvm-dis /scratch/linked/PowerEditor__visual.net__notepadPlus.bc -o - | grep -cE "^\s+(%[^ ]+ = )?(catchswitch|catchpad|cleanuppad|catchret|cleanupret|landingpad)" || true'
fi
STEP=svf;   if want "$@"; then step "svf-taint: build, full SVFG attempt, ptr-only fallback"
  images/audit-native/run.sh . - ./scratch -- bash /workspace/images/audit-native/svf-taint/build.sh /scratch/svf-taint-build
  cp scratch/svf-taint-build/svf-taint scratch-npp/svf-taint
  $R6 bash -c 'test -f /scratch/linked/npp.m2r.bc || opt -passes=mem2reg /scratch/linked/PowerEditor__visual.net__notepadPlus.bc -o /scratch/linked/npp.m2r.bc'
  for MODE in full ptr-only; do
    FLAG=""; [ $MODE = ptr-only ] && FLAG="-ptr-only"
    echo "--- svf-taint $MODE (MEM_LIMIT=$MEM)"
    MEM_LIMIT=$MEM $R6 bash -c "/scratch/svf-taint $FLAG -sources=ReadFile:1,MapViewOfFile:-1 -taint-verbose \
        -out=/scratch/svf-taint-$MODE.json /scratch/linked/npp.m2r.bc > /scratch/svf-taint-$MODE.log 2>&1; echo exit=\$?" || true
    grep -E "svf-taint:|source |iter |Assert|Killed" scratch-npp/svf-taint-$MODE.log | tail -6 || true
    if [ -f scratch-npp/svf-taint-$MODE.json ]; then python3 -c "
import json; r=json.load(open('scratch-npp/svf-taint-$MODE.json'))
print('  svfg', r['svfg'], '| sources', r['sources_seen'], '| tainted values', r['tainted_values'], '| objects', r['tainted_objects'], '| candidates', r['findings_total'])
for s in r['sources']: print('   SRC', s['name'], s['arg'], s['loc'][:70], '|', s['function'][:50])
hits=[f for f in r['findings'] if any(k in f['sink_loc'] for k in ('Utf8_16','CharDistribution','nsCodingStateMachine','Buffer.cpp'))]
print('  candidates at CVE files:', len(hits))
for f in hits[:30]: print('   ', f['kind'], f['sink_loc'][:60], '|', f['sink_function'][:40], '|', f['base_kind'], f['base_object'][:30], f['base_bytes'])"; break; fi
  done
fi
STEP=record; if want "$@"; then step "append raw results to validation record"
  { echo; echo "## Run log $(date +%F) (finish-runs.sh)"; echo; echo '```'
    grep -A40 "CSA cross-TU" "$LOG" | grep -E "findings v|^  |REMOVED|ADDED|before:" | head -40
    grep -A3 "funclet EH" "$LOG" | tail -1 | sed 's/^/funclet EH instructions: /'
    grep -E "svfg |candidates at CVE|Assert|exit=" "$LOG" | tail -6
    echo '```'; } >> validation/notepad-plus-plus-8.5.6.md
fi
STEP=push;  if want "$@"; then step "commit + push"
  git add -A && git commit -qm "L3 runs $(date +%F): CTU+taint on CVE TUs, svf-taint acceptance attempt (see validation record)" && git push
  git log --oneline -1
fi
echo; echo "done -> $LOG"
