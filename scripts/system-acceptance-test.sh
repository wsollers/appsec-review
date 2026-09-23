#!/usr/bin/env bash
# System acceptance test (SAT): one fixture, from a fresh clone of the system under test through the
# full review cycle (SARIF and report generation). Built and run in stages so each can be looked at
# and refined on its own. Run on the POSIX host (WSL or native Linux) from the repository root.
#
#   scripts/system-acceptance-test.sh --list                     show the stages and which are built
#   scripts/system-acceptance-test.sh [--fixture hello-autotools] --through <stage>
#                                                                start a new SAT and run up to <stage>
#   scripts/system-acceptance-test.sh --resume <sat_id> --through <stage>
#                                                                continue an earlier SAT from its first
#                                                                stage that has not passed
#
# Every SAT has an id (UTC timestamp) and a record under
# appsec-review-process/logs/system-acceptance/<sat_id>/ (gitignored): sat.json (per-stage status and
# evidence) and one log per stage. A stage either PASSES with evidence or FAILS and stops the SAT;
# nothing is skipped silently. Stages marked "not built" stop the SAT with NOT_IMPLEMENTED.
# Windows: scripts/system-acceptance-test.ps1 runs this inside WSL.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAT_ROOT="$REPO/appsec-review-process/logs/system-acceptance"
PY="${PY:-$HOME/.venvs/appsec-review-dagster/bin/python}"

# Stage table: id|built(1/0)|what it proves. Order is the process flow (docs/processes/job-catalog.md).
STAGES=(
  "sut-checkout|1|Fresh clone of the fixture at its pinned commit; clean; no answer key on the branch"
  "services|0|Dagster services healthy; host code location serving; job list reloaded"
  "run-create|0|run_process.py --start creates the run and its folders"
  "stage-inputs|0|stage_artifacts.py writes a valid artifact manifest (executor platform posix)"
  "intake|0|00-intake accepted (phase1_intake)"
  "partition-discovery|0|Partition map supplied and accepted (repository_partition_discovery)"
  "dev-project-discovery|0|Project discovery supplied and accepted (dev_project_discovery)"
  "engagement-workflow|0|engagement_workflow: preparation branches and join published"
  "build-configure|0|02-build-configure through B13 in the pinned build image (needs Phase 3, 4, E01)"
  "native-build|0|02-native-build: compile database and build outputs"
  "evidence|0|Evidence jobs (SAST, SBOM/SCA, secrets, IaC, ...) accepted or explicitly skipped"
  "evidence-index|0|02-evidence-index accepted"
  "review-lanes|0|01 characterization through 09 verification, 11, 12"
  "sarif|0|critical_findings_sarif: accepted SARIF from verified findings"
  "report|0|10-synthesis-report: report generated"
)

die() { echo "SAT: $*" >&2; exit 1; }
stage_ids() { for s in "${STAGES[@]}"; do echo "${s%%|*}"; done; }
stage_field() { local id="$1" n="$2"; for s in "${STAGES[@]}"; do [[ "${s%%|*}" == "$id" ]] && { IFS='|' read -r -a f <<< "$s"; echo "${f[$n]}"; return; }; done; }

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }

list() {
  printf '%-24s %-9s %s\n' STAGE BUILT PROVES
  for s in "${STAGES[@]}"; do IFS='|' read -r id built what <<< "$s"; printf '%-24s %-9s %s\n' "$id" "$([[ $built == 1 ]] && echo yes || echo 'not yet')" "$what"; done
}

# ---- record keeping ------------------------------------------------------------------------------
# sat.json is rewritten through python (json-safe) after every stage.
record() {  # record <status> <stage> <json-evidence>
  python3 - "$SAT_DIR/sat.json" "$1" "$2" "$3" <<'EOF'
import json, sys, datetime
path, status, stage, evidence = sys.argv[1:]
data = json.load(open(path))
data['stages'][stage] = {'status': status, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                         'evidence': json.loads(evidence) if evidence else {}}
json.dump(data, open(path, 'w'), indent=1)
EOF
}
stage_status() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stages"].get(sys.argv[2],{}).get("status",""))' "$SAT_DIR/sat.json" "$1"; }
sat_get() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$SAT_DIR/sat.json" "$1"; }

# ---- fixtures ------------------------------------------------------------------------------------
# name -> origin and pin come from fixtures/populate-targets.sh, the single source of the pin.
fixture_entry() {
  local line; line="$(grep -E "^[[:space:]]*\"$1\|" "$REPO/fixtures/populate-targets.sh" | head -1 | tr -d ' "')"
  [[ -n "$line" ]] || die "fixture '$1' is not listed in fixtures/populate-targets.sh"
  echo "$line"
}

# ---- stage 1: sut-checkout -----------------------------------------------------------------------
stage_sut_checkout() {
  local name url pin dest
  IFS='|' read -r name url pin <<< "$(fixture_entry "$FIXTURE")"
  dest="$REPO/fixtures/targets/$name"

  # Start from nothing. Only a clean clone of the expected origin is removed; anything else is
  # refused and left for a human, the same rule populate-targets.sh applies.
  if [[ -e "$dest" ]]; then
    [[ -d "$dest/.git" ]] || die "sut-checkout: $dest exists and is not a git clone; move it aside"
    local have; have="$(git -C "$dest" remote get-url origin)"
    [[ "$have" == "$url" ]] || die "sut-checkout: $dest has origin $have, expected $url; refusing to delete"
    [[ -z "$(git -C "$dest" status --porcelain --untracked-files=all)" ]] \
      || die "sut-checkout: $dest has local changes; refusing to delete (inspect it first)"
    echo "removing existing clean clone $dest"
    rm -rf -- "$dest"
  fi

  "$REPO/fixtures/populate-targets.sh" "$name"

  # Acceptance checks on the fresh clone.
  local head status tree answer_key comments
  head="$(git -C "$dest" rev-parse HEAD)"
  [[ "$head" == "$pin" ]] || die "sut-checkout: HEAD $head, expected pin $pin"
  status="$(git -C "$dest" status --porcelain --untracked-files=all)"
  [[ -z "$status" ]] || die "sut-checkout: fresh clone is not clean"
  [[ "$(git -C "$dest" remote get-url origin)" == "$url" ]] || die "sut-checkout: origin mismatch after clone"
  tree="$(git -C "$dest" rev-parse "HEAD^{tree}")"
  # The answer key must not be on the reviewed revision (it lives on with-vulnerabilities-doc), and
  # the source must carry no defect-identifying comments; otherwise the SAT measures recall of the
  # fixture's own notes instead of detection.
  answer_key="$( [[ -e "$dest/docs/VULNERABILITIES.md" ]] && echo present || echo absent )"
  [[ "$answer_key" == absent ]] || die "sut-checkout: docs/VULNERABILITIES.md is present on the pinned revision"
  comments="$(grep -rnE 'VULN|CWE-[0-9]+' "$dest/src" 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$comments" == 0 ]] || die "sut-checkout: $comments defect-identifying comment(s) in src/"
  local files; files="$(git -C "$dest" ls-files | wc -l | tr -d ' ')"

  record PASS sut-checkout "$(python3 -c 'import json,sys; print(json.dumps(dict(zip(["fixture","path","origin","pin","head","tree","tracked_files","answer_key","defect_comments_in_src"], sys.argv[1:]))))' \
    "$name" "fixtures/targets/$name" "$url" "$pin" "$head" "$tree" "$files" "$answer_key" "$comments")"
  echo "sut-checkout: PASS  $name at ${head:0:7} (tree ${tree:0:7}, $files tracked files, clean, no answer key)"
}

# ---- driver --------------------------------------------------------------------------------------
FIXTURE=hello-autotools; THROUGH=""; RESUME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) list; exit 0 ;;
    --fixture) FIXTURE="$2"; shift 2 ;;
    --through) THROUGH="$2"; shift 2 ;;
    --resume) RESUME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument $1" ;;
  esac
done
[[ -n "$THROUGH" ]] || { usage >&2; die "--through <stage> is required (see --list)"; }
stage_ids | grep -qx "$THROUGH" || die "unknown stage '$THROUGH' (see --list)"
[[ "$(uname -s)" == Linux ]] || die "run on the POSIX host (WSL or Linux); on Windows use scripts/system-acceptance-test.ps1"

if [[ -n "$RESUME" ]]; then
  SAT_DIR="$SAT_ROOT/$RESUME"; [[ -f "$SAT_DIR/sat.json" ]] || die "no SAT record $SAT_DIR/sat.json"
  FIXTURE="$(sat_get fixture)"
else
  SAT_ID="$(date -u +%Y%m%dT%H%M%SZ)"; SAT_DIR="$SAT_ROOT/$SAT_ID"; mkdir -p "$SAT_DIR"
  python3 - "$SAT_DIR/sat.json" "$SAT_ID" "$FIXTURE" "$(git -C "$REPO" rev-parse HEAD)" <<'EOF'
import json, sys
path, sat_id, fixture, repo_head = sys.argv[1:]
json.dump({'schema': 'appsec-review/system-acceptance/1', 'sat_id': sat_id, 'fixture': fixture,
           'repo_commit': repo_head, 'run_id': None, 'stages': {}}, open(path, 'w'), indent=1)
EOF
fi
echo "SAT $(sat_get sat_id)  fixture $FIXTURE  record ${SAT_DIR#$REPO/}"

for id in $(stage_ids); do
  if [[ "$(stage_status "$id")" == PASS ]]; then
    echo "$id: already PASS in this SAT"
  elif [[ "$(stage_field "$id" 1)" != 1 ]]; then
    record NOT_IMPLEMENTED "$id" ""
    echo "$id: NOT_IMPLEMENTED -- stage not built yet; SAT stops here"; exit 3
  else
    fn="stage_${id//-/_}"
    echo "== $id: $(stage_field "$id" 2)"
    if ! ( set -o pipefail; "$fn" 2>&1 | tee "$SAT_DIR/$id.log" ); then
      record FAIL "$id" "{\"log\": \"$id.log\"}"
      echo "$id: FAIL (log ${SAT_DIR#$REPO/}/$id.log)"; exit 1
    fi
  fi
  [[ "$id" == "$THROUGH" ]] && { echo "SAT $(sat_get sat_id): PASS through $THROUGH"; exit 0; }
done
