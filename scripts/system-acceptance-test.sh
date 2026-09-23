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
  "services|1|Dagster services healthy; host code location serving; job list reloaded"
  "run-create|1|run_process.py --start creates the run and its folders"
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
sat_get() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print("" if v is None else v)' "$SAT_DIR/sat.json" "$1"; }
sat_set() { python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d[sys.argv[2]]=sys.argv[3]; json.dump(d, open(p,"w"), indent=1)' "$SAT_DIR/sat.json" "$1" "$2"; }

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

# ---- stage 2: services ---------------------------------------------------------------------------
# Brings up this project's own Compose services (idempotent; recreates webserver/daemon if the code
# location address changed) and checks the host code location, which runs in the foreground in its
# own terminal and is therefore checked, not started.
SAT_REQUIRED_JOBS="phase1_intake repository_partition_discovery dev_project_discovery engagement_workflow full_review"

graphql() {  # graphql <query> -> the response's "data" as JSON on stdout
  python3 -c '
import json, sys, urllib.request
req = urllib.request.Request("http://127.0.0.1:3000/graphql", data=json.dumps({"query": sys.argv[1]}).encode(),
                             headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as r:
    body = json.load(r)
if body.get("errors"):
    sys.exit("graphql errors: " + json.dumps(body["errors"]))
print(json.dumps(body["data"]))' "$1"
}

compose_states() {  # "postgres=running/healthy daemon=... webserver=..."
  "${COMPOSE[@]}" ps --format json | python3 -c '
import json, sys
text = sys.stdin.read().strip()
rows = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
print(" ".join("%s=%s/%s" % (r["Service"], r.get("State"), r.get("Health") or "-") for r in sorted(rows, key=lambda r: r["Service"])))'
}

stage_services() {
  local dagster="$REPO/orchestrator/dagster" cl="$REPO/orchestrator/dagster/code-location.sh"
  COMPOSE=(docker compose -f "$dagster/compose.yaml")

  # 1. Docker engine answers.
  local engine rc=0 why
  command -v docker >/dev/null || die "services: no 'docker' command in this shell (Docker Desktop WSL integration off for this distro?)"
  engine="$(timeout ${SAT_DOCKER_TIMEOUT:-60} docker version --format '{{.Server.Version}}' 2>&1)" || rc=$?
  if [[ $rc != 0 || -z "$engine" ]]; then
    case $rc in
      124) why="'docker version' hung and was stopped after ${SAT_DOCKER_TIMEOUT:-60} s (the engine is not responding)" ;;
      0)   why="'docker version' returned no server version" ;;
      *)   why="'docker version' exited $rc: ${engine:-no output}" ;;
    esac
    die "services: Docker engine not answering: $why.
  Check: docker version; docker info. If it hangs or fails: stop the code location (Ctrl+C),
  'wsl --shutdown' from Windows, restart Docker Desktop and wait until it reports running, then
  orchestrator/dagster/code-location.sh start (own terminal) and re-run this stage."
  fi
  # One engine only: a native dockerd in the distro competes with Docker Desktop's WSL integration
  # for /var/run/docker.sock, which is how the engine wedged on 2026-09-23 (500 on /version).
  local engine_os
  engine_os="$(timeout 30 docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
  if [[ "$engine_os" == "Docker Desktop" ]] && systemctl is-active --quiet docker 2>/dev/null; then
    die "services: Docker Desktop answers, but a native docker service is also active in this distro; they
  compete for /var/run/docker.sock. Run: sudo systemctl disable --now docker.service docker.socket containerd.service"
  fi
  engine="$engine ($engine_os)"
  echo "docker engine $engine"

  # 2. Settings exist, and the code location address in .env matches this WSL boot.
  [[ -f "$dagster/.env" ]] || die "services: $dagster/.env missing; run: python3 orchestrator/dagster/setup.py"
  local env_host wsl_ip=""
  env_host="$(sed -n 's/^APPSEC_CODE_LOCATION_HOST=//p' "$dagster/.env" | tr -d '\r')"
  if [[ "$(wslinfo --networking-mode 2>/dev/null)" == nat ]]; then
    wsl_ip="$(ip -4 -o addr show dev eth0 | awk '{split($4,a,"/"); print a[1]; exit}')"
    [[ "$env_host" == "$wsl_ip" ]] || die "services: .env APPSEC_CODE_LOCATION_HOST=${env_host:-unset}, but this WSL boot's IP is $wsl_ip.
  Restart the code location (orchestrator/dagster/code-location.sh start) so it rewrites .env, then re-run."
  fi

  # 3. This project's Compose services up and healthy. 'up -d' is idempotent and recreates
  #    webserver/daemon when the code location address changed.
  "${COMPOSE[@]}" up -d
  local deadline=$((SECONDS + 240)) states svc ok
  while :; do
    states="$(compose_states)"; ok=1
    for svc in postgres webserver daemon; do [[ " $states " == *" $svc=running/healthy "* ]] || ok=0; done
    [[ $ok == 1 ]] && break
    (( SECONDS < deadline )) || die "services: not healthy after 240 s: $states"
    sleep 5
  done
  echo "compose: $states"

  # 4. The webserver maps host.docker.internal to the code location's address. Docker Desktop also
  #    adds its own (often IPv6) host-gateway entry for that name, so the check is that the address
  #    is among the name's IPv4 answers; step 5's reload is what proves the webserver reaches it.
  local resolved
  resolved="$("${COMPOSE[@]}" exec -T webserver getent ahostsv4 host.docker.internal | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//')"
  if [[ -n "$wsl_ip" && " $resolved " != *" $wsl_ip "* ]]; then
    die "services: in the webserver, host.docker.internal resolves (IPv4) to ${resolved:-nothing}, not the code location at $wsl_ip; run: ${COMPOSE[*]} up -d --force-recreate webserver daemon"
  fi
  echo "webserver: host.docker.internal (IPv4) -> $resolved"

  # 5. Host code location serving (gRPC health); the webserver then reloads the current job code.
  "$cl" check >/dev/null 2>&1 || die "services: host code location not answering on port 4000.
  Start it in its own terminal: orchestrator/dagster/code-location.sh start (wait for 'Started'), then re-run."
  echo "code location: gRPC health OK"
  local reload
  reload="$("$cl" reload 2>&1)" || die "services: reload failed: $reload"
  echo "$reload"
  [[ "$reload" == *'"loadStatus": "LOADED"'* ]] || die "services: code location did not report LOADED: $reload"

  # 6. The loaded job list has the jobs this SAT drives, and every daemon Dagster requires is healthy.
  local jobs daemons missing="" j
  jobs="$(graphql '{ repositoriesOrError { ... on RepositoryConnection { nodes { name location { name } jobs { name } } } } }' \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(sorted(j["name"] for n in d["repositoriesOrError"]["nodes"] if n["location"]["name"]=="appsec_review" for j in n["jobs"])))')" \
    || die "services: could not read the job list from the webserver"
  for j in $SAT_REQUIRED_JOBS; do [[ " $jobs " == *" $j "* ]] || missing+=" $j"; done
  [[ -z "$missing" ]] || die "services: loaded job list lacks:$missing (loaded: $jobs)"
  daemons="$(graphql '{ instance { daemonHealth { allDaemonStatuses { daemonType required healthy } } } }' \
    | python3 -c 'import json,sys; s=json.load(sys.stdin)["instance"]["daemonHealth"]["allDaemonStatuses"]; bad=[d["daemonType"] for d in s if d["required"] and not d["healthy"]]; print(("UNHEALTHY: " + " ".join(bad)) if bad else " ".join(sorted(d["daemonType"] for d in s if d["required"])))')" \
    || die "services: could not read daemon health from the webserver"
  [[ "$daemons" != UNHEALTHY* ]] || die "services: required Dagster daemons $daemons"
  echo "jobs loaded: $jobs"
  echo "required daemons healthy: $daemons"

  record PASS services "$(python3 -c 'import json,sys; k=["docker_engine","compose","code_location_host","webserver_resolves","reload","jobs","required_daemons"]; print(json.dumps(dict(zip(k, sys.argv[1:]))))' \
    "$engine" "$states" "${wsl_ip:-$env_host}" "$resolved" LOADED "$jobs" "$daemons")"
  echo "services: PASS  engine $engine; postgres, webserver, daemon healthy; code location LOADED; SAT jobs present"
}

# ---- stage 3: run-create -------------------------------------------------------------------------
# The security engineer's first command. Runs in the code location's environment (the same Python
# and APPSEC_* paths the jobs use), creates a brand-new run, and records its id in sat.json so every
# later stage of this SAT works on that run.
stage_run_create() {
  local cl="$REPO/orchestrator/dagster/code-location.sh" out run_id
  out="$("$cl" run -B "$REPO/appsec-review-process/run_process.py" --start)" || die "run-create: run_process.py --start failed: $out"
  echo "$out"
  run_id="$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')" \
    || die "run-create: could not read run_id from: $out"
  [[ "$run_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]] || die "run-create: unexpected run id '$run_id'"

  local rdir="$REPO/appsec-review-process/runs/$run_id" d
  [[ -d "$rdir" ]] || die "run-create: $rdir was not created (is APPSEC_RUNS_ROOT pointing elsewhere?)"
  for d in data inputs outputs; do [[ -d "$rdir/$d" ]] || die "run-create: $rdir/$d missing"; done

  # run-status.json: a new run, READY, for this id, starting at the first lane of the manifest order.
  local summary
  summary="$(python3 - "$rdir" "$run_id" "$REPO/appsec-review-process/process-manifest.json" <<'PY'
import json, sys, pathlib
rdir, run_id, manifest = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
s = json.loads((rdir / 'run-status.json').read_text())
problems = []
if s.get('schema') != 'appsec-review-process/run-status/0.1': problems.append('schema %r' % s.get('schema'))
if s.get('run_id') != run_id: problems.append('run_id %r' % s.get('run_id'))
if s.get('status') != 'READY': problems.append('status %r' % s.get('status'))
if s.get('completed_processes'): problems.append('completed_processes not empty')
order = json.loads(open(manifest).read())['process_order']
if s.get('resume_from') != order[0]: problems.append('resume_from %r, manifest starts %r' % (s.get('resume_from'), order[0]))
events = [json.loads(l) for l in (rdir / 'events.jsonl').read_text().splitlines() if l.strip()]
if [e.get('event') for e in events] != ['RUN_CREATED']: problems.append('events %r' % [e.get('event') for e in events])
if problems: sys.exit('run-status: ' + '; '.join(problems))
print(json.dumps({'status': s['status'], 'created_at': s['created_at'], 'resume_from': s['resume_from'],
                  'lanes': len(s['process_order'])}))
PY
)" || die "run-create: $summary"

  # The artifact manifest is still the unfilled template here; stage-inputs writes the real one.
  local template="$REPO/appsec-review-process/templates/artifact-manifest.template.json" manifest_state
  if cmp -s "$template" "$rdir/inputs/artifact-manifest.json"; then manifest_state=template
  else die "run-create: inputs/artifact-manifest.json is not the unfilled template (a fresh run should not be staged yet)"; fi

  sat_set run_id "$run_id"
  record PASS run-create "$(python3 -c 'import json,sys; e=json.loads(sys.argv[3]); e.update(run_id=sys.argv[1], run_dir=sys.argv[2], artifact_manifest=sys.argv[4]); print(json.dumps(e))' \
    "$run_id" "appsec-review-process/runs/$run_id" "$summary" "$manifest_state")"
  echo "run-create: PASS  run $run_id (READY, first lane $(printf '%s' "$summary" | python3 -c 'import json,sys; print(json.load(sys.stdin)["resume_from"])'); data/ inputs/ outputs/ present; manifest is the unfilled template)"
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
echo "SAT $(sat_get sat_id)  fixture $FIXTURE  record ${SAT_DIR#$REPO/}${RESUME:+  run $(sat_get run_id)}"

for id in $(stage_ids); do
  if [[ "$(stage_status "$id")" == PASS && "$id" == sut-checkout ]]; then
    # Later stages read this checkout, so on resume it is re-verified rather than trusted.
    head_now="$(git -C "$REPO/fixtures/targets/$FIXTURE" rev-parse HEAD 2>/dev/null || true)"
    head_then="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stages"]["sut-checkout"]["evidence"]["head"])' "$SAT_DIR/sat.json")"
    if [[ "$head_now" != "$head_then" || -n "$(git -C "$REPO/fixtures/targets/$FIXTURE" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
      echo "sut-checkout: the checkout changed since this SAT's stage 1 (HEAD ${head_now:-missing}, or local changes); start a new SAT"; exit 1
    fi
    echo "sut-checkout: already PASS in this SAT; checkout re-verified (${head_now:0:7}, clean)"
  elif [[ "$(stage_status "$id")" == PASS ]]; then
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
