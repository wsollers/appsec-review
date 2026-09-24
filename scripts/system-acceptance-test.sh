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
  "stage-inputs|1|stage_artifacts.py writes a valid artifact manifest (executor platform posix)"
  "intake|1|00-intake accepted (phase1_intake)"
  "partition-discovery|1|Partition map supplied and accepted (repository_partition_discovery)"
  "dev-project-discovery|1|Project discovery supplied and accepted (dev_project_discovery)"
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

# ---- stage 4: stage-inputs -----------------------------------------------------------------------
# The engineer states what is reviewed and why. For the SAT these are fixed, so every SAT stages the
# same engagement; SAT_* environment variables override them for experiments.
SAT_BUSINESS_GOAL="${SAT_BUSINESS_GOAL:-System acceptance test: full review cycle on the fixture}"
SAT_PLATFORM="${SAT_PLATFORM:-Linux}"
SAT_BUDGET="${SAT_BUDGET:-probe}"
SAT_EXECUTION_ENVIRONMENT="${SAT_EXECUTION_ENVIRONMENT:-dagster-read-only-linux}"

require_run() {  # the run this SAT created in stage 3
  RUN_ID="$(sat_get run_id)"
  [[ -n "$RUN_ID" ]] || die "$1: this SAT has no run yet (stage run-create)"
  RUN_DIR="$REPO/appsec-review-process/runs/$RUN_ID"
  [[ -d "$RUN_DIR" ]] || die "$1: run folder $RUN_DIR is missing"
}

stage_stage_inputs() {
  require_run stage-inputs
  local cl="$REPO/orchestrator/dagster/code-location.sh" target="$REPO/fixtures/targets/$FIXTURE" out
  out="$("$cl" run -B "$REPO/appsec-review-process/stage_artifacts.py" --run-id "$RUN_ID" --project "$FIXTURE" \
          --target "$target" --business-goal "$SAT_BUSINESS_GOAL" --platform "$SAT_PLATFORM" \
          --budget "$SAT_BUDGET" --execution-environment "$SAT_EXECUTION_ENVIRONMENT")" \
    || die "stage-inputs: stage_artifacts.py failed: $out"
  echo "$out"

  # The manifest is the intake contract: check it says exactly what was asked, on this host.
  local summary
  summary="$(python3 - "$RUN_DIR" "$RUN_ID" "$FIXTURE" "$(realpath "$target")" "$SAT_BUSINESS_GOAL" "$SAT_PLATFORM" "$SAT_BUDGET" "$SAT_EXECUTION_ENVIRONMENT" <<'PY'
import hashlib, json, sys, pathlib
rdir, run_id, project, target, goal, platform, budget, env = sys.argv[1:]
rdir = pathlib.Path(rdir)
path = rdir / 'inputs' / 'artifact-manifest.json'
m = json.loads(path.read_text())
c = m.get('intake_config', {})
want = {
    'orchestration_version': (m.get('orchestration_version'), 1),
    'run_id': (m.get('run_id'), run_id),
    'project': (m.get('project'), project),
    'target': (c.get('target'), target),
    'business_goal': (c.get('business_goal'), goal),
    'platforms': (c.get('platforms'), [platform]),
    'budget': (c.get('budget'), budget),
    'execution_environment': (c.get('execution_environment'), env),
    'executor_platform': (c.get('executor_platform'), 'posix'),
    'permissions': (c.get('permissions'), ['read-source']),
    'scope': (m.get('scope'), {'include': ['**'], 'exclude': []}),
    'imports': (c.get('imports'), []),
    'compile_database': (c.get('compile_database'), None),
    'supplied_evidence': (m.get('artifact_hashes'), {}),
    'engagement_relative': (c.get('engagement_relative'), 'pending-evidence'),
}
bad = ['%s=%r (expected %r)' % (k, got, exp) for k, (got, exp) in want.items() if got != exp]
status = json.loads((rdir / 'run-status.json').read_text()).get('status')
if status != 'READY':
    bad.append('run-status %r (expected READY)' % status)
if bad:
    sys.exit('manifest: ' + '; '.join(bad))
notes = m.get('notes', [])
print(json.dumps({'target': target, 'business_goal': goal, 'platforms': [platform], 'budget': budget,
                  'execution_environment': env, 'executor_platform': 'posix', 'permissions': ['read-source'],
                  'supplied_evidence': 0, 'pregather_expected_notes': len(notes),
                  'manifest_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
PY
)" || die "stage-inputs: $summary"

  record PASS stage-inputs "$summary"
  echo "stage-inputs: PASS  manifest for $FIXTURE on posix: platform $SAT_PLATFORM, budget $SAT_BUDGET, read-source only, no supplied evidence"
}

# ---- stage 5: intake -----------------------------------------------------------------------------
# The first Dagster job. Submitted and awaited with launch_job.py (which only submits and monitors;
# the work runs in the host code location), then the accepted output is checked on disk.
SAT_JOB_TIMEOUT="${SAT_JOB_TIMEOUT:-900}"

launch_job() {  # launch_job <dagster job> -> LAUNCH (final request JSON), LAUNCH_STATUS, LAUNCH_DAGSTER, LAUNCH_RC
  local cl="$REPO/orchestrator/dagster/code-location.sh"
  LAUNCH_RC=0
  LAUNCH="$("$cl" run -B "$REPO/appsec-review-process/launch_job.py" --run-id "$RUN_ID" --job "$1" --wait --timeout "$SAT_JOB_TIMEOUT")" || LAUNCH_RC=$?
  echo "$LAUNCH"
  LAUNCH_STATUS="$(printf '%s' "$LAUNCH" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || true)"
  LAUNCH_DAGSTER="$(printf '%s' "$LAUNCH" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("dagster_run_id",""))' 2>/dev/null || true)"
}

dagster_url() { echo "${LAUNCH_DAGSTER:+http://127.0.0.1:3000/runs/$LAUNCH_DAGSTER}${LAUNCH_DAGSTER:-none (see the launch request under runs/$RUN_ID/data/orchestration/launches/)}"; }

launch_and_wait() {  # launch_and_wait <stage> <dagster job>: the job must end SUCCESS
  launch_job "$2"
  [[ $LAUNCH_RC == 0 && "$LAUNCH_STATUS" == SUCCESS ]] || die "$1: Dagster job $2 did not succeed (status ${LAUNCH_STATUS:-unknown}, exit $LAUNCH_RC).
  Dagster run: $(dagster_url)"
}

stage_intake() {
  require_run intake
  launch_and_wait intake phase1_intake

  local head files summary
  head="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stages"]["sut-checkout"]["evidence"]["head"])' "$SAT_DIR/sat.json")"
  files="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stages"]["sut-checkout"]["evidence"]["tracked_files"])' "$SAT_DIR/sat.json")"
  summary="$(python3 - "$RUN_DIR" "$RUN_ID" "$LAUNCH" "$head" "$files" "$SAT_BUSINESS_GOAL" "$SAT_PLATFORM" "$SAT_BUDGET" <<'PY'
import hashlib, json, pathlib, sys
rdir, run_id, launch, head, files, goal, platform, budget = sys.argv[1:]
rdir = pathlib.Path(rdir); launch = json.loads(launch)
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
bad = []
base = rdir / 'data/jobs/00-intake/whole'
ptr = json.loads((base / 'accepted.json').read_text())
if ptr.get('status') != 'OK': bad.append('accepted status %r' % ptr.get('status'))
if ptr.get('dagster_run_id') != launch.get('dagster_run_id'): bad.append('accepted by Dagster run %r, launched %r' % (ptr.get('dagster_run_id'), launch.get('dagster_run_id')))
if json.loads((base / 'latest.json').read_text()).get('attempt_id') != ptr['attempt_id']: bad.append('accepted attempt is not the latest')
att = base / 'attempts' / ptr['attempt_id']
for f in ('outputs/intake.json', 'outputs/build-discovery.md', 'status.json'):
    if not (att / f).is_file(): bad.append('missing ' + f)
if sha(att / 'status.json') != ptr.get('status_sha256'): bad.append('status.json hash differs from the accepted pointer')
for rel, h in ptr.get('hashes', {}).items():
    if sha(att / rel) != h: bad.append('output changed since acceptance: ' + rel)
r = json.loads((att / 'outputs/intake.json').read_text())
exp = {'source_revision': head, 'business_goal': goal, 'platforms': [platform], 'budget': budget,
       'permissions': ['read-source'], 'ready_to_collect': True, 'pregather_complete': False, 'findings': []}
bad += ['intake %s=%r (expected %r)' % (k, r.get(k), v) for k, v in exp.items() if r.get(k) != v]
if len(r.get('scope', {}).get('all_paths', [])) != int(files): bad.append('intake saw %d files, the clone has %s' % (len(r['scope']['all_paths']), files))
n = r.get('native', {})
if n.get('build_status') != 'NOT_EXECUTED' or n.get('commands_attempted'): bad.append('intake executed build commands: %r' % n.get('commands_attempted'))
jobs = {j['job']: j.get('applicability') for j in r.get('selected_jobs', [])}
for j in ('02-repository-partition-discovery', '02-dev-project-discovery'):
    if jobs.get(j) != 'required': bad.append('%s applicability %r (expected required)' % (j, jobs.get(j)))
m = json.loads((rdir / 'inputs/artifact-manifest.json').read_text())
if m.get('accepted_intake') != ptr: bad.append('manifest accepted_intake differs from the accepted pointer')
if m.get('source_identity', {}).get('revision') != head: bad.append('manifest source_identity revision %r' % m.get('source_identity', {}).get('revision'))
events = [json.loads(l) for l in (rdir / 'data/events.jsonl').read_text().splitlines() if l.strip()] if (rdir / 'data/events.jsonl').exists() else []
if not any(e.get('event') == 'ACCEPTED' and e.get('attempt_id') == ptr['attempt_id'] for e in events): bad.append('no ACCEPTED event for the attempt')
if bad: sys.exit('; '.join(bad))
print(json.dumps({'dagster_run_id': ptr['dagster_run_id'], 'launch_id': launch.get('launch_id'), 'attempt_id': ptr['attempt_id'],
                  'source_revision': r['source_revision'], 'source_fingerprint': r['source_fingerprint'],
                  'files_fingerprinted': len(r['scope']['all_paths']), 'families': r['families'],
                  'native_applicable': n.get('applicable'), 'native_primary': n.get('primary'), 'native_strategy': n.get('strategy', {}).get('method'),
                  'selected_jobs': jobs, 'limitations': len(r['limitations'])}))
PY
)" || die "intake: $summary"

  # Intake is read-only: the checkout must be exactly as stage 1 left it.
  local target="$REPO/fixtures/targets/$FIXTURE"
  [[ "$(git -C "$target" rev-parse HEAD)" == "$head" && -z "$(git -C "$target" status --porcelain --untracked-files=all)" ]] \
    || die "intake: the checkout changed during intake (HEAD or local files)"

  record PASS intake "$summary"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("intake: PASS  Dagster %s accepted attempt %s; revision %s, %d files fingerprinted; families: %s; native: %s (%s); build not executed; no findings" % (
  s["dagster_run_id"][:8], s["attempt_id"], s["source_revision"][:7], s["files_fingerprinted"], ", ".join(sorted(s["families"])), s["native_applicable"], s["native_strategy"]))'
}

# ---- stage 6: partition-discovery -----------------------------------------------------------------
# 02-repository-partition-discovery is a supplied-result gate: it never invents the analysis. The
# stage proves both halves: with nothing supplied it must fail with an actionable hand-off; with the
# fixture's recorded analysis supplied it must accept it, and the accepted map must still match the
# checkout (every citation hash re-checked here, independently of the gate).
PARTITION_JOB=02-repository-partition-discovery

gate_validate() {  # gate_validate <job>: the project's own validator for an accepted gate result
  "$REPO/orchestrator/dagster/code-location.sh" run -B -c \
    'import sys; sys.path.insert(0, sys.argv[1]); import discovery_gate; discovery_gate.validate(sys.argv[2], sys.argv[3]); print("validator OK")' \
    "$REPO/appsec-review-process" "$RUN_ID" "$1"
}

gate_handoff_proof() {  # gate_handoff_proof <stage> <job id> <dagster job> <schema name> -> HANDOFF_STATE, HANDOFF_DAGSTER
  # With nothing supplied the gate must end FAILURE, write handoff.md/handoff.json naming
  # supplied/result.json and the schema, and accept nothing. Skipped (and recorded as skipped) when a
  # result is already supplied, e.g. when the stage is re-run after a later failure.
  local jobdir="$RUN_DIR/data/jobs/$2"
  HANDOFF_DAGSTER=""
  if [[ -e "$jobdir/supplied/result.json" ]]; then
    echo "-- a) skipped: a supplied result already exists for this run (stage re-run)"
    HANDOFF_STATE="skipped-already-supplied"; return 0
  fi
  echo "-- a) gate with nothing supplied: expect FAILURE and a hand-off"
  launch_job "$3"
  [[ "$LAUNCH_STATUS" == FAILURE ]] || die "$1: with nothing supplied the gate ended ${LAUNCH_STATUS:-unknown}, expected FAILURE. Dagster run: $(dagster_url)"
  HANDOFF_DAGSTER="$LAUNCH_DAGSTER"
  python3 - "$jobdir" "$4" <<'PY' || die "$1: hand-off check failed"
import json, pathlib, sys
d, schema = pathlib.Path(sys.argv[1]), sys.argv[2]
bad = [f for f in ('handoff.md', 'handoff.json') if not (d / f).is_file()]
if not bad:
    text = (d / 'handoff.md').read_text() + (d / 'handoff.json').read_text()
    for needle in ('supplied/result.json', schema):
        if needle not in text: bad.append('hand-off does not name ' + needle)
acc = d / 'accepted.json'
if acc.exists() and json.loads(acc.read_text()).get('status') == 'OK': bad.append('a result was accepted with nothing supplied')
if bad: sys.exit('; '.join(bad))
print('hand-off issued: handoff.md and handoff.json name supplied/result.json and the %s schema; nothing accepted' % schema)
PY
  HANDOFF_STATE="issued"
}

stage_partition_discovery() {
  require_run partition-discovery
  local jobdir="$RUN_DIR/data/jobs/$PARTITION_JOB"

  # a) Nothing supplied: the gate must fail with a hand-off, and accept nothing.
  gate_handoff_proof partition-discovery "$PARTITION_JOB" repository_partition_discovery repository-partition-map
  local handoff_state="$HANDOFF_STATE" handoff_dagster="$HANDOFF_DAGSTER"

  # b) Supply the fixture's recorded analysis (refuses a moved or dirty checkout, never overwrites).
  echo "-- b) supply the recorded partition map"
  "$REPO/orchestrator/dagster/code-location.sh" run -B "$REPO/fixtures/supply_record.py" --run-id "$RUN_ID" --job "$PARTITION_JOB" --fixture "$FIXTURE" \
    || die "partition-discovery: supply_record.py refused"

  # c) The gate accepts it.
  echo "-- c) gate with the supplied map: expect SUCCESS"
  launch_and_wait partition-discovery repository_partition_discovery
  gate_validate "$PARTITION_JOB" || die "partition-discovery: discovery_gate.validate rejected the accepted result"

  local summary
  summary="$(python3 - "$jobdir" "$REPO/fixtures/targets/$FIXTURE" "$REPO/fixtures/supplied/$FIXTURE/$PARTITION_JOB.json" "$LAUNCH_DAGSTER" "$(sat_get run_id)" <<'PY'
import hashlib, json, pathlib, sys
d, target, record_path, dagster_id, run_id = sys.argv[1:]
d, target = pathlib.Path(d), pathlib.Path(target)
bad = []
ptr = json.loads((d / 'accepted.json').read_text())
if ptr.get('status') != 'OK': bad.append('accepted status %r' % ptr.get('status'))
att = d / 'attempts' / ptr['attempt_id']
status = json.loads((att / 'status.json').read_text())
if status.get('dagster_run_id') != dagster_id: bad.append('accepted by Dagster run %r, launched %r' % (status.get('dagster_run_id'), dagster_id))
m = json.loads((att / 'repository-partition-map.json').read_text())
rec = json.loads(pathlib.Path(record_path).read_text())
head = __import__('subprocess').run(['git', '-C', str(target), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
if m.get('source_revision') != head: bad.append('map source_revision %r, checkout %r' % (m.get('source_revision'), head))
ids = {p['partition_id']: p for p in m.get('partitions', [])}
if sorted(ids) != sorted(p['partition_id'] for p in rec['partitions']): bad.append('partitions %r differ from the record' % sorted(ids))
if ids.get('docs', {}).get('disposition') != 'deferred': bad.append('docs partition is not deferred')
# Independent freshness check: every source-file citation hash matches the checkout now.
cites, stale = 0, []
def walk(v):
    global cites
    if isinstance(v, dict):
        if v.get('source_type') == 'source_file' and v.get('content_hash'):
            cites += 1
            f = target / v['path']
            if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != v['content_hash']: stale.append(v['path'])
        for x in v.values(): walk(x)
    elif isinstance(v, list):
        for x in v: walk(x)
walk(m)
if stale: bad.append('stale citations: ' + ', '.join(sorted(set(stale))))
if cites == 0: bad.append('no source-file citations found')
if bad: sys.exit('; '.join(bad))
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': ptr['attempt_id'], 'source_revision': head,
                  'partitions': {k: v.get('disposition') for k, v in ids.items()},
                  'primary_personas': sorted({v.get('primary_persona_id') for v in ids.values()}),
                  'citations_checked': cites}))
PY
)" || die "partition-discovery: $summary"

  record PASS partition-discovery "$(python3 -c 'import json,sys; e=json.loads(sys.argv[1]); e.update(handoff=sys.argv[2], handoff_dagster_run_id=sys.argv[3] or None); print(json.dumps(e))' "$summary" "$handoff_state" "$handoff_dagster")"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("partition-discovery: PASS  hand-off %s; map accepted by Dagster %s (attempt %s): %s; %d citations match the checkout" % (
  sys.argv[1], s["dagster_run_id"][:8], s["attempt_id"], ", ".join("%s=%s" % kv for kv in sorted(s["partitions"].items())), s["citations_checked"]))' "$handoff_state"
}

# ---- stage 7: dev-project-discovery ---------------------------------------------------------------
# How to build what the partition map found: project root, languages, manifests, candidate build
# image and a safe command plan. Same supplied-result pattern as stage 6; this gate additionally
# requires the accepted partition map at the same revision. It is the older gate path, whose
# accepted record carries no output hashes, so the stage compares the accepted output with the
# supplied file itself.
DEV_JOB=02-dev-project-discovery

stage_dev_project_discovery() {
  require_run dev-project-discovery
  local jobdir="$RUN_DIR/data/jobs/$DEV_JOB"

  gate_handoff_proof dev-project-discovery "$DEV_JOB" dev_project_discovery project-discovery
  local handoff_state="$HANDOFF_STATE" handoff_dagster="$HANDOFF_DAGSTER"

  echo "-- b) supply the recorded project discovery"
  "$REPO/orchestrator/dagster/code-location.sh" run -B "$REPO/fixtures/supply_record.py" --run-id "$RUN_ID" --job "$DEV_JOB" --fixture "$FIXTURE" \
    || die "dev-project-discovery: supply_record.py refused"

  echo "-- c) gate with the supplied discovery: expect SUCCESS"
  launch_and_wait dev-project-discovery dev_project_discovery
  gate_validate "$DEV_JOB" || die "dev-project-discovery: discovery_gate.validate rejected the accepted result"

  local summary
  summary="$(python3 - "$RUN_DIR" "$REPO/fixtures/targets/$FIXTURE" "$REPO/fixtures/supplied/$FIXTURE/$DEV_JOB.json" "$LAUNCH_DAGSTER" <<'PY'
import hashlib, json, pathlib, subprocess, sys
rdir, target, record_path, dagster_id = sys.argv[1:]
rdir, target = pathlib.Path(rdir), pathlib.Path(target)
d = rdir / 'data/jobs/02-dev-project-discovery'
bad = []
ptr = json.loads((d / 'accepted.json').read_text())
if ptr.get('status') != 'OK': bad.append('accepted status %r' % ptr.get('status'))
if ptr.get('dagster_run_id') != dagster_id: bad.append('accepted by Dagster run %r, launched %r' % (ptr.get('dagster_run_id'), dagster_id))
if json.loads((d / 'latest.json').read_text()).get('attempt_id') != ptr.get('attempt_id'): bad.append('accepted attempt is not the latest')
att = d / 'attempts' / ptr['attempt_id']
out = json.loads((att / 'output.json').read_text())
supplied = json.loads((d / 'supplied/result.json').read_text())
record = json.loads(pathlib.Path(record_path).read_text())
if out != supplied or supplied != record: bad.append('accepted output, supplied file and fixture record differ')
head = subprocess.run(['git', '-C', str(target), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
if out.get('source_revision') != head: bad.append('source_revision %r, checkout %r' % (out.get('source_revision'), head))
# The graph dependency: same revision as the accepted partition map.
pd = rdir / 'data/jobs/02-repository-partition-discovery'
pptr = json.loads((pd / 'accepted.json').read_text())
pmap = json.loads((pd / 'attempts' / pptr['attempt_id'] / 'repository-partition-map.json').read_text())
if pmap.get('source_revision') != out.get('source_revision'): bad.append('revision differs from the accepted partition map')
# Independent freshness check of every source-file citation.
cites, stale = [0], []
def walk(v):
    if isinstance(v, dict):
        if v.get('source_type') == 'source_file' and v.get('content_hash'):
            cites[0] += 1
            f = target / v['path']
            if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != v['content_hash']: stale.append(v['path'])
        for x in v.values(): walk(x)
    elif isinstance(v, list):
        for x in v: walk(x)
walk(out)
if stale: bad.append('stale citations: ' + ', '.join(sorted(set(stale))))
if cites[0] == 0: bad.append('no source-file citations')
plan = out.get('safe_command_plan', [])
if not plan: bad.append('empty safe command plan')
for c in plan:
    if not c.get('argv') or not c.get('authorization') or not c.get('purpose'): bad.append('incomplete plan entry %r' % c.get('argv'))
if bad: sys.exit('; '.join(bad))
p = out['projects'][0]
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': ptr['attempt_id'], 'source_revision': head,
                  'projects': [x['project_id'] for x in out['projects']], 'root': p.get('root'),
                  'languages': p.get('languages'), 'manifests': p.get('manifests'), 'lockfiles': p.get('lockfiles'),
                  'buildenv_images': p.get('candidate_buildenv_images'),
                  'command_plan': [{'argv': c['argv'], 'authorization': c['authorization']} for c in plan],
                  'coverage_gaps': len(out.get('coverage_gaps', [])), 'citations_checked': cites[0],
                  'output_hashes_in_accepted_record': False}))
PY
)" || die "dev-project-discovery: $summary"

  record PASS dev-project-discovery "$(python3 -c 'import json,sys; e=json.loads(sys.argv[1]); e.update(handoff=sys.argv[2], handoff_dagster_run_id=sys.argv[3] or None); print(json.dumps(e))' "$summary" "$handoff_state" "$handoff_dagster")"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("dev-project-discovery: PASS  hand-off %s; discovery accepted by Dagster %s: project %s (%s), manifests %s, image %s; plan: %s; %d citations match the checkout" % (
  sys.argv[1], s["dagster_run_id"][:8], ",".join(s["projects"]), "/".join(map(str, s["languages"])), ", ".join(map(str, s["manifests"])),
  ", ".join(map(str, s["buildenv_images"])), "; ".join(" ".join(c["argv"]) + " [" + c["authorization"] + "]" for c in s["command_plan"]), s["citations_checked"]))' "$handoff_state"
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
RUN_ID="$(sat_get run_id)"
echo "SAT $(sat_get sat_id)  fixture $FIXTURE  record ${SAT_DIR#$REPO/}${RUN_ID:+  run $RUN_ID}"

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
