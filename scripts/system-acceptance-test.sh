#!/usr/bin/env bash
# System acceptance test (SAT): one fixture, from a fresh clone of the system under test through the
# full review cycle (SARIF and report generation), in the order of the documented engagement flow
# (docs/processes/engagement-start.md). Built and run stage by stage; no stage is added until every
# earlier one runs and passes. Run on the POSIX host (WSL or native Linux) from the repository root.
#
#   scripts/system-acceptance-test.sh --list                     show the stages and which are built
#   scripts/system-acceptance-test.sh [--fixture hello-autotools] --through <stage>
#                                                                start a new SAT and run up to <stage>
#   scripts/system-acceptance-test.sh --resume <sat_id> --through <stage>
#                                                                continue an earlier SAT from its first
#                                                                stage that has not passed
#   scripts/system-acceptance-test.sh [--fixture hello-autotools] --dispatch --through <stage>
#                                                                start a new SAT whose partition-
#                                                                discovery stage (02-repository-
#                                                                partition-discovery) opts into D01's
#                                                                automatic persona dispatch instead of
#                                                                installing the fixture's supplied
#                                                                record (a real `claude` CLI call, not
#                                                                a fixture copy) -- a new SAT only; a
#                                                                `--resume` reads the choice its own
#                                                                first run made, --dispatch is ignored
#
# Every command runs under a contract (run_step, scripts/sat_contract.py):
#   pre   what it reads is present and valid (schema or structural contract; absent where required)
#   run   it executed and exited as expected
#   post  it wrote exactly the expected set (no unexpected add, change or delete anywhere in the
#         repository), and every artifact it wrote is valid
# and the stage then checks the job's own success signal and the artifacts' meaning.
#
# Record: appsec-review-process/logs/system-acceptance/<sat_id>/ (gitignored): sat.json (per-stage
# status and evidence), <stage>.log, contracts/, steps/ (pre and post report per command).
# A failing stage stops the SAT; an unbuilt stage stops it with NOT_IMPLEMENTED (exit 3).
# Windows: scripts/system-acceptance-test.ps1 runs this inside WSL.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAT_ROOT="$REPO/appsec-review-process/logs/system-acceptance"
CONTRACT_PY="$REPO/scripts/sat_contract.py"
CL="$REPO/orchestrator/dagster/code-location.sh"

# Stage table: id|built(1/0)|what it proves. Order: docs/processes/engagement-start.md.
STAGES=(
  "sut-checkout|1|Fresh clone of the fixture at its pinned commit; clean; no answer key on the branch"
  "services|1|Dagster services healthy; host code location serving; job list reloaded"
  "run-create|1|run_process.py --start creates the run and exactly its initial files"
  "stage-inputs|1|stage_artifacts.py writes the intake contract (manifest) for this engagement"
  "engagement-workflow|1|engagement_workflow: intake executed and accepted; 3 preparation branches; join"
  "partition-discovery|1|Gate: hand-off/supplied-record proof (default), or --dispatch: automatic live persona dispatch, schema+citation validated"
  "dev-project-discovery|1|Gate: hand-off with nothing supplied; project discovery supplied and accepted"
  "devops-project-discovery|1|Gate: DevOps project discovery (Dockerfile) supplied and accepted"
  "sre-operations-topology|1|Gate: SRE operations topology supplied and accepted"
  "build-index|0|02-build-index: deterministic, cited index of every build signal; nothing executed"
  "build-plan|0|02-build-plan: LLM build plan from the index only; validated; compared with the answer key"
  "build-resolution|0|02-build-resolution: image + trial configure/build via B13, <= build_resolution_attempts; image_build_<id> catalogued, lock written"
  "build-configure|0|02-build-configure (E01): replay the lock's configure in the catalogued image"
  "native-build|0|02-native-build (E02): compile database and build outputs"
  "evidence|0|Evidence collection (legacy pipeline + hashed import), every tool ran or is a recorded gap"
  "ossf-scorecard|0|02-ossf-scorecard published results ingested (needs a network permission grant)"
  "evidence-index|0|evidence_index: accepted searchable evidence"
  "review-lanes|0|01 characterization through 09 verification, 11, 12"
  "sarif|0|critical_findings_sarif: accepted SARIF from verified findings"
  "report|0|10-synthesis-report: report generated"
)
SAT_REQUIRED_JOBS="engagement_workflow repository_partition_discovery dev_project_discovery devops_project_discovery sre_operations_topology full_review"
SAT_JOB_TIMEOUT="${SAT_JOB_TIMEOUT:-900}"
SAT_BUSINESS_GOAL="${SAT_BUSINESS_GOAL:-System acceptance test: full review cycle on the fixture}"
SAT_PLATFORM="${SAT_PLATFORM:-Linux}"
SAT_BUDGET="${SAT_BUDGET:-probe}"
SAT_EXECUTION_ENVIRONMENT="${SAT_EXECUTION_ENVIRONMENT:-dagster-read-only-linux}"
PARTITION_JOB=02-repository-partition-discovery
DEV_JOB=02-dev-project-discovery
DEVOPS_JOB=02-devops-project-discovery
SRE_JOB=02-sre-operations-topology

die() { echo "SAT: $*" >&2; exit 1; }
stage_ids() { for s in "${STAGES[@]}"; do echo "${s%%|*}"; done; }
stage_field() { local id="$1" n="$2"; for s in "${STAGES[@]}"; do [[ "${s%%|*}" == "$id" ]] && { IFS='|' read -r -a f <<< "$s"; echo "${f[$n]}"; return; }; done; }
usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; }
list() {
  printf '%-26s %-9s %s\n' STAGE BUILT PROVES
  for s in "${STAGES[@]}"; do IFS='|' read -r id built what <<< "$s"; printf '%-26s %-9s %s\n' "$id" "$([[ $built == 1 ]] && echo yes || echo 'not yet')" "$what"; done
}

# ---- record keeping ------------------------------------------------------------------------------
record() {  # record <status> <stage> <json-evidence>: evidence plus every step report of the stage
  python3 - "$SAT_DIR" "$1" "$2" "$3" <<'EOF'
import json, sys, datetime, pathlib
sat_dir, status, stage, evidence = sys.argv[1:]
d = pathlib.Path(sat_dir); path = d / 'sat.json'
data = json.load(open(path))
steps = []
index = d / 'steps' / (stage + '.index')
for step in (index.read_text().split() if index.exists() else []):
    pre_f, post_f = d / 'steps' / f'{stage}.{step}.pre.json', d / 'steps' / f'{stage}.{step}.post.json'
    if not pre_f.exists() or not post_f.exists():
        steps.append({'step': step, 'incomplete': True}); continue
    pre, post = json.loads(pre_f.read_text()), json.loads(post_f.read_text())
    steps.append({'step': step, 'inputs_verified': len(pre['inputs']), 'exit': post['exit'],
                  'written': len(post['written']), 'deleted': len(post['removed']),
                  'ambient': len(post['ambient']), 'outputs_validated': len(post['outputs_validated']),
                  'report': f'steps/{stage}.{step}.post.json'})
data['stages'][stage] = {'status': status, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                         'evidence': json.loads(evidence) if evidence else {}, 'steps': steps}
json.dump(data, open(path, 'w'), indent=1)
EOF
}
stage_status() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stages"].get(sys.argv[2],{}).get("status",""))' "$SAT_DIR/sat.json" "$1"; }
sat_get() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print("" if v is None else v)' "$SAT_DIR/sat.json" "$1"; }
sat_set() { python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d[sys.argv[2]]=sys.argv[3]; json.dump(d, open(p,"w"), indent=1)' "$SAT_DIR/sat.json" "$1" "$2"; }
evidence_of() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stages"][sys.argv[2]]["evidence"][sys.argv[3]])' "$SAT_DIR/sat.json" "$1" "$2"; }

# ---- contracts and steps -------------------------------------------------------------------------
contract() {  # contract <stage> <step>  (JSON on stdin) -> prints the contract file path
  local f="$SAT_DIR/contracts/$1.$2.json"; mkdir -p "$SAT_DIR/contracts"; cat > "$f"; echo "$f"
}

step_vars() {
  local run_rel=""; [[ -n "${RUN_ID:-}" ]] && run_rel="appsec-review-process/runs/$RUN_ID"
  python3 -c 'import json,sys; print(json.dumps(dict(zip(["run","run_id","target","fixture","pin"], sys.argv[1:]))))' \
    "$run_rel" "${RUN_ID:-}" "fixtures/targets/$FIXTURE" "$FIXTURE" "${PIN:-}"
}

run_step() {  # run_step <stage> <step> <contract file> <command...>  -> STEP_OUT, STEP_RC
  local stage="$1" step="$2" contract="$3"; shift 3
  mkdir -p "$SAT_DIR/steps" "$SAT_DIR/snap"
  echo "$step" >> "$SAT_DIR/steps/$stage.index"
  local pre post hash_run=()
  pre="$(python3 "$CONTRACT_PY" pre --repo "$REPO" --contract "$contract" --vars "$(step_vars)")" \
    || { echo "$pre" > "$SAT_DIR/steps/$stage.$step.pre.json"; die "$stage/$step: pre-contract failed: $(printf '%s' "$pre" | python3 -c 'import json,sys; print("; ".join(json.load(sys.stdin)["problems"]))')"; }
  echo "$pre" > "$SAT_DIR/steps/$stage.$step.pre.json"
  echo "   [pre ] $step: $(printf '%s' "$pre" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("%d input(s) present and valid" % len(d["inputs"]))')"
  [[ -n "${RUN_ID:-}" ]] && hash_run=(--hash-root "appsec-review-process/runs/$RUN_ID")
  python3 "$CONTRACT_PY" snapshot "$SAT_DIR/snap/$stage.$step.before.json" --repo "$REPO" "${hash_run[@]}" \
    --hash-root "fixtures/targets/$FIXTURE" --exclude "${SAT_DIR#$REPO/}"
  echo "   [run ] $step: $*"
  STEP_RC=0
  STEP_OUT="$("$@")" || STEP_RC=$?
  [[ -n "$STEP_OUT" ]] && printf '%s\n' "$STEP_OUT"
  [[ -n "${RUN_ID:-}" ]] && hash_run=(--hash-root "appsec-review-process/runs/$RUN_ID")
  python3 "$CONTRACT_PY" snapshot "$SAT_DIR/snap/$stage.$step.after.json" --repo "$REPO" "${hash_run[@]}" \
    --hash-root "fixtures/targets/$FIXTURE" --exclude "${SAT_DIR#$REPO/}"
  post="$(python3 "$CONTRACT_PY" post --repo "$REPO" --contract "$contract" --vars "$(step_vars)" \
          --before "$SAT_DIR/snap/$stage.$step.before.json" --after "$SAT_DIR/snap/$stage.$step.after.json" \
          --exit "$STEP_RC" --report "$SAT_DIR/steps/$stage.$step.post.json")" \
    || die "$stage/$step: post-contract failed: $(printf '%s' "$post" | python3 -c 'import json,sys; print("; ".join(json.load(sys.stdin)["problems"]))') (report ${SAT_DIR#$REPO/}/steps/$stage.$step.post.json)"
  echo "   [post] $step: $(printf '%s' "$post" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("exit as expected; wrote %d file(s), deleted %d, all within contract; %d output(s) valid%s" % (d["written"], d["deleted"], d["outputs_validated"], ("; %d ambient change(s) ignored" % d["ambient"]) if d["ambient"] else ""))')"
}

launch_status() {  # parse STEP_OUT from launch_job.py -> LAUNCH_STATUS, LAUNCH_DAGSTER
  LAUNCH_STATUS="$(printf '%s' "$STEP_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || true)"
  LAUNCH_DAGSTER="$(printf '%s' "$STEP_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("dagster_run_id",""))' 2>/dev/null || true)"
}
dagster_url() { echo "${LAUNCH_DAGSTER:+http://127.0.0.1:3000/runs/$LAUNCH_DAGSTER}${LAUNCH_DAGSTER:-none (see runs/$RUN_ID/data/orchestration/launches/)}"; }
launch() { "$CL" run -B "$REPO/appsec-review-process/launch_job.py" --run-id "$RUN_ID" --job "$1" --wait --timeout "$SAT_JOB_TIMEOUT"; }

require_run() {
  RUN_ID="$(sat_get run_id)"
  [[ -n "$RUN_ID" ]] || die "$1: this SAT has no run yet (stage run-create)"
  RUN_DIR="$REPO/appsec-review-process/runs/$RUN_ID"
  [[ -d "$RUN_DIR" ]] || die "$1: run folder $RUN_DIR is missing"
}

checkout_unchanged() {  # checkout_unchanged <stage>
  local target="$REPO/fixtures/targets/$FIXTURE"
  [[ "$(git -C "$target" rev-parse HEAD)" == "$PIN" && -z "$(git -C "$target" status --porcelain --untracked-files=all)" ]] \
    || die "$1: the checkout changed (HEAD or local files)"
}

# Writes every Dagster-launched command may make besides its job's own files: the launch request
# (launch_job.py) and the ops' orchestration records under data/orchestration/dagster/<dagster run>/.
LAUNCH_WRITES='"{run}/data/orchestration/launches/*/request.json", "{run}/data/orchestration/launches/*/request.lock", "{run}/data/orchestration/dagster/*"'

# ---- fixtures ------------------------------------------------------------------------------------
fixture_entry() {  # name|origin|pin from fixtures/populate-targets.sh, the single source of the pin
  local line; line="$(grep -E "^[[:space:]]*\"$1\|" "$REPO/fixtures/populate-targets.sh" | head -1 | tr -d ' "')"
  [[ -n "$line" ]] || die "fixture '$1' is not listed in fixtures/populate-targets.sh"
  echo "$line"
}

# ---- stage: sut-checkout -------------------------------------------------------------------------
stage_sut_checkout() {
  local name url pin dest
  IFS='|' read -r name url pin <<< "$(fixture_entry "$FIXTURE")"
  dest="$REPO/fixtures/targets/$name"; PIN="$pin"

  if [[ -e "$dest" ]]; then
    # Pre: only a clean clone of the expected origin may be removed.
    [[ -d "$dest/.git" ]] || die "sut-checkout: $dest exists and is not a git clone; move it aside"
    [[ "$(git -C "$dest" remote get-url origin)" == "$url" ]] || die "sut-checkout: $dest has another origin; refusing to delete"
    [[ -z "$(git -C "$dest" status --porcelain --untracked-files=all)" ]] || die "sut-checkout: $dest has local changes; refusing to delete"
    run_step sut-checkout remove "$(contract sut-checkout remove <<'JSON'
{"inputs": [{"path": "{target}", "kind": "dir"}],
 "writes": {"allowed": [], "required": [], "deletes": ["{target}/*"]}}
JSON
)" rm -rf -- "$dest"
    [[ ! -e "$dest" ]] || die "sut-checkout: $dest still exists after removal"
  fi

  run_step sut-checkout clone "$(contract sut-checkout clone <<'JSON'
{"inputs": [{"path": "fixtures/populate-targets.sh", "kind": "file"}, {"path": "{target}", "kind": "absent"}],
 "writes": {"allowed": ["{target}/*"], "required": ["{target}/configure.ac", "{target}/Makefile.am", "{target}/src/*"], "deletes": []}}
JSON
)" "$REPO/fixtures/populate-targets.sh" "$name"

  local head tree files comments
  head="$(git -C "$dest" rev-parse HEAD)"
  [[ "$head" == "$pin" ]] || die "sut-checkout: HEAD $head, expected pin $pin"
  [[ -z "$(git -C "$dest" status --porcelain --untracked-files=all)" ]] || die "sut-checkout: fresh clone is not clean"
  [[ "$(git -C "$dest" remote get-url origin)" == "$url" ]] || die "sut-checkout: origin mismatch after clone"
  tree="$(git -C "$dest" rev-parse "HEAD^{tree}")"
  files="$(git -C "$dest" ls-files | wc -l | tr -d ' ')"
  # Exactly the tracked files were written (nothing generated, nothing extra).
  local written; written="$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(len(r["written"]))' "$SAT_DIR/steps/sut-checkout.clone.post.json")"
  [[ "$written" == "$files" ]] || die "sut-checkout: clone wrote $written files, the revision tracks $files"
  [[ ! -e "$dest/docs/VULNERABILITIES.md" ]] || die "sut-checkout: docs/VULNERABILITIES.md is present on the pinned revision"
  comments="$(grep -rnE 'VULN|CWE-[0-9]+' "$dest/src" 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$comments" == 0 ]] || die "sut-checkout: $comments defect-identifying comment(s) in src/"

  record PASS sut-checkout "$(python3 -c 'import json,sys; print(json.dumps(dict(zip(["fixture","path","origin","pin","head","tree","tracked_files","answer_key","defect_comments_in_src"], sys.argv[1:]))))' \
    "$name" "fixtures/targets/$name" "$url" "$pin" "$head" "$tree" "$files" absent "$comments")"
  echo "sut-checkout: PASS  $name at ${head:0:7} (tree ${tree:0:7}); wrote exactly its $files tracked files; clean; no answer key"
}

# ---- stage: services -----------------------------------------------------------------------------
graphql() {
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
compose_states() {
  "${COMPOSE[@]}" ps --format json | python3 -c '
import json, sys
text = sys.stdin.read().strip()
rows = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
print(" ".join("%s=%s/%s" % (r["Service"], r.get("State"), r.get("Health") or "-") for r in sorted(rows, key=lambda r: r["Service"])))'
}

stage_services() {
  local dagster="$REPO/orchestrator/dagster"
  COMPOSE=(docker compose -f "$dagster/compose.yaml")

  local engine rc=0 why
  command -v docker >/dev/null || die "services: no 'docker' command in this shell (Docker Desktop WSL integration off for this distro?)"
  engine="$(timeout "${SAT_DOCKER_TIMEOUT:-60}" docker version --format '{{.Server.Version}}' 2>&1)" || rc=$?
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
  local engine_os
  engine_os="$(timeout 30 docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
  if [[ "$engine_os" == "Docker Desktop" ]] && systemctl is-active --quiet docker 2>/dev/null; then
    die "services: Docker Desktop answers, but a native docker service is also active in this distro; they
  compete for /var/run/docker.sock. Run: sudo systemctl disable --now docker.service docker.socket containerd.service"
  fi
  engine="$engine ($engine_os)"
  echo "docker engine $engine"

  local env_host wsl_ip=""
  env_host="$(sed -n 's/^APPSEC_CODE_LOCATION_HOST=//p' "$dagster/.env" 2>/dev/null | tr -d '\r')"
  if [[ "$(wslinfo --networking-mode 2>/dev/null)" == nat ]]; then
    wsl_ip="$(ip -4 -o addr show dev eth0 | awk '{split($4,a,"/"); print a[1]; exit}')"
    [[ "$env_host" == "$wsl_ip" ]] || die "services: .env APPSEC_CODE_LOCATION_HOST=${env_host:-unset}, but this WSL boot's IP is $wsl_ip.
  Restart the code location (orchestrator/dagster/code-location.sh start) so it rewrites .env, then re-run."
  fi

  # compose up: reads the compose file and settings; writes nothing in the repository.
  run_step services compose-up "$(contract services compose-up <<'JSON'
{"inputs": [{"path": "orchestrator/dagster/compose.yaml", "kind": "file"}, {"path": "orchestrator/dagster/.env", "kind": "file"},
            {"path": "orchestrator/dagster/workspace.yaml", "kind": "file"}, {"path": "orchestrator/dagster/dagster.yaml", "kind": "file"}],
 "writes": {"allowed": [], "required": [], "deletes": []}}
JSON
)" "${COMPOSE[@]}" up -d
  local deadline=$((SECONDS + 240)) states svc ok
  while :; do
    states="$(compose_states)"; ok=1
    for svc in postgres webserver daemon; do [[ " $states " == *" $svc=running/healthy "* ]] || ok=0; done
    [[ $ok == 1 ]] && break
    (( SECONDS < deadline )) || die "services: not healthy after 240 s: $states"
    sleep 5
  done
  echo "compose: $states"

  local resolved
  resolved="$("${COMPOSE[@]}" exec -T webserver getent ahostsv4 host.docker.internal | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/ $//')"
  if [[ -n "$wsl_ip" && " $resolved " != *" $wsl_ip "* ]]; then
    die "services: in the webserver, host.docker.internal resolves (IPv4) to ${resolved:-nothing}, not the code location at $wsl_ip; run: ${COMPOSE[*]} up -d --force-recreate webserver daemon"
  fi
  echo "webserver: host.docker.internal (IPv4) -> $resolved"

  "$CL" check >/dev/null 2>&1 || die "services: host code location not answering on port 4000.
  Start it in its own terminal: orchestrator/dagster/code-location.sh start (wait for 'Started'), then re-run."
  echo "code location: gRPC health OK"

  # reload: reads the job definitions; writes nothing in the repository.
  run_step services reload "$(contract services reload <<'JSON'
{"inputs": [{"path": "orchestrator/dagster/definitions.py", "kind": "file"}, {"path": "appsec-review-process/dagster_workflow.py", "kind": "file"}],
 "writes": {"allowed": [], "required": [], "deletes": []}}
JSON
)" "$CL" reload
  [[ "$STEP_OUT" == *'"loadStatus": "LOADED"'* ]] || die "services: code location did not report LOADED: $STEP_OUT"

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

# ---- stage: run-create ---------------------------------------------------------------------------
stage_run_create() {
  RUN_ID=""
  run_step run-create start "$(contract run-create start <<'JSON'
{"inputs": [{"path": "appsec-review-process/process-manifest.json", "kind": "file", "nonempty": ["process_order"]},
            {"path": "appsec-review-process/templates/artifact-manifest.template.json", "kind": "file",
             "equals": {"schema": "appsec-review-process/artifact-manifest/0.1", "run_id": ""}}],
 "writes": {"required": ["appsec-review-process/runs/*/run-status.json", "appsec-review-process/runs/*/run-status.md",
                         "appsec-review-process/runs/*/events.jsonl", "appsec-review-process/runs/*/inputs/artifact-manifest.json"],
            "allowed": [], "deletes": []},
 "outputs": [{"path": "appsec-review-process/runs/*/run-status.json", "equals": {"schema": "appsec-review-process/run-status/0.1", "status": "READY", "completed_processes": []}, "nonempty": ["run_id", "process_order", "resume_from"]}]}
JSON
)" "$CL" run -B "$REPO/appsec-review-process/run_process.py" --start

  local run_id
  run_id="$(printf '%s' "$STEP_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')" || die "run-create: no run_id in: $STEP_OUT"
  [[ "$run_id" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]] || die "run-create: unexpected run id '$run_id'"
  # All four writes belong to this one new run.
  python3 - "$SAT_DIR/steps/run-create.start.post.json" "$run_id" <<'PY' || die "run-create: writes outside the new run"
import json, sys
r = json.load(open(sys.argv[1])); prefix = 'appsec-review-process/runs/%s/' % sys.argv[2]
amb = set(r['ambient'])
added = [p for p in r['added'] if p not in amb]
bad = sorted(p for p in r['written'] if not p.startswith(prefix) or p not in added)
if bad or len(r['written']) != 4: sys.exit('unexpected: %r (wrote %d)' % (bad, len(r['written'])))
PY
  RUN_ID="$run_id"; RUN_DIR="$REPO/appsec-review-process/runs/$RUN_ID"
  for d in data inputs outputs; do [[ -d "$RUN_DIR/$d" ]] || die "run-create: $RUN_DIR/$d missing"; done

  local summary
  summary="$(python3 - "$RUN_DIR" "$RUN_ID" "$REPO/appsec-review-process/process-manifest.json" "$REPO/appsec-review-process/templates/artifact-manifest.template.json" <<'PY'
import json, sys, pathlib, filecmp
rdir, run_id, manifest, template = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
s = json.loads((rdir / 'run-status.json').read_text())
bad = []
if s.get('run_id') != run_id: bad.append('run-status run_id %r' % s.get('run_id'))
order = json.loads(open(manifest).read())['process_order']
if s.get('resume_from') != order[0]: bad.append('resume_from %r, manifest starts %r' % (s.get('resume_from'), order[0]))
events = [json.loads(l) for l in (rdir / 'events.jsonl').read_text().splitlines() if l.strip()]
if [(e.get('event'), e.get('run_id')) for e in events] != [('RUN_CREATED', run_id)]: bad.append('events %r' % events)
if not filecmp.cmp(template, rdir / 'inputs/artifact-manifest.json', shallow=False): bad.append('manifest is not the unfilled template')
if f'`{run_id}`' not in (rdir / 'run-status.md').read_text(): bad.append('run-status.md does not name the run')
if bad: sys.exit('; '.join(bad))
print(json.dumps({'status': s['status'], 'created_at': s['created_at'], 'resume_from': s['resume_from'], 'lanes': len(s['process_order'])}))
PY
)" || die "run-create: $summary"

  sat_set run_id "$RUN_ID"
  record PASS run-create "$(python3 -c 'import json,sys; e=json.loads(sys.argv[3]); e.update(run_id=sys.argv[1], run_dir=sys.argv[2], artifact_manifest="template"); print(json.dumps(e))' \
    "$RUN_ID" "appsec-review-process/runs/$RUN_ID" "$summary")"
  echo "run-create: PASS  run $RUN_ID (READY); wrote exactly run-status.json, run-status.md, events.jsonl and the template manifest"
}

# ---- stage: stage-inputs -------------------------------------------------------------------------
stage_stage_inputs() {
  require_run stage-inputs
  local target="$REPO/fixtures/targets/$FIXTURE"
  run_step stage-inputs stage "$(contract stage-inputs stage <<'JSON'
{"inputs": [{"path": "{run}/run-status.json", "kind": "file", "equals": {"run_id": "{run_id}", "status": "READY"}},
            {"path": "{run}/inputs/artifact-manifest.json", "kind": "file", "equals": {"run_id": ""}},
            {"path": "{target}", "kind": "dir"}],
 "writes": {"required": ["{run}/inputs/artifact-manifest.json"],
            "allowed": ["{run}/data/publication.lock", "{run}/run-status.json", "{run}/run-status.md",
                        "{run}/processes/00-intake-recovery/status.json"],
            "deletes": []},
 "outputs": [{"path": "{run}/inputs/artifact-manifest.json",
              "equals": {"orchestration_version": 1, "run_id": "{run_id}", "project": "{fixture}",
                         "intake_config.executor_platform": "posix", "intake_config.permissions": ["read-source"],
                         "intake_config.imports": [], "intake_config.compile_database": null, "artifact_hashes": {},
                         "intake_config.engagement_relative": "pending-evidence", "scope": {"include": ["**"], "exclude": []}},
              "nonempty": ["intake_config.target", "intake_config.business_goal", "intake_config.platforms"]}]}
JSON
)" "$CL" run -B "$REPO/appsec-review-process/stage_artifacts.py" --run-id "$RUN_ID" --project "$FIXTURE" \
     --target "$target" --business-goal "$SAT_BUSINESS_GOAL" --platform "$SAT_PLATFORM" \
     --budget "$SAT_BUDGET" --execution-environment "$SAT_EXECUTION_ENVIRONMENT"

  local summary
  summary="$(python3 - "$RUN_DIR" "$(realpath "$target")" "$SAT_BUSINESS_GOAL" "$SAT_PLATFORM" "$SAT_BUDGET" "$SAT_EXECUTION_ENVIRONMENT" <<'PY'
import hashlib, json, sys, pathlib
rdir, target, goal, platform, budget, env = sys.argv[1:]
rdir = pathlib.Path(rdir); path = rdir / 'inputs' / 'artifact-manifest.json'
m = json.loads(path.read_text()); c = m['intake_config']
want = {'target': target, 'business_goal': goal, 'platforms': [platform], 'budget': budget, 'execution_environment': env}
bad = ['%s=%r (expected %r)' % (k, c.get(k), v) for k, v in want.items() if c.get(k) != v]
if json.loads((rdir / 'run-status.json').read_text()).get('status') != 'READY': bad.append('run-status not READY')
if bad: sys.exit('manifest: ' + '; '.join(bad))
print(json.dumps({**want, 'executor_platform': 'posix', 'permissions': ['read-source'], 'supplied_evidence': 0,
                  'pregather_expected_notes': len(m.get('notes', [])), 'manifest_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}))
PY
)" || die "stage-inputs: $summary"
  record PASS stage-inputs "$summary"
  echo "stage-inputs: PASS  manifest for $FIXTURE on posix: platform $SAT_PLATFORM, budget $SAT_BUDGET, read-source only, no supplied evidence"
}

# ---- stage: engagement-workflow ------------------------------------------------------------------
# Step 2 of the engagement: configuration, atomic intake (executed here, not reused), three parallel
# preparation branches and a validated join.
stage_engagement_workflow() {
  require_run engagement-workflow
  run_step engagement-workflow launch "$(contract engagement-workflow launch <<JSON
{"inputs": [{"path": "{run}/inputs/artifact-manifest.json", "kind": "file",
             "equals": {"orchestration_version": 1, "run_id": "{run_id}", "intake_config.executor_platform": "posix"}},
            {"path": "{run}/data/jobs/00-intake/whole/accepted.json", "kind": "absent"},
            {"path": "{run}/data/workflows/engagement/accepted.json", "kind": "absent"},
            {"path": "appsec-review-process/workflow-plan.json", "kind": "file", "equals": {"job": "engagement_workflow"}},
            {"path": "{target}", "kind": "dir"}],
 "writes": {"required": ["{run}/data/jobs/00-intake/whole/accepted.json", "{run}/data/jobs/00-intake/whole/attempts/*/outputs/intake.json",
                         "{run}/data/workflows/engagement/accepted.json",
                         "{run}/data/jobs/00-workflow-preparation/scope_check/accepted.json",
                         "{run}/data/jobs/00-workflow-preparation/native_plan_check/accepted.json",
                         "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/accepted.json"],
            "allowed": ["{run}/data/jobs/00-intake/whole/accepted.json", "{run}/data/jobs/00-intake/whole/latest.json", "{run}/data/jobs/00-intake/whole/job.lock", "{run}/data/jobs/00-intake/whole/attempts/*/inputs.json", "{run}/data/jobs/00-intake/whole/attempts/*/status.json", "{run}/data/jobs/00-intake/whole/attempts/*/evidence/source.json", "{run}/data/jobs/00-intake/whole/attempts/*/logs/*", "{run}/data/jobs/00-intake/whole/attempts/*/outputs/intake.json", "{run}/data/jobs/00-intake/whole/attempts/*/outputs/build-discovery.md", "{run}/data/jobs/00-intake/whole/attempts/*/validation/*/status.json", "{run}/data/jobs/00-intake/whole/attempts/*/validation/*/stdout.log", "{run}/data/jobs/00-intake/whole/attempts/*/validation/*/stderr.log", "{run}/data/jobs/00-workflow-preparation/scope_check/accepted.json", "{run}/data/jobs/00-workflow-preparation/scope_check/latest.json", "{run}/data/jobs/00-workflow-preparation/scope_check/job.lock", "{run}/data/jobs/00-workflow-preparation/scope_check/attempts/*/inputs.json", "{run}/data/jobs/00-workflow-preparation/scope_check/attempts/*/output.json", "{run}/data/jobs/00-workflow-preparation/scope_check/attempts/*/pre.json", "{run}/data/jobs/00-workflow-preparation/scope_check/attempts/*/post.json", "{run}/data/jobs/00-workflow-preparation/scope_check/attempts/*/status.json", "{run}/data/jobs/00-workflow-preparation/scope_check/attempts/*/logs/*", "{run}/data/jobs/00-workflow-preparation/native_plan_check/accepted.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/latest.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/job.lock", "{run}/data/jobs/00-workflow-preparation/native_plan_check/attempts/*/inputs.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/attempts/*/output.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/attempts/*/pre.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/attempts/*/post.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/attempts/*/status.json", "{run}/data/jobs/00-workflow-preparation/native_plan_check/attempts/*/logs/*", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/accepted.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/latest.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/job.lock", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/attempts/*/inputs.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/attempts/*/output.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/attempts/*/pre.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/attempts/*/post.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/attempts/*/status.json", "{run}/data/jobs/00-workflow-preparation/discovery_handoffs/attempts/*/logs/*", "{run}/data/workflows/engagement/accepted.json", "{run}/data/workflows/engagement/status.json", "{run}/data/workflows/engagement/attempts/*/result.json", "{run}/data/workflows/engagement/attempts/*/config.json", "{run}/data/events.jsonl", "{run}/data/publication.lock", "{run}/inputs/artifact-manifest.json", "{run}/processes/00-intake-recovery/status.json", "{run}/run-status.json", "{run}/run-status.md", $LAUNCH_WRITES],
            "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/00-intake/whole/attempts/*/outputs/intake.json", "schema": "intake.schema.json"},
             {"path": "{run}/data/jobs/00-intake/whole/accepted.json", "equals": {"status": "OK", "contract": "intake"}},
             {"path": "{run}/data/workflows/engagement/accepted.json", "equals": {"status": "OK", "downstream_execution": "PLANNED_NOT_EXECUTED"}},
             {"path": "{run}/data/jobs/00-workflow-preparation/*/attempts/*/output.json", "equals": {"findings": [], "target_execution": false}, "min": 3}]}
JSON
)" launch engagement_workflow
  launch_status
  [[ $STEP_RC == 0 && "$LAUNCH_STATUS" == SUCCESS ]] || die "engagement-workflow: status ${LAUNCH_STATUS:-unknown} (exit $STEP_RC). Dagster run: $(dagster_url)"

  local inspect
  inspect="$("$CL" run -B -c 'import json, sys; sys.path.insert(0, sys.argv[1]); import workflow; print(json.dumps(workflow.inspect_status(sys.argv[2])))' \
    "$REPO/appsec-review-process" "$RUN_ID")" || die "engagement-workflow: workflow.inspect_status failed: $inspect"
  echo "inspect_status: $inspect"

  local summary
  summary="$(python3 - "$RUN_DIR" "$LAUNCH_DAGSTER" "$inspect" "$PIN" "$(evidence_of sut-checkout tracked_files)" "$SAT_BUSINESS_GOAL" "$SAT_PLATFORM" "$SAT_BUDGET" <<'PY'
import hashlib, json, pathlib, sys
rdir, dagster_id, inspect, head, files, goal, platform, budget = sys.argv[1:]
rdir = pathlib.Path(rdir); inspect = json.loads(inspect)
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
bad = []
if inspect.get('status') != 'OK': bad.append('inspect_status %r: %s' % (inspect.get('status'), inspect.get('error')))
# Intake: executed by this workflow run (not reused), latest, unchanged since acceptance.
base = rdir / 'data/jobs/00-intake/whole'
ptr = json.loads((base / 'accepted.json').read_text())
if ptr.get('dagster_run_id') != dagster_id: bad.append('intake accepted by %r, launched %r' % (ptr.get('dagster_run_id'), dagster_id))
if json.loads((base / 'latest.json').read_text()).get('attempt_id') != ptr['attempt_id']: bad.append('intake attempt is not the latest')
att = base / 'attempts' / ptr['attempt_id']
if sha(att / 'status.json') != ptr.get('status_sha256'): bad.append('intake status.json differs from its pointer')
for rel, h in ptr.get('hashes', {}).items():
    if sha(att / rel) != h: bad.append('intake output changed since acceptance: ' + rel)
events = [json.loads(l) for l in (rdir / 'data/events.jsonl').read_text().splitlines() if l.strip()]
if not any(e.get('event') == 'ACCEPTED' and e.get('attempt_id') == ptr['attempt_id'] for e in events): bad.append('no ACCEPTED event for the intake attempt')
if any(e.get('event') == 'REUSE' for e in events): bad.append('intake was reused; a fresh run must execute it')
r = json.loads((att / 'outputs/intake.json').read_text())
exp = {'source_revision': head, 'business_goal': goal, 'platforms': [platform], 'budget': budget,
       'permissions': ['read-source'], 'ready_to_collect': True, 'pregather_complete': False, 'findings': []}
bad += ['intake %s=%r (expected %r)' % (k, r.get(k), v) for k, v in exp.items() if r.get(k) != v]
if len(r['scope']['all_paths']) != int(files): bad.append('intake saw %d files, the clone has %s' % (len(r['scope']['all_paths']), files))
n = r['native']
if n.get('build_status') != 'NOT_EXECUTED' or n.get('commands_attempted'): bad.append('intake executed build commands')
jobs = {j['job']: j.get('applicability') for j in r['selected_jobs']}
for j in ('02-repository-partition-discovery', '02-dev-project-discovery'):
    if jobs.get(j) != 'required': bad.append('%s applicability %r' % (j, jobs.get(j)))
m = json.loads((rdir / 'inputs/artifact-manifest.json').read_text())
if m.get('accepted_intake') != ptr: bad.append('manifest accepted_intake differs from the pointer')
if m.get('source_identity', {}).get('revision') != head: bad.append('manifest source_identity revision')
# Workflow: published by this run, joined exactly the three branches, on this intake.
w = json.loads((rdir / 'data/workflows/engagement/accepted.json').read_text())
if w.get('dagster_run_id') != dagster_id: bad.append('workflow published by %r' % w.get('dagster_run_id'))
if w.get('intake') != ptr: bad.append('workflow joined another intake')
names = sorted(b['branch'] for b in w.get('branches', []))
if names != ['discovery_handoffs', 'native_plan_check', 'scope_check']: bad.append('branches %r' % names)
outs = {b['branch']: json.loads((rdir / 'data/jobs/00-workflow-preparation' / b['branch'] / 'attempts' / b['attempt_id'] / 'output.json').read_text()) for b in w['branches']}
hand = outs['discovery_handoffs'].get('jobs', [])
if not hand or any(j.get('status') != 'PLANNED_NOT_EXECUTED' for j in hand): bad.append('discovery hand-offs not all PLANNED_NOT_EXECUTED')
if bad: sys.exit('; '.join(bad))
print(json.dumps({'dagster_run_id': dagster_id, 'intake_attempt_id': ptr['attempt_id'], 'source_revision': head,
                  'source_fingerprint': r['source_fingerprint'], 'files_fingerprinted': len(r['scope']['all_paths']),
                  'families': r['families'], 'native_applicable': n.get('applicable'), 'native_strategy': n.get('strategy', {}).get('method'),
                  'selected_jobs': jobs, 'branches': {b['branch']: b['attempt_id'] for b in w['branches']},
                  'planned_jobs': {j['job']: j['applicability'] for j in hand}, 'next_job': w.get('next_job')}))
PY
)" || die "engagement-workflow: $summary"
  checkout_unchanged engagement-workflow
  record PASS engagement-workflow "$summary"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("engagement-workflow: PASS  Dagster %s: intake executed (attempt %s; revision %s; %d files; families %s; build not executed; no findings); branches %s joined; %d discovery jobs planned" % (
  s["dagster_run_id"][:8], s["intake_attempt_id"], s["source_revision"][:7], s["files_fingerprinted"], ", ".join(sorted(s["families"])), ", ".join(sorted(s["branches"])), len(s["planned_jobs"])))'
}

# ---- gates: shared steps -------------------------------------------------------------------------
gate_handoff() {  # gate_handoff <stage> <job id> <dagster job> <schema>  -> HANDOFF_STATE, HANDOFF_DAGSTER
  local jobdir="$RUN_DIR/data/jobs/$2"
  HANDOFF_DAGSTER=""
  if [[ -e "$jobdir/supplied/result.json" ]]; then
    echo "-- handoff: skipped, a supplied result already exists for this run (stage re-run)"
    HANDOFF_STATE="skipped-already-supplied"; return 0
  fi
  echo "-- handoff: the gate with nothing supplied must fail with a hand-off and accept nothing"
  run_step "$1" handoff "$(contract "$1" handoff <<JSON
{"inputs": [{"path": "{run}/data/jobs/00-intake/whole/accepted.json", "kind": "file", "equals": {"status": "OK"}},
            {"path": "{run}/data/jobs/$2/supplied/result.json", "kind": "absent"}],
 "exit": 1,
 "writes": {"required": ["{run}/data/jobs/$2/handoff.md", "{run}/data/jobs/$2/handoff.json"],
            "allowed": ["{run}/data/jobs/$2/handoff/latest-handoff.json", "{run}/data/jobs/$2/handoff/handoffs/*.json", "{run}/data/jobs/$2/job.lock",
                        "{run}/data/jobs/$2/accepted.json", "{run}/data/jobs/$2/latest.json",
                        "{run}/data/jobs/$2/attempts/*/inputs.json", "{run}/data/jobs/$2/attempts/*/result.json", "{run}/data/jobs/$2/attempts/*/status.json",
                        $LAUNCH_WRITES], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$2/attempts/*/result.json", "schema": "worker-result-envelope.schema.json", "min": 0},
             {"path": "{run}/data/jobs/$2/handoff/handoffs/*.json", "nonempty": ["identity", "composition", "inputs", "input_fingerprint", "claim_class"]},
             {"path": "{run}/data/jobs/$2/handoff.json", "equals": {"job": "$2", "expected_schema": "$4.schema.json"}, "nonempty": ["expected_path", "resolved_handoff"]}]}
JSON
)" launch "$3"
  launch_status
  [[ "$LAUNCH_STATUS" == FAILURE ]] || die "$1: with nothing supplied the gate ended ${LAUNCH_STATUS:-unknown}, expected FAILURE. Dagster run: $(dagster_url)"
  python3 - "$jobdir" <<'PY' || die "$1: hand-off check failed"
import json, pathlib, sys
d = pathlib.Path(sys.argv[1])
h = json.loads((d / 'handoff.json').read_text())
if not h['expected_path'].endswith('supplied/result.json'): sys.exit('hand-off names %r' % h['expected_path'])
if h['expected_path'] not in (d / 'handoff.md').read_text(): sys.exit('handoff.md does not name the expected path')
if not pathlib.Path(h['resolved_handoff']).is_file(): sys.exit('resolved hand-off %s missing' % h['resolved_handoff'])
acc = d / 'accepted.json'
if acc.exists() and json.loads(acc.read_text()).get('status') == 'OK': sys.exit('a result was accepted with nothing supplied')
print('hand-off issued: names %s and its schema; nothing accepted' % h['expected_path'])
PY
  HANDOFF_DAGSTER="$LAUNCH_DAGSTER"; HANDOFF_STATE="issued"
}

gate_supply() {  # gate_supply <stage> <job id> <schema>: install the fixture's recorded analysis
  echo "-- supply: install the recorded analysis"
  run_step "$1" supply "$(contract "$1" supply <<JSON
{"inputs": [{"path": "fixtures/supplied/{fixture}/$2.json", "kind": "file", "schema": "$3.schema.json", "equals": {"source_revision": "{pin}"}},
            {"path": "{run}/inputs/artifact-manifest.json", "kind": "file", "nonempty": ["target.repo_path"]},
            {"path": "{run}/data/jobs/$2/supplied/result.json", "kind": "absent"}],
 "writes": {"required": ["{run}/data/jobs/$2/supplied/result.json"], "allowed": [], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$2/supplied/result.json", "schema": "$3.schema.json"}]}
JSON
)" "$CL" run -B "$REPO/fixtures/supply_record.py" --run-id "$RUN_ID" --job "$2" --fixture "$FIXTURE"
  cmp -s "$REPO/fixtures/supplied/$FIXTURE/$2.json" "$RUN_DIR/data/jobs/$2/supplied/result.json" || die "$1: supplied file differs from the fixture record"
}

gate_dispatch_mode() {  # gate_dispatch_mode <stage> <job id>: opt this run into D01's automatic
                        # persona dispatch for <job id> (discovery_gate.set_dispatch_mode), before
                        # any launch -- discovery_gate.run()'s own external signature never changes;
                        # this only writes the run-scoped dispatch-mode.json it reads internally.
  local already
  already="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except OSError:
    print("0"); sys.exit()
print("1" if d.get(sys.argv[2]) == "automatic" else "0")' "$RUN_DIR/data/dispatch-mode.json" "$2" 2>/dev/null || echo 0)"
  if [[ "$already" == 1 ]]; then
    echo "-- dispatch-mode: already automatic for $2 (stage re-run)"
    return 0
  fi
  echo "-- dispatch-mode: opt this run into automatic persona dispatch for $2 (real model call, not a fixture copy)"
  run_step "$1" dispatch-mode "$(contract "$1" dispatch-mode <<JSON
{"inputs": [{"path": "{run}/data/jobs/$2/supplied/result.json", "kind": "absent"}],
 "writes": {"required": ["{run}/data/dispatch-mode.json"], "allowed": [], "deletes": []},
 "outputs": [{"path": "{run}/data/dispatch-mode.json", "equals": {"$2": "automatic"}}]}
JSON
)" "$CL" run -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import discovery_gate; discovery_gate.set_dispatch_mode(sys.argv[2], sys.argv[3], "automatic"); print("dispatch mode: automatic for", sys.argv[3])' \
    "$REPO/appsec-review-process" "$RUN_ID" "$2"
}

gate_validate() {  # the project's own validator for an accepted gate result
  "$CL" run -B -c 'import sys; sys.path.insert(0, sys.argv[1]); import discovery_gate; discovery_gate.validate(sys.argv[2], sys.argv[3]); print("validator OK")' \
    "$REPO/appsec-review-process" "$RUN_ID" "$1"
}

citations_fresh() {  # citations_fresh <json file>: every source-file citation hash matches the checkout
  python3 - "$1" "$REPO/fixtures/targets/$FIXTURE" <<'PY'
import hashlib, json, pathlib, sys
value, target = json.loads(pathlib.Path(sys.argv[1]).read_text()), pathlib.Path(sys.argv[2])
count, stale = [0], []
def walk(v):
    if isinstance(v, dict):
        if v.get('source_type') == 'source_file' and v.get('content_hash'):
            count[0] += 1; f = target / v['path']
            if not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != v['content_hash']: stale.append(v['path'])
        for x in v.values(): walk(x)
    elif isinstance(v, list):
        for x in v: walk(x)
walk(value)
if stale: sys.exit('stale citations: ' + ', '.join(sorted(set(stale))))
if not count[0]: sys.exit('no source-file citations')
print(count[0])
PY
}

# ---- stage: partition-discovery ------------------------------------------------------------------
# Default (mode "supplied"): the pre-D01 gate/schema/chaining proof -- hand-off with nothing
# supplied, then the fixture's recorded analysis installed and accepted.
# --dispatch (mode "automatic", D01 item 6): no supplied file is ever installed; the run opts into
# discovery_gate.py's automatic-dispatch path (item 5) before the one launch, which dispatches a
# REAL live persona invocation (claude_cli_invoker.ClaudeCliInvoker) against the staged checkout --
# not a copy of a hand-authored fixture. The accept check changes accordingly: it can no longer
# byte-compare the live result against the fixture's answer key (a real model call has no reason to
# reproduce a human's exact partition IDs or wording), so acceptance is schema conformance
# (already required by discovery_gate itself), fresh evidence citations against the live checkout
# (citations_fresh, unchanged), and structural completeness of the routing table and coverage
# checks. A diff against the fixture answer key is still computed and logged, but only as an
# informational note -- never a pass/fail gate (per the plan: "comparing against the fixture record
# becomes an optional informational diff, never a pass/fail gate").
stage_partition_discovery() {
  require_run partition-discovery
  local handoff_state="" handoff_dagster=""

  if [[ "$PARTITION_DISPATCH" == 1 ]]; then
    gate_dispatch_mode partition-discovery "$PARTITION_JOB"
    handoff_state="automatic-dispatch"

    echo "-- accept: the automatic-dispatch gate must succeed (live persona invocation)"
    run_step partition-discovery accept "$(contract partition-discovery accept <<JSON
{"inputs": [{"path": "{run}/data/dispatch-mode.json", "kind": "file", "equals": {"$PARTITION_JOB": "automatic"}},
            {"path": "{run}/data/jobs/$PARTITION_JOB/supplied/result.json", "kind": "absent"},
            {"path": "{run}/data/jobs/00-intake/whole/accepted.json", "kind": "file", "equals": {"status": "OK"}}],
 "writes": {"required": ["{run}/data/jobs/$PARTITION_JOB/accepted.json", "{run}/data/jobs/$PARTITION_JOB/attempts/*/repository-partition-map.json"],
            "allowed": ["{run}/data/jobs/$PARTITION_JOB/latest.json", "{run}/data/jobs/$PARTITION_JOB/job.lock",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/inputs.json", "{run}/data/jobs/$PARTITION_JOB/attempts/*/repository-partition-summary.md",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/result.json", "{run}/data/jobs/$PARTITION_JOB/attempts/*/status.json",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/failure-result.json",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/outputs/persona/*", "{run}/data/jobs/$PARTITION_JOB/attempts/*/logs/persona/*",
                        "{run}/data/model-versions.json", "{run}/data/claude-binary.json", "{run}/data/*.jsonl",
                        "appsec-review-process/prompt-cache/$PARTITION_JOB/outer_prompt.md", $LAUNCH_WRITES], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$PARTITION_JOB/attempts/*/repository-partition-map.json", "schema": "repository-partition-map.schema.json", "equals": {"source_revision": "{pin}"}},
             {"path": "{run}/data/jobs/$PARTITION_JOB/attempts/*/result.json", "schema": "worker-result-envelope.schema.json", "equals": {"execution_status": "OK", "worker_kind": "persona"}},
             {"path": "{run}/data/jobs/$PARTITION_JOB/accepted.json", "equals": {"status": "OK"}}]}
JSON
)" launch repository_partition_discovery
  else
    gate_handoff partition-discovery "$PARTITION_JOB" repository_partition_discovery repository-partition-map
    handoff_state="$HANDOFF_STATE"; handoff_dagster="$HANDOFF_DAGSTER"
    gate_supply partition-discovery "$PARTITION_JOB" repository-partition-map

    echo "-- accept: the gate with the supplied map must succeed"
    run_step partition-discovery accept "$(contract partition-discovery accept <<JSON
{"inputs": [{"path": "{run}/data/jobs/$PARTITION_JOB/supplied/result.json", "kind": "file", "schema": "repository-partition-map.schema.json", "equals": {"source_revision": "{pin}"}},
            {"path": "{run}/data/jobs/00-intake/whole/accepted.json", "kind": "file", "equals": {"status": "OK"}}],
 "writes": {"required": ["{run}/data/jobs/$PARTITION_JOB/accepted.json", "{run}/data/jobs/$PARTITION_JOB/attempts/*/repository-partition-map.json"],
            "allowed": ["{run}/data/jobs/$PARTITION_JOB/latest.json", "{run}/data/jobs/$PARTITION_JOB/handoff.json", "{run}/data/jobs/$PARTITION_JOB/handoff.md",
                        "{run}/data/jobs/$PARTITION_JOB/handoff/latest-handoff.json", "{run}/data/jobs/$PARTITION_JOB/handoff/handoffs/*.json",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/inputs.json", "{run}/data/jobs/$PARTITION_JOB/attempts/*/repository-partition-summary.md",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/result.json", "{run}/data/jobs/$PARTITION_JOB/attempts/*/status.json",
                        "{run}/data/jobs/$PARTITION_JOB/attempts/*/supplied/result.json", $LAUNCH_WRITES], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$PARTITION_JOB/attempts/*/repository-partition-map.json", "schema": "repository-partition-map.schema.json", "equals": {"source_revision": "{pin}"}},
             {"path": "{run}/data/jobs/$PARTITION_JOB/attempts/*/result.json", "schema": "worker-result-envelope.schema.json", "equals": {"execution_status": "OK"}},
             {"path": "{run}/data/jobs/$PARTITION_JOB/attempts/*/supplied/result.json", "schema": "repository-partition-map.schema.json"},
             {"path": "{run}/data/jobs/$PARTITION_JOB/accepted.json", "equals": {"status": "OK"}}]}
JSON
)" launch repository_partition_discovery
  fi
  launch_status
  [[ $STEP_RC == 0 && "$LAUNCH_STATUS" == SUCCESS ]] || die "partition-discovery: status ${LAUNCH_STATUS:-unknown}. Dagster run: $(dagster_url)"
  gate_validate "$PARTITION_JOB" || die "partition-discovery: discovery_gate.validate rejected the accepted result"

  local jobdir="$RUN_DIR/data/jobs/$PARTITION_JOB" attempt map cites summary
  attempt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["attempt_id"])' "$jobdir/accepted.json")"
  map="$jobdir/attempts/$attempt/repository-partition-map.json"
  cites="$(citations_fresh "$map")" || die "partition-discovery: $cites"

  if [[ "$PARTITION_DISPATCH" == 1 ]]; then
    summary="$(python3 - "$jobdir" "$attempt" "$LAUNCH_DAGSTER" "$cites" "$REPO/fixtures/supplied/$FIXTURE/$PARTITION_JOB.json" <<'PY'
import json, pathlib, sys
d, attempt, dagster_id, cites, record_path = sys.argv[1:]
d = pathlib.Path(d); att = d / 'attempts' / attempt
bad = []
status = json.loads((att / 'status.json').read_text())
if status.get('dagster_run_id') != dagster_id: bad.append('accepted by %r, launched %r' % (status.get('dagster_run_id'), dagster_id))
if status.get('dispatch_mode') != 'automatic': bad.append('status.json does not record automatic dispatch')
m = json.loads((att / 'repository-partition-map.json').read_text())
ids = {p['partition_id']: p for p in m.get('partitions', [])}
if not ids: bad.append('the live dispatch produced no partitions at all')
personas = {'developer-engineer', 'devops-engineer', 'sre-engineer'}
for pid, p in ids.items():
    if p.get('primary_persona_id') not in personas: bad.append('partition %s: primary_persona_id %r is not a known persona' % (pid, p.get('primary_persona_id')))
    if not p.get('evidence_citations'): bad.append('partition %s cites no evidence' % pid)
checks = (m.get('coverage') or {}).get('category_checks') or []
if not checks: bad.append('coverage.category_checks is empty -- the routing table is not complete')
for c in checks:
    if c.get('result') not in ('found', 'not-found', 'uninspected'): bad.append('category_check %r has no valid result' % c.get('category'))
if bad: sys.exit('; '.join(bad))
diff_note = ''
try:
    rec = json.loads(pathlib.Path(record_path).read_text())
    rec_ids, live_ids = sorted(p['partition_id'] for p in rec['partitions']), sorted(ids)
    if rec_ids != live_ids:
        diff_note = 'informational only, not a failure: live partitions %s differ from the fixture answer key %s' % (live_ids, rec_ids)
except OSError:
    pass
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': attempt, 'partitions': {k: v.get('disposition') for k, v in ids.items()},
                  'primary_personas': sorted({v.get('primary_persona_id') for v in ids.values()}), 'citations_checked': int(cites),
                  'diff_note': diff_note}))
PY
)" || die "partition-discovery: $summary"
  else
    summary="$(python3 - "$jobdir" "$attempt" "$REPO/fixtures/supplied/$FIXTURE/$PARTITION_JOB.json" "$LAUNCH_DAGSTER" "$cites" <<'PY'
import json, pathlib, sys
d, attempt, record, dagster_id, cites = sys.argv[1:]
d = pathlib.Path(d); att = d / 'attempts' / attempt
bad = []
status = json.loads((att / 'status.json').read_text())
if status.get('dagster_run_id') != dagster_id: bad.append('accepted by %r, launched %r' % (status.get('dagster_run_id'), dagster_id))
m = json.loads((att / 'repository-partition-map.json').read_text()); rec = json.loads(pathlib.Path(record).read_text())
ids = {p['partition_id']: p for p in m['partitions']}
if sorted(ids) != sorted(p['partition_id'] for p in rec['partitions']): bad.append('partitions differ from the record')
if ids.get('docs', {}).get('disposition') != 'deferred': bad.append('docs partition is not deferred')
if bad: sys.exit('; '.join(bad))
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': attempt, 'partitions': {k: v.get('disposition') for k, v in ids.items()},
                  'primary_personas': sorted({v.get('primary_persona_id') for v in ids.values()}), 'citations_checked': int(cites)}))
PY
)" || die "partition-discovery: $summary"
  fi
  checkout_unchanged partition-discovery
  record PASS partition-discovery "$(python3 -c 'import json,sys; e=json.loads(sys.argv[1]); e.update(handoff=sys.argv[2], handoff_dagster_run_id=sys.argv[3] or None); print(json.dumps(e))' "$summary" "$handoff_state" "$handoff_dagster")"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
note = ("; " + s["diff_note"]) if s.get("diff_note") else ""
print("partition-discovery: PASS  hand-off %s; map accepted by Dagster %s: %s; %d citations match the checkout%s" % (
  sys.argv[1], s["dagster_run_id"][:8], ", ".join("%s=%s" % kv for kv in sorted(s["partitions"].items())), s["citations_checked"], note))' "$handoff_state"
}

# ---- stage: dev-project-discovery ----------------------------------------------------------------
# Older gate path: the accepted record carries no output hashes, so the accepted output is compared
# with the supplied file and the fixture record (recorded as a gap in the evidence).
stage_dev_project_discovery() {
  require_run dev-project-discovery
  gate_handoff dev-project-discovery "$DEV_JOB" dev_project_discovery project-discovery
  local handoff_state="$HANDOFF_STATE" handoff_dagster="$HANDOFF_DAGSTER"
  gate_supply dev-project-discovery "$DEV_JOB" project-discovery

  echo "-- accept: the gate with the supplied discovery must succeed"
  run_step dev-project-discovery accept "$(contract dev-project-discovery accept <<JSON
{"inputs": [{"path": "{run}/data/jobs/$DEV_JOB/supplied/result.json", "kind": "file", "schema": "project-discovery.schema.json", "equals": {"source_revision": "{pin}"}},
            {"path": "{run}/data/jobs/$PARTITION_JOB/accepted.json", "kind": "file", "equals": {"status": "OK"}}],
 "writes": {"required": ["{run}/data/jobs/$DEV_JOB/accepted.json", "{run}/data/jobs/$DEV_JOB/latest.json", "{run}/data/jobs/$DEV_JOB/attempts/*/output.json",
                         "{run}/data/jobs/$DEV_JOB/attempts/*/inputs.json", "{run}/data/jobs/$DEV_JOB/attempts/*/status.json"],
            "allowed": [$LAUNCH_WRITES], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$DEV_JOB/attempts/*/output.json", "schema": "project-discovery.schema.json", "equals": {"source_revision": "{pin}"}},
             {"path": "{run}/data/jobs/$DEV_JOB/accepted.json", "equals": {"status": "OK", "job": "$DEV_JOB"}}]}
JSON
)" launch dev_project_discovery
  launch_status
  [[ $STEP_RC == 0 && "$LAUNCH_STATUS" == SUCCESS ]] || die "dev-project-discovery: status ${LAUNCH_STATUS:-unknown}. Dagster run: $(dagster_url)"
  gate_validate "$DEV_JOB" || die "dev-project-discovery: discovery_gate.validate rejected the accepted result"

  local jobdir="$RUN_DIR/data/jobs/$DEV_JOB" attempt cites summary
  attempt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["attempt_id"])' "$jobdir/accepted.json")"
  cites="$(citations_fresh "$jobdir/attempts/$attempt/output.json")" || die "dev-project-discovery: $cites"
  summary="$(python3 - "$RUN_DIR" "$attempt" "$REPO/fixtures/supplied/$FIXTURE/$DEV_JOB.json" "$LAUNCH_DAGSTER" "$cites" <<'PY'
import json, pathlib, sys
rdir, attempt, record, dagster_id, cites = sys.argv[1:]
rdir = pathlib.Path(rdir); d = rdir / 'data/jobs/02-dev-project-discovery'
bad = []
ptr = json.loads((d / 'accepted.json').read_text())
if ptr.get('dagster_run_id') != dagster_id: bad.append('accepted by %r, launched %r' % (ptr.get('dagster_run_id'), dagster_id))
if json.loads((d / 'latest.json').read_text()).get('attempt_id') != attempt: bad.append('accepted attempt is not the latest')
out = json.loads((d / 'attempts' / attempt / 'output.json').read_text())
if out != json.loads((d / 'supplied/result.json').read_text()) or out != json.loads(pathlib.Path(record).read_text()):
    bad.append('accepted output, supplied file and fixture record differ')
pd = rdir / 'data/jobs/02-repository-partition-discovery'
pmap = json.loads((pd / 'attempts' / json.loads((pd / 'accepted.json').read_text())['attempt_id'] / 'repository-partition-map.json').read_text())
if pmap['source_revision'] != out['source_revision']: bad.append('revision differs from the accepted partition map')
plan = out.get('safe_command_plan', [])
if not plan or any(not (c.get('argv') and c.get('authorization') and c.get('purpose')) for c in plan): bad.append('incomplete command plan')
if bad: sys.exit('; '.join(bad))
p = out['projects'][0]
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': attempt, 'projects': [x['project_id'] for x in out['projects']],
                  'root': p.get('root'), 'languages': p.get('languages'), 'manifests': p.get('manifests'), 'lockfiles': p.get('lockfiles'),
                  'buildenv_images': p.get('candidate_buildenv_images'),
                  'command_plan': [{'argv': c['argv'], 'authorization': c['authorization']} for c in plan],
                  'coverage_gaps': len(out.get('coverage_gaps', [])), 'citations_checked': int(cites),
                  'output_hashes_in_accepted_record': False}))
PY
)" || die "dev-project-discovery: $summary"
  checkout_unchanged dev-project-discovery
  record PASS dev-project-discovery "$(python3 -c 'import json,sys; e=json.loads(sys.argv[1]); e.update(handoff=sys.argv[2], handoff_dagster_run_id=sys.argv[3] or None); print(json.dumps(e))' "$summary" "$handoff_state" "$handoff_dagster")"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("dev-project-discovery: PASS  hand-off %s; accepted by Dagster %s: %s (%s), %s, image %s; plan: %s; %d citations fresh" % (
  sys.argv[1], s["dagster_run_id"][:8], ",".join(s["projects"]), "/".join(map(str, s["languages"])), ", ".join(map(str, s["manifests"])),
  ", ".join(map(str, s["buildenv_images"])), "; ".join(" ".join(c["argv"]) + " [" + c["authorization"] + "]" for c in s["command_plan"]), s["citations_checked"]))' "$handoff_state"
}

# ---- stage: devops-project-discovery --------------------------------------------------------------
# Same gate shape as dev-project-discovery (William, 2026-09-24: a real gated record, not a skip),
# reading the devops-persona partitions of the same partition map -- the Dockerfile's build/release
# route, not a second native build. Reuses the project-discovery contract and schema.
stage_devops_project_discovery() {
  require_run devops-project-discovery
  gate_handoff devops-project-discovery "$DEVOPS_JOB" devops_project_discovery project-discovery
  local handoff_state="$HANDOFF_STATE" handoff_dagster="$HANDOFF_DAGSTER"
  gate_supply devops-project-discovery "$DEVOPS_JOB" project-discovery

  echo "-- accept: the gate with the supplied discovery must succeed"
  run_step devops-project-discovery accept "$(contract devops-project-discovery accept <<JSON
{"inputs": [{"path": "{run}/data/jobs/$DEVOPS_JOB/supplied/result.json", "kind": "file", "schema": "project-discovery.schema.json", "equals": {"source_revision": "{pin}"}},
            {"path": "{run}/data/jobs/$PARTITION_JOB/accepted.json", "kind": "file", "equals": {"status": "OK"}}],
 "writes": {"required": ["{run}/data/jobs/$DEVOPS_JOB/accepted.json", "{run}/data/jobs/$DEVOPS_JOB/latest.json", "{run}/data/jobs/$DEVOPS_JOB/attempts/*/output.json",
                         "{run}/data/jobs/$DEVOPS_JOB/attempts/*/inputs.json", "{run}/data/jobs/$DEVOPS_JOB/attempts/*/status.json"],
            "allowed": [$LAUNCH_WRITES], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$DEVOPS_JOB/attempts/*/output.json", "schema": "project-discovery.schema.json", "equals": {"source_revision": "{pin}"}},
             {"path": "{run}/data/jobs/$DEVOPS_JOB/accepted.json", "equals": {"status": "OK", "job": "$DEVOPS_JOB"}}]}
JSON
)" launch devops_project_discovery
  launch_status
  [[ $STEP_RC == 0 && "$LAUNCH_STATUS" == SUCCESS ]] || die "devops-project-discovery: status ${LAUNCH_STATUS:-unknown}. Dagster run: $(dagster_url)"
  gate_validate "$DEVOPS_JOB" || die "devops-project-discovery: discovery_gate.validate rejected the accepted result"

  local jobdir="$RUN_DIR/data/jobs/$DEVOPS_JOB" attempt cites summary
  attempt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["attempt_id"])' "$jobdir/accepted.json")"
  cites="$(citations_fresh "$jobdir/attempts/$attempt/output.json")" || die "devops-project-discovery: $cites"
  summary="$(python3 - "$RUN_DIR" "$attempt" "$REPO/fixtures/supplied/$FIXTURE/$DEVOPS_JOB.json" "$LAUNCH_DAGSTER" "$cites" <<'PY'
import json, pathlib, sys
rdir, attempt, record, dagster_id, cites = sys.argv[1:]
rdir = pathlib.Path(rdir); d = rdir / 'data/jobs/02-devops-project-discovery'
bad = []
ptr = json.loads((d / 'accepted.json').read_text())
if ptr.get('dagster_run_id') != dagster_id: bad.append('accepted by %r, launched %r' % (ptr.get('dagster_run_id'), dagster_id))
if json.loads((d / 'latest.json').read_text()).get('attempt_id') != attempt: bad.append('accepted attempt is not the latest')
out = json.loads((d / 'attempts' / attempt / 'output.json').read_text())
if out != json.loads((d / 'supplied/result.json').read_text()) or out != json.loads(pathlib.Path(record).read_text()):
    bad.append('accepted output, supplied file and fixture record differ')
pd = rdir / 'data/jobs/02-repository-partition-discovery'
pmap = json.loads((pd / 'attempts' / json.loads((pd / 'accepted.json').read_text())['attempt_id'] / 'repository-partition-map.json').read_text())
if pmap['source_revision'] != out['source_revision']: bad.append('revision differs from the accepted partition map')
plan = out.get('safe_command_plan', [])
if not plan or any(not (c.get('argv') and c.get('authorization') and c.get('purpose')) for c in plan): bad.append('incomplete command plan')
if not out.get('coverage_gaps'): bad.append('devops discovery must record the missing IaC/CI/CD/deployment coverage')
if bad: sys.exit('; '.join(bad))
p = out['projects'][0]
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': attempt, 'projects': [x['project_id'] for x in out['projects']],
                  'root': p.get('root'), 'languages': p.get('languages'), 'manifests': p.get('manifests'),
                  'buildenv_images': p.get('candidate_buildenv_images'),
                  'command_plan': [{'argv': c['argv'], 'authorization': c['authorization']} for c in plan],
                  'coverage_gaps': len(out.get('coverage_gaps', [])), 'citations_checked': int(cites)}))
PY
)" || die "devops-project-discovery: $summary"
  checkout_unchanged devops-project-discovery
  record PASS devops-project-discovery "$(python3 -c 'import json,sys; e=json.loads(sys.argv[1]); e.update(handoff=sys.argv[2], handoff_dagster_run_id=sys.argv[3] or None); print(json.dumps(e))' "$summary" "$handoff_state" "$handoff_dagster")"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("devops-project-discovery: PASS  hand-off %s; accepted by Dagster %s: %s (%s), %s, base image %s; plan: %s; %d coverage gaps; %d citations fresh" % (
  sys.argv[1], s["dagster_run_id"][:8], ",".join(s["projects"]), "/".join(map(str, s["languages"])), ", ".join(map(str, s["manifests"])),
  ", ".join(map(str, s["buildenv_images"])), "; ".join(" ".join(c["argv"]) + " [" + c["authorization"] + "]" for c in s["command_plan"]), s["coverage_gaps"], s["citations_checked"]))' "$handoff_state"
}

# ---- stage: sre-operations-topology ----------------------------------------------------------------
# Chains after the accepted devops-project-discovery record instead of the partition map directly
# (William, 2026-09-24: operations topology is read off the containers/services devops discovery
# already found). Its own schema (operations-topology.schema.json), not project-discovery's.
stage_sre_operations_topology() {
  require_run sre-operations-topology
  gate_handoff sre-operations-topology "$SRE_JOB" sre_operations_topology operations-topology
  local handoff_state="$HANDOFF_STATE" handoff_dagster="$HANDOFF_DAGSTER"
  gate_supply sre-operations-topology "$SRE_JOB" operations-topology

  echo "-- accept: the gate with the supplied topology must succeed"
  run_step sre-operations-topology accept "$(contract sre-operations-topology accept <<JSON
{"inputs": [{"path": "{run}/data/jobs/$SRE_JOB/supplied/result.json", "kind": "file", "schema": "operations-topology.schema.json", "equals": {"source_revision": "{pin}"}},
            {"path": "{run}/data/jobs/$DEVOPS_JOB/accepted.json", "kind": "file", "equals": {"status": "OK"}}],
 "writes": {"required": ["{run}/data/jobs/$SRE_JOB/accepted.json", "{run}/data/jobs/$SRE_JOB/latest.json", "{run}/data/jobs/$SRE_JOB/attempts/*/output.json",
                         "{run}/data/jobs/$SRE_JOB/attempts/*/inputs.json", "{run}/data/jobs/$SRE_JOB/attempts/*/status.json"],
            "allowed": [$LAUNCH_WRITES], "deletes": []},
 "outputs": [{"path": "{run}/data/jobs/$SRE_JOB/attempts/*/output.json", "schema": "operations-topology.schema.json", "equals": {"source_revision": "{pin}"}},
             {"path": "{run}/data/jobs/$SRE_JOB/accepted.json", "equals": {"status": "OK", "job": "$SRE_JOB"}}]}
JSON
)" launch sre_operations_topology
  launch_status
  [[ $STEP_RC == 0 && "$LAUNCH_STATUS" == SUCCESS ]] || die "sre-operations-topology: status ${LAUNCH_STATUS:-unknown}. Dagster run: $(dagster_url)"
  gate_validate "$SRE_JOB" || die "sre-operations-topology: discovery_gate.validate rejected the accepted result"

  local jobdir="$RUN_DIR/data/jobs/$SRE_JOB" attempt cites summary
  attempt="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["attempt_id"])' "$jobdir/accepted.json")"
  cites="$(citations_fresh "$jobdir/attempts/$attempt/output.json")" || die "sre-operations-topology: $cites"
  summary="$(python3 - "$RUN_DIR" "$attempt" "$REPO/fixtures/supplied/$FIXTURE/$SRE_JOB.json" "$LAUNCH_DAGSTER" "$cites" <<'PY'
import json, pathlib, sys
rdir, attempt, record, dagster_id, cites = sys.argv[1:]
rdir = pathlib.Path(rdir); d = rdir / 'data/jobs/02-sre-operations-topology'
bad = []
ptr = json.loads((d / 'accepted.json').read_text())
if ptr.get('dagster_run_id') != dagster_id: bad.append('accepted by %r, launched %r' % (ptr.get('dagster_run_id'), dagster_id))
if json.loads((d / 'latest.json').read_text()).get('attempt_id') != attempt: bad.append('accepted attempt is not the latest')
out = json.loads((d / 'attempts' / attempt / 'output.json').read_text())
if out != json.loads((d / 'supplied/result.json').read_text()) or out != json.loads(pathlib.Path(record).read_text()):
    bad.append('accepted output, supplied file and fixture record differ')
dd = rdir / 'data/jobs/02-devops-project-discovery'
devops_out = json.loads((dd / 'attempts' / json.loads((dd / 'accepted.json').read_text())['attempt_id'] / 'output.json').read_text())
if devops_out['source_revision'] != out['source_revision']: bad.append('revision differs from the accepted devops discovery record')
services = out.get('services', [])
ids = [s.get('service_id') for s in services]
if not services: bad.append('no services recorded')
if len(ids) != len(set(ids)): bad.append('duplicate service_id')
known = set(ids)
for s in services:
    for dep in s.get('dependencies', []):
        if dep.get('target_service_id') not in known: bad.append('dependency target %r does not resolve' % dep.get('target_service_id'))
if not out.get('coverage_gaps'): bad.append('sre topology must record its coverage gaps')
if bad: sys.exit('; '.join(bad))
print(json.dumps({'dagster_run_id': dagster_id, 'attempt_id': attempt, 'services': [{'id': s['service_id'], 'kind': s['kind']} for s in services],
                  'coverage_gaps': len(out.get('coverage_gaps', [])), 'citations_checked': int(cites)}))
PY
)" || die "sre-operations-topology: $summary"
  checkout_unchanged sre-operations-topology
  record PASS sre-operations-topology "$(python3 -c 'import json,sys; e=json.loads(sys.argv[1]); e.update(handoff=sys.argv[2], handoff_dagster_run_id=sys.argv[3] or None); print(json.dumps(e))' "$summary" "$handoff_state" "$handoff_dagster")"
  printf '%s' "$summary" | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("sre-operations-topology: PASS  hand-off %s; accepted by Dagster %s: %s; %d coverage gaps; %d citations fresh" % (
  sys.argv[1], s["dagster_run_id"][:8], ", ".join("%s(%s)" % (x["id"], x["kind"]) for x in s["services"]), s["coverage_gaps"], s["citations_checked"]))' "$handoff_state"
}

# ---- driver --------------------------------------------------------------------------------------
FIXTURE=hello-autotools; THROUGH=""; RESUME=""; DISPATCH_FLAG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) list; exit 0 ;;
    --fixture) FIXTURE="$2"; shift 2 ;;
    --through) THROUGH="$2"; shift 2 ;;
    --resume) RESUME="$2"; shift 2 ;;
    --dispatch) DISPATCH_FLAG=1; shift ;;
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
  [[ "$(sat_get schema)" == "appsec-review/system-acceptance/2" ]] || die "SAT $RESUME predates contract enforcement (schema $(sat_get schema)); start a new SAT"
  [[ -z "$DISPATCH_FLAG" ]] || echo "SAT $RESUME: --dispatch is ignored on resume; using this SAT's own recorded choice"
else
  SAT_ID="$(date -u +%Y%m%dT%H%M%SZ)"; SAT_DIR="$SAT_ROOT/$SAT_ID"; mkdir -p "$SAT_DIR"
  python3 - "$SAT_DIR/sat.json" "$SAT_ID" "$FIXTURE" "$(git -C "$REPO" rev-parse HEAD)" "$([[ -n "$DISPATCH_FLAG" ]] && echo true || echo false)" <<'EOF'
import json, sys
path, sat_id, fixture, repo_head, partition_dispatch = sys.argv[1:]
json.dump({'schema': 'appsec-review/system-acceptance/2', 'sat_id': sat_id, 'fixture': fixture,
           'repo_commit': repo_head, 'run_id': None, 'stages': {},
           'partition_dispatch': partition_dispatch == 'true'}, open(path, 'w'), indent=1)
EOF
fi
IFS='|' read -r _ _ PIN <<< "$(fixture_entry "$FIXTURE")"
RUN_ID="$(sat_get run_id)"
PARTITION_DISPATCH="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1])).get("partition_dispatch") else "0")' "$SAT_DIR/sat.json")"
echo "SAT $(sat_get sat_id)  fixture $FIXTURE  record ${SAT_DIR#$REPO/}${RUN_ID:+  run $RUN_ID}${PARTITION_DISPATCH:+$([[ $PARTITION_DISPATCH == 1 ]] && echo '  partition-discovery: automatic dispatch')}"

for id in $(stage_ids); do
  if [[ "$(stage_status "$id")" == PASS && "$id" == sut-checkout ]]; then
    # Later stages read this checkout, so on resume it is re-verified rather than trusted.
    head_now="$(git -C "$REPO/fixtures/targets/$FIXTURE" rev-parse HEAD 2>/dev/null || true)"
    if [[ "$head_now" != "$PIN" || -n "$(git -C "$REPO/fixtures/targets/$FIXTURE" status --porcelain --untracked-files=all 2>/dev/null)" ]]; then
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
    rm -f "$SAT_DIR/steps/$id.index"
    if ! ( set -o pipefail; "$fn" 2>&1 | tee "$SAT_DIR/$id.log" ); then
      record FAIL "$id" "{\"log\": \"$id.log\"}"
      echo "$id: FAIL (log ${SAT_DIR#$REPO/}/$id.log)"; exit 1
    fi
  fi
  [[ "$id" == "$THROUGH" ]] && { echo "SAT $(sat_get sat_id): PASS through $THROUGH"; exit 0; }
done
