#!/usr/bin/env bash
# Bash twin of Invoke-VendorAuditPrePass.ps1.
#
# Runs the broad static evidence toolbox from Linux/WSL without PowerShell.
set -euo pipefail

REPO_PATH=""
EVIDENCE_PATH=""
IMAGE_TAG="${IMAGE_TAG:-vendor-audit-toolbox:latest}"
STEPS_CSV=""
CLEAN_EVIDENCE=0
SKIP_DOCKER_CHECK=0

usage() {
  cat <<'EOF'
Usage:
  pipeline/Invoke-VendorAuditPrePass.sh REPO_PATH EVIDENCE_PATH [options]

Options:
  --image-tag TAG       Toolbox image tag. Default: vendor-audit-toolbox:latest
  --steps a,b,c         Optional comma-separated step subset.
  --clean-evidence      Delete existing evidence before running.
  --skip-docker-check   Do not run docker info before the first step.

Evidence layout and step names match Invoke-VendorAuditPrePass.ps1.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image-tag|-ImageTag) IMAGE_TAG="$2"; shift 2;;
    --steps|-Steps) STEPS_CSV="${STEPS_CSV:+$STEPS_CSV,}$2"; shift 2;;
    --clean-evidence|-CleanEvidence) CLEAN_EVIDENCE=1; shift;;
    --skip-docker-check|-SkipDockerCheck) SKIP_DOCKER_CHECK=1; shift;;
    -h|--help) usage; exit 0;;
    -*)
      echo "unknown option: $1" >&2
      usage
      exit 2
      ;;
    *)
      if [[ -z "$REPO_PATH" ]]; then
        REPO_PATH="$1"
      elif [[ -z "$EVIDENCE_PATH" ]]; then
        EVIDENCE_PATH="$1"
      else
        echo "unexpected argument: $1" >&2
        usage
        exit 2
      fi
      shift
      ;;
  esac
done

[[ -n "$REPO_PATH" && -n "$EVIDENCE_PATH" ]] || { usage; exit 2; }

REPO_PATH=$(realpath "$REPO_PATH")
mkdir -p "$EVIDENCE_PATH"
EVIDENCE_PATH=$(realpath "$EVIDENCE_PATH")
MANIFEST="$EVIDENCE_PATH/MANIFEST.json"
HOST_UID=$(id -u)
HOST_GID=$(id -g)
TOOLS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# pipeline/ and data/eol-reference.json are mounted read-only for the steps that run repo scripts
# in-image (evidence-scrub, dependency-lifecycle). Image-owned scripts live in the image (images/<name>/scripts).
tool_mount_args() {
  MOUNT_ARGS=(-v "$TOOLS_ROOT/pipeline:/opt/pipeline:ro" -v "$TOOLS_ROOT/data/eol-reference.json:/opt/data/eol-reference.json:ro")
}

docker_clean_path() {
  local mount_path="$1"
  local rel="${2:-}"
  local script
  if [[ -n "$rel" ]]; then
    script="rm -rf -- \"/evidence/$rel\""
  else
    script='find /evidence -mindepth 1 -maxdepth 1 -exec rm -rf {} +'
  fi
  docker run --rm -v "$mount_path:/evidence" --entrypoint sh "$IMAGE_TAG" -c "$script"
}

safe_remove_evidence_path() {
  local rel="${1:-}"
  if [[ -n "$rel" ]]; then
    rm -rf -- "$EVIDENCE_PATH/$rel" 2>/dev/null && return 0
    docker_clean_path "$EVIDENCE_PATH" "$rel" >/dev/null
  else
    find "$EVIDENCE_PATH" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null && return 0
    echo "host cleanup could not remove every evidence artifact; retrying cleanup in Docker as root" >&2
    docker_clean_path "$EVIDENCE_PATH" "" >/dev/null
  fi
}

if [[ "$CLEAN_EVIDENCE" == 1 ]]; then
  safe_remove_evidence_path ""
fi

if [[ "$SKIP_DOCKER_CHECK" != 1 ]]; then
  docker info >/dev/null
fi

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

manifest_update() {
  local step="$1" started="$2" dur="$3" exit_code="$4" output_ok="$5" treated_ok="$6"
  python3 - "$MANIFEST" "$step" "$started" "$dur" "$exit_code" "$output_ok" "$treated_ok" <<'PY'
import json, sys
path, step, started, dur, exit_code, output_ok, treated_ok = sys.argv[1:]
try:
    data = json.load(open(path, encoding="utf-8"))
    if not isinstance(data, list):
        data = []
except Exception:
    data = []
row = {
    "step": step,
    "startedUtc": started,
    "durationSec": round(float(dur), 1),
    "exitCode": int(exit_code),
    "outputOk": output_ok == "1",
    "treatedOk": treated_ok == "1",
}
by_step = {str(item.get("step")): item for item in data if isinstance(item, dict)}
by_step[step] = row
json.dump(list(by_step.values()), open(path, "w", encoding="utf-8"), indent=1)
PY
}

has_nonempty_file() {
  [[ -f "$EVIDENCE_PATH/$1" && -s "$EVIDENCE_PATH/$1" ]]
}

expected_ok() {
  local expected="$1" expected_any="$2"
  if [[ -n "$expected" ]]; then
    has_nonempty_file "$expected"
    return
  fi
  if [[ -n "$expected_any" ]]; then
    local item
    IFS=',' read -ra items <<< "$expected_any"
    for item in "${items[@]}"; do
      has_nonempty_file "$item" && return 0
    done
    return 1
  fi
  return 0
}

clear_outputs() {
  local expected="$1" expected_any="$2" outfile="$3"
  local item
  [[ -n "$expected" ]] && safe_remove_evidence_path "$expected"
  if [[ -n "$expected_any" ]]; then
    IFS=',' read -ra items <<< "$expected_any"
    for item in "${items[@]}"; do safe_remove_evidence_path "$item"; done
  fi
  [[ -n "$outfile" ]] && safe_remove_evidence_path "$outfile"
  return 0
}

docker_base_args() {
  local image="${1:-$IMAGE_TAG}"
  local env_args=(-e HOME=/tmp)
  for name in SEMANTIC_INDEX_BATCH_SIZE SEMANTIC_INDEX_SLICE_LIMIT SEMANTIC_INDEX_START SEMANTIC_INDEX_MODEL SEMANTIC_INDEX_TABLE; do
    if [[ -n "${!name:-}" ]]; then
      env_args+=(-e "$name=${!name}")
    fi
  done
  tool_mount_args "$image"
  printf '%s\0' run --rm --user "$HOST_UID:$HOST_GID" "${env_args[@]}" -w /tmp -v "$REPO_PATH:/workspace:ro" -v "$EVIDENCE_PATH:/evidence" "${MOUNT_ARGS[@]}" "$image"
}

run_container() {
  local image="$1"; shift
  local env_args=(-e HOME=/tmp)
  local name
  for name in SEMANTIC_INDEX_BATCH_SIZE SEMANTIC_INDEX_SLICE_LIMIT SEMANTIC_INDEX_START SEMANTIC_INDEX_MODEL SEMANTIC_INDEX_TABLE; do
    if [[ -n "${!name:-}" ]]; then
      env_args+=(-e "$name=${!name}")
    fi
  done
  tool_mount_args "$image"
  docker run --rm --user "$HOST_UID:$HOST_GID" "${env_args[@]}" -w /tmp -v "$REPO_PATH:/workspace:ro" -v "$EVIDENCE_PATH:/evidence" "${MOUNT_ARGS[@]}" "$image" "$@"
}

write_post_success() {
  local rel="$1" text="$2"
  [[ -z "$rel" ]] && return 0
  mkdir -p "$(dirname "$EVIDENCE_PATH/$rel")"
  printf '%s\n' "$text" > "$EVIDENCE_PATH/$rel"
}

step_meta() {
  local step="$1"
  SUBDIR="" ALLOW_NONZERO=0 EXPECTED="" EXPECTED_ANY="" OUTFILE="" CAPTURE_STDOUT=0 CAPTURE_STDERR=0 IMAGE="$IMAGE_TAG" POST_FILE="" POST_TEXT=""
  case "$step" in
    cloc) SUBDIR=cloc; EXPECTED=cloc/cloc.json; CMD=(cloc /workspace --json --out=/evidence/cloc/cloc.json --exclude-dir=.git,node_modules,vendor,bin,obj,.terraform,Library,Temp);;
    scc) SUBDIR=cloc; EXPECTED=cloc/scc.json; CMD=(scc /workspace --format json --output /evidence/cloc/scc.json);;
    secrets) SUBDIR=secrets; ALLOW_NONZERO=1; EXPECTED=secrets/gitleaks.json; CMD=(gitleaks detect --source=/workspace --report-format=json --report-path=/evidence/secrets/gitleaks.json --redact);;
    secrets-binary) SUBDIR=secrets; ALLOW_NONZERO=1; EXPECTED=secrets/binary-cert-inventory.txt; CMD=(bash -lc "find /workspace -type f \\( -iname '*.pem' -o -iname '*.key' -o -iname '*.pfx' -o -iname '*.p12' -o -iname '*.crt' -o -iname '*.cer' -o -iname '*.jks' -o -iname '*.keystore' \\) -print > /evidence/secrets/binary-cert-inventory.txt");;
    sbom) SUBDIR=sbom; EXPECTED=sbom/sbom.cdx.json; CMD=(syft dir:/workspace -o cyclonedx-json@1.5=/evidence/sbom/sbom.cdx.json);;
    sca) SUBDIR=sca; ALLOW_NONZERO=1; EXPECTED=sca/osv-scanner.json; CMD=(osv-scanner scan --sbom /evidence/sbom/sbom.cdx.json --format json --output /evidence/sca/osv-scanner.json);;
    sast-python) SUBDIR=sast-python; ALLOW_NONZERO=1; EXPECTED=sast-python/bandit.json; CMD=(bandit -r /workspace -f json -o /evidence/sast-python/bandit.json);;
    sast-go) SUBDIR=sast-go; ALLOW_NONZERO=1; EXPECTED=sast-go/gosec.json; CMD=(gosec -fmt=json -out=/evidence/sast-go/gosec.json /workspace/...);;
    sast-cpp) SUBDIR=sast-cpp; ALLOW_NONZERO=1; EXPECTED=sast-cpp/cppcheck.xml; CAPTURE_STDOUT=1; CAPTURE_STDERR=1; OUTFILE=sast-cpp/cppcheck.xml; CMD=(cppcheck --enable=all --inconclusive --xml --xml-version=2 /workspace);;
    sast-multi-semgrep-owasp) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-owasp.json; CMD=(semgrep scan --config=p/owasp-top-ten --verbose --json --output=/evidence/sast-multi/semgrep-owasp.json /workspace);;
    sast-multi-semgrep-csharp) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-csharp.json; CMD=(semgrep scan --config=p/csharp --verbose --json --output=/evidence/sast-multi/semgrep-csharp.json /workspace);;
    sast-multi-semgrep-golang) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-golang.json; CMD=(semgrep scan --config=p/golang --verbose --json --output=/evidence/sast-multi/semgrep-golang.json /workspace);;
    sast-multi-semgrep-python) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-python.json; CMD=(semgrep scan --config=p/python --verbose --json --output=/evidence/sast-multi/semgrep-python.json /workspace);;
    sast-multi-semgrep-php) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-php.json; CMD=(semgrep scan --config=p/php --verbose --json --output=/evidence/sast-multi/semgrep-php.json /workspace);;
    sast-multi-semgrep-java) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-java.json; CMD=(semgrep scan --config=p/java --verbose --json --output=/evidence/sast-multi/semgrep-java.json /workspace);;
    sast-multi-semgrep-security-audit) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-security-audit.json; CMD=(semgrep scan --config=p/security-audit --verbose --json --output=/evidence/sast-multi/semgrep-security-audit.json /workspace);;
    sast-multi-semgrep-terraform) SUBDIR=sast-multi; ALLOW_NONZERO=1; EXPECTED=sast-multi/semgrep-terraform.json; CMD=(semgrep scan --config=p/terraform --verbose --json --output=/evidence/sast-multi/semgrep-terraform.json /workspace);;
    sast-php) SUBDIR=sast-php; ALLOW_NONZERO=1; EXPECTED_ANY=sast-php/psalm.json,sast-php/phpstan.json,sast-php/phpcs.json; CMD=(bash /opt/scripts/run-sast-php.sh);;
    sast-php-parse-coverage) SUBDIR=sast-php; ALLOW_NONZERO=1; EXPECTED=sast-php/parse-coverage.json; CMD=(python3 /opt/scripts/php_parse_coverage.py /workspace -o /evidence/sast-php/parse-coverage.json);;
    # 2026-09-18: was "bash -lc" (login shell) - changed to "-c" while chasing a real
    # "tfsec: command not found" / "kube-linter: command not found" seen in eastl's
    # static-evidence/{iac,iac-k8s}/*.stderr.log. RESOLVED, and it was NOT a shell/PATH bug:
    # those stderr logs are dated 2026-09-16 19:41/20:22, but the audit-iac image (this
    # Dockerfile, with tfsec/kube-linter go-installed into it) wasn't created until commit
    # f2b8ab1 on 2026-09-17 14:37 - a full day later. The eastl evidence simply predates this
    # image existing in working form; it was never regenerated after the split. Confirmed
    # directly on hal5000 2026-09-18: both
    # `docker run --rm audit-iac:local bash -lc 'which tfsec kube-linter'` and the same with
    # `-c` resolve both binaries fine, identical PATH either way - so -lc was never the
    # problem. Left as -c anyway (a non-login, non-interactive shell is the objectively
    # correct choice for a programmatic invocation like this), but the real fix was just
    # re-running -Steps iac,iac-k8s to regenerate the evidence against the current image.
    # 2026-09-19: split into one-tool-one-container steps, matching the .ps1
    # twin's 2026-09-18 split (iac-checkov/iac-trivy) - this .sh twin had
    # drifted and still ran the old chained bash -c shape that caused the
    # original silent-failure bug documented in the comment block above (kept
    # for history). iac-tfsec added alongside as a genuinely new step (see
    # .ps1's iac-tfsec Note for why tfsec is not redundant with trivy).
    iac-checkov) SUBDIR=iac; ALLOW_NONZERO=1; EXPECTED=iac/results_json.json; IMAGE=audit-iac:local; CMD=(checkov -d /workspace -o json --output-file-path /evidence/iac/);;
    iac-trivy) SUBDIR=iac; ALLOW_NONZERO=1; EXPECTED=iac/trivy-config.json; IMAGE=audit-iac:local; CMD=(trivy config --format json --output /evidence/iac/trivy-config.json /workspace);;
    iac-tfsec) SUBDIR=iac; ALLOW_NONZERO=1; EXPECTED=iac/tfsec.json; IMAGE=audit-iac:local; CMD=(tfsec /workspace --format json --out /evidence/iac/tfsec.json);;
    weggli-note) SUBDIR=sast-cpp; EXPECTED=sast-cpp/weggli-usage.txt; CMD=(bash -lc "echo 'weggli is installed for interactive semantic C/C++ pattern search - example: weggli PATTERN /workspace, where PATTERN is a weggli query such as a memcpy-into-undersized-buffer match. Run it manually per Phase 4B hypothesis, it is not a one-shot batch scanner like the others in this pass.' > /evidence/sast-cpp/weggli-usage.txt");;
    ast-grep-scan)
      SUBDIR=structural-search; ALLOW_NONZERO=1
      if [[ -f "$REPO_PATH/sgconfig.yml" || -d "$REPO_PATH/.ast-grep" ]]; then
        EXPECTED=structural-search/ast-grep.json; CMD=(ast-grep scan --json)
      else
        POST_FILE=structural-search/ast-grep-usage.txt
        POST_TEXT="No ast-grep rule config found; use ast-grep run -p PATTERN -l LANG interactively per hypothesis."
        CMD=(true)
      fi
      ;;
    joern-parse) SUBDIR=joern; ALLOW_NONZERO=1; EXPECTED=joern/cpg.bin; POST_FILE=joern/README.txt; POST_TEXT="CPG built at /evidence/joern/cpg.bin. Open it interactively with Joern for hypothesis-driven dataflow queries."; CMD=(/opt/joern/joern-cli/c2cpg.sh /workspace --output /evidence/joern/cpg.bin --exclude "**/.git/**" --exclude "**/node_modules/**" --exclude "**/vendor/**");;
    symbol-index) SUBDIR=symbol-index; EXPECTED=symbol-index/index.json; CMD=(python3 /opt/scripts/build_symbol_index.py /workspace -o /evidence/symbol-index);;
    semantic-index) SUBDIR=semantic-index; EXPECTED=semantic-index/index.json; CMD=(bash /opt/scripts/run-semantic-index-batched.sh /workspace /evidence/symbol-index /evidence/semantic-index);;
    binskim) SUBDIR=binskim; ALLOW_NONZERO=1; EXPECTED=binskim/binskim.sarif; CMD=(bash -lc "binskim analyze '/workspace/**' --recurse --output /evidence/binskim/binskim.sarif || true");;
    sast-mobile-android) SUBDIR=sast-mobile; ALLOW_NONZERO=1; EXPECTED=sast-mobile/android-coverage.txt; CMD=(bash -lc "files=\$(find /workspace -type f \\( -iname '*.java' -o -iname '*.kt' -o -iname '*.kts' -o -iname 'AndroidManifest.xml' \\) | wc -l); echo \"android candidate files: \$files\" > /evidence/sast-mobile/android-coverage.txt; mobsfscan /workspace --type android --sarif -o /evidence/sast-mobile/mobsfscan-android.sarif || true; if [ \"\$files\" -eq 0 ]; then echo 'WARNING: zero matching source files - treat mobsfscan-android.sarif as NOT-SCANNED, not clean.' >> /evidence/sast-mobile/android-coverage.txt; fi");;
    sast-mobile-ios) SUBDIR=sast-mobile; ALLOW_NONZERO=1; EXPECTED=sast-mobile/ios-coverage.txt; CMD=(bash -lc "files=\$(find /workspace -type f \\( -iname '*.swift' -o -iname '*.m' -o -iname '*.mm' -o -iname 'Info.plist' \\) | wc -l); echo \"ios candidate files: \$files\" > /evidence/sast-mobile/ios-coverage.txt; mobsfscan /workspace --type ios --sarif -o /evidence/sast-mobile/mobsfscan-ios.sarif || true; if [ \"\$files\" -eq 0 ]; then echo 'WARNING: zero matching source files - treat mobsfscan-ios.sarif as NOT-SCANNED, not clean.' >> /evidence/sast-mobile/ios-coverage.txt; fi");;
    spotbugs-note) SUBDIR=sast-java; EXPECTED=sast-java/spotbugs-usage.txt; CMD=(bash -lc "echo 'SpotBugs+FindSecBugs analyze compiled bytecode, not source. Run manually against built Java services.' > /evidence/sast-java/spotbugs-usage.txt");;
    # 2026-09-18: was "bash -lc" (login shell) - changed to "-c" while chasing a real
    # "tfsec: command not found" / "kube-linter: command not found" seen in eastl's
    # static-evidence/{iac,iac-k8s}/*.stderr.log. RESOLVED, and it was NOT a shell/PATH bug:
    # those stderr logs are dated 2026-09-16 19:41/20:22, but the audit-iac image (this
    # Dockerfile, with tfsec/kube-linter go-installed into it) wasn't created until commit
    # f2b8ab1 on 2026-09-17 14:37 - a full day later. The eastl evidence simply predates this
    # image existing in working form; it was never regenerated after the split. Confirmed
    # directly on hal5000 2026-09-18: both
    # `docker run --rm audit-iac:local bash -lc 'which tfsec kube-linter'` and the same with
    # `-c` resolve both binaries fine, identical PATH either way - so -lc was never the
    # problem. Left as -c anyway (a non-login, non-interactive shell is the objectively
    # correct choice for a programmatic invocation like this), but the real fix was just
    # re-running -Steps iac,iac-k8s to regenerate the evidence against the current image.
    iac-k8s) SUBDIR=iac-k8s; ALLOW_NONZERO=1; EXPECTED=iac-k8s/kube-linter.json; IMAGE=audit-iac:local; CMD=(bash -c "kube-linter lint /workspace --format json > /evidence/iac-k8s/kube-linter.json || true");;
    dockerfile-lint) SUBDIR=iac-docker; ALLOW_NONZERO=1; IMAGE=audit-container:local; CMD=(bash /opt/scripts/run-dockerfile-lint.sh);;
    docker-base-images) SUBDIR=iac-docker; ALLOW_NONZERO=1; IMAGE=audit-container:local; CMD=(bash -lc "find /workspace -iname 'Dockerfile*' -type f -print0 | xargs -0 -r awk 'BEGIN{IGNORECASE=1} /^FROM[[:space:]]+/ {print FILENAME \":\" NR \":\" \$0}' > /evidence/iac-docker/base-images.txt");;
    scancode) SUBDIR=license; ALLOW_NONZERO=1; EXPECTED=license/scancode.json; IMAGE=scancode-toolkit:local; CMD=(-clip --json-pp /evidence/license/scancode.json /workspace);;
    dependency-lifecycle) SUBDIR=sbom; ALLOW_NONZERO=1; EXPECTED=sbom/dependency-lifecycle.json; CMD=(python3 /opt/pipeline/analyze_dependency_lifecycle.py --sbom /evidence/sbom/sbom.cdx.json --eol-reference /opt/data/eol-reference.json --scancode /evidence/license/scancode.json -o /evidence/sbom/dependency-lifecycle.json);;
    evidence-scrub) SUBDIR=_shareable; ALLOW_NONZERO=1; CMD=(python3 /opt/pipeline/scrub_evidence.py /evidence -o /evidence/_shareable);;
    *) return 1;;
  esac
}

ALL_STEPS=(
  cloc scc secrets secrets-binary sbom sca
  sast-python sast-go sast-cpp
  sast-multi-semgrep-owasp sast-multi-semgrep-csharp sast-multi-semgrep-golang
  sast-multi-semgrep-python sast-multi-semgrep-php sast-multi-semgrep-java
  sast-multi-semgrep-security-audit sast-multi-semgrep-terraform
  sast-php sast-php-parse-coverage iac-checkov iac-trivy iac-tfsec weggli-note ast-grep-scan joern-parse
  symbol-index semantic-index binskim sast-mobile-android sast-mobile-ios
  spotbugs-note iac-k8s dockerfile-lint docker-base-images scancode dependency-lifecycle evidence-scrub
)

if [[ -n "$STEPS_CSV" ]]; then
  IFS=',' read -ra SELECTED_STEPS <<< "$STEPS_CSV"
else
  SELECTED_STEPS=("${ALL_STEPS[@]}")
fi

echo "Resolved parameters for this run:"
echo "    RepoPath      = $REPO_PATH"
echo "    EvidencePath  = $EVIDENCE_PATH"
echo "    ImageTag      = $IMAGE_TAG"
echo "    Steps         = ${STEPS_CSV:-"(all)"}"

for step in "${SELECTED_STEPS[@]}"; do
  step="${step//[[:space:]]/}"
  [[ -n "$step" ]] || continue
  if ! step_meta "$step"; then
    echo "unknown step: $step" >&2
    exit 2
  fi
  mkdir -p "$EVIDENCE_PATH/$SUBDIR"
  clear_outputs "$EXPECTED" "$EXPECTED_ANY" "$OUTFILE"
  stderr_file="$EVIDENCE_PATH/$SUBDIR/$step.stderr.log"
  echo "==> $step"
  start_epoch=$(date +%s)
  started_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  set +e
  if [[ "$CAPTURE_STDOUT" == 1 && -n "$OUTFILE" ]]; then
    if [[ "$CAPTURE_STDERR" == 1 ]]; then
      run_container "$IMAGE" "${CMD[@]}" > /dev/null 2> "$EVIDENCE_PATH/$OUTFILE"
    else
      run_container "$IMAGE" "${CMD[@]}" > "$EVIDENCE_PATH/$OUTFILE" 2> "$stderr_file"
    fi
  else
    run_container "$IMAGE" "${CMD[@]}" 2> "$stderr_file"
  fi
  rc=$?
  set -e
  end_epoch=$(date +%s)
  dur=$((end_epoch - start_epoch))
  shell_fatal=0
  if [[ "$rc" == 2 || "$rc" == 126 || "$rc" == 127 || ( "$rc" -gt 128 && "$rc" -le 192 ) ]]; then
    shell_fatal=1
  fi
  exit_ok=0
  if [[ "$shell_fatal" == 0 && ( "$rc" == 0 || ( "$ALLOW_NONZERO" == 1 && "$rc" != -1 ) ) ]]; then
    exit_ok=1
  fi
  output_ok=0
  if expected_ok "$EXPECTED" "$EXPECTED_ANY"; then output_ok=1; fi
  treated_ok=0
  if [[ "$exit_ok" == 1 && "$output_ok" == 1 ]]; then
    treated_ok=1
    write_post_success "$POST_FILE" "$POST_TEXT"
    echo "    done in ${dur}s (exit $rc)"
  else
    echo "    WARNING: $step exit=$rc outputOk=$output_ok treatedOk=false; see $stderr_file" >&2
  fi
  manifest_update "$step" "$started_utc" "$dur" "$rc" "$output_ok" "$treated_ok"
done

echo
echo "Pre-pass complete. Evidence written to $EVIDENCE_PATH"
echo "Manifest: $MANIFEST"
