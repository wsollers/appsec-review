#!/usr/bin/env bash
# Re-invoke ONE already-fingerprinted job directly, by calling its own worker module, instead of
# relaunching the whole `full_review` Dagster graph. This writes to the exact same run-owned
# attempt directory (runs/<run_id>/data/jobs/<job>/) a Dagster-driven run would, through the same
# coordinate_worker_lifecycle locking/attempt/accepted.json machinery -- it just skips Dagster's
# own scheduling. A later `launch_job.py --job full_review --wait` for the same run id sees the
# freshly accepted (or still-blocked) attempt and continues from there.
#
# This does NOT rebuild any image and does NOT reload the Dagster code location -- it runs the
# worker's current on-disk Python directly. If you changed a Dockerfile or anything under
# orchestrator/dagster/, use orchestrator/prepare-host.sh and a real relaunch instead.
#
# Usage:
#   orchestrator/rerun-job.sh <run_id> [job_id] [--force]
#
#   orchestrator/rerun-job.sh 20261001T064759Z-4a8586
#   orchestrator/rerun-job.sh 20261001T064759Z-4a8586 01-component-characterization --force
#
# job_id defaults to 01-component-characterization. Add a JOB_MODULES entry below for any other
# job you want this script to reach; each one's worker module must accept the same
# `--run-id/--dagster-run-id/--force` CLI this script passes (component_characterization.py and
# claim_review_lifecycle.py already do -- the latter also needs --stage, not handled here).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

RUN_ID="${1:?$(usage)}"; shift || true
JOB_ID="01-component-characterization"
FORCE=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=(--force); shift;;
    -h|--help) usage; exit 0;;
    *) JOB_ID="$1"; shift;;
  esac
done

declare -A JOB_MODULES=(
  ["01-component-characterization"]="appsec-review-process/component_characterization.py"
)

MODULE="${JOB_MODULES[$JOB_ID]:-}"
if [[ -z "$MODULE" ]]; then
  echo "no worker module registered in this script for job '$JOB_ID'" >&2
  echo "known jobs: ${!JOB_MODULES[*]}" >&2
  exit 2
fi

RUN_DIR="appsec-review-process/runs/$RUN_ID"
if [[ ! -d "$RUN_DIR" ]]; then
  echo "no run directory at $RUN_DIR -- check the run id" >&2
  exit 2
fi

echo "# Re-invoking $JOB_ID directly for run $RUN_ID (not the whole full_review graph)" >&2
echo "python3 -B $MODULE --run-id $RUN_ID --dagster-run-id manual-rerun-$(date -u +%Y%m%dT%H%M%SZ) ${FORCE[*]:-}" >&2

RESULT_JSON=$(python3 -B "$MODULE" --run-id "$RUN_ID" \
  --dagster-run-id "manual-rerun-$(date -u +%Y%m%dT%H%M%SZ)" "${FORCE[@]}")
echo "$RESULT_JSON"

STATUS=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('status', '?'))" "$RESULT_JSON" 2>/dev/null || echo "?")
ATTEMPT=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('attempt_id', '?'))" "$RESULT_JSON" 2>/dev/null || echo "?")
echo >&2
echo "# status=$STATUS attempt=$ATTEMPT" >&2
echo "# full attempt record: $RUN_DIR/data/jobs/$JOB_ID/attempts/$ATTEMPT/result.json" >&2

if [[ "$STATUS" == "OK" || "$STATUS" == "OK_WITH_GAPS" ]]; then
  echo "# accepted. Resume the run with:" >&2
  echo "#   python3 appsec-review-process/launch_job.py --run-id $RUN_ID --job full_review --wait --timeout 21600" >&2
else
  echo "# not accepted (status=$STATUS). Read the attempt's status.json and logs before retrying." >&2
fi
