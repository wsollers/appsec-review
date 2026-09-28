#!/usr/bin/env bash
# Create and stage a full_review run for one ADR-0013 target, following
# docs/report-path/happy-path-operator-guide.md, with intake run before the build controls. Prints the run id on the last line.
#
#   orchestrator/stage-run.sh <target> [--goal "business goal"]
#   orchestrator/stage-run.sh hello-autotools
#
# Then: python3 appsec-review-process/launch_job.py --run-id <run-id> --job full_review --wait
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
TARGET_NAME="${1:?usage: stage-run.sh <target> [--goal TEXT]}"; shift
GOAL="Complete evidence-qualified application security review of $TARGET_NAME with final PDF and HTML publication."
while [[ $# -gt 0 ]]; do
    case "$1" in
        --goal) GOAL="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
TARGET="$REPO/fixtures/targets/$TARGET_NAME"
[[ -d "$TARGET/.git" ]] || { echo "no target clone at $TARGET; run fixtures/populate-targets.sh $TARGET_NAME" >&2; exit 2; }

export APPSEC_RUNS_ROOT="$REPO/appsec-review-process/runs"
# Canonical run-id shape: UTC stamp plus a short hex suffix (the target name is recorded in the manifest).
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"

echo "== run $RUN_ID for $TARGET_NAME"
python3 -B appsec-review-process/run_process.py --run-id "$RUN_ID" --start >/dev/null
python3 -B appsec-review-process/stage_artifacts.py \
  --run-id "$RUN_ID" \
  --project "$TARGET_NAME" \
  --target "$TARGET" \
  --business-goal "$GOAL" \
  --platform Linux \
  --budget full \
  --permission read-source \
  --permission read-run-data \
  --permission write-run-data \
  --permission read-offline-snapshots \
  --execution-environment dagster-read-only-linux
python3 -B appsec-review-process/offline_evidence_control.py stage-control "$RUN_ID" \
  --snapshot-registry "$REPO/appsec-review-process/offline/dependency-snapshots" \
  --max-database-age-seconds 1209600 \
  --reference-table "$REPO/data/reference/dependency-lifecycle-reference.json" \
  --max-reference-age-days 30
# Intake rewrites artifact-manifest.json when it is accepted (source identity, accepted pointer), and
# the build grants are bound to that manifest's hash. Run intake first, then stage the build controls,
# or 02-build-resolution blocks with STALE_GRANT.
echo "== intake (phase1_intake) before the build controls"
python3 -B appsec-review-process/launch_job.py --run-id "$RUN_ID" --job phase1_intake --wait --timeout 21600 >/dev/null  # includes time queued behind other runs
python3 -B appsec-review-process/build_resolution.py stage-control "$RUN_ID"
python3 -B appsec-review-process/build_configure.py stage-control "$RUN_ID"
echo "staged: launch with"
echo "  python3 appsec-review-process/launch_job.py --run-id $RUN_ID --job full_review --wait"
echo "$RUN_ID"
