#!/usr/bin/env bash
# Follow one run's pipeline log (JSON lines) as readable text.
#
#   orchestrator/tail-run-log.sh <run-id> [--raw] [--level warn|error] [--job SUBSTR] [--who SUBSTR] [--from-start]
#   orchestrator/tail-run-log.sh                       # no run id: the global log (daemons, no-run lines)
#
# Output: HH:MM:SS level job/step [who] message. Banner lines (###) are shown as-is so a new session
# (intake or resume) is easy to spot. Needs jq; --raw prints the file unchanged (pipe it to rg).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUNS="${APPSEC_RUNS_ROOT:-$REPO/appsec-review-process/runs}"
RUN=""; RAW=0; LEVEL=""; JOB=""; WHO=""; START="-n 50"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --raw) RAW=1; shift ;;
        --level) LEVEL="$2"; shift 2 ;;
        --job) JOB="$2"; shift 2 ;;
        --who) WHO="$2"; shift 2 ;;
        --from-start) START="-n +1"; shift ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *) RUN="$1"; shift ;;
    esac
done
if [[ -n "$RUN" ]]; then FILE="$RUNS/$RUN/data/logs/pipeline.log"; else FILE="$REPO/appsec-review-process/logs/pipeline.log"; fi
[[ -e "$FILE" ]] || { echo "waiting for $FILE" >&2; while [[ ! -e "$FILE" ]]; do sleep 1; done; }
if [[ $RAW -eq 1 ]] || ! command -v jq >/dev/null; then exec tail $START -F "$FILE"; fi
tail $START -F "$FILE" | jq -R -r --unbuffered --arg level "$LEVEL" --arg job "$JOB" --arg who "$WHO" '
  . as $line | (try fromjson catch null) as $r
  | if $r == null then (if ($line | startswith("#")) then $line else empty end)
    elif ($level != "" and $r.level != $level and ($level != "warn" or ($r.level != "error"))) then empty
    elif ($job != "" and (($r.job // "") | contains($job) | not)) then empty
    elif ($who != "" and (($r.who // "") | contains($who) | not)) then empty
    else "\($r.ts[11:19]) \(($r.level // "info") | ascii_upcase | .[0:6])\t\($r.job // "-")/\($r.step // "-")\t[\($r.who // $r.proc // "-")]\t\($r.msg)" end'
