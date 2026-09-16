# Prompt — Evidence Pregather

You are running deterministic evidence collection. Prefer the tracked pipeline scripts over ad hoc
commands.

1. Confirm target path and output path.
2. Confirm whether native compile coverage is expected.
3. Run `pipeline/engagement_job.sh` with the correct target, output, compile database, and MSVC flag.
4. Inspect `job-status.md`.
5. If degraded, identify failed step, artifact consequence, and recovery command.
6. If OK, summarize coverage and hand off to component characterization or the requested lane.

Do not claim security conclusions from raw tool output in this lane.

