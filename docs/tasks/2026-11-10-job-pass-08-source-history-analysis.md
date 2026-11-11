# Job pass 08 - `job_source_history_analysis`

This run-first receipt advances T-057. The parent executes the job before selecting repairs;
an observed failure will determine the job-specific unit regression, not an unrelated baseline
failure or a preemptive infrastructure audit.

## Criterion before the first c094 dispatch

Run `2026-11-10-0003` has accepted intake and catalog outputs for unchanged target fingerprint
`d3719c4b6b2d3768e1524ff3b7aa7f6439d2e7c5165af1bf9c0c152a05ae1933`. History must consume those
declared, pinned handoffs and retain their source identity.

The target is a non-shallow Git checkout of `https://github.com/wsollers/appsec-multi-vuln`,
at `bd69bfe83fec49155366303604475512c98c4ce6`. It has 23 reachable commits and **20 first-parent
commits**, dated September 26 through November 2, 2026, all within the configured six-month window.
The job's declared revision semantics count first-parent changes, not all merged-branch commits.
It must bind that actual repository/HEAD, retain resolving Git evidence and report any filtering
explicitly rather than claiming complete acquisition with missing history.

GitHub enrichment is `auto`, and the configured `GITHUB_TOKEN` is present. It must identify the
correct repository and either retain bounded enrichment evidence or report an explicit transport,
authorization or coverage problem; absence of acquired PR/deployment timing signals must not be
invented as observations. No token value belongs in outputs.

Blame and line history are bounded to 50 files each; symbols to 200. Every selected/skipped file,
source-language policy and exhausted bound must be represented honestly. Published history,
hotspots, shard hashes, source spans and lifecycle/count metrics must agree, with no fabricated
vulnerability claims from commit messages. The target checkout must remain unchanged.

## Validation state

No job code changed and no unit tests were rerun before this first live attempt. This receipt
does not claim that all existing history unit tests pass. The next result determines whether
a bounded repair and focused regressions are required.

## Observed result

Dispatch `3fc72d44-673e-4b39-af2c-d2e919e2e3a5`, attempt 1, completed in **394,018 ms** with
`COMPLETED_WITH_GAPS`, zero audit findings, and was accepted after content verification.
The direct-checkout policy documented in `docs/architecture/source-history-analysis.md` follows
`main`, then `master`, then `HEAD`; it does not pretend a detached review tag is the mainline.
Accordingly the output preserves the correct review HEAD (`bd69bfe8...`) but selects mainline
`422845994f4e28fb93032efa704592d97ce498a0` and its **21** first-parent commits. The pre-dispatch
20-commit count describes the review HEAD, not this selected mainline. The output explicitly
records `head_differs_from_mainline` and partial binding.

Independent comparison confirms 339 exact file bindings and five divergent files: root README,
`scripts/build.ps1`, `scripts/build.sh`, `scripts/validate-matrix.py` and `support/project-matrix.json`.
All eleven c094 files bind exactly. GitHub enrichment succeeded with 21 facts in 31 requests,
zero indeterminate records and no acquisition gaps. Line history selected the configured 50-file
bound. Symbol analysis covered 169 files; all nine c094 code files have complete symbol status
and no parser gaps. Retained parser gaps are in macro-heavy native headers/extension/JNI sources;
unsupported languages and the configured blame/line-history bounds remain explicit.

The six published index hashes resolve, including history and its upstream catalog shards.
Lifecycle, status and metrics agree. PR/deployment timing remains unavailable rather than inferred.
The 21 unique gap summaries (39 occurrences) are preserved, not represented as complete coverage
or vulnerability evidence. No code repair or unit-test change was needed for this documented
partial result. Logs: `runs/c094-source-history-{run,accept}.log`.
Next: `job_ci_configuration_analysis`.

## Planner-repair replay, 2026-11-11

The later planner request-size repair (`3edf424853a2f05ba047f59260cc32dd9d2fb88f`,
integrated as `f36939229`) also invalidates this job through the existing static cross-job import
closure. No release-scoping change was made. The parent inspected/admitted repair
`fca5656c7067c87c36c83cb9fa609742f2daf08433ffdac8410048c798f222ed` against release
`f7285bd1b10ad9fc62847e4d144b3b187acd730b03efbd90119d96d2d5ff91a0`, preserving the same
configuration, target and tooling image, then replayed the three early gates individually.

History replay dispatch `77b87591-cd6f-4261-bf78-ac228c16b344`, `attempt_0002`, completed
with the same declared partial dispositions and 21 gap summaries/39 occurrences, zero audit
findings. **It is not reaccepted.** The preserved-key comparison reports thirteen coverage
differences: nine execution-mount `runtime_source` values changed from Docker Desktop's
`/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/...` aliases to native checkout paths,
plus four normalized artifact-content signatures. Logical mount `source`, `target` and
`read_only` fields remain the same after ordinary run/attempt masking.

Report:
`runs/metadata/stepwise/2026-11-10-0003/checks/job_source_history_analysis-77b87591-cd6f-4261-bf78-ac228c16b344.json`.
No general environment exemption, mount-path equivalence, key rewrite or manual acceptance
was applied. The parent reverified all 27 recorded dispatches stopped and paused before CI,
environment and planner replays. Original acceptance keys and raw evidence remain intact.
Any new comparison rule requires a narrowly justified evidence check, not treating changed
content hashes as automatically volatile.
