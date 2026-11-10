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
