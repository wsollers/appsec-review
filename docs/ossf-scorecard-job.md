# OpenSSF Scorecard published-results job

`ossf_scorecard` is a registered Dagster evidence job backed by
`appsec-review-process/ossf_scorecard.py`. It ingests canonical JSON2 results already published by
the OpenSSF Scorecard Results API. It does not run Scorecard against a repository and does not turn
an aggregate or check score into a vulnerability finding.

## Authorization and input

Network access is denied unless the staged run's `intake_config.permissions` contains exactly:

```text
network:api.scorecard.dev
```

Stage `runs/<run_id>/inputs/ossf-scorecard-projects.json`:

```json
{
  "schema": "appsec-review/ossf-scorecard-projects/1",
  "projects": [
    {"repository": "github.com/ossf/scorecard"},
    {"repository": "github.com/example/project", "commit": "0123456789abcdef0123456789abcdef01234567"}
  ]
}
```

Only `github.com` and `gitlab.com` repository identities with one owner and repository segment are
accepted. A commit, when supplied, must be a 40-hex SHA. Inputs are bounded to 100 projects and
256 KiB. If the input is absent, the job publishes a validated `SKIPPED` receipt with reason
`not-requested-no-scorecard-projects` and does not use the network.

Launch a staged Linux-owned run:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --job ossf_scorecard --wait
```

## Evidence contract

Attempts live under:

```text
runs/<run_id>/data/jobs/02-ossf-scorecard/whole/attempts/<attempt_id>/
```

Each accepted applicable attempt contains `manifest.json`, normalized
`outputs/scorecard-results.json`, `outputs/summary.md`, bounded raw `response-NNN.json` files,
separate stdout/stderr, structured stream events, command metadata, validation receipts and status.
Publication occurs only after repository/commit identity, Scorecard version, check structure,
freshness and every artifact hash validate.

The worker sends only bounded unauthenticated HTTPS GET requests to the fixed
`api.scorecard.dev/projects` endpoint, follows no redirects, sends no target content or credentials,
and limits each response to 4 MiB. HTTP 404 means no published result and is recorded as a coverage
gap. Rate limits, other HTTP errors, timeouts, transport failures, malformed JSON, identity drift,
and invalid JSON2 fail the attempt. A newer failed attempt blocks any older success.

The public Results API contains published/cached results. For a public repository absent from that
dataset, use a separately designed and authorized pinned Scorecard CLI worker; this ingestion job
must not misrepresent a 404 as a live scan result or a clean project.

## Qualification

Qualification completed on Windows and in the Linux code-server on 2026-09-19:

- five focused behavioral tests passed on each platform;
- registry/graph validation passed with 83 records and 42 jobs;
- the loaded Linux Dagster repository included both the standalone job and lifecycle op;
- live engagement run: `ossf-dagster-2db37e67`;
- accepted Dagster run: `91ff058a-f631-416e-9873-a16bcc35d2fa`;
- accepted attempt: `09686a87f7c04bdfb6a7d80668c69959`;
- reuse Dagster run: `c0486d9a-3c83-4d68-a694-43c5ba8a4038`, which reused that attempt and
  wrote a reuse receipt;
- service image: `sha256:4e6f79b3ef9df020ceaa1a86a2d1d469fb6c2224f38f4e0fdcec6cd80dd15513`;
- fetched repository commit: `f92023a3f77879f96e0c9c1305f289d755be4bb6`;
- reported Scorecard: `v5.5.0` at `c395761df6afe1a69e476bc60a013a94bcbc153f`;
- raw response SHA-256: `ed1029e1ae2e6609f9a561d5ae5bdda919d51bdb2a39719e6d9e218ecc4c6fd1`;
- normalized results SHA-256: `f9deddb775c7721c353f43d8af62ea038384fa551208d3875eb9a20863bcc0c7`;
- worker SHA-256: `9ddea9fbf69066cc2862068e915461d3ab9a28a2275c25b8e0c58b3d1af427ed`;
- test SHA-256: `f1cc2c1db0c6747a65f24ae25070c456e487b8fe5f04619de4aba17eae67ef0c`.

The first live launch attempt was rejected before execution because the long-running Dagster code
server still held the earlier repository definition. No work attempt was created. After confirming
there were no active runs and restarting only the code server, the registered job launched and
completed successfully.
