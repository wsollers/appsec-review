# NVD reference feed

This directory is the local publication root for the asynchronous NVD JSON/API 2.0 feed. Feed
payloads and mutable state are intentionally ignored by Git; only this operator contract is
tracked.

The first successful `nvd_reference_sync` Dagster run downloads and validates the official yearly
JSON 2.0 feeds from 2002 through the current UTC year. Later scheduled runs query bounded CVE API
2.0 last-modified windows from the last published cursor. The schedule runs every two hours in UTC.
Set `NVD_API_KEY` in the deployment environment to use an NVD-issued key; the value is never written
to this directory.

Publication is fail closed:

- Dagster permits one run carrying the `nvd_feed_id=nvd` tag;
- an OS advisory lock plus `locks/lease.json` heartbeat permits one writer;
- work is retained under `staging/<attempt_id>/` until validation completes;
- payloads are stored as content-addressed blobs and snapshots are immutable manifests;
- `current.json` advances atomically only after validation;
- a failed refresh preserves the prior last-good pointer and records a failed attempt.

Operators must not delete lock files. An expired diagnostic lease is recoverable only after the
coordinator acquires the process-owned kernel lock; the recovery receipt is retained. Run
`python -B appsec-review-process/nvd_feed.py verify` to verify the current manifest chain and blobs.

NVD data is enrichment only. It does not establish that a component matches an affected product,
that vulnerable code is reachable or exploitable, that a severity applies to the reviewed target,
or that a finding exists. Engagement use must pin a snapshot and apply the separately approved
freshness policy.
