# Third-party data synchronization

`job_third_party_data_sync` is the Dagster-independent runtime job that refreshes external reference
data. Its schedule is declared once in `appsec-review.toml`: nightly at `00:00 UTC`. The production
Dagster deployment launches this same job for both console and scheduled runs, while the Python
runtime remains the authority for dependency ordering, validation, receipts, and publication.

## Topology and failure behavior

The unit graph is:

```text
nvd_sync:                  fetch -> process -> publish
osv_sync:                  fetch -> index -> publish
mitre_sync:                fetch -> normalize -> publish
cve_bin_tool_db_build:     resolve_nvd_snapshot -> build -> publish
                                      ^
                                      |
                              nvd_sync.publish
```

NVD, OSV, and MITRE are independent branches. The executor attempts every runnable unit even when
another branch fails. Only units whose own dependency failed are marked `SKIPPED`; the job result
and process status are `FAILED` when any unit failed or was skipped. Every task writes `status.json`
and, on success, `result.json` beneath the execution attempt. These receipts contain stable unit,
step, dependency, timing, status, error, and output identities suitable for later Dagster display.

The cve-bin-tool builder resolves and re-hashes the exact NVD snapshot published by this execution,
replays those already-downloaded NVD layers in order, and runs cve-bin-tool 3.4 in a pinned-base
container with networking disabled. It never invokes an NVD downloader. The image is built from
`tools/cve-bin-tool/`; its resulting image id and tool version are recorded in the database
manifest. When the configured `image` tag is missing locally, the step runs `docker build` on
`build_context` first; that build installs cve-bin-tool from PyPI and needs network access.
`build_timeout_seconds` (default 1800) bounds the image build and `run_timeout_seconds` (default
3600) bounds the networkless database build container. Scanning consumers must still treat CVE
matches as applicability leads rather than findings.

## Source and resource policy

All source selections, paths, worker counts, byte/record bounds, timeouts, tool settings, and the
schedule live in `appsec-review.toml` under the semantic job/step/task hierarchy.

- NVD bootstraps the official CVE 2.0 yearly feeds and then uses bounded last-modified API windows.
- OSV downloads only the explicitly configured ecosystem archives and builds a SQLite lookup index
  with configured result limits. Inference queries that index; it does not scan ZIP archives.
- MITRE requires Enterprise ATT&CK, CAPEC, and CWE in `source_selections`; configuration that omits
  any of them is rejected. Mobile and ICS ATT&CK are optional: they remain fully configured but
  become active only when added to `source_selections`.
- Each MITRE source may carry an optional `sha256` pin; a downloaded file that does not match fails
  the fetch. Without a pin the hash is recorded but not verified. The ATT&CK and CAPEC sources are
  pinned; CWE is currently unpinned, so its download is not hash-verified.
- Every download has a transport bound, source URL, retrieval timestamp, size, and SHA-256. Archive
  expansion and record counts are bounded, and archive member paths are validated.

Feed publications are immutable snapshot directories. A manifest hashes every published file, and
`current.json` advances atomically only after full validation. A failed refresh leaves the prior
last-known-good pointer unchanged.

## Metadata placement

Two deliberately different metadata scopes exist:

- `runs/metadata/` is host-level mutable coordination metadata. It contains only last-known feed
  identities under `feeds/` and the most recent job outcome under `jobs/`. It is useful for operator
  status and scheduling, is always re-verifiable against immutable feed snapshots, and is never
  evidence for a particular review execution. Its contents are ignored by Git.
- `runs/<yyyy-mm-dd-####>/` is immutable-by-convention execution evidence. The resolved TOML copy is
  under `data/configuration/`; job and per-task status/results are under
  `data/jobs/job_third_party_data_sync/attempts/<attempt-id>/`. These receipts bind the exact feed
  identities and errors observed by that execution. They are the source for later orchestration UI
  display and audit, not the mutable host metadata pointers.

Downloaded archives, indices, databases, feed snapshots, global metadata, and run receipts are
generated local state and must not be committed.

## Operation

Production operators should launch and verify through Dagster using the exact commands in
[`deploy/dagster/README.md`](../../deploy/dagster/README.md). The console is available at
<http://localhost:3000>. Direct runtime invocation remains useful for local diagnosis but is not the
Dagster acceptance path:

```powershell
python -m appsec_review run job_third_party_data_sync --trigger manual
```

Set `NVD_API_KEY` to use the NVD authenticated rate. Without it, the configured unauthenticated
delay is enforced. Docker must be available for the cve-bin-tool build. A nonzero exit means at
least one source branch failed; inspect the attempt's unit receipts rather than treating an
unavailable source as successful.
