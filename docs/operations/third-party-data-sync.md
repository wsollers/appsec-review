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
grype_db_sync:             fetch -> import -> publish
mitre_sync:                fetch -> normalize -> publish
kev_sync:                  fetch -> normalize -> publish
epss_sync:                 fetch -> normalize -> publish
cve_bin_tool_db_build:     resolve_nvd_snapshot -> build -> publish
                                      ^
                                      |
                              nvd_sync.publish
```

NVD, OSV, Grype, MITRE, KEV, and EPSS are independent branches. The executor attempts every runnable unit even when
another branch fails. Only units whose own dependency failed are skipped; the attempt and process
status are `FAILED` when a branch fails. The direct claimed-unit launcher does not write task
receipts for unstarted dependents or publish an accepted handoff for that failed attempt. Every
started task writes `status.json` and, on success, `result.json` beneath the execution attempt. These receipts contain stable unit,
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

With the opt-in `[signing] image_enforcement = "required"`, a pre-existing `image` is launched by ID
only after its signature verifies (see [signing](signing.md)); a freshly built one is derived and
unverified. With the default `"disabled"`, the image is launched by ID without an envelope check. The
optional `image_id` setting (`sha256:<64 hex>`) pins the image whatever the enforcement setting: the
tag must then resolve to exactly that ID, the step never builds it, and
`appsec-review signing sign-image --all-pinned` signs it. Without the pin an enforcing step verifies
whatever the tag currently resolves to, so a retagged but signed image is accepted.
The repository configuration leaves the pin unset: only the review-host session that builds and
smokes the image records its ID and then signs it (see [signing](signing.md#named-gaps)).

## Immutable publication provenance

New claimed publications retain their existing shared snapshot payloads and add small immutable
`provenance/<snapshot-id>/<sha256>.json` records. Each binds the manifest's exact bytes, original
application run/job/attempt and orchestration invocation, claim/configuration hashes, and an
input/configuration/publisher computation fingerprint. A fresh computation remains `computed`
when identical snapshot bytes already exist; separate producers never overwrite one another.

Publication records are retained **independently of producing runs**, alongside their snapshots
and NVD parent/blob chains. Removing a producing run does not invalidate a consuming run's
provenance. The retained record is an application assertion, not a reconstructed private claim;
only hashes and bounded identity metadata are exported, not target contents, prompts,
credentials or complete configuration. The application-owned feed root is the authority;
these records are not third-party signatures or acceptance decisions.

Consumers use per-attempt `feed-snapshot` receipts pointing to small run-local proofs and the
global records. The consumer's hash-pinned configuration allowlists the exact feed root under
repository `data/`. Snapshot selection is pinned permanently, independently of `current.json`.
Acceptance and resume verify records, manifests and files again, including NVD parent/blob
chains. A new manifest requiring provenance cannot be treated as legacy when a record is missing.
Legacy snapshots retain explicit unknown-original-producer labels. The Grype consumer requires the
new validated `grype-snapshot/2` contract; old manually imported `/1` databases are not promoted
into validated snapshots.

The existing nonblocking writer lock continues to reject concurrent snapshot publishers.
Record writes use atomic no-replace publication. NVD publishes a complete private directory
before exposing its snapshot path; failures leave the prior current pointer unchanged and
permit retry without replacing complete evidence. Claimed incremental NVD work verifies its
selected parent rather than silently rebuilding over a damaged pinned input.
No retention cleanup, live feed migration or copying of snapshots into runs is introduced.
See [shared-artifact provenance](review-data-indexing.md#shared-immutable-objects-and-attempt-receipts)
for the full scope and legacy limitations.

## Source and resource policy

All source selections, paths, worker counts, byte/record bounds, timeouts, tool settings, and the
schedule live in `appsec-review.toml` under the semantic job/step/task hierarchy.

- NVD bootstraps the official CVE 2.0 yearly feeds and then uses bounded last-modified API windows.
  Transport failures (including truncated responses, timeouts, HTTP 429 and transient server
  errors) use bounded exponential backoff. The NVD settings centrally configure
  `request_timeout_seconds`, `download_timeout_seconds` (socket timeouts), `max_attempts`,
  `retry_delay_seconds`, and `retry_max_delay_seconds`. A `Retry-After` longer than the configured
  delay bound fails rather than retrying too early. Permanent HTTP errors and integrity/protocol
  violations fail immediately.
  Within a download, retries resume the written offset using `Range` and a strong ETag or
  Last-Modified `If-Range` validator. Changed identities or inconsistent ranges fail; a server
  returning a full response restarts the file instead of appending it. Unverified partials are
  never published and are restarted on the next job invocation.
  Completed yearly downloads are cached in the ignored `data/feeds/nvd/downloads/` directory
  (under the configured `feed_root` for other roots). Every bootstrap fetches fresh official
  `.meta` files and rechecks compressed size, uncompressed size, and SHA-256 before reusing a
  cached year. Changed or corrupt cache entries are explicitly invalidated and downloaded again,
  so a late-year transport failure does not require downloading earlier verified years again.
  A failed refresh still leaves the previous published pointer unchanged. An NVD API key is
  optional and changes incremental API pacing; it does not repair truncated yearly feed files.
  Every snapshot (manifest schema `nvd-snapshot-manifest/2`) also publishes `index/nvd.sqlite`, keyed
  by CVE id with the English description, CWE weakness ids, CVSS metrics (family, version, vector,
  base score, base severity), `vulnStatus`, published and last-modified timestamps, and the raw
  record hash. It is built from the parent snapshot's index plus the new metadata layers (a `/1`
  parent without an index is replayed from its whole layer chain); a later layer overrides an earlier
  one unless its `last_modified` is older. Rows are inserted in CVE order into a fresh database, so
  the same layers give the same bytes. The manifest's `files` entry hashes the index, so
  `current.json` verification and per-run pinning cover it.
- KEV downloads the CISA Known Exploited Vulnerabilities catalog JSON from `url` (host allowlist
  `allowed_hosts`, default `www.cisa.gov`), bounded by `max_source_bytes` and `max_records`, with
  `timeout_seconds` and an optional `sha256` pin. Normalization rejects a catalog without
  `catalogVersion`/`dateReleased`/`vulnerabilities`, a declared `count` that disagrees, a malformed
  or repeated `cveID`, or a non-ISO `dateAdded`/`dueDate`, and writes `index/kev.sqlite` (CVE id,
  vendor/project, product, vulnerability name, date added, due date, known ransomware use, CWE ids,
  catalog version).
- EPSS downloads the FIRST daily `epss_scores-current.csv.gz` from `url` (host allowlist
  `allowed_hosts`, default `epss.empiricalsecurity.com`), bounded by `max_source_bytes`,
  `max_uncompressed_bytes` and `max_records`, with `timeout_seconds` and an optional `sha256` pin.
  Normalization requires the `#model_version:...,score_date:...` comment line and the
  `cve,epss,percentile` header, unique well-formed CVE ids, and probabilities in `[0, 1]`, and writes
  `index/epss.sqlite` (CVE id, EPSS, percentile, score date, model version). The daily file changes
  every day, so leave `sha256` unset unless a specific file must be reproduced.
- OSV downloads only the explicitly configured ecosystem archives and builds a SQLite lookup index
  with configured result limits. Inference queries that index; it does not scan ZIP archives. The
  default `ecosystems` are PyPI, crates.io, npm, Go, Maven, Packagist, NuGet, and RubyGems: every
  ecosystem whose lockfiles osv-scanner extracts offline and the build families produce. Each
  published `sources/<ecosystem>.zip` can be mounted for osv-scanner's offline database (each launch
  mounts only the ecosystems its lockfiles need; see [`static-analysis.md`](static-analysis.md)), so
  a lockfile of an ecosystem left out here is a named coverage gap. Measured 2026-10-15 the eight archives are
  291,048 records and 573 MB uncompressed (npm alone 218 MB compressed, 230,351 records), inside the
  configured `max_archive_bytes`, `max_uncompressed_bytes`, and `max_records` bounds. An advisory
  published in several ecosystem archives (for example a GHSA record) is stored and counted once
  with the affected packages of every copy.
- MITRE requires Enterprise ATT&CK, CAPEC, and CWE in `source_selections`; configuration that omits
  any of them is rejected. Mobile and ICS ATT&CK are optional: they remain fully configured but
  become active only when added to `source_selections`.
- MITRE snapshots (manifest schema `mitre-snapshot/2`, `index_schema = mitre-index/2`) publish
  `index/mitre.sqlite` with each CWE weakness's Common_Consequences in the `cwe_consequence` table
  (one row per consequence, in catalog order: its scopes and technical impacts). Notes and
  likelihoods are not captured. Capture is bounded to 32 consequences per weakness, 16 scopes or
  impacts per consequence and 128 characters per term. Terms are whitespace-normalized and
  deduplicated, and `consequence_truncated_weaknesses` counts weaknesses that were cut. The
  inference review derives each claim's `impact_class` from these rows
  (`cwe-impact-derivation/1`). A `mitre-index/1` snapshot has no consequences, so no impact class
  can be derived until `mitre_sync` runs again.
- Each MITRE source may carry an optional `sha256` pin; a downloaded file that does not match fails
  the fetch. Without a pin the hash is recorded but not verified. The ATT&CK and CAPEC sources are
  pinned; CWE is currently unpinned, so its download is not hash-verified.
- Every download has a transport bound, source URL, retrieval timestamp, size, and SHA-256. Archive
  expansion and record counts are bounded, and archive member paths are validated.
- KEV and EPSS snapshot identities exclude retrieval timestamps and HTTP validators, so republishing
  identical content yields the same content-addressed snapshot.

Feed publications are immutable snapshot directories. A manifest hashes every published file, and
`current.json` advances atomically only after full validation. A failed refresh leaves the prior
last-known-good pointer unchanged.

## Per-run pinning and freshness

### Grype database cache

`grype_db_sync` replaces `tools/publish_grype_snapshot.py`. Only the maintenance job downloads
database bytes. It fetches the official v6 `latest.json` and the relative `.tar.zst` archive over
verified HTTPS, refuses redirects, and checks the archive against the listing's SHA-256. An
inactive listing, unsupported schema, missing timestamp, stale build, or excessive future build
fails the branch without advancing `current.json`.

The publisher incrementally decompresses one complete zstd frame with a bounded window and
total expanded bytes. Tar headers (including bounded PAX metadata) count toward the member limit;
only one regular `vulnerability.db` is extracted. Links, sparse files, devices, duplicate files,
unexpected paths, oversized members, truncated frames and trailing compressed data are refused.
The pinned Grype image then runs its supported `db import /target/vulnerability.db` to hydrate
the raw database, followed by `db status -o json` against a read-only cache mount. All Grype
invocations use `network = "none"`, a read-only root, CPU/memory/time/output bounds, and a kernel
file-size limit. No missing image is built or pulled. The observed image ID is pinned across
version, import and status invocations and the existing signature policy still applies.

The central `grype_db_sync.settings` table configures listing/host selection, exact tool release,
schema major (6), listing/archive/expanded/database byte limits, tar-member and zstd-window limits,
download/run timeouts, memory, and age limits. Defaults are a 64 KiB listing, 1 GiB archive,
4 GiB expanded tar and hydrated database, eight tar headers, 128 MiB zstd window, 300-second
download socket timeout, 900-second tool timeout, 6 GiB container memory, a five-day maximum
database build age, and five minutes of future-clock tolerance. These are configured bounds,
not claims that the current live database fits them.

The immutable manifest retains upstream schema/build identity, both download receipts (URL,
retrieval time, byte size and SHA-256), and the validating image/tag/tool release. It hashes every
published file: `6/vulnerability.db`, `6/import.json`, `source/latest.json`,
`validation/version.json`, and `validation/status.json`. The downloaded archive and container
execution receipts remain under the producing attempt's protected `work/` dataset. Import and
status must agree with the upstream listing, including schema and build time. Publication rechecks
the imported hashes before the shared atomic snapshot publisher advances the last-known-good
pointer; failed fetch/import/validation leaves it unchanged.

`steps.grype_db_sync.feed.verify` resolves exactly one hash-verified cache with bounded manifest
and file sizes and rechecks freshness from the **upstream build**, not pointer publication time.
Both existing scanner consumers use their run's frozen Grype settings and require the same tool
release/image; missing, stale or unvalidated caches are named gaps. This is a cache-consumer
interface, not a new vulnerability matcher. `tools.disable_grype = true` is unchanged; T-105
matching-stage work and T-106 nightly activation remain separate.

The Python runtime now requires `zstandard==0.25.0` in both the package and Dagster requirements.
Deploying this dependency change requires an explicitly authorized Dagster tooling-image rebuild,
then the normal source reload/signing procedure. It does not require rebuilding the Grype image.

### Indexed reference feeds

`job_review_data_indexing` pins each feed's verified current snapshot into the run
(`feed_pins`, recorded in its `load.accepted_inputs` artifact). A feed is pinned only when its
pointer, manifest, and every manifest-hashed file verify and the manifest hashes the feed's index
(`index/nvd.sqlite`, `index/osv.sqlite`, `index/mitre.sqlite`, `index/kev.sqlite`,
`index/epss.sqlite`); otherwise it is `unavailable` with a reason. A snapshot whose `published_at` is
older than `feed_max_age_days` (default 14), or its entry in `feed_max_age_days_overrides`
(`kev = 7`, `epss = 3`), is pinned with `stale: true`. Products that join a stale or unavailable feed
record named gaps (`stale_feed`, `<feed>_stale_feed`, `<feed>_feed_unavailable`) and publish
`stale`/`partial` coverage; they never publish an empty result as complete. The inference review
validates claim CWEs only against a fresh pinned MITRE catalog and records a gap when it falls back.
It derives CWE impact classes from a fresh or stale pinned catalog; a stale one records the stale
gap on each derived factor. An unavailable catalog derives none.

Every record from these feeds is reference context. A KEV listing, an EPSS score, or an NVD CVSS
vector describes the advisory everywhere, not the target, and never satisfies a proof obligation.

## Verification status

The fetch, normalize, index, publish, verify and pinning code paths are tested offline with small
fixture feed files (valid, malformed, oversize, hash mismatch, tampered index, stale), including
NVD index determinism and override order. Real downloads from CISA, FIRST/Empirical Security, NVD,
OSV, and MITRE are not exercised by tests; the configured URLs and the live formats (in particular
the EPSS host and comment-line format, and the KEV field names) are unverified until a live run.
Grype units use small real zstd/tar fixtures and fake HTTP/Docker boundaries to exercise bounds,
validation, immutable publication, provenance and offline consumer failure behavior. Actual
Grype import/hydration, upstream archive compatibility, native-engine commissioning, deployment
and nightly execution have **not** been validated by these units.
For the next separately authorized Grype validation, retain the exact image/release, upstream
listing/archive identity, import/status receipts and published file hashes; establish that the
real hydrated cache fits the configured limits and mounts read-only for that same networkless
tool. A failed refresh must leave the prior pointer and snapshot bytes unchanged. This scenario
is not an automatic unit-test or deployment gate.

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
delay is enforced. Docker must be available for the cve-bin-tool build and the preinstalled Grype
validator image. A nonzero exit means at
least one source branch failed; inspect the attempt's unit receipts rather than treating an
unavailable source as successful.
