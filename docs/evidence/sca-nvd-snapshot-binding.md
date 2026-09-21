# SCA NVD Snapshot Binding (V09)

Status: model and resolver only. No worker, graph node, manifest or contract consumes it yet; V05
and V11 wire it into `02-sca-vulnerability-match`.

ADR-0010 decision G3: SCA matching reads the NVD copy under `/data` published by the existing
`appsec-review-process/nvd_feed.py`. This binding needs no publisher work, no network and no B11
capability. (The SCA matcher's own databases do have new out-of-run publishers: V16, V17.)
`appsec-review-process/sca_nvd_snapshot.py` is the read-only consumer side of that decision.

It does **not** select, wrap or invoke a matcher, does not parse CVE content, does not cache, does
not write, and never fetches.

**Role after the SCA matcher sub-decision (ADR-0010 M1-M5, 2026-09-20).** The matcher is a pinned
syft + Grype image reading a mirrored Grype vendor database, with an independent OSV snapshot
beside it. The NVD snapshot this module binds is therefore **no longer the matcher's source**; it
stays for `06-cve-reachability` enrichment and as an independent cross-check. `match_basis: "cpe"`
in the identity record remains true of THIS database. The expanded match basis (`purl`, `cpe`)
belongs to V05's match-record schema, not here.

## What the publisher actually writes

Determined from `nvd_feed.py`, not assumed. Under the NVD publication root (publisher default
`<repo>/data/feeds/nvd`, or `APPSEC_NVD_ROOT`):

| Path | Written by | Notes |
| --- | --- | --- |
| `current.json` | `_publish`, via `atomic_json` (temp file + `os.replace`) | The sole commit point; the last-good pointer. `snapshot_id`, `manifest_sha256`, `published_at`, `cursor`. |
| `snapshots/<snapshot_id>/manifest.json` | `_publish` | Immutable. The directory holds nothing else. |
| `blobs/sha256-<sha256>.json.gz` | `_put_blob` | Content-addressed store **shared by every snapshot**. Written before publication, so a failed refresh leaves orphan blobs. |
| `locks/writer.lock`, `locks/lease.json`, `locks/recoveries/` | `WriterLease` | Writer exclusion and diagnostics only. |
| `staging/<attempt>/`, `state.json`, `events.jsonl` | `sync` | Diagnostics. Not authoritative. |

A snapshot is a **chain**: a `bootstrap` manifest (yearly feeds, one `blob` per `year` layer) and
zero or more `incremental` manifests (`api-last-modified` layers with `pages[].blob`), each naming
its `parent_snapshot_id`. The current database is the whole chain, so the binding verifies the
whole chain.

What binds what:

- `snapshot_id` = `"sha256-"` + the first **16 hex digits** of sha256 over the canonical manifest
  without `snapshot_id`. It covers `captured_at`, `cursor`, `parent_snapshot_id` and every blob
  hash and size.
- `current.json.manifest_sha256` = full sha256 of the current `manifest.json` bytes.
- Each blob's `sha256`/`size_bytes` are in the manifest; its path is its content address.
- A **parent** manifest is bound only by the 64-bit truncated `parent_snapshot_id`. The pointer
  holds no full hash for it.
- `current.json.published_at` is bound by nothing. The binding parses it and never uses it.
- **Nothing outside the publication root anchors the root.** There is no signature and no
  externally held hash. See "Limits".

The publisher exposes `nvd_feed.verify()`. The binding does not call it, for three reasons:
`nvd_feed` imports `socket`, `urllib.request` and (through `execution_state`) `subprocess`, which
would void the import-level no-network proof; `verify()` falls back to a default or
environment-supplied root when none is passed; and it is weaker than this task requires
(it does not validate the pointer or manifest schemas, accepts a layer that lists no blob, does not
check the snapshot directory's file set, and hashes the manifest and then re-reads it). The small
read path is re-implemented and pinned to the publisher by parity tests
(`PublisherParityTests`): snapshot-id rule, schema constant, `beneath` behaviour, and agreement
with `verify()` on a tampered blob. For the same reason the module does not import
`execution_state`; `beneath` is a line-for-line equivalent, tested against the original.

## API

```python
NO_AGE_LIMIT                                   # the explicit "no limit" policy value
resolve_snapshot(data_root, *, max_age: timedelta | NO_AGE_LIMIT, now: datetime) -> Resolution
fingerprint_component(identity: dict) -> str
verify_identity(identity: dict, data_root, *, max_age: timedelta | NO_AGE_LIMIT, now: datetime) -> Resolution
identity_consistency_errors(identity: dict) -> list[str]
```

`data_root` is the NVD publication root (the directory holding `current.json`). All three
arguments are required. There is no default root, the `APPSEC_NVD_ROOT` environment variable is
not read, and the wall clock is never read: the caller passes a timezone-aware `now`.

**Age policy (sub-decision M4).** By default a job uses whatever static snapshot is present and
records its age: it passes `max_age=NO_AGE_LIMIT`. A job or engagement may set a tighter limit by
passing a `timedelta`; if the snapshot's data is older than that, the outcome is **`FAILED`**
(`SNAPSHOT_TOO_OLD`), not a usable result with a staleness gap. `max_age` still has **no default**:
"no limit" is a value the caller passes on purpose, never something reached by omission, and
`None` is a `TypeError`. Wrong types raise `TypeError`/`ValueError`; they are caller bugs,
not outcomes.

`Resolution` is frozen: `outcome`, `reason`, `detail`, `identity`, `fingerprint_component`,
`gaps`, `pointer_reads`. Its constructor refuses contradictory states: `identity` and
`fingerprint_component` are non-`None` **if and only if** the outcome is `OK`, so a caller cannot
proceed by accident on a refused snapshot. It also refuses a `fingerprint_component` that was not
computed from that `identity`, and an `identity` whose `age_policy` contradicts the reason. `gaps`
is reserved and always empty. After construction the `identity` is **read-only at every
depth** (mutating it raises `TypeError`), so the record a worker publishes cannot drift from the
component it already fingerprinted. `copy.deepcopy(resolution.identity)` gives an ordinary editable
`dict`; `json.dumps(resolution.identity)` works directly.

### A persisted identity is a cache, never an authority

`fingerprint_component` and `identity_consistency_errors` bind the derived fields: `age_policy` is
`no-limit` exactly when `max_age_seconds` is null, a `within-limit` record whose `age_seconds`
exceeds its own `max_age_seconds` is rejected (that state is `SNAPSHOT_TOO_OLD` and never has an
identity), `age_seconds` must equal `evaluated_at - cursor`, neither timestamp may be later than
`evaluated_at`, and `snapshot_id` must be in `chain_snapshot_ids`.

That catches an independently edited record. It cannot authenticate one: whoever can rewrite
`vulnerability-database-identity.json` can edit `evaluated_at` and `age_seconds` together and the
record agrees with itself (a test pins this). So a consumer of a **persisted**
record uses `verify_identity`. `data_root`, `max_age` and `now` are required; it re-resolves and
re-verifies the snapshot from bytes, accepts the record only if every snapshot-bound field equals
the fresh one, and returns the **fresh** `Resolution`. Age, the age policy and the fingerprint
component are always taken from that, never from the record. A test asserts every schema field is
either snapshot-bound (compared) or re-derived (ignored), so a new field cannot slip between.

## Outcomes

The outcome set is closed and maps onto the v1.0 envelope terminal statuses
(`docs/adapters/worker-result-envelope.md`).

| Outcome | Reason | Meaning |
| --- | --- | --- |
| `OK` | `VERIFIED_NO_AGE_LIMIT` | Whole chain verified; the job passed `NO_AGE_LIMIT`. Age is recorded, never judged. |
| `OK` | `VERIFIED_WITHIN_LIMIT` | Whole chain verified; cursor age ≤ the limit the job set. |
| `FAILED` | `SNAPSHOT_TOO_OLD` | Whole chain verified, but cursor age > the limit the job set (sub-decision M4). No identity, no fingerprint component. Recovery: refresh the snapshot, or re-launch with the age policy the engagement intends. |
| `BLOCKED` | `DATA_ROOT_MISSING` | The publication root does not exist. |
| `BLOCKED` | `POINTER_MISSING` | No `current.json`: the publisher has never published here. |
| `BLOCKED` | `SNAPSHOT_MISSING` | A valid pointer names a snapshot whose directory does not exist at all. |
| `FAILED` | `UNSAFE_PATH` | A link anywhere on a path, a root that is not a directory, or a blob path that is not `blobs/sha256-<64 hex>.json.gz` (so `../` and absolute paths). |
| `FAILED` | `POINTER_INVALID` | `current.json` is not JSON, has duplicate keys, violates `nvd-current-pointer.schema.json`, has an unparseable timestamp, or vanished mid-read. |
| `FAILED` | `MANIFEST_MISSING` | Snapshot directory exists without `manifest.json` (partial). |
| `FAILED` | `MANIFEST_HASH_MISMATCH` | sha256 of the manifest bytes ≠ `current.json.manifest_sha256`. |
| `FAILED` | `MANIFEST_INVALID` | Schema violation, unparseable timestamp, or a layer/page/blob record that is not exactly the publisher's shape (a layer that lists no blob is rejected). |
| `FAILED` | `SNAPSHOT_ID_MISMATCH` | The id derived from manifest content ≠ directory name / declared id (current or any parent). |
| `FAILED` | `POINTER_MANIFEST_MISMATCH` | `current.json.cursor` ≠ manifest `cursor`. |
| `FAILED` | `SNAPSHOT_FILE_SET_MISMATCH` | The snapshot directory contains anything other than `manifest.json`. |
| `FAILED` | `CHAIN_INVALID` | Missing parent, cycle, bootstrap/incremental parent rule broken, an incremental snapshot that does not start at its parent's cursor, or one blob listed with two sizes. |
| `FAILED` | `BLOB_MISSING` | A listed blob is absent (partial). |
| `FAILED` | `BLOB_SIZE_MISMATCH` / `BLOB_HASH_MISMATCH` | Re-hashed bytes disagree with the manifest. Every blob in the chain is re-hashed on every call. |
| `FAILED` | `TIMESTAMP_IN_FUTURE` | Manifest `cursor` or `captured_at` is later than `now`; age cannot be established, so it is not reported as fresh. |
| `FAILED` | `READ_ERROR` | A file cannot be opened/listed or is not a regular file. |

### Why `BLOCKED` versus `FAILED`

The envelope says an unavailable required input is never a skip, that every terminal result
carries its failure cause and a recovery instruction, and that neither `BLOCKED` nor `FAILED` is publishable. `BLOCKED` here means
a **preflight blocker with nothing to verify**: the required input is absent and the recovery is
operational ("run `nvd_reference_sync`", "mount the data volume"). `FAILED` means the input is
**present and contradicts itself**: there are bytes on disk and they disagree with a hash, a
schema, a path rule or the chain. That is evidence of corruption or tampering, re-running the job
will not fix it, and it must not look like an ordinary "publisher has not run yet". The boundary
case is a pointer that names a snapshot: if the snapshot directory is wholly absent there is
nothing to verify (`BLOCKED`, matching the V09 acceptance text "missing pointer or snapshot");
if the directory exists but is incomplete, or a parent or blob is missing, the snapshot is partial
(`FAILED`).

### File-set rule

The manifest's file set must equal the on-disk set **within what the snapshot owns**. A listed
blob that is missing is partial (`FAILED`). An unlisted entry inside `snapshots/<id>/` is
`FAILED`. An unlisted file in `blobs/` is **not** a failure: the store is shared across
generations and the publisher writes blobs before the commit point, so an orphan blob after a
failed refresh is a normal producible state
(`test_orphan_blob_from_a_failed_refresh_is_a_producible_state_and_not_a_failure`). Unlisted blobs
are never read, counted, or reachable through the identity record. This is where the code
overrode the "any extra file fails" reading of the task.

## Readers and the writer lease

Readers never take, wait on, read, or delete `locks/`. The module does not contain the path. A
fresh, expired, corrupt or missing lease, and a publisher that currently holds the kernel lock,
leave the result byte-identical (`LeaseTests`).

The real race is the pointer swap. `current.json` is replaced atomically, so a read sees one whole
pointer. The resolver reads the pointer bytes **once**, reaches everything else from those bytes
(manifest bound by full sha256, parents and blobs bound by the manifest), and re-reads the pointer
at the end. If it changed, it re-verifies from the new bytes, at most `MAX_POINTER_READS` (3)
passes. If the pointer is still moving after that, it returns the generation it verified last:
snapshots and blobs are immutable and content-addressed, that generation was the published
last-good pointer at an instant inside the call, and nothing from another generation entered its
verification, so the answer is sound and never a mix. A swap to a corrupt generation fails closed.

## Identity record

`schemas/vulnerability-database-identity.schema.json`, closed, every property required; published
by the SCA job as `outputs/vulnerability-database-identity.json`.

`database_kind` (`nvd`), `feed_id`, `feed_schema` (`NVD_CVE/2.0`, as the publisher records it),
`publisher`, `publisher_manifest_schema`, `snapshot_id`, `snapshot_mode`, `parent_snapshot_id`
(nullable), `chain_snapshot_ids`, `manifest_sha256`, `content_sha256`, `retrieved_at` (manifest
`captured_at`), `cursor`, `file_count`, `total_bytes`, `evaluated_at` (`now`), `age_seconds`,
`max_age_seconds` (null under `NO_AGE_LIMIT`), `age_policy` (`no-limit` | `within-limit`),
`match_basis: "cpe"`, `limitations`. Schema id `appsec-review/vulnerability-database-identity/2`
(`/1` had `freshness: fresh|stale` and an integer-only `max_age_seconds`).

- **Age is measured from the manifest `cursor`**, not `captured_at`: the cursor is the instant up
  to which NVD modifications are reflected (the publisher takes it before downloading), so it is
  the honest data-currency time and the more conservative of the two.
- `content_sha256` is a full-strength sha256 over the ordered chain (`snapshot_id` + full manifest
  sha256 of every generation) and every verified blob (`path`, `sha256`, `size_bytes`). It
  compensates for parents being bound only by a 64-bit id: two chains that collide on a truncated
  parent id still get different `content_sha256` values.
- `limitations` always states that NVD is CPE-keyed, that a component with no CPE mapping is a
  **coverage gap and never "no known vulnerabilities"**, that the record is enrichment and not a
  finding, and that the root is not authenticated.

## Fingerprint component

`fingerprint_component(identity)` validates the record against its schema and its cross-field
consistency rules (above) and returns canonical
JSON of: component version, `database_kind`, `feed_schema`, `snapshot_id`, `manifest_sha256`,
`content_sha256`, `match_basis`. Component version `vulnerability-database-identity/2`.

It excludes `age_seconds`, `evaluated_at`, `max_age_seconds`, `age_policy` and `retrieved_at`:
including the clock would invalidate reuse on every run, and under M4 age is not a property of a
usable result at all. What stops a cached `OK` being reused once the same snapshot exceeds the
job's limit is **order**: the worker calls `resolve_snapshot` in preflight *before* reuse admission,
gets `FAILED` with no component, and never reaches the cache. (Version `/1` carried `freshness` in
the component for the old `OK_WITH_GAPS` model; that model is gone.)

## No network

- The module imports only `dataclasses`, `datetime`, `hashlib`, `json`, `os`, `pathlib`, `re`,
  `stat` and `schema_validate`. A test enforces this as an allowlist and a second test imports the
  module in a clean interpreter and asserts `socket`, `ssl`, `urllib.request`, `http.client`,
  `subprocess`, `nvd_feed` and `execution_state` are not loaded.
- Every scenario is run with `socket.socket`, `socket.create_connection` and `socket.getaddrinfo`
  replaced by raisers.
- A missing or over-age snapshot is reported; nothing ever tries to refresh it.

## Limits (stated plainly)

1. **Integrity, not authenticity.** Every field the binding trusts is re-derived from bytes and
   tied to `current.json`, but `current.json` itself is anchored to nothing. Whoever can write the
   publication root can rewrite manifest, snapshot id, directory name and pointer consistently —
   including `cursor`/`captured_at`, turning an over-age snapshot into one inside the job's limit. Editing a timestamp alone,
   or the timestamp plus the pointer hash, is caught; a full consistent rewrite is not, and
   cannot be by a reader. `test_documented_limit_consistent_rewrite_of_the_whole_root_is_not_detectable`
   pins this. Closing it needs a publisher change (a signature or an externally recorded pointer
   hash) and is out of V09's scope; the mitigation today is filesystem permissions on `/data` and
   the run pinning `snapshot_id` + `manifest_sha256` + `content_sha256` in its fingerprint.
2. **Truncated ids.** `snapshot_id` is 64 bits, and it is the only thing binding a parent
   manifest. `content_sha256` records what was actually verified but cannot make the publisher's
   link stronger.
3. **CPE-keyed coverage.** Ecosystem packages match more weakly against NVD than against an
   OSV- or advisory-keyed source, which is why the SCA matcher (sub-decision M1/M2) reads a Grype
   vendor database and an OSV snapshot instead. This binding identifies the NVD database only.
4. **Cost.** Every call re-hashes every blob in the chain (the full yearly feeds). That is the
   requirement; the binding does not cache. The SCA job should resolve once per attempt.
5. Blob contents are not decompressed or parsed. The publisher validated them at download time;
   the binding proves they are the same bytes.

## Integration notes for V05 / V11

- Call `resolve_snapshot` once in preflight, **before reuse admission**, with the attempt's clock
  and the job's age policy: `NO_AGE_LIMIT` unless the job or engagement configured a tighter
  `max_age`. Map `outcome` to the envelope status and copy `reason`/`detail` into the blocker or
  failure. `SNAPSHOT_TOO_OLD` is `FAILED`.
- Put `Resolution.fingerprint_component` in the job's input fingerprint; write
  `Resolution.identity` verbatim to `outputs/vulnerability-database-identity.json`. Take both from
  the same `Resolution`; never recompute the component from a record read back from disk.
- Anything that later reads a persisted identity (reuse admission, a downstream consumer, status)
  calls `verify_identity` with the data root and the current `now`; it does not trust the file.
- The matcher must read only blobs reachable from the verified chain (`chain_snapshot_ids`),
  never "whatever is in `blobs/`", and should re-resolve if it needs the file list.
- A consumer that matches against THIS database records `match_basis: cpe`; components without a
  CPE mapping are coverage gaps. The SCA node itself matches with Grype (M1), so its match records
  carry the basis Grype used (`purl` or `cpe`) per V05's schema.
- The age policy is per job (M4). There is no repository-wide `max_age`; the NVD README's
  "separately approved freshness policy" is superseded by this decision.
- The Grype DB mirror (V16) and OSV snapshot (V17) need consumer bindings equivalent to this one.
