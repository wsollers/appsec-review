# OSV bulk feed

The OSV vulnerability database, treated the same way as the NVD feed: a writer publishes immutable
snapshots, a read-only binding checks age, a Dagster op refreshes it, and SCA binds to it. Reference
data only: nothing here establishes that a component is vulnerable, reachable or exploitable.

## Layout

Publication root `data/feeds/osv` (override `APPSEC_OSV_ROOT`; git-ignored):

```
current.json                      atomic pointer: snapshot id + manifest sha256
snapshots/<snapshot_id>/
  manifest.json                   source URLs, per-ecosystem sha256/bytes/records/fetched_at/etag,
                                  gaps, licences by advisory prefix, index hash
  NOTICE.txt                      attribution and no-redistribution notice
  index.sqlite                    lookup index (SQLite + FTS5), hash-listed in the manifest
  db/osv-scanner/<ecosystem>/all.zip
staging/  locks/  events.jsonl
```

`db/` is exactly the cache root OSV-Scanner's offline mode expects
(`<db>/osv-scanner/<ecosystem>/all.zip`), so it can be mounted read-only as `/inputs/osv-db`.
The brief's `<ecosystem>/all.zip` layout was deliberately nested one level (`db/osv-scanner/`)
because the worker's fixed mount contract (`/inputs/osv-db`, `XDG_CACHE_HOME`) is re-verified by
`dependency_workers.py` and must not change.

Ecosystems (GCS directory names, verified against the bucket): `npm`, `Go`, `Maven`, `crates.io`,
`NuGet`, `Packagist`, `PyPI`. Source: `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip`.

## Modules

| Module | Role |
|---|---|
| `osv_feed.py` | Writer. Downloads (conditional GET on the stored ETag, 2 GiB transport cap), verifies each archive is a CRC-clean zip of JSON advisories with unique ids, builds the index, publishes `snapshots/<id>` then flips `current.json`. Keeps the last N snapshots (`APPSEC_OSV_KEEP`, default 3, current always kept). `python osv_feed.py sync|verify`. |
| `osv_snapshot.py` | Read-only binding. Resolves `current`, re-hashes every archive and the index, enforces `max_age`, returns the read-only mount dir. Imports no network code. |
| `osv_index.py` / `osv_lookup.py` | Index build and queries; the JSON CLI. |
| `dependency_snapshot_registry.register_osv_feed` | Bridges a verified feed snapshot into the SCA dependency registry as database kind `osv` (hard links, not copies). CLI: `dependency_snapshot_registry.py register-osv-feed`. |
| `bench_osv_index.py` | The measurement behind the index decision (`docs/osv-index-measurement.md`). |

## Ages and failure

- Ceiling 14 days (1,209,600 s), same as NVD, measured against the OLDEST usable ecosystem's
  `fetched_at`. Over-age is FAILED (`SNAPSHOT_TOO_OLD`), never "OK with a staleness gap"; the SCA job
  fails on it. Absent feed is BLOCKED.
- A per-ecosystem failure is recorded and never deletes the last good data: that ecosystem's previous
  archive is carried forward with its ORIGINAL `fetched_at` (status `CARRIED_FORWARD`, so the ceiling still
  applies), or, if it never had one, it is a recorded gap (`gaps` in the manifest and identity).
  A gap is a coverage gap for that ecosystem, never "no known vulnerabilities". OSV-Scanner exits 127
  with "could not find local databases for ecosystems" when the SBOM has a gapped ecosystem; the
  existing `osv_exit_accepted` workaround therefore stays. Only a total failure fails the sync.
- An upstream 304 (unchanged ETag) reuses the prior bytes and refreshes `fetched_at`.

## Dagster

`osv_sync_work` runs beside `nvd_sync_work` in `nvd_reference_sync` (tag `osv_feed_id=osv`, same
2-hour schedule, same network pool). The ops are independent: one failing does not skip the other.
`APPSEC_NVD_SCHEDULE=stopped` stops both (there is no separate OSV schedule). Set
`APPSEC_DEPENDENCY_REGISTRY_ROOT` to also bind each published snapshot into the SCA registry; unset,
the op only publishes. `APPSEC_OSV_ROOT` is exported by `orchestrator/dagster/code-location.sh`.

## Licences

Mixed. The manifest's `licences` lists each advisory-id prefix with its record count and the licence
recorded for it (`GHSA`/`GO`/`PYSEC`/`OSV` CC-BY-4.0, `RUSTSEC`/`GSD` CC0-1.0, `MAL` Apache-2.0, Ubuntu
CC-BY-SA-4.0; unlisted prefixes such as `DRUPAL` are recorded as `unspecified`). The table is our reading of OSV's
documentation: verify before relying on it. `NOTICE.txt` ships with every snapshot. Do not redistribute
snapshots or the index outside the run/host cache.

## Commands

```
python appsec-review-process/osv_feed.py sync      # normally the Dagster op does this
python appsec-review-process/osv_feed.py verify
python appsec-review-process/osv_lookup.py by-id GHSA-xxxx-xxxx-xxxx
python appsec-review-process/osv_lookup.py by-alias CVE-2021-44228
python appsec-review-process/osv_lookup.py by-package --ecosystem PyPI --name django --version 3.2.0
python appsec-review-process/osv_lookup.py by-symbol Default --package github.com/gin-gonic/gin
python appsec-review-process/dependency_snapshot_registry.py register-osv-feed \
    --feed-root data/feeds/osv --registry-root <registry> --now 2026-09-29T00:00:00Z
```

`by-package --version` uses a generic dotted-numeric comparator over `SEMVER`/`ECOSYSTEM` ranges and
listed versions, not each ecosystem's official ordering; entries it cannot evaluate are kept and marked
`unknown`. Package names are normalised (PEP 503 for PyPI; case-folded for NuGet and Packagist).
