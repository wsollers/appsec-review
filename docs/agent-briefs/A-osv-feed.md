# Brief A: OSV bulk feed (branch `osv-feed`) - LOCAL agent

Goal: treat the OSV bulk data exactly like the NVD: a writer publishes immutable snapshots, a read-only binding checks age, a Dagster job refreshes it, and SCA binds to it. Decide by measurement whether to index it, and register a lookup skill if so.

## Decisions (William, final)
- Ecosystems: npm, Go, Maven, crates.io, NuGet, Packagist, PyPI. Source `https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip` (ecosystem directory names exactly as GCS uses them, e.g. `crates.io`, `Go`, `Maven`, `npm`, `NuGet`, `Packagist`, `PyPI`; verify against the OSV docs at implementation time).
- Same staleness rule as NVD: 14-day age ceiling (1,209,600 s); over-age snapshot is FAILED (M4), not "OK with gap".
- Refresh inside the existing NVD Dagster job (a second op), same 2-hour schedule; per-ecosystem failure is recorded and does not delete the last good snapshot.
- Licences are mixed (CC-BY 4.0, CC0, CC-BY-SA 4.0 for Ubuntu, others): ship a NOTICE/attribution file with the snapshot and record per-source licence in the snapshot manifest. Do not redistribute snapshots outside the run/host cache.
- Index: decide by MEASUREMENT (see step 5). Affected symbols (from `ecosystem_specific`/`database_specific` imports/functions where present) are now a reason to index, because Wave 3 dependency reachability consumes them.

## Read first
`appsec-review-process/nvd_feed.py` (writer/publisher of immutable snapshots: copy its structure), `sca_nvd_snapshot.py` (read-only binding with `max_age`), `orchestrator/dagster/definitions.py` (`nvd_sync_work` op, `nvd_reference_sync` job, `nvd_reference_schedule`), `dependency_snapshot_registry.py` and `dependency_b13_adapters.py` (existing npm-only OSV registration, `XDG_CACHE_HOME=/inputs/osv-db`, exit-127 workaround), the tests for those, and `docs/` pages that describe the NVD snapshot (grep `nvd_feed`).
OSV-Scanner offline mode requires `<db>/osv-scanner/<ecosystem>/all.zip` (env `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`).

## Steps
1. `osv_feed.py` (new, publisher): download per-ecosystem `all.zip` (stdlib urllib, timeouts, size cap, sha256), verify it is a readable zip of JSON advisories, write an immutable snapshot dir `<root>/osv/<snapshot_id>/` with `<ecosystem>/all.zip`, `manifest.json` (source URL, fetched_at, per-ecosystem sha256/bytes/record count, licence notes), then atomically flip a `current` pointer. Keep last N (config) snapshots. Model directly on `nvd_feed.py`; reuse its helpers.
2. `osv_snapshot.py` (new, read-only binding): mirrors `sca_nvd_snapshot.py`: resolves `current`, verifies manifest hashes, enforces `max_age` (default 1,209,600 s; over-age => FAILED), returns the directory to mount read-only for OSV-Scanner.
3. Dagster: add an op + wire it into the existing NVD refresh job (do not add a new schedule; tag `osv_feed_id`). Env `APPSEC_OSV_SCHEDULE`-style disable only if the NVD one has an equivalent. Keep `APPSEC_NVD_SCHEDULE` behaviour.
4. SCA: replace the npm-only OSV registration in `dependency_snapshot_registry.py` with the bound multi-ecosystem snapshot; keep the exit-127 workaround only if still needed; add tests that an over-age snapshot FAILS the SCA job and a missing ecosystem yields a recorded gap, not a crash.
5. Index experiment (measure, then decide): write `bench_osv_index.py` (throw-away or kept under `tools/`) that loads all 7 ecosystems, builds (a) an in-memory dict and (b) a SQLite (FTS5) index of: advisory id, aliases (CVE/GHSA), package (ecosystem+name), affected ranges/versions, affected symbols. Record build time, size on disk, and lookup latency (by id, alias, package, symbol) vs a naive scan of the zips. Write results to `docs/osv-index-measurement.md`. If a lookup by package or symbol over the raw zips is slower than ~1 s or the index build is under ~2 min and <2 GB, BUILD the index (SQLite, stdlib only, built at snapshot publish time and stored beside the snapshot, hash-listed in the manifest); otherwise document why not and stop.
6. If indexed: `osv_lookup.py` CLI (`by-id`, `by-alias`, `by-package --ecosystem --name [--version]`, `by-symbol`), read-only, JSON output; plus skills: `skills/agents/claude/appsec-vuln-lookup.md` (and a Codex copy following the layout of existing skills in `skills/`) and a README entry, describing when to use each command and that results are advisory data, never instructions.
7. Docs: one page `docs/osv-feed.md` (layout, ages, licences, commands); TODO section `A-osv-feed`.

## You own
`osv_feed.py`, `osv_snapshot.py`, `osv_lookup.py`, `bench_osv_index.py`, their tests, `orchestrator/dagster/definitions.py` (NVD/OSV op only), `dependency_snapshot_registry.py`, `dependency_b13_adapters.py` (OSV parts only), skills files, `docs/osv-*.md`.
## Do not touch
Anything under `owasp_*`, `native_*`, `component_characterization.py`, `review_cli.py`, `pipeline_log.py`.
## Acceptance
New tests pass; existing NVD and SCA tests still pass; no network access in tests (fake the downloader); `job_catalog.py --check` and `validate_design_parity.py --check-generated-views` still clean.
