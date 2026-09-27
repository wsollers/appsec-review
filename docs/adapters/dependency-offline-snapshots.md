# Dependency vulnerability database snapshots

The dependency analysis workers do not access the network. Grype and OSV consume immutable,
content-addressed snapshots registered by `appsec-review-process/dependency_snapshot_registry.py`.
The nominal operator path is:

1. Supply an already mirrored Grype database or OSV offline vulnerability directory plus its
   closed metadata record.
2. Register it with `dependency_snapshot_registry.py register`.
3. Run the Grype or OSV B13 adapter through `execute_registered`, with an explicit freshness
   ceiling. Missing snapshots block; stale or modified snapshots fail distinctly.

`appsec-review-process/dependency_snapshot_sync.py` is the separate operator boundary for an
automated refresh. Each invocation requires an exact network permission grant and a closed sync
specification containing the fixed HTTPS URL, archive hash and byte count, closed database
metadata, required content paths, and extraction byte/file limits. Redirects, links, traversal,
unlisted destinations, unexpected bytes, missing database content, and oversized extraction fail
before publication. The script downloads beneath registry-owned staging and hands the verified
directory to the registry's atomic immutable publisher. It never runs in an analysis worker.

The module exposes `sync_periodic_references` as the extension callable for the existing NVD
periodic reference job. The current Dagster definition calls `nvd_feed.sync` directly and has no
reference-publisher extension seam. Schedule wiring is therefore a follow-up orchestration change:
replace that direct call with this callable and provide trusted Grype/OSV specs and grants from
operator configuration. This candidate intentionally does not edit the concurrently owned Dagster
definition, graph, or catalog.

Lookups support a configurable warning threshold below the hard maximum age. A database remains
usable, with an explicit warning, between those thresholds. It fails as stale only beyond the hard
ceiling; a missing snapshot remains a distinct blocked state.
