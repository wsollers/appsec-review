# Dependency vulnerability database snapshots

The dependency analysis workers do not access the network. Grype and OSV consume immutable,
content-addressed snapshots registered by `appsec-review-process/dependency_snapshot_registry.py`.
The nominal operator path is:

1. Supply an already mirrored Grype database or OSV offline vulnerability directory plus its
   closed metadata record.
2. Register it with `dependency_snapshot_registry.py register`.
3. Run the Grype or OSV B13 adapter through `execute_registered`, with an explicit freshness
   ceiling. Missing snapshots block; stale or modified snapshots fail distinctly.

Automated mirror synchronization is deferred operations/hardening work. It must be a separate
operator-invoked boundary with an exact network permission grant, fixed destinations, pinned
download hashes and sizes, redirect denial, safe archive extraction, and an auditable handoff to
the registry. It must not add network access to analysis workers or their B13 requests.
