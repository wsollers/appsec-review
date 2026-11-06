---
name: codeql-release-recompile
description: Repository-agent procedure for a CodeQL image or release change and graph-export or custom QL changes, checking exact operator release and source identities and reusing the existing bounded compile scripts before an authorized review. Use when preparing affected CodeQL tooling.
metadata:
  audience: repository-agent
---

# Prepare a CodeQL release and query recompile

## Authorization and reuse

[Root AGENTS.md](../../../AGENTS.md) governs. Follow the existing
[coordination procedure](../multi-session-coordination/SKILL.md) for host-owned pins, source
freezes, shared resources and integration, and [docs-sync](../docs-sync/SKILL.md) for cumulative
documentation reconciliation. Do not copy these procedures or interpret examples as permission
to publish, replace another owner's image declarations or move an active run's source.

This is a repository-agent procedure, never a review-worker instruction or a grant of worker
authority. Integration tests, acceptance tests and live operations require an explicit user
request; they are never automatic repair, merge or completion gates. Compilation is tool
preparation, not a review, but consumes Docker/cache resources and requires the owning operator's
authorized build scope. A request to write this skill or repair Python code is not that scope.
The manual commands below are not executed automatically when this skill is loaded.

## Procedure

1. **Pin the exact change.** Record the repository revision and changed graph-export/custom QL
   files, runner source and Dockerfiles. Read the
   [rule registry](../../../rules/registry.toml), pack `qlpack.yml` dependencies and suites.
   Match each affected pack's explicit library version to the supplied release; do not replace
   pins with wildcard dependencies to silence a compile failure.
2. **Resolve installed identities with the owner.** Compare configured `source_image_tag`,
   immutable `source_image_id`, `version` and CLI `commit` in
   [CodeQL settings](../../../src/appsec_review/config/codeql.py) with the approved installed
   source and [asset lock](../../../containers/tools/codeql/assets.lock.json). A tag or version
   label alone does not establish the source image. The registry's compile image must resolve
   to that exact approved source image ID on the intended daemon. Reconcile disagreement with
   the host owner; do not pull, retag, re-pin or hash licensed installed payloads as a workaround.
   Keep supplied payload declarations distinct from hash-verified customer evidence.
3. **Check release and runner provenance.** Read `[review_policy.releases]` in
   [central configuration](../../../appsec-review.toml). Record `codeql` and `codeql_runner`
   declarations, effective numeric non-root UID:GID and exact query sources. For preinstalled
   runtimes, also verify `source_image_id`, `build_image_id`, `runtime_image_id`,
   `runtime_user`, `codeql_release_id`, `runner_release_id` and `runner_source` against the
   accepted environment. `image` means the image supplies the runner; `application` means the
   fixed application asset is mounted read-only. Application-supplied runners are not supported
   in native execution in the current slice. A present image is not evidence that an unknown
   runner is compatible. See [CodeQL operations](../../../docs/operations/codeql-analysis.md).
4. **Plan with the existing wrappers.** Reuse
   [compile-codeql-queries.sh](../../../scripts/compile-codeql-queries.sh) or its
   [PowerShell twin](../../../scripts/compile-codeql-queries.ps1), not a parallel compiler or
   ad hoc container. They delegate to [containers/build.py](../../../containers/build.py)
   `query-packs --warm`. The PowerShell twin enters WSL on Windows; it does not authorize a
   Windows-filesystem checkout. The following templates are for an authorized operator in
   the owning Linux checkout:

```text
bash scripts/compile-codeql-queries.sh --dry-run --language go
bash scripts/compile-codeql-queries.sh --language go --ram 7000 --threads 8 graph-export-go
```

   `--language` is repeatable or comma-separated; positional values are registered pack IDs.
   Use only selectors covering the real change. `--dry-run` compiles nothing, but still checks
   running Docker compile containers and reads configuration; it is not a daemon-free unit test.
   There is no wrapper `--config`, `--run-id`, image override or generic `--verify-only` option.
5. **Compile only what needs compiling.** After an image/release change or graph-export/custom
   QL change, complete the appropriate recompile before any separately authorized review.
   Select enabled registry entries with `warm = true`. Never warm the precompiled standard
   query suites or the licensed CERT pack that ships `.qlx`; a source-only type check is also
   not full query compilation. A new custom pack requiring compilation must be registered
   consistently rather than bypassing the registry. Compiles are sequential. Do not use
   `--allow-concurrent` to bypass another session's ownership or resource limits; preserve
   exit code 3 as a concurrency refusal, not a compile success.
6. **Verify the preparation, not imagined review coverage.** Inspect selected/skipped packs,
   exit status and run-owned compile logs under `runs/container-builds/`. Record the exact
   revision, approved resolved source image ID, declared releases, effective user, selected
   pack/library identities, compile-cache identity, command and elapsed time. The shared cache
   is keyed by declared CodeQL release and effective user in both
   [builder](../../../containers/build.py) and [runtime](../../../src/appsec_review/codeql/runtime.py);
   query/library bytes select entries within it. A dry run, no selected packs or a skipped pack
   is not successful compilation. Keep failed/missing coverage explicit.

## Current limitations

The wrapper resolves its registry image tag to an ID when compiling, but does not independently
compare that ID with the application's configured `source_image_id` or attest installed payloads.
The operator's exact-source check is therefore required; a successful compile is not provenance
proof by itself. The wrapper uses checkout configuration, not an arbitrary frozen run config.
Its cache uses operator declarations rather than detecting undeclared installed edits.

Different releases/configuration require a newly frozen run; never edit an old run's configuration
or assume its databases can be reused. Existing explicit predecessor admission, tool inventory,
custody and runtime checks still apply. No compile result proves language/build coverage, live
query correctness or finding quality. This procedure installs no licensed payload, provisions
no engine, starts no review and changes no worker grants.

## Verification and handoff

Use affected offline [registry/wrapper units](../../../tests/test_rule_pack_registry.py),
[preinstalled-runtime units](../../../tests/test_codeql_preinstalled.py) and
[analysis units](../../../tests/test_codeql_analysis.py), not automatic full/live suites.
Record focused commands, elapsed times, results and the tested revision using the owning Linux
environment and `test/tmp/` isolation. Record actual compile preparation separately if authorized;
otherwise mark it pending before a future review. Update affected operations docs and give the
integration owner the exact ready revision and prerequisite gaps. Mark integration, acceptance
and live validation **NOT RUN** unless explicitly authorized and actually completed.
