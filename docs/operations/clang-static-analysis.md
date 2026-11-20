---
title: "Operating Clang static analysis"
kind: "operations"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_clang_static_analysis", "job_cpp_compiled_analysis"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Operating Clang static analysis

The Clang job runs after an accepted `job_cpp_compiled_analysis` handoff. Its central configuration
must define the exact three-step topology below and the bounded settings consumed by the producer:

```text
load.accepted_cpp -> analyze.scopes -> acceptance.publish_handoff
```

- `workers`: concurrent accepted C/C++ scopes;
- `max_output_bytes`: maximum result document and execution file-size boundary;
- `max_diagnostics_per_scope`: maximum normalized diagnostics per engine and scope (1–100000);
- `clang_tidy_checks`: exact Clang-Tidy check globs, applied after clearing default checks and
  with an explicit non-inheriting configuration rather than target `.clang-tidy` files; and
- `clang_analyzer_checkers`: exact Static Analyzer checker or package names (`core`, `alpha.security`). Patterns such as `alpha.security.*` are rejected: clang fails every unit on one.

The container catalog entry is `tool-clang-static-analysis`, built from
`containers/tools/clang-static-analysis`. Build and validate it through the catalog driver, then run
startup, functional, and security acceptance before relying on its output. The job has no
`enabled` setting of its own and participates in the normal enabled review graph. Host-observed
image IDs come from frozen host bindings, not a committed `image_id` in the recipe catalog;
the executor verifies the resolved expected ID and configured signing policy. Follow
[image-pin verification](image-pin-verification.md), not a catalog edit. A missing local
image becomes a scope gap; it is not equivalent to zero findings. A scope whose compile units are
all outside Clang support (assembly, CUDA) is `SKIPPED_NA` in `not_applicable_scopes` and is never
launched; a scope with no compile commands at all is `unavailable`.

Operators should inspect the accepted summary's counts and gaps, then query `observations` coverage
for `clang-static:<project-id>`. Raw action documents, execution receipts, and rewritten compilation
databases remain under `data/clang-static/` as protected run artifacts. Published retrieval records
contain only bounded, source-mapped observations and resolving hashes.

Both frontends run in the accepted, rebased compile directory, including build subdirectories;
relative include options retain that context. The wrapper drains combined compiler output in
fixed-size chunks, retains at most 8 MiB per command, reads at most 8 MiB plus one overflow byte
per plist, and limits accumulated diagnostics to both the configured count and 8 MiB of serialized
record bytes. Every cut is explicit. Trace notes retain source paths, physical coordinates and
supported ranges; the job resolves them against accepted bytes. Invalid primary spans are dropped
with a gap, never clamped to EOF. Unresolving trace points/ranges remain explicitly unresolved.
Each trace carries reported/retained counts and a truncation flag, which the graph consumer preserves
when applying its own smaller display limit.

Retries reuse a scope checkpoint only when its identity (accepted scope, tool identity, checker
selection, bounds, and adapter) matches and every referenced run artifact still verifies. A changed
checker set or compile database produces a new immutable shard. Wrapper documents, raw streams and
detached native references are verified too; missing evidence is an integrity failure, not a cache hit.
Seed population omissions and source-observation provenance are part of the seeded identity.

For development verification, collect the desired files first, then use the bounded test wrapper
with that exact count (replace `COUNT` below):

```text
scripts/run-tests.sh --expect-tests COUNT --parallel --test-workers 2 --shuffle-seed 221122 -- tests/unit/job_clang_static_analysis/
```

These tests validate bounded normalization and injected execution. The tool-image acceptance is a
separate container check; a mocked run never proves that the pinned image is locally available.

## Seeded mode

In seeded mode the job writes only the translation units that contain a finding location into the compile
database the analyzers read (`jobs/job_clang_static_analysis/seeded.py`; bounds in
`[jobs.job_clang_static_analysis.settings.seeded_bounds]`). There is no whole-program fallback. Every
diagnostic in those units is kept and labelled `at_seed`, `in_seed_function`, `in_neighborhood`,
`outside_neighborhood` or, without an accepted seeded IR neighborhood, `unclassified` with a named gap.
Diagnostics carry the check id, severity, fix-it presence and trace length, and are filterable through
`query_observations`. A unit that fails to compile or analyze is a gap on its seeds and is not
checkpointed; an unsupported unit is `not_applicable`; zero seeds is a nonexecuted scope with a gap, not clean coverage
(`COMPLETED_WITH_GAPS`). The driver writes a per-unit outcome list (`units`) beside the diagnostics so a
failed unit is named; fix-its are detected from `-fdiagnostics-parseable-fixits` and plist fix-it hunks and
never applied. Aggregate exit zero without complete per-file outcomes is **incomplete**, not legacy
success: affected seeds stay unresolved (`not_run`) and no checkpoint is saved. Valid evidence from
other files/engines remains available. When no selected file has a verified successful outcome from
either engine, coverage is unavailable, including all-unit failures. Unsupported-only scopes remain
`SKIPPED_NA` in summary counts and manifest metadata, without fabricated measured coverage.
In the code-graph index, checks in the reviewed table `graph/analyzers.py` can corroborate a
CodeQL `sink_site` or add an inexact analyzer-only one (`docs/architecture/seeded-neighborhoods.md`
section 9). The `clang-static.py` change alters the `tool-clang-static-analysis` image
identity: an operator must rebuild this image, verify its new image/release identity and refresh the
host binding before use. `Dockerfile` copies the wrapper into `/opt/appsec`; reloading mounted Python
alone does not update it. The package asset lock is unchanged. Application-source changes separately
require the normal signed-source reload. These are manual rollout/acceptance steps, not unit-test
gates. Contract: `docs/architecture/seeded-neighborhoods.md`.

The [canonical job page](job_clang_static_analysis.md) distinguishes full-mode partial-result
reuse from seeded failure retry and records the independent acceptance checks.
