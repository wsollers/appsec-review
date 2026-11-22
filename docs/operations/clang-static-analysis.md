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

The plist adapter follows the LLVM 18 emitter's two collections: diagnostic-level `notes` followed
by flat `path` pieces. Calls are events with `depth`, not nested call objects. Standalone notes,
events, pop-ups and control edges preserve their origin, piece ranges and resolving accepted-source
spans. The shared 256-piece bound applies across both collections. Each retained piece has at most
16 ranges or control edges and 4096 message characters; `trace_omissions` separately counts omitted
pieces and omitted details of retained pieces. The reader validates these counts. Span projections
stay within the existing index payload-depth bound rather than raising it.
Plist range ends are inclusive **byte** coordinates: resolution validates the UTF-8 boundary
after the last byte, including a continuation byte at the end of a multibyte character. Diagnostic
points and range starts still require a code-point boundary; split-character ends, newline/EOF
sentinels and out-of-source bounds are not accepted as range endpoints.

Graph diagnostics preserve upstream `trace_omissions` (steps, ranges, edges and message characters)
unchanged. Additional graph display cuts are reported separately in `trace_display_omissions`;
detail loss in a one-step trace is not misrepresented as merely retaining one of one steps.

Positive plist regressions are **constructed, emitter-schema-faithful LLVM 18.1.8 fixtures**, not
captured compiler evidence. The only existing checked-in native plists found for this job identify
Ubuntu Clang 18.1.3 and contain no diagnostics. They validate the empty format, not positive note,
call, range or control-edge fidelity. The earlier synthetic nested-call/diagnostic-range example
is not native-format positive evidence; nested calls are now a malformed-output regression.
The inspected format authority is
[LLVM 18.1.8 PlistDiagnostics.cpp](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/clang/lib/StaticAnalyzer/Core/PlistDiagnostics.cpp);
`PlistSupport.h` defines the emitted inclusive range endpoint convention.

Retries reuse a scope checkpoint only when its identity (accepted scope, tool identity, checker
selection, bounds, and adapter) matches and every referenced run artifact still verifies. A changed
checker set or compile database produces a new immutable shard. Wrapper documents, raw streams and
detached native references are verified too; missing evidence is an integrity failure, not a cache hit.
Seed population omissions and source-observation provenance are part of the seeded identity.

For development verification, collect the desired files first, then use the bounded test wrapper
with that exact count (replace `COUNT` below):

```text
scripts/run-tests.sh --expect-tests COUNT --parallel --test-workers 2 --shuffle-seed 221122 -- tests/unit/job_clang_static_analysis/test_diagnostic_fidelity.py tests/unit/job_clang_static_analysis/test_plist_fidelity.py tests/unit/job_clang_static_analysis/test_outcomes_and_reuse.py
```

These example selectors validate diagnostic fidelity, outcome accounting and reuse with injected
execution; select other affected files explicitly for other changes. The tool-image acceptance is a
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
Outcomes identify the exact selected compilation context, not merely a filename: the identity binds
the rebased working directory, ordered compiler arguments, source path and accepted source SHA-256.
Each expected identity must appear exactly once with its matching source path; missing, duplicate
or unexpected identities remain incomplete. Clang-tidy reads a one-command compilation database for
each action, so two flag/cwd variants of one file cannot masquerade as repeated success for one variant.
In the code-graph index, checks in the reviewed table `graph/analyzers.py` can corroborate a
CodeQL `sink_site` or add an inexact analyzer-only one (`docs/architecture/seeded-neighborhoods.md`
section 9). The `clang-static.py` change alters the `tool-clang-static-analysis` image
identity: an operator must rebuild this image, verify its new image/release identity and refresh the
host binding before use. `Dockerfile` copies the wrapper into `/opt/appsec`; reloading mounted Python
alone does not update it. The package asset lock is unchanged. Application-source changes separately
require the normal signed-source reload. These are manual rollout/acceptance steps, not unit-test
gates. Contract: `docs/architecture/seeded-neighborhoods.md`.

**Hard pre-live gap:** old baked wrappers do not satisfy the current note/path or exactly-once
compile-context outcome contract. Before any live use, rebuild the affected tooling image, verify
its source/release and observed image identity, update the host binding under the configured signing
policy, and complete authorized native acceptance using non-empty reports. A Python reload or
passing synthetic units does not satisfy this requirement. No such rollout or positive native
acceptance is claimed by these offline regressions.

The [canonical job page](job_clang_static_analysis.md) distinguishes full-mode partial-result
reuse from seeded failure retry and records the independent acceptance checks.
