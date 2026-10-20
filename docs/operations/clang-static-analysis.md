# Operating Clang static analysis

The Clang job runs after an accepted `job_cpp_compiled_analysis` handoff. Its central configuration
must define the exact three-step topology below and the bounded settings consumed by the producer:

```text
load.accepted_cpp -> analyze.scopes -> acceptance.publish_handoff
```

- `workers`: concurrent accepted C/C++ scopes;
- `max_output_bytes`: maximum result document and execution file-size boundary;
- `max_diagnostics_per_scope`: maximum normalized diagnostics per engine and scope;
- `clang_tidy_checks`: exact Clang-Tidy check globs; and
- `clang_analyzer_checkers`: exact Static Analyzer checker or package names (`core`, `alpha.security`). Patterns such as `alpha.security.*` are rejected: clang fails every unit on one.

The container catalog entry is `tool-clang-static-analysis`, built from
`containers/tools/clang-static-analysis`. Build and validate it through the catalog driver, then run
startup, functional, and security acceptance before relying on its output. The job has no
`enabled` setting of its own and runs in every review graph; the catalog entry carries no
`image_id` pin, so the executor does not check this image's digest. A missing local
image becomes a scope gap; it is not equivalent to zero findings. A scope whose compile units are
all outside Clang support (assembly, CUDA) is `SKIPPED_NA` in `not_applicable_scopes` and is never
launched; a scope with no compile commands at all is `unavailable`.

Operators should inspect the accepted summary's counts and gaps, then query `observations` coverage
for `clang-static:<project-id>`. Raw action documents, execution receipts, and rewritten compilation
databases remain under `data/clang-static/` as protected run artifacts. Published retrieval records
contain only bounded, source-mapped observations and resolving hashes.

Retries reuse a scope checkpoint only when its identity (accepted scope, tool identity, checker
selection, bounds, and adapter) matches and every referenced run artifact still verifies. A changed
checker set or compile database produces a new immutable shard.

For development verification, run the producer and adapter suites together:

```text
python -m pytest -q tests/test_clang_static_analysis.py tests/test_clang_static_tool.py --basetemp=test/tmp/clang-static
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
checkpointed; an unsupported unit is `not_applicable`; zero seeds is a clean skip with a gap
(`COMPLETED_WITH_GAPS`). The driver writes a per-unit outcome list (`units`) beside the diagnostics so a
failed unit is named; fix-its are detected from `-fdiagnostics-parseable-fixits` and plist fix-it hunks and
never applied. In the code-graph index, checks in the reviewed table `graph/analyzers.py` can corroborate a
CodeQL `sink_site` or add an inexact analyzer-only one (`docs/architecture/seeded-neighborhoods.md`
section 9). The `clang-static.py` change alters the `tool-clang-static-analysis` image
identity: rebuild and re-pin it. Contract: `docs/architecture/seeded-neighborhoods.md`.
