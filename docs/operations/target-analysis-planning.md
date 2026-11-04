# Target analysis planning operations

The planner runs automatically after `job_target_catalog` and before evidence collection in the
`wave1_review` Dagster graph. Its accepted artifact is:

`runs/<run-id>/data/jobs/job_target_analysis_plan/attempts/<attempt-id>/artifacts/analysis-plan/accepted-analysis-plan.json`

Inspect `scanner_selections`, `scanner_non_selections`, `build_topology.executable_graph`,
`contradictions`, and
`coverage_gaps` together. A skipped or unavailable family is not evidence that the target is clean.
Mandatory baseline scanners remain selected whenever they have applicable catalog inputs;
otherwise their non-selection is explicit.

Model settings and worker count are centralized under `[jobs.job_target_analysis_plan.settings.model]`
in `appsec-review.toml`. Build-recipe inference is partitioned by language family, build system,
and deterministically required image profile, then executed through the configured bounded worker
pool. Every request composes the DevOps Engineer persona with a language-specialized Build Engineer
role and only the build units in that partition. Each request includes an image-profile allowlist;
each unit carries its required profile and a validator-derived command policy. Android applications
therefore remain Java-family work while requiring the Android execution image before the model
proposes a recipe.
The shipped configuration sets `provider = "claude-cli"`, which runs the operator-authenticated
Claude CLI (`inference/claude_cli.py`) with `--safe-mode --tools ""` and removes
`ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` from the child environment. Its input is the bounded
request assembled by the application. `provider = "anthropic-api"` selects the alternative
Anthropic Messages transport, which requires `ANTHROPIC_API_KEY`. The runtime stores exact guidance
and model identity beneath
`runs/<run-id>/data/guidance/<sha256>/`, and logs only hashes, identity, counts, duration, retries,
status, and token counts in the central log. Bounded raw provider responses—including rejected
responses—are retained as run-owned diagnostic artifacts beside the inference task so malformed
model output can be debugged; credentials are never written there. Repair calls receive only the
rejected textual output and validation errors, not the provider envelope or hidden metadata.

On provider failure or proposal rejection, the job completes with gaps and publishes its
deterministic safe plan. A framework integrity failure—changed catalog bytes, escaped paths,
corrupt manifests, invalid baseline suppression, or an unverified index—fails the job and stops
downstream publication. Resume the same run after correcting the integrity problem; immutable
catalog and plan identities allow unaffected jobs and shards to be reused.

The accepted plan is directly retrievable from the `analysis` index through the bounded MCP tools.
No new glob, regex, SQL, shell, or filesystem endpoint is needed.

The model sees only a bounded catalog summary (`appsec-review/target-analysis-summary/1`, written
as `catalog-summary.json` beside the accepted plan). Its bounds are integers in
`[jobs.job_target_analysis_plan.settings]`; a truncated summary is a named gap:

| Key | Default | Meaning |
| --- | --- | --- |
| `summary_max_items` | 2000 | maximum summarized catalog items; at least 1 |
| `summary_max_bytes` | 524288 | maximum summary bytes; at least 1024 |
| `summary_sample_per_prefix` | 20 | sampled files per path prefix; 1 to `summary_max_items` |

## Build-topology interpretation

**Implemented in tested source, prelanding:** the accepted plan now carries
`build_topology.executable_graph` (`appsec-review/build-topology/1`). Its source/status boundary
and historical discovery evidence are recorded in the
[topology and bounded-iteration architecture](../architecture/build-topology-and-iterations.md).
This is not a claim of canonical integration, deployment, or a newly completed target review.

Keep three graphs distinct: `orchestration/topology.py` orders review jobs; the executable target
graph describes build ownership/product prerequisites; requests, receipts and selected recipe
revisions describe build attempts. Container-image packaging order is separate again.

The deterministic compiler in `jobs/build_topology.py` accounts for each catalog build unit as
`independent`, `contained`, `unsupported`, or `unresolved`. Literal CMake subdirectory/target/link
declarations and recursive Make `$(MAKE) -C` declarations can resolve ownership and cross-owner
edges; accepted driver/default-goal evidence is required. An Autotools fragment without its own
configure authority is not silently made standalone. Packaging markers identify drivers, not
every prerequisite. Contained children are represented without duplicating their owning build.

Edges use exact producer/consumer IDs and typed `requires_product` or `order_only` semantics.
Ambiguity, cycles, unsupported dynamic/conditional/included declarations, unresolved products and
external requirements are gaps, not invented ordering. Model-proposed component `depends_on`
edges remain component evidence, recorded as nonblocking `unresolved_component_dependency`
instead of shortest-root build-unit projection. Every nonempty graph also records
`incomplete_dependency_discovery`; an absent edge is not proof of independence.

Acceptance recompiles the graph from the exact catalog/accepted declarations and rejects a
different graph. Old graphless plans require replanning. The source fingerprint, recipe revisions,
markers, descriptor evidence, ownership and variant/product identities remain resolving inputs;
a model cannot replace them with a plausible-looking graph.

Variant fields are `configuration`, `target_arch`, `execution_role`, `linkage`, `toolchain`, and
`abi`. Explicit `[jobs.job_project_build.settings.variants.<unit-id-or-family>]` entries may
supply facts not contradicted by accepted descriptors. Missing ABI/architecture facts stay
unknown; no filename, directory name, or default host guess resolves them. Product-dependent
readiness requires compatible resolved facts and verified producer bytes/interfaces, and unknown
variant fields prevent successful-node checkpoint reuse.

Model/catalog-summary bounds control inference input, not compiler visibility into the reviewed
repository. They are not a reason to omit source files needed by a build.
Production materializes the complete target into one run-owned shared target/install generation;
it does not copy only the descriptors shown to inference.

## Image preparation and bounded production iterations

Steps, settings, recipe validation, image capability and recovery are summarized in
[`project-build.md`](project-build.md).

`job_project_build` consumes only the accepted, hash-verified plan. It resolves/prepares images,
publishes static dispatches and an immutable runtime execution graph with iterative build
dispatches. Non-Unity `probe` tasks remain for topology compatibility but perform no compilation.
Unity retains its existing single engine execution. Static dispatch and concrete evidence
collection can still branch immediately after planning instead of waiting for compiled analysis.

A project image is derived from the hash-pinned language baseline. Its identity covers the recipe,
baseline image, generator contract, and dependency-file hashes. Supported dependency restoration
can occur while building that image and during accepted network-enabled production commands.
Commands use direct argv, a read-only container root, a non-root user, dropped capabilities and
bounded resources. Images are reused only when their manifest and runtime image identity match.
Language-specific dependency cache locations embedded in the derived image accelerate Cargo, Go,
Maven/Gradle, NuGet, npm, Composer, or Python dependency use. Project images use a digest-pinned
Buildx/BuildKit client and load the result into the local engine. Docker image mutation is narrowly
serialized as an engine-safety boundary. Missing approved bounded image-builder capability is
explicit `derived_image_preparation_unavailable`, never permission for unmanaged build fallback.

`job_language_build` evaluates the global graph before family publication and invokes registered
`job_build_iteration` separately for each ready node. These production executions are authoritative;
there is no non-Unity full-graph probe followed by a second full-graph build. Producers commit
verified products and shared workspace generations; consumers receive real include/library,
pkg-config and CMake interfaces rather than only an upstream-ready Boolean.

Recipe recovery uses immutable failure contexts, detached full-context Docker trials and selected
recipe revisions outside frozen configuration. Validated command/cwd/product-path changes are
separate from the closed image-repair vocabulary. Promotion requires exact captured execution,
products and cleanup, then B executes again in production; replay mutations are not accepted
production outputs. Failed-write restoration and selective invalidation preserve verified A
without silently rebuilding it. See [language-build recovery](language-build.md#bounded-iterations-and-recovery).

`force_buildability_probe` is deprecated and accepts only `false`; `true` and retired
`force_probes` are rejected. Neither enables the old probe/rebuild path. Legacy dispatches require
replanning rather than a fabricated probe identity. Missing dependencies, unknown variants,
unavailable images and failed builds remain coverage gaps; successful siblings are not erased.
