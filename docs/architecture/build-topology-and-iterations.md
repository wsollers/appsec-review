# Target build topology and bounded iterations

## Status and evidence boundary

**CURRENT/OBSERVED** below describes source commit
`1c7b38e1c927a1b5c46036df26e2da988e70557a`, tree
`80ad9506d23eea107a99f163e2c606557183c6ad`, and the coordinator-verified historical
run evidence identified below. This documentation pass inspected source, not raw model responses
or the target checkout. **PROPOSED** describes the agreed switch and is **NOT YET IMPLEMENTED**.
No implementation merge, complete target build topology, successful overall build, or accepted
SPDX endpoint is established by this page.

The operational descriptions remain in [project-build](../operations/project-build.md),
[language-build](../operations/language-build.md), and
[target analysis planning](../operations/target-analysis-planning.md).
This page records the proposed change and the limits of the discovery attempt, not new worker
guidance or executable commands.

## CURRENT/OBSERVED: topology and source-visibility gaps

Keep three different graphs distinct:

| Graph | Meaning | Status at the source baseline |
| --- | --- | --- |
| Review-job DAG | Ordering application producers such as planning, project-build, language-build, and artifact indexing | Implemented in `orchestration/topology.py`; does not establish target build prerequisites |
| Target build graph | Build-unit ownership and actual producer-to-consumer prerequisites, including generated inputs and dependency products | Partial catalog/component relationships and downstream family-local readiness; not a verified complete artifact-backed graph |
| Attempt/iteration graph | Separate bounded executions, failures, replay candidates, accepted recipe revisions, and retries | The replacement described below is proposed; current per-attempt receipts and checkpoints are not independently completed per-node jobs |

Container catalog image dependencies are a separate packaging concern. Building the right
toolchain image does not establish that a target library was built before its consumer.

The source establishes the following narrower behavior:

| Surface | CURRENT/OBSERVED behavior | Remaining gap |
| --- | --- | --- |
| `job_target_analysis_plan/planning.py:264-286` | Creates `build_actions` for catalog build units and `component_build_root` relationships | A directory/build-root inventory is not an executable producer/consumer topology |
| Same file, `validate_proposal` and `merge_proposal`, lines 296-425 | Validates component identities and proposal cycles; merges component-level `depends_on` edges and recipes | Does not establish which exact build unit produces a required header, archive, generated source, or package interface |
| `job_project_build/job.py:1157-1181` | Maps each component to its shortest-root candidate action | Ambiguous component ownership is projected onto one action rather than resolved with build-unit/artifact evidence |
| Same file, `probe_handler`, lines 1360-1381 | Iterates family image entries and probes them | Probe execution does not schedule those entries by `build_dependencies` |
| Same file, `_copy_source`, lines 91-118 | Copies the unit root and accepted dependency files; applies directory-name exclusions | Required sibling sources and checked-in inputs outside that copy can be absent even at the correct command directory |
| `job_language_build/job.py:1655-1740` | Already selects dependency-ready layers, detects cycles, and blocks failed same-family dependents | Runs after project probes, inside family lanes; is not a full cross-family target scheduler |
| Same file, lines 219-242, 887-921, and 1670-1677 | Generic builds make another per-unit/per-attempt source copy; the generic/native call does not receive the computed upstream map | Readiness alone neither materializes upstream products nor adds include, linker, pkg-config, or CMake search paths |

These are references beneath `src/appsec_review/jobs/` at the named source baseline;
the review-job graph is beneath `src/appsec_review/orchestration/`.
The ordering that already exists should be reused and improved, not described as absent.
Static dispatch can proceed from the accepted plan independently of compiled work.
Unity already performs one engine build and forwards its receipt, rather than doing the generic
probe/rebuild sequence.

## CURRENT/OBSERVED: historical discovery and build attempt

The historical application run is `2026-11-04-0003`, controller
`barracuda-spdx-1c7b38e1-cd42-20261104T1600Z`. It was **OPERATOR_STOPPED**.
Project-build invocation `1c9317e6-5b40-43f4-9806-b464ecd75685` was **CANCELED**.
Coordinator-verified stop records reported the controller/local workload gone, no leases, and no
monitor schedule, with the original target, configuration, images, and five services preserved.
This historical stop does not authorize a restart.

The accepted historical plan contained 295 build units, 271 roots, 194 nonnull recipes, and
101 null recipes. These are discovery/recipe counts, not a proven 295-node executable DAG or
295 successful builds. Representative execution evidence establishes:

| Unit or event | Observed result | Limit of the conclusion |
| --- | --- | --- |
| GoogleTest `4edbc733908bc8fd0daa`, root `fsh-server/Server/lib/libs/protobuf/protobuf-2.5.0/gtest/make` | `make` ran in the correct directory, exit 2 without timeout; `../samples/sample1.cc` was missing | The 2502-byte target source existed but was omitted from the partial workspace; moving the command to the repository root or installing packages is not the fix |
| GoogleTest `87501fd49ba97c80b2d8`, root `fsh-server/Server/lib/libs/protobuf/protobuf-2.5.0/gtest/scripts/test` | `make` ran in the correct directory, exit 2 without timeout; `../../samples/sample1.cc` was missing | The same relative-layout problem is demonstrated for this unit, not for every native failure |
| Native hiredis `75dc990fe57ef051d2b8` | `gcc` compiled objects, `ar rcs libhiredis.a` ran, and `make` exited 0 | This is actual native compilation, not a successful complete target build or downstream link |
| Two Lua commands | Exit 0, but printed target/platform choices only | An exit-zero help/selection command does not establish compilation |
| GoogleTest repair proposals | Three no-op proposals per representative unit were rejected as `repair proposal repeated the current repair set` | Those receipts are not three further compiler executions; the initial immutable C++ image was valid |
| Changed-image repairs | Separately blocked by the missing operator-approved bounded builder | Image-preparation capability and missing project source context are different failures |

The hiredis archive was 161332 bytes, SHA-256
`359af9134b94eb2ebe940f8738e808072cc0dac4a278e1ff4b827840c1603d69`.
No accepted overall project-build/SPDX endpoint was reached. The last uncompleted historical
model call has remote-provider completion **UNKNOWN**; stopped local workers do not establish
remote completion.

Preserved records are under
`runs/metadata/barracuda-spdx-1c7b38e1-cd42-20261104T1600Z/`.
Their sizes and SHA-256 identities were verified by the coordinator; this documentation pass did
not reread the large evidence payloads:

| Record | Bytes | SHA-256 |
| --- | --- | --- |
| `operator-stop-terminal-20261104T182647Z.json` | 42537 | `7bf37be5905d65b1e99a9ef934669c496ff4001643e7fd50cc4e1e38dc2713dc` |
| `operator-stop-native-probe-preservation-20261104T182915Z.json` | 60489 | `ca205f8b490e9d1558ca9d23e3edcf6ca912326ef1f39e4f9f6921cc86c0f97d` |
| `operator-stop-native-original-captures-20261104T183059Z.json` | 142738 | `fddeffb7309576f6a74f9ca32ab667ab5c9ea79a5b8a3ff04291782196f11164` |

This attempt found build roots, recipes, real compiler/artifact evidence, source-context failures,
and repair-capability limits. It did not resolve every owner or producer/consumer edge.
Historical target paths and unit identities are examples, never generic runtime constants.

## PROPOSED / NOT YET IMPLEMENTED: evidence-backed build order

Resolve explicit build-unit identities and output ownership instead of projecting component
dependencies onto a shortest-root candidate. A nested Makefile, directory ancestry, or model
suggestion alone does not establish an independently executable product. A parent build may own
several subdirectories; schedule that owning build once and retain resolving membership for its
children rather than rebuilding overlapping units and double-counting coverage.

For each node, identify the accepted driver, source/configuration/target tuple, recipe revision,
image/toolchain, working directories, expected products, and exported dependency interface.
Resolve producer-to-consumer edges from accepted descriptors and include chains, project
references, generators, package metadata, and captured compiler/linker/file-access evidence.
Distinguish source-layout needs, generated-source/host-tool prerequisites, required library
products, ordering-only constraints, containment, and external prepared requirements.
These meanings are design requirements, not implemented schema fields.

Do not let different versions, ABIs, debug/release modes, host/target architectures, or static/shared
variants satisfy one another merely because a filename matches. Reject unknown endpoints and
self-edges; report cycles and unresolved ownership rather than inventing an order.
New evidence that changes an edge needs an identified graph revision and affected-consumer
revalidation, not an unrecorded mid-command graph mutation.

Evaluate prerequisites across the compatible target graph before filtering by language family.
Start with one production writer and deterministic topological ready selection; stable IDs
are only tie-breaks between genuinely ready nodes. A producer is satisfied only when its required
products and compatibility bindings verify. Parallel production writes remain deferred until
write-set safety is demonstrated.

## PROPOSED / NOT YET IMPLEMENTED: one shared run-owned production tree

Leave the original target untouched. Copy the complete reviewed target into a mutable workspace
under `runs/<run-id>` and preserve its relative source layout. All compatible production nodes
share that tree across disposable build containers. Do not isolate each node into another
source-only or full-repository private copy that loses upstream artifacts.
Preserve required checked-in inputs even when a directory is named `build`, `bin`, `obj`, or
`target`; metadata and safe in-tree symlink handling need explicit path-custody rules.
Never follow an escaping link into the host.

The original target, other runs, application credentials, and host credentials remain isolated.
Model descriptor limits constrain inference input, not compiler visibility into the reviewed
repository. Complete source visibility does not widen resource, network, cancellation, or
capture policy.

Keep stable logical source/install paths inside containers. Preserve generated headers, libraries,
code-generator products, pkg-config records, CMake products, and the shared run-owned install
prefix where required. Preserve relevant modes and library symlink chains.
Outputs installed only inside a disposable container will not survive for the next node.
Downstream commands must receive the real include/library and package-resolution interfaces;
ordering by itself does not materialize them.

Run each command in its source-backed correct directory. Configure, build, and export can require
different directories; complete filesystem visibility is not permission to move every command
to the repository root. Any new typed export/install action needs validated run-owned
destinations. It cannot bypass the current recipe restrictions with arbitrary shell or host writes.
Installation or configuration alone does not establish compilation success.

### Committed progress and restoration after failed writes

Sharing a tree means failed B can overwrite or delete A's files, generated configuration, or
shared install-prefix contents. A's prior success cannot be reused merely because its receipt
still says success.

Maintain committed workspace generations and durable successful-node state. Treat uncommitted
changes after failure, cancellation, or a worker crash as tainted. Before retrying B, verify the
last committed generation and restore overwritten/deleted state, including A's required artifacts,
inputs, metadata, and shared-prefix contents; remove failed-attempt-only outputs.
Restoration must not need to recompile an unchanged valid A.
If required state cannot be verified or restored, report the miss and rebuild the affected
prerequisite instead of claiming reuse.

Publish durable product identities before accepting a node: bind producer/attempt, graph/recipe
revision, source/configuration, toolchain/image, exact upstream products, paths, sizes/hashes, and
relevant symlink facts. Earlier accepted evidence must remain immutable even as the production
workspace changes. The storage and atomic publication/restoration mechanism is not implemented
by documenting this requirement.

## PROPOSED / NOT YET IMPLEMENTED: separate bounded build jobs

The desired display is a sequence such as:

```text
build_cpp   : A succeeds; commit A's progress and products
build_cpp1  : B/r1 fails; retain A; block B's consumers
replay B/r2 : detached Docker trial; no review advancement
build_cpp2  : verified winning B/r2 runs in restored production state
build_cpp3  : C runs using accepted A and B products
finalize    : aggregate the requested scope's real terminal dispositions
```

These are illustrative iteration labels, not registered job names, a CLI, or an implemented schema.
Use separate bounded Dagster invocations of a registered iteration job or small fixed family
wrappers, not unlimited generated Python job definitions or a renamed family-long inner loop.
The proposed first increment executes one node's configure/build/export/capture transaction per
production invocation, with its own invocation ID, iteration request, and immutable receipt.
Registry, central TOML, and Dagster must stay in parity; current enforcement is in
`src/appsec_review/runtime/registry.py:33-42` and
`src/appsec_review/orchestration/dagster/adapter.py:385-386`.

Persist each node's accepted progress independently of the family's eventual aggregate.
After B fails, preserve its real failure/cleanup record, stop that advancing branch, and expose
the need for a recipe revision. Keep A usable after verification/restoration. Do not burn the
remaining family budget on identical image guesses or silently restart A.
Separate scheduler state, build outcome, and invocation status; a successful image build or
finished invocation alone does not satisfy a consumer prerequisite.

Bind reuse to source, graph/configuration, accepted recipe revision, image/toolchain/releases,
exact upstream products, and execution/capture/output-policy identities. A change to B invalidates
B and affected descendants, not unchanged A. Changed A products invalidate its consumers.
Missing required releases or products remain named reuse/restoration gaps.
Keep recipe revisions as immutable run-owned inputs; do not edit the frozen resolved run
configuration to change B's recipe.

Choose one authoritative captured production build. Do not require two complete graph executions
just to reproduce today's project probes followed by fresh language builds. Project-build should
coordinate preparation and iterations, and downstream consumers should normalize/use verified
production receipts. A genuinely different required build configuration needs a distinct identity.
Preserve existing single-build engine behavior.

An intermediate node's success is not the aggregate build handoff or permission to launch
dependency/SPDX work as though the requested scope were complete. Finalization must distinguish
successful completion, terminal coverage with gaps, awaiting repair/in-progress, and stopped or
canceled work. Static work that does not need compiled products can remain independent.

## PROPOSED / NOT YET IMPLEMENTED: detached Docker recipe recovery

"Offline" means outside the advancing review, not necessarily network-disabled package
acquisition. It does not authorize an unmanaged builder, broader credentials, host writes, or
resource widening.

Select B's exact failed attempt, graph/workspace generation, original streams/capture, and verified
upstream products. A detached replay context must contain the same complete source layout and
A's required products at the same logical container paths. This recovery copy is separate from
the shared production graph: it is not per-node production isolation and must not mutate
production while trials run.

Record a new typed recipe candidate and run one bounded Docker trial with the required capture,
real streams, deadlines, cancellation, and cleanup. Recipe correction can address validated
command/cwd/export choices where supported; it is not inherently limited to today's four-field
image-repair proposal. Distinguish source-context, prerequisite, recipe, toolchain/image-preparation,
and compiler/linker failures, including a non-image-repairable outcome.
Reject repeated normalized candidates and exit-zero help commands as winning builds.

Adopt only a winning revision whose exact inputs, real products, and capture verify. Promote the
recipe and replay evidence, then execute B in a new production invocation after restoring/verifying
committed production state. Do not transplant opaque replay-directory mutations as accepted
production outputs. Stale source, graph, recipe, image, or upstream products reject promotion.

Prepared pinned images remain usable. A candidate needing a new image must use the existing
approved bounded-builder contract; absent capability is an explicit block, not an unmanaged
Docker fallback. A specifically network-offline replay additionally needs prepared images and
locally available dependency material; that mode is not established by the word "offline".

## PROPOSED / NOT YET IMPLEMENTED: tunable workspace retention

The proposed central typed policy defaults to retaining the latest **three eligible terminal
run workspaces**, sweeping on completion. Exclude active, leased, preserved, and resumable
workspaces. These exclusions mean the policy is not a hard cap of three directories.
Preserve durable logs, receipts, and accepted artifacts even when disposable workspace state is
purged; consumers must not depend solely on deleted mutable paths. Missing state is an explicit
recovery condition, never a successful reuse.

The configuration key/location, enablement/default, custody checks, and sweep implementation
remain proposed. No current retention setting or purge execution is asserted here.

## Reconciliation after implementation: pending

Phase 1 records the proposed switch and evidence limits. Phase 2 requires tested implementation
receipts and the exact merged canonical WSL main SHA. Reconcile this page and linked operations
pages against that source before marking any proposal implemented.

Record the real discovered owners/nodes/edges and unresolved relationships; actual command
directories and executions; produced artifacts; failed and retried iterations; adopted recipe
revisions; A's verified reuse/restoration after B's failed writes; invalidated consumers; and
observed retention behavior. Distinguish authored code, focused unit results, definitions-load
checks, and user-requested live validation. A definitions-load check is not a live Dagster run.

The coordinator reports a pre-existing failure in
`tests/test_target_analysis_plan.py::test_plan_is_resumable_indexed_and_has_exact_dag_position`
with `missing_release_identity` on the base and repaired SHA; do not report all tests green
or weaken the assertion. This documentation work does not execute build tests or live workloads.
No main merge, review restart, builder commissioning, cleanup, provisioning, or deployment follows
from this design document.
