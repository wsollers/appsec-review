---
title: "Target acquisition and build"
kind: "architecture"
subsystem: "target acquisition and build"
status: "current"
jobs: ["job_build_environment_analysis", "job_build_iteration", "job_language_build", "job_project_build", "job_review_intake", "job_sanitizer_build", "job_target_acquisition", "job_target_analysis_plan", "job_target_catalog"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---

# Target acquisition and build

## As built today

**Source boundary:** this description was checked against implementation commit
`80e04db89504a4b9f276aa1e336ad703235dd10c`, with the same-domain job documentation through
`73bd86f53dd5adaa5338b320dff4c67fd7198ef6`. The frontmatter retains the documentation program's
existing reconciliation watermark. Later Wave1a repair and
[T-150](../TODO.md#t-150-publish-complete-protected-review-decision-products) coordination is future
reconciliation context, not implementation incorporated into this worktree. No later checkpoint
is assumed landed. This is a source description, not new compiler, image, Dagster or live-review
validation.

The subsystem turns an explicit target selection into an accepted source inventory, planning
decisions and build evidence. Its useful result is not merely “the build passed”: it identifies
which units executed, which tool invocations were observed, which bytes were retained, which
products satisfy downstream prerequisites and which coverage remains missing.

### Acquisition establishes custody; intake establishes the review binding

A review can use an existing checkout or a configured system composed of several pinned
components. [Acquisition](../../src/appsec_review/jobs/job_target_acquisition/job.py) supports
Git, Perforce and supported review-provider exports; it is not restricted to one Git repository.
Without a requested system, the gate records `NOT_REQUESTED` and does not acquire anything.
With a system, it acquires components under the configured concurrency bound and composes one
target root. No available component is a failure; some available components can yield explicit
partial coverage.

The [acquisition library](../../src/appsec_review/target_acquisition/acquire.py) stages new
content, checks paths and file/byte bounds, then records source and tree identities. Existing
checkouts with records are reverified, never pulled or replaced. Stable system identity remains
in the manifest; per-pass actions/timestamps go to a verification sidecar, so re-verification
alone does not invalidate intake. Git transport/hook/filter restrictions and credential handling
belong to [acquisition operations](../operations/target-acquisition.md#safety). Acquisition uses
configured host tools and network transports; it is not a scanner-container operation.

Intake freezes the configuration/target binding and optional external binary-publication
identities. Its raw snapshot includes regular non-VCS target bytes and symlink identities even
when the catalog later excludes their contents. An inventory count is therefore not the target
fingerprint's coverage denominator. Model availability and image-pin gates precede this work;
their freshness and [host image bindings](../operations/image-pin-verification.md) are separate
from target evidence. [Input contracts](job-input-contracts.md) distinguish admitted selections,
actual reads and evidence authority.

### Catalog and planning do not grant build execution authority

The catalog separates bounded content inventory from descriptor discovery. It retains
language/project/component facts, binary candidates, build points and driver membership,
folded/demoted markers, source-only scopes and orphaned compiled sources. Loose source files
do not manufacture a build. [Build discovery](../../src/appsec_review/jobs/build_discovery.py)
has concrete supported rules, not a complete interpreter for every build system.
Descriptor-package and summary bounds can still limit planning visibility.

Static environment analysis reads accepted setup scripts without executing them. Literal,
unknown and redacted declarations remain advisory; they do not prove the recipe's effective
environment. Source history supplies review-priority context, not build permission.
The planner preserves exact scanner scopes and mandatory baseline accounting, compiles source
relationships deterministically and optionally asks bounded model workers for validated recipes.
Model evidence requests remain tied to accepted paths/hashes. Guidance authority and complete
feedback-cache admission belong to [worker prompt contracts](worker-prompt-contracts.md) and
[planning operations](../operations/target-analysis-planning.md).

Keep these identities distinct:

| Structure | Authority | Does not establish |
| --- | --- | --- |
| Review-job DAG | Scheduling between semantic producers | Target library or generated-input prerequisites |
| Accepted target build graph | Descriptor-backed ownership, products, relations and unresolved coverage | That a selected recipe ran or produced compatible bytes |
| Recipe-bound refinement | Exact graph/bundle, recipe, selection, releases and operation bindings | Execution evidence from a merely plausible command |
| Iteration/product generation | Verified execution inputs, retained product bytes and committed workspace state | Runtime shipment, application behavior or security |
| Container image dependencies | Toolchain packaging and preparation | Target build order |

The current [graph compiler](../../src/appsec_review/jobs/build_topology.py#L919) builds
`appsec-review/build-topology/2` from the whole accepted descriptor bundle. Facts retain raw
hashes and declaring lines; conditional/candidate relationships are not silently promoted to
unconditional scheduling edges. Choosing a recipe creates a separate immutable refinement.
The [shared guard](../../src/appsec_review/jobs/build_topology_artifacts.py#L177) checks that
refinement at image, execution and cache boundaries. Graphless or older graph-only evidence
does not bypass current admission.

### Preparation, native proof and family execution have different owners

Project-build chooses available deterministic CMake/JVM/phpize recipes or accepted recipes,
binds explicit promotions, resolves images and publishes static/build dispatch descriptions.
Static dispatch is not a scanner execution. Image preparation is not compiler success.
The current production handlers do not call the retained model-repair helper.

Isolated native units execute once in project-build; product-connected units remain with the
language-build iteration controller. Unity also executes once through its configured engine
path, and the .NET lane carries that receipt rather than rebuilding generated project files.
The language job's family execution steps collect the global iteration receipts, not a second
round of compilation.

For native work, safe recipe/operation/capture admission precedes execution, but missing static
compiler metadata alone is not a refusal. The running image's compiler profiles are measured
through [the bounded collector](../../src/appsec_review/container_runtime/compiler_profiles.py).
[Captured native enforcement](../../src/appsec_review/jobs/job_project_build/enforcement.py#L111)
joins successful kernel-observed executable identities, compiler profiles, target flags,
translation units and output bytes. It requires one compatible observed target for a proven
verdict. Empty capture, unknown compiler closure, mixed targets or disallowed axes leave gaps;
unproven native outputs are withheld from accepted artifacts. Earlier static-proof descriptions
must not be mistaken for this current capture-proven path.

### Build isolation does not mean every build is offline

[BuildContainerExecutor](../../src/appsec_review/container_runtime/build_executor.py#L232)
defaults to `bridge`, and accepts only `bridge` or `none`. The selected path determines which
one is used; a recipe's network annotation is not itself a firewall.

| Current path | Network behavior in source | Boundary |
| --- | --- | --- |
| New target acquisition | Configured Git/Perforce/review transports can use network | Host acquisition tools, pin/path/credential checks; not build isolation |
| Customized project-image preparation | Build network `default` | [Resolver](../../src/appsec_review/container_runtime/project_images.py#L480) binds base image, dependency bytes and retained preparation identity |
| Generic native execution, including native production iterations | Explicit `none` | [Language executor](../../src/appsec_review/jobs/job_language_build/job.py#L999) chooses this by dispatch family |
| Other production iteration families | Explicit `bridge` | Dependency-bearing builds can fetch; shared workspace and command admission still apply |
| Standalone JVM/Wasm adapter defaults, Unity and sanitizer replay | Executor default `bridge` | These constructors do not override the default; native sanitizer replay is not the ordinary native lane |
| Compiler-profile measurement | Explicit `none` | Image-only probe, not a target build |
| Explicit offline recipe replay | `none`, with the stricter no-fetch/no-pull path | [Replay contract](build-topology-and-iterations.md#implemented-detached-docker-recipe-recovery); not the default for all builds |

The [Docker command builder](../../src/appsec_review/container_runtime/build_executor.py#L372)
uses a non-root runtime identity, read-only container root, dropped capabilities, no-new-privileges,
a PID bound and a contained run-owned working directory. The copied workspace and optional
separate install tree are writable; the original checkout is not the build output directory.
Time/output/capture limits and runtime resource admission remain separate. Ordinary Docker argv
does not carry fixed CPU/memory flags here; those flags are added for the opt-in native adapter.
Do not infer a uniform container memory limit from a higher-level resource declaration.

Captured execution uses process-tree-local `ptrace`/`strace`; this executor rejects other capture
backends. Tracing is required functionality inside the build boundary, not a forbidden capability
to omit. Secret scanning/redaction precedes retained capture publication. Generic captured
families include native, Rust, .NET, Go, Node, Python and PHP; JVM/Wasm have specialized provenance
paths. A successful wrapper/log line alone cannot establish compiler execution, and unsupported
or truncated capture remains coverage loss. See
[capture architecture](build-environments-and-execution-capture.md) for record contracts.

Admitted build tools may run generators or package hooks inside this boundary. That is not
authorization to run the resulting application or claim dynamic-security coverage.
Sanitizer replay verifies required runtime references by reading output bytes; it does not
execute the instrumented binary. [Signing](../operations/signing.md) and
[deployment/source identity](deployment-image-and-source-mount.md) remain independent controls.

### Mutable workspaces have immutable recovery evidence

The [workspace owner](../../src/appsec_review/jobs/build_workspace.py#L483) copies the complete
accepted tree into a run-owned target/install generation; a bounded model summary is not the
source materialization list. The [iteration controller](../../src/appsec_review/jobs/build_iterations.py)
serializes dependency-ready production transactions and sends each immutable request through
`job_build_iteration`. A request binds source, graph, recipe, image, configuration, releases,
upstream products and the expected generation.

Under the writer lock, a transaction rechecks prerequisites and product interfaces before
execution. It retains a prepared receipt, then requires successful execution, confirmed cleanup
and verified product contracts before committing. The ledger is a recoverable index, not success
authority. A prepared-but-uncommitted record is not a successful build.

Product roles and target axes are checked independently of filenames; a runtime DLL cannot
substitute for an import library. Retained files and generation metadata support restoration
without running a compiler. Failed writes taint the disposable tree; recovery verifies durable
bytes before restoring. Selected recipe/product changes invalidate the affected dependent
closure, not every unrelated node. Replay uses a separate generation and cannot silently
transplant trial outputs into production.

Retention removes only explicitly owned disposable workspace trees after terminal/hold/cleanup
checks; durable products and provenance remain. Thus “immutable run evidence” does not mean
every workspace path or controller pointer is immutable. Whole-job reuse, portable task
checkpoints and build-product reuse are separate mechanisms; see
[Wave 1 resumability](jobs-and-runtime.md#wave-1-resumability).

## Decisions

These are dated records, not newly granted permissions or revalidated live results.
The original documents and their historical evidence are preserved.

| Date | Decision retained | Original record and current reading |
| --- | --- | --- |
| 2026-10-09 | Use direct process-tree execution evidence rather than compiler-log inference; retain connection events and typed limits. | [Capture restart handoff](../handoffs/2026-10-09-build-execution-capture-restart.md#user-objective). Its old schema and uncommitted-state notes are historical, not the current executor contract. |
| 2026-11-04 | Separate review scheduling, target dependencies and bounded attempts; retain shared-workspace generations/products. | [Initial integration record](build-topology-and-iterations.md#status-and-evidence-boundary). Its focused results do not establish later source or new live acceptance. |
| 2026-11-08 | Discover build points and explain non-units; orphaned compiled sources do not become fallback builds. | [Discovery decisions](../plans/build-discovery-test-program-2026-11-08.md#21-decisions-after-the-first-fixture-tranche-2026-11-08). The full historical test program is not claimed complete. |
| 2026-11-08 | Keep acquisition identity stable across verification and move per-pass observations to a sidecar. | [Acquisition job pass](../tasks/2026-11-08-job-pass-03-target-acquisition.md#fixed). Intake can reuse an unchanged external manifest instead of seeing timestamp-only identity changes. |
| 2026-11-08 | Treat static environment declarations as bounded advisory data with typed failures and canonical gap records. | [Environment job pass](../tasks/2026-11-08-job-pass-06-build-environment-analysis.md#fixed). Declared values never become recipe-enforced compiler proof. |
| 2026-11-11 | Use captured compiler invocation/target evidence after safe native admission and keep one authoritative native build. | [Project-build pass criteria](../tasks/2026-11-11-job-pass-10-project-build.md#required-behavior-and-acceptance-criterion). The record's c094 acceptance is scoped historical evidence, not all-target acceptance at this page's source boundary. |

## Named gaps

The [single TODO registry](../TODO.md) owns scope, state and completion criteria.
These references identify relevant limits; they are not another backlog or a walk's
expected-gaps authorization.

- [T-034](../TODO.md#t-034-host-a-dependency-proxy-so-builds-can-run-without-external-egress)
  tracks dependency egress. Present build networking must not be documented as universally offline.
- [T-035](../TODO.md#t-035-component-layer-between-catalog-and-plan),
  [T-036](../TODO.md#t-036-build-mode-disposition-per-component-at-plan-time),
  [T-037](../TODO.md#t-037-recipe-provenance-declared-canonical-inferred) and
  [T-038](../TODO.md#t-038-declared-builds-operator-build-plan-file) own the remaining component,
  disposition and recipe/declaration work; this page does not claim their broader designs landed.
- [T-055](../TODO.md#t-055-catalog-gaps-as-records-so-job_target_catalog-can-be-strict) and
  [T-056](../TODO.md#t-056-build-discovery-test-program-build-points-total-assignment-case-matrix)
  distinguish current discovery from complete typed accounting and tested assignment coverage.
- [T-111](../TODO.md#t-111-surface-build-descriptor-bounds-as-gap-records-and-size-them-against-real-targets)
  and [T-112](../TODO.md#t-112-record-what-the-analysis-summary-trim-removed-and-do-not-report-truncation-under-the-bounds)
  cover descriptor/summary omission visibility; nested payload reasons are not all canonical outcomes.
- [T-092](../TODO.md#t-092-decide-whether-a-refused-build-command-fails-one-unit-or-the-whole-language-build)
  and [T-093](../TODO.md#t-093-bind-generated-make-drivers-of-configure-style-builds-to-their-accepted-inputs)
  retain command-custody and generated-driver boundaries, rather than promising every refused
  node permits sibling execution.
- [T-113](../TODO.md#t-113-walk-every-job-into-testsunit-with-code-level-tests-under-the-enforced-tier)
  and [T-147](../TODO.md#t-147-declare-exact-task-and-dataset-publication-bindings-for-documentation)
  own verification/declaration completeness. Source presence, generated declarations and this
  documentation check do not establish runtime validation.

Use the [walk's four checks](../processes/walk-charter.md#5-accepting-a-job-the-four-checks)
to compare actual inputs, independent quantities, canonical gaps and saved baselines.
Retryability is not severity or permission to ignore a gap; rejected framework attempts are
not accepted partial publications. Those semantics belong to [job interchange](job-interchange.md).

## Jobs and pages

Canonical pages contain the per-step process, gap construction, acceptance and invalidation
details. The generated job blocks describe possible work, not observed execution.

| Boundary | Canonical pages |
| --- | --- |
| Pre-target readiness | [Model connectivity](../operations/job_model_connectivity.md), [image pins](../operations/job_image_pin_verification.md) |
| Acquisition and review binding | [Target acquisition](../operations/job_target_acquisition.md), [review intake](../operations/job_review_intake.md) |
| Discovery and context | [Target catalog](../operations/job_target_catalog.md), [static environment](../operations/job_build_environment_analysis.md) |
| Adjacent history context | [Source history](../operations/job_source_history_analysis.md), [change context](../operations/job_change_context_analysis.md) |
| Accepted scope and recipes | [Target analysis plan](../operations/job_target_analysis_plan.md) |
| Preparation and one-time native/engine execution | [Project build](../operations/job_project_build.md) |
| Production receipts and transactions | [Language build](../operations/job_language_build.md), [internal build iteration](../operations/job_build_iteration.md) |
| Instrumented rebuild | [Sanitizer build](../operations/job_sanitizer_build.md) |
| Downstream evidence consumers | [Artifact indexing](../operations/job_artifact_indexing.md), [debug-symbol indexing](../operations/job_debug_symbol_indexing.md), [post-build assessment](../operations/job_post_build_security_assessment.md) |

The downstream rows are interfaces, not an expansion of this subsystem's build authority.
Source/index resolving mechanisms remain in [Python and retrieval](python-and-retrieval.md).

## Dataflow

```mermaid
flowchart TD
  gates["job_model_connectivity / job_image_pin_verification"] --> acquisition["job_target_acquisition"]
  configured["configured system and pinned components"] --> acquisition
  acquisition --> manifest["stable acquisition manifest"]
  existing["existing target checkout"] --> intake["job_review_intake"]
  manifest --> intake
  intake --> catalog["job_target_catalog"]
  catalog --> environment["job_build_environment_analysis"]
  catalog --> planning["job_target_analysis_plan"]
  environment --> planning
  history["accepted source-history context"] -. "routing, not build proof" .-> planning
  planning --> graph["build_topology.executable_graph + recipe-bound refinement"]
  graph --> project["job_project_build"]
  images["pinned base / bounded project-image preparation"] --> project
  project --> owned["captured isolated native / Unity receipt"]
  project --> dispatch["prepared build dispatches"]
  dispatch --> language["job_language_build"]
  language --> controller["BuildIterations"]
  controller --> transaction["job_build_iteration"]
  transaction --> capture["bounded build execution / capture"]
  capture --> prepared["immutable prepared receipt"]
  prepared --> product["verified committed product generation"]
  product --> controller
  controller --> receipts["accepted language-build receipts + build index"]
  owned --> receipts
  receipts --> sanitizer["job_sanitizer_build"]
  receipts --> consumers["artifact / debug / compiled-analysis consumers"]
  sanitizer --> instrumented["protected instrumented outputs; no runtime test"]
  capture -. "failure / incomplete proof" .-> gaps["canonical outcomes + rejected diagnostics"]
  planning -. "unresolved relations / bounded visibility" .-> gaps
  acquisition -. "unavailable component" .-> gaps
```

Arrows show data and control boundaries, not a replacement for the configured review DAG.
Static scanner dispatch can proceed independently of build success. A product-generation loop
means later nodes consume verified earlier products; it does not authorize an unbounded retry
or model-repair loop.
