---
title: "Project-build operations"
kind: "operations"
subsystem: "target acquisition and build"
status: "current"
jobs: ["job_image_pin_verification", "job_project_build"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Project-build operations

`job_project_build` consumes only the accepted, hash-verified target analysis plan and turns its
build recipes into project-image preparations and dispatches for downstream production iterations. The
planning-side narrative is in [`target-analysis-planning.md`](target-analysis-planning.md); the
consumer is [`language-build.md`](language-build.md). Capture semantics are in
[`../architecture/build-environments-and-execution-capture.md`](../architecture/build-environments-and-execution-capture.md).

**Source-integrated:** isolated native units execute once in `probe.native`, through the
language-build executor, and downstream language-build consumes that captured receipt rather
than compiling again. Product-connected native units retain the shared-workspace iteration
owner; other non-Unity families are prepared for downstream execution. The accepted executable
graph replaces shortest-root component projection. The
[topology and bounded-iteration architecture](../architecture/build-topology-and-iterations.md)
records the initial Windows/canonical WSL source publication, tested code and evidence limits.
Image preparation is not compiler success, deployment, or a completed target review.

**Graph/2 source admission:** `plan.load_recipes` publishes a new immutable accepted refinement
after choosing deterministic, inferred or selected promoted recipes. Native image admission
precedes resolver creation and image/repair cache access. Supplied compiler metadata must match its
bound image/recipe; an image tag or family label is not proof. Missing static metadata alone is
not a pre-build refusal: native target proof comes from captured compiler invocations and the
running image's measured profiles before outputs are accepted. Missing recipe, selected member,
recognized operation or required interface produces a named blocker. Recipe-null planning
remains valid, while graph/1 builds require accepted replanning. No metadata collector, builder
provisioning, new deployment or live acceptance is implied by this source update.
An image-changing recipe without matching prebound compiler/recipe metadata is blocked before
image derivation/cache access, even if its base image is known. Project-declared Android/iOS
scope does not supply an ISA, SDK, deployment target, device kind or hardware generation;
native stages still need explicit supported target proof, and 32-bit proof remains incompatible
unless the ISA is listed in the selection policy's `allowed_32bit_isas` (default `["wasm32"]`).

## Steps

The configured topology must be exactly `plan`, `image`, `static_dispatch`, `probe`,
`build_dispatch`, `acceptance`; a mismatch fails configuration validation.

| Step | Tasks | Purpose |
| --- | --- | --- |
| `plan` | `load_recipes` | verify the accepted executable graph and validated recipes |
| `image` | one per family | resolve or build the derived project image |
| `static_dispatch` | `global` plus one per family | publish `lang_jobflow_static` dispatches; depends only on `plan` |
| `probe` | one per family | execute isolated native units once; retain Unity's one engine execution; other families are preparation-only |
| `build_dispatch` | one per family | publish `lang_jobflow_build` dispatches from successful image preparation, not successful probes |
| `acceptance` | `publish_handoff` | write `accepted-project-build-dispatch.json` (`appsec-review/project-build-dispatch/3`) |

Families are `native`, `rust`, `go`, `java`, `node`, `dotnet`, `python`, `php`, and `wasm`; each
needs a resolved `settings.profiles.<family>` entry with a pinned `tag`, `image_id`, and non-root
`user`. Committed recipes carry tags; observed IDs are supplied by the
[host-pins layer](image-pin-verification.md#frozen-configuration), not copied into portable recipes.

Unity is an engine, not another language family. Its accepted units remain `dotnet` with
`build_system = "unity"` and additional engine identity. They bypass generic .NET recipe
inference, project-image construction/repair and the second language build. The `probe.dotnet`
task performs the configured Unity build once, publishes its real execution receipt, and the
language-build lane forwards that receipt to artifact and dependency consumers. The static C#
lane continues independently. See [Unity configuration and coverage](unity-build.md).

## Bounded integration tier (T-113)

`tests/integration/job_project_build/` contains four boundary test files, 19 cases:
base-image resolution and container isolation for ten profiles, timeout cleanup, four real
native artifact kinds, three real capture/verification outcomes, and one compiler-diagnostic
provenance check. Each case has the integration tier's 300 s cap; compiler commands use a
60 s limit and the timeout case deliberately uses 2 s. Tests resolve configured catalog tags
through the shared `job_image_pin_verification.pins.inspect_image` lookup, verify the resolved
image's existing signature, and freeze that immutable identity in the test's build profile.
They use `--pull never`, offline containers and private run-root fixtures. Production host
bindings are not rewritten or treated as current test-image observations; production run
admission still enforces those bindings. The launch and capture cases retain resolved image
IDs and successful signature verification as JUnit properties.
Tests never acquire images or change signing policy. Select the four files explicitly through
`scripts/run-tests.sh --allow-heavy --timeout-seconds 1800 -- ...`; the wrapper rejects a
bare directory selector.

The artifact checks exercise the job's parser and publication handler with real compiler
products. The capture checks exercise the real command/capture boundary used by the native
lane, then verify its hashes and publish a scoped diagnostic. They do **not** establish
full-job admission, native enforcement closure, checkpoint/resume, or accepted-handoff parity.

The graph, capture-graph, family, JVM/.NET, Node, native-layout and Unity suites now live under
`tests/acceptance/job_project_build/`. Case bodies are retained; moved target suites keep
named target prerequisites as fixtures. Shared graph helpers remain at their original
integration import paths because unit tests and other jobs import them; those helper modules
contain no test cases. One redundant graph-shape case was deleted, covered by
`tests/unit/job_project_build/test_job_graph.py::test_graph_fans_out_per_family_and_lane_and_joins_at_publication`.
The family suite's existing language-build map reference follows its move; no unit tests changed.

Inventory boundaries: the shared `test_build_topology_catalog_planner_publication.py` suite
tests the planner and its publication, not this job's execution, and is no longer selected by
this job's integration map. Shared topology consumer/recovery and R8 replay suites remain
with their cross-job owners, as do the whole-review `test_nothing_review.py` and downstream
language-build, CodeQL, installer-scan, PoC and sanitizer suites. None was executed here.
The current `build_job` handlers do not call a model: `_infer_repair` is reachable only from
retained, uncalled probe-repair helpers. A paid model smoke test would not prove this job's
current contract.

The first WSL run stopped all 19 cases on stale host bindings. After the lookup correction,
all 19 real integration cases passed, including the three capture cases. The installed
Gitleaks image was already signed; its historical missing-signature report referred to the
obsolete configured identity, not to the image the corrected tests use. No signing operation
or production pin refresh was necessary.

The diagnostic recording and adjacent `.provenance.json` now live under
`tests/integration/job_project_build/fixtures/`, without modifying unit-owned files.
The replay checks the original unit diagnostic after the documented driver-name normalization,
the exact compiler image and measured version, the catalog recipe version, and hashes of the
input and raw stderr. Changed image, input, version or output fails rather than silently
regenerating a fixture. To record an explicitly approved compiler update:

```bash
.venv/bin/python -m tests.integration.job_project_build.fixture_recording --write
```

The recorder runs the signed compiler on a tiny local input and removes its private scratch.
It is never invoked by pytest. Deliberately synthetic negative binary/APK/layout examples in
the unit tier remain synthetic, not retrospectively labeled as tool recordings. Full-job
enforcement, handoff/resume and family/Unity acceptance are still unverified: the repair is
limited to integration execution. T-113 in [`../TODO.md`](../TODO.md) preserves the initial
skipped result, the later successful verification and the remaining coverage boundaries.

## Settings

`[jobs.job_project_build.settings]` (shipped values):

| Key | Default | Meaning |
| --- | --- | --- |
| `command_timeout_seconds` | 1800 | retained project probe-helper command limit; production commands use language-build settings |
| `image_build_timeout_seconds` | 1800 | per project-image build |
| `output_bytes` | 8388608 | in-memory stream preview; complete streams are retained |
| `artifact_count_limit` | 10000 | retained project probe-helper artifact bound |
| `force_buildability_probe` | false | deprecated; only `false` accepted, `true` rejected |
| `repair_attempts` | 3 | retained legacy image-repair helper bound, integer 3-10; not an automatic production retry loop |
| `build_capture.event_count_limit` | 250000 | job override of the global `[build_capture]` limit |
| `build_capture.retain_raw_traces` | true | keep secret-scanned, hashed raw strace files under `raw-traces/` (debug period; see language-build.md) |
| `build_capture.raw_trace_bytes_limit` | 67108864 | retained raw-trace bytes per command; truncation is flagged in `record.json` |

`settings.model` must define exactly `enabled`, `provider`, `model`, `reasoning`,
`max_input_tokens`, `max_output_tokens`, and `timeout_seconds` (positive integers for the limits).
It configures retained image-repair helpers, not topology inference or an automatic iteration
repair loop. Retired `force_probes` is rejected. Legacy probe/rebuild dispatches and graphless plans
require replanning rather than selecting the old execution path.

`settings.variants` may contain entries keyed by build-unit ID or family, with
`configuration`, `target_arch`, `execution_role`, `linkage`, `toolchain`, and `abi`.
Entries must agree with accepted descriptor evidence; absent facts remain unknown. Required
product compatibility must resolve. Graph/2 checkpoint reuse verifies refinement, product roles/
axes and retained bytes, rather than rejecting every nullable legacy variant field independently.

## Recipe validation

Every recipe, including a repaired one, passes `validate_build_recipe` in
`src/appsec_review/jobs/build_discovery.py`. `image_profile` must equal the deterministic
`required_image_profile` supplied to inference. This normally equals the language family; an
accepted `com.android.application` Gradle unit remains in the Java family but requires the Android
profile. `source_dir` must equal the build-unit root; output paths remain validated run-owned
paths. Optional `execution_cwd` selects configure/build directories without changing source
ownership, and omitted phases default to `source_dir`. The common production/replay guard
revalidates actual cwd, descriptor/driver and recognized Make/CMake source/output operands
before every launch, including after configure changes the tree. Changed cwd supports recognized
native Make/CMake forms and direct Clang/GCC with accepted source hashes and in-unit outputs,
not arbitrary drivers or rewritten compiler flags. Commands are argv arrays
(at most 16 per list, 128 arguments each) without shell operators, and `argv[0]` must be a bare
name in that profile's `_PROFILE_COMMANDS` allowlist (for example `go` only for Go, `dotnet` and
`msbuild` for .NET). Test, run, and install subcommands, non-build Maven goals or Gradle tasks, and
secret-like environment names are rejected.

Native Visual C++ authority (`.vcxproj`/`.vcproj`) is not cross-platform .NET/MSBuild.
Accepted Win32, MSVC toolset, compiler or Windows SDK evidence produces an explicit unavailable
toolchain gap on the Linux native profile; a `make` placeholder or compiler-version probe is not
a Windows build recipe. Generic .NET projects are not excluded by this rule.

## Typed image repair and detached recipe recovery

The active path prepares images/dispatches and executes isolated native units once; it does not call the retained
default-image probe/model-repair loop. Production failures are recorded by bounded iterations,
then the operator can select failure context, try a detached recipe and promote a verified
revision for a new production execution. See
[bounded iterations and recovery](language-build.md#bounded-iterations-and-recovery).

The retained image-only helper contract is `appsec-review/build-image-repair/3`
([schema](../schemas/build-image-repair.schema.json)); only `/3` proposals are accepted.
Unsupported versions are validation errors, not valid `NOT_IMAGE_REPAIRABLE` refusals.
Its explicit `NOT_IMAGE_REPAIRABLE` outcome stops image repair. Typed failure diagnosis
prioritizes capability/prerequisite/source/capture evidence; only resolved image/environment
evidence establishes image repairability. A missing relative project header or library is not an
apt-package diagnosis. `RepairStopped.reason_code` and normalized proposal identities stop
non-image, repeated or no-op proposals without claiming another compiler ran.

An image-repair proposal's four data parts remain the complete closed repair set:

| Part | Bound | Applied as |
| --- | --- | --- |
| `system_packages` | 0-64 apt package specifiers | exec-form `apt-get install` in the derived image |
| `environment` | 0-16 names from the family allowlist, each value matching that name's pattern | `ENV` before every restore, and merged into the accepted command environment |
| `package_manager` | `null`, or a manager the family image pins (Node: npm, pnpm 9.15.9, Yarn 1.22.22) | the lockless Node restore; refused when a lockfile fixes the manager or the recipe runs another manager |
| `dependency_restores` | 0-8 accepted dependency files | a restore by the family's own manager, built by code, run in the manifest's directory while the image builds |

The environment allowlist (`REPAIR_ENVIRONMENT` in `src/appsec_review/jobs/job_project_build/repair.py`)
comes from the failures real builds hit: `PIP_BREAK_SYSTEM_PACKAGES`, `PIP_NO_BUILD_ISOLATION`,
`PIP_PREFER_BINARY`, and `SETUPTOOLS_SCM_PRETEND_VERSION` for Python; npm peer/engine/fund settings,
`YARN_IGNORE_ENGINES`, and a bounded `NODE_OPTIONS=--max-old-space-size=N` for Node; Cargo git
fetch, retry, multiplexing, and job settings; `MAVEN_ARGS` limited to plugin `*.skip=true`, test
skips, compiler source/target/release levels, and wagon retries; MSBuild warning, analyzer,
end-of-life, and locked-restore properties for .NET; `GOFLAGS` limited to `-mod=` and
`-buildvcs=false`, and `CGO_ENABLED` for Go; Composer platform-requirement, no-dev, and timeout
settings for PHP. Names that pick URLs, registries, credentials, toolchain downloads, or checksum
databases are absent, and a repair cannot overwrite a variable the accepted recipe already sets.

Restorable manifests are those whose dependencies land where the later build reads them: any
accepted `requirements*.txt` (pip into `/opt/project-deps`), `Cargo.toml`, `go.mod`/`go.work`,
`pom.xml`, Gradle build or settings file, and .NET project or solution; for Node only the
manifest or lockfile at the dependency root; for Composer only the unit's own `composer.json`. Node
restores keep `--ignore-scripts`, Composer keeps `--no-scripts --no-plugins`, and Maven keeps
`-DskipTests`. There is no free-form command, path, URL, or Dockerfile text in a proposal.

The applied repair is recorded on the recipe as `image_repairs` (environment, package manager, and
normalized restores with their manager), so it is part of recipe/image identity.
`validate_build_recipe` re-checks it whenever reused. This image-only vocabulary cannot change
accepted commands, paths, dependency files, outputs, base image, or container policy.
The separate detached recipe-candidate contract can revise validated commands, phase cwd,
build directory and product paths with accepted evidence; it does not widen source authority or
permit arbitrary environment, scripts, fetch URLs, product identities or interface variants.
Promotion is recipe-only: B must execute again in production, with no replay-output transplant.

Production adapter preparation remains run-owned. A networked Node recipe whose configure phase
runs `npm ci`/`npm install`, `pnpm install`, or `yarn install` writes its own dependency tree using
bounded temporary caches rather than a read-only image `node_modules` view. Without an explicit
restore the supported image-owned view remains available. A declared missing `build_dir` is
prepared only after path validation; an empty prepared directory is not an expected build product.
The former probe helper's legacy Maven source-layout adaptation is not a new production guarantee:
the accepted recipe and actual JVM adapter determine the source layout that is built.

Recipe normalization marks a Node recipe `network_required` whenever the unit's own `package.json`
declares `dependencies`, `devDependencies`, or `optionalDependencies`, even without a lockfile. The
derived image then runs the script-disabled lockless restore (`npm install --ignore-scripts`), so a
TypeScript build resolves the declared `typescript` and `@types/*` packages instead of failing with
TS2688. The Node build image is defined in `containers/buildenv/typescript/`.
An empty, installation-only, or optional (`--if-present`) inferred build command can be normalized to the accepted
manifest's `build` or `minify` script, never its `start` or `test` script. Bounded descriptor
discovery also retains `Gruntfile.js` and `gulpfile.js` independently of ordinary content limits.
A Grunt dependency alone does not identify a safe task: fallback requires a literal, unique
`build*` alias consisting solely of recognized build/minification tasks, invoked through
`npx --no-install grunt <alias>`. Its accepted Gruntfile joins the recipe's dependency identity.
Dynamic, unknown, test, watch and server tasks are not fallback build authority.
Optional package-script invocations are rejected when mandatory source-backed recovery is not
possible, including in configure commands. Arguments after the package manager's `--` separator
belong to the declared script, not the package manager's optional-execution flag.
The bounded model summary may omit descriptor text, but trimming never mutates the accepted
catalog. Deterministic normalization and validation use the full accepted descriptors for that
group, including their declared dependencies; model input bounds and allowed paths stay unchanged.
After the configured inference retries, individually validated
sibling recipes are retained and each unresolved unit has a marker/hash-resolving planning gap;
one missing recipe does not erase the other projects' valid recipes.

Native version queries, Make dry runs, and Autotools bootstrap/configuration commands alone do
not establish a compile/build step. A standalone proposal may retain bootstrap commands as
configure-stage preparation when it also proposes an actual build; normalization never invents
the missing build command. A `Makefile.am` fragment without its own accepted `configure.ac` or
`configure.in` is a named nonstandalone gap, not an independently buildable product. Generated
`./configure` currently has no native-profile driver exception (the PHP `phpize` driver has its
own explicit exception); installing Autotools packages does not fill that contract gap.
Own accepted markers and root-local context take precedence over nested optional descriptor
context within the existing file/byte limits. Make classification examines its own accepted
default-target authority, not neighboring Windows projects or a directory named `test`. Proven
Windows-shell/MSBuild wrappers and Docker-image orchestration defaults are named capability
gaps; they are not replaced with speculative Linux builds or direct Docker fallback.
Own accepted solution declarations of Visual C++ `.vcproj`/`.vcxproj` members also require
native MSBuild/VCBuild capability, even when discovery places the solution in the .NET family.
This does not prove a Windows platform or disqualify neighboring C# projects or Linux Make
alternatives. Missing include-chain authority remains unverified, not proof of portability.

Correlate preparation/iteration evidence by family, root, build-unit, recipe, attempt and
invocation identities, not adjacent log order. Production nodes are serial across the global
graph even though image preparation and static work have separate scheduling.

Derived image manifests use `appsec-review/project-build-image/2` and live under a run-private
namespace in `runs/metadata/project-images/`. Reuse requires operator-declared `platform` and
`build_toolchain` releases. Target dependency and effective recipe changes invalidate the image;
unrelated query declarations do not. Supplied generator/Dockerfile payloads are not fingerprinted:
`dockerfile_sha256` remains null, and the owner must update the relevant release declaration when
the generator or build environment changes. Missing declarations disable image reuse.
Within an active review resource scope, a missing derived image requires the authenticated
`review_policy.image_builder`; absent capability produces a per-project `BLOCKED`
`derived_image_preparation_unavailable` gap, never a default-network local `docker buildx`
fallback. This applies to initial dependency preparation and image-changing recipe recovery.
Pinned baselines and policy-valid prepared-image cache hits do not require new preparation, and
supported sibling work continues. Replay `--prepared-image` consumes existing bounded approval
evidence with the full image profile; it does not commission or invoke a builder itself.
This does not change build/capture container limits, model settings, retries or feature gates.
The builder's default
`bounded` policy retains CPU/RAM enforcement. The opt-in `concurrency_only` policy allows
exactly one image build, without builder-specific CPU/RAM caps, while retaining deadlines,
zero swap, private custody, provenance, independent cleanup and durable engine exclusivity.
Client and service must both declare that policy; approval does not provision its host assets.
See [builder commissioning and policy semantics](performance-assurance.md).
This does
not silently substitute the baseline image when the recipe requires dependency preparation.
Eligible declared prepared images remain usable; platform image preparation is separate work.

**TODO (deferred, not verified):** tune per-build CPU/RAM limits using measured build workloads.
Concurrency one bounds build count, not memory consumption or host contention; inherited
host ceilings remain effective and must be reported truthfully.

Old `project-build-repairs/` and `project-probes/` metadata describe retained legacy helper
checkpoints, not the new production success authority. Iteration reuse requires declared
`platform`, `build_toolchain` and `validation` identities, exact source/configuration/graph,
recipe/image/toolchain/upstream bindings, execution/output policy, and verified products and
receipts. Missing identities are explicit misses, not fabricated successful probes.

## Outputs and recovery

The accepted dispatch is published beneath the attempt's `artifacts/project-build/`. It records
`execution_mode = "iterative"`, the runtime execution graph/actions, image preparations and
`preparation_identity` on non-Unity dispatches; that field is not a compiler-probe identity.
Failed preparation yields an explicit omitted-unit/upstream gap, not an absent family or a
successful build. Static dispatch remains available independently.

Project-build owns its isolated native and Unity execution receipts; language-build consumes
those without rebuilding and publishes them with controller-owned production receipts,
captured command/tool provenance, typed artifacts and `[build_outputs]` classifications.
Mutable controller production state lives at
`runs/<run-id>/workspace/build/{target,install}`; immutable iterations/products/generations and
durable artifact copies remain run-owned outside disposable state. Failed writes are restored
before retry, and selected recipe changes invalidate the affected node/consumers without
recompiling an unchanged verifiable producer. JVM/Wasm retain their existing specialized
provenance semantics; sharing mounts is not a claim that every family uses standardized syscall
capture. See [language-build](language-build.md) for publication, replay CLI, retention and gaps.
