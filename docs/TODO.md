# Architecture TODOs

## Finish OWASP acceptance beyond bounded static assessment

- Implemented: complete pinned ASVS/MASVS inventories and MASTG/Top 10 context catalogs,
  independently reviewed inventory/content/license pins; explicit qualification versus assessment;
  configured worker and fresh blinded reviewer calls; four site-bound Python static procedures;
  accepted original-evidence custody and scoped outcomes with named unresolved coverage.
- Implemented in direct and Dagster graphs: accepted classification/prioritization/code graph → security tagging/tag
  cloud → opt-in OWASP → review data indexing/`control_evidence` → lead/hunt packages →
  red/blue/independent verifier requests. Tags route work; they do not prove controls.
- Verified offline: full-catalog publications, adverse/benign/dissent outcomes, configured caps,
  qualification isolation, projection/lead/package delivery, actual scripted review-role requests,
  original-source retrieval and indirect-proof guards. This is not live-provider efficacy.
- [x] Integrate the same enabled tagging/OWASP chain into direct CLI `start`/`resume`/`plan-resume`,
  including `--force-from` routing and rejection of disabled jobs. OWASP remains disabled by default.
  This closes the missing chain, not CI/post-build or standalone metadata-sync topology differences.
- [ ] Run authorized live-model efficacy/budget acceptance. Scripted `Infer` doubles establish
  contract behavior, not real-provider analytical quality.
- [ ] Review and implement additional language/control procedures with subject-bound acceptance.
  Complete catalog inventory is not full assessment coverage or compliance certification.
- [ ] Implement separately authorized environment-bound runtime/manual adapters;
  `MASVS-NETWORK-1` stays unsupported even when `dynamic_authorized = true`.
- [ ] Obtain independent exploit confirmation where warranted. Even elevated/ship-blocking OWASP
  hypotheses are provisional; no customer safety certification follows from this stage.

See [the current design](architecture/owasp-control-workbench.md) and
[operating limits](operations/owasp-control-assessment.md).

## Hook up Lua game-security rule scanning

- [ ] Integrate `rules/lua-game-security/game-security.yml` into
  `job_evidence_collection`'s existing `source_sast` step using the Semgrep/OpenGrep
  images. The 20-rule pack currently supports standalone scans only.
- [ ] Add typed central configuration, Lua source applicability and accepted dispatch
  selection; verify and hash-pin the rule bundle before mounting it read-only.
  Include source, rule, configuration and tool identities in checkpoint reuse.
- [ ] Normalize and index matches as review leads with resolving source locations,
  not confirmed vulnerabilities. Preserve parser failures, unsupported dialects
  (including Luau extensions), skipped files and timeouts as explicit coverage gaps.
- [ ] Add dispatch, configuration, provenance, normalization and failure/resume tests,
  plus an end-to-end Lua fixture run through the job using both pinned scanners.
  Retain exact-match rule fixtures and verify non-Lua scans remain unchanged.
- [ ] Update the pack README and pipeline operations documentation once the hookup
  is implemented; do not describe standalone fixture coverage as pipeline acceptance.

## Complete the Linux execution vertical before expanding platforms

Use `targets/appsec-multi-vuln` as the acceptance target until the generic execution path is
solid, repeatable, and queryable. Do not make the later Windows or large-repository work a
prerequisite for this stage.

The Linux vertical is complete only when:

- accepted static dispatches are consumed as executable `tool + build-unit` shards, while global
  scanners run once and static work remains independent of build probes;
- every successful or reused probe can dispatch a generic real build using the accepted recipe and
  exact derived image, without a repository-specific Dagster graph;
- native, Rust, Go, Java, Node/TypeScript, .NET, Python, PHP, and WASM build units publish explicit
  success, gap, or not-applicable receipts without discarding successful siblings;
- real builds retain bounded protected command provenance for compilers, assemblers, linker
  drivers, linkers, archivers, code generators, transpilers, bundlers, package builders, and
  post-link tools, plus sanitized searchable records and exact input/output identities;
- generated sources, objects, libraries, executables, bytecode, packages, debug data, link maps,
  and statically observed loader dependencies are cataloged without executing target binaries;
- the C++ AST, LLVM IR, Infer, binary, and post-build branches consume the generic native-build
  handoff instead of maintaining a separate project build path or fixed case list;
- compiled-language CodeQL traces the exact accepted clean build, interpreted-language CodeQL uses
  the accepted source snapshot, and both publish bounded database/query/SARIF identities and gaps;
- component dependencies determine build-unit ordering, while unrelated build units and analysis
  branches remain concurrent;
- unchanged recipe, dependency, image, source, tool, and query identities reuse only the valid
  checkpoints they actually cover; and
- unit tests, failure/resume tests, MCP integration tests, and a live Dagster acceptance run prove
  dispatch, execution, provenance capture, indexing, gaps, and selective reuse end to end.

Current status: the generic Linux native/CMake, Rust/Cargo, JVM Java/Kotlin (Maven, Gradle, and direct compiler), Go, manifest-declared Node/JavaScript/TypeScript, manifest-declared PHP/Composer, Linux-capable .NET SDK, and WebAssembly output-family adapters now cover
accepted dispatch validation, real build execution, protected compiler/link provenance, artifact catalogs, dependency ordering,
failure isolation, checkpoint reuse, default-image-first probing, three bounded inference-guided
dependency-image repairs, successful Dockerfile/image reuse, and dynamic C++/post-build
consumption. The Go adapter supports accepted modules/workspaces, vendor mode, package targets,
build tags, and cgo; uses the same syscall-authoritative capture boundary as native, Rust, and
.NET with its own Go-specific reconciliation (`go.capture_invocations`, successful process-exec
events only); and catalogs modules, packages, generated sources, binaries, build IDs, and sanitized
retrieval records. One parameterized contract now checks successful/failed/redacted exec,
envp/connect facts, wrapper reconciliation, malformed input, and cap/loss behavior across the three
`CapturedBuildDescriptor` families (native, Rust, .NET); adding another compiled language must
extend that descriptor contract rather than copy capture orchestration. The .NET adapter
allows declared dependency restore, catalogs MSBuild/Roslyn and
managed/native outputs, and reports Windows-only/.NET Framework units as explicit platform gaps.
The Rust adapter accepts Cargo workspaces/packages and bounded target/profile/features/lock
choices; retains rustc, linker, archiver, build-script, and proc-macro provenance; catalogs Cargo
metadata and resolve edges plus generated sources, rlib/rmeta, native libraries, binaries, and debug
metadata; and publishes sanitized build evidence without executing tests or produced programs.
Its current Docker fixture gate verifies dependency egress, standardized syscall/envp/connect
records, exact-name redaction, gitleaks findings, complete output files, Cargo dependency and
intermediate artifacts, loader facts, default plus security-extended CodeQL profiles, and truthful
zero-result SARIF. Recipe inference is a separate opt-in model gate and never contributes capture
authority. Rust compiler-native AST and IR producers remain unimplemented; tree-sitter and CodeQL
must not be described as substitutes for those missing branches.
The native adapter now uses the same syscall/envp/connect/gitleaks boundary as Rust and .NET.
Successful exec events alone establish tool provenance; compile databases and CMake link records are
exact-match enrichment only. Docker-backed fixture acceptance covers complete streams,
compiler/linker/archiver provenance, compile database, objects, static library, executable, split
debug data, link map, loader facts, Clang AST, LLVM IR, secret removal, and raw-trace cleanup. This
lower-level acceptance has not been promoted to a Dagster run while language work remains batched.
The Node adapter accepts npm, pnpm, and Yarn identities; allows dependency egress while denying application/test
execution; treats lifecycle scripts as sandboxed target code; and catalogs generated code, bundles,
maps, packages, and native addons with protected command/stream evidence and sanitized retrieval.
The PHP adapter accepts `composer.json` with an optional lockfile, prepares dependencies in the pinned derived image with
plugins/scripts disabled, applies explicit sandbox policy to real Composer build work, catalogs
package and dependency metadata, generated autoload/code, archives, and native extensions, and
keeps exact argv and streams out of retrieval-visible evidence.
The WebAssembly adapter consumes accepted Rust, native/Emscripten/WASI, Node/AssemblyScript, WAT,
and explicitly configured producer recipes without duplicating source discovery; catalogs modules,
components, bindings, interface/debug metadata, side modules, packages, and dependency evidence;
and never instantiates produced modules. Focused host tests cover protected stream truncation,
sanitized MCP retrieval, checkpoint reuse, tamper rejection, and sibling failure isolation. The
prior standalone WebAssembly deployment receipt predates integration into `job_language_build`
and is not acceptance evidence for the current tree. A fresh integrated Dagster run
(`d51d396c-4f0f-4386-a503-859b399f1449`, application run `2026-10-08-0081`) completed all 248
orchestration steps and accepted the shared language-build handoff with one native and seven JVM
successes, nine explicit .NET recipe gaps, and truthful non-selection for Go, Node, Python, PHP,
Rust, and WebAssembly. The composed retrieval manifest and an MCP query resolved sanitized JVM
class evidence while retaining the unrelated catalog build shard. Producer-positive fixture and
live-record coverage is tracked per language; a new integrated Dagster run remains required before
the Linux vertical can be closed.
The pinned cross-language CodeQL job and exact `query_codeql` MCP surface are implemented and have
fresh live acceptance on `appsec-multi-vuln`: producer Dagster run
`e596f2f0-3b47-4263-973e-e0bc0362fe5a`, application run `2026-10-09-0007`, and CodeQL attempt
`attempt_0006` completed all seven selected steps. Exact-tree verification run
`0958c6ff-907d-43fc-b82a-004243f3a573` then reused that accepted attempt and also completed all
seven selected steps. Thirty of 37 profile scopes completed real
database and query execution and published 30 normalized observations across Actions, C/C++,
Java/Kotlin, JavaScript/TypeScript, and Python. The seven Go scopes preserve explicit database and
query gaps because their exact accepted recipes download modules without compiling source; C# is
blocked by the accepted build environment, and Rust by missing accepted Cargo locks. PHP and raw
WebAssembly are explicitly not applicable. Static dispatch execution, pinned loader-dependency
parsing, broader MCP integration, and producer-positive live coverage for the remaining
language-build families are still required. Retained Dagster records describe only the revisions
and selected target recipes they captured.

Probe policy must be centrally configurable per build unit as `configure`, `selected-target`, or
`full-build`. This keeps the default test target rigorous without forcing future large repositories
through an unnecessary full probe before every instrumented or traced build.

## Implement conditional build-capture controls

The agreed semantics and the 18-row `appsec-multi-vuln` fixture mapping are documented in
[`architecture/build-environments-and-execution-capture.md`](architecture/build-environments-and-execution-capture.md),
using nested corpus commit `7c10536389c3cfb20a27d7a6a78943267ea43b3f`. Current status:

- implemented: independent typed central controls for build execution capture and
  compiler-artifact collection with `required`, `auto`, and `disabled` values;
- implemented: canonical immutable per-run resolution and binding into handoff, job-configuration,
  and resume identities;
- implemented: one deterministic descriptor-backed applicability evaluator and canonical
  `SUCCEEDED`, `SKIPPED_NA`, `SKIPPED_POLICY`, and `GAP` processing dispositions, without another
  syscall parser or reconciliation loop;
- implemented: CodeQL's typed capability model accepts `build`, `source`, `auto`, and `disabled`,
  with one-way load-time normalization of legacy `manual`/`none` values; executor receipts retain
  `manual`/`none` after deterministic capability selection;
- implemented: parameterized schema/path/applicability coverage for every matrix row and focused
  transitions for syntax-only versus material lifecycles, mixed native facts, missing inventory,
  unsupported capability, failed processing, and incomplete evidence; and
- remaining: specialized live Kotlin, Android SDK, Composer lifecycle, phpize, mixed-language
  CodeQL, and WebAssembly toolchain acceptance. Their absence is a validation gap, not a changed
  applicability decision.

Conditional policy dispatch and dispositions are implemented. Do not describe specialized live
toolchain acceptance as complete until the remaining gates above run. Executor-level CodeQL
receipts continue to use `manual`/`none` after the canonical decision selects build/source.

## Scale native acceptance from fixtures to a game-sized build

Advance native testing through explicit gates rather than moving directly from the synthetic
multi-language target to a full game project:

1. `appsec-multi-vuln` remains the functional acceptance target for dispatch, failure isolation,
   provenance, indexing, MCP retrieval, and selective resume across supported languages.
2. EASTL is the next native target. Use it to validate template- and header-heavy C++, custom
   allocators and containers, cross-translation-unit relationships, compile-database fidelity,
   static-library outputs, AST/IR scale, compiler-specific flags, and deduplication of findings
   emitted through many template instantiations.
3. The Unreal Engine Lyra sample project is the later game-scale target, after the required Windows
   and Unreal build capabilities are available. Use it to validate project/plugin/module/target
   discovery, UBT/UAT orchestration, generated headers and sources, C# build tooling, shader and
   asset-build provenance, native compiler/linker capture, selective configurations, traced
   CodeQL, large-index retrieval, and bounded resumption.

Externally obtained target and engine source remains under ignored `targets/` storage and is never
committed or copied wholesale into documentation, fixtures, prompts, or indexes. Retain only the
bounded derived evidence permitted by the index contract plus the source revision, acquisition
provenance, applicable capability state, and accepted run-owned artifact identities needed to
reproduce and verify a test.

## Add Windows and large native-build coverage after the Linux acceptance gate

Once the Linux vertical above passes against `appsec-multi-vuln`, add a first-class disposable
Windows executor rather than extending Linux recipes with platform-specific exceptions.

The follow-on work should:

- bootstrap an ephemeral Windows image or VM from centrally configured, hash-identified tooling;
- make the Clang/C++ test collector host-portable by isolating the Unix-only `resource` dependency,
  preserving the existing Linux file-size-limit assertions, and adding a Windows regression test
  that proves `tests/test_cpp_index_jobs.py` and the related Clang suites collect and run rather
  than failing during import;
- support MSVC, clang-cl, MSBuild, CMake/Ninja, and UBT/UAT-style modular build orchestration;
- capture `cl`, `clang-cl`, `link`, `lib`, `rc`, `cvtres`, `midl`, shader compilers, code generators,
  signing tools, and other build-time compiler/transpiler actions through the same protected
  provenance contract used on Linux;
- wrap the exact accepted Windows build for compiled-language CodeQL database creation when the
  required pinned assets and runtime capability are available;
- inventory installed compiler, SDK, build-system, extractor, and query-pack versions and hashes
  without copying redistributable tool payloads into this repository or run indexes;
- shard large repositories by component, module, plugin, target, platform, configuration, and
  dependency topology instead of producing project-named horizontal Dagster graphs;
- allow selective target/configuration matrices and centrally bounded concurrency, storage, and
  time budgets; and
- validate the executor with synthetic fixtures first, then representative larger native projects,
  while preserving gaps for unsupported platform or toolchain combinations.

## Add Android, iOS, and Unity application coverage

After the Linux execution vertical is accepted, extend the same discovery, recipe, provenance,
artifact, indexing, and gap contracts to mobile applications and Unity projects. Keep source-only
analysis useful before the corresponding platform build executor is available.

Android work should:

- discover Gradle/Android Gradle Plugin projects, modules, variants, manifests, resources, Java,
  Kotlin, JNI/NDK, native libraries, dependency catalogs, signing configuration references, and
  generated sources without retaining signing secrets;
- run selected source scanners, including the existing pinned `tool-mobsfscan` lane, before a build
  is available;
- build accepted variants in a pinned Linux Android SDK/NDK/JDK image, capture Gradle, Java/Kotlin,
  native compiler/linker, resource, DEX, packaging, and signing-tool provenance, and retain APK/AAB,
  mapping, symbol, manifest, SBOM, and native-library artifacts;
- add bounded APK/AAB MobSF artifact analysis when a reviewed full MobSF runtime is available; and
- correlate mobile, JVM, native, dependency, manifest, exported-component, permission, and binary
  observations through shared component and source identities.

iOS work should:

- discover Xcode projects/workspaces, schemes, targets, Swift packages, CocoaPods, Objective-C,
  Swift, C/C++, entitlements, privacy manifests, resources, frameworks, and extensions;
- keep source scanning and configuration assessment available on non-macOS workers;
- use an ephemeral, centrally configured macOS executor for accepted `xcodebuild`, Clang, Swift,
  linker, asset compiler, interface builder, package, archive, and codesign-metadata capture;
- retain bounded IPA/app/framework, symbol, dependency, entitlement, privacy, and signing-metadata
  evidence without retaining signing credentials or executing the application; and
- publish an explicit platform gap when the required macOS/Xcode capability is unavailable.

Unity work should:

- recognize projects from `Assets`, `Packages`, `ProjectSettings`, assembly definitions, package
  manifests, scripting backend, platform targets, plugins, native libraries, and recorded editor
  version;
- statically analyze C#, shaders, scripts, configuration, packages, managed assemblies, native
  plugins, and IL2CPP-generated C++ when those artifacts already exist;
- capture Unity batch-build, compiler, linker, shader compiler, asset pipeline, managed assembly,
  IL2CPP, packaging, and platform-tool invocations through the generic protected provenance model;
- shard evidence by project, assembly, package, scene, plugin, platform, configuration, and build
  target without exposing project assets to inference unnecessarily; and
- require a centrally configured licensed Unity runtime for builds. If that capability is absent,
  publish a named build-coverage gap while continuing source, package, configuration, and available
  artifact analysis.

Acceptance requires synthetic Android, iOS, and Unity fixtures; failure/resume and unavailable-
platform tests; bounded MobSF/MobSFScan integration tests; and live Dagster runs on workers that
actually provide each enabled platform capability.

## Close the SEI CERT rule-pack execution and coverage gaps

The pack (`rules/sei-cert/`) validates and evaluates cleanly under Semgrep 1.178.0 and OpenGrep
1.30.2 on fixtures and on `appsec-multi-vuln`, but these remain open:

- build and smoke-test the new `tool-opengrep` image and run one live evidence-collection
  acceptance with both engines; the image definition was validated statically only;
- verify the Sigstore signature that OpenGrep publishes for its release binary;
- verify live resolution of the canonical CERT URLs, which were derived from the official
  repository's content paths;
- run the Dagster definition tests with the new `opengrep_*` evidence tasks;
- re-read the drafted summaries and analysis classes of unimplemented entries against their
  official pages before promoting them, starting with entries flagged `pattern_candidate`;
- add Kotlin and Android-manifest analysis only after an applicable official rule and a capable
  engine exist; both are currently explicit gaps.

## Add `grype_db_sync` to `job_third_party_data_sync`

The archived pre-refactor tree was inspected for a reusable Grype database. It contains a Grype
executable archive and image/build records, but no database snapshot with a verifiable database
schema version, listing metadata, content hashes, source provenance, or freshness identity. Those
bytes are therefore not a usable database snapshot and were not copied.

Future work should add an independent `grype_db_sync` step to `job_third_party_data_sync`, alongside
the NVD, OSV, and MITRE branches. It must use Grype's supported database update mechanism, record the
Grype tool/image identity and upstream database schema/build identity, enforce download and
extraction bounds, hash every published file, validate the database with the pinned Grype version,
publish immutably with a last-known-good pointer, and expose a bounded lookup/consumer interface.
The step must fail truthfully when provenance, validation, or freshness cannot be established.

## Optimize produced-artifact Grype without reducing coverage

Future artifact Grype work must deduplicate accepted artifacts by content hash and cache only by
artifact hash plus exact Grype image, vulnerability-database digest, and policy identity. It should
reuse hash-verified accepted SBOMs, filter unsupported formats before launch, and use bounded
concurrency with partitioned resumability. Telemetry must report artifact/byte throughput, avoided
launches, and saved work. Acceptance tests must prove that deduplication, filtering, cache reuse,
resume, and sibling failure cannot suppress expected coverage or convert any gap into a clean result.

## Match OSV advisories against the snapshot's own index

Match OSV advisories against the snapshot's own index/osv.sqlite so memory scales with a project's
dependencies, not the ecosystem database size. osv-scanner 1.9.2's `--experimental-offline` mode
loads each needed ecosystem's whole `all.zip` into memory: npm.zip is 208 MB compressed, 368 MB of
JSON, 230k advisories, and a single npm project alone was measured peaking at 2.2 GB or more. The
live run 2026-10-16-0004 was OOM-killed at the uniform 1g scanner limit. Evidence collection now
runs one invocation per project and raises only osv-scanner's limit (`osv_memory`, default `3g`),
which bounds the blast radius but still pays the full ecosystem cost per launch. Extracting package
versions with osv-scanner (or the catalog) and looking them up in the indexed snapshot would make
the cost proportional to the dependencies actually present.

## Measure and extend seeded CodeQL neighborhoods

Design: `docs/architecture/seeded-codeql-neighborhoods.md`. Remaining after the first
implementation:

- measure seeded versus whole-program export time on a 20k-100k LOC project, and tune the default
  `seed_depth` and `seed_limit` from the numbers;
- measure one batched `codeql database run-queries` over all queries against serial runs;
- make `query-packs --warm` a routine step of the host image procedure after a CodeQL image
  rebuild, as a compile check (it fills a platform volume keyed by the image id; review runs share
  a separate cache keyed by the declared CodeQL and runner releases, so only the first run after a
  release change compiles cold; see `docs/operations/codeql-analysis.md`), and make the live
  CodeQL tests opt-in;
- measure the seeded packs for Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Go, C# and Rust
  (they use the same two external predicates, `exportScope` and `exportSeed`);
- profile the slow `job_evidence_collection` tests.

## Measure and extend seeded Clang neighborhoods

Design: `docs/architecture/seeded-neighborhoods.md`. The Clang AST/LLVM IR, Clang-Tidy/Static
Analyzer and (enabled-only) CPG producers run from the findings outward and publish through the
`graph` index. Remaining after the first implementation:

- measure seeded versus whole-program wall time on a 20k-100k LOC project, then tune `seeded_bounds`
  and `seed_depth`. The opt-in live tests (`tests/live/test_seeded_clang_live.py`) now run the real
  containers on the 12-unit fixture and on a small defective file (numbers in
  `docs/architecture/seeded-neighborhoods.md` section 12), but not at scale;
- cross-TU callers in translation units that were not replayed appear only as the standing
  `frontier` gap; extend the unit selection if the measurements show it matters;
- `--exclude-regex` is unverified against a live c2cpg at scale;
- `joern-cpg` rows still reach the graph index only as `producer_neighborhood` `cpg` rows, and the
  seeded CPG shard carries the generic `JOERN_GAP` wording (`jobs/job_cpg_analysis/job.py`; asserted
  in `tests/test_joern_tool.py`, which must keep "no CPG coverage is claimed");
- the `JOERN_CPG` call-site input to the graph cross-check is not wired: add it to
  `SECONDARY_KINDS` / `CrossCheckInputs` in `graph/crosscheck.py` (and `assign_secondary`) before
  claiming a third opinion on call sites;
- workflow consumers that should read seeded Clang facts but do not yet. Analyzer-only `sink_site`
  facts (inexact, `analyzer_only`) already flow into hunt-package `unit_context` through the graph
  families; everything else below is unread:
  - `job_review_prioritization` ranking: diagnostic density and guard/dominance facts per file
    (`jobs/job_review_prioritization/semantic.py`, `rules.py`, `scoring.py`, plus a new basis term in
    the basis taxonomy);
  - hunt-unit construction: clangd callers/callees to widen a unit (`review/packages.py` unit
    building, `GraphContext.unit_context`);
  - review scoring: analyzer severity and trace length as a signal (`review/scoring/factors.py`,
    `risk_model.py`);
  - package flow context: `ir_entity` flow rows are not in `_GRAPH_KINDS` or `GRAPH_ROLES`
    (`review/packages.py`), so `GraphContext.lead_context` cannot cite them; this needs the package
    schema extended;
- already wired, with no change: review source-SAST selection reads the `job_clang_static_analysis`
  observation shard (now the seeded subset, with its gaps), and package assembly reads the `graph`
  families per scope.

## Close the remaining CodeQL platform and accepted-build gaps

Cross-language CodeQL uses operator-declared releases for supplied offline extractors and query packs, exact protected
compiled-build replay, source/no-build analysis, bounded SARIF normalization, independent
database/query checkpoints, and accepted MCP retrieval. The pinned `audit-buildenv-dotnet` image
now backs the `dotnet` profile, and the accepted .NET fixture run recorded in
[`operations/language-build.md`](operations/language-build.md) created a C# database with both
suites. Remaining work is deliberately narrower: accepted Cargo locks and analyzer prerequisites
for Rust, a pinned Bundler execution lane for Ruby package lifecycles, and Go recipes that perform
the real accepted compilation rather than dependency download alone. Visual Basic, F#, and Swift
remain explicit unsupported-platform gaps (Swift execution is also gated off by
`tools.enable_swift`; see [`operations/swift-execution-policy.md`](operations/swift-execution-policy.md)).
Preserve the
current selective invalidation boundary: query-pack changes must not rebuild Clang AST, LLVM IR,
or an otherwise reusable CodeQL database.

## Make CodeQL database throughput tunable end to end

Run `2026-10-16-0004` (WSL host, 24 CPUs, 16 GB shared WSL limit) built 13 of 55 database scopes in
about 20 minutes. `concurrency = 2`, `threads = 2` and `ram_mb = 4096` are already configurable,
but at most two builds overlapped, and only briefly. Gaps of up to 7 minutes passed between
`TOOL_INVOCATION_STARTED` events with no CodeQL container running, apparently preparing the next
scope. That historical observation is not a current resource reservation or a matched benchmark.
The ready-work coordinator now uses `settings.concurrency` for active CodeQL actions, with
correlated preparation and queue/admission spans and cross-process resource reservations.
Database completion releases that scope's query/export work without waiting for every database.
Container memory, host staging, CPU and I/O reservations remain aggregate constraints: the
checked-in 10,240 MiB/one-I/O-slot defaults cannot overlap two ordinary 4,096 MiB actions.
See [performance and assurance](operations/performance-assurance.md) for sizing and custody.

Remaining acceptance: repeated equal-coverage performance measurements, real host enforcement
and eligible-overlap evidence, and separately authorized rollout. Fake scheduler/admission tests
do not establish production headroom. Required derived images also need a commissioned bounded
builder; missing preparation must not be treated as an acceptable coverage reduction.

The registered [native operator](../deploy/dagster/native/README.md) now has fake end-to-end
coverage through supervisor, simulated Dagster child, common launch, restricted broker and
owned-container cleanup. A shared builder/tool sequence covers derived-image visibility,
stopped-container exclusion and next-build admission after removal. Real installed-release
custody, exclusive PostgreSQL ownership, engine/cgroup enforcement and complete persistent
1-CPU/512-MiB baseline fit remain unproved. The prepared 9-CPU/12-GiB/one-I/O-slot contract is
not activated; commissioning and a subsequent strict third-party review are separate decisions.

Latest equal-semantic fixture medians were 23.176 seconds strict and 27.239 seconds managed
(17.529% slower), with unchanged resolving evidence and 99 gaps. The performance goal is unmet,
not a demonstrated gain. Historical overhead and real CodeQL non-regression gates remain
unestablished; later custody/native changes are unbenchmarked. Keep strict as the default and
follow the [rollback contract](operations/performance-assurance.md#metrics-and-comparison)
without restoring supplied-platform scans or rewriting frozen runs.

## Define and test the CodeQL checkpoint identity matrix

Maintain the matrix of identity inputs against the derived image, database, query, normalization,
index, and publication checkpoints. It covers declared CodeQL and extractor releases, source
bytes, accepted build recipes and replay commands, compiler/toolchain identities, base and derived
image identities, runtime policy and resource limits, query packs and suites, custom queries,
normalizer versions, and output schemas. For each change, state the smallest affected scope and
whether the expected action is reuse, database rebuild, query-only rerun, renormalization, or
republication.

Separate semantic execution inputs from provenance-only representation. A changed recipe or
target-owned build instructions that resolve to a different compiler, toolchain, filesystem,
runtime policy, or output image must invalidate dependent work. Supplied platform Dockerfiles,
source and image payloads are not fingerprinted: changed platform material requires an updated
operator release declaration, and missing declarations disable reuse rather than trigger hashing.
Provenance-only representation changes retain their original/current attribution without forcing
unrelated databases or queries to rerun.
Back the matrix with table-driven tests that change one dimension at a time and prove both required
invalidation and required reuse across unrelated languages, projects, scopes, and query profiles.

The explicit first-party predecessor path now accepts selected DB-only detached copies into a
new run under both frozen configurations and operator tenant/project authorization. Fake
`JobRunner` execute/finalize acceptance demonstrates new query declarations without new database
launches, then query reuse; mismatched material, source claims and optional handoff run bindings
fail. No prior queries, exports or guidance are imported. Retained real-run imports, performance
gates and deployment remain separately blocked; the fixture result is not live commissioning.

## Graph modes: aliases, slices, type layouts, buffer bounds, sink CFG context

Design: [`architecture/graph-alias-slice-layout-modes.md`](architecture/graph-alias-slice-layout-modes.md)
(proposed, not implemented). Chunks G0 to G7 and GC there; G4 depends on the SVF producer chunks S0 to S4
in [`architecture/svf-alias-producer.md`](architecture/svf-alias-producer.md) and on K1.

- G0 contract: five families and modes, vocabularies, identities, `GraphSettings` bounds.
- GC catalog revision 2 (R-UAF `memory_free` sink class, R-OOB-R `memory_read` entries); lands
  after G0 and before G3.
- G1 `Slices.ql` and the `program_slice` normalizer (data, control and summary edges; `on_paths`
  join; `frontier` and `declaration_without_initializer` nodes).
- G2 `TypeLayouts.ql`, `BufferBounds.ql`, the `layouts` branch of `job_cpp_compiled_analysis`
  (`-fdump-record-layouts-simple`) and `graph-cross-check/4`.
- G3 `ControlFlow.ql` as the internal `control_flow` family and `sink_site.result.cfg_context`
  (`graph-normalize/2`); no model-facing CFG mode.
- G4 `aliases` mode over republished `points_to_set` records, source-operand queries in the SVF job.
- G5 retrieval modes, schema mirror, scoped-adapter tests; G6 integration, live counts, docs truth-up.
- G7 `buffer_bound` package context role for lane A memory leads (v5 package schema), after G6's
  live counts.

Catalog and scanner follow-ups from
[`reviews/detector-coverage-checklist.md`](reviews/detector-coverage-checklist.md) not covered by
GC (R-INT `integer_conversion` entries, R-TOCTOU `path_check` and the `toctou_candidate` join,
R-CSA checker names on clang 18, R-CERT pack extraction, R-LIVE recording of the expanded upstream suite and Infer/CSA issue types).

## Joern bounded export and acceptance

**Deprecated (2026-10-12).** Joern is off by default (`jobs.job_cpg_analysis.settings.enabled =
false`). CodeQL is the code-graph producer, with Clang/LLVM cross-checks; see "Why Joern is
deprecated" in `docs/architecture/code-graph-precomputation.md`. The items below are kept for
reference only and are not planned.

Done:

- the pinned, reviewed, offline Joern/c2cpg runtime closure (`tool-joern`);
- the independent `job_cpg_analysis`, which runs c2cpg per accepted C/C++ scope over the exact
  accepted compile commands and retains each CPG as hash-identified, run-owned evidence;
- the `noexec` `/tmp` zstd JNI fix in the image.

Also done: the seeded job runs c2cpg on the seeded units only and a bounded `joern-export --repr all
--format neo4jcsv` (`jobs/job_cpg_analysis/export.py`), so the seeded shard carries real function
observations (a live run on the fixture exported 6 functions). The whole-program shard is still
`BLOCKED` with zero observations. Remaining work:

- a bounded whole-program CPG/PDG exporter;
- the index contract and source mapping beyond the seeded `cpg` rows;
- slicing;
- exporter security probes;
- live functional fixtures at scale.

Also resolve the per-tool resource profile
(Joern needs far more than 1 GiB at scale) and license attribution for JARs without embedded
metadata. Do not put the full CPG into MCP responses.

## Evaluate additional Joern language frontends

The pinned `v4.0.630` archive is verified whole, but `tool-joern` installs only the core and
`c2cpg`. The other thirteen frontend directories are excluded until a job needs them: `javasrc2cpg`,
`jimple2cpg`, `kotlin2cpg`, `jssrc2cpg`, `pysrc2cpg`, `php2cpg`, `rubysrc2cpg`, `gosrc2cpg`,
`csharpsrc2cpg`, `swiftsrc2cpg`, `rust2cpg`, `abap2cpg`, and `ghidra2cpg`. For each language that a
job will consume:

1. State the job and coverage the frontend serves, and why CodeQL or an existing producer does not
   already cover it.
2. Review the frontend's added JARs and any native AST generator, recording provenance, licenses,
   and advisories in `containers/tools/joern/LICENSE.md`. The native AST generators are
   `astgen-linux`, `SwiftAstGen-linux`, `goastgen-linux`, `dotnetastgen-linux`,
   `rust_ast_gen-linux`, and `abapgen-linux`; `php2cpg` also bundles a PHP parser `.phar`.
3. Prove that native AST generators and any interpreter dependency, such as a PHP runtime, run
   offline as uid 10001 under the read-only, no-network, drop-all policy without writing outside
   scratch.
4. Add the paths to `[closure].include` in `containers/tools/joern/tool.toml`, regenerate
   `inventory.json`, and update `tests/test_joern_tool.py`, which currently asserts that no other
   frontend or ELF binary is installed.
5. Add bounded-export fixtures and keep each language's coverage `unavailable` until they pass.

Do not enable all frontends wholesale: that adds about 2 GB and six unreviewed native binaries.
`ghidra2cpg` is binary analysis and belongs with the binary-analysis decomposition decision, not
source CPG coverage.

## Scale the clangd symbol index

Done: the pinned `tool-clangd-indexer` closure, and the independent `job_cpp_symbol_index`. Per
accepted C/C++ scope it runs clangd-indexer over the exact accepted compile commands. It then
normalizes symbols with exact source locations, and aggregated call/reference edges between
accepted symbols, into `analysis` shards with per-scope coverage and verified checkpoints. A live
run against the real image indexed the fixture completely. Remaining work:

- content-keyed, bounded TU batches with per-TU checkpoints, so Unreal-scale scopes fit the tool
  output bound (index output above it is currently a named truncation gap);
- symbols declared only in headers outside the accepted sources (SDK, engine, system) are counted,
  not indexed; decide how header-only symbols are emitted once across scopes;
- mount licensed MSVC and Windows SDK headers read-only for clang-cl commands;
- a reviewed per-tool resource profile for large compilation databases.

Resolve the open items in `containers/tools/clangd-indexer/LICENSE.md` first: confirming the LLVM
source ref, and an advisory match for the LLVM binary.

## Replace the Python build-capture tool wrapper with a static Go binary

`containers/build-capture/tool-wrapper.py` runs for every `PATH`-resolved build tool (cc, c++, ld,
ar, ninja, cmake and others). Measured cost, inside the executor's container boundary with
`--seccomp-bpf` capture:

- about 40 ms per call;
- 45 calls added about 1.8 s to a 0.65 s fixture build;
- about +9 s (+49%) on an 18 s zstd build.

At AAA scale (tens of thousands of compiler and linker calls) that is tens of CPU-minutes per
build. The wrapper also forces `python3` into every build image.

1. First confirm the wrapper still earns its place. strace already records every exec's argv,
   resolved executable and environment authoritatively. The wrapper's unique outputs are per-tool
   stdout/stderr and tool-call records, which reconciliation treats as optional secondary
   evidence. It also misses compilers invoked by absolute path, which Unreal's build tool does.
2. If it stays, reimplement it as a static Go binary (`CGO_ENABLED=0`) with byte-identical
   behaviour:
   - call ordinal locking and the call limit;
   - per-call record, stdout/stderr retention and envp redaction;
   - `exec` of the real tool.
3. Build it offline from a pinned Go toolchain image with locked modules (standard library only,
   if possible). Install it through the capture assets; never commit a binary.
4. Keep the tool-call record schema stable, and bump the capture identities so that changed
   captures invalidate build checkpoints.
5. Re-run the capture benchmark (plain, wrapped, captured) and record per-call cost before and
   after.
## Prove and extend the dataflow lane; build the contract and deployment lanes

The planned `query_dataflow` tool and `job_dataflow_summary`/`job_reachability_linking` jobs are
superseded by `query_code_graph`, the `job_codeql_analysis` export step and `job_code_graph_index`
([`architecture/code-graph-precomputation.md`](architecture/code-graph-precomputation.md)). For
C/C++ that lane is built end to end: `dataflow_path`, `entry_point`, `guard_fact`, `range_fact` and
`flow_summary` facts reach packages, admissibility and scoring. Remaining:

1. Run the operator live tier on the review host with the pinned CodeQL image:
   `python -m pytest -q tests/live/test_codeql_graph_export_live.py tests/live/test_code_graph_live.py`.
   Refresh `tests/fixtures/graph/codeql_export/native` from the diff (set its provenance `recording`
   to `live`), and fix the pack, or the expectation if the pack is right, for any failure of the
   synthetic dataflow expectations (`tests/fixtures/graph/codeql_export/synthetic/expected-facts.json`).
   The native fixture has no sources or sinks, so only the synthetic test proves the dataflow
   families.
2. Export packs/catalog sections and recorded fixtures now exist for Java/Kotlin,
   JavaScript/TypeScript, Python, Ruby, Go, C#, Rust and deferred Swift. Multilingual normalization,
   native-only secondary scoping and worker neighborhood retrieval are wired. Finish per-language
   live image/database/export acceptance with matching pins; Swift remains disabled and PHP has no
   CodeQL extractor. Keep recorded acceptance distinct from live acceptance (section 8).
3. Implement the contract and deployment lanes planned in
   [`architecture/evidence-sources-and-dataflow-retrieval.md`](architecture/evidence-sources-and-dataflow-retrieval.md).

Unresolved indirect calls, unmodeled externals, and path/depth limits must be published as gaps.

## Acquire dynamic execution evidence

Hash-verified import is now implemented for LCOV, Cobertura, JaCoCo, and LLVM coverage JSON, and
for textual folded-stack, perf-script, Callgrind, and LLVM sample profiles. Those producers ingest
artifacts already retained by accepted builds; they do not execute tests or profilers. Live
coverage/profile generation, sanitizer logs, fuzz corpora, and IAST traces are not yet available.
Define a separately authorized, isolated execution job before producing them. Positive traces may
support reachability; zero coverage is a gap and never refutes a claim.

## Add Perforce history to source history analysis

`job_source_history_analysis` implements local Git and optional GitHub enrichment only. Perforce is
designed in [`architecture/source-history-analysis.md`](architecture/source-history-analysis.md)
but not built. Implement it as a second history source behind the same signals, ranking, `history`
shard, and plan `history_priority` contract:

- export mode first: consume an operator-produced, SHA-256-pinned `p4 -ztag -Mj` bundle with no
  network or credentials in the review;
- then server mode in a pinned `tool-p4` image whose only egress is the configured `P4PORT`, with a
  pinned changelist, configured `ssl:` trust fingerprint, a ticket from an environment-variable
  secret, and target `P4CONFIG`/`P4ENVIRO`/`.p4config` ignored;
- bind every inventory file to `@N` with `p4 fstat -Ol` digests, reporting `ktext`, purged, and
  protections-hidden paths as per-path gaps;
- use `p4 describe -ds` for churn, `p4 fixes` for exact fix classification, and bounded
  `filelog -i` integration following;
- review the Helix Core CLI license before cataloging the image, and add the history identity probe
  inputs (server identity, depot scope, changelist, bundle hash) so resume reruns on any change.

## Consider following Git submodules in source history analysis

Submodule gitlinks are currently a `submodule_history_not_followed` gap. Decide whether each
submodule should become an independent history source bound to its gitlink commit, how its signals
roll up into the parent's components, and how its own `.git` (often under the parent's
`.git/modules/`, outside the submodule path) is resolved without leaving the target root.

## Finish deferred source history signals

- Exact security-fix classification needs an OSV index of `fixed` Git events keyed by commit id;
  extend the OSV sync index and match walked commits against it.
- Commit subjects are not indexed. Index them only after a gitleaks redaction pass, with a named gap
  when redaction is unavailable.
- Function-level history uses snapshot Tree-sitter spans, so renamed or moved functions keep their
  snapshot identity and deleted functions are not represented. Follow symbol identity across
  history if consumers need it.
- Cognitive complexity does not detect recursion. Add live grammar probes that pin the
  complexity node-type table to the locked Tree-sitter language pack.
- Add an exact-filter `query_history` MCP tool if consumers need more than `find(kind="hotspot")`.
  Blame-to-Tree-sitter function joins also exist in `job_change_context_analysis`.

## Extend change-context analysis

`job_change_context_analysis` is implemented; see
[`architecture/change-context-analysis.md`](architecture/change-context-analysis.md). Remaining work:

- Function-level fix-on-fix events: map the parent-side blamed lines through the fix and later
  changes to snapshot function spans instead of reporting the metric unavailable at function scope.
- Function attribution only sees surviving lines in the top blamed files; consider bounded
  `log -L` per function for changes whose lines were later rewritten.
- A deployment-event adapter for common CD systems. GitLab, Gerrit, and Azure DevOps review
  exports are produced by target acquisition (see
  [`operations/target-acquisition.md`](operations/target-acquisition.md)); validate them against
  live servers.
- Component relatedness uses nesting and co-change only; add build-graph or ownership-file
  (`CODEOWNERS`) relatedness when the catalog exposes them.
- Feed the change-context ranking into `job_target_analysis_plan` once the plan can wait on
  Tree-sitter without delaying the build lane.

## Narrow review-prioritization approximations

See [`architecture/review-prioritization.md`](architecture/review-prioritization.md).

- Resolve call targets (clangd symbols, CodeQL call graphs) so wrapper, sink, and recursion
  heuristics stop depending on callee names, and so indirect recursion is detected.
- Evaluate build-system include paths, tsconfig `paths`, Composer PSR-4 maps, and Cargo workspaces in
  import resolution, and count implicit same-package references.
- Diff public API and contract declarations between the snapshot and its mainline parent instead of
  combining declarations with the history hotspot.
- Score preprocessor-conditional and macro control flow instead of reporting it as unsupported.
- Add a Python mapping and any further languages the Tree-sitter producer gains.
- Add Semgrep or CodeQL path queries for PHP, which has no CodeQL extractor today.

## Wire binary decompilation publications into a review

Done: the pinned `tool-ghidra` image, the `[binary_decompilation]` configuration, the pre-run
`appsec-review binary-decompile` command, the verified publication store with its `current.json`
pointer and `resolve_current` lookup, and the case-083 known-binary efficacy comparison. Reviews now
consume publications: the `binary_evidence.resolve_publications` intake task with per-binary
`required`, `job_binary_evidence_indexing` (bounded `binary` shards served by the existing
retrieval and MCP tools, in the CLI graph and Dagster wave-1 topology), the registered
`binary-evidence` runtime skill with an enforced binary citation rule, PDB inputs with a
`debug_symbols_not_applied` gap, managed-code routing to a named decompiler, and a designed
binary-only target kind. See [`architecture/binary-decompilation.md`](architecture/binary-decompilation.md).

Outstanding, in order:

1. Rebuild `tool-ghidra` (it now ships `AppsecLoadDebugSymbols.java` and the wrapper's
   `--debug-symbols` option) and run a PE fixture live, with and without its PDB. Today the PE and
   PDB path is tested only with a fake Ghidra export; confirm Ghidra's PE loader and PDB analyzer
   accept the staged file and that `program.debug_symbols_loaded` is reported.
2. Measure peak container memory, wall time, publication file count and size, normalizer memory,
   and `job_binary_evidence_indexing` time and index size on a large real binary (tens of thousands
   of functions). Then tune `[binary_decompilation]` (`memory`, `max_heap`, `cpus`,
   `timeout_seconds`, `analysis_timeout_seconds`, `max_functions`, `max_strings`) and
   `[jobs.job_binary_evidence_indexing.settings]`, whose current values are provisional. This needs
   a Docker host and a licensed large binary, so it was not done.
3. Implement the binary-only target kind designed in the architecture page, including the open
   decision on the dangerous-import seed list.
4. Add a managed-code decompiler lane (ILSpy for CIL, jadx or CFR for JVM and Dalvik); today
   managed binaries are routed to a named gap only.

## Decide how to assert correctness for large query-set jobs

`docs/processes/acceptance-and-regression-testing.md` makes each job assert that its output is the
correct response to its inputs, through `Unit.output_validators`. Four contract classes carry most
of that: schema, conservation, internal consistency, and cross-job agreement. They caught every
defect found during the 2026-10-15 bring-up without needing an oracle.

**They do not reach jobs whose output is a large, open-ended result set.** `job_codeql_analysis`
runs 117 CERT C++ queries plus the default suites; `job_evidence_collection` drives twenty
scanners. For those, "is this the correct answer?" is a question about each rule's semantics, and
no conservation or consistency property answers it. The strongest contract available today is the
weak one the pipeline already applies: a required producer that returns zero results is a coverage
gap, not a clean classification.

What needs deciding, roughly in order of expected value:

- **Per-rule corpus expectations.** `rules/sei-cert/multivuln.json` already carries
  `expected_findings`, `expected_exclusions` and `known_false_negatives` against a pinned target
  commit. That is a machine-readable oracle for the SEI CERT rule set and should be the model for
  the rest. Decide whether it is authoritative, and extend the same shape to CodeQL's own suites.
- **Rule liveness.** Assert that every enabled rule produces at least one result somewhere across
  the corpus. A rule that never fires is either dead weight or broken, and today nothing notices.
  This is cheap and would have caught the CERT suite yielding nothing at rule granularity.
- **Metamorphic pairs.** For each rule, a vulnerable snippet must yield a result and its fixed
  counterpart must not. Testable without a full oracle, and it pins rule semantics rather than
  aggregate counts.
- **The engine's own test framework.** CodeQL ships `codeql test run` with `.qlref`/`.expected`
  files, and the upstream coding-standards repository already uses it. Query semantics probably
  belong there, not in our pipeline, with our contracts asserting only that the suite ran, resolved
  and produced accounted-for output.
- **Result envelopes rather than exact sets.** Where an exact expected set is unmaintainable, assert
  bounds (counts per rule, per family) so drift is visible without pinning every row.

This is a separate layer from the job contract, and both are required. The job contract asks
whether a job produced the declared number of correct outputs for its input. Query unit tests ask
whether a single query returns the correct rows for a known database. Neither substitutes for the
other, and conflating them is how a suite that runs but answers wrongly passes.
