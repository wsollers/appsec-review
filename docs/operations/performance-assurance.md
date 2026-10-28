# Performance and customer-evidence assurance

`[review_policy]` in the central configuration selects `strict` by default.
`first_party_managed` additionally requires an operator-approved `project_id`, membership in
`approved_first_party_projects`, an absolute matching `target_root`, and
`custody = "application_private_v1"`. These settings are frozen with the run and attempt claim.
A legacy claim cannot acquire managed trust from a subsequently changed configuration.
An accepted-attempt reuse claim carries policy only from its verified original claim, whose
run/job/attempt binding and frozen policy are checked first. Reuse does not invent a managed
grant for a legacy claim or modify the original claim/configuration.
Target-independent jobs retain an absent target root and the source identity `none`.
They consume target-bound upstream evidence only through a separately authenticated
`evidence_target_snapshot`, sealed with the managed claim and restored at execution/finalization.
This binding does not grant target filesystem access or turn a metadata-only readiness result
into target evidence.

Both modes exclude supplied platform software from customer assurance: application source,
container/tool payloads, installed CodeQL extractors, and supplied query/rule packs are not
fingerprinted. Reading their configuration or loading a rule for execution is not a payload
integrity measurement. Customer source, customer-generated databases/results, accepted evidence,
and frozen configuration/guidance retain their integrity requirements. Target-owned build/CI
files are build-chain context, not automatically shipped-runtime evidence. Directory names such
as `vendor`, `node_modules`, `build`, and `dist` do not establish platform ownership.
Job construction does not enumerate application source trees to assemble an implementation
identity; unused discovery left over from the former source-fingerprint path is removed.

## Publication and consumption

Strict consumers deduplicate expected-digest checks, receipt closure checks and shard validation
within one operation. The context is bound to its run, target snapshot and policy; incompatible
nested contexts fail. A new independent strict operation performs its own verification.

Managed publication still verifies new evidence. It detaches private builder files from writable
aliases, requires application-owned POSIX custody, removes accepted payload write permissions,
and issues an authenticated admission record outside the review run's mounts, under
`runs/metadata/evidence-admission/`. The local authentication key is private to the application;
it is not target evidence and must never be exported to workers or committed.
Admission schema `appsec-review/admission/2` binds authenticated shard and manifest summaries.
Handoffs also publish each configured unit's terminal status and result receipts, so managed
inventory can account for completed steps without scanning task directories. These are customer-run
execution records, not fingerprints of supplied runtime code.
Target-independent metadata is not managed evidence; its publication reports
`ADMISSION_NOT_APPLICABLE` and retains strict verification.

Managed consumers authenticate the record, check run/producer/target/configuration bindings and
accepted-output availability, and use admitted shard/receipt summaries instead of repeating
whole-payload hashes and SQLite validation. This deliberately does not detect every same-size
post-publication mutation by the application owner. Writable accepted payloads, unavailable
outputs, authentication failures and changed bindings fail consumption. Legacy evidence without
a record remains strict; managed inventory requires explicit re-admission of legacy producers.
Within one operation, exact unchanged configuration bytes may reuse their decoded policy and
digest, and the latest exact admission bytes plus the current authentication key may reuse HMAC
validation. Each cache retains at most 1 MiB of document bytes. Current bytes, configuration pins,
private-key custody, handoff bindings and output availability/permissions are still checked;
returned policy and record objects cannot mutate the cached proof. Independent operations start
without either cache. This does not remove detached-custody copies or new-output verification.
New payloads with identical verified content within one publication share a freshly detached
inode when their read-only modes and destination device/group match. Every original path is
validated before any detachment; one private temporary copy is fsynced, independently hashed,
closed and made read-only before any alias is replaced. No original producer inode is reused,
so existing writable handles remain detached. Incompatible destinations receive separate copies,
and failed links fail publication rather than authenticating partial custody. This grouping is
publication-local, not a persistent content cache or a shortcut for new-output validation.
Before admission is issued, every newly trusted artifact is fsynced in its final state, including
non-detached JSON and terminal receipts. Every destination-directory chain through the run parent
is then fsynced; distinct-device copies receive their own inode barrier. This orders durable data,
read-only modes and alias/rename entries before the authenticated admission record. New key and
record directory entries are also synced. Barrier failure aborts admission. Records lacking the
`fsync-inodes-and-parents/1` custody proof cannot enable managed bypass and require fresh admission;
older records are not silently upgraded. These additional barriers have not been benchmarked.
Unit execution restores only claim-pinned authenticated upstream admissions before input validators
and the handler read accepted evidence. Fresh-process finalization restores the same bindings before
collecting or validating outputs. It does not detach those admitted payloads again.
Attempt input preparation also authenticates the explicitly selected upstream handoffs before
merging their manifests, under `attempt.prepare_inputs`. Preparation cannot publish shared objects
against a provisional claim; a successful claim is written only after its input pin is known.
Job-level input validators restore the same authenticated upstream bindings.
Named shard consumption carries its known content pin through provenance recording instead of
rediscovering it by hashing. A pin alone never grants managed trust. Inventory keeps one validation
scope through authenticated enumeration and artifact checks; strict mismatches remain named audit
violations.
Standalone retrieval keeps one validation scope across accepted-handoff resolution and manifest loading;
that scope ends with construction rather than becoming a global trust cache.
Each retrieval query also has an operation scope, so multi-depth graph traversal does not hash
the same shard again at each depth. Queries inside an authenticated producer/consumer operation
reuse that admission. A standalone query without such admission verifies the shards it opens;
a previous query's digest cache does not authorize the next query or hide an intervening mutation.

Managed inventory accounts for accepted publications rather than walking arbitrary scratch.
Its report says `audit_scope = "accepted_publications"` and `scratch_audited = false`; those are
assurance limitations, not evidence that scratch is clean. Strict inventory retains customer-run
auditing and excludes application-reserved supplied CodeQL staging paths before traversal.

Catalog package publication assembles once. An authenticated projection binds the complete
package set and manifest to the accepted input manifest and assembly rule. Serialized validation
checks that projection, schemas, byte identities and membership independently, without calling
assembly. Recomputing package and manifest hashes cannot authorize changed retrieval grants,
evidence, context or coverage gaps. A missing projection requires strict re-admission.

## Operator-declared releases

Prebuilt target binaries have a distinct bounded intake-to-artifact-index-to-scanner path, including
when the language build publishes no build receipts. Target-relative paths resembling provisioned
tools remain customer content. Their delivery status is explicitly unknown unless established by
another contract; indexing them does not invent build success or prove that they are shipped.

Generated source that exists only in an accepted build workspace has a separate AST input lane.
It selects bounded source entries from verified build receipts/manifests rather than enumerating
workspace trees, applies delivery scope before reading bytes, and detaches selected customer source
into read-only run custody. Explicit generated logical paths and `source_backing` provenance
distinguish these sources from the target checkout. AST and priority locations retain that backing;
retrieval verifies its run, target, origin, canonical artifact, size and digest before resolving
lines, without falling back to a coincidentally named target file. When language builds are enabled,
AST waits for their accepted outputs; source-only graphs do not acquire a build prerequisite.
This does not infer shipping from a file's directory or generated origin, and unknown delivery
remains a named gap. Fixture and real-parser acceptance of this added lane remain separate gates.

Leave `[review_policy.releases]` empty until the deployment owner assigns real opaque release
IDs. Do not derive IDs from installed files, source trees, Dockerfiles, images or tool manifests.
Missing required IDs disable the affected reuse with `missing_release_identity`; they do not
enable fallback hashing. Changing supplied software without changing its declaration is a
platform release-management risk, not a customer review check.

| Component key | Responsibility |
|---|---|
| `platform`, `validation` | Application implementation and evidence validation contracts |
| Job ID, when assigned | Job-specific implementation overriding the general platform declaration |
| `build_toolchain`, `codeql`, `codeql_runner` | Build environment, CodeQL distribution, supplied runner |
| `extractor_<language>` | Installed extractor used to create a customer database |
| `query_<language>_<query_id>` | Independently reusable query profile |
| `export_<language>` | Supplied graph export pack and runner contract |
| `graph_catalog`, `graph_columns`, `graph_normalizer` | Graph classification, column contract and normalization |
| `codeql_normalizer` | SARIF observation normalization, separate from database/query production |
| `jvm_instrumentation`, `wasm_instrumentation` | Supplied language-family instrumentation contracts |
| Tool ID and `rules_<tool-id>` | Static scanner adapter/runtime and supplied rule bundle |
| `target_documents`, `feed_publisher` | Target-document parsing and reference-feed publication |

Derived dependency-image reuse requires `platform` and `build_toolchain`. Image manifests and
tags are run-private, and recipe identity includes only those relevant declarations, target
dependency hashes and effective recipe settings. Generated platform Dockerfiles are not hashed;
`dockerfile_sha256` is null. Availability of an unchanged baseline image is not a cache hit or a
saved build. CPP checkpoints require `platform`, `validation` and the applicable `tool-native-cpp`
or `tool-infer` declaration. Artifact scanner checkpoints require `platform`, `validation` and
their tool declaration (built-in inspectors require only the first two).
Project probes, accepted image repairs and language-build checkpoints require `platform`,
`build_toolchain` and `validation`. Their cache namespaces are run-private; matching recipes alone
do not authorize reuse across runs or targets. Probe keys also bind capture mode, limits and
applicability, and target intake integrity is checked before an early probe hit. Missing declarations
emit `CHECKPOINT_MISSED` with `missing_release_identity` and execute the ordinary bounded path,
subject to the separate builder prerequisite below. Language-build keys bind relevant releases;
unrelated query-pack declarations do not invalidate these build checkpoints.
CodeQL also supports explicit [preinstalled runtime declarations](codeql-analysis.md#explicit-preinstalled-runtimes)
binding source image, accepted build image, effective user, CodeQL/runner releases and inspected
runtime image ID. This is distinct no-build provenance, not reuse of a historical derived-image
manifest. An incomplete configured mapping fails; an absent mapping preserves bounded preparation.
An explicit ordinary-only `runner_source = "application"` mounts the fixed current platform
wrapper read-only rather than mislabeling an older wrapper inside the image. Its declared release
and source mode participate in provenance and identity; there is no arbitrary host-path option
or native mount-grant exemption. Execution reservations, protected target/build inputs and
cleanup remain unchanged.
SARIF observation publication binds `codeql_normalizer` as well as its normalizer schema;
changing that declaration selects a new observation shard without invalidating databases or
queries. Normalization still computes and independently validates its output rather than treating
an existing shard as permission to skip computation.
Document-issue ledger reuse requires its job-specific release (or `platform` fallback) and
`validation`. Its material key binds those declarations, schema, accepted inputs and settings;
missing declarations skip lookup and report `missing_release_identity`. New computation still
publishes an attributed receipt, and eligible reuse still verifies target-source resolution.
Release selectivity at the identity level does not establish cross-run reuse. A run's configuration
and releases remain immutable; a query-release change requires a new run, whose run-private
database cache is distinct. The CodeQL query compile cache is the one cross-run exception: it is
shared by runs with the same user and declared CodeQL release, and holds only compiled
repository-owned QL ([cache](codeql-analysis.md#query-precompilation)). The opt-in predecessor path below supports query-release-only changes
through a new frozen run. Fake-tool acceptance covers destination `JobRunner` execution and
finalization, accepted import provenance, zero new DB launches, fresh queries under the new
declaration and subsequent query reuse in both modes. Real retained-data import and production
performance remain unverified and require separate authorization. Changing an in-memory policy
inside an existing run is not a valid way to demonstrate that gate.

## Scheduling and limits

CodeQL topology is `plan.inventory` -> `execution.scopes` -> `acceptance.publish_handoff`.
Within `execution.scopes`, a completed database makes its queries and export ready immediately;
normalization follows each query. Resource eligibility still limits when ready work can execute.

Host-metadata leases account for configured CPU, container memory including its 1024 MiB
overhead, staging memory and I/O slots. They record process-start identity and tracked containers.
An unconfirmed container death or failed cleanup retains a quarantined reservation. Reconciliation
requires explicit confirmation, not PID absence alone. Operational producer/admission failures
remain named scope gaps; integrity and configuration failures remain fatal.

Review publication contexts also bind generic scanner, build, capture-secret-scan and CodeQL
inventory execution to the same host ledger. Reservations include preparation and close-out.
Nested launches cannot exceed or outlive the enclosing reservation; concurrent nested launches
serialize rather than each spending its parent's allocation. Platform-maintenance calls outside
review contexts are separate operator work and are not a claim of whole-host accounting.

The bounded builder client is selected only by frozen `review_policy.image_builder` configuration,
with an explicit operator `project_id`. Without it, a required image miss remains
`derived_image_preparation_unavailable` before staging or daemon mutation. An eligible declared
prepared image or valid uncustomized baseline remains usable; a baseline never substitutes for
required dependencies. Project dependency/repair Dockerfiles and offline CodeQL layering retain
their required semantics through the configured backend rather than an unbounded Docker client.

The Linux Unix-socket protocol is `appsec-review/bounded-image-builder/1`. It requires an
operator-private endpoint and authenticated peer UID, a bounded JSON request/response exchange,
and fresh request nonces. Each build binds tenant, project, run, target snapshot, recipe, declared
builder release, private context and output tag. The service must implement `prepare`, `start`,
`status`, `cancel` and `cleanup`; each response repeats the binding and stable worker ID/start
token. Before target staging, `prepare` must report private custody and positive, enforced CPU
quota/period and memory ceilings for both worker and fixed host overhead. It must not execute
target instructions until `start`. Image input aliases and output tags are namespace-private;
the service must not pull images or expose a Docker control socket to target build instructions.

The shared host ledger reserves worker plus host CPU/RAM and staging memory before preparation,
tracks build intent before contacting the service, and limits aggregate concurrent builds.
Client exit, timeout or launcher death cannot release a build reservation. Only independently
confirmed `CLEANED`, `work_stopped=true` and `context_released=true` release it. Unknown/rebound
workers retain quarantined reservations, including after owner exit; reconciliation additionally
requires explicit confirmation for every recorded build. Required output images must survive
worker cleanup. A successful terminal names its immutable output image ID; both resolvers compare
local image inspection with that ID before publication, and cache receipt verification requires
the same ID. A stale tag or a success response without a result ID is not accepted.
Bounded diagnostics and preparation/execution/cleanup receipts are retained under
`data/orchestration/image-builds/`; private contexts stay under metadata
`bounded-image-contexts/<namespace>/<build-id>/`. Cache reuse verifies the successful run-bound
receipt and declared releases without hashing supplied platform payloads.

Example contract (not enabled by default):

```toml
[review_policy]
project_id = "operator-project"

[review_policy.image_builder]
endpoint = "/run/user/1000/appsec-builder/control.sock"
tenant_id = "operator-tenant"
release_id = "commissioned-builder-release"
cpu = 1
host_cpu = 1
memory_mb = 4096
host_overhead_mb = 512
max_concurrency = 1
cleanup_timeout_seconds = 60
```

The backend implementation is available as
`python -m appsec_review.container_runtime.image_builder_service --config <operator-TOML>`.
It is **not commissioned or enabled by this change**. The typed service configuration is separate
from frozen client policy: `[image_builder_service]` defines private endpoint/journal paths,
declared worker/Docker/Skopeo releases and immutable worker image, native daemon/cgroup paths and
bounded execution settings. `[[image_builder_service.grants]]` authorizes an exact UID,
tenant/project/run, target snapshot, namespace and client/service context root.
`[[image_builder_service.images]]` allowlists local aliases, immutable image IDs and operator
release declarations. Neither target instructions nor request fields can create those grants.
Project-to-CodeQL layering and project repairs may also consume exact immutable outputs from
earlier successful builds recorded in the private service journal. These require confirmed
cleanup, released contexts, matching tenant/project/run/namespace and service release, and bound
worker/result proof. Dockerfile alias validation and OCI input staging use the same authorized
input map. Unknown, cross-run, failed, quarantined or legacy outputs without that proof are not
authorized; newly built images do not require editing the frozen static allowlist.

`[image_builder_service.admission]` requires the shared `metadata_root`, its non-root `uid`/`gid`
and a fixed `lease_id`. The supplied `--reserve-lifetime` command records the service's persistent
host reservation in the same admission ledger before startup; normal service startup verifies
that real reservation and each client's matching active build reservation. `--reconcile-admission`
uses the private service journal to match the complete build binding, endpoint, worker generation
and service contract before clearing abandoned client leases. Missing, unknown or rebound work,
and unrelated quarantine reasons, remain reserved. `--release-lifetime` requires independently
verified end of the reserved daemon/service work; stopping only the client or service process is
not sufficient. The operator helper preserves the non-root ledger ownership rather than replacing
it with root-owned files.

The persistent reservation is one CPU and 512 MiB, even while idle. Active clients conservatively
retain their existing worker-plus-host reservation as well: an ordinary build therefore reserves
three CPUs and 5,632 MiB in total including staging, although its worker/host execution caps remain
one CPU/4,096 MiB and one CPU/512 MiB. This deliberate extra reservation reduces available
headroom; it does not increase any execution limit or exempt idle daemon costs.

The service persists intent and request identity before external effects, keeps uncertain work
admitted across restart, and reconciles abandoned owners independently. Its worker uses locally
installed images through OCI layouts and verifies a freshly exported/loaded output identity.
An allowlisted base cannot authorize an implicit remote `FROM`, `COPY --from` or external
Dockerfile frontend. Package-network recipes additionally require an operator-provisioned
isolated egress proxy/network; they cannot gain Docker control access. Unsupported or ambiguous
recipe syntax fails explicitly, never by substituting a base image.

This initial driver requires native, verifiable Linux daemon/process/cgroup topology, a sandboxed
rootless BuildKit worker and independently capped host overhead. Translated Docker Desktop
context mappings are rejected. Existing Docker availability or CPU affinity does not satisfy
these prerequisites. Operator config, socket parents and journals require private custody.
Client and service must share the exact mount, PID and user namespaces, and authorized
`client_context_root` must equal `service_context_root`. This is native same-namespace support,
not compatibility with the existing containerized `/opt/app` client and WSL/native translated
paths. The explicit [native operator](../../deploy/dagster/native/README.md) implements the
same-namespace restricted-broker path; translated mappings remain unsupported. Deployment still
requires a separately approved arrangement satisfying these restrictions. Native fake-service
acceptance cannot clear that gate, and simply removing the checks is not an acceptable mapping.
The driver also permits only its worker/proxy on the configured engine during a build and loads
the resulting image into that engine. Client result inspection and later execution must see that
same immutable image. An ordinary review container overlapping a build on that engine is
rejected, not implicitly exempted. Any future higher-I/O or parallel deployment must preserve
builder/executor engine exclusivity or obtain separately validated integration; raising budgets
alone does not establish a compatible topology or safe scheduling.
No service, daemon, network, proxy, image or cgroup is provisioned by configuration loading.
Fixture evidence cannot establish real enforcement, isolation or cleanup; provisioning and
real-backend acceptance still require separate authorization and evidence.
Until then, equal-coverage and next-run gates involving required derived builds remain **blocked**;
named preparation gaps do not satisfy those gates or authorize reduced target coverage.

The checked-in `memory_mb = 10240` and `io_slots = 1` settings are deliberately conservative.
Two ordinary 4096 MiB CodeQL actions require 11264 MiB including container overhead and staging.
**Two-action overlap is unavailable under these defaults.** No production capacity increase is
implied by a fixture-validation allowance or by the unlimited package-count setting. Complete
backend/cleanup/reconciliation commissioning remains a rollout gate; fixture admission does not
establish available production capacity.

A capacity overlay may set `review_policy.resources.*` for one host. The checked-in
[`test/acceptance/prod-capacity-overlay.toml`](../../test/acceptance/prod-capacity-overlay.toml)
raises `io_slots` to 4, so four 2-CPU/1,536 MiB scanners fit the CPU and memory budget, and lowers
the Dagster `scanner` pool to match. The admission ledger is shared across runs on the host and
admits against the lowest limit among active leases, so a concurrent run without the overlay
restores one-slot admission. A scanner's admission wait counts against its tool `timeout_seconds`;
an admission timeout is a named gap. With the image builder service enabled, overlap with a build on
the same engine is still rejected regardless of `io_slots`, and a native operator contract must
declare the same budget.
Persistent service/daemon overhead also consumes the aggregate budget while the service is idle.
With even one CPU held for that lifetime inside the eight-CPU budget, an eight-CPU compiled
database or export-compilation action cannot be admitted while the service remains alive.
An admission timeout is missing coverage, not successful compiled analysis or an equal-coverage
performance result. The operator must resolve this configuration conflict before rollout using
separately authorized capacity or a verified lifecycle arrangement that actually stops the
reserved service/daemon work before those actions. The code does not silently reduce the profile,
exempt service overhead or increase production limits; process exit alone cannot release an
uncertain daemon reservation.
Feasibility must include the compiled action's 9,728 MiB runtime/staging peak plus the persistent
baseline and any separately charged proxy/daemon costs. A permanently infeasible request must
fail explicitly rather than enter an indefinite scheduling wait. A smaller synthetic
commissioning workload fitting the envelope does not establish compiled-review readiness.

## Explicit predecessor database reuse

`review_policy.predecessor_databases` is an opt-in, DB-only import from an exact accepted
CodeQL handoff in the same operator-owned run store. The selected handoff binds its original claim,
which must name the selected source run; an optional envelope run ID must agree when present.
Both frozen configurations must authorize
the same tenant and approved first-party project, assurance mode and target snapshot. Current
scope material, execution limits, environment and required component release declarations must
produce the same database identity. A missing declaration or incompatible selected scope fails
before scheduling; it never silently substitutes a fresh database build.

Configure `review_policy.store_authorization` with `tenant_id` and absolute `runs_root` in both
runs. In the new run, `predecessor_databases` requires the prior `run_id`, exact
`handoff_sha256` and an explicit `scope_ids` array. Its default bounds are 100,000 files,
1 GiB total DB bytes, 4 MiB aggregate metadata and a 600-second operation timeout. Metadata
bounds must fit the configured staging-memory reservation with parsing overhead. This is not
a global or cross-tenant database cache.

The ready coordinator verifies the original claim, frozen configuration, accepted result and
selected database manifests, then strictly verifies all selected DB bytes. A shared CPU,
staging-memory and I/O reservation covers import. Detached, read-only copies are staged before
publication under current-run scope paths; compatible existing destinations are recopied, not
trusted as potentially writable hardlinks. Copy failures remove staging. A retry verifies the
source and every destination again; an incomplete selected checkpoint cannot trigger a fresh
producer. `data/codeql/predecessor-import.json` binds both configurations, source handoff,
project/tenant, target and selected material identities, and is retained in the new result.

No prior queries, SARIF, exports, guidance or platform payloads are imported. Queries execute
under the new frozen declarations and keep their independent query checkpoint identities.
The `codeql.predecessor_import` span records actual verification/copy work and its reservation.
Code and fixtures do not authorize importing retained real-run data or demonstrate production
import performance; real-operation acceptance remains separate.

## Metrics and comparison

The existing pipeline log receives correlated operation start/completion records, bounded work
counters and process resource observations. Parallel tool invocations use `tool_invocation_id`;
run, job and attempt identity remain part of correlation. Counter updates are synchronized.
Log append reads a bounded tail rather than reparsing its complete history.
`event_count` and `event_counts` both describe deduplicated records; `raw_event_count` and
`raw_event_counts` describe the input log before lifecycle deduplication. Missing or conflicting
lifecycle terminals make accounting explicitly partial, rather than creating zero-duration work
or pairing ambiguous parallel starts and completions by arrival order.

Process CPU/I/O spans are inclusive and must not be added across overlaps. Unavailable child CPU,
physical I/O, peak RSS, model tokens or cost stay null with an explanation, not zero. Work counters
describe instrumented boundaries, not an inferred whole-host total.
`platform_work` distinguishes explicitly recorded zeros from absent instrumentation: absent
platform hash/scan counters are null with `platform_counters_not_emitted`, not assumed zero.
This is separate from the unconditional exclusion policy and from fixture deny-guard evidence.
CodeQL target staging, query database copying and export preparation have separate correlated
preparation spans before execution. Their copy counters count completed customer-material file
copies, including private database copies; they do not walk or fingerprint supplied export packs.
Preparation records bind the exact `scope_id`, query profile where applicable and
`tool_invocation_id`. Nested preparation inherits its action's `resource_lease_id`, linking the
work to eligibility/admission/release records without relying on concurrent log order.
Aggregated `resource_spans` retain these links and each span's work counters.
`resource_admissions` retains per-lease queue delay and scope/profile for admission and timeout;
an action that times out before admission has no execution span. Missing legacy fields stay null.
Shared-object streaming publication also records its actual copied byte/object counts. These are
logical copy counts, not physical storage I/O or a count of successfully admitted outputs.
`custody_alias_objects` counts completed alias replacements using that publication's freshly
detached copy. It is separate from copied bytes/objects and never counts reuse of a producer inode.

The three-repeat warm trace fixture compares prior per-open strict target-shard verification
with operation-scoped verification while requiring identical results and gaps. Both measured
batches reduced hashed objects from 16 to 8 and bytes from 917,504 to 458,752. The initial medians
were 40.14 ms versus 42.43 ms; after removing redundant canonical-root resolution they were
44.29 ms versus 43.49 ms. Individual samples and both batches remain in the validation evidence.
These small, noisy component measurements do not establish the 50% lifecycle-overhead target,
the CodeQL non-regression gate, or a production speedup.

Historical stage intervals are not matched benchmark trials or function attribution.
The retained package task was 1,836,099 ms and scanner-correlation transformation was 91,406 ms.
Do not infer speedup by adding overlapping intervals or treating logical hardlink bytes as disk
occupancy. Controlled comparisons must state workload, coverage, resource limits, cache state,
repetitions and unmeasured dimensions. No end-to-end production performance claim follows from
fixture results.

The latest six-graph intake/catalog/index/package fixture preserved all package membership,
resolving evidence and 99 coverage gaps. Three alternating samples per mode gave medians of
23.176 seconds strict and 27.239 seconds managed: managed was 17.529% slower, so the fixture's
50%-reduction flag was false. Exact-byte admission metadata reuse passed causal regressions,
but does not establish a lifecycle speedup. Handoff-publication medians remained 1.467 seconds
strict versus 3.701 seconds managed; these inclusive spans do not isolate copy time.
Grouped fresh-inode detachment removed five redundant copies totaling 540,672 bytes per managed
trial: 112 logical copies and five custody aliases remain, versus strict's 21 copies.
Copies cannot be removed solely
because a file is read-only or has one link: those facts do not exclude surviving writable handles.

A separate earlier six-graph telemetry comparison measured 4.290% overhead, meeting its fixture
5% flag on that earlier source state. Neither measurement establishes the historical
validation/accounting/package-overhead target or equal-coverage fresh-CodeQL non-regression.
Those gates remain unestablished, not passed and not failed historical comparisons. Stores were
fresh, host filesystem caches uncontrolled, FTS disabled and all tool/model work synthetic.

Rollback selects strict customer-evidence assurance and, if necessary, conservative scheduling.
It must never restore supplied-platform payload fingerprints or silently truncate package counts.
Apply that selection only to subsequent runs using explicit versioned configuration/code; never
rewrite an existing run's frozen policy or topology. Managed-admitted evidence needs strict
re-admission before strict reuse, or recomputation if verification cannot establish correctness.
Retain original receipts and logs. Native rollback stops new admission and only exact owned
processes; independently confirm descendants/container removal before releasing reservations.
Unknown work stays quarantined, and stopping the app does not release the persistent engine
baseline. An isolated native instance must not alter the existing Compose deployment on rollback.

The next-run performance goal remains unmet: the latest comparable fixture did not demonstrate
the requested reduction, and historical overhead and real equal-coverage CodeQL gates remain
unestablished. Later custody durability and native integration corrections have not been
remeasured. Passing fake lifecycle tests does not waive those gates or authorize a new review.
