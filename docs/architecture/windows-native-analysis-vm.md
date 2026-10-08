# Future Windows native-analysis project

Status: design only; no VM, image, installer, orchestration, or runtime implementation exists.

Research checked: 2026-10-08. Licensing conclusions in this document are engineering gates, not
legal advice. The operator must confirm current terms and its own entitlements before acquiring or
using any Microsoft or third-party product.

## Decision and boundary

The calibration corpus has exactly two conceptual native projects:

1. the standard Linux project, implemented separately; and
2. one future Windows project described here.

Solutions, projects, libraries, DLLs, executables, configurations, platforms, generated-source
pipelines, and scanner passes are build topology inside the Windows project. They are not additional
corpus projects and must not become corpus-specific Dagster operations.

The Windows project will run in a newly created, throwaway Windows VM. A run obtains an authorized
Windows source, installs a license-approved Visual Studio Community toolchain and the locked
supporting tools, builds and analyzes a source snapshot, exports hash-verified evidence, and destroys
the VM. It must not commit, publish, or assume permission to redistribute Windows images, Visual
Studio installers/layouts, installed-product images, license tokens, or product keys.

The first backend should be **local Hyper-V on Windows 11 Pro or Enterprise**. Hyper-V is a built-in
Windows feature, exposes a PowerShell automation surface, supports Generation 2 VMs and checkpoints,
and keeps the initial implementation within one Microsoft-supported stack. Microsoft documents the
host editions and hardware requirements, including SLAT and firmware virtualization, in
[Hyper-V system requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/host-hardware-requirements),
and documents scripted VM/checkpoint operations in
[Working with Hyper-V and Windows PowerShell](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell).

Supported backend choices should be represented behind one narrow provider interface:

| Backend | Initial status | Reason |
| --- | --- | --- |
| Hyper-V on Windows 11 Pro/Enterprise | Recommended first | Native automation, Generation 2/TPM support, and no additional hypervisor product. |
| Hyper-V on Windows Server | Later | Suitable for a dedicated runner, but host and guest licensing must be approved separately. |
| VMware Workstation/Fusion or VirtualBox | Deferred adapter | Potentially useful on non-Hyper-V hosts; vendor support, licensing, isolation controls, and automation parity require a separate review. |
| QEMU/KVM on a Linux host | Deferred research | Attractive for headless hosts, but Windows guest support, virtual TPM, drivers, image licensing, and operational support need proof. |
| Windows Sandbox | Rejected for the first backend | It is disposable, but its default network and clipboard behavior require hardening and it lacks the durable VM lifecycle, reboot, image, and evidence controls required here. Microsoft explicitly warns that networking can expose untrusted applications and mapped folders can expose the host in [Windows Sandbox configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file). |
| Azure or another hosted desktop | Out of local scope | It changes cost, data location, identity, licensing, and network assumptions. It is not a fallback without a new design review. |

## Legal, image, activation, and redistribution gates

### Windows source

The operator chooses exactly one approved acquisition route for a run:

- a Windows 11 Enterprise Evaluation ISO downloaded after registration from the
  [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise),
  only for a bounded evaluation that complies with those terms; or
- a retail, commercial-licensing, or Visual Studio-subscription image and activation path to which
  the operator is entitled.

The Evaluation Center currently describes a 90-day evaluation, prompts for activation, says no
product key is required for that evaluation, requires a Microsoft-account sign-in, and warns that an
expired or unactivated evaluation shuts down hourly. That makes evaluation media plausible for one
eventual acceptance test, not an assumed perpetual CI license. The public
[Windows 11 ISO page](https://www.microsoft.com/en-us/software-download/windows11) says its
multi-edition ISO may be used to create a VM but uses a product key to unlock the applicable edition.
Neither statement grants redistribution rights.

Before any live run, the operator must record the applicable license channel and review
[Windows 11 licensing for virtual desktops](https://www.microsoft.com/licensing/docs/documents/download/Windows%2011%20licensing%20for%20Virtual%20Desktops.pdf),
the current [Microsoft Product Terms](https://www.microsoft.com/licensing/terms/en-US/productoffering/WindowsDesktopOperatingSystem/MCA),
and the terms accompanying the chosen image. An OEM license must not be presumed to license a
throwaway VM. The automation must never inject a personal Microsoft account, Entra credentials,
product key, KMS secret, subscription token, or digital-license account into a guest. If a headless,
nonpersistent activation path cannot be documented without doing so, the run is `BLOCKED_LICENSE`.

### Visual Studio Community

Community is not simply "free for every organization." Microsoft's
[Community usage summary](https://visualstudio.microsoft.com/vs/community/) permits individuals and
certain organizational scenarios, while limiting other use in non-enterprise organizations to five
users and excluding other use in enterprise organizations. The exact selected version's controlling
terms must be saved by reference from the
[Visual Studio license directory](https://visualstudio.microsoft.com/license-terms/). The legal
approver records the organization class, use case, eligible users, product/version, terms URL, terms
hash when obtainable, decision, approver, and decision time.

If Community is not eligible, the design does not silently substitute another edition. The operator
must approve a revised, properly licensed product before implementation continues. Visual Studio
subscription accounts and tokens are host credentials and must never be automated into the guest.
Microsoft notes that Community installed from an offline layout may prompt for sign-in within 30
days but that the prompt does not affect use in
[Create an offline installation](https://learn.microsoft.com/en-us/visualstudio/install/create-an-offline-installation-of-visual-studio?view=vs-2022);
the selected version's terms still control.

### Redistribution

No Windows ISO/VHDX, prepared VM, Visual Studio bootstrapper/layout, installed tree, SDK, debugger,
CodeQL bundle, or license material is committed to Git, placed in public storage, embedded in an
evidence package, or copied to another operator. An internal content-addressed cache is allowed only
after the legal approver confirms that acquisition, caching, number of installations, users, and
retention are authorized. References in configuration are opaque artifact IDs and hashes, never the
proprietary bytes.

Microsoft's redistributable list is narrow. For example,
[Visual C++ redistribution guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170)
says distribution is limited to licensed Visual Studio users and governed by the applicable terms;
it does not authorize redistributing the IDE, compiler, SDK, or prepared VM. Evidence may include
facts and hashes about those tools, but not their binaries. Target-built artifacts are exported only
when the engagement permits it.

## Immutable acquisition and toolchain lock

Git stores a human-reviewable lock description, not proprietary payloads. A protected operator cache
stores authorized bytes by SHA-256. Each acquisition receipt records:

- artifact kind, logical name, exact version/build/edition/language/architecture;
- official source URL and acquisition timestamp;
- SHA-256 and byte length, plus Microsoft's published hash where available;
- Authenticode signer, certificate chain, timestamp, and verification result for executable content;
- license/terms URL, decision receipt ID, authorized scope, expiry, and retention deadline;
- cache object ID, access-control identity, and independent verification time; and
- any missing upstream checksum, signature, or reproducible download URL as a named provenance gap.

The Evaluation Center publishes SHA-256 verification instructions and a hash list for its ISO. A
Visual Studio layout is created on an authorized acquisition host, reduced to the selected language
and components, verified with the installer's `--verify` facility, and then hashed file-by-file into
an immutable manifest. Microsoft documents layout verification in
[Create a network-based installation](https://learn.microsoft.com/en-us/visualstudio/install/create-a-network-installation-of-visual-studio).
The client installs from that exact layout with `--noWeb`; it must not resolve moving packages during
a run. If the selected Community release has no fixed-version bootstrapper, the captured, verified
offline layout is the reproducibility unit. The lock must not claim that an evergreen bootstrapper is
reproducible.

Windows updates are treated like toolchain inputs. A baseline names every servicing-stack/cumulative
update or records the fully patched OS build and the authorized update snapshot that produced it.
Updates occur only in the trusted provisioning phase. Windows Update, Store updates, Visual Studio
updates, extension updates, package-manager updates, and symbol downloads are disabled during target
analysis. A baseline older than the configured security age is a no-go, not a reason to update
silently mid-run.

## Visual Studio installation contract

The unattended installer runs elevated only during trusted provisioning. The run uses a versioned
`.vsconfig` or an equivalent explicit component list, `--quiet --wait --norestart --noWeb`, a fixed
install path, one language, and no unsigned extensions. Microsoft documents noninteractive flags in
[command-line installation examples](https://learn.microsoft.com/en-us/visualstudio/install/command-line-parameter-examples?view=visualstudio)
and offline deployment behavior in
[Deploy Visual Studio from a layout](https://learn.microsoft.com/en-us/visualstudio/install/deploy-a-layout-onto-a-client-machine?view=visualstudio).
Installer exit codes and reboot requirements are interpreted by a typed state machine.

The baseline is full Visual Studio Community plus `Microsoft.VisualStudio.Workload.NativeDesktop`.
The lock selects exact catalog IDs for the chosen release rather than using
`--includeRecommended`, because recommended contents move. The initial desired capabilities are:

- MSBuild and Visual Studio project/solution support;
- MSVC x86/x64 compiler, linker, librarian, headers, libraries, and C/C++ code analysis;
- CMake tools and the bundled or separately locked Ninja executable;
- `clang-cl`, LLVM MSBuild integration, `clang-tidy`, and the Clang Static Analyzer checks exposed
  through clang-tidy;
- one exact Windows SDK, Universal CRT, resource/compiler tools, and supported debugging/symbol
  tools;
- the Visual C++ AddressSanitizer component; and
- `vswhere` or another Microsoft-supported inventory mechanism.

For a Visual Studio 2022 baseline, Microsoft's current
[Community component catalog](https://learn.microsoft.com/en-us/visualstudio/install/workload-component-id-vs-community?view=vs-2022)
names the native workload and components such as `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`,
`Microsoft.VisualStudio.Component.VC.CMake.Project`,
`Microsoft.VisualStudio.Component.VC.Llvm.Clang`,
`Microsoft.VisualStudio.Component.VC.Llvm.ClangToolset`,
`Microsoft.VisualStudio.Component.VC.ASAN`, and a versioned Windows SDK. These are examples, not a
floating install list: acceptance must copy IDs and package versions from the selected layout's
catalog. The installed CMake/Ninja and symbol-tool versions must be separately inventoried because a
workload label is not proof of their exact bytes. Debugging Tools for Windows and SDK acquisition are
documented under [Windows SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads)
and [Windows debugging tools](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools?view=windows-10).

Readiness captures `vswhere` instance JSON, installed component IDs/package versions, `cl /Bv`,
`clang-cl --version`, `clang-tidy --version`, `cmake --version`, `ninja --version`, `msbuild -version`,
Windows SDK directories and file versions, linker/librarian/debugger versions, and hashes of the
executables actually resolved on `PATH`. A harmless, repository-owned canary must compile and link
under every enabled compiler family before target material is attached.

## VM lifecycle and isolation

### State machine

The provider exposes explicit, idempotent transitions:

```text
authorize -> acquire -> create -> install OS -> apply locked updates
  -> install locked tools -> verify readiness -> seal provisioning state
  -> attach immutable inputs -> discover -> build/analyze -> export -> verify export
  -> revoke capabilities -> destroy -> verify cleanup
```

Each transition writes a checkpoint outside the guest with its input fingerprint, attempt ID,
timestamps, exit/status data, and next safe action. Expected Windows and installer reboots increment a
bounded reboot counter. The host waits for boot identity plus a readiness nonce, not just a listening
port. Unexpected reboot, boot-loop, readiness timeout, or state regression produces a gap and enters
cleanup. Resume never trusts a guest-written success marker without host-side evidence.

Fresh installation from the authorized ISO is the initial reproducibility model. A cached generalized
base VHDX is a later optimization only if Windows and Visual Studio terms expressly permit its
creation, storage, reuse, access pattern, and activation behavior. A checkpoint is recovery material,
not a distributable image, and is deleted with the VM.

### Network phases

Network policy is phase-specific and default-deny:

1. **Acquisition** runs on a trusted host process, not in the target VM. It may reach only approved
   Microsoft/vendor endpoints and writes the protected cache.
2. **Provisioning** prefers attached read-only, verified media. If certificate or activation traffic
   is legally required, a dedicated egress-only virtual switch permits an explicit destination set,
   records flows, denies inbound connections and RFC1918/host/production destinations, and is removed
   before target attachment.
3. **Analysis** has no default gateway, DNS, host network, corporate network, internet, Docker socket,
   named pipe, shared clipboard, enhanced session, host drive, writable shared folder, production
   endpoint, or metadata-service route. It may reach only the local evidence collector over a narrow
   isolated switch.
4. **Export** uses a one-run upload capability limited by run ID, content types, byte quota, and expiry.
   It cannot read, list, overwrite, or delete other objects.

The source snapshot, automation bundle, tool lock, and any legally approved offline tool payload are
attached as read-only virtual media and verified inside the guest before use. The target guide,
ground truth, expected findings, evaluator credentials, and evaluator repository are never present
on any attached disk, network, prompt, environment variable, or evidence-export service.

### Accounts and secrets

Provisioning uses a temporary local administrator reachable only through a host-to-guest control
channel such as PowerShell Direct. Target evaluation runs as a separate standard local account. No
host account token, SSH agent, cloud credential, Git credential, browser profile, certificate private
key, package-registry token, Microsoft account, Entra token, license token, or production secret is
copied into the guest. Environment and profile directories are scanned for forbidden secret shapes
before analysis starts.

The evidence-upload capability is random, single-use, scoped, short-lived, kept outside command lines
and central logs, revoked immediately after export, and useless outside the isolated switch. Secrets
must never persist in a base image, checkpoint, evidence bundle, crash dump, PDB, response file, or
installer log. When a tool cannot operate without a reusable secret, that capability is blocked.

### Teardown and recovery

Evidence is accepted only after the collector validates the manifest schema, object count and size
limits, every object hash, source/run identity, and terminal coverage dispositions. The provider then
stops and deletes the VM, checkpoints, differencing disks, temporary input/output media, virtual NIC,
switch/firewall rules, temporary accounts, and upload capability. It verifies that named resources
no longer exist and writes an immutable cleanup receipt with attempted actions and results.

Deletion is not described as cryptographic erasure on storage that cannot prove it. A cleanup failure
leaves the run terminal-with-gap, quarantines the residual resource, alerts the operator, and blocks a
same-identity retry until cleanup succeeds. Authorized source/tool caches are not run resources; they
follow their separate retention and entitlement policy.

## Generic `analyze_cpp_project` interface

The semantic interface is platform-neutral and reusable. Dagster may schedule its units, but no
operation may be named for this corpus, a vulnerability, or one solution/project.

Conceptual request fields:

```text
AnalyzeCppProjectRequest
  run_id, request_schema_version
  source_snapshot { artifact_ref, sha256, root }
  environment_profile { os_family, backend, image_lock, toolchain_lock }
  discovery_policy { allowed_build_systems, roots, max_files, max_graph_nodes }
  matrix_policy { configurations, platforms, compiler_families, max_cells }
  execution_policy { cpu, memory, pids, disk, per_phase_timeout, output_limits }
  network_policy, secret_policy, license_capabilities
  analyzer_policy { analyzer_ids, rule/profile locks, runtime_allowed }
  retention_policy, evidence_destination
```

The request contains typed intentions and artifact references, not a free-form shell script. Discovery
produces a reviewable `BuildPlan` of executable identities and exact argv arrays constrained by an
allowlist. Custom steps not representable by the policy are explicit gaps. Target-owned files and
model output are data; neither can widen the policy.

Conceptual result fields:

```text
AnalyzeCppProjectResult
  request_fingerprint, environment_identity, source_identity
  topology_graph, selected_matrix, build_actions
  protected_command_manifest, produced_artifact_manifest
  analyzer_shards, codeql_database_refs, symbol_manifest
  coverage_dispositions, gaps, truncations, timeouts
  export_receipt, cleanup_receipt, central_log_range
```

The application runtime remains authoritative for immutable attempts, validation, fingerprints,
publication, central logging, and accepted handoffs. A hypervisor adapter performs only typed provider
actions. Exact commands and response-file bytes are protected run evidence; the central JSONL log
contains bounded metadata, hashes, counts, durations, redacted paths, statuses, and correlation IDs.

## Topology discovery and dependency ordering

Discovery runs inside the isolated VM because even project evaluation may load target-controlled
properties and tasks. It first inventories, without building:

- `.sln`, `.slnx`, `.vcxproj`, `.vcxitems`, `.props`, `.targets`, `Directory.Build.*`, solution filters,
  CMake roots/presets, Ninja files, generated-project entrypoints, and declared custom build steps;
- every solution configuration/platform and its mapping to project configuration/platform;
- project GUID/path/type, `ProjectReference` edges, explicit solution dependencies, imported build
  logic, platform toolset, SDK, output/intermediate roots, target name/extension, and build inclusion;
- static-library, DLL, executable, utility, object-library, and generated-source roles; and
- expected outputs including `.obj`, `.lib` (distinguishing static and import libraries), `.exp`,
  `.dll`, `.exe`, `.pdb`, `.ilk`, `.map`, manifests, resources, and generated headers/sources.

For MSBuild, bounded evaluation uses properties/items queries, preprocessed project output, solution
configuration mappings, and project-graph construction. Microsoft documents `-getProperty`,
`-getItem`, `-preprocess`, `-graphBuild`, and binary logs in the
[MSBuild command-line reference](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio).
The graph records project references before dependents and preserves distinct configuration/platform
nodes. A cycle, unresolved reference, target-defined path escape, or graph-size limit is a gap or an
integrity failure according to whether trusted boundaries were violated.

For CMake, consume CMake Presets and the File API codemodel when available. Preserve generator,
toolset, architecture, configure/build preset, target dependencies, generated files, and per-config
artifacts. Ninja is preferred for transparent commands, but an existing Visual Studio generator is
honored when required. Microsoft documents both generator choices and platform selection in
[CMake Presets](https://learn.microsoft.com/en-us/cpp/build/cmake-presets-vs?view=msvc-170).

The matrix is bounded rather than blindly Cartesian. The baseline candidate is MSVC x64 Debug and
Release; clang-cl, Win32, ARM64, ASan, or project-specific named configurations are added only when
discovery proves support and the configured cell limit permits them. Every discovered but unselected
cell receives `NOT_SELECTED` with a reason. Builds follow a stable topological order within a cell;
independent cells may run concurrently subject to VM resource limits.

Generated sources are identified by comparing the immutable input manifest with post-configure and
post-build file inventories and by linking generator commands to outputs. They retain generator,
inputs, command hash, configuration, and output hash. They are never silently attributed to source
control.

## Command, binary, and symbol evidence

No single capture source is treated as complete. The plan combines and cross-checks:

- MSBuild binary log plus bounded diagnostic log and per-project evaluation/graph records;
- CMake File API, `compile_commands.json` when supported, and verbose Ninja/build output;
- allowlisted wrappers around the resolved `cl`, `clang-cl`, `link`, `lib`, `rc`, custom generator,
  and CMake/Ninja/MSBuild executables, recording exact argv and parent/action identity before exec;
- immediate content capture and hashing of every referenced response/command file before a build can
  delete or rewrite it; and
- CodeQL tracing around the exact accepted build command when CodeQL is licensed and enabled.

Absolute-path invocations or custom tools that bypass wrappers are reconciled against MSBuild/Ninja
logs and output inventories. A mismatch or incomplete capture is a named command-coverage gap, never
reconstructed heuristically from console prose.

For every compile, librarian, and link action, protected evidence keeps executable hash, exact argv,
environment allowlist/hash, working directory, parent action, start/end, exit code, stdout/stderr
object references, response files, and declared/observed inputs and outputs. Environment variables
and commands are redacted before indexing. Sensitive exact artifacts remain run-owned with stricter
access.

Produced-file evidence hashes and classifies all `.obj`, static `.lib`, import `.lib`, `.exp`, `.dll`,
`.exe`, `.pdb`, and `.map` outputs. Link evidence retains libraries searched, resolved inputs, imports,
exports, manifests, machine type, debug-directory/PDB identity, ASLR/DEP/CFG/CET and other applicable
PE flags, signing metadata, and timestamps without executing the binary. Microsoft's linker can emit
PDBs and maps, and may create import libraries for DLLs as documented in
[LINK output](https://learn.microsoft.com/en-us/cpp/build/reference/link-output?view=msvc-170).
`DUMPBIN` is the initial Microsoft-native metadata reader; its supported artifact types are described
in the [DUMPBIN reference](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-170).

Private PDBs can contain source paths and other sensitive information. They are protected evidence,
not retrieval text. A run-owned SymStore may index target PDBs by signature/age, with a transaction
receipt; nothing is uploaded to a public symbol server. Microsoft documents SymStore and related
utilities in [custom symbol stores](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-stores-and-symbol-servers).
Downloading Microsoft public symbols is off during analysis unless separately approved and
pre-cached under the network and provenance rules.

## Candidate analyzers and current gaps

| Analyzer | Planned use | Applicability and licensing gate |
| --- | --- | --- |
| MSVC `/analyze` | Per translation unit and project, fixed ruleset, SARIF/XML output, bounded paths and diagnostics. | Available capabilities and rule sets depend on the selected VS edition; Microsoft notes some native rule sets require Professional or higher. Community acceptance must inventory the exact rules that actually execute. `/analyze` logging options are documented [here](https://learn.microsoft.com/en-us/cpp/build/reference/analyze-code-analysis?view=msvc-170). |
| CodeQL C/C++ | Trace the exact accepted build, export database identity and bounded SARIF/query results. | Enabled from a separately supplied licensed local image. The active closure pins the source image, CLI, extractor, shipped license, query pack, and suite; runtime derives a minimal offline image from each accepted project build image. Database creation for compiled languages is documented by [GitHub](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages). |
| clang-tidy / Clang Static Analyzer checks | Run locked checks against captured compilation semantics under both MSVC and clang-cl where applicable. | Visual Studio supports clang-tidy for MSBuild and CMake and suggests `clang-analyzer-*` as a default family in [Microsoft's clang-tidy guidance](https://learn.microsoft.com/en-us/cpp/code-quality/clang-tidy?view=msvc-170). The selected LLVM binaries, third-party notices, check set, and output normalizer need independent license/provenance review. Standalone `scan-build` support on the selected Windows package remains an acceptance gap. |
| cppcheck | Independent, bounded source/compile-context pass; normalized findings only. | Not supplied by Microsoft or the locked VS workload. Its upstream license, binary provenance, dependencies, Windows behavior, and redistribution/caching rights require a separate approval. Until then it is `BLOCKED_TOOLING`, not silently downloaded. |
| MSVC AddressSanitizer | Build a separate instrumented matrix cell and retain runtime/symbol inputs. | Static build is permitted after component verification; execution is a later runtime capability. Microsoft documents Windows support for x86/x64 and `/fsanitize=address`, but not ThreadSanitizer, LeakSanitizer, MemorySanitizer, or UndefinedBehaviorSanitizer in [MSVC ASan](https://learn.microsoft.com/en-us/cpp/sanitizers/asan?view=msvc-170). ASan therefore does not cover data races or deadlocks. |
| Later bounded runtime tools | Approved fixture-only ASan launches, crash-dump capture, Application Verifier or debugger-assisted inspection, and purpose-built concurrency probes. | Separate threat model, tool license, privacy, and execution approval required. No target binary/test runs in the initial static-analysis acceptance. |

Every tool has a maximum input count, wall time, CPU/memory/process allowance, output bytes, diagnostic
count, and normalized-record count. Truncation preserves the original count if known, deterministic
selection rule, and `TRUNCATED` disposition. Tool absence, license uncertainty, unsupported project,
build failure, parser failure, timeout, crash, or incomplete command coverage is a gap; none means the
project is clean.

## Runtime and concurrency safety

Concurrency and deadlock samples are never run merely because they built. Runtime execution requires
an explicit capability in the request and a fixture allowlist based on source/artifact hashes. It
runs only after the build/export plane is proven, under a standard user with no network, no host
share, no secrets, and no production dependencies.

Each launch receives a Windows Job Object or equivalent whole-process-tree boundary with child
breakaway disabled, bounded process count, CPU, memory, handles, file output, and a hard wall-clock
deadline. The supervisor sends a graceful stop only when safe, then terminates the entire job, records
the timeout/deadlock gap and dump policy result, and reboots or destroys the VM if liveness is not
proven. A deadlock fixture may contend only on in-process/run-owned resources. It must not acquire
host, network, registry, service-manager, device, shared-file, production, or named global locks.

Start barriers, thread counts, schedules/seeds, heartbeat cadence, timeouts, and observed termination
are evidence. A timeout is not proof of a deadlock, and a completed run is not proof of race freedom.
No stress loop is unbounded. Initial acceptance keeps `runtime_allowed = false`.

## Fingerprints, resumability, telemetry, and gaps

The root request fingerprint binds the source snapshot, design/schema/validator versions, backend and
VM hardware profile, Windows source/update lock, installed toolchain manifest, analyzer/rules/query
locks, configuration matrix, resource/network/runtime policies, and license decision IDs. Unit
fingerprints add topology node, configuration/platform/compiler, exact accepted build action, and
upstream artifact hashes.

Reusable checkpoints are host-owned and immutable. Completed acquisition and legally approved tool
cache objects may be reused by digest. A run VM, activation state, target workspace, command capture,
analysis output, and guest checkpoint are not reused across runs. Within one interrupted run, resume
may continue only from a validated host checkpoint before target execution; otherwise it destroys
and recreates the VM while reusing already exported immutable evidence whose fingerprints still
match.

Identity evidence includes hypervisor/host version, VM Generation/firmware/Secure Boot/vTPM policy,
vCPU/RAM/disk/network settings, ISO and update hashes, OS edition/build/patch inventory, VS product
and instance ID, installed components/packages, compiler/linker/SDK/analyzer versions and hashes,
locale/time zone, and the configuration matrix. Volatile identifiers are recorded but excluded from
semantic fingerprints where they do not affect results.

Guest events are streamed or exported with run/attempt/unit IDs and monotonic local sequence. The
host validates and mirrors bounded, redacted events into the existing central run log. Important
metrics include provisioning/reboot/readiness durations, build and analyzer durations, cache hits,
resource high-water marks, produced/exported bytes, command/artifact counts, coverage disposition
counts, timeout/truncation counts, and cleanup latency. Target-controlled text is never a log field
name or status.

Framework-integrity failures stop publication: source/hash drift, path escape, manifest/schema
failure, artifact substitution, cross-run write, secret leak, evidence/cleanup receipt forgery, or
conflicting configuration. Environmental and coverage failures publish terminal gap shards so
sibling matrix cells remain usable.

## Test plan before a real VM

1. **Schema and policy unit tests:** validate locks, requests, plans, evidence manifests, cleanup
   receipts, license gates, destination/network rules, matrix bounds, redaction, and forbidden-secret
   detection.
2. **Mock provider contract:** simulate every Hyper-V transition, normal and repeated reboots,
   readiness loss, cancellation, crash, expired upload capability, partial export, teardown failure,
   and idempotent retry without creating a VM.
3. **Topology fixtures:** use neutral generated fixtures containing a solution, project references,
   static library, DLL plus import library, executable, custom generated source, multiple
   configurations/platforms, and a CMake/Ninja equivalent. Expected topology is fixture metadata
   outside the analyzed source view.
4. **Capture/normalizer tests:** synthetic binlogs, CMake File API replies, response files, compiler/
   linker/librarian commands, PDB/MAP/PE metadata, malformed/truncated output, and path escapes.
5. **Isolation tests:** prove plans cannot represent host credentials, Docker sockets, ground truth,
   arbitrary networks, production routes, writable host shares, persistent secrets, or unbounded
   target commands.
6. **Evaluator-blindness tests:** scan exported evidence and retrieval shards for answer-bearing
   paths/prose and confirm the evaluator guide is absent from inputs, guest, logs, and outputs.
7. **Genericity tests:** randomize fixture roots, solution/project names, GUIDs, configurations, and
   output paths. Reject code/configuration containing corpus case names or target-specific branches.
8. **No-VM dry run:** resolve an operator-supplied image/tool lock and produce the complete plan,
   resource estimate, legal decisions, and expected cleanup actions without acquiring or starting
   anything.
9. **One eventual live acceptance:** after every gate is approved, build only the harmless fixture
   on Hyper-V, with target execution disabled. Validate tool identity, topology, command capture,
   analyzer gaps/results, immutable export, central logging, and restart behavior.
10. **Teardown acceptance:** independently enumerate Hyper-V VMs, disks/checkpoints, switches/NICs,
    temporary accounts, capabilities, and staging paths and prove only authorized caches and accepted
    evidence remain.

No real corpus run occurs until the neutral acceptance passes. A successful acceptance authorizes
only the locked image/toolchain and policy combination that was tested.

## Prerequisites, estimates, and operator decisions

Host prerequisites for the initial backend are Windows 11 Pro/Enterprise, Hyper-V-capable firmware
and CPU, administrative authority for VM lifecycle, a dedicated local runner with no production
trust, an isolated virtual-switch/firewall capability, and protected cache/evidence storage. The
Microsoft Windows deployment lab uses 16 GiB RAM and 150 GiB free space as a minimum and recommends
32 GiB/300 GiB for its larger lab in
[the deployment-lab documentation](https://learn.microsoft.com/en-us/microsoft-365/enterprise/modern-desktop-deployment-and-management-lab?view=o365-worldwide).
This design should start with 8 vCPU, 16-32 GiB guest RAM, and at least 200 GiB free run capacity,
then replace estimates with acceptance measurements.

Planning estimates, not commitments:

| Item | Expected band |
| --- | --- |
| Windows ISO cache | 6-10 GiB per locked source |
| Selected VS/SDK/symbol-tool offline payload | 20-60 GiB; measure the exact layout |
| Fresh VM disk during a run | 80-160 GiB dynamic maximum |
| Evidence per matrix cell | 1-10 GiB; CodeQL/PDBs may push higher |
| Initial provisioning from ISO | 1-3 hours, dominated by OS/updates/VS install and reboots |
| Fixture build/static analysis | 15-90 minutes after readiness |
| Operator effort before live acceptance | 3-7 days across licensing, cache, firewall, schemas, mocks, and review |

The operator must decide and record:

1. Windows acquisition/license/activation route and whether evaluation media is limited to the one
   acceptance run.
2. Visual Studio Community eligibility, exact major/minor channel and product terms; current 2022
   versus 2026 component/servicing behavior must not be mixed.
3. Hyper-V host identity, capacity, administrative ownership, and whether it is dedicated.
4. OS update baseline, maximum baseline age, certificate/revocation strategy, and approved Microsoft
   egress destinations.
5. Authorized internal cache rights/retention and whether any generalized base image is permitted.
6. The licensed, hash-pinned local CodeQL source image and exact active asset lock.
7. Third-party approvals for LLVM-delivered tools, cppcheck, normalizers, and any later runtime tool.
8. Matrix bounds, evidence quotas/retention, private-PDB handling, and whether target-built binaries
   may leave the guest.
9. Whether any runtime execution will ever be allowed; the default and first acceptance are no.

## Go/no-go gates

Implementation may begin only through mock/unit work until gates G1-G6 pass. No real VM starts until
all gates pass.

| Gate | Go condition | No-go behavior |
| --- | --- | --- |
| G1 Windows rights | Written approval of source, VM use rights, activation path, retention, and expiry. | `BLOCKED_LICENSE`; acquire nothing. |
| G2 Community rights | Written Community eligibility for the organization/use/users and selected version. | `BLOCKED_LICENSE`; do not install or substitute. |
| G3 Immutable inputs | Authorized cache contains verified ISO, update closure, VS layout, SDK/debug tools, manifests, and terms receipts. | `BLOCKED_PROVENANCE`; no VM. |
| G4 Isolation design | Dedicated host/network review proves no host credentials, production routes, Docker socket, writable host shares, evaluator data, or persistent secrets. | `BLOCKED_ISOLATION`; mocks only. |
| G5 Provider/test readiness | Provider contract, schemas, cleanup failure injection, neutral topology fixtures, and evaluator isolation tests pass. | `BLOCKED_TESTS`; no live acceptance. |
| G6 Tool approvals | Each enabled analyzer has a pinned artifact, license/applicability decision, limits, parser, and failure disposition. | Disable that analyzer with a named gap; mandatory-tool failure blocks. |
| G7 Capacity | Host passes preflight for CPU/RAM/disk, quotas, evidence storage, and cleanup reserve. | `BLOCKED_CAPACITY`; no VM. |
| G8 Live acceptance | Neutral fixture completes export; independent teardown check finds no run resources or secrets. | Quarantine/clean up; do not run corpus. |
| G9 Corpus launch | Exact accepted locks/policies still current and target engagement permits binary/PDB evidence. | Re-accept changed inputs or remain blocked. |

## Planned implementation order

1. Approve legal/activation decisions and the two-project corpus boundary.
2. Define provider-neutral request/result, lock, topology, gap, export, and cleanup schemas.
3. Implement fake-provider state-machine, policy, fingerprint, and failure-injection tests.
4. Implement a generic Hyper-V adapter and neutral fixture path without corpus names or target logic.
5. Build the authorized acquisition/cache process and independent verifier.
6. Perform the single live neutral acceptance and teardown audit.
7. Only then connect `analyze_cpp_project` to the central job graph as generic units and plan a blind
   Windows corpus run.

No item in this order authorizes downloading Windows, installing Visual Studio, or creating a VM as
part of this documentation task.
