# Prepared native Dagster integration

This opt-in integration is not commissioned. Existing Compose deployment and its `wsl` platform
selection are unchanged. No daemon, scheduler, review, installation or active budget has been
changed while implementing it. The explicit operator entrypoint described below can start native
app processes only after separate operational authorization and prerequisite commissioning.

`deployment.example.toml` supplies explicit native paths, a non-root application UID, loopback
gRPC/web endpoints and an operator-selected existing PostgreSQL database. It does not create a
database or copy live credentials. The native instance must not share the live instance's
scheduler/storage ownership. Reachability and exclusive ownership still require commissioning.

`appsec_review.config.native_dagster` validates the closed TOML contract and renders the intended
instance, workspace, process commands and common environment. Run concurrency is one; existing
application definitions and launch gates remain the entry point. The renderer alone does not
prove child-process environment propagation, namespace identity or engine access.
Native environment markers alone still refuse application definition loading and common launch
admission. The explicit operator path must establish a matching private instance journal, live
controller generation, fresh database/service health, root-authored broker contract and capped
application cgroup. Definition loading may occur during owned startup, but run admission requires
RUNNING health and exact authorized run/target identity. Empty/unknown markers and stale ownership
refuse. Compose lifecycle/ops and Compose image-pin preflight always reject native markers.

The intended execution contract uses one native engine, common canonical context roots and the
same mount/PID/user namespaces. Docker Desktop is unsupported by the builder's kernel proof.
The root-owned private daemon socket cannot simply be exposed to UID 1000 with Docker-group
permissions. The bounded privileged operation broker is wired into the explicit native path and
validated with fake dependencies only; there is no generic Docker byte relay or socket-custody bypass. The native
guards reject unowned launches and unsupported commands; no native failure falls back to Compose.

Required build capture uses `strace` and needs the operator command's explicit
`allow_process_tree_trace = true`. It defaults to false and cannot be requested by a
client or added to the global syscall allowlist. Only that immutable command's execution
gets `ptrace`; other commands retain default denial. Before releasing the static launch
gate, kernel proof requires a separate PID namespace with the gate as its namespace init,
the exact non-root UID/GID, zero capabilities, no-new-privileges and enforced seccomp.
Host PID/network/mount namespace sharing, namespace creation/entry and cross-process VM
syscalls remain blocked. Tracing is confined to processes visible within that execution's
private PID namespace; it does not grant host tracing or `CAP_SYS_PTRACE`. The operator
must provision the pinned capture image/helper and its normal runtime syscall allowlist,
and commission actual capture plus host/foreign-process denial on the real backend.
Changing this policy changes the sealed service contract; it cannot reconfigure a live
lifetime in place. Offline policy tests do not establish that actual capture succeeded.

The privileged broker must **not** use the non-root application's editable checkout or virtual
environment. `root_entrypoint.py` is a prepared installation asset, not a command to run from
this checkout as root. An operator must install it with the complete non-editable application
and dependency closure under a root-controlled read-only release (`lib/appsec_review/...`), using
a separately trusted root-controlled interpreter. Its launch specification uses absolute paths,
Python `-I -S`, a root-controlled working directory and a fixed minimal host environment. Site
processing and editable `.pth` hooks are disabled; the release's library directory is added
explicitly. Client-requested environment is never inherited by this root process.

Metadata checks reject indirect, client-owned or writable launch paths, public configuration and
writable release mounts. They do not prove the provenance of every transitive installed file.
Installation/commissioning must establish that complete root-controlled, non-editable closure;
no per-review payload scanning or hashing is added. The initial interpreter invocation must
already be trusted and isolated: checks inside Python cannot undo an unsafe interpreter startup.
This entrypoint neither provisions anything nor replaces the pre-start persistent lifetime
reservation and kernel/cgroup checks.
Its closed `--operation` selector supports serving, pre-start lifetime reservation, admission
reconciliation and independently verified lifetime release through the same installed isolated
entrypoint. It is not an arbitrary root command or maintenance interface.
An additional closed `finalize-commissioning` operation supports the explicit engine-control
provisioning lifetime described below; it neither starts a daemon nor submits work.

The preparation helper writes a fresh private instance layout without starting processes or
overwriting an occupied, partially prepared or differently configured instance. Its child
environment checks explicit instance/configuration/profile, interpreter and checkout paths,
mount/PID/user namespaces and root identity. These checks do not replace persistent service
admission, engine-generation binding or storage/scheduler readiness.

`native_lifecycle.NativeSupervisor` supplies a process controller with durable spawn
intent, exact PID/start-token ownership, pidfd-based signaling, finite readiness/shutdown
deadlines, explicit child environment and database-scoped scheduler locking. Partial startup
retains unknown ownership instead of spawning another generation. Shutdown requires an active-run
check across all jobs and independent descendant/resource confirmation, not just absent leader
PIDs. Service output remains attached to the operator's logging sink. The registered
`appsec-review-native` entrypoint (also available as
`python -m appsec_review.orchestration.dagster.native_operator`) supports `prepare`, `run`,
`status` and guarded `stop`, with an explicit `--config`. `run` additionally requires a canonical
`--run-id` Dagster UUID and launches only `wave1_review` using the existing Dagster CLI/workspace,
code-location and common application launch gates. Its application run ID and target come from
the root-authored grant, never an inferred Git identity or ambient target setting.

The foreground controller preflights approved images through the restricted broker, holds database
ownership through startup/submission/terminal cleanup, and checks gRPC, GraphQL and PostgreSQL
readiness. CLI submission has a finite deadline while ownership health continues to be checked.
Each gRPC/web readiness endpoint must resolve through the expected live process's file descriptors
to its exact IPv4-loopback listening socket inode, before and after probing; a responsive foreign
endpoint does not qualify. The gRPC server ID is pinned for that lifetime. PostgreSQL settings
include connect, statement, lock and TCP bounds. The operator additionally installs a bounded
nonblocking libpq wait callback and per-operation deadlines, closing a stalled connection locally
instead of relying solely on a remote statement timeout or background-thread cancellation.
Lost database/service ownership marks the instance UNKNOWN and signals only the exact owned
scheduler; code-location/run children and persistent reservations are not automatically torn down.
Run admission rejects stale health. Submission intent is durable before CLI execution; uncertain
or previously occupied submission state requires explicit reconciliation, never an automatic
retry. This is a single exact-grant run path, not an automatic multi-review deployment.

A PostgreSQL advisory lock excludes only participants in this
protocol; it does not protect against an existing Compose scheduler. A separately commissioned,
exclusive instance database remains mandatory. Without an explicit application group,
application/controller/CLI descendants still share the published capped host group
(default 1 CPU/512 MiB). `native_engine.application_cgroup` instead publishes a separate
capped application subtree, at most 4 CPU/5 GiB, disjoint from control helpers, builds
and native executions. Its identity and termination join the lifetime proof. This does
not create application capacity: the operator must account it within the existing
service envelope before starting anything.

The explicit `resource_mode = "concurrency_only"` keeps one build, deadlines, cancellation,
cleanup and zero swap without builder-specific CPU/RAM caps. Shared ancestor ceilings
still apply and are reported. Optional `docker_helper_scope` pins separate root-private
Docker data/execution roots and requires those exact arguments on the socket's actual
daemon generation. Helper ancestry, owned groups and private runtime-root arguments
retain escaped/reparented helpers in custody; unrelated infrastructure is not mistaken
for this engine. Omitting that scope preserves the older global helper check. The
dedicated daemon must not share the existing socket, data-root, exec-root or image store.
Source support is not a commissioned daemon.
Native topology checks use server cgroup/OS/kernel/label fields, not the CLI's
`ClientInfo` plugin inventory or a workstation hostname. A stale local Desktop plugin
does not identify the daemon. Docker Desktop server markers still refuse, and actual
kernel socket-peer, namespace, root, generation and helper-custody proofs remain required.
The pinned Skopeo transport must negotiate the daemon's supported API. Ubuntu 22.04's
Skopeo 1.4.1 hardcodes API 1.22 and cannot talk to Docker 29.1.3's minimum API 1.44;
a command-local `DOCKER_API_VERSION` does not repair that hardcode. Provision a compatible
pinned private transport rather than lowering the daemon's API requirement.
Docker 29 may automatically use the existing `/run/containerd/containerd.sock` even with
separate Docker roots. A dedicated-engine scope therefore also requires an explicit
`docker_helper_scope.containerd_endpoint` beneath its private exec-root and the actual
daemon's matching `--containerd` argument. Kernel proof authenticates that Unix peer,
its root UID, same-host namespaces, control cgroup and stable generation, and requires
the helper's explicit `--root DATA_ROOT/containerd`, `--state EXEC_ROOT/containerd` and
`--address ENDPOINT` arguments. Private Docker arguments or an empty container list alone
do not establish a separate containerd image store. Existing infrastructure containerd
must never be adopted, reconfigured or stopped for this arrangement.

The opt-in `lifetime_domain = "engine"` additionally requires a typed `engine_domain`
with a private root-controlled metadata directory, exact existing shared cgroup ceiling
(at most 2 CPU/2 GiB), and explicit disjoint baseline engine groups. Both the existing
engine consumers and dedicated control lifetime have real persistent reservations in
that one ledger. Defaults allocate the baseline 1 CPU/1536 MiB and dedicated control
1 CPU/512 MiB; these are admission charges, not new per-builder caps or guaranteed
working-set maxima. Kernel inventory rejects non-engine/unknown consumers and memory
headroom violations; only clean inactive file cache is excluded from observed working
sets, never dirty/writeback pages or slab. Actual observations accompany host receipts.
No application, scanner or build execution may be relabeled as engine overhead.

In this explicit mode the real action ledger retains its full 8 CPU/10 GiB budget:
one build reserves that whole action envelope, and a later 8-CPU action can be admitted
while the separate control lifetime remains counted. This intentionally replaces
retire-before-CodeQL in the older action-domain arrangement. It never migrates a live
lease. Actual shutdown still requires the service lock, all owned app/control/worker
generations and scopes stopped, no daemon listener, clean journal and retired engine
ownership before releasing only the dedicated lifetime. The baseline engine reservation
remains. Bounded/default action-domain policy is unchanged.

An operator cannot know a daemon's future PID/start token, or future network/container IDs,
before starting it. For commissioning, set `engine_domain.control_lifetime_id` to the exact
admission lease UUID and initially select `lifecycle_stage = "provisioning"`. This requires
the explicit concurrency-only engine domain, no native clients or package network, and empty
owned scopes. `reserve-lifetime` creates a real continuously counted engine-control lease
before any daemon/proxy starts. Its immutable binding fixes control custody, releases,
kernel groups, resource budgets and lease identity, independently of subsequently observed
client/image/network identities. No lease is transferred, rebound or temporarily removed.
Repeated reservation records additional exact owned process generations for recovery.
The `PROVISIONING` fence refuses normal service/client admission.

After acquiring the actual immutable assets, select `lifecycle_stage = "configured"` in
the final private operator configuration and invoke `finalize-commissioning`. Under both
operator locks it verifies the same existing counted engine lease and original cgroup
identities, an unused work/interlock journal, empty application/action scopes, real daemon
custody, dedicated container inventory and egress isolation. A native configuration also
requires the real pinned daemon generation and engine ID. Only then is the complete final
service contract sealed and the fence advanced to `RESERVED`. Failure retains both leases
and the provisional fence. Repeating finalization with exactly that sealed contract is
idempotent; another policy or generation requires actual retirement, never refinalization.
Without an explicit control lifetime, the existing stopped-first, fully configured lifecycle
and persistent bindings are unchanged.

A failed provisional installation also requires actual retirement before releasing its
control lease. Independent process inventory still detects escaped/reparented helpers by
their dedicated roots, even when owned cgroups and the Unix listener are already absent.
The existing engine baseline stays reserved after that release. Acquisition/install receipts,
empty fake scopes and offline tests do not substitute for the real commissioning proofs.

Commissioning remains unverified. In particular, if existing services already reserve
the whole 6-CPU/8-GiB service envelope, a new native application cannot be started
alongside them merely because they are idle. A separately authorized controlled
transition or genuinely available service capacity is required; do not overbook,
increase a ceiling, or move application costs into the engine/action domains.

The broker's application client now translates only the closed operation set into authenticated
run/lease/engine requests. Generic executor and build execution paths enter that scope; unsupported
operations fail rather than falling back to ambient Docker. Each execution reserves one cancellation
and one removal message beyond its normal request budget. Cleanup retries require their original
nonce, and uncertain outcomes remain journaled for reconciliation. The global helper proof admits
native `runc`/shim helpers only under the explicitly declared and capped execution subtree; another
daemon remains rejected without the explicit dedicated-engine scope described above.
An owned helper in an unrelated subtree remains rejected in either mode.

The broker requires an explicit `native_engine.client_contract_root` before serving native
clients. This pre-existing directory and its ancestors must be root-controlled and traversable
by the configured application identity; it must be outside target/run custody. After lifetime
and engine proof and private listener binding, the broker durably publishes nonsecret,
root-owned read-only `grant-0.json`, `grant-1.json`, etc., in operator grant order. Select the
exact file in the native deployment's `engine_contract`; clients never invent their own mapping.
Each file pins the actual broker PID/start token, operator run/engine identity, matching resource
budget, grant-limited mounts, broker mount/PID/user namespace identities and unambiguous
executable aliases. The non-root client compares its own namespace identities to this
root-published declaration after authenticating the actual root socket peer PID/start token;
it need not read root-only procfs namespace links. The broker still independently checks
the application peer's real namespaces. Unreadable procfs is never silently accepted.
Restart can refresh the broker
process identity, but changing policy at an occupied publication path requires reconciliation.
Stale clients reject a restarted peer. Neither private socket, the broker release/journal nor an
ancestor containing those paths may be exposed through any worker mount, including read-only
platform mounts. Contract publication alone does not satisfy the native lifecycle and health gates.

Native CodeQL uses private run-owned bind directories for its disposable database and declared
release compile cache. It retains staged database export and query-input behavior without the
legacy Docker-volume/root-`chown` helper. Disposable directories are removed only after container
removal is confirmed; uncertainty retains both reservation and scratch. The operation translator
rejects volume management, image building/tagging, host namespaces and arbitrary Docker options.
Derived-image staging remains the bounded builder's responsibility.

Native cleanup requires container **removal**, not just stopped state. The opt-in resource
admission mode persists that requirement in ordinary leases. Even a successful remove command
must be followed by exact container-absence evidence. Unknown cleanup retains its reservation;
reconciliation cannot substitute stopped-only evidence. The explicit native entrypoint uses this
mode; existing Compose cleanup behavior is unchanged.

If a native create was rejected before intent publication, its uncertain client reservation stays
fenced while the engine is live. Operator admission reconciliation can recover that exact native
scope only after normal lifetime release has proved empty execution/application/helper cgroups,
dead generations and no daemon listener. It additionally requires a dedicated, private Docker
container-metadata directory with no entries, no retained engine owner or unresolved execution,
a dead client generation, and exact run/configuration/engine/budget binding. A stopped container,
a missing journal alone, or a foreign scope cannot release capacity. Existing intents still require
their ordinary independently confirmed removal records; no removal receipt is fabricated.

If the recovery fix is in a newer installed release, use its isolated root entrypoint with
`--config <current-runtime.toml> --operation reconcile-retired-admission
--prior-config <retired-lifetime.toml>`. The current configuration declares the new installed
`runtime_root` and `runtime_release_id`; every other host, policy, budget and admission field
must equal the unchanged prior configuration. The new operator's runtime is verified normally,
then reconciliation uses the prior configuration and its original frozen contract. The prior
lifetime must already be `RELEASED`, its service lock must be free, and the full independent
retirement/removal proof still applies. This operation cannot serve, restart, or rebind a lifetime.

For a prior lifetime with an uncertain create but no launched process, the corresponding
`release-prior-lifetime` operation uses the same two-configuration boundary and ordinary exclusive
lifetime release. Only after all recorded generations and execution/application/helper scopes
are proved stopped can a private, entirely empty Docker container-metadata directory settle that
one exact prelaunch intent and its matching ownership fence. A live client, launched process,
rebound cgroup, foreign owner or any stopped container retains the reservation. The genuine
absence observation and original failure are preserved in the operator journal; an empty cgroup
may remain as audit state. Normal admission reconciliation then accepts the exact client
`native_broker_outcome_unknown` quarantine only with independently confirmed removal evidence.

Rootless-worker inspection accepts Docker's equivalent `SETUID`/`SETGID` and
`CAP_SETUID`/`CAP_SETGID` spellings only as the same exact pair. The kernel capability bounding
set, zero effective capabilities and all remaining isolation checks are unchanged.

Native execution uses Docker's default private PID namespace rather than the unsupported
`--pid private` argument; inspect and kernel namespace proofs remain mandatory. The private
control root stays mode0700 while its read-only bind-mounted gate directory is explicitly0755
and the executable0555, including when the root service runs under umask077.

The Docker CLI inlines the compacted seccomp profile content into `HostConfig.SecurityOpt`,
so inspection compares that inlined JSON canonically with the broker-written profile and rejects
the path form, `unconfined`, any profile difference and any additional security option.

When an inspection or removal fix is in a newer installed release, a stopped broker's retained
intents are reconciled with `--operation reconcile-prior-engine --prior-config <prior.toml>`.
It uses the same two-configuration equivalence as `release-prior-lifetime`, takes the prior
service's exclusive lock (so the prior broker must be stopped), requires its `RESERVED` lifetime,
the host and engine identity checks, and then performs only the ordinary restart reconciliation
under the prior frozen contract. It never serves, publishes contracts, releases the lifetime or
rebinds a lease; unconfirmed removals remain quarantined.

Fake integration drives the registered operator through supervisor, simulated Dagster child,
common launch, default executor and restricted broker to confirmed owned-container cleanup.
A separate shared-journal/lease sequence covers builder -> derived-image tool -> removal -> next
builder, including rejection while an EXITED or uncertain tool retains engine ownership.
These fixtures inject process, database, socket, service and engine boundaries; they do not start
real Dagster services or commission a privileged installation.

The default resource contract remains 8 CPU, 10240 MiB, one I/O slot and 512 MiB staging.
The separately approved preparation target is 9 CPU, 12288 MiB and one I/O slot, with staging
unchanged. It is not activated here. The service's persistent 1 CPU/512 MiB reservation plus an
8 CPU/9728 MiB compiled action cannot fit the default CPU budget. Per-action production limits,
reasoning configuration and all-packages semantics must not be reduced to fit.
`budget.example.toml` contains matching fragments for separate operator-owned review and service
configurations, not a runnable application configuration. The service budget is pinned into
lifetime leases, its journal and client exchange. CPU, memory, I/O and staging must match;
changing only the client policy does not upgrade old service leases. Incompatible or legacy
bindings remain reserved until explicit, independently verified reconciliation.

Real worker/tool availability, native cgroup enforcement, root daemon/helper accounting, private
UID access, approved egress, stopped-container cleanup and storage/scheduler ownership remain
commissioning prerequisites. Observed host capacity is not a dedicated reservation. Fake tests
and prepared configuration do not establish those operational properties.

## Integration and acceptance tests

`tests/integration/test_native_broker_mounts.py` (run-root subdirectory bind mount; broker
rejection of a `,` subpath and of a symlinked subpath) and `tests/acceptance/test_native_tiny_build.py`
(the frozen `tiny-build` command compiles and runs `hello.c` under strace process-tree capture)
drive a real commissioned broker through the public `NativeClient`. They never commission, start
or reconfigure anything, and skip with the unmet precondition named unless:

- `APPSEC_NATIVE_INTEGRATION=1` (integration) or `APPSEC_NATIVE_ACCEPTANCE=1` (acceptance) is set;
- the published contract (`APPSEC_NATIVE_CLIENT_CONTRACT`, default
  `/run/appsec-review-f370/client-v9/contracts/grant-0.json`) loads and its `native.sock` exists;
- the process runs as the contract's uid/gid (1000) inside its host cgroup, i.e. the
  `appsecreview-services-appsecf370.slice`;
- the worktree's client modules equal the installed release copies (`APPSEC_NATIVE_RELEASE`,
  default `/opt/appsec-review/releases/a78696b8-native19`);
- for acceptance, `build-driver.sh`, `capture/` and `wrappers/` are staged in the granted run root.

Root launches them as uid 1000 in the services slice (only while no Dagster run is nonterminal):

```
systemd-run --wait --pipe --collect --slice=appsecreview-services-appsecf370.slice \
  --property=User=wsollers --property=Group=wsollers --property=MemorySwapMax=0 \
  --property=WorkingDirectory=/home/wsollers/projects/appsec-review-native-broker \
  --setenv=APPSEC_NATIVE_INTEGRATION=1 --setenv=APPSEC_NATIVE_ACCEPTANCE=1 -- \
  /home/wsollers/projects/appsec-review-native-broker/.venv/bin/python -m pytest -q -p no:cacheprovider -rs --basetemp=test/tmp/native-live \
  tests/integration/test_native_broker_mounts.py tests/acceptance/test_native_tiny_build.py
```
