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
exclusive instance database remains mandatory. All application/controller/CLI descendants must
share the published persistent host cgroup; its existing 1-CPU/512-MiB cap is enforced, not enlarged.
Whether the complete installed application, broker, engine/helpers and proxy fit remains an
unproved commissioning prerequisite. Fake entrypoint integration is not actual Dagster service,
kernel enforcement, network or capacity certification.

The builder's opt-in `resource_mode = "concurrency_only"` does not relax these native
application limits. The current native operator requires application descendants in the
same capped `host_cgroup` that the builder helper proof would require uncapped in that
mode. That arrangement cannot activate concurrency-only operation without a separately
approved application/helper cgroup and lifecycle arrangement; installation alone is not
sufficient. Do not remove the application's cap, bypass either proof, or claim that this
source-level builder mode commissions the whole native Dagster deployment.

A separate daemon with private socket/data-root would avoid mutating the existing
infra image store, but it does not satisfy the current global helper proof while
another daemon remains outside the declared topology. Dedicated-daemon coexistence
is a separate unverified commissioning prerequisite, not a supported bypass.

The broker's application client now translates only the closed operation set into authenticated
run/lease/engine requests. Generic executor and build execution paths enter that scope; unsupported
operations fail rather than falling back to ambient Docker. Each execution reserves one cancellation
and one removal message beyond its normal request budget. Cleanup retries require their original
nonce, and uncertain outcomes remain journaled for reconciliation. The global helper proof admits
native `runc`/shim helpers only under the explicitly declared and capped execution subtree; another
daemon or an unrelated subtree remains rejected.

The broker requires an explicit `native_engine.client_contract_root` before serving native
clients. This pre-existing directory and its ancestors must be root-controlled and traversable
by the configured application identity; it must be outside target/run custody. After lifetime
and engine proof and private listener binding, the broker durably publishes nonsecret,
root-owned read-only `grant-0.json`, `grant-1.json`, etc., in operator grant order. Select the
exact file in the native deployment's `engine_contract`; clients never invent their own mapping.
Each file pins the actual broker PID/start token, operator run/engine identity, matching resource
budget, grant-limited mounts and unambiguous executable aliases. Restart can refresh the broker
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
