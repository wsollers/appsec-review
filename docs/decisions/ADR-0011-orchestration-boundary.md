# ADR-0011: Host-Owned Dagster Code Location (Orchestration Boundary)

Status: Accepted 2026-09-22

## Context

The current stack (`orchestrator/dagster/compose.yaml`) runs op execution inside a `code-server`
container: `dagster code-server start -f /opt/app/definitions.py`, reached by `webserver`/`daemon`
over `grpc_server: host: code-server, port: 4000`. That was the right shape for the jobs qualified
so far -- read-only bind mounts, no host Docker socket, no host credentials (`orchestrator/dagster/README.md`).

Two things this repo has since decided break that shape:

- **B13** (`docs/adapters/pinned-container-adapter.md`) is the one piece of code allowed to compose
  `docker run`, against a registry-pinned, digest-resolved image, `--network none`, `--pull never`.
  For B13 to run at all, whatever process calls it needs real Docker access.
- **Phase 4** (`appsec-review-process/TODO.md`) adds an LLM-driven provisioning loop that runs
  `docker build` and installs packages over the network to hydrate a buildenv image -- an operation
  B13 deliberately cannot perform (no network, no pull, pinned image only) and was never meant to.

Both need host Docker reachable from wherever the op actually executes. A `code-server` container
gets there one of two ways: the host Docker socket bind-mounted in, or a socket proxy in front of
it. Both hand every op that runs inside `code-server` -- not just B13's narrow argv boundary --
the ability to launch, and by extension escape into, sibling containers on the host. That
contradicts the pinned-container adapter's entire reason for existing: a fixed, narrow, audited
path to Docker, not an ambient one available to anything scheduled onto that server.

## Decision

Dagster's orchestration layer -- webserver, daemon, postgres -- stays exactly what it is today: it
walks the process graph, holds state, retries and routes errors. It never itself references,
pulls, builds or runs an image; nothing here changes that.

What moves is where op **execution** happens. The code location that ops actually run inside comes
out of the `code-server` container and onto the host: `dagster api grpc` runs as a host process
(`orchestrator/dagster/code-location.sh`, with a `.ps1` twin for a Windows host that runs it under
WSL), ops execute as host processes with the host's own Docker, and B13 composes `docker run`
directly against that Docker -- never through a mounted socket, never through a proxy. `webserver`
and `daemon` stay containerized and reach the host code location over
`host.docker.internal:4000` (`workspace.yaml`; `compose.yaml` gets `extra_hosts:
["host.docker.internal:host-gateway"]` on both services). `compose.yaml` keeps only `postgres`,
`webserver` and `daemon`; the `code-server` service and the mounts that existed only to serve it
(`/runs`, `/opt/process`, `/opt/schemas`, `/targets/*`) are removed.

Runs become host-owned as a consequence: `run_process.py --start` and `stage_artifacts.py` run on
the host, and `--target` is a host path (`fixtures/targets/hello-autotools` for the fixture, a real
clone path for an engagement). The execution-platform check stays -- host platform is still
recorded in the manifest -- but the "create inside the code-server / Linux-owned" rule is retired
from `docs/dagster/dagster-launching.md`, `docs/dagster/operations.md`,
`orchestrator/dagster/README.md` and `00-intake-recovery/config.md`.

## Alternatives considered

Engine-boundary criteria used below: fork/join, pools, human gates, loops, external waits, UI.

| Alternative | Rejected because |
|---|---|
| Docker socket mounted into `code-server` | Grants every op scheduled onto that container container-escape-equivalent host privilege, not just B13's narrow argv boundary. Defeats the reason B13 exists: a fixed, pinned, audited path to Docker becomes an ambient one. |
| Socket proxy in front of `code-server` (e.g. a `docker-socket-proxy`-style guard) | Narrows the API surface but is still a privilege-delegation layer sitting in front of a socket that has to reach host Docker; it's a second component to build, qualify and keep in sync with B13's own boundary, for a containment guarantee B13 already provides on its own once it runs on the host directly. It also doesn't solve Phase 4's need for `docker build` (image creation) -- exposing that through a proxy profile safely is a harder problem than the one being solved. |
| Custom host executor -- a small always-on host daemon that `code-server` RPCs into for container/build work | Reinvents what `dagster api grpc` already is (a host-reachable execution surface) behind a bespoke protocol that then needs its own auth, failure semantics and qualification, for no benefit over running the code location on the host directly. |
| Switch orchestration engines | Dagster already provides fork/join (parallel ops), pools (B15), human gates (the G01-G03 pattern), loops (retry/reuse), external waits (sensors) and a UI, and is qualified against real usage (Batch 8 checkpoint, B09-B11). The container-vs-host execution boundary is not a Dagster limitation -- every alternative engine faces the identical "who is allowed to touch Docker" question -- so switching discards a working, qualified stack to re-solve a problem that has nothing to do with which engine is in use. |

## Consequences

- `orchestrator/dagster/workspace.yaml`, `compose.yaml`: updated per Decision (see Phase 2 in
  `appsec-review-process/TODO.md`).
- `orchestrator/dagster/code-location.sh` (+ `.ps1`): new. Starts the host gRPC server with
  `APPSEC_RUNS_ROOT=<repo>/appsec-review-process/runs`, a host `DAGSTER_HOME`/`dagster.yaml`
  copy, the repo venv, and a health check; a systemd user unit example is included for a
  persistent native-Linux host.
- `setup.py`, `qualify_dagster.py`, `tests/test_dagster.py`, `tests/test_phase1.py`: updated for
  the fixtures that assumed `/runs` and `/opt/process` container paths.
- B13 (`container_execution.py`) can now be wired into a real lifecycle worker (E01, D09, M03-M05)
  for the first time, since a caller with real host Docker access exists. That migration is its
  own separately qualified batch, not part of this ADR.
- Phase 4's provisioning loop runs as a host process for the same reason B13 does, and inherits the
  same "network only during provisioning, never during a pinned B13 run" split already recorded in
  `TODO.md`'s Phase 4 decisions.
- Native-Linux uid/gid handling (`APPSEC_UID`/`APPSEC_GID` in `setup.py`, `README.md`'s "Native
  Linux host" section) becomes moot for run data, since `run_process.py`/`stage_artifacts.py` now
  write as the host user directly rather than through a bind mount from a container; it is kept
  for `postgres`/`webserver`/`daemon`'s own volumes, which are unaffected by this ADR.
- Done when (Phase 2, `TODO.md`): smoke job, `phase1_intake` and `engagement_workflow` pass on the
  fixture from the host code location; a deliberately failed op is re-executed from failure in the
  UI and skips the successful ops; `qualify_dagster.py` passes. This closes the previously-open
  "B13 build execution" question by making a real Docker-reachable caller exist at all.

## Addendum 2026-09-22: host networking, verified on a Windows host (Docker Desktop + WSL 2 NAT)

The Decision above assumed `host.docker.internal` -> `host-gateway` reaches the host code location
everywhere. On `hal5000` (Docker Desktop, WSL 2 `nat` networking, code location running in the WSL
distro) it does not:

| Path from `webserver` | Result |
|---|---|
| `host-gateway` IPv4 (`192.168.65.254`, the Windows host) | refused -- WSL does not forward the port to Windows, with the server bound to `127.0.0.1` or `0.0.0.0` (`Test-NetConnection 127.0.0.1 -Port 4000` also fails) |
| `host-gateway` IPv6 (`fdc4:f303:9324::254`) | no route; harmless, the gRPC client falls back to IPv4 |
| the WSL distro's own `eth0` IP | reachable -- Docker Desktop runs in the same WSL VM |

So `compose.yaml` maps `host.docker.internal` to `${APPSEC_CODE_LOCATION_HOST:-host-gateway}`, and
`code-location.sh`, under WSL NAT, binds to the distro IP and keeps that key in `.env` current (the IP
changes on every WSL restart; the script prints the `up -d webserver daemon` recreate command when it
does). Elsewhere the bind stays `0.0.0.0` and the mapping stays `host-gateway`.

With that in place the plumbing bar was met the same day: webserver, daemon and postgres
containerized; `dagster api grpc` as a WSL host process; the `nop` job submitted from both the UI and
`dagster job launch`, dequeued by the daemon, and executed by a run worker on the host (host pid in
the run log). The fuller Phase 2 "Done when" in Consequences is still open.

**Exposure of the code-location port.** The code-location gRPC endpoint is unauthenticated, and anything that can
reach it can launch runs of the defined jobs as the host user, with host Docker -- the very privilege
this ADR keeps out of containers. Scope of each bind:

- WSL NAT, bound to the distro IP (the default there): the WSL VM (its containers and distros) and the
  Windows host via the NAT; not the LAN. Accepted for a development host.
- `0.0.0.0` on a native Linux host (the default there): every interface, LAN included, unless
  firewalled. Not accepted as-is for anything but a single-user development host; the follow-up is
  to bind to the Docker bridge gateway instead (the address `host-gateway` resolves to) -- tracked in
  Phase 2, not decided here.
- WSL `mirrored` networking was not needed and is not recommended here: it would place the port on
  the Windows host's real interfaces.

## Amendment 2026-09-23: `dagster code-server start` instead of `dagster api grpc`

The Decision names `dagster api grpc` as the host process. `code-location.sh` now runs `dagster
code-server start` with the same host, port, file, working directory and location name. Both serve
the same gRPC API on port 4000, and runs are still launched by the host server as host processes; the
difference is that `code-server start` keeps a stable endpoint and swaps a child server underneath on
reload, so `code-location.sh reload` (the webserver's `reloadRepositoryLocation`) re-imports changed
`definitions.py` without restarting the process. `api grpc` cannot reload in place and logged
"Reloading definitions ... not currently supported". Nothing else in this ADR changes: the endpoint,
its exposure (below) and the webserver/daemon wiring are the same. This is also what the retired
`code-server` container ran.

## Non-decisions

This ADR does not decide: which lifecycle worker migrates to B13 first (a separate batch per
worker), the shape of the Phase 4 provisioning loop itself (its own design surface, tracked in
`TODO.md`), or anything about `02-*` job semantics. It only decides where op execution physically
runs and why the alternatives that would have kept it in the `code-server` container were rejected.
