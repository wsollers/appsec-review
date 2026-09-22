# Continuation prompt — appsec-review, Phase 2 (host-owned Dagster code location), 2026-09-22

Paste this whole file as the first message of the next conversation (or reference it with
`@"Claude outputs/appsec-review-continuation-2026-09-22.md"`). It is self-contained and scoped
narrowly to Phase 2 of the step-4 plan — do not widen scope without the owner's say-so.

---

## 0. Environment — resolve this before anything else

This is a **Cowork session**, not a Claude Code CLI session on the target machine. The repo lives
on a Windows machine named `hal5000` at `F:\repos\appsec-review` (also cloned standalone at
`F:\repos\hello-autotools`), reached through the `mcp__remote-devices__*` tools once the user has
linked/connected those folders. `device_bash` runs commands, but **inside an isolated Linux VM
that is Cowork's own sandbox, not `hal5000` itself** — connected folders are bind-mounted into it
at `$HOME/mnt/<folder-name>`. Confirmed 2026-09-22: that VM is Ubuntu 22.04 (`uname -a`), has
**no `docker` binary and no `dagster` package installed**, and every `device_bash` call is a
**fresh shell with no state or background processes carried over from the last call** (see the
tool's own description).

**This is very likely a hard blocker for Phase 2 as ADR-0011 describes it.** ADR-0011 assumes a
long-running host process (`dagster api grpc -h 0.0.0.0 -p 4000 ...`) and a `docker compose up -d`
stack that stays up between commands. Neither fits "fresh ephemeral shell per call, no Docker
installed." First things to actually verify, don't assume either way:

1. Is Docker Desktop (or an engine) installed and reachable **on `hal5000` itself** — i.e. is there
   a way to run a persistent process on the real Windows/WSL host from this session (the built-in
   browser and `computer_*` tools reach the real machine's GUI/apps; `device_bash` reaches only the
   sandboxed VM)? Check `mcp__remote-devices__get_device_info` for `localMcpServers` and any signal
   of a WSL/Docker MCP; ask the owner directly if unclear.
2. If `device_bash`'s sandboxed VM is genuinely the only shell this session can reach, say so
   plainly to the owner before writing any infra code — Phase 2 either needs to run from a real
   terminal session on `hal5000` (Claude Code CLI locally, or the owner running commands by hand
   with this session giving instructions), or the design in ADR-0011 needs a variant that works
   inside a single ephemeral-shell-per-call model (much harder to make persistent).
3. Do not silently reinterpret "host" to mean the sandboxed VM and proceed — that would produce a
   code location that can't actually stay up, and nothing downstream (webserver/daemon reaching
   `host.docker.internal:4000`) would work.

## 1. What's already decided and committed — do not re-litigate

Repo: `wsollers/appsec-review`, `main`. As of this writing, `main = a664cdf`:

```text
a664cdf ADR-0011: host-owned Dagster code location
c56f381 Plan phase 4 for multi-ecosystem buildenv provisioning and cleanup
7ea68a7 Ignore fixtures/targets/: the fixture is cloned in, not committed
34dba75 Update TODO for VULN-04 and vendored-dependency SCA/SBOM expectations
2019239 Merge branch 'claude/g02-owasp-workbench-t10' into main (G02 task T10)
```

- **`docs/decisions/ADR-0011-orchestration-boundary.md`** (committed): Dagster (webserver, daemon,
  postgres) stays containerized and unchanged — it only walks the graph, holds state, retries,
  routes errors. Op *execution* moves to a host-owned `dagster api grpc` code location so B13
  (pinned-container adapter) and the Phase-4 provisioning loop get real Docker access without
  mounting the host Docker socket (or a proxy) into `code-server` — either would hand every op on
  that server container-escape-equivalent privilege, not just B13's narrow argv boundary.
  `webserver`/`daemon` reach it over `host.docker.internal:4000`. Read this file in full before
  touching any infra; it also records the rejected alternatives and why.
- `appsec-review-process/TODO.md`'s **"Decisions this plan is built on"** section (top of file) —
  the full list ADR-0011 formalizes one item of. Also has the Phase 4 (buildenv provisioning) and
  fixture-addendum (polyglot fixture) decisions from 2026-09-22 — unrelated to Phase 2, don't let
  them bleed into this scope.
- `fixtures/targets/hello-autotools/` (this repo) and `F:\repos\hello-autotools` (standalone) are
  both cloned at `e3ad863`. `fixtures/targets/` is gitignored on purpose (ADR: the fixture is
  cloned in like any real target, not committed into this repo's tree).

## 2. What Phase 2 still needs (from `TODO.md`, "Phase 2 -- ADR-0011 and the host code location")

None of this exists yet. In order:

- `orchestrator/dagster/workspace.yaml`: `grpc_server -> host.docker.internal:4000`.
- `orchestrator/dagster/compose.yaml`: add `extra_hosts: ["host.docker.internal:host-gateway"]` to
  `webserver` and `daemon`; **remove** the `code-server` service and the mounts that existed only
  to serve it (`/runs`, `/opt/process`, `/opt/schemas`, `/targets/*` — webserver/daemon need only
  `postgres` and `dagster.yaml`). Read the current file first — it's not trivial, it has a shared
  `x-runtime` anchor, named volumes, healthchecks, and native-Linux uid/gid handling
  (`APPSEC_UID`/`APPSEC_GID`) that ADR-0011's Consequences section says becomes moot for run data
  but must stay for postgres/webserver/daemon's own volumes.
- `orchestrator/dagster/code-location.sh` (+ a `.ps1` twin — the plan explicitly anticipates a
  Windows host running it under WSL, which matches `hal5000`): starts
  `dagster api grpc -h 0.0.0.0 -p 4000 -f appsec-review-process/../orchestrator/dagster/definitions.py`
  with `APPSEC_RUNS_ROOT=<repo>/appsec-review-process/runs`, a host `DAGSTER_HOME` pointing at a
  host copy of `dagster.yaml`, the repo venv, and a health check. A systemd user unit example is
  in scope per the plan, but `hal5000` is Windows — decide what the equivalent persistent-process
  mechanism is there (this is tied directly to the section 0 blocker above).
- `run_process.py --start` and `stage_artifacts.py` become host-owned; `--target` becomes a host
  path (`fixtures/targets/hello-autotools` for the fixture). Retire the "create inside the
  code-server / Linux-owned" rule from `docs/dagster/dagster-launching.md`,
  `docs/dagster/operations.md`, `orchestrator/dagster/README.md`, `00-intake-recovery/config.md` —
  keep the execution-platform check (host platform recorded in the manifest).
- Update `setup.py`, `qualify_dagster.py`, `tests/test_dagster.py`, `tests/test_phase1.py` for the
  fixtures that assume `/runs` and `/opt/process` container paths. **Read these files before
  editing them** — none were read in the session that wrote this prompt; don't assume their shape.

Files worth reading before writing anything, roughly in this order: `docs/decisions/ADR-0011-orchestration-boundary.md`,
`appsec-review-process/TODO.md` (Phase 2 section + the "Decisions" list at top),
`orchestrator/dagster/{compose.yaml,workspace.yaml,dagster.yaml,definitions.py,setup.py,README.md}`,
`docs/dagster/{dagster-launching.md,operations.md,run-data-and-job-execution.md}`,
`appsec-review-process/{launch_job.py,run_process.py,stage_artifacts.py,qualify_dagster.py}`,
`tests/test_dagster.py`, `tests/test_phase1.py`, `00-intake-recovery/config.md`.

## 3. Acceptance criteria for *this* continuation (owner's bar, 2026-09-22 — narrower than TODO.md's full Phase 2 "Done when")

The owner set a deliberately small, concrete target to prove the host-owned code location actually
works, before attempting the fuller Phase 2 qualification:

1. **Dagster starts** from the host-owned code location (webserver + daemon + postgres containers,
   code location as a host process per section 0/2 above) and the webserver **accepts jobs** (UI
   or CLI submission both count).
2. A new, trivial job named **`nop`** can be invoked. It does nothing but:
   - log something to stdout,
   - log to stderr that it is ending successfully,
   - exit 0 (success).
3. That's the bar for calling this continuation done. It is intentionally simpler than `TODO.md`'s
   full Phase 2 "Done when" (smoke job, `phase1_intake`, `engagement_workflow` all passing, a
   deliberately failed op re-executed from failure in the UI, `qualify_dagster.py` passing) — treat
   the `nop` job as proof the plumbing works, then decide with the owner whether to continue on to
   the full qualification bar in the same session or a later one.

Where `nop` goes: it's a new job, not an existing one — add it to `definitions.py` (or wherever the
existing `orchestration_smoke` job/ops are defined; read that first and follow its pattern rather
than inventing a new convention) as the smallest possible op graph. Don't wire it into
`job-graph.json`'s lifecycle graph or give it a `02-*` id — it's a plumbing smoke test, same
register as `orchestration_smoke`, not a review job.

## 4. Ground truth to re-verify at the start of the new session

```bash
# inside device_bash, $HOME/mnt/appsec-review
git log --oneline -8
git status --short
uname -a
which docker; docker version 2>&1 | head -5
which dagster; python3 -c "import dagster" 2>&1
```

Also re-check `mcp__remote-devices__get_device_info` for `connectedFolders` and any local MCP
server that might reach `hal5000` directly (not through the sandboxed VM) — this determines
whether section 0's blocker is real or already solved by a tool this prompt's author didn't know
about.

## 5. Things NOT decided here, don't invent them

- Which lifecycle worker migrates to B13 first (E01/D09/M03-M05) — separate batch, not this one.
- The Phase 4 provisioning loop's actual implementation (schema, skill file) — designed in
  conversation on 2026-09-22, committed to `TODO.md`, but no code written yet. Unrelated to Phase 2.
- Anything about the polyglot fixture (`hello-polyglot` or similar name TBD) — not started, not
  this continuation's job either.
