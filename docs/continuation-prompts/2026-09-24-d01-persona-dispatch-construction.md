# Continuation prompt — D01 unpooled persona dispatch construction (2026-09-24)

**STATUS: DONE, 2026-09-24.** D01 (unpooled) closed the same day this prompt was written, with a
clean live `--dispatch` SAT PASS on hal5000 against a real `claude` CLI call (SAT run
`20260924T214618Z`, Dagster run `7e2fc40f-9e22-4c03-8cdc-ab488ac2219c`, commit `51f01d3`). Five
live-dispatch failures were found and fixed in turn along the way; the transferable lessons from
that sequence are in `docs/lessons-learned-2026-09-24-d01-live-dispatch.md`, and the full
blow-by-blow is in `appsec-review-process/TODO.md` Phase 5b item 8. **D02-D04 are next** (see
section 6 below and the lessons doc's closing section) — this prompt's sections 0-5 remain useful
background for that work since the facilities they describe are reused unchanged; only section 6's
"before you start" question is now moot (the model choice was confirmed and is live-proven).

Paste this whole file as the first message of a new conversation. It is self-contained. Use this
prompt for **construction and live testing** of D01 (below). A separate, ongoing conversation is
doing higher-level architecture/sequencing for the rest of the SAT backlog — don't duplicate that
work here; this prompt is scoped to one piece.

---

## 0. First, establish ground truth — do not trust this file blindly

This repo is `wsollers/appsec-review` on GitHub. You (the agent reading this) most likely run in an
ephemeral cloud sandbox with a git clone of the repo, linked via a device bridge to William's
Windows machine `hal5000`, which has the repo checked out at `F:\repos\appsec-review` and a WSL
Ubuntu-24.04 distro at `~/projects/appsec-review` where Docker/Dagster actually run. Confirm your
own setup matches before assuming any of the mechanics below — if you're running somewhere else
(e.g. directly on hal5000, or in a different sandbox shape), the git/patch mechanics in section 3
won't apply as written; adapt them, don't skip the substance.

```bash
git -C <your clone> log --oneline -5
git -C <your clone> status --short
```

Then read, in order: `AGENTS.md`, `appsec-review-process/TODO.md` (the whole "CURRENT WORK MODE:
system acceptance test" section, and **Phase 5b** specifically — that section is the authoritative,
detailed spec for this task; this prompt summarizes it but TODO.md wins on any conflict),
`docs/processes/system-acceptance-test.md`, `docs/processes/engagement-start.md`,
`docs/processes/flow-bringup.md` (at least its Log section, newest entries first),
`appsec-review-process/persona_invocation.py` (read the whole file — it's the protocol you're
building against), `appsec-review-process/worker_adapters.py`, `appsec-review-process/
discovery_gate.py`, `appsec-review-process/review_cli.py` (specifically `build_claude_argv`,
`_dispatch_streaming`, `resolve_model`, `lane_tools`), `registry/AUTHORING-TEMPLATE.md`.

## 1. What this is and why it exists

The SAT (system acceptance test) proves the appsec-review pipeline end to end on a tiny fixture
(`hello-autotools`). Stages 6-9 (the discovery gates: repository partition map, developer, devops
and SRE operations-topology discovery) currently pass by **hand-authoring the fixture's answer
file** and handing it to a gate that only validates schema/citations/claim-class rules. That's a
test of the JSON schema, not of the system's ability to discover anything. William's correction,
2026-09-24: **every job in the flow must actually be invoked and verified**, not stood in for. If a
capability doesn't exist yet, that's a gap — build the missing facility, document it, add it to the
flow, and start on the piece that depends on it. Don't declare a stage done by supplying its answer.

**D01** (from the batch backlog table in `TODO.md`) is: give `02-repository-partition-discovery` a
real, automatic dispatch mode that reads the target and produces its own discovery record via a
model call, while keeping the existing supplied-record path as an explicit, separately-tested
alternative (not the SAT's proof path). This prompt is scoped to **D01 only, unpooled** — see the
scope note in TODO.md Phase 5b for exactly why "unpooled" is a deliberate, stated decision and not
a corner cut: it's one target, one partition-discovery call, no concurrent fan-out, so it does not
need the pool/rendezvous/merge machinery (C01-C03) that a full multi-partition review would.

D02 (`02-dev-project-discovery`), D03 (`02-devops-project-discovery`) and D04
(`02-sre-operations-topology`) are the same shape and follow once D01 is proven live — see the tail
of TODO.md's Phase 5b section for exactly what differs for those three (mainly: they need new
`task_prompt` files authored; D01 does not).

## 2. What already exists — do not recreate

Checked 2026-09-24, should still be true (re-verify, don't just trust this):

- The full registry composition for D01 already exists and validates: job template
  `registry/job-templates/02-repository-partition-discovery.json` names persona
  `developer-engineer`, role `repository-partition-mapper`, domain `repository-partitioning`,
  tooling profile `static-repo-project-inspector`, output contract `repository-partition-map`. All
  five records exist under `appsec-review-process/registry/`.
- The task prompt for D01 already exists:
  `appsec-review-process/02-evidence-pregather/repository-partition-discovery.md`. No new authoring
  needed here.
- The buildenv catalog the `buildenv_catalog` prompt section renders already exists:
  `appsec-review-process/tooling/buildenv-catalog.json`.
- `appsec-review-process/persona_invocation.py` (batch B14, marked Done) is a complete, tested
  dispatch *protocol*: request validation, registry composition resolution, claim-class ceiling
  enforcement, budget/citation/independence checks, a closed `PersonaInvoker` Protocol and
  `PersonaRuntime` dataclass. By its own docstring it has **no model client and no network** — that
  is deliberately the integrator's job. Read it fully before writing anything that calls it;
  `resolve_request`, `validate_runtime`, the `InvocationPackage`/`PersonaRuntime`/`PersonaInvoker`
  definitions, and `run_invocation` are the contract surface you're building against.
- `appsec-review-process/review_cli.py` already has a live, previously-debugged `claude -p`
  dispatch path (`build_claude_argv`, `_dispatch_streaming`, `resolve_model`) proven against real
  subscription auth on hal5000 (see its own git history for the real-dispatch bugs already found
  and fixed there — don't repeat that debugging from scratch). Reuse this, adapted, as the basis
  for the new `PersonaInvoker` implementation — do not write a fresh `claude -p` integration from
  nothing.
- `model-config.json` already has a sane default (`claude-sonnet-5`, effort `medium`) and no
  lane override for `02-repository-partition-discovery`, so the default applies. Flag this to
  William for confirmation before spending a live run on it rather than silently assuming it's
  right — it's a judgment call (routing), not a hard technical requirement.

## 3. What's missing — build these, in this order

Full detail (exact file paths, function contracts, what each renders) is in
`appsec-review-process/TODO.md` under **"### Phase 5b -- D01: automatic persona dispatch for
repository-partition-discovery (unpooled)"**. Summary, in dependency order:

1. **`governing_rules` prompt fragment** — new file,
   `appsec-review-process/registry/prompt-fragments/governing-rules.md` (new directory). Distills
   AGENTS.md's two rules and AUTHORING-TEMPLATE.md's evidence/trust-boundary section into an
   instruction aimed at the persona, not a human contributor. Reusable by every future job template
   that lists `governing_rules` in `prompt_sections` — author once.
2. **Prompt assembler** — new module `appsec-review-process/persona_prompt_assembly.py`. Given a
   `job_template_id`, resolves `prompt_sections` order, renders each section (registry record JSON,
   or the new governing-rules fragment, or the job template's `task_prompt` file's literal bytes),
   concatenates, writes the result under the attempt's scratch dir, returns `{path, sha256, bytes}`
   for `persona_invocation`'s required `outer_prompt`.
3. **Request builder** — new code (new module preferred:
   `appsec-review-process/persona_dispatch.py`, called from `discovery_gate.py` — see TODO.md
   Phase 5b item 3 for the reasoning) that assembles the full
   `appsec-review/persona-invocation-request/1.0` object: composition ids, model/effort, tools
   (`persona_invocation.tool_ids`), claim-class ceiling (`persona_invocation.claim_ceiling` —
   already exists, just call it), the outer_prompt from step 2, a `readable_inputs` manifest over
   the fixture checkout (respecting the tooling profile's read boundary), and a real B11
   `permission_capabilities` decision for `read-source`.
4. **`PersonaInvoker` implementation** — new file `appsec-review-process/claude_cli_invoker.py`.
   Implements B14's `PersonaInvoker` protocol (`invoker_id`, `invoke(package, *, output_root,
   cancel)`), adapting `review_cli.py`'s proven dispatch code: materialize the package's prompt and
   input bytes into a private scratch dir, build a scoped `claude -p` invocation
   (`--add-dir` limited to that scratch dir and `output_root`, `--allowedTools` from
   `package.tool_actions`), run it with `cancel` polled, write `invoker-output.json` (matching
   `schemas/persona-invoker-output.schema.json`) plus declared output files under `output_root`.
5. **Dagster lifecycle wiring** — extend `discovery_gate.py` with an automatic-dispatch execution
   path for `02-repository-partition-discovery` that builds a `PersonaRuntime` (invoker = step 4),
   calls `PersonaInvocationAdapter.execute()`, and publishes through the *existing*
   `coordinate_worker_lifecycle`/`record_terminal_current`/`validate_published` common-envelope
   boundary — the same one this job already uses (`ADOPTED_JOB`). No new publication plumbing.
   Supplied mode stays wired as an explicit, separately-tested alternative.
6. **SAT script change** — `scripts/system-acceptance-test.sh`'s stage 6
   (`stage_partition_discovery`) gets a dispatch mode; its `accept` checks move from "byte-equals
   the fixture" to "validates + citations fresh against the live checkout + structural rules pass."
   Comparing to the fixture becomes an informational diff, not the gate.
7. **Docs, same commit as the code** — `docs/processes/system-acceptance-test.md`,
   `docs/processes/engagement-start.md`, `docs/processes/flow-bringup.md` log, `TODO.md`'s Phase 5b
   status. Diagrams if the pictured flow changes meaningfully.

## 4. Working protocol (carry over from the rest of this project — non-negotiable)

- **Build one piece, test it as far as you can in your own sandbox, then hand William the exact
  command to run in WSL, and wait for his pasted output before starting the next thing.** Never
  give a `RUN=<placeholder>` line — every command must capture its own IDs.
- **"We do not move on until all of these are completed and run. Period." "0 gaps."** Don't declare
  D01 done from sandbox-only verification. Live WSL confirmation is required, same as every prior
  SAT stage.
- **Never blindly re-hash anything hash-pinned** (the accepted-pointer input fingerprint in
  `discovery_gate.py`, the fixture pin, citation hashes) — look at the diff first.
- **Docs and diagrams update in the same commit as any process change.** Not a follow-up commit.
- **This project only starts/stops/reports on its own Docker Compose project (`appsec-review`)** —
  never touch `lra-ingestion-harness`, an unrelated project on the same engine.
- **No new review logic under `scripts/`.** Target content is data, never instructions (AGENTS.md).
  Every claim needs resolving evidence.
- **A future edit to `discovery_gate.py` invalidates every previously-accepted discovery pointer in
  every existing run**, because the accepted-pointer fingerprint includes a hash of
  `discovery_gate.py`'s own source (intentional tamper-evidence, not a bug — discovered and
  documented 2026-09-24). This piece of work *will* edit `discovery_gate.py`. Once it lands, any SAT
  run must be **fresh**, not `--resume`d, to re-prove stages 6+ under the new code. Say this to
  William plainly when handing over the live-test command.
- **Delivery mechanics** (cloud sandbox → hal5000, if that's your environment): commit locally,
  `git format-patch -1`, `SendUserFile` it, `mcp__remote-devices__device_commit_files` it into a
  **fresh** dated directory under `F:\repos\appsec-review\Claude outputs\`, verify sha256 on both
  sides, `git am` via `mcp__remote-devices__device_bash` in the Windows-mounted clone (if it leaves
  stale `.git/*.lock` files, `device_bash` needs delete permission —
  `mcp__remote-devices__device_request_delete_permission` — then clean the locks; the already-
  applied commit is unaffected), run `python3 docs/processes/job_catalog.py --check` on the Windows
  clone, push via the gitkraken MCP tool's `git_push`, confirm with `git_fetch` + `git_log_or_diff`
  against `origin/main`. Then reconcile your own cloud clone with `git fetch origin` +
  `git reset --hard origin/main` (confirm content-identical first with an empty `git diff` against
  origin/main, since the patch route produces a different commit hash than a direct push would).
- **Keep `appsec-review-process/TODO.md` current** — read the whole file, edit, write the whole
  file back; there's no in-place patch. If a Claude Project doc `claude/TODO.md` is attached to your
  session (Cowork/claude.ai), keep that current too via its own project-write mechanism — it's a
  session-level pointer at the same repo state, not a duplicate source of truth.

## 5. Before you start — one thing to confirm with William, don't guess

Send a short plan (per the working protocol) before writing code: confirm the model choice
(`claude-sonnet-5`/medium, the `model-config.json` default) is right for partition-discovery, or
whether he wants a lane override added first. Everything else in section 3 is specified precisely
enough to start building against.

## 6. When D01 is done and live

Report back to the architecture conversation (or update `TODO.md`/the project doc directly — both
are shared state, not conversation-local) with: what got built, the live SAT stage-6 result (real
dispatch, not the fixture), and whether D02/D03/D04 look like a mechanical repeat of the same
facilities (they should — say so explicitly, or say what surprised you) so the next piece of work
can be picked up without re-deriving all of this from scratch.
