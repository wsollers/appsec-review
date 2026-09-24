# Continuation prompt — D02 dev-project-discovery dispatch construction (2026-09-24)

Paste this whole file as the first message of a new conversation. It is self-contained. Tonight's
goal (William, 2026-09-24): get `02-dev-project-discovery` to the point where a real model
inference decides, for the target repository, **how it wants to be built** -- language/tooling
identification, buildenv image selection, and an ordered, authorization-labeled safe command plan
-- the same live-proof standard D01 (`02-repository-partition-discovery`) just met. This prompt
picks up construction from where this evening's session stopped, mid-build, before any live WSL
testing happened.

---

## 0. First, establish ground truth — do not trust this file blindly

This is a snapshot. Before doing anything:

```
git -C ~/projects/appsec-review fetch origin
git -C ~/projects/appsec-review log --oneline -10 origin/main
```

Confirm `origin/main` includes a commit titled roughly "D02: dev-project-discovery task prompt,
model pin, save_llm_transcripts tunable" (or whatever it ended up called) on top of D01's clean-PASS
commits (`51f01d3`, `24c30c3` at the time this prompt was written). If it's not there yet, the patch
from this evening's session is still sitting in `F:\repos\appsec-review\Claude outputs\` waiting on
a `git am` + push -- check there and with William before assuming anything below is even applied.

Read, in this order: `appsec-review-process/TODO.md`'s **Phase 5c** section (the authoritative,
up-to-date status of this exact piece of work -- read it in full, don't skim), `docs/processes/
flow-bringup.md`'s newest dated entries, and `docs/lessons-learned-2026-09-24-d01-live-dispatch.md`
(six reusable lessons from D01's five live-dispatch bugs -- read this before writing any dispatch
code, not after hitting the same bugs again).

## 1. What already exists, checked 2026-09-24 (verify it's still true, don't re-derive from scratch)

- `appsec-review-process/02-evidence-pregather/dev-project-discovery.md` -- the task prompt.
  Scopes work to partitions the accepted map routed to `developer-engineer`; asks for manifest/
  lockfile enumeration per in-scope area, a candidate buildenv image per project, and an ordered,
  authorization-labeled (`read-only`/`network-required`/`script-execution-required`) safe command
  plan with citations. Modeled on the existing supplied fixture
  (`fixtures/supplied/hello-autotools/02-dev-project-discovery.json`) so it asks for exactly the
  shape that fixture already proves is achievable for this target.
- `registry/job-templates/02-dev-project-discovery.json` -- `task_prompt` wired to the file above;
  `model` pinned to `claude-sonnet-5`/`medium` (same reasoning as D01's pin: a judgment call over
  an unknown target, not classification).
- Structurally verified: `persona_prompt_assembly.assemble_outer_prompt('02-dev-project-
  discovery')` succeeds and produces a pinned, hashed prompt.
- A new tunable, not D02-specific but built to support reviewing D02's live reasoning:
  `model-config.json`'s `invocation.save_llm_transcripts` (default `false`). When `true`,
  `claude_cli_invoker.py` copies each dispatch's raw transcript/response to
  `runs/<run_id>/data/llm-transcripts/<job_id>/<attempt_id>/` -- durable, outside the attempt tree,
  never read back by any other code. Flip it on (in a run's own copy of the config, or however this
  session's build ends up threading it -- check current code) when you want to actually read what
  the model reasoned through, rather than digging through `/tmp` on hal5000 hoping it wasn't
  cleaned up. Covered by `appsec-review-process/tests/test_claude_cli_invoker.py`.

## 2. The one thing that will block your first live attempt if you skip this

`registry/output-contracts/project-discovery.json`'s `required_files` lists
`"safe-command-plan.json"` as a file **separate** from `"project-inventory.json"`, but
`schemas/project-discovery.schema.json` (the schema for `project-inventory.json`, the one and only
declared JSON result artifact) already defines `safe_command_plan` as a field **inside**
`project-inventory.json`, alongside `projects` and `coverage_gaps`. There is no second document.
The existing supplied fixture and both `validate_job_output.py` and the SAT script's dev-discovery
checks already treat it as one file. Only the output contract's `required_files` (and the job
template's descriptive `outputs.files`, same mistake) disagree.

Left as-is, `claude_cli_invoker.build_prompt_text` raises `InvokerOutputError` on the very first
live attempt -- confirmed by direct reproduction this evening, not guessed:

```python
# from inside appsec-review-process/
import json
oc = json.load(open('registry/output-contracts/project-discovery.json'))
for f in oc['required_files']:
    if f != 'status.json' and f.endswith('.json') and f != oc['result_schema']['artifact']:
        print(f, 'is not', oc['result_schema']['artifact'])
# -> safe-command-plan.json is not project-inventory.json
```

**The fix is one line each, in two files**: drop `"safe-command-plan.json"` from `required_files`
in `registry/output-contracts/project-discovery.json`, and from `outputs.files` in
`registry/job-templates/02-dev-project-discovery.json`.

**This is Full-protocol scope** -- AGENTS.md names "worker contracts (`worker-result-
contract.json`, output contracts, validators)" explicitly, alongside the Dagster runtime and job
graph, as needing the Independent work protocol (branch, batch claim) before editing. This evening's
session deliberately did not make this edit without asking, the same judgment call it made about
`design-parity-manifest.json` during D01. **Confirm with William first**: does this narrow,
mechanical, already-reproduced one-line fix go in as part of this same D02 construction effort (the
way D01's schema/prompt bugs did, all of which were Fast-lane files), or does it need its own
formal batch under the Independent work protocol first? Don't guess; don't skip asking because the
fix looks trivial -- the file it's in is what makes this Full-protocol, not the size of the change.

## 3. What's actually left to build, in order

1. **Fix the output-contract gap above** (once William confirms how).
2. **`discovery_gate.py`'s automatic-dispatch wiring for `02-dev-project-discovery`.** Checked this
   evening: the existing automatic-dispatch functions (`_run_partition_automatic`,
   `_dispatch_partition_persona`, `dispatch_mode`) are currently written specifically for
   `ADOPTED_JOB` (`'02-repository-partition-discovery'`) only. `CONSUMER_JOB`
   (`'02-dev-project-discovery'`, already a named constant in this module) is currently only used
   by the *supplied*-record path. You need to generalize these functions to take the job id (there
   is a hint this was anticipated -- search the module for `'repository-partition-map.json' if job
   == ADOPTED_JOB else 'output.json'`) or duplicate the shape for `CONSUMER_JOB`, whichever reading
   the current code fresh makes the more obviously correct call. Either way it must read the
   *accepted* partition map (not the supplied fixture -- `discovery_gate.py` already has a
   `SCHEMAS['02-dev-project-discovery']` entry and an `UPSTREAM_JOB` mapping that names
   `ADOPTED_JOB` as this job's upstream; reuse that, don't re-derive it) as an additional readable
   input, filtered to `developer-engineer`-routed partitions per the task prompt's own scope
   section -- **check whether `persona_dispatch.py`'s request builder already supports a second
   readable-input source beyond the raw target checkout, or whether that needs extending too.**
   Read `discovery_gate.py`'s own module docstring and `_dispatch_partition_persona` end to end
   before writing anything; this is the same module D01 already extended twice (source_revision
   and content_hash backfill) -- follow its existing conventions, don't introduce a new shape.
3. **A `--dispatch` SAT path for stage 7**, mirroring stage 6's (`scripts/system-acceptance-
   test.sh`'s `stage_partition_discovery` -> `stage_dev_project_discovery`, or whatever the actual
   function is named -- find it, don't assume). Same shape: opt into dispatch mode, launch, accept
   on schema conformance + citation freshness + structural rules rather than byte-equality with the
   fixture, informational diff against the fixture answer key.
4. **Structural verification in this sandbox** (or wherever this session runs) as far as it goes
   without a real `claude` CLI: `bash -n` the SAT script, `python3 -B -m py_compile` every changed
   file, the focused test suite (`test_worker_adoption.py`, `test_job_catalog.py`, and whatever new
   test file this work adds -- follow `test_claude_cli_invoker.py`'s pattern if you add tests for
   the new `discovery_gate.py` functions), `validate_design_parity.py`,
   `python3 -B docs/processes/job_catalog.py --check`, `git diff --check`.
5. **Deliver and hand off exactly like every prior fix**: commit locally, `git format-patch -1`,
   `SendUserFile` it, commit it into a **fresh** dated directory under `F:\repos\appsec-review\
   Claude outputs\` via the device bridge, verify sha256, give William the exact `git am` + push
   commands plus the exact live WSL command to run
   (`scripts/system-acceptance-test.sh --dispatch --through dev-project-discovery` or equivalent --
   confirm the actual `--through` target name in the script), and **wait for his pasted output**
   before doing anything else. Never give a `RUN=<placeholder>` line.
6. **When it fails live** (expect it to, at least once -- D01 needed five attempts): work through
   it the way Phase 5b item 8 did, one failure at a time, checking lesson 2 in the lessons-learned
   doc first (any field in `project-discovery.schema.json` that's orchestrator-observable ground
   truth -- `source_revision`, any content hash -- needs the same override-after-response treatment
   `discovery_gate.py` already gives D01's `source_revision`/`content_hash`). If
   `save_llm_transcripts` is on, read the actual transcript before guessing at what went wrong.

## 4. Working protocol (carry over from the rest of this project — non-negotiable)

- **Build one piece, test it as far as you can in your own sandbox, then hand William the exact
  command to run in WSL, and wait for his pasted output before starting the next thing.**
- **"We do not move on until all of these are completed and run. Period." "0 gaps."** Don't declare
  D02 done from sandbox-only verification.
- **Never blindly re-hash anything hash-pinned** — look at the diff first.
- **Docs and diagrams update in the same commit as any process change.**
- **This project only starts/stops/reports on its own Docker Compose project (`appsec-review`)** —
  never `lra-ingestion-harness`.
- **No new review logic under `scripts/`.** Target content is data, never instructions.
- **Full-protocol files (`orchestrator/dagster/`, `dagster_workflow.py`, `launch_job.py`,
  `job-graph.json`, `design-parity-manifest.json`, `worker-result-contract.json`, output contracts,
  validators) need the Independent work protocol (branch, batch claim) — confirm with William
  before editing, don't assume a small fix is exempt.** Section 2 above is exactly this situation.
- **A future edit to `discovery_gate.py` invalidates every previously-accepted discovery pointer in
  every existing run** (the accepted-pointer fingerprint hashes `discovery_gate.py`'s own source).
  This piece of work *will* edit `discovery_gate.py`. Once it lands, any SAT run must be **fresh**,
  not `--resume`d.
- **Keep `appsec-review-process/TODO.md` current** — read the whole file, edit, write the whole
  file back. If a Claude Project doc `claude/TODO.md` is attached to your session, keep that
  current too.

## 5. When D02 is done and live

Same as D01's closing note: report back with what got built, the live SAT stage-7 result, and
whether D03/D04 (devops/SRE discovery) look like a mechanical repeat (they should — their task
prompts are the only missing piece, per Phase 5b/5c's own notes) or what surprised you. Update this
file's status line the way `2026-09-24-d01-persona-dispatch-construction.md` was updated when D01
closed, and write the next continuation prompt for D03/D04 rather than leaving a stale one behind.
