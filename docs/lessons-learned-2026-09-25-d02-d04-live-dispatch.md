# Lessons learned: D02-D04 live persona dispatch (2026-09-25)

Status: **current, generalizable.** Written after D02 (`02-dev-project-discovery`), D03
(`02-devops-project-discovery`) and D04 (`02-sre-operations-topology`) went live, ending with the
first SAT in which every discovery stage is a real model call (fresh SAT `20260925T170552Z`, run
`20260925T170620Z-c6a12e`, stages 1-9 PASS). Complements
[`lessons-learned-2026-09-24-d01-live-dispatch.md`](lessons-learned-2026-09-24-d01-live-dispatch.md):
all six of its lessons held and still apply. The blow-by-blow is in `docs/processes/flow-bringup.md`
(2026-09-25 log entries) and `appsec-review-process/TODO.md` Phases 5c-5e. This file extracts what
transfers to the next persona jobs (the build lane's `02-build-plan` first).

## 1. Reading first pays: D02-D04's code passed live without a code fix

D01 needed five live attempts. D02 and D03 passed on their first, and D04's gate, claim builder and
SAT branch needed no change after going live. The difference was reading before building: every
failure mode D01 found (orchestrator-owned fields, literal schema, binary pinning, envelope files
without a schema, unknown prompt sections) was checked against each new job's contract, template
and schema before any code was written. Two bugs were caught that way, and each would have failed
the first live call before the model was even asked: a second required JSON file with no schema
(`live-state-followups.json` for D04, `safe-command-plan.json` for D02), and a template prompt
section the assembler does not know (`ops_artifacts` for D04, `pipeline_artifacts` for D03). **Keep
the checklist:** for a new persona job, open its output contract, job template (prompt sections,
`task_prompt`, model pin, `outputs.files`), result schema and role/tooling-profile claim ceiling
before writing its prompt.

## 2. The model's failures are wording failures; fix the prompt, keep the check strict

Both live failures on the way to D04 were the model reasonably filling a gap in what it was told,
not a gate bug:

- **Prose in a path field.** The D01 persona wrote a sentence into `coverage.inventory_scope` and
  every `search_scope`, because the schema types them only as strings and the prompt never said
  they hold paths. The earlier live runs had happened to write `**`.
- **A JSON value sent as a string.** The D03 persona returned `project_inventory` as a JSON-encoded
  string inside the envelope, because the envelope instructions said each key holds "the file's
  full content", which reads naturally as the file's text.

In both cases the validator's rejection was correct, and the fix was one or two sentences stating
the syntax the check already enforces (`e915d92`, `97eeb3d`). Neither check was loosened. A tolerant
parser that repaired a stringified value would hide exactly the drift the strict envelope exists to
catch. **Rule:** when a live model output fails a structural check, first ask whether the prompt
ever stated the rule. For any free-text-typed schema field with a narrower real syntax (paths,
globs, ids, enums enforced in code rather than in the schema), say so in the task prompt, and say
where explanations go instead.

## 3. The same prompt passes, then fails: one live pass is not proof of stable wording

The D01 prompt passed live several times before a run wrote prose where paths belong. Model
sampling means a gap in the wording shows up only sometimes. So each live PASS is evidence about the
code path, not a guarantee about the prompt. Once the full system runs, repeated runs and deliberate
prompt or persona variations (William, 2026-09-25) are how the wording gets hardened. Because SAT
acceptance is structural, not byte-equal, those runs are comparable.

## 4. Where to look when an envelope is rejected

`persona_invocation` records only `INVOKER_EXCEPTION`, by design: raw model output never enters the
trusted run record. The exception text is not persisted either. What survives:

- `persona-attempts/<id>/outputs/persona/` has the result files **only** if the envelope passed; an
  empty directory means the wrapper itself was rejected (not JSON, wrong keys, a non-object value,
  or a schema failure).
- The code location's `/tmp/claude-cli-invoker-*/raw-response.json` (on the host that ran the job,
  WSL here) keeps the raw terminal response of every call. Re-running `_parse_envelope` and
  `_validate_envelope` (or the claim builder, against `logs/persona/request.json`'s
  `readable_inputs`) on it reproduces the exact error offline, with no model call.
- `invocation.save_llm_transcripts` in `model-config.json` copies transcripts into the run for the
  next attempt; leave it off for real targets.

## 5. Generalize the shared path by table, and keep old record shapes still

D04 had a different upstream, schema and claim builder, so it could not reuse D02/D03's path as-is.
Folding it in behind one per-job table (`AUTOMATIC_JOBS`: persona id, result and summary file,
upstream jobs) kept one acceptance path for all three. Two choices kept it safe to merge:

- **Old shapes unchanged:** D02/D03's fingerprinted upstream record and staging directory keep their
  exact one-upstream shape, so their SAT stages and existing runs did not move. Only a job with
  several upstreams gets the new shape.
- **A test ties the table to the registry:** each job's result and summary files must equal its
  output contract's `result_schema.artifact` and `required_files`. A future template or contract
  edit that breaks the invoker's file expectations then fails in unit tests, not live.

## 6. Scope from the upstream that actually has content

For hello-autotools the partition map routes nothing to `sre-engineer`. A D04 prompt scoped only by
SRE-routed partitions would always have returned an empty result, which the zero-result rule would
have accepted only with a coverage gap: a pass that tests nothing. Scoping D04 from the devops
units, plus any SRE-routed partitions, gave it something real to map. **Check what the upstream
actually contains for the fixture before deciding a prompt's scope rule.**

## 7. The environment fails too, and looks like the system failing

Two of the day's failures were not the code at all:

- **A stuck Docker Desktop engine** returned `500` on `/version` while `docker ps` still worked. The
  native `docker.service` was confirmed disabled (the earlier double-engine cause, ruled out first).
  Quitting Desktop, `wsl --shutdown` and a restart fixed it. `curl --unix-socket
  /var/run/docker.sock http://localhost/_ping` and `/version` tell the two cases apart.
- **The Windows `claude` shadowed the Linux one.** WSL appends the Windows PATH, so before
  `~/.local/bin` was added, `claude` resolved to the Windows npm shim (`Exec format error`). The run
  pins the resolved path (`data/claude-binary.json`), so check `command -v claude` before a SAT.

## What the build lane inherits

Everything above plus the D01 file's six lessons. For `02-build-plan` specifically: read its
contract, template and schema first (lesson 1); state every narrower-than-schema syntax in its task
prompt, most of all the argv and package-name rules the plan validator enforces (lesson 2); plan for
repeated live runs rather than one (lesson 3); keep the shared invoker and its strict envelope
unchanged.
