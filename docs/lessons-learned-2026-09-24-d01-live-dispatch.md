# Lessons learned: D01 live persona dispatch (2026-09-24)

Status: **current, generalizable.** Continued by [`lessons-learned-2026-09-25-d02-d04-live-dispatch.md`](lessons-learned-2026-09-25-d02-d04-live-dispatch.md) (D02-D04 went live 2026-09-25; all six lessons below held). Written after `02-repository-partition-discovery`'s automatic
dispatch mode (D01, unpooled) went from "passes on a hand-authored fixture" to "passes against a
real `claude` CLI call, live on hal5000, zero contract violations" in one day, via five successive
live-dispatch failures, each fixed in turn. Full blow-by-blow is in `appsec-review-process/TODO.md`
Phase 5b item 8 and the matching entries in `docs/processes/flow-bringup.md`; this file extracts the
transferable lessons so D02-D04 (`02-dev-project-discovery`, `02-devops-project-discovery`,
`02-sre-operations-topology`) don't have to rediscover them one live SAT failure at a time. Unlike
the disposed `docs/lessons-learned-2026-09-16-eastl-full-stack.md` (an engagement log tied to a
`scratch/` flow this repo no longer has), nothing here is dated infrastructure -- it is about the
shape of automatic persona dispatch itself, which D02-D04 share unchanged.

## 1. A fixture proves the harness, not the system

The standing trap: a gate that only checks "does the supplied file validate" while a human
hand-writes the file it is checking is a test of the JSON schema, not of the system (William's
correction, 2026-09-24, is what started this work). Structural SAT passes, unit tests, and a
schema-conformant hand-built sample are all worth having, but none of them substitute for one real
model call reaching one real gate end to end. Budget for this: D01 needed five successive live
attempts, each surfacing exactly one new failure, before it was clean. That is not a sign the design
was wrong -- it is what "prove it live" costs the first time, and every fix it forced was real.

## 2. The caller owns provenance and verification data; the model owns evidence-derived content

Two fields in `repository-partition-map.json` cannot come from the model reliably, for structural
reasons, not competence: `source_revision` (a git SHA -- `.git` is deliberately excluded from the
persona's readable inputs, so it genuinely cannot know the revision) and every
`evidence_citations[].content_hash` (an exact SHA-256 -- no model computes one by hand). Both are
the same class of problem `status.json` already solved by never asking the model for it in the
first place. Where the field can't be excluded from the schema outright (citations need
*something* there during authoring, and the model should still try), the orchestrator overwrites it
unconditionally after the model responds, with its own pinned, independently-computed value, and
never trusts what the model wrote. `discovery_gate.py`'s `_dispatch_partition_persona` does this for
both fields today. **Before authoring D02-D04's dispatch wiring, check their output contracts
(`registry/output-contracts/`) and schemas for the same shape** -- any field that is
orchestrator-observable ground truth (a revision, a hash, a byte count, a timestamp the model
can't see) belongs on this list, and skipping this step is exactly how bugs 3 and 4 got found the
hard way, live, instead of by inspection.

## 3. Resolve external binaries once per run, from inside the process that dispatches, never pin a path

`claude` (the CLI) was found on the interactive WSL shell's `PATH` but not on the long-running
`dagster code-server` daemon's -- a `FileNotFoundError` only a live run could have surfaced, since
every earlier check ran the compiled code in a shell that happened to have it. The wrong fix is a
hardcoded absolute path in config: it breaks the moment the install moves, and configs are supposed
to be portable across machines and installs. The right fix, `claude_binary_resolver.py`: resolve the
real path with `shutil.which()` **from inside the process that will actually invoke it**, once per
run, pin the result to `runs/<run_id>/data/claude-binary.json`, and reuse the pin on resume -- the
same "resolve once per run, pin, reuse" shape `model_version_registry.py` already uses for model
identity. A resolution failure raises a named error, never a silent fallback to some other binary.
This generalizes to anything else D02-D04 might shell out to that isn't guaranteed to be on every
process's `PATH`.

## 4. Show the model the literal schema, not a description of it

`persona_prompt_assembly.py`'s `output_contract` prompt section rendered the output contract's own
registry *metadata* -- display name, claim class, prose validation rules -- never the actual JSON
Schema file with its real field names, enums, and required properties. The model, working from a
prose description alone, reasonably invented its own shape (`engagement`/`paths.include`/`kind`
singular instead of the schema's `target`/`source_revision`/`include_paths`/`kinds`) and produced a
well-reasoned, well-cited, but non-conformant response -- 29 schema errors. The fix,
`claude_cli_invoker.py`'s `_render_json_schema`, inlines the literal schema JSON (and every local
`$ref` it reaches) as a fenced block in the prompt. **D02-D04's task prompts and output contracts
should be checked for the same gap before their first live run**, not after: if the model is only
ever shown a contract's metadata, expect the same class of failure, first attempt.

## 5. A trivial-looking SAT contract gap is not the same as a production bug -- keep them separate, but expect several

Across five live attempts, four were real bugs in the dispatch chain (above) and one was purely
cosmetic: the automatic-mode `accept` contract's `writes.allowed` list hadn't been updated to
include every file the new code path actually writes (`claude-binary.json`, the cached outer
prompt, `failure-result.json`, `job.lock`). Each was caught the same way -- the SAT's own contract
checker flagging an "unexpected write" -- and each was a one-line addition to the allowed list, not
a design problem. **Expect this category of gap for D02-D04 too**: a job template's SAT contract is
written before its automatic-dispatch path exists, so it does not yet know every artifact that path
will produce; each surfaces once, on the first live attempt, not before. Do not conflate this with a
real bug when triaging a live SAT failure -- check whether the underlying job actually reached
`SUCCESS` first (visible in the launch's own JSON result, independent of what the SAT script
concludes) before spending time on the wrong half of the failure.

## 6. Diagnosing a live dispatch failure without echoing model output back into the trusted record

`persona_invocation.py`'s `_call_invoker` deliberately discards an invoker's raw exception text and
output before it reaches any run record -- a real security boundary against unvetted model output
leaking into persisted state (governing rule 1: target/evidence/model content is data, never
instructions, and that includes not letting it pollute diagnostics that later tooling trusts).
This means the informative half of a live failure (what did the model actually say?) is not in the
run record you'd normally read. It survives on disk anyway, in the invoker's own private
`tempfile.mkdtemp(prefix="claude-cli-invoker-")` diagnostics directory (raw transcript + response),
which is not part of the trusted envelope and is fine to read directly when debugging. Point anyone
debugging a live D02-D04 dispatch failure there first, and do not "fix" the discard in
`persona_invocation.py` to make debugging more convenient -- the boundary is the point.

## What D02-D04 inherit unchanged

Every facility above is job-agnostic: `claude_binary_resolver.py`, `model_version_registry.py`,
`persona_prompt_assembly.py`'s schema inlining, `discovery_gate.py`'s dispatch-mode opt-in and
provenance/hash backfill pattern, and `claude_cli_invoker.py` itself all operate on whatever job
template and output contract they're given. D02-D04 need one new `task_prompt` markdown file each
(`appsec-review-process/02-evidence-pregather/{dev,devops}-project-discovery.md`,
`sre-operations-topology.md`) and, per lesson 2 above, a check of their own output contracts for
orchestrator-owned fields -- not a rebuild of any of this machinery.
