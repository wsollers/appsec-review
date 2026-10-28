# Operating proof-of-concept generation

**Partial completion integration (`b702eb7`):** the registered graph now moves PoC before the
single final gate and enables it for new configurations. The handler/publication contract below
is still the old gate-coupled implementation from `5f5548d`, not an operational recipe for that new
graph. Its replacement will use
immutable attempt-owned artifacts and add explicit nonexecution assurance and protected
[per-outcome dossiers](dossier-publication.md). Final PoC/gate `/2` contracts are pending;
checkpoint `18eae9f` aligns the shared `/3` review reader and verifies PoC-basis digests.
Old frozen runs are not silently enabled or upgraded.
[Dossier data inventory](../architecture/dossier-data-inventory.md)
enumerates the actual accepted inputs and bounded retrieval; compiling either function still
does not observe its behavior.

The CLI now parses explicit gate re-admission as
`run job_final_publication_gate --run-id <id> --upstream-from-run --admit-manual-poc`.
It is restricted to that job with both preceding flags. End-to-end digest authentication awaits
the final gate contract; no ordinary `latest.json` discovery is permission to activate a disabled
manual PoC.

## Legacy handler reference

`job_poc_generation` writes, for each finding the judge agreed is correct, a **proof-of-concept unit-test
function** that a developer can add to a test target and watch in a debugger, and checks that it **compiles**
against the project's own build. It is the second half of the design in
[`../architecture/review-judge-and-poc.md`](../architecture/review-judge-and-poc.md) (section 5); the decisions it
took where that document left a choice open are in its section 8.

- The function has **no `main`**, takes no arguments and uses only in-memory fixtures. A second function, the
  **negative control**, makes the same call with a safe input so the difference is visible.
- The pipeline **never executes it**. It parses it, runs deterministic validators on the clang AST, compiles it
  (syntax, plain object, sanitizer object) and checks that the symbols the object needs resolve. Nothing is linked
  into an executable and nothing is run.
- At the original contract baseline the job was shipped disabled and invoked by hand on a
  finished run; current new-configuration defaults are enabled as noted above.

```text
job_final_publication_gate -> job_poc_generation -> job_final_report_publication   (only when enabled)
job_final_publication_gate -> job_final_report_publication                           (shipped: disabled)
```

## Invoking it

`settings.enabled` decides membership in the automatic graph (Dagster `wave1_review` and the direct `start`/`resume`
graph). It is not a permission to run: a direct dispatch of this job is allowed while it is disabled, because the
operator's command is the consent (`cli.MANUAL_JOB_IDS`). Every other disabled job is still refused.

```text
appsec-review run job_poc_generation --run-id <run-id> --upstream-from-run
```

`--upstream-from-run` binds the run's accepted handoffs of the jobs that would precede it in the graph (the gate,
the review, the language build and the rest), exactly as the graph would. The job needs, in that run:

- an accepted `job_final_publication_gate` handoff and the accepted `job_inference_security_review` handoff it was
  built from (both are re-verified from bytes);
- a `poc_candidates` array in the review handoff (below);
- an accepted `job_language_build` handoff with a successful native build unit that compiled the sink's file, its
  hash-bound workspace and the build image on the local daemon.

Then re-run `job_final_report_publication` on the run: when the PoC handoff is accepted and was produced from the
current gate handoff, the report's `poc_outcomes` shows the outcomes. A PoC handoff built from an older gate handoff
is *stale*: the report says so and shows nothing from it. Running the job again fixes that.

To make it part of the graph, set `jobs.job_poc_generation.settings.enabled = true` in the central configuration. The
resolved configuration of a run is frozen when the run starts, so a job enabled afterwards is run manually against the
run's frozen settings.

## Candidates

The review handoff lists `poc_candidates` (design section 4; produced by the judge work of
`job_inference_security_review`): every claim whose state is `supported` or `confirmed`, whose judge verdict is
`red_correct` (or `partly`, when the producer is configured to include it), that carries a resolved `poc_basis` and
that the policy asks to document. The reader (`jobs/job_poc_generation/candidates.py`, schema
[`poc-candidate.schema.json`](../schemas/poc-generation/poc-candidate.schema.json)) is strict:

| Field | Meaning |
| --- | --- |
| `claim_id`, `package_id` | the claim and the review package it was raised on |
| `state`, `judge_verdict` | the ledger state and the de-shuffled judge verdict |
| `poc_basis` | `{sha256, value}`: the bounded brief of review-protocol-v2 section 6.6; `sha256` is the SHA-256 of the canonical JSON of `value` |
| `finding_package` | `{finding_package_id, sha256}`, which must match the review handoff's finding package of that claim |
| `evidence_refs` | the evidence the claim rests on |

A handoff **without** the field is an older run: the job completes `COMPLETED_WITH_GAPS` with the named gap
`no_poc_candidates` and publishes an empty, valid handoff. An empty array is a run with nothing to document. A field
that does not match the documented shape, or a candidate that disagrees with the verified finding package, is an
integrity failure.

## Steps

The central configuration must define exactly this topology:

```text
load.verify_inputs -> plan.briefs -> write.poc_writer -> validate.policy -> compile.build_check -> package.files -> publish.publish_handoff
```

1. **`load.verify_inputs`** re-verifies the accepted gate and review handoffs with the gate's own helpers and reads
   `poc_candidates`. Confirmed claims are attempted first, in claim-id order, up to `max_candidates`; the rest are named
   in the gap `candidate_bound_reached`.
2. **`plan.briefs`** decides what can be attempted and builds each brief from the finding package, the `poc_basis` with
   its labels resolved in the labelled package view, the declarations at the sink, the safe build facts of the
   translation unit that contains the sink and the closed limits the validators enforce. A candidate that cannot be
   attempted gets its terminal status here: a judge verdict outside `accepted_judge_verdicts` or a sink in a file that no
   accepted native build compiled is `not_applicable`; a `poc_basis` without an entry, a path or a trigger, a package
   that names no sink function, or labels that do not resolve is `insufficient_evidence`.
3. **`write.poc_writer`** runs the model (below).
4. **`validate.policy`** assembles the file, runs the textual checks and then the AST validators in the build image.
5. **`compile.build_check`** runs the compile check.
6. **`package.files`** writes `data/poc/<claim-id>/`.
7. **`publish.publish_handoff`** validates and publishes `poc-generation.json` and the handoff.

### The writer

The role `poc_writer` and its runtime skill `poc-writer` (`pipeline/skills/poc-writer/SKILL.md`, loadable only by this
job through `guidance.skills.load_runtime_skill`; worked examples and non-examples are in the skill) are sent with the
shared governing rules, hash-pinned under `runs/<run-id>/data/guidance/<bundle-sha256>/`. The model is granted no
tools. The transport, turn schema (`worker-turn/1`) and recording are the review cells'. The application answers two
retrieval requests in process from the hash-verified accepted workspace: `read_source` (a window of at most 120 lines of
a file the build compiled, under the sink's include path) and `find_declaration` (prototype and type lines in the
project's headers). A denied request returns its code and the corrected shape and costs one query; the second
identical denial ends the attempt.

The answer is the compact shape of design section 5.2 or a **decline** with a status the writer may choose
(`insufficient_evidence`, `not_applicable`, `unsafe_to_attempt`). A schema error is repaired (up to `retry.max_attempts`
attempts). A deterministic validator verdict is never repaired: the schema bounds names and sizes loosely so that a
function named `main` reaches the validators instead of being "fixed" by the writer. A writer that produces no usable
answer leaves the candidate `insufficient_evidence` (`writer_*` reason). Per-candidate receipts under the attempt's
`write` step hold hashes, counts and the validated answer, never prompts.

### The validators

All of them are deterministic and fail closed; any violation is `policy_denied`.

- **Textual** (`source.py`): function names are `poc_<lowercase words>`, not `main` or another entry point; sizes and
  lines per function and per file; ASCII only; **no `#` or `%:` anywhere in a function body** (includes are listed and
  generated by the application, so a comment cannot hide a directive), no `_Pragma`, no assembler keyword; each include is
  an allowed standard header or a project header that resolves on the sink translation unit's include path inside the
  accepted workspace; no more than `bounds.max_includes`.
- **AST** (`policy.py`, over the reduced clang JSON AST): exactly the two named functions are defined at file scope and
  nothing else (no `main`, no second entry point, no variable, helper, namespace or type); each is `void f()`; every node
  kind must be on a closed list (so inline assembly, a lambda, `goto`, `while`, `do`, a range-for and an exception throw
  are refused); a `for` loop must count a local integer to a literal bound within `max_loop_iterations`; a function never
  references itself or the other PoC function; every function and variable referenced must be on the closed
  `call_allowlist` (**the allowlist wins over the denylist**; a name on neither is refused as unlisted, and a name on the
  denylist is reported by its category: process, shell, network, dynamic loading, file system, environment, control), or be
  the sink or a function on the brief's call path (`project_calls`); no indirect calls; every type declared, cast or
  constructed is a builtin, a project type or on `type_allowlist` (this is what refuses `std::ifstream`); array sizes and
  `new[]` sizes are constants within `max_array_elements`; string literals carry no URL, network address, absolute or
  `..` path, or secret-looking text; both functions call the sink (matched on the qualified name from the AST, not by text
  search); the test function carries every numeric trigger value of the brief (`greater than 16` needs a literal or array
  size above 16 in that function).
- A trigger constraint with no number in it is not checked and is recorded; integer constants are otherwise not bounded,
  because integer-overflow triggers need large values.

The AST is the reduction of `clang -fsyntax-only -Xclang -ast-dump=json`: for a translation unit that includes
`<string>` the dump is tens of megabytes, so `ast_reduce.py` (stdlib only, copied into the scratch workspace) runs inside
the build image around the compiler and returns only the PoC file's nodes, the identity of everything they reference
(qualified name, kind, file) and the project's own declarations. `policy.check_ast` is a pure function of that document;
its tests run on documents recorded once from the local build image
(`tests/fixtures/poc_generation/record_ast.py`).

### The compile check

In a hash-verified scratch copy of the accepted build workspace (`steps/compile/.../scratch`, removed after each
candidate), through the same `BuildContainerExecutor` the sanitizer job uses, with `--network none`:

1. `-fsyntax-only` with the project's own flags (the exact captured compiler argv of the sink's translation unit from the
   protected compile database, `-MD -MT -MF -o -c`, plugins and `-Werror` removed, the PoC file substituted);
2. `-c` with the project's flags plus `build.debug_flags` (`-g -O0`; the project's `-O` and `-g` are replaced);
3. `-c` again with `build.sanitizer_flags` (`-fsanitize=address,undefined -fno-omit-frame-pointer`);
4. `nm -P -u` of the plain object; `nm -P -g --defined-only` of the project's accepted objects and static libraries (and
   `-D` of its shared libraries); `nm -P -D --defined-only` of `build.runtime_libraries`. A required undefined symbol must be
   defined by the project, by a runtime library or begin with `build.runtime_symbol_prefixes` (`__asan_`, `__ubsan_`, ...).

The two objects are hashed and discarded. No derived command names a produced file, writes anything but an object file or
links; the tests assert this on every recorded argv.

## Statuses

| Status | Meaning |
| --- | --- |
| `compile_verified` | validators passed; the functions compile with the project's flags plain and under the sanitizers and every undefined symbol resolves |
| `compile_failed` | validators passed (or the code did not parse) but the generated code does not build, or needs a symbol nothing defines. This **does not contradict the finding** |
| `artifact_generated` | the source was generated but could not be verified: the build image or the accepted workspace was unavailable, or no accepted object or runtime library could be read (a named gap) |
| `policy_denied` | a deterministic validator refused it; the source is kept as data and was not compiled |
| `insufficient_evidence` | no usable `poc_basis`, no known sink function, or the writer produced no usable answer |
| `not_applicable` | the judge verdict is not configured for PoC generation, or no accepted native build compiled the sink's file (not C/C++, or a failed build) |
| `unsafe_to_attempt` | the writer declined because a safe in-memory demonstration is not possible |

## Outputs

Under `runs/<run-id>/data/poc/<claim-id>/` (only for a candidate with a source: `compile_verified`, `compile_failed`,
`artifact_generated`, `policy_denied`):

| File | Contents |
| --- | --- |
| `poc_<name>.cpp` (`.c` for C) | the banner, the generated includes, the test function and the negative control, stored verbatim as data |
| `compile.json` | status, the policy verdict and violations, every command (classified, never raw argv), exit codes, diagnostics, object hashes and the symbol check ([`compile-record.schema.json`](../schemas/poc-generation/compile-record.schema.json)) |
| `README.md` | what it shows, where to add it, setup, breakpoints, the expected observation, the writer's notes and limitations; model text is in code spans or fenced blocks that cannot be closed from inside |
| `provenance.json` | hashes of the poc_basis, brief, review package, source, settings, guidance bundle and writer receipt, the model, the upstream handoffs, the build unit, workspace manifest and image ([`provenance.schema.json`](../schemas/poc-generation/provenance.schema.json)) |

The handoff (`appsec-review/poc-generation-handoff/1`, summary [`poc-generation.schema.json`](../schemas/poc-generation/poc-generation.schema.json))
lists **every** attempted candidate with its status, reason, a description of at most 300 characters, the function names,
the four file references and the brief and writer-receipt references (each with its SHA-256). Statuses other than
`compile_verified` and `not_applicable` are named gaps, so the job finishes `COMPLETED_WITH_GAPS`. Datasets declare every
file (`poc_generation_summary`, `poc_writer_cells` (protected: briefs hold target source text) and `poc_reproducers`
(`data/poc/**`)), and the input matrix names the job as the producer of `poc_generation`.

## Settings

`[jobs.job_poc_generation.settings]` defines exactly these keys (the central configuration documents them):

| Key | Meaning |
| --- | --- |
| `enabled` | membership in the automatic graph; shipped `false` |
| `workers` | candidates processed concurrently inside a step |
| `max_candidates` | candidates attempted per run |
| `accepted_judge_verdicts` | verdicts a candidate may carry; `["red_correct"]` |
| `models.<profile>`, `roles.poc_writer.model_profile` | provider, model, reasoning, token, query, turn and timeout limits of the writer |
| `retry` | `max_attempts` and which failures are retried |
| `bounds` | lines, bytes, includes, list items, text, string literals, loop iterations, array elements, violations |
| `policy` | `allowed_std_headers`, `project_header_suffixes`, `project_calls`, `call_allowlist`, `type_allowlist`, `call_denylist.<category>` |
| `build` | command timeout and output bytes, workspace file and byte bounds, `ast_compilers`, `debug_flags`, `sanitizer_flags`, `runtime_libraries`, `runtime_symbol_prefixes`, `object_limit`, `scratch_directory` |
| `brief` | the package view and brief byte bounds, source lines, type declarations and declaration lines |

The shipped writer profile uses the model the rest of the pipeline already depends on, so enabling the job adds no model
to the preflight. Change `models.default` (or add a profile and point `roles.poc_writer` at it) for a stronger writer.
`settings_sha256` in each provenance file covers the validator policy, the build settings and the writer profile.

## What the job never does

- It never links, loads or runs the PoC or anything it compiled; the only outputs are two object files that are hashed
  and discarded.
- It never reads the target tree; the source copy is the run's accepted build workspace, re-hashed file by file.
- It never gives the build container a network (`--network none`).
- It never copies repository guidance, target guidance, development skills or continuation prompts into a prompt.
- It never repairs its way past a validator, never sets a claim state or score, and never reads `compile_failed` as
  evidence against a finding.
- It stores model output and PoC source verbatim as data only.
