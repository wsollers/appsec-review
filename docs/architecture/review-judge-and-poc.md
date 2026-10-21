# Judge role and proof-of-concept generation

Status: design; implementation follows this document. It extends
[review protocol v2](review-protocol-v2.md) and does not change the claim ledger rules (R4 predicates, R5
adjudication, R6 independence) or evidence admissibility.

## 1. What the owner decided

- Red develops the information a proof of concept can be generated from (`poc_basis`, protocol section 6.6).
- Blue receives the same package and tools as red and tries to refute.
- A **judge** receives the package plus the red and blue results and decides who is correct, recording a verdict
  and a reason. The two sides are shown as **A and B in shuffled order**.
- A separate job generates the proof of concept only if the judge agrees the finding is correct and developers
  need it documented.
- The proof of concept is a **function with no `main`**, built against the codebase, that demonstrates the issue so
  a developer can add it to a unit test and watch it in a debugger. **It is never executed by the pipeline.** The
  pipeline compiles it and checks that its symbols resolve; nothing else.

## 2. Where the judge sits in the review

```text
package -> red cells -> blue cells (same package, no sight of red)
                     -> blind verifier (existing, R6)
red + blue results   -> judge
all of it            -> adjudication (R5, unchanged) -> ledger states -> poc_candidates
```

- The blind verifier is **kept** for every claim, exactly as today. The judge is an addition, not a replacement, so
  R5 row 5 (`confirmed` needs R6 independence) is untouched. A judge sees red and blue and therefore can never be
  the R6 verifier.
- The judge never sets a state. Its verdict is a **proposal and a routing signal**; the application still derives
  states from resolved evidence relations (section 4).

## 3. The judge cell

### 3.1 When it runs

`[jobs.job_inference_security_review.settings.roles.adjudication_judge]` has `when`:

- `"all"` (default): one judge cell for every claim on which red affirmed at least one predicate. The PoC gate needs
  a judge verdict on every candidate, including claims blue did not dispute.
- `"disagreement"`: only where red affirms and any blue cell contradicts, qualifies, or leaves a predicate
  unresolved, or where the blue cells disagree with each other.

`judges_per_claim` defaults to 1. The model profile is configurable; `require_distinct_from_roles = ["red_team_analyst",
"hypothesis_hunter", "blue_team_refuter"]` records `judge_model_distinct`, as for the verifier, and is not required.

### 3.2 What it is shown

The same labelled package view red and blue received (protocol section 4), the normalized claim statement and
predicate, and **two sides, A and B**:

```json
"sides": {
  "A": {"stance": "contradicts", "per_predicate": {"missing_or_ineffective_guard": {"stance": "contradicts", "cites": ["G2", "J1"]}},
        "why": "The guard at line 13 rejects short input."},
  "B": {"stance": "supports", "per_predicate": {"affected_construct": {"stance": "supports", "cites": ["K1", "S1"]},
                                                  "missing_or_ineffective_guard": {"stance": "supports", "cites": ["R1", "S2", "J2"]}},
        "why": "The guard compares the input size with the length field, not with the 16-byte name."}
},
"cited_rows": {"J1": {"ref": "asr:guard_fact:ba307124…", "summary": "…"}, "J2": {"ref": "asr:range_fact:9cedee4f…", "summary": "…"}}
```

- **Shuffle.** Which side is A is decided by the low bit of `sha256(manifest_sha256 || claim_id || "judge-order")`. It
  is reproducible for replay and unrelated to role. The side-to-role map is stored in the cell record, never in the
  request. Role names, actor ids, model names and persona names are absent from the request, and a test asserts it
  against the stored request bytes (as R6 does for the verifier).
- **Cited rows.** Labels from the package keep their meaning. A row either side retrieved during its own cell
  (`Q…` labels there) is re-presented under judge-scoped `J…` labels with its bounded resolved content, so a
  citation can be checked without trusting either side's description.
- **Bounds.** Each side's `why` is at most 600 characters; the judge sees at most 12 cited rows per side. Omissions
  are counted and named.
- The judge has the same retrieval tools and in-process loop as every cell, and **must re-check** what it relies on:
  a verdict whose citations it did not either receive in `cited_rows` or retrieve itself is dropped with feedback.

### 3.3 What it answers

The shared compact shape (stance, per-predicate citations by label, bounded `why`) plus a verdict and a reason:

```json
{"action": "final", "result": {
  "claim": "c1",
  "verdict": "B",
  "per_predicate": {
    "affected_construct": {"verdict": "B", "cites": ["K1", "S1"]},
    "missing_or_ineffective_guard": {"verdict": "B", "cites": ["G2", "S2", "R1"]}
  },
  "reason": "The only length check compares input size with the length field. Nothing bounds the length by the 16-byte destination."
}}
```

`verdict` is one of `A`, `B`, `both`, `neither`, `unresolved`. The application de-shuffles it to
`red_correct`, `blue_correct`, `partly`, `neither`, `unresolved` using the stored map. A verdict that names a side
without a resolvable citation becomes `unresolved`.

### 3.4 What the application does with it

1. Records one `judge_verdict` ledger event per claim (closed fields: claim id, de-shuffled verdict, per-predicate
   verdicts, citation refs, `reason` text, cell id, `judge_model_distinct`).
2. Turns the judge's citations into evidence relations to the predicates it ruled on, with provenance
   `adjudication_judge`, under the same admissibility rules. Siding with red on a predicate records `supports` for
   its direct citations; siding with blue records `contradicts`. A citation that is not a direct row records
   `qualifies`.
3. Leaves R5 and R6 unchanged. A judge's relations are inputs like any other; they cannot make a predicate direct.
4. Publishes `judge_verdict` in the finding package and the report. A confirmed claim whose judge sided with blue
   is shown with that disagreement, never hidden.

## 4. PoC candidates

After adjudication, the inference handoff lists `poc_candidates`: every claim that meets **all** of

- R5 state is `supported` or `confirmed`;
- the judge verdict is `red_correct` (`partly` is configurable, default off);
- the claim carries a `poc_basis` whose `entry` and `path` resolved;
- the configured policy asks for developer documentation (default: risk matrix rating in
  `["medium", "high", "critical"]`).

Each entry carries `claim_id`, `package_id`, `state`, `judge_verdict`, `poc_basis` (hash and bounded copy),
`finding_package` (ref) and the evidence refs the claim rests on. Nothing else about the claim is copied.

## 5. `job_poc_generation`

Position: after `job_final_publication_gate`, before `job_final_report_publication`. The report reads the PoC
handoff when present and shows its outcome; when the job is disabled the report keeps its current "not run"
limitation.

### 5.1 Steps

1. **load**: verify the gate and review handoffs from bytes (same helpers as the gate) and read `poc_candidates`.
2. **plan**: per candidate, build the brief from the finding package, `poc_basis`, the labelled package view, the
   struct and function declarations at the sink, and the build facts for the translation unit that contains the sink
   function (compiler, include paths, defines, standard).
3. **write** (model, role `poc_writer`): answers with the compact shape below. The model runs under the same
   no-tools, in-process retrieval loop as the review cells.
4. **validate** (deterministic, fail closed): see 5.3.
5. **compile**: see 5.4. Nothing is linked into an executable and nothing is run.
6. **package**: the reproducer files, the compile record and a developer write-up, with hashes.
7. **publish**: one handoff listing every candidate with its status.

### 5.2 The writer's answer

```json
{"action": "final", "result": {
  "claim": "c1",
  "test_function": {"name": "poc_parse_header_overlong_name",
                    "includes": ["relay/relay.hpp"],
                    "source": "void poc_parse_header_overlong_name() { … }"},
  "negative_control": {"name": "poc_parse_header_name_fits",
                       "source": "void poc_parse_header_name_fits() { … }"},
  "setup": ["a 20-byte name field in the input", "a Header out object"],
  "expected_observation": "a stack-buffer-overflow write to Header::name in memcpy under a sanitizer",
  "breakpoints": [{"function": "relay::parse_header", "line": 16, "why": "the unbounded copy"}],
  "notes": "Add to the unit-test target; build with -fsanitize=address,undefined -g -O0 to observe the fault."
}}
```

- The function has **no `main`**, takes no arguments, returns nothing, and uses only in-memory fixtures.
- The **negative control** is a second function with a safe input that must not trigger the condition, so a
  developer can see the difference in a debugger.
- Source text is bounded (for example 80 lines per function) and stored verbatim as data.

### 5.3 Deterministic validators

Reject (status `policy_denied`) when any of these hold. The model never repairs its way past a validator.

- a definition named `main`, or a second translation-unit entry point;
- calls to process, shell, network, dynamic-loading, file-system or environment APIs, from a closed denylist **and**
  not in a closed allowlist of project and standard-library calls (the allowlist wins, so an unlisted call is
  rejected);
- includes outside the project's own headers and a closed set of standard headers;
- inline assembly, `#pragma`, macros that redefine project names, string literals that look like secrets, URLs or
  paths outside the source tree;
- unbounded loops or recursion, allocation of attacker-sized memory beyond a fixed cap, or constants beyond bounds;
- a function that never calls the sink function named in the brief, or whose trigger values do not appear in the
  source (checked on the clang AST, not by text search);
- size and line limits per function and per file.

The parser is clang (`-fsyntax-only -Xclang -ast-dump=json`) in the build image; the checks run on the AST.

### 5.4 Compile check (build only)

In the build image, in a copy of the accepted source tree (as `job_sanitizer_build` does):

1. Replay the translation unit's compile command from the build command facts, replacing the source with the PoC
   file, adding `-fsyntax-only`. The flags are the project's own (include paths, defines, standard).
2. Compile to an object (`-c`) with the project's flags plus `-g -O0`, and again with the sanitizer flags
   (`-fsanitize=address,undefined -fno-omit-frame-pointer`).
3. Read the object's undefined symbols (`nm -u`) and check each is defined in the project's accepted object files or
   belongs to a closed set of runtime libraries.

Statuses: `compile_verified`, `compile_failed` (the generated code does not build; this does not contradict the
finding), `artifact_generated` (the build image or object files are unavailable, a named gap), `policy_denied`,
`insufficient_evidence` (no usable `poc_basis`), `not_applicable`, `unsafe_to_attempt`.

### 5.5 Output

Under `runs/<run-id>/data/poc/<claim-id>/`: `poc_<name>.cpp` (both functions and the includes), `compile.json`
(commands, exit codes, diagnostics, symbol check), `README.md` (what it shows, where to add it, expected
observation, breakpoints, limitations) and `provenance.json` (hashes of the brief, package, source tree and image).
Published datasets declare every file. The report shows status, a bounded description and the function source in a
PoC box; the full reproducer stays in the run directory for the developer.

## 6. Open questions

1. Whether the judge should also see the verifier's result. Current answer: no, so the verifier stays blind and the
   judge is not anchored on a third opinion.
2. Whether `partly` verdicts should produce a PoC. Default: no.
3. Whether the writer should be a different model from red. Recorded as `writer_model_distinct`; not required.
4. Detecting the target's unit-test framework (from `job_test_coverage`) to emit an adapter snippet around the
   function. Deferred; the first version emits a plain function.
5. Whether a successful compile should additionally be checked by a model reviewer (does the function exercise
   the same path as `poc_basis.path`). The AST check covers the call to the sink function; a reviewer is deferred.

## 8. Decisions taken at implementation (poc job)

Where section 5 left a choice open, `job_poc_generation` took these. They change nothing in sections 1 to 4, and none of
them touches the claim ledger, R5, R6 or the judge. Operating details are in
[`../operations/poc-generation.md`](../operations/poc-generation.md).

1. **The candidate contract.** The job reads `poc_candidates` from the verified review handoff as an array of
   `{claim_id, package_id, state, judge_verdict, poc_basis: {sha256, value}, finding_package: {finding_package_id, sha256},
   evidence_refs}` (schema `docs/schemas/poc-generation/poc-candidate.schema.json`, reader `candidates.py`). `poc_basis.sha256`
   is `sha256(canonical_json(value))` (`review.identity.sha256_hex`). The reader is strict and cross-checks each entry against
   the verified finding package (id, digest, claim, state). A handoff without the field is an older run (named gap
   `no_poc_candidates`, empty valid handoff); a malformed field is an integrity failure. The handoff schema belongs to the judge
   work, so the job validates the review handoff against the existing schema *without* the property (a thin wrapper around the
   closed validator) and validates the property itself; nothing changes when the schema learns the property.
2. **Not a target job; manual while disabled.** The job reads no target tree: the source copy is the run's accepted
   `job_language_build` workspace (re-hashed file by file against its manifest), the compile command is the exact captured argv
   of the sink's translation unit from the protected compile database, and the labelled package view comes from the retrieval
   core pinned to the review's accepted manifest. It is therefore deliberately absent from `launch.TARGET_JOBS` (like the review,
   the gate and the report) and runs with no target root and the `none` source fingerprint. `settings.enabled` (shipped `false`)
   only decides membership in the automatic graphs. Because a finished run's resolved configuration is frozen, a direct dispatch
   of a *disabled* job normally refused by `cli` is allowed for this job alone (`cli.MANUAL_JOB_IDS`), and
   `topology.describe_wave1(..., include=...)` gives it the upstream handoffs it would have in the graph.
3. **Graph position.** Enabled: `job_final_publication_gate -> job_poc_generation -> job_final_report_publication` (one terminal
   job in both graphs). Disabled: the report follows the gate exactly as before. The report reads the run's accepted PoC handoff
   when one exists, re-proves the summary and every file it names, and shows its outcomes in `poc_outcomes`; when none exists the
   block is the previous "not run" text and the report is unchanged. A PoC handoff built from a different gate handoff is stale
   and is reported as such, never shown.
4. **The role is a runtime skill, not an inference role.** Inference role records in `pipeline/guidance/registry.json` are bound
   to `review.models.Role`, which the judge work owns, and the review cell executor (`review.cells.run_cell`) is bound to that
   enum and to manifest-scoped capabilities. `poc_writer` is therefore registered as a role record with a responsibility, its
   body is `pipeline/prompt-fragments/roles/poc_writer.md`, and the guidance (rules, examples, non-examples) is the runtime skill
   `pipeline/skills/poc-writer/SKILL.md` (job-scoped through `load_runtime_skill`). The job reuses the review cells' transport,
   `worker-turn/1` schema, tolerant parsing and recording, and has its own small loop (`writer.py`) with the same denial policy.
   Moving the role into the inference registry later is a mechanical change.
5. **Retrieval.** The writer's two in-process requests are `read_source` and `find_declaration`, served from the hash-verified
   accepted workspace and bounded by lines, bytes, queries and turns. The brief already carries the finding, the `poc_basis` with
   resolved labels, the package view, the declarations at the sink and the safe build facts; retrieval is for the rest.
6. **A decline form.** The answer may instead be `{decline: {status, why}}` with `insufficient_evidence`, `not_applicable` or
   `unsafe_to_attempt`, because section 5.4 lists those statuses but 5.2 gives the writer no way to reach them.
7. **Statuses.** `not_applicable`: the judge verdict is not accepted, or no accepted native build compiled the sink's file.
   `insufficient_evidence`: no usable `poc_basis` (an entry, a path and a trigger), no known sink function (hunt packages have
   none), unresolved labels, or a writer that produced no usable answer. `artifact_generated`: the build image, the accepted
   workspace or the accepted objects were unavailable when the validators or the compile check needed them. `compile_failed`:
   the code did not parse, did not compile, or needs a symbol neither the project nor a runtime library defines.
   `policy_denied` is final: the schema leaves names and sizes loose so the writer cannot repair a `main` away.
8. **Validators on a reduced AST, closed in both directions.** `clang ... -ast-dump=json` is tens of megabytes for a file that
   includes `<string>`, so `ast_reduce.py` (stdlib only, copied into the scratch workspace) runs in the build image around the
   compiler and returns the PoC file's nodes plus the identity of everything they reference; `policy.check_ast` is a pure
   function of that document. Node kinds must be on a closed list; calls and variable references must be on the closed
   allowlist (the allowlist wins; the denylist only names a refused call's category); types must be builtin, project or on the
   type allowlist (which refuses a file stream that has no call to refuse); project calls are the sink and the brief's call path.
   Integer literals are not bounded (integer-overflow triggers need large values); sizes that allocate memory are. A trigger
   constraint without a number cannot be checked on the AST and is recorded, not refused.
9. **Compile commands.** The replayed argv is the exact captured one (the safe build facts redact values and cannot be
   replayed; the brief shows the safe facts). Dependency-file, output, plugin and `-Werror` flags are dropped, the project's
   `-O` and `-g` are replaced for the object compiles, and any project `-fsanitize` is replaced for the sanitizer compile.
   `BuildContainerExecutor` gained a `network` argument (default `bridge`, unchanged for every other job); this job uses
   `none`, since it compiles already-fetched source.
10. **Scratch.** The validate and compile steps each make their own hash-verified copy of the workspace under their unit root
    and remove it afterwards; the two objects are hashed and discarded, so `data/poc/` holds only the four developer files.
11. **Model.** The shipped writer profile reuses the pipeline's existing model so enabling the job adds nothing to the model
    preflight (which walks every job's settings, enabled or not). A stronger writer is a configuration change.
12. **Open.** The judge work must emit exactly the shape of decision 1 (the hash definition in particular). The job rebuilds the
    package view with the same limits as the review cells so the labels in `poc_basis` resolve; if the review changes how
    labels are assigned the plan step reports unresolved labels as `insufficient_evidence` rather than guessing.
