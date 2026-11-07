# Design: SAST-to-Lean Verification and Proof-Directed Fuzzing

**Status:** Proposed design; not implemented by this document  
**Scope:** Milestone 1 (Lean-assisted SAST finding adjudication) and Milestone 2 (proof-directed fuzzing with reusable verified contracts)  
**Repository:** `wsollers/appsec-review`  
**Document role:** Engineering specification and phased implementation plan, not a runtime skill or authorization to execute targets  
**Prepared:** 2026-11-07

## 1. Purpose and concrete outcomes

The objective is to take **a real SAST finding already ingested by appsec-review**, formalize only the program behavior relevant to that finding, and use Lean 4 together with source-aware analysis and isolated dynamic execution to determine whether the alleged violation is feasible.

This is **not** a system for asking an LLM to write an attractive mathematical proof about approximate pseudocode. Every claimed result must be tied to source or binary identity, a documented program semantics, a complete-enough dependency slice, a checked proof or validated witness, and an auditable record of assumptions and gaps.

Two deliverables are in scope:

1. **M1 — SAST-to-Lean adjudicator.** Consume an accepted lead/finding and its exact build, graph, source, and evidence identities. Extract a property-specific semantic slice; generate an explicit security obligation; translate a **restricted supported subset** to Lean; check a theorem, find a candidate counterexample, or return `inconclusive`. Preserve evidence and named gaps.
2. **M2 — Obligation-directed function fuzzing with a reusable container.** For a selected Lean proof obligation that poses an experimentally answerable question, generate a targeted harness around the **actual source function** (and real caller/state setup where necessary), then run bounded Clang/libFuzzer/ASan/UBSan experiments in a pinned container. One operator approval grants an exact investigation envelope; within it, the system automatically seeds, fuzzes, minimizes, replays and refines the model without per-testcase approvals. This is not a generic whole-project/function-discovery fuzzing framework. Keep reusable verified contracts and reserve an optional separate track for stateful network fuzzing.

### Success means

For a supported, pinned target and a supported finding class, the system produces one of:

- **Model safety proof:** A Lean-kernel-checked theorem about an explicit model, with the source-to-model correspondence level accurately described.
- **Source-connected path refutation:** A safely closed path property with adequate dependency coverage and justified semantic connection to the actual program, not merely an LLM conclusion.
- **Model counterexample:** A machine-checkable violating assignment/trace; still a candidate until shown feasible for the real program.
- **Concrete reproduced violation:** A minimized input and deterministic replay in an explicitly authorized isolated lab showing the actual target violates the stated property.
- **Inconclusive:** A typed reason such as an unresolved call, alias, environment dependency, unsupported semantic feature, missing build evidence, unproved translation, proof timeout, or nonreproducible witness.

**Never equate `Lean failed to prove safe` with `the program is vulnerable`. Never equate a safe model with a safe source program unless the correspondence and scope justify that conclusion.** A failed proof initiates dynamic testing **only when there is a concrete, experimentally answerable question**. Missing mathematical lemmas, unsound abstractions and unproved source correspondence do not automatically justify fuzzing.

## 2. Repository baseline and mandatory compatibility

Before implementation, examine the current HEAD and preserve these existing contracts:

| Existing asset | Location | Reuse; do not duplicate |
|---|---|---|
| Inference packages, accepted lead identity, proof obligations | `docs/architecture/review-package-contract.md`; `src/appsec_review/review/` | Source of finding/claim identities and review scope |
| CodeQL source/sink, range, guard and graph index | `docs/architecture/code-graph-precomputation.md`; `src/appsec_review/graph/` | Grounded path candidates, graph facts and coverage |
| Review-package bounded source slices | `docs/architecture/dataflow-bounded-slices.md`; `src/appsec_review/review/slicing/` | Navigation seeds and package-visible slices |
| Proposed graph alias/CFG/layout extensions | `docs/architecture/graph-alias-slice-layout-modes.md` | **Design only**; do not treat as implemented |
| Evidence acceptance and adjudication | `docs/architecture/inference-security-review.md` | R4 predicates, R5 state, R6 independence, ledger and accepted manifests |
| Existing read-only evidence MCP | `docs/operations/retrieval-mcp.md`; `src/appsec_review/mcp/` | Scoped retrieval, not executable command access |
| Native build, Clang/LLVM and sanitizer outputs | `docs/operations/sanitizer-build.md` | Reuse accepted build provenance and instrumented outputs |
| Compile-only PoC generation | `docs/operations/poc-generation.md` | **Never executes generated PoCs**; do not relax this rule |
| Binary evidence | `docs/architecture/binary-decompilation.md` | Future binary track only; existing decompilation evidence is not compilable target source |
| Blind known-vulnerable target procedures | `docs/operations/test-targets.md` | Reuse pinned targets and keep answer keys outside worker view |

**Important distinction:** `package-slice/2` currently selects bounded lines for review *context*. It is **not** a semantically closed, proof-sufficient slice. A new verification slice may reuse its anchors and graph facts, but must establish separate closure and coverage properties. Treat `slice_truncated` and unresolved semantics as inability to certify source safety.

**Existing no-execution boundary:** `job_poc_generation` and `job_sanitizer_build` compile, inspect or prepare artifacts but do **not** execute the target. M2 therefore creates a distinct, manually authorized `formal-fuzz-lab` surface. Do not connect target execution to the normal automatic review graph by default.

**Repository development rules:** Root `AGENTS.md` governs. Respect separate development/runtime skills; all model outputs and target content are untrusted data; use central typed TOML configuration; hash-pin evidence; register datasets; follow multi-session coordination and preserve unrelated work. Documentation changes alone do not authorize integration, acceptance, or live validation.

## 3. System architecture

```text
Existing review pipeline:
  target snapshot + build provenance + CodeQL/SAST/SARIF
                   |
     accepted manifest / package / graph index
                   |
            formal verification planner
                   |
   finding-specific slice + dependency closure
                   |
 property / machine semantics / function summaries
                   |
       Lean model generator + proof obligations
                   |
          Lean kernel / bitvector solver
                   |
       verification receipt + assumptions
              /              \
   property proven       candidate witness
   (with scope)                  |
                         operator-authorized
                         isolated fuzzing lab
                           /          \
                     function harness   protocol adapter
                           \          /
                      replay and minimize
                              |
                   evidence-backed adjudication
                              |
                 reusable verified contract store

Existing R4/R5/R6 adjudication, PoC, gate and final report
remain authoritative unless separately changed and reviewed.
```

### Ownership boundaries

- **Deterministic core:** Verifies hashes/identities, extracts graph facts, checks coverage, validates intermediate representations, runs Lean, parses receipts, assembles immutable outputs, enforces budgets and authorization.
- **LLM assistant:** Proposes security properties, likely aliases/guards, function contracts, proof strategies and harness candidates. It cannot declare a proof verified or bypass a validator.
- **Lean proof checker:** Determines whether the theorem follows from the stated definitions, lemmas and assumptions. `#print axioms` and dependency audit must identify `sorryAx`, unreviewed axioms and other trust dependencies.
- **Independent dynamic lab:** Executes explicitly admitted targets under bounded conditions and records actual behavior; runtime evidence is not proof of universal absence of a bug.
- **Existing reviewer/adjudicator:** Consumes *qualified* formal/dynamic evidence via the normal evidence rules. The new system must not rewrite claim states directly.

## 4. M1 — SAST-to-Lean adjudication

### 4.1 Entry conditions and job selection

Accept two controlled entrypoints:

1. **From an accepted SAST lead:** `run_id`, immutable accepted manifest SHA, `package_id`, exact `lead_observation_id`, and rule/class identifiers. This is the primary way to test whether a vulnerability can be established **from ingestion** before an LLM reviewer labels it.
2. **From an accepted review claim:** The same source-bound identity plus its `claim_id`, security predicate, supporting/contradicting refs and review status. This enables targeted escalation of difficult already-adjudicated findings.

Do not accept an arbitrary source path or free-form SARIF file as privileged proof input. Ad hoc SARIF must first go through the accepted scanner ingestion path and immutable run binding. Every attempted lead, including unsupported ones, receives one accountable status.

Deterministic candidate selection:
- Initially admit only C/C++ cases with a successful, source-matched native build and resolvable CodeQL/Clang evidence.
- Rank by accepted finding metadata and supported property family, not by model confidence alone.
- Cap attempts per run and record every deferred lead with `budget_exhausted` or `unsupported_class`.
- Never hide scanner misses: distinguish **no ingested lead** from **lead ingested but verifier inconclusive**.
- Pin a verification attempt to one source commit, target snapshot, toolchain and accepted manifest; changed input means a new attempt.

### 4.2 V1 property families and explicit exclusions

Start with deliberately narrow, meaningful goals:

| Family | Example obligation | Initial semantics required |
|---|---|---|
| `integer_wrap_bounds` | Input accepted implies the byte count fits destination capacity | Unsigned BitVec arithmetic, comparisons, branch conditions, length checks |
| `index_and_copy_bounds` | Every reachable load/store/copy extent stays within a known bounded object | Constant or symbolically bounded arrays, offsets, strides, byte extent |
| `guard_path_feasibility` | The flagged sink is unreachable under an exhaustive guard/return chain | CFG, dominators, conditions, supported callees |
| `simple_authorization` | Reaching protected sink implies validated principal matches required owner | Straight-line and finite-state logic, explicit request/session fields |

M1 expressly does **not** claim full support for arbitrary pointer aliasing, concurrency, time-of-check/time-of-use, dynamic linking, unmodeled virtual dispatch, generic heap lifetimes, uncontrolled I/O, hostile OS states, arbitrary C/C++ undefined behavior, or arbitrary external libraries. Unsupported constructs produce formal coverage gaps, not guessed semantics.

**C/C++ semantics warning:** Do not model all integer operations as convenient mathematical integers. Track exact widths, signedness, casts, promotions, optimizer-sensitive undefined behavior, `poison`/`undef` in LLVM where applicable, pointer provenance, layout, and endianness. If an operation's semantics cannot be represented soundly, stop or add a conservative overapproximation. In particular, an unsigned wrap example cannot be copied unchanged as a claim about signed-overflow C behavior.

### 4.3 Finding-to-property compiler

Build a **closed, versioned property-template registry** keyed by supported rule families / CWE and a small set of exact sink kinds. A template contains:

- Affected instruction or source sink identity and expected safe behavior.
- Trusted input/origin boundary, admissible initial states and relevant environment assumptions.
- Security event predicate: e.g., `ReadOOB`, `WriteOOB`, `UnauthorizedRead`, `ReachBadSink`.
- Universally quantified safety statement and its existential violation dual.
- Applicable runtime checks and a mapping from counterexample variables to concrete test inputs.
- Required facts and minimum semantic capabilities; no template may silently degrade to a weaker property.

Representative obligations:

\[
  \mathrm{Safe} \equiv
  \forall s,\; \mathrm{Reachable}(s) \to \neg\mathrm{Bad}(s).
\]

\[
  \mathrm{Witness} \equiv
  \exists s,\; \mathrm{Reachable}(s) \land\mathrm{Bad}(s).
\]

For authorization, clarify whether the property concerns the entry-time session, the session at the sink, or a post-serialization consumer; do not reuse a check from one time or principal as a guarantee at another.

Each template records where a **property mismatch** (wrong notion of ownership, missing terminating byte, assumed buffer capacity, etc.) would invalidate an argument.

### 4.4 Semantic slice construction and closure

Build `VerificationSliceBuilder` **on top of existing retrieval and graph identities**; do not make an unrestricted on-demand source crawler available to agents.

Algorithm for each target sink:

1. Resolve accepted exact sink and source-file hashes, native build unit, compile flags and relevant graph facts.
2. Seed backward data and control dependencies from sink operands, guard predicates and memory objects; use the existing package slice and CodeQL path as navigational hints.
3. Add reaching definitions, relevant branches, alias targets, function parameters/returns, global reads/writes, side effects, error exits, object size/layout, loop invariants and candidate indirect callees.
4. For each call edge, use a verified summary **only if** its exact assumptions, calling context, type/layout and source identity apply. Otherwise expand the callee or model the unresolved behavior nondeterministically.
5. Close all security-relevant dependencies under the chosen property. Track open-world dispatch and missing code distinctly.
6. Use **property-driven refinement**: when a candidate counterexample is spurious because the abstraction omitted constraints, expand just the relevant facts and retry.
7. Enforce caps (nodes, edges, functions, bytes, expansion rounds). If a cap interrupts semantic closure, the result cannot support a global safety conclusion.

Proposed per-node metadata: `source_id`, file SHA-256, source range, compilation-unit identity, AST/IR position, kind, width/type, declaration/definition link, dependencies, side effects, extraction basis, provenance, coverage state. A separately typed summary explains every omitted callee or dependency.

**Key invariant:** Every concrete security-violating path covered by the claimed analysis scope must have a representation in the abstract slice. An arbitrary call-depth bound never proves that invariant.

Store both:
- **Context slice** (bounded excerpts, suitable for model reading).
- **Verification slice** (dependency/semantic graph and explicit closure proof obligations, suitable for formal reasoning).

These may differ substantially in size.

### 4.5 Source-aware semantic translation

Do not translate arbitrary decompiled C-like prose or ask a model to invent C semantics. Implement a **small typed intermediate representation** as the interface between supported source/LLVM analyses and Lean.

V1 IR requirements:

- `Bool` and `BitVec(width)`, comparison signedness, arithmetic operations, bitwise ops, zero/sign extension, truncation, selects.
- Basic blocks and conditional branches with predecessor/successor identities.
- SSA values and supported phi nodes.
- Finite arrays/buffers, object identity, byte offsets, lengths and loads/stores for explicitly modeled memory objects.
- Function inputs, return values, preconditions, postconditions and relevant side effects.
- Calls represented by an expanded body, a checked contract, or a conservative unknown-effect summary.
- Explicit nondeterminism, undefined/unsupported operations and environmental assumptions.
- Stable source-to-IR provenance; semantic frontend/tool versions pinned in the receipt.

Start with a restricted C/C++ frontend using Clang-produced build/IR facts where available. Avoid a claim of fully certified C or LLVM-to-Lean translation. Emit **translation obligations** and a machine-checkable traceability manifest from original operations to model operations. Validate model traces against concrete execution when possible, but mark this as testing evidence, **not a proof of equivalence**.

A future verified frontend or per-function refinement proof may upgrade correspondence from `assumed` to `checked`. Until then, a Lean proof is at most a **model proof / conditional source claim**.

### 4.6 Lean semantics, contract format and checker

Create a versioned Lean project within the verification tool image. Minimum library modules:

```text
AppSecVerify/
  Semantics/Values.lean
  Semantics/Memory.lean
  Semantics/ControlFlow.lean
  Semantics/Transitions.lean
  Security/Predicates.lean
  Security/Reachability.lean
  Abstraction/Soundness.lean
  Contracts/Hoare.lean
  Contracts/Composition.lean
  Generated/<attempt-id>/Model.lean
  Generated/<attempt-id>/Obligations.lean
```

The generator must emit definitions from validated IR, not executable untrusted directives. A separate proof agent may suggest a theorem body, but only the checked resulting Lean artifact has meaning.

Required checker behavior:
- Use pinned Lean 4/mathlib versions and lockfile; capture kernel and package identities.
- Check generated files with the actual Lean elaborator/kernel.
- Inspect `#print axioms` and imported dependencies; reject `sorryAx`, self-asserted target theorems, unchecked `axiom` declarations, and disallowed extensions of the trusted base.
- Prefer kernel-checked `bv_decide` proofs for bitvectors. External SMT or CBMC results are **hints/counterexample candidates** unless their proofs are imported and checked under a documented trusted path.
- Prevent model-generated `unsafe` or arbitrary import/IO/macro metaprogramming from bypassing the generation/checking boundary; compile in a resource-constrained sandbox in all cases.
- Record proof term/theorem qualified name, normalized statement, imports, axiom audit, exit status, time and digest.
- For timeouts or unchecked dependencies, emit `unknown`, not `proved`.

Reusable summary format is a Hoare-style contract:

\[
 \{\mathrm{Requires}(s)\}\; f \;\{\mathrm{Ensures}(s,s')\}
\]

with `modifies`/frame conditions, exact source hash, build/ABI assumptions, and proof level. A callee contract is admissible only when its preconditions and state effects are discharged at the caller.

### 4.7 Proof and counterexample states

Use **two orthogonal fields**, rather than one overloaded “verified” flag:

1. **Logical result:** `proved_safe_model`, `witness_in_model`, `unsat_path_model`, `proof_failed`, `timeout`, `unsupported`, `unknown`.
2. **Source correspondence:** `checked`, `assumed`, `tested_only`, `open`, `unsupported`.

Concrete reproduction is a **third** independent status: `not_attempted`, `reproduced`, `not_reproduced`, `unstable`, `lab_failed`, `policy_denied`.

An actual source-level safety conclusion requires (a) an appropriate universal property, (b) a sound overapproximation/coverage argument, (c) a justified semantic correspondence, and (d) environmental assumptions matching the claim. A single path-refutation conclusion applies **only to that path**, not automatically to all paths to the sink.

A model counterexample can be spurious. For an actual implementation vulnerability, demand a feasible witness anchored to the source/execution assumptions and, in M2, concrete reproduction where possible. A bounded search that finds no witness establishes only its bounded scope.

### 4.8 M1 evidence record

Publish immutable protected attempts with a minimal schema family:

- `formal-request/1`: parent accepted run/manifest/package/lead/claim, scope, property template, intent.
- `formal-slice/1`: typed nodes/edges, closure state, omitted deps, semantics gaps, resolution roots.
- `formal-obligation/1`: theorem and violation dual, quantified input model, preconditions/environment.
- `formal-translation/1`: source/IR/model traceability, transformation decisions, tool versions, correspondence status.
- `formal-proof/1`: Lean compilation, axiom audit, lemma dependencies, proof status, theorem artifact digest.
- `formal-witness/1`: symbolic assignments/trace, constraints, source mapping, feasibility/validation.
- `formal-attempt/1`: aggregate identity, completion/gap counts, dispositions and artifact refs.

All records must be JSON Schema-validated, bounded, deterministic, and content-addressed. Store raw proof files and secret-bearing data as protected run-owned artifacts; disclose only sanitized summaries through the existing report gate.

Example **proposed record** (not an existing API):

```json
{
  "schema": "appsec-review/formal-attempt/1",
  "attempt_id": "sha256:<digest>",
  "input": {
    "run_id": "<accepted-run>",
    "accepted_manifest_sha256": "<sha256>",
    "package_id": "<package-id>",
    "lead_observation_id": "<observation-id>",
    "target_snapshot_sha256": "<sha256>"
  },
  "property": "integer_wrap_bounds",
  "logical_result": "witness_in_model",
  "source_correspondence": "open",
  "reproduction": "not_attempted",
  "proof_ref": "<run-owned-ref>",
  "witness_ref": "<run-owned-ref>",
  "gaps": ["source_to_model_correspondence_unproved"]
}
```

The exemplar's `witness_in_model` is **not** an automatically confirmed security finding.

### 4.9 M1 operator interface (proposed, not implemented)

Build as a **detached, operator-invoked sidecar first**. Avoid changing the normal Dagster completion graph and publication gate until the experiment has meaningful results.

```text
appsec-review formal-verify plan --run-id RUN --lead-id LEAD
appsec-review formal-verify check --plan-id PLAN
appsec-review formal-verify inspect --attempt-id ATTEMPT
```

Commands accept **logical identities** validated against the accepted manifest, not arbitrary host paths. They write a new immutable attempt and never mutate the original finding status.

Later, after M1 acceptance, an optional `job_formal_verification` may consume accepted review packages; that requires separate graph, dataset, configuration, gate and schema integration work with its own tests. Do not claim it exists yet.

## 5. M2 — Proof-directed fuzzing and contract reuse

**M2 design decision (revised):** The **Lean proof obligation** is the unit of work—not the whole SAST finding, not every function in the slice, and not an unrestricted fuzz target. One ingested finding may yield multiple obligations; only those requiring concrete information about a specific reachable implementation path are eligible for function fuzzing. Use **one reusable Clang/libFuzzer/sanitizer container** and produce a **different function/caller harness, oracle, seed set and evidence receipt for each selected obligation**. Lean guides *what question to ask*; the fuzzer observes *what the actual function does*; checked proofs still determine universal statements about the model.

```text
SAST finding -> property-specific slice -> Lean obligations
                                   |
                          attempt static proof
                           /             \
                     discharged      unresolved
                                         |
                               concrete question?
                                /         \
                               no         yes
                               |           |
                          proof/model   generate targeted
                          work item     real-function harness
                                            |
                                    confirm bounded operator
                                    investigation admission
                                            |
                              Clang/libFuzzer/ASan/UBSan container
                                            |
                              coverage / behavior / crash / oracle
                                            |
                              same-fault minimization + clean replay
                                            |
                                model refinement + Lean recheck
                                            |
                                qualified evidence/adjudication
```

**No generic fuzzer is being developed.** Reuse libFuzzer's existing mutation/coverage engine; build only the deterministic, question-directed harness, input encoder, isolation runner, oracle, observation pipeline and Lean feedback. A reusable **network protocol session driver** may be built as a later separate, internally isolated profile and is not part of core M2 completion.

### 5.1 Inputs from M1

The M2 planner consumes only an immutable, validated M1 attempt and its accepted build custody. It may use:

- A model witness (`n`, flags, lengths, branch decisions, expected bad state).
- Path constraints and negated guards obtained from a supported solver.
- Boundary conditions derived from a proved property (zero, maximum, wrap threshold, off-by-one).
- A caller contract's precondition boundary or a callee contract violation hypothesis.
- Optional known-good and known-bad corpus samples owned by the test suite, **not** answer keys visible to the model.

It must map every symbolic value to a **concrete controllable input** (buffer bytes, command argument, file contents, or structured protocol message), recording an encoding and any remaining uncontrolled values. If no valid input encoding exists, issue `witness_not_concretizable` rather than inventing one.

#### Obligation triage and experiment request

Fuzz only `candidate_witness`, `observable_guard_question`, `input_boundary_question` or `model_discrepancy_replay`. The planner must distinguish these from a stuck proof due to missing lemmas, unsupported language/ABI semantics, or an unproved model-to-source mapping; the latter produce `not_experimentally_answerable` without executing anything.

Every proposed `formal-experiment-request/1` must include: `run_id`, `accepted_manifest_sha256`, `lead_observation_id`, `formal_attempt_id`, **`obligation_id`**, exact function symbol/source and build hashes, relevant real caller chain, valid preconditions, a specific testable hypothesis, typed input encoding/constraints, witness/boundary seeds, negative control, oracle, branch/coverage focus, and an operator admission reference. No arbitrary function discovery, raw commands, host paths or network destinations.

Example: If Lean cannot establish whether a length-check guard makes a copy safe, derive valid inputs immediately below, at and above the accepted threshold and capture the **actual function's** branch decisions and memory effects. If a model witness does not map to a valid caller-controlled argument, report `witness_not_concretizable`; do not invent impossible state.



### 5.2 Harness generation

Initially support **C/C++ function-level harnesses** for parsing and length-checking functions. Generate the smallest wrapper that uses the real target function and a fixed, documented setup:

**The target is always the original function compiled from the exact accepted source snapshot**, not a Lean-inspired C reimplementation. Model guidance may generate the wrapper, argument decoder and oracle, but cannot replace the function under test. Include the smallest *actual caller* when preconditions, globals, allocations or authentication/session state cannot be established at the callee boundary. Validate legitimate entry conditions and object lifetimes; harness-created invalid states and harness crashes are not evidence of a target defect.



- Input adapter: `uint8_t *data, size_t size` or an explicitly typed decoded structure.
- Deterministic state reset and teardown for every input; no dependence on previous fuzz cases.
- Fixed-size bounded allocations; no outside resources by default.
- A checkable oracle: sanitizer signal, assertion from a property, error-code mismatch, or state invariant.
- Seeds: model witness and boundary variants, plus a negative control and a small valid seed.
- Compile/relink against the exact accepted target build interface and record any adapter assumptions.
- AST-based and binary-symbol validation before acceptance; never run unvalidated model-generated shell commands.

Recommended source harness pattern (illustrative only):

```cpp
extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t *data, size_t size) {
  TargetState state = make_clean_test_state();
  Result actual = target_parse(&state, data, size);
  check_declared_security_invariant(actual, state, data, size);
  destroy_test_state(&state);
  return 0;
}
```

**Primary required tool profile:** pinned Clang + libFuzzer + SanitizerCoverage + AddressSanitizer/UndefinedBehaviorSanitizer. Reuse accepted sanitizer build custody when link-compatible; otherwise rebuild the **original source function** in a separate isolated workspace, recording all changed flags and assumptions. AFL++ is an optional alternative for a particular selected target, not a second general fuzzing framework. Do not mislabel a GCC sanitizer object as a Clang libFuzzer target without validating link/runtime compatibility. Keep branch/edge coverage and observed state changes tied to the exact obligation; a clean campaign is not proof of safety.

The generated harness is **not** the existing compile-only PoC: do not pass it to `job_poc_generation` for execution or change the no-run policy of that job.

### 5.3 Separate opt-in execution lab

**The ordinary review graph remains non-executing; the function-fuzzing container is a required part of this M2 design.** The operator explicitly authorizes a **bounded investigation envelope** for one accepted target/finding, selected obligations and functions, pinned image, allowed build/fuzz/minimize/replay operations, total run/time/resource limits and network profile. Within that envelope, the deterministic controller may **automatically run multiple generated inputs, minimization and clean replay without new approvals**. It revalidates admission and remaining quota for every subrun. An AI model cannot extend the target, function, caller, network, commands or budget; changing scope requires a new admission.

Build the isolated lab with these requirements:

- Only user-owned or expressly authorized targets from an allowlisted, immutable input snapshot.
- Explicit authorization attached to each admitted attempt (target digest, runner profile, allowed operations, duration and resource budget, optional network mode).
- No Docker socket or broad host filesystem mounts; no host networking, privileged mode, ambient credentials, public Internet or production target connectivity.
- Rootless/non-root where possible; dropped capabilities, `no-new-privileges`, read-only root, bounded writable scratch, cgroup CPU/memory/PIDs, seccomp/LSM policy when supported.
- Execution filesystem is a **copy of the admitted snapshot**; project source and accepted evidence stay read-only.
- Build tooling can be hostile even before a fuzz loop runs; apply equivalent isolation to generated build steps.
- Per-input and campaign timeouts, input bytes and output bytes caps, no infinite auto-retry.
- Kill and account for the entire process tree after completion or timeout.
- Protected capture of stdout, stderr, sanitizer stacks, exit/signal, process-map details when available, exact seed, target/build/image hashes.

Proposed first two profiles:

| Profile | Behavior | Network |
|---|---|---|
| `function_sanitized` (**required core M2**) | Original-function harness, Clang/libFuzzer/ASan/UBSan | None |
| `protocol_isolated` (**later separate extension**) | Structured application-protocol driver in a dedicated container network | Only lab-internal service and driver |

**Defer raw-socket injection, kernel stack fuzzing, privileged network namespaces and Internet-facing tests.** An application-layer protocol sequence adapter can be included in M2 after the function harness is proven. Packet-level networking and binary-only execution are later tracks needing separate authorization and safety designs.

### 5.4 Fuzzer and replay stages

```text
validated witness/seed plan
        |
harness compile + static policy checks
        |
operator admission
        |
bounded fuzz campaign (sanitizers, coverage, oracle)
        |
candidate artifacts
        |
minimize preserving the same failure predicate
        |
fresh-process deterministic replay (minimum 3 repeats)
        |
triage: reproduced / unstable / model_only / infrastructure_error
        |
immutable evidence, independent review, optional regression seed
```

Minimization must preserve the **same property or sanitizer signature**, not simply any crash. For structured protocols minimize both the number of messages and their field contents; sessions/nonces must be regenerated correctly. A PCAP alone is not necessarily replayable TCP/TLS state.

Define a *reproduction receipt* with:
`testcase_sha256`, `target_snapshot`, `harness_sha256`, `image_digest`, `compile_flags`, `seed`, `fuzzer_version`, `environment`, `oracle_id`, `expected`, `observed`, `minimization_steps`, `replay_attempts`, `replay_successes`, `coverage`, `sanitizer_reports` and exact protected log refs.

No claim of reproducibility without a clean reset and repeat against the **original accepted implementation**, rather than only the handwritten Lean model or a reimplemented function.

#### Evidence feeding formal verification

Add `formal-observation/1` with the selected `obligation_id`, test input digest, exact target function/source/harness identities, covered branches, state/return observations, expected outcome from the Lean model, actual outcome, sanitizer/oracle signature, and the challenged model assumption. The **feedback loop** is: observe -> compare with formal prediction -> expand the relevant slice or correct a model assumption -> generate a new hash-pinned Lean attempt -> recheck the theorem. Do not treat one or millions of clean tests as a universal proof.

Stop on a properly scoped proven theorem, a reproduced real violation, exhausted admission, absent meaningful coverage progress, unconstructible valid inputs, or a question that cannot be answered experimentally. Every outcome—including `no_failure_observed` and `proof_still_open`—is recorded without upgrading to `source_safe`.


### 5.5 Reusable verified contract registry

Create an immutable, content-addressed contract store within accepted evidence, not a global unversioned theorem cache.

Each contract must record:

| Item | Required record |
|---|---|
| Identity | Source hash, symbol and signature, build unit, ABI, compiler/toolchain assumptions |
| Statement | Lean `requires` / `ensures` / `modifies`, security property, quantified scope |
| Proof | Checked theorem, trusted dependencies, axiom audit, toolchain and proof digest |
| Correspondence | Source-to-model mapping, coverage status, tested/assumed/checked level |
| Use conditions | Exact preconditions, aliasing, object lifetime, global/environment state |
| Dependencies | Called contracts and transitive source/toolchain hashes |
| Disposition | `valid_for_this_context`, `conditional`, `stale`, `revoked` |

Contract lookup may narrow search, but cannot silently assume the caller satisfies `requires`. For every reuse, emit new caller-side proof obligations and check frame conditions and relevant state mutation.

Invalidate or mark stale when source, compilation flags, layouts/ABI, assumptions, callee contracts, or semantic frontend changes. If a proof establishes only model safety, store it as a model-level contract; never promote it to source-certified reuse by repetition.

### 5.6 Findings and feedback to the existing review

M2 findings can create independent evidence relations only after validators resolve their references to exact source or run artifacts. Runtime traces do not become self-authorizing accepted claims.

- Link `formal_attempt_id` and `fuzz_attempt_id` back to the original `lead_observation_id` and optional `claim_id`.
- Preserve the original scanner observation unchanged.
- Model witness alone: candidate/qualifier, **not** direct confirmation.
- Replayed violation: new protected execution evidence, subject to R4/R5/R6 and independent verification.
- Proven path infeasible: scoped contradiction to that path, not an automatic claim that no vulnerability exists.
- Missing/failed execution: named gap.
- Final report: a sanitized summary of certified outcomes, never raw witness bytes, exploit source or private harness artifacts.

Do not modify R5/R6 policy or existing publication gates as part of the prototype. Any future gate integration is its own versioned design and test milestone.

## 6. MCP and skill contracts

Do **not** expose a model-writable Docker shell or a network socket factory.

### 6.1 Read-only retrieval available to reviewers

Propose typed, bounded, versioned capabilities behind the existing MCP authorization and exact run scope:

| Proposed tool | Input | Output |
|---|---|---|
| `query_formal_candidates` | accepted run + bounded lead filters | supported candidates, refs, coverage |
| `query_formal_slice` | exact attempt/slice identity, cursor | grounded slice nodes and unresolved dependencies |
| `query_formal_proof` | exact attempt/proof identity | theorem statement, logical result, axiom audit, gaps |
| `query_formal_contracts` | exact symbol/build identity, limit | applicable contract refs and preconditions |
| `query_formal_reproduction` | exact admitted fuzz attempt | sanitized outcome, replay status and evidence refs |

Existing `query_code_graph` remains the graph retrieval authority. New capabilities return only accepted/precomputed records; they must never execute analyses on demand during inference retrieval.

### 6.2 Operator-only mutation/execution

Operator interfaces (CLI or separately authenticated privileged service) would admit `formal-verify plan/check` and `formal-fuzz admit/prepare/run/replay`. Authorization covers a fixed **investigation envelope**, not every test input; a deterministic runner may run a bounded sequence of approved per-obligation experiments automatically and must recheck scope/quota on every operation. Log every decision and return immutable job IDs. **Do not grant admission or privileged execution tools to inference workers.**

A runtime worker skill, if needed, must live only under `pipeline/skills/formal-verification/SKILL.md` and be registered in `pipeline/guidance/registry.json` with allowed roles. It describes how to interpret result types and cite evidence, **not** how to bypass authority or run targets. Development instructions belong separately in `.claude/skills/` under the repository's existing separation rules.

## 7. Proposed repository changes

These are **to be implemented**, not existing paths or shipped capabilities.

```text
src/appsec_review/
  formal_verification/
    __init__.py
    intake.py             # accepted manifest / lead binding
    candidate.py          # supported-class classifier
    property_registry.py  # closed security-property templates
    slice.py              # property-specific semantic dependency closure
    semantics_ir.py       # typed IR, validation and serialization
    frontend.py           # supported Clang/IR lowering
    correspondence.py     # mapping/coverage obligations and audit
    lean_generate.py      # IR -> Lean modules, no free-form execution
    lean_check.py         # pinned tool, kernel and axiom verification
    witness.py            # model assignment / trace and feasibility
    contracts.py          # reusable contracts and caller obligations
    custody.py            # immutable output, identity and hashes
    schemas.py            # strict contracts, no ad hoc JSON
  fuzz_lab/
    __init__.py
    obligations.py        # classify experiment-eligible Lean questions
    planning.py           # per-obligation seeds/constraints and input mapping
    harness.py            # actual source function + caller, AST validation
    build.py              # target/harness custody and instrumentation
    admission.py          # investigation authorization and quota enforcement
    execution.py          # restricted container runner, no model shell
    coverage.py           # relevant branch and behavior feedback
    feedback.py           # observed behavior -> Lean model recheck
    oracle.py             # question-specific safety/sanitizer conditions
    minimize.py           # same-fault reduction
    replay.py             # clean-process repeat
    protocol.py           # later separately authorized network driver
    custody.py
  mcp/
    # extend existing read-only retrieval registry and schemas

docs/
  formal-verification/
    lean-guided-verification-conversation.md
    sast-to-lean-and-proof-directed-fuzzing.md    # this design
  schemas/
    formal-verification/
      formal-request.schema.json
      formal-slice.schema.json
      formal-obligation.schema.json
      formal-translation.schema.json
      formal-proof.schema.json
      formal-witness.schema.json
      formal-attempt.schema.json
      formal-contract.schema.json
      formal-experiment-request.schema.json
      formal-lab-admission.schema.json
      formal-observation.schema.json
      formal-fuzz-plan.schema.json
      formal-fuzz-result.schema.json

containers/tools/
  lean-verifier/       # pinned Lean 4/mathlib, restricted compiler runner
  formal-fuzz/         # required pinned Clang/libFuzzer/ASan/UBSan runner

tests/
  formal_verification/ # fast isolated unit/contract regression tests
  fuzz_lab/            # runner-independent policy and oracle unit tests
  fixtures/
    formal_verification/ # synthetic paired vulnerable/safe C samples

pipeline/skills/
  formal-verification/SKILL.md   # only when explicitly registered
```

Additional integration edits once individual components work: `src/appsec_review/cli.py`, typed configuration parsers, `appsec-review.toml`, image catalog/policy, schema registrations, run dataset declarations and custody validators, job dispatch/graph **only if separately approved**, read-only MCP schema/capability bindings, ledger relation consumers, and documentation/operations pages.

Do not create unregistered `runs/` files or bypass the existing accepted-manifest and dataset reconciliation machinery.

## 8. Configuration and resource budgets

Use strict typed, versioned, centralized config in `appsec-review.toml`. Do not scatter options through model prompts. **Suggested prototype defaults** (subject to implementation validation):

| Control | Initial proposed default |
|---|---|
| Feature enabled in ordinary review runs | `false` |
| Operator-invoked verification allowed | Explicit CLI action on accepted run |
| Maximum candidates per invocation | 10 |
| Slice nodes / call expansion | 2,000 nodes / 4 rounds; truncation is a gap |
| Max generated Lean file bytes | 1 MiB per attempt |
| Lean CPU / memory / timeout | 2 CPUs / 4 GiB / 120 seconds per obligation |
| Function fuzzing | Required M2 container; no execution before bounded admission |
| Authorization granularity | One target/finding, specific obligations/functions, pinned image; no per-input approvals |
| Campaign limit | 4 admitted campaigns initially, counted globally across obligations |
| Lean model refinement | 2 bounded feedback cycles per selected obligation |
| Fuzzer duration | 60 seconds per admitted campaign initially |
| Per-test input cap | 64 KiB |
| Fuzz lab CPU / memory / PIDs | 2 CPUs / 4 GiB / 256 |
| Replay attempts | 3 with clean reset |
| Network access | `none`, except dedicated internal lab profile |
| Raw packets or host network | Disabled / out of scope |

Use existing container admission, policy, image identity and signing infrastructure; these are *resource planning values*, not evidence that host-specific images or permissions already exist. Frozen review configurations stay unchanged. Tool and compiler versions must be pinned before acceptance.

## 9. Phased implementation work packages

The order below intentionally builds **one usable end-to-end path** before expanding tool coverage.

### M1 work packages

| ID | Exact build work | Dependency | Required completion evidence |
|---|---|---|---|
| **F0** | Baseline repository state and applicable schemas; choose first supported CWE and pinned known-vulnerable C target | None | Inventory and immutable target/run/lead IDs; documented gaps |
| **F1** | Accepted-lead/claim resolver and candidate planner | F0 | Rejects fake IDs, stale hashes, missing source/build; handles real accepted lead |
| **F2** | Property registry with safety and existential witness duals | F1 | Two synthetic positive/negative unit pairs per first class |
| **F3** | Semantic slice closure and typed missing-dependency report | F1 | Correct guards, def-use and calls; no false closure on truncation/alias gaps |
| **F4** | Restricted source/IR frontend with validated widths/control flow | F2,F3 | Compiler-grounded fixtures, supported/unsupported matrix, traceability |
| **F5** | Lean semantics/translation/checker and axiom gate | F4 | Real Lean theorem check and witness model; `sorry`/axiom bypass rejected |
| **F6** | Immutable attempt schema, CLI/report projection and contracts v1 | F5 | Byte-hash verification, clean retry identities, honest verdicts |
| **F7** | Blind accepted-ingestion experiment and evaluation harness | F6 | Pinned result table for supported positives/controls, all unknowns counted |

**M1 definition of done:**
- A real SAST lead from a pinned target travels through the accepted ingestion path, creates a property-specific slice and an actual checked Lean artifact, and returns an auditable outcome.
- A real *supported* positive case produces a checked violating model assignment or a valid source-connected witness with explicit translation caveats.
- A *supported* negative control demonstrates either a properly scoped, justified infeasibility/safety proof or an honest `inconclusive` if the source correspondence cannot be established.
- No unsupported or truncated case is reported as fully source-proven safe.
- Existing pipeline findings, PoC compilation, gate and report remain unchanged.

### M2 work packages

| ID | Exact build work | Dependency | Required completion evidence |
|---|---|---|---|
| **P1** | Classify experiment-eligible Lean obligations and generate typed testable questions, valid inputs and boundary seeds | M1 F6 | Only selected obligations fuzzed; missing lemma produces no-run result |
| **P2** | Generate real-function/required-caller harness with preconditions, reset, seeds and specific oracle | P1 | Harness compiles against pinned original implementation; invalid setup rejected |
| **P3** | Build required Clang/libFuzzer/ASan/UBSan container and bounded investigation admission/quota supervisor | P2 | One authorized envelope permits automated subruns; wrong target/function denied |
| **P4** | Obligation-specific libFuzzer driver with source branch/edge, sanitizer and property-oracle observations | P3 | Observations trace to original source and exact Lean obligation |
| **P5** | Same-fault minimization, clean replay, observation-to-Lean refinement/recheck | P4 | Minimum reproducer + 3-replay receipt; model discrepancy creates new checked attempt |
| **P6** | Proof contract cache, transitive invalidation and caller obligations | M1 F5 | Valid contract reuse; changed source/assumptions invalidate reuse |
| **P7** | Read-only MCP evidence lookup and report integration proposal | P5,P6 | Capability denies execution and cross-run refs; no R5/R6 bypass |
| **P8** | Optional **separate later** application-protocol driver and session replay | P5 | Internal-network-only authorized sequences; not a core M2 gate |
| **P9** | Blind corpus comparison and regressions | P5,P6 | Reproductions on original target and matched negative controls |

**M2 definition of done:**
- At least one real ingested finding yields several Lean obligations, but only an **experimentally answerable** one triggers targeted fuzzing.
- The required container executes a **real original source function** with valid caller state; one bounded operator admission covers its automatic seed/fuzz/minimize/replay/refinement loop without per-testcase prompts.
- Branch/coverage/state observations are attached to the exact obligation and fed to a new, separately checked Lean model attempt; clean fuzz cases never certify source safety.
- No generalized function discovery or whole-application fuzzing engine is needed for the milestone.

- An ingested finding can lead to a model witness, generated concrete seed, policy-validated harness, **authorized** bounded fuzz run and deterministic replay against the original source-built target.
- A sanitizer error is distinguished from a security-property violation; both are evidence with a specified oracle.
- A minimal failing input and negative control are preserved, with exact hashes/flags/images/seed and retry counts.
- A verified contract can be reused only when its preconditions and source identity hold, and is invalidated correctly on edits.
- A worker with read-only MCP privileges cannot initiate target execution.
- The existing compile-only PoC job remains never-executed.

## 10. Validation against known-vulnerable projects

The user's existing known-vulnerable projects are the primary evaluation targets. Do **not** train or prompt a review worker with its own answer key.

Repository-supported targets already include:

- **`appsec-multi-vuln`** and the separate **`appsec-multi-vuln-guide`** answer key. Follow `docs/operations/test-targets.md` and its pinned commits.
- **Case-094** (seven documented defects and seven paired negative controls in the external evaluation guide), appropriate for paired false-positive/true-positive experiments.
- **CASTLE-C250** as a later, larger blind generalization target; do not claim M1 coverage across all of it.

The evaluator guide lives **outside the reviewed repository and all model/worker mounts**. Only an evaluator after the attempt finishes may join results to the ground truth. The known target's README, comments and metadata must not leak the answer key into the inference prompt. When the user supplies additional projects, pin legal target ownership/authorization, commit, build instructions, vulnerability version, fixed version and independently curated ground truth outside review scope.

### 10.1 Construct three complementary test tracks

| Track | Input | Measures |
|---|---|---|
| **A — Actual ingestion** | Real scanner/SARIF, accepted CodeQL graph and accepted review packages | End-to-end ability to start with a scanner lead and establish/refute it |
| **B — Directed known-location** | A fixed evaluator-selected sink and allowed source identity, still through an accepted synthetic test observation | Ability of formal system to analyze a case **when scanner did not produce a lead** |
| **C — Metamorphic/paired tests** | Vulnerable/fixed versions or close negative controls, with hidden labels | Spurious proof detection, overbroad claims, regression and generalization |

Track B must **not** be pooled into “found from SAST” scores. Report scanner recall (A) separately from verifier conditional performance (A/B).

### 10.2 Ground-truth case record (evaluator-only)

Maintain outside target, model and review mounts:

```json
{
  "case_id": "paired-length-check-001",
  "target_commit": "<commit-sha>",
  "fixed_commit": "<commit-sha-or-null>",
  "category": "integer_wrap_bounds",
  "expected": "vulnerable",
  "affected_source_ref": "<evaluator-only>",
  "expected_trigger_class": "input-length-wrap",
  "negative_control_case_id": "paired-length-check-001-fixed",
  "source": "curated-evaluator-guide"
}
```

Record whether the known defect is **applicable and triggerable** in the compiled test environment. A known CVE or vulnerable revision alone does not prove a particular harness can exercise the bug.

### 10.3 Evaluation procedure

1. Freeze the target commit, accepted run, tool images, property templates, prover toolchain, budgets and permitted test profiles.
2. Choose a class-balanced predeclared set of positives/controls. Start with supported cases from existing pinned paired corpora; don't quietly drop hard cases after inspecting outcomes.
3. Execute **ordinary ingestion** in the existing pipeline only when the operator explicitly authorizes that review.
4. Blindly run the sidecar formal verifier on every qualifying accepted lead; record no-lead, ineligible, failed and unknown outcomes separately.
5. Under an explicitly authorized investigation envelope, automatically run **only selected obligation-specific** fuzzing, clean replay and bounded Lean-feedback cycles; no general function-wide campaign is implied.
6. Freeze receipts before looking up expected labels in the evaluator guide.
7. Compare case-level results by weakness, proof status, source correspondence, reproducibility, false-safe rate, budgets and effort.
8. Repeat with fixed-version counterparts; inspect any bug witness that also fires on the control.
9. Record **confusion matrices plus abstentions**, not one flattering “accuracy” number.

### 10.4 Metrics and proposed acceptance gates

Record per case: `lead_ingested`, `lead_correlated`, `slice_closed`, `source_correspondence`, `model_result`, `concrete_reproduced`, `replay_rate`, `confirmed_weakness`, `false_safe`, `false_alarm`, `inconclusive_reason`, `elapsed_seconds`, `CPU_seconds`, `tokens`, and evidence completeness.

**M1 minimum demonstration (not a statistical generalization claim):**
- At least **two** supported vulnerable cases yield checked model witnesses with correct source assumptions, and at least **two** matched controls yield checked scoped refutations/safety arguments; if full correspondence is unavailable, status must remain conditional.
- **Zero** incorrect unconditional “source safe” conclusions on the pinned positive set.
- **100%** of attempted cases receive a final typed result and a complete/gapped coverage record.
- A tampered source hash, missing accepted lead, open alias, `sorry` dependency, or incomplete slice fails closed.

**M2 minimum demonstration:**
- At least **two distinct** supported vulnerable cases produce a minimized, **three-times replayable** violation against the actual admitted target.
- Matching controls are tested with the same harness and oracle and do not display that violation in the tested scope.
- Unauthorized, out-of-scope or over-budget execution is rejected; multiple permitted test inputs and retries under one valid investigation admission proceed without new per-input approval.
- Missing sanitizer, failed harness compilation, timeouts and nondeterminism are classified as gaps, never as safe.

The initial minimums establish that the path works; they do not imply acceptable coverage for all CWE classes. Before rollout, score a held-out set of known-vulnerable projects and report confidence intervals and class-level tradeoffs. Do not tune to a blind test set after seeing its labels.

## 11. Negative and failure-mode tests that must exist

### Trust and soundness

- A hand-written Lean model with an omitted unsafe branch must **not** certify source safety.
- A proof with `sorry`, a forbidden user axiom, unreviewed trust dependency or self-assumed theorem must be rejected.
- A satisfying model assignment on an impossible concrete path must remain **model witness only**.
- Truncated slice, unresolved indirect call, uncertain alias, unmodeled global state, unknown object size or missing compilation flags must prevent unconditional safety.
- Integer promotion, signed overflow, narrowing, alignment, object boundaries, endianness and optimizer-sensitive transformations must be checked or explicitly unsupported.
- A proved single path not reachable must not suppress a finding supported by another path.
- A failed/absent source analyzer must not be silently replaced by lexical source-text reasoning.
- A failed Lean proof without a concrete experimental question does not launch fuzzing; a clean campaign cannot establish source safety.
- A harness must invoke actual source, not an AI-authored imitation, and must not manufacture invalid caller states.

### Custody and execution policy

- Changed source commit or tool/image digest invalidates prior proof/corpus reuse.
- Cross-run, cross-target and unaccepted evidence refs are refused.
- Generated harness cannot call shell, use production credentials, connect outside the lab, or touch the host filesystem.
- Model instructions embedded in source strings or decompiled text are treated as data.
- Running without authorization, expanding a target/function/network scope, or exhausting a budget is denied; internal authorized repeats are allowed and accounted.
- Resource exhaustion, timeout, partial logs, sanitizer-runtime absence, build failure, and flaky replay preserve a failure or gap status, not a pass.
- Negative controls and the evaluator guide cannot be read by verification workers; evaluation is a separate role/process.

### Test placement and execution policy

Write fast isolated unit tests under `tests/formal_verification/` and `tests/fuzz_lab/`; use repository-configured `test/tmp/<session>` for disposable outputs. Each unit test must satisfy root `AGENTS.md`'s under-10-second expectation and pass alone, shuffled and in bounded parallel. Mark integration and live Docker/fuzz experiments as manual/operator-authorized; **do not run them automatically** as a change gate. Documentation-only changes require documentation checks, not an automatic test run.

## 12. Evidence acceptance and reporting

A report should provide a separate, auditable answer to each of:

1. **What did SAST report?** Scanner, rule, flow, sink, artifact and exact revision.
2. **What property was checked?** Quantified safety and bad-event predicates, threat/environment scope.
3. **What code was actually modeled?** Full slice manifest, contracts, unresolved edges, memory/ABI model.
4. **What did Lean prove?** Statement, proof digest, axiom audit and translation assumptions.
5. **If a counterexample exists, is it executable?** Input mapping and concrete replay against the actual target.
6. **What can be concluded?** Explicit path-level vs property-level scope; separate model and source confidence; any unresolved obligations.
7. **What should the developer do?** Fix location, safe regression check, or precise remaining investigative step.

Recommended final vocabulary:

| Label | Meaning |
|---|---|
| `MODEL_PROVEN_SAFE` | Kernel-checked theorem for a stated model only |
| `SOURCE_PROPERTY_PROVEN` | Proof plus fully justified source correspondence and scope |
| `PATH_INFEASIBLE_SCOPED` | One exact alleged path ruled out under recorded assumptions |
| `MODEL_WITNESS` | Lean/solver model violates an abstract property |
| `CONCRETE_VIOLATION_REPRODUCED` | Observed original-target violation under authorized repeatable execution |
| `CONDITIONAL` | Outcome depends on unproved source/environment premises |
| `INCONCLUSIVE` | Coverage, semantics, proof, time or environment cannot decide |

No “clean program” or “false positive” label is emitted from `MODEL_PROVEN_SAFE` alone. An observed crash without demonstrated property impact is not automatically a confirmed exploitable vulnerability.

## 13. Operational sequencing and rollback

- **First PR:** only M1 F0–F2 and small paired fixtures; no Docker executor or job graph changes.
- **Second PR:** semantic slice, IR/Lean checker, immutable proof receipts and strict axiom tests.
- **Third PR:** offline accepted-lead end-to-end evaluation, including at least one real vulnerable and one negative case.
- **Fourth PR:** M2 per-obligation question selection, real-function harness, required Clang/libFuzzer container and bounded investigation policy; denied-execution tests first.
- **Fifth PR:** authorized automatic bounded fuzz/minimize/replay, observation-to-Lean feedback and initial contract reuse.
- **Later PR:** optional read-only MCP retrieval, gated report projections, protocol adapter and job graph integration.

At each stage: maintain exact branch ownership, coherent commits, focused unit tests and honest gap accounting. If a new component fails, disable the new feature without modifying accepted SAST evidence, existing final gate, original PoC implementation, or existing source identities. Never replace a prior accepted attempt in place; create a new immutable attempt.

## 14. Deferred research (explicitly not M1/M2)

- Sound arbitrary C/C++ to Lean translation across full compiler and C++ semantics.
- Full application proofs, OS/network-stack global properties and concurrent race proofs.
- Machine-code P-code/VEX semantics and formal correspondence to executable instructions.
- Binary-only Ghidra-to-Lean pipeline and AFL++ QEMU/Frida runs against old games.
- General-purpose function discovery/whole-application fuzzing, Internet-facing penetration testing, privileged raw packet injection, kernel-level protocol fuzzing.
- Auto-triage that changes existing R5/R6 finding status or automatically executes generated PoCs.
- Claims of general vulnerability detection rate or exploitability from tiny demonstrations.

Those are valuable later directions, but must not be prerequisites for a working source-level milestone.

## 15. Open decisions for the first implementation PR

Resolve these using actual first-case evidence, and record the decision in a follow-up ADR rather than silently choosing:

1. Exact initial C/C++ weakness family (recommend unsigned length multiplication/truncation plus bounds checks).
2. Whether the first frontend uses an LLVM IR subset, restricted Clang AST subset or a combination, and exactly which constructs it proves semantically faithful.
3. Whether CBMC is used in the first vertical as a witness generator; its bounded/no-witness result must never substitute for unbounded Lean proof.
4. How the existing accepted source/build custody supplies a compiler-ready isolated fixture without granting model-written execution commands.
5. Which initial positive/negative cases from the blind known-vulnerable projects have resolvable scanner leads and compatible builds.
6. An isolated application-protocol session driver follows successful core function-level M2 and requires separate authorization; it is not required for M2 acceptance.
7. When a future sound translation/link proof can upgrade `source_correspondence` to `checked`.

These decisions do not block creating the M1 skeleton, data model, tests, and first genuine end-to-end experiment.

## 16. References

### Existing appsec-review authorities

- [Repository AGENTS.md](../../AGENTS.md)
- [Inference security review](../architecture/inference-security-review.md)
- [Review-package contract](../architecture/review-package-contract.md)
- [Code-graph precomputation](../architecture/code-graph-precomputation.md)
- [Dataflow-bounded slices](../architecture/dataflow-bounded-slices.md)
- [Graph alias/slice/layout proposal](../architecture/graph-alias-slice-layout-modes.md)
- [Sanitizer build operations](../operations/sanitizer-build.md)
- [Compile-only PoC operations](../operations/poc-generation.md)
- [Retrieval MCP operations](../operations/retrieval-mcp.md)
- [Test targets and blind evaluation](../operations/test-targets.md)
- [Binary decompilation](../architecture/binary-decompilation.md)
- [Conversation transcript](lean-guided-verification-conversation.md)

### Upstream technical documentation

- Lean mathlib `bv_decide`: <https://leanprover-community.github.io/mathlib4_docs/Lean/Elab/Tactic/BVDecide.html>
- CBMC bounded model checking: <https://www.cprover.org/cbmc/>
- LLVM libFuzzer: <https://llvm.org/docs/LibFuzzer.html>
- AFL++ documentation: <https://aflplus.plus/docs/>
- CodeQL documentation: <https://codeql.github.com/docs/>
- Clang AddressSanitizer: <https://clang.llvm.org/docs/AddressSanitizer.html>
- Clang UndefinedBehaviorSanitizer: <https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html>

---

**Design acceptance rule:** A successful proof of an attractive model is insufficient; the system succeeds only when the claim it makes matches the exact semantics, coverage, provenance and evidence it has actually established.
