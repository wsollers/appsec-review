---
title: "Design: SAST-to-Lean Verification and Proof-Directed Fuzzing"
kind: "history"
subsystem: "review inference and guidance"
status: "historical"
jobs: ["job_poc_generation", "job_sanitizer_build"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Design: SAST-to-Lean Verification and Proof-Directed Fuzzing

**Status:** Proposed design; not implemented by this document  
**Scope:** Milestone 1 (Lean-assisted SAST finding adjudication) and Milestone 2 (proof-directed fuzzing with reusable verified contracts)  
**Repository:** `wsollers/appsec-review`  
**Document role:** Engineering specification and phased implementation plan, not a runtime skill or authorization to execute targets  
**Prepared:** 2026-11-07

**Revision:** Design-review corrections; assurance gates G0-G4 below govern rollout

The file-level implementation sequence, job contracts, run-owned paths, container definitions,
MCP tools, and runtime-guidance changes are specified in the companion
[buildout plan](buildout-plan.md).

## 1. Purpose and concrete outcomes

The objective is to take **a real SAST finding already ingested by appsec-review**, formalize only the program behavior relevant to that finding, and use Lean 4 together with source-aware analysis and isolated dynamic execution to determine whether the alleged violation is feasible.

This is **not** a system for asking an LLM to write an attractive mathematical proof about approximate pseudocode. Every claimed result must be tied to source or binary identity, a documented program semantics, a complete-enough dependency slice, a checked proof or validated witness, and an auditable record of assumptions and gaps.

Two deliverables are in scope:

1. **M1 — SAST-to-Lean adjudicator.** Consume an accepted lead/finding and its exact build, graph, source, and evidence identities. Extract a property-specific semantic slice; generate an explicit security obligation; translate a **restricted supported subset** to Lean; check a theorem, find a candidate counterexample, or return `inconclusive`. Preserve evidence and named gaps.
2. **M2 — Obligation-directed function fuzzing with a reusable container.** For a selected Lean proof obligation that poses an experimentally answerable question, generate a targeted harness around the **actual source function** (and real caller/state setup where necessary), then run bounded Clang/libFuzzer/ASan/UBSan experiments in a pinned container. One operator approval grants an exact investigation envelope; within it, the system automatically seeds, fuzzes, minimizes, replays and refines the model without per-testcase approvals. This is not a generic whole-project/function-discovery fuzzing framework. Keep reusable verified contracts and reserve an optional separate track for stateful network fuzzing.

### Success means

For a supported, pinned target and a supported finding class, the system produces one of:

- **Model safety proof:** A checked theorem about an explicit model, with its `kernel_only` or `approved_native` assurance and source-to-model correspondence accurately described.
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

1. **Producer-stage request (`entry_kind = producer_lead`):** `run_id`, immutable upstream accepted manifest SHA, exact scanner/build/graph handoff and shard hashes, `lead_observation_id`, and rule/class identifiers. No `package_id` or `claim_id` is required or permitted. This request can precede package assembly; the manifest must contain all required upstream producers but cannot depend on this formal attempt or downstream indexing.
2. **Post-review request (`entry_kind = review_claim`):** Exact accepted package/index manifest, `package_id`, `claim_id`, original lead/source/build identities, security predicate, evidence refs and review status. This is a standalone escalation against a completed package; it cannot be used as input to a producer that precedes that package in the same graph generation.

Both entry kinds use a discriminated request schema. Bind the producer manifest separately from a later consumer/index manifest; do not resolve either through a moving latest pointer during an attempt. The first detached experiment may consume a completed run's accepted producer artifacts without requiring a review claim. Optional ordinary-graph integration uses only `producer_lead`.

Do not accept an arbitrary source path or free-form SARIF file as privileged proof input. Ad hoc SARIF must first go through the accepted scanner ingestion path and immutable run binding. Every attempted lead, including unsupported ones, receives one accountable status.

Deterministic candidate selection:
- Initially admit only C/C++ cases with a successful, source-matched native build and resolvable CodeQL/Clang evidence.
- Rank by accepted finding metadata and supported property family, not by model confidence alone.
- Cap attempts per run and record every deferred lead with `budget_exhausted` or `unsupported_class`.
- Never hide scanner misses: distinguish **no ingested lead** from **lead ingested but verifier inconclusive**.
- Pin a verification attempt to one source commit, target snapshot, toolchain and accepted manifest; changed input means a new attempt.

### 4.2 V1 property families and explicit exclusions

The first implemented subset is `local_copy_bounds/1`, specializing `index_and_copy_bounds`: a single nonrecursive C/C++ function with fixed-width unsigned scalar inputs, constant-size local byte arrays, initialization, supported comparisons/guards/returns, and an exact recognized `memcpy` operation. The first property checks both source-read and destination-write extents. Require disjoint live objects, known initialization, and exact length conversion to the pinned ABI's `size_t`; reject any unmatched AST construct. Use the paired example in section 10.5.1 only after measuring its real scanner alerts.

Exclude loops, heap allocation, pointer arithmetic beyond this recognized copy, indirect calls, user-defined conversions, exceptions, recursion, volatile/atomic operations, and external state from this initial subset. No caller assumption is needed for a safety theorem quantified over every value of the declared unsigned input type. A vulnerability witness still needs a legitimate input route before implementation-level confirmation. Broader families below are expansion targets, each requiring its own semantics and certificate extension after G2:

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

### 4.3.1 Assumption ledger and vacuity checks

Every premise has a stable ID, formal proposition, provenance, affected scope, owner, and one of `discharged`, `external_guarantee`, or `unresolved`, with resolving evidence. Distinguish caller preconditions, language-definedness obligations, environment restrictions, and abstraction assumptions. A source-safety certificate requires discharged premises or explicit independently established guarantees matching the advertised scope; guessed caller bounds remain conditional.

Check that the admitted initial-state predicate is satisfiable and retain a checked witness. An empty entry domain is `vacuous_entry_scope`, not successful safety certification. A deliberately unreachable sink is valid only when proved unreachable from that nonempty admissible entry domain. Check that the violation predicate is the exact logical dual over the same domain, transitions and bad event. Reject circular premises that assume the target property; prove caller obligations without importing the callee safety conclusion as an assumption.

Mandatory regressions include contradictory assumptions, an assumed copy bound never established by callers, omitted input values, a false initial-state predicate, and sink unreachability confused with impossible function entry. Satisfiability alone does not establish that premises cover the actual program; the correspondence certificate supplies that separate obligation.

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

### 4.4.1 Loops, recursion, and correctness scope

The first subset rejects loops and recursion. Later support must define transition semantics and prove invariant initialization, preservation on every iteration, and safety of intermediate operations, including abnormal exits. Unrolling or interpreter fuel exhaustion yields `bounded_only`/`unknown`; it must never become a successful terminating execution or an unbounded safety theorem. A bounded property records its bound in both theorem and public scope.

Contracts declare `partial_correctness` or `total_correctness`. A postcondition on returning executions does not establish absence of bad intermediate events, termination, or availability. Total correctness requires a termination argument. Recursive or mutually recursive summaries require a checked induction/fixed-point rule and explicit strongly connected dependency groups; circular reuse of unproved contracts is rejected. Resource exhaustion and liveness are separate properties, outside initial certification.

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

Correspondence is `checked` only through the certificate below. Before that checker and its soundness theorem exist, all generated Lean results remain model-only or conditional. Traceability, JSON schema validation, source hashes and matching test traces cannot substitute for this certificate.

### 4.5.1 Initial semantics and undefined behavior

Use a restricted Clang AST frontend for `local_copy_bounds/1`, before optimizer transformations. Preserve the exact preprocessed translation unit, included-file closure, compiler version, flags, target triple and ABI. Match every relevant AST node against the closed supported grammar and reject unmatched constructs. LLVM/graph facts provide navigation and corroboration; optimized IR is not the source-safety semantics authority for this subset.

Define source execution as an explicit transition system that emits `ReadOOB` or `WriteOOB` at the offending copy operation **before** undefined behavior. Unknown/unsupported behavior must remain an explicit gap or a sound overapproximation. Never assume absence of UB to prove the memory-safety property under investigation. Evaluate source and destination extents separately, preserve integer promotions/conversions, and discharge pointer validity, lifetime, initialization and non-overlap obligations. A `memcpy` summary cannot assume its own bounds precondition and thereby erase the alleged violation.

Any future LLVM path must record the extraction/pass stage and handle `poison`, `undef`, `freeze`, and immediate UB explicitly. Attributes such as `inbounds`, `nsw`, `nuw`, `nonnull`, and `noundef` are not automatically source facts: their preconditions must be established or the claim restricted. An optimizer may remove a UB-triggering source path; disappearance in optimized IR cannot refute a source finding. Changes to the semantic authority or supported grammar require a versioned certificate extension.

### 4.5.2 Source-correspondence certificate and verdict acceptance

Add `formal-correspondence/1`, binding the exact source/preprocessed/AST, verification slice, IR, generated Lean definitions, property template, assumption ledger, supported-subset version, build identity and proof assurance profile. The initial trusted base explicitly includes the pinned source parser/extractor and its source-to-AST binding, the certificate checker, the formal source semantics and the accepted Lean checking path. This is a claim about the selected source-language semantics/configuration, not a proof of parser, compiler, executable, other build configurations or whole-program correctness.

The certificate contains these separately checked obligations; a status flag cannot replace their resolving receipts:

| Obligation | Required evidence and checker |
|---|---|
| Property binding | Closed rule/sink/template matcher binds the alleged event, input quantification and exact violation dual; the registry owns the statement |
| Source binding and supported grammar | Trusted extractor binds all preprocessed source bytes and AST identities; a separate structural validator checks complete function-body coverage, guards, returns, widths, conversions, object declarations and copy arguments against the restricted grammar |
| Initial states | Checked relation maps every concrete admissible entry state to a model entry state; the assumption ledger and non-vacuity witness establish the advertised input domain |
| Transition preservation | A Lean-checked generic lowering theorem for the supported AST semantics, instantiated with a validated per-function derivation, establishes forward simulation (including explicit stuttering where justified) into the IR/model |
| Bad-event preservation | Checked lemma establishes that each concrete scoped bad event has a corresponding abstract bad event; unsupported operations cannot disappear from the trace |
| Slice completeness | Checked derivation accounts for every relevant branch, effect and dependency; initial V1 models the complete supported function body, with no heuristic pruning |
| Premises and dependencies | All caller/environment/frame obligations are discharged or independently guaranteed for the exact scope; all dependent contracts and certificates are current and unchallenged |
| Final theorem | Independently accepted proof of the fixed universal model property under an eligible assurance profile, bound to the same definitions and certificate hashes |

The application derives `SOURCE_PROPERTY_PROVEN` only when **all** rows pass and the certificate carries no unresolved, truncated, bounded-only, contradicted or revoked dependency. The source claim records the trusted base and exact property/configuration scope. For the initial source-certification gate, require `kernel_only` proof assurance. An `approved_native` result remains eligible for model evidence but cannot silently satisfy this gate.

A structural validator must not be the same lowering code merely reporting its own success. Retain a derivation that can be checked independently against the accepted AST and generic semantic theorem. If the first implementation cannot provide this path, G0/G1 may pass but G2 remains unmet; `SOURCE_PROPERTY_PROVEN` stays unavailable. Tests of a translator are useful validation, never a replacement for the stated simulation argument.

### 4.6 Lean semantics, contract format and checker

Create a versioned Lean project within the verification tool image. Minimum library modules:

```text
AppSecVerify/
  Semantics/Values.lean
  Semantics/Memory.lean
  Semantics/ControlFlow.lean
  Semantics/Transitions.lean
  Correspondence/LocalCopyBounds.lean
  Correspondence/Certificate.lean
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
- Treat `bv_decide` as an approved-native candidate mechanism unless the pinned implementation demonstrably produces a proof accepted by the kernel-only profile below. External SMT or CBMC results are **hints/counterexample candidates** unless their proofs are imported and checked under a documented trusted path.
- Prevent model-generated `unsafe` or arbitrary import/IO/macro metaprogramming from bypassing the generation/checking boundary; compile in a resource-constrained sandbox in all cases.
- Record proof term/theorem qualified name, normalized statement, imports, axiom audit, exit status, time and digest.
- For timeouts or unchecked dependencies, emit `unknown`, not `proved`.

#### Proof assurance profiles and independent acceptance

Record `proof_assurance` independently of logical result, source correspondence, and reproduction:

- `kernel_only`: the complete proof dependency closure uses only the explicitly approved logical axioms (initial allowlist: `propext`, `Classical.choice`, `Quot.sound`) and passes independent kernel replay. Native-computation axioms, `sorryAx`, unchecked declarations and arbitrary user axioms are rejected.
- `approved_native`: the pinned Lean compiler/runtime and specific audited native-evaluation procedures additionally enter the trusted base. Record every generated native axiom and its exact statement, origin and toolchain; never allow arbitrary axioms by a wildcard name. This profile is model evidence, not initial G2 source certification.
- `unaccepted`: failed, incomplete, unaudited or unsupported checking; no proved verdict.

Lean's `bv_decide` may verify SAT certificates using native computation and introduce native axioms; it must not be described as kernel-only solely because a Lean build succeeds. The exact behavior depends on the pinned release. Pin and test the axiom policy for that release, including legacy `Lean.trustCompiler` and newer per-computation axioms. If needed, replay certificate checking through kernel reduction or another explicitly validated kernel-only path; do not assume a cached certificate removes native trust.

Generate the challenge theorem and all referenced definitions in a trusted application stage. Elaborate untrusted proof candidates in the existing sandbox with a closed syntax/tactic/options allowlist; reject arbitrary elaborator hooks and kernel-check-disabling options. Outside that candidate process, validate exported artifacts, compare the elaborated theorem/type and definition closure against the trusted challenge, independently replay the proof, and audit transitive axioms. Use a pinned compatible `lean4checker`/`comparator` path or an equivalent documented checker; record its identity and limitations. Neither stdout text, a pretty-printed statement nor an axiom audit performed only inside the candidate process is acceptance evidence. Add forged-receipt, changed-definition, disabled-kernel-check and native-axiom regressions.

Reusable summary format is a Hoare-style contract:

\[
 \{\mathrm{Requires}(s)\}\; f \;\{\mathrm{Ensures}(s,s')\}
\]

with `modifies`/frame conditions, exact source hash, build/ABI assumptions, and proof level. A callee contract is admissible only when its preconditions and state effects are discharged at the caller.

### 4.7 Proof and counterexample states

Keep logical result and source correspondence separate, rather than one overloaded “verified” flag:

1. **Logical result:** `proved_safe_model`, `witness_in_model`, `unsat_path_model`, `proof_failed`, `timeout`, `unsupported`, `unknown`.
2. **Source correspondence:** `checked`, `assumed`, `tested_only`, `open`, `unsupported`.

Concrete reproduction is another independent status: `not_attempted`, `reproduced`, `not_reproduced`, `unstable`, `lab_failed`, `policy_denied`.

Also record `proof_assurance`, `correctness_scope`, explicit bounds and current validity; none is inferred from the other status fields. An actual source-level safety conclusion requires (a) an appropriate universal property, (b) a sound overapproximation/coverage argument, (c) a justified semantic correspondence, and (d) environmental assumptions matching the claim. A single path-refutation conclusion applies **only to that path**, not automatically to all paths to the sink.

A model counterexample can be spurious. For an actual implementation vulnerability, demand a feasible witness anchored to the source/execution assumptions and, in M2, concrete reproduction where possible. A bounded search that finds no witness establishes only its bounded scope.

### 4.8 M1 evidence record

Publish immutable protected attempts with a minimal schema family:

- `formal-request/1`: discriminated producer-lead or post-review request with exact upstream identities, scope, property template and intent; package/claim fields belong only to post-review requests.
- `formal-slice/1`: typed nodes/edges, closure state, omitted deps, semantics gaps, resolution roots.
- `formal-obligation/1`: theorem and violation dual, quantified input model, preconditions/environment.
- `formal-translation/1`: source/IR/model traceability, transformation decisions, tool versions, correspondence status.
- `formal-proof/1`: Lean compilation, independent replay, challenge comparison, assurance profile, axiom audit, lemma dependencies, proof status, theorem artifact digest.
- `formal-correspondence/1`: source-binding, grammar, simulation, bad-event, closure and premise certificates.
- `formal-assumption-ledger/1`: formal premises, provenance, discharge/guarantee status, scope and non-vacuity evidence.
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
    "entry_kind": "producer_lead",
    "lead_observation_id": "<observation-id>",
    "target_snapshot_sha256": "<sha256>"
  },
  "property": "index_and_copy_bounds",
  "semantic_subset": "local_copy_bounds/1",
  "logical_result": "witness_in_model",
  "source_correspondence": "open",
  "proof_assurance": "kernel_only",
  "reproduction": "not_attempted",
  "proof_ref": "<run-owned-ref>",
  "witness_ref": "<run-owned-ref>",
  "gaps": ["source_to_model_correspondence_unproved"]
}
```

The exemplar's `witness_in_model` represents a separately checked violating assignment under the recorded assurance profile; it is **not** an automatically confirmed security finding. Raw solver assignments without that check remain witness candidates.

### 4.9 M1 operator interface (proposed, not implemented)

Build as a **detached, operator-invoked sidecar first**. Avoid changing the normal Dagster completion graph and publication gate until the experiment has meaningful results.

```text
appsec-review formal-verify plan --run-id RUN --lead-id LEAD
appsec-review formal-verify check --plan-id PLAN
appsec-review formal-verify inspect --attempt-id ATTEMPT
```

Commands accept **logical identities** validated against the accepted manifest, not arbitrary host paths. They write a new immutable attempt and never mutate the original finding status.

After G2, an optional `job_formal_verification` may be integrated before indexing using only producer-stage requests; enabling it requires a separate G4 rollout decision. Post-review package/claim requests remain standalone. Graph integration requires separate graph, dataset, configuration, gate and schema integration work with its own tests. Do not claim it exists yet.

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

Every proposed `formal-experiment-request/1` must include: `run_id`, `accepted_manifest_sha256`, `lead_observation_id`, `formal_attempt_id`, **`obligation_id`**, exact function symbol/source and build hashes, relevant real caller chain, valid preconditions, a specific testable hypothesis, typed input encoding/constraints, witness/boundary seeds, negative control, oracle, branch/coverage focus, and a stable request digest. Planning cannot require an admission that does not yet exist: the later admission binds this request digest, and execution receipts bind both. No arbitrary function discovery, raw commands, host paths or network destinations.

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

#### Instrumentation, oracle calibration and coverage

Before treating a campaign as informative, run a separate known-failing calibration fixture for the selected sanitizer/oracle under the same toolchain/runtime policy. This is a tool-health positive control, not evaluator truth or a vulnerability seeded into the target. A negative control alone cannot show that detection works. Record both controls separately from target results and exclude calibration runs from target discovery metrics.

Bind the analyzed build and instrumented reproduction build separately, including changed optimization flags, sanitizer options/recovery behavior, linked objects, runtime versions and source mappings. Validate instrumentation at the admitted target function and relevant operation, not only that a sanitizer library was linked. Attribute faults to the target, adapter or calibration fixture. A sanitizer signal is not automatically the selected security-property violation.

Publish obligation-specific `sink_reached`, branch/operation coverage, oracle-health and instrumentation-coverage evidence, including uninstrumented dependencies. Distinguish `target_sink_not_reached`, `oracle_unavailable`, `instrumentation_gap`, `no_violation_observed`, and `violation_observed`. An optimized-away operation is a named coverage gap, not a successful negative result. Three replays establish repeatability only for the recorded build/input/reset; they do not establish source-to-binary equivalence or universal safety.

The generated harness is **not** the existing compile-only PoC: do not pass it to `job_poc_generation` for execution or change the no-run policy of that job.

### 5.3 Separate opt-in execution lab

**The ordinary review graph remains non-executing; the function-fuzzing container is a required part of this M2 design.** The operator explicitly authorizes a **bounded investigation envelope** for one accepted target/finding, selected obligations and functions, pinned image, allowed build/calibrate/fuzz/minimize/replay operations, total run/time/resource limits and network profile. Within that envelope, the deterministic controller may **automatically run multiple generated inputs, minimization and clean replay without new approvals**. It revalidates admission and remaining quota for every subrun. An AI model cannot extend the target, function, caller, network, commands or budget; changing scope requires a new admission.

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

#### Atomic admission accounting and interruption

Admission validation and quota reservation are one durable atomic operation scoped to the admission ID. Each compile, calibration, fuzz, minimize and replay operation has an idempotency key, reserved worst-case resource allowance, durable state and execution lease. Concurrent workers cannot spend the same remaining quota; retries cannot create a second execution for the same key. Account actual use on completion and release unused reservation only after the supervisor verifies termination. After a crash, reconcile the process/container identity before retrying or releasing quota; uncertain consumption stays reserved or conservatively charged.

Specify `requested -> reserved -> running -> completed/failed/cancelled` transitions and crash-recovery receipts. Expiry or revocation prevents new reservations; cancellation/revocation signals the supervisor to terminate active process trees and retain partial evidence. Campaign time limits and the admission deadline also constrain minimization and replay. Admission records stay immutable; revocation and quota events are append-only. Admission identity/authentication implementation may vary, but these semantics cannot be deferred.

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

#### Contradictions and transitive invalidation

A feasible accepted observation apparently contradicting a current source certificate immediately records `challenged` and suspends new use of that certificate and its dependent contracts pending deterministic lineage checks and independent adjudication. Classify wrong build/scope, invalid harness/oracle, model mismatch, translation defect, and actual certificate failure separately. A confirmed certificate failure records `revoked`; an invalid challenge records a resolving disposition rather than deleting the challenge.

Add append-only `formal-invalidation/1` events binding the challenged attempt/certificate, observation, reason, review disposition and transitive dependency closure. Maintain reverse dependencies to identify affected contracts, packages and published reports. New consumers reject challenged/revoked dependencies. Historical manifests and proofs remain immutable; an operator-visible affected-publication list drives a new accepted index/package/report generation with a visible correction. Historical readers display the pinned result as historical and disclose later invalidation when available; current validity uses a separately authenticated immutable checkpoint with its own hash/as-of identity alongside the proof manifest; they cannot present it as current certification without the current validity view. Superseding an attempt is not revocation by itself and cannot conceal a soundness failure. No automatic target execution or downstream review launch is implied.

### 5.6 Findings and feedback to the existing review

M2 findings can create independent evidence relations only after validators resolve their references to exact source or run artifacts. Runtime traces do not become self-authorizing accepted claims.

- Link `formal_attempt_id` and `fuzz_attempt_id` back to the original `lead_observation_id` and optional `claim_id`.
- Preserve the original scanner observation unchanged.
- Model witness alone: candidate/qualifier, **not** direct confirmation.
- Replayed violation: new protected execution evidence, subject to R4/R5/R6 and independent verification.
- Proven path infeasible: scoped contradiction to that path, not an automatic claim that no vulnerability exists.
- Missing/failed execution: named gap.
- Final report: a sanitized summary of certified outcomes, never raw witness bytes, exploit source or private harness artifacts.

#### Versioned formal-evidence admission

Define a `formal-evidence-admission/1` adapter before integrating formal rows into review. A new index family or generic artifact reference does not itself satisfy existing predicates. The adapter validates exact claim/sink, property, scope, correspondence certificate, assurance profile, premises, current validity and resolving artifacts, then emits only the relations allowed below:

| Result | Permitted effect under the adapter |
|---|---|
| Model theorem or abstract witness | Context/conditional evidence only; no direct source predicate or finding closure |
| Source-certified universal copy-bounds theorem | Scoped contradiction to the matching bounds/ineffective-guard allegation; does not refute another property or another build |
| Source-certified path infeasibility | Contradicts reachability of that exact path only; other paths remain open |
| Replayed original-target violation | Direct support only for observed affected construct, exercised path and the exact failed property after harness/input/oracle validation; attacker control requires separate evidence of a legitimate controllable entry route |
| Build/configuration custody | Supports only the configuration facts its structured receipt establishes |
| Failed, unknown, challenged or revoked result | Gap or invalidation; no supporting safety conclusion |

Each property family must instantiate this table with exact existing predicate IDs and support/contradiction polarity; unmatched mappings default to non-counting. Impact remains derived under existing policy. A source-safety certificate is not an automatic finding-state transition.

Record `derived_from` lineage across scanner, slice, assumptions, theorem, witness, harness and replay. The same source claim repackaged across stages is not independent corroboration. Concrete execution supplies a distinct observation but shares the modeled hypothesis and harness/oracle assumptions; independence evaluation must record these dependencies. A fresh review actor or different provider alone cannot erase shared evidence dependencies. Extend the admission adapter and lineage checks as a separately versioned integration change; retain existing R5/R6 thresholds and final-gate authority.

Do not modify R5/R6 policy or existing publication gates as part of the prototype. Any future gate integration is its own versioned design and test milestone.

## 6. MCP and skill contracts

Do **not** expose a model-writable Docker shell or a network socket factory.

The model-facing design has three separate capability planes:

1. the external/operator MCP and ordinary review-package retrieval remain read-only views over
   accepted evidence;
2. formal-analysis workers receive a job-scoped workbench bound to one candidate or obligation so
   they can iterate on property, slice, proof and harness proposals; and
3. admission and target execution remain operator-only application operations outside both model
   capability planes.

The first plane is sufficient for consuming results but not for developing a nontrivial proof. The
second plane is therefore required for the M1/M2 worker experience. It is not added to inference
review-cell transports and cannot publish accepted evidence directly.

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

Runtime worker procedures must live only under their registered `pipeline/skills/<name>/SKILL.md`
paths and be registered in `pipeline/guidance/registry.json` with allowed jobs. They describe
bounded analysis, proof, harness-design or evidence-interpretation procedures, **not** how to
bypass authority or run targets. Development instructions belong separately in `.claude/skills/`
under the repository's existing separation rules.

### 6.3 Job-scoped formal workbench

The formal worker needs a fluent, bounded proof-development loop. Provide a separate
application-mediated workbench, optionally using MCP framing internally, that is never included in
the external `appsec-review-mcp` catalog. Its expiring capability binds the application run,
accepted manifest, candidate, formal attempt, obligation, source/build identities, permitted
operations, response/page bounds, Lean-check count, slice-refinement count, model-call budget and
expiry. Every call revalidates that binding and writes only immutable candidate/diagnostic material
inside the current job attempt.

| Workbench operation | Purpose | Deterministic boundary |
|---|---|---|
| `get_formal_work_item` | Return the SAST allegation, applicable registered property templates, exact evidence identities, current slice/model state, open obligations and remaining budget | One bound candidate/obligation; no broad search or target-tree scan |
| `instantiate_formal_property` | Submit a registered template ID and typed parameters | The application validates that the instantiated property still matches the accepted rule, sink and alleged bad event |
| `request_slice_refinement` | Request one named unresolved call, alias, guard, state or layout dependency | The application expands only through already accepted bounded facts; missing producer evidence remains a gap rather than launching an analyzer during retrieval |
| `inspect_formal_model` | Read the normalized IR, generated Lean definitions, fixed theorem statement, assumptions and correspondence obligations needed to develop a proof | No arbitrary run file, import, theorem-statement or source-path access |
| `check_proof_candidate` | Submit a theorem body/proof term for the fixed generated obligation and receive bounded elaboration, tactic, timeout and axiom diagnostics | The application owns imports, definitions, theorem statement, files, pinned Lean invocation and axiom acceptance; no shell or arbitrary Lean project |
| `analyze_formal_witness` | Inspect a model trace, path constraints, source mapping and controllable/uncontrolled variables | Classifies infeasible or non-concretizable state; does not execute the target |
| `submit_harness_proposal` | Submit a declarative adapter, legitimate caller setup, reset, oracle, seeds and negative control | Deterministic rendering, AST/ABI/symbol policy and compile-check own the final harness; commands, mounts and destinations are absent from the schema |
| `submit_experiment_request` | Record a non-executable request tied to one eligible obligation | Cannot create admission, select a new target/function or start the lab |
| `inspect_experiment` | Read admission state and accepted sanitized observations/replay status | No polling that mutates a run and no access to protected testcase, harness or log bytes |

Workbench writes are untrusted proposals and diagnostics, not accepted proof or evidence. Only the
ordinary job validators, Lean checker, dataset declarations and handoff publication can promote a
validated result. A slice-refinement request cannot cause a new scanner/compiler/graph execution
inside a model call; required missing producer coverage schedules ordinary operator/job work or
leaves the attempt inconclusive.

`check_proof_candidate` is intentionally more capable than the read-only reviewer tools but less
capable than a shell. It accepts only a proof body for an existing generated theorem, caps bytes and
attempts, compiles in the pinned Lean sandbox, returns structured diagnostics, and rejects changed
definitions, theorem statements, imports, `unsafe`, IO, macros, unapproved axioms and `sorryAx`.

### 6.4 Runtime skills for the workbench

The formal jobs require four separately registered runtime procedures:

- **Formal obligation analysis:** preserve exact semantics, instantiate registered properties,
  identify source-correspondence obligations and distinguish proof gaps from security evidence.
- **Lean proof development:** inspect generated definitions, keep the theorem fixed, select bounded
  tactics (`simp`, `omega`, `bv_decide`, case analysis and registered lemmas), interpret checker
  diagnostics and stop rather than weakening the property or adding trust assumptions.
- **Proof-directed harness design:** map only experimentally answerable obligations to legitimate
  caller state, controllable inputs, an exact oracle, boundary seeds and a negative control.
- **Formal evidence interpretation:** keep logical result, source correspondence, concrete
  reproduction and coverage scope independent when review workers consume accepted results.

These skills guide use of application-enforced capabilities; they grant no tool, budget,
publication, admission or execution authority. Formal methods remains a responsibility/procedure,
not a new security-domain persona.

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
    correspondence.py     # independent certificate/derivation validation
    assumptions.py        # premise provenance, discharge and non-vacuity
    validity.py           # challenge/revocation and reverse dependencies
    evidence_admission.py # exact predicate/polarity and lineage mapping
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
    admission.py          # investigation authorization
    quota.py              # atomic reservations, leases, recovery, cancellation
    calibration.py        # oracle health and target instrumentation
    execution.py          # restricted container runner, no model shell
    coverage.py           # relevant branch and behavior feedback
    feedback.py           # observed behavior -> Lean model recheck
    oracle.py             # question-specific safety/sanitizer conditions
    minimize.py           # same-fault reduction
    replay.py             # clean-process repeat
    protocol.py           # later separately authorized network driver
    custody.py
  mcp/
    formal.py             # accepted read-only formal retrieval
    formal_workbench.py   # attempt-scoped proposal/proof-check adapter; not external MCP

docs/
  formal-verification/
    lean-guided-verification-conversation.md
    sast-to-lean-and-proof-directed-fuzzing.md    # this design
  schemas/
    formal-verification/
      formal-request.schema.json
      formal-work-item.schema.json
      formal-property-proposal.schema.json
      formal-proof-candidate.schema.json
      formal-workbench-event.schema.json
      formal-slice.schema.json
      formal-obligation.schema.json
      formal-translation.schema.json
      formal-proof.schema.json
      formal-correspondence.schema.json
      formal-assumption-ledger.schema.json
      formal-invalidation.schema.json
      formal-quota-event.schema.json
      formal-witness.schema.json
      formal-attempt.schema.json
      formal-contract.schema.json
      formal-experiment-request.schema.json
      formal-harness-proposal.schema.json
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
  formal-obligation-analysis/SKILL.md
  lean-proof-development/SKILL.md
  proof-directed-harness-design/SKILL.md
  formal-evidence-interpretation/SKILL.md
```

Additional integration edits once individual components work: `src/appsec_review/cli.py`, typed
configuration parsers, `appsec-review.toml`, image catalog/policy, schema registrations, run dataset
declarations and custody validators, job dispatch/graph **only if separately approved**, read-only
MCP schema/capability bindings, job-scoped workbench capability/budget enforcement, ledger relation
consumers, and documentation/operations pages.

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

Add aggregate formal-work limits across candidates, obligations, workbench checks, retries and refinement: initial proposed ceilings are 32 checker invocations, 1,800 checker wall-seconds, 3,600 checker CPU-seconds and 3,600 total job wall-seconds, plus the existing typed aggregate model-token/cost limit. Per-obligation limits remain maxima, not entitlements. Reserve quota atomically before dispatch, count failed attempts, and stop scheduling when any aggregate ceiling would be exceeded. Publish deferred obligations and the exhausted budget dimension. These prototype values require G1 measurement before rollout; do not silently enlarge them to pass a gate.

Use existing container admission, policy, image identity and signing infrastructure; these are *resource planning values*, not evidence that host-specific images or permissions already exist. Frozen review configurations stay unchanged. Tool and compiler versions must be pinned before acceptance.

## 9. Phased implementation work packages

The order below intentionally builds **one usable end-to-end path** before expanding tool coverage.

### M1 work packages

| ID | Exact build work | Dependency | Required completion evidence |
|---|---|---|---|
| **F0** | Freeze initial subset, certificate/assurance contracts and pinned real scanner pair | None | Inventory, immutable target/run/lead IDs and exact semantic/trust boundary |
| **F1** | Accepted-lead/claim resolver and candidate planner | F0 | Rejects fake IDs, stale hashes, missing source/build; handles real accepted lead |
| **F2** | Property registry, exact safety/witness duals, premise ledger and non-vacuity | F1 | Positive/negative units; empty domains, assumed bounds and circular premises rejected |
| **F3** | Complete supported-function AST coverage and typed missing-dependency report | F1 | Every branch/effect accounted for; no false closure from graph bounds |
| **F4** | Restricted AST-to-IR frontend, error-event semantics and checkable correspondence derivation | F2,F3 | Source binding, grammar validation and initial/transition/bad-event proof obligations |
| **F5** | Lean semantics, generic lowering proof, independent checker/comparator, assurance policy and fixed-theorem workbench | F4 | Checked model/witness and certificate lemmas; forged receipt, changed definitions, native-trust mislabeling and bypass rejected |
| **F6** | Detached accepted-attempt/CLI projection and contract record format; reuse deferred | F5 | Byte-hash verification, clean retry identities, honest verdicts and aggregate budgets |
| **F7** | Blind detached accepted-ingestion experiment and evaluation harness | F6 | G0/G1 result table; all unknowns counted, no source-certification inference |
| **F8** | Establish safe/vulnerable paired corpus with actual **same-rule** scanner alerts | F1,F2 | Pinned SARIF/observation identity on both twins; unflagged controls excluded from strict benchmark |
| **F9** | Independent correspondence checker and strict source-proof evaluation | F4-F8 | G2 certificates and same-rule safe/vulnerable evidence; model-only results leave G2 unmet |

**M1 model demonstration (G0/G1; not source-certification or rollout):**

- Safe-but-flagged findings are discharged only by a checked, source-connected theorem; scanner-quiet controls cannot count as eliminated alerts.
- A real SAST lead from a pinned target travels through the accepted ingestion path, creates a property-specific slice and an actual checked Lean artifact, and returns an auditable outcome.
- A real *supported* positive case produces a checked violating model assignment or a valid source-connected witness with explicit translation caveats.
- A *supported* negative control demonstrates either a properly scoped, justified infeasibility/safety proof or an honest `inconclusive` if the source correspondence cannot be established.
- No unsupported or truncated case is reported as fully source-proven safe.
- Existing pipeline findings, PoC compilation, gate and report remain unchanged.

### M2 work packages

| ID | Exact build work | Dependency | Required completion evidence |
|---|---|---|---|
| **P1** | Classify experiment-eligible Lean obligations and generate typed testable questions, valid inputs and boundary seeds | G1 | Only selected obligations fuzzed; missing lemma produces no-run result |
| **P2** | Generate real-function/required-caller harness through the bounded proposal workbench, with preconditions, reset, seeds and specific oracle | P1 | Deterministically rendered harness compiles against pinned original implementation; commands, widened scope and invalid setup rejected |
| **P3** | Build fuzz image and atomic reservation/idempotency/recovery/cancellation supervisor | P2 | Concurrent quota, crash/retry, revocation and process-tree checks; wrong target/function denied |
| **P4** | Obligation-specific fuzz driver, calibration and instrumentation/coverage validation | P3 | Positive/negative controls, target-operation coverage and exact analyzed/reproduction build relationship |
| **P5** | Same-fault minimization, replay, refinement and contradiction lifecycle | P4 | G3 replay evidence; discrepancy creates a new attempt, certificate challenge suspends dependent reuse |
| **P6** | Contract reuse, reverse dependencies, transitive invalidation and caller obligations | G2 and lifecycle checks | Challenged/revoked contracts cannot be reused; affected publications identified |
| **P7** | Formal evidence-admission/lineage adapter, read-only lookup and report projection | G2,P5,P6 | Exact predicate mapping; no derived-evidence double counting or R5/R6 bypass |
| **P8** | Optional **separate later** application-protocol driver and session replay | P5 | Internal-network-only authorized sequences; not a core M2 gate |
| **P9** | Grouped held-out comparison against matched-budget review/fuzz baselines | P5-P7 | G4 decision with incremental value, abstention, confidence intervals and total cost |

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

Record per case: `proof_assurance`, `certificate_status`, `premise_status`, `validity_checkpoint`, `correctness_scope`, `lead_ingested`, `lead_correlated`, `slice_closed`, `source_correspondence`, `model_result`, `concrete_reproduced`, `replay_rate`, `confirmed_weakness`, `false_safe`, `false_alarm`, `inconclusive_reason`, `elapsed_seconds`, `CPU_seconds`, `tokens`, and evidence completeness.

**G1 model-usefulness demonstration (not source-certification or rollout):**

- At least **two** supported vulnerable cases yield checked model witnesses with correct source assumptions, and at least **two** matched controls yield checked scoped refutations/safety arguments; if full correspondence is unavailable, status must remain conditional.
- **Zero** incorrect unconditional “source safe” conclusions on the pinned positive set.
- **100%** of attempted cases receive a final typed result and a complete/gapped coverage record.
- A tampered source hash, missing accepted lead, open alias, `sorry` dependency, or incomplete slice fails closed.

**G3 dynamic-lab demonstration:**

- Paired safe/vulnerable harnesses may corroborate results, but clean fuzzing cannot establish source safety without an adequate proof.
- At least **two distinct** supported vulnerable cases produce a minimized, **three-times replayable** violation against the actual admitted target.
- Matching controls are tested with the same harness and oracle and do not display that violation in the tested scope.
- Unauthorized, out-of-scope or over-budget execution is rejected; multiple permitted test inputs and retries under one valid investigation admission proceed without new per-input approval.
- Missing sanitizer, failed harness compilation, timeouts and nondeterminism are classified as gaps, never as safe.

The initial minimums establish that the path works; they do not imply acceptable coverage for all CWE classes. Before G4 rollout, score a held-out set of known-vulnerable projects and report confidence intervals and class-level tradeoffs. Do not tune to a blind test set after seeing its labels. Group related vulnerable/fixed twins, shared source ancestry and near-duplicate templates into the same development or held-out split. Freeze the split and selection policy before scoring; neutral filenames alone do not prevent leakage. Compare against existing scanner-plus-review and ordinary fuzzing with matched target scope, harness/oracle access, compute and time budgets. Report preparation/proof overhead, eligible and total-alert denominators, abstentions, time to valid evidence and incremental confirmed/refuted cases. State whether any measured gain comes from better harnesses, extra budget or proof-directed seeds.

### 10.5 False-positive proof benchmark: safe code that still triggers SAST

This milestone must answer **both sides** of SAST adjudication: can Lean establish a concrete violation in a flagged program, and can it establish that a flagged **safe** program cannot violate the *specific alleged property*?

A true false-positive proof experiment requires three independently verified facts:

\[
\mathrm{SASTAlert}(P,R)\ \land\
\mathrm{SafeUnderScope}(P,\varphi)\ \land\
\mathrm{CheckedSourceConnectedProof}(P,\varphi).
\]

The first is an **actual scanner result** under the pinned rule/version `R`, not synthetic SARIF. The second is independent evaluator-only ground truth; the third is a checked Lean theorem with the required model-to-source correspondence. If source correspondence remains unproved, the outcome is `MODEL_PROVEN_SAFE` or `CONDITIONAL`, **not** a closed false positive.

**Terminology:** Some appsec-review rules are purposely **informational review signals**, not claims of vulnerability. A safe match to one is a `safe_flagged_review_lead` and need not be a scanner defect. Reserve `true_sast_false_positive` for a tool claiming a weakness the program cannot exhibit in the stated scope. Score both cohorts separately.

#### 10.5.1 First paired scanner experiment — identical sink, different guards

Start with the repository's existing Semgrep rule [`appsec-review.review-signal.sink.cpp-copy-length-not-bounded`](../../rules/semgrep/review-signals.yml). This rule matches variable-length `memcpy`/`memmove` when the length expression lacks certain recognizable syntactic bounds. **Do not modify the rule to fabricate false positives.**

Safe candidate:

```cpp
#include <cstdint>
#include <cstring>

uint8_t checked_copy(uint32_t n) {
    uint8_t src[16] = {1};
    uint8_t dst[16] = {};
    if (n > 8) return 0;
    std::memcpy(dst, src, n);
    return dst[0];
}
```

Vulnerable candidate:

```cpp
#include <cstdint>
#include <cstring>

uint8_t checked_copy(uint32_t n) {
    uint8_t src[16] = {1};
    uint8_t dst[16] = {};
    if (n > 24) return 0;
    std::memcpy(dst, src, n);
    return dst[0];
}
```

Both are **proposed fixtures**; the actual scanner results still need to be measured. The safe variant reaches the copy only for `n ≤ 8`, which fits the 16-byte source and destination. The vulnerable twin reaches the copy for `n = 17`, requesting 17 bytes from and to 16-byte arrays.

The required safe-model property is

\[
\forall n:\mathrm{UInt32},\qquad
\mathrm{CopyReached}(n)\Longrightarrow n\le 8\le 16.
\]

Illustrative Lean theorem (model only until source correspondence is justified):

```lean
import Mathlib

def copyReached (n : BitVec 32) : Prop :=
  n.toNat ≤ 8

def copyOutOfBounds (n : BitVec 32) : Prop :=
  copyReached n ∧ 16 < n.toNat

theorem safe_copy (n : BitVec 32) :
    ¬ copyOutOfBounds n := by
  intro h
  rcases h with ⟨hreach, hoob⟩
  unfold copyReached at hreach
  omega
```

Required source correspondence: exact guard semantics and control flow, input width and promotion to `size_t`, array extent and lifetime, valid pointer operands, all reachable caller paths, build/compiler identity and no omitted mutation or alternate path. A short mathematical proof without those obligations must not dismiss the real finding. For the vulnerable twin, Lean/CBMC can provide `n = 17` as a candidate; M2 may fuzz/replay the **original** instrumented function in the separately authorized container, subject to build and optimization limits.

**Scanner precondition to score this pair:** Run the real pinned Semgrep profile against each staged target; respect its `tests/` path-exclusion behavior. Require a matching native rule ID and resolved sink location in **both** scan outputs. If the safe case is not flagged, score it as a normal true-negative control, not as a Lean-eliminated false alarm.

#### 10.5.2 Progressive classes of safe-but-flagged pairs

Plan an initial 10–20 paired cases, beginning with two locally provable examples and two interprocedural examples.

| Family | Safe-but-flagged implementation | Vulnerable counterpart | Lean proof requirement |
|---|---|---|---|
| Local bounds | Variable copy with unrecognized but sufficient guard | Same sink, weakened bound | Every reached read/write fits both objects |
| Interprocedural guard | Caller validation establishes callee precondition | Caller check missing or weakened | Precondition is established at every real call |
| Infeasible path | Contradictory branch guards prevent bad sink | Relaxed guard makes path feasible | Every admissible bad-path constraint is unsatisfiable |
| Arithmetic range | Input range prevents narrow multiplication overflow | Range admits wrap | Exact `BitVec` arithmetic cannot exceed limits |
| Authorization | Caller/session ownership invariant protects sensitive sink | Authentication/ownership guard bypassed | Every reachable protected operation is authorized |

Variants should test aliases, state mutation after validation, signedness, off-by-one checks, indirect callers, error paths and contracts reused across functions. If the verifier cannot justify the semantics or source correspondence, **abstain** rather than issuing a false safety claim.

#### 10.5.3 Corpus and hidden truth

The scanner-visible corpus must have neutral names, comments, commit messages and paths. Ground truth (vulnerable/safe labels, pair relationships, source property, expected witness, proof notes and fixed-version mapping) stays in a separate **evaluator-only** guide, outside model and worker mounts. Reuse the existing [test-target and guide isolation policy](../operations/test-targets.md).

For each case, freeze:

- Original target commit, exact file/source hashes, build system/toolchain/options.
- Scanner, native rule ID and rule digest, output observation/SARIF identity, sink coordinates, severity and whether an alert was truly produced.
- `formal_attempt_id`, `obligation_id`, exact proof theorem/axiom audit, translation/coverage gaps, model-to-source correspondence.
- Any M2 concrete reproduction with the original instrumented function, exact harness and authorization evidence; clean fuzzing is never a safety proof.
- **Only in the evaluator:** `pair_id`, `expected_label` and independent reference rationale.

Route each genuine alert through the **existing accepted SAST ingestion path**. Do not inject fabricated scanner observations to improve a benchmark score. Distinguish `safe_flagged`, `vulnerable_flagged`, `safe_unflagged`, `vulnerable_unflagged`, `unsupported_scan` and `ambiguous_match`. Only the first two support the strict same-rule false-positive adjudication benchmark.

The existing Case-094 pairs (seven defects and seven controls) and CASTLE-C250 controls are reusable *candidate cases*, but **do not assume their safe versions trigger any actual SAST alert**. The normal scanner scoring and the new conditional-on-alert Lean adjudication score are distinct.

The formal-verification extension should add an **evaluator-only** `appsec-review/formal-fp-case/1` schema and scoring module (suggested `src/appsec_review/formal_verification/fp_benchmark.py`) that reads frozen verification receipts and joins them with hidden labels after attempts finish. Add unit pairs under `tests/fixtures/formal_verification/paired_controls/`; acceptance targets remain separately pinned outside the repository's own source checkout. Do not expose answer keys in `pipeline/skills`, source prompts, retrieval MCP, or the fuzzer's seed corpus.

#### 10.5.4 Verdicts and quantitative gates

| Actual condition | Verification conclusion | Evaluation |
|---|---|---|
| Safe + real alert | `kernel_only` theorem **plus accepted section 4.5.2 certificate** | Successful source-level false-positive adjudication |
| Vulnerable + real alert | Feasible counterexample; preferably original-target replay | Correct vulnerable classification |
| Vulnerable + alert | Unconditional “source proved safe” | **Critical false-safe failure** |
| Safe + alert | Model theorem with incomplete source link | Conditional/inconclusive, **not** a proved false positive |
| Either + alert | Missing proof, unsupported semantics or timeout | Honest abstention |
| Safe + no alert | No alert to refute | Scanner true negative, **excluded** from false-alarm elimination |

\[
\mathrm{FlaggedSafeProofRate}=
\frac{\#(\mathrm{safe,\ alerted,\ source\!-\!proved})}
{\#(\mathrm{safe,\ alerted,\ attempted})}.
\]

\[
\mathrm{FalseSafeRate}=
\frac{\#(\mathrm{vulnerable,\ incorrectly\ certified\ safe})}
{\#(\mathrm{vulnerable,\ attempted})}.
\]

Report per rule/class: same-rule twin alerts, coverage/eligibility, proved safe, vulnerable witnesses, reproduced cases, abstentions, proof effort, and false-safe claims. **Zero incorrect unconditional source-safe claims** on the pinned positive corpus is a hard gate, not a statement of universal correctness. The G2 source-certification milestone must demonstrate at least **two** independently constructed *safe and flagged* cases with valid checked source-safety evidence and **two** paired *vulnerable and flagged* cases with violating evidence; if source correspondence cannot be justified, report the milestone unmet rather than weakening the standard.

#### 10.5.5 Mandatory negative regression cases

- Safe twin does not trigger the configured scanner: exclude it from “alert eliminated” metrics.
- Scanner rule/line mismatch or fabricated SARIF: refuse the false-positive test.
- Unsafe branch omitted from generated Lean model: reject source-safety certification.
- Proof depends on `sorryAx` or an untrusted axiom: reject.
- Unresolved alias, caller, ABI, arithmetic or translation: only conditional/inconclusive.
- A nominally fixed twin still contains another reachable bad path: cannot certify it.
- Hidden labels/pairs/expected proof are visible to the verification agent: benchmark contamination failure.
- Successful fuzzing with no crash is treated as a proof of universal safety: reject.

### 10.6 Named assurance and rollout gates

These gates replace ambiguous references to "M1 acceptance". Passing a lower gate cannot satisfy a higher one. Each decision has a frozen evidence manifest, exact revision/tool identities, outcome, gaps and operator decision; none authorizes live execution by itself.

| Gate | Evidence required | Capability it permits |
|---|---|---|
| G0: pipeline functionality | One actual accepted alert yields an immutable typed attempt with complete/gapped accounting; unsupported and tampered inputs rejected | Detached development path only |
| G1: model usefulness | At least two supported positives and two matched controls meet section 10.4's checked model/witness criteria, with premise/vacuity and proof-assurance negative cases | Model-only/conditional evaluation; no source certification or ordinary-graph enablement |
| G2: source certification | Section 4.5.2 checker and soundness obligations implemented; at least two independently constructed safe-and-flagged cases and two vulnerable-and-flagged twins meet section 10.5.4; kernel-only assurance and zero false-safe results | Scoped source certification for the exact registered subset; mandatory before ordinary graph integration work |
| G3: dynamic lab | Section 10.4's two distinct reproducible violations, calibrated oracle/instrumentation, matched controls, atomic admission/recovery and invalidation checks | Separately admitted function-lab use; never automatic target execution |
| G4: rollout | Held-out class-level evaluation, matched-budget baselines, confidence intervals, measured cost/abstention, deterministic evidence-admission/lineage checks and explicit operator decision | Optional ordinary verification enablement after G2; fuzz planning additionally requires G3 and its own enablement decision |

G0/G1 can succeed while G2 is unmet. Record that outcome honestly rather than changing the source-certification standard. The disabled standalone lab can be developed and explicitly exercised for G3 after G1 for conditional witnesses, but routine admitted use requires G3; it is not evidence of G2. Contract reuse and broader semantic families follow G2 and lifecycle validation. General automation is not the criterion for the first experiment: useful, defensible evidence is.

## 11. Negative and failure-mode tests that must exist

### Trust and soundness

- A hand-written Lean model with an omitted unsafe branch must **not** certify source safety.
- A proof with `sorry`, a forbidden user axiom, unreviewed trust dependency or self-assumed theorem must be rejected.
- Forged checker output, native axioms mislabeled kernel-only, changed elaborated definitions, kernel-check-disabling options and stale checker artifacts fail independent acceptance.
- Contradictory/empty entry premises, assumed bounds and a violation predicate with a different domain fail certification.
- UB-triggering paths removed by optimization or assumed-away copy bounds cannot refute source defects; loops/recursion outside the supported subset and exhausted fuel remain unsupported/unknown.
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
- Concurrent reservations, crash/retry duplication, uncertain quota consumption, cancellation and revocation cannot exceed the admission or leave active processes unaccounted.
- Failed positive calibration, an uninstrumented target operation, unreachable sink or a fault in the adapter is not a successful target negative result.
- Contradicting an accepted certificate suspends dependent reuse and identifies affected publications; replacing an attempt cannot erase invalidation.
- Producer-stage requests cannot require downstream packages; formal evidence without an exact predicate mapping is non-counting, and derived artifacts do not create independent corroboration.
- Evaluator-only control labels, pair relationships and the evaluator guide cannot be read by verification workers; evaluation is separate. Neutral operational seeds/calibration fixtures are allowed without hidden target truth, and calibration is excluded from target scores.

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
| `MODEL_PROVEN_SAFE` | Accepted theorem for a stated model only; assurance profile shown separately |
| `SOURCE_PROPERTY_PROVEN` | Kernel-only proof plus accepted correspondence certificate and current validity for the exact source/property/configuration scope |
| `PATH_INFEASIBLE_SCOPED` | One exact alleged path ruled out under recorded assumptions |
| `MODEL_WITNESS` | Lean/solver model violates an abstract property |
| `CONCRETE_VIOLATION_REPRODUCED` | Observed original-target violation under authorized repeatable execution |
| `CONDITIONAL` | Outcome depends on unproved source/environment premises |
| `INCONCLUSIVE` | Coverage, semantics, proof, time or environment cannot decide |

No “clean program” or “false positive” label is emitted from `MODEL_PROVEN_SAFE` alone. An observed crash without demonstrated property impact is not automatically a confirmed exploitable vulnerability.

## 13. Operational sequencing and rollback

- **First PR:** freeze the initial subset, certificate/checker contract and proof-assurance policy; implement only M1 F0–F2 and small paired fixtures; no Docker executor or job graph changes.
- **Second PR:** semantic slice, IR/Lean checker, bounded fixed-theorem workbench, immutable proof
  receipts and strict capability/axiom tests.
- **Third PR:** detached accepted-lead evaluation through G0/G1, then implement and validate the restricted correspondence certificate for G2. A model-only result leaves G2 unmet; no graph integration, broad contract reuse or source-safe verdict is enabled.
- **Fourth PR:** M2 per-obligation question selection, real-function harness, required Clang/libFuzzer container and bounded investigation policy; denied-execution tests first.
- **Fifth PR:** authorized automatic bounded fuzz/minimize/replay, observation-to-Lean feedback and contradiction/invalidation handling. Enable source-certified contract reuse only after G2 and lifecycle validation.
- **Later PR:** optional external read-only MCP retrieval, gated report projections, protocol
  adapter and job graph integration. The job-scoped proof workbench is not deferred because it is
  required to make M1 proof development usable. Ordinary-graph integration follows G2; enablement requires the separate G4 decision. The buildout plan uses this same ordering.

At each stage: maintain exact branch ownership, coherent commits, focused unit tests and honest gap accounting. If a new component fails, disable the new feature without modifying accepted SAST evidence, existing final gate, original PoC implementation, or existing source identities. Never replace a prior accepted attempt in place; create a new immutable attempt.

## 14. Deferred research (explicitly not M1/M2)

- Sound arbitrary C/C++ to Lean translation across full compiler and C++ semantics.
- Full application proofs, OS/network-stack global properties and concurrent race proofs.
- Machine-code P-code/VEX semantics and formal correspondence to executable instructions.
- Binary-only Ghidra-to-Lean pipeline and AFL++ QEMU/Frida runs against old games.
- General-purpose function discovery/whole-application fuzzing, Internet-facing penetration testing, privileged raw packet injection, kernel-level protocol fuzzing.
- Auto-triage that changes existing R5/R6 finding status or automatically executes generated PoCs.
- Claims of general vulnerability detection rate or exploitability from tiny demonstrations.

Those are valuable later directions, but must not be prerequisites for the restricted G2 source-certification milestone. The explicit restricted correspondence proof is required; arbitrary C/C++ correspondence remains deferred.

## 15. Open decisions for the first implementation PR

Resolve these using actual first-case evidence, and record the decision in a follow-up ADR rather than silently choosing:

1. Record the measured scanner rule/fixture pair for the fixed initial `local_copy_bounds/1` subset; if the proposed pair does not alert, select another genuine same-rule pair without broadening semantics silently.
2. Pin the Clang release, AST serialization and ABI implementing section 4.5.1. AST is the initial semantic authority; LLVM support is a later certificate extension.
3. Whether CBMC is used in the first vertical as a witness generator; its bounded/no-witness result must never substitute for unbounded Lean proof.
4. How the existing accepted source/build custody supplies a compiler-ready isolated fixture without granting model-written execution commands.
5. Which initial positive/negative cases from the blind known-vulnerable projects have resolvable scanner leads and compatible builds.
6. An isolated application-protocol session driver follows successful core function-level M2 and requires separate authorization; it is not required for M2 acceptance.
7. Record the implementation evidence for the mandatory section 4.5.2 correspondence checker and generic soundness theorem; an ADR cannot substitute a weaker certification rule. Pin the independent Lean checker and approved-native procedure allowlist separately.

These decisions do not block creating the M1 skeleton, data model, tests, and first genuine end-to-end experiment.

## 16. References

### Existing appsec-review authorities

- [Semgrep review-signal rules](../../rules/semgrep/review-signals.yml)
- [False-positive detector scoring and controls](../reviews/castle-style-detector-scoring.md)
- [Acceptance-funnel scoring](../operations/acceptance-funnel.md)

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

- [Lean proof validation and independent checking](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [Lean tactic reference, including native trust in `bv_decide`](https://lean-lang.org/doc/reference/latest/Tactic-Proofs/Tactic-Reference/)
- [LLVM undefined behavior semantics](https://llvm.org/docs/UndefinedBehavior.html)
- Lean mathlib `bv_decide`: <https://leanprover-community.github.io/mathlib4_docs/Lean/Elab/Tactic/BVDecide.html>
- CBMC bounded model checking: <https://www.cprover.org/cbmc/>
- LLVM libFuzzer: <https://llvm.org/docs/LibFuzzer.html>
- AFL++ documentation: <https://aflplus.plus/docs/>
- CodeQL documentation: <https://codeql.github.com/docs/>
- Clang AddressSanitizer: <https://clang.llvm.org/docs/AddressSanitizer.html>
- Clang UndefinedBehaviorSanitizer: <https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html>

---

**Design acceptance rule:** A successful proof of an attractive model is insufficient; the system succeeds only when the claim it makes matches the exact semantics, coverage, provenance and evidence it has actually established.
