---
title: "Design Review: Formal Verification Docs (2026-11-07)"
kind: "history"
subsystem: "review inference and guidance"
status: "historical"
jobs: ["job_cpp_compiled_analysis", "job_review_data_indexing", "job_tree_sitter_ast"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Design Review: Formal Verification Docs (2026-11-07)

**Status:** Review of [`sast-to-lean-and-proof-directed-fuzzing.md`](sast-to-lean-and-proof-directed-fuzzing.md)
and [`buildout-plan.md`](buildout-plan.md) at revision `42dee4d3`. Findings here are inputs to B0; none
is implemented by this document.

**Reviewer decisions already agreed:** remove `bv_decide`/`native_decide` and the `approved_native`
profile; drop CBMC/JBMC; the project IR is the multilingual contract; add a semantic-authority matrix
and a no-typed-frontend policy.

## 1. Summary

The trust-boundary engineering (admission, custody, capability planes, invalidation, gates) is more
mature than the formal core it protects. The weaknesses concentrate where soundness is actually
decided: what the source semantics *is*, how much Python sits in the trusted base, which Lean
mechanisms are trusted, and how the design generalizes beyond C/C++.

## 2. Trusted computing base, stated precisely

### 2.1 What Lean contributes (kernel-only path, replayed through `lean4checker`)

| Trusted | Not trusted |
|---|---|
| Lean kernel (C++), including GMP-accelerated `Nat` kernel operations | Elaborator, `simp`, `omega`, `decide` term construction, the Lean compiler |
| Axioms `propext`, `Quot.sound`, `Classical.choice` | Any tactic implementation |
| `.olean` reader and the comparator confirming the replayed environment contains the intended theorem *type* | Candidate stdout, in-process `#print axioms` |

### 2.2 Decision: no native evaluation (replaces "approved_native")

`bv_decide` verifies an LRAT certificate with a checker that is *proved* in Lean but *executed*
natively; every proof it closes depends on `Lean.ofReduceBool`. The same holds for `native_decide` and
`Lean.trustCompiler`. Accepting them adds the Lean-to-C compiler, the host C compiler that built Lean,
the runtime, and the specific compiled checker code to the trusted base.

Nothing in V1 requires them:

- `local_copy_bounds/1` and the registered guard/arithmetic families are discharged kernel-only by
  `simp [run]` followed by `omega` (`bv_omega` for `BitVec` goals).
- Witnesses are certified kernel-only by `decide` on a concrete finite state
  (`theorem w : Bad (run 17) := by decide`).
- Countermodel *search* may use any untrusted solver (including `bv_decide` run outside the
  acceptance path); its output is only a candidate until re-checked by `decide`.

Therefore: delete the `approved_native` profile and its policy machinery; keep `kernel_only` and
`unaccepted`. Revise design 4.6 and buildout 1.1/5.3/6.2 accordingly. CBMC/JBMC are removed for the
same reason plus weak C++/Java frontends and bounded, non-proof output; ADR #4 is resolved "not used".

### 2.3 What the project adds (this is the real TCB)

| Component | Nature | Growth | Mitigation |
|---|---|---|---|
| Property template registry (theorem statements) | Specification | per family | Mandatory paired-twin acceptance per *template version*: vulnerable twin yields a `decide`-checked witness and safe twin a kernel-only proof under the same statement before registration |
| IR operational semantics in Lean | Specification | once | Literate spec per construct; differential testing of the Lean evaluator against instrumented execution on concrete inputs; cross-read against Cerberus/Clight for the C subset |
| Per-language frontend `lower_<lang>` and its correspondence lemma | Specification + proof | per language | Keep each lowering small; grammar membership and lowering inside Lean (2.4) |
| Extractor binding (typed-frontend output → Lean AST term) | Code | per language | Round-trip: pretty-print the Lean term back to source and diff against the preprocessed function |
| Acceptance driver (Python) | Code | once | Tiny; decision reproducible from receipts alone |
| Toolchain/image pins | Configuration | once | Existing catalog/pin machinery |

Generator rules that follow from 2.1-2.3: no `partial def` in `AppSecVerify` (opaque constants cannot
be unfolded by the theorem; use fuel or structural recursion); no `@[implemented_by]`/`@[extern]`
anywhere in the library (kernel and runtime meanings diverge); no `axiom` in generated modules.

### 2.4 Shrink the TCB: grammar and lowering inside Lean

Buildout 4.2 implies the "independent structural validator" and the per-function derivation are
Python. Instead:

1. Define the supported source grammar as a Lean inductive with a `Decidable` membership predicate.
2. The extractor emits a Lean *term* of that inductive, hash-bound to the frontend's serialized output.
3. `lower : AST → IR` is a Lean function; the generic simulation theorem is `∀ a ∈ Grammar,
   Sim (srcSem a) (irSem (lower a))`.
4. Per-function instantiation is `by decide`/`rfl`.

The only remaining Python trust is the extractor binding, checked by the round-trip diff. This is the
concrete form of design 4.5.2's "a structural validator must not be the lowering code reporting its
own success".

## 3. The IR is the multilingual contract

"IR" here means the project's own typed intermediate representation (design 4.5), **not** LLVM IR
and not any language's native AST.

| Candidate pivot | Why not |
|---|---|
| LLVM IR | Post-frontend, optimizer-sensitive (`poison`, `undef`, attributes, removed UB paths); exists only for C/C++/Rust/Swift; already excluded as authority by design 4.5.1 |
| Each language's typed AST (Clang AST, `javac` trees, `go/types`+SSA, MIR) | Different data models and evaluation rules; proving simulation against each means one source semantics per language and linear TCB growth |
| `AppSecVerify` IR (Lean inductive) | One shared semantics; templates, duals, reachability/bad-event lemmas, tactics and the checker path are stated once over it |

IR contents: `BitVec w` values with explicit comparison signedness; finite memory objects with byte
extents; basic blocks; a closed primitive effect set (`copy src dst len`, `load`, `store`, `branch`,
`return`, `bad ReadOOB | WriteOOB`, `throw`/`panic` as distinct terminal events, `unknown_call` with
declared effects); explicit nondeterminism for unmodeled behavior.

Per language: a frontend `lower_<lang>` and a certificate `formal-correspondence/<lang>/1` whose claim
is "this lowering preserves the language's meaning for the registered grammar". Adding a language
adds exactly those two items. An IR extension is a versioned change with its own soundness lemmas,
never a per-language special case.

Structural consequence: managed-language frontends never emit `ReadOOB`/`WriteOOB` (the language has
no such event); they emit `Throw`/`Panic`. The "wrong statement" problem (a copy-bounds theorem applied
to Java, where the failure mode is an exception, not corruption) is therefore unexpressible rather
than merely prohibited.

## 4. Semantic-authority matrix and no-frontend policy

CodeQL and Semgrep are *lead* sources; losing one costs leads, not soundness (Semgrep is buildless
across all supported languages; Track B covers no-lead cases). What cannot be lost is a typed,
name-resolved frontend, because every family depends on widths, signedness, conversions and resolved
callees.

| Language | Typed frontend | Full build required? | Fail-closed condition |
|---|---|---|---|
| C/C++ | Clang AST (pre-optimization) | No; `-fsyntax-only` on one TU with include paths/defines | Any error diagnostic in the function's TU; unmatched grammar node |
| Java/Kotlin | `javac` tree API or JDT, `-proc:none`, no codegen | No; needs classpath | Unresolved symbol in the function's closure |
| Go | `go/types` + `x/tools/go/ssa` via `go/packages` | No binary build; needs module cache or vendor dir offline | Missing package |
| Rust | MIR (`rustc --emit=mir` / Charon) | `cargo check` level; needs crates | Missing crate; `unsafe` outside registered grammar |
| C# | Roslyn semantic model | Needs references | Unresolved reference |
| Python/JS/TS | none with fixed-width types | — | Memory/arithmetic families do not apply |

Policy when the typed frontend is unavailable: `source_correspondence` is capped at `assumed`;
verdicts are capped at `MODEL_WITNESS`/`CONDITIONAL`; `SOURCE_PROPERTY_PROVEN` is unavailable. A model
may still be built from tree-sitter plus inferred types to find a useful witness, but never as a
certification path. Add gap value `typed_frontend_unavailable`, distinct from `unsupported_class`.
`job_tree_sitter_ast` output is never semantic authority.

Family applicability: `local_copy_bounds/1`, `integer_wrap_bounds`, `index_and_copy_bounds` are
C/C++ (and Rust `unsafe`) families. Managed-language V1 family: `guard_path_feasibility` over typed
integer/boolean logic, which `javac`/`go/types` support and `omega` discharges.

## 5. Producer gaps verified against the tree

- **No pre-optimization Clang AST producer exists.** `job_cpp_compiled_analysis` emits Clang CFG and
  LLVM IR; `job_tree_sitter_ast` is syntactic. Buildout 2 hedges ("if existing compiler outputs lack
  them"); they do. Name the job/step, container and dataset family in B0. Prefer a LibTooling plugin
  emitting a closed schema over parsing `-ast-dump=json`, which is not a stable format; at minimum
  snapshot-test the pinned release.
- **Callee identity for "recognized `memcpy`":** enumerate `memcpy`, `std::memcpy`,
  `__builtin_memcpy`, and `__builtin___memcpy_chk` (emitted under `_FORTIFY_SOURCE`), plus the implicit
  `uint32_t → size_t` conversion node, array-to-pointer decay and aggregate-initializer zero-fill.
  Unlisted means rejected, and the 10.5.1 fixture would otherwise be rejected.
- **Scanner path mismatch:** design 4.1 admits leads with "CodeQL/Clang evidence", but 10.5.1 relies
  on the Semgrep INFO rule `appsec-review.review-signal.sink.cpp-copy-length-not-bounded`. Confirm
  `review_signal` entities (`src/appsec_review/review/units.py`) qualify as `lead_observation_id` in
  candidate selection; otherwise Track A cannot produce the G0 lead.

## 6. Proof-check boundary mechanics

- `check_proof_candidate` must enforce its allowlist as a Lean **syntax-tree walk** (reject by
  `SyntaxNodeKind`: `run_tac`, `set_option … in`, `native_decide`, `sorry`/`admit`, `open … in`, any
  `Lean.*` identifier), in addition to sandboxed elaboration and the post-hoc axiom audit. With
  `import Std` the `Lean` namespace is transitively reachable, and `run_tac` lifts arbitrary `IO`.
  Regex filtering is insufficient.
- **No Mathlib.** Buildout 6.1 ("minimal pinned library closure") and 6.2 ("mathlib commit") conflict.
  `BitVec`, `omega`, `decide` are core; Mathlib multiplies the olean closure the independent checker
  replays and widens the audit surface for no V1 gain.
- `lean4checker` runs under the identical toolchain against the trusted challenge `.olean`; the
  comparator diffs the elaborated theorem type and definitional closure. B3 should list the exact
  command and what "equivalent documented path" may mean.
- Add a deterministic `proof/auto` task before any worker call: fixed tactic script
  (`simp [run]; omega`). The `formal_property_analyst` is engaged only on failure.
- Duality by construction: one template defines `Safe` and `Witness` from the same `Reachable`/`Bad`;
  prove `¬Safe ↔ Witness` once in `Security/Predicates.lean`.
- Big-step `run : Input → Trace` for the acyclic V1 subset; reserve small-step and stuttering
  simulation (which needs a well-founded measure) for the loop extension in 4.4.1.
- Witness recipe: untrusted countermodel search → concrete `decide`-checked witness theorem.

## 7. Fuzz lab

- Admission/quota (durable leases, idempotency keys, crash reconciliation, concurrent reservations)
  is over-specified for v1. A typed `max_concurrency = 1` invariant plus a single lock and
  append-only events satisfies the same semantics trivially. Record that as the v1 implementation;
  keep the concurrent form as a later extension.
- Make the observation asymmetry explicit in the refinement classifier: a non-reproduction can never
  refute a source-level witness (binary ≠ source). A *reproduced* violation against a source-certified
  function is a trusted-base incident (parser binding, semantics, or checker defect) and is routed
  with priority, not as ordinary model refinement.
- Per-language runners later (libFuzzer; `go test -fuzz`; Jazzer) behind the same closed operation
  enum. Not an M2 concern.

## 8. Document consistency

- Two CLI surfaces: design 4.9 vs buildout 9.5. Pick one.
- Work packages F0–F8 (design 9) vs slices B0–B10 (buildout 12); design 13 says "first PR = F0–F2".
  Add a cross-map.
- `Contracts/Hoare.lean` and `Contracts/Composition.lean` ship in the B3 image but are unusable before
  G2. Defer them out of the image.
- `simple_authorization` has no semantics domain (it is not a memory property). Mark deferred or give
  it its own semantics sketch.

## 9. Required edits by document

| Document | Section | Change |
|---|---|---|
| design | 4.2 | Language applicability per family; managed-language V1 family |
| design | 4.5 | IR as multilingual contract; `Throw`/`Panic` events; explicit "not LLVM IR" |
| design | 4.5.2 | Grammar/lowering in Lean; per-language certificate `formal-correspondence/<lang>/1` |
| design | 4.6 | Remove `approved_native`, `bv_decide`, CBMC; no Mathlib; syntax-walk allowlist; `partial def`/`extern` rules |
| design | 4.7 | `proof_assurance ∈ {kernel_only, unaccepted}`; add `typed_frontend_unavailable` gap |
| design | 5.3 | `max_concurrency = 1` as v1 admission implementation |
| design | 5.5 | Reproduced violation on certified function → trusted-base incident |
| design | 15 | Resolve open decision 3 (CBMC) as "not used" |
| buildout | 1.1, 5.3, 6.2, 8 | Remove native profile and its policy files/settings |
| buildout | 2, 4.2 | Name the Clang AST producer job/step; forbid tree-sitter as authority |
| buildout | 4.2 | Add `proof/auto` task before workbench |
| buildout | 6.2 | Core-only library; drop Mathlib; defer `Contracts/*` |
| buildout | 9.4 | Specify syntax-walk allowlist for `check_proof_candidate` |
| buildout | 12 | F/B cross-map; B0 adds semantic-authority matrix and paired-twin template gate |
| buildout | 16 | Strike ADR #4; add ADR for typed-frontend producers per language |

## 10. Typed frontends as a shared producer for review and verification

The typed frontends in section 4 are not a verification-only concern. Today the review package for
any non-C/C++ language carries no semantic layer: `job_tree_sitter_ast` is untyped, CodeQL supplies
query-specific paths only, and the Clang CFG / LLVM IR / SVF producers exist only for C/C++. Red and
blue workers for Java, Go, Rust and C# therefore infer widths, conversions, resolved callees and
exception flow from surface text, which is where they are least reliable.

### 10.1 Decision: one typed-semantics producer, two consumers

Add a producer-stage job (working name `job_typed_semantics`; per-language step/task structure under
one dataset family `typed`) that runs the matrix's frontends over accepted sources and emits a
bounded per-function record. The formal verifier and the review packages both consume it; they differ
only in acceptance threshold.

| Consumer | Threshold | Behavior on gap |
|---|---|---|
| Formal frontend (`lower_<lang>`) | Complete closure for one function | Fail closed: `typed_frontend_unavailable` or `unsupported_class`; no model built from untyped facts |
| Red/blue/completeness workers | Partial allowed | Gap stays visible in the row (`callee_unresolved`, `type_unknown`); worker reasons with the gap named |

This also fixes the ordering problem: typed facts are generated by an ordinary accepted producer
*before* indexing, so by the time `job_formal_verification` runs, every candidate already has (or
provably lacks) its typed closure. Verification never invokes a frontend itself.

### 10.2 Record contents (bounded, per function)

- Signature with exact types, widths and signedness; parameter and return nullability where the
  language expresses it.
- Call sites with resolved targets: static/overload resolution exact; virtual/interface dispatch as a
  bounded candidate set with a coverage flag; unresolved marked, never omitted.
- Every implicit conversion, promotion, narrowing cast and unsigned/signed reinterpretation, with
  source span.
- Thrown and propagated terminal events: Java checked/unchecked exceptions, Go `panic`/`recover`,
  Rust `?`/`unwrap`, C# exceptions.
- Definite-initialization facts; constant-folded guard values and frontend-proved dead branches.
- Rust `unsafe` regions; C/C++ `__builtin_*`/fortified callee identities; preprocessor-expanded
  callee names.
- `semantic_level ∈ {typed, untyped}` and the frontend/toolchain identity on every row.

### 10.3 Contracts

- Producer-stage and non-inference only, like every other shard; no frontend invocation during a
  worker call or a workbench operation.
- Accepted through the ordinary handoff/manifest/inventory path; new family `typed` in
  `runtime/datasets.py:FAMILIES`; shard prefix `typed-<lang>-`.
- Read-only retrieval `query_typed_facts`, scoped like `query_code_graph`, package-granted IDs only;
  exposes resolved identities and gap flags, never source bytes.
- The package must carry `semantic_level` so a tree-sitter-only package and a `javac`-backed one are
  distinguishable to the worker; otherwise workers overclaim on the former.
- Per-language fail-closed conditions follow section 4's matrix. Missing classpath, module cache or
  include paths produce a typed row with gaps, not a silent fallback to tree-sitter.

### 10.4 Placement in the buildout

- B1/B2: implement the C/C++ Clang AST producer as the first `job_typed_semantics` language, since the
  formal frontend depends on it; the same job hosts Java/Go/Rust/C# steps as they are added.
- Topology: ordinary `wave1_review` producer before `job_review_data_indexing`, enabled independently
  of formal verification (it is review evidence in its own right).
- Guidance: existing red/blue/completeness roles gain `query_typed_facts`; no new persona.
- ADR: per-language frontend selection and pinning (replaces the struck CBMC ADR).

### 10.5 Edits implied

| Document | Section | Change |
|---|---|---|
| design | 2 | Add typed-semantics producer to the baseline table as a new prerequisite |
| design | 4.4 | Slice builder reads typed rows; tree-sitter demoted to navigation |
| buildout | 2, 4.1 | Add `job_typed_semantics` to the facility table and job inventory as an ordinary producer |
| buildout | 5.4 | Dataset family `typed`, prefix `typed-<lang>-` |
| buildout | 9.2 | Add `query_typed_facts` to the read-only tools |
| buildout | 9.3 | Grant `query_typed_facts` to review roles |
| buildout | 12 | B1/B2 host the first language; later languages are additive slices |
