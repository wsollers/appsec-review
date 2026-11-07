# Conversation Transcript: Lean-Guided Formal Verification for Application Security

> **Archive status:** Discussion transcript for the `appsec-review` project. This is a conversation record, not an approved architecture, implementation claim, validated proof, or authorization to run security tests.
>
> **Scope:** All substantive user/assistant turns in this ChatGPT discussion through the request to save it in `wsollers/appsec-review`. Rich UI diagrams have been translated to Markdown flow diagrams and tables; ephemeral tool progress, citations rendered by the chat interface, and interface-only widgets are not reproduced verbatim. Where necessary, prose has been lightly normalized for portability. **Use the original ChatGPT conversation for a byte-for-byte chat export.**
>
> **Relevant existing project documentation:** [Binary decompilation](../architecture/binary-decompilation.md), [bounded dataflow slices](../architecture/dataflow-bounded-slices.md), [code-graph precomputation](../architecture/code-graph-precomputation.md), [Clang static analysis](../architecture/clang-static-analysis.md).

---

## Turn 1 — User: Lean, fuzzing, network stacks, and an MCP harness

> I want to use lean to formally verify programs. Network stacks authentication recs  etc. If lean finds something might be askew how would I use a fuzzer both against its functions and network. Ie I can have you build a harness so that we can confirm there is issue. Then build an mcp/skill so that as you formalize with lean you can use a docker image with compiler and the source to fuzz or gen packets and replay or fuzz. Opinions on how to proceed.

### Assistant

I think this is an excellent direction, especially for network stacks, authentication protocols, packet parsers, and security-sensitive software.

I would build it as a **Lean-guided verification and fuzzing system**, with an MCP server that provides access to compilers, instrumented binaries, fuzzers, network test environments, and reproducible test cases.

There is one architectural decision I would make from the outset:

**Lean should define and verify the properties we expect software to satisfy. Fuzzing should help determine whether the actual implementation satisfies those properties.**

The system should work in both directions:

- **Lean → Fuzzer:** Formal analysis identifies a potential counterexample, an unsupported assumption, or a suspicious boundary condition. We generate and execute targeted tests against the implementation.
- **Fuzzer → Lean:** Fuzzing discovers a crash, unexpected state transition, or behavioral discrepancy. We use the result to refine the formal model, construct a counterexample, and determine exactly which property was violated.

An unfinished Lean proof is not itself evidence of a software bug. The proof might simply require additional lemmas, or the specification might be wrong. Our system needs to distinguish these cases.

#### 1. The architecture I would build

```text
AI verification agent
  Source review / specification / proof development / evidence analysis
                  |
             MCP server / skill
             /              \
Formal verification       Dynamic verification
Lean specifications       Compilers and sanitizers
State machines            Function-level fuzzing
Invariants                Protocol and packet fuzzing
Proof obligations         Trace capture and replay
             \              /
           Behavioral conformance oracle
          Expected results vs actual results
                  |
       Evidence and regression artifacts
   Minimal input / PCAP / trace / proof / build provenance
```

The important component is the **behavioral conformance oracle**. Without it, the fuzzer primarily finds crashes and other instrumented failures. With it, the fuzzer can detect logically incorrect behavior even when the program executes normally.

That is especially valuable for authentication, where an unauthorized state transition may occur without any crash.

#### 2. Two different kinds of fuzzing

I would implement two testing modes, initially using the same underlying test-case and reporting format.

| | Function-level fuzzing | Network-level fuzzing |
|---|---|---|
| Target | Parser, decoder, validator, authentication routine | Running server, protocol stack, authentication endpoint |
| Input | Bytes, structures, function arguments | Packets and sequences of protocol messages |
| Execution | In-process test harness | Isolated network environment |
| Main advantage | Very fast, precise coverage | Tests integration, sequencing, and real protocol behavior |
| Best evidence | Failing input and sanitizer trace | Reproducible transcript, PCAP, server state and logs |

**Function-level testing comes first.**

Suppose the source contains a packet parser with a length field.

We can formalize the required invariant in Lean:

\[
\forall p,\quad
\operatorname{Accepted}(p)\implies
\operatorname{DeclaredLength}(p)\leq
\operatorname{AvailableBytes}(p).
\]

Then build a harness that invokes the actual parser using arbitrary byte sequences.

```text
fuzz(input):
    reset_target()

    actual = implementation.parse(input)
    expected = reference_model.parse(input)

    assert conformance(actual, expected)
    assert no_memory_safety_failure()
```

This is conceptual pseudocode. The real harness will depend on the API and memory ownership rules of the source code.

We can make the Lean specification executable for differential testing, or use it to generate expected outcomes and test vectors. For high-throughput fuzzing, we should avoid invoking a separate Lean process for every generated input.

I would choose **libFuzzer or AFL++**, initially with Clang's AddressSanitizer and UndefinedBehaviorSanitizer enabled. Their coverage instrumentation lets the fuzzer prioritize inputs that exercise new code paths, while sanitizers detect faults that the logical oracle might miss.

**Network-level testing follows.**

Now imagine the parser is part of an authentication service. Calling the parser directly cannot establish whether the complete service handles sessions correctly.

For this, I would generate message sequences, not just isolated malformed packets.

Consider this simplified authentication protocol:

```text
Unauthenticated --(valid credentials)--> Authenticated

Security properties:
- Valid authentication permits the authorized transition.
- Invalid credentials cannot authenticate.
- Protected operations after logout must be denied.
- Replayed or expired credentials must not create an unauthorized session.
```

The Lean model specifies valid transitions. A protocol fuzzer generates sequences such as authentication, logout, reconnection, and protected requests, varying both the order and the content.

If the service accepts a protected operation after logout, we investigate a possible violation even though the server never crashed.

For network tools, I would use **Scapy** for packet construction and PCAP handling, **boofuzz** for structured protocol sessions, and consider **AFLNet** for state-guided protocol fuzzing.

One complication is that **replaying a PCAP is not necessarily the same as replaying a protocol transaction**. TCP sequence numbers, cryptographic handshakes, nonces, and session identifiers may need to be regenerated. I would preserve both raw captures and logical message traces.

#### 3. What the Docker-backed MCP server should provide

I would keep the MCP service relatively small and make its operations deterministic.

| MCP tool | Responsibility |
|---|---|
| `source.inspect` | Identify build system, functions, signatures, and dependencies |
| `harness.generate` | Create a reviewable fuzz harness around a chosen function |
| `target.build` | Compile source with suitable instrumentation |
| `lean.verify` | Compile proof modules and audit theorem dependencies |
| `fuzz.function` | Run bounded in-process fuzzing |
| `fuzz.protocol` | Exercise an isolated service with structured messages |
| `case.minimize` | Reduce a failure to a smaller input or message sequence |
| `case.replay` | Reproduce the case against the exact build |
| `finding.report` | Assemble evidence, classification, and provenance |

These would be typed tools, not an unrestricted shell exposed to the model. MCP supports structured input and output schemas, which is useful for making operations predictable and results machine-readable.

The **skill** would explain how the agent should orchestrate these tools: how to select targets, establish proof obligations, generate suitable harnesses, distinguish failures from genuine defects, and report findings.

The **MCP server** would handle actual execution, resource enforcement, artifact storage, and returning structured results.

**Docker layout:**

```text
MCP controller / job supervisor
    |-- Lean image (Lean 4, mathlib, verification libraries)
    |-- Compiler image (Clang, LLVM, AFL++, sanitizers)
    '-- Network lab (target service, packet generator, capture)
                       |
              Immutable evidence repository
     Source revision / input corpus / build logs / proofs / reproducers
```

The native fuzzing image should not need network access. The protocol lab should use a dedicated internal Docker network, with only the test containers connected and no external target access by default.

The containers should run without unnecessary privileges, with bounded CPU, memory, process count, execution duration, and filesystem access. I would favor rootless execution, restrict dangerous capabilities, and never mount the host Docker socket into the untrusted test environment.

For raw packet injection, any additional network capability should be isolated to the appropriate test component, not granted throughout the system.

#### 4. Connecting formal verification to existing source code

This is probably the hardest part of your idea.

Lean can prove theorems about a model of a program. That does **not** automatically mean the compiled C, C++, or Rust implementation has been verified.

We need a trustworthy connection between the source and the program modeled in Lean.

| Language | Approach |
|---|---|
| Rust | Explore Charon + Aeneas to translate supported Rust code into Lean, then prove properties of the extracted program |
| C/C++ | Model relevant semantics in Lean, use dynamic conformance testing, and add source-level verification tools where needed |

For Rust, there is substantial progress. Aeneas supports a Lean backend, although its documented support is still limited to a subset of Rust, principally safe sequential code.

A September 2026 research report describes using Rust, Aeneas, and Lean to verify parts of Microsoft's SymCrypt implementation, including functional correctness and memory-safety-related properties. This is encouraging evidence that the approach can be applied to production cryptographic software.

For C/C++, I would consider complementary tools such as **Frama-C** for proving source-code contracts. Its WP component supports deductive verification of annotated C code.

The important rule is that a passing set of conformance tests cannot replace a refinement proof. We should report exactly what has been proven, what has only been tested, and what remains assumed.

Lean proof auditing should also check dependencies with `#print axioms`, so a theorem relying on `sorryAx` or an unreviewed axiom cannot accidentally be reported as fully established.

#### 5. Evidence is just as important as discovery

I would make every suspected defect produce an evidence package. For example:

| Field | Illustrative value |
|---|---|
| Finding | `AUTH-001` |
| Property | `protected_action_requires_auth` |
| Lean expectation | Request denied |
| Observed result | Request accepted |
| Minimal trace | Login → Logout → Protected request |
| Evidence | Test input, message trace, PCAP, server log |
| Reproduction | Deterministic replay after clean reset |

This example illustrates the desired reporting format; it is not a finding against an actual implementation.

The full artifact should also record the source commit, image digest, compiler version and flags, seed, harness version, Lean specification version, and reproduction outcome.

I would maintain distinct verdicts for a confirmed property violation, a sanitizer-detected fault, a model/implementation discrepancy needing review, an incomplete formal proof, and a failure that could not be reproduced.

That separation prevents the agent from converting every unexpected result into a vulnerability claim.

#### 6. How I would proceed

I would organize implementation into four stages.

1. **Stage 1 — Working function-level prototype.** Pick a small C or Rust packet parser with a known build procedure. Formalize two or three properties in Lean, write a real in-process harness, run sanitized fuzzing, and generate reproducible evidence.
2. **Stage 2 — Protocol and authentication testing.** Add a state-machine model, structured message generation, session reset, network capture, and sequence replay in the isolated Docker lab.
3. **Stage 3 — MCP server and skill.** Expose the proven tools through typed MCP operations, with explicit execution policies and a skill that guides the Lean-to-fuzzer and fuzzer-to-Lean workflows.
4. **Stage 4 — Large-codebase integration.** Use call graphs, CodeQL findings, CPG analysis, and dataflow information to identify promising verification targets. Generate bounded harnesses for those targets rather than trying to translate or fuzz the entire application at once.

That final stage fits naturally with the CodeQL and bounded call-graph work you've been considering for your AppSec review framework. A call graph identifies where to investigate; Lean identifies properties worth proving; fuzzing supplies concrete behavioral evidence. The combination can make the agent substantially more targeted.

**My recommendation:** Start with a packet parser, then an authentication state machine, and only then make the infrastructure generic.

Make *counterexample minimization and deterministic replay* first-class capabilities from the beginning. A million generated inputs are much less useful than one minimal, independently reproducible violation of a precise specification.

The ultimate objective should be a system capable of saying:

> The source implementation violates property P. Here is the formal specification, the exact input or message sequence, the observed behavior, the reproducible evidence, and the source location. Here is what has been proven, what has been tested, and what remains uncertain.

That would go significantly beyond ordinary AI-assisted code review while retaining a clear distinction between mathematical proof and experimental evidence.

---

## Turn 2 — User: Starting with a SAST finding

> How, would I proceed from the other side. Given a sast finding use leans to formalize enough of the call graph to prove there is or is not a issue

### Assistant

Yes. In fact, I think **SAST finding → targeted formal verification → proof or counterexample** may be the more valuable starting point for the system you're designing.

Rather than formalizing an entire network stack or application, we use a SAST finding to identify a specific security property, construct the smallest sufficient representation of the relevant code in Lean 4, and attempt to prove whether a violation is possible.

**Use CodeQL to discover a suspected vulnerability, program slicing to isolate the relevant behavior, and Lean to determine whether the suspected behavior is actually possible.**

#### 1. Start with a SAST finding, not the entire program

Suppose CodeQL reports a possible authorization bypass:

```text
HTTP request (untrusted)
      |
    Handler
      |
Authorization check (is it sufficient?)
      |
Protected operation (security-sensitive sink)
```

A SAST path suggests a possible flow. It does not, by itself, establish that an executable path exists.

CodeQL's path queries expose source-to-sink dataflow, including interprocedural steps. Those results provide an excellent starting point for identifying the code to examine.

But we need more than a call graph.

We need a **security-relevant interprocedural program slice**, incorporating:

- Call relationships and possible indirect callees.
- Data dependencies, including aliases and mutations.
- Control-flow conditions that determine which branches execute.
- Authentication state, validation results, and relevant side effects.
- The assumptions necessary for the suspected path to be reachable.

For example, CodeQL might identify a flow from `request.accountId` to `readPrivateData`, but the actual code might reject that request unless the authenticated user owns the account.

Our job would be to establish whether that guard genuinely prevents unauthorized access.

#### 2. Turn the finding into a mathematical proposition

Let `S` denote program states, `I ⊆ S` the admissible initial states, and `T ⊆ S × S` the transition relation representing execution.

Define:

- `Reachable(s)`: state `s` can be reached from an admissible initial state.
- `Bad(s)`: state `s` contains the security violation specified by the finding.

The desired safety theorem is:

\[
\boxed{\forall s\in S,\quad \operatorname{Reachable}(s)\implies\neg\operatorname{Bad}(s)}
\]

A genuine violation requires:

\[
\boxed{\exists s\in S,\quad\operatorname{Reachable}(s)\land\operatorname{Bad}(s)}
\]

This gives us two fundamentally different verification goals:

| Goal | What we must establish |
|---|---|
| Prove the finding impossible | Every relevant reachable state satisfies the security property |
| Prove the finding possible | At least one valid execution reaches a state violating the property |

For the authorization example, the security property might be:

\[
\forall r,s,\quad
\operatorname{ProtectedAccess}(r,s)\implies
(\operatorname{Authenticated}(s)\land\operatorname{Authorized}(r,s)).
\]

Lean would attempt to establish this theorem from a model of the actual code and its environment.

**A crucial distinction:** Successfully proving the theorem about a hand-written model does not automatically prove it about the source code. We must also establish that the model faithfully captures the behavior relevant to the vulnerability.

That model-to-source connection is the most important soundness requirement in this entire design.

#### 3. Extract the minimum sufficient program slice

I would use **backward slicing from the vulnerability sink**, followed by selective expansion toward the relevant entry points.

```text
SAST finding / SARIF
       |
Backward program slice
  data / branches / calls / state
       |
       +-- Path constraints (reachability)
       '-- Function contracts (callee guarantees)
       |
Lean proof obligations
  reachability / invariants / prohibited behavior
```

Imagine the reported flow:

```text
handleRequest
  └── parseRequest
        └── getSession
              └── authorize
                    └── readPrivateData
```

Rather than formalizing all five functions in their entirety, extract only the parts relevant to the security property.

| Function | Relevant information |
|---|---|
| `handleRequest` | Entry conditions and request identity |
| `parseRequest` | How the account identifier is obtained |
| `getSession` | How the authenticated identity is established |
| `authorize` | Every condition permitting or denying access |
| `readPrivateData` | Conditions under which protected data is accessed |

We can eliminate unrelated logging, metrics, formatting, and other behavior *provided its exclusion is justified*. A logging call that mutates shared state or raises an exception, for example, may not be irrelevant.

I would build this using an interprocedural program-dependence graph rather than a call graph alone.

**The call graph tells us where execution might go. The dependence graph tells us which statements can influence the security outcome.**

**Bounded expansion:** Start at the reported sink; identify its data and control dependencies; expand calls that influence those dependencies; replace irrelevant or already verified functions with summaries; stop when the required proof can be completed or report unresolved assumptions.

A depth limit or token budget is a resource limit, **not a soundness justification**. If a call cannot be analyzed, its behavior must be conservatively modeled as unknown, or the theorem must remain conditional.

This prevents an agent from declaring a finding harmless simply because it stopped following the call chain.

#### 4. Formalize the actual decision logic in Lean

Consider this simplified source:

```c
int handle_request(Request *r, Session *s) {
    if (!s->authenticated)
        return DENIED;

    if (s->user_id != r->owner_id)
        return DENIED;

    return read_private_data(r->owner_id);
}
```

A SAST tool might report that the attacker-controlled `owner_id` flows into `read_private_data`.

However, the authorization guards could make the operation safe.

We can represent the relevant decision logic in Lean:

```lean
structure Session where
  authenticated : Bool
  userId : Nat

structure Request where
  ownerId : Nat

def reachesProtectedRead
    (s : Session) (r : Request) : Bool :=
  s.authenticated &&
    decide (s.userId = r.ownerId)

theorem protected_read_requires_authorization
    (s : Session) (r : Request) :
    reachesProtectedRead s r = true →
      s.authenticated = true ∧
      s.userId = r.ownerId := by
  simp [reachesProtectedRead]
```

This theorem establishes that the modeled operation is permitted only when the session is authenticated and its user ID matches the requested owner.

But we have not yet proven the C code is safe.

We still need to establish that:

- The Lean function correctly models the C control flow.
- The session's authentication state can be trusted.
- The user ID represents the correct security principal.
- No other path invokes the protected operation improperly.
- The relevant state cannot change between authorization and use.

That last point is particularly important for race conditions and time-of-check/time-of-use vulnerabilities.

#### 5. The really interesting part: proving the extracted model is sufficient

I would formalize this relationship as well.

Suppose we have a concrete program `C` and an abstract program `A` consisting only of the relevant slice.

Let

\[
\alpha:S_C\rightarrow S_A
\]

map concrete program states to their abstract counterparts.

For a proof of safety to transfer from the abstraction to the concrete program, we need two properties.

**Reachability coverage:**

\[
\operatorname{Reachable}_C(c)\implies
\operatorname{Reachable}_A(\alpha(c)).
\]

Every relevant concrete reachable state must be represented in the abstract model.

**Violation preservation:**

\[
\operatorname{Bad}_C(c)\implies
\operatorname{Bad}_A(\alpha(c)).
\]

The abstraction cannot erase the very security violation we are attempting to detect.

Given those properties, we can prove that safety of the abstract model implies safety of the concrete program.

```lean
theorem safe_by_abstraction
    {C A : Type}
    (α : C → A)
    (reachableC : C → Prop)
    (reachableA : A → Prop)
    (badC : C → Prop)
    (badA : A → Prop)
    (coverage :
      ∀ c, reachableC c → reachableA (α c))
    (preservesViolation :
      ∀ c, badC c → badA (α c))
    (abstractSafe :
      ∀ a, reachableA a → ¬ badA a) :
    ∀ c, reachableC c → ¬ badC c := by
  intro c hc hbad
  exact
    (abstractSafe (α c) (coverage c hc))
      (preservesViolation c hbad)
```

This is a generic theorem about sound abstraction, not a verification of a specific program.

However, it gives us the proper structure for our system. It tells us exactly which relationships must be established before claiming that a Lean proof applies to the original code.

The practical advantage is that we can start with a coarse abstraction and selectively refine it without formalizing the entire application.

#### 6. What if Lean cannot prove the property?

That should trigger an investigation, not an automatic vulnerability verdict.

- **Outcome A — Safety proven:** Lean proves the safety property, and the required model-to-source obligations are discharged. Result: Finding disproven within the explicitly verified source and environmental scope.
- **Outcome B — Counterexample discovered:** The model produces an execution that violates the security property. Generate a concrete test and replay it against the actual implementation. Result: Confirmed defect if the execution is feasible and the implementation exhibits the violation. Otherwise, investigate abstraction imprecision.
- **Outcome C — Proof remains unresolved:** The solver needs additional invariants, cannot analyze a callee, encounters unsupported language behavior, or exceeds its budget. Result: Inconclusive. Retain the finding and record the missing proof obligations.

For a counterexample, the agent could invoke the fuzzing or symbolic-execution harness we discussed earlier, using the violating assignments as test inputs.

For a proof, the agent should preserve the Lean theorem, its dependencies, all external assumptions, and the exact source revision.

#### 7. Combine Lean with automated model checking

Lean should serve as the proof authority and the place where specifications and reusable function contracts live. But there is no reason to require an AI agent to prove every path condition manually.

| Task | Primary tool |
|---|---|
| Discover suspicious flows | CodeQL |
| Extract relevant statements and dependencies | CodeQL plus compiler/IR analysis |
| Define formal properties and compose function contracts | Lean 4 |
| Prove bitvector arithmetic conditions | Lean `bv_decide` |
| Explore bounded C/C++ execution paths | CBMC |
| Translate supported Rust into a formal model | Charon + Aeneas |
| Confirm a potential concrete violation | Compiler, harness, fuzzer, replay |

Lean's `bv_decide` produces proofs checked within Lean, making it particularly useful for packet lengths, integer arithmetic, and bitwise operations.

CBMC can verify assertions across bounded C program executions and generate counterexample traces. Its conclusions must be scoped to the modeled inputs and unwind bounds.

For supported Rust, Aeneas provides a much closer source-to-Lean translation pathway than rewriting functions by hand, although it still has important limitations around unsafe code and concurrency.

#### 8. Extend the MCP service with a SAST verification workflow

| MCP operation | Function |
|---|---|
| `finding.ingest` | Read SARIF or other supported SAST results |
| `finding.context` | Retrieve source, exact revision, relevant symbols, and rule semantics |
| `slice.construct` | Compute the backward security-relevant slice |
| `slice.expand` | Expand an unresolved call, alias, guard, or state dependency |
| `contract.generate` | Propose function preconditions, postconditions, and invariants |
| `lean.model` | Produce or extract a source-connected Lean representation |
| `lean.prove` | Compile and check the theorem and its dependencies |
| `counterexample.validate` | Check model witnesses against concrete execution |
| `finding.adjudicate` | Assemble the evidence and a scoped verdict |

SARIF supports code-flow information and associated locations, making it a reasonable interchange format for the input side.

I would require every model to carry a **coverage manifest** listing all relevant functions, modeled side effects, unresolved calls, assumptions, and supported execution conditions. The MCP service could then refuse to certify a false positive if required relationships remain unproved.

Illustrative adjudication record:

| Field | Value |
|---|---|
| SAST finding | `AUTH-001` |
| Finding category | Authorization bypass |
| Relevant functions | 5 modeled or summarized |
| Security theorem | `protected_read_requires_authorization` |
| Model proof | Established |
| Source correspondence | Requires verification |
| Verdict | Conditional — not yet disproven |

This example shows why proving the model alone must not close the finding.

#### 9. Three levels of assurance

1. **Path infeasibility:** The particular SAST-reported path cannot execute under the modeled conditions. This may eliminate one suspected path but does not necessarily rule out other ways to reach the same sink.
2. **Property verification:** Every relevant path in the sufficiently complete model satisfies the security property. This is stronger and requires adequate coverage of the concrete program.
3. **Whole-system assurance:** The result remains valid under the real operating environment, including external dependencies, concurrency, deployment configuration, and trust boundaries. This is significantly harder.

I would have the system report these levels separately instead of treating them as equivalent.

**Where I would start:** Take **one CodeQL authorization, taint-flow, or bounds-checking finding** and produce a bounded program-dependence slice, Lean model, security theorem, assumptions manifest, proof or counterexample, and optional executable reproducer.

I would initially favor C code with straightforward control flow or supported safe Rust, rather than attempting a full TCP or TLS implementation.

The architecture can grow into **a proof-directed SAST adjudicator that expands only the code necessary to resolve each finding.**

The most interesting long-term possibility is reusable verified function summaries. Once the system has established that a particular authentication helper guarantees a property under certain preconditions, future SAST findings can reuse that theorem rather than reanalyzing the helper from scratch.

---

## Turn 3 — User: Binary-only software, Fallout, Ghidra, and recompilation

> Now, if I had an old game. Say Fallout thar source didnt exist for could we recompile with ghidra and do the same process? Ie scan with codeql, clang etc...? Use leans etc... it would be equivalent correct?

### Assistant

**Yes, you can apply essentially the same verification workflow to an old game for which you only have the executable. But the formal guarantees are not automatically equivalent.**

In fact, I'd design your system to support both source-code and binary-only analysis. For a game like the original *Fallout*, we could use Ghidra to recover its structure, CodeQL to analyze reconstructed source, Lean 4 to prove properties, and binary fuzzing to validate findings against the original executable.

The major difference is that **we must establish that the recovered representation accurately preserves the behavior of the original binary.**

#### 1. Ghidra does not simply recreate compilable source

Ghidra disassembles machine code and decompiles it into C-like pseudocode. That pseudocode is not necessarily compilable or semantically identical to the original program.

A Carnegie Mellon Software Engineering Institute study found substantial obstacles to recompiling Ghidra output, including missing declarations and incorrectly inferred function signatures.

A typical pipeline would look like this:

```text
Original game executable
       |
Ghidra (functions, CFG, call graph, P-code)
       |
       +--- Recovered C
       |      Repair signatures and types
       |      CodeQL / Clang / sanitizers
       |
       '--- Binary semantics
              P-code / lifted IR / instructions
              Lean / symbolic execution
       |
Original binary fuzzing and replay
```

The two branches serve different purposes. The reconstructed C makes familiar SAST and compiler tooling available. The lifted binary representation lets us reason closer to what the actual executable does.

#### 2. Which tools can we reuse?

| Tool | Binary-only application |
|---|---|
| **Ghidra** | Recover functions, control flow, data structures, and P-code |
| **CodeQL** | Analyze reconstructed C/C++ source |
| **Clang/LLVM** | Compile recovered code and run source-level instrumentation |
| **Lean 4** | Prove properties of a recovered or lifted model |
| **angr** | Symbolically explore paths through the original executable |
| **AFL++** | Fuzz the original binary without source code |
| **rev.ng** | Explore recompilable C and LLVM-based lifting |

CodeQL supports a no-build mode for C/C++, so we don't necessarily need to recompile the entire recovered game before running source analysis. Accuracy can be lower than a properly configured build.

AFL++ has QEMU and Frida modes that instrument closed-source binaries without requiring recompilation.

rev.ng explicitly targets recompilable C output and uses LLVM-based analyses, making it worth evaluating alongside Ghidra.

angr supports control-flow analysis, lifting, and symbolic execution directly on binaries.

#### 3. I would actually prefer verifying P-code over reconstructed C

This is where the approach gets especially interesting.

Ghidra translates machine instructions into **P-code**, an intermediate representation that expresses their low-level operations.

For example, an original instruction might have semantics equivalent to:

```text
r0 = r1 + r2
if r0 < r3:
    branch target
```

P-code represents operations such as integer addition, comparisons, loads, stores, and branches in a processor-independent form.

We could develop a Lean model of a subset of P-code instructions, including:

- Fixed-width integers and bitvectors.
- Machine registers.
- Memory and address calculations.
- Conditional branches.
- Stack behavior and function calls.
- Memory-safety and security invariants.

Then, instead of merely asserting that reconstructed C faithfully represents the binary, we could prove properties about the lower-level operations.

For example, suppose a game asset loader computes:

\[
\text{requiredBytes}=\text{entryCount}\times\text{entrySize}.
\]

If the original executable uses 32-bit arithmetic, then the multiplication may wrap modulo `2^32`.

Lean can model the actual bitvector arithmetic rather than relying on potentially inaccurate recovered C types.

We might ask Lean to establish:

\[
\forall n,\quad
\operatorname{Accepted}(n)\implies\operatorname{MemoryAccessSafe}(n).
\]

If that property fails, we could use symbolic execution to generate a candidate input and test it against the executable.

**This avoids the need to recompile the entire game just to investigate one suspicious routine.**

However, P-code lifting also introduces proof obligations. We need to account for instruction semantics, external calls, memory layout, and correct identification of executable code. A proof over a P-code model is only a proof about the original binary to the extent that the correspondence is established.

#### 4. Use both binaries as a differential-testing pair

Where we successfully reconstruct and compile a function, I would test both implementations using identical inputs:

```text
Generated test input
   |                      |
Original binary      Recompiled function
   |                      |
Observed A           Observed B
   \                      /
       Differential oracle
 Outputs / state / errors / memory effects
```

Matching outputs across many tests would increase our confidence in the reconstruction. A mismatch would tell us something important needs investigation.

But finite differential testing does not prove equivalence for all inputs. To make a formal equivalence claim, we would need an appropriate refinement or simulation proof connecting the representations.

#### 5. A good first experiment with a classic Fallout executable

I would not start by trying to reconstruct an entire game.

Instead, choose one contained, security-relevant function, such as a save-game parser, resource archive reader, map-data decoder, or scripting interpreter operation.

For a save-game parser, the workflow could be:

1. Load the legally obtained original executable into Ghidra.
2. Identify the file-reading routine and its callers.
3. Recover the relevant control-flow and data dependencies.
4. Identify a specific memory-safety property, such as preventing out-of-bounds reads.
5. Export the relevant low-level representation and recovered C.
6. Analyze the recovered C with CodeQL and Clang where feasible.
7. Express the property and applicable execution semantics in Lean.
8. Use angr to investigate whether violating paths are feasible.
9. Fuzz the original executable or an isolated original binary routine using crafted save files.
10. Preserve a minimal reproducer, binary hash, execution trace, and proof assumptions.

An old Windows game may require a Windows-compatible testing environment, such as a compatible VM or Wine-based setup. Binary-only instrumentation can be harder with GUI applications, callbacks, unusual memory layouts, and older runtime dependencies.

#### 6. What would actually be equivalent?

| Claim | Valid? |
|---|---|
| We can reuse the same SAST → Lean → fuzzing workflow | **Yes** |
| Recompiled decompiled code is automatically equivalent to the original binary | **No** |
| We can prove a security property of the original binary through a sound lifted model | **Yes, with the required correspondence and environmental assumptions established** |

This suggests that our larger MCP architecture should support two input modes:

**Source mode:** CodeQL → source slice → Lean → proof/counterexample → fuzzing.

**Binary mode:** Ghidra/angr → lifted slice → Lean → proof/counterexample → binary fuzzing.

Both can share the same findings database, proof contracts, fuzzer orchestration, and evidence system.

One additional architectural recommendation: make each formalized routine carry an explicit **representation and assurance level**:

- Recovered pseudocode only.
- Recompiled and tested against the original.
- Semantics extracted from machine instructions.
- Formally connected to the original binary by a verified correspondence theorem.

That would prevent the AI from inadvertently treating reconstructed source as authoritative.

**My preferred starting point would be Ghidra + angr + Lean + AFL++, with CodeQL and Clang added when we have sufficiently recovered C code.** I would avoid requiring a complete recompilation of Fallout before we can verify one function.

Ultimately, this could become a unified source-and-binary verification platform. You could investigate modern open-source network stacks and decades-old closed-source software using the same security-property language, proof infrastructure, and reproducible evidence system—the difference being how we establish the connection between the formal model and the actual executable.

---

## Turn 4 — User: Would assembly be better?

> Would it be better to just analyse the assembly?

### Assistant

**Yes. For a game with no source code, I would prefer analyzing the original assembly rather than attempting to reconstruct and recompile the entire program.**

More precisely, I would use **assembly as the authoritative representation, an instruction-level intermediate representation for automated analysis, and Lean 4 for formal verification.**

This eliminates a major source of uncertainty: whether Ghidra's reconstructed C code accurately reproduces the behavior of the original binary.

However, I would not try to prove properties directly over millions of individual assembly instructions. I'd retain the machine-level semantics while simplifying the representation used for proofs.

#### 1. The architecture I would recommend

```text
Original executable
    |
Ghidra disassembly and binary analysis
Functions / control flow / calls / memory references
    |
Raw P-code / VEX intermediate representation
Registers / flags / fixed-width arithmetic / loads / stores / branches
    |
Security-relevant program slice
    |
Lean 4 verification
Safety theorem / reachability / proof or counterexample
    |
Original executable testing
Fuzzing / concrete execution / reproducible evidence
```

Ghidra's raw P-code translates processor instructions into lower-level operations while generally preserving their control-flow meaning. The angr framework provides a comparable approach through VEX IR. Both are designed to make binary-level analysis more manageable across different instruction sets.

#### 2. Why this is better than reconstructed C

| Consideration | Reconstructed C | Assembly / instruction IR |
|---|---|---|
| Original integer widths | May be inferred incorrectly | Explicit in instruction semantics |
| Signed versus unsigned operations | Can be misrepresented | Determined by instructions and flags |
| Register and flag effects | Often abstracted away | Directly represented |
| Memory behavior | Depends on recovered types | Modeled through concrete addresses and loads/stores |
| Compiling a replacement program | Often difficult | Not required |
| Connection to shipped executable | Requires substantial validation | Closer, but lifting still needs validation |
| Proof complexity | Usually lower | Usually higher |

For security verification, the benefit of preserving the exact integer widths and machine operations is especially important.

We can still display Ghidra's decompiled C to help an AI understand what a routine is intended to do. We simply wouldn't treat that output as the authoritative definition of its behavior.

#### 3. Example: detecting integer overflow in an assembly routine

Suppose the game loads a resource containing a count of records. The binary computes the storage needed and compares it with an available buffer size.

An illustrative x86 instruction sequence might be:

```asm
; eax = record count
; edx = available buffer size

imul eax, eax, 4
cmp  eax, edx
ja   reject

; Continue using the accepted length
```

The multiplication produces a 32-bit result. If the program ignores the multiplication's overflow indication, the result can wrap.

For example:

\[
\begin{aligned}
n &= \texttt{0x40000001}=1{,}073{,}741{,}825,\\
n\cdot4 &= 4{,}294{,}967{,}300,\\
(n\cdot4)\bmod2^{32}&=4.
\end{aligned}
\]

If the available buffer contains eight bytes, the truncated result passes the comparison even though the true required size is much larger.

We could express the machine arithmetic in Lean:

```lean
import Mathlib

def accepts (count : BitVec 32) : Bool :=
  decide (count * 4 ≤ 8)

example :
    accepts 0x40000001 = true := by
  decide

example :
    (0x40000001 : Nat) * 4 > 8 := by
  decide
```

The two statements establish that the 32-bit acceptance check can succeed for a count whose mathematical byte requirement exceeds the available capacity.

Lean's `BitVec` type is particularly appropriate for reasoning about machine arithmetic, and `bv_decide` can automatically prove many fixed-width bitvector properties.

Of course, the actual routine would still need to be examined for additional guards and for whether that length discrepancy can cause an unsafe memory operation. We have demonstrated a potentially unsafe arithmetic condition, not automatically a complete vulnerability.

#### 4. How much assembly should we formalize?

I would **not formalize the entire game instruction by instruction**.

Instead:

1. Identify a suspicious routine through Ghidra or binary static analysis.
2. Extract the control-flow and data dependencies governing the suspected violation.
3. Lift the relevant instructions to P-code.
4. Translate that representation into Lean-compatible semantics.
5. Summarize other functions with verified contracts or conservative unknown behavior.
6. Prove the desired property—or construct a counterexample.
7. Test potential counterexamples directly against the original executable.

For instance, a routine manipulating a length field may require only a few dozen instructions for the arithmetic proof, even if the complete call path spans thousands.

One technical caution: raw P-code is not itself a complete formal proof of x86 semantics. Its lifting must be validated, and Ghidra's P-code call operations do not independently model every aspect of function-call behavior.

For stronger assurance, we can additionally compare lifted execution against the original binary and eventually develop verified instruction-semantics and refinement components in Lean.

#### 5. What I would change in the MCP design

I would make binary analysis a first-class capability, not an optional fallback from source analysis.

| MCP tool | Purpose |
|---|---|
| `binary.disassemble` | Recover instructions and candidate functions |
| `binary.lift` | Export raw P-code with original instruction addresses |
| `binary.slice` | Extract the security-relevant instruction slice |
| `binary.symbolic_execute` | Generate and analyze path conditions |
| `lean.translate` | Construct Lean definitions from lifted semantics |
| `lean.verify` | Prove safety properties or evaluate counterexamples |
| `binary.execute` | Run isolated tests against the original binary |
| `binary.compare` | Validate a lifted model against observed binary behavior |

CodeQL would remain valuable for source-available projects, but it would no longer be a required part of binary analysis.

**My recommendation:** Use a **hybrid representation with assembly-level authority**:

- Ghidra's decompiler for human and AI comprehension.
- Raw P-code for low-level semantic analysis.
- Lean for theorems about execution and security invariants.
- angr for path exploration.
- Binary instrumentation and fuzzing for reproduction.

There is also a longer-term direction I find especially worthwhile: **build a reusable Lean semantics library for x86 instructions and memory operations**, then implement a translator from Ghidra's P-code to those verified primitives.

That would let us automate verification of many different binary routines without inventing a new handwritten model each time.

The real technical challenge would shift from reconstructing C to demonstrating that the lifted instructions, memory model, external calls, and execution environment faithfully represent the original executable.

**The result would be considerably closer to formal verification of the actual shipped game than proving properties of reconstructed C code.**

---

## Turn 5 — User: Request to copy or move the transcript

> Can you give me transcript of this entire chat as a transcript in a text box i can copy to my appsec-review project or see if open has a way of moving it there

### Assistant

**Yes. ChatGPT has a built-in way to move this entire conversation into an existing ChatGPT Project.** That's better than copying a transcript because it preserves the complete discussion, including the diagrams, Lean examples, and technical details.

On your Android ChatGPT app:

1. Open the sidebar to view your chat history.
2. Find this conversation.
3. Open its **⋯** menu (you may need to long-press the conversation).
4. Select **Move to project**.
5. Choose **appsec-review**.

The conversation should then appear inside that project, where you can continue the discussion with its project instructions and files available.

One important distinction: if you mean your **ChatGPT Project**, use the steps above. If you mean your **GitHub repository** `wsollers/appsec-review`, the Move to project option won't put the transcript in GitHub. For that, we should create a verbatim Markdown transcript, suitable for storing as something like `docs/research/lean-guided-verification-discussion.md`.

I recommend moving the conversation into your ChatGPT Project first, if that is the intended destination. It preserves more context than a text export.

---

## Turn 6 — User: Clarification that this is a Codex project

> Its a codex project. Can I move it there?

### Assistant

**Yes, you can bring this conversation into your Codex `appsec-review` project**, although it isn't quite the same as moving a ChatGPT conversation into a ChatGPT Project.

OpenAI's current desktop documentation says you can open an existing ChatGPT conversation and **add it to a Codex chat**.

On the ChatGPT desktop app (Windows or macOS):

1. Switch to **Codex**.
2. Open your `appsec-review` project.
3. Start a new Codex chat.
4. Use the option to open an existing ChatGPT conversation and add it to the Codex chat.
5. Select this conversation about Lean, SAST, fuzzing, Ghidra, and assembly verification.

This brings the discussion into Codex as context; it doesn't relocate the original ChatGPT conversation or turn it into a repository file.

For permanent reference, preserve the discussion in the GitHub repository as `docs/research/lean-formal-verification-architecture.md`, with the proposed MCP architecture, CodeQL-to-Lean workflow, binary verification, P-code, fuzzing, and proof requirements.

Codex could then use it across future sessions without depending on this conversation remaining attached.

You can use the desktop integration for immediate context and the Markdown file for permanent project documentation.

---

## Turn 7 — User: Save the conversation in the repository

> In that case pull wsollers/appsec-review and add it as a md file id a new folder in docs called FormalVerification. Not sure on the casing.

### Archive note

The repository uses lowercase, hyphenated names such as `docs/architecture`, `docs/development`, and `docs/operations`. The matching directory chosen for this discussion is:

```text
docs/formal-verification/lean-guided-verification-conversation.md
```

This transcript is an archival input for future Codex work. It does **not** claim the described MCP tools, Lean translations, proof systems, fuzz harnesses, or binary-analysis interfaces already exist.

### Discussion's key implementation questions (index, not new commitments)

- How should a SAST finding be mapped to a formal security proposition?
- How is an interprocedural security-relevant slice constructed and its omissions justified?
- How can Lean proof obligations be connected to the exact source or binary revision?
- What constitutes a sound abstraction from C/C++, Rust, or machine instructions?
- How should the system distinguish proof failure, infeasibility, concrete exploitability, and unknown?
- What is the correct split among CodeQL, compiler IR, Ghidra/P-code, angr, CBMC, Lean, and AFL++?
- How should function-level and network-level fuzzing be orchestrated and replayed in isolated containers?
- Which evidence records and assurance levels are necessary for a defensible SAST adjudication?
