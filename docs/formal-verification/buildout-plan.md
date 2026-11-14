---
title: "Buildout Plan: SAST-to-Lean Verification and Proof-Directed Fuzzing"
kind: "history"
subsystem: "review inference and guidance"
status: "historical"
jobs: ["job_code_graph_index", "job_codeql_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_document_issue_analysis", "job_inference_security_review", "job_language_build", "job_review_data_indexing", "job_review_package_assembly", "job_sanitizer_build", "job_svf_alias_analysis"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Buildout Plan: SAST-to-Lean Verification and Proof-Directed Fuzzing

**Status:** Proposed implementation plan; no capability described here is implemented merely by
this document

**Design authority:** [SAST-to-Lean Verification and Proof-Directed
Fuzzing](sast-to-lean-and-proof-directed-fuzzing.md)

**Discussion input:** [Lean-Guided Formal Verification
Conversation](lean-guided-verification-conversation.md)

**Initial scope:** Source-available C/C++, accepted SAST leads, Lean 4 theorem proving for the
restricted `local_copy_bounds/1` subset, and obligation-directed function fuzzing

**Out of initial scope:** Binary-only verification, arbitrary C/C++ semantics, whole-application
fuzzing, raw packet generation, Internet-facing tests, and automatic finding closure

## 1. Outcome and binding decisions

This plan turns the design into an implementation sequence tied to the repository's current job,
dataset, configuration, container, retrieval, guidance, and run-custody contracts. The completed
vertical path must take one accepted SAST observation through a source-bound formal attempt and
produce one of three honest outcomes:

1. an accepted model theorem with explicit proof-assurance and source-correspondence levels;
2. a model witness that may be promoted only after feasibility and, where applicable, concrete
   reproduction; or
3. an inconclusive result with named coverage, semantics, proof, or execution gaps.

The following decisions are part of the buildout and should not be reopened implicitly in an
implementation pull request:

- Formal verification is a new evidence producer. It does not replace CodeQL, scanner ingestion,
  the claim ledger, R4/R5/R6 adjudication, or the final publication gate.
- The normal review graph remains non-executing with respect to target binaries. It may build Lean
  models, check Lean proofs, generate harness source, and compile-check a harness, but it does not
  run the target function.
- Target execution occurs only in `job_formal_fuzz_lab`, a standalone, operator-admitted job that
  is never an automatic dependency of `wave1_review`.
- The unit of dynamic work is one accepted Lean obligation and exact function/caller scope, not a
  finding, project, arbitrary function, or model-selected command.
- The Lean kernel is the proof authority for Lean theorems. CBMC, SMT, concolic execution, and
  fuzzing may supply candidates or observations; their clean completion is not a proof.
- Raw Lean sources, proof terms, harnesses, corpora, sanitizer logs, and reproducer bytes are
  protected artifacts. Only bounded summaries and resolving references are indexed.
- Ordinary review workers receive read-only, package-scoped retrieval. Formal-analysis workers
  additionally receive a job-scoped workbench for bounded property, slice, proof and harness
  proposals, but no worker receives a shell, filesystem, Docker, admission, target-execution or
  network capability.
- Formal methods is a responsibility and procedure, not a security-domain viewpoint. The first
  implementation adds roles, tasks, and runtime skills, but no new persona.

### 1.1 Binding design-review decisions

The companion design's sections 4.3.1-4.7 and gates G0-G4 are implementation contracts, not
optional follow-up research. Build one detached accepted-lead path before broad integration.

- First semantic subset: `local_copy_bounds/1`, specializing `index_and_copy_bounds`; complete
  single-function AST, fixed unsigned inputs, local constant-size byte arrays, guards/returns and
  recognized `memcpy`. Unsupported syntax, loops, recursion, heap and external state are rejected.
- Initial semantic authority: pinned pre-optimization Clang AST with complete preprocessed source
  custody and ABI. LLVM/graph facts guide navigation; they cannot erase source UB or establish
  correspondence by themselves.
- Source certification requires a validated `formal-correspondence/1` derivation, independently
  checked generic lowering/simulation and bad-event lemmas, non-vacuous entry scope, discharged
  premises and a `kernel_only` proof. Until implemented, the source-certified verdict is unavailable.
- Proof acceptance has separate `kernel_only`, `approved_native`, and `unaccepted` profiles.
  `bv_decide` may introduce native axioms; a successful Lean invocation is not kernel-only evidence.
- Producer-stage inputs do not require downstream package IDs. Post-review requests are standalone.
- Formal relations require a versioned predicate-admission adapter and explicit dependency lineage.
- Contradictions suspend certificate reuse and propagate append-only invalidation; immutable old
  artifacts remain historical, not silently current.
- Quota reservation, retries, cancellation, revocation and crash recovery are durable and atomic.
- Gates are distinct: G0 pipeline, G1 model usefulness, G2 source certification, G3 dynamic lab,
  G4 rollout. G0/G1 cannot authorize source certification or ordinary-graph integration/enablement.

## 2. Existing facilities to reuse

The buildout must extend the current architecture rather than create a second review system.

| Existing facility | Reuse in this buildout | Required extension |
| --- | --- | --- |
| Accepted job handoffs and `latest.json` pointers | Bind every input to one run, target snapshot, producer attempt, schema, and hash | Add formal jobs to the registry, topology where applicable, input-source matrix, and reuse invalidation |
| `job_codeql_analysis` and scanner observations | Supply the accepted lead, rule, sink, SARIF path, and scanner coverage | Add deterministic candidate qualification and exact observation binding |
| `job_code_graph_index` | Supply accepted calls, guards, ranges, SARIF paths, and producer neighborhoods | Add formal slice construction over bounded graph identities; do not run graph analysis during inference |
| `job_cpp_compiled_analysis`, `job_cpp_symbol_index`, and `job_svf_alias_analysis` | Supply compile units, LLVM/CFG facts, symbols, layout, and aliases | Add a supported-semantics matrix and explicit unresolved-edge accounting |
| `job_language_build` and `job_sanitizer_build` | Supply accepted build custody and instrumented native outputs | Add exact function/object selection and link-compatibility checks; never execute sanitizer outputs in these jobs |
| Run-local shared objects | Content-address large immutable bytes | Store Lean modules, proof outputs, harnesses, corpora, and logs as shared objects referenced from attempts |
| Dataset declarations and inventory | Account for every formal output and sanitized query route | Add dataset family `formal`, formal shard ownership, and protected-output declarations |
| Retrieval core and MCP adapters | Serve accepted, hash-verified, bounded evidence | Add a `formal` index, five read-only formal query tools, and a separate job-scoped formal workbench that cannot execute targets or publish directly |
| Guidance registry and pinned bundles | Select roles, tasks, personas, and runtime skills deterministically | Add formal roles/tasks/skills and preserve exact bundle pinning |
| Existing container catalog and admission limits | Pin images, enforce offline execution, resource bounds, and provenance | Add Lean and fuzz images plus a fuzz-specific execution admission profile |
| Review package assembly and inference review | Carry formal summaries into evidence-bound review | Add exact formal identities and scoped formal query grants to packages |

Accepted AST/source facts needed by the restricted checker are an explicit producer prerequisite.
If existing compiler outputs lack them, add a bounded producer export outside inference and name
that prerequisite; never reconstruct missing semantics from source snippets during a worker call.

The implementation must not treat a declaration, configured image tag, generated model, accepted
handoff, or successful container exit as evidence that the underlying security property is true.

## 3. End-state flows

### 3.1 Ordinary review flow: proof work, no target execution

The initial deployment is a detached operator-invoked verifier consuming accepted producer
artifacts. Only after G2 may graph integration add the two optional non-executing producers below;
ordinary verification enablement requires G4, and fuzz-planning enablement additionally requires G3.
This is the eventual topology, not the prerequisite for the first proof experiment:

```text
accepted target/build/scanner/graph handoffs
                   |
         job_formal_verification
     resolve -> slice -> lower -> prove
                   |
       job_formal_fuzz_planning (optional)
   triage -> harness design -> policy/compile check
                   |
        job_review_data_indexing
                   |
      job_review_package_assembly
                   |
       job_inference_security_review
```

`job_formal_verification` remains disabled in ordinary review until G4 passes after G2.
`job_formal_fuzz_planning` is independently disabled by default and can run only when formal
verification is enabled. Neither job may execute a produced target binary.

### 3.2 Authorized function-fuzzing flow

The operator selects an accepted experiment request and creates one immutable admission record.
The generic job launcher then starts the standalone lab with exact upstream handoff identities:

```text
accepted formal experiment request
accepted sanitizer/native build custody
operator-created formal-lab admission
                   |
          job_formal_fuzz_lab
 verify admission -> build -> fuzz -> minimize -> replay -> publish
                   |
       accepted formal observation and fuzz result
                   |
        job_formal_refinement
 compare model -> refine slice/model -> recheck Lean -> publish
```

The admission covers one run, target snapshot, lead, formal attempt, selected obligation set,
function/caller allowlist, image digest, operation allowlist, network profile, total campaign
count, wall-clock budget, CPU/memory/PID limits, input limit, output limit, and expiry. The lab
atomically validates admission and reserves quota before compile, calibration, campaign,
minimization, and replay; read-then-check quota logic is insufficient.
Changing any scoped value requires a new admission. Use idempotent operation IDs and a durable
`requested -> reserved -> running -> completed/failed/cancelled` state machine. Reserve worst-case
allowance before dispatch; reconcile actual use only after verified process termination. Recovery
must identify surviving processes and retain or conservatively charge uncertain consumption before
retry. Expiry/revocation denies new reservations; cancellation/revocation terminates active process
trees and preserves partial receipts. Revocations and quota events are append-only records linked
to the immutable admission.

`job_formal_refinement` is also standalone. It shares the formal library with the initial verifier
but publishes a new immutable attempt linked by `supersedes_attempt_id`; it never edits the earlier
attempt.

### 3.3 Returning authorized observations to review

Lab and refinement results occur after the original accepted index may already exist. They do not
mutate that index in place. To make the results visible to review workers, the operator explicitly
reruns the affected downstream publication chain:

```text
job_formal_refinement accepted handoff
             |
job_review_data_indexing (new accepted manifest)
             |
job_review_package_assembly (new packages)
             |
job_document_issue_analysis / job_inference_security_review
             |
normal deterministic gate and reporting
```

A contradictory accepted observation first publishes a challenge/invalidation event and suspends
new use of the affected source certificate and dependent contracts. A reverse-dependency walk
identifies affected packages/reports and creates an operator-visible correction queue. A
confirmed soundness failure revokes the certificate; a rejected challenge gets an explicit
resolution. Superseding an attempt never erases an invalidation. New consumers consult the current
validity view; historical pinned views retain their original result and disclose its historical
status and any known later challenge. Republishing or executing remains an explicit operation.

Every rerun binds the new accepted upstream hashes. Frozen earlier configurations and packages
remain immutable. This downstream rerun is not implied by successful fuzzing and is not started by
an inference worker. Challenge/invalidation recording occurs at accepted observation validation,
without waiting for optional refinement or downstream reruns; those later jobs resolve or publish
the consequence, not the initial suspension.

### 3.4 Later application-protocol flow

After core M2 acceptance, a separate `job_formal_protocol_lab` may consume a protocol experiment
request and a service image. It uses only a lab-internal network shared by the target service and a
protocol driver. It is not a prerequisite for M1/M2 and cannot add raw sockets, host networking,
external destinations, production credentials, or privileged containers without a new design and
authorization review.

## 4. New semantic jobs

### 4.1 Job inventory and topology

| Job | Graph status | Primary responsibility | Accepted inputs | Accepted outputs |
| --- | --- | --- | --- | --- |
| `job_formal_verification` | Optional `wave1_review` producer before data indexing | Qualify leads, build a property-specific semantic slice, lower supported semantics, check Lean, and publish formal attempts | Target catalog; language/native build; C++ compiled facts; CodeQL/scanner observations; code graph; aliases/symbols when available; prioritization | Candidate records, slices, IR, obligations, translation receipts, proof/witness records, contracts, attempt summaries, formal index shards |
| `job_formal_fuzz_planning` | Optional non-executing graph producer after formal verification and sanitizer build | Select experimentally answerable obligations and generate a declarative real-function harness package | Formal verification; sanitizer build; language build; exact source/build custody | Experiment requests, harness specs/source, oracles, seeds, compile-check receipts, planning summaries |
| `job_formal_fuzz_lab` | Standalone only; never a `wave1_review` vertex | Execute the fixed admitted build/fuzz/minimize/replay state machine | Formal fuzz plan; sanitizer/native build; target catalog; immutable lab admission | Build receipt, campaign receipt, minimized cases, replay receipts, observations, fuzz result summary |
| `job_formal_refinement` | Standalone only | Compare observations with formal predictions, refine only challenged assumptions, and check a new Lean attempt | Original formal attempt; accepted fuzz-lab handoff; code graph/build inputs | Refined slice/translation/proof/witness/attempt, explicit relationship to prior attempt |
| `job_formal_protocol_lab` | Deferred standalone job | Execute application-protocol sequences in an internal-only lab | Protocol request, service image, protocol admission | Logical transcript, sanitized state observations, protected captures and replay receipt |

`src/appsec_review/runtime/registry.py` must register each implemented job exactly once.
`src/appsec_review/orchestration/topology.py` must place only the two non-executing jobs in the
ordinary graph. `job_review_data_indexing` remains the closing inventory producer and must wait for
each enabled formal producer. The lab and refinement jobs must be absent from
`wave1_dependencies`; a unit test must assert that absence.

### 4.2 `job_formal_verification` step/task contract

| Step | Stable task | Behavior |
| --- | --- | --- |
| `scope` | `resolve_inputs` | Verify accepted upstream handoffs, accepted manifest/observation identities, target snapshot, compile unit, source hashes, and supported language/toolchain facts |
| `candidates` | `select` | Apply the closed property registry, deterministic rank/budget, and supported-semantics preconditions; publish a status for every considered lead |
| `slicing` | `build` | Construct property-specific data/control/call/memory dependencies and explicit closure/gap records from accepted bounded indices |
| `obligations` | `instantiate` | Instantiate a fixed template and exact violation dual; create premise ledger, check non-vacuous entry scope, and discharge caller/environment obligations independently |
| `translation` | `lower` | Lower the supported pre-optimization Clang AST to IR; retain complete function coverage, source binding and an independently checkable per-function derivation |
| `correspondence` | `check` | Check source binding, grammar, initial states, simulation, bad-event preservation, closure, premises and dependency validity against the generic Lean soundness theorem; emit `formal-correspondence/1` |
| `proof` | `check` | Generate a trusted challenge and definitions; elaborate candidates in isolation, independently replay and compare theorem/definitions, audit axioms, and derive proof assurance and logical status |
| `contracts` | `publish` | After G2/lifecycle validation, publish contracts only with checked premises/frame, explicit correctness scope and current transitive validity; model contracts remain model-only |
| `acceptance` | `publish_index` | Join independently accepted proof and correspondence receipts, derive the eligible verdict, create `formal` shards, and declare protected/artifact-only outputs |
| `acceptance` | `publish_handoff` | Publish the accepted handoff and coverage/gap accounting through the ordinary runner |

Candidate parallelism is bounded by typed task worker settings. Candidate IDs and processing order
are deterministic. A candidate timeout or unsupported construct produces a terminal typed attempt,
not an omitted row.

### 4.3 `job_formal_fuzz_planning` step/task contract

| Step | Stable task | Behavior |
| --- | --- | --- |
| `load` | `verify_inputs` | Resolve exact formal attempts/obligations and accepted build/sanitizer custody |
| `triage` | `select_obligations` | Admit only `candidate_witness`, `observable_guard_question`, `input_boundary_question`, or `model_discrepancy_replay` |
| `harness` | `generate` | Produce a declarative adapter around the original function and required actual caller/state setup |
| `oracle` | `bind` | Bind one property/sanitizer/behavior oracle, negative control, boundary seeds, and expected observations |
| `validate` | `policy` | Reject arbitrary commands, paths, network requests, unsupported calls, invalid object lifetimes, or widened function scope |
| `validate` | `compile_check` | Compile/link-check without executing the target and record exact flags, libraries, symbol resolution, and gaps |
| `acceptance` | `publish_handoff` | Publish protected harness material plus a sanitized experiment request and planning summary |

The worker may propose a harness specification; deterministic code owns path selection, template
rendering, AST checks, symbol checks, compiler invocation, and the final executable plan.

### 4.4 `job_formal_fuzz_lab` step/task contract

| Step | Stable task | Behavior |
| --- | --- | --- |
| `admission` | `verify` | Verify authorization record, request/target/function/image identity, allowed operations, expiry, and remaining aggregate quota |
| `workspace` | `materialize` | Copy the admitted source/build subset to bounded scratch; keep source/evidence mounts read-only |
| `build` | `compile_harness` | Invoke the fixed runner mode with validated compiler arguments; reject model-authored commands and unexpected outputs |
| `calibration` | `check_oracle` | Run separate known-failing tool-health and negative controls; verify target-operation instrumentation and analyzed/reproduction build relationship |
| `campaign` | `fuzz` | Run bounded libFuzzer/ASan/UBSan against the admitted executable/corpus with network disabled; record sink/branch coverage and oracle health separately |
| `minimize` | `same_fault` | Reduce only while preserving the exact oracle or sanitizer signature |
| `replay` | `clean_process` | Perform at least three fresh-process repeats with deterministic reset and record every outcome |
| `observation` | `compare` | Compare actual branch/state/return behavior with the formal prediction and identify the challenged assumption |
| `acceptance` | `publish_index` | Publish bounded sanitized formal/reproduction rows; keep corpus, logs, maps, and harness protected |
| `acceptance` | `publish_handoff` | Publish immutable lab result and coverage/gap accounting |

The runner exposes a closed operation enum such as `compile`, `calibrate`, `fuzz`, `minimize`, and `replay`.
There is no `argv`, `command`, `shell`, `working_directory`, `mount`, or destination-network field
in a model-produced request.

### 4.5 `job_formal_refinement` step/task contract

| Step | Stable task | Behavior |
| --- | --- | --- |
| `load` | `verify_lineage` | Verify original attempt, lab observation, obligation, source/build, and admission lineage |
| `compare` | `classify` | Classify corroboration, scope/build mismatch, model discrepancy, invalid harness/oracle, instability or infrastructure failure; challenge apparently contradicted source certificates and suspend dependent reuse |
| `refine` | `update_model` | Expand only the dependency or assumption challenged by the observation; preserve unchanged identities |
| `proof` | `recheck` | Generate and independently accept a new Lean attempt with full assurance/correspondence checks; append challenge resolution/revocation without deleting prior evidence |
| `acceptance` | `publish_index` | Publish `formal-refinement-*` shards and relations to the prior attempt/observation |
| `acceptance` | `publish_handoff` | Publish a new immutable accepted handoff |

## 5. Artifact and file flow

### 5.1 Accepted input flow

| Input record | Origin | Consumer | Validation before use |
| --- | --- | --- | --- |
| Accepted SAST observation and SARIF path | Scanner/CodeQL shards in the accepted retrieval manifest | Formal verifier | Run, target, producer, rule, source range, shard hash, coverage, and lead identity |
| Code graph facts | `job_code_graph_index` accepted `graph` shards | Slice builder | Exact subject identities, scope ID, producer coverage, bounds/truncation, and shard digest |
| Source file and compilation unit | Target catalog, language build, C++ compiled analysis | Slice/frontend/harness | Target snapshot, file hash, compile command identity, ABI/toolchain, path custody |
| Alias/symbol/layout facts | SVF, clangd, LLVM/CFG producers | Slice/frontend | Producer identity, applicable build unit, supported kind, and missing-coverage state |
| Sanitized build output | `job_sanitizer_build` accepted handoff | Fuzz planner/lab | Output hash, instrumentation evidence, link/runtime compatibility, exact accepted build ancestry |
| Formal attempt | `job_formal_verification` handoff and `formal` shard | Planner/refinement/review | Schema, attempt hash, obligation identity, source correspondence, proof audit, and gaps |
| Lab admission | Operator CLI under `data/authorizations/formal-fuzz/` | Fuzz lab only | Canonical bytes, scope hash, creator/authentication context, expiry, image, operations, and budget |
| Fuzz observation | `job_formal_fuzz_lab` handoff and formal shard | Refinement/review | Admission, testcase, target, harness, oracle, campaign, and replay identities |

Use a discriminated request contract: `producer_lead` binds exact accepted upstream scanner/build/
graph manifests and forbids package/claim IDs; `review_claim` binds an already accepted package and
claim and runs standalone. Record the producer manifest separately from subsequent index/package
manifests. Planning emits an experiment request digest without an admission reference; the later
admission binds that digest and execution receipts bind both, avoiding circular identities.

No consumer accepts an arbitrary source path, SARIF file, `.lean` file, harness, corpus directory,
container tag, or command line as a privileged input.

### 5.2 Run-owned directory layout

The framework continues to own `claim.json` (including its pinned dataset contract), task
status/result receipts, `outcomes.json`, `result.json`, `handoff.json`, rejected diagnostics, and
`latest.json`. Job code adds only the files shown below. `<attempt>` is the framework attempt ID; `<formal-id>`,
`<obligation-id>`, and `<experiment-id>` are content-derived logical IDs.

```text
runs/<run-id>/
  data/
    authorizations/
      formal-fuzz/
        <admission-sha256>.json
        events/<admission-sha256>/<event-id>.json  # quota, lease, cancellation, revocation
    jobs/
      job_formal_verification/
        latest.json
        attempts/<attempt>/
          claim.json
          steps/
            scope/tasks/resolve_inputs/accepted-inputs.json
            candidates/tasks/select/candidates.json
            candidates/tasks/select/workbench/<session-id>/
              work-item.json
              capability-receipt.json
              events/*.json
              property-proposals/*.json
            slicing/tasks/build/formal/<formal-id>/slice.json
            obligations/tasks/instantiate/formal/<formal-id>/
              request.json
              obligation-<obligation-id>.json
              assumption-ledger.json
              non-vacuity-witness.json
            translation/tasks/lower/formal/<formal-id>/
              ir.json
              traceability.json
              generated-manifest.json
              generated/Model.lean
              generated/Obligations.lean
              generated/Proof.lean
            correspondence/tasks/check/formal/<formal-id>/
              correspondence.json
              derivation.json
              validation-receipt.json
            proof/tasks/check/formal/<formal-id>/
              proof.json
              axiom-audit.json
              witness.json                 # only when produced
              checker-receipt.json
              trusted-challenge-manifest.json
              independent-replay-receipt.json
              candidates/<candidate-id>/
                proof-body.lean
                check-receipt.json
              stdout.ref.json              # protected shared-object reference
              stderr.ref.json              # protected shared-object reference
            contracts/tasks/publish/contracts/*.json
            acceptance/tasks/publish_index/formal-summary.json
            acceptance/tasks/publish_handoff/formal-handoff.json
          outcomes.json
          result.json
          handoff.json
      job_formal_fuzz_planning/
        latest.json
        attempts/<attempt>/steps/
          load/tasks/verify_inputs/accepted-inputs.json
          triage/tasks/select_obligations/experiment-requests.json
          harness/tasks/generate/experiments/<experiment-id>/
            experiment-request.json
            harness-spec.json
            harness.cc
            input-encoding.json
            workbench/<session-id>/
              work-item.json
              capability-receipt.json
              events/*.json
              harness-proposals/*.json
          oracle/tasks/bind/experiments/<experiment-id>/
            oracle.json
            seeds.json
            negative-control.json
          validate/tasks/policy/experiments/<experiment-id>/policy-receipt.json
          validate/tasks/compile_check/experiments/<experiment-id>/compile-receipt.json
          acceptance/tasks/publish_handoff/formal-fuzz-planning-handoff.json
      job_formal_fuzz_lab/
        latest.json
        attempts/<attempt>/steps/
          admission/tasks/verify/admission-receipt.json
          workspace/tasks/materialize/workspace-manifest.json
          build/tasks/compile_harness/experiments/<experiment-id>/build-receipt.json
          calibration/tasks/check_oracle/experiments/<experiment-id>/
            calibration-receipt.json
            instrumentation-receipt.json
          campaign/tasks/fuzz/experiments/<experiment-id>/
            campaign-receipt.json
            corpus-manifest.json
            coverage-summary.json
            logs/*.ref.json
          minimize/tasks/same_fault/experiments/<experiment-id>/minimization-receipt.json
          replay/tasks/clean_process/experiments/<experiment-id>/replay-receipt.json
          observation/tasks/compare/experiments/<experiment-id>/observation.json
          acceptance/tasks/publish_index/formal-fuzz-summary.json
          acceptance/tasks/publish_handoff/formal-fuzz-handoff.json
      job_formal_refinement/
        latest.json
        attempts/<attempt>/steps/
          load/tasks/verify_lineage/accepted-inputs.json
          compare/tasks/classify/comparison.json
          refine/tasks/update_model/formal/<formal-id>/
            refinement.json
            slice.json
            ir.json
            traceability.json
            generated/*.lean
          proof/tasks/recheck/formal/<formal-id>/
            proof.json
            axiom-audit.json
            checker-receipt.json
          acceptance/tasks/publish_index/formal-refinement-summary.json
          acceptance/tasks/publish_handoff/formal-refinement-handoff.json
    formal-validity/
      events/<event-id>.json              # immutable challenge/resolution/invalidation
      affected-publications/<event-id>.json
    indices/
      formal/
        formal-verification-<scope-id>/<fingerprint>.sqlite
        formal-fuzz-<scope-id>/<fingerprint>.sqlite
        formal-refinement-<scope-id>/<fingerprint>.sqlite
    shared/
      objects/<sha256>                    # raw Lean, harness, corpus, logs, maps
```

Files shown under task directories are immutable attempt artifacts. Large or duplicate bytes are
published through `data/shared/objects/<sha256>` and represented in task records by the standard
`{path, sha256, size_bytes}` reference. The plan does not add mutable global proof or corpus
caches. Authorization events are written only by the trusted supervisor, and validity events only
by deterministic validators. Their current views are derived atomically from append-only events;
sequence/ownership and crash recovery must be registered with the existing run-custody machinery,
not implemented as worker-writable ad hoc files.

### 5.3 Generated-record schemas

Add closed schemas under `docs/schemas/formal-verification/`:

| Schema | Producer | Indexed? | Main consumers |
| --- | --- | --- | --- |
| `formal-candidate.schema.json` | Formal candidate selection | Yes, sanitized | Operator query, package assembly |
| `formal-request.schema.json` | Formal verifier | Yes, sanitized | Slice/obligation stages |
| `formal-work-item.schema.json` | Formal verifier workbench | No; attempt-local context | Formal property/proof worker only |
| `formal-property-proposal.schema.json` | Formal property analyst | No; untrusted proposal | Deterministic property validator |
| `formal-proof-candidate.schema.json` | Formal property analyst | No; untrusted proposal | Pinned Lean checker |
| `formal-workbench-event.schema.json` | Workbench adapter | No; protected diagnostic | Attempt audit and budget accounting |
| `formal-slice.schema.json` | Slice builder | Summary only | Translator, operator query |
| `formal-ir.schema.json` | Frontend | No; protected artifact | Lean generator/checker |
| `formal-obligation.schema.json` | Property compiler | Yes, normalized statement and scope only | Proof, planning, package assembly |
| `formal-translation.schema.json` | Translator | Summary only | Proof acceptance, review |
| `formal-proof.schema.json` | Independent Lean acceptance checker | Yes, sanitized | Review, contracts, MCP |
| `formal-correspondence.schema.json` | Independent correspondence validator | Summary only | Source verdict acceptance, contracts, review |
| `formal-assumption-ledger.schema.json` | Property/premise validator | Summary only | Non-vacuity, correspondence, review |
| `formal-invalidation.schema.json` | Validity validator | Yes, sanitized | Contract reuse, affected-publication queue, review |
| `formal-quota-event.schema.json` | Trusted supervisor | No; protected authorization | Admission/recovery/cancellation accounting |
| `formal-witness.schema.json` | Lean/solver integration | Summary only | Fuzz planner, review |
| `formal-contract.schema.json` | Contract publisher | Yes | Contract lookup and caller obligations |
| `formal-attempt.schema.json` | Formal verifier/refinement | Yes | All downstream consumers |
| `formal-experiment-request.schema.json` | Fuzz planner | Summary only | Admission CLI/lab |
| `formal-harness.schema.json` | Fuzz planner | No; protected artifact | Policy, compile check, lab |
| `formal-harness-proposal.schema.json` | Formal harness designer | No; untrusted proposal | Deterministic harness renderer/policy |
| `formal-lab-admission.schema.json` | Operator CLI | No; protected authorization | Lab admission validator |
| `formal-fuzz-plan.schema.json` | Fuzz planner | Summary only | Lab |
| `formal-fuzz-result.schema.json` | Lab | Yes, sanitized | Review/refinement/MCP |
| `formal-observation.schema.json` | Lab | Yes, sanitized | Refinement/review |
| `formal-refinement.schema.json` | Refinement | Yes | Review and audit |
| `formal-fp-case.schema.json` | Evaluator-only benchmark | Never visible to workers | Offline evaluator only |

Each schema rejects unknown keys, bounds arrays/strings/bytes, uses run-relative canonical refs,
and separates logical result, source correspondence, and reproduction status. A record cannot
encode `SOURCE_PROPERTY_PROVEN` unless the translation/coverage predicates required by the design
are satisfied by deterministic validation of resolving certificates, not asserted booleans. Add
`proof_assurance`, `correctness_scope`, bounds, premise states and current validity separately from
logical/correspondence/reproduction fields. `approved_native` is not eligible for initial source
certification. Reject a contradictory entry domain or unmatched property/predicate mapping.

### 5.4 Dataset declarations

Add `formal` to `src/appsec_review/runtime/datasets.py:FAMILIES`. Each job receives a local
`datasets.py` with non-overlapping shard prefixes and protected artifact patterns.

| Job/output kind | Disposition | Schema/family | Claimed paths or shards |
| --- | --- | --- | --- |
| `formal_results` | `indexed` | `formal-attempt/1`, family `formal` | Index `formal`, prefix `formal-verification-` |
| `formal_models` | `protected` | Lean/IR/traceability artifacts | Verification attempt `translation/**` and `proof/**` raw files |
| `formal_contracts` | `indexed` | `formal-contract/1`, family `formal` | Index `formal`, prefix `formal-contract-` |
| `formal_plans` | `artifact_only` | `formal-experiment-request/1` | Planning summaries and policy/compile receipts |
| `formal_harnesses` | `protected` | `formal-harness/1` | Harness source, exact input encodings, raw seed bytes |
| `formal_fuzz_results` | `indexed` | `formal-fuzz-result/1`, family `formal` | Index `formal`, prefix `formal-fuzz-` |
| `formal_fuzz_evidence` | `protected` | Corpus/log/map/reproducer bytes | Lab campaign/minimize/replay trees and shared objects |
| `formal_refinements` | `indexed` | `formal-refinement/1`, family `formal` | Index `formal`, prefix `formal-refinement-` |
| `formal_validity` | `indexed` | `formal-invalidation/1`, family `formal` | Index `formal`, prefix `formal-validity-`; immutable event/affected-publication projections |
| `formal_certificates` | `protected` | Correspondence derivations, challenge and replay artifacts | Verification correspondence/proof trees; sanitized summaries in formal attempt shards |
| `formal_authorization_events` | `protected` | `formal-quota-event/1` | Admission events; never model-owned |

The dataset inventory must report missing or partial formal outputs as unavailable/partial with a
reason. A protected dataset exposes only sanitized identity, hash, status, and coverage through
`query_dataset_inventory`.

### 5.5 End-to-end artifact transformations

| Stage | Reads | Generates | Next consumer |
| --- | --- | --- | --- |
| Candidate qualification | Accepted observation, build, graph coverage | Candidate/status record | Slice builder |
| Semantic slicing | Candidate plus graph/IR/alias facts | Verification slice and closure gaps | Property compiler/frontend |
| Property compilation | Registered template plus slice | Obligation and violation dual | Lean generator/planner |
| Translation | Complete supported AST plus accepted source/build facts | IR, traceability, generated definitions and correspondence derivation | Independent correspondence validator |
| Correspondence validation | AST/IR derivation, generic semantic theorem, premise ledger | Validated source-binding, simulation, bad-event and closure receipts | Final verdict acceptance |
| Lean checking | Trusted challenge and definitions plus isolated candidate | Independent replay/comparison, axiom and assurance receipts | Final verdict acceptance |
| Verdict acceptance | Checked proof, correspondence/premise receipts, validity checkpoint | Derived model-only/conditional/source-certified result | Planner, review and later contract publisher |
| Fuzz planning | Eligible obligation/witness plus source/build custody | Experiment request, harness, oracle, seeds | Operator admission and lab |
| Lab execution | Admitted plan, atomic quota reservation, exact target/build/image | Calibration/instrumentation, campaign, testcase, coverage, sanitizer, minimize and replay receipts | Validity validator, refinement and review |
| Refinement | Formal prediction plus observation | New model/proof attempt and relationship | Index/package/review |
| Review projection | Accepted formal index rows | Package-scoped formal identities | Existing review roles and final evidence rules |

## 6. New tooling and containers

### 6.1 Tooling selection

| Capability | Tooling | Decision |
| --- | --- | --- |
| C/C++ compilation facts | Existing pinned Clang/LLVM in `tool-native-cpp` | Reuse compiler; add the restricted AST/source-binding producer contract if accepted artifacts lack the required facts; no heuristic fallback |
| Graph/path facts | Existing CodeQL, Clang CFG/IR, SVF, clangd producers | Reuse accepted outputs only |
| Formal semantics and proof | Lean 4, minimal pinned library closure, `AppSecVerify`, independent checker | New required image; separate kernel-only from approved-native paths such as `bv_decide` |
| Bounded witness exploration | Lean evaluation first; optional CBMC in a later separate image | Candidate evidence only; never proof authority without a checked certificate path |
| Function fuzzing | Clang, libFuzzer, SanitizerCoverage, ASan, UBSan | New required tool image |
| Coverage processing | `llvm-profdata`, `llvm-cov`, `llvm-symbolizer` | Included in the fuzz image; only bounded summaries indexed |
| Crash minimization | libFuzzer minimization plus property-oracle-aware reducer | Same-fault predicate required |
| Protocol sessions | Later Python driver using exact structured codecs; evaluate boofuzz/Scapy only for the internal profile | Deferred; no raw-packet requirement in M2 |

### 6.2 `tool-lean-verifier`

Add:

```text
containers/tools/lean-verifier/
  Dockerfile
  README.md
  tool.toml
  assets.lock.json
  lean-toolchain
  lake-manifest.json
  lakefile.toml
  lean_runner.py
  AppSecVerify/
    Semantics/Values.lean
    Semantics/Memory.lean
    Semantics/ControlFlow.lean
    Semantics/Transitions.lean
    Security/Predicates.lean
    Security/Reachability.lean
    Abstraction/Soundness.lean
    Correspondence/LocalCopyBounds.lean
    Correspondence/Certificate.lean
    Contracts/Hoare.lean
    Contracts/Composition.lean
```

The image must:

- pin the base digest, Lean toolchain, mathlib commit/packages, and every downloaded asset;
- build completely offline after the locked acquisition stage;
- run as `10001:10001`, network `none`, dropped capabilities, no-new-privileges, read-only root,
  read-only input mount, and bounded writable scratch;
- expose only `/opt/appsec/lean_runner.py` with closed `version`, `check`, and `audit` modes;
- reject arbitrary imports, `unsafe`, executable IO, unregistered macros/extensions, `sorryAx`,
  unapproved axioms, theorem self-assumption, and output paths outside scratch;
- emit canonical JSON containing tool/library identities, module digests, theorem name/statement,
  axiom dependencies, status, elapsed/resource use, and protected stdout/stderr refs;
- produce the trusted challenge outside the candidate process, then validate/replay exported proof
  artifacts in a fresh independent acceptance stage and compare elaborated theorem/definition
  identities; candidate stdout or a candidate-created receipt cannot declare acceptance;
- enforce the design's `kernel_only` logical-axiom allowlist and separate `approved_native` policy,
  including exact native axiom statements and origins for the pinned release; reject kernel-check
  disabling options, arbitrary elaborator hooks, forged receipts and changed definitions;
- never read a target checkout directly; it receives only validated generated modules and a
  manifest from the job workspace.

Add a catalog entry `tool-lean-verifier` and an application image setting pinned by image ID/digest.
Pin a compatible independent checker (`lean4checker`/`comparator` or an equivalent documented
path), including its limits. Kernel-only acceptance cannot rely on native-computation axioms merely
because a SAT certificate was checked or cached. Verify the chosen release's actual dependency
closure in manual tool acceptance. The first implementation must not invent a host-specific `image_id`; the review-host image builder
owns that value after build/smoke evidence exists.

### 6.3 `tool-formal-fuzz`

Add:

```text
containers/tools/formal-fuzz/
  Dockerfile
  README.md
  tool.toml
  assets.lock.json
  formal_fuzz_runner.py
  policy/
    allowed-compiler-flags.json
    allowed-sanitizers.json
    seccomp-profile.json
  templates/
    function_harness.cc.j2
    property_oracle.h
```

The image should derive from or share the exact pinned LLVM closure used by `tool-native-cpp`, not
silently install a different compiler. It contains Clang/Clang++, libFuzzer, ASan/UBSan runtimes,
SanitizerCoverage, llvm-cov/profdata/symbolizer, and the fixed runner.

Runtime contract:

| Control | Required behavior |
| --- | --- |
| User/root | Non-root `10001:10001`; read-only root; no-new-privileges; all capabilities dropped |
| Network | `none` for `function_sanitized`; runner refuses network configuration |
| Mounts | Accepted source/build inputs read-only; bounded executable scratch read-write; no Docker socket, host root, credentials, or arbitrary mounts |
| Process | Fixed runner starts the compiler/fuzzer directly, creates a process group, kills the complete tree on timeout, and records exit/signal |
| Resources | Admission-bound limits with atomic reservations, idempotent operations, leases, crash reconciliation and verified termination before releasing quota |
| Commands | Closed runner modes and validated structured fields; no shell and no model-supplied executable path |
| Outputs | Canonical receipts plus protected raw logs/corpus/maps; unknown files cause publication failure |
| Reproducibility | Exact analyzed and instrumented build identities/delta, image, compiler, flags, source, harness, corpus, seed, oracle and reset recorded |
| Calibration/coverage | Separate known-failing tool-health fixture and negative control; prove relevant target instrumentation and distinguish unreachable sink, missing oracle, instrumentation gap and no observed violation |

The global offline runtime policy must not be weakened. Add a separate typed
`formal_fuzz_function_sanitized` execution profile whose only material difference is permission to
execute the validated binary from bounded scratch. The profile still has no network and never
permits a generic command.

### 6.4 Optional `tool-formal-protocol-driver`

The later protocol profile adds a dedicated driver image, not protocol packages to the function
fuzzer. It accepts a validated logical message grammar and fixed destination service alias on a
lab-internal network. Raw sockets, `NET_RAW`, host networking, arbitrary IP/host/port fields,
external DNS, and Internet egress remain denied. Captures and logical transcripts are protected;
the indexed result includes only protocol-state outcomes, replay status, and evidence refs.

## 7. Proposed repository source tree

```text
src/appsec_review/
  formal_verification/
    __init__.py
    contracts.py
    correspondence.py
    assumptions.py
    validity.py
    evidence_admission.py
    custody.py
    frontend.py
    intake.py
    lean_check.py
    lean_generate.py
    model.py
    property_registry.py
    schemas.py
    semantics_ir.py
    slice.py
    witness.py
  fuzz_lab/
    __init__.py
    admission.py
    quota.py
    calibration.py
    build.py
    coverage.py
    custody.py
    execution.py
    feedback.py
    harness.py
    minimize.py
    obligations.py
    oracle.py
    planning.py
    protocol.py                 # deferred profile only
    replay.py
  jobs/
    job_formal_verification/
      __init__.py
      datasets.py
      job.py
      settings.py
    job_formal_fuzz_planning/
      __init__.py
      datasets.py
      job.py
      settings.py
    job_formal_fuzz_lab/
      __init__.py
      datasets.py
      job.py
      settings.py
    job_formal_refinement/
      __init__.py
      datasets.py
      job.py
      settings.py
  retrieval/
    formal.py
  mcp/
    formal.py
    formal_workbench.py

docs/
  architecture/formal-verification.md
  operations/formal-verification.md
  operations/formal-fuzz-lab.md
  schemas/formal-verification/*.schema.json

pipeline/
  guidance/tasks/formal-verification/*.md
  prompt-fragments/roles/formal_property_analyst.md
  prompt-fragments/roles/formal_harness_designer.md
  skills/formal-obligation-analysis/SKILL.md
  skills/lean-proof-development/SKILL.md
  skills/proof-directed-harness-design/SKILL.md
  skills/formal-evidence-interpretation/SKILL.md

tests/
  formal_verification/
  fuzz_lab/
  fixtures/formal_verification/
```

Also modify the existing central integration files: `appsec-review.toml`, typed config loaders,
`containers/catalog.toml`, the container runtime profile parser, runtime registry/topology/dataset
families, input-source matrix, review-data indexing, review-package schemas/assembly, retrieval
manifest/core, MCP tool schema/adapters/capabilities, guidance registry/composition tests, and
directly affected architecture/operations documentation.

## 8. Typed configuration

Add central job blocks with `settings.enabled = false` initially. Suggested names and bounds are
part of the config contract, not prompt text:

```toml
[jobs.job_formal_verification]
enabled = false

[jobs.job_formal_verification.settings]
property_registry_version = "1"
max_candidates = 10
max_slice_nodes = 2000
max_slice_edges = 8000
max_functions = 64
max_expansion_rounds = 4
max_generated_bytes = 1048576
max_obligations_per_candidate = 8
max_workbench_calls_per_obligation = 32
max_proof_checks_per_obligation = 8
max_total_proof_checks = 32
max_total_checker_seconds = 1800
max_total_checker_cpu_seconds = 3600
max_total_job_seconds = 3600
proof_assurance = "kernel_only"
max_proof_candidate_bytes = 131072
max_slice_refinement_requests = 4
lean_image_id = "<review-host-owned-pin>"
lean_timeout_seconds = 120
lean_memory_bytes = 4294967296
lean_cpus = 2

[jobs.job_formal_fuzz_planning]
enabled = false

[jobs.job_formal_fuzz_planning.settings]
max_experiments = 4
max_harness_bytes = 262144
max_seed_count = 64
max_seed_bytes = 65536
compile_check_timeout_seconds = 120

[jobs.job_formal_fuzz_lab]
enabled = false

[jobs.job_formal_fuzz_lab.settings]
profile = "function_sanitized"
fuzz_image_id = "<review-host-owned-pin>"
max_campaigns = 4
max_campaign_seconds = 60
max_total_seconds = 600
max_input_bytes = 65536
max_corpus_bytes = 67108864
max_output_bytes = 16777216
replay_attempts = 3
memory_bytes = 4294967296
cpus = 2
pids_limit = 256
network = "none"

[jobs.job_formal_refinement]
enabled = false

[jobs.job_formal_refinement.settings]
max_refinement_rounds = 2
max_observations = 32
```

The final syntax must follow the existing config model and per-step/task worker declarations.
Bind an aggregate model-token/cost limit through existing typed model-budget configuration as well.
Per-candidate/obligation caps do not grant additional aggregate quota. Reserve checker/time/model
budget atomically across workers, retries and refinement, count failures, and report every deferred
obligation with the exhausted dimension. The old per-obligation limits alone could permit 640
checks (76,800 checker wall-seconds); the aggregate ceilings bound that exposure. Values are
prototype limits to measure at G1, not acceptance targets to enlarge silently.
Unknown settings, invalid combinations, placeholder image IDs in executable profiles, excessive
job values, a lab enabled in ordinary topology, and a non-`none` function-fuzz network must fail
configuration validation. Frozen runs retain their resolved configuration under
`data/configuration/` and are not rewritten when the feature is added.

## 9. MCP and retrieval design

### 9.1 Boundary decision

Use three separate capability planes rather than making one MCP catalog serve incompatible trust
levels:

1. The external/operator MCP and ordinary review-package retrieval are read-only. They inspect
   already accepted formal records and cannot plan a new attempt, invoke Lean, generate a harness,
   create an admission, build a target, fuzz, replay, rerun a job, or update a finding.
2. Formal-analysis jobs receive a separate job-scoped workbench bound to one candidate or
   obligation. It supports bounded property, slice, proof and harness proposals plus pinned Lean
   checks, but cannot execute target code, widen scope, create admission or publish directly.
3. Mutation of accepted run state and target execution use authenticated operator/job-launch
   surfaces outside both model capability planes.

The workbench may use MCP framing internally, but it is not added to the external
`appsec-review-mcp` catalog or to inference review-cell transports. Its writes are immutable
untrusted proposals and diagnostics inside the active attempt, never accepted evidence. The local
admission CLI writes one immutable authorization record and logs the decision; the job launcher
accepts its logical ID. A future remote control service needs separate authenticated API and
threat-model work and must not be smuggled into either model-facing surface.

### 9.2 New read-only tools

Add definitions to `docs/schemas/retrieval-mcp-tools.json`, dispatch in
`src/appsec_review/mcp/adapter.py`, query logic in `src/appsec_review/retrieval/formal.py`, and
formal-specific serialization helpers in `src/appsec_review/mcp/formal.py`.

| Tool | Exact accepted inputs | Bounded output | Explicitly excluded |
| --- | --- | --- | --- |
| `query_formal_candidates` | Exact accepted run; optional exact observation, rule, family, status; limit/cursor | Candidate identities, qualification, source/build refs, coverage/gaps | Arbitrary paths, free-text search, new candidate generation |
| `query_formal_slice` | Exact formal attempt/slice ID; optional node/edge kind; limit/cursor | Logical nodes/edges, source refs, closure state, omitted dependencies | Source bytes, unrestricted graph traversal, on-demand analysis |
| `query_formal_proof` | Exact attempt/proof/obligation ID; limit/cursor | Normalized property, logical result, correspondence, theorem/axiom audit, proof digest, assurance, premise/correspondence receipts, current/historical validity, gaps | Raw Lean source/proof term, checker stdout/stderr, conclusion upgrading |
| `query_formal_contracts` | Exact symbol and build/source identity; optional property family; limit/cursor | Applicable contract refs, requires/ensures/modifies, proof/correspondence level, staleness | Name-only lookup, silent precondition satisfaction, global unversioned cache |
| `query_formal_reproduction` | Exact fuzz attempt/experiment/obligation ID; limit/cursor | Sanitized oracle/health, instrumentation and sink coverage, observed class, replay counts, build relationship, evidence refs | Testcase bytes, harness source, logs, commands, target execution |

All tools read the accepted `formal` SQLite shards from the session-pinned manifest. Responses
carry run ID, accepted manifest hash, shard ID/hash/fingerprint, producer attempt, coverage rows,
pagination, truncation, and gaps. Page sizes remain 1-100 and responses remain within the existing
MCP byte limit.

Current validity is a separately authenticated, immutable checkpoint over the append-only validity
events, with its own manifest/hash/as-of identity in the response alongside the proof's pinned
manifest. New acceptance/reuse pins and checks that checkpoint. A frozen session that cannot obtain
an up-to-date checkpoint may show a historical result but cannot claim current certification.
Do not silently repin the proof manifest, read unaccepted events as evidence, or expose an
unbounded invalidation scan through MCP.

### 9.3 Scoped worker capabilities

Extend review packages with:

```json
{
  "retrieval": {
    "indexes": ["formal"],
    "formal_attempt_ids": ["asr:formal_attempt:<sha256>"],
    "formal_obligation_ids": ["asr:formal_obligation:<sha256>"],
    "formal_contract_ids": ["asr:formal_contract:<sha256>"],
    "formal_experiment_ids": ["asr:formal_experiment:<sha256>"]
  }
}
```

The capability signature binds these exact arrays. Formal queries must reject cross-package IDs,
ungranted slices, contracts for a different source/build, and cursor reuse across a changed grant.
Suggested role grants:

| Role | Formal tools |
| --- | --- |
| `red_team_analyst` / `hypothesis_hunter` | `query_formal_proof`, `query_formal_reproduction` for package-granted IDs |
| `blue_team_refuter` / `independent_verifier` / `adjudication_judge` | `query_formal_proof`, `query_formal_contracts`, `query_formal_reproduction` for package-granted IDs |
| `completeness_reviewer` | Candidate/attempt coverage through package summaries and `query_dataset_inventory`; no raw slice |

No role gains an execution tool. A formal result is evidence to cite, not authority to set claim
state. The formal property and harness roles use the job-scoped workbench below, not a review
package capability.

### 9.4 Job-scoped formal workbench

Implement `src/appsec_review/mcp/formal_workbench.py` as an application-mediated adapter with a
separate catalog. An expiring capability binds `run_id`, accepted manifest, job/attempt,
candidate/obligation, source and build identities, exact operations, byte/page bounds, Lean-check
count, refinement count, model-call budget and expiry. The adapter reconstructs and checks this
binding on every call. It accepts no caller-supplied path, command, import, executable, mount,
container, network destination or theorem statement.

| Operation | Input | Result | Authority retained by the application |
| --- | --- | --- | --- |
| `get_formal_work_item` | Bound work-item ID | Allegation, applicable template IDs, evidence identities, current slice/model, open obligations, gaps and remaining budget | Selects and pins all identities; no broad search |
| `instantiate_formal_property` | Registered template ID plus typed parameters | Proposal receipt or exact mismatch diagnostics | Validates equivalence to the accepted SAST allegation and owns the final obligation |
| `request_slice_refinement` | One open dependency ID and registered refinement reason | New candidate slice view or named unavailable gap | Expands only accepted bounded facts; never launches an analyzer or scans the target during the call |
| `inspect_formal_model` | Bound obligation ID and bounded section selector | Normalized IR, generated definitions, fixed theorem, assumptions and correspondence obligations | Owns source selection, generation, imports and theorem statement |
| `check_proof_candidate` | Proof body/term for the fixed theorem | Structured elaboration/tactic diagnostics, resource status and axiom audit | Creates files, invokes pinned Lean, enforces limits and decides whether a checked result is admissible |
| `analyze_formal_witness` | Bound witness ID | Path constraints, source mapping, controllable/uncontrolled values and concretization status | Does not execute the target or invent caller-controlled inputs |
| `submit_harness_proposal` | Declarative adapter/caller/reset/oracle/seeds/negative control | Proposal receipt plus AST/ABI/symbol/policy/compile diagnostics when the job reaches those stages | Renders final source, selects fixed compiler mode and rejects commands/mounts/destinations |
| `submit_experiment_request` | Eligible obligation plus accepted harness proposal ID | Non-executable request receipt | Cannot create admission or start the lab |
| `inspect_experiment` | Bound experiment ID | Admission state and accepted sanitized result/replay summary | Does not expose raw harness, testcase, corpus, logs or mutable polling controls |

Grant operations by trusted role/task ID, not by target content:

| Workbench role/task | Operations |
| --- | --- |
| `formal_property_analyst` / property and invariant tasks | `get_formal_work_item`, `instantiate_formal_property`, `request_slice_refinement`, `inspect_formal_model`, `check_proof_candidate`, `analyze_formal_witness` |
| `formal_property_analyst` / observation-refinement task | `get_formal_work_item`, `request_slice_refinement`, `inspect_formal_model`, `check_proof_candidate`, `analyze_formal_witness`, `inspect_experiment` |
| `formal_harness_designer` / harness and oracle tasks | `get_formal_work_item`, `inspect_formal_model`, `analyze_formal_witness`, `submit_harness_proposal`, `submit_experiment_request` |

An operation absent from the task's signed capability is rejected even when another role in the
same job can use it. The capability is not inferred from prose or a requested tool name.

`check_proof_candidate` accepts only a bounded theorem body or proof term. The generated
definitions, imports, theorem name/type and project remain immutable. Reject unknown fields,
changed statements, arbitrary modules, IO, `unsafe`, unregistered macros/extensions, `sorryAx`,
unapproved axioms, oversized input and exhausted check budgets. Its stdout/stderr are protected;
the model receives only stable diagnostic codes, bounded source spans within the generated proof
body, messages scrubbed of host paths, resource accounting and the axiom audit.

`request_slice_refinement` is a model proposal to the formal job, not an on-demand retrieval
analyzer. If the requested fact is absent from accepted producers, the result is a gap or an
operator-visible prerequisite for a later ordinary job run. The workbench cannot use an arbitrary
call-depth increase as a soundness argument.

All workbench calls publish `formal-workbench-event/1` receipts beneath the attempt, including the
capability digest, operation, input/output digest, budget before/after, status and relevant artifact
refs. Only deterministic job validators with independent proof/correspondence receipts can promote a proposal to the formal attempt. Quota events use atomic reservation and idempotent dispatch, rather than trusting event counts supplied by the worker. Review
workers later see only accepted indexed projections through the read-only tools.

The intended worker loop is explicit:

```text
get work item
  -> instantiate registered property
  -> inspect/close semantic slice
  -> inspect fixed generated model and correspondence obligations
  -> submit bounded proof candidates and interpret checker diagnostics
  -> if proved, independently replay/compare the fixed theorem, then check every correspondence certificate obligation
  -> reject vacuous/undischarged premises and derive the eligible assurance-scoped verdict
  -> if a witness exists, analyze whether it maps to legitimate controllable input
  -> if and only if experimentally answerable, submit harness and experiment proposals
  -> after accepted observations, refine the challenged model assumption and check a new attempt
  -> otherwise finish conditional/inconclusive with named gaps
```

The workbench must always offer a terminal `conditional` or `inconclusive` route. It must never
force a proof, fabricate an experiment, or treat budget exhaustion as evidence for or against the
finding.

### 9.5 Operator CLI

Add narrowly scoped commands after their underlying job contracts exist:

```text
appsec-review formal list-candidates --run-id RUN [exact filters]
appsec-review formal inspect --run-id RUN --attempt-id ATTEMPT
appsec-review formal-fuzz admit --run-id RUN --experiment-id EXPERIMENT \
  --profile function_sanitized --max-campaigns N --max-seconds N --expires-at TIME
appsec-review formal-fuzz inspect-admission --run-id RUN --admission-id ADMISSION
```

`admit` resolves the accepted experiment and image before displaying/recording the exact envelope.
It accepts no arbitrary command, path, destination, or mount. Running a job remains an explicit
ordinary job launch with the admission ID in trusted job configuration/launch metadata. MCP never
calls these commands.

### 9.6 Evidence admission and validity projection

Implement `formal-evidence-admission/1` exactly as the companion design's section 5.6 table:
model-only outcomes are non-counting context; source-certified safety/path results contradict only
the matching scoped allegation/path; validated replay supports only observed predicates, with
separate attacker-control evidence. Map each supported property to exact existing predicate IDs
and relation polarity. Unmatched mappings fail closed. Preserve current R5/R6 thresholds and final
publication authority; this adapter is a separately versioned integration change, not an implicit
change caused by a new dataset family.

Retain `derived_from` identities through scanner, slice, premises, theorem, witness, harness and
replay. Do not count derived artifacts as independent confirmations merely because they have
different producer IDs. Validate shared dependencies and fresh independent review separately.
Current-validity projections reject challenged/revoked certificates and contracts and expose an
affected-publication queue; historical session-pinned manifests never silently change their old
proof bytes or present historical certification as a current result.

## 10. Roles, tasks, runtime skills, and personas

### 10.1 New roles

Add two model roles to `pipeline/guidance/registry.json` and matching role fragments:

| Role | Responsibility | Output | Prohibited actions |
| --- | --- | --- | --- |
| `formal_property_analyst` | Instantiate one registered property against one accepted bounded slice; propose invariants/summaries and iteratively develop a proof for the fixed generated theorem while naming unresolved semantics | `formal-property-proposal/1`, `formal-proof-candidate/1` | Change the template/theorem/imports, declare proof success without a checker receipt, invent source facts, execute code, request unlisted tools, widen scope, set claim state |
| `formal_harness_designer` | Propose one declarative adapter/oracle/seed plan for one experimentally answerable accepted obligation | `formal-harness-proposal/1` | Supply shell/commands/mounts/network destinations, replace the target function, fabricate caller state, execute, admit, widen scope, set claim state |

Deterministic validators select templates, generate final Lean definitions, render final harness
code, run tools, and determine acceptance. The roles never become proof or execution authorities.
Existing `independent_verifier` is reused for evidence review; a new proof-review persona/role is
not required for the first vertical slice.

### 10.2 Task prompts

Add `pipeline/guidance/tasks/formal-verification/`:

| Task file | Role | Bounded question |
| --- | --- | --- |
| `instantiate_property.md` | `formal_property_analyst` | Which registered property parameters and exact source facts apply to this obligation? |
| `propose_invariants.md` | `formal_property_analyst` | Which invariants/summaries may discharge the obligation, and which premises remain open? |
| `develop_proof.md` | `formal_property_analyst` | Which bounded proof body establishes the fixed generated theorem, and what does each checker diagnostic require without weakening the statement or trust base? |
| `classify_experiment.md` | `formal_property_analyst` | Is the unresolved obligation experimentally answerable under the closed eligibility enum? |
| `design_harness.md` | `formal_harness_designer` | How should validated input bytes establish legitimate state and call the exact function/caller? |
| `design_oracle.md` | `formal_harness_designer` | What exact observable predicate, negative control, and same-fault signature answer the obligation? |
| `interpret_observation.md` | `formal_property_analyst` | Which recorded model assumption is corroborated or challenged by this accepted observation? |

Tasks contain the question and output contract only. Budgets, models, reasoning, retries, timeouts,
worker pools, images, and tools remain in typed configuration and role capabilities.

### 10.3 Runtime skills

Four runtime skills are justified because they are reusable procedures across more than one task:

| Skill | Registered jobs | Procedure scope |
| --- | --- | --- |
| `formal-obligation-analysis` | `job_formal_verification`, `job_formal_refinement` | Distinguish model/source claims, use registered templates, preserve exact semantics, name gaps, and avoid proof-authority claims |
| `lean-proof-development` | `job_formal_verification`, `job_formal_refinement` | Inspect generated definitions, keep the theorem/imports fixed, use bounded trusted tactics and registered lemmas, interpret checker diagnostics, audit dependencies, and stop instead of weakening the property or adding trust assumptions |
| `proof-directed-harness-design` | `job_formal_fuzz_planning` | Map an eligible obligation to legitimate caller state, controllable inputs, oracle, seeds, and negative controls without executable authority |
| `formal-evidence-interpretation` | `job_inference_security_review` | Interpret logical result, correspondence, reproduction, and scope independently; cite exact records and never treat clean fuzzing as proof |

Each skill lives only under `pipeline/skills/<name>/SKILL.md`, has
`metadata.audience: runtime-worker`, is registered under `runtime_skills`, and is loaded only by
`load_runtime_skill`. None references `.claude/skills/`; development skills do not reference these
runtime files.

No new repository-development skill is needed for the first buildout. Implementers use the
existing `add-a-job-contract`, `add-runtime-guidance`, multi-session coordination, and docs-sync
procedures. A formal development skill should be considered only after a repeated implementation
procedure exists in code and tests.

### 10.4 Persona decision

Do **not** add a `formal_methods`, `lean_expert`, or `fuzzer` persona. Those labels describe a role
or technique, not a security viewpoint. Reuse the lead's existing domain persona:

- `memory_safety_native` for bounds, arithmetic, lifetime, and native memory properties;
- `parsing_deserialization` for parser/decoder invariants;
- `authorization_access_control` and `authentication_session` for principal/state properties;
- `network_api_surface` only for the later protocol profile;
- `generalist` when no narrower supported domain applies.

If evaluation reveals a security viewpoint not represented by those personas, add it based on the
missing domain lens, not because Lean or fuzzing is used.

## 11. Security and trust boundaries

| Boundary | Enforcement |
| --- | --- |
| Target text/model output is untrusted | Parsed only as data; no instructions, command interpolation, import selection, or path authority |
| Proof authority | Pinned Lean kernel and audited dependencies; `sorryAx`/unapproved axiom/unsafe escape fails acceptance |
| Source correspondence | Separate typed field and predicates; missing alias/caller/ABI/semantics prevents unconditional source claim |
| Build custody | Exact accepted source/build/image/flags hashes; changed identity creates a new attempt |
| Execution authority | Immutable operator admission plus deterministic validator and per-operation quota checks |
| Container isolation | Non-root, no socket/credentials, read-only inputs/root, bounded scratch/resources, no network for function fuzzing |
| Model/tool separation | Model emits schema-bound proposals; deterministic application generates files and invokes fixed tool modes |
| Evidence privacy | Raw models/harnesses/corpora/logs protected; MCP and reports expose sanitized summaries only |
| Review authority | Formal jobs publish evidence relations; existing adjudication and final gate remain authoritative |
| Evaluation blinding | Answer keys and pair labels remain outside worker, target, retrieval, seed, and container mounts |

## 12. Implementation sequence

Each slice is independently reviewable and keeps target execution disabled until the lab slice.

The dependency order is B0-B3 for the detached proof path; G2 then permits B4/B5.
B6-B8 may branch after G1 for explicitly admitted conditional-witness experiments, but their review
projection/contract reuse requires G2. B9 consumes the relevant completed gates. A slice number
alone does not authorize execution or override these dependencies.

### B0 — Contract and fixture baseline

- Freeze `local_copy_bounds/1`, its recognized AST grammar/ABI and measured real same-rule fixture pair.
- Freeze the correspondence certificate rows, generic soundness theorem contract, assumption/
  non-vacuity rules and proof-assurance/independent-checking policy before verdict implementation.
- Add the architecture/operations documents and closed schema skeletons.
- Record accepted scanner/build/graph prerequisites and unsupported semantics.
- No new job, image, model call, or execution.

Completion evidence: schema validation units and an independently verified real scanner alert on
both paired fixtures, or an honest decision to select a different existing rule.

### B1 — Formal domain model and intake

- Implement accepted observation/build/graph binding, property registry, IDs, schemas, and gap
  enums under `formal_verification/`.
- Add fast units for stale/cross-run/cross-target/tampered inputs and unsupported cases.
- Do not register a job until its handler can produce a complete typed attempt.

### B2 — Slice, IR, and traceability

- Implement complete supported-function AST coverage with accepted source/preprocessor/build custody;
  graph slices are navigation hints, not closure certificates.
- Implement the restricted IR and error-event semantics; never assume away UB at the copy operation.
- Add independent structural derivation checking, assumption ledger/non-vacuity and property-dual checks.
- Prove generic initial-state, transition and bad-event preservation lemmas for the supported grammar;
  instantiate them with per-function derivations. Missing obligations leave G2 unmet.
- Reject loops/recursion initially; later extensions require invariant/termination/correctness rules.
- Fail closed on truncation/open dependencies, mismatched widths/ABI and omitted branches.

### B3 — Lean checker and detached G0/G1/G2 experiment

- Build `tool-lean-verifier`, `AppSecVerify`, generator, independent replay/challenge comparator,
  certificate checker and explicit assurance policy.
- Provide the detached operator path with minimal standalone handler/dataset/custody support needed
  for accepted attempts; no ordinary graph vertex, broad retrieval rollout or reusable contract service.
- Demonstrate one genuine alerted pair end to end for G0, then two supported positives/controls for
  G1. These may remain model-only/conditional.
- Reach G2 only with the implemented companion design section 4.5.2 certificates, two safe-and-flagged source proofs
  and two vulnerable-and-flagged twins. If that fails, stop graph/semantic expansion and report G2
  unmet; separately admitted conditional-witness lab development may still follow G1.
- Reject vacuous premises, assumed-away UB, omitted branches, native trust labeled kernel-only,
  kernel-check bypass, forged receipt, wrong-width, `sorry`, unapproved axiom/import, timeout and
  tampered module/definition cases. Record authorized tool/experiment checks separately from units.

This slice changes a container image and therefore requires the repository's image build/smoke
process, but it does not authorize a live review.

### B4 — Optional ordinary graph integration (requires G2)

- Extend the detached handler with typed config, complete datasets, optional topology, index shards,
  inventory and operations docs only after G2; producer-stage requests cannot require packages.
- Keep the ordinary job disabled until G4; post-review requests remain standalone.
- Run focused offline units only unless the user separately authorizes a review/acceptance run.

### B5 — Review integration and contract reuse (requires G2)

- Add `formal` retrieval, read-only MCP tools, package capability binding, predicate-admission and
  dependency-lineage adapters, validity/invalidation projection and generated-prompt tests.
- Extend the minimal workbench and pinned guidance already needed by B3; do not defer fixed-theorem
  proof iteration until this integration milestone.
- Enable contract reuse only after premise/frame and transitive challenge/revocation checks pass;
  the current-validity view and affected-publication queue are prerequisites.
- Add bounded proof-candidate checks and proposal receipts, but no shell, arbitrary filesystem,
  admission, target-execution or network capability.
- Prove cross-package/cross-run/raw-artifact requests, changed theorem/imports, exhausted workbench
  budgets and work-item scope escalation are denied.

### B6 — Fuzz planning without execution (can follow G1 independently)

- Implement obligation eligibility, harness/oracle/seed schemas, deterministic template rendering,
  AST/symbol policy, compile-check, and `job_formal_fuzz_planning`.
- Add `tool-formal-fuzz` build contents, positive/negative calibration, operation instrumentation and
  analyzed/reproduction build delta contracts; keep the execution job absent or disabled.
- Show that a missing lemma, unsupported translation, or unconcretizable witness produces a no-run
  result.

### B7 — Admission and standalone fuzz lab (G3, after B6)

- Implement immutable admissions plus atomic reservation/idempotency/lease events, crash reconciliation,
  cancellation/revocation and process-tree accounting before enabling any lab operation.
- Implement closed runner modes, workspace custody, calibration/instrumentation validation,
  campaign/minimization/replay receipts and `job_formal_fuzz_lab`.
- Manually demonstrate G3 only under explicit authorization; failed calibration or uncovered target
  operations remain gaps, and replay does not establish binary equivalence.
- Keep the job out of ordinary topology and disabled until an explicit launch.
- Add denied-execution units before any manual container acceptance.

### B8 — Refinement, invalidation and review return path (requires B7; review projection requires G2)

- Implement observation comparison, bounded model refinement, new Lean attempt checking,
  `job_formal_refinement`, new index acceptance, and downstream package projection.
- Implement challenge/resolution/revocation events and reverse-dependency invalidation, with explicit
  historical/current publication views. Confirm old attempts remain immutable, supersession cannot
  erase contradictions, and clean campaigns never produce source-safe status.

### B9 — Held-out comparison and G4 rollout decision

- Run only under explicit user authorization against pinned known-vulnerable and safe-but-flagged
  targets.
- Freeze results before joining evaluator-only truth.
- Freeze grouped development/held-out splits that keep related twins, source ancestry and near-duplicate
  templates together. Run the G0-G3 experiments at their earlier slices, not only at B9.
- Compare against existing review and ordinary fuzzing with matched scope, harness/oracle access,
  compute and time; include preparation/proof cost and attribute gains to their actual source.
- Report eligibility/total-alert denominators, abstention, assurance/correspondence, false-safe rate,
  reproduction, time to evidence, confidence intervals and resource use by class.
- Require G2 and an explicit G4 decision before enabling ordinary verification; fuzz planning also
  requires G3 and separate enablement. Keep the lab manually admitted.

### B10 — Optional protocol extension

- Write and approve a separate network threat model, service/driver custody contract, logical
  transcript/replay schema, internal-network policy, and acceptance suite.
- Do not inherit function-lab admission as protocol authorization.

## 13. Focused verification plan

### 13.1 Offline unit files

Add focused tests such as:

```text
tests/formal_verification/test_intake.py
tests/formal_verification/test_property_registry.py
tests/formal_verification/test_slice_closure.py
tests/formal_verification/test_semantics_ir.py
tests/formal_verification/test_traceability.py
tests/formal_verification/test_correspondence.py
tests/formal_verification/test_assumptions.py
tests/formal_verification/test_validity.py
tests/formal_verification/test_evidence_admission.py
tests/formal_verification/test_lean_generate.py
tests/formal_verification/test_lean_check.py
tests/formal_verification/test_contracts.py
tests/formal_verification/test_job_contract.py
tests/formal_verification/test_index_and_retrieval.py
tests/formal_verification/test_mcp_capability.py
tests/formal_verification/test_formal_workbench.py
tests/formal_verification/test_guidance.py
tests/fuzz_lab/test_obligation_triage.py
tests/fuzz_lab/test_harness_policy.py
tests/fuzz_lab/test_admission.py
tests/fuzz_lab/test_quota.py
tests/fuzz_lab/test_calibration.py
tests/fuzz_lab/test_runner_protocol.py
tests/fuzz_lab/test_same_fault_minimize.py
tests/fuzz_lab/test_replay.py
tests/fuzz_lab/test_feedback.py
tests/fuzz_lab/test_job_contract.py
```

Also extend focused existing tests for registry/config/topology parity, dataset inventory,
input-source matrix, accepted handoff integrity, default collection exclusions, skill separation,
guidance composition, and package-scoped MCP capabilities.

### 13.2 Mandatory negative cases

- Fake, stale, foreign-run, or hash-changed accepted lead/build/graph input.
- Scanner line/rule mismatch and missing scanner coverage.
- Slice truncation, unresolved alias/caller/global/layout, or missing compile flags.
- Signedness, promotion, narrowing, endianness, ABI, lifetime, or UB not supported by the model.
- Omitted unsafe branch, unsupported AST node or incomplete source/header closure in the generated model.
- Vacuous initial-state predicate, contradictory premises, assumed copy bounds, mismatched violation
  dual, unsupported loops/recursion or fuel exhaustion incorrectly certified safe.
- UB removed by optimization or copy preconditions assumed instead of proved; wrong LLVM attribute trust.
- Native axioms labeled kernel-only, disabled kernel checks, forged checker receipts or modified
  elaborated definitions rejected by independent acceptance.
- Producer requests requiring downstream packages or admission/request identities forming a cycle.
- Unmapped formal predicates counted as direct evidence or derived artifacts counted as independent.
- A challenged/revoked dependency reused, supersession hiding an invalidation, or affected reports omitted.
- `sorryAx`, unapproved axiom/import, self-assumed theorem, unsafe IO, timeout, or modified proof bytes.
- Workbench proof candidate changes the theorem/imports/definitions, requests a host path, exceeds
  its check budget, reuses another work item's capability, or receives unsanitized host paths in a
  diagnostic.
- Slice refinement requests an ungranted dependency, arbitrary depth increase, target scan or new
  analyzer execution during the model call.
- Contract applied to a different source/build/ABI or without discharged preconditions/frame.
- Proof failure caused only by a missing lemma incorrectly classified as fuzzable.
- Harness calling a reimplementation instead of the admitted target function.
- Harness manufacturing an invalid caller state or using an unapproved symbol/object.
- Expired, wrong-target, wrong-function, wrong-image, over-budget, replay-only, or network-widened admission.
- Concurrent reservations overspending quota, duplicate retries, unaccounted survivor after a crash,
  premature reservation release, or cancellation/revocation failing to stop active work.
- Failed positive calibration, missing target-operation instrumentation, adapter fault or unreachable
  sink mislabeled a successful negative result; analyzed/reproduction build identities conflated.
- Child process surviving timeout; unexpected output file; missing sanitizer runtime; corrupt corpus.
- Minimizer preserving a different crash instead of the admitted predicate.
- Nondeterministic or fewer-than-required replays labeled reproduced.
- Clean fuzz campaign labeled safe or used to upgrade source correspondence.
- Cross-package formal MCP lookup or raw proof/harness/testcase/log retrieval.
- Hidden evaluator labels visible to a model, seed generator, target mount, or retrieval shard;
  related twins leaking across held-out splits or unequal baseline budgets hidden in reported gains.

### 13.3 Manual validations

Container functional tests, Dagster integration, acceptance runs, actual Lean image smoke, and live
fuzz campaigns remain manual validations requiring explicit user authorization. Their future
locations should be under `tests/integration/`, `tests/acceptance/`, or `tests/live/` so implicit
pytest collection excludes them. Unit success does not establish container availability, review
quality, source correspondence, or live isolation.

## 14. Documentation deliverables

Before each capability is called implemented, update:

- `docs/architecture/formal-verification.md`: stable boundaries, schemas, assurance levels, and
  topology;
- `docs/operations/formal-verification.md`: configuration, prerequisites, sidecar/graph operation,
  artifacts, gaps, and inspection;
- `docs/operations/formal-fuzz-lab.md`: admission, isolation, quotas, launch, stop, evidence,
  replay, and incident handling;
- `containers/tools/lean-verifier/README.md` and `containers/tools/formal-fuzz/README.md`: exact
  contents, provenance, build/smoke commands, security controls, and limitations;
- `docs/operations/retrieval-mcp.md`: formal tool contracts and package scoping;
- `docs/architecture/jobs-and-runtime.md`, `job-interchange.md`, and
  `indexing-and-query-reuse.md`: new producers, datasets, and query routes;
- the original design document: implemented/deferred status only after code and evidence exist.

Documentation must distinguish proposed, implemented, built, deployed, enabled, and validated
states. A configured tag is not a built image; a registered job is not a successful review; a
checked model proof is not automatically a source proof.

## 15. Definition of complete

The buildout is complete only when all of the following are true:

- One real accepted SAST lead reaches `job_formal_verification` through hash-verified upstream
  handoffs and produces a schema-valid, indexed, auditable result.
- The exact supported source/compiler semantics and every unresolved dependency are recorded.
- Lean checks the generated theorem/witness using the pinned image, and the axiom/import audit
  and independent challenge comparison/replay pass under the declared assurance profile, or the
  attempt remains non-proven.
- G0/G1, G2, G3 and G4 are recorded separately. A safe-but-flagged case can be source-certified only
  through the exact companion design section 4.5.2 certificate and kernel-only acceptance; conditional results leave
  G2 unmet. Ordinary enablement requires G4 after G2, not merely a working model pipeline.
- A vulnerable paired case yields a valid witness and, after explicit admission, a minimized
  three-times replayable violation against the original admitted implementation.
- The function lab calibrates its oracle, verifies operation instrumentation and build identities,
  atomically accounts quotas/retries/recovery/revocation, is absent from ordinary topology, and
  refuses unauthorized/widened execution and exposes no execution MCP tool.
- Lab observations create a new immutable refinement attempt and can reach review only through a
  new accepted index/package chain.
- Formal MCP results are bounded, accepted-manifest-pinned, package-scoped, sanitized, and deny raw
  protected data.
- The formal workbench supports iterative fixed-theorem proof checks and bounded proposal/refinement
  feedback while denying cross-work-item access, arbitrary files/imports/commands, admission,
  target execution and direct accepted publication.
- Roles/tasks/skills are hash-pinned and separation tests prove development guidance never reaches
  runtime workers.
- Evidence admission maps exact predicates/scopes and preserves lineage; challenged certificates
  suspend transitive reuse and identify affected publications without rewriting historical attempts.
- Existing SAST observations, PoC compile-only behavior, claim adjudication, and final publication
  policy remain authoritative and unchanged unless a separately reviewed milestone changes them.
- Focused units pass; authorized integration/acceptance/live results are reported separately with
  exact commands, duration, revision, image identities, and gaps.

## 16. Decisions requiring explicit ADRs during implementation

The plan fixes the architecture but leaves a small number of evidence-dependent choices. Record
each as an ADR before code silently commits to it:

1. The measured real scanner rule/paired fixtures satisfying the same-alert gate for the fixed
   `local_copy_bounds/1` subset. Do not silently broaden it when an example fails to alert.
2. The pinned Clang AST serialization/source-binding implementation and ABI for the closed grammar;
   AST is the initial authority. Later LLVM support needs a versioned certificate extension.
3. The pinned Lean/library/independent-checker releases and exact approved-native procedure list;
   the kernel-only G2 policy and independent acceptance requirements are already fixed.
4. Whether CBMC adds enough candidate value to justify a separate image in M1; if added, its
   bounded conclusions remain non-proof evidence.
5. The exact source/build materialization mechanism that gives the lab only the admitted function
   and required callers without breaking the accepted build.
6. The operator identity/authentication mechanism for local versus remote admission creation.
7. The implementation evidence satisfying each mandatory companion design section 4.5.2 correspondence predicate;
   this ADR records the checker/lemma identities, not permission to weaken the certificate.
8. Whether the optional protocol driver is justified after core M2 results; it must not delay M1
   or function-level M2.

These ADRs may narrow support. They may not weaken evidence, custody, authorization, or gap
reporting to make a demonstration pass.
