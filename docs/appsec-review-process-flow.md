# AppSec review — end-to-end process flow and construction status

Snapshot: 2026-09-21, `main` = `ec7b2d0`. Built from `job-graph.json` (42 jobs), `TODO.md`
batch statuses, ADR-0008/0009/0010, the three task series and the 2026-09-21 continuation prompt.
Regenerate or re-verify before relying on a status: `TODO.md` is the authority, and a few of its
lines are stale (called out in section 6).

## Legend

| Colour | Meaning |
|---|---|
| Green | **Built and qualified** — runs today (graph `implemented: true`, or qualified runtime) |
| Blue | **Foundation only** — contracts, schemas, validators or prompts exist; the worker/runner does not |
| Amber | **Designed, not built** — accepted ADR or registry/prompt text; no code, waiting on a prerequisite |
| Red | **Open decision or gate** — needs the owner, or is undecided |
| Grey | **Not designed** — named in the plan, no design record found |

## 1. Lifecycle: from engagement request to final report

```mermaid
flowchart TD
  classDef built fill:#d4edda,stroke:#2e7d32,color:#111
  classDef found fill:#d6e6f7,stroke:#1565c0,color:#111
  classDef todo fill:#fff0cc,stroke:#b26a00,color:#111
  classDef gate fill:#f8d7da,stroke:#b71c1c,color:#111
  classDef none fill:#e6e6e6,stroke:#666,color:#111

  REQ([Engagement request and target]):::built --> RUN[Create or resume run<br/>Dagster queue, run-owned data dir,<br/>immutable attempts, accepted.json]:::built
  RUN --> VET{{A01 prompt vetting record<br/>not attempted on Linux}}:::gate
  VET --> INT[00 Intake<br/>identity, scope, build applicability, job plan]:::built

  INT --> P2[[Phase 02: evidence pregather<br/>see section 2]]:::todo
  P2 --> ASM[02 Evidence assembly<br/>wait-all join of every 02 producer]:::todo
  ASM --> CMP[01 Component characterization<br/>component map, tag cloud]:::todo

  CMP --> TM[03 Threat model / DFD / STRIDE<br/>four-wave workbench, ADR-0008]:::todo
  CMP --> OW[04 OWASP worklist then ASVS/MASVS<br/>control workbench, ADR-0009]:::found
  CMP --> NM[05 Native memory]:::todo
  CMP --> CV[06 CVE reachability]:::todo
  CMP --> HD[15 STIG/SRG worklist then deployment hardening]:::gate
  TM --> OW
  TM --> FZ[13 Fuzz-target triage]:::todo
  NM --> FZ
  CV --> FZ

  OW --> RT
  TM --> RT
  NM --> RT
  CV --> RT
  HD --> RT
  FZ --> RT[07 Red team discovery]:::todo
  RT --> BT[08 Blue team refutation]:::todo
  RT --> IV
  BT --> IV[09 Independent verification]:::todo
  IV --> SC[12 Scoring and prioritisation]:::todo
  HD --> SC
  TM --> SC
  IV -. only if remediation requested .-> RM[11 Remediation and same-environment retest]:::todo
  SC --> SY[10 Synthesis report]:::todo
  RM -. optional .-> SY
  SY --> SARIF[Critical-findings SARIF<br/>standalone job, not a graph node]:::built
  SY --> FIN{{Final publication gate L12<br/>completeness + synthetic-hypothesis loop L11}}:::todo

  IV -. dynamic rescope L10 .-> CMP
  FIN -. gaps found .-> RT
```

Notes on the diagram

- Every arrow above is a `required` edge in `job-graph.json` unless dashed. A skipped upstream job
  only unblocks its consumer for the skip reasons written on that edge.
- Only `00-intake`, `02-ossf-scorecard` and `02-evidence-index` are `implemented: true`. Every
  other lifecycle node blocks with `WORKER_NOT_IMPLEMENTED`.
- `02-repository-partition-discovery` is a supplied hand-off gate and is correctly
  `implemented: false`.
- The 04 box is blue because ADR-0009's lane-in, applicability, batching, validator hand-off,
  validator output, intercom and dynamic-test-request modules exist (OWASP T02A–T09). Dispatch,
  join and lifecycle wiring (T10–T14) do not.
- `03`'s graph node depends only on `01`; ADR-0008 replaces that single step with the four-wave
  workbench and needs `S02`/`T10` to land.

## 2. Phase 02 — evidence pregather in detail

```mermaid
flowchart LR
  classDef built fill:#d4edda,stroke:#2e7d32,color:#111
  classDef found fill:#d6e6f7,stroke:#1565c0,color:#111
  classDef todo fill:#fff0cc,stroke:#b26a00,color:#111
  classDef gate fill:#f8d7da,stroke:#b71c1c,color:#111

  INT[00 Intake]:::built

  subgraph S["Source-only, no build needed"]
    SC[02-ossf-scorecard]:::built
    EI[02-evidence-index<br/>+ cloc/scc metrics, V15]:::built
    SS[02-source-sast<br/>D09 / V13]:::todo
    DOC[02-doc-intelligence-ingest]:::todo
    API[02-api-collection-intelligence-ingest]:::todo
    TI[02-test-intelligence-ingest]:::todo
    OPD[02-operations-doc-ingest]:::todo
    STD[02-standards-source-ingest<br/>needs G02 + G03 ADRs]:::gate
  end

  subgraph V["Vendor pre-pass nine nodes (ADR-0010, not yet in job-graph.json)"]
    SEC[secrets + IaC per-tool jobs<br/>V10 / M03]:::todo
    SBOM[02-sbom-inventory, SCA, license, lifecycle<br/>V11 / M05]:::todo
    CIM[container image inventory, mobile,<br/>02-binary-hardening<br/>V12 / M04]:::todo
  end

  PART[02-repository-partition-discovery<br/>supplied hand-off gate]:::found
  INT --> PART
  PART --> DEV[02-dev-project-discovery<br/>D02]:::todo
  PART --> DVO[02-devops-project-discovery<br/>D03]:::todo
  PART --> SRE[02-sre-operations-topology<br/>D04]:::todo
  INT --> S
  INT --> V

  DEV --> BC[02-build-configure<br/>build discovery is runnable, E01]:::found
  BC --> NB[02-native-build<br/>E02, needs B13]:::todo
  NB --> NS[02-native-sast E03]:::todo
  NB --> IRC[02-ir-capture E04]:::todo --> IRL[02-ir-link]:::todo --> IRF[02-ir-facts E05]:::todo
  NB --> DSI[02-debug-symbol-index E06]:::todo
  NB --> BTR[02-binary-triage E07, needs M02]:::gate
  BTR --> BCFG[02-binary-cfg]:::todo
  DSI --> BCFG
  BCFG --> BII[02-binary-intelligence-ingest E08]:::todo
  NB --> TE[02-test-execution E09]:::todo
  TE --> TR[02-test-result-ingest]:::todo
  TE --> TC[02-test-coverage-ingest]:::todo

  SBOM -. matcher inputs .-> GDB[Grype DB mirror V16<br/>OSV snapshot V17<br/>consumer bindings V18]:::todo
  SBOM -. NVD binding, V09 done .-> NVD[NVD snapshot under /data]:::found

  SEC & SBOM & CIM & SS & DOC & API & TI & OPD & STD & DVO & SRE & DEV & NS & IRF & BII & TR & TC & SC & EI --> ASM[[02-evidence-assembly<br/>wait-all join F02]]:::todo
  ASM --> CMP[01 Component characterization F03<br/>longest pole]:::todo
```

Fan-out rules that the graph already enforces

- Non-native targets skip the whole build-gated branch with `not-applicable-non-native`.
- Partition review can skip a node with `not-applicable-after-partition-review`.
- ADR-0010 adds `not-applicable-no-matching-inputs` (G5) — registered by V02, not yet present.
- `02-license-scan` depends on `02-sbom-inventory` (PR #23 review, option A).
- Every scanner producer redacts with a receipt (V06, done) and verifies it before parsing
  anything it published.

## 3. What every worker does (the common runtime)

```mermaid
flowchart TD
  classDef built fill:#d4edda,stroke:#2e7d32,color:#111
  classDef found fill:#d6e6f7,stroke:#1565c0,color:#111
  classDef todo fill:#fff0cc,stroke:#b26a00,color:#111

  A[Resolve registry handoff<br/>immutable, run-owned input hashes]:::built --> B[Per-job lock and reuse decision]:::built
  B -->|reusable accepted attempt| Z[Reuse published result]:::built
  B --> C[Allocate attempt, PENDING pointer]:::built
  C --> D{Execution boundary}
  D -->|deterministic argv child| E[deterministic-child/1.0<br/>timeout, drained streams, tree cleanup]:::built
  D -->|pinned container argv| F[B13 pinned-container adapter<br/>in progress in another session]:::todo
  D -->|persona invocation| G[B14 persona adapter]:::todo
  E & F & G --> H[Redact + receipt V06]:::built
  H --> I[Verify receipt, then parse published files<br/>status.json + manifest.json + outputs]:::built
  I --> J[Validate output contract<br/>validate_job_output dispatch]:::found
  J -->|OK / OK_WITH_GAPS / SKIPPED with receipt| K[Publish accepted.json,<br/>atomically move latest.json]:::built
  J -->|BLOCKED / FAILED / CANCELED| L[Durable terminal envelope,<br/>downstream blocked, resumable]:::built
  K --> M[Evidence store, retrieval MCP,<br/>index by locator not by content]:::built
```

The dispatch box (J) is blue because validators for the nine ADR-0010 contracts exist as modules
(V04 ×2, V07 ×3, V05 ×4) but are not yet dispatched from `validate_job_output.py`.

## 4. Persona pool runtime (feeds every persona-driven node)

```mermaid
flowchart LR
  classDef found fill:#d6e6f7,stroke:#1565c0,color:#111
  classDef todo fill:#fff0cc,stroke:#b26a00,color:#111
  P[B11 permission-capability model<br/>READY, 11 follow-ups]:::found --> B13[B13 container adapter]:::todo
  P --> B14[B14 persona adapter]:::todo
  P --> B15[B15 dedicated pools]:::todo
  B13 & B14 & B15 --> C01[C01 pool spec + instance expansion]:::todo
  C01 --> C02[C02 wait-all rendezvous + terminal manifest]:::todo
  C02 --> C03[C03 typed deterministic merges]:::todo
  C03 --> C04[C04 evidence-qualified quorum + diversity]:::todo
  C04 --> L01[L01 append-only claim/decision ledger]:::todo
```

Registry content (`registry/personas`, `roles`, `domains`, `tooling-profiles`, `output-contracts`,
`job-templates`, `permission-capabilities`) is largely authored; the runtime that instantiates
them is what is missing.

## 5. Adversarial claim lifecycle (07 → 10)

```mermaid
flowchart TD
  classDef todo fill:#fff0cc,stroke:#b26a00,color:#111
  classDef none fill:#e6e6e6,stroke:#666,color:#111
  L01[L01 claim ledger]:::todo
  RT[07 Red team<br/>general + known-list, catalog]:::todo -->|claims| L01
  L01 --> BT[08 Blue team refutation]:::todo
  BT -->|contested claims| IV[09 Independent verification<br/>same-environment testcase]:::todo
  IV -->|verified / refuted / unresolved| L01
  IV --> RM[11 Remediation proposal]:::todo
  RM --> RETEST[L09 same-environment retest loop]:::todo
  RETEST -->|still exploitable| RM
  IV --> SC[12 Scoring]:::todo
  SC --> SY[10 Synthesis]:::todo
  L10[L10 dynamic rescope controller]:::none -. new components .-> RT
  L11[L11 completeness + synthetic hypotheses]:::none -. gaps .-> RT
  SY --> L12[L12 SARIF binding + final publication gate]:::todo
```

Prompt text for 07–12 exists under `appsec-review-process/0x-*/`; none of the nodes has a worker.
L10, L11 and L12 are named in `TODO.md` but no design record beyond one-paragraph entries was found.

## 6. Status by area — what is built and what is left

### 6.1 Built and qualified

| Area | Evidence |
|---|---|
| Dagster stack, run queue, run-owned data, immutable attempts, `accepted.json` | live stack; Linux baseline 857 tests OK |
| Common worker envelope, lifecycle coordinator, deterministic child boundary | Batch 7/8, qualified Windows + Linux |
| `00-intake` (Phase 1 acceptance A02–A16) | `phase-1-acceptance.md`; A01 not attempted on Linux |
| `02-ossf-scorecard`, `02-evidence-index` (+ V15 metrics) | requalified on Linux, `metrics_sha256` identical |
| Critical-findings SARIF (B09, standalone) | QUALIFIED |
| Build discovery, source evidence retrieval | runnable |
| Evidence redaction + receipt (V06), evidence store, retrieval MCP | done |
| Shared shapes V03; NVD snapshot binding V09; secrets/IaC contracts V04; SBOM-family contracts V05; container/mobile/binary contracts V07 | merged |
| OWASP foundations T02A–T09 (snapshots, NVD 2.0 publisher, lane-in, applicability, batching, validator hand-off, output, intercom, dynamic requests) | merged, unit-tested |
| Decisions: ADR-0008 (threat workbench), ADR-0010 (vendor pre-pass) | accepted 2026-09-20 |

### 6.2 To be constructed — in dependency order

| # | Item | IDs | Blocked by | Notes |
|---|---|---|---|---|
| 1 | **Integrator: declare nine vendor-prepass nodes, skip reason, licence→SBOM edge, validator dispatch** | V02 | none — READY | Unblocks V08, T03, V10–V13. Recommended next slice. |
| 2 | Status hygiene | — | none | task-series still says V04/V07 "in review", V05/V15 `READY`; TODO closures for G01, M01, F01/V15 |
| 3 | Permission-capability wiring | B11 | none — READY | Opens B14, B15, V16, V17 |
| 4 | Pinned-container adapter | B13 | B11 | **Another session is mid-flight** (`claude/b13-pinned-container-adapter`, no PR). Unblocks all container-run workers. |
| 5 | Persona adapter, resource pools | B14, B15 | B11 | |
| 6 | Pool specification, wait-all, merges, quorum | C01–C04 | B13–B15 | Owner chose B13→B14→B15→C01→C02 before OWASP T10 |
| 7 | Operator status/resume detail; supplied-discovery envelope | B12, B10 | B10/B12 lines say `BLOCKED(B09)` but B09 is QUALIFIED — likely stale, confirm | |
| 8 | Vendor mirrors: Grype DB publisher, OSV publisher, consumer bindings | V16, V17, V18 | B11 wiring | |
| 9 | Vendor pre-pass workers | V10 secrets+IaC, V11 SBOM family, V12 container/mobile/binary, V13 = D09 source SAST | V02 + B13 (+V16–18 for V11, M02 for V12) | |
| 10 | Discovery dispatch | D01–D04 | B14, C01–C03 | |
| 11 | Ingest jobs | D05–D08 | B09 done, D05 for D08 | Independent of pools; could be built in parallel once graph declares them |
| 12 | Build/compiled evidence | E01–E10 (native build, SAST, IR capture/link/facts, debug symbols, binary triage/CFG, test execution/ingest) | B13, D02, M02, B11 | `qualify_tooling` needs `audit-buildenv-*` images built on this host |
| 13 | Evidence enrichment, assembly rendezvous, characterization | F01, F02, **F03** | most of 10–12 | F03 is the longest pole; F02 has ~14 pregather batches behind it |
| 14 | Standards ingest and workbenches | S01 standards, S02 threat model, S03 OWASP/ASVS/MASVS, S04 STIG/deployment | G02, G03 ADRs, F03, B14 | T02–T10 (threat) and T10–T14 (OWASP) sit here |
| 15 | Claim ledger and analysis lanes | L01–L04 | C04, F03 | native memory, CVE reachability, fuzz triage |
| 16 | Adversarial lifecycle | L05 red, L06 blue, L07 verify, L08 scoring | 14, 15, B14, C04 | |
| 17 | Remediation loop, rescope, completeness, synthesis | L09–L12 | L07, L08 | L10–L12 least designed |
| 18 | Retire legacy runners | V14 / M07 | V10–V13, V15, M06, V15 verified on Windows | deletes `scripts/` prepass runners |
| 19 | Release | Q01–Q05, design-parity gate, R01 | all applicable batches | |

### 6.3 Open decisions and gates (owner-owned)

| Gate | State | What is needed |
|---|---|---|
| **A01** prompt-vetting record | not attempted on Linux | Line-by-line review of `phase-1-implementation-prompt.md` approved by the owner, or accept A02–A16 as the Linux baseline |
| **G02** OWASP applicability/evidence ADR | ADR-0009 header still says *Proposed* | Owner approval; blocks S01, S03 |
| **G03** DISA/NSA hardening ADR | `HUMAN_GATE`, packet only | Owner approval; blocks S01, S04, and node 15 |
| **M02** binary/mobile/container image pinning and split | READY (decision) | Blocks E07, V12 |
| **M06** semantic-index disposition | READY (decision) | Blocks V14 |
| V15 metrics location | undecided | Keep in `manifest.json` `member_schemas`, or sibling `metrics.json` (identity change) |
| `first-party` label for Freeciv21 `dependencies/` | undecided | Metrics rules bump = identity change |
| Inert pip pin | undecided | Real upgrade needs Dockerfile step + version check; batch with next stack change (6 Dependabot alerts) |
| `nvd_feed.py` has no authenticity anchor; stale-but-valid NVD wording vs M4; V03 `header-mismatch` errors quote document values | undecided | Raise before V11 |
| Q04 skill-installation docs | READY | Small, independent |

### 6.4 Not yet verified anywhere

- **Nothing has run on Windows** since the Linux-first switch: V15 `GOLDEN_SHA256`, focused suites
  for V03–V09/V05/V15, and the stack on Docker Desktop with the new compose file. V14 requires
  this.
- End-to-end run of any lifecycle beyond intake plus the three built `02-*` jobs has never
  happened; `qualify_phase1.py` gates A02–A16 cover intake only.

## 7. How work moves through the build process (the delivery loop)

```mermaid
flowchart TD
  classDef built fill:#d4edda,stroke:#2e7d32,color:#111
  classDef gate fill:#f8d7da,stroke:#b71c1c,color:#111
  O[Owner picks slice or answers a gate<br/>AskUserQuestion, max 4, recommended first]:::gate --> C[Coordinator writes self-contained task prompt<br/>verbatim task text, allowed paths, lessons 1-16]:::built
  C --> S[Fable subagent in isolated worktree<br/>branch claude/task, commits and pushes]:::built
  S --> V[Coordinator adversarial verification<br/>boundary diff, merge origin/main,<br/>focused + full suite in the code-server,<br/>own probes: resealed mutations, tampering, wrong party]:::built
  V -->|findings| FX[Fix on same branch, separate commit]:::built --> V
  V --> PR[Coordinator opens PR, draft if an acceptance clause is unmet]:::built
  PR --> RV[Reviewer pushes Feedback.md with P1/P2]:::built
  RV -->|findings| R2[Reproduce, opine, wait for 'fix', fix, git rm feedback, push]:::built --> RV
  RV -->|No objections| M{{Owner names the PR to merge}}:::gate
  M --> MG[gh pr merge --match-head-commit;<br/>prove SHA is ancestor of origin/main]:::built
  MG --> RQ[Requalify anything whose identity changed<br/>qualify_*.py, record report path + sha256]:::built
```

Integrator-only surfaces (graph, parity manifest, worker-result contract, `dagster_workflow.py`,
`launch_job.py`, `orchestrator/dagster/*`, validators, `TODO.md`, accepted ADRs) are touched only
when the owner assigns an integrator task. That serialises V02, the validator dispatch, and every
later node-flip, so they, not the workers, set the pace.

## 8. Critical path summary

```text
B11 wiring ──► B13 ──┬─► B14 ─► B15 ─► C01 ─► C02 ─► C03 ─► C04 ─► L01
                     │
V02 (independent) ───┼─► V08, T03; V10 ─ V13 (with B13) ─► V14 delete runners
                     │
                     └─► E01 ─► E02 ─► E03–E10 ─► F01 ─► F02 ─► F03 ─► S02/S03/S04, L02–L04
                                                                      └─► L05 ─► L06 ─► L07 ─► L08 ─► L12
```

Owner decisions that gate that path: G02, G03, M02, M06, A01. V02 and the B11 wiring are the only
two large slices with no unmet prerequisite today.
