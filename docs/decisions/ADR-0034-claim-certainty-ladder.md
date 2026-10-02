# ADR-0034: Claim certainty ladder and verification evidence

Status: **Accepted** (2026-10-02, William, in the prompt/persona/role alignment work, item R13 / decision D5).

## Context

Stage 09 could never return VERIFIED. `claim_lifecycle_core.verify` requires a citation that is new to the
claim and produced by the verifier's own job and attempt. `claim_review_derive` only lets a reviewer cite
ids already on the upstream record. Nothing defined what "independent evidence" is.

Investigating this showed three more gaps on the same path (code read 2026-10-02):

- The production claim ledger never ingests 07/08/09 decisions. `build_ledger` supports a prior ledger
  plus decision requests (`claim_ledger.py:860-905`), but `claim_ledger.run` calls it with candidates
  only (`:1054`, `:1107`). Every claim stays `candidate`.
- Stage actors carry the pool instance id as `attempt_id` (`claim_review_derive.actor`). The merge does
  not restamp it (`claim_review_lifecycle.build_result`). `claim_ledger.load_decision` (`:782`) rejects
  any actor whose attempt id is not the accepted stage attempt.
- Report assembly expects a ledger with a status-decision chain and a status for each 09 record that
  matches the ledger (`report_input_assembly.py:265-274`, `:477-482`). It also re-hashes every
  citation's artifact under its producer's attempt (`:379-398`).

## Decision

1. **Certainty is a ladder, computed by Python.** It is reported for every claim, never only for
   verified ones. The report shows each claim's highest rung and the evidence for every rung it reached.

   | rung | meaning | source today |
   |---|---|---|
   | `finding` | a candidate exists | SAST and tool leads, hunter hypotheses, threat-model candidates (ledger) |
   | `reachable` | a call path reaches the location | `reachability.py` REACHABLE witness over the CPG; `06-cve-reachability` for dependencies |
   | `reachable_tainted` | attacker data flows to it | CodeQL `taint_paths` (engine reachability rows) |
   | `inference_validated` | 09 satisfied every proof obligation | 09 decision |
   | `poc` | a reproducer exists | none yet (12b PoCs are static text written after 09); a target-supplied reproducer test counts |
   | `patch` | a fix is proposed | 12b fix proposal (unvalidated) |

2. **What counts as independent evidence.** A PoC that exists, a known vulnerability that is reachable,
   or other evidence derived from something more than a SAST finding. A SAST finding alone never
   verifies anything.

3. **VERIFIED.**
   - Dependency vulnerabilities: a matched advisory with a REACHABLE call path to the vulnerable
     function.
   - Code findings: `inference_validated` and `reachable`. Taint, PoC and patch raise the reported
     certainty above that.
   - VERIFIED unlocks 12 scoring (factors, CVSS) and 12b.

4. **Uncertainty never blocks.** When an analysis cannot decide (reachability UNKNOWN, a missing CPG,
   a failed step), the rung is recorded as uncertain with the reason. The claim stays UNRESOLVED and the
   run continues to the report.

5. **Verifier evidence lives in the 09 attempt.** A deterministic step assembles the independent items
   per claim into `verification-evidence.json`, published in the 09 attempt. The 09 model cites items by
   id. Derive turns them into citations whose producer is the 09 attempt, so `core.verify` and report
   assembly can resolve them.

## Work items

- **V1 — stage verdicts reach the ledger.**
  - The 07/08/09 merge stamps each decision actor with its own accepted attempt id.
  - The production ledger appends 07, 08 and 09 status decisions after 09.
  - Report assembly runs on the transitioned ledger.
  - Confirm with a run through report generation.
- **V2 — certainty ladder and verification evidence.**
  - `verification-evidence.json` and the 09 citations from it.
  - VERIFIED per item 3, checked in the repair loop and the merge.
  - Certainty published on 09 records and shown in the report.
  - Report assembly accepts the 09 judgment keys (`cwe_judgment`, `mitre_refs`).
- **R13 and R14** then describe the stages as built.
