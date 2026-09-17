# Design review of v3 — 2026-09-11

Open items from the 2026-09-11 review, ordered by expected cost in a real engagement.
Each becomes a doc section or ADR; check off when folded into `design-v3.md`.

## Must address before first run

- [ ] **Agent-facing prompt injection is not in the threat model.** §2.2 treats the build as hostile; the source tree is equally hostile input to every LLM lane (comments, strings, README, fixtures). Add: evidence delivered as data not instructions; L7 verifiers see only cited artifact spans, never discoverer prose; `INJECTION_SUSPECTED` ledger event. The engagement's own Sept 3 lessons doc records a forged-context injection being caught.
  - Partially folded into §6.1 (2026-09-17): formalizes the data-not-instructions rule as part of the threat model, and adds `INJECTION_SUSPECTED` to §23.8's ledger event list (spec only — no orchestrator exists yet to emit it). Still open: "L7 verifiers see only cited artifact spans, never discoverer prose" is a process-enforcement change to lane 09, not addressed here.
- [x] **Refutation has no lane.** §1 names Refuters; the lane table has none and `blue-team-refutation` is only a skill. Define where it runs and make a refutation attempt a required input before High/Critical reaches L7/L8.
  - Folded into §4.1 (2026-09-17): documents the harness's `08-blue-team-refutation` as the de facto implementation and flags the §4/§18 divergence as still open. Requiring a refutation attempt before High/Critical reaches L7/L8 is a process-enforcement change, not a doc change — left open for the orchestrator-layer work.
  - Resolved further (2026-09-17, same day): added `L4B`/`L5B` as a formal §4 lane-table row rather than leaving it as a documented divergence — decision made with the repo owner. `08` now also carries the `07` red-team claim's `L4`/`L5` design-lane tag through refutation. The §4/§18 divergence noted above no longer applies; the process-enforcement gap (refutation required before High/Critical reaches L7/L8) remains open.
- [ ] **Isolation profile for the actual host.** §2.2 assumes a microVM. Define the Linux-container profile (no network, read-only workspace, cap-drop, seccomp, quotas, disposable) and, if a Windows host ever appears, a Hyper-V snapshot-revert profile. Add `ANALYSIS_TOOLCHAIN_DIVERGENCE` next to the compile-database trust states for clang-cl ≠ cl.
  - Partially folded into new §2.2.1 (2026-09-17): documents `images/audit-native/run.sh`'s actual Linux-container profile in full (network none, read-only root + scoped tmpfs, cap-drop ALL, no-new-privileges, non-root user, pids/memory/cpu quotas, read-only evidence mount + disposable scratch) — this is the "define the Linux-container profile" ask, now accurate to what's built rather than assumed. Still open: no custom seccomp profile exists (Docker's default applies; a scoped one needs to be written and validated against a running container, not authored blind — see §2.2.1's note on why that wasn't attempted here); no Windows/Hyper-V snapshot-revert profile has been designed at all (flagged in §2.2.1 as a genuine open gap, not just undocumented); `ANALYSIS_TOOLCHAIN_DIVERGENCE` ledger event not yet added.
- [ ] **L3 substrate.** Add SVF / LLVM IR / CPG enrichment and the tiered strategy (ADR-0001). Current text lists only clang/CSA/Joern/cppcheck.
- [ ] **VERIFIED_PRIMITIVE stranding.** Must-Fix requires VERIFIED, VERIFIED requires reachability, static analysis often can't establish reachability. Add: high-consequence primitive + unresolved dependency past deadline → forced escalation or must-fix-with-caveat; terminal state `PRIMITIVE_UNRESOLVED_REPORTED` required by the finalization gate.
- [ ] **§19 pass criteria and holdout.** Required recall per defect class, false-positive budget, discrimination targets for benign/ambiguous cases. Split tuning corpus from holdout. Include real historical CVEs (Notepad++ v8.5.6→v8.5.7) alongside planted defects.
- [ ] **Ledger anchoring.** Hash chain is tamper-evident only if the head hash is anchored outside the orchestrator (signed with a key it doesn't hold, or written out-of-band periodically). State that the orchestrator never parses evidence content, only schema + hashes.

## Smaller

- [x] Duplicate section 21 in the Doc (renumbered 22/23 in the markdown export).
  - Verified 2026-09-17: current markdown export has no duplicate — sections run 21 (Design conclusion), 22 (Code Index...), 23 (Incremental Verification...) with no collision. No doc change needed; flag if the next Google Doc export reintroduces the duplicate.
- [x] Define "model diversity is consequence-weighted": minimum distinct model families for NO-GO / malfeasance votes.
  - Folded into §5.1 (2026-09-17): at least 2 distinct model families for any WARRANTED-tier vote, at least 3 for malfeasance/NO-GO/RE-DAST-escalation votes.
- [x] Bound RESCOPE rounds per component to prevent oscillation.
  - Folded into §23.2 (2026-09-17): capped at 2 automated re-scopes per component; a third forces human escalation via §20.1.
- [x] Derive CVSS 4.0 vector components deterministically from verified-fact attributes where possible; LLM only for the residual.
  - Folded into §14 (2026-09-17): documents which verified-fact attributes map directly to which CVSS 4.0 metrics; the actual derivation script is an implementation task, not yet built.
- [x] Enumerate human gates: who dispositions intent, who approves protected-test modification, who signs FINAL.
  - Folded into new §20.1 (2026-09-17): table of gate / who / ledger event, covering intent disposition, protected-test modification, FINAL sign-off, and RE/DAST/fuzz/live-state escalation authorization.
- [x] Secrets scrubbing step before evidence enters prompts or the ledger (`scripts/scrub_evidence.py` exists).
  - Folded into §9 (2026-09-17): documents the existing `scripts/scrub_evidence.py` step and the rule that only redaction metadata, never secret values, is recorded.
- [x] Second, VS2013-era validation target with a known CVE (ADR-0001 consequence).
  - Folded into §19 (2026-09-17): added as a bullet in the validation-corpus list; the actual second target still needs to be built.
