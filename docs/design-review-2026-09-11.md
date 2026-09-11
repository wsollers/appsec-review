# Design review of v3 — 2026-09-11

Open items from the 2026-09-11 review, ordered by expected cost in a real engagement.
Each becomes a doc section or ADR; check off when folded into `design-v3.md`.

## Must address before first run

- [ ] **Agent-facing prompt injection is not in the threat model.** §2.2 treats the build as hostile; the source tree is equally hostile input to every LLM lane (comments, strings, README, fixtures). Add: evidence delivered as data not instructions; L7 verifiers see only cited artifact spans, never discoverer prose; `INJECTION_SUSPECTED` ledger event. The engagement's own Sept 3 lessons doc records a forged-context injection being caught.
- [ ] **Refutation has no lane.** §1 names Refuters; the lane table has none and `blue-team-refutation` is only a skill. Define where it runs and make a refutation attempt a required input before High/Critical reaches L7/L8.
- [ ] **Isolation profile for the actual host.** §2.2 assumes a microVM. Define the Linux-container profile (no network, read-only workspace, cap-drop, seccomp, quotas, disposable) and, if a Windows host ever appears, a Hyper-V snapshot-revert profile. Add `ANALYSIS_TOOLCHAIN_DIVERGENCE` next to the compile-database trust states for clang-cl ≠ cl.
- [ ] **L3 substrate.** Add SVF / LLVM IR / CPG enrichment and the tiered strategy (ADR-0001). Current text lists only clang/CSA/Joern/cppcheck.
- [ ] **VERIFIED_PRIMITIVE stranding.** Must-Fix requires VERIFIED, VERIFIED requires reachability, static analysis often can't establish reachability. Add: high-consequence primitive + unresolved dependency past deadline → forced escalation or must-fix-with-caveat; terminal state `PRIMITIVE_UNRESOLVED_REPORTED` required by the finalization gate.
- [ ] **§19 pass criteria and holdout.** Required recall per defect class, false-positive budget, discrimination targets for benign/ambiguous cases. Split tuning corpus from holdout. Include real historical CVEs (Notepad++ v8.5.6→v8.5.7) alongside planted defects.
- [ ] **Ledger anchoring.** Hash chain is tamper-evident only if the head hash is anchored outside the orchestrator (signed with a key it doesn't hold, or written out-of-band periodically). State that the orchestrator never parses evidence content, only schema + hashes.

## Smaller

- [ ] Duplicate section 21 in the Doc (renumbered 22/23 in the markdown export).
- [ ] Define "model diversity is consequence-weighted": minimum distinct model families for NO-GO / malfeasance votes.
- [ ] Bound RESCOPE rounds per component to prevent oscillation.
- [ ] Derive CVSS 4.0 vector components deterministically from verified-fact attributes where possible; LLM only for the residual.
- [ ] Enumerate human gates: who dispositions intent, who approves protected-test modification, who signs FINAL.
- [ ] Secrets scrubbing step before evidence enters prompts or the ledger (`scripts/scrub_evidence.py` exists).
- [ ] Second, VS2013-era validation target with a known CVE (ADR-0001 consequence).
