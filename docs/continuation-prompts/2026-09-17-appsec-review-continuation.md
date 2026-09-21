# Continuation prompt — AppSec Review, next cheap-wins pass

Paste this as the first message in the next chat (it's attached to the "AppSec Review" Claude
project — read `claude/appsec-review-architecture-2026-09-17.md` and `claude/TODO.md` from that
project first, they carry full context).

---

We're working on my `appsec-review` repo (device-bridge to my machine "hal5000": Windows-mounted
view at `F:\repos\appsec-review` for this session, my actual WSL checkout is
`~/projects/appsec-review`, WSL user `wsollers`). This session is attached to the "AppSec Review"
Claude project — read `claude/appsec-review-architecture-2026-09-17.md` (current-state
architecture, includes a "Design vs. built — gap status" section that's the authoritative gap
list) and `claude/TODO.md` (has a "Next cheap wins" section, ordered by leverage-per-effort) before
doing anything else. `docs/architecture/design-v3.md` in the repo is the design authority; `docs/design-
review-2026-09-11.md` is its open-items checklist, seven "Smaller" items plus the refutation-lane
item were already folded in as of 2026-09-17.

**What's already done (2026-09-17, commit `25a5f03` and earlier):** the `audit-iac`/`audit-
container`/`audit-report` Docker images and build scripts; a new `15-deployment-hardening` harness
lane implementing design's L15 (reuses existing IaC/container scan evidence, no new tooling
needed); design-v3.md §4.1 mapping table reconciling the built `00`–`15` lanes against the
design's `L0`–`L15` scheme; and doc-only fixes for seven smaller design-review items (model-
diversity minimums, RESCOPE round cap, CVSS 4.0 derivation mapping, a new human-gates table,
secrets-scrubbing note, a second VS2013 validation-target bullet, and documenting the `08-blue-
team-refutation` vs. design divergence).

**Known outstanding housekeeping — check this first:** as of the last session, commits `f2b8ab1`,
`4fc3940`, `4357406`, and `25a5f03` were made in the device-bridge sandbox but the sandbox cannot
push to GitHub (no credentials). Ask me to confirm I've run `git push origin main` on hal5000 and
`git pull` in `~/projects/appsec-review`. If I haven't, remind me before assuming the repo state
you see is what's actually on GitHub.

**What to do next — work through `claude/TODO.md`'s "Next cheap wins" list, same approach as the
L15 lane:** for each item, check what evidence/prompt-structure already exists before assuming new
work is needed (the L15 lane was cheap specifically because the pipeline already gathered
everything it needed — verify that's true for each item below before starting, since some may need
a new scanner step first, which is out of "cheap" scope). In rough priority order:

1. **L1 broadening** — widen `06-cve-reachability` (or split a new lane) to cover the full
   design `L1` scope: SBOM/dependency resolution, EOL/abandonware, license inventory, not just CVE
   reachability. Check whether `audit-static`'s syft output already has license data before
   assuming this is doc-only.
2. **07/08 → L4/L5 split** — `07-red-team-adversarial` already runs general + known-list
   subtasks; check `07-red-team-adversarial/subprompts.md` to see how much of an L4 (AppSec
   discovery) vs. L5 (malfeasance/insider) split already exists as sub-structure before deciding
   whether this is a prompt restructuring job or needs a new lane folder.
3. **L8 scoring/prioritization as its own step** — the CVSS 4.0 deterministic-derivation mapping
   is now in design-v3.md §14; extract scoring out of `10-synthesis-report` into its own
   lane/step ahead of synthesis, using that mapping.
4. **Resolve the 08-blue-team-refutation divergence** — decide (with me, this is a judgment call
   not a technical one) whether to add `blue-team-refutation` as a real row in design-v3.md §4's
   lane table, or fold the harness's dedicated lane back into `07` as an inline skill to match the
   design as currently written. Small doc edit either way once decided.
5. **Seccomp profile + Windows/Hyper-V isolation doc note** — one of the six still-open "must
   address before first run" items in `design-review-2026-09-11.md`. `images/audit-native/run.sh`
   already has most of a hardened profile; this is mostly documenting it in design-v3.md §2.2,
   plus optionally writing an actual seccomp JSON profile if I want to go beyond doc-only.
6. **Prompt-injection threat-model formalization** — another open "must address" item; fold the
   harness's already-informal data-not-instructions rule into design-v3.md's actual threat model
   text, and add an `INJECTION_SUSPECTED` event name to §23.8's ledger event list (the event won't
   actually fire anywhere until the orchestrator exists — this is a spec addition, not working
   code).

**Explicitly out of scope for this pass** (larger tracks, deliberately deferred — see
`claude/TODO.md`'s "Larger tracks" section): the orchestrator/contract/schema layer
(`orchestrator/`, `contracts/`, `schemas/` are all still README-only stubs — this is the biggest
single remaining item but is real Python implementation, not a cheap win); new lanes that need
evidence the pipeline doesn't gather yet (`L6B`, `L10`, `L12`, `L13`); and the three remaining
"must address" items that need either the orchestrator to exist first (ledger anchoring) or
deeper standalone work (§19 recall/FP-budget/holdout-split criteria, final confirmation of
`VERIFIED_PRIMITIVE` stranding coverage in §23.1).

**House rules carried over, still apply:**
- Never `git add -A`; stage files explicitly by name.
- Never touch `images/audit-native/ir-facts/ir-facts.cpp` or `Claude outputs/` — both are
  pre-existing unrelated dirty state in the repo, not part of this work.
- The device-bridge sandbox cannot push to GitHub — after committing, ask me to push and pull on
  hal5000 myself, same as every prior session.
- Update `claude/appsec-review-architecture-2026-09-17.md` and `claude/TODO.md` in the project
  again at the end of this pass, the same way this session's summary was written back, so the next
  chat starts from an accurate state.

Start by re-reading `docs/architecture/design-v3.md` §4.1 and `docs/design-review-2026-09-11.md` on the repo
directly (not just my project summary of them) to confirm nothing changed since 2026-09-17, then
work through the "Next cheap wins" list above, checking with me before any item that turns out to
need new scanner tooling rather than doc/prompt work.
