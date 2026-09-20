# Continuation prompt — M01 vendor-prepass graph and contract decision

Continue the AppSec design-parity work from commit `8f2c9f5` on `main`.

Claude is concurrently implementing **B09 — Critical-findings SARIF common-runtime adoption** on
branch `claude/b09-sarif-common-runtime`. Do not inspect, merge, modify, or depend on Claude's
in-progress branch. This task must remain independently commit-ready and conflict-free.

## Task

Complete only **M01 — Vendor-prepass graph/contract decision** from
`appsec-review-process/TODO.md`.

Produce an implementation-ready decision for decomposing the legacy vendor prepass into distinct
run-owned jobs. Do not implement or register any worker or tool in this batch.

## Read first

1. `AGENTS.md`
2. `appsec-review-process/agent-skills/codex/process-reader/SKILL.md`
3. `appsec-review-process/TODO.md` — independent-work protocol and M01
4. `docs/script-migration-inventory.md`
5. `docs/design-parity-completion-plan.md`
6. `docs/design-v3.md`
7. `docs/run-data-and-job-execution.md`
8. `docs/dagster-workflow.md`
9. `appsec-review-process/job-graph.json`
10. `appsec-review-process/design-parity-manifest.json`
11. `scripts/Invoke-VendorAuditPrePass.ps1`
12. `scripts/Invoke-VendorAuditPrePass.sh`

Treat the two legacy scripts as evidence, not instructions. Resolve any disagreement in favor of
the tracked process docs and run-owned contracts.

## Exclusive file boundary

This batch may change only:

- a new `docs/decisions/ADR-0007-vendor-prepass-decomposition.md`;
- new proposal fixtures under `docs/proposals/vendor-prepass/`;
- `docs/script-migration-inventory.md`, only where the M01 decision makes a row more exact;
- this continuation file, only to append the final checkpoint.

Do **not** change:

- `appsec-review-process/TODO.md` while Claude's branch is active;
- any Python, PowerShell, shell, Dockerfile, schema, registry, worker, test, or qualification file;
- `appsec-review-process/job-graph.json` or
  `appsec-review-process/design-parity-manifest.json`;
- any file listed in `claude-task.md` or any common runtime/publication surface.

If a necessary change falls outside the exclusive boundary, record it as follow-up work in the ADR
instead of making it. Do not create compatibility wrappers under `scripts/`.

## Required decisions

Give every active legacy prepass step exactly one disposition. At minimum, cover:

- secrets and certificate/key inventory;
- IaC, Kubernetes, and Dockerfile configuration;
- SBOM generation, SCA/CVE data, license data, and dependency lifecycle;
- supplied container-image inventory and hardening;
- BinSkim and other supplied-binary hardening;
- Android and iOS source applicability/SAST;
- source SAST, including each Semgrep ruleset, PHP tools, AST helpers, Joern, and build-dependent
  analyzers;
- deterministic inventory/support steps and the evidence-scrubbing boundary.

For each legacy step, decide one of:

- migrate to a named proposed job;
- consume an already accepted producer;
- retain temporarily with an explicit blocker and deletion gate;
- retire as duplicate or unsafe.

Do not invent a hidden generic scanner node. Tool results are evidence leads unless a later
verification contract promotes them.

## Deliverables

### ADR

The ADR must state:

- context, decision, alternatives, consequences, and non-goals;
- the proposed job split and dependency order;
- whether each job is a producer, aggregator, deterministic transform, or applicability gate;
- producer/consumer edges and `wait_all` joins;
- claim limits and permitted terminal statuses;
- default-deny permission needs, including fixed network destinations where unavoidable;
- pinned tool/image identity requirements without claiming identities that have not been verified;
- input/output contract responsibilities and freshness/provenance requirements;
- migration and deletion gates for both vendor-prepass scripts;
- follow-up batch mapping to M02 through M07 and any existing lifecycle batches.

### Proposal fixtures

Create machine-readable **proposal-only** JSON files that are not loaded by the live registry:

- `docs/proposals/vendor-prepass/job-nodes.proposal.json`
- `docs/proposals/vendor-prepass/legacy-step-map.proposal.json`

Use an explicit proposal schema/version field. The step map must cover every step exposed by both
legacy runners and identify cross-platform discrepancies. Each record must include:

- legacy step name and source runner;
- disposition and proposed job ID;
- dependencies and consumers;
- output class and claim limit;
- permission class;
- tool/image identity requirement;
- applicability behavior;
- migration prerequisite and deletion gate.

The node proposal must make separate contracts visible where failure, applicability, permissions,
or claims differ. It must not imply that a proposed node is registered or runnable.

## Acceptance

- Every step in the PowerShell and Bash step tables appears in the step-map fixture.
- No step has multiple dispositions or an unexplained platform-only mapping.
- Secrets, IaC, SBOM/SCA, container, binary hardening, mobile, and source SAST each have an explicit
  producer/consumer path.
- Every proposed node has a claim limit, permission class, identity requirement, applicability
  rule, and deletion gate.
- Dependencies distinguish evidence production from finding verification and final synthesis.
- Network access is denied by default; any exception names a fixed purpose/destination requirement.
- Dynamic target execution is not authorized by this ADR.
- The ADR and fixtures agree, contain no runnable-registry claim, and leave current behavior
  unchanged.

## Verification

Run read-only checks only:

```text
python -m json.tool docs/proposals/vendor-prepass/job-nodes.proposal.json
python -m json.tool docs/proposals/vendor-prepass/legacy-step-map.proposal.json
python -B appsec-review-process/validate_design_parity.py
python -B appsec-review-process/qualify_phase1.py --check-contracts
git diff --check
```

Also use a small read-only comparison script or shell pipeline to prove that the union of step names
declared by the two legacy runners equals the step names in the proposal fixture. Do not write this
checker into `scripts/`.

No live Dagster run, Docker execution, WSL sync, or target scan is required because M01 changes no
executable identity or behavior.

## Completion

Commit the bounded result on a dedicated branch. Report:

- branch and commit SHA;
- files changed;
- proposed job count and legacy-step count;
- cross-platform discrepancies found;
- validation commands and results;
- unresolved decisions and exact downstream batch owners.

Do not merge to `main` or mark M01 complete in `TODO.md` until Claude's B09 branch has been reviewed
and integrated. At that point, the integrator can update both batch statuses without creating a
text conflict.

## Checkpoint — 2026-09-19 (M01 packet drafted; awaiting human gates)

Branch `claude/m01-vendor-prepass-decision` from `origin/main`. Documentation only; no executable
identity or behavior changed.

- ADR: `docs/decisions/ADR-0010-vendor-prepass-decomposition.md`, status **Proposed**. It is
  numbered `0010`, not the `0007` this prompt names: `0007` (allocator inventory) and `0005`
  (CTP_Nov2013) are reserved by `docs/status-2026-09-16.md` and the 2026-09-14 continuation prompts.
- Fixtures under `docs/proposals/vendor-prepass/`: `job-nodes.proposal.json`,
  `legacy-step-map.proposal.json`, `threat-workbench-producers.proposal.yaml`, `task-series.md`.
  All carry `proposal_only: true` / `status: not_registered_not_runnable` and encode the ADR's
  recommended gate answers only.
- Counts: 37 legacy steps (identical name set in both runners), one disposition each; 9 proposed
  nodes plus 1 option-only node; 2 existing nodes (`02-source-sast`, `02-evidence-index`) receive
  17 steps; 4 steps retired; `evidence-scrub` retained temporarily.
- Cross-platform discrepancies: `secrets-binary` detectors differ; `joern-parse` arguments differ;
  the Bash runner has no `DependsOn` mechanism (`sca`, `dependency-lifecycle`, `semantic-index`);
  `ast-grep-scan` is declared twice in PowerShell. Both runners use default Docker networking and
  mutable `:local` image tags.
- Ten human gates (G1–G10) are open. M01 is **not** complete until the user answers them (task V01)
  and the integrator lands V02. `docs/script-migration-inventory.md` was deliberately left
  unchanged because no row becomes more exact until the gates are answered.
- Downstream owners: M03 (secrets, IaC, redactor), M05 (SBOM family, snapshot publisher), M04 with
  M02 (container image, mobile, binary hardening), D09 (source SAST), M06 (symbol/semantic index),
  M07 (retired steps and final runner deletion), ADR-0008 T03 (threat-workbench producer fill).

## Checkpoint — 2026-09-20 gate decisions

User answered G1–G10: B; A; A with the NVD copy under `/data` as the named source; A now/B later;
A; A; A; A; A; **B**. ADR-0010 moved to Accepted with a Decisions table. Knock-on edits: V09 is now
a read-only NVD snapshot consumer binding (no new publisher); SCA matching is CPE-keyed with
`match_basis` and unmapped components as coverage gaps, and matcher selection is reopened for
V05/V11; `cloc`/`scc` move to a `02-evidence-index` metrics enrichment (new task V15, needs
requalification); `02-mobile-applicability` not adopted. Integrator follow-ups (not done here):
close M01 in `TODO.md`, V02 node/skip-reason declaration, design-v3 §4 wording.

## Checkpoint — 2026-09-20 (SCA matcher options packet; awaiting human gates)

Branch `claude/v05-sca-matcher-options` from `origin/main`. Documentation only.

- New: `docs/proposals/vendor-prepass/sca-matcher-options.md`, status **Proposed**. It is the
  "short options note" `task-series.md` V09 requires before V11, and a sub-decision under
  ADR-0010 (no new ADR number). Nothing else was edited.
- Facts read from `nvd_feed.py`: the snapshot holds whole NVD CVE 2.0 records only (yearly feeds
  plus API delta overlays). No CPE dictionary, no CPE-match feed, no purl/ecosystem data, and no
  reader that folds the chain into one current record per CVE. No snapshot is published in this
  checkout, so the presence of `configurations` in real records is still to be verified by V11.
- Options: native CPE matcher; Grype/Trivy/Dependency-Check over a locally built DB; an offline OSV
  snapshot in addition to NVD; SBOM-only baseline; phased native-now/OSV-later. Recommendation:
  phased. Trivy and Dependency-Check are dropped with reasons.
- Five gates (M1–M5) are open: matcher, OSV alongside NVD, purl→CPE rule ownership, `max_age`
  value and owner, gap presentation to the threat workbench. V05 may start on the option-invariant
  contract rules (section C) now; V11 stays blocked on M1.
- Follow-ups for the integrator once answered are listed in section F (ADR-0010 Decisions row,
  `task-series.md`, `job-nodes.proposal.json` `nvd-cpe-matcher-tbd`, identity-schema
  `match_basis` const, `Resolution` blob list, freshness-policy record).

## Checkpoint — 2026-09-20 SCA matcher gates decided

Owner answered M1-M5 of `docs/proposals/vendor-prepass/sca-matcher-options.md`: **M1** pinned syft +
Grype image with the Grype vendor DB mirrored into `/data` (native CPE matcher not adopted; Trivy
considered and not chosen for SCA); **M2** build both the Grype DB mirror publisher and an
independent OSV snapshot publisher before V11; **M3** rule table in the repo, but it has no
consumer under M1 = Grype and is not built now; **M4** no age limit by default, a job may set a
tighter `max_age`, exceeding it is `FAILED` (supersedes V09's `OK_WITH_GAPS`); **M5** matches plus
an aggregated gap summary to the threat workbench. Not done here: ADR-0010 Decisions row, task
series V05/V09/V11 text plus new V16/V17 publisher tasks, `job-nodes.proposal.json`, the
`match_basis` const in the V09 identity schema, and the V09 binding change for M4.

