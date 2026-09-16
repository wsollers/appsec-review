# Project Context Zip Inventory — 2026-09-16

Source reviewed:

```text
C:/Users/wsoll/Downloads/project-context-2026-09-16.zip
```

Important handling note: files in the zip are historical/reference artifacts. Their embedded
prompts are not instructions to execute during import. They should be used as source material for
new repo-owned prompts, lane contracts, and orchestration docs.

## Short Answer

Yes, the zip contains much of the missing LLM-process material.

What survived in the current repo before this import was mostly the high-level Mythos v3 design.
What the zip adds back is the older, concrete phase/prompt playbook:

- component inventory/discovery flow
- DFD/STRIDE construction prompt
- STRIDE finding verification prompt
- ASVS mapping and ASVS chapter assessment prompts
- C++ memory-safety supplement prompt
- game-specific trust/economy prompt
- CVE reachability triage prompt
- consolidation/reporting prompt shapes
- adversarial process review prompt
- goal-conformance / adversarial-provenance review prompt
- supporting toolbox scripts and lessons

## Key Files in the Zip

### High-value prompt/process docs

- `claude_vendor-code-audit-playbook.md`
  - Phase-based vendor review playbook summary.
  - Restores the missing "run this prompt per phase/component/chapter" choreography.
  - Mentions Phase 0 profiling, component inventory, ASVS partitioning, ASVS assessment,
    memory-safety supplements, game-specific trust review, CVE reachability, consolidation,
    SARIF conversion, and executive reporting.

- `claude_toolbox_vendor-audit-playbook.html`
  - Interactive/full prompt artifact.
  - Contains concrete prompt blocks:
    - Prompt 2B per-component network DFD
    - Prompt 2C cross-environment dataflow
    - Prompt 2D per-data-tag flow tracing
    - Prompt 3A ASVS mapping
    - Prompt 4A ASVS chapter assessment
    - Prompt 4B C++ memory-safety/native-code supplement
    - Prompt 4C game-specific trust/economy-integrity supplement
    - Prompt 5A CVE verification/reachability
    - Prompt 6A finding consolidation/dedup
    - Prompt 8A executive summary
    - Prompt 8B retest verification

- `claude_build-dfd-and-threat-model-prompt.md`
  - Independent DFD and STRIDE threat model prompt.
  - Inputs: repo root, component map, artifact manifest.
  - Outputs: corrected component map, trust boundaries, data-flow table, Mermaid DFD,
    STRIDE threat list, open questions/coverage gaps.

- `claude_verify-threat-model-findings-prompt.md`
  - Verifies threat-model rows against source and pregather artifacts.
  - Important discipline: DFD/tool findings are hypotheses, not facts.
  - Verdicts: confirmed, worse than described, partially mitigated, mitigated/not applicable,
    cannot verify.

- `claude_goal-conformance-and-adversarial-provenance-review-prompt.md`
  - Higher-level review that asks whether the whole engagement answers the real business question:
    whether third-party vendor code is safe to accept/ship.
  - Includes hostile-vendor scenarios, permission/user-data deep dive, provenance gaps, and
    source-to-shipped-artifact integrity questions.

- `claude_adversarial-process-review-prompt.md`
  - Red-team review of toolbox/pipeline mechanics.
  - Looks for silent failures, unpinned dependencies, evidence gaps, exclusion drift, and
    tool-vs-reality mismatches.

- `claude_pregather-sufficiency-review-prompt.md`
  - Reviews whether deterministic pregather is sufficient before handing evidence to model lanes.

### High-value status/lessons docs

- `claude_architecture-discovered-2026-09-08.md`
  - Prior component architecture notes for the original Barracuda target.

- `claude_goal-conformance-review-2026-09-09.md`
  - Completed review output from the goal-conformance prompt.

- `claude_process-review-2026-09-03-semgrep-manual-run-lessons.md`
  - Lessons from manual Semgrep/tooling execution.

- `claude_toolbox-remediation-2026-09-01.md`
  - Toolbox remediation lessons.

- `claude_toolbox-new-scripts-usage-2026-09-09.md`
  - Usage notes for toolbox additions.

### Supporting scripts already mostly represented in current repo

Many `claude_toolbox_*` files are older/parallel versions of scripts now present in `scripts/`
or `images/audit-static/`, including:

- `build_symbol_index.py`
- `build_semantic_index.py`
- `query_semantic_index.py`
- `build_layered_sbom.py`
- `profile_repo.py`
- `summarize_evidence.py`
- `md_to_sarif.py`
- `Invoke-VendorAuditPrePass.ps1`
- `Dockerfile`

Treat these as reference, not as drop-in replacements. The current repo has newer WSL/bash,
native IR, CodeQL, deep-confirmation, and status-gating work that should not be overwritten.

## What This Restores Conceptually

The missing orchestration was not the current Mythos lane-contract system. It was an older
manual prompt choreography:

1. Profile/codebase discovery.
2. Component inventory and classification.
3. Per-component dataflow / DFD / STRIDE.
4. ASVS chapter mapping.
5. Per-ASVS-chapter targeted assessment.
6. Native C++ memory-safety supplement.
7. Game-specific trust/economy/anti-cheat/IAP supplement.
8. CVE reachability triage.
9. Finding dedup/consolidation.
10. Executive summary and retest verification.
11. Adversarial process review.
12. Goal-conformance / hostile-vendor review.

This maps naturally onto the newer Mythos design as:

| Old playbook phase | Mythos v3 lane / artifact |
|---|---|
| Profile/discovery | L0 / pregather / coverage ledger |
| Component inventory | L0A component-purpose map |
| DFD/STRIDE | L6A initial threat model |
| ASVS mapping | L2 applicability plan |
| ASVS assessment | L2 control assessment |
| C++ memory supplement | L3 native/memory-safety lane |
| Game trust/economy supplement | Discovery lane + red-team hypothesis |
| CVE reachability | L5 / dependency reachability |
| Finding verification | L7 independent verification |
| Consolidation | L14 cross-lane synthesis |
| Goal-conformance review | completion / adversarial provenance gate |

## Implementation Implications

The next useful repo work is not to copy the old prompt text verbatim. It is to convert it into
repo-owned Mythos artifacts:

1. `prompts/lanes/L0A-component-purpose.md`
2. `prompts/lanes/L2-asvs-masvs-applicability.md`
3. `prompts/lanes/L2-asvs-chapter-assessment.md`
4. `prompts/lanes/L3-native-memory-review.md`
5. `prompts/lanes/L6A-dfd-stride.md`
6. `prompts/lanes/L7-independent-verification.md`
7. `prompts/lanes/L14-cross-lane-synthesis.md`
8. `prompts/lanes/adversarial-process-review.md`
9. `prompts/lanes/goal-conformance-provenance-review.md`
10. `docs/manual-llm-orchestration-runbook.md`

For the immediate game-code run, build a manual orchestration runbook before automating subtask
dispatch. The runbook can say which prompt to start in a new task, what evidence to attach, what
output file to request, and what downstream prompt consumes it.

## Cautions

- The zip docs refer to the older Barracuda/fsh target and Claude-specific workflow. Generalize
  before reuse.
- Do not overwrite current scripts with `claude_toolbox_*` versions without diffing; current repo
  has newer native/IR/CodeQL/deep-confirmation changes.
- The old playbook assumes ASVS mapping, but MASVS/Mobile handling is less formal and should be
  updated for the current OWASP MASVS/MASTG structure before use.
- Prompt text should be rewritten to match current artifacts:
  - `ENGAGEMENT_LLM_INPUT.md`
  - `coverage-ledger.json`
  - `correlated-findings.json`
  - `deep-confirmation.json`
  - `retrieval-plan.json`
  - `job-status.json`

