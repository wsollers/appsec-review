# ADR-0019: Threat Workbench Slice 1 And The Privacy Cell (L13)

Status: Accepted 2026-09-29 (the open decisions below are resolved in `DECISION-LOG-2026-09-29.md`; proposed 2026-09-28). Implementation: merged to `main` from
`ws-workbench` (`35fca25`, 2026-09-29); no live run yet.

Builds on: [ADR-0008](ADR-0008-threat-workbench.md) (accepted design), [ADR-0013](ADR-0013-run-to-report-first.md)
(run to report), [ADR-0015](ADR-0015-tool-leads-are-ledger-candidates.md) (supporting-evidence menu,
branch `review-batch`), [ADR-0016](ADR-0016-attack-chain-composition.md) (attack chains, branch
`adr-kill-chains`). L13 is the privacy lane in `docs/architecture/design-v3.md` (section 4 table).

## Context

ADR-0008 was accepted as design only. `03-threat-model-dfd-stride` published the deterministic DFD
and STRIDE core with `attack_trees`, `abuse_scenarios`, `deployment_zones` and `data_classes`
hard-coded empty; the wave runner (T05), join (T07) and validator (T08) did not exist and the
intercom bus (T06) had no caller. L13 (privacy) had no lane.

## Decision

`03-threat-model-dfd-stride` keeps one job, one output contract and the deterministic core as its
substrate, and adds the smallest complete vertical slice of the ADR-0008 workbench
(`appsec-review-process/threat_workbench.py`):

1. **Wave runner.** Each wave is one C01 pool specification (one worker group per selected
   workcell) launched by `pool_launcher` and joined by the C02 `wait_all` rendezvous. Concurrency
   is the job tunable `workbench_concurrent_cells_<budget class>` (Decision 6 defaults 1/2/3).
   Wave 2 reads `wave-1-model.json`, the deterministic join of wave 1; nothing else crosses waves.
2. **Cells** (registry compositions, `candidate_only` ceiling): `pii-user-data-mapper` (L13),
   `deployment-topology-mapper` (trait: deployment files), `abuse-scenario-analyst`,
   `attack-tree-builder`, `supply-chain-specialist` (trait: SBOM/SCA/dependency evidence).
   The `domain-specialist-router` is deterministic Python (trait detection).
3. **Privacy (L13), William's default:** LINDDUN categories (linking, identifying,
   non-repudiation, detecting, data disclosure, unawareness, non-compliance) as a new record family
   `privacy_threats` (`schemas/threat-model-privacy-threat.schema.json`); a PII/data-class inventory
   in `data_classes`; personal-data flows by setting `flows[].data_class_ids`; regulatory mapping
   only as `regulatory_candidate_notes` on a privacy threat, never a verdict (text that states a
   compliance, severity, runtime or remediation conclusion is dropped as a gap).
4. **Persona-facing schema, then derive.** Cells return judgment only
   (`threat-workbench-cell-persona.schema.json`). Python derives every id (content-derived, so tree
   and node ids are stable across replays for ADR-0016), every citation (from the retained
   readable-input index: `target-repository:<path>[:lines]` becomes a `raw` citation at the bound
   snapshot, a menu path becomes the producer's accepted artifact), evidence classes (resolved
   evidence: `STRONG_INFERENCE`; none: `WEAK_INFERENCE` citing the component map), exposure labels
   (always `DECLARED_EXPOSURE`) and DFD cross-references.
5. **Evidence menu.** Cells get `supporting_evidence_menu` when that module is importable
   (review-batch), restricted to 01-/02- producers so the menu can never create a cycle through
   03/06/15; until it merges, the same shape is built from the exact F02 assembly manifest the core
   already binds. Target files are pinned by tunable (`workbench_pin_target_source`) and served
   through the invoker's lookup tools (input_read/grep/jq, evidence_search).
6. **Join and validator.** The join is a pure function of the base model, the retained cell replies
   and the readable-input index; the job's validator replays it byte for byte, re-derives the
   projections (`attack-trees.mmd`, `dfd.mmd`, `ranked-threat-scenarios.json`, the intercom
   transcript, per-cell `cell-result.json`, wave manifests) and runs `validate_overlays` (id
   uniqueness, references to DFD ids, AND/OR/leaf structure, acyclic and reachable trees, cited
   evidence leaves, no `OBSERVED_EXPOSURE`, rescope trigger for a sensitive data class without a
   store). Unresolved ids, unresolvable evidence refs, failed or omitted cells and open intercom
   records become gaps; the join never fails on model output.
7. **Downstream.** `claim_ledger.threat_candidates` also admits abuse scenarios and privacy threats
   (routes keyed by their ids; attack trees are left to ADR-0016 chain composition, which reads them
   from the model). The Dagster op moves to the `persona_llm` pool.

## Deviations from ADR-0008 (for William)

- **A failed cell is a gap, not a FAILED job** (ADR-0013 over ADR-0008's status table). The job
  publishes `OK_WITH_GAPS` with a `failed_workcell` gap.
- **Not built:** wave 3 challenge/refutation cell, wave 4 responses (`wave_4:
  omitted_no_challenges`), the agent/native/mobile/cloud specialists (a trait that selects one
  raises a `trait_without_specialist` rescope trigger and a gap), persona versions of the
  architecture and STRIDE cells (the deterministic core stands in). All appear in `coverage`.
- **M01 gating is not enforced**: the menu offers whatever accepted 02 producers exist.

## Open decisions

1. Accept "failed cell = gap" for the workbench, or restore ADR-0008's FAILED for always-selected cells.
2. Order of the next cells: challenge cell (needs a different model family per ADR-0008) vs native
   parser specialist (every C/C++ target raises the trait trigger today).
3. Should privacy threats and abuse scenarios enter the claim ledger (more 07/08/09 reviewer load)?
4. Synthesis report: add `data_classes`, `privacy_threats`, `deployment_zones` to the report's
   closed `threat_model` section (schema change) so L13 output is visible in the report.
   Implemented on `report-complete` (brief M2): the three families (and attack trees) are carried
   as optional schema keys, summarised in `report.md` (counts and ids only) and rendered as report
   section 3C "Threat model workbench"; pending William's acceptance of this ADR.
5. Engine-scale targets: keep `workbench_pin_target_source` on (pool specs grow with file count) or
   switch to index-only lookup.
