# Simplification S1 cleanup record

Status: bounded S1 cleanup, 2026-10-07.

This record applies the deletion gate in
[`simplification-s0-inventory.md`](simplification-s0-inventory.md). Target repositories, generated
evidence, logs and old prompt text were treated as data. A candidate was removed only when the S0
matrix said **Delete now** or when the prerequisite named by that matrix was satisfied in this
change. Everything else remains until its replacement proof resolves.

## Baseline verification

- Branch: `main`.
- Protected baseline commit: `8e2a184daabea94dc359294a2f635cca7c408d15`.
- Annotated tag: `pre-simplification-2026-10-07`, resolving to the protected commit.
- Starting `HEAD`: `e4fa1b8ef44cf9fc01afe9f4a73b746dc1ee1220`.
- The tracked working tree was clean before the cleanup. Git could not enumerate the
  permission-protected `.pytest_cache/`, as already recorded by S0.

## Removed surfaces

| Surface | Replacement / retention | Deletion proof |
|---|---|---|
| Ignored `appsec-review-process/registry/container-images/*.json` and the now-empty `registry/` directory | Generated B16 records under `appsec-review-process/pipeline/container-images/` | No live reader of the old path; the S0 matrix marked it Delete now. The obsolete ignore rule was removed. |
| Six tracked files under `Claude outputs/` | Git history plus current architecture and continuation documents under `docs/` | No inbound tracked link to any of the six files; the S0 matrix marked them Delete now. Host-local ignored files in that directory were not touched. |
| Superseded continuation prompts dated 2026-10-01 and the completed/rerun prompts dated 2026-10-03 | This record, the new 2026-10-07 continuation prompt, the current operator guide, and the retained hello gap record | The new prompt re-derives live state and the continuation index has no link to a removed prompt. The 2026-10-03 gap punch list remains because it is acceptance evidence. |

## Retained blockers

| Candidate | Why it remains | Proof required before deletion |
|---|---|---|
| Manual lane state and handoff harness (`run_process.py`, `stage_artifacts.py`, `create_handoff.py`, `validate_lane_output.py`, legacy branches of `review_cli.py`, and their templates/status outputs) | Live callers remain in `phase1.py`, `review_cli.py`, OWASP helpers, qualification tools, `orchestrator/stage-run.sh`, current docs, generated catalog/BPMN views, and mixed current-path tests. Removing only entry points would strand run creation and diagnostics while leaving two state authorities. | Remove or migrate every live caller atomically; keep focused intake/workflow and the eight invariant suites green; regenerate graph/catalog views; then produce one clean `hello-autotools` `full_review` report without the manual path. |
| Generic numbered-lane `config.md`, `prompt.md`, `subprompts.md`, and manual-only `process-manifest.json` fields | Generic files and task-specific production prompts coexist in the same lane folders; current readers still derive names and hashes from parts of this tree. Bulk deletion would remove current taxonomies, workcells, and task prompts. | Per-file reader/hash inventory with graph metadata separated from manual prompt metadata, followed by targeted worker and generated-view checks and the hello report proof. |
| Root legacy engagement runners, pregather scripts, `assemble.py`, and the listed transforms | The old runners are still the only callers for several transforms, and field-level parity has not been demonstrated. `extract_component_locations.py` still has unique Syft-location semantics and a focused test. | Map every output field and gap semantic to a run-owned producer, migrate any unique semantics, run touched worker tests, and complete a clean hello report without the chain. Delete `extract_component_locations.py` last. |
| Shared-scratch routing and explicit immutable legacy import | The current code and tests intentionally preserve explicit hashed imports even though implicit shared-scratch discovery is obsolete. There is no owner decision removing historical import as a supported recovery feature. | Separate and delete implicit discovery only; retain explicit immutable import until an owner decision and a hello operator run prove it unnecessary. |
| Run-root compatibility `outputs/<lane>/` | Manual state, handoff, CLI, and validation readers remain. Attempt-local `outputs/` is current and must not be confused with this surface. | Zero run-root compatibility readers plus worker-runtime, evidence-store, publication, report-input, and hello report proofs. |
| Superseded implementation prompts, completed agent briefs, proposal packets, and qualification-era documents | Some are still hashed by `qualify_phase1.py`; several proposal records are read by tests; generated views and ADRs still link to qualification documents. | Remove the qualification consumer, migrate proposal data that is acting as a contract, prove zero runtime/test readers for each packet, and update generated links before moving or deleting it. |
| Compatibility-only tests listed by S0 | Their matching compatibility behaviors remain, so deleting the tests first would erase the only characterization of those surfaces. | Delete each test in the same commit as its behavior, while retaining or replacing coverage for evidence lineage, citation resolution, gap semantics, applicability, immutable attempts/reuse, validation/publication, independent verification, and report rendering. |
| Remaining top-level `scripts/` candidates | The script migration ledger is stale and several scripts remain operator or image/feed qualification tools rather than review logic. | Refresh `docs/architecture/script-migration-inventory.md`; require a caller search and relevant help/smoke proof per file. |

These blockers mean S1's exit condition is not yet met: the repository still contains a tracked
legacy workflow because the S0 replacement gates have not all resolved. Retaining it is deliberate,
not an assertion that it is the preferred operator path.

## Verification

The safe deletion slice completed these checks:

```powershell
python -B appsec-review-process/validate_design_parity.py --check-generated-views
python -B docs/processes/job_catalog.py --check
```

- S0 focused invariants: 12 run, 11 passed, 1 skipped because the pinned Linux ssdeep runtime is not
  present on this Windows host (the same explicit S0 limitation).
- Generated design-parity views: PASS (`91` jobs, `16` capabilities); existing readiness gaps were
  retained rather than reclassified.
- Generated job catalog: PASS.
- Changed-document relative links and references to removed continuation prompts: PASS.
- `git diff --check`: PASS.

Because this slice removes no runtime behavior, no compatibility-only test was deleted.
