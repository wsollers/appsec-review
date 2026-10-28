# Evidence completion documentation inventory

Date: 2026-10-28. Phase: initial source inventory and documentation change map.
Inspected source: `5f5548da3d039f73c7d6858d2b28a4593a264efe`; ancestry verified with
`git merge-base --is-ancestor`. No completion implementation commits have been reconciled yet.
The controlling delivery decisions are
[completion design section 11](../architecture/evidence-completion-and-remediation.md#11-parallel-implementation-decisions).
This is a documentation implementation record, not evidence that the planned pipeline runs.

## Delivered inventory

The [dossier data inventory](../architecture/dossier-data-inventory.md) records:

- accepted configuration/guidance/review/package/ledger/evidence/adjudication/independence/score/
  shipment/coverage identities and resolver references;
- all 19 public retrieval tool names, bounded selectors, graph modes, neighborhood families and
  consumer-specific source windows; 17 logical indexes and their shard ownership;
- all 16 allowed precomputed query-set names, the 10 actual producers and 6 pending products;
- all 120 dataset output kinds in the 37 baseline producer declaration modules, separated into
  indexed, artifact-only and protected sensitivity/disposition;
- source/build/document, CodeQL/Clang/AST/IR/CPG/SVF, artifact/dependency/CVE/SBOM,
  CI/IaC/hardening, coverage/profile/history/change/control/tag/prioritization data, and
  compile-only PoC/developer artifacts, with explicit provenance and evidence ceilings.

Sources were inspected as repository implementation, not target/evaluator data.
No target checkout, evaluator ground truth, runtime skill instructions, raw prompt or credential
was loaded for this work. No product/config/schema/test/container/pin files were changed.
No broad `docs-sync` reconciliation was performed and `docs/docs-sync.json` is unchanged.

## Documentation map

| Page | Initial-phase change / later reconciliation |
| --- | --- |
| [Dossier data inventory](../architecture/dossier-data-inventory.md) | New source-verified inputs/query/index/dataset catalog and architecture change map. Later add actual completion producer schemas, outputs, visibility and consumers. |
| [Dossier operations](../operations/dossier-publication.md) | New explicitly proposed operational boundary: membership, pre-gate placement, protected deterministic artifacts, render gaps, assurance and recovery. Later replace proposed settings/commands/receipts only from implemented code. |
| [Completion design](../architecture/evidence-completion-and-remediation.md) | Link inventory/operational boundary; preserve proposed status and existing decisions. Later distinguish implemented slices from remaining design. |
| [Jobs/runtime](../architecture/jobs-and-runtime.md) | Mark pending topology/schema/resume/inventory changes without altering the current 37-job inventory. Later enumerate actual new jobs and dependencies. |
| [PoC operations](../operations/poc-generation.md) | Mark current gate dependency/mutable path as a transition boundary, not the new design. Later update shared verifier, pre-gate binding, immutable attempt paths, handoff/schema, manual admission and settings. |
| [Final report operations](../operations/final-report.md) | Distinguish existing post-gate outcome discovery and stale hardcoded PoC limitation from intended single snapshot. Later document certified attachments/capability accounting, schema and public references. |
| [Inference operations](../operations/inference-security-review.md) | Mark chain producer/ledger stages as pending; preserve single-ledger/nonexecution policy. Later document real composition/challenge bounds, events, manifests and gaps. |
| [Report rendering](../operations/report-rendering.md) | Distinguish broad standalone diagnostic rendering from the narrower protected dossier/public projections. Later document actual job reuse, receipts, sample and failure behavior. |
| [Architecture navigation](../architecture/README.md), [agent navigation](../agent-reader.md) | Link inventory, proposed dossier operations and this record without introducing authority. |
| [Wave1 operations](../operations/wave1-review.md), [inference design](../architecture/inference-security-review.md), [review package contract](../architecture/review-package-contract.md), [red output](../architecture/red-discovery-output.md), [indexing design](../architecture/indexing-and-query-reuse.md) | Integration follow-up: reconcile precise producer placement, package/reference schemas, chain publication, input matrix and availability; do not rewrite unrelated historic design. |

## Unresolved implementation details

The baseline only declares completion schema constants, `FindingBinding` and nonexecution helpers
in `jobs/completion_contracts.py`. Chain composition/ledger events, remediation producers, dossier
job/renderer and their accepted artifacts are not implemented here. Final versions and exact shapes
of review/PoC/gate/report summaries, optional-job admission, frozen snapshot binding, validation
adapters, rendering receipts, settings/defaults, dataset visibility and live PDF sample await
implementation-owner commits.

Important source-verified distinctions for integration:

| Surface | Evidence / implication |
| --- | --- |
| Document-origin findings | `document_issues.verify_document_issue_ledger` rejects published findings/scoring inputs; automatic mapping has no proof reviews. Inference declares only indexing as input. Dossier eligibility must use **accepted confirmed packages**, not label document candidates confirmed or limit dossiers to document-origin claims. |
| Package versions | Pre-adjudication `review_packages.py` uses `review-package/3` / manifest `/2`; inference `review/packages.py` uses package `/6` / manifest `/1`. They are separate surfaces, not interchangeable schema versions. |
| Planned graph/query features | Nine graph modes exist; alias/slice/layout/buffer-bound modes do not. Six query-set names are accepted API vocabulary but `pending_follow_up`. SVF memory and bounded producer flow/CPG rows exist without implying those missing APIs. |
| Publication ordering | PoC currently consumes gate; report separately discovers a gate-bound PoC handoff. Gate hardcodes PoC/chain/remediation absence. Integration must remove the cycle risk and post-gate discovery, not run the gate twice. |
| Protected content | Existing PoC source is declared artifact-only/internal, not automatically public. New developer dossiers are explicitly protected and must exclude secrets/raw prompts/transcripts. Standalone diagnostic interchange is not the dossier allowlist. |
| Assurance | Compile-only PoC, instrumentation and build-checked patches never prove runtime reproduction, passing negative controls, fixed/resolved findings or deployment. |

## Checks and limitations

At source commit `5f5548da3d039f73c7d6858d2b28a4593a264efe`, the standard-library link test
`tests/test_documentation.py::test_current_documentation_local_links_resolve` was invoked with
`runpy` without installing dependencies. **Baseline: exactly two unresolved links**, both in
`docs/architecture/build-environments-and-execution-capture.md`:

```text
../../targets/appsec-multi-vuln/support/project-matrix.json
../../targets/appsec-multi-vuln/README.md
```

They refer to an uninstalled user-owned target, not a documentation regression from this work.
Do not install/edit that target or remove unrelated links to make the check green.
The post-edit link test reports **exactly the same two missing target links and no introduced
failure**. A focused standard-library AST check confirms all 120 dataset output kinds appear in
the correct indexed/artifact-only/protected column across all 37 producer modules. It also checks
the exact 19 public tool names, 17 logical indexes and 16 allowed query-set names against their
source declarations. The six pending query products remain explicitly distinguished from the
ten implemented ones.

`git -c core.whitespace=cr-at-eol diff --check` passes, preserving the already tracked CRLF style
of the two navigation pages rather than treating carriage returns as added trailing whitespace.
The repository root was inspected; this work created no disposable root material and made no
non-documentation changes.
No model, runtime pipeline, build container, target analysis, remediation execution or live PDF
was exercised in this initial documentation phase.
