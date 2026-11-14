---
title: "Effective worker prompt contracts"
kind: "architecture"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_inference_security_review", "job_remediation_planning"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Effective worker prompt contracts

This inventory describes model-worker contracts, distinguishing current dispatch paths from the
explicitly marked dormant build-repair contract; registration alone does not establish dispatch.
The dispatch boundary is `ModelRequest` or `ReviewModelRequest`. Both retain a generated
Capability & Artifact Card in their serialized request; providers use the shared request renderers.
The card is a projection, not a grant, and does not replace output validation.

## Dispatch inventory

When invoked, these contracts receive `pipeline/prompt-fragments/governing-rules.md` through shared
authenticated bundle publication. Viewpoints and procedures are job-selected application inputs, never target
guidance. The same selected content is verified before rendering and pinned under
`data/guidance/<bundle-sha256>/`.

| Worker family / role | Effective viewpoint and task | Response / citation contract | Retrieval and missing evidence |
| --- | --- | --- | --- |
| Review lead: `red_team_analyst` | Routed rich persona and stack; stack, preconditions or failure-mode lead task; generative investigation | `red-compact` expanded and validated as red discovery; cell-local labels or admitted logical identities | Application-mediated cell capability, exact catalog and existing remaining-query/turn fields. Missing predicates produce evidence requests or blocked claims. |
| Review hunt: `hypothesis_hunter` | Routed rich persona/stack; selected variant, sink-up, entry-down, control-gap or persona-sweep task; generative investigation and, for control-gap, effective-control verification | Same compact discovery contract; no acceptance or severity authority | Same scoped cell retrieval. Missing/excluded/failed coverage is not absence of a defect or proof of one. |
| Review challenge: `blue_team_refuter` | Skeptical persona view; control or reachability task; effective-control verification | `blue-compact`, expanded into bounded relations; labels/admitted identities | No other cell's hidden reasoning. A hypothetical guard is not a refutation; name the unresolved predicate. |
| Review verification: `independent_verifier` | Skeptical persona; blind predicate task; predicate verification | `verifier-compact`; per-predicate labels/admitted identities | Neutral condition, not red argument; unresolved evidence remains insufficient. |
| Review judge: `adjudication_judge` | Generalist skeptical view with hand-offs withheld; conflict-resolution task/procedure | `judge-result-compact`, labelled sides A/B and resolvable citations | Application mediates the same bounded evidence tools; no role names or private deliberation are injected into the side comparison. |
| Chain composition / challenge | `attack_chain_analyst`, `blue_team_refuter`, `independent_verifier`; `chain_composer`, `chain_refuter`, `chain_weakest_link_verifier` | Chain-specific schema selected in `jobs/job_inference_security_review/chains.py`; existing accepted claim identities, never newly invented findings | Scoped cell retrieval; missing transition/weakest-link evidence prevents an unsupported chain conclusion. |
| Lead prioritization: `lead_triager` | Lean governing/role/`lead_severity` contract, not a full persona panel | `lead-triage-result`; exact supplied lead ID and that lead's tool-fact ID | No retrieval. Missing basis leaves unresolved priority; this worker does not verify a vulnerability. |
| OWASP: `control_assessor`, `independent_reviewer` | Domain persona, effective controls/false positives and appropriate verification procedure; named proof obligations | `owasp-assessment-turn/1`; **complete typed references**, including original source identity, publication and locator | Application-mediated accepted-component expansion through `EvidenceResolver`; `cannot_verify` for unsupported obligations. The independent reviewer receives no assessor conclusion. |
| Build planning: `build_engineer_{family}` | DevOps persona plus native, Rust, Go, Java, Node, .NET, Python, PHP or Wasm role; `target-analysis-planning` | `target-analysis-proposal/3`; one recipe or abstention per unit. Evidence requests copy exact inventory `path`, `sha256`, `reason` | No direct tools. The existing bounded planning feedback loop reads admitted inventory documents. Omitted inventory and ambiguity require abstention, not guessed layouts. |
| Build repair: `build_engineer_{family}` — dormant helper, not current job dispatch | Same family expertise; `build-image-repair` | `build-image-repair/3`; `reason` grounded in diagnostics and allowed repair options, **no extra citation field** | No direct retrieval. Source-layout, failed prerequisite/capture and ambiguous failures are not proof an image repair is appropriate; `NOT_IMAGE_REPAIRABLE` is supported. |
| Post-build: `build_security_assessor` | Rich build/supply-chain persona, bounded registered responsibility, `post-build-security-assessment` | `build-security-inference-proposal/1`; `evidence_ids` names supplied action, compile-unit, artifact or artifact-hash identities | No retrieval. Explain the requested-setting -> observed compile/link -> actual-artifact chain. Deterministic checks retain authority; failed/missing producers are gaps. |
| Dependency repository: `native_dependency_resolver` | The substantive `dependency_repository_investigator.md`, role, `native_repository_resolution`, `native-dependency-resolution` | `native-dependency-resolution-proposal/1`; exact `allowed_evidence_refs`, allowed repository hosts | No browsing/tools. Plausible repository context is provisional; unsupported identity returns null with zero confidence. |
| Native curation: `native_sbom_investigator` | Substantive `native_dependency_analyst.md`, curation task, `native-sbom-investigation` | `native-component-curation/1`; supplied input candidate IDs and exact supporting paths | No direct tools. Keep physical copies separate and account for selected, rejected and uncertain candidates. |
| Native metadata planning / proposal | Same analyst/role/skill, component-local metadata task; separately pinned plan and proposal schemas | `native-metadata-plan/1` selects supplied catalog paths; `native-metadata-proposal/1` cites `{path,start_line,end_line,quote}` from displayed excerpts | Application reads selected bounded files between stages. An unread path is not release evidence; omit unsupported/conflicting fields, including parent-SDK or ABI versions presented as component releases. |
| PoC writing: `poc_writer` | Role plus `poc-writer`; accepted brief and bounded PoC basis | `poc-writer-answer/1`; exact compact function/negative-control or decline contract | Application `read_source` / `find_declaration`, no direct tools. Query/turn limits and denial recovery are retained. Generated source is not an executed reproduction. |
| Remediation: `remediation_writer` | Bounded correction responsibility, supplied invariant and accepted source/evidence; selected `stateful-invariant-analysis` | Worker-turn containing `PlanAnswer`; `evidence_ids` must be supplied **relation IDs**, not paths | Optional application `SourceReader.retrieve` over admitted source windows. Insufficient evidence or architectural changes require the corresponding explicit non-patch outcome. |
| Remediation review: `remediation_reviewer` | Independent semantic responsibility; planner argument withheld; selected `stateful-invariant-analysis` | Worker-turn containing exact `decision`, `reason`, `evidence_ids`, `residual_concerns`; same relation IDs | Current dispatch is final-only. Analyst assessment and static/compile results are not proof of a runtime fix. |

`api_web` still maps to `network_api_surface`; `deployment_operations` still maps to
`cloud_container_deployment`. Native dependency personas are substantive files despite their
short registry records. Binary-evidence procedures remain conditioned on admitted binary state.
Selected stateful review personas/tasks add the same bounded invariant procedure; see the
[selection matrix](guidance-procedures.md#selection-and-provenance). This does not expand grants
or inject deployment/threat-model artifacts whose producers have not yet supplied them.

`independent_scorer`, `finding_adjudicator`, `completeness_reviewer`, and workbench
`component_classifier`, `applicability_router`, `evidence_verifier`, `result_adjudicator` describe
deterministic responsibilities, not additional model dispatches. `poc_designer` and `poc_verifier`
are registered but not dispatched by the current PoC writer path. No scorer rubric, tools, new
worker pool, or development skill was added.

At source `80e04db89504a4b9f276aa1e336ad703235dd10c`,
[`job_project_build.build_job`](../../src/appsec_review/jobs/job_project_build/job.py#L1179)
accepts an `infer` argument but its registered units do not call `_probe_with_repairs`.
The [active probe handler](../../src/appsec_review/jobs/job_project_build/job.py#L1400)
uses native `_execute_one` or the Unity executor, not `_infer_repair`.
The latter is reached only from the dormant repair helper; the image handler can still reuse an
already accepted repair. Thus the registered `build_repair` worker and its tested request
contract do not demonstrate fresh project-build model dispatch.

## Publication and compatibility

`guidance.compose` owns verification, rendering and immutable `pin_bundle` publication through
the existing shared-storage authentication boundary. Review bundles retain `/3`; lean triage
retains its established version. New specialized and workbench bundles use
`appsec-review/guidance-bundle/4`, whose explicit `selected_sections` must be in the common order
and include governing rules, role and task. Selected procedure text is loaded exclusively through
the registered, job-allowlisted runtime-skill loader. Only selected files affect content hashes.
Build-system/model identity remains pinned where it previously participated.

New publications contain `bundle.json` and verified `prompt.md`. Native curation, plan and
metadata variants snapshot together on first use; changing a repository file during the run does
not replace that snapshot. Republish verifies existing immutable bytes rather than overwriting.
The complete specialized rendered bundle is bounded to 48 KiB.

`load_pinned_prompt` reads common `/1`-`/4`, lean triage and the explicitly recognized historical
native, remediation, dependency, build, post-build and PoC layouts. It verifies their original
hash algorithms and retained bytes, including line endings; it never rewrites them into `/4`.
Legacy audit readability is **not** a claim that old unguided dependency/build publications
retroactively contained governing rules. New dispatch uses newly assembled governed bundles.

## Capability & Artifact Card

The card is generated from the issued capability and/or explicitly admitted request fields.
It contains only the selected worker's datasets, availability, evidence authority, producer and
accepted identities when supplied, scoped references, exact operation schemas, citation contract,
existing limits/remaining fields, and missing/omitted coverage counts. Unknown producer or dataset
identity is explicit `null`, not a fabricated receipt. Source file hashes remain distinct from
dataset acceptance hashes. Review producer lookup is bounded to 64 exact in-scope seed identities,
not an inventory query; unrelated same-index producer details are not copied.

Cards are canonical JSON with their own SHA-256 and a 32 KiB limit. Complete schemas and a
dataset availability row are preserved; excess identity samples are deterministically omitted
and counted. Raw protected artifacts, source bodies, credentials, target guidance, private
outputs and opposing-role reasoning are not card fields. Cards cannot authorize retrieval:
`CellCapability`, accepted-source readers and output validators still decide access and citations.
OWASP's direct workbench tool remains MCP-only, not a cell grant; accepted `control_evidence`
projections remain available through their existing admitted retrieval surface.

The common catalog renderer preserves cell parameter schemas, including locator and `expand`
forms. Existing `remaining_queries`, `remaining_turns`, and `final_required` are copied only from
application turns, not recalculated from a second counter or accepted from worker prose.
Specialized protocol bounds remain those already supplied by the owning job.

## Verification and limits

Unit coverage includes every specialized family/family-specific build role, all registered review
tasks, rich persona migration, selected-only hashes, common rules, immutable legacy reads,
authority/tool/schema rejection, deterministic card bounds, scope denial, missing artifacts and
blinded metadata. Existing output-validator tests remain the authority for good/bad examples:
native curation/metadata, dependency resolution, build repair/planning, post-build evidence,
compact review outputs, PoC and remediation.

The scripted competence harness adds real multi-turn cells, accepted index manifests, scoped
retrieval, paging/truncation, denial recovery, final-turn limits, missing artifacts, wrong
citations, misleading source text, false-positive controls and justified abstention. Scripts
fake only the external model boundary. Passing scripts establish **protocol behavior, not model
quality**. Discovery now includes both hunter and lead-analyst compact expansion and configured
red admission, including the admitted outcome when raw no-claim and blocked entries overlap.
Specialized competence adapters exercise the production planning feedback loop and
remediation accepted-review, scope, source/build readers and final validators. Remediation
experiments cannot substitute an unverified review mapping or a different retrieval manifest.
Their fixture derives finding/adjudication/partition identities by applying production publication
functions to synthetic review inputs rather than assigning a confirmed state directly.
The remediation writer task is assembled
once in `job_remediation_planning.inputs.writer_task`, with a baseline wire-shape compatibility
fixture; its fields and authority did not change.
See [manual evaluation](../operations/guidance-evaluation.md) and the package's
[verification record](../tasks/2026-11-06-worker-prompt-contracts.md).

Manual cross-family integration:

```sh
.venv/bin/python -m pytest tests/integration/test_worker_prompt_contracts.py \
  --basetemp=test/tmp/pkg04-manual-integration -q
```

This suite is written but not run by package 04. It connects accepted producer shards and real
application authorization/retrieval to review, dependency, build and remediation card assembly.
It deliberately does not claim end-to-end build execution or accepted remediation findings.
The acceptance/live entrypoint is also written but not run; no deployment, model call or review
run is an automatic completion gate.
