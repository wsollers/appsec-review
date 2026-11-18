# Job 42/47 — job_dossier_publication

## Scope and result

- **Source:** clean `main`, **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 via `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. Source reads used the matching UNC checkout. Editable import resolved to this checkout's `src/appsec_review/__init__.py`. HEAD, branch, status and import were rechecked at completion.
- **Four new reproduced functional findings:** DP-01 high; DP-02, DP-03 and DP-04 medium. **RV-F05**, already reported by the remediation-validation auditor, was independently confirmed and is **not counted again**.
- **70 focused units passed in 11.00 s**, wrapper total **20.886030 s**; exact collection 70, two workers, shuffle seed 42, zero failures/skips/tests over 10 s. The four mapped job files account for 66; one additional dossier redesign case and three environment-guard cases account for the rest.
- One sequential offline reproduction batch confirmed four new findings plus RV-F05 in **0.463374 s**, including fixture creation/cleanup after imports.
- No repository source/configuration/environment edits, installs, models/providers, external rendering/compiler/tool execution, target execution, service operations, integration/acceptance/live reviews, commits, pushes or subagents. Pure Python document/string rendering and synthetic files were used; no XeLaTeX/PDF engine ran. Reproduction scratch was removed; wrapper evidence remains in its unique `test/tmp/` namespace.

## Registration, intended contract and settings

`src/appsec_review/runtime/registry.py:110,181` registers the builder. `appsec-review.toml:3806-3834` enables the job and defines exactly three single-worker steps/tasks. The typed settings loader is selected at `src/appsec_review/config/loader.py:1438-1439`.

`src/appsec_review/jobs/job_dossier_publication/datasets.py:23-92` declares review-graph dispatch, accepted-evidence target access, propagating handoffs and `always_execute=False`. Scheduling follows inference review, PoC, planning and validation; dependency reduction yields remediation validation as the immediate predecessor when all are enabled (`orchestration/topology.py:46-80`). The final gate is a **consumer**, not an input. `.settings.enabled` controls graph selection through `runtime/selection.py:11-24`; an explicit direct invocation is not equivalent to enabled graph membership.

Intended population:

1. One protected dossier for each accepted finding whose state is `confirmed`.
2. A separate dossier for every accepted PoC candidate outcome, including unsuccessful/unavailable outcomes and supported findings with an eligible PoC.
3. Exact `(kind, finding_package_id)` partition into items and explicit cap omissions.
4. Preserve accepted evidence, qualification, risk dimensions, remediation and chain context without confirming a supported finding, changing shipment decisions or treating compilation as runtime proof.

The contract contains **74 requirements across 22 producers**:

- Required/reject: `job_inference_security_review/handoff`, envelope `/2`.
- Review payloads: accepted scope, lead triage, review packages/cells, claim ledger, attack chains, scores/findings.
- Protected decision audit: metadata, manifest, decisions, verification coverage, decision bases and continuations, with `WHEN_DECLARED` compatibility rather than permission to read undeclared outputs.
- Optional accepted PoC summary/writer/reproducer records; optional planning summary/proposals; optional validation summary/receipts.
- Original source/index families from `bound_artifacts.source_context_inputs`: target catalog; Tree-sitter; compiled C++; C++ symbols; SVF; code graph; CodeQL; evidence collection; Clang; CPG; CI; artifact security; binary evidence; dependency intelligence; review priority; tagging; review-data indexing.
- `decision_audit_inputs.original_audit_source_inputs` merges original scanner/control permissions, including native advisory observations and post-build security. These are source grants, not claims that every dataset is actually read.

Dev settings: 10,000 packages, 20,000 dossiers, 16 MiB artifact bound, four source excerpts, 24 evidence rows, 1,800 text characters, 40 code lines/4,000 code characters, PDF enabled, pinned `tool-report-latex:1.0.0`, 600-second renderer timeout. Image identity is supplied by host-pin resolution and strictly validated as an immutable SHA-256. `settings.py:26-58` closes the key set, types and ranges and hashes the resolved settings.

## Every declared step/task

| Step / task | Actual dispatch and output | Correctness / coverage |
|---|---|---|
| `load.verify_inputs` | `job.py:139-151`; shared `load_accepted_review(..., include_decision_audit=True)` then `inputs.load_inputs`; writes attempt-owned `inputs.json`. | Verifies review/ledger/package/finding partition and exact bound identities; loads optional engineering summaries; verifies source/chain manifests and audit bundle. Unit fixtures replace the accepted-review input boundary; audit-consumer tests exercise the real protected audit reader. |
| `dossiers.create` | `job.py:153-258`; rehash snapshot, reload audit, sort kind/finding pairs, cap explicitly, bounded excerpt and inert PoC-source reads, attach remediation/chains, `build_dossier`, `render_dossier`, write `dossiers.json`. | All declared work is reached; no model/prompt dispatch. DP-01/02 affect content projection, DP-03/04 affect new Markdown/HTML outputs. PDF success/failure/disabled branches have fake-executor coverage. |
| `acceptance.publish_handoff` | `job.py:260-284`; reverify snapshot and `verify_publication`, compare exact expected pair set and upstream pins, publish summary reference/count/gaps and terminal status. | Duplicate/kind/status/count/file/model/receipt checks exist. Final gate additionally validates finding triples and exact cap population. Schema and deterministic-content checks are narrower than the complete document schema; see limits below. |

Units and dependencies are explicit at `job.py:286-288`. `_validate` rejects central step/task drift. `UnitExecutor` does not run create/publish after a failed prerequisite; exceptions become failed-unit receipts rather than empty-success results. Pools are application for load/create and lifecycle for acceptance (`orchestration/dagster/adapter.py:121,129`). No dossier entry was found in the runtime guidance registry, and the handler has no inference call; no missing task prompt was assumed.

## Input and transformation trace

### Accepted identity and eligibility

- `jobs/accepted_review.py` was read completely. It verifies accepted handoff `/3`, run/schema, scope identity, both package manifests, ledger shard chains and exact reconstructed projection bytes, chain publication/membership, coverage counts, score/finding schemas, duplicate identities, judge correspondence, PoC candidate package/basis agreement, exact confirmed/supported partition and shipment totals. Projected findings retain exact claim/package/content hash and source path.
- `inputs.py:64-123` checks optional producer envelope/summary schema and review/run binding, item/gap counts, duplicate finding outcomes, exact claim/package/hash triples and confirmed-only remediation. PoC status is closed and nonexecution assurance is checked. Remediation artifact schema/run/finding/status/review and assurance agree with its row; nested references are rehashed.
- `inputs.py:145-154` requires accepted validation to name the accepted planning handoff. Chains use the accepted review's manifest rather than discovery. `verify_snapshot:177-193` rehashes recorded references and rechecks accepted handoff selections.
- The runtime route is `indexing.store.accepted_handoff` → `runtime.consume.accepted_upstream`. Inside runtime scope, the typed envelope requirement and admitted digest select the producer; an optional unsupplied producer returns `None`, not a newly discovered later handoff. Snapshot checks inside this scope recheck the pinned selection, not an arbitrary latest pointer.
- Dataset-level read receipt coverage is uneven: audit reads call `observe_output`, source shards call `observe_shard`, but generic `bound_artifacts.read_bound_json` rehashes bytes without recording each payload dataset read. This is prior bounded-reader instrumentation debt, already noted in earlier audits and `docs/architecture/job-input-contracts.md:110-132`; not a new claim that there is no admission/hash checking.

### Protected audit and source evidence

The full `review/decision_audit/reader.py` was read. It binds original accepted review/configuration/scope/ledger/package identities, checks protected operational declarations, uses no-follow bounded file reads, validates canonical manifest/shard/continuation bytes and record budgets, rechecks original claim/cell/proposal/lead memberships and original relation attribution, and verifies recorded independence/own-read evidence. It records actual byte reads. An over-budget or malformed available audit fails rather than yielding partially verified success.

`audit_relation_ids` and `_decision_basis` bind finding/adjudication/path/hash and ledger/review/projection identities. Opposition, qualification and original noncounted reasons remain distinct in the **decision_basis** section. **DP-01 is a later projection defect:** those same additional source excerpts are reused as an invented taint timeline.

`job.py:103-125` selects cited direct/analyst-assessed identities first, then additional audited relations, calls `read_excerpt(context_lines=2)`, checks returned identity and records absent/truncated/capped excerpts. Source retrieval uses the accepted manifest and dataset-owner filter, not a target-tree scan. `retrieval/core.py:710-743` checks source identity/location/hash/UTF-8 and bounds text; source failures return explicit coverage gaps. The dossier replaces their detailed reason with its generic unavailable-identity gap; this loses diagnostic specificity, but is not silently clean coverage.

PoC text is hash-bound and read-only; oversize/non-UTF-8 text becomes an explicit gap. `build_dossier` retains compile-only notices and `runtime_verified=False`. No generated code is linked, loaded or run.

### Rendering, datasets, publication and downstream gate

- `reporting/dossiers.py` constructs a deterministic allowlisted model; canonical row ordering, text/source redaction and primary projection truncations are implemented. Direct and analyst evidence strengths remain distinct in the evidence section. Scores remain separate dimensions.
- `dossier_render.py:214-319` refuses an existing/outside-run output directory, pins three template files, writes bounded JSON/LaTeX/Markdown/HTML, and runs PDF only if commissioned. PDF success requires successful non-timeout/non-OOM/non-size-failure execution and bounded `%PDF-...%%EOF` output; failure never receives a PDF reference.
- Rendering uses immutable configured image identity, network none, read-only input/template mounts, shell escape disabled, bounded resources, and retained execution/log artifacts. The shell entry point and tool manifest were read but **not executed**. Pure string escaping and fake executor tests passed; actual typography/page layout/PDF validity/determinism are not established.
- Ordinary unavailable/failed rendering retains JSON/LaTeX and a named gap; image/configuration/template integrity errors fail. Fresh staging directories alone are cleaned up. There is no dossier-specific semantic cache; generic attempt/input/config/implementation identity governs reuse.
- One `dossier_publications` dataset is protected/sensitive, nonindexed, schema `dossier-publication/1`, and claims all load/dossiers/acceptance trees (`datasets.py:5-11`). Inventory routes expose sanitized metadata, not payload access. **DP-04:** broad path ownership does not create missing per-file publication references.
- `verify_publication` checks summary schema/run/counts, duplicate/unknown pairs, status totals, PDF/status equivalence, artifact hashes and model/receipt identity. It does not re-render JSON into LaTeX/Markdown/HTML, compare all settings/renderer identities, or invoke `finding-dossier.schema.json`.
- `job_final_publication_gate/attachments.py:203-241` reuses the verifier, checks exact expected confirmed/PoC scope and cap partition, validates accepted finding triples and dossier schema identity, binds receipt/files and returns sanitized references. `verify_attachments` additionally checks optional producer schema/upstream/terminal/accounting and its broader nested reference closure.
- Final report reads the gate-certified dossier JSON via `job_final_report_publication/pdf.py:54-80`, and publishes only the certified file map. Its SARIF adapter consumes certified dossier source locations, not a new target scan. No full gate/report integration was executed here.

## Findings

### DP-01 — High — Fallback dossier sections invent taint paths and guard/verification conclusions

- **Evidence:** `src/appsec_review/reporting/dossiers.py:157-226,245-279`; presentation at `:666-714`. Actual claim fields: `review/models.py:297-309`, projected by `review/ledger.py:546-558`; accepted finding projection: `jobs/accepted_review.py:74-112`.
- **Trigger:** a normal accepted finding lacks the optional `taint_path`/`guard_analysis` fields; the actual claim and accepted-finding producer shapes do not supply them. Audited opposing/qualifying relations can add source excerpts.
- **Expected:** display source/evidence locations as unordered context unless an accepted ordered path exists; preserve missing guard/verification facts and original dissent without manufacturing support.
- **Actual:** source excerpts followed by evidence locations become a positional “source → hop → sink” timeline. A counted citation is labelled `verified_unblocked_citation`, an analyst citation `analyst_assessed_nonblocking`, and confirmed/no-missing-predicate state produces a universal guard-failure narrative and `confirmed_independent`. Predicate, relation role and actual recorded verification facts are not the basis of these assertions.
- **R1:** real accepted-audit fixture, real `_excerpts`/`build_dossier`, canned source-reader boundary. The noncounted **dissent** relation's excerpt became **step 1, role `source`**. The supporting evidence list still correctly contained only `support`. Dossier headline reported `confirmed_independent` while its verified audit field `existing_r6_passed.value` was **false**. No target execution or full accepted review was involved.
- The same badge code (`dossiers.py:123-145`) collects `entity_kind` and arbitrary shard IDs as “corroborating scanners”; R1 displayed `["default", "source_file"]`. These are not two independently corroborating scanners.
- **Impact:** developer-facing dossiers assert an ordered exploit path/guard conclusion not present in accepted evidence, including turning counterevidence source into path context. Original finding/ship state is not mutated, but presentation strengthens its meaning.
- **Confidence:** reproduced, with static production shape confirmation. The R6 inconsistency is a synthetic accepted-audit case, not a claim that a current live review emitted that combination.
- **Smallest correction:** consume a typed accepted ordered-path/guard/verification projection, or explicitly show unavailable/unordered context. Keep counterevidence separately qualified; derive scanner attribution only from actual producer identity. Do not infer absent structure from confirmation or citation position.
- **Overlap:** **T-076** already tracks missing finding actionability/source/sink fields; **T-150** delivered preservation of counterevidence; completed **T-176** added these sections. This is new evidence of downstream invention, not a request to invent the missing upstream fields. Broad **T-5078** may overlap, but its host-local run audit files were not available/read.

### DP-02 — Medium — Remediation projection cannot render the actual accepted patch format

- **Evidence:** `src/appsec_review/jobs/job_dossier_publication/job.py:62-80`; `reporting/dossiers.py:336-356,369-376`; actual producer `job_remediation_planning/job.py:123-134`; `docs/schemas/remediation/plan.schema.json:5-25`, `exact-patch.schema.json:4-28`.
- **Trigger:** a valid accepted `proposal_generated` plan containing a bound `patch` reference to `remediation-exact-patch/1`.
- **Expected:** retain a bounded, redacted, provenance-bound representation of the exact accepted edits in the developer remediation section, and label the unvalidated proposal as proposal-only.
- **Actual:** `_remediation` omits `patch` and reads nonexistent `proposed_patch`/`unified_diff` fields instead. Those fields are not allowed by the closed plan schema. `_build_remediation_guide` only looks for those nonexistent strings. Its proposal-only branch also recognizes `planned`/`proposed`, not real `proposal_generated`.
- **R2:** a plan and exact patch both passed the actual remediation schema checker; actual `_remediation` + `build_dossier` returned **`proposed_diff=None`**, **`validation_tier=manual_design_required`**, despite the accepted `proposal_generated` status. The plan reference remains, so an operator can manually open it; the promised inline edit is missing.
- **Impact:** the “Validated Remediation Patch & Verification Checklist” section cannot show any ordinary producer patch, and a proposal without a validation result is mislabelled as needing manual design.
- **Confidence:** reproduced producer/consumer format mismatch. The synthetic patch was schema-valid inert data; applicability to an actual target was neither required nor asserted.
- **Smallest correction:** read the existing hash-bound exact-edit patch with bounded source/provenance, render exact edits or derive a clearly labelled bounded diff, retain truncations, and use the real planning status vocabulary. Do not apply/execute the patch.
- **Overlap:** **T-174/T-176** own the relevant producer/consumer formats. Existing redesign test injects `proposed_patch` directly (`tests/unit/reporting/test_t176_radar_and_dossiers.py:270-274`), bypassing the actual job seam. This finding is distinct from prior **RV-F05**.

### DP-03 — Medium — Markdown dossiers silently drop decision basis, qualifications, risk and provenance

- **Evidence:** `src/appsec_review/reporting/dossier_render.py:39-201`; complete common document projection `reporting/dossiers.py:714-867`.
- **Trigger:** the dossier has a verified decision audit, qualified chain context, separate risk scores or resolving upstream provenance.
- **Expected:** each advertised developer dossier format preserves these limitations/evidence distinctions or explicitly identifies omitted sections.
- **Actual:** the separate Markdown formatter includes classification/timeline, synthesized adjudication, source text, PoC, remediation guide and gap/truncation lists, but never renders `decision_basis`, `chains`, `scores` or `provenance`. It also omits detailed remediation check/status rows. There is no format-omission notice.
- **R3:** the same rich model was rendered by real Python Markdown and HTML functions. Markdown lacked `Protected decision basis`, `dissent`, `UNIQUE_CHAIN_LIMITATION`, risk provider `synthetic-risk`, and `review_handoff`; HTML retained the decision basis, chain qualification and risk provider.
- **Impact:** a developer reading the Markdown loses accepted counterevidence and qualification while still seeing the stronger synthesized headline from DP-01. JSON/HTML/LaTeX retain more complete context.
- **Confidence:** reproduced content omission, not a real external-renderer test.
- **Smallest correction:** generate Markdown from the common renderer-neutral document or add complete parity sections and explicit bounded omission records. Add a rich counterevidence/chain/risk fixture rather than checking only section-key presence/determinism.
- **Overlap:** **T-150/T-176**; no exact earlier per-job finding found. T-5078 overlap remains unconfirmed because its host-local evidence was not read.

### DP-04 — Medium — Newly written Markdown/HTML are absent from publication and gate file bindings

- **Evidence:** `src/appsec_review/reporting/dossier_render.py:225-238,305-319`; `job_dossier_publication/job.py:315-329`; `job_final_publication_gate/attachments.py:223-233`; downstream file listing `job_final_report_publication/render.py:274-277`.
- **Trigger:** every `render_dossier` call writes `dossier.md` and `dossier.html`.
- **Expected:** retain those advertised output formats as immutable hash-bound deliverables through the receipt, publication and final gate, or explicitly treat them as uncertified diagnostic sidecars.
- **Actual:** both files are written, but the renderer returns/binds only `json`, `latex`, `pdf`, and `receipt`; the verifier and final gate require that old exact file-key set. No Markdown/HTML hash is in the rendering receipt or dossier summary. The certified final-report file listing therefore cannot expose them.
- **R4:** real PDF-disabled writer plus real `verify_publication` and gate `_dossiers`: both sidecar files existed, but published files were exactly `["json","latex","pdf","receipt"]`; the gate binding list contained JSON, TeX and receipt only.
- **Impact:** newly generated formats are orphaned from the supported deliverable/reference chain and are not checked by these dossier/gate verifiers. **They remain under a protected dataset path**; this is not a claim of public access or a demonstrated full-runtime custody bypass.
- **Confidence:** reproduced at the rendering/summary/gate seam; no full JobRunner admission or final-report execution claimed.
- **Smallest correction:** version/extend the file-map contracts consistently across renderer, receipt, publication, gate and report; hash and verify all published formats. Preserve historical four-key support explicitly if needed.
- **Overlap:** **T-176** adds the new formats; no exact earlier finding found.

### Prior finding confirmed — RV-F05, medium — Rejected validation is labelled static_checked

`reporting/dossiers.py:324-335,370,805` promotes a row when patch applicability alone passed, even when accepted status is `rejected` and static checks failed. Real `build_dossier` reproduced `validation_tier=static_checked` from that combination. This is the remediation-validation auditor's **RV-F05**, acknowledged by the coordinator during this audit. **Do not add a second cumulative finding.** Overall validation status must remain separate from successful individual check dimensions.

## Documentation and validation limits, not additional functional counts

- T-176 task acceptance claims `/2` dossier schema publication; actual constant is `appsec-review/dossier/1` (`jobs/completion_contracts.py:20`), and `docs/schemas/dossier/finding-dossier.schema.json` accepts `/1` spellings. The schema is exercised in the added redesign unit but is not called by dossier publication; final gate checks the identity string, not all document properties. Treat this as schema/versioning and documentation drift, not proof that all current generated models fail schema.
- T-176's TODO “done” reference points to nonexistent `docs/tasks/2026-11-17-t176-executive-report-dossier-and-12axis-radar.md`; the existing detailed task is `...-t176-expanded-radar-executive-dossier-redesign.md`, which was read.
- The canonical operation page describes JSON/LaTeX/PDF but not the newly written Markdown/HTML. Reconcile it with actual deliverables when fixing DP-03/04.
- Legacy audit absence returns `legacy_unrecorded` with no reads; `inputs.py:165-172` then omits both audit fields, and create omits the decision-basis section. Available/unavailable metadata with reads is handled explicitly. This is narrower than operation prose claiming all audit absence is explicit; existing historical no-audit tests preserve the old output shape.
- Additional presentation helpers use fixed bounds and discard some truncation records (`_safe_str`, `_safe_diff`, fixed timeline/checklist caps); primary `_Projection` cuts are recorded. No additional live failure was asserted for those secondary limits.
- Missing exact task-binding metadata is already **T-147**. Legacy string gaps/`strict_gaps=False` are existing registered debt, not new statuses or evidence of no canonical runtime outcomes.
- `DOSSIER_PUBLICATION_PUBLISHED.dossiers_rendered` counts all emitted items, including `latex_only`/`render_failed`, while separate status counters remain accurate (`job.py:276-281`). Interpret it as attempted/emitted dossiers, not successful PDFs.
- No audit of a malicious custom renderer, actual image/signature enforcement, real source excerpt quality, PDF typography, model competence, target security or live review completeness was performed.

## Validation commands and results

All Linux commands were transported through:

```powershell
$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $b | base64 -d | bash"
```

### Identity/environment and focused tests

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'from tests.test_000_unit_environment_guard import offending_environment; import os; bad=offending_environment(os.environ); print("environment offences:", bad); assert not bad'
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 42 \
  --max-tests 70 --expect-tests 70 --timeout-seconds 300 -- \
  tests/test_000_unit_environment_guard.py \
  tests/test_dossier_publication.py \
  tests/test_dossiers.py \
  tests/unit/job_dossier_publication/test_coverage_edges.py \
  tests/unit/review_decision_audit_consumers/test_dossier.py \
  tests/unit/reporting/test_t176_radar_and_dossiers.py::test_redesigned_dossier_sections_and_deterministic_latex_escaping
```

Environment offences `[]`. **70 collected and passed, 11.00 s pytest, 20.886030142079107 s total wrapper, exit 0.** No failures/errors/skips/over-10-second cases. Wrapper collection took 4.885573 s; supervised execution process took 15.637644 s. Both cleanup records confirmed zero remaining processes.

| File | Cases |
|---|---:|
| `tests/test_000_unit_environment_guard.py` | 3 |
| `tests/test_dossier_publication.py` | 27 |
| `tests/test_dossiers.py` | 23 |
| `tests/unit/job_dossier_publication/test_coverage_edges.py` | 3 |
| `tests/unit/review_decision_audit_consumers/test_dossier.py` | 13 |
| Explicit T-176 dossier case | 1 |

The wrapper executed the exact selectors above using:

```text
/home/wsollers/projects/appsec-review/.venv/bin/python -m pytest
-p ops_test_guard -c /home/wsollers/projects/appsec-review/pyproject.toml
--rootdir=/home/wsollers/projects/appsec-review -o addopts= -q -rfE
--basetemp=test/tmp/tests-custom-20261118-134903-596149-3546347
--junitxml=test/tmp/tests-custom-20261118-134903-596149-3546347.junit.xml
-o junit_family=legacy -n 2 --shuffle-seed=42
```

Its own preliminary collection removed `-n 2` and added `--collect-only`, using the same fresh wrapper-owned namespace sequentially. No separate/shared-default collection was run.

Durable evidence, relative to the authorized checkout:

- `test/tmp/logs/tests-custom-20261118-134903-596149-3546347.log`
- `test/tmp/logs/tests-custom-20261118-134903-596149-3546347.collection.log`
- `test/tmp/tests-custom-20261118-134903-596149-3546347.collection.json`
- `test/tmp/tests-custom-20261118-134903-596149-3546347.junit.xml`
- `test/tmp/tests-custom-20261118-134903-596149-3546347.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-134903-596149-3546347.json`

### Offline reproduction batch

Executed once with the same HEAD/clean checks and `.venv/bin/python -B - <<'PY' ... PY`; no pytest or external subprocess. Unique scratch:
`test/tmp/job-audit-dossier-repro-691d03c052b143e8a1a36200d8409be1`, removed in `finally`.

Reproduction recipes use inspected `tests.dossier_fixture` and `tests.unit.review_decision_audit_consumers.helpers.Fixture`, real projection/read/write/verifier functions, and only a canned `Core.read_excerpt` boundary:

| Probe | Exact critical setup/call | Result |
|---|---|---|
| R1 / DP-01 | `f=Fixture(base/"audit"); audit=f.load(); data=f.dossier()`. `_excerpts(Core(), data["relations"], data["finding"], settings(), audit_relations=audit_relation_ids(audit,data["finding"]))`; Core returns each requested identity with `example/<identity>.c:1` and inert comment text. `build_dossier(**data, excerpts=sources, decision_audit=audit)`. | `entity-dissent` is step 1/source; guard summary says candidate guards did not block the taint path; headline `confirmed_independent`; actual audit R6 false; scanners `default`, `source_file`. |
| R2 / DP-02 | Seed a normal finding; write schema-valid exact patch `files=[{path:"src/synthetic.c",before_sha256:"a"*64,absence_proof:false,edits:[{start:0,end:1,old:"x",new:"y"}]}]`; bind it as plan `patch`; fill required plan fields and verify `SchemaSet(.../remediation).errors("plan", plan)==[]`, likewise `"exact-patch"`. Pass plan row to actual `_remediation`, then `build_dossier`. | Patch hash `7cd3d375aa572a950603de1c0e75a7f90a2406bf88d070e864acad696e031523`; forwarded `patch` absent; guide diff null; tier `manual_design_required`. No patch application/target read. |
| R3 / DP-03 | Build audit fixture dossier with no excerpts, a synthetic accepted-style score provider `synthetic-risk`, and chain qualification `UNIQUE_CHAIN_LIMITATION`; call `render_dossier_markdown` and `render_dossier_html`. | Markdown missing all five markers listed in DP-03; HTML retains decision/dissent/chain/risk content. |
| R4 / DP-04 | `render_dossier(f.root,f.root/"data"/"rendered",rich,settings=settings(render_pdf=False),repository_root=ROOT)`; construct exact one-item summary, run `verify_publication` and `_dossiers(root,summary,findings,[],bindings)`. | Both MD/HTML files exist; returned file keys are JSON/LaTeX/PDF/receipt only; gate binding paths contain no `.md`/`.html`. |
| Prior RV-F05 | `build_dossier(...,remediation=[{stage:"Validation",status:"rejected",checks:{patch_applicability:{status:"passed",reason:"exact edit"},static_checks:{status:"failed",reason:"static policy refused"}}}])`. | Guide tier `static_checked`; duplicate confirmed, not recounted. |

All assertions matched; **0.463374 s**, exit 0, scratch removal confirmed. These probes are not five extra passed pytest cases and do not establish complete accepted-job integration.

### Inspection failures and final cleanliness

An initial Linux search attempted unavailable `rg`; it failed with exit 127. Subsequent searches used the available UNC `rg` tool or SSH `grep`; no package was installed. A Windows-style skill glob returned no matches, so the authorized SSH directory listing supplied the skill inventory. The stale T-176 task link failed to open; the existing alternative named above was read. These were inspection failures, not test failures.

Final `git rev-parse HEAD`, `git branch --show-current`, `git status --short`, ancestor check and editable import all matched the authorized clean source. Repository-root inventory was inspected; unrelated existing ignored files were left untouched. Only this session report was added outside the repository.

## Read inventory and material unread scope

**Read fully:**

- Complete shared audit brief, authorized `AGENTS.md`, coordination skill; canonical development skill inventory.
- All five `.py` files in `jobs/job_dossier_publication/`.
- `reporting/dossiers.py`, `reporting/dossier_render.py`, `reporting/text.py`.
- `jobs/accepted_review.py`, `jobs/bound_artifacts.py`, `jobs/decision_audit_inputs.py`, complete `review/decision_audit/reader.py`, complete `job_final_publication_gate/attachments.py`.
- Canonical job operation page; historical `docs/architecture/dossier-data-inventory.md`; existing T-176 task document; dossier schema and remediation plan/exact-patch/validation/common schemas.
- Four mapped unit files, `tests/dossier_fixture.py`, audit-consumer fixture helper; root/unit conftests and environment guard; shell test wrapper/common script.
- Renderer tool manifest and `render-pdf.sh` as source only.
- Prior remediation-planning and remediation-validation reports, including RV-F05.

**Read selected ranges/searches:**

- Current reporting architecture (through its main accepted-audit/rendering descriptions), input-contract receipt boundary; TODO entries T-076/T-147/T-150/T-174/T-176/T-5078/T-113 and related matches.
- Central TOML, registry/config loader/host-pin hooks, topology and graph selection, Dagster pool map, guidance registry absence and test-map entry.
- Shared completion constants/binding/assurance; claim model and ledger projection; runtime consume/inputs/unit/handoff/publication and shared artifact verification paths.
- Pure LaTeX text/box/table/document rendering, bounded source excerpt reader, final-report bound dossier loader/file listing/SARIF adapter.
- T-176 mixed test module imports and its one selected dossier test; other tests in that module were neither audited nor executed.
- Earlier inference/PoC/cumulative reports searched for overlap; relevant local Git history. Those other jobs were not re-audited.

**Material unread/unexecuted gaps:**

- Complete generic JobRunner/admission/signing/reuse/storage closure and full concurrent-source/pointer invalidation; no admitted full job/gate/report cycle. Unit job fixtures use synthetic accepted-review/core boundaries.
- All original source-index producers, full retrieval/source-resolution/shard machinery, decision-audit codec and schema corpus, inference ledger/adjudication/scoring/chain generation internals. The accepted verifier/reader was read, not the entire upstream implementation.
- Actual run-owned finding/PoC/remediation/PDF artifacts, live developer usefulness or accuracy against target source, PDF page layout/font/output correctness, image availability and real renderer receipts.
- Mapped `tests/integration/job_dossier_publication/test_dossier_review_chain.py` and `tests/integration/test_dossier_live.py`, acceptance/live/Dagster/full-suite tests deliberately not run.
- Full shared HTML/chart/template implementation and non-dossier report/export behavior; only necessary render interfaces and downstream bindings were traced.
- Host-local T-5078 output audit files on HAL5000; overlap beyond their TODO summary is unknown.

**Stop:** this job only. Findings are persistent; no fixes or next-job work were started.
