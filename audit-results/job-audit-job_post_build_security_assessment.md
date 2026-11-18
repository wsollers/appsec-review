# Job 28/47 — job_post_build_security_assessment

## Scope and result

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`, clean before tests and at final verification.
- **Authorized checkout:** `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 on `wsl-ubuntu`; SSH execution and the brief's WSL UNC root only. The default Windows checkout was not audited or tested.
- Editable import: `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Functional implementation audit only: no source/config/environment-file changes, installations, commits, pushes, subagents, real builds, scanners, models, target execution, service operations, or integration/live/Dagster execution.
- **Findings:** 15 findings below: **2 high, 12 medium, 1 low**, including reconfirmed historical issues explicitly attributed below. These are implementation-correctness severities, not target-vulnerability findings.
- **Validation:** 56 passed, 0 failed/skipped, 0 tests over 10 seconds; 7.22 seconds pytest, 16.438 seconds complete wrapper. Two synthetic reproduction batches succeeded in 0.838 and 1.050 seconds; a valid Mach-O follow-up succeeded in 0.003 seconds.
- This audit does **not** certify live output quality or end-to-end publication. Every declared task was traced, but production runner/admission and external-tool behavior were not executed.

## Registration, configuration and contract

`runtime/registry.py:168-169` registers the job with the centrally recorded inference adapter. `job.py:919-936` constructs seven units and attaches the two dataset declarations and typed contract. Its dispatch is `REVIEW_GRAPH`, target access `CHECKOUT`, `always_execute=False`, `propagate_handoff=True` (`datasets.py:102-108`). Runtime enablement is **true**. `orchestration/topology.py:46-80` derives graph edges from schedule and consumes declarations; the actual reduced predecessor is **job_cpp_compiled_analysis**, confirmed programmatically and by the static Dagster-definition unit.

The contract has **34 input requirements from six producers**, all optional/gap/allow-partial by default (`runtime/contracts.py:52-65`):

| Producer | Declared inputs | Actual use in this job |
|---|---|---|
| `job_cpp_compiled_analysis` | envelope; build graph; AST; IR; Infer; symbols; blocked branches; plan/summary; protected case material | `load_accepted_cpp` reads accepted envelope, internal unit-execution result and index manifest. Catalogs, protected/raw commands, outputs and retained binary records are then used. The non-envelope read-accounting defect is F10. |
| `job_language_build` | envelope; topology refinement; native/JVM actions; receipts; workspaces | Conditional accepted envelope/receipt read; successful non-native binary/wheel cases; native catalogs also carry its protected commands and execution references. F06 concerns built-but-partial receipts. |
| `job_build_environment_analysis` | envelope and build environment | Not directly read by the seven handlers; declared availability is not actual consumption. |
| `job_project_build` | envelope; topology; dispatch; workspaces; image streams | Not directly read; some build provenance arrives indirectly in the compiled catalog. |
| `job_target_analysis_plan` | envelope; feedback cache; plan index/documents | Not directly read. |
| `job_target_catalog` | envelope; artifact intake; source/symbol/component/document/build-unit indices; catalog documents | Not directly read. Inherited manifest verification must not be confused with reading their semantic payloads. |

The source fingerprint is explicitly checked against the compiled handoff (`job.py:274-276`). The shared reader verifies the CPP result and manifest identities (`jobs/cpp_index_scopes.py:54-80`). It is nevertheless called unconditionally despite the optional CPP envelope declaration: **known K01 / T-057**, below.

Central configuration (`appsec-review.toml:2367-2407`) supplies job workers 8; step workers 1/6/6/6/2/2/1. There is exactly one task in each step. The five `native_units` handlers iterate sorted cases serially inside their task; the step worker limits do not create per-case parallelism (`job.py:303-315`). `_validate_config:251-269` checks exact step/task order, model keys, Boolean enabled, positive integer token/time limits and retries 0–5. Model identity strings are handed to shared guidance/transport rather than validated by a job-specific provider enum.

Dev model: disabled; `claude-cli`, `claude-haiku-5-5`, medium; 32,000 input/8,000 output tokens; 120 seconds; one retry. Reviewed profile model blocks change provider/model/bounds but do not enable this job's model. Disabling inference is explicitly a named coverage gap, not loss of deterministic results.

## Every step and task

All paths in this table are under `src/appsec_review/jobs/job_post_build_security_assessment/` unless qualified.

| Step.task | Dispatch, input and processing | Output, errors and audit result |
|---|---|---|
| `load.accepted_cpp_build` | `job.py:273-301`; unconditional accepted CPP read, snapshot check, accepted catalog extraction; successful/N/A catalogs retained, blocked catalogs reduced to status/gaps; conditional accepted language receipts and `family_build_cases:157-188`. | Cases, upstream manifest/hash and load gaps. Missing family envelope is a gap. Missing CPP envelope raises (K01). Built/partial family outputs disappear (F06). Payload reads are not observed (F10). |
| `provenance.native_units` | Aggregate `303-315`; native handler `317-487`; family handler `191-241`. Protected compile rows preferred; fallback compile DB and link.txt; normalization, protected raw argv, sanitized argv/environment, execution timing fallback, input/output discovery and hash verification. Wheel extraction is selected by suffix, capped at 256 members and 512 MiB/member. N/A/blocked cases write empty, hash-bound documents. | `build-command-provenance.json`. Missing exact argv, environment, action timing, links and attribution are explicit reasons. Basename joins create false exact attribution (F02); changed catalog outputs are rediscovered (F11); `cc` aliases lose compiler checks (F05). |
| `inspection.native_units` | `job.py:490-540`; reads each retained binary as bytes through `assessment.inspect_binary:597-641`; ELF/PE/COFF/Mach-O/archive/bitcode/link-map readers; optional retained `analysis/binary/records.json` joins by binary SHA, adds pinned-tool identity and bounded defined names. | `binary-inspections.json`; inherits provenance gaps. Missing native nm/readelf observation is a named ELF gap, including family ELF cases. Oversize records break later indexing (F07); Mach-O `.o` dispatch is wrong (F13); ELF table truncation can become false facts without a parser gap (F14). |
| `deterministic.native_units` | `job.py:543-570`; `assessment.py:645-787`, `hardening.py`; GNU/MSVC compile checks, ELF/PE facts, family expectation table, command/binary mismatch and cross-TU checks. Native/mixed captured compiles use flag-driven rules; Go/Rust/.NET have documented tables; unknown families/defaults are N/A rather than PASS. | `deterministic-results.json`, rule version and PASS/FAIL/UNKNOWN/N/A counts. Applicable UNKNOWN adds a gap; FAIL is a judgment, not a tool failure. F01 case-wide flag union, F04 override order, F12 PE32 applicability. |
| `inference.native_units` | `job.py:573-704`; registered `post_build` worker, role/persona/task/procedure and hash-pinned bundle (`guidance/workers.py:37-39,96-180`). Structured actions/artifacts/checks and admitted evidence IDs; all tool/build/path/component allowlists empty. | N/A/no-evidence/over-budget/disabled/no-client zero-call paths are explicit. Shared `Execution` enforces total deadline, request/response sizes, usage and call count; retry policy handles provider/timeout/schema failures and collapses to one attempt under active execution safety. `inference-results.json` records requested identity, request hash, calls and validation counts. F08 error-shaped success; F09 unrelated evidence confirmation. |
| `index.native_units` | `job.py:707-890`; derives per-case fingerprint and immutable SQLite path; reuses existing shard through attestation or indexes actions, compile units, artifacts, archive members, loader dependencies, deterministic and model observations. Producing/source/link/OBSERVED_AT edges use resolved endpoint maps. | `build_security` shard, source artifact references, index identity and union of case gaps. F03 omitted output-sensitive fingerprint inputs, F02 false exact relations, F07 missing `kind`. Scope/producer metadata and evidence-edge limitations are noted under K03. |
| `publication.publish_handoff` | `job.py:892-918`; verifies upstream manifest, removes inherited `build_security`, preserves other index names, appends this attempt's case shards, writes/verifies composed manifest. | `post-build-security-summary.json` and `index_manifest`; summary joins indexed-case gaps only. Load-only gaps survive in the originating unit/canonical job outcomes, not necessarily this summary. Actual accepted handoff is runtime-owned, not created by this closure itself. F15 declaration/schema mismatch. |

### Status, publication and downstream checks

- The job uses legacy string gaps, not `strict_gaps=True`; runtime control validation wraps them as `producer_reported_gap`. No new terminal-status vocabulary was found. `runtime/handoff.py:198-300` owns canonical outcome validation; `runtime/runner.py:683-690` opens the actual unit read/publication scopes.
- A per-case exception escapes the aggregate, failing that task and preventing dependent work; the oversized-artifact failure is therefore not isolated to its case. Existing handler units exercise N/A, blocked, empty, disabled, missing client, input overflow, invalid-response retry, exhausted provider retry and snapshot drift.
- The `build_security` indexed declaration has a unique owner/route. Case JSON globs match actual `.../steps/<stage>/tasks/native_units/p-<hash>/*.json`; the summary glob also matches. However, one schema is incorrectly claimed for heterogeneous case documents (F15). Protected fallback commands and extracted wheel member bytes are outside those JSON globs; the job has no separate declared protected-command/member dataset.
- The only committed post-build JSON Schema located is `docs/schemas/post-build-security-assessment.schema.json`, a closed **summary** schema. The model proposal schema is an identity string; the worker task text is generic and does not spell out an observations response structure (`guidance/workers.py:139-150`). Transport JSON/schema-ID checking is not equivalent to full domain validation (F08).
- `job_codeql_analysis/job.py:1590-1600` optionally composes accepted post-build manifests so later publication preserves these shards.
- Review-data indexing reconciles accepted producer manifests (`job_review_data_indexing/job.py:261-339`) and selects `build_security` for build-provenance products (`indexing/products.py:175-177`). `indexing/links.py:138-153` tries case/hash representation links.
- `RetrievalCore.query_build_security:1609-1681` exposes exact project/root/action/configuration/compile-unit/artifact/producer/shard filters over accepted SQLite data; it does not run binary tools. `query_sanitizer_readiness:2105-2144` also projects mitigation rows.
- `review/lead_families.py:665-682` admits deterministic **FAIL** rows as `post_build_hardening` leads, reports UNKNOWN as a gap, and excludes model-produced observations from that deterministic lead family. This makes false deterministic FAILs materially relevant, without equating a lead to a final vulnerability.
- Explicit consuming contracts were checked for CodeQL, OWASP, security tagging, document analysis, inference review, review package assembly and review-data indexing. Gate/dossier auditing admits the original `build_security` dataset through `jobs/decision_audit_inputs.py:26-66`.
- Relevant completed T-172 improves downstream availability, not correctness of these upstream checks. No final gate, dossier, scoring or report execution was performed.

## Findings

### PBS-F01 — High — Case-wide flags falsely create requested-versus-binary failures

- **Evidence:** `assessment.py:749-770`, especially `all_flags` at 749 and RELRO mismatch at 759-761; contrasting applicability guard at 730-734. Downstream lead admission: `review/lead_families.py:665-682`.
- **Trigger:** one link action requests `-z relro` for artifact A while another artifact is an ordinary ELF object or a differently configured executable.
- **Expected/actual:** only a resolved producing/link chain for an applicable linked output should determine its requested posture. Instead, the union of every case action's flags is applied to every ELF/PE record; `linked_artifact_ids` is ignored. An ELF object with `relro=False` receives `command_binary.relro_mismatch: FAIL`, despite its ordinary `elf.relro` check being N/A.
- **Reproduction:** R3 supplied a linker mapped only to `one` and an unrelated object `two`; the real function produced a FAIL scoped to `two`, citing its hash and `link-one`.
- **Impact:** ordinary hardened multi-artifact builds can produce many false hardening leads; a model can subsequently label those checks CONFIRMED.
- **Confidence:** reproduced. **Correction:** resolve producing action/linked-input closure per artifact and apply linked-output applicability before mismatch evaluation.
- **Overlap:** no exact TODO located; T-172 is downstream exposure, not this correction.

### PBS-F02 — Medium — Basename collisions produce false exact provenance

- **Evidence:** `job.py:466-480`, relation publication `801-806`.
- **Trigger:** compile outputs `one/dup.o` and `two/dup.o`.
- **Expected/actual:** each full output path should bind its own action. The basename dictionary overwrites the first action, linking both artifacts to the second. Relations are subsequently emitted with `exact=True, confidence=1.0`.
- **Reproduction:** R7 real provenance handler yielded linked artifact counts `[0, 2]` for the two actions. The unrelated stale artifact in that fixture prevented the aggregate `relationships_exact` flag from being true; when every artifact has a basename hit, lines 478-480 also allow that stronger incorrect flag.
- **Impact:** wrong compile/source/output chains and output hashes.
- **Confidence:** reproduced. **Correction:** normalize outputs against each working directory/build root; use unique full-path resolution and preserve ambiguity.
- **Overlap:** **reconfirmed** historical `docs/reviews/system-review-2026-11-13.md:1485-1494`, **C08-F07**. No matching TODO entry located.

### PBS-F03 — High — Changed inference results reuse an old shard while advertising new source artifacts

- **Evidence:** `job.py:713-729,872-888`; `assessment.py:830-837`.
- **Trigger:** same command references, binary hashes, tool/model/guidance identity and CPP manifest, but a new model response, retry result, model-enabled state, deterministic/provenance metadata or family input interpretation.
- **Expected/actual:** content-changing stage outputs must invalidate their derived index. The fingerprint omits actual inference/deterministic/provenance/inspection document identities and model enabled/budget settings. Existing SQLite is reused while `source_artifacts` points at this invocation's new documents.
- **Reproduction:** R9 indexed a case, then supplied a new hash-bound inference document with `observation-new`, keeping fingerprint inputs fixed. Second indexing reported reuse and identical SQLite SHA; SQL found **zero** new observation rows, while its returned source-artifact SHA was new.
- **Impact:** accepted retrieval can expose stale claims or gaps while the publication references different current evidence.
- **Confidence:** reproduced. **Correction:** bind actual stage-output/content hashes and all semantic selection inputs into shard identity; immutable attestation alone cannot prove freshness.
- **Overlap:** canonical operations page `docs/operations/job_post_build_security_assessment.md` “Resume and invalidation” already acknowledges this limitation. T-5005 is an analogous **OWASP** identity problem, not this job's fix.

### PBS-F04 — Medium — Flag sets discard override precedence and report disabled protections as PASS

- **Evidence:** `assessment.py:150-158,692-714`.
- **Trigger:** common appended flags such as `-O2 -O0 -D_FORTIFY_SOURCE=2`, or `-fcf-protection=full -fcf-protection=none`.
- **Expected/actual:** effective final settings should decide, or ambiguous/unexpanded settings should be UNKNOWN. Set membership sees any optimization/positive protection and reports FORTIFY and control-flow PASS even after disabling overrides.
- **Reproduction:** R2 normalized this exact argv and got `gnu.fortify=PASS`, `gnu.control_flow=PASS`.
- **Impact:** incorrect deterministic requested posture and cross-TU comparison.
- **Confidence:** reproduced function behavior; no compiler executed. **Correction:** evaluate ordered, compiler-specific option precedence, including macro undefines and response-file uncertainty.
- **Overlap:** no exact TODO located; runtime procedure's “Evidence chain” explicitly asks for override precedence.

### PBS-F05 — Medium — Common compiler aliases are classified unknown and lose all compile checks

- **Evidence:** `assessment.py:114-138,206-209,688-689`.
- **Trigger:** a valid captured/fallback command starting with `cc` (also structurally `c++` or bare `cl`) rather than the narrow recognized executable names.
- **Expected/actual:** actual compiler identity or recognized aliases should preserve compile classification; instead `cc -c x.c -o x.o -fno-stack-protector` becomes unknown, with no compile-unit ID or compile checks.
- **Reproduction:** R1 called real `normalize_action` and `deterministic_checks`: `classification=unknown`, checks `[]`.
- **Impact:** missing insecure-override/stack protection evidence without a corresponding classification coverage gap.
- **Confidence:** reproduced. **Correction:** use accepted toolchain identity, recognize supported aliases/wrappers explicitly, and gap genuinely unresolved compiler identity.
- **Overlap:** no exact TODO located. The existing “all toolchains” test does not cover these aliases; family tests bypass classification by supplying `classification=compiler`.

### PBS-F06 — Medium — Built family outputs with provenance gaps are silently skipped

- **Evidence:** `job.py:166-170,290-298`; intended typed outcome semantics `jobs/build_outcome.py:5-26,87-97`.
- **Trigger:** accepted Go/Rust/other non-native receipt with `build_outcome="built"`, retained permitted binary artifacts and `terminal_status="COMPLETED_WITH_GAPS"`.
- **Expected/actual:** inspect the retained permitted products and preserve their receipt gaps. `family_build_cases` tests exact terminal SUCCEEDED and returns no case, regardless of `build_outcome`; no omission reason is produced.
- **Reproduction:** R11 verified `build_succeeded(receipt) is True` while `family_build_cases` returned `{}` for an existing synthetic ELF.
- **Impact:** omitted hardening coverage, potentially with zero case-count evidence that the build existed.
- **Confidence:** reproduced. **Correction:** use the typed products-exist predicate while retaining all enforcement exclusions and rejected-artifact boundaries.
- **Overlap:** **T-5039**, `docs/TODO.md:3237-3244`, is the same remaining-consumer migration. Its enumerated examples do not name this job.

### PBS-F07 — Medium — Oversize-artifact gap records crash first-time indexing

- **Evidence:** `assessment.py:602-604` returns no `kind`; `job.py:779` unconditionally formats `record['kind']`. Aggregate behavior: `job.py:303-315`.
- **Trigger:** a cataloged artifact over the 512 MiB parser limit. Cataloged artifacts are retained before the separate discovery size filter.
- **Expected/actual:** publish unsupported coverage and continue. Inspection does return a gap, but index construction raises `KeyError('kind')`, failing the entire index task and blocking publication.
- **Reproduction:** R10 lowered only the in-memory parser threshold to four bytes over a tiny synthetic artifact, ran actual inspection/deterministic/inference/index handlers, and received `KeyError: kind`. A changed test manifest digest ensured a prior shard did not mask first publication.
- **Impact:** one large object/library prevents all case shards from being published.
- **Confidence:** reproduced; no large file allocation. **Correction:** give every parser branch a uniform record shape and use defensive indexing for unsupported records.
- **Overlap:** no exact TODO located; the existing bound unit checks only parser format/gaps, not downstream indexing.

### PBS-F08 — Medium — Error-shaped model replies become successful empty assessments

- **Evidence:** `assessment.py:790-799` defaults missing observations to `[]`; `job.py:668-675,692-704`; transport `inference/claude_cli.py:61-62`.
- **Trigger:** provider returns `{"schema":"appsec-review/build-security-inference-proposal/1","error":"unable to assess"}`.
- **Expected/actual:** malformed domain response should be rejected/retried or reported as a gap. Schema-ID matching plus permissive validation accepts it as zero observations, zero rejections and SUCCEEDED.
- **Reproduction:** R6 pure validation and R14 real inference handler with a fake provider: one call despite retries enabled, `terminal_status=SUCCEEDED`, `observations=[]`, `rejections=[]`, `gaps=[]`.
- **Impact:** a failed/nonconforming explanation is silently presented as completed inferential coverage.
- **Confidence:** reproduced. **Correction:** publish and supply a closed response schema, require observations explicitly, reject unknown/error fields and validate claim types rather than coercing them.
- **Overlap:** no exact TODO located. C08-F11 discusses the intended deterministic-label boundary, not acceptance of malformed responses.

### PBS-F09 — Medium — A known but unrelated evidence ID can confirm a different scope's check

- **Evidence:** `assessment.py:804-824`, especially fallback at 816; accepted-ID construction `job.py:652-655`.
- **Trigger:** one deterministic `elf.pie` failure for scope A/hash A, but an observation cites supplied hash B. An explicit A scope does not require evidence overlap.
- **Expected/actual:** evidence must resolve to the selected check/scope. When only one candidate survives, fallback accepts it even without intersection, labels CONFIRMED, drops the scope from the retained observation and keeps only unrelated hash B.
- **Reproduction:** R6 produced `confirmed_count=1` for that exact input.
- **Impact:** confirmation/refutation labels can be attached to evidence that does not establish their referenced fact; indexed evidence links can point to the wrong binary.
- **Confidence:** reproduced. **Correction:** require a subject-bound check/evidence match, including artifact/compile aliases, and retain resolved scope/check identity. This does not require proving arbitrary prose beyond the explicitly bounded validator's remit.
- **Overlap:** no exact TODO located; `test_assessment.py` currently **expects** acceptance of a scoped claim citing unrelated `sha-1`, so a correction must change that assertion.

### PBS-F10 — Medium — Payload reads bypass dataset permission checks and actual-read receipts

- **Evidence:** `jobs/cpp_index_scopes.py:54-80`; `jobs/job_language_build/job.py:136-171`; job-local raw/protected/record reads `job.py:53-59,79-99,344-350,432-443,501-508`; proper boundary `runtime/inputs.py:519-545`.
- **Trigger:** a scope supplies the two accepted envelopes but no permissions for their actual payload datasets.
- **Expected/actual:** payload access should require the relevant typed dataset and hash-bound output reference, recording an actual read. Envelope reading is checked, but internal result/receipt/case-file reads use ordinary filesystem access without `observe_output`.
- **Reproduction:** R12 used a real `input_read_scope`, accepted synthetic CPP/language envelopes and an envelope-only contract. Load read observations named only the two handoffs. Provenance still parsed one real synthetic compile action, with **zero payload reads** and no contract refusal.
- **Impact:** consumption accounting cannot distinguish used case material from unread supply; removing its declared permission does not stop the read.
- **Confidence:** reproduced. **Correction:** bind case/receipt/command/binary records to admitted artifact datasets and invoke the shared payload reader/observation boundary; do not merely add more unused declarations.
- **Overlap:** historical **C08-F09**, `docs/reviews/system-review-2026-11-13.md:1507-1516`, and similar shared-reader gaps in prior CPP/clang/SVF/debug audits. Current envelope scoping works; the old report's suggestion to add a `contract` argument to `accepted_upstream` is not the current API/fix.

### PBS-F11 — Medium — A rejected catalog hash is immediately re-admitted as a discovered artifact

- **Evidence:** `job.py:432-465`: mismatches skipped at 438-440, `known_paths` built only from accepted artifacts at 446, unrestricted re-discovery at 449-465.
- **Trigger:** a cataloged supported binary still exists but its bytes differ from the catalog hash.
- **Expected/actual:** retain a changed-identity gap and exclude that path from evidence unless an explicit new admission permits it. The discovery loop finds the same path, computes its new hash and appends it with `kind="discovered"`.
- **Reproduction:** R8 set the catalog SHA of `stale.o` to a different value; the real handler emitted the mismatch gap **and** the same file in `artifacts` with its current SHA.
- **Impact:** rejected identity becomes input to hardening checks and model context.
- **Confidence:** reproduced job-stage behavior, **not** a demonstrated bypass of full earlier runner admission. **Correction:** track rejected paths independently and exclude them from discovery; changed accepted evidence should use the existing integrity-failure policy.
- **Overlap:** canonical operations “Gaps” acknowledges changed artifacts being omitted, but this second-loop re-admission contradicts that description. No exact TODO located.

### PBS-F12 — Medium — PE32 is incorrectly required to have 64-bit high-entropy VA

- **Evidence:** `assessment.py:738-747`; `.NET` table `hardening.py:112-113` explicitly describes x64.
- **Trigger:** ordinary 32-bit PE, high-entropy flag false.
- **Expected/actual:** high-entropy virtual-address entropy is architecture-inapplicable for PE32. The implementation only special-cases SafeSEH on 64-bit images; PE32 gets applicable `pe.high_entropy_va=FAIL`.
- **Reproduction:** R4 returned FAIL with `applicable=True` for `bits=32`.
- **Impact:** false deterministic hardening lead for an ordinary platform limitation.
- **Confidence:** reproduced. **Correction:** add architecture-aware applicability, including mismatch checks.
- **Overlap:** T-157 concerns declaration/applicability metadata broadly, not this implemented rule. No exact TODO found.

### PBS-F13 — Medium — Valid Mach-O `.o` files take the COFF parser

- **Evidence:** `assessment.py:613-616`; `_coff_object:495-502`.
- **Trigger:** Mach-O object with conventional `.o` suffix.
- **Expected/actual:** magic should select Mach-O before a generic object-suffix fallback. `.o` selects COFF first; its machine check fails, yielding malformed/unknown.
- **Reproduction:** the follow-up wrote the same valid 32-byte x86-64 `MH_OBJECT` header under `unit.o` and `unit.macho`. First returned malformed; second returned Mach-O/object. No compiler or loader was invoked.
- **Impact:** supported Mach-O objects lose metadata and are wrongly recorded as malformed.
- **Confidence:** reproduced with a valid header. **Correction:** prioritize supported format magic over the suffix-based COFF fallback.
- **Overlap:** no exact TODO located. The initial R5 helper had a intentionally malformed trailing command; the follow-up removed that ambiguity and is the decisive reproduction.

### PBS-F14 — Medium — Truncated ELF tables silently become negative protection facts

- **Evidence:** `assessment.py:254-277,350-369`; declared header counts retained despite early loop breaks.
- **Trigger:** ELF header declares program/section tables beyond the available bytes.
- **Expected/actual:** mark malformed or incomplete parsing and leave unavailable protection facts UNKNOWN. Loops break silently; the result retains format ELF and declared counts, returns `relro=False`, and may have no parser gaps.
- **Reproduction:** R15 provided a 64-byte ELF64 header with one PHDR at offset 4096 and one SHDR at 8192. Result: `format=ELF`, both counts 1, `relro=false`, `gaps=[]`.
- **Impact:** failed coverage is converted into a deterministic absence/FAIL rather than an unknown; inspected/truncated telemetry also misses this truncation.
- **Confidence:** reproduced. **Correction:** validate table extents/entry sizes and record exact bounded omission; only infer absence after complete applicable parsing.
- **Overlap:** no exact TODO located. Existing rich ELF32 coverage exercises truncated-loop branches but does not require an omission gap.

### PBS-F15 — Low — Artifact-only dataset claims the summary schema for incompatible documents

- **Evidence:** `datasets.py:17-21`; actual schemas `assessment.py:23-25`, `job.py:525,561,694`; summary schema `docs/schemas/post-build-security-assessment.schema.json:5-15`.
- **Trigger:** normal provenance, inspection, deterministic or inference JSON matches the declaration's per-case glob.
- **Expected/actual:** each declared artifact format should match its promised schema, or an explicit envelope/union should describe the heterogeneous set. All files are declared as post-build **summary** schema.
- **Reproduction:** R13 matched an actual provenance artifact against the production glob, then validated it with the declared Draft 2020-12 schema: seven errors; actual schema was `appsec-review/build-command-provenance/1`.
- **Impact:** misleading dataset inventory and incompatible schema-based consumption/validation. No runtime rejection was claimed: control validation is separate.
- **Confidence:** reproduced declaration/schema mismatch. **Correction:** split schema-correct declarations or define a versioned dataset envelope; retain protected artifacts separately.
- **Overlap:** T-147 is the broader exact task/dataset-binding effort, though its specific documented schema example is artifact security, not this job.

## Known issues and boundaries not promoted to new findings

- **K01 — Medium, exact known T-057:** CPP handoff declared optional but `load_accepted_cpp` always required. `docs/TODO.md:349-354` explicitly requires changing that envelope to REQUIRED/REJECT, without making every per-scope graph dataset mandatory. Reconfirmed statically at this revision; no duplicate TODO requested.
- **K02 — Existing policy/coverage limit:** every family ELF lacks the C++ lane's pinned nm/readelf record and therefore gets a gap (`job.py:501-526`). Historical C08-F08 calls this redundant; the current canonical operations page expressly describes it. This audit does not authorize removing the independent-observation requirement or deleting the model task (historical C08-F11).
- **K03 — Verified metadata/relationship limitations:** binary/model rows hardcode `RelWithDebInfo`; binary rows hardcode producer `job_cpp_compiled_analysis` and native-style build roots, including family cases (`job.py:780-783,858-862`). Action project/configuration can differ from case-based binary scope. `evidence_entities:837-839` maps action IDs and binary hashes, not all compile-unit/artifact IDs accepted by inference. Exact retrieval filters and relation traversal should not be described as subject-complete. The canonical operations page already warns about fixed labels. These additional limits were statically traced, not separately exercised through every downstream query.
- **K04 — Bounds/family completeness not established:** raw DB/link count limits, wheel-member limits and binary parser constants are not central typed policy fields. Some truncation paths record reasons; others do not. No stress allocation, zip-size amplification, complete endian/architecture/target-triple matrix, static-PIE identification, thin-archive dialect, response-file expansion or runtime hardening enforcement was validated. Family tables are keyed by language, not all actual target triples/build modes.
- **K05 — N/A versus summary:** empty/N/A cases may result in empty case shards and publication SUCCEEDED. This is not independently called a defect; canonical originating unit outcomes remain the coverage authority. Load-only gaps are intentionally narrower than final summary gaps.

## Validation commands, results and reproducibility

### Transport and identity

All Linux bodies used this PowerShell transport, preserving quoting:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# exact Linux body below
'@
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Preflight:

```bash
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -c 'import os, appsec_review; from tests.test_000_unit_environment_guard import offending_environment; assert not offending_environment(os.environ), offending_environment(os.environ); print(appsec_review.__file__)'
```

Passed. No production selectors were unset or changed. Per-process test/reproducer umask and in-memory fake policy values did not modify shared environment files.

### Focused units: exact executed command

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 281118 --strict \
  --max-tests 56 --expect-tests 56 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_post_build_security_assessment/test_contract.py \
  tests/unit/job_post_build_security_assessment/test_hardening.py \
  tests/unit/job_post_build_security_assessment/test_assessment.py \
  tests/unit/job_post_build_security_assessment/test_binary_inspection.py \
  tests/unit/job_post_build_security_assessment/test_handlers.py \
  tests/test_family_binary_assessment.py \
  tests/orchestration/dagster/test_post_build_security.py
```

The wrapper used this checkout's `.venv/bin/python`, collected exactly 56 tests, used two workers and reused only its own fresh collection/execution base temp:

`test/tmp/tests-custom-20261118-125618-959950-3130872`

Result: **56 passed, 7.22 s; 0 failed, 0 skipped, 0 tests over 10 s; wrapper exit 0, total 16.437925757 s**. The 56 comprise 55 mapped job cases and one production-environment guard.

Retained evidence (all relative to the authorized checkout):

- `test/tmp/logs/tests-custom-20261118-125618-959950-3130872.log`
- `test/tmp/logs/tests-custom-20261118-125618-959950-3130872.collection.log`
- `test/tmp/tests-custom-20261118-125618-959950-3130872.collection.json`
- `test/tmp/tests-custom-20261118-125618-959950-3130872.junit.xml`
- `test/tmp/tests-custom-20261118-125618-959950-3130872.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-125618-959950-3130872.json`

Safety inspection: the test files use synthetic byte headers, JSON/SQLite/wheel fixtures and fake `ModelResult`/`ProviderError` providers. The static Dagster test constructs definitions but never executes them. Root fixtures prevent report-container execution and use inert image pins; `tests/unit/conftest.py` forbids real engines/providers/network and disables filesystem fsync for unit timing. No integration or live test was selected.

### Synthetic reproduction invocations

Each batch was executed through the above transport as `.venv/bin/python - <<'PY' ... PY`. Each created a fresh UUID path under `test/tmp/` and removed only that directory in `finally`. No standalone script/source/test file was added.

| Invocation | Exact real-function operations/input recipe | Result |
|---|---|---|
| A / R1 | `normalize_action` with `['cc','-c','x.c','-o','x.o','-fno-stack-protector']`, then `deterministic_checks([action],[])` | unknown classification, zero checks |
| A / R2 | Same normalizer with gcc and appended `-O2 -O0 -D_FORTIFY_SOURCE=2 -fcf-protection=full -fcf-protection=none` | FORTIFY and CFI PASS |
| A / R3 | `deterministic_checks([{'classification':'linker','argv':['ld','-pie','-z','relro','-o','one'],'build_action_id':'link-one','linked_artifact_ids':['one']}],[{'format':'ELF','kind':'object','artifact_id':'two','sha256':'2'*64,'hardening':{'pie':None,'relro':False}}])` | unrelated object RELRO mismatch FAIL |
| A / R4 | `deterministic_checks([], [{'format':'PE/COFF','kind':'executable','bits':32,'artifact_id':'pe','sha256':'3'*64,'hardening':{'high_entropy_va':False}}])` | applicable high-entropy FAIL |
| A / R5 | `_write_macho` test byte helper → `inspect_binary(native.o)` | malformed; superseded by valid-header follow-up C |
| A / R6 | `validate_inference({'schema':INFERENCE_PROPOSAL_SCHEMA,'error':'unable to assess'},checks=[],evidence_ids=[])`; then one FAIL check at scope A/evidence hash-A and claim citing supplied hash-B | empty success; unrelated evidence CONFIRMED |
| A / R7–R8 | `_make_ctx`, three `_write_elf64_with_dep(...,executable=False)` fixtures at `one/dup.o`, `two/dup.o`, `stale.o`; `compile_commands.json` has `clang -c a.c -o one/dup.o` and corresponding b/two command. Set stale catalog hash to `'0'*64`. Invoke the real `provenance.native_units` handler with supplied load output. | `[0,2]` linked counts; stale file re-added as discovered |
| A / R9 | Run real inspection, deterministic, disabled inference and index handlers. Replace only returned inference observations/artifact with a new hash-bound `observation-new`, retain model identity; index again. Query SQLite `SELECT COUNT(*) FROM entities WHERE native_id='observation-new'`. | reused identical shard, count 0, new source-artifact SHA advertised |
| A / R10 | `patch.object(assessment,'MAX_BINARY_BYTES',4)` only during real inspection; run deterministic/inference; change synthetic upstream manifest digest to avoid reuse; invoke index. | `KeyError('kind')` |
| B / R11 | Existing tiny ELF in Go receipt with `terminal_status='COMPLETED_WITH_GAPS', build_outcome='built'`; `build_succeeded` and `family_build_cases` | true / empty cases |
| B / R12 | `_publish_cpp_handoff` and `_publish_language_build_handoff` synthetic fixture writers; `replace(ctx,contract=JobContract(inputs=tuple(i for i in CONTRACT.inputs if i.output_kind=='handoff')))`. Invoke actual load/provenance handlers inside `input_read_scope(ctx)`. | only two envelope reads; one actual compile action; zero provenance payload reads |
| B / R13 | Match actual provenance artifact with `compile_glob` over DATASETS; `Draft202012Validator` over committed summary schema | glob matches, seven schema errors |
| B / R14 | Actual inference handler, enabled fixture config, retries 1; fake provider returns `ModelResult({'schema':INFERENCE_PROPOSAL_SCHEMA,'error':'unable to assess'},input_tokens=1,output_tokens=1)` | one call, SUCCEEDED, no observations/rejections/gaps |
| B / R15 | `b'\x7fELF'+bytes([2,1,1,0])+bytes(8)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0,4096,8192,0,64,56,1,64,1,0)` → real `inspect_binary` | ELF, declared counts 1/1, RELRO false, no gaps |
| C | `struct.pack('<IiiIIIII',0xfeedfacf,0x01000007,3,1,0,0,0,0)` saved identically as `unit.o` and `unit.macho`; real `inspect_binary` on each | malformed versus Mach-O/object |

Assertions checked the observed results in both batches. **A: exit 0, 0.838 s. B: exit 0, 1.050 s. C: exit 0, 0.003 s.** The expected schema errors and caught `KeyError` are successful defect reproductions, not pytest failures. The fixture/context helpers are in the fully inspected `tests/unit/job_post_build_security_assessment/test_handlers.py`; no real JobRunner execution was used.

### Audit-only command failures and final verification

- Initial operations-page read exceeded the view tool's 20 KiB limit; the page was then read in complete bounded ranges.
- Navigation searches for guessed `schemas/`, `config/` and `jobs/native_build.py` paths found no such paths. The actual schema was found under `docs/schemas/`; actual producer command publication was inspected in `job_language_build/job.py`.
- One final metadata probe incorrectly accessed `JobConfig.enabled` and exited 1 with `AttributeError`. This was an **auditor probe error**, not a product/test failure. The corrected probe used `runtime.selection.job_is_enabled` and succeeded.
- Final corrected probe read the wrapper report, confirmed 34 inputs, all seven steps, enabled status and the exact predecessor; `git branch --show-current`, `git rev-parse HEAD`, `git status --short`, `git diff --check` returned `main`, required SHA, clean and no whitespace errors. Reproducer directories were absent; the final Mach-O directory was also removed in `finally`. Wrapper test evidence remains under its private `test/tmp` paths.

## Read coverage and remaining gaps

### Read fully

- Shared audit brief; authorized `AGENTS.md`; `.claude/skills/multi-session-coordination/SKILL.md`; development-skill directory inventory.
- All five files in `src/appsec_review/jobs/job_post_build_security_assessment/`.
- Both operations pages: `docs/operations/job_post_build_security_assessment.md`, `docs/operations/post-build-security-assessment.md`.
- `docs/schemas/post-build-security-assessment.schema.json`.
- All seven mapped unit-test files, root `tests/conftest.py`, `tests/unit/conftest.py`, `tests/test_000_unit_environment_guard.py`, `tests/handoff_fixture.py`.
- Runtime guidance as **data**, not instructions: post-build procedure, build-supply-chain persona, `guidance/workers.py` and matching registry records.
- `runtime/consume.py`; `jobs/build_outcome.py`; `jobs/decision_audit_inputs.py`; `inference/request.py`; `inference/execution.py`; `tests/host_pins_support.py`.
- `scripts/run-tests.sh` and `scripts/lib/common.sh`.

### Read relevant ranges / symbols, not whole subsystems

- `appsec-review.toml:2367-2407`; applicable profile blocks; `tests/job-test-map.json:533-549`.
- `cpp_index_scopes.py:1-84`; language reader `job_language_build/job.py:120-177`, protected command/link publication references `1544-1593`; CPP catalog `job_cpp_compiled_analysis/job.py:1130-1165`.
- `native_components.py:133-233`; `tests/capture_fakes.py:33-68`.
- `runtime/contracts.py:25-175`; `runtime/registry.py:63-180`; `orchestration/topology.py:1-160`; Dagster definition construction `adapter.py:394-525`.
- `runtime/inputs.py:293-570`; `runtime/units.py:120-276`; `runtime/handoff.py:35-112,457-530` and outcome-validation references; runner input-read-scope callsite.
- `inference/claude_cli.py:47-116`; `guidance/cards.py:312-414`.
- `retrieval/core.py:1609-1682,2105-2151`; downstream paths listed above.
- `deploy/dagster/bin/ops_tests.py:85-154,331-571`; wrapper callsites.
- Architecture: `docs/architecture/job-interchange.md:89-130`, plus navigation to related input/publication sections.
- TODO registry matched sections, especially T-057, T-113 job paragraph, T-147, T-157, T-164, T-172, T-5005, T-5039. Historical system-review C08-F07–F11; prior CPP/language/cumulative audit report matches. Findings are not asserted new merely because absent from the current TODO index.

### Material unread/unexecuted scope

- Full upstream build/compiler capture implementations, physical images, tool versions/grammar and real binary/model samples; upstream auditors own those jobs.
- Integration JobRunner and live post-build suites were not run. Native managed/publication-scope enforcement, signing, immutable-admission transactions and repair/restart behavior were only traced at necessary boundaries, not end-to-end exercised.
- Full downstream OWASP, inference-package, gate/dossier and final reporting paths were not audited in this job; only their consuming contracts, shard-preservation and relevant lead/query seams were inspected.
- Full parser hostile-input/stress matrix, archive dialects, actual Rust/Go target defaults, PE load-config semantics, Mach-O entitlement/signing semantics and source/runtime exploitability were not verified.
- No blanket assertion that every JSON/control/payload schema was validated. The summary-domain mismatch is independently demonstrated; production handoff control validation remains a separate gate.

**Stop point:** this job only. No remediation performed and no subsequent job started.
