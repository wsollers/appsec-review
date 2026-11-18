# Job 26/47 — job_binary_evidence_indexing

## Scope and result

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review`, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized Ubuntu-22.04 UNC path. HEAD and tracked cleanliness checked before tests and again at completion; the required ancestor check passed. Import identity was `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read the entire updated audit brief and the authorized checkout's AGENTS/coordination skill. This was one read-only job audit, without subagents, source/environment edits, installs, services, real binary tools, provider/network calls, integration, acceptance, or live execution. The native Windows checkout was not audited.
- **Four reproduced job-local findings:** BE-01/02/04 medium; BE-03 low. **One reproduced known cross-job defect class:** BE-K01, dataset-level read observations. Passing units do not certify live correctness.
- Focused validation: **31 passed, 0 failed/errors/skips, 5.33 s pytest / 11.852 s wrapper**, two workers, shuffled. No test exceeded 10 s. Four synthetic-publication reproductions took **0.358711 s** after imports; the separate receipt reproduction took **0.954395 s**.

## Registration, intended contract, and all tasks

`runtime/registry.py:94,164` registers the builder. `job.py:44-51,426-433` declares all three units; there are no additional tasks, job-local task prompts, model calls, or decompiler invocations. The generated missing task bindings are the already-open **T-147**, not evidence inferred from a missing tool declaration.

The default recipe enables this job by omitting `settings.enabled`; `runtime/selection.py:10-23` defines that behavior. Job/step workers are one (`appsec-review.toml:2309-2335`). Its `JobContract` has review-graph dispatch, `schedule_after=("job_target_catalog",)`, checkout target access, `always_execute=False`, and propagated handoffs (`datasets.py:33-61`). The focused topology tests confirm catalog precedes it and review-data indexing receives it.

| Step / task | Actual handler and dependencies | Processing, result, and verified limits |
|---|---|---|
| `load.accepted_publications` | `build_job.load`, `job.py:373-389`; no unit dependency | Validates seven positive integer settings; follows the admitted intake envelope to hash-verified intake and binary-evidence JSON; splits resolved/unavailable IDs; checks frozen manifest/publication identities and binary hash; re-verifies every resolved publication. Returns frozen IDs/hashes, intake handoff hash, unavailable reasons. Missing/changed references fail rather than publish a successful empty shard. **BE-K01:** payload reads lack dataset observations. |
| `index.binaries` | `build_job.index`, `job.py:391-403`; depends on load | Re-reads pinned intake, compares the resolved-ID set, sorts binary IDs, calls `index_binary` and `_Binary.build`. Imports/thunks → functions/backing → calls → strings/edges. Returns per-binary shard identities, counts, gaps and status; no configured binaries is `NOT_APPLICABLE`, unavailable/gapped binaries `COMPLETED_WITH_GAPS`. **BE-01–04.** |
| `acceptance.publish_handoff` | `build_job.publish`, `job.py:405-424`; depends on load and index | `cpp_index_scopes.publish_scope_indexes:353-392` composes new binary shards and coverage onto the pinned manifest, removes earlier shards from this same job, preserves other producers, verifies the new manifest. Writes `binary-evidence-index-summary.json`, sums seven count fields, publishes its artifact reference plus manifest, item count = functions, gaps/status. **BE-03** propagates the inaccurate relation count. No separate job-specific conservation/output validator. |

The direct `UnitExecutor` executes the declared handlers and dependencies (`runtime/units.py:85-211`). The runtime shared-unit path additionally opens input/publication/admission scopes, validates/reuses or invokes the same handler, and writes result hashes and input-consumption receipts (`runtime/runner.py:675-735`). The direct handler units exercised here are **not** a full execution of that runtime acceptance path.

### Accepted inputs

All five are handoff-channel declarations with producer-evidence authority:

| Producer / output | Schema suffix | Availability / missing policy | Actual use |
|---|---|---|---|
| review intake / `handoff` | `job-handoff/2` | required / reject | `accepted_upstream`; exact admitted digest, decoded run/job envelope; envelope observation. |
| review intake / `review_intake` | `review-intake/1` | optional / gap | Reads published intake JSON by path/hash, checks schema marker. Required by the current reader once invoked. |
| review intake / `binary_evidence` | `binary-evidence-intake/1` | optional / gap | Reads referenced document by path/hash, checks schema and binary-list shape. Actual indexing authority. |
| review intake / `model_preflight` | `model-preflight/1` | optional / gap | Declared, but this job does not read it; do not label it consumed. |
| target catalog / `handoff` | `job-handoff/2` | required / reject | Claim-bound retrieval manifest for composition. Catalog shards are verified/carried, not queried as binary evidence. |

`runtime/consume.py:143-214` enforces envelope permission and pins; moving `latest.json` cannot silently switch an admitted digest. `job.py:65-112` verifies run-owned JSON containment/hash and the external publication's frozen manifest SHA, publication identity, and binary SHA. `binary_decompilation/publication.py:218-259` checks exact dataset set/paths/size/hash and every referenced pseudo-C/P-code file, rejects missing/extra function files, and bounds JSONL lines. The job does **not** reopen/execute the original binary or resolve a new `current.json`; that selection belongs to intake (`job_review_intake/job.py:35-81`).

### Identities, data, bounds, and gaps

- Native function identity = kind + target snapshot + binary SHA + entry address; call-site identity adds caller/site/target; import identity adds library/name; string identity adds address (`job.py:172-180,209-219,224-227,282-283,315`). Binary ID separates physical shard filenames; aliases of identical bytes retain the deliberately shared logical binary/address identity.
- Each native pseudo-C location binds snapshot, binary/address path, exact byte digest/span, line/column span, mapping version and backing (`job.py:237-255`). `retrieval/source_resolution.py:122-164` detaches bytes into a content-addressed shared object, binds run/snapshot/publication/manifest identity in `binary-source-backing/1`, and re-verifies the source on retrieval. It rejects source over 16 MiB.
- Managed routing keeps metadata and names a suitable decompiler, but suppresses native pseudo-C locations; imports/strings never receive locations. `review/evidence.py:208-254` requires a matching binary/function/pseudo-C anchor for citations. This is not original-source equivalence.
- Seven central limits are read, all reject missing/noninteger/bool/nonpositive values: functions 200,000; retained-caller call sites 1,000,000; imports 20,000; strings 200,000; string xrefs 64; string characters 4,096; searchable function-text UTF-8 bytes 65,536. Limits are applied to table prefixes; all five input tables are first loaded fully (`job.py:161`), so output caps are not streaming/memory caps. **T-032** already owns large-binary measurement/tuning.
- Gaps include table caps, pseudo-C truncation, inherited publication gaps/coverage flags, unavailable binaries, managed code, invalid call-site address, unresolved computed/targetless calls, and xref clipping. A maximum-ten-message SQLite coverage summary explicitly reports omitted messages; full gaps remain in the shard identity/results. String clipping is the exception in **BE-04**. Search-text clipping preserves full detached pseudo-C for `read_excerpt`; it should not be confused with source-byte loss.
- Native direct targets missing from the retained function/import set produce unlocated/unlinked metadata; truncation upstream may already explain the loss. No new assertion about live unresolved-call completeness was made.
- `index_binary:332-361` fingerprints snapshot, binary/publication/manifest identities, tool ID/image/Ghidra/export identities, parser/normalizer/mapping versions and **all seven** limits. Publication/pseudo-C verification and normalization happen even when the physical shard exists; `IndexBuilder.build_or_reuse` then re-attests existing bytes. Full repair/re-admission/resume behavior was not executed.
- Job statuses are legal `ProducerStatus` strings. The job remains legacy `strict_gaps=False`; free-text gaps are converted to canonical producer-gap accounting by `runtime/handoff.py:196-255`, not silently treated as proof of complete coverage. The control validator checks status/gap fields, **not** complete binary payload semantics (`interchange.py:521-571`).

### Dataset ownership and downstream retrieval

| Dataset | Declaration / actual publication |
|---|---|
| `binary_functions` | `index`, `retrieval-index/2`, `binary` index and `binary-` prefix; owns native/managed function metadata, call sites, imports, strings, typed relations and coverage shards. |
| `binary_pseudo_c` | `index`, `binary-source-backing/1`, artifact-only `data/binary-evidence/sources/*.json`; bytes themselves are runtime-owned `data/shared/objects/*`. Excerpts require a located accepted entity, not arbitrary payload access. |
| `binary_evidence_summary` | `acceptance`, `binary-evidence-index/1`, artifact-only acceptance-task JSON glob; actual summary and returned result have that marker. Runtime more-specific declarations own status/result/checkpoint receipts. |

The focused inventory test verified no unaccounted job/backing files or claim errors. Runtime claims also own shared objects, manifests and receipts (`indexing/inventory.py:78-165`).

`job_review_data_indexing/job.py:259-278,300-340` reconciles producer-owned accepted shards and detects differing same-producer identities. Its contract includes all three datasets. Binary contracts also appear in inference review, package assembly, security tagging, document analysis and OWASP assessment; those complete consumers were not audited.

`RetrievalCore.find/read_excerpt/trace` (`retrieval/core.py:680-828`) query immutable accepted SQLite, retain identities and gap metadata, re-read the hash-bound source, and bound excerpts/traversal. MCP declares those generic routes (`mcp/schema.py:34-65`). Inference adds the binary capability only for a shard with `producer.binary_id` (`job_inference_security_review/job.py:226-236`), so coverage-only empty shards grant nothing. The registered `binary-evidence` skill is inference-only (`pipeline/guidance/registry.json:709-714`), not loaded by this indexing job.

## Findings

### BE-01 — Medium — Direct external references cannot resolve to their exported imports

- **Evidence:** `containers/tools/ghidra/scripts/AppsecExportProgram.java:447-453,510-519`; `src/appsec_review/jobs/job_binary_evidence_indexing/job.py:209-219,265-271,302-306`.
- **Trigger:** a Ghidra `ExternalReference` call, without an intermediate thunk: exporter writes `to=null`, `resolved_external=true`, `resolved_name=location.getLabel()` (unqualified), while imports carry a separate library and name.
- **Expected:** connect the already-resolved call/caller to the matching import using a stable external identity, preserving ambiguity where libraries contain equal names.
- **Actual:** import map is keyed `library::name`, but `_callee` searches the bare label. Both `CALLS` edges are omitted and an already-resolved call becomes `unresolved_call`.
- **Reproduced:** a normalized, hash-verified publication with `KERNEL32.DLL / CreateFileA` and the actual exporter-shaped bare-label call produced **1 import, 0 CALLS edges**, `COMPLETED_WITH_GAPS`, `fixture: unresolved_call: 0x110`.
- **Impact:** import-caller traversal misses valid external-call evidence, notably the direct external-reference path; synthetic PE tests only change program metadata and reuse qualified ELF-style fake call rows.
- **Confidence:** high, producer/consumer shape disagreement and real Python normalization/index reproduction; real Ghidra not run.
- **Smallest correction:** export/normalize the external library plus symbol identity and use the same key in the consumer; do not resolve an ambiguous bare name to an arbitrary library. Add a focused external-reference fixture.
- **TODO overlap:** T-032's PE/live work is relevant but does not describe/fix this identity mismatch. No exact prior report/TODO found.

### BE-02 — Medium — Pseudo-C call-location matching accepts declarations and string literals

- **Evidence:** `src/appsec_review/jobs/job_binary_evidence_indexing/job.py:134-147,284-296`; `src/appsec_review/retrieval/core.py:707-739`; `src/appsec_review/review/evidence.py:208-224`.
- **Trigger:** a recursive function, or a callee-shaped spelling in a literal/comment. The regular expression scans every line without distinguishing a function declaration/body or code from literal/comment text.
- **Expected:** a call-site anchor points at an actual call expression, or remains unlocated/explicitly uncertain without inventing a non-call anchor.
- **Actual:** recursive `void f(void)` at line 1 and `f();` at line 3 produce an ambiguous location at **line 1**, not the actual call. A literal-only `puts("sink(");` is classified as a **unique** `sink` match.
- **Reproduced:** real indexed recursive call returned anchor `(binary SHA, 0x100, 1, 1)` and `read_excerpt` returned `void f(void)`. Direct `_line_of` literal test returned `(3,15,31,17,False)`.
- **Impact:** a source hash can be entirely correct while the semantic call-to-line mapping is wrong. The `binary_anchor` shape check accepts the wrong line; an ambiguous flag in the recursive case does not repair the anchor.
- **Confidence:** high. This is a mapping correctness defect, not a claim that review has confirmed a false vulnerability.
- **Smallest correction:** bounded lexical matching that excludes comments/literals/declarations, or use producer call-to-text mapping; leave nonunique/unreliable mapping unlocated rather than selecting a declaration. Add recursive and literal/comment cases.
- **TODO overlap:** no exact item found. T-032's lossy decompilation/scale work is not a reason to treat a non-call as a call location.

### BE-03 — Low — Published relation counts exceed the relations actually stored

- **Evidence:** `src/appsec_review/jobs/job_binary_evidence_indexing/job.py:182-185,302-304,359-361,410-418`; `src/appsec_review/retrieval/model.py:220-226`; `src/appsec_review/retrieval/index.py:125-139,156-157,274`.
- **Trigger:** two different call sites in one function target the same callee, an ordinary binary pattern.
- **Expected:** summary `counts.relations` is the actual published edge count; attempted/merged rows, if useful, are separately named.
- **Actual:** every `_relation` invocation increments the count. The builder intentionally merges equal relation IDs; caller→callee identities exclude the payload's `call_site`. The summary never reconciles that deduplication.
- **Reproduced:** two calls yield **reported 6 relations, SQLite 5**, with `relation_duplicates_merged="1"`. Both site-specific edges remain; this finding is incorrect accounting, not loss of the call-site facts.
- **Impact:** summary and independent SQLite/coverage counts disagree and downstream accounting can overstate published graph size.
- **Confidence:** high.
- **Smallest correction:** report unique published relation IDs (including the reuse path), and optionally a separate merged count. Compare against SQLite in a two-calls-one-callee test.
- **Test blind spot:** `tests/unit/job_binary_evidence_indexing/test_handlers.py:463` compares the relation count to itself; the whole-graph test does likewise for the summary.
- **TODO overlap:** none specific found.

### BE-04 — Medium — Truncated string evidence still publishes clean coverage

- **Evidence:** `src/appsec_review/jobs/job_binary_evidence_indexing/job.py:309-327,348-361,399-403`; `containers/tools/ghidra/scripts/AppsecExportProgram.java:585-588`; `appsec-review.toml:2314-2321`.
- **Trigger:** a string exceeds `max_string_chars`, or an upstream string row already has `truncated=true`, with no other gap.
- **Expected:** retained truncation is propagated to the job's named coverage gap/status, consistent with the central config's “each truncation is a named coverage gap” and binary architecture coverage contract.
- **Actual:** only entity payload `truncated` is set; no gap is added. Both shard and job status are based exclusively on the gap list, so clipped string evidence is counted under complete coverage.
- **Reproduced:** `public-SECRETTAIL` limited to six characters indexed as `public`, `truncated=true`, **`SUCCEEDED`, `gaps=[]`, SQLite coverage `complete`**. String entities are navigation-only and have no full-string excerpt route.
- **Impact:** searches for the omitted suffix cannot find that evidence, while job summary/coverage omit the loss. This is not a claim that a truncated string is directly citable.
- **Confidence:** high for behavior; documentation is internally inconsistent: the operations page accurately mentions payload-only clipping, while the central/architecture contract promises named gaps.
- **Smallest correction:** add a binary/address-scoped string-value truncation gap for either upstream or index clipping; retain the payload flag and distinguish this from row-count/xref truncation.
- **TODO overlap:** T-032 tunes bounds but does not track this omitted gap. No exact prior report found.

## Existing overlaps and limitations (not additional new findings)

### BE-K01 — Medium, known cross-job class — Intake payload reads are not observed by dataset

`job.py:65-93` calls `accepted_upstream` then reads `review_intake` and `binary_evidence` using `Path.read_text`; neither read calls `runtime.inputs.observe_output`. `runtime/inputs.py:453-470` records the envelope only; `:528-551` is the dataset membership/schema/authority/observation boundary omitted here.

The real reader was rerun under `input_read_scope` with a typed contract containing **only the intake handoff**. It read both payload documents successfully, preserved the pinned hash, and reported only `[("job_review_intake","handoff")]`. Thus actual payload reads can appear supplied-but-unread, and removing their individual permission does not stop that read. This does **not** mean the files were unhashed or the envelope unpinned.

This extends **CC-07**, the planner/project-build/tree-sitter and debug-symbol reports' known reader-observation class; coordinate a reader fix rather than count every manifestation as a wholly new issue. Relevant broader notes are T-113; T-147 is documentation/task binding and does not supply receipts. T-054 is **already done** and the required catalog input is present; do not reopen its resolved undeclared-envelope defect.

Other explicitly bounded observations:

- **T-032:** real PE/PDB verification, managed decompiler lanes, binary-only targets, large-binary memory/runtime tuning remain deferred. No such execution was authorized here.
- **T-147:** exact deterministic task bindings remain undeclared. This source trace found no model/tool execution in the job itself.
- Function/search-text clipping is not source clipping: full pseudo-C backing remains. Generic settings are not a closed job-specific typed settings dataclass; unknown extra keys are not rejected by `_settings`. No speculative new setting was introduced or tested.
- All publication tables are loaded before output bounds; no large or malformed-publication stress test, race test, or memory measurement was run.
- Job-specific JSON schema markers and location constructors are checked, but the job supplies no closed full-payload/output conservation validator. Full runner schema/admission/custody enforcement was read only at the relevant seams, not certified end to end.
- `docs/architecture/binary-decompilation.md` still describes whole-graph index/citation coverage under `tests/test_binary_evidence_indexing.py`; those cases now live in the integration file. The generated job test map and operations page identify the tiers correctly. No integration case was executed.

## Validation commands and evidence

All Linux commands used the brief's PowerShell base64 transport:

```powershell
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
  "printf %s $encoded | base64 -d | bash"
```

The initial direct-quoted SSH identity command failed with bash syntax error at `print(appsec_review.__file__)`, exit 2; **no tests ran**. Retrying with the supplied base64 transport succeeded. No install or environment repair was needed.

Identity preflight:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
git rev-parse HEAD
git status --short
git branch --show-current
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Explicit collection:

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-binary-26-collect-20261118T1305 \
  tests/unit/job_binary_evidence_indexing/test_contract.py \
  tests/unit/job_binary_evidence_indexing/test_handlers.py \
  tests/test_binary_evidence_indexing.py
```

**31 collected in 0.78 s**, exit 0. The first two files are under the enforced unit-tier guards. Before execution, all three test files, fake Docker/export helper and applicable fixtures were read. Every `decompile_binary` call in these tests injects `FakeDocker`; catalog image inspection/run/kill requests are handled by that fake. Signing uses the unit accepting-verifier fixture; no real verifier process/decompiler is required. The tests create synthetic input/publication files only in pytest scratch.

Execution:

```bash
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 261118 \
  --max-tests 31 --expect-tests 31 --timeout-seconds 120 -- \
  tests/unit/job_binary_evidence_indexing/test_contract.py \
  tests/unit/job_binary_evidence_indexing/test_handlers.py \
  tests/test_binary_evidence_indexing.py
```

The wrapper owned fresh `test/tmp/tests-custom-20261118-125124-767511-3086130`; its serial collection/execution reuse was private to this invocation. Exact selector/count proofs passed for both workers. Results: **31 passed in 5.33 s; no failures/errors/skips, no tests >10 s**. Wrapper total **11.851653537 s**, collection supervisor **2.067486 s**, execution supervisor **9.435049 s**; owned-process cleanup confirmed.

Retained evidence relative to the WSL checkout:

- `test/tmp/logs/tests-custom-20261118-125124-767511-3086130.log`
- `test/tmp/logs/tests-custom-20261118-125124-767511-3086130.collection.log`
- `test/tmp/tests-custom-20261118-125124-767511-3086130.collection.json`
- `test/tmp/tests-custom-20261118-125124-767511-3086130.junit.xml`
- `test/tmp/tests-custom-20261118-125124-767511-3086130.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-125124-767511-3086130.json`

### Bounded reproduction commands

Executed once through `.venv/bin/python - <<'PY'` after `cd` and exact-HEAD check. No binary/decompiler/provider call was used. R1–R4 constructed two-function synthetic exports using `tests.binary_decompilation_fakes.write_export`, replaced only the scratch JSONL data, then invoked the **real** `publish_export → verified_publication → index_binary → IndexBuilder → RetrievalCore` path. Each case used a separate child of `test/tmp/job-audit-binary-26-repros-20261118`, snapshot `b*64`, synthetic binary SHA `a*64`, per-case publication identity `sha256(case_name)`, matching manifest/table hashes, and a private `runs/2026-11-18-0026`.

Exact material inputs/queries:

```python
# Common limits, passed to real index_binary:
limits = dict(max_functions_per_binary=20, max_call_sites_per_binary=20,
              max_imports_per_binary=20, max_strings_per_binary=20,
              max_string_xrefs=20, max_entity_text_bytes=65536,
              max_string_chars=4096)
# Common functions: 0x100 f, 0x200 sink; decompile_status="ok".
# P-code, exports, gaps empty; pseudo-C for sink is "void sink(void) {}\n".
# publish_export is given binary/manifest identity, synthetic tool metadata,
# request authorization="synthetic test", and no execution callback.

# R1:
text = "void f(void)\n{\n  CreateFileA();\n}\n"
imports = [dict(library="KERNEL32.DLL", name="CreateFileA",
                kind="function", thunks=[])]
calls = [dict(from_function="0x100", call_site="0x110", to=None,
              to_name="CreateFileA", resolved_name="CreateFileA",
              resolved_external=True, kind="call", computed=True)]
# Query SELECT count(*) FROM relations WHERE kind='CALLS'.
# => 0; imports=1; gaps=["fixture: unresolved_call: 0x110"].

# R2:
text = "void f(void)\n{\n  f();\n}\n"
calls = [dict(from_function="0x100", call_site="0x110", to="0x100",
              to_name="f", resolved_name="f", resolved_external=False,
              kind="call", computed=False)]
# core.find(kind="binary_call_site", indexes=("binary",)) -> site
# binary_anchor(site) => (a*64, "0x100", 1, 1)
# core.read_excerpt(identity=site["identity"], context_lines=0)
# => "void f(void)"; line_match="ambiguous", actual call line=3.
_line_of('void f(void)\n{\n  puts("sink(");\n}\n', "sink")
# => (3, 15, 31, 17, False)

# R3:
text = "void f(void)\n{\n  sink();\n  sink();\n}\n"
calls = [dict(from_function="0x100", call_site=site, to="0x200",
              to_name="sink", resolved_name="sink", resolved_external=False,
              kind="call", computed=False) for site in ("0x110", "0x120")]
# result["counts"]["relations"] => 6
# SELECT count(*) FROM relations => 5
# metadata.relation_duplicates_merged => "1"

# R4:
text = "void f(void) {}\n"
strings = [dict(address="0x300", value="public-SECRETTAIL", length=17,
                truncated=False, xrefs=[], xrefs_truncated=False)]
# Override max_string_chars=6.
# real result => SUCCEEDED, gaps=[]
# core.find(kind="binary_string", indexes=("binary",))
# => payload.value="public", payload.truncated=True
# SELECT area,status,gap FROM coverage => ("binary:fixture","complete",None)
```

All four returned successfully; measured normalization/index/query time after imports was **0.358711 s**. These are observed counterexamples, not four added/passing pytest cases.

Separate BE-K01 command body:

```python
from pathlib import Path
from types import SimpleNamespace
from dataclasses import replace
from appsec_review.jobs.job_binary_evidence_indexing.job import (
    accepted_binary_evidence, INTAKE_SCHEMA, JOB_ID)
from appsec_review.jobs.job_binary_evidence_indexing.datasets import CONTRACT
from appsec_review.runtime.inputs import input_read_scope
from tests.unit.job_binary_evidence_indexing.test_handlers import _write_intake_handoff

root = Path("test/tmp/job-audit-binary-26-receipts-20261118").resolve()
root.mkdir(parents=True, exist_ok=False)
doc = dict(schema=INTAKE_SCHEMA, data_dir=str(root/"data"), binaries=[])
sha = _write_intake_handoff(root, doc)
contract = replace(CONTRACT, inputs=tuple(
    item for item in CONTRACT.inputs
    if item.producer == "job_review_intake" and item.output_kind == "handoff"))
context = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id=JOB_ID),
                          upstream_handoffs={"job_review_intake": sha}, contract=contract)
with input_read_scope(context) as reads:
    loaded, loaded_sha = accepted_binary_evidence(root)
# loaded == doc, loaded_sha == sha
# reads.document()["reads"] contains only job_review_intake/handoff.
```

Exit 0; **0.954395 s** after imports. Narrowing the in-memory test contract does not edit the repository/environment. The report preserves inputs/results; disposable reproduction trees were removed after inspection. Wrapper evidence remains.

## Read coverage and unverified scope

**Read fully:** audit brief; authorized AGENTS and coordination skill; job operations page; binary-decompilation architecture; all three job source files; all three mapped unit files; the six-case integration file (read only); `binary_decompilation/publication.py`; binary export/Docker fakes; handoff fixture; root and unit conftest; unit environment guard; runtime selection and job model; runtime input consumption through `accepted_upstream`; binary runtime skill; run-tests shell/common wrapper; own wrapper JSON report.

**Read relevant ranges, not whole systems:** central job configuration; config parsing/binary bounds; source-resolution binary branch; retrieval index builder/identity/deduplication; retrieval manifest resolver/find/excerpt/trace; evidence anchor/citation resolver; runtime input admission/read records and observers; shared runner unit execution; unit executor; interchange statuses/gap validation; handoff outcome construction; dataset declarations/ownership and inventory runtime claims; scope publisher; intake binary resolver; binary pre-run runner through execution setup; Ghidra call/import/string exporter sections; downstream review-data reconciliation and inference capability selection; MCP route schemas; registry/topology/input matrix/guidance registry; architecture interchange/retrieval sections; TODO entries T-032/T-054/T-113/T-128/T-147 and targeted keyword searches; cumulative/prior reports' overlaps. Local branch/log/pickaxe reads showed existing binary wiring, T-054, reuse and T-113 history; no fetch/integration action.

**Material unread/unexecuted:** full decompiler implementation/API semantics, real native/PE/Mach-O/managed outputs, full binary manifest JSON Schema beyond the Python verifier, complete storage signing/admission/repair internals, all consumer handlers/capability enforcement, live citation effectiveness, complete final report/package generation, scale/resource usage, concurrent publication mutation, and full runtime acceptance/resume. No target-owned code, production run payload or answer key was executed/read for result steering. An incidental initial filename search returned run-file names only; those run documents were not inspected.

Final HEAD remained the exact required commit and `git status --short` was empty. Root hygiene was inspected; pre-existing root files were untouched. No code/TODO/commit/push changes. **Stopped after this one job.**
