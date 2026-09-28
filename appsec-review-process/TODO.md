# AppSec Review TODO: run four targets through to a report

Approach: [ADR-0013](../docs/decisions/ADR-0013-run-to-report-first.md). Run `full_review`, fix the
first thing that breaks, re-run, until the target produces its report. Breakage is expected. Process
hardening (qualification rituals, recovery proofs, batch protocol) is out of scope.

The earlier batch backlog and phase plan were removed on 2026-09-27; see git history at `2e98423a`.

## Targets, in order

| # | Target | Source | Pinned commit | What it exercises | Status |
|---|---|---|---|---|---|
| 1 | `hello-autotools` | `github.com/wsollers/hello-autotools` | `632522b` | C/autotools, vendored cJSON, Dockerfile; known answer key on branch `with-vulnerabilities-doc` | NEXT |
| 2 | `appsec-multi-vuln` | `github.com/wsollers/appsec-multi-vuln` | `878d5d6` | C++, C#, Go, Java, JS/TS, PHP, PowerShell, Rust, Bash and six Dockerfiles; answer key in private `appsec-multi-vuln-guide` | TODO |
| 3 | `freeciv21` | `github.com/longturn/freeciv21` | `0ce1c60` | Large CMake/Qt C++ codebase, many build dependencies | TODO |
| 4 | `doom3-bfg` | `github.com/id-Software/DOOM-3-BFG` | `1caba19` | Large Windows-oriented C++ (MSVC/clang-cl, ADR-0003); a Linux build is expected to fail and appear as gaps | TODO |

`fixtures/populate-targets.sh <name>` clones each target at its pinned commit into
`fixtures/targets/<name>`.

A target is **done** when `full_review` publishes its synthesis report. Build failures, unsupported
languages and tools that did not run appear as gaps inside the report; they do not block it.

## Before the first run

`orchestrator/prepare-host.sh` does every host prerequisite and is safe to re-run;
`--check` reports what is missing without changing anything, `--buildenvs` also builds the
per-language build images (expected for appsec-multi-vuln). It covers: offline Grype/OSV snapshots
within the 14-day ceiling (already registered on zarathustra 2026-09-27), the Dagster stack, the
images the B13 registry needs (on zarathustra: `audit-report`, `tool-osv-scanner`,
`tool-microsoft-sbom-tool`, `tool-sbomasm` were missing), B16 registry records, the code location
(started in the background, log `orchestrator/dagster/.host/code-location.log`), the four target
clones and a Claude CLI probe. Machine layouts (zarathustra, hal5000 WSL and Windows) and the
host-local state each one keeps: `docs/processes/host-layouts.md`.

## Running a target

`orchestrator/stage-run.sh <target>` creates and stages the run (the steps in
`docs/report-path/happy-path-operator-guide.md`, with `--max-database-age-seconds 1209600`) and prints
the run id; then:

```bash
python3 appsec-review-process/launch_job.py --run-id "$RUN_ID" --job full_review --wait
```

`python3 orchestrator/run-status.py <run-id> [--failed]` lists every job's latest status and cause.
When Dagster reports FAILURE but no job shows FAILED/BLOCKED, `python3 orchestrator/dagster-failures.py
orchestrator/dagster/.host/launch-<run-id>.log` prints each failed step's underlying error.

Work the frontier one job at a time: when a job fails, fix it and re-launch; accepted upstream jobs are reused. When every job has been accepted once, run one clean `full_review` from a fresh run to confirm a single pass.

When a run stops: read the failing op's status/result in `runs/$RUN_ID/data/jobs/<job>/`, fix the
cause, `code-location.sh reload`, and re-launch the same run (accepted upstream attempts are reused).
Start a fresh run only when the fix changes what an upstream job would have produced.

Build units install into disposable copy-on-write layers over our sealed buildenv images
(`cow_install.py`). When a run is finished, remove its layers with
`python3 -B appsec-review-process/cow_install.py "$RUN_ID"` (`--all` for every run, `--dry-run` to
list). Sealed images carry no disposable label and are never removed.

For `hello-autotools`, the test step needs `python3 -B appsec-review-process/test_evidence.py
stage-control "$RUN_ID"` once the native build is accepted (see the operator guide).

## Target notes

- **appsec-multi-vuln.** OSV has only the npm ecosystem registered; other ecosystems (Go, Maven,
  crates.io, NuGet, Packagist, PyPI) need their own snapshots for OSV matching, otherwise they are OSV
  gaps (Grype still matches them). Score the report against `appsec-multi-vuln-guide` afterwards.
- **freeciv21.** Expect the build-plan and build-resolution steps to need Qt and many system
  packages; long runtimes for native analysis, Joern and search indexing.
- **doom3-bfg.** Upstream builds on Windows only. Expect build-resolution/native-build gaps on Linux;
  source SAST, secrets, search and the persona review lanes should still run from source.

## Follow-ups (after hello-autotools reaches a report)

- [ ] **Source SAST Semgrep rules.** `data/source-sast/rules-v1.yml` has only 4 C/C++ rules
      (strcpy, non-literal printf, memcpy, system), so `02-source-sast` always reports the gap
      "Repository-owned C/C++ Semgrep rules do not cover every source-analysis family". Decided
      (William, 2026-09-27): vendor the 16 C rules from `opengrep/opengrep-rules` at
      `f1d2b562b414783763fd02a6ed2736eaed622efa` (LGPL-2.1 + Commons Clause; keep LICENSE and a
      NOTICE naming the commit) under `data/source-sast/`, add a second `--config`, map their rule ids
      in `source_sast.RULE_CATEGORIES`, and extend the closed category enum in
      `schemas/source-sast.schema.json`. Keep our 4 rules. Then narrow the gap text to what is still
      uncovered.
- [ ] **Semgrep/opengrep code signals for partitioning.** The design intended rule-based signals to
      inform partition discovery; nothing does that today (partition discovery is a single persona
      call over the intake file list and file contents). Add a deterministic job before
      `02-repository-partition-discovery` that runs structural rules (entry points and argv parsing,
      socket listen/accept and HTTP routes, file/DB/IPC access, exec/system, crypto,
      deserialization) and publishes per-file/per-directory tags with citations; feed them to
      partition discovery and `01-component-characterization` as an upstream.

- [ ] `tests.test_persona_invocation.RegistryTests.test_tracked_registry_passes_as_is_and_the_default_denied_set_is_pinned` fails on `main` (registry validation reports a problem with `job-templates/02-native-sast`); also `test_vendor_prepass_graph` (16 failures). Pre-existing, not blocking runs.

## Native lane granularity

[ADR-0014](../docs/decisions/ADR-0014-native-lane-granularity.md): native analysis is per clang
invocation (compile-DB entry, keyed by source hash + normalised argv + toolchain); link-level jobs
per link target; configure/build/tests per build unit. Zero invocations = SKIPPED
`not-applicable-no-native-binaries`; one failure = one gap. Order: per-invocation loops + zero skips,
link-command capture + link-target level, plan-driven tests, unit `depends_on`, parallel shards,
content-addressed reuse cache.

Slice 1 (branch `adr14-slice1`):

- [x] IR capture/link/facts, native SAST, test execution: zero built units publish SKIPPED
  `not-applicable-no-native-binaries` (IR/native SAST: result documents with empty lists and null
  link identities; test execution and its ingests: an `evidence-skip` document). Ingests propagate.
- [x] IR capture already iterates per compile-DB entry with per-entry gaps; it now serves every build
  image its units used (one pinned toolchain per image; receipts list the image set and each trial's
  image is checked against it).
- [x] IR link: without link commands, one link target per run (the unit with most modules); every
  other unit is a named `not-linked-one-link-target-per-run` gap.
- [x] Native SAST accepts an OK_WITH_GAPS native build.
- [x] Test execution with built units but no staged control: SKIPPED `not-applicable-no-test-plan`
  (new reason, edges to both ingests and evidence assembly).
- [x] 06-cve-reachability accepts a native-less ir-facts skip.
- [ ] Native SAST: one unit's analyzer failure is a gap for that unit, not the job (receipt count is
  2 per unit today).
- [x] Binary hardening with no binaries: empty staged input root; the worker probe finds no
  candidates and skips `not-applicable-no-matching-inputs` (branch `slice2`).
- [ ] Records JSONL + index for per-invocation IR/SAST outputs (ADR-0014 item 5).

## Scale: engine-sized targets

[`docs/scale-audit-unreal-engine.md`](../docs/scale-audit-unreal-engine.md) lists every static limit
we would exceed on an Unreal Engine-sized target, with priorities. Index-first is the rule: anything
that grows with the target is stored as records, indexed, and queried. First items: lazy
hash-verified input serving for model jobs, then the records-file pattern for every large producer.
All tunables are in config (`docs/processes/tunables.md`, `tunables.py check`). Indexing coverage
plan: the scale audit's "Indexing coverage" table (source/native SAST findings, vendor tools, SBOM/SCA,
build index/plan, discovery, standards corpus, review-stage claims).

## Breakage log

Newest first. One line per breakage: date, target, run id, job, what broke, fix (commit).

| Date | Target | Run | Job | Breakage | Fix |
|---|---|---|---|---|---|
| 2026-09-28 | appsec-multi-vuln | 17b564af | 02-build-resolution | All 34 C/C++ units failed configure: "/scratch/src does not appear to contain CMakeLists.txt". Plan cwd is relative to the unit root (build_plan.check joins root + cwd); the trial and replay runners ran it from the repository root. Native build then had zero units, so the whole native lane skipped | Build resolution re-anchors commands to repository-relative cwd for the trial and the lock (replay reads the lock) |
| 2026-09-28 | appsec-multi-vuln | 17b564af | 06-cve-reachability | IR facts SKIPPED (nothing linked); re-validating the SKIPPED pointer without a consumer edge failed, and a skipped facts result would have been read as facts | IR/test/native-SAST validate() and lifecycles name their consumer edge; cve reachability treats SKIPPED facts as absent |
| 2026-09-28 | freeciv21 | abae7f4b | 02-license-scan | scancode TIMEOUT at 3600 s (single process) | scancode -n 4 merged (795a99f9); OPEN: timeout as a license gap |
| 2026-09-28 | doom3-bfg | 22d32a79 | 02-license-scan | scancode TIMEOUT again at 3600 s (single process) | `scancode -n` from tunable `scancode_processes` = 4, CPU 4000 millicpu. OPEN: a tool timeout should publish a license gap, not block |
| 2026-09-28 | freeciv21 | abae7f4b | 02-ir-link, 02-test-result-ingest, 02-test-coverage-ingest | Upstream skips published (IR capture, test execution SKIPPED), but consumers rejected the SKIPPED pointer: it carries `reason`, their key sets did not allow it | Pointer key set allows `reason` when status is SKIPPED (as evidence assembly already did) |
| 2026-09-28 | freeciv21 | abae7f4b | 02-build-plan | The re-plan ignored the new offline rule (no `FREECIV_DOWNLOAD_FONTS=OFF`) and went back to the noble base | Build resolution backstop: on an offline download failure, find the CMake download switches (`if()`/`option()` names containing DOWNLOAD) and retry once with `-D<name>=OFF`; the lock records the adapted commands |
| 2026-09-28 | doom3-bfg | 22d32a79 | 02-ir-capture, 02-native-sast, 02-test-execution | The new SKIPPED results failed publication: no named consumer edge; contract files/status fields (b13 receipts, modules, records, qualification) absent; test execution's evidence-skip document checked against the test-execution schema | Skips name their consumer edge and write the contract files/fields; the validator checks an `appsec-review/evidence-skip/1` document against evidence-skip.schema.json |
| 2026-09-28 | hello-autotools | e3c8fca2 | 01-component-characterization | Model output valid at last; publication stopped at "immutable attempt inputs changed": `evidence.artifacts` held tuples, inputs.json lists | Inputs built JSON-equal (lists) |
| 2026-09-28 | hello-autotools, doom3-bfg | e3c8fca2, 22d32a79 | (pool) | doom3-bfg scancode held the only `docker` pool slot for an hour; hello-autotools sat idle with nothing in progress (not a failure, pure contention) | `docker` pool slots are the shared tunable `pool_docker_slots` = 2 |
| 2026-09-28 | freeciv21, doom3-bfg | both | 02-binary-hardening | "accepted native build publishes no binaries" (Blocked) | Empty manifest allowed and an empty `binaries/` root staged; the worker skips with `not-applicable-no-matching-inputs` |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-native-sast | One analyzer record cited a file that is not a regular file in the checkout; the whole job failed | Such records are dropped and counted: `analyzer-records-outside-checkout:<n>` gap per unit |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-binary-intelligence-ingest | SKIPPED with `not-applicable-no-native-binaries` but no named consumer edge | Primary consumer 02-evidence-assembly (its edge already allows the reason) |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-build-plan | 9 of the first 38 per-unit calls planned the wrong unit (haiku, lookup mode; retry fixed them) | Invoker (shared runtime) inlines small upstream task files (<= 4 KB each, 16 KB total) such as plan-unit.json |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-build-resolution | On the 26.04 base all 11 apt names resolve and cmake configures; the build compiles until ExternalProject downloads the Libertinus font (offline trial). The resolver then chased configure's optional `ToLuaProgram` miss. Unit `dir:ai` (a subdirectory of the main project) ran `cmake ..` on noble with KF6 names dropped | Download failures are named in the gap and stop the rounds; the plan contract says to turn build-time downloads off (`FREECIV_DOWNLOAD_FONTS=OFF`); dropped apt names also trigger the 26.04 fallback. OPEN: classification makes `ai/` its own build unit |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 01-component-characterization | Only remaining error: component id `fixed-buffer-store` is not the slug of its name `Fixed Buffer Store Macro` | Orchestrator re-derives ids from names and rewrites every reference (relationships, groups, tags, triggers, unknowns); replayed on the failed output: 0 errors |
| 2026-09-28 | doom3-bfg | 20260928T013300Z-0c0b82 | 02-license-scan | scancode TIMEOUT at 900 s | Timeout tunable 3600 s; dependency workers' re-verification reads the same tunables (the static `LIMITS` dicts in `dependency_b13_adapters`/`binary_evidence_adapter` were dead or stale; the scale audit missed them) |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-source-sast | spotbugs "No files to analyze" (source-only Java) failed the job | A language tool that fails is a per-tool coverage gap (`execution_gaps` names tools without receipts) |
| 2026-09-28 | freeciv21, doom3-bfg | both | 02-ir-capture, -link, -facts, 02-native-sast, 02-test-execution | Zero built units (see OPEN row below) | ADR-0014 slice 1: SKIPPED `not-applicable-no-native-binaries` across the lane; N images/units supported (branch `adr14-slice1`) |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 01-component-characterization | Model output now parses; independent validation rejected it: (a) path patterns matched from the right (`PurePosixPath.match`), so `LICENSE` also claimed `vendor/cJSON-1.7.18/LICENSE` (false overlap); (b) representative locations with `:23-61` suffixes, and call sites in `src/main.cpp`, counted as outside the component; (c) negative evidence `generated-code` not taken for `generated`; (d) one component missing from the tag cloud | Root-anchored glob matching; line suffixes stripped and one own location required; `<category>-*` counts; an untagged component becomes a `tag_cloud:<id>` classification gap (ADR-0013); contract rules name the exact tokens |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-secrets-inventory, 02-iac-config-scan | Reuse re-validation: redacted tool output 'is 598 bytes, listed as 519' although the redaction receipt maps it. `tool_instance_shapes` never imported `json`; `_redaction_files` swallowed the NameError and returned no receipt | `import json`; only a missing or unparsable receipt is treated as absent |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-sca-vulnerability-match | OSV exit 127 (missing local ecosystem DBs) accepted by the adapter but rejected by the worker's independent re-verification | One shared predicate `dependency_b13_adapters.osv_exit_accepted` |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-source-sast | phpcs exit 3 (fixable and non-fixable violations) treated as a tool failure | phpcs hit exit codes 1, 2, 3 |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-build-plan | After 18 good units, haiku answered the dotnet/case-050 prompt with a plan for cpp/case-001; one bad unit failed the whole job (and discarded 18 paid plans) | Per unit: one retry, then a `<unit>: no build plan: <reason>` coverage gap; the job continues OK_WITH_GAPS. OPEN: state the unit id in the per-unit prompt so a small model cannot anchor on the first unit it reads |
| 2026-09-28 | freeciv21, doom3-bfg | both | 02-binary-triage, 02-debug-symbol-index | Zero built units: the binary jobs skip with `not-applicable-no-native-binaries`, a reason no dependency edge allowed | Reason allowed wherever `not-applicable-non-native` is (22 edges) |
| 2026-09-28 | freeciv21, doom3-bfg | both | 02-ir-capture, 02-native-sast, 02-test-execution | Zero built units: IR capture demands one image generation, native SAST accepts only an OK native build, test execution needs an operator control that can only be staged for exactly one accepted unit | OPEN: skip these with `not-applicable-no-native-binaries` when no unit was built; test execution should stage its own control for 0..N units (multi-vuln has 27 native units) |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 01-component-characterization | Now reaching the model: `component-purpose-map.json` and `.md` slugged to one envelope key, so the model was told one key is both an object and markdown | Markdown key gets `_markdown` when stems collide (also build-index, synthesis report) |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-build-plan | Model sent the plan JSON and the summary as two fenced blocks, no envelope; the plan was lost | Invoker salvages the result JSON (has `schema`) and the markdown from fenced blocks/prose |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-secrets-inventory, 02-iac-config-scan | Redacted tool outputs: the redactor records no source hash for redacted files, so the raw-to-published mapping never matched | Match on path, `redacted` disposition and published bytes |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-source-sast | gosec reports `line` as a range (`38-42`) | Language adapters take the first line of a range |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 02-sca-vulnerability-match | OSV-Scanner exits 127 when some ecosystems (Maven, GitHub Actions) have no offline database; only npm is registered | Exit 127 with that message is accepted; results stand. Follow-up: surface the missing ecosystems as an SCA gap, and register more OSV snapshots |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-build-resolution | The CoW trial copied the checkout with its symlinks into the attempt tree; publication refuses linked paths | Trial copies follow links (dangling ones skipped) in build resolution and build replay |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-secrets-inventory | Rewriting the tool listing after redaction broke the receipt and citation hashes | Listing keeps the raw hash; the on-disk check accepts published bytes when the redaction receipt maps raw to published |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-sbom-inventory | CPE schema rejected CPE 2.3 backslash escapes (`softprops\/action-gh-release`) | Pattern allows escaped characters |
| 2026-09-28 | doom3-bfg | 20260928T013300Z-0c0b82 | 02-build-plan | Model marked doomclassic tier C but left it out of coverage_gaps | Build plan fills tier C units into coverage_gaps before validation |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 01-component-characterization | Real cause of every failure of this job: the claude CLI invoker had no claim builder for `component-purpose-map.schema.json` and raised before dispatch (the 9.3 MB prompt was a second problem, not the first) | Generic fallback claim builder: one claim per result object whose `evidence_citations` resolve to a pinned input |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-build-resolution | Model planned CMake/Qt6 (tier A) but named apt packages that do not exist on noble (`libqt6core6-dev`, `libkf6archive-dev`); image build exited 100 | Image-build failure is a coverage gap naming the missing packages. Follow-up: give build-plan an offline apt package lookup, or feed the apt error back for one repair round |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-code-property-graph | Joern records name files not in the checkout (`client/luascript/tolua.h`) | Skipped and counted as `source-unavailable` |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-secrets-inventory | Reconciling tool-results after redaction left the redaction receipt unsealed | Receipt re-sealed after the update |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 02-binary-triage, 02-debug-symbol-index, binary-hardening | Upstream build-resolution fingerprint changed mid-run (code reloaded while the run was executing) | None needed; relaunch re-runs build-resolution. Reloading during a run mixes code versions |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-repository-partition-discovery | Indexed-mode inventory listed all 6,100 files (895K chars) and hit the $2 per-call cap | Inventories over 300 rows are summarised by folder (6K chars); `input_list` has every ref |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-secrets-inventory | Redaction rewrote gitleaks output after tool-results.json listed its hash | Listing re-reconciled to the published bytes; receipt check accepts the pre-redaction hash the redaction receipt maps |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-code-property-graph | Joern export NPE on call/identifier nodes without an enclosing method | Export skips those nodes |
| 2026-09-28 | doom3-bfg | 20260928T013300Z-0c0b82 | 02-build-resolution | Model planned both units (doomclassic, neo) as MSBuild/Win32-only tier C with no commands; resolution raised | Unbuildable units and failed trials are coverage gaps; job publishes OK_WITH_GAPS |
| 2026-09-28 | doom3-bfg | 20260928T013300Z-0c0b82 | 02-code-property-graph | Joern line numbers beyond our line count (lone CR line endings) | Line count treats CR as a break; remaining mismatches skipped and counted as `line-beyond-file` |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 02-build-plan | With lookup tools the model narrates before its JSON; parser required the reply to be only JSON | Parser takes the last fenced JSON block, else the outermost object |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-repository-partition-discovery | Readable-input paths limited to `[A-Za-z0-9._ /-]`; freeciv21 has `logo+splash/` | Input paths accept any name except control characters/backslash and dot or empty segments |
| 2026-09-28 | doom3-bfg | 20260928T013300Z-0c0b82 | 00-intake | Post-validation recomputed the inventory from the in-memory identity and reported a semantic mismatch; recomputing from the recorded `source.json` matches | Post-validation uses the recorded snapshot the worker consumed |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-code-property-graph | Joern exporter script threw "CPG record limit exceeded" (50,000 via param) | Param set to Int max; count logged by size_log |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-repository-partition-discovery | A symlink in the checkout (`data/icons/...`) refused the whole model request | Symlinks are skipped (not followed) and counted on stderr |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 01-component-characterization | Uncapped, the model prompt inlined 9.3 MB of inputs (Joern graph 5 MB) and the CLI raised | Model jobs over `invocation.inline_input_bytes` (150 KB) get an inventory and look things up through the new read-only `input_mcp.py`: pinned inputs (`input_list/read/grep`) plus the run's evidence index (`evidence_search/read/similar/derived`). No built-in tools; every call audited under `data/retrieval/` |
| 2026-09-28 | hello-autotools | 20260927T192621Z-helloautotoo | 00-intake | Editing any schema, job template or shared module made intake stale (its definition hash covers all of them), which re-runs the whole run | Intake freshness now compares what intake read: target snapshot, config, dependencies, tools |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac | 02-doc-intelligence-ingest | Extracted record count over the 1,000 ceiling | Count ceilings removed, not raised (William: do not cap, log): static-intelligence files/records, persona readable-input count, evidence-index producers/records/links, Joern bytes/records, build-discovery bytes, plus the matching schema maxima. Sizes now logged to `runs/<run>/data/size-observations/`; view with `orchestrator/size-report.py <run>` |
| 2026-09-27 | hello-autotools | 20260927T192621Z-helloautotoo | 01-component-characterization | Persona request over the 256-readable-input ceiling: evidence assembly publishes the ~1.2k-file standards corpus | Standards corpus excluded from the staged evidence (221 inputs). Large targets (freeciv21, doom3) will still exceed 256 from source files alone; needs a sampled/indexed target view |
| 2026-09-28 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | 21/22 OK; one instance `BUDGET_EXCEEDED` on input: its pinned files were ~116k input units (limit 100k) | Keep the probe input budget as well (200k units, 8 MiB) |
| 2026-09-28 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | 22/23 OK; one instance's model replied with non-JSON twice | `evidence_assembly_runtime._fill_binding` via `fill_result`: the whole binding is supplied, the hashes/job id filled from pinned inputs |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | After the hash fix 15/18 instances OK; 2 `TIMEOUT` (300 s) and 1 `BUDGET_EXCEEDED` (20k output units) from long haiku thinking | `evidence_assembly_runtime` keeps the probe budget for output units/time (100k, 900 s); template timeout 900 s |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `persona-tool-pool-dispatch` | Quorum failed: one of two reviewers returned non-JSON, then a bare array, when asked to echo the canonical intake candidates verbatim | `ClaudeCliInvoker(fill_result=...)` hook; the pool reviewer supplies the canonical candidates (fully determined by intake) instead of depending on the model's echo |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | (policy) | Fixes to shared modules re-ran accepted jobs (intake, discovery, build plan) because their code fingerprints included shared runtime | ADR-0013 item 8: `execution_state.SHARED_RUNTIME` is dropped from every job's code fingerprint (23 `_code_hashes` wrapped; inline entries removed in `discovery_gate`, `ossf_scorecard`, `critical_findings_sarif`). One-time re-run of all jobs follows |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | 12 of the first 13 pool instances failed `INVOKER_EXCEPTION`: the producer-binding result asks the model to echo four 64-hex file hashes and a job id, and the model miscopies them (invented `accepted_pointer_sha256`) | `claude_cli_invoker._fill_pinned_values` writes those orchestrator-known values from the pinned inputs before validation; the exact-echo check still runs |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | `PermissionModelError: context.now is malformed`: its clock was the newest producer `accepted_at` (ISO with microseconds and `+00:00`), the permission model needs `YYYY-MM-DDTHH:MM:SSZ` | `evidence_assembly_runtime`: compare `accepted_at` as datetimes and normalise to whole-second UTC `Z` |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | `02-sbom-inventory has an incomplete accepted producer root`: the dependency workers wrote an accepted pointer without `hashes`/`accepted_at` and no `latest.json` | `dependency_workers._publish_pointer` writes the full common pointer and `latest.json` (also upgrades an existing pointer on reuse); this run's five dependency pointers upgraded in place |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | `02-ossf-scorecard does not publish an intact permission.json` (the only one of 26 producers without permission/lineage receipts) | `ossf_scorecard` writes both receipts on the published and skipped paths, bound to the canonical intake source fingerprint (a manifest-hash binding was rejected as an alias without build lineage) |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | (policy) | Two breakages (#2, #6) were phrase rules misreading ordinary model text | ADR-0013 item 7: conclusions are enumerated `claim_class` values and structured fields only; phrase scanning no longer fails jobs (`persona_invocation`, `validate_job_output`) |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-build-resolution` | `STALE_GRANT` again: a code change re-ran intake, which rewrote `artifact-manifest.json` after the controls were re-staged | `build_resolution`, `build_replay`, `test_evidence` rebind staged grants to the current manifest hash at execution (still bound to run and job) |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-build-plan` | Persona result rejected `PROHIBITED_CLAIM`: the `remediation_status` text rule matched "Compiler choice is fixed by the orchestrator" ("is fixed" in the sense of set) | `persona_invocation`: "fixed" counts only with a security subject (vulnerability/issue/bug/defect/finding/flaw/weakness/CVE); "remediated"/"patched" still count alone |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-evidence-assembly` | Blocked: `02-evidence-index` does not expose one current common-envelope result (the index still published the pre-envelope accepted pointer) | `evidence_store.run` writes a common `result.json` envelope and accepted pointer (schema, job, envelope path/hash, `sha256:` fingerprint); `validate()` accepts either fingerprint form; this run's index re-run with `--force` |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-secrets-inventory`, `02-iac-config-scan`, `02-container-image-inventory`, `02-mobile-sast`, `02-binary-hardening` | Publication redactor flagged the run id `20260927T192621Z-helloautotoo` as a high-entropy secret and replaced it with `[REDACTED:high-entropy:1]`; the results then failed their schemas | `evidence_redaction` run-id exemption accepts a 4-12 character alphanumeric suffix (was hex only); `stage-run.sh` now generates the canonical `<UTC stamp>-<6 hex>` run id; redaction golden hashes updated |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-build-resolution` | BLOCKED `STALE_GRANT`: build grants bind to the hash of `artifact-manifest.json`, which intake rewrites on acceptance; the controls had been staged before intake | Operator order: run `phase1_intake` before `build_resolution`/`build_configure stage-control` (`stage-run.sh`, operator guide); this run's controls re-staged after intake |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `02-repository-partition-discovery` | Result rejected: claim-class text check read the model's disclaimer "not asserted as a verified finding" as a finding promotion (negation lookbehind only matched "not a "/"no ") | `validate_job_output`: a promotion phrase counts only without a negation (not/no/never/without/nor) in the 40 characters before it |
| 2026-09-27 | hello-autotools | `20260927T192621Z-helloautotoo` | `persona-tool-pool-dispatch` | BLOCKED: no pinned `model-versions.json`; the job ran before discovery pinned model identities | `persona_tool_pool_lifecycle._current_inputs` calls `resolve_run_model_versions(run_id)` first, like every other persona worker |
