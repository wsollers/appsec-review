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

- [x] **Source SAST Semgrep rules.** Done on branch ws-sast (see breakage log).
      Original note: `data/source-sast/rules-v1.yml` has only 4 C/C++ rules
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

- [x] `tests.test_persona_invocation` registry failure on `job-templates/02-native-sast`: passes on `main`
      since hardening-b (`6f4f0c2`, underscore claim ids; 86 tests OK 2026-09-29).
- [ ] `test_vendor_prepass_graph` (16 failures). Pre-existing, not blocking runs.

## Report findings: CWE, CVSS, reachability, EPSS/KEV (ADR-0020, branch ws-report)

| Item | Status |
|---|---|
| Pinned rule->CWE map + CWE catalog; reviewer `cwe` at 07/09/12 validated and carried to the report | DONE (curated 96-entry catalog; import full MITRE export with `cwe_catalog.py intake`) |
| `cvss4.py` pinned CVSS v4.0; 12 `cvss_v4` base metrics + rationale -> vector/score/severity | DONE (diff the table once against FIRST `cvss_lookup.js`) |
| `reachability.py` CPG call-graph arbiter with witness; Critical requires REACHABLE | DONE for code findings; entry points beyond `main` need a source (exports/handlers) |
| 06 CVE reachability from vulnerable function -> app call path (`reachability.py cve-evidence`) | DONE and wired into full_review by brief E (ADR-0022, `f5ca4d3`); see the dependency reachability section |
| EPSS/KEV dated snapshot (`epss_kev_snapshot.py intake`), "as of" in report, "not assessed" gap | DONE; no snapshot imported yet |
| Hash-verified redacted snippets; 11 objectives + 12 PATCH_PROPOSED_UNVALIDATED remediation | DONE |
| Persona prompt text for 07/09/12 mentions the new judgment fields | DONE (`claim-review-pool-task.md` "Judgement fields", hardening-b `323c022`) |

- [x] **Claim ledger: CodeQL leads.** Every `02-codeql-<lang>` node is a row in `claim_ledger.LEAD_PRODUCERS`
      (was `02-codeql-sast`, `f50caba`; per-language since ADR-0023, `1248b43`), normalised like `02-source-sast`
      (plus `language`, `rule_name`, `cwe`); `codeql-security-query` and the new source-SAST categories are P1.
- [ ] **audit-codeql image.** Rebuild (`image_build.py`, picks up `scripts/codeql-sast-lane.sh`) and
      register the B16 record; until then every language is an `UNAVAILABLE` gap. The .NET SDK for C#
      and the traced C/C++ tool id are in (branch `lang-servers`, see section C below); the traced lane
      is not wired yet.

## Threat workbench (ADR-0008 slice 1 + privacy L13)

[ADR-0019](../docs/decisions/ADR-0019-threat-workbench-slice-1-and-privacy.md), branch `ws-workbench`, merged `35fca25`.
`03-threat-model-dfd-stride` now runs persona cells over the deterministic DFD/STRIDE core as C01/C02
wave pools (`threat_workbench.py`) and publishes non-empty data classes, LINDDUN privacy threats,
declared deployment zones, abuse scenarios and attack trees, plus `attack-trees.mmd`, `dfd.mmd`,
`ranked-threat-scenarios.json` and the intercom transcript. Tunables: `workbench_*` in
`registry/job-templates/03-threat-model-dfd-stride.json`.

- [x] T05 wave runner (pool per wave, budget-class concurrency), T07 deterministic join, T08 overlay
      validator, T06 intercom bus wired (cell notes -> transcript -> assumptions/gaps).
- [x] L13 privacy cell: data-class/PII inventory, personal-data flows, LINDDUN threats, candidate
      regulatory notes only.
- [x] Claim ledger admits abuse scenarios and privacy threats as candidates (attack trees left to ADR-0016).
- [ ] William: ADR-0019 open decisions (failed cell = gap; next cells; ledger load; report section; engine scale).
- [ ] First live run on hello-autotools (5 model calls; 03 and everything downstream re-run: 03's code hash changed).
- [x] `design-parity-manifest.json` 03 `resource_pool` is `persona_llm`, as the Dagster op runs it (docs-sync-G).
- [ ] Controller-owned (do not edit from docs): 03 still describes the pre-workbench job in
      `job-graph.json` `required_artifacts` (no `attack-trees.mmd`, `dfd.mmd`, `ranked-threat-scenarios.json`,
      `intercom-transcript.jsonl`), the registry template model (`deterministic-python`) and
      `threat_model_core.py` `worker_kind="deterministic_python"`; the manifest's `execution.mode` follows them.
- [ ] Wave 3 challenge cell (different model family) and wave 4 responses; agent/native/mobile/cloud specialists.
- [ ] Synthesis report: show `data_classes`, `privacy_threats`, `deployment_zones` (closed report schema).
- [ ] After review-batch merges: confirm the cells use `supporting_evidence_menu` (fallback today: F02 intel manifest).
- [ ] ADR-0016 chain composition: consume `attack_trees` (ids are content-derived and stable across replays).

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
- [x] Native SAST: one unit's analyzer failure (timeout/OOM/tool error) is a gap for that unit, not the job
  (hardening-b B1, `61ac5b8`).
- [x] Binary hardening with no binaries: empty staged input root; the worker probe finds no
  candidates and skips `not-applicable-no-matching-inputs` (branch `slice2`).
- [ ] Records JSONL + index for per-invocation IR/SAST outputs (ADR-0014 item 5).

## Retrieval and IO (measured 2026-09-28, ~2,760 audited model tool calls)

- Index tools are almost unused: evidence_search 6, evidence_derived 2 of ~2,760 calls. Models use
  input_read (1,575), input_jq (926), input_grep (169, 106 ms avg vs 643 ms for evidence_search).
  Fine at current target sizes; at doom3/Unreal scale route input_grep over the FTS index.
- 742 of 1,575 input_read calls re-read a range already returned in the same invocation. input_read now
  answers a repeat with a pointer (`again=true` forces the text), per conversation.
- Build plan: 871 input_jq calls over 138 unit invocations, mostly the same three shared JSONs
  (build-classification, build-index, buildenv-catalog). [ ] Pre-slice the unit's classification row,
  index signals and catalog bases into plan-unit.json (costs one re-plan; do with the next plan change).
- Build resolution kept a ~720 MB source copy per trial (freeciv21: 11 GB per job), tree-hashed on every
  re-validation. [x] Trial source copies are pruned after their logs are read (branch io-prune).
- [ ] Same audit for native-build/replay and code-property-graph (freeciv21 2.8 GB, doom3-bfg 4.0 GB).

## Relaunch tax

Measured 2026-09-28: pure reuse is cheap (hello-autotools relaunch: 46 steps in 2.4 min). The tax is
re-execution after a fingerprint change: multi-vuln spent 41 min re-planning 53 units (the plan
contract text changed) and 12.6 min re-assembling evidence; freeciv21 60 min in scancode.

- [x] Persona result cache (shared runtime, branch persona-cache; tunable persona_result_cache): an OK persona result is keyed by the request identity
  (outer-prompt sha, pinned readable-input hashes, model, output contract) minus attempt ids; an
  identical request in the same run reuses it with provenance instead of a new model call. A code-only
  change to a model job then costs no model calls. Key includes job id and persona so independent
  cells never share an answer; today's acceptance is re-run on the cached answer.
- [ ] Per-item memo in loops (ADR-0014 item 6): build-plan units, build-resolution units (image +
  plan commands + trial inputs), IR/SAST invocations, keyed by content, reused across attempts.
- [ ] Tool output cache: pinned-tool runs (scancode, syft, grype, semgrep...) keyed by image digest +
  argv + source snapshot; a job re-execution with the same key reuses the verified B13 result.
- [ ] Fingerprint scope: prompt/contract text is part of a model job's identity (correct), but
  docs-only edits to other files must not be; audit `_code_hashes` lists for files that are not
  semantics (READMEs, comments-only registries).
- [ ] Tail iteration: launch single jobs (`launch_job.py --job <name>`) instead of full_review while
  fixing the model tail; batch fixes and merge between runs.

## Scale: engine-sized targets

[`docs/scale-audit-unreal-engine.md`](../docs/scale-audit-unreal-engine.md) lists every static limit
we would exceed on an Unreal Engine-sized target, with priorities. Index-first is the rule: anything
that grows with the target is stored as records, indexed, and queried. First items: lazy
hash-verified input serving for model jobs, then the records-file pattern for every large producer.
All tunables are in config (`docs/processes/tunables.md`, `tunables.py check`). Indexing coverage
plan: the scale audit's "Indexing coverage" table (source/native SAST findings, vendor tools, SBOM/SCA,
build index/plan, discovery, standards corpus, review-stage claims).

## Personas and reviewer pools (ADR-0021, branch `ws-personas`, merged `195683f`)

- [x] Registry records for the 48 catalog personas that had none (`catalog_personas.py generate`,
      `provenance.reviewed: false`); `check` guards missing/stale records.
- [x] `persona_variants` on job templates; `claim-review-pool-cell.stage_personas` gives 07/08/09/12
      attacker / defender / verifier / scorer persona pools, disjoint across stages.
- [x] 07/08/09/12 claims sharded across `claim_review_pool_instances` (default 3) reviewer instances,
      one review per claim per stage, each instance its own persona; `shard-coverage.json` per attempt.
- [x] Persona/role audit of model-calling jobs: `docs/personas-and-registry/persona-assignment.md`.
- [ ] William: review/own the generated persona records (start with the stage reviewer pools).
- [ ] William: partial stage publication with explicit `UNREVIEWED` decisions when one shard fails
      (today the pool attempt fails naming the claims; rerun reuses cached shards).
- [ ] Decide persona variants for OWASP validator cells (by chapter) and the intake review pool.
- [x] Per-stage registry roles (red-team-adversary, blue-team-refuter, independent-verifier, scorer)
      instead of the generic `claim-reviewer` role (brief J, ADR-0024).

## OSV feed (brief A, branch `osv-feed`, merged `aafbe53`)

- [x] `osv_feed.py` / `osv_snapshot.py`, Dagster `osv_sync_work` in `nvd_reference_sync`, SCA registry bridge
      (`register_osv_feed`), measured SQLite index, `osv_lookup.py`, skills; see `docs/osv-feed.md`.
- [ ] Operator: run `osv_feed.py sync` once on a networked host and set `APPSEC_DEPENDENCY_REGISTRY_ROOT`
      for the Dagster stack so the SCA registry follows the feed (unset, the op only publishes).
- [ ] Image smoke test in WSL (no Docker here): mount a published `db/` read-only at `/inputs/osv-db` and run
      OSV-Scanner offline against an SBOM with npm, Go and PyPI components; see `scripts/smoke_osv_feed.sh`.
- [ ] Verify the licence-by-prefix table in `osv_feed.py` against OSV's current documentation.
- [ ] Wave 3 reachability: only Go advisories carry affected symbols today (`docs/osv-index-measurement.md`).
- [x] `APPSEC_OSV_ROOT` is not in `scripts/sat_contract.py` AMBIENT (`data/feeds/nvd/**` is); done 2026-09-29.
- [ ] Pre-existing, not touched: 4 failures and 1 error in `tests.test_resource_pools_dagster` on baseline
      (`rp.PERSONA` missing, pinned Dagster version); the `osv_sync_work` pool assertion added there cannot run past it.

## Attack chains (ADR-0016, brief D, branch `kill-chains`, merged `497e1b7`, `bc95049`)

- [x] S1 seeding `attack_chain_seeds.py`; S2 composer persona + `attack_chain_derive.py`; S3 refuter
      persona + `attack_chain_refute.py` + `attack_chain_pool.py`; S4 workers, graph nodes
      `14-attack-chain-composition` / `14-attack-chain-refutation`, Dagster ops, optional edge into 10.
      Unit tests only (stub invokers); nothing has run live.
- [x] Report section (brief S5): `attack_chain_report.py` -> `attack-chains.json` in the 10 attempt,
      "Attack chains" section in the HTML/TeX templates (body up to `chains_reported_max`, appendix,
      refuted count, SKIPPED/absent reason). HTML and TeX render locally; the PDF compile (Docker
      `audit-report` image) is untested here: run a 10 publication in WSL.
- [ ] First live run on appsec-multi-vuln (expect argv -> strcpy at `case-001/main.cpp:6-7`), then
      freeciv21; record chain counts by state, gaps and cost here; tune the lane-14 tunables.
- [ ] Controller: confirm the refuter shares the composer's model family (only sonnet-5 and haiku are
      configured; both cell templates use `claude-sonnet-5`).
- [x] Lane-14 Dagster ops return `NOT_PUBLISHED` instead of raising (`dagster_workflow.py`
      `attack_chain_lifecycle_op`), so 10 proceeds with an ABSENT section.
- [x] Merged; 10's fingerprint changed (new optional dependency): runs past 09 re-run 10 after a reload.
- Slice numbering: the ADR/plan call live acceptance S5 and the report S4; this section's "brief S5" is the report.

## Hardening (brief B, branch `hardening-b`, merged `60ae2e3`)

- B1 native SAST per-unit gaps (`61ac5b8`), B3 OWASP validator reduced citation reply + `owasp_validator_derive.py`
  (`446d599`), B4 component-map and build-plan bookkeeping derive (`e2af0af`), B5 07/09/12 prompt text (`323c022`),
  B6 stale test fixes (`6f4f0c2`) done; B2 not reproducible (invoker now inlines plan-unit.json; build_plan.check already rejects wrong-unit plans).
- OPEN: build classification makes `ai/` its own build unit (freeciv21 `dir:ai`); belongs to build_index/build_classify.
- OPEN, pre-existing failures on baseline: `test_validator_vendor_prepass_dispatch` (128F/13E), `test_phase1` A08 x2, `test_owasp_dispatch...prohibited_text_in_the_candidate_itself`, `test_build_discovery` and `test_b13_harmless` (import errors).
- Reachability has no model judgement field at stages 07/09/12; Python arbitrates it (brief assumed one).

## Run log (branch `run-log`, merged `f25a1e9`)

Supersedes the buffered central log (`d60d07b`); the same series added model-call start/heartbeat/finish
lines (`f273a04`), reviewer-diag tracebacks in the claim reviewer pool (`0b9fe32`), component-map citation
normalisation (`1b550b5`) and the Python-merged tag cloud (`8dca5fa`). Operator view: `docs/run-log.md` and the
operator guide (tailing, `APPSEC_*` settings).

| Item | Status |
|---|---|
| `pipeline_log` JSON lines, one file per run, banner at intake/resume, context from Dagster ops, `orchestrator/tail-run-log.sh` | DONE (`docs/run-log.md`) |
| Idle watchdog in `review_cli._dispatch_streaming` (warn default, kill off by default) | DONE |
| Workers other than `review_cli` / `claim_reviewer_pool` do not yet log their own progress lines; only step start/finish + those two | OPEN |
| Persistent processes (Dagster daemon, webserver, code location) should set `APPSEC_LOG_PROC` and write to the global file | Not needed: `proc` defaults to the process name (argv[0] basename), so the daemon and webserver are named by what they run; setting it globally in `code-location.sh` would rename every step process. Set `APPSEC_LOG_PROC` only for a process whose default name is unhelpful. |

## C: language servers, tree-sitter, CodeQL traced (branch `lang-servers`, merged `955d797`)

Merged, not yet built (details and WSL commands: `docs/language-servers.md` §7):
pinned servers on every `audit-buildenv-*` image, vendored tree-sitter (`audit-lsp-vendor`),
`lsp_driver.py`, `treesitter_ast.py` (+ schema), `codeql-cpp-traced` in `codeql_sast.py`,
`queries/appsec-graph-cpp`, .NET SDK in `audit-codeql`, `scripts/smoke_lang_servers.sh`, skills.
OPEN:
- Build `audit-lsp-vendor`, then the 9 buildenv images and both CodeQL images; run
  `images/test/run-lsp-smoke.sh`; regenerate B16 records (now include `audit-codeql`,
  `audit-codeql-native`). Fix whatever the first build breaks (QL compile, offline servers).
- [x] Wire `codeql-cpp-traced`: done by brief G (`1248b43`): `02-codeql-cpp` waits for `02-native-build`
  and adds one traced row per replayable unit.
- `treesitter_ast.py` is not a graph job yet; host venv lacks py-tree-sitter (parsing tests skip).
- [x] `images.tests.test_tool_pins` failures for tool-checkov/tool-mobsfscan (Dependabot bumps): re-recorded with
  `tool_pins.py pin --keep-lock` (`1661f48`); 20 tests OK.

## Light PoC and proposed fix (lane 12b, brief F, branch `poc-fix`, merged `5d1a7b0`)

- [x] Lane `12b-poc-and-fix` after 12: `poc_fix_select.py` (verified + CRITICAL + REACHABLE via the
      report's enrichment code), `poc_fix_derive.py`, `poc_fix_denylist.py`, `poc_fix_pool.py`,
      `poc_fix_worker.py`; persona `poc-fix-author`, graph node, optional edge into 10, Dagster op,
      catalogs. Unit tests only (fake persona replies); nothing has run live.
- [x] Report: `poc_fix_report.py` -> `poc-fix-section.json` in the 10 attempt; HTML/TeX block under
      each Critical REACHABLE finding. HTML and TeX render locally; the PDF compile (Docker
      `audit-report`) is untested here: run a 10 publication in WSL.
- [ ] First live run on appsec-multi-vuln (expect one request for the argv -> strcpy finding at
      `case-001/main.cpp:7` if 12 scores it CRITICAL). Record PoC/fix/denylist counts and cost; tune
      `poc_findings_max` and `poc_citation_window_lines`.
- [ ] Denylist false positives (`connect(`, `bind(`, `remove("...")`, `token`-like names) cost a PoC,
      never publish one; review the rejected-rule counts after the first runs.
- [x] Merged; 10's fingerprint changed (new optional input, new modules): runs past 12 re-run 10 after a reload.
- Operator view: `docs/report-path/happy-path-operator-guide.md` §6-7; flow: `docs/appsec-review-process-flow.md`.

## Dependency reachability (06, ADR-0022, brief E, merged `f5ca4d3`)

Merged (details: `docs/dependency-reachability.md`): `dep_reachability.py` (symbols
from reviewed map / OSV, engine per ecosystem, lattice, hash-bound witness), adapters `cpg`,
`codeql` (tables), `lsp` (incomingCalls chain), `treesitter` (hints only), CodeQL packs for
Go/Java/C#/JS/Python in `data/codeql-reachability/` (pinned to bundle 2.27.0 libraries, symbols via
generated data extension), and `06-cve-reachability` in `full_review` now derives its evidence
instead of an empty file (at merge: edges from `02-code-property-graph`, `02-codeql-sast`; since ADR-0023 06 is
the correlator over the two engine jobs, see section G). This
supersedes the "not yet wired into full_review" row under Report findings.
OPEN:
- WSL: `scripts/smoke_codeql_reachability.sh` (needs `audit-codeql:local`); expect QL compile
  fixes (packs written, not compiled). Go autobuild needs a Go toolchain in `audit-codeql`
  (image request for brief C's owner).
- [x] The CodeQL packs run in `06-reachability-codeql` (brief G, `1248b43`; image rebuild pending, section G).
  The LSP incomingCalls walk and `treesitter_ast.py` still run outside the graph (section G).
- OSV symbols exist mostly for Go; other ecosystems need `inputs/cve-reachability-functions.json`.
- [x] `codeql-cpp-traced` tables reach 06 through `02-codeql-cpp` and `06-reachability-codeql` (brief G).
- No Ruby or Rust CodeQL pack; PHP has no CodeQL extractor (lsp/treesitter only).

## G: per-language CodeQL nodes and reachability engines (ADR-0023, brief G, branch `codeql-reach`, merged `1248b43`)

Design: per-language `02-codeql-<lang>` nodes (parallel; compiled languages gated on a successful build of that language, otherwise a gap, never a failure), engine jobs `06-reachability-codeql` and `06-reachability-ir` (same table shape), and `06-cve-reachability` becomes the Python correlator whose output feeds the report and the 07/08/09 red/blue lanes. See `docs/agent-briefs/G-per-language-codeql-reachability.md`.

Merged (ADR-0023, `docs/dependency-reachability.md`; operator view in the happy-path operator guide): eight `02-codeql-<lang>`
nodes replace `02-codeql-sast` (SKIPPED `not-applicable-language-absent`; cpp waits for
`02-native-build` and adds traced rows per unit; Go/Rust are gaps; databases retained as hash-bound
pointers); `dep_symbol_resolver.py` (PyPI, npm, Maven, Go, NuGet, Cargo, Packagist); engine jobs
`06-reachability-codeql` (packs against the retained databases, parallel per language) and
`06-reachability-ir` (CPG arbiter) with one table schema; `06-cve-reachability` is the Python
correlator (`conflict` verdict, LSP/tree-sitter hints only) with the summary for 10 (section 3B),
the claim ledger (reachable = P1 claim, conflict = review obligation) and 07/08/09/12 (evidence
menu). This closes E's OPEN items "no job runs the CodeQL packs" (for Go/Java/C#/JS/Python, once the
image is rebuilt) and "`codeql-cpp-traced` tables reach 06 only once ... wiring lands"; E's other
OPEN items stand. 81 jobs.

OPEN (deferred, not in brief G's first cut):
- [ ] **Java bytecode reachability** in `06-reachability-ir`: a JVM call-graph engine over the built classes and the vendored dependency jars (for example Soot, WALA or ASM-based class-hierarchy/RTA analysis), including shaded/relocated jars, so a Java dependency can be `reachable`/`unreachable` without relying on CodeQL alone.
- [ ] **.NET IL reachability** in `06-reachability-ir`: the same for C# assemblies (IL call graph over the built assemblies and the vendored NuGet packages, resolving assembly and namespace names to package ids).
- [ ] Rust MIR/LLVM IR engine and Go SSA engine (same table shape) once the C/C++ LLVM IR + Joern path is qualified.
- [ ] Reflection, dynamic dispatch, dependency injection and serialisation entry points: record a per-language "incomplete call graph" reason so `unreachable` is never asserted across them.
- [ ] WSL: rebuild `audit-codeql` and `audit-codeql-native` (the lane script gained `keep-db`, the
      new `codeql-reachability-lane.sh`, tool.json `reachability_script`), then
      `python3 -B images/registry_records.py generate`, then `scripts/smoke_codeql_per_language.sh`.
      Until then every `02-codeql-<lang>` node is `UNAVAILABLE` (gap) and every CodeQL reachability
      row is `unknown`. Expect a QL compile round for `data/codeql-reachability/*` (never compiled here).
- [ ] `02-codeql-go`: needs the Go toolchain in `audit-codeql` plus an offline Go build (vendored
      `vendor/`) or a Go build step; until then Go is `language not built`. Image request.
- [ ] `02-codeql-rust`: pin a rust suite in `images/audit-codeql/tool.json` once the bundle's Rust
      extractor is qualified offline (and add `rust` to `BUILD_MODE_NONE`); Ruby and Rust
      reachability packs do not exist (`no-pack`).
- [ ] Java/C# build-mode none leaves dependency jars/assemblies unresolved; the `through-dependency`
      tier needs vendored dependency sources in the database (artifact repository, per version).
- [ ] Database store size: one retained database per language and traced unit per run under
      `<run>/data/codeql-databases/`; no pruning of superseded attempts yet.
- [ ] LSP incomingCalls walk and `treesitter_ast.py` still run outside the graph (hints are
      run-supplied under `<run>/inputs/dependency-reachability/`).
- [ ] NuGet namespaces come from assembly file names (heuristic, recorded as such); reading
      assembly metadata would be exact.
- [ ] Controller to confirm: node name `02-codeql-javascript` (CodeQL's `javascript` extractor, JS+TS);
      cpp always also runs build-mode none next to traced rows; `06-cve-reachability` now feeds
      `claim-ledger-routing` and `10-synthesis-report` directly (new required edges).
- [ ] ADR-0023 decision 9 names a `review_flags` entry `reachability-conflict`; `claim_ledger.py` records an
      engine conflict as a review obligation instead. Align the ADR or the code (controller).
- [ ] Controller to confirm: the `02-codeql-<lang>` nodes are NOT edges of `02-evidence-assembly`
      (brief asked to move the edge; 34 producers would exceed `pool_groups_max` 32 in its persona
      pool). Ordering into the ledger holds via 06-reachability-codeql -> 06 -> claim-ledger-routing.

## H: Ghidra and x64dbg in audit images (branch `image-reverse-tools`, merged `7690f90`)

Both images now pin Ghidra 12.1.3, Temurin 21.0.12+8 and x64dbg 2026.05.27, with a sha256 check for
each download. x64dbg runs under Wine and Xvfb. Details are in `docs/processes/tool-images.md`. The
Ghidra, Wine and x64dbg layers of `audit-native`, built alone on `ubuntu:24.04`, passed
`scripts/smoke_reverse_tools.sh` in the cloud workspace.

OPEN:
- [ ] Build both images in WSL: `python3 -B images/image_build.py build audit-binary-analysis` and
      `... build audit-native`. Then run `scripts/smoke_reverse_tools.sh --docker <image>` for each.
      This also rebuilds `audit-buildenv-cpp`, which extends `audit-native:local`.
- [ ] `audit-binary-analysis` apt pin `wine=8.0~repack-4` is unverified. Debian mirrors were blocked
      from the pinning host. If apt reports the version is not found, read the right one with
      `apt-cache policy wine` in a bookworm container and update `WINE_VERSION` and the smoke script.
- [ ] Check the Ghidra zip sha256 `93a5d11a…` against the hash in the Ghidra 12.1.3 release notes.
- [ ] No job or persona uses Ghidra headless in `audit-native`, or x64dbg in either image, yet.
      Candidates: `02-binary-triage` or `02-binary-cfg` (PE triage), and `buildenv-catalog.json` tool
      lists. Qualify live x64dbg debugging (it needs ptrace, so the `DEBUG_CAPS` profile) before any
      job relies on it.

## J: personas and roles folder (brief J, branch `personas-folder`, ADR-0024)

- [x] `personas/personas/<id>/{persona.json,prompt.md}` and `personas/roles/<id>/{role.json,prompt.md}`
      replace `registry/personas|roles`; closed schemas in `personas/`; `persona_registry.py` resolves
      paths; `tests/test_persona_folder_uniform.py` enforces the shape. Prompts and record hashes unchanged.
- [x] Stage roles red-team-adversary / blue-team-refuter / independent-verifier / scorer via
      `role_variants` + `claim-review-pool-cell.stage_roles`.
- [ ] William: confirm `prompt.md` as the rendered prompt section (generated) rather than hand-written
      prose, and the persona key set (the brief's role/jobs/model/budget/contract keys live on job
      templates and were not copied into personas).
- [ ] Add `persona_registry.py` to `execution_state.SHARED_RUNTIME` (brief I owns that file).
- [ ] No `hypothesis-hunter` role: the hunters already run as `vulnerability-hypothesis-hunter` (rename
      would change the hunter prompts; ADR-0024 open question).
- [ ] First live 07/08/09/12 pool run with the stage roles (each stage re-runs once: fingerprint moved).

## Retire legacy runners (ADR-0010 task V14, branch `retire-legacy-runners`)

Retired and deleted the legacy monolithic static prepass runners `pipeline/Invoke-VendorAuditPrePass.ps1` and `pipeline/Invoke-VendorAuditPrePass.sh` per ADR-0010 task V14:
- [x] Deleted `pipeline/Invoke-VendorAuditPrePass.ps1` and `pipeline/Invoke-VendorAuditPrePass.sh`.
- [x] Updated engagement callers `pipeline/engagement_job.sh` and `pipeline/engagement_job.ps1` to eliminate invocations of the legacy prepass scripts.
- [x] Updated `pipeline/README.md` to document that static analysis is decomposed into run-owned Dagster jobs (`02-*`).
- [x] Updated `docs/architecture/script-migration-inventory.md` closing rows 44 and 45 (`Invoke-VendorAuditPrePass.ps1` and `.sh`).
- [x] Updated `docs/decisions/ADR-0010-vendor-prepass-decomposition.md` and `docs/proposals/vendor-prepass/task-series.md` marking task V14 completed.
- [ ] Run-owned Dagster jobs (`02-*` nodes) continue providing individual tool evidence for full reviews.

## M: report completion (brief M, branch `report-complete`)

- [x] M1 CVSS v4.0 table diffed against FIRST `cvss-v4-calculator` `c5b0d40`: 270/270 entries, 204,976
      vectors, 0 mismatches (`data/reference/cvss/`, `cvss4_reference_check.py`, 1,500-vector offline sample).
- [x] M2 report section 3C "Threat model workbench" (data classes, LINDDUN privacy threats, deployment zones,
      attack-tree summaries); optional keys in `synthesis-report.schema.json`.
- [x] M3 job 03: required artifacts = output contract; template model and `worker_kind` `pool_coordinator`.
- [x] M4 ADR-0023 decision 9 aligned to the claim ledger (conflict = proof obligation, no `review_flags`).
- [x] M5 design note `docs/reachability-entry-points.md`; `reachability.PROGRAM_ENTRY_NAMES` adds
      `wmain`/`WinMain`/`wWinMain`/`DllMain` as entries (always on).
- [ ] M5 open: exported-symbol entries (needs linkage facts: exporter field or binary/IR export join, tunable
      default off) and CodeQL `EntryPoint` rows into the CPG engine; library functions shipped for other
      consumers should be UNKNOWN, not UNREACHABLE, once export facts exist.
- [ ] `docs/report-examples/appsec-review-sample.{html,pdf}` predate sections 3A-3C; re-render in WSL.
## I: dev-mode restart and generic executor (ADR-0025, brief I, branch `dev-executor`)

- [x] I1 dev-mode restart policy (`dev_restart.py`): `APPSEC_RUN_MODE=dev|prod` (default prod), content +
  shape hashes, REUSE/RERUN/REWIND, early cutoff, `--force <job>`, `launch_job.py --mode/--explain`,
  guard rails (dev receipts never evidence; `final_publication.publish` refuses dev). Operator doc
  `docs/dev-mode-restart.md`. Prod fingerprints unchanged (tests/test_dev_restart.py).
- [x] I2 generic item executor (`job_executor.py`, `items/<job>/item.json` + `input.schema.json` +
  `output.schema.json`): PRE resolve/validate/redact-stream/hash, PROCESS argv worker, POST validate,
  coverage/gap record, receipt (mode, evidence_grade, resume_from, rerun_command), pass-through
  normaliser, publication through `publish_job_output`. `02-operations-doc-ingest` ported; outputs
  byte-identical to the legacy worker (tests/test_job_executor.py).
- [ ] HOLD with I3: I2b registers item ops in `dagster_workflow.py` (`job_executor.register_item_ops`).
  `workflow.py` hashes `dagster_workflow.py` into the workflow-preparation branch fingerprints, so this
  one-line wiring reruns build discovery (and what follows it) once in prod.
- [x] I3 fingerprint scope audit (HOLD until the hello-autotools baseline finishes): 502 files are
  hashed by the per-job code lists; all are semantics (code, schemas, contracts, templates, prompts,
  rule sets). The only docs were 3 files in `job_graph.definition_hash` (phase-1 implementation
  spec, `00-intake-recovery/config.md` and `prompt.md`); removed. Only 00-intake's recorded
  definition hash changes once. ADR-0013 item 8 already keeps it out of intake staleness, so no job
  reruns.
- [ ] Controller decision (relaunch tax, not docs): `workflow.py` hashes `dagster_workflow.py` into
  every workflow-preparation branch, so any op wiring edit reruns build discovery and what follows.
  Four modules (`analysis_feature_lifecycle`, `control_feature_lifecycle`, `joern_cpg`, `test_evidence`)
  still hash SHARED_RUNTIME files (`publish_job_output.py` and others) without
  `drop_shared_runtime` (ADR-0013). Together they cover 15 jobs.
- [ ] Legacy lifecycles keep their prod fingerprint in dev too (no early cutoff: inputs pin upstream
  attempt ids). The win arrives per job as jobs are ported to the item executor.
- [ ] Container items: `job_executor.check_item` refuses `grants.container` until an item needs one
  (route through `container_execution` then). Network grants likewise.
- [ ] Brief K (registry move) must update the `registry/...` paths in `items/*/item.json`.
- [ ] The legacy CLI `operations_doc_ingest.py validate` does not accept executor attempts (different
  inputs record); consumers read `accepted.json` + `result.json` and are unaffected.
- [ ] Not run live: needs the code location started with `APPSEC_RUN_MODE=dev` in WSL.

## O: MITRE ATT&CK / CAPEC reference feed (ADR-0026, brief O, branch `mitre-feed`)

- [x] `mitre_feed.py` (sync/verify/resolve, pinned ATT&CK Enterprise v19.2 + CAPEC 3.9, carry-forward with the
      original `fetched_at`), `attack_reference.py` (derived `reference.json`, validator, `screen`), third op
      `mitre_sync_work` in `nvd_reference_sync`, tunable `reference_snapshot_max_age_seconds` (1209600) used by
      OSV and this feed, optional `attack_refs`/`capec_refs` at 07 (-> `mitre_refs`, carried to 12) and on lane-14
      chain links (rendered in the attack-chain section only); `scripts/smoke_mitre_feed.sh`; `docs/mitre-feed.md`.
- [ ] Operator (WSL): `python3 appsec-review-process/mitre_feed.py sync`, then `verify`, then
      `bash scripts/smoke_mitre_feed.sh`. Until the first sync every tag is withheld as `MITRE_REFERENCE_MISSING`.
- [ ] Prompt menu (after brief J, persona files under `appsec-review-process/personas/` are J's): give lane 14's
      composer and lane 07 vendor/insider mode (L5) a tactic-filtered technique menu or an `attack_reference`
      lookup tool, never the whole matrix in a prompt; tell the 07 reviewer and the composer persona the fields
      exist (today only the runtime `judgment_fields` block and the schema descriptions mention them).
- [ ] Show claim-level `mitre_refs` in the synthesis report (`synthesis_report.JUDGMENT_FIELDS` /
      presentation are brief M's); today they stop at the 12 scored records.
- [ ] CAPEC from `mitre/cti` is frozen at 3.9 (2023); if MITRE publishes a newer CAPEC only as XML at
      capec.mitre.org, add an XML source (not reachable from the build sandbox; verify the URL in WSL).
- [ ] Verify the ATT&CK and CAPEC terms-of-use text in `mitre_feed.NOTICE` against attack.mitre.org and
      capec.mitre.org (both blocked from the build sandbox; text is from MITRE's published terms).
- [ ] Shell literals of the 14-day ceiling remain in `orchestrator/prepare-host.sh`, `orchestrator/stage-run.sh`
      and the operator guide (`--max-database-age-seconds 1209600`); read the tunable there if wanted.
- [ ] Decision to confirm (William): stale/missing MITRE snapshot withholds tags as a gap (current) vs hard block.

## L: shared formats and stricter validator (brief L, branch `formats-2`)

- [x] `schema_validate.py` implements Draft 2020-12 assertions/applicators used or plausible here
      (length, numeric bounds, maxItems/uniqueItems/contains/prefixItems, object keywords, allOf/anyOf/
      oneOf/not/if-then-else, `format` date-time/date, `$ref` to `file#/pointer` and local `#/pointer`);
      any other keyword, format or remote `$ref` raises `UnsupportedSchema`. Shared runtime: no fingerprint moves.
      Previously ignored: minLength (335 uses), minimum (198), maxLength, maxItems, uniqueItems, maximum,
      if/then, allOf, oneOf, format; `#/$defs/...` refs (binary-cfg, debug-symbol-index,
      threat-model-reconciliation) crashed.
- [x] `schema_keyword_lint.py`: keywords used vs supported, bad `$ref`, patterns that do not compile.
- [x] `schemas/common/formats.schema.json` + `formats.py` (22 kinds); outside the hashed top-level schema set.
- [x] `schema_format_lint.py` + `schemas/common/inline-format-baseline.json` (1,025 inline copies in 268
      schemas, ratchet: new copies fail, converted copies must shrink the baseline).
- [x] `contract_derive.py`: orchestrator-owned fields derived from final vs persona schema; matches
      `attack_chain_derive._ORCHESTRATOR_KEYS` exactly. Not wired into any job.
- [ ] William: `threat-model-reconciliation.schema.json` `$defs/citation/properties/path` pattern
      `^[^/\\](?:[^\\]*[^/\\])?$` does not compile (the `\\]` escapes the bracket); validating any
      citation path raises. Fix = `[^/\\\\]` in three places. Edits a top-level schema (every job's
      definition hash moves). Allow-listed in `tests/test_schema_validate_keywords.py` until then.
- [ ] William: convert the 1,025 inline copies to `$ref` (top-level schema edits: every job's definition
      hash moves; `$`-anchored copies also start rejecting a trailing newline). One batch, then
      `schema_format_lint.py --write-baseline`.
- [x] William: `_ORCHESTRATOR_KEYS` drift the schemas show (an echo costs a repair round, not a note):
      `poc_fix_derive` misses `explanation_status`, `poc.reason`; `claim_review_derive` misses `citations`;
      `hypothesis_hunt_derive` misses `drop_reason`. Fixed in brief L2 (section below).
- [ ] William: `const`/`enum` still use Python equality (`0` passes `const: false`), as before. Strict JSON
      equality (`schema_validate.json_equal`, already used by `uniqueItems`) changes the rejection message in
      three tests owned elsewhere (owasp_dispatch, evidence_index_metrics, pool_rendezvous); no published bytes.

## L2: derive-list fixes (brief L2, branch `derive-fixes`)

- [x] `poc_fix_derive` and `hypothesis_hunt_derive` build `_ORCHESTRATOR_KEYS` with
      `contract_derive.orchestrator_keys` (record vs persona schema; the hunter keeps its echo-habit names on
      top); `contract_derive.py` joins lane 12b's and 07-hypothesis-discovery's implementation lists.
      `explanation_status`, `poc.reason` and `drop_reason` echoes are now dropped (poc-fix with a note).
- [x] `claim_review_derive` keeps a hand-written list, now with `citations` (decision and proof
      obligation; the ids an echo names still join `citation_ids`, behaviour unchanged). Generating it would
      list `contract_derive.py` in `claim_reviewer_pool.py`, which the intake persona-tool pool also hashes.
- [x] `tests/test_contract_derive.py` fails when any schema-derived field is missing from a derive list
      (KNOWN_DRIFT removed). Fingerprints moved: claim-review pool, 07-hypothesis-discovery, 12b only.
- [ ] `attack_chain_derive` (checked, no drift) and `owasp_validator_derive` (not in the drift test) still
      hand-write their lists.

## Breakage log

Newest first. One line per breakage: date, target, run id, job, what broke, fix (commit).

| Date | Target | Run | Job | Breakage | Fix |
|---|---|---|---|---|---|
| 2026-09-29 | (image build, WSL) | - | image_build audit-native | Wine layer: apt could not resolve `wine32:i386` because `liboss4-salsa-asound2` (temurin-21-jdk's `libasound2` provider) conflicts with `libasound2t64:i386`; audit-binary-analysis built OK | `4c375bc`: audit-native installs `libasound2t64` for amd64 and i386 in the Wine step (`WINE_EXTRA_PACKAGES`), apt replaces the shim; the step checks `java -version`. Reproduced and verified on ubuntu:24.04 in the cloud workspace |
| 2026-09-28 | appsec-multi-vuln | be3585 | (new) 07-hypothesis-discovery | Nothing read target code to propose vulnerabilities: the ledger held STRIDE templates, OWASP routes and tool leads only, so e.g. `eval(argv[2])` at `projects/javascript/case-010/index.js:2` (no tool lead) could never be reviewed; the red-team prompts were never loaded | Branch `ws-hunt` (ADR-0018): hunter persona pool (general + known-list red team, prompts renamed to `task-hypothesis-hunt-*.md`) over component shards with the P1/P2 lead menu; persona schema + `hypothesis_hunt_derive`; checkout-resolved `hypothesis-discovery.json`; ledger fourth source (`hunter:` claims; hypotheses on a P1/P2 lead line corroborate that claim). be3585 Python replay: strcpy + PHP include corroborate leads, eval = 1 hunter claim, hallucinated file = gap, 151 claims. OPEN: first live run (cost <= 3 x 2 USD default); specialist hunter personas not in the registry yet; different-class hypothesis on a lead line still attaches to the lead |
| 2026-09-28 | appsec-multi-vuln | be3585 (replay) | 10-synthesis-report | Report findings carried hard-coded CWE "Not asserted", no CVSS, reachability "unknown", no EPSS/KEV, no snippets, no remediation; severity was a factor bucket | Branch ws-report (ADR-0020): finding-enrichment.json from pinned CWE map/catalog, pinned CVSS v4.0, CPG reachability witness (Critical requires REACHABLE), offline EPSS/KEV snapshot, verified snippets, 11/12 remediation. Replay: case-001 main.cpp:7 -> CWE-121, CWE-120, CWE-676; CVSS:4.0/AV:L/.../SA:N 8.6 High; REACHABLE via main() main.cpp:4 |
| 2026-09-28 | freeciv21 | 3e7553f8 | 02-ir-facts | "IR facts attempted a prohibited verdict promotion": the guard substring-matched words like finding/severity anywhere in the serialized result, i.e. in freeciv function names and paths | Guard checks verdict-shaped keys only (ADR-0013 item 7); on review-batch |
| 2026-09-28 | appsec-multi-vuln | be3585 | claim-ledger-routing | Tool leads never became claims (ledger sources: threat model + OWASP routes only): 41 source-SAST + 119 native-SAST + 2 secrets + 15 IaC leads were unreviewed and 07/08/09 saw only 60 generic STRIDE hypotheses, so the report would be empty | Branch `claim-ledger-leads`: accepted source/native SAST, secrets, SCA, IaC and mobile leads are a third candidate source (merged per path:line, tiered P1/P2/P3, P3 grouped per file and ordered last, none dropped; absent/SKIPPED producers are coverage rows); routing marks source_kind/review_priority; the draft lists unverified tool leads. be3585 replay: 90 lead claims (P1 27, P2 48, P3 15) + 60 threat = 150. OPEN: 07/08/09/12 review every ledger claim in one reviewer instance (no count cap; report assembly requires every claim verified) - watch persona budget/cost on large targets |

| 2026-09-28 | (all) | - | 02-codeql-sast (new) | CodeQL never ran in the graph (ADR-0006 image only); freeciv21/doom3-bfg had no native SAST at all | Branch ws-sast: new job `02-codeql-sast` (codeql_sast.py, ADR-0017, always run, no license gate): one B13 container per detected language, `--build-mode none`, bundled `<lang>-security-extended`, SARIF -> leads (rule id, pinned rule name, CWE, path, lines, source hash; messages withheld); timeout/OOM/exit -> per-language gap; required edge into 02-evidence-assembly. OPEN: rebuild `audit-codeql` (lane script) and register its B16 record, else every language is an UNAVAILABLE gap; C# needs a .NET SDK in the image; claim ledger needs the `02-codeql-sast` producer row (below). Live qualification with audit-codeql:local: vuln.c fixture 7 cpp leads in 34 s; multi-vuln cpp 19, javascript 8, java 0, csharp failed (no dotnet) |
| 2026-09-28 | (all) | - | 02-source-sast | Only 4 repository C/C++ rules, so the lane always reported the generic rules gap | Branch ws-sast: 16 opengrep C rules vendored verbatim at f1d2b562 under `data/source-sast/opengrep-rules/` (LICENSE, NOTICE, hash lock `opengrep-rules.lock.json`; drift blocks), second `--config`, own tool id `semgrep-opengrep-rules-f1d2b562`, 8 new closed categories, optional `cwe` on leads, narrowed gap text. Live tool-semgrep 1.178.0: fixture 12 of 16 rules hit; multi-vuln +44 vendored leads |
| 2026-09-28 | freeciv21, doom3-bfg | abae7f4b, 22d32a79 | 02-license-scan | (the OPEN rows below) scancode TIMEOUT blocked the job | Branch ws-sast: `dependency_b13_adapters.tool_gap` (shared by adapter and worker): scancode TIMEOUT / OOM_KILLED / non-accepted non-zero exit publishes OK_WITH_GAPS with `LICENSE_SCAN_TOOL_GAP: ...`, zero records and `outputs/pinned-tool-gap.json` derived from the re-verified B13 attempt; no output hash is trusted; canceled/blocked containers and tampered attempts still block |
| 2026-09-28 | doom3-bfg | a8d9629d | 15-deployment-hardening | IaC scan pointer is SKIPPED (no IaC inputs); standards_lifecycle loaded it as a normal accepted result and refused it | A skipped IaC scan yields no deployment targets and a gap naming the skip reason |
| 2026-09-28 | appsec-multi-vuln | 5f5589f5 | 07-red-team-adversarial | Reached claim review (61 steps OK). All 60 pool decisions omit 4 of 10 reviewer identity fields (artifact_path ...) and give citations as bare ids: model-written bookkeeping | Branch claim-review-derive (not merged): the reviewer returns `{decisions: [...]}` per `claim-review-pool-persona.schema.json` (verdict text + citation/obligation ids); `claim_review_derive.py` stamps all 10 actor fields, resolves ids to the canonical upstream citation objects (a model-typed object is never published), copies obligation statements, serializes the assertion and pre-runs the stage rules so violations get a repair round. Replayed on the failed reply: 60/60 derive and pass red_team. Changes the deterministic-pool-merge (07/08/09/12) and persona-tool-pool-dispatch code hashes |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac (Dagster 7c6d6a0e) | 02-debug-symbol-index | `worker result validation failed: declared result artifact exceeds 33554432 bytes`: debug-symbol-index.json was 77 MB (12 binaries, ~54 MB of symbols) | Branch freeciv-native (b7b3dc35): scale-audit B records file. The result is a summary with `records_file` (path, sha256, count); symbols go to debug-symbol-index.records.jsonl, re-derived and re-hashed on validation. 02-binary-cfg hydrates the records in memory from the accepted attempt after hash/count checks. Nothing dropped |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac (Dagster 7c6d6a0e) | 02-binary-hardening | `schema:result: $.binaries[4].path ... (pattern)`: the redactor's high-entropy rule rewrote `unit-bb1dd96e77f4/build/freeciv21-modpack-qt` to a marker | HELD on branch freeciv-native (cdf5629b, redactor treats word+digits like `freeciv21` as a plain word). Not merged yet: it changes the redaction ruleset hash, so every run would re-run its vendor jobs and evidence assembly. Merge after hello/multi-vuln publish |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac (Dagster 7c6d6a0e) | 02-native-sast | `translation unit build/client/freeciv21-client_autogen/mocs_compilation.cpp does not resolve beneath its immutable attempt`: Qt AUTOMOC sources exist only in the build copy | Branch freeciv-native (94d83ade): compile entries whose path names nothing in the checkout (no component exists, none a symlink) are excluded and recorded (`generated-sources-not-in-checkout:<n>` plus up to 5 `generated-source-not-in-checkout:<path>`). A unit left with no sources is recorded (`unit-without-checkout-sources:<unit>`), and all-excluded runs follow the ADR-0014 SKIPPED path. Symlink/escape/hash checks unchanged |
| 2026-09-28 | freeciv21 | 20260928T005228Z-5b0fac (Dagster 7c6d6a0e) | 02-ir-capture | `compile entry source is missing: build/server/tests/test_server_cli_autogen/mocs_compilation.cpp` (30 of 395 entries are AUTOMOC outputs) | Branch freeciv-native (94d83ade): the same absent-from-checkout test gives a `generated-source-not-in-checkout` coverage gap per entry (OK_WITH_GAPS), and attempt validation accepts exactly those gaps. With zero modules, 02-ir-link already skips |
| 2026-09-28 | appsec-multi-vuln | 20260928T034921Z-be3585 | 04-asvs-masvs (join) | Join blocked: no accepted 04-owasp-validator-dispatch accounting because T03 lane-in, T04, T05 batching, T06 handoffs and T10 dispatch were never run by full_review. Also found: T05 refused an all-cannot_determine model ("routing rules match no selected proof obligation") and the join paginated its matrix quadratically | Branch owasp-dispatch: new owasp_workbench_lifecycle.py derives T03-T06 requests from accepted run evidence (ADR-0009 baseline ASVS 5.0.0 L2 selection, approver adr-0009-baseline, unless inputs/owasp-standard-selection.json exists) and runs T10 under the join's own facts (standards_lifecycle.prepare_owasp_join) with ClaudeCliInvoker; full_review runs job_04_owasp_validator_handoffs (cpu) then job_04_owasp_validator_dispatch (persona_llm) before job_04_asvs_masvs. Empty handoff set publishes an accepted EMPTY accounting; T05 unused-rule check skipped when nothing is assigned; join pagination made linear |
| 2026-09-28 | appsec-multi-vuln | 3a726581 | 04-asvs-masvs (join) | Passed input assembly (57 steps OK). Join needs an accepted 04-owasp-validator-dispatch accounting, but nothing runs that job: owasp_dispatch.dispatch (and the validator handoff/batching publication it reads) has no Dagster op in full_review | OPEN: wire validator batching + dispatch ahead of the join (branch owasp-dispatch) |
| 2026-09-28 | hello-autotools | 9de8ccea | 01-component-characterization | Model authored relationship id `report-runner--writes-to--logger` that is not the derived id | Relationship ids are always derived (from--type--to); duplicate edges dropped |
| 2026-09-28 | (all, pre-emptive) | - | 07/08/09 claim review | Found by the schema-format audit (tmp/schema-format-audit.md): claim_reviewer_pool passed pointer accepted_at (isoformat micros +00:00) as the permission-model now, which only takes whole-second Z; every real run would BLOCK. Tests used a Z fixture | Normalized to whole-second Z; test fixture now uses a real pointer stamp. Uniform formats work queued (audit proposal) |
| 2026-09-28 | freeciv21 | a63ffa38 | 01-component-characterization | Model map: `flake.nix` in no scope; a representative location that is not a target file; tag component ids unordered | ADR-0013 repairs before validation (`_repair_against_target`): tag ids sorted, foreign locations dropped, unscoped files become `scope:<path>` gaps |
| 2026-09-28 | hello-autotools, doom3-bfg | 3523ce6c, b8ae329f | 02-full-review-input-assembly | Derived plan `generated_at` was isoformat with micros/+00:00; schema wants whole-second `Z` (05-native-memory then failed on the missing assembly pointer) | `derive_plan` normalizes the stamp |
| 2026-09-28 | appsec-multi-vuln | fd86f0a4 | 02-native-sast | CSA container: compile-database `directory` is the unit's build dir (`projects/cpp/case-001/build`), which does not exist in the pristine checkout mounted at /workspace; subprocess cwd FileNotFoundError | OPEN on branch build-limits: adapter rebases a missing directory to its nearest existing ancestor (merge with the batch below) |
| 2026-09-28 | appsec-multi-vuln | fd86f0a4 | 02-binary-triage, 02-debug-symbol-index, 02-binary-hardening | Native build published CMake's probe executables (`CMakeFiles/<ver>/CompilerIdCXX/a.out`, `CMakeDetermineCompilerABI_*.bin`) per unit: identical content across units repeats a binary id (`bin_`+sha prefix), and the high-entropy redactor rewrote those paths so they fail the path pattern | OPEN on branch build-limits: replay runner skips `CMakeFiles/`; evidence core drops byte-identical repeats. Merge when hello's run ends (build/binary job fingerprints) |
| 2026-09-28 | appsec-multi-vuln | fd86f0a4 | 02-ir-facts | `ir-facts.json` 9.4 MB > `result_artifact_max_bytes` 8 MiB (debug_locations 3 MB, facts 4.9 MB, 45 linked cases) | Shared tunable raised to 32 MiB; split into summary + records file is the scale fix (docs/scale-audit B) |
| 2026-09-28 | hello-autotools | 73fe984c | 01-component-characterization | Model named a relationship endpoint that is not a component (`shell-report-runner--writes-to--tmp-hello-autotools-log`) | ADR-0013: unresolved relationship edges are dropped and recorded as classification gaps (`_drop_unresolved_relationships`) |
| 2026-09-28 | freeciv21 | a63ffa38 | 02-build-resolution | Retry with FREECIV_DOWNLOAD_FONTS=OFF under bear hit the 1800 s container timeout at 405/578 objects (2 CPUs, 2 GiB); dir:ai still a separate unit | Build jobs (resolution, configure, native build): 8 CPUs, 8 GiB, 2048 pids, 3600 s, and the staged controls take the timeout from the tunable (re-stage both controls for freeciv21). OPEN: dir:ai unit (classification) |
| 2026-09-28 | appsec-multi-vuln | 005628c6 | 02-native-build | (milestone) 9 units built, 25 binaries; result rejected: a direct-compile unit has one command and the schema required two (configure + build) | native-build `commands` minItems 1 |
| 2026-09-28 | hello-autotools, doom3-bfg | 832f8d4e, 9c2411a2 | 02-evidence-assembly | All 26 producer-binding model cells failed INVOKER_EXCEPTION: the new persona cache key json-dumped the frozen persona mapping (mappingproxy) and raised before any call. My bug; the unit test used plain dicts | Key thaws the persona (default=str); key and cache write are wrapped so a cache failure is always a live call; test uses a frozen request |
| 2026-09-28 | hello-autotools | ff976ec6 | 02-binary-cfg | accepted pointer input fingerprint mismatch: build_replay.py (native-build code) was merged at 12:15 while the run was past native build, so re-derived upstream inputs changed. Third time today | Process: merge job code only when no run is past that job (or accept a hello relaunch, ~3 min); shared-runtime merges are safe |
| 2026-09-28 | appsec-multi-vuln | 49e3637e | 02-build-configure | (milestone) 9 C/C++ units built after the cwd and -cc1 fixes; configure replay then failed on a unit with no configure step (empty locked phase read as a failed sequence) | Replay compares against the locked command count; configured-build `commands` may be empty |
| 2026-09-28 | hello-autotools, doom3-bfg | 928c1b47, d9704dea | 02-full-review-input-assembly (then 05-native-memory) | "dependency accepted pointer is invalid": the dependency jobs now publish the common pointer (hashes, accepted_at) and the assembly accepted only the older key set; native memory then found no assembly | Both pointer dialects accepted |
| 2026-09-28 | appsec-multi-vuln | d3c7cb66 | 02-build-resolution | With bear always on, clang's internal `clang-21 -cc1` re-exec was recorded as a compile command ("compiler is not the fixed clang path"), and one unit's bad DB failed the whole job | -cc1 entries dropped (resolution and replay); an unusable DB is that unit's gap |
| 2026-09-28 | freeciv21 | 14420f45 | 02-license-scan | scancode -n 4 finished in 30 min (6,098 files) but exited 1: three .blend files failed to scan | scancode exit 1 with "Some files failed to scan properly" and a complete output is accepted (adapter and worker share exit_accepted) |
| 2026-09-28 | hello-autotools | 928c1b47 | (milestone) | 54 steps OK: past component characterization, threat model, evidence index | - |
| 2026-09-28 | freeciv21 | 14420f45 | 02-build-resolution | (milestone) With -DFREECIV_DOWNLOAD_FONTS=OFF (added by the download-switch retry) freeciv21 BUILT on the 26.04 base; the unit still became a gap: "build succeeded but produced no compile_commands.json" because the cmake-export plan puts it in build/ and the trial runner only used bear for bear plans | The trial always runs the build under bear (the lock already records bear and the replay uses it) |
| 2026-09-28 | appsec-multi-vuln | 17b564af | 02-full-review-input-assembly | "staged target must be run-owned for dispatch": every fixture target lives outside the run | Dispatch from the run-owned, hash-bound source projection (automatic_evidence_inputs.source_projection) |
| 2026-09-28 | appsec-multi-vuln | 17b564af | 03-threat-model-dfd-stride | "F03 must cite exactly one substantive F02 assembly artifact; found 0": the component map cited only repository files | Bind the first cited upstream artifact, else the assembly's hash-bound intel-manifest.json |
| 2026-09-28 | appsec-multi-vuln | 17b564af | 01-component-characterization | (milestone) accepted for the first time on multi-vuln | - |
| 2026-09-28 | hello-autotools | 053e813a | 02-binary-intelligence-ingest | accepted pointer input fingerprint mismatch after mid-run merges | Relaunch (inputs re-derive) |
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

## Decisions 2026-09-29

All outstanding ADR questions, the brief I/J/M confirmations and the fuzz-entry alignment are resolved in
`docs/decisions/DECISION-LOG-2026-09-29.md` (controller decisions by William's delegation; he can override any row).
OPEN items that log leaves: CWE in the MITRE feed, exported-symbol entry points, stage 12 `scorer` wording, sample 3C
records and report re-render (WSL), image rebuild and smoke, brief N fingerprint-scope narrowing (D-13).

## P: sample report refresh (brief P, branch `claude/sweet-mccarthy-zb4at6`)

- DONE: `pipeline/report/sample_data.py` regenerates the sample's processes (81 jobs, 17 lane families),
  3A attack chains, 3B dependency reachability, 3C workbench records (real `threat_workbench.join` over
  `examples/hello-autotools.workbench-replies.json`), EPSS/KEV lines and lane-12 CVSS rows; `--check` and
  `tests/test_sample_report_data.py` guard drift. HTML re-rendered.
- OPEN: re-render `docs/report-examples/appsec-review-sample.pdf` in WSL (`bash pipeline/report/render-in-docker.sh`,
  then copy `build/report.pdf`); the README marks it stale until then.
- OPEN: `render.py` applies the native tier cap only to a family named `native`; the graph has no such lane, so the
  sample's assurance carries no tier cap.
- OPEN: 3A replays the lane-14 case-001 fixture, so its entry fact names `projects/cpp/case-001/main.cpp`.
## Q: exported-symbol entry points (brief Q, `entry_exports.py`, tunables default off)

- [x] Q1 `binary-summary` records `dynamic_exports` (ELF `.dynsym`, PE export directory; binding, visibility,
      version-hidden, `c++filt`-demangled, artifact kind, `complete`); `entry_exports` reads it hash-bound from the
      accepted `02-binary-triage` attempt and joins it uniquely to the CPG (`exported-symbol` roots,
      `ambiguous-export` escapes, not-in-CPG / unjoinable / incomplete-table gaps keep UNKNOWN). Finding enrichment
      uses it when `reachability_export_entries` is on. One entry-name table (`ENTRY_POINT_SOURCES["cpp"]["names"]`
      is `reachability.PROGRAM_ENTRY_NAMES`). Replaces the M5 open item for source 2.
- [x] Q2 `join_codeql_entries` (`(path, start_line)`, same snapshot, framework reasons only) and `CpgEngine(extra=)`,
      canned tables only (`reachability_codeql_entries`).
- [ ] Q3 WSL: rebuild `audit-binary-analysis`, run `bash scripts/smoke_entry_exports.sh`, then William decides the
      `reachability_export_entries` default.
- [ ] Exported-symbol roots for `06-reachability-ir` (needs a `02-binary-triage` input edge); source 3 live consumer
      (non-native `EntryPoints` tables); Mach-O exports; IR linkage facts for stripped binaries.

## N: tool-output cache and per-item memo (brief N, branch `caches`)

- [x] N1 tool-output cache (`tool_output_cache.py`, call site `dependency_b13_adapters.execute`):
  syft/grype/osv/scancode keyed by pinned request + adapter-computed content digests + mode; a hit is
  re-verified end to end (B13, output hash, receipt, permission) and recorded as `reused_from`;
  TIMEOUT/OOM gaps cached under the same limits only. Tunable `tool_output_cache` = dev (prod off).
- [x] N2 per-item memo (`item_memo.py`) for 02-build-plan units, today's validation re-run on a hit;
  unit id and root stated at both ends of the per-unit prompt. Tunable `item_memo` = dev.
- [x] N3 store `data/caches/` (git-ignored), size caps, pruning, `tool_output_cache.py stats|prune|clear`;
  docs in `docs/dev-mode-restart.md`.
- [x] N4 fingerprint scope (D-13): (a) build discovery hashes `dagster_workflow.py:branch_op` only, so
  the I2b op wiring no longer reruns build discovery; (b) analysis/control feature lifecycles,
  `joern_cpg`, `test_evidence` drop shared runtime. 14 jobs move once (3 + 7 + 1 + 3), plus the four
  preparation branches and, in prod, build discovery's consumers.
- [ ] Memo call sites not done: build-resolution units (image + plan commands + trial inputs; its
  receipts cite trials relative to the attempt, so a reused trial needs a cross-attempt receipt path)
  and IR/SAST invocations (ADR-0014 item 6, cross-run).
- [ ] `control_feature_lifecycle._code` hashes no per-job worker module (`completeness_audit.py`,
  `dynamic_rescope.py`, ...): an edit there does not rerun that job. Not changed (widening).
- [ ] Controller: set `tool_output_cache` / `item_memo` to `on` for prod after a live dev loop.
- [ ] Not run live (no Docker here): first dev relaunch of freeciv21 license-scan should show
  `tool-output-reuse.json` in the new orchestration attempt.
