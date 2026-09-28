# Unimplemented / stubbed inventory (read-only audit, 2026-09-28)

Scope: `main` at `1ca9bdbb`, compared with branch `review-batch` (ADR-0015 tool leads as ledger
candidates, supporting-evidence menu, `claim_review_derive.py`), which is treated as implemented
and not listed. Kill chains / attack trees are listed as **in design** only (ADR-0016 being drafted
separately).

Headline facts:

- **Wiring is complete, depth is not.** All 67 `job-graph.json` jobs have a real Dagster op in
  `full_review` (no `blocked_op` remains; `dagster_workflow.py:1571-1636`). OWASP T03-T06 handoffs
  and T10 dispatch are now run ahead of the `04-asvs-masvs` join (commit `0a5a5b5d`).
- **Most "analysis" after evidence gathering is deterministic Python, not model reasoning.**
  `03-threat-model-dfd-stride` (`threat_model_core.py`, no model call; `attack_trees`,
  `abuse_scenarios`, `deployment_zones` hard-coded empty at line 237), `05/06/13`
  (`analysis_feature_lifecycle.py` / `bounded_analysis_workers.py`), `11-remediation-proposal`,
  the five control features (`dynamic_rescope.py` 39 lines, `completeness_audit.py` 19,
  `synthetic_hypothesis_resynthesis.py` 32, `remediation_retest.py` 36, `evidence_quorum.py` 55)
  and `10-synthesis-report` are all thin deterministic cores. The only model reasoning over security
  claims is one `claim-reviewer` instance per stage (07/08/09/12, `claim_reviewer_pool.py:199`
  `max_instances: 1`).
- **Nobody generates new hypotheses from code.** The ledger's candidates are threat-model STRIDE
  hypotheses, OWASP routes and (on `review-batch`) tool leads. No persona reads the code to propose
  vulnerabilities; the rich lane prompts in `appsec-review-process/07-red-team-adversarial/`
  (`general-red-team.md`, `known-list-red-team.md`, `known-issue-catalog.md`) are referenced by no
  `.py`, job template or prompt fragment.
- **Report findings are skeletal.** `synthesis_report_presentation.py:128-140` emits every finding
  with `cwe: "Not asserted by retained draft"`, `cvss: None`, `reachability: "unknown"`,
  `epss: None`, `kev: False`, `snippets: []`, `remediation: "No remediation assertion ..."`.
  Severity is a score bucket (`claim_lifecycle_core.py:503-506`), not CVSS 4.0.
- **`tests/test_design_parity.py` (5 failures on main)** are stale expectations, not missing
  features: job count 66 vs 67 (two tests), a stale generated `design-parity-readiness.md`, and two
  fixtures that assume `02-native-sast` is still a `blocked_op`/unassigned pool. Fix = regenerate
  views and update fixtures (S). The manifest itself reports 57 jobs `implemented_not_qualified`,
  10 `implemented_and_qualified`, and 14 of 16 capabilities `implemented_not_qualified`.

Priority key: **P0** blocks a meaningful report; **P1** major quality gap; **P2** scale/robustness;
**P3** nice-to-have. Size: S (< 1 day), M (1-3 days), L (> 3 days).

## Top 15

| # | Item | Area | State | Pri | Size |
|---|---|---|---|---|---|
| 1 | Code-reading hypothesis discovery (L4/L5 red-team *discovery* persona(s), per partition/component, feeding the ledger) | review/claims | absent | P0 | L |
| 2 | Finding enrichment in the report: CWE, code snippet, location context, remediation text, reachability, CVSS vector | synthesis/report | stub (hard-coded nulls) | P0 | M |
| 3 | Claim-review sharding / multi-instance pools (07/08/09/12 run one instance for all claims; 150+ claims on multi-vuln, thousands at scale) | review/claims | stub (`max_instances: 1`) | P0 | M |
| 4 | Threat workbench (ADR-0008): T05 pool/wave runner, T07 join, T08 validator, workcell personas; model-driven DFD/STRIDE, abuse scenarios, attack trees | threat modeling | designed-only (schemas + T06 intercom module exist, no caller) | P1 | L |
| 5 | Kill chains / attack trees / cross-lane chains (L14) and verified-fact graph (`verified-facts.jsonl`) | synthesis / threat modeling | in design (ADR-0016) | P1 | L |
| 6 | Remediation proposals surfaced in report; L11 patch proposal + validation | synthesis/report | partial (objectives only; report says none) | P1 | M |
| 7 | CVSS 4.0 scoring with EPSS/KEV/exposure (L8) | review/claims | stub (score buckets) | P1 | M |
| 8 | Model-bookkeeping derive registry for remaining contracts (OWASP validator result, component map lineage, closed `downstream_lanes` vocabulary, evidence-binding model call removal, build classify/plan stamping, D01-D04) | formats/validation | designed (tmp audit §4-5); only claim review done on `review-batch` | P1 | M |
| 9 | Source SAST coverage: vendor 16 opengrep C rules + more languages' rules; SAST gap text | evidence: SAST | decided, not done (TODO:76) | P1 | S |
| 10 | Uniform formats (`formats.schema.json`, `formats.py`, validator keyword coverage: minLength/maxLength/minimum/format, `$` anchor, local `$defs`) | formats/validation | designed-only (schema-format audit §5) | P1 | M |
| 11 | Lazy hash-verified input serving + no per-call staging copy | scale | absent (scale audit A, priority 1) | P2 | M |
| 12 | Records-file pattern for every large producer (source/native SAST, IR facts, SBOM, binary intel, build index) + streaming consumers | scale | partial (CPG, debug symbols, binary core only) | P2 | L |
| 13 | ADR-0014 remaining: per-unit native-SAST failure isolation, link-command capture, plan-driven tests, `depends_on`, shards, content-addressed reuse | evidence: native | partial (slice 1 done) | P2 | L |
| 14 | Tool-timeout-as-gap (scancode) and OSV ecosystem snapshots beyond npm | evidence: SCA | open (TODO breakage rows 208, 234) | P1 | S |
| 15 | Partition code signals (opengrep structural rules before partition discovery / component characterization) | evidence: SAST / threat modeling | decided, not done (TODO:85) | P2 | M |

## Per-area detail

Impact columns: **4T** = impact on the four current targets (hello-autotools, appsec-multi-vuln,
freeciv21, doom3-bfg); **Scale** = a modern game engine (Unreal-sized).

### Threat modeling

| Item | Planned | State | Depends on it | 4T impact | Scale impact | Size | Pri |
|---|---|---|---|---|---|---|---|
| Threat workbench subworkflow: waves 1-4, architecture/data/deployment modelers, STRIDE enumerator, abuse analyst, attack-tree builder, challenge cell, join, validator | `docs/decisions/ADR-0008-threat-workbench.md:3,91-100`; `docs/proposals/threat-workbench/task-series.md` (T05, T07, T08, T09) | designed-only. Schemas `threat-workbench-cell-result`, `-wave-manifest` have no producer; `threat_workbench_intercom.py` (T06) is imported by nothing | 07 hypotheses quality; report threat-model section; ADR-0016 | 03 is deterministic templating from the component map: DFD + generic STRIDE per boundary flow. multi-vuln got 60 generic build-flow hypotheses (ADR-0015 context) | Generic STRIDE per flow explodes with component count and says little | L | P1 |
| Abuse scenarios, deployment zones, data classes populated | `threat_model_core.py:237` (empty lists); schemas `threat-model-abuse-scenario`, `-deployment-zone`, `-data-class` | stub | report, 07, 15-deployment | Sections empty in every report | same | M (with workbench) | P1 |
| Attack trees / kill chains | `threat-model-attack-tree.schema.json`; ADR-0008 wave 2; ADR-0016 (drafting) | **in design** | L14 synthesis, exec summary | No chain narrative | Essential for a game (client/server trust, anti-cheat, mod loading) | L | P1 |
| V08 fill threat-workbench producers | `docs/proposals/vendor-prepass/task-series.md:136` | not done (M01-gated sources into workbench) | workbench | - | - | M | P2 |
| Partition-level code signals feeding characterization | `appsec-review-process/TODO.md:85` | absent | 01, D01 partition discovery | Component maps built from file lists + prose | Needed to route 100K files | M | P2 |

### Review / claims

| Item | Planned | State | Depends on it | 4T impact | Scale impact | Size | Pri |
|---|---|---|---|---|---|---|---|
| Hypothesis discovery persona(s) (L4/L5 general + known-list red team) that read code/evidence and add ledger candidates | `docs/architecture/design-v3.md:125-126,160`; lane prompts `appsec-review-process/07-red-team-adversarial/*.md` (unused) | absent. 07 only reviews existing ledger claims | every verified finding not already a tool lead | Report can only contain tool leads (after ADR-0015) and generic STRIDE; logic/authz/protocol bugs never appear. multi-vuln answer key will score low | Critical: a game's real bugs (netcode, parsers, save files) are not tool leads | L | P0 |
| Specialist attacker/defender personas | `docs/personas-and-registry/persona-catalog.md` (~52 personas); registry has 17 | 49 catalog personas have no registry record (e.g. native-exploitability-engineer, protocol-rfc-lawyer, supply-chain-attacker, insider-developer, defensive-skeptic, evidence-only-verifier, dependency-reachability-skeptic, completeness-auditor, synthesis-integrator, scoring-prioritization-reviewer, remediation-planner) | discovery, 08/09 independence | 07/08/09/12 all use the single `claim-reviewer` persona; red/blue/verifier independence is by prompt only | Domain specialists needed for engine code | M per persona batch | P1 |
| Claim-review sharding / multiple instances per stage | `claim_reviewer_pool.py:199` (`max_instances: 1`); ADR-0015 consequences (branch `review-batch`) | stub | 07-12, report | multi-vuln 60 → 150 claims in one reviewer call per stage; bigger targets will time out or budget out | Blocking (thousands of leads); also pool limit 64 instances (scale audit D) | M | P0 |
| P3 lead policy (group/skip code-quality leads) | ADR-0015 consequences (review-batch) | designed | review cost | Cost/time | Required | S | P2 |
| CVSS 4.0 / EPSS / KEV / exposure scoring (L8) | `design-v3.md:130` | stub: `claim_lifecycle_core.py:497-510` maps a numeric score to P0-P3 buckets; EPSS/KEV present only as presentation placeholders | report severity | No defensible severity | same | M | P1 |
| CVE reachability (06) beyond applicability receipt | `design-v3.md:159` (L1 full scope) | partial: deterministic join of SCA matches + optional IR facts (`analysis_feature_lifecycle.py:99-150`); no call-graph reachability; EOL/abandonware (`data/eol-reference.json`) has no Python consumer | 07 SCA claims, report | SCA findings unprioritised | High dependency count | M | P1 |
| 05 native memory, 13 fuzz triage | `design-v3.md:158,166` | partial: deterministic `bounded_analysis_workers.native_memory` / `fuzz_triage` scoring; no model | 07 | Few native claims beyond CSA leads | Important for C++ engines | M | P2 |
| Escalation model / post-escalation re-verification | `design-v3.md:485-501` | absent (no code references "escalation") | L7 re-verification | none now (static only) | - | M | P3 |
| Streaming L7 verification (verify as findings arrive) | `design-v3.md:230-234` | absent: stages run as a batch chain | latency | none | Throughput at scale | M | P3 |

### Synthesis / report

| Item | Planned | State | Depends on it | 4T impact | Scale impact | Size | Pri |
|---|---|---|---|---|---|---|---|
| Finding enrichment: CWE, code snippet, location context, remediation text, reachability | `synthesis_report_presentation.py:128-140` hard-codes nulls | stub | reader value of every finding | Findings show title + one location + score only | same | M | P0 |
| Remediation proposals into report; L11 patch proposal + isolated validation | `design-v3.md:133,522-529`; `remediation_proposal.py` (objectives only, no patch), `remediation_retest.py` (36 lines) | partial | report remediation section | "No remediation assertion" on every finding | same | M (text) / L (validated patches) | P1 |
| L14 cross-lane synthesis over a verified-fact graph (`verified-facts.jsonl`) | `design-v3.md:136,403,503-505` | absent (no code references) | exec summary, chains | Report is a list, not a synthesis | Needed for large finding sets | L | P1 (in design with ADR-0016) |
| Executive/stakeholder outputs (product-owner, dev-lead, executive-risk-briefing personas) | `persona-catalog.md:1098-1206` | absent | exec audience | Technical report only | - | M | P2 |
| SARIF export in `full_review` | `critical_findings_sarif.py` (standalone Dagster job, not in `job-graph.json`) | partial | CI consumers | No SARIF from a full run | 4 MB input cap (scale B) | S | P2 |
| Human finalization gate | `final_publication.py` (317 lines, human signoff ledger) | implemented, never exercised live (`final-publication-gate` capability `no_live_qualification`) | final report | Draft only (acceptable per ADR-0013) | - | S | P3 |
| Unverified-lead appendix | ADR-0015 item 6 | on `review-batch` (not listed) | - | - | - | - | - |

### Evidence lanes

| Lane | Item | Planned | State | 4T impact | Scale impact | Size | Pri |
|---|---|---|---|---|---|---|---|
| SAST | Vendor 16 opengrep C rules, map ids, widen category enum, narrow gap text | `TODO.md:76` | decided, not done (4 own C/C++ rules only) | C/C++ targets (all four) under-covered; permanent gap line | same | S | P1 |
| SAST | Findings into the evidence index (FTS + columns) for source/native SAST, secrets, IaC, container, mobile, binary hardening | `docs/scale-audit-unreal-engine.md` "Indexing coverage" | absent (16 producers indexed, these not) | Reviewers can't search leads | Required | M | P2 |
| Native | Per-unit analyzer failure = unit gap | `TODO.md:118` | open | one bad unit fails native SAST | frequent at scale | S | P1 |
| Native | Records JSONL + index for per-invocation IR/SAST | `TODO.md:122`; ADR-0014 item 5 | absent | ir-facts already 9.4 MB on multi-vuln (limit raised to 32 MiB) | breaks | M | P2 |
| Native | Link-command capture, link-target level, plan-driven tests, unit `depends_on`, parallel shards, reuse cache | ADR-0014 items 4, 6, 7 | absent (one link target per run fallback) | Only one linked target analysed per run | breaks | L | P2 |
| Native | freeciv-native branch (4 commits ahead): redactor word+digits fix held | `TODO.md:178` | held | freeciv21 binary hardening path pattern | - | S | P1 (merge after hello/multi publish) |
| Native | `dir:ai` sub-project unit classification | `TODO.md:191` | open | freeciv21 duplicate unit | - | S | P2 |
| Binary | Binary records files beyond debug symbols (triage, cfg, intel), MAX_RAW_BYTES 16 MB | scale audit B | partial | - | breaks | M | P2 |
| SCA | License scan tool timeout → license gap, not block | `TODO.md:208` | open | doom3/freeciv21 scancode risk | breaks | S | P1 |
| SCA | OSV snapshots for Go, Maven, crates.io, NuGet, Packagist, PyPI; surface missing ecosystems as SCA gap | `TODO.md` target notes, row 234 | open (npm only) | multi-vuln non-npm OSV coverage is a gap (Grype still matches) | - | S | P1 |
| SCA | NVD snapshot binding into `02-sca-vulnerability-match` | `docs/evidence/sca-nvd-snapshot-binding.md:3` | model/resolver only | CVE enrichment | - | S | P2 |
| SCA / L12 | Native/vendored supply-chain inference (tier B, vendored cJSON etc.), provenance/SLSA/SSDF | `design-v3.md:134,173-210` | absent (no SLSA code) | hello-autotools vendored cJSON; doom3/freeciv vendored libs invisible to L1 | Engines vendor heavily | L | P1 |
| Secrets / IaC | Implemented (gitleaks, checkov, trivy-config, tfsec, kube-linter, hadolint) | `vendor_evidence_workers.py:33-39` | done | - | redaction limits (scale B) | - | - |
| Container | Build and scan Dockerfile images (package/CVE inspection) | `vendor_evidence_workers.py:36-37,50-52` | partial: only pre-existing `*.tar`/OCI archives are inspected; Dockerfiles get hadolint + base-image inventory only | multi-vuln has 6 Dockerfiles, no image contents scanned | - | M | P2 |
| Mobile | mobsfscan Android/iOS | `vendor_evidence_workers.py:39` | done (no targets exercise it) | n/a | - | - | P3 |
| Test | Test execution for 0..N units with self-staged control (hello needs manual `stage-control`) | `TODO.md` (OPEN row about operator control), operator guide | partial | test evidence only for hello | - | M | P2 |
| Docs / intel | `qa-intel-merge`, `intel-search-index`, `intel-lane-bridge` jobs | `docs/evidence/intelligence-sources-and-jobs.md:518-600` | absent (not in job graph) | Minor for these targets | - | M | P3 |
| Docs / standards | Standards corpus indexed (requirement text FTS) | scale audit "Indexing coverage" | absent | OWASP/STIG reviewers can't search requirements | - | S | P2 |
| Semantic | LanceDB semantic recall worker | `docs/evidence/semantic-recall-lifecycle-plan.md` (`implemented: false`) | designed-only | - | Useful at scale | M | P3 |
| L10 | Static protocol/parser/wire-format analysis | `design-v3.md:132,479-483` | absent (no harness lane) | freeciv21 network protocol, doom3 netcode unreviewed | Core for multiplayer games | L | P1 |
| L13 | Privacy / data protection | `design-v3.md:135` | absent | low for these targets | Telemetry/accounts in modern games | L | P3 |

### Build lane

| Item | Planned | State | 4T impact | Scale impact | Size | Pri |
|---|---|---|---|---|---|---|
| Offline apt package lookup (or one repair round with apt error) for build-plan | `TODO.md:240` | open | freeciv21 wrong package names | - | M | P2 |
| State the unit id in per-unit plan prompt; Python stamps `plans[0].unit_id/root/class` | `TODO.md:227`; bookkeeping audit item 9 | open | wrong-unit plans (9/38) | - | S | P1 |
| Pre-slice classification/index/catalog into `plan-unit.json` | `TODO.md:132` | open | 871 `input_jq` calls | cost | S | P2 |
| Windows/MSVC build (clang-cl + xwin) in the run | ADR-0003; `TODO.md` doom3 note | not in `full_review` (Linux build only; doom3 = gaps) | doom3 native lane empty | UE is Windows-first | L | P2 |
| Per-target size class for build/SAST/Joern container resources; UE `Setup.sh` dependency fetch | scale audit C | absent (fixed 8 CPU / 8 GiB / 3600 s) | ok | breaks | M | P2 |
| Local caching proxy for downloads | ADR-0012:149 | deferred | - | - | M | P3 |

### Orchestration / infra

| Item | Planned | State | Size | Pri |
|---|---|---|---|---|
| Per-item memo in loops (build-plan units, resolution units, IR/SAST invocations) | `TODO.md:149` | absent | M | P2 |
| Pinned-tool output cache (scancode, syft, grype, semgrep) | `TODO.md:151` | absent (60 min scancode re-runs) | M | P2 |
| Fingerprint scope audit (`_code_hashes` include non-semantic files) | `TODO.md:153` | open | S | P2 |
| Retire legacy runners (`02-evidence-pregather`), V14 | `vendor-prepass/task-series.md:197` | open | M | P3 |
| `UnsupportedWorkerAdapter` kinds ("specified but not implemented") | `worker_adapters.py:117-121` | stub | S | P3 |
| Downstream handoff dispatch in `review_cli.py:821`, `create_handoff.py:116`, `validate_lane_output.py:64`, `phase1.py:510` message | legacy CLI paths | stub (superseded by Dagster) | S (delete) | P3 |
| Concurrent-run limit enforcement (`OUTER_LIMITS` = 2, ran 3) | scale audit D | unverified | S | P3 |

### Formats / validation

| Item | Planned | State | Size | Pri |
|---|---|---|---|---|
| Shared derive registry (`derive.py`), persona-facing schemas, fixed envelope keys, persona-schema hash in cache key | `tmp/model-bookkeeping-audit.md:324-395` | designed; only claim review (item 1) on `review-batch` | M | P1 |
| OWASP validator result derive (item 3) | bookkeeping audit §3.10 | designed | M | P1 |
| Component map lineage out of model schema; closed `downstream_lanes` vocabulary (60 free-text lanes seen) (items 4, 5, 7) | bookkeeping audit | designed; ad hoc repairs exist | M | P1 |
| Drop evidence-producer-binding model call (item 6) | bookkeeping audit | designed (reply is overwritten anyway) | S | P2 |
| `formats.schema.json` + `formats.py` + lint; validator enforces minLength/maxLength/minimum etc.; `\Z` anchors; local `$defs` refs | `tmp/schema-format-audit.md:214-313` | designed-only | M | P1 |
| Single source for skip reasons / status enums | schema-format audit risk 8 | designed | S | P2 |
| Accepted-pointer schema | schema-format audit risk 3 | absent | S | P2 |
| Pre-existing test failures: `test_vendor_prepass_graph` (16), registry test on `02-native-sast`, 5 stale design-parity tests | `TODO.md:93`; test run 2026-09-28 | open (stale expectations) | S | P3 |

### Scale (Unreal-sized)

From `docs/scale-audit-unreal-engine.md` ("Nothing here is fixed yet except where noted"); verified
still open on main:

| Item | Where | State | Pri | Size |
|---|---|---|---|---|
| Lazy hash-verified input serving; no per-call staging copy | `persona_invocation`, `claude_cli_invoker._stage_inputs_for_mcp` (`:217`) | absent | P2 (P0 for UE) | M |
| Evidence index file/byte caps raise | `evidence_store.py:370,399` | still raises (tunable) | P2 | S |
| Intake 4 GiB fingerprint cap; scope excludes for fetched deps | `intake.py` | open | P2 | S |
| Records-file pattern for all large producers | only `joern_cpg`, `binary_evidence_core`, index enrichment use `records_file` | partial | P2 | L |
| Build index 512 KB, SARIF 4 MB, handoff 16/64 MB, IR 64 MB, redaction 2,000 files | scale audit B | open | P2 | M |
| Partitioned Joern / SAST / native analysis | scale audit C | absent | P2 | L |
| Pool fan-out 64 instances / 32 groups | `pool_specification.py:101,553` | open | P2 | S |
| `input_grep` over FTS for whole-repo searches | `TODO.md` Retrieval and IO | open | P2 | S |
| IO audit for native-build/replay and CPG (2.8-4.0 GB) | `TODO.md:136` | open | P2 | S |

### Personas / registry

- Catalog vs registry: 49 of ~66 catalog personas have no `registry/personas/*.json`. The 17 that
  exist are all used by at least one job template. The missing set is almost exactly the attacker,
  domain-specialist, defensive/verification, synthesis and stakeholder personas that the review
  and report stages need (see Review/claims and Synthesis above). Size: M per batch of personas
  plus job-template/role wiring; P1 for attacker/verifier personas, P2 for stakeholder outputs.
- Lane prompt folders `00-15` (`config.md`, `prompt.md`, `subprompts.md`) are the design-v3 §4.1
  "tracked LLM prompt harness", but the Dagster workers for 03, 05-13 and 15 do not load them
  (deterministic or single claim-reviewer task prompt). P1 as part of item 1.
- ADR-0009 status is still **Proposed**; report/finding promotion and per-engagement scope decisions
  remain open (`ADR-0009-owasp-control-workbench.md:3-5`). P2.

## Notes on what is NOT missing

- Every graph node has a worker; OWASP dispatch wired; claim-review timestamp and identity fixes
  (identity on `review-batch`); build-limits fixes merged (CSA directory rebase, CMake probe skip);
  persona result cache; IO prune; ADR-0014 slice 1 zero-skips.
- Kill chains / attack trees: listed as in design only (ADR-0016).
