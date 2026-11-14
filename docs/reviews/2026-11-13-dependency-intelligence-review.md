---
title: "Dependency and supply-chain intelligence subsystem review"
kind: "review"
subsystem: "scanners and evidence collection"
status: "current"
jobs: ["job_artifact_security_analysis", "job_dependency_intelligence", "job_evidence_collection", "job_inference_security_review", "job_review_data_indexing", "job_review_package_assembly", "job_target_catalog", "job_third_party_data_sync"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# Dependency and supply-chain intelligence subsystem review

## Charter and evidence boundary

Review date: **2026-11-13**. Reviewed code base:
**5926171238607e27a948bc7d40ce190a853b3d0c**, branch `main`.
`git merge-base --is-ancestor` and `git rev-parse HEAD` confirmed that exact base at
the start. The purpose is to improve the value of dependency intelligence from discovery
through reviewer decisions, not to audit this repository for vulnerabilities or commission a
target review. The [enhancement design](../architecture/dependency-intelligence-enhancement.md)
is **proposed, not implemented or approved**.

Integration note: T-146 subsequently landed on local main, verified at
`2612ee80f305970707520ad92774d1e1c1336c1c`. Its
[implementation record](../tasks/2026-11-13-behavior-oriented-review.md#implementation-and-verification-record)
supersedes references below to its in-flight status. This review retains its exact inspection
baseline; registration does not claim a fresh runtime or efficacy review of the later source.

The shared checkout had extensive unrelated documentation and documentation-test changes.
Those are owned by the documentation program and were neither edited nor used as proof of
runtime behavior. Source, typed contracts, central configuration and existing tests are the
authority for this review. Line references below refer to the reviewed code base; document
prose may change during reconciliation. No target, private answer key, production feed cache,
run artifact, model, scanner, container or live service was inspected or executed. Existing
tests were read, not rerun. Consequently this is **source-verified behavior and design analysis,
not observed deployment or target findings**.

The canonical backlog is [docs/TODO.md](../TODO.md). T-009–T-013 and T-098–T-106
remain authoritative, including the agreed build/topology-first sequencing. This review
refines them rather than commissioning competing discovery or matcher implementations.
T-129 owns the future intelligence-bucket taxonomy. No canonical bucket mapping existed at
review kickoff: proposed bucket names below are provisional, not retrieval-index names and
not the documentation program's eight subsystem labels.

## Executive assessment

The subsystem already has unusually strong native evidence custody, conservative release
claims, bounded model investigation, immutable SPDX publication and reference/evidence
separation. The principal value problem is **not the absence of another scanner**:

1. Several useful inventories do not converge: built-artifact Syft packages, installed
   package summaries and Unity SPDX additions do not all become normalized dependency entities.
2. Advisory information loses identity on the way to review. Source OSV/Grype projections omit
   version coordinates; artifact OSV findings use a shape the advisory join does not consume.
3. Inventory-only advisory facts are retrievable but are not independently admitted as review
   leads. Discovery, publication, indexing, lead admission and actual reviewer use are different
   coverage stages.
4. Dependency and Scorecard context is run-wide rather than selected for a build/component.
   The useful question—“which exact copy matters to this delivered artifact, and what remains
   to establish applicability?”—is not an explicit intelligence product.
5. Source release identification, advisory-range membership, patch applicability, delivery and
   attacker reachability need separate states. A current `applicability_verified` Boolean
   cannot convey all of them.

The recommendation is to finish the existing common-finder/unified-matcher program, preserve
its evidence controls, and add one consumer-oriented slice, **DEP-A**, for scoped dependency
decision packets, inventory-only lead routing and measured use. Design slice DEP-A is scheduled
as [T-149](../TODO.md#t-149-route-scoped-dependency-decision-packets-into-review-and-account-for-their-use).

## Source evidence register

These are bounded static reads, not execution results.

| Ref | Source and precise entry point | What it establishes |
| --- | --- | --- |
| S1 | [target catalog](../../src/appsec_review/jobs/job_target_catalog/job.py), `dependencies`, lines 306–337 | Only `package.json` dependency/devDependency extraction here; other recognized manifests get deferred-parser gaps; runtime declaration delivery remains unknown. |
| S2 | [source adapters](../../src/appsec_review/jobs/job_evidence_collection/adapters.py), `_syft_parser`, `_grype_parser`, `_osv_parser`, lines 606–645; registry lines 832–852 | Syft preserves coordinates; source vulnerability projections do not; Trivy is configuration scanning, not SBOM vulnerability matching. |
| S3 | [dependency job](../../src/appsec_review/jobs/job_dependency_intelligence/job.py), `_target_dependencies`, `_evidence_packages`, `build_job`, lines 143–181, 241–317 | Actual merge input sets and native curation/investigation ordering. |
| S4 | [native input integration](../../src/appsec_review/jobs/job_dependency_intelligence/integration.py), `collect_inputs`, lines 95–286 | Accepted membership/snapshot checks; detached protected input; source Syft bytes; explicit artifact-inventory-not-merged gap; separate Unity inventory. |
| S5 | [native discovery](../../src/appsec_review/jobs/job_dependency_intelligence/discovery.py), `_eligible`, `_vendor_root`, `_Discovery`, lines 99–126, 488–587, 747–809 | Catalog-bounded discovery; header literal checks; root scoping; independent claim/conflict/bound accounting. |
| S6 | [normalization](../../src/appsec_review/jobs/job_dependency_intelligence/resolution.py), `repository_identity`, `infer_maximal_exposure`, `normalize_dependencies`, lines 45–67, 148–282 | Repository URL parsing; conservative scope priority; current package/root dedup keys and retained projections. |
| S7 | [SPDX writer](../../src/appsec_review/jobs/job_dependency_intelligence/sbom.py), `build_spdx`, lines 573–914; [integration](../../src/appsec_review/jobs/job_dependency_intelligence/integration.py), `publish_sbom`, lines 402–490 | Preserved baseline relationships/conflicts, evidence-gated additions, fingerprints; effective native plus source-Syft/Unity publication, not every merged declaration. |
| S8 | [dependency datasets](../../src/appsec_review/jobs/job_dependency_intelligence/datasets.py), `DATASETS`, `CONTRACT`; [job publication](../../src/appsec_review/jobs/job_dependency_intelligence/job.py), lines 393–542 | Actual output kinds, inventory shard, evidence relations, optional historical native extension, accepted loader. |
| S9 | [artifact scanner](../../src/appsec_review/jobs/job_artifact_security_analysis/scanners.py), `ScannerAdapter.argv`, `scanner_input`, lines 119–172; [findings](../../src/appsec_review/jobs/job_artifact_security_analysis/findings.py), `_grype`, `_osv`, `_summary_observation`, lines 115–203 | File-mode Syft/Grype, npm record presentation, full native references versus bounded finding/summary projections. |
| S10 | [advisory links](../../src/appsec_review/indexing/links.py), `advisory_pairs`, lines 239–261 | Accepts top-level package/advisory or nested Grype matches, not artifact OSV's package-name/advisory-id fields. |
| S11 | [advisory products](../../src/appsec_review/indexing/products.py), `_resolved_version`, `_inventory_advisory_pairs`, `_build_dependency_advisories`, lines 348–475, 581–747 | Bounded lookup, optional range evaluation, joins, flags and eight-item provenance projections. |
| S12 | [OSV matcher](../../src/appsec_review/osv_matching.py), `ECOSYSTEM_ORDERINGS`, `_range`, `_entry`, `evaluate_record`, lines 40–44, 125–293 | Implemented SemVer range ordering, ecosystem ordering for npm/Go/crates.io; unsupported orderings/GIT ranges remain named uncertainty. |
| S13 | [review lead collection](../../src/appsec_review/review/lead_families.py), producer decisions lines 90–140, `collect_leads` lines 526–685 | Scanner observations produce dependency leads; dependency-advisory precomputed facts enrich existing leads rather than create inventory-only leads. |
| S14 | [review advisory projection](../../src/appsec_review/review/advisories.py), `advisory_facts`, `_advisory`, `context_for`; [units](../../src/appsec_review/review/units.py), `_engineering_context`, `build_units`, lines 51–92, 236–282 | Bounded reference facts and run-wide dependency/Scorecard context. |
| S15 | [package admission](../../src/appsec_review/review/packages.py), `admission_reasons`, lines around 260; context selection lines 1291–1315; [evidence](../../src/appsec_review/review/evidence.py), lines 59–75, 141–158 | KEV/severity admission, role-balanced context cap, and indirect-only dependency/advisory facts. |
| S16 | [feed pinning](../../src/appsec_review/jobs/job_review_data_indexing/job.py), `feed_pins`, lines 116–162; [feed publication](../../src/appsec_review/jobs/job_third_party_data_sync/publication.py), `publish_snapshot`, `verify_current` | Verified immutable snapshots and provenance; stale feeds explicitly marked, not automatically refreshed by review. |
| S17 | [runtime consumption](../../src/appsec_review/runtime/consume.py), `accepted_upstream`, lines 149–192; [source scan identity](../../src/appsec_review/jobs/job_evidence_collection/job.py), lines 417–435 | Typed admitted pins and observed reads; scanner reuse includes input, image, parser, normalizer, release and settings identities. |
| S18 | [final report](../../src/appsec_review/jobs/job_final_report_publication/job.py), `build_job`, lines 72–118; [OpenVEX projection](../../src/appsec_review/jobs/job_openvex_export/projection.py), `assemble_export`, lines 84–151 | Final publication consumes the accepted gate; OpenVEX projects publishable claims, not all packages or unmatched advisories. |
| S19 | [native telemetry](../../src/appsec_review/observability/telemetry.py), `_native_sbom_metrics`, lines 1322–1479 | Work, reuse, accepted inventory, publication and native inference accounting; not dependency-specific reviewer usefulness. |
| S20 | [configuration](../../appsec-review.toml), lines 148, 1129–1143, 2586–2641, 2867–2869, 2912–2923; [container catalog](../../containers/catalog.toml), lines 473–481 | Grype disabled; indexed OSV matching disabled; model/native inference enabled; bounded Scorecard; cve-bin-tool scan image deferred. |
| S21 | [Composer installed catalog](../../src/appsec_review/jobs/job_language_build/php.py), `InstalledCatalog`, lines 237–325; [Go installed catalog](../../src/appsec_review/jobs/job_language_build/go.py), `VendoredCatalog`, line 642; [npm](../../src/appsec_review/jobs/job_language_build/node.py), `_InstalledCoverage`, line 285 | npm, Go vendor records and Composer installed records already have build-output summarization; this is not equivalent to merged dependency coverage. |
| S22 | [input matrix](../../src/appsec_review/indexing/input_matrix.py), `INPUT_SOURCES`, lines 52–61, 91–118 | Declared input-source routes; a matrix “current” row does not establish a successful launch, complete merge or model use. |

## Current end-to-end map

1. **Catalog.** The accepted source partition binds source paths, hashes, sizes and exclusions.
   The dependency subcatalog publishes declarations separately from components and delivery
   scope. It is not a universal lockfile parser (S1).
2. **Build and artifact evidence.** Accepted language receipts expose protected command rows,
   workspace manifests, package-manager metadata and installed summaries. Artifact indexing
   exposes built and target-intake artifacts. The artifact security job applies delivery lanes,
   format applicability and bounded scanners; npm installer records avoid redundant per-package
   Syft/Grype scans (S9, S21).
3. **Source scans.** Syft scans `dir:/target`. Source Grype, when enabled, consumes that original
   Syft JSON, not the enriched native SPDX. Source OSV launches per selected project/lockfile
   against offline ecosystem snapshots. Trivy parses misconfigurations (S2).
4. **Dependency merge.** The job reads declarations, source-Syft observation entities, and
   authenticated source/workspace/command/artifact native inputs. Deterministic discovery runs
   before bounded curation and metadata investigation; repository inference then handles
   unresolved native candidates. Scope-local native copies survive normalization (S3–S6).
   The contract also declares C/C++ inputs/scheduling, but `collect_inputs` and `load` actually
   read the four producers in S4. Permission and scheduling are not proof those C/C++ payloads
   were used.
5. **Two related publications, not one equivalent inventory.** Normalized dependency entities
   are built from declarations/source Syft/native candidates. SPDX is built from converted source
   Syft, effective native discovery and Unity enrichment. `publish_sbom` does not consume the
   normalized dependency list. A package can therefore exist in one publication but not the other.
   SPDX baseline relationships survive; dependency instances do not yet have a general
   root-to-package-to-delivered-artifact relationship graph (S7–S8).
6. **Repository practices.** Canonical repository groups share bounded Scorecard retrieval/cache
   work; exact response bytes are retained per run and fanned back to dependencies. Practices are
   contextual, never evidence that a package is vulnerable or that its bytes came from that repo.
7. **Indexing.** Accepted shards are composed and audited. Package/advisory links and the
   `dependency_advisories` precomputed product join source/artifact scanner matches and dependency
   inventory OSV candidates to pinned OSV/NVD/KEV/EPSS. Name-only lookup is intentionally uncertain.
   Default inventory lookup does not evaluate versions (S10–S12, S16).
8. **Review and reporting.** Dependency scanner findings become leads. Severity and configured
   KEV admission determine lane A; lane B receives ranked units and dependency context.
   Precomputed inventory matches alone do not instantiate such leads. Citations are re-resolved
   under strict evidence admission; publishable claims traverse the final gate and report.
   OpenVEX is a projection of that gate, not a dependency-VEX inventory exporter (S13–S18).

### Producer-to-consumer intelligence matrix

Output kinds and routes here are implemented identifiers; “available” means a supported route,
not a claim that a particular run produced or read it.

| Intelligence | Producer/output kind and disposition | Actual retrieval/consumer route | Published but unavailable or unused limitation |
| --- | --- | --- | --- |
| Declared dependencies | Target catalog `catalog_documents`, artifact-only dependency subcatalog | Dependency job `_target_dependencies`; source inventory remains separately queryable | Most recognized manifest formats not extracted in this catalog path; declaration gaps are not returned by `_target_dependencies`. |
| Source Syft package coordinates | Evidence collection `static_tool_observations`, indexed; `static_tool_evidence`, raw publication | `observations` → `_evidence_packages` → `inventory`/`dependency-intelligence`; raw source JSON → SPDX converter | First package location only in adapter; package graph/scope is not carried through the flat observation projection. |
| Installed/resolved packages | Language `language_build_receipts`, `build_workspaces`; artifact index `artifact_catalog` | `artifacts`, `query_artifacts`; npm record scanner attribution | npm/Go/Composer build summaries are not common-finder records; presence in artifact indexing does not make them normalized dependencies. |
| Artifact Syft inventories | Artifact security `artifact_security_results`, artifact-only; `artifact_security_observations`, indexed summaries | Raw native result references; `observations`/`artifact-security` summaries | Summary intentionally removes package array; dependency contract does not consume artifact-security output. `artifact_inventory_not_merged` is explicit. |
| Native identities/versions | Dependency `native_discovery`, `native_component_curation`, `native_metadata_investigation`; effective `dependency_context` | `inventory` dependency/observation entities, `find`, `trace`, `read_excerpt`, `resolve_evidence` | Source, detached workspace and command evidence remain distinct; inferred/conflicted versions cannot become asserted SPDX releases. |
| Native SPDX and provenance | `native_spdx`, `native_sbom_provenance`, artifact-only | Accepted handoff and evidence-artifact references from inventory | Not current Grype input; artifact SBOMs not merged; a general dependency-relationship query is not materialized. |
| Scorecard practices | `scorecard_responses`, artifact-only; `dependency_context`, indexed review signals | Inventory search/find; run-wide review context | Model-inferred repository remains uncertain; no measured package relevance/use; not a severity or vulnerability assertion. |
| Source vulnerability matches | Evidence collection `static_tool_observations` | `observations` → advisory links/precomputed product → dependency-advisory leads | Source coordinate projection loses version/PURL; configured Grype does not launch. |
| Artifact vulnerability matches | Artifact security `artifact_security_observations` | Observation leads; nested Grype matches → advisory products | OSV finding shape is not recognized by `advisory_pairs`, so lead can exist without feed enrichment. |
| External advisory/prioritization data | Third-party sync shared immutable snapshots; external `feed_snapshot` input uses `appsec-review/public-feed-use/1` | Indexing feed pins → `dependency_advisories`; `query_precomputed` | Snapshot publication is separate from sync work output `feed_sync_work`; cve-bin-tool database publication does not establish an enabled binary scan consumer. |
| Inventory-only advisory candidates | Review-data indexing precomputed product | `query_precomputed(query_set="dependency_advisories")`, indirect reference facts | Queryable and bounded, but no dedicated candidate-to-lead adapter in `collect_leads`; “lead” in producer comments is not lane-A admission. |
| Dependency outcomes/metrics | Existing review ledger, package audit, final gate; native SBOM/inference telemetry | Generic review/report and telemetry readers | No dependency-specific funnel from observed instance through matched/scoped/read/cited/dispositioned; final report is not a full SBOM coverage report. |

## Findings and recommendations

“Verified” below means established by source/control-flow inspection. It does not assert an
observed bad finding, exploit or production incident.

| ID/status | Deficiency and evidence | Product consequence | Scheduling treatment |
| --- | --- | --- | --- |
| D1 — verified disconnect | S4 explicitly emits `artifact_inventory_not_merged`; S9 drops Syft package bodies from summaries; S8 has no artifact-security input. S21 installed summaries remain in another shape. | Built-only or installed dependencies can be found by tools but absent from normalized identities, Scorecard and inventory-driven advisory lookup. | Refine T-099/T-011/T-102; consume authenticated artifact results, not sanitized summaries as if complete. |
| D2 — verified mismatch | S3 normalized dependencies and S7 SPDX have different input lists; `unity.enrich_unity_spdx` enriches only SPDX. | “Merged inventory,” SPDX package count and indexed dependency count are not interchangeable. Matcher coverage over SPDX alone would miss declarations; index-only matching can miss SPDX-only additions. | T-099 defines one common observation truth and accounted projections; T-105 declares exactly which projection each matcher receives. |
| D3 — verified identity loss | S2 source OSV/Grype omit version/ecosystem/PURL; S10 assigns `version=None,purl=None` for flat package/advisory records. | Versioned matches lose specificity, fail to coalesce with versioned inventory facts, and cannot reliably select a package instance. | Refine T-099/T-105 to preserve scanner coordinates and native selectors end to end. |
| D4 — verified join disconnect | S9 artifact `_osv` emits `package_name`, `package_version`, `advisory_id`; S10 recognizes neither these nor the original OSV `results` shape. | Artifact OSV findings still enter review, but lack the accepted advisory join, KEV/EPSS context and NVD severity fallback through that route. | Add a focused producer→join regression to T-105; fix the bounded pair adapter before assessing precision. |
| D5 — verified consumer gap | S11 can produce inventory-only advisory facts; S13 loops observation leads and control assessments, not dependency-advisory facts. | Newly discovered vendored/header-only inventory may nominate a CVE without a corresponding review package. Raising scanner recall alone may not reduce review misses. | DEP-A explicitly routes normalized matcher nominations without granting them evidence authority. |
| D6 — verified scope limitation | S14 appends all dependency/Scorecard entries to every review unit; S15 balances roles then caps at configured 64 entries. S6 defaults unknown exposure to `PROD`. | Relevant copies compete with unrelated packages; conservative priority can be mistaken for deployment; repeated context consumes budget. | T-099 preserves instance/build/delivery relations; DEP-A selects scoped packets and counts exclusions/truncation. |
| D7 — verified semantic weakness | S11 marks `applicability_verified = scanner_reported or range_matched`, including scanner pairs missing a version. S14's bounded advisory projection does not preserve this Boolean, lookup basis or version-match evidence. | “Scanner reported,” “affected range” and “target is affected” are not independently visible at the reviewer boundary. Existing indirect-evidence rules prevent this flag alone from proving a claim. | T-105 replaces ambiguity with separate typed states; DEP-A carries them intact. Do not equate this with a demonstrated false positive. |
| D8 — verified general-normalizer limitation | S6 groups nonnative rows by exact PURL or folded name/version, drops most raw nonnative fields and uses first nonempty version/repository; it has no general per-field conflict set. Native and SPDX paths have stronger conflict treatment. | Same coordinates in separate managed installs can be flattened; conflicting values for one PURL can disappear from the normalized representation; cross-ecosystem name collisions remain ambiguous. | Refine T-099 with instance identity, corroboration and conflict-preserving projections; keep package coordinate identity separate from physical copy. |
| D9 — verified repository parsing limitation | S6 `repository_identity` accepts at least two URL path components but retains only the first two; `gitlab.com` is allowed by S20. | A valid subgroup/project URL can be reduced to the wrong repository, producing wrong/missing practices context. Canonicalizing a URL is not proving package-origin equivalence. | Include forge-specific namespace parsing and uncertainty in T-099 normalization acceptance; do not broaden network hosts. |
| D10 — verified coverage fragmentation | S3 `_target_dependencies` returns dependency rows, not its subcatalog gaps; S4 inherits partition/build/artifact/Syft gaps, not that dependency-parser gap list. S19 measures production/work, not dependency review use. | Some gaps remain upstream rather than dependency-scoped; complete shard publication cannot answer inventory recall or actual reviewer utilization. | T-099 preserves finder eligibility/completion/exclusions; DEP-A reports a stage-by-stage funnel and unknown denominators. |
| D11 — implemented but disabled/incomplete | S20 disables Grype and indexed OSV version matching. S12 supports only specified orderings; S2 Trivy is IaC-only; cve-bin-tool scan image remains deferred. | Tool catalog/feed availability overstates effective matcher coverage if read without config and actual receipts. | T-009 is implemented; retain T-013/T-102/T-103/T-105/T-106 activation and evaluation boundaries. |
| D12 — design gap, not an observed defect | S5 corroborates a local release string; S11 evaluates upstream advisory data; neither proves whether a vendored fork contains a vulnerable change or a backport. S7 preserves baseline dependency relationships, while S8 indexes derivations rather than a full instance/use graph. | Version-only matching cannot settle patched forks, static-link participation, affected configuration or reachable use. | T-105 preserves unresolved applicability; DEP-A supplies a bounded target-evidence investigation packet. No automated “not affected” from missing graph edges. |

### Configured, optional and live-unverified distinctions

- **Configured path:** dependency model and native inference are enabled; deterministic fallback
  and named inference gaps exist. No model availability was tested.
- **Configured bounds:** 100,000 normalized dependencies, 10,000 native candidates, 2,048 native
  roots, 50,000 native evidence records; 256 physical native-inference calls per stage;
  Scorecard 10,000 requests, 1 MiB response, seven-day cache age and **two retries** in central
  configuration. Older prose saying one retry does not override the configuration.
- **Disabled implementation:** Grype is disabled for source and artifact scanning;
  `osv_version_matching = "disabled"` is the shipped default. Profiles change model settings,
  not those switches in the inspected configuration. An uninspected run overlay may differ.
- **Optional/reference:** Scorecard success depends on a resolved supported repository, cache
  or permitted remote response. Failure does not discard the dependency.
- **Existing but not consumer-complete:** Grype snapshot synchronization code and indexed OSV
  matching exist in this base. CPE lookup, Trivy SBOM matching and the cve-bin-tool scan adapter
  remain scheduled work. A cve-bin-tool database builder is not its scan adapter.
- **Live-unverified:** no claim here that the nightly is currently stopped/running, feeds are
  fresh/stale on this host, images exist, or a specific target inventory is complete. T-106's
  historical operational observations remain attributed to that task, not reobserved here.

## Representative traces

These are source-derived case analyses, not executed fixture or customer-review results.

| Case | Actual path and useful output | Where value currently stops; required distinction |
| --- | --- | --- |
| Managed lockfile plus npm install | Lockfile → source Syft/OSV; package.json declaration → catalog; a recipe-written npm record → installed summary → artifact index → one scanner launch per supported record. Source Syft coordinates enter dependency inventory; source OSV findings enter leads. | Declared constraint is not installed release. Source match loses version in projection; installed/artifact Syft view is not merged. Unknown delivery cannot be inferred from runtime dependency naming alone. |
| Vendored native library/header-only copy | Cataloged `dependencies/lib/...` header/document → root-scoped native evidence → curation/investigation → independent identity/release/upstream claims → SPDX addition and inventory entity. A successful build is not needed once required upstream handoffs are admitted. | A generic/no PURL record falls to name-only OSV lookup; CPE matching is pending. An inventory-only advisory is not a lead package. Catalog vendored-component ownership and delivery linkage remain T-098 work even though native discovery recognizes `dependencies/`. |
| Conflicting/unknown release | Contradictory native literals → conflicted claim and version gap → no asserted native SPDX release. ABI/filename hints remain inferred. A versioned PURL conflicting with a normalized version becomes `version_identity_conflict` in optional OSV range matching. | General managed normalization does not preserve all competing claims. No range result is not “unaffected”; unsupported ordering, unknown version and zero matches are different states. |
| Statically linked binary | Accepted artifact → format/native inspection and bounded Syft/Grype capability; retained link/archive/loader evidence can identify candidates; no target execution. | No NEEDED entry is expected for a static copy; absence is not exclusion evidence. Binary Syft packages do not merge and cve-bin-tool scan adapter is deferred. Component identity does not show inclusion of vulnerable functions. |
| Patched vendored fork | A literal upstream version may be correctly corroborated and associated with an advisory; exact source/file artifacts remain available to review. | Local release label does not prove upstream-equivalent bytes. No explicit patch applicability product establishes the fix or vulnerable construct. Refutation needs accepted local evidence and review adjudication, not version string or fork naming. |
| Two builds/copies, one repository | Root-scoped native copies remain separate; repository dedup shares one Scorecard fetch. SPDX retains conflicting baseline records. | Managed PURL grouping may collapse copies; global context cannot identify the affected build. Share advisory/Scorecard reference work, not delivery, patch or reachability decisions. |

## Strengths and invariants to preserve

- Accepted membership, source snapshot, size/hash and path custody checks; instrumented admitted
  upstream reads. A declared input or manifest route is not an actual read receipt.
- Native identity/release/upstream states are independent; corroboration comes from bounded
  literal evidence, not model confidence. Retain conservative originals when inference fails.
- Physical root separation, detached workspace evidence, exact selectors and model-attempt
  accounting. Do not substitute current workspace bytes for run-owned evidence.
- SPDX 2.3 official schema plus semantic validation; baseline metadata/relationships and
  conflict records survive enrichment. Keep unknown fields honest.
- Scorecard repository-level dedup/cache with exact response retention, deterministic bounds,
  controlled host policy and named operational gaps.
- Reference-only advisory/practices semantics; no package name, CVSS, KEV, EPSS or exposure
  heuristic can satisfy target proof obligations alone.
- Scanner failure/unsupported/bounded scope remains visible; per-finding observations are
  distinct from inventory/scan summaries; reuse does not manufacture new work or coverage.
- Final report and OpenVEX depend on accepted adjudication/gates, not direct scanner-to-report
  shortcuts. Preserve existing signing and worker authorization.

## Existing tests and documentation reconciliation

The following tests provide **intended contract evidence**, not new pass results:

- [dependency tests](../../tests/test_dependency_intelligence.py): repository dedup/cache,
  exposure conflicts/defaults, nonexact model proposals and accepted publication.
- [native SBOM job tests](../../tests/test_native_sbom_job.py): buildless catalog, source-Syft
  publication membership, tampering, conversion failures, detached workspace selectors,
  zero-with-coverage and task reuse.
- [OSV tests](../../tests/test_osv_matching.py): strict SemVer, unsupported orderings,
  withdrawn advisories, missing ecosystem coverage, PURL/version conflicts and default-disabled
  behavior.
- [indexing tests](../../tests/test_review_data_indexing.py): inventory-to-advisory facts,
  unverified applicability and rule-change invalidation. The test calling the fact a “lead”
  does not test its admission by `collect_leads`.
- [review advisory tests](../../tests/review/test_advisory_enrichment.py): NVD/KEV/EPSS
  enrichment, KEV admission, EPSS non-admission, bounded context and reference-only semantics.

Existing prose/TODO refinements should be coordinated, not silently rewritten during this
review: T-009 is already done at code/unit level; T-013's “not merged” text no longer describes
this base; T-011's “Composer next” text lags the implemented `php.InstalledCatalog`.
T-105's agreed permission to match discovered native versions as **leads** supersedes the
older native-SBOM design prohibition as a future design decision, not as evidence that runtime
matching is already wired. T-099 remains the registry/merge owner; T-129 remains the bucket
mapping owner.

The companion design defines precise contracts, producer/consumer changes, sequencing,
independent evaluation labels and measurable acceptance. This review deliberately makes no
claim that unit, integration, acceptance or live review behavior passed during this assignment.
