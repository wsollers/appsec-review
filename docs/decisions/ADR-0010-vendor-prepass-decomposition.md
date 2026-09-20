# ADR-0010: Vendor-Prepass Decomposition Into Run-Owned Evidence Jobs

Status: **Accepted 2026-09-20** (see Decisions). This closes the M01 design gate only. No worker,
tool, schema, registry record, graph node, graph edge, skip reason or readiness claim follows from
this document. Both legacy runners keep their current behavior until the task series below lands.

Date: 2026-09-19 (drafted); 2026-09-20 (gate decisions)

## Decisions

Recorded 2026-09-20 from the user's answers to gates G1–G10. Two differ from the packet's
recommendation (G3 source, G10) and their consequences are stated here rather than left implicit.

| Gate | Decision |
|---|---|
| G1 Granularity | **B.** Nine family nodes; each tool keeps its own template, attempt and `accepted.json` under `data/jobs/<node>/<tool-id>/`. |
| G2 SBOM/SCA home | **A.** `02-*` pregather producers joined at `02-evidence-assembly`. design-v3 §4's "06 = full L1 scope" wording is now stale (follow-up). |
| G3 SCA data | **A, with the source named by the user: the NVD copy under `/data`**, i.e. the immutable snapshot published by the existing `nvd_feed.py` publisher. No live lookup, no `api.osv.dev`, no new OSV publisher. Consequences: (1) V09 is no longer a new publisher; it binds `02-sca-vulnerability-match` to the current NVD snapshot pointer. (2) NVD is CPE-keyed, so matching ecosystem packages (npm, PyPI, Go, NuGet, Maven) is weaker than an OSV-keyed match; every match record carries `match_basis: cpe` and every SBOM component that cannot be mapped to a CPE is a **coverage gap**, never "no known vulnerabilities". (3) The legacy `osv-scanner` cannot consume a raw NVD feed, so the matcher was reopened as a V05/V11 tool-selection item. **That item is now closed by M1–M5 below, which supersede three statements in this row:** the NVD copy is no longer the matcher's source, there ARE new out-of-run publishers, and match records are not `cpe`-only. The NVD snapshot and its V09 binding stay, for `06-cve-reachability` enrichment and as an independent cross-check. |
| G4 Package restore | **A now, B later.** Never restore in the SBOM job; manifests and lockfiles only. Resolved dependencies from accepted build output may be layered in later. |
| G5 Inapplicability | **A.** New skip reason `not-applicable-no-matching-inputs` (shared-surface change to `worker-result-contract.json`, task V02). |
| G6 Mobile gating | **A.** In-worker probe. The option-only node `02-mobile-applicability` is **not adopted**. |
| G7 BinSkim | **A.** Separate supplied-binary node `02-binary-hardening`. |
| G8 Supplied images | **A.** Static archive-only `02-container-image-inventory`; no registry pull. |
| G9 Redaction | **A.** Every scanner-backed producer redacts at its own publication boundary and emits a redaction receipt. |
| G10 `cloc`/`scc` | **B.** Fold language/size metrics into `02-evidence-index` enrichment; one enrichment replaces both steps. Consequence: this touches an implemented, qualified worker, so it changes that worker's executable identity and needs requalification (task V15). |
| ADR number | **0010 kept.** |
| M1 SCA matcher | **Pinned syft + Grype image; the Grype vendor database mirrored into `/data`.** Decided 2026-09-20 from `docs/proposals/vendor-prepass/sca-matcher-options.md`. A new out-of-run publisher (task V16) downloads the Grype DB archive, records its identity (vendor build timestamp, schema version, sha256) and publishes it immutably in the `nvd_feed.py` pattern. The scan job runs with database auto-update disabled and **no network**. Grype consumes the syft SBOM natively and matches by purl/ecosystem **and** CPE. Trivy was considered and not chosen for SCA: it matches language packages from its own `trivy-db`, not from NVD. The native in-repo CPE matcher is **not** adopted. Consequence: "known vulnerable" rests on a third-party aggregated database that is pinned and hashed but not authored here; its licence and attribution terms are reviewed before V11 ships. |
| M2 OSV source | **Build BOTH** the Grype DB mirror publisher (V16) **and** an independent offline OSV snapshot publisher (V17), before V11. OSV is kept as a second, independent source even though the Grype DB already carries GHSA/OSV-derived advisories. Each publisher has exactly one fixed network destination, authorized as a B11 capability **outside any engagement run**. |
| M3 purl→CPE rules | A versioned rule table in the repo was chosen before M1 was refined. Under M1 = Grype there is no in-repo CPE matcher, so the table has **no consumer and is not built now**; the answer stands if a native NVD cross-check is added later. |
| M4 Database age policy | **No age limit by default**: a job uses whatever static snapshot is present and always records its age. A job or engagement **may set a tighter `max_age`**; exceeding it is **`FAILED`**. This supersedes V09's original acceptance line ("older than policy ⇒ `OK_WITH_GAPS`"). "No limit" is an explicit, required argument value (`NO_AGE_LIMIT`), never a default, and the worker resolves the database in preflight **before** reuse admission so a cached `OK` is never reached with an over-age database. Implemented for the NVD binding in the same change as this row; V16/V17's bindings follow the same rule. |
| M5 Gaps → threat workbench | The `sbom-sca-license-lifecycle` source family receives **matches plus an aggregated gap summary** (counts by ecosystem and reason; the full per-component list by reference). |

Backlog: `TODO.md` M01 (`READY`, now decided); unblocks M03, M04, M05, D09, M07 and — through ADR-0008
Decision 5 — S02. Companion packet: `docs/proposals/vendor-prepass/`.

ADR number: `0010` is the next number that is free in every sense. `docs/decisions/` on `main` and
on every remote branch holds 0001–0004, 0006, 0008, 0009. `0005` (CTP_Nov2013 shim vs Tier B) and
`0007` (allocator inventory) are unwritten but reserved by `docs/status-2026-09-16.md` and the two
`docs/continuation-prompt-2026-09-14*.md` files. The M01 continuation prompt names
`ADR-0007-vendor-prepass-decomposition.md`; this packet deviates from that one filename to avoid
the reservation collision and records the deviation in the continuation checkpoint.

## Context

`scripts/Invoke-VendorAuditPrePass.ps1` and `.sh` are one monolithic orchestrator that runs 37
named steps in sequence inside toolbox containers and writes a shared `static-evidence/` tree plus
a `MANIFEST.json`. The repo owner's 2026-09-19 instruction (`TODO.md` §8) is that it is **not**
replaced by a single Python orchestrator: each tool becomes a job that communicates like every
other job in the graph (`accepted.json`, `attempts/<id>/`), orchestrated by Dagster.
`job-graph.json` declares `02-source-sast` for source scanners but has **no node** for secrets,
IaC, SBOM/SCA, license, container, binary hardening or mobile SAST. `AGENTS.md` forbids a
compatibility wrapper.

ADR-0008 Decision 5 made this packet a hard prerequisite of the threat model: four `m01_gated`
source families in `docs/proposals/threat-workbench/input-sources.proposal.yaml` carry
`producers: []` until M01 names node IDs and contract IDs.

### What reading both runners established

- Both runners declare the **same 37 step names**; no step is platform-only. Six steps differ in
  semantics between the twins (see "Cross-platform discrepancies").
- **No step is network-isolated.** Both runners call `docker run` with default networking. `sca`
  (`osv-scanner`) queries a live vulnerability service; the eight Semgrep steps fetch `p/...` rule
  packs from the Semgrep registry (the PS1 history records a registry 404 breaking a whole run);
  `checkov` and `trivy config` can download policy bundles. None of this is recorded as a
  permission. Under `docs/design-v3.md` §2.1 and B11 default-deny, every one of these is a
  decision, not an inherited behavior.
- **Every image is a mutable local tag** (`audit-iac:local`, `audit-container:local`,
  `scancode-toolkit:local`, and the `-ImageTag` default). `images/audit-container/Dockerfile`
  itself says Trivy is installed from a floating install script. No legacy identity can be carried
  forward as verified.
- **Secrets leak through non-secret scanners.** The `evidence-scrub` note records, verified live,
  that Semgrep and mobsfscan SARIF embed the raw matched source line, including literal secret
  values. `gitleaks --redact` protects only gitleaks' own output. A whole-tree scrub that runs last
  is the wrong boundary for run-owned evidence: by then the value already sits in an accepted
  attempt and in `02-evidence-index`.
- **"Zero inputs" was reported as success.** The mobile steps count any `*.java`/`*.kt`/`*.m` file
  as a mobile candidate and append a "treat as NOT-SCANNED" warning to a text file that nothing
  reads. `dockerfile-lint` and `docker-base-images` deliberately have no expected output.
- **There is no supplied-container-image step.** The legacy `audit-container` image ships Trivy,
  but no step runs it against an image. Supplied images are in scope per design-v3 §2.1/§17.
- `cloc`, `scc`, `weggli-note` and `spotbugs-note` have no consumer in any lane prompt or graph
  node; the two `-note` steps write a static usage string and analyze nothing.

### Where the new evidence sits in the graph

`02-evidence-assembly` is the pregather barrier (`join_policy.mode:
all-required-terminal-accepted`, `require_explicit_skip_receipts: true`, `failure_is_not_skip:
true`). `01-component-characterization` requires it; `03-threat-model-dfd-stride`,
`06-cve-reachability` and `15-deployment-hardening` require `01`. Anything a `03`-or-later lane
needs from the prepass must therefore be an `02-*` producer joined at assembly. Nothing proposed
here depends on `01-*`, `03-*` or any later node, so no cycle is possible.
`15-deployment-hardening` and `06-cve-reachability` are consumers only.

The five registered skip reasons in `worker-result-contract.json` are `no-debug-symbols`,
`not-applicable-after-partition-review`, `not-applicable-non-native`, `not-requested`,
`not-requested-no-scorecard-projects`. The `forbidden_promotions` enum in
`schemas/output-contract.schema.json` is closed: `finding | severity | runtime-state`.

## Options

Each option block ends in a numbered gate. The fixtures under `docs/proposals/vendor-prepass/`
encode the **recommended** answer to each gate so they are internally consistent; a different
answer changes the fixtures as noted, and nothing is decided until the user answers.

### G1 — Node granularity

- **A. One graph node per tool** (≈16 new nodes: `02-secrets-gitleaks`,
  `02-iac-checkov`, `02-iac-trivy-config`, …). Most literal reading of "each tool becomes a job".
  Every tool gets its own assembly edge, contract and skip policy. Cost: 16 new required `wait_all`
  edges on the busiest join, 16 contract files that differ only in tool name, and a graph edit
  (shared surface) every time a tool is added or swapped.
- **B. One graph node per evidence family, with one attempt-bearing tool instance per tool beneath
  it** (9 new nodes). This is the shape `02-source-sast` already has (one node, D09 delivers
  "per-tool worker(s)"). Each tool instance is still its own job in the owner's sense — its own
  registered template, its own `attempts/<id>/`, `accepted.json`, permission decision, identity and
  terminal status under `data/jobs/<node>/<tool-id>/`, the same two-level layout
  `00-workflow-preparation/<branch>/` already uses. The node's accepted output is a deterministic
  aggregate (`tool-results.json` + `coverage.json`) that preserves successful siblings and reports
  each failed or blocked tool as a named coverage gap. A family splits into more than one node
  wherever **failure, applicability, permissions or claims differ** — which is why SBOM, SCA,
  license and lifecycle are four nodes and supplied images are separate from IaC.
- **C. One aggregate `02-vendor-prepass` node.** Rejected without a gate: it is the hidden generic
  scanner node M01 forbids and contradicts the owner's instruction. Listed only for completeness.

Recommendation: **B**. It keeps per-tool isolation and provenance, keeps the assembly join
readable, and lets M03–M05 add or replace a tool without a shared-surface edit. Its cost is that
the per-node aggregate must be specified once (task V03) and must never report a node `OK` while
hiding a failed tool.

> **Gate G1.** Node granularity: per-tool nodes (A) or per-family nodes with per-tool instances (B)?

### G2 — Where SBOM / SCA / license / lifecycle live

`docs/design-v3.md` §4 currently says `06-cve-reachability` was "broadened 2026-09-17 to full L1
scope: dependency inventory, license inventory, … EOL/abandonware signals … and CVE reachability
triage", and `06-cve-reachability/config.md` reads `static-evidence/sbom|sca|license/`.

- **A. `02-*` pregather producers joined at assembly; `06` consumes them transitively and owns only
  reachability triage.** Matches M05 ("separate SBOM, dependency lifecycle, vulnerability database,
  and license producers … do not claim reachability"), ADR-0008 Decision 5, and the split between
  evidence production and analysis. Requires a follow-up wording fix to design-v3 §4.
- **B. Tool steps inside `06-cve-reachability`.** Matches today's design-v3 text. But `06` is an
  analysis lane downstream of `01`; `03` has no edge to it and ADR-0008 says the workbench "never
  waits for it". The `sbom-sca-license-lifecycle` family could not be filled and S02 stays blocked.
  It also mixes deterministic tool evidence and persona reachability judgement in one contract.
- **C. As A, plus direct declared edges from `06-cve-reachability` to the four `02-*` producers.**
  Makes freshness explicit for `06` instead of relying on the intel manifest. More shared-surface
  edits; ADR-0008 left the equivalent question for the workbench to its T10 integration task.

Recommendation: **A**, leaving direct edges (C) to L03's integration task.

> **Gate G2.** SBOM/SCA/license/lifecycle: `02-*` producers (A), inside `06` (B), or `02-*` plus
> direct `06` edges now (C)?

### G3 — Vulnerability data source for SCA matching

- **A. Offline snapshot.** `02-sca-vulnerability-match` has network denied and consumes an
  immutable, hashed vulnerability-database snapshot published by a separate asynchronous reference
  publisher, the same pattern as `nvd_feed.py` / `reference_snapshots.py`. Snapshot id, timestamp,
  hash and age enter the input fingerprint. Missing snapshot ⇒ `BLOCKED`; stale beyond policy ⇒
  `OK_WITH_GAPS`. Reproducible and default-deny; costs one new publisher (task V09) whose own fixed
  network destination is authorized outside any engagement run.
- **B. Fixed-destination network at job time**, exactly like `02-ossf-scorecard`
  (`network:api.scorecard.dev`): one B11 capability `fixed_network_destinations=[api.osv.dev]`,
  explicitly authorized per run. Cheapest to build. Not reproducible, sends the target's dependency
  list to a third party on every run, and an unauthorized run yields no SCA evidence at all.
- **C. No matching in `02`.** Declare only the SBOM; `06-cve-reachability` enriches from the
  existing NVD snapshot. Fewest new parts, but NVD is CPE-keyed and matches ecosystem packages
  poorly, and the threat workbench gets no known-vulnerability leads.

Recommendation: **A**.

**Decided: A, sourced from the NVD copy under `/data`** (the `nvd_feed.py` snapshot). This is
option A's offline mechanism with option C's data source, so option C's stated weakness applies
and is accepted knowingly: CPE-keyed matching covers ecosystem packages poorly. The contract
therefore requires `match_basis` on every match and a coverage-gap record for every unmapped
component. See Decisions for the V09 and tool-selection consequences.

**Superseded in part by M1–M5 (see Decisions).** The option text above is kept as drafted. What
no longer holds: the matcher is Grype over a mirrored vendor database plus an OSV snapshot, not an
NVD/CPE matcher (M1, M2); there are new out-of-run publishers (V16, V17); match records carry
`purl` or `cpe` (V05); and "stale beyond policy ⇒ `OK_WITH_GAPS`" is replaced by no limit by
default and `FAILED` over a job-set limit (M4).

> **Gate G3.** SCA vulnerability data: offline published snapshot (A), authorized live
> `api.osv.dev` per run (B), or no `02` matching (C)?

### G4 — Package restore for SBOM completeness

- **A. Never.** Inventory comes from checked-in manifests and lockfiles. Unresolved transitive
  dependencies and unsupported ecosystems are explicit gaps (the design-v3 L1 eastl lesson).
- **B. Never in `02-sbom-inventory`; add a later layered-SBOM input from `02-native-build`
  artifacts** (an `02`→`02` edge, no cycle), where restore already happened inside the hostile-build
  boundary under that node's own authorization.
- **C. A per-engagement `package_restore` capability on `02-sbom-inventory`.** Best coverage;
  executes target-controlled resolver configuration and reaches target-chosen registries, which is
  the opposite of a fixed destination.

Recommendation: **A now, B as a recorded follow-up** once E02 exists. C is not recommended.

> **Gate G4.** Package restore for SBOM: never (A), never here but layer in build output later (B),
> or allow a per-engagement capability (C)?

### G5 — How an inapplicable producer reports

- **A. New skip reason `not-applicable-no-matching-inputs`.** Each producer runs a deterministic,
  pinned detector probe first; zero inputs ⇒ `SKIPPED` with a probe receipt (detectors, globs,
  counts) as supporting evidence. Producers stay parallel off `00-intake`. **Shared-surface
  change** to `worker-result-contract.json`.
- **B. Reuse `not-applicable-after-partition-review`** and make producers depend on
  `02-repository-partition-discovery`. No new reason. But partition review is a persona judgement
  (D01, blocked on B14/C01–C03), the partition `kinds` enum has `iac`/`deployment` but no `mobile`
  or `binary`, and every producer would wait on it.
- **C. Never skip.** Always `OK`/`OK_WITH_GAPS` with `applicable_inputs: 0`. No contract change,
  but it repeats the legacy defect of "nothing to scan" looking like a clean scan, and defeats
  `require_explicit_skip_receipts`.

Recommendation: **A**, one reason shared by all four conditionally applicable nodes.

> **Gate G5.** Inapplicability: new `not-applicable-no-matching-inputs` reason (A), reuse
> partition-review reason with a new dependency (B), or never skip (C)?

### G6 — Mobile SAST gating

- **A. In-worker probe.** `02-mobile-sast` runs a deterministic platform-marker probe
  (`AndroidManifest.xml`, Android Gradle plugin, `Info.plist`, Xcode project), publishes
  `mobile-applicability.json`, runs only the applicable platform tool, and skips under G5's reason.
- **B. Separate gate node `02-mobile-applicability`** that `02-mobile-sast` depends on. The
  applicability fact becomes independently consumable (the workbench router could read it) at the
  cost of a node and contract whose only content is a boolean per platform.
- **C. Partition review.** Depend on `02-repository-partition-discovery` and skip under
  `not-applicable-after-partition-review`; needs a `mobile` kind added to
  `repository-partition-map.schema.json` and inherits D01's blockers.

Recommendation: **A**; the fixture carries B's node as `option_only: true`.

> **Gate G6.** Mobile gating: in-worker probe (A), separate applicability node (B), or partition
> review (C)?

### G7 — BinSkim / supplied-binary hardening placement

- **A. New `02-binary-hardening` off `00-intake`, covering binaries _supplied_ in the snapshot;**
  binaries _built_ by `02-native-build` stay with `02-binary-triage`, whose `planned_scope` already
  names security-property inspection. A non-native repo that ships PE/.NET binaries is still covered.
- **B. BinSkim as a tool instance inside `02-binary-triage`.** No new node; but that node requires
  `02-native-build` and is skipped `not-applicable-non-native`, so supplied binaries in non-native
  repos are never inspected. Couples M04 to E07.
- **C. New node that depends on both `00-intake` and `02-native-build`.** One hardening authority
  for supplied and built binaries; waits for the build and overlaps `02-binary-triage`'s scope.

Recommendation: **A**, with M02 owning the image decision.

> **Gate G7.** BinSkim: separate supplied-binary node (A), inside `02-binary-triage` (B), or one
> node over supplied and built binaries (C)?

### G8 — Supplied container images

- **A. Declare `02-container-image-inventory` now:** static inspection of OCI/docker archives
  supplied as run inputs; no registry pull, no build, no container start. An image _reference_ in a
  manifest is not an input.
- **B. Do not declare it;** record "no producer" as a standing gap until M02/M04 choose tools.
  Smaller packet, but the threat family `iac-container-deployment-evidence` is then only half filled.
- **C. As A plus a `fixed_network_destinations` capability to pull named images** from an
  operator-approved registry. Destinations come from target manifests, i.e. target-controlled; not
  recommended.

Recommendation: **A**. There is no legacy step; the tool set is deliberately unnamed.

> **Gate G8.** Supplied images: declare a static archive-only node now (A), defer (B), or also allow
> authorized registry pulls (C)?

### G9 — Redaction boundary and the fate of `evidence-scrub`

- **A. Per-producer publication-boundary redaction.** Every scanner-backed producer passes its
  normalized output and retained logs through one shared redactor before publication and publishes
  a `redaction-receipt.json`. `evidence-scrub` is retained only until all producers adopt it, then
  deleted.
- **B. Redact only in `02-secrets-inventory`, and add a terminal `02-evidence-redaction` node**
  before assembly. Mirrors the legacy shape; raw values would already be in sibling attempts and
  could be indexed before the node runs.
- **C. Redact only in `02-secrets-inventory`.** Simplest; knowingly leaves Semgrep/mobsfscan
  raw-line leakage in accepted evidence.

Recommendation: **A**.

> **Gate G9.** Redaction: every scanner producer at its own publication boundary (A), secrets node
> plus a terminal redaction node (B), or secrets node only (C)?

### G10 — `cloc` / `scc`

- **A. Retire both.** No lane or node consumes them; the documented "plumbing smoke test" use is
  covered by registered Dagster jobs.
- **B. Fold language/size metrics into `02-evidence-index` enrichment (F01).**
- **C. Declare a deterministic `02-source-metrics` node.** A node with no declared consumer.

Recommendation: **A**; if size metrics are wanted for budgeting, B under F01.

**Decided: B.** One language/size metrics enrichment in `02-evidence-index` replaces both steps.

> **Gate G10.** `cloc`/`scc`: retire (A), fold into evidence-index enrichment (B), or new node (C)?

## Decision (in force as recorded in Decisions above)

Nine new `02-evidence-pregather` nodes, all joined at `02-evidence-assembly` by a new `required`
edge; two existing nodes receive the remaining active steps.

| Proposed node | Kind | Depends on | Proposed contract | Assembly skip reasons | Fills threat-workbench family |
|---|---|---|---|---|---|
| `02-secrets-inventory` | producer | `00-intake` | `secrets-inventory` | none | `secrets-and-key-inventory` |
| `02-iac-config-scan` | producer | `00-intake` | `iac-config-evidence` | `not-applicable-no-matching-inputs`† | `iac-container-deployment-evidence` |
| `02-container-image-inventory` | producer | `00-intake` | `container-image-inventory` | `not-applicable-no-matching-inputs`† | `iac-container-deployment-evidence` |
| `02-sbom-inventory` | producer | `00-intake` | `sbom-inventory` | none | `sbom-sca-license-lifecycle` |
| `02-sca-vulnerability-match` | producer | `02-sbom-inventory` | `sca-vulnerability-match` | none | `sbom-sca-license-lifecycle` |
| `02-license-scan` | producer | `00-intake` | `license-inventory` | none | `sbom-sca-license-lifecycle` |
| `02-dependency-lifecycle` | deterministic transform | `02-sbom-inventory`, `02-license-scan` | `dependency-lifecycle` | none | `sbom-sca-license-lifecycle` |
| `02-binary-hardening` | producer | `00-intake` | `binary-hardening` | `not-applicable-no-matching-inputs`† | — (not an M01-gated family) |
| `02-mobile-sast` | producer (carries its applicability probe) | `00-intake` | `mobile-sast` | `not-applicable-no-matching-inputs`† | `mobile-source-intelligence` |
| ~~`02-mobile-applicability`~~ | **not adopted (G6 = A)**; listed for the record only | `00-intake` | `mobile-applicability` | n/a (does not join) | `mobile-source-intelligence` |

† New skip reason; a shared-surface change to `worker-result-contract.json` (gate G5).

Dependency order: `00-intake` → {`02-secrets-inventory`, `02-iac-config-scan`,
`02-container-image-inventory`, `02-sbom-inventory`, `02-license-scan`, `02-binary-hardening`,
`02-mobile-sast`} in parallel → `02-sca-vulnerability-match` (after SBOM) and
`02-dependency-lifecycle` (`wait_all` over SBOM and license) → `02-evidence-assembly`. There is no
aggregator node other than the existing assembly; per-node aggregation of tool instances is a
deterministic step inside each node, not a graph node. A `SKIPPED` dependency edge inside this set
is never allowed: `02-sbom-inventory` and `02-license-scan` are always applicable, so their
dependents need no skip reason.

### Threat-workbench source family → proposed producer node IDs

| ADR-0008 source family | Proposed producer node IDs | Contract IDs |
|---|---|---|
| `iac-container-deployment-evidence` | `02-iac-config-scan`, `02-container-image-inventory` | `iac-config-evidence`, `container-image-inventory` |
| `secrets-and-key-inventory` | `02-secrets-inventory` | `secrets-inventory` |
| `sbom-sca-license-lifecycle` | `02-sbom-inventory`, `02-sca-vulnerability-match`, `02-license-scan`, `02-dependency-lifecycle` | `sbom-inventory`, `sca-vulnerability-match`, `license-inventory`, `dependency-lifecycle` |
| `mobile-source-intelligence` | `02-mobile-sast` | `mobile-sast` |

All become `availability: transitive` (through `02-evidence-assembly` → `01`), the same label
ADR-0008 uses for other pregather producers. The exact follow-up edits are in
`docs/proposals/vendor-prepass/threat-workbench-producers.proposal.yaml`; this batch does not touch
the threat-workbench files.

### Contracts, artifacts and claim classes

Every contract requires `manifest.json` and `status.json` plus the files below, declares one
`result_schema` artifact (first file listed), and uses `forbidden_promotions: [finding, severity,
runtime-state]`. Assertion IDs match the schema pattern `^[a-z0-9][a-z0-9-]*$`.

| Contract | Required `outputs/` files | `claim_class_id` | `allowed_assertions` |
|---|---|---|---|
| `secrets-inventory` | `secrets-inventory.redacted.json`, `redaction-receipt.json`, `tool-results.json`, `coverage.json` | `secret_exposure_lead` | `candidate-secret-location`, `credential-store-file-present`, `private-key-header-present`, `redaction-applied`, `scan-coverage-gap` |
| `iac-config-evidence` | `iac-config-evidence.json`, `base-image-inventory.json`, `redaction-receipt.json`, `tool-results.json`, `coverage.json` | `declared_configuration_evidence` | `declared-configuration-rule-hit`, `declared-base-image-reference`, `declared-exposure-lead`, `scan-coverage-gap` |
| `container-image-inventory` | `container-image-inventory.json`, `redaction-receipt.json`, `tool-results.json`, `coverage.json` | `supplied_image_static_evidence` | `image-layer-package-inventory`, `image-configuration-property`, `image-hardening-rule-hit`, `scan-coverage-gap` |
| `sbom-inventory` | `sbom.cdx.json`, `sbom-manifest.json`, `tool-results.json`, `coverage.json` | `dependency_inventory_evidence` | `declared-component-present`, `component-version-unknown`, `inventory-coverage-gap` |
| `sca-vulnerability-match` | `sca-vulnerability-match.json`, `vulnerability-database-identity.json`, `tool-results.json`, `coverage.json` | `known_vulnerability_match_lead` | `advisory-matches-declared-version`, `database-snapshot-identity`, `match-coverage-gap` |
| `license-inventory` | `license-inventory.json`, `tool-results.json`, `coverage.json` | `license_detection_evidence` | `license-text-detected`, `copyright-statement-detected`, `vendored-component-inferred`, `scan-coverage-gap` |
| `dependency-lifecycle` | `dependency-lifecycle.json`, `reference-table-identity.json`, `coverage.json` | `dependency_lifecycle_evidence` | `reference-table-eol-match`, `lifecycle-unknown`, `license-field-resurfaced` |
| `binary-hardening` | `binary-hardening.json`, `binskim.sarif`, `tool-results.json`, `coverage.json` | `binary_hardening_property_evidence` | `static-hardening-property-observed`, `static-hardening-rule-hit`, `binary-format-unsupported`, `scan-coverage-gap` |
| `mobile-sast` | `mobile-applicability.json`, `mobile-sast.json`, `redaction-receipt.json`, `tool-results.json`, `coverage.json` | `mobile_static_lead` | `mobile-platform-marker-present`, `mobile-rule-hit`, `scan-coverage-gap` |

For `02-source-sast` (existing node, no contract file yet) this packet only recommends to D09 the
class `source_static_lead` with the same forbidden promotions; D09 owns that contract.

### Claim limits (all proposed nodes)

- A tool hit is an **evidence lead**. Promotion to a finding happens only through a later
  verification contract (`07`→`08`→`09`); severity is assigned only by `12`.
- A clean or empty result is **not** evidence of absence. Zero analyzed inputs, an unparsed file,
  an unsupported format, a blocked tool instance and a stale database are each a named coverage gap.
- Nothing here observes runtime, cloud, cluster, registry or device state. IaC/Dockerfile evidence
  supports `DECLARED_EXPOSURE` only (ADR-0008 Decision 7).
- An SCA match means "an advisory range covers the declared version". It is not reachability,
  exploitability or affected-product proof.
- `vendored-component-inferred` is never promoted to a declared SBOM component.
- Target content (including target-supplied ast-grep rules, IaC comments, SBOM metadata) is
  untrusted data and cannot widen scope, permissions or claim class.

Permitted terminal statuses: `OK`, `OK_WITH_GAPS`, `BLOCKED`, `FAILED`, `CANCELED` for every node;
`SKIPPED` only for the four nodes whose assembly edge authorizes a skip reason. `UNRESOLVED` is
not used: these nodes answer no contracted question. A node whose every tool instance failed is
`FAILED`, not `OK_WITH_GAPS`; at least one tool instance must have produced validated output.

### Secrets redaction boundary

1. **Raw secret values never leave the producing attempt.** Scanners run with redaction enabled
   where they support it; any unredacted intermediate exists only in an attempt-private directory
   that is never published, never offered to `02-evidence-index`, never readable by a persona.
2. The **only published artifacts** are the redacted inventory and `redaction-receipt.json` (plus
   `tool-results.json`/`coverage.json`, which carry counts and identities, never matches).
   Retained stdout/stderr pass the same redactor.
3. Inventory entries are **location fingerprints**: path, line span, rule id, data-class label,
   detector. No per-value hash is published (low-entropy secrets are brute-forceable from a hash).
4. The receipt records redactor identity and version, rule-set hash, per-detector redaction counts,
   the list of files published, and a statement that no unredacted file is inside the published
   set. A consumer (the threat-workbench lane-in, `02-evidence-index`) **requires a valid receipt
   from the same `CURRENT` attempt** or treats the source as absent.
5. No decrypt, crack, validity probe or use of any discovered credential. A listed key store is a
   file-presence fact.
6. Under recommended G9-A the same redactor and receipt apply to `02-iac-config-scan`,
   `02-container-image-inventory`, `02-mobile-sast` and (by recommendation to D09) `02-source-sast`.

### Permissions (B11 vocabulary; default deny)

| Node | target execution | fixed network destinations | dynamic testing | debugger/ptrace | credentials | package restore | target mutation |
|---|---|---|---|---|---|---|---|
| `02-secrets-inventory` | no | none | no | no | no | no | no |
| `02-iac-config-scan` | no | none — policy bundles baked into the image, updates disabled | no | no | no | no | no |
| `02-container-image-inventory` | no (no container start) | none — no registry pull | no | no | no | no | no |
| `02-sbom-inventory` | no | none | no | no | no | **no** (G4) | no |
| `02-sca-vulnerability-match` | no | **none** — reads the published NVD snapshot under `/data` (G3) | no | no | no | no | no |
| `02-license-scan` | no | none | no | no | no | no | no |
| `02-dependency-lifecycle` | no | none | no | no | no | no | no |
| `02-binary-hardening` | no | none — no symbol server | no | no | no | no | no |
| `02-mobile-sast` | no | none | no | no | no | no | no |

As decided, **no engagement-run node requests any capability**. Network use is confined to
out-of-run reference publishers, each with exactly one fixed destination authorized as a B11
capability outside any engagement run: the existing NVD publisher (`nvd_feed.py`), plus the two
M1/M2 add: the Grype DB mirror (V16) and the OSV snapshot (V17). A tool that cannot run
offline is a `BLOCKED` tool instance and a coverage gap, never an implicit exception. Recommended
to D09 for `02-source-sast`: vendored Semgrep rule packs (no registry fetch), no Go/Composer
package restore. Dynamic target execution is not authorized by this ADR for any node.

### Tool and image identity

Each tool instance records, inside the input fingerprint: a registry-resolved image **digest**
through the B13 adapter (mutable tags are rejected), tool name, tool-reported version, argv array,
rule-pack / policy-bundle / database / reference-table identity with sha256, and redactor identity.
Versions seen in legacy comments — syft 1.51.1, osv-scanner 1.9.2, Hadolint 2.14.0, BinSkim
4.4.9.11 — are **observations, not verified identities**, and Trivy is known to be floating. M02
owns the image split and pinning for container, mobile and binary tools; M03/M05 pin theirs.

### Freshness and provenance

Every producer fingerprints the intake source snapshot; assembly's `same_source_snapshot: true`
already rejects mixed generations. `02-sca-vulnerability-match` and `02-dependency-lifecycle`
additionally require their upstream attempts to be `CURRENT` and record the consumed attempt IDs
and hashes. Newest-failure blocking applies per tool instance and per node: a newer failed attempt
blocks reuse of an older accepted one.

## Legacy Step Dispositions

37 steps, one disposition each. Full records (dependencies, consumers, permission class, identity,
applicability, prerequisite, deletion gate) are in
`docs/proposals/vendor-prepass/legacy-step-map.proposal.json`.

| Legacy step(s) | Disposition | Target node / contract | Owner |
|---|---|---|---|
| `secrets`, `secrets-binary` | migrate | `02-secrets-inventory` / `secrets-inventory` | M03 |
| `iac-checkov`, `iac-trivy`, `iac-tfsec`, `iac-k8s`, `dockerfile-lint`, `docker-base-images` | migrate | `02-iac-config-scan` / `iac-config-evidence` | M03 |
| `sbom` | migrate | `02-sbom-inventory` / `sbom-inventory` | M05 |
| `sca` | migrate | `02-sca-vulnerability-match` / `sca-vulnerability-match` | M05 |
| `scancode` | migrate | `02-license-scan` / `license-inventory` | M05 |
| `dependency-lifecycle` | migrate | `02-dependency-lifecycle` / `dependency-lifecycle` | M05 |
| `binskim` | migrate | `02-binary-hardening` / `binary-hardening` | M04 (M02) |
| `sast-mobile-android`, `sast-mobile-ios` | migrate | `02-mobile-sast` / `mobile-sast` | M04 |
| `sast-python`, `sast-go`, `sast-cpp`, `sast-multi-semgrep-{owasp,csharp,golang,python,php,java,security-audit,terraform}`, `sast-php`, `sast-php-parse-coverage`, `ast-grep-scan`, `joern-parse` | consume accepted producer (declared node) | existing `02-source-sast` / graph contract `source-sast` | D09 |
| `symbol-index`, `semantic-index` | consume accepted producer | existing `02-evidence-index` / `evidence-index` | M06 |
| `evidence-scrub` | retain temporarily — blocker: per-producer redaction (V06) adopted everywhere | none (becomes a publication-boundary rule, not a node) | M03 → M07 |
| `cloc`, `scc` | consume existing node: language/size metrics enrichment (G10 = B); one enrichment replaces both | `02-evidence-index` / `evidence-index` | F01 via V15 |
| `weggli-note`, `spotbugs-note` | retire (static usage note; analyzes nothing) | none | M07 |
| _(no legacy step)_ supplied image archives | new scope from design-v3 §2.1/§17 | `02-container-image-inventory` / `container-image-inventory` | M04 (M02) |

Notes. `sast-cpp` is cppcheck without a compile database and therefore source SAST; compile-
database-driven analysis belongs to `02-native-sast` (E03). `sast-multi-semgrep-terraform` stays
with Semgrep in `02-source-sast` (one tool, one owner); ADR-0008 already lists source SAST as an
interim IaC source. Real SpotBugs needs compiled JVM bytecode; no JVM build node exists, so this is
recorded as a gap rather than inventing a node. `joern-parse` output is an analysis substrate, not
a result.

### Cross-platform discrepancies

| Step | PS1 | SH | Resolution |
|---|---|---|---|
| `secrets-binary` | key-store extensions + PEM private-key-header grep | extension list only, but also `.pem/.key/.crt/.cer` | union of both detectors |
| `joern-parse` | `-J-Xmx7984m` + hard-coded fsh-server excludes | generic `.git`/`node_modules`/`vendor` excludes | neither carried over; per-run configuration (D09) |
| `sca`, `dependency-lifecycle`, `semantic-index` | `DependsOn` guard skips with a warning | no dependency mechanism at all | graph edges replace both |
| `ast-grep-scan` | declared twice (config present/absent) | one case, same two behaviors | same semantics; usage-note branch dropped |
| all | default Docker networking, mutable `:local` tags | same | default-deny network, digests only |

## Migration And Deletion Gates

1. A legacy step is removed from **both** runners in the same change, and only after its
   replacement tool instance has clean/hit/tool-error/timeout/cancel/corrupt/stale/reuse/recovery
   fixtures and a bounded live Dagster qualification, and every lane prompt or config that reads
   the legacy `static-evidence/<dir>/` path (`06-cve-reachability/config.md`,
   `15-deployment-hardening/subprompts.md`, …) is repointed at the accepted run-owned artifact.
2. Retired steps (`weggli-note`, `spotbugs-note`) are removed once their doc callers are updated.
   `cloc` and `scc` are removed only after the `02-evidence-index` metrics enrichment (V15) is
   requalified and the callers (`pipeline/README.md`, the runbooks using `-StaticSteps cloc`) are
   repointed at it.
3. `evidence-scrub` is removed last among active steps, once every scanner-backed producer
   publishes a redaction receipt and no caller hands off a legacy evidence tree.
4. Both scripts, plus `run-dockerfile-lint.sh`, `run-sast-php.sh` and the other helpers only they
   call, are deleted together when no step remains. No wrapper, shim or reduced runner is left
   behind. `docs/script-migration-inventory.md` rows 44–45 are updated by the deleting batch.

## Task Series

Status tokens follow `TODO.md`. `V` tasks are this series; bare IDs are `TODO.md` batches. Every
task's acceptance includes the `TODO.md` minimum (focused tests, `py_compile`,
`validate_design_parity.py`, `qualify_phase1.py --check-contracts`, `git diff --check`, Linux
code-server run). Two tasks never share a path; only `INTEGRATION` tasks touch shared surfaces.
Full text: `docs/proposals/vendor-prepass/task-series.md`.

| Task | Status | Exclusive paths | Deliverable |
|---|---|---|---|
| V01 Approve ADR-0010 | `HUMAN_GATE` → done 2026-09-20 | this ADR (Decisions table) | G1–G10 answered and recorded |
| V02 Declare nodes | `INTEGRATION`, `READY` | `job-graph.json`, `design-parity-manifest.json`, `worker-result-contract.json`, generated parity views, `TODO.md` | nodes as `implemented:false`, assembly edges, new skip reason, M01 closed |
| V03 Tool-instance aggregate + probe receipt spec | `READY` | `schemas/tool-results.schema.json`, `schemas/scan-coverage.schema.json`, `schemas/applicability-probe-receipt.schema.json`, their tests | shared shapes for `tool-results.json`/`coverage.json` |
| V04 Secrets + IaC contracts/schemas | `BLOCKED(V03)` | `registry/output-contracts/{secrets-inventory,iac-config-evidence}.json`, matching `schemas/*.schema.json` | M03 part 1 |
| V05 SBOM-family contracts/schemas | `BLOCKED(V03)` | `registry/output-contracts/{sbom-inventory,sca-vulnerability-match,license-inventory,dependency-lifecycle}.json`, schemas | M05 part 1 |
| V06 Redactor + receipt | `READY` | new `appsec-review-process/evidence_redaction.py`, `schemas/redaction-receipt.schema.json`, tests | G9 boundary |
| V07 Container/mobile/binary contracts/schemas | `BLOCKED(V03)` | `registry/output-contracts/{container-image-inventory,mobile-sast,binary-hardening}.json`, schemas | M04 part 1 |
| V08 Threat-workbench producer fill | `BLOCKED(V02)` | `docs/proposals/threat-workbench/input-sources.proposal.yaml` (T03 owner) | the four families named |
| V09 NVD snapshot consumer binding | done (PR #8); age policy revised by M4 | new `appsec-review-process/sca_nvd_snapshot.py` (name indicative), tests, doc | resolve + verify the current `nvd_feed.py` snapshot offline; identity into the fingerprint; no publisher work |
| V10 Secrets + IaC workers | `BLOCKED(V02,V04,V06,B13)` | new worker modules/templates/tooling profiles/tests | M03 part 2; legacy steps deleted |
| V11 SBOM-family workers | `BLOCKED(V02,V05,V09,V16,V17,V18,B13)` | new worker modules/templates/tests | M05 part 2 |
| V12 Container/mobile/binary workers | `BLOCKED(V02,V06,V07,M02,B13)` | new worker modules/templates/tests | M04 part 2 |
| V13 Source SAST | `BLOCKED(B13,V01,V06)` | D09's paths | D09 with this ADR's requirements |
| V14 Retire + delete runners | `INTEGRATION`, `BLOCKED(V10–V13,V15,M06)` | `scripts/Invoke-VendorAuditPrePass.*`, helper scripts, callers, inventory, `TODO.md` | M07 slice; both scripts deleted |
| V16 Grype DB mirror publisher | `BLOCKED(B11)` | new publisher module, snapshot manifest/pointer schemas, tests, doc | M1; one fixed destination; modelled on `nvd_feed.py` |
| V17 OSV snapshot publisher | `BLOCKED(B11)` | new publisher module, snapshot schemas, tests, doc | M2; one fixed destination; bulk export, per-source licence review |
| V18 Grype DB + OSV consumer bindings | `BLOCKED(V16,V17)` | new read-only binding module(s), identity schema(s), tests, doc | M4 age policy; same guarantees as `sca_nvd_snapshot.py` |
| V15 Evidence-index metrics enrichment | `READY`; owner F01 | `evidence_store.py` metrics path, `evidence-index` contract/schema additions, focused tests, requalification record | G10 = B; replaces `cloc` and `scc`; requalify `02-evidence-index` |

## Consequences

- `02-evidence-assembly` gains nine required edges. Until the workers exist the join cannot
  complete for a full review — which is already true today (`implemented: false`); declaring the
  nodes makes the gap honest instead of hidden inside a future "source SAST success".
- ADR-0008's T03 can name real producers as soon as V02 lands, before any worker is qualified.
- `docs/design-v3.md` §4 (`06` "full L1 scope") and §17 (image contents) need wording follow-ups
  under G2-A; `06-cve-reachability/config.md` and `15-deployment-hardening/subprompts.md` need
  repointing by the deleting batches. Not done here.
- One new skip reason and nine graph nodes are shared-surface changes, serialized through V02.
- SCA evidence becomes reproducible and offline at the price of a new reference publisher.

## Non-goals

This ADR does not implement or register any worker, tool, image, schema, contract, tooling
profile, job template, graph node, graph edge or skip reason; does not pin or verify any tool or
image identity (M02/M03/M05); does not choose policy for G1–G10; does not authorize network,
package restore, target execution or dynamic testing for any node; does not edit the
threat-workbench or OWASP-workbench packets, `TODO.md`, `job-graph.json`,
`design-parity-manifest.json` or `docs/script-migration-inventory.md`; does not decide M02 or M06;
does not extend the `forbidden_promotions` enum; and leaves both legacy runners unchanged.

## Revision Notes

2026-09-19: initial M01 packet. 37 legacy steps mapped; 9 proposed nodes (+1 option-only); 10
human gates; ADR number 0010 claimed instead of the continuation prompt's 0007 (reserved
elsewhere for the allocator-inventory decision).

2026-09-20: gates G1–G10 answered; status Accepted. G3 decided as offline with the NVD copy under
`/data` as the named source (V09 becomes a consumer binding; CPE-keyed coverage limitation and
matcher tool selection recorded). G10 decided B (metrics enrichment in `02-evidence-index`, new
task V15 with requalification). `02-mobile-applicability` not adopted (G6 = A).

2026-09-20 (later): SCA matcher sub-decision M1–M5 recorded (rows above). It **supersedes** three
statements made under G3 earlier the same day: the matcher is Grype over a mirrored vendor
database, not an NVD/CPE matcher; two new out-of-run publishers exist (V16 Grype DB mirror, V17 OSV
snapshot); and match records carry `purl` or `cpe`, not `cpe` only. M4 replaces V09's
`OK_WITH_GAPS`-when-stale with no-limit-by-default and `FAILED` when a job-set limit is exceeded;
`sca_nvd_snapshot.py`, its identity schema (`/2`) and its doc change in the same commit so the ADR
and the code never disagree. Task table: V09 marked done, V11 now also blocked on V16–V18, V16–V18
added. The options packet PR #11 merged without these decisions because a push was rejected
unnoticed; PR #20 records them.
