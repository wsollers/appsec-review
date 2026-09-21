# Vendor-Prepass Decomposition Task Series

Status: task packet for M03, M04, M05, D09 and the M07 deletion slice under **accepted**
ADR-0010 (gates decided 2026-09-20). Do not mark any `02-*`
node implemented from this document. Status tokens follow `TODO.md`: `READY`, `BLOCKED(<ids>)`,
`HUMAN_GATE`, `INTEGRATION`. IDs prefixed `V` are this series; bare IDs are `TODO.md` batches.

Paths are relative to the repo root; `arp/` abbreviates `appsec-review-process/`. Task text assumes
the ADR's recorded Decisions (G3: NVD copy under `/data`; M1–M5: Grype over a mirrored vendor DB plus an OSV snapshot, no age limit by default and `FAILED` over a job-set limit; G10: evidence-index enrichment; G6: no applicability node).

## Review Pattern

Same as `docs/proposals/threat-workbench/task-series.md`: one agent drafts a bounded slice on a
dedicated branch from `origin/main`; the other reviews for evidence boundaries, schema drift, claim
overreach and integration conflicts; only an `INTEGRATION` owner touches shared surfaces
(`arp/job-graph.json`, `arp/design-parity-manifest.json`, `arp/worker-result-contract.json`,
`arp/dagster_workflow.py`, `arp/launch_job.py`, `orchestrator/dagster/definitions.py`, common
runtime modules, generated parity views, `arp/TODO.md`). Every task's acceptance includes the
`TODO.md` minimum: focused tests, `python -B -m py_compile` on changed modules,
`python -B appsec-review-process/validate_design_parity.py`,
`python -B appsec-review-process/qualify_phase1.py --check-contracts`, `git diff --check`, and the
focused suite in the Linux code-server.

## Dependency Map

```text
V01 (HUMAN_GATE) ─┬─ V02 INTEGRATION: declare nodes + skip reason ─┬─ V08 threat-workbench fill
                  ├─ V03 shared tool-results/coverage/probe shapes ─┬─ V04 ─┐
                  │                                                 ├─ V05 ─┤
                  │                                                 └─ V07 ─┤
                  ├─ V06 redactor + receipt ────────────────────────────────┤
                  ├─ V09 NVD snapshot consumer binding (done) ──────────────┤
B11 ── V16 Grype DB mirror publisher ─┬─ V18 Grype DB + OSV consumer bindings ──┤ (V11)
B11 ── V17 OSV snapshot publisher ────┘                                          │
                  └─ V15 evidence-index metrics enrichment (F01) ─────────── V14
B13 pinned-container adapter ───────────────────────────────────────────────┤
M02 binary/mobile/container image decision ─────────────────────────────────┤
                                       V10 secrets+IaC │ V11 SBOM family │ V12 container/mobile/binary │ V13 = D09
M06 semantic-index disposition ─────────────────────────────────────── V14 INTEGRATION: delete runners
```

## V01 — Approve ADR-0010 — `HUMAN_GATE` → done 2026-09-20

- Owner: user, after one Codex and one Claude review pass on the packet.
- Exclusive paths: `docs/decisions/ADR-0010-vendor-prepass-decomposition.md` (add a Decisions table
  and flip Status), `docs/proposals/vendor-prepass/*` (regenerate fixtures if an answer differs from
  the recommendation).
- Deliverables: G1–G10 answered verbatim; fixtures agree with the answers.
- Acceptance: no gate left open; fixtures and ADR agree; step-set equality check still passes.
- Reviewer focus: no answer silently widens a permission; node IDs match the chosen G1/G6/G8 shape.

## V02 — Declare Nodes, Edges And Skip Reason — `INTEGRATION`, in review (branch `claude/v02-declare-vendor-prepass-nodes`)

- Exclusive paths: `arp/job-graph.json`, `arp/design-parity-manifest.json`,
  `arp/worker-result-contract.json`, generated parity views (`docs/design-parity-report.md`,
  `docs/full-review-workflow.mmd`, `docs/design-parity-readiness.md`), `arp/TODO.md`.
- Deliverables: the approved nodes as `implemented: false`, `template: null`, with `planned_scope`
  and `required_artifacts`; one `required` `02-evidence-assembly` edge per joining node with the
  approved `allowed_skip_reasons`; `not-applicable-no-matching-inputs` registered (G5 = A);
  parity-manifest rows with honest blockers; M01 closed and M03/M04/M05/D09 statuses refreshed.
- Acceptance: graph validates and stays acyclic; no `02-*` node depends on `01-*` or later; node
  count matches the ADR; every new node blocks with `WORKER_NOT_IMPLEMENTED`; bounded live Dagster
  check that registration still loads; no readiness flag turns true.
- Reviewer focus: no edge from a new node to `03`/`06`/`15`; skip reasons only on the four
  conditionally applicable edges; generated views regenerated, not hand-edited.

## V03 — Shared Tool-Instance Aggregate And Probe Shapes — done (PR #9)

- Exclusive paths: new `schemas/tool-results.schema.json`, `schemas/scan-coverage.schema.json`,
  `schemas/applicability-probe-receipt.schema.json`, `arp/tests/test_tool_instance_shapes.py`.
- Deliverables: one schema for `tool-results.json` (per tool instance: tool id, attempt id,
  terminal status, identity block, argv, exit semantics, output hashes), one for `coverage.json`
  (analyzed / not-analyzed / unsupported inputs, named gaps), one for the probe receipt.
- Acceptance: golden + mutation fixtures — a node aggregate cannot be `OK` with a failed tool
  instance unreported, cannot be `OK_WITH_GAPS` with zero validated tool outputs, and cannot be
  `SKIPPED` without a receipt showing zero inputs for every tool.
- Reviewer focus: shapes are reusable by D09's `02-source-sast` without change; no field can hold
  a raw match line.

## V04 — Secrets And IaC Contracts — done (PR #18, #21)

- Exclusive paths: `arp/registry/output-contracts/secrets-inventory.json`,
  `arp/registry/output-contracts/iac-config-evidence.json`,
  `schemas/secrets-inventory.schema.json`, `schemas/iac-config-evidence.schema.json`, focused tests.
- Deliverables: contracts with the ADR's required files, `result_schema`, `claim_class` and
  validation rules (receipt required; declared-exposure only).
- Acceptance: `--check-contracts` passes; mutation fixtures reject a secret value, a per-value hash,
  a missing receipt, an `OBSERVED` exposure assertion and any forbidden promotion.
- Reviewer focus: the inventory schema has no free-text field able to carry a match.

## V05 — SBOM-Family Contracts — done (PR #23)

- Exclusive paths: `arp/registry/output-contracts/{sbom-inventory,sca-vulnerability-match,
  license-inventory,dependency-lifecycle}.json`, matching `schemas/*.schema.json`, focused tests.
- Deliverables: four contracts; component/version/source/database timestamps and hashes (M05);
  database identity mandatory for SCA; reference-table identity mandatory for lifecycle.
- Matcher (ADR-0010 M1/M2): Grype over a mirrored Grype vendor database, with an independent OSV
  snapshot. The `sca-vulnerability-match` contract therefore:
  - names the database identity **per match** (`grype-db` or `osv`), each with vendor build
    identity, schema version, snapshot id and sha256; both enter the input fingerprint;
  - makes `match_basis` a closed enum (`purl`, `cpe`), never the constant `cpe`;
  - records every component no source covers as an explicit coverage-gap record with a closed
    reason, and publishes the aggregated gap summary M5 sends to the threat workbench (counts by
    ecosystem and reason; the per-component list by reference);
  - collapses CVE/GHSA aliases so one advisory reported by both sources is one match with two
    citations, not two matches;
  - states the version scheme used for range evaluation; an unparseable version is a gap, never
    "not vulnerable".
- Acceptance: mutations reject a reachability/exploitability assertion, a match without database
  identity, a `match_basis` outside the enum, an uncovered component with no gap record,
  `supported` inferred from table absence, and an inferred vendored component promoted to a
  declared one.
- Reviewer focus: nothing duplicates `06-cve-reachability`'s contract.

## V06 — Redactor And Redaction Receipt — done (PR #10; 1.1.0 in PR #17)

- Exclusive paths: new `arp/evidence_redaction.py`, `schemas/redaction-receipt.schema.json`,
  `arp/tests/test_evidence_redaction.py`, `docs/evidence-redaction.md`.
- Deliverables: deterministic redactor (entropy pass + secret-name-aware pass, ported in behavior
  from `scripts/scrub_evidence.py`, not lifted verbatim) applied at the publication boundary; the
  receipt described in the ADR; bounded input handling.
- Acceptance: fixtures for machine tokens, human passwords, PEM blocks, SARIF snippet fields,
  oversized and malformed inputs; proof that no published file and no retained log contains a
  planted value; receipt tamper detection.
- Reviewer focus: redaction happens before anything is offered to `02-evidence-index`; the module
  does not import or alter common runtime publication code (adoption happens in V10–V13).

## V07 — Container, Mobile And Binary-Hardening Contracts — done (PR #19)

- Exclusive paths: `arp/registry/output-contracts/{container-image-inventory,mobile-sast,
  binary-hardening}.json`, matching schemas, focused tests.
- Acceptance: mutations reject runtime-state assertions, a mobile result without
  `mobile-applicability.json`, and a hardening "pass" for an unsupported format.
- Reviewer focus: no contract implies a registry pull or container start.

## V08 — Fill Threat-Workbench Producers — `BLOCKED(V02)`

- Owner: the ADR-0008 T03 owner. Exclusive paths:
  `docs/proposals/threat-workbench/input-sources.proposal.yaml`.
- Deliverables: apply `threat-workbench-producers.proposal.yaml`; `m01_gated` → `transitive`.
- Acceptance: every producer ID exists in `job-graph.json`; YAML parses; secrets family keeps the
  receipt requirement.

## V09 — NVD Snapshot Consumer Binding — done (PR #8); age policy revised by M4

Decision G3 made the NVD copy under `/data` (published by `nvd_feed.py`) an offline source. M1 then
made Grype the SCA matcher, so this binding is **no longer the matcher's source**: it serves
`06-cve-reachability` enrichment and an independent cross-check. No network, no B11 capability.

- Delivered: `appsec-review-process/sca_nvd_snapshot.py`, its tests, `docs/sca-nvd-snapshot-binding.md`,
  `schemas/vulnerability-database-identity.schema.json`.
- Age policy (M4, supersedes the original "older than policy => `OK_WITH_GAPS`"): `max_age` is
  required and has no default; a job passes `NO_AGE_LIMIT` unless it or the engagement configured a
  tighter limit; a snapshot older than a limit the job set is **`FAILED`** (`SNAPSHOT_TOO_OLD`) with
  no identity and no fingerprint component. The worker resolves in preflight before reuse admission.
- Unchanged acceptance: missing pointer or snapshot => `BLOCKED`; hash mismatch or partial snapshot
  => fails closed; a writer lease never blocks a reader; no code path opens a socket.
- `match_basis: cpe` in its identity record is true of the NVD database. The SCA match-record
  basis (`purl`, `cpe`) is V05's.

## V10 — Secrets And IaC Workers (M03) — `BLOCKED(V02,V04,V06,B13)`

- Exclusive paths: new worker modules, job templates, tooling profiles and tests for
  `02-secrets-inventory` and `02-iac-config-scan`. Registration edits go to the integration owner.
- Acceptance: M03's list (clean/hit/secret-output/tool-error/timeout/cancel/reuse/recovery, bounded
  live runs) plus offline proof for checkov/trivy, digest-only images, union key-material detector,
  and deletion of the eight mapped steps from **both** runners.
- Reviewer focus: no `|| true`; a tool that needs network is `BLOCKED`, not excepted.

## V11 — SBOM-Family Workers (M05) — `BLOCKED(V02,V05,V16,V17,V18,B13)`

- Exclusive paths: new worker modules/templates/profiles/tests for the four nodes.
- Matcher: a pinned image carrying syft and Grype (digest-pinned per B13), reading the mirrored
  Grype DB and the OSV snapshot through V18's bindings. Database auto-update disabled; no network.
- To verify before relying on it (from the M1–M5 packet): the exact Grype flags/environment for
  no-update and no-network operation and that nothing phones home with them set; DB schema-version
  pinning against the pinned Grype version; determinism for a fixed DB and SBOM; syft's CPE/purl
  output surviving the pinned CycloneDX version; the attribution notices the bundled data requires.
- Acceptance: M05's list plus: a missing database => `BLOCKED`; a database older than a limit the
  job set => `FAILED`, no limit by default (M4); both database identities in the fingerprint;
  CycloneDX version pin recorded; no package restore; `06-cve-reachability/config.md` repointed
  (it still names `static-evidence/sca/osv-scanner.json`); four steps deleted from both runners.

## V12 — Container, Mobile And Binary-Hardening Workers (M04) — `BLOCKED(V02,V06,V07,M02,B13)`

- Exclusive paths: new worker modules/templates/profiles/tests for the three nodes.
- Acceptance: M04's list plus the marker-based mobile probe (server-side Java must not count),
  archive-only image input, three steps deleted from both runners.

## V13 — Source SAST (D09) — `BLOCKED(B13,V01,V06)`

- Exclusive paths: D09's. This series adds only the requirements listed under
  `existing_nodes_receiving_legacy_steps` in `job-nodes.proposal.json`.
- Acceptance: D09's list plus vendored rule packs, no package restore, redaction receipt, fifteen
  steps deleted from both runners.

## V14 — Retire And Delete The Runners (M07 slice) — `INTEGRATION`, `BLOCKED(V10,V11,V12,V13,V15,M06)`

- Exclusive paths: `scripts/Invoke-VendorAuditPrePass.ps1`, `.sh`, helper scripts only they call,
  engagement callers, `pipeline/README.md`, runbooks, `docs/script-migration-inventory.md`,
  `arp/TODO.md`.
- Acceptance: zero remaining steps, zero executable callers, no wrapper, inventory rows closed.

## V15 — Evidence-Index Metrics Enrichment (F01) — done (PR #25; Windows verification outstanding)

Decision G10 = B: language/size metrics move into `02-evidence-index`; one enrichment replaces the
legacy `cloc` and `scc` steps.

- Exclusive paths: the metrics code path in `arp/evidence_store.py`, additive fields in the
  `evidence-index` contract/manifest schema, focused tests, and the requalification record. No
  change to retrieval behavior or to `evidence_mcp.py`.
- Deliverables: deterministic per-language file/line counts computed from the already-indexed
  snapshot (no external `cloc`/`scc` binary, no container), published inside the existing
  `manifest.json` or a sibling artifact declared in the contract.
- Acceptance: `02-evidence-index` is an implemented, qualified worker, so this changes its
  executable identity: prior accepted pointers stay integrity-readable but are not reused as
  current; `qualify_evidence_index.py` is rerun and its report path and hash recorded; metrics are
  descriptive only (no claim class promotion); generated/vendored scope is labelled, not dropped.
- Reviewer focus: additive and deterministic; identical snapshot => identical metrics on Windows
  and Linux; no regression in index build time beyond a recorded bound.

## V16 — Grype DB Mirror Publisher — `BLOCKED(B11)`

ADR-0010 M1. Out-of-run reference publisher, modelled on `nvd_feed.py`.

- Exclusive paths: new publisher module, snapshot manifest/pointer/lease schemas, tests,
  `docs/grype-db-mirror-publisher.md`. Do not edit `nvd_feed.py`.
- Deliverables: downloads the Grype vulnerability DB archive from its one fixed destination,
  verifies the vendor checksum, records vendor build timestamp, DB schema version and sha256, and
  publishes it immutably with an atomic last-good pointer under `/data`.
- Acceptance: redirect/oversize/tamper/partial-download/lease-contention fixtures; the fixed
  destination is a B11 `fixed-network-destination` capability granted **outside any engagement
  run**; a DB whose schema version the pinned Grype cannot read is refused at publication; licence
  and attribution terms of the bundled data recorded.
- Reviewer focus: no engagement-run job gains network; the archive is never executed or unpacked
  by the publisher beyond what verification needs.

## V17 — OSV Snapshot Publisher — `BLOCKED(B11)`

ADR-0010 M2. Independent second source, kept although the Grype DB carries OSV-derived data.

- Exclusive paths: new publisher module, snapshot schemas, tests, `docs/osv-snapshot-publisher.md`.
- Deliverables: bulk-export download from one fixed destination, per-ecosystem files hashed,
  immutable snapshot plus atomic pointer under `/data`.
- Acceptance: as V16, plus per-source licence terms recorded (several OSV sources are CC-BY) and
  export location/format/size confirmed rather than assumed.
- Reviewer focus: one fixed destination; alias data (CVE <-> GHSA) preserved for V05's collapsing.

## V18 — Grype DB And OSV Consumer Bindings — `BLOCKED(V16,V17)`

- Exclusive paths: new read-only binding module(s), identity schema(s), tests, doc.
- Deliverables: for each database, what `sca_nvd_snapshot.py` does for NVD: resolve the current
  snapshot, re-verify every hash offline on every call, return an identity record and a fingerprint
  component only for a usable outcome.
- Acceptance: the same guarantees, stated as tests: every safety input required with no default;
  `NO_AGE_LIMIT` explicit and `FAILED` over a job-set limit (M4); every trusted field re-derived
  from bytes; a persisted identity verified by re-resolution, never trusted; identity read-only
  after resolution; path containment and link rejection; provably no network.
- Reviewer focus: a returned or persisted record is a cache, never an authority.
