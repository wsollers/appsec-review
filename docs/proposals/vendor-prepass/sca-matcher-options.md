# SCA Matcher Selection For The NVD-Keyed Offline Snapshot

Status: **Decided 2026-09-20** (see Decisions). Documentation only. No matcher, worker, schema,
contract, registry record or graph change follows from this document; the outcome still has to be
recorded in the authoritative documents in the same change: ADR-0010's Decisions table and task
table, the task series (V05, V09, V11, new V16-V18), `job-nodes.proposal.json`,
`threat-workbench-producers.proposal.yaml`, and the V09 binding's age policy (code, schema, doc).

Date: 2026-09-20 (drafted and decided)

## Decisions

Recorded 2026-09-20 from the owner's answers. M1 was first answered with a question ("we have Trivy,
can Trivy be used? or do we build a docker image with grype and syft that consumes our static NVD
and other static sources?"), which surfaced an option this packet had under-weighted: running an
off-the-shelf scanner offline against a **mirrored copy of its own vendor database**, rather than
against a database built from our raw NVD mirror (B2). The gate was re-put with that option.

| Gate | Decision |
|---|---|
| M1 Matcher | **Pinned syft + Grype image; the Grype vendor database mirrored into `/data`.** A new out-of-run publisher downloads the Grype DB archive, records its identity (vendor build timestamp, schema version, sha256) and publishes it immutably, in the same pattern as `nvd_feed.py`. The scan job runs with database auto-update disabled and no network. Grype consumes the syft SBOM natively and matches by purl/ecosystem **and** CPE. The raw NVD mirror is no longer the matcher's source; it stays for `06-cve-reachability` enrichment and as an independent cross-check. Trivy was considered and not chosen for SCA: it matches language packages from its own `trivy-db`, not from NVD, so "Trivy against our NVD mirror" detects almost nothing; against a mirrored `trivy-db` it would be viable, but Grype pairs directly with the syft SBOM. B1/B5 (native CPE matcher) is **not** adopted. |
| M2 OSV | **Yes, and before V11: build BOTH** the Grype DB mirror publisher and an independent offline OSV snapshot publisher. The owner chose to keep OSV as a second, independent source even though the Grype DB already carries GHSA/OSV-derived ecosystem advisories. Each publisher has exactly one fixed network destination, authorized as a B11 capability outside any engagement run; no engagement-run job gains network. |
| M3 purl→CPE rules | Answered **A (versioned rule table in the repo)** before M1 was refined. Under M1 = Grype there is no in-repo CPE matcher, so the table has **no consumer and is not built now**. The answer stands for the case where a native NVD cross-check is added later. |
| M4 Freshness | **No age limit by default**: a job uses whatever static snapshot is present and always records its age. A job or engagement **may set a tighter `max_age`**; exceeding that limit is **`FAILED`** (not `OK_WITH_GAPS`, not `BLOCKED`). This supersedes task V09's acceptance line "snapshot older than policy => `OK_WITH_GAPS`" and changes the merged binding (section F). "No limit" must be an explicit, required argument value, never a default. |
| M5 Gaps → workbench | **Matches plus an aggregated gap summary** (counts by ecosystem and reason; the full per-component list available by reference). |

Consequences for V05 (contract) and V11 (worker):

- The `sca-vulnerability-match` contract names **two possible database identities** per match: the
  Grype vendor DB and, where used, the OSV snapshot. `match_basis` is an enum (at least `purl`,
  `cpe`), never the constant `cpe`. Section C's rules all still hold.
- "Known vulnerability" now rests on a **third-party aggregated database** whose contents we pin
  and hash but do not author. The contract must carry its vendor build identity and schema version
  in the input fingerprint, and the licence/attribution terms of the bundled data must be reviewed
  before V11 ships (to verify).
- Still **to verify in V11**, not asserted here: the exact Grype flags and environment for
  no-update/no-network operation and that nothing phones home with them set; DB schema-version
  pinning against the pinned Grype version; determinism for a fixed DB and SBOM; the OSV bulk
  export location, format, size and per-source licence terms; CVE/GHSA alias collapsing between the
  two sources so one advisory is not reported twice.
- New tasks the task series needs (its owner adds them): **V16 Grype DB mirror publisher** and
  **V17 OSV snapshot publisher**, both `BLOCKED(B11)`, both modelled on `nvd_feed.py`, both
  prerequisites of V11; plus consumer bindings equivalent to V09 for each.

This is a **sub-decision under the accepted ADR-0010**, not a new ADR. ADR-0010 Decision G3 fixed
the data source (the NVD copy under `/data`) and recorded that "the matcher is reopened as a
V05/V11 tool-selection item; no tool is chosen by this ADR"
(`docs/decisions/ADR-0010-vendor-prepass-decomposition.md:18`); `task-series.md:145-147` requires
"its own short options note before V11 starts". This is that note. Once the gates are answered,
the outcome is recorded in ADR-0010's Decisions table by whoever records it; this document is then
frozen as the supporting packet.

Already decided and not reopened here: G2 = `02-*` producers; G3 = offline, NVD under `/data`, no
engagement-run network; G4 = no package restore. Every option below keeps
`02-sca-vulnerability-match` at `fixed_network_destinations: denied`.

## A. What is actually in `/data`

Read from `appsec-review-process/nvd_feed.py`; nothing here is assumed. No snapshot is published
in this checkout (`data/feeds/nvd/` holds only `README.md`), so record *contents* could not be
inspected; statements about NVD's own record shape are marked as such.

| Question | Fact | Source |
|---|---|---|
| What is fetched | Only the CVE yearly feeds `nvdcve-2.0-<year>.json.gz` + `.meta`, and CVE API 2.0 pages. Exactly two base URLs exist. | `nvd_feed.py:32-33`, `:335-339`, `:361-365` |
| Record format | `NVD_CVE/2.0`. Feed blobs are stored byte-for-byte (size and sha256 checked against NVD's `.meta`); API pages are stored as the exact response body, re-gzipped with `mtime=0`. | `nvd_feed.py:187-193`, `:393-398`, `:354` |
| Are `configurations` / CPE match strings present? | The publisher never strips, projects or normalises a record, so whatever NVD serves is retained whole. It also never *reads* `configurations`: validation touches only `cve.id`. Presence is therefore inherited from NVD, not guaranteed by the repo. In NVD's 2.0 schema each `cpeMatch` carries `criteria`, `vulnerable` and `versionStart/End Including/Excluding`, which is enough to evaluate a range. **To verify in V11 against a real snapshot.** | `nvd_feed.py:194-204`, `:215-224` |
| CPE dictionary | **Not in the snapshot.** Never fetched. | no `cpes/2.0` URL in `nvd_feed.py` |
| CPE-match feed (`cpematch/2.0`) | **Not in the snapshot.** Never fetched. A matcher can evaluate ranges from the inline `cpeMatch` fields but cannot expand a `matchCriteriaId` to the enumerated CPE names. | same |
| Any purl↔CPE mapping, GHSA, OSV, distro data | **None.** Nothing in `/data/feeds` is ecosystem-keyed. | same |
| Year coverage | 2002 through the UTC year of the bootstrap run. | `nvd_feed.py:34`, `:334`, `:356` |
| Incremental semantics | Each later sync adds `api-last-modified` layers (≤119-day windows, 2000/page) over the immutable parent. Layers are **overlays, not merges**: a CVE modified after bootstrap exists in the yearly blob *and* in one or more delta pages; duplicate IDs at inclusive window boundaries are counted, not removed. | `nvd_feed.py:35-36`, `:368-419`, `:395-400` |
| Merged view / reader | **None exists.** No code yields "current record per CVE". `iter_vulnerabilities` is used only for validation; the V09 binding does not decompress or parse blobs. A matcher must itself fold the chain (newest `lastModified` per CVE wins) and honour `vulnStatus` (e.g. rejected records). | `nvd_feed.py:144`, `:196`; `docs/sca-nvd-snapshot-binding.md:10`, `:227-228` |
| Identity V09 exposes | `snapshot_id`, `manifest_sha256`, `content_sha256` (full sha256 over the ordered chain and every blob), `chain_snapshot_ids`, `cursor`, `age_seconds`, `max_age_seconds`, `freshness`, `match_basis`, `limitations`. Fingerprint component = kind, feed schema, the three hashes/ids, `match_basis`, `freshness`. | `docs/sca-nvd-snapshot-binding.md:168-172`, `:187-197` |
| `match_basis` today | `const: "cpe"` in the schema and a module constant. | `schemas/vulnerability-database-identity.schema.json:30`; `sca_nvd_snapshot.py:34` |
| Blob list for a matcher | `Resolution` exposes no file list; the doc tells the matcher to "re-resolve if it needs the file list" and to read only blobs reachable from the verified chain. | `docs/sca-nvd-snapshot-binding.md:70-71`, `:240-241` |
| Publisher weaknesses V09 reported | Root is unsigned (a consistent full rewrite is undetectable); parents are bound by a 64-bit id; `published_at` is bound by nothing; every resolve re-hashes every blob. | `docs/sca-nvd-snapshot-binding.md:211-226` |
| Freshness policy | No owner and no value. The NVD README refers to "the separately approved freshness policy"; V09 found no such record. | `data/feeds/nvd/README.md:28-29`; `docs/sca-nvd-snapshot-binding.md:243-244` |

**Findings that matter for the choice.** (1) The snapshot has everything needed to *evaluate* a
CPE range and nothing needed to *derive* a CPE from a purl. (2) Any consumer — in-repo or
off-the-shelf — needs a chain-folding reader that does not exist yet. (3) NVD records that NVD has
not yet analysed carry no `configurations` at all (NVD has run an analysis backlog since 2024);
under every NVD-only option those CVEs are invisible, so the contract needs a database-side
coverage statement (count of records without configurations), not only component-side gaps.

## B. Options

Legend: FN = false negatives, FP = false positives. "To verify" = must be proven by V11 before it
is relied on; it is not asserted here.

### B1. Native CPE matcher (in-repo, deterministic)

A small Python matcher in the `02-sca-vulnerability-match` worker: fold the verified chain; take
candidate CPEs from the accepted SBOM (syft writes CPE candidates into CycloneDX components) plus a
curated, versioned purl→CPE rule table; evaluate NVD `configurations` ranges.

| Aspect | Assessment |
|---|---|
| Matches well | Components with a stable NVD vendor:product: C/C++ and vendored native libraries (openssl, zlib, curl, sqlite, libxml2…), runtimes, servers, well-known Java/.NET frameworks. This is the population OSV covers worst. |
| Matches badly | npm, PyPI, Go modules, crates, RubyGems, most NuGet/Maven long tail: no CPE, or an ambiguous one. These become coverage gaps. |
| FN character | High for ecosystem packages; total for CVEs NVD has not analysed; any component whose rule is missing. All are *countable* and reportable as gaps. |
| FP character | Syft's generated CPE candidates are heuristic guesses; product-name collisions (same product name, different vendor/ecosystem); `AND` configurations with platform nodes (`vulnerable:false` "running on") read as plain matches unless handled. Controlled by labelling the basis (`cpe-sbom-declared` vs `cpe-generated` vs `cpe-curated-rule`). |
| Offline / reproducibility | Best available. Fingerprint = V09 component + matcher code identity + rule-table sha256 + SBOM hash. No second database. |
| Code / ownership burden | New and ours: chain reader, CPE 2.3 parsing, configuration-tree evaluation, version comparison, rule table, fixtures. Moderate; the rule table is a standing curation cost (gate M3). |
| Tool / image pinning (M02/B13) | None beyond the worker's own image. |
| Licence | NVD data is a US-government work with NVD's attribution notice (**to verify** the exact notice text V11 must carry). No bundled third-party tool. |
| V05 contract effect | `match_basis` enum gains only `cpe-*` values; gap reasons as in section C. |
| Threat-workbench family | `sbom-sca-license-lifecycle` is filled, but for a typical web/service target mostly with gaps; leads concentrate on native/vendored components. |
| Verify before V11 relies on it | Real-snapshot presence and shape of `configurations`; share of records with none; that syft's CPE output survives the pinned CycloneDX version; the version-comparison rules per scheme (section C). |

### B2. Off-the-shelf scanner fed from a locally built database

| Aspect | Grype (+ `grype-db`/`vunnel`) | Trivy (+ `trivy-db`) | OWASP Dependency-Check |
|---|---|---|---|
| What is established | Apache-2.0. Consumes a CycloneDX SBOM. Its database is built by separate tooling from provider data; NVD is one provider among GHSA and distro feeds. Can run with DB auto-update disabled against an imported DB. | Apache-2.0. Consumes CycloneDX. Language-package detection is driven by ecosystem advisories (GHSA and similar); NVD contributes severity/CVSS enrichment rather than detection. | Apache-2.0, JVM. The established NVD/CPE scanner: builds a local DB from NVD and identifies CPEs from file evidence. Does **not** take an SBOM as input; it scans the tree itself. |
| Driven from *our* raw NVD JSON 2.0 mirror, offline? | **To verify.** The NVD provider is written against the NVD API, not against a local yearly-feed + delta-page chain; an adapter or a fork is likely. | **Effectively ruled out.** An NVD-only `trivy-db` would detect almost nothing for ecosystem packages because Trivy does not CPE-match them. (**To verify**, but this is the documented design.) | **To verify.** It supports pointing at an NVD data-feed mirror; whether our layout (yearly blobs + API delta pages) is acceptable without re-serving it over HTTP is unknown. |
| Matches well / badly | With NVD only: same population as B1, using Grype's own CPE logic. Grype by default *suppresses* CPE matching for ecosystems where it expects GHSA data, so an NVD-only DB needs non-default configuration to match them at all (**to verify**). | n/a | Java, .NET, native archives reasonably; known for high FP from evidence-based CPE guessing. |
| FN / FP | As B1, but the mapping heuristics are the tool's and cannot be curated by us. | n/a | FP-heavy; a second, SBOM-independent component inventory that can disagree with `02-sbom-inventory`. |
| Offline / reproducibility | Two identities enter the fingerprint: V09's and the built DB's (hash, schema version, build tooling digest). A new **out-of-run DB build job** is required; it needs no network if it reads `/data`. | — | Same two-identity problem; several analyzers call external services and must be provably disabled. |
| New burden | DB-build pipeline + adapter + three pinned tools (scanner, `grype-db`, `vunnel`); DB schema version couples scanner and builder. | — | JVM image, DB build job, analyzer lockdown, output normaliser. |
| Licence | Apache-2.0 tools; data as B1. | Apache-2.0 | Apache-2.0 |
| V05 contract effect | `match_basis` values as B1 plus an opaque `tool-reported` value, because the tool does not always say *why* it matched. Adds a required `derived_database_identity`. | — | Breaks the declared `02-sbom-inventory` → `02-sca-vulnerability-match` edge semantics (matcher ignores the SBOM). |
| Verify before V11 | Everything marked above, plus: DB build is deterministic for a fixed snapshot; no phone-home with updates disabled. | — | As left. |

Net: B2 buys someone else's CPE heuristics at the price of a second pinned database, a build job
and an adapter, and it does **not** fix the underlying problem (A, finding 1). Trivy is dropped;
Dependency-Check is dropped because it bypasses the accepted SBOM edge.

### B3. Add an offline OSV snapshot **in addition to** NVD

A second out-of-run publisher (same pattern as `nvd_feed.py`) mirrors OSV's bulk per-ecosystem
export; the matcher matches purl/ecosystem+version against OSV ranges and keeps NVD for
CPE-identified components.

This **partially revisits G3**: the Decisions row says "no new OSV publisher" and also "Adding an
offline OSV snapshot later remains possible without changing the node or contract"
(ADR-0010 `:18`). It is framed here strictly as *in addition to* NVD and needs the owner's
explicit yes (gate M2). It needs **one new out-of-run publisher with one fixed network
destination** (the OSV bulk-export host) — a B11 capability authorized outside any engagement run,
exactly as the NVD publisher is. No engagement-run job gains network.

| Aspect | Assessment |
|---|---|
| Matches well | npm, PyPI, Go, crates, RubyGems, NuGet, Maven, Packagist: exact ecosystem+name+version-range matching, including GHSA-only advisories with no CVE. |
| Matches badly | Vendored/native C and C++ with no package identity — which is what NVD+CPE covers. The two are complementary. |
| FN / FP | Lowest of all options for ecosystem packages. FP mainly from wrong ecosystem version semantics; FN from advisories not yet in OSV. Duplicate reporting of one issue under CVE and GHSA ids must be collapsed by alias. |
| Offline / reproducibility | Same story as NVD: immutable snapshot, pointer, hashes, age. Two database identities in the fingerprint; `vulnerability-database-identity` becomes a list or gains a sibling record. |
| Code / ownership | New publisher + new consumer binding (a second V09) + OSV range evaluator per ecosystem version scheme. Largest build of the options. |
| Tool / image pinning | None if matched natively. If `osv-scanner` is reused in offline mode, one pinned tool; its offline-database layout and flags are **to verify**. |
| Licence | OSV records carry per-source licences (several are CC-BY and need attribution) — **to verify** per source before redistribution in evidence bundles. `osv-scanner` is Apache-2.0. |
| V05 contract effect | `match_basis` gains `purl-ecosystem-range`; `database_kind` gains `osv`. Both must already be enums (section C) for this to be additive. |
| Threat-workbench family | The only option that gives the workbench real known-vulnerability leads for typical service targets. |
| Verify before V11 | Bulk-export location, format stability and size; licence terms; alias handling; per-ecosystem version comparison. |

### B4. SBOM only in `02`; all matching in `06-cve-reachability` (baseline, ADR option G3-C)

Not chosen at G3 and shown only for comparison. No deterministic match evidence exists; a persona
lane would do CPE matching by judgement; the workbench (`03`, which has no edge to `06`) gets no
vulnerability leads; `02-sca-vulnerability-match` and its contract are deleted from the packet.
Zero new code, zero pinning, and the worst FN/FP character because nothing is reproducible.
It contradicts the adopted node list and is not offered as a gate answer.

### B5. Hybrid / phased: B1 now, B3 later, one contract

Ship B1 with honest coverage gaps. Write the V05 contract so that `match_basis`, `database_kind`
and the database-identity cardinality are already open to B3. When (and if) M2 is answered yes,
the OSV publisher, binding and range evaluator are added as tool instances of the same node; no
node, edge or contract id changes — which is what ADR-0010 `:18` already promises.

Cost: until B3 lands, SCA output for npm/PyPI/Go-heavy targets is mostly gap records, and
reviewers must not read a short match list as a clean bill. Benefit: V05 and V11 unblock now, on
the data the owner named, with no new tool to pin and no second database.

## C. Contract consequences that hold under every option

V05 can start on these today; none depends on gates M1–M5.

1. `match_basis` is a **closed enum, not a const**, on every match record. Minimum values:
   `cpe-sbom-declared`, `cpe-generated`, `cpe-curated-rule`; reserved for B3:
   `purl-ecosystem-range`. The V09 identity schema's `const: "cpe"`
   (`schemas/vulnerability-database-identity.schema.json:30`) describes the *database*, not a
   match, and must be reconciled (follow-up; not edited here).
2. Every match cites the database identity it was made against (`snapshot_id` + `content_sha256`),
   and the identity record is a required artifact. A match without it is rejected (V05 acceptance).
3. Every SBOM component appears **exactly once** in the output: as one or more matches, as
   `evaluated-no-match`, or as a coverage gap. Gap reasons are a closed enum, at least:
   `no-cpe-mapping`, `ambiguous-cpe-mapping`, `version-missing`, `version-unparseable`,
   `version-scheme-unsupported`, `ecosystem-not-covered-by-database`. `evaluated-no-match` is
   allowed only when a mapping existed and every candidate range was evaluated; it still asserts
   nothing beyond "no advisory range in this snapshot covered this version".
4. A database-side coverage block: snapshot age/freshness, count of CVE records with no
   `configurations`, count skipped by `vulnStatus`. An empty match list with these absent is invalid.
5. A match means **"an advisory range covers the declared version"**. Reachability,
   exploitability, affected-product proof, severity-for-this-target and "finding" are forbidden
   fields; `06-cve-reachability` owns them (`job-nodes.proposal.json` claim class
   `known_vulnerability_match_lead`).
6. Each match records the **version scheme** used (`semver`, `pep440`, `maven`, `go-pseudo`,
   `cpe-loose`, …) and the evaluated bounds. An unparseable or scheme-less version is a gap, never
   "not vulnerable". Wildcard/`-`/`*` CPE versions are recorded as such, not silently matched.
7. `02-dependency-lifecycle`: `supported` is never inferred from absence in the reference table;
   absence is `lifecycle-unknown` with the table identity cited.
8. An inferred vendored component (license/L12 inference) is never promoted to a declared
   component; if matched, its basis says so.
9. Stale snapshot ⇒ `OK_WITH_GAPS`; missing ⇒ `BLOCKED`; never a live fetch (V09 outcomes).

## D. Recommendation (as drafted; superseded by the Decisions above)

**Recommendation (not a decision): B5 — ship B1 now, keep the contract open for B3, and ask the
owner separately whether B3 may be built.**

Reasoning: the snapshot contains what range evaluation needs and nothing a third-party scanner
needs, so B2 adds a build job, an adapter and three pinned identities without improving ecosystem
coverage; Trivy cannot use the data at all. B1 is small, deterministic, fingerprintable with the
identity V09 already produces, and honest: its weakness shows up as counted gap records instead of
silence. It is also strongest exactly where OSV is weakest (vendored native code), so it is not
throwaway work if B3 follows. B3 is the only route to useful ecosystem coverage, but it revisits
an owner decision and needs a new networked publisher, so it must be the owner's call (M2), not a
side effect of tool selection.

## E. Human gates (all decided 2026-09-20; see Decisions)

> **Gate M1 — Matcher.** Which matcher does `02-sca-vulnerability-match` use against the NVD
> snapshot?
> - A. **(Recommended)** Native in-repo CPE matcher (B1), contract written so OSV can be added
>   later (B5).
> - B. Grype with a database built offline from the NVD snapshot (B2), subject to V11 proving the
>   build can be driven from our mirror.
> - C. No matching in `02`; remove the node and leave matching to `06-cve-reachability` (B4;
>   reverses part of the accepted G3/node list).

> **Gate M2 — OSV alongside NVD.** May an offline OSV snapshot be added *in addition to* the NVD
> copy, via a new out-of-run publisher with one fixed network destination?
> - A. **(Recommended)** Yes, as a later task after the NVD matcher is qualified; no engagement-run
>   job gains network.
> - B. Yes, and build it before V11 so the first SCA worker ships with both sources.
> - C. No. NVD only; ecosystem packages stay coverage gaps permanently.

> **Gate M3 — purl→CPE rules.** How are curated purl→CPE mapping rules produced and who owns them?
> - A. **(Recommended)** A versioned, hashed rule table in the repo, owned by the M05 batch owner,
>   changed only by reviewed commit; its sha256 enters the input fingerprint; SBOM-declared and
>   syft-generated CPEs are used but labelled separately.
> - B. No curated table: use only CPEs already present in the SBOM; everything else is a gap.
> - C. Curated table plus per-engagement overrides supplied at intake (recorded and fingerprinted).

> **Gate M4 — Freshness policy.** What is `max_age` for the NVD snapshot, and who owns it?
> - A. **(Recommended)** 7 days, owned by the repo owner, recorded as one policy record that the
>   run configuration cites; older ⇒ `OK_WITH_GAPS` with age recorded.
> - B. 48 hours (the publisher schedule is every two hours), same ownership.
> - C. 30 days, same ownership.
> - D. No default: each engagement states `max_age` at intake; a run without one is `BLOCKED`.

> **Gate M5 — Gaps and the threat workbench.** How are components with no CPE mapping presented to
> the `sbom-sca-license-lifecycle` source family?
> - A. **(Recommended)** Surfaced: matches plus an aggregated gap summary (counts by ecosystem and
>   reason, with the full per-component list available by reference), so the workbench can see
>   that coverage is partial.
> - B. Surfaced in full: every gap record goes into the bundle.
> - C. Withheld: only matches reach the workbench; gaps stay in `coverage.json` for
>   `02-evidence-assembly` and `06`.

## F. Follow-ups outside this document's boundary

To be done by the integrator / owning batch once the gates are answered — not done here:

- `docs/decisions/ADR-0010-vendor-prepass-decomposition.md` — add the matcher outcome (and M2–M5)
  to the Decisions table and a Revision Notes line; if M2 ≠ C, amend the G3 row's "no new OSV
  publisher" wording.
- `docs/proposals/vendor-prepass/task-series.md` — V05 deliverables/acceptance gain section C
  (enum `match_basis`, closed gap-reason enum, database-side coverage block, version-scheme
  field); V11 gains the chain-folding reader and the "to verify" items; V09's "matcher selection
  is open" note is closed; if M2 = A/B, add a publisher task and a second binding task.
- `docs/proposals/vendor-prepass/job-nodes.proposal.json` — replace
  `tool_instances[0].tool_id: "nvd-cpe-matcher-tbd"` (`:427`) and its note for
  `02-sca-vulnerability-match`; extend `identity_requirement` with the rule-table hash (M3).
- `docs/proposals/vendor-prepass/threat-workbench-producers.proposal.yaml` — artifact list for the
  family per M5.
- `schemas/vulnerability-database-identity.schema.json:30` and `sca_nvd_snapshot.py:34` —
  reconcile `match_basis: const "cpe"` with the enum in C.1 (rename to a database-level field or
  widen); `database_kind` const → enum if M2 ≠ C. Changes the fingerprint component version.
- `appsec-review-process/sca_nvd_snapshot.py` — expose the verified, ordered blob list on
  `Resolution` so the matcher does not re-derive it (`docs/sca-nvd-snapshot-binding.md:240-241`).
- `appsec-review-process/nvd_feed.py` — V09's publisher weaknesses (unsigned root, 64-bit parent
  binding). No option here *depends* on fixing them, but B2 would copy unauthenticated data into a
  second database, widening the exposure. Separately: nothing records how many records lack
  `configurations`; the matcher must compute it.
- A freshness-policy record and owner (M4); `data/feeds/nvd/README.md:28-29` refers to one that
  does not exist.
- `appsec-review-process/06-cve-reachability/config.md:23` still reads
  `static-evidence/sca/osv-scanner.json` (already a V11 repoint item).
- `appsec-review-process/TODO.md:753` ("network-enabled Trivy/Grype DB refreshes") is superseded
  by G3 under M1 = A and should be struck or reworded.
