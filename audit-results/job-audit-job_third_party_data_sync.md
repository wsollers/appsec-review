# Job 47/47 — job_third_party_data_sync

## Scope and verdict

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review` through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. HEAD and clean tracked/untracked status were confirmed before and after the audit. `.venv/bin/python` imports `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read the updated assignment brief, authorized checkout's `AGENTS.md`, and canonical multi-session coordination skill. The Windows working checkout was not audited, executed, or modified.
- Read-only functional audit, not a live feed validation or vulnerability assessment. No downloads, actual tools/containers/providers, network connections, services, installations, environment-file changes, commits, or subagents. Reproductions used synthetic bytes, test-owned files, real parsing/index/publication functions, blocked sockets/subprocesses, and no-op durability flushes.
- **Ten findings: two high, seven medium, one low.** All have bounded reproductions or an explicitly identified static extension of a reproduction. **201 focused units passed in 7.92 s**, two workers, shuffled; zero failures/skips and zero cases over ten seconds. One real-loopback HTTP unit was deliberately deselected.
- Passing those tests does not establish exact correctness: the reproduced cases expose untested data loss, acceptance, provenance, and consumer-boundary failures.

## Registration, activation, input and output contract

`runtime/registry.py:85,155` imports/registers the factory. `jobs/job_third_party_data_sync/datasets.py:27-35` declares `MAINTENANCE`, no accepted semantic upstream inputs, no scheduling predecessors, `TargetAccess.NONE`, `always_execute=True`, and `propagate_handoff=True`. `job.py:307-309` enables strict gaps. `orchestration/topology.py:46-58` includes only `REVIEW_GRAPH` contracts, excluding this job. `orchestration/dagster/adapter.py:404-443` creates its standalone graph and schedule from enabled configuration.

The dev job is enabled; TOML declares job workers 3, all seven steps and 21 tasks at one worker, and enabled `0 0 * * *` UTC scheduling (`appsec-review.toml:296-508`). This is configuration, **not verification that a host schedule is running**; T-106 explicitly tracks the stopped/failing nightly schedule.

`validate_input` (`job.py:73-86`) requires the exact seven-step set and task order, constructs every feed's settings, confines feed roots to repository `data`, and confines mutable metadata to the run-storage parent. There is no target access or model/prompt/guidance worker. Missing task tool-binding declarations are already T-147; they do not mean these tasks do not execute.

The job result is `appsec-review/job-result/third-party-data-sync/1`; final validation checks its schema label and complete unit-receipt key set (`job.py:285-305`). Individual validators check expected schema labels, not full feed-domain content (`job.py:99-104`). Domain validation belongs to the feed implementations. Runtime finalization verifies task result hashes, strict control-field/outcome accounting, and rejects failed attempts (`runtime/runner.py:959-1022`, `interchange.py:521-565`).

The one declared dataset, `feed_sync_work`, is protected/reference-authority and claims
`data/jobs/job_third_party_data_sync/attempts/*/steps/*/tasks/*/work/**`
(`datasets.py:13-19`). It covers download/index/build/import work, not shared snapshots, global metadata, or NVD's feed-root staging/download/blob directories. Its declaration is attached to `nvd_sync` with the aggregate result schema; there is no indexed public feed payload in that dataset.

### Configured sources and actual bounds

| Branch | Configured identity | Actual validation, bounds and reuse |
|---|---|---|
| NVD | Fixed official `nvd.nist.gov/feeds/json/cve/2.0` yearly feeds, then `services.nvd.nist.gov/rest/json/cves/2.0`; first year 2002; optional `NVD_API_KEY` | Fresh `.meta`, gzip/plain sizes and SHA-256; 512 MiB compressed download, 64 MiB API response, page size 2000, 119-day windows, 120/90 s socket timeouts, six retries with 5–60 s backoff, 0.6/6 s API pacing. Verified yearly cache; incremental immutable parent chain and SQLite merge. F01–F03 affect completeness/validation. No configured total-chain, total-page, or decompressed-year byte ceiling. |
| OSV | Fixed HTTPS Google Storage ecosystem archives: PyPI, crates.io, npm, Go, Maven, Packagist, NuGet, RubyGems | 512 MiB per archive, 2 GiB aggregate declared expansion, 500,000 distinct IDs, lookup cap 500, 300 s socket timeout. ZIP path/size checks, advisory/package/alias SQLite tables and whole-archive ecosystem metadata. F04 affects duplicate versions; F09 affects custom-root consumers. |
| Grype | `https://grype.anchore.io/databases/v6/latest.json`, allowed host `grype.anchore.io`, tool **0.119.0**, schema major **6** | Active listing, relative `.tar.zst`, SHA-256, five-day build age/300 s future tolerance; 64 KiB listing, 1 GiB compressed, 4 GiB expanded/database, eight tar headers, 128 MiB zstd window; 300 s download/900 s tool timeout, 6g memory. No redirects. Closed extraction/import cache and exact image/version/status validation. No build/pull fallback. |
| MITRE | Required enterprise ATT&CK **19.2**, CAPEC **3.9**, CWE **4.20**; configured but unselected mobile/ICS ATT&CK 19.2 | Enterprise SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`; CAPEC `ee6244f48259c1963d0507535e1843d67ba08fe58b4dfe351c1b74f9e376fa69`. CWE is version-configured but **not hash-pinned**. 256 MiB source/512 MiB XML expansion, 250,000 records, lookup 500, 300 s socket timeout. 32 consequences, 16 terms, 128 chars per term. F05/F08 affect identity/truncation accounting. |
| cve-bin-tool | Builder tag `appsec-review/cve-bin-tool:3.4`, tool **3.4**, `tools/cve-bin-tool`, optional exact image ID unset | Exact NVD result from this attempt; oldest-first verified layers copied/rehashed; build timeout 1800 s/run timeout 3600 s; networkless DB construction. Missing unpinned Docker tag can trigger an image build; pinned absence refuses it. Native path requires preinstalled image and reserves 2 CPU/4g. No explicit layer-byte/database-size ceiling in these settings. F06 affects output validation. |
| KEV | CISA `known_exploited_vulnerabilities.json`, allowed host `www.cisa.gov`; no optional SHA pin configured | 32 MiB, 50,000 records, 120 s socket timeout; version/release/array, count if supplied, unique CVE IDs and dates, sorted SQLite rows. Empty catalogs are currently accepted. |
| EPSS | FIRST `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`; same host allowlist; no optional SHA pin configured | 64 MiB compressed/256 MiB expanded, 1,000,000 rows, 120 s socket timeout; required model/date/header, unique CVEs, finite probabilities in [0,1], nonempty scores, sorted SQLite rows. |

The general downloader's redirected-source behavior is F07. Feed settings other than Grype are not uniformly closed/strictly typed; for example OSV/MITRE convert values and do not validate positive/finite timeouts. This was inspected, but not expanded into another finding.

## Every declared step/task

All handler references below are in `src/appsec_review/jobs/job_third_party_data_sync/job.py`; implementation paths are relative to the same job directory.

| Step/task | Handler and real implementation | Inputs, output and observed limit |
|---|---|---|
| `nvd_sync.fetch` | `119-122`; `steps/nvd_sync/feed.py:509-676` | No upstream; acquires writer lock, bootstraps or extends and **already publishes** snapshot/current pointer. Output is `nvd-current-pointer/1` because the returned pointer's schema overwrites the wrapper's `nvd-fetch/1` literal. F01–F03. |
| `nvd_sync.process` | `124-130`; `NvdPublisher.verify`, `feed.py:678-725` | Depends on fetch; verifies manifest/blob/parent/index identities and requires same snapshot ID. Returns `nvd-process/1` plus fetch's manifest hash. Not the indexing step: indexing happened during fetch. |
| `nvd_sync.publish` | `132-138` | Depends on process; writes mutable global NVD metadata, returns `nvd-publication/1`. |
| `osv_sync.fetch` | `140-141`; `steps/osv_sync/feed.py:51-60` | No upstream; downloads every configured ecosystem to task work; `osv-fetch/1`. Source redirect issue F07. |
| `osv_sync.index` | `143-144`; `steps/osv_sync/feed.py:63-132` | Fetch archives; validates names/expansion/IDs, creates advisory/package/alias/metadata tables; `osv-index/2`. F04. Zero-record archive accepted; ecosystem still recorded as indexed whole. |
| `osv_sync.publish` | `146-155`; `steps/osv_sync/feed.py:135-156` | Fetch + index results; snapshots source ZIPs and index, verifies current, writes metadata; `osv-publication/1`. F09/F10. |
| `grype_db_sync.fetch` | `200-202`; `steps/grype_db_sync/feed.py:88-106` | No upstream; listing/source identity/freshness and archive checksum; `grype-fetch/1`. |
| `grype_db_sync.import` | `204-213`; `steps/grype_db_sync/feed.py:155-249` | Fetch receipt, configured/frozen catalog; bounded zstd/tar extraction, pinned-image version/import/status commands; `grype-import/1`. Real tools not run. |
| `grype_db_sync.publish` | `215-227`; `steps/grype_db_sync/feed.py:290-364` | Revalidates fetch/import files, publishes closed five-file cache, verifies fresh current **and checks pointer/verified snapshot equality**; `grype-publication/1`. |
| `mitre_sync.fetch` | `157-158`; `steps/mitre_sync/feed.py:88-101` | No upstream; selected source downloads and configured pin checks; `mitre-fetch/1`. F07. |
| `mitre_sync.normalize` | `160-161`; `steps/mitre_sync/feed.py:164-248` | STIX bundle or CWE XML, normalized entries/consequences; `mitre-normalize/2`. F05/F08; required source selection does not enforce nonzero useful rows. |
| `mitre_sync.publish` | `163-172`; `steps/mitre_sync/feed.py:251-275` | Source bytes/index, counts/truncation metadata; verify/current/global metadata; `mitre-publication/1`. F10. |
| `cve_bin_tool_db_build.resolve_nvd_snapshot` | `229-231`; `steps/cve_bin_tool_db_build/database.py:61-97` | **Only cross-step edge: `nvd_sync.publish`.** Requires exact NVD pointer/hash, traverses acyclic chain and rehashes raw layers oldest first; `resolved-nvd-snapshot/1`. |
| `cve_bin_tool_db_build.build` | `233-235`; `steps/cve_bin_tool_db_build/database.py:252-272`; `tools/cve-bin-tool/build_db.py` | Resolved layers copied/rehashed; injected or Docker/native builder; `_check` validates some DB content; `cve-bin-tool-build/1`. F06. Real formatter/populate behavior unverified. |
| `cve_bin_tool_db_build.publish` | `237-249`; `steps/cve_bin_tool_db_build/database.py:275-282,321-328` | Three output files, NVD/tool/count metadata; verifies NVD binding then global metadata; `cve-bin-tool-publication/1`. Does not compare returned publication pointer against verified current ID. |
| `kev_sync.fetch` | shared `178-179`; `steps/kev_sync/feed.py:68-80` | No upstream; HTTPS catalog, bytes/optional pin; `kev-fetch/1`. F07. |
| `kev_sync.normalize` | shared `181-182`; `steps/kev_sync/feed.py:100-151` | Catalog validation and sorted DB; `kev-normalize/1`. |
| `kev_sync.publish` | shared `184-195`; `steps/kev_sync/feed.py:154-178` | Source/index snapshot, verify current, mutable global metadata; `kev-publication/1`. F10 reproduced here. |
| `epss_sync.fetch` | shared `178-179`; `steps/epss_sync/feed.py:76-88` | No upstream; gzip source, bytes/optional pin; `epss-fetch/1`. F07. |
| `epss_sync.normalize` | shared `181-182`; `steps/epss_sync/feed.py:103-166` | Bounded expansion/metadata/header/score validation and DB; `epss-normalize/1`. |
| `epss_sync.publish` | shared `184-195`; `steps/epss_sync/feed.py:169-188` | Source/index snapshot, verify current, global metadata; `epss-publication/1`. F10. |

Six branches are independent; cve-bin-tool alone depends on NVD publication. The direct `UnitExecutor` executes declared units serially and records failed/skipped dependent units while continuing unrelated branches (`runtime/units.py:84-222`). Dagster owns parallel scheduling. The claimed-unit finalizer requires all successful terminal receipts; failed attempts have no accepted handoff. Earlier successful **feed** publications are not rolled back by a later branch failure. No synthetic successful gap result is manufactured by the feed handlers.

## Immutable publication, reuse and actual consumers

- General publisher (`publication.py:86-155`) hashes source files, computes a manifest-derived snapshot ID, locks a feed writer, copies into private staging, verifies files, atomically exposes the directory, refuses differing existing manifest bytes, records provenance, and atomically updates `current.json`. Metadata under `runs/metadata/{feeds,jobs}` is mutable coordination state, not per-review evidence.
- NVD has content-addressed raw and metadata blobs, immutable parent-linked manifests and a hashed `index/nvd.sqlite`; its verified yearly download cache is the only download reuse here. Grype preserves `6/vulnerability.db`, `6/import.json`, source listing, version and status records; the archive and command receipts stay in protected attempt work.
- OSV publishes source ZIPs plus `index/osv.sqlite`; MITRE source documents plus `index/mitre.sqlite`; KEV/EPSS source files plus their corresponding index; cve-bin-tool `cve.db`, `version_map.db`, `build.json`. Schemas are respectively OSV snapshot `/1`, MITRE `/2` and index `/2`, KEV/EPSS `/1`, Grype `/2`, cve-bin-tool `/1`, NVD manifest `/2`.
- `storage/feed_provenance.py` was read fully: configured root/claim/config hashes, immutable producer records, computation fingerprint, legacy unknown-origin handling, NVD parent/blob checks, run-local use proofs, and pinned consumption. Producer records outlive runs. F10 concerns mixed identities in the task/global metadata, not an assertion that the immutable snapshot publisher overwrites an existing snapshot.
- `always_execute` is honored by `runtime/resume.py:80-81`; fresh dispatch does not reuse the whole job. Identical manifest bytes may reuse an immutable directory. OSV/MITRE/Grype include retrieval metadata in manifest identity; cve's generated version-map timestamp also changes output bytes. Only KEV/EPSS explicitly omit retrieval timestamps/HTTP validators from their snapshot identity. No portable failed-attempt feed checkpoint is implemented here.
- `job_review_data_indexing/job.py:108-162` verifies and pins NVD, OSV, MITRE, KEV, EPSS and cve-bin-tool from **frozen configured roots**, requires the five queryable feed index files, and records snapshot hashes/freshness. It does not depend on a maintenance-job accepted handoff.
- `review/references.py:92-164` consumes accepted indexing feed pins, verifies provenance/index hash, and loads CWE identities/consequences for review; unavailable/stale catalog handling is explicit. Advisory/index consumers query stored reference data rather than feed archives; `osv_matching.py:248-293,334-379` supplies the verified F04 downstream example.
- `job_dependency_intelligence/native_advisories.py:271-274,331-352,440-449` uses `verify_consumer` and actual cve-bin-tool CPE-range/severity rows. Artifact security uses the same verified database offline (`scanners.py:249-250,300-303`).
- Evidence collection and artifact security verify Grype with frozen settings/exact tool identity and mount it read-only. OSV scanner consumers mount required ecosystem ZIPs, but use hard-coded roots rather than the configured publisher root: F09.
- Reference presence never establishes target applicability, reachability or exploitation.

## Findings

### SYNC-F01 — High — Bootstrap cursor skips updates newer than the downloaded yearly snapshots

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/feed.py:510,517,533,547-549,575,583-590`.
- **Trigger:** A verified yearly feed's `.meta.lastModifiedDate` precedes bootstrap wall-clock time, and a CVE changes between those instants.
- **Expected:** Incremental coverage starts at a watermark actually covered by the bootstrap inputs, or bootstrap catches up from that watermark before advancing the cursor.
- **Actual:** Metadata dates are retained but ignored when choosing the cursor: it is set to bootstrap `clock()`. The next API request starts there, skipping the uncovered interval.
- **Bounded reproduction A:** Feed metadata 00:00Z, bootstrap 02:00Z, an API-visible CVE change 01:00Z, next sync 03:00Z. Fake API honors the requested time filter. Both snapshots verify, but the changed CVE remains absent; the next request starts at 02:00Z.
- **Impact:** Missing/obsolete NVD records can persist indefinitely unless changed again; derived cve-bin-tool databases replay the same incomplete history.
- **Confidence:** High; real publisher/index/verification executed.
- **Smallest correction:** Derive a conservative bootstrap watermark from all verified source snapshots and cover the gap with bounded API windows before declaring the later cursor.
- **TODO overlap:** Related operational completeness scope T-106; no matching root-cause item found. T-113's prior coverage claim does not cover this case.

### SYNC-F02 — High — Inconsistent NVD page counts are accepted and permanently advance the cursor

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/feed.py:594-620,639-648`.
- **Trigger:** Valid JSON says `resultsPerPage=2,totalResults=2` but contains zero vulnerabilities, or an equivalent short/nonconforming page.
- **Expected:** Require returned count to equal parsed rows and validate page/window continuity; reject incomplete windows without pointer advancement.
- **Actual:** Pagination advances by the unverified `resultsPerPage`, not `count`; `index >= total` ends the window before the empty-page check.
- **Reproduction A:** Real `sync` accepted the zero-row/two-declared page, published a new cursor at 04:00Z, and `verify()` passed with only the prior one CVE.
- **Impact:** Incomplete API results are recorded as completed coverage, preventing subsequent incremental requests from recovering omitted changes.
- **Confidence:** High.
- **Smallest correction:** Validate parsed count, requested limit, remaining total and stable pagination before storing/advancing a completed window; distinguish legitimate cross-window duplicates.
- **TODO overlap:** T-106/T-113 are related, not existing descriptions of this defect.

### SYNC-F03 — Medium — Yearly NVD parser accepts malformed or incomplete JSON documents

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/nvd_sync/feed.py:243-274,522-523`; downstream whole-document parser `tools/cve-bin-tool/build_db.py:39`.
- **Trigger:** A source has the vulnerabilities-array closing bracket but lacks its enclosing object close, or omits commas between vulnerability objects.
- **Expected:** A successful yearly parse establishes a valid NVD document and complete array/envelope.
- **Actual:** The regex locates an array without parsing the envelope; a comma is optional, and `]` causes the rest of the stream to be discarded without JSON validation.
- **Reproduction A:** Standard `json.loads` rejects both fixtures; `iter_vulnerabilities` accepts one and two records respectively.
- **Impact:** Upstream size/hash equality does not establish JSON validity. Such bytes can enter the NVD chain and index, while cve-bin-tool's full JSON loader subsequently rejects the retained raw layer.
- **Confidence:** High for parser acceptance and static downstream incompatibility; no actual builder tool executed.
- **Smallest correction:** Use a bounded streaming JSON parser that validates separators and the complete top-level envelope/format/version.
- **TODO overlap:** T-113 (parser coverage); no exact existing item found.

### SYNC-F04 — Medium — OSV duplicate merging silently discards newer advisory state, withdrawal and aliases

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/osv_sync/feed.py:97-117`; `src/appsec_review/osv_matching.py:255-270,365-379`.
- **Trigger:** Sequential ecosystem archives contain different valid revisions of the same advisory, including a later withdrawal or corrected affected range.
- **Expected:** Choose/validate the advisory version deterministically, retain consistent package/range/alias data, or expose conflicting revisions as a gap.
- **Actual:** First copy wins `INSERT OR IGNORE`; only package associations merge. Newer `modified`, `withdrawn`, raw ranges and aliases are ignored without a gap.
- **Reproduction B:** Earlier unwithdrawn record from PyPI, newer withdrawn duplicate from npm. Real index/matcher returned `status=complete`, one affected match, zero withdrawn, no gaps, and lost the later CVE alias.
- **Impact:** Advisory applicability and CVE cross-reference context can be wrong and depend on archive order. The matcher is currently default-disabled, but the stale raw record/alias loss exists in every generated index.
- **Confidence:** High.
- **Smallest correction:** Resolve duplicate revisions by validated identity/time with explicit conflict policy, updating the associated package/alias/raw data consistently; add a withdrawal/different-version cross-archive regression.
- **TODO overlap:** T-013 owns matcher evolution, not duplicate-version reconciliation. The operations page explicitly documents “first archive”; that describes the defective behavior rather than preventing its stale-result impact.

### SYNC-F05 — Medium — Unversioned, non-CWE XML is published under the configured CWE version

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/mitre_sync/feed.py:204-212,251-267`; unpinned CWE source `appsec-review.toml:426-429`.
- **Trigger:** Configured CWE ZIP contains XML with no `Version` and an unrelated root but descendant elements named `Weakness`.
- **Expected:** Validate the CWE catalog identity and require the configured version before producing its classification index.
- **Actual:** Version comparison runs only if the attribute is truthy; root/namespace are not checked. Arbitrary matching local element names become CWE entries, with the configured version retained in source metadata.
- **Reproduction B:** `<unrelated><Weakness ID="79" Name="Unversioned"/></unrelated>` successfully normalized, published and verified as one CWE entry under required version 4.20. Required ATT&CK/CAPEC bundle selections with zero objects also published zero counts without a gap.
- **Impact:** A wrong/unidentified source document can be treated as the pinned catalog and affect permitted CWE/classification context.
- **Confidence:** High.
- **Smallest correction:** Require the expected catalog root/namespace and a nonempty exact version, with explicit required-source content validation.
- **TODO overlap:** T-113; no exact existing identity-validation item found.

### SYNC-F06 — Medium — cve-bin-tool validation trusts the declared range count without checking range rows

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/cve_bin_tool_db_build/database.py:234-249,275-282,310-328`; consumer query `src/appsec_review/jobs/job_dependency_intelligence/native_advisories.py:350-352`.
- **Trigger:** Builder output has a healthy SQLite file and correct NVD severity count but incomplete/empty CPE-range content inconsistent with `build.json`.
- **Expected:** Validate actual range/source/schema content and its declared count before claiming a verified derived database.
- **Actual:** `_check` queries only `cve_severity`; it returns `range_count` and `layer_records` directly from JSON. Both publication verification and scanner/native-advisory consumer verification reuse this check.
- **Reproduction B:** One NVD severity row, zero `cve_range` rows, declared range count 99: `_check` succeeds and returns “verified” range count 99.
- **Impact:** A structurally healthy but incomplete database can be published/consumed as verified, omitting native advisory matches and reporting incorrect counts.
- **Confidence:** High for acceptance. Actual pinned-tool output corruption was not asserted or tested.
- **Smallest correction:** Query/validate NVD range rows and required columns, compare actual counts with the build record, and validate nonnegative replay-count facts against input receipts where meaningful.
- **TODO overlap:** T-5049 is the separate range-query indexing performance item; T-113 covers real-tool fixture gaps. Neither implements this integrity check.

### SYNC-F07 — Medium — General downloader's redirects escape the configured HTTPS source identity

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/publication.py:32-48,76-82`; OSV/MITRE/KEV/EPSS default downloader construction in their `fetch` functions.
- **Trigger:** An initially allowed HTTPS feed URL redirects to another host or to HTTP.
- **Expected:** Every fetched location obeys configured source policy, and provenance records the effective source or explicitly bounded redirect chain.
- **Actual:** Only the initial URL is checked. Default `urllib.request.urlopen` follows redirects; the response's effective URL is never checked, and the receipt records the original allowed URL.
- **Reproduction C:** With fake transport, the standard-library redirect handler constructs `http://different.invalid/catalog`; real `HttpDownloader.download` accepts its response bytes and records `https://allowed.invalid/catalog`. No real redirect/network request occurred.
- **Impact:** Configured source identity/HTTPS claims need not describe the actual byte supplier. Grype is not affected because it explicitly disables redirects.
- **Confidence:** High static flow plus fake-boundary reproduction; live server behavior intentionally untested.
- **Smallest correction:** Disable redirects or apply the same scheme/host/credential validation on every redirect and record bounded effective-source identity.
- **TODO overlap:** T-113's transport validation; no exact existing item found.

### SYNC-F08 — Low — MITRE character truncation is omitted from truncation accounting

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/steps/mitre_sync/feed.py:130-146,157-161,225-245`.
- **Trigger:** A normalized CWE scope/impact term exceeds 128 characters while term/consequence counts stay within their caps.
- **Expected:** `consequence_truncated_weaknesses` reflects every weakness whose captured consequence content was cut, as the function contract says.
- **Actual:** `_terms` slices characters before examining truncation and returns a flag only for excess term count.
- **Reproduction B:** A 129-character impact becomes 128 characters with `truncated=False`.
- **Impact:** Completeness/truncation metadata understates lost content.
- **Confidence:** High.
- **Smallest correction:** Carry a character-truncation flag into the existing aggregate; do not increase bounds.
- **TODO overlap:** T-113; no exact existing item found.

### SYNC-F09 — Medium — Configurable OSV publisher root is ignored by the actual scanner consumers

- **Evidence:** Publisher configuration `src/appsec_review/jobs/job_third_party_data_sync/steps/osv_sync/feed.py:30-40,142-148`; consumers `src/appsec_review/jobs/job_evidence_collection/job.py:337-342` and `src/appsec_review/jobs/job_artifact_security_analysis/scanners.py:239-252`; configured-root pinning contrast `src/appsec_review/jobs/job_review_data_indexing/job.py:126-139`.
- **Trigger:** Set the supported OSV `feed_root` to another valid directory beneath repository `data`.
- **Expected:** Every review consumer resolves the snapshot from that run's frozen configured root.
- **Actual:** Both OSV scanner paths always read repository `data/feeds/osv`. Indexing uses the correct configured root. Under active provenance enforcement, an old default-root snapshot also disagrees with the configured root and fails closed.
- **Reproduction C:** Successfully published/verified a fixture under `data/feeds/custom-osv`; real evidence-collection prerequisite resolution returned zero mounts and an unavailable-snapshot `FileNotFoundError` gap.
- **Impact:** A successful sync can supply indexing but not scanners. This is a named coverage loss, not a claim of silent clean coverage.
- **Confidence:** High for publisher/evidence-collection path; artifact-security occurrence is the identical verified static hard-coded-root defect.
- **Smallest correction:** Give OSV consumers a frozen-settings helper like Grype/cve-bin-tool and resolve the configured root.
- **TODO overlap:** T-013 is related OSV consumer work, not this root mismatch. No matching finding in the prior job reports searched.

### SYNC-F10 — Medium — Interleaved publishers produce successful receipts containing different snapshot identities

- **Evidence:** `src/appsec_review/jobs/job_third_party_data_sync/job.py:148-155,165-172,184-195`; per-publication lock/return `publication.py:119-151`; correct equality guard for comparison `job.py:217-221`.
- **Trigger:** Another permitted sync publishes the same feed after this unit's `publish()` releases the writer lock but before its separate `verify()` reads `current.json`.
- **Expected:** Verify the exact snapshot just published, or fail if current changed; task/global metadata must agree on one identity.
- **Actual:** OSV/MITRE/KEV/EPSS handlers return the original pointer alongside the newer verified identity and write both into global metadata. Only Grype explicitly compares the IDs.
- **Reproduction D:** Two real valid KEV publications were interleaved at the verify boundary. Handler result and metadata contained pointer `sha256-46b5637bfc1dfbbcdd117a7b` but verified identity `sha256-ba31e6d889a5d434469d5cb3`; its output validator accepted the result.
- **Impact:** Successful attempt/global metadata misattributes another publication as verification of its own work. Immutable payload bytes themselves were not overwritten.
- **Confidence:** High for KEV, static shared-handler equivalence for EPSS and identical OSV/MITRE sequences. cve-bin-tool also lacks pointer equality, but its NVD binding check narrows the race; it was not included in the reproduced affected set.
- **Smallest correction:** Verify by returned snapshot/manifest identity rather than floating current, or enforce matching snapshot and manifest hash before returning metadata.
- **TODO overlap:** T-5038 concerns post-run manifest/provenance instability, but this audit does **not** prove that historical failure has this cause. Related T-106/T-113; no exact existing race item found.

## Non-findings, documented limitations and unproved concerns

- **Publication age is not source-data age.** Reproduction C published EPSS scores dated 2020-01-01; the real indexing pin reported `pinned`, `stale=False` because `published_at` was fresh. `job_review_data_indexing/job.py:150-157` explicitly implements publication-age policy; the operations documentation says this too. Recorded as a confirmed design limitation/T-106 overlap, not an additional new defect. Grype separately validates upstream build age.
- **No whole-job transaction.** A failure in one branch can coexist with new usable snapshots from others. This matches the operations documentation and is not a rollback bug.
- **Empty reference sets.** OSV archives, MITRE bundles and KEV catalogs can produce zero rows; EPSS and cve-bin-tool refuse their respective empty outputs. These behaviors were traced. No live format/expected cardinality was available to justify certifying an empty reference set as complete.
- **Boundedness limits.** NVD decompression walks the complete gzip before comparing `.meta` size/hash; it has no independent uncompressed-year bound. cve's image builder reads/decompresses full layers and derives a new timestamped version-map. Native CPU/memory reservation does not make total replay layers or output sizes independently bounded. These are named audit limits, not tested resource-exhaustion allegations.
- **XML declaration guard scope.** MITRE checks `payload[:65536]` for DTD/entity declarations. No entity expansion or out-of-prefix/encoding test was executed, and no exploitation claim is made.
- **Configured live identities not verified.** Upstream URL availability, exact current pin matches/formats, real Grype import, actual cve-bin-tool 3.4 formatter/populate/update semantics and tool-output schema remain unverified. Synthetic doubles do not establish those facts.
- **Documentation drift:** claims that NVD protocol violations always fail and cve “matching build counts” are validated are stronger than F02/F03/F06 permit. The MITRE truncation claim is stronger than F08. “Verified external snapshots” must not be read as verification of live configured source pins in this audit.

## Focused validation: commands, counts, timing and evidence

Every Linux command below ran in the authorized checkout through this transport; no WSL service operation was performed:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Exact Linux command/script below
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

### Collection

```sh
.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-sync-47-collect-20261118-1404 \
  tests/unit/job_third_party_data_sync/test_contract.py \
  tests/unit/job_third_party_data_sync/test_job_graph.py \
  tests/unit/job_third_party_data_sync/test_publication.py \
  tests/unit/job_third_party_data_sync/test_cve_bin_tool_database.py \
  tests/unit/job_third_party_data_sync/test_osv_feed.py \
  tests/unit/job_third_party_data_sync/test_nvd_sync_job.py \
  tests/unit/job_third_party_data_sync/test_nvd_http.py \
  tests/unit/job_third_party_data_sync/test_reference_feed_sync.py \
  tests/unit/job_third_party_data_sync/test_grype_db_sync.py \
  -k 'not test_real_http_truncation_resumes_from_the_written_offset' | tail -5
```

Result: **201/202 collected, one deselected, 0.49 s**, exit 0. A generic unknown-config-option warning tail was visible; its specific key was not retained by this intentionally bounded output. This was not a test failure. No dependency was installed. The root and unit harnesses were inspected, including preflight, private scratch/fixture pins, fake fsync and external-execution guards.

### Rejected wrapper invocation

The following full selection was first invoked with a trailing unsupported `-p no:cacheprovider`:

```sh
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 47 \
  --max-tests 201 --expect-tests 201 --timeout-seconds 180 -- \
  tests/unit/job_third_party_data_sync/test_contract.py \
  tests/unit/job_third_party_data_sync/test_job_graph.py \
  tests/unit/job_third_party_data_sync/test_publication.py \
  tests/unit/job_third_party_data_sync/test_cve_bin_tool_database.py \
  tests/unit/job_third_party_data_sync/test_osv_feed.py \
  tests/unit/job_third_party_data_sync/test_nvd_sync_job.py \
  tests/unit/job_third_party_data_sync/test_nvd_http.py \
  tests/unit/job_third_party_data_sync/test_reference_feed_sync.py \
  tests/unit/job_third_party_data_sync/test_grype_db_sync.py \
  -k 'not test_real_http_truncation_resumes_from_the_written_offset' -p no:cacheprovider
```

Exit **2** before collection/execution: `unsupported focused pytest option '-p'; scope/report/worker options belong to run-tests`. Zero tests ran; elapsed not measured. Retried with only that unsupported option removed; no source/environment/tooling changes.

### Successful wrapper invocation

```sh
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 47 \
  --max-tests 201 --expect-tests 201 --timeout-seconds 180 -- \
  tests/unit/job_third_party_data_sync/test_contract.py \
  tests/unit/job_third_party_data_sync/test_job_graph.py \
  tests/unit/job_third_party_data_sync/test_publication.py \
  tests/unit/job_third_party_data_sync/test_cve_bin_tool_database.py \
  tests/unit/job_third_party_data_sync/test_osv_feed.py \
  tests/unit/job_third_party_data_sync/test_nvd_sync_job.py \
  tests/unit/job_third_party_data_sync/test_nvd_http.py \
  tests/unit/job_third_party_data_sync/test_reference_feed_sync.py \
  tests/unit/job_third_party_data_sync/test_grype_db_sync.py \
  -k 'not test_real_http_truncation_resumes_from_the_written_offset'
```

Wrapper used `.venv/bin/python`, its own unique base temp
`test/tmp/tests-custom-20261118-140146-525673-3674194`, two workers, seed 47, exact count guard 201. Result: **201 passed, 7.92 s, zero failures, zero skips, no tests over 10 s**. The one deselected node is
`tests/unit/job_third_party_data_sync/test_nvd_http.py::test_real_http_truncation_resumes_from_the_written_offset`
because it starts a real loopback HTTP server, outside this assignment.

| Unit file | Passed | Slowest case (seconds) |
|---|---:|---:|
| test_contract.py | 3 | 0.336 |
| test_job_graph.py | 18 | 0.136 |
| test_publication.py | 9 | 0.020 |
| test_cve_bin_tool_database.py | 24 | 0.218 |
| test_osv_feed.py | 13 | 0.109 |
| test_nvd_sync_job.py | 9 | 0.327 |
| test_nvd_http.py | 30 | 0.005 |
| test_reference_feed_sync.py | 26 | 0.528 |
| test_grype_db_sync.py | 69 | 1.322 |

Retained wrapper evidence, repository-relative:

- `test/tmp/logs/tests-custom-20261118-140146-525673-3674194.log`
- `test/tmp/tests-custom-20261118-140146-525673-3674194.junit.xml`
- `test/tmp/tests-custom-20261118-140146-525673-3674194.timings.sqlite`
- `test/tmp/tests-custom-20261118-140146-525673-3674194.collection.json`
- `test/tmp/reports/tests-custom-20261118-140146-525673-3674194.json`

### Reproduction A — NVD loss and parsing

Exact Python command body, run with `.venv/bin/python - <<'PY'`:

```python
import gzip, hashlib, io, json, os, shutil, socket, sqlite3, subprocess, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.feed import NvdPublisher, iter_vulnerabilities
from appsec_review.jobs.job_third_party_data_sync.steps.nvd_sync.models import NvdSettings
from tests.unit.job_third_party_data_sync.test_nvd_sync_job import vulnerability
start=time.monotonic()
base=Path('test/tmp')/('job-audit-sync-47-nvd-repro-'+uuid.uuid4().hex)
base.mkdir(parents=True)
class Client:
    def __init__(self):
        self.raw=json.dumps({'format':'NVD_CVE','version':'2.0','vulnerabilities':[vulnerability('CVE-2026-1000')]}).encode()
        self.gz=gzip.compress(self.raw,mtime=0); self.starts=[]; self.bad_page=False
    def get_bytes(self,url,api_key=None):
        if url.endswith('.meta'):
            return (f'lastModifiedDate:2026-10-08T00:00:00.000Z\nsize:{len(self.raw)}\ngzSize:{len(self.gz)}\nsha256:{hashlib.sha256(self.raw).hexdigest()}\n').encode()
        first=parse_qs(urlsplit(url).query)['lastModStartDate'][0]; self.starts.append(first)
        changed='2026-10-08T01:00:00.000Z'
        rows=[vulnerability('CVE-2026-1001',changed)] if first<=changed else []
        return json.dumps({'format':'NVD_CVE','version':'2.0','startIndex':0,'resultsPerPage':2 if self.bad_page else len(rows),'totalResults':2 if self.bad_page else len(rows),'vulnerabilities':rows}).encode()
    def download(self,url,destination,api_key=None,*,expected_size=None):
        destination.write_bytes(self.gz); return len(self.gz)
def forbidden(*args,**kwargs): raise AssertionError('external boundary forbidden')
try:
    with patch('socket.socket.connect',forbidden), patch('subprocess.Popen',forbidden), patch('os.fsync',lambda _:None):
        settings=NvdSettings.from_mapping(base,{'feed_root':'data/feeds/nvd','first_year':2026,'request_delay_without_key_seconds':0})
        client=Client(); instant=datetime(2026,10,8,2,tzinfo=timezone.utc)
        publisher=NvdPublisher(settings,client=client,clock=lambda:instant,pause=lambda _:None)
        p1=publisher.sync('fixture-bootstrap')
        instant+=timedelta(hours=1); p2=publisher.sync('fixture-incremental')
        verify=publisher.verify()
        db=settings.feed_root/'snapshots'/p2['snapshot_id']/'index/nvd.sqlite'
        with sqlite3.connect(db) as conn: ids=[row[0] for row in conn.execute('SELECT cve_id FROM cve ORDER BY cve_id')]
        assert p1['cursor']=='2026-10-08T02:00:00.000Z' and client.starts==[p1['cursor']] and ids==['CVE-2026-1000']
        print('NVD_BOOTSTRAP_LAG',json.dumps({'source_last_modified':'2026-10-08T00:00:00.000Z','bootstrap_cursor':p1['cursor'],'missed_change':'CVE-2026-1001 at 01:00Z','next_api_start':client.starts[0],'verified_ids':ids}))
        client.bad_page=True; instant+=timedelta(hours=1)
        p3=publisher.sync('fixture-inconsistent-page'); verify=publisher.verify()
        manifest=json.loads((settings.feed_root/'snapshots'/p3['snapshot_id']/'manifest.json').read_bytes())
        assert manifest['record_count']==0 and verify['index']['record_count']==1
        print('NVD_INCONSISTENT_PAGE',json.dumps({'declared_total':2,'declared_returned':2,'actual_rows':0,'published_cursor':p3['cursor'],'verified_count':verify['index']['record_count']}))
        a=json.dumps(vulnerability('CVE-2026-1000')).encode(); b=json.dumps(vulnerability('CVE-2026-1001')).encode()
        for label,raw in [('missing_outer_close',b'{"vulnerabilities":['+a+b']'),('missing_comma',b'{"vulnerabilities":['+a+b' '+b+b']}')]:
            try: json.loads(raw)
            except json.JSONDecodeError: pass
            else: raise AssertionError('fixture must be invalid JSON')
            parsed=list(iter_vulnerabilities(io.BytesIO(raw)))
            print('NVD_INVALID_JSON',label,'accepted_records',len(parsed))
finally:
    shutil.rmtree(base)
print('elapsed_seconds',round(time.monotonic()-start,3),'scratch_removed',str(base))
```

Exit 0; **0.307 s**. Output confirmed F01/F02 and malformed-JSON accepted counts 1/2. Scratch `test/tmp/job-audit-sync-47-nvd-repro-977b1db2ea5a47b1bdada5d7f88c4c45` removed.

### Reproduction B — MITRE, OSV and cve-bin-tool

Exact `.venv/bin/python - <<'PY'` body:

```python
import io, json, os, shutil, socket, sqlite3, subprocess, time, uuid, xml.etree.ElementTree as ET, zipfile
from pathlib import Path
from unittest.mock import patch
from appsec_review.jobs.job_third_party_data_sync.steps.mitre_sync import feed as mitre
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv
from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as cve
from appsec_review.osv_matching import match_package
from tests.unit.job_third_party_data_sync.test_osv_feed import _fetched
from tests.unit.job_third_party_data_sync.test_cve_bin_tool_database import write_databases
start=time.monotonic(); base=Path('test/tmp')/('job-audit-sync-47-reference-repro-'+uuid.uuid4().hex); base.mkdir(parents=True)
def forbidden(*a,**k): raise AssertionError('external boundary forbidden')
try:
    with patch('socket.socket.connect',forbidden),patch('subprocess.Popen',forbidden),patch('os.fsync',lambda _:None):
        sources={k:{'kind':v,'url':'https://cwe.mitre.org/x','version':'4.20'} for k,v in [('enterprise_attack','attack'),('capec','capec'),('cwe','cwe')]}
        cfg=mitre.MitreSettings.from_mapping(base,{'feed_root':'data/feeds/mitre','source_selections':list(sources),'sources':sources})
        work=base/'mitre';work.mkdir()
        (work/'empty.json').write_text('{"type":"bundle","objects":[]}')
        with zipfile.ZipFile(work/'cwe.zip','w') as archive:
            archive.writestr('not-cwe.xml','<unrelated><Weakness ID="79" Name="Unversioned"/></unrelated>')
        fetched={'sources':{name:{**entry,'path':str(work/('cwe.zip' if name=='cwe' else 'empty.json'))} for name,entry in sources.items()}}
        normalized=mitre.normalize(cfg,fetched,work/'normalized'); pointer=mitre.publish(cfg,fetched,normalized); verified=mitre.verify(cfg)
        assert normalized['source_counts']=={'enterprise_attack':0,'capec':0,'cwe':1}
        print('MITRE_UNVERSIONED_WRONG_ROOT',json.dumps({'required_version':'4.20','source_counts':normalized['source_counts'],'verified_count':verified['record_count'],'published':pointer['snapshot_id']}))
        term='x'*129
        entries,truncated=mitre.weakness_consequences(ET.fromstring('<Weakness><Common_Consequences><Consequence><Impact>'+term+'</Impact></Consequence></Common_Consequences></Weakness>'))
        assert len(entries[0][1][0])==128 and truncated is False
        print('MITRE_TERM_TRUNCATION','original_length',len(term),'stored_length',len(entries[0][1][0]),'truncated',truncated)
        old={'id':'GHSA-fixture','modified':'2026-01-01T00:00:00Z','affected':[{'package':{'ecosystem':'npm','name':'fixture'},'versions':['1.0.0']}]}
        new={**old,'modified':'2026-02-01T00:00:00Z','withdrawn':'2026-02-01T00:00:00Z','aliases':['CVE-2026-1001']}
        cfg_o=osv.OsvSettings.from_mapping(base,{'feed_root':'data/feeds/osv','ecosystems':['PyPI','npm']})
        fetched_o=_fetched(base/'osv',{'PyPI':{'shared.json':old},'npm':{'shared.json':new}})
        idx=osv.index(cfg_o,fetched_o,base/'osv-index')
        with sqlite3.connect(idx['database_path']) as conn:
            result=match_package(conn,'npm','fixture','1.0.0'); aliases=conn.execute('SELECT * FROM alias').fetchall()
        assert result['status']=='complete' and len(result['matches'])==1 and result['withdrawn_count']==0 and aliases==[]
        print('OSV_NEWER_WITHDRAWAL_IGNORED',json.dumps({'status':result['status'],'matched':len(result['matches']),'withdrawn':result['withdrawn_count'],'aliases':aliases,'gaps':result['gaps']}))
        output=base/'cve-out'; write_databases(output,cve_count=1)
        build=json.loads((output/'build.json').read_text());build['range_count']=99
        (output/'build.json').write_text(json.dumps(build))
        with sqlite3.connect(output/'cve.db') as conn: actual=conn.execute('SELECT COUNT(*) FROM cve_range').fetchone()[0]
        checked=cve._check(output,'3.4')
        assert checked['range_count']==99 and actual==0
        print('CVE_RANGE_COUNT_UNCHECKED',json.dumps({'declared_and_verified_ranges':checked['range_count'],'actual_ranges':actual,'verified_cves':checked['cve_count']}))
finally:
    shutil.rmtree(base)
print('elapsed_seconds',round(time.monotonic()-start,3),'scratch_removed',str(base))
```

Exit 0; **0.160 s**. Results are recorded under F04/F05/F06/F08. Scratch `test/tmp/job-audit-sync-47-reference-repro-0c0fe3f67213466c8db99db084c4b239` removed.

### Reproduction C — transport identity, custom root and documented freshness limitation

Exact `.venv/bin/python - <<'PY'` body:

```python
import io,json,shutil,socket,subprocess,time,uuid,urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.jobs.job_third_party_data_sync.publication import HttpDownloader,verify_current
from appsec_review.jobs.job_evidence_collection.job import _prerequisites
from tests.fixtures.reference_feeds import publish_osv, publish_epss, epss_bytes, pin_feeds
start=time.monotonic();base=Path('test/tmp')/('job-audit-sync-47-boundary-repro-'+uuid.uuid4().hex);base.mkdir(parents=True)
def forbidden(*a,**k): raise AssertionError('external boundary forbidden')
try:
    with patch('socket.socket.connect',forbidden),patch('subprocess.Popen',forbidden),patch('os.fsync',lambda _:None):
        class Response(io.BytesIO):
            status=200;headers={'Content-Length':'2'}
            def geturl(self): return 'http://different.invalid/catalog'
        followed=[]
        def redirected(request,*,timeout,context):
            changed=urllib.request.HTTPRedirectHandler().redirect_request(request,None,302,'Found',{},'http://different.invalid/catalog')
            followed.append(changed.full_url);return Response(b'{}')
        with patch('urllib.request.urlopen',redirected):
            receipt=HttpDownloader().download('https://allowed.invalid/catalog',base/'redirect.json',max_bytes=10,allowed_hosts=('allowed.invalid',))
        assert followed==['http://different.invalid/catalog'] and receipt['url']=='https://allowed.invalid/catalog'
        print('REDIRECT_IDENTITY',json.dumps({'followed':followed[0],'recorded_url':receipt['url'],'accepted_bytes':receipt['size_bytes']}))
        custom=publish_osv((base/'data/feeds/custom-osv').resolve(),[{'id':'OSV-fixture','affected':[{'package':{'ecosystem':'PyPI','name':'fixture'}}]}],base/'osv-work')
        assert verify_current(custom,'osv')['verified_files']==2
        selection=SimpleNamespace(applicable=True,files=('requirements.txt',))
        unit=SimpleNamespace(job=SimpleNamespace(repository_root=base.resolve(),run_root=base/'run'))
        _,mounts,environment,gap=_prerequisites(unit,SimpleNamespace(tool_id='tool-osv-scanner'),selection)
        assert not mounts and 'OSV database snapshot is unavailable' in gap
        print('CUSTOM_OSV_ROOT',json.dumps({'custom_snapshot_verified':True,'scanner_mounts':len(mounts),'gap':gap}))
        # A documented freshness limitation, not counted as a new defect in this audit.
        old=publish_epss((base/'data/feeds/epss').resolve(),epss_bytes([('CVE-2026-1000',0.1,0.2)],score_date='2020-01-01'),base/'epss-work')
        from datetime import datetime,timezone
        pins=pin_feeds(base.resolve(),{'epss':old},now=datetime.now(timezone.utc),overrides={'epss':3})
        print('DOCUMENTED_PUBLICATION_AGE_LIMITATION',json.dumps({'score_date':'2020-01-01','pin_status':pins['epss']['status'],'stale':pins['epss']['stale']}))
finally:
    shutil.rmtree(base)
print('elapsed_seconds',round(time.monotonic()-start,3),'scratch_removed',str(base))
```

Exit 0; **0.130 s**. Results: redirected supplier accepted under original URL; custom-root scanner mounts 0/unavailable; old EPSS `pinned/stale=False`. Scratch `test/tmp/job-audit-sync-47-boundary-repro-dde4722da81f4bbaa8c5a0c6471b5c11` removed.

### Reproduction D — actual publication interleaving

Exact `.venv/bin/python - <<'PY'` body:

```python
import json,shutil,socket,subprocess,time,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.jobs.job_third_party_data_sync.job import build_job
from appsec_review.jobs.job_third_party_data_sync.steps.kev_sync import feed
from tests.fixtures.reference_feeds import kev_document,kev_entry,kev_settings
from tests.unit.job_third_party_data_sync.test_reference_feed_sync import Downloader
start=time.monotonic();base=(Path('test/tmp')/('job-audit-sync-47-publication-repro-'+uuid.uuid4().hex)).resolve();base.mkdir(parents=True)
def forbidden(*a,**k):raise AssertionError('external boundary forbidden')
try:
    with patch('socket.socket.connect',forbidden),patch('subprocess.Popen',forbidden),patch('os.fsync',lambda _:None):
        cfg=kev_settings(base/'data/feeds/kev')
        a=feed.fetch(cfg,base/'a',Downloader(json.dumps(kev_document([kev_entry('CVE-2026-1000')],version='A')).encode()))
        na=feed.normalize(cfg,a,base/'na')
        b=feed.fetch(cfg,base/'b',Downloader(json.dumps(kev_document([kev_entry('CVE-2026-1001')],version='B')).encode()))
        nb=feed.normalize(cfg,b,base/'nb')
        outputs={'kev_sync.fetch':a,'kev_sync.normalize':na}
        job=SimpleNamespace(repository_root=base,config=SimpleNamespace(step=lambda _:SimpleNamespace(settings={'feed_root':str(cfg.feed_root),'url':cfg.url})),metadata_root=base/'runs/metadata',run_id='fixture',attempt_id='attempt_0001')
        context=SimpleNamespace(job=job,output=outputs.__getitem__)
        unit=next(unit for unit in build_job().units if unit.unit_id=='kev_sync.publish')
        real_verify=feed.verify
        def interleaved(settings):
            feed.publish(settings,b,nb)
            return real_verify(settings)
        with patch.object(feed,'verify',interleaved):
            result=unit.handler(context)
        for validator in unit.output_validators:validator(context,result)
        metadata=json.loads(Path(result['metadata_path']).read_bytes())
        assert result['pointer']['snapshot_id']!=result['identity']['snapshot_id']
        print('PUBLICATION_INTERLEAVING',json.dumps({'published_pointer':result['pointer']['snapshot_id'],'verified_identity':result['identity']['snapshot_id'],'validator_accepted':True,'metadata_mismatch':metadata['pointer']['snapshot_id']!=metadata['identity']['snapshot_id']}))
finally:
    shutil.rmtree(base)
print('elapsed_seconds',round(time.monotonic()-start,3),'scratch_removed',str(base))
```

Exit 0; **0.082 s**. Both real snapshots verified individually; mixed task/global identities and validator acceptance were observed. Scratch `test/tmp/job-audit-sync-47-publication-repro-165caad0a0bd4783a020ce1c9eb7f976` removed.

## Read coverage, existing work and material unread scope

**Read fully:** updated audit brief; authorized `AGENTS.md` and multi-session skill; both third-party-sync operations pages; job `job.py`, `datasets.py`, `publication.py`; all seven nontrivial step implementations, NVD models/index; Grype config; all nine mapped job unit test files (including the deliberately unexecuted real-HTTP case); `tests/fixtures/reference_feeds.py`, `tests/fixtures/grype.py`; `tests/unit/conftest.py`, unit environment guard; `runtime/units.py`; `storage/feed_provenance.py`; cve-bin-tool `build_db.py` and Dockerfile; shell test wrapper/common helper.

**Read relevant ranges/searches:** TOML 296–508; registry import/registration; topology 1–110; standalone Dagster creation/scheduling 404–443; runtime job 124–165, resume 50–112, runner 945–1025, interchange 480–565; root pytest harness 1–180; wrapper `ops_tests.py` 95–145,345–430 and option locations; review-data feed pinning 95–168; evidence-collection prerequisite 270–390 and Grype/offline-consumer locations; artifact scanners 220–325; native-advisory verify/query locations; review references 1–165; OSV matching 248–295,334–382; job-interchange architecture 89–165; jobs/runtime architecture 11–51,416–467; `tests/job-test-map.json` job selection and shared references.

**Prior work checked:** relevant TODO headings/text T-009, T-013, T-106, T-113, T-147, T-5038, T-5049 and related searches. Prior session job reports were searched for third-party sync, bootstrap cursor, pagination, cve-range, freshness/feed pins, OSV raw record, feed-root and consequence truncation overlap; indexing report findings were checked. No claim that every historical report/TODO was read in full. T-5038's actual incident was not investigated because that would require existing host feed/run evidence. No TODO was added or edited.

**Material unread/unexecuted gaps:** the eight mapped integration files, integration fixtures/conftest and real loopback test execution; whole claimed-job lifecycle/Dagster acceptance; deployed schedule/source mount/native engine/signature validation; all existing host feed stores, pins, runs and target material; actual external URLs and pinned source bytes; installed container internals and cve-bin-tool third-party library implementation; broad consumer implementations beyond the named interfaces; most generic storage/container runtime, full JSON-schema registry and unrelated runtime paths; trivial package `__init__.py` files were not separately read. No target findings or live output quality were assessed.

The wrapper evidence remains under its private `test/tmp` run directory; all four ad hoc reproduction directories were removed by their own `finally` blocks. Source remained clean at the exact required revision. This is the final assigned job; no further job audit was started.
