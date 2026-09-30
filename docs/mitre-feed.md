# MITRE ATT&CK / CAPEC / CWE reference feed

ATT&CK, CAPEC and the CWE catalog, published the same way as the NVD and OSV feeds: a writer publishes
immutable snapshots, a resolver checks integrity and age, a Dagster op refreshes it. Decisions:
[ADR-0026](decisions/ADR-0026-mitre-attack-capec-reference-feed.md) and its CWE addendum (brief O2).

**Labels, never evidence.** An ATT&CK technique or CAPEC pattern id labels a claim or a chain link.
It never supports, promotes or upgrades a finding, never changes a review state, chain state or
severity, and a claim never needs one.

## Sources (pinned by release, verified 2026-09-29)

| Source | Default | URL | Upstream version | sha256 |
|---|---|---|---|---|
| `enterprise-attack` | yes | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json` | ATT&CK 19.2 | `dc1639ca…c3d8f4` |
| `capec` | yes | `https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.2/capec/2.1/stix-capec.json` | CAPEC 3.9 | `ee6244f4…76fa69` |
| `mobile-attack` | no | `…/attack-stix-data/v19.2/mobile-attack/mobile-attack-19.2.json` | ATT&CK 19.2 | `acfa5ca2…dada64` |
| `ics-attack` | no | `…/attack-stix-data/v19.2/ics-attack/ics-attack-19.2.json` | ATT&CK 19.2 | `08b83d2c…82dada9` |
| `cwe` | yes | `https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip` | CWE List 4.20 | OPEN (version-pinned) |

Full hashes are in `mitre_feed.SOURCES`. A fetched bundle must hash to its pin and carry the pinned
upstream version (`x-mitre-collection.x_mitre_version`, `x_capec_version`); anything else is a failed
source. Never `master` or `latest` at run time: raising a pin is a reviewed edit of `SOURCES`.
Mobile/ICS: `APPSEC_MITRE_SOURCES=enterprise-attack,capec,mobile-attack` or `sync --sources ...`.
CAPEC comes from `mitre/cti` (STIX 2.1) because `capec.mitre.org` was not reachable from the build
sandbox; the XML at capec.mitre.org is the same 3.9 release.

CWE is pinned by version (never `cwec_latest`): the zip must hold exactly one `cwec_v<version>.xml`
(no DTD, size-capped) whose `Weakness_Catalog` `Version` equals the pin. `cwe.mitre.org` was not
reachable from the build sandbox either, so its byte pin (`sha256`) is still `None`; the smoke script
prints the digest of the first real download so it can be pinned (TODO section O2).

## Layout

Publication root `data/feeds/mitre` (override `APPSEC_MITRE_FEED_ROOT`; git-ignored; exported by
`orchestrator/dagster/code-location.sh`):

```
current.json                      atomic pointer: snapshot id + manifest sha256
snapshots/<snapshot_id>/
  manifest.json                   per source: URL, upstream version, sha256, bytes, record count,
                                  fetched_at, etag, licence, MITRE marking statements; gaps; reference hash
  NOTICE.txt                      MITRE copyright designations and the ATT&CK / CAPEC terms-of-use licence text
  reference.json                  derived table (attack_reference.py), hash-listed in the manifest
  cwe-catalog.json                derived CWE table (cwe_catalog.py), hash-listed as manifest.cwe_catalog
  sources/<source>.json           unmodified upstream STIX bundles
  sources/cwe.xml.zip             unmodified upstream CWE zip
staging/  locks/  events.jsonl
```

`reference.json` is a pure function of the bundle bytes (sorted, no timestamps, no model prose), so
re-syncing the same pins yields the same `reference_sha256` even though each sync publishes a new
snapshot id. It holds ATT&CK tactics and techniques/sub-techniques (id, name, tactics, platforms,
deprecated, revoked, url, domains) and CAPEC patterns (id, name, status, deprecated, related CWE ids,
related ATT&CK ids where MITRE gives them, url).

`cwe-catalog.json` has the same shape as the committed `data/reference/cwe/cwe-catalog.json`
(`id`, `name`, plus `status`, `abstraction` and `deprecated`; deprecated weaknesses are flagged, not
dropped). It is derived through `cwe_catalog._parse_xml` (one parser for intake and the feed), is a
pure function of the zip bytes, and its `as_of` is MITRE's release date, so a re-sync of the same pin
keeps the same `sha256`. `reference.json` does not change when CWE is added.

## Modules

| Module | Role |
|---|---|
| `mitre_feed.py` | Writer and resolver. `sync` (per-source failure carries the last good bundle forward with its ORIGINAL `fetched_at`; only a total failure or a failed derivation fails the sync and leaves `current.json` untouched), `verify` (re-hash everything), `resolve` (integrity + age; `SnapshotBlocked` / `SnapshotStale` / `SnapshotInvalid`, the SCA registry's semantics). Keeps the last N snapshots (`APPSEC_MITRE_KEEP`, default 3). |
| `cwe_catalog.py` | `current()` is the catalog in force: the feed's `cwe-catalog.json` (via `mitre_feed.resolve_cwe`) when the snapshot verifies and the CWE source is in the ceiling, else the committed curated catalog with a recorded gap. `bound(identity)` reproduces a stage's bound catalog without re-ageing it. The rule map is always the committed hash-pinned file. `intake` (offline manual import) still works. CLI: `cwe_catalog.py current [--validate CWE-n]`. |
| `attack_reference.py` | Derives `reference.json`; `Reference.validate_technique(id, tactic=None)` / `validate_capec(id)` return `OK` / `UNKNOWN_ID` / `DEPRECATED` / `TACTIC_MISMATCH`; `screen()` is the one gate for claims and chain links. CLI: `attack_reference.py technique T1190 --tactic initial-access`, `attack_reference.py capec CAPEC-66`. |

The feed is not bound into `dependency_snapshot_registry` (that registry is shaped for container
scanner databases: `data/` mount, closed metadata record). `mitre_feed.resolve` gives the same
outcomes instead.

## Age ceiling and the staleness rule

One tunable, `reference_snapshot_max_age_seconds` (1,209,600 s = 14 days, `appsec-review-process/pipeline/tunables.json`),
is the ceiling for OSV, the OSV SCA registry binding and this feed. Age is measured from the OLDEST
usable source's original `fetched_at`.

| Snapshot state | OSV | MITRE labels |
|---|---|---|
| in ceiling | used | validated; only `OK` ids kept |
| older than the ceiling | SCA fails (`SNAPSHOT_TOO_OLD`) | **gap** `MITRE_REFERENCE_STALE`: every tag withheld |
| never published / missing | SCA blocked | **gap** `MITRE_REFERENCE_MISSING`: every tag withheld |
| fails integrity | SCA fails | **gap** `MITRE_REFERENCE_INVALID`: every tag withheld |
| one source missing (e.g. CAPEC) | ecosystem gap | that kind's tags withheld as `MITRE_REFERENCE_MISSING` |

CWE follows the same ceiling, measured from the CWE source's own ORIGINAL `fetched_at` (`resolve_cwe`;
`resolve` ages ATT&CK/CAPEC only, so one kind going stale never withholds the other):

| CWE state | Catalog used | Gap recorded |
|---|---|---|
| in ceiling | feed `cwe-catalog.json` (full MITRE catalog) | none |
| older than the ceiling | committed curated catalog (96 ids) | `CWE_REFERENCE_STALE` |
| no feed, no CWE source, or a bad zip at sync | committed curated catalog | `CWE_REFERENCE_MISSING` |
| integrity failure, or the rule map names an id the feed catalog lacks | committed curated catalog | `CWE_REFERENCE_INVALID` |

Whichever catalog is in force, an unknown or deprecated CWE id is still rejected (reviewer reply,
repair round) or dropped with a note (tool tag); it is never published. The claim path (07/09/12)
binds the catalog identity (table hash, or the curated fallback and its gap; never the snapshot id,
which changes every sync) into its inputs when a decision carries `cwe`, and records `cwe_catalog`
(snapshot id or `committed-curated`) on each judgment. `finding-enrichment.json` records the catalog
used; a fallback also appears as a report limitation.

A stale label table does not stop a code review: tags are withheld and the gap is recorded; an
unvalidated id is never published. William can change this to a hard block (ADR-0026, decision 2).
Per-tag drops are recorded as `MITRE_REF_UNKNOWN_ID`, `MITRE_REF_DEPRECATED` (deprecated or revoked),
`MITRE_REF_TACTIC_MISMATCH` or `MITRE_REF_OVER_LIMIT` (more than 8 per claim or link). A malformed tag
is described (`<malformed id, N chars>`), never echoed.

## Where tags go

- **Claims (07 red team).** Optional `attack_refs` / `capec_refs` in the reviewer decision, next to
  `cwe`. The screened result is `mitre_refs` (`schemas/mitre-refs.schema.json`) on the hypothesis and
  carried unchanged to 08, 09 and 12. The reference identity (or its gap) is bound into the 07 inputs
  only when a decision is tagged, so a re-validation reproduces the same tags and a stale or re-pinned
  snapshot re-executes the stage. Not yet shown in the synthesis report (OPEN, TODO section O).
- **Chain links (lane 14).** Optional `attack_refs` per composer link, validated against the link
  stage's tactics (`attack_reference.CHAIN_STAGE_TACTICS`); drops are composer limitations. Rendered
  only in the report's attack-chain section, with the ATT&CK version.

## Lookup tools (ADR-0034 item 5)

Model jobs can look up an id instead of carrying the matrix in the prompt: `mitre_technique`
(`id=T1190` or `T1078.004`, optional `tactic=` shortname or `TA` id), `mitre_capec` (`id=CAPEC-66`) and
`mitre_cwe` (`id=CWE-89`), in `mitre_query_mcp.py`, served by `input_mcp.py` on the same pattern as
the `code_*` tools ([code-query-tools.md](code-query-tools.md), ADR-0032):

- **Grant.** Only when the job's tooling profile lists `query tool: mitre_<...>` (today
  `claim-review-static`, which also covers the lane 14 composer, and `hypothesis-hunt-static`) and the
  tunable `mitre_query_attack_enabled` / `mitre_query_capec_enabled` / `mitre_query_cwe_enabled`
  (default on) is on. No per-job pin. The tools live on the input server, so only indexed-mode jobs
  get them; the grant never makes an inline job indexed. `--allowedTools`, the server's tools/list and
  the `mitre_lookup` tool guide come from one granted list.
- **One table per invocation.** The invoker takes `mitre_query_mcp.binding()` (the ATT&CK/CAPEC
  `attack_reference.binding()` plus the CWE catalog identity) once and passes it to the server, which
  reopens exactly that table (`attack_reference.bound` / `cwe_catalog.bound`: checked for integrity,
  not re-aged). The attempt's limitations record the table used ("MITRE lookups answered from ...").
- **Answers.** `status` (`OK` / `UNKNOWN_ID` / `DEPRECATED` / `TACTIC_MISMATCH`), `entry` (names,
  tactics, platforms, related ids from the pinned table only), `reference` (reference hash, ATT&CK
  and CAPEC versions) or `catalog` (CWE catalog source, version, hash), `gap`, `truncated` (names over
  `mitre_query_text_chars_max`, lists over `mitre_query_list_items_max`), and a fixed note that the
  answer is untrusted data. A missing, stale or invalid snapshot is an answer with `status=null` and
  gap `MITRE_REFERENCE_MISSING` / `_STALE` / `_INVALID`: never an error and never a guessed name.
  `mitre_cwe` uses the addendum's `CWE_REFERENCE_*` codes; on the curated fallback it still names
  ids the committed catalog holds, and returns `status=null` (not `UNKNOWN_ID`) for ids outside it. A
  malformed id is `UNKNOWN_ID` with `malformed=true` and is described (`<malformed id, N chars>`),
  never echoed.
- **Labels, not evidence.** The guide says so, says a gap means the name is unknown rather than the id
  being wrong, and forbids concluding a claim from a lookup. Tags a worker emits still go through
  `screen()` and the CWE checks, and the 07 lifecycle still binds the reference identity when a
  decision is tagged.
- **Not bound into the model job's inputs.** The pool jobs' input identity does not include the MITRE
  binding. Binding it unconditionally would re-run every granted model stage when the snapshot goes
  stale, and ADR-0026 section 5 binds only tagged decisions. The binding is recorded in the attempt
  instead.

## Dagster

`mitre_sync_work` is the third independent op of `nvd_reference_sync` (tag `mitre_feed_id=mitre`,
same 2-hour schedule and network pool; `APPSEC_NVD_SCHEDULE=stopped` stops all three). A failure in
one op never stops the others.

## Commands

```
python3 appsec-review-process/mitre_feed.py sync        # normally the Dagster op does this
python3 appsec-review-process/mitre_feed.py verify
python3 appsec-review-process/mitre_feed.py resolve     # exit 2 missing, 3 stale, 4 invalid
python3 appsec-review-process/mitre_feed.py resolve --cwe  # CWE catalog; exit 2 missing, 3 stale, 4 invalid
python3 appsec-review-process/attack_reference.py technique T1059.004 --tactic execution
python3 appsec-review-process/cwe_catalog.py current --validate CWE-1321
python3 appsec-review-process/mitre_query_mcp.py mitre_technique T1190   # the lookup tool's answer
bash scripts/smoke_mitre_feed.sh                         # sync, verify, resolve, T1190 OK, T9999 UNKNOWN_ID, stale,
                                                         # CWE-1321 OK, CWE-99999 rejected, stale CWE falls back
```
