# MITRE ATT&CK / CAPEC / CWE reference feed

ATT&CK, CAPEC and (brief O1b) the full MITRE CWE catalog, published the same way as the NVD and OSV feeds: a writer publishes immutable
snapshots, a resolver checks integrity and age, a Dagster op refreshes it. Decisions:
[ADR-0026](decisions/ADR-0026-mitre-attack-capec-reference-feed.md).

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
| `cwe` | yes | `https://cwe.mitre.org/data/xml/cwec_v4.19.xml.zip` | CWE 4.19 | **not yet pinned** |

The CWE zip is pinned by version (the XML root's `Weakness_Catalog/@Version` must equal the pin). Its
sha256 is not pinned yet: cwe.mitre.org was unreachable from the build sandbox. The smoke script
prints the hash of the first real sync; copy it into `SOURCES["cwe"]["sha256"]` as a reviewed change.

Full hashes are in `mitre_feed.SOURCES`. A fetched bundle must hash to its pin and carry the pinned
upstream version (`x-mitre-collection.x_mitre_version`, `x_capec_version`); anything else is a failed
source. Never `master` or `latest` at run time: raising a pin is a reviewed edit of `SOURCES`.
Mobile/ICS: `APPSEC_MITRE_SOURCES=enterprise-attack,capec,mobile-attack` or `sync --sources ...`.
CAPEC comes from `mitre/cti` (STIX 2.1) because `capec.mitre.org` was not reachable from the build
sandbox; the XML at capec.mitre.org is the same 3.9 release.

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
  cwe-catalog.json                derived CWE table (cwe_catalog.py), hash-listed in the manifest ("cwe_catalog")
  sources/<source>.json           unmodified upstream STIX bundles
  sources/cwe.xml.zip             unmodified upstream CWE zip
staging/  locks/  events.jsonl
```

`reference.json` is a pure function of the bundle bytes (sorted, no timestamps, no model prose), so
re-syncing the same pins yields the same `reference_sha256` even though each sync publishes a new
snapshot id. It holds ATT&CK tactics and techniques/sub-techniques (id, name, tactics, platforms,
deprecated, revoked, url, domains) and CAPEC patterns (id, name, status, deprecated, related CWE ids,
related ATT&CK ids where MITRE gives them, url).

## Modules

| Module | Role |
|---|---|
| `mitre_feed.py` | Writer and resolver. `sync` (per-source failure carries the last good bundle forward with its ORIGINAL `fetched_at`; only a total failure or a failed derivation fails the sync and leaves `current.json` untouched), `verify` (re-hash everything), `resolve` (integrity + age; `SnapshotBlocked` / `SnapshotStale` / `SnapshotInvalid`, the SCA registry's semantics). Keeps the last N snapshots (`APPSEC_MITRE_KEEP`, default 3). |
| `attack_reference.py` | Derives `reference.json`; `Reference.validate_technique(id, tactic=None)` / `validate_capec(id)` return `OK` / `UNKNOWN_ID` / `DEPRECATED` / `TACTIC_MISMATCH`; `screen()` is the one gate for claims and chain links. CLI: `attack_reference.py technique T1190 --tactic initial-access`, `attack_reference.py capec CAPEC-66`. |

## CWE (brief O1b)

`cwe-catalog.json` has the same shape as the committed `data/reference/cwe/cwe-catalog.json` (schema
`appsec-review/cwe-catalog/1.0`), with every weakness in the MITRE catalog: `cwe_id`, `name`, `status`,
`abstraction` and a `deprecated` flag (deprecated ids stay in the table, flagged, and are never
accepted). It is derived with `cwe_catalog`'s one XML parser; a zip that does not hold exactly one
`cwec_v<version>.xml`, parses to fewer than 100 weaknesses or carries another version is a failed source.

`cwe_catalog.Catalog()` resolves the snapshot with `kinds=("cwe",)`. The CWE source is aged on its
own, so a stale CWE download does not withhold ATT&CK tags and a stale ATT&CK bundle does not demote
the CWE catalog. `attack_reference` resolves with `kinds=("attack", "capec")` for the same reason.

| CWE snapshot state | Catalog in force | Gap recorded |
|---|---|---|
| in ceiling, rule map resolves | snapshot's full catalog (`catalog` = `snapshot_id`) | none |
| older than the ceiling | committed curated catalog (`committed-curated`) | `CWE_REFERENCE_STALE` |
| no feed root, no snapshot, or no usable CWE source | committed curated catalog | `CWE_REFERENCE_MISSING` |
| integrity failure, or the committed rule map names an id the snapshot lacks or deprecates | committed curated catalog | `CWE_REFERENCE_INVALID` |

The fallback never blocks. Reviewer and tool CWE ids are validated against whichever catalog is in
force; an unknown or deprecated id is still rejected (reviewer: repair round) or dropped with a
limitation (tool tag, or a judgment the report's catalog no longer knows), never published. Each
reviewer judgment records the catalog that validated it (`catalog`). The synthesis enrichment binds
`catalog_source` and lists the gap. `rule-cwe-map.json` stays committed and hash-pinned by
`cwe-lock.json` together with the fallback catalog; the feed table is pinned by its manifest hash.
`cwe_catalog.py intake` (offline import into the committed catalog) still works. `Catalog(directory)`
with an explicit directory reads only the committed files.

The feed is not bound into `dependency_snapshot_registry` (that registry is shaped for container
scanner databases: `data/` mount, closed metadata record). `mitre_feed.resolve` gives the same
outcomes instead.

## Age ceiling and the staleness rule

One tunable, `reference_snapshot_max_age_seconds` (1,209,600 s = 14 days, `registry/tunables.json`),
is the ceiling for OSV, the OSV SCA registry binding and this feed. Age is measured from the OLDEST
usable source's original `fetched_at`.

| Snapshot state | OSV | MITRE labels |
|---|---|---|
| in ceiling | used | validated; only `OK` ids kept |
| older than the ceiling | SCA fails (`SNAPSHOT_TOO_OLD`) | **gap** `MITRE_REFERENCE_STALE`: every tag withheld |
| never published / missing | SCA blocked | **gap** `MITRE_REFERENCE_MISSING`: every tag withheld |
| fails integrity | SCA fails | **gap** `MITRE_REFERENCE_INVALID`: every tag withheld |
| one source missing (e.g. CAPEC) | ecosystem gap | that kind's tags withheld as `MITRE_REFERENCE_MISSING` |

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

## Dagster

`mitre_sync_work` is the third independent op of `nvd_reference_sync` (tag `mitre_feed_id=mitre`,
same 2-hour schedule and network pool; `APPSEC_NVD_SCHEDULE=stopped` stops all three). A failure in
one op never stops the others.

## Commands

```
python3 appsec-review-process/mitre_feed.py sync        # normally the Dagster op does this
python3 appsec-review-process/mitre_feed.py verify
python3 appsec-review-process/mitre_feed.py resolve     # exit 2 missing, 3 stale, 4 invalid
python3 appsec-review-process/mitre_feed.py resolve --kinds cwe
python3 appsec-review-process/attack_reference.py technique T1059.004 --tactic execution
python3 appsec-review-process/cwe_catalog.py check      # catalog in force, snapshot id or committed-curated, gap
bash scripts/smoke_mitre_feed.sh                         # sync, verify, resolve, T1190 OK, T9999 UNKNOWN_ID,
                                                         # CWE-1004 OK, CWE-99999 rejected, both stale paths
```
