# ADR-0026: MITRE ATT&CK and CAPEC as a pinned reference feed; tags are labels, withheld when stale

Status: **Proposed** (2026-09-29, brief O, branch `mitre-feed`; awaiting William). Importing ATT&CK and
CAPEC "the same way as NVD/OSV, with the same 14-day ceiling" and "reference data only" were decided by
William in the brief; the rest awaits review. Offline unit tests plus one real sync from the build
sandbox; no engagement run yet. Details: [`docs/mitre-feed.md`](../mitre-feed.md).

## Context

Lane 14 (attack chains, ADR-0016) and lane 07's vendor/insider mode want to name ATT&CK techniques;
the general hunt benefits from CWE -> CAPEC. `docs/design-v3.md` 5.4 already lists ATT&CK, CAPEC and
CWE as citable standards (stable ids, permissive licences). Without a pinned table a model-written
`T1234` cannot be told from an invented one. NVD and OSV already establish the pattern: an immutable
published snapshot, an atomic pointer, carry-forward of the last good data with its original age, and
a 14-day ceiling (`1209600` s) hard-coded in several places.

## Decision

1. **Publisher `mitre_feed.py`, a sibling of `osv_feed.py`.** Release-pinned STIX 2.1 bundles
   (ATT&CK Enterprise v19.2 by default, Mobile/ICS on request; CAPEC 3.9 from `mitre/cti` tag
   `ATT&CK-v19.2`), each checked against a pinned sha256 and upstream version, published as an immutable
   snapshot (`manifest.json`, `NOTICE.txt` with MITRE's copyright designations and terms-of-use licence
   text, the bundles, a derived `reference.json`), `current.json` flipped atomically last, last N kept.
   A failed source keeps its last good bundle **with its original `fetched_at`** or becomes a recorded
   gap; a pin change never carries the old release forward. `resolve()` has the SCA registry's
   semantics (`SnapshotBlocked` / `SnapshotStale` / `SnapshotInvalid`, age from the original
   `fetched_at`); the feed is not bound into `dependency_snapshot_registry`, which is shaped for
   container scanner databases. It runs as a third independent op of `nvd_reference_sync`.

2. **A stale or missing snapshot is a recorded gap that withholds tags.** Tag validation against a
   snapshot that is missing, older than the ceiling or fails integrity records `MITRE_REFERENCE_MISSING`,
   `MITRE_REFERENCE_STALE` or `MITRE_REFERENCE_INVALID` and withholds every tag. It never accepts an
   unvalidated id and never fails the run. (OSV, by contrast, fails SCA when stale: a stale label table
   must not stop a code review.) William can turn this into a hard block by making `attack_reference.load`
   raise instead of returning the gap.

3. **One shared tunable for the 14-day ceiling.** `reference_snapshot_max_age_seconds` (default and
   current value 1209600) in `registry/tunables.json` replaces the hard-coded ceiling in
   `definitions.py` (OSV registry binding), `osv_snapshot.DEFAULT_MAX_AGE`, the `osv_lookup.py` and
   `dependency_snapshot_registry.py register-osv-feed` CLI defaults, and is this feed's default. The value
   and all OSV/NVD behaviour are unchanged. NVD's resolver has no default by design (callers pass
   `max_age`), so there was no NVD literal to replace. The shell literals in
   `orchestrator/prepare-host.sh` / `stage-run.sh` and the operator guide remain (TODO section O).

4. **ATT&CK and CAPEC ids are labels, never evidence.** A tag never supports, promotes or upgrades a
   claim, never changes a link state, edge, chain id or chain state, never sets severity, and is never
   required. Python validates every id (`attack_reference.validate_technique` / `validate_capec`:
   `OK` / `UNKNOWN_ID` / `DEPRECATED` / `TACTIC_MISMATCH`); only `OK` ids are kept, each drop is a
   recorded gap, and a malformed tag is described, never echoed. The model supplies ids only; names,
   tactics, versions and the reference identity come from the pinned table (ADR-0013).

5. **Carry, minimally.** Claims: optional `attack_refs` / `capec_refs` on the 07 decision, next to
   `cwe` (ADR-0020), screened into `mitre_refs` and carried 07 -> 12 like `cwe_judgments`. The MITRE
   reference identity (derived-table hash and upstream versions, or the gap code) is bound into the 07
   inputs only when a decision is tagged, so a re-validation reproduces the tags and a stale or re-pinned
   snapshot re-executes the stage; untagged runs keep their inputs. Chains: optional `attack_refs` per
   composer link, checked against the link stage's tactics, rendered only in the attack-chain report
   section. Persona prompt files are unchanged; the prompt-side technique menu is follow-up work.

## Consequences

- A fresh host has no MITRE snapshot until the first sync: every tag is withheld as
  `MITRE_REFERENCE_MISSING` until `mitre_feed.py sync` (or the schedule) runs.
- Each 2-hour sync publishes a new snapshot id even when the pinned bytes are unchanged (fresh
  `fetched_at`), but `reference.json` and so the 07 input binding stay identical.
- Claim-level `mitre_refs` are not yet shown in the synthesis report (brief M owns that module).
- Raising the ATT&CK/CAPEC release is a reviewed edit of `mitre_feed.SOURCES` (URL, version, sha256).

## Addendum (2026-09-29, brief O2, branch `cwe-feed`): CWE joins the feed

Decision log D-05 ("pull cwe same way as the other static files") and brief O1b.

1. **CWE is a third source of the same snapshot.** `mitre_feed.SOURCES["cwe"]` pins
   `https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip` by version (never `cwec_latest`); the zip must hold
   one `cwec_v<version>.xml` without a DTD whose `Version` equals the pin. Same manifest fields, NOTICE
   (CWE terms of use added), carry-forward with the original `fetched_at`, the same ceiling tunable. The
   byte pin is OPEN (cwe.mitre.org was unreachable from the build sandbox); raising it is a reviewed edit.
2. **A derived `cwe-catalog.json`** in the snapshot (hash-listed as `manifest.cwe_catalog`) has the
   committed catalog's shape, is built through `cwe_catalog._parse_xml` (no second parser), flags
   deprecated weaknesses instead of dropping them, and is deterministic in the zip bytes.
   `reference.json` and ATT&CK/CAPEC resolution are unchanged: `resolve()` ages ATT&CK/CAPEC only and
   `resolve_cwe()` ages the CWE source alone.
3. **Fallback, never a block.** `cwe_catalog.current()` uses the feed catalog when it verifies and is in
   the ceiling, else the committed curated catalog with `CWE_REFERENCE_MISSING`, `CWE_REFERENCE_STALE` or
   `CWE_REFERENCE_INVALID`. Unknown and deprecated ids are rejected or dropped under either catalog.
   `rule-cwe-map.json` stays committed and hash-pinned in `cwe-lock.json` with the curated catalog; the
   feed table is pinned by the manifest hash. `cwe_catalog.py intake` still works.
4. **Recorded, reproducible.** Stages 07/09/12 bind the catalog identity (table hash or curated plus gap)
   into their inputs when a decision carries `cwe`, validate against the bound catalog, and record
   `cwe_catalog` (snapshot id or `committed-curated`) on each judgment; `finding-enrichment.json` records
   the catalog used and reports a fallback as a limitation.
