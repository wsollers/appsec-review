# Brief O: ATT&CK and CAPEC reference feed, same rules as NVD/OSV (branch `mitre-feed`) - CLOUD agent

Decided (William, 2026-09-29): import MITRE ATT&CK (and CAPEC) for the red-team lanes to reference, published the
same way as the NVD and OSV snapshots, with the same 14-day staleness ceiling (`1209600` s). Reference data only:
a technique or pattern tag labels a claim, it is never evidence and never promotes or upgrades a finding.
Primary consumers: lane 14 (attack chains, ADR-0016) and lane 07 vendor/insider mode (L5). CAPEC also helps the
general appsec hunt (CWE -> attack pattern). Read first: `osv_feed.py` (the pattern to mirror),
`nvd_feed.py`, `dependency_snapshot_registry.py`, `orchestrator/dagster/definitions.py` (`nvd_reference_sync`),
`cwe_catalog.py` (validation pattern; it also becomes a consumer, O1b), `docs/personas-and-registry/` standards-citation rules
(`docs/design-v3.md` 5.4: ATT&CK/CAPEC/CWE citable, stable IDs, permissive licences).

## O1. Publisher `mitre_feed.py` (sibling of `osv_feed.py`)
- Sources (verify the exact URLs; pin by release, never `latest`/`master` at run time): ATT&CK enterprise STIX from
  `mitre-attack/attack-stix-data` (versioned files; mobile and ICS as an option, enterprise only by default), CAPEC STIX
  or XML from MITRE (`mitre/cti` or capec.mitre.org). Download to staging, verify it parses, publish an immutable
  snapshot exactly like OSV: `<root>/snapshots/<snapshot_id>/manifest.json`, `NOTICE.txt` (MITRE copyright and licence
  text, required by the terms of use), the source files, and a derived `reference.json` (below); `current.json`
  advanced atomically only after the snapshot is complete; keep the last N; one source failing keeps that source's last
  good file WITH ITS ORIGINAL `fetched_at` so the age ceiling still bites (mirror `_carry`). Manifest records source
  URL, upstream version, sha256, fetched_at, licence.
- CLI mirroring `osv_feed.py`: `python3 appsec-review-process/mitre_feed.py sync|verify [--root R]`. Feed root default
  `data/feeds/mitre` (git-ignored, host-local), override env `APPSEC_MITRE_FEED_ROOT`.
- Add it to the periodic reference job: a third independent op in `nvd_reference_sync` (a failure in one op must not
  stop the others, as today). Bind into the SCA snapshot registry only if that registry cleanly supports non-container
  kinds; otherwise give `mitre_feed.py` its own `resolve()` with IDENTICAL semantics (age from ORIGINAL fetched_at,
  `SnapshotStale` / `SnapshotBlocked` / `SnapshotInvalid`).
- ONE tunable for the ceiling. `1209600` is hard-coded in `definitions.py` and tests today; introduce a single tunable
  (`reference_snapshot_max_age_seconds`, default 1209600, listed in `docs/processes/tunables.md` via the generator)
  and use it for OSV, NVD-derived checks and this feed. Do not change the value or any existing behaviour.

## O1b. CWE joins the feed (added 2026-09-29, decision log D-05; same rules, same publisher)
Publish MITRE's CWE catalog (`cwec_v<version>.xml.zip` from cwe.mitre.org; pin by version, never `latest`) as a third
source in the same immutable snapshot, alongside ATT&CK and CAPEC: same manifest fields, same NOTICE (MITRE terms),
same carry-forward with the ORIGINAL `fetched_at`, same 14-day ceiling and tunable. Then make `cwe_catalog.py`
read the full catalog from the resolved snapshot instead of requiring the manual `intake` step:
- Reuse `cwe_catalog._parse_xml` (do not write a second parser). The snapshot's derived table has the same shape as
  `data/reference/cwe/cwe-catalog.json` (id, name, plus status/abstraction if MITRE provides them; deprecated ids are
  flagged, not dropped).
- FALLBACK, never a block: when the CWE snapshot is missing, older than the ceiling, or invalid, `cwe_catalog` uses the
  committed curated 96-entry catalog exactly as today and records the gap `CWE_REFERENCE_STALE` or
  `CWE_REFERENCE_MISSING` (with which catalog it used). Reviewer and tool CWE ids are still validated against whichever
  catalog is in force; an unknown id is still rejected or dropped, never published.
- The `rule-cwe-map.json` file stays committed and hash-pinned (it is the repository's own judgement, not upstream
  data). `cwe-lock.json` keeps pinning it and the fallback catalog; the feed snapshot is pinned by its manifest hash.
- The report and the claim path record which catalog was used: `snapshot_id` or `committed-curated`.
- Keep `cwe_catalog.py intake` working (offline manual import remains a supported path).
Tests: offline fake fetcher; full-catalog validation accepts an id absent from the curated subset; a snapshot older
than the ceiling falls back to the curated catalog with the gap recorded; a bad zip falls back; an invented id
(`CWE-99999`) is still rejected. Existing CWE tests must pass unchanged. In the smoke script: one real CWE id outside
the curated subset validates after `sync`.

## O2. Derived reference and validator `attack_reference.py`
- From the pinned STIX derive `reference.json` (hash listed in the manifest): ATT&CK techniques and sub-techniques
  (id, name, tactics, platforms, deprecated/revoked flag, url) and tactics; CAPEC patterns (id, name, related CWE ids,
  related ATT&CK ids where MITRE provides them, url). Python only, deterministic, sorted, no prose from the model.
- Validator API: `validate_technique(id, tactic=None)`, `validate_capec(id)`, each returning OK / UNKNOWN_ID /
  DEPRECATED / TACTIC_MISMATCH against the resolved snapshot. Follow `cwe_catalog.py`.
- Staleness rule (same ceiling, gap not block): a missing or older-than-ceiling snapshot makes tag validation a
  recorded gap `MITRE_REFERENCE_STALE` or `MITRE_REFERENCE_MISSING`. Tags are then withheld from published output,
  never accepted unvalidated and never failing the whole run. State this behaviour in the report; William can change it
  to a hard block. (OSV blocks SCA; here a stale label table must not stop a code review.)

## O3. Carry the tags through, minimally
Add one OPTIONAL judgement field to the claim/finding path, mirroring how `cwe` is carried (ADR-0020): `attack_refs`
(list of technique ids) and `capec_refs`, validated by O2, dropped with a gap if invalid, never required. Touch only
what `cwe` touched. Lane 14 chain links may carry `attack_refs`; render them in the attack-chain report section only.
Do NOT edit persona prompt files (brief J owns them); instead list in `appsec-review-process/TODO.md` (section "O") the
prompt-menu work for after brief J merges: a tactic-filtered technique menu or lookup for lane 14 and lane 07 (L5),
never the whole matrix in a prompt.

## O4. Smoke and docs
`scripts/smoke_mitre_feed.sh` (WSL, network allowed only for the sync step): sync, verify, resolve, one known technique
validates, one invented id (`T9999`) is UNKNOWN_ID, and a snapshot faked older than the ceiling reports stale.
Update `docs/processes/` feed documentation and the operator guide with the sync command and the staleness rule.
Tests for O1 (offline, fake fetcher like `test_osv_feed.py`), O2 and O3.

## You own
`mitre_feed.py`, `attack_reference.py`, their tests and schemas, the one tunable, `nvd_reference_sync` op wiring in
`orchestrator/dagster/definitions.py`, the smoke script, feed docs. `claim_ledger.py`/claim-review schemas ONLY for the
optional field (smallest possible diff).
## Do not touch
Persona files (brief J), `execution_state.py` (brief I), `synthesis_report_presentation.py` beyond the chain section
(brief M), OSV/NVD behaviour.
## Acceptance
Offline tests pass; existing OSV/NVD tests unchanged and passing; ceiling tunable default equals 1209600; validator
rejects an invented id; baseline failures in 00-common.md unchanged. Report the upstream versions pinned and the URLs
you verified.
