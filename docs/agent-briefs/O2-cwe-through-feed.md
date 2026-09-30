# Brief O2: CWE through the MITRE feed

Branch `cwe-feed`, from latest `main` (brief O, `mitre-feed`, is merged). Read `00-common.md`, `O-mitre-attack-capec-feed.md`
(section O1b is your spec), `docs/mitre-feed.md`, ADR-0026, `appsec-review-process/mitre_feed.py`, `cwe_catalog.py`,
and decision log D-05 and D-18.

## Scope
Deliver exactly O1b: CWE as a third source in the same immutable MITRE snapshot (pinned `cwec_v<version>.xml.zip`,
never `latest`), same manifest fields, NOTICE, carry-forward with the ORIGINAL `fetched_at`, same 14-day ceiling and the
one shared tunable `reference_snapshot_max_age_seconds`. `cwe_catalog.py` reads the full catalog from the resolved
snapshot, reusing `cwe_catalog._parse_xml` (no second parser). Missing, stale or invalid snapshot: fall back to the
committed curated catalog and record `CWE_REFERENCE_STALE` or `CWE_REFERENCE_MISSING`; never block. Unknown CWE ids
are still rejected or dropped. `rule-cwe-map.json` stays committed and hash-pinned.

## Rules
- Do not change ATT&CK or CAPEC behaviour or snapshot identity for existing sources beyond adding the third source.
- Add tests (parse, carry-forward, stale, missing, fallback, unknown id) and extend `scripts/smoke_mitre_feed.sh`.
- Add an ADR-0026 addendum, not a new ADR. Update `docs/mitre-feed.md` and the TODO.
- Report any job fingerprint that moves, listed by job id.
