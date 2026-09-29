# CVSS v4.0 lookup table provenance

`appsec-review-process/cvss4.py` carries the CVSS v4.0 macrovector lookup table, the per-EQ maximal
vectors and the maximal severity distances (ADR-0020 decision 2), pinned by `LOOKUP_SHA256`.

`cvss4-lookup-provenance.json` records the reference they were checked against:

- Source: FIRST reference calculator, https://github.com/FIRSTdotorg/cvss-v4-calculator
- Commit: `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a` (2024-08-19), files `cvss_lookup.js`,
  `max_composed.js`, `max_severity.js`, `cvss_score.js` (sha256 in the JSON)
- Checked: 2026-09-29, entry by entry (270 of 270 macrovectors equal, maximal vectors and severity
  distances equal) and by score (all 104,976 base vectors plus 100,000 seeded vectors with
  threat/environmental/supplemental metrics: 0 macrovector or score mismatches)

Re-run after any edit to the table or the scorer, with a local checkout of the pinned commit and
Node.js:

```sh
git clone https://github.com/FIRSTdotorg/cvss-v4-calculator /tmp/cvss-v4-calculator
git -C /tmp/cvss-v4-calculator checkout c5b0d409ae9f57c44264c6ce5f27d89298e1d32a
cd appsec-review-process
python3 cvss4_reference_check.py compare --first-checkout /tmp/cvss-v4-calculator
```

Exit status 0 means no mismatch. `tests/test_cvss4.py` checks the scorer offline against the
1,500 reference results in `tests/fixtures/cvss4-first-reference-sample.json`.
