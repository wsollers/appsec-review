# ADR-0020: Report findings carry CWE, CVSS v4.0, reachability, EPSS/KEV, snippets and remediation

Status: **Proposed** (2026-09-28; implementation merged to `main` from `ws-report`, `2f93649`). Reachability as final arbiter and the offline
EPSS/KEV snapshot were decided by William on 2026-09-28; the rest awaits review.

## Context

`synthesis_report_presentation.py` hard-coded every report-template field it could not source: CWE
"Not asserted", no CVSS vector, reachability "unknown", no EPSS, KEV false, no snippets and "No
remediation assertion". Severity was a bucket of the 12 factor sum (`claim_lifecycle_core.score`),
and `06-cve-reachability` only joined an externally supplied evidence file.

## Decision

Python does the bookkeeping and the arithmetic; reviewers supply judgment through persona-facing
fields that `claim_review_derive` passes through and `claim_lifecycle_core` validates.

1. **CWE.** Tool rules map to CWE through the pinned `data/reference/cwe/rule-cwe-map.json`; lead
   tags (`CWE-n`) are read too. Reviewers may add `cwe: {cwe_id, rationale}` at 07, 09 and 12; the
   judgment is validated against the pinned catalog (`cwe-catalog.json`, hash-locked in
   `cwe-lock.json`) and carried forward as `cwe_judgments` through 08/09/12 into the synthesis
   report. An unknown id goes back to the model for repair. The report's primary CWE is the latest
   reviewer judgment, else the first mapped tool CWE. The committed catalog is a curated subset of
   CWE 4.14; `cwe_catalog.py intake <cwec_v*.xml|csv>` imports the full MITRE export offline.
2. **CVSS v4.0.** At 12 a reviewer may give `cvss_v4: {metrics, rationale}` (eleven base metrics,
   one justification each). `cvss4.py` (FIRST reference algorithm, macrovector table pinned by hash)
   builds the vector and computes score and severity; the 12 record stores vector, score, severity,
   macrovector and per-metric rationale. With a CVSS assessment the severity is the CVSS band (and
   priority P0..P3 follows it); without one it stays the factor bucket.
3. **Reachability is the final arbiter.** `reachability.py` builds a call graph from the accepted
   CPG (resolved call edges; unresolvable calls are escapes) and runs a bounded multi-source BFS
   from entry points (`main`, plus exported symbols / handlers listed in the hash-bound
   `inputs/reachability-entry-points.json`). States: `REACHABLE` (witness path: ordered functions
   with `file:line` call sites to the finding line), `UNREACHABLE` (graph exhausted, no indirect,
   ambiguous or through-variable call reached, no CPG coverage gap that could hide an edge),
   `UNKNOWN` (everything else, with the reason). **Critical requires REACHABLE; UNKNOWN and
   UNREACHABLE cap at High**, and the report says so. SCA findings take the accepted 06
   classification; `reachability.py cve-evidence` writes 06's evidence file from a
   reviewer-supplied advisory -> vulnerable-function map (call path from application code).
4. **EPSS/KEV.** `epss_kev_snapshot.py intake --epss <csv[.gz]> --kev <json>` imports user-supplied
   files into `data/feeds/epss-kev/snapshot.json`, pinned in `snapshot.lock.json`. The pipeline never
   fetches. SCA findings show "EPSS/KEV as of <date>"; with no snapshot the report says "not
   assessed" and lists the gap.
5. **Snippets.** `code_snippets.py` cuts +-5 lines (max 41 lines, 200 chars per line) from the run's
   projected checkout only when the file hash equals the lead's `source_sha256`, and runs the
   evidence redactor over it. Otherwise the snippet is withheld with a reason.
6. **Remediation.** 11 objectives are carried into the report; a 12 reviewer may add
   `remediation: {objective, patch_proposal}`, always published as `PATCH_PROPOSED_UNVALIDATED`.
7. **Where it runs.** `10-synthesis-report` builds `finding-enrichment.json` deterministically
   (`finding_enrichment.py`), re-derives and compares it on validation, and feeds it to the
   presentation. The renderer accepts a CVSS vector in authoritative mode only with the pinned
   score; it never scores.

## Consequences

Code hashes change for 07, 08, 09, 12 (lifecycle, derive, pool, schemas) and 10 (synthesis worker,
presentation, renderer templates, new modules, job template, output contract), so those jobs re-run.
Earlier accepted artifacts stay schema-valid: every new field is optional and absent when unused.

## Open

- The CVSS macrovector table was transcribed; it is hash-pinned and checked against 16 published
  calculator vectors, but should be diffed once against FIRST `cvss_lookup.js`.
- The CWE catalog is a 96-entry curated subset until the full MITRE export is imported.
- Entry points beyond `main` need a source: component-map exports, network handler detection, or
  the per-run entry-point file (currently manual).
- Ambiguous C++ method names (for example `size()` on std containers vs project classes) are
  treated as escapes, so UNREACHABLE is rare on C++ targets. That is conservative by design.
