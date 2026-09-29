# Brief P: refresh the sample report to the current jobs and real 3C records (branch `sample-report`) - CLOUD agent
William, 2026-09-29: "rerender to reflect current ops and jobs: replacing the sample 3C records and re-rendering the
sample report in WSL". The retained sample (`docs/report-examples/appsec-review-sample.{html,pdf}`, built from
`pipeline/report/examples/hello-autotools.review.json`) is stale: its `processes` list has 42 entries and 6 families
while `job-graph.json` now has 81 jobs (per-language CodeQL nodes, lane 14, 12b, 06 correlator and engines, workbench
cells), and its `threat_workbench` (section 3C) records are hand-written. It stays labelled SAMPLE DATA (it is not
evidence of a live scan), but it must be derived from the real code paths so it cannot drift again.

## P1. Generate `processes` and `families` from the job graph
Write `pipeline/report/sample_data.py` (deterministic, no network, no model): reads `appsec-review-process/job-graph.json`
and the parity manifest and emits the `families` and `processes` arrays in the report schema shape (id, family, kind,
status, tools, evidence). Family grouping follows the graph's own lane/family field; do not invent groups. Statuses are
illustrative SAMPLE values chosen by a fixed, documented rule (all OK except a few showing `OK_WITH_GAPS` and `SKIPPED`
with the real reason codes the code emits, for example `not-applicable-language-absent`, `not-applicable-no-native-binaries`).
Every job in the graph appears exactly once; a test fails if the graph gains a job the sample lacks.
## P2. Real 3C records from a replay of the workbench code
Replace the hand-written `threat_workbench` block by running the actual `threat_workbench.py` / `threat_model_core.py`
join and overlay validator over canned cell replies for the hello-autotools fixture (reuse the canned replies used by
`tests/test_threat_workbench_report.py` and the workbench tests; extend them for a privacy threat and an attack tree so
every 3C table is non-empty). The block must be exactly what `synthesis_report_presentation` would carry from a
published 03 output, produced by the real functions, with content-derived ids. Also regenerate the attack-tree summary,
data classes, deployment zones and privacy threats this way. Keep the `_comment` marking the file SAMPLE DATA and say
how it was produced.
## P3. Re-check the other sections against current behaviour
Sections 3A (dependency reachability, ADR-0022/0023), 3B, attack chains (lane 14), PoC and fix (12b), CVSS 4.0
(brief M1 verified), EPSS/KEV "not assessed" gap, the CWE catalog in force, and the new job counts in the summary must
match the current code and job graph; correct any that do not. Add one `MITRE_REFERENCE_*` gap row only if brief O has
merged (check `git log origin/main`), otherwise leave it out.
## P4. Render
In the cloud: run the HTML render (`python3 pipeline/report/render.py <json> --out <dir>`, jinja2 needed; no TeX) and
commit the regenerated `docs/report-examples/appsec-review-sample.html` if it renders. The PDF needs the pinned TeX
image, so do NOT hand-produce or edit the PDF: list the exact WSL commands for William (below) and mark the PDF stale
in `docs/report-examples/README.md` until he has run them.
WSL commands to give William (verify they match the current scripts):
```
bash pipeline/report/render-in-docker.sh                 # -> pipeline/report/build/report.pdf
cp pipeline/report/build/report.pdf docs/report-examples/appsec-review-sample.pdf
python3 pipeline/report/render.py pipeline/report/examples/hello-autotools.review.json --out pipeline/report/build
cp pipeline/report/build/report.html docs/report-examples/appsec-review-sample.html
```
## You own
`pipeline/report/sample_data.py`, `pipeline/report/examples/hello-autotools.review.json`, its tests,
`docs/report-examples/**`. Do NOT touch `synthesis_report_presentation.py`, templates or schemas (brief M owns them and
is merged); if the sample cannot validate against the current schema, report it instead of changing the schema.
## Acceptance
The sample JSON validates against `schemas/synthesis-report.schema.json`; the process list equals the job graph; the
3C block equals the output of the real functions on the canned replies (test); the HTML renders; baseline test failures
in 00-common.md unchanged. Report what changed in each section and every assumption.
