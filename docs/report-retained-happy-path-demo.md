# Retained report happy-path demo

This demo exercises accepted fixture producers, report-input assembly, draft synthesis, completion
controls, human-signoff validation, and final publication. It is a contract demonstration, not a
scan of a target. The generated finding is fixture data. Analysis, dependency, and vendor-family
qualification files are indexed separately as supplemental implementation/test coverage and are
explicitly not promoted into report findings.

From the repository root, retain a draft without any signoff:

```bash
python -B appsec-review-process/retained_happy_path_demo.py \
  --output-root /absolute/path/to/retained-demo \
  --run-id retained-demo
```

The draft is written to
`<output-root>/data/jobs/10-synthesis-report/attempts/draft-1`; `demo-index.json` and
`supplemental-family-qualification.json` provide the retained entry points.

To exercise final publication, the operator must explicitly supply a key of at least 32 bytes, a
trusted SHA-256 ledger anchor, and a reviewer identity:

```bash
python -B appsec-review-process/retained_happy_path_demo.py \
  --output-root /absolute/path/to/retained-final-demo \
  --run-id retained-final-demo \
  --authorization-key /absolute/path/to/demo-hmac.key \
  --ledger-anchor sha256:<64-hex-digits> \
  --demo-reviewer-id operator-name
```

The coordinator prefixes the reviewer with `DEMO-OPERATOR:`, uses a `DEMO-AUTHORIZATION` receipt,
and records a `DEMO ONLY` rationale. The final package is `<output-root>/final`. Existing output
roots are never reused or overwritten, and partial signoff arguments fail before any output is
created.

## Render the retained final package

The presentation adapter verifies the final artifact inventory and preserves the report's
authoritative severity, lifecycle score, and priority. It does not manufacture a CVSS vector or a
process-assurance score. Supplemental family qualification remains non-promotional and the rendered
fixture remains visibly labeled DEMO.

```bash
python -B pipeline/report/final_publication_adapter.py \
  /absolute/path/to/retained-final-demo/final \
  --supplemental /absolute/path/to/retained-final-demo/supplemental-family-qualification.json \
  --output /absolute/path/to/retained-final-demo/final.review.json

bash pipeline/report/render-in-docker.sh \
  /absolute/path/to/retained-final-demo/final.review.json
```

The Docker command runs with no network and writes `pipeline/report/build/report.pdf`; the same
input also produces the HTML preview and TeX source.
