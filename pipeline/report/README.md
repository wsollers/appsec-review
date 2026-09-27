# Report renderer (proposed template)

Renders the engagement report from one data file into three outputs:

- `report.tex` -> `report.pdf` (compiled in `images/audit-report`)
- `report.html` - the same report with math rendered by KaTeX, for fast iteration
- `workbench.html` - paste or open any `.tex` and see it rendered live beside the editor

Status: the visual style and presentation scoring for the example remain proposals.
`examples/hello-autotools.review.json` is **sample data** (tool statuses, scores and evidence hashes
are illustrative). The final-publication adapter is an executable presentation boundary: it verifies
every retained final-package hash and preserves authoritative lifecycle severity, score, and priority
without synthesizing CVSS or process-assurance values.

## Run

```bash
bash pipeline/report/render-in-docker.sh                     # pinned image, network none -> build/report.pdf
python3 pipeline/report/render.py --watch               # host: re-render HTML/.tex on every save (needs jinja2, cvss)
python3 pipeline/report/render.py --pdf --engine lualatex
```

To render a retained final publication, first adapt it to renderer JSON, then pass that JSON to the
same offline Docker renderer (absolute paths are accepted):

```bash
python3 -B pipeline/report/final_publication_adapter.py \
  /absolute/path/to/retained/final \
  --supplemental /absolute/path/to/retained/supplemental-family-qualification.json \
  --output /absolute/path/to/retained/final.review.json
bash pipeline/report/render-in-docker.sh /absolute/path/to/retained/final.review.json
```

Only `report.json.verified_findings` enters the Findings section. Supplemental implementation/test
qualification remains under `supplemental_qualification`; it provides no finding, evidence, severity,
priority, or process-assurance credit. DEMO packages remain visibly labeled DEMO in HTML, TeX, and PDF.

Outputs go to `pipeline/report/build/` (git-ignored).

## Report structure

Cover (rating, process assurance, native tier) · 1 executive summary · 2 scope and process
coverage (every process by family, including designed-but-unbuilt lanes, each with status, credit,
gap or skip receipt) · 3 findings (CVSS 4.0 vector and score, the worked priority equation, code
snippets, lane trail 07 -> 08 -> 09 -> 11 -> 12, evidence links) · 4 coverage gaps · 5 scoring method
· A evidence register · B provenance.

## Code snippets

Each finding lists `snippets: [{path, flaw: [lines], note}]`. The renderer shows 5 lines of context
either side, flaw lines on a light red background, monospaced, in both PDF (`codesnippet` box with
`\codeline` / `\flawline`) and HTML. Lines are read from `--source-root <checkout>` when given,
otherwise from the `source` lines embedded in the data file; `--embed-snippets --source-root <checkout>`
refreshes them.

## Scoring (proposed, not decided)

- Finding priority: `P = min(10, S * e * v * r * t)` - CVSS 4.0 base score scaled by evidence strength,
  verification result, reachability, and a KEV/EPSS bonus.
- Process assurance: each process earns 1 (OK), its measured coverage (OK_WITH_GAPS) or 0 (BLOCKED,
  FAILED, NOT_BUILT); SKIPPED with an applicability receipt is excluded. Family averages (native
  family capped by build tier) combine as a weighted mean.
- Rating: the band of the highest non-refuted priority; a Low/None rating with assurance below 0.85
  becomes Indeterminate.

Weights and thresholds live in the data file's `scoring` block.

## Files

- `render.py` - scoring model and renderer (Jinja2 with LaTeX-safe delimiters `\VAR{}`, `\BLOCK{}`, `%%`)
- `final_publication_adapter.py` - fail-closed retained-package verifier and presentation adapter
- `templates/report.tex.j2`, `templates/report.html.j2`, `templates/workbench.html.j2`
- `templates/vendor/katex-0.16.11.css` - KaTeX CSS with fonts inlined, so rendering needs no network
- `examples/hello-autotools.review.json` - sample data
- `render-in-docker.sh` - runs the renderer in `images/audit-report` with the directory mounted read-only
