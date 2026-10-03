# Report renderer and document templates (proposed)

Three LaTeX documents share one house style (`latex/appsec-house.sty`): the engagement report,
an operator user guide, and an executive design doc.

## Document templates

| File | For | Shape |
|---|---|---|
| `latex/user-guide.tex` | Operators | Conventions, flow diagram, prerequisites, numbered steps with terminal blocks, concepts, tasks, troubleshooting table, reference, glossary |
| `latex/design-doc.tex` | Executives | Positions appsec-review as a repeatable, hands-off process. Page 1 carries the message: bottom line, KPI tiles, what changes. Then why change, how the process runs (diagram, where people stay in the loop), options with recommendation, status (RAG), risk heat, success measures; technical detail in the appendix. `decision` box available for docs that need an ask |
| `latex/appsec-house.sty` | Both | Palette, type, cover from `\doctype`/`\docversion`/`\docstatus`/`\docowner`/`\docaudience`; callouts (`note`, `tip`, `warning`, `danger`), `terminal` + `\cmd`/`\out`, `steps` + `\step`, `bluf`, `decision`, `\metrics`/`\metric`, `\rag`, `\heat`, `\kbd`, `\tbd`, `codesnippet` + `\flawline`, `revisions` |

`\tbd{...}` marks a fill-in (amber in drafts). `\usepackage[final]{appsec-house}` renders them plainly and
drops the template banner. The example content describes appsec-review; figures marked TBD are
fill-ins, not estimates.

```bash
bash pipeline/report/latex/build-in-docker.sh        # all templates -> build/latex/*.pdf
cd pipeline/report/latex && latexmk -pdf design-doc.tex   # host
```

The workbench page (`build/workbench.html`) previews all three: pick one from the list, edit, and it
re-renders as you type. TikZ diagrams show as placeholders there; they render in the PDF.

LaTeX is also the canonical source for retained operator and design publications. Produce an exact
source copy and a read-only KaTeX HTML view, then compile the same source in the pinned container:

```bash
python3 pipeline/report/render_documents.py --out docs/generated-documents \
  pipeline/report/latex/user-guide.tex pipeline/report/latex/design-doc.tex
SKIP_BUILD=1 bash pipeline/report/latex/build-in-docker.sh user-guide.tex design-doc.tex
```

Copy the resulting PDFs from `pipeline/report/build/latex/` beside the retained TeX and HTML. The
HTML viewer supports the house macros and uses the same browser-side KaTeX path as the report
workbench; TikZ figures remain labelled placeholders in HTML and render fully in PDF.

## Report renderer

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
- `templates/vendor/purify-3.4.16.min.js` - DOMPurify 3.4.16 (Apache-2.0 / MPL-2.0, sha256
  `2c90a9b46d6463f26038a29b686e82bc91de01fdac9d5229e7cfe3b360134ea2`, from the npm `dist/`); the workbench
  sanitizes rendered HTML with it before showing it
- `examples/hello-autotools.review.json` - sample data; its derived blocks (processes, sections 3A/3B/3C)
  are regenerated by `sample_data.py` from the real code paths (see `docs/report-examples/README.md`)
- `render-in-docker.sh` - runs the renderer in `images/audit-report` with the directory mounted read-only
- `latex/` - house style, user guide and design doc templates, `build-in-docker.sh`
