# Report rendering (PDF and single-page HTML)

`python -m appsec_review.reporting` turns a finished review run into a readable report: a LaTeX
document compiled to PDF by the `tool-report-latex` image, or one self-contained HTML file. It is a
standalone tool. No pipeline job runs it yet, `job_final_report_publication` does not call it, and
`final-report.json` keeps `renderers.pdf.state = "not_rendered"` (see
[`final-report.md`](final-report.md)). Because no job runs the image, `appsec-review.toml` has no pin
for it; the image is an enabled catalog entry, so `job_image_pin_verification` requires it to be
present locally like every other enabled image (build it with the command below).

## What it renders

The loader (`src/appsec_review/reporting/loader.py`) reads a run directory read-only and builds one
renderer-neutral document. Missing or unreadable artifacts become **named gaps** in the report
("Artifacts this report could not read"), never a failure and never a clean verdict.

- **Cover and summary**: run, review and publication status, counts (claims, packages, cells, model
  calls, tokens), ledger head hash, limitations, accounting, findings, provenance.
- **Per reviewed package**: the *evidence passed in* (lead, location, source excerpt when the
  package carries one, scope and proof obligations, neighbourhood facts, build context, tags,
  coverage gaps, provenance); the *protocol interchange* of each review cell as a timeline of turns
  (task and tools, the model's retrieve requests, the application's result rows, denials and tool
  errors returned as feedback, the final answer, tokens and model per turn); the *outcome* (claims
  with relations and state transitions, cell outcomes, ledger gaps).
- Sources: `final-report.json`, the assembled and review packages, `data/inference-recordings`, the
  review ledger shards and the cell receipts of `job_inference_security_review`.

Everything shown is bounded. A cut field says `n more <unit>, sha256 <64 hex>` (the hash is of the
whole). Defaults live in `Limits` (`tokens.py`). Model output, target content and tool output are
data: every string is cleaned (control, format and private-use characters removed), bounded and
escaped for exactly one output language; tests prove hostile text (`\input`, `\write18`,
`</script>`, bidi controls, NULs, 300-character identifiers) is inert in both formats.

## Box legend

One kind of content, one colour, one chip. The colours are defined once in
`src/appsec_review/reporting/tokens.py`; the HTML stylesheet and
`containers/report/latex/template/appsec-palette.tex` are generated from them (a test fails if the
committed palette drifts: `python -m appsec_review.reporting palette --write`).

| Box | Chip | Accent | Tint | Meaning |
| --- | --- | --- | --- | --- |
| evidence | EVIDENCE | teal `#0F766E` | `#F0FDFA` | what we pass in: lead, source, neighbourhood, build, tags |
| request | REQUEST | slate `#334155` | `#F1F5F9` | application to model: task and tools |
| response | MODEL | violet `#6D28D9` | `#F5F3FF` | model to application: retrieve action, final answer |
| result | RESULT | sky `#0369A1` | `#F0F9FF` | retrieval result rows |
| feedback | FEEDBACK | amber `#B45309` | `#FFFBEB` | denials and tool errors returned to the model |
| claim | CLAIM / PROPOSAL | red `#B91C1C` | `#FEF2F2` | red affirmation |
| counter | COUNTER | blue `#1D4ED8` | `#EFF6FF` | blue counter-claim |
| verification | VERIFIER | green `#15803D` | `#F0FDF4` | blind verifier |
| gap | GAP (dashed border) | pink `#BE185D` | `#FDF2F8` | gap or limitation |
| provenance | PROVENANCE | grey `#52525B` | `#F4F4F5` | hashes, receipts |

Verdict badges (white text on a solid colour): confirmed `#15803D`, supported `#4D7C0F`,
contradicted `#B91C1C`, not reachable `#475569`, insufficient evidence `#B45309`, unresolved
`#6B7280`; also proposed `#6D28D9`, not exploitable `#0369A1`, duplicate and out of scope `#6B7280`,
coverage gap `#BE185D`. Neutral base: ink `#111827`, muted `#4B5563`, rule `#E5E7EB`. Every accent
has at least 4.5:1 contrast against white (tested), and the chip text and the dashed gap border keep
the meaning in greyscale. Both formats include a "Reading guide" with this legend.

## Running it

```text
scripts/render-report.sh --run <run-id|run-dir> [--format pdf|html] [--runs-dir DIR]
    [--output-dir DIR] [--limit N] [--package ID]... [--max-cells N] [--image TAG] [--keep-work]
scripts\render-report.ps1 -Run <run-id|run-dir> [-Format pdf|html] [-RunsDir DIR]
    [-OutputDir DIR] [-Limit N] [-Package ID,...] [-MaxCells N] [-Image TAG] [-KeepWork] [-Help]
```

Both print the output path. The default output directory is `<repo>/runs/reports` (`runs/` is git
ignored); the file is `<run-id>.pdf` or `<run-id>.html`. `--runs-dir` defaults to `<repo>/runs`.
They work from any directory and with paths containing spaces. The scripts only read the run.
`APPSEC_PYTHON` selects the interpreter (default `.venv`, then `python3`/`python`/`py -3`);
`APPSEC_DOCKER_BIN` the Docker client. Exit status: 0 success, 1 render failure, 2 usage error or
missing prerequisite (Python, Docker, or the image, with the build command in the message).

```text
scripts/render-report.sh --run 2026-10-21-0007 --format html
scripts/render-report.sh --run 2026-10-21-0007 --format pdf --limit 3
scripts\render-report.ps1 -Run 2026-10-21-0007 -Format pdf -OutputDir "C:\Reports with spaces"
python -m appsec_review.reporting render --run <id> --runs-dir runs --format html --out DIR
```

`--limit` and `--package` bound the render (a whole run has hundreds of packages); the report says
how many it shows. The `html` format needs only Python. The `pdf` format writes `report.tex` and runs the image
with `--network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001`,
the policy memory/CPU/PID limits and a `/tmp` tmpfs. The template (`/template`) and the input
(`/input`) are read-only mounts; `/scratch` is the one writable mount, a throw-away host directory
(like the builder's own scratch mounts) from which the PDF is copied out and which is then removed.

## Determinism

The same run gives byte-identical `.html` and `report.tex`: no clock, locale, network or randomness;
ordering is by id. The one date used (`SOURCE_DATE_EPOCH`) comes from the run (the publication
handoff's `completed_at`, else the date in the run id, else 0). The image sets `FORCE_SOURCE_DATE=1`
so the PDF creation date and document id are fixed; a test renders twice and compares the PDFs.

## Image and template

`tool-report-latex:1.0.0` (catalog entry `tool-report-latex`; the deferred `audit-report` entry is
now `replaced` by it). XeTeX from TeX Live 2023 (Ubuntu 24.04 packages), fonts Inter and JetBrains
Mono (SIL OFL, Ubuntu packages) loaded by path, poppler-utils for `pdfinfo`, `pdftotext`,
`pdftoppm`. The closure is 111 exact-version `.deb` files recorded in
`containers/report/latex/packages.manifest` and locked by size and SHA-256 in `assets.lock.json`;
image size about 1.0 GB. The template (`containers/report/latex/template/`:
`appsec-report.cls`, `report-skeleton.tex`, generated `appsec-palette.tex`) is not part of the
image. Rebuild:

```text
containers/report/latex/acquire_assets.sh          # only to refresh the locked package closure
containers/build-all.sh build tool-report-latex     # or containers\build-all.ps1
containers/build-all.sh smoke --functional tool-report-latex
```

## Limits and what is not done

- Only `job_inference_security_review` recordings are drawn; a recording's longest call chain is the
  interchange, other chains are counted. Blue and verifier answers use the generic digest (their
  field names are not fixed yet; fields named stance, verdict, state, disposition and so on become badges).
- Glyphs the bundled fonts lack (for example CJK) appear as `<U+XXXX>` in the PDF; HTML shows them.
- No PDF accessibility tagging; links and bookmarks are internal only.
- A full run (hundreds of packages) is hundreds of pages; use `--limit`/`--package`.

A rendered sample of the synthetic test fixture (not a real run) is committed for design review: [PDF](../samples/report-synthetic-fixture.pdf), [HTML](../samples/report-synthetic-fixture.html).
