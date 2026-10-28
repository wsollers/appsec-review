# LaTeX report renderer (`tool-report-latex`)

The image renders the review report's LaTeX to a deterministic PDF. It replaces the archived
`audit-report` image (not copied). It is enabled in
[`containers/catalog.toml`](../../catalog.toml) because its conditions are met:

- hash-locked package closure: `acquire_assets.sh` resolves 111 exact-version Ubuntu 24.04 `.deb`
  files (`texlive-xetex`, `texlive-fonts-recommended`, `fonts-inter`, `fonts-jetbrains-mono`,
  `poppler-utils` and dependencies) from the Dockerfile's pinned base; `packages.manifest` lists every
  version and SHA-256, `assets.lock.json` pins the tar by size and SHA-256 (the build is offline,
  like `tool-native-cpp`; place the tar in `downloads/` by running the script);
- template separated from the image: `template/` is mounted read-only at `/template`;
- deterministic render: `render-pdf.sh` sets `SOURCE_DATE_EPOCH` (from `/input/source-date-epoch`) and
  `FORCE_SOURCE_DATE=1`, runs without shell escape, repeats until references settle;
- structural checks: `render-pdf` prints `pdfinfo` and writes `report.txt` (`pdftotext`); `pdftoppm`
  is in the image for visual checks; `tests/reporting/test_pdf_docker.py` checks the PDF structure.

Runtime: the standard boundary of `runtime-policy.toml` (no network, UID 10001, read-only root, all
capabilities dropped). Mounts: `/template` and `/input` read-only, `/scratch` writable. Dossier
publication uses this same image through `ContainerExecutor`. The protected
`job_dossier_publication` binds its immutable image ID in central settings, consumes the accepted
review and optional PoC/remediation summaries before the final gate, and writes one dossier per
confirmed finding (including document-origin findings) and per accepted PoC outcome. The standalone
report scripts remain available (see
[`docs/operations/report-rendering.md`](../../../docs/operations/report-rendering.md)).

Build and check (about 5 minutes, about 1.0 GB image):

```text
containers/report/latex/acquire_assets.sh      # refresh the closure; then update assets.lock.json
containers/build-all.sh build tool-report-latex
containers/build-all.sh smoke --functional tool-report-latex
```

Layout: `Dockerfile`, `render-pdf.sh` (entry point `/opt/tool/bin/render-pdf`), `tool.toml`,
`acquire_assets.sh`, `assets.lock.json`, `packages.manifest`, `template/`
(`appsec-report.cls`, `report-skeleton.tex`, generated `appsec-palette.tex`), smoke input in
[`../../fixtures/report-latex/`](../../fixtures/report-latex/).

## Protected finding and PoC dossiers

Dossiers reuse the renderer-neutral report model, palette, fonts and class. Every dossier retains
`dossier.json`, `dossier.tex`, a real `dossier.pdf` when rendering succeeds, and `receipt.json`
under its producing attempt. Receipts bind the model, LaTeX, PDF, template, image, settings and
container execution. Container diagnostics are retained; staging input and scratch are removed.
Rendering failure or an explicit LaTeX-only policy retains the source and a named gap, never an
empty/fake PDF. Retrying uses a new attempt and cannot overwrite a prior publication.

Only cited, resolving accepted source identities are queried, with bounded excerpts. Credential
literals are conservatively redacted. Raw prompts, model conversations and arbitrary producer
records are not copied into a dossier. Dossiers are protected developer artifacts; public reports
may expose sanitized descriptions, statuses and references, not generated function bodies.
Compile verification is explicitly not runtime proof; remediation checks do not claim a finding
is fixed.

The harmless seeded fixture creates both finding and PoC dossiers for layout review:

```text
python -m tests.dossier_fixture --run runs/dossier-synthetic-sample --image-id sha256:<verified-image-id>
python -m pytest tests/test_dossiers.py tests/test_dossier_publication.py -q --basetemp=test/tmp/dossiers
python -m pytest tests/test_dossier_live.py -q --basetemp=test/tmp/dossier-live
```

The live test uses the real local image and renders twice, checking PDF structure, core text,
retained hashes, byte reproducibility, and every contents entry against its actual PDF text page.
The shared template checksum-checks the contents file so a changed contents page triggers another
pass even when the last-page label is unchanged. Unit-test executor doubles do not inspect the host
container's mounts or require Docker. The live test skips if Docker/the image is unavailable. The sample
contains seeded review/compile dispositions only; it is not evidence of a real-target vulnerability
or a real-target compile.

Dossier job telemetry uses the existing event log: `DOSSIER_INPUTS_VERIFIED`,
`DOSSIER_BATCH_PLANNED`, `DOSSIER_RENDER_STARTED`, `DOSSIER_RENDER_COMPLETED`,
`DOSSIER_RENDER_FAILED` (raised integrity/runtime failures), `DOSSIER_PUBLICATION_ASSEMBLED`,
and `DOSSIER_PUBLICATION_PUBLISHED`. Events carry bounded counts by kind/status, cap/omission/gap
counts, durations, output byte sizes and receipt hashes. Finding/dossier IDs are correlation fields,
not metric label dimensions. Events never include source, generated functions, prompts or prose.
