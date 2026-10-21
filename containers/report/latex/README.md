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
capabilities dropped). Mounts: `/template` and `/input` read-only, `/scratch` writable. No pipeline
job runs this image yet, so `appsec-review.toml` carries no pin for it (see
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
