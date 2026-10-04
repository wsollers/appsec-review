# audit-doc-convert

PDF and DOCX to text for `02-doc-intelligence-ingest` (gap 7): `pdftotext -layout` (poppler-utils
24.02.0-1ubuntu9.9) and `pandoc --sandbox -f docx -t gfm` (pandoc 3.1.3+ds-2), pinned by exact package
version on the digest-pinned Ubuntu 24.04 base.

`appsec-review-process/doc_convert.py` runs one container per document as a B13 pinned-container step
(network none, checkout mounted read-only at `/workspace`, output in `/scratch`) plus one version probe
per tool, and records tool version, image digest and output sha256 per document. Encrypted, corrupt,
oversized and image-only PDFs are gaps; there is no OCR. HTML and man pages are converted in Python.

## Build

```bash
python3 -B images/image_build.py build audit-doc-convert
python3 -B images/registry_records.py generate --image-id audit-doc-convert
```

`orchestrator/prepare-host.sh` builds it with the other B16 images. Without its record the job still
publishes text documents and records each PDF/DOCX as a `converter-unavailable` gap.
