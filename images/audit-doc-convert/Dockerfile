# syntax=docker/dockerfile:1
#
# audit-doc-convert: document-to-text converters for 02-doc-intelligence-ingest (gap 7).
#
# Tools (Ubuntu 24.04 packages at exact versions; bumping one is a deliberate edit of this file, which
# changes the build fingerprint and so the B16 record and every conversion's input fingerprint):
#   pdftotext  poppler-utils 24.02.0-1ubuntu9.9   PDF -> UTF-8 text, `-layout`; pages end in form feeds
#   pandoc     pandoc 3.1.3+ds-2                  DOCX -> GitHub-flavoured markdown, `--sandbox`
#
# The job (appsec-review-process/doc_convert.py) runs one argv per document inside the B13 boundary:
# network none, read-only root and checkout (/workspace), non-root user, one run-owned /scratch.
# Images define tools only: no repo script is copied or mounted. No OCR engine is installed on purpose:
# an image-only PDF is a recorded gap. HTML and man pages are converted in Python (stdlib) and never
# reach this image.

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        pandoc=3.1.3+ds-2 \
        poppler-utils=24.02.0-1ubuntu9.9 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC
WORKDIR /scratch
CMD ["/usr/bin/pdftotext", "-v"]
