# syntax=docker/dockerfile:1
#
# audit-report — final report build lane (LaTeX -> PDF).
#
# Consumes lane 10 (`10-synthesis-report`) output and produces the delivered
# engagement report as a PDF, built from LaTeX source. Adapted from the LRA
# governance project's standalone LaTeX build image
# (F:\repos\lra-governance\docker\lra-exercises-latex\Dockerfile) — that image
# was chosen over its sibling `lra-tex-dev` because it is the standalone
# variant (no lra-common mount, no multi-volume edition/paper environment
# variables), which matches a single self-contained report document rather
# than a multi-volume book build. Same pinned TeX Live base image digest as
# the source Dockerfile, for the same reproducibility reason every other
# image in this repo pins its base.
#
# pandoc is added on top of the source image (not present in lra-exercises-latex)
# so lane 10's markdown findings/report draft can be converted straight into
# LaTeX section source instead of being retyped by hand; the actual document
# class, style, and section structure are still open — see the project TODO
# ("Decide on format and styleguide for LaTeX reporting of results and
# sections needed").
#
# Tools:
#   latexmk, biber, chktex   TeX Live build toolchain (compile + bibliography +
#                             lint the .tex source itself)
#   ghostscript, poppler-utils, qpdf   PDF post-processing/inspection (merge,
#                             redact/inspect metadata, validate the produced PDF)
#   pandoc                   markdown (lane 10 report draft, findings tables) -> LaTeX
#   python3                  for any report-assembly scripting (e.g. templating
#                             per-finding LaTeX sections from correlated-findings.json)
#   python3-jinja2, cvss     pipeline/report/render.py: Jinja2 templates -> report.tex, and
#                             CVSS 4.0 base scores computed from vectors. Jinja2 comes from
#                             Debian; cvss is pinned by hash in requirements.lock (the only
#                             repo file copied in). The renderer itself is mounted read-only
#                             at run time, never copied (see pipeline/report/README.md).

FROM texlive/texlive:latest@sha256:2f9918a156cfc6c7527590e06f69bfb4fbc827278e4736c90e567382855d7cd1

RUN apt-get update && apt-get install -y --no-install-recommends \
        biber \
        ca-certificates \
        chktex \
        fontconfig \
        ghostscript \
        git \
        latexmk \
        less \
        make \
        pandoc \
        perl \
        poppler-utils \
        python3 \
        python3-jinja2 \
        python3-pip \
        qpdf \
        ripgrep \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --no-cache-dir --break-system-packages \
        --require-hashes --no-deps -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

RUN fc-cache -fv

ENV TEXMFVAR=/tmp/texmf-var
ENV TEXMFCONFIG=/tmp/texmf-config
ENV HOME=/tmp
ENV max_print_line=1000

WORKDIR /workspace

CMD ["latexmk", "--version"]
