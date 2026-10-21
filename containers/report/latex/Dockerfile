# syntax=docker/dockerfile:1
# tool-report-latex: deterministic LaTeX -> PDF rendering of the review report.
#
# The exact package closure (XeTeX from TeX Live 2023 as packaged by Ubuntu 24.04, the Inter and
# JetBrains Mono fonts, and poppler-utils for the structural checks) is acquired by
# acquire_assets.sh, recorded in assets.lock.json and packages.manifest, and supplied from the
# ignored downloads cache. Docker dependency resolution is offline. The report template is NOT part
# of the image: it is mounted read-only at /template at render time (see render-pdf.sh).
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS build
ARG DEBIAN_FRONTEND=noninteractive
# The locked tar is bind-mounted for this one RUN, so its 150 MB never becomes an image layer.
RUN --mount=type=bind,source=downloads/report-latex-debs.tar,target=/tmp/report-latex-debs.tar \
    mkdir /tmp/debs \
    && tar -xf /tmp/report-latex-debs.tar -C /tmp/debs \
    && cp /tmp/debs/*.deb /var/cache/apt/archives/ \
    && apt-get install -y --no-download --no-install-recommends /tmp/debs/*.deb \
    && rm -rf /tmp/debs /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

FROM build AS runtime
ARG TOOL_VERSION
LABEL org.opencontainers.image.title="tool-report-latex" \
      org.opencontainers.image.version="${TOOL_VERSION}" \
      org.opencontainers.image.licenses="LPPL-1.3c AND OFL-1.1 AND GPL-2.0-or-later AND mixed Ubuntu distribution packages"
RUN groupadd -g 10001 worker \
    && useradd -m -u 10001 -g 10001 -s /usr/sbin/nologin worker \
    && mkdir -p /scratch /opt/tool/bin \
    && chown 10001:10001 /scratch
COPY --chmod=0555 render-pdf.sh /opt/tool/bin/render-pdf
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC TOOL_VERSION=${TOOL_VERSION} \
    TEXMFVAR=/scratch/.texmf-var TEXMFCONFIG=/scratch/.texmf-config TEXMFHOME=/scratch/.texmf
RUN xelatex --version | grep -F "(TeX Live 2023/Debian)" \
    && pdfinfo -v 2>&1 | grep -F "pdfinfo version 24.02.0" \
    && test -f /usr/share/fonts/opentype/inter/Inter-Regular.otf \
    && test -f /usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf \
    && kpsewhich tcolorbox.sty fontspec.sty fvextra.sty booktabs.sty microtype.sty hyperref.sty >/dev/null \
    && /opt/tool/bin/render-pdf --version | grep -F "tool-report-latex ${TOOL_VERSION}"
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /scratch
