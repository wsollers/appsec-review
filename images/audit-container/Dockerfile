# syntax=docker/dockerfile:1
#
# audit-container — Dockerfile/container-image scanning lane.
#
# Split out of the audit-static omnibus image (MIGRATION.md item 7, image-per-lane
# per design §17) on 2026-09-17. Hadolint and the `run-dockerfile-lint.sh` wrapper
# moved here unchanged from audit-static; behavior of the `dockerfile-lint` and
# `docker-base-images` evidence steps is unchanged, only the image boundary moved.
#
# Scope: what a repo's Dockerfiles say about how images are built, and a
# zero-cost inventory of what they're built FROM — not deployed infrastructure
# state (that's `audit-iac`: Terraform/Kubernetes/Helm). Two images so a
# Kubernetes-only or Terraform-only engagement never needs to pull a
# Docker-focused image, and vice versa.
#
# Tools:
#   hadolint    binary download, pinned — lints every Dockerfile in the tree
#               directly from source (unpinned/floating base tags, ADD vs COPY,
#               running as root, etc.), no `docker build` needed. Invoked via
#               /opt/scripts/run-dockerfile-lint.sh (baked in below), same static
#               argv-array Cmd pattern as every other step in this toolbox — see
#               that script's own header for the PowerShell/docker.exe
#               argv-marshalling bug it was written to avoid.
#   (none)      `docker-base-images` needs only `find`/`grep`/`awk`, already in
#               this base image — a zero-cost FROM-line inventory across every
#               Dockerfile in the tree, no build required.
#   trivy       install script — included for `trivy image`/`trivy fs` against an
#               actually-built image or filesystem layer, per the audit-static
#               Dockerfile's own original note ("the build-dependent deep pass...
#               opportunistic, not automated here"). Not yet wired to an
#               orchestrator step; add one when a real engagement has a
#               buildable image to scan. Kept here rather than in audit-iac so
#               this image is self-contained for anything "container image"
#               shaped.
#
# VERSION PINNING: Hadolint is pinned (matches the version previously pinned in
# audit-static). Trivy's install-script pull is still floating — pin it here
# before relying on `trivy image`/`trivy fs` results for a real engagement.
#     Hadolint   HADOLINT_VERSION = 2.14.0

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates bash findutils gawk grep \
    && rm -rf /var/lib/apt/lists/*

# --- Hadolint (Dockerfile linter) --------------------------------------------
ARG HADOLINT_VERSION=2.14.0
RUN curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
      -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# --- Trivy (image/filesystem scanning — STILL FLOATING) ---------------------
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# --- This repo's own evidence-shaping script (moved from audit-static) ------
COPY scripts/run-dockerfile-lint.sh /opt/scripts/run-dockerfile-lint.sh
RUN chmod +x /opt/scripts/run-dockerfile-lint.sh

WORKDIR /workspace
# No ENTRYPOINT/CMD by design — the orchestrator runs one tool at a time via
# `docker run <image> <command...>`, matching audit-static's invocation model.
CMD ["/bin/bash"]
