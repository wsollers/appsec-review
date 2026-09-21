# syntax=docker/dockerfile:1
#
# audit-iac — Infrastructure-as-Code scanning lane.
#
# Split out of the audit-static omnibus image (MIGRATION.md item 7, image-per-lane
# per design §17) on 2026-09-17. Everything in this image previously lived in
# audit-static's Terraform/Go-toolchain/pip layers; behavior of each tool is
# unchanged, only the image boundary moved.
#
# Scope: policy/config scanning of Terraform, Kubernetes manifests, Helm charts,
# and Kustomize — the orchestrator's `iac` and `iac-k8s` evidence steps. Dockerfile
# linting and container-image/base-image inventory are a separate concern and live
# in `audit-container` instead (Dockerfiles describe a build, not deployed
# infrastructure state — kept as two images so a Terraform-only or
# Kubernetes-only engagement never needs to pull a Docker-focused image, and
# vice versa).
#
# Tools:
#   terraform   HashiCorp apt repo, current stable — `terraform graph`/validate
#               are not run here (no engagement network/state access), only the
#               downstream scanners below read the checked-in HCL.
#   checkov     pip, policy scanning across Terraform/CloudFormation/K8s/Dockerfile
#   tfsec       go install — upstream-deprecated in favor of `trivy config` (see
#               the `iac` step's own Note in pipeline/Invoke-VendorAuditPrePass.*),
#               left running for continuity, not a target for new coverage
#   trivy       install script — `trivy config` against Terraform/K8s/CloudFormation
#   kube-linter go install — Kubernetes manifests, Helm charts, Kustomize
#
# VERSION PINNING: every tool here should be pinned before relying on results for
# a real engagement, same discipline as audit-static. Go-installed tools
# (tfsec, kube-linter) and the Trivy install script are still floating
# (`@latest` / `main`) — carried over unpinned from audit-static, not a new gap
# introduced by this split. Pin them here the same way audit-static pinned
# gitleaks/BinSkim/Hadolint, and record the pinned versions in this header.

FROM ubuntu:22.04

ARG GO_VERSION=1.22.5
ARG DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8 \
    PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl wget unzip ca-certificates gnupg lsb-release \
      software-properties-common jq bash \
      python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# --- Go toolchain (needed for tfsec + kube-linter) --------------------------
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz

# --- tfsec + kube-linter (STILL FLOATING — pin before a real engagement) ----
RUN go install github.com/aquasecurity/tfsec/cmd/tfsec@latest \
    && go install golang.stackrox.io/kube-linter/cmd/kube-linter@latest

# --- Terraform (HashiCorp apt repo) -----------------------------------------
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
       > /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update && apt-get install -y --no-install-recommends terraform \
    && rm -rf /var/lib/apt/lists/*

# --- Trivy (config/IaC scanning — STILL FLOATING, install-script pull) -----
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# --- checkov (pip) -----------------------------------------------------------
RUN pip3 install --no-cache-dir checkov

WORKDIR /workspace
# No ENTRYPOINT/CMD by design — the orchestrator runs one tool at a time via
# `docker run <image> <command...>`, matching audit-static's invocation model.
CMD ["/bin/bash"]
