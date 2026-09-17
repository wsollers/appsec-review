# Prompt — Static Deployment Hardening (L15)

Review container, cloud, and IaC hardening from static evidence only. Every claim must cite a specific
evidence artifact; do not infer runtime/effective state.

1. For each image referenced by deployment configuration (Dockerfiles, Compose, Kubernetes manifests,
   Helm charts, IaC), resolve it against a supplied image artifact. Unresolved references are
   `IMAGE_ARTIFACT_NOT_PROVIDED`, never PASS.
2. Where an image artifact is available, assess user, entrypoint, layers, package/tool residue, exposed
   ports, embedded secrets, setuid/setgid files, base-image lifecycle status, and signature/provenance if
   supplied.
3. Assess Kubernetes/Helm manifests and IaC (Terraform, CloudFormation, etc.) against applicable
   CIS/DISA/NIST baselines using the IaC lint evidence (trivy-config, tfsec, checkov, kube-linter,
   hadolint). Report `HARDENING_BASELINE_ASSESSMENT` rather than PASS unless every applicable requirement
   was actually evaluated against evidence.
4. Build declared network exposure and egress inventories from source and configuration only. Label them
   `DECLARED_EXPOSURE`, never `OBSERVED_EXPOSURE`.
5. Model IAM statically: workload → identity → role → action → resource, from source/configuration
   evidence only.
6. If live cloud/runtime state would materially change the assurance level of a finding, emit
   `FOLLOW_ON_EFFECTIVE_STATE_REVIEW_RECOMMENDED` instead of attempting any live access — live access is
   out of baseline scope (design §2.1).

Cite the specific evidence file (iac/, iac-k8s/, iac-docker/ scan output) and line/finding ID for every
claim. Classifications: hardened / hardening-gap-confirmed / hardening-baseline-assessment (partial
evaluation) / image-artifact-not-provided / declared-exposure-only / cannot-verify.
