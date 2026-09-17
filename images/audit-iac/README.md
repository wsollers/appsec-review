# audit-iac

Infrastructure-as-Code policy scanning: Terraform, Kubernetes manifests, Helm charts, Kustomize.
Split out of `audit-static` on 2026-09-17 (MIGRATION.md item 7). Runs the orchestrator's `iac`
and `iac-k8s` steps (`checkov`, `tfsec`, `trivy config`, `kube-linter`).

Container-image/Dockerfile scanning is a separate image, `audit-container` — this image never
needs Docker-in-Docker or a build step, `audit-container` never needs Terraform/Kubernetes state.

## Build

```bash
docker build -t audit-iac:local images/audit-iac
```

No repo-root context or COPY dependency — self-contained, unlike `audit-container`.

## Status

Tool versions still floating (`tfsec`, `kube-linter` via `go install @latest`; Trivy via install
script) — see the Dockerfile header. Pin before relying on results for a real engagement.
