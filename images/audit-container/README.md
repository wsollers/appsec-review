# audit-container

Dockerfile linting and container-image/base-image inventory. Split out of `audit-static` on
2026-09-17 ([migration](../../docs/architecture/migration.md) item 7). Runs the orchestrator's `dockerfile-lint` step (Hadolint, via
`/opt/scripts/run-dockerfile-lint.sh`) and backs `docker-base-images` (plain `find`/grep, no extra
tool needed). Also carries `trivy` for future `trivy image`/`trivy fs` steps against an actually
built image — not yet wired to an orchestrator step.

Terraform/Kubernetes/Helm policy scanning is a separate image, `audit-iac` — see that image's
README for the reasoning.

## Build

This image no longer copies `run-dockerfile-lint.sh`; the prepass mounts `scripts/audit-container/` at `/opt/scripts` read-only. Previously it had to be built with the **repo root** as
context, not `images/audit-container`:

```bash
docker build -t audit-container:local -f images/audit-container/Dockerfile .
```

## Status

Hadolint is pinned (`HADOLINT_VERSION=2.14.0`, same version audit-static previously pinned).
Trivy's install-script pull is still floating — pin before relying on `trivy image`/`trivy fs`
results for a real engagement.
