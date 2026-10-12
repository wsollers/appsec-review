---
id: ci_pipeline
version: 1
covers: []
standards: ["cicd-top10", "slsa1", "scorecard"]
max_tokens: 1500
---
## Runtime and framework model
Workflow definitions executed by a CI/CD system: GitHub Actions (`.github/workflows/*.yml`,
composite actions, reusable workflows), GitLab CI (`.gitlab-ci.yml`, includes), Azure Pipelines,
Jenkins (`Jenkinsfile`, shared libraries), CircleCI, Buildkite, or Tekton. Jobs run shell steps
and third-party actions or images on hosted or self-hosted runners with tokens, secrets, and
cloud identities injected by the platform.

## Trust and interface layer
- Triggers determine whose code and data run: `push` and `workflow_dispatch` (maintainers),
  `pull_request` (fork code, no secrets by default), `pull_request_target` and `workflow_run`
  (base-branch privileges, often handling fork data), `issue_comment` and `issues` (any user's
  text), scheduled jobs.
- Event payload fields (titles, bodies, branch names, commit messages, labels) are attacker text.
- Artifacts, caches, and outputs passed between jobs or workflows carry trust from their producer.
- Reusable workflows and included templates execute with the caller's secrets.

## Idiomatic security mechanisms
- `permissions:` blocks per workflow and job; GitLab protected branches and variables; Jenkins
  folder-scoped credentials.
- Environments with required reviewers and branch restrictions for deploy jobs.
- OIDC federation (`id-token: write`) with cloud trust conditions instead of long-lived keys.
- Actions pinned to full commit SHAs; images pinned by digest.
- `persist-credentials: false` on checkout; ephemeral runners.

## Stack-specific pitfalls
- `run: echo "${{ github.event.pull_request.title }}"` style interpolation (expression
  injection); the same in `actions/github-script` `script:` inputs.
- `pull_request_target` plus `actions/checkout` with the PR head ref, followed by `npm install`,
  `make`, or test runs.
- Writing to `$GITHUB_ENV` or `$GITHUB_OUTPUT` from untrusted data (environment injection,
  `LD_PRELOAD`, `NODE_OPTIONS`).
- `workflow_run` consumers that download and unzip fork artifacts into the workspace, then execute.
- Self-hosted runners attached to public repositories; runner labels shared across trust levels.
- GitLab `CI_JOB_TOKEN` allowlists too broad; Jenkins `script` approval bypasses.
- Secrets printed through debug logging or uploaded inside artifacts.
- Caches keyed only by lockfile hash shared between `pull_request` and release jobs, letting fork
  builds seed the cache that a privileged job restores.

## Build and deployment facts to check
- Repository and organization settings: fork PR approval requirements, default token permissions,
  allowed actions policy (often unavailable offline; record the gap).
- Branch protection on the branches that trigger deploy and release jobs.
- Which jobs publish packages, images, or releases, and with which credentials.
- Cloud trust policies referenced by OIDC role ARNs or workload identity providers.
