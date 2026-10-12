---
id: ci_cd_pipeline
version: 1
covers: ["cwe:829", "infra:ci:*"]
standards: ["cwe", "attack", "ssdf", "slsa1", "cicd-top10", "scorecard"]
max_tokens: 1500
---
## Viewpoint
A pipeline attacker. CI runs code from many trust levels with the repository's secrets, write
tokens, cloud identities, and publishing rights. The question is whether an outside contributor,
a compromised action, or a poisoned cache can make a privileged job run their code.

## Coverage
GENERATED

## Likely failure modes
- Pwn requests: `pull_request_target` or `workflow_run` jobs that check out the fork's head
  (`ref: ${{ github.event.pull_request.head.sha }}`) and then build, test, or run scripts with
  secrets or a write token.
- Expression injection: `${{ github.event.issue.title }}`, `head_ref`, PR body, commit message,
  or branch names interpolated into `run:` scripts or `actions/github-script` code.
- Over-broad tokens: no `permissions:` block (inheriting write-all), `contents: write` or
  `id-token: write` on jobs that do not need them; GitLab `CI_JOB_TOKEN` scope too wide.
- OIDC trust: cloud roles whose trust policy accepts any repository, branch, or `pull_request`
  subject claim.
- Third-party actions or orbs pinned to a tag or branch instead of a full commit SHA; Docker
  `uses:` without a digest.
- Self-hosted runners on public repositories, non-ephemeral runners reused across jobs.
- Cache and artifact poisoning: untrusted jobs writing caches or artifacts that release jobs
  restore and execute.
- Secrets echoed into logs, written into artifacts, or passed to fork builds; `set -x` with
  secret environment variables.
- Deploy steps without environment protection rules or required reviewers.

## Effective controls
- Untrusted code runs only in `pull_request` jobs with read-only tokens and no secrets; a separate
  privileged workflow consumes only data artifacts, treated as untrusted.
- Event data passed through `env:` and quoted as shell variables, never inlined into scripts.
- Explicit minimal `permissions:` at workflow and job level.
- Actions pinned by full SHA, with an update bot proposing bumps.
- OIDC trust conditions on exact `repo`, `ref`, and `environment` subject claims.
- Ephemeral, isolated runners; cache keys partitioned by trust level; environments with
  reviewers for deployment.

## False positives
- `pull_request_target` workflows that only label or comment and never check out or execute PR
  code.
- `${{ }}` expressions over trusted values (`github.sha`, `matrix` constants, `inputs` of a
  maintainer-only `workflow_dispatch`).
- Tag-pinned first-party actions from the same organization under branch protection.

## Evidence by predicate
- `affected_construct`: the workflow file, job, step, and line with the trigger, checkout,
  expression, or permission.
- `attacker_input_control`: the event field, fork content, PR metadata, or artifact the outsider
  controls, given the trigger.
- `source_to_sink_reachability`: trigger to job to step ordering showing untrusted content reaches
  execution within the privileged context.
- `missing_or_ineffective_guard`: absent `permissions:`, missing actor or label conditions, inline
  interpolation, unpinned reference, or no environment gate.
- `configuration_enables`: repository settings for fork workflows, required approvals for outside
  contributors, runner groups, cloud trust policies.
- `security_impact`: secret exfiltration, repository write, package or release publication, or
  cloud access through the federated role.

## Hand-offs
Dependency and registry trust go to `build_supply_chain`. Cloud IAM roles beyond the trust policy
go to `cloud_container_deployment`. Secret strength and handling in application code go to
`cryptography_data_protection`. Script injection outside CI goes to `injection_interpreters`.
