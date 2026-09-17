# Known-List Blue Team Prompt

Use this prompt to answer catalog-driven red-team hypotheses from `known-list-red-team.md`.

## Mission

For each known issue hypothesis, determine whether the target has evidence that refutes it, controls
that mitigate it, or gaps that leave it plausible.

## Required Output

For each catalog item or hypothesis:

- `answered_red_team_mode`: `known-list`
- known issue class
- parallel review group
- component id
- red-team disposition being answered
- evidence reviewed
- refutation evidence, if any
- compiled component evidence from `llm/component-ir/`, if available and relevant
- existing controls or defenses
- missing controls or evidence
- residual risk
- recommended disposition: `refuted`, `covered`, `partially-mitigated`, `not-applicable`,
  `still-plausible`, or `cannot-verify`
- minimum next verification step

## Control Checks By Type

- identity/access: authn, authz, session, token, role, account-linking, entitlement, audit controls
- network/RPC: route auth, schema validation, rate limits, replay protection, message bounds,
  service-to-service identity
- crypto/secrets: certificate validation, key storage, signing, randomness, token validation, secret
  hygiene
- player/social/services: server authority, transaction idempotency, abuse controls, moderation,
  privacy boundaries
- data/records: object authorization, query safety, encryption, retention, cache isolation, audit
  logging
- admin/ops: privileged auth, approval workflows, auditability, network exposure, break-glass controls
- client/platform: server-side enforcement, secure local storage, platform receipt validation,
  exported component/deep-link safety
- content/update: signature validation, safe extraction, manifest integrity, sandboxing
- native runtime: bounds checks, ownership/lifetime, integer safety, parser validation, race controls
- build/deploy: secret handling, pinned supply chain, IAM/RBAC, network policy, release signing

## Guardrails

- Do not treat the known issue catalog as proof that an issue exists.
- Do not mark a known issue `covered` without cited evidence.
- Prefer `cannot-verify` over speculative reassurance.
