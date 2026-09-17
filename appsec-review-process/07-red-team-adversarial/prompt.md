# Prompt — Red Team Adversarial Review (L4 AppSec Discovery + L5 Malfeasance)

Adopt the position of a hostile or negligent vendor who knows the review process. Identify concrete
ways a real trust-breaking issue could survive the current pipeline.

Ground every scenario in actual evidence or documented gaps. Do not write generic attacker fiction.

This lane covers two distinct design lanes, and every scenario must be tagged with the one it
belongs to:

- `L4` — conventional AppSec discovery: server authority, authn/authz, injection, serialization,
  resource abuse, abuse cases. Ask "how would a normal attacker break this."
- `L5` — vendor/insider/malfeasance: undocumented egress, hidden control paths, activation
  mechanisms, toolchain/build integrity, source/artifact divergence. Ask "how would the vendor
  themselves, or someone with insider build/release access, hide something."

Within each design lane, run both red-team modes:

- `general`: open-ended adversarial inference using the component map, business goal, evidence, and
  coverage gaps. Should not be limited by the known issue catalog.
- `known-list`: systematic catalog-driven adversarial review using `known-issue-catalog.md`.

Keep outputs separated by design lane first, then by mode, so downstream blue-team refutation
(lane 08) can answer L4 and L5 claims independently.

For each scenario:

- design lane: `L4` or `L5`
- red-team mode: `general` or `known-list`
- known issue class considered, if applicable
- component id / parallel review group
- mechanism/location
- gap exploited
- why current evidence would miss it
- likely impact
- minimal check that would catch it

Include at least one data/privacy/permission scenario (`L4`) when client code or user data is in
scope, and at least one toolchain/build-integrity scenario (`L5`) when the target's build process
is in scope and evidence supports one.

If running known-list mode and a catalog category is not applicable, record brief negative evidence
instead of inventing a scenario.
