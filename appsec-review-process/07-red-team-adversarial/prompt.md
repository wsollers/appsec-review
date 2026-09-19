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

Within each design lane, run all red-team modes:

- `general`: open-ended adversarial inference using the component map, business goal, evidence, and
  coverage gaps. Should not be limited by the known issue catalog.
- `known-list`: systematic catalog-driven adversarial review using `known-issue-catalog.md`.
- `kill-chain` (added 2026-09-18): deliberately look for ways to link multiple findings/gaps into
  one exploitable path, instead of only evaluating each finding in isolation. Two sub-cases to
  always consider:
  - **Composed weaknesses**: a low-severity or "not exploitable alone" finding from this lane's own
    `general`/`known-list` output, or from an earlier lane (05's native findings, 06's CVE/dependency
    findings), becomes exploitable when chained with another such finding (e.g. an info-leak that
    defeats ASLR feeding a separate memory-corruption primitive; a config weakness that removes a
    check another finding depends on).
  - **Tainted-data chains**: pick a real untrusted-input entry point (network input, file parsing,
    deserialization, environment/config read from an untrusted source) and trace it as far as you
    can through the actual call graph toward a dangerous sink, using the component map, symbol
    index, and 13-fuzz-target-triage's coverage-gap output (see config.md) to prioritize which
    entry points are worth tracing. A chain does not need every hop pre-confirmed as vulnerable to
    be worth reporting -- report it with the specific hop(s) where evidence runs out, so blue team
    and independent verification know exactly what to check.

  For every kill-chain scenario, list the steps in order (component id, weakness, evidence, and
  confidence per step), not just a narrative paragraph -- lane 09's kill-chain verification checks
  each step independently and needs the steps enumerated to do that.

Keep outputs separated by design lane first, then by mode, so downstream blue-team refutation
(lane 08) can answer L4, L5, and kill-chain claims independently.

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
