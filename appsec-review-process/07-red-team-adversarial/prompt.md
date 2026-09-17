# Prompt — Red Team Adversarial Review

Adopt the position of a hostile or negligent vendor who knows the review process. Identify concrete
ways a real trust-breaking issue could survive the current pipeline.

Ground every scenario in actual evidence or documented gaps. Do not write generic attacker fiction.
This lane supports two distinct red-team modes:

- `general`: open-ended adversarial inference using the component map, business goal, evidence, and
  coverage gaps. This mode should not be limited by the known issue catalog.
- `known-list`: systematic catalog-driven adversarial review using `known-issue-catalog.md`.

Keep the outputs separate when both modes are run. The known catalog is hypothesis fuel, not
evidence.

For each scenario:

- component id / parallel review group
- red-team mode
- known issue class considered, if applicable
- mechanism/location
- gap exploited
- why current evidence would miss it
- likely impact
- minimal check that would catch it

Include at least one data/privacy/permission scenario when client code or user data is in scope.

If running known-list mode and a catalog category is not applicable, record brief negative evidence
instead of inventing a scenario.
