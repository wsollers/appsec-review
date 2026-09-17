# Config — Red Team / Adversarial (L4 AppSec Discovery + L5 Malfeasance)

Restructured 2026-09-17 to make design-v3.md's L4/L5 split an explicit dimension of this lane,
rather than an implicit blend. This lane already ran two orthogonal axes informally
(general/known-list "how", and AppSec-vs-malfeasance "what," blurred together); the design lane
axis is now first-class alongside the existing general/known-list mode axis. No new lane folder
was created — the design lanes are covered as two review dimensions within `07`, matching how the
harness already treats `general`/`known-list`/`combined` as run modes of one lane rather than
separate lane folders.

## Design Lanes (new axis)

- `L4` — Application-security discovery: conventional AppSec review. Server authority, authn/authz,
  injection, serialization, resource abuse, abuse cases.
- `L5` — Vendor / insider / malfeasance: undocumented egress, hidden control paths, activation
  mechanisms, toolchain/build integrity, source/artifact divergence, hostile-vendor placement.

Every scenario this lane produces must declare which design lane it belongs to. A scenario that
plausibly fits both should be filed under the design lane whose evidence and impact framing it
argues most directly, with a note that it also touches the other.

## Red-Team Modes (existing axis, orthogonal to design lane)

- `general`: open-ended hostile review within the chosen design lane.
- `known-list`: catalog-driven review within the chosen design lane, using
  `known-issue-catalog.md`.
- `combined`: allowed only for small targets or synthesis; keep sections separate by design lane
  and by mode.

## Required Inputs

- stated business goal
- component-purpose map
- component taxonomy / component cloud
- known issue catalog
- evidence package
- current findings
- known coverage gaps

## Required Outputs

- general adversarial scenarios from open-ended inference, tagged `L4` or `L5`
- known-list adversarial scenarios from `known-issue-catalog.md`, tagged `L4` or `L5`
- strongest exploitability arguments
- hostile-vendor placement hypotheses (`L5`)
- component-mapped known-issue hypotheses
- minimum checks required to defeat each scenario
- design lane used: `L4`, `L5`, or `both` (with the note above)
- red-team mode used: `general`, `known-list`, or `combined`
