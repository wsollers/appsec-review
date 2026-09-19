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
- `kill-chain` (added 2026-09-18): explicitly search for multi-step attack chains that combine
  several individually weak, low-severity, or "not applicable alone" findings/gaps into an
  exploitable path, rather than only scoring findings one at a time. Includes tainted-data kill
  chains specifically: trace untrusted/attacker-influenced data from a real entry point, through
  intermediate components/functions, to a dangerous sink (memory write, deserialization, command
  execution, trust decision, etc.), even when no single hop on that path looks exploitable in
  isolation. A `general` or `known-list` scenario that turns out to need another finding to be
  reachable or impactful should be promoted into a `kill-chain` scenario rather than left as a
  weaker standalone one.
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
- kill-chain scenarios (added 2026-09-18): each one must enumerate its individual steps (per step:
  component id, weakness/gap exploited, evidence), identify the taint source and sink explicitly
  for tainted-data chains, and state why the composed chain survives currently deployed mitigations
  end-to-end -- not just why each step looks plausible alone
- strongest exploitability arguments
- hostile-vendor placement hypotheses (`L5`)
- component-mapped known-issue hypotheses
- minimum checks required to defeat each scenario
- known coverage gaps used as scenario input, and their source (see "Known Coverage Gaps" below)
- design lane used: `L4`, `L5`, or `both` (with the note above)
- red-team mode used: `general`, `known-list`, `kill-chain`, or `combined`

## Known Coverage Gaps (added 2026-09-18)

This lane's "Required Inputs" have always listed "known coverage gaps," but nothing formally
produced them until `13-fuzz-target-triage` was added. Read that lane's real output --
`appsec-review-process/runs/<run_id>/outputs/13-fuzz-target-triage/result.md` (see this run's
`## Upstream Outputs` handoff section for the exact path) -- for its ranked list of
under-tested/high-uncertainty areas; treat components it flags as high-uncertainty as good starting
points for both `general` and `kill-chain` scenarios, since a gap in test/analysis coverage is
exactly where a multi-step chain is least likely to have been noticed.
