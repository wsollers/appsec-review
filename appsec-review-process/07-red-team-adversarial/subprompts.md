# Subprompts — Red Team / Adversarial (L4 AppSec Discovery + L5 Malfeasance)

Each subprompt below states which design lane(s) it primarily serves. Tag every scenario produced
with `L4` or `L5` regardless of which subprompt generated it.

## AppSec Discovery Sweep (L4)

Walk the component-purpose map for conventional AppSec exposure: authn/authz boundaries, input
validation and injection surfaces, serialization/deserialization, resource-abuse and rate-limit
gaps, and business-logic abuse cases. Ground each in evidence or a documented coverage gap.

## Known Issue Matrix (L4 and L5)

For each component or parallel review group in the component-purpose map, select applicable issue
classes from `known-issue-catalog.md`. Tag each selected class `L4` or `L5` based on whether it's a
conventional AppSec issue or a vendor/insider/malfeasance issue. For each selected issue class,
write one evidence-backed hypothesis or explicitly mark it as not applicable with negative evidence.

Do not turn catalog entries into findings without target-specific evidence.

## Exploitability Argument (L4 or L5)

Build the strongest evidence-backed exploitability argument for one unresolved or deep-confirmed
cluster. State which design lane the argument belongs to.

## Hostile Vendor Placement (L5)

Identify where malicious or trust-breaking code would be easiest to hide given current coverage
gaps: undocumented egress, hidden control/activation paths, toolchain and build-integrity gaps,
divergence between source and shipped artifacts.

## Goal-Conformance Challenge (L4 and L5)

Ask whether the current process actually answers the user's stated accept/ship/integrate decision,
across both conventional AppSec risk (L4) and vendor-trust risk (L5).
