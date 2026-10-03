---
name: appsec-owasp-routing
description: Build, inspect, or operate AppSec Review's component-scoped OWASP applicability, batching, validator handoff, and accounting flow. Applies when deciding which OWASP controls run against which components or modules.
---

# AppSec OWASP component routing

Use the accepted component map as the target inventory, then build a complete selected-control x
component applicability matrix. Every pair must end as applicable, conditional, not applicable,
cannot determine, or explicitly out of scope. Absence of a rule is `cannot_determine`, never
`not_applicable`. The one generated technical N/A: ASVS V3, V4, V7, V9, V10 and V17 for a component
the accepted map classifies with high confidence as a local CLI or library with no network, HTTP or
session trait (`owasp_component_routing.py`, P24; resting on the bound component map is pending owner
confirmation). A partially classified component gets a `conditional` rule carrying its open questions.

Batch only applicable and conditional rows. Partition by component or component group, OWASP
domain, evidence mode, tooling profile, authorization boundary, and validator role. Preserve the
component ID, control ID, proof obligations, citations, source snapshot, and applicability-model
hash through handoff, assessment, join, and report.

Read [references/component-routing.md](references/component-routing.md) before creating requests,
changing routing, or claiming OWASP coverage. It explains the existing index and the automatic
assembly lifecycle.
