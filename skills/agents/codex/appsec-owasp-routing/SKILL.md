---
name: appsec-owasp-routing
description: Build, inspect, or operate AppSec Review's component-scoped OWASP applicability, batching, validator handoff, and accounting flow. Applies when deciding which OWASP controls run against which components or modules.
---

# AppSec OWASP component routing

Routing follows ADR-0034 (inference classifies, Python routes). `04-owasp-candidate-search` (Python)
collects per-chapter candidate code from the code index, full-text and semantic search, SAST hits and
the tag cloud; `04-owasp-participation` (model, read-only `code_*` tools) only labels each candidate
`implements`/`enforces`/`consumes`/`not_participating` with resolving citations; `04-owasp-universe`
(Python) decides each ASVS chapter `participating`, `not_applicable` (zero candidates with complete
coverage, or all candidates cited as not participating) or `gap`, and enforces the validator-call budget
before any call. `owasp_component_routing.py` is a pure projection of the accepted universe into the T04
request: 17 `asvs-V<n>` targets, each with `control_scope` so its rows are only that chapter's controls.
No keyword or trait rule decides applicability; the component map is report context only. Absence of
coverage is a gap, never `not_applicable`.

Batch only applicable and conditional rows. Partition by component or component group, OWASP
domain, evidence mode, tooling profile, authorization boundary, and validator role. Preserve the
component ID, control ID, proof obligations, citations, source snapshot, and applicability-model
hash through handoff, assessment, join, and report.

Read [references/component-routing.md](references/component-routing.md) before creating requests,
changing routing, or claiming OWASP coverage. It explains the existing index and the automatic
assembly lifecycle.
