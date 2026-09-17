# Known-List Red Team Prompt

Use this prompt for systematic catalog-driven red-team review. This is separate from the general red
team prompt.

## Mission

Walk `known-issue-catalog.md` against the component cloud and staged evidence. For each applicable
component or parallel review group, select relevant known issue classes and try to build the
strongest evidence-backed attack hypothesis.

## Required Method

1. Read the component-purpose map and identify applicable parallel review groups.
2. For each applicable group, read the matching section in `known-issue-catalog.md`.
3. Read `retrieval-guide.md` and use its source/evidence search pattern with the component's
   aliases, search terms, representative locations, and `component_id`.
4. Use search terms, semantic index, symbol index, CodeQL/CSA/IR artifacts, `llm/component-ir/`
   compiled component slices when present, and source review to look for target-specific evidence.
5. Produce either:
   - an evidence-backed hypothesis, or
   - negative evidence / not applicable rationale.

## Required Output

For each reviewed catalog item:

- `mode`: `known-list`
- parallel review group
- component id
- known issue class
- relevant search terms used
- evidence found or negative evidence
- candidate mechanism/location, if any
- why current tools might miss it
- minimum check to confirm or refute
- disposition: `candidate`, `not-applicable`, `insufficient-evidence`, or `covered`

## Guardrails

- The catalog is not evidence.
- Do not report a generic issue class unless the target has matching code, configuration, artifact
  evidence, or a meaningful coverage gap.
- Prefer many small, precise hypotheses over broad generic warnings.
