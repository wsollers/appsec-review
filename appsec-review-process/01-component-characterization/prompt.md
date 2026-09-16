# Prompt — L0A Component And Purpose Identification

You are building the component-purpose map for an appsec review. Use deterministic artifacts first,
then direct source inspection. Do not infer security conclusions in this lane.

For each component:

- assign `component_id`
- identify path(s)
- classify component type
- state observed purpose
- assign confidence
- cite evidence
- identify trust-boundary relevance
- note deployability/liveness if known
- identify downstream lanes that should inspect it

Output both JSON and markdown. Mark unknowns explicitly.

Do not treat vendored, sample, test, or generated code as production unless evidence supports that
classification.

