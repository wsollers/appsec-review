# 10 -- Refresh docs/agent-reader.md against the new tree

Goal: the entry point must reflect the partitioned tree and include the current docs it was
missing.

## Inputs
- Chunks 01, 06, 07, 08, 09 done.
- Missing today (all CURRENT): `docs/adapters/permission-capabilities.md`,
  `docs/adapters/persona-invocation-adapter.md`, `docs/evidence/sbom-family-contracts.md`.

## Steps
1. Rewrite the Read Order to walk the buckets: architecture -> dagster -> processes -> evidence ->
   pools/rendezvous/adapters -> personas-and-registry -> review-lanes -> workbenches (proposals) ->
   design-parity -> continuation. Keep it to what an agent needs before touching a run; everything
   else is "when involved".
2. Update every path in the doc to its new location; add the three missing docs.
3. Keep the Dagster Quick Map, Job Requirements and validator invocation sections -- they are the
   operational core.

## Done when
Every link resolves; the read order covers every bucket that has a doc.

## Touches
`docs/agent-reader.md` only.
