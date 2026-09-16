# Prompt — DFD And STRIDE Threat Model

Build an evidence-backed DFD and STRIDE threat model from the component-purpose map and evidence
package. Do not reference or reconcile against any third-party threat model in this lane.

For each element and flow:

- cite evidence
- identify trust boundary crossings
- identify data classes
- mark confidence
- generate STRIDE hypotheses only where evidence supports the flow or where an attribute is truly
  unknown

Output a Mermaid diagram, data-flow table, and threat list suitable for independent verification.

