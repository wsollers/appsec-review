# Prompt — Fuzz Target Triage

Identify where fuzz testing would provide benefit that exceeds its cost for this target, and
produce the "known coverage gaps" input `07-red-team-adversarial` needs. Do not write a fuzz
harness or recommend a specific fuzzer/toolchain here -- this lane triages targets, it does not
build fuzzing infrastructure.

Work from the component-purpose map and DFD outward: for each component that touches untrusted or
externally-influenced input (per the DFD's trust boundaries, or the component map's data
classes/trust boundary tags when no DFD is available), ask two separate questions and answer both
with evidence, not intuition:

1. **Would fuzzing likely find a real bug here?** Ground this in real signals: manual
   parsing/decoding of untrusted bytes, manual pointer/length arithmetic, custom allocators,
   thin or absent existing test coverage of malformed input, weaker native-analysis-tier coverage
   (Tier B/C per ADR-0001 means static tools have seen less of this code than Tier A), or a CVE
   history in this component or a structurally similar library (from `06-cve-reachability`'s
   evidence). A component with none of these signals is a weak fuzz candidate even if it touches
   untrusted input -- say so, don't pad the list.
2. **What would it actually cost to fuzz here?** A harness that reuses an existing standalone entry
   point with an available seed corpus is cheap; a harness that needs new build scaffolding, heavy
   object setup, or has no obvious seed material is expensive. Estimate this honestly from what the
   repo's actual build/test structure shows, not a generic assumption.

Rank candidates by benefit clearly exceeding cost first. Do not recommend a candidate as `fuzz now`
on benefit alone if the cost case is prohibitive, and do not bury a cheap, high-signal candidate
under a more dramatic-sounding but expensive one.

Finally, separately from the ranked fuzz recommendations, produce the "known coverage gaps" section
`07-red-team-adversarial` consumes: the components/areas with the weakest current combined
analysis coverage, regardless of whether they made the fuzz-now list. A component can be a coverage
gap worth flagging to red team even if fuzzing it specifically isn't worth the cost right now.
