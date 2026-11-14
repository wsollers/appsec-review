---
name: unit-purpose-collation
description: Name a first-party component's security role and assets from supplied excerpts, citing a supplied line or a deterministic tag for every claim.
metadata:
  audience: runtime-worker
---

# Unit purpose collation

1. Read the supplied deterministic facets first. Each is a closed tag with an assignment id; it was
   established from the code by rules and is the baseline you add to, never a claim to restate.
2. Read the supplied excerpts. Each line is labelled `path:line`. Only these lines exist for this
   task: a construct you remember from a library or a framework but cannot point to in a supplied
   line is not evidence.
3. Decide, for the component as a whole, which `role` values and which `asset` values the supplied
   lines establish. Use only values from the supplied allowed lists. A value that would need a line
   you were not given is left out and the facet is listed under `unknown`.
4. For every value you assert, give at least one citation: a supplied `path` and `line`, or the
   `assignment_id` of a deterministic facet that already establishes it. A citation to an
   unsupplied line, a paraphrase, or a line that does not show the claimed behaviour makes the
   whole proposal unusable.
5. Write one paragraph, within the stated character bound, that says what this component is for
   in plain terms: what it reads, what it decides, what it keeps and what it writes, as the
   supplied lines show. Do not name weaknesses, severities, controls or fixes; that is another
   worker's job and this paragraph is routing context, not a finding.
6. Return exactly the closed response contract: `schema`, `component_id`, `role`, `asset`,
   `purpose`, `claims` and `unknown`, with no other keys and no prose outside it. When nothing is
   established, return empty lists, an empty purpose and name the unknown facets.
