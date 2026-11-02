---
name: native-sbom-investigation
description: Curate supplied native components and assess component-local metadata evidence in staged SBOM proposals.
metadata:
  audience: runtime-worker
---

# Native SBOM investigation procedure

1. Inventory the supplied candidate IDs, physical roots, and all supplied path context. Distinguish
   a concrete library or named SDK module from a generic directory, incidental file, or ambiguous
   observation. Track an explicit retained, rejected, or uncertain disposition for each candidate.
2. Resolve names against the entire supplied layout. Look beneath generic roots for specific
   components. Treat unfamiliar but explicitly named SDK modules as real candidates when their
   packaging supports them. Keep copies from distinct physical roots separate.
3. Check proposed SDK relationships against coherent distribution or header evidence. A lexical
   prefix is a clue, not sufficient grouping evidence. Keep individual components visible within
   a group and keep their metadata independent.
4. For a requested plan, rank the allowed catalog entries by component specificity and potential
   release or attribution evidence. Choose exact catalog paths and inert descriptions of likely
   version declarations. A planned source is not evidence that its contents have been observed.
5. After the application supplies excerpts for metadata investigation, distinguish the component's
   own release declarations from ABI, compatibility, parent-project, and build-tool values.
   Reconcile applicability across the supplied excerpts before proposing any value.
6. For each prospective metadata value, trace its identity and relationship to exact source spans.
   Check every quote against the supplied excerpt and its displayed line numbers. Package
   coordinates, supplier relationships, declared licenses, and upstream locations each need their
   own applicable support; a familiar name does not supply missing evidence.
7. Leave unknown or unresolved conflicting fields without claims, and abstain entirely when no
   value has support. Check the stage-specific task contract for the corresponding empty-array
   representation. Do not fill evidence gaps with remembered or latest public metadata.
8. Before returning the requested proposal, check candidate accounting, physical-root separation,
   stage-specific structure, and citation applicability. Keep observed text, interpretation, and
   unresolved ambiguity distinct; recognition and confidence do not turn an interpretation into
   an established fact.
