<!-- tool-guide: code_exports v1 tools: code_exports -->
### code_exports (shipped library exports)

When: which functions a shipped shared library exports (its external attack surface) and how each
export joins to a CPG method (`joined`, `ambiguous`, `not-in-cpg`, `unjoinable`).
Source: the dynamic export tables of the accepted `02-binary-triage` evidence (brief Q).
`complete=false` when a table is partial or missing; an unlisted function may still be exported.
Cite: the export row identifies the binary and symbol; read the joined definition before citing it.
