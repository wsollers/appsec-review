# Native metadata investigation

## Question
For the supplied candidate, perform only the explicitly requested stage: propose a bounded
evidence-read plan, or propose metadata from the excerpts the application subsequently supplies.
The application mediates reads between these stages. Neither stage grants tools, retrieval,
broad filesystem access, online lookup, execution, or writes.

## Plan stage
Inspect only the supplied candidate context and allowed file catalog. Return one JSON object with
exactly this shape:

```json
{
  "schema": "appsec-review/native-metadata-plan/1",
  "candidate_id": "exact supplied candidate ID",
  "files": ["exact allowed catalog path"],
  "version_patterns": ["inert description of a likely version declaration"]
}
```

Select exact, unique paths from the allowed catalog, retaining their spelling and physical-root
identity. Prefer component-local release declarations, package descriptors, version headers,
build metadata, and attribution or license files. Do not invent paths, glob patterns, directories
to traverse, or locations outside the catalog. A catalog entry is a possible source, not a claim
that its contents have been read.

`version_patterns` contains inert descriptive hints such as a named version macro or a package
release declaration. It is not executable code, a command, a retrieval request, or an instruction
to evaluate an expression. Return empty `files` and `version_patterns` arrays to abstain when no
allowed source is justified. Do not return metadata claims in this stage.

## Metadata stage
Use only the supplied component context and application-provided, line-numbered excerpts.
Return one JSON object with exactly this shape:

```json
{
  "schema": "appsec-review/native-metadata-proposal/1",
  "candidate_id": "exact supplied candidate ID",
  "claims": [
    {
      "field": "version",
      "value": "value supported by the cited text",
      "citations": [
        {
          "path": "exact supplied excerpt path",
          "start_line": 1,
          "end_line": 1,
          "quote": "exact source text within the cited line range"
        }
      ]
    }
  ]
}
```

The examples illustrate member shapes, not source evidence. The only claim fields are `version`,
`purl`, `supplier`, `download_location`, `license_declared`, and `upstream`. Include at most one
claim for each field. Every claim needs a concrete supported value and nonempty citations.
Citation paths come exactly from supplied excerpts; line ranges are inclusive, use the displayed
source line numbers, and contain the exact quoted source text. Do not cite unread catalog entries,
the plan, candidate names alone, or invented line numbers. Multiple excerpts can jointly support
a value, but each cited span must contribute to that value for this component.

Abstain for every unknown or conflicting field by omitting its claim. Omission is field-level
abstention in this schema; an empty `claims` array explicitly abstains from all metadata. Do not
substitute a literal unknown value, null-valued claim, multiple conflicting claims, or an uncited
explanation. Do not add fields for rationale, confidence, or abstention reasons.

## Metadata distinctions
- A version identifies the supplied physical component copy, not a remembered release, the latest
  public release, or a release inferred from familiarity with the project.
- Distinguish release versions from ABI or SONAME values, shared-library suffixes, API levels,
  compatibility versions, and toolchain versions. Such a value is not a component release unless
  the supplied source explicitly establishes that relationship.
- Combine version parts only when their declarations unambiguously define this component's
  release. Do not execute build expressions, manufacture missing parts, or resolve ambiguous
  conditional definitions by guessing.
- Do not propagate an SDK, parent project, sibling module, or enclosing distribution version to
  an individual component without explicit evidence that it is also that component's release.
  Keep distinct roots and potentially different copies separate.
- Propose a PURL only when supplied evidence establishes its package type, namespace when
  applicable, name, and any included version, qualifiers, or subpath. Do not manufacture
  coordinates from a directory name, guessed ecosystem, or repository URL. Omit a PURL that
  cannot be grounded even when a component name or upstream URL is known.
- Distinguish a supplier from a copyright holder or contributor, a download location from a
  homepage, and an upstream from a mirror or incidental URL. Propose only the relationship the
  text supports; do not follow links.
- A declared license needs component-applicable declaration evidence, not an assumption inherited
  from a neighboring or enclosing project. Keep the supported declaration rather than guessing
  an SPDX identifier or a more permissive interpretation.
- If supplied evidence disagrees and does not resolve applicability to this exact component,
  omit the affected field. Do not choose by confidence, majority, apparent recency, or memory.
  A model proposal remains a proposal; confidence never establishes metadata truth.
